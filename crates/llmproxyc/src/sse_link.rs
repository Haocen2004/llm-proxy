//! 客户端的 SSE 隧道传输（设计 §10 第二档）。
//!
//! 形态：一条 `POST /__dshp/tunnel` 长连接，请求体承载上行帧、响应体是 SSE 下行帧。
//! 编码细节见 `llm_proxy_transport::sse`。
//!
//! # 为什么放在客户端 crate 而不是 `llm-proxy-transport`
//!
//! 它需要 hyper 的 **client** 端。`llm-proxy-transport` 目前只做"给一条已有字节流套上帧隧道"
//! （WS 那套就是），把 hyper 客户端塞进去会让传输层的依赖面显著变大，而**唯一的使用者
//! 就是客户端**。放在这里，依赖边界和实际使用者对齐。

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, StreamBody};
use hyper::client::conn::http1;
use hyper::Request;
use hyper_util::rt::TokioIo;
use llm_proxy_core::config::MAX_FRAME_BYTES;
use llm_proxy_core::Frame;
use llm_proxy_transport::sse::{ChunkWriter, Duplex, OkSink, SseReader};
use llm_proxy_transport::{Mux, SessionError};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// 隧道路径。必须与服务端 `llmproxyd::egress::TUNNEL_PATH` 一致。
pub const TUNNEL_PATH: &str = "/__dshp/tunnel";

type TunnelBody = BoxBody<Bytes, std::io::Error>;

/// 从 `ws://host:port` 或 `host:port` 里取出 `host:port`。
pub fn host_of(server: &str) -> &str {
    let s = server
        .strip_prefix("ws://")
        .or_else(|| server.strip_prefix("wss://"))
        .or_else(|| server.strip_prefix("http://"))
        .or_else(|| server.strip_prefix("https://"))
        .unwrap_or(server);
    // 去掉可能存在的路径部分
    s.split('/').next().unwrap_or(s)
}

/// 建立一条 SSE 帧隧道。
pub async fn connect(server: &str) -> Result<(Mux, mpsc::Receiver<Frame>), SessionError> {
    let addr = host_of(server);
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| SessionError::Transport(format!("SSE 隧道无法连接 {addr}：{e}")))?;
    tcp.set_nodelay(true).ok();

    let (mut sender, conn) = http1::handshake::<_, TunnelBody>(TokioIo::new(tcp))
        .await
        .map_err(|e| SessionError::Transport(format!("SSE 隧道 HTTP 握手失败：{e}")))?;
    // 连接任务必须活着：它同时驱动请求体与响应体两个方向
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(?e, "SSE 隧道连接结束");
        }
    });

    // 请求体 = 上行帧流。用 `futures-channel`：tokio 的 mpsc Sender 没有 Sink 实现。
    let (otx, orx) = futures_channel::mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    let req_body: TunnelBody = BodyExt::boxed(StreamBody::new(
        orx.map(|r| r.map(http_body::Frame::<Bytes>::data)),
    ));
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://{addr}{TUNNEL_PATH}"))
        .header("content-type", "application/octet-stream")
        .header("accept", "text/event-stream")
        .body(req_body)
        .map_err(|e| SessionError::Protocol(format!("构造隧道请求失败：{e}")))?;

    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| SessionError::Transport(format!("SSE 隧道请求失败：{e}")))?;
    let status = resp.status();
    if status != hyper::StatusCode::OK {
        return Err(SessionError::Transport(format!(
            "SSE 隧道被拒绝：HTTP {status}（服务端可能不支持该模式）"
        )));
    }
    // 校验内容类型：若中间设备把它换成了普通 JSON 错误页，这里当场发现，
    // 而不是等很久之后才在帧解析上失败
    let ctype = resp
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !ctype.starts_with("text/event-stream") {
        return Err(SessionError::Transport(format!(
            "SSE 隧道响应类型不对：{ctype:?}（中间设备可能改写了响应）"
        )));
    }

    let (_, body) = resp.into_parts();
    let out = ChunkWriter::new(OkSink::new(otx));
    let inp = SseReader::new(body.into_data_stream());
    Ok(Mux::spawn(Duplex::new(out, inp), MAX_FRAME_BYTES))
}
