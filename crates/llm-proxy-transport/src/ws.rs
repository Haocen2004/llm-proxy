//! WS 模式（M0 默认首选）：穿透 443 / CDN 最友好。
//!
//! DSHP 帧一律走 **Binary** 消息；收到 Text 也接受（便于用 `websocat` 之类工具调试）。

use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::{Sink, Stream};
use llm_proxy_core::config::MAX_FRAME_BYTES;
use llm_proxy_core::Frame;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::Error as WsError;

use crate::session::{Mux, SessionError};

/// 把 WS 消息流适配成 [`Mux`] 需要的纯字节流。
pub struct BytesIo<S> {
    inner: S,
}

impl<S> BytesIo<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> Stream for BytesIo<S>
where
    S: Stream<Item = Result<Message, WsError>> + Unpin,
{
    type Item = Result<Vec<u8>, WsError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(b)))) => {
                    return Poll::Ready(Some(Ok(b.to_vec())))
                }
                Poll::Ready(Some(Ok(Message::Text(t)))) => {
                    return Poll::Ready(Some(Ok(t.as_bytes().to_vec())))
                }
                // 控制帧由 tungstenite 内部处理，这里直接跳过
                Poll::Ready(Some(Ok(Message::Ping(_))))
                | Poll::Ready(Some(Ok(Message::Pong(_))))
                | Poll::Ready(Some(Ok(Message::Frame(_)))) => continue,
                Poll::Ready(Some(Ok(Message::Close(_)))) => return Poll::Ready(None),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> Sink<Vec<u8>> for BytesIo<S>
where
    S: Sink<Message, Error = WsError> + Unpin,
{
    type Error = WsError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        Pin::new(&mut self.get_mut().inner).start_send(Message::Binary(item))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

/// 客户端：连上 server 的 WS 端点。
///
/// 同时支持 `ws://` 与 `wss://`。TLS 在客户端连接 Cloudflare Tunnel 等
/// HTTPS 入口时由 `tokio-tungstenite`/rustls 终止，服务端 origin 仍可使用
/// 本地明文 WS；DSHP 自己的 PSK + AEAD 握手继续覆盖隧道内容。
///
/// 返回 `(Mux, 会话级帧队列)`。会话级帧（`stream_id == 0`）用于 Hello/Caps/Err。
pub async fn connect(url: &str) -> Result<(Mux, tokio::sync::mpsc::Receiver<Frame>), SessionError> {
    // rustls 的 crypto provider 是**进程级、只能装一次**的。这里以前就地 `expect` ✗ ——
    // 那个 `Once` 只防住了"自己重复调用"，没防住**别的模块先装**：
    // 上游 TLS 路径（`upstream::connector`）在启动时就会先装 ⇒ 客户端一启动就 panic ✗✗，
    // 而且 panic 会**毒化这个 Once** ⇒ 之后每次连接都再炸一次（第 181 轮实测正是如此 ✓）。
    // ⇒ 收敛成一处（`crate::install_crypto_provider_once`），两边共用 ✓。
    crate::install_crypto_provider_once();
    let (ws, _resp) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| SessionError::Transport(format!("WS 连接失败 {url}: {e}")))?;
    Ok(Mux::spawn(BytesIo::new(ws), MAX_FRAME_BYTES))
}

/// 服务端：在已接受的 TCP 连接上完成 WS 握手。
pub async fn accept<S>(stream: S) -> Result<(Mux, tokio::sync::mpsc::Receiver<Frame>), SessionError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let ws = tokio_tungstenite::accept_async(stream)
        .await
        .map_err(|e| SessionError::Transport(format!("WS 握手失败: {e}")))?;
    Ok(Mux::spawn(BytesIo::new(ws), MAX_FRAME_BYTES))
}
