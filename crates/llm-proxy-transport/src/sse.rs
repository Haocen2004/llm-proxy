//! SSE 传输模式（M3）：用**单次 HTTP 往返**承载一条双向帧隧道。
//!
//! # 它为什么存在
//!
//! 设计 §10 把它列为 WS 之后的第二档，理由是**企业代理常常放通 POST，却拦掉
//! WebSocket 的 `Upgrade`**。WS 一被拦，客户端就只剩"直连上游"（L2）这一条路——
//! 功能还在，但增量和模板收益全丢。SSE 模式补上的正是这一段：
//! 只要中间设备允许**流式 HTTP**，隧道就能立起来。
//!
//! # 形态
//!
//! ```text
//! client ──POST /__dshp/tunnel──▶ server     请求体 = 帧流（4B 大端长度前缀，二进制）
//! client ◀──text/event-stream─── server      响应体 = 帧流（每帧一个 SSE 事件）
//! ```
//!
//! 两个方向的编码**刻意不对称**：
//!
//! * 请求体是普通 POST body，**没有文本约束**，所以直接用长度前缀的二进制，不付膨胀；
//! * 响应体是 `text/event-stream`，`data:` 只能承载文本、且换行就是事件分隔符，
//!   所以必须 base64——付 33% 膨胀，换来任何 HTTP 中间设备都能原样转发。
//!
//! 能省下的膨胀就不付。
//!
//! # 一个必须说清的局限
//!
//! 这个模式要求中间设备支持**长连接的流式 HTTP**。设计 §10 提到"仅短连接 HTTP/1.1"
//! 的极端环境——那种环境下**任何隧道模式都立不起来**（WS 和 SSE 都不行），
//! 只剩 L2 直连上游。所以它的实际定位是：**WS 被拦、但流式 HTTP 可用**的常见企业网络。

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use base64::Engine;
use bytes::Bytes;
use futures_util::{Sink, Stream};

/// 请求方向帧的长度前缀字节数。
pub const LEN_PREFIX: usize = 4;
/// 单帧上限（与 [`llm_proxy_core::config::MAX_FRAME_BYTES`] 一致，留出前缀余量）。
pub const MAX_TUNNEL_FRAME: usize = llm_proxy_core::config::MAX_FRAME_BYTES;
/// SSE 事件累积缓冲上限。超限说明对端在发一个永远不结束的事件——必须拒绝而不是无限涨内存。
pub const MAX_EVENT_BUF: usize = MAX_TUNNEL_FRAME * 2;

#[derive(Debug, thiserror::Error)]
pub enum SseError {
    #[error("SSE 事件解码失败：{0}")]
    Decode(String),
    #[error("底层传输错误：{0}")]
    Inner(String),
    #[error("隧道已关闭")]
    Closed,
    #[error("单帧 {0} 字节超过上限 {MAX_TUNNEL_FRAME}")]
    TooLarge(usize),
}

fn inner<E: std::fmt::Display>(e: E) -> SseError {
    SseError::Inner(e.to_string())
}

// ---------------------------------------------------------------------------
// 编解码
// ---------------------------------------------------------------------------

/// 帧 → 一个 SSE 事件：`data: <base64>\n\n`。
pub fn encode_event(frame: &[u8]) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(frame);
    let mut out = Vec::with_capacity(b64.len() + 8);
    out.extend_from_slice(b"data: ");
    out.extend_from_slice(b64.as_bytes());
    out.extend_from_slice(b"\n\n");
    out
}

/// 从一段完整 SSE 事件里取出 `data:` 载荷并 base64 解码。
///
/// 只认 `data:` 字段；注释行（`:` 开头）、`event:`/`id:` 一律忽略——这样
/// `curl` 手看流量时看到的东西和解析结果不会互相干扰。
/// 返回 `None` 表示这个事件里**根本没有 `data:` 字段**（心跳、注释），应当忽略；
/// 返回 `Some(vec![])` 表示这是一个**载荷为空的合法帧**（零长帧是协议允许的）。
///
/// 这两种情况必须分开：早先我把它们都当成"空"处理，结果丢掉了合法的空帧。
/// 这类混淆不会报错，只会**悄悄丢数据**。
pub fn decode_event(ev: &[u8]) -> Result<Option<Vec<u8>>, SseError> {
    let text = std::str::from_utf8(ev).map_err(|e| SseError::Decode(e.to_string()))?;
    let mut payload = String::new();
    // **判据是「有没有 data 字段」，不是「载荷是否为空」。**
    // `data:` 后面什么都不写是一个合法的**空帧**；完全没有 data 字段的事件
    // （纯注释 / 心跳）才应当被忽略。早先我按"载荷为空"判断，把合法空帧也一起丢了——
    // 这类混淆不会报错，只会悄悄丢数据。
    let mut saw_data = false;
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let Some(rest) = line.strip_prefix("data:") else {
            continue;
        };
        saw_data = true;
        // SSE 规定：紧跟冒号的一个前导空格要去掉
        payload.push_str(rest.strip_prefix(' ').unwrap_or(rest));
    }
    if !saw_data {
        return Ok(None);
    }
    if payload.is_empty() {
        return Ok(Some(Vec::new()));
    }
    base64::engine::general_purpose::STANDARD
        .decode(payload.as_bytes())
        .map(Some)
        .map_err(|e| SseError::Decode(e.to_string()))
}

/// 帧 → 长度前缀块（请求方向）。
pub fn encode_chunk(frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(LEN_PREFIX + frame.len());
    out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    out.extend_from_slice(frame);
    out
}

// ---------------------------------------------------------------------------
// 读入适配器：字节流 → 帧流
// ---------------------------------------------------------------------------

/// `Stream<Item = Bytes>`（SSE 事件流）→ 帧流。
pub struct SseReader<S> {
    inner: S,
    buf: Vec<u8>,
    ready: VecDeque<Vec<u8>>,
    done: bool,
}

impl<S> SseReader<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            ready: VecDeque::new(),
            done: false,
        }
    }
}

/// `Stream<Item = Bytes>`（长度前缀块流）→ 帧流。
pub struct ChunkReader<S> {
    inner: S,
    buf: Vec<u8>,
    ready: VecDeque<Vec<u8>>,
    done: bool,
}

impl<S> ChunkReader<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            ready: VecDeque::new(),
            done: false,
        }
    }
}

impl<S> SseReader<S> {
    /// 把一个**致命**解码错误标记为"流就此结束"，并返回它。
    ///
    /// 为什么必须这么做：`poll_next` 在返回错误后仍会被再次调用。如果缓冲区没被清掉，
    /// 下一次调用会看到同样的数据、返回同样的错误——上层 `collect` 会无限累积错误
    /// （实测直接吃到 64GB 后 OOM），真实链路里则是读取循环空转烧 CPU。
    /// 所以**任何不可恢复的解码错误都必须同时终止这个流**。
    fn fatal(&mut self, e: SseError) -> SseError {
        self.buf.clear();
        self.ready.clear();
        self.done = true;
        e
    }
}

impl<S> ChunkReader<S> {
    /// 同 [`SseReader::fatal`]。
    fn fatal(&mut self, e: SseError) -> SseError {
        self.buf.clear();
        self.ready.clear();
        self.done = true;
        e
    }
}

impl<S, E> Stream for SseReader<S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    type Item = Result<Vec<u8>, SseError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(f) = this.ready.pop_front() {
                return Poll::Ready(Some(Ok(f)));
            }
            if this.done {
                return Poll::Ready(None);
            }
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(b))) => {
                    this.buf.extend_from_slice(&b);
                    if this.buf.len() > MAX_EVENT_BUF {
                        // 对端发了一个永不结束的事件 → 拒绝，而不是让内存无限涨。
                        // **必须同时终止这个流**：只返回错误不清缓冲的话，下一次 poll
                        // 会看到同样的缓冲、返回同样的错误——`collect` 就会无限累积，
                        // 实测直接吃到 64GB 然后 OOM。真实链路里则表现为读取循环空转烧 CPU。
                        return Poll::Ready(Some(Err(
                            this.fatal(SseError::TooLarge(this.buf.len()))
                        )));
                    }
                    // 切出所有**完整**事件；半个事件留在缓冲里等下一片
                    while let Some(end) = llm_proxy_json::sse::next_event_end(&this.buf) {
                        let ev: Vec<u8> = this.buf.drain(..end).collect();
                        match decode_event(&ev) {
                            // 无 `data:` 的事件（注释、心跳）直接忽略，不是错误
                            Ok(None) => {}
                            Ok(Some(f)) => this.ready.push_back(f),
                            Err(e) => return Poll::Ready(Some(Err(this.fatal(e)))),
                        }
                    }
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(inner(e)))),
                Poll::Ready(None) => {
                    this.done = true;
                    // 收尾：残留的不完整事件必须报错。
                    // 静默丢弃等于把"隧道被截断"伪装成"正常结束"——
                    // 那正是设计 §16 M7 明确禁止的"静默错误"。
                    if !this.buf.is_empty() {
                        return Poll::Ready(Some(Err(this.fatal(SseError::Decode(format!(
                            "隧道结束时残留 {} 字节不完整事件",
                            this.buf.len()
                        ))))));
                    }
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S, E> Stream for ChunkReader<S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    type Item = Result<Vec<u8>, SseError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            // 先把缓冲里能切出的帧全部切出来
            loop {
                if this.buf.len() < LEN_PREFIX {
                    break;
                }
                let n = u32::from_be_bytes(this.buf[..LEN_PREFIX].try_into().expect("长度已检查"))
                    as usize;
                if n > MAX_TUNNEL_FRAME {
                    // 同上：致命错误必须一起终止流，否则同一个错误会被无限返回
                    return Poll::Ready(Some(Err(this.fatal(SseError::TooLarge(n)))));
                }
                if this.buf.len() < LEN_PREFIX + n {
                    break;
                }
                let frame: Vec<u8> = this.buf[LEN_PREFIX..LEN_PREFIX + n].to_vec();
                this.buf.drain(..LEN_PREFIX + n);
                this.ready.push_back(frame);
            }
            if let Some(f) = this.ready.pop_front() {
                return Poll::Ready(Some(Ok(f)));
            }
            if this.done {
                return Poll::Ready(None);
            }
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(b))) => this.buf.extend_from_slice(&b),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(inner(e)))),
                Poll::Ready(None) => {
                    this.done = true;
                    if !this.buf.is_empty() {
                        return Poll::Ready(Some(Err(this.fatal(SseError::Decode(format!(
                            "隧道结束时残留 {} 字节不完整帧",
                            this.buf.len()
                        ))))));
                    }
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 写出适配器：帧流 → 字节流
// ---------------------------------------------------------------------------

/// 帧流 → SSE 事件字节。
pub struct SseWriter<W> {
    inner: W,
}

impl<W> SseWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }
}

/// 帧流 → 长度前缀块字节。
pub struct ChunkWriter<W> {
    inner: W,
}

impl<W> ChunkWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }
}

macro_rules! writer_impl {
    ($t:ident, $encode:expr) => {
        impl<W, E> Sink<Vec<u8>> for $t<W>
        where
            W: Sink<Bytes, Error = E> + Unpin,
            E: std::fmt::Display,
        {
            type Error = SseError;

            fn poll_ready(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Result<(), SseError>> {
                let this = self.get_mut();
                Pin::new(&mut this.inner).poll_ready(cx).map_err(inner)
            }

            fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), SseError> {
                if item.len() > MAX_TUNNEL_FRAME {
                    return Err(SseError::TooLarge(item.len()));
                }
                let this = self.get_mut();
                let bytes = Bytes::from($encode(&item));
                Pin::new(&mut this.inner).start_send(bytes).map_err(inner)
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Result<(), SseError>> {
                let this = self.get_mut();
                Pin::new(&mut this.inner).poll_flush(cx).map_err(inner)
            }

            fn poll_close(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Result<(), SseError>> {
                let this = self.get_mut();
                Pin::new(&mut this.inner).poll_close(cx).map_err(inner)
            }
        }
    };
}

writer_impl!(SseWriter, encode_event);
writer_impl!(ChunkWriter, encode_chunk);

// ---------------------------------------------------------------------------
// 双向合成
// ---------------------------------------------------------------------------

/// 把分离的写出端与读入端合成为 [`crate::Mux`] 需要的 `Stream + Sink`。
///
/// HTTP 隧道天然是"一个方向一个对象"（请求体 sink + 响应体 stream），
/// 而 Mux 要的是单个双向对象，所以需要这一层粘合。
pub struct Duplex<W, R> {
    sink: W,
    stream: R,
    ready: VecDeque<Vec<u8>>,
    sink_closed: bool,
}

impl<W, R> Duplex<W, R> {
    pub fn new(sink: W, stream: R) -> Self {
        Self {
            sink,
            stream,
            ready: VecDeque::new(),
            sink_closed: false,
        }
    }
}

impl<W, R, E> Stream for Duplex<W, R>
where
    W: Unpin,
    R: Stream<Item = Result<Vec<u8>, E>> + Unpin,
{
    type Item = Result<Vec<u8>, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let Some(f) = this.ready.pop_front() {
            return Poll::Ready(Some(Ok(f)));
        }
        Pin::new(&mut this.stream).poll_next(cx)
    }
}

impl<W, R> Sink<Vec<u8>> for Duplex<W, R>
where
    W: Sink<Vec<u8>, Error = SseError> + Unpin,
    R: Unpin,
{
    type Error = SseError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SseError>> {
        let this = self.get_mut();
        if this.sink_closed {
            return Poll::Ready(Err(SseError::Closed));
        }
        Pin::new(&mut this.sink).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), SseError> {
        let this = self.get_mut();
        Pin::new(&mut this.sink).start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SseError>> {
        let this = self.get_mut();
        Pin::new(&mut this.sink).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SseError>> {
        let this = self.get_mut();
        this.sink_closed = true;
        Pin::new(&mut this.sink).poll_close(cx)
    }
}

/// 把 `Sink<Result<Bytes, E>>` 适配成 `Sink<Bytes>`。
///
/// 存在的理由：响应体的产出端（`futures-channel` 的 sender、以及任何
/// `http_body::Body` 的产出端）接收的是 `Result<Bytes, E>`，而隧道只需要吐 `Bytes`
/// ——"永远成功"这件事由上层决定。
///
/// 错误统一映射成 [`SseError`]，这样上层不必知道底层 sender 的错误类型
/// （`futures-channel` 的 `SendError` 与 `hyper` 的 `Error` 是两回事）。
///
/// 带 `PhantomData` 是因为 `E`/`SE` 只出现在 impl 的 where 子句里；不写进类型，
/// Rust 无法把它们约束到 impl 上（`E0207`）。
pub struct OkSink<W, E, SE> {
    inner: W,
    _p: std::marker::PhantomData<(E, SE)>,
}

impl<W, E, SE> OkSink<W, E, SE> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            _p: std::marker::PhantomData,
        }
    }
}

impl<W, E, SE> Sink<Bytes> for OkSink<W, E, SE>
where
    W: Sink<Result<Bytes, E>, Error = SE> + Unpin,
    SE: std::fmt::Display,
    E: Unpin,
    SE: Unpin,
{
    type Error = SseError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SseError>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_ready(cx).map_err(inner)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), SseError> {
        let this = self.get_mut();
        Pin::new(&mut this.inner)
            .start_send(Ok(item))
            .map_err(inner)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SseError>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx).map_err(inner)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SseError>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_close(cx).map_err(inner)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;

    /// 收集流用一个小型 current-thread 运行时；
    /// 不为测试新开 `futures-util` 的 `executor` feature（依赖面越小越好）。
    fn block<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("运行时")
            .block_on(f)
    }

    fn feed(parts: &[&[u8]]) -> Vec<Result<Vec<u8>, SseError>> {
        let chunks: Vec<Result<Bytes, std::io::Error>> =
            parts.iter().map(|p| Ok(Bytes::from(p.to_vec()))).collect();
        let s = futures_util::stream::iter(chunks);
        block(SseReader::new(s).collect::<Vec<_>>())
    }

    fn feed_chunks(parts: &[&[u8]]) -> Vec<Result<Vec<u8>, SseError>> {
        let chunks: Vec<Result<Bytes, std::io::Error>> =
            parts.iter().map(|p| Ok(Bytes::from(p.to_vec()))).collect();
        let s = futures_util::stream::iter(chunks);
        block(ChunkReader::new(s).collect::<Vec<_>>())
    }

    #[test]
    fn sse_event_roundtrip_with_binary_payload() {
        // 含换行、NUL、非 UTF-8 字节——base64 存在的理由就是这些
        let frame: Vec<u8> = (0u8..=255).collect();
        let ev = encode_event(&frame);
        assert!(ev.starts_with(b"data: "));
        assert!(ev.ends_with(b"\n\n"));
        assert!(ev.is_ascii(), "SSE 事件必须是纯 ASCII 文本");
        assert_eq!(decode_event(&ev).unwrap().unwrap(), frame);
    }

    #[test]
    fn empty_frame_roundtrips() {
        let ev = encode_event(&[]);
        // 空载荷是一个**合法帧**，不是"无 data 字段的心跳"
        assert_eq!(decode_event(&ev).unwrap(), Some(Vec::<u8>::new()));
    }

    /// 最关键的一条：SSE 事件可能被 TCP 切成任意片到达。
    #[test]
    fn event_split_across_reads_is_reassembled() {
        let frame = b"hello-dshp-frame".to_vec();
        let ev = encode_event(&frame);
        // 按 1 字节切片喂进去——最坏情况
        let parts: Vec<&[u8]> = ev.chunks(1).collect();
        let out = feed(&parts);
        assert_eq!(out.len(), 1, "应恰好得到一个帧");
        assert_eq!(out[0].as_ref().unwrap(), &frame);
    }

    #[test]
    fn multiple_events_in_one_read_are_split() {
        let a = b"AAAA".to_vec();
        let b = b"BBBBBBBB".to_vec();
        let mut buf = encode_event(&a);
        buf.extend_from_slice(&encode_event(&b));
        let out = feed(&[&buf]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].as_ref().unwrap(), &a);
        assert_eq!(out[1].as_ref().unwrap(), &b);
    }

    #[test]
    fn crlf_terminated_events_also_work() {
        // 有些实现（和某些中间设备）会把换行改写成 CRLF
        let frame = b"payload".to_vec();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&frame);
        let ev = format!("data: {b64}\r\n\r\n").into_bytes();
        assert_eq!(decode_event(&ev).unwrap().unwrap(), frame);
        let out = feed(&[&ev]);
        assert_eq!(out[0].as_ref().unwrap(), &frame);
    }

    #[test]
    fn comment_and_heartbeat_events_are_ignored() {
        let frame = b"real".to_vec();
        let mut buf = b": keep-alive\n\n".to_vec();
        buf.extend_from_slice(&encode_event(&frame));
        buf.extend_from_slice(b"event: ping\n\n");
        let out = feed(&[&buf]);
        assert_eq!(out.len(), 1, "无 data 的事件应当被忽略，而不是产出空帧");
        assert_eq!(
            decode_event(b": keep-alive\n\n").unwrap(),
            None,
            "心跳没有 data 字段"
        );
        assert_eq!(out[0].as_ref().unwrap(), &frame);
    }

    /// 隧道被截断必须**报错**，不能静默当成正常结束。
    #[test]
    fn truncated_event_is_an_error_not_silent_eof() {
        let frame = b"complete".to_vec();
        let mut buf = encode_event(&frame);
        buf.extend_from_slice(b"data: aGVsbG8"); // 缺 \n\n
        let out = feed(&[&buf]);
        assert_eq!(out.len(), 2);
        assert!(out[0].is_ok(), "完整的那条应正常交付");
        assert!(
            out[1].is_err(),
            "残留的不完整事件必须是错误——静默丢弃等于把截断伪装成正常结束"
        );
    }

    #[test]
    fn chunk_framing_roundtrip() {
        let frame = b"0123456789".to_vec();
        let c = encode_chunk(&frame);
        assert_eq!(&c[..4], &[0, 0, 0, 10], "4 字节大端长度前缀");
        assert_eq!(&c[4..], &frame);
    }

    #[test]
    fn chunk_split_across_reads_is_reassembled() {
        let a = b"first-frame".to_vec();
        let b = b"second".to_vec();
        let mut buf = encode_chunk(&a);
        buf.extend_from_slice(&encode_chunk(&b));
        let parts: Vec<&[u8]> = buf.chunks(3).collect();
        let out = feed_chunks(&parts);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].as_ref().unwrap(), &a);
        assert_eq!(out[1].as_ref().unwrap(), &b);
    }

    #[test]
    fn truncated_chunk_is_an_error() {
        let a = b"complete".to_vec();
        let mut buf = encode_chunk(&a);
        buf.extend_from_slice(&[0, 0, 0, 9]); // 声称 9 字节却一个都没给
        let out = feed_chunks(&[&buf]);
        assert!(out[0].is_ok());
        assert!(out[1].is_err(), "声明的长度没给够，必须报错");
    }

    #[test]
    fn implausible_chunk_length_is_rejected_early() {
        // 声称 1GB：不能等它真的把内存储满才拒绝
        let mut buf = vec![0x40, 0x00, 0x00, 0x00];
        buf.extend_from_slice(b"x");
        let out = feed_chunks(&[&buf]);
        assert!(matches!(out[0], Err(SseError::TooLarge(_))));
        // **必须只有一项**：致命错误之后就结束了，绝不能继续返回同一个错误
        // （那样上层 collect 会无限累积 —— 实测 OOM）
        assert_eq!(
            out.len(),
            1,
            "致命错误后流必须终止，而不是反复返回同一个错误"
        );
    }

    #[test]
    fn empty_frame_chunk_roundtrip() {
        let c = encode_chunk(&[]);
        assert_eq!(c, vec![0, 0, 0, 0]);
        let out = feed_chunks(&[&c]);
        assert_eq!(out[0].as_deref().unwrap(), &[] as &[u8]);
    }

    /// 编码一轮再解码一轮，必须**逐字节一致**——这是整个隧道模式的前提。
    #[test]
    fn full_tunnel_roundtrip_is_byte_exact() {
        let frames: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"small".to_vec(),
            (0u8..=255).collect(),
            vec![0x55u8; 100_000],
        ];
        let mut sse = Vec::new();
        let mut raw = Vec::new();
        for f in &frames {
            sse.extend_from_slice(&encode_event(f));
            raw.extend_from_slice(&encode_chunk(f));
        }
        let from_sse: Vec<Vec<u8>> = feed(&[&sse]).into_iter().map(|r| r.unwrap()).collect();
        let from_raw: Vec<Vec<u8>> = feed_chunks(&[&raw])
            .into_iter()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(from_sse, frames);
        assert_eq!(from_raw, frames);
    }

    /// 两种编码的体积代价对比。这个不对称是刻意的：能省下的膨胀就不付。
    #[test]
    fn sse_inflates_by_a_third_but_the_request_direction_does_not() {
        let frame = vec![0x5Au8; 60_000];
        let sse = encode_event(&frame).len();
        let raw = encode_chunk(&frame).len();
        let sse_over = sse as f64 / frame.len() as f64;
        let raw_over = raw as f64 / frame.len() as f64;
        println!(
            "  [SSE 编码] 帧 {} B → SSE {sse} B（{:.1}%）｜长度前缀 {raw} B（{:.2}%）",
            frame.len(),
            sse_over * 100.0,
            raw_over * 100.0
        );
        assert!(
            (sse_over - 4.0 / 3.0).abs() < 0.05,
            "SSE 方向的 base64 膨胀应约 33%（实测 {:.1}%）",
            sse_over * 100.0
        );
        assert!(
            raw_over < 1.01,
            "请求方向不该有膨胀（实测 {:.2}%）",
            raw_over * 100.0
        );
    }
}
