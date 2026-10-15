//! 把 DSHP 帧流桥接成 `http_body::Body`。
//!
//! 请求与响应两个方向都需要它：DSHP 是帧流，hyper 需要 `Body`。
//! 这里刻意**不缓冲**——SSE 的逐 token 实时性依赖背压，缓冲会破坏它。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use tokio::sync::mpsc;

/// 由 channel 驱动的 body。发送端被 drop 即表示流结束。
pub struct ChannelBody {
    rx: mpsc::Receiver<Result<Bytes, io::Error>>,
    exact: Option<u64>,
    done: bool,
}

impl ChannelBody {
    /// 容量刻意取小：软路由内存受限，而且小队列本身就是背压。
    pub const DEFAULT_CAPACITY: usize = 8;

    pub fn new(rx: mpsc::Receiver<Result<Bytes, io::Error>>) -> Self {
        Self {
            rx,
            exact: None,
            done: false,
        }
    }

    /// 建立 `(发送端, body)` 对。
    pub fn channel() -> (mpsc::Sender<Result<Bytes, io::Error>>, Self) {
        let (tx, rx) = mpsc::channel(Self::DEFAULT_CAPACITY);
        (tx, Self::new(rx))
    }

    /// 声明确切的字节数。
    ///
    /// 当上游/客户端给了 `Content-Length` 时必须设置：否则 hyper 会改用分块编码，
    /// 而我们已经转发了 `Content-Length` 头，两者不一致会导致请求失败。
    pub fn with_exact_size(mut self, n: u64) -> Self {
        self.exact = Some(n);
        self
    }

    pub fn exact_size(&self) -> Option<u64> {
        self.exact
    }
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match this.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(b))) => Poll::Ready(Some(Ok(Frame::data(b)))),
            Poll::Ready(Some(Err(e))) => {
                this.done = true;
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }

    fn size_hint(&self) -> SizeHint {
        match self.exact {
            Some(n) => SizeHint::with_exact(n),
            None => SizeHint::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn relays_bytes_in_order_and_ends_on_drop() {
        let (tx, body) = ChannelBody::channel();
        tokio::spawn(async move {
            for chunk in [b"one".as_slice(), b"two", b"three"] {
                tx.send(Ok(Bytes::copy_from_slice(chunk))).await.unwrap();
            }
            drop(tx);
        });
        let collected = body.collect().await.unwrap().to_bytes();
        assert_eq!(&collected[..], b"onetwothree");
    }

    #[tokio::test]
    async fn exact_size_is_reported() {
        let (_tx, body) = ChannelBody::channel();
        let body = body.with_exact_size(42);
        assert_eq!(body.size_hint().exact(), Some(42));
        assert_eq!(body.exact_size(), Some(42));
    }

    #[tokio::test]
    async fn unknown_size_stays_unknown() {
        let (_tx, body) = ChannelBody::channel();
        assert_eq!(body.size_hint().exact(), None);
    }

    #[tokio::test]
    async fn error_propagates() {
        let (tx, body) = ChannelBody::channel();
        tx.send(Err(io::Error::other("boom"))).await.unwrap();
        let res = body.collect().await;
        assert!(res.is_err());
    }
}
