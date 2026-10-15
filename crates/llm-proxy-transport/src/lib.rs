//! DSHP 传输层：把「一条双向帧隧道」抽象成 [`Session`]，让上层不感知底层是
//! WS / SSE / KCP。
//!
//! M0 只实现 **WS 模式**；SSE 模式在 M3、KCP 在 M4。
//!
//! 降级链（设计 §10）：`KCP → WS → SSE → L2 直连上游 → L3 经 server 原样转发`。
//! 任何一档失败都必须能落到下一档，最终**绝不让 SDK 请求失败**。
#![forbid(unsafe_code)]

pub mod body;
pub mod fec;
pub mod fec_adapt;
pub mod kcp;
pub mod kcp_link;
pub mod session;
pub mod sse;
pub mod udp_handshake;
pub mod upstream;
pub mod ws;

pub use body::ChannelBody;
pub use session::SessionCrypto;
pub use session::{handshake_mac, verify_handshake, Caps, Mux, SessionError};
pub use sse::{ChunkReader, ChunkWriter, Duplex, OkSink, SseError, SseReader, SseWriter};
pub use ws::{accept, connect, BytesIo};

/// 装上 rustls 的进程级 crypto provider（**幂等**）。
///
/// 为什么收敛到一处：rustls 0.23 的 provider **进程级、只能装一次**，而本 crate 里
/// 有两条 TLS 用途（`wss://` 隧道、`https://` 上游）。原先各自装、各自 `expect` ✗
/// ⇒ 谁先装谁就把另一条打成 panic（第 181 轮实测：客户端一启动就 panic，
/// 并且 panic 会**毒化对方的 `Once`**，之后每次连接都再炸一次 ✗✗）。
///
/// 语义：**已经装过就用现成的** ✓ —— 只启用了 `ring` 一个 provider feature，
/// 所以"装过"必然是同一个 provider ✓，不是"配置被覆盖"✗。
pub fn install_crypto_provider_once() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
    });
}
