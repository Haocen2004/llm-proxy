//! 帧多路复用会话：把「一条双向帧隧道」抽象成可并发开流的能力。
//!
//! 上层（client / server）不感知底层是 WS / SSE / KCP，只跟 [`Mux`] 打交道。
//!
//! 多路复用是必需的而非优化：SDK 会流水线并发发起请求（实测同一 harness 在
//! 15 秒窗口内连续发 21 个请求），单流串行会让尾延迟叠加。

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use llm_proxy_core::crypto::{Direction, Opener, Sealer, SessionKeys};
use llm_proxy_core::{crc32c, Flags, Frame, FrameType};

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("连接已关闭")]
    Closed,
    #[error("握手失败：{0}")]
    Handshake(String),
    #[error("协议错误：{0}")]
    Protocol(String),
    #[error("传输错误：{0}")]
    Transport(String),
    #[error("认证失败：{0}")]
    Auth(String),
    #[error("缺少能力协商：{0}")]
    MissingCap(&'static str),
    #[error("AEAD 失败：{0}")]
    Crypto(String),
}

/// 会话级能力协商结果。两端必须一致，否则缓存命名空间会错位（设计 §4.1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caps {
    pub proto_version: String,
    pub dict_id: u32,
    pub upstream_host: String,
    pub window_log: u32,
    pub max_frame_bytes: u32,
    pub caps: Vec<String>,
}

impl Default for Caps {
    fn default() -> Self {
        Self {
            proto_version: llm_proxy_core::config::PROTO_VERSION.to_string(),
            dict_id: llm_proxy_core::dict::DICT_ID_NONE,
            upstream_host: String::new(),
            window_log: llm_proxy_core::config::WINDOW_LOG,
            max_frame_bytes: llm_proxy_core::config::MAX_FRAME_BYTES as u32,
            caps: Vec::new(),
        }
    }
}

/// 由底层流驱动的多路复用句柄。可克隆共享（内部均为 Arc）。
#[derive(Clone)]
pub struct Mux {
    tx: tokio::sync::mpsc::Sender<Frame>,
    routes: Arc<Mutex<HashMap<u32, tokio::sync::mpsc::Sender<Frame>>>>,
    /// 尚未绑定路由的**业务流**帧暂存区。
    ///
    /// 为什么必须有它：服务端要收到 `ReqOpen` 才知道有这条流，但在它调用
    /// `bind_stream` 之前，同一条流的后续帧（`BodyChunk`）可能已经被读到。
    /// 早先把这类帧直接丢进收件箱，结果被服务端当成无关帧忽略——请求体永远不完整，
    /// 上游请求不返回，双向互等形成死锁。
    ///
    /// 只暂存业务流帧；`stream_id == 0` 的会话级帧仍走收件箱。
    pending: Arc<Mutex<HashMap<u32, Vec<Frame>>>>,
    pending_bytes: Arc<std::sync::atomic::AtomicUsize>,
    closed: Arc<std::sync::atomic::AtomicBool>,
    dropped: Arc<std::sync::atomic::AtomicU64>,
    /// 收到的帧总数（解密后即计数）。见 [`Mux::received_frames`]。
    received: Arc<std::sync::atomic::AtomicU64>,
    /// 会话级 AEAD。握手完成前为 `None`，此时载荷明文。
    crypto: Arc<std::sync::RwLock<Option<Arc<SessionCrypto>>>>,
}

/// 暂存区上限。超出即丢弃并计数，避免未认证来源用海量 stream_id 撑爆内存。
const PENDING_MAX_STREAMS: usize = 32;
const PENDING_MAX_BYTES: usize = 2 << 20;

/// 进程级流 id 分配器（见 [`Mux::open_stream`] 的说明：sid 必须跨连接唯一 ✓）。
static NEXT_STREAM_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
impl Mux {
    /// 在一个已建立的双向字节流上启动收发任务。
    ///
    /// `io` 需同时实现 `Stream<Item = Result<Vec<u8>, E>>` 与 `Sink<Vec<u8>, Error = E>`；
    /// WS 的 `WebSocketStream` 通过 [`crate::ws`] 适配后正好满足。
    ///
    /// 返回 `(句柄, 收件箱)`：**会话级帧**（`stream_id == 0`）一律进收件箱。
    pub fn spawn<S, E>(io: S, max_frame_bytes: usize) -> (Self, tokio::sync::mpsc::Receiver<Frame>)
    where
        S: futures_util::Stream<Item = Result<Vec<u8>, E>>
            + futures_util::Sink<Vec<u8>, Error = E>
            + Send
            + Unpin
            + 'static,
        E: std::fmt::Debug + Send + 'static,
    {
        let (tx, rx) = tokio::sync::mpsc::channel::<Frame>(256);
        let (inbox_tx, inbox_rx) = tokio::sync::mpsc::channel::<Frame>(256);
        let routes: Arc<Mutex<HashMap<u32, tokio::sync::mpsc::Sender<Frame>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pending: Arc<Mutex<HashMap<u32, Vec<Frame>>>> = Arc::new(Mutex::new(HashMap::new()));
        let pending_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropped = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let received = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let crypto: Arc<std::sync::RwLock<Option<Arc<SessionCrypto>>>> =
            Arc::new(std::sync::RwLock::new(None));

        let (mut sink, mut stream) = io.split();

        // 写方向
        let mut outbound = rx;
        let closed_w = Arc::clone(&closed);
        let routes_w = Arc::clone(&routes);
        let pending_w = Arc::clone(&pending);
        let pending_bytes_w = Arc::clone(&pending_bytes);
        tokio::spawn(async move {
            while let Some(f) = outbound.recv().await {
                let bytes = f.encode();
                if sink.send(bytes).await.is_err() {
                    break;
                }
            }
            // 写不出去同样是"链路已死"。不在这里收尾的话，`is_closed()` 要等到
            // 读方向也发现（可能更晚），而**在途请求**则完全没有机会醒来。
            closed_w.store(true, Ordering::SeqCst);
            let live = abort_streams(&routes_w, &pending_w, &pending_bytes_w);
            if live > 0 {
                tracing::warn!(streams = live, "链路写端结束，已中止在途流");
            }
            let _ = sink.close().await;
        });

        // 读方向：0 号进收件箱；已绑定的进路由；未绑定的进暂存区
        let routes_r = Arc::clone(&routes);
        let pending_r = Arc::clone(&pending);
        let pending_bytes_r = Arc::clone(&pending_bytes);
        let dropped_r = Arc::clone(&dropped);
        let received_r = Arc::clone(&received);
        let closed_r = Arc::clone(&closed);
        let crypto_r = Arc::clone(&crypto);
        tokio::spawn(async move {
            'read: while let Some(item) = stream.next().await {
                let bytes = match item {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::debug!(?e, "传输读端结束");
                        break;
                    }
                };
                // 一次读可能带回多帧（底层不保证帧边界与消息边界一致）
                let mut buf = bytes.as_slice();
                loop {
                    match Frame::decode(buf, max_frame_bytes) {
                        Ok(Some((mut f, used))) => {
                            buf = &buf[used..];

                            // **解密必须在这里**：早于任何路由决策。
                            // 被篡改的帧绝不允许进入路由——否则一次认证失败只会在某条
                            // 业务流上表现为"数据不对"，而不是"连接有问题"。
                            let crypto_now = crypto_r.read().unwrap().clone();
                            if let Some(c) = crypto_now {
                                if let Err(e) = c.open_frame(&mut f) {
                                    tracing::error!(?e, "AEAD 认证失败，终止连接");
                                    break 'read;
                                }
                            }
                            received_r.fetch_add(1, Ordering::Relaxed);
                            let sid = f.stream_id;

                            // 会话级帧走收件箱，流级帧走该流的通道。
                            //
                            // 判据用 `FrameType::is_session_level()`，而不是"`sid == 0`"——
                            // 后者只是**当前**的约定，前者写明了意图（`Hello`/`Caps`/
                            // `Ping`/`Pong`/`GoAway` 与流无关，不该因为对端把 sid 写错
                            // 就塞进某条流的通道）。这个 helper 长期没人调用，
                            // 是第 39 轮函数级门禁（`cargo run -p dev-tools -- gates`）
                            // 查出来的——一个"写明了意图却没人用"的判据。
                            if sid == 0 || f.ty.is_session_level() {
                                // 控制帧不能用 try_send 丢弃：Cancel 丢失会泄漏服务端
                                // 的活跃槽位，GoAway/Pong 丢失会破坏会话生命周期。
                                // 这里让读取任务在收件箱满时背压底层连接，业务帧仍可
                                // 继续由其它已绑定 stream 路由。
                                if inbox_tx.send(f).await.is_err() {
                                    break 'read;
                                }
                                continue;
                            }

                            let target = routes_r.lock().unwrap().get(&sid).cloned();
                            if let Some(s) = target {
                                if s.try_send(f).is_err() {
                                    routes_r.lock().unwrap().remove(&sid);
                                    dropped_r.fetch_add(1, Ordering::Relaxed);
                                }
                                continue;
                            }

                            // 未绑定。分两种情况：
                            //   * 该流**首次**出现 → 送收件箱，这是服务端发现新流的信号
                            //     （它必须是 ReqOpen，服务端据此才可能 bind_stream）
                            //   * 该流已出现但尚未绑定 → 暂存，等 bind_stream 按序冲刷
                            // 早先把两者都丢进收件箱，导致抢先到达的 BodyChunk 被服务端
                            // 当成无关帧忽略，请求体永远不完整 → 双向互等死锁。
                            let sz = f.payload.len() + llm_proxy_core::HEADER_LEN;
                            let mut p = pending_r.lock().unwrap();
                            let first = !p.contains_key(&sid);
                            if first && p.len() >= PENDING_MAX_STREAMS {
                                drop(p);
                                dropped_r.fetch_add(1, Ordering::Relaxed);
                                tracing::warn!(stream_id = sid, "暂存流数超限，丢弃帧");
                                continue;
                            }
                            let cur = pending_bytes_r.load(Ordering::Relaxed);
                            if !first && cur + sz > PENDING_MAX_BYTES {
                                drop(p);
                                dropped_r.fetch_add(1, Ordering::Relaxed);
                                tracing::warn!(stream_id = sid, "暂存字节超限，丢弃帧");
                                continue;
                            }
                            p.entry(sid).or_default();
                            drop(p);

                            if first {
                                if inbox_tx.try_send(f).is_err() {
                                    dropped_r.fetch_add(1, Ordering::Relaxed);
                                    tracing::warn!(stream_id = sid, "收件箱已满，丢弃流的首帧");
                                }
                            } else {
                                pending_r.lock().unwrap().get_mut(&sid).unwrap().push(f);
                                pending_bytes_r.fetch_add(sz, Ordering::Relaxed);
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            tracing::warn!(?e, "帧解码失败，终止连接");
                            break 'read;
                        }
                    }
                }
            }
            closed_r.store(true, Ordering::SeqCst);
            abort_streams(&routes_r, &pending_r, &pending_bytes_r);
        });

        (
            Self {
                tx,
                routes,
                pending,
                pending_bytes,
                closed,
                dropped,
                received,
                crypto,
            },
            inbox_rx,
        )
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// 因路由缺失或暂存超限被丢弃的帧数。非 0 说明有正确性风险，应告警。
    pub fn dropped_frames(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// **收到的帧总数**（解密之后、路由之前就计数）。
    ///
    /// 与 [`Self::dropped_frames`] 对称：两者一起能把"帧到底走到哪一步"钉死——
    /// `received` 没涨说明帧**从未到达本端**，`received` 涨了而 `dropped`/路由都没动静
    /// 说明帧被吞在中间。缺口 8 排查时正是缺这一个数。
    pub fn received_frames(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }

    /// 开一条新流，返回 `(stream_id, 该流的帧接收端)`。
    ///
    /// ⚠️ **sid 必须跨连接唯一**（第 189 轮修）✓ —— 原来这个计数器是**每条连接一个**
    /// （`self.next_id` ✗）⇒ 每条新连接都从 **1** 开始 ✗ ⇒ **跨连接 sid 复用** ✓✓：
    /// 老连接上"已经用到 id 52"的那条流，其在途帧可能被投给**新连接**上 id 空间只有
    /// 1~15 的流 ✗ ⇒ 客户端查不到那个模板 ⇒ `UnknownTemplate` ✗
    /// ⇒ 按 M7 红线**主动截断**（绝不给半截内容 ✓）⇒ SDK 看到传输错误
    /// ⇒ 线上表现就是 **`terminated`** ✓✓。
    /// 现场判据（已取到 ✓）：`UnknownTemplate(52)` 且 `template_store_held=15`、
    /// `id_min=1` ⇒ 表**不空也没满** ✓ ⇒ 既不是 LRU 淘汰、也不是"换了新表" ✓ ⇒ 只能是投错流 ✓。
    ///
    /// 改成**进程级单调分配** ✓ ⇒ 老连接的残留帧**永远投不到**新流上 ✓（sid 不同 ✓），
    /// **不动协议、不改帧格式** ✓，只让 id 不再重复 ✓。
    /// 32 位回绕（约 42 亿条流）时可能与仍在途的流撞上 ✗ —— 概率可忽略 ✓，
    /// 且撞上时的表现仍是上面那条"如实截断" ✓（绝不会拼出错误内容 ✓）。
    pub fn open_stream(&self) -> (u32, tokio::sync::mpsc::Receiver<Frame>) {
        loop {
            let id = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
            if id == 0 {
                continue; // 0 保留给会话级帧
            }
            let rx = self.bind_stream(id);
            return (id, rx);
        }
    }

    /// 绑定某个 stream_id 的入站帧接收端，并把**此前抢先到达的帧**按序冲进去。
    pub fn bind_stream(&self, id: u32) -> tokio::sync::mpsc::Receiver<Frame> {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let buffered = self.pending.lock().unwrap().remove(&id).unwrap_or_default();
        if !buffered.is_empty() {
            let bytes: usize = buffered
                .iter()
                .map(|f| f.payload.len() + llm_proxy_core::HEADER_LEN)
                .sum();
            self.pending_bytes.fetch_sub(bytes, Ordering::Relaxed);
        }
        self.routes.lock().unwrap().insert(id, tx.clone());
        // 先冲入已有帧，再暴露路由：这样即使冲刷过程中又有新帧到达，
        // 它们也会走 tx 而不是重回暂存区，顺序不会乱。
        for f in buffered {
            if tx.try_send(f).is_err() {
                tracing::warn!(stream_id = id, "冲刷暂存帧失败，路由已满");
                break;
            }
        }
        rx
    }

    pub fn unbind_stream(&self, id: u32) {
        // 释放该流的重放水位与发送序号；stream_id 单调递增不复用，所以安全
        if let Some(c) = self.crypto.read().unwrap().clone() {
            c.forget_stream(id);
        }
        self.routes.lock().unwrap().remove(&id);
        if let Some(v) = self.pending.lock().unwrap().remove(&id) {
            let bytes: usize = v
                .iter()
                .map(|f| f.payload.len() + llm_proxy_core::HEADER_LEN)
                .sum();
            self.pending_bytes.fetch_sub(bytes, Ordering::Relaxed);
        }
    }

    /// 发送帧。会话级帧用 `stream_id == 0`。
    ///
    /// 握手完成后载荷会被 AEAD 封装（`Hello`/`Caps` 除外），帧的 `seq` 字段被
    /// 批次序号接管——协议逻辑从不读取它。
    pub async fn send(&self, f: Frame) -> Result<(), SessionError> {
        if self.is_closed() {
            return Err(SessionError::Closed);
        }
        let f = self.seal_if_enabled(f)?;
        self.tx.send(f).await.map_err(|_| SessionError::Closed)
    }

    /// 发送帧但允许来自非 async 上下文（路由任务内部使用）。
    pub fn try_send(&self, f: Frame) -> Result<(), SessionError> {
        if self.is_closed() {
            return Err(SessionError::Closed);
        }
        let f = self.seal_if_enabled(f)?;
        self.tx.try_send(f).map_err(|_| SessionError::Closed)
    }

    /// 握手完成后开启 AEAD。可重复调用（第二次覆盖，用于重连后换密钥）。
    pub fn enable_crypto(&self, c: SessionCrypto) {
        *self.crypto.write().unwrap() = Some(Arc::new(c));
    }

    pub fn crypto_enabled(&self) -> bool {
        self.crypto.read().unwrap().is_some()
    }

    /// `(已加密, 已解密, 豁免明文)`；未启用 AEAD 时返回 `None`。
    pub fn crypto_stats(&self) -> Option<(u64, u64, u64)> {
        self.crypto.read().unwrap().as_ref().map(|c| c.stats())
    }

    fn seal_if_enabled(&self, mut f: Frame) -> Result<Frame, SessionError> {
        let c = self.crypto.read().unwrap().clone();
        if let Some(c) = c {
            c.seal_frame(&mut f)?;
        }
        Ok(f)
    }

    /// 发送一条会话级帧（`stream_id = 0`）。
    pub async fn send_session(&self, ty: FrameType, payload: Vec<u8>) -> Result<(), SessionError> {
        self.send(Frame::new(ty, 0, 0, payload)).await
    }
}

/// 会话级 AEAD 状态。
///
/// # 为什么批次序号必须由这里分配，不能沿用调用方给的 `seq`
///
/// 调用方会在 `Err`、`Ping`、`ReqOpen` 这类帧上重复使用 `seq = 0`。若直接拿它当 AEAD
/// 的批次序号，就会**在同一个 `(key, stream_id, seq)` 上用两次 nonce**——对
/// ChaCha20-Poly1305 而言这是唯一的致命误用，会直接丧失机密性且**不会报错**。
///
/// 因此这里用 [`Sealer`] 自己的**全局单调计数器**分配序号，并把它写回帧的 `seq` 字段
/// 传给对端（接收方据此重建 nonce）。全局单调比"每流一个计数器"更强：它顺带保证
/// 同一 nonce 绝不会在不同流之间重复。
///
/// 代价是 `Frame::seq` 的语义被 AEAD 接管——**已确认协议逻辑从不读取该字段**，
/// 只在构造时赋值。
pub struct SessionCrypto {
    sealer: Mutex<Sealer>,
    opener: Mutex<Opener>,
    dir_out: Direction,
    dir_in: Direction,
    /// 观测计数：证明加密**真的在执行**，而不是静默没启用。
    sealed: std::sync::atomic::AtomicU64,
    opened: std::sync::atomic::AtomicU64,
    /// 因 `Hello`/`Caps` 而放行明文的次数（应当恰好 1）。
    exempt: std::sync::atomic::AtomicU64,
}

impl SessionCrypto {
    /// `is_client` 决定本端在哪个方向上发送。
    pub fn new(keys: &SessionKeys, is_client: bool) -> Self {
        let (dir_out, dir_in, sealer, opener) = if is_client {
            (
                Direction::ClientToServer,
                Direction::ServerToClient,
                keys.sealer_for_client(),
                keys.opener_for_client(),
            )
        } else {
            (
                Direction::ServerToClient,
                Direction::ClientToServer,
                keys.sealer_for_server(),
                keys.opener_for_server(),
            )
        };
        Self {
            sealer: Mutex::new(sealer),
            opener: Mutex::new(opener),
            dir_out,
            dir_in,
            sealed: std::sync::atomic::AtomicU64::new(0),
            opened: std::sync::atomic::AtomicU64::new(0),
            exempt: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// 返回 `(已加密帧数, 已解密帧数, 豁免明文帧数)`。
    pub fn stats(&self) -> (u64, u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        (
            self.sealed.load(Relaxed),
            self.opened.load(Relaxed),
            self.exempt.load(Relaxed),
        )
    }

    /// 加密一帧的载荷（就地）。`Hello`/`Caps` 原样放行——它们要在密钥建立前交换。
    pub fn seal_frame(&self, f: &mut Frame) -> Result<(), SessionError> {
        if !llm_proxy_core::crypto::needs_protection(f.ty) {
            self.exempt
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(());
        }
        // 取号 → 写回帧 → 用含该序号的 AAD 加密。全程持同一把锁，
        // 保证「序号分配顺序」与「帧实际发出的顺序」在单条流内一致。
        let mut s = self.sealer.lock().unwrap();
        let seq = s.reserve_seq();
        f.seq = seq as u32;
        let aad = llm_proxy_core::crypto::aead_aad(f.ty.as_u8(), f.stream_id, f.seq);
        let ct = s
            .seal_reserved(f.stream_id, self.dir_out, &aad, &f.payload)
            .map_err(|e| SessionError::Crypto(e.to_string()))?;
        f.payload = ct;
        f.flags = Flags(f.flags.0 | llm_proxy_core::flags::ENCRYPTED);
        self.sealed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// 解密一帧的载荷（就地）。未标记 `ENCRYPTED` 的帧原样放行。
    pub fn open_frame(&self, f: &mut Frame) -> Result<(), SessionError> {
        if !f.flags.contains(llm_proxy_core::flags::ENCRYPTED) {
            return Ok(());
        }
        let aad = llm_proxy_core::crypto::aead_aad(f.ty.as_u8(), f.stream_id, f.seq);
        let pt = self
            .opener
            .lock()
            .unwrap()
            .open(f.stream_id, self.dir_in, f.seq as u64, &aad, &f.payload)
            .map_err(|e| SessionError::Crypto(e.to_string()))?;
        f.payload = pt;
        f.flags = Flags(f.flags.0 & !llm_proxy_core::flags::ENCRYPTED);
        self.opened
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    pub fn forget_stream(&self, sid: u32) {
        self.opener.lock().unwrap().forget_stream(sid);
    }
}

impl std::fmt::Debug for SessionCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCrypto")
            .field("dir_out", &self.dir_out)
            .field("dir_in", &self.dir_in)
            .finish_non_exhaustive()
    }
}

/// 认证：握手 HMAC。
///
/// 设计 §13.5：`HELLO` 带单调 nonce 与时间戳，配合 ±120s 时间窗防重放。
pub fn handshake_mac(psk: &[u8], nonce: u64, timestamp_ms: i64) -> Vec<u8> {
    let key = blake3_of(psk);
    let mut msg = Vec::with_capacity(16);
    msg.extend_from_slice(&nonce.to_le_bytes());
    msg.extend_from_slice(&timestamp_ms.to_le_bytes());
    blake3::keyed_hash(&key, &msg).as_bytes().to_vec()
}

/// 校验握手 HMAC 与时间窗。返回 Err 时应拒绝连接。
pub fn verify_handshake(
    psk: &[u8],
    nonce: u64,
    timestamp_ms: i64,
    mac: &[u8],
    now_ms: i64,
) -> Result<(), SessionError> {
    const WINDOW_MS: i64 = 120_000;
    if (now_ms - timestamp_ms).abs() > WINDOW_MS {
        return Err(SessionError::Auth(format!(
            "时间戳超出 ±{}s 窗口",
            WINDOW_MS / 1000
        )));
    }
    let expect = handshake_mac(psk, nonce, timestamp_ms);
    // 定时比较，避免时序侧信道
    if !ct_eq(&expect, mac) {
        return Err(SessionError::Auth("HMAC 不匹配".into()));
    }
    Ok(())
}

fn blake3_of(psk: &[u8]) -> [u8; 32] {
    *blake3::hash(psk).as_bytes()
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// 链路结束时的收尾：**丢掉每条流的发送端**，让在途请求立刻看到明确错误。
///
/// 只置 `closed` 是不够的：`is_closed()` 只在 `route()` 里被**新请求**检查，
/// 而**在途请求**正阻塞在 `rx.recv()` 上。发送端如果还活着（它挂在 `routes` 里、
/// 被 `Arc<Mux>` 保着），`rx.recv()` 就永远不返回——链路已经死了，请求却
/// **永久挂住**，SDK 既拿不到结果也拿不到错误（设计 §16 M7 不允许）。
///
/// 实测：一条 700 KB 的请求在传输中途断链后，客户端一直挂到测试 90s 超时。
/// 清空之后，在途流的 `recv()` 立刻得到 `None`，"等待响应头时连接关闭"
/// 与"未收到 RespEnd"两条红线判断才能生效。
fn abort_streams(
    routes: &Mutex<HashMap<u32, tokio::sync::mpsc::Sender<Frame>>>,
    pending: &Mutex<HashMap<u32, Vec<Frame>>>,
    pending_bytes: &std::sync::atomic::AtomicUsize,
) -> usize {
    let live = {
        let mut r = routes.lock().unwrap();
        let n = r.len();
        r.clear();
        n
    };
    pending.lock().unwrap().clear();
    pending_bytes.store(0, Ordering::SeqCst);
    live
}

/// 构造一个 Ping 帧，便于保活。载荷为 CRC32C 校验用的会话标识，无业务含义。
pub fn ping_frame() -> Frame {
    Frame::new(
        FrameType::Ping,
        0,
        0,
        crc32c(b"dshp").to_le_bytes().to_vec(),
    )
}

/// 构造一个**取消帧**：客户端放弃某条流。
///
/// 刻意做成**会话级**帧（`stream_id = 0`），目标流写在**载荷**里（4 字节 LE）。
/// 理由见 `FrameType::is_session_level` 的文档：缺口 8 实测"流级"取消帧在客户端
/// 入队后到不了对端，而会话级帧（`KeyConfirm`/`Ping`）走的是已被证明能到达的路径。
pub fn cancel_frame(sid: u32) -> Frame {
    Frame::new(FrameType::Cancel, 0, 0, sid.to_le_bytes().to_vec())
}

/// 从取消帧载荷里取回目标 stream_id。载荷不合法时返回 `None`。
pub fn cancel_target(f: &Frame) -> Option<u32> {
    if f.ty != FrameType::Cancel {
        return None;
    }
    let b: [u8; 4] = f.payload.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_verifies() {
        let psk = b"secret";
        let nonce = 42u64;
        let ts = 1_700_000_000_000i64;
        let mac = handshake_mac(psk, nonce, ts);
        assert!(verify_handshake(psk, nonce, ts, &mac, ts).is_ok());
        assert!(verify_handshake(psk, nonce, ts, &mac, ts + 60_000).is_ok());
    }

    #[test]
    fn handshake_rejects_replay_window_and_wrong_key() {
        let psk = b"secret";
        let nonce = 42u64;
        let ts = 1_700_000_000_000i64;
        let mac = handshake_mac(psk, nonce, ts);
        // 超出时间窗
        assert!(verify_handshake(psk, nonce, ts, &mac, ts + 121_000).is_err());
        // 错误密钥
        assert!(verify_handshake(b"other", nonce, ts, &mac, ts).is_err());
        // 篡改 nonce
        assert!(verify_handshake(psk, nonce + 1, ts, &mac, ts).is_err());
    }

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    // ---- 路由竞态回归测试 ----
    //
    // 这条测试锁住的是一个真实死锁：服务端要收到 ReqOpen 才知道有这条流，
    // 但同一条流的后续 BodyChunk 可能已经被读到。若把它们一并丢进收件箱，
    // 服务端会当成无关帧忽略 → 请求体永远不完整 → 上游不返回 → 双向互等。

    struct TestIo {
        rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
        tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    }

    impl futures_util::Stream for TestIo {
        type Item = Result<Vec<u8>, std::io::Error>;
        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            self.rx.poll_recv(cx).map(|o| o.map(Ok))
        }
    }

    impl futures_util::Sink<Vec<u8>> for TestIo {
        type Error = std::io::Error;
        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn start_send(self: std::pin::Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
            self.tx
                .send(item)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "closed"))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn first_frame_is_a_discovery_signal_rest_buffer_until_bind() {
        let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (out_tx, _out_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (mux, mut inbox) = Mux::spawn(
            TestIo {
                rx: in_rx,
                tx: out_tx,
            },
            4096,
        );

        // 会话级帧
        in_tx
            .send(Frame::new(FrameType::Caps, 0, 0, vec![]).encode())
            .unwrap();
        // 5 号流：首帧（发现信号）+ 两个后续帧（抢跑）
        in_tx
            .send(Frame::new(FrameType::ReqOpen, 5, 0, b"open".to_vec()).encode())
            .unwrap();
        in_tx
            .send(Frame::new(FrameType::BodyChunk, 5, 1, b"part1".to_vec()).encode())
            .unwrap();
        in_tx
            .send(Frame::new(FrameType::BodyChunk, 5, 2, b"part2".to_vec()).encode())
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        // 收件箱里应当只有会话级帧 + 5 号流的**首帧**
        let f1 = inbox.try_recv().expect("Caps 应在收件箱");
        assert_eq!(f1.ty, FrameType::Caps);
        let f2 = inbox.try_recv().expect("ReqOpen 应作为发现信号进收件箱");
        assert_eq!(f2.ty, FrameType::ReqOpen);
        assert_eq!(f2.stream_id, 5);
        assert!(inbox.try_recv().is_err(), "后续帧不应进收件箱");

        // 绑定后，抢跑的两个 BodyChunk 必须按序到达，一个都不能少
        let mut rx5 = mux.bind_stream(5);
        let mut got = Vec::new();
        while let Ok(Some(f)) =
            tokio::time::timeout(std::time::Duration::from_millis(200), rx5.recv()).await
        {
            got.push(f.payload);
        }
        assert_eq!(
            got,
            vec![b"part1".to_vec(), b"part2".to_vec()],
            "抢跑帧必须按序冲刷，不得丢失或乱序"
        );
        assert_eq!(mux.dropped_frames(), 0);
    }

    #[tokio::test]
    async fn binding_before_any_traffic_routes_directly() {
        let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (out_tx, _out_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (mux, mut inbox) = Mux::spawn(
            TestIo {
                rx: in_rx,
                tx: out_tx,
            },
            4096,
        );

        let mut rx7 = mux.bind_stream(7);
        in_tx
            .send(Frame::new(FrameType::RespData, 7, 1, b"hi".to_vec()).encode())
            .unwrap();

        let f = tokio::time::timeout(std::time::Duration::from_millis(200), rx7.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(f.payload, b"hi");
        assert!(inbox.try_recv().is_err(), "已绑定的流不应进收件箱");
    }

    #[tokio::test]
    async fn unbind_clears_buffer_and_accounting() {
        let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (out_tx, _out_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (mux, _inbox) = Mux::spawn(
            TestIo {
                rx: in_rx,
                tx: out_tx,
            },
            4096,
        );
        for i in 0..3u32 {
            in_tx
                .send(Frame::new(FrameType::BodyChunk, 9, i, vec![0u8; 32]).encode())
                .unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        mux.unbind_stream(9);
        assert_eq!(
            mux.pending_bytes.load(Ordering::Relaxed),
            0,
            "解绑必须归还暂存字节计数，否则会慢性泄漏预算"
        );
    }
}

/// **第 189 轮：`sid` 必须跨连接唯一** ✓ —— 现场 `terminated` 的根因。
///
/// 曾经的 `open_stream` 用**每条连接一个**的计数器 ⇒ 每条新连接都从 `1` 开始 ✗
/// ⇒ 老连接上"已用到 id 52"的流，其在途帧会被投给**新连接**上 id 空间只有 1~15 的流 ✗
/// ⇒ 客户端在批量帧里查不到那个模板 ⇒ `UnknownTemplate` ✗ ⇒ 按 M7 红线主动截断 ✓
/// ⇒ SDK 看到传输错误 ⇒ 线上表现 `terminated` ✓✓。
#[cfg(test)]
mod stream_id_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};
    use std::sync::RwLock;

    /// 直接构造一个 `Mux` 骨架：本用例只关心 **id 分配** ✓，不碰任何 IO ✓。
    /// （测试与 `Mux` 同模块 ⇒ 私有字段可见 ✓。）
    fn new_mux() -> Mux {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        Mux {
            tx,
            routes: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            pending_bytes: Arc::new(AtomicUsize::new(0)),
            closed: Arc::new(AtomicBool::new(false)),
            dropped: Arc::new(AtomicU64::new(0)),
            received: Arc::new(AtomicU64::new(0)),
            crypto: Arc::new(RwLock::new(None)),
        }
    }

    #[test]
    fn stream_ids_are_never_reused_across_connections() {
        // 关键性质：**两条不同连接**（各自一个 Mux ✓）开流时**不得拿到同一个 sid** ✓。
        // 负向对照：把 `open_stream` 改回 `self.next_id`（每连接计数 ✓）⇒ 本用例立即变红 ✓✓。
        let mut seen = std::collections::HashSet::new();
        for conn in 0..8 {
            let mux = new_mux();
            for _ in 0..4 {
                let (sid, _rx) = mux.open_stream();
                assert_ne!(sid, 0, "0 保留给会话级帧 ✓");
                assert!(
                    seen.insert(sid),
                    "sid {sid} 在第 {conn} 条连接上被**重复**分配 ✗"
                );
            }
        }
        // 反向：同一连接内部也必须唯一 ✓
        let mux = new_mux();
        let mut local = std::collections::HashSet::new();
        for _ in 0..16 {
            let (sid, _rx) = mux.open_stream();
            assert!(local.insert(sid), "同一连接内 sid {sid} 重复 ✗");
        }
    }
}
