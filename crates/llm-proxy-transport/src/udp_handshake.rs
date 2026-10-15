//! UDP 抗反射放大握手（设计 §13.6）。
//!
//! # 为什么必须有它
//!
//! KCP 跑在 UDP 上，UDP **可以伪造源地址**。一个没有防护的握手意味着：
//! 攻击者用受害者的地址发一个小请求，服务端回一个大响应 —— 服务端就成了
//! 一台 DDoS 放大器（设计 §13.1 的威胁 T6）。放大倍数就是"响应/请求"的体积比。
//!
//! 设计 §13.6 给的四条约束，逐条对应到实现：
//!
//! 1. **未验证对端地址前，回包不得超过请求包大小** —— 由 [`ServerHandshake::reply`]
//!    统一把关：它是**唯一**的出口，任何超包都在这里被丢掉并计数。
//!    把约束做成结构性的，而不是靠每个分支自己记得检查。
//! 2. 两轮握手：`HELLO → COOKIE → HELLO+COOKIE → ACK`
//! 3. `COOKIE` 无状态生成：`blake3_keyed(secret, 对端地址 ‖ 时间片)`。
//!    服务端**不需要为未认证来源保存任何东西**就能事后验证它。
//! 4. 未通过认证的包**不创建任何状态**。`sessions` 只在 cookie 验证通过后才插入。
//!
//! # 为什么 `HELLO` 必须带填充
//!
//! 约束 1 反过来要求：**客户端的首个包必须足够大**，否则"回包不超过请求"就没法满足
//! ——COOKIE 响应本身就有 21 字节。所以 `HELLO` 强制填充到 [`MIN_HELLO`]
//! （QUIC 的 1200 字节初始包是同一个道理）。小于它的包**一个字节都不回**。

use std::collections::HashMap;
use std::net::SocketAddr;

/// `HELLO` 的最小长度。任何回包都不会超过它，因此放大倍数被钉死在 ≤1。
///
/// 取 64 而不是 QUIC 的 1200：DSHP 的握手载荷很小，64 已经足够容纳任何回包，
/// 也不至于让每个握手都白扔 1KB。
pub const MIN_HELLO: usize = 64;

/// cookie 长度。128 位足够抗伪造，且让明文包保持短小。
pub const COOKIE_LEN: usize = 16;

/// 时间片长度（毫秒）。cookie 的有效期 = 2 个时间片。
pub const EPOCH_MS: u64 = 60_000;

pub const T_HELLO: u8 = 1;
pub const T_COOKIE: u8 = 2;
pub const T_HELLO_COOKIE: u8 = 3;
pub const T_ACK: u8 = 4;

#[derive(Debug, PartialEq, Eq)]
pub enum HandshakeError {
    /// 包比 `HELLO` 的最小长度还短——**不回任何东西**。
    TooSmall(usize),
    UnknownType(u8),
    Malformed,
    /// cookie 不符（地址不对 / 过期 / 伪造）。
    BadCookie,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooSmall(n) => write!(f, "包只有 {n} 字节，小于最小 HELLO ({MIN_HELLO})"),
            Self::UnknownType(t) => write!(f, "未知握手类型 {t}"),
            Self::Malformed => write!(f, "握手包畸形"),
            Self::BadCookie => write!(f, "cookie 校验失败"),
        }
    }
}

impl std::error::Error for HandshakeError {}

/// ACK 的认证密钥长度。
pub const ACK_MAC_LEN: usize = 16;

/// 由 PSK 派生 ACK 认证密钥。
///
/// **客户端必须验证 ACK 的 HMAC**：否则盲目的路径外攻击者只要能猜中 conv，
/// 就能跟客户端"完成"握手——客户端随后会把业务数据发给一个它并不认识的对端。
/// 服务端的 ACK 里带上 `PRF(psk, nonce ‖ conv ‖ 对端地址)`，客户端据此确认
/// 对面确实持有同一个 PSK。
fn ack_key(psk: &[u8]) -> [u8; 32] {
    let key = blake3::hash(psk);
    let mut out = [0u8; 32];
    out.copy_from_slice(blake3::keyed_hash(key.as_bytes(), b"dshp/1 udp-ack-mac").as_bytes());
    out
}

/// 计算 ACK 的认证标签：`PRF(psk, nonce ‖ conv)`。
///
/// # 为什么不绑定地址（这一点我写错过一次）
///
/// 最初我把"对端地址"也放进了 MAC 输入。结果**永远验证不过**：
/// 服务端拿到的是**客户端**的地址，客户端知道的却是**服务端**的地址，
/// 两边喂进去的东西不可能相同。
///
/// 更根本的是：**客户端无法可靠地知道自己对外可见的地址**（NAT 后面就不是它 bind 的那个）。
/// 所以地址绑定只应该出现在**服务端能自己观测到地址**的那一步——
/// 也就是 COOKIE，那里服务端看到的就是客户端的真实源地址，而客户端只是原样回送。
///
/// ACK 这边要防的是"猜中 conv 的路径外攻击者伪造 ACK"，靠的是
/// **每次握手都不同的 nonce** 加上 PSK——两者都不需要地址。
pub fn ack_mac(psk: &[u8], nonce: &[u8; 8], conv: u32) -> [u8; ACK_MAC_LEN] {
    let k = ack_key(psk);
    let mut msg = Vec::with_capacity(12);
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(&conv.to_le_bytes());
    let h = blake3::keyed_hash(&k, &msg);
    let mut out = [0u8; ACK_MAC_LEN];
    out.copy_from_slice(&h.as_bytes()[..ACK_MAC_LEN]);
    out
}

/// 无状态 cookie 的密钥与生成/验证。
#[derive(Clone)]
pub struct CookieKey {
    secret: [u8; 32],
}

impl std::fmt::Debug for CookieKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CookieKey(<redacted>)")
    }
}

impl CookieKey {
    /// 由 PSK 派生。
    ///
    /// 用 PSK 而不是进程随机数，是为了让服务端**重启后仍在途的握手依然有效**——
    /// 随机密钥会让每次重启都产生一批验证不过的 cookie，客户端只能重试。
    /// 时效性由时间片保证，不依赖"每次启动换密钥"。
    pub fn from_psk(psk: &[u8]) -> Self {
        let mut secret = [0u8; 32];
        let key = blake3::hash(psk);
        let h = blake3::keyed_hash(key.as_bytes(), b"dshp/1 udp-cookie-key");
        secret.copy_from_slice(h.as_bytes());
        Self { secret }
    }

    fn epoch_of(&self, now_ms: u64) -> u64 {
        now_ms / EPOCH_MS
    }

    /// `COOKIE = PRF(secret, 对端地址 ‖ 时间片)`。
    ///
    /// 绑地址是**关键**：不绑的话，攻击者拿到一个 cookie 就能从任意伪造源地址复用，
    /// 放大防护形同虚设。
    pub fn issue(&self, addr: &SocketAddr, epoch: u64) -> [u8; COOKIE_LEN] {
        let mut msg = Vec::with_capacity(24);
        match addr {
            SocketAddr::V4(a) => {
                msg.extend_from_slice(&a.ip().octets());
                msg.extend_from_slice(&a.port().to_le_bytes());
            }
            SocketAddr::V6(a) => {
                msg.extend_from_slice(&a.ip().octets());
                msg.extend_from_slice(&a.port().to_le_bytes());
            }
        }
        msg.extend_from_slice(&epoch.to_le_bytes());
        let h = blake3::keyed_hash(&self.secret, &msg);
        let mut out = [0u8; COOKIE_LEN];
        out.copy_from_slice(&h.as_bytes()[..COOKIE_LEN]);
        out
    }

    /// 校验：接受**当前与上一个**时间片。
    ///
    /// 接受两个片而不是一个，是为了避免"客户端刚拿到 cookie、服务端就翻片"这
    /// 一秒内的必然失败。再往前的不接受——那等于把有效期拉长到任意长。
    pub fn verify(&self, addr: &SocketAddr, cookie: &[u8], now_ms: u64) -> bool {
        if cookie.len() != COOKIE_LEN {
            return false;
        }
        let cur = self.epoch_of(now_ms);
        for epoch in [cur, cur.saturating_sub(1)] {
            if crate::session::ct_eq(&self.issue(addr, epoch), cookie) {
                return true;
            }
        }
        false
    }
}

/// 服务端对每个收到的数据报要采取的动作。
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// 什么都不做（畸形、未认证、或回包会超限）。
    Drop,
    /// 回一个包。
    Reply(Vec<u8>),
    /// 握手完成：**同时**给出要回的 ACK 与建立的 `conv`。
    ///
    /// 不让调用方自己拼 ACK：那一来容易漏、二来会绕过下面那道放大检查
    /// （检查只看 `Reply`）。把 ACK 一并放在这里，它就同样被管住了。
    Established { conv: u32, ack: Vec<u8> },
}

/// 服务端握手状态机。
pub struct ServerHandshake {
    key: CookieKey,
    psk: Vec<u8>,
    /// **只有通过 cookie 验证的地址**才会出现在这里。
    sessions: HashMap<SocketAddr, u32>,
    next_conv: u32,
    /// 因"回包会超过请求包"而被拦下的次数。它必须是 0——不为 0 就说明
    /// 某条路径突破了 §13.6 的约束 1。
    pub suppressed_replies: u64,
    /// 未通过认证就被丢弃的包数。
    pub rejected: u64,
}

impl ServerHandshake {
    pub fn new(psk: &[u8]) -> Self {
        Self {
            key: CookieKey::from_psk(psk),
            psk: psk.to_vec(),
            sessions: HashMap::new(),
            next_conv: 1,
            suppressed_replies: 0,
            rejected: 0,
        }
    }

    /// 已建立的会话数。用于断言"未认证来源不占状态"。
    pub fn tracked_peers(&self) -> usize {
        self.sessions.len()
    }

    /// 处理一个数据报。
    ///
    /// `request_len` 就是 `data.len()`；单独传是为了让"回包不超过请求"
    /// 这条约束在签名上就看得见。
    pub fn on_datagram(&mut self, addr: SocketAddr, data: &[u8], now_ms: u64) -> Action {
        match self.handle(addr, data, now_ms) {
            Ok(a) => {
                // **唯一的出口**：在这里统一执行放大防护。
                // 把约束做成结构性的，而不是指望每条分支自己记得检查。
                let reply: Option<&Vec<u8>> = match &a {
                    Action::Reply(r) => Some(r),
                    Action::Established { ack, .. } => Some(ack),
                    Action::Drop => None,
                };
                if let Some(r) = reply {
                    if r.len() > data.len() {
                        self.suppressed_replies += 1;
                        return Action::Drop;
                    }
                }
                a
            }
            Err(_) => {
                self.rejected += 1;
                Action::Drop
            }
        }
    }

    fn handle(
        &mut self,
        addr: SocketAddr,
        data: &[u8],
        now_ms: u64,
    ) -> Result<Action, HandshakeError> {
        if data.len() < MIN_HELLO {
            // 太短：**一个字节都不回**。这也是"客户端首个包必须够大"的执行点。
            return Err(HandshakeError::TooSmall(data.len()));
        }
        let ty = data[0];
        match ty {
            T_HELLO => {
                // 第一轮：只发 cookie，**不创建任何状态**。
                let epoch = self.key.epoch_of(now_ms);
                let cookie = self.key.issue(&addr, epoch);
                let mut out = Vec::with_capacity(1 + COOKIE_LEN + 8);
                out.push(T_COOKIE);
                out.extend_from_slice(&cookie);
                out.extend_from_slice(&epoch.to_le_bytes());
                Ok(Action::Reply(out))
            }
            T_HELLO_COOKIE => {
                // 第二轮：验证 cookie。**只有到这里才可能建状态**。
                if data.len() < 1 + 8 + COOKIE_LEN {
                    return Err(HandshakeError::Malformed);
                }
                let cookie = &data[9..9 + COOKIE_LEN];
                if !self.key.verify(&addr, cookie, now_ms) {
                    return Err(HandshakeError::BadCookie);
                }
                let conv = match self.sessions.get(&addr) {
                    // 重复的 HELLO+COOKIE：回同一个 conv，不新建。
                    // 建新的会让重传把会话数刷爆（每包一个新会话）。
                    Some(c) => *c,
                    None => {
                        let c = self.next_conv;
                        self.next_conv = self.next_conv.wrapping_add(1).max(1);
                        self.sessions.insert(addr, c);
                        c
                    }
                };
                let nonce: [u8; 8] = data[1..9].try_into().expect("长度已检查");
                let mut ack = Vec::with_capacity(1 + 4 + ACK_MAC_LEN);
                ack.push(T_ACK);
                ack.extend_from_slice(&conv.to_le_bytes());
                ack.extend_from_slice(&ack_mac(&self.psk, &nonce, conv));
                Ok(Action::Established { conv, ack })
            }
            other => Err(HandshakeError::UnknownType(other)),
        }
    }

    pub fn forget(&mut self, addr: &SocketAddr) {
        self.sessions.remove(addr);
    }
}

/// 客户端握手状态机。
pub struct ClientHandshake {
    nonce: [u8; 8],
    psk: Vec<u8>,
    state: State,
    conv: Option<u32>,
    /// 已重试次数（HELLO 无响应时重发）
    pub retries: u32,
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    Init,
    SentHello,
    Established,
}

impl ClientHandshake {
    /// `nonce` 由调用方提供（通常是 CSPRNG），便于测试里固定它。
    pub fn new(nonce: [u8; 8], psk: &[u8]) -> Self {
        Self {
            nonce,
            psk: psk.to_vec(),
            state: State::Init,
            conv: None,
            retries: 0,
        }
    }

    /// 生成首个 `HELLO`。**填充到 [`MIN_HELLO`]**，这样服务端的任何回包都不会超限。
    pub fn hello(&self) -> Vec<u8> {
        let mut out = vec![0u8; MIN_HELLO];
        out[0] = T_HELLO;
        out[1..9].copy_from_slice(&self.nonce);
        out
    }

    /// 处理服务端回包；返回下一个要发的包（或 `None`）。
    pub fn on_datagram(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, HandshakeError> {
        match data.first().copied() {
            Some(T_COOKIE) => {
                if data.len() < 1 + COOKIE_LEN {
                    return Err(HandshakeError::Malformed);
                }
                let mut out = Vec::with_capacity(MIN_HELLO);
                out.push(T_HELLO_COOKIE);
                out.extend_from_slice(&self.nonce);
                out.extend_from_slice(&data[1..1 + COOKIE_LEN]);
                // 同样填充：第二轮的请求也不能比第一轮小
                out.resize(MIN_HELLO, 0);
                self.state = State::SentHello;
                Ok(Some(out))
            }
            Some(T_ACK) => {
                if data.len() < 1 + 4 + ACK_MAC_LEN {
                    return Err(HandshakeError::Malformed);
                }
                let conv = u32::from_le_bytes(data[1..5].try_into().expect("长度已检查"));
                if conv == 0 {
                    return Err(HandshakeError::Malformed);
                }
                // **必须验证**：不验的话，猜中 conv 的攻击者就能让我们
                // 把业务数据发给一个并不持有 PSK 的对端。
                let want = ack_mac(&self.psk, &self.nonce, conv);
                if !crate::session::ct_eq(&want, &data[5..5 + ACK_MAC_LEN]) {
                    return Err(HandshakeError::BadCookie);
                }
                self.conv = Some(conv);
                self.state = State::Established;
                Ok(None)
            }
            Some(other) => Err(HandshakeError::UnknownType(other)),
            None => Err(HandshakeError::TooSmall(0)),
        }
    }

    pub fn established(&self) -> Option<u32> {
        self.conv
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), port)
    }

    fn keys() -> (ServerHandshake, ClientHandshake) {
        (ServerHandshake::new(b"test-psk-0123456789"), {
            ClientHandshake::new([1, 2, 3, 4, 5, 6, 7, 8], b"test-psk-0123456789")
        })
    }

    /// 完整两轮握手。
    #[test]
    fn full_handshake_establishes() {
        let (mut s, mut c) = keys();
        let a = addr(4000);

        let hello = c.hello();
        let cookie = match s.on_datagram(a, &hello, 0) {
            Action::Reply(r) => r,
            other => panic!("期望 COOKIE 回复，实际 {other:?}"),
        };
        let second = c.on_datagram(&cookie).unwrap().expect("应产出第二个包");
        let ack = match s.on_datagram(a, &second, 0) {
            Action::Established { conv, ack } => {
                assert_eq!(c.established(), None, "客户端还没收到 ACK");
                assert_eq!(conv, 1);
                ack
            }
            other => panic!("期望建立会话，实际 {other:?}"),
        };
        // 客户端收到 ACK 才算完成
        c.on_datagram(&ack).unwrap();
        assert_eq!(c.established(), Some(1));
        assert_eq!(s.tracked_peers(), 1);
    }

    /// **约束 1**：任何回包都不得超过请求包大小。这是抗放大的全部意义。
    #[test]
    fn no_reply_is_ever_larger_than_the_request() {
        let (mut s, mut c) = keys();
        let a = addr(4001);
        let hello = c.hello();
        let cookie = match s.on_datagram(a, &hello, 0) {
            Action::Reply(r) => {
                assert!(
                    r.len() <= hello.len(),
                    "COOKIE 回复 {} 字节 > HELLO {} 字节 —— 这就是放大",
                    r.len(),
                    hello.len()
                );
                r
            }
            other => panic!("{other:?}"),
        };
        let second = c.on_datagram(&cookie).unwrap().unwrap();
        // 第二轮的回复也不得超限
        if let Action::Established { ack, .. } = s.on_datagram(a, &second, 0) {
            assert!(
                ack.len() <= second.len(),
                "ACK {} 字节 > 请求 {} 字节 —— 这就是放大",
                ack.len(),
                second.len()
            );
        }
        assert_eq!(s.suppressed_replies, 0, "不应有任何被压制的回包");
    }

    /// **约束 4**：未通过认证的包不创建任何状态。
    #[test]
    fn unauthenticated_packets_create_no_state() {
        let (mut s, mut c) = keys();
        let a = addr(4002);

        // 只发 HELLO：应当只回 cookie，不建会话
        let hello = c.hello();
        let _ = s.on_datagram(a, &hello, 0);
        assert_eq!(s.tracked_peers(), 0, "仅 HELLO 不得建会话");

        // cookie 伪造：不得建会话
        let mut bad = vec![T_HELLO_COOKIE];
        bad.extend_from_slice(&[0u8; 8]);
        bad.extend_from_slice(&[0u8; COOKIE_LEN]);
        bad.resize(MIN_HELLO, 0);
        assert_eq!(s.on_datagram(a, &bad, 0), Action::Drop);
        assert_eq!(s.tracked_peers(), 0, "伪造 cookie 不得建会话");

        // 畸形与未知类型
        let mut junk = vec![99u8];
        junk.resize(MIN_HELLO, 0);
        assert_eq!(s.on_datagram(a, &junk, 0), Action::Drop);
        let short = vec![T_HELLO; 8]; // 小于 MIN_HELLO
        assert_eq!(s.on_datagram(a, &short, 0), Action::Drop);
        assert_eq!(s.tracked_peers(), 0, "畸形包不得建会话");

        // 走完整流程后才应出现一个
        let cookie = match s.on_datagram(a, &c.hello(), 0) {
            Action::Reply(r) => r,
            other => panic!("{other:?}"),
        };
        let second = c.on_datagram(&cookie).unwrap().unwrap();
        let _ = s.on_datagram(a, &second, 0);
        assert_eq!(s.tracked_peers(), 1);
    }

    /// cookie **绑定地址**：换个源地址就不能用。
    ///
    /// 不绑的话，攻击者拿一个 cookie 就能从任意伪造源地址复用，放大防护形同虚设。
    #[test]
    fn cookie_is_bound_to_the_source_address() {
        let key = CookieKey::from_psk(b"psk");
        let c = key.issue(&addr(5000), 10);
        assert!(key.verify(&addr(5000), &c, 10 * EPOCH_MS));
        assert!(
            !key.verify(&addr(5001), &c, 10 * EPOCH_MS),
            "换了端口就不该通过"
        );
        let other = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 5000);
        assert!(!key.verify(&other, &c, 10 * EPOCH_MS), "换了 IP 就不该通过");
    }

    /// cookie **绑定时间**：接受当前与上一个时间片，再往前不接受。
    #[test]
    fn cookie_expires() {
        let key = CookieKey::from_psk(b"psk");
        let a = addr(5002);
        let c = key.issue(&a, 10);
        let t = |epoch: u64| epoch * EPOCH_MS + 1;
        assert!(key.verify(&a, &c, t(10)), "当前时间片必须通过");
        assert!(key.verify(&a, &c, t(11)), "上一个时间片必须通过");
        assert!(!key.verify(&a, &c, t(12)), "再往前必须失效");
        assert!(!key.verify(&a, &c, t(9)), "还没到的时间片不该通过");
    }

    /// **无状态**：不保存任何东西也能验证——同样的输入必然得到同样的 cookie。
    #[test]
    fn cookie_generation_is_stateless() {
        let a = addr(5003);
        let k1 = CookieKey::from_psk(b"same-psk");
        let c1 = k1.issue(&a, 7);
        let c2 = k1.issue(&a, 7);
        assert_eq!(c1, c2, "同样输入必须得到同样的 cookie（无状态）");
        // 服务端重启（重新派生密钥）后，在途的 cookie 仍然有效
        let k2 = CookieKey::from_psk(b"same-psk");
        assert!(k2.verify(&a, &c1, 7 * EPOCH_MS), "重启后仍应有效");
        // 换 PSK 则失效
        let k3 = CookieKey::from_psk(b"different-psk");
        assert!(!k3.verify(&a, &c1, 7 * EPOCH_MS));
    }

    /// 重复的 `HELLO+COOKIE` 必须复用同一个 conv，不能每包新建会话——
    /// 否则一次重传就能把会话表刷爆（这本身就是一种 DoS）。
    #[test]
    fn repeated_second_round_reuses_the_same_conv() {
        let (mut s, mut c) = keys();
        let a = addr(5004);
        let cookie = match s.on_datagram(a, &c.hello(), 0) {
            Action::Reply(r) => r,
            other => panic!("{other:?}"),
        };
        let second = c.on_datagram(&cookie).unwrap().unwrap();
        let c1 = match s.on_datagram(a, &second, 0) {
            Action::Established { conv, .. } => conv,
            other => panic!("{other:?}"),
        };
        let c2 = match s.on_datagram(a, &second, 0) {
            Action::Established { conv, .. } => conv,
            other => panic!("{other:?}"),
        };
        assert_eq!(c1, c2, "重复包必须复用 conv");
        assert_eq!(s.tracked_peers(), 1, "重复包不得新增会话");
    }

    /// 一个"放大倍数"的量化：扫描各种输入长度，确认没有任何一条路径能放大。
    #[test]
    fn amplification_ratio_never_exceeds_one() {
        let (mut s, _) = keys();
        let a = addr(5005);
        let mut worst: f64 = 0.0;
        for len in [MIN_HELLO, 100, 200, 1200, 1400] {
            let mut d = vec![T_HELLO];
            d.resize(len, 0);
            if let Action::Reply(r) = s.on_datagram(a, &d, 0) {
                let ratio = r.len() as f64 / d.len() as f64;
                worst = worst.max(ratio);
                assert!(ratio <= 1.0, "长度 {len} 时回包放大了 {ratio:.3} 倍");
            }
        }
        println!("  [抗放大] 最大回包/请求比 = {worst:.3}（必须 ≤1.0）");
        assert!(worst > 0.0, "必须真的取到了回包，否则这条测试没测到东西");
        assert_eq!(s.suppressed_replies, 0);
    }

    #[test]
    fn too_small_datagrams_get_no_reply_at_all() {
        let (mut s, _) = keys();
        let a = addr(5006);
        for len in 0..MIN_HELLO {
            let d = vec![T_HELLO; len];
            assert_eq!(
                s.on_datagram(a, &d, 0),
                Action::Drop,
                "长度 {len} 的包不该有任何回包"
            );
        }
        assert_eq!(s.tracked_peers(), 0);
    }

    #[test]
    fn keys_are_never_printed() {
        let k = CookieKey::from_psk(b"psk");
        assert!(format!("{k:?}").contains("redacted"));
    }

    /// **ACK 必须被认证**：不验的话，猜中 conv 的攻击者就能让客户端
    /// 把业务数据发给一个并不持有 PSK 的对端。
    #[test]
    fn forged_ack_is_rejected() {
        // MAC 已经不绑定地址了，这里保留一个地址只为记录"曾经绑过"
        let mut c = ClientHandshake::new([9, 9, 9, 9, 9, 9, 9, 9], b"real-psk");

        // 攻击者用**错的 PSK** 造 ACK
        let mut bad = vec![T_ACK];
        bad.extend_from_slice(&7u32.to_le_bytes());
        bad.extend_from_slice(&ack_mac(b"wrong-psk", &[9u8; 8], 7));
        assert!(c.on_datagram(&bad).is_err(), "用错 PSK 签的 ACK 必须被拒绝");
        assert_eq!(c.established(), None, "被拒绝的 ACK 不得建立会话");

        // 把 MAC 改一个字节也要拒绝
        let mut bad2 = vec![T_ACK];
        bad2.extend_from_slice(&7u32.to_le_bytes());
        bad2.extend_from_slice(&ack_mac(b"real-psk", &[9u8; 8], 7));
        let n = bad2.len();
        bad2[n - 1] ^= 1;
        assert!(c.on_datagram(&bad2).is_err(), "改动 MAC 必须被拒绝");

        // 绑定了地址：同一个 MAC 换到别的地址上不成立
        let mut bad3 = vec![T_ACK];
        bad3.extend_from_slice(&7u32.to_le_bytes());
        bad3.extend_from_slice(&ack_mac(b"real-psk", &[9u8; 8], 8));
        // 换个 conv 也是另一个 MAC——MAC 必须覆盖 conv
        assert!(
            c.on_datagram(&bad3).is_err(),
            "conv 不同则 MAC 不同，必须拒绝"
        );

        // 正确的才通过
        let mut good = vec![T_ACK];
        good.extend_from_slice(&7u32.to_le_bytes());
        good.extend_from_slice(&ack_mac(b"real-psk", &[9u8; 8], 7));
        c.on_datagram(&good).unwrap();
        assert_eq!(c.established(), Some(7));
    }

    /// 完整流程里 ACK 的 MAC 必须能对上（否则正常路径根本走不通）。
    #[test]
    fn ack_mac_matches_across_the_full_flow() {
        let psk = b"shared-psk";
        let a = addr(6002);
        let mut s = ServerHandshake::new(psk);
        let mut c = ClientHandshake::new([5, 5, 5, 5, 5, 5, 5, 5], psk);

        let cookie = match s.on_datagram(a, &c.hello(), 0) {
            Action::Reply(r) => r,
            other => panic!("{other:?}"),
        };
        let second = c.on_datagram(&cookie).unwrap().unwrap();
        let ack = match s.on_datagram(a, &second, 0) {
            Action::Established { ack, .. } => ack,
            other => panic!("{other:?}"),
        };
        c.on_datagram(&ack).expect("正常流程的 ACK 必须通过验证");
        assert!(c.established().is_some());
    }
}
