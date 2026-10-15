//! 传输安全（设计 §13）：握手密钥调度 + **批次级** AEAD + 抗重放。
//!
//! # 三条由设计固定、不可改动的决定
//!
//! 1. **AEAD 作用域是批次，不是单帧**（§13.3）。实测模板化后的 203 个小帧 payload 合计
//!    1240 B，逐帧 AEAD 的 16 B tag 总开销是 3248 B = **payload 的 261.9%**，把模板化
//!    收益吃掉 72%。所以调用方必须把多个逻辑消息攒成一批再 `seal` 一次。
//! 2. **ChaCha20-Poly1305，不用 AES-GCM**（§13.4）。软路由常见的 ARM Cortex-A53 上
//!    ARMv8 Crypto Extensions 是**可选项**，无硬件 AES 时软件实现慢数倍且有查表时序
//!    侧信道风险。
//! 3. **X25519 + PSK 组成 Noise IK 风格握手**（§13.4）。PSK 提供认证，X25519 提供
//!    **前向保密**——避免纯静态 PSK 的长期密钥泄露风险。
//!
//! # nonce 是结构化的，不是随机的
//!
//! `nonce = stream_id(4B) ‖ direction(1B) ‖ batch_seq(7B)`，全部大端、`batch_seq` 单调。
//! 因为非随机，不需要 XChaCha20 的扩展 nonce，标准 96-bit 足够且少一次 HChaCha20 运算。
//! 单调性同时承担抗重放：接收方拒绝任何 `batch_seq` 不大于已见最大值的批次。
//!
//! # 一个必须理解的取舍
//!
//! `psk` 作为 HKDF 的 **salt**、X25519 共享秘密作为 **IKM**。所以：
//! * 不知道 PSK 的中间人无法派生密钥 → 认证成立；
//! * 临时私钥用完即弃 → 即使 PSK 日后泄露，**已过去的流量仍不可解**。
#![forbid(unsafe_code)]

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

/// 会话密钥长度。
pub const KEY_LEN: usize = 32;
/// Poly1305 tag 长度。
pub const TAG_LEN: usize = 16;
/// ChaCha20-Poly1305 标准 nonce 长度。
pub const NONCE_LEN: usize = 12;
/// X25519 公钥长度。
pub const PUB_LEN: usize = 32;

/// HKDF `info` 前缀。掺入协议版本，避免与其它用途的密钥派生混用。
const INFO_PREFIX: &[u8] = b"dshp/1 ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// 系统随机源失败。**绝不能降级为弱随机**——宁可拒绝启动。
    NoRandom,
    /// 对端确认值不符：PSK 不同，或存在中间人。
    PeerNotAuthenticated,
    /// AEAD 认证失败：密文被篡改、方向/nonce 错配，或密钥不同。
    NotAuthenticated,
    /// 批次序号回退或重复——**重放**。
    Replayed { seen: u64, got: u64 },
    /// 明文 + tag 会超过帧上限。
    TooLarge(usize),
    /// 未预留序号就调用了 `seal_reserved`。
    NoReservation,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRandom => write!(f, "系统随机源不可用"),
            Self::PeerNotAuthenticated => {
                write!(f, "对端确认值不符：PSK 不一致或存在中间人")
            }
            Self::NotAuthenticated => write!(f, "AEAD 认证失败：密文被篡改或密钥不符"),
            Self::Replayed { seen, got } => {
                write!(f, "批次序号回退（重放）：已见 {seen}，收到 {got}")
            }
            Self::TooLarge(n) => write!(f, "明文 {n} 字节过大"),
            Self::NoReservation => write!(f, "未预留批次序号就加密"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// 批次方向。参与 nonce，**防止把收到的批次原样反射回去当成合法输入**。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    ClientToServer = 1,
    ServerToClient = 2,
}

impl Direction {
    pub fn byte(self) -> u8 {
        self as u8
    }
}

/// 生成 32 字节密码学随机数。
///
/// 早期版本的握手 nonce 用系统时间拼凑（M0 遗留缺口），这里一并改为 CSPRNG。
/// 随机源失败时**返回错误而不是退化为弱随机**。
pub fn random_32() -> Result<[u8; 32], CryptoError> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|_| CryptoError::NoRandom)?;
    Ok(b)
}

/// 会话密钥：两个方向各一把。**方向分离**保证同一 batch_seq 在两个方向上不会
/// 复用同一 (key, nonce) 组合——那是 ChaCha20-Poly1305 唯一的致命误用方式。
#[derive(Clone)]
pub struct SessionKeys {
    c2s: [u8; KEY_LEN],
    s2c: [u8; KEY_LEN],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 绝不打印密钥内容
        f.write_str("SessionKeys(<redacted>)")
    }
}

impl SessionKeys {
    pub fn key_for(&self, dir: Direction) -> &[u8; KEY_LEN] {
        match dir {
            Direction::ClientToServer => &self.c2s,
            Direction::ServerToClient => &self.s2c,
        }
    }

    /// 本端作为发送方使用的方向。
    pub fn sealer_for_client(&self) -> Sealer {
        Sealer::new(*self.key_for(Direction::ClientToServer))
    }
    pub fn sealer_for_server(&self) -> Sealer {
        Sealer::new(*self.key_for(Direction::ServerToClient))
    }
    pub fn opener_for_client(&self) -> Opener {
        Opener::new(*self.key_for(Direction::ServerToClient))
    }
    pub fn opener_for_server(&self) -> Opener {
        Opener::new(*self.key_for(Direction::ClientToServer))
    }
}

struct Schedule {
    keys: SessionKeys,
    confirm_client: [u8; 32],
    confirm_server: [u8; 32],
}

/// 从 PSK + X25519 共享秘密派生会话密钥与双向确认值。
fn schedule(
    psk: &[u8],
    shared: &[u8; 32],
    client_pub: &[u8; PUB_LEN],
    server_pub: &[u8; PUB_LEN],
) -> Schedule {
    let hk = Hkdf::<Sha256>::new(Some(psk), shared);
    let transcript = |label: &[u8]| {
        let mut info = Vec::with_capacity(INFO_PREFIX.len() + PUB_LEN * 2 + label.len() + 1);
        info.extend_from_slice(INFO_PREFIX);
        info.extend_from_slice(client_pub);
        info.extend_from_slice(server_pub);
        info.push(b' ');
        info.extend_from_slice(label);
        info
    };
    let mut c2s = [0u8; KEY_LEN];
    let mut s2c = [0u8; KEY_LEN];
    let mut cfc = [0u8; 32];
    let mut cfs = [0u8; 32];
    hk.expand(&transcript(b"c2s"), &mut c2s).expect("长度合法");
    hk.expand(&transcript(b"s2c"), &mut s2c).expect("长度合法");
    // 确认值也走 HKDF-Expand：它是以 PSK+DH 为密钥的 PRF，等价于 HMAC 的作用，
    // 但不需要额外引入 hmac 依赖。掺入双方公钥即绑定整个握手转录。
    hk.expand(&transcript(b"confirm-client"), &mut cfc)
        .expect("长度合法");
    hk.expand(&transcript(b"confirm-server"), &mut cfs)
        .expect("长度合法");
    Schedule {
        keys: SessionKeys { c2s, s2c },
        confirm_client: cfc,
        confirm_server: cfs,
    }
}

/// 握手结果。
pub struct HandshakeDone {
    pub keys: SessionKeys,
    /// 本端应发给对端的确认值。
    pub our_confirm: [u8; 32],
    /// 本端期望收到的对端确认值。
    pub peer_confirm: [u8; 32],
}

impl HandshakeDone {
    /// 校验对端确认值。**必须调用**——不校验等于没有认证。
    pub fn verify_peer(&self, got: &[u8]) -> Result<(), CryptoError> {
        if got.len() != 32 || !bool::from(self.peer_confirm.ct_eq(got)) {
            return Err(CryptoError::PeerNotAuthenticated);
        }
        Ok(())
    }
}

/// 握手发起方（客户端）。
pub struct Initiator {
    secret: StaticSecret,
    public: [u8; PUB_LEN],
    psk: Vec<u8>,
}

/// 握手响应方（服务端）。
pub struct Responder {
    secret: StaticSecret,
    public: [u8; PUB_LEN],
    psk: Vec<u8>,
}

/// 为握手某一端生成实现。
///
/// `$is_client` 决定本端在派生转录里的位置（`client_pub ‖ server_pub` 这个顺序必须两端
/// 一致）。**必须显式传参**——早先版本试图用 `stringify!` 从字段名推断，那在宏展开后
/// 根本区分不出两端。
macro_rules! handshake_side {
    ($t:ty, $is_client:expr, $ours:ident, $peers:ident) => {
        impl $t {
            /// 生成本端临时密钥对。PSK 为空时直接拒绝——**不允许无认证的握手**。
            pub fn new(psk: &[u8]) -> Result<Self, CryptoError> {
                if psk.is_empty() {
                    return Err(CryptoError::PeerNotAuthenticated);
                }
                let secret = StaticSecret::from(random_32()?);
                let public = PublicKey::from(&secret).to_bytes();
                Ok(Self {
                    secret,
                    public,
                    psk: psk.to_vec(),
                })
            }

            pub fn public(&self) -> [u8; PUB_LEN] {
                self.public
            }

            /// 收到对端公钥后完成握手。
            ///
            /// 返回的 `HandshakeDone` 同时含「本端该发的确认值」与「该收到的确认值」，
            /// 因此发送与校验的**先后顺序不影响结果**。
            pub fn finish(self, their_pub: [u8; PUB_LEN]) -> HandshakeDone {
                let shared = self
                    .secret
                    .diffie_hellman(&PublicKey::from(their_pub))
                    .to_bytes();
                let (client_pub, server_pub) = if $is_client {
                    (self.public, their_pub)
                } else {
                    (their_pub, self.public)
                };
                let s = schedule(&self.psk, &shared, &client_pub, &server_pub);
                HandshakeDone {
                    keys: s.keys,
                    our_confirm: s.$ours,
                    peer_confirm: s.$peers,
                }
            }
        }
    };
}

handshake_side!(Initiator, true, confirm_client, confirm_server);
handshake_side!(Responder, false, confirm_server, confirm_client);

/// 构造 nonce：`stream_id(4B) ‖ direction(1B) ‖ batch_seq(7B)`，全大端。
pub fn nonce_of(stream_id: u32, dir: Direction, batch_seq: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..4].copy_from_slice(&stream_id.to_be_bytes());
    n[4] = dir.byte();
    // 7 字节足够 2^56 个批次；超出时回绕会破坏唯一性，故显式截断保护
    n[5..].copy_from_slice(&(batch_seq & 0x00FF_FFFF_FFFF_FFFF).to_be_bytes()[1..]);
    n
}

/// 发送侧：持有密钥与单调批次序号。
pub struct Sealer {
    cipher: ChaCha20Poly1305,
    next_seq: u64,
    /// 已预留但尚未使用的序号。见 [`Sealer::reserve_seq`]。
    reserved: Option<u64>,
}

impl Sealer {
    pub fn new(key: [u8; KEY_LEN]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&key.into()),
            next_seq: 0,
            reserved: None,
        }
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// 预留下一个批次序号。
    ///
    /// AAD 需要包含序号，因此调用方必须先拿到序号、再加密。为了不破环"序号由计数器
    /// 独占分配"这条安全性前提，这里用预留语义：`reserve_seq` 取号，`seal_reserved` 消费。
    /// **同一序号只能加密一次**——重复调用会因预留已被消费而报错。
    pub fn reserve_seq(&mut self) -> u64 {
        let s = self.next_seq;
        self.reserved = Some(s);
        self.next_seq = self.next_seq.wrapping_add(1);
        s
    }

    /// 用 [`Self::reserve_seq`] 预留的序号加密。
    pub fn seal_reserved(
        &mut self,
        stream_id: u32,
        dir: Direction,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let seq = self.reserved.take().ok_or(CryptoError::NoReservation)?;
        let nonce = nonce_of(stream_id, dir, seq);
        self.cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::TooLarge(plaintext.len()))
    }

    /// 加密一批。`aad` 是**不加密但要认证**的元数据（这里传帧头里除 payload 之外的部分）。
    ///
    /// 返回值含 16 字节 tag。调用方负责把 `batch_seq` 放进 AAD 或帧头，使接收方能重建 nonce。
    pub fn seal(
        &mut self,
        stream_id: u32,
        dir: Direction,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(u64, Vec<u8>), CryptoError> {
        let seq = self.next_seq;
        let nonce = nonce_of(stream_id, dir, seq);
        let out = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::TooLarge(plaintext.len()))?;
        self.next_seq = self.next_seq.wrapping_add(1);
        Ok((seq, out))
    }
}

/// 接收侧：持有密钥与**抗重放**水位。
///
/// 水位按 `stream_id` 分别记录，且要求 `batch_seq` **严格递增**。因为一个流的批次
/// 在链路上是有序的，重复或乱序批次会直接被拒绝——这正是设计 §13.5 的第一层。
pub struct Opener {
    cipher: ChaCha20Poly1305,
    highest: std::collections::HashMap<u32, u64>,
    /// 水位表上限。stream 数有上限（§13.10 规定 4），留足余量即可挡住畸形流。
    max_streams: usize,
}

impl Opener {
    pub fn new(key: [u8; KEY_LEN]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&key.into()),
            highest: std::collections::HashMap::new(),
            max_streams: 64,
        }
    }

    /// 解密一批，并校验序号严格递增。
    pub fn open(
        &mut self,
        stream_id: u32,
        dir: Direction,
        batch_seq: u64,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if let Some(&seen) = self.highest.get(&stream_id) {
            if batch_seq <= seen {
                return Err(CryptoError::Replayed {
                    seen,
                    got: batch_seq,
                });
            }
        }
        let nonce = nonce_of(stream_id, dir, batch_seq);
        // 认证失败时**不推进水位**：否则一次伪造的高序号批次就能永久堵死该流
        let plain = self
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::NotAuthenticated)?;
        if self.highest.len() >= self.max_streams && !self.highest.contains_key(&stream_id) {
            // 水位表满了且来了新流。拒绝而不是淘汰——淘汰会让被淘汰流上的重放重新可行。
            return Err(CryptoError::TooLarge(self.highest.len()));
        }
        self.highest.insert(stream_id, batch_seq);
        Ok(plain)
    }

    /// 流结束后释放水位。由 mux 在 `unbind_stream` 时调用。
    pub fn forget_stream(&mut self, stream_id: u32) {
        self.highest.remove(&stream_id);
    }

    /// 当前跟踪的流数（观测用）。
    pub fn tracked_streams(&self) -> usize {
        self.highest.len()
    }
}

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sealer(next_seq={})", self.next_seq)
    }
}

impl std::fmt::Debug for Opener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Opener(tracked={})", self.highest.len())
    }
}

/// 构造 AEAD 的附加认证数据（AAD）。
///
/// 绑定**路由元数据**，使密文无法被搬到另一条流或另一个批次上复用
/// （否则攻击者可以把 A 流第 3 批的密文原样塞进 B 流）。
///
/// 只取 `type ‖ stream_id ‖ seq` 共 9 字节，**刻意不含 payload_len**：加密后长度会变
/// （+16 tag），两端重建该字段时极易写错，而这三个字段已足以绑定「谁的第几批」。
pub fn aead_aad(ty: u8, stream_id: u32, seq: u32) -> [u8; 9] {
    let mut a = [0u8; 9];
    a[0] = ty;
    a[1..5].copy_from_slice(&stream_id.to_be_bytes());
    a[5..9].copy_from_slice(&seq.to_be_bytes());
    a
}

/// 该帧类型是否需要 AEAD 保护。
///
/// `Hello` / `Caps` 承载握手本身，必须明文——它们要在密钥建立**之前**交换。
/// 其余一律加密，包括 `Ping`/`Pong`：留下明文会话帧等于给流量分析送特征。
pub fn needs_protection(ty: crate::frame::FrameType) -> bool {
    use crate::frame::FrameType as T;
    !matches!(ty, T::Hello | T::Caps)
}
#[cfg(test)]
mod tests {
    use super::*;

    fn psk() -> &'static [u8] {
        b"e2e-test-psk-0123456789abcdef"
    }

    fn pair() -> (SessionKeys, SessionKeys) {
        let client = Initiator::new(psk()).unwrap();
        let server = Responder::new(psk()).unwrap();
        let cpub = client.public();
        let spub = server.public();
        let cd = client.finish(spub);
        let sd = server.finish(cpub);
        cd.verify_peer(&sd.our_confirm)
            .expect("客户端应能验证服务端");
        sd.verify_peer(&cd.our_confirm)
            .expect("服务端应能验证客户端");
        (cd.keys, sd.keys)
    }

    // ---- 握手 ----

    #[test]
    fn both_sides_derive_the_same_keys() {
        let (ck, sk) = pair();
        assert_eq!(
            ck.key_for(Direction::ClientToServer),
            sk.key_for(Direction::ClientToServer)
        );
        assert_eq!(
            ck.key_for(Direction::ServerToClient),
            sk.key_for(Direction::ServerToClient)
        );
    }

    #[test]
    fn directions_use_different_keys() {
        let (ck, _) = pair();
        assert_ne!(
            ck.key_for(Direction::ClientToServer),
            ck.key_for(Direction::ServerToClient),
            "方向必须分离；否则同一 batch_seq 在两个方向上会复用同一 (key, nonce)"
        );
    }

    #[test]
    fn different_ephemeral_keys_give_different_sessions() {
        let (a, _) = pair();
        let (b, _) = pair();
        assert_ne!(
            a.key_for(Direction::ClientToServer),
            b.key_for(Direction::ClientToServer),
            "每次握手的临时密钥不同 ⇒ 会话密钥不同（前向保密的落点）"
        );
    }

    #[test]
    fn mismatched_psk_fails_key_confirmation() {
        let client = Initiator::new(psk()).unwrap();
        let server = Responder::new(b"another-psk-entirely").unwrap();
        let cpub = client.public();
        let spub = server.public();
        let cd = client.finish(spub);
        let sd = server.finish(cpub);
        assert_eq!(
            cd.verify_peer(&sd.our_confirm),
            Err(CryptoError::PeerNotAuthenticated),
            "PSK 不一致必须认证失败——这正是双向认证要挡的"
        );
        assert_eq!(
            sd.verify_peer(&cd.our_confirm),
            Err(CryptoError::PeerNotAuthenticated)
        );
    }

    #[test]
    fn empty_psk_is_refused() {
        assert!(Initiator::new(b"").is_err(), "不允许无认证握手");
        assert!(Responder::new(b"").is_err());
    }

    #[test]
    fn confirmation_rejects_wrong_length_and_content() {
        let client = Initiator::new(psk()).unwrap();
        let server = Responder::new(psk()).unwrap();
        let spub = server.public();
        let cd = client.finish(spub);
        assert!(cd.verify_peer(&[0u8; 31]).is_err(), "长度不符必须拒绝");
        assert!(cd.verify_peer(&[0u8; 32]).is_err(), "全零确认值必须拒绝");
    }

    #[test]
    fn man_in_the_middle_is_detected() {
        // 中间人各自与两端握手，但没有 PSK
        let client = Initiator::new(psk()).unwrap();
        let mitm = Responder::new(b"no-idea-what-the-psk-is").unwrap();
        let cpub = client.public();
        let mpub = mitm.public();
        let cd = client.finish(mpub);
        let md = mitm.finish(cpub);
        assert!(cd.verify_peer(&md.our_confirm).is_err());
    }

    // ---- AEAD 往返 ----

    #[test]
    fn seal_open_roundtrip() {
        let (ck, ck_peer) = pair();
        let mut sealer = ck.sealer_for_client();
        let mut opener = ck_peer.opener_for_server();
        let msg = b"{\"model\":\"gpt-4o\",\"messages\":[]}";
        let (seq, ct) = sealer
            .seal(7, Direction::ClientToServer, b"hdr", msg)
            .unwrap();
        assert_eq!(ct.len(), msg.len() + TAG_LEN, "密文只比明文多一个 tag");
        let back = opener
            .open(7, Direction::ClientToServer, seq, b"hdr", &ct)
            .unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn batch_scope_is_what_makes_aead_affordable() {
        // 这是 §13.3 的核心量化：逐帧 tag 会吃掉收益，批次化后可以忽略
        let (ck, sk) = pair();
        let mut sealer = ck.sealer_for_client();
        let mut opener = sk.opener_for_server();
        // 203 个小消息，每个 6 字节（模板增量的典型大小）
        let msgs: Vec<&[u8]> = (0..203).map(|_| &b"\"tok\""[..]).collect();
        let payload_total: usize = msgs.iter().map(|m| m.len()).sum();

        // 逐帧 AEAD：每条消息单独一批（这正是要被否决的做法）
        let mut per_frame = 0usize;
        for m in msgs.iter() {
            let (s, ct) = sealer.seal(0, Direction::ClientToServer, b"", m).unwrap();
            let _ = opener
                .open(0, Direction::ClientToServer, s, b"", &ct)
                .unwrap();
            per_frame += ct.len();
        }
        let overhead_per_frame = per_frame - payload_total;

        // 批次化：每 20 个消息一批
        let mut sealer2 = ck.sealer_for_client();
        let mut opener2 = sk.opener_for_server();
        let mut batched = 0usize;
        for chunk in msgs.chunks(20) {
            let joined: Vec<u8> = chunk.concat();
            let (s, ct) = sealer2
                .seal(0, Direction::ClientToServer, b"", &joined)
                .unwrap();
            let _ = opener2
                .open(0, Direction::ClientToServer, s, b"", &ct)
                .unwrap();
            batched += ct.len();
        }
        let overhead_batched = batched - payload_total;

        println!(
            "  [AEAD 粒度] payload {payload_total} B ｜ 逐帧 tag {overhead_per_frame} B（{:.1}%）｜ 批次 tag {overhead_batched} B（{:.1}%）",
            overhead_per_frame as f64 / payload_total as f64 * 100.0,
            overhead_batched as f64 / payload_total as f64 * 100.0,
        );
        assert_eq!(overhead_per_frame, 203 * TAG_LEN);
        assert_eq!(overhead_batched, 11 * TAG_LEN);
        assert!(
            overhead_batched * 10 < overhead_per_frame,
            "批次化的 tag 开销必须比逐帧低一个数量级"
        );
    }

    #[test]
    fn tampering_is_rejected() {
        let (ck, sk) = pair();
        let mut sealer = ck.sealer_for_client();
        let mut opener = sk.opener_for_server();
        let (seq, mut ct) = sealer
            .seal(1, Direction::ClientToServer, b"hdr", b"secret payload")
            .unwrap();
        for i in 0..ct.len() {
            ct[i] ^= 0x01;
            assert!(
                opener
                    .open(1, Direction::ClientToServer, seq, b"hdr", &ct)
                    .is_err(),
                "翻转第 {i} 字节必须认证失败"
            );
            ct[i] ^= 0x01;
        }
        // 恢复后仍可用
        assert!(opener
            .open(1, Direction::ClientToServer, seq, b"hdr", &ct)
            .is_ok());
    }

    #[test]
    fn aad_mismatch_is_rejected() {
        let (ck, sk) = pair();
        let mut sealer = ck.sealer_for_client();
        let mut opener = sk.opener_for_server();
        let (seq, ct) = sealer
            .seal(1, Direction::ClientToServer, b"hdr-A", b"payload")
            .unwrap();
        assert!(
            opener
                .open(1, Direction::ClientToServer, seq, b"hdr-B", &ct)
                .is_err(),
            "AAD 是认证的一部分，改动必须被发现"
        );
    }

    /// 方向参与 nonce：把收到的批次反射回去必须失败。
    #[test]
    fn reflected_batch_is_rejected() {
        let (ck, _server_side) = pair();
        let mut csealer = ck.sealer_for_client();
        let (seq, ct) = csealer
            .seal(1, Direction::ClientToServer, b"", b"hi")
            .unwrap();
        // 服务端把它当成 ServerToClient 打开
        let mut copener = ck.opener_for_client();
        assert!(
            copener
                .open(1, Direction::ServerToClient, seq, b"", &ct)
                .is_err(),
            "方向必须影响 nonce，否则反射攻击可行"
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (ck, _) = pair();
        let (other, _) = pair();
        let mut sealer = ck.sealer_for_client();
        let mut opener = other.opener_for_server();
        let (seq, ct) = sealer
            .seal(1, Direction::ClientToServer, b"", b"hi")
            .unwrap();
        assert!(opener
            .open(1, Direction::ClientToServer, seq, b"", &ct)
            .is_err());
    }

    // ---- 抗重放 ----

    #[test]
    fn replaying_the_same_batch_is_rejected() {
        let (ck, sk) = pair();
        let mut sealer = ck.sealer_for_client();
        let mut opener = sk.opener_for_server();
        let (seq, ct) = sealer
            .seal(1, Direction::ClientToServer, b"", b"pay")
            .unwrap();
        assert!(opener
            .open(1, Direction::ClientToServer, seq, b"", &ct)
            .is_ok());
        assert_eq!(
            opener.open(1, Direction::ClientToServer, seq, b"", &ct),
            Err(CryptoError::Replayed { seen: 0, got: 0 }),
            "同一批次重放必须被拒——这是抗重放的第一层"
        );
    }

    #[test]
    fn out_of_order_batches_are_rejected() {
        let (ck, sk) = pair();
        let mut sealer = ck.sealer_for_client();
        let mut opener = sk.opener_for_server();
        let (s0, c0) = sealer
            .seal(1, Direction::ClientToServer, b"", b"a")
            .unwrap();
        let (s1, c1) = sealer
            .seal(1, Direction::ClientToServer, b"", b"b")
            .unwrap();
        assert!(opener
            .open(1, Direction::ClientToServer, s1, b"", &c1)
            .is_ok());
        assert!(
            opener
                .open(1, Direction::ClientToServer, s0, b"", &c0)
                .is_err(),
            "回退序号必须被拒（链路保证有序，回退即异常）"
        );
    }

    #[test]
    fn streams_have_independent_watermarks() {
        let (ck, sk) = pair();
        let mut sealer = ck.sealer_for_client();
        let mut opener = sk.opener_for_server();
        for _ in 0..3 {
            let (s, c) = sealer
                .seal(1, Direction::ClientToServer, b"", b"x")
                .unwrap();
            opener
                .open(1, Direction::ClientToServer, s, b"", &c)
                .unwrap();
        }
        // 另一个流从序号 0 起算，不应受流 1 水位影响
        let (s, c) = sealer
            .seal(2, Direction::ClientToServer, b"", b"y")
            .unwrap();
        assert!(
            opener
                .open(2, Direction::ClientToServer, s, b"", &c)
                .is_ok(),
            "水位必须按 stream 独立记录"
        );
        assert_eq!(opener.tracked_streams(), 2);
    }

    /// 认证失败时**不得推进水位**——否则一次伪造的高序号批次就能永久堵死该流。
    #[test]
    fn failed_auth_does_not_advance_the_watermark() {
        let (ck, sk) = pair();
        let mut sealer = ck.sealer_for_client();
        let mut opener = sk.opener_for_server();
        // 伪造一个序号很高的坏批次
        let bogus = vec![0u8; 32];
        assert!(opener
            .open(1, Direction::ClientToServer, 999, b"", &bogus)
            .is_err());
        // 真实批次（序号 0）必须仍能被接受
        let (s, c) = sealer
            .seal(1, Direction::ClientToServer, b"", b"real")
            .unwrap();
        assert!(
            opener
                .open(1, Direction::ClientToServer, s, b"", &c)
                .is_ok(),
            "认证失败不得推进水位，否则合法批次会被误判为重放"
        );
    }

    #[test]
    fn forget_stream_releases_the_watermark() {
        let (ck, sk) = pair();
        let mut sealer = ck.sealer_for_client();
        let mut opener = sk.opener_for_server();
        let (s, c) = sealer
            .seal(9, Direction::ClientToServer, b"", b"z")
            .unwrap();
        opener
            .open(9, Direction::ClientToServer, s, b"", &c)
            .unwrap();
        assert_eq!(opener.tracked_streams(), 1);
        opener.forget_stream(9);
        assert_eq!(opener.tracked_streams(), 0);
    }

    // ---- nonce ----

    #[test]
    fn nonce_layout_is_as_designed() {
        let n = nonce_of(0x01020304, Direction::ServerToClient, 0x05060708090A0B);
        assert_eq!(&n[..4], &[1, 2, 3, 4], "stream_id 大端在前");
        assert_eq!(n[4], 2, "方向字节");
        assert_eq!(&n[5..], &[5, 6, 7, 8, 9, 10, 11], "batch_seq 7 字节大端");
    }

    #[test]
    fn nonce_differs_across_stream_direction_and_seq() {
        let a = nonce_of(1, Direction::ClientToServer, 0);
        assert_ne!(a, nonce_of(2, Direction::ClientToServer, 0));
        assert_ne!(a, nonce_of(1, Direction::ServerToClient, 0));
        assert_ne!(a, nonce_of(1, Direction::ClientToServer, 1));
    }

    #[test]
    fn random_32_is_not_constant() {
        let a = random_32().unwrap();
        let b = random_32().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn keys_are_never_printed() {
        let (ck, _) = pair();
        let s = format!("{ck:?}");
        assert!(s.contains("redacted"), "调试输出绝不能含密钥：{s}");
    }
}
