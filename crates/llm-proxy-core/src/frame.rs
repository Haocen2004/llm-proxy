//! 24 字节固定帧头 + 类型专属 protobuf 载荷。
//!
//! 布局（小端）：
//! ```text
//! offset size field
//! 0      2    magic 'D','P'
//! 2      1    ver
//! 3      1    type
//! 4      2    flags
//! 6      4    stream_id
//! 10     4    seq
//! 14     4    payload_len
//! 18     4    crc32c  (覆盖 header[0..18] 与 payload)
//! 22     2    reserved
//! ```
//!
//! 设计文档早期版本把 `type`/`stream_id`/`seq` 同时放在帧头和 protobuf `Frame` 消息里，
//! 实现时去掉了这处冗余：结构字段只在帧头，payload 只放该帧类型专属的消息。

use bytes::{Buf, BufMut, BytesMut};

pub const MAGIC: [u8; 2] = *b"DP";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("帧头不足：需要 {HEADER_LEN} 字节，实际 {0}")]
    ShortHeader(usize),
    #[error("magic 不匹配：{0:02x?}")]
    BadMagic([u8; 2]),
    #[error("协议版本不支持：{0}")]
    BadVersion(u8),
    #[error("未知帧类型：{0}")]
    BadType(u8),
    #[error("crc32c 校验失败")]
    BadCrc,
    #[error("载荷长度 {got} 与声明 {want} 不符")]
    LengthMismatch { got: usize, want: usize },
    #[error("载荷超过上限 {limit} 字节：{got}")]
    TooLarge { got: usize, limit: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Hello = 1,
    Caps = 2,
    Ping = 3,
    Pong = 4,
    /// 握手最后一步：客户端回送确认值（此时载荷已加密）。
    KeyConfirm = 5,
    ReqOpen = 10,
    Need = 11,
    BodyChunk = 12,
    ReqCommit = 13,
    RespHead = 20,
    RespData = 21,
    RespEnd = 22,
    /// 响应侧模板定义（服务端主导下发）。
    TemplateDef = 23,
    /// 响应侧批量增量帧。**不得**退化为「一帧一个事件」。
    RespBatch = 24,
    Resume = 30,
    Err = 31,
    GoAway = 32,
    /// **客户端→服务端**：放弃这条流（SDK 断了、或用户取消了请求）。
    ///
    /// 载荷为空，用 `stream_id` 定位。为什么需要它：SDK 一断，客户端那条 response
    /// future 就被丢掉，但**对端学不到任何东西**——服务端仍在上游那里等着，
    /// 于是它按 `MAX_CONCURRENT_STREAMS` 占着的槽位再也不释放。
    /// 上游一旦挂死，4 次放弃就足以让代理对该上游**永久不再服务**（实测见
    /// README 缺口 8 与 `e2e-tests/abandon.rs`）。
    ///
    /// 之前 17 个变体里**没有任何一个**表达"取消"，所以那条路径无解——
    /// 这不是补漏洞式的新增，而是协议里本来就缺的一格。
    Cancel = 33,
    /// 服务端已为该流取得活跃执行额度，客户端现在可以发送请求体。
    ///
    /// 这是多请求排队的准入屏障：没有这条确认，客户端不得发送
    /// `BodyChunk`/`ReqCommit`，避免等待全局并发槽位的请求把请求体提前堆进
    /// 每条 stream 的接收 channel。
    StreamReady = 34,
}

impl FrameType {
    /// 线上判别字节。与 [Self::from_u8] 必须一一对应——已有测试钉住这条。
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Result<Self, FrameError> {
        Ok(match v {
            1 => Self::Hello,
            2 => Self::Caps,
            3 => Self::Ping,
            4 => Self::Pong,
            5 => Self::KeyConfirm,
            10 => Self::ReqOpen,
            11 => Self::Need,
            12 => Self::BodyChunk,
            13 => Self::ReqCommit,
            20 => Self::RespHead,
            21 => Self::RespData,
            22 => Self::RespEnd,
            23 => Self::TemplateDef,
            24 => Self::RespBatch,
            30 => Self::Resume,
            31 => Self::Err,
            32 => Self::GoAway,
            33 => Self::Cancel,
            34 => Self::StreamReady,
            other => return Err(FrameError::BadType(other)),
        })
    }

    /// 该类型是否允许在没有已建立 stream 的情况下出现。
    ///
    /// 它同时决定**路由去向**：会话级帧进会话收件箱，流级帧进该流的通道
    /// （见 `llm-proxy-transport` 的读循环）。`Cancel` 归到这里是**刻意的**：
    ///
    /// * 它要表达"目标流"——靠**载荷里的 stream_id**，不靠帧头；
    /// * 缺口 8 实测："流级"的取消帧在客户端入队后**从未到达对端**
    ///   （服务端 `received_frames` 增量 0，同一时刻客户端 `cancel_sent=4`），
    ///   而握手后的会话级加密帧 `KeyConfirm` **必须到达**（否则握手直接失败）。
    ///   于是把取消放到**已知能到达**的那条路径上。
    pub fn is_session_level(self) -> bool {
        matches!(
            self,
            Self::Hello | Self::Caps | Self::Ping | Self::Pong | Self::GoAway | Self::Cancel
        )
    }
}

pub mod flags {
    /// 该帧是当前 stream 的最后一帧。
    pub const LAST: u16 = 1 << 0;
    /// 需要对方回 ACK。
    pub const ACK_REQ: u16 = 1 << 1;
    /// 载荷经 AEAD 封装（KCP 模式必需，WS/SSE 下为防御纵深）。
    pub const ENCRYPTED: u16 = 1 << 2;
    /// 载荷经 zstd 压缩。
    pub const COMPRESSED: u16 = 1 << 3;
    /// 载荷是 TokenStream（含 REF 引用）。
    pub const TOKENSTREAM: u16 = 1 << 4;
    /// 载荷是**流式 zstd** 的一段（慢路径，设计 §6.3）。
    ///
    /// 与「整段 zstd」不同：这是一条连续的压缩流，逐帧喂入即可增量解压，
    /// 因此可以按时间窗口切分发送而不必等整段完成。
    pub const STREAM_ZSTD: u16 = 1 << 5;
    /// 同 [`STREAM_ZSTD`]，但**不带字典**。
    ///
    /// 这个位存在的唯一理由：实测发现 `dict_sse` 只在**短流**上占优
    /// （≈4KB 处交叉，见 `llm_proxy_core::stream_zstd` 的说明），超过之后不带字典反而更小。
    /// 于是慢路径在跨越交叉点时会**结束当前帧、另起一条无字典流**，
    /// 客户端凭这一位就知道该换一个解压器。
    pub const STREAM_ZSTD_NODICT: u16 = 1 << 6;
}

/// 带类型的标志位包装，避免裸 u16 到处传。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags(pub u16);

impl Flags {
    pub fn contains(self, bit: u16) -> bool {
        self.0 & bit != 0
    }
    pub fn with(self, bit: u16) -> Self {
        Self(self.0 | bit)
    }
}

/// 一个已解析（或待发送）的帧。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub ty: FrameType,
    pub flags: Flags,
    pub stream_id: u32,
    pub seq: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(ty: FrameType, stream_id: u32, seq: u32, payload: Vec<u8>) -> Self {
        Self {
            ty,
            flags: Flags::default(),
            stream_id,
            seq,
            payload,
        }
    }

    pub fn with_flags(mut self, f: Flags) -> Self {
        self.flags = f;
        self
    }

    /// 编码成完整帧（帧头 + 载荷）。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(HEADER_LEN + self.payload.len());
        out.put_slice(&MAGIC);
        out.put_u8(VERSION);
        out.put_u8(self.ty as u8);
        out.put_u16_le(self.flags.0);
        out.put_u32_le(self.stream_id);
        out.put_u32_le(self.seq);
        out.put_u32_le(self.payload.len() as u32);
        out.put_u32_le(0); // crc32c 占位，下一行回填
        out.put_u16_le(0); // reserved
        debug_assert_eq!(out.len(), HEADER_LEN);

        let crc = crc_of_parts(&out[0..18], &self.payload);
        out[18..22].copy_from_slice(&crc.to_le_bytes());

        out.put_slice(&self.payload);
        out.to_vec()
    }

    /// 从缓冲区解析一帧；返回 `(帧, 消耗字节数)`。
    ///
    /// 数据不足时返回 `Ok(None)`（调用方继续累积），而不是错误。
    pub fn decode(buf: &[u8], max_payload: usize) -> Result<Option<(Self, usize)>, FrameError> {
        if buf.len() < HEADER_LEN {
            return Ok(None);
        }
        if buf[0..2] != MAGIC {
            return Err(FrameError::BadMagic([buf[0], buf[1]]));
        }
        if buf[2] != VERSION {
            return Err(FrameError::BadVersion(buf[2]));
        }
        let ty = FrameType::from_u8(buf[3])?;
        let flags = Flags(u16::from_le_bytes([buf[4], buf[5]]));
        let stream_id = u32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]);
        let seq = u32::from_le_bytes([buf[10], buf[11], buf[12], buf[13]]);
        let payload_len = u32::from_le_bytes([buf[14], buf[15], buf[16], buf[17]]) as usize;
        let want_crc = u32::from_le_bytes([buf[18], buf[19], buf[20], buf[21]]);

        if payload_len > max_payload {
            return Err(FrameError::TooLarge {
                got: payload_len,
                limit: max_payload,
            });
        }
        if buf.len() < HEADER_LEN + payload_len {
            return Ok(None);
        }
        let payload = &buf[HEADER_LEN..HEADER_LEN + payload_len];

        let crc = crc_of_parts(&buf[0..18], payload);
        if crc != want_crc {
            return Err(FrameError::BadCrc);
        }

        Ok(Some((
            Self {
                ty,
                flags,
                stream_id,
                seq,
                payload: payload.to_vec(),
            },
            HEADER_LEN + payload_len,
        )))
    }

    /// 从累积缓冲区里连续取出所有完整帧。
    pub fn drain(buf: &mut BytesMut, max_payload: usize) -> Result<Vec<Self>, FrameError> {
        let mut out = Vec::new();
        while let Some((f, used)) = Self::decode(buf, max_payload)? {
            buf.advance(used);
            out.push(f);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// CRC32C (Castagnoli)，自实现以避免额外依赖并保持 ARM 上行为一致
// ---------------------------------------------------------------------------

const fn make_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = make_table();

/// 计算 CRC32C。返回的是已完成最终异或的结果。
pub fn crc32c(data: &[u8]) -> u32 {
    crc32c_finish(crc32c_continue(!0u32, data))
}

/// 跨两段连续计算并一次性终结。
///
/// 帧的校验覆盖 `header[0..18] ‖ payload`，所以必须**先合并再终结**：
/// 如果对帧头单独终结、再拿终结后的值继续算载荷，得到的是别的函数，
/// 虽然两端一致仍能"通过"往返测试，但已经不是标准 CRC32C。
fn crc_of_parts(a: &[u8], b: &[u8]) -> u32 {
    crc32c_finish(crc32c_continue(crc32c_continue(!0u32, a), b))
}

#[inline]
fn crc32c_finish(crc: u32) -> u32 {
    crc ^ !0u32
}

/// 增量计算，便于分「帧头」与「载荷」两段喂入。
fn crc32c_continue(prev: u32, data: &[u8]) -> u32 {
    let mut crc = prev;
    for &b in data {
        crc = CRC_TABLE[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_known_vectors() {
        // CRC-32C (Castagnoli) 的规范 check 值与常用向量。
        // 注意：早先这里写的是 0x8A9136AA —— 那是**记错的向量**，已用独立的位级
        // 实现交叉验证过，本实现输出 0x46DD794E（与独立实现一致）。
        assert_eq!(crc32c(b""), 0x0000_0000);
        assert_eq!(crc32c(b"a"), 0xC1D0_4330);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0xffu8; 32]), 0x62A8_AB43);
        assert_eq!(crc32c(&(0u8..32).collect::<Vec<_>>()), 0x46DD_794E);
    }

    #[test]
    fn crc32c_incremental_matches_oneshot() {
        let a = b"header-part";
        let b = b"payload-part";
        let mut whole = a.to_vec();
        whole.extend_from_slice(b);
        // 分两段喂入必须与一次性计算相同——帧头与载荷正是分两段算的
        let split = crc_of_parts(a, b);
        assert_eq!(split, crc32c(&whole));
    }

    #[test]
    fn roundtrip() {
        let f = Frame::new(FrameType::ReqOpen, 7, 3, b"hello dshp".to_vec())
            .with_flags(Flags::default().with(flags::LAST));
        let bytes = f.encode();
        assert_eq!(bytes.len(), HEADER_LEN + 10);
        let (back, used) = Frame::decode(&bytes, 1024).unwrap().unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(back, f);
    }

    #[test]
    fn decode_needs_more_data() {
        let f = Frame::new(FrameType::Caps, 0, 0, vec![1, 2, 3]);
        let bytes = f.encode();
        assert!(Frame::decode(&bytes[..HEADER_LEN - 1], 1024)
            .unwrap()
            .is_none());
        // 帧头完整但载荷不全
        assert!(Frame::decode(&bytes[..HEADER_LEN + 1], 1024)
            .unwrap()
            .is_none());
        assert!(Frame::decode(&bytes, 1024).unwrap().is_some());
    }

    #[test]
    fn detects_corruption() {
        let mut bytes = Frame::new(FrameType::RespData, 1, 1, vec![9, 9, 9]).encode();
        *bytes.last_mut().unwrap() ^= 0x01;
        assert_eq!(Frame::decode(&bytes, 1024).unwrap_err(), FrameError::BadCrc);
    }

    #[test]
    fn rejects_oversize_payload_early() {
        let bytes = Frame::new(FrameType::RespData, 1, 1, vec![0; 64]).encode();
        assert!(matches!(
            Frame::decode(&bytes, 16).unwrap_err(),
            FrameError::TooLarge { .. }
        ));
    }

    #[test]
    fn drain_multiple_frames() {
        let mut buf = BytesMut::new();
        for i in 0..3u32 {
            buf.extend_from_slice(&Frame::new(FrameType::BodyChunk, 1, i, vec![i as u8]).encode());
        }
        let frames = Frame::drain(&mut buf, 1024).unwrap();
        assert_eq!(frames.len(), 3);
        assert!(buf.is_empty());
    }
}
