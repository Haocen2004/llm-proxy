//! **SSE 续传**的服务端半边（设计 §11.2，缺口 #2）——环形缓冲。
//!
//! # 设计里已经定好的部分（照做，不重新发明）
//!
//! * 服务端为进行中的请求保留环形缓冲（**256 KB / 最长 5 min**）；
//! * 客户端重连后发 `RESUME{req_id, ack_seq}`，服务端**从断点重放**；
//! * 缓冲溢出 ⇒ `ERR(STREAM_GAP)` ⇒ 客户端**不自动重放上游**，而是按上游错误格式
//!   交给 SDK 决定（重放 = 重新计费 + 采样结果会变 ✓）。
//!
//! # `seq` 从哪来（这一条不用改协议）
//!
//! 设计写"每帧带 `seq`"——而 **24 字节帧头里早就有 `seq: u32`** ✓
//! （`llm_proxy_core::frame::Frame`），所以续传**不需要动协议** ✓：
//! 客户端 ack 它最后**应用**过的 seq，服务端重放 `seq > ack` 的那些帧 ✓。
//!
//! # 内存预算（设计 §11.2 要求先答的问题之一）
//!
//! 环上限 [`RING_BYTES`] = 256 KB，并发上限
//! `MAX_CONCURRENT_STREAMS` = 4 ⇒ 最坏 **1 MiB**。§12 的常驻 RSS 预算是 32 MiB、
//! 实测 8.5–9.5 MiB ⇒ **装得下** ✓（且环是**按字节**占的，短响应根本到不了上限 ✓）。
//!
//! # 降级时环去哪（问题之二）
//!
//! 环**挂在 req_id 上、进程级**，不随会话销毁 ✓ —— 这正是"重连（新会话）还能续"的前提 ✓；
//! 流正常结束或取消时释放 ✓，异常情况下由 [`RING_SECS`] 的 TTL 兜底 ✓。
//!
//! ⚠️ **与设计不同的一处（保守化）**：设计说"上游在客户端断线期间默认 hold + 缓冲"，
//! 但没给**上限**。无上限地 hold 等于"客户端再也不回来也一直烧上游 token" ✗✗
//! ⇒ 这里加一个**hold 窗口**（[`HOLD_SECS`]）：客户端失踪超过它就**主动结束该流** ✓
//! （既保住"短暂断线能续"✓，又不让成本无界 ✓）。

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use llm_proxy_core::frame::Frame;
use llm_proxy_transport::Mux;

/// 每个在途流的环形缓冲上限（字节）。设计 §11.2 定的 256 KB。
pub const RING_BYTES: usize = 256 * 1024;

/// 环里内容的最长保留时间（秒）。设计 §11.2 的"最长 5 min"。
pub const RING_SECS: u64 = 300;

/// 客户端失踪后**继续 hold + 缓冲**的上限（秒）。
///
/// 为什么必须有个上限：设计只说了默认 hold + 缓冲 ✗。若客户端再也不回来，
/// 服务端会一直把上游的 token 烧完 ✗✗ ⇒ 用这个窗口把"可续传"和"不无限烧钱"分开 ✓。
pub const HOLD_SECS: u64 = 60;

/// 一条已经发出去的响应帧在环里的副本。
#[derive(Debug, Clone)]
struct Entry {
    /// 帧头里的 `seq`（客户端 ack 的就是它）。
    seq: u32,
    /// 帧的**线上字节**（帧头 + 载荷），重放时原样再发一次 ✓。
    bytes: Vec<u8>,
    at: Instant,
}

/// 一个流的环形缓冲。
///
/// 语义是"按字节有界的**帧序列**窗口"：要么能**完整**重放 `seq > ack` 的全部帧，
/// 要么明确告诉调用方"续不了"（⇒ `STREAM_GAP`）。**没有中间态** ✓ ——
/// 部分重放会拼出缺帧的响应，那正是本项目最不能接受的"看起来正常、其实是错的" ✗✗。
#[derive(Debug)]
pub struct StreamRing {
    entries: VecDeque<Entry>,
    bytes: usize,
    /// 已经因为超界被丢掉的**最小 seq**（+1）。若客户端 ack 小于它 ⇒ 续不了 ✓。
    /// `None` 表示从未丢过任何帧 ✓。
    dropped_before: Option<u32>,
    /// 最后一条入环帧的 seq，用于判断"客户端是不是已经追上来了" ✓。
    last_seq: u32,
}

/// 一次续传请求的结果。
#[derive(Debug, PartialEq, Eq)]
pub enum Replay {
    /// 可以续：按顺序把这些帧原样重发（**必然完整覆盖** `ack` 之后的所有帧）✓。
    Frames(Vec<Vec<u8>>),
    /// 续不了：调用方必须回 `ERR(STREAM_GAP)` ✓（绝不"能发多少发多少" ✗）。
    Gap,
}

impl Default for StreamRing {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamRing {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            bytes: 0,
            dropped_before: None,
            last_seq: 0,
        }
    }

    /// 记一条已发出的帧（线上字节原样留存 ✓）。
    pub fn push(&mut self, seq: u32, wire: Vec<u8>, now: Instant) {
        let n = wire.len();
        // 单帧就超过整个环：留不下 ⇒ 直接记成"续不了" ✓
        // （留一个半截的帧毫无意义，而且会让"完整重放"的判据失效 ✗）。
        if n > RING_BYTES {
            self.dropped_before = Some(
                self.dropped_before
                    .map(|d| d.max(seq.saturating_add(1)))
                    .unwrap_or(seq.saturating_add(1)),
            );
            self.last_seq = seq;
            return;
        }
        self.entries.push_back(Entry {
            seq,
            bytes: wire,
            at: now,
        });
        self.bytes += n;
        self.last_seq = seq;
        self.evict(now);
    }

    /// 按字节上限与 TTL 淘汰旧帧；每淘汰一条就抬高 `dropped_before` ✓。
    fn evict(&mut self, now: Instant) {
        let ttl = Duration::from_secs(RING_SECS);
        while self.bytes > RING_BYTES
            || self
                .entries
                .front()
                .map(|e| now.duration_since(e.at) > ttl)
                .unwrap_or(false)
        {
            let Some(old) = self.entries.pop_front() else {
                break;
            };
            self.bytes -= old.bytes.len();
            self.dropped_before = Some(
                self.dropped_before
                    .map(|d| d.max(old.seq.saturating_add(1)))
                    .unwrap_or(old.seq.saturating_add(1)),
            );
        }
    }

    /// 客户端请求从 `ack` 之后续传。
    pub fn replay_after(&mut self, ack: u32, now: Instant) -> Replay {
        self.evict(now);
        // 客户端 ack 之后**从未丢过**帧 ⇒ 还能完整续 ✓；丢过 ⇒ 缺口真实存在 ⇒ 明确说续不了 ✓。
        if let Some(dropped) = self.dropped_before {
            if ack < dropped.saturating_sub(1) {
                return Replay::Gap;
            }
        }
        let mut out = Vec::new();
        for e in self.entries.iter() {
            if e.seq > ack {
                out.push(e.bytes.clone());
            }
        }
        Replay::Frames(out)
    }

    /// 最后一条入环帧的 seq（诊断用）。
    pub fn last_seq(&self) -> u32 {
        self.last_seq
    }

    /// 环里现在有多少字节（诊断 + 内存判据用）。
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

/// **一条流的响应出口**（可重定向）。
///
/// # 为什么必须有这层间接
///
/// "续传"要求：客户端断线重连后，服务端**仍在产出**的这条流要把后续帧发到**新会话**上 ✗→✓。
/// 而转发任务里捕获的是**老会话的 `Mux`** ✗ ⇒ 若不引入这层，重放完历史帧之后新会话就再也
/// 收不到东西了（客户端会一直等 ⇒ 超时 ✗，比今天的"立刻明确报错"更糟 ✗✗）。
///
/// # 语义（与设计 §11.2 一致，外加一处保守化）
///
/// * `send()` 把帧**记进环**并尝试发给**当前** mux ✓；当前没有 mux（客户端不在）时
///   **不算错误**（设计："默认 hold + 缓冲" ✓）——但要受 [`HOLD_SECS`] 约束：
///   超窗后由转发任务主动结束该流 ✓（否则客户端再也不回来也一直烧上游 token ✗✗）。
/// * `rebind()` 把后续帧改发到新会话 ✓，并把环里 `seq > ack` 的帧**补发**给新会话 ✓。
///   补发**不重复记账**（它们已经在环里了 ✓）。
pub struct RespSink {
    /// 当前会话的 mux。`None` = 客户端不在（hold 中）。
    current: Mutex<Option<Mux>>,
    ring: Mutex<StreamRing>,
    /// 客户端失踪（`current == None`）的起始时刻；`None` = 客户端在。
    gone_since: Mutex<Option<Instant>>,
    /// **是否启用"断线期间 hold + 缓冲"**（= 对端在能力清单里声明了 `"resume"` ✓）。
    ///
    /// 关着的时候本 sink **与接线前的行为逐字节一致** ✓：发送错误直接向上传播 ⇒
    /// 转发任务结束该流（这正是今天所有已部署客户端的行为 ✓，不改变成本 ✓）。
    hold: bool,
}

impl RespSink {
    /// `hold`：对端声明了续传能力才为真（见 [`ConnCaps`](crate::egress::ConnCaps) 的说明）。
    pub fn new(mux: Mux, hold: bool) -> Arc<Self> {
        Arc::new(Self {
            current: Mutex::new(Some(mux)),
            ring: Mutex::new(StreamRing::new()),
            gone_since: Mutex::new(None),
            hold,
        })
    }

    /// 发一条响应帧：**先记进环**（保证"要重放就一定能完整重放" ✓），再发给当前会话。
    ///
    /// 两条路径泾渭分明：
    ///
    /// * `hold == false`（今天所有客户端 ✓）：错误向上传播 ⇒ 与接线前**逐行为一致** ✓；
    /// * `hold == true`（对端声明了续传 ✓）：会话不可写**不算错误** ⇒ 继续产出并缓冲 ✓，
    ///   但一旦超过 [`HOLD_SECS`] 就报错 ⇒ 转发任务结束该流 ✓（**把成本上界钉死** ✓）。
    pub async fn send(&self, f: Frame) -> anyhow::Result<()> {
        let seq = f.seq;
        let wire = f.encode();
        {
            let mut ring = self.ring.lock().unwrap();
            ring.push(seq, wire, Instant::now());
        }
        let cur = self.current.lock().unwrap().clone();
        match cur {
            Some(m) => match m.send(f).await {
                Ok(()) => {
                    *self.gone_since.lock().unwrap() = None;
                    Ok(())
                }
                Err(e) => {
                    if !self.hold {
                        return Err(anyhow::Error::from(e));
                    }
                    tracing::debug!(seq, %e, "响应帧发不出去 ⇒ 转入 hold（客户端声明过续传）");
                    self.mark_gone();
                    Ok(())
                }
            },
            None => {
                if !self.hold {
                    anyhow::bail!("会话已不在（对端未声明续传能力）");
                }
                if self.hold_exceeded() {
                    anyhow::bail!(
                        "客户端失踪超过 {}s 仍未续传 ⇒ 主动结束该流（不再消耗上游）",
                        HOLD_SECS
                    );
                }
                Ok(())
            }
        }
    }

    fn mark_gone(&self) {
        let mut g = self.gone_since.lock().unwrap();
        if g.is_none() {
            *g = Some(Instant::now());
        }
        *self.current.lock().unwrap() = None;
    }

    /// hold 是否已经超窗 ⇒ 转发任务应当**主动结束**这条流 ✓（不无限烧 token ✓）。
    pub fn hold_exceeded(&self) -> bool {
        let g = self.gone_since.lock().unwrap();
        match *g {
            Some(t) => t.elapsed() > Duration::from_secs(HOLD_SECS),
            None => false,
        }
    }

    /// 当前会话的 mux（发会话级帧、如 `Err` 用）。客户端不在时为 `None` ✓。
    pub fn session(&self) -> Option<Mux> {
        self.current.lock().unwrap().clone()
    }

    /// 客户端（新会话）来续传：把后续帧改发到它，并补发环里 `seq > ack` 的帧。
    ///
    /// 返回 [`Replay`]：`Gap` 时调用方必须回 `ERR(STREAM_GAP)` ✓（**绝不部分重放** ✓）。
    pub async fn rebind_and_replay(&self, mux: Mux, ack: u32) -> Replay {
        let frames = {
            let mut ring = self.ring.lock().unwrap();
            ring.replay_after(ack, Instant::now())
        };
        // 先换出口再补发：否则补发期间新产出的帧又会发到老会话上 ✗。
        *self.current.lock().unwrap() = Some(mux.clone());
        *self.gone_since.lock().unwrap() = None;
        match frames {
            Replay::Gap => Replay::Gap,
            Replay::Frames(list) => {
                for wire in &list {
                    // 补发的帧**直接发**（不经 `send`）：它们已经在环里，再记一次会重复 ✓。
                    match Frame::decode(wire, llm_proxy_core::config::MAX_FRAME_BYTES) {
                        Ok(Some((f, _))) => {
                            if let Err(e) = mux.send(f).await {
                                tracing::warn!(?e, "续传补发失败");
                                return Replay::Gap;
                            }
                        }
                        _ => {
                            tracing::error!("环里的帧解不回来——绝不在这种状态下继续续传");
                            return Replay::Gap;
                        }
                    }
                }
                Replay::Frames(vec![])
            }
        }
    }

    /// 环的诊断读数（`(字节数, 最后 seq)`）。
    pub fn ring_stats(&self) -> (usize, u32) {
        let r = self.ring.lock().unwrap();
        (r.bytes(), r.last_seq())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at0() -> Instant {
        Instant::now()
    }

    #[test]
    fn replays_exactly_the_frames_after_the_ack() {
        let mut r = StreamRing::new();
        let now = at0();
        for (seq, s) in [(1u32, "a"), (2, "bb"), (3, "ccc")] {
            r.push(seq, s.as_bytes().to_vec(), now);
        }
        assert_eq!(
            r.replay_after(1, now),
            Replay::Frames(vec![b"bb".to_vec(), b"ccc".to_vec()]),
            "只重放 ack 之后的帧"
        );
        assert_eq!(
            r.replay_after(3, now),
            Replay::Frames(vec![]),
            "已经追平 ⇒ 没有要重放的（合法，不是错误）"
        );
    }

    #[test]
    fn overflow_makes_it_a_gap_not_a_partial_replay() {
        let mut r = StreamRing::new();
        let now = at0();
        // 塞满并越过上限：每帧 64 KiB ⇒ 5 帧就把 256 KiB 环顶穿 ✓
        let big = vec![7u8; 64 * 1024];
        for seq in 1..=5 {
            r.push(seq, big.clone(), now);
        }
        assert!(r.bytes() <= RING_BYTES, "环必须始终 ≤ 上限：{}", r.bytes());
        // ack=0 的那部分已经被淘汰 ⇒ **必须**报 Gap，而不是"能发多少发多少" ✗
        assert_eq!(r.replay_after(0, now), Replay::Gap);
        // 而 ack 已经追到被淘汰之后的区间 ⇒ 仍然能续 ✓
        match r.replay_after(4, now) {
            Replay::Frames(f) => assert!(!f.is_empty(), "最新的那帧应当还在环里"),
            Replay::Gap => panic!("ack 落在保留区间内却报 Gap，判据过严"),
        }
    }

    #[test]
    fn a_single_frame_larger_than_the_ring_is_honestly_a_gap() {
        let mut r = StreamRing::new();
        let now = at0();
        r.push(1, vec![0u8; RING_BYTES + 1], now);
        assert_eq!(r.bytes(), 0, "留不下的帧不该占着环");
        assert_eq!(
            r.replay_after(0, now),
            Replay::Gap,
            "单帧超界 ⇒ 从它之前的位置续不了 ✓"
        );
    }

    #[test]
    fn ttl_drops_old_frames_even_when_bytes_are_plenty() {
        let mut r = StreamRing::new();
        let t0 = at0();
        r.push(1, b"x".to_vec(), t0);
        let later = t0 + Duration::from_secs(RING_SECS + 1);
        assert_eq!(
            r.replay_after(0, later),
            Replay::Gap,
            "超过 TTL 的帧必须被淘汰 ⇒ 续不了要说清 ✓"
        );
    }
}
