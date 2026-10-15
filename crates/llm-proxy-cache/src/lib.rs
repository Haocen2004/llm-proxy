//! 块缓存（服务端）与上传记账（客户端）。
//!
//! 设计要点见 §5.1 / §5.5 / §9：
//!
//! * **纯内存，默认不落盘**（保护软路由 flash 寿命）。
//! * TTL = 6h，**自创建时刻固定计算**（非滑动），另加容量上限 LRU 淘汰。
//! * 客户端**只保留块指纹**（约 9 KB/快照），块内容留在服务端——
//!   实测单个 body 中位 3 MB，若客户端保留完整体则 12 MB 预算仅够 4 个快照。
//! * 内存压力下先淘汰最旧条目，**不得 OOM**；单个块超预算时拒绝写入。
//!
//! 两条必须在实现里保住的正确性性质：
//!
//! 1. **淘汰是安全的**。客户端遗忘一个块指纹，只会导致该块被重发（多花流量），
//!    不会导致错误内容；服务端淘汰一个块，会导致 `BLOCK_MISS` 并由上层降级重发。
//! 2. **`get` 永不返回「别的块」**。指纹是 128 bit 内容寻址，键冲突即错误重组，
//!    因此这里不做任何「近似匹配」。

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use llm_proxy_core::fingerprint::{block_fp, Fp, Namespace};
use llm_proxy_core::token::{recompose_collect, Recompose, RecomposeError};

/// 设计 §5.1：TTL 固定 6 小时。
pub const DEFAULT_TTL: Duration = Duration::from_secs(6 * 60 * 60);

/// 服务端块存储的默认预算。服务端无 ARM 内存约束，可远大于客户端。
pub const DEFAULT_SERVER_BUDGET: usize = 256 << 20;
/// 客户端上传记账的默认条目上限。
///
/// 每条约 24 B + 哈希开销，20 万条约数 MB，落在 §12 的 12 MB 缓存预算内。
pub const DEFAULT_UPLOAD_ENTRIES: usize = 200_000;

// ---------------------------------------------------------------------------
// 服务端：块存储
// ---------------------------------------------------------------------------

struct Entry {
    data: Vec<u8>,
    created: Instant,
    /// 最近使用时刻，用于 LRU 淘汰。
    used: Instant,
    used_seq: u64,
}

/// 块存储统计。用于可观测性（设计 §14）与降级判断。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StoreStats {
    pub hits: u64,
    pub misses: u64,
    pub inserts: u64,
    pub evicted_lru: u64,
    pub evicted_ttl: u64,
    /// 因单块超过预算而被拒的次数。
    pub rejected_oversize: u64,
}

/// 服务端块存储：`fp -> 块内容`，LRU + 固定 TTL。
pub struct BlockStore {
    map: HashMap<Fp, Entry>,
    /// `used_seq -> fp`，用于 O(log n) 找到最久未用的条目。
    by_seq: BTreeMap<u64, Fp>,
    seq: u64,
    bytes: usize,
    budget: usize,
    ttl: Duration,
    stats: StoreStats,
}

impl BlockStore {
    pub fn new(budget: usize, ttl: Duration) -> Self {
        Self {
            map: HashMap::new(),
            by_seq: BTreeMap::new(),
            seq: 0,
            bytes: 0,
            budget,
            ttl,
            stats: StoreStats::default(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_SERVER_BUDGET, DEFAULT_TTL)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn budget(&self) -> usize {
        self.budget
    }

    pub fn stats(&self) -> StoreStats {
        self.stats
    }

    /// 查块。命中会刷新 LRU 位置。
    pub fn get_at(&mut self, fp: &Fp, now: Instant) -> Option<&[u8]> {
        let created = match self.map.get(fp) {
            Some(e) => e.created,
            None => {
                self.stats.misses += 1;
                return None;
            }
        };
        if now.duration_since(created) > self.ttl {
            self.remove(fp);
            self.stats.evicted_ttl += 1;
            self.stats.misses += 1;
            return None;
        }
        // 刷新 LRU：摘掉旧的排序键，插入新的。
        // 注意先把 `map` 的可变借用结束掉，再动 `by_seq`，否则借用检查器不允许。
        let old_seq = self.map.get(fp).map(|e| e.used_seq).unwrap();
        self.by_seq.remove(&old_seq);
        let seq = self.next_seq();
        if let Some(e) = self.map.get_mut(fp) {
            e.used = now;
            e.used_seq = seq;
        }
        self.by_seq.insert(seq, *fp);
        self.stats.hits += 1;
        self.map.get(fp).map(|e| e.data.as_slice())
    }

    pub fn get(&mut self, fp: &Fp) -> Option<&[u8]> {
        self.get_at(fp, Instant::now())
    }

    /// 写入块。返回 `false` 表示因单块超过预算被拒（**不静默截断**）。
    ///
    /// 重复写入同一指纹时只刷新 LRU，不重复计费。
    pub fn insert_at(&mut self, fp: Fp, data: Vec<u8>, now: Instant) -> bool {
        if data.len() > self.budget {
            self.stats.rejected_oversize += 1;
            return false;
        }
        if self.map.contains_key(&fp) {
            // 内容寻址：同指纹必同内容，无需比对，只刷新 LRU
            let old_seq = self.map.get(&fp).map(|e| e.used_seq).unwrap();
            self.by_seq.remove(&old_seq);
            let seq = self.next_seq();
            if let Some(e) = self.map.get_mut(&fp) {
                e.used = now;
                e.used_seq = seq;
            }
            self.by_seq.insert(seq, fp);
            return true;
        }
        let need = data.len();
        while self.bytes + need > self.budget {
            if !self.evict_lru() {
                break;
            }
        }
        let seq = self.next_seq();
        self.bytes += need;
        self.map.insert(
            fp,
            Entry {
                data,
                created: now,
                used: now,
                used_seq: seq,
            },
        );
        self.by_seq.insert(seq, fp);
        self.stats.inserts += 1;
        true
    }

    pub fn insert(&mut self, fp: Fp, data: Vec<u8>) -> bool {
        self.insert_at(fp, data, Instant::now())
    }

    /// 清理过期条目。
    pub fn sweep_at(&mut self, now: Instant) -> usize {
        let dead: Vec<Fp> = self
            .map
            .iter()
            .filter(|(_, e)| now.duration_since(e.created) > self.ttl)
            .map(|(fp, _)| *fp)
            .collect();
        let n = dead.len();
        for fp in dead {
            self.remove(&fp);
        }
        self.stats.evicted_ttl += n as u64;
        n
    }

    /// 用本存储重组 TokenStream，并把其中的 literal 块顺手落库。
    ///
    /// 合并成一次调用是为了少一次重切分：`recompose_collect` 在处理 literal 时已经
    /// 知道块内容与指纹，直接复用即可。
    pub fn recompose(
        &mut self,
        ns: Namespace,
        stream: &[u8],
        now: Instant,
    ) -> Result<Recompose, RecomposeError> {
        let r = {
            let this: &Self = self;
            recompose_collect(ns, stream, |fp| this.map.get(fp).map(|e| e.data.as_slice()))
        }?;
        for (fp, data) in &r.new_blocks {
            self.insert_at(*fp, data.clone(), now);
        }
        Ok(r)
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn evict_lru(&mut self) -> bool {
        let Some((&seq, &fp)) = self.by_seq.iter().next() else {
            return false;
        };
        self.by_seq.remove(&seq);
        self.remove(&fp);
        self.stats.evicted_lru += 1;
        true
    }

    fn remove(&mut self, fp: &Fp) {
        if let Some(e) = self.map.remove(fp) {
            self.bytes = self.bytes.saturating_sub(e.data.len());
            self.by_seq.remove(&e.used_seq);
        }
    }
}

impl Default for BlockStore {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ---------------------------------------------------------------------------
// 客户端：上传记账
// ---------------------------------------------------------------------------

/// 客户端一侧的「对端已持有这些块」账本。
///
/// **只记指纹，不存内容**——这是 §5.5 修正后的关键约束：客户端算增量只需要知道
/// 「对端有没有」，不需要块的字节。内容留在服务端。
///
/// 生命周期：
/// 1. 发请求前用 [`Self::believes`] 决定每块发 `REF` 还是 `LITERAL`；
/// 2. 把本请求的新增指纹保存在请求自己的局部变量中；
/// 3. 收到 `RespHead`（提交点）后用 [`Self::commit_sent`] 原子并入共享账本；
/// 4. 请求失败时不提交本请求的局部指纹；
/// 5. 对端报告缺块（服务端重启/淘汰）则 [`Self::forget`] 指定指纹；跨设备探测
///    得到的已存在指纹则用 [`Self::observe_present`] 记录。
///
/// [`Self::record_sent`] / [`Self::commit`] / [`Self::rollback`] 仍保留给串行调用者
/// 和兼容测试，但并行请求不能共用它们的 `pending` 列表。第 3 步之前不提交是必需的：
/// 未提交的请求可能被重传，若提前记账会让后续请求引用对端其实没有的块。
pub struct UploadSet {
    known: HashSet<Fp>,
    order: VecDeque<Fp>,
    pending: Vec<Fp>,
    max_entries: usize,
    /// 因容量上限被遗忘的指纹数。非 0 是正常的（只是多花流量），但值得观测。
    forgotten: u64,
}

impl UploadSet {
    pub fn new(max_entries: usize) -> Self {
        Self {
            known: HashSet::new(),
            order: VecDeque::new(),
            pending: Vec::new(),
            max_entries: max_entries.max(1),
            forgotten: 0,
        }
    }

    pub fn believes(&self, fp: &Fp) -> bool {
        self.known.contains(fp)
    }

    pub fn len(&self) -> usize {
        self.known.len()
    }

    pub fn is_empty(&self) -> bool {
        self.known.is_empty()
    }

    pub fn forgotten(&self) -> u64 {
        self.forgotten
    }

    /// 记下本次以 `LITERAL` 发出的块，等提交点确认。
    pub fn record_sent<'a>(&mut self, fps: impl IntoIterator<Item = &'a Fp>) {
        for fp in fps {
            if !self.known.contains(fp) {
                self.pending.push(*fp);
            }
        }
    }

    /// 提交点已过：把 pending 并入 known。
    pub fn commit(&mut self) {
        // 先把 pending 取出来，避免 drain 的借用与 insert_known 的 &mut self 冲突
        let pending = std::mem::take(&mut self.pending);
        for fp in pending {
            self.insert_known(fp);
        }
    }

    /// 在一个独立请求成功后提交它实际发送过的指纹。
    ///
    /// `pending` 适合单请求串行调用，但客户端允许多个 session/stream 并行：
    /// 若所有请求共用一个 pending 列表，一个请求失败时 `rollback()` 会误删另一个
    /// 请求的待提交状态，或者一个请求成功时 `commit()` 会提前提交尚未完成的请求。
    /// 并发路径应把指纹保存在请求自己的局部变量中，提交点到达后调用本方法；
    /// 这样缓存知识仍是进程级共享的，事务状态却按请求隔离。
    pub fn commit_sent<'a>(&mut self, fps: impl IntoIterator<Item = &'a Fp>) {
        for fp in fps {
            self.insert_known(*fp);
        }
    }

    /// 通过服务端的 `BLOCK_MISS` 响应确认远端已有的块。
    ///
    /// 这用于跨设备冷启动探测：客户端可以先用整批 `REF` 试探服务端缓存，
    /// 服务端只返回缺失指纹；未列入缺失清单的指纹因此可以加入本地知识。
    pub fn observe_present<'a>(&mut self, fps: impl IntoIterator<Item = &'a Fp>) {
        self.commit_sent(fps);
    }

    /// 请求失败：丢弃 pending（对端可能没收到）。
    pub fn rollback(&mut self) {
        self.pending.clear();
    }

    /// 对端状态丢失：全部遗忘，下次请求回退到全量。
    pub fn clear(&mut self) {
        self.known.clear();
        self.order.clear();
        self.pending.clear();
    }

    /// **只遗忘指定指纹**（服务端明确报告缺失的那些）。
    ///
    /// 比 `clear()` 精确得多：服务端可能只是淘汰了少量块（LRU/TTL），
    /// 整本清空会让下一次请求白重发几 MB。返回真正被遗忘的条数。
    pub fn forget<'a>(&mut self, fps: impl IntoIterator<Item = &'a Fp>) -> usize {
        let mut n = 0;
        for fp in fps {
            if self.known.remove(fp) {
                n += 1;
            }
        }
        if n > 0 {
            let known = &self.known;
            self.order.retain(|fp| known.contains(fp));
        }
        n
    }

    fn insert_known(&mut self, fp: Fp) {
        if !self.known.insert(fp) {
            return;
        }
        self.order.push_back(fp);
        while self.order.len() > self.max_entries {
            if let Some(old) = self.order.pop_front() {
                if self.known.remove(&old) {
                    self.forgotten += 1;
                }
            }
        }
    }
}

/// 把 `body` 的块指纹全部记入账本（用于「已确认全量送达」之后）。
pub fn all_block_fps(ns: Namespace, body: &[u8]) -> Vec<Fp> {
    llm_proxy_core::cdc::chunks(body)
        .map(|b| block_fp(ns, b))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use llm_proxy_core::token::{decompose, write_literal, write_ref};

    fn ns() -> Namespace {
        Namespace::derive(b"psk", "t", "h")
    }

    fn blk(i: u8, len: usize) -> Vec<u8> {
        vec![i; len]
    }

    /// 约 400 KB 的高多样性 body，用于缓存路径测试。
    ///
    /// 用 CJK 池逐字符采样以保证窗口多样性——周期或低多样性内容会让 CDC 退化、
    /// 切不出足够多的块（见 `llm-proxy-core::cdc` 的专项测试），那样这些测试就测不到
    /// 多块路径了。
    fn test_body() -> Vec<u8> {
        let mut x = 0x1234_5678_9ABC_DEF0u64;
        let mut s = String::with_capacity(400_000);
        for _ in 0..120_000 {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            s.push(char::from_u32(0x4E00 + ((x >> 33) as u32 % 3000)).unwrap());
        }
        format!(r#"{{"model":"m","messages":[{{"content":"{s}"}}]}}"#).into_bytes()
    }

    // ---- BlockStore ----

    #[test]
    fn insert_get_roundtrip() {
        let mut s = BlockStore::new(1024, DEFAULT_TTL);
        let fp = block_fp(ns(), b"hello");
        assert!(s.insert(fp, b"hello".to_vec()));
        assert_eq!(s.get(&fp), Some(&b"hello"[..]));
        assert_eq!(s.len(), 1);
        assert_eq!(s.bytes(), 5);
    }

    #[test]
    fn missing_block_is_none_and_counted() {
        let mut s = BlockStore::new(1024, DEFAULT_TTL);
        let fp = block_fp(ns(), b"nope");
        assert!(s.get(&fp).is_none());
        assert_eq!(s.stats().misses, 1);
        assert_eq!(s.stats().hits, 0);
    }

    #[test]
    fn rejects_single_block_over_budget_without_truncating() {
        let mut s = BlockStore::new(64, DEFAULT_TTL);
        let fp = block_fp(ns(), &blk(1, 65));
        assert!(!s.insert(fp, blk(1, 65)), "超过预算的单块必须被拒");
        assert_eq!(s.len(), 0, "被拒的块不得留在存储里");
        assert_eq!(s.stats().rejected_oversize, 1);
    }

    #[test]
    fn evicts_lru_when_over_budget() {
        // 预算 20 字节、每块 10 字节 → 恰好放两块，第三块必须触发淘汰
        let mut s = BlockStore::new(20, DEFAULT_TTL);
        let now = Instant::now();
        let a = block_fp(ns(), &blk(1, 10));
        let b = block_fp(ns(), &blk(2, 10));
        let c = block_fp(ns(), &blk(3, 10));
        assert!(s.insert_at(a, blk(1, 10), now));
        assert!(s.insert_at(b, blk(2, 10), now));
        assert_eq!(s.bytes(), 20);
        assert_eq!(s.len(), 2);

        // 触碰 a，使其成为最近使用
        assert!(s.get_at(&a, now + Duration::from_secs(1)).is_some());

        // 插入 c 需腾出 10 字节，应淘汰最久未用的 b
        assert!(s.insert_at(c, blk(3, 10), now + Duration::from_secs(2)));
        assert_eq!(s.len(), 2, "预算只够两块");
        assert_eq!(s.bytes(), 20);
        assert!(
            s.get_at(&b, now + Duration::from_secs(3)).is_none(),
            "b 最久未用，应被淘汰"
        );
        assert!(
            s.get_at(&a, now + Duration::from_secs(3)).is_some(),
            "a 刚被触碰，应保留"
        );
        assert_eq!(s.stats().evicted_lru, 1);
    }

    #[test]
    fn ttl_is_fixed_from_creation_not_sliding() {
        let mut s = BlockStore::new(1024, Duration::from_secs(100));
        let fp = block_fp(ns(), b"x");
        let t0 = Instant::now();
        assert!(s.insert_at(fp, b"x".to_vec(), t0));

        // 反复访问不应延长寿命（设计：固定 TTL，非滑动）
        for k in 1..=90u64 {
            assert!(s.get_at(&fp, t0 + Duration::from_secs(k)).is_some());
        }
        // 超过 100s 即过期，即使期间一直在用
        assert!(s.get_at(&fp, t0 + Duration::from_secs(101)).is_none());
        assert_eq!(s.len(), 0);
        assert_eq!(s.stats().evicted_ttl, 1);
    }

    #[test]
    fn sweep_removes_expired_only() {
        let mut s = BlockStore::new(1024, Duration::from_secs(100));
        let t0 = Instant::now();
        let old = block_fp(ns(), b"old");
        assert!(s.insert_at(old, b"old".to_vec(), t0));
        let fresh = block_fp(ns(), b"fresh");
        assert!(s.insert_at(fresh, b"fresh".to_vec(), t0 + Duration::from_secs(95)));
        assert_eq!(s.sweep_at(t0 + Duration::from_secs(101)), 1);
        assert_eq!(s.len(), 1);
        assert!(s.get_at(&fresh, t0 + Duration::from_secs(102)).is_some());
    }

    #[test]
    fn reinsert_does_not_double_count_bytes() {
        let mut s = BlockStore::new(1024, DEFAULT_TTL);
        let fp = block_fp(ns(), b"dup");
        assert!(s.insert(fp, b"dup".to_vec()));
        assert!(s.insert(fp, b"dup".to_vec()));
        assert_eq!(s.len(), 1);
        assert_eq!(s.bytes(), 3);
    }

    #[test]
    fn recompose_uses_store_and_populates_it() {
        let n = ns();
        let mut s = BlockStore::new(1 << 20, DEFAULT_TTL);

        // 冷启动：全 literal
        let body = test_body();
        let d = decompose(n, &body, |_| false);
        let r = s
            .recompose(n, &d.stream, Instant::now())
            .expect("冷启动必须成功");
        assert_eq!(r.body, body, "重组必须逐字节一致");
        assert!(!r.new_blocks.is_empty(), "literal 块应被落库");
        assert!(!s.is_empty());

        // 热路径：全部命中
        let d2 = decompose(n, &body, |fp| s.map.contains_key(fp));
        assert_eq!(d2.refs, d2.blocks, "同 body 再来一次应全命中");
        let r2 = s.recompose(n, &d2.stream, Instant::now()).unwrap();
        assert_eq!(r2.body, body);
        assert!(r2.new_blocks.is_empty());
    }

    #[test]
    fn recompose_reports_all_missing_blocks() {
        let n = ns();
        let mut s = BlockStore::new(1 << 20, DEFAULT_TTL);
        let body = test_body();
        let mut stream = Vec::new();
        let mut expect = 0;
        for b in llm_proxy_core::cdc::chunks(&body) {
            write_ref(&mut stream, &block_fp(n, b));
            expect += 1;
        }
        let missing = match s.recompose(n, &stream, Instant::now()).unwrap_err() {
            RecomposeError::Missing(v) => v,
            other => panic!("引用不存在的块应当是 Missing，而不是 {other:?}"),
        };
        assert_eq!(missing.len(), expect, "应一次收集全部缺失块");
    }

    #[test]
    fn recompose_mixed_ref_and_literal() {
        let n = ns();
        let mut s = BlockStore::new(1 << 20, DEFAULT_TTL);
        let body = test_body();
        let chunks: Vec<&[u8]> = llm_proxy_core::cdc::chunks(&body).collect();

        // 只把前一半块放进存储
        let half = chunks.len() / 2;
        let mut stream = Vec::new();
        for (i, b) in chunks.iter().enumerate() {
            let fp = block_fp(n, b);
            if i < half {
                assert!(s.insert(fp, b.to_vec()));
                write_ref(&mut stream, &fp);
            } else {
                write_literal(&mut stream, b);
            }
        }
        let r = s.recompose(n, &stream, Instant::now()).unwrap();
        assert_eq!(r.body, body, "混合路径也必须逐字节一致");
        assert_eq!(s.len(), chunks.len(), "literal 部分应补齐存储");
    }

    // ---- UploadSet ----

    #[test]
    fn upload_set_commit_only_after_success() {
        let mut u = UploadSet::new(100);
        let fp = block_fp(ns(), b"a");
        assert!(!u.believes(&fp));
        u.record_sent([&fp]);
        assert!(!u.believes(&fp), "提交点之前不得声称对端已持有");
        u.commit();
        assert!(u.believes(&fp));
    }

    #[test]
    fn upload_set_rollback_discards_pending() {
        let mut u = UploadSet::new(100);
        let fp = block_fp(ns(), b"a");
        u.record_sent([&fp]);
        u.rollback();
        assert!(!u.believes(&fp));
        assert_eq!(u.len(), 0);
    }

    #[test]
    fn upload_set_clear_forgets_everything() {
        let mut u = UploadSet::new(100);
        let fp = block_fp(ns(), b"a");
        u.record_sent([&fp]);
        u.commit();
        assert!(u.believes(&fp));
        u.clear();
        assert!(!u.believes(&fp), "对端状态丢失后必须回退到全量");
        assert_eq!(u.forgotten(), 0, "clear 是显式遗忘，不计入容量淘汰");
    }

    #[test]
    fn upload_set_evicts_oldest_and_stays_bounded() {
        let mut u = UploadSet::new(3);
        let fps: Vec<Fp> = (0..5u8).map(|i| block_fp(ns(), &[i])).collect();
        for fp in &fps {
            u.record_sent([fp]);
            u.commit();
        }
        assert_eq!(u.len(), 3, "条目数必须被上限约束");
        assert!(u.forgotten() >= 2);
        // 被遗忘的只是需要重发，不影响正确性
        assert!(!u.believes(&fps[0]));
        assert!(u.believes(&fps[4]));
    }

    #[test]
    fn record_sent_skips_already_known() {
        let mut u = UploadSet::new(100);
        let fp = block_fp(ns(), b"a");
        u.record_sent([&fp]);
        u.commit();
        u.record_sent([&fp]);
        u.commit();
        assert_eq!(u.len(), 1);
    }

    #[test]
    fn concurrent_request_commits_are_independent() {
        // 两个并行请求各自持有自己的待提交指纹；一个请求提交时不能把另一个
        // 请求的状态一并带入共享账本。生产并发路径使用 `commit_sent`，而不是
        // UploadSet 的兼容性 pending/commit 组合。
        let mut u = UploadSet::new(100);
        let a = block_fp(ns(), b"a");
        let b = block_fp(ns(), b"b");

        u.commit_sent([&a]);
        assert!(u.believes(&a));
        assert!(!u.believes(&b));

        // 第二个请求失败时不需要 rollback 共享状态：它尚未提交，所以 b 仍然
        // 不会被错误地标记为远端已有。
        u.commit_sent(std::iter::empty::<&Fp>());
        assert!(!u.believes(&b));

        u.commit_sent([&b]);
        assert!(u.believes(&b));
    }

    #[test]
    fn forget_only_the_named_blocks() {
        let mut u = UploadSet::new(100);
        let fps: Vec<Fp> = (0..4u8).map(|i| block_fp(ns(), &[i])).collect();
        u.record_sent(fps.iter());
        u.commit();
        assert_eq!(u.len(), 4);

        // 服务端报告只缺 1、3
        let n = u.forget([&fps[1], &fps[3]]);
        assert_eq!(n, 2);
        assert_eq!(u.len(), 2);
        assert!(u.believes(&fps[0]) && u.believes(&fps[2]));
        assert!(!u.believes(&fps[1]) && !u.believes(&fps[3]));

        // 被遗忘的可以重新记账
        u.record_sent([&fps[1]]);
        u.commit();
        assert!(u.believes(&fps[1]));
        assert_eq!(u.len(), 3);
    }

    #[test]
    fn forget_unknown_is_noop() {
        let mut u = UploadSet::new(100);
        let fp = block_fp(ns(), b"x");
        assert_eq!(u.forget([&fp]), 0);
        assert_eq!(u.len(), 0);
    }

    #[test]
    fn all_block_fps_matches_decompose() {
        let n = ns();
        let body = test_body();
        let fps = all_block_fps(n, &body);
        let d = decompose(n, &body, |_| false);
        assert_eq!(fps.len(), d.blocks);
        assert_eq!(d.new_fps.len(), fps.len());
    }
}
