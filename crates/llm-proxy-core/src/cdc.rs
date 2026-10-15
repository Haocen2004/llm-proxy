//! FastCDC 内容定义分块（CDC）。
//!
//! 设计 §5.4：分块的目的**不是压缩率**，而是**中段插入/删除时的鲁棒性**。
//! 对话中间插入工具调用结果或多模态图片时，定长分块会让其后所有块整体错位、
//! 全部失去复用；内容定义分块只会影响插入点附近的少数块。
//!
//! 实测依据（设计 §5.5）：真实请求里 `tools`（28,960 B）位于 `messages` 之后，
//! `messages` 一变长，纯前缀法就无法复用 `tools`（那 28 KB 被整段重发），
//! 而块级去重能完整复用它们。

/// 最小块。低于此长度不检查切点，避免产生碎片。
pub const MIN_SIZE: usize = 1 << 10; // 1 KiB
/// 目标平均块长，决定伪随机掩码的位数。
pub const AVG_SIZE: usize = 1 << 13; // 8 KiB
/// 最大块。到此处强制切分，保证最坏情况的块大小有界。
pub const MAX_SIZE: usize = 1 << 16; // 64 KiB

/// Gear 表：由 splitmix64 在编译期生成，保证跨平台、跨版本完全一致。
///
/// **必须一致**：客户端与服务端用不同的表会得到不同的切点，块指纹全部对不上，
/// 复用率归零（且不会报错，只会静默退化）。因此这里不允许用任何随机源。
const GEAR: [u64; 256] = gear_table();

const fn gear_table() -> [u64; 256] {
    let mut t = [0u64; 256];
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let mut i = 0;
    while i < 256 {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        t[i] = z ^ (z >> 31);
        i += 1;
    }
    t
}

#[inline]
const fn mask(bits: u32) -> u64 {
    (1u64 << bits) - 1
}

/// 从 `d` 的起点向前找切点，返回相对偏移（1..=min(len, MAX_SIZE)）。
///
/// 采用 FastCDC 的**归一化分块**：平均点之前用更稀疏的掩码、之后用更密集的掩码，
/// 抑制块长的方差。
fn cut_point(d: &[u8]) -> usize {
    let bits = AVG_SIZE.trailing_zeros();
    let mask_s = mask(bits + 1); // 平均点之前：更难命中 → 块更长
    let mask_l = mask(bits - 1); // 平均点之后：更易命中 → 块更短
    let limit = d.len().min(MAX_SIZE);

    let mut h = 0u64;
    let mut i = 0usize;
    while i < limit {
        h = (h << 1).wrapping_add(GEAR[d[i] as usize]);
        i += 1;
        if i < MIN_SIZE {
            continue;
        }
        let m = if i < AVG_SIZE { mask_s } else { mask_l };
        if h & m == 0 {
            return i;
        }
    }
    limit
}

/// 计算分块边界（每个块的**结束**偏移，最后一个恒为 `data.len()`）。
pub fn chunk_boundaries(data: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    if data.is_empty() {
        return out;
    }
    let mut start = 0usize;
    while start < data.len() {
        let remaining = data.len() - start;
        if remaining <= MIN_SIZE {
            out.push(data.len());
            break;
        }
        let end = start + cut_point(&data[start..]);
        out.push(end);
        start = end;
    }
    out
}

/// 逐个产出块，避免调用方再切一次。
pub fn chunks(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut prev = 0usize;
    chunk_boundaries(data).into_iter().map(move |end| {
        let s = &data[prev..end];
        prev = end;
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 确定性伪随机负载，避免测试依赖外部数据。
    fn payload(n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        let mut x = 12345u64;
        for _ in 0..n {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            // 混入可重复的文本模式，模拟 JSON
            v.push(b"abcdefghijklmnopqrstuvwxyz0123456789"[((x >> 33) % 36) as usize]);
        }
        v
    }

    #[test]
    fn gear_table_matches_golden_values() {
        // 硬编码黄金值。Gear 表是**跨端契约**：客户端与服务端用不同的表会得到不同
        // 切点，块指纹全部对不上，复用率静默归零。任何改动都必须显式失败。
        // 数值由独立的 Python 实现（正确的 splitmix64，每轮只加一次常量）算出后核对。
        assert_eq!(GEAR[0], 0x6e78_9e6a_a1b9_65f4);
        assert_eq!(GEAR[1], 0x06c4_5d18_8009_454f);
        assert_eq!(GEAR[255], 0xcbdc_6d34_b7c7_534d);
        assert_eq!(GEAR, gear_table());
        let set: std::collections::HashSet<u64> = GEAR.iter().copied().collect();
        assert_eq!(set.len(), 256, "256 个值必须互不相同");
    }

    #[test]
    fn block_sizes_respect_bounds() {
        let d = payload(1 << 20); // 1 MiB
        let b = chunk_boundaries(&d);
        assert!(b.len() > 8, "1MiB 至少应切出若干块，实际 {}", b.len());
        let mut prev = 0usize;
        for &end in &b {
            let len = end - prev;
            assert!(len > 0, "不允许空块");
            assert!(len <= MAX_SIZE, "块长 {len} 超过上限");
            // 最后一块可以小于 MIN（尾部残余）
            if end != d.len() {
                assert!(len >= MIN_SIZE, "块长 {len} 低于下限");
            }
            prev = end;
        }
        assert_eq!(*b.last().unwrap(), d.len(), "最后一块必须覆盖到结尾");
    }

    #[test]
    fn empty_and_tiny_inputs() {
        assert!(chunk_boundaries(b"").is_empty());
        assert_eq!(chunk_boundaries(b"hi"), vec![2]);
        let small = payload(100);
        assert_eq!(chunk_boundaries(&small), vec![100]);
    }

    #[test]
    fn chunks_cover_input_exactly_once() {
        let d = payload(300_000);
        let joined: Vec<u8> = chunks(&d).flatten().copied().collect();
        assert_eq!(joined, d, "分块必须无缝覆盖");
    }

    /// 块内容的指纹序列。**比较内容而不是边界偏移**——偏移相同不代表可复用，
    /// 内容相同才代表可以命中缓存。早先的版本比较偏移，得出过错误结论。
    fn content_fps(data: &[u8], bounds: &[usize]) -> Vec<u64> {
        let mut v = Vec::with_capacity(bounds.len());
        let mut prev = 0usize;
        for &end in bounds {
            let h = blake3::hash(&data[prev..end]);
            v.push(u64::from_le_bytes(h.as_bytes()[..8].try_into().unwrap()));
            prev = end;
        }
        v
    }

    fn block_starts(bounds: &[usize]) -> Vec<usize> {
        let mut v = Vec::with_capacity(bounds.len());
        let mut prev = 0usize;
        for &end in bounds {
            v.push(prev);
            prev = end;
        }
        v
    }

    /// 在 `a` 的给定位置插入一段后，统计 `b` 中**插入点之后**的块有多少能按内容命中 `a`。
    fn post_insertion_match_ratio(
        cut: impl Fn(&[u8]) -> Vec<usize>,
        a: &[u8],
        inserted_at: usize,
        inserted_len: usize,
    ) -> (usize, usize) {
        let mut b = a.to_vec();
        let ins = payload(inserted_len);
        b.splice(inserted_at..inserted_at, ins.iter().copied());

        let fa = content_fps(a, &cut(a));
        let bb = cut(&b);
        let fb = content_fps(&b, &bb);
        let starts = block_starts(&bb);
        let set: std::collections::HashSet<u64> = fa.into_iter().collect();

        // 插入点 + 哈希窗口（64 字节）之后才算"重同步区"
        let boundary = inserted_at + inserted_len + 64;
        let mut matched = 0;
        let mut total = 0;
        for (i, &s) in starts.iter().enumerate() {
            if s > boundary {
                total += 1;
                if set.contains(&fb[i]) {
                    matched += 1;
                }
            }
        }
        (matched, total)
    }

    /// 核心性质：中段插入后，CDC 能让插入点之后的块按内容重新对齐。
    #[test]
    fn cdc_resyncs_by_content_after_insertion() {
        let a = payload(400_000);
        let (matched, total) = post_insertion_match_ratio(chunk_boundaries, &a, 200_000, 300);
        assert!(total > 10, "应存在足够多的插入点之后块，实际 {total}");
        let ratio = matched as f64 / total as f64;
        assert!(
            ratio > 0.9,
            "CDC 插入点之后应绝大部分按内容命中，实际 {matched}/{total} = {ratio:.2}"
        );
    }

    /// 对照组：同一场景下定长分块**一个都复用不了**。这是选用 CDC 的直接依据。
    #[test]
    fn fixed_size_chunking_reuses_nothing_after_insertion() {
        let a = payload(400_000);
        let fixed = |d: &[u8]| -> Vec<usize> {
            let mut v: Vec<usize> = (1..=d.len() / 8192).map(|i| i * 8192).collect();
            if v.last().copied() != Some(d.len()) {
                v.push(d.len());
            }
            v
        };
        let (matched, total) = post_insertion_match_ratio(fixed, &a, 200_000, 300);
        assert!(total > 10, "应存在足够多的插入点之后块，实际 {total}");
        assert_eq!(
            matched, 0,
            "定长分块在插入点之后内容整体位移，不可能有任何块命中"
        );
    }

    #[test]
    fn chunking_is_stable_across_calls() {
        let d = payload(200_000);
        assert_eq!(chunk_boundaries(&d), chunk_boundaries(&d));
    }

    /// 记录一条**根本性**性质：CDC 在强周期内容上退化为 MAX_SIZE 分块。
    ///
    /// 原因：掩码测试的低位只依赖最近约 12 字节（`h = (h<<1) + GEAR[b]`，低位由
    /// 最近若干个 GEAR 值决定），而周期为 P 的内容只有 P 个互不相同的窗口。
    /// P=138 时命中 12 位掩码的概率约 `138/4096 ≈ 3%`，于是绝大多数块直接冲到上限。
    ///
    /// **这不是实现缺陷**：任何滚动哈希都有同一上界——平均块长不可能小于
    /// 「可用不同窗口数」`= min(周期, 窗口长度)`，而要得到 2^k 字节的平均块长就
    /// 需要 2^k 个不同窗口。真实 LLM 请求里的 system prompt / 工具 schema 常有
    /// 长段重复样板，因此这个退化在现实中会遇到，必须显式记录而不是假装不存在。
    ///
    /// 影响面：
    /// * **尾部追加**（多轮对话的主要形态）——无害，已有块全部复用；
    /// * **中段插入**（工具结果、多模态图片插入对话中段）——退化为定长分块，
    ///   丧失设计 §5.4 想要的鲁棒性。
    ///
    /// 缓解手段是把 [`MAX_SIZE`] 调小（直接决定退化时的有效块长），代价是块数
    /// 与指纹存储同比增加。
    #[test]
    fn periodic_content_degenerates_to_max_size() {
        // 周期 138 字节：同一句话反复出现
        let sentence = payload(138);
        let mut periodic = Vec::with_capacity(400_000);
        while periodic.len() < 400_000 {
            periodic.extend_from_slice(&sentence);
        }
        let b = chunk_boundaries(&periodic);
        let at_max = b.windows(2).filter(|w| w[1] - w[0] == MAX_SIZE).count();
        let ratio = at_max as f64 / (b.len() - 1).max(1) as f64;
        assert!(
            ratio > 0.8,
            "周期内容应主要在 MAX_SIZE 处分块，实际 {ratio:.2}（{at_max}/{})",
            b.len() - 1
        );

        // 对照：非周期（伪随机）内容应落在设计目标附近
        let rnd = payload(1 << 20);
        let br = chunk_boundaries(&rnd);
        let avg = rnd.len() as f64 / br.len() as f64;
        assert!(
            avg > AVG_SIZE as f64 / 2.0 && avg < AVG_SIZE as f64 * 3.0,
            "非周期内容的平均块长应接近 AVG_SIZE={AVG_SIZE}，实际 {avg:.0}"
        );
    }
}
