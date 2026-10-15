//! zstd 压缩上下文池（设计 §7 压缩层选型、§12 ARM 资源预算）。
//!
//! # 四条约束决定了这里的设计
//!
//! 1. **上下文必须复用且数量受限**。zstd 的 `CCtx` 会按 windowLog/hashLog 预分配内部表，
//!    每帧新建上下文在 ARM 软路由上不可接受。这里用固定容量的池（`COMPRESS_CTX_POOL`），
//!    并且**池忙时直接放弃压缩**而不是等待——原样发送永远正确，等待会拖慢整条链路。
//! 2. **压缩绝不能使体积变大**。`try_compress` 只在结果**严格更小**时返回 `Some`。
//!    这条规则让"要不要压缩"不需要任何熵估计/启发式：试一次，不比原文小就不用。
//!    设计 §7.2 说"高熵内容禁用字典"，这里是它的**可执行形式**。
//! 3. **内存必须可测量、可断言**。用 `ZSTD_sizeof_CCtx/DCtx` 直接取上下文自身的常驻内存。
//!    注意一个容易踩的陷阱：**内存在首次压缩之后才会长到稳态**，创建时测会明显低估——
//!    所以这里按槽位记录**峰值**，而不是建池那一刻的值。
//! 4. **必须用 `compress2` 而不是 `compress`**。`CCtx::compress` 包的是 `ZSTD_compressCCtx`，
//!    它会**忽略上下文里设置的参数与已加载的字典**；只有 `compress2`（`ZSTD_compress2`）
//!    才采用上下文参数。用错的话 windowLog 与字典设置全部失效且不会报错。
//!
//! # 字典是"格式化字典"
//!
//! `dicts/*.zstdict` 由 Python `zstd.train_dictionary(...).as_bytes()` 产出，带 zstd 字典
//! 魔数 `37a430ec` 和内嵌 dictID。因此 zstd 会把 dictID 写进帧、解压时校验——**字典不匹配
//! 会直接报错，而不是解出一段看似正常的垃圾**。这正是我们要的失败方式。
#![forbid(unsafe_code)]

use std::sync::Mutex;

use zstd::zstd_safe::{get_error_name, CCtx, CParameter, DCtx};

use crate::config::{COMPRESS_CTX_POOL, WINDOW_LOG};

/// 压缩级别。设计 §7.4：级别 1（软路由上 CPU 是瓶颈，级别再高收益很小）。
pub const LEVEL: i32 = 1;

/// 小于此长度的载荷直接原样发送。
///
/// 试压要付一次参数设置 + 一次压缩调用的 CPU，而这么短的载荷即使压得动也只省几个字节。
pub const MIN_COMPRESS_BYTES: usize = 128;

/// 单次解压结果的上限保护。畸形输入可能声明一个巨大的长度，不能照单分配。
pub const MAX_DECOMPRESS_BYTES: usize = 16 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressError {
    /// 字典超过 zstd window，zstd 会直接报错。
    DictionaryTooLarge {
        dict_bytes: usize,
        window_bytes: usize,
    },
    /// 创建/配置 zstd 上下文失败。
    Context(String),
    /// 解压失败：畸形、截断，或**字典不匹配**（dictID 校验不通过）。
    Corrupt(String),
    /// 声明的解压长度超过上限。
    TooLarge { declared: usize, limit: usize },
}

impl std::fmt::Display for CompressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DictionaryTooLarge {
                dict_bytes,
                window_bytes,
            } => write!(
                f,
                "字典 {dict_bytes} 字节超过 zstd window {window_bytes} 字节"
            ),
            Self::Context(e) => write!(f, "zstd 上下文错误：{e}"),
            Self::Corrupt(e) => write!(f, "解压失败：{e}"),
            Self::TooLarge { declared, limit } => {
                write!(f, "声明的解压长度 {declared} 超过上限 {limit}")
            }
        }
    }
}

impl std::error::Error for CompressError {}

/// 统计。用于可观测性（设计 §14），也是判断「压缩是否真的划算」的依据。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub attempted: u64,
    pub used: u64,
    /// 因载荷过短而跳过。
    pub skipped_small: u64,
    /// 因池中无空闲上下文而跳过（**不是错误**）。
    pub skipped_busy: u64,
    /// 试压后不比原文小，放弃。
    pub skipped_incompressible: u64,
    pub original_bytes: u64,
    /// 实际该经链路发送的字节数（压缩成功时是压缩后长度，否则是原文长度）。
    pub wire_bytes: u64,
    pub decompressed: u64,
}

impl Stats {
    /// 改发压缩后，体积占比；没有样本时返回 1.0（"没省"）。
    pub fn ratio(&self) -> f64 {
        if self.original_bytes == 0 {
            1.0
        } else {
            self.wire_bytes as f64 / self.original_bytes as f64
        }
    }
}

struct Slot {
    cc: CCtx<'static>,
    busy: bool,
    /// 该上下文**观察到的峰值**常驻内存。内存在首次压缩后才到稳态，故取峰值。
    peak_bytes: usize,
}

struct Inner {
    slots: Vec<Slot>,
    dctx: DCtx<'static>,
    stats: Stats,
}

/// 一个字典对应的压缩上下文池。
pub struct CompressPool {
    inner: Mutex<Inner>,
    dict_id: u32,
    capacity: usize,
}

impl CompressPool {
    /// 建池。`capacity` 为 0 时按 [`COMPRESS_CTX_POOL`] 取。
    pub fn new(dict: &[u8], capacity: usize) -> Result<Self, CompressError> {
        let window_bytes = 1usize << WINDOW_LOG;
        if dict.len() > window_bytes {
            return Err(CompressError::DictionaryTooLarge {
                dict_bytes: dict.len(),
                window_bytes,
            });
        }

        let capacity = if capacity == 0 {
            COMPRESS_CTX_POOL
        } else {
            capacity
        };

        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            let mut cc = CCtx::create();
            cc.set_parameter(CParameter::CompressionLevel(LEVEL))
                .map_err(safe_err)?;
            // 显式钉住 window：字典必须装得下，且上下文内存可预测（设计 §12）
            cc.set_parameter(CParameter::WindowLog(WINDOW_LOG))
                .map_err(safe_err)?;
            // 把原始长度写进帧头，解压端据此精确分配并检测截断
            cc.set_parameter(CParameter::ContentSizeFlag(true))
                .map_err(safe_err)?;
            // **必须开校验**。zstd 默认不做块级校验，翻转一个字节会**静默解出错误字节**
            // ——这正是设计 §3.2 列为唯一致命风险的那种失败。代价是每帧 4 字节，
            // 而一个 body 每请求只压一次，这 4 字节换来「损坏必报错」非常值。
            //
            // 注意这**不是**在替代帧层 CRC32C，而是第二道防线：CRC 挡传输损坏，
            // 这里挡「压缩数据本身被改坏」以及实现层面的错配。
            cc.set_parameter(CParameter::ChecksumFlag(true))
                .map_err(safe_err)?;
            if !dict.is_empty() {
                cc.load_dictionary(dict).map_err(safe_err)?;
            }
            // 建池时已经有一份基础分配；首次压缩后会涨到稳态，故取峰值
            let peak_bytes = cc.sizeof();
            slots.push(Slot {
                cc,
                busy: false,
                peak_bytes,
            });
        }

        let mut dctx = DCtx::create();
        if !dict.is_empty() {
            dctx.load_dictionary(dict).map_err(safe_err)?;
        }

        Ok(Self {
            inner: Mutex::new(Inner {
                slots,
                dctx,
                stats: Stats::default(),
            }),
            dict_id: crate::dict::dict_id(dict),
            capacity,
        })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn dict_id(&self) -> u32 {
        self.dict_id
    }

    /// **上下文自身的常驻内存**。设计 §12 要求"压缩相关内存 <1MB"，这就是那个量。
    ///
    /// 取的是各上下文的**峰值**。首次压缩前该值会明显偏低——这是刻意的：
    /// 门禁必须断言稳态值，而不是一个还没长起来的数。
    pub fn context_bytes(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.slots.iter().map(|s| s.peak_bytes).sum::<usize>() + inner.dctx.sizeof()
    }

    pub fn stats(&self) -> Stats {
        self.inner.lock().unwrap().stats
    }

    /// 可用的空闲上下文数（观测用）。
    pub fn available(&self) -> usize {
        self.inner
            .lock()
            .unwrap()
            .slots
            .iter()
            .filter(|s| !s.busy)
            .count()
    }

    /// 尝试压缩。
    ///
    /// 返回 `None` 表示**不要压缩**：载荷过短、池中无空闲上下文、或压完不比原文小。
    /// 三种原因都不该被当作错误——调用方原样发送即可，永远正确。
    pub fn try_compress(&self, src: &[u8]) -> Option<Vec<u8>> {
        if src.len() < MIN_COMPRESS_BYTES {
            self.record(src.len(), src.len(), |s| s.skipped_small += 1);
            return None;
        }

        let mut inner = self.inner.lock().unwrap();
        inner.stats.attempted += 1;
        let Some(idx) = inner.slots.iter().position(|s| !s.busy) else {
            inner.stats.skipped_busy += 1;
            inner.stats.original_bytes += src.len() as u64;
            inner.stats.wire_bytes += src.len() as u64;
            return None;
        };
        inner.slots[idx].busy = true;

        let outcome = {
            let slot = &mut inner.slots[idx];
            // `compress2` 采用上下文参数与已加载字典；`compress` 不会。
            let r = (|| -> Result<Vec<u8>, CompressError> {
                let mut out = Vec::with_capacity(src.len());
                slot.cc.compress2(&mut out, src).map_err(safe_err)?;
                Ok(out)
            })();
            // 内存此时已长到稳态，记录峰值
            slot.peak_bytes = slot.peak_bytes.max(slot.cc.sizeof());
            slot.busy = false;
            r
        };

        inner.stats.original_bytes += src.len() as u64;
        match outcome {
            // 压缩失败必须是"放弃压缩"，绝不能是"发错数据"
            Err(_) => {
                inner.stats.skipped_incompressible += 1;
                inner.stats.wire_bytes += src.len() as u64;
                None
            }
            Ok(out) if out.len() >= src.len() => {
                inner.stats.skipped_incompressible += 1;
                inner.stats.wire_bytes += src.len() as u64;
                None
            }
            Ok(out) => {
                inner.stats.used += 1;
                inner.stats.wire_bytes += out.len() as u64;
                Some(out)
            }
        }
    }

    /// 解压。`limit` 是允许的最大输出长度。
    ///
    /// 失败一律返回 `Err`——**绝不返回部分结果**。这与设计 §3.2 的红线一致：
    /// 半个 body 比一个明确的错误危险得多。
    pub fn decompress(&self, src: &[u8], limit: usize) -> Result<Vec<u8>, CompressError> {
        let limit = limit.min(MAX_DECOMPRESS_BYTES);
        let declared = zstd::zstd_safe::get_frame_content_size(src)
            .ok()
            .flatten()
            .map(|n| n as usize);
        if let Some(n) = declared {
            if n > limit {
                return Err(CompressError::TooLarge { declared: n, limit });
            }
        }

        let mut inner = self.inner.lock().unwrap();
        let mut out: Vec<u8> = Vec::with_capacity(declared.unwrap_or(0).min(limit) + 64);
        inner
            .dctx
            .decompress(&mut out, src)
            .map_err(|code| CompressError::Corrupt(get_error_name(code).to_string()))?;
        if out.len() > limit {
            return Err(CompressError::TooLarge {
                declared: out.len(),
                limit,
            });
        }
        inner.stats.decompressed += 1;
        Ok(out)
    }

    fn record(&self, original: usize, wire: usize, f: impl FnOnce(&mut Stats)) {
        let mut inner = self.inner.lock().unwrap();
        inner.stats.attempted += 1;
        f(&mut inner.stats);
        inner.stats.original_bytes += original as u64;
        inner.stats.wire_bytes += wire as u64;
    }
}

impl std::fmt::Debug for CompressPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompressPool")
            .field("dict_id", &self.dict_id)
            .field("capacity", &self.capacity)
            .field("context_bytes", &self.context_bytes())
            .field("stats", &self.stats())
            .finish()
    }
}

fn safe_err(code: usize) -> CompressError {
    CompressError::Context(get_error_name(code).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dict::Dicts;

    fn pool() -> CompressPool {
        let d = Dicts::bootstrap();
        CompressPool::new(d.patch, 0).expect("建池失败")
    }

    /// 真实 LLM 请求里会反复出现的句子。**字典与 zstd 的收益主要来自这种重复与结构。**
    const FRAGMENTS: &[&str] = &[
        "请复核重传窗口与拥塞窗口的配置是否匹配。",
        "建议把探测间隔降到十毫秒并开启 nodelay。",
        "这个模块的测试覆盖了乱序与丢包，但没有覆盖窗口耗尽。",
        "工具返回的内容包含路径与行号，我已按依赖关系排序。",
        "上游返回 429 时应退避而不是立刻重试，否则会放大限流。",
        "缓存条目的有效期固定为六小时，不做滑动续期。",
        "补缺协商最多额外一轮往返，否则会拖慢首字节时间。",
        "加密的作用域是批次而不是单帧，否则标签会吃掉全部收益。",
    ];

    /// 结构化请求体：键名高度重复 + 工具 schema 冗余 + 自然语言片段池。
    ///
    /// **不要用伪随机字节做压缩率测试**：那测的是熵下限，不是字典收益。
    /// Python 门禁已经量过这一点——脱敏语料上 full_body 的字典增益只有 1.02×，
    /// 因为脱敏填充物本身就是伪随机的；字典的真实收益在**结构**上（structure 增益 2.15×）。
    fn structured_body(n_msgs: usize) -> Vec<u8> {
        let mut s = String::from(
            r#"{"model":"gpt-4o","stream":true,"temperature":0.7,"tools":[{"type":"function","function":{"name":"search","description":"查询内部知识库并返回匹配片段","parameters":{"type":"object","properties":{"query":{"type":"string"},"top_k":{"type":"integer"}}}}},{"type":"function","function":{"name":"read_file","description":"读取文件内容","parameters":{"type":"object","properties":{"path":{"type":"string"},"start":{"type":"integer"}}}}},{"type":"function","function":{"name":"run","description":"执行命令","parameters":{"type":"object","properties":{"command":{"type":"string"}}}}}],"messages":["#,
        );
        for i in 0..n_msgs {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&format!(
                r#"{{"role":"{}","content":"[{i}] {}"}}"#,
                if i % 2 == 0 { "user" } else { "assistant" },
                FRAGMENTS[i % FRAGMENTS.len()]
            ));
        }
        s.push_str("]}");
        s.into_bytes()
    }

    /// 不可压的伪随机字节，专用于「压缩绝不能使体积变大」。
    fn random_body(n: usize) -> Vec<u8> {
        let mut x = 0xDEAD_BEEF_1234_5678u64;
        (0..n)
            .map(|_| {
                x = x
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (x >> 33) as u8
            })
            .collect()
    }

    // ---- 内存：这是 M0 验收「压缩相关内存 <1MB」的落点 ----

    /// 必须先压缩再测：上下文内存在**首次压缩之后**才长到稳态，建池那一刻的值偏低
    /// （实测低估 2.1 倍：232 KB → 497 KB）。门禁必须断言稳态值。
    ///
    /// 还要让**每个槽位都热起来**：`try_compress` 总是挑第一个空闲槽位，顺序调用只会
    /// 用到 slot 0。生产里并发流会占满所有槽位，所以这里手动占住 slot 0 去压一次，
    /// 让 slot 1 也到稳态——那才是真实的最坏情况。
    #[test]
    fn steady_state_context_memory_is_under_one_megabyte() {
        let p = pool();
        let cold = p.context_bytes();

        for n in [1usize, 64, 400] {
            let src = structured_body(n);
            if let Some(c) = p.try_compress(&src) {
                let _ = p.decompress(&c, 1 << 22).unwrap();
            }
        }
        // 占住 slot 0，强迫下一次压缩落到 slot 1 上，使两个槽位都长到稳态
        {
            let mut inner = p.inner.lock().unwrap();
            inner.slots[0].busy = true;
        }
        let _ = p.try_compress(&structured_body(400));
        {
            let mut inner = p.inner.lock().unwrap();
            inner.slots[0].busy = false;
            for (i, s) in inner.slots.iter().enumerate() {
                println!("  [压缩内存] slot{i} 峰值 {} B", s.peak_bytes);
            }
        }

        let warm = p.context_bytes();
        println!(
            "  [压缩内存] 建池时 {cold} B → **全槽位稳态 {warm} B**（{} 个 CCtx + 1 个 DCtx）",
            p.capacity()
        );
        assert!(warm >= cold, "稳态内存不应低于建池时（否则测量口径反了）");
        assert!(
            warm < 1 << 20,
            "压缩相关内存必须 <1MiB（设计 §12），实际稳态 {warm} B"
        );
    }

    /// **解压上限的边界 + 对照**（第 75 轮补）。
    ///
    /// 为什么补：`MAX_DECOMPRESS_BYTES` 原先只出现在**定义**与那行 clamp
    /// （`let limit = limit.min(MAX_DECOMPRESS_BYTES)`）里，**没有任何测试碰它** ✗——
    /// 死常量门禁能保证"有人引用"，但引用不等于**边界有人验**（`limits.rs` 自己写下的标准）。
    /// 它头部那句"14 个常量里只有 `MAX_TOKENSTREAM_BYTES` 缺边界"因此**不成立**，本测试补上这条。
    ///
    /// 判据两侧都要有（只测"超大被拒"不够，`limits.rs` 的范式）：
    /// * **边界**：一份"声明输出 32 MiB"的合法 zstd 载荷（压得很小，典型 zip-bomb 形状），
    ///   即便调用方传 `usize::MAX`，也必须被 clamp 拦住并报 `TooLarge` ⇒ 护住的是**内存**；
    /// * **对照**：同一路径在界内正常解出 ⇒ 证明拦截的原因是**上限**，而不是解压路径本身坏了。
    #[test]
    fn decompress_limit_is_clamped_and_still_allows_legal_input() {
        let d = Dicts::bootstrap();
        let p = CompressPool::new(d.patch, 1).unwrap();

        // 32 MiB 全零：zstd 会压到几 KB ⇒ 正是"压缩后很小、解压后很大"的典型形状
        let big = vec![0u8; 32 << 20];
        let c = p.try_compress(&big).expect("32 MiB 全零应当压得动");
        println!(
            "  [解压上限] 32 MiB 原始 → 压缩后 {} B（炸弹输入的典型形状）",
            c.len()
        );
        assert!(
            c.len() < (1 << 20),
            "对照组前提不成立：压缩后竟有 {} B，这条测试就没在测'小输入大输出'",
            c.len()
        );

        // 边界：调用方声称"可以给我 32 MiB"，clamp 必须把它压回 16 MiB 再拒
        match p.decompress(&c, usize::MAX) {
            Err(CompressError::TooLarge { declared, limit }) => {
                println!("  [解压上限] 被拦：declared={declared} limit={limit}");
                assert_eq!(limit, MAX_DECOMPRESS_BYTES, "clamp 用的必须是那个常量");
                assert!(
                    declared > limit,
                    "报的 declared({declared}) 应当确实超过 limit({limit})"
                );
            }
            other => panic!("32 MiB 的解压结果必须被上限拦住，实际 {other:?}"),
        }

        // 对照：同一路径在界内正常解出
        let small = vec![0u8; 64 << 10];
        let cs = p.try_compress(&small).expect("64 KiB 全零应当压得动");
        let got = p.decompress(&cs, usize::MAX).expect("界内载荷必须照常解出");
        assert_eq!(got, small, "界内载荷必须逐字节还原");
    }

    /// 冷态下容量翻倍应使内存增加——确认「内存上限由 `COMPRESS_CTX_POOL` 决定」。
    #[test]
    fn cold_context_memory_grows_with_pool_capacity() {
        let d = Dicts::bootstrap();
        let one = CompressPool::new(d.patch, 1).unwrap();
        let four = CompressPool::new(d.patch, 4).unwrap();
        println!(
            "  [压缩内存] 冷态：1 个 CCtx + DCtx {} B，4 个 {} B",
            one.context_bytes(),
            four.context_bytes()
        );
        assert!(
            four.context_bytes() > one.context_bytes(),
            "4 个上下文的冷态内存必须多于 1 个"
        );
    }

    // ---- 往返 ----

    #[test]
    fn roundtrip_is_byte_exact() {
        let p = pool();
        for n in [1usize, 8, 64, 400] {
            let src = structured_body(n);
            let c = p.try_compress(&src).expect("这么大的 JSON 应当压得动");
            assert!(c.len() < src.len());
            let back = p.decompress(&c, src.len() + 16).expect("解压失败");
            assert_eq!(back, src, "n={n} 往返必须逐字节一致");
        }
    }

    #[test]
    fn compressed_form_carries_content_size() {
        let p = pool();
        let src = structured_body(20);
        let c = p.try_compress(&src).unwrap();
        let declared = zstd::zstd_safe::get_frame_content_size(&c).unwrap();
        assert_eq!(
            declared,
            Some(src.len() as u64),
            "帧头必须写明原始长度，解压端才能精确分配并检测截断"
        );
    }

    /// 证明**字典真的被用上了**。这里刻意**不断言"有字典一定更小"**——
    /// 实测数据不支持这个性质。
    ///
    /// 实测（结构化且高度重复的 body，43,754 B）：
    ///
    /// | 配置 | 压缩后 |
    /// |---|---|
    /// | `dict_patch` | 2,362 B |
    /// | `dict_sse` | 2,150 B |
    /// | **无字典** | **1,781 B** |
    ///
    /// 字典在这个负载上是**负收益**。这与 Python 门禁的结论一致：
    /// `full_body.gain = 0.9989`（基本中性），因为 `dict_patch` 是在 **patch** 样本上
    /// 训练的，不是完整 body；而在高度重复的内容上，字典预置的熵表反而不如自适应表。
    ///
    /// 所以本测试只断言两件**确实成立**的事：
    /// 1. 不同字典产出不同 → 若误用 `CCtx::compress`（忽略上下文参数），字典会被完全
    ///    忽略、两次产出必然一致，这条就会失败；
    /// 2. 有没有字典都能逐字节往返。
    ///
    /// 跨字典解压**必须失败**（见 `wrong_dictionary_fails_loudly`），那是"帧真的绑定了
    /// 字典"的最强证据。
    #[test]
    fn dictionary_is_actually_applied() {
        let d = Dicts::bootstrap();
        let src = structured_body(400);

        // 空字典 = 合法的「无字典」基线（zstd 用它表示清除字典）
        let no_dict = CompressPool::new(&[], 1).unwrap();
        let with_patch = CompressPool::new(d.patch, 1).unwrap();
        let with_sse = CompressPool::new(d.sse, 1).unwrap();

        let a = with_patch.try_compress(&src).expect("有字典应压得动");
        let b = with_sse.try_compress(&src).expect("另一本字典也能压");
        let n = no_dict.try_compress(&src).expect("无字典也能压");

        println!(
            "  [字典应用] 原文 {} B ｜ dict_patch {} B ｜ dict_sse {} B ｜ 无字典 {} B（字典在此负载上非正收益，与门禁一致）",
            src.len(),
            a.len(),
            b.len(),
            n.len()
        );

        assert_ne!(
            a, b,
            "两本不同字典产出必须不同；若相同说明字典根本没被使用（误用了 CCtx::compress）"
        );
        assert_eq!(with_patch.decompress(&a, 1 << 22).unwrap(), src);
        assert_eq!(with_sse.decompress(&b, 1 << 22).unwrap(), src);
        assert_eq!(no_dict.decompress(&n, 1 << 22).unwrap(), src);
    }

    // ---- 「压缩绝不能使体积变大」 ----

    #[test]
    fn incompressible_input_is_never_expanded() {
        let p = pool();
        let src = random_body(4096);
        assert!(
            p.try_compress(&src).is_none(),
            "压不小就必须返回 None，由调用方原样发送"
        );
        assert_eq!(p.stats().skipped_incompressible, 1);
    }

    #[test]
    fn short_payload_is_skipped() {
        let p = pool();
        let src = vec![b'a'; MIN_COMPRESS_BYTES - 1];
        assert!(p.try_compress(&src).is_none());
        let s = p.stats();
        assert_eq!(s.skipped_small, 1);
        assert_eq!(s.attempted, 1);
        assert_eq!(s.wire_bytes, src.len() as u64);
    }

    /// 池忙时必须**放弃压缩**而不是等待——等待会拖慢整条链路，而原样发送永远正确。
    #[test]
    fn busy_pool_degrades_instead_of_blocking() {
        let d = Dicts::bootstrap();
        let p = CompressPool::new(d.patch, 1).unwrap();
        {
            let mut inner = p.inner.lock().unwrap();
            inner.slots[0].busy = true;
        }
        assert_eq!(p.available(), 0);
        assert!(
            p.try_compress(&structured_body(10)).is_none(),
            "池忙应返回 None（发原文），而不是阻塞或报错"
        );
        assert_eq!(p.stats().skipped_busy, 1);
    }

    // ---- 解压的失败方式必须明确 ----

    #[test]
    fn corrupt_input_is_rejected_not_partially_returned() {
        let p = pool();
        let src = structured_body(10);
        let mut c = p.try_compress(&src).unwrap();
        let n = c.len();
        c[n / 2] ^= 0xFF;
        assert!(
            p.decompress(&c, 1 << 20).is_err(),
            "损坏的输入必须报错，绝不能返回半个 body"
        );
    }

    #[test]
    fn truncated_input_is_rejected() {
        let p = pool();
        let src = structured_body(10);
        let c = p.try_compress(&src).unwrap();
        for cut in 1..c.len().min(40) {
            assert!(
                p.decompress(&c[..cut], 1 << 20).is_err(),
                "截断到 {cut} 字节应报错"
            );
        }
    }

    #[test]
    fn decompress_respects_the_limit() {
        let p = pool();
        let src = structured_body(10);
        let c = p.try_compress(&src).unwrap();
        match p.decompress(&c, 64) {
            Err(CompressError::TooLarge { declared, limit }) => {
                assert_eq!(declared, src.len());
                assert_eq!(limit, 64);
            }
            other => panic!("应报 TooLarge，实际 {other:?}"),
        }
    }

    /// **字典不匹配必须报错**。字典是格式化字典、帧里带 dictID，zstd 会校验，
    /// 所以拿另一个字典解压会明确失败，而不是解出一段垃圾。
    #[test]
    fn wrong_dictionary_fails_loudly() {
        let d = Dicts::bootstrap();
        let c = CompressPool::new(d.patch, 1).unwrap();
        let compressed = c.try_compress(&structured_body(30)).unwrap();
        let other = CompressPool::new(d.ctrl, 1).unwrap();
        assert!(
            other.decompress(&compressed, 1 << 20).is_err(),
            "用错字典必须报错；解出垃圾才是灾难（设计 §3.2）"
        );
    }

    #[test]
    fn oversized_dictionary_is_refused_up_front() {
        let huge = vec![0u8; (1 << WINDOW_LOG) + 1];
        match CompressPool::new(&huge, 1) {
            Err(CompressError::DictionaryTooLarge {
                dict_bytes,
                window_bytes,
            }) => {
                assert_eq!(window_bytes, 1 << WINDOW_LOG);
                assert!(dict_bytes > window_bytes);
            }
            other => panic!("应报 DictionaryTooLarge，实际 {other:?}"),
        }
    }

    #[test]
    fn real_dictionaries_all_fit_and_work() {
        let d = Dicts::bootstrap();
        for (name, dict) in [
            ("dict_patch", d.patch),
            ("dict_ctrl", d.ctrl),
            ("dict_sse", d.sse),
        ] {
            let p = CompressPool::new(dict, 1).unwrap_or_else(|e| panic!("{name} 建池失败：{e}"));
            let src = structured_body(20);
            if let Some(c) = p.try_compress(&src) {
                assert_eq!(p.decompress(&c, 1 << 20).unwrap(), src, "{name} 往返不一致");
            }
            assert!(p.context_bytes() < 1 << 20, "{name} 上下文内存超限");
        }
    }

    /// 统计口径必须自洽：`wire_bytes` 必须等于实际该发的字节数。
    #[test]
    fn stats_account_for_every_attempt() {
        let p = pool();
        let compressible = structured_body(30);
        let c = p.try_compress(&compressible).expect("应压得动");
        let short = vec![b'x'; 10];
        assert!(p.try_compress(&short).is_none());

        let s = p.stats();
        assert_eq!(s.attempted, 2);
        assert_eq!(s.used, 1);
        assert_eq!(s.skipped_small, 1);
        assert_eq!(
            s.wire_bytes,
            c.len() as u64 + short.len() as u64,
            "实发字节应为压缩后长度 + 原样长度"
        );
        assert_eq!(
            s.original_bytes,
            compressible.len() as u64 + short.len() as u64
        );
        println!(
            "  [压缩效果] 原文 {} B → {} B = {:.2}%",
            compressible.len(),
            c.len(),
            c.len() as f64 / compressible.len() as f64 * 100.0
        );
        assert!(s.ratio() < 0.5, "这份 JSON 应压到一半以下");
    }
}
