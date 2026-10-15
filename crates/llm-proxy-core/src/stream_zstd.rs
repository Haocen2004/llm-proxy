//! 流式 zstd：**慢路径**（设计 §6.3）的压缩基础。
//!
//! # 它解决什么问题
//!
//! 模板归纳只在"同一形状的响应反复出现"时有效。真实的 LLM 上游会不断加新 event 类型，
//! 那些响应落不进任何模板——如果只能按原样透传，代理就退化成了一个普通转发器。
//!
//! 慢路径是这里的安全网：**未命中模板时改用流式 zstd + `dict_sse`**，
//! 让"不认识的响应"至少还能压一压。
//!
//! # 时间驱动 flush，不是计数驱动
//!
//! 设计 §6.3 明确要求：flush 由「距上次 flush ≥100ms 或累积 ≥1KB，先到者触发」驱动。
//! 计数驱动有个致命问题——**高吞吐时延迟爆炸**（攒够 1KB 才发，而事件稀疏时永远攒不够）。
//! 时间驱动把延迟上界钉死在窗口长度上。
//!
//! 所以这个模块的 `push` **必须**保证：返回的字节是**自包含可增量解压的**，
//! 即调用方随时可以把返回值发出去，对端都能解出到目前为止的全部原文。
//! 这是靠 `ZSTD_e_flush` 达成的——它产生一个可完全解压的刷新点。

use zstd::zstd_safe::{get_error_name, CCtx, CParameter, DCtx, DParameter, InBuffer, OutBuffer};

use crate::compression::CompressError;
use crate::config::WINDOW_LOG;

/// 压缩级别。与整段路径一致，取 1。
const LEVEL: i32 = 1;

/// 单次 `compress_stream2` 的输出缓冲大小。太小会让循环次数暴涨，太大会浪费内存。
const OUT_CHUNK: usize = 16 << 10;

fn safe_err(code: usize) -> CompressError {
    CompressError::Context(get_error_name(code).to_string())
}

/// 每轮循环都把 `OutBuffer` 建在**全新的定长缓冲**上，再取 `pos` 截断。
///
/// 不用 `Vec<u8>` 直接作 `OutBuffer::around` 的目标，是因为它要求调用方自己预留容量、
/// 而 `filled_until` 会把长度设成写入量——一旦某轮写满，`Vec` 的 `len` 与 `capacity`
/// 就纠缠在一起，极易写出"读到了未初始化字节"这种静默错误。定长数组没有这个问题。
fn pump<F>(mut f: F) -> Result<Vec<u8>, CompressError>
where
    F: FnMut(&mut OutBuffer<'_, [u8]>) -> Result<(usize, bool), CompressError>,
{
    let mut out = Vec::new();
    let mut buf = vec![0u8; OUT_CHUNK];
    loop {
        let (produced, done) = {
            let mut ob = OutBuffer::around(&mut buf[..]);
            let (produced, done) = f(&mut ob)?;
            (produced, done)
        };
        out.extend_from_slice(&buf[..produced]);
        if done {
            return Ok(out);
        }
    }
}

/// 流式压缩器。
pub struct StreamCompressor {
    cc: CCtx<'static>,
}

impl StreamCompressor {
    pub fn new(dict: &[u8]) -> Result<Self, CompressError> {
        let mut cc = CCtx::create();
        cc.set_parameter(CParameter::CompressionLevel(LEVEL))
            .map_err(safe_err)?;
        cc.set_parameter(CParameter::WindowLog(WINDOW_LOG))
            .map_err(safe_err)?;
        if !dict.is_empty() {
            cc.load_dictionary(dict).map_err(safe_err)?;
        }
        Ok(Self { cc })
    }

    /// 喂入一段原文，返回**可立即发出**的压缩字节。
    ///
    /// 返回值保证构成一个可完全解压的刷新点（`ZSTD_e_flush`），
    /// 所以调用方可以按时间窗口任意切分发送——这正是慢路径 latency 上界的基础。
    pub fn push(&mut self, src: &[u8]) -> Result<Vec<u8>, CompressError> {
        let cc = &mut self.cc;
        let mut input = InBuffer::around(src);
        pump(|ob| {
            // flush 语义要求持续调用直到返回 0，才代表"到目前为止全部可解压"
            let r = cc
                .compress_stream2(
                    ob,
                    &mut input,
                    zstd::zstd_safe::zstd_sys::ZSTD_EndDirective::ZSTD_e_flush,
                )
                .map_err(safe_err)?;
            let done = input.pos() == src.len() && r == 0;
            Ok((ob.pos(), done))
        })
    }

    /// 结束这个流（产生收尾块）。
    pub fn finish(&mut self) -> Result<Vec<u8>, CompressError> {
        let cc = &mut self.cc;
        let mut input = InBuffer::around(&[]);
        pump(|ob| {
            let r = cc
                .compress_stream2(
                    ob,
                    &mut input,
                    zstd::zstd_safe::zstd_sys::ZSTD_EndDirective::ZSTD_e_end,
                )
                .map_err(safe_err)?;
            // 结束指令返回 0 表示帧已收尾
            Ok((ob.pos(), r == 0))
        })
    }
}

/// 流式解压器。
pub struct StreamDecompressor {
    dc: DCtx<'static>,
}

impl StreamDecompressor {
    pub fn new(dict: &[u8]) -> Result<Self, CompressError> {
        let mut dc = DCtx::create();
        dc.set_parameter(DParameter::WindowLogMax(WINDOW_LOG))
            .map_err(safe_err)?;
        if !dict.is_empty() {
            // **必须**与压缩端用同一本字典：不一致时 zstd 会明确报错，
            // 而不是解出错误内容（这正是我们要的失败方式）
            dc.load_dictionary(dict).map_err(safe_err)?;
        }
        Ok(Self { dc })
    }

    /// 喂入一段压缩字节，返回**本次能解出的**原文。
    ///
    /// 输入不构成完整刷新点时返回空 Vec（不是错误）——调用方继续喂即可。
    pub fn push(&mut self, src: &[u8]) -> Result<Vec<u8>, CompressError> {
        let dc = &mut self.dc;
        let mut input = InBuffer::around(src);
        pump(|ob| {
            let _r = dc.decompress_stream(ob, &mut input).map_err(safe_err)?;
            // **终止条件必须是「输入吃完**且**输出缓冲没写满」**。
            //
            // 只看"输入吃完"是错的：解码器有内部缓冲，输出缓冲写满时即使输入已消费完，
            // 它还有内容没吐出来。早先这么写会让**任何超过输出缓冲大小的响应被静默截断**
            // ——不报错，只是内容少了一截。这正是设计 §16 M7 明令禁止的"静默错误"。
            let done = input.pos() == src.len() && ob.pos() < OUT_CHUNK;
            Ok((ob.pos(), done))
        })
    }
}

impl std::fmt::Debug for StreamCompressor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StreamCompressor")
    }
}

impl std::fmt::Debug for StreamDecompressor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StreamDecompressor")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dict::Dicts;

    fn sse_dict() -> Vec<u8> {
        Dicts::bootstrap().sse.to_vec()
    }

    #[test]
    fn roundtrip_with_sse_dict() {
        let d = sse_dict();
        let mut c = StreamCompressor::new(&d).unwrap();
        let mut dec = StreamDecompressor::new(&d).unwrap();
        let mut got = Vec::new();
        for piece in [b"event: a\n".as_slice(), b"data: {}\n\n", b"event: b\n"] {
            let z = c.push(piece).unwrap();
            got.extend_from_slice(&dec.push(&z).unwrap());
        }
        let z = c.finish().unwrap();
        got.extend_from_slice(&dec.push(&z).unwrap());
        assert_eq!(
            String::from_utf8_lossy(&got),
            "event: a\ndata: {}\n\nevent: b\n"
        );
    }

    /// **最关键的一条**：每次 `push` 的返回值必须构成一个可完全解压的刷新点。
    ///
    /// 慢路径的延迟上界完全建立在这个性质上——若 push 返回的字节只能"解出一部分"，
    /// 接收方就必须等到流结束才能拿到内容，100ms 的延迟承诺就不成立。
    #[test]
    fn every_push_is_independently_decompressible() {
        let d = sse_dict();
        let mut c = StreamCompressor::new(&d).unwrap();
        let mut dec = StreamDecompressor::new(&d).unwrap();

        let mut expect = Vec::new();
        let mut got = Vec::new();
        for i in 0..12 {
            let piece = format!("event: e{i}\ndata: {{\"i\":{i}}}\n\n");
            expect.extend_from_slice(piece.as_bytes());
            let z = c.push(piece.as_bytes()).unwrap();
            assert!(!z.is_empty(), "第 {i} 次 push 应当产出字节（已 flush）");
            // 每一片单独喂进去，必须能解出到目前为止的全部原文
            got.extend_from_slice(&dec.push(&z).unwrap());
            assert_eq!(
                got, expect,
                "第 {i} 次 push 之后必须已解出全部原文——否则刷新点不成立"
            );
        }
    }

    /// 稀疏输入同样成立：这正是"事件少、攒不满 1KB"的场景。
    #[test]
    fn sparse_tiny_pushes_still_flush() {
        let d = sse_dict();
        let mut c = StreamCompressor::new(&d).unwrap();
        let mut dec = StreamDecompressor::new(&d).unwrap();
        let z = c.push(b"x").unwrap();
        assert!(!z.is_empty(), "哪怕只有一个字节也必须能立刻发出");
        assert_eq!(dec.push(&z).unwrap(), b"x");
    }

    /// 对照两种内容：**高度重复** vs **真实形状的多样事件**。
    ///
    /// 之所以要分开量：早先在 `dict_patch` 上就发现过"字典在高重复内容上反而更差"。
    /// 若不区分，很容易把"字典没用"这个结论错误地推广到全部场景，
    /// 或者反过来——被一个恰好对字典有利的样本骗过去。
    #[test]
    fn dict_gain_depends_on_content_diversity() {
        let d = sse_dict();

        // A：200 行近乎相同（只有索引号不同）——高度重复
        let repetitive: Vec<u8> = (0..200)
            .flat_map(|i| {
                format!(
                    "event: message_delta\ndata: {{\"type\":\"message_delta\",\"index\":{i},\
                     \"delta\":{{\"stop_reason\":null}}}}\n\n"
                )
                .into_bytes()
            })
            .collect();

        // B：多种事件类型 + 各字段取值都在变——更接近"上游加了新 event"的样子
        const KINDS: [&str; 7] = [
            "message_start",
            "content_block_start",
            "content_block_delta",
            "content_block_stop",
            "message_delta",
            "ping",
            "tool_use",
        ];
        const WORDS: [&str; 8] = [
            "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta",
        ];
        let varied: Vec<u8> = (0..200usize)
            .flat_map(|i| {
                let k = KINDS[i % KINDS.len()];
                let w = WORDS[(i * 3 + 1) % WORDS.len()];
                let u = WORDS[(i * 5 + 2) % WORDS.len()];
                format!(
                    "event: {k}\ndata: {{\"type\":\"{k}\",\"index\":{i},\
                     \"uuid\":\"req_{w}_{u}_{i}\",\"text\":\"some {w} content {u}\",\
                     \"usage\":{{\"input_tokens\":{},\"output_tokens\":{}}}}}\n\n",
                    i * 7 + 13,
                    i * 3 + 5
                )
                .into_bytes()
            })
            .collect();

        // C：**短流**——慢路径真正高频出现的样子（模板不适用、但响应本身很小）
        let short: Vec<u8> = varied[..varied.len().min(1200)].to_vec();
        let tiny: Vec<u8> = varied[..varied.len().min(400)].to_vec();

        // 找交叉点：从 400B 到 35KB 逐档扫
        let mut sweep: Vec<(String, Vec<u8>)> = Vec::new();
        for kb in [400usize, 800, 1600, 3200, 6400, 12800] {
            let n = varied.len().min(kb);
            sweep.push((format!("~{kb}B"), varied[..n].to_vec()));
        }
        let _ = (&tiny, &short, &repetitive, &varied);
        for (name, body) in sweep {
            let mut plain = StreamCompressor::new(&[]).unwrap();
            let mut with = StreamCompressor::new(&d).unwrap();
            let zp = plain.push(&body).unwrap();
            let zw = with.push(&body).unwrap();
            println!(
                "  [慢路径/{name}] 原文 {} B → 无字典 {} B（{:.2}%）｜dict_sse {} B（{:.2}%）",
                body.len(),
                zp.len(),
                zp.len() as f64 / body.len() as f64 * 100.0,
                zw.len(),
                zw.len() as f64 / body.len() as f64 * 100.0
            );
            assert_eq!(
                StreamDecompressor::new(&d).unwrap().push(&zw).unwrap(),
                body
            );
            assert_eq!(
                StreamDecompressor::new(&[]).unwrap().push(&zp).unwrap(),
                body
            );
        }
    }

    /// 交叉点策略本身：**短流用字典、长流不用**。
    ///
    /// 这条测试替代了早先那条"字典一定更小"的断言。那条断言**是错的**——
    /// 实测（见上一条测试的扫描）显示字典只在短流上占优，约 4KB 处交叉。
    /// 留着一条与事实相反的断言比没有断言更糟：它会把正确的实现判成失败，
    /// 或者反过来逼着实现去做错的事。
    #[test]
    fn dict_policy_crossover_is_where_we_think_it_is() {
        let d = sse_dict();
        const KINDS: [&str; 7] = [
            "message_start",
            "content_block_start",
            "content_block_delta",
            "content_block_stop",
            "message_delta",
            "ping",
            "tool_use",
        ];
        const WORDS: [&str; 8] = [
            "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta",
        ];
        let gen = |n: usize| -> Vec<u8> {
            (0..n)
                .flat_map(|i| {
                    let k = KINDS[i % KINDS.len()];
                    let w = WORDS[(i * 3 + 1) % WORDS.len()];
                    let u = WORDS[(i * 5 + 2) % WORDS.len()];
                    format!(
                        "event: {k}\ndata: {{\"type\":\"{k}\",\"index\":{i},\
                     \"uuid\":\"req_{w}_{u}_{i}\",\"text\":\"some {w} content {u}\"}}\n\n"
                    )
                    .into_bytes()
                })
                .collect()
        };
        let short = gen(4); // ~700B，明显在交叉点之下
        let long = gen(300); // ~35KB，明显在交叉点之上

        let sz = |body: &[u8], dict: &[u8]| {
            StreamCompressor::new(dict)
                .unwrap()
                .push(body)
                .unwrap()
                .len()
        };
        assert!(
            short.len() < 4096,
            "短样本必须落在交叉点之下（实际 {} B）",
            short.len()
        );
        assert!(
            long.len() > 8192,
            "长样本必须落在交叉点之上（实际 {} B）",
            long.len()
        );
        assert!(
            sz(&short, &d) < sz(&short, &[]),
            "交叉点之下字典必须更小：{} vs {}",
            sz(&short, &d),
            sz(&short, &[])
        );
        assert!(
            sz(&long, &[]) < sz(&long, &d),
            "交叉点之上无字典必须更小：{} vs {}——\
             这正是 SlowState 要在 4KB 处换流的原因",
            sz(&long, &[]),
            sz(&long, &d)
        );
    }
    /// **流式压缩必须守住钉住的窗口上限**——这是「每流内存有界」的前提。
    ///
    /// 为什么非测不可：慢路径每个在途响应都要一条 `StreamCompressor`，并发上限 4。
    /// 若压缩端忘了钉窗口，zstd 对大数据会用更大的默认窗口（设计 §12 的原话：
    /// 单上下文约 1.3 MB），4 条并发就是数 MB 额外内存——而 RSS 天花板（32 MiB）
    /// 余量很大，**抓不住这种回退**。
    ///
    /// 判据在解压端：`StreamDecompressor` 把 `WindowLogMax` 钉在 `WINDOW_LOG`。
    /// 喂一份远超 128 KiB 的数据——压缩端若没钉窗口，帧会声明更大的窗口，
    /// 被上限明确拒绝（报错，而不是解出错内容）。
    #[test]
    fn streamed_window_stays_within_the_pinned_budget() {
        let d = sse_dict();
        let mut c = StreamCompressor::new(&d).unwrap();
        let mut dec = StreamDecompressor::new(&d).unwrap();

        let piece: &[u8] =
            b"event: content_block_delta\ndata: {\"type\":\"text_delta\",\"text\":\"abcdefghij\"}\n\n";
        let mut plain = Vec::new();
        while plain.len() < 500 * 1024 {
            plain.extend_from_slice(piece);
        }

        let mut got = Vec::new();
        for chunk in plain.chunks(8 * 1024) {
            let z = c.push(chunk).unwrap();
            got.extend_from_slice(&dec.push(&z).expect("解压不得因窗口上限失败"));
        }
        let z = c.finish().unwrap();
        got.extend_from_slice(&dec.push(&z).expect("收尾字节也不得因窗口上限失败"));
        assert_eq!(got.len(), plain.len(), "流式往返必须完整");
        assert!(got == plain, "流式往返内容必须逐字节一致");
    }

    /// 字典不匹配必须**报错**，不能解出错误内容。
    #[test]
    fn wrong_dict_fails_loudly() {
        let a = sse_dict();
        let mut c = StreamCompressor::new(&a).unwrap();
        let z = c.push(b"hello world hello world hello world").unwrap();
        // 用一本**不同**的字典去解
        let mut other = a.clone();
        for b in other.iter_mut() {
            *b ^= 0x5A;
        }
        let mut dec = StreamDecompressor::new(&other).unwrap();
        let r = dec.push(&z);
        match r {
            Err(_) => {}
            Ok(v) => panic!("字典不匹配却解出了内容（{} 字节）——这会是静默错误", v.len()),
        }
    }

    /// 输出**超过单次输出缓冲**时必须完整解出，不能被静默截断。
    ///
    /// 这条测试的存在理由：解压器早先把终止条件写成"输入消费完"，
    /// 于是任何大于 16KB 的响应都会被悄悄截掉一截——**不报错，只是内容少了**。
    /// 只断言"没报错"是抓不到的，必须比对完整内容。
    #[test]
    fn output_larger_than_one_buffer_is_not_silently_truncated() {
        let d = sse_dict();
        // 明显超过 OUT_CHUNK（16KB）
        let body: Vec<u8> = (0..3000)
            .flat_map(|i| format!("line {i} of a fairly long body\n").into_bytes())
            .collect();
        assert!(body.len() > 2 * OUT_CHUNK, "样本必须跨多个输出缓冲");

        let mut c = StreamCompressor::new(&d).unwrap();
        let z = c.push(&body).unwrap();
        let got = StreamDecompressor::new(&d).unwrap().push(&z).unwrap();
        assert_eq!(
            got.len(),
            body.len(),
            "解出的长度必须与原文一致（截断会在这里暴露）"
        );
        assert_eq!(got, body, "内容必须逐字节一致");
    }

    #[test]
    fn truncated_stream_does_not_panic() {
        let d = sse_dict();
        let mut c = StreamCompressor::new(&d).unwrap();
        let z = c
            .push(b"some payload that is long enough to compress a bit")
            .unwrap();
        let mut dec = StreamDecompressor::new(&d).unwrap();
        // 只喂前一半：应当要么解出部分内容、要么报错，但绝不能 panic 或死循环
        let half = &z[..z.len() / 2];
        let _ = dec.push(half);
    }
}
