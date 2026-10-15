//! TokenStream：把请求体编码成 `LITERAL` 与 `REF` 交替的字节流。
//!
//! 设计 §5.3：`REF` 就是「用缓存内容标记」的落点——**协议层完全不理解 body 语义**，
//! 只做「整块引用替换」，因此对任意格式（JSON、multipart、base64 图像、未来格式）
//! 都成立。
//!
//! 相对设计文档的两处实现简化：
//!
//! 1. 设计里的 `REF` 带 `offset` 与 `len`（可引用任意字节区间）。本实现以 **CDC 块**
//!    为引用单位，因此 `REF` 只需块指纹——长度由块本身决定。
//! 2. 设计里的流以 `varint(count)` 开头。计数前缀要求先知道总块数，与流式编码冲突。
//!    本实现去掉计数：TokenStream 串在 `BodyChunk` 帧的载荷里，由帧的 `LAST` 标志
//!    界定结束，顺序解码至耗尽即可。
//!
//! 编码：
//! ```text
//! TokenStream := Token*
//! Token       := 0x00 varint(len) LITERAL_BYTES
//!              | 0x01 FP(24B)
//! ```

use std::collections::HashSet;

use crate::cdc;
use crate::fingerprint::{block_fp, Fp, Namespace, FP_LEN, NS_LEN};

pub const TAG_LITERAL: u8 = 0x00;
pub const TAG_REF: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("TokenStream 在偏移 {at} 处截断")]
    Truncated { at: usize },
    #[error("偏移 {at} 处出现未知标签 0x{tag:02x}")]
    BadTag { at: usize, tag: u8 },
    #[error("变长整数溢出（偏移 {at}）")]
    VarintOverflow { at: usize },
    #[error("引用块长度非法：声明 {len}")]
    BadRefLen { len: u64 },
}

/// 重组失败的**两种不同原因**，必须分开。
///
/// 曾经把两者都压成 `Vec<Fp>`：解析失败时那个列表**是空的**，于是上层报出
/// 「缺少 0 个块」+ 提示 `SEND_MISSING`——一条自相矛盾的错误，而且把
/// 「客户端发来的编码坏了」记成「缓存缺块」。后果有三层：
///
/// * 日志与指标指向错误方向（运维会去查缓存淘汰，真因是编码）；
/// * 详情「缺少 0 个块」本身就不可读；
/// * 提示误导客户端：它按 `SEND_MISSING` 去「忘掉缺块、只补发」，
///   可 0 块可忘 ⇒ 拿同一份坏字节再发一遍（白付一个 RTT），真因继续被掩盖。
///
/// 所以解析失败归 [`RecomposeError::Malformed`]，由上层映射成
/// `BAD_ENCODING` + `RETRY_WITH_FULL`（设计原则：**明确拒绝而不是猜语义**）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecomposeError {
    /// 解析成功，但有块不在对端缓存里——报告缺哪些，交给上层一次补发。
    #[error("缺少 {} 个块", .0.len())]
    Missing(Vec<Fp>),
    /// TokenStream 本身不合法（未知标签 / 截断）。**与缺块无关**。
    #[error("TokenStream 不合法：{0}")]
    Malformed(TokenError),
}

/// 解码出的单个 token。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Literal(Vec<u8>),
    Ref(Fp),
}

// ---------------------------------------------------------------------------
// 变长整数
// ---------------------------------------------------------------------------

pub fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            return;
        }
    }
}

pub fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, TokenError> {
    let start = *pos;
    let mut v = 0u64;
    let mut shift = 0u32;
    loop {
        if *pos >= buf.len() {
            return Err(TokenError::Truncated { at: start });
        }
        let b = buf[*pos];
        *pos += 1;
        if shift >= 64 {
            return Err(TokenError::VarintOverflow { at: start });
        }
        v |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(v);
        }
        shift += 7;
    }
}

// ---------------------------------------------------------------------------
// 编码
// ---------------------------------------------------------------------------

pub fn write_literal(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(TAG_LITERAL);
    write_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

pub fn write_ref(out: &mut Vec<u8>, fp: &Fp) {
    out.push(TAG_REF);
    out.extend_from_slice(fp.as_bytes());
}

/// 分解结果与统计。统计口径直接用「实发字节 / 原始字节」，即验收指标。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decompose {
    pub stream: Vec<u8>,
    /// 总块数。
    pub blocks: usize,
    /// 命中缓存、以 `REF` 发送的块数。
    pub refs: usize,
    /// 以 `REF` 发送的块所代表的原始字节数（**省下的部分**）。
    pub ref_bytes: usize,
    /// 原始体字节数。
    pub body_bytes: usize,
    /// 本次新引入、需要上传的块指纹（供客户端记账）。顺序与流内出现顺序一致。
    pub new_fps: Vec<Fp>,
}

impl Decompose {
    /// 实发字节占原始字节的比例——M1a 的验收指标。
    pub fn ratio(&self) -> f64 {
        if self.body_bytes == 0 {
            return 0.0;
        }
        self.stream.len() as f64 / self.body_bytes as f64
    }
}

/// 把 body 分解成 TokenStream。`have` 判定某块是否已在对端缓存中。
pub fn decompose(ns: Namespace, body: &[u8], have: impl Fn(&Fp) -> bool) -> Decompose {
    let mut d = Decompose {
        body_bytes: body.len(),
        ..Default::default()
    };
    if body.is_empty() {
        return d;
    }

    // 用 HashSet 去重：同一块在体内重复出现时，只需上传一次。
    let mut seen: HashSet<Fp> = HashSet::new();
    let mut prev = 0usize;
    for end in cdc::chunk_boundaries(body) {
        let blk = &body[prev..end];
        prev = end;
        d.blocks += 1;
        let fp = block_fp(ns, blk);
        if have(&fp) {
            write_ref(&mut d.stream, &fp);
            d.refs += 1;
            d.ref_bytes += blk.len();
        } else {
            write_literal(&mut d.stream, blk);
            if seen.insert(fp) {
                d.new_fps.push(fp);
            }
        }
    }
    d
}

/// 重建结果：完整 body + 流中以 `literal` 出现、需要落库的块。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recompose {
    pub body: Vec<u8>,
    /// 去重后的 `(指纹, 内容)`，顺序与流内首次出现一致。
    pub new_blocks: Vec<(Fp, Vec<u8>)>,
}

/// 重建 body，并**顺手收集** `literal` 块。
///
/// 服务端需要把收到的块落库；在解码时直接拿到它们，可以省掉一次对整段 body 的
/// 重新切分（3 MB body 在 VPS 上重切约数十毫秒，且纯属重复劳动）。
///
/// 缺失的块会**全部收集**后一次性返回，便于一次补发（设计 §9.2：最多 1 个 RTT）。
pub fn recompose_collect<'a>(
    ns: Namespace,
    stream: &[u8],
    lookup: impl Fn(&Fp) -> Option<&'a [u8]>,
) -> Result<Recompose, RecomposeError> {
    let mut body = Vec::with_capacity(stream.len());
    let mut new_blocks: Vec<(Fp, Vec<u8>)> = Vec::new();
    let mut seen_literal: HashSet<Fp> = HashSet::new();
    let mut missing: Vec<Fp> = Vec::new();
    let mut missing_seen: HashSet<Fp> = HashSet::new();
    let mut pos = 0usize;

    let ok = (|| -> Result<(), TokenError> {
        while pos < stream.len() {
            let at = pos;
            let tag = stream[pos];
            pos += 1;
            match tag {
                TAG_LITERAL => {
                    let len = read_varint(stream, &mut pos)? as usize;
                    if pos + len > stream.len() {
                        return Err(TokenError::Truncated { at });
                    }
                    let bytes = &stream[pos..pos + len];
                    pos += len;
                    body.extend_from_slice(bytes);
                    let fp = block_fp(ns, bytes);
                    if seen_literal.insert(fp) {
                        new_blocks.push((fp, bytes.to_vec()));
                    }
                }
                TAG_REF => {
                    if pos + NS_LEN + FP_LEN > stream.len() {
                        return Err(TokenError::Truncated { at });
                    }
                    let fp =
                        Fp::from_slice(&stream[pos..pos + NS_LEN + FP_LEN]).expect("长度已校验");
                    pos += NS_LEN + FP_LEN;
                    match lookup(&fp) {
                        Some(b) => body.extend_from_slice(b),
                        None => {
                            if missing_seen.insert(fp) {
                                missing.push(fp);
                            }
                        }
                    }
                }
                other => return Err(TokenError::BadTag { at, tag: other }),
            }
        }
        Ok(())
    })();

    // **两种失败必须分开报**：解析失败时 `missing` 可能是空的，
    // 用空列表当"缺块"报出去就是那条"缺少 0 个块"的自相矛盾错误。
    if let Err(e) = ok {
        return Err(RecomposeError::Malformed(e));
    }
    if !missing.is_empty() {
        return Err(RecomposeError::Missing(missing));
    }
    Ok(Recompose { body, new_blocks })
}

/// 重建 body。缺失的块会**全部收集**后一次性返回，便于一次补发（设计 §9.2：最多 1 个 RTT）。
pub fn recompose<'a>(
    stream: &[u8],
    lookup: impl Fn(&Fp) -> Option<&'a [u8]>,
) -> Result<Vec<u8>, RecomposeError> {
    let mut out = Vec::with_capacity(stream.len());
    let mut missing: Vec<Fp> = Vec::new();
    let mut missing_seen: HashSet<Fp> = HashSet::new();
    let mut pos = 0usize;

    // 解码错误在此处视为缺失（交由上层降级为全量），不 panic
    let ok = (|| -> Result<(), TokenError> {
        while pos < stream.len() {
            let at = pos;
            let tag = stream[pos];
            pos += 1;
            match tag {
                TAG_LITERAL => {
                    let len = read_varint(stream, &mut pos)? as usize;
                    if pos + len > stream.len() {
                        return Err(TokenError::Truncated { at });
                    }
                    out.extend_from_slice(&stream[pos..pos + len]);
                    pos += len;
                }
                TAG_REF => {
                    if pos + NS_LEN + FP_LEN > stream.len() {
                        return Err(TokenError::Truncated { at });
                    }
                    let fp =
                        Fp::from_slice(&stream[pos..pos + NS_LEN + FP_LEN]).expect("长度已校验");
                    pos += NS_LEN + FP_LEN;
                    match lookup(&fp) {
                        Some(b) => out.extend_from_slice(b),
                        None => {
                            if missing_seen.insert(fp) {
                                missing.push(fp);
                            }
                        }
                    }
                }
                other => {
                    return Err(TokenError::BadTag { at, tag: other });
                }
            }
        }
        Ok(())
    })();

    // **两种失败必须分开报**：解析失败时 `missing` 可能是空的，
    // 用空列表当"缺块"报出去就是那条"缺少 0 个块"的自相矛盾错误。
    if let Err(e) = ok {
        return Err(RecomposeError::Malformed(e));
    }
    if !missing.is_empty() {
        return Err(RecomposeError::Missing(missing));
    }
    Ok(out)
}

/// 解码成 token 列表（调试与测试用；生产走 [`recompose`] 以免二次分配）。
pub fn decode(stream: &[u8]) -> Result<Vec<Token>, TokenError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < stream.len() {
        let at = pos;
        let tag = stream[pos];
        pos += 1;
        match tag {
            TAG_LITERAL => {
                let len = read_varint(stream, &mut pos)? as usize;
                if pos + len > stream.len() {
                    return Err(TokenError::Truncated { at });
                }
                out.push(Token::Literal(stream[pos..pos + len].to_vec()));
                pos += len;
            }
            TAG_REF => {
                if pos + NS_LEN + FP_LEN > stream.len() {
                    return Err(TokenError::Truncated { at });
                }
                out.push(Token::Ref(
                    Fp::from_slice(&stream[pos..pos + NS_LEN + FP_LEN]).expect("长度已校验"),
                ));
                pos += NS_LEN + FP_LEN;
            }
            other => return Err(TokenError::BadTag { at, tag: other }),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns() -> Namespace {
        Namespace::derive(b"psk", "t", "h")
    }

    const TOOLS_JSON: &str = concat!(
        r#"[{"type":"function","function":{"name":"tool_0","description":"查询内部知识库并返回匹配片段，支持分页与过滤参数。","parameters":{"type":"object","properties":{"query":{"type":"string"},"top_k":{"type":"integer"}}}}}"#,
        r#",{"type":"function","function":{"name":"tool_1","description":"读取文件内容并返回指定行范围。","parameters":{"type":"object","properties":{"path":{"type":"string"},"start":{"type":"integer"}}}}}"#,
        r#",{"type":"function","function":{"name":"tool_2","description":"执行命令并回传标准输出。","parameters":{"type":"object","properties":{"command":{"type":"string"}}}}}"#,
        r#",{"type":"function","function":{"name":"tool_3","description":"列出目录结构。","parameters":{"type":"object","properties":{"dir":{"type":"string"}}}}}"#,
        r#",{"type":"function","function":{"name":"tool_4","description":"搜索代码符号。","parameters":{"type":"object","properties":{"symbol":{"type":"string"}}}}}"#,
        r#",{"type":"function","function":{"name":"tool_5","description":"写入文件。","parameters":{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}}}}}]"#
    );

    /// 生成高多样性的中文文本。
    ///
    /// **窗口多样性是决定 CDC 行为的关键量**：滚动哈希在每个位置看到的是最近若干
    /// 字节，只有当「互不相同的窗口数」远大于 `2^掩码位数`（这里 16384）时，切点才会
    /// 落在设计的平均块长附近。
    ///
    /// 用小词表拼句子（例如 20 名词 × 16 连接词）只能给出几千个不同的短窗口，实测
    /// 让平均块长从理想的约 10 KB 涨到 31 KB；而真实自然语言有数万个不同的短窗口。
    /// 这里直接用 CJK 基本区的 3000 字池逐字符采样，逼近真实文本的多样性。
    ///
    /// 强周期内容（例如同一段话反复出现）则更极端——见 `cdc` 模块的专项测试。
    fn varied_cjk(seed: u64, n_chars: usize) -> String {
        const POOL: u32 = 3000;
        let mut x = seed
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(0x5DEE_CE66_D000_0000);
        let mut s = String::with_capacity(n_chars * 3);
        for _ in 0..n_chars {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let c =
                char::from_u32(0x4E00 + ((x >> 33) as u32 % POOL)).expect("CJK 基本区内的合法码位");
            s.push(c);
        }
        s
    }

    /// 单条消息约 1.7 KB——对齐实测语料（3020462 B / 1720 条 ≈ 1756 B/条）。
    fn message(i: usize, role: &str) -> String {
        let body = varied_cjk(i as u64 + 1, 560);
        format!(r#"{{"role":"{role}","content":"[{i}] {body}"}}"#)
    }

    /// 构造请求体，尾部固定字段（`tools`）大小可调——它决定了两种增量策略的胜负。
    fn body_with_tail(n_msgs: usize, tail: &str) -> Vec<u8> {
        let system = varied_cjk(0xABCD, 4000);
        let mut msgs = format!(r#"[{{"role":"system","content":"{system}"}}"#);
        for i in 0..n_msgs {
            let role = if i % 2 == 0 { "user" } else { "assistant" };
            msgs.push(',');
            msgs.push_str(&message(i, role));
        }
        msgs.push(']');
        format!(
            r#"{{"model":"gpt-4o","stream":true,"messages":{msgs},"tools":{tail},"temperature":0.7}}"#
        )
        .into_bytes()
    }

    /// `tools` 放在 `messages` 之后——与真实请求一致，这正是「尾部字段随 messages
    /// 增长而整体错位」的成因。
    fn realistic_body(n_msgs: usize) -> Vec<u8> {
        body_with_tail(n_msgs, TOOLS_JSON)
    }

    /// 纯前缀法的实发字节数：从 body 首字节起的最长公共前缀之后的部分。
    fn prefix_delta_bytes(a: &[u8], b: &[u8]) -> usize {
        let n = a.len().min(b.len());
        let mut p = 0;
        while p < n && a[p] == b[p] {
            p += 1;
        }
        b.len() - p
    }

    /// 模拟「客户端记账 + 服务端块存储」的一对端。
    struct Peer {
        store: std::collections::HashMap<Fp, Vec<u8>>,
        have: HashSet<Fp>,
    }

    impl Peer {
        fn new() -> Self {
            Self {
                store: std::collections::HashMap::new(),
                have: HashSet::new(),
            }
        }

        /// 发一次请求：分解 → 服务端重建校验 → 落库 → 记账。
        fn send(&mut self, body: &[u8]) -> Decompose {
            let d = decompose(ns(), body, |fp| self.have.contains(fp));

            // 服务端侧重建：这是正确性红线，必须逐字节等价
            let got = recompose(&d.stream, |fp| self.store.get(fp).map(|v| v.as_slice()))
                .unwrap_or_else(|m| panic!("全 literal 路径不该缺块，实缺 {m:?}"));
            assert_eq!(got, body, "重组结果必须与原始请求体逐字节一致");

            // 块落库（去重）
            for blk in cdc::chunks(body) {
                let fp = block_fp(ns(), blk);
                self.store.entry(fp).or_insert_with(|| blk.to_vec());
            }
            self.have.extend(d.new_fps.iter().copied());
            d
        }
    }

    /// 冷启动：无任何缓存时全部走 literal，只在编码上有开销。
    #[test]
    fn cold_cache_produces_all_literals_and_recomposes_exactly() {
        let body = realistic_body(1000);
        let d = decompose(ns(), &body, |_| false);
        assert_eq!(d.refs, 0);
        assert_eq!(d.blocks, d.new_fps.len());
        assert!(
            d.ratio() > 1.0 && d.ratio() < 1.02,
            "全 literal 时只有标签与变长整数的编码开销，实际 {:.4}",
            d.ratio()
        );
        assert!(
            d.blocks > 100,
            "约 {} KB 的负载应切出足够多的块（AVG_SIZE=8KB），实际 {}",
            body.len() / 1024,
            d.blocks
        );

        let store: std::collections::HashMap<Fp, Vec<u8>> = std::collections::HashMap::new();
        let got = recompose(&d.stream, |fp| store.get(fp).map(|v| v.as_slice())).unwrap();
        assert_eq!(got, body, "冷启动路径必须逐字节还原");
    }

    /// M1a 核心验收：成熟会话的多轮增量比 ≤ 5%。
    #[test]
    fn multi_turn_delta_converges_under_5_percent() {
        let mut peer = Peer::new();
        // 成熟会话起点：1000 条消息 ≈ 1.6 MB
        let mut n = 1000usize;
        let mut ratios = Vec::new();
        for _ in 0..8 {
            let body = realistic_body(n);
            let d = peer.send(&body);
            ratios.push(d.ratio());
            n += 2; // 每轮追加一问一答
        }

        // 第 1 轮无任何缓存，必然全量——这是设计预期，不是失败。
        assert!(
            ratios[0] > 0.99,
            "首轮应为全量发送（冷启动无缓存），实际 {:.4}",
            ratios[0]
        );
        // 设计标准：**第 5 轮起**上行 ≤ 原始的 5%
        for (i, r) in ratios.iter().enumerate().skip(4) {
            assert!(
                *r <= 0.05,
                "第 {} 轮增量比 {:.4} 超过 5% 上限；各轮 = {:?}",
                i + 1,
                r,
                ratios.iter().map(|x| format!("{x:.4}")).collect::<Vec<_>>()
            );
        }
        // 实测参考：设计 §5.5 的真实语料给出 1.00%（纯前缀），块级应更优
        let last = *ratios.last().unwrap();
        assert!(
            last < 0.03,
            "成熟会话的稳态增量比应远低于 5%，实际 {last:.4}"
        );
        println!(
            "  [M1a 多轮增量比] {:?}  （稳态 body 约 {} KB，块存储 {} 块）",
            ratios.iter().map(|r| format!("{r:.4}")).collect::<Vec<_>>(),
            realistic_body(1014).len() / 1024,
            peer.store.len()
        );
    }

    /// 冷启动会话：块数少、块粒度相对内容增长偏粗，增量比会明显更高。
    /// 这里**只量化不设硬指标**——它是 CDC 粒度的固有代价，必须被记录而不是被忽略。
    #[test]
    fn cold_start_conversation_shows_granularity_overhead() {
        let mut peer = Peer::new();
        let mut n = 4usize;
        let mut ratios = Vec::new();
        for _ in 0..6 {
            let body = realistic_body(n);
            let d = peer.send(&body);
            ratios.push(d.ratio());
            n += 2;
        }
        // 会话还小的时候不可能达标，但必须仍然在下降
        assert!(
            ratios[0] > ratios[ratios.len() - 1],
            "增量比应随会话增长而下降，实际 {:?}",
            ratios
        );
    }

    /// 量化粒度代价：真正有意义的量是「实发 / body」，而不是「实发 / 新增内容」。
    #[test]
    fn granularity_overhead_is_measured_against_body_size() {
        let mut peer = Peer::new();
        let a = realistic_body(1000);
        let b = realistic_body(1002);
        peer.send(&a);
        let d = peer.send(&b);

        let actual_new = b.len() - a.len();
        let sent = d.stream.len();
        let to_body = sent as f64 / b.len() as f64;
        let to_new = sent as f64 / actual_new as f64;

        // 每轮新增（约 3.4 KB）远小于一个块（实测约 12 KB），所以相对新增内容的
        // 倍数会很大；但相对 body 的占比仍然很小——后者才是验收口径。
        assert!(sent >= actual_new, "实发不可能小于真实新增");
        println!(
            "  [粒度代价] body {} KB / 块数 {} / 新增 {} B / 实发 {} B = body 的 {:.4}、新增的 {:.1}×",
            b.len() / 1024,
            d.blocks,
            actual_new,
            sent,
            to_body,
            to_new
        );
        assert!(
            to_body <= 0.05,
            "相对 body 的增量比必须满足 M1a 上限，实际 {to_body:.4}（实发 {sent} / body {} / 新增 {actual_new}，倍数 {to_new:.1}×）",
            b.len()
        );
        assert!(
            to_new <= 15.0,
            "相对新增内容的倍数应受块粒度约束在常数倍内，实际 {to_new:.1}×"
        );
        assert!(d.refs > 0, "成熟会话的下一轮必须能复用已有块");
    }

    /// 修正一条早先的判断：**块级去重并非总优于纯前缀**。
    ///
    /// 设计 §5.5 基于真实语料得出「块级 0.08% vs 纯前缀 1.00%」，那是因为真实请求里
    /// `tools` 有 28,960 B（远大于一个块）：`messages` 一变长它就整体错位，纯前缀法
    /// 只能整段重发，而块级能把这些块全部复用。
    ///
    /// 反过来，当尾部固定内容**小于一个块**时，纯前缀法能在内容真正分叉的位置精确
    /// 切断，而块级必须按块粒度对齐、重发整个跨界块，于是前缀法更省。
    ///
    /// 正确结论因此是：**两种增量都算一遍，发更小的那个**（设计 §5.3 的「编码选择」）。
    /// 本测试把这个权衡量化并固化，避免再被任何单侧结论误导。
    #[test]
    fn prefix_vs_block_delta_is_a_tradeoff_not_a_winner() {
        let small_tail = TOOLS_JSON.to_string(); // ≈1.3 KB，小于一个块
        let big_tail = format!("\"{}\"", varied_cjk(0x77, 15000)); // ≈45 KB，大于一个块

        let mut outcomes = Vec::new();
        for (label, tail) in [("小尾部", small_tail), ("大尾部", big_tail)] {
            let a = body_with_tail(1000, &tail);
            let b = body_with_tail(1002, &tail);
            let prefix_sent = prefix_delta_bytes(&a, &b);

            let mut peer = Peer::new();
            peer.send(&a);
            let block_sent = peer.send(&b).stream.len();

            // 两者都必须满足 M1a 的 5% 上限
            for (name, v) in [("前缀", prefix_sent), ("块级", block_sent)] {
                let r = v as f64 / b.len() as f64;
                assert!(
                    r <= 0.05,
                    "{label}/{name} 增量比 {r:.4} 超过 5%（{v} / {}）",
                    b.len()
                );
            }
            outcomes.push((label, tail.len(), prefix_sent, block_sent));
        }

        let (_, small_len, small_prefix, small_block) = outcomes[0];
        let (_, big_len, big_prefix, big_block) = outcomes[1];
        println!(
            "  [前缀 vs 块级] 小尾部({small_len} B): 前缀 {small_prefix} / 块级 {small_block} ；\
             大尾部({big_len} B): 前缀 {big_prefix} / 块级 {big_block}"
        );
        assert!(big_len > small_len * 5, "两组尾部字段大小应有量级差");

        // 小尾部：前缀更省（能精确切断，块级要重发整个跨界块）
        assert!(
            small_prefix < small_block,
            "尾部小于一个块时纯前缀应更省，实际 前缀 {small_prefix} vs 块级 {small_block}"
        );
        // 大尾部：块级更省（能复用错位但仍完整的尾部块）
        assert!(
            big_block < big_prefix,
            "尾部大于一个块时块级应更省，实际 块级 {big_block} vs 前缀 {big_prefix}"
        );
    }

    #[test]
    fn missing_blocks_are_collected_all_at_once() {
        let body = realistic_body(300);
        let mut refs_only = Vec::new();
        let mut n_blocks = 0;
        for blk in cdc::chunks(&body) {
            write_ref(&mut refs_only, &block_fp(ns(), blk));
            n_blocks += 1;
        }
        let missing = match recompose(&refs_only, |_| None).unwrap_err() {
            RecomposeError::Missing(v) => v,
            other => panic!("引用不存在块应当是 Missing，而不是 {other:?}"),
        };
        assert_eq!(missing.len(), n_blocks, "应一次收集全部缺失块");
        assert!(n_blocks > 10);
    }

    /// 重复发送同一份 body 必须全部命中缓存——幂等性要求，也是块级去重的基本性质。
    #[test]
    fn resending_identical_body_is_all_refs() {
        let mut peer = Peer::new();
        let body = realistic_body(600);

        let d1 = peer.send(&body);
        assert_eq!(d1.refs, 0, "首轮应全量");

        let d2 = peer.send(&body);
        assert_eq!(d2.new_fps.len(), 0, "重复 body 不应引入任何新块");
        assert_eq!(d2.refs, d2.blocks, "重复 body 应全部命中缓存");
        assert!(
            d2.stream.len() <= d2.blocks * 32,
            "全 REF 时实发量应约等于每块 25 字节，实际 {} 字节 / {} 块",
            d2.stream.len(),
            d2.blocks
        );
    }

    #[test]
    fn corrupted_stream_yields_error_not_wrong_bytes() {
        // 截断的 literal 必须报错，绝不能静默产出短 content
        let mut s = Vec::new();
        write_literal(&mut s, b"0123456789");
        s.truncate(s.len() - 3);
        let store: std::collections::HashMap<Fp, Vec<u8>> = std::collections::HashMap::new();
        let r = recompose(&s, |fp| store.get(fp).map(|v| v.as_slice()));
        assert!(r.is_err(), "截断流不得被当成正常结果");
    }

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 1, 127, 128, 300, 16384, u32::MAX as u64, u64::MAX] {
            let mut b = Vec::new();
            write_varint(&mut b, v);
            let mut p = 0;
            assert_eq!(read_varint(&b, &mut p).unwrap(), v);
            assert_eq!(p, b.len());
        }
    }

    #[test]
    fn varint_rejects_truncation_and_overflow() {
        let mut p = 0;
        assert!(matches!(
            read_varint(&[0x80], &mut p),
            Err(TokenError::Truncated { .. })
        ));
        let mut p = 0;
        assert!(matches!(
            read_varint(&[0x80u8; 12], &mut p),
            Err(TokenError::VarintOverflow { .. })
        ));
    }

    #[test]
    fn literal_and_ref_roundtrip() {
        let mut s = Vec::new();
        write_literal(&mut s, b"hello");
        let fp = block_fp(ns(), b"world");
        write_ref(&mut s, &fp);
        write_literal(&mut s, b"");

        let toks = decode(&s).unwrap();
        assert_eq!(
            toks,
            vec![
                Token::Literal(b"hello".to_vec()),
                Token::Ref(fp),
                Token::Literal(Vec::new()),
            ]
        );
    }

    #[test]
    fn decode_rejects_bad_tag() {
        assert!(matches!(
            decode(&[0x09, 0x01]),
            Err(TokenError::BadTag { .. })
        ));
    }

    #[test]
    fn decode_rejects_truncated_literal_and_ref() {
        let mut s = Vec::new();
        write_literal(&mut s, b"abcdef");
        s.truncate(s.len() - 2);
        assert!(matches!(decode(&s), Err(TokenError::Truncated { .. })));

        let mut s = Vec::new();
        write_ref(&mut s, &block_fp(ns(), b"x"));
        s.truncate(10);
        assert!(matches!(decode(&s), Err(TokenError::Truncated { .. })));
    }
    /// **畸形流必须与缺块分开报**（这条钉住的是"分类"，不是某个字符串）。
    ///
    /// 曾经两者都返回 `Err(Vec<Fp>)`：畸形流时那个列表是**空的**，上层于是报出
    /// 「缺少 0 个块」+ 提示 `SEND_MISSING`——自相矛盾，而且把"编码坏了"记成"缓存缺块",
    /// 让客户端按提示去补一个不存在的缺块清单（白付一个 RTT）。
    #[test]
    fn malformed_stream_is_not_reported_as_missing_blocks() {
        let n = ns();

        // 合法引用：必须报"缺 1 块"（不是畸形）
        let mut ok_ref = Vec::new();
        write_ref(&mut ok_ref, &block_fp(n, b"never-stored-anywhere"));
        match recompose_collect(n, &ok_ref, |_| None) {
            Err(RecomposeError::Missing(v)) => {
                assert_eq!(v.len(), 1, "合法的引用应当报「缺 1 块」")
            }
            other => panic!("合法引用应当是 Missing(1)，实际 {other:?}"),
        }

        // 三种畸形形态：都必须 Malformed
        for (name, bytes) in [
            ("未知标签 0x02", vec![0x02u8]),
            ("截断的 REF（只有 5 字节）", {
                let mut v = vec![0x01u8];
                v.extend_from_slice(&[0x5A; 5]);
                v
            }),
            ("截断的 LITERAL（声明 100 字节只给 3 个）", {
                let mut v = vec![0x00u8, 100];
                v.extend_from_slice(b"abc");
                v
            }),
        ] {
            match recompose_collect(n, &bytes, |_| None) {
                Err(RecomposeError::Malformed(_)) => {}
                other => panic!(
                    "{name} 必须报 Malformed（上层据此回 BAD_ENCODING），实际 {other:?}——\
                     报成 Missing 就会产生「缺少 0 个块」那种自相矛盾的错误"
                ),
            }
        }
    }
}
