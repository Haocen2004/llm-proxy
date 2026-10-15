//! 响应侧批量帧的**紧凑编码**。
//!
//! 批量帧在热路径上，每个字节都要乘以事件数。protobuf 每条目的 tag/length 开销约
//! 4 字节；在 128 字节的 Anthropic 事件上就是约 3%——足以决定「省 ≥90%」这条验收线
//! 过不过，也决定了能否把批量窗口压到 40 ms 而不牺牲首字节后的延迟。
//!
//! 线格式：
//!
//! ```text
//! varint item_count
//! 重复 item_count 次：
//!   varint tag        tag == 0 → 原样条目；否则是 template_id
//!   tag == 0:  varint len, len 字节原样数据
//!   否则:      按模板槽序重复 { varint len, len 字节 }
//! ```
//!
//! **槽数不进流**——客户端已经从模板定义知道它（`segments.len() - 1`），
//! 省掉每个条目一个计数字节，即约 0.8%。

use crate::token::write_varint;
/// 一条批量项。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchItem {
    /// 0 表示原样字节。
    pub template_id: u32,
    /// `template_id == 0` 时使用。
    pub raw: Vec<u8>,
    /// `template_id != 0` 时使用，按模板槽序排列。
    pub vars: Vec<Vec<u8>>,
}

impl BatchItem {
    pub fn raw(bytes: Vec<u8>) -> Self {
        Self {
            template_id: 0,
            raw: bytes,
            vars: Vec::new(),
        }
    }

    pub fn delta(template_id: u32, vars: Vec<Vec<u8>>) -> Self {
        Self {
            template_id,
            raw: Vec::new(),
            vars,
        }
    }

    pub fn is_raw(&self) -> bool {
        self.template_id == 0
    }

    /// 该条目在线上占用的字节数（不含批次的计数字段）。
    pub fn encoded_len(&self) -> usize {
        let tag = varint_len(self.template_id as u64);
        if self.is_raw() {
            tag + varint_len(self.raw.len() as u64) + self.raw.len()
        } else {
            tag + self
                .vars
                .iter()
                .map(|v| varint_len(v.len() as u64) + v.len())
                .sum::<usize>()
        }
    }
}

pub fn varint_len(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchError {
    /// 缓冲区在中途结束。
    Truncated,
    /// 条目引用了客户端不认识的模板——**无法重组，必须失败而不是猜**。
    UnknownTemplate(u32),
    /// item_count 大到不可能（防止畸形流导致巨量分配）。
    ImplausibleCount(u64),
}

impl std::fmt::Display for BatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatchError::Truncated => write!(f, "批量帧被截断"),
            BatchError::UnknownTemplate(id) => write!(f, "未知模板 {id}"),
            BatchError::ImplausibleCount(n) => write!(f, "条目数 {n} 不合理"),
        }
    }
}

impl std::error::Error for BatchError {}

/// 单批最多允许的条目数。批量窗口最多合并几十个事件，取 4096 留足余量即可挡住畸形流。
const MAX_ITEMS: u64 = 4096;

pub fn encode(items: &[BatchItem], out: &mut Vec<u8>) {
    write_varint(out, items.len() as u64);
    for it in items {
        write_varint(out, it.template_id as u64);
        if it.is_raw() {
            write_varint(out, it.raw.len() as u64);
            out.extend_from_slice(&it.raw);
        } else {
            for v in &it.vars {
                write_varint(out, v.len() as u64);
                out.extend_from_slice(v);
            }
        }
    }
}

/// 解码。`slots(template_id)` 返回该模板的槽数；返回 `None` 即为未知模板。
pub fn decode(
    buf: &[u8],
    slots: impl Fn(u32) -> Option<usize>,
) -> Result<Vec<BatchItem>, BatchError> {
    let mut pos = 0usize;
    let count = read_wire_varint(buf, &mut pos)?;
    if count > MAX_ITEMS {
        return Err(BatchError::ImplausibleCount(count));
    }
    let mut items = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let tag = read_wire_varint(buf, &mut pos)?;
        if tag > u32::MAX as u64 {
            return Err(BatchError::UnknownTemplate(u32::MAX));
        }
        let template_id = tag as u32;
        if template_id == 0 {
            let len = read_wire_varint(buf, &mut pos)? as usize;
            let end = pos.checked_add(len).ok_or(BatchError::Truncated)?;
            if end > buf.len() {
                return Err(BatchError::Truncated);
            }
            let raw = buf[pos..end].to_vec();
            pos = end;
            items.push(BatchItem::raw(raw));
        } else {
            let n = slots(template_id).ok_or(BatchError::UnknownTemplate(template_id))?;
            let mut vars = Vec::with_capacity(n);
            for _ in 0..n {
                let len = read_wire_varint(buf, &mut pos)? as usize;
                let end = pos.checked_add(len).ok_or(BatchError::Truncated)?;
                if end > buf.len() {
                    return Err(BatchError::Truncated);
                }
                vars.push(buf[pos..end].to_vec());
                pos = end;
            }
            items.push(BatchItem::delta(template_id, vars));
        }
    }
    if pos != buf.len() {
        return Err(BatchError::Truncated);
    }
    Ok(items)
}

fn read_wire_varint(buf: &[u8], pos: &mut usize) -> Result<u64, BatchError> {
    // 复用 token 的 varint 实现，把它的错误折叠成 Truncated
    let mut p = *pos;
    match crate::token::read_varint(buf, &mut p) {
        Ok(v) => {
            *pos = p;
            Ok(v)
        }
        Err(_) => Err(BatchError::Truncated),
    }
}

/// **只读地**取出"第一个条目的 `tag`"（不解码、不分配）✓。
///
/// 第 194 轮加：定位 `terminated` 时需要**看清 wire 上到底是什么** ✓，
/// 而 [`decode`] 只在出错时给 `BatchError::UnknownTemplate(id)` —— 那个 `id`
/// 来自**同一条**读取路径 ✓ ⇒ 看到它并不能说明"帧的开头是否合理" ✓。
/// 于是给出这��只读探针 ✓：调用方把它和 `head_hex` 一起打出来 ✓，就能**手撸**判断
/// 这一帧的 `item_count` 与首个 `tag` 是否讲得通 ✓✓
/// （讲得通 ⇒ 服务端确实发了那个 id ✓；讲不通 ⇒ 帧内容本身是垃圾 ✓）。
///
/// **不改变任何解码行为** ✓（只读 ✓），因此不构成"为测试而改生产语义" ✓。
pub fn peek_first_tag(buf: &[u8]) -> Option<u64> {
    let mut pos = 0usize;
    let _count = read_wire_varint(buf, &mut pos).ok()?;
    read_wire_varint(buf, &mut pos).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_mixed_items() {
        let items = vec![
            BatchItem::raw(b"raw bytes here".to_vec()),
            BatchItem::delta(7, vec![b"\"a\"".to_vec()]),
            BatchItem::raw(b"x".to_vec()),
            BatchItem::delta(7, vec![b"\"bc\"".to_vec()]),
            BatchItem::delta(9, vec![b"1".to_vec(), b"null".to_vec()]),
        ];
        let mut buf = Vec::new();
        encode(&items, &mut buf);
        let got = decode(&buf, |id| match id {
            7 => Some(1),
            9 => Some(2),
            _ => None,
        })
        .unwrap();
        assert_eq!(got, items);
    }

    #[test]
    fn empty_batch_roundtrips() {
        let mut buf = Vec::new();
        encode(&[], &mut buf);
        assert_eq!(buf, vec![0u8]);
        assert_eq!(decode(&buf, |_| None).unwrap(), vec![]);
    }

    #[test]
    fn zero_slot_template_costs_one_tag_byte() {
        // 完全重复的事件：模板没有变量槽，条目只剩一个 tag
        let items = vec![BatchItem::delta(3, vec![])];
        let mut buf = Vec::new();
        encode(&items, &mut buf);
        assert_eq!(buf.len(), 2, "count(1) + tag(1)");
        assert_eq!(decode(&buf, |_| Some(0)).unwrap(), items);
    }

    /// 紧凑编码的意义：在 Anthropic 那种 128 字节事件上，每条目开销
    /// 必须小到「省 ≥90%」可以达成。
    #[test]
    fn per_item_overhead_is_small_enough() {
        // 一个槽、值为 "\"a\""（3 字节）——真实 LLM 短 token 的典型形态
        let item = BatchItem::delta(1, vec![b"\"a\"".to_vec()]);
        let n = item.encoded_len();
        assert_eq!(n, 5, "tag(1) + len(1) + 3 字节变量 = 5");
        assert!(n <= 6, "每条目开销必须压到个位数，实际 {n}");
    }

    #[test]
    fn unknown_template_is_rejected_not_guessed() {
        let items = vec![BatchItem::delta(42, vec![b"x".to_vec()])];
        let mut buf = Vec::new();
        encode(&items, &mut buf);
        assert_eq!(
            decode(&buf, |_| None).unwrap_err(),
            BatchError::UnknownTemplate(42)
        );
    }

    #[test]
    fn truncated_input_is_rejected() {
        let items = vec![BatchItem::raw(b"abcdef".to_vec())];
        let mut buf = Vec::new();
        encode(&items, &mut buf);
        for cut in 1..buf.len() {
            assert!(
                decode(&buf[..cut], |_| Some(1)).is_err(),
                "截断到 {cut} 字节应报错"
            );
        }
    }

    #[test]
    fn trailing_garbage_is_rejected() {
        let items = vec![BatchItem::raw(b"a".to_vec())];
        let mut buf = Vec::new();
        encode(&items, &mut buf);
        buf.push(0xFF);
        assert!(decode(&buf, |_| Some(0)).is_err(), "多余字节必须报错");
    }

    #[test]
    fn implausible_count_is_rejected() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 1_000_000);
        assert!(matches!(
            decode(&buf, |_| Some(0)),
            Err(BatchError::ImplausibleCount(_))
        ));
    }

    /// 第 194 轮：`peek_first_tag` 必须与 `decode` 的**同一条**读取路径一致 ✓ ——
    /// 否则"探针看到的 tag"就不能用来解释 `UnknownTemplate(id)` 里的 id ✓✗。
    #[test]
    fn peek_first_tag_agrees_with_decode() {
        for (id, nslots) in [(1u32, 1usize), (7, 2), (112, 3), (4095, 0)] {
            let vars: Vec<Vec<u8>> = (0..nslots).map(|i| format!("v{i}").into_bytes()).collect();
            let items = vec![BatchItem::delta(id, vars)];
            let mut buf = Vec::new();
            encode(&items, &mut buf);
            assert_eq!(
                peek_first_tag(&buf),
                Some(id as u64),
                "id={id} 的探针必须与线格式一致 ✓"
            );
            // 顺带确认：decode 在"未知模板"时报的就是这个 id ✓
            assert_eq!(
                decode(&buf, |_| None).unwrap_err(),
                BatchError::UnknownTemplate(id)
            );
        }
        // 原样条目（tag=0）也要能探出来 ✓
        let mut buf = Vec::new();
        encode(&[BatchItem::raw(b"abc".to_vec())], &mut buf);
        assert_eq!(peek_first_tag(&buf), Some(0));
        // 半个 varint ⇒ 探针给出 None ✓（而不是瞎猜 ✓）
        assert_eq!(peek_first_tag(&[0x80]), None);
    }

    #[test]
    fn compact_encoding_beats_protobuf_on_the_hot_path() {
        // 120 个事件、每事件 1 个 3 字节变量
        let items: Vec<BatchItem> = (0..120)
            .map(|_| BatchItem::delta(1, vec![b"\"a\"".to_vec()]))
            .collect();
        let mut buf = Vec::new();
        encode(&items, &mut buf);
        // protobuf 每条约 7 字节（tag+len 各自带字段号），这里应为 5+1
        assert_eq!(buf.len(), 1 + 120 * 5);
        assert!(
            buf.len() < 120 * 7,
            "紧凑编码必须明显小于 protobuf 形态，实际 {}",
            buf.len()
        );
    }
}
