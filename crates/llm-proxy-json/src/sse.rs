//! SSE 的**语法**级切分与事件扫描。
//!
//! 同样遵守 §3.1：只认 `field: value` 行结构与空行分隔，不认任何具体事件名或字段名。
//! 未识别的形态（多行 `data:`、非 JSON 载荷）一律返回 `None`，由上层原样透传——
//! 这是「上游新增事件类型时代理无需改代码」的落点。

use crate::json::{self, Leaf, Scan, Span};

/// 在缓冲区里找下一个完整事件的**结束偏移**（含空行终止符）。
///
/// 只认 SSE 规范允许的三种终止：`\n\n`、`\r\n\r\n`、`\r\r`。
/// 返回 `None` 表示还没凑够一个完整事件。
pub fn next_event_end(buf: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    while i < buf.len() {
        match buf[i] {
            b'\n' => {
                if buf.get(i + 1) == Some(&b'\n') {
                    return Some(i + 2);
                }
            }
            b'\r' => {
                if buf.get(i + 1) == Some(&b'\r') {
                    return Some(i + 2);
                }
                // 注意：常见形态是「行以 \r\n 结束，再跟一个空的 \r\n 行」，
                // 即连续 4 字节 \r\n\r\n。写成 \r\n\n 是错的。
                if buf.get(i + 1) == Some(&b'\n')
                    && buf.get(i + 2) == Some(&b'\r')
                    && buf.get(i + 3) == Some(&b'\n')
                {
                    return Some(i + 4);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// 找出事件内**唯一**一条 `data:` 行的载荷区间（相对事件起点）。
///
/// 多于一条返回 `None`：多行 `data:` 按规范要用 `\n` 拼接，我们的 JSON 扫描器
/// 不处理该形态，交给原样透传更安全。
fn single_data_payload(ev: &[u8]) -> Option<Span> {
    let mut found: Option<Span> = None;
    let mut line_start = 0usize;
    while line_start <= ev.len() {
        let rest = &ev[line_start..];
        let line_len = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
        let line = &rest[..line_len];
        let line = strip_cr(line);
        if let Some(after) = line.strip_prefix(b"data:") {
            if found.is_some() {
                return None; // 多行 data：不支持
            }
            let skip = after.iter().take_while(|&&b| b == b' ').count();
            let start = line_start + b"data:".len() + skip;
            let end = line_start + line.len();
            if start > end {
                return None;
            }
            found = Some(Span { start, end });
        }
        if line_len == rest.len() {
            break;
        }
        line_start += line_len + 1;
    }
    found
}

fn strip_cr(line: &[u8]) -> &[u8] {
    match line.last() {
        Some(b'\r') => &line[..line.len() - 1],
        _ => line,
    }
}

/// 扫描一个完整 SSE 事件（**含终止符**），产出覆盖整事件的叶值与骨架。
///
/// 骨架覆盖整事件，因此事件名（`event:` 行）也进了骨架——不同事件名必然得到不同
/// 骨架，不会错误共用同一套字面段。
///
/// 返回 `None` 的三种情况（一律由上层原样透传）：
/// * 没有 `data:` 行或多于一条；
/// * 载荷不是合法 JSON；
/// * 载荷是空白的。
pub fn scan_event(ev: &[u8]) -> Option<Scan> {
    let payload = single_data_payload(ev)?;
    let raw = ev.get(payload.start..payload.end)?;
    if raw.iter().all(|b| b.is_ascii_whitespace()) {
        return None;
    }

    let inner = json::scan(raw).ok()?;

    // 把叶值区间从「载荷内偏移」平移到「事件内偏移」
    let leaves: Vec<Leaf> = inner
        .leaves
        .into_iter()
        .map(|l| Leaf {
            path: l.path,
            span: Span {
                start: l.span.start + payload.start,
                end: l.span.end + payload.start,
            },
            kind: l.kind,
        })
        .collect();

    let skeleton = json::skeleton_of(ev, &leaves);
    let schema = json::schema_of(&skeleton);
    Some(Scan {
        leaves,
        skeleton,
        schema,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_boundaries_newline() {
        let buf = b"data: 1\n\ndata: 2\n\n";
        assert_eq!(next_event_end(buf), Some(9));
        assert_eq!(next_event_end(&buf[9..]), Some(9));
        assert_eq!(next_event_end(b"data: 1\n"), None);
    }

    #[test]
    fn event_boundaries_crlf_and_cr() {
        assert_eq!(next_event_end(b"data: 1\r\n\r\n"), Some(11));
        assert_eq!(next_event_end(b"data: 1\r\r"), Some(9));
        // 单个 \r\n 不算边界
        assert_eq!(next_event_end(b"data: 1\r\nx"), None);
    }

    #[test]
    fn scans_openai_shaped_chunk() {
        let ev = b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\
\"created\":1740000000,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\
\"delta\":{\"content\":\"\xe5\xad\x97\"},\"finish_reason\":null}]}\n\n";
        let s = scan_event(ev).expect("应能扫描");
        let paths: Vec<String> = s
            .leaves
            .iter()
            .map(|l| String::from_utf8_lossy(&l.path).into_owned())
            .collect();
        assert_eq!(
            paths,
            [
                "/id",
                "/object",
                "/created",
                "/model",
                "/choices/0/index",
                "/choices/0/delta/content",
                "/choices/0/finish_reason"
            ]
        );
        // 骨架覆盖整事件，所以必然包含 event 行之外的 data 前缀
        let sk = String::from_utf8_lossy(&s.skeleton);
        assert!(sk.starts_with("data: {"));
        assert!(sk.ends_with("}\n\n"), "终止符应在字面段里：{sk:?}");
        assert!(!sk.contains("chatcmpl-1"));
    }

    #[test]
    fn scans_anthropic_shaped_event_with_event_line() {
        let ev = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\
\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"a\"}}\n\n";
        let s = scan_event(ev).unwrap();
        let sk = String::from_utf8_lossy(&s.skeleton);
        assert!(
            sk.contains("event: content_block_delta"),
            "事件名必须在字面段里：{sk:?}"
        );
        assert!(!sk.contains("text_delta"));
    }

    #[test]
    fn same_shape_different_values_share_schema_across_events() {
        let mk = |tok: &str| {
            format!(
                "data: {{\"id\":\"chatcmpl-1\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{tok}\"}}}}]}}\n\n"
            )
            .into_bytes()
        };
        let a = scan_event(&mk("a")).unwrap();
        let b = scan_event(&mk("longer token")).unwrap();
        assert_eq!(a.schema, b.schema);
        assert_eq!(a.skeleton, b.skeleton);
    }

    #[test]
    fn different_event_name_yields_different_schema() {
        let mk = |name: &str| format!("event: {name}\ndata: {{\"index\":0}}\n\n").into_bytes();
        assert_ne!(
            scan_event(&mk("content_block_delta")).unwrap().schema,
            scan_event(&mk("message_stop")).unwrap().schema,
            "事件名不同不得共用模板，否则字面段会错"
        );
    }

    #[test]
    fn non_json_and_multiline_payloads_fall_back_to_none() {
        // [DONE] 哨兵
        assert!(scan_event(b"data: [DONE]\n\n").is_none());
        // 空载荷
        assert!(scan_event(b"data:\n\n").is_none());
        // 多行 data
        assert!(scan_event(b"data: {\"a\":\ndata: 1}\n\n").is_none());
        // 没有 data 行
        assert!(scan_event(b"event: ping\n\n").is_none());
        // 非 JSON 载荷
        assert!(scan_event(b"data: hello world\n\n").is_none());
    }

    /// 叶值区间必须落在事件内，且能据此逐字节拼回原事件。
    #[test]
    fn leaf_spans_reconstruct_the_whole_event_byte_exactly() {
        let ev = b"event: x\ndata: {\"a\":\"bb\",\"b\":[1,{\"c\":null}]}\n\n";
        let s = scan_event(ev).unwrap();
        // 这里原本**内联**实现了同一件事（把 leaves 拼回原文再比对），而
        // `tmpl::spans_reconstruct` 就是为它写的、却全仓库没人调用——第 39 轮的
        // 函数级门禁（`cargo run -p dev-tools -- gates`）把它查了出来。
        // 改成调用它：既不重复实现，也不再有"声称用于自检却没人跑"的工具。
        assert!(
            crate::tmpl::spans_reconstruct(ev, &s.leaves),
            "叶值 spans 必须把整个事件逐字节拼回来"
        );
    }
}
