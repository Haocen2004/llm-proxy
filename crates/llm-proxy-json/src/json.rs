//! 保序 JSON **语法**级扫描。
//!
//! 设计约束见 §3.1「上游无关」：
//!
//! * 只做**语法**分析（键路径、类型、字节区间），**不得**硬编码上游字段名；
//! * 只输出 **span 位置**，不输出反序列化后的值——重组必须逐字节等价；
//! * 判定标准：上游新增字段或新事件类型时，本模块**无需修改**。
//!
//! 不建「值模型」是刻意的：扫一遍只产出区间与路径，不复制任何字符串，因此内存占用
//! 与 body 大小关系很小（只与叶值个数成正比）。

/// 源字节里的一个区间。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn len(&self) -> usize {
        self.end - self.start
    }
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// 叶值类别。判别值刻意落在 ASCII 控制区，便于嵌进骨架字节流而不与正文混淆。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Kind {
    Str = 1,
    Num = 2,
    Bool = 3,
    Null = 4,
}

impl Kind {
    pub fn marker(self) -> u8 {
        self as u8
    }
}

/// 一个叶值：路径 + **完整 token 区间**（字符串含首尾引号）+ 类别。
///
/// 区间含引号是有意的：这样切片出来的就是自定界的合法 JSON token，
/// 可以直接作为变量槽的值原样插入，不需要任何转义处理。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    pub path: Vec<u8>,
    /// 相对**传入切片**的偏移。SSE 场景下由调用方再加上事件内偏移。
    pub span: Span,
    pub kind: Kind,
}

/// 扫描结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scan {
    /// 按**源字节顺序**排列的叶值。
    pub leaves: Vec<Leaf>,
    /// 结构骨架：把每个叶值的区段替换为一个类别字节，其余字节原样保留。
    ///
    /// 两个事件的骨架相同 ⇔ 除叶值外的每个字节都相同。这正好是「可以共用同一套
    /// 字面段」的充要条件，因此用它做模板的匹配键是安全且完备的。
    pub skeleton: Vec<u8>,
    /// 骨架的 128 位哈希，用作模板匹配键。
    pub schema: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError {
    pub at: usize,
    pub msg: &'static str,
}

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "偏移 {} 处 {} ", self.at, self.msg)
    }
}

impl std::error::Error for JsonError {}

/// 递归深度上限。畸形/恶意输入不该把栈打爆。
const MAX_DEPTH: usize = 96;

struct Scanner<'a> {
    src: &'a [u8],
    pos: usize,
    leaves: Vec<Leaf>,
    path: Vec<u8>,
    depth: usize,
}

impl<'a> Scanner<'a> {
    fn err(&self, msg: &'static str) -> JsonError {
        JsonError { at: self.pos, msg }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            match b {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), JsonError> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err("期望的分隔符缺失"))
        }
    }

    /// 扫描一个字符串 token（含引号），不记叶。
    fn string_token(&mut self) -> Result<Span, JsonError> {
        let start = self.pos;
        self.expect(b'"')?;
        loop {
            match self.peek() {
                None => {
                    return Err(JsonError {
                        at: start,
                        msg: "字符串未闭合",
                    })
                }
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(Span {
                        start,
                        end: self.pos,
                    });
                }
                Some(b'\\') => {
                    self.pos += 1;
                    match self.peek() {
                        None => {
                            return Err(JsonError {
                                at: start,
                                msg: "转义序列未完成",
                            })
                        }
                        // \uXXXX：只按语法跳 4 个字符，不校验码位
                        Some(b'u') => {
                            self.pos += 1;
                            for _ in 0..4 {
                                match self.peek() {
                                    Some(c) if c.is_ascii_hexdigit() => self.pos += 1,
                                    _ => {
                                        return Err(JsonError {
                                            at: self.pos,
                                            msg: "\\u 转义需要 4 位十六进制",
                                        })
                                    }
                                }
                            }
                        }
                        Some(_) => self.pos += 1,
                    }
                }
                Some(c) if c < 0x20 => return Err(self.err("字符串内出现未转义的控制字符")),
                Some(_) => self.pos += 1,
            }
        }
    }

    fn number_token(&mut self) -> Result<Span, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits_start = self.pos;
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.pos += 1;
        }
        if self.pos == digits_start {
            return Err(JsonError {
                at: start,
                msg: "数字缺少整数部分",
            });
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            let frac = self.pos;
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
            if self.pos == frac {
                return Err(JsonError {
                    at: start,
                    msg: "小数点后缺少数字",
                });
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            let exp = self.pos;
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
            if self.pos == exp {
                return Err(JsonError {
                    at: start,
                    msg: "指数缺少数字",
                });
            }
        }
        Ok(Span {
            start,
            end: self.pos,
        })
    }

    fn keyword(&mut self, word: &[u8], kind: Kind) -> Result<Span, JsonError> {
        let start = self.pos;
        if self.src.len() >= self.pos + word.len()
            && &self.src[self.pos..self.pos + word.len()] == word
        {
            self.pos += word.len();
            let _ = kind;
            Ok(Span {
                start,
                end: self.pos,
            })
        } else {
            Err(self.err("非法字面量"))
        }
    }

    fn push_leaf(&mut self, span: Span, kind: Kind) {
        self.leaves.push(Leaf {
            path: self.path.clone(),
            span,
            kind,
        });
    }

    fn value(&mut self) -> Result<(), JsonError> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => {
                let s = self.string_token()?;
                self.push_leaf(s, Kind::Str);
                Ok(())
            }
            Some(b't') => {
                let s = self.keyword(b"true", Kind::Bool)?;
                self.push_leaf(s, Kind::Bool);
                Ok(())
            }
            Some(b'f') => {
                let s = self.keyword(b"false", Kind::Bool)?;
                self.push_leaf(s, Kind::Bool);
                Ok(())
            }
            Some(b'n') => {
                let s = self.keyword(b"null", Kind::Null)?;
                self.push_leaf(s, Kind::Null);
                Ok(())
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => {
                let s = self.number_token()?;
                self.push_leaf(s, Kind::Num);
                Ok(())
            }
            _ => Err(self.err("期望一个值")),
        }
    }

    fn descend(&mut self) -> Result<(), JsonError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(self.err("嵌套过深"));
        }
        Ok(())
    }

    fn object(&mut self) -> Result<(), JsonError> {
        self.descend()?;
        self.expect(b'{')?;
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(());
        }
        loop {
            self.skip_ws();
            let key_span = self.string_token()?;
            // 键用**源字节形态**（含转义）入路径，保证同一序列化器下稳定，
            // 且不需要实现反转义
            let saved = self.path.len();
            self.path.push(b'/');
            self.path
                .extend_from_slice(&self.src[key_span.start + 1..key_span.end - 1]);
            self.skip_ws();
            self.expect(b':')?;
            self.value()?;
            self.path.truncate(saved);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    self.depth -= 1;
                    return Ok(());
                }
                _ => return Err(self.err("对象成员之间期望 ',' 或 '}'")),
            }
        }
    }

    fn array(&mut self) -> Result<(), JsonError> {
        self.descend()?;
        self.expect(b'[')?;
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(());
        }
        let mut idx = 0usize;
        loop {
            let saved = self.path.len();
            self.path.push(b'/');
            self.path.extend_from_slice(idx.to_string().as_bytes());
            self.value()?;
            self.path.truncate(saved);
            idx += 1;
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    self.depth -= 1;
                    return Ok(());
                }
                _ => return Err(self.err("数组元素之间期望 ',' 或 ']'")),
            }
        }
    }
}

/// 构造结构骨架：把每个叶值的区段替换为一个类别字节。
pub fn skeleton_of(src: &[u8], leaves: &[Leaf]) -> Vec<u8> {
    let leaf_bytes: usize = leaves.iter().map(|l| l.span.len()).sum();
    let mut out = Vec::with_capacity(src.len() - leaf_bytes + leaves.len());
    let mut pos = 0usize;
    for l in leaves {
        // 叶值必须按源序且不重叠——扫描器保证，这里用断言把它钉死
        debug_assert!(l.span.start >= pos, "叶值区间必须按源序且不重叠");
        out.extend_from_slice(&src[pos..l.span.start]);
        out.push(l.kind.marker());
        pos = l.span.end;
    }
    out.extend_from_slice(&src[pos..]);
    out
}

pub fn schema_of(skeleton: &[u8]) -> [u8; 16] {
    let h = blake3::hash(skeleton);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.as_bytes()[..16]);
    out
}

/// 扫描一段完整 JSON（要求恰好一个顶层值，允许前后空白）。
pub fn scan(src: &[u8]) -> Result<Scan, JsonError> {
    let mut s = Scanner {
        src,
        pos: 0,
        leaves: Vec::new(),
        path: Vec::new(),
        depth: 0,
    };
    s.skip_ws();
    s.value()?;
    s.skip_ws();
    if s.pos != src.len() {
        return Err(JsonError {
            at: s.pos,
            msg: "顶层值之后还有内容",
        });
    }
    let leaves = s.leaves;
    let skeleton = skeleton_of(src, &leaves);
    let schema = schema_of(&skeleton);
    Ok(Scan {
        leaves,
        skeleton,
        schema,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(s: &Scan) -> Vec<String> {
        s.leaves
            .iter()
            .map(|l| String::from_utf8_lossy(&l.path).into_owned())
            .collect()
    }

    fn values<'a>(src: &'a [u8], s: &Scan) -> Vec<&'a [u8]> {
        s.leaves
            .iter()
            .map(|l| &src[l.span.start..l.span.end])
            .collect()
    }

    #[test]
    fn scans_flat_object() {
        let src = br#"{"id":"abc","n":12,"ok":true,"nothing":null}"#;
        let s = scan(src).unwrap();
        assert_eq!(paths(&s), ["/id", "/n", "/ok", "/nothing"]);
        assert_eq!(values(src, &s), [&b"\"abc\""[..], b"12", b"true", b"null"]);
        assert_eq!(
            s.leaves.iter().map(|l| l.kind).collect::<Vec<_>>(),
            [Kind::Str, Kind::Num, Kind::Bool, Kind::Null]
        );
    }

    #[test]
    fn scans_nested_with_array_indices() {
        let src = br#"{"choices":[{"index":0,"delta":{"content":"hi"},"logprobs":null}]}"#;
        let s = scan(src).unwrap();
        assert_eq!(
            paths(&s),
            [
                "/choices/0/index",
                "/choices/0/delta/content",
                "/choices/0/logprobs"
            ]
        );
    }

    #[test]
    fn spans_are_exactly_the_tokens() {
        let src = br#"{"a":"x","b":[1,2]}"#;
        let s = scan(src).unwrap();
        for l in &s.leaves {
            let tok = &src[l.span.start..l.span.end];
            // 切出来必须是合法 JSON 片段
            assert!(
                scan(tok).is_ok(),
                "叶值区间切出的 {:?} 不是合法 JSON token",
                String::from_utf8_lossy(tok)
            );
        }
    }

    #[test]
    fn strings_include_quotes_and_survive_escapes() {
        let src = br#"{"t":"a\"b\\c\u0041d"}"#;
        let s = scan(src).unwrap();
        assert_eq!(s.leaves.len(), 1);
        assert_eq!(
            &src[s.leaves[0].span.start..s.leaves[0].span.end],
            br#""a\"b\\c\u0041d""#
        );
    }

    #[test]
    fn numbers_cover_negatives_fractions_exponents() {
        let src = br#"[0,-1,3.5,1e10,-2.5E-3]"#;
        let s = scan(src).unwrap();
        assert_eq!(values(src, &s).len(), 5);
        assert_eq!(values(src, &s)[4], b"-2.5E-3");
        assert!(s.leaves.iter().all(|l| l.kind == Kind::Num));
    }

    #[test]
    fn whitespace_does_not_change_leaf_spans() {
        let src = b"{ \"a\" : \"x\" ,\n \"b\" : 1 }";
        let s = scan(src).unwrap();
        assert_eq!(paths(&s), ["/a", "/b"]);
        assert_eq!(values(src, &s), [&b"\"x\""[..], b"1"]);
    }

    #[test]
    fn empty_containers_have_no_leaves() {
        for src in [&b"{}"[..], b"[]", b"{\"a\":{}}", b"{\"a\":[]}"] {
            let s = scan(src).unwrap();
            assert!(
                s.leaves.is_empty(),
                "{:?} 不应有叶值",
                String::from_utf8_lossy(src)
            );
        }
    }

    // ---- 骨架 ----

    #[test]
    fn skeleton_replaces_exactly_the_leaf_ranges() {
        let src = br#"{"a":"xy","b":12}"#;
        let s = scan(src).unwrap();
        // 叶值总长 = `"xy"`(4) + `12`(2)；每个叶值折算为 1 字节
        let leaf_bytes: usize = s.leaves.iter().map(|l| l.span.len()).sum();
        assert_eq!(leaf_bytes, 6);
        assert_eq!(s.skeleton.len(), src.len() - leaf_bytes + s.leaves.len());
        // 骨架里应保留键名与标点
        let sk = String::from_utf8_lossy(&s.skeleton).into_owned();
        assert!(sk.contains("\"a\""));
        assert!(sk.contains("\"b\""));
        assert!(!sk.contains("xy"));
        assert!(!sk.contains("12"));
    }

    /// 骨架相同 ⇔ 除叶值外每个字节都相同——这是模板匹配的充要条件。
    #[test]
    fn same_shape_different_values_share_a_schema() {
        let a = r#"{"id":"msg_1","delta":{"text":"你好"}}"#.as_bytes();
        let b = r#"{"id":"msg_2","delta":{"text":"世界和平"}}"#.as_bytes();
        let sa = scan(a).unwrap();
        let sb = scan(b).unwrap();
        assert_eq!(sa.schema, sb.schema, "结构相同应共用模板");
        assert_eq!(sa.skeleton, sb.skeleton);
    }

    #[test]
    fn different_shape_or_extra_field_changes_the_schema() {
        let base = br#"{"id":"m","delta":{"text":"x"}}"#;
        let extra = br#"{"id":"m","delta":{"text":"x"},"usage":{"n":1}}"#;
        let reordered = br#"{"delta":{"text":"x"},"id":"m"}"#;
        let kind_changed = br#"{"id":"m","delta":{"text":1}}"#;
        let spacing = br#"{"id": "m","delta":{"text":"x"}}"#;
        let sb = scan(base).unwrap().schema;
        for (label, other) in [
            ("多字段", &extra[..]),
            ("键序不同", &reordered[..]),
            ("值类型不同", &kind_changed[..]),
            ("空白不同", &spacing[..]),
        ] {
            let so = scan(other).unwrap().schema;
            assert_ne!(sb, so, "{label} 必须得到不同骨架（否则字面段会错）");
        }
    }

    #[test]
    fn schema_is_stable_across_repeated_scans() {
        let src = br#"{"a":[1,2,{"b":"c"}]}"#;
        assert_eq!(scan(src).unwrap().schema, scan(src).unwrap().schema);
    }

    // ---- 错误处理 ----

    #[test]
    fn rejects_malformed_input() {
        let cases: &[(&[u8], &str)] = &[
            (b"", "空"),
            (b"{}x", "尾随内容"),
            (br#"{"a":}"#, "缺值"),
            (br#"{"a":1,}"#, "尾逗号"),
            (br#""unterminated"#, "未闭合字符串"),
            (br#"{"a":"\u00"#, "\\u 位数不足"),
            (br#"{"a":01"#, "尾随内容"),
            (b"[1,2", "数组未闭合"),
            (b"nul", "非法字面量"),
        ];
        for (src, label) in cases {
            assert!(
                scan(src).is_err(),
                "{label} 应被拒绝：{:?}",
                String::from_utf8_lossy(src)
            );
        }
    }

    #[test]
    fn rejects_deep_nesting_instead_of_overflowing() {
        let deep: Vec<u8> = vec![b'['; MAX_DEPTH + 10];
        assert!(scan(&deep).is_err(), "过深嵌套必须报错而不是崩溃栈");
    }

    #[test]
    fn rejects_unescaped_control_chars_in_strings() {
        assert!(scan(b"{\"a\":\"x\ny\"}").is_err());
    }

    #[test]
    fn roundtrip_reconstruction_from_spans_is_byte_exact() {
        // 用 span 把原文拼回去，必须逐字节相同——模板重组依赖这一点
        let src =
            r#"{"model":"gpt-4o","choices":[{"delta":{"content":"字"},"index":0}]}"#.as_bytes();
        let s = scan(src).unwrap();
        let mut rebuilt = Vec::new();
        let mut pos = 0usize;
        for l in &s.leaves {
            rebuilt.extend_from_slice(&src[pos..l.span.start]);
            rebuilt.extend_from_slice(&src[l.span.start..l.span.end]);
            pos = l.span.end;
        }
        rebuilt.extend_from_slice(&src[pos..]);
        assert_eq!(rebuilt, src);
    }
}
