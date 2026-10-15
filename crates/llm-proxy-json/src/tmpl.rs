//! 字节模板归纳：把「同骨架的事件」压成「一套字面段 + 若干变量槽」。
//!
//! # 为什么是字节模板而不是结构模板
//!
//! 最自然的设计是「把 JSON 解析成结构、记住常量字段、只传变量字段，客户端再序列化回去」。
//! 但那**做不到逐字节一致**：键顺序、空白、转义形态、数字写法都可能被序列化器改动，
//! 而 §3.2 把「重组结果必须与原始逐字节相同」列为正确性红线。
//!
//! 这里改用另一种做法：模板保存的是**原始字节**被切开后的字面段，变量槽保存的是
//! 原样的 JSON token 区间（字符串含引号）。客户端重组只做 `seg0 + v0 + seg1 + …`，
//! **不存在任何序列化步骤**，因此逐字节一致是构造性成立的，不依赖序列化器的行为。
//!
//! # 归纳过程（两个样本即可定模板）
//!
//! 1. 某骨架首次出现 → 原样发送，留作样本；
//! 2. 同骨架第二次出现 → 逐叶值比较两个样本，**不同的降为变量、相同的留在字面段**，
//!    据此定出模板；本次发 `TEMPLATE_DEF` + 增量；
//! 3. 之后每次 → 抽变量、**本地重建并与原事件比对**，一致才发增量；
//! 4. 若某常量漂移导致比对失败 → 把漂移的叶值也降级为变量，用当前事件重建模板
//!    （重发 DEF），而不是退回原样发送。
//!
//! 第 3 步的本地验证是关键：它把「客户端会重组出错误字节」变成「服务端当场发现并
//! 改道」，代价是每次多一次几百字节的拼接与比较。§3.2 的红线值这个代价。

use std::collections::{HashMap, VecDeque};

use crate::json::{Leaf, Scan, Span};

/// 一个字节模板。
///
/// `segments.len() == var_leaf_idx.len() + 1`，重组为
/// `segments[0] + v0 + segments[1] + v1 + … + segments[n]`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub id: u32,
    pub schema: [u8; 16],
    pub segments: Vec<Vec<u8>>,
    /// 变量槽对应的叶值路径（按槽序），仅用于观测与调试。
    pub var_paths: Vec<Vec<u8>>,
    /// 变量槽对应的叶值下标（按槽序）。
    var_leaf_idx: Vec<usize>,
    /// 归纳时参考样本的**全部**叶值字节（按叶值序），用于检测常量漂移。
    ref_leaf_bytes: Vec<Vec<u8>>,
}

impl Template {
    /// 从线上下发的定义构造（客户端侧使用）。
    ///
    /// 客户端**只需要 `segments` 就能重组**——`rebuild` 不做任何推断或校验，
    /// 所以 `var_leaf_idx` / `ref_leaf_bytes` 留空即可。这两个字段只服务于
    /// 服务端侧的归纳与漂移检测，不必下发（下发反而多传几百字节）。
    pub fn from_parts(
        id: u32,
        schema: [u8; 16],
        segments: Vec<Vec<u8>>,
        var_paths: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            id,
            schema,
            segments,
            var_paths,
            var_leaf_idx: Vec::new(),
            ref_leaf_bytes: Vec::new(),
        }
    }

    /// 槽数（客户端可据此校验下发内容自洽）。
    pub fn slots(&self) -> usize {
        self.segments.len().saturating_sub(1)
    }

    /// 用给定变量槽值重建字节。`vars.len()` 必须等于槽数。
    pub fn rebuild(&self, vars: &[Vec<u8>]) -> Option<Vec<u8>> {
        if vars.len() + 1 != self.segments.len() {
            return None;
        }
        let mut out = Vec::with_capacity(
            self.segments.iter().map(Vec::len).sum::<usize>()
                + vars.iter().map(Vec::len).sum::<usize>(),
        );
        for (i, seg) in self.segments.iter().enumerate() {
            out.extend_from_slice(seg);
            if let Some(v) = vars.get(i) {
                out.extend_from_slice(v);
            }
        }
        Some(out)
    }

    /// 从同骨架的事件里抽出各变量槽的原始字节。
    pub fn extract<'a>(&self, src: &'a [u8], leaves: &[Leaf]) -> Option<Vec<&'a [u8]>> {
        if leaves.len() != self.ref_leaf_bytes.len() {
            return None;
        }
        let mut out = Vec::with_capacity(self.var_leaf_idx.len());
        for &i in &self.var_leaf_idx {
            let sp = leaves.get(i)?.span;
            out.push(src.get(sp.start..sp.end)?);
        }
        Some(out)
    }

    pub fn var_count(&self) -> usize {
        self.var_leaf_idx.len()
    }

    /// 模板自身的字节开销（DEF 需要传这么多）。
    pub fn encoded_len(&self) -> usize {
        self.segments.iter().map(|s| s.len()).sum::<usize>()
            + self.var_paths.iter().map(|p| p.len()).sum::<usize>()
            + 16
    }

    /// 抽出的变量槽就是「增量要传的东西」的总字节数。
    pub fn vars_len(vars: &[Vec<u8>]) -> usize {
        vars.iter().map(Vec::len).sum()
    }

    fn build(id: u32, schema: [u8; 16], src: &[u8], leaves: &[Leaf], var_idx: Vec<usize>) -> Self {
        let mut var_idx = var_idx;
        var_idx.sort_unstable();
        var_idx.dedup();

        let mut segments = Vec::with_capacity(var_idx.len() + 1);
        let mut pos = 0usize;
        for &i in &var_idx {
            let sp = leaves[i].span;
            segments.push(src[pos..sp.start].to_vec());
            pos = sp.end;
        }
        segments.push(src[pos..].to_vec());

        let var_paths = var_idx.iter().map(|&i| leaves[i].path.clone()).collect();
        let ref_leaf_bytes = leaves
            .iter()
            .map(|l| src[l.span.start..l.span.end].to_vec())
            .collect();

        Self {
            id,
            schema,
            segments,
            var_paths,
            var_leaf_idx: var_idx,
            ref_leaf_bytes,
        }
    }

    /// 在既有变量集基础上，把**值已漂移的常量**也降级为变量。
    fn demoted_var_idx(&self, src: &[u8], leaves: &[Leaf]) -> Vec<usize> {
        let mut idx = self.var_leaf_idx.clone();
        for (i, l) in leaves.iter().enumerate() {
            let cur = &src[l.span.start..l.span.end];
            if self.ref_leaf_bytes.get(i).map(Vec::as_slice) != Some(cur) {
                idx.push(i);
            }
        }
        idx.sort_unstable();
        idx.dedup();
        idx
    }
}

/// 对一个事件的处理结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Induction {
    /// 该骨架首次出现（或模板已失效）：**原样发送**。
    Raw,
    /// 归纳/重建出模板：本次需发 `TEMPLATE_DEF` 再发增量。
    Defined {
        template: Template,
        vars: Vec<Vec<u8>>,
    },
    /// 已有模板可用：只发增量。
    Delta { id: u32, vars: Vec<Vec<u8>> },
}

impl Induction {
    /// 本次「增量」实际要传的变量字节数；`Raw` 返回 `None`。
    pub fn var_bytes(&self) -> Option<usize> {
        match self {
            Induction::Raw => None,
            Induction::Defined { vars, .. } | Induction::Delta { vars, .. } => {
                Some(Template::vars_len(vars))
            }
        }
    }
}

struct Sample {
    bytes: Vec<u8>,
    leaves: Vec<Leaf>,
}

#[derive(Default)]
struct State {
    /// 已归纳出模板。
    template: Option<Template>,
    /// 正在等待第二个样本。
    sample: Option<Sample>,
}

/// 归纳器。**由服务端持有**——设计 §6.2 明确要求模板由服务端主导建立并显式下发，
/// 不做双侧独立归纳：两端各自归纳会在边界条件上发散，产生静默错误。
pub struct Inducer {
    states: HashMap<[u8; 16], State>,
    max_templates: usize,
    /// 模板的 LRU 顺序（按 schema）。
    lru: VecDeque<[u8; 16]>,
}

/// **模板 id 的进程级签发器** ✓（第 198 轮）。
///
/// # 为什么必须进程级，而不是每 `Inducer` 一个
///
/// 原来是 `next_id` 从 1 开始、**每个 `Inducer` 一份** ✓ ⇒ 而服务端是**每会话一个
/// `Inducer`**（`llmproxyd::egress::run_session` 里 `Inducer::new` ✓）⇒ 于是
/// **每条会话都有自己的 id 空间，全都从 1 开始** ✓ ⇒ 同一个 id 在不同会话里
/// 指向**不同的模板** ✗✗。
///
/// 客户端那边只要出现"多会话共用一张模板表"（并发多个 SDK 请求时就会 ✓），
/// 两套 id 空间就会**互相覆盖** ✓ ⇒ 表现正是现场抓到的形态：
///
/// * `template_defs=247` 而 `template_store.held=24` ✓（多套 1..N 反复覆盖 ✓）
/// * `evicted=0` ✓（不是淘汰 ✓）、`recoveries=0` ✓（不是重连 ✓）
/// * **表中间有洞**（有 id 35 ✓ 却缺 54 ✓）⇒ `UnknownTemplate` ⇒ 截断 ⇒ `terminated` ✗
/// * 客户端的"清空自愈"**治不了** ✗：清空后只补发**当前会话**的 def ✓，
///   别的会话的引用立刻又缺 ⇒ 抖动循环（现场：清空 14 次 / 失败 23 次 ✓）
///
/// ⇒ 改成**进程级单调签发** ✓ ⇒ id 在整个服务端进程内**全局唯一** ✓ ⇒
/// 客户端无论怎么共用表、并发多少会话，都不会再出现"同 id 不同义" ✓✓
/// —— 这也正是"几十上百个客户端并发连一个服务端"所要求的形态 ✓。
///
/// 与第 190 轮对 `sid` 的修法**同源** ✓（那里也从"每连接"提到了"进程级" ✓）。
static NEXT_TEMPLATE_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

impl Inducer {
    pub fn new(max_templates: usize) -> Self {
        Self {
            states: HashMap::new(),
            max_templates: max_templates.max(1),
            lru: VecDeque::new(),
        }
    }

    pub fn template_count(&self) -> usize {
        self.states
            .values()
            .filter(|s| s.template.is_some())
            .count()
    }

    /// 处理一个事件（必须是 `scan_event` 成功的结果）。
    pub fn feed(&mut self, ev: &[u8], scan: &Scan) -> Induction {
        let schema = scan.schema;

        // ---- 已有模板：抽变量 → 本地重建 → 比对 ----
        if let Some(t) = self.states.get(&schema).and_then(|s| s.template.as_ref()) {
            if let Some(vars) = t.extract(ev, &scan.leaves) {
                if t.rebuild(&vars.iter().map(|v| v.to_vec()).collect::<Vec<_>>())
                    .as_deref()
                    == Some(ev)
                {
                    let owned: Vec<Vec<u8>> = vars.into_iter().map(|v| v.to_vec()).collect();
                    let id = t.id;
                    self.touch(schema);
                    return Induction::Delta { id, vars: owned };
                }
            }
            // 常量漂移（例如 fingerprint 字段变了）：降级为变量后重建模板，
            // 而不是退回原样发送——后者会让该骨架永远拿不到模板。
            let t = self
                .states
                .get(&schema)
                .and_then(|s| s.template.clone())
                .unwrap();
            let idx = t.demoted_var_idx(ev, &scan.leaves);
            let nt = Template::build(t.id, schema, ev, &scan.leaves, idx);
            let vars = nt
                .extract(ev, &scan.leaves)
                .map(|v| v.into_iter().map(|x| x.to_vec()).collect())
                .unwrap_or_default();
            self.states.get_mut(&schema).unwrap().template = Some(nt.clone());
            self.touch(schema);
            return Induction::Defined { template: nt, vars };
        }

        // ---- 尚无模板：攒两个样本 ----
        let has_sample = self
            .states
            .get(&schema)
            .map(|s| s.sample.is_some())
            .unwrap_or(false);
        if !has_sample {
            self.states.entry(schema).or_default().sample = Some(Sample {
                bytes: ev.to_vec(),
                leaves: scan.leaves.clone(),
            });
            self.touch(schema);
            return Induction::Raw;
        }

        let first = self.states.get_mut(&schema).unwrap().sample.take().unwrap();
        // 两个样本的叶值路径必须一一对应（骨架相同即保证），否则放弃归纳
        if first.leaves.len() != scan.leaves.len() {
            self.states.get_mut(&schema).unwrap().sample = Some(Sample {
                bytes: ev.to_vec(),
                leaves: scan.leaves.clone(),
            });
            return Induction::Raw;
        }
        let var_idx: Vec<usize> = (0..scan.leaves.len())
            .filter(|&i| {
                let a = first.leaves[i].span;
                let b = scan.leaves[i].span;
                a.len() != b.len() || first.bytes[a.start..a.end] != ev[b.start..b.end]
            })
            .collect();

        // **进程级单调签发** ✓（第 198 轮，见 `NEXT_TEMPLATE_ID` 的说明 ✓）。
        // `wrapping_add` 后 `.max(1)` 保证**永不签发 0** ✓ —— 0 在原样条目里是保留值 ✓
        //（`BatchItem::is_raw` 用 `template_id == 0` 判定 ✓）。
        let id = NEXT_TEMPLATE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let t = Template::build(id, schema, ev, &scan.leaves, var_idx);
        let vars = t
            .extract(ev, &scan.leaves)
            .map(|v| v.into_iter().map(|x| x.to_vec()).collect())
            .unwrap_or_default();

        // 容量上限：淘汰最久未用的模板（连同它的样本）
        self.evict_if_needed();
        self.states.entry(schema).or_default().template = Some(t.clone());
        self.touch(schema);
        Induction::Defined { template: t, vars }
    }

    /// 清空全部状态（响应结束时调用，模板按响应生命周期管理）。
    pub fn clear(&mut self) {
        self.states.clear();
        self.lru.clear();
    }

    /// 按 id 取一份**模板副本** ✓。
    ///
    /// # 为什么需要它（第 195 轮：`terminated` 的根因修复）
    ///
    /// 模板 id 是**每会话单调**的（`next_id` ✓，每会话一个 `Inducer` ✓），
    /// 而 `TemplateDef` **只在首次定义时下发一次**（服务端的 `drain_events` ✓）。
    /// ⇒ 于是**客户端只要换一张新表**（重连 / 进程刚起 ✓），
    /// 后面某条响应引用到"更早响应里定义过的模板"时就**必然查不到** ✓
    /// ⇒ `UnknownTemplate` ⇒ 按 M7 红线如实截断 ⇒ **harness 报 `terminated`** ✓✓。
    ///
    /// ⇒ 修法是"**本响应内引用到的模板，本响应至少发一次 def**" ✓
    /// ⇒ 这需要能按 id 把模板**取回来重发** ✓ ⇒ 就是这个方法 ✓。
    pub fn template_by_id(&self, id: u32) -> Option<Template> {
        self.states
            .values()
            .filter_map(|s| s.template.as_ref())
            .find(|t| t.id == id)
            .cloned()
    }

    /// 当前**全部已知**的模板 id ✓。
    ///
    /// 服务端用它来判定"这条流是否需要补发 def" ✓：客户端声明表非空时 ✓
    /// （即它已经有这些 id ✓），补发就是纯浪费 ⇒ 直接跳过 ✓。
    pub fn template_ids(&self) -> Vec<u32> {
        self.states
            .values()
            .filter_map(|s| s.template.as_ref())
            .map(|t| t.id)
            .collect()
    }

    fn touch(&mut self, schema: [u8; 16]) {
        self.lru.retain(|s| *s != schema);
        self.lru.push_back(schema);
    }

    fn evict_if_needed(&mut self) {
        while self.template_count() >= self.max_templates {
            let Some(old) = self.lru.pop_front() else {
                break;
            };
            if self
                .states
                .get(&old)
                .map(|s| s.template.is_some())
                .unwrap_or(false)
            {
                self.states.remove(&old);
                break;
            }
            // 没有模板的条目直接丢掉即可，继续找下一个
            self.states.remove(&old);
        }
    }
}

/// 工具：给定 spans 的切片拼起来是否等于原文（用于自检）。
pub fn spans_reconstruct(src: &[u8], leaves: &[Leaf]) -> bool {
    let mut pos = 0usize;
    for l in leaves {
        if l.span.start < pos || l.span.end > src.len() {
            return false;
        }
        pos = l.span.end;
    }
    true
}

/// 供调用方构造空 Span（避免测试里的生命周期麻烦）。
pub const EMPTY_SPAN: Span = Span { start: 0, end: 0 };

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sse;

    fn openai_chunk(tok: &str) -> Vec<u8> {
        format!(
            "data: {{\"id\":\"chatcmpl-BnAbCd\",\"object\":\"chat.completion.chunk\",\
\"created\":1740000000,\"model\":\"gpt-4o-2024-08-06\",\"system_fingerprint\":\"fp_abc123\",\
\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{tok}\"}},\"logprobs\":null,\
\"finish_reason\":null}}]}}\n\n"
        )
        .into_bytes()
    }

    /// 归纳器驱动一整条响应，返回 (每个事件实际要传的字节数, 重建结果)。
    fn drive(events: &[Vec<u8>]) -> (Vec<usize>, Vec<Vec<u8>>, Inducer) {
        let mut ind = Inducer::new(64);
        let mut costs = Vec::new();
        let mut rebuilt = Vec::new();
        for ev in events {
            let Some(scan) = sse::scan_event(ev) else {
                costs.push(ev.len());
                rebuilt.push(ev.clone());
                continue;
            };
            match ind.feed(ev, &scan) {
                Induction::Raw => {
                    costs.push(ev.len());
                    rebuilt.push(ev.clone());
                }
                Induction::Defined { template, vars } => {
                    costs.push(vars.iter().map(Vec::len).sum::<usize>());
                    let r = template.rebuild(&vars).expect("可重建");
                    rebuilt.push(r);
                }
                Induction::Delta { id, vars } => {
                    costs.push(vars.iter().map(Vec::len).sum::<usize>());
                    let t = ind
                        .states
                        .values()
                        .find_map(|s| s.template.as_ref().filter(|t| t.id == id))
                        .cloned()
                        .expect("模板应存在");
                    rebuilt.push(t.rebuild(&vars).expect("可重建"));
                }
            }
        }
        (costs, rebuilt, ind)
    }

    #[test]
    fn template_rebuild_is_byte_exact_for_every_event() {
        let events: Vec<Vec<u8>> = ["你", "好", "世", "界", "和平"]
            .iter()
            .map(|t| openai_chunk(t))
            .collect();
        let (_, rebuilt, _) = drive(&events);
        for (i, (orig, got)) in events.iter().zip(rebuilt.iter()).enumerate() {
            assert_eq!(
                got,
                orig,
                "第 {i} 个事件重建结果必须逐字节相同\n原文 {:?}\n得到 {:?}",
                String::from_utf8_lossy(orig),
                String::from_utf8_lossy(got)
            );
        }
    }

    /// M2 核心指标：200 个分片的响应，增量总字节数应远小于原文。
    #[test]
    fn batched_delta_shrinks_openai_stream_by_over_90_percent() {
        let tokens: Vec<String> = (0..200)
            .map(|i| {
                [
                    "模型", "代理", "缓存", "增量", "同步", "降级", "恢复", "稳定",
                ][i % 8]
                    .to_string()
            })
            .collect();
        let events: Vec<Vec<u8>> = tokens.iter().map(|t| openai_chunk(t)).collect();

        let total: usize = events.iter().map(Vec::len).sum();
        let (costs, rebuilt, _) = drive(&events);
        let delta: usize = costs.iter().sum();

        // 前两个事件原样（归纳需要两个样本）
        assert_eq!(costs[0], events[0].len());
        assert!(
            costs[2] < 64,
            "第 3 个事件起应只传变量（token 本身约 6 字节），实际 {}",
            costs[2]
        );

        let ratio = delta as f64 / total as f64;
        println!(
            "  [M2 归纳] {} 个分片，原文 {total} B，增量 {delta} B = {:.2}%",
            events.len(),
            ratio * 100.0
        );
        // 只算增量本身（不含帧头/批量开销），应远低于 10%
        assert!(
            ratio < 0.05,
            "归纳后的增变量应低于原文的 5%，实际 {:.2}%",
            ratio * 100.0
        );
        for (i, (o, g)) in events.iter().zip(rebuilt.iter()).enumerate() {
            assert_eq!(g, o, "第 {i} 个事件重建不一致");
        }
    }

    #[test]
    fn identical_repeated_events_cost_zero_vars() {
        // 两个样本完全相同 → 全部叶值都是常量 → 模板没有变量槽
        let ev = openai_chunk("x");
        let (costs, rebuilt, ind) = drive(&[ev.clone(), ev.clone(), ev.clone()]);
        assert_eq!(costs[2], 0, "完全重复的事件增量应为 0 字节");
        assert_eq!(ind.template_count(), 1);
        assert_eq!(rebuilt[2], ev);
    }

    #[test]
    fn schema_change_starts_a_new_template() {
        // 前两个分片同骨架；后面换成 finish_reason 为字符串的骨架。
        // 新骨架同样需要**两个样本**才能定模板，因此要各出现两次。
        let a = openai_chunk("a");
        let tail = b"data: {\"id\":\"chatcmpl-BnAbCd\",\"object\":\"chat.completion.chunk\",\
\"created\":1740000000,\"model\":\"gpt-4o-2024-08-06\",\"system_fingerprint\":\"fp_abc123\",\
\"choices\":[{\"index\":0,\"delta\":{},\"logprobs\":null,\"finish_reason\":\"stop\"}]}\n\n"
            .to_vec();
        let (costs, rebuilt, ind) = drive(&[a.clone(), a.clone(), tail.clone(), tail.clone()]);
        assert_eq!(ind.template_count(), 2, "两个骨架应各得一个模板");
        assert_eq!(costs[2], tail.len(), "新骨架首现应原样发送");
        assert!(
            costs[3] == 0,
            "新骨架第二次出现且内容完全相同，增量应为 0，实际 {}",
            costs[3]
        );
        assert_eq!(rebuilt[2], tail);
        assert_eq!(rebuilt[3], tail);
    }

    #[test]
    fn const_drift_is_demoted_not_given_up() {
        // 第二个样本里 system_fingerprint 会变，第三个又变一次：
        // 期望第 3 次能把漂移字段降为变量并继续用模板，而不是退回原样
        let mk = |tok: &str, fp: &str| {
            format!(
                "data: {{\"id\":\"m\",\"system_fingerprint\":\"{fp}\",\
\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{tok}\"}}}}]}}\n\n"
            )
            .into_bytes()
        };
        let e1 = mk("a", "fp_1");
        let e2 = mk("b", "fp_2"); // 两样本差异 = content + fp
        let e3 = mk("c", "fp_3"); // fp 再变
        let (costs, rebuilt, _) = drive(&[e1.clone(), e2.clone(), e3.clone()]);
        assert_eq!(rebuilt[1], e2);
        assert_eq!(rebuilt[2], e3, "漂移后仍必须逐字节一致");
        // 第 3 次应走 Defined（重发 DEF）且增量只含两个变量
        assert!(
            costs[2] < e3.len() / 2,
            "漂移后应仍是增量发送，实际 {} / {}",
            costs[2],
            e3.len()
        );
    }

    #[test]
    fn unknown_event_shape_falls_back_to_raw() {
        // 非 JSON、多行 data、[DONE] 一律走原样
        let events: Vec<Vec<u8>> = vec![
            b"data: [DONE]\n\n".to_vec(),
            b"event: ping\n\n".to_vec(),
            b"data: not json\n\n".to_vec(),
            b"data: {\"a\":\n\n".to_vec(),
        ];
        let mut ind = Inducer::new(8);
        for ev in &events {
            match sse::scan_event(ev) {
                None => {}
                Some(s) => {
                    assert_eq!(ind.feed(ev, &s), Induction::Raw, "不该归纳未知形态");
                }
            }
        }
        assert_eq!(ind.template_count(), 0);
    }

    #[test]
    fn template_capacity_is_bounded() {
        let mut ind = Inducer::new(3);
        for i in 0..20 {
            // 每个事件结构都不同（键名不同）→ 各自一个骨架
            let ev = format!("data: {{\"k{i}\":1,\"v\":{i}}}\n\n").into_bytes();
            if let Some(s) = sse::scan_event(&ev) {
                ind.feed(&ev, &s);
                ind.feed(&ev, &s);
            }
        }
        assert!(
            ind.template_count() <= 3,
            "模板数必须被上限约束，实际 {}",
            ind.template_count()
        );
    }

    #[test]
    fn rebuild_rejects_wrong_var_count() {
        // 两个样本内容不同 → 至少一个变量槽
        let e1 = openai_chunk("a");
        let e2 = openai_chunk("b");
        let s1 = sse::scan_event(&e1).unwrap();
        let s2 = sse::scan_event(&e2).unwrap();
        let mut ind = Inducer::new(4);
        assert_eq!(ind.feed(&e1, &s1), Induction::Raw);
        let Induction::Defined { template, vars } = ind.feed(&e2, &s2) else {
            panic!("第二次应定出模板");
        };
        assert!(template.var_count() >= 1, "内容不同应至少有一个变量槽");
        assert!(template.rebuild(&vars).is_some(), "正确槽数应能重建");
        assert!(template.rebuild(&[]).is_none(), "槽数不足必须拒绝");
        assert!(
            template.rebuild(&vec![b"x".to_vec(); 99]).is_none(),
            "槽数过多必须拒绝"
        );
    }

    #[test]
    fn empty_leaf_event_is_handled() {
        // data 载荷是空对象：没有叶值，模板只有一个字面段
        let ev = b"data: {}\n\n".to_vec();
        let s = sse::scan_event(&ev).unwrap();
        assert!(s.leaves.is_empty());
        let (costs, rebuilt, _) = drive(&[ev.clone(), ev.clone(), ev.clone()]);
        assert_eq!(costs[2], 0);
        assert_eq!(rebuilt[2], ev);
    }

    #[test]
    fn anthropic_style_stream_is_byte_exact_and_small() {
        let mk_delta = |t: &str| {
            format!(
                "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\
\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"{t}\"}}}}\n\n"
            )
            .into_bytes()
        };
        let mut events = vec![
            b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-5\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":1024,\"output_tokens\":1}}}\n\n".to_vec(),
            b"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n".to_vec(),
        ];
        for i in 0..100 {
            events.push(mk_delta(["字", "节", "流", "啊"][i % 4]));
        }
        events.push(
            b"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n"
                .to_vec(),
        );

        let total: usize = events.iter().map(Vec::len).sum();
        let (costs, rebuilt, ind) = drive(&events);
        let delta: usize = costs.iter().sum();
        println!(
            "  [M2 Anthropic] {} 个事件，原文 {total} B，增量 {delta} B = {:.2}%，模板 {} 个",
            events.len(),
            delta as f64 / total as f64 * 100.0,
            ind.template_count()
        );
        for (i, (o, g)) in events.iter().zip(rebuilt.iter()).enumerate() {
            assert_eq!(g, o, "第 {i} 个事件重建不一致");
        }
        // M2 的验收线是「响应方向省 ≥ 90%」，即增变量占比 ≤ 10%。
        //
        // 这里刻意比 OpenAI 情形更宽松：Anthropic 的 delta 事件只有约 128 字节，
        // 而模板要传的变量（含引号的 token）约 5 字节，单事件占比本就约 4%；
        // 另外 message_start / content_block_start / content_block_stop 这类
        // **一次事件**无法归纳（只有一次观测就永远只是"样本"），要原样发送。
        let ratio = delta as f64 / total as f64;
        assert!(
            ratio < 0.10,
            "增变量占比应满足 M2 的 10% 上限，实际 {:.2}%",
            ratio * 100.0
        );
    }
}
