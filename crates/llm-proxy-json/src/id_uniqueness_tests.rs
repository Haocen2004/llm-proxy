// 第 198 轮：模板 id **进程级唯一**的守门用例 ✓。
//
// # 这条不变量为什么是根治性的
//
// 服务端是**每会话一个 `Inducer`**（`llmproxyd::egress::run_session` 里 `Inducer::new` ✓）。
// 原来 `next_id` 从 1 开始、每个 `Inducer` 一份 ⇒ **每条会话都有自己的 id 空间，全都从 1 开始** ✗
// ⇒ 同一个 id 在不同会话里指向**不同的模板** ✗✗。
//
// 客户端只要出现"多会话共用一张模板表"（并发多个 SDK 请求就会 ✓），两套 id 空间就**互相覆盖** ✓
// ⇒ 现场形态：`template_defs=247` 而 `held=24`、`evicted=0`、`recoveries=0`、
// **表中间有洞**（有 id 35 却缺 54 ✓）⇒ `UnknownTemplate` ⇒ 按 M7 红线截断 ⇒ `terminated` ✗。
//
// ⇒ 改法：`NEXT_TEMPLATE_ID` 进程级单调签发 ✓ ⇒ id 全局唯一 ✓ ⇒ 客户端怎么共用表都不冲突 ✓✓
// ⇒ 这也正是"几十上百个客户端并发连一个服务端"所要求的形态 ✓。
//
// # 负向对照
//
// 把签发改回 `Inducer` 自己的 `next_id`（从 1 开始 ✓）⇒
// `ids_are_unique_across_sessions` 立刻变红 ✓✓（两组 id 会从同一个值开始 ✓）。

use crate::sse;
use crate::tmpl::{Inducer, Induction};

/// 造一个**必定命中同一骨架**的事件（只有 content 变 ⇒ 同 schema ✓）。
fn ev(tok: &str) -> Vec<u8> {
    format!(
        "data: {{\"id\":\"chatcmpl-BnAbCd\",\"object\":\"chat.completion.chunk\",\
\"created\":1740000000,\"model\":\"gpt-4o-2024-08-06\",\"system_fingerprint\":\"fp_abc123\",\
\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{tok}\"}},\"logprobs\":null,\
\"finish_reason\":null}}]}}\n\n"
    )
    .into_bytes()
}

/// 驱动一个 `Inducer`（= 一条会话 ✓）跑若干事件，返回它**签发过的** id ✓。
///
/// ⚠️ 只收 `Defined` 那一次 ✓ —— `Delta` 是对**同一个模板**的重复引用 ✓，
/// 它带的是同一个 id ✓（收进来会让人误以为"同会话内 id 重复" ✗）。
fn drive_session(n: usize) -> Vec<u32> {
    let mut ind = Inducer::new(64);
    let mut ids = Vec::new();
    for i in 0..n {
        let e = ev(&format!("tok-{i}"));
        let Some(scan) = sse::scan_event(&e) else {
            continue;
        };
        if let Induction::Defined { template, .. } = ind.feed(&e, &scan) {
            ids.push(template.id);
        }
    }
    ids
}

#[test]
fn ids_are_unique_across_sessions() {
    // 现场是"同一台客户端上多条会话并发" ✓ ⇒ 这里就开两条会话 ✓，
    // 它们的 id 集合**必须不相交** ✓✓ —— 这正是修复的全部意义 ✓。
    let a = drive_session(6);
    let b = drive_session(6);
    assert!(!a.is_empty() && !b.is_empty(), "两条会话都应归纳出模板 ✓");

    let sa: std::collections::HashSet<u32> = a.iter().copied().collect();
    let sb: std::collections::HashSet<u32> = b.iter().copied().collect();
    let overlap: Vec<u32> = sa.intersection(&sb).copied().collect();
    assert!(
        overlap.is_empty(),
        "两条会话签发了**重叠**的模板 id {overlap:?} ✗ —— 这会让客户端多会话共用表时互相覆盖 ✗\n\
         a={a:?}\n b={b:?}"
    );
    assert_eq!(
        sa.len(),
        a.len(),
        "同一条会话内部也不该出现重复 id ✓（重复会让 `TemplateStore` 覆盖 ✓）"
    );
}

#[test]
fn ids_are_never_zero() {
    // 0 是"原样条目"的保留 tag ✓（`BatchItem::is_raw` 用 `template_id == 0` 判定 ✓）
    // ⇒ 签发出的 id **永远不能是 0** ✓，否则会把一个 delta 当成原样条目 ✗（静默错内容 ✓）。
    let ids = drive_session(8);
    assert!(!ids.is_empty(), "应当归纳出 id ✓");
    assert!(ids.iter().all(|id| *id != 0), "id 绝不能是 0 ✓：{ids:?}");
}

#[test]
fn a_third_session_still_sees_a_disjoint_id_space() {
    // 多开几条（现场是 4 条 ✓，未来可能几十上百 ✓）⇒ 仍然两两不相交 ✓。
    let sets: Vec<std::collections::HashSet<u32>> = (0..4)
        .map(|_| drive_session(5).into_iter().collect())
        .collect();
    for i in 0..sets.len() {
        for j in (i + 1)..sets.len() {
            let inter: Vec<u32> = sets[i].intersection(&sets[j]).copied().collect();
            assert!(
                inter.is_empty(),
                "会话 {i} 与 {j} 的 id 空间重叠了 {inter:?} ✗"
            );
        }
    }
}
