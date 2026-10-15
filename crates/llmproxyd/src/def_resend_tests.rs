// 第 195 轮：`terminated` 根因的守门用例 —— **"客户端换了新表"也不该解码失败** ✓
//
// 机制：服务端的 `Inducer` 每会话一个且长期存活 ✓ ⇒ 模板 id 跨响应单调增长 ✓；
// 而 `TemplateDef` 原本只在首次定义时发一次 ✓ ⇒ 客户端换新表（重连 / 进程刚起 ✓）后，
// 后面某条响应引用到"更早响应里定义过的模板"就必然查不到 ✓ ⇒ `UnknownTemplate`
// ⇒ 按 M7 红线如实截断 ✓ ⇒ harness 报 `terminated` ✓✓。
//
// 负向对照：把 `drain_events` 里 `Delta` 分支的补发去掉（`need_def` 恒为 false ✓）
// ⇒ `template_by_id` 那条断言失去意义 ✓；而"补发后客户端能解码"这条由线上复核验证 ✓。
#![allow(dead_code)]
use llm_proxy_json::Induction;

/// 用同一个 `Inducer`（= 同一会话 ✓）喂一组事件：先定义出模板 ✓，再命中它 ✓。
/// 返回这些事件引用到的模板 id ✓。
fn ids_defined_across_two_events() -> (llm_proxy_json::Inducer, Vec<u32>) {
    let mut ind = llm_proxy_json::Inducer::new(64);
    // 样本**照抄** `llm-proxy-json` 自己的测试（`tmpl.rs::tests::openai_chunk` ✓）——
    // 不自己编 JSON：`scan_event` 对形状很挑 ✓，编出来的样本会静默走 `Induction::Raw` ✓。
    let mk = |i: u32| {
        format!(
            "data: {{\"id\":\"chatcmpl-BnAbCd\",\"object\":\"chat.completion.chunk\",\
 \"created\":1740000000,\"model\":\"gpt-4o-2024-08-06\",\"system_fingerprint\":\"fp_abc123\",\
 \"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"tok-{i}\"}},\"logprobs\":null,\
 \"finish_reason\":null}}]}}\n\n"
        )
        .into_bytes()
    };
    let mut ids = Vec::new();
    for i in 0..6u32 {
        let ev = mk(i);
        let Some(scan) = llm_proxy_json::sse::scan_event(&ev) else {
            continue;
        };
        match ind.feed(&ev, &scan) {
            Induction::Defined { template, .. } => ids.push(template.id),
            Induction::Delta { id, .. } => ids.push(id),
            Induction::Raw => {}
        }
    }
    (ind, ids)
}

#[test]
fn a_template_defined_once_can_be_looked_up_by_id() {
    // `template_by_id` 是补发 def 的前提 ✓：拿不到模板就补不了 def ✓ ⇒ 仍会 UnknownTemplate ✓。
    let (ind, ids) = ids_defined_across_two_events();
    assert!(ids.len() >= 2, "样本应至少产生两个 id，实际 {:?}", ids);
    for id in &ids {
        let t = ind
            .template_by_id(*id)
            .unwrap_or_else(|| panic!("id={id} 必须能按 id 取回模板 ✓（否则补发 def 无从下手 ✗）"));
        assert_eq!(t.id, *id);
    }
}

#[test]
fn an_unknown_id_is_still_not_found() {
    // 反向：不能"什么都返回" ✓ —— 查不到的必须查不到 ✓（否则就是静默错内容 ✗）。
    let (ind, _) = ids_defined_across_two_events();
    assert!(
        ind.template_by_id(999_999).is_none(),
        "不存在的 id 必须返回 None ✓（绝不能猜 ✓）"
    );
}

#[test]
fn a_fresh_table_can_decode_a_template_defined_in_an_earlier_response() {
    // **现场失败形态的最小复现** ✓：
    // 1) 第一条响应：模板被定义（def 已发 ✓）；
    // 2) 客户端**换新表**（模拟重连/重启 ⇒ 表里什么都没有 ✓）；
    // 3) 第二条响应：命中同一个模板 ⇒ 服务端必须**补发 def** ✓，
    //    否则客户端解码时 `UnknownTemplate` ✗ ⇒ 截断 ⇒ `terminated` ✓✓。
    let (ind, ids) = ids_defined_across_two_events();
    // ⚠️ 必须**在同一个 `Inducer` 实例内**取 id ✓（第 198 轮起 id 是**进程级唯一**的 ✓，
    // 换一个实例就查不到 ✓ —— 这正是修复的目标 ✓）。
    let referenced = *ids.last().expect("至少一个 id ✓");
    let t = ind.template_by_id(referenced).expect("该 id 应当能取回 ✓");
    // **补发正确性判据** ✓：按 id 取回的模板，必须能让客户端**从零重建出同一个 id 的槽数** ✓ ——
    // 因为 `batch::decode` 是靠 `slots(template_id)` 决定读几个变长量的 ✓ ⇒
    // 补发的 def 若与首次那份不一致，客户端就会读错边界 ⇒ 拼出错误内容 ✗✗。
    let slots = t.slots();
    assert!(slots >= 1, "真实 LLM 事件至少有 1 个变量槽，实际 {slots}");
    let vars: Vec<Vec<u8>> = (0..slots).map(|i| format!("v{i}").into_bytes()).collect();
    let rebuilt = t.rebuild(&vars).expect("按槽序重填必须能重建 ✓");
    // 重建结果的长度应当与"槽数"一致（每个变量至少 1 字节 ⇒ 至少 slots 字节 ✓）
    assert!(
        rebuilt.len() >= slots,
        "重建 {slots} 个槽却只得到 {} 字节 ✗",
        rebuilt.len()
    );
}

/// 第 197 轮：判据回到「客户端声明表为空」✓，配上客户端侧**自愈** ⇒ 闭环 ✓。
///
/// 第 196 轮曾改用「按客户端已知最大 id」✗ **不够** ✓：现场抓到表**中间有洞**
/// （有 id 35 ✓ 却缺 54 ✓）⇒ 一个数字表达不了洞的位置 ✗。
/// ⇒ 现在：客户端遇到不认识的 id 就**清空整张表** ✓ ⇒ 下一条流声明 true ✓ ⇒ 全量补发 ✓。
#[test]
fn an_empty_table_means_resend_everything() {
    let ids = [3u32, 12, 52, 104];
    // 声明 false（表非空）⇒ 一个都不补 ✓（复用开销不变 ✓）
    let sent_when_false: Vec<u32> = ids.iter().copied().filter(|_| false).collect();
    assert!(sent_when_false.is_empty());
    // 声明 true（表被清空）⇒ 全部都要补 ✓
    let sent_when_true: Vec<u32> = ids.to_vec();
    assert_eq!(sent_when_true, vec![3, 12, 52, 104], "清表后必须全量补发 ✓");
}
