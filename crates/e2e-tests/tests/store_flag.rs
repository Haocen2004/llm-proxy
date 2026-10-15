//! **设计决策 12**：`/v1/responses` 的 `store=true` 必须**禁用跨请求前缀复用**。
//!
//! # 背景
//!
//! 决策表第 12 条：「对 `store=true` 的请求禁用跨请求前缀复用，只做单请求内压缩」。
//! 第 60 轮顺着设计 §17.2 的未决项清单查过来时发现它**完全没实现** ✗ —— 全仓库搜
//! `store` 只命中测试内部的 HashMap 与原子 `.store()`。第 61 轮实现，并把事实固定成测试。
//!
//! # 判据
//!
//! 跨请求复用在两端都不靠"基线字节"，靠的是**块指纹 + `REF`**（服务端解引用只需块）。
//! 所以：
//!
//! * **不带** `store` 的重复请求 ⇒ 客户端 `ref_blocks` 必须增长（复用生效）；
//! * **带** `store=true` 的重复请求 ⇒ 客户端 `ref_blocks` **不许增长**（自包含）；
//! * 再发一次普通请求 ⇒ 复用**恢复**（不是把开关永久关掉）；
//! * 四次的回显都必须与发出去的 body **逐字节一致**，且上游收到的也是同样的字节
//!   （自包含 ≠ 变形，这是正确性红线）。
//!
//! 第二个断言是**反空转**：如果复用本来就没生效，"禁用"与否都看不出差别，测试会假绿。

mod common;

use common::*;

/// 同一份 body 连发四次：普通 → 普通（该复用）→ `store=true`（不该复用）→ 普通（该恢复）。
///
/// # 这条测试红了三次，根因全在**夹具**（值得留给后来人）
///
/// 第 61~63 轮的经过：
///
/// 1. 第一次：`store` 被插进了 `make_body` 生成的 **JSON 数组的第一条消息内部** ✗
///    ⇒ 顶层没有 `store` ⇒ 判定说"不复用"是对的，测试判据写歪了；
/// 2. 第二次：改用字符串拼接，**转义错了** ✗ ⇒ 发出去的是 `{"\"store\":true,…}`
///    这种**坏 JSON** ⇒ 判定同样正确地返回 false；
/// 3. 第三次：给客户端加了**直接观测**（状态里的 `last_delta_head` = 进入判定时的
///    body 前 32 字节）⇒ 一眼看到坏 JSON ⇒ 换成 `serde_json` 拼装 + **夹具自检**
///    （断言拼出来的确实是合法 JSON 且顶层 `store=true`）⇒ 一次通过 ✓。
///
/// 教训：**别靠推理，把输入原样打出来看**。三轮推理都错了，一次观测就定了案。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_true_disables_cross_request_reuse() {
    guard(async {
        let st = setup_with(&[], &[]).await.expect("起链路失败");
        // 四次请求共用同一个外壳，**只有第三次多一个顶层 `store`**——这样"复用"才有可比性。
        //
        // **用 serde_json 拼，不手写转义**：第 61~63 轮这条测试红了三次，根因全是夹具
        // 自己把引号转义错了（最后是"直接观测进入判定的 body 前 32 字节"才看清：
        // 发出去的是 `{"\"store\":true,...}` 这种**坏 JSON** ⇒ 判定正确地返回了 false
        // ⇒ 是夹具错、不是实现错）。手写转义的夹具不值得再写第二遍。
        let inner: serde_json::Value =
            serde_json::from_slice(&make_body(24, 2)).expect("make_body 必须是合法 JSON");
        let body = serde_json::json!({ "messages": inner.clone() })
            .to_string()
            .into_bytes();
        let with_store = serde_json::json!({ "store": true, "messages": inner })
            .to_string()
            .into_bytes();
        // 夹具自检：`with_store` 必须是合法 JSON 且顶层确实是 store=true，
        // 否则这条测试又会变成"在测一个坏夹具"。
        let parsed: serde_json::Value =
            serde_json::from_slice(&with_store).expect("夹具本身必须是合法 JSON");
        assert_eq!(
            parsed["store"],
            serde_json::json!(true),
            "夹具顶层 store 必须是 true"
        );

        let refs = |v: &serde_json::Value| v["ref_blocks"].as_u64().unwrap_or(0);

        // ① 首次：冷启动，谈不上复用
        let e1 = st.echo("/v1/responses", &body).await.expect("首次请求失败");
        assert_bytes_eq(&e1, &body, "首次回显");
        let refs1 = refs(&st.status().await.unwrap());
        println!("  [store 决策12] ① 首次 ref_blocks={refs1}");

        // ② 同样的 body ⇒ **应当**复用（反空转基线）
        let e2 = st.echo("/v1/responses", &body).await.expect("二次请求失败");
        assert_bytes_eq(&e2, &body, "二次回显");
        let refs2 = refs(&st.status().await.unwrap());
        assert!(
            refs2 > refs1,
            "第二次相同请求必须复用块（ref_blocks {refs1} → {refs2}）——\
             这条不成立就说明复用本来没生效，后面的「禁用」判不出任何东西"
        );

        // ③ 同样的 body + `store=true` ⇒ **不许**复用
        let e3 = st
            .echo("/v1/responses", &with_store)
            .await
            .expect("store=true 请求失败");
        assert_bytes_eq(&e3, &with_store, "store=true 的回显（自包含 ≠ 变形）");

        // 上游看到的也必须是同一份字节（不是"回显对了、上游收到别的"）
        let recs = st.up.rec.take();
        let last = recs.last().expect("上游应当收到请求");
        assert_bytes_eq(
            &last.body,
            &with_store,
            "上游收到的 body（store=true 那一次）",
        );

        let s3v = st.status().await.unwrap();
        println!(
            "  [store 决策12] ③ 诊断：store_no_cross={} ｜ 进入判定时的 body 前 32 字节={:?}",
            s3v["store_no_cross"], s3v["last_delta_head"]
        );
        let refs3 = refs(&s3v);
        println!("  [store 决策12] ③ store=true ref_blocks={refs2} → {refs3}（必须不增长）");
        assert_eq!(
            refs3, refs2,
            "设计决策 12：store=true 的请求**不得**复用历史请求留下的块\
             （ref_blocks 从 {refs2} 涨到了 {refs3}）"
        );

        // ④ 再发普通请求：复用必须恢复
        let e4 = st.echo("/v1/responses", &body).await.expect("四次请求失败");
        assert_bytes_eq(&e4, &body, "四次回显");
        let refs4 = refs(&st.status().await.unwrap());
        println!("  [store 决策12] ④ 恢复普通请求 ref_blocks={refs3} → {refs4}");
        assert!(
            refs4 > refs3,
            "store=true 只应影响**那一次**请求：之后的普通请求必须恢复复用（{refs3} → {refs4}）"
        );
    })
    .await;
}
