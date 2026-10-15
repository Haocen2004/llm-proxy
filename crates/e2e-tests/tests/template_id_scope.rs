//! **模板 id 在进程内全局唯一**（第 200 轮）—— 端到端守门人。
//!
//! # 为什么需要端到端版本
//!
//! `llm-proxy-json::id_uniqueness_tests` 已经在**单元层**钉住了"两个 `Inducer` 的 id 不相交"，
//! 但现场那次的形态是**端到端**的：同一个客户端上**多条会话并发**（现场原话「本地 4 条会话
//! 同时在跑」），而服务端的 `Inducer` 是**每会话一个** ⇒ 每条会话都从 id 1 开始 ⇒
//! 同一个 id 在不同会话里指向**不同的模板** ⇒ 客户端只要出现「多会话共用一张模板表」
//! 就互相覆盖 ⇒ 表出洞 ⇒ `UnknownTemplate` ⇒ 按 M7 红线如实截断 ⇒ **`terminated`**。
//!
//! 所以这里用**两条真实会话**（两个独立客户端指向同一服务端）跑一遍，
//! 断言两件事：
//!
//! 1. 两边都**不截断**（`truncated_responses == 0`、`template_miss == 0`）；
//! 2. 两边的**模板 id 区间不相交** —— 这是「进程级唯一签发」的直接后果，也是根因的反面。
//!
//! **负向对照**：把 `NEXT_TEMPLATE_ID` 改回「每个 `Inducer` 自己的 `next_id`」（从 1 开始）
//! ⇒ 两条会话的区间都会从 1 开始 ⇒ 第 2 条断言立刻变红。

mod common;

use common::*;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn template_ids_are_unique_across_sessions_end_to_end() {
    guard(async {
        // 一个服务端；**两个独立客户端**指向它 —— 这就是"两条会话"。
        let up = MockUpstream::start().await;
        let dport = free_port().await;
        let dargs: Vec<String> = vec![
            "--listen".into(),
            format!("127.0.0.1:{dport}"),
            "--upstream".into(),
            up.base_url(),
        ];
        let drefs: Vec<&str> = dargs.iter().map(String::as_str).collect();
        let _d = spawn_proxy("llmproxyd", &drefs, true).expect("服务端启动失败");
        assert!(
            wait_ready(&format!("127.0.0.1:{dport}"), Duration::from_secs(8)).await,
            "llmproxyd 未就绪"
        );

        let mut clients = Vec::new();
        for _ in 0..2 {
            let cport = free_port().await;
            let cargs: Vec<String> = vec![
                "--listen".into(),
                format!("127.0.0.1:{cport}"),
                "--server".into(),
                format!("ws://127.0.0.1:{dport}"),
                "--upstream-fallback".into(),
                up.base_url(),
            ];
            let crefs: Vec<&str> = cargs.iter().map(String::as_str).collect();
            let c = spawn_proxy("llmproxyc", &crefs, false).expect("客户端启动失败");
            let addr = format!("127.0.0.1:{cport}");
            assert!(
                wait_ready(&addr, Duration::from_secs(8)).await,
                "客户端未就绪"
            );
            clients.push((c, addr));
        }

        // 两边发**同一个** body（同骨架 ⇒ 两边各自都会归纳出模板 ⇒ 各自签发 id）。
        let body = make_body(12, 0);
        let mut spans: Vec<(u64, u64)> = Vec::new();
        for (_, addr) in &clients {
            let r = raw_request(
                addr,
                "POST",
                "/v1/messages",
                &[
                    ("content-type", "application/json"),
                    ("x-test-mode", "sse-many"),
                ],
                &body,
            )
            .await
            .expect("请求失败");
            assert_eq!(r.status, 200, "请求必须成功");

            let st = raw_request(addr, "GET", "/__dshp/status", &[], b"")
                .await
                .expect("status 请求失败");
            let v: serde_json::Value =
                serde_json::from_slice(&st.body).expect("status 不是合法 JSON");

            // 判据 1：不得截断，也不得出现模板缺失（现场就是这两条同时涨）。
            assert_eq!(
                v["truncated_responses"].as_u64().unwrap(),
                0,
                "响应被截断 ⇒ harness 会报 terminated：{v}"
            );
            assert_eq!(
                v["template_miss"].as_u64().unwrap(),
                0,
                "出现模板缺失（UnknownTemplate）：{v}"
            );

            let lo = v["template_ids"]["min"].as_u64().unwrap();
            let hi = v["template_ids"]["max"].as_u64().unwrap();
            assert!(hi > 0, "本会话应当归纳出至少一个模板：{v}");
            spans.push((lo, hi));
        }

        // 判据 2：**两条会话的 id 区间不相交**。
        let (a_lo, a_hi) = spans[0];
        let (b_lo, b_hi) = spans[1];
        assert!(
            a_hi < b_lo || b_hi < a_lo,
            "两条会话的模板 id 区间重叠：A=[{a_lo},{a_hi}] B=[{b_lo},{b_hi}]\n\
             ⇒ 同一个 id 在不同会话里指向不同模板 ⇒ 客户端多会话共用表时互相覆盖\n\
             ⇒ 表出洞 ⇒ UnknownTemplate ⇒ 如实截断 ⇒ terminated（现场就是这个）"
        );
        println!(
            "  [id 唯一] 会话 A=[{a_lo},{a_hi}] 会话 B=[{b_lo},{b_hi}] 不相交，且两边均未截断"
        );
    })
    .await;
}
