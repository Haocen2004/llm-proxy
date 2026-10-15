//! §12 资源预算的**可执行验收**。
//!
//! 设计把下面这些列为"硬约束"，但硬约束如果只写在文档里，就会在实现漂移时静默失效。
//! 本文件存在的理由：把每一条变成会红的断言。
//!
//! # 并发流上限：一个差点做错的约束
//!
//! `MAX_CONCURRENT_STREAMS` 曾经**只是一个从未被读过的常量**——声明了不执行等于没有防护。
//!
//! 但补上执行时，第一版做成了"超限就拒绝"。那是错的：客户端正常并发（SDK 很容易同时
//! 发 8 个请求）会被变成一堆 502——**把内存保护做成了功能故障**。正确的语义是
//! **背压**：排队等待，只有等待超时才拒绝（那才是真的 DoS）。
//!
//! 相应地，断言也不能是"被拒了几个"——那会把正确的排队判成失败。要守的性质是
//! **上游侧同时在进行的请求数不超过上限**，因为内存正是被这些请求占住的。
//!
//! **第 112 轮起这条性质在全局成立** ✓：信号量原先建在 `run_session` 里 ⇒ 只对**单连接**成立 ✗
//! （两个客户端就能把上游并发推到 8 ✗）。现在它是 `App.slots`（**进程级** ✓）⇒ 单连接与多连接
//! 都 ≤ `MAX_CONCURRENT_STREAMS` ✓。本文件测的仍是单连接这一面 ✓；**多客户端那一面**由
//! `multi_client.rs::the_stream_limit_is_global_and_is_actually_reached` 守（断言"不超上限
//! **且必须达到上限**" ✓）。

mod common;

use common::*;

/// 并发超过上限时应当**排队**，而不是让合法的并发请求失败。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn excess_concurrency_is_backpressured_not_rejected() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let body = make_body(10, 0);
        let limit = llm_proxy_core::config::MAX_CONCURRENT_STREAMS;

        // 8 个并发请求打向"慢响应"上游（1.5s 才回），必然超过上限
        let mut handles = Vec::new();
        for i in 0..(limit * 2) {
            let client = st.client.clone();
            let b = body.clone();
            handles.push(tokio::spawn(async move {
                let r = raw_request(
                    &client,
                    "POST",
                    "/v1/chat/completions",
                    &[
                        ("content-type", "application/json"),
                        ("x-test-mode", "slow"),
                    ],
                    &b,
                )
                .await;
                (i, r)
            }));
        }

        let mut ok = 0usize;
        for h in handles {
            let (i, r) = h.await.expect("任务 panic");
            let resp = r.unwrap_or_else(|e| panic!("第 {i} 个请求连接失败：{e}"));
            assert_eq!(
                resp.status,
                200,
                "超过上限的并发请求应当排队后成功，而不是被拒：第 {i} 个拿到 {}，body={}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            );
            assert_eq!(resp.body, body, "第 {i} 个请求必须逐字节一致");
            ok += 1;
        }
        assert_eq!(ok, limit * 2, "所有请求都应最终成功");

        let peak = st
            .up
            .max_inflight
            .load(std::sync::atomic::Ordering::Acquire);
        println!(
            "  [并发背压] {} 个并发请求全部成功；上游侧并发峰值 {peak}（上限 {limit}）",
            limit * 2
        );
        assert!(
            peak <= limit,
            "上游侧同时在进行的请求数不得超过 {limit}（实测峰值 {peak}）——\
             这个上限保护的正是内存，排队是它的正确实现方式"
        );
        assert!(peak >= 1, "峰值统计必须真的在工作（否则这条断言毫无意义）");
    })
    .await;
}

/// 一个客户端可以承载明显多于活跃槽位的逻辑请求：请求体在拿到
/// `StreamReady` 前不会发送，20 个并发请求应全部排队完成，且上游峰值仍受控。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn twenty_logical_requests_are_admitted_with_bounded_upstream_parallelism() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let n = 20usize;
        let limit = llm_proxy_core::config::MAX_CONCURRENT_STREAMS;
        let mut handles = Vec::with_capacity(n);

        for i in 0..n {
            let client = st.client.clone();
            let body = make_body(20 + i, i);
            handles.push(tokio::spawn(async move {
                let response = raw_request(
                    &client,
                    "POST",
                    "/v1/chat/completions",
                    &[
                        ("content-type", "application/json"),
                        ("x-test-mode", "slow"),
                    ],
                    &body,
                )
                .await
                .map_err(|e| format!("请求 {i} 失败：{e}"))?;
                Ok::<_, String>((i, body, response))
            }));
        }

        for handle in handles {
            let (i, body, response) = handle
                .await
                .expect("任务 panic")
                .unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(response.status, 200, "第 {i} 个请求不应被拒绝");
            assert_eq!(response.body, body, "第 {i} 个请求响应不得串流");
        }

        let peak = st
            .up
            .max_inflight
            .load(std::sync::atomic::Ordering::Acquire);
        assert!(
            peak <= limit,
            "20 个逻辑请求的上游峰值 {peak} 超过上限 {limit}"
        );
        assert!(peak >= 1, "上游峰值统计必须记录到实际请求");

        let diag = st.server_diag().await.expect("读取服务端诊断失败");
        assert_eq!(diag["dropped_frames"].as_u64(), Some(0), "准入屏障不应丢帧");
    })
    .await;
}

/// 等待队列是有界的：活跃额度和等待额度都占满后，后续逻辑请求应快速收到
/// `TOO_MANY_STREAMS`，而不是无限创建任务。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_admission_is_bounded() {
    guard(async {
        let st = setup_with(
            &[
                "--max-concurrent-streams".into(),
                "4".into(),
                "--max-pending-streams".into(),
                "2".into(),
                "--stream-wait-ms".into(),
                "5000".into(),
            ],
            &[],
        )
        .await
        .expect("启动失败");

        let mut handles = Vec::new();
        for i in 0..10usize {
            let client = st.client.clone();
            let body = make_body(8 + i, i);
            handles.push(tokio::spawn(async move {
                raw_request(
                    &client,
                    "POST",
                    "/v1/chat/completions",
                    &[
                        ("content-type", "application/json"),
                        ("x-test-mode", "slow"),
                    ],
                    &body,
                )
                .await
            }));
        }

        let mut succeeded = 0usize;
        let mut rejected = 0usize;
        for handle in handles {
            let response = handle.await.expect("任务 panic").expect("客户端请求失败");
            match response.status {
                200 => succeeded += 1,
                429 | 502 | 503 => {
                    let text = String::from_utf8_lossy(&response.body);
                    assert!(
                        text.contains("等待队列") || text.contains("并发流超限"),
                        "拒绝响应应说明准入原因，实际：{text}"
                    );
                    rejected += 1;
                }
                status => panic!(
                    "意外状态码 {status}：{}",
                    String::from_utf8_lossy(&response.body)
                ),
            }
        }

        assert!(succeeded >= 1, "活跃额度内的请求必须成功");
        assert!(rejected >= 1, "准入队列满后必须拒绝后续请求");
    })
    .await;
}

/// 等待超时后必须**拒绝**——否则"背压"就成了无上限的排队，也就没有 DoS 防护了。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn waiting_too_long_is_rejected() {
    guard(async {
        // 等待时限压到 300ms，而上游要 1.5s 才回 → 超限的那些必然等不到槽位
        let st = setup_with(&["--stream-wait-ms".into(), "300".into()], &[])
            .await
            .expect("启动失败");
        let body = make_body(10, 0);
        let limit = llm_proxy_core::config::MAX_CONCURRENT_STREAMS;

        let mut handles = Vec::new();
        for i in 0..(limit * 2) {
            let client = st.client.clone();
            let b = body.clone();
            handles.push(tokio::spawn(async move {
                raw_request(
                    &client,
                    "POST",
                    "/v1/chat/completions",
                    &[
                        ("content-type", "application/json"),
                        ("x-test-mode", "slow"),
                    ],
                    &b,
                )
                .await
                .map_or_else(|e| (i, Err(e)), |r| (i, Ok(r)))
            }));
        }

        let mut ok = 0usize;
        let mut rejected = 0usize;
        for h in handles {
            let (i, r) = h.await.expect("任务 panic");
            let resp = r.unwrap_or_else(|e| panic!("第 {i} 个请求连接失败：{e}"));
            if resp.status == 200 {
                assert_eq!(resp.body, body);
                ok += 1;
            } else {
                let msg = String::from_utf8_lossy(&resp.body).into_owned();
                assert!(
                    msg.contains("并发流超限"),
                    "非 200 的响应应当明确说明是并发超限，实际：{msg}"
                );
                rejected += 1;
            }
        }
        println!("  [并发超时] 成功 {ok}，因等待超时被拒 {rejected}（上限 {limit}）");
        assert!(
            rejected >= 1,
            "等待超时后必须拒绝，否则排队无上限，DoS 防护失效"
        );
        assert!(ok >= 1, "槽位之内的请求必须正常服务——只拒不放同样是错的");
    })
    .await;
}

/// 上限之内的并发必须**无串流**且逐字节一致（回归）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_within_limit_all_succeed() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let n = llm_proxy_core::config::MAX_CONCURRENT_STREAMS;

        let mut handles = Vec::new();
        for i in 0..n {
            let client = st.client.clone();
            let b = make_body(12 + i, 0);
            handles.push(tokio::spawn(async move {
                let r = raw_request(
                    &client,
                    "POST",
                    "/v1/chat/completions",
                    &[
                        ("content-type", "application/json"),
                        ("x-test-mode", "slow"),
                    ],
                    &b,
                )
                .await
                .expect("请求失败");
                (b, r)
            }));
        }

        let mut seen = Vec::new();
        for h in handles {
            let (sent, resp) = h.await.expect("任务 panic");
            assert_eq!(resp.status, 200, "上限之内的请求不应被拒");
            assert_eq!(resp.body, sent, "并发请求不得互相串流");
            seen.push(resp.body);
        }
        assert_eq!(seen.len(), n);

        let recs = st.up.rec.take();
        assert_eq!(recs.len(), n, "上游应收到 {n} 次请求");
        for r in recs {
            assert!(
                seen.contains(&r.body),
                "上游收到的 body 与任何一次发送都不匹配——疑似串流"
            );
        }
    })
    .await;
}
