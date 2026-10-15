//! M0 验收：四协议经代理后与直连**逐字节一致**。
//!
//! 链路：原始 HTTP 客户端 → llmproxyc（ingress）→ WS/DSHP → llmproxyd（egress）→ mock 上游
//!
//! 注意：需要先 `cargo build`。端到端测试启动的是真实二进制，不是进程内调用。

mod common;

use common::*;

/// 验收 1：四协议路径 + query 原样透传，上行与下行都逐字节一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn four_protocols_byte_exact() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let up = &st.up;

        let paths = [
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/responses",
            r#"/v1/messages?beta=true"#,
        ];

        for path in paths {
            let body = format!(r#"{{"model":"m","stream":false,"marker":"{path}"}}"#);
            let resp = raw_request(
                &st.client,
                "POST",
                path,
                &[
                    ("content-type", "application/json"),
                    ("x-test-mode", "plain"),
                    ("authorization", "Bearer sk-test-abcdef"),
                    ("anthropic-version", "2023-06-01"),
                ],
                body.as_bytes(),
            )
            .await
            .unwrap_or_else(|e| panic!("{path} 请求失败: {e}"));

            // ---- 上游侧：方法 / path+query / header / body 全部逐字节一致 ----
            let recs = up.rec.take();
            assert_eq!(recs.len(), 1, "{path}: 上游应恰好收到 1 次请求");
            let r = &recs[0];
            assert_eq!(r.method, "POST", "{path}: 方法不一致");
            assert_eq!(
                r.path_and_query, path,
                "{path}: path 与 query 必须原样透传（设计 §4.1）"
            );
            assert_eq!(
                r.body,
                body.as_bytes(),
                "{path}: 上游收到的请求体与发出者不一致"
            );
            assert_eq!(
                header_of(r, "authorization"),
                "Bearer sk-test-abcdef",
                "{path}: 认证头未原样透传"
            );
            assert_eq!(header_of(r, "anthropic-version"), "2023-06-01");
            assert_eq!(header_of(r, "content-type"), "application/json");

            // ---- 下行侧：状态码 / header / body ----
            assert_eq!(resp.status, 200, "{path}: 状态码不一致");
            assert_eq!(
                resp.body, br#"{"ok":true,"note":"mock upstream"}"#,
                "{path}: 响应体不一致"
            );
            let h = normalize_headers(&resp.headers);
            assert!(
                h.iter()
                    .any(|(k, v)| k == "content-type" && v == b"application/json"),
                "{path}: 响应 content-type 丢失"
            );
            assert!(
                h.iter()
                    .any(|(k, v)| k == "x-upstream-marker" && v == b"plain-response"),
                "{path}: 上游自定义响应头丢失"
            );
        }
    })
    .await;
}

/// 验收 2：SSE 逐段转发，且字节与上游产出完全一致（不允许被缓冲或改写）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_is_byte_exact_and_incremental() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let up = &st.up;

        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/messages",
            &[("content-type", "application/json"), ("x-test-mode", "sse")],
            br#"{"stream":true}"#,
        )
        .await
        .expect("SSE 请求失败");

        assert_eq!(resp.status, 200);
        assert_eq!(
            header_of(&up.rec.take()[0], "x-test-mode"),
            "sse",
            "测试用的模式头未透传"
        );

        let expect = up.sse_bytes.lock().unwrap().clone();
        assert!(!expect.is_empty());
        assert_eq!(
            resp.body, expect,
            "SSE 字节必须与上游产出逐字节一致（含 event:/data: 行与空行分隔）"
        );
    })
    .await;
}

/// 验收 2b：**流式转发**——代理不得把响应整段缓冲。
///
/// # 为什么单独用慢速上游
///
/// 这条以前是用快速上游（8 片 × 10ms ≈ 80ms）加「分片数 ≥ 2」来断言的。那是**错的测法**：
/// 分片数取决于传输层的**读取边界**，OS 完全可以把服务端的两次写入合并成一次读取。
/// 于是它会在机器有负载时随机变红——实测就是这样：同一份代码有时过、有时不过，
/// 而失败那次 `passthrough` 整体耗时从 7.9s 涨到 16.8s。
///
/// 换成一个**秒级**的慢速上游后，判据变成时间维度的：缓冲式代理的首字节必须等满全程，
/// 流式代理只等一个批量窗口。2.4s 与 ≤150ms 的差距不会被负载抹平。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_streams_instead_of_buffering() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let up = &st.up;

        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/messages",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "sse-slow"),
            ],
            br#"{"stream":true}"#,
        )
        .await
        .expect("SSE 请求失败");

        assert_eq!(resp.status, 200);
        let expect = up.sse_bytes.lock().unwrap().clone();
        assert_bytes_eq(&resp.body, &expect, "慢速 SSE 也必须逐字节一致");

        let total = resp
            .chunk_times
            .last()
            .map(|t| t.duration_since(resp.start))
            .unwrap_or_default();
        let first = resp
            .chunk_times
            .first()
            .map(|t| t.duration_since(resp.start))
            .unwrap_or_default();
        println!(
            "  [SSE 流式] 首字节 {first:?}，整体 {total:?}，分片数 {}",
            resp.chunk_times.len()
        );

        // 先确认这条测试**没有空过**：上游确实慢，否则断言毫无意义
        assert!(
            total >= std::time::Duration::from_millis(1500),
            "上游应当持续推送 ~2.4s；实际只有 {total:?}，说明这条测试没有测到它想测的东西"
        );
        assert!(
            first < std::time::Duration::from_millis(1000),
            "流式代理的首字节必须很快到达（实测 {first:?}）；\
             若接近 {total:?} 说明响应被整段缓冲了"
        );
    })
    .await;
}

/// 验收 3：非 2xx 状态码与相关 header 原样透传。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_2xx_status_passes_through() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/chat/completions",
            &[("x-test-mode", "status")],
            b"{}",
        )
        .await
        .expect("请求失败");

        assert_eq!(resp.status, 429, "状态码必须原样透传");
        let h = normalize_headers(&resp.headers);
        assert!(
            h.iter().any(|(k, v)| k == "retry-after" && v == b"7"),
            "retry-after 头必须原样透传"
        );
        assert_eq!(resp.body, br#"{"error":{"type":"rate_limit_error"}}"#);
    })
    .await;
}

/// 验收 4：大 body（量级对齐实测真实单请求 3 MB）完整往返。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_body_roundtrip() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let payload = vec![b'x'; 3 * 1024 * 1024];

        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/chat/completions",
            &[("x-test-mode", "echo")],
            &payload,
        )
        .await
        .expect("大 body 请求失败");

        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.len(), payload.len(), "回显长度不一致");
        assert_eq!(resp.body, payload, "大 body 内容不一致");

        let r = &st.up.rec.take()[0];
        assert_eq!(r.body.len(), payload.len(), "上游收到的长度不一致");
        assert_eq!(r.body, payload);
        assert_eq!(
            header_of(r, "content-length"),
            payload.len().to_string(),
            "content-length 必须原样透传"
        );
    })
    .await;
}

/// 验收 5：多路复用——并发请求各自独立、互不串流。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_do_not_cross_streams() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let client = st.client.clone();

        let mut handles = Vec::new();
        for i in 0..8u32 {
            let client = client.clone();
            handles.push(tokio::spawn(async move {
                // 每个请求体不同且够大，串流会立刻暴露为内容错配
                let body = format!(
                    r#"{{"n":{i},"pad":"{}"}}"#,
                    "p".repeat(1024 * (i as usize + 1))
                );
                let resp = raw_request(
                    &client,
                    "POST",
                    "/v1/responses",
                    &[("x-test-mode", "echo")],
                    body.as_bytes(),
                )
                .await
                .expect("并发请求失败");
                (i, body, resp)
            }));
        }

        for h in handles {
            let (i, body, resp) = h.await.expect("任务 panic");
            assert_eq!(resp.status, 200, "请求 {i} 状态码异常");
            assert_eq!(
                resp.body,
                body.as_bytes(),
                "请求 {i} 的回显与自身请求体不匹配（多路复用串流）"
            );
        }
        assert_eq!(st.up.rec.len(), 8, "上游应收到 8 次请求");
    })
    .await;
}

/// 验收 6：管理端点在本地生效，且不会被转发到上游。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn management_endpoint_is_local_only() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let resp = raw_request(&st.client, "GET", "/__dshp/status", &[], b"")
            .await
            .expect("状态请求失败");
        assert_eq!(resp.status, 200);
        let text = String::from_utf8_lossy(&resp.body);
        assert!(text.contains("\"mode\":\"ws\""), "状态输出异常: {text}");
        assert!(st.up.rec.is_empty(), "管理端点不得被转发到上游");
    })
    .await;
}
