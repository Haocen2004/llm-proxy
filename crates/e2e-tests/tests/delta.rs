//! M1a 验收：增量路径的**端到端**行为。
//!
//! 这组测试的价值在于：M0 的端到端测试要求逐字节一致，一旦增量逻辑出错就立刻失败。
//! 因此这里同时断言「省了流量」与「内容一字不差」——只测其中一个都不够。

mod common;

use common::*;

/// 验收 M1a-1：增量路径确实生效，且**增量请求本身**的上行占比满足 5% 上限；
/// 上下游内容都逐字节一致。
///
/// 度量口径很重要：把「首个全量请求 + 后续增量请求」加在一起算总节省会被首个请求
/// 稀释（实测约 48%），看不出增量路径的真实效果。必须按**增量请求自身**测。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delta_path_saves_traffic_and_stays_byte_exact() {
    guard(async {
        let st = setup().await.expect("启动失败");

        // 两档体量：小会话（约 340 KB）与对齐实测的真实量级（约 2.7 MB）
        for (label, n_msgs, hard) in [
            ("小会话", 200usize, 0.05_f64),
            ("真实量级", 1600usize, 0.01_f64),
        ] {
            let body_a = make_body(n_msgs, 0);
            let body_b = make_body(n_msgs, 2);

            // 首个请求：冷启动，全量
            let e0 = st.echo("/v1/chat/completions", &body_a).await.unwrap();
            assert_eq!(e0, body_a, "{label}：首次回显必须逐字节一致");
            let w0 = st.status().await.unwrap()["req_wire_bytes"]
                .as_u64()
                .unwrap();

            // 第二个请求：只多了两条消息
            let e1 = st.echo("/v1/chat/completions", &body_b).await.unwrap();
            assert_eq!(e1, body_b, "{label}：增量回显必须逐字节一致");
            let v = st.status().await.unwrap();
            let w1 = v["req_wire_bytes"].as_u64().unwrap();

            // 上游侧逐字节比对
            let recs = st.up.rec.take();
            assert_eq!(recs.len(), 2, "{label}：上游应收到 2 次请求");
            assert_eq!(recs[0].body, body_a, "{label}：上游第 1 个 body 不一致");
            assert_eq!(recs[1].body, body_b, "{label}：上游第 2 个 body 不一致");

            let incr = (w1 - w0) as f64 / body_b.len() as f64;
            println!(
                "  [M1a 端到端-{label}] body {} B（+{} B），增量请求实发 {} B = {:.3}%  复用块 {}",
                body_b.len(),
                body_b.len() - body_a.len(),
                w1 - w0,
                incr * 100.0,
                v["ref_blocks"]
            );
            assert!(
                incr <= 0.05,
                "{label}：增量请求占比 {:.3}% 超过 M1a 的 5% 上限",
                incr * 100.0
            );
            assert!(
                incr <= hard,
                "{label}：增量请求占比 {:.3}% 高于该体量的预期上限 {:.1}%",
                incr * 100.0,
                hard * 100.0
            );
        }

        let v = st.status().await.unwrap();
        assert_eq!(
            v["delta_fallbacks"].as_u64().unwrap(),
            0,
            "不该发生降级：{v}"
        );
        assert!(v["ref_blocks"].as_u64().unwrap() > 0, "必须复用了块：{v}");
    })
    .await;
}

/// 验收 M1a-2：关闭增量时仍逐字节一致，且状态端点如实反映没有走增量。
///
/// 这条同时是**对照实验**：若它和上一条都通过，说明上面的节省确实来自增量路径，
/// 而不是别的因素。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_path_when_delta_disabled_is_byte_exact() {
    guard(async {
        let st = setup_with(
            &[],
            &[
                "--no-delta".to_string(),
                "--upload-entries".to_string(),
                "10".to_string(),
            ],
        )
        .await
        .expect("启动失败");

        let body = make_body(120, 0);
        for _ in 0..2 {
            let echoed = st.echo("/v1/chat/completions", &body).await.unwrap();
            assert_eq!(echoed, body, "原样路径必须逐字节一致");
            let r = &st.up.rec.take()[0];
            assert_eq!(r.body, body);
        }

        let v = st.status().await.unwrap();
        assert_eq!(v["delta_enabled"], false);
        assert_eq!(v["delta_requests"].as_u64().unwrap(), 0, "不应走增量：{v}");
        assert_eq!(
            v["req_wire_bytes"].as_u64().unwrap(),
            v["req_raw_bytes"].as_u64().unwrap(),
            "原样路径下实发应等于原始字节"
        );
    })
    .await;
}

/// 验收 M1a-3：服务端块存储被淘汰后，必须**精确遗忘缺块并重试增量**恢复，
/// 而不是直接降级为全量，更不允许产出错误内容。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovers_from_server_side_block_eviction() {
    guard(async {
        // 预算远小于单次请求的块总量，逼出 LRU 淘汰
        let st = setup_with(
            &["--block-cache-bytes".to_string(), "150000".to_string()],
            &[],
        )
        .await
        .expect("启动失败");

        let body = make_body(200, 0);
        assert!(body.len() > 250_000, "负载需明显大于服务端预算");

        // 第一次：客户端全量发块，服务端只能留住一部分
        let e1 = st.echo("/v1/chat/completions", &body).await.unwrap();
        assert_eq!(e1, body, "首次必须逐字节一致");
        st.up.rec.take();

        // 第二次：客户端以为块都在，会发 REF；服务端应当报缺块
        let e2 = st.echo("/v1/chat/completions", &body).await.unwrap();
        assert_eq!(e2, body, "缺块恢复后仍必须逐字节一致");
        let r = &st.up.rec.take()[0];
        assert_eq!(r.body, body, "上游收到的 body 必须逐字节一致");

        let v = st.status().await.unwrap();
        assert!(
            v["forgotten_blocks"].as_u64().unwrap() > 0,
            "应发生过精确遗忘：{v}"
        );
        assert_eq!(
            v["delta_fallbacks"].as_u64().unwrap(),
            0,
            "缺块应通过重试增量恢复，而不是降级为全量：{v}"
        );
    })
    .await;
}

/// 验收 M1a-4：超过缓冲上限的请求体必须走流式原样，不得缓冲、不得分解。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_body_bypasses_delta() {
    guard(async {
        let st = setup_with(
            &[],
            &["--max-decompose-bytes".to_string(), "4096".to_string()],
        )
        .await
        .expect("启动失败");

        let body = make_body(60, 0);
        assert!(body.len() > 4096);

        let echoed = st.echo("/v1/chat/completions", &body).await.unwrap();
        assert_eq!(echoed, body, "超限时应原样转发且逐字节一致");

        let v = st.status().await.unwrap();
        assert_eq!(
            v["delta_requests"].as_u64().unwrap(),
            0,
            "超过上限不得走增量：{v}"
        );
    })
    .await;
}

/// 验收 M1a-5：SSE 响应经增量请求路径后仍逐字节一致、仍然流式。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_response_is_intact_over_delta_request() {
    guard(async {
        let st = setup().await.expect("启动失败");

        // 先热一次，让后续请求走增量
        let warm = make_body(150, 0);
        st.echo("/v1/chat/completions", &warm).await.unwrap();
        st.up.rec.take();

        let body = make_body(150, 1);
        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/messages",
            &[("content-type", "application/json"), ("x-test-mode", "sse")],
            &body,
        )
        .await
        .expect("SSE 请求失败");

        assert_eq!(resp.status, 200);
        let count = st.up.rec.len();
        assert_eq!(count, 1, "上游应收到请求");
        let r = &st.up.rec.take()[0];
        assert_eq!(r.body, body, "增量路径下上游收到的 body 仍须逐字节一致");

        let expect = st.up.sse_bytes.lock().unwrap().clone();
        assert!(!expect.is_empty());
        assert_eq!(resp.body, expect, "SSE 字节必须与上游产出逐字节一致");
        assert!(
            resp.chunk_times.len() >= 4,
            "增量请求路径不得影响响应侧的流式转发，实际观测 {} 片",
            resp.chunk_times.len()
        );

        let v = st.status().await.unwrap();
        // 首个请求是冷启动，现在会走整段压缩（ENC_ZSTD）而不是全 literal 的 TokenStream；
        // 服务端在压缩路径上会解压后切块入库，所以**第二个请求仍应走增量并复用块**。
        // 这里断言真正重要的性质，而不是某个固定的计数。
        assert!(
            v["ref_blocks"].as_u64().unwrap() > 0,
            "冷启动之后的请求必须复用块（否则冷启动改走压缩就白改了）：{v}"
        );
        assert!(
            v["delta_requests"].as_u64().unwrap() >= 1,
            "至少有一个请求走了增量路径：{v}"
        );
    })
    .await;
}

/// 冷启动路径：整段 body 压缩发送，服务端解压后切块入库，
/// 于是**下一个请求就能走增量**——这次改道不能让后续请求退回冷启动。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_request_is_compressed_and_then_becomes_incremental() {
    guard(async {
        let st = setup().await.expect("启动失败");

        // 关键：负载必须**同时**具备两个性质，否则测不出东西——
        //   * 高窗口多样性（`make_body` 用 CJK 池采样保证）→ CDC 能切出设计中的块长；
        //   * 结构上的重复（这里追加一大段重复的工具 schema）→ zstd 有东西可压。
        // 只满足前者则压不动，只满足后者则切不出块。真实 LLM 请求两者都占。
        let schema = r#",{"type":"function","function":{"name":"read_file","description":"读取文件内容并返回指定行范围","parameters":{"type":"object","properties":{"path":{"type":"string"},"start":{"type":"integer"},"end":{"type":"integer"},"encoding":{"type":"string"}}}}}"#;
        let mut tools = String::from(r#""tools":["#);
        for i in 0..120 {
            if i > 0 {
                tools.push(',');
            }
            tools.push_str(schema);
        }
        tools.push(']');

        let base = make_body(400, 0);
        let mut body = base[..base.len() - 1].to_vec(); // 去掉收尾的 `}`
        body.push(b',');
        body.extend_from_slice(tools.as_bytes());
        body.push(b'}');

        // 第一个请求：冷启动
        let e1 = st.echo("/v1/chat/completions", &body).await.unwrap();
        assert_eq!(e1, body, "冷启动回显必须逐字节一致");
        let r = &st.up.rec.take()[0];
        assert_eq!(r.body, body, "上游收到的 body 必须逐字节一致");

        let v1 = st.status().await.unwrap();
        println!(
            "  [压缩路径] 冷启动：原文 {} B → 链路 {} B（压缩请求 {} 次）",
            v1["req_raw_bytes"].as_u64().unwrap(),
            v1["req_wire_bytes"].as_u64().unwrap(),
            v1["compressed_requests"].as_u64().unwrap()
        );
        assert!(
            v1["compressed_requests"].as_u64().unwrap() >= 1,
            "冷启动应走整段压缩：{v1}"
        );
        let cold_wire = v1["req_wire_bytes"].as_u64().unwrap();
        assert!(
            cold_wire < body.len() as u64,
            "压缩后的整段发送应小于原文：{cold_wire} vs {}",
            body.len()
        );

        // 第二个请求：应走增量（服务端在压缩路径上已切块入库）
        let e2 = st.echo("/v1/chat/completions", &body).await.unwrap();
        assert_eq!(e2, body, "第二个请求仍必须逐字节一致");
        let r2 = &st.up.rec.take()[0];
        assert_eq!(r2.body, body);

        let v2 = st.status().await.unwrap();
        let incr = v2["req_wire_bytes"].as_u64().unwrap() - cold_wire;
        println!(
            "  [压缩路径] 第二个请求：实发 {} B = body 的 {:.4}%（复用块 {}）",
            incr,
            incr as f64 / body.len() as f64,
            v2["ref_blocks"]
        );
        assert!(
            incr < cold_wire,
            "压缩入库之后，第二个请求应比冷启动更省：{incr} vs {cold_wire}"
        );
        assert!(
            incr as f64 / body.len() as f64 <= 0.05,
            "第二个请求应满足 5% 增量上限，实际 {:.4}%",
            incr as f64 / body.len() as f64 * 100.0
        );
    })
    .await;
}
