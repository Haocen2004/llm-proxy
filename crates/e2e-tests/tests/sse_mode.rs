//! M3 验收：**禁用 WS 时自动落 SSE 且功能完整**。
//!
//! # 这条测试守的是什么
//!
//! M3 的验收原文是「禁用 UDP/WS 时自动落 SSE 且功能完整」。它对应一个非常真实的
//! 部署场景：**企业代理放通 POST、拦掉 WebSocket 的 `Upgrade` 头**。
//! 没有这一档时，WS 一被拦客户端就直接掉到 L2 直连——功能还在，但增量、模板、
//! 压缩带来的收益全部丢失。
//!
//! 所以这里不能只断言"连上了"，必须断言**走 SSE 时四条协议仍逐字节一致、
//! SSE 响应仍逐片到达、增量复用仍在生效**。只验证连通性是不够的：
//! 一条能连上但语义退化的路径，比没有它更糟——因为它看起来"在工作"。

mod common;

use common::*;

/// 用 `--force-mode sse` 起链路的夹具。
///
/// 为什么要强制而不是"去拦 WS"：降级链是"能用就用好的"，而**验收需要能确定性地
/// 测到每一档**。靠外部手段拦 WebSocket 既脆弱又测不准，还会让失败的归因变模糊。
async fn setup_sse() -> anyhow::Result<Stack> {
    setup_with(&[], &["--force-mode".into(), "sse".into()]).await
}

/// SSE 模式下四条协议都必须逐字节一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_mode_serves_all_protocols_byte_exact() {
    guard(async {
        let st = setup_sse().await.expect("SSE 模式启动失败");
        let body = make_body(40, 2);

        let v = st.status().await.unwrap();
        println!(
            "  [SSE 模式] mode={} link_alive={} aead={}",
            v["mode"], v["link_alive"], v["aead"]["enabled"]
        );
        assert_eq!(v["mode"], "sse", "应走 SSE 隧道：{v}");
        assert_eq!(v["link_alive"], true, "链路必须是活的：{v}");
        assert_eq!(
            v["aead"]["enabled"], true,
            "SSE 隧道上同样必须建立加密会话——传输方式变了，安全强度不能变：{v}"
        );

        for path in [
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/messages",
            "/v1/responses",
        ] {
            let echoed = st.echo(path, &body).await.unwrap();
            assert_eq!(echoed, body, "{path} 在 SSE 模式上必须逐字节一致");
        }

        // 四次请求都要真的经过隧道（而不是悄悄落到直连）
        let v2 = st.status().await.unwrap();
        assert_eq!(v2["mode"], "sse", "请求过程中不应掉到其它模式：{v2}");
        assert_eq!(v2["bypass_requests"], 0, "不应有任何请求走直连：{v2}");
    })
    .await;
}

/// SSE 模式下，**响应方向的 SSE 流式时序**不能被破坏。
///
/// 这条尤其值得测：隧道本身是 SSE，承载的响应又是 SSE（SSE 套 SSE）。
/// 如果任何一层做了整段缓冲，最内层的流式就会消失。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_mode_preserves_sse_streaming() {
    guard(async {
        let st = setup_sse().await.expect("SSE 模式启动失败");

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
        let expect = st.up.sse_bytes.lock().unwrap().clone();
        assert_bytes_eq(
            &resp.body,
            &expect,
            "慢速 SSE 在 SSE 模式下也必须逐字节一致",
        );

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
        println!("  [SSE 模式] 首字节 {first:?}，整体 {total:?}");

        assert!(
            total >= std::time::Duration::from_millis(1500),
            "上游应当持续推送 ~2.4s；实际只有 {total:?}，说明这条测试没有测到它想测的东西"
        );
        assert!(
            first < std::time::Duration::from_millis(1000),
            "SSE 套 SSE 之后仍须流式：首字节实测 {first:?}，接近 {total:?} 就说明被缓冲了"
        );
    })
    .await;
}

/// SSE 模式下增量复用必须仍然生效——否则这条路径只是"能跑"，不是"有收益"。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_mode_keeps_incremental_savings() {
    guard(async {
        let st = setup_sse().await.expect("SSE 模式启动失败");
        let body = make_body(200, 6);

        assert_eq!(st.echo("/v1/chat/completions", &body).await.unwrap(), body);
        let v1 = st.status().await.unwrap();
        let raw1 = v1["req_raw_bytes"].as_u64().unwrap();
        let wire1 = v1["req_wire_bytes"].as_u64().unwrap();

        // 再发同一个 body：应当全部走增量引用
        assert_eq!(st.echo("/v1/chat/completions", &body).await.unwrap(), body);
        let v2 = st.status().await.unwrap();
        let d_raw = v2["req_raw_bytes"].as_u64().unwrap() - raw1;
        let d_wire = v2["req_wire_bytes"].as_u64().unwrap() - wire1;
        let pct = d_wire as f64 / d_raw as f64 * 100.0;
        println!(
            "  [SSE 模式] 冷启动 {wire1}/{raw1} ｜ 增量 {d_wire}/{d_raw}（{pct:.4}%）\
             复用块={}",
            v2["ref_blocks"]
        );

        assert_eq!(v2["mode"], "sse", "增量请求也必须走 SSE：{v2}");
        assert_eq!(v2["delta_fallbacks"], 0, "不应发生增量回退：{v2}");
        assert!(
            pct < 5.0,
            "SSE 模式下增量复用必须仍然生效（实测 {pct:.4}%）——\
             若接近 100% 说明隧道把请求体退化成原样转发了"
        );

        // 注意：请求方向不走 base64（长度前缀二进制），所以这里**不该**看到
        // 那 33% 的膨胀。若膨胀出现，说明两个方向的编码用反了。
        assert!(
            (wire1 as f64 / raw1 as f64) < 0.9,
            "冷启动走的是整段 zstd，不该接近原始大小"
        );
    })
    .await;
}

/// 强制 WS 时不应误落到 SSE——否则"强制"就没有意义，验收也就测不准。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forced_ws_stays_on_ws() {
    guard(async {
        let st = setup_with(&[], &["--force-mode".into(), "ws".into()])
            .await
            .expect("启动失败");
        let body = make_body(20, 0);
        assert_eq!(st.echo("/v1/chat/completions", &body).await.unwrap(), body);
        assert_eq!(st.status().await.unwrap()["mode"], "ws");
    })
    .await;
}

/// **M3 验收原文**：WS 被中间设备拦掉时，必须**自动**落到 SSE，且功能完整。
///
/// 与上面三条的区别：那三条用 `--force-mode sse` 跳过 WS 尝试，只能证明"SSE 能用"；
/// 这条把 WS 真的拦掉（模拟企业代理），验证「自动」这两个字。
/// 这条链路建立不起来时，客户端会掉到直连（L2）——功能还在，但收益全丢，
/// 所以还要断言 `mode == "sse"` 且 `bypass_requests == 0`。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_blocked_by_middlebox_falls_back_to_sse_automatically() {
    guard(async {
        let st = setup_behind_ws_blocker().await.expect("启动失败");
        let body = make_body(50, 2);

        let v = st.status().await.unwrap();
        let link_ms = v["link_ms"].as_u64().unwrap_or(0);
        println!(
            "  [自动降级] mode={} link_alive={} aead={} 链路建立耗时={link_ms}ms",
            v["mode"], v["link_alive"], v["aead"]["enabled"]
        );
        // M3 验收原文的另一半：「降级耗时 <3s」。这里包含"WS 试一次被 403 +
        // 换 SSE 成功"的完整代价，正是那条验收要量的东西。
        //
        // ⚠️ **第 180 轮：真因是"读早了"，已从夹具侧修。**
        //
        // 夹具 `setup_behind_ws_blocker` 原先只等 **HTTP 端口就绪**（`/__dshp/status` 能应答），
        // 而那时客户端的**首次链路尝试可能还没结束** —— 这种时刻 `link_ms == 0`、
        // 且 `mode` 还是初始值 `bypass`（含义是"还没有链路"，不是"放弃隧道改直连"：
        // `bypass_requests` 仍是 0）。Windows 上恰好赢了那个竞态，GitHub 的 Linux runner 上输了
        // ⇒ 这条用例确定性红（两遍都红）✗ ⇒ 夹具现在显式 `wait_for_link` ✓。
        //
        // 判据只留上界：0 也可能来自"尝试在 1ms 内完成"（`as_millis()` 截断）。
        // 真正的 M3 判据是**下面那几条结果**（自动落到 sse、没走直连、功能完整），一条没放宽。
        if link_ms == 0 {
            println!("  [自动降级] 注意：link_ms=0（尝试 <1ms 完成，或被截断）");
        }
        assert!(link_ms < 3000, "降级耗时必须在 3s 内（实测 {link_ms}ms）");
        assert_eq!(
            v["mode"], "sse",
            "WS 被拦时应**自动**落到 SSE，而不是直连：{v}"
        );
        assert_eq!(v["link_alive"], true);
        assert_eq!(v["aead"]["enabled"], true, "SSE 上同样必须有加密会话：{v}");

        for path in [
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/messages",
            "/v1/responses",
        ] {
            let echoed = st.echo(path, &body).await.unwrap();
            assert_eq!(echoed, body, "{path} 在自动降级后必须逐字节一致");
        }

        let v2 = st.status().await.unwrap();
        assert_eq!(v2["mode"], "sse", "不应在请求过程中掉档：{v2}");
        assert_eq!(
            v2["bypass_requests"], 0,
            "直连次数必须为 0——掉到直连虽然也能成功，但那不是「落 SSE」：{v2}"
        );
    })
    .await;
}
