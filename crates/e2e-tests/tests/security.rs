//! 传输安全验收：证明 **AEAD 真的在链路两端执行**，而不只是"代码存在"。
//!
//! 这组测试的存在理由：加密代码可以在完全不生效的情况下让所有既有测试通过——
//! 那样"实现了密码学"就成了一个无法证伪的说法。因此这里断言的是**可观测的副作用**
//! （已加密/已解密帧数），以及**认证失败时的行为**。

mod common;

use common::*;

/// 验收 §13：握手完成后载荷确实被 AEAD 封装。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn payloads_are_actually_encrypted() {
    guard(async {
        let st = setup().await.expect("启动失败");

        let body = make_body(40, 0);
        let echoed = st.echo("/v1/chat/completions", &body).await.unwrap();
        assert_eq!(echoed, body, "加密链路上也必须逐字节一致");

        let v = st.status().await.unwrap();
        let aead = &v["aead"];
        println!(
            "  [AEAD] enabled={} 已加密 {} 帧 / 已解密 {} 帧 / 豁免明文 {} 帧",
            aead["enabled"], aead["sealed_frames"], aead["opened_frames"], aead["plaintext_exempt"]
        );

        assert_eq!(aead["enabled"], true, "握手后 AEAD 必须已启用：{v}");
        assert!(
            aead["sealed_frames"].as_u64().unwrap() > 0,
            "必须有帧被加密——否则'加密'只是一段没被调用的代码：{v}"
        );
        assert!(
            aead["opened_frames"].as_u64().unwrap() > 0,
            "必须有帧被解密：{v}"
        );
        // `plaintext_exempt` 统计的是"AEAD 已启用、但因帧类型豁免而放行明文"的次数。
        // 客户端这边应为 0：它的 `Hello` 是在 `enable_crypto` **之前**发出的，
        // 根本没进入加密路径（这也正是握手的设计——公钥必须在密钥建立前交换）。
        // 上限 1 是给 `Caps` 留的余量（服务端侧会命中，客户端侧不会）。
        assert!(
            aead["plaintext_exempt"].as_u64().unwrap() <= 1,
            "豁免明文的帧不得超过 1 条，多了说明有帧绕过了加密：{v}"
        );
    })
    .await;
}

/// 加密不得破坏四种协议的字节精确性与 SSE 流式时序。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_protocols_stay_byte_exact_over_aead() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let body = make_body(30, 0);

        for path in [
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/messages",
            "/v1/responses",
        ] {
            let echoed = st.echo(path, &body).await.unwrap();
            assert_eq!(echoed, body, "{path} 在加密链路上必须逐字节一致");
        }

        // SSE：既要字节一致，也要保持流式（不能因为加密而退化成整段缓冲）。
        //
        // **用上游故意拖慢的 `sse-slow`（12 片 × 200ms）来证明流式。**
        // 原来用的是普通 `sse`，它在**一个批量窗口内就能发完**——客户端拿到几片、
        // 时间跨度多大，完全取决于当时的机器负载。这条断言因此在全量 CI 并发跑时
        // 崩过一次（单独跑 5/5 通过）：它测到的是负载，不是流式。
        // 换成有确定的 2.4s 拉开的流之后，缓冲式代理的首字节要等 2.4s、
        // 流式代理 ≤ 一个批量窗口，差距足够大，负载抖不动它。
        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/messages",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "sse-slow"),
            ],
            &body,
        )
        .await
        .expect("SSE 请求失败");
        let expect = st.up.sse_bytes.lock().unwrap().clone();
        assert_bytes_eq(&resp.body, &expect, "加密之后 SSE 仍必须逐字节一致");

        let first = resp
            .chunk_times
            .first()
            .map(|t| t.duration_since(resp.start))
            .unwrap_or_default();
        let total = resp
            .chunk_times
            .last()
            .map(|t| t.duration_since(resp.start))
            .unwrap_or_default();
        println!(
            "  [加密 SSE] 首字节 {first:?}，整体 {total:?}，分片数 {}",
            resp.chunk_times.len()
        );
        // 先确认这条测试没有空过：上游确实把流拉开了
        assert!(
            total >= std::time::Duration::from_millis(1400),
            "上游应当有一段 ~2.4s 的间隔流；实际只有 {total:?}，这条测试没测到它要测的东西"
        );
        assert!(
            resp.chunk_times.len() >= 2 && first < std::time::Duration::from_millis(900),
            "SSE 在加密链路上仍须流式到达：首字节 {first:?}，整体 {total:?}，\
             分片数 {}。首字节接近整体说明实现退化成了整段缓冲",
            resp.chunk_times.len()
        );

        let v = st.status().await.unwrap();
        assert!(
            v["aead"]["sealed_frames"].as_u64().unwrap() > 0
                && v["aead"]["opened_frames"].as_u64().unwrap() > 0,
            "这一轮请求也必须经过加密：{v}"
        );
    })
    .await;
}

/// 验收 §13.8：**PSK 不一致绝不能建立 DSHP 会话**。
///
/// 注意这条测试在引入降级链之后**语义变了**：首次连接失败现在不再让客户端退出，
/// 它会以**直连模式**继续服务（设计 §10 的 L2 兜底）。所以断言也要跟着变——
/// 要守的性质不是"客户端起不来"，而是「**它绝不会声称自己有一条加密的 DSHP 链路**」。
///
/// 这才是真正重要的性质：如果客户端在 PSK 不匹配时仍然报告 `mode=ws` 且
/// `aead.enabled=true`，就说明存在一条"以为加密、其实没有"的路径——那是最危险的失败。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mismatched_psk_never_establishes_a_session() {
    guard(async {
        let st = setup_with_psk(&[], &[], Some("server-side-psk"), Some("client-side-psk"))
            .await
            .expect("客户端应以直连模式启动，而不是退出");

        tokio::time::sleep(std::time::Duration::from_millis(900)).await;
        let v = st.status().await.unwrap();
        println!(
            "  [PSK 不匹配] mode={} link_alive={} aead={} 重连尝试={}",
            v["mode"], v["link_alive"], v["aead"]["enabled"], v["reconnect_attempts"]
        );

        assert_eq!(v["mode"], "bypass", "PSK 不匹配时绝不能进入 WS 模式：{v}");
        assert_eq!(v["link_alive"], false, "不应存在可用链路：{v}");
        assert_eq!(
            v["aead"]["enabled"], false,
            "绝不能声称自己有一条加密会话——那是最危险的失败方式：{v}"
        );
        assert!(
            v["reconnect_attempts"].as_u64().unwrap() >= 1,
            "应持续尝试重连（而不是放弃）：{v}"
        );
    })
    .await;
}

/// 三处 `/__dshp*` 端点的**鉴权口径不是同一条规则**，这条把它们钉住。
///
/// 为什么要专门守：三处"一刀切"（都开放或都要凭据）都能让绝大多数测试照旧通过，
/// 但两种切法的后果完全不同——
///
/// * 统计页面/统计 API 一刀切开放 ⇒ 线上读流量统计不需要任何凭据；
/// * 诊断端点一刀切要凭据 ⇒ 夹具（**故意不配 token**）唯一的观测通道 401 ⇒
///   `multi_client.rs` 的三条判据全红。**后者就是本轮修掉的旧缺陷**：
///   `authorized()` 对空 token 恒返回 false，而 `multi_client` 的判据依赖 `slots_limit`。
///
/// 所以这里同时钉住两半：**该关的必须关，该开的必须开**。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stats_pages_close_without_a_token_but_diagnostics_stay_open() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let addr = format!("127.0.0.1:{}", st.dport);

        // 必须用 POST：服务端按**首字节**分流（`G` 一律当 WS 握手），夹具的 diag 也是这样发的。
        let ui = raw_request(&addr, "POST", "/__dshp/ui", &[], b"")
            .await
            .unwrap();
        let stats = raw_request(&addr, "POST", "/__dshp/api/stats", &[], b"")
            .await
            .unwrap();
        assert_eq!(ui.status, 401, "未配置 token 时统计页面必须关闭（401）");
        assert_eq!(stats.status, 401, "未配置 token 时统计 API 必须关闭（401）");

        let diag = st
            .server_diag()
            .await
            .expect("未配置 token 时诊断端点必须可读——否则夹具没有观测通道");
        assert!(
            diag["slots_limit"].is_u64(),
            "诊断端点必须返回服务端诊断字段：{diag}"
        );
        println!(
            "  [鉴权口径] 未配 token：/__dshp/ui={} /__dshp/api/stats={} /__dshp/status=开放（slots_limit={}）",
            ui.status, stats.status, diag["slots_limit"]
        );
    })
    .await;
}
