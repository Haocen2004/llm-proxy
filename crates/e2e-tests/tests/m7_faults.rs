//! M7 故障演练（设计 §16）。
//!
//! 这一套守的是**整个项目唯一一条致命红线**：任何故障下，SDK 要么拿到**正确结果**，
//! 要么拿到**明确错误**——**绝不允许**拿到"看起来正常、其实内容不全/不对"的响应。
//!
//! 为什么单独成篇：这类缺陷**不会让任何既有测试变红**。上游断在半路时，
//! 代理如果干净地收尾 HTTP body，SDK 看到的就是一次成功的 200——
//! 所有"内容逐字节一致"的断言依然成立（因为那些测试的上游从不半途而废）。
//! 只有专门注入故障才能碰到它。

mod common;

use common::*;
use std::time::Duration;

/// 上游发到一半断流：**绝不能变成一次"成功的"响应**。
///
/// 故障注入方式见 `sse_response_cut`：mock 上游发 3 个事件后让响应体直接出错，
/// 于是 TCP 连接被中止、chunked 的结束块永远不会发出。这是一次**真实可检测**的
/// 中途断流（"把 stream 正常结束"不算——那在 HTTP 语义上就是一条完整响应，
/// 代理没有能力区分它和截断）。
///
/// 客户端必须看到明确错误。若拿到 200，SDK 会把半截 SSE 当成完整回复——
/// 这正是设计 §16 M7 点名禁止的静默错误内容。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_midstream_abort_is_never_a_clean_200() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let body = make_body(20, 0);
        let before = st.status().await.unwrap();

        let r = raw_request(
            &st.client,
            "POST",
            "/v1/messages",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "sse-cut"),
            ],
            &body,
        )
        .await;

        let after = st.status().await.unwrap();
        let truncated = after["truncated_responses"].as_u64().unwrap()
            - before["truncated_responses"].as_u64().unwrap();

        match r {
            Err(e) => {
                // 正确：SDK 拿到一个明确的传输错误
                println!("  [M7 断流] 客户端拿到明确错误：{e}");
                println!("  [M7 断流] 主动中止计数 truncated_responses={truncated}");
            }
            Ok(resp) => {
                panic!(
                    "上游中途断流，代理却返回了**完整**响应（HTTP {}，{} 字节）——\
                     这就是静默截断：SDK 无法察觉内容不全。\
                     响应体前 120 字节：{:?}",
                    resp.status,
                    resp.body.len(),
                    String::from_utf8_lossy(&resp.body[..resp.body.len().min(120)])
                );
            }
        }

        // 观测点必须同步变化：没有它，"中止"与"恰好没走到"区分不开
        assert!(
            truncated > 0,
            "应当计入一次主动中止，否则这条红线没有观测点：{after}"
        );
        assert_eq!(
            after["template_miss"], 0,
            "这一轮不该有模板缺失（那是另一条路径）"
        );

        // **不得重发 POST**。上游已经收到并开始回复，重发就是重复生成——
        // 用户账单翻倍、内容还可能不同。这是设计的不可协商项。
        assert_eq!(
            st.up.rec.len(),
            1,
            "上游中途断流不得触发重新 POST（实际打了 {} 次）",
            st.up.rec.len()
        );
    })
    .await;
}

/// 断流之后链路**必须还能继续服务**：不能因为一次上游故障就把连接或会话搞坏。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn link_still_serves_normally_after_an_upstream_abort() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let body = make_body(20, 0);

        // 先制造一次断流
        let _ = raw_request(
            &st.client,
            "POST",
            "/v1/messages",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "sse-cut"),
            ],
            &body,
        )
        .await;

        // 再走一次正常请求：必须逐字节一致
        let echoed = st.echo("/v1/chat/completions", &body).await.unwrap();
        assert_eq!(echoed, body, "一次上游故障不得影响后续请求的正确性");

        // 注意：`sse_bytes` 是**累积**记录器，刚才那次断流也往里写了 3 个事件。
        // 所以必须先记住偏移量，再比较这一次的那一段——直接整体比较会拿到
        // "断流前缀 + 本次全部"，看起来像内容不符，其实是被自己的注入污染了读数。
        let off = st.up.sse_bytes.lock().unwrap().len();
        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/messages",
            &[("content-type", "application/json"), ("x-test-mode", "sse")],
            &body,
        )
        .await
        .expect("断流之后的正常 SSE 请求不该失败");
        let expect = st.up.sse_bytes.lock().unwrap()[off..].to_vec();
        assert!(!expect.is_empty(), "记录器里应当有本次请求的字节");
        assert_bytes_eq(&resp.body, &expect, "断流之后 SSE 仍须逐字节一致");

        let v = st.status().await.unwrap();
        assert_eq!(v["mode"], "ws", "断流不该把传输模式打坏：{v}");
        assert_eq!(v["link_alive"], true, "链路应当仍然活着：{v}");
    })
    .await;
}

/// 请求体传到一半链路消失：**绝不能把半截请求发给上游**。
///
/// 这是响应侧那条红线的镜像。`forward_raw` 的收包循环用"帧流结束"当结束信号，
/// 链路中途断掉时循环正常退出、`drop(body_tx)` 干净收尾——若上游侧是 chunked
/// 编码，就成了一条"格式完整、内容只有半截"的请求，上游会照着半截问题生成答案。
///
/// 注入方式：客户端到服务端之间放一个按字节预算砍断的中继（`CutProxy`）。
/// 预算 200 KB 落在第一个 512 KB 的 BodyChunk 中间，且远在 32 KB 字典握手之后。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_body_cut_midstream_never_reaches_upstream() {
    guard(async {
        let st = setup_behind_cut_proxy(Some(200_000), None)
            .await
            .expect("启动失败");
        let body = make_body(400, 6); // ~700 KB ⇒ 至少两个 512 KB 的 BodyChunk

        let r = raw_request(
            &st.client,
            "POST",
            "/v1/chat/completions",
            &[("content-type", "application/json")],
            &body,
        )
        .await;

        let hits = st.up.rec.len();
        match r {
            Err(e) => println!("  [M7 请求断流] 客户端拿到传输错误：{e}"),
            Ok(resp) => {
                println!("  [M7 请求断流] 客户端拿到 HTTP {}", resp.status);
                // **2xx 才是静默错误**：那意味着 SDK 收到一个"成功"的响应，
                // 但它对应的请求根本没被完整送到上游。
                // 5xx（客户端代理本地生成的 502）是**正确**行为：明确错误。
                assert!(
                    !(200..300).contains(&resp.status),
                    "半截请求体不得变成 2xx 响应（实际 HTTP {}，{} 字节）",
                    resp.status,
                    resp.body.len()
                );
            }
        }

        println!("  [M7 请求断流] 上游被请求次数={hits}");
        // **核心断言**：上游一次都不该被这条半截请求打到。
        assert_eq!(
            hits, 0,
            "半截请求体不得发给上游（上游收到 {hits} 次）——\
             上游会照着半截问题生成一个看起来正常的答案，那是静默错误内容"
        );
    })
    .await;
}

/// 响应传到一半链路消失（**链路断**，不是上游断）：同样绝不能变成成功的 200。
///
/// 与 `upstream_midstream_abort_is_never_a_clean_200` 的区别在故障位置：
/// 那条是上游断、这条是 DSHP 链路断。两者在客户端看到的是同一个现象
/// （响应帧流提前结束），但代码路径不同——上游断会走到 `Err` 帧，
/// 链路断只会让 `recv()` 返回 `None`。**只有 `None` 这条最容易漏。**
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn link_cut_midresponse_is_never_a_clean_200() {
    guard(async {
        // 预算取 64 KB：既远在握手（几百字节）之后，又远小于响应体（~700 KB）。
        //
        // 这里**刻意用 echo 的大响应**，而不是 SSE：模板化之后 140 个事件的 SSE
        // 在链路上只有 ~1.5 KB——比握手预算还小，砍不到。我第一版就是这么写错的：
        // 预算 4 KB 落在了响应之后，测试拿到的是一份**完整的** 16406 字节。
        // **注入的字节预算必须按"链路上真实字节数"来定，而不是按业务字节数。**
        let st = setup_behind_cut_proxy(None, Some(64 * 1024))
            .await
            .expect("启动失败");
        let body = make_body(400, 6); // ~700 KB，响应逐字节回显
        let before = st.status().await.unwrap();

        let r = raw_request(
            &st.client,
            "POST",
            "/v1/chat/completions",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "echo"),
            ],
            &body,
        )
        .await;

        let after = st.status().await.unwrap();
        let truncated = after["truncated_responses"].as_u64().unwrap()
            - before["truncated_responses"].as_u64().unwrap();

        match r {
            Err(e) => println!("  [M7 链路断流] 客户端拿到明确错误：{e}"),
            Ok(resp) => {
                // 第二种**同样合法**的形态：客户端自己回一个明确的错误状态。
                // 线上就是这个形状 —— "DSHP 链路不可用，且未配置 --upstream-fallback"
                // ⇒ **502 + 一段说明**。它和 transport 错误一样**没有骗人**：
                // 调用方看到的是 5xx，不是半截内容。
                //
                // ⚠️ 红线在这里：**2xx 一律算失败**（那才是静默截断）。
                //
                // 第 180 轮修：原判据只接受 `Err` ⇒ 在 Linux 上会红（实测：先写出 502、
                // 连接才被 drop ⇒ 拿到 `Ok(502, 172B)`），而 Windows 上是 transport 错误
                // ⇒ 同一个正确行为在两个平台上呈现不同 ⇒ **是判据太窄，不是产品违规**。
                assert!(
                    !(200..300).contains(&resp.status),
                    "链路在响应中途断掉，代理却返回了 2xx（HTTP {}，{} 字节）——\
                     这是静默截断：SDK 拿到的是半截内容",
                    resp.status,
                    resp.body.len()
                );
                println!(
                    "  [M7 链路断流] 客户端给了明确错误状态：HTTP {}（{} 字节）",
                    resp.status,
                    resp.body.len()
                );
            }
        }
        // 第二道判据是**可观测性**，不是红线。链路断掉有**两条都合法**的走向：
        //
        //   (a) 客户端先在隧道内看到帧流提前结束 ⇒ 记一次主动中止（`truncated_responses`++）；
        //   (b) 客户端先把链路判死 ⇒ 当场翻直连（`bypass_requests`++），
        //       没有 `--upstream-fallback` 时回 502 —— 上面的"非 2xx"已经把红线守住了。
        //
        // 哪一条先发生取决于"链路死亡"与"帧流 EOF"的观测次序 ⇒ 平台/负载相关。
        // **实测**：Windows 上走 (a)；GitHub 的 Linux runner 上走 (b)
        // （诊断：`mode=bypass`、`link_alive=false`、`bypass_requests=1`、`truncated_responses=0`）。
        // 两种都不许出现 2xx ✓，所以这里只要求"链路断这件事在客户端侧**有痕迹**"。
        let bypassed = after["bypass_requests"].as_u64().unwrap_or(0)
            - before["bypass_requests"].as_u64().unwrap_or(0);
        assert!(
            truncated > 0 || bypassed > 0,
            "既没记主动中止、也没翻直连 ⇒ 链路断掉这件事在客户端侧没有任何痕迹：{after}"
        );
        if truncated == 0 {
            println!(
                "  [M7 链路断流] 该平台走的是「先翻直连」那条：bypass_requests +{bypassed}\
                 （同样是明确错误，不是 2xx）"
            );
        }
    })
    .await;
}

/// 模式全挂：WS 与 SSE 隧道都被中间设备拦掉 → 落到 L2 直连上游。
///
/// 这条守的不是"降级发生了"（那是 M3 的验收），而是**降级之后结果依然正确**：
/// 最后一档是"退回原样 HTTP 直连"，它必须仍然逐字节一致，否则用户在最坏的网络里
/// 拿到的是错误内容。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_tunnel_modes_blocked_still_serves_correctly() {
    guard(async {
        let st = setup_behind_all_modes_blocker().await.expect("启动失败");
        let body = make_body(30, 0);

        // 等客户端认清"隧道建不起来"，落到直连
        let mut bypassed = false;
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let v = st.status().await.unwrap();
            if v["mode"] == "bypass" {
                bypassed = true;
                break;
            }
        }
        let v = st.status().await.unwrap();
        assert!(
            bypassed,
            "WS 与 SSE 都不通时必须落到 L2 直连，实际 mode={} link_alive={}",
            v["mode"], v["link_alive"]
        );

        // 四种协议都要逐字节一致
        let mut expect = Vec::new();
        for path in [
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/messages",
            "/v1/responses",
        ] {
            let echoed = st.echo(path, &body).await.unwrap();
            expect.push(path);
            assert_eq!(echoed, body, "{path} 在模式全挂时必须逐字节一致");
        }

        // SSE 也要正确（直连路径下 SSE 是原样透传）
        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/messages",
            &[("content-type", "application/json"), ("x-test-mode", "sse")],
            &body,
        )
        .await
        .expect("直连模式下 SSE 请求失败");
        let sse = st.up.sse_bytes.lock().unwrap().clone();
        assert_bytes_eq(&resp.body, &sse, "模式全挂下的 SSE 必须逐字节一致");

        let after = st.status().await.unwrap();
        let link_ms = after["link_ms"].as_u64().unwrap_or(0);
        println!(
            "  [M7 模式全挂] 落 L2：bypass_requests={} bypass_switches={} link_ms={}",
            after["bypass_requests"], after["bypass_switches"], link_ms
        );
        // **M3 验收的另一半「降级耗时 <3s」在"最坏情形"下也要成立。**
        //
        // 此前它只在 `sse_mode.rs` 的"仅 WS 被拦"用例里断言；而**两种隧道都不通**
        // （降到 L2 直连）这个最坏情形只打印、不判定——"打印出来没人看"等于没有约束。
        // 第 51 轮补上：界给得很宽（实测个位数毫秒），它防的是"降级链卡住"这类回归。
        assert!(
            link_ms > 0 && link_ms < 3000,
            "M3：「降级耗时 <3s」在最坏情形（两种隧道都不通 ⇒ 落 L2）也必须成立，\
             实测 {link_ms}ms（0 说明客户端根本没试过建链）"
        );
        assert!(
            after["bypass_requests"].as_u64().unwrap() >= 5,
            "四个协议 + 一次 SSE 都应当走直连：{after}"
        );
    })
    .await;
}
