//! 缺口 #7：**`GOAWAY` 优雅排空**（第 181 轮从"定义齐全但没人发"变成"能发、且被验证"）。
//!
//! # 这一组在守什么
//!
//! 设计 §15 把 `GOAWAY` 记为未实现，理由是"收益不大"——但那份证据量的是**降级速度**
//! （断链后首个请求 2.3ms、重连 65/326ms、没有 502 窗口）。它**没有覆盖**另一件事：
//! 计划内重启（换二进制 / 改配置 / `systemctl restart`）会**切断在途响应** ⇒
//! SDK 看到传输错误、整轮对话白跑、还白付一次上游调用 ✗。
//!
//! 所以本组的两条主判据是：
//!
//! 1. **排空不得切断在途响应**（`drain_lets_in_flight_response_finish_and_then_exits`）
//!    —— 逐字节一致 + `truncated_responses == 0` + 服务端随后真的退出；
//! 2. **排空期间接不了新活**（`drain_rejects_new_work_with_503`）
//!    —— "明牌 503"优于"接了又被切"（与 M7 红线同向）。
//!
//! 另外两条是**守门人自己的守门人**：
//!
//! * `drain_endpoint_requires_token`：排空是**写操作**（终止服务）⇒ 必须凭据。
//!   诊断端点是只读的，所以它可以"没配 token 就开放"；排空**不能**照抄那条规矩 ✗。
//! * `hard_kill_mid_stream_truncates_response`：**负向对照**。没有它，第 1 条判据可能
//!   只是"这条响应本来就来得及跑完"——那判的就不是排空，而是运气 ✗。
//!
//! # 怎么触发（为什么不是 SIGTERM）
//!
//! 生产里的触发路径是 `SIGTERM`（`systemctl restart` 就会发），但**夹具在本机发不出它**
//! （Windows 上 `taskkill` 不带 `/F` 杀不掉无窗口控制台进程）。项目纪律又不许"为测试在
//! 生产代码里开注入开关" ✗ ⇒ 服务端另外提供一个**带凭据的管理端点** `POST /__dshp/drain`：
//! 它是**运维功能**（运维本来就需要"排空后重启"），不是测试开关 ✓，同时让这条判据可机械验证 ✓。

mod common;

use common::*;

/// 排空端点用的凭据（夹具通过 `DSHP_WEBUI_TOKEN` 注入）。
const TOKEN: &str = "e2e-drain-token";

/// 服务端地址（排空/诊断端点都从这里打）。
fn server_addr(st: &Stack) -> String {
    format!("127.0.0.1:{}", st.dport)
}

fn bearer() -> String {
    format!("Bearer {TOKEN}")
}

/// 轮询客户端状态，等它**因为收到 GOAWAY 而降级**（`link_alive=false` 且 `mode=bypass`）。
///
/// 为什么不单次采样：第 182 轮在 GitHub runner 上实测到偶发红 —— GOAWAY 是**异步**送达的，
/// 单次采样会撞在"帧还在路上"的瞬间 ✗（详见调用点的说明：同步缺失 ≠ 判据放松 ✓）。
async fn wait_client_bypass(st: &Stack, timeout_ms: u64) -> serde_json::Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    let mut last = serde_json::Value::Null;
    while std::time::Instant::now() < deadline {
        if let Ok(v) = st.status().await {
            let flipped = v["link_alive"] == serde_json::Value::Bool(false)
                && v["mode"] == serde_json::Value::String("bypass".into());
            last = v;
            if flipped {
                return last;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    last
}

/// 轮询服务端诊断，等到**至少一条流在途**（不靠猜时间 ✓）。
async fn wait_stream_inflight(addr: &str, token: Option<&str>, timeout_ms: u64) -> u64 {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    let mut last: u64 = 0;
    while std::time::Instant::now() < deadline {
        let hdrs: Vec<(&str, &str)> = match token {
            Some(t) => vec![("authorization", t)],
            None => vec![],
        };
        if let Ok(r) = raw_request(addr, "GET", "/__dshp/status", &hdrs, b"").await {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&r.body) {
                last = v["streams_inflight"].as_u64().unwrap_or(0);
                if last >= 1 {
                    return last;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    last
}

/// **主判据**：排空不切断在途响应，送完之后才退出。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drain_lets_in_flight_response_finish_and_then_exits() {
    guard(async {
        let token_env = [("DSHP_WEBUI_TOKEN", TOKEN)];
        let mut st = setup_full(&[], &[], None, None, &token_env, &[])
            .await
            .expect("启动失败");
        let daddr = server_addr(&st);

        // ---- 起一条**慢**的流式请求（moc 的 `sse-slow`：12 个事件 × 200ms ≈ 2.4s）----
        let base_len = st.up.sse_bytes.lock().unwrap().len();
        let client = st.client.clone();
        let body = make_body(40, 0);
        let in_flight = tokio::spawn(async move {
            raw_request(
                &client,
                "POST",
                "/v1/messages",
                &[("content-type", "application/json"), ("x-test-mode", "sse-slow")],
                &body,
            )
            .await
        });

        // ---- 等到它真的在途（服务端权威计数，不猜时间 ✓）----
        let inflight = wait_stream_inflight(&daddr, Some(&bearer()), 5000).await;
        assert!(
            inflight >= 1,
            "5s 内没有观察到在途流（streams_inflight={inflight}）⇒ 后面的断言判的不是排空"
        );
        // ---- 再等到**客户端正在收响应**（活信号）：这样排空是在"响应传到一半"时发生的 ✓
        //      ⚠️ 不能用 mock 的 `sse_bytes`：它把整个 body **一次性**算好写进去 ✗
        //      （第 181 轮实测：那个数在排空前就已经是全长，用它当"是否还在流"会写出无效判据 ✗）；
        //      节奏在**发送侧**（每事件 200ms）✓ ⇒ 只有"客户端逐帧累加"的帧计数是活信号 ✓。----
        let frames_before = wait_client_frames(&st.client, 5000).await;
        assert!(
            frames_before > 0,
            "5s 内客户端一个响应帧都没收到（frames={frames_before}）⇒ 排空没赶上「响应正在传」的窗口"
        );

        // ---- 排空前的**前提**：链路还活着、模式还是 ws ----
        // 没有这两条，后面的"排空后 link_alive=false"就说明不了是 GOAWAY 造成的 ✗
        // （可能只是连接真的断了）。第 181 轮实测撞到过这种**假通过**：
        // 那次 drain 落在了"响应已经跑完"之后 ⇒ 连接被正常关掉 ⇒ 判据看着成立 ✗。
        let c0 = st.status().await.unwrap();
        assert_eq!(
            c0["link_alive"], true,
            "排空前的**前提**成立不了：链路应当还活着（否则后面那条判据无意义）：{c0}"
        );
        assert_eq!(c0["mode"], "ws", "排空前的模式应当是 ws：{c0}");

        // ---- 触发排空（记下"此刻客户端已收到多少帧"，事后用它证明响应**还在传**）----
        let t_drain = std::time::Instant::now();
        let r = raw_request(&daddr, "POST", "/__dshp/drain", &[("authorization", &bearer())], b"")
            .await
            .expect("排空请求失败");
        assert_eq!(r.status, 202, "排空端点应回 202（先回应、再排空、最后退出）");

        // ---- 客户端**必须因为收到 `GOAWAY` 而当场降级**（不是等连接真的断掉）----
        //
        // 这是客户端那一半的**直接判据**：此刻服务端还在等这条在途流（连接**还开着** ✓）——
        // 前提由上面两条 + 下面那条"当时还没跑完"共同固定 ✓。
        //
        // ⚠️ 第 182 轮在 GitHub runner 上实测到这条**偶发红**（公开仓库那条 CI ✗）：
        // 单次采样会撞在"客户端还没处理完那一帧"的瞬间 —— 实测读到的正是
        // `link_alive=true, mode=ws, reconnect_attempts=0`（即 GOAWAY 还在路上 ✓）。
        // 这不是判据错，而是**判据里缺了同步** ✗ ⇒ 改成有界轮询（≤2s，20ms 步长）。
        //
        // 为什么轮询**不等于**放松判据：紧跟着断言"此刻服务端仍在排空、且这条流仍在途" ✓。
        // 若客户端没处理 GOAWAY（负向对照：把泵里的 `enter_bypass()` 注释掉），它只会在
        // **连接真的断掉之后**才降级 —— 而那一刻服务端已经排空完成、进程退出 ⇒
        // 后面那两条会**如实变红** ✓（负向对照依然成立，第 181 轮实测过这一点 ✓）。
        let c = wait_client_bypass(&st, 2000).await;
        println!(
            "  [排空] 当场读客户端：link_alive={} mode={}（服务端此刻仍在等这条在途流）",
            c["link_alive"], c["mode"]
        );
        assert_eq!(
            c["link_alive"],
            false,
            "收到 GOAWAY 后客户端应**当场**判定链路失效（此刻服务端还没关连接）：{c}"
        );
        assert_eq!(
            c["mode"], "bypass",
            "收到 GOAWAY 后应立刻降级为直连模式（后台再重连）：{c}"
        );
        // 直接否决"其实是连接断了造成的"：服务端**此刻**还在排空，且这条流仍在途 ✓。
        let s = raw_request(&daddr, "GET", "/__dshp/status", &[("authorization", &bearer())], b"")
            .await
            .expect("读服务端状态失败");
        let sj: serde_json::Value = serde_json::from_slice(&s.body).unwrap();
        assert_eq!(
            sj["draining"].as_bool(),
            Some(true),
            "客户端降级时服务端应当仍在排空（否则说明降级是连接断开造成的 ✗）：{sj}"
        );
        assert!(
            sj["streams_inflight"].as_u64().unwrap_or(0) >= 1,
            "客户端降级时这条在途流应当还没跑完（否则同上 ✗）：{sj}"
        );

        // ---- 在途响应必须**完整**送达（红线：不许切成半截）----
        let resp = in_flight.await.expect("任务 panic").expect("在途请求失败");
        assert_eq!(resp.status, 200, "排空不得把在途响应变成错误");
        let expect = st.up.sse_bytes.lock().unwrap()[base_len..].to_vec();
        assert!(!expect.is_empty(), "mock 应当产出了一段 SSE 字节");
        // **关键前提**：排空那一刻响应**还在传**。用"帧计数在排空后继续增长"来证明 ✓
        // —— 只比较"已收到多少"是不够的（可能刚好收完 ✗），"排空后还有新帧"才是硬证据 ✓。
        let frames_after = wait_client_frames(&st.client, 2000).await;
        assert!(
            frames_after > frames_before,
            "排空后客户端没有再收到新帧（排空前 {frames_before}，排空后 {frames_after}）⇒ \
             响应在排空时其实已经传完了，这条判据判的不是「排空不切断在途响应」✗"
        );
        assert_bytes_eq(
            &resp.body,
            &expect,
            "排空期间的在途响应必须**逐字节完整**（这正是排空存在的意义）",
        );

        let v = st.status().await.unwrap();
        assert_eq!(
            v["truncated_responses"].as_u64().unwrap(),
            0,
            "排空不得导致任何「没收到 RespEnd」的截断：{v}"
        );

        // ---- 服务端应当**随后真的退出**（不是挂着等）----
        let waited = st
            .d
            .wait_exit(std::time::Duration::from_secs(10))
            .await
            .expect("排空完成后 10s 内服务端没有退出");
        println!(
            "  [排空] 在途流跑完 + 服务端退出：排空请求到退出共 {:.0}ms，观察等待 {:.0}ms（含响应传输）",
            t_drain.elapsed().as_secs_f64() * 1000.0,
            waited as f64
        );
    })
    .await;
}

/// 排空期间**不再接新活**：新隧道与新透传都是明牌 `503`；管理端点照旧可用。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drain_rejects_new_work_with_503() {
    guard(async {
        let token_env = [("DSHP_WEBUI_TOKEN", TOKEN), ("DSHP_ALLOW_PASSTHROUGH", "1")];
        let mut st = setup_full(&[], &[], None, None, &token_env, &[])
            .await
            .expect("启动失败");
        let daddr = server_addr(&st);

        // 先确认排空前这些路径是通的（否则"503 是排空造成的"这个结论不成立 ✗）
        let before = raw_request(&daddr, "GET", "/v1/models", &[], b"")
            .await
            .expect("排空前的透传请求失败");
        assert_ne!(
            before.status, 503,
            "排空前透传就不通 ⇒ 后面那个 503 说明不了任何事"
        );

        // 起一条慢流，让排空窗口足够长（排空会等它）
        let body = make_body(40, 0);
        let client = st.client.clone();
        let in_flight = tokio::spawn(async move {
            raw_request(
                &client,
                "POST",
                "/v1/messages",
                &[
                    ("content-type", "application/json"),
                    ("x-test-mode", "sse-slow"),
                ],
                &body,
            )
            .await
        });
        let inflight = wait_stream_inflight(&daddr, Some(&bearer()), 5000).await;
        assert!(inflight >= 1, "没等到在途流（{inflight}）⇒ 排空窗口不成立");

        let r = raw_request(
            &daddr,
            "POST",
            "/__dshp/drain",
            &[("authorization", &bearer())],
            b"",
        )
        .await
        .expect("排空请求失败");
        assert_eq!(r.status, 202);

        // ---- 新隧道：503（这条在 WS 入口就拦住了）----
        let t = raw_request(
            &daddr,
            "POST",
            "/__dshp/tunnel",
            &[("content-type", "application/octet-stream")],
            b"",
        )
        .await
        .expect("隧道探测请求失败");
        assert_eq!(
            t.status, 503,
            "排空期间新隧道必须**明牌 503**（接了再切掉 = 静默半截 ✗）"
        );

        // ---- 新透传：503 ----
        let p = raw_request(&daddr, "GET", "/v1/models", &[], b"")
            .await
            .expect("透传探测请求失败");
        assert_eq!(p.status, 503, "排空期间新透传请求也应明牌 503");

        // ---- 管理端点照旧（运维要看得到"我正在排空"，否则无从判断该不该重试）----
        let s = raw_request(
            &daddr,
            "GET",
            "/__dshp/status",
            &[("authorization", &bearer())],
            b"",
        )
        .await
        .expect("排空期间读诊断失败");
        assert_eq!(s.status, 200, "排空期间诊断端点必须仍然可读");
        let j: serde_json::Value = serde_json::from_slice(&s.body).unwrap();
        assert_eq!(
            j["draining"].as_bool(),
            Some(true),
            "诊断端点必须如实报告正在排空：{j}"
        );

        // 在途那条流仍然要完整送达
        let resp = in_flight.await.expect("任务 panic").expect("在途请求失败");
        assert_eq!(resp.status, 200);
        let _ = st.d.wait_exit(std::time::Duration::from_secs(10)).await;
    })
    .await;
}

/// 排空端点**必须凭据**：未配置 token ⇒ 401；配了但给错 ⇒ 401；且服务端**不能被停掉**。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drain_endpoint_requires_token() {
    guard(async {
        // 情形 A：服务端**没有配** token（这是夹具的默认状态）
        let mut st = setup_with(&[], &[]).await.expect("启动失败");
        let daddr = server_addr(&st);
        let r = raw_request(&daddr, "POST", "/__dshp/drain", &[], b"")
            .await
            .expect("排空请求失败");
        assert_eq!(
            r.status, 401,
            "未配置 token 时排空端点必须关闭（否则任何能访问端口的人都能停掉服务端 ✗✗）"
        );
        assert!(
            !st.d.has_exited(),
            "401 之后服务端**绝不能**已经退出 —— 那说明鉴权是摆设 ✗"
        );
        st.d.kill();

        // 情形 B：配了 token，但请求给了错的
        let token_env = [("DSHP_WEBUI_TOKEN", TOKEN)];
        let mut st = setup_full(&[], &[], None, None, &token_env, &[])
            .await
            .expect("启动失败");
        let daddr = server_addr(&st);
        let r = raw_request(
            &daddr,
            "POST",
            "/__dshp/drain",
            &[("authorization", "Bearer 错的-token")],
            b"",
        )
        .await
        .expect("排空请求失败");
        assert_eq!(r.status, 401, "错误凭据必须 401");
        let s = raw_request(
            &daddr,
            "GET",
            "/__dshp/status",
            &[("authorization", &bearer())],
            b"",
        )
        .await
        .expect("读诊断失败");
        let j: serde_json::Value = serde_json::from_slice(&s.body).unwrap();
        assert_eq!(
            j["draining"].as_bool(),
            Some(false),
            "带错凭据的排空请求**不得**启动排空：{j}"
        );
        assert!(!st.d.has_exited(), "带错凭据不应影响服务端存活");
        st.d.kill();
    })
    .await;
}

/// 轮询**客户端**，等到它真的收到过响应帧为止（返回 `items + batch_frames`）。
///
/// 为什么用**帧计数**而不是字节计数：客户端那四组字节（`resp_bytes` 等）是
/// **"每个响应结束时累加一次"** 的口径（与四组字节同一设计 ✓）⇒ 非 0 时响应已经结束了 ✗；
/// `resp_frames.*` 是**逐帧累加**的活计数器 ✓ ⇒ 它非 0 就是"响应正在流"的铁证 ✓。
async fn wait_client_frames(client: &str, timeout_ms: u64) -> u64 {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    let mut last = 0u64;
    while std::time::Instant::now() < deadline {
        if let Ok(r) = raw_request(client, "GET", "/__dshp/status", &[], b"").await {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&r.body) {
                let f = &v["resp_frames"];
                last = f["items"].as_u64().unwrap_or(0) + f["batch_frames"].as_u64().unwrap_or(0);
                if last > 0 {
                    return last;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    last
}

/// **负向对照**：不做排空、直接硬杀 ⇒ 在途响应**确实**会被切断。
///
/// 没有这条，主判据可能只是"这条响应本来就来得及跑完"——那判的是运气，不是排空 ✗。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hard_kill_mid_stream_truncates_response() {
    guard(async {
        let token_env = [("DSHP_WEBUI_TOKEN", TOKEN)];
        let mut st = setup_full(&[], &[], None, None, &token_env, &[])
            .await
            .expect("启动失败");
        let daddr = server_addr(&st);

        let base_len = st.up.sse_bytes.lock().unwrap().len();
        let body = make_body(40, 0);
        let client = st.client.clone();
        let caddr = st.client.clone();
        let in_flight = tokio::spawn(async move {
            raw_request(
                &client,
                "POST",
                "/v1/messages",
                &[
                    ("content-type", "application/json"),
                    ("x-test-mode", "sse-slow"),
                ],
                &body,
            )
            .await
        });

        // **等到"响应正在传"的确切时刻**再杀。两层等待各有其职：
        // ① 服务端已开流（`streams_inflight`）—— 只等它会杀在"请求还没发完"上 ✗
        //    （实测：outcome=Ok(502) 且 truncated_responses=0 ⇒ 头都没到，判不出切断 ✗）；
        // ② 客户端已收到响应帧（**逐帧累加**的活计数器）—— 这才是"客户端正在收响应" ✓。
        //    ⚠️ 不能用 mock 的 `sse_bytes`：它把整个 body 一次算好 ✗（第 181 轮实测踩过 ✗）。
        let inflight = wait_stream_inflight(&daddr, Some(&bearer()), 5000).await;
        assert!(inflight >= 1, "没等到在途流（{inflight}）");
        let frames = wait_client_frames(&caddr, 5000).await;
        assert!(
            frames > 0,
            "5s 内客户端一个响应帧都没收到（frames={frames}）⇒ 杀下去只是「请求失败」，不是「切断」"
        );

        // 比较基准是这条响应**应有的总长度**（mock 把整个 body 一次算好 ✓，所以它就是全长）。
        // ⚠️ 别改成"杀之前的已发出量"：mock 的 `sse_bytes` 是**一次性算好**的 ✗，
        // 它在排空前就已经是全长 ⇒ 拿它当"已发多少"会写出无效判据（第 181 轮实测踩过 ✗）。
        let full_len = st.up.sse_bytes.lock().unwrap()[base_len..].len();

        // 硬杀（等同"进程消失"）：这正是排空要替代的旧行为
        st.d.kill();

        let outcome = in_flight.await.expect("任务 panic");
        let got_len = match &outcome {
            Ok(resp) => resp.body.len(),
            Err(_) => 0,
        };
        // "没发完"有两种如实表现：**显式错误**（客户端主动截断 ⇒ SDK 看到传输错误）
        // 或**短于应有长度**。两者都算切断；"完整送达"不算 ✓。
        let cut = match &outcome {
            Ok(resp) => resp.status != 200 || resp.body.len() < full_len,
            Err(_) => true,
        };
        assert!(
            cut,
            "硬杀之后在途响应竟然完整送达（{got_len} 字节 / 应有 {full_len}）⇒ \
             主判据无法区分「排空」与「运气」，这组用例的结论不成立"
        );
        let v = st.status().await.unwrap();
        let n = v["truncated_responses"].as_u64().unwrap();
        assert!(
            n >= 1,
            "硬杀必须被记成**截断**（红线观测点），实测 truncated_responses={n}：{v}"
        );
        println!(
            "  [负向对照] 硬杀：客户端已收到 {frames} 帧时切断，最终拿到 {got_len} / 应有 {full_len}，\
             truncated_responses={n}"
        );
    })
    .await;
}
