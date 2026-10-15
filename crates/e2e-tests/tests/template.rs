//! M2 验收：响应侧自动模板归纳 + 批量成帧的端到端行为。
//!
//! 这组测试的核心是**两个必须同时成立**的断言：
//!
//! 1. 客户端重组出的字节与上游产出**逐字节一致**（正确性红线，§3.2）；
//! 2. 链路上实际承载的字节（**含 24 字节帧头**）不超过上游原始字节的 10%，
//!    即「省 ≥90%」（M2 验收标准）。
//!
//! 只测其一都不够：第 2 条单独成立可能意味着"省了但省错了"，第 1 条单独成立
//! 则可能意味着"根本没省，全部走了原样透传"。

mod common;

use common::*;

/// 验收 M2-1：SSE 响应经归纳后省 ≥90%，且逐字节一致、仍是流式。
///
/// 批量窗口显式传入，使测量可复现、不随默认值漂移。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_template_induction_saves_90_percent_and_is_byte_exact() {
    guard(async {
        let st = setup_with(&["--sse-batch-ms".to_string(), "150".to_string()], &[])
            .await
            .expect("启动失败");

        let body = make_body(60, 0);
        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/messages",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "sse-many"),
            ],
            &body,
        )
        .await
        .expect("SSE 请求失败");
        assert_eq!(resp.status, 200);

        // 上游实际产出的 SSE 字节
        let expect = st.up.sse_bytes.lock().unwrap().clone();
        assert!(!expect.is_empty(), "mock 应产出 SSE 字节");
        assert_bytes_eq(
            &resp.body,
            &expect,
            "客户端重组出的 SSE 必须与上游产出逐字节一致",
        );

        let v = st.status().await.unwrap();
        assert_eq!(
            v["template_miss"].as_u64().unwrap(),
            0,
            "不得发生模板缺失导致的截断：{v}"
        );

        let raw = v["resp_raw_bytes"].as_u64().unwrap();
        let wire = v["resp_wire_bytes"].as_u64().unwrap();
        let saved = 1.0 - wire as f64 / raw as f64;
        let hdr = v["resp_frames"]["header_bytes"].as_u64().unwrap();
        let defs = v["resp_frames"]["template_defs"].as_u64().unwrap();
        let batches = v["resp_frames"]["batch_frames"].as_u64().unwrap();
        let items = v["resp_frames"]["items"].as_u64().unwrap();
        let def_b = v["resp_breakdown"]["template_def_bytes"].as_u64().unwrap();
        let raw_b = v["resp_breakdown"]["raw_items_bytes"].as_u64().unwrap();
        let var_b = v["resp_breakdown"]["var_bytes"].as_u64().unwrap();
        println!(
            "  [M2 端到端] 上游 SSE {raw} B → 链路 {wire} B = {:.1}%（省 {:.1}%）\n\
               分解：帧头 {hdr} B（{defs} 个 DEF + {batches} 个批量帧 = {items} 项）\
＋模板定义 {def_b} B ＋原样项 {raw_b} B ＋变量槽 {var_b} B",
            wire as f64 / raw as f64 * 100.0,
            saved * 100.0
        );

        assert!(raw > 10_000, "负载应足够长才有统计意义，实际 {raw} B");
        assert!(
            saved >= 0.90,
            "M2 验收：响应方向省 ≥90%（含帧头），实际省 {:.1}%（raw={raw} wire={wire}；\
             帧头 {hdr}／定义 {def_b}／原样 {raw_b}／变量 {var_b}）",
            saved * 100.0
        );

        // 批量成帧不得退化为"整段缓冲"：分片应随上游推送陆续到达
        assert!(
            resp.chunk_times.len() >= 2,
            "应观测到多个分片，实际 {}",
            resp.chunk_times.len()
        );
    })
    .await;
}

/// 验收 M2-2：未识别形态（`[DONE]` 哨兵、非 JSON 载荷）必须原样透传，
/// 代理**无需改代码**。这是「上游无关」的判定标准（§3.1）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrecognized_sse_shapes_pass_through_untouched() {
    guard(async {
        let st = setup().await.expect("启动失败");

        let body = make_body(20, 0);
        // mock 的 sse_out 是**跨请求累积**的，因此按本次请求新增的部分比对
        for mode in ["sse", "sse-many"] {
            let before = st.up.sse_bytes.lock().unwrap().len();
            let resp = raw_request(
                &st.client,
                "POST",
                "/v1/chat/completions",
                &[("content-type", "application/json"), ("x-test-mode", mode)],
                &body,
            )
            .await
            .unwrap_or_else(|e| panic!("{mode} 请求失败：{e}"));
            let all = st.up.sse_bytes.lock().unwrap().clone();
            assert_bytes_eq(
                &resp.body,
                &all[before..],
                &format!("{mode} 必须逐字节一致"),
            );
        }

        let v = st.status().await.unwrap();
        assert_eq!(v["template_miss"].as_u64().unwrap(), 0, "{v}");
    })
    .await;
}

/// 验收 M2-3：模板表按**连接**存活——第二个响应不应再重付归纳样本与 `TEMPLATE_DEF`。
///
/// 这条测试的存在本身就是一条教训：连接级复用是在第 4 轮实现的，但当时的测试只发了
/// 一个请求、根本没有第二个响应可复用，于是「改了却测不出收益」。没有这条测试，
/// 那段代码就是**未被验证**的。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn templates_are_reused_across_responses_on_one_connection() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let body = make_body(30, 0);

        async fn measure(st: &Stack, body: &[u8]) -> (u64, u64, u64, u64, u64) {
            let before = st.up.sse_bytes.lock().unwrap().len();
            let resp = raw_request(
                &st.client,
                "POST",
                "/v1/messages",
                &[
                    ("content-type", "application/json"),
                    ("x-test-mode", "sse-many"),
                ],
                body,
            )
            .await
            .expect("请求失败");
            let all = st.up.sse_bytes.lock().unwrap().clone();
            assert_bytes_eq(&resp.body, &all[before..], "每个响应都必须逐字节一致");
            let v = st.status().await.unwrap();
            (
                v["resp_frames"]["template_defs"].as_u64().unwrap(),
                v["resp_wire_bytes"].as_u64().unwrap(),
                v["resp_raw_bytes"].as_u64().unwrap(),
                v["resp_breakdown"]["raw_items_bytes"].as_u64().unwrap(),
                v["template_miss"].as_u64().unwrap(),
            )
        }

        // 第一个响应：需要归纳（1 个样本 + 1 个 TEMPLATE_DEF）
        let (defs_1, wire_1, raw_1, raw_items_1, miss_1) = measure(&st, &body).await;
        assert!(defs_1 >= 1, "首个响应必须下发模板定义，实际 {defs_1}");
        assert_eq!(miss_1, 0, "不得发生模板缺失");

        // 第二个响应：主体模板（content_block_delta）应按连接复用，但
        // **每响应只出现一次的事件**（message_stop）此时才凑够第二个观测，
        // 会被归纳出来并多下发一个 DEF。这是归纳需要两个样本的必然结果，
        // 不是缺陷：它为后续每个响应省下一次原样发送，约第 4 个响应起回本。
        let (defs_2, wire_2, raw_2, raw_items_2, miss_2) = measure(&st, &body).await;
        assert!(
            defs_2 - defs_1 <= 1,
            "第二个响应最多只应为「单例事件」新下发 1 个 DEF，实际新增 {}",
            defs_2 - defs_1
        );
        assert_eq!(miss_2, 0, "不得发生模板缺失——否则说明两侧认知已经不一致");
        assert!(
            raw_items_2 == raw_items_1,
            "第二个响应不应再出现「归纳样本」原样项：{raw_items_1} → {raw_items_2}"
        );

        // 第三个响应：所有骨架都已有模板，**不应再有任何 DEF**——这才是连接级复用的证据
        let (defs_3, wire_3, raw_3, raw_items_3, miss_3) = measure(&st, &body).await;
        assert_eq!(
            defs_3, defs_2,
            "第三个响应不应再下发任何模板定义（全部骨架已按连接存活），\
             实际从 {defs_2} 涨到 {defs_3}"
        );
        assert_eq!(miss_3, 0, "不得发生模板缺失");
        assert_eq!(
            raw_items_3, raw_items_2,
            "第三个响应不应有任何原样项：{raw_items_2} → {raw_items_3}"
        );

        let d2_wire = wire_2 - wire_1;
        let d2_raw = raw_2 - raw_1;
        let d3_wire = wire_3 - wire_2;
        let d3_raw = raw_3 - raw_2;
        println!(
            "  [M2 连接级复用] 响应1 {wire_1}/{raw_1} = {:.2}% ｜ 响应2 {d2_wire}/{d2_raw} = {:.2}% ｜ 响应3 {d3_wire}/{d3_raw} = {:.2}%",
            wire_1 as f64 / raw_1 as f64 * 100.0,
            d2_wire as f64 / d2_raw as f64 * 100.0,
            d3_wire as f64 / d3_raw as f64 * 100.0
        );
        assert!(
            d3_wire as f64 / d3_raw as f64 <= 0.10,
            "稳态响应必须满足 ≥90%，实际 {:.2}%",
            d3_wire as f64 / d3_raw as f64 * 100.0
        );
        assert!(
            d3_wire < wire_1,
            "稳态响应应比首个响应更省（一次性成本已被分摊）：{d3_wire} vs {wire_1}"
        );
    })
    .await;
}

/// 非 SSE 响应（普通 JSON）不得被归纳路径影响：必须逐字节一致且不走批量帧。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_sse_response_is_untouched() {
    guard(async {
        let st = setup().await.expect("启动失败");

        let resp = raw_request(&st.client, "GET", "/v1/models", &[], b"")
            .await
            .expect("请求失败");
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.body, br#"{"ok":true,"note":"mock upstream"}"#,
            "非 SSE 响应必须原样回传"
        );

        let v = st.status().await.unwrap();
        let raw = v["resp_raw_bytes"].as_u64().unwrap();
        let wire = v["resp_wire_bytes"].as_u64().unwrap();
        assert!(
            wire >= raw,
            "非 SSE 路径没有归纳收益，链路字节不应少于原文（raw={raw} wire={wire}）"
        );
        assert_eq!(v["template_miss"].as_u64().unwrap(), 0);
    })
    .await;
}

/// `--sse-batch-max`（批大小上限）**必须真的生效**。
///
/// # 为什么值得单独测
///
/// 这个开关此前在全仓库里**没有任何使用点**（测试、脚本、文档都没有）——
/// 也就是说：运维把它调小/调大之后，**没有任何东西能证明行为变了**。
/// 一个"设了没用"的开关比没有这个开关更糟：它让人以为限制已经生效。
///
/// 判据用**批量帧数**：同一份 140 事件的流，上限越小 → 攒满得越快 → 帧数越多。
/// 两条都要逐字节一致（改批大小不许改变内容）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_batch_max_actually_changes_batching() {
    guard(async {
        let body = make_body(60, 0);
        let mut frames = Vec::new();

        // 上限 2 与上限 32（默认值）：同一份上游流
        for cap in ["2", "32"] {
            let st = setup_with(&["--sse-batch-max".into(), cap.into()], &[])
                .await
                .expect("启动失败");
            let resp = raw_request(
                &st.client,
                "POST",
                "/v1/messages",
                &[("content-type", "application/json"), ("x-test-mode", "sse-many")],
                &body,
            )
            .await
            .unwrap_or_else(|e| panic!("sse-batch-max={cap} 请求失败：{e}"));
            assert_eq!(resp.status, 200);

            let expect = st.up.sse_bytes.lock().unwrap().clone();
            assert_bytes_eq(
                &resp.body,
                &expect,
                &format!("sse-batch-max={cap} 时内容仍必须逐字节一致"),
            );

            let v = st.status().await.expect("取 status 失败");
            let n = v["resp_frames"]["batch_frames"].as_u64().unwrap();
            let items = v["resp_frames"]["items"].as_u64().unwrap();
            println!("  [批大小] max={cap}: 批量帧 {n} 个 / 共 {items} 项");

            // **默认值下「帧头占比」的上限**（第 68 轮补，来自设计 §17.2 第 1 条的实测）。
            //
            // 那份实测给出的分解是：小响应（141 项、链路 ~1257 B）里**帧头 408 B ≈ 32.5%**、
            // 变量槽 532 B、模板定义 150 B ⇒ 对"多而小"的响应 **帧头才是最大开销**，
            // 而它由批大小决定。这条断言防的就是"默认批大小被调小 / 退回逐 chunk 成帧"
            // 这类回归：那会让帧数成倍增长、帧头占比冲到 80% 以上。
            //
            // 只在默认值（32）那一轮判；界给得宽松（50%）——**门禁误报比漏报更糟**，
            // 它抓的是数量级回归，不是微调。
            if cap == "32" {
                let hdr = v["resp_frames"]["header_bytes"].as_u64().unwrap();
                let wire = v["resp_wire_bytes"].as_u64().unwrap();
                let share = if wire > 0 { hdr as f64 / wire as f64 } else { 0.0 };
                println!(
                    "  [批大小] 默认值下：帧头 {hdr} B / 链路 {wire} B = {:.1}%（上限 50%）",
                    share * 100.0
                );
                assert!(
                    share > 0.0 && share <= 0.50,
                    "默认批大小下帧头占比 {:.1}%（{hdr}/{wire}）超出上限——\
                     多半是批大小被调小或退回了逐 chunk 成帧",
                    share * 100.0
                );
            }

            frames.push((cap, n, items));
        }

        let (small, big) = (frames[0].1, frames[1].1);
        assert!(
            small > big,
            "把 --sse-batch-max 从 32 调到 2 之后批量帧数没有增加（{small} vs {big}）——\
             这个开关没有生效"
        );
        // 反空转：上限 2 时每帧最多 2 项，帧数与项数的关系必须对得上
        let items = frames[0].2;
        assert!(
            small >= items / 4,
            "上限为 2 却只发了 {small} 个批量帧（共 {items} 项）——数值关系对不上，判据可能测的是别的东西"
        );
    })
    .await;
}

/// **模板表必须与连接同生命周期**（第 180 轮修掉的"静默错误内容"）。
///
/// # 背景
///
/// 服务端的归纳器是**每会话**新建的（`llmproxyd::egress::run_session` 里 `Inducer::new`）
/// ⇒ **模板 id 每个会话都从 1 重新开始**。客户端的模板表若**跨会话共用**，会有两类后果：
///
/// * 新会话的 id N **覆盖**老会话的 id N ⇒ 老会话**在途**的帧引用 id N 时会用**新模板**重建
///   ⇒ 拼出"看着正常、其实是错的"字节流 —— M7 红线要防的静默错误内容，而且**不会报错**；
/// * 老会话在途帧里的老 id 在新会话的表里查不到 ⇒ `UnknownTemplate` ⇒ 主动截断
///   ⇒ SDK 看到传输错误 ⇒ harness 报 `terminated`（线上现象）。
///
/// 现场对账：客户端一共收到 70 个 def、表里只剩 21、`evicted=0` —— 70 是各会话之和，
/// 21 是**单会话内**不同 id 的个数，而 `evicted=0` 正好排除了"被 LRU 淘汰"这条解释。
///
/// # 本条钉住哪一半
///
/// 钉住**可确定断言**的那一半：重连之后，表里应当**恰好**只剩**新会话**的模板
/// （`held == 新会话收到的 def 数`）。共用表会让老会话那一份也留在表里（份数更多）⇒ 这里必红 ✓。
/// 两次会话**故意用不同形态**（第一会话多、第二会话少），否则两份份数可能相同、差不开 ✓。
///
/// "在途帧"那一半需要"旧会话还活着的同时就完成重连"，构造上不确定 ⇒ 由作用域修复一并覆盖
/// （旧 link 连同它的表一起被整体丢弃，不会再被拿去解新会话的帧）。
/// 等链路真的建立，并把"链路已建立"当成**显式前提**报出来。
///
/// 为什么不用夹具里那个 `wait_for_link`：它等不到时只**报警告、不致命**
/// ⇒ 后续断言只会看到一个含义模糊的 502（"链路不可用且未配置 --upstream-fallback"），
/// 而真正的原因是"链路压根还没建起来"。第 180 轮在 GitHub 的共享 runner 上就是这么红的：
/// 重连（发现断链 + 一次失败尝试 + 退避重试）超过了它 5 秒的预算。
///
/// 这里给 30 秒，并把超时写成"前提不成立"，让失败原因一眼可读。
async fn wait_link_up(st: &Stack, which: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let v = st.status().await.unwrap();
        if v["link_alive"] == true {
            return;
        }
        last = v.to_string();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    panic!("{which}：30s 内链路仍未建立 ⇒ 下面的请求只会拿到 502（前提不成立）：{last}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn template_store_is_scoped_to_one_session() {
    guard(async {
        let mut st = setup().await.expect("启动失败");
        let body = make_body(40, 0);
        let client = st.client.clone();
        let ask = |mode: &'static str| {
            let client = client.clone();
            let body = body.clone();
            async move {
                raw_request(
                    &client,
                    "POST",
                    "/v1/messages",
                    &[("content-type", "application/json"), ("x-test-mode", mode)],
                    &body,
                )
                .await
            }
        };

        // ---- 第一个会话：问两种形态 ⇒ 归纳出**两个**模板 ----
        // （实测：`sse` 1 个、`sse-many` 再 1 个 ⇒ 合计 2；`sse-slow` 复用、不新增。）
        wait_link_up(&st, "首条会话").await;
        assert_eq!(ask("sse-many").await.expect("请求失败").status, 200);
        assert_eq!(ask("sse").await.expect("请求失败").status, 200);
        let before = st.status().await.unwrap();
        let defs_before = before["resp_frames"]["template_defs"].as_u64().unwrap();
        assert!(
            defs_before >= 2,
            "**前提不成立**：首个会话只归纳出 {defs_before} 个模板 ⇒ 两条会话的份数相同、\
             判据分不开共用表与按连接建表（先用两种形态各问一次）：{before}"
        );
        assert_eq!(
            before["template_store"]["held"].as_u64().unwrap(),
            defs_before,
            "首条会话：收到的 def 应当都在表里：{before}"
        );

        // ---- 换一条会话：同端口重启服务端 ⇒ 归纳器重新从 id 1 开始 ----
        st.d.kill();
        for _ in 0..50 {
            if std::net::TcpStream::connect(("127.0.0.1", st.dport)).is_err() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        let mut server = respawn_server(st.dport, &st.up.base_url()).expect("重启服务端失败");
        wait_link_up(&st, "首条会话").await;

        // ---- 新会话只问**一种**形态 ⇒ 只归纳出 1 个模板；两次会话份数必然不同 ⇒ 判据分得开。
        //      正确性红线仍是逐字节一致。
        // mock 的 `sse_bytes` 是**累加**的（`extend_from_slice`，从不清空）⇒ 只取本次新增的那段
        let base_len = st.up.sse_bytes.lock().unwrap().len();
        let r2 = ask("sse-many").await.expect("重连后的 SSE 请求失败");
        assert_eq!(r2.status, 200);
        let expect = st.up.sse_bytes.lock().unwrap()[base_len..].to_vec();
        assert!(!expect.is_empty(), "mock 应当又产出了一段 SSE 字节");
        assert_bytes_eq(&r2.body, &expect, "重连后的响应仍必须与上游产出逐字节一致");

        let after = st.status().await.unwrap();
        let defs_delta = after["resp_frames"]["template_defs"].as_u64().unwrap() - defs_before;
        let held_after = after["template_store"]["held"].as_u64().unwrap();
        assert!(
            defs_delta > 0,
            "新会话应当也归纳出模板（defs 增量 {defs_delta}）：{after}"
        );
        // **精确判据**：表按连接建 ⇒ 表里应当**恰好**是本会话收到的那些 def。
        // 共用表时老会话的模板会**留下来**（新会话的同号 id 只会*覆盖*它，数目不变大）
        // ⇒ 这里会比本会话的 def 数多出老会话那一份 ⇒ 必红 ✓
        // （第一会话形态更多 ⇒ 两份的份数一定不同 ⇒ 差得开 ✓）。
        assert_eq!(
            held_after, defs_delta,
            "模板表**跨会话共用**了：held={held_after} 而本会话只收到 {defs_delta} 个 def ⇒ \
             老会话的模板还留在表里，新会话的同号 id 会被它顶掉 ⇒ 可能用错模板重建出错误内容"
        );
        assert_eq!(
            after["template_miss"].as_u64().unwrap(),
            0,
            "重连后不得出现模板缺失（那正是 terminated 的来源）：{after}"
        );

        server.kill();
    })
    .await;
}
