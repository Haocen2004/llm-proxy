//! **客户端放弃请求时，服务端的并发流槽位必须被释放**。
//!
//! # 为什么值得单独测
//!
//! 服务端的并发流上限是 4（`MAX_CONCURRENT_STREAMS`）。上限本身有验收（`budget.rs`：
//! 超限要**排队**、等不到才拒绝），但那里测的是"正常请求占满槽位"。
//! 缺的是另一面：**客户端中途放弃**（SDK 超时、用户 Ctrl-C、网络抖动导致连接断）
//! 时，服务端那两个资源能不能回收——
//!
//! * 槽位（信号量 permit）：不释放 ⇒ 4 次放弃之后，代理对**所有**请求都只会
//!   排队到超时再拒绝 ⇒ **代理被自己的上限堵死**；
//! * 上游连接：不释放 ⇒ 上游侧看到永远挂着的请求。
//!
//! 这条路径的触发条件是"**放弃**"而不是"失败"：现有夹具里的中断都是
//! **上游**断流（`sse-cut` / `cut-body`），那是上游的错；这里要测的是**客户端**的错
//! ——它连着的代理还活得好好的，只是它自己不等了。两者走的代码路径完全不同。
//!
//! 判据：连续放弃 6 次（> 上限 4）之后，一个**正常**请求仍必须快速成功且逐字节一致。
//! 若槽位泄漏，它会排队 20s（`stream_wait_ms`）再被拒——所以"1s 内成功"这个界
//! 就是泄漏的判据。

mod common;

use common::*;
use std::time::{Duration, Instant};

/// 放弃 6 次（> 上限 4）之后，正常请求仍须立刻成功。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abandoned_requests_do_not_leak_stream_slots() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let body = make_body(20, 0);
        let limit = llm_proxy_core::config::MAX_CONCURRENT_STREAMS;

        // 先确认正常路径可用（基线，也让链路建起来）
        assert_eq!(st.echo("/v1/chat/completions", &body).await.unwrap(), body);

        // 连续发起"慢上游"请求，并在 ~300ms 时**放弃**（drop 掉 future ⇒ 连接断开）。
        // 上游那侧要 1.5s 才回，所以放弃时请求肯定还挂在服务端的槽位上。
        let abandons = limit + 2;
        for i in 0..abandons {
            let fut = raw_request(
                &st.client,
                "POST",
                "/v1/messages",
                &[
                    ("content-type", "application/json"),
                    ("x-test-mode", "slow"),
                ],
                &body,
            );
            let r = tokio::time::timeout(Duration::from_millis(300), fut).await;
            assert!(
                r.is_err(),
                "第 {i} 次请求在上游还没回时就该被我们放弃（超时），却已经完成了"
            );
            // 让服务端有机会处理这次断开
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // 反空转：这些请求确实到达了上游（否则"放弃"发生在别处，测不到槽位）
        let reached = st.up.rec.len();
        assert!(
            reached >= limit,
            "上游只收到 {reached} 次（上限 {limit}）——放弃发生在到达上游之前，\
             这条测试没有测到槽位占用"
        );
        println!(
            "  [放弃] 放弃了 {abandons} 次慢请求，上游见到 {reached} 次，\
             上游侧并发峰值 {}",
            st.up
                .max_inflight
                .load(std::sync::atomic::Ordering::Relaxed)
        );

        // 判据：槽位必须已经回收 ⇒ 正常请求立刻成功
        //
        // 先用服务端诊断把"取消到底走到哪一步"记下来（夹具丢弃子进程日志，
        // 这是唯一通道）：`cancel_frames` 是"帧到没到服务端"的直接证据，
        // `streams_inflight` 是"槽位放没放"的直接证据。
        if let Ok(d) = st.server_diag().await {
            println!(
                "  [放弃] 服务端诊断：cancel_frames={} cancelled_streams={} \
                 streams_inflight={} streams_peak={} dropped_frames={}",
                d["cancel_frames"],
                d["cancelled_streams"],
                d["streams_inflight"],
                d["streams_peak"],
                d["dropped_frames"]
            );
        }
        let t = Instant::now();
        let echoed = st
            .echo("/v1/chat/completions", &body)
            .await
            .expect("放弃若干次之后，正常请求必须仍然成功（槽位不得泄漏）");
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(echoed, body, "槽位回收后的请求也必须逐字节一致");
        println!("  [放弃] 之后的正常请求：{ms:.0}ms");

        // 若槽位泄漏，新请求会在 `stream_wait_ms`（默认 20s）里排队到超时再被拒；
        // 所以"1s 内成功"就是泄漏的判据（正常量级是几十毫秒）。
        assert!(
            ms < 1000.0,
            "放弃之后正常请求用了 {ms:.0}ms —— 看起来在等槽位（默认要等 20s 才拒绝），\
             说明放弃的流把槽位泄漏了"
        );

        let v = st.status().await.unwrap();
        println!(
            "  [放弃] 客户端状态：mode={} link_alive={} 请求={} 增量回退={} \
             **cancel_attempts={} cancel_sent={}**",
            v["mode"],
            v["link_alive"],
            v["requests"],
            v["delta_fallbacks"],
            v["cancel_attempts"],
            v["cancel_sent"]
        );
        assert_eq!(v["mode"], "ws", "放弃请求不该把链路打坏：{v}");
        assert_eq!(v["link_alive"], true, "链路应当仍然活着：{v}");
    })
    .await;
}

/// **上游永不回话**（黑洞上游）时，服务端的两条性质。
///
/// # 缺口 8 的**验收测试**（缺陷已修，本测试已转正）
///
/// 实测（2026-10 本机，4 次放弃 + 轮询 12s）：
///
/// * **性质一 ✓ 成立**：占满槽位后第 5 个请求会被**有界地**拒绝
///   （`--stream-wait-ms 500` ⇒ 实测 1551ms，`502 服务端错误 17：并发流超限`）；
/// * **性质二 ✗ 不成立**：放弃那 4 个请求之后，**12s 内一直没有恢复**——
///   槽位被永久占住（只要上游不回话）。
///
/// # 机制（已由代码确认，不是猜测）
///
/// 两端都**没有**"SDK 端已断开"的信号：
///
/// * 客户端 ingress **没有 Drop 守卫**：SDK 一断，那个 response future 被丢掉，
///   DSHP 流既不 unbind 也不通知对端；
/// * 服务端 `forward` 只**等上游**：客户端那条流死了它根本不知道；
/// * 协议里也**没有任何客户端→服务端的取消帧**（`FrameType` 全部 17 个变体里没有），
///   所以就算客户端本地 unbind，对端也学不到。
///
/// ⇒ 这与项目里那条"**流结束 ≠ 发送完成**"是同一个硬币的另一面：
/// **连接断开 ≠ 流可以回收**。
///
/// # 本轮尝试过修它，**没成功**（如实记录）
///
/// 试的路子是补上协议里缺的那一格：`FrameType::Cancel`（空载荷 + `stream_id`，
/// 与 `Ping` 同构）、客户端在响应体被 drop（= SDK 先走）时发一帧、服务端在"等上游"
/// 的 `select!` 里听它。**基础设施都在了**（两端收发 + 门禁全过），但实测**仍然泄漏**：
/// 用原始对端**显式发 4 帧 `Cancel`** 的隔离实验里，第 5 条流照样被拒
/// （`code=17 并发流超限`）。
///
/// ⇒ 所以问题**不止于"协议少一格"**（我最初的判断过于乐观）：要么那帧没到达
/// "等上游"那处 `select!`（路由到了别处 / 那时 `rx` 已不在读），要么**槽位并不随
/// 那个任务的作用域释放**。两点都还没查清。
///
/// ### 查不清的直接原因（值得记下来）
///
/// 夹具 `spawn_proxy` 把子进程的 `stdout`/`stderr` **全部丢弃**
/// （`Stdio::null()` + 强制 `RUST_LOG=warn`），所以**服务端内部状态观察不到**。
/// 要推进这条缺陷，先得有一条只读诊断通道——例如让服务端在状态里暴露
/// `MAX_CONCURRENT_STREAMS` 的**当前可用额度**（那本来也是运维想看的指标）。
///
/// ### 当前诚实状态
///
/// ### 最终修法（第 46 轮）：**从外部 abort 那条任务**
///
/// 排查到最后发现的关键事实：那 4 个任务**首轮之后就不再被轮询**
/// （100ms 心跳也只跑了一次），所以任何"任务侧监听取消"的机制——无论是 rx 关闭、
/// `Notify` 还是 200ms 轮询——**都不会触发**。既然任务自己醒不过来，
/// 就由**会话循环**拿住它的 `JoinHandle`，收到取消帧时 `abort()`：
/// abort 是外部操作，不要求目标任务在跑；任务被丢弃时 permit 与在途计数
/// 一并释放。
///
/// 实测（本测试）：放弃 4 个之后 **14ms 恢复正常**（修复前 12s 始终不恢复），
/// 在途 4 → 0，`cancel_frames=4`。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hung_upstream_is_bounded_and_releases_slots() {
    guard(async {
        // `stream_wait_ms` 压小，否则第 5 个请求要等 20s 才被拒（验收关心"有界"，
        // 不关心那个界具体多大）
        let st = setup_with(&["--stream-wait-ms".into(), "500".into()], &[])
            .await
            .expect("启动失败");
        let body = make_body(12, 0);
        let limit = llm_proxy_core::config::MAX_CONCURRENT_STREAMS;

        // ⚠️ 第 167 轮：首请求失败时**把两侧状态与上游健康一并打出来** ✗→✓。
        //
        // 为什么必须这样 ✗→✓：这一族"首请求 502"已经追了 **6 轮** ✓（每次换一个用例 ✗）——
        // 服务端日志是空的 ✓、`phases` 有历史噪声 ✓，而**客户端侧与上游侧一直是黑的** ✗
        // ⇒ 我只能看到结果（502）✓，看不到最关键的问题：**请求到底有没有到达上游** ✓。
        match st.echo("/v1/chat/completions", &body).await {
            Ok(r) => assert_eq!(r, body, "第一个 echo 必须逐字节一致 ✓"),
            Err(e) => {
                let cli = st.status().await.unwrap_or_default();
                let srv = st.server_diag().await.unwrap_or_default();
                panic!(
                    "第一个 echo 就失败了 ✗：{e:#}\n\
                     · 上游 mock 收到的请求数 = {}（**0 ⇒ 请求根本没到上游** ✓）\n\
                     · 服务端 diag：streams_inflight={} streams_opened={} received_frames={} cancel_frames={}\n\
                     · 服务端 phases：{}\n\
                     · 客户端 status（全部）：{cli}",
                    st.up.rec.len(),
                    srv["streams_inflight"],
                    srv["streams_opened"],
                    srv["received_frames"],
                    srv["cancel_frames"],
                    srv["phases"],
                )
            }
        }

        // 占满槽位：`limit` 个请求打向"永不回话"的上游，**并发**发起并保持不完成
        let mut held = Vec::new();
        for _ in 0..limit {
            let client = st.client.clone();
            let b = body.clone();
            held.push(tokio::spawn(async move {
                let _ = raw_request(
                    &client,
                    "POST",
                    "/v1/messages",
                    &[
                        ("content-type", "application/json"),
                        ("x-test-mode", "hang"),
                    ],
                    &b,
                )
                .await;
            }));
        }

        // 反空转：确认上游真的同时接住了 limit 条（否则"占满"只是我们的想象）
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let peak = st
                .up
                .max_inflight
                .load(std::sync::atomic::Ordering::Relaxed);
            if peak >= limit {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "5s 内上游并发峰值只到 {peak}，没到上限 {limit} ⇒ 槽位没被占满，\
                 这条测试测不到它想测的东西"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        println!(
            "  [死上游] 上游并发峰值 {}（上限 {limit}），响应体永不产出",
            st.up
                .max_inflight
                .load(std::sync::atomic::Ordering::Relaxed)
        );

        // 性质一：第 limit+1 个请求必须**有界地**被拒，而不是永远排队
        let t = Instant::now();
        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/chat/completions",
            &[("content-type", "application/json")],
            &body,
        )
        .await;
        let waited = t.elapsed().as_secs_f64() * 1000.0;
        let status = resp.as_ref().map(|r| r.status).unwrap_or(0);
        let note = resp
            .as_ref()
            .map(|r| String::from_utf8_lossy(&r.body).to_string())
            .unwrap_or_default();
        println!(
            "  [死上游] 第 {} 个请求：{waited:.0}ms status={status} body={note:.120}",
            limit + 1
        );
        assert!(
            waited < 5000.0,
            "第 {} 个请求等了 {waited:.0}ms —— 槽位被死上游占住时必须有界地拒绝",
            limit + 1
        );
        assert!(
            resp.as_ref().map(|r| r.status != 200).unwrap_or(true),
            "槽位已满时不该给出 200：status={status} body={note}"
        );

        // 性质二：放弃那 4 个挂着死上游的请求 ⇒ 槽位必须释放
        let recv_before = st
            .server_diag()
            .await
            .map(|d| d["received_frames"].as_u64().unwrap_or(0))
            .unwrap_or(0);
        for h in held {
            h.abort();
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        // **增量算术**：放弃窗口里除这 4 帧取消外没有别的帧 ⇒ `received_frames` 的增量
        // 是 4（取消到了）或 0（取消没到）。用它代替猜测。
        let recv_after = st
            .server_diag()
            .await
            .map(|d| d["received_frames"].as_u64().unwrap_or(0))
            .unwrap_or(0);
        let d_after = st.server_diag().await.unwrap_or_default();
        println!(
            "  [死上游] 放弃后收帧 {recv_before} → {recv_after}（增量 {}）\
             cancel_frames={} cancelled_streams={} 在途={}",
            recv_after.saturating_sub(recv_before),
            d_after["cancel_frames"],
            d_after["cancelled_streams"],
            d_after["streams_inflight"]
        );

        // 先**刻画**：放弃之后到底多久才恢复（若永远不恢复，说明取消根本没传播）。
        // 这里轮询 12s，只打印、不判定——判定写在后面。
        let probe = Instant::now();
        let mut recovered_at = None;
        let mut probe_stuck = 0usize;
        while probe.elapsed() < Duration::from_secs(12) {
            // ⚠️ **每次探测必须有超时** ✗→✓（第 160 轮修）：原先直接 `st.echo(…).await` ✓ ——
            // 一旦代理"接下了请求但永不回话" ✗，这一个 `await` 就**永不返回** ⇒ 12s 窗口不走完
            // ⇒ 一路挂到 `guard` 的 90s ✗✗（实测 1/3 概率 ✓）。**假死掩盖了现象本身** ✗。
            let attempt = tokio::time::timeout(
                Duration::from_millis(1500),
                st.echo("/v1/chat/completions", &body),
            )
            .await;
            match attempt {
                Ok(Ok(r)) if r == body => {
                    recovered_at = Some(probe.elapsed().as_secs_f64() * 1000.0);
                    break;
                }
                Ok(_) => {}
                Err(_) => {
                    // 探测自己超时 ⇒ **这正是要抓的时刻** ✓：把服务端 `phases` 打出来
                    // （第 100 轮建那套仪器就是为了"一眼看出每条流卡在哪一步" ✓）。
                    probe_stuck += 1;
                    if probe_stuck == 1 {
                        if let Ok(d) = st.server_diag().await {
                            println!(
                                "  [死上游] ⚠️ 探测超时（1500ms 无响应）—— 在途={} cancel_frames={} \
                                 cancelled_streams={} phases={}",
                                d["streams_inflight"],
                                d["cancel_frames"],
                                d["cancelled_streams"],
                                d["phases"]
                            );
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        if probe_stuck > 0 {
            println!("  [死上游] 探测超时 {probe_stuck} 次（代理『接下了但不回话』 ✗）");
        }
        if let Ok(d) = st.server_diag().await {
            println!(
                "  [死上游] 放弃前收帧={} cancel_frames={} 在途={}",
                d["received_frames"], d["cancel_frames"], d["streams_inflight"]
            );
        }
        match recovered_at {
            Some(ms) => println!("  [死上游] 放弃 4 个之后 {ms:.0}ms 恢复正常"),
            None => println!(
                "  [死上游] 放弃 4 个之后 **12s 内一直没有恢复** —— 槽位被泄漏了\
                 （上游永不回话 ⇒ 服务端一直挂在那 4 条流上）"
            ),
        }

        let t = Instant::now();
        let echoed = st
            .echo("/v1/chat/completions", &body)
            .await
            .expect("放弃挂着死上游的请求之后，正常请求必须仍然成功（槽位不得泄漏）");
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(echoed, body, "槽位回收后的请求也必须逐字节一致");
        println!("  [死上游] 放弃 4 个之后正常请求：{ms:.0}ms");
        assert!(
            ms < 2000.0,
            "放弃挂着死上游的请求之后，正常请求用了 {ms:.0}ms —— 取消没有传播到上游，\
             槽位被泄漏了"
        );
    })
    .await;
}
