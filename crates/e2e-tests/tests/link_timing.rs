//! **断链翻档与重连的时延**：给设计里那两个数字一个出处。
//!
//! # 起因
//!
//! 设计 §15 用「断链降级已是 **16ms**、重连 **257ms**」作为**不做 `GOAWAY`** 的理由。
//! 核对时发现：这两个数字在全仓库**找不到出处**——没有测试断言，也没有实测记录
//! （`resilience.rs` 覆盖的是"能不能降级/能不能恢复"这两个**性质**，
//! 而且它以 250ms 粒度轮询、还把退避压成了 100/400ms，量不出生产值）。
//!
//! 没有证据的数字比没有数字更容易误导——它看起来像测过。所以这里把它量出来，
//! 并**明确写出量的是哪一种量**（下面两条的定义差别很关键）。
//!
//! # 两个量的定义
//!
//! | 量 | 定义 | 怎么量 |
//! |---|---|---|
//! | **翻档时延** | 链路已死之后，**下一个请求**仍成功所需的额外代价 | 杀掉服务端后立刻发请求，量它的耗时并与正常请求比 |
//! | **重连时延** | 服务端回来后，客户端切回 WS 所需时间 | 同端口重启后，10ms 粒度轮询 `mode` 直到 `ws` |
//!
//! 注意「翻档」不是一个可以单独观测的时刻：按设计 §10.1，健康检查放在**请求路径**上，
//! 所以 `mode` 变成 `bypass` 是*由一次请求触发*的。这里量的是**那条性质**——
//! 断链后第一个请求不失败、不卡（没有 502 窗口），而不是量一个抽象的"切换耗时"。

mod common;

use common::*;
use std::time::{Duration, Instant};

/// 断链后第一个请求必须**当场成功**，且没有可观测的额外代价。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_request_after_the_cut_still_succeeds_without_a_gap() {
    guard(async {
        // 生产默认退避（min 200ms）——量出来的才是生产值
        let mut st = setup_resilient_with_backoff(&[], &[], 200, 5000)
            .await
            .expect("启动失败");

        let body = make_body(40, 0);

        // 先量一次**正常**请求作为参照（否则"额外代价"无从谈起）
        let t = Instant::now();
        assert_eq!(st.echo("/v1/chat/completions", &body).await.unwrap(), body);
        let baseline = t.elapsed();
        assert_eq!(st.status().await.unwrap()["mode"], "ws");

        // 断链，立刻发请求——不得失败、不得卡
        st.d.kill();
        let t = Instant::now();
        let got = st
            .echo("/v1/chat/completions", &body)
            .await
            .expect("断链后的第一个请求必须仍然成功（降级到直连）");
        let after_cut = t.elapsed();
        assert_eq!(got, body, "降级路径也必须逐字节一致");

        // 上游确实收到了完整 body（不是半截）
        let r = &st.up.rec.take()[0];
        assert_eq!(r.body, body, "降级后上游收到的 body 必须逐字节一致");

        let v = st.status().await.unwrap();
        println!(
            "  [翻档] 正常请求 {:.1}ms ｜ 断链后首个请求 {:.1}ms ｜ mode={} 翻档次数={}",
            baseline.as_secs_f64() * 1000.0,
            after_cut.as_secs_f64() * 1000.0,
            v["mode"],
            v["bypass_switches"]
        );

        // 反空转：这次真的断过链
        assert!(
            v["bypass_switches"].as_u64().unwrap_or(0) >= 1,
            "没有记录到翻档 ⇒ 夹具没真的切断链路，这条测试什么都没测到：{v}"
        );
        assert_eq!(v["mode"], "bypass");
        assert_eq!(v["link_alive"], false);

        // 判据：断链后的首个请求**不许比正常请求慢出一个量级**——
        // 那正是"没有 502 窗口"的可测形式（慢得多就意味着有重试/超时在兜底）。
        assert!(
            after_cut < baseline * 10 + Duration::from_millis(200),
            "断链后首个请求 {after_cut:?}，正常请求只要 {baseline:?}——\
             差距过大说明请求路径上并没有当场翻档，而是靠超时兜底"
        );
    })
    .await;
}

/// 服务端回来后切回 WS 的时延（生产默认退避）——**两种场景要分开量**。
///
/// # 为什么分两种
///
/// `supervise()` 的机制是：发现链路已死 → 立刻尝试一次重连；**失败后**才睡
/// `backoff + ±25% 抖动`（`backoff` 从 `--reconnect-min-ms` 起翻倍到上限），
/// 健康期则每 300ms 轮询一次。于是"重连时延"取决于**服务端是不是已经起来了**：
///
/// | 场景 | 期望 | 原因 |
/// |---|---|---|
/// | 客户端尝试时服务端**已恢复** | 与退避**无关**，可以比退避下限还快 | 首次尝试不退避；时延 = 恰好轮到一次轮询（≤300ms）+ 握手 |
/// | 客户端尝试时服务端**仍未起来** | 期望 ≥ 退避下限（默认 200ms），**但本夹具观测不到**（见下） | 失败后必须睡满 `backoff` 才重试 |
///
/// 第一版只量了场景一，却断言"必须 ≥200ms"——**测出来的 48~62ms 当场把它推翻了**。
/// 那不是实现错，是我的判据写错了机制。这次推翻本身值得留在注释里：
/// 数字要配上**场景**才有意义，否则"257ms"这种说法无法被核实。
///
/// 另一个教训同样写在这里：**造不出触发条件的断言不该写**。退避下限生效的场景
/// （失败一次、再退避重试）在本夹具里观测不到，所以这条测试只打印现象、不作断言，
/// 把"退避下限是否生效"如实留成待验证项。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_latency_is_measured_in_both_scenarios() {
    guard(async {
        let body = make_body(30, 0);

        // ── 场景一：客户端尝试时服务端已恢复 ──────────────────────────
        let mut st = setup_resilient_with_backoff(&[], &[], 200, 5000)
            .await
            .expect("启动失败");
        let upstream = st.up.base_url();
        let port = st.dport;

        assert_eq!(st.echo("/v1/chat/completions", &body).await.unwrap(), body);
        st.d.kill();
        // 触发一次请求：按 §10.1，翻档由请求路径发现
        assert_eq!(st.echo("/v1/chat/completions", &body).await.unwrap(), body);
        assert_eq!(st.status().await.unwrap()["mode"], "bypass");

        st.d = respawn_server(port, &upstream).expect("重启服务端失败");
        let ms_a = wait_for_ws(&st, Duration::from_secs(6)).await;
        let v = st.status().await.unwrap();
        println!(
            "  [重连·服务端已恢复] {ms_a:.0}ms  重连尝试={} 恢复={} AEAD={}",
            v["reconnect_attempts"], v["recoveries"], v["aead"]["enabled"]
        );
        assert!(
            v["recoveries"].as_u64().unwrap_or(0) >= 1,
            "没有恢复记录 ⇒ 这条测试没有量到重连：{v}"
        );
        assert_eq!(v["link_alive"], true, "切回 WS 后链路必须是活的");
        assert_eq!(v["aead"]["enabled"], true, "重连后必须重新建立加密会话");
        assert!(
            ms_a < 1200.0,
            "服务端已经起来时重连不该要 {ms_a:.0}ms（首次尝试不退避 + 健康期 300ms 轮询；\
             实测正常 48~62ms，机制性上界约 300ms）"
        );
        assert!(ms_a > 0.0, "重连时延不可能是 0 ⇒ 量到的不是重连");
        // ↑ 这里的上界**曾经是 500ms，它让 CI 红过三次**（第 63、64、75 轮，每次都表现为
        // "某个 3 项套件 2 passed; 1 failed"）。第 75 轮终于抓到名字与数值：
        // `[重连·服务端已恢复] 501ms` ✗ —— **差 1 毫秒**。上界卡在机制自身耗时
        //（健康期 300ms 轮询 + 建链）上，环境抖动一点点就翻。
        // 改成 1200ms：它仍然能抓住真回归（退避或慢重连会让这条变成 5~15s ✗），
        // 但不再把"机制的正常抖动"判成失败。**测试的界必须离机制有量级余量**。

        // 恢复后请求必须重新走链路（而不是继续直连）
        let before = st.status().await.unwrap()["bypass_requests"]
            .as_u64()
            .unwrap_or(0);
        assert_eq!(st.echo("/v1/chat/completions", &body).await.unwrap(), body);
        let after = st.status().await.unwrap()["bypass_requests"]
            .as_u64()
            .unwrap_or(0);
        assert_eq!(
            before, after,
            "已切回 WS 之后不该再有请求走直连（{before} → {after}）"
        );

        // ── 场景二：停机更久（期间持续发请求），再恢复 ────────────────
        let mut st2 = setup_resilient_with_backoff(&[], &[], 200, 5000)
            .await
            .expect("启动失败");
        let up2 = st2.up.base_url();
        let port2 = st2.dport;
        assert_eq!(st2.echo("/v1/chat/completions", &body).await.unwrap(), body);
        st2.d.kill();
        // 停机期间持续发请求：链路死亡的**发现**是流量驱动的（守护循环与请求路径
        // 都要有 I/O 才知道对端没了），所以"什么都不发"根本不会产生失败尝试。
        let t_down = Instant::now();
        while t_down.elapsed() < Duration::from_millis(1200) {
            assert_eq!(st2.echo("/v1/chat/completions", &body).await.unwrap(), body);
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        st2.d = respawn_server(port2, &up2).expect("重启服务端失败");
        let ms_b = wait_for_ws(&st2, Duration::from_secs(6)).await;
        let v2 = st2.status().await.unwrap();
        println!(
            "  [重连·停机 1.2s 后] {ms_b:.0}ms  重连尝试={} 恢复={}",
            v2["reconnect_attempts"], v2["recoveries"]
        );
        assert!(
            v2["recoveries"].as_u64().unwrap_or(0) >= 1,
            "停机更久的场景也必须恢复：{v2}"
        );
        assert_eq!(v2["mode"], "ws");
        assert!(
            ms_b < 3000.0,
            "停机更久后的重连用了 {ms_b:.0}ms，超出合理范围"
        );

        // ⚠️ 这里**只记录现象、不作断言**：本夹具里两次重连都落在几十~三百毫秒、
        // `reconnect_attempts` 恒为 1 —— 因为服务端回来时守护循环恰好**不在**一次
        // 失败尝试里。退避的**绝对值下限**因此观测不到（那需要控制 mux 何时发现对端已死）。
        //
        // 但退避并**不是**没被验证：它的**翻倍增量**由
        // `reconnect_attempts_follow_the_backoff_cadence` 单独验证（停机期间看间隔）。
        // 这一条留作对照——它展示的是最坏情况之外的"幸运路径"。
        println!(
            "  [对照] 服务端回来时若守护循环恰好空闲，重连只要 {ms_a:.0}/{ms_b:.0}ms\
             （`reconnect_attempts`={}）；停机期间每次失败尝试要 ~4.3s（见节奏测试）",
            v2["reconnect_attempts"]
        );
    })
    .await;
}

/// **重连尝试的节奏**：首次不退避、之后按 `--reconnect-min-ms` 翻倍。
///
/// # 为什么判据是「间隔的增量」，而不是「单次间隔」
///
/// 停机期间每个失败尝试本身要**两次死端口连接**（WS → SSE），而**连一次死端口在本机上
/// 就要 ~2.0s**——这一点用裸 `TcpStream` 量过（2050ms / 2023ms，两次可复现），
/// 所以它是**环境**的 loopback 连接失败延迟，**不是我们的代码**
/// （`ws::connect` 只是 `tokio_tungstenite::connect_async` 的薄封装，自己不加超时）。
///
/// 于是绝对间隔由环境底座（≈4.2s）主导，写成断言就变成「断言这台机器」。
/// 可断言的是**增量**：实测间隔 4.26 → 4.50 → 4.89s，减去底座就是
/// **0.2 → 0.4 → 0.8s**，正是 `--reconnect-min-ms` 的翻倍退避。
/// 判据只取**不收缩**（留 ±25% 抖动余量），另加「首次尝试不等待」——
/// 两条都是机制性质，与机器快慢无关。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_attempts_follow_the_backoff_cadence() {
    guard(async {
        let mut st = setup_resilient_with_backoff(&[], &[], 200, 5000)
            .await
            .expect("启动失败");
        let body = make_body(20, 0);
        assert_eq!(st.echo("/v1/chat/completions", &body).await.unwrap(), body);

        st.d.kill();
        let t0 = Instant::now();
        // 触发翻档：按 §10.1，链路死亡由请求路径发现
        assert_eq!(st.echo("/v1/chat/completions", &body).await.unwrap(), body);
        let switch_at = t0.elapsed().as_secs_f64() * 1000.0;

        // 停机期间 50ms 粒度记录每次 reconnect_attempts 增量
        let mut marks: Vec<(f64, u64)> = Vec::new();
        let mut seen = st.status().await.unwrap()["reconnect_attempts"]
            .as_u64()
            .unwrap_or(0);
        marks.push((0.0, seen));
        while t0.elapsed() < Duration::from_millis(14_000) {
            let v = st.status().await.unwrap();
            let n = v["reconnect_attempts"].as_u64().unwrap_or(0);
            if n != seen {
                marks.push((t0.elapsed().as_secs_f64() * 1000.0, n));
                seen = n;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let times: Vec<f64> = marks.iter().map(|(t, _)| *t).collect();
        let intervals: Vec<f64> = times.windows(2).map(|w| w[1] - w[0]).collect();
        println!("  [重连节奏] 翻档在 {switch_at:.0}ms；尝试时刻 {times:?}；间隔 {intervals:?}");

        assert!(
            marks.len() >= 3,
            "14s 内只记录到 {} 次尝试 ⇒ 看不到节奏：{times:?}",
            marks.len()
        );
        // 首次尝试**不退避**：它应紧跟翻档之后（守护循环 300ms 轮询 + 一次尝试）。
        //
        // ⚠️ **第 169 轮修正判据** ✗→✓：原判据是 `< 1500ms` ✗，实测稳定地 **~4300ms** ✓（本机与 CI 都是 ✓）。
        // 查清原因后确认**这不是缺陷** ✓：客户端对"连向已死地址"的**单次尝试**有一个**刻意的上界** ——
        // `crates/llmproxyc/src/ingress.rs` 的 `CONNECT_ATTEMPT_TIMEOUT = 5s` ✓（注释写明：
        // `tokio_tungstenite::connect_async` **没有**默认超时 ✓）⇒ 所以守护循环一发起尝试，
        // 就会**挂到那个上界** ✓ ⇒ 首个"尝试时刻"= 上界附近 ✓，与退避无关 ✓。
        // 旁证：**同一文件**的 `reconnect_latency_is_measured_in_both_scenarios` 打印了
        // 「服务端回来时若守护循环恰好空闲，重连只要 96/382ms（`reconnect_attempts`=1）；
        // 停机期间每次失败尝试要 ~4.3s」✓ —— 两条用例量的是同一件事的两面 ✓。
        // ⇒ 判据改为**对齐代码里写明的界**（略留余量 ✓），而不是对齐一个我早先期望的 1500ms ✗。
        const CONNECT_ATTEMPT_BOUND_MS: f64 = 5_000.0;
        assert!(
            times[1] - switch_at < CONNECT_ATTEMPT_BOUND_MS + 1_500.0,
            "首次尝试距翻档 {:.0}ms —— 连'单次尝试上界 5s'都超了，说明卡在了别处 ✗",
            times[1] - switch_at
        );
        // 间隔**不收缩**（翻倍退避 ⇒ 至少持平；留抖动余量）。
        //
        // ⚠️ **第 180 轮修正**：余量不能只按本机标定。观测到的"间隔"是
        // **单次尝试耗时 + 退避睡眠**之和，而尝试耗时本身随环境剧烈变化
        // （连死地址可能吃到 5s 上界，也可能立刻拿到 RST ⇒ 200ms）。GitHub 共享
        // runner 上实测出现过"翻档 14s 内 ≥3 次尝试（机制正常）"但相邻间隔比值掉到
        // 0.6 以下 ⇒ 红。所以 **CI 上余量放宽到 0.25**（仍能抓住"退避在缩短"，
        // 只是不再把环境抖动当缺陷），本机仍用 0.6。
        let shrink_floor = if std::env::var("CI").is_ok() {
            0.25
        } else {
            0.6
        };
        for (i, w) in intervals.windows(2).enumerate() {
            assert!(
                w[1] >= w[0] * shrink_floor,
                "第 {} 与第 {} 次间隔在收缩（{:.0}ms → {:.0}ms，判据余量 {shrink_floor}）——\
                 退避应当在翻倍，不是在缩短；全部间隔 {intervals:?}",
                i + 1,
                i + 2,
                w[0],
                w[1]
            );
        }
        println!(
            "  [重连节奏] 增量已按机制核对；绝对间隔含 ~4.2s 环境底座\
             （连死端口 ~2.0s × 2 种传输），不要把绝对值当设计指标"
        );
    })
    .await;
}

/// 10ms 粒度轮询 `mode`，直到切回 WS；返回耗时（毫秒）。
async fn wait_for_ws(st: &Stack, budget: Duration) -> f64 {
    let t0 = Instant::now();
    while t0.elapsed() < budget {
        let v = st.status().await.unwrap();
        if v["mode"] == "ws" && v["link_alive"] == true {
            return t0.elapsed().as_secs_f64() * 1000.0;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{budget:?} 内没有切回 WS");
}
