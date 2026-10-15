//! **并发流上限的作用域**（缺口 11）：设计说"上限 4（硬限，保护内存）"。
//!
//! **第 112 轮起已改为进程级** ✓：信号量挂在 `App.slots` 上 ⇒ **全局 ≤ 4** ✓。
//! 下面这几段描述的是**修改前**的状态 ✗，保留它是为了记住"为什么必须改" ✓：
//!
//! 而实现是**每连接** 4 条。
//!
//! # 这一条在测什么
//!
//! `MAX_CONCURRENT_STREAMS = 4` 的信号量建在 `run_session` 里 ⇒ **每个 DSHP 连接**
//! 各有一份额度。于是：
//!
//! * 单客户端：最多 4 条在途 ✓（`budget.rs` 已覆盖，行为正确）；
//! * **多客户端**：N 个客户端可以同时有 4N 条在途 ✗ —— 而设计 §12 把这 4 条
//!   描述为"保护内存"的硬限（未加"每连接"限定），§13.10 又把它列为 DoS 防护。
//!   按这个描述读，上限应当是**服务端全局**的。
//!
//! 这条测试**不去判定哪种语义对**（改成全局会带来跨客户端的排队与队头阻塞，
//! 是另一面的权衡），而是把事实固定下来：服务端的**全局在途数**可以超过 4。
//! 已记为 README 缺口 11，等设计定夺。
//!
//! ⚠️ **上面这两句是"修改前"的陈述** ✓ —— 缺口 11 **已定夺并实现** ✓（第 112/116 轮）：
//! 上限已改为**进程级** ✓，本文件第二条测试 `the_stream_limit_is_global_and_is_actually_reached`
//! 就是它的守门人 ✓（**两侧判据**：不超上限 ✓ 且必须达到上限 ✓）。
//!
//! 判据用的是服务端诊断里的**全局** `streams_inflight`（它跨会话累加），
//! 不是单会话的额度——两者在只有一个客户端时数值相同，**多客户端时才分叉**，
//! 这正是要展示的差别。

mod common;

use common::*;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// **缺口 11 · 下半：连接数上限**（第 114 轮）。两侧判据缺一不可 ✓：
///
/// * **不超限**：先握住 `MAX_CONNECTIONS` 条裸 TCP 连接（**不握手** ✓ —— 上限在 accept 处生效 ✓）；
/// * **超限时立刻失败**：第 N+1 条**仍能完成 TCP 握手**（三次握手发生在 accept 之前 ✓），
///   但服务端**立刻关掉**它 ⇒ 读返回 0（或复位 ✓）—— **不是挂住** ✗。
///   这一条才是关键：把它留在 backlog 里会变成"看起来连得上、其实永远没人处理" ✗✗，
///   那比明确拒绝更糟 ✓。判据是"读在 3 秒内**返回**" ✓：既处理又不关闭就会超时 ⇒ 红 ✓。
///
/// 注：`connect` 必须传 `&format!(…)` ✓（`&String` 解引用成 `&str` 才实现 `ToSocketAddrs`；
/// 传 `String` 会报 `u16: ToSocketAddrs` 这类看不懂的错 ✗ —— 第 113 轮我在同一处栽过 ✓）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_connection_cap_closes_the_excess_immediately() {
    use tokio::io::AsyncReadExt;

    guard(async {
        let st = setup_with(&[], &[]).await.expect("起链路失败");
        let limit = llm_proxy_core::config::MAX_CONNECTIONS;
        let addr = format!("127.0.0.1:{}", st.dport);
        let mut held = Vec::new();
        for i in 0..limit {
            match tokio::net::TcpStream::connect(&addr).await {
                Ok(s) => held.push(s),
                Err(e) => panic!("第 {i} 条连接就失败了（上限是 {limit}）：{e}"),
            }
        }
        println!("  [缺口11·下半] 已握住 {limit} 条裸 TCP 连接（未握手，上限在 accept 处生效）");

        let mut extra = tokio::net::TcpStream::connect(&addr)
            .await
            .expect("超限那条应当仍能完成 TCP 握手（否则测的是 backlog，不是我们的上限）");
        let mut buf = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(3), extra.read(&mut buf)).await {
            Err(_) => panic!("超限连接被**挂住**了 ✗ —— 服务端既没处理也没关闭"),
            Ok(Ok(0)) => println!("  [缺口11·下半] 超限连接被立刻关闭（读到 EOF ✓）"),
            Ok(Ok(_)) => panic!("超限连接竟然收到了数据"),
            Ok(Err(e)) => println!("  [缺口11·下半] 超限连接被复位（明确失败 ✓）：{e}"),
        }

        // **额度随会话释放**：用服务端的可观测计数判 ✓，不猜时间 ✗。
        //
        // 第 115 轮我在这里**量错过一次** ✗：只放 1 条就去看计数、结论是"没释放" ✗ ——
        // 其实是算术没做对 ✓：握 62 条 + 读状态 1 条 + **夹具自带的客户端链路 1 条** = 64 ✓✓
        // ⇒ **放出来的额度被新需求正好填满** ✓，计数当然不降 ✓。
        // ⇒ 正确做法是让**释放量明显大于需求量** ✓：一次放 10 条 ⇒ 计数应掉到 54 上下 ✓。
        //
        // 两侧判据都要 ✓：既"**确实下降**"（释放 ✓），又"**仍不超上限**"（不越界 ✓）。
        for _ in 0..10 {
            held.pop();
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut now = u64::MAX;
        while Instant::now() < deadline {
            now = raw_request(
                &format!("127.0.0.1:{}", st.dport),
                "POST",
                "/__dshp/status",
                &[],
                b"",
            )
            .await
            .ok()
            .and_then(|r| serde_json::from_slice::<serde_json::Value>(&r.body).ok())
            .and_then(|v| v["conns_inflight"].as_u64())
            .unwrap_or(u64::MAX);
            if now <= (limit - 10) as u64 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        println!(
            "  [缺口11·下半] 一次放掉 10 条后，服务端 conns_inflight={now}（上限 {limit}）\
             —— 下降即证明额度**随会话释放** ✓"
        );
        // 这条判据按**真实语义**写 ✓：放 10 条 ⇒ 实测落到 56（不是 54）✓ ——
        // 因为这次轮询本身又要占 1 条、夹具的客户端链路也占 1 条 ✓（各 +1 ✓）。
        // 所以判"**显著下降**"（留 5 条余量 ✓），而不是钉死一个数字 ✗ ——
        // 钉死数字只是把"测量环境"写进判据，环境一变就假红 ✗。
        assert!(
            now <= (limit - 5) as u64,
            "放掉 10 条后 conns_inflight 仍为 {now}（上限 {limit}）⇒ 额度没有随会话释放 ✗"
        );
        assert!(now < limit as u64, "计数不该达到/超过上限且不降 ✗");
    })
    .await;
}

/// **缺口 11 的字节级实测**：单连接上 4 条大请求同时在途，服务端到底缓冲了多少。
///
/// 设计 §12 把「并发响应流上限 4」写成「硬限，保护内存」，而第 70 轮查出：
/// 每流上限 `MAX_DECOMPOSE_BYTES = 8 MiB`、每连接 4 条 ⇒ **单连接最坏 32 MiB**，
/// 已经贴着设计自己写的 RSS 预算（32 MiB）⇒ 这条上限**限不住**内存。
///
/// 这条测试把"最坏情形"**真的构造出来**（不是纸上算术）：同一连接上 4 条 6 MiB 的请求
/// 挂在"永不回话"的上游上，然后看服务端的在途数。断言"它能被构造出来且服务端仍正常响应"——
/// 这正是要交给设计定夺的依据。
///
/// 口径（别把两件事混起来）：这里量的是**缓冲字节**，不是 RSS ✗。
/// RSS 要在**目标平台（Linux）**上观测，属外部项；本机（Windows）读不到另一个进程的
/// 工作集，我不编造这个数。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn worst_case_per_connection_buffering_is_reachable() {
    guard(async {
        let st = setup_with(&[], &[]).await.expect("起链路失败");
        let limit = llm_proxy_core::config::MAX_CONCURRENT_STREAMS;
        // 6 MiB：小于 `MAX_DECOMPOSE_BYTES`（8 MiB），因此走增量/压缩路径并被服务端缓冲
        let per_req = 6 * 1024 * 1024usize;
        let body = serde_json::json!({ "messages": [{ "content": "x".repeat(per_req) }] })
            .to_string()
            .into_bytes();
        assert!(body.len() > per_req, "夹具应当确实是大 body：{} B", body.len());

        let mut held = Vec::new();
        for _ in 0..limit {
            let addr = st.client.clone();
            let b = body.clone();
            held.push(tokio::spawn(async move {
                let _ = raw_request(
                    &addr,
                    "POST",
                    "/v1/messages",
                    &[("content-type", "application/json"), ("x-test-mode", "hang")],
                    &b,
                )
                .await;
            }));
        }

        // 等在途数到齐（反空转：否则"最坏情形"只是我们没发出去）
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut inflight = 0u64;
        while Instant::now() < deadline {
            inflight = st
                .server_diag()
                .await
                .ok()
                .and_then(|d| d["streams_inflight"].as_u64())
                .unwrap_or(0);
            if inflight >= limit as u64 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let buffered = body.len() * inflight as usize;
        println!(
            "  [缺口11] 单连接在途 {inflight} 条 × {} B/条 = **缓冲 {:.1} MiB**（每流上限 8 MiB、4 条理论最坏 32 MiB）",
            body.len(),
            buffered as f64 / 1024.0 / 1024.0
        );

        assert!(
            inflight >= limit as u64,
            "同一连接上的 {limit} 条大请求没有全部在途（实测 {inflight}）⇒ 最坏情形没构造出来"
        );

        // 关键：服务端在这种负载下**仍然正常响应**（诊断请求就是一次完整往返）
        let diag = st
            .server_diag()
            .await
            .expect("最坏情形下服务端仍应能响应诊断请求");
        assert_eq!(
            diag["slots_limit"],
            serde_json::json!(limit),
            "每次写死的额度没变"
        );

        for h in held {
            h.abort();
        }
    })
    .await;
}

/// 两个客户端同时打开"挂住不走"的流：服务端**全局**在途数**不会**超过上限 4 ✓（第 112 轮改）。
///
/// 这条同时测**另一半**：上限必须**被达到** ✓ —— 否则"没超过"可能只是"没人发到那么多" ✗，
/// 那是个空转判据 ✓。两侧缺一不可 ✓。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_stream_limit_is_global_and_is_actually_reached() {
    guard(async {
        // 两个**独立**的客户端指向同一个服务端（同一个 upstream）
        let up = MockUpstream::start().await;
        let dport = free_port().await;
        let dargs: Vec<String> = vec![
            "--listen".into(),
            format!("127.0.0.1:{dport}"),
            "--upstream".into(),
            up.base_url(),
            "--max-concurrent-streams".into(),
            llm_proxy_core::config::MAX_CONCURRENT_STREAMS.to_string(),
            "--max-pending-streams".into(),
            "32".into(),
            "--stream-wait-ms".into(),
            "500".into(),
        ];
        let drefs: Vec<&str> = dargs.iter().map(String::as_str).collect();
        let d = spawn_proxy("llmproxyd", &drefs, true).expect("服务端启动失败");
        assert!(
            wait_ready(&format!("127.0.0.1:{dport}"), Duration::from_secs(8)).await,
            "llmproxyd 未就绪"
        );

        let mut clients = Vec::new();
        for _ in 0..2 {
            let cport = free_port().await;
            let cargs: Vec<String> = vec![
                "--listen".into(),
                format!("127.0.0.1:{cport}"),
                "--server".into(),
                format!("ws://127.0.0.1:{dport}"),
                "--upstream-fallback".into(),
                up.base_url(),
            ];
            let crefs: Vec<&str> = cargs.iter().map(String::as_str).collect();
            let c = spawn_proxy("llmproxyc", &crefs, false).expect("客户端启动失败");
            let addr = format!("127.0.0.1:{cport}");
            assert!(
                wait_ready(&addr, Duration::from_secs(8)).await,
                "客户端未就绪"
            );
            clients.push((c, addr, cport));
        }

        let body = make_body(12, 0);
        let limit = llm_proxy_core::config::MAX_CONCURRENT_STREAMS;

        // 每个客户端发 limit 条"永不回话"的请求（用 hang 上游）
        let mut held = Vec::new();
        for (_, addr, _) in &clients {
            for _ in 0..limit {
                let addr = addr.clone();
                let b = body.clone();
                held.push(tokio::spawn(async move {
                    let _ = raw_request(
                        &addr,
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
        }

        // 等上游真的同时接住这么多（反空转：否则"被达到"只是我们没发出去）
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut peak = 0;
        while Instant::now() < deadline {
            peak = up.max_inflight.load(Ordering::Relaxed);
            if peak >= limit {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let diag_addr = format!("127.0.0.1:{dport}");
        let r = raw_request(&diag_addr, "POST", "/__dshp/status", &[], b"")
            .await
            .expect("读服务端状态失败");
        let diag: serde_json::Value = serde_json::from_slice(&r.body).unwrap_or_default();
        let inflight = diag["streams_inflight"].as_u64().unwrap_or(0);
        println!(
            "  [多客户端] 上游并发峰值 {peak}（**全局**上限 {limit}）；\
             服务端全局在途 {inflight}、slots_limit 字段={}",
            diag["slots_limit"]
        );

        // 两侧判据（缺一不可 ✓）：
        assert!(
            peak <= limit,
            "两个客户端共发 {} 条，上游并发峰值 {peak} **超过**了全局上限 {limit} ⇒ 上限不是进程级的",
            2 * limit
        );
        assert_eq!(
            peak, limit,
            "上游并发峰值 {peak} 没达到上限 {limit} ⇒ 这条测试空转了（没人发到那么多）"
        );
        assert!(
            inflight <= limit as u64,
            "服务端全局在途 {inflight} 超过上限 {limit} ⇒ 信号量不是进程级的"
        );
        assert_eq!(
            inflight, limit as u64,
            "服务端全局在途 {inflight} 没达到上限 {limit} ⇒ 空转（两侧判据缺一不可）"
        );

        for h in held {
            h.abort();
        }
        drop(d);
        for (mut c, _, _) in clients {
            c.kill();
        }
    })
    .await;
}
