//! 降级链验收（设计 §10）：**代理应当"降级"，而不是"死掉"**。
//!
//! 这组测试针对 README 里长期挂着的第 1 号缺口——「无重连/降级链 → 不具生产可用性」。
//! 它要证明的性质有两条，缺一不可：
//!
//! 1. **DSHP 链路断掉之后，请求仍然成功且逐字节一致**（降级到 L2 直连上游）；
//! 2. **链路恢复之后能切回 WS 模式**（否则只是把"死掉"换成了"永久降级"）。

mod common;

use common::*;

/// 验收 §10-1：服务端被杀掉之后，客户端必须继续服务，且内容逐字节一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn survives_server_death_and_keeps_serving() {
    guard(async {
        let mut st = setup_resilient(&[], &[]).await.expect("启动失败");

        // 先确认走的是 WS
        let body = make_body(40, 0);
        let e0 = st.echo("/v1/chat/completions", &body).await.unwrap();
        assert_eq!(e0, body, "WS 路径必须逐字节一致");
        let v0 = st.status().await.unwrap();
        assert_eq!(v0["mode"], "ws", "初始应为 WS 模式：{v0}");
        assert_eq!(v0["aead"]["enabled"], true, "WS 模式下必须已加密：{v0}");

        // 杀掉服务端——模拟断线/服务端崩溃
        st.d.kill();

        // 立刻发请求。**这里不应该失败**：客户端要么已降级，要么在请求路径上当场降级。
        let e1 = st.echo("/v1/chat/completions", &body).await.unwrap();
        assert_eq!(e1, body, "服务端挂掉后，直连回退路径也必须逐字节一致");
        let r = &st.up.rec.take()[0];
        assert_eq!(r.body, body, "直连回退时上游收到的 body 必须逐字节一致");

        let v1 = st.status().await.unwrap();
        println!(
            "  [降级] 服务端已杀 → mode={} link_alive={} 降级次数={} 直连请求={}",
            v1["mode"], v1["link_alive"], v1["bypass_switches"], v1["bypass_requests"]
        );
        assert_eq!(v1["mode"], "bypass", "链路断开后应降级为直连：{v1}");
        assert_eq!(v1["link_alive"], false);
        assert!(
            v1["bypass_switches"].as_u64().unwrap() >= 1,
            "应记录到降级：{v1}"
        );
        assert!(
            v1["bypass_requests"].as_u64().unwrap() >= 1,
            "应有请求走直连：{v1}"
        );
        assert_eq!(
            v1["aead"]["enabled"], false,
            "降级后不应声称自己有 AEAD 会话：{v1}"
        );

        // 再多发几次，确认稳定（不是只成功一次）
        for i in 0..3 {
            let b = make_body(20 + i, 0);
            let e = st.echo("/v1/completions", &b).await.unwrap();
            assert_eq!(e, b, "直连模式下第 {i} 次请求仍须逐字节一致");
        }
        let v2 = st.status().await.unwrap();
        assert_eq!(v2["mode"], "bypass", "服务端未恢复前应保持直连：{v2}");
    })
    .await;
}

/// 验收 §10-2：服务端恢复后必须**切回 WS 模式**，而不是永久留在直连。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovers_to_ws_after_server_returns() {
    guard(async {
        let mut st = setup_resilient(&[], &[]).await.expect("启动失败");
        let upstream = st.up.base_url();
        let port = st.dport;

        let body = make_body(30, 0);
        assert_eq!(st.echo("/v1/chat/completions", &body).await.unwrap(), body);

        // 杀服务端 → 降级
        st.d.kill();
        let e = st.echo("/v1/chat/completions", &body).await.unwrap();
        assert_eq!(e, body, "降级期间必须继续可用");
        assert_eq!(st.status().await.unwrap()["mode"], "bypass");

        // 同端口重启服务端
        st.d = respawn_server(port, &upstream).expect("重启服务端失败");

        // 等它切回 WS（退避上限 400ms，给足余量）
        let mut recovered = false;
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            let v = st.status().await.unwrap();
            if v["mode"] == "ws" {
                println!(
                    "  [恢复] 已切回 WS：重连尝试 {} 次，恢复 {} 次，AEAD={}",
                    v["reconnect_attempts"], v["recoveries"], v["aead"]["enabled"]
                );
                assert_eq!(v["link_alive"], true, "切回 WS 后链路必须是活的：{v}");
                assert_eq!(
                    v["aead"]["enabled"], true,
                    "恢复后必须重新建立加密会话（新握手 ⇒ 新密钥）：{v}"
                );
                recovered = true;
                break;
            }
        }
        assert!(recovered, "服务端恢复后客户端应切回 WS 模式");

        // 恢复之后内容仍要逐字节一致（新链路、新会话密钥）
        let b2 = make_body(50, 2);
        let e2 = st.echo("/v1/chat/completions", &b2).await.unwrap();
        assert_eq!(e2, b2, "恢复 WS 之后必须逐字节一致");
        let recs = st.up.rec.take();
        assert!(recs.iter().any(|r| r.body == b2), "上游应收到恢复后的请求");
    })
    .await;
}

/// **未配置 `--upstream-fallback` 时必须明确失败**，而不是悄悄当普通代理用。
///
/// 这条守住的是"降级"与"静默换语义"的边界：没有兜底路径时，客户端应当报错，
/// 让运维知道该配置这一项，而不是让人以为"代理在工作"（其实什么都没省）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_fallback_it_fails_loudly() {
    guard(async {
        // 注意：这里用 setup_with（**不**带 --upstream-fallback）
        let mut st = setup_with(&[], &[]).await.expect("启动失败");
        let body = make_body(20, 0);
        assert_eq!(st.echo("/v1/chat/completions", &body).await.unwrap(), body);

        st.d.kill();
        // 给客户端一点时间发现链路断掉
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;

        let r = raw_request(
            &st.client,
            "POST",
            "/v1/chat/completions",
            &[("content-type", "application/json")],
            &body,
        )
        .await
        .expect("本地连接应仍可完成");
        assert_eq!(r.status, 502, "无兜底路径时应明确 502，而不是假装成功");
        let msg = String::from_utf8_lossy(&r.body);
        assert!(
            msg.contains("upstream-fallback"),
            "错误信息应指出缺少哪一项配置，实际：{msg}"
        );
        println!("  [无兜底] 如预期明确失败：{}", msg.trim());
    })
    .await;
}
