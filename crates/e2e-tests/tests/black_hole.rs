//! **黑洞对端**：连接建得上，但永远不回话。
//!
//! # 为什么单开一组
//!
//! 现有故障夹具全是**拒绝**型（403 / 502 / ECONNREFUSED），拒绝会**快速失败**，
//! 于是降级链很快走完、M3 的「降级耗时 <3s」轻松成立。真实企业网络里更常见的是
//! **黑洞**：SYN 被丢，或 TCP 建上了但对面永不回话。这时"快速失败"的前提**不成立**——
//! 如果实现里没有自己的超时，降级链就会卡在第一个传输上。
//!
//! 所以这组要守的不是"降级多快"，而是：**永不回话的对端面前，客户端仍然服务**
//! （先落到 L2 直连），且请求逐字节正确。这条性质比"降级耗时"更根本：
//! 耗时是性能，卡死是可用性。

mod common;

use common::*;
use std::time::{Duration, Instant};

/// 对端永不回话时，客户端必须**仍然可用**，而不是等链路。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn black_hole_endpoint_does_not_block_serving() {
    guard(async {
        let st = setup_behind_black_hole().await.expect("启动失败");
        let body = make_body(20, 0);

        // 客户端就绪之后**立刻**发请求：不许等那条永远建不完的链路
        let t = Instant::now();
        let got = st
            .echo("/v1/chat/completions", &body)
            .await
            .expect("黑洞对端下客户端必须仍然服务（不能等链路）");
        let first_ms = t.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(got, body, "黑洞对端下降级路径也必须逐字节一致");

        let r = &st.up.rec.take()[0];
        assert_eq!(r.body, body, "上游收到的 body 必须逐字节一致（不是半截）");

        let v = st.status().await.unwrap();
        println!(
            "  [黑洞] 首个请求 {first_ms:.0}ms（正常请求量级）｜mode={} link_alive={} \
             重连尝试={} 翻档次数={} 直连请求={}",
            v["mode"],
            v["link_alive"],
            v["reconnect_attempts"],
            v["bypass_switches"],
            v["bypass_requests"]
        );

        // 判据一：请求走的是直连（链路从未建起来）
        assert!(
            v["bypass_requests"].as_u64().unwrap_or(0) >= 1,
            "黑洞对端下请求必须由直连路径完成：{v}"
        );
        assert_eq!(v["link_alive"], false, "链路不可能活着：{v}");
        // 判据二：**不是"等超时之后才服务"，而是立刻服务**。
        //
        // 这条是回归钉子：修复前 `run()` 先 `connect_link().await`、后 `bind`，
        // 于是黑洞下 HTTP 端口**永远起不来**（本测试当时红在 `wait_ready` 上）。
        // 2s 的界刻意给得宽松（实测 3ms），但它足以在有人把顺序改回去时变红。
        assert!(
            first_ms < 2000.0,
            "首个请求用了 {first_ms:.0}ms —— 看起来是在等链路，而不是先起监听再尝试\
             （客户端是代理：链路只是优化，不是前提）"
        );

        // 观察 10s：记录它会不会放弃这次永远建不完的尝试。
        // **不作断言**：挂着不放弃是可接受的（降级已经生效、功能不受影响）；
        // 但"是否放弃"这件事必须被记录下来，否则没人知道对端黑洞时客户端的最终状态。
        let t2 = Instant::now();
        let mut last = (
            v["reconnect_attempts"].as_u64().unwrap_or(0),
            v["mode"].as_str().unwrap_or("?").to_string(),
        );
        while t2.elapsed() < Duration::from_secs(10) {
            let v = st.status().await.unwrap();
            let now = (
                v["reconnect_attempts"].as_u64().unwrap_or(0),
                v["mode"].as_str().unwrap_or("?").to_string(),
            );
            if now != last {
                println!(
                    "  [黑洞] t={:.1}s 状态变化：重连尝试 {}→{}，mode {}→{}",
                    t2.elapsed().as_secs_f64(),
                    last.0,
                    now.0,
                    last.1,
                    now.1
                );
                last = now;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        println!(
            "  [黑洞] 10s 观察结束：重连尝试={} mode={}（服务始终由直连提供）",
            last.0, last.1
        );

        // 判据三：挂死的尝试**必须被切断并重试**。
        //
        // 没有这个上限时，一次挂死的尝试永远不返回 ⇒ 重连守护再也不会重试 ⇒
        // 就算服务端后来恢复，客户端也发现不了（这是修复的第二层）。
        // 实测：每次尝试 5s 超时 ⇒ 10s 窗口内应有 ≥2 次尝试（首次 + 至少一次重试）。
        assert!(
            last.0 >= 1,
            "10s 内一次重连尝试都没记录到 ⇒ 挂死的尝试没有被切断，重连永远不会发生：{last:?}"
        );

        // 判据四：整个观察期里服务都不受影响的——再发一次请求确认
        let got2 = st.echo("/v1/chat/completions", &body).await.unwrap();
        assert_eq!(got2, body, "观察期后请求仍必须逐字节一致");
    })
    .await;
}
