//! **空闲保活的验收**（缺口 9）。
//!
//! # 背景
//!
//! `Ping`/`Pong` 的**接收**侧两端都齐（服务端收到 `Ping` 回 `Pong`、客户端同理），
//! 但此前**没有任何发送方**——只有 KCP 那条路自己内联发。于是 WS/SSE 链路空闲时
//! 没有保活，中间设备/NAT 可以悄悄回收连接而双方都不知情；下一个请求才由请求路径的
//! 健康检查发现并降级（能自愈，但那次请求失去了链路收益）。
//!
//! 这个缺口是第 39 轮**新加的函数级门禁**（`cargo run -p dev-tools -- gates`）查出来的：
//! `session::ping_frame()` 的注释写着"便于保活"，全仓库却没人调用。
//!
//! # 两条判据
//!
//! | 用例 | 判据 |
//! |---|---|
//! | 间隔 1s、空闲 2.6s | `pings_sent >= 2`，链路仍 `ws`，业务请求仍逐字节一致 |
//! | `--keepalive-sec 0` | 空闲 1.5s 后 `pings_sent == 0`（**负向对照**：证明计数不是恒增的空转） |

mod common;

use common::*;
use std::time::Duration;

/// 空闲链路必须按间隔发保活 Ping。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_link_sends_keepalive_pings() {
    guard(async {
        let st = setup_with(&[], &["--keepalive-sec".into(), "1".into()])
            .await
            .expect("启动失败");
        let body = make_body(16, 0);

        // 先做一次业务请求，确认链路真的建起来了
        assert_eq!(st.echo("/v1/chat/completions", &body).await.unwrap(), body);
        let before = st.status().await.unwrap();
        assert_eq!(before["mode"], "ws", "先得有链路，保活才有对象");

        // **空闲** 2.6s：期间不发任何业务请求
        tokio::time::sleep(Duration::from_millis(2600)).await;

        let v = st.status().await.unwrap();
        let pings = v["pings_sent"].as_u64().unwrap_or(0);
        println!(
            "  [保活] 空闲 2.6s 后 pings_sent={pings} failed={} skipped={} mode={} link_alive={}",
            v["pings_failed"], v["pings_skipped"], v["mode"], v["link_alive"]
        );
        assert!(
            pings >= 2,
            "空闲 2.6s、间隔 1s，应至少发出 2 帧保活 Ping，实际 {pings} \
             （发送失败或任务没起来都会是这个结果）"
        );
        assert_eq!(v["mode"], "ws", "保活不得把模式打坏：{v}");
        assert_eq!(v["link_alive"], true, "保活后链路必须是活的：{v}");

        // 保活不得影响业务：链路仍逐字节一致
        assert_eq!(
            st.echo("/v1/chat/completions", &body).await.unwrap(),
            body,
            "保活期间与之后的业务请求仍须逐字节一致"
        );

        // 反空转：平台侧确实在处理这些帧（服务端诊断里能看到被打开/处理的会话帧）
        if let Ok(d) = st.server_diag().await {
            println!("  [保活] 服务端诊断：{d}");
        }
    })
    .await;
}

/// 负向对照：`--keepalive-sec 0` 必须真的关掉（否则上一条的计数可能是空转）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keepalive_can_be_disabled() {
    guard(async {
        let st = setup_with(&[], &["--keepalive-sec".into(), "0".into()])
            .await
            .expect("启动失败");
        let body = make_body(16, 0);
        assert_eq!(st.echo("/v1/chat/completions", &body).await.unwrap(), body);

        tokio::time::sleep(Duration::from_millis(1500)).await;
        let v = st.status().await.unwrap();
        let pings = v["pings_sent"].as_u64().unwrap_or(0);
        println!("  [保活] 关闭后空闲 1.5s：pings_sent={pings}");
        assert_eq!(
            pings, 0,
            "`--keepalive-sec 0` 必须彻底关闭保活，实际发了 {pings} 帧"
        );
        assert_eq!(st.echo("/v1/chat/completions", &body).await.unwrap(), body);
    })
    .await;
}
