//! **夹具的"启动失败 ⇒ 换端口重试"必须真的生效**（第 163 轮加 ✓）。
//!
//! 为什么需要它 ✗→✓：第 161 轮我加了重试逻辑 ✓，但**没法证明它生效** ✗ —— 第 162 轮我做了一次
//! 负向对照，用的输入是"特权端口 1" ✗，结果**这个端口在 Windows 上是可以绑的** ✓ ⇒ 第一次尝试
//! 直接成功了 ⇒ **对照根本没走到重试路径** ✓✗（假阳性对照 ✗）。按第 ③ 条硬规矩：
//! **先问"这个场景能不能构造出来"** ✓ —— 这次先把"必失败的输入"**实测出来**了 ✓：
//!
//! ```text
//!   --listen 一次 + 再一次  ⇒  exit=2  error: the argument '--listen <LISTEN>' cannot be used multiple times
//!   --listen not-an-addr    ⇒  exit=1
//!   --listen 127.0.0.1:99999⇒  exit=1
//!   --no-such-flag          ⇒  exit=2  error: unexpected argument '--no-such-flag' found
//! ```
//!
//! 代价：每次尝试要等 `wait_ready` 的 8s 超时 ✗ ⇒ 本测试约 **24s** ✓（一次性可接受 ✓）。

mod common;

use common::*;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixture_startup_failure_is_retried_and_reported() {
    // ① **必失败的输入**（上面实测过 ✓）：重复 `--listen` ⇒ 服务端 exit=2，端口上什么都起不来 ⇒
    //    `wait_ready` 超时 ⇒ 一次尝试失败 ✓。三次都失败 ⇒ 必须返回错误 ✓，且错误里说明重试过 ✓。
    let extra = vec!["--listen".to_string(), "bogus".to_string()];
    // 用 `match` 而不是 `expect_err` ✗：后者要求 `Stack: Debug` ✓，而它没实现 ✓（实测编译错误 ✓）。
    let msg = match setup_with_psk(&extra, &[], None, None).await {
        Ok(_) => panic!("重复 --listen 时服务端必然起不来 ⇒ 夹具必须报错 ✗"),
        Err(e) => format!("{e:#}"),
    };
    assert!(
        msg.contains("重试 3 次"),
        "错误信息必须说明『重试 3 次』，否则人看不出重试发生过 ✗（实得：{msg}）"
    );

    // ② **反例**（否则上面那次失败可能是别的原因 ✗）：去掉那个多余参数 ⇒ 必须能起来 ✓。
    let ok = setup_with_psk(&[], &[], None, None)
        .await
        .expect("同样的夹具、去掉多余参数后必须能起来 ✓");
    assert!(
        wait_ready(&ok.client, Duration::from_secs(2)).await,
        "起来之后客户端必须可连 ✓"
    );
    // ③ 顺带确认"能在空闲端口上成功"这件事本身 ✓（`start_once` 直接调 ✓，用两个空闲端口 ✓）。
    let d = free_port().await;
    let c = free_port().await;
    assert!(
        start_once(&[], &[], None, None, d, c).await.is_ok(),
        "空闲端口上 start_once 必须成功 ✓"
    );
}
