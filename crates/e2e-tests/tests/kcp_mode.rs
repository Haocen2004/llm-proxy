//! M4 验收：**KCP 模式下整条链路必须与直连逐字节一致**。
//!
//! # 这组测试要证明什么
//!
//! KCP 的三块（ARQ / FEC / 抗放大握手）各自都有单元测试，但"各自测通"不等于
//! "拼起来能用"——`crates/llm-proxy-transport` 里的 `kcp_link` 测试只证明了
//! **传输层**能搬字节。这里要证明的是：把这套传输换成 KCP 之后，
//! 上面那整条 DSHP 逻辑（握手、增量、块缓存、模板、压缩）**行为完全不变**。
//!
//! # 为什么必须显式断言 `mode == "kcp"`
//!
//! 只断言"内容对"是不够的：链路建不起来时会**静默降级**到直连，内容照样是对的，
//! 测试照样绿——但 KCP 一个字节都没走。这类"测试通过、功能没生效"的假阳性
//! 比测试失败更难发现。

//! # 状态与历史（这几行曾经全部是**过期**的，值得留个记录）
//!
//! 这里原先写着「整组测试 ignored / 已知失败 / 根因未定位 / 标为 `ignore` /
//! README 缺口表里也记着它」。但逐条核对下来**五条陈述里没有一条还成立**：
//!
//! | 原注释说 | 实际 |
//! |---|---|
//! | 整组标为 ignored | 文件里**没有任何 `#[ignore]`**，CI 每次都在跑 |
//! | 已知失败、根因未定位 | 根因**早已定位并修复**（窗口探测被实现成"空载荷 PUSH 段"，真实 KCP 用 `WASK`；见 README「KCP 进展」） |
//! | 90s 挂住 | 那次症状描述的正是修复前的行为 |
//! | 不要删除、标成 ignore | 判据没变，测试一直在守那条路径 |
//!
//! **为什么要写这段**：一条说"这组测试是禁用的/坏的"的注释，会让后来者要么
//! 不再信任这套测试、要么照着注释把 `#[ignore]` 加回去——**把已经修好的回归
//! 防线关掉**。文档说错了和代码写错了一样有害，只是更隐蔽。
//!
//! # 现状（实测）
//!
//! * 本组**在 CI 里正常跑**（不是 ignored）；
//! * 曾经有 **1/38（≈2.6%）的偶发失败**，全部落在**建链阶段**：那次的
//!   `kcp_stack()` 花了 12.4s（正常 5.2s）。最可能是 `free_udp_port()` 的端口竞态
//!   （bind 一下拿到号就关掉，之后才让代理去 bind）——旁证是**只有 KCP 测试用
//!   UDP 端口**，也只有它偶发；
//! * 已加固 `kcp_stack()`：**等到真的进 KCP 模式才返回**，并在建链失败时换端口重试
//!   （最多 3 次）。**判据一条都没放宽**——重试的是建链，不是被测行为。

mod common;

use common::*;
use std::time::Duration;

/// 起一个带 KCP 监听的栈，并强制客户端走 KCP。
///
/// # 为什么要「等到真的进了 KCP 模式」才返回，以及为什么要重试建链
///
/// 端到端跑这套测试时出现过**偶发失败**：实测 **1/38（≈2.6%）**，而且全部落在
/// **建链阶段**——那次的 `kcp_stack()` 花了 12.4s（正常 5.2s），像是等就绪超时；
/// 文件头早期记的"连过两次、第三次挂住"也是同一类症状。
///
/// 最可能的原因是 `free_udp_port()` 的竞态：它 bind 一下拿到端口号就**关掉**，
/// 之后才让代理去 bind 同一个端口，中间另一个进程完全可以把这个端口拿走。
/// 两条旁证都对得上：**只有 KCP 测试用 UDP 端口**，也只有**它**偶发。
///
/// 这里做两件事，**判据一条都没放宽**：
///
/// 1. **等到 `mode == "kcp"` 才返回**——把"链路没建起来"从测试体深处的随机断言失败，
///    变成明确的前置失败，并带上 status 以便定位；
/// 2. 建链没成功就**换个端口重试**（最多 3 次）。重试的是**建链**，不是被测行为。
async fn kcp_stack() -> Stack {
    let mut last = String::from("（没拿到 status）");
    for attempt in 1..=3 {
        // **必须是 UDP 端口**——TCP 空闲不代表 UDP 空闲，两者是独立的命名空间
        let kport = free_udp_port().await;
        let kaddr = format!("127.0.0.1:{kport}");
        let st = setup_with(
            &["--kcp-bind".into(), kaddr.clone()],
            &[
                "--kcp-server".into(),
                kaddr,
                "--force-mode".into(),
                "kcp".into(),
            ],
        )
        .await
        .expect("启动失败");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            if let Ok(v) = st.status().await {
                if v["mode"] == "kcp" {
                    return st; // 落在 st 上，进程随它一起活
                }
                last = v.to_string();
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        eprintln!("  [KCP 建链] 第 {attempt} 次未进 KCP 模式，换端口重试；status={last}");
        // st 在此作用域结束处 drop，`Proc::drop` 会杀掉两个子进程
    }
    panic!("KCP 链路 3 次都没建起来（不是被测行为失败，是建链失败）；最后一次 status={last}");
}

/// 基本验收：走的是 KCP，且内容逐字节一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kcp_mode_is_byte_exact() {
    guard(async {
        let st = kcp_stack().await;

        let body = make_body(300, 4);
        let e = st
            .echo("/v1/chat/completions", &body)
            .await
            .expect("请求失败");
        assert_eq!(e, body, "KCP 模式下回显必须逐字节一致");

        let v = st.status().await.unwrap();
        assert_eq!(
            v["mode"], "kcp",
            "必须真的走在 KCP 上——内容对但 mode 不是 kcp，说明是静默降级：{v}"
        );
        assert_eq!(v["link_alive"], true, "链路必须是活的");
        println!(
            "  [M4/KCP] mode={} alive={} aead={} 上行实发 {} / 原始 {}",
            v["mode"], v["link_alive"], v["aead"], v["req_wire_bytes"], v["req_raw_bytes"]
        );

        // 上游侧再验一遍：代理内部一致不代表上游收到的一致
        let recs = st.up.rec.take();
        assert_eq!(
            recs.last().expect("上游必须收到请求").body,
            body,
            "上游收到的 body 必须逐字节一致"
        );
    })
    .await;
}

/// **大 body**：必须超过 KCP 的接收窗口（128 段）与多个 FEC 组。
///
/// 这条不是"顺便测个大文件"。KCP 里曾经有过一个只在**在途段数超过窗口**时才显形的
/// 静默错误（窗口探测被实现成空载荷的 PUSH 段，对端把它当数据收下，整个字节流错位）。
/// 小传输的测试**全部通过**，问题藏了很久。
/// 所以这里刻意把数据量压过窗口边界——把那个触发条件钉进端到端测试集。
///
/// # 它现在是**正常跑着的**（下面这几行曾经说反了）
///
/// 这里原先写着「已知失败 / 根因未定位 / 标成 `ignore` / README 缺口表里记着它」。
/// 逐条核对下来没有一条成立：**根因早已定位并修复**（窗口探测必须是 `WASK` 控制段，
/// 不是空载荷的 PUSH 段；见 README「KCP 进展」），文件里**没有任何 `#[ignore]`**，
/// CI 每次都在跑它，缺口表里也没有这一条。
///
/// 保留这段的理由和文件头一样：**一条说"这条测试是坏的/被禁用的"的注释，
/// 会让人照着它把 `#[ignore]` 加回去，把已经修好的回归防线关掉。**
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kcp_mode_handles_bodies_larger_than_the_window() {
    guard(async {
        let st = kcp_stack().await;

        // 约 400 KB：**必须超过** KCP 的一个窗口（128 段 × 1176 B ≈ 150 KB），
        // 但**不能超过** `MAX_FRAME_BYTES`(1 MiB)——那是另一个限制，超了会被
        // 传输层主动断开（`Kcp::send` 的长度守卫），测的就不是窗口边界了。
        let body = make_body(320, 8);
        assert!(
            body.len() > 300 * 1024,
            "这条测试的前提是 body 足够大（实际 {} B）",
            body.len()
        );

        let e = st
            .echo("/v1/chat/completions", &body)
            .await
            .expect("请求失败");
        assert_eq!(
            e.len(),
            body.len(),
            "长度不一致说明中间丢了一段（实测 {} vs {}）",
            e.len(),
            body.len()
        );
        assert_eq!(e, body, "大 body 必须逐字节一致——错位就是静默错误");

        let v = st.status().await.unwrap();
        assert_eq!(v["mode"], "kcp", "大 body 也必须走在 KCP 上：{v}");
        println!(
            "  [M4/KCP 大body] {} B 往返一致，上行实发 {} B（{:.1}%）",
            body.len(),
            v["req_wire_bytes"],
            100.0 * v["req_wire_bytes"].as_f64().unwrap() / v["req_raw_bytes"].as_f64().unwrap()
        );
    })
    .await;
}

/// KCP 模式下**增量复用**必须照常生效——换传输方式不该影响上层逻辑。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kcp_mode_still_reuses_blocks() {
    guard(async {
        let st = kcp_stack().await;

        let body_a = make_body(300, 0);
        let body_b = make_body(300, 2);
        let e0 = st
            .echo("/v1/chat/completions", &body_a)
            .await
            .expect("首次失败");
        assert_eq!(e0, body_a);
        let w0 = st.status().await.unwrap()["req_wire_bytes"]
            .as_u64()
            .unwrap();

        let e1 = st
            .echo("/v1/chat/completions", &body_b)
            .await
            .expect("二次失败");
        assert_eq!(e1, body_b);
        let v = st.status().await.unwrap();
        let w1 = v["req_wire_bytes"].as_u64().unwrap();

        let ratio = (w1 - w0) as f64 / body_b.len() as f64;
        println!(
            "  [M4/KCP 增量] body {} B，增量请求实发 {} B = {:.3}%  复用块 {}  mode={}",
            body_b.len(),
            w1 - w0,
            ratio * 100.0,
            v["ref_blocks"],
            v["mode"]
        );
        assert_eq!(v["mode"], "kcp");
        assert!(
            ratio <= 0.05,
            "KCP 模式下增量占比 {:.3}% 超过 5% 上限——换传输方式不该让上层退化",
            ratio * 100.0
        );
        let recs = st.up.rec.take();
        assert_eq!(recs[0].body, body_a, "上游第 1 个 body 不一致");
        assert_eq!(recs[1].body, body_b, "上游第 2 个 body 不一致");
    })
    .await;
}
