//! 硬约束的**边界测试**（设计 §12 资源上限 / §13.10 DoS 防护）。
//!
//! # 为什么单独开一个文件
//!
//! `crates/llm-proxy-core/src/config.rs` 是"资源硬约束的唯一真值"，并且已经有一道
//! 死常量门禁保证**每个常量都有人引用**。但"有人引用"不等于"边界有人验"——
//! 我按这条线索审计了一遍，14 个常量里只有 `MAX_TOKENSTREAM_BYTES` **在生产
//! 路径上被检查、却没有任何测试走到那个边界**（其余：`Frame::decode` 的
//! `TooLarge` 有测试、模板容量有 `template_capacity_is_bounded`、并发上限有
//! e2e 实测峰值、压缩池有内存实测）。所以补在这里。
//!
//! **第 75 轮更正：上面那句"只有 `MAX_TOKENSTREAM_BYTES`"当时是错的** ✗。
//! 顺着同一条线索再查一遍发现 `MAX_DECOMPRESS_BYTES`（解压侧 16 MiB 的 clamp）
//! 也**没有任何测试碰过** ✗ —— 它只出现在定义与 `limit.min(MAX_DECOMPRESS_BYTES)` 那一行里，
//! 而引用它的是**生产代码本身**，死常量门禁照样放行。已补在
//! `llm-proxy-core/src/compression.rs::decompress_limit_is_clamped_and_still_allows_legal_input`：
//! 一份"压缩后 1050 B、声称解压出 32 MiB"的炸弹载荷被 clamp 正确拦下 ✓，
//! 并用界内载荷作对照（证明拦截的原因是上限，不是路径坏了）✓。
//! **教训**：这种"我审计过了，只剩最后一处"的结论，本身也要能被再查一遍。
//!
//! # 边界测试必须带对照
//!
//! 只测"超大被拒"是不够的：实现完全可能**对所有 TokenStream 都拒绝**，
//! 那条断言照样通过。所以配一条"中等尺寸正常转发"的对照组——
//! 它证明拒绝的原因是**尺寸**，而不是这条编码路径本身有问题。
//!
//! **已知未覆盖**：恰好在 16 MiB 上的载荷（判据是 `total > MAX`，
//! 所以边界那次应当放行）没有测——那要推动 16 MiB 通过上游并被回显，
//! 代价与收益不成比例。这里如实记下，而不是假装边界已闭合。

mod common;

use common::*;
use llm_proxy_core::proto::Encoding;
use std::time::Duration;

const PSK: &[u8] = b"e2e-test-psk";

fn ns_of(psk: &[u8], caps: &llm_proxy_core::proto::Caps) -> llm_proxy_core::Namespace {
    llm_proxy_core::Namespace::derive(psk, "", &caps.upstream_host)
}

/// 超过 `MAX_TOKENSTREAM_BYTES` 的 TokenStream 必须在**发给上游之前**被拒。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_tokenstream_is_rejected_before_reaching_upstream() {
    guard(async {
        let st = setup().await.expect("启动失败");

        // 纯字面量 TokenStream：`0x00 varint(len) bytes` 反复写，长度可控且不依赖块缓存。
        // 重建结果就是这些字面量的**拼接**，所以 body 在这里直接跟着攒出来——
        // 不需要反向解析（反解析只会多一个可能出错的环节）。
        let limit = llm_proxy_core::config::MAX_TOKENSTREAM_BYTES;
        let chunk = vec![b'x'; 1 << 20];
        let mut stream = Vec::new();
        let mut body = Vec::new();
        while body.len() <= limit {
            llm_proxy_core::token::write_literal(&mut stream, &chunk);
            body.extend_from_slice(&chunk);
        }
        assert!(
            body.len() > limit,
            "构造的载荷应当超过上限：{} <= {}",
            body.len(),
            limit
        );
        println!(
            "  [上限] TokenStream {} 字节（上限 {}）",
            body.len(),
            limit
        );

        let mut peer = connect_raw_peer(st.dport, PSK)
            .await
            .expect("原始对端握手失败");
        let honest_fp = llm_proxy_core::body_fp(ns_of(PSK, &peer.caps), &body)
            .as_bytes()
            .to_vec();

        // 服务端会在累计超限时立刻回 Err，此时后续写入可能失败——
        // 那是**预期**的（连接被切断），所以不 `expect`。
        let _ = peer
            .send_request(
                1,
                "POST",
                "/v1/chat/completions",
                Encoding::EncTokenstream,
                honest_fp,
                &stream,
            )
            .await;

        match peer.await_verdict(1).await.expect("等判定失败") {
            RawVerdict::Rejected {
                code, hint, detail, ..
            } => {
                println!("  [上限] 服务端拒绝：code={code} hint={hint} detail={detail}");
                assert_eq!(
                    code,
                    llm_proxy_core::config::err_code::TOO_LARGE,
                    "必须是 TOO_LARGE（13）：{detail}"
                );
                assert_eq!(
                    hint,
                    llm_proxy_core::config::hint::RETRY_WITH_FULL,
                    "提示应当是「整段重发」——服务端不该猜怎么补救"
                );
            }
            RawVerdict::Forwarded { status } => panic!(
                "{} 字节的 TokenStream 超过了上限 {limit}，服务端却把它发给了上游（状态 {status}）——\
                 §13.10 的 DoS 防护没有生效：攻击者可以用一条申报超大长度的流把内存吃干",
                body.len()
            ),
        }

        // **上游一次都不许被打到**：超限的内容根本不该出门
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            st.up.rec.len(),
            0,
            "超限载荷不得发给上游（上游收到 {} 次）",
            st.up.rec.len()
        );
    })
    .await;
}

/// 对照组：**中等尺寸**的 TokenStream 必须正常转发。
///
/// 没有这一条，上面那条可能只是"所有 TokenStream 都被拒"，属于空转。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn moderate_tokenstream_is_forwarded() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let body = make_body(200, 0);
        assert!(
            body.len() < llm_proxy_core::config::MAX_TOKENSTREAM_BYTES,
            "对照载荷应当远小于上限"
        );
        let mut stream = Vec::new();
        llm_proxy_core::token::write_literal(&mut stream, &body);

        let mut peer = connect_raw_peer(st.dport, PSK)
            .await
            .expect("原始对端握手失败");
        let honest_fp = llm_proxy_core::body_fp(ns_of(PSK, &peer.caps), &body)
            .as_bytes()
            .to_vec();
        peer.send_request(
            2,
            "POST",
            "/v1/chat/completions",
            Encoding::EncTokenstream,
            honest_fp,
            &stream,
        )
        .await
        .expect("发送请求失败");

        match peer.await_verdict(2).await.expect("等判定失败") {
            RawVerdict::Forwarded { status } => {
                println!("  [上限 对照] {} 字节正常转发（状态 {status}）", body.len());
                assert_eq!(status, 200);
            }
            RawVerdict::Rejected { code, detail, .. } => panic!(
                "中等尺寸（{} 字节，上限 {}）被拒了（code={code}）：{detail}——\
                 说明拒绝的原因不是尺寸",
                body.len(),
                llm_proxy_core::config::MAX_TOKENSTREAM_BYTES
            ),
        }
        assert_eq!(st.up.rec.len(), 1, "对照组的请求应当恰好到上游一次");
    })
    .await;
}
