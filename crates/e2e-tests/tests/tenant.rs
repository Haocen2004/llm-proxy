//! 租户一致性校验（设计 §4.1 / §13.9 T7）。
//!
//! # 为什么这条必须硬失败
//!
//! 租户参与缓存命名空间派生：`ns = HMAC(psk, tenant ‖ upstream_host)`（§5.1），
//! 指纹是 `fp = ns ‖ BLAKE3_128(...)`。两端不一致时：
//!
//! 1. **缓存全不命中**——这一层的收益本来就靠命中，命名空间错位等于白花流量；
//! 2. 更糟：**不同租户共享命名空间**。§13.9 明确要求「块查询与 manifest 比对
//!    **严格限定在本租户命名空间内**，跨命名空间一律视为 miss」，
//!    共享就等于把补缺协商变成**跨租户的内容确认预言机**。
//!
//! 所以设计 §4.1 的原话是「两端都配置，并在 `CAPS` 握手中校验一致，
//! **不一致直接拒绝连接**」——不是降级、不是自动纠正。
//!
//! # 实现前的实际状态（值得记一笔）
//!
//! `Hello.tenant` 这个字段**协议里一直存在**，但服务端从不读它，两端
//! `Namespace::derive` 都传 `""`。也就是说：协议留了位、实现里被静默忽略，
//! 两个不同租户的客户端实际落在同一个命名空间里。
//! 这类"字段存在 ≠ 约束生效"已经在本项目栽过多次，`cargo run -p dev-tools -- gates`
//! 就是为它加的——但那条门禁只查**常量**，协议字段需要靠测试守。
//!
//! # 每条都要有对照
//!
//! 只测"不一致被拒"是不够的：把校验写成 `if true { bail!() }` 也能过。
//! 所以配一条"一致时正常握手并完成请求"的正对照。

mod common;

use common::*;
use llm_proxy_core::proto::Encoding;
use std::time::Duration;

const PSK: &[u8] = b"e2e-test-psk";

fn ns_of(
    psk: &[u8],
    tenant: &str,
    caps: &llm_proxy_core::proto::Caps,
) -> llm_proxy_core::Namespace {
    llm_proxy_core::Namespace::derive(psk, tenant, &caps.upstream_host)
}

/// 租户不一致：**握手必须失败**，不许"能用但缓存不命中"。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mismatched_tenant_is_refused_at_handshake() {
    guard(async {
        let st = setup_with_psk(&["--tenant".into(), "acme".into()], &[], None, None)
            .await
            .expect("启动失败");

        let res = connect_raw_peer_with_tenant(st.dport, PSK, "other").await;
        match res {
            Err(e) => println!("  [租户] 不一致被拒：{e}"),
            Ok(_) => panic!(
                "客户端声明租户 other、服务端配置 acme，握手却成功了——\
                 两端命名空间会错位，且不同租户将共享缓存命名空间（§13.9 T7）"
            ),
        }
        // 空租户（旧客户端）同样必须被拒——不能"旧客户端照旧能用"
        let res = connect_raw_peer_with_tenant(st.dport, PSK, "").await;
        assert!(
            res.is_err(),
            "空租户对上一个配置了租户的服务端也必须拒绝（否则隔离形同虚设）"
        );
    })
    .await;
}

/// 正对照：租户一致时握手正常、`Caps` 回传租户、请求逐字节完成。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matching_tenant_handshakes_and_serves() {
    guard(async {
        let st = setup_with_psk(&["--tenant".into(), "acme".into()], &[], None, None)
            .await
            .expect("启动失败");

        let mut peer = connect_raw_peer_with_tenant(st.dport, PSK, "acme")
            .await
            .expect("租户一致时握手必须成功");
        assert_eq!(
            peer.caps.tenant, "acme",
            "服务端必须在 Caps 里回传租户，客户端才能双向校验（设计 §4.1）"
        );

        // 正常请求：逐字节一致
        let body = make_body(30, 0);
        let mut stream = Vec::new();
        llm_proxy_core::token::write_literal(&mut stream, &body);
        let fp = llm_proxy_core::body_fp(ns_of(PSK, "acme", &peer.caps), &body)
            .as_bytes()
            .to_vec();
        peer.send_request(
            1,
            "POST",
            "/v1/chat/completions",
            Encoding::EncTokenstream,
            fp,
            &stream,
        )
        .await
        .expect("发送请求失败");
        match peer.await_verdict(1).await.expect("等判定失败") {
            RawVerdict::Forwarded { status } => assert_eq!(status, 200),
            RawVerdict::Rejected { code, detail, .. } => {
                panic!("租户一致、指纹按租户算，却被拒绝（code={code}）：{detail}")
            }
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(st.up.rec.len(), 1, "请求应当恰好到上游一次");
    })
    .await;
}

/// **租户真的参与了命名空间**：同一份内容、只改租户 ⇒ 指纹不同 ⇒ 服务端认不出块。
///
/// 这条是隔离性的核心证据：如果租户没被接进 `Namespace::derive`，
/// 两个租户的指纹会**完全相同**，缓存就会跨租户命中——而这在"不一致被拒"那条
/// 测试里看不出来（连接根本建不起来）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn namespace_actually_depends_on_the_tenant() {
    let caps = llm_proxy_core::proto::Caps {
        upstream_host: "localhost".into(),
        ..Default::default()
    };
    let a = llm_proxy_core::body_fp(ns_of(PSK, "acme", &caps), b"same bytes");
    let b = llm_proxy_core::body_fp(ns_of(PSK, "globex", &caps), b"same bytes");
    let none = llm_proxy_core::body_fp(ns_of(PSK, "", &caps), b"same bytes");
    assert_ne!(a, b, "不同租户对同一内容必须得到不同指纹");
    assert_ne!(a, none, "空租户与非空租户也必须不同");
    // 反空转：指纹不同必须来自命名空间前缀，而不是摘要部分
    assert_eq!(
        a.as_bytes()[llm_proxy_core::NS_LEN..],
        b.as_bytes()[llm_proxy_core::NS_LEN..],
        "摘要部分应当相同（同一份内容），差异只在命名空间前缀"
    );
    assert_ne!(
        a.as_bytes()[..llm_proxy_core::NS_LEN],
        b.as_bytes()[..llm_proxy_core::NS_LEN],
        "命名空间前缀必须不同"
    );
}

/// **命名空间的另一个输入**：`upstream_host` 两端不一致时必须拒绝链路。
///
/// 设计 §4.1 的原话是「两端都配置，并在 `CAPS` 握手中校验一致，不一致直接拒绝连接
/// ——否则两端缓存命名空间会错位」。校验在客户端（`ingress.rs` 里 `bail!`），
/// 但**此前没有任何测试**：`--upstream-host` 这个开关在全仓库里只出现在设计文档里。
///
/// 拒绝之后的行为也要如实断出来：客户端**不是报错**，而是按降级链继续往下走，
/// 最终落到 L2 直连——功能还在（请求仍然逐字节正确），只是增量/模板/压缩收益全丢。
/// 所以两条都要查：**链路确实没建起来**，**请求仍然正确**。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_host_mismatch_is_refused_and_falls_back() {
    guard(async {
        // --- 不一致：链路必须建不起来，请求仍靠 L2 直连完成 ---
        //
        // 用 `setup_resilient`（它配了 `--upstream-fallback`）而不是 `setup_with_psk`：
        // 后者的降级链末端是"整体不可用"，于是拒绝建链之后客户端只能回 502——
        // 那是**正确行为**，但测不到"降级之后功能还在"。第一版就是这么写的，
        // 实测拿到 502，才回头把夹具换对。
        let st = setup_resilient(
            &["--upstream-host".into(), "api.example.com".into()],
            &["--upstream-host".into(), "other.example.com".into()],
        )
        .await
        .expect("启动失败");

        let body = make_body(40, 0);
        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/chat/completions",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "echo"),
            ],
            &body,
        )
        .await
        .expect("请求失败");
        assert_eq!(resp.status, 200, "降级之后请求仍必须成功");
        assert_eq!(resp.body, body, "直连回退也必须逐字节正确");

        tokio::time::sleep(Duration::from_millis(300)).await;
        let v = st.status().await.expect("取 status 失败");
        println!(
            "  [命名空间] 不一致：mode={} link_alive={} bypass_requests={}",
            v["mode"], v["link_alive"], v["bypass_requests"]
        );
        assert_eq!(
            v["link_alive"], false,
            "两端 upstream_host 不一致，链路却建起来了——命名空间会错位：{v}"
        );
        assert_eq!(v["mode"], "bypass", "应当落到直连档：{v}");
        assert!(
            v["bypass_requests"].as_u64().unwrap_or(0) >= 1,
            "至少有一个请求应当走直连（说明确实降级了，而不是链路还活着）：{v}"
        );

        // --- 对照：一致时必须正常建链并保住增量收益 ---
        let ok = setup_resilient(
            &["--upstream-host".into(), "api.example.com".into()],
            &["--upstream-host".into(), "api.example.com".into()],
        )
        .await
        .expect("启动失败");
        // 同一份 body 发两次：第二次应当走增量（复用块），证明链路真的在用
        for _ in 0..2 {
            let r = raw_request(
                &ok.client,
                "POST",
                "/v1/chat/completions",
                &[
                    ("content-type", "application/json"),
                    ("x-test-mode", "echo"),
                ],
                &body,
            )
            .await
            .expect("请求失败");
            assert_eq!(r.status, 200);
            assert_eq!(r.body, body);
        }
        let v = ok.status().await.expect("取 status 失败");
        println!(
            "  [命名空间] 一致：mode={} link_alive={} bypass_requests={}",
            v["mode"], v["link_alive"], v["bypass_requests"]
        );
        assert_eq!(v["link_alive"], true, "一致时必须建起链路：{v}");
        assert_eq!(v["bypass_requests"], 0, "一致时不该有任何请求走直连：{v}");
    })
    .await;
}
