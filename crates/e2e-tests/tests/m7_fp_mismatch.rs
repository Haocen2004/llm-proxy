//! M7：`FP_MISMATCH` 红线（设计 §9.2 / §11.3）。
//!
//! 这条检查是"服务端在把 body 发给上游**之前**，校验重组/解压结果是否等于客户端
//! 声明的 `target_fp`"。它守的是**两端认知不一致**这一类错配：块缓存不同步、
//! 字典错位、实现漂移——只要重组结果与声明不符，就必须**拒绝**，
//! 而不是把"看起来合理"的内容发上游。
//!
//! # 为什么只能用原始对端来测
//!
//! `target_fp` 是客户端**自己算的**，正常客户端永远算对。HTTPS 层的夹具
//! （`llmproxyc` + `raw_request`）无论如何都触发不到这条判断——
//! 状态全在被测进程内部。所以这里自己跑一遍 DSHP 握手，做那个**说谎的客户端**。
//!
//! 这也是"防御性检查无法从正常路径覆盖"的通用解法：**不要为了测试在生产代码里
//! 开注入开关**（那条路会把开关本身带进发布物），而是把不可信的一面实现出来。

mod common;

use common::*;
use llm_proxy_core::proto::Encoding;
use std::time::Duration;

/// 与两端一致的命名空间：`Namespace::derive(psk, tenant, upstream_host)`。
///
/// `upstream_host` **不在 URL 里**，它是部署期常量（服务端默认 `localhost`），
/// 客户端是**从 Caps 学来的**（设计 §4.1：两端不一致则缓存命名空间错位）。
/// 所以这里也从 `caps.upstream_host` 取——这正是真实客户端的做法，
/// 也顺手验证了那个字段确实在传。
fn ns_of(psk: &[u8], caps: &llm_proxy_core::proto::Caps) -> llm_proxy_core::Namespace {
    llm_proxy_core::Namespace::derive(psk, "", &caps.upstream_host)
}

const PSK: &[u8] = b"e2e-test-psk";

/// 声明一个**错误**的 `target_fp`：服务端必须拒绝，且**绝不**把内容发上游。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lying_target_fp_is_rejected_not_forwarded() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let body = make_body(20, 0);

        // 合法但**不相关**的 target_fp：`llm_proxy_core::FP_LEN` 是**摘要**长度（16），
        // 完整指纹是 `ns(8) ‖ 摘要(16)` = 24 字节。这里故意只给 16 字节——
        // 它同样是被拒绝的（长度不对 ≠ 内容不对，两条都是红线）。
        let lying_fp = vec![0xABu8; llm_proxy_core::FP_LEN];

        // 载荷用**纯字面量** TokenStream（`0x00 varint(len) bytes`）。
        // 不能用 `decompose`：它会产出 REF（引用块指纹），而服务端此刻没有那些块，
        // 于是先撞上 BLOCK_MISS 而不是 FP_MISMATCH——**测到的是另一条路径**。
        let mut stream = Vec::new();
        llm_proxy_core::token::write_literal(&mut stream, &body);

        let mut peer = connect_raw_peer(st.dport, PSK)
            .await
            .expect("原始对端握手失败");
        assert!(
            peer.caps.max_frame_bytes > 0,
            "Caps 必须已送达，否则握手其实没完成：{:?}",
            peer.caps
        );

        peer.send_request(
            1,
            "POST",
            "/v1/chat/completions",
            Encoding::EncTokenstream,
            lying_fp,
            &stream,
        )
        .await
        .expect("发送请求失败");

        match peer.await_verdict(1).await.expect("等判定失败") {
            RawVerdict::Rejected {
                code, hint, detail, ..
            } => {
                println!("  [M7 FP_MISMATCH] 服务端拒绝：code={code} hint={hint} detail={detail}");
                assert_eq!(
                    code,
                    llm_proxy_core::config::err_code::FP_MISMATCH,
                    "必须是 FP_MISMATCH（11），而不是别的拒绝原因：{detail}"
                );
                assert_eq!(
                    hint,
                    llm_proxy_core::config::hint::RETRY_WITH_FULL,
                    "提示必须是「整段重发」——服务端不应猜测根因"
                );
            }
            RawVerdict::Forwarded { status } => panic!(
                "内容与声明的 target_fp 不符，服务端却把请求**发给了上游**（状态 {status}）——\
                 这正是设计 §16 M7 禁止的静默错误：上游会照着一段来路不明的内容生成回答"
            ),
        }

        // **上游必须一次都没被打到**。这是这条红线真正的价值所在：
        // 不是"报错了"，而是"错误的内容根本没出门"。
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            st.up.rec.len(),
            0,
            "校验不过的内容不得发给上游（上游收到 {} 次）",
            st.up.rec.len()
        );
    })
    .await;
}

/// 对照组：**正确的** `target_fp` 必须被正常放行。
///
/// 没有这一条，上面那条测试可能只是"所有请求都被拒"，那就是空转。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn honest_target_fp_is_forwarded() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let body = make_body(20, 0);

        let mut stream = Vec::new();
        llm_proxy_core::token::write_literal(&mut stream, &body);

        let mut peer = connect_raw_peer(st.dport, PSK)
            .await
            .expect("原始对端握手失败");
        // 与 `llmproxyc` 同源的计算方式：ns 从 Caps 里的 upstream_host 推出
        let honest_fp = llm_proxy_core::body_fp(ns_of(PSK, &peer.caps), &body)
            .as_bytes()
            .to_vec();
        peer.send_request(
            7,
            "POST",
            "/v1/chat/completions",
            Encoding::EncTokenstream,
            honest_fp,
            &stream,
        )
        .await
        .expect("发送请求失败");

        match peer.await_verdict(7).await.expect("等判定失败") {
            RawVerdict::Forwarded { status } => {
                println!("  [M7 FP 对照] 声明正确 → 正常转发（状态 {status}）");
                assert_eq!(status, 200, "对照组应当正常拿到上游状态码");
            }
            RawVerdict::Rejected { code, detail, .. } => {
                panic!("声明正确却被拒绝（code={code}）：{detail}")
            }
        }

        // 上游确实被打到了——证明上面那条的 `rec.len()==0` 不是"上游根本没配好"
        let hits = st.up.rec.len();
        assert_eq!(hits, 1, "对照组应当恰好打到上游一次（实际 {hits} 次）");

        // 上游看到的字节必须与原始 body 逐字节一致（内容没错位）
        let rec = st.up.rec.take();
        assert_eq!(rec.len(), 1);
        assert_eq!(
            rec[0].body, body,
            "重组后的 body 与原始请求体必须逐字节一致"
        );
    })
    .await;
}

/// 压缩路径（`ENC_ZSTD`）上的同一条红线。
///
/// 服务端在这一路径上的校验点在**解压之后**——它挡的是"解压能成功、
/// 但结果不是客户端声明的那份内容"这类错配（例如字典错位到了恰好还能解出前缀）。
/// 与 TokenStream 路径是两个独立的判断点，必须各有一条测试。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lying_target_fp_on_compressed_path_is_rejected() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let body = make_body(30, 0);

        // 客户端侧压缩：与 `llmproxyc` 一样用引导字典与同一个压缩池
        let dict = llm_proxy_core::dict::Dicts::bootstrap().patch;
        let pool =
            llm_proxy_core::compression::CompressPool::new(dict, 1).expect("压缩池初始化失败");
        let blob = pool.try_compress(&body).expect("压缩失败（body 太小？）");

        let mut peer = connect_raw_peer(st.dport, PSK)
            .await
            .expect("原始对端握手失败");
        peer.send_request(
            3,
            "POST",
            "/v1/chat/completions",
            Encoding::EncZstd,
            vec![0xCDu8; llm_proxy_core::FP_LEN],
            &blob,
        )
        .await
        .expect("发送请求失败");

        match peer.await_verdict(3).await.expect("等判定失败") {
            RawVerdict::Rejected { code, detail, .. } => {
                println!("  [M7 FP_MISMATCH(压缩)] 服务端拒绝：code={code} {detail}");
                assert_eq!(
                    code,
                    llm_proxy_core::config::err_code::FP_MISMATCH,
                    "压缩路径也必须报 FP_MISMATCH，而不是 DECOMPRESS_FAILED 之类：{detail}"
                );
            }
            RawVerdict::Forwarded { status } => {
                panic!("压缩路径上内容与声明不符，却被转发给了上游（状态 {status}）")
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(st.up.rec.len(), 0, "校验不过的压缩请求不得发给上游");
    })
    .await;
}
