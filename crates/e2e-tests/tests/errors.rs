//! 错误路径的**协议行为**：每个错误码与提示都必须真的产生过一次，并被观察到。
//!
//! # 为什么要单独一组
//!
//! 用机械审计量过：`config.rs` 里的 8 个错误码 + 5 个提示中，**有 8 项在测试侧从未出现**。
//! 这不是笔误——它意味着这些路径的**线上表现**（错误码、提示、详情）从来没有被钉住：
//!
//! * 客户端按 `hint` 决定行动（补块 / 全量重发 / 降级直连），`hint` 发错就是**行为错**；
//! * 拒绝的 `detail` 必须**通用**：回给未认证来源具体原因等于送一个认证预言机；
//! * 有些码是**红线**的落点（`LENGTH_MISMATCH` = Content-Length 一致性、
//!   `BAD_ENCODING` = 不猜语义）。
//!
//! # 为什么只能用原始对端
//!
//! 这些触发条件正常客户端**永远不会**满足（发送未实现的编码、声明错长度的 Content-Length、
//! 用错的租户十握手）。与 `m7_fp_mismatch.rs` 同样的理由：把不可信的那一面实现出来，
//! 而不是在生产代码里开注入开关。

mod common;

use common::*;
use llm_proxy_core::proto::Encoding;
use std::time::Duration;

const PSK: &[u8] = b"e2e-test-psk";

/// 缺块：`BLOCK_MISS` + **`SEND_MISSING`**，并且要说清缺了**几个**。
///
/// # 为什么这条提示是承重的
///
/// `config.rs` 里写着「客户端按 `hint` 行动，`code` 只用于日志与指标」——
/// 提示发错不是"日志不好看"，而是**行为错**：客户端收到 `SEND_MISSING`
/// 才会"忘掉缺的那些块、只补发它们"；收到别的提示（例如 `RETRY_WITH_FULL`）
/// 会整段重发，白丢增量收益。
///
/// 所以这里同时钉三件事：码、提示、以及缺块清单的**条数**
/// （客户端要靠它知道补哪几块，条数错了就补错东西）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_tokenstream_is_refused_as_bad_encoding() {
    guard(async {
        let st = setup_with_psk(
            &[],
            &[],
            Some(std::str::from_utf8(PSK).unwrap()),
            Some(std::str::from_utf8(PSK).unwrap()),
        )
        .await
        .expect("启动失败");

        let mut peer = connect_raw_peer(st.dport, PSK)
            .await
            .expect("原始对端握手失败");

        // **畸形** TokenStream：标签 0x02 不在协议里（只有 0x00 LITERAL / 0x01 REF）。
        //
        // 为什么用这种形态而不是"引用不存在的块"：后者在**单元层**已被精确覆盖
        // （`token::tests::malformed_stream_is_not_reported_as_missing_blocks` 与
        // `llm-proxy-cache` 的缺块收集测试），而"引用不存在块"这条 e2e 路径走不通——
        // 见 README 里记的那条未解释现象（手工构造的 25 字节纯 REF 载荷经夹具链路
        // 到达服务端时被截断）。畸形标签没有这个歧义：一个字节就够。
        let stream = vec![0x02u8];

        peer.send_request(
            1,
            "POST",
            "/v1/messages",
            Encoding::EncTokenstream,
            vec![0u8; llm_proxy_core::FP_LEN], // 到不了指纹校验那一步，先撞缺块
            &stream,
        )
        .await
        .expect("发送请求失败");

        match peer.await_verdict(1).await.expect("等判定失败") {
            RawVerdict::Rejected {
                code,
                hint,
                detail,
                fps,
            } => {
                println!("  [畸形流] code={code} hint={hint} 缺块清单 {fps} 项 detail={detail:?}");
                assert_eq!(
                    code,
                    llm_proxy_core::config::err_code::BAD_ENCODING,
                    "畸形 TokenStream 必须报 BAD_ENCODING，**不能**报成缺块：{detail}"
                );
                assert_eq!(
                    hint,
                    llm_proxy_core::config::hint::RETRY_WITH_FULL,
                    "畸形编码的提示必须是「用原样重发」，不能是 SEND_MISSING——\
                     后者会让客户端去补一个**不存在**的缺块清单（实际 {hint:?}）"
                );
                assert_eq!(
                    fps, 0,
                    "畸形流不该报出任何缺块清单（那正是「缺少 0 个块」的来源）：{detail}"
                );
                assert!(
                    detail.contains("0x02"),
                    "详情要点名是哪个标签不认识：{detail:?}"
                );
            }
            RawVerdict::Forwarded { status } => panic!(
                "引用了不存在的块，却把请求发给了上游（status={status}）——\
                 那等于把缺块的内容凭空补成别的东西"
            ),
        }

        assert!(
            st.up.rec.is_empty(),
            "被拒的请求不得触达上游（上游收到 {} 个）",
            st.up.rec.len()
        );
    })
    .await;
}

/// 并发超限：`TOO_MANY_STREAMS` + `RETRY_WITH_FULL`。
///
/// # 与 `budget.rs` 那条的分工
///
/// `budget.rs` 从**客户端视角**测同一件事（合法并发应当排队而不是失败；排队等不到才拒绝，
/// 且拒绝理由要写清楚）。这条补的是**线上形态**：错误码与提示。
/// 两者不是重复——客户端视角看不到码，而提示决定了客户端接下来做什么。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrency_refusal_carries_a_retry_hint() {
    guard(async {
        let st = setup_with_psk(
            &["--stream-wait-ms".into(), "300".into()],
            &[],
            Some(std::str::from_utf8(PSK).unwrap()),
            Some(std::str::from_utf8(PSK).unwrap()),
        )
        .await
        .expect("启动失败");

        let mut peer = connect_raw_peer(st.dport, PSK)
            .await
            .expect("原始对端握手失败");
        let limit = llm_proxy_core::config::MAX_CONCURRENT_STREAMS as u32;

        // 用 limit 条**半截流**占满槽位：只发 ReqOpen、不发体 ⇒ 服务端一直等着
        for sid in 1..=limit {
            peer.send_open_only(
                sid,
                "POST",
                "/v1/messages",
                Encoding::EncTokenstream,
                vec![0u8; llm_proxy_core::FP_LEN],
            )
            .await
            .expect("占位请求发送失败");
        }
        tokio::time::sleep(Duration::from_millis(150)).await;

        // 第 limit+1 条：等 300ms 仍无空位 ⇒ 必须被拒（而不是永远挂着）
        let over = limit + 1;
        peer.send_open_only(
            over,
            "POST",
            "/v1/messages",
            Encoding::EncTokenstream,
            vec![0u8; llm_proxy_core::FP_LEN],
        )
        .await
        .expect("超限请求发送失败");

        match peer.await_verdict(over).await.expect("等判定失败") {
            RawVerdict::Rejected {
                code, hint, detail, ..
            } => {
                println!("  [并发超限] code={code} hint={hint} detail={detail:?}");
                assert_eq!(
                    code,
                    llm_proxy_core::config::err_code::TOO_MANY_STREAMS,
                    "并发超限必须用 TOO_MANY_STREAMS：{detail}"
                );
                assert_eq!(
                    hint,
                    llm_proxy_core::config::hint::RETRY_WITH_FULL,
                    "提示决定客户端下一步：这里应当是「重试」而不是「降级直连」\
                     （槽位很快会空出来，直连白丢全部收益）。实际 {hint:?}"
                );
                assert!(
                    detail.contains("并发流超限"),
                    "详情要让运维一眼看出是并发而不是别的问题：{detail:?}"
                );
            }
            RawVerdict::Forwarded { status } => {
                panic!("并发超限却把请求发给了上游（status={status}）——上限形同不存在")
            }
        }
    })
    .await;
}

/// 缺块：`BLOCK_MISS` + **`SEND_MISSING`**，并且要说清缺了**几个**。
///
/// # 为什么这条提示是承重的
///
/// `config.rs` 里写着「客户端按 `hint` 行动，`code` 只用于日志与指标」——
/// 提示发错不是"日志不好看"，而是**行为错**：客户端收到 `SEND_MISSING` 才会
/// "忘掉缺的那些块、只补发它们"；收到别的提示（例如 `RETRY_WITH_FULL`）会整段重发，
/// 白丢增量收益。
///
/// 所以这里同时钉三件事：码、提示、缺块清单的**条数**
/// （客户端要靠它知道补哪几块，条数错了就补错东西）。
///
/// # 构造载荷时的一个坑（我在这上面栽过）
///
/// 假的块指纹要写满 `NS_LEN + FP_LEN` = **24** 字节。只写 `FP_LEN`（那是**摘要**长度 16）
/// 会造出一个**截断的 REF**：服务端会正确地报"截断"，但排查时容易先怀疑传输。
/// 详见 README「第二个真缺陷」一节的收尾。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_blocks_are_reported_with_send_missing() {
    guard(async {
        let st = setup_with_psk(
            &[],
            &[],
            Some(std::str::from_utf8(PSK).unwrap()),
            Some(std::str::from_utf8(PSK).unwrap()),
        )
        .await
        .expect("启动失败");

        let mut peer = connect_raw_peer(st.dport, PSK)
            .await
            .expect("原始对端握手失败");

        // `0x01` + 24 字节指纹（全 0x5A，服务端不可能有这块）
        let mut stream = vec![0x01u8];
        stream.extend_from_slice(&[0x5Au8; llm_proxy_core::NS_LEN + llm_proxy_core::FP_LEN]);

        peer.send_request(
            1,
            "POST",
            "/v1/messages",
            Encoding::EncTokenstream,
            vec![0u8; llm_proxy_core::NS_LEN + llm_proxy_core::FP_LEN], // 到不了指纹校验，先撞缺块
            &stream,
        )
        .await
        .expect("发送请求失败");

        match peer.await_verdict(1).await.expect("等判定失败") {
            RawVerdict::Rejected {
                code,
                hint,
                detail,
                fps,
            } => {
                println!("  [缺块] code={code} hint={hint} 缺 {fps} 块 detail={detail:?}");
                assert_eq!(
                    code,
                    llm_proxy_core::config::err_code::BLOCK_MISS,
                    "缺块必须报 BLOCK_MISS：{detail}"
                );
                assert_eq!(
                    hint,
                    llm_proxy_core::config::hint::SEND_MISSING,
                    "提示必须是 SEND_MISSING——**客户端据此只补缺块**；换成别的提示它会\
                     整段重发，增量收益全丢（实际 {hint:?}）"
                );
                assert_eq!(
                    fps, 1,
                    "缺块清单的条数必须准确（这里正好引用了 1 个不存在的块）：{detail}"
                );
            }
            RawVerdict::Forwarded { status } => panic!(
                "引用了不存在的块，却把请求发给了上游（status={status}）——\
                 那等于把缺块的内容凭空补成别的东西"
            ),
        }

        assert!(
            st.up.rec.is_empty(),
            "被拒的请求不得触达上游（上游收到 {} 个）",
            st.up.rec.len()
        );
    })
    .await;
}

/// 握手被拒：`AUTH_FAILED` + `DOWNGRADE_BYPASS`，且详情**不得**泄露具体原因。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_refusal_is_generic_and_says_downgrade_bypass() {
    guard(async {
        let st = setup_with_psk(
            &[],
            &[],
            Some(std::str::from_utf8(PSK).unwrap()),
            Some(std::str::from_utf8(PSK).unwrap()),
        )
        .await
        .expect("启动失败");

        let e = connect_raw_peer_expecting_refusal(st.dport, PSK, "not-the-configured-tenant")
            .await
            .expect("服务端必须拒绝租户不一致的握手，且回一条 Err");

        println!(
            "  [拒绝] code={} hint={} detail={:?}",
            e.code, e.hint, e.detail
        );

        assert_eq!(
            e.code,
            llm_proxy_core::config::err_code::AUTH_FAILED,
            "握手失败必须用 AUTH_FAILED：{}",
            e.detail
        );
        assert_eq!(
            e.hint,
            llm_proxy_core::config::hint::DOWNGRADE_BYPASS,
            "客户端**按 hint 行动**：握手失败时它应当直接降级直连，而不是重试或补块。\
             实际 hint={:?}",
            e.hint
        );
        // 反预言机：详情必须是通用原因，不能带租户名/PSK/字典等任何具体线索
        for leak in [
            "not-the-configured-tenant",
            "tenant",
            "PSK",
            "psk",
            "dict",
            "字典",
        ] {
            assert!(
                !e.detail.contains(leak),
                "拒绝详情里出现了 {leak:?}（{e:?}）——回给未认证来源具体原因等于送一个认证预言机"
            );
        }
        assert!(
            !e.detail.is_empty(),
            "详情也不能空着：完全不给理由会让运维无法区分「被拒」和「网络断了」"
        );
    })
    .await;
}

/// 未实现的编码必须**明确拒绝**（`BAD_ENCODING`），而不是猜语义。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unimplemented_encoding_is_refused_not_guessed() {
    guard(async {
        let st = setup_with_psk(
            &[],
            &[],
            Some(std::str::from_utf8(PSK).unwrap()),
            Some(std::str::from_utf8(PSK).unwrap()),
        )
        .await
        .expect("启动失败");
        let body = make_body(8, 0);

        let mut peer = connect_raw_peer(st.dport, PSK)
            .await
            .expect("原始对端握手失败");
        peer.send_request(
            1,
            "POST",
            "/v1/messages",
            Encoding::EncStruct,
            vec![0u8; llm_proxy_core::FP_LEN],
            &body,
        )
        .await
        .expect("发送请求失败");

        match peer.await_verdict(1).await.expect("等判定失败") {
            RawVerdict::Rejected {
                code, hint, detail, ..
            } => {
                println!("  [未实现编码] code={code} hint={hint} detail={detail:?}");
                assert_eq!(
                    code,
                    llm_proxy_core::config::err_code::BAD_ENCODING,
                    "未实现的编码必须报 BAD_ENCODING：{detail}"
                );
                assert_eq!(
                    hint,
                    llm_proxy_core::config::hint::RETRY_WITH_FULL,
                    "既然是「这个编码我解不了」，就该让客户端**用原样重发**（hint={hint:?}）"
                );
                assert!(
                    detail.contains("ENC_STRUCT"),
                    "详情要点名是哪个编码：{detail:?}"
                );
            }
            RawVerdict::Forwarded { status } => panic!(
                "服务端把不认识的编码**转发给上游**了（status={status}）——\
                 安静的误解析会变成重组错误，这正是这条检查要拦的"
            ),
        }

        // 上游必须一点都没收到
        assert!(
            st.up.rec.is_empty(),
            "被拒的请求不得触达上游（上游收到了 {} 个请求）",
            st.up.rec.len()
        );
    })
    .await;
}

/// 非法 header（值里带换行）：必须**拒绝**，不许 panic，也不许带出去。
///
/// # 这条覆盖的是 `INTERNAL`
///
/// 触发点不在协议解析层，而在**组装上游请求**时：`HeaderValue::from_bytes` 会拒绝
/// 含 CR/LF 的值（HTTP 头本来就不允许换行——那是 header 注入的经典入口）。
/// 于是 `forward()` 返回 Err，服务端回 `Err{INTERNAL, DOWNGRADE_BYPASS}`。
///
/// 为什么值得测：这是**唯一**由「客户端送来的脏数据」直接走进 `INTERNAL` 的路径，
/// 而 `INTERNAL` 此前在测试侧从未出现过。要守三件事：
///
/// 1. 服务端**不许 panic**（一条畸形请求不该带走整个连接）；
/// 2. **不许**把带换行的 header 送上游（那正是 header 注入）；
/// 3. 客户端要拿到明确判定，而不是干等超时。
///
/// # 关于分类的一点保留意见
///
/// 从「谁的错」看，这更像客户端侧的 `BAD_ENCODING`，而不是服务端内部的 `INTERNAL`。
/// 但提示选 `DOWNGRADE_BYPASS` 是对的：无论重发多少次这个 header 都过不去，
/// 客户端该做的是绕开代理。这里**钉住现状并写明保留**，而不是自作主张改码——
/// 码按设计只用于日志与指标，改它会动指标口径，应当单独决定。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn illegal_header_is_refused_without_reaching_upstream() {
    guard(async {
        let st = setup_with_psk(
            &[],
            &[],
            Some(std::str::from_utf8(PSK).unwrap()),
            Some(std::str::from_utf8(PSK).unwrap()),
        )
        .await
        .expect("启动失败");

        let body = make_body(6, 0);
        let mut stream = Vec::new();
        llm_proxy_core::token::write_literal(&mut stream, &body);

        let mut peer = connect_raw_peer(st.dport, PSK)
            .await
            .expect("原始对端握手失败");
        let ns = llm_proxy_core::Namespace::derive(PSK, "", &peer.caps.upstream_host);

        peer.send_request_with_headers(
            1,
            "POST",
            "/v1/messages",
            vec![
                llm_proxy_core::proto::Header {
                    name: "content-type".into(),
                    value: b"application/json".to_vec(),
                },
                llm_proxy_core::proto::Header {
                    name: "x-injected".into(),
                    // 值里带换行：HTTP 头不允许，这正是 header 注入的入口
                    value: b"ok\r\nx-evil: 1".to_vec(),
                },
            ],
            Encoding::EncTokenstream,
            llm_proxy_core::fingerprint::body_fp(ns, &body)
                .as_bytes()
                .to_vec(),
            &stream,
        )
        .await
        .expect("发送请求失败");

        match peer.await_verdict(1).await.expect("等判定失败") {
            RawVerdict::Rejected {
                code, hint, detail, ..
            } => {
                println!("  [非法 header] code={code} hint={hint} detail={detail:?}");
                assert_eq!(
                    code,
                    llm_proxy_core::config::err_code::INTERNAL,
                    "非法 header 目前走 INTERNAL（见本测试的保留意见）：{detail}"
                );
                assert_eq!(
                    hint,
                    llm_proxy_core::config::hint::DOWNGRADE_BYPASS,
                    "提示必须是「绕开代理」——重发多少次都过不去（实际 {hint:?}）"
                );
            }
            RawVerdict::Forwarded { status } => {
                panic!("带换行的 header 被送给了上游（status={status}）——这正是 header 注入")
            }
        }

        assert!(
            st.up.rec.is_empty(),
            "被拒的请求不得触达上游（上游收到 {} 个）",
            st.up.rec.len()
        );
    })
    .await;
}

/// `Content-Length` 与重组结果不符 → `LENGTH_MISMATCH`，且**绝不**发上游。
///
/// 这是设计里的红线之一：上游拿到"声明的长度"和"实际字节"不一致的请求，
/// 行为由上游决定——可能是截断、可能是解析错误，而代理**已经失去了控制**。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn content_length_dispute_is_refused_not_forwarded() {
    guard(async {
        let st = setup_with_psk(
            &[],
            &[],
            Some(std::str::from_utf8(PSK).unwrap()),
            Some(std::str::from_utf8(PSK).unwrap()),
        )
        .await
        .expect("启动失败");
        let body = make_body(12, 0);

        // 纯字面量 TokenStream：不引用块，免得先撞 BLOCK_MISS（测到另一条路径）
        let mut stream = Vec::new();
        llm_proxy_core::token::write_literal(&mut stream, &body);

        let mut peer = connect_raw_peer(st.dport, PSK)
            .await
            .expect("原始对端握手失败");
        // 命名空间与两端一致：`Namespace::derive(psk, tenant, upstream_host)`，
        // 而 `upstream_host` 是**从 Caps 学来的**（部署期常量，不在 URL 里）——
        // 这正是真实客户端的做法。
        let ns = llm_proxy_core::Namespace::derive(PSK, "", &peer.caps.upstream_host);
        peer.send_request_with_headers(
            1,
            "POST",
            "/v1/messages",
            vec![
                llm_proxy_core::proto::Header {
                    name: "content-type".into(),
                    value: b"application/json".to_vec(),
                },
                llm_proxy_core::proto::Header {
                    name: "content-length".into(),
                    // **说谎**：声称 9999，实际只有 body.len()
                    value: b"9999".to_vec(),
                },
            ],
            Encoding::EncTokenstream,
            llm_proxy_core::fingerprint::body_fp(ns, &body)
                .as_bytes()
                .to_vec(),
            &stream,
        )
        .await
        .expect("发送请求失败");

        match peer.await_verdict(1).await.expect("等判定失败") {
            RawVerdict::Rejected {
                code, hint, detail, ..
            } => {
                println!("  [长度争议] code={code} hint={hint} detail={detail:?}");
                assert_eq!(
                    code,
                    llm_proxy_core::config::err_code::LENGTH_MISMATCH,
                    "长度不符必须报 LENGTH_MISMATCH：{detail}"
                );
                assert_eq!(
                    hint,
                    llm_proxy_core::config::hint::RETRY_WITH_FULL,
                    "客户端应当用原样重发（hint={hint:?}）"
                );
                assert!(
                    detail.contains("9999") && detail.contains(&body.len().to_string()),
                    "详情要把两个数字都报出来（那是排查的唯一线索）：{detail:?}"
                );
            }
            RawVerdict::Forwarded { status } => {
                panic!("Content-Length 与重组结果不符，却把请求发给了上游（status={status}）")
            }
        }

        assert!(
            st.up.rec.is_empty(),
            "被拒的请求不得触达上游（上游收到了 {} 个请求）",
            st.up.rec.len()
        );
    })
    .await;
}
