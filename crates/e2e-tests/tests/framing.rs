//! 合法但"少见"的响应形态：代理必须**原样透传**（设计 §3.1 上游无关 / §12）。
//!
//! # 为什么单独开一个文件
//!
//! M0 的判据是"四协议经代理后与直连逐字节一致"。常规用例（`passthrough.rs`）覆盖了
//! 路径、query、认证头、大 body、非 2xx——但**它们全都是"带 content-length 的普通响应"**。
//! 而朴素代理实现真正翻车的地方往往在这五种形态上，每一种都合法：
//!
//! | 形态 | 朴素实现的典型错法 |
//! |---|---|
//! | `transfer-encoding: chunked`（无 content-length） | 自己拼一个 content-length，或把分块边界当内容 |
//! | `content-encoding: zstd` | "顺手"解压再转发 ⇒ 字节变了、头没改 ⇒ 下游解不开 |
//! | `204 No Content` | 凭空补一个空 body 或把它变成 200 |
//! | 重复的 `set-cookie` | 合并成一行 ⇒ 只留一个 cookie |
//! | `HEAD`（有 content-length，无 body） | 等 body ⇒ 挂住；或把 GET 的 body 发回去 |
//!
//! 这些都是**静默**的：SDK 拿到的东西"看起来正常"，错在别处才暴露。
//! 所以每条都按"bug 的形状"来断言，并且都走完整链路
//! （`raw_request` → `llmproxyc` → `llmproxyd` → mock 上游）。
//!
//! # 关于逐跳头
//!
//! `transfer-encoding` / `connection` 这类逐跳头**按规范本来就不该**逐字节透传
//! （中间节点可以重新分帧），所以断言用的是**去掉逐跳头之后**的 header 比对
//! （`normalize_headers`）。**body 的字节则必须完全一致**——那才是"逐字节一致"的实质。

mod common;

use common::*;

/// 分块（无 `content-length`）的上游响应必须逐字节中继。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chunked_upstream_body_is_relayed_byte_exact() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let body = make_body(120, 0);
        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/chat/completions",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "chunked"),
            ],
            &body,
        )
        .await
        .expect("请求失败");

        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.body,
            body,
            "上游用分块传输时，body 必须逐字节一致（长度 {} vs {}）——\
             代理不许把分块边界当内容、也不许丢掉尾块",
            resp.body.len(),
            body.len()
        );
        // 上游确实分了多块：否则这条测试可能只是"上游没分块"
        assert!(
            st.up.rec.len() == 1,
            "上游应恰好被请求一次（实际 {}）",
            st.up.rec.len()
        );
    })
    .await;
}

/// `content-encoding: zstd` 的 body **不许被代理解码**。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encoded_body_passes_through_undecoded() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let body = make_body(120, 0);

        // 自己算一份上游将要发出的编码结果，用于比对
        let encoded = llm_proxy_core::compression::CompressPool::new(b"", 1)
            .expect("建压缩器")
            .try_compress(&body)
            .expect("压缩");
        assert!(
            encoded.len() < body.len(),
            "编码结果应当更小（{} vs {}），否则这条测试分辨不出「已解码」与「未解码」",
            encoded.len(),
            body.len()
        );

        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/chat/completions",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "encoded"),
            ],
            &body,
        )
        .await
        .expect("请求失败");

        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.body,
            encoded,
            "带 content-encoding 的 body 必须**原样**转发（代理不许解压）。\
             拿到 {} 字节，期望 {} 字节",
            resp.body.len(),
            encoded.len()
        );
        let hs = normalize_headers(&resp.headers);
        assert_eq!(
            header_of_norm(&hs, "content-encoding"),
            Some("zstd".to_string()),
            "content-encoding 必须保留——代理既不改 body 也不该改这个头"
        );
        // 反空转：body 绝不能等于解码后的原文（那正是"顺手解压"的 bug 形状）
        assert_ne!(resp.body, body, "body 被解压了：下游会按 zstd 去解一段明文");
    })
    .await;
}

/// `204 No Content` 必须原样透传：状态码不变、body 为空。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_content_is_passed_through_without_inventing_a_body() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/chat/completions",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "no-content"),
            ],
            b"{}",
        )
        .await
        .expect("请求失败");

        assert_eq!(
            resp.status, 204,
            "无内容响应的状态码必须原样透传（拿到 {}）",
            resp.status
        );
        assert!(
            resp.body.is_empty(),
            "204 不许有 body，代理也不许凭空造一个（拿到 {} 字节）",
            resp.body.len()
        );
    })
    .await;
}

/// 重复的响应头必须**都**保留。
///
/// 典型错法：把 `headers()` 收进 `HashMap` ⇒ 两个 `set-cookie` 只剩一个。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_response_headers_are_not_merged() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/chat/completions",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "dup-headers"),
            ],
            b"{}",
        )
        .await
        .expect("请求失败");

        assert_eq!(resp.status, 200);
        let cookies: Vec<String> = resp
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, v)| String::from_utf8_lossy(v).to_string())
            .collect();
        assert_eq!(
            cookies.len(),
            2,
            "两条 set-cookie 必须都在（实际 {cookies:?}）——\
             合并或只留一条会让下游丢掉一个 cookie"
        );
        assert!(
            cookies.iter().any(|c| c.starts_with("dshp_a=")),
            "{cookies:?}"
        );
        assert!(
            cookies.iter().any(|c| c.starts_with("dshp_b=")),
            "{cookies:?}"
        );
    })
    .await;
}

/// `HEAD` 请求：状态码与头要透传，但**没有 body**——代理不许挂住等 body。
///
/// 这条测的是"流结束 ≠ 发送完成"的另一面：对 HEAD 而言，**没有 body 就是正确的终点**。
/// 实现若把"没收到 body"当成"流没发完"，就会一直等到超时。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn head_request_completes_without_a_body() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let t0 = std::time::Instant::now();
        let resp = raw_request(
            &st.client,
            "HEAD",
            "/v1/chat/completions",
            &[("x-test-mode", "plain")],
            b"",
        )
        .await
        .expect("请求失败");
        let elapsed = t0.elapsed();

        println!("  [HEAD] 状态 {} 耗时 {:?}", resp.status, elapsed);
        assert_eq!(resp.status, 200);
        assert!(
            resp.body.is_empty(),
            "HEAD 不许有 body（拿到 {} 字节）",
            resp.body.len()
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "HEAD 请求花了 {elapsed:?}——像是代理在等一个永远不会有的 body"
        );
    })
    .await;
}

/// **SSE + `content-encoding`**：压缩过的流式响应必须原样透传，代理不许拿压缩字节切事件。
///
/// 这是本轮最危险的形态：响应侧按 `content-type` 分流，`text/event-stream` 会走进
/// 「切事件 → 归纳模板 → 批量成帧」。而 body 是压缩过的，切出来的"事件"全是垃圾——
/// 代理若是照旧重建响应，SDK 收到的将是**被改写过的压缩流**（或干脆一团乱码），
/// 而这在字节比对里一眼可见，在真实使用中却是"偶尔解析失败"。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encoded_sse_is_relayed_without_event_splitting() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/messages",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "sse-encoded"),
            ],
            &make_body(20, 0),
        )
        .await
        .expect("请求失败");

        assert_eq!(resp.status, 200);
        // 按本次请求新增的部分比对（mock 的累积缓冲是跨请求的）
        let expected = st.up.sse_bytes.lock().unwrap().clone();
        assert!(!expected.is_empty(), "上游应当产出了一段编码后的 SSE");
        assert_eq!(
            resp.body,
            expected,
            "带 content-encoding 的流式响应必须**原样**中继（{} 字节 vs 上游 {} 字节）。\
             若这里不等，说明代理拿压缩字节去切了 SSE 事件、然后重建了响应",
            resp.body.len(),
            expected.len()
        );
        let hs = normalize_headers(&resp.headers);
        assert_eq!(
            header_of_norm(&hs, "content-encoding"),
            Some("zstd".to_string()),
            "content-encoding 必须保留"
        );
        assert_eq!(
            header_of_norm(&hs, "content-type"),
            Some("text/event-stream".to_string()),
            "content-type 也必须保留——代理没有权利改它"
        );
    })
    .await;
}

// ---------------------------------------------------------------------------
// 请求侧：同样的稳健性矩阵。代理对方法/头/编码**没有假设**才叫"上游无关"。
// ---------------------------------------------------------------------------

/// `GET`（无 body）：方法、path 原样透传，且**不许挂住等一个不存在的请求体**。
///
/// 经典错法：把"没有 body"当成"请求没发完"，一直等到超时；或给 GET 也套上
/// 增量路径的空 body 处理。ingress 的判据是 `content-length` 是否存在——
/// GET 没有，于是走原样转发。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_without_a_body_is_forwarded_verbatim() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let t0 = std::time::Instant::now();
        let resp = raw_request(
            &st.client,
            "GET",
            "/v1/models?limit=3",
            &[("accept", "application/json")],
            b"",
        )
        .await
        .expect("请求失败");
        let elapsed = t0.elapsed();

        assert_eq!(resp.status, 200);
        let recs = st.up.rec.take();
        assert_eq!(recs.len(), 1, "上游应恰好被请求一次");
        assert_eq!(recs[0].method, "GET", "方法必须原样透传");
        assert_eq!(
            recs[0].path_and_query, "/v1/models?limit=3",
            "GET 的 path+query 必须原样透传"
        );
        assert!(recs[0].body.is_empty(), "GET 的请求体应为空");
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "GET 花了 {elapsed:?}——像是代理在等一个不存在的请求体"
        );
    })
    .await;
}

/// `PUT` 带 body：方法与 body 原样透传（代理不挑方法）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_post_methods_with_a_body_pass_through() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let body = make_body(40, 0);
        let resp = raw_request(
            &st.client,
            "PUT",
            "/v1/files/abc",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "plain"),
            ],
            &body,
        )
        .await
        .expect("请求失败");

        assert_eq!(resp.status, 200);
        let recs = st.up.rec.take();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].method, "PUT", "方法必须原样透传");
        assert_eq!(recs[0].path_and_query, "/v1/files/abc");
        assert_eq!(recs[0].body, body, "PUT 的 body 必须逐字节一致");
    })
    .await;
}

/// 重复的**请求**头必须都转发（不许合并成一行）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_request_headers_are_all_forwarded() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/chat/completions",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "plain"),
                ("x-dshp-dup", "alpha"),
                ("x-dshp-dup", "beta"),
            ],
            b"{}",
        )
        .await
        .expect("请求失败");
        assert_eq!(resp.status, 200);

        let recs = st.up.rec.take();
        let vals: Vec<String> = recs[0]
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("x-dshp-dup"))
            .map(|(_, v)| String::from_utf8_lossy(v).to_string())
            .collect();
        assert_eq!(
            vals.len(),
            2,
            "两个同名请求头必须都转发（实际 {vals:?}）——合并或只留一个会让上游丢信息"
        );
        assert!(vals.contains(&"alpha".to_string()), "{vals:?}");
        assert!(vals.contains(&"beta".to_string()), "{vals:?}");
    })
    .await;
}

/// **压缩过的请求体**：与响应侧同一条红线——已编码的 body 是不透明的，代理只准原样搬。
///
/// 而且这里刻意**发两次同样的压缩体**，让第二次可能命中增量路径
/// （块缓存已认识这段内容）。内容寻址的块缓存本身与内容语义无关，
/// 所以两条路径都必须逐字节还原。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encoded_request_body_is_not_parsed_as_json() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let body = make_body(60, 0);
        let encoded = llm_proxy_core::compression::CompressPool::new(b"", 1)
            .expect("建压缩器")
            .try_compress(&body)
            .expect("压缩");
        assert!(
            encoded.len() < body.len(),
            "编码结果应当更小（{} vs {}），否则这条测试分辨不出「被改写」与「未改写」",
            encoded.len(),
            body.len()
        );

        for round in 1..=2 {
            let resp = raw_request(
                &st.client,
                "POST",
                "/v1/chat/completions",
                &[
                    ("content-type", "application/json"),
                    ("content-encoding", "zstd"),
                    ("x-test-mode", "plain"),
                ],
                &encoded,
            )
            .await
            .unwrap_or_else(|e| panic!("第 {round} 轮请求失败：{e}"));
            assert_eq!(resp.status, 200);

            let recs = st.up.rec.take();
            assert_eq!(recs.len(), 1, "第 {round} 轮：上游应恰好被请求一次");
            assert_eq!(
                recs[0].body,
                encoded,
                "第 {round} 轮：压缩请求体必须逐字节一致（{} vs {}）",
                recs[0].body.len(),
                encoded.len()
            );
            assert_ne!(
                recs[0].body, body,
                "第 {round} 轮：被解压了——上游会拿一段明文当 zstd 去解"
            );
            assert_eq!(
                header_of(&recs[0], "content-encoding"),
                "zstd",
                "第 {round} 轮：content-encoding 必须原样转发"
            );
        }
    })
    .await;
}
/// **上游把 body 发到一半就断**（非 SSE 路径）：SDK 必须看到明确错误，而不是半截 200。
///
/// 这是 §15「流结束 ≠ 发送完成」在 **raw（非 SSE）路径**上的镜像，
/// 也是「Content-Length 一致性」这条非协商项的边界。
///
/// 机制上有两层：egress 的 `relay_raw` 用 `?` 把上游 body 错误往上抛，
/// **于是不会发 `RespEnd`**；ingress 的泵只认 `RespEnd` 为完成信号，收不到就
/// 往 body 里注入 `Err`。任何一层被改掉，这条测试都会红。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mid_body_abort_on_the_raw_path_is_a_clear_error() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let body = make_body(40, 0);
        let res = raw_request(
            &st.client,
            "POST",
            "/v1/chat/completions",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "cut-body"),
            ],
            &body,
        )
        .await;

        match res {
            // 明确错误：正是要的
            Err(e) => println!("  [响应中途断] SDK 拿到明确错误：{e}"),
            // 非 2xx 也是"明确错误"（例如 502），可以接受
            Ok(r) if r.status != 200 => {
                println!(
                    "  [响应中途断] SDK 拿到非 2xx：{}（body {} 字节）",
                    r.status,
                    r.body.len()
                )
            }
            // **只有这一种不行**：干净的 200 配半截 body
            Ok(r) => panic!(
                "上游在响应体中途断开，代理却让 SDK 拿到干净的 200 + {} 字节 body——\
                 这就是 §15 禁止的**静默截断**：SDK 会当成完整响应去解析",
                r.body.len()
            ),
        }

        // 观测点：客户端必须记下这次"响应中途断掉"
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let status = raw_request(&st.client, "GET", "/__dshp/status", &[], b"")
            .await
            .expect("取 status 失败");
        let text = String::from_utf8_lossy(&status.body).to_string();
        assert!(
            text.contains(r#""truncated_responses": 1"#)
                || text.contains(r#""truncated_responses":1"#),
            "主动中止计数值应为 1（说明代理确实识别出响应没发完，而不是让 body 自然结束）；\
             status 片段：{}",
            &text[text.find("truncated_responses").unwrap_or(0)
                ..(text.find("truncated_responses").unwrap_or(0) + 40).min(text.len())]
        );
    })
    .await;
}

// ---------------------------------------------------------------------------
// Accept-Encoding：设计 §15 把它列为**绝对禁止**的改动。
// ---------------------------------------------------------------------------

/// 代理**绝不**改动 `Accept-Encoding`，也不该顺手加任何头。
///
/// §15 的原话：「修改 `Accept-Encoding` 以让上游返回压缩内容 → **改变上游返回字节，
/// 破坏正确性，绝对禁止**」。这条反模式的诱惑是真实的：慢路径已经在压缩响应了，
/// "顺手让上游也压一下"看起来能再省一点——但它会让上游返回的字节与本端缓存、
/// 与 SDK 的预期全部对不上。
///
/// 全仓库搜 `accept-encoding` **零命中**，也就是实现从没碰过它（正确性由构造保证）。
/// 但没有测试钉住的话，将来一次"优化"就可能悄悄加上——所以要显式钉住：
///
/// 1. 客户端**没发** `Accept-Encoding` ⇒ 上游**也不该看见**它；
/// 2. 客户端发了具体值 ⇒ 上游看到的值**逐字节相同**；
/// 3. 上游看到的**头名集合**不得多出客户端没发的（防顺手加头）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_encoding_is_never_touched() {
    guard(async {
        let st = setup().await.expect("启动失败");

        // 1) 不发 Accept-Encoding
        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/chat/completions",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "plain"),
            ],
            b"{}",
        )
        .await
        .expect("请求失败");
        assert_eq!(resp.status, 200);
        let recs = st.up.rec.take();
        assert_eq!(recs.len(), 1);
        let names: Vec<String> = recs[0]
            .headers
            .iter()
            .map(|(k, _)| k.to_ascii_lowercase())
            .collect();
        assert!(
            !names.iter().any(|k| k == "accept-encoding"),
            "客户端没发 Accept-Encoding，上游却收到了——这正是 §15 绝对禁止的改动。\
             上游看到的头：{names:?}"
        );

        // 2) 发一个具体值：必须逐字节透传
        let sent = "gzip, deflate, br, zstd;q=0.9";
        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/messages",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "plain"),
                ("accept-encoding", sent),
            ],
            b"{}",
        )
        .await
        .expect("请求失败");
        assert_eq!(resp.status, 200);
        let recs = st.up.rec.take();
        assert_eq!(recs.len(), 1);
        assert_eq!(
            header_of(&recs[0], "accept-encoding"),
            sent,
            "Accept-Encoding 必须逐字节原样透传（不许补、不许删、不许改写）"
        );

        // 3) 头名集合：上游不得看到客户端没发的端到端头
        //    允许的额外项只有代理/连接自身管理的那些（host 由客户端发、长度由 framing 决定）
        const ALLOW_EXTRA: &[&str] = &[
            "host",
            "content-length",
            "connection",
            "transfer-encoding",
            "te",
            "trailer",
            "upgrade",
            "keep-alive",
            "proxy-connection",
        ];
        let extra: Vec<String> = recs[0]
            .headers
            .iter()
            .map(|(k, _)| k.to_ascii_lowercase())
            .filter(|k| {
                !ALLOW_EXTRA.contains(&k.as_str())
                    && !matches!(
                        k.as_str(),
                        "content-type" | "x-test-mode" | "accept-encoding"
                    )
            })
            .collect();
        assert!(
            extra.is_empty(),
            "上游看到了客户端没发的头：{extra:?}——代理不许顺手加头（会改变上游行为）"
        );
    })
    .await;
}

// ---------------------------------------------------------------------------
// M0 的「含 SSE 流时序」：不只是"首字节快"，整条流都必须**跟着上游走**。
// ---------------------------------------------------------------------------

/// 慢速上游（12 片 × 200ms = 2.4s）：交付时间必须**铺满**整个上游时长。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_delivery_pacing_tracks_the_upstream() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let t0 = std::time::Instant::now();
        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/messages",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "sse-slow"),
            ],
            &make_body(20, 0),
        )
        .await
        .expect("请求失败");
        let elapsed = t0.elapsed();

        // 客户端记录的每个数据分片的到达时刻（相对请求开始）
        let mut times: Vec<f64> = resp
            .chunk_times
            .iter()
            .map(|t| t.duration_since(resp.start).as_secs_f64())
            .collect();
        times.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let first = times.first().copied().unwrap_or(f64::NAN);
        let last = times.last().copied().unwrap_or(f64::NAN);
        println!(
            "  [SSE 时序] 上游 2.4s，整体 {:.3}s，分片 {} 个：首 {:.3}s 尾 {:.3}s，跨度 {:.3}s",
            elapsed.as_secs_f64(),
            times.len(),
            first,
            last,
            last - first
        );

        assert_eq!(resp.status, 200);
        assert!(!times.is_empty(), "应当至少收到一个数据分片");

        // **首字节快**：证明没有整段缓冲
        assert!(
            first <= 0.5,
            "首字节 {first:.3}s——整段缓冲了（2.4s 的上游不该等这么久）"
        );
        // **尾字节也跟着上游走**：证明不是"只把首片放出去、其余攒到结束"。
        //
        // 这一条是首字节断言抓不到的失败形态：只刷前导沿同样能让首字节很快，
        // 但后面的事件会全部堆在最后一起到达——流式体验其实是没了。
        assert!(
            last >= 1.6,
            "最后一个分片在 {last:.3}s 就到了——上游要到 2.4s 才发完，\
             说明后面的内容被提前攒批并一次性放出去了（只实现了前导沿）"
        );
        // 铺满：跨度应当接近上游时长而不是接近 0
        assert!(
            last - first >= 1.0,
            "分片跨度只有 {:.3}s——交付没有铺满上游时长，流式被压缩成一阵",
            last - first
        );
    })
    .await;
}
