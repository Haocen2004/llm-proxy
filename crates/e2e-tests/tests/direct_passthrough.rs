//! **直连透传**（非隧道的普通 HTTP 请求）的验收。
//!
//! 背景：服务端原先只服务 DSHP 隧道，其它路径一律 404 —— 而且因为分流只看首字节 `P`，
//! `GET`/`HEAD` 到未知路径会落到 **WS 握手分支**，于是握手失败、连接被直接关掉，
//! 调用方拿到的是 "Empty reply from server"（连状态码都没有）。SDK 把 `base_url`
//! 指到服务端时，`GET /v1/models` 这类探测请求正好是这个形状 —— 线上实测踩到过。
//!
//! 现在：认得出 HTTP 方法词就走 HTTP 路由；非隧道、非管理端点的请求**原样透传**给上游，
//! 并且**单独记账**（`passthrough` 一组），不并进隧道的四组 —— 免得把隧道节省率摊薄。
//!
//! 这个套件守住四条：
//! 1. 普通方法（含 `GET`）**能进来**，不再被当成 WS 握手；
//! 2. 方法 / 路径+query / 头 / 体**原样**到上游，响应原样回给调用方；
//! 3. 透传的账记在 `passthrough` 里，**隧道四组一点不动**；
//! 4. 开关默认关闭；关着时给的是**可读的 403**（说清怎么开、有什么替代）。

mod common;

use common::*;
use std::time::Duration;

/// 取统计 JSON（夹具里**显式**配了 token，所以这里带凭据取）。
async fn stats_json(addr: &str, token: &str) -> anyhow::Result<serde_json::Value> {
    let auth = format!("Bearer {token}");
    let r = raw_request(
        addr,
        "GET",
        "/__dshp/api/stats",
        &[("authorization", &auth)],
        &[],
    )
    .await?;
    assert_eq!(r.status, 200, "带凭据的统计接口应当放行");
    Ok(serde_json::from_slice(&r.body)?)
}

/// 起一台服务端（可选开透传）+ 一台假上游。
async fn spawn_server(
    allow_passthrough: bool,
    token: Option<&str>,
) -> anyhow::Result<(String, MockUpstream, Proc)> {
    let upstream = MockUpstream::start().await;
    let port = free_port().await;
    let listen = format!("127.0.0.1:{port}");
    let mut env: Vec<(&str, &str)> = Vec::new();
    if allow_passthrough {
        env.push(("DSHP_ALLOW_PASSTHROUGH", "1"));
    }
    if let Some(t) = token {
        env.push(("DSHP_WEBUI_TOKEN", t));
    }
    let mut server = spawn_proxy_env(
        "llmproxyd",
        &["--listen", &listen, "--upstream", &upstream.base_url()],
        true,
        None,
        &env,
    )?;
    if !wait_ready(&listen, Duration::from_secs(20)).await {
        server.kill();
        anyhow::bail!("服务端没起来：{listen}");
    }
    Ok((listen, upstream, server))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_http_requests_pass_through_and_are_accounted_separately() {
    guard(async {
        let (listen, upstream, mut server) = spawn_server(true, Some("e2e-token"))
            .await
            .expect("启动失败");

        // 1) GET 普通 LLM 路径 ⇒ **透传**（改前这里是"连接被直接关掉"，连状态码都没有）
        let get = raw_request(&listen, "GET", "/v1/models", &[], &[])
            .await
            .expect("GET 请求失败");
        assert_eq!(
            get.status, 200,
            "GET /v1/models 应当被透传，而不是被当成 WS 握手关掉连接"
        );
        assert_eq!(
            header_of_norm(&get.headers, "x-upstream-marker").as_deref(),
            Some("plain-response"),
            "响应必须来自上游"
        );
        assert_bytes_eq(
            &get.body,
            br#"{"ok":true,"note":"mock upstream"}"#,
            "透传的响应体",
        );

        // 2) POST 带体 + query ⇒ 上游必须收到**一模一样**的方法/路径/头/体
        let payload = br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#;
        let post = raw_request(
            &listen,
            "POST",
            "/v1/messages?debug=1",
            &[("content-type", "application/json")],
            payload,
        )
        .await
        .expect("POST 请求失败");
        assert_eq!(post.status, 200);
        assert_bytes_eq(
            &post.body,
            br#"{"ok":true,"note":"mock upstream"}"#,
            "透传的响应体",
        );
        let recs = upstream.rec.take();
        assert_eq!(recs.len(), 2, "上游应当正好收到两次请求");
        assert_eq!(recs[0].method, "GET");
        assert_eq!(recs[0].path_and_query, "/v1/models");
        assert_eq!(recs[1].method, "POST");
        assert_eq!(
            recs[1].path_and_query, "/v1/messages?debug=1",
            "路径与 query 必须原样（上游无关：不做任何路径改写）"
        );
        assert_bytes_eq(&recs[1].body, payload, "上游收到的请求体");
        assert_eq!(
            header_of(&recs[1], "content-type"),
            "application/json",
            "业务头必须带过去"
        );

        // 3) **独立记账**：透传那一组有数，隧道的四组一点不动（这条防"摊薄"）
        let stats = stats_json(&listen, "e2e-token").await.expect("读统计失败");
        assert_eq!(stats["passthrough"]["requests"].as_u64(), Some(2));
        assert_eq!(
            stats["passthrough"]["request_bytes"].as_u64(),
            Some(payload.len() as u64),
            "只有 POST 带请求体"
        );
        assert_eq!(
            stats["passthrough"]["response_bytes"].as_u64(),
            Some((get.body.len() + post.body.len()) as u64),
            "下行按实际回给调用方的字节记"
        );
        assert_eq!(
            stats["passthrough"]["protocols"]["messages"].as_u64(),
            Some(1),
            "按协议各记各的"
        );
        assert_eq!(
            stats["responses"].as_u64(),
            Some(0),
            "透传**不能**进隧道的响应数"
        );
        assert_eq!(
            stats["request_body_bytes"].as_u64(),
            Some(0),
            "透传**不能**进隧道四组（那四组是「前/后」两端才有意义的口径）"
        );
        assert_eq!(stats["request_transport_bytes"].as_u64(), Some(0));
        assert_eq!(stats["response_body_bytes"].as_u64(), Some(0));

        server.kill();
    })
    .await;
}

/// 开关默认**关闭**：这时给的是**可读的 403**（说清怎么开、有什么替代），
/// 而不是含糊的 404 —— 更不是把连接直接关掉。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn passthrough_is_off_by_default_and_the_refusal_is_readable() {
    guard(async {
        let (listen, _upstream, mut server) = spawn_server(false, None).await.expect("启动失败");

        let r = raw_request(&listen, "GET", "/v1/models", &[], &[])
            .await
            .expect("GET 请求失败");
        assert_eq!(r.status, 403, "未开启时必须是 403，而不是 404 或断连");
        let body = String::from_utf8_lossy(&r.body);
        assert!(
            body.contains("__dshp/tunnel"),
            "要说清本端口服务什么：{body}"
        );
        assert!(
            body.contains("--upstream-fallback"),
            "要给出替代路径：{body}"
        );
        assert!(
            body.contains("DSHP_ALLOW_PASSTHROUGH"),
            "要说清怎么显式打开：{body}"
        );

        // 未知的 `/__dshp/*` 仍是 404（那是代理自己的命名空间，不许漏给上游）
        let own = raw_request(&listen, "GET", "/__dshp/nope", &[], &[])
            .await
            .expect("GET 请求失败");
        assert_eq!(own.status, 404);

        server.kill();
    })
    .await;
}
