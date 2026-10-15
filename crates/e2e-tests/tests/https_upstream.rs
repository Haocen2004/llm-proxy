//! 缺口 #4：**https 上游**支持（第 181 轮）。
//!
//! # 这一组在守什么
//!
//! 在此之前 `Config::http_client` 写死 `enforce_http(true)`（注释写着"M0 只支持明文上游；
//! TLS 在部署阶段接入"）⇒ 上游必须是明文，或者由**外部**做 TLS 终止 ✗。
//!
//! 补齐之后要守住三条：
//!
//! 1. **能用**：`--upstream https://…` + `--upstream-ca <自签 CA>` ⇒ 隧道照常工作、逐字节一致；
//! 2. **失败要响亮**（**负向对照**）：不配 CA ⇒ 请求必须**失败**，而且上游**一个请求都收不到**
//!    —— 那才是"没有静默降级成明文"的直接证据 ✓（只说"请求失败了"不够：那也可能是别处出错 ✗）；
//! 3. **客户端那条路也要能用**：`--upstream-fallback https://…`（主链路不可用时的 L2 直连）
//!    走的必须是同一套证书策略 ✓。
//!
//! 证书**在测试时现生成**（rcgen + tokio-rustls）⇒ 仓库里没有私钥 ✓。

mod common;

use common::*;
use std::path::PathBuf;

/// 起"服务端 + **https** mock 上游 + 客户端"，返回 `(Stack, 本次生成的 CA 文件路径)`。
///
/// `with_ca == false` 时**刻意不配** `--upstream-ca` —— 那正是负向对照要的场景 ✓
/// （夹具本身就是"配置"的一种，不是"生产代码里的注入开关" ✓）。
async fn setup_https(with_ca: bool, server_extra: &[&str]) -> anyhow::Result<(Stack, PathBuf)> {
    let (up, ca_path) = MockUpstream::start_tls().await;
    let dport = free_port().await;
    let cport = free_port().await;

    let mut args: Vec<String> = vec![
        "--listen".to_string(),
        format!("127.0.0.1:{dport}"),
        "--upstream".to_string(),
        up.base_url_https(),
    ];
    if with_ca {
        args.push("--upstream-ca".to_string());
        args.push(ca_path.to_string_lossy().into_owned());
    }
    args.extend(server_extra.iter().map(|s| s.to_string()));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let d = spawn_proxy_env("llmproxyd", &refs, true, None, &[])?;
    anyhow::ensure!(
        wait_ready(
            &format!("127.0.0.1:{dport}"),
            std::time::Duration::from_secs(8)
        )
        .await,
        "llmproxyd 未在 8s 内就绪（dport={dport}）"
    );

    let cargs: Vec<String> = vec![
        "--listen".to_string(),
        format!("127.0.0.1:{cport}"),
        "--server".to_string(),
        format!("ws://127.0.0.1:{dport}"),
    ];
    let crefs: Vec<&str> = cargs.iter().map(String::as_str).collect();
    let c = spawn_proxy_env("llmproxyc", &crefs, false, None, &[])?;
    let client = format!("127.0.0.1:{cport}");
    anyhow::ensure!(
        wait_ready(&client, std::time::Duration::from_secs(8)).await,
        "llmproxyc 未在 8s 内就绪"
    );
    wait_for_link(&client, true).await;

    Ok((
        Stack {
            up,
            d,
            c,
            client,
            dport,
        },
        ca_path,
    ))
}

async fn ask(st: &Stack, mode: &str, base_len: usize) -> (RawResponse, Vec<u8>) {
    let body = make_body(40, 0);
    let r = raw_request(
        &st.client,
        "POST",
        "/v1/messages",
        &[("content-type", "application/json"), ("x-test-mode", mode)],
        &body,
    )
    .await
    .expect("请求失败");
    let expect = st.up.sse_bytes.lock().unwrap()[base_len..].to_vec();
    (r, expect)
}

/// 主判据：配上 CA 之后 https 上游**照常工作**，且逐字节一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https_upstream_works_with_ca() {
    guard(async {
        let (mut st, ca_path) = setup_https(true, &[]).await.expect("夹具应能起来");
        assert!(
            ca_path.exists(),
            "夹具应当生成一份 CA 文件（现生成 ✓ 不入库）：{}",
            ca_path.display()
        );

        let base_len = st.up.sse_bytes.lock().unwrap().len();
        let (r, expect) = ask(&st, "sse-many", base_len).await;
        assert_eq!(r.status, 200, "https 上游应当照常工作");
        assert!(!expect.is_empty(), "上游应当产出了字节");
        assert_bytes_eq(&r.body, &expect, "经 https 上游的响应必须逐字节一致");

        assert_eq!(
            st.up.rec.len(),
            1,
            "上游应当**恰好**收到一次请求（多一次少一次都说明路径不对）"
        );
        assert!(
            st.up.tls_ok.load(std::sync::atomic::Ordering::Relaxed) >= 1,
            "TLS 握手应当成功过"
        );
        assert_eq!(
            st.status().await.unwrap()["truncated_responses"]
                .as_u64()
                .unwrap(),
            0,
            "经 https 上游不该产生任何截断"
        );
        st.d.kill();
    })
    .await;
}

/// **负向对照**：不配 CA ⇒ 请求必须失败，而且**上游一个请求都收不到**。
///
/// 这条是整组里最重要的一条：它同时否掉两种"看起来能用"的错法 ——
/// ① 静默降级成明文（那上游会收到请求 ✗）；② 校验失败但客户端却拿到了 200 ✗。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https_upstream_without_ca_fails_and_upstream_sees_nothing() {
    guard(async {
        let (mut st, ca_path) = setup_https(false, &[]).await.expect("夹具应能起来");

        let base_len = st.up.sse_bytes.lock().unwrap().len();
        let (r, _) = ask(&st, "sse-many", base_len).await;
        assert_ne!(
            r.status, 200,
            "上游证书不被信任时**绝不能**回 200（那等于把 TLS 做成装饰品）✗：{:?}",
            String::from_utf8_lossy(&r.body)
        );
        assert_eq!(
            st.up.rec.len(),
            0,
            "上游**一个请求都不该收到** ⇒ 这就是「没有静默降级成明文」的直接证据 ✗"
        );
        assert!(
            st.up.tls_fail.load(std::sync::atomic::Ordering::Relaxed) >= 1,
            "应当发生且仅发生 TLS 握手失败（用于把「失败在哪一步」说清）"
        );
        println!(
            "  [负向对照] 未配 CA（CA 文件确实存在：{}）⇒ 请求 {}，上游收到 {} 个请求，TLS 握手失败 {} 次",
            ca_path.display(),
            r.status,
            st.up.rec.len(),
            st.up.tls_fail.load(std::sync::atomic::Ordering::Relaxed)
        );
        st.d.kill();
    })
    .await;
}

/// 客户端的 **L2 直连回退**也要支持 https（与共用同一份连接器构造 ✓）。
///
/// 做法：把 `--server` 指到一个**没有人监听**的端口 ⇒ 客户端起不来隧道、只能走直连；
/// 直连目标用 https mock + 生成的 CA ✓。**逐字节一致**是这里唯一的正确性判据 ✓。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_direct_fallback_supports_https() {
    guard(async {
        let (up, ca_path) = MockUpstream::start_tls().await;
        let dead = free_port().await; // 没人监听 ⇒ 隧道建不起来 ✓
        let cport = free_port().await;

        let cargs: Vec<String> = vec![
            "--listen".to_string(),
            format!("127.0.0.1:{cport}"),
            "--server".to_string(),
            format!("ws://127.0.0.1:{dead}"),
            "--upstream-fallback".to_string(),
            up.base_url_https(),
            "--upstream-ca".to_string(),
            ca_path.to_string_lossy().into_owned(),
            "--reconnect-min-ms".to_string(),
            "100".to_string(),
        ];
        let crefs: Vec<&str> = cargs.iter().map(String::as_str).collect();
        // ⚠️ 必须**绑定住**这个句柄（`_c` 而不是 `_`）：`Proc` 的 `Drop` 会杀掉子进程 ✗，
        // 而 `let _ = …` 会**立刻**丢掉它 ⇒ 客户端还没收到请求就没了 ✓。
        let _c = spawn_proxy_env("llmproxyc", &crefs, false, None, &[]).expect("启动客户端失败");
        let client = format!("127.0.0.1:{cport}");
        assert!(
            wait_ready(&client, std::time::Duration::from_secs(8)).await,
            "llmproxyc 未在 8s 内就绪"
        );

        let body = make_body(40, 0);
        let r = raw_request(
            &client,
            "POST",
            "/v1/messages",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "sse-many"),
            ],
            &body,
        )
        .await
        .expect("直连回退请求失败");
        assert_eq!(
            r.status,
            200,
            "主链路不可用时，L2 直连也必须能经 **https** 上游把请求做完：{:?}",
            String::from_utf8_lossy(&r.body)
        );
        let expect = up.sse_bytes.lock().unwrap().clone();
        assert!(!expect.is_empty(), "上游应当产出了字节");
        assert_bytes_eq(&r.body, &expect, "经 https 直连回退的响应必须逐字节一致");
        assert!(
            up.tls_ok.load(std::sync::atomic::Ordering::Relaxed) >= 1,
            "直连回退那次应当是 TLS 连接过"
        );
        assert_eq!(
            up.rec.len(),
            1,
            "上游应当恰好收到一次请求（隧道没建成 ⇒ 只可能是直连那次）"
        );
        let v = raw_request(&client, "GET", "/__dshp/status", &[], b"")
            .await
            .expect("读客户端状态失败");
        let j: serde_json::Value = serde_json::from_slice(&v.body).unwrap();
        assert!(
            j["bypass_requests"].as_u64().unwrap() >= 1,
            "这次请求应当被记成**直连回退**（否则它没走 L2，判据就没测到直连那条路）：{j}"
        );
    })
    .await;
}
