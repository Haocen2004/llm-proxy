//! **上游 HTTP 客户端**（含 TLS）—— 缺口 #4：让 `--upstream` / `--upstream-fallback` 支持 `https://`。
//!
//! # 为什么放在这里
//!
//! 服务端（`llmproxyd`，隧道出口）与客户端（`llmproxyc`，直连回退）**都要**能连上游，
//! 而两边原先各写了一份逐字相同的 `http_client()` ✗ —— 那种重复一定会漂移
//! （第 174 轮把两处逐字相同的链路等待抽成 `wait_for_link` 就是同一个教训 ✓）。
//!
//! # 证书策略（刻意保守）
//!
//! * 根证书 = **内嵌的 Mozilla 根集**（[`webpki_roots`]），**不读系统证书目录**：
//!   OpenWrt 上常常没有 `/etc/ssl/certs` ⇒ 读系统存储会变成"开发机连得上、装到设备上不行" ✗。
//! * 私有 / 自签 CA 用 `--upstream-ca <path>` **追加**（不是替换 ✓，公网上游照旧可用 ✓）。
//! * **没有"跳过校验"的开关**：缺口表里那一行说的是"支持 TLS"，不是"支持假装有 TLS" ✗。
//!   真正的失败必须**响亮**（握手/校验失败 ⇒ 请求失败），绝不静默降级成明文 ✓。

use std::path::Path;

use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::ChannelBody;

/// 上游连接器：明文走 `HttpConnector`，`https://` 走 rustls（自动按 URL 的 scheme 选 ✓）。
pub type UpstreamConnector = HttpsConnector<HttpConnector>;

/// 上游 HTTP 客户端。两端的 `config.rs` 都直接用它（同一个类型，同一个构造 ✓）。
///
/// 响应体复用隧道侧同款 [`ChannelBody`]：**刻意不另造一个"形状相同的" body 类型** ——
/// 那种两份定义一定会有人在某处混用 ✗（第 181 轮把两处逐字相同的夹具抽成一个，同一条规矩 ✓）。
pub type UpstreamClient = hyper_util::client::legacy::Client<UpstreamConnector, ChannelBody>;

/// 构造上游连接器时可能出现的错误。
///
/// 用 `thiserror` 而不是 `anyhow`：这个 crate 是**库**，其余模块也都是 thiserror 风格 ✓
/// （调用方两端都是 anyhow，`?` 会自动转换 ✓）。
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("读不到上游 CA 文件 {path}：{source}")]
    CaRead {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("解析上游 CA 文件失败：{0}")]
    CaParse(String),
    #[error("上游 CA 证书不被接受：{0}")]
    CaRejected(String),
    #[error("上游 CA 文件 {path} 里没有解析出任何证书（期望 PEM 格式的 CERTIFICATE 块）")]
    CaEmpty { path: String },
}

/// 构造上游连接器。
///
/// `ca_file`：可选的 PEM 证书文件路径（`--upstream-ca`）。它**追加**在内嵌根集之上 ✓。
pub fn connector(ca_file: Option<&Path>) -> Result<UpstreamConnector, UpstreamError> {
    // 进程级 crypto provider：与 `wss://` 隧道那条路共用**同一处**幂等安装 ✓
    // （见 `crate::install_crypto_provider_once` 的说明：各自 `expect` 会把对方打成 panic ✗）。
    crate::install_crypto_provider_once();

    let mut roots = rustls::RootCertStore::empty();
    // 内嵌 Mozilla 根集：`webpki_roots::TLS_SERVER_ROOTS` 是 `TrustAnchor` 列表 ✓。
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(path) = ca_file {
        let pem = std::fs::read(path).map_err(|e| UpstreamError::CaRead {
            path: path.display().to_string(),
            source: e,
        })?;
        let mut rd = std::io::BufReader::new(&pem[..]);
        let mut added = 0usize;
        for cert in rustls_pemfile::certs(&mut rd) {
            let cert = cert.map_err(|e| UpstreamError::CaParse(e.to_string()))?;
            roots
                .add(cert)
                .map_err(|e| UpstreamError::CaRejected(e.to_string()))?;
            added += 1;
        }
        if added == 0 {
            return Err(UpstreamError::CaEmpty {
                path: path.display().to_string(),
            });
        }
        tracing::info!(path = %path.display(), added, roots = roots.len(), "上游 CA 已追加");
    }

    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        // 上游一律用默认的密码套件与 TLS1.2/1.3 ✓：不加"兼容旧服务端"的例外，
        // 因为静默放宽的下限迟早会变成默认值 ✗。
        .with_no_client_auth();
    // ⚠️ **不要自己设 `alpn_protocols`** ✗：`HttpsConnectorBuilder` 会自己按启用的
    // HTTP 版本设置，预置它会**直接 panic**（"ALPN protocols should not be pre-defined" ✓，
    // 第 181 轮被"连接器能否构造"那条用例当场抓到 ✓）。
    // 本项目的上游走 HTTP/1.1（M0 起如此），所以下面只 `enable_http1()` ✓。

    let mut http = HttpConnector::new();
    http.set_nodelay(true);
    // **必须放开**：`enforce_http(true)`（M0 的"只支持明文上游"）会让 https 请求在
    // 连接层就被拒 ✗。放开之后安全性由上面的 rustls 配置负责 ✓，而不是"不允许 https"。
    http.enforce_http(false);

    Ok(hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .wrap_connector(http))
}

/// 构造上游 HTTP 客户端。见 [`connector`] 的证书策略。
pub fn client(ca_file: Option<&Path>) -> Result<UpstreamClient, UpstreamError> {
    let connector = connector(ca_file)?;
    Ok(hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build(connector))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_type_is_anyhow_compatible() {
        // 两端的 `config.rs` 都是 anyhow ⇒ 这里**编译期**保证 `?` 能转换。
        // 少了这条，"错误类型忘了派生/字段不满足 Send+Sync"会在**调用方**变成一个
        // 让人费解的 E0308（第 181 轮实测就是如此 ✗）。
        fn assert_bounds<E: std::error::Error + Send + Sync + 'static>() {}
        assert_bounds::<UpstreamError>();
    }

    #[test]
    fn connector_builds_without_ca_file() {
        // 内嵌根集必须非空（否则 https 上游会全数失败，而且现场只会看到"证书无效" ✗）。
        let c = connector(None).expect("构造上游连接器失败");
        let _ = c;
    }

    #[test]
    fn missing_ca_file_is_a_loud_error() {
        let e = connector(Some(Path::new("不存在的-CA-文件.pem"))).unwrap_err();
        assert!(
            e.to_string().contains("读不到上游 CA 文件"),
            "缺文件必须报出**它自己的**原因：{e}"
        );
    }

    #[test]
    fn ca_file_without_certificate_is_rejected() {
        // 空文件 / 只有注释：**必须报错**，不能"静默地什么都没加"✗
        // （那会让运维以为配了 CA，实际仍在用内嵌根集 ⇒ 连不上时完全查不出原因）。
        let dir = std::env::temp_dir().join("dshp-upstream-ca-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("empty.pem");
        std::fs::write(&p, "# 只有注释\n".as_bytes()).unwrap();
        let e = connector(Some(&p)).unwrap_err();
        assert!(
            e.to_string().contains("没有解析出任何证书"),
            "空 CA 文件必须响亮失败：{e}"
        );
    }
}
