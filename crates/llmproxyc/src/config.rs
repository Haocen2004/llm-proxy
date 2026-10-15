//! 客户端配置。

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// 本地入口监听地址。默认只绑回环；局域网监听必须显式启用 `allow_lan`。
    pub listen: String,
    /// 显式允许把本地入口绑定到局域网地址。
    pub allow_lan: bool,
    /// 服务端 WS 地址，支持 `ws://` 与 `wss://`。
    pub server: String,
    /// 上游主机名。用于缓存命名空间派生，必须与服务端一致（设计 §4.1）。
    pub upstream_host: String,
    /// 租户标识。参与缓存命名空间派生 `ns = HMAC(psk, tenant ‖ upstream_host)`（§5.1）。
    ///
    /// **必须与服务端一致**：不一致时握手会被服务端拒绝（设计 §4.1）。这里不做
    /// 「不一致就自动改」的兜底——那会让租户隔离变得不可观测，也可能把请求
    /// 送进另一个租户的命名空间。
    pub tenant: String,
    /// 预共享密钥。
    pub psk: String,
    /// tokio 工作线程数。软路由上取 1~2。
    pub worker_threads: usize,
    /// 是否启用增量路径。关闭后一律原样转发（用于排查问题与对照测试）。
    pub enable_delta: bool,
    /// 增量路径允许缓冲的请求体上限。超过则流式原样转发。
    pub max_decompose_bytes: usize,
    /// 上传记账的条目上限。只存指纹，不存内容。
    pub upload_entries: usize,
    /// 缓存有效期（秒）。仅用于状态展示与文档一致性。
    pub cache_ttl_secs: u64,
    /// **L2 直连回退**的上游 base URL。
    ///
    /// 设计 §10 的降级链末端：`KCP → WS → SSE → L2 直连上游`。DSHP 链路不可用时，
    /// 客户端直接以普通 HTTP 转发到上游——**功能不中断，只是失去流量优化**。
    /// 不给这一项时降级链退化为"整体不可用"。
    pub upstream_fallback: Option<String>,
    /// 强制使用某种传输模式（`ws` / `sse`）。不给则按降级链逐档尝试。
    ///
    /// 存在的理由：降级链是"能用就用好的"，而**验收需要能确定性地测每一档**。
    /// 没有它就只能靠外部手段去拦 WebSocket，测起来既脆弱又测不准。
    /// KCP(UDP) 服务端地址，例如 127.0.0.1:9000。
    /// **不设就完全不试 KCP**——它需要放行 UDP，盲目尝试只会白等一轮握手。
    pub kcp_server: Option<String>,
    pub force_mode: Option<String>,
    /// 重连退避下限（毫秒）。
    pub reconnect_min_ms: u64,
    /// 重连退避上限（毫秒）。退避翻倍增长到此为止，再加 ±25% 抖动避免惊群。
    pub reconnect_max_ms: u64,
    /// 空闲保活间隔（秒）。0 = 关闭。
    ///
    /// 为什么需要（缺口 9）：`Ping`/`Pong` 的**接收**侧两端都齐，但此前**没有任何
    /// 发送方**（只有 KCP 内联发）⇒ WS/SSE 链路空闲时没有保活，中间设备/NAT 可以
    /// 悄悄回收连接而双方都不知情（下一个请求才由请求路径的健康检查发现并降级）。
    /// 取 30s：远小于常见的 NAT 空闲超时（通常 ≥60s），又不至于让心跳成为噪声。
    pub keepalive_sec: u64,
    /// **上游 CA 证书文件**（PEM）。直连回退（`--upstream-fallback`）指向自签/私有 CA 的
    /// https 上游时才需要；语义是**追加**到内嵌 Mozilla 根集之上 ✓。
    /// 来源：`--upstream-ca` 或 `DSHP_UPSTREAM_CA`。**没有"跳过校验"的开关** ——
    /// 见 `llm_proxy_transport::upstream`（与 `llmproxyd` 共用同一份实现 ✓）。
    pub upstream_ca: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8787".to_string(),
            allow_lan: false,
            server: "ws://127.0.0.1:9000".to_string(),
            upstream_host: "localhost".to_string(),
            // 默认单租户：空串。多租户部署必须显式设置。
            tenant: String::new(),
            psk: "change-me".to_string(),
            worker_threads: 2,
            enable_delta: true,
            max_decompose_bytes: llm_proxy_core::config::MAX_DECOMPOSE_BYTES,
            upload_entries: llm_proxy_cache::DEFAULT_UPLOAD_ENTRIES,
            cache_ttl_secs: llm_proxy_cache::DEFAULT_TTL.as_secs(),
            upstream_fallback: None,
            kcp_server: None,
            force_mode: None,
            reconnect_min_ms: 200,
            keepalive_sec: 30,
            reconnect_max_ms: 5_000,
            upstream_ca: None,
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let mut cfg = match path {
            Some(p) if p.exists() => {
                let text = std::fs::read_to_string(p)
                    .with_context(|| format!("读取配置失败 {}", p.display()))?;
                toml::from_str(&text).with_context(|| format!("解析配置失败 {}", p.display()))?
            }
            _ => Self::default(),
        };
        if let Ok(v) = std::env::var("DSHP_PSK") {
            cfg.psk = v;
        }
        if let Ok(v) = std::env::var("DSHP_ALLOW_LAN") {
            cfg.allow_lan = matches!(v.as_str(), "1" | "true" | "yes");
        }
        if let Ok(v) = std::env::var("DSHP_UPSTREAM_CA") {
            cfg.upstream_ca = Some(v);
        }
        Ok(cfg)
    }

    /// 拒绝把入口绑到非回环地址。
    pub fn check_loopback(&self) -> Result<(), String> {
        if self.allow_lan {
            return Ok(());
        }
        let host = self
            .listen
            .rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| self.listen.clone());
        let ok = matches!(host.as_str(), "127.0.0.1" | "localhost" | "[::1]" | "::1");
        if !ok {
            return Err(format!(
                "入口地址 {} 不是回环地址。这会把 prompt 与 API key 暴露到局域网；\
                 如确需如此，请显式修改 check_loopback 的判定。",
                self.listen
            ));
        }
        Ok(())
    }
}

pub type Shared = Arc<Config>;

/// 直连回退用的 HTTP 客户端。
///
/// 只有 `--upstream-fallback` 路径会用它——正常路径由服务端发上游请求。
/// 类型与构造都与服务端共用（见 `llm_proxy_transport::upstream`）✓。
pub type HttpClient = llm_proxy_transport::upstream::UpstreamClient;

impl Config {
    /// 直连回退用的上游 HTTP 客户端（**支持 https**，缺口 #4）。
    ///
    /// 与服务端共用同一份连接器构造（`llm_proxy_transport::upstream`）⇒ 证书策略一致：
    /// 内嵌 Mozilla 根集 + 可选 `--upstream-ca` 追加，**没有跳过校验的开关** ✓。
    pub fn http_client(&self) -> anyhow::Result<HttpClient> {
        Ok(llm_proxy_transport::upstream::client(
            self.upstream_ca.as_deref().map(std::path::Path::new),
        )?)
    }

    /// 直连回退地址的 scheme 必须在启动时检查：写错不该等到降级那一刻才失败 ✗
    /// （那时正好是"主链路已断"的时刻，现场最不适合排查 ✓）。
    pub fn check_fallback_scheme(&self) -> anyhow::Result<()> {
        let Some(base) = &self.upstream_fallback else {
            return Ok(());
        };
        let lower = base.to_ascii_lowercase();
        anyhow::ensure!(
            lower.starts_with("http://") || lower.starts_with("https://"),
            "直连回退地址必须以 http:// 或 https:// 开头，实测 `{base}`"
        );
        Ok(())
    }

    /// 直连回退的完整 URL。**只做前缀拼接，不做任何路径改写**（设计 §4.1 上游无关），
    /// 与 `llmproxyd::Config::upstream_url` 保持同一规则。
    pub fn fallback_url(&self, path_and_query: &str) -> Option<String> {
        let base = self.upstream_fallback.as_ref()?.trim_end_matches('/');
        Some(if path_and_query.starts_with('/') {
            format!("{base}{path_and_query}")
        } else {
            format!("{base}/{path_and_query}")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 直连回退的 scheme 也要在**启动时**判死（缺口 #4）——失败时刻正是"主链路已断"，
    /// 那是最不适合排查的时候 ✗。
    #[test]
    fn fallback_scheme_is_checked_at_startup() {
        let mk = |base: Option<&str>| Config {
            upstream_fallback: base.map(str::to_string),
            ..Config::default()
        };
        assert!(mk(None).check_fallback_scheme().is_ok(), "没配就不检查 ✓");
        assert!(mk(Some("http://h:1")).check_fallback_scheme().is_ok());
        assert!(mk(Some("https://h:1")).check_fallback_scheme().is_ok());
        assert!(mk(Some("HTTPS://h:1")).check_fallback_scheme().is_ok());
        assert!(mk(Some("h:1")).check_fallback_scheme().is_err());
        assert!(mk(Some("ws://h:1")).check_fallback_scheme().is_err());
    }

    #[test]
    fn loopback_guard() {
        let mut c = Config::default();
        assert!(c.check_loopback().is_ok());
        c.listen = "localhost:8787".into();
        assert!(c.check_loopback().is_ok());
        c.listen = "0.0.0.0:8787".into();
        assert!(c.check_loopback().is_err());
        c.listen = "192.168.1.1:8787".into();
        assert!(c.check_loopback().is_err());
    }
}
