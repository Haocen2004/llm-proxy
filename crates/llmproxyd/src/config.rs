//! 服务端配置。

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use serde::Deserialize;

/// 上游 HTTP 客户端（支持明文与 TLS，见 `llm_proxy_transport::upstream`）。
pub type HttpClient = llm_proxy_transport::upstream::UpstreamClient;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// WS 监听地址。
    pub listen: String,
    /// KCP(UDP) 监听地址。未设置则不起 UDP 监听——KCP 需要放行 UDP，
    /// 不做成默认开启，否则在只放行 TCP 的环境里会白等一轮握手。
    pub kcp_bind: Option<String>,
    /// 上游 base URL（**不含 path**）：收到的 path 与 query 原样拼在其后。
    pub upstream_base: String,
    /// 预共享密钥。
    pub psk: String,
    /// 与客户端 `CAPS` 强校验的一致性字段（设计 §4.1）。
    pub upstream_host: String,
    /// 租户标识。参与缓存命名空间派生 `ns = HMAC(psk, tenant ‖ upstream_host)`（§5.1）。
    ///
    /// **必须与客户端一致**：不一致时握手**直接拒绝**（设计 §4.1），不做任何降级——
    /// 两端命名空间错位会让缓存全不命中（白花钱），更糟的是让不同租户共享命名空间，
    /// 而 §13.9/T7 要求「块查询严格限定在本租户命名空间内」。
    pub tenant: String,
    /// tokio 工作线程数。软路由上取 1~2。
    pub worker_threads: usize,
    /// 服务端块存储预算（字节）。服务端无 ARM 内存约束，可远大于客户端。
    pub block_cache_bytes: usize,
    /// 缓存有效期（秒）。设计 §5.1 定为 6 小时，自创建时刻固定计算。
    pub cache_ttl_secs: u64,
    /// 是否启用慢路径（对照实验用）。
    pub enable_slow_path: bool,
    /// 慢路径的 flush 窗口（毫秒）。设计 §6.3 定为 100ms。
    ///
    /// **时间驱动而非计数驱动**：计数驱动在高吞吐时延迟爆炸（攒够 1KB 才发），
    /// 时间驱动把延迟上界钉死在窗口长度上。这个值同时也是 M3 验收「慢路径延迟 ≤100ms」的量。
    pub slow_flush_ms: u64,
    /// 慢路径的 flush 字节阈值。与 `slow_flush_ms` **先到者触发**。
    pub slow_flush_bytes: usize,
    /// 并发流超限时**等待**多长时间才拒绝（毫秒）。
    ///
    /// 等待而非立即拒绝：这个上限保护的是内存（每个流可能缓冲到
    /// `MAX_DECOMPOSE_BYTES`），而客户端正常并发时排队即可——没有理由让它失败。
    /// 超时才拒绝，那才是真的 DoS。
    pub stream_wait_ms: u64,
    /// 同时访问上游的活跃流上限。所有 session 共享这一额度；`usize::MAX` 表示默认无界。
    ///
    /// 这是资源上限，不是客户端可以创建的逻辑请求数；超过它的请求会先等待
    /// `stream_wait_ms`，只有等不到额度才失败。
    pub max_concurrent_streams: usize,
    /// 全进程允许等待活跃额度的 stream 数量；`usize::MAX` 表示默认无界。
    /// 客户端在收到 `StreamReady` 前不会发送请求体，因此显式配置限额时，排队不会
    /// 把大 body 提前灌入流 channel。
    pub max_pending_streams: usize,
    /// SSE 批量帧的刷新窗口（毫秒）。
    ///
    /// **这不是纯优化参数，而是延迟与带宽的权衡**，且权衡曲线是「先陡后平」：
    /// 24 字节帧头摊薄得很快，但摊到一定程度后剩下的地板是变量槽本身。
    ///
    /// 实测（116 字节/事件、10 ms/事件、3 字节 token）：
    ///
    /// | 窗口 | 每批事件数 | 链路占比 | 是否达标(≤10%) |
    /// |---|---|---|---|
    /// | 40 ms | ≈4 | **14.2%** | ❌ |
    /// | 100 ms | ≈7 | **10.2%** | ❌ 差 0.2 个百分点 |
    /// | 150 ms | ≈10 | **8.9%** | ✅ |
    ///
    /// 之所以必须取到 150 ms 而不是设计 §13.3 文本里的 100 ms：还有一笔**每响应固有**
    /// 的一次性成本（一个归纳样本 + 一次 `TEMPLATE_DEF` + 单例事件 ≈ 314 B），
    /// 在 16 KB 的短响应上就占 1.9%。窗口越小、帧头摊销越差，两者叠加就越过验收线。
    ///
    /// 后续若要压低延迟，正确方向不是缩窗口，而是**跨响应复用模板**（设计 §6.4），
    /// 把那一笔 314 B 变成只在连接首响应支付。
    pub sse_batch_ms: u64,
    /// 单帧最多合并多少个事件。达到即立刻刷新，不等窗口。
    ///
    /// 突发到达时靠它把批做大，避免全依赖时间窗口。
    pub sse_batch_max: usize,
    /// WebUI/统计接口鉴权令牌。为空时不启用 WebUI（避免误暴露诊断数据）。
    pub webui_token: String,
    /// 统计快照路径；空字符串表示仅使用内存。
    pub stats_file: String,
    /// 是否允许**非隧道的普通 HTTP 请求直连透传**到上游（默认关闭）。
    ///
    /// 与客户端的 `--allow-lan` 一样是**显式授权**：服务端的端口本来是"只服务 DSHP 隧道"的，
    /// 打开它等于服务端同时也是对上游的普通反代 —— 谁能访问这个端口谁就能用上游，
    /// 凭据仍然是上游自己的 key（代理不会替你鉴权）。用 `DSHP_ALLOW_PASSTHROUGH=1` 打开。
    pub allow_passthrough: bool,
    /// **上游 CA 证书文件**（PEM）。可选；用了自签/私有 CA 的 https 上游才需要。
    ///
    /// 语义是**追加**到内嵌的 Mozilla 根集之上（不是替换 ✓）。来源：`--upstream-ca` 或
    /// `DSHP_UPSTREAM_CA`。**没有"跳过校验"的开关** —— 见 `llm_proxy_transport::upstream`。
    pub upstream_ca: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9000".to_string(),
            kcp_bind: None,
            upstream_base: "http://127.0.0.1:9100".to_string(),
            psk: "change-me".to_string(),
            upstream_host: "localhost".to_string(),
            // 默认单租户：空串。多租户部署必须显式设置，否则不同客户会共享命名空间。
            tenant: String::new(),
            worker_threads: 2,
            block_cache_bytes: llm_proxy_cache::DEFAULT_SERVER_BUDGET,
            cache_ttl_secs: llm_proxy_cache::DEFAULT_TTL.as_secs(),
            stream_wait_ms: 20_000,
            // 生产默认不按请求数量限流；资源保护由每流大小上限、缓存预算和传输背压承担。
            // 运维若需要硬护栏，可通过 CLI 显式设置这两个值。
            max_concurrent_streams: usize::MAX,
            max_pending_streams: usize::MAX,
            enable_slow_path: true,
            slow_flush_ms: 100,
            slow_flush_bytes: 1024,
            sse_batch_ms: 150,
            sse_batch_max: 32,
            webui_token: String::new(),
            stats_file: String::new(),
            allow_passthrough: false,
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
        if let Ok(v) = std::env::var("DSHP_WEBUI_TOKEN") {
            cfg.webui_token = v;
        }
        if let Ok(v) = std::env::var("DSHP_STATS_FILE") {
            cfg.stats_file = v;
        }
        if let Ok(v) = std::env::var("DSHP_ALLOW_PASSTHROUGH") {
            cfg.allow_passthrough = matches!(v.as_str(), "1" | "true" | "yes");
        }
        if let Ok(v) = std::env::var("DSHP_UPSTREAM_CA") {
            cfg.upstream_ca = Some(v);
        }
        // 至少保留一个活跃槽位；否则 App 会被迫用 `max(1)`，而诊断端点与错误
        // 信息却仍显示用户配置的 0，形成“看起来已关闭、实际上仍可执行”的错觉。
        cfg.max_concurrent_streams = cfg.max_concurrent_streams.max(1);
        Ok(cfg)
    }

    /// 上游 HTTP 客户端（**支持 https**，缺口 #4）。
    ///
    /// 连接的 scheme 由 URL 决定：`http://` 走明文、`https://` 走 rustls ✓
    /// （证书策略见 `llm_proxy_transport::upstream`：内嵌 Mozilla 根集 + 可选 `--upstream-ca` 追加，
    /// **没有跳过校验的开关** ✓）。
    pub fn http_client(&self) -> anyhow::Result<HttpClient> {
        Ok(llm_proxy_transport::upstream::client(
            self.upstream_ca.as_deref().map(Path::new),
        )?)
    }

    /// 上游 base 的 scheme 必须是 http/https —— 别的（或写错）要在**启动时**就报错，
    /// 而不是等到第一个请求才失败（那样现场只剩一个含义模糊的 502 ✗）。
    pub fn check_upstream_scheme(&self) -> anyhow::Result<()> {
        let lower = self.upstream_base.to_ascii_lowercase();
        anyhow::ensure!(
            lower.starts_with("http://") || lower.starts_with("https://"),
            "上游地址必须以 http:// 或 https:// 开头，实测 `{}`",
            self.upstream_base
        );
        Ok(())
    }

    /// 拼接上游完整 URL。**只做前缀拼接，不做任何路径改写**（设计 §4.1 上游无关）。
    pub fn upstream_url(&self, path_and_query: &str) -> String {
        let base = self.upstream_base.trim_end_matches('/');
        if path_and_query.starts_with('/') {
            format!("{base}{path_and_query}")
        } else {
            format!("{base}/{path_and_query}")
        }
    }
}

pub type Shared = Arc<Config>;

#[cfg(test)]
mod tests {
    use super::*;

    /// 上游 scheme 在**启动时**就要判死（缺口 #4）：写错不该等到第一个请求才变成含义模糊的 502 ✗。
    #[test]
    fn upstream_scheme_is_checked_at_startup() {
        for (base, ok) in [
            ("http://127.0.0.1:9100", true),
            ("https://api.example.com", true),
            ("HTTPS://api.example.com", true), // 大小写不该影响判定 ✓
            ("ftp://x", false),
            ("127.0.0.1:9100", false), // 漏了 scheme 也要拒 ✓
            ("", false),
        ] {
            let cfg = Config {
                upstream_base: base.to_string(),
                ..Config::default()
            };
            assert_eq!(
                cfg.check_upstream_scheme().is_ok(),
                ok,
                "`{base}` 的判定不对（期望 ok={ok}）"
            );
        }
    }

    #[test]
    fn url_join_preserves_path_and_query() {
        let cfg = Config::default();
        assert_eq!(
            cfg.upstream_url("/v1/messages?beta=true"),
            "http://127.0.0.1:9100/v1/messages?beta=true"
        );
        assert_eq!(
            cfg.upstream_url("/v1/chat/completions"),
            "http://127.0.0.1:9100/v1/chat/completions"
        );
        // base 尾部斜杠不应产生双斜杠
        let cfg2 = Config {
            upstream_base: "http://h:1/".into(),
            ..Config::default()
        };
        assert_eq!(cfg2.upstream_url("/v1/x"), "http://h:1/v1/x");
    }
}
