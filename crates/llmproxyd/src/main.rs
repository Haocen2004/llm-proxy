//! llmproxyd —— DSHP 服务端（egress）。
//!
//! M0 目标：四协议经代理后与直连**逐字节一致**（1:1 原样透传）。

mod config;
mod def_resend_tests;
mod egress;
mod resume;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "llmproxyd", about = "DSHP 服务端（egress）", version)]
struct Args {
    /// TOML 配置文件。
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// WS 监听地址，覆盖配置文件。
    #[arg(long)]
    listen: Option<String>,
    /// KCP(UDP) 监听地址，例如 0.0.0.0:9000。不设则不起 UDP 监听。
    #[arg(long)]
    kcp_bind: Option<String>,
    /// 上游 base URL（不含 path），覆盖配置文件。
    #[arg(long)]
    upstream: Option<String>,
    /// 上游主机名（命名空间的一部分），覆盖配置文件。
    #[arg(long)]
    upstream_host: Option<String>,
    /// 租户标识（命名空间的一部分），覆盖配置文件。**两端必须一致**，
    /// 不一致时握手直接拒绝（设计 §4.1 / §13.9）。
    #[arg(long)]
    tenant: Option<String>,
    /// 块存储预算（字节）。测试用它逼出淘汰与降级路径。
    #[arg(long)]
    block_cache_bytes: Option<usize>,
    /// 缓存有效期（秒）。
    #[arg(long)]
    cache_ttl_secs: Option<u64>,
    /// 并发流超限时的等待时限（毫秒）。测试用它逼出拒绝路径。
    #[arg(long)]
    stream_wait_ms: Option<u64>,
    /// 同时访问上游的活跃流上限（所有 session 共享）。
    #[arg(long)]
    max_concurrent_streams: Option<usize>,
    /// 等待活跃流额度的全局队列上限。
    #[arg(long)]
    max_pending_streams: Option<usize>,
    /// 慢路径 flush 窗口（毫秒）。默认 100。
    #[arg(long)]
    slow_flush_ms: Option<u64>,
    /// 慢路径 flush 字节阈值。默认 1024。
    #[arg(long)]
    slow_flush_bytes: Option<usize>,
    /// 关闭慢路径（用于对照实验）。
    #[arg(long)]
    disable_slow_path: bool,
    /// SSE 批量帧刷新窗口（毫秒）。越大越省带宽，但事件滞留越久。
    #[arg(long)]
    sse_batch_ms: Option<u64>,
    /// 单帧最多合并多少个事件。
    #[arg(long)]
    sse_batch_max: Option<usize>,
    /// 上游 CA 证书文件（PEM）。用于自签/私有 CA 的 **https** 上游；
    /// 语义是**追加**到内嵌 Mozilla 根集之上。**没有"跳过校验"的开关**。
    #[arg(long)]
    upstream_ca: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut cfg = config::Config::load(args.config.as_deref())?;
    if let Some(v) = args.listen {
        cfg.listen = v;
    }
    if let Some(v) = args.kcp_bind {
        cfg.kcp_bind = Some(v);
    }
    if let Some(v) = args.upstream {
        cfg.upstream_base = v;
    }
    if let Some(v) = args.upstream_host {
        cfg.upstream_host = v;
    }
    if let Some(v) = args.tenant {
        cfg.tenant = v;
    }
    if let Some(v) = args.block_cache_bytes {
        cfg.block_cache_bytes = v;
    }
    if let Some(v) = args.cache_ttl_secs {
        cfg.cache_ttl_secs = v;
    }
    if let Some(v) = args.stream_wait_ms {
        cfg.stream_wait_ms = v;
    }
    if let Some(v) = args.max_concurrent_streams {
        cfg.max_concurrent_streams = v;
    }
    if let Some(v) = args.max_pending_streams {
        cfg.max_pending_streams = v;
    }
    if let Some(v) = args.slow_flush_ms {
        cfg.slow_flush_ms = v;
    }
    if let Some(v) = args.slow_flush_bytes {
        cfg.slow_flush_bytes = v;
    }
    cfg.enable_slow_path = !args.disable_slow_path;
    if let Some(v) = args.sse_batch_ms {
        cfg.sse_batch_ms = v;
    }
    if let Some(v) = args.sse_batch_max {
        cfg.sse_batch_max = v;
    }
    if let Some(v) = args.upstream_ca {
        cfg.upstream_ca = Some(v.to_string_lossy().into_owned());
    }
    // 上游 scheme 在**启动时**就要检查：写错（或漏了 scheme）不该等到第一个请求才变成一个
    // 含义模糊的 502 ✗。
    cfg.check_upstream_scheme()?;
    if cfg
        .upstream_base
        .to_ascii_lowercase()
        .starts_with("https://")
    {
        eprintln!(
            "提示：上游是 https —— 使用内嵌 Mozilla 根集校验{}",
            if cfg.upstream_ca.is_some() {
                "，并已追加 --upstream-ca 指定的 CA"
            } else {
                "（自签/私有 CA 请加 --upstream-ca <PEM>）"
            }
        );
    }
    if cfg.psk == "change-me" {
        eprintln!("警告：仍在使用默认 PSK，请通过配置或 DSHP_PSK 环境变量设置");
    }
    if cfg.webui_token.is_empty() {
        eprintln!("提示：未设置 DSHP_WEBUI_TOKEN，统计 WebUI 将保持关闭");
    }

    // 启动自检：三本内嵌字典必须落在 zstd 窗口内（设计 §12 硬约束 2）
    llm_proxy_core::Dicts::bootstrap()
        .check_fits_window()
        .map_err(|e| anyhow::anyhow!("字典自检失败：{e}"))?;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // 默认 **info**，不再默认 `llmproxyd=debug` ✓。
                //
                // 为什么改：第 187 轮在生产机核实（`docs/llmproxyd-cpu-report.md` E6 ✓）发现
                // 该机的 unit 里**没有** `RUST_LOG` ⇒ 默认就落在 `debug` ✗，于是每次归纳/每会话
                // 都要格式化若干行写进 journald ✓。
                //
                // 如实说清收益：热路径（`relay_sse`/`drain_events`/`flush_*`）**没有**每事件级日志 ✓
                // （已逐行扫过 ✓），`"SSE 归纳完成"` 是**每流一条** ✓ ⇒ 关掉它**不会**带来可测的
                // CPU 下降 ✗ —— 所以这次改的是**默认值的合理性** ✓（诊断仍随时可开 ✓），
                // 而不是把它当作 CPU 问题的解 ✗。
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let workers = cfg.worker_threads.max(1);
    let cfg = Arc::new(cfg);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(1)
        .enable_all()
        .build()?;
    rt.block_on(egress::run(cfg))
}
