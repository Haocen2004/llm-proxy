//! llmproxyc —— DSHP 客户端（ingress），目标平台 ARM 软路由。
//!
//! M0 目标：四协议经代理后与直连**逐字节一致**（1:1 原样透传）。

mod config;
mod ingress;
mod sse_link;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "llmproxyc", about = "DSHP 客户端（ingress）", version)]
struct Args {
    /// TOML 配置文件。
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// 本地监听地址，覆盖配置文件。
    #[arg(long)]
    listen: Option<String>,
    /// 显式允许局域网访问本地入口（会暴露 prompt 与 API key，请配合防火墙）。
    #[arg(long)]
    allow_lan: bool,
    /// 服务端 WS 地址，覆盖配置文件。
    #[arg(long)]
    server: Option<String>,
    /// 上游主机名，覆盖配置文件。
    #[arg(long)]
    upstream_host: Option<String>,
    /// 租户标识，覆盖配置文件。**两端必须一致**，不一致时握手会被直接拒绝（设计 §4.1）。
    #[arg(long)]
    tenant: Option<String>,
    /// 关闭增量路径，一律原样转发（用于对照与排查）。
    #[arg(long)]
    no_delta: bool,
    /// 增量路径允许缓冲的请求体上限。
    #[arg(long)]
    max_decompose_bytes: Option<usize>,
    /// 上传记账条目上限。
    #[arg(long)]
    upload_entries: Option<usize>,
    /// L2 直连回退的上游 base URL。不给则降级链末端为"整体不可用"。
    #[arg(long)]
    upstream_fallback: Option<String>,
    /// KCP(UDP) 服务端地址，例如 127.0.0.1:9000。不设则不试 KCP。
    #[arg(long)]
    kcp_server: Option<String>,
    /// 强制传输模式：ws / sse。不给则按降级链逐档尝试。
    #[arg(long)]
    force_mode: Option<String>,
    /// 重连退避下限（毫秒）。
    #[arg(long)]
    reconnect_min_ms: Option<u64>,
    /// 空闲保活间隔（秒），0 = 关闭
    ///
    /// 注：这一行 `#[arg(long)]` 不能少——少了 clap 会把它当成**位置参数**
    /// （报错信息形如 `Usage: … [KEEPALIVE_SEC]`，而 `--keepalive-sec` 变成
    /// "unexpected argument"）。我第一次就漏了，端到端夹具表现为"客户端 8s 内没就绪"，
    /// 真正的原因得手工跑一次才看得见——夹具**丢弃子进程输出**。
    #[arg(long)]
    keepalive_sec: Option<u64>,
    /// 重连退避上限（毫秒）。
    #[arg(long)]
    reconnect_max_ms: Option<u64>,
    /// 上游 CA 证书文件（PEM）。直连回退指向自签/私有 CA 的 **https** 上游时才需要；
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
    if args.allow_lan {
        cfg.allow_lan = true;
    }
    if let Some(v) = args.server {
        cfg.server = v;
    }
    if let Some(v) = args.upstream_host {
        cfg.upstream_host = v;
    }
    if let Some(v) = args.tenant {
        cfg.tenant = v;
    }
    if args.no_delta {
        cfg.enable_delta = false;
    }
    if let Some(v) = args.max_decompose_bytes {
        cfg.max_decompose_bytes = v;
    }
    if let Some(v) = args.upload_entries {
        cfg.upload_entries = v;
    }
    if let Some(v) = args.upstream_fallback {
        cfg.upstream_fallback = Some(v);
    }
    if let Some(v) = args.kcp_server {
        cfg.kcp_server = Some(v);
    }
    if let Some(v) = args.force_mode {
        cfg.force_mode = Some(v);
    }
    if let Some(v) = args.reconnect_min_ms {
        cfg.reconnect_min_ms = v;
    }
    if let Some(v) = args.reconnect_max_ms {
        cfg.reconnect_max_ms = v;
    }
    // 注：**加了 CLI 字段不等于接线**——我第一次就漏了这三行，于是
    // `--keepalive-sec 1` 解析成功却毫无作用（生效值仍是默认 30），
    // 端到端表现为"空闲 2.6s 发了 0 帧保活"，只能靠把配置值也暴露到状态里才看出来。
    if let Some(v) = args.keepalive_sec {
        cfg.keepalive_sec = v;
    }
    if let Some(v) = args.upstream_ca {
        cfg.upstream_ca = Some(v.to_string_lossy().into_owned());
    }
    // 直连回退的 scheme 在**启动时**检查（缺口 #4）：写错不该等到"主链路已断、正在降级"
    // 那一刻才失败 —— 那是最不适合排查的时刻 ✗。
    cfg.check_fallback_scheme()?;
    if let Some(base) = &cfg.upstream_fallback {
        if base.to_ascii_lowercase().starts_with("https://") {
            eprintln!(
                "提示：直连回退上游是 https —— 使用内嵌 Mozilla 根集校验{}",
                if cfg.upstream_ca.is_some() {
                    "，并已追加 --upstream-ca 指定的 CA"
                } else {
                    "（自签/私有 CA 请加 --upstream-ca <PEM>）"
                }
            );
        }
    }
    if cfg.psk == "change-me" {
        eprintln!("警告：仍在使用默认 PSK，请通过配置或 DSHP_PSK 环境变量设置");
    }

    // 启动自检：字典必须落在 zstd 窗口内（设计 §12 硬约束 2）
    llm_proxy_core::Dicts::bootstrap()
        .check_fits_window()
        .map_err(|e| anyhow::anyhow!("字典自检失败：{e}"))?;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // 同服务端：默认 **info** ✓（默认 debug 会让软路由上的 journal/串口写入变重 ✗）。
                // 需要诊断时显式给 `RUST_LOG=llmproxyc=debug` 即可 ✓。
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let workers = cfg.worker_threads.max(1);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(1)
        .enable_all()
        .build()?;
    rt.block_on(ingress::run(Arc::new(cfg)))
}
