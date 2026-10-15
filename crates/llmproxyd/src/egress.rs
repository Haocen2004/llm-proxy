//! 服务端 egress：认证 → 按 stream 转发上游 → 原样回传响应。
//!
//! M1a 起支持两种请求编码：
//!
//! * `ENC_RAW`——逐字节原样转发（**流式**，不缓冲，M0 行为）；
//! * `ENC_TOKENSTREAM`——收到 TokenStream 后用块存储重组，**校验通过才发上游**。
//!
//! 为什么 `ENC_TOKENSTREAM` 必须先缓冲再校验：POST 上游不可幂等，把一个重组错误的
//! body（哪怕只是一个字节）发出去就是真实事故。设计 §3.2 把「静默错误」列为唯一
//! 致命风险，所以这里宁可用内存换掉这个风险。代价是单流最多缓冲
//! [`llm_proxy_core::config::MAX_DECOMPOSE_BYTES`]（8 MB）。

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context};
use base64::Engine;
use bytes::Bytes;
use http::{HeaderName, HeaderValue, Request, Response};
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use llm_proxy_cache::BlockStore;
use llm_proxy_core::compression::CompressPool;
use llm_proxy_core::config::{
    err_code, hint, semaphore_permits, MAX_DECOMPOSE_BYTES, MAX_TOKENSTREAM_BYTES,
};
use llm_proxy_core::fingerprint::{block_fp, body_fp, Namespace};
use llm_proxy_core::token::RecomposeError;
use llm_proxy_core::{flags, proto, Flags, Frame, FrameType};
use llm_proxy_transport::{verify_handshake, ChannelBody, Mux, SessionError};
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::config::{Config, HttpClient, Shared};

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 进程级共享状态。
pub struct App {
    pub cfg: Config,
    pub client: HttpClient,
    /// **进程级**并发流信号量（缺口 11，第 112 轮）。
    ///
    /// 原先它建在 `run_session` 里 ⇒ 只限**每条连接** 4 条 ✗ ⇒ 两个客户端就能把上游并发推到 8，
    /// 而 `MAX_DECOMPRESS_BYTES` 级的缓冲是**按流**占的 ⇒ 内存上界因此不成立 ✗
    /// （`budget.rs` / `common/mod.rs` 的注释写着"要守的性质是**上游侧**并发不超上限，
    /// 因为内存正是被这些请求占住的"✓ —— 那句话只有在**进程级**才成立 ✓）。
    ///
    /// 语义仍是**等待**而不是立即拒绝 ✓（理由见 `run_session` 里的注释：直接拒绝会把
    /// 合法的并发请求变成 502 ✗）。公平性如实写明：**FIFO、只保证不超额、不保证跨连接公平带宽** ✓。
    pub slots: Arc<tokio::sync::Semaphore>,
    /// 逻辑 stream 的全局准入额度 = 活跃额度 + 等待队列额度。
    ///
    /// 该信号量不参与上游并发控制，只负责防止客户端无限创建等待任务。
    pub admission: Arc<tokio::sync::Semaphore>,
    /// **进程级连接额度**（缺口 11 的下半，第 113 轮）。TCP 与 KCP 两条 accept 路径**共用** ✓。
    ///
    /// 超限时：TCP"接进来立刻关" ✓（客户端拿到 EOF，而不是在 backlog 里挂住 ✗）；
    /// KCP 直接丢弃该会话 ✓。理由与取值见 `llm_proxy_core::config::MAX_CONNECTIONS` ✓。
    pub conns: Arc<tokio::sync::Semaphore>,
    /// 与 session 解耦的进程级内容寻址块缓存。所有已认证 session 只要属于同一
    /// `Namespace` 就可以复用其中的块；`Fp` 自带 namespace，租户之间不会串缓存。
    pub blocks: Mutex<BlockStore>,
    /// 压缩上下文池（固定容量、可复用）。见 `llm_proxy_core::compression`。
    pub compress: Arc<CompressPool>,
    /// **只读运行期诊断**：供 `/__dshp/status` 与测试观察内部状态。
    ///
    /// 为什么需要它：缺口 8（客户端放弃后槽位泄漏）迟迟没查清，卡点之一是
    /// **服务端内部状态观察不到**——夹具把子进程 `stdout`/`stderr` 全部丢弃
    /// （`Stdio::null()` + 强制 `RUST_LOG=warn`），日志这条路是断的。
    /// 这几个数字同时也是运维真正想看的指标（并发额度用了多少）。
    pub diag: Arc<Diag>,
    /// **诊断**：每条流当前走到哪一步（`sid=阶段`，供 `/__dshp/status` 读）。它是
    /// 缺口 8 排查的主要仪器（一眼指出"任务卡在哪一段"），同时也是运维想看的
    /// "每条流在做什么"——写入点很少，代价可忽略。
    ///
    /// ⚠️ **它只 insert、从不清理** ✗（第 166 轮发现我自己被它误导过 ✓）⇒ 已结束的流会**永远**
    /// 留着最后一次的相位 ✓ ⇒ 于是"`phases` 里有 N 条 `await-upstream`"**不能**证明那 N 条都还卡着 ✗
    /// —— 那是**历史** ✓。**权威的"当前有几条在途"永远是 `streams_inflight`** ✓。
    /// （清理它要动本字段的所有权 ⇒ 列为待办 ✓；在那之前**先让读它的人知道别被带偏** ✓。）
    pub phases: std::sync::Mutex<std::collections::HashMap<u32, String>>,
    /// **活着的会话登记**（缺口 #7 优雅排空，第 181 轮）。
    ///
    /// 为什么需要它：`FrameType::GoAway` 定义齐全但**全仓库从来没人发**——因为服务端
    /// 手里根本没有"当前有哪些会话"这份名单 ✗。排空要逐个通知，就必须先登记。
    /// 键是会话号（本进程内单调递增），值是该会话的 [`Mux`]（用它发会话级帧 ✓）。
    ///
    /// 只在**握手成功之后**登记 ✓ 同 `diag`：未认证的来源不该出现在名单里，
    /// 更不该被服务端主动发帧（那等于送出一个"你认证过了"的预言机 ✓）。
    pub sessions: std::sync::Mutex<std::collections::HashMap<u64, Mux>>,
    /// 会话号来源（单调递增，进程内唯一）。
    pub next_session: std::sync::atomic::AtomicU64,
    /// **排空状态**：置位后拒绝新隧道连接（`503`），且排空流程只跑一次。
    ///
    /// 为什么排空期间要拒新连接：客户端收到 `GoAway` 会立刻降级并在后台重连；
    /// 若此时还接受它建新会话，就会"建起来→立刻又被排空"来回打转 ✗。
    /// 明确回 503 让客户端继续退避重试，是可预期的行为 ✓。
    pub draining: std::sync::atomic::AtomicBool,
    /// **响应环形缓冲登记**（缺口 #2 SSE 续传，设计 §11.2）：`sid → 该流的响应出口`。
    ///
    /// 为什么挂在 `App`（进程级）而不是会话里：续传的前提正是"**会话死了还能续**" ✓ ——
    /// 客户端重连后是**新会话**，它按 `req_id`（即 `sid`）找到这条流的环继续读 ✓。
    /// 这同时回答了设计 §11.2 的第二个前置问题（"降级时环形缓冲何去何从"）：
    /// 环**不随会话销毁** ✓，由流的生命周期与 `resume::RING_SECS` 的 TTL 兜底 ✓。
    pub rings:
        std::sync::Mutex<std::collections::HashMap<u32, std::sync::Arc<crate::resume::RespSink>>>,
    /// 响应流量与上游 usage 统计，供鉴权后的 WebUI 查看。
    pub traffic: Arc<TrafficStats>,
}

/// 服务端累计流量统计。**以「客户端发请求」为主视角分上下行，每向再分前后两组**：
///
/// | 方向 | 前（内容） | 后（实际传输） |
/// |---|---|---|
/// | 上行（客户端 → 服务端 → 上游） | [`Self::request_body_bytes`] | [`Self::request_transport_bytes`] |
/// | 下行（上游 → 服务端 → 客户端） | [`Self::response_body_bytes`] | [`Self::response_transport_bytes`] |
///
/// 「前」是**应用层内容**：上行是客户端本要发的那份完整请求体（服务端重建后发往上游的那份），
/// 下行是上游真正吐出来的响应体。
/// 「后」是**DSHP 链路上实际占用的字节**（含帧头），口径与客户端状态里的 `req_wire_bytes` /
/// `resp_wire_bytes` 一致，因此两侧可以直接对账。
///
/// 四个数**都随每个正常结束的响应各累加一次**（与 `responses` 同源），所以
/// 「四组数 ÷ 响应数」= 该向的平均字节数，且四者与响应数可互相校验。
///
/// 注意：下行恒为省（代理只在下面省流量），**上行不一定省**——小请求加上帧头后可能比原始更大。
/// 因此节省比例一律用 `1 - 后/前`，**允许为负**（负值表示膨胀），不要拿"省了多少"当上行判据。
#[derive(Debug, Default)]
pub struct TrafficStats {
    counters: std::sync::Mutex<()>,
    persistence: std::sync::Mutex<Option<std::path::PathBuf>>,
    pub responses: std::sync::atomic::AtomicU64,
    /// 上行「前」：客户端原始请求内容（服务端重建出、发往上游的请求体字节）。
    pub request_body_bytes: std::sync::atomic::AtomicU64,
    /// 上行「后」：请求方向在 DSHP 链路上实际传输的字节（含帧头）。
    pub request_transport_bytes: std::sync::atomic::AtomicU64,
    /// 下行「前」：上游响应内容字节。
    pub response_body_bytes: std::sync::atomic::AtomicU64,
    /// 下行「后」：代理实际发给客户端的响应字节（含帧头）。
    pub response_transport_bytes: std::sync::atomic::AtomicU64,
    pub input_tokens: std::sync::atomic::AtomicU64,
    pub output_tokens: std::sync::atomic::AtomicU64,
    /// 输入缓存命中的**原始分量**（口径差异见 [`UsageScanner`]）。
    ///
    /// 三个分量都要留：OpenAI 的 `cached_tokens` 是 `prompt_tokens` 的子集，
    /// 而 Anthropic 的 `cache_read`/`cache_creation` 不在 `input_tokens` 里 ⇒
    /// 命中率的分母要把它们加回去才对两种协议都成立（见 `stats_json`）。
    pub cached_subset_tokens: std::sync::atomic::AtomicU64,
    pub cache_read_tokens: std::sync::atomic::AtomicU64,
    pub cache_creation_tokens: std::sync::atomic::AtomicU64,
    /// **只统计"报了 cache 字段"的那些响应**的输入总量 ⇒ 它就是命中率的分母。
    ///
    /// 不报 cache 的响应**一律不进这个数**（它们的输入量既不做分子也不做分母），
    /// 否则一个不报 cache 的上游会把命中率无脑拉低。覆盖率看 [`Self::cache_reports`]
    /// 与 `usage_reports` 的比值。
    pub cache_input_tokens: std::sync::atomic::AtomicU64,
    /// 报了 cache 字段的响应数（命中率的样本量）。
    pub cache_reports: std::sync::atomic::AtomicU64,
    pub usage_reports: std::sync::atomic::AtomicU64,
    pub chat_completions: ProtocolTraffic,
    pub responses_api: ProtocolTraffic,
    pub messages: ProtocolTraffic,
    /// 直连透传（非隧道 HTTP 请求）的独立记账，见 [`PassthroughStats`]。
    pub passthrough: PassthroughStats,
}

/// 直连透传（非隧道 HTTP 请求）的记账。
///
/// **为什么不并进隧道那四组**：那四组的定义是"前 = 客户端原始内容、后 = 链路上实际传输"，
/// 而透传根本没有编码/复用这一步（前 = 后）⇒ 并进去只会把隧道的节省率**摊薄**。
/// 这一组记的是"**没走隧道、因此没省下来**"的那部分流量，外加它自带的 usage/cache。
#[derive(Debug, Default)]
pub struct PassthroughStats {
    pub requests: std::sync::atomic::AtomicU64,
    /// 上行内容字节（请求体）。
    pub request_bytes: std::sync::atomic::AtomicU64,
    /// 下行内容字节（响应体）。
    pub response_bytes: std::sync::atomic::AtomicU64,
    pub input_tokens: std::sync::atomic::AtomicU64,
    pub output_tokens: std::sync::atomic::AtomicU64,
    pub cached_subset_tokens: std::sync::atomic::AtomicU64,
    pub cache_read_tokens: std::sync::atomic::AtomicU64,
    pub cache_creation_tokens: std::sync::atomic::AtomicU64,
    pub cache_input_tokens: std::sync::atomic::AtomicU64,
    pub cache_reports: std::sync::atomic::AtomicU64,
    pub usage_reports: std::sync::atomic::AtomicU64,
    /// 按协议的请求数（与隧道那份**各记各的**）。
    pub chat_completions: std::sync::atomic::AtomicU64,
    pub responses_api: std::sync::atomic::AtomicU64,
    pub messages: std::sync::atomic::AtomicU64,
}

/// 透传按协议计数。**与隧道的 [`protocol_stats`] 分开**：两份口径不能互相污染。
fn passthrough_protocol<'a>(
    p: &'a PassthroughStats,
    path: &str,
) -> &'a std::sync::atomic::AtomicU64 {
    if path.contains("/chat/completions") {
        &p.chat_completions
    } else if path.contains("/responses") {
        &p.responses_api
    } else if path.contains("/messages") {
        &p.messages
    } else {
        &p.responses_api
    }
}

#[derive(Debug, Default)]
pub struct ProtocolTraffic {
    pub requests: std::sync::atomic::AtomicU64,
    pub input_tokens: std::sync::atomic::AtomicU64,
    pub output_tokens: std::sync::atomic::AtomicU64,
    pub total_tokens: std::sync::atomic::AtomicU64,
    pub cached_subset_tokens: std::sync::atomic::AtomicU64,
    pub cache_read_tokens: std::sync::atomic::AtomicU64,
    pub cache_creation_tokens: std::sync::atomic::AtomicU64,
    pub cache_input_tokens: std::sync::atomic::AtomicU64,
    pub cache_reports: std::sync::atomic::AtomicU64,
    pub usage_reports: std::sync::atomic::AtomicU64,
}

/// 落盘快照。字段与 [`TrafficStats`] 一一对应。
///
/// **改动过字段名，所以每个字段都留了旧名 `alias`**：仓库历史上出现过三套命名
/// （`source_bytes`/`wire_bytes`、"`upload_bytes` + `request_transport_bytes`"、
/// `download_source_bytes`/`download_wire_bytes`），而快照带 `deny_unknown_fields`
/// ——没有 alias 的话，用新二进制启动会**直接拒绝启动**（`统计快照损坏，拒绝覆盖已有数据`）。
/// 这条不是假想：线上就有一份旧命名快照，换版本时实测会挡住启动。
#[derive(serde::Serialize, serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[serde(default)]
struct TrafficSnapshot {
    version: u32,
    responses: u64,
    #[serde(alias = "source_bytes", alias = "download_source_bytes")]
    response_body_bytes: u64,
    #[serde(alias = "wire_bytes", alias = "download_wire_bytes")]
    response_transport_bytes: u64,
    #[serde(alias = "upload_bytes")]
    request_body_bytes: u64,
    request_transport_bytes: u64,
    input_tokens: u64,
    output_tokens: u64,
    cached_subset_tokens: u64,
    cache_read_tokens: u64,
    cache_creation_tokens: u64,
    cache_input_tokens: u64,
    cache_reports: u64,
    usage_reports: u64,
    chat_completions: ProtocolSnapshot,
    responses_api: ProtocolSnapshot,
    messages: ProtocolSnapshot,
    /// 直连透传那一组（旧快照里没有这张表 ⇒ 靠容器级 `default` 补 0）。
    passthrough: PassthroughSnapshot,
}

/// 透传的落盘形状。
///
/// **嵌套结构必须一起写 `#[serde(default)]`**：线上事故就是漏了它 ——
/// 表在、但表里没有新加的字段时反序列化直接失败，服务端起不来（`missing field ...`）。
#[derive(serde::Serialize, serde::Deserialize, Default)]
#[serde(default)]
struct PassthroughSnapshot {
    requests: u64,
    request_bytes: u64,
    response_bytes: u64,
    input_tokens: u64,
    output_tokens: u64,
    cached_subset_tokens: u64,
    cache_read_tokens: u64,
    cache_creation_tokens: u64,
    cache_input_tokens: u64,
    cache_reports: u64,
    usage_reports: u64,
    chat_completions: u64,
    responses_api: u64,
    messages: u64,
}

/// 逐协议统计的落盘形状。
///
/// **`#[serde(default)]` 是必须的，不是顺手加的**：这三张表在旧快照里**是带着的**，
/// 只是里面没有后来的新字段（cache_*）⇒ 嵌套结构不加 default 就会在启动时直接报
/// `missing field \`cached_subset_tokens\`` 而**拒绝启动**。线上实测栽过一次：
/// 顶层字段有 alias/default 保护，唯独嵌套表没有，于是换版本把服务打起不来。
#[derive(serde::Serialize, serde::Deserialize, Default)]
#[serde(default)]
struct ProtocolSnapshot {
    requests: u64,
    input_tokens: u64,
    output_tokens: u64,
    total_tokens: u64,
    cached_subset_tokens: u64,
    cache_read_tokens: u64,
    cache_creation_tokens: u64,
    cache_input_tokens: u64,
    cache_reports: u64,
    usage_reports: u64,
}

#[cfg(test)]
mod persistence_tests {
    use super::TrafficStats;
    use std::sync::atomic::Ordering;

    #[test]
    fn snapshot_survives_restart_and_corruption_is_not_overwritten() {
        let path = std::env::temp_dir().join(format!("dshp-stats-{}.toml", std::process::id()));
        let name = path.to_str().unwrap();
        let stats = TrafficStats::load(name).unwrap();
        stats.responses.store(7, Ordering::Relaxed);
        stats.request_body_bytes.store(9000, Ordering::Relaxed);
        stats.request_transport_bytes.store(1500, Ordering::Relaxed);
        stats.response_body_bytes.store(1200, Ordering::Relaxed);
        stats.response_transport_bytes.store(300, Ordering::Relaxed);
        stats.input_tokens.store(42, Ordering::Relaxed);
        stats.output_tokens.store(18, Ordering::Relaxed);
        stats.usage_reports.store(5, Ordering::Relaxed);
        stats.cached_subset_tokens.store(1500, Ordering::Relaxed);
        stats.cache_read_tokens.store(200, Ordering::Relaxed);
        stats.cache_creation_tokens.store(50, Ordering::Relaxed);
        stats.cache_input_tokens.store(1800, Ordering::Relaxed);
        stats.cache_reports.store(4, Ordering::Relaxed);
        stats.chat_completions.requests.store(3, Ordering::Relaxed);
        stats
            .chat_completions
            .cache_read_tokens
            .store(11, Ordering::Relaxed);
        stats.save().unwrap();
        drop(stats);
        let restored = TrafficStats::load(name).unwrap();
        assert_eq!(restored.responses.load(Ordering::Relaxed), 7);
        // 上下行 × 前后 **四组都要活着回来** ——少一组就等于"字段在、数据不在"
        assert_eq!(restored.request_body_bytes.load(Ordering::Relaxed), 9000);
        assert_eq!(
            restored.request_transport_bytes.load(Ordering::Relaxed),
            1500
        );
        assert_eq!(restored.response_body_bytes.load(Ordering::Relaxed), 1200);
        assert_eq!(
            restored.response_transport_bytes.load(Ordering::Relaxed),
            300
        );
        assert_eq!(restored.input_tokens.load(Ordering::Relaxed), 42);
        assert_eq!(restored.output_tokens.load(Ordering::Relaxed), 18);
        assert_eq!(restored.usage_reports.load(Ordering::Relaxed), 5);
        // 缓存命中的三个原始分量也要活着回来——比例是**现算**的，分量丢了比例就丢了
        assert_eq!(restored.cached_subset_tokens.load(Ordering::Relaxed), 1500);
        assert_eq!(restored.cache_read_tokens.load(Ordering::Relaxed), 200);
        assert_eq!(restored.cache_creation_tokens.load(Ordering::Relaxed), 50);
        assert_eq!(restored.cache_input_tokens.load(Ordering::Relaxed), 1800);
        assert_eq!(restored.cache_reports.load(Ordering::Relaxed), 4);
        assert_eq!(
            restored.chat_completions.requests.load(Ordering::Relaxed),
            3
        );
        assert_eq!(
            restored
                .chat_completions
                .cache_read_tokens
                .load(Ordering::Relaxed),
            11
        );
        std::fs::write(&path, "broken snapshot").unwrap();
        assert!(TrafficStats::load(name).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "broken snapshot");
        std::fs::remove_file(path).unwrap();
        assert!(TrafficStats::load("").is_ok());
    }

    /// **协议表在、但表里缺新字段时也必须能载入**。
    ///
    /// 这条是**线上事故换来的**（不是假想）：顶层字段有 alias + `default` 双保险，
    /// 而嵌套的 `[chat_completions]` 表当时**没有** `#[serde(default)]` ⇒
    /// 换上新二进制后启动直接失败（`missing field \`cached_subset_tokens\``），
    /// 客户端当场拿到 502。旧测试只造顶层字段，**恰好绕开了这个形状**。
    #[test]
    fn snapshot_with_a_protocol_table_missing_new_fields_still_loads() {
        let path =
            std::env::temp_dir().join(format!("dshp-stats-table-{}.toml", std::process::id()));
        // 真实线上形状：表在，表里只有"当时存在"的那些字段。
        let text = "version = 1\nresponses = 5\nrequest_body_bytes = 10\n\
                    \n[chat_completions]\nrequests = 3\ninput_tokens = 7\noutput_tokens = 1\n\
                    total_tokens = 8\nusage_reports = 1\n\
                    \n[messages]\nrequests = 2\n";
        std::fs::write(&path, text).unwrap();
        let restored = TrafficStats::load(path.to_str().unwrap())
            .unwrap_or_else(|e| panic!("协议表缺字段的快照必须能载入，却失败：{e}"));
        assert_eq!(restored.responses.load(Ordering::Relaxed), 5);
        assert_eq!(
            restored.chat_completions.requests.load(Ordering::Relaxed),
            3
        );
        assert_eq!(
            restored
                .chat_completions
                .input_tokens
                .load(Ordering::Relaxed),
            7
        );
        assert_eq!(
            restored
                .chat_completions
                .cache_input_tokens
                .load(Ordering::Relaxed),
            0,
            "缺的字段应当取默认 0，而不是报错"
        );
        assert_eq!(restored.messages.requests.load(Ordering::Relaxed), 2);
        std::fs::remove_file(path).unwrap();
    }

    /// 透传那一组：往返要一致，**旧快照里没有 `[passthrough]` 表时也要能载入**。
    #[test]
    fn passthrough_survives_restart_and_a_missing_table_still_loads() {
        let path =
            std::env::temp_dir().join(format!("dshp-stats-pass-{}.toml", std::process::id()));
        let name = path.to_str().unwrap();
        let stats = TrafficStats::load(name).unwrap();
        stats.passthrough.requests.store(2, Ordering::Relaxed);
        stats.passthrough.request_bytes.store(11, Ordering::Relaxed);
        stats
            .passthrough
            .response_bytes
            .store(22, Ordering::Relaxed);
        stats
            .passthrough
            .cache_input_tokens
            .store(33, Ordering::Relaxed);
        stats.passthrough.messages.store(1, Ordering::Relaxed);
        stats.save().unwrap();
        let restored = TrafficStats::load(name).unwrap();
        assert_eq!(restored.passthrough.requests.load(Ordering::Relaxed), 2);
        assert_eq!(
            restored.passthrough.request_bytes.load(Ordering::Relaxed),
            11
        );
        assert_eq!(
            restored.passthrough.response_bytes.load(Ordering::Relaxed),
            22
        );
        assert_eq!(
            restored
                .passthrough
                .cache_input_tokens
                .load(Ordering::Relaxed),
            33
        );
        assert_eq!(restored.passthrough.messages.load(Ordering::Relaxed), 1);
        std::fs::remove_file(&path).unwrap();

        // 旧快照：连 `[passthrough]` 这张表都没有（靠容器级 default 补默认值）
        let old =
            std::env::temp_dir().join(format!("dshp-stats-passold-{}.toml", std::process::id()));
        std::fs::write(&old, "version = 1\nresponses = 1\n").unwrap();
        let ok = TrafficStats::load(old.to_str().unwrap())
            .unwrap_or_else(|e| panic!("没有 passthrough 表的旧快照必须能载入：{e}"));
        assert_eq!(ok.passthrough.requests.load(Ordering::Relaxed), 0);
        std::fs::remove_file(&old).unwrap();
    }

    /// **历史命名写下的快照必须还能载入**，否则换个二进制就起不来。
    ///
    /// 这条不是假想：仓库前后出现过三套命名（`source_bytes`/`wire_bytes`；
    /// `upload_bytes` + `request_transport_bytes`；`download_source_bytes`/`download_wire_bytes`），
    /// 而快照带 `deny_unknown_fields` —— 真实线上就有一份旧命名快照，实测会挡住启动，
    /// 所以三套名字都写进了 `alias`，这里逐套验一遍。
    #[test]
    fn legacy_snapshot_field_names_still_load() {
        let cases = [
            (
                "source_bytes/wire_bytes（HEAD 口径）",
                "version = 1\nresponses = 5\nsource_bytes = 1200\nwire_bytes = 300\ninput_tokens = 1\noutput_tokens = 2\nusage_reports = 1\n",
            ),
            (
                "upload_bytes + request_transport_bytes",
                "version = 1\nresponses = 5\nsource_bytes = 1200\nwire_bytes = 300\nupload_bytes = 4400\nrequest_transport_bytes = 900\n",
            ),
            (
                "download_source_bytes/download_wire_bytes",
                "version = 1\nresponses = 5\ndownload_source_bytes = 1200\ndownload_wire_bytes = 300\nupload_bytes = 4400\n",
            ),
        ];
        for (what, text) in cases {
            let path = std::env::temp_dir().join(format!(
                "dshp-stats-legacy-{}-{}.toml",
                std::process::id(),
                what.len()
            ));
            std::fs::write(&path, text).unwrap();
            let name = path.to_str().unwrap();
            let restored = TrafficStats::load(name)
                .unwrap_or_else(|e| panic!("{what} 的快照应当可读，却失败了：{e}"));
            assert_eq!(
                restored.response_body_bytes.load(Ordering::Relaxed),
                1200,
                "{what}"
            );
            assert_eq!(
                restored.response_transport_bytes.load(Ordering::Relaxed),
                300,
                "{what}"
            );
            assert_eq!(restored.responses.load(Ordering::Relaxed), 5, "{what}");
            std::fs::remove_file(&path).unwrap();
        }
    }
}

impl TrafficStats {
    fn load(path: &str) -> anyhow::Result<Self> {
        use std::sync::atomic::Ordering as O;
        let stats = Self::default();
        if path.is_empty() {
            return Ok(stats);
        }
        let path = std::path::PathBuf::from(path);
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let s: TrafficSnapshot =
                    toml::from_str(&contents).context("统计快照损坏，拒绝覆盖已有数据")?;
                anyhow::ensure!(s.version == 1, "不支持的统计快照版本");
                stats.responses.store(s.responses, O::Relaxed);
                stats
                    .request_body_bytes
                    .store(s.request_body_bytes, O::Relaxed);
                stats
                    .request_transport_bytes
                    .store(s.request_transport_bytes, O::Relaxed);
                stats
                    .response_body_bytes
                    .store(s.response_body_bytes, O::Relaxed);
                stats
                    .response_transport_bytes
                    .store(s.response_transport_bytes, O::Relaxed);
                stats.input_tokens.store(s.input_tokens, O::Relaxed);
                stats.output_tokens.store(s.output_tokens, O::Relaxed);
                stats
                    .cached_subset_tokens
                    .store(s.cached_subset_tokens, O::Relaxed);
                stats
                    .cache_read_tokens
                    .store(s.cache_read_tokens, O::Relaxed);
                stats
                    .cache_creation_tokens
                    .store(s.cache_creation_tokens, O::Relaxed);
                stats
                    .cache_input_tokens
                    .store(s.cache_input_tokens, O::Relaxed);
                stats.cache_reports.store(s.cache_reports, O::Relaxed);
                stats.usage_reports.store(s.usage_reports, O::Relaxed);
                load_protocol(&stats.chat_completions, &s.chat_completions);
                load_protocol(&stats.responses_api, &s.responses_api);
                load_protocol(&stats.messages, &s.messages);
                load_passthrough(&stats.passthrough, &s.passthrough);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("读取统计快照失败"),
        }
        *stats.persistence.lock().unwrap() = Some(path);
        stats.save()?;
        Ok(stats)
    }

    // 在阻塞线程中串行写入临时文件，再原子替换快照，避免半写文件。
    fn save(&self) -> anyhow::Result<()> {
        use std::io::Write;
        use std::sync::atomic::Ordering as O;
        let guard = self.persistence.lock().unwrap();
        let Some(path) = guard.as_ref() else {
            return Ok(());
        };
        let counters = self.counters.lock().unwrap();
        let snapshot = TrafficSnapshot {
            version: 1,
            responses: self.responses.load(O::Relaxed),
            request_body_bytes: self.request_body_bytes.load(O::Relaxed),
            request_transport_bytes: self.request_transport_bytes.load(O::Relaxed),
            response_body_bytes: self.response_body_bytes.load(O::Relaxed),
            response_transport_bytes: self.response_transport_bytes.load(O::Relaxed),
            input_tokens: self.input_tokens.load(O::Relaxed),
            output_tokens: self.output_tokens.load(O::Relaxed),
            cached_subset_tokens: self.cached_subset_tokens.load(O::Relaxed),
            cache_read_tokens: self.cache_read_tokens.load(O::Relaxed),
            cache_creation_tokens: self.cache_creation_tokens.load(O::Relaxed),
            cache_input_tokens: self.cache_input_tokens.load(O::Relaxed),
            cache_reports: self.cache_reports.load(O::Relaxed),
            usage_reports: self.usage_reports.load(O::Relaxed),
            chat_completions: snapshot_protocol(&self.chat_completions),
            responses_api: snapshot_protocol(&self.responses_api),
            messages: snapshot_protocol(&self.messages),
            passthrough: snapshot_passthrough(&self.passthrough),
        };
        drop(counters);
        let tmp = path.with_extension("tmp");
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(toml::to_string(&snapshot)?.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)?;
        #[cfg(unix)]
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        #[cfg(unix)]
        std::fs::File::open(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(std::path::Path::new(".")),
        )?
        .sync_all()?;
        Ok(())
    }
}

fn snapshot_protocol(stats: &ProtocolTraffic) -> ProtocolSnapshot {
    use std::sync::atomic::Ordering::Relaxed;
    ProtocolSnapshot {
        requests: stats.requests.load(Relaxed),
        input_tokens: stats.input_tokens.load(Relaxed),
        output_tokens: stats.output_tokens.load(Relaxed),
        total_tokens: stats.total_tokens.load(Relaxed),
        cached_subset_tokens: stats.cached_subset_tokens.load(Relaxed),
        cache_read_tokens: stats.cache_read_tokens.load(Relaxed),
        cache_creation_tokens: stats.cache_creation_tokens.load(Relaxed),
        cache_input_tokens: stats.cache_input_tokens.load(Relaxed),
        cache_reports: stats.cache_reports.load(Relaxed),
        usage_reports: stats.usage_reports.load(Relaxed),
    }
}

fn load_protocol(stats: &ProtocolTraffic, snapshot: &ProtocolSnapshot) {
    use std::sync::atomic::Ordering::Relaxed;
    stats.requests.store(snapshot.requests, Relaxed);
    stats.input_tokens.store(snapshot.input_tokens, Relaxed);
    stats.output_tokens.store(snapshot.output_tokens, Relaxed);
    stats.total_tokens.store(snapshot.total_tokens, Relaxed);
    stats
        .cached_subset_tokens
        .store(snapshot.cached_subset_tokens, Relaxed);
    stats
        .cache_read_tokens
        .store(snapshot.cache_read_tokens, Relaxed);
    stats
        .cache_creation_tokens
        .store(snapshot.cache_creation_tokens, Relaxed);
    stats
        .cache_input_tokens
        .store(snapshot.cache_input_tokens, Relaxed);
    stats.cache_reports.store(snapshot.cache_reports, Relaxed);
    stats.usage_reports.store(snapshot.usage_reports, Relaxed);
}

fn snapshot_passthrough(p: &PassthroughStats) -> PassthroughSnapshot {
    use std::sync::atomic::Ordering::Relaxed;
    PassthroughSnapshot {
        requests: p.requests.load(Relaxed),
        request_bytes: p.request_bytes.load(Relaxed),
        response_bytes: p.response_bytes.load(Relaxed),
        input_tokens: p.input_tokens.load(Relaxed),
        output_tokens: p.output_tokens.load(Relaxed),
        cached_subset_tokens: p.cached_subset_tokens.load(Relaxed),
        cache_read_tokens: p.cache_read_tokens.load(Relaxed),
        cache_creation_tokens: p.cache_creation_tokens.load(Relaxed),
        cache_input_tokens: p.cache_input_tokens.load(Relaxed),
        cache_reports: p.cache_reports.load(Relaxed),
        usage_reports: p.usage_reports.load(Relaxed),
        chat_completions: p.chat_completions.load(Relaxed),
        responses_api: p.responses_api.load(Relaxed),
        messages: p.messages.load(Relaxed),
    }
}

fn load_passthrough(p: &PassthroughStats, snapshot: &PassthroughSnapshot) {
    use std::sync::atomic::Ordering::Relaxed;
    p.requests.store(snapshot.requests, Relaxed);
    p.request_bytes.store(snapshot.request_bytes, Relaxed);
    p.response_bytes.store(snapshot.response_bytes, Relaxed);
    p.input_tokens.store(snapshot.input_tokens, Relaxed);
    p.output_tokens.store(snapshot.output_tokens, Relaxed);
    p.cached_subset_tokens
        .store(snapshot.cached_subset_tokens, Relaxed);
    p.cache_read_tokens
        .store(snapshot.cache_read_tokens, Relaxed);
    p.cache_creation_tokens
        .store(snapshot.cache_creation_tokens, Relaxed);
    p.cache_input_tokens
        .store(snapshot.cache_input_tokens, Relaxed);
    p.cache_reports.store(snapshot.cache_reports, Relaxed);
    p.usage_reports.store(snapshot.usage_reports, Relaxed);
    p.chat_completions.store(snapshot.chat_completions, Relaxed);
    p.responses_api.store(snapshot.responses_api, Relaxed);
    p.messages.store(snapshot.messages, Relaxed);
}

/// 运行期诊断计数（只加不减的用 `AtomicU64`，在途数用成对的加减）。
#[derive(Debug, Default)]
pub struct Diag {
    /// 建立过的流总数。
    pub streams_opened: std::sync::atomic::AtomicU64,
    /// **当前**在途流数（拿到槽位到任务结束之间）。
    pub streams_inflight: std::sync::atomic::AtomicU64,
    /// 在途流数峰值。
    pub streams_peak: std::sync::atomic::AtomicU64,
    /// **当前**占用的连接额度（缺口 11 下半，第 115 轮）。
    ///
    /// 为什么必须有它：连接上限的"额度是否**随会话释放**"这一侧，
    /// 第 114 轮**判不了** ✗ —— 客户端关闭后服务端任务要读到 EOF 才结束，
    /// 靠固定 sleep 去猜就是一条会偶发的判据 ✗。有了这个计数，测试可以**轮询到它降下来**
    /// ✓（可观测信号 ✓，而不是猜时间 ✓）。
    pub conns_inflight: std::sync::atomic::AtomicU64,
    /// 收到的客户端取消帧数（缺口 8 的直接证据）。
    pub cancel_frames: std::sync::atomic::AtomicU64,
    /// 因客户端取消而提前结束的流数。
    pub cancelled_streams: std::sync::atomic::AtomicU64,
    /// 最近一次连接里被 mux 丢弃的帧数（"路由缺失"的直接证据）。
    pub dropped_frames: std::sync::atomic::AtomicU64,
    /// 最近一次连接里 mux **收到**的帧总数（解密后即计数）。
    pub received_frames: std::sync::atomic::AtomicU64,
}

/// 在途计数守卫：与信号量 permit 同生共死。
///
/// 用 `Drop` 而不是手写减法：这条路径有多个提前返回，手写必然漏。
struct InflightGuard(Arc<Diag>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering as O;
        self.0.streams_inflight.fetch_sub(1, O::AcqRel);
    }
}

/// 连接额度守卫（缺口 11 下半 ✓）：与 accept 处拿到的 permit **同生共死** ✓。
///
/// 形状照抄上面的 `InflightGuard` ✓ —— 同一套机制，不发明第二种 ✓。
/// 它存在的意义是让"额度**随会话释放**"变得**可观测** ✓（否则只能靠时间猜 ✗，
/// 而第 114 轮正因此**放弃了**一条会偶发的判据 ✓）。
struct ConnGuard(Arc<Diag>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering as O;
        self.0.conns_inflight.fetch_sub(1, O::AcqRel);
    }
}

pub type AppShared = Arc<App>;

/// **会话登记守卫**（缺口 #7 排空，第 181 轮）：与 [`run_session`] 同生共死。
///
/// 形状还是照抄上面两个守卫 ✓ —— 排空要的是"当前活着的会话名单"，
/// 而名单**必须在会话结束时自动摘掉**，否则排空会对着早已结束的会话发帧，
/// 日志里还会报出一堆不存在的会话数 ✗（"看起来在工作、其实对象都没有"）。
struct SessionGuard {
    id: u64,
    app: AppShared,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.app.sessions.lock().unwrap().remove(&self.id);
    }
}

/// 对端声明的能力。目前只有一项：是否支持慢路径的流式 zstd 帧。
#[derive(Debug, Default)]
pub struct ConnCaps {
    pub client_stream_zstd: bool,
    /// 客户端支持 `StreamReady` 准入屏障。旧客户端没有该能力时保留旧行为。
    pub client_stream_ready: bool,
    /// **对端会不会续传**（缺口 #2，设计 §11.2）：段清单里声明 `"resume"` 才为真 ✓。
    ///
    /// 为什么必须有这个门控（而不是"一律 hold + 缓冲"）✗→✓：客户端断线后服务端若继续
    /// 把上游消费完，那是**真金白银** ✗ —— 对一个**不会续传**的客户端（例如今天所有已部署的
    /// 版本 ✓）这么做等于白烧 token ✗✗。所以 hold **只在对方声明能力时**启用 ✓，
    /// 老客户端保持"发不出去就结束该流"的既有行为 ✓。
    pub client_resume: bool,
    /// 本条连接的 `req_id` 幂等台账（缺口 14 ✓）。挂在 `ConnCaps` 上是因为它
    /// **每连接一份**、且已经是 `Arc` 共享的 ✓ ⇒ 不需要给任何调用点加参数 ✓。
    pub ledger: ReqLedger,
}

/// 每连接的"已见 `req_id`"台账（**缺口 14** 的最小止血版，第 110 轮）。
///
/// # 为什么必须**按连接**记账
///
/// `ReqOpen.req_id` 的**值就是 `sid as u64`** ⇒ 它**只在单连接内唯一** ✗。
/// 若做成全局表，两个客户端各自的 `sid = 1` 会互相串号 ✗ —— 那会把"防重复计费"
/// 变成"把**别人的响应**回给你" ✓✗，比不做更糟 ✓。所以台账挂在 `ConnCaps` 上（每连接一份 ✓）。
///
/// # 为什么是"拒绝"而不是"返回缓存结果"
///
/// 设计 §13.6 要求"重复 `req_id` 直接返回已缓存结果，**不重新调用上游**" ✓。
/// 但"返回缓存结果"需要把整条响应留存下来重放 ✗，而响应路径是**流式零拷贝**的
/// （上游 `Incoming` 原样回传 ✓）⇒ 第 110 轮只做**安全那一半**：**绝不第二次调用上游** ✓ ——
/// 与设计"POST 上游不可幂等"的红线一致 ✓。代价是重复请求**响亮地失败** ✓，而不是静默重复计费 ✓。
///
/// # 为什么不做"进行中 vs 已完成"的区分
///
/// 两者的**动作相同**（都拒绝 ✓），区分只会多出一份没人用的分支 ✗
/// ⇒ 台账只回答一个问题：**这个 `req_id` 见过没有** ✓。
/// 将来做"重放已缓存结果"时才需要区分状态 ✓（那时存的就变成响应留存 ✓）。
///
/// # 边界
///
/// * 只记「`req_id` → 首次见到时刻」✓，**不记 body** ⇒ 内存与请求体大小无关 ✓；
/// * 超过 `ttl` 的条目在下一次 `admit` 时顺手清掉 ✓（`ttl` 默认 6h，与设计"缓存有效期 6h"一致 ✓）；
/// * 因此**内存上界 = 6 小时内的请求数** ✓（而不是无限增长 ✓）。
#[derive(Debug)]
pub struct ReqLedger {
    seen: Mutex<std::collections::HashMap<u64, std::time::Instant>>,
    ttl: std::time::Duration,
}

impl Default for ReqLedger {
    fn default() -> Self {
        Self::new(std::time::Duration::from_secs(6 * 3600))
    }
}

impl ReqLedger {
    pub fn new(ttl: std::time::Duration) -> Self {
        Self {
            seen: Mutex::new(std::collections::HashMap::new()),
            ttl,
        }
    }

    /// 放行吗？`true` = 第一次见到（已登记 ✓）；`false` = **重复** ⇒ 调用方必须拒绝 ✓。
    ///
    /// 判定与登记在**同一把锁内**完成 ✓ ⇒ 并发的同 `req_id` 只有一个拿到 `true` ✓。
    pub fn admit(&self, req_id: u64) -> bool {
        let mut g = self.seen.lock().expect("台账锁中毒");
        let now = std::time::Instant::now();
        g.retain(|_, at| now.duration_since(*at) < self.ttl); // 顺手清过期 ✓
        g.insert(req_id, now).is_none()
    }

    /// 仅供测试/诊断：当前条目数。
    ///
    /// **必须标成 test-only** ✓：`-D warnings` 下 bin 目标会报 `method len is never used` ✗
    /// —— 第 109 轮实测撞上过 ✓。
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.seen.lock().expect("台账锁中毒").len()
    }
}

/// HTTP 响应体类型，**只给 SSE 隧道与错误页用**。
///
/// 普通转发路径不走这里——那条路把上游的 `Incoming` 原样回传（零拷贝）。
/// 隧道则要自己**产出**一个流式响应体，所以需要一个可装箱的类型。
pub type RespBody = BoxBody<Bytes, std::io::Error>;

/// 启动 WS 入口。
pub async fn run(cfg: Shared) -> anyhow::Result<()> {
    let app = Arc::new(App {
        client: cfg.http_client()?,
        // 许可数一律过 `semaphore_permits` ✓：配置的"无界"是 `usize::MAX`，
        // 直接交给 `Semaphore::new` 会 panic（服务端起不来 ✗）。
        slots: Arc::new(tokio::sync::Semaphore::new(semaphore_permits(
            cfg.max_concurrent_streams,
        ))),
        admission: Arc::new(tokio::sync::Semaphore::new(semaphore_permits(
            cfg.max_concurrent_streams
                .saturating_add(cfg.max_pending_streams),
        ))),
        conns: Arc::new(tokio::sync::Semaphore::new(
            llm_proxy_core::config::MAX_CONNECTIONS,
        )),
        blocks: Mutex::new(BlockStore::new(
            cfg.block_cache_bytes,
            Duration::from_secs(cfg.cache_ttl_secs),
        )),
        compress: Arc::new(
            CompressPool::new(llm_proxy_core::dict::Dicts::bootstrap().patch, 0)
                .context("初始化压缩上下文池失败")?,
        ),
        diag: Arc::new(Diag::default()),
        phases: std::sync::Mutex::new(std::collections::HashMap::new()),
        sessions: std::sync::Mutex::new(std::collections::HashMap::new()),
        next_session: std::sync::atomic::AtomicU64::new(1),
        draining: std::sync::atomic::AtomicBool::new(false),
        rings: std::sync::Mutex::new(std::collections::HashMap::new()),
        traffic: Arc::new(TrafficStats::load(&cfg.stats_file)?),
        cfg: (*cfg).clone(),
    });

    let listener = TcpListener::bind(&app.cfg.listen)
        .await
        .with_context(|| format!("无法监听 {}", app.cfg.listen))?;
    tracing::info!(
        listen = %app.cfg.listen,
        upstream = %app.cfg.upstream_base,
        block_cache_mb = app.cfg.block_cache_bytes / (1 << 20),
        ttl_h = app.cfg.cache_ttl_secs / 3600,
        "llmproxyd 已启动"
    );

    // **计划内停机的优雅排空**（缺口 #7，第 181 轮）：收到 SIGTERM / Ctrl-C 后先排空再退出。
    //
    // 为什么必须有这条：`systemctl restart` / 换二进制 / 改配置都会发 SIGTERM，
    // 而在此之前服务端是**直接消失**的 ⇒ 在途响应被切断 ⇒ SDK 看到传输错误 ✗。
    // 这与 M7 红线是同一件事的另一面：**不许把没发完的响应当成发完了**，
    // 反过来也不该在能等的时候主动制造"没发完"。
    {
        let app = app.clone();
        tokio::spawn(async move {
            wait_for_shutdown_signal().await;
            // `drain` 内部已经按 `drain_timeout` 有界；外面这层是兜底——`send_session`
            // 可能卡在"对端不读"上（写缓冲满），那种情况下宁可退出，也不能挂在停机上。
            let report = match tokio::time::timeout(Duration::from_secs(60), drain(&app)).await {
                Ok(r) => r,
                Err(_) => DrainReport {
                    sessions: app.sessions.lock().unwrap().len(),
                    waited_ms: 60_000,
                    streams_left: app
                        .diag
                        .streams_inflight
                        .load(std::sync::atomic::Ordering::Relaxed),
                },
            };
            exit_after_drain(report);
        });
    }

    // KCP(UDP) 监听是**可选**的：它需要放行 UDP，所以在没配置时完全不起，
    // 否则在只放行 TCP 的环境里会白等一轮握手（§10 的降级链要的是快速失败）。
    if let Some(bind) = app.cfg.kcp_bind.clone() {
        let addr: std::net::SocketAddr = bind
            .parse()
            .with_context(|| format!("无效的 kcp_bind：{bind}"))?;
        let psk = app.cfg.psk.clone().into_bytes();
        // FEC 打开：设计 §10 的 `10:2` 档。
        //
        // 这里曾经是 `None`，因为 `FecEncoder` 攒满一组（10 个）才发校验包，
        // 而 KCP 一次 flush 只产出它当时该发的段——一批 28 个分片被切成
        // "2 个整组 + 8 个永远不齐的尾片"，尾片卡在编码器里出不去，
        // 接收侧那一组永远凑不齐，KCP 于是重组出半截消息（端到端报 `BadMagic`）。
        //
        // 现在编码器**凑不满一组就先不发**，等 KCP 这一拍空转时把尾片按
        // "独立包"放出去，接收侧对独立包直接交付。尾片因此一定落地，
        // 代价只是这几个分片没有校验保护——少省一点，但不会停摆。
        let fec = Some(llm_proxy_transport::fec_adapt::FecSettings::adaptive(
            llm_proxy_transport::fec::FecConfig::R10_2,
        ));
        let mut kcp = llm_proxy_transport::kcp_link::KcpListener::bind(addr, &psk, fec)
            .await
            .with_context(|| format!("无法绑定 KCP 端口 {addr}"))?;
        tracing::info!(%addr, "KCP(UDP) 监听已启动（FEC 10:2）");
        let app = app.clone();
        tokio::spawn(async move {
            while let Some(a) = kcp.accept().await {
                // 与 TCP 共用同一份额度 ✓（两条路径各自一份就又会漂移 ✗）。
                // UDP 上没有"挂住"的概念 ⇒ 拿不到额度就**直接丢弃**这个会话 ✓
                // （与 §13.6"未认证不建状态"同向 ✓）。
                let permit = match Arc::clone(&app.conns).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::warn!(peer = %a.peer, limit = llm_proxy_core::config::MAX_CONNECTIONS,
                            "KCP 连接数超限：丢弃该会话");
                        drop(a);
                        continue;
                    }
                };
                let app = app.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    // 与 TCP 路径同样计数 ✓（两处都要，否则诊断会少报 KCP 那部分 ✗）。
                    app.diag
                        .conns_inflight
                        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    let _conn = ConnGuard(Arc::clone(&app.diag));
                    // **与 WS / SSE 走同一个 `run_session`**：握手、认证、转发、
                    // 背压全部共用。新增一条传输路径不该另起一套安全逻辑——
                    // 两份实现一定会各自漂移。
                    if let Err(e) = run_session(a.mux, a.inbox, a.peer, app).await {
                        tracing::debug!(peer = %a.peer, ?e, "KCP 会话结束");
                    }
                });
            }
        });
    }

    loop {
        let (stream, peer) = listener.accept().await?;
        // 连接数上限（缺口 11 的下半 ✓）：**必须先拿到额度再 spawn** ✓ ——
        // 拿不到就**立刻关掉**这个 socket ✓（客户端拿到 EOF/复位 ✓），
        // 而不是把它留在 backlog 里挂住 ✗（那会变成"看起来连得上、其实永远没人处理" ✗✗）。
        let permit = match Arc::clone(&app.conns).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(%peer, limit = llm_proxy_core::config::MAX_CONNECTIONS,
                    "连接数超限：立刻关闭该连接（不排队、不挂着）");
                drop(stream);
                continue;
            }
        };
        let app = app.clone();
        tokio::spawn(async move {
            // 额度跟**会话生命周期**绑定 ✓：任务结束即释放 ✓（用 `_permit` 持有 ✓）。
            let _permit = permit;
            // 同时让它**可观测** ✓（诊断计数 ✓，形状与流计数一致 ✓）。
            app.diag
                .conns_inflight
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let _conn = ConnGuard(Arc::clone(&app.diag));
            if let Err(e) = dispatch(stream, peer, app).await {
                tracing::debug!(%peer, ?e, "连接结束");
            }
        });
    }
}

/// SSE 隧道路径。客户端用 `POST` 打开一条长连接：请求体承载上行帧，响应是 SSE 下行帧。
const TUNNEL_PATH: &str = "/__dshp/tunnel";

/// 优雅排空端点（`POST`，凭据同统计端点）。见 [`drain`]。
const DRAIN_PATH: &str = "/__dshp/drain";

/// 排空时等待在途流送完的上限（毫秒）。可用 `DSHP_DRAIN_TIMEOUT_MS` 覆盖。
///
/// 取值理由：上游一个流式响应通常几秒到几十秒；给 30s 覆盖绝大多数在途流，
/// 又不会让"计划内重启"卡到运维以为服务端挂了。**到点即退**（不无限等 ✗）。
const DRAIN_TIMEOUT_MS: u64 = 30_000;

fn drain_timeout() -> Duration {
    std::env::var("DSHP_DRAIN_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(Duration::from_millis(DRAIN_TIMEOUT_MS))
}

/// 排空结果：(通知到的会话数, 实际等待毫秒, 退出时仍在途的流数)。
struct DrainReport {
    sessions: usize,
    waited_ms: u128,
    streams_left: u64,
}

/// **优雅排空**：给每个活着的会话发 `GOAWAY`，等在途流归零（有界），然后由调用方退出进程。
///
/// # 为什么值得做（README 缺口表第 7 行）
///
/// `FrameType::GoAway` 定义齐全，但**全仓库从来没人发**——设计 §15 把它记为未实现，
/// 理由是"收益不大"，而那份证据量的是**降级速度**（断链后首个请求 2.3ms、重连 65/326ms、
/// 没有 502 窗口）。它**没有覆盖另一件事**：计划内重启（改配置、换二进制、`systemctl restart`）
/// 会**切断在途响应** ⇒ SDK 看到传输错误、整轮对话白跑、还白付一次上游调用 ✗。
/// 排空把这一条去掉：先告诉会话"别再开新流"，把已经在飞的流送完，再退出。
///
/// 因此本函数只做三件事，语义刻意保持最小：
/// 1. `draining` 置位（幂等：第二次调用直接返回空报告 ✓）⇒ 期间新隧道/新透传请求回 `503`
///    （"明牌失败"优于"接了又被切" ✓ 与 M7 红线同向 ✓）；
/// 2. 逐个会话 `send_session(GoAway)`（失败只记日志：对端可能已经没了 ✓）；
/// 3. 轮询 `streams_inflight` 归零，最多等 [`drain_timeout`]。
async fn drain(app: &AppShared) -> DrainReport {
    use std::sync::atomic::Ordering as O;
    if app.draining.swap(true, O::AcqRel) {
        return DrainReport {
            sessions: 0,
            waited_ms: 0,
            streams_left: app.diag.streams_inflight.load(O::Relaxed),
        };
    }
    let sessions: Vec<Mux> = {
        let map = app.sessions.lock().unwrap();
        map.values().cloned().collect()
    };
    let n_sessions = sessions.len();
    for m in &sessions {
        if let Err(e) = m.send_session(FrameType::GoAway, Vec::new()).await {
            // 对端可能已经走了：这不是错误，只是这条会话不需要再通知。
            tracing::debug!(?e, "GOAWAY 发送失败（会话可能已结束）");
        }
    }
    tracing::warn!(
        sessions = n_sessions,
        in_flight = app.diag.streams_inflight.load(O::Relaxed),
        "排空开始：已向全部会话发送 GOAWAY，等待在途流结束"
    );
    let t0 = std::time::Instant::now();
    let timeout = drain_timeout();
    loop {
        let inflight = app.diag.streams_inflight.load(O::Relaxed);
        if inflight == 0 {
            break;
        }
        if t0.elapsed() >= timeout {
            tracing::warn!(
                in_flight = inflight,
                timeout_ms = timeout.as_millis() as u64,
                "排空超时：仍有在途流，**如实记录并退出**（不无限等）"
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    DrainReport {
        sessions: n_sessions,
        waited_ms: t0.elapsed().as_millis(),
        streams_left: app.diag.streams_inflight.load(O::Relaxed),
    }
}

/// 等停机信号：Unix 上 `SIGTERM` 或 Ctrl-C，其它平台只有 Ctrl-C。
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = term.recv() => tracing::warn!("收到 SIGTERM"),
                    _ = tokio::signal::ctrl_c() => tracing::warn!("收到 Ctrl-C"),
                }
            }
            Err(e) => {
                tracing::error!(?e, "无法监听 SIGTERM，退化为只监听 Ctrl-C");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// 排空完成后的收尾：给响应留出写出的时间，然后退出进程。
///
/// 为什么要留时间：`POST /__dshp/drain` 的调用方应当拿到 `202`，而不是"连接被断"。
/// 两者对运维的差别很大——后者看起来像服务端崩了 ✓。
fn exit_after_drain(report: DrainReport) {
    tracing::warn!(
        sessions = report.sessions,
        waited_ms = report.waited_ms,
        streams_left = report.streams_left,
        "排空完成，退出进程"
    );
    std::process::exit(0);
}

/// 排空期间的"明牌拒绝"：503 + 一句人看得懂的话。
fn draining_response() -> Response<RespBody> {
    status_body(
        http::StatusCode::SERVICE_UNAVAILABLE,
        "服务端正在排空重启（已收到停机信号）：不再接受新请求，请稍后重连。\n\
         已经在途的响应会被送完，不会被切断。\n"
            .to_string(),
    )
}

/// 排空期间给 WS 入口的 503（这条路径还没进 hyper，只能自己写 HTTP）。
async fn write_503<S>(stream: &mut S) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let body = "服务端正在排空重启（已收到停机信号）：不再接受新连接，请稍后重连。\n";
    let resp = format!(
        "HTTP/1.1 503 Service Unavailable\r\n\
         content-type: text/plain; charset=utf-8\r\n\
         content-length: {}\r\n\
         connection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// 只读状态端点（诊断 + 运维指标）。见 [`Diag`]。
const STATUS_PATH: &str = "/__dshp/status";
const STATS_PATH: &str = "/__dshp/api/stats";
const UI_PATH: &str = "/__dshp/ui";

/// 按**窥探到的请求行**分流：认得出 HTTP 方法词就走 HTTP 路由，否则走 WS。
///
/// # 为什么不能只看首字节
///
/// 最早只认首字节 `P`（`POST`）+ 三个白名单 `GET`。后果是**任何别的 `GET`/`HEAD`/
/// `DELETE`/`OPTIONS` 到未知路径都会落到 WS 分支** ⇒ 握手失败、连接被直接关掉，
/// 调用方拿到的是 "Empty reply from server"（连状态码都没有）。实测踩到过：SDK 把
/// `base_url` 指到服务端时，`GET /v1/models` 这类探测请求正好是这个形状。现在认全部
/// 方法词，它们会进 HTTP 路由，拿到一个**可读的**响应（透传，或明确的 403）。
///
/// # 唯一的例外：WS 握手
///
/// DSHP 的 WS 通道永远是 `GET /__dshp/tunnel`，把它交给 hyper 会把握手吃掉 ⇒ 这一条
/// 仍然留给 WS。窥探窗口可能比请求行短（分片到达）：**只要还不能排除**它是这条路径
/// 就按 WS 处理（保守选择，与改前一致，不会把 WS 弄坏）。
///
/// 非 HTTP 通道不受影响：DSHP 原始帧首字节是 magic `D`（`llm-proxy-core/src/frame.rs`），
/// 不是方法词。
///
/// 用 `BufReader::fill_buf` 窥探而不消费：判完把同一个 reader 交给下游，首字节不会丢。
fn looks_like_http(peek: &[u8]) -> bool {
    // ① WS 握手：头里带 `Upgrade: websocket` ⇒ 必须留给 WS 通道。
    //
    // **这条是本轮踩出来的**：DSHP 的 WS 通道连的是**服务端地址的根路径**
    // （`connect(&cfg.server)`：`ws://host:port` ⇒ 请求行是 `GET / HTTP/1.1`），
    // 它和"普通 GET"在头几个字节上**完全一样**。上一版按"路径白名单"分流，
    // 于是把这个握手送进了 HTTP 路由 ⇒ 客户端拿不到 101、当场降级成 SSE
    // （CI 红在 `abandon.rs` 的 `mode == "ws"`，客户端状态里 `"mode":"sse"`）。
    if has_websocket_upgrade(peek) {
        return false;
    }
    const METHODS: [&[u8]; 7] = [
        b"GET ",
        b"HEAD ",
        b"POST ",
        b"PUT ",
        b"PATCH ",
        b"DELETE ",
        b"OPTIONS ",
    ];
    // ② 不是 GET/HEAD 的方法**不可能**是 WS 握手（握手永远是 GET）⇒ 直接算 HTTP，
    //    不要求把头读全（头部很大时第一段可能看不到结束空行）。
    let get_like = peek.starts_with(b"GET ") || peek.starts_with(b"HEAD ");
    if !get_like && METHODS.iter().any(|m| peek.starts_with(m)) {
        return true;
    }
    // ③ GET/HEAD：**头读全了**（见到结束空行）才算普通 HTTP；还没读全 ⇒ 保守按 WS 处理。
    //    宁可让普通 GET 退化成改前的行为，也不能把客户端的**主**通道弄坏。
    if !peek.windows(4).any(|w| w == b"\r\n\r\n") {
        return false;
    }
    METHODS.iter().any(|m| peek.starts_with(m))
}

/// 头里有没有 `Upgrade: websocket`（大小写不敏感）。真实握手的这两段总在同一批字节里。
fn has_websocket_upgrade(peek: &[u8]) -> bool {
    let lower = peek.to_ascii_lowercase();
    lower.windows(8).any(|w| w == b"upgrade:") && lower.windows(9).any(|w| w == b"websocket")
}

/// 分流判据的用例。**这条判据踩过坑**：只看首字节 `P` 时，`GET /v1/models`
/// 会落到 WS 分支 ⇒ 握手失败、连接被直接关掉（调用方拿到 "Empty reply from server"，
/// 连状态码都没有）。所以这里把"普通方法都要进 HTTP"和"WS 握手必须留在 WS"两半都钉住。
#[cfg(test)]
mod dispatch_tests {
    use super::looks_like_http;

    #[test]
    fn plain_http_methods_go_to_the_http_router() {
        for head in [
            &b"GET /v1/models HTTP/1.1\r\nHost: x\r\n\r\n"[..],
            b"HEAD /v1/models HTTP/1.1\r\n\r\n",
            b"POST /v1/messages HTTP/1.1\r\n\r\n",
            b"PUT /x HTTP/1.1\r\n\r\n",
            b"PATCH /x HTTP/1.1\r\n\r\n",
            b"DELETE /x HTTP/1.1\r\n\r\n",
            b"OPTIONS /x HTTP/1.1\r\n\r\n",
            // 头部很大、第一段还没看到结束空行：非 GET/HEAD **也要**认成 HTTP
            b"POST /v1/messages HTTP/1.1\r\ncontent-type: application/json\r\nx-pad: ",
        ] {
            assert!(
                looks_like_http(head),
                "{} 应当走 HTTP 路由",
                String::from_utf8_lossy(&head[..head.len().min(7)])
            );
        }
    }

    #[test]
    fn the_ws_handshake_stays_on_the_ws_path() {
        // DSHP 的 WS 通道永远是这条路径 —— 交给 hyper 会把握手吃掉
        assert!(!looks_like_http(
            b"GET /__dshp/tunnel HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"
        ));
        // 窥探窗口比请求行短（分片到达）：**只要还不能排除**是隧道就按 WS 处理（保守）
        assert!(!looks_like_http(b"GET "));
        assert!(!looks_like_http(b"GET /__dsh"));
        // 非 HTTP 通道：原始帧首字节是 magic `D`
        assert!(!looks_like_http(b"DP\x01\x00"));
        assert!(!looks_like_http(b""));
    }

    /// **真实 WS 握手**（根路径 `GET / HTTP/1.1` + `Upgrade: websocket`）必须留在 WS。
    ///
    /// 这一版之前就是在这里错的：按"路径白名单"分流 ⇒ 把根路径的握手送进 HTTP 路由 ⇒
    /// 客户端拿不到 101、**当场降级成 SSE**（CI 红在 `abandon.rs` 的 `mode == "ws"`，
    /// 客户端状态里 `"mode":"sse"`）。独立成一条，防止再被改回去。
    #[test]
    fn the_real_ws_handshake_at_the_root_path_stays_on_ws() {
        assert!(
            !looks_like_http(
                b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
            ),
            "根路径 + Upgrade 的握手不许被当成普通 HTTP"
        );
        assert!(
            !looks_like_http(b"GET / HTTP/1.1\r\nhost: x\r\nupgrade: WebSocket\r\n\r\n"),
            "Upgrade 判定要大小写不敏感"
        );
        assert!(
            !looks_like_http(b"GET /v1/models HTTP/1.1\r\nHost: x"),
            "GET 但头没读全 ⇒ 保守走 WS（主通道优先）"
        );
    }
}

async fn dispatch<S>(stream: S, peer: std::net::SocketAddr, app: AppShared) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut stream = tokio::io::BufReader::new(stream);
    let http_request = {
        use tokio::io::AsyncBufReadExt;
        let buf = stream.fill_buf().await.context("读取首字节失败")?;
        looks_like_http(buf)
    };

    match http_request {
        true => {
            // HTTP 服务：管理端点在 `route()` 里各走各的，隧道端点走 SSE，**其余路径直连透传**
            // （未显式开启时给一个说明性的 403，而不是 404）。
            let app2 = app.clone();
            let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                let app = app2.clone();
                async move { Ok::<_, std::convert::Infallible>(route(req, peer, app).await) }
            });
            hyper::server::conn::http1::Builder::new()
                .keep_alive(true)
                .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                .await
                .context("HTTP 连接结束")
        }
        // WS 路径：tungstenite 自己在同一条流上完成握手（与 M0 起的行为完全一致）。
        // 走 `BufReader` 不影响它——窥探过的那一个字节仍在缓冲里，读取时会照常拿到。
        _ => handle_conn(stream, peer, app).await,
    }
}

/// HTTP 路由。SSE 隧道 + **只读状态**。
async fn route(
    req: Request<Incoming>,
    peer: std::net::SocketAddr,
    app: AppShared,
) -> Response<RespBody> {
    // 三处端点**不是同一条鉴权规则**，别合并成"一刀切"：
    //
    // * 统计页面 `/__dshp/ui` 与统计 API `/__dshp/api/stats`：**未配置 token 就是关闭**（401）
    //   —— README 里"WebUI 默认关闭"说的就是这两个；
    // * 诊断端点 `/__dshp/status`：夹具会丢弃子进程日志，**这是观察服务端内部的唯一通道**
    //   （缺口 11 的在途流/连接额度判据全靠它）⇒ 未配置 token 时**必须开放**；
    //   一旦配了 token（线上就是这样）就要凭据。
    //
    // 这条曾被写成一刀切：`authorized()` 对空 token 恒返回 false ⇒ 没配 token 时诊断端点
    // 也 401 ⇒ `multi_client.rs` 的 3 条判据一直是红的。**负向对照做过**：把工作区切回 HEAD
    // 实跑同一套件，同样 3 条失败、`slots_limit` 同样解析成 null ⇒ 是 HEAD 里就有的旧缺陷，
    // 不是本轮统计改动引入的。夹具没有 token，所以修法只能在这里。
    let path = req.uri().path();
    let stats_ui_closed = path == STATS_PATH || path == UI_PATH;
    let diag_gated = path == STATUS_PATH && !app.cfg.webui_token.is_empty();
    // 排空端点**与统计端点同一条规矩**：未配置 token 就是关闭（401）。
    //
    // 为什么不能像诊断端点那样"没配 token 就开放"：那意味着任何能访问这个端口的人
    // 都能让服务端退出 ✗✗。诊断端点是**只读**的，开放它只是泄露内部计数；
    // 排空是**写操作**（终止服务），必须凭据。
    // 代价是 e2e 夹具必须显式配 token 才能测它 —— 那是配置，不是"生产代码里的注入开关" ✓。
    let drain_closed = path == DRAIN_PATH;
    if (stats_ui_closed || diag_gated || drain_closed) && !authorized(&req, &app.cfg.webui_token) {
        return unauthorized();
    }
    if req.uri().path() == STATUS_PATH {
        use std::sync::atomic::Ordering as O;
        let d = &app.diag;
        // ⚠️ **必须先在独立语句里算完再传进 `format!`** ✗→✓（第 182 轮实测踩到的自死锁 ✗✗）：
        // `format!` 的**实参临时值活到整条语句结束**，所以
        //     format!("…{}…{}", map.lock().unwrap().len(), map.lock().unwrap()…)
        // 会在同一条语句里对**同一个 `std::sync::Mutex` 锁两次** ⇒ 第二次永远等不到 ⇒
        // `/__dshp/status` 直接挂死（夹具全都靠它观察服务端 ⇒ 整套 e2e 超时红 ✗✗）。
        // `std::sync::Mutex` **不可重入**，而 tokio 里这类"顺手写在一个表达式里"极易发生 ✓。
        let (rings_count, rings_bytes) = {
            let rings = app.rings.lock().unwrap();
            (
                rings.len(),
                rings.values().map(|s| s.ring_stats().0).sum::<usize>(),
            )
        };
        let phases = app
            .phases
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(",");
        let slots_limit = if app.cfg.max_concurrent_streams == usize::MAX {
            "null".to_string()
        } else {
            app.cfg.max_concurrent_streams.to_string()
        };
        let json = format!(
            "{{\"slots_limit\":{},\"slots_unbounded\":{},\"streams_opened\":{},\"streams_inflight\":{},\
             \"streams_peak\":{},\"cancel_frames\":{},\"cancelled_streams\":{},\
             \"dropped_frames\":{},\"received_frames\":{},\
             \"conns_limit\":{},\"conns_inflight\":{},\"draining\":{},\
             \"resp_rings_count\":{},\"resp_rings_bytes\":{},\"phases\":\"{}\"}}",
            slots_limit,
            app.cfg.max_concurrent_streams == usize::MAX,
            d.streams_opened.load(O::Relaxed),
            d.streams_inflight.load(O::Relaxed),
            d.streams_peak.load(O::Relaxed),
            d.cancel_frames.load(O::Relaxed),
            d.cancelled_streams.load(O::Relaxed),
            d.dropped_frames.load(O::Relaxed),
            d.received_frames.load(O::Relaxed),
            // 连接额度（缺口 11 下半 ✓）：测试靠它判"额度随会话释放" ✓（不靠猜时间 ✓）。
            llm_proxy_core::config::MAX_CONNECTIONS,
            d.conns_inflight.load(O::Relaxed),
            // 排空状态（缺口 #7 ✓）：测试靠它判定"排空已经开始"，不靠猜时间 ✓。
            app.draining.load(O::Relaxed),
            // **响应环形缓冲**（缺口 #2）：条数与字节数 —— 让"1 MiB 最坏占用"这个代价
            // **可观测** ✓（否则它只是注释里的一句话 ✗）。环是有界的（256 KB × 在途流 ✓）。
            rings_count,
            rings_bytes,
            // 各流当前走到哪一步。**缺口 8 排查的主要仪器**：它一眼指出"任务卡在
            // 哪一段"，比反复猜假设省事得多（本轮就是靠它把 4 个任务定位到
            // `send_buffered` 的 select 里的）。它同时是运维想看的"每条流在做什么"。
            phases,
        );
        return Response::builder()
            .header("content-type", "application/json")
            .body(full_body(json))
            .unwrap_or_else(|_| Response::new(full_body("{}".to_string())));
    }
    if req.uri().path() == STATS_PATH {
        return Response::builder()
            .header("content-type", "application/json")
            .body(full_body(stats_json(&app.traffic)))
            .unwrap_or_else(|_| Response::new(full_body("{}".to_string())));
    }
    if req.uri().path() == UI_PATH {
        return Response::builder()
            .header("content-type", "text/html; charset=utf-8")
            .body(full_body(WEBUI_HTML.to_string()))
            .unwrap_or_else(|_| Response::new(full_body("webui error".to_string())));
    }
    if path == DRAIN_PATH {
        // 只接受 `POST`：排空是**动作**，不该被某个爬虫的 GET 触发（那会变成"访问一次就停服" ✗）。
        if req.method() != http::Method::POST {
            let mut r = status_body(
                http::StatusCode::METHOD_NOT_ALLOWED,
                "排空端点只接受 POST（它会终止服务端，不做幂等的 GET）。\n",
            );
            r.headers_mut()
                .insert("allow", http::HeaderValue::from_static("POST"));
            return r;
        }
        // **先回应，再排空，最后退出**（见 `exit_after_drain` 里为什么留 120ms）。
        let app2 = app.clone();
        tokio::spawn(async move {
            let report = drain(&app2).await;
            tracing::warn!(
                sessions = report.sessions,
                waited_ms = report.waited_ms,
                streams_left = report.streams_left,
                "排空完成（来自 /__dshp/drain）"
            );
            tokio::time::sleep(Duration::from_millis(120)).await;
            exit_after_drain(report);
        });
        return Response::builder()
            .status(http::StatusCode::ACCEPTED)
            .header("content-type", "application/json")
            .body(full_body(
                "{\"draining\":true,\"note\":\"已向全部会话发送 GOAWAY，等在途流结束后退出进程\"}"
                    .to_string(),
            ))
            .unwrap_or_else(|_| Response::new(full_body("{}".to_string())));
    }
    // 排空期间：**不再接新活**，但管理端点照旧（运维还要看状态）。
    // 为什么明牌 503 而不是继续接：接了也会在退出时被切断 ⇒ 那是"看起来成功、其实没发完" ✗。
    if app.draining.load(std::sync::atomic::Ordering::Relaxed) {
        return draining_response();
    }
    if req.uri().path() == TUNNEL_PATH {
        return match tunnel(req, peer, app).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(%peer, ?e, "SSE 隧道建立失败");
                let mut r = Response::new(full_body(format!("隧道建立失败：{e:#}")));
                *r.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
                r
            }
        };
    }
    if req.uri().path().starts_with("/__dshp/") {
        // `/__dshp/` 是**代理自己的命名空间**：未知端点就是 404，不要漏给上游。
        return status_body(http::StatusCode::NOT_FOUND, "not found".to_string());
    }
    // 其余都是非隧道、非管理端点的普通 HTTP 请求 ⇒ 直连透传（见 `passthrough`）。
    passthrough(req, peer, app).await
}

/// 带状态码的一次性文本响应（提示/错误信息一律用文本，让人直接看得懂）。
fn status_body(status: http::StatusCode, msg: impl Into<String>) -> Response<RespBody> {
    let mut r = Response::new(full_body(msg.into()));
    *r.status_mut() = status;
    r
}

/// 透传请求体的上限：超过直接 413，免得畸形请求把服务端内存吃光。
///
/// 32 MiB 是"够用但可控"的位置：真实 LLM 请求体（长上下文 + base64 图片）一般远小于它。
const MAX_PASSTHROUGH_REQUEST: usize = 32 << 20;

/// 转发时**不能原样带过去**的逐跳头（连接由每一跳自己管）。
///
/// `host` 也不带：要让上游按自己的 authority 收请求；`content-length` 也不带：
/// 由 hyper 依据我们声明的精确长度重新生成，避免"转发了旧长度、却发了新字节"的不一致。
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

/// 非隧道的普通 HTTP 请求：**原样透传**给上游，响应（含流式）原样回给调用方。
///
/// 与隧道路径共用同一条上游规则（[`Config::upstream_url`]，只做前缀拼接、不改写路径），
/// 但**不参与**隧道的四组字节统计 —— 那四组要求"前/后"两端都有意义，而透传根本没有
/// 编码/复用这一步（前=后）⇒ 单独记到 `passthrough` 那一组，**免得把隧道的节省率摊薄**。
///
/// 这是**显式授权**的能力（`allow_passthrough`，默认关闭）：打开之后服务端同时也是对
/// 上游的普通反代，谁能访问这个端口谁就能用上游 —— **凭据仍然是上游自己的 key**，
/// 代理不替你鉴权。没打开时给的是说明性的 403，而不是含糊的 404。
async fn passthrough(
    req: Request<Incoming>,
    peer: std::net::SocketAddr,
    app: AppShared,
) -> Response<RespBody> {
    if !app.cfg.allow_passthrough {
        tracing::warn!(%peer, path = %req.uri().path(), "非隧道的普通请求：未开启直连透传");
        return status_body(
            http::StatusCode::FORBIDDEN,
            "本端口只服务 DSHP 隧道（/__dshp/tunnel）。\n\
             · 正常用法：把 SDK 的 base_url 指向客户端（如 http://<客户端地址>:8080），由客户端做增量复用；\n\
             · 链路不可用时的兜底：给客户端配 --upstream-fallback；\n\
             · 确实要让服务端本身也做普通反代：用 DSHP_ALLOW_PASSTHROUGH=1 显式打开。\n",
        );
    }
    use futures_util::StreamExt;

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let method = req.method().clone();
    let headers = req.headers().clone();

    // 边收边卡上限：`BodyExt::collect()` 会先把内存吃满再判大小 ✗
    let mut payload = Vec::new();
    let mut incoming = req.into_body().into_data_stream();
    while let Some(chunk) = incoming.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => {
                return status_body(
                    http::StatusCode::BAD_REQUEST,
                    format!("读取请求体失败：{e}\n"),
                )
            }
        };
        if payload.len() + chunk.len() > MAX_PASSTHROUGH_REQUEST {
            return status_body(
                http::StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "请求体超过透传上限 {} 字节；这条通路不做分块转发，请改走客户端隧道。\n",
                    MAX_PASSTHROUGH_REQUEST
                ),
            );
        }
        payload.extend_from_slice(&chunk);
    }
    let request_bytes = payload.len() as u64;

    let url = app.cfg.upstream_url(&path_and_query);
    let mut builder = Request::builder().method(method.clone()).uri(&url);
    for (name, value) in headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        builder = builder.header(name, value);
    }
    // 请求体走与隧道同一条桥（`ChannelBody`）：一次性投喂 + 声明精确长度 ⇒ 上游看到定长体。
    let (body_tx, up_body) = ChannelBody::channel();
    let up_req = match builder.body(up_body.with_exact_size(request_bytes)) {
        Ok(r) => r,
        Err(e) => {
            return status_body(
                http::StatusCode::BAD_REQUEST,
                format!("构造上游请求失败：{e}\n"),
            )
        }
    };
    if !payload.is_empty() {
        // 容量 8，一次投喂必定放得下；投完立刻 drop 发送端 ⇒ 上游读到完整定长体。
        if body_tx.send(Ok(Bytes::from(payload))).await.is_err() {
            return status_body(
                http::StatusCode::BAD_GATEWAY,
                "上游连接在发送请求体前就断开了\n".to_string(),
            );
        }
    }
    drop(body_tx);

    let resp = match app.client.request(up_req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(%peer, %url, ?e, "透传：上游请求失败");
            return status_body(
                http::StatusCode::BAD_GATEWAY,
                format!("上游请求失败：{e}\n"),
            );
        }
    };
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let mut builder = Response::builder().status(status);
    for (name, value) in resp_headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        builder = builder.header(name, value);
    }
    // **边转发边记账**：字节在流里数，usage/cache 在流里扫，流结束那一刻落账。
    let acc = PassthroughCount {
        app: Arc::clone(&app),
        method: method.as_str().to_string(),
        path: path_and_query,
        status: status.as_u16(),
        request_bytes,
        response_bytes: 0,
        scanner: UsageScanner::default(),
        finished: false,
    };
    let counted = count_passthrough(resp.into_body().into_data_stream(), acc);
    let stream_body =
        http_body_util::StreamBody::new(counted.map(|r| r.map(http_body::Frame::<Bytes>::data)));
    match builder.body(BodyExt::boxed(stream_body)) {
        Ok(r) => r,
        Err(e) => status_body(
            http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("构造响应失败：{e}\n"),
        ),
    }
}

/// 透传的记账状态。**必须等流真正结束再落账**：响应体是流式的，
/// 中途落账会把字节数记少（而这正是这条通路唯一的账）。
struct PassthroughCount {
    app: AppShared,
    method: String,
    path: String,
    status: u16,
    request_bytes: u64,
    response_bytes: u64,
    scanner: UsageScanner,
    finished: bool,
}

impl PassthroughCount {
    /// 落账：一条透传请求对应的所有计数一次加齐（与隧道那份**分开**），
    /// 并按协议只记请求数；同时把这次透传的摘要写进日志（"额外记录信息"）。
    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        use std::sync::atomic::Ordering as O;
        let t = &self.app.traffic;
        let total_tokens = if self.scanner.total_tokens > 0 {
            self.scanner.total_tokens
        } else {
            self.scanner
                .input_tokens
                .saturating_add(self.scanner.output_tokens)
        };
        {
            let _counters = t.counters.lock().unwrap();
            t.passthrough.requests.fetch_add(1, O::Relaxed);
            t.passthrough
                .request_bytes
                .fetch_add(self.request_bytes, O::Relaxed);
            t.passthrough
                .response_bytes
                .fetch_add(self.response_bytes, O::Relaxed);
            passthrough_protocol(&t.passthrough, &self.path).fetch_add(1, O::Relaxed);
            t.passthrough
                .input_tokens
                .fetch_add(self.scanner.input_tokens, O::Relaxed);
            t.passthrough
                .output_tokens
                .fetch_add(self.scanner.output_tokens, O::Relaxed);
            t.passthrough
                .cached_subset_tokens
                .fetch_add(self.scanner.cached_subset, O::Relaxed);
            t.passthrough
                .cache_read_tokens
                .fetch_add(self.scanner.cache_read, O::Relaxed);
            t.passthrough
                .cache_creation_tokens
                .fetch_add(self.scanner.cache_creation, O::Relaxed);
            if self.scanner.input_tokens > 0 || self.scanner.output_tokens > 0 {
                t.passthrough.usage_reports.fetch_add(1, O::Relaxed);
            }
            if self.scanner.saw_cache {
                let denom = self
                    .scanner
                    .input_tokens
                    .saturating_add(self.scanner.cache_read)
                    .saturating_add(self.scanner.cache_creation);
                t.passthrough
                    .cache_input_tokens
                    .fetch_add(denom, O::Relaxed);
                t.passthrough.cache_reports.fetch_add(1, O::Relaxed);
            }
        }
        tracing::info!(
            method = %self.method,
            path = %self.path,
            status = self.status,
            request_bytes = self.request_bytes,
            response_bytes = self.response_bytes,
            input_tokens = self.scanner.input_tokens,
            output_tokens = self.scanner.output_tokens,
            cached_input_tokens = self.scanner.cached_subset + self.scanner.cache_read,
            total_tokens,
            "直连透传完成（未走隧道，故不计入隧道四组）"
        );
        let traffic = Arc::clone(&self.app.traffic);
        tokio::task::spawn_blocking(move || {
            if let Err(error) = traffic.save() {
                tracing::error!(?error, "统计持久化失败，内存计数保留");
            }
        });
    }
}

/// 把上游响应流桥成"带记账"的流：逐块计数 + 喂 usage 扫描器，**流结束（或出错）时落账**。
fn count_passthrough<S>(
    stream: S,
    acc: PassthroughCount,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>>
where
    S: futures_util::Stream<Item = Result<Bytes, hyper::Error>>,
{
    use futures_util::StreamExt;
    let init = Some((Box::pin(stream), acc));
    futures_util::stream::unfold(init, |state| async move {
        let (mut stream, mut acc) = state?;
        match stream.next().await {
            Some(Ok(data)) => {
                acc.response_bytes = acc.response_bytes.saturating_add(data.len() as u64);
                acc.scanner.feed(&data);
                Some((Ok::<Bytes, std::io::Error>(data), Some((stream, acc))))
            }
            Some(Err(e)) => {
                acc.finish();
                let err = std::io::Error::other(e.to_string());
                Some((Err(err), None))
            }
            None => {
                acc.finish();
                None
            }
        }
    })
}

fn unauthorized() -> Response<RespBody> {
    Response::builder()
        .status(http::StatusCode::UNAUTHORIZED)
        .header("www-authenticate", "Basic realm=\"dshp\"")
        .body(full_body("需要 WebUI 鉴权".to_string()))
        .unwrap_or_else(|_| Response::new(full_body("unauthorized".to_string())))
}

/// 组装 `/__dshp/api/stats` 的响应。
///
/// **四组字节一律给整数原值**：单位换算只发生在 WebUI 的显示层，接口不掺显示口径
/// （这样脚本/对账拿到的是可比对的原始数字，换行改版也不会把数字改掉）。
/// 两个节省比例统一用 `1 - 后/前`，**允许为负**——上行的小请求加上帧头后可能比原始更大。
fn stats_json(t: &TrafficStats) -> String {
    use std::sync::atomic::Ordering as O;
    let up_body = t.request_body_bytes.load(O::Relaxed);
    let up_wire = t.request_transport_bytes.load(O::Relaxed);
    let down_body = t.response_body_bytes.load(O::Relaxed);
    let down_wire = t.response_transport_bytes.load(O::Relaxed);
    let input = t.input_tokens.load(O::Relaxed);
    let output = t.output_tokens.load(O::Relaxed);
    // 命中率的分子/分母**只来自报了 cache 字段的响应**（不报的一律不参与）。
    let cache_hit_tokens = t
        .cached_subset_tokens
        .load(O::Relaxed)
        .saturating_add(t.cache_read_tokens.load(O::Relaxed));
    let cache_denom = t.cache_input_tokens.load(O::Relaxed);
    serde_json::json!({
        "responses": t.responses.load(O::Relaxed),
        "request_body_bytes": up_body,
        "request_transport_bytes": up_wire,
        "saved_request_ratio": ratio6(up_body, up_wire),
        "response_body_bytes": down_body,
        "response_transport_bytes": down_wire,
        "saved_response_ratio": ratio6(down_body, down_wire),
        "input_tokens": input,
        "output_tokens": output,
        "total_tokens": input.saturating_add(output),
        "cached_input_tokens": cache_hit_tokens,
        "cache_input_tokens": cache_denom,
        "cache_hit_ratio": cache_hit_ratio(cache_hit_tokens, cache_denom),
        "cache_reports": t.cache_reports.load(O::Relaxed),
        "usage_reports": t.usage_reports.load(O::Relaxed),
        "protocols": {
            "chat_completions": protocol_json(&t.chat_completions),
            "responses": protocol_json(&t.responses_api),
            "messages": protocol_json(&t.messages),
        },
        "passthrough": passthrough_json(&t.passthrough),
    })
    .to_string()
}

/// 「后/前」的节省比例；**允许为负**（负值=膨胀）。内容为 0 时给 0，避免除零。
fn ratio6(body: u64, wire: u64) -> f64 {
    if body == 0 {
        return 0.0;
    }
    let ratio = (1.0 - wire as f64 / body as f64) * 1_000_000.0;
    ratio.round() / 1_000_000.0
}

/// 输入缓存命中率 = **命中 / 参与统计的输入总量**，两端都只来自"报了 cache 字段"的响应。
///
/// 为什么两端的口径要这么定（三个原始分量在这里合成）：
///
/// * OpenAI：`prompt_tokens_details.cached_tokens` 是 `prompt_tokens` 的**子集**
///   （此时 `cache_read`/`cache_creation` 为 0）；
/// * Anthropic：`cache_read_input_tokens` 与 `cache_creation_input_tokens` **不在**
///   `input_tokens` 里 ⇒ 分母必须把它们加回去。
///
/// 于是：**命中 = `cached_subset + cache_read`**（分子的两项都由 `stats_json` 从原始分量加出来），
/// **分母 = `cache_input_tokens`** —— 它在累加时就**只统计报了 cache 的响应**，
/// 所以不报 cache 的上游不会把命中率拉低（用户点名要求的分开）。
/// 分母为 0（这个窗口里没有任何响应报 cache）时给 0，**不编造**。
fn cache_hit_ratio(hit: u64, denom: u64) -> f64 {
    if denom == 0 {
        return 0.0;
    }
    let ratio = (hit as f64 / denom as f64) * 1_000_000.0;
    ratio.round() / 1_000_000.0
}

fn protocol_json(stats: &ProtocolTraffic) -> serde_json::Value {
    use std::sync::atomic::Ordering::Relaxed;
    let input = stats.input_tokens.load(Relaxed);
    // 与全局同一口径：分子/分母只来自报了 cache 的响应。
    let cache_hit_tokens = stats
        .cached_subset_tokens
        .load(Relaxed)
        .saturating_add(stats.cache_read_tokens.load(Relaxed));
    let cache_denom = stats.cache_input_tokens.load(Relaxed);
    serde_json::json!({
        "requests": stats.requests.load(Relaxed),
        "input_tokens": input,
        "output_tokens": stats.output_tokens.load(Relaxed),
        "total_tokens": stats.total_tokens.load(Relaxed),
        "cached_input_tokens": cache_hit_tokens,
        "cache_input_tokens": cache_denom,
        "cache_hit_ratio": cache_hit_ratio(cache_hit_tokens, cache_denom),
        "cache_reports": stats.cache_reports.load(Relaxed),
        "usage_reports": stats.usage_reports.load(Relaxed),
    })
}

/// 透传那一组的 JSON。**与隧道口径完全分开**：页面单独一块展示，
/// 对账时也不会把"没走隧道因此没省下来"的流量混进隧道节省率。
fn passthrough_json(p: &PassthroughStats) -> serde_json::Value {
    use std::sync::atomic::Ordering::Relaxed;
    let input = p.input_tokens.load(Relaxed);
    let output = p.output_tokens.load(Relaxed);
    let hit = p
        .cached_subset_tokens
        .load(Relaxed)
        .saturating_add(p.cache_read_tokens.load(Relaxed));
    let denom = p.cache_input_tokens.load(Relaxed);
    serde_json::json!({
        "requests": p.requests.load(Relaxed),
        "request_bytes": p.request_bytes.load(Relaxed),
        "response_bytes": p.response_bytes.load(Relaxed),
        "input_tokens": input,
        "output_tokens": output,
        "total_tokens": input.saturating_add(output),
        "cached_input_tokens": hit,
        "cache_input_tokens": denom,
        "cache_hit_ratio": cache_hit_ratio(hit, denom),
        "cache_reports": p.cache_reports.load(Relaxed),
        "usage_reports": p.usage_reports.load(Relaxed),
        // 按协议只给请求数（与隧道那份各记各的）
        "protocols": {
            "chat_completions": p.chat_completions.load(Relaxed),
            "responses": p.responses_api.load(Relaxed),
            "messages": p.messages.load(Relaxed),
        },
    })
}

/// `/__dshp/api/stats` 的契约测试：**四组字节都是原始整数**、两个比例上下行分开、
/// 三条协议固定都出现。这条测的是"页面与脚本看到的东西"，不是内部字段。
#[cfg(test)]
mod stats_json_tests {
    use super::{stats_json, TrafficStats};
    use std::sync::atomic::Ordering::Relaxed;

    #[test]
    fn four_byte_groups_and_two_direction_ratios_are_present() {
        let t = TrafficStats::default();
        t.responses.store(2, Relaxed);
        t.request_body_bytes.store(1000, Relaxed);
        t.request_transport_bytes.store(1250, Relaxed); // 小请求加帧头 ⇒ 上行膨胀
        t.response_body_bytes.store(4000, Relaxed);
        t.response_transport_bytes.store(1000, Relaxed); // 下行省 75%
        t.input_tokens.store(30, Relaxed);
        t.output_tokens.store(12, Relaxed);
        t.usage_reports.store(2, Relaxed);
        t.messages.requests.store(2, Relaxed);
        let v: serde_json::Value = serde_json::from_str(&stats_json(&t)).unwrap();
        // 四组一律给原始整数——显示单位只在页面里换，接口不掺显示口径
        assert_eq!(v["request_body_bytes"].as_u64(), Some(1000));
        assert_eq!(v["request_transport_bytes"].as_u64(), Some(1250));
        assert_eq!(v["response_body_bytes"].as_u64(), Some(4000));
        assert_eq!(v["response_transport_bytes"].as_u64(), Some(1000));
        // 节省比例**上下行分开**，且上行允许为负（1 - 1250/1000 = -0.25）
        assert!((v["saved_response_ratio"].as_f64().unwrap() - 0.75).abs() < 1e-6);
        assert!((v["saved_request_ratio"].as_f64().unwrap() + 0.25).abs() < 1e-6);
        assert_eq!(v["total_tokens"].as_u64(), Some(42));
        // 三条协议固定都在：缺失与 0 是两件事，页面上必须分得开
        for k in ["chat_completions", "responses", "messages"] {
            assert!(v["protocols"][k].is_object(), "{k} 必须固定出现");
        }
        assert_eq!(v["protocols"]["messages"]["requests"].as_u64(), Some(2));
    }

    #[test]
    fn zero_body_does_not_divide_by_zero() {
        let t = TrafficStats::default();
        let v: serde_json::Value = serde_json::from_str(&stats_json(&t)).unwrap();
        assert_eq!(v["saved_request_ratio"].as_f64(), Some(0.0));
        assert_eq!(v["saved_response_ratio"].as_f64(), Some(0.0));
        assert_eq!(v["cache_hit_ratio"].as_f64(), Some(0.0));
        assert_eq!(v["cached_input_tokens"].as_u64(), Some(0));
    }

    /// **输入缓存命中率**：两种协议的分母不同，必须各算对一遍。
    ///
    /// 这个数要跟"上行节省比例"互相对照用（请求侧做的是 KV cache 的等价物），
    /// 所以算错了会直接把判断带偏——上面那条 `cache_rate` 的统一公式就是为它写的。
    #[test]
    fn cache_hit_ratio_handles_both_protocol_shapes() {
        // OpenAI：命中是输入的子集 ⇒ 1888/2000 = 0.944
        let t = TrafficStats::default();
        t.input_tokens.store(2000, Relaxed);
        t.cached_subset_tokens.store(1888, Relaxed);
        t.cache_input_tokens.store(2000, Relaxed);
        t.cache_reports.store(4, Relaxed);
        let v: serde_json::Value = serde_json::from_str(&stats_json(&t)).unwrap();
        assert_eq!(v["cached_input_tokens"].as_u64(), Some(1888));
        assert_eq!(v["cache_input_tokens"].as_u64(), Some(2000));
        assert!((v["cache_hit_ratio"].as_f64().unwrap() - 0.944).abs() < 1e-6);
        assert_eq!(v["cache_reports"].as_u64(), Some(4), "样本量要能看见");

        // Anthropic：命中**不在**输入里 ⇒ 分母 = 1241 + 7 + 188 = 1436 ⇒ 188/1436 ≈ 0.130919
        let t = TrafficStats::default();
        t.input_tokens.store(1241, Relaxed);
        t.cache_creation_tokens.store(7, Relaxed);
        t.cache_read_tokens.store(188, Relaxed);
        t.cache_input_tokens.store(1436, Relaxed);
        t.cache_reports.store(1, Relaxed);
        let v: serde_json::Value = serde_json::from_str(&stats_json(&t)).unwrap();
        assert_eq!(v["cached_input_tokens"].as_u64(), Some(188));
        assert_eq!(v["cache_input_tokens"].as_u64(), Some(1436));
        assert!((v["cache_hit_ratio"].as_f64().unwrap() - 0.130919).abs() < 1e-5);

        // 逐协议那一层也要跟着算（页面是按协议分块显示的）
        let t = TrafficStats::default();
        t.chat_completions.input_tokens.store(2000, Relaxed);
        t.chat_completions.cached_subset_tokens.store(1500, Relaxed);
        t.chat_completions.cache_input_tokens.store(2000, Relaxed);
        let v: serde_json::Value = serde_json::from_str(&stats_json(&t)).unwrap();
        assert_eq!(
            v["protocols"]["chat_completions"]["cached_input_tokens"].as_u64(),
            Some(1500)
        );
        assert!(
            (v["protocols"]["chat_completions"]["cache_hit_ratio"]
                .as_f64()
                .unwrap()
                - 0.75)
                .abs()
                < 1e-6
        );
    }

    /// **没报 cache 的响应不许污染命中率**：它的输入量既不做分子也不做分母。
    ///
    /// 这条就是用户点名要的那件事：`input_tokens` 会照常涨（用于总量/tokens 展示），
    /// 但命中率只看"报了 cache 的样本"。
    #[test]
    fn cache_less_responses_do_not_dilute_the_hit_ratio() {
        let t = TrafficStats::default();
        // 10 万个输入 token 的响应**没报** cache ⇒ 只有 input_tokens 涨，命中率两端不动
        t.input_tokens.store(100_000, Relaxed);
        let v: serde_json::Value = serde_json::from_str(&stats_json(&t)).unwrap();
        assert_eq!(
            v["cache_hit_ratio"].as_f64(),
            Some(0.0),
            "没有样本 ⇒ 0，而不是被那 10 万 token 摊薄"
        );
        assert_eq!(v["cache_input_tokens"].as_u64(), Some(0));

        // 再来一个报了 cache 的（命中 1888 / 输入 2000）：比例只由它决定
        t.cached_subset_tokens.store(1888, Relaxed);
        t.cache_input_tokens.store(2000, Relaxed);
        t.cache_reports.store(1, Relaxed);
        let v: serde_json::Value = serde_json::from_str(&stats_json(&t)).unwrap();
        assert_eq!(
            v["cache_input_tokens"].as_u64(),
            Some(2000),
            "分母只算报了 cache 的那个响应"
        );
        assert!(
            (v["cache_hit_ratio"].as_f64().unwrap() - 0.944).abs() < 1e-6,
            "没报 cache 的 10 万 token 不得摊薄命中率"
        );
        assert_eq!(v["input_tokens"].as_u64(), Some(100_000));
    }

    /// 透传那一组**单独出现**，而且**不进**隧道的四组与两个比例 —— 这是"不许摊薄"的判据。
    #[test]
    fn passthrough_is_counted_separately_and_does_not_dilute_tunnel_ratios() {
        let t = TrafficStats::default();
        t.request_body_bytes.store(1000, Relaxed);
        t.request_transport_bytes.store(100, Relaxed);
        // 透传：前 = 后（没有编码/复用），量大且"完全没省"
        t.passthrough.requests.store(3, Relaxed);
        t.passthrough.request_bytes.store(500_000, Relaxed);
        t.passthrough.response_bytes.store(700_000, Relaxed);
        t.passthrough.input_tokens.store(900, Relaxed);
        t.passthrough.cached_subset_tokens.store(600, Relaxed);
        t.passthrough.cache_input_tokens.store(1000, Relaxed);
        t.passthrough.messages.store(2, Relaxed);
        let v: serde_json::Value = serde_json::from_str(&stats_json(&t)).unwrap();
        assert_eq!(v["passthrough"]["requests"].as_u64(), Some(3));
        assert_eq!(v["passthrough"]["request_bytes"].as_u64(), Some(500_000));
        assert_eq!(v["passthrough"]["response_bytes"].as_u64(), Some(700_000));
        assert_eq!(v["passthrough"]["cached_input_tokens"].as_u64(), Some(600));
        assert_eq!(v["passthrough"]["cache_input_tokens"].as_u64(), Some(1000));
        assert!((v["passthrough"]["cache_hit_ratio"].as_f64().unwrap() - 0.6).abs() < 1e-6);
        assert_eq!(v["passthrough"]["protocols"]["messages"].as_u64(), Some(2));
        // 隧道的四组与比例**一点没被影响**（这条就是要防"摊薄"）
        assert_eq!(v["request_body_bytes"].as_u64(), Some(1000));
        assert_eq!(v["request_transport_bytes"].as_u64(), Some(100));
        assert!((v["saved_request_ratio"].as_f64().unwrap() - 0.9).abs() < 1e-6);
        // 隧道的 tokens 也没被带偏
        assert_eq!(v["input_tokens"].as_u64(), Some(0));
    }
}

fn protocol_stats<'a>(traffic: &'a TrafficStats, path: &str) -> &'a ProtocolTraffic {
    if path.contains("/chat/completions") {
        &traffic.chat_completions
    } else if path.contains("/responses") {
        &traffic.responses_api
    } else if path.contains("/messages") {
        &traffic.messages
    } else {
        &traffic.responses_api
    }
}

fn authorized(req: &Request<Incoming>, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let Some(value) = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    if let Some(bearer) = value.strip_prefix("Bearer ") {
        return bearer == token;
    }
    let Some(encoded) = value.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
        return false;
    };
    let Ok(credentials) = std::str::from_utf8(&decoded) else {
        return false;
    };
    credentials.strip_prefix("admin:") == Some(token)
}

const WEBUI_HTML: &str = r#"<!doctype html>
<meta charset="utf-8"><meta name="color-scheme" content="dark light"><title>DSHP 统计</title>
<style>
/* 颜色**一律走 CSS 变量**：主题只换变量、不动结构 ⇒ 两套主题不会各自漂移。
   **默认深色**：深色值直接写在 `:root` 上，所以脚本还没跑之前页面就是深色（没有白闪）；
   `light` 显式覆盖成浅色；`auto` 才去跟随系统（系统深色时不用覆盖，默认就是深色）。 */
:root,:root[data-theme=dark]{--bg:#14161a;--fg:#e8eaed;--muted:#9aa0a6;--line:#333840;--line2:#2a2e34;--card:#1c1f24;--accent:#7ab3ff}
:root[data-theme=light]{--bg:#fff;--fg:#111;--muted:#666;--line:#ddd;--line2:#eee;--card:#fff;--accent:#0b62d6}
@media (prefers-color-scheme:light){:root[data-theme=auto]{--bg:#fff;--fg:#111;--muted:#666;--line:#ddd;--line2:#eee;--card:#fff;--accent:#0b62d6}}
body{background:var(--bg);color:var(--fg);font:16px system-ui;margin:2rem;max-width:900px}
h1{font-size:1.4rem}h2{font-size:1rem;color:var(--muted);margin:1.4rem 0 .5rem}h3{font-size:.95rem;margin:0 0 .5rem}
main{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.card{border:1px solid var(--line);background:var(--card);border-radius:8px;padding:14px}
.v{font-size:1.5rem;font-weight:700;word-break:break-all}.k{color:var(--muted);font-size:.85rem}
.sub{color:var(--muted);font-size:.8rem;margin-top:6px}
.proto{border:1px solid var(--line2);border-radius:10px;padding:14px;margin-bottom:14px}
#theme{position:fixed;top:12px;right:12px;font:14px system-ui;padding:6px 10px;border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:8px;cursor:pointer}
</style>
<button id="theme" type="button">主题：深色</button>
<h1>DSHP 服务端统计</h1><p id="state">加载中…</p>
<h2>上行（客户端 → 上游）</h2><main id="up"></main>
<h2>下行（上游 → 客户端）</h2><main id="down"></main>
<h2>分协议</h2><div id="proto"></div>
<h2>直连透传（非隧道）</h2><p class="sub" id="passtip">这部分**没走隧道** ⇒ 没有增量复用，也不计入上面四组（免得摊薄隧道节省率）。</p><main id="pass"></main>
<h2>汇总</h2><main id="rest"></main>
<script>
// 主题：**只换 CSS 变量，不碰任何数字**（判据仍然只看接口原值）。
// **默认深色**（`:root` 里就是深色值，脚本没跑之前也不白闪）；三种状态：
// dark（默认）/ light / auto（跟随系统）；手动选择存 localStorage；也支持
// `?theme=light` 直接指定（截图/分享用）。
var THEME_KEY='dshp-theme';
var THEME_ORDER=['dark','light','auto'];
var THEME_LABEL={dark:'主题：深色',light:'主题：浅色',auto:'主题：自动'};
function themeMode(){return document.documentElement.getAttribute('data-theme')||'dark'}
function applyTheme(mode){
  document.documentElement.setAttribute('data-theme',mode);
  var b=document.getElementById('theme'); if(b){b.textContent=THEME_LABEL[mode]||THEME_LABEL.dark}
}
function cycleTheme(){
  var next=THEME_ORDER[(THEME_ORDER.indexOf(themeMode())+1)%THEME_ORDER.length];
  try{localStorage.setItem(THEME_KEY,next)}catch(e){}
  applyTheme(next);
}
(function(){
  var q=null; try{q=new URLSearchParams(location.search).get('theme')}catch(e){}
  var saved=null; try{saved=localStorage.getItem(THEME_KEY)}catch(e){}
  // 优先级：URL 指定 > 上次选择 > **默认深色**
  var pick=THEME_ORDER.indexOf(q)>=0?q:(THEME_ORDER.indexOf(saved)>=0?saved:'dark');
  applyTheme(pick);
  var b=document.getElementById('theme'); if(b){b.onclick=cycleTheme}
})();
// 这里**只做显示换算**：接口给的是原始字节数，页面按 1024 进制自适应单位。
// 判据/对账请用接口原值，别用这个显示值。
function bytes(v){var n=Number(v)||0;var u=['B','KB','MB','GB','TB'];var i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return (i===0?n:n.toFixed(n>=100?0:n>=10?1:2))+' '+u[i]}
function pct(v){return ((Number(v)||0)*100).toFixed(2)+'%'}
function num(v){return Number(v||0).toLocaleString()}
function card(label,value,sub){return '<div class="card"><div class="k">'+label+'</div><div class="v">'+value+'</div>'+(sub?'<div class="sub">'+sub+'</div>':'')+'</div>'}
// 每条协议**各自一块**：三条都固定出现，哪怕计数为 0（"没流量"和"没这一栏"要分得开）
var ORDER=[['chat_completions','chat/completions'],['responses','responses'],['messages','messages']];
function protoBlock(title,v){
  var body=card('请求数',num(v.requests))
   +card('输入 tokens',num(v.input_tokens),'命中 '+num(v.cached_input_tokens))
   +card('缓存命中率',pct(v.cache_hit_ratio),'样本 '+num(v.cache_reports)+' / usage '+num(v.usage_reports)+'（没报 cache 的不计）')
   +card('输出 tokens',num(v.output_tokens))
   +card('总 tokens',num(v.total_tokens),'usage 报告数 '+num(v.usage_reports));
  return '<div class="proto"><h3>'+title+'</h3><main>'+body+'</main></div>';
}
async function load(){
  var r=await fetch('/__dshp/api/stats'); if(!r.ok) throw Error(r.status);
  var d=await r.json();
  var up=card('客户端请求内容（前）',bytes(d.request_body_bytes),'客户端本要发的完整请求体')
   +card('请求传输内容（后）',bytes(d.request_transport_bytes),'链路上实际传输（含帧头）')
   +card('上行节省比例',pct(d.saved_request_ratio),'1 - 后/前，负值表示比原始更大');
  var down=card('上游响应内容（前）',bytes(d.response_body_bytes),'上游真正吐出的响应体')
   +card('响应传输内容（后）',bytes(d.response_transport_bytes),'发给客户端（含帧头）')
   +card('下行节省比例',pct(d.saved_response_ratio),'1 - 后/前');
  var rest=card('响应数',num(d.responses),'四组字节都按已完成的响应累加')
   +card('总 tokens',num(d.total_tokens),'输入 '+num(d.input_tokens)+' / 输出 '+num(d.output_tokens))
   +card('缓存命中率',pct(d.cache_hit_ratio),'命中 '+num(d.cached_input_tokens)+' / 分母 '+num(d.cache_input_tokens)+'；样本 '+num(d.cache_reports)+'（usage '+num(d.usage_reports)+'）')
   +card('usage 报告数',num(d.usage_reports),'识别到用量字段的响应数');
  var p=d.protocols||{};
  var proto='';
  ORDER.forEach(function(e){ proto+=protoBlock(e[1],p[e[0]]||{requests:0,input_tokens:0,output_tokens:0,total_tokens:0,usage_reports:0}); });
  var pz=d.passthrough||{};
  var pass=card('透传请求数',num(pz.requests),'没走隧道 ⇒ 没有增量复用')
   +card('上行内容',bytes(pz.request_bytes),'客户端请求体字节')
   +card('下行内容',bytes(pz.response_bytes),'上游响应体字节')
   +card('输入 tokens',num(pz.input_tokens),'命中 '+num(pz.cached_input_tokens))
   +card('缓存命中率',pct(pz.cache_hit_ratio),'样本 '+num(pz.cache_reports)+' / usage '+num(pz.usage_reports)+'（没报 cache 的不计）')
   +card('总 tokens',num(pz.total_tokens));
  document.getElementById('pass').innerHTML=pass;
  document.getElementById('up').innerHTML=up;
  document.getElementById('down').innerHTML=down;
  document.getElementById('proto').innerHTML=proto;
  document.getElementById('rest').innerHTML=rest;
  state.textContent='已更新 '+new Date().toLocaleString();
}
load().catch(function(e){state.textContent='加载失败：'+e});setInterval(function(){load().catch(function(){})},5000);
</script>"#;

/// WebUI 的契约测试。页面是一段静态字符串，最容易"改着改着把要展示的东西弄丢"，
/// 或者"深色模式写成了另一套硬编码色值"（那个迟早会和浅色漂移），所以在这里钉住。
///
/// 主题的实现口径：**只换 CSS 变量**（`body` 的背景/前景都取自 `var(--*)`），
/// 页面上的任何数字都不因为它变化。
#[cfg(test)]
mod webui_tests {
    use super::WEBUI_HTML;

    #[test]
    fn dark_mode_is_the_default_and_can_be_switched() {
        // **默认深色**：深色值写在 `:root` 本身上 ⇒ 脚本还没跑之前页面就是深色（没有白闪）。
        // 这条判据要点在"默认值的位置"，而不是"存不存在深色"。
        assert!(
            WEBUI_HTML.contains(":root,:root[data-theme=dark]{--bg:#14161a"),
            "深色必须是 CSS 的默认值（挂成媒体查询会在加载瞬间白闪）"
        );
        assert!(
            WEBUI_HTML.contains("saved:'dark'"),
            "没有 URL 指定、也没有存过选择时，必须回落到深色"
        );
        assert!(
            WEBUI_HTML.contains(":root[data-theme=light]"),
            "必须能显式切到浅色"
        );
        assert!(
            WEBUI_HTML.contains("prefers-color-scheme:light"),
            "auto 档要能跟随系统（系统浅色时才覆盖成浅色）"
        );
        assert!(
            WEBUI_HTML.contains("localStorage"),
            "手动选择必须记住（否则每 5 秒/每次刷新都被打回默认）"
        );
        assert!(
            WEBUI_HTML.contains("URLSearchParams"),
            "要支持 ?theme=light / ?theme=dark 直接指定（截图/分享用）"
        );
        assert!(
            WEBUI_HTML.contains("主题：深色") && WEBUI_HTML.contains("主题：浅色"),
            "按钮上要写清当前档位"
        );
    }

    #[test]
    fn theme_only_swaps_css_variables() {
        assert!(
            WEBUI_HTML.contains("background:var(--bg)"),
            "body 的背景必须来自变量"
        );
        assert!(
            WEBUI_HTML.contains("color:var(--fg)"),
            "body 的前景必须来自变量"
        );
        assert!(
            !WEBUI_HTML.contains("body{background:#"),
            "不许把 body 的背景写死成硬编码色值——那样两套主题迟早漂移"
        );
    }

    /// 页面必须展示的东西：四组字节、两个方向的比例、命中率与样本量、三条协议。
    #[test]
    fn the_page_still_shows_everything_it_must() {
        for label in [
            "客户端请求内容（前）",
            "请求传输内容（后）",
            "上游响应内容（前）",
            "响应传输内容（后）",
            "上行节省比例",
            "下行节省比例",
            "缓存命中率",
            "样本 ",
            "直连透传（非隧道）",
            "透传请求数",
            "chat/completions",
            "responses",
            "messages",
        ] {
            assert!(WEBUI_HTML.contains(label), "页面少了「{label}」");
        }
        // 接口一律给原始整数 ⇒ 单位换算只能在页面上做，这条函数必须在。
        assert!(
            WEBUI_HTML.contains("function bytes("),
            "自适应单位函数不能丢"
        );
    }
}

/// 建立 SSE 隧道：上行取请求体，下行写 SSE 事件流。
///
/// 两侧的编码**刻意不对称**（见 `llm_proxy_transport::sse` 的模块说明）：
/// 请求体是普通 POST body，没有文本约束，直接用长度前缀二进制；
/// 响应体是 `text/event-stream`，必须 base64。
async fn tunnel(
    req: Request<Incoming>,
    peer: std::net::SocketAddr,
    app: AppShared,
) -> anyhow::Result<Response<RespBody>> {
    use futures_util::StreamExt;
    use llm_proxy_transport::sse::{ChunkReader, Duplex, OkSink, SseWriter};

    // 用 `futures-channel` 而不是 tokio 的 mpsc：**tokio 的 `Sender` 没有 `Sink` 实现**
    // （也没有 `sink` feature），而 `Mux` 要求写出端是 `Sink`。
    let (tx, rx) = futures_channel::mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    // 产出端收 `Result<Bytes, _>`，隧道只吐 `Bytes` → 用 OkSink 适配
    let out = SseWriter::new(OkSink::new(tx));
    // `Incoming` 实现的是 `http_body::Body`，不是 futures 的 `Stream`；
    // `into_data_stream()` 才是它与 `ChunkReader` 之间的桥
    let inp = ChunkReader::new(req.into_body().into_data_stream());
    let (mux, inbox) = Mux::spawn(
        Duplex::new(out, inp),
        llm_proxy_core::config::MAX_FRAME_BYTES,
    );

    // 会话在后台跑；响应立刻返回，SSE 事件随帧产出。**不能先 await 会话再返回响应**——
    // 那会让客户端永远收不到响应头，隧道根本立不起来。
    tokio::spawn(async move {
        if let Err(e) = run_session(mux, inbox, peer, app).await {
            tracing::debug!(%peer, ?e, "SSE 隧道会话结束");
        }
    });

    // `.boxed()` 在 `BodyExt` 与 `StreamExt` 上都有，必须消歧义
    let body = BodyExt::boxed(http_body_util::StreamBody::new(
        rx.map(|r| r.map(http_body::Frame::<Bytes>::data)),
    ));
    Response::builder()
        .status(http::StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        // 有些反代默认缓冲响应；显式关掉，否则"流式"名存实亡
        .header("x-accel-buffering", "no")
        .body(body)
        .context("构造 SSE 响应失败")
}

/// 一次性响应体（错误页）。
fn full_body(s: String) -> RespBody {
    http_body_util::Full::new(Bytes::from(s))
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed()
}

/// WS 路径：在已接受的 TCP 连接上完成 WS 握手并跑会话。
async fn handle_conn<S>(stream: S, peer: std::net::SocketAddr, app: AppShared) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 排空期间**不接新隧道**（缺口 #7）：这条路径还没进 hyper，只能自己写 503。
    // 为什么不干脆让它连上再被排空：那会变成"建起来→立刻又被通知走人"来回打转 ✗，
    // 客户端还多付一轮握手（含两次握手往返与认证）。明牌 503 + 客户端退避重试更干净 ✓。
    if app.draining.load(std::sync::atomic::Ordering::Relaxed) {
        let mut s = stream;
        if let Err(e) = write_503(&mut s).await {
            tracing::debug!(%peer, ?e, "排空期间拒绝新 WS 隧道时写 503 失败");
        }
        return Ok(());
    }
    let (mux, inbox) = llm_proxy_transport::accept(stream).await?;
    run_session(mux, inbox, peer, app).await
}

/// **传输无关**的会话主体：握手 → 帧循环。
///
/// 抽出来是为了让 WS 与 SSE 两条路共用同一套握手、认证、转发与背压逻辑——
/// 否则新增一条传输路径就意味着把这些安全相关逻辑复制一遍，两份会各自漂移。
async fn run_session(
    mux: Mux,
    mut inbox: mpsc::Receiver<Frame>,
    peer: std::net::SocketAddr,
    app: AppShared,
) -> anyhow::Result<()> {
    let (caps, ns, client_caps) = match handshake(&mux, &mut inbox, &app).await {
        Ok(v) => v,
        Err(e) => {
            // 认证失败是**安全事件**，必须 warn 级可见。早先只在 debug 级记录，
            // 默认过滤下 stderr 一片空白——实测 PSK 配错时运维完全无从下手。
            tracing::warn!(%peer, %e, "握手失败");
            // 回一条**通用原因**的 Err，让对端知道"是被拒了"而不是"网络断了"。
            // 具体原因（PSK 不一致 / 字典不一致 / 版本不符）只留在上面这行日志里：
            // 回给未认证来源等于送出一个认证预言机。
            let _ = send_err(
                &mux,
                0,
                err_code::AUTH_FAILED,
                "握手失败",
                hint::DOWNGRADE_BYPASS,
                Vec::new(),
            )
            .await;
            return Err(e);
        }
    };
    tracing::debug!(dict_id = caps.dict_id, ?client_caps, "握手完成");

    // **登记这条会话**（缺口 #7 排空）：排空需要一份"当前活着**且已认证**"的名单。
    //
    // 只在握手成功之后登记，理由与握手失败只回通用原因相同：对未认证的来源主动发帧，
    // 等于告诉它"你已通过认证"——那是个认证预言机 ✗。
    // 守卫保证会话结束时自动摘掉（否则排空会对着早已结束的会话发帧）。
    let session_id = app
        .next_session
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    app.sessions.lock().unwrap().insert(session_id, mux.clone());
    let _session = SessionGuard {
        id: session_id,
        app: app.clone(),
    };

    // 归纳器**按连接**存活，而不是按响应。
    //
    // 真实聊天里每个响应的 SSE 结构完全相同；按响应重建意味着每次都重付
    // 「两个归纳样本 + 一次 TEMPLATE_DEF」。实测这部分约 317 B/响应，
    // 在本轮 16 KB 的短响应上就占 1.9%——足以决定「省 ≥90%」过不过。
    let inducer = Arc::new(Mutex::new(llm_proxy_json::Inducer::new(
        llm_proxy_core::config::MAX_TEMPLATES,
    )));

    // 并发流信号量（**进程级**：缺口 11 第 112 轮从 `run_session` 提上来 ✓）。
    // 设计 §12 把它列为**硬限**（保护内存），§13.10 列为 DoS 防护 ✓。
    //
    // 语义是**等待**而不是立即拒绝 ✓。原因：这个上限保护的是内存（每个流可能缓冲到
    // `MAX_DECOMPOSE_BYTES`），而客户端正常并发时会同时打开多个流——直接拒绝会把这些
    // **合法的**请求变成 502 ✗，那是把内存保护做成了功能故障 ✓。排队才是正确的背压语义 ✓；
    // 只有等待超时才拒绝 ✓，那才是真的 DoS ✓。
    let slots = Arc::clone(&app.slots);
    let admission = Arc::clone(&app.admission);
    let diag = Arc::clone(&app.diag);
    /// 会话级：sid → 该流转发任务的句柄（取消时从外部 abort）。见 Cancel 分支。
    type Handles =
        Arc<std::sync::Mutex<std::collections::HashMap<u32, Option<tokio::task::AbortHandle>>>>;
    /// 任务结束时**自清**：不这么做，句柄表会按流累加（长会话里无界增长）。
    /// 用 `Option` 占位是为了避开"任务秒退 ⇒ 守卫先删、循环后插回"的竞态：
    /// 先插入 `None`，任务起来后再**就地把**它换成句柄（键已不在就不插）。
    struct DropRemove {
        map: Handles,
        sid: u32,
    }
    impl Drop for DropRemove {
        fn drop(&mut self) {
            self.map.lock().unwrap().remove(&self.sid);
        }
    }
    let handles: Handles = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let wait = std::time::Duration::from_millis(app.cfg.stream_wait_ms);

    // 连接级能力。慢路径是新的线上格式，**必须**按对端声明门控。
    let conn_caps = Arc::new(ConnCaps {
        ledger: ReqLedger::default(),
        client_stream_zstd: client_caps.iter().any(|c| c == "stream-zstd"),
        client_stream_ready: client_caps.iter().any(|c| c == "stream-ready"),
        // 续传同样**必须**按对端声明门控（见 `ConnCaps::client_resume` 的说明）✓。
        client_resume: client_caps.iter().any(|c| c == "resume"),
    });

    while let Some(f) = inbox.recv().await {
        // 把 mux 的"丢弃帧"计数搬到诊断里：缺口 8 查证时，它是"取消帧到底有没有
        // 被路由"的直接证据（`Mux::dropped_frames` 的注释写着"非 0 说明有正确性
        // 风险，应告警"——只是此前没人看）。
        {
            use std::sync::atomic::Ordering as O;
            app.diag
                .dropped_frames
                .store(mux.dropped_frames(), O::Relaxed);
            app.diag
                .received_frames
                .store(mux.received_frames(), O::Relaxed);
        }
        match f.ty {
            // **客户端取消**（缺口 8）。分两种情况，两条都要处理：
            //
            // * 帧被 mux 路由到了那条流的通道 ⇒ 由转发任务里的 `wait_client_cancel`
            //   直接看到（那条路径本来就有）；
            // * 帧落到**会话收件箱**（mux 只把帧投给**已绑定**的 stream_id，未绑定的
            //   送收件箱）⇒ 就是这里。实测：`mux.send` 全部 Ok，而服务端
            //   `cancel_frames=0`、`dropped_frames=0`——帧既没进流通道也没被丢。
            //
            // 这里的动作只有一件：`unbind_stream`。它会丢掉路由表里那个 sender ⇒
            // 转发任务手里的 `rx` 随即关闭 ⇒ 任务的 `wait_client_cancel` 走"通道关闭"、
            // 丢弃上游请求、释放并发槽位。**不必把取消信号一路穿进转发函数**。
            FrameType::Cancel => {
                // 目标流在**载荷**里（取消是会话级帧，帧头 sid 恒为 0）；
                // 兼容早期按帧头定位的形态。
                let sid = llm_proxy_transport::session::cancel_target(&f).unwrap_or(f.stream_id);
                use std::sync::atomic::Ordering as O;
                app.diag.cancel_frames.fetch_add(1, O::Relaxed);
                // 取消帧的到达由会话循环处理：**从外部 abort 那条任务**（见下）。
                // **从外部 abort 那条流的任务**——这是唯一不依赖"任务自己还在被轮询"
                // 的释放手段。实测：那些任务首轮之后就不再被轮询（100ms 心跳也只跑了
                // 一次），所以任何"任务侧监听取消"的机制都不会触发。
                // `JoinHandle::abort` 会丢弃任务的整个 future 树 ⇒ 槽位 permit 与
                // 在途计数随之释放。
                if let Some(Some(h)) = handles.lock().unwrap().remove(&sid) {
                    tracing::debug!(stream_id = sid, "取消：从外部中止转发任务");
                    h.abort();
                }
                mux.unbind_stream(sid);
                tracing::debug!(
                    stream_id = sid,
                    "会话收到客户端取消，解绑该流以唤醒转发任务"
                );
            }
            FrameType::ReqOpen => {
                let sid = f.stream_id;
                let (app2, mux2, ind2) = (app.clone(), mux.clone(), inducer.clone());
                let slots2 = Arc::clone(&slots);
                let admission2 = Arc::clone(&admission);
                let caps2 = Arc::clone(&conn_caps);
                let diag2 = Arc::clone(&diag);
                // 先限制逻辑 stream 总数，再创建等待任务。新客户端会等
                // `StreamReady` 后才发送请求体，因此排队不会制造大量 body 缓冲。
                let admission_permit = match admission2.try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        let _ = send_err(
                            &mux,
                            sid,
                            err_code::TOO_MANY_STREAMS,
                            "服务端等待队列已满",
                            hint::RETRY_WITH_FULL,
                            Vec::new(),
                        )
                        .await;
                        continue;
                    }
                };
                // 旧客户端没有 `stream-ready` 能力时保留旧路由时序，以兼容已部署版本。
                // 新客户端在拿到活跃槽位前不绑定路由，也不会发送 BodyChunk。
                let legacy_rx = if caps2.client_stream_ready {
                    None
                } else {
                    Some(mux.bind_stream(sid))
                };
                // 会话循环留住句柄：取消时**从外部 abort**（见下方 Cancel 分支）。
                handles.lock().unwrap().insert(sid, None);
                let cleanup = DropRemove {
                    map: Arc::clone(&handles),
                    sid,
                };
                let handle = tokio::spawn(async move {
                    let _cleanup = cleanup;
                    let _admission = admission_permit;
                    // 背压：拿不到槽位就等，而不是把合法的并发请求变成失败。
                    let _slot = match tokio::time::timeout(wait, slots2.acquire_owned()).await {
                        Ok(Ok(p)) => {
                            // 在途计数与槽位同生共死：`InflightGuard` 与 `p` 一起被丢弃。
                            // （缺口 8 的诊断：看"取消之后槽位到底放没放"）
                            use std::sync::atomic::Ordering as O;
                            diag2.streams_opened.fetch_add(1, O::Relaxed);
                            let cur = diag2.streams_inflight.fetch_add(1, O::AcqRel) + 1;
                            diag2.streams_peak.fetch_max(cur, O::AcqRel);
                            (p, InflightGuard(Arc::clone(&diag2)))
                        }
                        Ok(Err(_)) => return, // 信号量已关闭
                        Err(_) => {
                            tracing::warn!(
                                stream_id = sid,
                                wait_ms = wait.as_millis() as u64,
                                limit = app2.cfg.max_concurrent_streams,
                                "等待并发流槽位超时，拒绝该流"
                            );
                            let _ = send_err(
                                &mux2,
                                sid,
                                err_code::TOO_MANY_STREAMS,
                                &format!(
                                    "并发流超限（上限 {}），等待 {}ms 仍无空位",
                                    app2.cfg.max_concurrent_streams,
                                    wait.as_millis()
                                ),
                                hint::RETRY_WITH_FULL,
                                Vec::new(),
                            )
                            .await;
                            mux2.unbind_stream(sid);
                            return;
                        }
                    };

                    let rx = match legacy_rx {
                        Some(rx) => rx,
                        None => {
                            // 只有拿到活跃槽位后才建立服务端路由并放行客户端请求体。
                            let rx = mux2.bind_stream(sid);
                            if mux2
                                .send(Frame::new(FrameType::StreamReady, sid, 0, Vec::new()))
                                .await
                                .is_err()
                            {
                                mux2.unbind_stream(sid);
                                return;
                            }
                            rx
                        }
                    };

                    if let Err(e) =
                        forward(app2.clone(), caps2, mux2.clone(), ind2, ns, sid, f, rx).await
                    {
                        tracing::warn!(stream_id = sid, ?e, "转发失败");
                        let _ = send_err(
                            &mux2,
                            sid,
                            err_code::INTERNAL,
                            &format!("{e:#}"),
                            hint::DOWNGRADE_BYPASS,
                            Vec::new(),
                        )
                        .await;
                    }
                    mux2.unbind_stream(sid);
                });
                // 就地登记句柄（键已被守卫清掉就不再插回——那样会漏一条）。
                if let Some(slot) = handles.lock().unwrap().get_mut(&sid) {
                    *slot = Some(handle.abort_handle());
                }
            }
            FrameType::Ping => {
                mux.send_session(FrameType::Pong, Vec::new()).await?;
            }
            // **续传**（缺口 #2，设计 §11.2）：客户端重连后，拿 `RESUME{req_id, ack_seq}` 来续。
            //
            // 语义只有两种结果，**没有中间态** ✓：
            // * 环里还完整留着 `seq > ack_seq` 的全部帧 ⇒ 重放并把后续帧改发到**这条新会话** ✓；
            // * 否则 ⇒ `ERR(STREAM_GAP)` ✓ —— 客户端**不自动重放上游**（那等于重新计费 +
            //   采样结果会变 ✗），而是按上游错误格式交给 SDK 决定 ✓。
            FrameType::Resume => {
                let parsed = proto::Resume::decode(&f.payload[..]);
                match parsed {
                    Ok(r) => {
                        let sid = r.req_id as u32;
                        let sink = app.rings.lock().unwrap().get(&sid).cloned();
                        match sink {
                            Some(s) => match s.rebind_and_replay(mux.clone(), r.ack_seq).await {
                                crate::resume::Replay::Frames(_) => {
                                    tracing::info!(
                                        stream_id = sid,
                                        ack = r.ack_seq,
                                        "续传成功：已从断点重放并把后续帧改发到新会话"
                                    );
                                }
                                crate::resume::Replay::Gap => {
                                    tracing::warn!(
                                        stream_id = sid,
                                        ack = r.ack_seq,
                                        "续传失败（环里已无该断点）⇒ 报 STREAM_GAP"
                                    );
                                    let target = s.session().unwrap_or_else(|| mux.clone());
                                    let _ = send_err(
                                        &target,
                                        sid,
                                        err_code::STREAM_GAP,
                                        "断点已不在服务端的环形缓冲里",
                                        hint::DOWNGRADE_BYPASS,
                                        Vec::new(),
                                    )
                                    .await;
                                }
                            },
                            None => {
                                tracing::warn!(stream_id = sid, "续传请求找不到对应流");
                                let _ = send_err(
                                    &mux,
                                    sid,
                                    err_code::STREAM_GAP,
                                    "该流已不在服务端（可能早已结束）",
                                    hint::DOWNGRADE_BYPASS,
                                    Vec::new(),
                                )
                                .await;
                            }
                        }
                    }
                    Err(e) => tracing::warn!(?e, "RESUME 解不出来，忽略"),
                }
            }
            FrameType::GoAway => break,
            other => tracing::debug!(ty = ?other, "忽略的会话级帧"),
        }
    }
    // 会话断开时同时终止仍在等待全局槽位的任务。否则新准入模型下，
    // 这些任务会继续持有 admission permit，直到等待超时才退出。
    let leftovers: Vec<tokio::task::AbortHandle> = handles
        .lock()
        .unwrap()
        .drain()
        .filter_map(|(_, h)| h)
        .collect();
    for h in leftovers {
        h.abort();
    }
    Ok(())
}

async fn send_err(
    mux: &Mux,
    sid: u32,
    code: u32,
    detail: &str,
    hint: &str,
    missing: Vec<Vec<u8>>,
) -> Result<(), SessionError> {
    let e = proto::Err {
        code,
        detail: detail.to_string(),
        hint: hint.to_string(),
        req_id: sid as u64,
        missing,
    };
    let mut f = Frame::new(FrameType::Err, sid, 0, e.encode_to_vec());
    f.flags = Flags::default().with(flags::LAST);
    mux.send(f).await
}

/// 握手：等 `Hello`，验 HMAC 与时间窗，回 `Caps`，并派生缓存命名空间。
async fn handshake(
    mux: &Mux,
    inbox: &mut mpsc::Receiver<Frame>,
    app: &App,
) -> anyhow::Result<(proto::Caps, Namespace, Vec<String>)> {
    // 握手第一步的准备：生成本端临时 X25519 密钥对。
    // 用 CSPRNG，且 PSK 为空时直接拒绝——不允许无认证握手（设计 §13.4/§13.8）。
    let responder = llm_proxy_core::crypto::Responder::new(app.cfg.psk.as_bytes())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let our_pub = responder.public();

    let hello_frame = loop {
        let f = inbox.recv().await.context("连接在握手完成前关闭")?;
        match f.ty {
            FrameType::Hello => break f,
            FrameType::Ping => {
                mux.send_session(FrameType::Pong, Vec::new()).await?;
            }
            other => bail!("握手期收到意外帧 {other:?}"),
        }
    };

    let hello = proto::Hello::decode(&hello_frame.payload[..]).context("Hello 解码失败")?;
    verify_handshake(
        app.cfg.psk.as_bytes(),
        hello.nonce,
        hello.timestamp_ms,
        &hello.hmac,
        now_ms(),
    )
    .map_err(|e: SessionError| anyhow::anyhow!("{e}"))?;

    if !hello.proto_version.is_empty()
        && hello.proto_version != llm_proxy_core::config::PROTO_VERSION
    {
        bail!(
            "协议版本不一致：客户端 {} vs 服务端 {}",
            hello.proto_version,
            llm_proxy_core::config::PROTO_VERSION
        );
    }

    // 字典协商（设计 §7.3）。当前两端都用内嵌的引导字典；客户端把它随 Hello 上送，
    // 服务端**必须校验与自己的字典一致**——不一致时 zstd 会在解压期报 dictID 不符，
    // 与其拖到运行时，不如在握手期就明确拒绝。
    let our_id = llm_proxy_core::dict::dict_id(llm_proxy_core::dict::Dicts::bootstrap().patch);
    let dict_id = if hello.dict.is_empty() {
        llm_proxy_core::dict::DICT_ID_NONE
    } else {
        llm_proxy_core::config::check_dict_fits_window(hello.dict.len())
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let id = llm_proxy_core::dict::dict_id(&hello.dict);
        if hello.dict_id != 0 && hello.dict_id != id {
            bail!(
                "dict_id 与字典字节不一致：声明 {} 实算 {}",
                hello.dict_id,
                id
            );
        }
        if id != our_id {
            bail!(
                "字典不一致：客户端 dict_id={id} 服务端 dict_id={our_id}。\
                 压缩帧会绑定字典，两端不一致会导致解压失败，必须当场拒绝。"
            );
        }
        id
    };

    // **租户一致性（设计 §4.1）**：两端必须配置同一个租户，不一致**直接拒绝**。
    //
    // 为什么不能"不一致也能用"：租户参与缓存命名空间派生，两端不一致会让
    // ①缓存全不命中（白花流量，而这一层收益本来就靠命中）；
    // ②不同租户共享命名空间——§13.9/T7 明确要求「块查询严格限定在本租户命名空间内，
    // 跨命名空间一律视为 miss」，共享就等于把补缺协商变成跨租户的内容确认预言机。
    if hello.tenant != app.cfg.tenant {
        bail!(
            "租户不一致：客户端 {:?} 服务端 {:?}。\
             两端必须配置同一个租户，否则缓存命名空间会错位（设计 §4.1）",
            hello.tenant,
            app.cfg.tenant
        );
    }

    // 握手第二步：用客户端公钥完成 DH，派生出会话密钥。
    let their_pub: [u8; 32] = hello
        .x25519_pub
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Hello 里的 X25519 公钥长度不是 32 字节"))?;
    let done = responder.finish(their_pub);

    let caps = proto::Caps {
        proto_version: llm_proxy_core::config::PROTO_VERSION.to_string(),
        dict_id,
        // **本端"能收"的编码**（不是"能发"）。方向必须说清楚：
        //
        //   · 请求方向：客户端发 → 服务端收 ⇒ 收的这端（本处）宣告 `raw/tokenstream/zstd`；
        //     客户端据此检查（它此前**从不读**这份清单——那条方向的协商是死的，
        //     已补 `check_server_caps`）。
        //   · 响应方向：服务端发 → 客户端收 ⇒ **客户端**宣告 `stream-zstd`
        //     （`client_stream_zstd`）。这里**不要**加 `stream-zstd`：本端不发也不收它，
        //     加了只会让"谁负责声明"再次变模糊——正是这一点让慢路径曾静默地从未启用。
        caps: vec![
            "ws".into(),
            "raw".into(),
            "tokenstream".into(),
            "zstd".into(),
            "stream-ready".into(),
        ],
        upstream_host: app.cfg.upstream_host.clone(),
        // 回传自己的租户，让客户端也能双向校验（设计 §4.1：两端都配置、校验一致）
        tenant: app.cfg.tenant.clone(),
        max_frame_bytes: llm_proxy_core::config::MAX_FRAME_BYTES as u32,
        window_log: llm_proxy_core::config::WINDOW_LOG,
        x25519_pub: our_pub.to_vec(),
        confirm: done.our_confirm.to_vec(),
    };
    // 握手第二步：用客户端公钥完成 DH，派生出会话密钥。
    // **必须在发出 Caps 之前开启 AEAD**：Caps 本身是明文的（`needs_protection` 排除，
    // 它要携带公钥与确认值），但紧随其后的 `KeyConfirm` 是密文——开启晚了就解不开。
    mux.enable_crypto(llm_proxy_transport::SessionCrypto::new(&done.keys, false));
    // 记下**客户端**声明的能力：慢路径是新的线上格式，
    // 对端不声明支持就绝不能发——否则旧客户端解不开这些帧，响应直接坏掉。
    let client_caps = hello.caps.clone();

    mux.send_session(FrameType::Caps, caps.encode_to_vec())
        .await?;

    // 握手第三步：等客户端的确认值并**校验**。这一步不能省——它是双向认证的落点。
    let kc_frame = loop {
        let f = inbox.recv().await.context("握手期连接关闭")?;
        match f.ty {
            FrameType::KeyConfirm => break f,
            FrameType::Ping => {
                mux.send_session(FrameType::Pong, Vec::new()).await?;
            }
            other => bail!("等待 KeyConfirm 时收到意外帧 {other:?}"),
        }
    };
    let kc = proto::KeyConfirm::decode(&kc_frame.payload[..]).context("KeyConfirm 解码失败")?;
    done.verify_peer(&kc.confirm)
        .map_err(|e| anyhow::anyhow!("客户端认证失败：{e}"))?;
    tracing::debug!("双向认证完成，会话已加密");

    // 两端必须用同一命名空间派生输入，否则缓存物理隔离会错位。
    // 用配置值（不是 `hello.tenant`）：上面已经校验两者相等，用配置值更直白地表达
    // **本端认定的租户**，也避免"某天有人把校验删了、命名空间悄悄跟着客户端走"。
    let ns = Namespace::derive(
        app.cfg.psk.as_bytes(),
        &app.cfg.tenant,
        &app.cfg.upstream_host,
    );
    Ok((caps, ns, client_caps))
}

#[allow(clippy::too_many_arguments)] // 转发链的上下文：拆结构体在这里只会增加间接层
async fn forward(
    app: AppShared,
    conn_caps: Arc<ConnCaps>,
    mux: Mux,
    inducer: Arc<Mutex<llm_proxy_json::Inducer>>,
    ns: Namespace,
    sid: u32,
    open_frame: Frame,
    rx: mpsc::Receiver<Frame>,
) -> anyhow::Result<()> {
    let open = proto::ReqOpen::decode(&open_frame.payload[..]).context("ReqOpen 解码失败")?;

    // 缺口 14：同一 `req_id` 第二次出现就**拒绝** ⇒ **绝不第二次调用上游** ✓。
    //
    // 位置刻意选在这里：`forward` 是三种编码（RAW / TOKENSTREAM / ZSTD）**唯一的**分派点 ✓，
    // 所以一处即覆盖全部路径 ✓；更靠前（HTTP 层）不行——那时还没有 `req_id` ✓。
    // `req_id` 就是 `sid` ✓ ⇒ 台账**必须按连接**记 ✓（见 `ReqLedger` 的类型文档 ✓）。
    if !conn_caps.ledger.admit(open.req_id) {
        tracing::warn!(
            stream_id = sid,
            req_id = open.req_id,
            "重复的 req_id：拒绝，不重放上游"
        );
        let _ = send_err(
            &mux,
            sid,
            err_code::REQ_REPLAY,
            "重复的 req_id（同一连接内已见过）：绝不第二次调用上游",
            hint::DUPLICATE_REQ_ID,
            Vec::new(),
        )
        .await;
        return Ok(());
    }
    match open.encoding() {
        // **必须传连接级归纳器**（见 `forward_raw` 顶部那段事故记录）：
        // 这条路径曾经自己新建归纳器 ⇒ 一条连接上两套模板 id 空间。
        proto::Encoding::EncRaw => forward_raw(app, conn_caps, mux, inducer, sid, open, rx).await,
        proto::Encoding::EncTokenstream => {
            forward_token(app, conn_caps, mux, inducer, ns, sid, open, rx).await
        }
        proto::Encoding::EncZstd => {
            forward_zstd(app, conn_caps, mux, inducer, ns, sid, open, rx).await
        }
        proto::Encoding::EncStruct => {
            // 结构编码在 M1b 落地。在此之前**明确拒绝**而不是猜测语义，
            // 并让客户端回退到全量——安静的误解析会变成重组错误。
            send_err(
                &mux,
                sid,
                err_code::BAD_ENCODING,
                "ENC_STRUCT 尚未实现（M1b）",
                hint::RETRY_WITH_FULL,
                Vec::new(),
            )
            .await?;
            Ok(())
        }
    }
}

/// 一次请求的上行字节（**客户端视角**：前=内容，后=实际传输）。
///
/// 两者都要各累加一次到 [`TrafficStats`]：**上行不一定省**——小请求加上帧头可能比原始更大，
/// 若只报"省了多少"就会把这件事藏起来（所以比例允许为负，见 `ratio6`）。
#[derive(Clone, Copy, Debug, Default)]
struct UpstreamBytes {
    /// 前：客户端原始请求内容（服务端重建出、发往上游的请求体字节）。
    body: u64,
    /// 后：请求方向在 DSHP 链路上实际传输的字节（含帧头）。
    transport: u64,
}

/// 原样透传：请求体边收边喂给上游，不缓冲。
async fn forward_raw(
    app: AppShared,
    conn_caps: Arc<ConnCaps>,
    mux: Mux,
    inducer: Arc<Mutex<llm_proxy_json::Inducer>>,
    sid: u32,
    open: proto::ReqOpen,
    mut rx: mpsc::Receiver<Frame>,
) -> anyhow::Result<()> {
    let (req, content_length) = build_request(&app.cfg, &open, None)?;
    // 上行两组：**载荷**是客户端发来的字节，**帧头**也要算进"实际传输"，
    // 口径与客户端状态里的 `req_wire_bytes` 一致，两侧可直接对账。
    let up_body = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let up_transport = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (body_tx, body) = ChannelBody::channel();
    let body = match content_length {
        Some(n) => body.with_exact_size(n),
        None => body,
    };
    let req = req.body(body)?;

    let upstream = app.client.request(req);
    let observed_body = std::sync::Arc::clone(&up_body);
    let observed_transport = std::sync::Arc::clone(&up_transport);
    let feed = async move {
        // **只有见到 `LAST` 或 `ReqCommit` 才算请求体发完。**
        //
        // 不能用"帧流结束"当结束信号：链路在请求体发到一半时断掉，
        // `rx.recv()` 会返回 `None`，循环正常退出，然后 `drop(body_tx)` 干净收尾。
        // 若上游侧是 **chunked**（客户端没给 `Content-Length`，`content_length` 为 None），
        // 就成了一条"格式完整、内容只有半截"的请求——上游会照着半截问题生成答案，
        // 用户拿到一个看起来正常但答非所问的响应。**这是静默错误内容。**
        // （有 `Content-Length` 时 hyper 会自己发现长度不符而失败，但那条保护
        //   只在一种编码下存在，不能依赖。）
        let mut committed = false;
        while let Some(f) = rx.recv().await {
            match f.ty {
                FrameType::BodyChunk => {
                    let last = f.flags.contains(flags::LAST);
                    // 前＝载荷（原样透传路径下，载荷**就是**请求体字节）；后＝含帧头的实际传输。
                    observed_body
                        .fetch_add(f.payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    observed_transport.fetch_add(
                        (llm_proxy_core::frame::HEADER_LEN + f.payload.len()) as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    if body_tx.send(Ok(Bytes::from(f.payload))).await.is_err() {
                        break;
                    }
                    if last {
                        committed = true;
                        break;
                    }
                }
                FrameType::ReqCommit => {
                    committed = true;
                    break;
                }
                FrameType::Ping => {}
                _ => {}
            }
        }
        if !committed {
            tracing::error!(stream_id = sid, "请求体未发完就断流，中止上游请求");
            let _ = body_tx
                .send(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "DSHP 请求体未发完（缺 LAST / ReqCommit）",
                )))
                .await;
        }
        drop(body_tx);
    };
    app.phases
        .lock()
        .unwrap()
        .insert(sid, "raw:await-upstream".to_string());
    let joined = async { tokio::join!(upstream, feed).0 };
    // 等上游的同时**也听显式取消**（缺口 8）。这条路径是 `ENC_RAW`——客户端把请求体
    // 原样透传（无预热时的常见形态）。上一版我只把取消接进了 `send_buffered`，
    // 于是本场景（冷启动 + `hang` 上游）里的任务**从未被唤醒过**。
    let resp = tokio::select! {
        r = joined => r.context("上游请求失败")?,
    };
    // **归纳器必须是连接级那一个**（由 `forward` 传入）。
    //
    // 这里曾经每次请求 `Inducer::new(...)` 新建一个 ⇒ 同一条连接上并存**两套模板 id 空间**
    // （连接级的 1..N 与每请求的 1..N），而客户端的模板表是**连接级、按 id 索引**的：
    // 两套 id 互相覆盖 ⇒ 客户端可能拿**错的模板**解析批量帧 ⇒ 槽数错位 ⇒ 读出垃圾 id
    // ⇒ 主动截断响应 ⇒ SDK 收到传输错误（harness 报 `terminated`）。
    //
    // 实测证据（线上、可复现构建）：客户端 12 次 `UnknownTemplate(10)`、一次 `(11779)`；
    // 而整轮运行里归纳器 `templates` **从未超过 8**（`next_id` 从 1 递增、容量 64 不淘汰
    // ⇒ 合法 id 只可能是 1..8）⇒ **服务端不可能引用 10**，那个 id 只能是错位读出来的。
    // 顺带：这条路径还在按响应重复付 `TEMPLATE_DEF`（实测客户端收到 43 次定义只对应 8 个模板），
    // 正是 `Inducer` 上方注释里说要避免的那笔开销（设计 §6.2：模板由服务端主导、按连接存活）。
    relay_response(
        &app,
        &conn_caps,
        &mux,
        &inducer,
        sid,
        open.req_id,
        &open.path_and_query,
        UpstreamBytes {
            body: up_body.load(std::sync::atomic::Ordering::Relaxed),
            transport: up_transport.load(std::sync::atomic::Ordering::Relaxed),
        },
        resp,
        // 客户端声明「我的表是空的」⇒ 本流引用到的模板定义要补发 ✓（第 195/197 轮 ✓）
        open.client_needs_defs,
    )
    .await
}

/// 增量：收 TokenStream → 重组 → **校验通过才发上游**。
#[allow(clippy::too_many_arguments)] // 转发链的上下文：拆结构体在这里只会增加间接层
async fn forward_token(
    app: AppShared,
    conn_caps: Arc<ConnCaps>,
    mux: Mux,
    inducer: Arc<Mutex<llm_proxy_json::Inducer>>,
    ns: Namespace,
    sid: u32,
    open: proto::ReqOpen,
    mut rx: mpsc::Receiver<Frame>,
) -> anyhow::Result<()> {
    // ---- 1. 收齐 TokenStream ----
    let mut stream: Vec<u8> = Vec::new();
    let mut total = 0usize;
    // 上行「后」：请求方向实际传输的字节（**含帧头**）。「前」要等重组出 body 才知道。
    let mut up_transport = 0u64;
    // 见 `forward_raw` 里的长注释：**没发完就不许当成发完了**。
    // 这条路径靠的是后面的 `target_fp` 校验兜底，但那是"事后发现"；
    // 在这里直接拒绝，才是"根本不发出去"。
    let mut committed = false;
    while let Some(f) = rx.recv().await {
        match f.ty {
            FrameType::BodyChunk => {
                let last = f.flags.contains(flags::LAST);
                up_transport += (llm_proxy_core::frame::HEADER_LEN + f.payload.len()) as u64;
                if !f.payload.is_empty() {
                    total += f.payload.len();
                    if total > MAX_TOKENSTREAM_BYTES {
                        return send_err(
                            &mux,
                            sid,
                            err_code::TOO_LARGE,
                            &format!("TokenStream 超过 {MAX_TOKENSTREAM_BYTES} 字节"),
                            hint::RETRY_WITH_FULL,
                            Vec::new(),
                        )
                        .await
                        .map_err(Into::into);
                    }
                    stream.extend_from_slice(&f.payload);
                }
                if last {
                    committed = true;
                    break;
                }
            }
            FrameType::ReqCommit => {
                committed = true;
                break;
            }
            FrameType::Ping => {}
            _ => {}
        }
    }
    if !committed {
        // 半截 TokenStream 有可能**恰好自洽**（引用到的块都在），重组出的是一个
        // 更短的 body——不在这里拦，就要靠 `target_fp` 事后发现。
        return send_err(
            &mux,
            sid,
            err_code::LENGTH_MISMATCH,
            "TokenStream 未发完就断流",
            hint::RETRY_WITH_FULL,
            Vec::new(),
        )
        .await
        .map_err(Into::into);
    }

    // ---- 2. 用块存储重组（literal 块顺带落库）----
    let recomposed = {
        let mut store = app.blocks.lock().unwrap();
        store.recompose(ns, &stream, Instant::now())
    };
    let r = match recomposed {
        Ok(r) => r,
        // 缺块：报告**缺哪些**，客户端据此只补这些（设计 §9.2：最多 1 个 RTT）。
        // 注意日志别写成"请求全量重发"：提示是 `SEND_MISSING`，
        // 客户端的行为是"忘掉缺块、只补发缺的那些"（实测见 e2e-tests/recovery.rs）。
        Err(RecomposeError::Missing(missing)) => {
            tracing::debug!(
                stream_id = sid,
                n = missing.len(),
                "缺块，请客户端补发缺的那些"
            );
            return send_err(
                &mux,
                sid,
                err_code::BLOCK_MISS,
                &format!("缺少 {} 个块", missing.len()),
                hint::SEND_MISSING,
                missing.iter().map(|fp| fp.as_bytes().to_vec()).collect(),
            )
            .await
            .map_err(Into::into);
        }
        // 编码不合法：**明确拒绝而不是猜语义**。
        //
        // 这里绝不能报成"缺块"：解析失败时缺块清单本来就是空的，
        // 报出去就是"缺少 0 个块" + 提示客户端去补一个不存在的清单。
        // 真实起因（客户端发的 TokenStream 坏了）必须体现在码与详情里。
        Err(RecomposeError::Malformed(e)) => {
            tracing::warn!(stream_id = sid, %e, "TokenStream 不合法，拒绝而不是猜测");
            return send_err(
                &mux,
                sid,
                err_code::BAD_ENCODING,
                &format!("TokenStream 不合法：{e}"),
                hint::RETRY_WITH_FULL,
                Vec::new(),
            )
            .await
            .map_err(Into::into);
        }
    };

    // ---- 3. 正确性红线：先校验，再发上游 ----
    if !open.target_fp.is_empty() {
        let actual = body_fp(ns, &r.body);
        if actual.as_bytes().as_slice() != open.target_fp.as_slice() {
            tracing::error!(
                stream_id = sid,
                declared = %hex(&open.target_fp),
                actual = %actual,
                "target_fp 不符——重组结果与客户端声明不一致"
            );
            // 该流引用过的块可能已脏；不猜测根因，让客户端全量重发
            return send_err(
                &mux,
                sid,
                err_code::FP_MISMATCH,
                "重组结果与 target_fp 不符",
                hint::RETRY_WITH_FULL,
                Vec::new(),
            )
            .await
            .map_err(Into::into);
        }
    }
    let body = r.body;
    if body.len() > MAX_DECOMPOSE_BYTES {
        return send_err(
            &mux,
            sid,
            err_code::TOO_LARGE,
            &format!("重组后 body {} 字节超过上限", body.len()),
            hint::RETRY_WITH_FULL,
            Vec::new(),
        )
        .await
        .map_err(Into::into);
    }

    // ---- 4. 声明长度必须与实际一致，否则上游会挂住或截断 ----
    send_buffered(
        app,
        conn_caps,
        mux,
        inducer,
        sid,
        open,
        up_transport,
        body,
        rx,
    )
    .await
}

/// 增量：请求体是**单个 zstd 帧**（`ENC_ZSTD`）。
///
/// 用于冷启动 / 缓存未命中的整段回退路径——那条路径上要原样发出整个 body
/// （真实量级 3 MB），zstd + dict_patch 是唯一能显著削减它的手段。
#[allow(clippy::too_many_arguments)] // 转发链的上下文：拆结构体在这里只会增加间接层
async fn forward_zstd(
    app: AppShared,
    conn_caps: Arc<ConnCaps>,
    mux: Mux,
    _inducer: Arc<Mutex<llm_proxy_json::Inducer>>,
    ns: Namespace,
    sid: u32,
    open: proto::ReqOpen,
    mut rx: mpsc::Receiver<Frame>,
) -> anyhow::Result<()> {
    let mut blob: Vec<u8> = Vec::new();
    // 上行「后」：含帧头的实际传输；「前」= 解压后的 body 长度（在 `send_buffered` 里取）。
    let mut up_transport = 0u64;
    // 见 `forward_raw`：没发完不许当成发完了。
    // 这条路径上，截断的 zstd 帧多半会在解压时报错（DECOMPRESS_FAILED），
    // 但"多半"不是保证——多帧 zstd 流被从帧边界切断时是可以解出前缀的。
    let mut committed = false;
    while let Some(f) = rx.recv().await {
        match f.ty {
            FrameType::BodyChunk => {
                let last = f.flags.contains(flags::LAST);
                up_transport += (llm_proxy_core::frame::HEADER_LEN + f.payload.len()) as u64;
                blob.extend_from_slice(&f.payload);
                if blob.len() > MAX_ZSTD_BYTES {
                    return send_err(
                        &mux,
                        sid,
                        err_code::TOO_LARGE,
                        &format!("压缩帧超过 {MAX_ZSTD_BYTES} 字节"),
                        hint::RETRY_WITH_FULL,
                        Vec::new(),
                    )
                    .await
                    .map_err(Into::into);
                }
                if last {
                    committed = true;
                    break;
                }
            }
            FrameType::ReqCommit => {
                committed = true;
                break;
            }
            FrameType::Ping => {}
            _ => {}
        }
    }
    if !committed {
        return send_err(
            &mux,
            sid,
            err_code::LENGTH_MISMATCH,
            "压缩请求体未发完就断流",
            hint::RETRY_WITH_FULL,
            Vec::new(),
        )
        .await
        .map_err(Into::into);
    }

    let body = match app
        .compress
        .decompress(&blob, llm_proxy_core::config::MAX_DECOMPOSE_BYTES)
    {
        Ok(b) => b.to_vec(),
        Err(e) => {
            // 解压失败一律**拒绝**，绝不拿半个 body 去发上游（设计 §3.2 红线）。
            // 最常见的原因是字典不匹配，所以握手期已校验；这里兜住其余情况。
            tracing::warn!(stream_id = sid, %e, "解压失败，拒绝该请求");
            return send_err(
                &mux,
                sid,
                err_code::DECOMPRESS_FAILED,
                &format!("解压失败：{e}"),
                hint::RETRY_WITH_FULL,
                Vec::new(),
            )
            .await
            .map_err(Into::into);
        }
    };
    // 校验 target_fp：解压正确性由 zstd 校验和保证，这一步挡的是"客户端与服务端
    // 认知不一致"这类更高层的错配。与增量路径同一道红线。
    if !open.target_fp.is_empty() {
        let actual = body_fp(ns, &body);
        if actual.as_bytes().as_slice() != open.target_fp.as_slice() {
            tracing::error!(stream_id = sid, "target_fp 不符（压缩路径）");
            return send_err(
                &mux,
                sid,
                err_code::FP_MISMATCH,
                "解压结果与 target_fp 不符",
                hint::RETRY_WITH_FULL,
                Vec::new(),
            )
            .await
            .map_err(Into::into);
        }
    }

    // **切块入库**。这一步是关键：只省了冷启动那一笔流量还不够，必须让服务端同时
    // 拿到块，否则下一个请求仍然是冷的、又要整段重发一次。
    // CDC 是内容定义的，两端切出的块必然一致，客户端可以据此自行记账。
    let mut inserted = 0usize;
    {
        let mut store = app.blocks.lock().unwrap();
        let now = Instant::now();
        for chunk in llm_proxy_core::cdc::chunks(&body) {
            let fp = block_fp(ns, chunk);
            if store.insert_at(fp, chunk.to_vec(), now) {
                inserted += 1;
            }
        }
    }
    tracing::debug!(stream_id = sid, blocks = inserted, "压缩路径已切块入库");

    send_buffered(
        app,
        conn_caps,
        mux,
        _inducer,
        sid,
        open,
        up_transport,
        body,
        rx,
    )
    .await
}

/// 等客户端的取消信号。
///
/// # 为什么需要（README 缺口 8）
///
/// SDK 一断，客户端会丢掉那条 response future 并发来一帧 `FrameType::Cancel`。
/// 在这之前服务端**收不到任何信号**：它只在上游那里等着，于是按
/// `MAX_CONCURRENT_STREAMS` 占着的槽位再也不释放——上游一旦挂死，4 次放弃就足以
/// 让代理对该上游**永久不再服务**。
///
/// 两种返回都算"这条流不要了"：
///
/// * 收到 `Cancel`（客户端主动放弃）；
/// * `rx` 关闭（链路断了 ⇒ 客户端也拿不到结果 ⇒ 上游请求同样应当取消）。
///
/// `Ping` 照旧忽略；其它帧在"请求已提交"之后本就不该出现，忽略即可。
/// 等"这条流被客户端取消"的**显式通知**。
///
/// 与 [`wait_client_cancel`]（听那条流的帧通道）互补：实测后者依赖的
/// "路由 sender 被丢掉 ⇒ rx 关闭"这条链在缺口 8 场景里没有生效，所以会话循环
/// 取消由会话循环**从外部 abort 任务**实现（缺口 8 的最终修法）；本条只覆盖
/// "客户端把流解绑导致 rx 关闭"这种情形。
async fn wait_client_cancel(rx: &mut mpsc::Receiver<Frame>, sid: u32, diag: &Arc<Diag>) {
    while let Some(f) = rx.recv().await {
        match f.ty {
            FrameType::Cancel => {
                use std::sync::atomic::Ordering as O;
                diag.cancel_frames.fetch_add(1, O::Relaxed);
                tracing::debug!(stream_id = sid, "收到客户端取消，取消上游请求并释放槽位");
                return;
            }
            FrameType::Ping => {}
            _ => {}
        }
    }
    tracing::debug!(stream_id = sid, "客户端那条流已关闭，取消上游请求");
}

/// 把**已完整组装**的 body 发给上游并回传响应。
///
/// 增量重组与 zstd 解压之后都走这里：两者都必须先拿到完整 body 才能校验
/// （`target_fp` / 解压完整性），因此都不流式。
///
/// `rx` 是这条流自己的帧通道：请求提交之后还要用它听客户端的 `Cancel`（缺口 8）。
/// 参数因此到了 9 个——比把这一串"转发上下文"打包成结构体更直白，而且它只有两个调用点。
#[allow(clippy::too_many_arguments)]
async fn send_buffered(
    app: AppShared,
    conn_caps: Arc<ConnCaps>,
    mux: Mux,
    inducer: Arc<Mutex<llm_proxy_json::Inducer>>,
    sid: u32,
    open: proto::ReqOpen,
    up_transport: u64,
    body: Vec<u8>,
    mut rx: mpsc::Receiver<Frame>,
) -> anyhow::Result<()> {
    // 上行「前」= 重组出的请求体（增量/整段压缩路径重建后的**全量**）；
    // 「后」= 调用方在收帧时累加的实际传输字节（含帧头），这条路径上它**不等于** body.len()。
    let up = UpstreamBytes {
        body: body.len() as u64,
        transport: up_transport,
    };
    let (req, content_length) = build_request(&app.cfg, &open, Some(body.len()))?;
    if let Some(n) = content_length {
        if n != body.len() as u64 {
            return send_err(
                &mux,
                sid,
                err_code::LENGTH_MISMATCH,
                &format!("Content-Length 声明 {n}，重组结果 {} 字节", body.len()),
                hint::RETRY_WITH_FULL,
                Vec::new(),
            )
            .await
            .map_err(Into::into);
        }
    }

    // 完整 body 一次性喂入；capacity=8，单块必然进得去
    let (body_tx, chan) = ChannelBody::channel();
    let chan = chan.with_exact_size(body.len() as u64);
    let _ = body_tx.try_send(Ok(Bytes::from(body)));
    drop(body_tx);

    app.phases
        .lock()
        .unwrap()
        .insert(sid, "buffered:await-upstream".to_string());
    // **等上游，同时听客户端取消**：客户端一断就把上游请求 drop 掉，
    // 槽位随作用域释放（README 缺口 8）。
    let resp = tokio::select! {
        r = app.client.request(req.body(chan)?) => r.context("上游请求失败")?,
        _ = wait_client_cancel(&mut rx, sid, &app.diag) => {
            // 直接返回：上游 future 已被丢弃 ⇒ 上游连接取消；
            // 调用方的作用域结束时并发槽位随之释放。
            use std::sync::atomic::Ordering as O;
            app.diag.cancelled_streams.fetch_add(1, O::Relaxed);
            return Ok(());
        }
    };
    relay_response(
        &app,
        &conn_caps,
        &mux,
        &inducer,
        sid,
        open.req_id,
        &open.path_and_query,
        up,
        resp,
        // 客户端声明「我的表是空的」⇒ 本流引用到的模板定义要补发 ✓（第 195/197 轮 ✓）
        open.client_needs_defs,
    )
    .await
}

/// 组装上游请求。`reconstructed_len` 给出时以它为准设置 body 长度。
fn build_request(
    cfg: &Config,
    open: &proto::ReqOpen,
    reconstructed_len: Option<usize>,
) -> anyhow::Result<(http::request::Builder, Option<u64>)> {
    let url = cfg.upstream_url(&open.path_and_query);
    let mut builder = Request::builder().method(open.method.as_str()).uri(&url);
    let mut declared: Option<u64> = None;
    for h in &open.headers {
        if h.name.eq_ignore_ascii_case("content-length") {
            declared = std::str::from_utf8(&h.value)
                .ok()
                .and_then(|s| s.parse().ok());
        }
        let name = HeaderName::from_bytes(h.name.as_bytes())
            .with_context(|| format!("非法 header 名 {:?}", h.name))?;
        let value = HeaderValue::from_bytes(&h.value)
            .with_context(|| format!("非法 header 值 {:?}", h.name))?;
        builder = builder.header(name, value);
    }
    // 返回给调用方做**一致性校验**的长度，必须是**客户端声明的**那个，不能是重组长度。
    //
    // 这里曾经写成 `reconstructed_len.or(declared)`——顺序反了。上游路径传的是
    // `Some(body.len())`，于是返回值恒等于重组长度，调用方拿它和自己比，
    // 那条 `LENGTH_MISMATCH` 检查**永远不会触发**：一条写着"声明 N，重组 M"的报错
    // 却永远只会打印 N == M。是"写测试时才发现"的死检查（见 e2e-tests/errors.rs）。
    //
    // 顺序换过来不影响另一处调用：流式路径传 `None`，两种写法都等于 `declared`。
    let len = declared.or(reconstructed_len.map(|n| n as u64));
    Ok((builder, len))
}

/// 把上游响应原样回传。
///
/// 两条路径，按上游 `Content-Type` 分流：
///
/// * `text/event-stream` → [`relay_sse`]：切事件、归纳模板、**批量成帧**；
/// * 其余 → [`relay_raw`]：逐帧原样转发，不缓冲。
///
/// 两条路径都必须让客户端重组出**与上游逐字节相同**的 body——这是 §3.2 的红线。
#[allow(clippy::too_many_arguments)]
async fn relay_response(
    app: &App,
    conn_caps: &ConnCaps,
    mux: &Mux,
    inducer: &Arc<Mutex<llm_proxy_json::Inducer>>,
    sid: u32,
    req_id: u64,
    path: &str,
    up: UpstreamBytes,
    resp: Response<Incoming>,
    client_needs_defs: bool,
) -> anyhow::Result<()> {
    let status = resp.status();
    let headers: Vec<proto::Header> = resp
        .headers()
        .iter()
        .map(|(k, v)| proto::Header {
            name: k.as_str().to_string(),
            value: v.as_bytes().to_vec(),
        })
        .collect();
    let is_sse = wants_event_framing(&headers);

    // 这条流的**响应出口**（缺口 #2 的地基）：下游所有响应帧都经它发，并顺手记进环形缓冲 ✓。
    //
    // 为什么在这一层建：`relay_response` 同时拿得到 `app`（登记表）与 `mux`（当前会话）✓，
    // 于是**不必**把 sink 贯穿上面那一串 `forward*` 签名（那串改动面大、且与续传无关 ✗）。
    // ⚠️ 本轮语义**与接线前逐行为一致**：`send()` 仍把发送错误向上传播 ✓ ——
    // "断线期间 hold + 缓冲"要和 `RESUME`、客户端能力声明一起上（见 `RespSink::send` 的说明）✓。
    let sink = crate::resume::RespSink::new(mux.clone(), conn_caps.client_resume);
    app.rings
        .lock()
        .unwrap()
        .insert(sid, std::sync::Arc::clone(&sink));

    let head = proto::RespHead {
        status: status.as_u16() as u32,
        headers,
        req_id,
    };
    sink.send(Frame::new(
        FrameType::RespHead,
        sid,
        0,
        head.encode_to_vec(),
    ))
    .await?;

    let body = resp.into_body();
    let (seq, metrics) = if is_sse {
        relay_sse(app, conn_caps, &sink, inducer, sid, body, client_needs_defs).await?
    } else {
        relay_raw(&sink, sid, body).await?
    };

    let end = proto::RespEnd {
        req_id,
        usage: Vec::new(),
    };
    let mut f = Frame::new(FrameType::RespEnd, sid, seq, end.encode_to_vec());
    f.flags = Flags::default().with(flags::LAST);
    sink.send(f).await?;
    // 流已正常结束 ⇒ 从登记表摘掉（环随之释放 ✓；异常路径由 TTL 兜底 ✓）。
    app.rings.lock().unwrap().remove(&sid);
    use std::sync::atomic::Ordering as O;
    let protocol = protocol_stats(&app.traffic, path);
    let total_tokens = if metrics.total_tokens > 0 {
        metrics.total_tokens
    } else {
        metrics.input_tokens.saturating_add(metrics.output_tokens)
    };
    {
        // **四组一次加齐**：与 `responses` 同源累加，所以「四组 ÷ 响应数」就是平均值的对账口径。
        let _counters = app.traffic.counters.lock().unwrap();
        app.traffic.responses.fetch_add(1, O::Relaxed);
        app.traffic
            .request_body_bytes
            .fetch_add(up.body, O::Relaxed);
        app.traffic
            .request_transport_bytes
            .fetch_add(up.transport, O::Relaxed);
        app.traffic
            .response_body_bytes
            .fetch_add(metrics.source_bytes, O::Relaxed);
        app.traffic
            .response_transport_bytes
            .fetch_add(metrics.wire_bytes, O::Relaxed);
        app.traffic
            .input_tokens
            .fetch_add(metrics.input_tokens, O::Relaxed);
        app.traffic
            .output_tokens
            .fetch_add(metrics.output_tokens, O::Relaxed);
        // 输入缓存命中的三个原始分量（两种协议口径不同，比例留到 `stats_json` 里算）。
        app.traffic
            .cached_subset_tokens
            .fetch_add(metrics.cached_subset, O::Relaxed);
        app.traffic
            .cache_read_tokens
            .fetch_add(metrics.cache_read, O::Relaxed);
        app.traffic
            .cache_creation_tokens
            .fetch_add(metrics.cache_creation, O::Relaxed);
        // 命中率的**分子/分母只累加报了 cache 字段的响应**：不报的一律不参与
        // （否则一个不报 cache 的上游会把命中率无脑拉低）——它只被 `usage_reports` 记账，
        // 覆盖率 = `cache_reports / usage_reports`。
        if metrics.saw_cache {
            let denom = metrics
                .input_tokens
                .saturating_add(metrics.cache_read)
                .saturating_add(metrics.cache_creation);
            app.traffic.cache_input_tokens.fetch_add(denom, O::Relaxed);
            app.traffic.cache_reports.fetch_add(1, O::Relaxed);
            protocol.cache_input_tokens.fetch_add(denom, O::Relaxed);
            protocol.cache_reports.fetch_add(1, O::Relaxed);
        }
        protocol.requests.fetch_add(1, O::Relaxed);
        protocol
            .input_tokens
            .fetch_add(metrics.input_tokens, O::Relaxed);
        protocol
            .output_tokens
            .fetch_add(metrics.output_tokens, O::Relaxed);
        protocol
            .cached_subset_tokens
            .fetch_add(metrics.cached_subset, O::Relaxed);
        protocol
            .cache_read_tokens
            .fetch_add(metrics.cache_read, O::Relaxed);
        protocol
            .cache_creation_tokens
            .fetch_add(metrics.cache_creation, O::Relaxed);
        protocol.total_tokens.fetch_add(total_tokens, O::Relaxed);
        if total_tokens > 0 {
            app.traffic.usage_reports.fetch_add(1, O::Relaxed);
            protocol.usage_reports.fetch_add(1, O::Relaxed);
        }
    }
    let traffic = Arc::clone(&app.traffic);
    tokio::task::spawn_blocking(move || {
        if let Err(error) = traffic.save() {
            tracing::error!(?error, "统计持久化失败，内存计数保留");
        }
    })
    .await?;
    Ok(())
}

/// 这个响应该不该走「切事件 → 归纳模板 → 批量成帧」那条路？
///
/// # 为什么不能只看 `content-type`
///
/// 实测过 `text/event-stream` + `content-encoding: zstd` 这种响应（真实网关会压缩
/// 流式响应，不是凭空造的场景）。**当前实现是靠"碰巧"保持字节一致的**：
/// 压缩字节切不出事件，于是落进慢路径（流式 zstd），而那条路是无损往返，
/// 所以 SDK 最终拿到的字节没变。
///
/// 但这是**偶然**，不是设计：
///
/// * 一旦事件切分/模板归纳变得更宽容（例如接受任意二进制当一条事件），
///   同一份输入就会被**改写**——而这种错在字节比对之外很难被发现；
/// * 即使在当前实现里也**白花钱**：拿已经压缩过的数据再流式压缩一遍，
///   压缩率接近 1（甚至变大），CPU 全白费。
///
/// 所以这里显式排除任何非 identity 的 `content-encoding`：**已经编码的 body 是
/// 不透明的，代理只准原样搬**。`content-encoding` 可能是列表（`gzip, br`），
/// 只要有一个不是 identity 就整体按不透明处理。
#[cfg(test)]
/// 缺口 14 台账的**两侧**判据（都必须在，缺一边就等于没守 ✓）。
///
/// 用外层 `///` 而不是内层 `//!` ✓：`mod` 上同时出现外层属性与内层文档会触发
/// clippy 的 `mixed_attributes_style` ✗（第 109 轮实测 ✓）。
mod req_ledger_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn first_seen_is_admitted_and_the_second_is_rejected() {
        let l = ReqLedger::default();
        assert!(l.admit(1), "第一次必须放行");
        assert!(
            !l.admit(1),
            "第二次必须拒绝（否则会第二次调用上游 ⇒ 重复计费）"
        );
        assert!(
            l.admit(2),
            "**另一个 req_id 不受影响** —— 这条防的是「台账写坏成一律拒绝」"
        );
        assert_eq!(l.len(), 2);
    }

    #[test]
    fn entries_expire_after_the_ttl() {
        let l = ReqLedger::new(Duration::from_millis(30));
        assert!(l.admit(7));
        assert!(!l.admit(7), "ttl 内仍算重复");
        std::thread::sleep(Duration::from_millis(60));
        assert!(
            l.admit(7),
            "过期后必须重新放行（否则台账会永久封死一个 sid）"
        );
        assert_eq!(l.len(), 1, "过期条目应被顺手清掉，长度不随时间无限增长");
    }

    #[test]
    fn the_default_ttl_matches_the_cache_ttl() {
        // 设计：缓存有效期固定 6 小时 ✓ —— 台账的默认 ttl 跟着它 ✓。
        assert_eq!(ReqLedger::default().ttl, Duration::from_secs(6 * 3600));
    }
}

fn wants_event_framing(headers: &[proto::Header]) -> bool {
    let is_sse = headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("content-type")
            && h.value
                .windows(17)
                .any(|w| w.eq_ignore_ascii_case(b"text/event-stream"))
    });
    if !is_sse {
        return false;
    }
    let encoded = headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("content-encoding")
            && !h.value.eq_ignore_ascii_case(b"identity")
    });
    !encoded
}

/// 非 SSE：逐帧原样转发。**不缓冲**，保证不被代理引入额外延迟。
#[derive(Debug, Default)]
struct RelayMetrics {
    source_bytes: u64,
    wire_bytes: u64,
    input_tokens: u64,
    output_tokens: u64,
    total_tokens: u64,
    /// 输入缓存命中的**原始分量**（口径差异见 [`UsageScanner`]）。
    cached_subset: u64,
    cache_read: u64,
    cache_creation: u64,
    /// 这个响应报没报 cache 字段（决定它**是否参与**命中率，见 [`UsageScanner::saw_cache`]）。
    saw_cache: bool,
}

/// usage 尾部窗口。usage 总在流的末尾附近，而畸形流不能把内存吃光。
const USAGE_WINDOW: usize = 8192;

#[derive(Default)]
struct UsageScanner {
    tail: Vec<u8>,
    input_tokens: u64,
    output_tokens: u64,
    total_tokens: u64,
    /// OpenAI 口径：`prompt_tokens_details.cached_tokens`，**是 `prompt_tokens` 的子集**。
    cached_subset: u64,
    /// Anthropic 口径：`cache_read_input_tokens`，**不计入** `input_tokens`。
    cache_read: u64,
    /// Anthropic 口径：`cache_creation_input_tokens`，同样不计入 `input_tokens`，且**没命中**。
    cache_creation: u64,
    /// 这个响应**报没报** cache 字段（**`null` 不算报，`0` 算报**）。
    ///
    /// 判据必须是"字段在不在"，**不是**"值是不是 > 0"：
    ///
    /// * `"prompt_tokens_details": null`（真实网关在不带缓存统计时就是这个形状）⇒ **没报**
    ///   ⇒ 这个响应**不许进命中率**，否则它的输入量会白白把命中率拉低；
    /// * `"cached_tokens": 0` ⇒ **报了**，是一条真实的 0 命中样本，不能丢。
    ///
    /// 实现上两者天然分得开：`find_number` 要求键后面**真有数字**，
    /// `null` / 缺字段都读不出数，`0` 读得出。
    saw_cache: bool,
}

impl UsageScanner {
    fn feed(&mut self, bytes: &[u8]) {
        self.tail.extend_from_slice(bytes);
        if self.tail.len() > USAGE_WINDOW {
            let keep = self.tail.split_off(self.tail.len() - USAGE_WINDOW);
            self.tail = keep;
        }
        for key in [b"input_tokens".as_slice(), b"prompt_tokens", b"inputTokens"] {
            if let Some(v) = find_number(&self.tail, key) {
                self.input_tokens = self.input_tokens.max(v);
            }
        }
        for key in [
            b"output_tokens".as_slice(),
            b"completion_tokens",
            b"outputTokens",
        ] {
            if let Some(v) = find_number(&self.tail, key) {
                self.output_tokens = self.output_tokens.max(v);
            }
        }
        if let Some(v) = find_number(&self.tail, b"total_tokens") {
            self.total_tokens = self.total_tokens.max(v);
        }
        // 输入缓存命中——**从响应里拿**，两种口径都认，因为它们的**分母不同**：
        // OpenAI 的 `cached_tokens` ⊆ `prompt_tokens`；Anthropic 的 `cache_read_input_tokens`
        // 与 `cache_creation_input_tokens` 都**不在** `input_tokens` 里。
        // 所以这里只存原始分量，把口径差异留到最后算比例（见 `stats_json`），
        // 否则两种协议里必有一种算错。
        //
        // 顺带一提：`cache_read_input_tokens` / `cache_creation_input_tokens` 里都含有
        // `input_tokens` 这个**后缀** —— 上面那条 `input_tokens` 的左右边界判断正是为此，
        // 没有它这里会把缓存读入误记成输入 token（`find_number` 的文档第 1 条）。
        if let Some(v) = find_number(&self.tail, b"cached_tokens") {
            self.cached_subset = self.cached_subset.max(v);
            self.saw_cache = true;
        }
        if let Some(v) = find_number(&self.tail, b"cache_read_input_tokens") {
            self.cache_read = self.cache_read.max(v);
            self.saw_cache = true;
        }
        if let Some(v) = find_number(&self.tail, b"cache_creation_input_tokens") {
            self.cache_creation = self.cache_creation.max(v);
            self.saw_cache = true;
        }
    }
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// 在 `buf` 里找 `key: <数字>`。
///
/// 三条严格性，每条都对应一种**会静默记错数字**的形态：
///
/// 1. **键必须完整**：`prompt_tokens_details`（真实网关会给的字段）里含有 `prompt_tokens`
///    这个前缀。若不加左右边界判断，第一个"假命中"后面跟着 `_` ⇒ 解析失败 ⇒ 整次查找
///    直接放弃 ⇒ **真正的 `prompt_tokens` 明明在后面却被无视**。
/// 2. **数字必须完整**：窗口是从流中间切出来的，`197298` 可能只剩 `298`。解析出 `298`
///    比解析失败更糟——它会安静地进统计。所以"数字贴到缓冲区末尾、后面还没到"时**这轮不认**，
///    等下一轮补齐（窗口有 8 KiB，够等到）。
/// 3. 命中多处时**取最大值**：流式用量是分多次上报的——Anthropic 的 `message_start`
///    先给 `output_tokens=1`，`message_delta` 才给真正的 16。只看第一个命中就会记成 1
///    （这条是测试当场抓出来的）。
fn find_number(buf: &[u8], key: &[u8]) -> Option<u64> {
    let mut best: Option<u64> = None;
    let mut from = 0usize;
    // 用 `memchr::memmem`（SIMD）找候选位置 ✓ —— 语义与原来的
    // `buf[from..].windows(key.len()).position(|w| w == key)` **逐字相同** ✓：
    // 同样从 `from` 起找、同样 `from = at + 1`（允许重叠 ✓）、同样逐个做左右边界判断 ✓。
    //
    // 为什么必须换：第 187 轮在生产机上做**受控复现**（1200 事件 / 180 KB 流式响应 ✓），
    // perf 显示 **90% 的 CPU 全在字节比较上** ✗ ——
    // `memcmp` 36% + `SlicePartialEq::equal_same_length` 28% + `[u8]::eq` 6% + `bcmp` 5%
    // + 本函数自身 15% ✓。原因就是朴素扫描每个位置都要 `memcmp(key.len())`，
    // 而 `feed()` 每来一个分片就把整个 8 KiB 窗口 × 10 个键**重扫一遍** ✗✗
    // ⇒ 1200 个分片 ≈ 上亿次字节比较 ✓。换 SIMD 后同一条流的热点消失 ✓（实测见提交说明）。
    let finder = memchr::memmem::Finder::new(key);
    while let Some(pos) = finder.find(&buf[from..]) {
        let at = from + pos;
        from = at + 1;
        let left_ok = at == 0 || !is_ident(buf[at - 1]);
        let right_ok = buf
            .get(at + key.len())
            .map(|b| !is_ident(*b))
            .unwrap_or(true);
        if !(left_ok && right_ok) {
            continue;
        }
        let mut i = at + key.len();
        // **必须包含 `"`**：JSON 里键是带引号的，`"prompt_tokens":31` 在键与冒号之间
        // 有一个引号。少了它，本函数对**所有**合法 JSON 都返回 None——token 统计
        // 因此长期恒为 0（实测：74 个响应、input/output/usage 全是 0）。
        while i < buf.len() && matches!(buf[i], b' ' | b'\t' | b'\r' | b'\n' | b':' | b'"') {
            i += 1;
        }
        let begin = i;
        while i < buf.len() && buf[i].is_ascii_digit() {
            i += 1;
        }
        if i == begin {
            continue;
        }
        if i == buf.len() {
            // 数字可能被窗口切断了：宁可下轮再认，也不认成截断值（见文档第 2 条）。
            continue;
        }
        if let Ok(digits) = std::str::from_utf8(&buf[begin..i]) {
            if let Ok(v) = digits.parse::<u64>() {
                best = Some(best.map_or(v, |b| b.max(v)));
            }
        }
    }
    best
}

/// usage 扫描器的测试。**样本全部照抄真实网关吐出来的字节**（不是自己编的 JSON）：
/// 这些写法是从线上 new-api 的响应/log 里抓的，OpenAI 与 Anthropic 两种协议、
/// 流式与非流式都覆盖到。
#[cfg(test)]
mod usage_scanner_tests {
    use super::UsageScanner;

    fn scan(chunks: &[&[u8]]) -> (u64, u64, u64) {
        let mut s = UsageScanner::default();
        for c in chunks {
            s.feed(c);
        }
        (s.input_tokens, s.output_tokens, s.total_tokens)
    }

    /// OpenAI 非流式（真实样本：`prompt_tokens_details` 与 `completion_tokens_details` 都在）。
    #[test]
    fn openai_non_stream_shape_is_counted() {
        let body = br#"{"id":"chatcmpl-1","usage":{"prompt_tokens":31,"total_tokens":47,"completion_tokens":16,"prompt_tokens_details":null,"completion_tokens_details":{"reasoning_tokens":16}}}"#;
        assert_eq!(scan(&[body.as_slice()]), (31, 16, 47));
    }

    /// OpenAI **流式**最后一帧（真实样本：`prompt_tokens=197298` 量级的长上下文）。
    #[test]
    fn openai_stream_final_chunk_is_counted() {
        let chunk = br#"data: {"id":"chatcmpl-2","choices":[],"usage":{"prompt_tokens":197298,"completion_tokens":429,"total_tokens":197727}}

data: [DONE]

"#;
        assert_eq!(scan(&[chunk.as_slice()]), (197298, 429, 197727));
    }

    /// Anthropic：`message_start` 给 input，`message_delta` 给 output ⇒ 取各自最大值。
    #[test]
    fn anthropic_start_and_delta_are_merged() {
        let start = br#"event: message_start
data: {"type":"message_start","message":{"usage":{"input_tokens":1241,"cache_creation_input_tokens":0,"cache_read_input_tokens":188,"output_tokens":1}}}

"#;
        let delta = br#"event: message_delta
data: {"type":"message_delta","usage":{"output_tokens":16}}

"#;
        assert_eq!(scan(&[start.as_slice(), delta.as_slice()]), (1241, 16, 0));
    }

    /// 真实网关的"双份用量"形态：`billing_usage.claude_usage` 与顶层字段同时存在，
    /// 顶层 `output_tokens` 还是 0 ⇒ 取最大值才能拿到 16。
    #[test]
    fn nested_billing_usage_is_not_lost() {
        let body = br#"{"usage":{"prompt_tokens":1429,"completion_tokens":16,"total_tokens":1445,"billing_usage":{"claude_usage":{"input_tokens":1241,"cache_read_input_tokens":188,"output_tokens":16}},"input_tokens":1429,"output_tokens":0}}"#;
        assert_eq!(scan(&[body.as_slice()]), (1429, 16, 1445));
    }

    /// **假键诱导**：`prompt_tokens_details` 里含 `prompt_tokens` 这个前缀。
    /// 修前这里会返回 0（第一个命中不合格就整体放弃，真正的键在后面被无视）。
    #[test]
    fn a_longer_key_before_the_real_one_does_not_short_circuit() {
        let body = br#"{"usage":{"prompt_tokens_details":{"cached_tokens":188},"prompt_tokens":1429,"completion_tokens_details":null,"completion_tokens":16}}"#;
        assert_eq!(scan(&[body.as_slice()]), (1429, 16, 0));
    }

    /// **窗口切断数字**：`197298` 只剩 `197` 时宁可这轮不认——
    /// 认成 197 就是"数字不对"，而且它不会让任何东西变红。
    #[test]
    fn a_number_cut_by_the_window_is_not_parsed_as_truncated() {
        let filler = vec![b'x'; 8192];
        let head = br#""output_tokens":197"#;
        let tail = b"298}\n";
        let mut s = UsageScanner::default();
        s.feed(&filler);
        s.feed(head);
        assert_eq!(s.output_tokens, 0, "被切断的数字不许当成截断值");
        s.feed(tail);
        assert_eq!(s.output_tokens, 197298, "补齐后必须认出来");
    }

    /// **OpenAI 口径**：`prompt_tokens_details.cached_tokens` 是 `prompt_tokens` 的**子集**。
    #[test]
    fn openai_cached_tokens_is_read_from_the_response() {
        let body = br#"{"id":"chatcmpl-3","usage":{"prompt_tokens":2000,"completion_tokens":50,"total_tokens":2050,"prompt_tokens_details":{"cached_tokens":1888,"audio_tokens":0}}}"#;
        let mut s = UsageScanner::default();
        s.feed(body);
        assert_eq!(s.cached_subset, 1888, "命中数必须从响应里读出来");
        assert_eq!(s.input_tokens, 2000);
        assert_eq!(s.cache_read, 0, "OpenAI 没有这个字段，不许凭空造");
        assert!(s.saw_cache, "报了 cache ⇒ 参与命中率统计");
    }

    /// **Anthropic 口径**：`cache_read_input_tokens` **不在** `input_tokens` 里，
    /// 而且它的名字里含 `input_tokens` 这个**后缀** —— 绝不能把它当成输入 token
    /// （`find_number` 的左右边界判断就是为此）。
    #[test]
    fn anthropic_cache_read_is_not_mistaken_for_input_tokens() {
        let body = br#"{"type":"message_start","message":{"usage":{"input_tokens":1241,"cache_creation_input_tokens":7,"cache_read_input_tokens":188,"output_tokens":1}}}"#;
        let mut s = UsageScanner::default();
        s.feed(body);
        assert_eq!(s.input_tokens, 1241, "缓存读入不得混进 input_tokens");
        assert_eq!(s.cache_read, 188);
        assert_eq!(s.cache_creation, 7);
        assert!(s.saw_cache);
    }

    /// **全 miss 也要算"报了"**：`cached_tokens: 0` 是一条真实的 0 命中样本，
    /// 不能因为值是 0 就当成"没报"——那等于把一次真实的 miss 从样本里删掉。
    #[test]
    fn a_zero_cached_tokens_still_counts_as_reported() {
        let body = br#"{"usage":{"prompt_tokens":900,"completion_tokens":10,"total_tokens":910,"prompt_tokens_details":{"cached_tokens":0}}}"#;
        let mut s = UsageScanner::default();
        s.feed(body);
        assert_eq!(s.cached_subset, 0);
        assert!(s.saw_cache, "值是 0 也是报了");
    }

    /// 完全没报 cache 字段的响应：**不得进入命中率的样本**。
    ///
    /// 用的是**真实形状**：网关不带缓存统计时给的就是 `"prompt_tokens_details": null`
    /// 与 `"completion_tokens_details": null`（线上响应里抓到的原样）。
    #[test]
    fn a_response_without_cache_fields_is_marked_unreported() {
        let body = br#"{"id":"chatcmpl-4","usage":{"prompt_tokens":3000,"completion_tokens":20,"total_tokens":3020,"prompt_tokens_details":null,"completion_tokens_details":null}}"#;
        let mut s = UsageScanner::default();
        s.feed(body);
        assert_eq!(s.input_tokens, 3000);
        assert!(!s.saw_cache, "null / 缺字段 ⇒ 不许参与命中率");
        assert_eq!(s.cached_subset, 0);
    }
}

async fn relay_raw(
    sink: &crate::resume::RespSink,
    sid: u32,
    body: Incoming,
) -> anyhow::Result<(u32, RelayMetrics)> {
    let mut seq = 1u32;
    let mut body = body;
    let mut metrics = RelayMetrics::default();
    let mut usage = UsageScanner::default();
    while let Some(frame) = http_body_util::BodyExt::frame(&mut body).await {
        let frame = frame.context("上游响应体错误")?;
        if let Ok(data) = frame.into_data() {
            if data.is_empty() {
                continue;
            }
            metrics.source_bytes += data.len() as u64;
            metrics.wire_bytes += data.len() as u64;
            usage.feed(&data);
            sink.send(Frame::new(FrameType::RespData, sid, seq, data.to_vec()))
                .await?;
            seq += 1;
        }
    }
    metrics.input_tokens = usage.input_tokens;
    metrics.output_tokens = usage.output_tokens;
    metrics.total_tokens = usage.total_tokens;
    metrics.cached_subset = usage.cached_subset;
    metrics.cache_read = usage.cache_read;
    metrics.cache_creation = usage.cache_creation;
    metrics.saw_cache = usage.saw_cache;
    Ok((seq, metrics))
}

/// SSE 累计缓冲上限。畸形流（永远等不到空行）不能把内存吃光。
const MAX_SSE_ACC: usize = 1 << 20;

/// 压缩帧的线上上限。压缩率再好也不会超过原文，给 2 倍余量足够，同时挡住畸形流。
const MAX_ZSTD_BYTES: usize = 2 * llm_proxy_core::config::MAX_DECOMPOSE_BYTES;

#[derive(Default)]
struct SseStats {
    /// 是否走了慢路径（流式 zstd）。用于观测与验收。
    slow_path: bool,
    events: u64,
    /// 原样发送的事件数（无法归纳或首次出现）。
    raw: u64,
    /// 归纳出新模板的次数。
    defined: u64,
    delta: u64,
    /// 原文字节数与实际下发字节数，用于观测归纳效果。
    src_bytes: u64,
    wire_bytes: u64,
    batch_frames: u64,
}

/// SSE 路径：切事件 → 归纳 → 批量成帧。
///
/// 用「泵 + select(窗口 tick)」而不是在 body 上直接 `timeout`：`timeout` 需要取消
/// 一个正在 poll 的 body future，而 hyper 并未承诺该操作可取消。泵进通道则明确安全。
async fn relay_sse(
    app: &App,
    conn_caps: &ConnCaps,
    sink: &crate::resume::RespSink,
    inducer: &Arc<Mutex<llm_proxy_json::Inducer>>,
    sid: u32,
    body: Incoming,
    client_needs_defs: bool,
) -> anyhow::Result<(u32, RelayMetrics)> {
    let (tx, mut rx) = mpsc::channel::<Result<Bytes, hyper::Error>>(8);
    tokio::spawn(async move {
        let mut body = body;
        while let Some(f) = http_body_util::BodyExt::frame(&mut body).await {
            match f {
                Ok(f) => {
                    if let Ok(d) = f.into_data() {
                        if !d.is_empty() && tx.send(Ok(d)).await.is_err() {
                            return;
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            }
        }
    });

    let mut buf: Vec<u8> = Vec::new();
    let mut pending: Vec<llm_proxy_core::batch::BatchItem> = Vec::new();
    // **本响应已发过 def 的模板 id** ✓（第 195 轮修 `terminated` 的根因 ✓，见 `drain_events` ✓）。
    //
    // 判据在第 196 轮修正过 ✓：原来是"客户端声明表为空" ⇒ 留空集合 ⇒ 全补发 ✓；
    // 表非空 ⇒ 预填**全部** ⇒ 一个都不补 ✓。**那个判据是错的** ✗ ——
    // 同一连接跑久了，服务端 id 空间**跨响应累加** ✓，客户端表**非空却未必含有较新的 id** ✓
    // ⇒ 声明"非空"就跳过了补发 ✓ ⇒ 照样 `UnknownTemplate` ✓
    // （现场：客户端表有 24 个模板，却引用了 id 52 与 104 ✓）。
    //
    // 第 196 轮试过"报**已知最大 id**"✗ **不够** ✓：现场又抓到表**中间有洞**
    // （有 id 35 ✓ 却缺 54 ✓）⇒ 一个数字表达不了洞在哪里 ✗。
    //
    // ⇒ 第 197 轮改为**客户端自愈** ✓：它一旦遇到不认识的 id 就**清空整张表** ✓
    // ⇒ 下一条流的 `client_needs_defs` 就是 true ✓ ⇒ 这里全量补发 ✓ ⇒ 闭环 ✓。
    let mut defs_sent: std::collections::HashSet<u32> = if client_needs_defs {
        std::collections::HashSet::new()
    } else {
        inducer.lock().unwrap().template_ids().into_iter().collect()
    };
    let mut stats = SseStats::default();
    let mut usage = UsageScanner::default();
    let mut seq = 1u32;

    let window = Duration::from_millis(app.cfg.sse_batch_ms.max(1));
    // 「前导沿 + 尾部批量」：刚静默满一个窗口时，第一个到达的事件**立刻下发**，
    // 以保住首字节时间；此后累积到窗口边界再批量下发。
    //
    // 没有前导沿，短响应会被整段缓冲到流结束才发出——实测 9 个事件的 SSE 会退化成
    // **单个分片**，流式体验完全消失。初值取 `now - window`，使连接建立后的
    // 第一个事件走前导沿。
    let mut last_flush = tokio::time::Instant::now() - window;

    // 慢路径状态（设计 §6.3）。**只在客户端声明 `stream-zstd` 时才启用**——
    // 这是一套新的线上格式，对端不认就会把响应解坏（不是"少省一点"，是"内容错"）。
    let slow_supported = conn_caps.client_stream_zstd;
    let mut slow: Option<SlowState> = None;
    let slow_window = Duration::from_millis(app.cfg.slow_flush_ms.max(1));
    let mut slow_last = tokio::time::Instant::now();
    let boot = llm_proxy_core::dict::Dicts::bootstrap();
    let sse_dict = boot.sse;

    // **两个定时器在循环外建一次** ✓ —— 不要每轮新建 ✗✗。
    //
    // 第 188 轮在生产机复现（慢速上游 20 ms/事件 ⇒ 1200 事件）后符号化，热点**不是**任何算法函数，
    // 而是"每分片的基础设施开销" ✓：`tokio::time::Inner::lock` 4.0% + `Sleep::poll` 2.3%
    // + `AtomicWaker::register_by_ref` 2.7% + 内核调度/自旋 ~20% ✓。
    // 原因就是原来这版把 `sleep_until(...)` **写在 `select!` 分支里** ✗ ⇒ 上游每来一个事件，
    // tokio 就要**注册两套定时器条目 + 两套唤醒器、再注销** ✓✓（上游慢 ⇒ 唤醒次数 = 事件数 ✓）。
    //
    // 改成复用同一个 `Sleep`（tokio 的 `Sleep` 可重复 `reset` ✓、是 cancel-safe ✓）
    // 并且**只在它自己触发时重排** ✓ ⇒ recv 分支里**零定时器操作** ✓。
    // 定时器按 `last_flush`/`slow_last` 懒对齐 ⇒ 若窗口因别的分支前移，它可能**早到一拍**，
    // 那一拍只是空转一次（下面两个分支都对空缓冲做了空操作）✓，**不会早发或晚发内容** ✓。
    // ⚠️ **慢路径定时器在启用前必须占一个"远期"时刻** ✗✗ —— 第 188 轮我在这里踩了一个自旋坑：
    // 初版写的是 `sleep_until(slow_last + slow_window)` ✓，而快路径（`slow == None`，绝大多数流 ✓）
    // **从不更新 `slow_last`** ✗ ⇒ 每次 `reset` 都把截止点设在**过去** ⇒ 这个分支**每轮都立刻就绪**
    // ⇒ `select!` 空转 ✓✓（现场判据：空闲 10 秒烧了 **276 jiffies = 单核 27.6%** ✗，
    // 而此前几版空闲时是 0 ✓；profile 里也正好是 `AtomicWaker::register_by_ref` 12.8% 那一族 ✓）。
    // 后果不只是烧 CPU ✗：2 个 worker 被空转占满 ⇒ 别的流的收发被拖延 ⇒ 客户端超时 ⇒ **`terminated`** ✗✗。
    // ⇒ 未启用时给一个**远期**截止点（一小时 ✓），真正转入慢路径那一瞬再 `reset` 一次（见触发处 ✓）。
    let far = tokio::time::Instant::now() + Duration::from_secs(3600);
    let mut batch_timer = Box::pin(tokio::time::sleep_until(last_flush + window));
    let mut slow_timer = Box::pin(tokio::time::sleep_until(far));

    loop {
        tokio::select! {
            got = rx.recv() => match got {
                None => break,
                Some(Err(e)) => return Err(anyhow::anyhow!("上游响应体错误：{e}")),
                Some(Ok(d)) => {
                    usage.feed(&d);
                    buf.extend_from_slice(&d);
                    drain_events(sink, sid, inducer, &mut defs_sent, &mut buf, &mut pending, &mut stats).await?;
                    let now = tokio::time::Instant::now();

                    // 慢路径判定：喂了足够多事件却一个模板都没归纳出来，
                    // 说明这批响应不适合模板化。此时改用流式 zstd，而不是继续按原样透传。
                    // **一旦转入就保持**（sticky）：这条响应已经证明了自己的形态不合适，
                    // 再切回去只会在两者之间反复横跳。
                    if slow.is_none()
                        && slow_supported
                        && app.cfg.enable_slow_path
                        && stats.defined == 0
                        && stats.delta == 0
                        && stats.raw >= SLOW_TRIGGER
                    {
                        tracing::debug!(
                            stream_id = sid,
                            raw = stats.raw,
                            "模板未命中，转入慢路径（流式 zstd）"
                        );
                        slow = Some(SlowState::new(sse_dict)?);
                        stats.slow_path = true;
                        // 转入慢路径的这一瞬，把它的定时器**对齐到当前时刻** ✓（此前它在远期占位 ✓）。
                        slow_last = now;
                        slow_timer.as_mut().reset(slow_last + slow_window);
                    }

                    if let Some(s) = slow.as_mut() {
                        // 此前累积的原样项（判定条件保证这段时间里全是原样项）转入压缩缓冲
                        for item in pending.drain(..) {
                            s.buf.extend_from_slice(&item.raw);
                        }
                        if !s.buf.is_empty()
                            && (s.buf.len() >= app.cfg.slow_flush_bytes.max(1)
                                || now.duration_since(slow_last) >= slow_window)
                        {
                            seq = flush_slow(sink, sid, s, seq, &mut stats).await?;
                            slow_last = now;
                        }
                    } else if pending.len() >= app.cfg.sse_batch_max {
                        seq = flush_batch(sink, sid, &mut pending, seq).await?;
                        stats.batch_frames += 1;
                        last_flush = now;
                    } else if pending.len() == 1 && now.duration_since(last_flush) >= window {
                        // 前导沿：静默已满一个窗口，先把这个事件发出去
                        seq = flush_batch(sink, sid, &mut pending, seq).await?;
                        stats.batch_frames += 1;
                        last_flush = now;
                    }
                    // 畸形流保护：等不到事件边界时按原样下发，而不是无限缓冲
                    if buf.len() > MAX_SSE_ACC && pending.is_empty() {
                        stats.src_bytes += buf.len() as u64;
                        pending.push(raw_item(std::mem::take(&mut buf)));
                    }
                }
            },
            _ = &mut batch_timer => {
                // 这一拍只负责**快路径**的批量帧。
                //
                // 慢路径**不再**跟着这一拍走：那一版是无条件 flush，于是
                // `--slow-flush-ms` 完全不决定延迟上界——实测（`slow_flush_knobs_*`）
                // 100ms / 900ms / 只留字节阈值三档，慢路径的第 2 个分片都在 ~0.15s，
                // 也就是这一拍（`sse_batch_ms`）。两个开关当时形同装饰品。
                if slow.is_none() && !pending.is_empty() {
                    seq = flush_batch(sink, sid, &mut pending, seq).await?;
                    stats.batch_frames += 1;
                }
                last_flush = tokio::time::Instant::now();
                // **只在这里重排** ✓（见循环外的说明：recv 分支里零定时器操作 ✓）。
                batch_timer.as_mut().reset(last_flush + window);
            }
            // 慢路径**自己的**定时拍：延迟上界就是 `--slow-flush-ms`（设计 §6.3）。
            _ = &mut slow_timer => {
                if let Some(s) = slow.as_mut() {
                    if !s.buf.is_empty() {
                        seq = flush_slow(sink, sid, s, seq, &mut stats).await?;
                    }
                    slow_last = tokio::time::Instant::now();
                }
                // 同样**只在这里重排** ✓（recv 分支里零定时器操作 ✓）。
                slow_timer.as_mut().reset(slow_last + slow_window);
            }
        }
    }

    // 尾部残留（可能是被上游截断的半截事件）必须原样发出，
    // 否则客户端重组出的 body 会比上游短，破坏逐字节一致。
    if !buf.is_empty() {
        stats.src_bytes += buf.len() as u64;
        stats.wire_bytes += buf.len() as u64;
        pending.push(raw_item(std::mem::take(&mut buf)));
    }
    if let Some(s) = slow.as_mut() {
        for item in pending.drain(..) {
            s.buf.extend_from_slice(&item.raw);
        }
        seq = flush_slow(sink, sid, s, seq, &mut stats).await?;
        // 收尾：把两条流都正常结束，客户端才能确认收到完整内容
        for (seg, using_dict) in s.finish()? {
            let mut f = Frame::new(FrameType::RespData, sid, seq, seg.clone());
            f.flags = Flags(
                f.flags.0
                    | if using_dict {
                        flags::STREAM_ZSTD
                    } else {
                        flags::STREAM_ZSTD_NODICT
                    },
            );
            stats.wire_bytes += seg.len() as u64;
            stats.batch_frames += 1;
            sink.send(f).await?;
            seq += 1;
        }
    } else if !pending.is_empty() {
        seq = flush_batch(sink, sid, &mut pending, seq).await?;
        stats.batch_frames += 1;
    }

    let n_templates = inducer.lock().unwrap().template_count();
    tracing::debug!(
        stream_id = sid,
        events = stats.events,
        raw = stats.raw,
        delta = stats.delta,
        templates = n_templates,
        src = stats.src_bytes,
        wire = stats.wire_bytes,
        frames = stats.batch_frames,
        ratio = format!(
            "{:.4}",
            if stats.src_bytes > 0 {
                stats.wire_bytes as f64 / stats.src_bytes as f64
            } else {
                1.0
            }
        ),
        "SSE 归纳完成"
    );
    Ok((
        seq,
        RelayMetrics {
            source_bytes: stats.src_bytes,
            wire_bytes: stats.wire_bytes,
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            total_tokens: usage.total_tokens,
            cached_subset: usage.cached_subset,
            cache_read: usage.cache_read,
            cache_creation: usage.cache_creation,
            saw_cache: usage.saw_cache,
        },
    ))
}

// 慢路径（设计 §6.3）：模板未命中时改用流式 zstd，见下方 SlowState。

/// 喂入多少个事件仍归纳不出模板，就判定"这批响应不适合模板化"。
const SLOW_TRIGGER: u64 = 6;

/// 字典的**使用跨度**上限。
///
/// 实测（`llm_proxy_core::stream_zstd` 的 `dict_gain_depends_on_content_diversity`）：
/// `dict_sse` 只在短流上占优，约 4KB 处与"不用字典"交叉——
///
/// ```text
///  ~400B  46.50% → 30.25%（字典好）
/// ~1600B  26.94% → 21.88%（字典好）
/// ~3200B  19.97% → 19.41%（持平）
/// ~6400B  14.80% → 16.92%（字典差）
/// ~12800B 11.49% → 15.61%（字典差）
/// ```
///
/// 所以既不能全程用字典、也不能全程不用：**跨过交叉点就换一条无字典流**。
/// 客户端凭 `flags::STREAM_ZSTD_NODICT` 知道该换解压器。
const DICT_SPAN_LIMIT: usize = 4096;

/// 慢路径的压缩状态。维护两条流（带字典 / 不带字典），按跨度上限切换。
struct SlowState {
    dict_c: llm_proxy_core::stream_zstd::StreamCompressor,
    plain_c: llm_proxy_core::stream_zstd::StreamCompressor,
    using_dict: bool,
    dict_span: usize,
    plain_used: bool,
    buf: Vec<u8>,
}

impl SlowState {
    fn new(dict: &[u8]) -> anyhow::Result<Self> {
        Ok(Self {
            dict_c: llm_proxy_core::stream_zstd::StreamCompressor::new(dict)
                .map_err(|e| anyhow::anyhow!("慢路径压缩器初始化失败：{e}"))?,
            plain_c: llm_proxy_core::stream_zstd::StreamCompressor::new(&[])
                .map_err(|e| anyhow::anyhow!("慢路径压缩器初始化失败：{e}"))?,
            using_dict: true,
            dict_span: 0,
            plain_used: false,
            buf: Vec::new(),
        })
    }

    /// 压入原文，返回 `(压缩段, 是否带字典)` 的列表。
    /// 跨越交叉点时会返回**两段**：先把字典流收尾，再另起无字典流。
    fn compress(&mut self, raw: &[u8]) -> anyhow::Result<Vec<(Vec<u8>, bool)>> {
        let mut out = Vec::new();
        let mut rest = raw;
        while !rest.is_empty() {
            if self.using_dict && self.dict_span >= DICT_SPAN_LIMIT {
                let tail = self
                    .dict_c
                    .finish()
                    .map_err(|e| anyhow::anyhow!("慢路径收尾失败：{e}"))?;
                if !tail.is_empty() {
                    out.push((tail, true));
                }
                self.using_dict = false;
            }
            let take = if self.using_dict {
                (DICT_SPAN_LIMIT - self.dict_span).min(rest.len())
            } else {
                rest.len()
            };
            let (chunk, tail) = rest.split_at(take);
            let seg = if self.using_dict {
                self.dict_span += chunk.len();
                self.dict_c.push(chunk)
            } else {
                self.plain_used = true;
                self.plain_c.push(chunk)
            }
            .map_err(|e| anyhow::anyhow!("慢路径压缩失败：{e}"))?;
            if !seg.is_empty() {
                out.push((seg, self.using_dict));
            }
            rest = tail;
        }
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<(Vec<u8>, bool)>> {
        let mut out = Vec::new();
        if self.using_dict {
            let t = self
                .dict_c
                .finish()
                .map_err(|e| anyhow::anyhow!("慢路径收尾失败：{e}"))?;
            if !t.is_empty() {
                out.push((t, true));
            }
            self.using_dict = false;
        }
        // 没喂过内容就不要产生一个空帧
        if self.plain_used {
            let t = self
                .plain_c
                .finish()
                .map_err(|e| anyhow::anyhow!("慢路径收尾失败：{e}"))?;
            if !t.is_empty() {
                out.push((t, false));
            }
        }
        Ok(out)
    }
}

/// 把慢路径缓冲里的原文压成若干段并下发。
async fn flush_slow(
    sink: &crate::resume::RespSink,
    sid: u32,
    slow: &mut SlowState,
    seq: u32,
    stats: &mut SseStats,
) -> anyhow::Result<u32> {
    if slow.buf.is_empty() {
        return Ok(seq);
    }
    let raw = std::mem::take(&mut slow.buf);
    stats.src_bytes += raw.len() as u64;
    let mut seq = seq;
    for (seg, using_dict) in slow.compress(&raw)? {
        let mut f = Frame::new(FrameType::RespData, sid, seq, seg.clone());
        f.flags = Flags(
            f.flags.0
                | if using_dict {
                    flags::STREAM_ZSTD
                } else {
                    flags::STREAM_ZSTD_NODICT
                },
        );
        stats.wire_bytes += seg.len() as u64;
        stats.batch_frames += 1;
        sink.send(f).await?;
        seq += 1;
    }
    Ok(seq)
}
/// 把缓冲区里已经完整的事件全部处理掉（可能触发若干 `TEMPLATE_DEF` 下发）。
///
/// # `defs_sent`：本响应里**已经发过 def 的模板 id** ✓
///
/// **为什么必须有它（第 195 轮，定位 `terminated` 的根因）** ✓：
/// 服务端的 `Inducer` 是**每会话一个**且**长期存活** ✓ ⇒ 模板 id 跨响应单调增长 ✓；
/// 而 `TemplateDef` 原本**只在首次定义时发一次** ✓ ⇒ ⇒ **客户端一旦换一张新表**
/// （重连 ✓ / 进程刚起 ✓），后面某条响应引用到"更早响应里定义过的模板"时就**必然查不到** ✓
/// ⇒ `UnknownTemplate` ⇒ 按 M7 红线**如实截断** ⇒ **harness 报 `terminated`** ✓✓。
///
/// ⇒ 修法：**本响应内引用到的模板，本响应至少发一次 def** ✓（协议与帧格式完全不变 ✓，
/// 只是 `TEMPLATE_DEF` 在**新响应的第一次引用**时多发一次 ✓ —— 每响应每个模板至多一次 ✓，
/// 成本是"每响应每模板几十字节" ✓，换来的是"客户端表是新的也能解码" ✓✓）。
async fn drain_events(
    sink: &crate::resume::RespSink,
    sid: u32,
    inducer: &Arc<Mutex<llm_proxy_json::Inducer>>,
    defs_sent: &mut std::collections::HashSet<u32>,
    buf: &mut Vec<u8>,
    pending: &mut Vec<llm_proxy_core::batch::BatchItem>,
    stats: &mut SseStats,
) -> anyhow::Result<()> {
    let mut consumed = 0usize;
    while let Some(end) = llm_proxy_json::sse::next_event_end(&buf[consumed..]) {
        let ev_end = consumed + end;
        // 复制出事件字节：避免与 `buf` 的可变借用冲突，且事件本就很短
        let ev = buf[consumed..ev_end].to_vec();
        consumed = ev_end;
        stats.events += 1;
        stats.src_bytes += ev.len() as u64;

        match llm_proxy_json::sse::scan_event(&ev) {
            // 未识别的形态一律原样透传——这是「上游新增事件类型无需改代码」的落点
            None => {
                stats.raw += 1;
                stats.wire_bytes += ev.len() as u64;
                pending.push(raw_item(ev));
            }
            // 锁的作用域必须**显式收紧并绑定到具名变量**：写成
            // `match inducer.lock().unwrap().feed(..)` 会让 MutexGuard 存活到整个
            // match（其中包含 `mux.send(..).await`），future 就不再是 Send。
            Some(scan) => {
                let induction = {
                    let mut guard = inducer.lock().unwrap();
                    guard.feed(&ev, &scan)
                };
                match induction {
                    llm_proxy_json::Induction::Raw => {
                        stats.raw += 1;
                        stats.wire_bytes += ev.len() as u64;
                        pending.push(raw_item(ev));
                    }
                    llm_proxy_json::Induction::Defined { template, vars } => {
                        let def = proto::TemplateDef {
                            template_id: template.id,
                            schema: template.schema.to_vec(),
                            segments: template.segments.clone(),
                            var_paths: template
                                .var_paths
                                .iter()
                                .map(|p| String::from_utf8_lossy(p).into_owned())
                                .collect(),
                        };
                        let def_len = def.encoded_len();
                        sink.send(Frame::new(
                            FrameType::TemplateDef,
                            sid,
                            0,
                            def.encode_to_vec(),
                        ))
                        .await?;
                        stats.defined += 1;
                        stats.wire_bytes += def_len as u64;
                        let n = vars.iter().map(Vec::len).sum::<usize>();
                        stats.wire_bytes += n as u64;
                        defs_sent.insert(template.id);
                        pending.push(var_item(template.id, vars));
                    }
                    llm_proxy_json::Induction::Delta { id, vars } => {
                        // **本响应第一次引用这个模板 ⇒ 补发一次 def** ✓（见 `drain_events` 的说明 ✓）。
                        // 取模板时**必须立刻释放锁** ✓：下面有 `sink.send(..).await` ✓，
                        // 持锁跨 await 会让整个 future 失去 `Send` ✗（本文件踩过 ✓）。
                        let need_def = !defs_sent.contains(&id);
                        if need_def {
                            let t = { inducer.lock().unwrap().template_by_id(id) };
                            if let Some(t) = t {
                                let def = proto::TemplateDef {
                                    template_id: t.id,
                                    schema: t.schema.to_vec(),
                                    segments: t.segments.clone(),
                                    var_paths: t
                                        .var_paths
                                        .iter()
                                        .map(|p| String::from_utf8_lossy(p).into_owned())
                                        .collect(),
                                };
                                let def_len = def.encoded_len();
                                sink.send(Frame::new(
                                    FrameType::TemplateDef,
                                    sid,
                                    0,
                                    def.encode_to_vec(),
                                ))
                                .await?;
                                stats.defined += 1;
                                stats.wire_bytes += def_len as u64;
                                defs_sent.insert(id);
                            }
                        }
                        stats.delta += 1;
                        stats.wire_bytes += vars.iter().map(Vec::len).sum::<usize>() as u64;
                        pending.push(var_item(id, vars));
                    }
                }
            }
        }
    }
    if consumed > 0 {
        buf.drain(..consumed);
    }
    Ok(())
}

fn raw_item(bytes: Vec<u8>) -> llm_proxy_core::batch::BatchItem {
    llm_proxy_core::batch::BatchItem::raw(bytes)
}

fn var_item(id: u32, vars: Vec<Vec<u8>>) -> llm_proxy_core::batch::BatchItem {
    llm_proxy_core::batch::BatchItem::delta(id, vars)
}

async fn flush_batch(
    sink: &crate::resume::RespSink,
    sid: u32,
    pending: &mut Vec<llm_proxy_core::batch::BatchItem>,
    seq: u32,
) -> anyhow::Result<u32> {
    let items = std::mem::take(pending);
    let mut payload = Vec::new();
    llm_proxy_core::batch::encode(&items, &mut payload);
    sink.send(Frame::new(FrameType::RespBatch, sid, seq, payload))
        .await?;
    Ok(seq.wrapping_add(1))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod framing_tests {
    use super::*;

    fn h(name: &str, value: &str) -> proto::Header {
        proto::Header {
            name: name.to_string(),
            value: value.as_bytes().to_vec(),
        }
    }

    /// 判据矩阵：**已编码的 body 一律不走事件切分**。
    ///
    /// 这条规则是从一次实测反推出来的：`text/event-stream` + `content-encoding: zstd`
    /// 当时"能过"，是因为它落进慢路径的无损往返——那是碰巧，且白花一次压缩。
    /// 现在把规则钉在函数上，端到端那条（`crates/e2e-tests/tests/framing.rs`）
    /// 守的是结果，这里守的是判据本身。
    #[test]
    fn event_framing_is_refused_for_any_non_identity_encoding() {
        // 正常 SSE：走事件切分
        assert!(
            wants_event_framing(&[h("content-type", "text/event-stream")]),
            "普通 SSE 必须走事件切分（否则模板/批量收益全没了）"
        );
        assert!(
            wants_event_framing(&[
                h("content-type", "text/event-stream; charset=utf-8"),
                h("content-encoding", "identity"),
            ]),
            "identity 等于没编码，仍应切分"
        );

        // 已编码：必须拒绝
        for enc in ["zstd", "gzip", "br", "ZSTD", "gzip, br"] {
            assert!(
                !wants_event_framing(&[
                    h("content-type", "text/event-stream"),
                    h("content-encoding", enc),
                ]),
                "content-encoding={enc} 的 body 是不透明的，不许切事件"
            );
        }

        // 不是 SSE：无论编不编码都不切
        assert!(!wants_event_framing(&[h(
            "content-type",
            "application/json"
        )]));
        assert!(!wants_event_framing(&[
            h("content-type", "application/json"),
            h("content-encoding", "zstd"),
        ]));
        // 连 content-type 都没有：不许猜
        assert!(!wants_event_framing(&[]));

        // 头名大小写不敏感（上游大小写不受我们控制）
        assert!(!wants_event_framing(&[
            h("Content-Type", "TEXT/EVENT-STREAM"),
            h("Content-Encoding", "zstd"),
        ]));
    }
}
