//! 客户端 ingress：本地 HTTP 服务（**反向代理形态**，不是 CONNECT 转发代理）。
//!
//! 设计 §4.1 的关键点：增量分解必须在 TLS 终止点**之内**才能看到明文请求体。
//! `HTTPS_PROXY` 式转发代理建立的是加密隧道，body 在隧道里，增量/缓存/模板全部失效。
//!
//! M1a 起有两条路径：
//!
//! * **增量**（`ENC_TOKENSTREAM`）——缓冲请求体 → CDC 分块 → 对已在对端缓存里的块发
//!   `REF`、其余发 `LITERAL`。要求 `Content-Length` 已知且不超过
//!   [`llm_proxy_core::config::MAX_DECOMPOSE_BYTES`]。
//! * **原样**（`ENC_RAW`）——流式转发，不缓冲。用于长度未知、过大、或增量失败降级。
//!
//! 降级链（M1a 只有前两档）：`增量 → 增量重试(忘掉缺块) → 全量原样`。

use std::collections::HashMap;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use bytes::Bytes;
use http::{header, Request, Response};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use llm_proxy_cache::UploadSet;
use llm_proxy_core::compression::CompressPool;
use llm_proxy_core::config::{err_code, hint};
use llm_proxy_core::fingerprint::{body_fp, Namespace};
use llm_proxy_core::{flags, proto, Flags, Frame, FrameType};
use llm_proxy_transport::{ChannelBody, Mux};
use prost::Message;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::config::{Config, Shared};

pub type RespBody = BoxBody<Bytes, std::io::Error>;

/// 连接级模板表容量。见 TemplateStore 的说明：给大是为了让
/// 「正在被使用的模板」在 LRU 上永远是最新项，不可能被淘汰。
///
/// ⚠️ **第 189 轮把这个值从 512 提到 4096** ✓ —— 512 **不够** ✗，现场已经因此产出
/// `terminated` ✓（根因链：`UnknownTemplate` ⇒ 按 M7 红线主动截断 ⇒ SDK 看到传输错误 ✓）：
/// 一次真实会话里服务端创建了 **1000+ 个模板**（客户端报的 `UnknownTemplate` id 到过
/// **2312** ✓），而**正在被引用的旧模板会被新模板挤出 LRU** ✓ ⇒ 断了。
///
/// 原来"在用模板永远是最新项"这个假设**只在模板种类少时成立** ✓ —— 一旦一条长响应里
/// **交替出现很多种骨架**（工具调用、多形态内容），LRU 保不住全部在用模板 ✗。
///
/// 为什么 4096 安全 ✓：单条模板约 150 B（见 [`TemplateStore::get`] 的注释 ✓）⇒
/// 4096 条约 0.6 MB（连 HashMap 开销也就 ~1 MB 量级 ✓），而目标路由器
/// **实测 1.9 GB 内存 / 1.5 GB 可用** ✓ —— 相对块缓存的预算而言可以忽略 ✓。
/// 取 4096 而不是"改成不淘汰" ✓：不设上限会让长会话的内存**无界增长** ✗。
const TEMPLATE_STORE_MAX: usize = 4096;

/// 观测计数器（设计 §14）。
#[derive(Default)]
pub struct Stats {
    pub requests: AtomicU64,
    /// 客户端发出的请求体原始字节数。
    pub req_raw_bytes: AtomicU64,
    /// 实际经 DSHP 发出的请求体字节数（含标签与引用开销）。
    pub req_wire_bytes: AtomicU64,
    pub resp_bytes: AtomicU64,
    pub delta_requests: AtomicU64,
    /// 增量失败、降级为全量的次数。
    pub delta_fallbacks: AtomicU64,
    /// 因对端报告缺块而精确遗忘的块数。
    pub forgotten_blocks: AtomicU64,
    /// 以 `REF` 复用、未实际发送的块数。
    pub ref_blocks: AtomicU64,
    /// **决策 12 命中次数**：解析出 `store=true` 并因此禁用跨请求复用的请求数。
    ///
    /// 它既是排查仪器，也是运维想看的合规指标——第 61 轮发现"那个请求有没有走到
    /// 这条路径"光看 `ref_blocks` 判不出来（复用与不复用都能涨），需要一个
    /// **直接反映判定本身**的数。
    pub store_no_cross: AtomicU64,
    /// **直接观测**（第 63 轮）：最近一次进入增量判定的 body 前 32 字节。
    ///
    /// 为什么需要它：缺口 13 里"判定没命中"这件事，光看计数器只能知道"没命中"，
    /// 不知道**为什么会没命中**。把判定当时的输入原样记下来，就不用再推理
    /// （第 61~62 轮的教训：我在这条链上推理错了三次）。
    pub last_delta_head: std::sync::Mutex<String>,
    /// 模板缺失/槽数不符导致的**主动截断**次数。非 0 即协议 bug，必须告警。
    pub template_miss: AtomicU64,
    /// 因为**没收到 `RespEnd`** 而主动中止 HTTP 响应体的次数。
    ///
    /// 非 0 表示确实发生过"响应中途断掉"（链路断、上游断流、对端报错）。
    /// 它与 `template_miss` 的区别：后者是本地重组不了，前者是对端没能把响应送完。
    /// 两者都必须让 SDK 看到**明确错误**，而不是半截 200——这个计数就是那条红线的观测点。
    pub truncated_responses: AtomicU64,
    /// 因 SDK 先走（响应体被 drop）而**尝试**发取消帧的次数。
    ///
    /// 与 `cancel_sent` 成对看：`attempts > 0` 而 `sent == 0` 说明帧发不出去；
    /// 两者都是 0 说明**守卫根本没触发**——那就是缺口 8 的卡点。
    pub cancel_attempts: AtomicU64,
    /// 取消帧成功写进链路（`mux.send` 返回 Ok）的次数。
    pub cancel_sent: AtomicU64,
    /// 发出的保活 `Ping` 次数（缺口 9 的验收依据）。
    pub pings_sent: AtomicU64,
    /// 保活发送**失败**的次数（诊断：区分"任务没跑"与"发了但被拒"）。
    pub pings_failed: AtomicU64,
    /// 到点时链路不可用而跳过保活的次数（诊断）。
    pub pings_skipped: AtomicU64,
    /// 走整段压缩（`ENC_ZSTD`）的请求数。
    pub compressed_requests: AtomicU64,
    /// 降级到直连的次数。
    pub bypass_switches: AtomicU64,
    /// 成功重连并切回 WS 的次数。
    pub recoveries: AtomicU64,
    /// 直连模式下服务的请求数。
    pub bypass_requests: AtomicU64,
    /// 重连尝试次数（含失败）。
    pub reconnect_attempts: AtomicU64,
    /// 从启动到链路建立（或判定为直连）的耗时毫秒。
    ///
    /// 直接对应 M3 验收的「降级耗时 <3s」——没有这个数字，那条验收就只能靠感觉说。
    /// 在 WS 被拦的场景里，它包含"WS 试一次失败 + 换 SSE 成功"的完整代价。
    pub link_ms: AtomicU64,
    /// 响应方向上链路实际承载的字节数，**含 24 字节帧头**。
    ///
    /// 必须含帧头才诚实：M2 的核心风险正是一帧一事件时帧头吃掉全部收益。
    pub resp_wire_bytes: AtomicU64,
    /// 客户端重组出的 body 字节数（应等于上游原始字节数）。
    pub resp_raw_bytes: AtomicU64,
    /// 响应侧各部分的计数与字节数。用于把链路占用**精确分解**，
    /// 而不是靠估算判断瓶颈在帧头、模板定义还是变量槽。
    pub resp_template_defs: AtomicU64,
    pub resp_template_def_bytes: AtomicU64,
    pub resp_batch_frames: AtomicU64,
    /// 批量项总数（含原样项）。
    pub resp_batch_items: AtomicU64,
    /// 原样项占用的链路字节数。
    pub resp_raw_items_bytes: AtomicU64,
    /// 模板项的变量槽占用字节数。
    pub resp_var_bytes: AtomicU64,
}

/// 当前传输模式。设计 §10 降级链的档位：**KCP(UDP)、WS、SSE、直连四档都已实现**。
///
/// 第 59 轮修：这里原先写着「KCP 尚未实现」✗，而 `Kcp = 3` 是真实档位，
/// `crates/e2e-tests/tests/kcp_mode.rs` 也一直在守它——**别让注释比实现旧**。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    /// 经 DSHP 服务端转发，走 WebSocket（首选）。
    Ws = 0,
    /// **L2 直连上游**：DSHP 链路不可用时直接以普通 HTTP 转发。
    /// 功能不中断，只是失去流量优化——这正是"降级而不是死掉"。
    Bypass = 1,
    /// 经 DSHP 服务端转发，走 **SSE 隧道**（`POST` 长连接 + `text/event-stream`）。
    ///
    /// 存在的理由：企业代理极常见地**放通 POST、拦掉 WebSocket 的 `Upgrade`**。
    /// 没有这一档时，WS 一被拦客户端就直接掉到直连，增量和模板收益全丢。
    Sse = 2,
    /// 经 DSHP 服务端转发，走 **KCP(UDP)**。
    ///
    /// 只在**显式配置了 KCP 服务端地址**时才尝试：它需要放行 UDP，
    /// 盲目去试会在只放行 TCP 的环境里白等一轮握手。
    Kcp = 3,
}

impl Mode {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Bypass,
            2 => Self::Sse,
            3 => Self::Kcp,
            _ => Self::Ws,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Ws => "ws",
            Self::Sse => "sse",
            Self::Kcp => "kcp",
            Self::Bypass => "bypass",
        }
    }
    /// 是否走 DSHP 链路（而非直连）。
    pub fn is_tunnel(self) -> bool {
        matches!(self, Self::Ws | Self::Sse | Self::Kcp)
    }
}

/// 一条已握手完成的 DSHP 链路。
///
/// **独立成结构体是为了让它可替换**：WS 断开后整条链路作废，客户端必须能换一条新的。
/// 早先把 `Mux` 直接放在 `Proxy` 里，等于把"连接"与"进程"绑死——一次断线就永久失效。
pub struct Link {
    mux: Mux,
    pub caps: proto::Caps,
    /// 这条链路是用哪种传输建起来的（状态端点会展示）。
    pub mode: Mode,
    /// 服务端是否支持 `ReqOpen` 后先等待 `StreamReady` 的准入屏障。
    pub stream_ready: bool,
    /// **这条连接**的模板表（见 [`TemplateStore`] 的说明）。
    ///
    /// ⚠️ **必须挂在 `Link` 上，不能挂在 `Proxy` 上** —— 第 180 轮修的静默错误内容就是这么来的：
    /// 服务端的归纳器是**每会话**新建的（`llmproxyd::egress::run_session` 里 `Inducer::new`）
    /// ⇒ 模板 id **每个会话都从 1 重新开始**。而模板表若跨会话共用：
    ///
    /// * 新会话的 id 5 会**覆盖**老会话的 id 5 ⇒ 老会话在途帧引用 id 5 时会用**新模板**
    ///   重建 ⇒ 拼出"看着正常、其实是错的"字节流（M7 红线要防的静默错误内容，而且**不会报错**）；
    /// * 反过来，老会话在途帧里的 id 92 在新会话的表里查不到 ⇒ `UnknownTemplate(92)`
    ///   ⇒ 主动截断 ⇒ SDK 看到传输错误（harness 报 `terminated`）。
    ///
    /// 现场对账：客户端共收到 70 个 def、表里只剩 21、`evicted=0` —— 70 是各会话之和，
    /// 21 是**单会话内**不同 id 的个数，`evicted=0` 正好排除"被 LRU 淘汰"这条解释。
    pub templates: Arc<Mutex<TemplateStore>>,
}

pub struct Proxy {
    pub cfg: Config,
    /// 当前链路。`None` 表示正在重连（此时一定处于 [`Mode::Bypass`]）。
    pub link: RwLock<Option<Arc<Link>>>,
    pub mode: AtomicU8,
    pub stats: Arc<Stats>,
    pub ns: Namespace,
    /// 与链路生命周期解耦的客户端块知识：所有重连后的 Link、并行 stream 和
    /// subagent 请求共享同一份 `Namespace` 账本。这里只存远端已确认持有的指纹，
    /// 不存块内容；每个请求的待提交指纹保存在自己的局部变量中。
    pub uploads: Mutex<UploadSet>,
    /// 压缩上下文池（固定容量、可复用）。见 `llm_proxy_core::compression`。
    pub compress: Arc<CompressPool>,
    /// 直连回退用的上游 HTTP 客户端。
    pub client: crate::config::HttpClient,
}

impl Proxy {
    pub fn mode(&self) -> Mode {
        Mode::from_u8(self.mode.load(Ordering::Relaxed))
    }

    /// 装上一条新链路并切回 WS 模式。
    fn install(&self, link: Link) {
        let m = link.mode;
        *self.link.write().unwrap() = Some(Arc::new(link));
        self.mode.store(m as u8, Ordering::Relaxed);
        self.stats.recoveries.fetch_add(1, Ordering::Relaxed);
    }

    /// 切入直连模式并丢弃失效链路。
    fn enter_bypass(&self) {
        *self.link.write().unwrap() = None;
        self.mode.store(Mode::Bypass as u8, Ordering::Relaxed);
    }

    /// 取一条**确认可用**的链路，或判定应当直连。
    ///
    /// 关键点：链路健康检查放在**请求路径上**，而不是只靠 supervisor 轮询。否则从
    /// "链路断掉"到"supervisor 发现"之间的那个窗口里，所有请求都会拿到 502。
    fn route(&self) -> Result<Arc<Link>, Mode> {
        if let Some(l) = self.link.read().unwrap().as_ref() {
            if !l.mux.is_closed() {
                return Ok(Arc::clone(l));
            }
        }
        if self.mode().is_tunnel() {
            // 当场翻档，不等 supervisor
            self.enter_bypass();
            self.stats.bypass_switches.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("DSHP 链路不可用，当场降级为直连上游");
        }
        Err(Mode::Bypass)
    }
}

/// 连接级模板表。
///
/// **必须跨响应存活**：真实聊天里每个响应的 SSE 结构完全相同，按响应丢弃模板
/// 意味着每个响应都要重付「两个归纳样本 + 一次 `TEMPLATE_DEF`」（实测约 317 B，
/// 在 16 KB 的短响应上就占 1.9%）。服务端的归纳器同样按连接存活，两边因此一致。
///
/// 淘汰是**风险点**：客户端一旦丢掉某个模板，而服务端仍在使用它，就会出现
/// 「无法重组」——按正确性红线只能截断响应。所以容量给得很大（512），
/// 且每次使用都刷新 LRU，使**正在被使用的模板永远是最新项**、不会被淘汰。
/// 真的发生淘汰时打 WARN，因为它意味着协议两侧的认知可能已经不一致。
pub struct TemplateStore {
    map: HashMap<u32, llm_proxy_json::Template>,
    order: VecDeque<u32>,
    max: usize,
    evicted: u64,
}

impl TemplateStore {
    pub fn new(max: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            max: max.max(1),
            evicted: 0,
        }
    }

    pub fn insert(&mut self, id: u32, t: llm_proxy_json::Template) {
        if self.map.insert(id, t).is_none() {
            self.order.push_back(id);
        }
        while self.order.len() > self.max {
            if let Some(old) = self.order.pop_front() {
                if self.map.remove(&old).is_some() {
                    self.evicted += 1;
                    tracing::warn!(
                        template_id = old,
                        "模板表超限，淘汰了模板；若服务端仍引用它，响应将被截断"
                    );
                }
            }
        }
    }

    /// 取模板并刷新 LRU。返回克隆（模板只有约 150 字节，克隆远比持锁跨 await 便宜）。
    pub fn get(&mut self, id: u32) -> Option<llm_proxy_json::Template> {
        let t = self.map.get(&id)?.clone();
        self.order.retain(|x| *x != id);
        self.order.push_back(id);
        Some(t)
    }

    /// 表里最小的模板 id（空表 ⇒ 0）—— 与 `id_max` 一起构成"id 区间"判据 ✓。
    pub fn id_min(&self) -> u32 {
        self.map.keys().copied().min().unwrap_or(0)
    }

    /// 表里最大的模板 id（空表 ⇒ 0）。
    pub fn id_max(&self) -> u32 {
        self.map.keys().copied().max().unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[allow(dead_code)] // 与 len 成对，给后续观测用
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// **自愈**：判定"某个 id 不认识"时调用 ✓ —— 清空整张表 ✓。
    ///
    /// # 为什么必须清空整张，而不是"补回那一个"（第 197 轮）
    ///
    /// 现场抓到过一种"**中间有洞**"的表 ✓：表里**有** id 35 ✓ 却**没有** 54 ✓ ⇒
    /// 客户端报的"最大 id"已经 ≥ 54 ⇒ 服务端按 `id > 最大值` 判**不需要补发** ✗ ⇒ 复发 ✓。
    /// ⇒ 洞的位置客户端自己知道 ✓、但协议里**没有表达洞的办法** ✗（一个数字表达不了 ✓）⇒
    /// 与其发明"报告缺哪些 id"的协议 ✗，不如**清表重来** ✓：
    /// 代价是**这一次**响应丢 ✓（本来就已在丢 ✓）+ 之后**每条流多发一遍 def** ✓（几十字节/模板 ✓），
    /// 换来的是**后续不再复发** ✓✓（自愈 ✓）。
    ///
    /// 为什么表的中间会开洞：还没查清 ✓（服务端 `Inducer::evict_if_needed` 会摘掉状态 ✓，
    /// 而**已经进入本批**的引用仍会被发出 ✓ ⇒ 这条线值得继续查 ✓）——
    /// 但清表**不依赖**那个答案 ✓，它对任何成因都成立 ✓。
    /// ⚠️ **当前无人调用**（第 199 轮撤掉了"清空自愈" ✗）：
    /// 它的前提"表被 id 冲突污染"已被"模板 id 进程级唯一"消除 ✓（第 198 轮 ✓）。
    /// **保留作为兜底** ✓：万一将来又出现"同 id 不同义" ✓，这是最快的止血手段 ✓，
    /// 所以不删 ✓（删了也不会有人知道它曾在两轮里立过功 ✓）。
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }
}

pub type ProxyShared = Arc<Proxy>;

fn err_body(status: u16, msg: impl Into<String>) -> Response<RespBody> {
    let body = serde_json::json!({ "error": { "message": msg.into() } }).to_string();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full(body.into_bytes()))
        .unwrap()
}

fn full(b: Vec<u8>) -> RespBody {
    Full::new(Bytes::from(b))
        .map_err(|e: Infallible| -> std::io::Error { match e {} })
        .boxed()
}

/// 启动本地 HTTP 入口。
pub async fn run(cfg: Shared) -> anyhow::Result<()> {
    cfg.check_loopback().map_err(|e| anyhow::anyhow!(e))?;

    // 租户参与命名空间派生（设计 §5.1）。与服务端不一致会在握手期被**拒绝**，
    // 这里不做任何"自动改"的兜底——那会让租户隔离不可观测。
    let ns = Namespace::derive(cfg.psk.as_bytes(), &cfg.tenant, &cfg.upstream_host);
    // 引导字典。设计 §7.3 要求字典在客户端本地训练、经握手协商上送；那一步尚未实现，
    // 当前两端都用内嵌的引导字典，并在握手期校验 dict_id 一致——**字典不一致必须当场
    // 失败**，否则 zstd 解压会报 dictID 不符（这是好的失败方式，但不能拖到运行时）。
    let dicts = llm_proxy_core::dict::Dicts::bootstrap();
    let proxy = Arc::new(Proxy {
        link: RwLock::new(None),
        // 初值取 Bypass：首次连接成功前**不能**声称自己是 WS 模式
        mode: AtomicU8::new(Mode::Bypass as u8),
        stats: Arc::new(Stats::default()),
        ns,
        uploads: Mutex::new(UploadSet::new(cfg.upload_entries)),
        compress: Arc::new(CompressPool::new(dicts.patch, 0).context("初始化压缩上下文池失败")?),
        client: cfg.http_client()?,
        cfg: (*cfg).clone(),
    });

    // **先把监听端口起起来，再做首次连接尝试。**
    //
    // 之前是反过来的：先 `connect_link().await`（注释还写着"失败不致命"），成功或失败
    // 之后才 `TcpListener::bind`。那个顺序只覆盖了**快速失败**——对端如果是**黑洞**
    // （TCP 建得上、永不回话），首次连接会一直挂着 ⇒ HTTP 端口根本不起 ⇒ SDK 拿到的是
    // "连接被拒"。拒绝型故障（403 / ECONNREFUSED）永远不会暴露这一点，所以这条路径
    // 长期没被测验过（见 `e2e-tests/black_hole.rs`）。
    //
    // 客户端是**代理**：必须无论链路状态都能服务。链路只是优化，不是前提。
    let listener = TcpListener::bind(&proxy.cfg.listen)
        .await
        .with_context(|| format!("无法监听 {}", proxy.cfg.listen))?;
    tracing::info!(
        listen = %proxy.cfg.listen,
        "llmproxyc 已启动（SDK 请把 base_url 指向此处）"
    );

    // 首次连接在后台跑；**它结束之后**才交给 `supervise`，避免两者同时发起连接。
    let (init_done, wait_init) = tokio::sync::oneshot::channel::<()>();
    {
        let proxy = proxy.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            let t_link = std::time::Instant::now();
            match connect_link_guarded(&cfg, &proxy).await {
                Ok(link) => {
                    tracing::info!(
                        server = %cfg.server,
                        dict_id = link.caps.dict_id,
                        upstream_host = %link.caps.upstream_host,
                        delta = cfg.enable_delta,
                        "已连接服务端"
                    );
                    proxy.install(link);
                    // install 会 +1 recovery，首次连接不算"恢复"
                    proxy.stats.recoveries.fetch_sub(1, Ordering::Relaxed);
                }
                Err(e) => tracing::warn!(
                    %e,
                    fallback = ?cfg.upstream_fallback,
                    "首次连接服务端失败，以直连模式启动（后台会持续重试）"
                ),
            }
            let link_ms = t_link.elapsed().as_millis() as u64;
            proxy.stats.link_ms.store(link_ms, Ordering::Relaxed);
            tracing::info!(link_ms, mode = proxy.mode().name(), "首次链路尝试结束");
            let _ = init_done.send(());
        });
    }
    let proxy_for_supervise = proxy.clone();
    tokio::spawn(async move {
        // 等首次尝试收尾（成功/失败/超时都算），再进入重连守护
        let _ = wait_init.await;
        supervise(proxy_for_supervise).await;
    });
    // **空闲保活**（缺口 9）：按间隔发一帧 `Ping`，对端回 `Pong`（两端接收侧都齐，
    // 此前只缺发送方）。链路不是隧道时跳过——降级模式没有链路可保活。
    {
        let proxy = proxy.clone();
        tokio::spawn(async move {
            let secs = proxy.cfg.keepalive_sec;
            if secs == 0 {
                tracing::info!("保活已关闭（keepalive_sec = 0）");
                return;
            }
            let mut tick = tokio::time::interval(Duration::from_secs(secs));
            tick.tick().await; // 第一个 tick 立刻返回，跳过它
            loop {
                tick.tick().await;
                // 只在"链路可用"时发：降级模式下没有链路可保活。
                // `link` 是 `RwLock<Option<Link>>`，拿不到就跳过这一拍。
                let mux = {
                    let l = proxy.link.read().unwrap();
                    l.as_ref().map(|link| link.mux.clone())
                };
                let Some(mux) = mux else {
                    proxy
                        .stats
                        .pings_skipped
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    continue;
                };
                match mux.send(llm_proxy_transport::session::ping_frame()).await {
                    Ok(()) => {
                        proxy
                            .stats
                            .pings_sent
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(e) => {
                        proxy
                            .stats
                            .pings_failed
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        tracing::debug!(%e, "保活 Ping 发送失败");
                    }
                }
            }
        });
    }

    loop {
        let (stream, _peer) = listener.accept().await?;
        let proxy = proxy.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: Request<Incoming>| {
                let p = proxy.clone();
                async move { Ok::<_, Infallible>(handle(p, req).await) }
            });
            // 本地侧只需 HTTP/1.1 + keep-alive：SDK 对明文 http:// 基本不协商 h2
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .keep_alive(true)
                .serve_connection(io, svc)
                .await
            {
                tracing::debug!(?e, "本地连接结束");
            }
        });
    }
}

/// 建立一条已握手完成的 DSHP 链路。
///
/// 一次链路尝试的**上限**。
///
/// 为什么必须有：`tokio_tungstenite::connect_async` **没有**默认超时，而"连接建得上、
/// 对面永不回话"的**黑洞**对端在真实网络里很常见（SYN 被丢、或中间设备握着连接不处理）。
/// 没有这个上限时，一次挂死的尝试会**永远不返回** ⇒ 重连守护循环再也不会重试 ⇒
/// 就算服务端后来恢复了，客户端也发现不了。
///
/// 取值 5s 的依据：本机**被拒绝**的连接要 ~2s（实测，见 `e2e-tests/link_timing.rs`），
/// 而一次尝试在降级链上最多试两种传输（WS → SSE）⇒ 2×~2s 已在 5s 之内；
/// 真正的远端握手留了余量，又不会让人等到 20s 以上。
const CONNECT_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// [`connect_link`] + **尝试上限**。超时按"尝试失败"处理（交给降级链 / 重连守护）。
async fn connect_link_guarded(cfg: &Config, proxy: &ProxyShared) -> anyhow::Result<Link> {
    match tokio::time::timeout(CONNECT_ATTEMPT_TIMEOUT, connect_link(cfg, proxy)).await {
        Ok(r) => r,
        Err(_) => Err(anyhow::anyhow!(
            "链路尝试超过 {}s 未完成（对端很可能只接受连接、不回话）",
            CONNECT_ATTEMPT_TIMEOUT.as_secs()
        )),
    }
}

/// **传输层逐档尝试**：WS → SSE。注意区分两类失败：
///
/// * **传输建不起来**（TCP 失败、WS 握手被中间设备拦掉、SSE 返回非
///   `text/event-stream`）→ 换下一档，这正是降级链要处理的；
/// * **DSHP 握手失败**（PSK 不一致、字典不一致、版本不符）→ **直接报错，不换档**。
///   换档救不了凭据错误，只会把同一个失败重复一遍、还把问题拖得更久。
async fn connect_link(cfg: &Config, proxy: &ProxyShared) -> anyhow::Result<Link> {
    let forced = cfg.force_mode.as_deref();

    let want_ws = forced.is_none() || forced == Some("ws");
    let want_sse = forced.is_none() || forced == Some("sse");

    let mut transport: Option<(Mux, mpsc::Receiver<Frame>, Mode)> = None;

    // **KCP 排在降级链首位**（设计 §10：`KCP → WS → SSE → L2`），
    // 但只在**显式配置了 `kcp_server`** 时才尝试：它需要放行 UDP，
    // 在只放行 TCP 的环境里盲目去试会白等一轮握手，反而拖慢降级。
    let want_kcp = forced.is_none() || forced == Some("kcp");
    if want_kcp {
        if let Some(a) = cfg.kcp_server.as_deref() {
            match a.parse::<std::net::SocketAddr>() {
                Ok(addr) => {
                    // FEC `10:2`，与服务端同档（见 `llmproxyd` 同处的说明）。
                    // 两端必须用同一个 `FecConfig`：档位不一致时解码侧会把
                    // 超出本端分片数的包直接丢掉，等于白开。
                    let fec = Some(llm_proxy_transport::fec_adapt::FecSettings::adaptive(
                        llm_proxy_transport::fec::FecConfig::R10_2,
                    ));
                    match llm_proxy_transport::kcp_link::connect(addr, cfg.psk.as_bytes(), fec)
                        .await
                    {
                        Ok((mux, inbox)) => transport = Some((mux, inbox, Mode::Kcp)),
                        Err(e) if forced.is_some() => {
                            return Err(anyhow::anyhow!("KCP 传输失败：{e}"))
                        }
                        Err(e) => tracing::warn!(%e, "KCP 建不起来，改试 WS"),
                    }
                }
                Err(e) => tracing::warn!(%e, addr = %a, "kcp_server 地址无效，跳过 KCP"),
            }
        }
    }

    if want_ws && transport.is_none() {
        match llm_proxy_transport::connect(&cfg.server).await {
            Ok((mux, inbox)) => transport = Some((mux, inbox, Mode::Ws)),
            Err(e) if forced.is_some() => return Err(anyhow::anyhow!("WS 传输失败：{e}")),
            Err(e) => tracing::warn!(%e, "WS 传输建不起来，改试 SSE 隧道"),
        }
    }
    if transport.is_none() && want_sse {
        match crate::sse_link::connect(&cfg.server).await {
            Ok((mux, inbox)) => {
                tracing::info!("已切换到 SSE 隧道传输");
                transport = Some((mux, inbox, Mode::Sse));
            }
            Err(e) if forced.is_some() => return Err(anyhow::anyhow!("SSE 传输失败：{e}")),
            Err(e) => return Err(anyhow::anyhow!("WS 与 SSE 两种传输都建不起来：{e}")),
        }
    }
    let (mux, mut inbox, mode) = transport.context("没有可用的传输模式")?;

    let caps = handshake(&mux, &mut inbox, cfg).await?;
    let stream_ready = caps.caps.iter().any(|c| c == "stream-ready");
    spawn_session_pump(mux.clone(), inbox, Arc::downgrade(proxy));
    // 模板表**每条连接一张新建**：与本会话的 id 空间同生命周期（见 [`Link::templates`]）。
    Ok(Link {
        mux,
        caps,
        mode,
        stream_ready,
        templates: Arc::new(Mutex::new(TemplateStore::new(TEMPLATE_STORE_MAX))),
    })
}

/// 会话级帧（Err / GoAway / Ping）的后台处理。
/// 校验服务端宣告的**块参数**与本端一致。
///
/// # 为什么值得查（此前从来不查）
///
/// `Caps` 里宣告了 `max_frame_bytes` 与 `window_log`，而客户端**从不读它们**——
/// 切帧时用的是自己的编译期常量。今天两端共用同一份常量，所以不会有差异；
/// 但**"协议版本号相同、常量不同"的部署**（两个不同 revision 的二进制）会出现：
/// 客户端按更大的上限切帧，服务端按更小的上限拒收（`TOO_LARGE`）。
/// 那时错在**帧层**而不是握手层，排查成本高得多——而这正是握手该拦住的事。
///
/// 与 `proto_version` / `dict_id` / `tenant` 同级：不一致就**明确失败**。
///
/// 兼容性：值为 0 视为"未宣告"（旧服务端），跳过检查而不是拒绝——
/// 拒绝一个没有声明该字段的对端，等于把版本兼容性做成硬门槛。
/// 服务端宣告的**接收能力**必须覆盖本端将要发送的编码。
///
/// # 为什么需要（这条方向此前完全没有生效）
///
/// 能力协商有两个方向，而**只有一个是活的**：服务端读客户端的 `stream-zstd`
/// （决定要不要走慢路径）；客户端**从来不读**服务端的 `caps` 清单
/// （服务端一直在宣告 `ws/raw/tokenstream/zstd`，没人看）。
///
/// 后果：客户端照发 `ENC_TOKENSTREAM` / `ENC_ZSTD`，**不检查对端是否支持**。
/// 两端版本有偏差时，这会在请求中途变成 `BAD_ENCODING` 之类的失败——
/// 而那本该在握手期就明确拒绝（与租户、`upstream_host`、块参数同一条原则）。
///
/// 兼容性：清单为空视为"旧对端没有宣告"，跳过检查而不是拒绝——
/// 与前几项一致，不把版本兼容性做成硬门槛。
fn check_server_caps(caps: &proto::Caps, enable_delta: bool) -> anyhow::Result<()> {
    if caps.caps.is_empty() || !enable_delta {
        // 关掉增量路径时本端只发原样编码，不依赖对端宣告任何东西
        return Ok(());
    }
    for need in ["tokenstream", "zstd"] {
        if !caps.caps.iter().any(|c| c == need) {
            anyhow::bail!(
                "服务端未宣告 {need}（它宣告的是 {:?}）：本端的增量/压缩路径会发这种编码，\
                 对端很可能拒收。两端版本不一致应当在这里失败，而不是请求发到一半才报错",
                caps.caps
            );
        }
    }
    Ok(())
}

/// 本端在 `Hello` 里宣称的能力。
///
/// # 为什么把它单独拎出来
///
/// 这些字符串是**跨实现契约**：服务端逐个字面比对（`c == "stream-zstd"`）。
/// 它们此前散在结构体字面量里，**少一个既不会编译失败、也不会测试失败**——
/// 实测就栽在这里：`stream-zstd` 漏了，于是服务端判定
/// `client_stream_zstd == false`，整条慢路径（设计 §6.3）在生产与全部端到端测试里
/// **从未被启用**；`slow_path.rs` 那组测试测的其实是快路径，
/// `--slow-flush-ms` / `--slow-flush-bytes` 两个开关也因此形同不存在。
///
/// 客户端**解码侧早就实现了**（`STREAM_ZSTD` → `StreamDecompressor`），
/// 所以这不是"没实现"，而是"没声明"——比没实现更难发现。
/// 现在有单元测试钉住这份清单，删一个就会红。
fn client_caps() -> Vec<String> {
    [
        // 传输：WS 隧道
        "ws",
        // 编码：原样 / TokenStream / 整段 zstd
        "raw",
        "tokenstream",
        "zstd",
        // 流式 zstd（慢路径）。**服务端按它决定要不要启用慢路径**。
        "stream-zstd",
        // 请求准入：服务端取得活跃槽位后才允许客户端发送请求体。
        "stream-ready",
        // ⚠️ **刻意不声明 `"resume"`**（缺口 #2 的服务端半边已就绪，客户端半边未做 ✗）。
        //
        // 服务端一旦看到这个能力位，就会在客户端断线期间**继续消费上游**并缓冲
        // （设计 §11.2 的"hold + 缓冲" ✓）。而"会续传"必须真的成立 —— 客户端要先做到：
        // 重连后按流发 `RESUME{req_id, ack_seq}`、并把该流的接收端**重挂到新会话**上
        // （否则重放的帧没有接收者 ✗）。
        // 在只做了一半的时候就声明它，等于让服务端**白烧上游 token** ✗✗ —— 那是真金白银，
        // 比"功能没做完"严重得多。等客户端半边落地时再一起加上 ✓。
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

fn check_caps_compatible(caps: &proto::Caps) -> anyhow::Result<()> {
    let our_frame = llm_proxy_core::config::MAX_FRAME_BYTES as u32;
    if caps.max_frame_bytes != 0 && caps.max_frame_bytes != our_frame {
        anyhow::bail!(
            "帧上限不一致：服务端 {} 本端 {}——切帧按本端上限走，\
             超出服务端上限的帧会被 TOO_LARGE 拒收。两端必须用同一份块参数",
            caps.max_frame_bytes,
            our_frame
        );
    }
    let our_window = llm_proxy_core::config::WINDOW_LOG;
    if caps.window_log != 0 && caps.window_log != our_window {
        anyhow::bail!(
            "zstd 窗口不一致：服务端 2^{} 本端 2^{}——压缩帧绑定窗口（字典也受它约束），\
             不一致会导致解压失败或字典装不下",
            caps.window_log,
            our_window
        );
    }
    Ok(())
}

fn spawn_session_pump(mux: Mux, mut inbox: mpsc::Receiver<Frame>, proxy: std::sync::Weak<Proxy>) {
    tokio::spawn(async move {
        while let Some(f) = inbox.recv().await {
            match f.ty {
                FrameType::Ping => {
                    let _ = mux.send_session(FrameType::Pong, Vec::new()).await;
                }
                FrameType::Err => {
                    if let Ok(e) = proto::Err::decode(&f.payload[..]) {
                        tracing::warn!(
                            code = e.code, detail = %e.detail, hint = %e.hint,
                            "服务端错误（会话级）"
                        );
                    }
                }
                FrameType::GoAway => {
                    // **接到既有的链路失效路径上**（设计 §15 早就写明这条，缺口 #7 的另一半）。
                    //
                    // 原先这里只是 `break`：会话泵停掉之后连 PING/ERR 都不再处理，
                    // 而且**既不降级也不重连** ⇒ `GOAWAY` 形同忽略 ✗。
                    //
                    // 现在：置链路失效 ⇒ 请求路径上的 `route()` 当场翻档（没有 502 窗口 ✓），
                    // `supervise` 轮询到链路为空就带退避重连 ✓。
                    //
                    // **刻意不 `break`**：会话泵要继续应答 PING/ERR，并把这条会话上**已经在途**的流
                    // 读完——服务端排空时会先把手上的流送完再关连接 ✓。若在这里 break，
                    // 我们就会把那批"服务端正要好好送完"的响应自己丢掉 ✗（与排空的目的正好相反）。
                    tracing::warn!("服务端要求关闭会话（GOAWAY）：立即降级为直连上游，后台重连");
                    if let Some(p) = proxy.upgrade() {
                        p.enter_bypass();
                    }
                }
                _ => {}
            }
        }
    });
}

/// 链路守护：断线即降级为直连，后台带退避重连，恢复后切回 WS。
///
/// **降级必须是即时的**（不等这个循环）：请求路径上的 [`Proxy::route`] 会当场发现
/// 链路失效并翻档，把"链路断掉 → 发现"之间的 502 窗口从数百毫秒压到微秒级。
/// 这个循环负责的是**恢复**，所以它可以慢、可以有退避。
async fn supervise(proxy: ProxyShared) {
    let min = Duration::from_millis(proxy.cfg.reconnect_min_ms.max(50));
    let max = Duration::from_millis(proxy.cfg.reconnect_max_ms.max(proxy.cfg.reconnect_min_ms));
    let mut backoff = min;

    loop {
        let alive = proxy
            .link
            .read()
            .unwrap()
            .as_ref()
            .map(|l| !l.mux.is_closed())
            .unwrap_or(false);
        if alive {
            backoff = min;
            tokio::time::sleep(Duration::from_millis(300)).await;
            continue;
        }

        if proxy.mode().is_tunnel() {
            tracing::warn!("DSHP 链路已失效，降级为直连上游");
            proxy.enter_bypass();
            proxy.stats.bypass_switches.fetch_add(1, Ordering::Relaxed);
        }

        proxy
            .stats
            .reconnect_attempts
            .fetch_add(1, Ordering::Relaxed);
        match connect_link_guarded(&proxy.cfg, &proxy).await {
            Ok(link) => {
                tracing::info!("已恢复 DSHP 链路，切回 WS 模式");
                proxy.install(link);
                backoff = min;
            }
            Err(e) => {
                tracing::debug!(%e, backoff_ms = backoff.as_millis() as u64, "重连失败");
                // ±25% 抖动：多客户端同时掉线时避免同时重连造成惊群
                let jitter = {
                    let seed = proxy.stats.reconnect_attempts.load(Ordering::Relaxed);
                    let span = (backoff.as_millis() as u64) / 4 + 1;
                    seed.wrapping_mul(2_654_435_761) % span
                };
                tokio::time::sleep(backoff + Duration::from_millis(jitter)).await;
                backoff = (backoff * 2).min(max);
            }
        }
    }
}
async fn handshake(
    mux: &Mux,
    inbox: &mut mpsc::Receiver<Frame>,
    cfg: &Config,
) -> anyhow::Result<proto::Caps> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let nonce = {
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        t ^ (cfg.listen.len() as u64).rotate_left(17)
    };
    let hmac = llm_proxy_transport::handshake_mac(cfg.psk.as_bytes(), nonce, ts);

    let patch_dict = llm_proxy_core::dict::Dicts::bootstrap().patch;
    // 握手第一步：用 CSPRNG 生成临时 X25519 密钥对，公钥随 Hello 上送。
    // PSK 提供认证，X25519 提供前向保密（设计 §13.4）。
    let hs = llm_proxy_core::crypto::Initiator::new(cfg.psk.as_bytes())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let our_pub = hs.public();
    let hello = proto::Hello {
        proto_version: llm_proxy_core::config::PROTO_VERSION.to_string(),
        // 租户随 Hello 上送；服务端校验不一致会**直接拒绝连接**（设计 §4.1）。
        // 早先这里恒发空串：协议留了字段、实现里被忽略，于是两个不同租户
        // 实际共享同一套缓存命名空间——正是 §13.9/T7 要防的事。
        tenant: cfg.tenant.clone(),
        dict_id: llm_proxy_core::dict::dict_id(patch_dict),
        dict: patch_dict.to_vec(),
        nonce,
        timestamp_ms: ts,
        hmac,
        caps: client_caps(),
        x25519_pub: our_pub.to_vec(),
    };
    mux.send_session(FrameType::Hello, hello.encode_to_vec())
        .await?;

    let f = loop {
        let f = inbox
            .recv()
            .await
            .context("握手期连接在收到 Caps 之前就关闭了")?;
        match f.ty {
            FrameType::Caps => break f,
            FrameType::Err => {
                let e = proto::Err::decode(&f.payload[..]).unwrap_or_default();
                anyhow::bail!(
                    "服务端拒绝握手（code={}）：{}。\
                     最常见原因是两端 DSHP_PSK 不一致——具体原因见服务端日志\
                     （它刻意不把细节回给未认证的来源）。",
                    e.code,
                    e.detail
                );
            }
            _ => continue,
        }
    };
    let caps = proto::Caps::decode(&f.payload[..]).context("Caps 解码失败")?;

    // 握手第二步：与服务端公钥完成 DH，派生出会话密钥，并**校验服务端确认值**。
    // 不校验它等于没有双向认证——假 server 可以据此诱骗 client 交出上游 API key
    // （设计 §13.8 明确列为不可省略）。
    let their_pub: [u8; 32] = caps
        .x25519_pub
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Caps 里的 X25519 公钥长度不是 32 字节"))?;
    let done = hs.finish(their_pub);
    done.verify_peer(&caps.confirm)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // 块参数一致性：`Caps` 里宣告了 `max_frame_bytes` 与 `window_log`，客户端必须查。
    check_caps_compatible(&caps)?;

    // **反方向的能力协商**：服务端宣告的接收能力必须覆盖本端将要发送的编码。
    check_server_caps(&caps, cfg.enable_delta)?;

    // **双向**校验租户（设计 §4.1：两端都配置、校验一致，不一致直接拒绝）。
    // 服务端也做同向校验，这里再查一遍是为了防"连错服务端"——连到另一个租户的
    // 出口代理时，命名空间会错位，而客户端侧那时早已把缓存灌进了错误的命名空间。
    if caps.tenant != cfg.tenant {
        anyhow::bail!(
            "服务端租户不一致：服务端 {:?} 本端 {:?}——拒绝使用该连接（设计 §4.1）",
            caps.tenant,
            cfg.tenant
        );
    }

    mux.enable_crypto(llm_proxy_transport::SessionCrypto::new(&done.keys, true));

    // 握手第三步：回送本端确认值。此时 AEAD 已开启，这条帧是密文——
    // 「能发出合法密文」本身已经证明了 PSK 知识，确认值是第二道显式认证。
    let kc = proto::KeyConfirm {
        confirm: done.our_confirm.to_vec(),
    };
    mux.send_session(FrameType::KeyConfirm, kc.encode_to_vec())
        .await?;

    // 两端 upstream_host 必须一致，否则缓存命名空间会错位（设计 §4.1）
    if !caps.upstream_host.is_empty() && caps.upstream_host != cfg.upstream_host {
        anyhow::bail!(
            "upstream_host 不一致：客户端 {} vs 服务端 {}。\
             这会导致两端缓存命名空间错位，必须修正配置。",
            cfg.upstream_host,
            caps.upstream_host
        );
    }
    Ok(caps)
}

async fn handle(proxy: ProxyShared, req: Request<Incoming>) -> Response<RespBody> {
    if req.uri().path() == "/__dshp/status" {
        return status(&proxy);
    }
    match forward(proxy.clone(), req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(?e, "转发失败");
            err_body(502, format!("{e:#}"))
        }
    }
}

fn status(proxy: &ProxyShared) -> Response<RespBody> {
    let s = &proxy.stats;
    let raw = s.req_raw_bytes.load(Ordering::Relaxed);
    let wire = s.req_wire_bytes.load(Ordering::Relaxed);
    let resp_raw = s.resp_raw_bytes.load(Ordering::Relaxed);
    let resp_wire = s.resp_wire_bytes.load(Ordering::Relaxed);
    let resp_saved = if resp_raw > 0 && resp_wire > 0 {
        1.0 - (resp_wire as f64 / resp_raw as f64)
    } else {
        0.0
    };
    // json! 宏不接受块表达式作值，先把分解值都算出来
    let n_defs = s.resp_template_defs.load(Ordering::Relaxed);
    let n_batches = s.resp_batch_frames.load(Ordering::Relaxed);
    let n_items = s.resp_batch_items.load(Ordering::Relaxed);
    let header_bytes = (n_defs + n_batches) * llm_proxy_core::frame::HEADER_LEN as u64;
    let def_bytes = s.resp_template_def_bytes.load(Ordering::Relaxed);
    let raw_item_bytes = s.resp_raw_items_bytes.load(Ordering::Relaxed);
    let var_bytes = s.resp_var_bytes.load(Ordering::Relaxed);
    let (link_ok, caps_dict_id, caps_upstream_host, aead_enabled, aead) = {
        let l = proxy.link.read().unwrap();
        match l.as_ref() {
            Some(l) => (
                !l.mux.is_closed(),
                l.caps.dict_id,
                l.caps.upstream_host.clone(),
                l.mux.crypto_enabled(),
                l.mux.crypto_stats().unwrap_or((0, 0, 0)),
            ),
            None => (false, 0, String::new(), false, (0, 0, 0)),
        }
    };
    // **第 192 轮加的传输侧判据** ✓：这两个计数器此前**只有服务端**状态里有 ✓，
    // 客户端看不到 ⇒ "帧到底有没有在传输侧被丢"是个**黑箱** ✗ ⇒ 排查 	erminated 卡在这里很久 ✓。
    // Mux::dropped_frames 会数：未绑定流超过暂存上限（PENDING_MAX_STREAMS/BYTES ✓）
    // 而来、或绑已解绑流的帧 ✓ —— 两者都会让 TemplateDef **凭空消失** ✓，
    // 表现正是"批量帧引用了表里没有的模板 id" ⇒ UnknownTemplate ✓。
    let (mux_dropped, mux_received) = {
        let l = proxy.link.read().unwrap();
        match l.as_ref() {
            Some(l) => (l.mux.dropped_frames(), l.mux.received_frames()),
            None => (0, 0),
        }
    };
    // 模板表现在**按连接**存放（见 [`Link::templates`]）⇒ 这里只能报**当前链路**那张表；
    // 没有链路时（正在重连 / 已降级直连）报 0 —— 那时本来也没有模板在用 ✓。
    let (n_templates_held, n_templates_evicted, n_templates_min, n_templates_max) = {
        let cur = proxy.link.read().unwrap();
        match cur.as_ref() {
            Some(l) => {
                let st = l.templates.lock().unwrap();
                let lo = st.id_min();
                let hi = st.id_max();
                (st.len(), st.evicted(), lo, hi)
            }
            None => (0, 0, 0, 0),
        }
    };
    // **注意**：不能再往下面那个 `json!` 里加字段了——第 62 轮加了一个
    // `store_no_cross` 就撞上 `json_internal!` 的**递归上限**（默认 128）✗。
    // 需要加字段时用宏之后的赋值（见紧邻的下一行），别去动 `json!` 的体积。
    let mut json = serde_json::json!({
        // `mode` 是**选定**的模式：重连成功时置位，只有在请求路径上发现链路已断
        // 才降到 `bypass`（设计 §10.1：健康检查放在请求路径上，才有"断线当场降级"
        // 而没有 502 窗口）。所以它**不是存活信号**——判断链路是否真的活着要用
        // `link_alive`。这里原本还有一行重复的 `"mode": "ws"`（被这行覆盖，
        // 纯装饰但会误导读者与测试），已删。
        "mode": proxy.mode().name(),
        "listen": proxy.cfg.listen,
        "server": proxy.cfg.server,
        "link_ms": s.link_ms.load(Ordering::Relaxed),
        "link_alive": link_ok,
        "upstream_fallback": proxy.cfg.upstream_fallback,
        "bypass_switches": s.bypass_switches.load(Ordering::Relaxed),
        "recoveries": s.recoveries.load(Ordering::Relaxed),
        "bypass_requests": s.bypass_requests.load(Ordering::Relaxed),
        "reconnect_attempts": s.reconnect_attempts.load(Ordering::Relaxed),
        "dict_id": caps_dict_id,
        "upstream_host": caps_upstream_host,
        "delta_enabled": proxy.cfg.enable_delta,
        "requests": s.requests.load(Ordering::Relaxed),
        "delta_requests": s.delta_requests.load(Ordering::Relaxed),
        "compressed_requests": s.compressed_requests.load(Ordering::Relaxed),
        "delta_fallbacks": s.delta_fallbacks.load(Ordering::Relaxed),
        "req_raw_bytes": raw,
        "req_wire_bytes": wire,
        "req_saved_ratio": if raw > 0 { 1.0 - (wire as f64 / raw as f64) } else { 0.0 },
        "ref_blocks": s.ref_blocks.load(Ordering::Relaxed),
        "forgotten_blocks": s.forgotten_blocks.load(Ordering::Relaxed),
        "resp_bytes": s.resp_bytes.load(Ordering::Relaxed),
        "resp_wire_bytes": resp_wire,
        "resp_raw_bytes": resp_raw,
        "resp_saved_ratio": resp_saved,
        "template_miss": s.template_miss.load(Ordering::Relaxed),
        "truncated_responses": s.truncated_responses.load(Ordering::Relaxed),
    "cancel_attempts": s.cancel_attempts.load(Ordering::Relaxed),
    "cancel_sent": s.cancel_sent.load(Ordering::Relaxed),
    "pings_sent": s.pings_sent.load(Ordering::Relaxed),
    "keepalive_sec": proxy.cfg.keepalive_sec,
    "pings_failed": s.pings_failed.load(Ordering::Relaxed),
    "pings_skipped": s.pings_skipped.load(Ordering::Relaxed),
        // 链路占用的精确分解——用于判断瓶颈在帧头、模板定义还是变量槽
        "resp_frames": {
            "template_defs": n_defs,
            "batch_frames": n_batches,
            "items": n_items,
            "header_bytes": header_bytes,
        },
        "resp_breakdown": {
            "template_def_bytes": def_bytes,
            "raw_items_bytes": raw_item_bytes,
            "var_bytes": var_bytes,
        },
        "aead": {
            "enabled": aead_enabled,
            "sealed_frames": aead.0,
            "opened_frames": aead.1,
            "plaintext_exempt": aead.2,
        },
        "template_store": {
            "held": n_templates_held,
            "evicted": n_templates_evicted,
        },
        "known_blocks": proxy.uploads.lock().unwrap().len(),
    });
    // 决策 12 的合规指标：宏之后赋值（不动 `json!` 的体积，见上面那段说明）。
    // **模板 id 区间（第 200 轮加）**：现场 `terminated` 的根因是"模板 id 每会话从 1 开始"
    // ⇒ 多会话共用一张表时 id 互相覆盖 ⇒ 表出洞 ⇒ `UnknownTemplate`。
    // 修法是"进程级唯一签发" ⇒ **不同会话的 id 区间必须不相交** ⇒ 这两个数就是它的判据 ✓。
    json["template_ids"] = serde_json::json!({ "min": n_templates_min, "max": n_templates_max });
    // **`json!` 的体积必须控制**：加字段会让 `json_internal!` 触发**递归上限** ✗
    //（第 62 轮踩过、第 199 轮又踩：直接编译失败 ✓）⇒ 新字段一律放在宏之后赋值 ✓。
    json["compress"] = serde_json::json!({
        "used": proxy.compress.stats().used,
        "skipped_small": proxy.compress.stats().skipped_small,
        "skipped_busy": proxy.compress.stats().skipped_busy,
        "skipped_incompressible": proxy.compress.stats().skipped_incompressible,
        "available": proxy.compress.available(),
    });
    // `mux_frames` 从宏里挪出来 ✓（同因：减宏体积 ✓；第 192 轮加的传输侧判据 ✓）。
    json["mux_frames"] = serde_json::json!({
        "dropped": mux_dropped,
        "received": mux_received,
    });
    json["store_no_cross"] = serde_json::json!(s.store_no_cross.load(Ordering::Relaxed));
    json["last_delta_head"] = serde_json::json!(s
        .last_delta_head
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default());
    let json = json.to_string();
    Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, "application/json")
        .body(full(json.into_bytes()))
        .unwrap()
}

/// 一次请求的静态部分。
struct Outgoing {
    method: String,
    path_and_query: String,
    headers: Vec<proto::Header>,
}

/// 请求体来源：已缓冲或流式。
enum Payload {
    Buf(Vec<u8>),
    Stream(Incoming),
}

enum Outcome {
    /// 拿到响应头，后续帧在此接收端上。
    Head(u32, mpsc::Receiver<Frame>, proto::RespHead),
    /// 服务端明确返回错误——交给调用方决定降级。
    Remote(proto::Err),
}

async fn forward(proxy: ProxyShared, req: Request<Incoming>) -> anyhow::Result<Response<RespBody>> {
    let method = req.method().clone();
    // path 与 query **原样保留**，不做任何映射（设计 §4.1）
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let headers: Vec<proto::Header> = req
        .headers()
        .iter()
        .map(|(k, v)| proto::Header {
            name: k.as_str().to_string(),
            value: v.as_bytes().to_vec(),
        })
        .collect();
    let content_length: Option<u64> = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    let out = Outgoing {
        method: method.as_str().to_string(),
        path_and_query,
        headers,
    };

    proxy.stats.requests.fetch_add(1, Ordering::Relaxed);

    // 先定路线。链路失效时这里会**当场**翻到直连，而不是等 supervisor 轮询发现——
    // 否则那几百毫秒里所有请求都会拿到 502。
    let link = match proxy.route() {
        Ok(l) => l,
        Err(_) => {
            proxy.stats.bypass_requests.fetch_add(1, Ordering::Relaxed);
            return bypass_forward(proxy, out, req.into_body()).await;
        }
    };

    // 只有长度已知且不超上限时才走增量；否则流式原样（不缓冲，保护 ARM 内存）
    let delta_ok = proxy.cfg.enable_delta
        && content_length.is_some_and(|n| n as usize <= proxy.cfg.max_decompose_bytes);

    let (parts, incoming) = req.into_parts();
    let _ = parts;

    if delta_ok {
        let body = BodyExt::collect(incoming)
            .await
            .context("读本地请求体失败")?
            .to_bytes()
            .to_vec();
        return Ok(delta_with_fallback(proxy, link, out, body).await);
    }

    match run_stream(
        &link,
        &out,
        proto::Encoding::EncRaw,
        Vec::new(),
        Payload::Stream(incoming),
    )
    .await?
    {
        Outcome::Head(sid, rx, head) => Ok(build_response(
            &link.mux,
            Arc::clone(&proxy.stats),
            Arc::clone(&link.templates),
            sid,
            rx,
            head,
        )),
        Outcome::Remote(e) => {
            // 原样转发也拿到服务端错误：如实上报，不再降级（已经是最底层）
            Ok(err_body(
                502,
                format!("服务端错误 {}：{}", e.code, e.detail),
            ))
        }
    }
}

/// 请求是否要求**禁用跨请求前缀复用**（设计决策 12）。
///
/// `/v1/responses` 的 `store=true` 意味着这份对话由上游保存，代理必须保守处理：
/// **不许靠历史请求留下的块来拼这份 body**，只做单请求内的压缩。
///
/// 实现要点：跨请求复用在两端都不靠"基线字节"，而靠**块指纹 + `REF`**
/// （服务端解引用只需要块）。所以"禁用"= **不要声称对端已经有这些块**：
/// 谓词恒为 `false` ⇒ 每个块都按 `LITERAL` 发，整段自包含。
/// **单请求内**的去重仍然生效（同一 body 内重复的块只发一次、其余走 `REF`），
/// 那正是决策 12 允许的「只做单请求内压缩」。
///
/// 为什么用 `serde_json` 而不是在字节里搜 `store`：空格写法（`"store": true`）、
/// 以及正文里恰好出现的同名字符串都会骗过搜索——**猜字段名与猜语义都是红线**。
/// 解析失败（不是 JSON）时返回 `false`，即维持原有行为。
fn disables_cross_request_reuse(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("store").and_then(|s| s.as_bool()))
        .unwrap_or(false)
}

/// 增量路径 + 降级链：`增量 → 忘掉缺块重试增量 → 全量原样`。
async fn delta_with_fallback(
    proxy: ProxyShared,
    link: Arc<Link>,
    out: Outgoing,
    body: Vec<u8>,
) -> Response<RespBody> {
    let stats = Arc::clone(&proxy.stats);
    stats
        .req_raw_bytes
        .fetch_add(body.len() as u64, Ordering::Relaxed);

    // 决策 12：`store=true` ⇒ 本次请求不许用历史请求的块（见上面那段说明）。
    let no_cross = disables_cross_request_reuse(&body);
    // 直接观测判定当时的输入（前 32 字节）：缺口 13 排查用，也方便线上核对。
    if let Ok(mut g) = stats.last_delta_head.lock() {
        *g = String::from_utf8_lossy(&body[..body.len().min(32)]).into_owned();
    }
    if no_cross {
        stats.store_no_cross.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(
            bytes = body.len(),
            "store=true：禁用跨请求前缀复用，本次请求自包含"
        );
    }

    // 客户端进程之间不共享 UploadSet，但服务端 BlockStore 是跨 session、跨设备的。
    // 本地账本为空时先做一次“全 REF 探测”：服务端只返回真正缺失的块，成功后把
    // 未列入缺失清单的指纹写入本地账本。这样相同 system prompt 在另一台设备上
    // 也能复用服务端已有块，而不必先传一遍完整 literal。
    let mut probe_server_cache = !no_cross && proxy.uploads.lock().unwrap().is_empty();

    // 冷启动（一个块都复用不上）改走整段压缩。
    //
    // 此时 TokenStream 会退化成"全 literal"，体积约等于 body 本身，还要多付每块
    // 1~3 字节标签；而 zstd + dict_patch 能把它压到零头。真实量级 3 MB 的首个请求
    // 是这条路径的主要成本来源。
    //
    // 服务端在压缩路径上会**解压后切块入库**，两端对"有哪些块"的认知因此仍然一致，
    // 所以这次改道不会让后续请求退回冷启动。
    let cold = {
        let uploads = proxy.uploads.lock().unwrap();
        llm_proxy_core::decompose(proxy.ns, &body, |fp| !no_cross && uploads.believes(fp)).refs == 0
    };
    // **优先级（第 199 轮接手时修正）**：冷启动**先试整段压缩**，压缩不可用才去探测跨设备缓存。
    //
    // 原来这里是 `cold && !probe_server_cache && …` —— 而 `probe_server_cache` 在
    // **本地账本为空**时就为真（100% 的冷启动都是）⇒ 冷启动走整段压缩这条路径
    // **永远被挡住** ⇒ 现场表现：`compressed_requests=0`、`req_wire_bytes ≈ req_raw_bytes`
    //（省 0%）、`known_blocks=80`（改成走了全 REF 探测 ⇒ 探测成功后记账）。
    //
    // 为什么压缩优先才对：
    // * 冷启动的语义就是「一个块都复用不上」⇒ 此时**必须先有一个全量传输**把内容送到，
    //   而整段压缩正是「用 zstd 把它压到零头」的路径 ⇒ 它比全 REF 探测**省得多**；
    // * 跨设备缓存的收益是「**另一个**设备已有这些块」⇒ 那属于**压缩不可用**时的兜底，
    //   不该抢在压缩前面。
    // ⇒ 压缩成功 ⇒ 服务端解压后切块入库 ⇒ 后续请求自然转增量（探测仍随时兜底）。
    if cold && proxy.compress.try_compress(&body).is_some() {
        tracing::debug!(bytes = body.len(), "冷启动，改走整段压缩");
        return raw_response(proxy, Arc::clone(&link), out, body).await;
    }

    // 最多两次增量尝试：第二次是在忘掉服务端报告的缺块之后
    for attempt in 0..2 {
        let all_fps = llm_proxy_cache::all_block_fps(proxy.ns, &body);
        let d = {
            let uploads = proxy.uploads.lock().unwrap();
            llm_proxy_core::decompose(proxy.ns, &body, |fp| {
                !no_cross && (probe_server_cache || uploads.believes(fp))
            })
        };
        let target_fp = body_fp(proxy.ns, &body).as_bytes().to_vec();

        let started = Instant::now();
        let outcome = run_stream(
            &link,
            &out,
            proto::Encoding::EncTokenstream,
            target_fp,
            Payload::Buf(d.stream.clone()),
        )
        .await;

        let outcome = match outcome {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(attempt, ?e, "增量请求失败，降级为全量");
                stats.delta_fallbacks.fetch_add(1, Ordering::Relaxed);
                return raw_response(proxy, Arc::clone(&link), out, body).await;
            }
        };

        match outcome {
            Outcome::Head(sid, rx, head) => {
                // 提交点已过：记账并统计
                {
                    let mut u = proxy.uploads.lock().unwrap();
                    // 请求自己的 `d.new_fps` 才是事务边界；不能使用 UploadSet
                    // 的共享 pending 列表，否则并行 stream 的 rollback/commit 会互相污染。
                    if probe_server_cache {
                        u.observe_present(all_fps.iter());
                    } else {
                        u.commit_sent(d.new_fps.iter());
                    }
                }
                stats.delta_requests.fetch_add(1, Ordering::Relaxed);
                stats
                    .req_wire_bytes
                    .fetch_add(d.stream.len() as u64, Ordering::Relaxed);
                stats.ref_blocks.fetch_add(d.refs as u64, Ordering::Relaxed);
                tracing::debug!(
                    body = body.len(),
                    wire = d.stream.len(),
                    blocks = d.blocks,
                    refs = d.refs,
                    ratio = format!("{:.4}", d.ratio()),
                    elapsed_us = started.elapsed().as_micros(),
                    "增量发送完成"
                );
                return build_response(
                    &link.mux,
                    Arc::clone(&proxy.stats),
                    Arc::clone(&link.templates),
                    sid,
                    rx,
                    head,
                );
            }
            Outcome::Remote(e) => {
                // 缺口 14：**显式认出来**，否则日志里只剩裸的 `code 18` ✗
                // （运维得去翻协议表才知道是什么 ✓）。它天然不满足下面的 `recoverable`
                // 条件（那个要求 `BLOCK_MISS` + `SEND_MISSING` ✓）⇒ **不会重试** ✓，
                // 这正是我们要的：重试只会再撞一次同一个拒绝 ✓。
                if e.code == err_code::REQ_REPLAY || e.hint == hint::DUPLICATE_REQ_ID {
                    tracing::warn!(
                        code = e.code,
                        hint = %e.hint,
                        "重复的 req_id（缺口 14）：服务端拒绝重放上游 ⇒ 本条请求不重试"
                    );
                }
                let recoverable = e.code == err_code::BLOCK_MISS
                    && e.hint == hint::SEND_MISSING
                    && attempt == 0
                    && !e.missing.is_empty();
                if recoverable {
                    if probe_server_cache {
                        let missing: std::collections::HashSet<_> = e
                            .missing
                            .iter()
                            .filter_map(|b| llm_proxy_core::Fp::from_slice(b))
                            .collect();
                        // `observe_present` 要的是 `Item = &Fp` ✓，而 `.copied()` 会把它变成值 ✗
                        // ⇒ 类型对不上 ✓（第 199 轮接手时修 ✓）。
                        let present = all_fps.iter().filter(|fp| !missing.contains(*fp));
                        proxy.uploads.lock().unwrap().observe_present(present);
                    }
                    // 精确遗忘服务端报告缺的那些块，再试一次增量。
                    // 比整本清空便宜得多：服务端可能只淘汰了少量块。
                    let fps: Vec<llm_proxy_core::Fp> = e
                        .missing
                        .iter()
                        .filter_map(|b| llm_proxy_core::Fp::from_slice(b))
                        .collect();
                    let n = proxy.uploads.lock().unwrap().forget(fps.iter());
                    stats
                        .forgotten_blocks
                        .fetch_add(n as u64, Ordering::Relaxed);
                    tracing::info!(forgot = n, "服务端缺块，遗忘后重试增量");
                    // 探测只应发生在第一次尝试；第二次必须对缺块发送 literal，
                    // 同时继续复用服务端已经确认存在的公共块。
                    probe_server_cache = false;
                    continue;
                }
                tracing::warn!(
                    code = e.code, hint = %e.hint, attempt,
                    "增量路径不可用，降级为全量"
                );
                stats.delta_fallbacks.fetch_add(1, Ordering::Relaxed);
                return raw_response(proxy, Arc::clone(&link), out, body).await;
            }
        }
    }
    // 两次都用完（理论上不可达）
    stats.delta_fallbacks.fetch_add(1, Ordering::Relaxed);
    raw_response(proxy, link, out, body).await
}

/// 用已缓冲的 body 走原样路径，**先试压缩**。
///
/// 这条路径是「冷启动 / 缓存未命中」的整段回退：要把整个 body 原样发出，
/// 真实量级 3 MB。zstd + dict_patch 是这里唯一能显著削减上行的手段。
///
/// 压缩失败、压不小、或池忙时**原样发送**——`try_compress` 返回 `None` 就代表这三种情况，
/// 它们都不是错误。
async fn raw_response(
    proxy: ProxyShared,
    link: Arc<Link>,
    out: Outgoing,
    body: Vec<u8>,
) -> Response<RespBody> {
    // 先试压缩。压缩后的字节与原文都留着：服务端若因版本旧而不认识 ENC_ZSTD，
    // 我们用原文原样重发一次。这次重试是**安全的**——服务端是在转发上游**之前**
    // 就拒绝了编码（提交点未过），上游没有看到任何请求。
    if let Some(c) = proxy.compress.try_compress(&body) {
        let wire = c.len() as u64;
        tracing::debug!(
            original = body.len(),
            compressed = c.len(),
            ratio = format!("{:.4}", c.len() as f64 / body.len().max(1) as f64),
            "整段 body 已压缩"
        );
        match run_stream(
            &link,
            &out,
            proto::Encoding::EncZstd,
            Vec::new(),
            Payload::Buf(c),
        )
        .await
        {
            Ok(Outcome::Head(sid, rx, head)) => {
                // 服务端在压缩路径上会切块入库。CDC 是内容定义的，两端切出的块必然
                // 一致，所以客户端可以自行算出这批指纹并记账——下一个请求就能走增量的
                // REF 而非再次整段重发。
                {
                    let mut uploads = proxy.uploads.lock().unwrap();
                    let fps = llm_proxy_cache::all_block_fps(proxy.ns, &body);
                    // 压缩路径同样在响应头到达后提交本请求自己的指纹集合。
                    uploads.commit_sent(fps.iter());
                }
                proxy
                    .stats
                    .compressed_requests
                    .fetch_add(1, Ordering::Relaxed);
                proxy
                    .stats
                    .req_wire_bytes
                    .fetch_add(wire, Ordering::Relaxed);
                return build_response(
                    &link.mux,
                    Arc::clone(&proxy.stats),
                    Arc::clone(&link.templates),
                    sid,
                    rx,
                    head,
                );
            }
            Ok(Outcome::Remote(e)) => tracing::warn!(
                code = e.code,
                detail = %e.detail,
                "服务端不接受 ENC_ZSTD，改以原样重发"
            ),
            Err(e) => return err_body(502, format!("{e:#}")),
        }
    }
    let body_len = body.len() as u64;
    match run_stream(
        &link,
        &out,
        proto::Encoding::EncRaw,
        Vec::new(),
        Payload::Buf(body),
    )
    .await
    {
        Ok(Outcome::Head(sid, rx, head)) => {
            proxy
                .stats
                .req_wire_bytes
                .fetch_add(body_len, Ordering::Relaxed);
            build_response(
                &link.mux,
                Arc::clone(&proxy.stats),
                Arc::clone(&link.templates),
                sid,
                rx,
                head,
            )
        }
        Ok(Outcome::Remote(e)) => err_body(502, format!("服务端错误 {}：{}", e.code, e.detail)),
        Err(e) => err_body(502, format!("{e:#}")),
    }
}

/// **L2 直连上游**：DSHP 链路不可用时的回退路径（设计 §10 降级链末端）。
///
/// 它保证的是「功能不中断」——请求照常到达上游、响应照常返回，只是失去了
/// 增量/模板/压缩带来的流量优化。
///
/// **必须与 DSHP 路径保持同等的正确性**：header 原样（含 Host）、path/query 原样、
/// 响应逐字节透传。任何"顺手清理"都会让降级路径与正常路径行为不一致，而那种不一致
/// 只会在链路出问题的时候暴露出来——最难排查的时机。
async fn bypass_forward(
    proxy: ProxyShared,
    out: Outgoing,
    incoming: Incoming,
) -> anyhow::Result<Response<RespBody>> {
    let Some(url) = proxy.cfg.fallback_url(&out.path_and_query) else {
        return Ok(err_body(
            502,
            "DSHP 链路不可用，且未配置 --upstream-fallback。\
             此时不是「降级」而是「不可用」——请配置该项以获得直连兜底。",
        ));
    };

    let mut builder = Request::builder().method(out.method.as_str()).uri(&url);
    for h in &out.headers {
        if let (Ok(n), Ok(v)) = (
            http::HeaderName::from_bytes(h.name.as_bytes()),
            http::HeaderValue::from_bytes(&h.value),
        ) {
            builder = builder.header(n, v);
        }
    }
    // HttpClient 的 body 类型是 ChannelBody，本地请求体是 Incoming，必须转接一次
    let cl = out
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .and_then(|h| std::str::from_utf8(&h.value).ok())
        .and_then(|s| s.parse::<u64>().ok());
    let (tx, chan) = ChannelBody::channel();
    let chan = match cl {
        Some(n) => chan.with_exact_size(n),
        None => chan,
    };
    tokio::spawn(async move {
        let mut incoming = incoming;
        while let Some(f) = BodyExt::frame(&mut incoming).await {
            match f {
                Ok(f) => {
                    if let Ok(d) = f.into_data() {
                        if !d.is_empty() && tx.send(Ok(d)).await.is_err() {
                            return;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(?e, "本地请求体读取失败");
                    return;
                }
            }
        }
    });
    let req = builder.body(chan).context("组装直连请求失败")?;
    let resp = proxy.client.request(req).await.context("直连上游失败")?;
    tracing::debug!(%url, status = resp.status().as_u16(), "直连回退完成");
    Ok(relay_direct(resp))
}

/// 把上游响应原样转成本地响应（直连回退路径用）。
fn relay_direct(resp: Response<Incoming>) -> Response<RespBody> {
    let (parts, mut body) = resp.into_parts();
    let len: Option<u64> = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());
    let (tx, chan) = ChannelBody::channel();
    let chan = match len {
        Some(n) => chan.with_exact_size(n),
        None => chan,
    };
    tokio::spawn(async move {
        while let Some(f) = BodyExt::frame(&mut body).await {
            match f {
                Ok(f) => {
                    if let Ok(d) = f.into_data() {
                        if !d.is_empty() && tx.send(Ok(d)).await.is_err() {
                            return;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(?e, "直连上游响应体错误");
                    return;
                }
            }
        }
    });
    Response::from_parts(parts, chan.boxed())
}
/// 起一条 DSHP 流、发完请求与请求体，然后等响应头或错误。
async fn run_stream(
    link: &Link,
    out: &Outgoing,
    encoding: proto::Encoding,
    target_fp: Vec<u8>,
    payload: Payload,
) -> anyhow::Result<Outcome> {
    let (sid, mut rx) = link.mux.open_stream();

    let open = proto::ReqOpen {
        method: out.method.clone(),
        path_and_query: out.path_and_query.clone(),
        headers: out.headers.clone(),
        // **恒为空，这是有意的**（不是漏了）。
        //
        // `alt_bases` 属于更早的**前缀基线**方案（设计 §5.2）：客户端带最多 4 个候选
        // `prefix_fp(k)`，服务端选第一个本地存在的作为基线。实现走的是另一条路——
        // TokenStream 的 `REF` 是**只含指纹的内容寻址引用**（`token.rs`：`0x01 FP(24B)`，
        // 没有 offset/len），所以服务端解引用只需要**块**，从头到尾不需要任何基线字节。
        //
        // 于是"服务端只有上一轮缓存"这个 miss 由 `BLOCK_MISS` + `SEND_MISSING`
        // （遗忘缺块 → 重试增量）解决，等价效果且不需要基线：见 `recovery.rs`
        // 与 `delta.rs` 的 M1a-3。留字段是因为它属于已冻结的帧布局，
        // 删它只换来一次线格式变更、没有任何收益。
        alt_bases: Vec::new(),
        encoding: encoding as i32,
        target_fp,
        req_id: sid as u64,
        // **本流的模板表是不是空的** ✓（第 195 轮的判据 ✓，第 197 轮加自愈后闭环 ✓）。
        // 空 ⇒ 让服务端把本流引用到的模板定义一并补发 ✓；非空 ⇒ 零补发 ✓。
        // 之所以够用：一旦出现"表里有洞"的 `UnknownTemplate` ✓，
        // 下面会**清空整张表** ✓ ⇒ 下一条流这里就变成 true ✓ ⇒ 服务端全量补发 ✓。
        client_needs_defs: link.templates.lock().unwrap().is_empty(),
    };
    link.mux
        .send(Frame::new(FrameType::ReqOpen, sid, 0, open.encode_to_vec()))
        .await?;

    // 新版服务端把全局活跃槽位作为显式准入：拿到 `StreamReady` 之前不发送请求体。
    // 这样一个客户端同时提交 10~20 个请求时，排队请求不会提前把大 body 堆进
    // 服务端每条 stream 的接收 channel。旧服务端未宣告该能力时保留旧时序。
    if link.stream_ready {
        loop {
            match rx.recv().await {
                Some(f) if f.ty == FrameType::StreamReady => break,
                Some(f) if f.ty == FrameType::Err => {
                    let e = proto::Err::decode(&f.payload[..]).unwrap_or_default();
                    link.mux.unbind_stream(sid);
                    return Ok(Outcome::Remote(e));
                }
                Some(f) if f.ty == FrameType::Ping => continue,
                Some(_) => continue,
                None => anyhow::bail!("等待流准入时连接关闭"),
            }
        }
    }

    // 发请求体
    let mut seq = 1u32;
    match payload {
        Payload::Buf(buf) => {
            for chunk in buf.chunks(llm_proxy_core::config::MAX_FRAME_BYTES / 2) {
                link.mux
                    .send(Frame::new(FrameType::BodyChunk, sid, seq, chunk.to_vec()))
                    .await?;
                seq += 1;
            }
        }
        Payload::Stream(incoming) => {
            let mut body = incoming;
            while let Some(f) = BodyExt::frame(&mut body).await {
                let f = f.context("读本地请求体失败")?;
                if let Ok(data) = f.into_data() {
                    if data.is_empty() {
                        continue;
                    }
                    for chunk in data.chunks(llm_proxy_core::config::MAX_FRAME_BYTES / 2) {
                        link.mux
                            .send(Frame::new(FrameType::BodyChunk, sid, seq, chunk.to_vec()))
                            .await?;
                        seq += 1;
                    }
                }
            }
        }
    }

    // 显式结束请求体
    let mut last = Frame::new(FrameType::BodyChunk, sid, seq, Vec::new());
    last.flags = Flags::default().with(flags::LAST);
    link.mux.send(last).await?;
    link.mux
        .send(Frame::new(
            FrameType::ReqCommit,
            sid,
            seq + 1,
            proto::ReqCommit { req_id: sid as u64 }.encode_to_vec(),
        ))
        .await?;

    // 等响应头
    while let Some(f) = rx.recv().await {
        match f.ty {
            FrameType::RespHead => {
                let head = proto::RespHead::decode(&f.payload[..]).context("RespHead 解码失败")?;
                return Ok(Outcome::Head(sid, rx, head));
            }
            FrameType::Err => {
                let e = proto::Err::decode(&f.payload[..]).unwrap_or_default();
                link.mux.unbind_stream(sid);
                return Ok(Outcome::Remote(e));
            }
            FrameType::Ping => continue,
            _ => continue,
        }
    }
    anyhow::bail!("等待响应头时连接关闭")
}

/// 响应体守卫：**被 drop 时**（= SDK 先走了）给服务端发一帧 `Cancel`。
///
/// 为什么用 Drop 而不是"在泵里检测"：泵此刻正阻塞在 `rx.recv()` 上等一个**可能永不
/// 回话**的上游，它没有任何机会去看"SDK 还在不在"。而 hyper 丢弃响应体是**必然会
/// 发生**的事件——把它当信号最稳。
struct CancelOnDrop {
    inner: RespBody,
    mux: Mux,
    sid: u32,
    /// 泵正常收尾后置真：流已结束，无须再取消。
    finished: Arc<std::sync::atomic::AtomicBool>,
    /// 诊断计数（缺口 8）：守卫触发次数与成功发送次数。
    stats: Arc<Stats>,
}

impl http_body::Body for CancelOnDrop {
    type Data = bytes::Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        std::pin::Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.finished.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        // Drop 里不能 await ⇒ 丢给运行时去发。失败也无所谓：链路可能已经没了，
        // 而"没发出去"最坏退化成修复前的行为（等服务端自己发现）。
        use std::sync::atomic::Ordering as O;
        self.stats.cancel_attempts.fetch_add(1, O::Relaxed);
        let mux = self.mux.clone();
        let sid = self.sid;
        let stats = Arc::clone(&self.stats);
        tokio::spawn(async move {
            // 走 `send_session`：取消帧是**会话级**帧（目标流在载荷里），
            // 这条路径已被 `KeyConfirm` 证明能到达对端（见 `cancel_frame` 的文档）。
            if mux
                .send_session(FrameType::Cancel, sid.to_le_bytes().to_vec())
                .await
                .is_ok()
            {
                stats.cancel_sent.fetch_add(1, O::Relaxed);
            }
        });
    }
}

/// 用响应头构造本地响应，并把后续 `RespData` 逐帧灌进 body。
fn build_response(
    mux: &Mux,
    stats: Arc<Stats>,
    store: Arc<Mutex<TemplateStore>>,
    sid: u32,
    mut rx: mpsc::Receiver<Frame>,
    head: proto::RespHead,
) -> Response<RespBody> {
    let mut builder = Response::builder().status(head.status as u16);
    let mut resp_len: Option<u64> = None;
    for h in &head.headers {
        if h.name.eq_ignore_ascii_case("content-length") {
            resp_len = std::str::from_utf8(&h.value)
                .ok()
                .and_then(|s| s.parse().ok());
        }
        if let (Ok(n), Ok(v)) = (
            http::HeaderName::from_bytes(h.name.as_bytes()),
            http::HeaderValue::from_bytes(&h.value),
        ) {
            builder = builder.header(n, v);
        }
    }

    let (tx, body) = ChannelBody::channel();
    let body = match resp_len {
        Some(n) => body.with_exact_size(n),
        None => body,
    };
    // **SDK 断开时必须告诉服务端"这条流不要了"。**
    //
    // 背景（README 缺口 8）：SDK 一断，hyper 会 drop 掉这个响应体，而泵任务的
    // `rx.recv()` 还阻塞在一个**可能永不回话**的上游上 ⇒ 泵永远活着 ⇒ 服务端按
    // `MAX_CONCURRENT_STREAMS` 占着的槽位再也不释放。上游一旦挂死，4 次放弃就足以
    // 让代理对该上游永久不再服务。
    //
    // 修法：给响应体套一个 Drop 守卫。泵**正常收尾时先解除武装**（那时流已经结束，
    // 不需要再取消），未解除就说明 SDK 先走了 ⇒ 发一帧 `Cancel`（载荷为空，
    // 用 `stream_id` 定位）。
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancel_armed = Arc::clone(&done);
    let cancel_mux = mux.clone();
    let resp = match builder.body(
        CancelOnDrop {
            inner: body.boxed(),
            mux: cancel_mux,
            sid,
            finished: cancel_armed,
            stats: Arc::clone(&stats),
        }
        .boxed(),
    ) {
        Ok(r) => r,
        Err(e) => return err_body(502, format!("组装本地响应失败：{e}")),
    };

    let stats = Arc::clone(&stats);
    let wire = Arc::clone(&stats);
    let mux = mux.clone();
    // 后台把剩余帧灌进响应体。逐帧转发、**不缓冲**——缓冲会破坏 SSE 实时性。
    tokio::spawn(async move {
        let mut total = 0u64;

        // 慢路径解压器。`(解压器, 是否带字典)`——服务端跨越字典交叉点时会另起一条
        // 无字典流，客户端凭标志位换解压器。
        let mut slow_dec: Option<(llm_proxy_core::stream_zstd::StreamDecompressor, bool)> = None;
        let sse_dict = llm_proxy_core::dict::Dicts::bootstrap().sse;

        // 标签化的循环：模板缺失时要从批次内部跳出整个循环
        //
        // **只有收到 `RespEnd` 才算这条响应结束。**
        //
        // 不能用"帧流结束"当结束信号：链路中途断掉、上游中途断流、或者对端发来
        // `Err`，三者都会让 `rx.recv()` 返回 `None`（或走到某个 `break`）。
        // 若此时直接 `drop(tx)`，hyper 会**干净地**收尾这个 body——SDK 于是拿到
        // HTTP 200 + 半截内容，**完全无法察觉**。那正是设计 §16 M7 点名禁止的
        // 「静默错误内容」，比报错严重得多。
        let mut complete = false;
        'pump: while let Some(f) = rx.recv().await {
            // 响应方向的诚实度量：含帧头，才能反映 M2 的真实收益
            if matches!(
                f.ty,
                FrameType::RespData | FrameType::TemplateDef | FrameType::RespBatch
            ) {
                wire.resp_wire_bytes.fetch_add(
                    (llm_proxy_core::frame::HEADER_LEN + f.payload.len()) as u64,
                    Ordering::Relaxed,
                );
            }
            match f.ty {
                FrameType::RespData => {
                    total += f.payload.len() as u64;
                    let with_dict = f.flags.contains(llm_proxy_core::flags::STREAM_ZSTD);
                    let no_dict = f.flags.contains(llm_proxy_core::flags::STREAM_ZSTD_NODICT);
                    if !with_dict && !no_dict {
                        // 普通原样帧
                        if tx.send(Ok(Bytes::from(f.payload))).await.is_err() {
                            break;
                        }
                    } else {
                        // 换档（带字典 ⇄ 不带字典）时必须换一个解压器：
                        // 服务端在跨越字典交叉点时结束了上一条流、另起了一条。
                        if slow_dec.as_ref().map(|(_, d)| *d) != Some(with_dict) {
                            let dict: &[u8] = if with_dict { sse_dict } else { &[] };
                            match llm_proxy_core::stream_zstd::StreamDecompressor::new(dict) {
                                Ok(d) => slow_dec = Some((d, with_dict)),
                                Err(e) => {
                                    tracing::error!(?e, "慢路径解压器初始化失败");
                                    break;
                                }
                            }
                        }
                        let Some((d, _)) = slow_dec.as_mut() else {
                            break;
                        };
                        match d.push(&f.payload) {
                            Ok(plain) => {
                                if !plain.is_empty()
                                    && tx.send(Ok(Bytes::from(plain))).await.is_err()
                                {
                                    break;
                                }
                            }
                            // 解压失败必须**响亮**：静默丢掉等于给用户一个残缺的响应
                            Err(e) => {
                                tracing::error!(?e, "慢路径解压失败，中止该响应");
                                break;
                            }
                        }
                    }
                }
                FrameType::TemplateDef => match proto::TemplateDef::decode(&f.payload[..]) {
                    Ok(d) => {
                        let id = d.template_id;
                        stats.resp_template_defs.fetch_add(1, Ordering::Relaxed);
                        stats
                            .resp_template_def_bytes
                            .fetch_add(f.payload.len() as u64, Ordering::Relaxed);
                        let t = template_from(d);
                        if t.slots() + 1 != t.segments.len() {
                            tracing::error!(template_id = id, "模板定义自相矛盾，拒绝使用");
                            break;
                        }
                        store.lock().unwrap().insert(id, t);
                    }
                    Err(e) => {
                        tracing::error!(?e, "TemplateDef 解码失败");
                        break;
                    }
                },
                FrameType::RespBatch => {
                    // 锁的作用域刻意收紧到调用内：绝不在持锁期间 await
                    let items = match llm_proxy_core::batch::decode(&f.payload, |id| {
                        store.lock().unwrap().get(id).map(|t| t.slots())
                    }) {
                        Ok(v) => v,
                        Err(e) => {
                            // 未知模板 / 截断 → **无法重组**。绝不猜测：
                            // 宁可让响应提前终止（SDK 会看到错误），
                            // 也不能拼出看似正常但内容错误的字节流。
                            stats.template_miss.fetch_add(1, Ordering::Relaxed);
                            // ⚠️ **第 189 轮加的定案诊断** ✓ —— `UnknownTemplate` 有三种**表象相同、机制不同**的成因
                            // （① 这条流的模板被 LRU 淘汰 ✗；② 重连后客户端换了表、而**老会话的流还在发帧** ✗；
                            // ③ 服务端把两条流的帧发到了同一个 sid ✗）。不带表状态就只能靠猜 ✗（本轮已猜错两次 ✗），
                            // 所以把"表里有多少条 / id 区间"一起打出来 ✓：held≈0 ⇒ 表是**新**的 ⇒ 指向 ②③ ✓；
                            // held 顶到上限 ⇒ 指向 ①（淘汰）✓。
                            let (t_held, t_lo, t_hi) = {
                                let s = store.lock().unwrap();
                                let lo = s.map.keys().copied().min().unwrap_or(0);
                                let hi = s.map.keys().copied().max().unwrap_or(0);
                                (s.map.len(), lo, hi)
                            };
                            // **第 194 轮的定案抓取**：把出错那一帧的头部字节打出来 ✓。
                            // 读代码已逐条排除：batch 编解码（对称 + 9 条测试 ✓）、AEAD（per-session 密钥
                            // + 全局单调 Sealer ✓）、传输丢帧（客户端 dropped=0 ✓）、客户端淘汰
                            // （evicted=0 ✓）、服务端 id 空间（templates=7 ⇒ 到不了 112 ✓）
                            // ⇒ 只剩"**wire 上的字节到底是什么**"没看过 ✓。
                            // 手撸解码这一帧即可一锤定音 ✓：
                            //   * `first_tag` 真是 112 ⇒ 服务端确实发了这个 id ✓（客户端重组没错 ✓）；
                            //   * 头部就不合理（item_count 巨大 / 字节乱）⇒ 帧内容本身是垃圾 ✓
                            //     ⇒ 说明上游或编码链某处坏了 ✓（而不是重组逻辑 ✓）。
                            let head_hex: String = f
                                .payload
                                .iter()
                                .take(48)
                                .map(|b| format!("{b:02x}"))
                                .collect();
                            let first_tag = llm_proxy_core::batch::peek_first_tag(&f.payload);
                            // **第 199 轮撤掉"清空自愈"** ✗：它的前提是"表被 id 冲突污染" ✓，
                            // 而那个污染源已被"模板 id 进程级唯一"消除（第 198 轮 ✓）。
                            // 留着它**只剩副作用**：一失败就清空 ✓ ⇒ 服务端只补发**当前这条流**用到的模板 ✓
                            // ⇒ 别的在途流立刻又缺 ⇒ **失败被放大** ✗（现场：defs=967 而 held=8、失败率 22% ✓）。
                            // ⇒ 现在只有"按需补发"（client_needs_defs ✓）+ 日志告警 ✓，不再清表 ✓。                            }
                            tracing::error!(
                                ?e,
                                first_tag,
                                payload_head_hex = head_hex,
                                template_store_held = t_held,
                                template_id_min = t_lo,
                                template_id_max = t_hi,
                                "批量帧不可重组，主动截断响应而不是产出错误内容"
                            );
                            break;
                        }
                    };
                    stats.resp_batch_frames.fetch_add(1, Ordering::Relaxed);
                    for item in items {
                        stats.resp_batch_items.fetch_add(1, Ordering::Relaxed);
                        let bytes = if item.is_raw() {
                            stats
                                .resp_raw_items_bytes
                                .fetch_add(item.raw.len() as u64, Ordering::Relaxed);
                            item.raw
                        } else {
                            stats.resp_var_bytes.fetch_add(
                                item.vars.iter().map(|v| v.len() as u64).sum::<u64>(),
                                Ordering::Relaxed,
                            );
                            let Some(t) = ({ store.lock().unwrap().get(item.template_id) }) else {
                                stats.template_miss.fetch_add(1, Ordering::Relaxed);
                                tracing::error!(
                                    template_id = item.template_id,
                                    "批量项引用了未知模板，主动截断响应"
                                );
                                break 'pump;
                            };
                            match t.rebuild(&item.vars) {
                                Some(b) => b,
                                None => {
                                    stats.template_miss.fetch_add(1, Ordering::Relaxed);
                                    tracing::error!(
                                        template_id = item.template_id,
                                        got = item.vars.len(),
                                        want = t.slots(),
                                        "变量槽数不符，主动截断响应"
                                    );
                                    break 'pump;
                                }
                            }
                        };
                        total += bytes.len() as u64;
                        if tx.send(Ok(Bytes::from(bytes))).await.is_err() {
                            break 'pump;
                        }
                    }
                }
                FrameType::RespEnd => {
                    complete = true;
                    break;
                }
                FrameType::Err => {
                    if let Ok(e) = proto::Err::decode(&f.payload[..]) {
                        tracing::warn!(code = e.code, hint = %e.hint, "流中断");
                    }
                    break;
                }
                _ => {}
            }
        }
        if !complete {
            // 没见到 `RespEnd`：**主动中止响应体**，让 hyper 掐掉这个连接，
            // SDK 看到一个明确的传输错误。
            //
            // 注：本地重组失败的几个 `break` 上面写着"宁可让响应提前终止
            // （SDK 会看到错误）"——在这段代码存在之前，那句注释是**不成立**的：
            // 提前终止看起来和正常结束一模一样。这条判断才让它成立。
            stats.truncated_responses.fetch_add(1, Ordering::Relaxed);
            tracing::error!(
                stream_id = sid,
                "DSHP 流未正常结束（未收到 RespEnd），主动中止响应体以免交付半截内容"
            );
            let _ = tx
                .send(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "DSHP 流在中途结束（未收到 RespEnd）",
                )))
                .await;
        }
        stats.resp_bytes.fetch_add(total, Ordering::Relaxed);
        stats.resp_raw_bytes.fetch_add(total, Ordering::Relaxed);
        // **解除响应体守卫的武装**：泵走到这里说明这条流已经收尾（正常 `RespEnd`、
        // 或已被判定为截断并主动中止），不需要再向服务端发 `Cancel`。
        // 反过来看：只有泵**没能**走到这里（因为它还阻塞在等一个不回话的上游）
        // 而响应体先被 drop 时，守卫才会发取消——那正是 SDK 先走了的情形。
        done.store(true, Ordering::Relaxed);
        drop(tx);
        mux.unbind_stream(sid);
    });

    resp
}

/// 从下发的定义构造客户端侧模板。
///
/// 客户端只需要 `segments` 就能重组，因此不下发服务端的 `var_leaf_idx` /
/// `ref_leaf_bytes`（那是归纳与漂移检测用的，多传几百字节没有意义）。
fn template_from(d: proto::TemplateDef) -> llm_proxy_json::Template {
    let mut schema = [0u8; 16];
    let n = d.schema.len().min(16);
    schema[..n].copy_from_slice(&d.schema[..n]);
    llm_proxy_json::Template::from_parts(
        d.template_id,
        schema,
        d.segments,
        d.var_paths.into_iter().map(String::into_bytes).collect(),
    )
}

#[cfg(test)]
mod caps_tests {
    use super::*;

    fn caps(frame: u32, window: u32) -> proto::Caps {
        proto::Caps {
            max_frame_bytes: frame,
            window_log: window,
            ..Default::default()
        }
    }

    /// 块参数一致性矩阵。
    ///
    /// 为什么这个函数值得有测试：它守的是**"协议版本号相同、编译期常量不同"**那种
    /// 部署错配——两端各自编译、`PROTO_VERSION` 一致，但帧上限/窗口不同。
    /// 那种错今天看不出来（两端共用同一份常量），只会在**换二进制的那一天**以
    /// 帧层 `TOO_LARGE` 或解压失败的形式出现，排查成本高得多。
    #[test]
    fn block_parameters_must_match() {
        let our_frame = llm_proxy_core::config::MAX_FRAME_BYTES as u32;
        let our_window = llm_proxy_core::config::WINDOW_LOG;

        // 一致：通过
        assert!(check_caps_compatible(&caps(our_frame, our_window)).is_ok());

        // 未宣告（旧服务端）：跳过检查，不许拒绝——否则版本兼容性变成硬门槛
        assert!(
            check_caps_compatible(&caps(0, 0)).is_ok(),
            "缺字段应当视为未宣告而不是不一致"
        );

        // 帧上限不同：必须失败，且错误里要说清两侧的值
        let e = check_caps_compatible(&caps(our_frame / 2, our_window)).unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("帧上限"), "错误信息要指名字段：{msg}");
        assert!(
            msg.contains(&(our_frame / 2).to_string()) && msg.contains(&our_frame.to_string()),
            "错误信息要同时给出服务端与本端的值：{msg}"
        );

        // 窗口不同：必须失败
        let e = check_caps_compatible(&caps(our_frame, our_window - 1)).unwrap_err();
        assert!(e.to_string().contains("窗口"), "{e}");

        // 反空转：只差一个字段也要能被查出来（避免"两个都查但只查了一个"）
        assert!(check_caps_compatible(&caps(our_frame, our_window)).is_ok());
        assert!(check_caps_compatible(&caps(our_frame, our_window + 1)).is_err());
        assert!(check_caps_compatible(&caps(our_frame + 1, our_window)).is_err());
    }
}

#[cfg(test)]
mod caps_declaration_tests {
    use super::*;

    /// 反方向能力检查的判据矩阵。
    ///
    /// 守的是「客户端会发这种编码、却不看对端宣没宣告」这一类：缺了必须在**握手期**
    /// 失败，而不是请求发到一半才报错。
    #[test]
    fn server_must_declare_the_encodings_we_send() {
        let with = |list: &[&str]| proto::Caps {
            caps: list.iter().map(|s| (*s).to_string()).collect(),
            ..Default::default()
        };
        let full: &[&str] = &["ws", "raw", "tokenstream", "zstd"];

        // 齐全：通过
        assert!(check_server_caps(&with(full), true).is_ok());
        // 缺 tokenstream：失败，且错误里要说清缺什么
        let e = check_server_caps(&with(&["ws", "raw", "zstd"]), true).unwrap_err();
        assert!(e.to_string().contains("tokenstream"), "{e}");
        // 缺 zstd：失败
        let e = check_server_caps(&with(&["ws", "raw", "tokenstream"]), true).unwrap_err();
        assert!(e.to_string().contains("zstd"), "{e}");
        // 空清单（旧对端没宣告）：跳过，不拒绝
        assert!(check_server_caps(&with(&[]), true).is_ok());
        // 关掉增量路径：本端只发原样编码，不依赖对端宣告
        assert!(check_server_caps(&with(&["ws"]), false).is_ok());
        // 反空转：只差一项也要能查出来
        assert!(check_server_caps(&with(&["tokenstream"]), true).is_err());
    }

    /// **客户端必须声明慢路径能力**，否则服务端永远不启用它。
    ///
    /// 这条守的是一个真实事故：`stream-zstd` 曾在清单里缺失——客户端解得开这种帧
    /// （解码侧早就实现了），服务端却只在声明时才发（`client_stream_zstd`），
    /// 两者一凑，整条慢路径静默地'从未执行'：没有编译错误、没有测试失败、
    /// 也没有任何日志可看。
    #[test]
    fn client_declares_the_stream_zstd_capability() {
        let caps = client_caps();
        for required in [
            "ws",
            "raw",
            "tokenstream",
            "zstd",
            "stream-zstd",
            "stream-ready",
        ] {
            assert!(
                caps.iter().any(|c| c == required),
                "必须声明 {required}（缺 stream-zstd 会让慢路径彻底不启用）：{caps:?}"
            );
        }
        // 反空转：清单不该是空的，也不该有重复项
        assert!(caps.len() >= 5, "{caps:?}");
        let mut sorted = caps.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), caps.len(), "能力清单不该有重复项：{caps:?}");
    }
}

#[cfg(test)]
mod store_flag_tests {
    use super::disables_cross_request_reuse as f;

    /// 判定本身（纯函数）：三种会骗过"字节搜索"的写法都要判对。
    #[test]
    fn store_detection_is_parsed_not_searched() {
        assert!(f(br#"{"store":true,"messages":[]}"#), "紧凑写法");
        assert!(f(br#"{ "store" : true , "messages" : [] }"#), "带空格写法");
        assert!(!f(br#"{"messages":[]}"#), "没有 store");
        assert!(!f(br#"{"store":false}"#), "store 为 false");
        assert!(
            !f(br#"{"input":"please set store to true"}"#),
            "正文里出现 store 字样不得被当成字段（字节搜索会在这里出错）"
        );
        assert!(!f(br#"{"store":{"nested":true}}"#), "store 不是布尔");
        assert!(!f(b"not json at all"), "解析失败时维持原行为（返回 false）");
    }
}
