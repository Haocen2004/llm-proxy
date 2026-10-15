//! 生命周期内的公共辅助：mock 上游、端口借用、原始 HTTP 客户端。
//!
//! 每个测试二进制都各自 `mod common;` 一次，因此不会有单个二进制用到全部条目——
//! 这里统一允许死代码，避免每个测试文件都刷一遍「未使用」警告。
#![allow(dead_code)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body::Frame;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};

pub type BoxedBody = BoxBody<Bytes, std::io::Error>;

pub fn boxed_full(b: impl Into<Bytes>) -> BoxedBody {
    Full::new(b.into())
        .map_err(|e: Infallible| -> std::io::Error { match e {} })
        .boxed()
}

/// `StreamBody` 也需要装箱，才能与静态响应共用同一个返回类型。
fn boxed_stream(rx: tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>) -> BoxedBody {
    let st = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|r| (r.map(Frame::data), rx))
    });
    StreamBody::new(st).boxed()
}

// ---------------------------------------------------------------------------
// 端口
// ---------------------------------------------------------------------------

/// 借一个空闲端口：绑定 `:0` 读回端口后立即释放。
///
/// ⚠️ **第 170 轮的错误修正，第 171 轮回退** ✗→✓→✗。历史与教训都要留在这里 ✓：
///
/// * 第 170 轮我看到"失败用的端口上有 5 条 `TimeWait`" ✓，就断定是"`free_port` 把端口弄成
///   TIME_WAIT ⇒ 服务端绑不上" ✗，于是改成"**随机取端口 + connect 探测**" ✗；
/// * 第 171 轮的诊断（`wait_ready` 打印 stderr ✓）一句话就否掉了它 ✓：
///   `Error: 无法监听 … Caused by: 以一种访问权限不允许的方式做了一个访问套接字的尝试 (os error 10013)`
///   —— **WSAEACCES** ✓ ⇒ Windows 上存在**被保留/排除的端口段**（Hyper-V / WSL 等 ✓）：
///   那些端口**拒绝连接**（于是"connect 探测"认为它空闲 ✓）但**根本不允许绑定** ✗✗
///   ⇒ 我的改写会系统性地挑出**绑不上的端口** ✓；
/// * 而"TIME_WAIT"那条推断本身也是错的 ✗：**只监听、未接受连接的套接字被关闭不会进 TIME_WAIT** ✓
///   （TIME_WAIT 需要一次**完成的连接** ✓）⇒ 那 5 条是**真实连接的结果** ✓，不是这里的因 ✓。
///
/// ⇒ 结论：**原实现是对的，恢复它** ✓。绑 `:0` 由系统分配 ⇒ 一定是**允许绑定**的端口 ✓；
/// 与随后真实 bind 之间的竞态**确实存在但极小** ✓（撞车由夹具的换端口重试兜住 ✓✓）。
pub async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}
/// 找一个空闲的 **UDP** 端口。
///
/// 不能用 `free_port()`：它绑的是 TCP，而 **TCP 与 UDP 是两个独立的端口命名空间**——
/// 一个"空闲的 TCP 端口"完全可能正被某个 UDP 套接字占着。
/// 实测就这么撞过一次：KCP 监听报"无法绑定端口"。
pub async fn free_udp_port() -> u16 {
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let p = s.local_addr().unwrap().port();
    drop(s);
    p
}

/// 轮询直到端口可连接（子进程就绪）。
pub async fn wait_ready(addr: &str, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            // ⚠️ **超时必须带上证据** ✗→✓（第 171 轮）。
            //
            // 为什么在这里做 ✓：`common` 里有 **8 个夹具入口** ✗（`setup` / `setup_with` /
            // `setup_resilient*` / `setup_behind_{black_hole,all_modes_blocker,ws_blocker,cut_proxy}` ✓），
            // 它们各自 spawn、各自 `wait_ready` ⇒ 失败信息却只有一句"未在 Ns 内就绪" ✗
            // ⇒ 于是我只能靠猜"为什么没起来" ✓（第 170 轮就卡在这句上 ✓）。
            // **改在这一处 ⇒ 8 个入口全部受益** ✓（不重复、不遗漏 ✓）。
            let tail = |bin: &str| -> String {
                std::fs::read_to_string(target_dir().join("e2e-logs").join(format!("{bin}.err")))
                    .map(|s| {
                        let v: Vec<&str> = s.lines().rev().take(6).collect();
                        v.into_iter().rev().collect::<Vec<_>>().join(" ｜ ")
                    })
                    .unwrap_or_else(|_| "（无日志）".to_string())
            };
            eprintln!(
                "  [夹具] ⚠️ {addr} 在 {timeout:?} 内没有就绪 ✗\n\
                 · llmproxyd stderr 尾部：{}\n\
                 · llmproxyc stderr 尾部：{}",
                tail("llmproxyd"),
                tail("llmproxyc")
            );
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

// ---------------------------------------------------------------------------
// mock 上游
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Record {
    pub method: String,
    pub path_and_query: String,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

#[derive(Default)]
pub struct Recorder {
    records: Mutex<Vec<Record>>,
}

impl Recorder {
    pub fn take(&self) -> Vec<Record> {
        std::mem::take(&mut *self.records.lock().unwrap())
    }
    pub fn len(&self) -> usize {
        self.records.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub struct MockUpstream {
    pub addr: SocketAddr,
    pub rec: Arc<Recorder>,
    /// mock 实际产出的 SSE 字节（用于与客户端收到的内容比对）
    pub sse_bytes: Arc<Mutex<Vec<u8>>>,
    /// 同时处理中的请求数，以及历史峰值。
    ///
    /// 「并发流上限」要守的性质是**上游侧同时在进行的请求数不超过上限**，
    /// 而不是某个实现细节（服务端有没有返回拒绝码）。直接断言"被拒了几个"
    /// 会把背压正确地排队也判成失败。
    pub inflight: Arc<std::sync::atomic::AtomicUsize>,
    pub max_inflight: Arc<std::sync::atomic::AtomicUsize>,
    /// **TLS 变体专用**（缺口 #4）：握手成功/失败计数。
    ///
    /// 负向对照要靠它们说清"失败发生在**哪一步**"：握手失败（对端证书不被信任 ✓）
    /// 与"握手成功但请求被拒"是完全不同的两件事 ✗。
    /// 更直接的证据是 [`Recorder::len`]——上游**一个请求都没收到** ✓。
    pub tls_ok: Arc<std::sync::atomic::AtomicUsize>,
    pub tls_fail: Arc<std::sync::atomic::AtomicUsize>,
}

pub const SSE_EVENTS: usize = 8;
/// 用于测量归纳收益的长流。
pub const SSE_MANY_EVENTS: usize = 140;

/// 真实 LLM 分片的 token 文本很短（1~2 字符）。
///
/// 这一点**直接决定测试是否诚实**：用长 token 会让变量槽变大、看不出帧头开销问题，
/// 于是「省 ≥90%」这条验收线会被轻松通过，而真实短 token 场景其实过不了。
const SSE_TOKENS: &[&str] = &["a", "b", "的", "在", "ab", "c"];

fn sse_chunks(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| {
            format!(
                "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\
                 \"delta\":{{\"type\":\"text_delta\",\"text\":\"{}\"}}}}\n\n",
                SSE_TOKENS[i % SSE_TOKENS.len()]
            )
        })
        .chain(std::iter::once(
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
        ))
        .collect()
}

/// 产出 SSE 响应：每片之间 10 ms，模拟真实逐 token 推送速率。
///
/// 这个间隔刻意保留——它同时用于验证「代理没有整段缓冲」和「批量只引入有界延迟」。
/// 上游每片间隔 `gap_ms` 的 SSE。用于**稳健地**验证流式转发：
/// 总时长足够长（秒级），缓冲式代理的首字节延迟会暴露无遗。
fn sse_response_gapped(
    n: usize,
    gap_ms: u64,
    sse_out: &Arc<Mutex<Vec<u8>>>,
) -> Response<BoxedBody> {
    let chunks = sse_chunks(n);
    for c in &chunks {
        sse_out.lock().unwrap().extend_from_slice(c.as_bytes());
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(16);
    tokio::spawn(async move {
        for c in chunks {
            if tx.send(Ok(Bytes::from(c.into_bytes()))).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(gap_ms)).await;
        }
    });
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(boxed_stream(rx))
        .unwrap()
}

/// 形态**各不相同**的 SSE 事件：每个事件的键集合都不一样，因此归纳不出模板，
/// 服务端会转入慢路径（流式 zstd）。
///
/// 形态在前 8 个事件内快速结束，然后**长时间静默**，最后再补一个事件。
/// 这个"静默期"是测量慢路径延迟的关键：只有**时间驱动** flush 才能让客户端
/// 在静默期开始前就拿到数据；计数驱动（攒够 1KB）会把所有内容憋到流结束。
fn novel_chunks(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| {
            let keys: String = (0..=(i % 5))
                .map(|k| format!("\"k{}_{}\":{},", i, k, i * 7 + k))
                .collect();
            format!("event: novel_{i}\ndata: {{{keys}\"n\":{i}}}}}\n\n")
        })
        .collect()
}

/// **大且不可模板化**的上游响应（慢路径收益的测量用）。
///
/// 为什么需要它：`sse-novel` 只有 ~500 B——在这么小的量级上，zstd 的帧头开销
/// 很可能**超过**它省下来的字节，于是"慢路径到底划不划算"根本测不出来。
/// 这个模式给 200 个形态各异的事件（每个几百字节），量级对齐真实长响应。
fn sse_novel_big_response(sse_out: &Arc<Mutex<Vec<u8>>>) -> Response<BoxedBody> {
    let mut chunks: Vec<String> = (0..200)
        .map(|i| {
            // 每个事件键集合与取值都不同 ⇒ 归纳不出模板 ⇒ 必走慢路径
            let keys: String = (0..=(i % 7))
                .map(|k| {
                    format!(
                        "\"k{}_{}\":\"{}\",",
                        i,
                        k,
                        "v".repeat(40 + (i * 13 + k) % 60)
                    )
                })
                .collect();
            format!("event: novel_{i}\ndata: {{{keys}\"n\":{i}}}}}\n\n")
        })
        .collect();
    chunks.push("event: novel_tail\ndata: {\"t\":0,\"u\":\"final\"}\n\n".to_string());
    for c in &chunks {
        sse_out.lock().unwrap().extend_from_slice(c.as_bytes());
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(16);
    tokio::spawn(async move {
        for c in chunks {
            if tx.send(Ok(Bytes::from(c.into_bytes()))).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    });
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(boxed_stream(rx))
        .unwrap()
}

/// 慢路径专用的上游响应：8 个形态各异的事件 → 静默 1.5s → 1 个事件 → 结束。
fn sse_novel_response(sse_out: &Arc<Mutex<Vec<u8>>>) -> Response<BoxedBody> {
    let mut chunks = novel_chunks(8);
    chunks.push("event: novel_tail\ndata: {\"t\":0,\"u\":\"final\"}\n\n".to_string());
    for c in &chunks {
        sse_out.lock().unwrap().extend_from_slice(c.as_bytes());
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(16);
    tokio::spawn(async move {
        for (i, c) in chunks.iter().enumerate() {
            if i == 8 {
                // 静默期：慢路径若做了计数驱动 flush，客户端在这段时间内收不到任何东西
                tokio::time::sleep(Duration::from_millis(1500)).await;
            }
            if tx
                .send(Ok(Bytes::from(c.clone().into_bytes())))
                .await
                .is_err()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(boxed_stream(rx))
        .unwrap()
}
fn sse_response(n: usize, sse_out: &Arc<Mutex<Vec<u8>>>) -> Response<BoxedBody> {
    let chunks = sse_chunks(n);
    for c in &chunks {
        sse_out.lock().unwrap().extend_from_slice(c.as_bytes());
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(16);
    tokio::spawn(async move {
        for c in chunks {
            if tx.send(Ok(Bytes::from(c.into_bytes()))).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(boxed_stream(rx))
        .unwrap()
}

/// **中途断流**：发 3 个事件后让响应体直接出错。
///
/// 用 `Err(io::Error)` 而不是"把 stream 正常结束"——后者在 HTTP 语义上就是
/// **一条完整的响应**（chunked 会正常收尾），代理**没有能力**区分它和截断。
/// 只有让连接真的断掉，才构成一次可检测的故障注入。
///
/// 这也是 M7 要守的那条红线：上游断在半路时，SDK 必须看到**明确错误**，
/// 而不是 HTTP 200 + 半截内容。
fn sse_response_cut(n_events: usize, sse_out: &Arc<Mutex<Vec<u8>>>) -> Response<BoxedBody> {
    let chunks = sse_chunks(n_events);
    for c in &chunks {
        sse_out.lock().unwrap().extend_from_slice(c.as_bytes());
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(16);
    tokio::spawn(async move {
        for c in chunks {
            if tx.send(Ok(Bytes::from(c.into_bytes()))).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // 断在半路：连接被中止，chunked 的结束块**永远不会发出去**
        let _ = tx
            .send(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "mock 上游中途断流",
            )))
            .await;
    });
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(boxed_stream(rx))
        .unwrap()
}

impl MockUpstream {
    pub async fn start() -> Self {
        Self::start_inner(None).await.0
    }

    /// **TLS 版**（缺口 #4：https 上游）：自签证书在**测试时现生成**（不把私钥提交进仓库 ✓）。
    ///
    /// 返回 `(mock, CA 的 PEM 路径)` —— 把那个路径交给 `--upstream-ca` ✓。
    pub async fn start_tls() -> (Self, std::path::PathBuf) {
        let (cfg, ca_pem) = tls_server_config();
        let dir = target_dir().join("e2e-certs");
        std::fs::create_dir_all(&dir).expect("创建 e2e-certs 目录失败");
        let ca_path = dir.join("ca.pem");
        std::fs::write(&ca_path, ca_pem.as_bytes()).expect("写 CA 文件失败");
        let (up, _) = Self::start_inner(Some(cfg)).await;
        (up, ca_path)
    }

    async fn start_inner(tls: Option<Arc<rustls::ServerConfig>>) -> (Self, ()) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let rec = Arc::new(Recorder::default());
        let sse_bytes = Arc::new(Mutex::new(Vec::<u8>::new()));
        let inflight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let max_inflight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tls_ok = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tls_fail = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let rec_t = Arc::clone(&rec);
        let sse_t = Arc::clone(&sse_bytes);
        let inflight_t = Arc::clone(&inflight);
        let max_inflight_t = Arc::clone(&max_inflight);
        let tls_ok_t = Arc::clone(&tls_ok);
        let tls_fail_t = Arc::clone(&tls_fail);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let rec = Arc::clone(&rec_t);
                let sse = Arc::clone(&sse_t);
                let inflight = Arc::clone(&inflight_t);
                let max_inflight = Arc::clone(&max_inflight_t);
                let tls_ok = Arc::clone(&tls_ok_t);
                let tls_fail = Arc::clone(&tls_fail_t);
                let tls = tls.clone();
                tokio::spawn(async move {
                    // 可选 TLS 握手。**失败就丢掉这条连接、且不记入 `records`** ✓ ——
                    // 于是测试可以断言"上游一个请求都没收到"，那正是"没有静默降级成明文"
                    // 的直接证据 ✓（只说"请求失败了"是不够的：那也可能是上游别的地方出错 ✗）。
                    let io: Box<dyn AsyncReadWrite> = match tls {
                        None => Box::new(stream),
                        Some(cfg) => {
                            let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
                            match acceptor.accept(stream).await {
                                Ok(s) => {
                                    tls_ok.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    Box::new(s)
                                }
                                Err(e) => {
                                    tls_fail.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    eprintln!("  [mock] TLS 握手失败：{e}（不记入 records ✓）");
                                    return;
                                }
                            }
                        }
                    };
                    let io = TokioIo::new(io);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let rec = Arc::clone(&rec);
                        let sse = Arc::clone(&sse);
                        let inflight = Arc::clone(&inflight);
                        let max_inflight = Arc::clone(&max_inflight);
                        async move {
                            let (parts, body) = req.into_parts();
                            // **不要 `unwrap()`** ✗：客户端在读完 body 之前丢掉连接（测试里很常见，
                            // 例如 `multi_client.rs` 的连接上限用例 ✓）会让 `collect()` 返回 `Err`
                            // ⇒ mock 的 task 直接 panic ✗ —— 这正是第 117 轮实测到的那个后台 panic ✓。
                            // 后果不是"套件挂了"，而是**日志里多一条无关 panic** ✓✗：它掩盖真问题，
                            // 所以修掉 ✓。处理方式：按"未收到请求"算 ✓（不记入 `records` ✓，
                            // 直接用一个空 body 走同一个 `respond` ✓ —— 形状与下面正常路径一致 ✓）。
                            let bytes = match body.collect().await {
                                Ok(b) => b.to_bytes().to_vec(),
                                Err(e) => {
                                    eprintln!(
                                        "  [mock] 客户端在读完 body 前断开：{e}（按未收到处理 ✓）"
                                    );
                                    return Ok::<_, Infallible>(respond(
                                        "",
                                        &[],
                                        &sse,
                                        &inflight,
                                        &max_inflight,
                                    ));
                                }
                            };
                            let record = Record {
                                method: parts.method.to_string(),
                                path_and_query: parts
                                    .uri
                                    .path_and_query()
                                    .map(|p| p.as_str().to_string())
                                    .unwrap_or_else(|| "/".into()),
                                headers: parts
                                    .headers
                                    .iter()
                                    .map(|(k, v)| (k.as_str().to_string(), v.as_bytes().to_vec()))
                                    .collect(),
                                body: bytes.clone(),
                            };
                            let mode = header_of(&record, "x-test-mode");
                            rec.records.lock().unwrap().push(record);
                            Ok::<_, Infallible>(respond(
                                &mode,
                                &bytes,
                                &sse,
                                &inflight,
                                &max_inflight,
                            ))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });

        (
            Self {
                addr,
                rec,
                sse_bytes,
                inflight,
                max_inflight,
                tls_ok,
                tls_fail,
            },
            (),
        )
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// https 形式的上游 base（TLS 变体用）。
    pub fn base_url_https(&self) -> String {
        format!("https://{}", self.addr)
    }
}

/// 盒装的双向流：让"明文 TCP"与"TLS 流"在同一个 accept 循环里走同一条路 ✓。
trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

/// 为测试**当场生成**一套证书：CA + 叶子（SAN 同时含 `localhost` 与 `127.0.0.1`）。
///
/// 为什么现生成而不是把证书提交进仓库：私钥进版本库（哪怕是测试用的）既容易被人误用，
/// 也会让"公开前审计"多一类要人工判断的东西 ✗。rcgen 生成一次只要毫秒级 ✓。
///
/// SAN 里两个名字都要有：夹具连的是 `https://127.0.0.1:port` ⇒ 只放 `localhost`
/// 会在**校验主机名**那一步失败（那看起来像"CA 没配上"，实际是名字不对 ✗）。
fn tls_server_config() -> (Arc<rustls::ServerConfig>, String) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};

    // 进程级 crypto provider：两端（客户端 rustls / 这里）都只启用了 `ring` ✓。
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut ca_params = CertificateParams::new(Vec::new()).expect("CA 参数");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().expect("生成 CA 私钥");
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA 自签失败");

    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("叶子参数");
    leaf_params.is_ca = IsCa::NoCa;
    let leaf_key = KeyPair::generate().expect("生成叶子私钥");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("叶子签名失败");

    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf_cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
        )
        .expect("构造 TLS 服务端配置失败");
    (Arc::new(cfg), ca_cert.pem())
}

pub fn header_of(r: &Record, name: &str) -> String {
    r.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| String::from_utf8_lossy(v).to_string())
        .unwrap_or_default()
}

/// 并发名额守卫：**在响应体真正产完之后**才释放名额。
///
/// 用 `Drop` 而不是手写 `fetch_sub`，是因为 `respond` 有多个提前返回的分支，
/// 手写很容易漏掉其中一条——漏掉就会让峰值统计失真，而失真的统计比没有统计更糟。
struct Release {
    inflight: Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for Release {
    fn drop(&mut self) {
        self.inflight
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

fn respond(
    mode: &str,
    req_body: &[u8],
    sse_out: &Arc<Mutex<Vec<u8>>>,
    inflight: &Arc<std::sync::atomic::AtomicUsize>,
    max_inflight: &Arc<std::sync::atomic::AtomicUsize>,
) -> Response<BoxedBody> {
    use std::sync::atomic::Ordering as O;
    // 每进入一次上游处理就算占一个并发名额。
    // **必须覆盖整个响应体产出期**：`slow` 模式是异步产出 body 的，
    // 若在返回 Response 时就减掉，就测不到真实并发。
    let cur = inflight.fetch_add(1, O::AcqRel) + 1;
    max_inflight.fetch_max(cur, O::AcqRel);
    let release = {
        let i = Arc::clone(inflight);
        Release { inflight: i }
    };
    match mode {
        "echo" => Response::builder()
            .status(200)
            .header("content-type", "application/octet-stream")
            .header("x-upstream-saw-len", req_body.len().to_string())
            .body(boxed_full(req_body.to_vec()))
            .unwrap(),
        // **永不回话**：连接建上了，但响应体永远不产出。
        //
        // 与 `slow` 的区别是本质性的：`slow` 1.5s 后会回，所以"占着槽位"是**暂时**的；
        // `hang` 让服务端**真的挂在上游上**，用来检验两件事：
        // (a) 并发上限是否**有界地**拒绝后续请求（而不是永远排队）；
        // (b) 客户端**放弃**之后，那个挂在死上游上的槽位能不能释放。
        "hang" => {
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(1);
            tokio::spawn(async move {
                // 同时持有 tx 与 release：body 永不产出，且 inflight 一直计着
                let _keep_tx = tx;
                let _keep_release = release;
                tokio::time::sleep(Duration::from_secs(3600)).await;
            });
            Response::builder()
                .status(200)
                .header("content-type", "application/octet-stream")
                .body(boxed_stream(rx))
                .unwrap()
        }
        // 慢响应：用于验证并发流上限——请求必须"停留"足够久才会撞上限
        "slow" => {
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
            let body = req_body.to_vec();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                let _ = tx.send(Ok(Bytes::from(body))).await;
                let _ = &release;
            });
            Response::builder()
                .status(200)
                .header("content-type", "application/octet-stream")
                .body(boxed_stream(rx))
                .unwrap()
        }
        // 慢速 SSE：12 片 × 200ms = 2.4s。缓冲式代理的首字节要等 2.4s，
        // 流式代理 ≤ 一个批量窗口（150ms）。差距足够大，断言不会因负载而抖动。
        // 慢路径：形态各异 → 归纳不出模板 → 流式 zstd
        "sse-novel" => sse_novel_response(sse_out),
        "sse-novel-big" => sse_novel_big_response(sse_out),
        "sse-slow" => sse_response_gapped(12, 200, sse_out),
        // M7 故障注入：上游发到一半就把连接断掉
        "sse-cut" => sse_response_cut(3, sse_out),
        "sse" => sse_response(SSE_EVENTS, sse_out),
        // 长流：用于测量模板归纳 + 批量成帧的真实收益
        "sse-many" => sse_response(SSE_MANY_EVENTS, sse_out),
        // ---- 合法但"少见"的响应形态（稳健性矩阵，crates/e2e-tests/tests/framing.rs）----
        //
        // 这些形态都合法，而朴素的代理实现常常在其中之一上悄悄出错：
        // 分块无长度、已编码的 body、无内容状态码、重复响应头、HEAD。
        // 不加长度头 ⇒ hyper 自动用 chunked 分帧
        "chunked" => {
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
            let body = req_body.to_vec();
            tokio::spawn(async move {
                // 三段，中间跨过一个很短的间隔：既能验证分块，又不拖慢测试
                let third = (body.len() / 3).max(1);
                for part in body.chunks(third) {
                    if tx.send(Ok(Bytes::copy_from_slice(part))).await.is_err() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            });
            Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(boxed_stream(rx))
                .unwrap()
        }
        // **body 发到一半就断**（非 SSE 路径）。
        //
        // 这是「流结束 ≠ 发送完成」（§15）在 **raw 路径**上的镜像，M7 的断流
        // 注入只覆盖了 SSE 那条。做法：不给 content-length（于是分块），
        // 发两段之后**返回 Err** ⇒ hyper 不会写终止块，而是异常终止连接。
        //
        // 第一版我用"声明一个比实际大的 content-length"来注入，结果 hyper 的
        // **服务端**直接 panic（`payload claims content-length of N,
        // custom content-length header claims M`）——**注入方式本身不合法**，
        // 测到的是夹具崩溃而不是产品行为。合法且等价的手法只有"连接异常终止"。
        "cut-body" => {
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
            let body = req_body.to_vec();
            tokio::spawn(async move {
                let half = body.len() / 2;
                let _ = tx.send(Ok(Bytes::copy_from_slice(&body[..half]))).await;
                tokio::time::sleep(Duration::from_millis(20)).await;
                let _ = tx.send(Ok(Bytes::copy_from_slice(&body[half..]))).await;
                tokio::time::sleep(Duration::from_millis(20)).await;
                // **不发终止块**，直接报错 ⇒ 分块 body 不完整
                let _ = tx
                    .send(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "上游在响应体中途断开",
                    )))
                    .await;
            });
            Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(boxed_stream(rx))
                .unwrap()
        }
        // 无内容状态码：不许凭空造出 body，也不许丢掉状态码
        "no-content" => Response::builder()
            .status(204)
            .body(boxed_full(Vec::new()))
            .unwrap(),
        // **SSE + content-encoding**：`text/event-stream` 但 body 是压缩过的。
        //
        // 这是本轮做稳健性矩阵时发现的最危险形态：响应侧只按 `content-type` 分流，
        // 于是代理会拿**压缩字节**去切 SSE 事件。真实网关（CDN / 反向代理）会压缩
        // 流式响应，所以这不是凭空造出来的场景。
        "sse-encoded" => {
            let raw: Vec<u8> = sse_chunks(SSE_EVENTS)
                .into_iter()
                .flat_map(|c| c.into_bytes())
                .collect();
            let encoded = llm_proxy_core::compression::CompressPool::new(b"", 1)
                .ok()
                .and_then(|c| c.try_compress(&raw))
                .unwrap_or_else(|| raw.clone());
            *sse_out.lock().unwrap() = encoded.clone();
            Response::builder()
                .status(200)
                .header("content-type", "text/event-stream")
                .header("content-encoding", "zstd")
                .body(boxed_full(encoded))
                .unwrap()
        }
        // 重复响应头：两个 set-cookie 必须都到（不许合并、不许只留一个）
        "dup-headers" => Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .header("set-cookie", "dshp_a=1; Path=/")
            .header("set-cookie", "dshp_b=2; Path=/")
            .body(boxed_full(req_body.to_vec()))
            .unwrap(),
        // 已编码的 body：代理**不许**解码（也不许改 content-encoding）。
        // 用真 zstd 帧而不是随机字节：若代理真去解码，它会解得出来，
        // 于是"改没改"这件事在字节上立刻现形。
        "encoded" => Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .header("content-encoding", "zstd")
            .body(boxed_full(
                llm_proxy_core::compression::CompressPool::new(b"", 1)
                    .ok()
                    .and_then(|c| c.try_compress(req_body))
                    .unwrap_or_else(|| req_body.to_vec()),
            ))
            .unwrap(),
        "status" => Response::builder()
            .status(429)
            .header("content-type", "application/json")
            .header("retry-after", "7")
            .body(boxed_full(
                br#"{"error":{"type":"rate_limit_error"}}"#.to_vec(),
            ))
            .unwrap(),
        _ => Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .header("x-upstream-marker", "plain-response")
            .body(boxed_full(
                br#"{"ok":true,"note":"mock upstream"}"#.to_vec(),
            ))
            .unwrap(),
    }
}

// ---------------------------------------------------------------------------
// 子进程
// ---------------------------------------------------------------------------

pub enum Proc {
    Server(std::process::Child),
    Client(std::process::Child),
}

impl Proc {
    pub fn kill(&mut self) {
        let c = match self {
            Proc::Server(c) | Proc::Client(c) => c,
        };
        let _ = c.kill();
        let _ = c.wait();
    }

    /// 进程是否**已经退出**（不阻塞）。
    ///
    /// 为什么需要（第 181 轮排空用例）：要判"服务端排空完就真的退了"。
    /// 靠 `sleep` 猜时间是**会偶发**的判据 ✗；`try_wait` 是直接观测 ✓（与
    /// `conns_inflight` 那条"可观测信号优于猜时间"同一条规矩 ✓）。
    pub fn has_exited(&mut self) -> bool {
        let c = match self {
            Proc::Server(c) | Proc::Client(c) => c,
        };
        matches!(c.try_wait(), Ok(Some(_)))
    }

    /// 轮询等它退出，返回等待毫秒数；超时返回 `None`（**不 panic**，由调用方决定怎么报 ✗）。
    pub async fn wait_exit(&mut self, timeout: std::time::Duration) -> Option<u128> {
        let t0 = std::time::Instant::now();
        while t0.elapsed() < timeout {
            if self.has_exited() {
                return Some(t0.elapsed().as_millis());
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        None
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        self.kill();
    }
}

pub fn target_dir() -> PathBuf {
    // crates/e2e-tests/tests/common/mod.rs → ../../../target
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates
    p.pop(); // workspace root
    p.push("target");
    p.push("debug");
    p
}

pub fn bin_path(name: &str) -> PathBuf {
    let mut p = target_dir().join(name);
    p.set_extension(std::env::consts::EXE_EXTENSION);
    p
}

pub fn spawn_proxy(bin: &str, args: &[&str], kind_server: bool) -> anyhow::Result<Proc> {
    spawn_proxy_psk(bin, args, kind_server, None)
}

/// 与 [`spawn_proxy`] 相同，但可指定 PSK。用于验证「PSK 不一致必须失败」。
pub fn spawn_proxy_psk(
    bin: &str,
    args: &[&str],
    kind_server: bool,
    psk: Option<&str>,
) -> anyhow::Result<Proc> {
    spawn_proxy_env(bin, args, kind_server, psk, &[])
}

/// 与 [`spawn_proxy_psk`] 相同，但可**显式**注入额外环境变量。
///
/// 用于那些"显式授权"类的开关（`DSHP_ALLOW_PASSTHROUGH`）以及需要凭据的统计接口
/// （`DSHP_WEBUI_TOKEN`）：不显式传就与原来一样——只给 PSK/RUST_LOG，并清掉宿主可能
/// 带来的 `DSHP_WEBUI_TOKEN`（否则诊断端点会要求凭据，制造与代码无关的假红）。
pub fn spawn_proxy_env(
    bin: &str,
    args: &[&str],
    kind_server: bool,
    psk: Option<&str>,
    env: &[(&str, &str)],
) -> anyhow::Result<Proc> {
    let path = bin_path(bin);
    if !path.exists() {
        anyhow::bail!(
            "找不到 {}。请先运行 `cargo build`（端到端测试需要已构建的二进制）。",
            path.display()
        );
    }
    let child = std::process::Command::new(&path)
        .args(args)
        .env("DSHP_PSK", psk.unwrap_or("e2e-test-psk"))
        .env("RUST_LOG", "warn")
        // 夹具**必须**在"没有 WebUI token"的前提下跑：服务端的诊断端点
        // `/__dshp/status` 是观察服务端内部的唯一通道（子进程日志被丢弃），
        // 一旦继承到宿主 shell 里的 token，它就会要求凭据 ⇒ 一串与代码无关的假红。
        .env_remove("DSHP_WEBUI_TOKEN")
        .envs(env.iter().copied())
        .stdout(std::process::Stdio::null())
        // ⚠️ **服务端/客户端的 stderr 必须落盘** ✗→✓（第 164 轮修）。
        //
        // 原先一律 `Stdio::null()` ✗ ⇒ 失败时**看不到任何原因** ✓ ⇒ 我这几轮只能靠"猜 + 反复重跑"
        // 追那串随机红（`sse_delivery_pacing` 的 502、`slow_templatable_stream…` 等 **5 个不同用例** ✗）——
        // 而真正的线索（那行 `tracing::warn!` ✓、二进制启动失败的原因 ✓）**当场就被丢掉了** ✗✗。
        // ⇒ 现在写入 `target/e2e-logs/<bin>.err` ✓，并显式打印一行"本进程 pid + 日志路径" ✓
        // （否则多进程混在一个文件里没法归属 ✗）。
        //
        // ⚠️ **第 176 轮：每个测试进程只截断一次** ✗→✓。此前是纯 `append` ✓ ⇒ 文件**跨轮次累积** ✗ ——
        // 第 172 轮我就是把**上一轮**留下的 `os error 10013` 当成了当次的现场 ✗（追错了方向一整轮 ✓）。
        // 用 `OnceLock` 保证"每个测试二进制启动后第一次 spawn 时清空" ✓ ⇒ 同一个进程内多进程仍可归属 ✓，
        // 但**不会再混入历史** ✓。
        .stderr({
            // **按文件名各截断一次** ✓（第 176 轮）：单个 `OnceLock` 只会截断"先来的那一个" ✗
            // （服务端与客户端是**两个**文件 ✓）⇒ 用一张"已截断过哪些文件"的表 ✓。
            static FRESH: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
                std::sync::OnceLock::new();
            let dir = target_dir().join("e2e-logs");
            let _ = std::fs::create_dir_all(&dir);
            let log = dir.join(format!("{bin}.err"));
            let mut seen = FRESH
                .get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
                .lock()
                .unwrap();
            if seen.insert(bin.to_string()) {
                // 本进程内该文件第一次出现 ⇒ 截断 ✓（此后继续 append ✓）
                let _ = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&log);
            }
            drop(seen);
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log)
            {
                Ok(f) => std::process::Stdio::from(f),
                // 打不开就退回 null ✓ —— 诊断能力**不该让测试起不来** ✗
                Err(_) => std::process::Stdio::null(),
            }
        })
        .spawn()
        .map_err(|e| anyhow::anyhow!("启动 {} 失败: {e}", path.display()))?;
    // 归属用 ✓：多进程共用同一个 `.err` 文件 ⇒ **打印 pid** 才能把日志行对上进程 ✓
    // （本轮实测过：注释里写了这句、代码里却没有 ✗ —— 这种"注释比代码更乐观"的东西最容易骗人 ✓）。
    eprintln!(
        "  [夹具] 起了 {bin} pid={} ⇒ stderr 落盘在 target/debug/e2e-logs/{bin}.err ✓",
        child.id()
    );
    Ok(if kind_server {
        Proc::Server(child)
    } else {
        Proc::Client(child)
    })
}

// ---------------------------------------------------------------------------
// 原始 HTTP 客户端（用于精确比对响应字节）
// ---------------------------------------------------------------------------

pub struct RawResponse {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
    /// 每个 body 分片到达的时刻，用于判断是否流式转发
    pub chunk_times: Vec<std::time::Instant>,
    /// 每个 body 分片的**字节数**（与 `chunk_times` 一一对应）。
    ///
    /// 为什么光有时间不够：判"这一片是慢路径攒出来的批量 flush，还是快路径前导沿的单个事件"时，
    /// **时间地板不可靠**（第 180 轮实测：Linux runner 上前导沿落到 0.073s，越过了按本机标定的
    /// 0.05s 地板 ⇒ 被当成慢路径的 flush，连红两轮）。而按**内容**判就稳：单片 ≥2 个事件
    /// 只可能是批量 flush。
    pub chunk_lens: Vec<usize>,
    /// 请求发出的时刻。有了它才能判断"首字节多久才到"——
    /// 只看分片之间的跨度是不够的：OS 可能把两次写入合并成一次读取，
    /// 那样分片数会退化，但**首字节延迟**依然如实反映是否流式。
    pub start: std::time::Instant,
}

/// 直接经握手后的 HTTP/1.1 连接发一次请求，读完整响应。
pub async fn raw_request(
    addr: &str,
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> anyhow::Result<RawResponse> {
    let stream = TcpStream::connect(addr).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let start = std::time::Instant::now();
    let mut builder = Request::builder().method(method).uri(url);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder.body(Full::new(Bytes::copy_from_slice(body)))?;
    let resp = sender.send_request(req).await?;
    let (parts, mut resp_body) = resp.into_parts();

    let mut chunk_times = Vec::new();
    let mut chunk_lens = Vec::new();
    let mut collected = Vec::new();
    while let Some(frame) = resp_body.frame().await {
        let frame = frame?;
        if let Ok(d) = frame.into_data() {
            if !d.is_empty() {
                chunk_times.push(std::time::Instant::now());
                chunk_lens.push(d.len());
                collected.extend_from_slice(&d);
            }
        }
    }
    Ok(RawResponse {
        status: parts.status.as_u16(),
        headers: parts
            .headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.as_bytes().to_vec()))
            .collect(),
        body: collected,
        chunk_times,
        chunk_lens,
        start,
    })
}

/// 在**已规范化**的 header 集合里取第一个值（名字按 ASCII 大小写不敏感比对）。
pub fn header_of_norm(hs: &[(String, Vec<u8>)], name: &str) -> Option<String> {
    hs.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| String::from_utf8_lossy(v).to_string())
}

/// 规范化 header 集合：小写化名字、排序，并剔除逐跳头。///
/// 逐跳头（connection / transfer-encoding 等）按 HTTP 规范**本来就不该**逐字节透传，
/// 中间节点可以增删；把它们排除在比对之外，并不放松对端到端头的逐字节要求。
pub fn normalize_headers(hs: &[(String, Vec<u8>)]) -> Vec<(String, Vec<u8>)> {
    const HOP_BY_HOP: &[&str] = &[
        "connection",
        "transfer-encoding",
        "keep-alive",
        "upgrade",
        "te",
        "trailer",
        "proxy-connection",
    ];
    let mut v: Vec<(String, Vec<u8>)> = hs
        .iter()
        .filter(|(k, _)| !HOP_BY_HOP.contains(&k.to_ascii_lowercase().as_str()))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();
    v.sort();
    v
}

/// 逐字节比对，失败时**只报长度与首个差异的局部片段**。
///
/// 不要用 `assert_eq!` 直接比字节数组：SSE 负载有几十 KB，失败信息会把整个
/// 测试日志淹没，真正的差异位置反而看不见。
#[track_caller]
pub fn assert_bytes_eq(actual: &[u8], expected: &[u8], label: &str) {
    if actual == expected {
        return;
    }
    let at = actual.iter().zip(expected).position(|(a, b)| a != b);
    let window = |v: &[u8]| match at {
        Some(i) => {
            let s = i.saturating_sub(48);
            let e = (i + 48).min(v.len());
            format!("{:?}", String::from_utf8_lossy(&v[s..e]))
        }
        None => String::from("(无差异位置，仅长度不同)"),
    };
    panic!(
        "{label}：字节不一致\n  实际长度 {} / 期望长度 {}\n  首个差异偏移 {:?}\n  实际片段 {}\n  期望片段 {}",
        actual.len(),
        expected.len(),
        at,
        window(actual),
        window(expected)
    );
}

// ---------------------------------------------------------------------------
// 完整链路夹具
// ---------------------------------------------------------------------------

/// 给每个测试套一层超时。
///
/// 没有它，一次死锁会让 CI 无限挂起（本项目已遇到过一次真实死锁：抢先到达的
/// `BodyChunk` 被路由进收件箱后当成无关帧忽略，导致请求体永不完整、双向互等）。
/// 超时会 drop 整个 future，`Stack` 随之析构，子进程随 `Proc::drop` 被杀，不留孤儿。
pub async fn guard<F: std::future::Future>(f: F) -> F::Output {
    const SECS: u64 = 90;
    match tokio::time::timeout(Duration::from_secs(SECS), f).await {
        Ok(v) => v,
        Err(_) => panic!("测试在 {SECS}s 内未完成（疑似死锁）"),
    }
}

pub struct Stack {
    pub up: MockUpstream,
    pub d: Proc,
    pub c: Proc,
    pub client: String,
    /// 服务端监听端口（用于杀掉后按同端口重启，验证恢复）。
    pub dport: u16,
}

impl Stack {
    /// 读客户端的 `/__dshp/status`，返回解析后的 JSON。
    pub async fn status(&self) -> anyhow::Result<serde_json::Value> {
        let r = raw_request(&self.client, "GET", "/__dshp/status", &[], b"").await?;
        Ok(serde_json::from_slice(&r.body)?)
    }

    /// 读**服务端**的 `/__dshp/status`（并发额度、在途流、取消帧等运行期诊断）。
    ///
    /// 必须用 **POST**：服务端的 `dispatch` 按**首字节**分流（`P` 走 HTTP、
    /// 其余含 `G` 一律走 WS），而 WS 握手本身就是 `GET ` 开头，所以 `G` 不能
    /// 收进 HTTP 分支。夹具丢弃子进程日志，这是观察服务端内部的唯一通道。
    pub async fn server_diag(&self) -> anyhow::Result<serde_json::Value> {
        let addr = format!("127.0.0.1:{}", self.dport);
        let r = raw_request(&addr, "POST", "/__dshp/status", &[], b"").await?;
        Ok(serde_json::from_slice(&r.body)?)
    }

    /// 经代理发一次 echo 请求，返回回显内容。
    pub async fn echo(&self, path: &str, body: &[u8]) -> anyhow::Result<Vec<u8>> {
        let r = raw_request(
            &self.client,
            "POST",
            path,
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "echo"),
            ],
            body,
        )
        .await?;
        anyhow::ensure!(r.status == 200, "状态码 {} 非 200", r.status);
        Ok(r.body)
    }
}

/// 起完整链路。`server_extra` / `client_extra` 追加到命令行，便于测降级路径。
pub async fn setup_with(server_extra: &[String], client_extra: &[String]) -> anyhow::Result<Stack> {
    setup_with_psk(server_extra, client_extra, None, None).await
}

/// 可分别指定两端 PSK 的夹具。用于验证「PSK 不一致必须失败，而不是降级成明文」。
pub async fn setup_with_psk(
    server_extra: &[String],
    client_extra: &[String],
    server_psk: Option<&str>,
    client_psk: Option<&str>,
) -> anyhow::Result<Stack> {
    setup_full(server_extra, client_extra, server_psk, client_psk, &[], &[]).await
}

/// 全参数夹具：两端 PSK + **两端环境变量**（第 181 轮从 `setup_with_psk` 里抽出来 ✓）。
///
/// 抽的理由与 [`start_once_env`] 相同：`DSHP_WEBUI_TOKEN` **只有环境变量一条来源**
/// （没有 CLI 开关），而需要凭据的管理端点（`/__dshp/drain` 排空）必须能被测到 ✓。
/// 好处是"换端口重试 3 次"那套逻辑仍然只有一份 ✓（不复制第二遍 ✗）。
pub async fn setup_full(
    server_extra: &[String],
    client_extra: &[String],
    server_psk: Option<&str>,
    client_psk: Option<&str>,
    server_env: &[(&str, &str)],
    client_env: &[(&str, &str)],
) -> anyhow::Result<Stack> {
    // **启动失败要重试**（第 161 轮加 ✗→✓）。
    //
    // 实测（10 遍里 1 次 ✗）：用例在**夹具区** `expect("启动失败")` 失败 —— 与代理逻辑无关 ✓，
    // 根因是 `free_port()` 的**竞态**（先挑一个"此刻空闲"的端口、随后才去绑 ✗）或被残留进程占住 ✓。
    // 这类失败会让**任意用例随机变红** ⇒ 与 CI 里那串 502 同源 ✓（都是"连不上/绑不上"）。
    // ⇒ 处置：**换端口重试 3 次** ✓，并把每次失败的端口打出来 ✓（否则"随机红"永远查不清 ✗）。
    let mut last: Option<anyhow::Error> = None;
    for attempt in 1..=3 {
        let dport = free_port().await;
        let cport = free_port().await;
        match start_once_env(
            server_extra,
            client_extra,
            server_psk,
            client_psk,
            dport,
            cport,
            server_env,
            client_env,
        )
        .await
        {
            Ok(st) => return Ok(st),
            Err(e) => {
                eprintln!(
                    "  [夹具] 第 {attempt} 次启动失败（dport={dport} cport={cport}）：{e} ⇒ 换端口重试 ✓"
                );
                last = Some(e);
            }
        }
    }
    // ⚠️ 第 163 轮修：这里原先写 `Err(last.unwrap_or_else(…))` ✗ ⇒ **永远返回最后一次的错误** ✓
    // ⇒ 我在上面加的那句"重试 3 次"文案**根本没机会出现** ✗✗（`fixture_retry.rs` 的断言当场抓到 ✓）。
    // ⇒ 现在把**重试上下文包进去** ✓：调用者一眼能看出"试过 3 次、每次换了端口" ✓。
    Err(anyhow::anyhow!(
        "夹具启动失败：**重试 3 次均失败** ✗（每次都已换新端口 ✓）。最后一次错误：{}",
        last.map(|e| format!("{e:#}"))
            .unwrap_or_else(|| "（无）".to_string())
    ))
}

/// 等 DSHP 链路**真的**建好（第 174 轮把两处逐字相同的等待抽成它 ✓）。
///
/// 为什么需要 ✓：第 167 轮我在两个夹具里各写了一份**逐字相同**的等待 ✗ ⇒ 锚点分不开 ✓、
/// 想按 PSK 门控也没法加参数 ✓ ⇒ 于是只能"无条件等" ✗ ⇒ **自伤了那条故意配错 PSK 的用例** ✗
/// （`mismatched_psk_never_establishes_a_session` 的期望**正是**"建不起来" ✓，实测 CI 三条重试全打在它身上 ✓）。
///
/// `expect == true`：等不到就**报警告**（把客户端 status 与两端 stderr 尾部一起打出来 ✓，
/// 但不致命 ✓ —— 因为某些夹具本来就走 bypass/故意断链 ✓）。
/// `expect == false`：**不等** ✓（链路本该建不起来时 ✓）。
pub async fn wait_for_link(client: &str, expect: bool) {
    if !expect {
        return;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut last_status = String::from("（读不到）");
    let link_t0 = tokio::time::Instant::now();
    loop {
        let status_json = raw_request(client, "GET", "/__dshp/status", &[], b"")
            .await
            .ok()
            .and_then(|r| serde_json::from_slice::<serde_json::Value>(&r.body).ok());
        let linked = status_json
            .as_ref()
            .and_then(|v| v["aead"]["enabled"].as_bool())
            .unwrap_or(false);
        if linked {
            println!(
                "  [夹具] 链路建立耗时 {:.1}ms ✓（第 169 轮的分布样本）",
                link_t0.elapsed().as_secs_f64() * 1000.0
            );
            return;
        }
        if let Some(v) = &status_json {
            last_status = v.to_string();
        }
        if tokio::time::Instant::now() >= deadline {
            let tail = |bin: &str| -> String {
                std::fs::read_to_string(target_dir().join("e2e-logs").join(format!("{bin}.err")))
                    .map(|s| {
                        let v: Vec<&str> = s.lines().rev().take(6).collect();
                        v.into_iter().rev().collect::<Vec<_>>().join(" ｜ ")
                    })
                    .unwrap_or_else(|_| "（无日志）".to_string())
            };
            eprintln!(
                "  [夹具] ⚠️ DSHP 链路 5s 内没建立（`aead` 仍关着 ⇒ 请求会走 bypass ⇒ **若本夹具没配\n\
                 bypass 上游，第一个请求就会 502** ✗）—— 不致命，继续跑 ✓\n\
                 · 客户端 status：{last_status}\n\
                 · llmproxyd stderr 尾部：{}\n\
                 · llmproxyc stderr 尾部：{}",
                tail("llmproxyd"),
                tail("llmproxyc")
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// 单次启动尝试（第 161 轮从 `setup_with_psk` 里抽出来 ✓，以便**换端口重试** ✓）。
///
/// 第 163 轮起是 `pub` ✓ —— 供 `fixture_retry.rs` 直接验证"启动失败会被重试" ✓。
pub async fn start_once(
    server_extra: &[String],
    client_extra: &[String],
    server_psk: Option<&str>,
    client_psk: Option<&str>,
    dport: u16,
    cport: u16,
) -> anyhow::Result<Stack> {
    start_once_env(
        server_extra,
        client_extra,
        server_psk,
        client_psk,
        dport,
        cport,
        &[],
        &[],
    )
    .await
}

/// 同 [`start_once`]，但可给两端**显式注入环境变量**（第 181 轮加）。
///
/// 为什么需要：`DSHP_WEBUI_TOKEN` **只有环境变量这一条来源**（没有 CLI 开关）
/// ⇒ 要测需要凭据的管理端点（`/__dshp/drain` 优雅排空），夹具就必须能设它。
/// 这是**配置**，不是"生产代码里的注入开关" ✓ —— 后者是项目明令禁止的 ✗。
#[allow(clippy::too_many_arguments)] // 夹具参数：拆结构体只会让每个调用点更长（项目既有惯例）
pub async fn start_once_env(
    server_extra: &[String],
    client_extra: &[String],
    server_psk: Option<&str>,
    client_psk: Option<&str>,
    dport: u16,
    cport: u16,
    server_env: &[(&str, &str)],
    client_env: &[(&str, &str)],
) -> anyhow::Result<Stack> {
    // 第 174 轮：**两端 PSK 一致时才等链路** ✓（不一致时"建不起来"正是设计要验的行为 ✓）。
    let expect_link = server_psk == client_psk;
    let up = MockUpstream::start().await;

    let mut dargs: Vec<String> = vec![
        "--listen".into(),
        format!("127.0.0.1:{dport}"),
        "--upstream".into(),
        up.base_url(),
    ];
    // 生产默认不按请求数量限流；这组历史资源预算测试需要显式固定 4，
    // 否则它们测到的是无界模式而不是各自声明的上限性质。
    if !server_extra
        .iter()
        .any(|arg| arg == "--max-concurrent-streams")
    {
        dargs.extend([
            "--max-concurrent-streams".into(),
            llm_proxy_core::config::MAX_CONCURRENT_STREAMS.to_string(),
        ]);
    }
    if !server_extra
        .iter()
        .any(|arg| arg == "--max-pending-streams")
    {
        dargs.extend(["--max-pending-streams".into(), "32".into()]);
    }
    dargs.extend_from_slice(server_extra);
    let drefs: Vec<&str> = dargs.iter().map(String::as_str).collect();
    let d = spawn_proxy_env("llmproxyd", &drefs, true, server_psk, server_env)?;
    anyhow::ensure!(
        wait_ready(&format!("127.0.0.1:{dport}"), Duration::from_secs(8)).await,
        "llmproxyd 未在 8s 内就绪"
    );

    let mut cargs: Vec<String> = vec![
        "--listen".into(),
        format!("127.0.0.1:{cport}"),
        "--server".into(),
        format!("ws://127.0.0.1:{dport}"),
    ];
    cargs.extend_from_slice(client_extra);
    let crefs: Vec<&str> = cargs.iter().map(String::as_str).collect();
    let c = spawn_proxy_env("llmproxyc", &crefs, false, client_psk, client_env)?;
    let client = format!("127.0.0.1:{cport}");
    anyhow::ensure!(
        wait_ready(&client, Duration::from_secs(8)).await,
        "llmproxyc 未在 8s 内就绪"
    );

    // ⚠️ **端口通了 ≠ 链路建好了** ✗→✓（第 167 轮 —— 这是追了 6 轮的"首请求 502"的真根因 ✓）。
    // 第 174 轮把这**两处逐字相同**的等待（原先分别在 `start_once` 与 `setup_resilient_with_backoff` 里 ✗，
    // 锚点分不开、也没法按 PSK 门控 ⇒ 只能无条件等 ⇒ 自伤了故意配错 PSK 的用例 ✗）
    // **抽成 [`wait_for_link`]** ✓：现在能传 `expect_link` ✓，语境与实现都由那一个函数说清 ✓。
    wait_for_link(&client, expect_link).await;

    Ok(Stack {
        up,
        d,
        c,
        client,
        dport,
    })
}

/// 起完整链路，并给客户端配上 **L2 直连回退**（指向同一个 mock 上游）。
///
/// 用于验证降级链末端：DSHP 链路不可用时，客户端应当**继续服务**而不是整体挂掉。
pub async fn setup_resilient(
    server_extra: &[String],
    client_extra: &[String],
) -> anyhow::Result<Stack> {
    // 测试里把退避压到很小，否则恢复要等好几秒（`resilience.rs` 的验收只关心"能不能恢复"）
    setup_resilient_with_backoff(server_extra, client_extra, 100, 400).await
}

/// 同 `setup_resilient`，但**退避参数可指定**。
///
/// 为什么需要：`setup_resilient` 把退避压到 100/400ms 是为了让"能否恢复"的测试跑得快，
/// 但那样量出来的**重连时延不是生产值**（生产默认是 200ms 起）。
/// 要把"断链后多久恢复"当作一个**数字**记录进文档，就必须用生产默认值来量。
pub async fn setup_resilient_with_backoff(
    server_extra: &[String],
    client_extra: &[String],
    reconnect_min_ms: u64,
    reconnect_max_ms: u64,
) -> anyhow::Result<Stack> {
    // 第 174 轮：本夹具两端 PSK 都是默认值 ⇒ 一致 ⇒ 等链路 ✓。
    let expect_link = true;
    let up = MockUpstream::start().await;
    let fallback = up.base_url();
    let dport = free_port().await;
    let cport = free_port().await;

    let mut dargs: Vec<String> = vec![
        "--listen".into(),
        format!("127.0.0.1:{dport}"),
        "--upstream".into(),
        up.base_url(),
    ];
    dargs.extend_from_slice(server_extra);
    let drefs: Vec<&str> = dargs.iter().map(String::as_str).collect();
    let d = spawn_proxy("llmproxyd", &drefs, true)?;
    anyhow::ensure!(
        wait_ready(&format!("127.0.0.1:{dport}"), Duration::from_secs(8)).await,
        "llmproxyd 未在 8s 内就绪"
    );

    let mut cargs: Vec<String> = vec![
        "--listen".into(),
        format!("127.0.0.1:{cport}"),
        "--server".into(),
        format!("ws://127.0.0.1:{dport}"),
        "--upstream-fallback".into(),
        fallback,
        "--reconnect-min-ms".into(),
        reconnect_min_ms.to_string(),
        "--reconnect-max-ms".into(),
        reconnect_max_ms.to_string(),
    ];
    cargs.extend_from_slice(client_extra);
    let crefs: Vec<&str> = cargs.iter().map(String::as_str).collect();
    let c = spawn_proxy("llmproxyc", &crefs, false)?;
    let client = format!("127.0.0.1:{cport}");
    anyhow::ensure!(
        wait_ready(&client, Duration::from_secs(8)).await,
        "llmproxyc 未在 8s 内就绪"
    );

    // ⚠️ **端口通了 ≠ 链路建好了** ✗→✓（第 167 轮 —— 这是追了 6 轮的"首请求 502"的真根因 ✓）。
    // 第 174 轮把这**两处逐字相同**的等待（原先分别在 `start_once` 与 `setup_resilient_with_backoff` 里 ✗，
    // 锚点分不开、也没法按 PSK 门控 ⇒ 只能无条件等 ⇒ 自伤了故意配错 PSK 的用例 ✗）
    // **抽成 [`wait_for_link`]** ✓：现在能传 `expect_link` ✓，语境与实现都由那一个函数说清 ✓。
    wait_for_link(&client, expect_link).await;

    Ok(Stack {
        up,
        d,
        c,
        client,
        dport,
    })
}

/// 用同一个端口重启服务端（用于验证恢复）。
pub fn respawn_server(port: u16, upstream: &str) -> anyhow::Result<Proc> {
    spawn_proxy(
        "llmproxyd",
        &[
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--upstream",
            upstream,
        ],
        true,
    )
}

/// 「黑洞」中间设备：接受 TCP，但**永不回话**（读完就挂着，不断开）。
///
/// 现有故障夹具都是**拒绝**型（403 / 502 / ECONNREFUSED），它们快速失败，所以降级链
/// 很快走完。真实企业网络更常见的是**黑洞**：连接建上了，对面永不回话。此时"快速失败"
/// 的前提不成立——如果实现没有自己的超时，整条降级链会**卡在第一个传输上**。
/// 这条守的就是那个前提：**永不回话的对端面前，客户端仍然服务**。
pub struct BlackHole {
    pub addr: String,
}

impl BlackHole {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            // 只持有连接：不读、不写、不断开。
            let mut held = Vec::new();
            loop {
                match listener.accept().await {
                    Ok((sock, _)) => held.push(sock),
                    Err(_) => break,
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        });
        Self { addr }
    }
}

/// 客户端指向**黑洞**（其余同 `setup_resilient`：配了上游回退，链路建不起来能落 L2）。
pub async fn setup_behind_black_hole() -> anyhow::Result<Stack> {
    let up = MockUpstream::start().await;
    let fallback = up.base_url();
    let cport = free_port().await;
    let hole = BlackHole::start().await;
    let cargs: Vec<String> = vec![
        "--listen".into(),
        format!("127.0.0.1:{cport}"),
        "--server".into(),
        format!("ws://{}", hole.addr),
        "--upstream-fallback".into(),
        fallback,
        "--reconnect-min-ms".into(),
        "200".into(),
        "--reconnect-max-ms".into(),
        "5000".into(),
    ];
    let crefs: Vec<&str> = cargs.iter().map(String::as_str).collect();
    let c = spawn_proxy("llmproxyc", &crefs, false)?;
    let client = format!("127.0.0.1:{cport}");
    anyhow::ensure!(
        wait_ready(&client, Duration::from_secs(8)).await,
        "llmproxyc 未在 8s 内就绪"
    );
    Box::leak(Box::new(hole));
    // 这个夹具不需要服务端：`d` 起一个未被使用的，保持 `Stack` 形状一致。
    let dport = free_port().await;
    let dargs: Vec<String> = vec![
        "--listen".into(),
        format!("127.0.0.1:{dport}"),
        "--upstream".into(),
        up.base_url(),
    ];
    let drefs: Vec<&str> = dargs.iter().map(String::as_str).collect();
    let d = spawn_proxy("llmproxyd", &drefs, true)?;
    Ok(Stack {
        up,
        d,
        c,
        client,
        dport,
    })
}

// ---------------------------------------------------------------------------
// 只拦 WebSocket 的中间代理
// ---------------------------------------------------------------------------

/// 模拟**企业代理放通 POST、拦掉 WebSocket `Upgrade`** 的常见配置。
///
/// 这是 SSE 传输模式存在的**唯一理由**，所以验收必须真的复现这个条件，而不是
/// 用 `--force-mode sse` 绕过去——后者能证明"SSE 能用"，却证明不了"WS 被拦时
/// **自动**落到 SSE"这条 M3 验收原文。
///
/// 实现：读够请求头，含 `upgrade:` 就回 403 并断开；否则把已读字节补写回去、
/// 双向透传。
pub struct WsBlockingProxy {
    pub addr: String,
    _task: tokio::task::JoinHandle<()>,
}

impl WsBlockingProxy {
    pub async fn start(target: String) -> Self {
        Self::start_with(target, false).await
    }

    /// `block_tunnel = true` 时**连 SSE 隧道一起拦掉**（对 `/__dshp/tunnel` 直接 502）。
    ///
    /// 这是"模式全挂"的故障注入：WS 与 SSE 都不通，客户端只能落到 L2 直连上游
    /// （设计 §10 降级链的最后一档）。它守的性质不是"降级发生了"，而是
    /// **降级之后结果依然逐字节正确**。
    pub async fn start_with(target: String, block_tunnel: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut inbound, _)) = listener.accept().await else {
                    break;
                };
                let target = target.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    // 读请求头（到 \r\n\r\n 为止）
                    let mut head = Vec::new();
                    let mut b = [0u8; 1];
                    while head.len() < 8192 {
                        match inbound.read(&mut b).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {
                                head.push(b[0]);
                                if head.ends_with(b"\r\n\r\n") {
                                    break;
                                }
                            }
                        }
                    }
                    let lower = String::from_utf8_lossy(&head).to_lowercase();
                    if lower.contains("upgrade:") {
                        let _ = inbound
                            .write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n")
                            .await;
                        return; // 断开：正是中间设备拦 WebSocket 的行为
                    }
                    if block_tunnel && lower.contains("/__dshp/tunnel") {
                        let _ = inbound
                            .write_all(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n")
                            .await;
                        return;
                    }
                    let Ok(mut outbound) = tokio::net::TcpStream::connect(&target).await else {
                        return;
                    };
                    let _ = outbound.write_all(&head).await;
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                });
            }
        });
        Self { addr, _task: task }
    }
}

/// 起完整链路，但 **WS 与 SSE 隧道都被中间代理拦掉**，只能直连上游。
pub async fn setup_behind_all_modes_blocker() -> anyhow::Result<Stack> {
    let up = MockUpstream::start().await;
    let dport = free_port().await;
    let cport = free_port().await;

    let dargs: Vec<String> = vec![
        "--listen".into(),
        format!("127.0.0.1:{dport}"),
        "--upstream".into(),
        up.base_url(),
    ];
    let drefs: Vec<&str> = dargs.iter().map(String::as_str).collect();
    let d = spawn_proxy("llmproxyd", &drefs, true)?;
    anyhow::ensure!(
        wait_ready(&format!("127.0.0.1:{dport}"), Duration::from_secs(8)).await,
        "llmproxyd 未在 8s 内就绪"
    );

    let blocker = WsBlockingProxy::start_with(format!("127.0.0.1:{dport}"), true).await;

    let cargs: Vec<String> = vec![
        "--listen".into(),
        format!("127.0.0.1:{cport}"),
        "--server".into(),
        format!("ws://{}", blocker.addr),
        "--upstream-fallback".into(),
        up.base_url(),
    ];
    let crefs: Vec<&str> = cargs.iter().map(String::as_str).collect();
    let c = spawn_proxy("llmproxyc", &crefs, false)?;
    let client = format!("127.0.0.1:{cport}");
    anyhow::ensure!(
        wait_ready(&client, Duration::from_secs(8)).await,
        "llmproxyc 未在 8s 内就绪"
    );

    Box::leak(Box::new(blocker));

    Ok(Stack {
        up,
        d,
        c,
        client,
        dport,
    })
}

/// 起完整链路，但客户端的 WS 被中间代理拦掉，只能落到 SSE。
pub async fn setup_behind_ws_blocker() -> anyhow::Result<Stack> {
    let up = MockUpstream::start().await;
    let dport = free_port().await;
    let cport = free_port().await;

    let dargs: Vec<String> = vec![
        "--listen".into(),
        format!("127.0.0.1:{dport}"),
        "--upstream".into(),
        up.base_url(),
    ];
    let drefs: Vec<&str> = dargs.iter().map(String::as_str).collect();
    let d = spawn_proxy("llmproxyd", &drefs, true)?;
    anyhow::ensure!(
        wait_ready(&format!("127.0.0.1:{dport}"), Duration::from_secs(8)).await,
        "llmproxyd 未在 8s 内就绪"
    );

    let blocker = WsBlockingProxy::start(format!("127.0.0.1:{dport}")).await;

    let cargs: Vec<String> = vec![
        "--listen".into(),
        format!("127.0.0.1:{cport}"),
        "--server".into(),
        format!("ws://{}", blocker.addr),
        "--upstream-fallback".into(),
        up.base_url(),
    ];
    let crefs: Vec<&str> = cargs.iter().map(String::as_str).collect();
    let c = spawn_proxy("llmproxyc", &crefs, false)?;
    let client = format!("127.0.0.1:{cport}");
    anyhow::ensure!(
        wait_ready(&client, Duration::from_secs(8)).await,
        "llmproxyc 未在 8s 内就绪"
    );

    // blocker 必须活到测试结束：绑在 Stack 的自定义字段上会让类型复杂化，
    // 这里用 `Box::leak` 换简化——测试进程很快退出，代价可忽略。
    Box::leak(Box::new(blocker));

    // ⚠️ **必须等 DSHP 链路真的建好**，不能只等 HTTP 端口就绪（第 180 轮修）：
    // `wait_ready` 只保证 `/__dshp/status` 能应答，而那时客户端的**首次链路尝试可能还没结束**
    // —— 此时 `mode` 还是初始值 `bypass`（"还没有链路"）、`link_ms` 还是 0。
    // 之前的判据正是踩了这个竞态：Windows 上恰好赢了（读的时候已经落到 SSE），
    // GitHub 的 Linux runner 上输了 ⇒ `ws_blocked_by_middlebox_...` 确定性红（两遍都红）✗。
    wait_for_link(&client, true).await;

    Ok(Stack {
        up,
        d,
        c,
        client,
        dport,
    })
}
pub async fn setup() -> anyhow::Result<Stack> {
    setup_with(&[], &[]).await
}

// ---------------------------------------------------------------------------
// 原始 DSHP 对端（M7：只有"说谎的客户端"才碰得到 FP_MISMATCH）
// ---------------------------------------------------------------------------

/// 直接与 `llmproxyd` 建一条 DSHP 会话，**不经过 `llmproxyc`**。
///
/// 为什么必须有它：`target_fp` 是客户端**自己算的**，正常客户端永远算对——
/// `FP_MISMATCH` 这条红线守的是"两端认知不一致"，要走到它只能伪造一个
/// "内容与声明不符"的请求。HTTP 层的夹具做不到（状态全在被测进程里），
/// 所以必须下沉到协议层，自己跑一遍 DSHP 握手。
///
/// 握手步骤与 `llmproxyc::ingress::handshake` 同构，但这里**刻意重写**而不是复用：
/// 那是被测进程内部的私有函数，而且这里的语义是「**不可信**的对端」。
pub struct RawPeer {
    pub mux: llm_proxy_transport::Mux,
    pub inbox: tokio::sync::mpsc::Receiver<llm_proxy_core::Frame>,
    pub caps: llm_proxy_core::proto::Caps,
}

/// 连上 `llmproxyd` 的 DSHP 端口并完成握手（含 AEAD 启用）。
/// 原始对端握手，带租户。`tenant` 参与 Hello——**它是租户隔离的入口**（设计 §4.1）：
/// 服务端拿它与自己的配置比对，不一致直接拒绝连接。
/// 握手**被拒绝**时，把服务端回的那条 `Err` 原样取出来。
///
/// # 为什么需要它
///
/// `connect_raw_peer_with_tenant` 在收到 `Err` 时直接 `bail`，只留下一句话——
/// 而拒绝**本身**是协议行为，值得被断言：错误码、提示、以及**详情的通用性**
/// （服务端刻意不回具体原因，否则等于送给未认证来源一个认证预言机）。
/// 只断言"连不上"测不到这三点。
pub async fn connect_raw_peer_expecting_refusal(
    dport: u16,
    psk: &[u8],
    tenant: &str,
) -> anyhow::Result<llm_proxy_core::proto::Err> {
    use prost::Message;
    use std::time::{SystemTime, UNIX_EPOCH};

    let (mux, mut inbox) = llm_proxy_transport::connect(&format!("ws://127.0.0.1:{dport}"))
        .await
        .map_err(|e| anyhow::anyhow!("WS 建链失败：{e}"))?;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let nonce = ts as u64;
    let hmac = llm_proxy_transport::handshake_mac(psk, nonce, ts);
    let patch_dict = llm_proxy_core::dict::Dicts::bootstrap().patch;
    let hs = llm_proxy_core::crypto::Initiator::new(psk).map_err(|e| anyhow::anyhow!("{e}"))?;
    let hello = llm_proxy_core::proto::Hello {
        proto_version: llm_proxy_core::config::PROTO_VERSION.to_string(),
        tenant: tenant.to_string(),
        dict_id: llm_proxy_core::dict::dict_id(patch_dict),
        dict: patch_dict.to_vec(),
        nonce,
        timestamp_ms: ts,
        hmac,
        caps: vec![
            "ws".into(),
            "raw".into(),
            "tokenstream".into(),
            "zstd".into(),
        ],
        x25519_pub: hs.public().to_vec(),
    };
    mux.send_session(llm_proxy_core::FrameType::Hello, hello.encode_to_vec())
        .await
        .map_err(|e| anyhow::anyhow!("发送 Hello 失败：{e}"))?;

    loop {
        let f = tokio::time::timeout(std::time::Duration::from_secs(8), inbox.recv())
            .await
            .map_err(|_| anyhow::anyhow!("等服务端判定超时（既没给 Caps 也没给 Err）"))?
            .ok_or_else(|| anyhow::anyhow!("握手期连接关闭，且没有收到任何 Err"))?;
        match f.ty {
            llm_proxy_core::FrameType::Err => {
                return llm_proxy_core::proto::Err::decode(&f.payload[..])
                    .map_err(|e| anyhow::anyhow!("Err 解码失败：{e}"));
            }
            // 服务端要是给了 Caps，说明它**接受了**这次握手——那这条测试要抓的就是失败
            llm_proxy_core::FrameType::Caps => {
                anyhow::bail!("服务端接受了本应被拒绝的握手（收到了 Caps 而不是 Err）")
            }
            _ => continue,
        }
    }
}

pub async fn connect_raw_peer_with_tenant(
    dport: u16,
    psk: &[u8],
    tenant: &str,
) -> anyhow::Result<RawPeer> {
    use prost::Message;
    use std::time::{SystemTime, UNIX_EPOCH};

    let (mux, mut inbox) = llm_proxy_transport::connect(&format!("ws://127.0.0.1:{dport}"))
        .await
        .map_err(|e| anyhow::anyhow!("WS 建链失败：{e}"))?;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let hmac = llm_proxy_transport::handshake_mac(psk, nonce, ts);
    let patch_dict = llm_proxy_core::dict::Dicts::bootstrap().patch;
    let hs = llm_proxy_core::crypto::Initiator::new(psk).map_err(|e| anyhow::anyhow!("{e}"))?;
    let hello = llm_proxy_core::proto::Hello {
        proto_version: llm_proxy_core::config::PROTO_VERSION.to_string(),
        tenant: tenant.to_string(),
        dict_id: llm_proxy_core::dict::dict_id(patch_dict),
        dict: patch_dict.to_vec(),
        nonce,
        timestamp_ms: ts,
        hmac,
        caps: vec![
            "ws".into(),
            "raw".into(),
            "tokenstream".into(),
            "zstd".into(),
        ],
        x25519_pub: hs.public().to_vec(),
    };
    mux.send_session(llm_proxy_core::FrameType::Hello, hello.encode_to_vec())
        .await
        .map_err(|e| anyhow::anyhow!("发送 Hello 失败：{e}"))?;

    let caps = loop {
        let f = tokio::time::timeout(std::time::Duration::from_secs(8), inbox.recv())
            .await
            .map_err(|_| anyhow::anyhow!("等 Caps 超时"))?
            .ok_or_else(|| anyhow::anyhow!("握手期连接关闭"))?;
        match f.ty {
            llm_proxy_core::FrameType::Caps => break f,
            llm_proxy_core::FrameType::Err => {
                let e = llm_proxy_core::proto::Err::decode(&f.payload[..]).unwrap_or_default();
                anyhow::bail!("服务端拒绝握手（code={}）：{}", e.code, e.detail);
            }
            _ => continue,
        }
    };
    let caps = llm_proxy_core::proto::Caps::decode(&caps.payload[..])
        .map_err(|e| anyhow::anyhow!("Caps 解码失败：{e}"))?;
    let their_pub: [u8; 32] = caps
        .x25519_pub
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Caps 里的公钥不是 32 字节"))?;
    let done = hs.finish(their_pub);
    done.verify_peer(&caps.confirm)
        .map_err(|e| anyhow::anyhow!("服务端确认值校验失败：{e}"))?;
    mux.enable_crypto(llm_proxy_transport::SessionCrypto::new(&done.keys, true));
    let kc = llm_proxy_core::proto::KeyConfirm {
        confirm: done.our_confirm.to_vec(),
    };
    mux.send_session(llm_proxy_core::FrameType::KeyConfirm, kc.encode_to_vec())
        .await
        .map_err(|e| anyhow::anyhow!("发送 KeyConfirm 失败：{e}"))?;
    Ok(RawPeer { mux, inbox, caps })
}

impl RawPeer {
    /// 发一条**完整**请求（`ReqOpen` + 载荷 + `LAST` + `ReqCommit`），返回流号。
    ///
    /// `target_fp` 由调用方给定——**这正是能造假的地方**。
    pub async fn send_request(
        &self,
        sid: u32,
        method: &str,
        path: &str,
        encoding: llm_proxy_core::proto::Encoding,
        target_fp: Vec<u8>,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        self.send_request_with_headers(
            sid,
            method,
            path,
            vec![llm_proxy_core::proto::Header {
                name: "content-type".into(),
                value: b"application/json".to_vec(),
            }],
            encoding,
            target_fp,
            payload,
        )
        .await
    }

    /// **只发 `ReqOpen`，故意不发请求体**——用来占住并发流槽位。
    ///
    /// 服务端的并发槽位在 `ReqOpen` 时获取、流结束才释放，所以"4 个半截流"就能把上限占满，
    /// 第 5 个才会走到"等待槽位超时 → `TOO_MANY_STREAMS`"。正常客户端不会发半截流，
    /// 所以这条只能靠原始对端触发。
    pub async fn send_open_only(
        &self,
        sid: u32,
        method: &str,
        path: &str,
        encoding: llm_proxy_core::proto::Encoding,
        target_fp: Vec<u8>,
    ) -> anyhow::Result<()> {
        use prost::Message;
        let open = llm_proxy_core::proto::ReqOpen {
            method: method.to_string(),
            path_and_query: path.to_string(),
            headers: vec![llm_proxy_core::proto::Header {
                name: "content-type".into(),
                value: b"application/json".to_vec(),
            }],
            alt_bases: Vec::new(),
            encoding: encoding as i32,
            target_fp,
            req_id: sid as u64,
            // 这个原生客户端**没有跨响应的模板表** ⇒ 一个 id 都不知道（0 ✓）⇒
            // 服务端会把本流引用到的模板定义全部下发 ✓（第 196 轮 `terminated` 的根因 ✓）。
            // 这个原生客户端**没有跨响应的模板表** ⇒ 声明「我没表」✓ ⇒ 服务端全量补发 def ✓
            // （第 195/197 轮 `terminated` 的根因 ✓）。
            client_needs_defs: true,
        };
        self.mux
            .send(llm_proxy_core::Frame::new(
                llm_proxy_core::FrameType::ReqOpen,
                sid,
                0,
                open.encode_to_vec(),
            ))
            .await
            .map_err(|e| anyhow::anyhow!("发送 ReqOpen 失败：{e}"))
    }

    /// 同 `send_request`，但**自己指定头**。
    ///
    /// 需要它是因为有些断言只能用"说谎的客户端"触发：
    /// 例如声明 `Content-Length: 999` 却发别长度的体，
    /// 服务端必须报 `LENGTH_MISMATCH` 而**不是**照发上游（Content-Length 一致性是红线）。
    #[allow(clippy::too_many_arguments)]
    pub async fn send_request_with_headers(
        &self,
        sid: u32,
        method: &str,
        path: &str,
        headers: Vec<llm_proxy_core::proto::Header>,
        encoding: llm_proxy_core::proto::Encoding,
        target_fp: Vec<u8>,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        use prost::Message;
        let open = llm_proxy_core::proto::ReqOpen {
            method: method.to_string(),
            path_and_query: path.to_string(),
            headers,
            // 与客户端保持一致：这个字段恒为空（前缀基线方案已被内容寻址的块引用取代，
            // 详见 `llmproxyc/src/ingress.rs` 里 ReqOpen 处的注释与设计 §5.2）
            alt_bases: Vec::new(),
            encoding: encoding as i32,
            target_fp,
            req_id: sid as u64,
            // 这个原生客户端**没有跨响应的模板表** ⇒ 一个 id 都不知道（0 ✓）⇒
            // 服务端会把本流引用到的模板定义全部下发 ✓（第 196 轮 `terminated` 的根因 ✓）。
            // 这个原生客户端**没有跨响应的模板表** ⇒ 声明「我没表」✓ ⇒ 服务端全量补发 def ✓
            // （第 195/197 轮 `terminated` 的根因 ✓）。
            client_needs_defs: true,
        };
        self.mux
            .send(llm_proxy_core::Frame::new(
                llm_proxy_core::FrameType::ReqOpen,
                sid,
                0,
                open.encode_to_vec(),
            ))
            .await
            .map_err(|e| anyhow::anyhow!("发送 ReqOpen 失败：{e}"))?;

        let mut seq = 1u32;
        for chunk in payload.chunks(256 * 1024) {
            self.mux
                .send(llm_proxy_core::Frame::new(
                    llm_proxy_core::FrameType::BodyChunk,
                    sid,
                    seq,
                    chunk.to_vec(),
                ))
                .await
                .map_err(|e| anyhow::anyhow!("发送 BodyChunk 失败：{e}"))?;
            seq += 1;
        }
        let mut last =
            llm_proxy_core::Frame::new(llm_proxy_core::FrameType::BodyChunk, sid, seq, Vec::new());
        last.flags = llm_proxy_core::Flags::default().with(llm_proxy_core::flags::LAST);
        self.mux
            .send(last)
            .await
            .map_err(|e| anyhow::anyhow!("发送 LAST 失败：{e}"))?;
        let commit = llm_proxy_core::proto::ReqCommit { req_id: sid as u64 };
        self.mux
            .send(llm_proxy_core::Frame::new(
                llm_proxy_core::FrameType::ReqCommit,
                sid,
                seq + 1,
                commit.encode_to_vec(),
            ))
            .await
            .map_err(|e| anyhow::anyhow!("发送 ReqCommit 失败：{e}"))?;
        Ok(())
    }

    /// 等这条流上的第一个 `Err` 或 `RespHead`，返回 `(是Err, 解码结果描述)`。
    ///
    /// 只关心这两类：`Err` 说明服务端拒绝了（红线生效），`RespHead` 说明
    /// 它**把内容发上游了**——那才是要抓的失败。
    pub async fn await_verdict(&mut self, sid: u32) -> anyhow::Result<RawVerdict> {
        let deadline = std::time::Duration::from_secs(10);
        let start = std::time::Instant::now();
        loop {
            let left = deadline.checked_sub(start.elapsed()).unwrap_or_default();
            if left.is_zero() {
                anyhow::bail!("等判定超时（既没有 Err 也没有 RespHead）");
            }
            let f = match tokio::time::timeout(left, self.inbox.recv()).await {
                Ok(Some(f)) => f,
                Ok(None) => anyhow::bail!("连接在判定前关闭"),
                Err(_) => anyhow::bail!("等判定超时（既没有 Err 也没有 RespHead）"),
            };
            if f.stream_id != sid && f.stream_id != 0 {
                continue;
            }
            match f.ty {
                llm_proxy_core::FrameType::Err => {
                    use prost::Message;
                    let e = llm_proxy_core::proto::Err::decode(&f.payload[..]).unwrap_or_default();
                    return Ok(RawVerdict::Rejected {
                        code: e.code,
                        hint: e.hint,
                        detail: e.detail,
                        fps: e.missing.len(),
                    });
                }
                llm_proxy_core::FrameType::RespHead => {
                    use prost::Message;
                    let h =
                        llm_proxy_core::proto::RespHead::decode(&f.payload[..]).unwrap_or_default();
                    return Ok(RawVerdict::Forwarded { status: h.status });
                }
                _ => continue,
            }
        }
    }
}

#[derive(Debug)]
pub enum RawVerdict {
    /// 服务端**拒绝**了这条请求（给了明确的错误码与提示）——红线要求的行为
    Rejected {
        code: u32,
        hint: String,
        detail: String,
        fps: usize,
    },
    /// 服务端把请求**发给了上游**——对 `FP_MISMATCH` 场景而言这就是失败
    Forwarded { status: u32 },
}

/// 逐字节中继，但**按字节预算把连接砍断**的故障注入代理。
///
/// 为什么需要它：`WsBlockingProxy` 只能"整条拦掉"，而 M7 要注入的是
/// **传了一半才断**。字节预算是确定性的——同样的请求，断点落在同一位置，
/// 不像"睡一会儿再杀"那样看运气。
///
/// 两个方向各有一个预算（`None` = 不限）。哪个方向先耗尽，整条连接立刻断掉：
/// 这模拟的是中间设备/链路在传输中途消失，而不是"对方正常关闭"。
pub struct CutProxy {
    pub addr: String,
    _task: tokio::task::JoinHandle<()>,
}

impl CutProxy {
    pub async fn start(
        target: String,
        up_budget: Option<usize>,
        down_budget: Option<usize>,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            loop {
                let Ok((inbound, _)) = listener.accept().await else {
                    break;
                };
                let target = target.clone();
                tokio::spawn(async move {
                    let Ok(upstream) = tokio::net::TcpStream::connect(&target).await else {
                        return;
                    };
                    let (cr, cw) = inbound.into_split();
                    let (sr, sw) = upstream.into_split();
                    let a = pump(cr, sw, up_budget, "C→S");
                    let b = pump(sr, cw, down_budget, "S→C");
                    // 任一方向结束就取消另一方向：两个写半端随之被 drop，
                    // TCP 连接被**硬断**（不是 FIN 之后的对端正常收尾）。
                    tokio::select! {
                        _ = a => {}
                        _ = b => {}
                    }
                });
            }
        });
        Self { addr, _task: task }
    }
}

async fn pump(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    budget: Option<usize>,
    dir: &str,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 8192];
    let mut sent = 0usize;
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            // 对端正常关闭：不打印，否则每个连接都会刷一行噪声
            return Ok(());
        }
        if let Some(b) = budget {
            if sent + n > b {
                // 只送出预算内的那一部分，剩下的丢掉 → 接收侧看到的是一段**不完整**的数据
                let allow = b.saturating_sub(sent);
                if allow > 0 {
                    let _ = to.write_all(&buf[..allow]).await;
                }
                eprintln!(
                    "[CutProxy {dir}] 预算 {b} 用尽，砍断（已转发 {} 字节）",
                    sent + allow
                );
                return Ok(());
            }
        }
        to.write_all(&buf[..n]).await?;
        sent += n;
    }
}

/// 起完整链路，但客户端到服务端之间隔一个**会砍断连接**的中继。
///
/// 用它来注入两类故障：
/// * `up_budget = Some(n)`：请求体传到一半链路消失（测**请求侧**"没发完不许当成发完了"）；
/// * `down_budget = Some(n)`：响应传到一半链路消失（测**响应侧**绝不能变成一次成功的 200）。
pub async fn setup_behind_cut_proxy(
    up_budget: Option<usize>,
    down_budget: Option<usize>,
) -> anyhow::Result<Stack> {
    let up = MockUpstream::start().await;
    let dport = free_port().await;
    let cport = free_port().await;

    let dargs: Vec<String> = vec![
        "--listen".into(),
        format!("127.0.0.1:{dport}"),
        "--upstream".into(),
        up.base_url(),
    ];
    let drefs: Vec<&str> = dargs.iter().map(String::as_str).collect();
    let d = spawn_proxy("llmproxyd", &drefs, true)?;
    anyhow::ensure!(
        wait_ready(&format!("127.0.0.1:{dport}"), Duration::from_secs(8)).await,
        "llmproxyd 未在 8s 内就绪"
    );

    let cut = CutProxy::start(format!("127.0.0.1:{dport}"), up_budget, down_budget).await;

    // 刻意**不给** `--upstream-fallback`：L2 直连会绕过这条被砍的链路，
    // 于是"上游有没有被半截请求打到"就测不出来了。
    let cargs: Vec<String> = vec![
        "--listen".into(),
        format!("127.0.0.1:{cport}"),
        "--server".into(),
        format!("ws://{}", cut.addr),
    ];
    let crefs: Vec<&str> = cargs.iter().map(String::as_str).collect();
    let c = spawn_proxy("llmproxyc", &crefs, false)?;
    let client = format!("127.0.0.1:{cport}");
    anyhow::ensure!(
        wait_ready(&client, Duration::from_secs(8)).await,
        "llmproxyc 未在 8s 内就绪"
    );

    Box::leak(Box::new(cut));

    Ok(Stack {
        up,
        d,
        c,
        client,
        dport,
    })
}

/// 高多样性 CJK 文本。
///
/// 窗口多样性决定 CDC 能否切出设计中的块长；用低多样性内容（重复短语）会让
/// 分块器退化到 `MAX_SIZE`，于是"复用率"这类测量完全失真。
fn cjk(seed: u64, n_chars: usize) -> String {
    let mut x = seed
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x5DEE_CE66_D000_0000);
    let mut s = String::with_capacity(n_chars * 3);
    for _ in 0..n_chars {
        x = x
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s.push(char::from_u32(0x4E00 + ((x >> 33) as u32 % 3000)).unwrap());
    }
    s
}

// ---------------------------------------------------------------------------
// 负载生成
// ---------------------------------------------------------------------------

/// 构造一个 `n_msgs` 条消息的请求体，每条约 1.7 KB，对齐实测真实量级。
pub fn make_body(n_msgs: usize, extra_msgs: usize) -> Vec<u8> {
    let total = n_msgs + extra_msgs;
    let mut msgs = String::from("[");
    for i in 0..total {
        if i > 0 {
            msgs.push(',');
        }
        let role = if i % 2 == 0 { "user" } else { "assistant" };
        msgs.push_str(&format!(
            r#"{{"role":"{role}","content":"[{i}] {}"}}"#,
            cjk(i as u64 + 1, 560)
        ));
    }
    msgs.push(']');
    format!(
        r#"{{"model":"m","stream":false,"messages":{msgs},"tools":[{{"type":"function","function":{{"name":"t","description":"固定尾部字段，用于验证错位后的可复用性"}}}}],"temperature":0.7}}"#
    )
    .into_bytes()
}

/// 兼容用法：不带租户（空串）。多数测试与"单租户部署"等价。
pub async fn connect_raw_peer(dport: u16, psk: &[u8]) -> anyhow::Result<RawPeer> {
    connect_raw_peer_with_tenant(dport, psk, "").await
}
