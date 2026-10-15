//! **真实流量重放**（Rust 版 ✓；第 155 轮把原先的 Python 版搬过来 ✓）。
//!
//! 用 `corpus-next/`（真实请求日志的脱敏产物：源 2.92 GB / 1091 请求 ✓）当
//! **模拟客户端 + 模拟上游** ✓，端到端重放一遍：
//!
//! ```text
//!   模拟客户端 → llmproxyc → DSHP → llmproxyd → 本文件里的极简上游（记录实际收到的字节）
//! ```
//!
//! 判据两条 ✓（都是 M0/M1a 的核心性质，**在真实 payload 上** ✓）：
//!   ① **响应逐字节一致** ✓ —— 客户端收到的字节 == 日志里的 `stream` ✓；
//!   ② **上行真实收益** ✓ —— 上游实际收到的请求字节 vs 日志里的 `body` ✓。
//!
//! **为什么用 Rust 而不是 Python** ✗→✓（用户要求，第 154 轮）：这类活是"把真实语料按
//! 实现的口径算/跑一遍"，Python 版又慢（分钟级 ✗）又**静默出错** ✗ —— 第 152~153 轮我在
//! Python 里连踩三层坑（字段名、`datetime`、会话层数），每次都是**静默返回 0** ✗✗，
//! 差点把"没算对"当成"没有收益"。Rust 版**直接复用既有 harness** ✓ 且编译期**大声报错** ✓。
//!
//! **语料不在库里**（`corpus-next/` 被 gitignore ✓）⇒ 本测试**明确跳过并打印原因** ✓，
//! **不判红** ✗（与 ARM 交叉构建那一步同样的处置 ✓）。

mod common;

use common::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 排队回放的 `(响应字节, content-type)` ✓。
///
/// **提成类型别名** ✓（第 156 轮）：直接写 `Arc<Mutex<Vec<(Vec<u8>, String)>>>` 会被
/// `clippy::type_complexity` 判红 ✓（`-D warnings` 下是**错误** ✗，第 155 轮实测 ✓）。
/// 用别名而不是 `#[allow]` ✓ —— 后者只是把告警藏起来 ✗，而别名让签名真的更好读 ✓。
type Queue = Arc<Mutex<Vec<(Vec<u8>, String)>>>;
/// 上游实际收到的请求体字节数（按到达次序 ✓）。
type Received = Arc<Mutex<Vec<usize>>>;

/// 极简上游：按**到达次序**回放预置响应，并记录每次请求体的字节数 ✓。
///
/// 为什么不用 `common::MockUpstream` ✗：它按 `x-test-mode` 头返回**合成**内容 ✓，
/// 而这里要回放**日志里的真实响应字节** ✓ —— 判据不同 ⇒ 需要自己的上游 ✓。
struct RealUpstream {
    addr: String,
    /// 按次序排队回放的 (响应字节, content-type) ✓
    queue: Queue,
    /// 实际收到的请求体字节数（按到达次序 ✓）
    received: Received,
}

impl RealUpstream {
    fn start() -> std::io::Result<Self> {
        let l = TcpListener::bind("127.0.0.1:0")?;
        let addr = format!("127.0.0.1:{}", l.local_addr()?.port());
        let queue: Queue = Arc::new(Mutex::new(Vec::new()));
        let received: Received = Arc::new(Mutex::new(Vec::new()));
        let (q, r) = (Arc::clone(&queue), Arc::clone(&received));
        std::thread::spawn(move || {
            for stream in l.incoming() {
                let Ok(mut s) = stream else { break };
                let (q, r) = (Arc::clone(&q), Arc::clone(&r));
                std::thread::spawn(move || {
                    let _ = serve_one(&mut s, &q, &r);
                });
            }
        });
        Ok(Self {
            addr,
            queue,
            received,
        })
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

/// 读一个请求（只处理 `content-length` 形态 ✓ 足够给代理当上游用 ✓），回一个响应 ✓。
fn serve_one(s: &mut TcpStream, queue: &Queue, received: &Received) -> std::io::Result<()> {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 4096];
    // 读到头部结束 ✓
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 1 << 20 {
            break;
        }
    }
    let head_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(buf.len());
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let clen: usize = head
        .lines()
        .find_map(|l| {
            let l = l.to_ascii_lowercase();
            l.strip_prefix("content-length:")
                .map(|v| v.trim().to_string())
        })
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < clen {
        let n = s.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    received.lock().unwrap().push(body.len());

    let (payload, ctype) = queue.lock().unwrap().pop_front_or_default();
    let mut out = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\n\r\n",
        payload.len()
    )
    .into_bytes();
    out.extend_from_slice(&payload);
    s.write_all(&out)?;
    s.flush()
}

/// `Vec::pop` 是尾部 ✓，而我们要**队首**（按到达次序 ✓）⇒ 小工具把它补上 ✓。
trait PopFrontOrDefault {
    fn pop_front_or_default(self) -> (Vec<u8>, String);
}
impl PopFrontOrDefault for std::sync::MutexGuard<'_, Vec<(Vec<u8>, String)>> {
    fn pop_front_or_default(mut self) -> (Vec<u8>, String) {
        if self.is_empty() {
            (b"{}".to_vec(), "application/json".to_string())
        } else {
            self.remove(0)
        }
    }
}

/// 从 `v1-messages-2026-10-09T020118-eaf31a88.log` 里取上游路径 ⇒ `/v1/messages` ✓
fn path_of(file: &str) -> String {
    let stem = file.split("-20").next().unwrap_or("v1-messages");
    let parts: Vec<&str> = stem.split('-').collect();
    if parts.len() >= 2 {
        format!("/{}/{}", parts[0], parts[1..].join("/"))
    } else {
        "/v1/messages".to_string()
    }
}

fn content_type_of(b: &[u8]) -> String {
    if b.starts_with(b"data:") || b.starts_with(b"event:") || b.starts_with(b":") {
        "text/event-stream".to_string()
    } else {
        "application/json".to_string()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_corpus_replays_byte_exact_and_shows_uplink_savings() {
    // **默认跳过**（第 157 轮加 ✓）：本用例要读 1.5 GB 语料、并用**真实 payload** 跑往返 ✓
    // ⇒ 与"时延类"用例放在**同一趟**里会互相挤 ✗（第 156 轮实测：`slow_path` 的首字节用例
    // 被挤成 502 ✗ —— 那**不是**被测代码坏了 ✗，是测量环境被压垮 ✓）。
    // ⇒ 由 CI 的**独立步骤**用 `DSHP_REAL_CORPUS=1` 打开 ✓（见 `scripts/ci.ps1` ✓）。
    if std::env::var("DSHP_REAL_CORPUS").is_err() {
        println!(
            "  ⏭ 跳过真实流量重放：需要 `DSHP_REAL_CORPUS=1`\
             （CI 有独立步骤跑它 ✓，避免挤到时延用例）"
        );
        return;
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let corpus = root.join("corpus-next");
    let reqs = corpus.join("req.jsonl");
    let resps = corpus.join("resp.jsonl");
    if !reqs.exists() || !resps.exists() {
        // **明确跳过** ✓：语料不入库（gitignore ✓）⇒ 在 CI/他人机器上应当安静跳过 ✓
        println!(
            "  ⏭ 跳过真实流量重放：找不到 {}（语料不入库 ✓ 属正常）\
             ⇒ 用 `corpus-next/` 放一份真实日志产物即可跑本测试 ✓",
            reqs.display()
        );
        return;
    }

    // ---- 读语料：resp 按 file 建表；req 流式读、只挑 messages 并按文件名排序取窗口 ----
    let mut streams: std::collections::HashMap<String, String> = Default::default();
    for line in std::fs::read_to_string(&resps).unwrap().lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(o) = serde_json::from_str::<serde_json::Value>(line) {
            if let (Some(f), Some(s)) = (o["file"].as_str(), o["stream"].as_str()) {
                streams.insert(f.to_string(), s.to_string());
            }
        }
    }
    let limit = std::env::var("DSHP_REPLAY_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20usize);
    let mut picks: Vec<(String, String)> = Vec::new(); // (file, body)
                                                       // **流式读**（req.jsonl 有 1.5 GB ✗ —— `read_to_string` 既慢又是 30 秒级 ✓，第 155 轮实测 ✓）
    {
        use std::io::BufRead;
        let f = std::fs::File::open(&reqs).unwrap();
        for line in std::io::BufReader::new(f).lines() {
            let Ok(line) = line else { continue };
            if line.trim().is_empty() {
                continue;
            }
            let Ok(o) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            let Some(f) = o["file"].as_str() else {
                continue;
            };
            if !f.starts_with("v1-messages-") || !streams.contains_key(f) {
                continue;
            }
            let Some(b) = o["body"].as_str() else {
                continue;
            };
            picks.push((f.to_string(), b.to_string()));
        }
    }
    picks.sort();
    picks.truncate(limit);
    assert!(!picks.is_empty(), "语料里没有可重放的 v1/messages 请求");

    // ---- 起极简上游 + 代理两端 ----
    let up = RealUpstream::start().expect("起上游失败");
    for (f, _) in &picks {
        let s = streams.get(f).unwrap().as_bytes().to_vec();
        let ct = content_type_of(&s);
        up.queue.lock().unwrap().push((s, ct));
    }
    let dport = free_port().await;
    let cport = free_port().await;
    let d = spawn_proxy(
        "llmproxyd",
        &[
            "--listen",
            &format!("127.0.0.1:{dport}"),
            "--upstream",
            &up.base_url(),
        ],
        true,
    )
    .expect("起服务端失败");
    assert!(
        wait_ready(&format!("127.0.0.1:{dport}"), Duration::from_secs(8)).await,
        "llmproxyd 未在 8s 内就绪"
    );
    let c = spawn_proxy(
        "llmproxyc",
        &[
            "--listen",
            &format!("127.0.0.1:{cport}"),
            "--server",
            &format!("ws://127.0.0.1:{dport}"),
        ],
        false,
    )
    .expect("起客户端失败");
    assert!(
        wait_ready(&format!("127.0.0.1:{cport}"), Duration::from_secs(8)).await,
        "llmproxyc 未在 8s 内就绪"
    );
    // ⚠️ 必须绑到**名字**上 ✗→✓：`let _ = (d, c);` 会**立刻 drop** ⇒ 进程当场被杀 ✗✗
    // ⇒ 后面第一次请求就"目标计算机积极拒绝" ✓（第 155 轮实测踩到 ✓）。
    let _keep = (d, c);

    // ---- 逐条重放 ----
    let mut raw = 0usize;
    let mut wire = 0usize;
    let mut bad = 0usize;
    let client = format!("127.0.0.1:{cport}");
    for (i, (f, body)) in picks.iter().enumerate() {
        let path = path_of(f);
        let expect = streams.get(f).unwrap().as_bytes().to_vec();
        let t0 = Instant::now();
        let r = raw_request(
            &client,
            "POST",
            &path,
            &[("content-type", "application/json")],
            body.as_bytes(),
        )
        .await
        .expect("重放请求失败（连接层）");
        let ms = t0.elapsed().as_millis();
        let exact = r.body == expect;
        if !exact {
            bad += 1;
        }
        raw += body.len();
        wire += up.received.lock().unwrap().get(i).copied().unwrap_or(0);
        println!(
            "  [{:>2}/{}] {:<16} 上行 {:>8.1} KiB  响应 {:>7.1} KiB  {} {}ms",
            i + 1,
            picks.len(),
            path,
            body.len() as f64 / 1024.0,
            r.body.len() as f64 / 1024.0,
            if exact { "✓" } else { "✗" },
            ms
        );
    }
    let pct = if raw > 0 {
        wire as f64 / raw as f64 * 100.0
    } else {
        0.0
    };
    println!(
        "  [真实流量重放] {} 条：响应逐字节一致 {}/{} ✓；上行 {:.2} MiB → 上游实收 {:.2} MiB = **{:.2}%**（省 {:.2}%）",
        picks.len(),
        picks.len() - bad,
        picks.len(),
        raw as f64 / 1048576.0,
        wire as f64 / 1048576.0,
        pct,
        100.0 - pct
    );
    assert_eq!(
        bad, 0,
        "有 {} 条响应与日志不一致 ⇒ 真实流量上的逐字节性质被破坏 ✗",
        bad
    );
}
