//! Reqable `v1/responses` 真实流量重放与压力测试。
//!
//! `F:\\Reqable\\tools\\reqable-responses-stats` 已经把 Reqable 的 LMDB 元数据和
//! capture 文件映射成 `report/responses_payload_samples.csv`。这里直接复用这个索引，
//! 从 `capture/` 读取原始请求/响应体，并在 Rust 内完成与 Go 工具相同的 chunked 解包。
//! 这样重放路径不依赖外部解释器，也不需要在压力测试过程中再次扫描 LMDB。
//!
//! 测试默认跳过。使用 Reqable 数据运行：
//!
//! ```text
//! $env:DSHP_REQABLE_RESPONSES = "1"
//! $env:DSHP_REQABLE_HOME = "F:\\Reqable"       # 可省略，默认就是该路径
//! $env:DSHP_REQABLE_LIMIT = "64"              # 样本数，默认 32
//! $env:DSHP_REQABLE_CONCURRENCY = "8"         # 并发请求数，默认 8
//! $env:DSHP_REQABLE_ROUNDS = "1"              # 重复轮数，默认 1
//! cargo test -p e2e-tests --test replay_reqable_responses -- --nocapture
//! ```
//!
//! 链路为：
//!
//! ```text
//! fake client (本测试) → llmproxyc → DSHP → llmproxyd → fake upstream (本测试)
//! ```
//!
//! fake upstream 按请求体精确查找对应的真实 SSE 响应，并支持并发连接；测试同时检查
//! 响应逐字节一致、上游没有收到未知请求以及整体吞吐量。

mod common;

use common::*;
use flate2::read::GzDecoder;
use futures_util::stream::{self, StreamExt};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
struct ReplayCase {
    key: String,
    request: Vec<u8>,
    response: Vec<u8>,
    content_type: String,
    raw_bytes: usize,
    payload_bytes: usize,
}

struct ResponseTemplate {
    payload: Vec<u8>,
    content_type: String,
}

type ResponseMap = Arc<HashMap<Vec<u8>, Arc<ResponseTemplate>>>;

struct ReqableUpstream {
    addr: String,
    received: Arc<Mutex<Vec<usize>>>,
    misses: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl ReqableUpstream {
    fn start(responses: ResponseMap, chunk_bytes: usize) -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = format!("127.0.0.1:{}", listener.local_addr()?.port());
        let received = Arc::new(Mutex::new(Vec::new()));
        let misses = Arc::new(Mutex::new(Vec::new()));
        let received_thread = Arc::clone(&received);
        let misses_thread = Arc::clone(&misses);
        let responses_thread = Arc::clone(&responses);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let responses = Arc::clone(&responses_thread);
                let received = Arc::clone(&received_thread);
                let misses = Arc::clone(&misses_thread);
                std::thread::spawn(move || {
                    let _ = serve_one(&mut stream, &responses, &received, &misses, chunk_bytes);
                });
            }
        });

        Ok(Self {
            addr,
            received,
            misses,
        })
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

fn serve_one(
    stream: &mut TcpStream,
    responses: &ResponseMap,
    received: &Arc<Mutex<Vec<usize>>>,
    misses: &Arc<Mutex<Vec<Vec<u8>>>>,
    chunk_bytes: usize,
) -> io::Result<()> {
    let request = read_http_request(stream)?;
    received.lock().unwrap().push(request.len());

    let Some(template) = responses.get(&request) else {
        misses.lock().unwrap().push(request);
        let body = b"unknown Reqable request";
        let head = format!(
            "HTTP/1.1 404 Not Found\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes())?;
        stream.write_all(body)?;
        stream.flush()?;
        return Ok(());
    };

    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {}\r\ncache-control: no-cache\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        template.content_type,
        template.payload.len()
    );
    stream.write_all(head.as_bytes())?;
    let width = chunk_bytes.max(1);
    for chunk in template.payload.chunks(width) {
        stream.write_all(chunk)?;
        stream.flush()?;
    }
    Ok(())
}

fn read_http_request(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut buf = Vec::new();
    let mut temp = [0u8; 8192];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut temp)?;
        if n == 0 {
            return Ok(Vec::new());
        }
        buf.extend_from_slice(&temp[..n]);
        if buf.len() > 4 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "请求头超过 4 MiB",
            ));
        }
    }

    let head_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(buf.len());
    let head = String::from_utf8_lossy(&buf[..head_end]);
    let content_length = header_value(&head, "content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let chunked = header_value(&head, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);

    let mut body = buf[head_end..].to_vec();
    if chunked {
        return read_chunked_stream(stream, &mut body);
    }
    while body.len() < content_length {
        let n = stream.read(&mut temp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&temp[..n]);
    }
    body.truncate(content_length.min(body.len()));
    Ok(body)
}

fn read_chunked_stream(stream: &mut TcpStream, raw: &mut Vec<u8>) -> io::Result<Vec<u8>> {
    let mut cursor = 0usize;
    let mut decoded = Vec::new();
    let mut temp = [0u8; 8192];
    loop {
        let line_end = loop {
            if let Some(p) = raw[cursor..].windows(2).position(|w| w == b"\r\n") {
                break cursor + p;
            }
            let n = stream.read(&mut temp)?;
            if n == 0 {
                return Ok(decoded);
            }
            raw.extend_from_slice(&temp[..n]);
        };
        let size = parse_chunk_size(&raw[cursor..line_end]).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "无效的 Transfer-Encoding: chunked",
            )
        })?;
        cursor = line_end + 2;
        while raw.len() < cursor + size + 2 {
            let n = stream.read(&mut temp)?;
            if n == 0 {
                decoded.extend_from_slice(&raw[cursor..]);
                return Ok(decoded);
            }
            raw.extend_from_slice(&temp[..n]);
        }
        if size == 0 {
            return Ok(decoded);
        }
        decoded.extend_from_slice(&raw[cursor..cursor + size]);
        cursor += size + 2;
    }
}

fn header_value(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

fn parse_chunk_size(line: &[u8]) -> Option<usize> {
    let token = line.split(|b| *b == b';').next()?.iter();
    let mut size = 0usize;
    let mut any = false;
    for b in token {
        let digit = match b {
            b'0'..=b'9' => usize::from(b - b'0'),
            b'a'..=b'f' => usize::from(b - b'a' + 10),
            b'A'..=b'F' => usize::from(b - b'A' + 10),
            b' ' | b'\t' => continue,
            _ => return None,
        };
        any = true;
        size = size.checked_mul(16)?.checked_add(digit)?;
    }
    any.then_some(size)
}

fn decode_reqable_body(raw: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut payload = decode_chunked_body(raw);
    if payload.starts_with(&[0x1f, 0x8b]) {
        let mut decoded = Vec::new();
        GzDecoder::new(payload.as_slice()).read_to_end(&mut decoded)?;
        payload = decoded;
    }
    Ok(payload)
}

fn decode_chunked_body(raw: &[u8]) -> Vec<u8> {
    let Some(first_end) = raw.windows(2).position(|w| w == b"\r\n") else {
        return raw.to_vec();
    };
    if parse_chunk_size(&raw[..first_end]).is_none() {
        return raw.to_vec();
    }

    let mut cursor = 0usize;
    let mut decoded = Vec::with_capacity(raw.len());
    while let Some(line_end_rel) = raw[cursor..].windows(2).position(|w| w == b"\r\n") {
        let line_end = cursor + line_end_rel;
        let Some(size) = parse_chunk_size(&raw[cursor..line_end]) else {
            break;
        };
        cursor = line_end + 2;
        if size == 0 {
            break;
        }
        if cursor >= raw.len() {
            break;
        }
        let available = raw.len() - cursor;
        let take = size.min(available);
        decoded.extend_from_slice(&raw[cursor..cursor + take]);
        if take < size {
            break;
        }
        cursor += size;
        if raw.len() >= cursor + 2 && &raw[cursor..cursor + 2] == b"\r\n" {
            cursor += 2;
        } else {
            break;
        }
    }
    decoded
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut chars = line.trim_end_matches('\r').chars().peekable();
    let mut quoted = false;
    while let Some(ch) = chars.next() {
        match (quoted, ch) {
            (true, '"') => {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    quoted = false;
                }
            }
            (true, _) => field.push(ch),
            (false, '"') if field.is_empty() => quoted = true,
            (false, ',') => {
                fields.push(std::mem::take(&mut field));
            }
            (false, _) => field.push(ch),
        }
    }
    fields.push(field);
    fields
}

fn column(header: &[String], name: &str) -> anyhow::Result<usize> {
    header
        .iter()
        .position(|v| v == name)
        .ok_or_else(|| anyhow::anyhow!("Reqable 报告缺少列 {name:?}"))
}

fn parse_usize(fields: &[String], index: usize) -> usize {
    fields
        .get(index)
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0)
}

fn load_cases(root: &Path, limit: usize) -> anyhow::Result<Vec<ReplayCase>> {
    let report = root.join("report").join("responses_payload_samples.csv");
    let capture = root.join("capture");
    let file = File::open(&report)
        .map_err(|e| anyhow::anyhow!("无法打开 Reqable 报告 {}：{e}", report.display()))?;
    let mut lines = BufReader::new(file).lines();
    let header_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("Reqable 报告为空"))??;
    let header = parse_csv_line(header_line.trim_start_matches('\u{feff}'));
    let key_col = column(&header, "key")?;
    let method_col = column(&header, "method")?;
    let path_col = column(&header, "path")?;
    let status_col = column(&header, "status")?;
    let content_type_col = column(&header, "content_type")?;
    let raw_bytes_col = column(&header, "raw_bytes")?;
    let payload_bytes_col = column(&header, "payload_bytes")?;

    let mut cases = Vec::new();
    for line in lines {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let fields = parse_csv_line(&line);
        let Some(key) = fields.get(key_col).filter(|v| !v.is_empty()) else {
            continue;
        };
        if fields.get(method_col).map(String::as_str) != Some("POST")
            || fields.get(path_col).map(String::as_str) != Some("/v1/responses")
            || fields.get(status_col).and_then(|v| v.parse::<u16>().ok()) != Some(200)
        {
            continue;
        }
        let request_path = capture.join(format!("{key}-req_raw-body.reqable"));
        let response_path = capture.join(format!("{key}-res-raw-body.reqable"));
        let response_path = if response_path.exists() {
            response_path
        } else {
            capture.join(format!("{key}-res-extract-body.reqable"))
        };
        if !request_path.exists() || !response_path.exists() {
            continue;
        }
        let request = std::fs::read(&request_path)?;
        let response_raw = std::fs::read(&response_path)?;
        let response = decode_reqable_body(&response_raw)?;
        let raw_bytes = parse_usize(&fields, raw_bytes_col);
        let payload_bytes = parse_usize(&fields, payload_bytes_col);
        if payload_bytes != 0 && payload_bytes != response.len() {
            eprintln!(
                "  [Reqable] {} payload_bytes={}，实际解码={}；按 capture 实际内容重放",
                key,
                payload_bytes,
                response.len()
            );
        }
        cases.push(ReplayCase {
            key: key.clone(),
            request,
            response,
            content_type: fields
                .get(content_type_col)
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| "application/octet-stream".to_string()),
            raw_bytes,
            payload_bytes,
        });
        if cases.len() >= limit {
            break;
        }
    }
    Ok(cases)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn enabled() -> bool {
    std::env::var("DSHP_REQABLE_RESPONSES")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "on"))
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reqable_responses_replay_under_load() {
    if !enabled() {
        println!("  ⏭ 跳过 Reqable v1/responses 重放：设置 DSHP_REQABLE_RESPONSES=1 后启用");
        return;
    }

    let root = std::env::var_os("DSHP_REQABLE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"F:\Reqable"));
    let limit = env_usize("DSHP_REQABLE_LIMIT", 32);
    let concurrency = env_usize("DSHP_REQABLE_CONCURRENCY", 8);
    let rounds = env_usize("DSHP_REQABLE_ROUNDS", 1);
    let chunk_bytes = env_usize("DSHP_REQABLE_CHUNK_BYTES", 4096);

    let cases = load_cases(&root, limit).expect("读取 Reqable v1/responses 样本失败");
    assert!(
        !cases.is_empty(),
        "Reqable 报告中没有可重放的 v1/responses 样本"
    );

    let mut response_map: HashMap<Vec<u8>, Arc<ResponseTemplate>> = HashMap::new();
    for case in &cases {
        let template = Arc::new(ResponseTemplate {
            payload: case.response.clone(),
            content_type: case.content_type.clone(),
        });
        if let Some(previous) = response_map.get(&case.request) {
            assert_eq!(
                previous.payload, template.payload,
                "Reqable key {} 与同请求体样本的响应不同，无法在无序并发下唯一匹配",
                case.key
            );
        } else {
            response_map.insert(case.request.clone(), template);
        }
    }
    let response_map: ResponseMap = Arc::new(response_map);
    let upstream = ReqableUpstream::start(Arc::clone(&response_map), chunk_bytes)
        .expect("启动 Reqable fake upstream 失败");

    let dport = free_port().await;
    let cport = free_port().await;
    let d = spawn_proxy(
        "llmproxyd",
        &[
            "--listen",
            &format!("127.0.0.1:{dport}"),
            "--upstream",
            &upstream.base_url(),
        ],
        true,
    )
    .expect("启动 llmproxyd 失败");
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
    .expect("启动 llmproxyc 失败");
    assert!(
        wait_ready(&format!("127.0.0.1:{cport}"), Duration::from_secs(8)).await,
        "llmproxyc 未在 8s 内就绪"
    );
    let _keep = (d, c);

    let total = cases.len() * rounds;
    let client = format!("127.0.0.1:{cport}");
    let cases = Arc::new(cases);
    let started = Instant::now();
    let results = stream::iter((0..total).map(|index| {
        let case = Arc::new(cases[index % cases.len()].clone());
        let client = client.clone();
        async move {
            let request_started = Instant::now();
            let result = raw_request(
                &client,
                "POST",
                "/v1/responses",
                &[
                    ("content-type", "application/json"),
                    ("accept", "text/event-stream"),
                ],
                &case.request,
            )
            .await;
            (index, case, result, request_started.elapsed())
        }
    }))
    .buffer_unordered(concurrency)
    .collect::<Vec<_>>()
    .await;

    let mut failures = Vec::new();
    let mut response_bytes = 0usize;
    let mut latency_total = Duration::ZERO;
    for (index, case, result, latency) in results {
        latency_total += latency;
        match result {
            Ok(response) if response.status == 200 && response.body == case.response => {
                response_bytes += response.body.len();
            }
            Ok(response) => failures.push(format!(
                "第 {} 条 key={} status={} actual={} expected={}",
                index,
                case.key,
                response.status,
                response.body.len(),
                case.response.len()
            )),
            Err(error) => failures.push(format!(
                "第 {} 条 key={} 请求失败：{error:#}",
                index, case.key
            )),
        }
    }
    let elapsed = started.elapsed();
    let received = upstream.received.lock().unwrap().len();
    let misses = upstream.misses.lock().unwrap().len();
    let request_bytes: usize = cases.iter().map(|case| case.request.len()).sum::<usize>() * rounds;
    let report_raw_bytes: usize = cases.iter().map(|case| case.raw_bytes).sum::<usize>() * rounds;
    let report_payload_bytes: usize =
        cases.iter().map(|case| case.payload_bytes).sum::<usize>() * rounds;
    println!(
        "  [Reqable v1/responses] 样本={} 轮数={} 总请求={} 并发={}；请求 {:.2} MiB，报告 raw {:.2} MiB，报告 payload {:.2} MiB，实际响应 {:.2} MiB；耗时 {:?}，吞吐 {:.2} req/s，平均延迟 {:?}",
        cases.len(),
        rounds,
        total,
        concurrency,
        request_bytes as f64 / 1048576.0,
        report_raw_bytes as f64 / 1048576.0,
        report_payload_bytes as f64 / 1048576.0,
        response_bytes as f64 / 1048576.0,
        elapsed,
        total as f64 / elapsed.as_secs_f64().max(f64::EPSILON),
        latency_total / total as u32
    );
    assert!(
        failures.is_empty(),
        "Reqable 重放有 {} 条失败，首条：{}",
        failures.len(),
        failures.first().cloned().unwrap_or_default()
    );
    assert_eq!(
        received, total,
        "fake upstream 收到的请求数与压力测试总数不一致"
    );
    assert_eq!(misses, 0, "fake upstream 收到了无法匹配 Reqable 样本的请求");
}
