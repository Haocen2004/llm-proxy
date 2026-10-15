//! 真实 `llmproxyc`/`llmproxyd` 子进程长稳夹具。
use super::*;
use std::time::{Duration, Instant};
use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread,
};

struct Upstream {
    addr: String,
    stop: Arc<AtomicBool>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(&self.addr);
    }
}

fn upstream() -> Result<Upstream> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = format!("http://{}", listener.local_addr()?);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    thread::spawn(move || {
        while !stop_thread.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    thread::spawn(|| {
                        let _ = serve_upstream(stream);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(_) => break,
            }
        }
    });
    Ok(Upstream { addr, stop })
}

fn header(headers: &str, name: &str) -> Option<String> {
    headers.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.eq_ignore_ascii_case(name)).then(|| value.trim().to_string())
    })
}

fn serve_upstream(mut stream: TcpStream) -> Result<()> {
    let mut input = Vec::new();
    let mut buf = [0u8; 8192];
    let end = loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        input.extend_from_slice(&buf[..n]);
        if let Some(pos) = input.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if input.len() > 4 * 1024 * 1024 {
            bail!("soak 上游请求头过大");
        }
    };
    let head = String::from_utf8_lossy(&input[..end]).into_owned();
    let length = header(&head, "content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    while input.len() < end + length {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        input.extend_from_slice(&buf[..n]);
    }
    let body = &input[end..end + length.min(input.len().saturating_sub(end))];
    let mode = header(&head, "x-test-mode").unwrap_or_else(|| "echo".into());
    let payload = match mode.as_str() {
        "sse" => sse_body(32, false),
        "sse-novel" => sse_body(96, true),
        _ => body.to_vec(),
    };
    let content_type = if mode.starts_with("sse") {
        "text/event-stream"
    } else {
        "application/json"
    };
    let response = format!("HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncache-control: no-cache\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",payload.len());
    stream.write_all(response.as_bytes())?;
    for chunk in payload.chunks(if mode.starts_with("sse") {
        97
    } else {
        payload.len().max(1)
    }) {
        stream.write_all(chunk)?;
        stream.flush()?;
    }
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

fn sse_body(count: usize, novel: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..count {
        let event = if novel {
            json!({"id":format!("evt-{i}"),"object":format!("chunk-{i}"),"delta":{"content":format!("token-{i}-{}", "x".repeat(i%31))},"choices":[{"index":i,"finish_reason":null}]})
        } else {
            json!({"id":"chatcmpl-soak","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"模"},"finish_reason":null}]})
        };
        out.extend_from_slice(format!("data: {}\n\n", event).as_bytes());
    }
    out.extend_from_slice(b"data: [DONE]\n\n");
    out
}

fn request(addr: &str, mode: &str, nonce: u64) -> Result<usize> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let body = format!(
        r#"{{"model":"gpt-4o","stream":false,"messages":[{{"role":"user","content":"soak-{nonce}"}}]}}"#
    );
    let req = format!("POST /v1/chat/completions HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\nx-test-mode: {mode}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",body.len());
    stream.write_all(req.as_bytes())?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let status = response
        .strip_prefix(b"HTTP/1.1 ")
        .and_then(|v| v.get(..3))
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(0);
    if status != 200 {
        bail!("soak 请求返回 HTTP {status}");
    }
    Ok(response.len())
}

fn ready(addr: &str, upstream: &Upstream) -> Result<()> {
    for _ in 0..40 {
        if request(addr, "echo", 0).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!("客户端代理未就绪（上游 {}）", upstream.addr)
}

#[cfg(windows)]
fn memory_bytes(pid: u32) -> Option<u64> {
    #[repr(C)]
    struct Counters {
        cb: u32,
        page_fault: u32,
        peak_working: usize,
        working: usize,
        quota_peak_paged: usize,
        quota_paged: usize,
        quota_peak_nonpaged: usize,
        quota_nonpaged: usize,
        pagefile: usize,
        peak_pagefile: usize,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut std::ffi::c_void;
        fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
    }
    #[link(name = "psapi")]
    extern "system" {
        fn GetProcessMemoryInfo(
            process: *mut std::ffi::c_void,
            counters: *mut Counters,
            size: u32,
        ) -> i32;
    }
    unsafe {
        let handle = OpenProcess(0x1000, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut c = std::mem::zeroed::<Counters>();
        c.cb = std::mem::size_of::<Counters>() as u32;
        let ok = GetProcessMemoryInfo(handle, &mut c, c.cb);
        CloseHandle(handle);
        (ok != 0).then_some(c.pagefile as u64)
    }
}

#[cfg(not(windows))]
fn memory_bytes(pid: u32) -> Option<u64> {
    let text = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    text.lines()
        .find(|line| line.starts_with("VmRSS:"))
        .and_then(|line| line.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map(|kb| kb * 1024)
}

fn spawn_proxy(path: &Path, args: &[String], psk: &str, stderr: &Path) -> Result<Child> {
    let file = fs::File::create(stderr)?;
    Ok(Command::new(path)
        .args(args)
        .env("DSHP_PSK", psk)
        .stdout(Stdio::null())
        .stderr(Stdio::from(file))
        .spawn()?)
}

fn slope(samples: &[(f64, u64)], warmup: f64) -> f64 {
    let points: Vec<_> = samples.iter().filter(|(t, _)| *t >= warmup).collect();
    if points.len() < 2 {
        return 0.0;
    }
    let n = points.len() as f64;
    let mean_x = points.iter().map(|(x, _)| *x).sum::<f64>() / n;
    let mean_y = points.iter().map(|(_, y)| *y as f64).sum::<f64>() / n;
    let den = points
        .iter()
        .map(|(x, _)| (*x - mean_x).powi(2))
        .sum::<f64>();
    if den == 0.0 {
        return 0.0;
    }
    let num = points
        .iter()
        .map(|(x, y)| (*x - mean_x) * (*y as f64 - mean_y))
        .sum::<f64>();
    num / den * 60.0 / 1024.0
}

pub fn run(args: SoakArgs) -> Result<()> {
    if args.duration == 0 || args.interval == 0 || args.rate == 0 {
        bail!("duration/interval/rate 必须大于零");
    }
    let upstream = upstream()?;
    let bin_dir = args.bin_dir.unwrap_or_else(|| root().join("target/debug"));
    let suffix = std::env::consts::EXE_SUFFIX;
    let server_path = bin_dir.join(format!("llmproxyd{suffix}"));
    let client_path = bin_dir.join(format!("llmproxyc{suffix}"));
    if !server_path.exists() || !client_path.exists() {
        bail!(
            "找不到 {} 或 {}，请先 cargo build --workspace",
            server_path.display(),
            client_path.display()
        );
    }
    let dport = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let cport = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let out_dir = args.out.parent().unwrap_or(Path::new("target/soak"));
    fs::create_dir_all(out_dir)?;
    let mut server = spawn_proxy(
        &server_path,
        &[
            "--listen".into(),
            format!("127.0.0.1:{dport}"),
            "--upstream".into(),
            upstream.addr.clone(),
            "--block-cache-bytes".into(),
            (args.server_cache_mb << 20).to_string(),
            "--cache-ttl-secs".into(),
            args.ttl_secs.to_string(),
        ],
        "soak-psk",
        &out_dir.join("llmproxyd.stderr"),
    )?;
    let mut client = spawn_proxy(
        &client_path,
        &[
            "--listen".into(),
            format!("127.0.0.1:{cport}"),
            "--server".into(),
            format!("ws://127.0.0.1:{dport}"),
            "--upstream-fallback".into(),
            upstream.addr.clone(),
            "--upload-entries".into(),
            args.client_entries.max(2000).to_string(),
        ],
        "soak-psk",
        &out_dir.join("llmproxyc.stderr"),
    )?;
    let client_addr = format!("127.0.0.1:{cport}");
    if let Err(error) = ready(&client_addr, &upstream) {
        let _ = server.kill();
        let _ = client.kill();
        return Err(error);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let ok = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let mut workers = Vec::new();
    for worker in 0..4 {
        let stop = Arc::clone(&stop);
        let ok = Arc::clone(&ok);
        let errors = Arc::clone(&errors);
        let addr = client_addr.clone();
        let rate = (args.rate / 4).max(1);
        let every = args.sse_every.max(1);
        let novel = args.novel;
        workers.push(thread::spawn(move || {
            let begin = Instant::now();
            let mut n = worker as u64;
            while !stop.load(Ordering::Acquire) {
                for i in 0..rate {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    n += 1;
                    let mode = if novel && n % every == 0 {
                        "sse-novel"
                    } else if n % every == 0 {
                        "sse"
                    } else {
                        "echo"
                    };
                    if request(&addr, mode, n).is_ok() {
                        ok.fetch_add(1, Ordering::Relaxed)
                    } else {
                        errors.fetch_add(1, Ordering::Relaxed)
                    };
                    let _ = i;
                }
                let elapsed = begin.elapsed();
                let target = Duration::from_secs_f64(
                    (ok.load(Ordering::Relaxed) + errors.load(Ordering::Relaxed)) as f64
                        / args.rate as f64,
                );
                if elapsed < target {
                    thread::sleep(target - elapsed);
                }
            }
        }));
    }
    let start = Instant::now();
    let warmup = Duration::from_secs(args.warmup.min(args.duration / 2));
    let interval = Duration::from_secs(args.interval);
    let mut samples = Vec::new();
    while start.elapsed() < Duration::from_secs(args.duration) {
        thread::sleep(
            interval.min(Duration::from_secs(args.duration).saturating_sub(start.elapsed())),
        );
        let elapsed = start.elapsed().as_secs_f64();
        samples.push((
            elapsed,
            memory_bytes(server.id()).unwrap_or(0),
            memory_bytes(client.id()).unwrap_or(0),
        ));
    }
    stop.store(true, Ordering::Release);
    for worker in workers {
        let _ = worker.join();
    }
    let _ = server.kill();
    let _ = client.kill();
    let _ = server.wait();
    let _ = client.wait();
    if samples.is_empty() {
        bail!("soak 无采样点，测程无效");
    }
    let server_points: Vec<_> = samples.iter().map(|(t, s, _)| (*t, *s)).collect();
    let client_points: Vec<_> = samples.iter().map(|(t, _, c)| (*t, *c)).collect();
    let max_rss = samples
        .iter()
        .map(|(_, s, c)| (*s).max(*c))
        .max()
        .unwrap_or(0);
    let server_slope = slope(&server_points, warmup.as_secs_f64());
    let client_slope = slope(&client_points, warmup.as_secs_f64());
    let worst = server_slope.max(client_slope);
    let result = json!({"duration_s":start.elapsed().as_secs_f64(),"warmup_s":warmup.as_secs_f64(),"requests":ok.load(Ordering::Relaxed),"errors":errors.load(Ordering::Relaxed),"samples":samples.iter().map(|(t,s,c)|json!({"t":t,"server_rss_bytes":s,"client_rss_bytes":c})).collect::<Vec<_>>(),"server_slope_kib_per_min":server_slope,"client_slope_kib_per_min":client_slope,"worst_slope_kib_per_min":worst,"peak_rss_mb":max_rss as f64/1048576.0,"rss_budget_mb":args.rss_budget_mb,"leak_limit_kib_per_min":args.leak_limit,"ceiling_only":args.ceiling_only,"rust":true});
    write_json(&args.out, &result)?;
    if max_rss > args.rss_budget_mb as u64 * 1048576 {
        bail!(
            "RSS 超过预算：{:.2} MiB > {} MiB",
            max_rss as f64 / 1048576.0,
            args.rss_budget_mb
        );
    }
    if !args.ceiling_only && worst > args.leak_limit as f64 {
        bail!("内存上升斜率超限：{worst:.2} KiB/min > {}", args.leak_limit);
    }
    println!(
        "Rust soak 完成：{} requests，峰值 {:.2} MiB，结果 {}",
        ok.load(Ordering::Relaxed),
        max_rss as f64 / 1048576.0,
        args.out.display()
    );
    Ok(())
}
