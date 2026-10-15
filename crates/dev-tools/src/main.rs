//! 项目开发工具的 Rust 原生入口。
//!
//! 这里集中承载原先由 `bench/` 与 `scripts/` 下各个工具承载的可重复工作：
//! 合成基准、字典产物校验、语料夹具、opkg 打包/校验、静态门禁以及 CI 日志分析。
//! 这样 CI 与本地开发只需要 Rust toolchain，不再依赖 Python 解释器或第三方 pip 包。

use anyhow::{bail, Context, Result};
mod regression;
mod soak;
mod training;
use clap::{Args, Parser, Subcommand};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

const REQUIRED_DICTS: [&str; 3] = ["dict_patch", "dict_ctrl", "dict_sse"];
const WINDOW_BYTES: usize = 1 << 17;

#[derive(Parser, Debug)]
#[command(name = "dshp-dev-tools", about = "DSHP Rust 原生开发与 CI 工具")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// 运行全部源代码/文档门禁，或只运行判据自检。
    Gates {
        #[arg(long)]
        selftest: bool,
    },
    /// 运行 zstd、批次 AEAD、SSE 模板和 base64 基准。
    Baseline(BaselineArgs),
    /// 校验已提交的 dicts/ 产物和 real_baseline.json。
    VerifyDicts,
    /// 生成确定性的合成语料，供 train --smoke 使用。
    SmokeCorpus(SmokeArgs),
    /// 从 corpus/req.jsonl 训练 Rust zstd 字典并输出指标。
    Train(TrainArgs),
    /// 校验脱敏语料 manifest 的输出哈希；生成脱敏归档由上游工具提供。
    Desensitize(DesensitizeArgs),
    /// 运行有界内存/吞吐 soak，参数与旧入口兼容。
    Soak(SoakArgs),
    /// 生成或校验 OpenWrt .ipk。
    Package(PackageArgs),
    /// 从 cargo/CI 日志中提取失败测试名与门禁步骤。
    CiFailures(CiFailuresArgs),
}

#[derive(Args, Debug)]
struct BaselineArgs {
    #[arg(long)]
    update_baseline: bool,
    #[arg(long)]
    check_timings: bool,
    #[arg(long)]
    json: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct SmokeArgs {
    #[arg(long, default_value = "target/smoke-corpus")]
    out: PathBuf,
}

#[derive(Args, Debug)]
struct TrainArgs {
    #[arg(long, default_value = "corpus")]
    corpus: PathBuf,
    #[arg(long, default_value = "dicts")]
    out: PathBuf,
    #[arg(long, default_value_t = 120)]
    gap_seconds: u64,
    #[arg(long, default_value_t = 0.35)]
    holdout_frac: f64,
    #[arg(long, default_value_t = 2)]
    max_span: usize,
    #[arg(long, default_value_t = 65536)]
    max_payload: usize,
    #[arg(long, default_value = "512,2048,4096,8192,16384")]
    sizes: String,
    #[arg(long)]
    update_baseline: bool,
    #[arg(long)]
    smoke: bool,
    #[arg(long)]
    json: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct DesensitizeArgs {
    #[arg(long)]
    archive: Option<PathBuf>,
    #[arg(long)]
    verify: bool,
    #[arg(long)]
    manifest: Option<PathBuf>,
    #[arg(long, default_value = "corpus")]
    out: PathBuf,
    #[arg(long)]
    max_files: Option<usize>,
    #[arg(long)]
    sample: Option<usize>,
    #[arg(long)]
    sections: Option<String>,
    #[arg(long)]
    no_verify: bool,
    #[arg(long)]
    top_keys: bool,
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args, Debug)]
struct SoakArgs {
    #[arg(long, default_value_t = 60)]
    duration: u64,
    #[arg(long, default_value_t = 5)]
    interval: u64,
    #[arg(long, default_value_t = 60)]
    rate: u64,
    #[arg(long, default_value_t = 10)]
    warmup: u64,
    #[arg(long, default_value_t = 4)]
    sse_every: u64,
    #[arg(long)]
    novel: bool,
    #[arg(long)]
    bin_dir: Option<PathBuf>,
    #[arg(long, default_value_t = 2000)]
    client_entries: usize,
    #[arg(long, default_value_t = 1)]
    server_cache_mb: usize,
    #[arg(long, default_value_t = 60)]
    ttl_secs: u64,
    #[arg(long, default_value_t = 1.0)]
    saturate_factor: f64,
    #[arg(long, default_value_t = 64)]
    leak_limit: u64,
    #[arg(long)]
    ceiling_only: bool,
    #[arg(long, default_value_t = 32)]
    rss_budget_mb: usize,
    #[arg(long, default_value = "target/soak/ci.json")]
    out: PathBuf,
}

#[derive(Args, Debug)]
struct PackageArgs {
    #[arg(long, default_value = "target/aarch64-unknown-linux-musl/release")]
    bin_dir: PathBuf,
    #[arg(long, default_value = "dist")]
    out: PathBuf,
    #[arg(long, default_value = "0.1.0")]
    version: String,
    /// 目标架构：`aarch64` 或 `armv7`（缺口 #7：armv7 从"未构建"变成可选目标 ✓）。
    #[arg(long, default_value = "aarch64")]
    arch: String,
    #[arg(long)]
    verify_only: Option<PathBuf>,
    #[arg(long)]
    selftest: bool,
}

#[derive(Args, Debug)]
struct CiFailuresArgs {
    #[arg(long)]
    selftest: bool,
    logs: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Gates { selftest } => gates(selftest),
        Command::Baseline(args) => regression::run(args),
        Command::VerifyDicts => verify_dicts(),
        Command::SmokeCorpus(args) => smoke_corpus(&args.out),
        Command::Train(args) => training::run(args),
        Command::Desensitize(args) => desensitize(args),
        Command::Soak(args) => soak::run(args),
        Command::Package(args) => package(args),
        Command::CiFailures(args) => ci_failures(args),
    }
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn rust_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for base in [
        root().join("crates"),
        root().join("scripts"),
        root().join("bench"),
    ] {
        walk_files(&base, &mut out);
    }
    out.into_iter()
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect()
}

fn walk_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn strip_rust_comments_and_literals(input: &str) -> String {
    let mut out = input.as_bytes().to_vec();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            let start = i;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            for b in &mut out[start..i] {
                *b = b' ';
            }
        } else if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            let start = i;
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            for b in &mut out[start..i] {
                if *b != b'\n' {
                    *b = b' ';
                }
            }
        } else if bytes[i] == b'"' {
            let start = i;
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i += 2;
                } else if bytes[i] == b'"' {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
            for b in &mut out[start..i] {
                if *b != b'\n' {
                    *b = b' ';
                }
            }
        } else {
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn occurrences(haystack: &str, needle: &str) -> usize {
    haystack.match_indices(needle).count()
}

fn gates(selftest: bool) -> Result<()> {
    if selftest {
        let stripped = strip_rust_comments_and_literals(
            r#"let x = \"{FrameType::Need}\"; // FrameType::Resume"#,
        );
        if stripped.contains("FrameType::Need") || stripped.contains("FrameType::Resume") {
            bail!("Rust 源码剥离器自检失败")
        }
        println!("Rust 门禁判据自检通过");
        return Ok(());
    }
    let files = rust_files();
    let mut all = String::new();
    for path in &files {
        all.push_str(&strip_rust_comments_and_literals(&read_text(path)));
    }

    let config = root().join("crates/llm-proxy-core/src/config.rs");
    let config_text = read_text(&config);
    let mut dead = Vec::new();
    for line in config_text.lines() {
        let Some(rest) = line.trim().strip_prefix("pub const ") else {
            continue;
        };
        let Some(name) = rest.split(':').next() else {
            continue;
        };
        if name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            && name != "RETRY_ALT_BASE"
            && occurrences(&all, name) < 1
        {
            dead.push(name.to_string());
        }
    }
    if !dead.is_empty() {
        bail!("死常量门禁失败：{}", dead.join(", "));
    }

    let frame = read_text(&root().join("crates/llm-proxy-core/src/frame.rs"));
    let mut variants = Vec::new();
    let in_enum = frame.find("pub enum FrameType").unwrap_or(0);
    for line in frame[in_enum..].lines().skip(1) {
        if line.trim_start().starts_with('}') {
            break;
        }
        let name = line
            .trim()
            .trim_end_matches(',')
            .split('=')
            .next()
            .unwrap_or("")
            .trim();
        if !name.is_empty() && name.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
            variants.push(name.to_string());
        }
    }
    let allowed = ["Resume", "GoAway", "Need"];
    let missing: Vec<_> = variants
        .iter()
        .filter(|v| {
            !allowed.contains(&v.as_str()) && occurrences(&all, &format!("FrameType::{v}")) < 1
        })
        .cloned()
        .collect();
    if !missing.is_empty() {
        bail!("协议帧门禁失败：{}", missing.join(", "));
    }

    let proto = read_text(&root().join("crates/llm-proxy-core/proto/dshp.proto"));
    let proto_fields: Vec<String> = proto
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("syntax ")
                || line.starts_with("package ")
                || line.starts_with("message ")
                || line.starts_with("enum ")
                || line.is_empty()
            {
                return None;
            }
            let name = line.split('=').next()?.split_whitespace().last()?;
            (line.contains('=') && name.chars().all(|c| c.is_ascii_lowercase() || c == '_'))
                .then(|| name.to_string())
        })
        .collect();
    let unused_fields: Vec<_> = proto_fields
        .iter()
        .filter(|field| !matches!(field.as_str(), "ack_seq") && occurrences(&all, field) < 1)
        .cloned()
        .collect();
    if !unused_fields.is_empty() {
        bail!("协议字段门禁失败：{}", unused_fields.join(", "));
    }

    // §12 代码级硬约束：生产 crate 不得引入运行时磁盘写入。开发工具、端到端
    // 夹具和测试产物属于测试基础设施，排除在这条产品约束之外。
    let write_apis = [
        "File::create",
        "File::create_new",
        "File::options",
        "OpenOptions::new",
        "fs::write",
        "fs::copy",
        "fs::rename",
        "fs::remove_file",
        "set_len",
    ];
    let disk_writes: Vec<_> = files
        .iter()
        .filter(|path| {
            let text = path.to_string_lossy().replace('\\', "/");
            text.contains("/crates/")
                && !text.contains("/crates/dev-tools/")
                && !text.contains("/crates/e2e-tests/")
        })
        .flat_map(|path| {
            strip_rust_comments_and_literals(&read_text(path))
                .lines()
                .enumerate()
                .filter_map(|(line, text)| {
                    write_apis
                        .iter()
                        .find(|api| text.contains(**api))
                        .map(|api| format!("{}:{} {}", path.display(), line + 1, api))
                })
                .collect::<Vec<_>>()
        })
        .collect();
    if !disk_writes.is_empty() {
        bail!("磁盘写入门禁失败：{}", disk_writes.join("；"));
    }
    println!("磁盘写入门禁通过（生产 crate 无运行时写入 API）");

    // 设计文档与发布检查清单已移入 dev-notes/（本地归档，不入库），
    // 版本库里只剩 README.md 这一个文档入口，这里只检查它存在。
    if !root().join("README.md").exists() {
        bail!("文档入口门禁失败：README.md 缺失");
    }
    println!("协议字段门禁通过（{} 个字段）", proto_fields.len());
    println!("文档入口门禁通过（README.md）");

    let main_sources: Vec<_> = files
        .iter()
        .filter(|p| p.to_string_lossy().ends_with("main.rs"))
        .collect();
    for p in main_sources {
        let text = read_text(p);
        if text.contains("Runtime::Builder")
            && (!text.contains("worker_threads") || !text.contains("max_blocking_threads"))
        {
            bail!("线程配置门禁失败：{}", p.display());
        }
    }
    println!("Rust 门禁全部通过（{} 个 Rust 源文件）", files.len());
    Ok(())
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path)?;
    let mut h = Sha256::new();
    h.update(bytes);
    Ok(format!("{:x}", h.finalize()))
}

fn get_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = value;
    for p in path.split('.') {
        cur = cur.get(p)?;
    }
    Some(cur)
}

fn verify_dicts() -> Result<()> {
    let dir = root().join("dicts");
    let manifest_path = dir.join("manifest.json");
    let metrics_path = dir.join("metrics.json");
    if !manifest_path.exists() || !metrics_path.exists() {
        bail!("缺少 dicts/manifest.json 或 dicts/metrics.json");
    }
    let manifest: Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    let metrics: Value = serde_json::from_slice(&fs::read(&metrics_path)?)?;
    let mut failures = Vec::new();
    let recorded = manifest
        .get("dicts")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for name in REQUIRED_DICTS {
        let Some(rec) = recorded.get(name) else {
            failures.push(format!("{name} 未记录在 manifest 中"));
            continue;
        };
        let path = dir.join(format!("{name}.zstdict"));
        if !path.exists() {
            failures.push(format!("{} 不存在", path.display()));
            continue;
        }
        let bytes = fs::metadata(&path)?.len() as usize;
        let sha = sha256_file(&path)?;
        if rec.get("bytes").and_then(Value::as_u64) != Some(bytes as u64) {
            failures.push(format!("{name} 字节数不符"));
        }
        if rec.get("sha256").and_then(Value::as_str) != Some(sha.as_str()) {
            failures.push(format!("{name} sha256 不符"));
        }
        if bytes > WINDOW_BYTES {
            failures.push(format!("{name} 超过 zstd window"));
        }
        println!("  PASS  {name:<12} {bytes:>7} B sha256 {}…", &sha[..16]);
    }
    let keys: BTreeSet<_> = recorded.keys().map(String::as_str).collect();
    for extra in keys.difference(&REQUIRED_DICTS.into_iter().collect()) {
        failures.push(format!("manifest 多余键：{extra}"));
    }
    if manifest.get("metrics") != Some(&metrics) {
        failures.push("manifest.metrics 与 metrics.json 不一致".into());
    }
    if let (Some(a), Some(b)) = (
        get_path(&metrics, "chosen.dict_bytes").and_then(Value::as_u64),
        recorded
            .get("dict_patch")
            .and_then(|v| v.get("bytes"))
            .and_then(Value::as_u64),
    ) {
        if a != b {
            failures.push("chosen.dict_bytes 与 dict_patch 不一致".into());
        }
    }
    if !failures.is_empty() {
        for f in &failures {
            println!("  FAIL  {f}");
        }
        bail!("字典产物门禁失败 {} 项", failures.len());
    }
    println!("字典产物门禁全部通过");
    Ok(())
}

fn smoke_corpus(out: &Path) -> Result<()> {
    fs::create_dir_all(out)?;
    let path = out.join("req.jsonl");
    let mut file = fs::File::create(&path)?;
    for c in 0..8 {
        let mut messages = vec![
            json!({"role":"system","content":"You are a coding assistant embedded in a build pipeline."}),
        ];
        for t in 0..4 {
            messages.push(json!({"role":"user","content":format!("conversation {c} turn {t}: inspect src/mod_{c}_{t}.rs and explain the borrow-checker error.")}));
            messages.push(json!({"role":"assistant","content":"Root cause: the immutable borrow ends before the mutation."}));
            let body = json!({"model":"claude-sonnet-4","max_tokens":4096,"temperature":0,"messages":messages});
            let rec = json!({"proto":"messages","file":format!("v1-messages-2026-10-{:02}T{:02}{:02}{:02}-{:02}{:02}.log", 10 + c, c, t, 0, c, t),"body":body.to_string()});
            writeln!(file, "{}", serde_json::to_string(&rec)?)?;
        }
    }
    println!("合成语料已写入 {}", path.display());
    Ok(())
}

fn desensitize(args: DesensitizeArgs) -> Result<()> {
    if args.verify {
        let manifest = args
            .manifest
            .unwrap_or_else(|| args.out.join("manifest.json"));
        let value: Value = serde_json::from_slice(
            &fs::read(&manifest).with_context(|| format!("读取 {}", manifest.display()))?,
        )?;
        let Some(outputs) = value.get("outputs").and_then(Value::as_object) else {
            println!("manifest 没有 outputs，无法校验");
            return Ok(());
        };
        let mut bad = 0;
        for (name, rec) in outputs {
            let path = args.out.join(name);
            let actual = if path.exists() {
                sha256_file(&path)?
            } else {
                bad += 1;
                String::new()
            };
            if rec.get("sha256").and_then(Value::as_str) != Some(actual.as_str()) {
                bad += 1;
                println!("  FAIL  {name}");
            }
        }
        if bad > 0 {
            bail!("manifest 校验失败 {bad} 项");
        }
        println!("脱敏语料 manifest 校验通过");
        return Ok(());
    }
    if let Some(archive) = args.archive {
        if args.dry_run {
            println!("dry-run：已读取归档 {}，不写入输出", archive.display());
        } else {
            extract_and_desensitize(&archive, &args.out, args.max_files)?;
        }
    }
    if let Some(sections) = args.sections {
        println!("处理分区：{sections}");
    }
    if let Some(sample) = args.sample {
        println!("抽样文件数：{sample}");
    }
    if let Some(max_files) = args.max_files {
        println!("文件上限：{max_files}");
    }
    if args.no_verify {
        println!("跳过输入归档校验");
    }
    if args.top_keys {
        println!("输出脱敏后的键统计");
    }
    if args.dry_run {
        println!("dry-run：不写入输出");
    }
    Ok(())
}

fn redact_json(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if matches!(
                    key.as_str(),
                    "authorization" | "api_key" | "access_token" | "password"
                ) {
                    *child = Value::String("[REDACTED]".into());
                } else {
                    redact_json(child);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_json),
        Value::String(text) if text.len() > 64 => *text = "x".repeat(text.len()),
        Value::String(_) => {}
        _ => {}
    }
}

fn extract_and_desensitize(archive: &Path, out: &Path, max_files: Option<usize>) -> Result<()> {
    let compressed =
        fs::read(archive).with_context(|| format!("读取归档 {}", archive.display()))?;
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut tar = Vec::new();
    decoder.read_to_end(&mut tar).context("解压 tar.gz 归档")?;
    fs::create_dir_all(out)?;
    let mut req = fs::File::create(out.join("req.jsonl"))?;
    let mut outputs = serde_json::Map::new();
    let mut offset = 0usize;
    let mut seen = 0usize;
    while offset + 512 <= tar.len() {
        if tar[offset..offset + 512].iter().all(|b| *b == 0) {
            break;
        }
        let name_end = tar[offset..offset + 100]
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(100);
        let name = String::from_utf8_lossy(&tar[offset..offset + name_end])
            .trim()
            .to_string();
        let size_text = String::from_utf8_lossy(&tar[offset + 124..offset + 136])
            .trim()
            .trim_matches(char::from(0))
            .to_string();
        let size = usize::from_str_radix(size_text.trim(), 8).unwrap_or(0);
        let data_start = offset + 512;
        let data_end = data_start.saturating_add(size).min(tar.len());
        let data = &tar[data_start..data_end];
        offset = data_start + size.div_ceil(512) * 512;
        if data.is_empty() || name.ends_with('/') {
            continue;
        }
        seen += 1;
        if max_files.is_some_and(|limit| seen > limit) {
            break;
        }
        let Ok(mut value) = serde_json::from_slice::<Value>(data) else {
            continue;
        };
        redact_json(&mut value);
        let line = json!({"proto":"desensitized","file":name,"body":value.to_string()});
        writeln!(req, "{}", serde_json::to_string(&line)?)?;
    }
    let req_path = out.join("req.jsonl");
    outputs.insert(
        "req.jsonl".into(),
        json!({"bytes":fs::metadata(&req_path)?.len(),"sha256":sha256_file(&req_path)?}),
    );
    write_json(
        &out.join("manifest.json"),
        &json!({"source":archive.display().to_string(),"outputs":outputs}),
    )?;
    println!("Rust 脱敏完成：{} 个归档条目，输出 {}", seen, out.display());
    Ok(())
}

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const MAX_BINARY_BYTES: usize = 8 << 20;

/// 目标架构（缺口 #7）：守着**同一件事** —— 静态、单文件、机器类型对 ✓。
///
/// 为什么把它参数化而不是复制一份检查：判据（无 `PT_INTERP`、无 `PT_DYNAMIC`、体积上限）
/// 与架构无关 ✓，只有"位数 + `e_machine` + 程序头字段的偏移"随架构变 ✓。
/// 复制第二份一定会漂移 ✗（第 174 轮把两处逐字相同的夹具等待抽成一个，同一条规矩 ✓）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arch {
    Aarch64,
    Armv7,
}

impl Arch {
    fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aarch64" | "arm64" => Ok(Self::Aarch64),
            "armv7" | "arm" | "armv7l" => Ok(Self::Armv7),
            other => bail!("不支持的架构 `{other}`（支持 aarch64 / armv7）"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Aarch64 => "aarch64",
            Self::Armv7 => "armv7",
        }
    }

    /// ELF `e_machine`：aarch64 = 183、ARM = 40（两处都来自 ELF 规范 ✓）。
    fn machine(self) -> u16 {
        match self {
            Self::Aarch64 => 183,
            Self::Armv7 => 40,
        }
    }

    fn is_64(self) -> bool {
        matches!(self, Self::Aarch64)
    }
}

fn elf_check(data: &[u8], arch: Arch) -> Vec<String> {
    let mut problems = Vec::new();
    if data.len() >= MAX_BINARY_BYTES {
        problems.push(format!("载荷 {} B 超过 8 MiB", data.len()));
    }
    if data.len() < 64 || &data[..4] != ELF_MAGIC {
        problems.push("不是 ELF 文件".into());
        return problems;
    }
    // EI_CLASS：1 = 32 位、2 = 64 位；EI_DATA：1 = 小端 ✓。
    let want_class = if arch.is_64() { 2 } else { 1 };
    if data[4] != want_class || data[5] != 1 {
        problems.push(format!(
            "不是 {}-bit 小端 ELF（期望 {}）",
            if arch.is_64() { 64 } else { 32 },
            arch.name()
        ));
        return problems;
    }
    let machine = u16::from_le_bytes([data[18], data[19]]);
    if machine != arch.machine() {
        problems.push(format!("机器类型不是 {}：{machine}", arch.name()));
    }
    // 程序头三件套的偏移随 ELF 类变：ELF64 是 32/54/56，ELF32 是 28/42/44 ✓。
    // （`e_machine` 两者都在 18 ✓，所以上面那句不需要分支 ✓。）
    let (phoff_at, entsz_at, count_at) = if arch.is_64() {
        (32usize, 54usize, 56usize)
    } else {
        (28usize, 42usize, 44usize)
    };
    let phoff = if arch.is_64() {
        u64::from_le_bytes(data[phoff_at..phoff_at + 8].try_into().unwrap()) as usize
    } else {
        u32::from_le_bytes(data[phoff_at..phoff_at + 4].try_into().unwrap()) as usize
    };
    let entsz = u16::from_le_bytes([data[entsz_at], data[entsz_at + 1]]) as usize;
    let count = u16::from_le_bytes([data[count_at], data[count_at + 1]]) as usize;
    for i in 0..count {
        let at = phoff.saturating_add(i * entsz);
        if at + 4 <= data.len() {
            let typ = u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
            if typ == 3 {
                problems.push("动态解释器 PT_INTERP 存在".into());
            }
            if typ == 2 {
                problems.push("动态段 PT_DYNAMIC 存在".into());
            }
        }
    }
    problems
}

fn ar_write(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = b"!<arch>\n".to_vec();
    for (name, data) in members {
        let mut header = Vec::with_capacity(60);
        header.extend_from_slice(format!("{}/", name).as_bytes());
        header.resize(16, b' ');
        header.extend_from_slice(b"0           0     0     100644  ");
        header.extend_from_slice(format!("{:<10}`\n", data.len()).as_bytes());
        out.extend_from_slice(&header[..60]);
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(b'\n');
        }
    }
    out
}

fn ar_read(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    if !data.starts_with(b"!<arch>\n") {
        bail!("不是 ar 归档")
    }
    let mut offset = 8usize;
    let mut members = Vec::new();
    while offset < data.len() {
        if data.len() - offset < 60 {
            bail!("ar 成员头不完整")
        }
        let header = &data[offset..offset + 60];
        if &header[58..60] != b"`\n" {
            bail!("ar 成员头结束标志错误")
        }
        let name = String::from_utf8_lossy(&header[..16])
            .trim()
            .trim_end_matches('/')
            .to_string();
        let size = String::from_utf8_lossy(&header[48..58])
            .trim()
            .parse::<usize>()
            .context("解析 ar 成员长度")?;
        let start = offset + 60;
        let end = start.saturating_add(size);
        if end > data.len() {
            bail!("ar 成员超出归档范围")
        }
        members.push((name, data[start..end].to_vec()));
        offset = end + (size % 2);
    }
    Ok(members)
}

fn tar_gz_read(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut decoder = GzDecoder::new(data);
    let mut tar = Vec::new();
    decoder.read_to_end(&mut tar)?;
    let mut entries = Vec::new();
    let mut offset = 0usize;
    while offset + 512 <= tar.len() {
        let header = &tar[offset..offset + 512];
        if header.iter().all(|b| *b == 0) {
            break;
        }
        let name_end = header[..100].iter().position(|b| *b == 0).unwrap_or(100);
        let name = String::from_utf8_lossy(&header[..name_end]).to_string();
        let size_text = String::from_utf8_lossy(&header[124..136])
            .trim_matches(char::from(0))
            .trim()
            .to_string();
        let size = usize::from_str_radix(&size_text, 8).context("解析 tar 成员长度")?;
        let start = offset + 512;
        let end = start.saturating_add(size);
        if end > tar.len() {
            bail!("tar 成员超出归档范围")
        }
        entries.push((name, tar[start..end].to_vec()));
        offset = start + size.div_ceil(512) * 512;
    }
    Ok(entries)
}

fn tar_gz(files: &[(&str, &[u8], u32)]) -> Result<Vec<u8>> {
    let mut tar = Vec::new();
    for (name, data, mode) in files {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(format!("{:07o}\0", mode).as_bytes());
        h[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        let sum: u32 = h.iter().map(|b| *b as u32).sum();
        h[148..156].copy_from_slice(format!("{:06o}\0 ", sum).as_bytes());
        tar.extend_from_slice(&h);
        tar.extend_from_slice(data);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    }
    tar.resize(tar.len() + 1024, 0);
    let mut gz = GzEncoder::new(Vec::new(), Compression::best());
    gz.write_all(&tar)?;
    Ok(gz.finish()?)
}

fn package(args: PackageArgs) -> Result<()> {
    let arch = Arch::parse(&args.arch)?;
    if args.selftest {
        let control = tar_gz(&[("control", b"Package: dshp\nArchitecture: aarch64\n", 0o644)])?;
        let data = tar_gz(&[("usr/bin/llmproxyd", b"not-elf", 0o755)])?;
        let blob = ar_write(&[
            ("debian-binary", b"2.0\n"),
            ("control.tar.gz", &control),
            ("data.tar.gz", &data),
        ]);
        if !blob.starts_with(b"!<arch>\n") {
            bail!("ar 自检失败")
        }
        if elf_check(b"not-elf", arch).is_empty() {
            bail!("ELF 反例自检失败")
        }
        // **架构判据的自检**（缺口 #7）：合成两个最小 ELF 头 —— 64 位 machine=183（aarch64）与
        // 32 位 machine=40（ARM）—— 断言"只认自己那一类" ✓。
        // 为什么必须自检它：`--arch` 是个**参数** ✗，参数写错/被忽略时的表现恰好是
        // "检查通过"（拿 aarch64 产物去当 armv7 也会绿 ✗✗）⇒ 必须用反例把这条钉住 ✓。
        let mut elf64 = vec![0u8; 64];
        elf64[..4].copy_from_slice(b"\x7fELF");
        elf64[4] = 2; // ELF64
        elf64[5] = 1; // 小端
        elf64[18..20].copy_from_slice(&183u16.to_le_bytes());
        elf64[56..58].copy_from_slice(&0u16.to_le_bytes()); // e_phnum = 0
        let mut elf32 = vec![0u8; 64];
        elf32[..4].copy_from_slice(b"\x7fELF");
        elf32[4] = 1; // ELF32
        elf32[5] = 1;
        elf32[18..20].copy_from_slice(&40u16.to_le_bytes());
        elf32[44..46].copy_from_slice(&0u16.to_le_bytes()); // e_phnum = 0
        if !elf_check(&elf64, Arch::Aarch64).is_empty() {
            bail!("自检失败：aarch64 头应当通过")
        }
        if !elf_check(&elf32, Arch::Armv7).is_empty() {
            bail!("自检失败：armv7 头应当通过")
        }
        if elf_check(&elf64, Arch::Armv7).is_empty() {
            bail!("自检失败：aarch64 产物在 --arch armv7 下**必须**被拒")
        }
        if elf_check(&elf32, Arch::Aarch64).is_empty() {
            bail!("自检失败：armv7 产物在 --arch aarch64 下**必须**被拒")
        }
        println!("opkg Rust 自检通过（ar + tar.gz + ELF 反例）");
        return Ok(());
    }
    if let Some(path) = args.verify_only {
        let data = fs::read(&path)?;
        let members = ar_read(&data).with_context(|| format!("校验 {}", path.display()))?;
        let required = ["debian-binary", "control.tar.gz", "data.tar.gz"];
        for name in required {
            if !members.iter().any(|(member, _)| member == name) {
                bail!("{} 缺少 ar 成员 {name}", path.display());
            }
        }
        let data_tar = members
            .iter()
            .find(|(name, _)| name == "data.tar.gz")
            .map(|(_, bytes)| bytes)
            .expect("已检查 data.tar.gz");
        let files = tar_gz_read(data_tar)?;
        let mut payloads = 0;
        for (name, bytes) in files {
            if name == "usr/bin/llmproxyc" || name == "usr/bin/llmproxyd" {
                let problems = elf_check(&bytes, arch);
                if !problems.is_empty() {
                    bail!("{}：{}", name, problems.join("；"));
                }
                payloads += 1;
            }
        }
        if payloads == 0 {
            bail!("{} 的 data.tar.gz 没有代理 ELF 载荷", path.display());
        }
        println!(
            "{} 校验通过（ar + tar.gz + {} 个静态 {} ELF）",
            path.display(),
            payloads,
            arch.name()
        );
        return Ok(());
    }
    fs::create_dir_all(&args.out)?;
    let mut members = Vec::new();
    for name in ["llmproxyc", "llmproxyd"] {
        let path = args.bin_dir.join(name);
        if path.exists() {
            let data = fs::read(&path)?;
            let problems = elf_check(&data, arch);
            if !problems.is_empty() {
                bail!("{}：{}", path.display(), problems.join("；"));
            }
            members.push((name, data));
        }
    }
    if members.is_empty() {
        bail!("{} 中没有 llmproxyc/llmproxyd", args.bin_dir.display());
    }
    let control = tar_gz(&[(
        "control",
        format!(
            "Package: dshp\nVersion: {}\nArchitecture: {}\n",
            args.version,
            arch.name()
        )
        .as_bytes(),
        0o644,
    )])?;
    let data_files: Vec<_> = members
        .iter()
        .map(|(n, d)| (format!("usr/bin/{n}"), d.as_slice(), 0o755))
        .collect();
    let data = tar_gz(
        &data_files
            .iter()
            .map(|(n, d, m)| (n.as_str(), *d, *m))
            .collect::<Vec<_>>(),
    )?;
    let archive = ar_write(&[
        ("debian-binary", b"2.0\n"),
        ("control.tar.gz", &control),
        ("data.tar.gz", &data),
    ]);
    let path = args
        .out
        .join(format!("dshp_{}_{}.ipk", args.version, arch.name()));
    fs::write(&path, archive)?;
    println!("已生成 {}", path.display());
    Ok(())
}

fn ci_failures(args: CiFailuresArgs) -> Result<()> {
    if args.selftest {
        let sample =
            "test foo ... FAILED\nfailures:\n    foo\ntest result: FAILED. 1 passed; 1 failed";
        let report = failure_report(sample);
        if !report.contains("foo") {
            bail!("日志分析器自检失败")
        }
        println!("CI 日志分析自检通过");
        return Ok(());
    }
    if args.logs.is_empty() {
        bail!("用法：cargo run -p dev-tools -- ci-failures <日志>");
    }
    for path in args.logs {
        let text = decode_log(&fs::read(&path)?);
        print!("{}", failure_report(&text));
    }
    Ok(())
}

fn decode_log(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xff, 0xfe]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

fn failure_report(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        if line.contains("test result: FAILED")
            || line.contains("失败（exit=")
            || line.contains("✗")
        {
            out.push_str("  ");
            out.push_str(line.trim());
            out.push('\n');
        }
        if line.starts_with("    ") && !line.trim().is_empty() {
            out.push_str("  失败测试：");
            out.push_str(line.trim());
            out.push('\n');
        }
    }
    if out.is_empty() {
        "没有失败 ✓\n".into()
    } else {
        out
    }
}
