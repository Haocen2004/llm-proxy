//! **真实语料的增量收益标定**（Rust ✓；第 156 轮从 `crates/dshp-replay` 搬进来 ✓）。
//!
//! 为什么放在 `tests/` 而不是新开一个 bin ✗：§12 的**硬约束门禁**（`cargo run -p dev-tools -- gates` ✓）
//! 扫的是 `crates/*/src` ✓，它对"生产源"有硬约束（纯内存、磁盘 0 写入、线程数、以及
//! "**只有两个二进制**"✓）—— 而标定工具要读语料文件、本来就不该按"生产源"来量 ✓。
//! 放进 `tests/` 既不被那道门禁扫 ✓，又能把结论**变成被判定的性质** ✓（比只打印报告强 ✓）。
//!
//! **口径**：直接调用实现本身 `llm_proxy_core::token::decompose` ✓ —— 不是复刻 ✓。
//! 这一点是第 154 轮改 Rust 的核心动机：Python 版是"我在复刻它的口径" ✗，
//! 第 152~153 轮我因此连踩三层坑（字段名／`datetime`／会话层数 ✓），而且每次
//! **静默返回 0** ✗✗，差点把"没算对"当成"没有收益"。
//!
//! 语料不入库（`corpus-next/` 被 gitignore ✓）⇒ 找不到时**明确跳过并打印原因** ✓，不判红 ✗。

use llm_proxy_core::fingerprint::{Fp, Namespace};
use llm_proxy_core::token::decompose;
use std::collections::HashSet;
use std::io::BufRead;

/// 从 `v1-messages-2026-10-09T020118-eaf31a88.log` 里取 `2026-10-09T020118` 的"分钟数" ✓。
///
/// 只需要**可比大小 + 算差** ✓，不必是真日历算法 ✓（差 >2 即 >120 s ⇒ 断开会话 ✓）。
fn ts_of(file: &str) -> Option<i64> {
    let b = file.as_bytes();
    for i in 0..b.len().saturating_sub(15) {
        let w = &file[i..i + 16]; // 形如 `2026-10-09T020118` —— **没有冒号** ✓
        let ok = w.as_bytes().get(4) == Some(&b'-')
            && w.as_bytes().get(7) == Some(&b'-')
            && w.as_bytes().get(10) == Some(&b'T')
            && w.bytes()
                .enumerate()
                .all(|(k, c)| matches!(k, 4 | 7 | 10) || c.is_ascii_digit());
        if ok {
            let y: i64 = w[0..4].parse().ok()?;
            let mo: i64 = w[5..7].parse().ok()?;
            let d: i64 = w[8..10].parse().ok()?;
            let h: i64 = w[11..13].parse().ok()?;
            let mi: i64 = w[13..15].parse().ok()?;
            return Some(((y * 372 + mo * 31 + d) * 24 + h) * 60 + mi);
        }
    }
    None
}

fn corpus_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn real_corpus_uplink_savings_meet_the_m1a_bar() {
    // **默认跳过**（第 157 轮加 ✓）：真实语料上跑 963×1.4 MB 的 `decompose` 在 debug 下约 97 s ✓
    // ⇒ 与"时延类"用例同趟会相互挤 ✗（第 156 轮实测把 `slow_path` 的首字节用例挤成 502 ✓）。
    // ⇒ 由 CI 的**独立步骤**用 `DSHP_REAL_CORPUS=1` 打开 ✓。
    if std::env::var("DSHP_REAL_CORPUS").is_err() {
        println!("  ⏭ 跳过真实语料标定：需要 `DSHP_REAL_CORPUS=1`（CI 有独立步骤跑它 ✓）");
        return;
    }
    let reqs = corpus_dir().join("corpus-next").join("req.jsonl");
    if !reqs.exists() {
        println!(
            "  ⏭ 跳过真实语料标定：找不到 {}（语料不入库 ✓ 属正常）\
             ⇒ 把真实日志的脱敏产物放到 `corpus-next/` 即可跑本测试 ✓",
            reqs.display()
        );
        return;
    }

    // 流式读（req.jsonl 1.5 GB ✗ —— 别 `read_to_string` ✓，第 155 轮实测 30 秒级 ✓）
    let mut recs: Vec<(i64, Vec<u8>)> = Vec::new();
    {
        let f = std::fs::File::open(&reqs).unwrap();
        for line in std::io::BufReader::new(f).lines() {
            let Ok(line) = line else { continue };
            if line.trim().is_empty() {
                continue;
            }
            let Ok(o) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            if o.get("proto").and_then(|p| p.as_str()) != Some("messages") {
                continue;
            }
            let (Some(f), Some(b)) = (o["file"].as_str(), o["body"].as_str()) else {
                continue;
            };
            let Some(ts) = ts_of(f) else { continue };
            recs.push((ts, b.as_bytes().to_vec()));
        }
    }
    assert!(!recs.is_empty(), "语料里没有 proto=messages 的请求");
    recs.sort_by_key(|r| r.0);

    // 按 120 s 间隔分组成会话 ✓（与 `train_dict.group_conversations` 同一口径 ✓）
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut cur: Vec<usize> = Vec::new();
    for i in 0..recs.len() {
        if let Some(&last) = cur.last() {
            if recs[i].0 - recs[last].0 > 2 {
                groups.push(std::mem::take(&mut cur));
            }
        }
        cur.push(i);
    }
    if !cur.is_empty() {
        groups.push(cur);
    }

    let ns = Namespace::derive(b"replay-test-psk", "replay", "replay.local");
    let mut raw_total = 0usize;
    let mut wire_total = 0usize;
    let mut satisfying = 0usize;
    let mut long_groups: Vec<(usize, f64)> = Vec::new();
    for g in &groups {
        // 客户端本地"已知块"：本会话里**此前发过**的块 ✓（正是 DSHP 客户端记账的语义 ✓）
        let mut known: HashSet<Fp> = HashSet::new();
        let (mut raw, mut wire) = (0usize, 0usize);
        for &idx in g {
            let body = &recs[idx].1;
            let d = decompose(ns, body, |fp| known.contains(fp));
            raw += body.len();
            wire += d.stream.len(); // 线上字节 = 流本体 ✓（真字段是 `stream` ✓）
            for fp in &d.new_fps {
                known.insert(*fp);
            }
        }
        raw_total += raw;
        wire_total += wire;
        let pct = if raw > 0 {
            wire as f64 / raw as f64 * 100.0
        } else {
            0.0
        };
        if g.len() >= 5 {
            long_groups.push((g.len(), pct));
            if pct <= 5.0 {
                satisfying += 1;
            }
        }
    }
    // 按"条数"排序打印，便于人读 ✓
    long_groups.sort_by_key(|(n, _)| std::cmp::Reverse(*n));
    let total_pct = wire_total as f64 / raw_total as f64 * 100.0;
    println!(
        "  [真实语料标定] {} 条真实请求 / {} 会话组；原始 {:.2} MiB → 线流 {:.2} MiB = **{:.2}%**（省 {:.2}%）",
        recs.len(),
        groups.len(),
        raw_total as f64 / 1048576.0,
        wire_total as f64 / 1048576.0,
        total_pct,
        100.0 - total_pct
    );
    for (n, pct) in long_groups.iter().take(6) {
        println!("    长会话 {n:>3} 轮 ⇒ 线流 {pct:>6.2}%");
    }
    println!(
        "  M1a 口径「≥5 轮且上行 ≤5%」：**{satisfying}/{}** ✓",
        long_groups.len()
    );

    // **判据**：真实语料上，长会话必须满足 M1a 的 5% 线 ✓（不允许用合成夹具代替 ✓）
    assert!(
        !long_groups.is_empty(),
        "语料里没有 ≥5 轮的会话 ⇒ 无法判定 M1a（应换一段更长的真实窗口 ✓）"
    );
    assert!(
        satisfying * 2 >= long_groups.len(),
        "真实语料上满足「≥5 轮且 ≤5%」的会话太少：{satisfying}/{} ✗",
        long_groups.len()
    );
    assert!(
        long_groups.iter().any(|(n, pct)| *n >= 100 && *pct <= 5.0),
        "没有任何 ≥100 轮的长会话落在 5% 线内 ⇒ 大流量场景的收益未被证明 ✗"
    );
}
