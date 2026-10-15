//! 按协议/时间分组、追加消息 patch、时间留出评估与字典产物。
use super::*;
use std::{collections::BTreeMap, io::BufRead};

pub const GATES: &[(&str, f64, bool)] = &[
    ("chosen.gain_vs_nodict", 1.0, false),
    ("chosen.holdout_ratio", 0.70, true),
    ("structure_only.gain_vs_nodict", 1.30, false),
    ("extra_dicts.dict_ctrl.gain", 2.0, false),
    ("patch_samples.train", 20.0, false),
    ("patch_samples.holdout", 10.0, false),
    ("chosen.dict_bytes", WINDOW_BYTES as f64, true),
];

pub fn evaluate(metrics: &Value, allow_missing: bool) -> Result<()> {
    let mut failures = Vec::new();
    for &(path, threshold, upper) in GATES {
        let Some(value) = get_path(metrics, path).and_then(Value::as_f64) else {
            if !allow_missing {
                failures.push(format!("缺少指标 {path}"));
            }
            println!("  SKIP  {path}（缺少对应语料）");
            continue;
        };
        let ok = if upper {
            value <= threshold
        } else {
            value >= threshold
        };
        println!(
            "  {}  {path}: {value:.4} {} {threshold}",
            if ok { "PASS" } else { "FAIL" },
            if upper { "<=" } else { ">=" }
        );
        if !ok {
            failures.push(path.to_owned());
        }
    }
    if !failures.is_empty() {
        bail!("语料门禁失败：{}", failures.join("、"));
    }
    Ok(())
}

struct Record {
    time: i64,
    proto: String,
    data: Vec<u8>,
}

fn timestamp(name: &str) -> Option<i64> {
    for raw in name.as_bytes().windows(17) {
        if raw[4] != b'-' || raw[7] != b'-' || raw[10] != b'T' {
            continue;
        }
        let number = |range: std::ops::Range<usize>| -> Option<i64> {
            std::str::from_utf8(&raw[range]).ok()?.parse().ok()
        };
        let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return None;
        }
        let leap = |y: i64| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
        let mut days = (year - 1970) * 365;
        days += (1970..year).filter(|&y| leap(y)).count() as i64;
        let months = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        days += months[..(month - 1) as usize].iter().sum::<i64>();
        if month > 2 && leap(year) {
            days += 1;
        }
        days += day - 1;
        return Some(
            days * 86400 + number(11..13)? * 3600 + number(13..15)? * 60 + number(15..17)?,
        );
    }
    None
}

fn records(path: &Path, field: &str, require_time: bool) -> Result<Vec<Record>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let reader = std::io::BufReader::new(fs::File::open(path)?);
    let mut result = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let row: Value = serde_json::from_str(&line)
            .with_context(|| format!("{}:{}", path.display(), index + 1))?;
        let time = row.get("file").and_then(Value::as_str).and_then(timestamp);
        if require_time && time.is_none() {
            continue;
        }
        if let Some(data) = row.get(field) {
            let bytes = data
                .as_str()
                .map(str::as_bytes)
                .map(Vec::from)
                .unwrap_or_else(|| data.to_string().into_bytes());
            result.push(Record {
                time: time.unwrap_or(0),
                proto: row["proto"].as_str().unwrap_or("unknown").into(),
                data: bytes,
            });
        }
    }
    result.sort_by_key(|r| r.time);
    Ok(result)
}

fn patches(
    records: &[Record],
    gap: i64,
    max_span: usize,
    max_payload: usize,
) -> Result<Vec<(i64, Vec<u8>)>> {
    let mut groups: BTreeMap<&str, Vec<&Record>> = BTreeMap::new();
    for row in records {
        groups.entry(&row.proto).or_default().push(row);
    }
    let mut result = Vec::new();
    for rows in groups.values() {
        let bodies: Vec<Option<Value>> = rows
            .iter()
            .map(|r| serde_json::from_slice(&r.data).ok())
            .collect();
        for i in 0..rows.len() {
            for j in i + 1..(i + max_span + 1).min(rows.len()) {
                if (i + 1..=j).any(|k| rows[k].time - rows[k - 1].time > gap) {
                    break;
                }
                let messages = |index: usize| bodies[index].as_ref()?.get("messages")?.as_array();
                let (Some(a), Some(b)) = (messages(i), messages(j)) else {
                    continue;
                };
                if b.len() <= a.len() {
                    continue;
                }
                let prefix = a.iter().zip(b).take_while(|(x, y)| x == y).count();
                if prefix == 0 {
                    continue;
                }
                let payload = serde_json::to_vec(&b[prefix..])?;
                if payload.len() <= max_payload {
                    result.push((rows[j].time, payload));
                }
            }
        }
    }
    result.sort_by_key(|(time, _)| *time);
    Ok(result)
}

fn skeleton(data: &[u8]) -> Vec<u8> {
    fn walk(value: &mut Value, key: &str) {
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    walk(value, key);
                }
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, key);
                }
            }
            Value::String(s)
                if ![
                    "role",
                    "type",
                    "model",
                    "object",
                    "finish_reason",
                    "stop_reason",
                    "status",
                    "effort",
                    "reasoning_effort",
                    "quality",
                    "size",
                    "detail",
                    "encoding_format",
                    "format",
                    "tool_choice",
                    "service_tier",
                    "truncation",
                    "include",
                    "cache_control",
                    "stream",
                    "index",
                    "required",
                    "enum",
                ]
                .contains(&key) =>
            {
                s.clear()
            }
            _ => {}
        }
    }
    let Ok(mut value) = serde_json::from_slice(data) else {
        return data.to_vec();
    };
    walk(&mut value, "");
    serde_json::to_vec(&value).expect("JSON value serializes")
}

pub fn compressor(dict: &[u8]) -> Result<zstd::bulk::Compressor<'_>> {
    if dict.is_empty() {
        return Ok(zstd::bulk::Compressor::new(1)?);
    }
    let mut compressor = zstd::bulk::Compressor::with_dictionary(1, dict)?;
    compressor.set_parameter(zstd::zstd_safe::CParameter::ContentSizeFlag(false))?;
    Ok(compressor)
}

fn ratio(samples: &[Vec<u8>], dict: &[u8]) -> Result<f64> {
    let total: usize = samples.iter().map(Vec::len).sum();
    if total == 0 {
        return Ok(0.0);
    }
    let mut c = compressor(dict)?;
    let mut compressed = 0;
    for sample in samples {
        compressed += c.compress(sample)?.len();
    }
    Ok(compressed as f64 / total as f64)
}

fn split(samples: &[Vec<u8>], fraction: f64) -> (&[Vec<u8>], &[Vec<u8>]) {
    let count = ((samples.len() as f64 * fraction).round() as usize)
        .max(1)
        .min(samples.len().saturating_sub(1));
    samples.split_at(samples.len() - count)
}

pub fn run(args: TrainArgs) -> Result<()> {
    if !(0.0..1.0).contains(&args.holdout_frac) || args.max_span == 0 || args.max_payload == 0 {
        bail!("holdout-frac 须在 0..1，max-span/max-payload 须大于零");
    }
    let req = records(&args.corpus.join("req.jsonl"), "body", true)?;
    if req.is_empty() {
        bail!("{} 没有带时间戳的请求", args.corpus.display());
    }
    let patch = patches(
        &req,
        args.gap_seconds as i64,
        args.max_span,
        args.max_payload,
    )?;
    if patch.len() < 2 {
        bail!("没有足够的追加消息 patch（{} 个）", patch.len());
    }
    let payloads: Vec<_> = patch.iter().map(|(_, data)| data.clone()).collect();
    let (train, holdout) = split(&payloads, args.holdout_frac);
    let sk_train: Vec<_> = train.iter().map(|v| skeleton(v)).collect();
    let sk_hold: Vec<_> = holdout.iter().map(|v| skeleton(v)).collect();
    let base = ratio(holdout, &[])?;
    let sk_base = ratio(&sk_hold, &[])?;
    let sizes: Vec<usize> = args
        .sizes
        .split(',')
        .map(|s| s.trim().parse::<usize>())
        .collect::<Result<_, _>>()?;
    if sizes.is_empty() || sizes.iter().any(|&s| s == 0 || s > WINDOW_BYTES) {
        bail!("字典尺寸须在 1..={WINDOW_BYTES}");
    }
    let mut sweep = serde_json::Map::new();
    let mut trained = BTreeMap::new();
    for size in sizes {
        let Ok(dict) = zstd::dict::from_samples(train, size) else {
            println!("SKIP {size}B：训练样本不足");
            continue;
        };
        let rh = ratio(holdout, &dict)?;
        let sh = ratio(&sk_hold, &dict)?;
        sweep.insert(size.to_string(),json!({"dict_bytes":dict.len(),"train_ratio":ratio(train,&dict)?,"holdout_ratio":rh,"gain_vs_nodict":base/rh,"structure_holdout_ratio":sh,"structure_gain":sk_base/sh}));
        trained.insert(size, dict);
    }
    let best = sweep
        .values()
        .filter_map(|v| v["structure_holdout_ratio"].as_f64())
        .fold(f64::INFINITY, f64::min);
    let chosen = trained
        .keys()
        .copied()
        .find(|s| {
            sweep[&s.to_string()]["structure_holdout_ratio"]
                .as_f64()
                .unwrap()
                <= best * 1.05
        })
        .context("所有字典尺寸均训练失败")?;
    let dict = &trained[&chosen];
    let selected = &sweep[&chosen.to_string()];
    let maximum = *trained.keys().last().unwrap();
    let full: Vec<_> = req.iter().map(|r| r.data.clone()).collect();
    let (_, full_hold) = split(&full, args.holdout_frac);
    let mut outputs = BTreeMap::from([("dict_patch", dict.clone())]);
    let mut extra = serde_json::Map::new();
    for (name, file, field, size, timed) in [
        ("dict_ctrl", "headers.jsonl", "headers", 1024, false),
        ("dict_sse", "resp.jsonl", "stream", 4096, true),
    ] {
        let data: Vec<_> = records(&args.corpus.join(file), field, timed)?
            .into_iter()
            .map(|r| r.data)
            .collect();
        if data.len() < 2 {
            println!("SKIP {name}：无可用语料");
            continue;
        }
        let (tr, ho) = if timed {
            split(&data, args.holdout_frac)
        } else {
            (data.as_slice(), data.as_slice())
        };
        if let Ok(d) = zstd::dict::from_samples(tr, size) {
            let rd = ratio(ho, &d)?;
            let rn = ratio(ho, &[])?;
            extra.insert(
                name.into(),
                json!({"dict_bytes":d.len(),"holdout_ratio":rd,"holdout_nodict":rn,"gain":rn/rd}),
            );
            outputs.insert(name, d);
        }
    }
    let metrics = json!({
        "zstd_level":1,"split":{"kind":"global_time_ordered","holdout_frac":args.holdout_frac,"gap_seconds":args.gap_seconds,"max_span":args.max_span,"max_payload":args.max_payload},
        "patch_samples":{"total":patch.len(),"train":train.len(),"holdout":holdout.len(),"train_bytes":train.iter().map(Vec::len).sum::<usize>(),"holdout_bytes":holdout.iter().map(Vec::len).sum::<usize>(),"train_last_ts":patch[train.len()-1].0,"holdout_first_ts":patch[train.len()].0},
        "chosen":{"size":chosen,"dict_bytes":dict.len(),"holdout_ratio":selected["holdout_ratio"],"holdout_nodict_ratio":base,"gain_vs_nodict":selected["gain_vs_nodict"]},
        "structure_only":{"holdout_ratio_nodict":sk_base,"holdout_ratio_dict":selected["structure_holdout_ratio"],"gain_vs_nodict":selected["structure_gain"],"skeleton_share_train":sk_train.iter().map(Vec::len).sum::<usize>() as f64 / train.iter().map(Vec::len).sum::<usize>() as f64},
        "full_body":{"holdout_ratio_nodict":ratio(full_hold,&[])?,"holdout_ratio_dict":ratio(full_hold,dict)?,"gain":ratio(full_hold,&[])?/ratio(full_hold,dict)?},
        "saturation":{"saturated":chosen < maximum,"tested_min":trained.keys().next(),"tested_max":maximum},"sweep":sweep,"extra_dicts":extra
    });
    if let Some(path) = args.json {
        write_json(&path, &metrics)?;
    }
    let result = evaluate(&metrics, true);
    if !args.smoke {
        result?;
    } else {
        println!("--smoke：仅验证管线，标定阈值不判红");
    }
    if args.update_baseline || args.smoke {
        fs::create_dir_all(&args.out)?;
        let mut manifest = serde_json::Map::new();
        for (name, data) in outputs {
            let path = args.out.join(format!("{name}.zstdict"));
            fs::write(&path, &data)?;
            manifest.insert(
                name.into(),
                json!({"bytes":data.len(),"sha256":sha256_file(&path)?}),
            );
        }
        write_json(&args.out.join("metrics.json"), &metrics)?;
        write_json(
            &args.out.join("manifest.json"),
            &json!({"source_corpus":args.corpus,"dicts":manifest,"metrics":metrics}),
        )?;
        if args.update_baseline {
            write_json(
                &root().join("bench/real_baseline.json"),
                &json!({"metrics":metrics}),
            )?;
        }
    }
    println!(
        "训练完成：{} 个 patch，训练 {} / 留出 {}，选型 {} B",
        patch.len(),
        train.len(),
        holdout.len(),
        chosen
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timestamp_and_gap_cross_day() {
        assert_eq!(
            timestamp("a-2026-10-10T235959-abcdef12.log").unwrap() + 1,
            timestamp("a-2026-10-11T000000-abcdef12.log").unwrap()
        );
    }
    #[test]
    fn patch_excludes_old_messages_and_obeys_gap() {
        let records = vec![Record{time:0,proto:"messages".into(),data:br#"{"messages":[{"role":"user","content":"old"}]}"#.to_vec()},Record{time:1,proto:"messages".into(),data:br#"{"messages":[{"role":"user","content":"old"},{"role":"user","content":"new"}]}"#.to_vec()}];
        let p = patches(&records, 120, 2, 65536).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&p[0].1).unwrap(),
            json!([{"role":"user","content":"new"}])
        );
        assert!(patches(&records, 0, 2, 65536).unwrap().is_empty());
    }
    #[test]
    fn gate_rejects_regression_and_missing_measurement() {
        assert!(evaluate(&json!({"chosen":{"gain_vs_nodict":0.5}}), true).is_err());
        assert!(evaluate(&json!({}), false).is_err());
    }
}
