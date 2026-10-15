//! M3 验收最后一项：**慢路径延迟 ≤100ms**（设计 §6.3）。
//!
//! # 慢路径是干什么的
//!
//! 真实 LLM 上游会不断加新 event 类型。那些响应落不进任何模板——如果只能按原样透传，
//! 代理就退化成了一个普通转发器。慢路径是这里的安全网：**未命中模板时改用流式 zstd**。
//!
//! # 为什么必须验"延迟"而不是只验"能跑"
//!
//! 设计 §6.3 要求 flush 由「距上次 flush ≥100ms 或累积 ≥1KB，**先到者触发**」驱动，
//! 并特别说明：**计数驱动在高吞吐时延迟爆炸**。
//!
//! 所以这条测试要区分的是两种实现：
//!
//! * **时间驱动**：上游静默期间客户端已经拿到前面的事件 → 首字节早；
//! * **计数驱动**：攒不满 1KB 就一个字节都不发 → 首字节要等到流结束。
//!
//! 上游样本刻意做成"事件很少、字节数远小于 1KB、然后长时间静默"，
//! 正是这两种实现差异最大的形状。只断言"最后内容对"，两者都会通过。

mod common;

use common::*;

/// 模板未命中时，慢路径必须在 100ms 量级内把已收到的事件发出去。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_path_flushes_on_time_not_on_byte_count() {
    guard(async {
        let st = setup().await.expect("启动失败");

        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/messages",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "sse-novel"),
            ],
            br#"{"stream":true}"#,
        )
        .await
        .expect("请求失败");

        assert_eq!(resp.status, 200);
        let expect = st.up.sse_bytes.lock().unwrap().clone();
        assert!(
            !expect.is_empty(),
            "上游必须真的产出了内容，否则这条测试毫无意义"
        );
        assert_bytes_eq(
            &resp.body,
            &expect,
            "慢路径必须逐字节还原——压缩只是传输手段，不能改变内容",
        );

        let total = resp
            .chunk_times
            .last()
            .map(|t| t.duration_since(resp.start))
            .unwrap_or_default();
        let first = resp
            .chunk_times
            .first()
            .map(|t| t.duration_since(resp.start))
            .unwrap_or_default();
        println!(
            "  [慢路径] 首字节 {first:?}，整体 {total:?}，分片数 {}，上游共 {} B",
            resp.chunk_times.len(),
            expect.len()
        );

        // 先确认这条测试没有空过：上游确实有一段长静默
        assert!(
            total >= std::time::Duration::from_millis(1400),
            "上游应当有一段 ~1.5s 的静默；实际总共只有 {total:?}，\
             说明这条测试没有测到它想测的东西"
        );
        // 核心断言：前 8 个事件只有几百字节，远不到 1KB 阈值。
        // 时间驱动 → 100ms 量级就发出来了；计数驱动 → 要等到 {total:?}。
        assert!(
            first < std::time::Duration::from_millis(600),
            "慢路径必须**按时间**flush：首字节实测 {first:?}，而整体 {total:?}。\
             若首字节接近整体，说明实现退化成了计数驱动（攒够阈值才发）——\
             那在高吞吐时会让延迟爆炸"
        );
    })
    .await;
}

/// 对照实验：关掉慢路径时**行为必须仍然正确**，只是不再压缩。
///
/// 这条守的是"慢路径是一个优化，不是正确性前提"。如果一个开关能改变内容，
/// 那它就不该叫优化。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabling_slow_path_still_serves_correctly() {
    guard(async {
        let st = setup_with(&["--disable-slow-path".into()], &[])
            .await
            .expect("启动失败");

        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/messages",
            &[
                ("content-type", "application/json"),
                ("x-test-mode", "sse-novel"),
            ],
            br#"{"stream":true}"#,
        )
        .await
        .expect("请求失败");
        assert_eq!(resp.status, 200);
        let expect = st.up.sse_bytes.lock().unwrap().clone();
        assert_bytes_eq(&resp.body, &expect, "关掉慢路径后内容仍须逐字节一致");
    })
    .await;
}

/// 常规可模板化的 SSE **不得**被误判进慢路径——否则会把模板化的收益白白丢掉。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn templatable_sse_does_not_enter_slow_path() {
    guard(async {
        let st = setup().await.expect("启动失败");
        let resp = raw_request(
            &st.client,
            "POST",
            "/v1/messages",
            &[("content-type", "application/json"), ("x-test-mode", "sse")],
            br#"{"stream":true}"#,
        )
        .await
        .expect("请求失败");
        assert_eq!(resp.status, 200);
        let expect = st.up.sse_bytes.lock().unwrap().clone();
        assert_bytes_eq(&resp.body, &expect, "常规 SSE 必须逐字节一致");

        let v = st.status().await.unwrap();
        let defs = v["resp_frames"]["template_defs"].as_u64().unwrap_or(0);
        println!("  [模板路径] 模板定义 {defs} 个");
        assert!(
            defs >= 1,
            "常规形态的 SSE 必须走模板归纳，而不是慢路径（模板定义数为 0 说明判据过宽）：{v}"
        );
    })
    .await;
}

/// `--slow-flush-ms` 与 `--slow-flush-bytes` **必须真的决定延迟上界**。
///
/// # 为什么单独测这两个开关
///
/// 它们此前在全仓库里**没有任何使用点**（测试、脚本、文档都没有）——也就是说
/// 调了它们没有任何东西能证明行为变了。而设计 §6.3 的原话是
/// 「flush 由『距上次 flush ≥100ms 或累积 ≥1KB，**先到者触发**』驱动」：
/// 它们不是调参玩具，而是慢路径延迟上界的定义。
///
/// # 三档对照（都在 `sse-novel` 上游上跑：8 个小事件在 ~80ms 内到齐，然后静默 1.5s）
///
/// | 档 | 配置 | 期望首字节 |
/// |---|---|---|
/// | A | `ms=100, bytes=1MB` | ~100ms（时间阈值触发） |
/// | B | `ms=900, bytes=1MB` | ~900ms（**跟着开关走**） |
/// | C | `ms=1000000, bytes=1024` | ~1.6s（时间阈值形同关闭 ⇒ 只能等字节阈值/流结束） |
///
/// B 那一档是核心：如果定时分支**无条件** flush（不看 `slow_window`），
/// A 与 B 的首字节会几乎一样——那说明开关是装饰品。实测确实如此（见 README）。
///
/// 三档都必须**逐字节一致**：flush 节奏只影响分帧，不许影响内容。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_flush_knobs_govern_the_latency_bound() {
    guard(async {
        let cases: [(&str, &str, &str); 3] = [
            ("A 时间 100ms", "100", "1000000"),
            ("B 时间 900ms", "900", "1000000"),
            ("C 只靠字节 1KB", "1000000", "1024"),
        ];
        let mut firsts: Vec<(&str, f64, f64)> = Vec::new();
        for (label, ms, bytes) in cases {
            let st = setup_with(
                &[
                    "--slow-flush-ms".into(),
                    ms.into(),
                    "--slow-flush-bytes".into(),
                    bytes.into(),
                ],
                &[],
            )
            .await
            .expect("启动失败");

            let resp = raw_request(
                &st.client,
                "POST",
                "/v1/messages",
                &[
                    ("content-type", "application/json"),
                    ("x-test-mode", "sse-novel"),
                ],
                br#"{"stream":true}"#,
            )
            .await
            .unwrap_or_else(|e| panic!("{label} 请求失败：{e}"));
            assert_eq!(resp.status, 200);

            // 内容不许随 flush 节奏变化
            let expect = st.up.sse_bytes.lock().unwrap().clone();
            assert_bytes_eq(
                &resp.body,
                &expect,
                &format!("{label}：改 flush 节奏不许改变内容"),
            );

            // **探针按内容判，不按时间地板判。**
            //
            // 夹具 `sse-novel`：8 个形态各异的小事件（合计 ~500 B、单个 ~60 B）→ 静默 1.5s → 1 个事件。
            // 慢路径把前面那批**攒起来一次 flush** ⇒ 那一片**单片 ≥2 个事件**（≥100 B）；
            // 快路径前导沿最多只带 1 个事件（~60 B）⇒ 用"这一片够不够大"就能把两者分开 ✓✓。
            //
            // 第 180 轮实测教训：原先只用"首个 ≥0.05s 的分片"当探针，那个地板是按本机标定的
            // （本机前导沿 0.004s），而 GitHub 的 Linux runner 上前导沿落在 **0.067~0.073s**
            // ⇒ 越过地板被当成慢路径的 flush ⇒ 连红两轮（先 B 档、再 C 档）✗。
            // **时间地板在那个环境下不可靠，内容可靠** ✓。
            let mut pairs: Vec<(f64, usize)> = resp
                .chunk_times
                .iter()
                .zip(resp.chunk_lens.iter())
                .map(|(t, len)| (t.duration_since(resp.start).as_secs_f64(), *len))
                .collect();
            pairs.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
            let times: Vec<f64> = pairs.iter().map(|(t, _)| *t).collect();
            assert!(!pairs.is_empty(), "{label}：一个分片都没有，测不到任何东西");

            // 静默期之前**第一片够大**的，就是慢路径那次批量 flush。
            // C 档整段只在流结束时发一次 ⇒ 这里应当是 NaN（下面按"没有批量 ⇒ 被扣到结束"判）。
            const BATCH_MIN_BYTES: usize = 100; // ≥2 个事件（单个 ~60 B）
            const SILENCE_END_S: f64 = 1.4; // 夹具静默 1.5s，留 0.1s 余量
            let flush_knob = pairs
                .iter()
                .find(|(t, len)| *t < SILENCE_END_S && *len >= BATCH_MIN_BYTES)
                .map(|(t, _)| *t)
                .unwrap_or(f64::NAN);
            println!(
                "  [慢路径开关] {label}：首字节 {:.3}s，静默前首个批量片 {flush_knob:.3}s\
                 （{} 片 / {:?} B / 共 {:.0} B）",
                times[0],
                pairs.len(),
                pairs.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
                expect.len() as f64
            );
            firsts.push((label, times[0], flush_knob));
        }

        let (a_first, a_flush) = (firsts[0].1, firsts[0].2);
        let b_flush = firsts[1].2;
        let c_flush = firsts[2].2;

        // A 档：慢路径必须**在时间阈值附近**把那一批交出来（探针＝"静默前首个批量片"，
        // 与快路径前导沿的到达时刻无关 ✓）。
        assert!(
            a_flush.is_finite() && a_flush <= 0.4,
            "A（时间阈值 100ms）：慢路径批量 flush 落在 {a_flush:.3}s（首字节 {a_first:.3}s）——\
             时间驱动没生效，稀疏事件会被无限期扣住"
        );
        // **判据是相对的，不是绝对窗口。** 第一版写 `(0.6..=1.2).contains(b)`：
        // 单独跑稳过、进 CI 就红——整套测试并行时调度抖动会把 900ms 那一拍推出窗口。
        // 而机制真正预言的只是"B 随开关成比例地晚于 A"，那就照机制写：
        // B 至少晚 A 三倍、且不晚于流结束；绝对时间只在 A 档留一条宽松上限。
        assert!(
            b_flush.is_finite() && b_flush >= a_flush.max(0.05) * 3.0 && b_flush <= 1.6,
            "B（时间阈值 900ms）：慢路径批量 flush 落在 {b_flush:.3}s，而 A 是 {a_flush:.3}s——\
             没有随开关成比例地推迟，`--slow-flush-ms` 没真正决定延迟上界\
             （定时分支很可能在无条件 flush）"
        );
        // C 档：时间阈值形同关闭、1KB 字节阈值在 ~500 B 的上游上攒不满 ⇒
        // **静默期之前根本不应当有批量片**（内容只能等到流结束才发）。
        // 判据按"探针为 NaN"写，而不是按分片数或绝对时刻（旧版断言"≥两片"就把调度偶然当判据了）。
        assert!(
            !c_flush.is_finite(),
            "C（时间阈值形同关闭、只留 1KB 字节阈值）：静默前出现了批量 flush（{c_flush:.3}s）——\
             说明时间阈值仍在生效，不能把早发归因于字节阈值"
        );
    })
    .await;
}

/// **慢路径到底省不省**：小响应与大响应各测一次，并与关掉慢路径对照。
///
/// # 为什么必须现在测
///
/// 慢路径在上一轮之前**从未被启用**（客户端没声明 `stream-zstd`），所以它的量化结论
/// 此前只有合成基准（`cargo run -p dev-tools -- baseline` 的 16.3% / 5.9%），**没有任何端到端数字**。
/// 它现在真的跑起来了，第一件该做的事就是量它。
///
/// # 判据
///
/// 用客户端状态里的 `resp_wire_bytes`（含帧头的实际下行字节）对比同一份内容在
/// 开/关慢路径下的差异：
///
/// * 大响应（200 个形态各异的事件，~20 KB）：慢路径**应当明显更省**——这是它存在的理由；
/// * 小响应（~500 B）：**这里不断言方向**，只记录实测。若实测更贵，那是一条真实结论：
///   进慢路径的判据只看"事件数够多、归纳不出模板"，**没有看量级**——
///   量级太小时它是在倒贴流量。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_path_savings_measured_end_to_end() {
    guard(async {
        let mut rows: Vec<(String, u64, u64)> = Vec::new();
        for mode in ["sse-novel", "sse-novel-big"] {
            for slow in [true, false] {
                let extra: Vec<String> = if slow {
                    vec![]
                } else {
                    vec!["--disable-slow-path".into()]
                };
                let st = setup_with(&extra, &[]).await.expect("启动失败");
                let resp = raw_request(
                    &st.client,
                    "POST",
                    "/v1/messages",
                    &[("content-type", "application/json"), ("x-test-mode", mode)],
                    br#"{"stream":true}"#,
                )
                .await
                .unwrap_or_else(|e| panic!("{mode} slow={slow} 请求失败：{e}"));
                assert_eq!(resp.status, 200);

                // 无论开关怎么设，内容都必须逐字节一致
                let expect = st.up.sse_bytes.lock().unwrap().clone();
                assert_bytes_eq(
                    &resp.body,
                    &expect,
                    &format!(
                        "{mode}（慢路径{}）：内容不许随开关变化",
                        if slow { "开" } else { "关" }
                    ),
                );

                let v = st.status().await.expect("取 status 失败");
                let wire = v["resp_wire_bytes"].as_u64().unwrap_or(0);
                // **基准用上游自己的字节数**，不是 `resp_raw_bytes`。
                //
                // 第一版用了后者，于是同一个上游在开/关两栏里"原文"不一样（302 vs 500）——
                // 因为它其实是**"原样项字节数"**（一个分项计数器：走慢路径的事件不再计入
                // 原样项）。拿分项计数当总量，两栏就不可比了。
                let upstream = expect.len() as u64;
                let ratio = if upstream > 0 {
                    wire as f64 / upstream as f64
                } else {
                    0.0
                };
                println!(
                    "  [慢路径收益] {mode:<15} 慢路径{}：上游 {upstream:>6} B → 链路 {wire:>6} B = {:.1}%",
                    if slow { "开" } else { "关" },
                    ratio * 100.0
                );
                rows.push((
                    format!("{mode} {}", if slow { "开" } else { "关" }),
                    upstream,
                    wire,
                ));
            }
        }

        let wire_of = |key: &str| {
            rows.iter()
                .find(|(k, _, _)| k == key)
                .map(|(_, _, w)| *w)
                .unwrap_or(0)
        };
        let big_on = wire_of("sse-novel-big 开");
        let big_off = wire_of("sse-novel-big 关");
        let small_on = wire_of("sse-novel 开");
        let small_off = wire_of("sse-novel 关");

        // 大响应：慢路径必须真的省——这是它存在的理由
        assert!(
            big_on < big_off,
            "大响应（~70 KB）开慢路径反而更大：{big_on} vs {big_off}——流式 zstd 没起作用"
        );
        // 而且必须**明显**更省（不是省一两个字节）
        assert!(
            big_on * 2 < big_off,
            "大响应上慢路径只省了一点：{big_on} vs {big_off}——\
             流式 zstd 应当把这种量级的响应压到很小的比例"
        );
        // 小响应：实测也是慢路径更省，但**省的是逐项帧头，不是内容压缩**——
        // 这点要写清楚，否则容易读成"500 B 的内容被压掉了一半"。
        assert!(
            small_on < small_off,
            "小响应（500 B）开慢路径反而更大：{small_on} vs {small_off}"
        );
        println!(
            "  [慢路径收益] 小结：大响应 {big_off}→{big_on} B（省 {:.0}%），\
             小响应 {small_off}→{small_on} B（省的是逐项帧头，不是内容）",
            (1.0 - big_on as f64 / big_off as f64) * 100.0
        );
    })
    .await;
}

/// **慢速但可模板化**的响应不得误进慢路径。
///
/// # 这是一个真实的判据边界
///
/// 进慢路径的条件是「原样项 ≥ `SLOW_TRIGGER`(6) 且归纳不出模板」，而慢路径一旦进入
/// 就**粘住整条响应**。于是有一格没人测过：上游**形态可模板化但发得很慢**
/// （`sse-slow`：12 个事件、间隔 200ms）。这时第 6 个事件在 ~1.2s 才到，
/// 而模板归纳正需要样本——如果归纳慢过计数阈值，一条**本来该走模板**的响应
/// 会被判进慢路径，白丢模板收益。
///
/// 既有测试 `templatable_sse_does_not_enter_slow_path` 用的是**快到**的 `sse`
/// （事件瞬间到齐），所以这一格是覆盖盲区。
///
/// # 判据
///
/// 用**模板定义数**当探针：模板路径必然产生 `template_defs ≥ 1`；
/// 慢路径不走模板归纳 ⇒ 恒为 0。比"比链路字节数"干净得多——
/// 两条路径的字节数都在很小的比例上，靠比值分不出来。
/// 反空转由第二条断言提供：不可模板化的流必须 `template_defs == 0`。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_templatable_stream_still_prefers_templates() {
    guard(async {
        check_template_defs("sse-slow", true).await;
        // 反空转：探针必须真的会动——不可模板化的流不该有模板定义
        check_template_defs("sse-novel-big", false).await;
    })
    .await;
}

/// **慢路径 × 各传输模式**：这是两条正交机制的交点，原先一个格子都没测。
///
/// 慢路径是**帧层**的编码（流式 zstd），传输是**帧怎么走**（WS / SSE 隧道 / L2 直连）。
/// 正交不等于可组合：SSE 隧道还要把帧再包一层 SSE 事件，L2 直连则**根本不走 DSHP**。
/// 所以三个格子各有各的断言：
///
/// | 传输 | 断言 |
/// |---|---|
/// | WS（默认） | 逐字节一致 + 慢路径生效（`template_defs == 0`） |
/// | SSE 隧道 | 同上——隧道多包了一层，最容易在这里出问题 |
/// | L2 直连 | 逐字节一致 + **`template_defs == 0` 是因为没走 DSHP**（对照，证明前两行的探针没看错东西） |
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_path_works_over_every_transport() {
    guard(async {
        for (label, resilient, extra) in [
            ("ws  ", false, Vec::<String>::new()),
            (
                "sse ",
                false,
                vec!["--force-mode".into(), "sse".into()],
            ),
            // L2 直连要**配了真实上游回退**才可能成立：`setup_with` 的客户端只有
            // DSHP 一条路，强制 l2 的结果是"整条链都不可用"⇒ 502（与租户测试踩到的同一件事）。
            // 所以这一格用 `setup_resilient`——它同时也就是"降级链真的能落到上游"的检查。
            ("l2  ", true, vec!["--force-mode".into(), "l2".into()]),
        ] {
            let st = if resilient {
                setup_resilient(&[], &extra).await.expect("启动失败")
            } else {
                setup_with(&[], &extra).await.expect("启动失败")
            };
            let resp = raw_request(
                &st.client,
                "POST",
                "/v1/messages",
                &[("content-type", "application/json"), ("x-test-mode", "sse-novel-big")],
                br#"{"stream":true}"#,
            )
            .await
            .unwrap_or_else(|e| panic!("{label} 传输请求失败：{e}"));
            assert_eq!(resp.status, 200);
            let expect = st.up.sse_bytes.lock().unwrap().clone();
            assert_bytes_eq(
                &resp.body,
                &expect,
                &format!("{label} 传输：不可模板化的流也必须逐字节一致"),
            );

            let v = st.status().await.expect("取 status 失败");
            let mode = v["mode"].as_str().unwrap_or("?").to_string();
            let defs = v["resp_frames"]["template_defs"].as_u64().unwrap_or(0);
            let wire = v["resp_wire_bytes"].as_u64().unwrap_or(0);
            println!(
                "  [慢路径 × 传输] {label} mode={mode:<7} 模板定义 {defs}，链路 {wire:>6} B（上游 {} B）",
                expect.len()
            );
            assert_eq!(
                defs, 0,
                "{label}：不可模板化的流不该有模板定义（这条对三种传输都成立）"
            );
            // WS / SSE 走 DSHP ⇒ 慢路径必须真的压了；
            // L2 直连**不经 DSHP** ⇒ 链路字节必须是 0（这正是对照的意义：
            // 前两行那个"压下来了"确实是 DSHP 干的，不是计数器看错了地方）
            if mode == "bypass" {
                assert_eq!(
                    wire, 0,
                    "{label}：L2 直连不经 DSHP，链路字节必须是 0（实际 {wire}）——\
                     否则说明这一格并没有真的绕开链路"
                );
            } else {
                assert!(
                    (wire as usize) * 2 < expect.len(),
                    "{label}（mode={mode}）：走了 DSHP 却没压下来——慢路径在 {mode} 上没生效\
                     （链路 {wire} B vs 上游 {} B）",
                    expect.len()
                );
            }
        }
    })
    .await;
}

async fn check_template_defs(mode: &str, expect_templates: bool) {
    let st = setup().await.expect("启动失败");
    let resp = raw_request(
        &st.client,
        "POST",
        "/v1/messages",
        &[("content-type", "application/json"), ("x-test-mode", mode)],
        br#"{"stream":true}"#,
    )
    .await
    .unwrap_or_else(|e| panic!("{mode} 请求失败：{e}"));
    assert_eq!(resp.status, 200);

    let expect = st.up.sse_bytes.lock().unwrap().clone();
    assert_bytes_eq(&resp.body, &expect, &format!("{mode} 必须逐字节一致"));

    let v = st.status().await.expect("取 status 失败");
    let defs = v["resp_frames"]["template_defs"].as_u64().unwrap_or(0);
    let wire = v["resp_wire_bytes"].as_u64().unwrap_or(0);
    println!(
        "  [慢路径判据] {mode:<15} 模板定义 {defs} 个，链路 {wire} B（上游 {} B）",
        expect.len()
    );
    if expect_templates {
        assert!(
            defs >= 1,
            "{mode} 的形态可模板化（只是发得慢），却被判进了慢路径——\
             归纳慢过计数阈值就会白丢模板收益。模板定义 {defs} 个：{v}"
        );
    } else {
        assert_eq!(
            defs, 0,
            "{mode} 不可模板化，却报告了 {defs} 个模板定义——探针失效，第一条断言就不可信了"
        );
    }
}
