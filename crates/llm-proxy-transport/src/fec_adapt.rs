//! 运行时质量降级：按**实测重传率**在 FEC 两档之间切换（设计 §10「拥塞期特化」）。
//!
//! # 判据：**相对基线**，不是绝对阈值
//!
//! §10 要求"拥塞期提高 FEC 冗余"，但"拥塞"没有可观测的定义。本地唯一能拿到的
//! 信号在 KCP 的发送计数里。我先试过**绝对阈值**，然后把它推翻了——实测：
//!
//! | 链路 | 全部重传率 | 只算超时重传 |
//! |---|---|---|
//! | 干净、无丢包（多个窗口） | 35% ~ 41% | 1.6% ~ 5.7% |
//! | 丢包 1/8（多个窗口） | 26% ~ 95% | 0% ~ 26% |
//!
//! 两个方向的失败都在里面：**干净链路的底噪就有 35%~41%**（KCP 的快速重传在
//! ACK 乱序时也会触发，它是"提前补救"而不是"链路在丢包"的证据），所以任何
//! 低于该量级的绝对阈值都会在好链路上误升档；而只算超时重传又会漏报——`resend=2`
//! 几乎总能把丢包提前补回来，轮不到 RTO 触发。
//!
//! **根因是"底噪是链路相关的"**：同一条线在不同机器/时段上的重传率底噪不同，
//! 所以绝对阈值必然顾此失彼。判据因此改成**与自己的底噪比**：
//!
//! * 维护最近 `baseline_windows` 个窗口的重传率，取其**最小值**作为底噪估计
//!   （取最小值而不是均值：均值会把"已经变差的那几窗"算进底噪，于是越坏越不触发）；
//! * **升档**：当前窗口 > `max(底噪 × escalate_factor, floor)`；
//! * **降档**：当前窗口 ≤ `max(底噪 × deescalate_factor, floor)`，且连续
//!   `deescalate_windows` 个窗口满足（单向确认，避免抖动）；
//! * `floor` 防止"底噪≈0 时把一点点噪声当成暴涨"。
//!
//! 这样**不需要为每条链路标定一个绝对数字**——它自己学。仍需在真实链路上确认
//! `escalate_factor` 的取值（K 越大越迟钝），但那是"调灵敏度"，不再是
//! "为某种链路找一个能用的常数"。
//!
//! # 为什么两端各自决定是安全的
//!
//! 换档**不做协商**——两端各自看自己的超时重传率。这是刻意的：协商要多一个往返，
//! 而"链路变差"两端本来就会各自观测到。前提是**档位不一致不会破坏正确性**：
//!
//! * 两档的 `data_shards` 都是 10 ⇒ **交付语义完全相同**；
//! * 差异只在校验分片个数。发送方多发时接收方按低档解，多出来的会因
//!   `index >= total` 被丢掉——**少一层保护，不是错内容**；
//! * 发送方少发时接收方按高档解，只会"补不动"，同样不猜。
//!
//! 也就是说：**档位不一致只会降低恢复能力，绝不影响正确性。**
//! 这条性质有专门的测试钉住（`asymmetric_configs_never_corrupt_delivery`）——
//! 没有它，无协商的自适应就是在赌。
//!
//! # 滞回
//!
//! 单阈值会让档位在边界上反复横跳，而每次换档都要丢弃当前半组、
//! 并把扣着的尾片按独立包发出（见 `FecEncoder::set_config`）——抖动是有代价的。
//! 所以升档与降档用**不同阈值**，并且要求一个窗口内样本足够。

use std::time::{Duration, Instant};

use crate::fec::FecConfig;
use crate::kcp::TxStats;

/// 换档策略。
///
/// 判据是**与自己的底噪比**，不是绝对阈值——理由见模块文档的实测表。
#[derive(Clone, Copy, Debug)]
pub struct FecAdaptPolicy {
    /// 统计窗口长度。
    pub window: Duration,
    /// 当前窗口超过「底噪 × 该倍数」时升档。
    ///
    /// 灵敏度旋钮：越大越迟钝。默认 3.0（重传率涨到平时的 3 倍才动手）。
    pub escalate_factor: f64,
    /// 当前窗口回落到「底噪 × 该倍数」以内时降档。
    ///
    /// **必须明显小于 `escalate_factor`**：这就是滞回。相等会抖动。
    pub deescalate_factor: f64,
    /// 底噪估计取最近多少个窗口的**最小值**。
    ///
    /// 取最小值而不是均值：均值会把"已经变差的那几窗"算进底噪，
    /// 于是链路越坏越不触发——那是自欺。
    pub baseline_windows: usize,
    /// 重传率的绝对下界，防止"底噪≈0 时把一点噪声当成暴涨"。
    pub floor: f64,
    /// 降档需要**连续**几个窗口都满足条件。
    ///
    /// 单向确认：升档要快（冗余不够会掉包），降档要慢（降早了要重传）。
    pub deescalate_windows: usize,
    /// 一个窗口内至少要有这么多样本才做判断。
    ///
    /// 没有它，一个只有 3 个段的窗口就能凭 1 次重传触发升档——那是噪声。
    pub min_samples: u64,
    /// **预热窗口数**：前这么多个窗口只量不判。
    ///
    /// 为什么需要：连接刚建立时 cwnd 从小到大爬，`fastresend` 会被大量触发。
    /// 拿它做决策会让每次连接刚建立就升一次档。
    pub warmup_windows: u64,
}

impl FecAdaptPolicy {
    /// 部署默认：60s 窗口；重传率涨到**底噪的 3 倍**升档、回落到 **1.2 倍**以内
    /// 且连续 3 窗满足才降档；底噪取最近 8 窗的最小值；绝对下界 0.5%。
    ///
    /// 这里**没有需要按链路标定的绝对阈值**——它自己学底噪。
    /// `escalate_factor` 是灵敏度旋钮，真实链路上可按需调（越大越迟钝）。
    pub const DEFAULT: Self = Self {
        window: Duration::from_secs(60),
        escalate_factor: 3.0,
        deescalate_factor: 1.2,
        baseline_windows: 8,
        floor: 0.005,
        deescalate_windows: 3,
        min_samples: 200,
        warmup_windows: 1,
    };
}
/// 低档（默认）与高档。
pub const LOW: FecConfig = FecConfig::R10_2;
pub const HIGH: FecConfig = FecConfig::R10_4;

/// 传输层要用的 FEC 设置：**档位** + 可选的自适应策略。
///
/// 把它做成一个结构体而不是"再加一个 bool 参数"，是为了让每个调用点都**显式**
/// 选择"固定档位"还是"按实测重传率自适应"——这两件事的运维含义完全不同。
#[derive(Clone, Copy, Debug)]
pub struct FecSettings {
    /// 起始档位。
    pub config: FecConfig,
    /// `None` = 固定档位，永不换档。
    pub adapt: Option<FecAdaptPolicy>,
}

impl FecSettings {
    /// 固定档位。
    pub fn fixed(config: FecConfig) -> Self {
        Self {
            config,
            adapt: None,
        }
    }

    /// 自适应：从 `config` 起步，按 `FecAdaptPolicy::DEFAULT` 换档。
    pub fn adaptive(config: FecConfig) -> Self {
        Self {
            config,
            adapt: Some(FecAdaptPolicy::DEFAULT),
        }
    }

    /// 自适应 + 自定义策略（测试用短窗口）。
    pub fn with_policy(config: FecConfig, policy: FecAdaptPolicy) -> Self {
        Self {
            config,
            adapt: Some(policy),
        }
    }
}

/// 逐窗口评估超时重传率并给出档位。
pub struct FecAdaptor {
    policy: FecAdaptPolicy,
    current: FecConfig,
    window_start: Instant,
    /// 窗口起点处的计数快照
    base: TxStats,
    /// 上一个窗口的**重传率**（判据）
    pub last_ratio: Option<f64>,
    /// 上一个窗口里**超时重传**占的比例（诊断：用来分辨"丢包"与"ACK 抖动"）
    pub last_rto_ratio: Option<f64>,
    pub escalations: u64,
    pub deescalations: u64,
    /// 采到的窗口数（观测用）
    pub windows: u64,
    /// 最近若干窗口的重传率（用于学底噪）。`VecDeque` 保持定长。
    history: std::collections::VecDeque<f64>,
    /// 连续满足降档条件的窗口数（单向确认，防抖）
    calm_windows: u64,
    /// **全程最干净**的重传率（单调不增，且不含预热窗）。
    ///
    /// 为什么需要第二个基线：降档不能用"近期底噪"判——链路持续变差时，
    /// 那批好窗口会被挤出近期历史，于是**坏状态自己成了新的"平静"**，
    /// 判据就会降档，随后重传率仍高又升档 ⇒ 来回横跳。
    /// 降档必须对着"这条连接历史上最干净的水平"比。
    long_floor: Option<f64>,
    /// 当前学到的近期底噪（观测用）
    pub baseline: Option<f64>,
    /// 当前学到的全程底噪（观测用）
    pub long_baseline: Option<f64>,
}

impl FecAdaptor {
    pub fn new(policy: FecAdaptPolicy, current: FecConfig, now: Instant) -> Self {
        Self {
            policy,
            current,
            window_start: now,
            base: TxStats::default(),
            last_ratio: None,
            last_rto_ratio: None,
            escalations: 0,
            deescalations: 0,
            windows: 0,
            history: std::collections::VecDeque::new(),
            calm_windows: 0,
            long_floor: None,
            baseline: None,
            long_baseline: None,
        }
    }

    pub fn current(&self) -> FecConfig {
        self.current
    }

    pub fn policy(&self) -> FecAdaptPolicy {
        self.policy
    }

    /// 喂一次累计计数。返回 `Some(新档位)` 表示**应当换档**。
    ///
    /// `tx` 是 KCP 的累计计数——本函数自己按窗口取差分，调用方不必维护窗口。
    /// 注意 `tx` 是 `&mut`：窗口翻页时基线要跟着推进（否则增量会被重复计算）。
    pub fn observe(&mut self, now: Instant, tx: TxStats) -> Option<FecConfig> {
        if now.duration_since(self.window_start) < self.policy.window {
            return None;
        }
        let d = tx.delta(&self.base);
        self.window_start = now;
        // 基线推进到**观测点**，不是"当前"——否则窗口之间的增量会被重复计算
        self.base = tx;
        self.windows += 1;
        if d.total() < self.policy.min_samples {
            // 样本不足：这一窗不判断，也不更新读数（免得把噪声记成"上次很好"）
            self.last_ratio = None;
            self.last_rto_ratio = None;
            return None;
        }
        // 判据 = 全部重传率（含快速重传）；`rto` 的占比单独记下作为诊断。
        // 只算超时那个版本在这台机器上两头都不成立，见模块文档的实测表。
        let ratio = d.retrans_ratio().unwrap_or(0.0);
        self.last_ratio = Some(ratio);
        self.last_rto_ratio = d.rto_ratio();
        if self.windows <= self.policy.warmup_windows {
            // 预热期：只量不判。
            //
            // 启动期 cwnd 从小到大爬，`fastresend` 会被大量触发——实测**无丢包的
            // 干净链路**首个窗口的全重传率高达 33%。拿它做决策，每次连接刚建立
            // 就会升一次档，纯浪费。
            return None;
        }

        // ---- 判据：与**自己的底噪**比 ----
        //
        // 底噪取最近 `baseline_windows` 窗的**最小值**（均值会把已经变差的窗
        // 算进底噪，于是越坏越不触发）。历史为空时先用当前窗起步。
        let baseline = self.history.iter().copied().fold(f64::INFINITY, f64::min);
        let baseline = if baseline.is_finite() {
            baseline
        } else {
            ratio
        };
        self.baseline = Some(baseline);
        let hi = (baseline * self.policy.escalate_factor).max(self.policy.floor);

        // 全程底噪：**单调不增**。一旦见过干净的水平，它在变差期间不会被污染，
        // 所以"降档"始终对着它比。（预热窗不参与——启动期 cwnd 爬升本身就有噪声。）
        let lf = match self.long_floor {
            Some(v) => v.min(ratio),
            None => ratio,
        };
        self.long_floor = Some(lf);
        self.long_baseline = Some(lf);
        let lo = (lf * self.policy.deescalate_factor).max(self.policy.floor);

        // 先入历史再决策？**后入**：当前窗不该参与判定自己的底噪，
        // 否则一次暴涨会立刻抬高底噪、把这次升档自己劝住。
        let want = if ratio > hi {
            self.calm_windows = 0;
            Some(HIGH)
        } else if ratio <= lo {
            // 降档要**连续**若干窗确认：升档要快（冗余不够会掉包），
            // 降档要慢（降早了立刻要重传）。
            self.calm_windows += 1;
            if self.calm_windows >= self.policy.deescalate_windows as u64 {
                self.calm_windows = 0;
                Some(LOW)
            } else {
                None
            }
        } else {
            // 滞回带内：保持现状，不抖
            self.calm_windows = 0;
            None
        };

        self.history.push_back(ratio);
        while self.history.len() > self.policy.baseline_windows.max(1) {
            self.history.pop_front();
        }

        let want = match want {
            Some(w) if w != self.current => w,
            _ => return None,
        };
        if want == HIGH {
            self.escalations += 1;
        } else {
            self.deescalations += 1;
        }
        self.current = want;
        Some(want)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pol() -> FecAdaptPolicy {
        FecAdaptPolicy {
            window: Duration::from_millis(100),
            escalate_factor: 3.0,
            deescalate_factor: 1.2,
            baseline_windows: 4,
            floor: 0.005,
            deescalate_windows: 3,
            min_samples: 100,
            warmup_windows: 0,
        }
    }

    /// 累计计数喂食器。
    ///
    /// **必须喂累计值**：`TxStats` 存的是累计计数，`delta()` 做的是饱和减法。
    /// 第一版我按"每窗独立"造绝对计数，于是重传数变化时累计值**变小**、
    /// 饱和减到 0，第二窗的重传率被算成 100% 并触发了升档——
    /// **测出来的"缺陷"其实是我的喂法违约**。累加器把这件事显式钉住。
    struct Feeder {
        first: u64,
        rto: u64,
        fast: u64,
    }

    impl Feeder {
        fn new() -> Self {
            Self {
                first: 0,
                rto: 0,
                fast: 0,
            }
        }

        /// 追加一个窗口：共发 `samples` 个段，其中 `ratio` 比例是快速重传。
        fn window(&mut self, samples: u64, ratio: f64) -> TxStats {
            let r = (samples as f64 * ratio).round() as u64;
            self.first += samples - r;
            self.fast += r;
            TxStats {
                first: self.first,
                rto: self.rto,
                fast: self.fast,
            }
        }
    }

    /// 推进一个窗口（累计喂食）并返回决策。
    fn step(
        a: &mut FecAdaptor,
        f: &mut Feeder,
        t0: Instant,
        n: u64,
        samples: u64,
        ratio: f64,
    ) -> Option<FecConfig> {
        let tx = f.window(samples, ratio);
        a.observe(t0 + Duration::from_millis(100 * n), tx)
    }

    #[test]
    fn no_decision_before_the_window_elapses() {
        let t0 = Instant::now();
        let mut a = FecAdaptor::new(pol(), LOW, t0);
        assert_eq!(
            a.observe(
                t0 + Duration::from_millis(10),
                TxStats {
                    first: 500,
                    rto: 0,
                    fast: 500
                }
            ),
            None,
            "窗口没到就不该判断"
        );
        assert_eq!(a.current(), LOW);
    }

    /// **干净但噪声很大的链路不得升档。**
    ///
    /// 这是绝对阈值版本栽掉的那个场景：干净链路的重传率底噪本就有 30%~40%
    /// （KCP 的快速重传在 ACK 乱序时也会触发），任何比它低的绝对阈值都会
    /// 在好链路上误升档、白花 20% 冗余。相对判据学自己的底噪，因此不受影响。
    #[test]
    fn clean_noisy_link_never_escalates() {
        let t0 = Instant::now();
        let mut a = FecAdaptor::new(pol(), LOW, t0);
        let mut f = Feeder::new();
        // 底噪 ~0.30，围绕它抖动 ±0.1
        for (i, r) in [0.30, 0.41, 0.28, 0.36, 0.33, 0.39, 0.31, 0.44, 0.29, 0.35]
            .iter()
            .enumerate()
        {
            assert_eq!(
                step(&mut a, &mut f, t0, i as u64 + 1, 1000, *r),
                None,
                "干净链路第 {i} 窗（重传率 {r}）不该换档"
            );
        }
        assert_eq!(a.escalations, 0, "干净链路上一次都不许升档");
        assert_eq!(a.current(), LOW);
        assert!(a.baseline.unwrap() <= 0.30, "底噪应当学到 0.30 附近");
    }

    /// 底噪之上的一次暴涨必须升档。
    #[test]
    fn a_surge_above_the_learned_baseline_escalates() {
        let t0 = Instant::now();
        let mut a = FecAdaptor::new(pol(), LOW, t0);
        let mut f = Feeder::new();
        for i in 0..4 {
            step(&mut a, &mut f, t0, i + 1, 1000, 0.10);
        }
        assert_eq!(a.escalations, 0, "底噪学习期不该换档");
        let got = step(&mut a, &mut f, t0, 5, 1000, 0.50);
        assert_eq!(got, Some(HIGH), "5 倍于底噪的暴涨必须升档");
        assert_eq!(a.escalations, 1);
    }

    /// **持续高重传率不得来回横跳。**
    ///
    /// 每次换档都要丢弃当前半组、把扣着的尾片按独立包重发，抖动是有代价的。
    #[test]
    fn sustained_high_does_not_oscillate() {
        let t0 = Instant::now();
        let mut a = FecAdaptor::new(pol(), LOW, t0);
        let mut f = Feeder::new();
        for i in 0..4 {
            step(&mut a, &mut f, t0, i + 1, 1000, 0.10);
        }
        assert_eq!(step(&mut a, &mut f, t0, 5, 1000, 0.50), Some(HIGH));
        for i in 6..20 {
            assert_eq!(
                step(&mut a, &mut f, t0, i, 1000, 0.50),
                None,
                "已经高档、且仍然高重传 —— 不该再换（第 {i} 窗）"
            );
        }
        assert_eq!(a.escalations, 1);
        assert_eq!(a.deescalations, 0);
        assert_eq!(a.current(), HIGH);
    }

    /// 降档要**连续**若干窗确认——单向确认，防抖。
    #[test]
    fn recovery_needs_consecutive_calm_windows() {
        let t0 = Instant::now();
        let mut a = FecAdaptor::new(pol(), LOW, t0);
        let mut f = Feeder::new();
        for i in 0..4 {
            step(&mut a, &mut f, t0, i + 1, 1000, 0.10);
        }
        assert_eq!(step(&mut a, &mut f, t0, 5, 1000, 0.50), Some(HIGH));
        // 第 1、2 个平静窗只计数，不降档；第 3 个才降。
        assert_eq!(step(&mut a, &mut f, t0, 6, 1000, 0.02), None, "第 1 窗不降");
        assert_eq!(step(&mut a, &mut f, t0, 7, 1000, 0.02), None, "第 2 窗不降");
        assert_eq!(
            step(&mut a, &mut f, t0, 8, 1000, 0.02),
            Some(LOW),
            "连续第 3 窗才降档"
        );
        assert_eq!(a.deescalations, 1);
    }

    /// 样本不足不许判断：3 个段里 1 次重传是 33%，但那是噪声。
    #[test]
    fn tiny_windows_are_ignored() {
        let t0 = Instant::now();
        let mut a = FecAdaptor::new(pol(), LOW, t0);
        assert_eq!(
            a.observe(
                t0 + Duration::from_millis(100),
                TxStats {
                    first: 2,
                    rto: 1,
                    fast: 0
                }
            ),
            None
        );
        assert_eq!(a.current(), LOW, "样本不足时不得凭噪声升档");
        assert!(a.last_ratio.is_none(), "样本不足时读数也不该更新");
        assert_eq!(a.windows, 1, "窗口仍应被计为一次（便于观测）");
    }

    /// 窗口之间不重复计算增量。
    #[test]
    fn windows_use_deltas_not_totals() {
        let t0 = Instant::now();
        let mut a = FecAdaptor::new(pol(), LOW, t0);
        let mut f = Feeder::new();
        step(&mut a, &mut f, t0, 1, 1000, 0.10);
        // 第二窗累计只涨了 1000 个首发、0 次重传 ⇒ 该窗重传率是 0%，
        // 而不是累计的 100/2000 = 5%
        assert_eq!(step(&mut a, &mut f, t0, 2, 1000, 0.0), None);
        assert_eq!(a.last_ratio, Some(0.0), "第二窗应当是 0% 重传");
        assert_eq!(f.fast, 100, "累计重传次数只涨了第一窗那一批");
    }

    /// 预热期只量不判。
    #[test]
    fn warmup_windows_only_measure() {
        let t0 = Instant::now();
        let mut p = pol();
        p.warmup_windows = 2;
        let mut a = FecAdaptor::new(p, LOW, t0);
        let mut f = Feeder::new();
        assert_eq!(
            step(&mut a, &mut f, t0, 1, 1000, 0.60),
            None,
            "预热窗 1 不判"
        );
        assert_eq!(
            step(&mut a, &mut f, t0, 2, 1000, 0.60),
            None,
            "预热窗 2 不判"
        );
        assert_eq!(a.escalations, 0);
        // 第 3 窗仍在 0.6：底噪已经被预热期拉到 0.6，3× = 1.8 ⇒ 不升档。
        // 这正是"预热期参与学底噪"的预期效果：启动期的噪声成了底噪的一部分。
        assert_eq!(step(&mut a, &mut f, t0, 3, 1000, 0.60), None);
    }

    /// **两类重传必须分开上报**，否则判据无法解释。
    #[test]
    fn rto_and_fast_retransmission_are_reported_separately() {
        let tx = TxStats {
            first: 1000,
            rto: 0,
            fast: 500,
        };
        let all = tx.retrans_ratio().unwrap();
        let rto = tx.rto_ratio().unwrap();
        assert!(all > 0.3, "构造的样本应当有 30%+ 的重传率");
        assert_eq!(rto, 0.0, "这批样本里没有超时重传");
        assert!(rto < all, "超时重传率必然是全部重传率的子集");

        let mixed = TxStats {
            first: 1000,
            rto: 100,
            fast: 100,
        };
        assert!(mixed.rto_ratio().unwrap() < mixed.retrans_ratio().unwrap());
        assert_eq!(mixed.retrans(), 200);
        assert_eq!(mixed.total(), 1200);

        let t0 = Instant::now();
        let mut a = FecAdaptor::new(pol(), LOW, t0);
        a.observe(t0 + Duration::from_millis(100), tx);
        assert_eq!(a.last_ratio, Some(all), "判据 = 全部重传率");
        assert_eq!(a.last_rto_ratio, Some(0.0), "诊断 = 超时重传占比");
    }

    /// 部署默认值要自洽：滞回带必须够宽，且没有"按链路标定的绝对阈值"。
    #[test]
    fn default_policy_is_self_consistent() {
        let d = FecAdaptPolicy::DEFAULT;
        assert!(
            d.escalate_factor > d.deescalate_factor,
            "升档倍数必须大于降档倍数，否则一直抖"
        );
        assert!(
            d.escalate_factor / d.deescalate_factor >= 2.0,
            "滞回带太窄，会在边界附近反复横跳"
        );
        assert!(d.baseline_windows >= 2, "底噪至少要看到两个窗口");
        assert!(d.deescalate_windows >= 2, "降档必须要有连续确认");
        let (lo, hi) = (LOW, HIGH);
        assert_eq!(lo.data_shards, hi.data_shards, "两档的数据分片数必须相同");
        assert!(hi.parity_shards > lo.parity_shards);
    }

    /// **换档不做协商的安全前提**：两端档位不一致时，正确性必须不受影响。
    ///
    /// 这是整个"各自决定"设计的赌注所在：发送方用高档、接收方用低档
    /// （以及反过来）时，交付内容必须仍然逐字节正确。
    /// 若这条不成立，无协商自适应就会变成**静默错误内容**。
    #[test]
    fn asymmetric_configs_never_corrupt_delivery() {
        use crate::fec::{FecDecoder, FecEncoder};
        const SHARD: usize = 256;
        const N: usize = 10;
        let payload_of = |i: usize| vec![(i as u8).wrapping_mul(11); 40 + i * 9];
        let expect: Vec<Vec<u8>> = (0..N).map(payload_of).collect();

        for (enc_cfg, dec_cfg, label) in [
            (HIGH, LOW, "发送高档 / 接收低档"),
            (LOW, HIGH, "发送低档 / 接收高档"),
        ] {
            let mut enc = FecEncoder::new(enc_cfg, SHARD);
            let mut dec = FecDecoder::new(dec_cfg);
            let mut packets = Vec::new();
            for i in 0..N {
                packets.extend(enc.push(&payload_of(i)).expect("容量内"));
            }
            let kept: Vec<Vec<u8>> = packets
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != 1 && *i != 3)
                .map(|(_, p)| p.clone())
                .collect();
            let mut got = Vec::new();
            for p in &kept {
                got.extend(dec.push(p).unwrap_or_else(|e| panic!("{label}：{e}")));
            }
            assert_eq!(
                got, expect,
                "{label}：档位不一致时仍必须逐字节正确——\
                 这正是「两端各自换档、不做协商」能成立的前提"
            );
        }
    }
}
