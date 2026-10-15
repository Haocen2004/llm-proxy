//! KCP：UDP 之上的 ARQ（设计 §10 / §13.6）。
//!
//! # 为什么需要它
//!
//! 跨境 / 弱网下 TCP 的表现很差：一次丢包会让整个窗口停顿一个 RTO，而 RTO 是以
//! RTT 为基准估出来的——200ms RTT 下就是几百毫秒的"什么都不发"。KCP 用**更激进的重传**
//! 换取吞吐：`nodelay=1, resend=2, nc=1` 允许丢包后立刻重传、不理会拥塞窗口。
//!
//! 代价是浪费带宽。设计 §10 的取舍是：只在弱网用它，带宽充裕时走 WS。
//!
//! # 实现上的定位
//!
//! 这是**协议核心**，不做 IO：`update` 由调用方按时间驱动，要发的包由 `flush` 收进一个
//! 列表，收到的包由 `input` 喂进来。这样它可以在没有真实网络的测试里被精确验证——
//! 丢包、乱序、延迟都能按事件顺序复现，而不是"跑一遍看看"。
//!
//! 参数取自设计 §10 的**低内存档**：`mtu=1200, sndwnd=128, rcvwnd=128`。
//! 低内存档不是随便写的：每连接的内存大致是 `(sndwnd + rcvwnd) × mss`，
//! 128×1200×2 ≈ 300KB，乘以并发流上限 4 就是 1.2MB——这在 §12 的 32MB 预算里必须算得清。

use std::collections::VecDeque;

// ---- 协议常量（与 KCP 参考实现一致，改动会破坏互通）----

/// 段头长度：conv(4) + cmd(1) + frg(1) + wnd(2) + ts(4) + sn(4) + una(4) + len(4)
pub const OVERHEAD: usize = 24;

/// 发送侧的段计数（观测 + 质量降级的唯一输入）。
///
/// **两类重传必须分开看**：
/// * `rto` —— 超时重传，是"包真的丢了"的直接证据；
/// * `fast` —— 快速重传，KCP 在收到后续 ACK 后**提前**补发，ACK 乱序或滞后时
///   同样会触发。实测**无丢包的干净链路**上两者合计能到 33%，几乎全是 `fast`。
///
/// 把两者混成一个数当丢包率用，会让 FEC 在好链路上白白升档（多花 20% 带宽）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxStats {
    pub first: u64,
    pub rto: u64,
    pub fast: u64,
}

impl TxStats {
    /// 全部重传段数。
    pub fn retrans(&self) -> u64 {
        self.rto + self.fast
    }

    /// 段总数（首发 + 全部重传）。
    pub fn total(&self) -> u64 {
        self.first + self.retrans()
    }

    /// 重传率（含快速重传）。**不要单独拿它判断链路质量**，见类型注释。
    pub fn retrans_ratio(&self) -> Option<f64> {
        let t = self.total();
        if t == 0 {
            return None;
        }
        Some(self.retrans() as f64 / t as f64)
    }

    /// 超时重传率——**这才是「链路在丢包」的判据**。
    pub fn rto_ratio(&self) -> Option<f64> {
        let t = self.total();
        if t == 0 {
            return None;
        }
        Some(self.rto as f64 / t as f64)
    }

    pub fn delta(&self, base: &TxStats) -> TxStats {
        TxStats {
            first: self.first.saturating_sub(base.first),
            rto: self.rto.saturating_sub(base.rto),
            fast: self.fast.saturating_sub(base.fast),
        }
    }
}

pub const CMD_PUSH: u8 = 81;
pub const CMD_ACK: u8 = 82;
pub const CMD_WASK: u8 = 83;
pub const CMD_WINS: u8 = 84;

pub const RTO_NDL: u32 = 30;
pub const RTO_MIN: u32 = 100;
pub const RTO_DEF: u32 = 200;
pub const RTO_MAX: u32 = 60_000;

/// 从**已编码**的段里读出命令字。
///
/// 传输适配层需要它来区分数据段与控制段：控制段（ACK/WASK/WINS）很小，
/// 送进 FEC 会被"等长补齐"放大几十倍（见 `kcp_link::FEC_MIN_PROTECT`），
/// 所以必须能在**不解析整段**的前提下把它们挑出来。
pub fn segment_cmd(seg: &[u8]) -> Option<u8> {
    seg.get(4).copied()
}

pub const ASK_SEND: u32 = 5000;
pub const ASK_TELL: u32 = 5;

/// 连续重传多少次没有 ACK 就认定连接已死。
const DEAD_LINK: u32 = 20;

/// 对端把自己的窗口通告为 0 时，我们这边最多能积压多少字节。
///
/// 没有这个上限，一个不断发数据但从不读的对端会让发送队列无限增长——
/// 这正是 §13.10 要防的 DoS。
const MAX_PENDING_BYTES: usize = 8 << 20;

/// 一个待发/待确认的段。
#[derive(Clone, Debug)]
pub struct Segment {
    pub cmd: u8,
    pub frg: u8,
    pub wnd: u16,
    pub ts: u32,
    pub sn: u32,
    pub una: u32,
    pub data: Vec<u8>,
    // 发送侧状态
    pub resendts: u32,
    pub rto: u32,
    pub fastack: u32,
    pub xmit: u32,
}

impl Segment {
    fn new(cmd: u8, sn: u32, data: Vec<u8>) -> Self {
        Self {
            cmd,
            frg: 0,
            wnd: 0,
            ts: 0,
            sn,
            una: 0,
            data,
            resendts: 0,
            rto: 0,
            fastack: 0,
            xmit: 0,
        }
    }

    /// 编码为线格式。
    pub fn encode(&self, conv: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(OVERHEAD + self.data.len());
        out.extend_from_slice(&conv.to_le_bytes());
        out.push(self.cmd);
        out.push(self.frg);
        out.extend_from_slice(&self.wnd.to_le_bytes());
        out.extend_from_slice(&self.ts.to_le_bytes());
        out.extend_from_slice(&self.sn.to_le_bytes());
        out.extend_from_slice(&self.una.to_le_bytes());
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }
}

/// KCP 参数。默认值即设计 §10 的**低内存档**。
#[derive(Clone, Copy, Debug)]
pub struct KcpConfig {
    /// 1 = 启用 nodelay（不按 RTO 最小值等待）
    pub nodelay: i32,
    /// 内部 update 间隔（ms）。10ms 是低内存档的取值。
    pub interval: u32,
    /// 跳多少个 ACK 就快速重传。2 表示丢两个包就重传，比 TCP 的 3 更激进。
    pub fastresend: i32,
    /// 1 = 关闭拥塞控制（弱网下宁可浪费带宽也要把延迟压下来）
    pub nocwnd: i32,
    pub snd_wnd: u32,
    pub rcv_wnd: u32,
}

impl Default for KcpConfig {
    fn default() -> Self {
        Self {
            nodelay: 1,
            interval: 10,
            fastresend: 2,
            nocwnd: 1,
            snd_wnd: 128,
            rcv_wnd: 128,
        }
    }
}

/// KCP 会话。
pub struct Kcp {
    conv: u32,
    cfg: KcpConfig,
    mss: usize,

    snd_una: u32,
    snd_nxt: u32,
    rcv_nxt: u32,
    ts_recent: u32,

    ssthresh: u32,
    rx_rttval: i32,
    rx_srtt: i32,
    rx_rto: i32,
    rmt_wnd: u32,
    cwnd: u32,
    probe: u32,

    current: u32,
    ts_flush: u32,
    updated: bool,

    snd_queue: VecDeque<Segment>,
    snd_buf: VecDeque<Segment>,
    /// 已按 sn 排好、但还不连续的段
    rcv_buf: VecDeque<Segment>,
    /// 可交付、连续的段
    rcv_queue: VecDeque<Segment>,

    /// (sn, ts) 待发送的 ACK
    acklist: VecDeque<(u32, u32)>,
    /// 需要立刻发出的控制段（窗口应答）。与 acklist 分开，
    /// 因为它们自带完整段头、不能只靠 (sn, ts) 重建。
    pending_ctrl: VecDeque<Segment>,

    /// 已下发但尚未被 `input` 确认的总字节数，用于内存上限。
    pending_bytes: usize,
    /// 发送队列因超限被丢弃的字节数（观测用）
    dropped_bytes: u64,
    /// 首次发出的数据段数（观测用）。
    ///
    /// 与 `tx_retrans` 一起给出**实测重传率**——运行时质量降级（设计 §10）
    /// 必须建立在这个数字上：链路"还活着但变差"时，唯一诚实的判据就是
    /// "有多少段需要重传"，而不是任何本地推测。
    tx_first: u64,
    /// **RTO 超时**导致的重传段数（观测用）。
    tx_rto_retrans: u64,
    /// **快速重传**（`fastack` 累积触发）的段数（观测用）。
    ///
    /// 与 RTO 分开记是必要的：快速重传在**没有丢包**时也会因为 ACK 乱序/滞后而触发，
    /// 它是 KCP 的"提前补救"，不是"链路在丢包"的证据。实测无丢包的干净链路上
    /// 两者合计能到 33%，其中绝大多数来自快速重传——把两者混成一个数当丢包率用，
    /// 会让 FEC 在好链路上白白升档（多花 20% 带宽）。
    tx_fast_retrans: u64,
}

impl std::fmt::Debug for Kcp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kcp")
            .field("snd_una", &self.snd_una)
            .field("snd_nxt", &self.snd_nxt)
            .field("rcv_nxt", &self.rcv_nxt)
            .field("snd_queue", &self.snd_queue.len())
            .field("snd_buf", &self.snd_buf.len())
            .field("rcv_queue", &self.rcv_queue.len())
            .finish()
    }
}

impl Kcp {
    pub fn new(conv: u32, cfg: KcpConfig, mtu: usize) -> Self {
        let mtu = mtu.max(OVERHEAD + 1);
        Self {
            conv,
            cfg,
            mss: mtu - OVERHEAD,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            ts_recent: 0,
            ssthresh: 2,
            rx_rttval: 0,
            rx_srtt: 0,
            rx_rto: RTO_DEF as i32,
            rmt_wnd: cfg.rcv_wnd,
            cwnd: 0,
            probe: 0,
            current: 0,
            ts_flush: cfg.interval,
            updated: false,
            snd_queue: VecDeque::new(),
            snd_buf: VecDeque::new(),
            rcv_buf: VecDeque::new(),
            rcv_queue: VecDeque::new(),
            acklist: VecDeque::new(),
            pending_ctrl: VecDeque::new(),
            pending_bytes: 0,
            dropped_bytes: 0,
            tx_first: 0,
            tx_rto_retrans: 0,
            tx_fast_retrans: 0,
        }
    }

    pub fn conv(&self) -> u32 {
        self.conv
    }

    pub fn mss(&self) -> usize {
        self.mss
    }

    /// 待发送的字节数（含尚未确认的）。上层的背压依据。
    pub fn wait_snd(&self) -> usize {
        let q: usize = self.snd_queue.iter().map(|s| s.data.len()).sum();
        let b: usize = self
            .snd_buf
            .iter()
            .filter(|s| !s.data.is_empty())
            .map(|s| s.data.len())
            .sum();
        q + b
    }

    pub fn dropped_bytes(&self) -> u64 {
        self.dropped_bytes
    }

    /// `(首次发出的段数, 重传的段数)`。
    ///
    /// 重传率 = `retrans / (first + retrans)`。**这是运行时质量降级唯一诚实的输入**：
    /// 链路变差时本地能观测到的只有"有多少段需要重传"，其余都得靠猜。
    pub fn tx_stats(&self) -> TxStats {
        TxStats {
            first: self.tx_first,
            rto: self.tx_rto_retrans,
            fast: self.tx_fast_retrans,
        }
    }

    /// 把 `data` 切成段送进发送队列。
    ///
    /// 返回实际接收的字节数；中队满时可能少于 `data.len()`（0 表示完全没收）。
    pub fn send(&mut self, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }
        // `frg` 只有 8 位，所以**单组**最多 255 片。超过就分组发送——
        // 真实 KCP 要求调用方自己切分，但"超长就静默返回 0"是个陷阱：
        // 调用方会以为发出去了，实际一个字节都没入队（实测就踩到了这个坑）。
        // 对上层而言这是字节流，分成多个"帧"完全无所谓。
        let group = 255 * self.mss;
        let mut total = 0usize;
        for chunk in data.chunks(group) {
            let n = self.send_group(chunk);
            total += n;
            if n < chunk.len() {
                break; // 队列已满，剩下的交给上层的背压
            }
        }
        total
    }

    /// 发送一组（≤255 片）。
    fn send_group(&mut self, data: &[u8]) -> usize {
        let count = data.len().div_ceil(self.mss);
        if count == 0 || count > 255 {
            return 0;
        }
        // 内存上限：队列里积压太多就拒收，让上层背压。
        // **不能无限收**——一个只发不读的对端会让内存涨到耗尽。
        if self.pending_bytes + data.len() > MAX_PENDING_BYTES {
            self.dropped_bytes += data.len() as u64;
            return 0;
        }
        let mut accepted = 0usize;
        for i in 0..count {
            let off = i * self.mss;
            let end = (off + self.mss).min(data.len());
            let mut seg = Segment::new(CMD_PUSH, 0, data[off..end].to_vec());
            seg.frg = (count - i - 1) as u8;
            self.snd_queue.push_back(seg);
            accepted += end - off;
        }
        self.pending_bytes += accepted;
        accepted
    }

    /// 取出一段**完整**的数据。
    ///
    /// # 必须找到帧尾才能交付
    ///
    /// 早先的写法是"从头一直拼到 `frg == 0` 为止"。看起来对，但队列里**还没有帧尾**时
    /// （后半段还在路上），它会把整队拼出来当成一个完整帧返回——
    /// 上层于是收到**半个消息**，并把它当成帧头去解析。实测的表现是服务端报
    /// `BadMagic([104, 102])`，也就是"收到了帧头不对的东西"。
    ///
    /// 正确做法是**先确认帧尾存在**再消费：`rcv_queue` 里片段是连续的，
    /// 第一个 `frg == 0` 就是帧尾。找不到就原样留在队列里，等后面的片段到齐。
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        let end = self.rcv_queue.iter().position(|s| s.frg == 0)?;
        let mut out = Vec::new();
        for _ in 0..=end {
            let seg = self.rcv_queue.pop_front().expect("位置刚查到");
            out.extend_from_slice(&seg.data);
        }
        Some(out)
    }

    /// 时间驱动。`current` 是单调毫秒。
    pub fn update(&mut self, current: u32, out: &mut Vec<Vec<u8>>) {
        self.current = current;
        if !self.updated {
            self.updated = true;
            self.ts_flush = current;
        }
        let mut slap = current.wrapping_sub(self.ts_flush) as i32;
        if !(-10000..10000).contains(&slap) {
            // 时钟跳变（重启 / 休眠）：不能按负差去算，直接对齐
            self.ts_flush = current;
            slap = 0;
        }
        if slap >= 0 {
            self.ts_flush = current.wrapping_add(self.cfg.interval);
            self.flush(out);
        }
        self.flush_acks(out);
    }

    /// 把拥塞窗口允许的段发出去。
    fn flush(&mut self, out: &mut Vec<Vec<u8>>) {
        // 对端窗口为 0 时定期探测。
        //
        // **必须用 `WASK` 控制段，绝不能用"空载荷的 PUSH 段"**——后者会被对端
        // 当成一个**数据段**收下、消耗掉一个 sn，于是整条字节流从那里开始错位。
        // 这个错误只在**在途段数超过窗口**（触发探测）时才显形，
        // 所以 20KB 以下的小传输全都正常，问题藏了很久。
        if self.rmt_wnd == 0 {
            if self.probe == 0 {
                self.probe = ASK_SEND;
            }
            self.probe = self.probe.saturating_sub(1);
            if self.probe == 0 {
                out.push(Segment::new(CMD_WASK, 0, Vec::new()).encode(self.conv));
            }
        } else {
            self.probe = 0;
        }

        // 计算本次能发多少
        let cwnd = if self.cfg.nocwnd == 0 {
            let mss = self.mss as u32;
            let mut w = self.cfg.snd_wnd.min(self.rmt_wnd);
            if self.cwnd < self.rmt_wnd {
                let m = (self.cwnd / 2).max(1);
                w = w.min(m.max(self.cwnd.saturating_add(mss)));
            }
            w
        } else {
            self.cfg.snd_wnd
        };
        let cwnd = if cwnd == 0 { 1 } else { cwnd };

        // 从 snd_queue 搬到 snd_buf，直到 snd_buf 填满
        let snd_buf_len = self.snd_buf.len() as u32;
        let mut new_segs = 0u32;
        while snd_buf_len + new_segs < cwnd {
            match self.snd_queue.pop_front() {
                Some(mut seg) => {
                    seg.sn = self.snd_nxt;
                    seg.ts = self.current;
                    self.snd_nxt = self.snd_nxt.wrapping_add(1);
                    self.snd_buf.push_back(seg);
                    new_segs += 1;
                }
                None => break,
            }
        }

        let current = self.current;
        // 同 `flush_acks`：`una` 说的是对端的发送序，必须是 `rcv_nxt`
        let una = self.rcv_nxt;
        let fastresend = self.cfg.fastresend;
        // 在借 snd_buf 之前算好，否则会与 `&mut self.snd_buf[i]` 冲突
        let wnd_unused = self.compute_wnd_unused() as u16;
        let nodelay = self.cfg.nodelay;
        let rx_rto = self.rx_rto.max(0) as u32;
        let minrto = if nodelay == 0 { RTO_MIN } else { RTO_NDL };

        // 计数先落在局部变量里：循环体里正借着 `self.snd_buf` 的可变借用，
        // 直接写 `self.tx_first` 会冲突。
        let mut n_first = 0u64;
        let mut n_rto = 0u64;
        let mut n_fast = 0u64;
        for i in 0..self.snd_buf.len() {
            let mut need_send = false;
            {
                let seg = &mut self.snd_buf[i];
                if seg.xmit == 0 {
                    need_send = true;
                    seg.xmit = 1;
                    seg.rto = rx_rto;
                    seg.resendts = current.wrapping_add(seg.rto);
                    n_first += 1;
                } else if (current.wrapping_sub(seg.resendts) as i32) >= 0 {
                    need_send = true;
                    seg.xmit += 1;
                    n_rto += 1;
                    if nodelay == 0 {
                        let step = (rx_rto as f32 * 1.5).max(minrto as f32) as u32;
                        seg.rto = seg.rto.saturating_add(step);
                    } else {
                        let step =
                            (rx_rto as f32 * (seg.xmit as f32 + 1.0)).max(minrto as f32) as u32;
                        seg.rto = seg.rto.saturating_add(step);
                    }
                    seg.resendts = current.wrapping_add(seg.rto);
                } else if seg.fastack >= fastresend as u32 && fastresend > 0 {
                    need_send = true;
                    seg.xmit += 1;
                    n_fast += 1;
                    seg.fastack = 0;
                    seg.resendts = current.wrapping_add(seg.rto);
                }
                if seg.xmit > DEAD_LINK {
                    // 连续重传太多次：认定连接已死。
                    // 不能无限重传——那会让一个断掉的链路永远占着内存与带宽。
                    self.dropped_bytes += seg.data.len() as u64;
                    continue;
                }
            }
            if !need_send {
                continue;
            }
            let mut seg = self.snd_buf[i].clone();
            seg.una = una;
            seg.wnd = wnd_unused;
            out.push(seg.encode(self.conv));
        }
        self.tx_first += n_first;
        self.tx_rto_retrans += n_rto;
        self.tx_fast_retrans += n_fast;
    }

    fn compute_wnd_unused(&self) -> u32 {
        // 本端还能接收多少（通知对端）
        let bufsize = self.cfg.rcv_wnd as usize;
        let used = self.rcv_buf.len() + self.rcv_queue.len();
        bufsize.saturating_sub(used) as u32
    }

    /// 把待发 ACK 收进 `out`。
    fn flush_acks(&mut self, out: &mut Vec<Vec<u8>>) {
        // **`una` 是 `rcv_nxt`，不是 `snd_una`。**
        //
        // 它表达的是"我已经收到你 sn < una 的全部段"——说的是**对端的发送序**。
        // 我原来发的是本方的 `snd_una`（本方自己的发送序），两者完全是两码事。
        // 后果：正向传完一批后 `snd_una` 涨到 N，这个过期的 una 传到对端，
        // 对端的 `parse_una(N)` 会把**它自己刚入队、还没发出去的段**整片丢掉。
        // 实测就是反向大帧永远收不到，而发送侧还显示 `wait_snd=0`（以为发完了）。
        let una = self.rcv_nxt;
        while let Some(seg) = self.pending_ctrl.pop_front() {
            out.push(seg.encode(self.conv));
        }
        let n = self.acklist.len();
        for _ in 0..n {
            let Some((sn, ts)) = self.acklist.pop_front() else {
                break;
            };
            let mut seg = Segment::new(CMD_ACK, 0, Vec::new());
            seg.sn = sn;
            seg.ts = ts;
            seg.una = una;
            out.push(seg.encode(self.conv));
        }
    }

    /// 喂入一个收到的 UDP 载荷。返回是否有数据可交付。
    pub fn input(&mut self, data: &[u8]) -> bool {
        let mut maxack: u32 = 0;
        let mut got_ack = false;
        let mut pos = 0usize;
        let mut fresh = false;

        while pos + OVERHEAD <= data.len() {
            let conv = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
            let cmd = data[pos + 4];
            let frg = data[pos + 5];
            let wnd = u16::from_le_bytes(data[pos + 6..pos + 8].try_into().unwrap());
            let ts = u32::from_le_bytes(data[pos + 8..pos + 12].try_into().unwrap());
            let sn = u32::from_le_bytes(data[pos + 12..pos + 16].try_into().unwrap());
            let una = u32::from_le_bytes(data[pos + 16..pos + 20].try_into().unwrap());
            let len = u32::from_le_bytes(data[pos + 20..pos + 24].try_into().unwrap()) as usize;
            pos += OVERHEAD;
            if pos + len > data.len() {
                // 截断的段：整包作废，不做部分解析——部分解析会产出"看似成功但内容错"的数据
                break;
            }
            let payload = &data[pos..pos + len];
            pos += len;

            if conv != self.conv {
                // conv 不符：不是本会话的包，丢弃。
                // 不报错是因为 UDP 上完全可能收到别人的包。
                continue;
            }

            // **累积确认**：对端用它告诉我们"sn < una 的都收到了"。
            //
            // 没有这一步，每个数据段都要靠自己的 ACK 才能从 snd_buf 移除，
            // 于是一个 ACK 段对应一个数据段——ACK 流量与数据流量同量级。
            // 在 FEC 下这尤其致命：分片必须等长，24 字节的 ACK 会被补齐到 MTU，
            // 等于把协议开销放大几十倍。
            if una > self.snd_una {
                self.parse_una(una);
            }

            match cmd {
                CMD_PUSH => {
                    fresh = true;
                    self.parse_data(frg, sn, ts, payload);
                }
                CMD_ACK => {
                    got_ack = true;
                    if ts >= self.ts_recent || (self.ts_recent.wrapping_sub(ts) > 10000) {
                        self.ts_recent = ts;
                    }
                    self.parse_ack(sn);
                    if maxack == 0 || (sn.wrapping_sub(maxack) as i32) > 0 {
                        maxack = sn;
                    }
                }
                CMD_WASK => {
                    // 对端在探测我们的窗口。应答**不超过请求包大小**（§13.6 的放大防护），
                    // 这条 WINS 是 24 字节的头、零载荷，比任何 WASK 请求都不大。
                    let mut seg = Segment::new(CMD_WINS, 0, Vec::new());
                    seg.una = self.snd_una;
                    seg.wnd = self.compute_wnd_unused() as u16;
                    self.pending_ctrl.push_back(seg);
                }
                CMD_WINS => {
                    self.probe = 0;
                }
                _ => {}
            }
            self.rmt_wnd = wnd as u32;
        }

        if got_ack {
            self.parse_fastack(maxack);
        }
        self.shrink_buf();
        fresh
    }

    fn parse_data(&mut self, frg: u8, sn: u32, ts: u32, payload: &[u8]) {
        // 滑动窗口保护：太旧或太远的段一律不收。
        // 收下来会污染重组结果——那正是"静默错误"。
        if (sn.wrapping_sub(self.rcv_nxt) as i32) >= (self.cfg.rcv_wnd as i32) {
            return;
        }
        if (sn.wrapping_sub(self.rcv_nxt) as i32) < 0 {
            // 已经交付过：仍然要 ACK，否则对端会一直重传
            self.acklist.push_back((sn, ts));
            return;
        }
        self.acklist.push_back((sn, ts));

        // 按 sn 插入 rcv_buf（去重）
        if !self.rcv_buf.iter().any(|s| s.sn == sn) {
            let mut seg = Segment::new(CMD_PUSH, sn, payload.to_vec());
            seg.frg = frg;
            seg.ts = ts;
            let at = self
                .rcv_buf
                .iter()
                .position(|s| (sn.wrapping_sub(s.sn) as i32) < 0)
                .unwrap_or(self.rcv_buf.len());
            self.rcv_buf.insert(at, seg);
        }

        // 把连续的段搬进 rcv_queue
        while let Some(front) = self.rcv_buf.front() {
            if front.sn != self.rcv_nxt {
                break;
            }
            let seg = self.rcv_buf.pop_front().unwrap();
            self.rcv_queue.push_back(seg);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        }
    }

    fn parse_ack(&mut self, sn: u32) {
        if (sn.wrapping_sub(self.snd_una) as i32) < 0 {
            return;
        }
        if (sn.wrapping_sub(self.snd_nxt) as i32) >= 0 {
            return;
        }
        // **只移除被确认的那一个段**，不做"连它之前一起丢"。
        // 之前的段若还没被确认，它们仍需要重传——一起丢掉等于把丢包当成已送达，
        // 那是静默错误。
        let Some(idx) = self.snd_buf.iter().position(|s| s.sn == sn) else {
            return;
        };
        let seg = self.snd_buf.remove(idx).expect("位置刚查到");
        if !seg.data.is_empty() {
            self.pending_bytes = self.pending_bytes.saturating_sub(seg.data.len());
        }
        self.update_rtt(seg.ts);
    }

    /// 丢弃 `sn < una` 的全部未确认段。
    fn parse_una(&mut self, una: u32) {
        while let Some(front) = self.snd_buf.front() {
            if (front.sn.wrapping_sub(una) as i32) >= 0 {
                break;
            }
            let seg = self.snd_buf.pop_front().expect("刚看到过");
            if !seg.data.is_empty() {
                self.pending_bytes = self.pending_bytes.saturating_sub(seg.data.len());
            }
        }
    }

    fn parse_fastack(&mut self, sn: u32) {
        if (sn.wrapping_sub(self.snd_una) as i32) < 0 || (sn.wrapping_sub(self.snd_nxt) as i32) >= 0
        {
            return;
        }
        for seg in self.snd_buf.iter_mut() {
            if (seg.sn.wrapping_sub(sn) as i32) < 0 {
                seg.fastack += 1;
            }
        }
    }

    fn update_rtt(&mut self, ts: u32) {
        if ts == 0 {
            return;
        }
        let current = self.current;
        let rtt = current.wrapping_sub(ts) as i32;
        let rtt = if rtt >= 0 { rtt } else { 0 };
        if self.rx_srtt == 0 {
            self.rx_srtt = rtt;
            self.rx_rttval = rtt / 2;
        } else {
            let mut delta = rtt - self.rx_srtt;
            self.rx_srtt += delta / 8;
            if delta < 0 {
                delta = -delta;
            }
            self.rx_rttval += (delta - self.rx_rttval) / 4;
        }
        let minrto = if self.cfg.nodelay == 0 {
            RTO_MIN as i32
        } else {
            RTO_NDL as i32
        };
        let interval = self.cfg.interval as i32;
        let rto = self.rx_srtt + (4 * self.rx_rttval).max(interval);
        self.rx_rto = rto.clamp(minrto, RTO_MAX as i32);
    }

    /// 拥塞窗口相关：ACK 之后推进窗口。
    fn shrink_buf(&mut self) {
        if self.snd_buf.is_empty() {
            self.snd_una = self.snd_nxt;
        } else {
            self.snd_una = self.snd_buf[0].sn;
        }
        self.update_cwnd();
    }

    fn update_cwnd(&mut self) {
        if self.cfg.nocwnd != 0 {
            return;
        }
        let inflight = self.snd_nxt.wrapping_sub(self.snd_una);
        if self.cwnd < self.rmt_wnd {
            // 慢启动
            let mss = self.mss as u32;
            if self.cwnd < self.ssthresh {
                self.cwnd += 1;
                if self.cwnd > self.rmt_wnd {
                    self.cwnd = self.rmt_wnd;
                }
            } else if inflight > (self.cwnd / 2).max(1) {
                // 拥塞避免
                self.cwnd += mss * mss / self.cwnd.max(1);
                if self.cwnd > self.rmt_wnd {
                    self.cwnd = self.rmt_wnd;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 确定性链路模拟。
    ///
    /// 用模拟而不用真网络，是因为**丢包/乱序/延迟必须能按事件顺序复现**。
    /// 真网络下"跑一遍看看"既不能证明算法正确，也不能定位失败点。
    struct Sim {
        a: Kcp,
        b: Kcp,
        to_b: Vec<(u32, Vec<u8>)>,
        to_a: Vec<(u32, Vec<u8>)>,
        now: u32,
        delay: u32,
        /// 每 N 个包丢一个（0 = 不丢）。确定性丢包让每次运行结果一致。
        drop_every: u64,
        n_pkts: u64,
        dropped: u64,
        got_b: Vec<u8>,
        got_a: Vec<u8>,
    }

    impl Sim {
        fn new(delay: u32, drop_every: u64) -> Self {
            let cfg = KcpConfig::default();
            Self {
                a: Kcp::new(0x1234, cfg, 1200),
                b: Kcp::new(0x1234, cfg, 1200),
                to_b: Vec::new(),
                to_a: Vec::new(),
                now: 0,
                delay,
                drop_every,
                n_pkts: 0,
                dropped: 0,
                got_b: Vec::new(),
                got_a: Vec::new(),
            }
        }

        fn should_drop(&mut self) -> bool {
            self.n_pkts += 1;
            if self.drop_every == 0 {
                return false;
            }
            if self.n_pkts % self.drop_every == 0 {
                self.dropped += 1;
                true
            } else {
                false
            }
        }

        /// 推进 1ms。
        fn step(&mut self) {
            self.now = self.now.saturating_add(1);

            let mut out = Vec::new();
            self.a.update(self.now, &mut out);
            for p in out {
                if !self.should_drop() {
                    self.to_b.push((self.now + self.delay, p));
                }
            }
            let mut out = Vec::new();
            self.b.update(self.now, &mut out);
            for p in out {
                if !self.should_drop() {
                    self.to_a.push((self.now + self.delay, p));
                }
            }

            let due: Vec<Vec<u8>> = {
                let mut d = Vec::new();
                self.to_b.retain(|(t, p)| {
                    if *t <= self.now {
                        d.push(p.clone());
                        false
                    } else {
                        true
                    }
                });
                d
            };
            for p in due {
                self.b.input(&p);
            }
            let due: Vec<Vec<u8>> = {
                let mut d = Vec::new();
                self.to_a.retain(|(t, p)| {
                    if *t <= self.now {
                        d.push(p.clone());
                        false
                    } else {
                        true
                    }
                });
                d
            };
            for p in due {
                self.a.input(&p);
            }

            while let Some(d) = self.b.recv() {
                self.got_b.extend_from_slice(&d);
            }
            while let Some(d) = self.a.recv() {
                self.got_a.extend_from_slice(&d);
            }
        }

        fn run(&mut self, ms: u32) {
            for _ in 0..ms {
                self.step();
            }
        }
    }

    fn payload(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn delivers_in_order_over_lossless_link() {
        let mut s = Sim::new(5, 0);
        let data = payload(20_000);
        assert_eq!(s.a.send(&data), data.len());
        s.run(3000);
        assert_eq!(s.got_b.len(), data.len(), "全部字节必须送达");
        assert_eq!(s.got_b, data, "内容与顺序都必须一致");
    }

    /// 10% 丢包——正是 M4 验收的条件之一。
    #[test]
    fn delivers_everything_under_10pct_loss() {
        let mut s = Sim::new(10, 10);
        let data = payload(20_000);
        s.a.send(&data);
        s.run(5000);
        assert!(s.dropped > 0, "这条测试必须真的丢了包，否则没测到东西");
        assert_eq!(
            s.got_b.len(),
            data.len(),
            "10% 丢包下仍须完整送达（丢 {} 个包）",
            s.dropped
        );
        assert_eq!(s.got_b, data, "内容与顺序都必须一致");
    }

    /// 高丢包（30%）下仍要正确——性能可以差，正确性不能差。
    #[test]
    fn stays_correct_under_heavy_loss() {
        let mut s = Sim::new(20, 3);
        let data = payload(8_000);
        s.a.send(&data);
        s.run(20000);
        assert_eq!(s.got_b.len(), data.len(), "30% 丢包下也必须完整送达");
        assert_eq!(s.got_b, data);
    }

    #[test]
    fn tolerates_duplicate_packets() {
        let mut s = Sim::new(5, 0);
        let data = payload(5_000);
        s.a.send(&data);
        // 跑一段，把已在途的包复制一份塞进去
        s.run(50);
        let dup: Vec<Vec<u8>> = s.to_b.iter().map(|(_, p)| p.clone()).collect();
        for p in dup {
            s.b.input(&p);
        }
        s.run(2000);
        assert_eq!(s.got_b, data, "重复包不得导致数据重复或错位");
    }

    #[test]
    fn rejects_foreign_conv() {
        let mut k = Kcp::new(0xAAAA, KcpConfig::default(), 1200);
        let mut seg = Segment::new(CMD_PUSH, 0, b"hello".to_vec());
        seg.una = 0;
        let bytes = seg.encode(0xBBBB); // 别的会话
        k.input(&bytes);
        assert!(
            k.recv().is_none(),
            "conv 不符的包必须丢弃：UDP 上完全可能收到别人的包"
        );
    }

    /// 截断/畸形的包必须被**安全忽略**，不能 panic，也不能产出错误数据。
    ///
    /// 注意这条测试**不**覆盖载荷篡改：KCP 自身没有任何完整性校验，
    /// 改掉载荷它照样会当成正常数据收下。防篡改是 DSHP 层 AEAD 的职责
    /// （设计 §13.2：AEAD 下沉到协议层，且作用域是批次）。
    /// 把"KCP 没检测出篡改"当成 bug 是搞错了分层。
    #[test]
    fn malformed_packets_are_ignored_safely() {
        let mut k = Kcp::new(0x1234, KcpConfig::default(), 1200);
        // 比段头还短
        k.input(&[0u8; 10]);
        assert!(k.recv().is_none(), "短于段头的包不该产出数据");
        // 段头声称的长度超出实际载荷（长度字段在 [20..24]）
        let mut bad = Segment::new(CMD_PUSH, 0, b"x".to_vec()).encode(0x1234);
        bad[20..24].copy_from_slice(&9999u32.to_le_bytes());
        k.input(&bad);
        assert!(k.recv().is_none(), "声明长度超出实际载荷的段必须整包作废");
        // 之后仍能正常工作
        let mut s = Sim::new(5, 0);
        let data = payload(2_000);
        s.a.send(&data);
        s.run(1000);
        assert_eq!(s.got_b, data);
    }

    /// 反复丢包时 RTO 必须**增长**，否则会以极高频率空转重传。
    #[test]
    fn rto_grows_when_acks_never_come() {
        let mut k = Kcp::new(1, KcpConfig::default(), 1200);
        k.send(b"data that will never be acked");
        // 按 1 秒分窗计数，看**频率**是否在下降。
        // 早先我用"前 100ms 的次数 vs 后 2900ms 的次数"做算术比较，
        // 在计数很小时（1 次 vs 3 次）会因为取整而误判——行为是对的，断言写歪了。
        const WIN: u32 = 1000;
        const WINDOWS: usize = 8;
        let mut per_win = [0usize; WINDOWS];
        for t in 1..=(WIN * WINDOWS as u32) {
            let mut out = Vec::new();
            k.update(t, &mut out);
            if out.iter().any(|p| p[4] == CMD_PUSH) {
                per_win[((t - 1) / WIN) as usize] += 1;
            }
        }
        println!("  [KCP/RTO] 每秒重传次数：{per_win:?}");
        let first = per_win[0];
        let last = *per_win.last().unwrap();
        assert!(first > 0, "第一秒必须发生过重传，否则没测到东西");
        assert!(
            last < first,
            "重传频率必须随时间下降（退避），实测首秒 {first} 次、末秒 {last} 次"
        );
    }

    /// 对端只发不读时，发送队列必须有上限——否则内存会被耗尽（§13.10）。
    #[test]
    fn send_queue_is_bounded() {
        let mut k = Kcp::new(1, KcpConfig::default(), 1200);
        let chunk = vec![0u8; 64 * 1024];
        let mut accepted = 0usize;
        for _ in 0..400 {
            accepted += k.send(&chunk);
        }
        println!(
            "  [KCP/背压] 连续灌入 {} MiB，实际接收 {} MiB，丢弃 {} MiB",
            400 * 64 / 1024,
            accepted / (1024 * 1024),
            k.dropped_bytes() / (1024 * 1024)
        );
        assert!(
            accepted <= MAX_PENDING_BYTES + chunk.len(),
            "接收量必须被上限兜住（实际 {accepted}）"
        );
        assert!(k.dropped_bytes() > 0, "超限的部分必须被明确丢弃并计数");
    }

    /// 空载荷不会被当成有效数据交付。
    #[test]
    fn empty_send_is_a_noop() {
        let mut k = Kcp::new(1, KcpConfig::default(), 1200);
        assert_eq!(k.send(&[]), 0);
        assert!(k.recv().is_none());
    }

    /// 双向都能传——KCP 是全双工的，ACK 与数据在同一通道上来回。
    #[test]
    fn bidirectional_transfer() {
        let mut s = Sim::new(10, 20);
        let a_to_b = payload(12_000);
        let b_to_a: Vec<u8> = payload(9_000).into_iter().rev().collect();
        s.a.send(&a_to_b);
        s.b.send(&b_to_a);
        s.run(6000);
        assert_eq!(s.got_b, a_to_b, "A→B 必须一致");
        assert_eq!(s.got_a, b_to_a, "B→A 必须一致");
    }

    /// 收尾用的对照测试：**低延迟档 vs 标准（TCP 式）档**在同一模拟链路上的 goodput。
    ///
    /// # 这条对比能说明什么、不能说明什么
    ///
    /// 两档是**同一份实现的两种参数**：
    ///
    /// * 标准档 `nodelay=0, fastresend=0, nocwnd=0`——按 RTO 最小值等待、
    ///   不快速重传、受拥塞窗口约束。这正是 TCP 的行为方式。
    /// * 低延迟档 `nodelay=1, fastresend=2, nocwnd=1`——设计 §10 的取值。
    ///
    /// 所以它隔离出来的是**参数的效果**，是一个干净的对照实验。
    /// 但它**不是"KCP vs Linux TCP"**：真实 TCP 的实现细节（SACK、PRR、
    /// 各种 RTO 微调）这里都没有。要拿到对着真实 TCP 的数字，需要 `tc netem`
    /// 级别的链路仿真，本环境不具备。
    #[test]
    fn goodput_comparison_low_latency_vs_tcp_like() {
        const RTT_MS: u32 = 200;
        const LOSS_EVERY: u64 = 10; // 10% 丢包
        const TOTAL: usize = 400_000;

        // 返回 (用了多少模拟毫秒, 送达了多少字节)。**不要求两者都送完**——
        // 标准档在 10% 丢包 / 200ms RTT 下送不完，这本身就是结论。
        let measure = |cfg: KcpConfig, name: &str| -> (u32, usize) {
            let mut s = Sim {
                a: Kcp::new(0x1234, cfg, 1200),
                b: Kcp::new(0x1234, cfg, 1200),
                to_b: Vec::new(),
                to_a: Vec::new(),
                now: 0,
                delay: RTT_MS / 2,
                drop_every: LOSS_EVERY,
                n_pkts: 0,
                dropped: 0,
                got_b: Vec::new(),
                got_a: Vec::new(),
            };
            let data = payload(TOTAL);
            s.a.send(&data);
            // 上限 60s 模拟时间，防止实现有 bug 时死循环
            let mut elapsed = 0u32;
            while s.got_b.len() < TOTAL && elapsed < 60_000 {
                s.step();
                elapsed += 1;
            }
            if s.got_b.len() == TOTAL {
                assert_eq!(s.got_b, data, "{name}：送完了就必须逐字节一致");
            } else {
                // 没送完时也要确认已送达的是正文前缀——错位是不允许的
                let n = s.got_b.len();
                let bad = (0..n).find(|&i| s.got_b[i] != data[i]);
                println!(
                    "    （{name} 送达 {n} 字节，{}）",
                    match bad {
                        Some(i) => format!(
                            "首处不符在偏移 {i}：收到 {:?} 期望 {:?}",
                            s.got_b[i], data[i]
                        ),
                        None => "内容是正文前缀".to_string(),
                    }
                );
                assert_eq!(
                    s.got_b,
                    data[..n],
                    "{name}：已送达部分必须是正文前缀，不能错位"
                );
                println!("    （{name} 在 {}s 内未送完）", elapsed / 1000);
            }
            (elapsed, s.got_b.len())
        };

        let tcp_like = KcpConfig {
            nodelay: 0,
            fastresend: 0,
            nocwnd: 0,
            ..KcpConfig::default()
        };
        let (ms_slow, got_slow) = measure(tcp_like, "标准档");
        let (ms_fast, got_fast) = measure(KcpConfig::default(), "低延迟档");

        let g_slow = got_slow as f64 / 1024.0 / (ms_slow as f64 / 1000.0);
        let g_fast = got_fast as f64 / 1024.0 / (ms_fast as f64 / 1000.0);

        println!(
            "  [KCP goodput] 模拟链路 RTT={RTT_MS}ms 丢包=10% 总量={} KiB，时限 60s",
            TOTAL / 1024
        );
        println!(
            "    标准（TCP 式）档  {ms_slow}ms  送达 {} KiB  goodput {g_slow:.1} KiB/s",
            got_slow / 1024
        );
        println!(
            "    低延迟档          {ms_fast}ms  送达 {} KiB  goodput {g_fast:.1} KiB/s",
            got_fast / 1024
        );
        println!("    goodput 比 {:.2}×", g_fast / g_slow.max(0.001));

        assert_eq!(
            got_fast, TOTAL,
            "低延迟档必须在时限内完整送达（实测 {} / {TOTAL} 字节）",
            got_fast
        );
        assert!(
            g_fast > g_slow * 2.0,
            "低延迟档的 goodput 必须达到标准档的 2 倍以上（实测 {g_fast:.1} vs {g_slow:.1} KiB/s）"
        );
    }

    /// **回归测试**：传输量必须超过接收窗口（128 段）才不会漏掉这条 bug。
    ///
    /// 这里守的是一个曾经真实存在的错误：对端窗口为 0 时，我把窗口探测包实现成了
    /// "空载荷的 PUSH 段"并复用了 `snd_buf` 里的 sn。对端会把它当成**一个数据段**
    /// 收下、消耗掉一个 sn——于是从那一点起整条字节流错位。
    ///
    /// 它只在**在途段数超过窗口**（才会触发窗口探测）时显形，
    /// 所以最初那批 ≤20KB 的测试全都正常通过，问题藏了很久。
    /// 这条测试的价值不在于"能传大文件"，而在于**把触发条件钉进测试集**——
    /// 否则下次重构又会把它带回来，而小传输的测试依然全绿。
    #[test]
    fn transfers_larger_than_the_window_are_not_shifted() {
        let window_segments = KcpConfig::default().rcv_wnd as usize;
        let data = payload(4 * window_segments * 1176); // 远超一个窗口

        for (name, loss) in [("无丢包", 0u64), ("10% 丢包", 10)] {
            let mut s = Sim::new(20, loss);
            let sent = s.a.send(&data);
            assert_eq!(sent, data.len(), "{name}：必须全部入队");
            let mut ms = 0u32;
            while s.got_b.len() < data.len() && ms < 60_000 {
                s.step();
                ms += 1;
            }
            assert_eq!(
                s.got_b.len(),
                data.len(),
                "{name}：{} 字节必须全部送达（实测 {}，用时 {ms}ms）",
                data.len(),
                s.got_b.len()
            );
            assert_eq!(
                s.got_b, data,
                "{name}：内容与顺序必须完全一致——错位就是静默错误"
            );
        }
    }

    /// **累积确认**的作用：让 ACK 流量不随数据量线性增长。
    ///
    /// 没有它，每个数据段都要靠自己的 ACK 才能从 `snd_buf` 移除——
    /// ACK 段数与数据段数一比一。在 FEC 下这尤其致命：分片必须等长，
    /// 24 字节的 ACK 会被补齐到 MTU，协议开销直接被放大几十倍。
    #[test]
    fn cumulative_ack_removes_many_segments_at_once() {
        let mut s = Sim::new(10, 0);
        let data = payload(60_000);
        s.a.send(&data);
        // 只跑很短一段，让对端收到一批、回一批 ACK
        s.run(400);
        let inflight_before = s.a.snd_buf.len();
        s.run(2000);
        let inflight_after = s.a.snd_buf.len();
        println!(
            "  [KCP/累积确认] snd_buf {inflight_before} → {inflight_after}，送达 {} / {}",
            s.got_b.len(),
            data.len()
        );
        assert_eq!(s.got_b, data, "确认之后内容仍必须完整且一致");
        assert_eq!(
            s.a.snd_buf.len(),
            0,
            "全部确认后 snd_buf 必须清空（残留说明有段永远没被确认掉）"
        );
    }

    /// 对端的 `una` 必须真的推动 `snd_una`，否则发送窗口会永久卡住。
    #[test]
    fn una_advances_the_send_window() {
        let mut k = Kcp::new(9, KcpConfig::default(), 1200);
        // 手工塞 3 个段进 snd_buf
        k.send(&vec![7u8; 3000]);
        let mut out = Vec::new();
        k.update(10, &mut out);
        let sn_before = k.snd_una;
        // 构造一个携带 una 的包（内容无所谓，只要 conv 对）
        let mut seg = Segment::new(CMD_ACK, 0, Vec::new());
        seg.una = 2;
        seg.sn = 0;
        k.input(&seg.encode(9));
        assert!(
            k.snd_una > sn_before,
            "una 必须推动 snd_una（{sn_before} → {}）",
            k.snd_una
        );
    }

    /// **半个消息绝不能被当成完整帧交付。**
    ///
    /// 这条守的是一个真实发生过的错误：`recv` 在队列里还没有帧尾（`frg == 0`）时
    /// 会把整队拼出来返回，上层于是拿到半个消息并把它当帧头解析——
    /// 端到端表现是服务端报 `BadMagic([104, 102])`，排查了很久才落到这里。
    #[test]
    fn recv_never_returns_a_partial_message() {
        let mut k = Kcp::new(3, KcpConfig::default(), 1200);
        // 手工构造一条 3 片的消息，逐片喂入
        let parts = [b"AAAA".to_vec(), b"BBBB".to_vec(), b"CCCC".to_vec()];
        for (i, p) in parts.iter().enumerate() {
            let mut seg = Segment::new(CMD_PUSH, i as u32, p.clone());
            seg.frg = (parts.len() - i - 1) as u8; // 2,1,0
            seg.ts = 1;
            k.parse_data(seg.frg, seg.sn, seg.ts, &seg.data);
            if i < parts.len() - 1 {
                assert!(
                    k.recv().is_none(),
                    "第 {i} 片到达时还没有帧尾，绝不能交付半个消息"
                );
            }
        }
        let whole = k.recv().expect("帧尾到齐后必须交付");
        assert_eq!(whole, b"AAAABBBBCCCC", "拼出来的必须是完整的一条");
        // 交付完队列应清空，不能把片段留在里面造成重复交付
        assert!(k.recv().is_none(), "交付后不该再有内容");
    }

    /// 两条消息背靠背时不能粘在一起，也不能互相截断。
    #[test]
    fn back_to_back_messages_stay_separate() {
        let mut k = Kcp::new(4, KcpConfig::default(), 1200);
        // 消息 1：2 片；消息 2：1 片
        k.parse_data(1, 0, 1, b"one-");
        k.parse_data(0, 1, 1, b"two");
        assert_eq!(k.recv().expect("消息 1"), b"one-two");
        k.parse_data(0, 2, 1, b"three");
        assert_eq!(k.recv().expect("消息 2"), b"three");
        assert!(k.recv().is_none());
    }

    /// **`una` 必须填 `rcv_nxt`，不能填 `snd_una`。**
    ///
    /// 这条守的是一个真实存在过、且极难查的错误。`una` 的语义是
    /// "我已经收到你 sn < una 的全部段"——说的是**对端的发送序**。
    /// 我原来填的是本方的 `snd_una`（本方自己的发送序），两者完全无关。
    ///
    /// 后果不是"少省一点流量"，而是**数据丢失**：正向传完一批后本方的 `snd_una`
    /// 涨到 N，这个过期的 `una` 传到对端，对端的 `parse_una(N)` 会把
    /// **它自己刚入队、还没发出去的段**整片丢掉。端到端表现是单向大帧永远收不到，
    /// 而发送侧还显示"已全部确认"。
    ///
    /// 它表现出尺寸依赖与间歇性（纯竞态），我先按 FEC、通道容量、窗口边界逐一排除，
    /// 最后靠"发送侧显示 wait_snd=0 但接收侧从未交付"这个矛盾才锁定到这里。
    #[test]
    fn una_carries_rcv_nxt_not_snd_una() {
        let mut k = Kcp::new(77, KcpConfig::default(), 1200);
        // 让本方的 `snd_una` 前进：塞数据并模拟对端确认
        k.send(&vec![1u8; 5000]);
        let mut out = Vec::new();
        k.update(10, &mut out);
        for sn in 0..4u32 {
            let mut ack = Segment::new(CMD_ACK, 0, Vec::new());
            ack.sn = sn;
            ack.ts = 10;
            k.input(&ack.encode(77));
        }
        // 让本方的 `rcv_nxt` 前进到 3：喂 3 个对端数据段
        for sn in 0..3u32 {
            k.parse_data(0, sn, 10, b"x");
        }
        let mut out = Vec::new();
        k.update(20, &mut out);
        let mut saw = false;
        for p in &out {
            if p.len() >= 24 {
                let una = u32::from_le_bytes(p[16..20].try_into().unwrap());
                assert_eq!(
                    una, 3,
                    "`una` 必须是 rcv_nxt(3)，实测 {una}——\
                     填成 snd_una 会让对端丢掉它自己的未发段"
                );
                saw = true;
            }
        }
        assert!(saw, "这一轮必须真的发出了段，否则没测到东西");
    }
}
