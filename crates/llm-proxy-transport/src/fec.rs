//! FEC（前向纠错）：用冗余包换掉"等重传"的时间（设计 §10：`10:2`，丢包上升时提至 `10:4`）。
//!
//! # 为什么在 KCP 之外还要 FEC
//!
//! KCP 的 ARQ 能保证正确性，但每一个丢失的包都要**等一个 RTT** 才发现并重传。
//! 200ms RTT 下，一次丢包就是 200ms 的停顿。FEC 把"丢包"在**本地**补回来，
//! 对上层完全不可见——延迟上省掉的就是那一个 RTT。
//!
//! 代价是固定冗余（10:2 就是 20% 额外带宽），**丢包率低时是纯浪费**。
//! 所以设计 §10 要求按丢包率在两档之间切换，而不是一直开着。
//!
//! # 为什么不是简单 XOR
//!
//! 简单 XOR（所有校验包都是数据的异或）**只能恢复一个**丢失分片。
//! `10:2` 要恢复两个，就需要两个**线性无关**的方程——也就是 GF(256) 上的
//! 里德-所罗门编码（范德蒙矩阵）。这就是下面 `Gf256` 存在的理由。
//!
//! # 一个必须守住的性质
//!
//! **恢复必须要么完全正确，要么完全不做。** 宁可让上层走 KCP 重传，
//! 也绝不能交付一个"看起来恢复了、其实内容错了"的分片——那是设计 §16 M7
//! 明令禁止的静默错误。所以解码在丢包数超过校验分片数时**直接放弃**，
//! 不做任何尽力而为的猜测。
//!
//! # 尾片：一组凑不满的时候怎么办
//!
//! 这是本模块最容易写错、也最难被发现的一处。
//!
//! 一组要 `data_shards` 个分片才算出校验。可是**发送侧一次能拿到几个分片，
//! 是由 KCP 决定的**——KCP 一次 `update` 只产出"此刻该发"的段。于是一串 28 个段
//! 会变成"2 个整组 + 8 个尾片"，而那 8 个尾片永远等不到第 9、第 10 个同伴。
//!
//! 如果尾片照原样按组成员发出去，接收侧的解码器就会**一直等这一组凑齐**，
//! 既等不到数据、也没有校验包可解——那 8 个分片连同它们承载的 KCP 段
//! 就永远停在接收侧的缓冲里，**整条链路静默停住**。
//!
//! 所以发送侧**先不发**：分片攒在本对象里，凑满一组就整组（含校验）发出去；
//! 若 KCP 已经没别的要发了，就由 [`FecEncoder::flush`] 把剩下的尾片按
//! **独立包**（[`FLAG_STANDALONE`]）发出，接收侧对独立包**直接交付**，
//! 不参与任何组的等待。
//!
//! 代价是这批尾片没有校验保护。但"不交付"是错的，"少一层保护"只是少省一点。

/// GF(256) 的乘法表，本原多项式 0x11d（RS 编码的事实标准）。
struct Gf256 {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Gf256 {
    fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        // 下标同时写进 `exp` 与 `log` 两个数组，改成迭代器反而看不出在做什么
        #[allow(clippy::needless_range_loop)]
        for i in 0..255usize {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Self { exp, log }
    }

    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let s = self.log[a as usize] as usize + self.log[b as usize] as usize;
        self.exp[s]
    }

    /// `a` 的乘法逆元（`a != 0`）。
    fn inv(&self, a: u8) -> u8 {
        self.exp[255 - self.log[a as usize] as usize]
    }
}

/// 编码器/解码器共用的参数。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FecConfig {
    pub data_shards: usize,
    pub parity_shards: usize,
}

impl FecConfig {
    /// 设计 §10 的低丢包档。
    pub const R10_2: Self = Self {
        data_shards: 10,
        parity_shards: 2,
    };
    /// 设计 §10 的高丢包档（丢包上升时切换）。
    pub const R10_4: Self = Self {
        data_shards: 10,
        parity_shards: 4,
    };

    pub fn total(&self) -> usize {
        self.data_shards + self.parity_shards
    }
}

/// FEC 包头长度：flags(1) + group_seq(4) + index(1) + len(2)
pub const HEADER: usize = 8;
const FLAG_PARITY: u8 = 1 << 0;
/// **独立包**：不属于任何组，接收侧直接交付，不参与校验计算。
///
/// 存在的理由是"尾片不能等"——见模块文档。
const FLAG_STANDALONE: u8 = 1 << 1;

/// 每个**组内**分片载荷开头的真实长度（u16 LE）。
///
/// **为什么长度要放进载荷里**：同一组的分片必须等长（见 `FecEncoder::shard_size`），
/// 短包因此会被补零。补出来的零对上层是垃圾——如果直接把补齐后的分片交给上层，
/// 上层就只能靠"猜"来区分真数据和填充（`Kcp::input` 恰好靠"conv 不符就跳过"
/// 容忍了它，但那是巧合，不是契约）。
///
/// 把长度放进分片自身，恢复出来的分片也就自带长度：上层拿到的永远是**精确切片**。
/// 额外开销是每分片 2 字节，对比 20% 的冗余可以忽略。
///
/// 独立包**不用**这个前缀——它本来就是精确定长的，长度就在包头里。
pub const LEN_PREFIX: usize = 2;

/// 单包上限。与 KCP 的 mtu 同量级。
pub const MAX_PACKET: usize = 1500;

/// 接收侧最多同时跟踪多少个"还没凑齐"的组（见 [`FecDecoder::note_pending`]）。
const MAX_GROUPS: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub enum FecError {
    Truncated,
    TooLarge(usize),
    /// 同一组里同一位置来了两个不同的包——说明链路或对端有问题，不能猜。
    Conflicting,
    /// 分片内部自述的长度与内容对不上。
    ///
    /// 正常情况下不会出现；一旦出现就意味着这**不是**一个可信的分片，
    /// 必须丢掉而不是交付——静默错误比丢包严重得多。
    Corrupt,
}

impl std::fmt::Display for FecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "FEC 包被截断"),
            Self::TooLarge(n) => write!(f, "FEC 包 {n} 字节超过上限"),
            Self::Conflicting => write!(f, "同一组同一位置出现冲突内容"),
            Self::Corrupt => write!(f, "FEC 分片长度字段与内容不符"),
        }
    }
}

impl std::error::Error for FecError {}

/// 解析出的包头。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecHeader {
    pub group: u32,
    pub index: u8,
    pub is_parity: bool,
    pub standalone: bool,
    pub len: usize,
}

pub fn parse_header(buf: &[u8]) -> Result<(FecHeader, &[u8]), FecError> {
    if buf.len() < HEADER {
        return Err(FecError::Truncated);
    }
    let is_parity = buf[0] & FLAG_PARITY != 0;
    let standalone = buf[0] & FLAG_STANDALONE != 0;
    let group = u32::from_le_bytes(buf[1..5].try_into().expect("长度已检查"));
    let index = buf[5];
    let len = u16::from_le_bytes(buf[6..8].try_into().expect("长度已检查")) as usize;
    if len > MAX_PACKET {
        return Err(FecError::TooLarge(len));
    }
    if buf.len() < HEADER + len {
        return Err(FecError::Truncated);
    }
    Ok((
        FecHeader {
            group,
            index,
            is_parity,
            standalone,
            len,
        },
        &buf[HEADER..HEADER + len],
    ))
}

fn build(header: FecHeader, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + payload.len());
    let mut flag = 0u8;
    if header.is_parity {
        flag |= FLAG_PARITY;
    }
    if header.standalone {
        flag |= FLAG_STANDALONE;
    }
    out.push(flag);
    out.extend_from_slice(&header.group.to_le_bytes());
    out.push(header.index);
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// 把一个分片补齐到 `shard_size`：`真实长度(2B) ‖ 载荷 ‖ 零`。
fn pad(payload: &[u8], shard_size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(shard_size);
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(payload);
    out.resize(shard_size, 0);
    out
}

/// [`pad`] 的逆：按分片自述的长度切出真实载荷。
///
/// 长度字段是分片内容的一部分，所以**恢复出来的分片也带着它**——
/// 校验运算逐位置进行，长度字段跟着一起被正确重建。
fn unpad(shard: &[u8]) -> Result<Vec<u8>, FecError> {
    if shard.len() < LEN_PREFIX {
        return Err(FecError::Truncated);
    }
    let n = u16::from_le_bytes(shard[..LEN_PREFIX].try_into().expect("长度已检查")) as usize;
    if shard.len() < LEN_PREFIX + n {
        return Err(FecError::Corrupt);
    }
    Ok(shard[LEN_PREFIX..LEN_PREFIX + n].to_vec())
}

/// 范德蒙系数：第 `p` 个校验分片对第 `i` 个数据分片的系数 = `(i+1)^p`。
///
/// `p=0` 时全部为 1（退化成简单 XOR，只够恢复一个）；
/// `p=1` 起引入位置权重，让各行线性无关——这正是 `10:2` 能恢复两个丢包的原因。
fn vandermonde_coef(gf: &Gf256, p: usize, i: usize) -> u8 {
    let base = (i + 1) as u8;
    let mut acc: u8 = 1;
    for _ in 0..p {
        acc = gf.mul(acc, base);
    }
    acc
}

/// 发送侧：攒够 `data_shards` 个数据包后生成校验包。
pub struct FecEncoder {
    gf: Gf256,
    cfg: FecConfig,
    /// 组内每个分片的固定长度。
    ///
    /// **同组分片必须等长**，这是 FEC 能精确恢复的前提：恢复算法按位置异或，
    /// 事先不知道"某个丢失分片本来多长"。若允许变长，恢复出来的分片会被补齐到
    /// 组内最长的一个——**长度就错了**，而且不报错。
    /// 所以这里由编码器**统一补齐**，调用方只需保证不超过它。
    shard_size: usize,
    /// 当前组的载荷（**原始**，未补齐），按 index 排列
    group: Vec<Vec<u8>>,
    group_seq: u32,
    /// 已按独立包发出的尾片数（观测用）
    pub flushed: u64,
    /// 已原样直发的控制包数（观测用）
    pub raw_wrapped: u64,
}

impl FecEncoder {
    pub fn new(cfg: FecConfig, shard_size: usize) -> Self {
        Self {
            gf: Gf256::new(),
            cfg,
            shard_size: shard_size.clamp(LEN_PREFIX, MAX_PACKET),
            group: Vec::with_capacity(cfg.data_shards),
            group_seq: 0,
            flushed: 0,
            raw_wrapped: 0,
        }
    }

    pub fn shard_size(&self) -> usize {
        self.shard_size
    }

    pub fn config(&self) -> FecConfig {
        self.cfg
    }

    /// 当前是否还扣着没发出去的分片（见模块文档"尾片"）。
    pub fn has_pending(&self) -> bool {
        !self.group.is_empty()
    }

    /// 换档（丢包上升时 `10:2` → `10:4`）。
    ///
    /// 返回值是**扣着的尾片**（按独立包编码），调用方必须把它们发出去——
    /// 半组的校验包配上新档的参数是解不出来的，所以这些分片只能走独立包那条路。
    /// 直接丢掉它们也不丢数据（KCP 会重传），但那要多等一个 RTO。
    pub fn set_config(&mut self, cfg: FecConfig) -> Vec<Vec<u8>> {
        if cfg == self.cfg {
            return Vec::new();
        }
        let tail = self.flush();
        self.cfg = cfg;
        tail
    }

    /// 喂一个数据包，返回可以立刻发出的字节。
    ///
    /// **凑不满一组时返回空**——不是"暂时还没算校验"，而是那些分片现在还不该上线路，
    /// 理由见模块文档"尾片"。调用方在确认没有更多分片可喂时（KCP 这一拍空转）
    /// 要调用 [`Self::flush`]。
    pub fn push(&mut self, payload: &[u8]) -> Result<Vec<Vec<u8>>, FecError> {
        if payload.len() + LEN_PREFIX > self.shard_size {
            return Err(FecError::TooLarge(payload.len()));
        }
        self.group.push(payload.to_vec());
        if self.group.len() < self.cfg.data_shards {
            return Ok(Vec::new());
        }
        Ok(self.emit_group())
    }

    /// 把一个**不值得做 FEC** 的段原样直发（ACK/WASK/WINS 这类控制段）。
    ///
    /// 为什么必须区分：FEC 要求同组分片等长，24 字节的 ACK 会被补齐到 `shard_size`
    /// ——顺带还会为它产生校验包。也就是说一个 ACK 从 24 字节变成 ~1210 字节，
    /// **放大约 50 倍**，而 KCP 的 ACK 本来就是靠重传兜底的。
    /// 在软路由那种上行只有几百 kbit/s 的环境里，这一项足以吃掉 KCP 的全部收益。
    ///
    /// 直发包与尾片共用同一种封装（`FLAG_STANDALONE`）：都是"不参与任何组、
    /// 原样交付"。区分它们对接收侧没有意义，所以不额外造一种包型。
    pub fn wrap_raw(&mut self, payload: &[u8]) -> Result<Vec<u8>, FecError> {
        if payload.len() > MAX_PACKET {
            return Err(FecError::TooLarge(payload.len()));
        }
        self.raw_wrapped += 1;
        Ok(self.standalone(payload))
    }

    /// 把凑不满一组的尾片按**独立包**发出去。
    ///
    /// 返回空表示本来就没有扣着的分片（正常情况下每拍都会走到这里）。
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        if self.group.is_empty() {
            return Vec::new();
        }
        let shards = std::mem::take(&mut self.group);
        let out: Vec<Vec<u8>> = shards.iter().map(|s| self.standalone(s)).collect();
        // 组号照样推进：这个组号已经作废，绝不能再被后面的整组复用
        // （复用会让接收侧把两个不同组当成同一个，那是静默错位）。
        self.group_seq = self.group_seq.wrapping_add(1);
        self.flushed += out.len() as u64;
        out
    }

    /// 独立包：不带长度前缀、不补齐，长度就在包头里。
    fn standalone(&self, payload: &[u8]) -> Vec<u8> {
        build(
            FecHeader {
                group: self.group_seq,
                index: 0,
                is_parity: false,
                standalone: true,
                len: payload.len(),
            },
            payload,
        )
    }

    /// 整组（数据 + 校验）编码。
    fn emit_group(&mut self) -> Vec<Vec<u8>> {
        let group = self.group_seq;
        // 补齐放在这里做：组内分片必须等长，而独立包不需要
        let padded: Vec<Vec<u8>> = self.group.iter().map(|p| pad(p, self.shard_size)).collect();
        let mut out = Vec::with_capacity(self.cfg.total());
        for (i, data) in padded.iter().enumerate() {
            out.push(build(
                FecHeader {
                    group,
                    index: i as u8,
                    is_parity: false,
                    standalone: false,
                    len: data.len(),
                },
                data,
            ));
        }
        for p in 0..self.cfg.parity_shards {
            let mut parity = vec![0u8; self.shard_size];
            for (i, data) in padded.iter().enumerate() {
                // 系数取自范德蒙矩阵：第 p 行第 i 列 = (i+1)^p 的 GF(256) 幂。
                // 不同 p 行线性无关，所以能解出 p 个丢失分片。
                let coef = vandermonde_coef(&self.gf, p, i);
                for (j, b) in data.iter().enumerate() {
                    parity[j] ^= self.gf.mul(coef, *b);
                }
            }
            out.push(build(
                FecHeader {
                    group,
                    index: (self.cfg.data_shards + p) as u8,
                    is_parity: true,
                    standalone: false,
                    len: self.shard_size,
                },
                &parity,
            ));
        }
        self.group.clear();
        self.group_seq = self.group_seq.wrapping_add(1);
        out
    }
}

/// 接收侧：按组缓存，丢包在本地补齐。
pub struct FecDecoder {
    gf: Gf256,
    cfg: FecConfig,
    /// group_seq → (每个位置的载荷，None 表示还没到)
    groups: std::collections::BTreeMap<u32, Vec<Option<Vec<u8>>>>,
    /// 已交付的最大组号与"是否交付过"。
    ///
    /// 单独用一个布尔量而不是把初值设成 `u32::MAX` 之类的哨兵：
    /// 哨兵值容易被后续代码当成真实组号用，而 `0` 又会把**第一组**误判成重复
    /// （写这里时正是这么错的）。
    last_group: u32,
    delivered_any: bool,
    /// 已恢复的分片数与放弃的组数（观测用）
    pub recovered: u64,
    pub abandoned: u64,
    /// 直接交付的独立包（尾片）数（观测用）
    pub stood_alone: u64,
}

impl FecDecoder {
    pub fn new(cfg: FecConfig) -> Self {
        Self {
            gf: Gf256::new(),
            cfg,
            groups: std::collections::BTreeMap::new(),
            last_group: 0,
            delivered_any: false,
            recovered: 0,
            abandoned: 0,
            stood_alone: 0,
        }
    }

    pub fn set_config(&mut self, cfg: FecConfig) {
        if cfg != self.cfg {
            self.cfg = cfg;
            self.groups.clear();
        }
    }

    /// 喂一个收到的 FEC 包。返回值是**可以按序交付给上层的载荷**（可能是恢复出来的）。
    ///
    /// 若某组丢包数超过校验分片数，该组被**整体放弃**并返回空——
    /// 不猜测。上层由 KCP 的重传兜底。
    pub fn push(&mut self, buf: &[u8]) -> Result<Vec<Vec<u8>>, FecError> {
        let (h, payload) = parse_header(buf)?;
        if h.standalone {
            // 独立包（尾片或控制段）：不属于任何组，载荷就是原样字节，
            // 也**不碰任何组的记账**（它带的是作废组号，
            // 拿它去推进 `last_group` 会把后面一个真实整组误判成重复）。
            self.stood_alone += 1;
            return Ok(vec![payload.to_vec()]);
        }
        if h.index as usize >= self.cfg.total() {
            // 参数与本端不一致（换档瞬间会这样）：丢掉，不按错的档解
            return Ok(Vec::new());
        }
        if self.delivered_any && h.group <= self.last_group {
            // 该组已经交付过了（重复包或迟到包）。
            // **必须在这里挡住**：放进去会重建一个"新"组，等数据再次凑齐时
            // 又交付一遍——上层就看到重复数据了。
            return Ok(Vec::new());
        }
        // 先把这一组**取出来**再操作：`solve` 需要 `&self`，
        // 若 `slots` 还借着 `self.groups` 就会冲突。
        let mut slots = self
            .groups
            .remove(&h.group)
            .unwrap_or_else(|| vec![None; self.cfg.total()]);
        let slot = &mut slots[h.index as usize];
        if let Some(prev) = slot {
            if prev != payload {
                self.note_pending(h.group, slots);
                return Err(FecError::Conflicting);
            }
            self.note_pending(h.group, slots);
            return Ok(Vec::new()); // 重复包
        }
        *slot = Some(payload.to_vec());

        // 数据齐了就交付
        let data_ready = slots[..self.cfg.data_shards].iter().all(|s| s.is_some());
        if data_ready {
            match deliver(&slots, self.cfg.data_shards) {
                Ok(out) => {
                    self.note_delivered(h.group);
                    return Ok(out);
                }
                Err(e) => {
                    // 交付不出去（长度字段自相矛盾）：整组作废，不猜。
                    self.abandoned += 1;
                    self.note_pending(h.group, slots);
                    return Err(e);
                }
            }
        }

        // 数据不全：看看校验包够不够补
        let missing: Vec<usize> = (0..self.cfg.data_shards)
            .filter(|i| slots[*i].is_none())
            .collect();
        let have_parity = (self.cfg.data_shards..self.cfg.total())
            .filter(|i| slots[*i].is_some())
            .count();
        if missing.is_empty() || missing.len() > have_parity {
            // 后者：**放弃，不猜。** 宁可让 KCP 重传，也不能交付一个"看起来对"的分片。
            if !missing.is_empty() {
                self.abandoned += 1;
            }
            self.note_pending(h.group, slots);
            return Ok(Vec::new());
        }

        // 用范德蒙矩阵解出缺失分片
        let recovered = match self.solve(&mut slots, &missing) {
            Some(v) => v,
            None => {
                self.abandoned += 1;
                self.note_pending(h.group, slots);
                return Ok(Vec::new());
            }
        };
        match deliver(&slots, self.cfg.data_shards) {
            Ok(out) => {
                self.recovered += recovered as u64;
                self.note_delivered(h.group);
                Ok(out)
            }
            Err(e) => {
                // 校验算出来的长度字段不可信：**宁可丢掉整组**，
                // 因为那意味着恢复结果本身就是错的。
                self.abandoned += 1;
                self.note_pending(h.group, slots);
                Err(e)
            }
        }
    }

    /// 记下"这一组还没凑齐"，同时把同时跟踪的组数压在上限内。
    ///
    /// 为什么需要上限：丢包（或对端换档）时会有组永远凑不齐，槽位就此留在表里。
    /// 在软路由那种长期运行的进程里，那就是一个慢性内存泄漏。
    ///
    /// **淘汰最老的组是安全的**：那些分片对应的 KCP 段从来没被本端 KCP 确认过，
    /// KCP 一定会重传，重传的段会进入后面的组。丢掉只是多一次重传，不丢数据。
    fn note_pending(&mut self, group: u32, slots: Vec<Option<Vec<u8>>>) {
        self.groups.insert(group, slots);
        while self.groups.len() > MAX_GROUPS {
            let Some(oldest) = self.groups.keys().next().copied() else {
                break;
            };
            self.groups.remove(&oldest);
        }
    }

    fn note_delivered(&mut self, group: u32) {
        self.last_group = self.last_group.max(group);
        self.delivered_any = true;
        let upto = self.last_group;
        self.groups.retain(|g, _| *g > upto);
    }

    /// 解 `missing` 里的分片。成功时写入 `slots` 并返回恢复个数。
    fn solve(&self, slots: &mut [Option<Vec<u8>>], missing: &[usize]) -> Option<usize> {
        let d = self.cfg.data_shards;
        let max = slots.iter().flatten().map(|v| v.len()).max().unwrap_or(0);
        if max == 0 {
            return Some(0);
        }
        // 取 `missing.len()` 个可用的校验分片，构造方程组：
        //   sum_i coef(p, i) * data_i = parity_p
        // 已知项移到右边，未知项是 missing 里的 data。
        let parity_idx: Vec<usize> = (d..self.cfg.total())
            .filter(|i| slots[*i].is_some())
            .take(missing.len())
            .collect();
        if parity_idx.len() < missing.len() {
            return None;
        }

        // 逐字节解 m×m 小的线性方程组（m ≤ parity_shards，很小）
        let m = missing.len();
        let mut rebuilt: Vec<Vec<u8>> = vec![Vec::with_capacity(max); m];
        // 逐字节位置求解
        for pos in 0..max {
            // 构造 m×m 矩阵与右端
            let mut a = vec![vec![0u8; m]; m];
            let mut b = vec![0u8; m];
            #[allow(clippy::needless_range_loop)] // 下标同时用于 a 与 b
            for (row, &p) in parity_idx.iter().enumerate() {
                for (col, &mi) in missing.iter().enumerate() {
                    a[row][col] = vandermonde_coef(&self.gf, p - d, mi);
                }
                let mut rhs = slots[p]
                    .as_ref()
                    .map(|v| *v.get(pos).unwrap_or(&0))
                    .unwrap_or(0);
                for i in 0..d {
                    if missing.contains(&i) {
                        continue;
                    }
                    let known = slots[i]
                        .as_ref()
                        .map(|v| *v.get(pos).unwrap_or(&0))
                        .unwrap_or(0);
                    rhs ^= self.gf.mul(vandermonde_coef(&self.gf, p - d, i), known);
                }
                b[row] = rhs;
            }
            let x = self.gauss(a, b)?;
            for (col, v) in x.into_iter().enumerate() {
                rebuilt[col].push(v);
            }
        }

        for (col, &mi) in missing.iter().enumerate() {
            slots[mi] = Some(std::mem::take(&mut rebuilt[col]));
        }
        Some(m)
    }

    /// GF(256) 上的高斯消元。无解返回 None。
    fn gauss(&self, mut a: Vec<Vec<u8>>, mut b: Vec<u8>) -> Option<Vec<u8>> {
        let n = b.len();
        for col in 0..n {
            #[allow(clippy::needless_range_loop)] // 下标用于 a 的行与 b
            let piv = (col..n).find(|r| a[*r][col] != 0)?;
            a.swap(col, piv);
            b.swap(col, piv);
            let inv = self.gf.inv(a[col][col]);
            // 下标同时用于 `a` 的两个维度，用迭代器只会更晦涩
            #[allow(clippy::needless_range_loop)]
            for j in col..n {
                a[col][j] = self.gf.mul(a[col][j], inv);
            }
            b[col] = self.gf.mul(b[col], inv);
            for r in 0..n {
                if r == col || a[r][col] == 0 {
                    continue;
                }
                let f = a[r][col];
                #[allow(clippy::needless_range_loop)]
                for j in col..n {
                    a[r][j] ^= self.gf.mul(f, a[col][j]);
                }
                b[r] ^= self.gf.mul(f, b[col]);
            }
        }
        Some(b)
    }
}

/// 把一组的**数据**分片按 index 顺序切出真实载荷。
fn deliver(slots: &[Option<Vec<u8>>], data_shards: usize) -> Result<Vec<Vec<u8>>, FecError> {
    let mut out = Vec::with_capacity(data_shards);
    for s in &slots[..data_shards] {
        // 能走到这里说明每个位置都 Some——`ok_or` 只是不想 unwrap
        out.push(unpad(s.as_deref().ok_or(FecError::Truncated)?)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHARD: usize = 256;

    /// 第 `i` 个分片的**原始**内容（长度各不相同，都会被补齐到 SHARD）。
    fn payload_of(i: usize) -> Vec<u8> {
        vec![(i as u8).wrapping_mul(7); 40 + i * 13]
    }

    fn payloads(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(payload_of).collect()
    }

    /// 喂满一整组，返回线路上的全部包。
    fn send_group(enc: &mut FecEncoder, n: usize) -> Vec<Vec<u8>> {
        let mut all = Vec::new();
        for i in 0..n {
            all.extend(enc.push(&payload_of(i)).expect("补齐在容量内"));
        }
        all
    }

    /// 把包喂给解码器并按序收集交付结果。
    fn drain(dec: &mut FecDecoder, packets: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for p in packets {
            out.extend(dec.push(p).unwrap_or_else(|e| panic!("解码失败：{e}")));
        }
        out
    }

    #[test]
    fn lossless_roundtrip() {
        let cfg = FecConfig::R10_2;
        let mut enc = FecEncoder::new(cfg, SHARD);
        let mut dec = FecDecoder::new(cfg);
        let expect = payloads(10);
        let packets = send_group(&mut enc, 10);
        assert_eq!(packets.len(), 12, "10 数据 + 2 校验");
        let got = drain(&mut dec, &packets);
        // 交付出来的必须是**精确的原始载荷**，不是补齐到 SHARD 的版本
        assert_eq!(got, expect, "无损时必须逐字节一致");
        assert!(
            got.iter().zip(&expect).all(|(g, e)| g.len() == e.len()),
            "长度必须精确——补齐出来的零不许漏给上层"
        );
    }

    /// **`10:2` 的核心承诺**：任意丢 2 个都能恢复。
    #[test]
    fn recovers_any_two_lost_shards() {
        let cfg = FecConfig::R10_2;
        let expect = payloads(10);
        let total = cfg.total();
        let mut checked = 0;
        for a in 0..total {
            for b in (a + 1)..total {
                let mut enc = FecEncoder::new(cfg, SHARD);
                let mut dec = FecDecoder::new(cfg);
                let packets = send_group(&mut enc, 10);
                let kept: Vec<Vec<u8>> = packets
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != a && *i != b)
                    .map(|(_, p)| p.clone())
                    .collect();
                let got = drain(&mut dec, &kept);
                assert_eq!(
                    got, expect,
                    "丢掉第 {a}、{b} 个分片后必须完整恢复\
                     （不是部分恢复，也不是内容错）"
                );
                checked += 1;
            }
        }
        println!("  [FEC 10:2] 验证了 {checked} 种双丢包组合，全部恢复正确");
        assert!(checked > 60, "组合数太少，没覆盖到");
    }

    /// **丢多了必须放弃，不能猜。**
    ///
    /// 这是整个 FEC 最重要的一条：宁可让 KCP 重传，也绝不能交付一个
    /// "看起来恢复了、其实内容错了"的分片——那是静默错误。
    #[test]
    fn too_many_losses_are_abandoned_not_guessed() {
        let cfg = FecConfig::R10_2;
        let mut enc = FecEncoder::new(cfg, SHARD);
        let mut dec = FecDecoder::new(cfg);
        let packets = send_group(&mut enc, 10);
        // 只留 9 个（丢 3 个），而校验只有 2 个
        let kept: Vec<Vec<u8>> = packets.iter().take(9).cloned().collect();
        let got = drain(&mut dec, &kept);
        assert!(
            got.is_empty(),
            "丢 3 个时必须整体放弃，实际却交付了 {} 个分片",
            got.len()
        );
        assert!(dec.abandoned > 0, "放弃必须被计数，否则观测不到");
    }

    #[test]
    fn recovers_four_with_r10_4() {
        let cfg = FecConfig::R10_4;
        let expect = payloads(10);
        let mut enc = FecEncoder::new(cfg, SHARD);
        let mut dec = FecDecoder::new(cfg);
        let packets = send_group(&mut enc, 10);
        assert_eq!(packets.len(), 14);
        // 丢前 4 个（含数据与校验）
        let kept: Vec<Vec<u8>> = packets.iter().skip(4).cloned().collect();
        let got = drain(&mut dec, &kept);
        assert_eq!(got, expect, "10:4 档必须能恢复 4 个丢包");
    }

    #[test]
    fn duplicate_packets_are_not_delivered_twice() {
        let cfg = FecConfig::R10_2;
        let mut enc = FecEncoder::new(cfg, SHARD);
        let mut dec = FecDecoder::new(cfg);
        let expect = payloads(10);
        let packets = send_group(&mut enc, 10);
        let mut doubled = packets.clone();
        doubled.extend(packets.iter().cloned());
        let got = drain(&mut dec, &doubled);
        assert_eq!(got, expect, "重复包不得导致数据重复");
    }

    #[test]
    fn out_of_order_arrival_still_works() {
        let cfg = FecConfig::R10_2;
        let mut enc = FecEncoder::new(cfg, SHARD);
        let mut dec = FecDecoder::new(cfg);
        let expect = payloads(10);
        let packets = send_group(&mut enc, 10);
        // 倒序到达
        let rev: Vec<Vec<u8>> = packets.iter().rev().cloned().collect();
        let got = drain(&mut dec, &rev);
        assert_eq!(got, expect, "乱序到达必须按原顺序交付");
    }

    /// 同一位置来两个不同内容：**必须报错**，不能任选一个。
    #[test]
    fn conflicting_packet_is_an_error() {
        let cfg = FecConfig::R10_2;
        let mut enc = FecEncoder::new(cfg, SHARD);
        let mut dec = FecDecoder::new(cfg);
        let packets = send_group(&mut enc, 10);
        dec.push(&packets[0]).unwrap();
        let mut tampered = packets[0].clone();
        let n = tampered.len();
        tampered[n - 1] ^= 0xFF; // 同一个 index，不同内容
        assert!(
            matches!(dec.push(&tampered), Err(FecError::Conflicting)),
            "同一位置冲突必须报错——任选一个就是在猜"
        );
    }

    #[test]
    fn malformed_packets_are_rejected_safely() {
        let cfg = FecConfig::R10_2;
        let mut dec = FecDecoder::new(cfg);
        assert!(matches!(dec.push(&[0u8; 4]), Err(FecError::Truncated)));
        // 声称的长度超出实际
        let mut bad = build(
            FecHeader {
                group: 0,
                index: 0,
                is_parity: false,
                standalone: false,
                len: 3,
            },
            b"abc",
        );
        bad[6..8].copy_from_slice(&999u16.to_le_bytes());
        assert!(matches!(dec.push(&bad), Err(FecError::Truncated)));
    }

    /// 参数与本端不一致的包（换档瞬间）必须被丢弃，而不是按错的档去解。
    #[test]
    fn packets_beyond_own_shard_count_are_dropped() {
        let mut dec = FecDecoder::new(FecConfig::R10_2); // 共 12
        let pkt = build(
            FecHeader {
                group: 0,
                index: 13, // 超出本端 12
                is_parity: true,
                standalone: false,
                len: 2,
            },
            b"zz",
        );
        assert!(dec.push(&pkt).unwrap().is_empty());
    }

    #[test]
    fn multiple_groups_are_delivered_in_order() {
        let cfg = FecConfig::R10_2;
        let mut enc = FecEncoder::new(cfg, SHARD);
        let mut dec = FecDecoder::new(cfg);
        let mut expect = Vec::new();
        let mut packets = Vec::new();
        for _ in 0..3 {
            expect.extend(payloads(10));
            packets.extend(send_group(&mut enc, 10));
        }
        let got = drain(&mut dec, &packets);
        assert_eq!(got, expect, "多组必须按组序交付");
    }

    #[test]
    fn empty_payload_roundtrip() {
        let cfg = FecConfig::R10_2;
        let mut enc = FecEncoder::new(cfg, SHARD);
        let mut dec = FecDecoder::new(cfg);
        let mut packets = Vec::new();
        for _ in 0..10 {
            packets.extend(enc.push(b"").unwrap());
        }
        let got = drain(&mut dec, &packets);
        assert_eq!(got.len(), 10, "空载荷也要按个数交付");
        assert!(
            got.iter().all(|p| p.is_empty()),
            "空载荷交付出来必须还是空的——不许把补齐的零带出来"
        );
        assert!(
            enc.push(b"").unwrap().is_empty(),
            "整组发完，新的一拍不该有东西出去"
        );
    }

    // -----------------------------------------------------------------
    // 尾片：一组凑不满的路径
    // -----------------------------------------------------------------

    /// **凑不满一组时先不发**——分片扣在编码器里，不能按组成员漏出去。
    ///
    /// 漏出去的后果不是"少点保护"，而是接收侧那一组永远凑不齐，
    /// 于是这些分片永远不交付：整条链路静默停住。
    #[test]
    fn partial_group_is_held_not_leaked_as_group_member() {
        let cfg = FecConfig::R10_2;
        let mut enc = FecEncoder::new(cfg, SHARD);
        let mut dec = FecDecoder::new(cfg);
        for i in 0..3 {
            let out = enc.push(&payload_of(i)).unwrap();
            assert!(out.is_empty(), "第 {i} 个分片就被放出去了，尾片会卡死对端");
        }
        assert!(enc.has_pending(), "扣着的分片必须能被观察到");

        let tail = enc.flush();
        assert_eq!(tail.len(), 3, "尾片有几个就该发几个");
        assert!(!enc.has_pending(), "flush 之后不该还扣着东西");
        // 尾片必须是独立包，接收侧才会直接交付而不是等一组
        for p in &tail {
            let (h, _) = parse_header(p).unwrap();
            assert!(h.standalone, "尾片必须以独立包发出");
            assert!(!h.is_parity, "尾片是数据分片");
        }
        let got = drain(&mut dec, &tail);
        assert_eq!(got, payloads(3), "独立包必须被直接、精确地交付");
        assert!(
            dec.abandoned == 0,
            "独立包不该被算成放弃——它本来就只到自己一个"
        );
    }

    /// 独立包**不许**推进组号记账，否则后面一个真实整组会被当成重复丢掉。
    #[test]
    fn standalone_packet_does_not_poison_group_tracking() {
        let cfg = FecConfig::R10_2;
        let mut enc = FecEncoder::new(cfg, SHARD);
        let mut dec = FecDecoder::new(cfg);
        // 先来一个只有 3 个分片的尾片组（组号 0 → 作废）
        for i in 0..3 {
            enc.push(&payload_of(i)).unwrap();
        }
        let tail = enc.flush();
        // 再来一整组（组号 1）
        let full = send_group(&mut enc, 10);

        let mut got = drain(&mut dec, &tail);
        got.extend(drain(&mut dec, &full));
        let mut expect = payloads(3);
        expect.extend(payloads(10));
        assert_eq!(
            got, expect,
            "独立包之后的整组必须照常交付（组号记账被污染就会整组丢失）"
        );
    }

    /// 一组**跨多个 flush 周期**时，先发的尾片与后到的整组互不干扰。
    #[test]
    fn interleaved_tail_and_full_groups_all_arrive() {
        let cfg = FecConfig::R10_2;
        let mut enc = FecEncoder::new(cfg, SHARD);
        let mut dec = FecDecoder::new(cfg);
        let mut expect = Vec::new();
        let mut wire = Vec::new();

        // 3 个尾片
        for i in 0..3 {
            enc.push(&payload_of(i)).unwrap();
        }
        expect.extend(payloads(3));
        wire.extend(enc.flush());
        // 一整组
        expect.extend(payloads(10));
        wire.extend(send_group(&mut enc, 10));
        // 再来 7 个尾片
        for i in 0..7 {
            enc.push(&payload_of(i)).unwrap();
        }
        expect.extend(payloads(7));
        wire.extend(enc.flush());

        let got = drain(&mut dec, &wire);
        assert_eq!(got, expect, "尾片与整组交错时必须全部按序送达");
    }

    /// 换档不能把扣着的分片吞掉——吞掉就是让那些 KCP 段白等一个 RTO。
    #[test]
    fn switching_config_does_not_swallow_the_tail() {
        let mut enc = FecEncoder::new(FecConfig::R10_2, SHARD);
        let mut dec = FecDecoder::new(FecConfig::R10_4);
        for i in 0..4 {
            enc.push(&payload_of(i)).unwrap();
        }
        let tail = enc.set_config(FecConfig::R10_4);
        assert_eq!(tail.len(), 4, "换档时必须把扣着的分片交出来");
        dec.set_config(FecConfig::R10_4);
        assert_eq!(drain(&mut dec, &tail), payloads(4));
    }

    /// 永远凑不齐的组不能无限堆积——软路由是长期运行的进程。
    #[test]
    fn unfinished_groups_do_not_accumulate_forever() {
        let cfg = FecConfig::R10_2;
        let mut dec = FecDecoder::new(cfg);
        // 200 个"只到 1 个分片"的组
        for g in 0..200u32 {
            let pkt = build(
                FecHeader {
                    group: g,
                    index: 0,
                    is_parity: false,
                    standalone: false,
                    len: LEN_PREFIX + 1,
                },
                &pad(b"x", LEN_PREFIX + 1),
            );
            dec.push(&pkt).unwrap();
        }
        assert!(
            dec.groups.len() <= MAX_GROUPS,
            "组表必须被压在上限内，实际 {} 个",
            dec.groups.len()
        );
    }
}
