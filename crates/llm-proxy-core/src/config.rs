//! 资源硬约束。全部集中在此，方便门禁与启动自检引用同一份真值。

/// zstd 窗口大小上限的 log2。设计 §12 硬约束 1：
/// 不限定的话 zstd 默认 512KB 窗口会把单压缩上下文推到约 1.3MB。
pub const WINDOW_LOG: u32 = 17;

/// 由 [`WINDOW_LOG`] 推出的窗口字节数。字典长度必须 ≤ 此值，否则 zstd 直接报错。
pub const WINDOW_BYTES: usize = 1 << WINDOW_LOG;

/// 单帧载荷上限（设计 §13.10 DoS 防护）。
pub const MAX_FRAME_BYTES: usize = 1 << 20;

/// 在途并发响应流上限（设计 §12）。**第 112 轮起是进程级**（原先误在 `run_session` 里 ⇒ 每连接一份 ✗）。
pub const MAX_CONCURRENT_STREAMS: usize = 4;
/// `tokio::sync::Semaphore` 允许的最大许可数（Tokio 内部即 `usize::MAX >> 3`）。
///
/// **为什么必须有它**：`max_concurrent_streams` / `max_pending_streams` 的"无界"
/// 默认值是 `usize::MAX`，而 `Semaphore::new(usize::MAX)` 会**直接 panic**
/// （`a semaphore may not have more than MAX_PERMITS permits`）⇒ 服务端根本起不来。
/// 现场就是这么炸的：`llmproxyd` 启动即 panic ⇒ 夹具三次重试全失败 ⇒ CI 那条红。
///
/// ⇒ 凡是要交给 `Semaphore` 的许可数，一律先过 [`semaphore_permits`]。
pub const SEMAPHORE_MAX_PERMITS: usize = usize::MAX >> 3;

/// 把配置里的"无界"（`usize::MAX`）折到 `Semaphore` 能接受的上限。
///
/// 折完仍是天文数字（约 2.3e18）⇒ **实际语义依旧无界**（永远不可能被取满），
/// 但不再 panic。下界取 1：`Semaphore::new(0)` 会让每次 `acquire` 永久等待，
/// 那是"关死"而不是"无界"，与配置意图相反。
pub fn semaphore_permits(n: usize) -> usize {
    n.clamp(1, SEMAPHORE_MAX_PERMITS)
}

/// **进程级连接数上限**（缺口 11 的下半，第 113 轮）。
///
/// 为什么还需要它：流上限（上面那条，**全局 4** ✓）管的是"同时在途的上游请求" ⇒ 它兜住真正的
/// 内存大头 ✓；但**连接**本身也占资源（fd、每个 `run_session` 的 Mux/缓冲/句柄表 ✓），
/// 而两条 accept 循环原先**完全没有上限** ✗ ⇒ 反复重连就能把任务表与 fd 撑满 ✓。
///
/// 取值 64 的理由：它只需"防无界增长" ✓，**不承担内存上界**（那是流上限的职责 ✓）；
/// 64 × 每条极小的固定开销，远低于 32 MiB 的 RSS 预算 ✓。这是**本项目自定的默认值**
/// （设计未规定 ✗）⇒ 所以写在常量旁并说明它是**可调的运维参数** ✓。
///
/// 超限时**明确失败**而不是排队 ✓：TCP 上"接进来立刻关"（客户端拿到 EOF/复位 ✓，
/// 而不是在 backlog 里挂住 ✗）；KCP/UDP 上**直接丢弃**该会话（与 §13.6"未认证不建状态"同向 ✓）。
pub const MAX_CONNECTIONS: usize = 64;

/// 压缩上下文对象池容量：并发 4 流不得新建超过 2 个 CCtx（设计 §12 硬约束 3）。
pub const COMPRESS_CTX_POOL: usize = 2;

// ── 这里删掉了 5 个"假约束"（保留这条注释说明它们去哪了）──────────────
//
// `MAX_CACHE_ENTRY_BYTES` / `MAX_CACHE_ENTRIES` / `CACHE_BUDGET_BYTES`
// / `SSE_RING_BYTES` / `SSE_RING_SECS` 曾经声明在这里，**但没有任何代码引用**。
// 缓存预算的真值是 `llm_proxy_cache::BlockStore::new(budget, ttl)` 的入参
// （服务端 `DEFAULT_SERVER_BUDGET` 256 MiB、客户端 `--block-cache-bytes`）；
// SSE 环形缓冲（设计 §11.2「SSE 续传」）**从来没有实现**。
//
// 这类常量唯一的效果是让人以为那几条约束被守住了——本项目反复栽在这上面，
// 现在由 `cargo run -p dev-tools -- gates` 接进 CI 兜住：config 里的每个
// `pub const` 都必须在**代码**里有引用，**只有文档引用也不算数**
// （文档不会执行任何约束）。
//
// 惰性保留但不引用，是**不允许**的。需要保留的必须写进那个脚本的 ALLOWLIST
// 并注明理由——那一步的意义就是逼人写下理由。

/// 模板库容量上限（设计 §6.4）。
pub const MAX_TEMPLATES: usize = 64;

/// 协议版本字符串，参与 `Hello`/`Caps` 协商。
pub const PROTO_VERSION: &str = "dshp/1";

/// 增量路径允许缓冲的请求体上限。
///
/// 超过此值的请求走 `ENC_RAW` **流式原样转发**，不缓冲、不分解。
/// 这是 ARM 客户端的硬保护：3 MB 的真实请求很常见，但不能让 100 MB 的
/// 上传把 32 MB 内存预算打爆。
pub const MAX_DECOMPOSE_BYTES: usize = 8 << 20;

/// TokenStream 字节数上限。它只会比 body 大一点点（每块多 1~3 字节标签），
/// 给 2 倍余量足够，同时挡住畸形流。
pub const MAX_TOKENSTREAM_BYTES: usize = 2 * MAX_DECOMPOSE_BYTES;

/// 错误码。客户端按 `hint` 行动，`code` 只用于日志与指标。
pub mod err_code {
    pub const INTERNAL: u32 = 1;
    /// 服务端缺少若干块，`Err.missing` 里带着它们的指纹。
    pub const BLOCK_MISS: u32 = 10;
    /// 重组后的 body 与客户端声明的 `target_fp` 不符——**正确性红线被触发**。
    pub const FP_MISMATCH: u32 = 11;
    pub const BAD_ENCODING: u32 = 12;
    /// TokenStream 或 body 超过上限。
    pub const TOO_LARGE: u32 = 13;
    /// 声明长度与实际重组结果不符。
    pub const LENGTH_MISMATCH: u32 = 14;
    /// zstd 解压失败：畸形、截断，或**字典不匹配**。
    pub const DECOMPRESS_FAILED: u32 = 15;
    /// 并发流超限（§12/§13.10 的 DoS 防护）。
    pub const TOO_MANY_STREAMS: u32 = 17;
    /// 握手/认证失败。**回给对端时只给通用原因**，具体原因只进服务端日志——
    /// 把"PSK 不一致"回给未认证来源等于送出一个认证预言机。
    pub const AUTH_FAILED: u32 = 16;
    /// 同一连接内**重复的 `req_id`**（缺口 14 的幂等台账拦下的）。
    ///
    /// 为什么是错误而不是"静默复用结果"：设计 §13.6 要的是"直接返回已缓存结果、不再调用上游" ✓，
    /// 但那需要把**整条响应**留存下来重放 ✗，而响应路径是**流式零拷贝**的（上游 `Incoming` 原样回传 ✓）
    /// ⇒ 第 110 轮先做**安全那一半**：**绝不第二次调用上游** ✓（重复即拒 ✓）。
    /// 与设计"POST 上游不可幂等"的红线一致 ✓；代价是重复请求**响亮地失败** ✓ 而不是静默重复计费 ✓。
    pub const REQ_REPLAY: u32 = 18;
    /// **SSE 续传失败**：客户端要续的位置已经不在服务端的环形缓冲里（设计 §11.2）。
    ///
    /// 语义要点（照设计，**刻意不"聪明"**）：客户端收到它**不自动重放上游** ✗，
    /// 而是按上游错误格式返回给 SDK，由应用决定 —— 因为重放等于**重新计费**，
    /// 而且同一个 prompt 重跑一次**采样结果会变** ✓（那是"悄悄换了答案"，比报错更糟 ✗）。
    pub const STREAM_GAP: u32 = 19;
}

/// 降级指令。设计 §8.3：由服务端给出，客户端无需本地判断即可行动。
pub mod hint {
    /// 只补发缺失的块（当前实现回退为全量，M5 起改为精确补发）。
    pub const SEND_MISSING: &str = "SEND_MISSING";
    /// 重复的 `req_id`：**不要重试**（重试只会再撞一次同一个拒绝 ✓）。
    pub const DUPLICATE_REQ_ID: &str = "DUPLICATE_REQ_ID";
    /// 用 `ENC_RAW` 重发完整 body。
    pub const RETRY_WITH_FULL: &str = "RETRY_WITH_FULL";
    /// 换一个基线候选重试。
    pub const RETRY_ALT_BASE: &str = "RETRY_ALT_BASE";
    /// 绕过代理，直连上游。
    pub const DOWNGRADE_BYPASS: &str = "DOWNGRADE_BYPASS";
}

/// 启动自检：字典长度必须落在窗口内。返回 Err 时应拒绝启动而不是继续跑。
pub fn check_dict_fits_window(dict_len: usize) -> Result<(), String> {
    if dict_len > WINDOW_BYTES {
        return Err(format!(
            "字典 {dict_len}B 超过 zstd 窗口 {WINDOW_BYTES}B（windowLog={WINDOW_LOG}）"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_matches_design() {
        assert_eq!(WINDOW_BYTES, 131_072);
        assert_eq!(WINDOW_LOG, 17);
    }

    #[test]
    fn dict_fit_check_rejects_oversize() {
        assert!(check_dict_fits_window(WINDOW_BYTES).is_ok());
        assert!(check_dict_fits_window(WINDOW_BYTES + 1).is_err());
    }
}

#[cfg(test)]
mod semaphore_permits_tests {
    use super::*;

    /// **守门用例（第 199 轮）**：配置里的"无界"（`usize::MAX`）绝不能让
    /// `Semaphore::new` panic —— 现场就是死在这：`llmproxyd` 启动即
    /// `a semaphore may not have more than MAX_PERMITS permits` ⇒ 服务端起不来 ⇒
    /// e2e 夹具三次重试全失败 ⇒ CI 那条红。
    ///
    /// **负向对照**：把 `semaphore_permits` 改成直接 `return n;`（即原样传给
    /// `Semaphore::new`）⇒ 本用例的 `<= SEMAPHORE_MAX_PERMITS` 立刻变红。
    #[test]
    fn unbounded_config_never_panics_the_semaphore() {
        for n in [usize::MAX, usize::MAX - 1, 1 << 40, 4, 1, 0] {
            let p = semaphore_permits(n);
            assert!(
                p >= 1,
                "许可数必须 ≥ 1：`Semaphore::new(0)` 会让每次 acquire **永久等待**，\
                 那是把服务关死，不是无界（n={n}）"
            );
            assert!(
                p <= SEMAPHORE_MAX_PERMITS,
                "许可数 {p} 超过 Tokio 上限 {SEMAPHORE_MAX_PERMITS} ⇒ `Semaphore::new` 会 **panic**\
                 ⇒ 服务端起不来（n={n}）"
            );
        }
    }

    /// 无界必须**保持无界**（不是被折成一个小数 ⇒ 那会静默限流 ✗）。
    #[test]
    fn unbounded_stays_effectively_unbounded() {
        assert_eq!(
            semaphore_permits(usize::MAX),
            SEMAPHORE_MAX_PERMITS,
            "无界应折到 Tokio 能接受的最大值（约 2.3e18 ⇒ 实际永远取不满）"
        );
        // 显式限额必须原样保留 ⇒ 否则运维配的护栏会被悄悄改掉 ✗。
        for n in [1usize, 2, 4, 16, 64, 4096] {
            assert_eq!(semaphore_permits(n), n, "显式限额 {n} 必须原样保留");
        }
    }
}
