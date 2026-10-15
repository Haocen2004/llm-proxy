//! 字典：内嵌引导字典 + 客户端本地训练字典的身份。
//!
//! 设计 §7.3 的设计变更：字典改为**客户端本地训练**（流量不离开设备，无需脱敏，
//! 且天然匹配使用者的领域词汇），在 `CAPS` 握手中上传，按 `dict_id` 缓存复用。
//! 内嵌的固定字典退化为**首启动的引导默认值**。
//!
//! 实测（`cargo run -p dev-tools -- train`）：骨架指标到 32KB 仍未饱和，故 `dict_id` 必须参与
//! 协商——两端字典不一致会导致重组静默出错，属于正确性红线。

/// 引导字典：`dict_patch`（真实 patch 结构）。
pub const BOOTSTRAP_PATCH: &[u8] = include_bytes!("../../../dicts/dict_patch.zstdict");
/// 引导字典：`dict_ctrl`（控制帧与 header，纯结构，实测 3.76x 增益）。
pub const BOOTSTRAP_CTRL: &[u8] = include_bytes!("../../../dicts/dict_ctrl.zstdict");
/// 引导字典：`dict_sse`（响应流模板）。
pub const BOOTSTRAP_SSE: &[u8] = include_bytes!("../../../dicts/dict_sse.zstdict");

/// 表示「不使用字典」。
pub const DICT_ID_NONE: u32 = 0;

/// 三本字典的持有者。服务端按 `dict_id` 缓存客户端上传的字典，客户端持有本地训练的字典。
#[derive(Debug, Clone, Copy)]
pub struct Dicts {
    pub patch: &'static [u8],
    pub ctrl: &'static [u8],
    pub sse: &'static [u8],
}

impl Dicts {
    /// 内嵌的引导字典。
    pub const fn bootstrap() -> Self {
        Self {
            patch: BOOTSTRAP_PATCH,
            ctrl: BOOTSTRAP_CTRL,
            sse: BOOTSTRAP_SSE,
        }
    }

    /// 启动自检：三本字典都必须落在 zstd 窗口内。
    ///
    /// 设计 §12 硬约束 2：字典长度 > window 时 zstd 会直接报错。
    /// 这里把它前移到启动期，避免运行到一半才炸。
    pub fn check_fits_window(&self) -> Result<(), String> {
        for (name, d) in [
            ("dict_patch", self.patch),
            ("dict_ctrl", self.ctrl),
            ("dict_sse", self.sse),
        ] {
            crate::config::check_dict_fits_window(d.len()).map_err(|e| format!("{name}: {e}"))?;
        }
        Ok(())
    }

    /// 三本字典的总字节数（用于内存预算核对）。
    pub fn total_bytes(&self) -> usize {
        self.patch.len() + self.ctrl.len() + self.sse.len()
    }
}

impl Default for Dicts {
    fn default() -> Self {
        Self::bootstrap()
    }
}

/// 字典身份 = BLAKE3(字典字节) 的前 4 字节（小端）。
///
/// 不用 sha256：BLAKE3 已是既有依赖，且这里只需要一个稳定的短标识。
/// `dev-tools train` 的 manifest 里记录的 sha256 是**来源追溯**用途，二者互补。
///
/// 返回值不会等于 [`DICT_ID_NONE`]：真撞上 0 时映射到 1，避免与「无字典」混淆。
pub fn dict_id(dict: &[u8]) -> u32 {
    if dict.is_empty() {
        return DICT_ID_NONE;
    }
    let h = blake3::hash(dict);
    let mut v = u32::from_le_bytes([
        h.as_bytes()[0],
        h.as_bytes()[1],
        h.as_bytes()[2],
        h.as_bytes()[3],
    ]);
    if v == DICT_ID_NONE {
        v = 1;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_dicts_are_embedded_and_fit() {
        let d = Dicts::bootstrap();
        assert!(!d.patch.is_empty());
        assert!(!d.ctrl.is_empty());
        assert!(!d.sse.is_empty());
        d.check_fits_window().expect("引导字典必须落在窗口内");
        // 设计与实测：dict_patch、dict_ctrl 1KB、dict_sse 4KB。
        //
        // **第 146 轮起 dict_patch 是 16 KiB** ✓（原 32 KiB ✗）：用**真实流量语料**
        // （`corpus-next/`，1091 个真实请求、源约 2.92 GB ✓）重新标定后，
        // 选型收敛到 **16384 B** ✓ —— `dev-tools train` 给出的理由是
        // "骨架指标容差 105% 内的最小尺寸；骨架最优 16.89%，该尺寸 16.89%" ✓，
        // 且已判定**饱和**（32768 B 反而 19.54% ✓）。
        // 留出集指标同时从 0.6377 改善到 **0.6226** ✓（`bench/real_baseline.json` ✓）。
        assert_eq!(d.patch.len(), 16 * 1024);
        assert_eq!(d.ctrl.len(), 1024);
        assert_eq!(d.sse.len(), 4096);
        assert_eq!(d.total_bytes(), 21 * 1024);
    }

    #[test]
    fn dict_id_is_stable_and_nonzero() {
        let d = Dicts::bootstrap();
        let a = dict_id(d.patch);
        assert_eq!(a, dict_id(d.patch));
        assert_ne!(a, DICT_ID_NONE);
        assert_ne!(a, dict_id(d.ctrl));
        assert_ne!(a, dict_id(d.sse));
        assert_eq!(dict_id(&[]), DICT_ID_NONE);
    }
}
