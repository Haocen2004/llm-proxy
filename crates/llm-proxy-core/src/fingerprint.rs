//! 内容指纹与命名空间隔离。
//!
//! 设计 §5.1 的关键取舍：指纹取 **128 bit（16 字节）**，不用 8 字节截断——
//! 此处的碰撞是**正确性事故**（会重组出错误内容）而非性能问题。
//!
//! 命名空间混淆 `ns = KDF(psk, tenant ‖ upstream_host)[0..8]`，最终
//! `fp = ns ‖ BLAKE3_128(...)`（共 24 字节）。不同凭据/上游的缓存因此物理隔离，
//! 也防止 `NEED` 补缺协商退化成跨租户的内容确认预言机（设计 §13.9）。

use std::fmt;

/// 指纹的**摘要部分**长度（字节）。**这不是指纹的总长度。**
///
/// 完整指纹是 [`Fp`] = `ns(NS_LEN) ‖ digest(FP_LEN)` = **24 字节**（设计 §5.1）。
/// 别把 `FP_LEN` 当成指纹长度：写 `&[0x5A; FP_LEN]` 想造一个假指纹，实际造出来的是
/// **截断的 16 字节**——协议层会正确地报"截断"，但排查时会先怀疑传输。
/// 本项目已经在这上面踩过一次（见 README「第二个真缺陷」一节的收尾）。
pub const FP_LEN: usize = 16;
/// 命名空间前缀长度（字节）。
pub const NS_LEN: usize = 8;

/// 带命名空间的内容指纹，共 24 字节。
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fp([u8; NS_LEN + FP_LEN]);

impl Fp {
    /// 用给定命名空间包装一个裸哈希。
    pub fn new(ns: Namespace, digest16: [u8; FP_LEN]) -> Self {
        let mut out = [0u8; NS_LEN + FP_LEN];
        out[..NS_LEN].copy_from_slice(&ns.0);
        out[NS_LEN..].copy_from_slice(&digest16);
        Self(out)
    }

    pub fn as_bytes(&self) -> &[u8; NS_LEN + FP_LEN] {
        &self.0
    }

    /// 命名空间部分。
    pub fn namespace(&self) -> Namespace {
        let mut ns = [0u8; NS_LEN];
        ns.copy_from_slice(&self.0[..NS_LEN]);
        Namespace(ns)
    }

    pub fn from_slice(s: &[u8]) -> Option<Self> {
        if s.len() != NS_LEN + FP_LEN {
            return None;
        }
        let mut out = [0u8; NS_LEN + FP_LEN];
        out.copy_from_slice(s);
        Some(Self(out))
    }
}

impl fmt::Debug for Fp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fp({})", hex(&self.0))
    }
}

impl fmt::Display for Fp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

/// 缓存命名空间：把「谁 + 访问哪个上游」压成 8 字节。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Namespace([u8; NS_LEN]);

impl Namespace {
    /// 由预共享密钥、租户标识与上游主机名派生。
    ///
    /// 用 BLAKE3 keyed mode 代替 HMAC-SHA256：已是既有依赖，无需额外 crate。
    pub fn derive(psk: &[u8], tenant: &str, upstream_host: &str) -> Self {
        let key = blake3::hash(psk);
        let mut h = Vec::with_capacity(32 + tenant.len() + 1 + upstream_host.len());
        h.extend_from_slice(key.as_bytes().as_slice());
        h.extend_from_slice(tenant.as_bytes());
        h.push(0);
        h.extend_from_slice(upstream_host.as_bytes());
        let d = blake3::keyed_hash(key.as_bytes(), &h);
        let mut ns = [0u8; NS_LEN];
        ns.copy_from_slice(&d.as_bytes()[..NS_LEN]);
        Self(ns)
    }

    pub fn as_bytes(&self) -> &[u8; NS_LEN] {
        &self.0
    }
}

impl fmt::Debug for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ns({})", hex(&self.0))
    }
}

/// 128 bit 裸摘要（不含命名空间）。
fn digest16(data: &[u8]) -> [u8; FP_LEN] {
    let mut out = [0u8; FP_LEN];
    // BLAKE3 默认输出 32 字节，取前 16
    out.copy_from_slice(&blake3::hash(data).as_bytes()[..FP_LEN]);
    out
}

/// 完整请求体指纹。
pub fn body_fp(ns: Namespace, body: &[u8]) -> Fp {
    Fp::new(ns, digest16(body))
}

/// 对话历史前缀指纹。`prefix` 必须是**原始字节**的切片，不能是重新序列化的结果。
pub fn prefix_fp(ns: Namespace, prefix: &[u8]) -> Fp {
    Fp::new(ns, digest16(prefix))
}

/// CDC 块指纹。
pub fn block_fp(ns: Namespace, block: &[u8]) -> Fp {
    Fp::new(ns, digest16(block))
}

fn hex(b: &[u8]) -> String {
    use fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_isolates_tenants() {
        let a = Namespace::derive(b"psk", "tenant-a", "api.openai.com");
        let b = Namespace::derive(b"psk", "tenant-b", "api.openai.com");
        let c = Namespace::derive(b"psk", "tenant-a", "api.anthropic.com");
        assert_ne!(a, b, "不同租户必须得到不同命名空间");
        assert_ne!(a, c, "不同上游必须得到不同命名空间");
        // 稳定性
        assert_eq!(a, Namespace::derive(b"psk", "tenant-a", "api.openai.com"));
    }

    #[test]
    fn fp_is_24_bytes_and_roundtrips() {
        let ns = Namespace::derive(b"psk", "t", "h");
        let fp = body_fp(ns, b"{\"a\":1}");
        assert_eq!(fp.as_bytes().len(), 24);
        assert_eq!(fp.namespace(), ns);
        assert_eq!(Fp::from_slice(fp.as_bytes()), Some(fp));
        assert!(Fp::from_slice(&[0u8; 23]).is_none());
    }

    #[test]
    fn same_bytes_same_fp_different_bytes_different_fp() {
        let ns = Namespace::derive(b"psk", "t", "h");
        assert_eq!(body_fp(ns, b"abc"), body_fp(ns, b"abc"));
        assert_ne!(body_fp(ns, b"abc"), body_fp(ns, b"abd"));
        // 一个字节的差异必须改变指纹
        assert_ne!(body_fp(ns, b"abc"), body_fp(ns, b"abc "));
    }

    #[test]
    fn cross_namespace_fp_never_collides() {
        let a = Namespace::derive(b"psk", "a", "h");
        let b = Namespace::derive(b"psk", "b", "h");
        assert_ne!(body_fp(a, b"same"), body_fp(b, b"same"));
    }
}
