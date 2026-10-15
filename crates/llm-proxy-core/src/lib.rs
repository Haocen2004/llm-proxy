//! DSHP 核心：帧编解码、内容指纹、字典与资源约束。
//!
//! 本 crate 不依赖 tokio，可在嵌入式/测试环境中单独使用。

pub mod batch;
pub mod cdc;
pub mod compression;
pub mod config;
pub mod crypto;
pub mod dict;
pub mod fingerprint;
pub mod frame;
pub mod stream_zstd;
pub mod token;

/// 由 `proto/dshp.proto` 生成的载荷类型。
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/dshp.v1.rs"));
}

pub use dict::Dicts;
pub use fingerprint::{block_fp, body_fp, Fp, Namespace, FP_LEN, NS_LEN};
pub use frame::{crc32c, flags, Flags, Frame, FrameError, FrameType, HEADER_LEN, MAGIC, VERSION};
pub use token::{
    decompose, recompose, recompose_collect, Decompose, Recompose, RecomposeError, Token,
    TokenError,
};
