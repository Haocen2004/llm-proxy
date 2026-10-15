//! 保序 JSON **语法**级扫描与 SSE 事件切分。
//!
//! 设计约束见 §3.1「上游无关」：
//!
//! * 只做 JSON / SSE 的**语法**分析（键路径、类型、字节区间），**不得**硬编码上游
//!   字段名（`messages` / `system` / `tools` / `choices` / `delta` 等一律不许出现在
//!   判定逻辑里）；
//! * 只输出 **span 位置**，不输出反序列化后的值——重组必须逐字节等价；
//! * 判定标准：上游新增字段或新事件类型时，本 crate **无需修改**。
//!
//! 不建「值模型」是刻意的：扫一遍只产出区间与路径，不复制任何字符串。
#![forbid(unsafe_code)]

pub mod json;
pub mod sse;
pub mod tmpl;

#[cfg(test)]
mod id_uniqueness_tests;

pub use json::{scan, schema_of, skeleton_of, JsonError, Kind, Leaf, Scan, Span};
pub use tmpl::{Inducer, Induction, Template};
