// 用 vendored protoc，避免在 ARM 交叉编译环境里依赖宿主 protoc。
// 设计文档要求把生成的 .rs 提交进仓库；M0 阶段先走 build.rs，稳定后再固化生成物。
fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("必须能定位 vendored protoc");
    std::env::set_var("PROTOC", protoc);
    prost_build::compile_protos(&["proto/dshp.proto"], &["proto/"]).expect("编译 dshp.proto 失败");
    println!("cargo:rerun-if-changed=proto/dshp.proto");
}
