#!/usr/bin/env bash
# 本地运行与 CI 相同的 Rust 检查。项目开发工具已经内置在 dev-tools crate，
# 不再依赖 Python 解释器、pip 或额外的脚本运行时。
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== 1/6 格式 ==="
cargo fmt --all -- --check
echo "=== 2/6 Clippy ==="
cargo clippy --workspace --all-targets -- -D warnings
echo "=== 3/6 构建 ==="
cargo build --workspace
echo "=== 4/6 测试 ==="
cargo test --workspace -- --test-threads=1 2>&1 | tee target/ci-tests.log
echo "=== 5/6 Rust 源码与协议门禁 ==="
cargo run --offline -q -p dev-tools -- gates
cargo run --offline -q -p dev-tools -- package --selftest
echo "=== 6/6 回归门禁 ==="
cargo run --offline -q -p dev-tools -- baseline
cargo run --offline -q -p dev-tools -- verify-dicts

if [ -f corpus/req.jsonl ]; then
  echo "=== 额外：真实语料门禁 ==="
  cargo run --offline -q -p dev-tools -- train --corpus corpus --out target/train-real
else
  echo "=== 跳过真实语料门禁（未发现 corpus/req.jsonl） ==="
fi

echo "=== 额外：Rust 语料门禁机制（合成夹具） ==="
cargo run --offline -q -p dev-tools -- smoke-corpus --out target/smoke-corpus
cargo run --offline -q -p dev-tools -- train --corpus target/smoke-corpus --out target/smoke-out --smoke --sizes 512,1024,2048

echo "=== 额外：Rust 有界长稳压测 ==="
cargo run --offline -q -p dev-tools -- soak --duration 60 --interval 5 --rate 60 --server-cache-mb 1 --ttl-secs 6 --ceiling-only --out target/soak/ci.json

if [ -x "$HOME/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc" ] \
   && rustup target list --installed | grep -q aarch64-unknown-linux-musl; then
  echo "=== 额外：ARM 交叉构建与 Rust opkg 校验 ==="
  bash scripts/build-arm.sh
  cargo run --offline -q -p dev-tools -- package --bin-dir target/aarch64-unknown-linux-musl/release --out dist
else
  echo "=== 跳过 ARM 交叉构建（未安装 aarch64 musl 工具链） ==="
fi
echo "全部检查通过。"
