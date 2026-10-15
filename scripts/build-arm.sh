#!/usr/bin/env bash
# 构建 ARM 软路由目标：aarch64-unknown-linux-musl 静态单二进制（设计 §12 硬约束）。
#
# 需要：
#   * rustup target add aarch64-unknown-linux-musl
#   * 一份 aarch64 的 musl C 工具链（zstd-sys 有 C 代码）
#
# 两条可用路径（都无需 root）：
#
#   A) **musl.cc 预编译工具链**（默认；本机与离线环境常用）
#        curl -sSL https://musl.cc/aarch64-linux-musl-cross.tgz | tar xz -C "$HOME"
#        export MUSL_ARM_PREFIX="$HOME/aarch64-linux-musl-cross"
#        bash scripts/build-arm.sh --package
#
#   B) **zig 自带的交叉工具链**（CI 用这条）
#        pip install ziglang cargo-zigbuild
#        ARM_CARGO=cargo-zigbuild bash scripts/build-arm.sh --package
#
#      为什么 CI 用 B：A 依赖 `musl.cc` 这一个镜像，第 180 轮第一次在 GitHub runner 上跑
#      就撞上它连不上（`curl: (28) ... musl.cc:443 after 134868 ms`），而 GitHub 上
#      **没有**官方 musl 交叉工具链 release（三个候选仓库都是 404）。
#      zig 由 PyPI 官方 wheel 提供 aarch64-musl 的完整工具链，来源稳定、无需镜像。
#      两条路径产出的产物都必须过下面的**同一套校验**（aarch64 + 静态 + 无动态依赖）。
#
# 之所以要显式装上 C 交叉编译器：`zstd-sys` 会编译 zstd 的 C 源码。纯 Rust 依赖
# 本来可以只靠 rustup 的目标 std 就能构建，但一旦掺进 C 就必须有目标 C 工具链。
#
#   C) **Windows 本机 + clang 包装器**（本仓库在这台机器上一直用的就是这条；第 180 轮恢复并验证）
#
#      需要两样东西放在 `.toolchains/`（已 gitignore）：
#        * `aarch64-linux-musl-cross/`  —— aarch64 的 musl sysroot（可从 WSL 的
#          `~/aarch64-linux-musl-cross` 拷来：`cp -r ~/aarch64-linux-musl-cross /mnt/d/.../.toolchains/`）
#        * `clang-aarch64-musl.cmd`     —— 一行包装器（与 `clang-x86-musl.cmd` 同款）：
#            @"C:\Program Files\LLVM\bin\clang.exe" --target=aarch64-linux-musl \
#              --sysroot="D:\code\llm-proxy\.toolchains\aarch64-linux-musl-cross" %*
#      然后（本机 rustup 已带 `aarch64-unknown-linux-musl` target）：
#        $env:CC_aarch64_unknown_linux_musl  = 'D:\code\llm-proxy\.toolchains\clang-aarch64-musl.cmd'
#        $env:AR_aarch64_unknown_linux_musl  = 'llvm-ar'
#        $env:CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER = <同一个 .cmd>
#        $env:PATH = "C:\Program Files\LLVM\bin;.toolchains\aarch64-linux-musl-cross\bin;$env:PATH"
#        cargo build --release --target aarch64-unknown-linux-musl -p llmproxyc -p llmproxyd
#
#      **验证过可复现**：用这条 recipe 重编 `llmproxyc` 得到 sha256
#      `945cb35852d72214a1bedd8dc2de8a6a4ca91829ba3a31bb5a2e252927ae4102`，
#      与线上部署的那一份**逐字节相同** ✓（换句话说：线上客户端 == 仓库源码 ✓）。
#      ⚠️ 第 180 轮之前它一度**编不出来**，原因不是工具链没了，而是
#      `.toolchains/` 里的 **aarch64 sysroot 与那个 .cmd 包装器都不在了**（只剩 x86 那套）
#      —— 记在这里，别再丢第二次。
#
# 用法：bash scripts/build-arm.sh [--package]（`ARM_CARGO=cargo-zigbuild` 切到路径 B）
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET="${ARM_TARGET:-aarch64-unknown-linux-musl}"
# 路径 A 的 musl 工具链前缀按目标平台给默认值（可用 MUSL_ARM_PREFIX 覆盖）✓。
case "$TARGET" in
  aarch64-*) MUSL_ARM_PREFIX="${MUSL_ARM_PREFIX:-$HOME/aarch64-linux-musl-cross}" ;;
  armv7-*)   MUSL_ARM_PREFIX="${MUSL_ARM_PREFIX:-$HOME/arm-linux-musleabihf-cross}" ;;
  *)         MUSL_ARM_PREFIX="${MUSL_ARM_PREFIX:-}" ;;
esac
# `file -b` 在两类产物上的措辞不同（缺口 #7 实测）：
#   aarch64 ⇒ "ELF 64-bit LSB executable, ARM aarch64, ..."
#   armv7   ⇒ "ELF 32-bit LSB executable, ARM, EABI5 ..."（注意这里是裸 "ARM" ✓）
case "$TARGET" in
  aarch64-*) ARCH_MATCH="aarch64" ;;
  armv7-*)   ARCH_MATCH="ARM" ;;
  *)         ARCH_MATCH="" ;;
esac
ARCH_NAME="${TARGET%%-*}"
ARM_CARGO="${ARM_CARGO:-cargo}"
OUT_DIR="dist"

if [ "$ARM_CARGO" = "cargo-zigbuild" ]; then
  command -v cargo-zigbuild >/dev/null 2>&1 || {
    echo "ARM_CARGO=cargo-zigbuild，但找不到它：pip install ziglang cargo-zigbuild" >&2
    exit 1
  }
  command -v zig >/dev/null 2>&1 || {
    echo "找不到 zig：pip install ziglang（zig 自带各架构的 musl 交叉工具链）" >&2
    exit 1
  }
  echo "=== 使用 zig 交叉工具链（zig $(zig version 2>/dev/null || echo '?')）==="
else
  if [ -z "$MUSL_ARM_PREFIX" ] || [ ! -x "$MUSL_ARM_PREFIX/bin/${ARCH_NAME}-linux-musl*-gcc" ] && ! ls "$MUSL_ARM_PREFIX"/bin/*-musl*-gcc >/dev/null 2>&1; then
    echo "找不到 $TARGET 的 musl 工具链：$MUSL_ARM_PREFIX" >&2
    echo "按脚本头部注释安装（路径 A），或用 MUSL_ARM_PREFIX 指定路径。" >&2
    echo "CI/无镜像环境请改用路径 B：ARM_CARGO=cargo-zigbuild bash scripts/build-arm.sh" >&2
    exit 1
  fi
  export PATH="$MUSL_ARM_PREFIX/bin:$PATH"

  # cc-rs 通过这个变量找 C 编译器（zstd-sys 用）。变量名是 **target 里 `-` 换 `_`** 的
  # 固定约定 ⇒ 按 $TARGET 生成，就不再写死 aarch64 ✓（缺口 #7：armv7 也走同一条路 ✓）。
  cc_env="CC_${TARGET//-/_}"
  ar_env="AR_${TARGET//-/_}"
  ld_env="CARGO_TARGET_$(echo "$TARGET" | tr 'a-z-' 'A-Z_')_LINKER"
  export "$cc_env=$(ls "$MUSL_ARM_PREFIX"/bin/*-musl*-gcc | head -1)"
  export "$ar_env=$(ls "$MUSL_ARM_PREFIX"/bin/*-musl*-ar | head -1)"
  export "$ld_env=$(ls "$MUSL_ARM_PREFIX"/bin/*-musl*-gcc | head -1)"
fi

echo "=== 构建 $TARGET（release，用 $ARM_CARGO）==="
if [ "$ARM_CARGO" = "cargo-zigbuild" ]; then
  cargo zigbuild --release --target "$TARGET" -p llmproxyc -p llmproxyd
else
  "$ARM_CARGO" build --release --target "$TARGET" -p llmproxyc -p llmproxyd
fi

echo
echo "=== 校验产物 ==="
fail=0
for bin in llmproxyc llmproxyd; do
  p="target/$TARGET/release/$bin"
  [ -f "$p" ] || { echo "  缺少 $p"; fail=1; continue; }

  size=$(stat -c %s "$p")
  desc=$(file -b "$p")
  echo "  $bin"
  echo "    大小   $((size / 1024)) KiB"
  echo "    类型   $desc"

  # 1) 必须是目标架构（缺口 #7：判据随 $TARGET 走，不再写死 aarch64 ✓）
  case "$desc" in
    *"$ARCH_MATCH"*) ;;
    *) echo "    ✗ 不是 $ARCH_NAME 产物（期望含 $ARCH_MATCH）"; fail=1 ;;
  esac

  # 2) 必须静态链接——这是硬约束，动态链接在软路由上大概率跑不起来
  case "$desc" in
    *"statically linked"*) echo "    ✓ 静态链接" ;;
    *) echo "    ✗ 不是静态链接（软路由上 glibc 版本不可控）"; fail=1 ;;
  esac

  # 3) 不得有任何动态依赖（第二道确认，file 的判断偶尔会漏）
  if command -v readelf >/dev/null 2>&1; then
    need=$(readelf -d "$p" 2>/dev/null | grep -c NEEDED || true)
    if [ "$need" != "0" ]; then
      echo "    ✗ 存在 $need 个动态依赖"; fail=1
    else
      echo "    ✓ 无动态依赖"
    fi
  fi
done

if [ "$fail" != "0" ]; then
  echo
  echo "产物校验失败。" >&2
  exit 1
fi

if [ "${1:-}" = "--package" ]; then
  echo
  echo "=== 打包 ==="
  mkdir -p "$OUT_DIR"
  tgz="$OUT_DIR/dshp-$TARGET.tar.gz"
  tar czf "$tgz" \
    -C "target/$TARGET/release" llmproxyc llmproxyd
  echo "  $tgz  ($(( $(stat -c %s "$tgz") / 1024 )) KiB)"
  echo
  echo "  部署：解包后两个二进制均为静态、无依赖，scp 到软路由即可运行。"
fi

echo
echo "ARM 构建通过。"
