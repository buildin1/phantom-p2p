#!/bin/bash
# 从 macOS 交叉编译 Windows ARM64 版本
# 参考 build-windows-cross.sh（x64）的结构，仅目标三元组和产物命名不同。
#
# 目标三元组选择说明：
#   使用 aarch64-pc-windows-gnullvm 而不是 aarch64-pc-windows-msvc。
#   - aarch64-pc-windows-msvc 需要完整的 MSVC link.exe + Windows SDK/CRT 头文件与
#     导入库，在 macOS/Linux 上交叉编译该目标通常要借助 `cargo-xwin`（自动下载并
#     缓存一份 Windows SDK/MSVC CRT，体积约 1-2GB），本仓库沙箱环境没有网络无法
#     验证这条路径，且额外引入 cargo-xwin 这个构建期依赖。
#   - aarch64-pc-windows-gnullvm 是 Rust 官方为"从非 Windows 主机交叉编译到
#     Windows ARM64"专门设计的目标（配合 LLVM 的 lld 链接器 + mingw-w64 风格的
#     import lib，不需要真正的 MSVC 工具链)，通过 `rustup target list` 已确认
#     该 target 在当前工具链下可安装（`rustup target add aarch64-pc-windows-gnullvm`）。
#   - 已知限制：该目标编译时仍需要一份支持 aarch64 的 mingw 交叉工具链提供
#     `aarch64-w64-mingw32-clang`（或等价的 clang+lld+headers），Homebrew 的
#     `mingw-w64` 包只提供 x86_64/i686，不含 aarch64。需要额外安装
#     llvm-mingw（https://github.com/mstorsjo/llvm-mingw/releases，选择
#     macOS/universal 版本），解压后把其 bin/ 目录加入 PATH。
#     本沙箱环境无网络无法下载验证 llvm-mingw，因此这条交叉编译路径本脚本已
#     写好但未实机跑通，需要用户在有网络的 macOS 机器上补充安装 llvm-mingw 后
#     验证一次。

set -e

echo "=========================================="
echo "幻梦P2P - Windows ARM64 交叉编译脚本 (from macOS)"
echo "=========================================="

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build/release/windows-arm64"
TARGET="aarch64-pc-windows-gnullvm"

command -v node >/dev/null 2>&1 || { echo "ERROR: node was not found in PATH"; exit 1; }

# ── 预检查：llvm-mingw 提供的 aarch64 交叉工具链 ────────────────────────────
if ! command -v aarch64-w64-mingw32-clang >/dev/null 2>&1; then
  echo "ERROR: 未找到 aarch64-w64-mingw32-clang。" >&2
  echo "  该 target 需要 llvm-mingw 提供的 aarch64 交叉工具链，Homebrew 的" >&2
  echo "  mingw-w64 包不包含 aarch64。请从以下地址下载并把 bin/ 加入 PATH：" >&2
  echo "    https://github.com/mstorsjo/llvm-mingw/releases" >&2
  exit 1
fi

if [ "${PHANTOM_SKIP_VERSION_BUMP:-0}" = "1" ]; then
  node "$PROJECT_ROOT/tools/version.mjs" check
else
  node "$PROJECT_ROOT/tools/version.mjs" bump
fi
APP_VERSION="$(node "$PROJECT_ROOT/tools/version.mjs" current)"
echo "PhantomP2P Windows ARM64 cross-build $APP_VERSION"

echo "项目根目录: $PROJECT_ROOT"
echo "输出目录:   $BUILD_DIR"
echo "编译目标:   $TARGET"
echo ""

# ── 0. 清理 macOS 资源叉文件（同 build-macos.sh）─────────────────────────────
echo "[0/5] 清理 macOS 资源叉文件..."
dot_clean -m "$PROJECT_ROOT"
find "$PROJECT_ROOT" -name "._*" -not -path "*/.git/*" -delete 2>/dev/null || true
echo "✅ 资源叉文件清理完成"
echo ""

# ── 1. 清理旧产物 ──────────────────────────────────────────────────────────────
echo "[1/5] 清理旧的编译产物..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# ── 2. 前端构建 ────────────────────────────────────────────────────────────────
echo ""
echo "[2/5] 构建前端资源..."
cd "$PROJECT_ROOT"
npm run build
echo "✅ 前端构建完成"

# ── 3. 安装 Rust 目标 + 编译信令服务器 ───────────────────────────────────────
echo ""
echo "[3/5] 编译信令服务器..."
rustup target add "$TARGET" 2>/dev/null || true
export CC_aarch64_pc_windows_gnullvm=aarch64-w64-mingw32-clang
export CXX_aarch64_pc_windows_gnullvm=aarch64-w64-mingw32-clang++
export AR_aarch64_pc_windows_gnullvm=aarch64-w64-mingw32-ar
export CARGO_TARGET_AARCH64_PC_WINDOWS_GNULLVM_LINKER=aarch64-w64-mingw32-clang
cd "$PROJECT_ROOT"
cargo build -p phantom-server --release --target "$TARGET"
echo "✅ 信令服务器编译完成"

# ── 4. 编译 Tauri 客户端 ─────────────────────────────────────────────────────
TAURI_BUILD_TARGET="$HOME/Library/Caches/phantom-p2p-windows-arm64-build"
mkdir -p "$TAURI_BUILD_TARGET"

echo ""
echo "[4/5] 检查 NSIS 打包工具..."
if ! command -v makensis &>/dev/null; then
    echo "  正在安装 NSIS（用于生成 Windows 安装包）..."
    brew install nsis
fi
echo "  ✓ NSIS: $(makensis -VERSION 2>&1 | head -1)"

echo ""
echo "[4/5] 编译 Tauri 客户端..."
echo "  Cargo target 临时放: $TAURI_BUILD_TARGET"
cd "$PROJECT_ROOT"
CARGO_TARGET_DIR="$TAURI_BUILD_TARGET" cargo build -p phantom-p2p --release --target "$TARGET"
echo "✅ 客户端编译完成"

# ── 5. 复制产物 + 生成 NSIS 安装包 ───────────────────────────────────────────
echo ""
echo "[5/5] 复制编译产物 + 生成 NSIS 安装包..."

cp "$PROJECT_ROOT/target/$TARGET/release/phantom-server.exe" "$BUILD_DIR/"
echo "  ✓ phantom-server.exe"

cp "$PROJECT_ROOT/server/config.toml" "$BUILD_DIR/"
echo "  ✓ config.toml"

# ARM64 版 wintun.dll / WebView2Loader.dll 与 x64 版不是同一份二进制，
# 不能复用 build/wintun.dll、build/WebView2Loader.dll（那两个是 x86_64）。
# 参照 .github/workflows/build.yml 里 windows-arm64 job 的做法，从官方源下载：
WINTUN_ARM64="$PROJECT_ROOT/build/wintun-arm64.dll"
WEBVIEW2_ARM64="$PROJECT_ROOT/build/WebView2Loader-arm64.dll"
if [ ! -f "$WINTUN_ARM64" ]; then
    echo "  下载 ARM64 wintun.dll..."
    TMP_WINTUN="$(mktemp -d)"
    curl -fsSL 'https://www.wintun.net/builds/wintun-0.14.1.zip' -o "$TMP_WINTUN/wintun.zip"
    unzip -q "$TMP_WINTUN/wintun.zip" -d "$TMP_WINTUN/wintun"
    cp "$TMP_WINTUN/wintun/wintun/bin/arm64/wintun.dll" "$WINTUN_ARM64"
    rm -rf "$TMP_WINTUN"
fi
if [ ! -f "$WEBVIEW2_ARM64" ]; then
    echo "  下载 ARM64 WebView2Loader.dll..."
    TMP_WV2="$(mktemp -d)"
    curl -fsSL 'https://www.nuget.org/api/v2/package/Microsoft.Web.WebView2/1.0.2792.45' -o "$TMP_WV2/webview2.zip"
    unzip -q "$TMP_WV2/webview2.zip" -d "$TMP_WV2/webview2"
    cp "$TMP_WV2/webview2/runtimes/win-arm64/native/WebView2Loader.dll" "$WEBVIEW2_ARM64"
    rm -rf "$TMP_WV2"
fi

# 生成 NSIS 安装包
STAGING_DIR="$(mktemp -d)"
cp "$TAURI_BUILD_TARGET/$TARGET/release/phantom-p2p.exe" "$STAGING_DIR/"
cp "$WINTUN_ARM64" "$STAGING_DIR/wintun.dll"
cp "$WEBVIEW2_ARM64" "$STAGING_DIR/WebView2Loader.dll"
echo "  ✓ sidecar: wintun.dll / WebView2Loader.dll (arm64)"

echo ""
echo "  生成 NSIS 安装包..."
makensis \
    -INPUTCHARSET UTF8 \
    "-DSTAGING_DIR=$STAGING_DIR" \
    "-DOUTPUT_DIR=$BUILD_DIR" \
    "-DAPP_VERSION=$APP_VERSION" \
    "$PROJECT_ROOT/build/windows-installer.nsi"
rm -rf "$STAGING_DIR"

INSTALLER=$(find "$BUILD_DIR" -name "*setup.exe" 2>/dev/null | head -1)
if [ -z "$INSTALLER" ]; then
    echo "❌ NSIS 安装包生成失败" >&2
    exit 1
fi
echo "  ✓ $(basename "$INSTALLER")（NSIS 安装包）"

cat > "$BUILD_DIR/start-server.bat" << 'BAT'
@echo off
cd /d "%~dp0"
phantom-server.exe
pause
BAT
echo "  ✓ start-server.bat"

cat > "$BUILD_DIR/README.txt" << 'EOF'
幻梦P2P - Windows ARM64 版本
============================

安装包: *-setup.exe
  - 双击运行，自动安装并在桌面创建快捷方式
  - 首次安装时若系统缺少 WebView2 运行时，安装包会自动处理
  - 支持卸载（控制面板 → 程序和功能 → 幻梦P2P）

信令服务器（可选，本地自托管）:
  phantom-server.exe  信令服务器
  config.toml         服务器配置
  start-server.bat    快速启动
EOF
echo "  ✓ README.txt"

# 打包 zip
echo ""
echo "打包 Windows ARM64 发布包..."
cd "$PROJECT_ROOT/build/release"
if command -v zip &>/dev/null; then
    zip -r "phantom-p2p-windows-arm64.zip" windows-arm64/ >/dev/null
    echo "✅ 已创建: build/release/phantom-p2p-windows-arm64.zip"
fi

# ── 清理 ._* 垃圾文件 ──────────────────────────────────────────────────────────
echo ""
echo "清理 ._* 临时文件..."
find "$PROJECT_ROOT" -name "._*" -not -path "*/.git/*" -delete 2>/dev/null || true
find "$TAURI_BUILD_TARGET/$TARGET/release" -maxdepth 5 -name "._*" -delete 2>/dev/null || true
echo "✅ 清理完成"

echo ""
echo "=========================================="
echo "Windows ARM64 编译完成"
echo "产物目录: $BUILD_DIR"
echo "=========================================="
