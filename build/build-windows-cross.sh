#!/bin/bash
# 从 macOS 交叉编译 Windows x64 版本
# 参考 build-macos.sh 的 ._* 清理方案

set -e

echo "=========================================="
echo "幻梦P2P - Windows 交叉编译脚本 (from macOS)"
echo "=========================================="

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build/release/windows"
TARGET="x86_64-pc-windows-gnu"

command -v node >/dev/null 2>&1 || { echo "ERROR: node was not found in PATH"; exit 1; }
if [ "${PHANTOM_SKIP_VERSION_BUMP:-0}" = "1" ]; then
  node "$PROJECT_ROOT/tools/version.mjs" check
else
  node "$PROJECT_ROOT/tools/version.mjs" bump
fi
APP_VERSION="$(node "$PROJECT_ROOT/tools/version.mjs" current)"
echo "PhantomP2P Windows cross-build $APP_VERSION"

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
cd "$PROJECT_ROOT"
cargo build -p phantom-server --release --target "$TARGET"
echo "✅ 信令服务器编译完成"

# ── 4. 编译 Tauri 客户端 ─────────────────────────────────────────────────────
# 外置卷（HFS+）会产生 ._* AppleDouble 文件干扰 Tauri build.rs，解决方案与
# build-macos.sh 一致：CARGO_TARGET_DIR 指向内置 APFS 缓存，产物最终复制回来。
# 注意：macOS 版 npx tauri build --bundles 只接受 app/dmg，不接受 nsis；
#       改用 cargo build 编译二进制，再手动调用 makensis 生成安装包。
TAURI_BUILD_TARGET="$HOME/Library/Caches/phantom-p2p-windows-build"
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

# 生成 NSIS 安装包
STAGING_DIR="$(mktemp -d)"
cp "$TAURI_BUILD_TARGET/$TARGET/release/phantom-p2p.exe" "$STAGING_DIR/"

# 复制 sidecar 运行库（优先取 release 目录，其次允许手动放在 build/）
for f in WebView2Loader.dll; do
    if [ -f "$TAURI_BUILD_TARGET/$TARGET/release/$f" ]; then
        cp "$TAURI_BUILD_TARGET/$TARGET/release/$f" "$STAGING_DIR/"
        echo "  ✓ sidecar: $f (from target release)"
    elif [ -f "$PROJECT_ROOT/build/$f" ]; then
        cp "$PROJECT_ROOT/build/$f" "$STAGING_DIR/"
        echo "  ✓ sidecar: $f (from build/)"
    else
        echo "  ⚠️  未找到 sidecar: $f"
    fi
done

# 兜底复制可能存在的其余 Windows 动态库
find "$TAURI_BUILD_TARGET/$TARGET/release" -maxdepth 1 -name "*.dll" -type f -print0 2>/dev/null | while IFS= read -r -d '' dll; do
    cp "$dll" "$STAGING_DIR/"
done

echo ""
echo "  生成 NSIS 安装包..."
makensis \
    -INPUTCHARSET UTF8 \
    "-DSTAGING_DIR=$STAGING_DIR" \
    "-DOUTPUT_DIR=$BUILD_DIR" \
    "$PROJECT_ROOT/build/windows-installer.nsi"
rm -rf "$STAGING_DIR"

INSTALLER=$(find "$BUILD_DIR" -name "*setup.exe" 2>/dev/null | head -1)
if [ -n "$INSTALLER" ]; then
    echo "  ✓ $(basename "$INSTALLER")（NSIS 安装包）"
else
    echo "  ⚠️  NSIS 安装包生成失败，回退复制裸 exe"
    cp "$TAURI_BUILD_TARGET/$TARGET/release/phantom-p2p.exe" "$BUILD_DIR/"
fi

cat > "$BUILD_DIR/start-server.bat" << 'BAT'
@echo off
cd /d "%~dp0"
phantom-server.exe
pause
BAT
echo "  ✓ start-server.bat"

cat > "$BUILD_DIR/README.txt" << 'EOF'
幻梦P2P - Windows x64 版本
==========================

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
echo "打包 Windows 发布包..."
cd "$PROJECT_ROOT/build/release"
if command -v zip &>/dev/null; then
    zip -r "phantom-p2p-windows-x64.zip" windows/ >/dev/null
    echo "✅ 已创建: build/release/phantom-p2p-windows-x64.zip"
fi

# ── 清理 ._* 垃圾文件 ──────────────────────────────────────────────────────────
echo ""
echo "清理 ._* 临时文件..."
find "$PROJECT_ROOT" -name "._*" -not -path "*/.git/*" -delete 2>/dev/null || true
find "$TAURI_BUILD_TARGET/$TARGET/release" -maxdepth 5 -name "._*" -delete 2>/dev/null || true
echo "✅ 清理完成"

echo ""
echo "=========================================="
echo "Windows x64 编译完成"
echo "产物目录: $BUILD_DIR"
echo "=========================================="
