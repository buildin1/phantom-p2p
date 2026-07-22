#!/bin/bash
# macOS 编译脚本

set -e  # 遇到错误立即退出

echo "=========================================="
echo "幻梦P2P - macOS 编译脚本"
echo "=========================================="

# 获取项目根目录
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build/release/macos"

command -v node >/dev/null 2>&1 || { echo "ERROR: node was not found in PATH"; exit 1; }
if [ "${PHANTOM_SKIP_VERSION_BUMP:-0}" = "1" ]; then
  node "$PROJECT_ROOT/tools/version.mjs" check
else
  node "$PROJECT_ROOT/tools/version.mjs" bump
fi
APP_VERSION="$(node "$PROJECT_ROOT/tools/version.mjs" current)"
echo "PhantomP2P macOS build $APP_VERSION"

echo "项目根目录: $PROJECT_ROOT"
echo "输出目录: $BUILD_DIR"
echo ""

# 清理 macOS 在外置卷上生成的资源叉文件（._* 文件会导致 tauri build 失败）
echo "[0/5] 清理 macOS 资源叉文件..."
dot_clean -m "$PROJECT_ROOT"
find "$PROJECT_ROOT" -name "._*" -not -path "*/.git/*" -delete 2>/dev/null || true
echo "✅ 资源叉文件清理完成"
echo ""

# 清理旧的编译产物
echo "[1/5] 清理旧的编译产物..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# 构建前端
echo ""
echo "[2/5] 构建前端资源..."
cd "$PROJECT_ROOT"
npm run build
echo "✅ 前端构建完成"

# 编译信令服务器
echo ""
echo "[3/5] 编译信令服务器..."
cd "$PROJECT_ROOT/server"
cargo build --release
echo "✅ 信令服务器编译完成"

# 编译客户端（Tauri 会同时打包 .app + .dmg）
# 注意：tauri build script 在 target/ 中生成临时 .toml 文件后立刻读回，
# macOS 外置卷会在期间插入 ._* 导致 UTF-8 解析失败。
# 只将 tauri 的中间产物放内置 APFS 盘（Library/Caches），最终产物仍复制回外置盘。
TAURI_BUILD_TARGET="$HOME/Library/Caches/phantom-p2p-build"
mkdir -p "$TAURI_BUILD_TARGET"
echo ""
echo "[4/5] 编译客户端（target 临时放 $TAURI_BUILD_TARGET）..."
cd "$PROJECT_ROOT"
CARGO_TARGET_DIR="$TAURI_BUILD_TARGET" npx tauri build
echo "✅ 客户端编译完成"

# 复制编译产物
echo ""
echo "[5/5] 复制编译产物到 build/release/macos..."

# 复制信令服务器
cp "$PROJECT_ROOT/target/release/phantom-server" "$BUILD_DIR/"
echo "  ✓ phantom-server"

# 复制客户端产物（优先 .app bundle，其次裸二进制）
APP_BUNDLE=$(find "$TAURI_BUILD_TARGET/release/bundle/macos" -name "*.app" 2>/dev/null | head -1)
if [ -n "$APP_BUNDLE" ]; then
  cp -r "$APP_BUNDLE" "$BUILD_DIR/"
  echo "  ✓ $(basename "$APP_BUNDLE")"
else
  cp "$TAURI_BUILD_TARGET/release/phantom-p2p" "$BUILD_DIR/" 2>/dev/null || true
  echo "  ✓ phantom-p2p (裸二进制)"
fi
# 复制 .dmg（如果有）
DMG=$(find "$TAURI_BUILD_TARGET/release/bundle/dmg" -name "*.dmg" 2>/dev/null | head -1)
if [ -n "$DMG" ]; then
  cp "$DMG" "$BUILD_DIR/"
  echo "  ✓ $(basename "$DMG")"
fi

# 复制配置文件
cp "$PROJECT_ROOT/server/config.toml" "$BUILD_DIR/"
echo "  ✓ config.toml"

# 创建启动脚本
cat > "$BUILD_DIR/start-server.sh" << 'EOF'
#!/bin/bash
# 启动信令服务器

cd "$(dirname "$0")"
./phantom-server
EOF
chmod +x "$BUILD_DIR/start-server.sh"
echo "  ✓ start-server.sh"

cat > "$BUILD_DIR/start-client.sh" << 'EOF'
#!/bin/bash
# 启动客户端

cd "$(dirname "$0")"
./phantom-p2p "$@"
EOF
chmod +x "$BUILD_DIR/start-client.sh"
echo "  ✓ start-client.sh"

# 创建 README
cat > "$BUILD_DIR/README.txt" << 'EOF'
幻梦P2P - macOS 版本
==================

文件说明:
- phantom-server: 信令服务器
- phantom-p2p: 客户端程序
- config.toml: 服务器配置文件
- start-server.sh: 启动服务器脚本
- start-client.sh: 启动客户端脚本

使用方法:
1. 启动服务器: ./start-server.sh
2. 启动客户端: ./start-client.sh
3. 开发者模式: ./start-client.sh --dev

配置说明:
- 编辑 config.toml 修改服务器配置
- 信令端口: 10209
- QUIC 中继端口: 10990-11090
- UDP 中继端口: 11091-11191
EOF
echo "  ✓ README.txt"

echo ""
echo "=========================================="
echo "✅ 编译完成!"
echo "=========================================="
echo "输出目录: $BUILD_DIR"
echo ""
echo "文件列表:"
ls -lh "$BUILD_DIR"
echo ""
echo "使用方法:"
echo "  cd $BUILD_DIR"
echo "  ./start-server.sh    # 启动服务器"
echo "  ./start-client.sh    # 启动客户端"
echo "=========================================="
