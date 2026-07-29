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

# 代码签名（可选）：如果设置了 APPLE_SIGNING_IDENTITY 环境变量，
# 通过 tauri 的 --config 覆盖机制注入，而不是把证书信息写死在 tauri.conf.json 里。
# 公证（notarization）由 tauri-cli 在检测到以下环境变量时自动触发：
#   APPLE_ID / APPLE_PASSWORD / APPLE_TEAM_ID（或 APPLE_API_KEY 系列）
# 本仓库沙箱环境没有真实的 Apple Developer 证书，因此默认不签名（ad-hoc/未签名产物，
# 本机可运行但其他机器首次打开会被 Gatekeeper 拦截，需要用户右键"打开"）。
TAURI_CONFIG_OVERRIDE=()
if [ -n "${APPLE_SIGNING_IDENTITY:-}" ]; then
  echo "  检测到 APPLE_SIGNING_IDENTITY，使用其对 .app/.dmg 进行签名"
  TAURI_CONFIG_OVERRIDE=(--config "{\"bundle\":{\"macOS\":{\"signingIdentity\":\"${APPLE_SIGNING_IDENTITY}\"}}}")
else
  echo "  未设置 APPLE_SIGNING_IDENTITY，产物将不签名（仅供本机测试）"
fi

CARGO_TARGET_DIR="$TAURI_BUILD_TARGET" npx tauri build --bundles app,dmg "${TAURI_CONFIG_OVERRIDE[@]}"
echo "✅ 客户端编译完成"

# 复制编译产物
echo ""
echo "[5/5] 复制编译产物到 build/release/macos..."

# 复制信令服务器
cp "$PROJECT_ROOT/target/release/phantom-server" "$BUILD_DIR/"
echo "  ✓ phantom-server"

# 复制客户端产物（.app bundle 是必需产物，生成不出来就直接报错，不做裸二进制 fallback）
APP_BUNDLE=$(find "$TAURI_BUILD_TARGET/release/bundle/macos" -name "*.app" 2>/dev/null | head -1)
if [ -z "$APP_BUNDLE" ]; then
  echo "❌ 未找到 .app bundle（$TAURI_BUILD_TARGET/release/bundle/macos），tauri build 未能正确产出 App 包" >&2
  echo "   请检查上面的 tauri build 输出日志排查原因，不应该用裸二进制伪装成安装包。" >&2
  exit 1
fi
cp -r "$APP_BUNDLE" "$BUILD_DIR/"
echo "  ✓ $(basename "$APP_BUNDLE")"

# 复制 .dmg（同样是必需产物）
DMG=$(find "$TAURI_BUILD_TARGET/release/bundle/dmg" -name "*.dmg" 2>/dev/null | head -1)
if [ -z "$DMG" ]; then
  echo "❌ 未找到 .dmg 安装包（$TAURI_BUILD_TARGET/release/bundle/dmg）" >&2
  exit 1
fi
cp "$DMG" "$BUILD_DIR/"
echo "  ✓ $(basename "$DMG")"

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

APP_BASENAME="$(basename "$APP_BUNDLE")"
cat > "$BUILD_DIR/start-client.sh" <<EOF
#!/bin/bash
# 启动客户端（打开 .app bundle）

cd "\$(dirname "\$0")"
open "./${APP_BASENAME}" --args "\$@"
EOF
chmod +x "$BUILD_DIR/start-client.sh"
echo "  ✓ start-client.sh"

# 创建 README
cat > "$BUILD_DIR/README.txt" << EOF
幻梦P2P - macOS 版本
==================

文件说明:
- phantom-server: 信令服务器
- ${APP_BASENAME}: 客户端 App（未签名/未公证，首次打开需在"系统设置 → 隐私与安全性"中允许，或右键选择"打开"）
- *.dmg: 客户端安装包（挂载后拖拽安装）
- config.toml: 服务器配置文件
- start-server.sh: 启动服务器脚本
- start-client.sh: 启动客户端脚本（打开 .app）

使用方法:
1. 启动服务器: ./start-server.sh
2. 启动客户端: ./start-client.sh
3. 或直接双击 .dmg 挂载后安装 ${APP_BASENAME}

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
