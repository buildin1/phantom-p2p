#!/bin/bash
# 跨平台交叉编译脚本
# 支持在 macOS/Linux 上编译 Windows/Linux/macOS 版本

set -e

echo "=========================================="
echo "幻梦P2P - 交叉编译脚本"
echo "=========================================="

# 获取项目根目录
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# 显示使用说明
show_usage() {
    echo "使用方法:"
    echo "  ./build-cross.sh [target]"
    echo ""
    echo "支持的目标平台:"
    echo "  macos          - macOS (x86_64-apple-darwin)"
    echo "  macos-arm      - macOS Apple Silicon (aarch64-apple-darwin)"
    echo "  linux          - Linux Desktop (x86_64-unknown-linux-gnu)"
    echo "  linux-musl     - Linux with musl (x86_64-unknown-linux-musl)"
    echo "  linux-headless - Linux Headless Web UI (x86_64-unknown-linux-gnu)"
    echo "  windows        - Windows (x86_64-pc-windows-gnu)"
    echo "  all            - 编译所有平台"
    echo ""
    echo "示例:"
    echo "  ./build-cross.sh windows    # 编译 Windows 版本"
    echo "  ./build-cross.sh all        # 编译所有平台"
}

# 检查并安装目标平台
install_target() {
    local target=$1
    echo "检查目标平台: $target"
    if ! rustup target list | grep -q "$target (installed)"; then
        echo "安装目标平台: $target"
        rustup target add "$target"
    else
        echo "✓ 目标平台已安装: $target"
    fi
}

# 编译指定目标
build_target() {
    local target=$1
    local platform=$2
    local is_headless=${3:-false}
    local build_dir="$PROJECT_ROOT/build/release/$platform"

    echo ""
    echo "=========================================="
    echo "编译目标: $platform ($target)"
    if [[ "$is_headless" == "true" ]]; then
        echo "模式: Headless Web UI"
    fi
    echo "=========================================="

    # 清理旧的编译产物
    echo "[1/5] 清理旧的编译产物..."
    rm -rf "$build_dir"
    mkdir -p "$build_dir"

    # 安装目标平台
    install_target "$target"

    # 编译信令服务器
    echo ""
    echo "[2/5] 编译信令服务器..."
    cd "$PROJECT_ROOT/server"
    cargo build --release --target "$target"
    echo "✅ 信令服务器编译完成"

    # 编译客户端
    if [[ "$is_headless" == "true" ]]; then
        # Headless 模式：编译 Web 客户端
        echo ""
        echo "[3/5] 编译 Web 客户端（Headless 模式）..."
        cd "$PROJECT_ROOT/src-web"
        cargo build --release --target "$target" --features web-server
        echo "✅ Web 客户端编译完成"
    else
        # 桌面模式：使用 Tauri CLI
        echo ""
        echo "[3/5] 编译桌面客户端（使用 Tauri CLI）..."
        cd "$PROJECT_ROOT"
        npm run tauri build -- --target "$target"
        echo "✅ 桌面客户端编译完成"
    fi

    # 构建前端（Headless 模式需要）
    if [[ "$is_headless" == "true" ]]; then
        echo ""
        echo "[4/5] 构建前端 UI..."
        cd "$PROJECT_ROOT"
        npm run build
        echo "✅ 前端 UI 构建完成"
    else
        echo ""
        echo "[4/5] 跳过前端构建（Tauri 已包含）"
    fi

    # 复制编译产物
    echo ""
    echo "[5/5] 复制编译产物..."

    local server_bin="phantom-server"
    local client_bin="phantom-p2p"
    local ext=""

    # Windows 需要 .exe 后缀
    if [[ "$platform" == "windows" ]]; then
        ext=".exe"
    fi

    cp "$PROJECT_ROOT/target/$target/release/${server_bin}${ext}" "$build_dir/"
    echo "  ✓ ${server_bin}${ext}"

    if [[ "$is_headless" == "true" ]]; then
        # Headless 模式：复制 Web 客户端
        cp "$PROJECT_ROOT/src-web/target/$target/release/phantom-p2p-web${ext}" "$build_dir/"
        echo "  ✓ phantom-p2p-web${ext}"

        # 复制前端资源
        cp -r "$PROJECT_ROOT/dist" "$build_dir/"
        echo "  ✓ dist/ (前端资源)"
    else
        # 桌面模式：复制 Tauri 客户端
        cp "$PROJECT_ROOT/target/$target/release/${client_bin}${ext}" "$build_dir/"
        echo "  ✓ ${client_bin}${ext}"
    fi

    # Windows 平台：下载并复制 WebView2Loader.dll
    if [[ "$platform" == "windows" ]]; then
        echo ""
        echo "下载 WebView2Loader.dll..."
        local webview2_url="https://www.nuget.org/api/v2/package/Microsoft.Web.WebView2/1.0.2792.45"
        local temp_dir="$build_dir/.temp"
        mkdir -p "$temp_dir"

        if command -v curl &> /dev/null; then
            curl -L "$webview2_url" -o "$temp_dir/webview2.zip" 2>/dev/null
        elif command -v wget &> /dev/null; then
            wget -q "$webview2_url" -O "$temp_dir/webview2.zip"
        else
            echo "  ⚠️  未找到 curl 或 wget，跳过 WebView2Loader.dll 下载"
            echo "  ⚠️  请手动从 https://www.nuget.org/packages/Microsoft.Web.WebView2 下载"
        fi

        if [[ -f "$temp_dir/webview2.zip" ]]; then
            unzip -q "$temp_dir/webview2.zip" -d "$temp_dir" 2>/dev/null || true

            # 复制 x64 版本的 DLL
            if [[ -f "$temp_dir/runtimes/win-x64/native/WebView2Loader.dll" ]]; then
                cp "$temp_dir/runtimes/win-x64/native/WebView2Loader.dll" "$build_dir/"
                echo "  ✓ WebView2Loader.dll"
            else
                echo "  ⚠️  WebView2Loader.dll 提取失败"
            fi

            # 清理临时文件
            rm -rf "$temp_dir"
        fi
    fi

    cp "$PROJECT_ROOT/server/config.toml" "$build_dir/"
    echo "  ✓ config.toml"

    # 创建启动脚本
    if [[ "$platform" == "windows" ]]; then
        create_windows_scripts "$build_dir" "$is_headless"
    else
        create_unix_scripts "$build_dir" "$is_headless"
    fi

    echo ""
    echo "✅ $platform 编译完成: $build_dir"

    # Windows 平台：创建 zip 压缩包
    if [[ "$platform" == "windows" ]]; then
        echo ""
        echo "创建 Windows 发布包..."
        cd "$PROJECT_ROOT/build/release"
        if command -v zip &> /dev/null; then
            zip -r "phantom-p2p-windows-x64.zip" windows/ >/dev/null
            echo "✅ 已创建: build/release/phantom-p2p-windows-x64.zip"
        else
            echo "⚠️  未找到 zip 命令，跳过打包"
        fi
        cd "$PROJECT_ROOT"
    fi
}

# 创建 Unix 启动脚本
create_unix_scripts() {
    local build_dir=$1
    local is_headless=${2:-false}

    cat > "$build_dir/start-server.sh" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
./phantom-server
EOF
    chmod +x "$build_dir/start-server.sh"
    echo "  ✓ start-server.sh"

    if [[ "$is_headless" == "true" ]]; then
        # Headless 模式：启动 Web 客户端
        cat > "$build_dir/start-client.sh" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
echo "=========================================="
echo "Phantom P2P - Web 客户端模式"
echo "=========================================="
echo ""
./phantom-p2p-web --bind 0.0.0.0:8080 "$@"
EOF
        chmod +x "$build_dir/start-client.sh"
        echo "  ✓ start-client.sh (Web 模式)"

        cat > "$build_dir/README.txt" << 'EOF'
幻梦P2P - Linux Headless 版本
==================

文件说明:
- phantom-server: 信令服务器
- phantom-p2p-web: Web 客户端（无图形界面）
- dist/: 前端 UI 资源
- config.toml: 服务器配置文件

使用方法:
1. 启动服务器: ./start-server.sh
2. 启动 Web 客户端: ./start-client.sh
3. 在浏览器访问: http://服务器IP:8080

自定义端口:
./phantom-p2p-web --bind 0.0.0.0:9000

开发者模式:
./phantom-p2p-web --bind 0.0.0.0:8080 --verbose

配置说明:
- 编辑 config.toml 修改服务器配置
- 信令端口: 10209
- QUIC 中继端口: 10990-11090
- UDP 中继端口: 11091-11191
- Web UI 端口: 8080（可自定义）

防火墙设置:
- 需要开放端口 10209（信令）
- 需要开放端口 10990-11090（QUIC 中继）
- 需要开放端口 11091-11191（UDP 中继）
- 需要开放端口 8080（Web UI，可自定义）

适用场景:
- 无图形界面的 Linux 服务器
- 通过浏览器访问 P2P 客户端
- 支持局域网内多设备访问
EOF
    else
        # 桌面模式：启动 Tauri 客户端
        cat > "$build_dir/start-client.sh" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
./phantom-p2p "$@"
EOF
        chmod +x "$build_dir/start-client.sh"
        echo "  ✓ start-client.sh"

        cat > "$build_dir/README.txt" << 'EOF'
幻梦P2P - Linux Desktop 版本
==================

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
    fi
    echo "  ✓ README.txt"
}

# 创建 Windows 启动脚本
create_windows_scripts() {
    local build_dir=$1

    cat > "$build_dir/start-server.bat" << 'EOF'
@echo off
cd /d "%~dp0"
phantom-server.exe
pause
EOF
    echo "  ✓ start-server.bat"

    cat > "$build_dir/start-client.bat" << 'EOF'
@echo off
cd /d "%~dp0"
phantom-p2p.exe %*
EOF
    echo "  ✓ start-client.bat"

    cat > "$build_dir/README.txt" << 'EOF'
幻梦P2P - Windows 版本
==================

文件说明:
- phantom-server.exe: 信令服务器
- phantom-p2p.exe: 客户端程序
- WebView2Loader.dll: WebView2 加载器（客户端依赖）
- config.toml: 服务器配置文件
- start-server.bat: 启动服务器脚本
- start-client.bat: 启动客户端脚本

使用方法:
1. 启动服务器: 双击 start-server.bat
2. 启动客户端: 双击 start-client.bat
3. 开发者模式: start-client.bat --dev

配置说明:
- 编辑 config.toml 修改服务器配置
- 信令端口: 10209
- QUIC 中继端口: 10990-11090
- UDP 中继端口: 11091-11191

防火墙设置:
- 需要开放端口 10209（信令）
- 需要开放端口 10990-11090（QUIC 中继）
- 需要开放端口 11091-11191（UDP 中继）

注意事项:
- 服务器程序 (phantom-server.exe) 可以直接运行
- 客户端程序需要 Microsoft Edge WebView2 运行时
- Windows 10/11 通常已预装 WebView2
- 如果客户端无法启动，请安装 WebView2 运行时:
  https://developer.microsoft.com/microsoft-edge/webview2/
EOF
    echo "  ✓ README.txt"
}

# 检查依赖
check_dependencies() {
    echo "检查编译依赖..."

    if ! command -v rustc &> /dev/null; then
        echo "❌ 未找到 Rust 工具链，请先安装: https://rustup.rs/"
        exit 1
    fi

    echo "✓ Rust 版本: $(rustc --version)"
    echo "✓ Cargo 版本: $(cargo --version)"

    # 检查 Linux 交叉编译工具
    if [[ "$1" == "linux"* ]] || [[ "$1" == "all" ]]; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS 上交叉编译 Linux 非常复杂，不推荐
            echo ""
            echo "⚠️  在 macOS 上交叉编译 Linux 需要完整的工具链，配置复杂"
            echo ""
            echo "推荐方案："
            echo "  1. 在 Linux 机器上直接构建（最简单）"
            echo "  2. 使用 Docker 构建："
            echo "     docker run --rm -v \"\$PWD\":/app -w /app rust:latest bash -c \\"
            echo "       apt-get update && apt-get install -y nodejs npm && \\"
            echo "       npm run build && \\"
            echo "       cargo build --release -p phantom-p2p-web\""
            echo "  3. 使用 GitHub Actions 自动构建"
            echo ""
            echo "如果你在 macOS 上，建议先构建 macOS 版本测试："
            echo "  ./build-cross.sh macos"
            echo ""
            read -p "是否继续尝试交叉编译? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
            # Linux 上编译 Linux（本地编译，不需要交叉工具）
            echo "✓ 本地 Linux 编译"
        fi
    fi

    # 检查 Windows 交叉编译工具
    if [[ "$1" == "windows" ]] || [[ "$1" == "all" ]]; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
                echo ""
                echo "⚠️  Windows 交叉编译需要 MinGW-w64"
                echo "   安装命令: brew install mingw-w64"
                read -p "是否继续? (y/n) " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    exit 1
                fi
            fi
        elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
            if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
                echo ""
                echo "⚠️  Windows 交叉编译需要 MinGW-w64"
                echo "   Ubuntu/Debian: sudo apt install mingw-w64"
                echo "   CentOS/RHEL: sudo yum install mingw64-gcc"
                read -p "是否继续? (y/n) " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    exit 1
                fi
            fi
        fi
    fi
}

# 主函数
main() {
    local target_platform=${1:-}

    if [[ -z "$target_platform" ]]; then
        show_usage
        exit 1
    fi

    check_dependencies "$target_platform"

    if ! command -v node &> /dev/null; then
        echo "ERROR: node was not found in PATH"
        exit 1
    fi
    if [[ "${PHANTOM_SKIP_VERSION_BUMP:-0}" == "1" ]]; then
        node "$PROJECT_ROOT/tools/version.mjs" check
    else
        node "$PROJECT_ROOT/tools/version.mjs" bump
    fi

    case "$target_platform" in
        macos)
            build_target "x86_64-apple-darwin" "macos" false
            ;;
        macos-arm)
            build_target "aarch64-apple-darwin" "macos-arm" false
            ;;
        linux)
            build_target "x86_64-unknown-linux-gnu" "linux" false
            ;;
        linux-musl)
            build_target "x86_64-unknown-linux-musl" "linux-musl" false
            ;;
        linux-headless)
            # macOS 上交叉编译 Linux Headless，使用 musl
            if [[ "$OSTYPE" == "darwin"* ]]; then
                build_target "x86_64-unknown-linux-musl" "linux-headless" true
            else
                # Linux 上本地编译
                build_target "x86_64-unknown-linux-gnu" "linux-headless" true
            fi
            ;;
        windows)
            build_target "x86_64-pc-windows-gnu" "windows" false
            ;;
        all)
            # 根据当前系统选择编译目标
            if [[ "$OSTYPE" == "darwin"* ]]; then
                build_target "x86_64-apple-darwin" "macos" false
                build_target "aarch64-apple-darwin" "macos-arm" false
                # macOS 上交叉编译 Linux 使用 musl
                build_target "x86_64-unknown-linux-musl" "linux-headless" true
            else
                # Linux 上本地编译
                build_target "x86_64-unknown-linux-gnu" "linux" false
                build_target "x86_64-unknown-linux-gnu" "linux-headless" true
            fi
            build_target "x86_64-pc-windows-gnu" "windows" false
            ;;
        *)
            echo "❌ 不支持的目标平台: $target_platform"
            echo ""
            show_usage
            exit 1
            ;;
    esac

    echo ""
    echo "=========================================="
    echo "✅ 所有编译任务完成!"
    echo "=========================================="
    echo "输出目录: $PROJECT_ROOT/build/release/"
    ls -lh "$PROJECT_ROOT/build/release/"
}

main "$@"
