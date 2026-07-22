#!/bin/bash

# 测试 dev 模式是否工作

echo "=== 测试 1: 检查 --dev 参数传递 ==="
cd "/Users/buildin1/Desktop/小说/book/p2p/修复清单/第14阶段/phantom-p2p"

# 启动应用（dev 模式）
echo "启动应用（带 --dev 参数）..."
./target/release/phantom-p2p --dev &
APP_PID=$!
sleep 3

# 检查进程是否运行
if ps -p $APP_PID > /dev/null; then
    echo "✓ 应用已启动 (PID: $APP_PID)"
else
    echo "✗ 应用启动失败"
    exit 1
fi

# 等待用户手动检查
echo ""
echo "请手动检查以下内容："
echo "1. 打开应用，进入「创建房间」页面"
echo "2. 检查是否显示黄色的「开发者选项」区域"
echo "3. 检查是否有「强制中继模式」复选框"
echo ""
echo "按 Enter 继续测试，或 Ctrl+C 退出..."
read

# 清理
kill $APP_PID 2>/dev/null
echo "应用已关闭"

echo ""
echo "=== 测试 2: 检查 is_dev_mode 命令 ==="
echo "需要在应用运行时，在浏览器控制台执行："
echo "  await window.__TAURI__.invoke('is_dev_mode')"
echo "应该返回: true"
