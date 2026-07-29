import { defineConfig } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// 官方信令服务器地址：从项目根目录 official.env 读取（OFFICIAL_SIGNAL_SERVER=ws://...），
// 该文件不入库（由打包/发布流程注入），本地开发时若不存在则回退到当前已知的官方地址字面量。
// 前端通过编译期常量 __OFFICIAL_SIGNAL_SERVER__ 引用它，用于和用户自建的信令地址做简单字符串比较，
// 从而区分"官方网络"与"自建/第三方网络"（不涉及密码学身份校验，后者是独立的后续任务）。
function readOfficialSignalServer() {
  const fallback = "ws://qx.coreyuan.cn:10112";
  try {
    const envPath = path.resolve(__dirname, "official.env");
    const content = fs.readFileSync(envPath, "utf-8");
    const match = content.match(/^\s*OFFICIAL_SIGNAL_SERVER\s*=\s*(.+?)\s*$/m);
    if (match) {
      return match[1].trim().replace(/^["']|["']$/g, "");
    }
  } catch {
    // official.env 不存在（例如本地开发或该文件由并行分支引入前）时使用兜底值
  }
  return fallback;
}

const OFFICIAL_SIGNAL_SERVER = readOfficialSignalServer();

export default defineConfig({
  clearScreen: false,
  server: {
    port: 1430,
    strictPort: true,
  },
  envPrefix: ["VITE_", "TAURI_"],
  define: {
    __OFFICIAL_SIGNAL_SERVER__: JSON.stringify(OFFICIAL_SIGNAL_SERVER),
  },
  build: {
    // Tauri 使用 Chromium，不需要支持旧浏览器
    target: ["es2021", "chrome100", "safari13"],
    // 不要压缩太多，方便调试
    minify: !process.env.TAURI_DEBUG ? "esbuild" : false,
    // 生成 sourcemap 方便调试
    sourcemap: !!process.env.TAURI_DEBUG,
  },
  // 关键：设置 base 为相对路径，确保 Tauri 能正确加载资源
  base: "./",
  // 使用单文件插件，将所有资源内联到 HTML 中
  plugins: [viteSingleFile()],
});
