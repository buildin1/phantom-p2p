import { defineConfig } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

// 读取根目录 official.env，拼出官方信令地址，编译期注入到前端常量
// __OFFICIAL_SIGNAL_SERVER__ 里，避免在 src/main.js 里重复手写字面量。
function readOfficialSignalServer() {
  const rootDir = path.dirname(fileURLToPath(import.meta.url));
  const envPath = path.join(rootDir, "official.env");
  const raw = readFileSync(envPath, "utf-8");
  const values = {};
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const idx = trimmed.indexOf("=");
    if (idx === -1) continue;
    const key = trimmed.slice(0, idx).trim();
    const value = trimmed.slice(idx + 1).trim().replace(/^"|"$/g, "");
    values[key] = value;
  }
  const scheme = values.OFFICIAL_SIGNAL_SCHEME || "ws";
  const host = values.OFFICIAL_SIGNAL_HOST;
  const port = values.OFFICIAL_SIGNAL_PORT;
  if (!host || !port) {
    throw new Error(
      `official.env at ${envPath} must define OFFICIAL_SIGNAL_HOST and OFFICIAL_SIGNAL_PORT`
    );
  }
  return `${scheme}://${host}:${port}`;
}

const OFFICIAL_SIGNAL_SERVER = readOfficialSignalServer();

export default defineConfig({
  clearScreen: false,
  define: {
    __OFFICIAL_SIGNAL_SERVER__: JSON.stringify(OFFICIAL_SIGNAL_SERVER),
  },
  server: {
    port: 1430,
    strictPort: true,
  },
  envPrefix: ["VITE_", "TAURI_"],
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
