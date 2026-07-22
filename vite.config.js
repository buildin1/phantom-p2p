import { defineConfig } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile";

export default defineConfig({
  clearScreen: false,
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
