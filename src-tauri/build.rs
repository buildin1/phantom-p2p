fn main() {
    // 清理 macOS 在外置卷上自动生成的资源叉文件，防止 tauri_build 读取失败
    for dir in &["capabilities", "icons"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.to_string_lossy().starts_with("._") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }

    tauri_build::build()
}
