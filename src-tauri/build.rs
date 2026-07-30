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

    // tauri.macos.conf.json 声明的 externalBin sidecar（特权 TUN 提权 helper，
    // 见 crates/core/src/tun_macos.rs）在编译期就会被 tauri_build::build()
    // 校验是否存在，即便只是 `cargo check`。CI 和 build/build-macos.sh 都会在
    // 编译这个 crate 之前先把它编译好、放到该路径下；本地手动 `cargo build`/
    // `cargo tauri dev` 也需要先跑那一步，这里给出清晰的报错而不是让
    // tauri_build 的 "resource path ... doesn't exist" 这种含糊错误直接冒出来。
    #[cfg(target_os = "macos")]
    {
        let target = std::env::var("TARGET").unwrap_or_default();
        let dest =
            std::path::Path::new("binaries").join(format!("phantom-macos-helper-{}", target));
        if !dest.exists() {
            panic!(
                "缺少特权 TUN 提权 helper（{}）。请先编译：\n  \
                 cargo build --release -p macos-helper --target {target}\n  \
                 mkdir -p src-tauri/binaries\n  \
                 cp target/{target}/release/macos-helper {}",
                dest.display(),
                dest.display(),
            );
        }
    }

    tauri_build::build()
}
