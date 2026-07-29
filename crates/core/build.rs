use std::fs;
use std::path::Path;

/// Reads the repo-root `official.env` file and injects a single
/// `OFFICIAL_SIGNAL_SERVER` compile-time env var (e.g. `ws://qx.coreyuan.cn:10112`)
/// so `USER_MODE_SIGNAL_SERVER` in `src/config.rs` doesn't have to hardcode the
/// official signaling address as a string literal.
///
/// `build.rs` runs with its working directory set to the crate root
/// (`crates/core`), so the repo root is two levels up: `crates/core` ->
/// `crates` -> `<repo root>`.
fn main() {
    let env_path = Path::new("../../official.env");
    println!("cargo:rerun-if-changed=../../official.env");

    let contents = fs::read_to_string(env_path).unwrap_or_else(|err| {
        panic!(
            "failed to read official.env at {} (relative to crates/core): {err}\n\
             This file must exist at the repository root with OFFICIAL_SIGNAL_SCHEME, \
             OFFICIAL_SIGNAL_HOST and OFFICIAL_SIGNAL_PORT set.",
            env_path.display()
        )
    });

    let mut scheme: Option<String> = None;
    let mut host: Option<String> = None;
    let mut port: Option<String> = None;

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        match key {
            "OFFICIAL_SIGNAL_SCHEME" => scheme = Some(value.to_string()),
            "OFFICIAL_SIGNAL_HOST" => host = Some(value.to_string()),
            "OFFICIAL_SIGNAL_PORT" => port = Some(value.to_string()),
            _ => {}
        }
    }

    let scheme = scheme.unwrap_or_else(|| "ws".to_string());
    let host = host.unwrap_or_else(|| {
        panic!("official.env is missing OFFICIAL_SIGNAL_HOST");
    });
    let port = port.unwrap_or_else(|| {
        panic!("official.env is missing OFFICIAL_SIGNAL_PORT");
    });

    let url = format!("{scheme}://{host}:{port}");
    println!("cargo:rustc-env=OFFICIAL_SIGNAL_SERVER={url}");
}
