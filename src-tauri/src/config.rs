pub use phantom_core::config::*;

#[tauri::command]
pub fn load_config() -> ClientConfig {
    let mut cfg = ClientConfig::load();
    cfg.apply_mode_policy();
    cfg
}

#[tauri::command]
pub fn save_config(mut config: ClientConfig) -> Result<(), String> {
    config.apply_mode_policy();
    config.save().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_config_path() -> String {
    ClientConfig::config_path().to_string_lossy().to_string()
}
