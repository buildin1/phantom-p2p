#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let dev_mode = std::env::args().any(|a| a == "--dev");
    phantom_p2p_lib::run(dev_mode)
}
