//! Tiny privileged helper spawned (via `osascript ... with administrator
//! privileges`) by `crates/core/src/tun_macos.rs` on macOS.
//!
//! It does exactly one thing: call the root-only `provision()` step
//! (open the utun control socket, connect it to a free unit, assign its
//! address/MTU via `ifconfig`), then hand the resulting fd back to the
//! unprivileged GUI process over a Unix domain socket (`SCM_RIGHTS`, via
//! `passfd`) whose path is passed as argv[1]. This keeps the long-running
//! GUI process itself unprivileged -- see the module doc comment in
//! `tun_macos.rs` for why that matters (root Cocoa/WebView processes are
//! laggy and can't be minimized/full-screened).
//!
//! Wire protocol (see `tun_macos.rs` for the client side): one status
//! byte (1 = ok, 0 = error), then either the fd (via `send_fd`, ok case)
//! followed by the interface name as UTF-8 text until EOF, or the error
//! message as UTF-8 text until EOF (error case).

#[cfg(target_os = "macos")]
fn run() -> Result<(), String> {
    use std::io::Write;
    use std::net::Ipv4Addr;
    use std::os::unix::net::UnixStream;

    let mut args = std::env::args().skip(1);
    let socket_path = args.next().ok_or("missing socket path argument")?;
    let address: Ipv4Addr = args
        .next()
        .ok_or("missing address argument")?
        .parse()
        .map_err(|e| format!("invalid address: {}", e))?;
    let netmask: Ipv4Addr = args
        .next()
        .ok_or("missing netmask argument")?
        .parse()
        .map_err(|e| format!("invalid netmask: {}", e))?;
    let mtu: u16 = args
        .next()
        .ok_or("missing mtu argument")?
        .parse()
        .map_err(|e| format!("invalid mtu: {}", e))?;

    let mut stream =
        UnixStream::connect(&socket_path).map_err(|e| format!("connect to GUI failed: {}", e))?;

    match phantom_core::tun::macos_provision_tun(address, netmask, mtu) {
        Ok(provisioned) => {
            use passfd::FdPassingExt;
            use std::os::fd::AsRawFd;

            stream
                .write_all(&[1u8])
                .map_err(|e| format!("write status byte failed: {}", e))?;
            stream
                .send_fd(provisioned.fd.as_raw_fd())
                .map_err(|e| format!("send_fd failed: {}", e))?;
            stream
                .write_all(provisioned.name.as_bytes())
                .map_err(|e| format!("write ifname failed: {}", e))?;
            Ok(())
        }
        Err(error) => {
            let _ = stream.write_all(&[0u8]);
            let _ = stream.write_all(error.to_string().as_bytes());
            Err(error.to_string())
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn run() -> Result<(), String> {
    Err("phantom-macos-helper only runs on macOS".to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("phantom-macos-helper: {}", error);
        std::process::exit(1);
    }
}
