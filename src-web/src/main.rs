use clap::Parser;
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod runtime;
mod web_server;

#[derive(Parser, Debug)]
#[command(name = "phantom-p2p")]
#[command(about = "PhantomP2P Linux Headless client with WebUI")]
struct Args {
    /// Local management listener. The same port is also opened on the Host virtual IP.
    #[arg(long, default_value = "0.0.0.0:9080")]
    bind: SocketAddr,

    /// Signaling WebSocket URL (developer mode may override the built-in endpoint).
    /// Defaults to phantom_core::config::USER_MODE_SIGNAL_SERVER when not given
    /// (resolved in `main`, since clap's `#[arg(default_value = ...)]` needs a
    /// string literal and can't reference a const from another crate directly).
    #[arg(long)]
    signal: Option<String>,

    /// Do not create a Host room automatically after authentication.
    #[arg(long)]
    no_auto_room: bool,

    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let filter = if args.verbose {
        "phantom_p2p_web=debug,phantom_core=debug"
    } else {
        "info"
    };
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(filter))
        .with(tracing_subscriber::fmt::layer())
        .init();

    println!("PhantomP2P Linux Headless {}", env!("CARGO_PKG_VERSION"));
    println!("Linux TUN requires root or CAP_NET_ADMIN.");

    let runtime = runtime::HeadlessRuntime::new(args.bind.port())?;
    let signal_arg = args
        .signal
        .unwrap_or_else(|| phantom_core::config::USER_MODE_SIGNAL_SERVER.to_string());
    let signal_url = phantom_core::config::runtime_signal_server(&signal_arg);
    runtime.start(signal_url, !args.no_auto_room).await;
    web_server::start_web_server(args.bind, runtime).await
}
