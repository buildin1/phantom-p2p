//! Virtual L3 overlay over QUIC.
//!
//! The bridge transports complete IPv4 packets. TCP state, UDP state and
//! checksums therefore remain the responsibility of the host OS instead of
//! being reimplemented in an application-level port proxy.

use crate::tun::{Ipv4Header, TunDevice, TunError};
use quinn::{Connection, RecvStream, SendStream};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, warn};

const STREAM_MAGIC: &[u8; 4] = b"PIP1";
const MAX_PACKET: usize = 65535;

/// Time budget for a single QUIC write to a peer's overlay stream. QUIC
/// congestion / flow control can stall `write_all` indefinitely; without a
/// timeout one slow/wedged peer would block the single TUN read loop and
/// starve every other peer sharing this bridge (this is the relay-mode
/// freeze this module used to suffer from).
const PEER_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounded per-peer outbound queue. Packets read from the TUN device are
/// handed off here without waiting on the peer's QUIC stream; a dedicated
/// task per peer performs the actual (potentially slow) write. Bounded so a
/// permanently wedged peer applies backpressure only to itself (the queue
/// fills and new packets for that peer are dropped) instead of unbounded
/// memory growth.
const PEER_QUEUE_DEPTH: usize = 256;

/// A handle to a peer's dedicated forwarding task: send IP packets here and
/// they will be written to the peer's QUIC SendStream by that task, with a
/// bounded write timeout so a stalled peer cannot block anyone else.
#[derive(Clone)]
struct PeerForwarder {
    tx: mpsc::Sender<Vec<u8>>,
}

impl PeerForwarder {
    /// Best-effort enqueue; if the queue is full or the task has exited the
    /// packet is dropped (never blocks the caller).
    fn try_forward(&self, packet: &[u8]) -> bool {
        match self.tx.try_send(packet.to_vec()) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("[TUN] peer queue full, dropping packet");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }
}

/// Spawn the task that owns a peer's SendStream and performs writes off the
/// TUN read loop's critical path.
fn spawn_peer_forwarder(sender: Arc<Mutex<SendStream>>) -> PeerForwarder {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(PEER_QUEUE_DEPTH);
    tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            let len = packet.len() as u16;
            let mut stream = sender.lock().await;
            let write = async {
                stream.write_all(&len.to_be_bytes()).await?;
                stream.write_all(&packet).await
            };
            match tokio::time::timeout(PEER_WRITE_TIMEOUT, write).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    warn!("[TUN] peer stream write failed ({} bytes): {}", packet.len(), e);
                    // The stream is likely broken beyond recovery; stop this
                    // forwarder so future sends are dropped immediately
                    // instead of queueing behind a dead connection.
                    break;
                }
                Err(_) => {
                    warn!(
                        "[TUN] peer stream write timed out after {:?} ({} bytes); dropping packet",
                        PEER_WRITE_TIMEOUT,
                        packet.len()
                    );
                    // Keep the forwarder alive: a single stalled write (e.g.
                    // transient congestion) shouldn't necessarily kill the
                    // peer, but repeated timeouts will keep dropping packets
                    // rather than backing up the queue indefinitely.
                }
            }
        }
    });
    PeerForwarder { tx }
}

type PeerSenders = Arc<Mutex<HashMap<Ipv4Addr, PeerForwarder>>>;

pub struct TunBridge {
    tun: Arc<TunDevice>,
    host_vip: Ipv4Addr,
    my_vip: Ipv4Addr,
    guest_network: Ipv4Addr,
    is_host: bool,
    peers: PeerSenders,
    default_peer: Mutex<Option<PeerForwarder>>,
    closed: std::sync::atomic::AtomicBool,
    tx_packets: AtomicU64,
}

impl TunBridge {
    /// Create a bridge and attach one QUIC connection. Guest uses this form;
    /// Host may use it for the first peer and attach additional peers later.
    pub async fn start(
        subnet_prefix: &str,
        virtual_ip: &str,
        host_virtual_ip: &str,
        quic_conn: Connection,
    ) -> Result<Arc<Self>, TunError> {
        let my_ip: Ipv4Addr = virtual_ip
            .parse()
            .map_err(|_| TunError::CreateFailed(format!("invalid virtual IP {}", virtual_ip)))?;
        let host_ip: Ipv4Addr = host_virtual_ip.parse().map_err(|_| {
            TunError::CreateFailed(format!("invalid Host virtual IP {}", host_virtual_ip))
        })?;
        let guest_network = parse_network(subnet_prefix)?;
        if !same_prefix24(my_ip, guest_network) {
            return Err(TunError::CreateFailed(
                "virtual IP is outside the assigned subnet".into(),
            ));
        }
        let tun_name = adapter_name(my_ip);
        let tun =
            TunDevice::create(&tun_name, my_ip, Ipv4Addr::new(255, 255, 255, 0), 1500).await?;
        if !same_prefix24(host_ip, guest_network) {
            tun.add_route(host_ip, 32).await?;
        }
        let bridge = Self::from_tun(tun, host_ip, my_ip, guest_network, false);
        bridge.attach_peer(quic_conn, None).await?;
        Ok(bridge)
    }

    /// Create a Host bridge before any peer connection exists.
    pub async fn start_host(subnet_prefix: &str, virtual_ip: &str) -> Result<Arc<Self>, TunError> {
        let guest_network = parse_network(subnet_prefix)?;
        let my_ip: Ipv4Addr = virtual_ip.parse().map_err(|_| {
            TunError::CreateFailed(format!("invalid Host virtual IP {}", virtual_ip))
        })?;
        let fixed_host = !same_prefix24(my_ip, guest_network);
        let tun_name = adapter_name(my_ip);
        let netmask = if fixed_host {
            Ipv4Addr::new(255, 255, 255, 255)
        } else {
            Ipv4Addr::new(255, 255, 255, 0)
        };
        let tun = TunDevice::create(&tun_name, my_ip, netmask, 1500).await?;
        if fixed_host {
            tun.add_route(guest_network, 24).await?;
        }
        Ok(Self::from_tun(tun, my_ip, my_ip, guest_network, true))
    }

    fn from_tun(
        tun: TunDevice,
        host_vip: Ipv4Addr,
        my_vip: Ipv4Addr,
        guest_network: Ipv4Addr,
        is_host: bool,
    ) -> Arc<Self> {
        let bridge = Arc::new(Self {
            tun: Arc::new(tun),
            host_vip,
            my_vip,
            guest_network,
            is_host,
            peers: Arc::new(Mutex::new(HashMap::new())),
            default_peer: Mutex::new(None),
            closed: std::sync::atomic::AtomicBool::new(false),
            tx_packets: AtomicU64::new(0),
        });
        let reader = bridge.clone();
        tokio::spawn(async move {
            reader.tun_read_loop().await;
        });
        bridge
    }

    /// Attach a peer's QUIC connection. The optional hint is used until the
    /// first packet reveals the guest virtual source address.
    pub async fn attach_peer(
        &self,
        conn: Connection,
        peer_hint: Option<Ipv4Addr>,
    ) -> Result<(), TunError> {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| TunError::WriteFailed(format!("打开 TUN QUIC 流失败: {}", e)))?;
        send.write_all(STREAM_MAGIC)
            .await
            .map_err(|e| TunError::WriteFailed(format!("写入 TUN 流头失败: {}", e)))?;
        let send = Arc::new(Mutex::new(send));
        let forwarder = spawn_peer_forwarder(send);
        tracing::info!(
            "[TUN] PIP1 stream opened (local={}, peer_hint={:?}, host={})",
            self.my_vip,
            peer_hint,
            self.is_host
        );
        if let Some(ip) = peer_hint {
            self.peers.lock().await.insert(ip, forwarder.clone());
        }
        let mut default = self.default_peer.lock().await;
        if !self.is_host && default.is_none() {
            *default = Some(forwarder.clone());
        }
        drop(default);

        let tun = self.tun.clone();
        let peers = self.peers.clone();
        let sender = forwarder;
        let is_host = self.is_host;
        let host_vip = self.host_vip;
        let guest_network = self.guest_network;
        tokio::spawn(async move {
            if let Err(e) = receive_frames(
                &mut recv,
                tun,
                peers,
                sender,
                is_host,
                host_vip,
                guest_network,
            )
            .await
            {
                debug!("TUN peer stream ended: {}", e);
            }
        });
        Ok(())
    }

    /// Handle a stream accepted by the Host QUIC endpoint after its magic has
    /// already been consumed by the tunnel dispatcher.
    pub async fn handle_peer_stream(
        &self,
        send: SendStream,
        mut recv: RecvStream,
    ) -> Result<(), TunError> {
        let sender = spawn_peer_forwarder(Arc::new(Mutex::new(send)));
        tracing::info!(
            "[TUN] PIP1 stream accepted (local={}, host={})",
            self.my_vip,
            self.is_host
        );
        let mut default = self.default_peer.lock().await;
        if !self.is_host && default.is_none() {
            *default = Some(sender.clone());
        }
        drop(default);
        receive_frames(
            &mut recv,
            self.tun.clone(),
            self.peers.clone(),
            sender,
            self.is_host,
            self.host_vip,
            self.guest_network,
        )
        .await
        .map_err(TunError::ReadFailed)
    }

    async fn tun_read_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; MAX_PACKET];
        while !self.closed.load(std::sync::atomic::Ordering::Relaxed) {
            let n = match self.tun.read_packet(&mut buf).await {
                Ok(n) if n >= 20 => n,
                Ok(_) => continue,
                Err(e) => {
                    warn!("[TUN] read failed: {}", e);
                    break;
                }
            };
            let Some(header) = Ipv4Header::from_bytes(&buf[..n]) else {
                continue;
            };
            let dst = header.destination_addr();
            let src = header.source_addr();
            if src != self.my_vip {
                warn!(
                    "[TUN] dropped packet with non-overlay source {} -> {} (expected {})",
                    src, dst, self.my_vip
                );
                continue;
            }
            let sender = {
                let peers = self.peers.lock().await;
                peers.get(&dst).cloned()
            };
            let sender = match sender {
                Some(sender) => Some(sender),
                None if !self.is_host => self.default_peer.lock().await.clone(),
                None => None,
            };
            if let Some(sender) = sender {
                // Handing off to the peer's dedicated forwarder task keeps
                // this loop non-blocking: the actual (possibly slow) QUIC
                // write happens elsewhere, under its own timeout, so a
                // single wedged peer can no longer starve every other peer
                // sharing this bridge.
                if sender.try_forward(&buf[..n]) {
                    let count = self.tx_packets.fetch_add(1, Ordering::Relaxed) + 1;
                    if count <= 100 || count % 1000 == 0 {
                        tracing::info!(
                            "[TUN] tx #{} {} -> {} {} bytes={}",
                            count,
                            src,
                            dst,
                            packet_protocol(&buf[..n]),
                            n
                        );
                    }
                } else {
                    warn!(
                        "[TUN] peer forward queue rejected packet {} -> {} ({} bytes)",
                        src, dst, n
                    );
                }
            } else {
                warn!(
                    "[TUN] no peer route for {} -> {} ({} bytes, host={})",
                    src, dst, n, self.is_host
                );
            }
        }
    }

    pub async fn close(&self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.tun.close().await;
    }

    pub fn host_vip(&self) -> Ipv4Addr {
        self.host_vip
    }
    pub fn my_vip(&self) -> Ipv4Addr {
        self.my_vip
    }
}

async fn receive_frames(
    recv: &mut RecvStream,
    tun: Arc<TunDevice>,
    peers: PeerSenders,
    sender: PeerForwarder,
    is_host: bool,
    host_vip: Ipv4Addr,
    guest_network: Ipv4Addr,
) -> Result<(), String> {
    loop {
        let len = recv.read_u16().await.map_err(|e| e.to_string())? as usize;
        if !(20..=MAX_PACKET).contains(&len) {
            return Err(format!("invalid packet length {}", len));
        }
        let mut packet = vec![0u8; len];
        recv.read_exact(&mut packet)
            .await
            .map_err(|e| e.to_string())?;
        let Some(header) = Ipv4Header::from_bytes(&packet) else {
            continue;
        };
        let source = header.source_addr();
        let valid_source = if is_host {
            source != host_vip && same_prefix24(source, guest_network)
        } else {
            source == host_vip
        };
        if !valid_source {
            warn!(
                "[TUN] rejected virtual packet source {} (host={}, expected host={})",
                source, is_host, host_vip
            );
            continue;
        }
        // A virtual IP may be reused after a Guest reconnects or switches
        // transport. Always let the newest authenticated stream own the route;
        // retaining the first sender would black-hole replies into a closed
        // QUIC connection.
        peers.lock().await.insert(source, sender.clone());
        tun.write_packet(&packet).await.map_err(|e| {
            format!(
                "Wintun write {} -> {} ({} bytes): {}",
                source,
                header.destination_addr(),
                len,
                e
            )
        })?;
        let count = tun_rx_counter(&tun, &peers, &sender, is_host);
        if count <= 100 || count % 1000 == 0 {
            tracing::info!(
                "[TUN] rx #{} {} -> {} {} bytes={}",
                count,
                source,
                header.destination_addr(),
                packet_protocol(&packet),
                len
            );
        }
    }
}

fn packet_protocol(packet: &[u8]) -> String {
    let Some(header) = Ipv4Header::from_bytes(packet) else {
        return "invalid-ipv4".to_string();
    };
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    match header.protocol {
        6 if packet.len() >= header_len + 20 => {
            let src_port = u16::from_be_bytes([packet[header_len], packet[header_len + 1]]);
            let dst_port = u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
            let flags = packet[header_len + 13];
            format!("tcp {}->{} flags=0x{:02x}", src_port, dst_port, flags)
        }
        17 if packet.len() >= header_len + 8 => {
            let src_port = u16::from_be_bytes([packet[header_len], packet[header_len + 1]]);
            let dst_port = u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
            format!("udp {}->{}", src_port, dst_port)
        }
        protocol => format!("proto={}", protocol),
    }
}

// Kept separate from packet routing so the receive path remains allocation-free.
fn tun_rx_counter(
    _tun: &Arc<TunDevice>,
    _peers: &PeerSenders,
    _sender: &PeerForwarder,
    _is_host: bool,
) -> u64 {
    // receive_frames is shared by host and guest and predates per-bridge state;
    // the log counter is process-local and only used for diagnostics.
    static COUNT: AtomicU64 = AtomicU64::new(0);
    COUNT.fetch_add(1, Ordering::Relaxed) + 1
}

fn parse_network(prefix: &str) -> Result<Ipv4Addr, TunError> {
    let ip: Ipv4Addr = format!("{}.0", prefix)
        .parse()
        .map_err(|_| TunError::CreateFailed(format!("invalid virtual subnet {}", prefix)))?;
    Ok(ip)
}

fn same_prefix24(ip: Ipv4Addr, network: Ipv4Addr) -> bool {
    ip.octets()[..3] == network.octets()[..3]
}

fn adapter_name(ip: Ipv4Addr) -> String {
    // Linux IFNAMSIZ limits interface names to 15 characters. Keep all four
    // octets so simultaneous rooms cannot collide while staying portable.
    #[cfg(target_os = "linux")]
    {
        let [a, b, c, d] = ip.octets();
        return format!("pp2-{}-{}-{}-{}", a, b, c, d);
    }
    #[cfg(not(target_os = "linux"))]
    {
        format!("PhantomP2P-{}", ip.to_string().replace('.', "-"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_name_is_unique_per_virtual_ip() {
        #[cfg(target_os = "linux")]
        {
            assert_eq!(adapter_name(Ipv4Addr::new(172, 16, 1, 1)), "pp2-172-16-1-1");
            assert!(adapter_name(Ipv4Addr::new(172, 16, 1, 1)).len() <= 15);
            assert_ne!(
                adapter_name(Ipv4Addr::new(172, 16, 1, 1)),
                adapter_name(Ipv4Addr::new(172, 16, 1, 2))
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(
                adapter_name(Ipv4Addr::new(172, 16, 1, 1)),
                "PhantomP2P-172-16-1-1"
            );
            assert_eq!(
                adapter_name(Ipv4Addr::new(172, 16, 1, 2)),
                "PhantomP2P-172-16-1-2"
            );
        }
    }

    #[test]
    fn fixed_host_is_outside_dynamic_guest_subnet() {
        let guest_network = parse_network("172.16.8").unwrap();
        assert!(same_prefix24(Ipv4Addr::new(172, 16, 8, 1), guest_network));
        assert!(!same_prefix24(Ipv4Addr::new(172, 24, 0, 1), guest_network));
    }

    // Regression tests for the relay-mode freeze: forwarding to one peer
    // must never block or fail forwarding to another peer. `PeerForwarder`
    // is exercised directly against a bare mpsc channel here (rather than a
    // real QUIC SendStream) so the non-blocking/backpressure contract can be
    // verified without a network stack.

    #[tokio::test]
    async fn try_forward_is_non_blocking_when_queue_is_full() {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1);
        let forwarder = PeerForwarder { tx };

        // Fill the bounded queue.
        assert!(forwarder.try_forward(b"first"));
        // The queue is now full; try_forward must return immediately with
        // `false` instead of blocking the caller (this is what previously
        // starved every other peer sharing the single TUN read loop).
        assert!(!forwarder.try_forward(b"second"));

        let received = rx.recv().await.expect("first packet should be queued");
        assert_eq!(received, b"first");
    }

    #[tokio::test]
    async fn try_forward_reports_false_once_receiver_is_gone() {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(4);
        drop(rx);
        let forwarder = PeerForwarder { tx };
        assert!(!forwarder.try_forward(b"packet"));
    }

    #[tokio::test]
    async fn independent_peer_queues_do_not_block_each_other() {
        // Two peers sharing a bridge: one has a full/stalled queue, the
        // other must still accept packets without waiting.
        let (stalled_tx, _stalled_rx) = mpsc::channel::<Vec<u8>>(1);
        let stalled = PeerForwarder { tx: stalled_tx };
        assert!(stalled.try_forward(b"a")); // fills the only slot
        assert!(!stalled.try_forward(b"b")); // now full, must not block

        let (healthy_tx, mut healthy_rx) = mpsc::channel::<Vec<u8>>(4);
        let healthy = PeerForwarder { tx: healthy_tx };
        assert!(healthy.try_forward(b"c"));
        assert_eq!(healthy_rx.recv().await.unwrap(), b"c");
    }
}
