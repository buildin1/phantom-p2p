use jni::objects::{GlobalRef, JByteArray, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jlong};
use jni::{JNIEnv, JavaVM};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use phantom_core::tunnel::{
    build_relay_client_config, create_guest_connection, create_host_endpoint,
};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc;

mod session;

static NEXT_HANDLE: AtomicI64 = AtomicI64::new(1);
static NEXT_STREAM: AtomicI64 = AtomicI64::new(1);
pub(crate) static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    // 2 个 worker 线程在 relay 场景下容易被同步 JNI 回调（见 ip_packet）和
    // block_on 调用叠加占满，导致整个 Runtime 上所有连接一起卡死。
    // 提升到 4 个线程：在典型 Android 设备（4核以上）上开销可接受，
    // 同时显著降低"两个线程都被阻塞"的概率。
    Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .thread_name("phantom-mobile")
        .build()
        .expect("create phantom mobile tokio runtime")
});
static BRIDGES: Lazy<Mutex<HashMap<i64, BridgeState>>> = Lazy::new(|| Mutex::new(HashMap::new()));

struct BridgeState {
    _endpoint: Option<quinn::Endpoint>,
    connection: quinn::Connection,
    callback: Arc<NativeCallback>,
    streams: HashMap<i64, StreamState>,
    // One writer per QUIC PIP1 stream. A Host may have several Guest
    // streams, so packets must be broadcast to every live peer.
    packet_writers: Vec<mpsc::UnboundedSender<Vec<u8>>>,
}

struct StreamState {
    writer: mpsc::UnboundedSender<Vec<u8>>,
}

struct NativeCallback {
    vm: JavaVM,
    object: GlobalRef,
}

impl NativeCallback {
    fn ip_packet(&self, data: &[u8]) {
        let Ok(mut env) = self.vm.attach_current_thread() else {
            return;
        };
        let Ok(array) = env.byte_array_from_slice(data) else {
            return;
        };
        let array_obj = JObject::from(array);
        let _ = env.call_method(
            self.object.as_obj(),
            "onNativeIpPacket",
            "([B)V",
            &[JValue::Object(&array_obj)],
        );
    }
}
impl NativeCallback {
    fn tcp_data(&self, stream_id: i64, data: &[u8]) {
        let Ok(mut env) = self.vm.attach_current_thread() else {
            return;
        };
        let Ok(array) = env.byte_array_from_slice(data) else {
            return;
        };
        let array_obj = JObject::from(array);
        let _ = env.call_method(
            self.object.as_obj(),
            "onNativeTcpData",
            "(J[B)V",
            &[JValue::Long(stream_id), JValue::Object(&array_obj)],
        );
    }

    fn tcp_closed(&self, stream_id: i64) {
        let Ok(mut env) = self.vm.attach_current_thread() else {
            return;
        };
        let _ = env.call_method(
            self.object.as_obj(),
            "onNativeTcpClosed",
            "(J)V",
            &[JValue::Long(stream_id)],
        );
    }

    fn inbound_tcp_stream(&self, stream_id: i64, target_port: u16) {
        let Ok(mut env) = self.vm.attach_current_thread() else {
            return;
        };
        let _ = env.call_method(
            self.object.as_obj(),
            "onNativeInboundTcpStream",
            "(JI)V",
            &[JValue::Long(stream_id), JValue::Int(target_port as i32)],
        );
    }
}

#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_data_NativeQuicStreamBridge_nativeCreateBridge(
    env: JNIEnv,
    this: JObject,
    mode: JString,
    endpoint: JString,
    relay_token: JString,
    local_port: jint,
    is_guest: jboolean,
) -> jlong {
    let result = catch_unwind(AssertUnwindSafe(|| {
        native_create_bridge_inner(env, this, mode, endpoint, relay_token, local_port, is_guest)
    }));
    result.unwrap_or(0)
}

#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_data_NativePacketBridge_nativeCreateBridge(
    env: JNIEnv,
    this: JObject,
    mode: JString,
    endpoint: JString,
    relay_token: JString,
    local_port: jint,
    is_guest: jboolean,
) -> jlong {
    let result = catch_unwind(AssertUnwindSafe(|| {
        native_create_bridge_inner(env, this, mode, endpoint, relay_token, local_port, is_guest)
    }));
    result.unwrap_or(0)
}

fn native_create_bridge_inner(
    mut env: JNIEnv,
    this: JObject,
    mode: JString,
    endpoint: JString,
    relay_token: JString,
    local_port: jint,
    is_guest: jboolean,
) -> jlong {
    let mode = match env.get_string(&mode) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(_) => return 0,
    };
    let endpoint = match env.get_string(&endpoint) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(_) => return 0,
    };
    let relay_token = match env.get_string(&relay_token) {
        Ok(value) => value.to_string_lossy().into_owned(),
        Err(_) => return 0,
    };
    if mode != "p2p" && mode != "relay" {
        throw_illegal_state(env, "unsupported native QUIC bridge mode");
        return 0;
    }

    let Ok(peer_addr) = endpoint.parse::<SocketAddr>() else {
        return 0;
    };
    let Ok(socket) = bind_udp_socket(local_port) else {
        return 0;
    };
    if !protect_socket(&mut env, &this, &socket) {
        return 0;
    }
    let Ok(vm) = env.get_java_vm() else {
        return 0;
    };
    let Ok(object) = env.new_global_ref(this) else {
        return 0;
    };

    let (endpoint_keepalive, connection) = if mode == "p2p" && is_guest != 0 {
        match RUNTIME.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(12),
                create_guest_connection(socket, peer_addr),
            )
            .await
        }) {
            Ok(Ok(connection)) => (None, connection),
            _ => return 0,
        }
    } else if mode == "p2p" {
        match create_host_endpoint(socket) {
            Ok(endpoint) => {
                let accepted = RUNTIME.block_on(async {
                    tokio::time::timeout(Duration::from_secs(90), async {
                        let incoming = endpoint.accept().await.ok_or("accept failed")?;
                        incoming.await.map_err(|_| "handshake failed")
                    })
                    .await
                });
                match accepted {
                    Ok(Ok(connection)) => (Some(endpoint), connection),
                    _ => return 0,
                }
            }
            Err(_) => return 0,
        }
    } else {
        match RUNTIME.block_on(connect_relay(socket, peer_addr, relay_token, is_guest != 0)) {
            Ok(connection) => (None, connection),
            Err(_) => return 0,
        }
    };

    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    BRIDGES.lock().insert(
        handle,
        BridgeState {
            _endpoint: endpoint_keepalive,
            connection,
            callback: Arc::new(NativeCallback { vm, object }),
            streams: HashMap::new(),
            packet_writers: Vec::new(),
        },
    );
    let callback = BRIDGES
        .lock()
        .get(&handle)
        .map(|bridge| bridge.callback.clone());
    let connection = BRIDGES
        .lock()
        .get(&handle)
        .map(|bridge| bridge.connection.clone());
    if let (Some(callback), Some(connection)) = (callback, connection) {
        RUNTIME.spawn(accept_inbound_streams(handle, connection, callback.clone()));
        if mode == "p2p" && is_guest == 0 {
            let endpoint = BRIDGES
                .lock()
                .get(&handle)
                .and_then(|bridge| bridge._endpoint.clone());
            if let Some(endpoint) = endpoint {
                RUNTIME.spawn(accept_additional_connections(handle, endpoint, callback));
            }
        }
    }
    handle as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_data_NativePacketBridge_nativeStartPacketStream(
    env: JNIEnv,
    _this: JObject,
    handle: jlong,
) -> jboolean {
    let (connection, callback) = {
        let bridges = BRIDGES.lock();
        let Some(bridge) = bridges.get(&(handle as i64)) else {
            return 0;
        };
        (bridge.connection.clone(), bridge.callback.clone())
    };
    let opened = RUNTIME.block_on(async {
        tokio::time::timeout(Duration::from_secs(12), connection.open_bi()).await
    });
    let (mut send, mut recv) = match opened {
        Ok(Ok(streams)) => streams,
        _ => return 0,
    };
    if RUNTIME.block_on(send.write_all(b"PIP1")).is_err() {
        return 0;
    }
    let (writer, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    RUNTIME.spawn(async move {
        while let Some(packet) = rx.recv().await {
            if packet.len() < 20 || packet.len() > 65535 {
                continue;
            }
            if send
                .write_all(&(packet.len() as u16).to_be_bytes())
                .await
                .is_err()
                || send.write_all(&packet).await.is_err()
            {
                break;
            }
        }
        let _ = send.finish();
    });
    let read_callback = callback.clone();
    RUNTIME.spawn(async move {
        let mut len = [0u8; 2];
        loop {
            if recv.read_exact(&mut len).await.is_err() {
                break;
            }
            let size = u16::from_be_bytes(len) as usize;
            if !(20..=65535).contains(&size) {
                break;
            }
            let mut packet = vec![0u8; size];
            if recv.read_exact(&mut packet).await.is_err() {
                break;
            }
            // ip_packet() 内部是同步阻塞的 JNI 调用（attach_current_thread + call_method），
            // 直接在 async worker 线程上执行会占用 RUNTIME 的宝贵线程；
            // 用 spawn_blocking 移到专用阻塞线程池执行，await 该 JoinHandle 不会阻塞 worker。
            let cb = read_callback.clone();
            let _ = tokio::task::spawn_blocking(move || cb.ip_packet(&packet)).await;
        }
    });
    if let Some(bridge) = BRIDGES.lock().get_mut(&(handle as i64)) {
        bridge.packet_writers.push(writer);
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_data_NativePacketBridge_nativeWritePacket(
    mut env: JNIEnv,
    _this: JObject,
    handle: jlong,
    data: JByteArray,
) {
    let Some(data) = byte_array_to_vec(&mut env, data) else {
        return;
    };
    if let Some(bridge) = BRIDGES.lock().get_mut(&(handle as i64)) {
        bridge.packet_writers.retain(|writer| !writer.is_closed());
        for writer in &bridge.packet_writers {
            let _ = writer.send(data.clone());
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_data_NativeQuicStreamBridge_nativeOpenTcpStream(
    env: JNIEnv,
    _this: JObject,
    handle: jlong,
    target_port: jint,
) -> jlong {
    if target_port <= 0 || target_port > 65535 {
        throw_illegal_state(env, "invalid target port");
        return 0;
    }

    let (connection, callback) = {
        let bridges = BRIDGES.lock();
        let Some(bridge) = bridges.get(&(handle as i64)) else {
            return 0;
        };
        (bridge.connection.clone(), bridge.callback.clone())
    };

    let opened = RUNTIME.block_on(async {
        tokio::time::timeout(Duration::from_secs(8), connection.open_bi()).await
    });
    let (mut send, mut recv) = match opened {
        Ok(Ok(streams)) => streams,
        _ => return 0,
    };

    let port_header = (target_port as u16).to_be_bytes();
    if RUNTIME.block_on(send.write_all(&port_header)).is_err() {
        let _ = send.finish();
        return 0;
    }

    let stream_id = NEXT_STREAM.fetch_add(1, Ordering::Relaxed);
    let (writer, mut receiver) = mpsc::unbounded_channel::<Vec<u8>>();
    RUNTIME.spawn(async move {
        while let Some(data) = receiver.recv().await {
            if send.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = send.finish();
    });

    let read_callback = callback.clone();
    RUNTIME.spawn(async move {
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            match recv.read(&mut buffer).await {
                Ok(Some(n)) if n > 0 => read_callback.tcp_data(stream_id, &buffer[..n]),
                Ok(Some(_)) => continue,
                Ok(None) => break,
                Err(_) => break,
            }
        }
        read_callback.tcp_closed(stream_id);
    });

    let mut bridges = BRIDGES.lock();
    let Some(bridge) = bridges.get_mut(&(handle as i64)) else {
        return 0;
    };
    bridge.streams.insert(stream_id, StreamState { writer });
    stream_id as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_data_NativeQuicStreamBridge_nativeWriteTcpStream(
    mut env: JNIEnv,
    _this: JObject,
    handle: jlong,
    stream_id: jlong,
    data: JByteArray,
) {
    let Some(data) = byte_array_to_vec(&mut env, data) else {
        throw_illegal_state(env, "invalid byte array");
        return;
    };
    let bridges = BRIDGES.lock();
    let Some(bridge) = bridges.get(&(handle as i64)) else {
        throw_illegal_state(env, "native bridge handle not found");
        return;
    };
    let Some(stream) = bridge.streams.get(&(stream_id as i64)) else {
        throw_illegal_state(env, "native TCP stream not found");
        return;
    };
    if stream.writer.send(data).is_err() {
        throw_illegal_state(env, "native TCP stream is closed");
    }
}

#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_data_NativeQuicStreamBridge_nativeCloseTcpStream(
    _env: JNIEnv,
    _this: JObject,
    handle: jlong,
    stream_id: jlong,
) {
    if let Some(bridge) = BRIDGES.lock().get_mut(&(handle as i64)) {
        bridge.streams.remove(&(stream_id as i64));
    }
}

#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_data_NativeQuicStreamBridge_nativeCloseBridge(
    _env: JNIEnv,
    _this: JObject,
    handle: jlong,
) {
    if let Some(bridge) = BRIDGES.lock().remove(&(handle as i64)) {
        bridge.connection.close(0u32.into(), b"closed");
    }
}

#[no_mangle]
pub extern "system" fn Java_com_buildin1_phantom_1p2p_data_NativePacketBridge_nativeCloseBridge(
    _env: JNIEnv,
    _this: JObject,
    handle: jlong,
) {
    if let Some(bridge) = BRIDGES.lock().remove(&(handle as i64)) {
        bridge.connection.close(0u32.into(), b"closed");
    }
}

fn bind_udp_socket(local_port: i32) -> std::io::Result<UdpSocket> {
    let bind_addr = if local_port > 0 && local_port <= 65535 {
        format!("0.0.0.0:{}", local_port)
    } else {
        "0.0.0.0:0".to_string()
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

async fn connect_relay(
    socket: UdpSocket,
    relay_addr: SocketAddr,
    token: String,
    is_guest: bool,
) -> Result<quinn::Connection, String> {
    let runtime = quinn::default_runtime().ok_or("quinn runtime unavailable")?;
    let mut endpoint =
        quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
            .map_err(|e| e.to_string())?;
    endpoint.set_default_client_config(build_relay_client_config()?);
    let connection = tokio::time::timeout(
        Duration::from_secs(30),
        endpoint
            .connect(relay_addr, "phantom-relay")
            .map_err(|e| e.to_string())?,
    )
    .await
    .map_err(|_| "relay connect timeout".to_string())?
    .map_err(|e| e.to_string())?;
    let (mut send, mut recv) = connection.open_bi().await.map_err(|e| e.to_string())?;
    let role = if is_guest { "guest" } else { "host" };
    send.write_all(format!("{}|{}", role, token).as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;
    let mut response = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(90), recv.read(&mut response))
        .await
        .map_err(|_| "relay pair timeout".to_string())?
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "relay closed".to_string())?;
    if &response[..n] != b"OK" {
        return Err(String::from_utf8_lossy(&response[..n]).to_string());
    }
    Ok(connection)
}

async fn accept_inbound_streams(
    handle: i64,
    connection: quinn::Connection,
    callback: Arc<NativeCallback>,
) {
    loop {
        let Ok((mut send, mut recv)) = connection.accept_bi().await else {
            break;
        };
        let mut header = [0u8; 4];
        if recv.read_exact(&mut header).await.is_err() {
            let _ = send.finish();
            continue;
        }
        if &header == b"PIP1" {
            let (writer, mut packets) = mpsc::unbounded_channel::<Vec<u8>>();
            if let Some(bridge) = BRIDGES.lock().get_mut(&handle) {
                bridge.packet_writers.push(writer);
            }
            RUNTIME.spawn(async move {
                while let Some(packet) = packets.recv().await {
                    if packet.len() < 20 || packet.len() > 65535 {
                        continue;
                    }
                    if send
                        .write_all(&(packet.len() as u16).to_be_bytes())
                        .await
                        .is_err()
                        || send.write_all(&packet).await.is_err()
                    {
                        break;
                    }
                }
                let _ = send.finish();
            });
            let read_callback = callback.clone();
            RUNTIME.spawn(async move {
                let mut len = [0u8; 2];
                loop {
                    if recv.read_exact(&mut len).await.is_err() {
                        break;
                    }
                    let size = u16::from_be_bytes(len) as usize;
                    if !(20..=65535).contains(&size) {
                        break;
                    }
                    let mut packet = vec![0u8; size];
                    if recv.read_exact(&mut packet).await.is_err() {
                        break;
                    }
                    // 同上：避免同步 JNI 回调阻塞 async worker 线程。
                    let cb = read_callback.clone();
                    let _ = tokio::task::spawn_blocking(move || cb.ip_packet(&packet)).await;
                }
            });
            continue;
        }
        let target_port = u16::from_be_bytes([header[0], header[1]]);
        let stream_id = NEXT_STREAM.fetch_add(1, Ordering::Relaxed);
        let (writer, mut receiver) = mpsc::unbounded_channel::<Vec<u8>>();
        if let Some(bridge) = BRIDGES.lock().get_mut(&handle) {
            bridge.streams.insert(stream_id, StreamState { writer });
        }
        callback.inbound_tcp_stream(stream_id, target_port);

        let mut send_stream = send;
        RUNTIME.spawn(async move {
            while let Some(data) = receiver.recv().await {
                if send_stream.write_all(&data).await.is_err() {
                    break;
                }
            }
            let _ = send_stream.finish();
        });

        let read_callback = callback.clone();
        RUNTIME.spawn(async move {
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                match recv.read(&mut buffer).await {
                    Ok(Some(n)) if n > 0 => read_callback.tcp_data(stream_id, &buffer[..n]),
                    Ok(Some(_)) => continue,
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
            BRIDGES
                .lock()
                .get_mut(&handle)
                .map(|bridge| bridge.streams.remove(&stream_id));
            read_callback.tcp_closed(stream_id);
        });
    }
}

async fn accept_additional_connections(
    handle: i64,
    endpoint: quinn::Endpoint,
    callback: Arc<NativeCallback>,
) {
    while let Some(incoming) = endpoint.accept().await {
        let Ok(connection) = incoming.await else {
            continue;
        };
        RUNTIME.spawn(accept_inbound_streams(handle, connection, callback.clone()));
    }
}

#[cfg(unix)]
fn protect_socket(env: &mut JNIEnv, object: &JObject, socket: &UdpSocket) -> bool {
    match env.call_method(
        object,
        "onProtectSocket",
        "(I)Z",
        &[JValue::Int(socket.as_raw_fd())],
    ) {
        Ok(value) => value.z().unwrap_or(false),
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn protect_socket(_env: &mut JNIEnv, _object: &JObject, _socket: &UdpSocket) -> bool {
    true
}

fn byte_array_to_vec(env: &mut JNIEnv, data: JByteArray) -> Option<Vec<u8>> {
    let len = env.get_array_length(&data).ok()?;
    let mut out = vec![0; len as usize];
    env.get_byte_array_region(data, 0, &mut out).ok()?;
    Some(out.into_iter().map(|value| value as u8).collect())
}

fn throw_illegal_state(mut env: JNIEnv, message: &str) {
    let _ = env.throw_new("java/lang/IllegalStateException", message);
}
