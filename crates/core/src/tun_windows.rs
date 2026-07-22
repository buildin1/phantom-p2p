//! Windows 平台 TUN 实现（基于 wintun.dll 官方事件驱动模式）
//!
//! wintun.dll 需与应用一同分发（位于可执行文件同级目录）。
//! 下载地址: https://www.wintun.net/
//!
//! 遵循官方 example.c 设计：
//! - 专用接收线程 + WintunGetReadWaitEvent + QuitEvent 实现事件驱动
//! - 通过 mpsc 通道将包传给 async 读取方
//! - 使用 iphlpapi CreateUnicastIpAddressEntry 设置 IP

use crate::tun::TunError;
use std::ffi::c_void;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tracing::{info, warn};

// ============================================================
// kernel32 FFI（用于运行时加载 wintun.dll）
// ============================================================

type HMODULE = *mut c_void;

const LOAD_LIBRARY_SEARCH_APPLICATION_DIR: u32 = 0x00000200;
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x00000800;

extern "system" {
    fn LoadLibraryExW(lpLibFileName: *const u16, hFile: HMODULE, dwFlags: u32) -> HMODULE;
    fn GetProcAddress(hModule: HMODULE, lpProcName: *const u8) -> *mut c_void;
    fn GetLastError() -> u32;
}

// ============================================================
// iphlpapi FFI（用于设置 IP 地址）
// ============================================================

#[repr(C)]
struct MIB_UNICASTIPADDRESS_ROW {
    // 仅声明需要使用的字段，其他用 padding
    _pad1: [u8; 8], // InterfaceLuid (64bit) + InterfaceIndex (32bit) = 12 bytes
    _pad2: [u8; 4], // PrefixOrigin + SuffixOrigin + ValidLifetime + PreferredLifetime + SkipAsSource
    _pad3: [u8; 8], // CreationTimeStamp
    // Address 字段: SOCKADDR_INET 最大 28 字节
    si_family: u16, // Address.si_family
    _pad4: [u8; 26],
    OnLinkPrefixLength: u8, // 子网掩码长度
    _pad5: [u8; 3],
    DadState: i32,
    _pad6: [u8; 8],  // ScopeId + ...
    _pad7: [u8; 16], // 剩余对齐
}

extern "system" {
    fn InitializeUnicastIpAddressEntry(Row: *mut MIB_UNICASTIPADDRESS_ROW);
    fn CreateUnicastIpAddressEntry(Row: *const MIB_UNICASTIPADDRESS_ROW) -> u32;
}

// ============================================================
// wintun.dll FFI 定义（运行时动态加载）
// ============================================================

type WintunAdapterHandle = *mut c_void;
type WintunSessionHandle = *mut c_void;

type CreateAdapterFn = unsafe extern "system" fn(
    Name: *const u16,
    TunnelType: *const u16,
    RequestedGuid: *const u16,
) -> WintunAdapterHandle;

type CloseAdapterFn = unsafe extern "system" fn(Adapter: WintunAdapterHandle);

type OpenAdapterFn = unsafe extern "system" fn(Name: *const u16) -> WintunAdapterHandle;

type StartSessionFn =
    unsafe extern "system" fn(Adapter: WintunAdapterHandle, Capacity: u32) -> WintunSessionHandle;

type EndSessionFn = unsafe extern "system" fn(Session: WintunSessionHandle);

type GetAdapterLuidFn = unsafe extern "system" fn(Adapter: WintunAdapterHandle, Luid: *mut i64);

type GetReadWaitEventFn = unsafe extern "system" fn(Session: WintunSessionHandle) -> *mut c_void;

type AllocateSendPacketFn =
    unsafe extern "system" fn(Session: WintunSessionHandle, PacketSize: u32) -> *mut u8;

type SendPacketFn = unsafe extern "system" fn(Session: WintunSessionHandle, Packet: *mut u8);

type ReceivePacketFn =
    unsafe extern "system" fn(Session: WintunSessionHandle, PacketSize: *mut u32) -> *const u8;

type ReleaseReceivePacketFn =
    unsafe extern "system" fn(Session: WintunSessionHandle, Packet: *const u8);

type SetLoggerFn = unsafe extern "system" fn(Logger: *mut c_void);

struct WintunDll {
    _module: std::mem::ManuallyDrop<HMODULE>,
    create_adapter: CreateAdapterFn,
    close_adapter: CloseAdapterFn,
    start_session: StartSessionFn,
    end_session: EndSessionFn,
    get_adapter_luid: GetAdapterLuidFn,
    get_read_wait_event: GetReadWaitEventFn,
    allocate_send_packet: AllocateSendPacketFn,
    send_packet: SendPacketFn,
    receive_packet: ReceivePacketFn,
    release_receive_packet: ReleaseReceivePacketFn,
}

impl WintunDll {
    fn load() -> Result<Self, TunError> {
        unsafe {
            // 优先从可执行文件同级目录加载（绝对路径，默认搜索行为 = 包含 System32，满足 wintun.dll 对 nci.dll 等系统 DLL 的依赖）
            let dll_path = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("wintun.dll")));

            let module = if let Some(ref path) = dll_path {
                let path_wide = to_wstring(path.to_str().unwrap_or("wintun.dll"));
                LoadLibraryExW(
                    path_wide.as_ptr(),
                    std::ptr::null_mut(),
                    0, // 0 = 默认搜索（同 LoadLibraryW），会搜索 System32 满足依赖
                )
            } else {
                std::ptr::null_mut()
            };

            // 如果绝对路径加载失败，回退到搜索应用目录 + System32（与官方 wintun example.c 一致）
            let module = if module.is_null() {
                LoadLibraryExW(
                    to_wstring("wintun.dll").as_ptr(),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            } else {
                module
            };

            if module.is_null() {
                let err = GetLastError();
                return Err(TunError::CreateFailed(format!(
                    "加载 wintun.dll 失败 (GetLastError={})",
                    err
                )));
            }
            let module = std::mem::ManuallyDrop::new(module);

            macro_rules! load_fn {
                ($name:expr, $fn_type:ty) => {{
                    let name_bytes = concat!($name, "\0").as_bytes();
                    let ptr = GetProcAddress(*module, name_bytes.as_ptr());
                    if !ptr.is_null() {
                        std::mem::transmute::<*mut c_void, $fn_type>(ptr)
                    } else {
                        return Err(TunError::CreateFailed(format!(
                            "wintun.dll 中未找到 {}（版本不兼容）。请更新 wintun.dll",
                            $name,
                        )))
                    }
                }};
            }

            Ok(Self {
                _module: module,
                create_adapter: load_fn!("WintunCreateAdapter", CreateAdapterFn),
                close_adapter: load_fn!("WintunCloseAdapter", CloseAdapterFn),
                start_session: load_fn!("WintunStartSession", StartSessionFn),
                end_session: load_fn!("WintunEndSession", EndSessionFn),
                get_adapter_luid: load_fn!("WintunGetAdapterLUID", GetAdapterLuidFn),
                get_read_wait_event: load_fn!("WintunGetReadWaitEvent", GetReadWaitEventFn),
                allocate_send_packet: load_fn!("WintunAllocateSendPacket", AllocateSendPacketFn),
                send_packet: load_fn!("WintunSendPacket", SendPacketFn),
                receive_packet: load_fn!("WintunReceivePacket", ReceivePacketFn),
                release_receive_packet: load_fn!(
                    "WintunReleaseReceivePacket",
                    ReleaseReceivePacketFn
                ),
            })
        }
    }
}

unsafe impl Send for WintunDll {}
unsafe impl Sync for WintunDll {}

/// 将字符串转为以 null 结尾的 UTF-16 宽字符数组
fn to_wstring(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    let mut v: Vec<u16> = std::ffi::OsStr::new(s).encode_wide().collect();
    v.push(0);
    v
}

// ============================================================
// 设置 IP 地址（使用 iphlpapi API，比 netsh 更可靠）
// ============================================================

fn set_ip_address_iphlp(
    name: &str,
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    mtu: u16,
) -> Result<(), TunError> {
    // Wintun exposes a normal Windows interface. Fail hard here: reporting a
    // TUN as ready while its address/route was not installed creates a silent
    // black hole for every packet.
    let cmd = format!(
        "netsh interface ipv4 set address name=\"{}\" source=static addr={} mask={} gateway=none",
        name, address, netmask
    );
    run_command_with_retry(&cmd, &format!("设置地址 {}", address))?;

    // The static /24 address creates its on-link route automatically.
    let mtu_cmd = format!(
        "netsh interface ipv4 set subinterface \"{}\" mtu={} store=active",
        name, mtu
    );
    run_command_with_retry(&mtu_cmd, &format!("设置 MTU {}", mtu))?;
    configure_overlay_firewall(address)?;

    Ok(())
}

fn overlay_firewall_rule_name(address: Ipv4Addr) -> String {
    format!("PhantomP2P Overlay {}", address)
}

fn remove_overlay_firewall(address: Ipv4Addr) {
    let command = format!(
        "netsh advfirewall firewall delete rule name=\"{}\"",
        overlay_firewall_rule_name(address),
    );
    let _ = std::process::Command::new("cmd")
        .args(["/c", &command])
        .output();
}

fn configure_overlay_firewall(address: Ipv4Addr) -> Result<(), TunError> {
    remove_overlay_firewall(address);
    let command = format!(
        "netsh advfirewall firewall add rule name=\"{}\" dir=in action=allow protocol=any localip={} remoteip={} profile=any",
        overlay_firewall_rule_name(address),
        address,
        "172.16.0.0/12",
    );
    run_command_with_retry(&command, "configure PhantomP2P firewall rule")
}

fn run_command_with_retry(command: &str, action: &str) -> Result<(), TunError> {
    let mut last_error = String::new();
    for attempt in 0..10 {
        match std::process::Command::new("cmd")
            .args(["/c", command])
            .output()
        {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                last_error = format!(
                    "{} {}",
                    String::from_utf8_lossy(&output.stdout).trim(),
                    String::from_utf8_lossy(&output.stderr).trim(),
                );
            }
            Err(error) => last_error = error.to_string(),
        }
        if attempt < 9 {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
    Err(TunError::SetIpFailed(format!(
        "{} 失败: {}",
        action,
        last_error.trim()
    )))
}

// ============================================================
// 平台 TUN 实现
// ============================================================

/// Windows 平台 TUN 实现（基于 wintun.dll 事件驱动模式）
pub struct PlatformTun {
    name: String,
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    wintun: WintunDll,
    adapter: Mutex<Option<WintunAdapterHandle>>,
    session: Mutex<Option<WintunSessionHandle>>,
    /// 接收线程发送的包通道
    packet_rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
    inject_tx: std::sync::mpsc::Sender<InjectCommand>,
    inject_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// 用于向接收线程发送退出信号
    quit_event: Mutex<Option<std::mem::ManuallyDrop<*mut c_void>>>,
    closed: AtomicBool,
}

enum InjectCommand {
    Packet {
        data: Vec<u8>,
        completion: tokio::sync::oneshot::Sender<Result<usize, TunError>>,
    },
    Stop,
}

unsafe impl Send for PlatformTun {}
unsafe impl Sync for PlatformTun {}

impl Drop for PlatformTun {
    fn drop(&mut self) {
        self.close_inner();
    }
}

impl PlatformTun {
    pub async fn create(
        name: &str,
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        mtu: u16,
    ) -> Result<Self, TunError> {
        let wintun = WintunDll::load()?;

        let name16 = to_wstring(name);
        let tunnel_type = to_wstring("PhantomP2P");

        // 创建适配器
        let adapter = unsafe {
            (wintun.create_adapter)(name16.as_ptr(), tunnel_type.as_ptr(), std::ptr::null())
        };
        if adapter.is_null() {
            return Err(TunError::CreateFailed(format!(
                "WintunCreateAdapter 失败 (GetLastError={})",
                unsafe { GetLastError() }
            )));
        }

        // 获取 LUID
        let mut luid: i64 = 0;
        unsafe { (wintun.get_adapter_luid)(adapter, &mut luid) };

        // 启动会话（容量 4MB）
        let capacity = 4 * 1024 * 1024;
        let session = unsafe { (wintun.start_session)(adapter, capacity) };
        if session.is_null() {
            unsafe { (wintun.close_adapter)(adapter) };
            return Err(TunError::CreateFailed(format!(
                "WintunStartSession 失败 (GetLastError={})",
                unsafe { GetLastError() }
            )));
        }

        // 获取读等待事件
        let read_event = unsafe { (wintun.get_read_wait_event)(session) };
        if read_event.is_null() {
            unsafe { (wintun.end_session)(session) };
            unsafe { (wintun.close_adapter)(adapter) };
            return Err(TunError::CreateFailed("WintunGetReadWaitEvent 失败".into()));
        }

        // 创建退出事件
        let quit_event = unsafe {
            let event = CreateEventW(std::ptr::null_mut(), 1i32, 0i32, std::ptr::null());
            if event.is_null() {
                (wintun.end_session)(session);
                (wintun.close_adapter)(adapter);
                return Err(TunError::CreateFailed("创建退出事件失败".into()));
            }
            event
        };

        // 设置 IP 地址
        set_ip_address_iphlp(name, address, netmask, mtu)?;

        // 创建包通道
        let (packet_tx, packet_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        // Wintun injection is synchronous. A single long-lived writer preserves
        // packet order without creating an operating-system thread per packet.
        let (inject_tx, inject_rx) = std::sync::mpsc::channel::<InjectCommand>();
        let inject_session_ptr = session as usize;
        let allocate_fn = wintun.allocate_send_packet as usize;
        let send_fn = wintun.send_packet as usize;
        let inject_thread = std::thread::spawn(move || {
            let inject_session = inject_session_ptr as WintunSessionHandle;
            let alloc_packet: AllocateSendPacketFn = unsafe { std::mem::transmute(allocate_fn) };
            let send_packet: SendPacketFn = unsafe { std::mem::transmute(send_fn) };

            while let Ok(command) = inject_rx.recv() {
                match command {
                    InjectCommand::Packet { data, completion } => {
                        let packet = unsafe { alloc_packet(inject_session, data.len() as u32) };
                        if packet.is_null() {
                            let _ = completion.send(Err(TunError::WriteFailed(
                                "WintunAllocateSendPacket failed".into(),
                            )));
                            continue;
                        }
                        unsafe {
                            std::ptr::copy_nonoverlapping(data.as_ptr(), packet, data.len());
                            send_packet(inject_session, packet);
                        }
                        let _ = completion.send(Ok(data.len()));
                    }
                    InjectCommand::Stop => break,
                }
            }
        });

        // 启动专用接收线程（官方推荐的事件驱动模式）
        let session_ptr = session as usize;
        let read_event_ptr = read_event as usize;
        let quit_event_ptr = quit_event as usize;
        let recv_fn = wintun.receive_packet as usize;
        let release_fn = wintun.release_receive_packet as usize;
        let _thread_handle = std::thread::spawn(move || {
            let session = session_ptr as WintunSessionHandle;
            let read_evt = read_event_ptr as *mut c_void;
            let quit_evt = quit_event_ptr as *mut c_void;
            let recv_func: ReceivePacketFn = unsafe { std::mem::transmute(recv_fn) };
            let release_func: ReleaseReceivePacketFn = unsafe { std::mem::transmute(release_fn) };

            // 注册 wintun 日志
            // (示例中通过 WintunSetLogger 设置，这里省略)

            let wait_handles = [read_evt, quit_evt];

            loop {
                // 等待读事件或退出事件
                let wait_result =
                    unsafe { WaitForMultipleObjects(2, wait_handles.as_ptr(), 0i32, u32::MAX) };

                if wait_result == u32::MAX - 1 {
                    // WAIT_FAILED
                    warn!("[TUN] 接收线程 WaitForMultipleObjects 失败");
                    break;
                }

                if wait_result == 1 {
                    // quit_event 触发，退出
                    break;
                }

                // 读事件触发：循环读取所有可用包
                loop {
                    let mut packet_size: u32 = 0;
                    let packet = unsafe { recv_func(session, &mut packet_size) };
                    if packet.is_null() {
                        let err = unsafe { GetLastError() };
                        if err == 0x103 {
                            // ERROR_NO_MORE_ITEMS
                            break; // 没有更多包，回到等待
                        }
                        warn!("[TUN] WintunReceivePacket 失败: err={}", err);
                        break;
                    }

                    // 复制包数据
                    let len = packet_size as usize;
                    let mut data = vec![0u8; len];
                    unsafe {
                        std::ptr::copy_nonoverlapping(packet as *const u8, data.as_mut_ptr(), len);
                        release_func(session, packet);
                    }

                    // 发送到通道（忽略接收端已关闭的错误）
                    let _ = packet_tx.send(data);
                }
            }

            info!("[TUN] 接收线程已退出");
        });

        info!(
            "[TUN] Windows TUN 设备已创建: name={}, addr={}/{}",
            name, address, netmask,
        );

        Ok(Self {
            name: name.to_string(),
            address,
            netmask,
            wintun,
            adapter: Mutex::new(Some(adapter)),
            session: Mutex::new(Some(session)),
            packet_rx: tokio::sync::Mutex::new(packet_rx),
            inject_tx,
            inject_thread: Mutex::new(Some(inject_thread)),
            quit_event: Mutex::new(Some(std::mem::ManuallyDrop::new(quit_event))),
            closed: AtomicBool::new(false),
        })
    }

    /// 从通道读取一个 IP 包
    pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(TunError::ReadFailed("设备已关闭".into()));
        }

        let data = self
            .packet_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| TunError::ReadFailed("接收通道已关闭".into()))?;

        let len = data.len();
        if buf.len() < len {
            return Err(TunError::ReadFailed("缓冲区不足".into()));
        }
        buf[..len].copy_from_slice(&data);
        Ok(len)
    }

    /// 写入 IP 包到 TUN 设备
    pub async fn write_packet(&self, buf: &[u8]) -> Result<usize, TunError> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(TunError::WriteFailed("device is closed".into()));
        }

        let (tx, rx) = tokio::sync::oneshot::channel::<Result<usize, TunError>>();
        self.inject_tx
            .send(InjectCommand::Packet {
                data: buf.to_vec(),
                completion: tx,
            })
            .map_err(|_| TunError::WriteFailed("Wintun injection thread stopped".into()))?;

        rx.await
            .map_err(|e| TunError::WriteFailed(format!("Wintun injection interrupted: {}", e)))?
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    pub async fn add_route(&self, prefix: Ipv4Addr, prefix_len: u8) -> Result<(), TunError> {
        let command = format!(
            "netsh interface ipv4 add route prefix={}/{} interface=\"{}\" nexthop=0.0.0.0 metric=1 store=active",
            prefix, prefix_len, self.name,
        );
        run_command_with_retry(
            &command,
            &format!("configure route {}/{}", prefix, prefix_len),
        )
    }

    pub async fn close(&self) {
        // close_inner 只访问同步 Mutex 和 AtomicBool，适合在 async 中直接调用
        self.close_inner();
    }

    fn close_inner(&self) {
        if self.closed.swap(true, Ordering::Relaxed) {
            return;
        }

        // The writer owns the raw session pointer and must exit before the
        // Wintun session is ended below.
        let _ = self.inject_tx.send(InjectCommand::Stop);
        if let Ok(mut writer_guard) = self.inject_thread.lock() {
            if let Some(writer) = writer_guard.take() {
                let _ = writer.join();
            }
        }

        // 触发退出事件，让接收线程退出
        if let Ok(mut guard) = self.quit_event.lock() {
            if let Some(event) = guard.take() {
                unsafe {
                    SetEvent(*event);
                }
            }
        }

        // 关闭会话和适配器
        if let Ok(mut session_guard) = self.session.lock() {
            if let Some(session) = session_guard.take() {
                unsafe { (self.wintun.end_session)(session) };
            }
        }
        if let Ok(mut adapter_guard) = self.adapter.lock() {
            if let Some(adapter) = adapter_guard.take() {
                unsafe { (self.wintun.close_adapter)(adapter) };
            }
        }

        remove_overlay_firewall(self.address);
        info!("[TUN] Windows TUN 设备已关闭");
    }
}

// ============================================================
// Win32 API FFI（事件对象）
// ============================================================

extern "system" {
    fn CreateEventW(
        lpEventAttributes: *mut c_void,
        bManualReset: i32,
        bInitialState: i32,
        lpName: *const u16,
    ) -> *mut c_void;

    fn SetEvent(hEvent: *mut c_void) -> i32;

    fn WaitForMultipleObjects(
        nCount: u32,
        lpHandles: *const *mut c_void,
        bWaitAll: i32,
        dwMilliseconds: u32,
    ) -> u32;
}

// ============================================================
// 辅助函数
// ============================================================
