use crate::adb_protocol::{
    validate_handshake_payload, validate_payload, AdbMessageHeader, A_AUTH, A_CLSE, A_OKAY, A_OPEN,
    A_WRTE,
};
use crate::error::TransportError;
use crate::usb_iface::{IF_CLASS_VENDOR, IF_PROTOCOL_ADB, IF_SUBCLASS_ANDROID};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::net::{Shutdown, TcpStream};
use std::os::windows::ffi::OsStrExt;
use std::sync::{Arc, Condvar, Mutex};
use windows::core::{GUID, PCWSTR};
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInterfaces, SetupDiGetClassDevsW,
    SetupDiGetDeviceInterfaceDetailW, SP_DEVICE_INTERFACE_DATA, SP_DEVICE_INTERFACE_DETAIL_DATA_W,
};
use windows::Win32::Devices::Usb::{
    WinUsb_Free, WinUsb_Initialize, WinUsb_QueryInterfaceSettings, WinUsb_QueryPipe,
    WinUsb_ReadPipe, WinUsb_SetPipePolicy, WinUsb_WritePipe, USB_INTERFACE_DESCRIPTOR,
    WINUSB_INTERFACE_HANDLE, WINUSB_PIPE_INFORMATION, WINUSB_PIPE_POLICY,
};
use windows::Win32::Foundation::{CloseHandle, ERROR_SEM_TIMEOUT, ERROR_TIMEOUT, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};

const ADB_CLASS_GUID: GUID = GUID {
    data1: 0xF72FE0D4,
    data2: 0xCBCB,
    data3: 0x407D,
    data4: [0x88, 0x14, 0x9E, 0xD6, 0x73, 0xD0, 0xDD, 0x6B],
};

/// WinUSB pipe policy 类型：读/写传输超时（毫秒）。取值 0 表示无限等待（WinUSB 默认），
/// 非 0 时主机控制器在超时后取消该次传输、`WinUsb_ReadPipe` 返回失败。（winusbio.h）
const PIPE_TRANSFER_TIMEOUT: u32 = 0x03;

/// WinUSB pipe policy 类型：写长度恰为 wMaxPacketSize 整数倍时由 WinUSB 自动补一个零长度包，
/// 值为 1 字节 UCHAR。（winusbio.h）
const SHORT_PACKET_TERMINATE: u32 = 0x01;

/// push 时通告的文件权限（0o100666，与既有行为一致）。
const PUSH_FILE_MODE: u32 = 0o100666;

/// 写默认超时（毫秒）：避免设备不读取 bulk-out 时 `WinUsb_WritePipe` 永久阻塞。
/// 取 30s：远大于健康设备单次写所需，异常时有界失败而非无限挂死。
const DEFAULT_WRITE_TIMEOUT_MS: u32 = 30_000;

/// 数据读默认超时：设备长时间无任何回包即判挂死报错，避免进程永久卡住。
/// 这是「单次传输空闲」窗口——设备持续回包就不会触发。
pub(crate) const DEFAULT_READ_TIMEOUT_MS: u32 = 60_000;

/// 流式（shell 等）等待下一个报头的轮询窗口：短窗口醒来检查取消纪元与静默上限，
/// 无包则继续等。窗口只落在报文间隙（报头恒为单个 24 字节 USB 包），不会截断报文。
const STREAM_HEADER_POLL_MS: u32 = 1_000;

/// shell 等流式操作允许的最长连续静默（毫秒）：不短于默认读超时（普通短命令行为不变）；
/// 调用方声明了更长的操作超时（如 `su dd` 大分区备份 120–7200s）则放宽到它——
/// 设备端长时间无输出的合法操作不再被 60s 空闲窗口误判失败。
pub(crate) fn shell_idle_window_ms(op_timeout_secs: u32) -> u32 {
    (op_timeout_secs as u64)
        .saturating_mul(1000)
        .clamp(DEFAULT_READ_TIMEOUT_MS as u64, u32::MAX as u64) as u32
}

/// 握手期读超时：等用户在手机点「允许 USB 调试」需较长人工时间，故用宽窗口；
/// 超时则判定未授权/无响应而报错，仍强于永久阻塞。
const AUTH_WAIT_TIMEOUT_MS: u32 = 180_000;

/// 普通握手不是人工授权：设备不回 CNXN/AUTH 时应尽快释放坏连接，不能占着句柄等三分钟。
const HANDSHAKE_READ_TIMEOUT_MS: u32 = 5_000;

/// USB 的零长度包（ZLP）只结束一次 bulk transfer，不代表 ADB 连接结束。
/// 与 AOSP usb_windows.cpp::usb_read 一样跳过它；超时和真正的 USB 错误仍原样返回。
fn read_usb_data(
    buf: &mut [u8],
    mut read: impl FnMut(&mut [u8]) -> Result<usize, TransportError>,
) -> Result<usize, TransportError> {
    if buf.is_empty() {
        return Ok(0);
    }
    loop {
        match read(buf)? {
            0 => continue,
            n => return Ok(n),
        }
    }
}

/// 生成非零 ADB 本地 stream id（时间戳低位 | 1）。
/// 不 `.unwrap()`：绝不为时钟异常在传输中途 panic（release 为 panic=abort）。
fn new_stream_id() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1)
        | 1
}

/// 句柄竞争退避（毫秒）：第 `attempt` 次重试（从 0 起）等待 `min(base << attempt, cap)`。
/// 上个进程的 WinUSB 句柄通常数十毫秒即释放，先快后慢的指数轮询能在刚释放瞬间命中，
/// 避免线性长退避把常见情形拖成几百毫秒——连续命令提速的关键。
fn handle_race_backoff_ms(attempt: u32, base: u64, cap: u64) -> u64 {
    base.saturating_mul(1u64 << attempt.min(20)).min(cap)
}

/// 写 ADB 报文所需的最小句柄集（Copy），可按值复制到输入线程：写由外部 `Mutex` 串行化，
/// 读写端点分离互不干扰。取代旧「`&mut Self` 裸指针跨线程共享」的 UB 做法。
/// 携带取样时刻的协商协议版本：旧协议设备要求每包带载荷校验和（见 adb_protocol）。
/// [`AdbWinUsbDevice::raw_writer`] 只在 connect 之后取样，版本已定型。
#[derive(Clone, Copy)]
pub(crate) struct AdbRawWriter {
    winusb_handle: WINUSB_INTERFACE_HANDLE,
    bulk_out_addr: u8,
    protocol_version: u32,
}

impl AdbRawWriter {
    fn write_bytes(&self, data: &[u8]) -> Result<(), TransportError> {
        unsafe {
            let mut written: u32 = 0;
            let result = WinUsb_WritePipe(
                self.winusb_handle,
                self.bulk_out_addr,
                data,
                Some(&mut written),
                None,
            );
            if let Err(e) = result {
                return Err(TransportError::Usb(format!("WinUsb_WritePipe 失败: {e:?}")));
            }
            if written as usize != data.len() {
                return Err(TransportError::Usb("写入数据不完整".into()));
            }
            Ok(())
        }
    }

    pub(crate) fn write_message(
        &self,
        command: u32,
        local_id: u32,
        remote_id: u32,
        data: &[u8],
    ) -> Result<(), TransportError> {
        let header = AdbMessageHeader::for_payload(
            command,
            local_id,
            remote_id,
            data,
            self.protocol_version,
        );
        self.write_bytes(&header.encode())?;
        if !data.is_empty() {
            self.write_bytes(data)?;
        }
        Ok(())
    }

    /// 测试用空句柄写端：只能配合「会话已死」快速失败路径使用，绝不可真正写入。
    #[cfg(test)]
    pub(crate) fn dead_for_tests() -> Self {
        Self {
            winusb_handle: unsafe { mem::zeroed() },
            bulk_out_addr: 0,
            protocol_version: crate::adb_protocol::ADB_VERSION_MIN,
        }
    }
}

pub struct AdbWinUsbDevice {
    device_handle: HANDLE,
    winusb_handle: WINUSB_INTERFACE_HANDLE,
    bulk_in_addr: u8,
    bulk_out_addr: u8,
    next_local_id: u32,
    is_connected: bool,
    /// 协商后的协议版本。初始 [`crate::adb_protocol::ADB_VERSION_MIN`]（AOSP atransport 同款）：
    /// 在收到对端 CNXN 之前一切出向报文都带载荷校验和，旧设备（收包必校验）才收得下；
    /// 协商到 ≥ SKIP_CHECKSUM 后校验和置 0（新设备不校验，省 CPU）。
    protocol_version: u32,
    /// 对端通告的单包最大载荷（出向上限）。旧设备只有 4KiB，push/sideload 必须按它切块，
    /// 否则旧 adbd 按 check_header 直接断链。
    max_payload: u32,
    /// 设备接口路径，用于 connect 失败时按路径重开一个干净句柄（深度恢复）。
    device_path: String,
    /// 流式等待报头允许的最长连续静默（毫秒）。默认取 [`DEFAULT_READ_TIMEOUT_MS`]；
    /// embed hub 在 shell 前按调用方操作超时放宽、结束后复原。
    stream_idle_window_ms: u32,
    /// 本次操作的取消令牌（`embed::CancelToken`）：Some=hub 在调用线程捕获后注入
    /// （覆盖排队等待窗口，且带上本操作私有句柄）；None=以传输操作自身起点为准（CLI 等直连路径）。
    op_cancel: Option<crate::embed::CancelToken>,
    /// 设备在 A_CNXN 里回的 banner（握手成功后才有）。5037 server 的 `host:features` 与
    /// `devices -l` 的 product/model/device 全靠它，丢掉就只能对客户端瞎报能力。
    peer_banner: crate::adb_protocol::PeerBanner,
    /// Header read immediately precedes payload read.  Used to validate the
    /// inbound checksum before handing bytes to a service handler.
    pending_header: Mutex<Option<AdbMessageHeader>>,
}

pub struct AdbDeviceInfo {
    pub device_path: String,
}

/// ADB 设备接口路径 → 序列号（接口路径或复合设备父节点，见 [`crate::usb_iface::serial_for_interface`]），
/// 设备确实没报序列号时记 "unknown"——adb 侧的 `devices` 输出与 `-s` 匹配都按这个口径。
pub fn serial_from_path(path: &str) -> String {
    crate::usb_iface::serial_for_interface(path).unwrap_or_else(|| "unknown".to_string())
}

/// 正停在「签名被拒、已发公钥、等用户在手机上点允许 USB 调试」的设备序列号。
///
/// 5037 mux server 为了不抢句柄，`devices` 只枚举、不开设备，本来看不出授权状态，只能一律报
/// `device`；于是设备（比如重启后「允许」没勾「始终」而失效）在等授权时，投屏 prep 会当它已就绪，
/// 界面报「检测到 ADB 设备」，scrcpy 起来后所有流都挂死。持有设备的那条握手线程在这里登记，
/// server 才能像官方 adb 一样如实报 `unauthorized`。
fn awaiting_auth() -> &'static Mutex<std::collections::HashSet<String>> {
    static SET: std::sync::OnceLock<Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    SET.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

/// 这台设备此刻是否正等用户在手机上授权（见 [`awaiting_auth`]）。
pub fn is_awaiting_authorization(serial: &str) -> bool {
    awaiting_auth()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(serial)
}

/// 授权等待登记：从发出公钥起持有，握手结束（成功、失败或放弃重试）时 drop 撤销。
struct AuthWait(String);

impl AuthWait {
    fn begin(serial: String) -> Self {
        awaiting_auth()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(serial.clone());
        Self(serial)
    }
}

impl Drop for AuthWait {
    fn drop(&mut self) {
        awaiting_auth()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
    }
}

/// 握手已经结束、但设备没有接受本机的序列号：完整握手发了公钥却没等到授权（超时、用户拒绝、
/// 中途 IO 失败），或探测式握手签名被拒。
///
/// 与 [`awaiting_auth`] 合起来才是「设备未授权」的完整判定。只看等授权窗口的话，握手一放弃，
/// 这台仍未授权的设备就会被报回 `device`，各页面随即误显示「已连接」。下一次握手成功即撤销；
/// 设备从 USB 枚举消失时由 [`forget_absent_authorization`] 清掉，重新插上后按新的握手结论判。
fn rejected_auth() -> &'static Mutex<std::collections::HashSet<String>> {
    static SET: std::sync::OnceLock<Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    SET.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

/// 记下一次握手的授权结论（`true` = 设备回了 A_CNXN）。
fn record_handshake(serial: &str, authorized: bool) {
    let mut set = rejected_auth().lock().unwrap_or_else(|e| e.into_inner());
    if authorized {
        set.remove(serial);
    } else {
        set.insert(serial.to_string());
    }
}

/// 这台设备此刻是否未授权 USB 调试：正等用户在手机上点允许，或最近一次握手没被接受。
/// 5037 server 据此报 `unauthorized`，与官方 adb 同口径。
pub fn is_unauthorized(serial: &str) -> bool {
    is_awaiting_authorization(serial)
        || rejected_auth()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(serial)
}

/// 丢掉已从 USB 枚举消失的设备的未授权结论。`present` 为本轮枚举到的全部序列号。
pub fn forget_absent_authorization(present: &[String]) {
    rejected_auth()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|serial| present.iter().any(|p| p == serial));
}

#[cfg(test)]
mod auth_wait_tests {
    use super::{
        forget_absent_authorization, is_awaiting_authorization, is_unauthorized, record_handshake,
        AuthWait,
    };

    /// 握手放弃后设备仍算未授权，直到下一次握手成功或设备拔掉；否则等授权超时的那一刻，
    /// 界面就会把未授权设备报回「已连接」。
    #[test]
    fn rejected_handshake_stays_unauthorized_until_success_or_unplug() {
        let serial = "rejected-auth-test-serial";
        assert!(!is_unauthorized(serial));

        record_handshake(serial, false);
        assert!(is_unauthorized(serial));
        assert!(!is_awaiting_authorization(serial), "结论不应冒充等待窗口");

        record_handshake(serial, true);
        assert!(!is_unauthorized(serial), "握手成功即撤销");

        record_handshake(serial, false);
        forget_absent_authorization(&["some-other-device".to_string()]);
        assert!(!is_unauthorized(serial), "设备拔掉即清掉结论");

        record_handshake(serial, false);
        forget_absent_authorization(&[serial.to_string()]);
        assert!(is_unauthorized(serial), "设备仍在枚举里就保留结论");
        record_handshake(serial, true);
    }

    #[test]
    fn awaiting_authorization_counts_as_unauthorized() {
        let serial = "awaiting-counts-test-serial";
        let wait = AuthWait::begin(serial.to_string());
        assert!(is_unauthorized(serial));
        drop(wait);
        assert!(!is_unauthorized(serial));
    }

    /// 登记只在持有期间生效：握手线程不论以何种方式离开 connect（成功、失败、panic 展开），
    /// 都必须撤销，否则 mux server 会对一台早已授权的设备永远报 unauthorized。
    #[test]
    fn auth_wait_is_visible_only_while_held() {
        let serial = "auth-wait-test-serial";
        assert!(!is_awaiting_authorization(serial));
        let wait = AuthWait::begin(serial.to_string());
        assert!(is_awaiting_authorization(serial));
        assert!(!is_awaiting_authorization("another-serial"));
        drop(wait);
        assert!(!is_awaiting_authorization(serial));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellV2Kind {
    Stdin,
    Stdout,
    Stderr,
    Exit,
    CloseStdin,
    WindowSizeChange,
    Invalid(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellProtocol {
    V2,
    Legacy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellV2Packet {
    pub kind: ShellV2Kind,
    pub payload: Vec<u8>,
}

impl ShellV2Packet {
    pub fn exit_code(&self) -> Option<i32> {
        if self.kind == ShellV2Kind::Exit {
            self.payload.first().copied().map(i32::from)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShellExit {
    pub code: i32,
    pub protocol: ShellProtocol,
}

/// 单个 stream 上读到的一个包（其他 stream 的包已被读掉丢弃）。
enum StreamPacket {
    Okay,
    Data,
    Closed,
}

pub fn parse_shell_v2_packet(buf: &[u8]) -> Result<ShellV2Packet, String> {
    if buf.len() < 5 {
        return Err("shell v2 packet too short".into());
    }

    let kind = match buf[0] {
        0 => ShellV2Kind::Stdin,
        1 => ShellV2Kind::Stdout,
        2 => ShellV2Kind::Stderr,
        3 => ShellV2Kind::Exit,
        4 => ShellV2Kind::CloseStdin,
        5 => ShellV2Kind::WindowSizeChange,
        other => ShellV2Kind::Invalid(other),
    };
    let len = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if buf.len() < 5 + len {
        return Err("shell v2 packet payload truncated".into());
    }

    Ok(ShellV2Packet {
        kind,
        payload: buf[5..5 + len].to_vec(),
    })
}

impl AdbWinUsbDevice {
    pub fn enumerate() -> Result<Vec<AdbDeviceInfo>, TransportError> {
        let mut devices = Vec::new();

        unsafe {
            let hdev_info = match SetupDiGetClassDevsW(
                Some(&ADB_CLASS_GUID),
                PCWSTR::null(),
                None,
                windows::Win32::Devices::DeviceAndDriverInstallation::DIGCF_DEVICEINTERFACE
                    | windows::Win32::Devices::DeviceAndDriverInstallation::DIGCF_PRESENT,
            ) {
                Ok(h) => h,
                Err(_) => return Err(TransportError::Usb("SetupDiGetClassDevsW 失败".into())),
            };

            let mut index = 0u32;
            loop {
                let mut interface_data: SP_DEVICE_INTERFACE_DATA = mem::zeroed();
                interface_data.cbSize = mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;

                let result = SetupDiEnumDeviceInterfaces(
                    hdev_info,
                    None,
                    &ADB_CLASS_GUID,
                    index,
                    &mut interface_data,
                );

                if result.is_err() {
                    break;
                }

                let mut required_size: u32 = 0;
                let _ = SetupDiGetDeviceInterfaceDetailW(
                    hdev_info,
                    &interface_data,
                    None,
                    0,
                    Some(&mut required_size),
                    None,
                );

                if required_size > 0 {
                    let mut detail_data: Vec<u8> = vec![0; required_size as usize];
                    let detail_ptr =
                        detail_data.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
                    (*detail_ptr).cbSize =
                        mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;

                    let result = SetupDiGetDeviceInterfaceDetailW(
                        hdev_info,
                        &interface_data,
                        Some(detail_ptr),
                        required_size,
                        None,
                        None,
                    );

                    if result.is_ok() {
                        let device_path_ptr = (*detail_ptr).DevicePath.as_ptr();
                        let device_path = widestring_to_string(device_path_ptr);

                        // ADB 接口类 GUID 下混着 fastboot/fastbootd、甚至 WinUSB 驱动的 EDL 9008/
                        // 诊断口：不过滤会把它们当在线 adb 设备报给上层，detect_mode 据此误判
                        // （如「进 EDL」对 EDL 口发 adb reboot edl → 打开后必然「未找到 Bulk 端点」）。
                        // 判据用不开句柄的兼容 ID 三元组（与 AOSP is_adb_interface 同一判据），
                        // 避免探测性 open 在连续命令下制造句柄竞争；只有真「判不出来」（属性缺失）
                        // 才放行，由 find_endpoints 读接口描述符兜底。
                        match crate::usb_iface::probe(&device_path) {
                            Some(crate::usb_iface::AndroidIface::Adb) | None => {
                                devices.push(AdbDeviceInfo { device_path });
                            }
                            // fastboot 或其它厂商接口（EDL 9008 等）：确定性排除
                            Some(_) => {}
                        }
                    }
                }

                index += 1;
            }

            let _ = SetupDiDestroyDeviceInfoList(hdev_info);
        }

        Ok(devices)
    }

    /// 打开 ADB WinUSB 设备。连续命令下上个进程的句柄由内核释放有毫秒级延迟，
    /// 新进程可能 open 偶发失败，或拿到残留会话状态的 pipe 致首次 ReadPipe 失败。
    /// 重试退避覆盖 CreateFileW/WinUsb_Initialize 偶发失败；不复位设备端点，原因见 try_open_device。
    pub fn open_device(device_path: &str) -> Result<Self, TransportError> {
        // 5ms 起步、指数封顶 200ms 的先快后慢轮询，总预算约 2s：覆盖秒级释放延迟，又不让常见情形空等。
        const MAX_OPEN_ATTEMPTS: u32 = 16;
        let mut last_err = TransportError::Usb("打开设备失败".into());
        for attempt in 0..MAX_OPEN_ATTEMPTS {
            match Self::try_open_device(device_path) {
                Ok(dev) => return Ok(dev),
                // 非 ADB 接口（fastboot）是确定性结果：重试无意义且每轮 open+query 骚扰复合设备，
                // 立即返回让调用方快速让位。
                Err(e @ TransportError::NotAdbInterface) => return Err(e),
                Err(e) => {
                    last_err = e;
                    if attempt + 1 < MAX_OPEN_ATTEMPTS {
                        std::thread::sleep(std::time::Duration::from_millis(
                            handle_race_backoff_ms(attempt, 5, 200),
                        ));
                    }
                }
            }
        }
        // 重试预算（~2s）耗尽仍拒绝访问 ⇒ 不是内核释放延迟，而是句柄被别的进程长期持有
        // （winusb.sys 同一设备接口仅容一个打开者：GUI 常驻 adb_hub、5037 上的 server、官方 adb）。
        // 保留原始错误文本（error.rs 按 HRESULT/文案分类要靠它），只追加处置提示。
        Err(match last_err {
            TransportError::Usb(msg) if crate::error::usb_text_is_access_denied(&msg) => {
                TransportError::Usb(format!(
                    "{msg}（设备接口已被其他 ADB 进程独占打开：可能是 RMFlashTool 图形界面、投屏 mux \
                     或官方 adb server。请经 127.0.0.1:5037 的 adb server 复用连接，\
                     或执行 adb kill-server / 关闭占用程序后重试）"
                ))
            }
            e => e,
        })
    }

    fn try_open_device(device_path: &str) -> Result<Self, TransportError> {
        unsafe {
            let path_wide: Vec<u16> = OsStr::new(device_path)
                .encode_wide()
                .chain(Some(0))
                .collect();
            let raw_handle = CreateFileW(
                PCWSTR(path_wide.as_ptr()),
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                None,
            );

            // 错误文本保留 `{:?}`：它带出 HRESULT(0x80070005)，是跨语言环境唯一稳定的「拒绝访问」判据
            //（见 error::usb_text_is_access_denied）。
            let handle = raw_handle.map_err(|err| {
                TransportError::Usb(format!("CreateFileW 失败，OS 错误码: {:?}", err))
            })?;
            if handle.is_invalid() {
                return Err(TransportError::Usb("CreateFileW 返回无效句柄".into()));
            }
            let device_handle = HANDLE(handle.0);

            let mut winusb_handle: WINUSB_INTERFACE_HANDLE = mem::zeroed();
            let result = WinUsb_Initialize(device_handle, &mut winusb_handle);

            if result.is_err() {
                let _ = CloseHandle(device_handle);
                return Err(TransportError::Usb(format!(
                    "WinUsb_Initialize 失败，OS 错误码: {:?}",
                    result.err()
                )));
            }

            let (bulk_in, bulk_out) = match Self::find_endpoints(winusb_handle) {
                Ok(eps) => eps,
                Err(e) => {
                    // 端点枚举失败也要释放已初始化的 WinUSB 句柄，避免句柄泄漏占用设备
                    let _ = windows::Win32::Devices::Usb::WinUsb_Free(winusb_handle);
                    let _ = CloseHandle(device_handle);
                    return Err(e);
                }
            };

            // 打开时绝不 WinUsb_ResetPipe（与官方 adb 的 Windows 后端 AdbWinApi 一致）：它会向设备
            // 发 CLEAR_FEATURE(ENDPOINT_HALT)，已与上一个主机会话建过连的 adbd（实测 Android 17）
            // 的 FunctionFS 端点被清 HALT 后挂着的读直接出错，adbd 随即重置 USB 功能、整机重新枚举
            // 约 2s：本次首写报 ERROR_GEN_FAILURE、重开报 ERROR_FILE_NOT_FOUND；mux hub 建连后流刚
            // 打开设备就掉线，shell 以 0 字节正常结束（上层拿到空输出），push 被中途掐断。
            // 上个会话残留在设备侧的报文由握手循环读掉丢弃（非 CNXN/AUTH 一律跳过），错位的坏报头
            // 让 decode 报错、走 connect 的重开重试——ResetPipe 只清主机侧缓冲，本也清不掉它们。

            let dev = AdbWinUsbDevice {
                device_handle,
                winusb_handle,
                bulk_in_addr: bulk_in,
                bulk_out_addr: bulk_out,
                next_local_id: 1,
                is_connected: false,
                protocol_version: crate::adb_protocol::ADB_VERSION_MIN,
                max_payload: crate::adb_protocol::ADB_LEGACY_MAX_PAYLOAD,
                device_path: device_path.to_string(),
                stream_idle_window_ms: DEFAULT_READ_TIMEOUT_MS,
                op_cancel: None,
                peer_banner: Default::default(),
                pending_header: Mutex::new(None),
            };
            // 给 bulk-in 端点设默认读超时：设备无响应时 ReadPipe 会超时返回错误而非永久阻塞。
            dev.set_read_timeout(DEFAULT_READ_TIMEOUT_MS);
            // 给 bulk-out 端点设默认写超时：设备不取数据时 WritePipe 有界失败而非永久挂死。
            dev.set_write_timeout(DEFAULT_WRITE_TIMEOUT_MS);
            dev.enable_short_packet_terminate();
            Ok(dev)
        }
    }

    /// 设置 bulk-in 端点的读传输超时（毫秒，0=无限）。设备在超时窗口内完全无回包时，后续
    /// `WinUsb_ReadPipe` 会失败返回而不是永久挂死，从而让 connect/shell/pull 等读操作可被中断。
    pub(crate) fn set_read_timeout(&self, timeout_ms: u32) {
        unsafe {
            let value: u32 = timeout_ms;
            let _ = WinUsb_SetPipePolicy(
                self.winusb_handle,
                self.bulk_in_addr,
                WINUSB_PIPE_POLICY(PIPE_TRANSFER_TIMEOUT),
                mem::size_of::<u32>() as u32,
                &value as *const u32 as *const std::ffi::c_void,
            );
        }
    }

    /// 设置 bulk-out 端点的写传输超时（毫秒，0=无限）。设备不取数据时 `WinUsb_WritePipe` 会永久阻塞
    /// （对 fastboot 设备发 A_CNXN 即触发，曾致 adb devices 卡 321s）；设超时后有界失败返回。
    fn set_write_timeout(&self, timeout_ms: u32) {
        unsafe {
            let value: u32 = timeout_ms;
            let _ = WinUsb_SetPipePolicy(
                self.winusb_handle,
                self.bulk_out_addr,
                WINUSB_PIPE_POLICY(PIPE_TRANSFER_TIMEOUT),
                mem::size_of::<u32>() as u32,
                &value as *const u32 as *const std::ffi::c_void,
            );
        }
    }

    /// adbd 用固定大小的 aio 读收包：载荷恰为 wMaxPacketSize 整数倍、又没有短包或零长度包收尾时，
    /// 这次读不会完成，设备不回 A_OKAY；老版 adbd 还会多排一个读专门吃 ZLP，host 不发就吞掉下一个
    /// 报头。AOSP host 对这种长度一律补 ZLP（usb_libusb.cpp `should_perform_zero_transfer`）。
    /// 策略挂在端点上，`raw_writer` 的拷贝共用同一端点，一并生效。
    fn enable_short_packet_terminate(&self) {
        let value: u8 = 1;
        let result = unsafe {
            WinUsb_SetPipePolicy(
                self.winusb_handle,
                self.bulk_out_addr,
                WINUSB_PIPE_POLICY(SHORT_PACKET_TERMINATE),
                mem::size_of::<u8>() as u32,
                &value as *const u8 as *const std::ffi::c_void,
            )
        };
        if result.is_err() {
            crate::logger::log_line(
                "ADB bulk-out 设置 SHORT_PACKET_TERMINATE 失败，整包对齐的载荷可能卡住设备",
            );
        }
    }

    /// 协商后的出向单包载荷上限（对端 CNXN 回的 maxdata）。
    pub(crate) fn max_payload(&self) -> u32 {
        self.max_payload
    }

    /// 设置流式等待报头的最长连续静默（毫秒）。embed hub 在 shell 前后设置/复原。
    pub(crate) fn set_stream_idle_window_ms(&mut self, ms: u32) {
        self.stream_idle_window_ms = ms;
    }

    /// 注入/清除本次操作的取消令牌（embed hub 在 job 前后设置/复原）。
    pub(crate) fn set_op_cancel(&mut self, token: Option<crate::embed::CancelToken>) {
        self.op_cancel = token;
    }

    /// 取一个可跨线程按值携带的原始写句柄（Copy）。用于交互式 shell 的输入线程写出端点，
    /// 避免把 `&mut Self` 裸指针跨线程共享（可变别名，UB）。
    /// 调用方约定：只在 connect 完成后取样（协商版本已定型，校验和策略随之固定）。
    pub(crate) fn raw_writer(&self) -> AdbRawWriter {
        AdbRawWriter {
            winusb_handle: self.winusb_handle,
            bulk_out_addr: self.bulk_out_addr,
            protocol_version: self.protocol_version,
        }
    }

    /// 深度恢复：关闭当前（可能因上个进程未释放而无法 IO 的）句柄，按 `device_path`
    /// 重新打开拿一个干净句柄。用于连续命令竞争下 connect 握手失败的恢复。
    ///
    /// # 不变量（勿破坏）
    /// 一旦 [`Self::raw_writer`] 的拷贝交给了 `MuxSession`/桥接线程，本函数（以及会在失败
    /// 路径调用它的 [`Self::connect`]）就**绝不能**再在该设备实例上运行：这里会 WinUsb_Free
    /// 旧句柄再重开，而 `AdbRawWriter` 持有的只是句柄裸拷贝、不经任何锁同步——静默违反即
    /// 重新引入 WinUSB use-after-free。`MuxSession::new` 只在取 raw_writer **之前** connect
    /// 一次，此后设备仅归读循环线程使用。
    fn reopen(&mut self) -> Result<(), TransportError> {
        unsafe {
            let _ = WinUsb_Free(self.winusb_handle);
            let _ = CloseHandle(self.device_handle);
            // 立即置空：若下面重开失败提前返回，Drop 不会二次释放已释放的句柄
            self.winusb_handle = mem::zeroed();
            self.device_handle = HANDLE(0);
        }
        self.is_connected = false;
        // 重开即重新握手：协商状态归零，按 MIN 版本（带校验和）重发 CNXN。
        self.protocol_version = crate::adb_protocol::ADB_VERSION_MIN;
        self.max_payload = crate::adb_protocol::ADB_LEGACY_MAX_PAYLOAD;

        let mut fresh = Self::try_open_device(&self.device_path)?;
        self.device_handle = fresh.device_handle;
        self.winusb_handle = fresh.winusb_handle;
        self.bulk_in_addr = fresh.bulk_in_addr;
        self.bulk_out_addr = fresh.bulk_out_addr;
        // fresh 的句柄已被本结构体接管：把 fresh 的句柄字段置空后让它正常析构，只释放
        // device_path 等堆资源（此前用 mem::forget 会连 String 一起泄漏，常驻进程反复
        // 重连会累积）。Drop 对空句柄的 WinUsb_Free/CloseHandle 是无害空操作，与上方
        // 「重开失败提前返回」路径依赖的行为一致。
        fresh.winusb_handle = unsafe { mem::zeroed() };
        fresh.device_handle = HANDLE(0);
        Ok(())
    }

    unsafe fn find_endpoints(
        winusb_handle: WINUSB_INTERFACE_HANDLE,
    ) -> Result<(u8, u8), TransportError> {
        let mut iface_desc: USB_INTERFACE_DESCRIPTOR = mem::zeroed();
        let result = WinUsb_QueryInterfaceSettings(winusb_handle, 0, &mut iface_desc);

        if result.is_err() {
            return Err(TransportError::Usb(
                "WinUsb_QueryInterfaceSettings 失败".into(),
            ));
        }

        // 根因防线（AOSP is_adb_interface 全等判定）：adb 接口的描述符三元组必须是
        // class=0xFF/subclass=0x42/protocol=0x01。ADB 接口类 GUID 下还混着 fastboot(0x03)、
        // WinUSB 驱动的 EDL 9008/高通诊断口(0xFF/0xFF/0xFF) 等接口：
        // - 对 fastbootd 发 A_CNXN 会令设备状态机错乱、bulk 读写阻塞（实测卡 321s）；
        // - 对 EDL 口做 bulk IO 会搅乱 Sahara 状态机，其接口也常无成对 bulk 端点
        //   （历史故障「未找到 Bulk 端点」重试 16 轮 ≈ 2.1s 后报错）。
        // 描述符是确定性结果，不匹配即拒绝——绝不做任何 ResetPipe/bulk IO，也绝不重试
        // （open_device 对 NotAdbInterface 立即返回），与 AOSP「不匹配则跳过设备」一致。
        if !(iface_desc.bInterfaceClass == IF_CLASS_VENDOR
            && iface_desc.bInterfaceSubClass == IF_SUBCLASS_ANDROID
            && iface_desc.bInterfaceProtocol == IF_PROTOCOL_ADB)
        {
            crate::logger::log_line(&format!(
                "跳过非 ADB 接口：class={:02x} subclass={:02x} protocol={:02x}（ADB 要求 ff/42/01）",
                iface_desc.bInterfaceClass,
                iface_desc.bInterfaceSubClass,
                iface_desc.bInterfaceProtocol
            ));
            return Err(TransportError::NotAdbInterface);
        }

        let mut bulk_in: Option<u8> = None;
        let mut bulk_out: Option<u8> = None;

        for pipe_index in 0..iface_desc.bNumEndpoints {
            let mut pipe_info: WINUSB_PIPE_INFORMATION = mem::zeroed();
            let result = WinUsb_QueryPipe(winusb_handle, 0, pipe_index, &mut pipe_info);

            if result.is_ok() {
                let pipe_id = pipe_info.PipeId;
                if pipe_info.PipeType == windows::Win32::Devices::Usb::UsbdPipeTypeBulk {
                    if pipe_id & 0x80 != 0 {
                        bulk_in = Some(pipe_id);
                    } else {
                        bulk_out = Some(pipe_id);
                    }
                }
            }
        }

        // 三元组已确认是 adb 接口，规范要求恰好一对 bulk 端点；缺失只出现在设备正被移除
        // （reboot 竞态）等瞬态下，带上端点数便于定位。
        match (bulk_in, bulk_out) {
            (Some(in_addr), Some(out_addr)) => Ok((in_addr, out_addr)),
            _ => Err(TransportError::Usb(format!(
                "ADB 接口缺少成对 Bulk 端点（bNumEndpoints={}，设备可能正在重启/移除）",
                iface_desc.bNumEndpoints
            ))),
        }
    }

    fn alloc_local_stream_id(&mut self) -> u32 {
        if self.next_local_id == 0 {
            self.next_local_id = 1;
        }
        let id = self.next_local_id;
        self.next_local_id = self.next_local_id.wrapping_add(1);
        if self.next_local_id == 0 {
            self.next_local_id = 1;
        }
        id
    }

    pub fn write_pipe(&self, data: &[u8]) -> Result<(), TransportError> {
        unsafe {
            let mut written: u32 = 0;
            let result = WinUsb_WritePipe(
                self.winusb_handle,
                self.bulk_out_addr,
                data,
                Some(&mut written),
                None,
            );

            if let Err(e) = result {
                return Err(TransportError::Usb(format!("WinUsb_WritePipe 失败: {e:?}")));
            }

            if written as usize != data.len() {
                return Err(TransportError::Usb("写入数据不完整".into()));
            }

            Ok(())
        }
    }

    pub fn read_pipe(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        read_usb_data(buf, |buf| unsafe {
            let mut read: u32 = 0;
            let result = WinUsb_ReadPipe(
                self.winusb_handle,
                self.bulk_in_addr,
                Some(buf),
                Some(&mut read),
                None,
            );

            if let Err(e) = result {
                // 管道超时（PIPE_TRANSFER_TIMEOUT 策略触发，WinUSB 同步读报 ERROR_SEM_TIMEOUT）
                // 单独归类：轮询式等包的调用方要能把「窗口内无数据」与真实 IO 故障区分开。
                if e.code() == ERROR_SEM_TIMEOUT.to_hresult()
                    || e.code() == ERROR_TIMEOUT.to_hresult()
                {
                    return Err(TransportError::Timeout);
                }
                return Err(TransportError::Usb(format!("WinUsb_ReadPipe 失败: {e:?}")));
            }

            Ok(read as usize)
        })
    }

    pub fn read_exact(&self, buf: &mut [u8]) -> Result<(), TransportError> {
        let mut total = 0;
        while total < buf.len() {
            let read = self.read_pipe(&mut buf[total..])?;
            total += read;
        }
        Ok(())
    }

    pub fn write_header(&mut self, header: &AdbMessageHeader) -> Result<(), TransportError> {
        let data = header.encode();
        self.write_pipe(&data)
    }

    pub fn read_header(&self) -> Result<AdbMessageHeader, TransportError> {
        let mut buf = [0u8; 24];
        self.read_exact(&mut buf)?;
        self.accept_header(&buf)
    }

    /// 解码报头并登记为待读载荷的那一个。凡是从管道读报头的路径（含可取消的轮询读
    /// [`Self::poll_stream_header`]）都必须经过这里，否则紧随其后的 [`Self::read_payload`]
    /// 找不到报头、整条流报「payload read without a header」。
    fn accept_header(&self, buf: &[u8; 24]) -> Result<AdbMessageHeader, TransportError> {
        let header = AdbMessageHeader::decode(buf)
            .map_err(|e: std::io::Error| TransportError::Usb(e.to_string()))?;
        if !crate::adb_protocol::is_known_command(header.command) {
            return Err(TransportError::Usb(format!(
                "unknown ADB command 0x{:08x}",
                header.command
            )));
        }
        if header.command == crate::adb_protocol::A_STLS {
            return Err(TransportError::Usb(
                "ADB TLS upgrade (A_STLS) is not supported by this transport".to_string(),
            ));
        }
        *self
            .pending_header
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(header);
        Ok(header)
    }

    fn write_message(
        &mut self,
        command: u32,
        local_id: u32,
        remote_id: u32,
        data: &[u8],
    ) -> Result<(), TransportError> {
        let header = AdbMessageHeader::for_payload(
            command,
            local_id,
            remote_id,
            data,
            self.protocol_version,
        );
        self.write_header(&header)?;
        if !data.is_empty() {
            self.write_pipe(data)?;
        }
        Ok(())
    }

    /// 收到对端 A_CNXN 后套用协商结果（AOSP `atransport::update_version`）：
    /// arg0=对端版本、arg1=对端 maxdata。此后出向报文的校验和策略与单包上限随之固定。
    fn apply_peer_cnxn(&mut self, header: &AdbMessageHeader, banner: &[u8]) {
        let (version, max_payload) = crate::adb_protocol::negotiate(header.arg0, header.arg1);
        self.protocol_version = version;
        self.max_payload = max_payload;
        self.peer_banner = crate::adb_protocol::parse_banner(&String::from_utf8_lossy(banner));
    }

    /// 设备 CNXN banner（未握手时各字段为空）。5037 server 用它作答 `host:features` 与 `devices -l`。
    pub fn peer_banner(&self) -> &crate::adb_protocol::PeerBanner {
        &self.peer_banner
    }

    /// 打开 `service`（须已带结尾 NUL），返回设备侧 stream id。
    fn open_service(&mut self, local_id: u32, service: &[u8]) -> Result<u32, String> {
        let name = String::from_utf8_lossy(service.strip_suffix(&[0]).unwrap_or(service))
            .replace('\0', " ");
        self.write_message(A_OPEN, local_id, 0, service)
            .map_err(|e| format!("打开 {} 失败: {:?}", name, e))?;
        loop {
            let hdr = self
                .read_header()
                .map_err(|e| format!("读取 {} 的打开响应失败: {:?}", name, e))?;
            // 先读完 payload 再过滤，跳包不消费 payload 会让流错位。
            self.read_payload(hdr.data_length)
                .map_err(|e| format!("读取 {} 的打开响应失败: {:?}", name, e))?;
            if hdr.arg1 != local_id {
                continue;
            }
            match hdr.command {
                A_OKAY => return Ok(hdr.arg0),
                A_CLSE => return Err(format!("设备拒绝 {} 服务", name)),
                _ => {}
            }
        }
    }

    /// 读本 stream 的下一个包：A_WRTE 的载荷追加进 `inbound` 并立即回 A_OKAY；其他 stream 的包读掉丢弃。
    /// `poll` 给出时用可取消的短轮询等报头（等设备长时间处理的收尾阶段用）。
    fn read_stream_packet(
        &mut self,
        local_id: u32,
        inbound: &mut Vec<u8>,
        poll: Option<&crate::embed::CancelToken>,
    ) -> Result<StreamPacket, String> {
        loop {
            let hdr = match poll {
                Some(cancel) => self.wait_stream_header(cancel)?,
                None => self
                    .read_header()
                    .map_err(|e| format!("读取流报头失败: {:?}", e))?,
            };
            let payload = self
                .read_payload(hdr.data_length)
                .map_err(|e| format!("读取流载荷失败: {:?}", e))?;
            if hdr.arg1 != local_id {
                continue;
            }
            match hdr.command {
                A_OKAY => return Ok(StreamPacket::Okay),
                A_WRTE => {
                    inbound.extend_from_slice(&payload);
                    self.write_message(A_OKAY, local_id, hdr.arg0, &[])
                        .map_err(|e| format!("发送 A_OKAY 失败: {:?}", e))?;
                    return Ok(StreamPacket::Data);
                }
                A_CLSE => return Ok(StreamPacket::Closed),
                _ => {}
            }
        }
    }

    /// 发一个 A_WRTE 并等它的 A_OKAY（每包一 A_OKAY 的流控）；等待期间设备回的数据收进 `inbound`。
    /// 返回 true 表示对端已关流。
    fn send_packet(
        &mut self,
        local_id: u32,
        remote_id: u32,
        data: &[u8],
        inbound: &mut Vec<u8>,
    ) -> Result<bool, String> {
        self.write_message(A_WRTE, local_id, remote_id, data)
            .map_err(|e| format!("发送数据失败: {:?}", e))?;
        loop {
            match self.read_stream_packet(local_id, inbound, None)? {
                StreamPacket::Okay => return Ok(false),
                StreamPacket::Data => {}
                StreamPacket::Closed => return Ok(true),
            }
        }
    }

    /// 执行 `service`（如 `exec:cmd package install -S <size>`），把 `stdin` 全部写给它，
    /// 再收齐输出直到对端关流。服务中途关流（如 pm 提前报错）时停止写入、返回已收到的输出。
    pub(crate) fn exec_with_stdin(
        &mut self,
        service: &[u8],
        stdin: &mut dyn Read,
    ) -> Result<Vec<u8>, String> {
        self.connect().map_err(|e| format!("ADB 握手失败: {}", e))?;
        let local_id = new_stream_id();
        let mut dest = service.to_vec();
        dest.push(0);
        let remote_id = self.open_service(local_id, &dest)?;
        let cancel = self
            .op_cancel
            .clone()
            .unwrap_or_else(crate::embed::CancelToken::current);
        let mut packet = vec![0u8; (self.max_payload as usize).max(1)];
        let mut output = Vec::new();
        let mut closed = false;
        while !closed {
            if cancel.is_cancelled() {
                let _ = self.write_message(A_CLSE, local_id, remote_id, &[]);
                return Err("已取消".to_string());
            }
            let n = crate::adb_sync::read_full(stdin, &mut packet)
                .map_err(|e| format!("读取输入失败: {}", e))?;
            if n == 0 {
                break;
            }
            closed = self.send_packet(local_id, remote_id, &packet[..n], &mut output)?;
        }
        while !closed {
            closed = matches!(
                self.read_stream_packet(local_id, &mut output, Some(&cancel))?,
                StreamPacket::Closed
            );
        }
        let _ = self.write_message(A_CLSE, local_id, remote_id, &[]);
        Ok(output)
    }

    fn read_payload(&mut self, len: u32) -> Result<Vec<u8>, TransportError> {
        let mut data = vec![0u8; len as usize];
        if !data.is_empty() {
            self.read_exact(&mut data)?;
        }
        let header = self
            .pending_header
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| TransportError::Usb("ADB payload read without a header".to_string()))?;
        if header.data_length != len {
            return Err(TransportError::Usb(
                "ADB payload length does not match header".to_string(),
            ));
        }
        let validated = if self.is_connected {
            validate_payload(&header, &data, self.protocol_version)
        } else {
            validate_handshake_payload(&header, &data)
        };
        validated.map_err(|e| TransportError::Usb(e.to_string()))?;
        Ok(data)
    }

    /// # 不变量（勿破坏）
    /// [`Self::raw_writer`] 的拷贝交给 `MuxSession` 之后**绝不能**再调用本函数：失败路径会经
    /// [`Self::reopen`] 释放并重开底层句柄，令在外的 `AdbRawWriter` 悬空（WinUSB
    /// use-after-free 静默复发）。`MuxSession::new` 在取 raw_writer 之前完成唯一一次 connect。
    pub fn connect(&mut self) -> Result<(), String> {
        if self.is_connected {
            return Ok(());
        }
        // 连续命令竞争下，上个进程的 WinUSB 句柄释放有秒级延迟，期间新句柄「能 Initialize 却
        // 无法 IO」（发 A_CNXN 即失败），reset pipe 无效，必须重开底层句柄。重试用先快后慢轮询：
        // 15ms 起步、指数封顶 400ms，退避总计约 3.6s（不含 USB IO），覆盖句柄释放窗口。
        // 只有发出公钥后才进入人工授权等待；该阶段结束后不再重复握手。
        const MAX_CONNECT_ATTEMPTS: u32 = 14;
        let mut last_err = String::new();
        // 授权登记保持到函数退出，最终结论登记前不能短暂报回已授权。
        let mut auth_wait: Option<AuthWait> = None;
        for attempt in 0..MAX_CONNECT_ATTEMPTS {
            self.set_read_timeout(HANDSHAKE_READ_TIMEOUT_MS);
            let result = self.try_connect(&mut auth_wait);
            self.set_read_timeout(DEFAULT_READ_TIMEOUT_MS);
            match result {
                Ok(()) => {
                    record_handshake(&serial_from_path(&self.device_path), true);
                    return Ok(());
                }
                Err(e) => {
                    last_err = e;
                    crate::logger::log_line(&format!(
                        "[adb-usb] 握手失败（第 {} 次）：{}",
                        attempt + 1,
                        last_err
                    ));
                    // 发过公钥后失败或超时就结束本次等待，不能反复重开、重弹授权框。
                    if auth_wait.is_some() {
                        break;
                    }
                    if attempt + 1 < MAX_CONNECT_ATTEMPTS {
                        std::thread::sleep(std::time::Duration::from_millis(
                            handle_race_backoff_ms(attempt, 15, 400),
                        ));
                        // 重开底层句柄拿干净的；失败则下一轮继续退避重试
                        let _ = self.reopen();
                    }
                }
            }
        }
        // 发过公钥（进过等授权窗口）却没建成连接：设备仍未授权。必须在 auth_wait 随函数返回
        // drop 之前记下，两份登记之间不能留出一个报 `device` 的空档。
        if auth_wait.is_some() {
            record_handshake(&serial_from_path(&self.device_path), false);
        }
        Err(last_err)
    }

    fn try_connect(&mut self, auth_wait: &mut Option<AuthWait>) -> Result<(), String> {
        // 1. 发送初始的 A_CNXN
        let (header, banner) = crate::adb_protocol::make_connection_message();
        self.write_header(&header)
            .map_err(|e| format!("发送 A_CNXN 失败: {e}"))?;
        self.write_pipe(&banner)
            .map_err(|e| format!("发送 A_CNXN 载荷失败: {e}"))?;

        let mut auth_attempts = 0;

        loop {
            let resp_header = self
                .read_header()
                .map_err(|e| format!("读取报头失败: {:?}", e))?;
            let payload = self
                .read_payload(resp_header.data_length)
                .map_err(|e| format!("读取报文载荷失败: {:?}", e))?;

            if resp_header.command != 0x4e584e43 && resp_header.command != 0x48545541 {
                continue;
            }

            match resp_header.command {
                0x4e584e43 => {
                    // 对端 CNXN 带其版本、maxdata 与 banner：先协商再上线，后续报文按协商结果发。
                    self.apply_peer_cnxn(&resp_header, &payload);
                    self.is_connected = true;
                    crate::logger::log_line("ADB 认证成功，连接已建立");
                    return Ok(());
                }
                0x48545541 => {
                    // 收到 A_AUTH
                    let (priv_pem, mut pub_key) =
                        crate::crypto::get_or_create_keys().map_err(|_| "密钥引擎崩溃")?;

                    if resp_header.arg0 == 1 {
                        // AUTH_TOKEN
                        if auth_attempts == 0 {
                            // 第一次收到 Token：尝试签名并发送
                            auth_attempts += 1;
                            crate::logger::log_line(
                                "ADB 收到认证令牌，已用持久化密钥签名应答（设备若曾授权则免弹窗）",
                            );
                            if let Ok(signature) = crate::crypto::sign_token(&priv_pem, &payload) {
                                // AUTH 发生在协商完成前（版本仍为 MIN）→ write_message 自动带校验和，
                                // 与 AOSP「为 connection/auth 包计算校验和」一致。
                                self.write_message(A_AUTH, 2, 0, &signature)
                                    .map_err(|e| format!("发送签名失败: {:?}", e))?;
                                continue;
                            }
                        }

                        // 第二次及以后收到 Token：说明签名被拒！必须发公钥触发弹窗！
                        if pub_key.last() != Some(&0) {
                            pub_key.push(0);
                        }

                        if auth_attempts == 1 {
                            crate::logger::log_line(
                                "ADB 等待授权：设备未识别本机公钥，已发送公钥，请在手机点击「允许 USB 调试」",
                            );
                            crate::progress::print_info("请点亮手机屏幕并点击「允许 USB 调试」");
                        }
                        if auth_wait.is_none() {
                            *auth_wait = Some(AuthWait::begin(serial_from_path(&self.device_path)));
                        }
                        auth_attempts += 1;

                        self.write_message(A_AUTH, 3, 0, &pub_key)
                            .map_err(|e| format!("发送公钥失败: {:?}", e))?;
                        self.set_read_timeout(AUTH_WAIT_TIMEOUT_MS);
                        continue;
                    }
                }
                _ => {
                    if resp_header.data_length > 0 {
                        let mut data = vec![0u8; resp_header.data_length as usize];
                        let _ = self.read_exact(&mut data);
                    }
                    continue;
                }
            }
        }
    }

    /// 快速连接探测：仅设备已授权时建连成功。与 [`connect`](Self::connect) 不同：绝不发公钥、
    /// 不弹授权框、不等用户，故不会在未授权设备上等 180s。供无控制台的常驻 daemon
    /// 秒级判定并让位给直连路径。
    /// 返回：`Ok(true)`=已授权且建连；`Ok(false)`=未授权（未建连）；`Err`=IO/协议错误。
    pub fn connect_probe(&mut self, timeout_ms: u32) -> Result<bool, String> {
        if self.is_connected {
            return Ok(true);
        }
        // 探测期读写都收紧到 timeout_ms（纵深防御：即便设备被误当 adb，最坏各阻塞一次即返回），
        // 结束后无论成败都恢复常规读/写超时，避免后续 shell 等被探测窗口误伤。
        self.set_read_timeout(timeout_ms);
        self.set_write_timeout(timeout_ms);
        let result = self.try_connect_probe();
        self.set_read_timeout(DEFAULT_READ_TIMEOUT_MS);
        self.set_write_timeout(DEFAULT_WRITE_TIMEOUT_MS);
        // IO/协议错误说明不了授权与否，只记确定的结论。
        if let Ok(authorized) = result {
            record_handshake(&serial_from_path(&self.device_path), authorized);
        }
        result
    }

    fn try_connect_probe(&mut self) -> Result<bool, String> {
        let (header, banner) = crate::adb_protocol::make_connection_message();
        self.write_header(&header).map_err(|_| "发送 A_CNXN 失败")?;
        self.write_pipe(&banner)
            .map_err(|_| "发送 A_CNXN 载荷失败")?;

        let mut signed = false;
        loop {
            let resp = self
                .read_header()
                .map_err(|e| format!("读取报头失败: {:?}", e))?;
            let payload = self
                .read_payload(resp.data_length)
                .map_err(|e| format!("读取报文载荷失败: {:?}", e))?;

            match resp.command {
                // A_CNXN：设备接受，已授权。
                0x4e584e43 => {
                    self.apply_peer_cnxn(&resp, &payload);
                    self.is_connected = true;
                    return Ok(true);
                }
                // A_AUTH
                0x48545541 if resp.arg0 == 1 => {
                    // AUTH_TOKEN：用持久化私钥签名应答一次（设备若记得本机公钥即免弹窗直接通过）。
                    if !signed {
                        signed = true;
                        let (priv_pem, _) =
                            crate::crypto::get_or_create_keys().map_err(|_| "密钥引擎崩溃")?;
                        if let Ok(sig) = crate::crypto::sign_token(&priv_pem, &payload) {
                            self.write_message(A_AUTH, 2, 0, &sig)
                                .map_err(|e| format!("发送签名失败: {:?}", e))?;
                            continue;
                        }
                        return Ok(false);
                    }
                    // 再次收到 Token = 签名被拒 = 未授权。探测模式不发公钥、不等用户，
                    // 立即判定并交由直连路径去弹窗授权。
                    return Ok(false);
                }
                _ => {}
            }
        }
    }

    pub fn reboot(&mut self, target: &str) -> Result<(), String> {
        self.connect()?;
        let local_id = new_stream_id();

        let cmd = if target.is_empty() {
            "reboot:\0".to_string()
        } else {
            format!("reboot:{}\0", target)
        };

        self.write_message(0x4e45504f, local_id, 0, cmd.as_bytes())
            .map_err(|e| format!("发送 reboot 命令失败: {:?}", e))?;

        Ok(())
    }

    pub fn execute_service(&mut self, service: &str) -> Result<Vec<u8>, String> {
        self.connect().map_err(|e| format!("ADB 握手失败: {}", e))?;

        let local_id = new_stream_id();
        let mut remote_id = 0;

        let mut dest_str = service.to_string();
        if !dest_str.ends_with('\0') {
            dest_str.push('\0');
        }

        self.write_message(A_OPEN, local_id, 0, dest_str.as_bytes())
            .map_err(|e| format!("发送 A_OPEN 失败: {:?}", e))?;

        let mut output_buffer = Vec::new();

        loop {
            let resp_header = self.read_header().map_err(|_| "Stream 读取报头失败")?;

            // 先读完 payload 再过滤：跳过不属于本流的包时若不消费其 payload，
            // 下一次 read_header 会从残留 payload 中间解析（流错位）。
            let payload = if resp_header.data_length > 0 {
                let mut data = vec![0u8; resp_header.data_length as usize];
                let _ = self.read_exact(&mut data);
                data
            } else {
                Vec::new()
            };

            if resp_header.arg1 != local_id {
                continue;
            }

            match resp_header.command {
                0x59414b4f => {
                    if remote_id == 0 {
                        remote_id = resp_header.arg0;
                    }
                }
                0x45545257 => {
                    output_buffer.extend_from_slice(&payload);
                    let _ = self.write_message(A_OKAY, local_id, resp_header.arg0, &[]);
                }
                0x45534c43 => {
                    let _ = self.write_message(A_CLSE, local_id, resp_header.arg0, &[]);
                    break;
                }
                _ => {}
            }
        }

        Ok(output_buffer)
    }

    /// 流式（shell 等）等待下一个 stream 报头：短轮询窗口逐次等包，窗口间检查「取消令牌」
    /// 与连续静默上限（[`Self::stream_idle_window_ms`]）。报头恒为单个 24 字节 USB 包，
    /// 轮询超时只会落在包间空隙；万一出现罕见的跨读半头，剩余字节改用常规读超时补齐。
    fn wait_stream_header(
        &self,
        cancel: &crate::embed::CancelToken,
    ) -> Result<AdbMessageHeader, String> {
        self.set_read_timeout(STREAM_HEADER_POLL_MS);
        let outcome = self.poll_stream_header(cancel);
        self.set_read_timeout(DEFAULT_READ_TIMEOUT_MS);
        outcome
    }

    fn poll_stream_header(
        &self,
        cancel: &crate::embed::CancelToken,
    ) -> Result<AdbMessageHeader, String> {
        let mut buf = [0u8; 24];
        let wait_started = std::time::Instant::now();
        let idle_window = std::time::Duration::from_millis(self.stream_idle_window_ms as u64);
        let first = loop {
            if cancel.is_cancelled() {
                return Err("已取消".to_string());
            }
            match self.read_pipe(&mut buf) {
                Ok(n) => break n,
                Err(TransportError::Timeout) => {
                    if wait_started.elapsed() >= idle_window {
                        return Err(format!(
                            "读取流报头失败：设备连续 {} 秒无任何数据",
                            idle_window.as_secs()
                        ));
                    }
                }
                Err(e) => return Err(format!("读取流报头失败: {:?}", e)),
            }
        };
        if first < 24 {
            self.set_read_timeout(DEFAULT_READ_TIMEOUT_MS);
            self.read_exact(&mut buf[first..])
                .map_err(|e| format!("读取流报头失败: {:?}", e))?;
        }
        self.accept_header(&buf)
            .map_err(|e| format!("解析流报头失败: {:?}", e))
    }

    pub fn execute_service_streaming<F>(
        &mut self,
        service: &str,
        mut on_data: F,
    ) -> Result<(), String>
    where
        F: FnMut(&[u8]) -> Result<(), String>,
    {
        self.connect()
            .map_err(|e| format!("ADB handshake failed: {}", e))?;

        let local_id = new_stream_id();
        let mut remote_id = 0;

        let mut dest_str = service.to_string();
        if !dest_str.ends_with('\0') {
            dest_str.push('\0');
        }

        self.write_message(A_OPEN, local_id, 0, dest_str.as_bytes())
            .map_err(|e| format!("failed to send A_OPEN: {:?}", e))?;

        let cancel = self
            .op_cancel
            .clone()
            .unwrap_or_else(crate::embed::CancelToken::current);
        loop {
            let resp_header = self.wait_stream_header(&cancel)?;

            // 先读完 payload 再过滤：跳过不属于本流的包时若不消费其 payload，
            // 下一次 read_header 会从残留 payload 中间解析（流错位）。
            let payload = if resp_header.data_length > 0 {
                let mut data = vec![0u8; resp_header.data_length as usize];
                self.read_exact(&mut data)
                    .map_err(|e| format!("failed to read stream payload: {:?}", e))?;
                data
            } else {
                Vec::new()
            };

            if resp_header.arg1 != local_id {
                continue;
            }

            match resp_header.command {
                A_OKAY => {
                    if remote_id == 0 {
                        remote_id = resp_header.arg0;
                    }
                }
                A_WRTE => {
                    on_data(&payload)?;
                    self.write_message(A_OKAY, local_id, resp_header.arg0, &[])
                        .map_err(|e| format!("failed to send A_OKAY: {:?}", e))?;
                }
                A_CLSE => {
                    let _ = self.write_message(A_CLSE, local_id, resp_header.arg0, &[]);
                    break;
                }
                _ => {}
            }
        }

        let _ = remote_id;
        Ok(())
    }

    pub fn forward_tcp_stream(
        &mut self,
        remote: &str,
        mut local_stream: TcpStream,
    ) -> Result<(), String> {
        struct WriteState {
            can_send: bool,
            closed: bool,
        }

        self.connect()?;
        self.set_read_timeout(0);
        local_stream
            .set_nodelay(true)
            .map_err(|e| format!("failed to configure local socket: {}", e))?;

        let local_id = new_stream_id();
        let mut destination = remote.as_bytes().to_vec();
        destination.push(0);

        self.write_message(A_OPEN, local_id, 0, &destination)
            .map_err(|e| format!("failed to open remote service '{}': {:?}", remote, e))?;

        let remote_id = loop {
            let hdr = self
                .read_header()
                .map_err(|e| format!("failed to read ADB stream open response: {:?}", e))?;
            let _payload = self.read_payload(hdr.data_length).unwrap_or_default();
            if hdr.arg1 != local_id {
                continue;
            }
            match hdr.command {
                A_OKAY => break hdr.arg0,
                A_CLSE => return Err(format!("device rejected remote service '{}'", remote)),
                other => {
                    return Err(format!(
                        "unexpected ADB response while opening '{}': 0x{:08x}",
                        remote, other
                    ));
                }
            }
        };

        let writer = self.raw_writer();
        let write_lock = Arc::new(Mutex::new(()));
        let state = Arc::new((
            Mutex::new(WriteState {
                can_send: true,
                closed: false,
            }),
            Condvar::new(),
        ));

        let mut local_reader = local_stream
            .try_clone()
            .map_err(|e| format!("failed to clone local socket: {}", e))?;
        let close_stream = local_stream
            .try_clone()
            .map_err(|e| format!("failed to clone local socket: {}", e))?;
        let thread_state = state.clone();
        let thread_write_lock = write_lock.clone();
        // 单个 A_WRTE 不得超过对端 maxdata（老 adbd 只有 4KiB）。
        let chunk = (32 * 1024).min(self.max_payload as usize).max(1);

        let upstream = std::thread::spawn(move || {
            let mut buf = vec![0u8; chunk];
            loop {
                let read = match local_reader.read(&mut buf) {
                    Ok(0) => {
                        let _guard = thread_write_lock.lock().ok();
                        let _ = writer.write_message(A_CLSE, local_id, remote_id, &[]);
                        let (lock, cv) = &*thread_state;
                        if let Ok(mut st) = lock.lock() {
                            st.closed = true;
                            cv.notify_all();
                        }
                        break;
                    }
                    Ok(n) => n,
                    Err(_) => {
                        let _guard = thread_write_lock.lock().ok();
                        let _ = writer.write_message(A_CLSE, local_id, remote_id, &[]);
                        let (lock, cv) = &*thread_state;
                        if let Ok(mut st) = lock.lock() {
                            st.closed = true;
                            cv.notify_all();
                        }
                        break;
                    }
                };

                let (lock, cv) = &*thread_state;
                let mut st = match lock.lock() {
                    Ok(st) => st,
                    Err(_) => break,
                };
                while !st.can_send && !st.closed {
                    st = match cv.wait(st) {
                        Ok(st) => st,
                        Err(_) => return,
                    };
                }
                if st.closed {
                    break;
                }
                st.can_send = false;
                drop(st);

                let _guard = thread_write_lock.lock().ok();
                if writer
                    .write_message(A_WRTE, local_id, remote_id, &buf[..read])
                    .is_err()
                {
                    let (lock, cv) = &*thread_state;
                    if let Ok(mut st) = lock.lock() {
                        st.closed = true;
                        cv.notify_all();
                    }
                    break;
                }
            }
            let _ = close_stream.shutdown(Shutdown::Both);
        });

        loop {
            let hdr = match self.read_header() {
                Ok(hdr) => hdr,
                Err(e) => {
                    let (lock, cv) = &*state;
                    if let Ok(mut st) = lock.lock() {
                        st.closed = true;
                        cv.notify_all();
                    }
                    let _ = local_stream.shutdown(Shutdown::Both);
                    let _ = upstream.join();
                    return Err(format!("ADB stream read failed: {:?}", e));
                }
            };
            let payload = self.read_payload(hdr.data_length).unwrap_or_default();
            if hdr.arg1 != local_id {
                continue;
            }

            match hdr.command {
                A_WRTE => {
                    if local_stream.write_all(&payload).is_err() {
                        let _guard = write_lock.lock().ok();
                        let _ = self.write_message(A_CLSE, local_id, hdr.arg0, &[]);
                        break;
                    }
                    let _guard = write_lock.lock().ok();
                    let _ = self.write_message(A_OKAY, local_id, hdr.arg0, &[]);
                }
                A_OKAY => {
                    let (lock, cv) = &*state;
                    if let Ok(mut st) = lock.lock() {
                        st.can_send = true;
                        cv.notify_all();
                    }
                }
                A_CLSE => {
                    let _guard = write_lock.lock().ok();
                    let _ = self.write_message(A_CLSE, local_id, hdr.arg0, &[]);
                    break;
                }
                _ => {}
            }
        }

        let (lock, cv) = &*state;
        if let Ok(mut st) = lock.lock() {
            st.closed = true;
            cv.notify_all();
        }
        let _ = local_stream.shutdown(Shutdown::Both);
        let _ = upstream.join();
        Ok(())
    }

    pub fn reverse_bridge_loop<F>(
        &mut self,
        remote: &str,
        local: &str,
        on_ready: F,
    ) -> Result<(), String>
    where
        F: FnOnce(&str) -> Result<(), String>,
    {
        struct ReverseWriteState {
            can_send: bool,
            closed: bool,
        }

        struct ReverseStream {
            device_id: u32,
            socket: TcpStream,
            state: Arc<(Mutex<ReverseWriteState>, Condvar)>,
            upstream: Option<std::thread::JoinHandle<()>>,
        }

        fn parse_host_tcp_port(local: &str) -> Result<u16, String> {
            let Some(port) = local.strip_prefix("tcp:") else {
                return Err(format!(
                    "native adb reverse currently supports only host local tcp:<port>, got {}",
                    local
                ));
            };
            if port.is_empty() {
                return Err("reverse local tcp port must not be empty".to_string());
            }
            let port = port
                .parse::<u16>()
                .map_err(|_| format!("invalid reverse local tcp port: {}", port))?;
            if port == 0 {
                return Err("reverse local tcp port must not be 0".to_string());
            }
            Ok(port)
        }

        fn connect_host_tcp_service(local: &str) -> Result<TcpStream, String> {
            let port = parse_host_tcp_port(local)?;
            let stream = TcpStream::connect(("127.0.0.1", port))
                .map_err(|e| format!("failed to connect host service {}: {}", local, e))?;
            stream
                .set_nodelay(true)
                .map_err(|e| format!("failed to configure host socket: {}", e))?;
            Ok(stream)
        }

        fn normalize_actual_remote(requested: &str, response: &[u8]) -> String {
            if requested != "tcp:0" {
                return requested.to_string();
            }
            let text = String::from_utf8_lossy(response);
            let trimmed = text.trim_matches(char::from(0)).trim();
            if let Some(port) = trimmed.strip_prefix("tcp:") {
                if port.parse::<u16>().map(|p| p > 0).unwrap_or(false) {
                    return format!("tcp:{}", port);
                }
            }
            if trimmed.parse::<u16>().map(|p| p > 0).unwrap_or(false) {
                return format!("tcp:{}", trimmed);
            }
            requested.to_string()
        }

        fn finish_stream(mut stream: ReverseStream) {
            let (lock, cv) = &*stream.state;
            if let Ok(mut st) = lock.lock() {
                st.closed = true;
                cv.notify_all();
            }
            let _ = stream.socket.shutdown(Shutdown::Both);
            if let Some(upstream) = stream.upstream.take() {
                let _ = upstream.join();
            }
        }

        parse_host_tcp_port(local)?;
        if remote.trim().is_empty() {
            return Err("REMOTE must not be empty".to_string());
        }

        self.connect()?;
        self.set_read_timeout(0);

        let setup_id = self.alloc_local_stream_id();
        let setup_service = format!("reverse:forward:{};{}\0", remote, local);
        self.write_message(A_OPEN, setup_id, 0, setup_service.as_bytes())
            .map_err(|e| format!("failed to request adb reverse setup: {:?}", e))?;

        let mut setup_remote_id = 0;
        let mut setup_output = Vec::new();
        loop {
            let hdr = self
                .read_header()
                .map_err(|e| format!("failed to read reverse setup response: {:?}", e))?;
            let payload = self.read_payload(hdr.data_length).unwrap_or_default();
            if hdr.arg1 != setup_id {
                continue;
            }

            match hdr.command {
                A_OKAY => {
                    setup_remote_id = hdr.arg0;
                }
                A_WRTE => {
                    setup_output.extend_from_slice(&payload);
                    self.write_message(A_OKAY, setup_id, hdr.arg0, &[])
                        .map_err(|e| format!("failed to ack reverse setup response: {:?}", e))?;
                }
                A_CLSE => {
                    let _ = self.write_message(A_CLSE, setup_id, hdr.arg0, &[]);
                    break;
                }
                other => {
                    return Err(format!(
                        "unexpected adb reverse setup packet: 0x{:08x}",
                        other
                    ));
                }
            }
        }

        if setup_remote_id == 0 {
            return Err(format!("device rejected adb reverse service '{}'", remote));
        }
        let setup_text = String::from_utf8_lossy(&setup_output);
        let setup_trimmed = setup_text.trim_matches(char::from(0)).trim();
        if let Some(msg) = setup_trimmed.strip_prefix("FAIL") {
            return Err(if msg.trim().is_empty() {
                "device rejected adb reverse setup".to_string()
            } else {
                msg.trim().to_string()
            });
        }

        let actual_remote = normalize_actual_remote(remote, &setup_output);
        on_ready(&actual_remote)?;

        let writer = self.raw_writer();
        let write_lock = Arc::new(Mutex::new(()));
        let mut streams: HashMap<u32, ReverseStream> = HashMap::new();

        loop {
            let hdr = self
                .read_header()
                .map_err(|e| format!("ADB reverse stream read failed: {:?}", e))?;
            let payload = self.read_payload(hdr.data_length).unwrap_or_default();

            match hdr.command {
                A_OPEN => {
                    let requested = String::from_utf8_lossy(&payload)
                        .trim_matches(char::from(0))
                        .to_string();
                    let host_socket = match connect_host_tcp_service(local) {
                        Ok(socket) => socket,
                        Err(e) => {
                            eprintln!(
                                "adb reverse could not open host target {} for {}: {}",
                                local, requested, e
                            );
                            let _guard = write_lock.lock().ok();
                            let _ = self.write_message(A_CLSE, 0, hdr.arg0, &[]);
                            continue;
                        }
                    };

                    let local_id = self.alloc_local_stream_id();
                    let device_id = hdr.arg0;
                    let mut local_reader = host_socket
                        .try_clone()
                        .map_err(|e| format!("failed to clone reverse host socket: {}", e))?;
                    let close_socket = host_socket
                        .try_clone()
                        .map_err(|e| format!("failed to clone reverse host socket: {}", e))?;
                    let state = Arc::new((
                        Mutex::new(ReverseWriteState {
                            can_send: true,
                            closed: false,
                        }),
                        Condvar::new(),
                    ));
                    let thread_state = state.clone();
                    let thread_write_lock = write_lock.clone();
                    let chunk = (32 * 1024).min(self.max_payload as usize).max(1);
                    let upstream = std::thread::spawn(move || {
                        let mut buf = vec![0u8; chunk];
                        loop {
                            let read = match local_reader.read(&mut buf) {
                                Ok(0) => {
                                    let _guard = thread_write_lock.lock().ok();
                                    let _ = writer.write_message(A_CLSE, local_id, device_id, &[]);
                                    let (lock, cv) = &*thread_state;
                                    if let Ok(mut st) = lock.lock() {
                                        st.closed = true;
                                        cv.notify_all();
                                    }
                                    break;
                                }
                                Ok(n) => n,
                                Err(_) => {
                                    let _guard = thread_write_lock.lock().ok();
                                    let _ = writer.write_message(A_CLSE, local_id, device_id, &[]);
                                    let (lock, cv) = &*thread_state;
                                    if let Ok(mut st) = lock.lock() {
                                        st.closed = true;
                                        cv.notify_all();
                                    }
                                    break;
                                }
                            };

                            let (lock, cv) = &*thread_state;
                            let mut st = match lock.lock() {
                                Ok(st) => st,
                                Err(_) => break,
                            };
                            while !st.can_send && !st.closed {
                                st = match cv.wait(st) {
                                    Ok(st) => st,
                                    Err(_) => return,
                                };
                            }
                            if st.closed {
                                break;
                            }
                            st.can_send = false;
                            drop(st);

                            let _guard = thread_write_lock.lock().ok();
                            if writer
                                .write_message(A_WRTE, local_id, device_id, &buf[..read])
                                .is_err()
                            {
                                let (lock, cv) = &*thread_state;
                                if let Ok(mut st) = lock.lock() {
                                    st.closed = true;
                                    cv.notify_all();
                                }
                                break;
                            }
                        }
                        let _ = close_socket.shutdown(Shutdown::Both);
                    });

                    let _guard = write_lock.lock().ok();
                    if self
                        .write_message(A_OKAY, local_id, device_id, &[])
                        .is_err()
                    {
                        finish_stream(ReverseStream {
                            device_id,
                            socket: host_socket,
                            state,
                            upstream: Some(upstream),
                        });
                        continue;
                    }
                    drop(_guard);

                    streams.insert(
                        local_id,
                        ReverseStream {
                            device_id,
                            socket: host_socket,
                            state,
                            upstream: Some(upstream),
                        },
                    );
                }
                A_WRTE => {
                    let local_id = hdr.arg1;
                    let mut close_after = None;
                    let ack = if let Some(stream) = streams.get_mut(&local_id) {
                        let device_id = stream.device_id;
                        if stream.socket.write_all(&payload).is_err() {
                            close_after = Some((local_id, device_id));
                            None
                        } else {
                            Some((local_id, device_id))
                        }
                    } else {
                        None
                    };

                    if let Some((local_id, device_id)) = ack {
                        let _guard = write_lock.lock().ok();
                        let _ = self.write_message(A_OKAY, local_id, device_id, &[]);
                    }
                    if let Some((local_id, device_id)) = close_after {
                        if let Some(stream) = streams.remove(&local_id) {
                            finish_stream(stream);
                        }
                        let _guard = write_lock.lock().ok();
                        let _ = self.write_message(A_CLSE, local_id, device_id, &[]);
                    }
                }
                A_OKAY => {
                    if let Some(stream) = streams.get(&hdr.arg1) {
                        let (lock, cv) = &*stream.state;
                        if let Ok(mut st) = lock.lock() {
                            st.can_send = true;
                            cv.notify_all();
                        }
                    }
                }
                A_CLSE => {
                    let local_id = hdr.arg1;
                    if let Some(stream) = streams.remove(&local_id) {
                        let device_id = stream.device_id;
                        let _guard = write_lock.lock().ok();
                        let _ = self.write_message(A_CLSE, local_id, device_id, &[]);
                        drop(_guard);
                        finish_stream(stream);
                    }
                }
                _ => {}
            }
        }
    }

    pub fn shell_command_streaming<FO, FE>(
        &mut self,
        command: &str,
        mut on_stdout: FO,
        mut on_stderr: FE,
    ) -> Result<ShellExit, String>
    where
        FO: FnMut(&[u8]),
        FE: FnMut(&[u8]),
    {
        match self.shell_v2_streaming(command, &mut on_stdout, &mut on_stderr) {
            Ok(exit) => Ok(exit),
            Err(e) if e.starts_with("shell v2 unsupported:") => {
                self.shell_legacy_streaming(command, &mut on_stdout)
            }
            Err(e) => Err(e),
        }
    }

    fn shell_v2_streaming<FO, FE>(
        &mut self,
        command: &str,
        on_stdout: &mut FO,
        on_stderr: &mut FE,
    ) -> Result<ShellExit, String>
    where
        FO: FnMut(&[u8]),
        FE: FnMut(&[u8]),
    {
        let service = format!("shell,v2,raw:{}", command);
        let mut pending = Vec::new();
        let mut exit_code = 0;
        let mut saw_exit = false;
        let mut saw_packet = false;

        self.execute_service_streaming(&service, |payload| {
            if saw_exit {
                return Ok(());
            }

            pending.extend_from_slice(payload);
            loop {
                if pending.len() < 5 {
                    break;
                }

                let payload_len =
                    u32::from_le_bytes([pending[1], pending[2], pending[3], pending[4]]) as usize;
                let packet_len = 5 + payload_len;
                if pending.len() < packet_len {
                    break;
                }

                let had_packet = saw_packet;
                let packet = parse_shell_v2_packet(&pending[..packet_len])?;
                pending.drain(..packet_len);

                match packet.kind {
                    ShellV2Kind::Stdout => on_stdout(&packet.payload),
                    ShellV2Kind::Stderr => on_stderr(&packet.payload),
                    ShellV2Kind::Exit => {
                        exit_code = packet.exit_code().unwrap_or(0);
                        saw_exit = true;
                        saw_packet = true;
                        break;
                    }
                    ShellV2Kind::Invalid(kind) => {
                        if !had_packet {
                            return Err(format!(
                                "shell v2 unsupported: invalid packet kind {}",
                                kind
                            ));
                        }
                        return Err(format!("invalid shell v2 packet kind {}", kind));
                    }
                    _ => {}
                }

                saw_packet = true;
            }

            Ok(())
        })?;

        if !saw_exit {
            if !saw_packet {
                return Err("shell v2 unsupported: empty or invalid response".into());
            }
            if !pending.is_empty() {
                return Err("shell v2 stream ended with a truncated packet".into());
            }
            return Err("shell v2 stream ended without exit packet".into());
        }

        Ok(ShellExit {
            code: exit_code,
            protocol: ShellProtocol::V2,
        })
    }

    fn shell_legacy_streaming<FO>(
        &mut self,
        command: &str,
        on_stdout: &mut FO,
    ) -> Result<ShellExit, String>
    where
        FO: FnMut(&[u8]),
    {
        let service = format!("shell:{}", command);
        self.execute_service_streaming(&service, |payload| {
            on_stdout(payload);
            Ok(())
        })?;
        Ok(ShellExit {
            code: 0,
            protocol: ShellProtocol::Legacy,
        })
    }

    pub fn shell_command(&mut self, command: &str) -> Result<String, String> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = self.shell_command_streaming(
            command,
            |b| stdout.extend_from_slice(b),
            |b| stderr.extend_from_slice(b),
        )?;

        if exit.code == 0 {
            Ok(String::from_utf8_lossy(&stdout).to_string())
        } else if !stderr.is_empty() {
            Err(String::from_utf8_lossy(&stderr).to_string())
        } else {
            Err(String::from_utf8_lossy(&stdout).to_string())
        }
    }

    pub fn screencap(&mut self, save_path: &str) -> Result<(), String> {
        let raw_data = self.execute_service("exec:screencap -p")?;

        fs::write(save_path, &raw_data).map_err(|e| format!("保存图片失败: {}", e))?;
        Ok(())
    }

    pub fn push(&mut self, local_path: &str, remote_path: &str) -> Result<(), String> {
        self.connect().map_err(|e| format!("ADB 握手失败: {}", e))?;
        let mode = crate::adb_sync::SyncMode::for_device(&self.peer_banner.features);
        match self.push_with_mode(local_path, remote_path, mode) {
            Err(e) if mode != crate::adb_sync::SyncMode::V1 && e != "已取消" => {
                crate::logger::log_line(&format!("sync v2 push 失败，回退 v1 重试: {}", e));
                self.push_with_mode(local_path, remote_path, crate::adb_sync::SyncMode::V1)
            }
            other => other,
        }
    }

    /// sync 是字节流：请求、DATA 块、DONE 按协商 maxdata 连续打包进 A_WRTE（多块共用一包），
    /// 每包等一个 A_OKAY。设备中途回的 FAIL 随时收下并停止发送。
    fn push_with_mode(
        &mut self,
        local_path: &str,
        remote_path: &str,
        mode: crate::adb_sync::SyncMode,
    ) -> Result<(), String> {
        use crate::adb_sync::{parse_status, read_full, PushStream};

        let file = fs::File::open(local_path).map_err(|e| format!("打开本地文件失败: {}", e))?;
        let push_total = file.metadata().map(|m| m.len()).unwrap_or(0);
        let local_id = new_stream_id();
        let remote_id = self.open_service(local_id, b"sync:\0")?;

        // 传输进度接进 xfer 快照（与 fastboot flash 同一套），宿主 UI 轮询即可画进度/速率。
        // 直连设备对象不记序列号，计入不指定设备的通道（adb 侧不参与批量并发传输）。
        let xfer = crate::embed::XferRun::start(None, push_total);

        let cancel = self
            .op_cancel
            .clone()
            .unwrap_or_else(crate::embed::CancelToken::current);
        let mtime = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        let mut stream = PushStream::new(file, remote_path, PUSH_FILE_MODE, mtime, mode)
            .map_err(|e| format!("初始化 sync 流失败: {}", e))?;
        let mut packet = vec![0u8; (self.max_payload as usize).max(1)];
        let mut status = Vec::new();
        let mut reported = 0u64;
        let mut closed = false;
        loop {
            // 分包之间协作式取消：进程内没有子进程可杀，「停止」只能靠这里及时中止传输。
            if cancel.is_cancelled() {
                let _ = self.write_message(A_CLSE, local_id, remote_id, &[]);
                return Err("已取消".to_string());
            }
            let n =
                read_full(&mut stream, &mut packet).map_err(|e| format!("读取文件失败: {}", e))?;
            if n == 0 {
                break;
            }
            closed = self.send_packet(local_id, remote_id, &packet[..n], &mut status)?;
            let sent = stream.file_bytes();
            xfer.add(sent - reported);
            reported = sent;
            if closed || parse_status(&status).is_some() {
                break;
            }
        }
        while !closed && parse_status(&status).is_none() {
            closed = matches!(
                self.read_stream_packet(local_id, &mut status, Some(&cancel))?,
                StreamPacket::Closed
            );
        }
        if !closed {
            let _ = self.write_message(A_CLSE, local_id, remote_id, &[]);
        }
        match parse_status(&status) {
            Some(Ok(())) => Ok(()),
            Some(Err(reason)) => Err(format!("手机底层的 SYNC 引擎拒绝了传输: {}", reason)),
            None => Err("手机提前关闭了连接，可能空间不足或路径非法".into()),
        }
    }

    pub fn pull(&mut self, remote_path: &str, local_path: &str) -> Result<(), String> {
        self.connect()?;
        let mode = crate::adb_sync::SyncMode::for_device(&self.peer_banner.features);
        match self.pull_with_mode(remote_path, local_path, mode) {
            Err(e) if mode != crate::adb_sync::SyncMode::V1 && e != "已取消" => {
                crate::logger::log_line(&format!("sync v2 pull 失败，回退 v1 重试: {}", e));
                self.pull_with_mode(remote_path, local_path, crate::adb_sync::SyncMode::V1)
            }
            other => other,
        }
    }

    fn pull_with_mode(
        &mut self,
        remote_path: &str,
        local_path: &str,
        mode: crate::adb_sync::SyncMode,
    ) -> Result<(), String> {
        use crate::adb_sync::{recv_request, PullProgress, PullSink};

        let local_id = new_stream_id();
        let remote_id = self.open_service(local_id, b"sync:\0")?;
        let file = fs::File::create(local_path).map_err(|e| format!("无法创建本地文件: {}", e))?;
        let mut sink = PullSink::new(std::io::BufWriter::new(file), mode)
            .map_err(|e| format!("初始化 sync 流失败: {}", e))?;

        // 回读进度接进 xfer 快照（与 push 同一套，见 embed::Xfer）。RECV 不带文件大小，
        // 总量报 0，百分比由宿主用它已知的期望大小折算；v2 按解压后的字节计。
        let xfer = crate::embed::XferRun::start(None, 0);

        self.write_message(
            A_WRTE,
            local_id,
            remote_id,
            &recv_request(remote_path, mode),
        )
        .map_err(|e| format!("发送 RECV 请求失败: {:?}", e))?;

        let cancel = self
            .op_cancel
            .clone()
            .unwrap_or_else(crate::embed::CancelToken::current);
        let mut inbound = Vec::new();
        let mut reported = 0u64;
        let outcome = loop {
            // 数据包之间协作式取消：pull 的数据持续流入，这里能在秒级内响应「停止」。
            if cancel.is_cancelled() {
                break Err("已取消".to_string());
            }
            match self.read_stream_packet(local_id, &mut inbound, None)? {
                StreamPacket::Okay => {}
                StreamPacket::Data => {
                    let progress = sink.feed(&inbound);
                    inbound.clear();
                    let written = sink.bytes_written();
                    xfer.add(written - reported);
                    reported = written;
                    match progress {
                        Ok(PullProgress::Done) => break Ok(()),
                        Ok(PullProgress::More) => {}
                        Err(e) => break Err(e),
                    }
                }
                StreamPacket::Closed => break Err("设备在传完之前关闭了 sync 流".to_string()),
            }
        };
        let _ = self.write_message(A_CLSE, local_id, remote_id, &[]);
        outcome
    }

    pub fn logcat(&mut self, grep_keyword: Option<&str>) -> Result<(), String> {
        self.connect()?;
        // 流式抓日志：设备安静时可能长时间无新日志，属正常。关掉读超时（0=无限），
        // 由用户 Ctrl+C 结束，避免默认读超时在空闲时误判掉线而中断 logcat。
        self.set_read_timeout(0);
        let local_id = new_stream_id();

        self.write_message(0x4e45504f, local_id, 0, b"shell:logcat\0")
            .map_err(|e| format!("发送 logcat OPEN 失败: {:?}", e))?;

        loop {
            let hdr = self.read_header().map_err(|_| "读取通道确认失败")?;
            let _ = self.read_payload(hdr.data_length);
            if hdr.arg1 == local_id && hdr.command == 0x59414b4f {
                break;
            }
        }

        if let Some(kw) = grep_keyword {
            println!("拦截包含 {} 的日志 Ctrl+C 退出", kw);
        }

        let mut line_buffer = String::new();

        while let Ok(hdr) = self.read_header() {
            let payload = self.read_payload(hdr.data_length).unwrap_or_default();

            if hdr.command == 0x45545257 {
                let text = String::from_utf8_lossy(&payload);
                line_buffer.push_str(&text);

                while let Some(pos) = line_buffer.find('\n') {
                    let line = line_buffer[..=pos].to_string();
                    line_buffer.drain(..=pos);

                    match grep_keyword {
                        Some(kw) => {
                            if line.contains(kw) {
                                print!("{}", line);
                            }
                        }
                        None => print!("{}", line),
                    }
                }

                use std::io::Write;
                let _ = std::io::stdout().flush();

                let _ = self.write_message(0x59414b4f, local_id, hdr.arg0, &[]);
            } else if hdr.command == 0x45534c43 {
                let _ = self.write_message(0x45534c43, local_id, hdr.arg0, &[]);
                break;
            }
        }
        Ok(())
    }

    pub fn root(&mut self) -> Result<(), String> {
        self.connect()?;
        let local_id = 999;

        self.write_message(0x4e45504f, local_id, 0, b"root:\0")
            .map_err(|e| format!("发送 root OPEN 失败: {:?}", e))?;

        let mut output = Vec::new();
        while let Ok(hdr) = self.read_header() {
            let payload = self.read_payload(hdr.data_length).unwrap_or_default();
            if hdr.command == 0x45545257 {
                output.extend_from_slice(&payload);
                let _ = self.write_message(0x59414b4f, local_id, hdr.arg0, &[]);
            } else if hdr.command == 0x45534c43 {
                break;
            }
        }
        crate::progress::print_info(&String::from_utf8_lossy(&output));
        Ok(())
    }

    pub fn unroot(&mut self) -> Result<(), String> {
        self.connect()?;
        let local_id = 888;

        self.write_message(0x4e45504f, local_id, 0, b"unroot:\0")
            .map_err(|e| format!("发送 unroot OPEN 失败: {:?}", e))?;

        let mut output = Vec::new();
        while let Ok(hdr) = self.read_header() {
            let payload = self.read_payload(hdr.data_length).unwrap_or_default();
            if hdr.command == 0x45545257 {
                output.extend_from_slice(&payload);
                let _ = self.write_message(0x59414b4f, local_id, hdr.arg0, &[]);
            } else if hdr.command == 0x45534c43 {
                break;
            }
        }
        crate::progress::print_info(&String::from_utf8_lossy(&output));
        Ok(())
    }

    pub fn true_pty_shell(&mut self) -> Result<(), String> {
        self.connect()?;
        let local_id = new_stream_id();

        self.write_message(0x4e45504f, local_id, 0, b"shell:\0")
            .map_err(|e| format!("发送 shell OPEN 失败: {:?}", e))?;

        let remote_id = loop {
            let hdr = self.read_header().map_err(|_| "读取通道确认失败")?;
            let _ = self.read_payload(hdr.data_length);
            if hdr.arg1 == local_id && hdr.command == 0x59414b4f {
                break hdr.arg0;
            }
        };

        // 交互式终端：用户可能长时间不输入、设备也不回包，属正常空闲。关掉读超时（0=无限），
        // 否则默认读超时会在空闲时误判掉线而退出终端。
        self.set_read_timeout(0);

        println!("输入 exit 退出");

        use std::sync::{Arc, Mutex};
        // 不把 `&mut Self` 裸指针跨线程共享（可变别名 UB）：两侧各持 Copy 的 `AdbRawWriter`，
        // 所有写经同一把 `write_lock` 串行化；读只在主线程走入端点，互不干扰。
        let writer = self.raw_writer();
        let write_lock = Arc::new(Mutex::new(()));

        let expected_cmd = Arc::new(Mutex::new(String::new()));
        let is_skipping = Arc::new(Mutex::new(false));

        let write_lock_clone = write_lock.clone();
        let expected_cmd_clone = expected_cmd.clone();
        let is_skipping_clone = is_skipping.clone();

        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            loop {
                let mut buf = String::new();
                if stdin.read_line(&mut buf).is_ok() {
                    let cmd = buf.trim_end();
                    if cmd == "exit_rusty" {
                        std::process::exit(0);
                    }

                    if !cmd.is_empty() {
                        *expected_cmd_clone.lock().unwrap() = cmd.to_string();
                        *is_skipping_clone.lock().unwrap() = true;
                    }

                    let script = format!("{}\n", cmd);

                    let _guard = write_lock_clone.lock().unwrap();
                    let _ =
                        writer.write_message(0x45545257, local_id, remote_id, script.as_bytes());
                }
            }
        });

        let mut skip_buffer = String::new();

        while let Ok(hdr) = self.read_header() {
            let payload = self.read_payload(hdr.data_length).unwrap_or_default();

            if hdr.arg1 != local_id {
                continue;
            }

            if hdr.command == 0x45545257 {
                let payload_str = String::from_utf8_lossy(&payload);
                let mut text_to_print = String::new();

                {
                    let mut skipping = is_skipping.lock().unwrap();
                    if *skipping {
                        skip_buffer.push_str(&payload_str);

                        while let Some(idx) = skip_buffer.find('\n') {
                            let line = skip_buffer[..=idx].to_string();
                            let expected = expected_cmd.lock().unwrap().clone();

                            skip_buffer = skip_buffer[idx + 1..].to_string();

                            if line.contains(&expected) {
                                *skipping = false;
                                text_to_print.push_str(&skip_buffer);
                                skip_buffer.clear();
                                break;
                            }
                        }
                    } else {
                        text_to_print.push_str(&payload_str);
                    }
                }

                if !text_to_print.is_empty() {
                    print!("{}", text_to_print);
                    use std::io::Write;
                    let _ = std::io::stdout().flush();
                }

                let _guard = write_lock.lock().unwrap();
                let _ = writer.write_message(0x59414b4f, local_id, hdr.arg0, &[]);
            } else if hdr.command == 0x45534c43 {
                let _guard = write_lock.lock().unwrap();
                let _ = writer.write_message(0x45534c43, local_id, hdr.arg0, &[]);
                break;
            }
        }
        Ok(())
    }

    /// 全双工中继：把设备 ADB 流（`A_OPEN <service>`）与 TCP 客户端 socket 双向桥接，
    /// 供 ADB server(5037) 代理需要客户端输入的 local 服务（交互式 shell / sync: 等）。
    /// 复用 [`forward_tcp_stream`]：客户端→设备方向有 A_OKAY 窗口流控（大文件 push 不会打爆设备缓冲），
    /// 设备→客户端每包回 A_OKAY。真机端到端行为需接入设备后验证。
    pub fn relay_stream_tcp(
        &mut self,
        service: &str,
        tcp: &std::net::TcpStream,
    ) -> Result<(), String> {
        let client = tcp
            .try_clone()
            .map_err(|e| format!("clone socket 失败: {}", e))?;
        self.forward_tcp_stream(service, client)
    }

    /// `adb install -r <apk>`（CLI 入口）。实现见 [`crate::adb_install`]。
    pub fn install(&mut self, apk_path: &str) -> Result<(), String> {
        crate::adb_install::install(self, apk_path, &crate::adb_install::replace_flag(true))
            .map(|_| ())
    }

    /// `adb install-multiple [-r] <apk...>`（CLI 入口）。实现见 [`crate::adb_install`]。
    pub fn install_multiple(&mut self, apk_paths: &[String], replace: bool) -> Result<(), String> {
        crate::adb_install::install_multiple(
            self,
            apk_paths,
            &crate::adb_install::replace_flag(replace),
        )
        .map(|_| ())
    }

    pub fn sideload(&mut self, package_path: &str) -> Result<(), String> {
        const BLOCK_SIZE: usize = 64 * 1024;

        let mut file = fs::File::open(package_path)
            .map_err(|e| format!("failed to open sideload package '{}': {}", package_path, e))?;
        let size = file
            .metadata()
            .map_err(|e| format!("failed to stat sideload package '{}': {}", package_path, e))?
            .len();
        if size == 0 {
            return Err("sideload package is empty".to_string());
        }

        self.connect()?;
        self.set_read_timeout(0);
        // 单块必须装进一个 A_WRTE（≤ 协商 maxdata）；块长在 sideload-host 服务串里声明。
        let block_size = BLOCK_SIZE.min((self.max_payload as usize).max(1));
        let result = self.sideload_host(&mut file, size, block_size);
        self.set_read_timeout(DEFAULT_READ_TIMEOUT_MS);
        result
    }

    fn sideload_host(
        &mut self,
        file: &mut fs::File,
        size: u64,
        block_size: usize,
    ) -> Result<(), String> {
        let service = format!("sideload-host:{}:{}", size, block_size);
        let local_id = new_stream_id();
        let mut destination = service.into_bytes();
        destination.push(0);

        self.write_message(A_OPEN, local_id, 0, &destination)
            .map_err(|e| format!("failed to open sideload-host service: {:?}", e))?;

        let remote_id = loop {
            let hdr = self
                .read_header()
                .map_err(|e| format!("failed to read sideload open response: {:?}", e))?;
            let _ = self.read_payload(hdr.data_length);
            if hdr.arg1 != local_id {
                continue;
            }
            match hdr.command {
                A_OKAY => break hdr.arg0,
                A_CLSE => return Err("device rejected sideload-host service".to_string()),
                _ => {}
            }
        };

        let mut sent: u64 = 0;
        loop {
            let hdr = self
                .read_header()
                .map_err(|e| format!("failed to read sideload request: {:?}", e))?;
            let payload = self
                .read_payload(hdr.data_length)
                .map_err(|e| format!("failed to read sideload request payload: {:?}", e))?;
            if hdr.arg1 != local_id {
                continue;
            }
            match hdr.command {
                A_WRTE => {
                    self.write_message(A_OKAY, local_id, hdr.arg0, &[])
                        .map_err(|e| format!("failed to ack sideload request: {:?}", e))?;

                    if payload == b"DONEDONE" {
                        println!("\rTotal xfer: {:.2}x", sent as f64 / size as f64);
                        let _ = self.write_message(A_CLSE, local_id, remote_id, &[]);
                        return Ok(());
                    }
                    if payload == b"FAILFAIL" {
                        return Err("device reported sideload failure".to_string());
                    }
                    if payload.len() != 8 {
                        return Err(format!("invalid sideload block request: {:?}", payload));
                    }

                    let block_text = String::from_utf8_lossy(&payload);
                    let block = block_text
                        .parse::<u64>()
                        .map_err(|_| format!("invalid sideload block number: {}", block_text))?;
                    let offset = block.saturating_mul(block_size as u64);
                    if offset >= size {
                        return Err(format!(
                            "device requested sideload block beyond EOF: {}",
                            block
                        ));
                    }
                    let to_read = ((size - offset).min(block_size as u64)) as usize;
                    let mut data = vec![0u8; to_read];
                    file.seek(SeekFrom::Start(offset))
                        .map_err(|e| format!("failed to seek sideload package: {}", e))?;
                    file.read_exact(&mut data)
                        .map_err(|e| format!("failed to read sideload package: {}", e))?;
                    self.write_message(A_WRTE, local_id, remote_id, &data)
                        .map_err(|e| format!("failed to send sideload block: {:?}", e))?;
                    self.wait_stream_okay(local_id)?;
                    sent = sent.saturating_add(to_read as u64);
                    print!("\rTotal xfer: {:.2}x", sent as f64 / size as f64);
                    let _ = std::io::stdout().flush();
                }
                A_CLSE => return Err("device closed sideload stream".to_string()),
                A_OKAY => {}
                _ => {}
            }
        }
    }

    fn wait_stream_okay(&mut self, local_id: u32) -> Result<(), String> {
        loop {
            let hdr = self
                .read_header()
                .map_err(|e| format!("failed to read stream OKAY: {:?}", e))?;
            let _ = self.read_payload(hdr.data_length);
            if hdr.arg1 != local_id {
                continue;
            }
            match hdr.command {
                A_OKAY => return Ok(()),
                A_CLSE => return Err("device closed stream".to_string()),
                _ => {}
            }
        }
    }

    /// 录屏到设备临时文件再拉回本地。录制期间设备端 `screenrecord` 阻塞不回包，
    /// 故临时把读超时放宽到「录制时长 + 30s」，避免默认读超时中途误判掉线。
    pub fn screenrecord(&mut self, output_path: &str, time_limit: u32) -> Result<(), String> {
        let remote = "/data/local/tmp/recording.mp4";
        self.connect()?;
        self.set_read_timeout(time_limit.saturating_add(30).saturating_mul(1000));
        let cmd = format!("screenrecord --time-limit {} {}", time_limit, remote);
        let record_result = self.shell_command(&cmd);
        self.set_read_timeout(DEFAULT_READ_TIMEOUT_MS);
        record_result?;
        self.pull(remote, output_path)?;
        let _ = self.shell_command(&format!("rm {}", remote));
        Ok(())
    }
}

impl Drop for AdbWinUsbDevice {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Devices::Usb::WinUsb_Free(self.winusb_handle);
            let _ = CloseHandle(self.device_handle);
        }
    }
}

unsafe fn widestring_to_string(ptr: *const u16) -> String {
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf16_lossy(slice)
}

#[cfg(test)]
mod usb_packet_tests {
    use super::*;
    use crate::adb_protocol::{payload_checksum, ADB_VERSION, A_CNXN};
    use std::collections::VecDeque;

    /// 回放 USB 传输：整包对齐的 CNXN / WRTE 之后会有 ZLP，下一次读仍必须得到下一条 ADB 包。
    #[test]
    fn zero_length_usb_packets_preserve_adb_frame_boundaries() {
        let mut banner = b"device::features=shell_v2;".to_vec();
        banner.resize(64, b';');
        let output = vec![b'x'; 512];
        let frames = [(A_CNXN, banner), (A_WRTE, output), (A_CLSE, Vec::new())];
        let mut transfers = VecDeque::new();
        transfers.push_back(Vec::new());
        for (command, payload) in &frames {
            transfers.push_back(
                AdbMessageHeader::for_payload(
                    *command,
                    ADB_VERSION,
                    4096,
                    payload,
                    crate::adb_protocol::ADB_VERSION_MIN,
                )
                .encode(),
            );
            if !payload.is_empty() {
                transfers.push_back(payload.clone());
            }
            transfers.push_back(Vec::new());
        }
        let mut read = |buf: &mut [u8]| {
            let transfer = transfers.pop_front().expect("不能多读或丢失传输");
            assert!(transfer.len() <= buf.len());
            buf[..transfer.len()].copy_from_slice(&transfer);
            Ok(transfer.len())
        };
        for (command, expected_payload) in frames {
            let mut raw_header = [0; 24];
            assert_eq!(read_usb_data(&mut raw_header, &mut read).unwrap(), 24);
            let header = AdbMessageHeader::decode(&raw_header).unwrap();
            assert_eq!(header.command, command);
            let mut payload = vec![0; header.data_length as usize];
            assert_eq!(
                read_usb_data(&mut payload, &mut read).unwrap(),
                payload.len()
            );
            assert_eq!(payload, expected_payload);
            assert_eq!(header.data_checksum, payload_checksum(&payload));
        }
        assert_eq!(transfers.len(), 1, "最后一个 ZLP 留给下次读，不吞后继报文");
    }

    #[test]
    fn zero_length_usb_packets_do_not_hide_timeout_or_disconnect() {
        for error in [TransportError::Timeout, TransportError::Disconnected] {
            let mut responses = VecDeque::from([Ok(0), Ok(0), Err(error)]);
            let result = read_usb_data(&mut [0; 24], |_| responses.pop_front().unwrap());
            assert!(matches!(
                result,
                Err(TransportError::Timeout | TransportError::Disconnected)
            ));
            assert!(responses.is_empty());
        }
    }

    #[test]
    fn empty_usb_read_does_not_consume_a_transfer() {
        assert_eq!(
            read_usb_data(&mut [], |_| panic!("空缓冲不应发起 USB IO")).unwrap(),
            0
        );
    }
}

#[cfg(test)]
mod shell_v2_tests {
    use super::*;

    #[test]
    fn parse_shell_v2_stdout_packet() {
        let packet = parse_shell_v2_packet(&[1, 2, 0, 0, 0, b'o', b'k']).unwrap();
        assert_eq!(packet.kind, ShellV2Kind::Stdout);
        assert_eq!(packet.payload, b"ok");
    }

    #[test]
    fn parse_shell_v2_exit_packet() {
        let packet = parse_shell_v2_packet(&[3, 1, 0, 0, 0, 7]).unwrap();
        assert_eq!(packet.kind, ShellV2Kind::Exit);
        assert_eq!(packet.exit_code(), Some(7));
    }

    #[test]
    fn parse_shell_v2_rejects_short_packet() {
        assert!(parse_shell_v2_packet(&[1, 0, 0]).is_err());
    }

    /// 静默窗口选择：绝不窄于默认 60s（普通短命令行为不变）；调用方超时更长则放宽到它。
    #[test]
    fn shell_idle_window_never_narrower_than_default() {
        assert_eq!(shell_idle_window_ms(0), DEFAULT_READ_TIMEOUT_MS);
        assert_eq!(shell_idle_window_ms(30), DEFAULT_READ_TIMEOUT_MS);
        assert_eq!(shell_idle_window_ms(60), DEFAULT_READ_TIMEOUT_MS);
        assert_eq!(shell_idle_window_ms(61), 61_000);
        assert_eq!(shell_idle_window_ms(7200), 7_200_000);
        assert_eq!(shell_idle_window_ms(u32::MAX), u32::MAX);
    }

    /// `read_payload` 只认 `accept_header` 登记的报头。可取消的轮询读报头若自己解码，
    /// push 收尾等 SYNC 状态时就报「payload read without a header」（文件其实已写完）。
    /// 走源码断言：真跑要设备晚于 A_OKAY 回状态，离线造不出这个时序。
    #[test]
    fn every_pipe_header_read_registers_the_pending_header() {
        let src = include_str!("adb_winusb_transport.rs");
        let body = |signature: &str| {
            src.split(signature)
                .nth(1)
                .and_then(|tail| tail.split("\n    }\n").next())
                .unwrap_or_else(|| panic!("应能定位 {signature}"))
                .to_string()
        };
        for reader in [
            "pub fn read_header(&self) -> Result<AdbMessageHeader, TransportError> {",
            "    fn poll_stream_header(",
        ] {
            let body = body(reader);
            assert!(body.contains("self.accept_header(&buf)"), "{reader}");
            assert!(!body.contains("AdbMessageHeader::decode"), "{reader}");
        }
    }
}
