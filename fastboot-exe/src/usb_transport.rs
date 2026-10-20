use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::error::TransportError;
use crate::transport::AsyncTransport;
use crate::usb_iface::{
    IF_CLASS_VENDOR, IF_PROTOCOL_ADB, IF_PROTOCOL_FASTBOOT, IF_SUBCLASS_ANDROID,
};
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbMode {
    Fastboot,
    Adb,
}

#[derive(Debug, Clone)]
pub struct UsbDeviceInfo {
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial_number: String,
    pub device_path: String,
    pub is_usb3: bool,
    pub product_name: Option<String>,
    pub manufacturer: Option<String>,
}

pub use self::windows_impl::*;

/// 仅从硬件 ID 段提取接口字段；后面的设备实例 ID、序列号和接口 GUID 不进入诊断。
fn format_usb_diagnostic_context(
    backend: &str,
    device_path: &str,
    read_pipe: Option<u8>,
    write_pipe: Option<u8>,
) -> String {
    let hardware_id = device_path.split(['#', '\\']).find(|part| {
        part.get(..4)
            .is_some_and(|s| s.eq_ignore_ascii_case("VID_"))
    });
    let field = |prefix: &str, width: usize| {
        hardware_id.and_then(|id| {
            id.split('&').find_map(|part| {
                let name = part.get(..prefix.len())?;
                if !name.eq_ignore_ascii_case(prefix) {
                    return None;
                }
                let value = part.get(prefix.len()..)?;
                if value.len() != width || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return None;
                }
                u16::from_str_radix(value, 16).ok()
            })
        })
    };
    let format_field = |value: Option<u16>, width: usize| {
        value
            .map(|v| format!("0x{v:0width$x}"))
            .unwrap_or_else(|| "unknown".to_string())
    };
    let format_pipe = |pipe: Option<u8>| {
        pipe.map(|p| format!("0x{p:02x}"))
            .unwrap_or_else(|| "n/a".to_string())
    };
    format!(
        "backend={backend} vid={} pid={} mi={} read_pipe={} write_pipe={}",
        format_field(field("VID_", 4), 4),
        format_field(field("PID_", 4), 4),
        format_field(field("MI_", 2), 2),
        format_pipe(read_pipe),
        format_pipe(write_pipe),
    )
}

mod windows_impl {
    use super::*;
    use std::ffi::OsStr;
    use std::ffi::OsString;
    use std::mem;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::ptr;
    use winapi::shared::guiddef::GUID;
    use winapi::shared::minwindef::*;
    use winapi::shared::winerror::*;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::fileapi::*;
    use winapi::um::handleapi::*;
    use winapi::um::ioapiset::*;
    use winapi::um::minwinbase::OVERLAPPED;
    use winapi::um::setupapi::*;
    use winapi::um::synchapi::*;
    use winapi::um::winbase::*;
    use winapi::um::winnt::*;
    const ADB_DEVICE_GUID: GUID = GUID {
        Data1: 0xF72FE0D4,
        Data2: 0xCBCB,
        Data3: 0x407D,
        Data4: [0x88, 0x14, 0x9E, 0xD6, 0x73, 0xD0, 0xDD, 0x6B],
    };
    const FILE_DEVICE_UNKNOWN: DWORD = 0x00000022;
    const fn ctl_code(device_type: DWORD, function: DWORD, method: DWORD, access: DWORD) -> DWORD {
        (device_type << 16) | (access << 14) | (function << 2) | method
    }

    const METHOD_BUFFERED: DWORD = 0;
    const FILE_READ_ACCESS: DWORD = 1;
    const ADB_CTL_GET_USB_DEVICE_DESCRIPTOR: DWORD = 10;
    const ADB_CTL_GET_SERIAL_NUMBER: DWORD = 16;

    const ADB_IOCTL_GET_USB_DEVICE_DESCRIPTOR: DWORD = ctl_code(
        FILE_DEVICE_UNKNOWN,
        ADB_CTL_GET_USB_DEVICE_DESCRIPTOR,
        METHOD_BUFFERED,
        FILE_READ_ACCESS,
    );
    const ADB_IOCTL_GET_SERIAL_NUMBER: DWORD = ctl_code(
        FILE_DEVICE_UNKNOWN,
        ADB_CTL_GET_SERIAL_NUMBER,
        METHOD_BUFFERED,
        FILE_READ_ACCESS,
    );

    use winapi::shared::winusbio::WINUSB_PIPE_INFORMATION;
    use winapi::um::winusb::{
        WinUsb_AbortPipe, WinUsb_FlushPipe, WinUsb_Free, WinUsb_GetOverlappedResult,
        WinUsb_Initialize, WinUsb_QueryInterfaceSettings, WinUsb_QueryPipe, WinUsb_ReadPipe,
        WinUsb_ResetPipe, WinUsb_SetPipePolicy, WinUsb_WritePipe, USB_INTERFACE_DESCRIPTOR,
        WINUSB_INTERFACE_HANDLE,
    };
    const USB_ENDPOINT_DIRECTION_IN: u8 = 0x80;
    use winapi::shared::winusbio::PIPE_TRANSFER_TIMEOUT;

    #[repr(C, packed)]
    #[derive(Debug, Clone, Copy, Default)]
    struct UsbDeviceDescriptor {
        b_length: u8,
        b_descriptor_type: u8,
        bcd_usb: u16,
        b_device_class: u8,
        b_device_sub_class: u8,
        b_device_protocol: u8,
        b_max_packet_size0: u8,
        id_vendor: u16,
        id_product: u16,
        bcd_device: u16,
        i_manufacturer: u8,
        i_product: u8,
        i_serial_number: u8,
        b_num_configurations: u8,
    }
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum DriverType {
        Legacy,
        WinUsb,
    }
    #[derive(Debug, Clone, Copy)]
    struct WinUsbEndpoints {
        read_pipe: u8,
        write_pipe: u8,
    }

    pub struct UsbTransport {
        device_handle: HANDLE,
        read_handle: HANDLE,
        write_handle: HANDLE,
        winusb_handle: WINUSB_INTERFACE_HANDLE,
        winusb_endpoints: Option<WinUsbEndpoints>,
        driver_type: DriverType,
        device_path: String,
        timeout: Duration,
        write_event: HANDLE,
        read_event: HANDLE,
    }

    impl UsbTransport {
        pub fn enumerate_devices() -> Result<Vec<UsbDeviceInfo>, TransportError> {
            Self::enumerate_devices_by_mode(Some(UsbMode::Fastboot))
        }
        pub fn enumerate_adb_devices() -> Result<Vec<UsbDeviceInfo>, TransportError> {
            Self::enumerate_devices_by_mode(Some(UsbMode::Adb))
        }
        fn enumerate_devices_by_mode(
            mode_filter: Option<UsbMode>,
        ) -> Result<Vec<UsbDeviceInfo>, TransportError> {
            let mut devices = Vec::new();

            unsafe {
                let dev_info = SetupDiGetClassDevsW(
                    &ADB_DEVICE_GUID,
                    ptr::null(),
                    ptr::null_mut(),
                    DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
                );

                if dev_info == INVALID_HANDLE_VALUE {
                    return Ok(devices);
                }

                let mut dev_interface_data: SP_DEVICE_INTERFACE_DATA = mem::zeroed();
                dev_interface_data.cbSize = mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as DWORD;

                let mut index = 0;
                while SetupDiEnumDeviceInterfaces(
                    dev_info,
                    ptr::null_mut(),
                    &ADB_DEVICE_GUID,
                    index,
                    &mut dev_interface_data,
                ) != 0
                {
                    if let Some(info) = Self::get_device_info(dev_info, &mut dev_interface_data) {
                        let actual_mode = Self::detect_device_mode(&info);

                        match mode_filter {
                            Some(UsbMode::Fastboot) if actual_mode == Some(UsbMode::Fastboot) => {
                                devices.push(info)
                            }
                            Some(UsbMode::Adb) if actual_mode == Some(UsbMode::Adb) => {
                                devices.push(info)
                            }
                            None => devices.push(info),
                            _ => {}
                        }
                    }
                    index += 1;
                }

                SetupDiDestroyDeviceInfoList(dev_info);
            }
            devices.dedup_by(|a, b| a.serial_number == b.serial_number);

            Ok(devices)
        }
        /// 判定接口属于 fastboot 还是 adb。顺序：兼容 ID 三元组 → 纯 fastboot PID 名单 → 打开设备读接口描述符。
        /// 前两步不碰设备句柄——`fastboot devices` 每 1.5s 探测一轮，开句柄会与真实命令抢 WinUSB 句柄，
        /// 还会让 Windows 反复报设备变更（不停的插拔提示音）。
        /// 兼容 ID 是权威判据故排最前；PID 名单只认常见纯 fastboot PID，漏判才落到 open 兜底。
        /// 返回 `None` = 既非 adb 也非 fastboot（如 WinUSB 驱动下的 EDL 9008/诊断口），从两侧列表排除；
        /// AOSP 对描述符不匹配的接口就是直接跳过设备（is_adb_interface / fastboot recognized_device）。
        fn detect_device_mode(info: &UsbDeviceInfo) -> Option<UsbMode> {
            match crate::usb_iface::probe(&info.device_path) {
                Some(crate::usb_iface::AndroidIface::Fastboot) => return Some(UsbMode::Fastboot),
                Some(crate::usb_iface::AndroidIface::Adb) => return Some(UsbMode::Adb),
                // 三元组可读但既非 adb 也非 fastboot（EDL 9008/诊断口等）：确定性排除。
                // 绝不能落进任何「兜底当 adb」路径——那正是 GUI 对 EDL 口发 adb reboot edl、
                // 报「未找到 Bulk 端点」的根因。
                Some(crate::usb_iface::AndroidIface::Other) => return None,
                // 判不出来（拿不到兼容 ID）才继续往下兜底，不能就此认定某一种模式
                None => {}
            }
            if Self::is_fastboot_device(info) {
                return Some(UsbMode::Fastboot);
            }
            unsafe {
                let path: Vec<u16> = std::ffi::OsStr::new(&info.device_path)
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();

                let device_handle = CreateFileW(
                    path.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    ptr::null_mut(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    ptr::null_mut(),
                );

                if device_handle == INVALID_HANDLE_VALUE {
                    return Some(UsbMode::Adb);
                }

                let mut winusb_handle: WINUSB_INTERFACE_HANDLE = ptr::null_mut();
                if WinUsb_Initialize(device_handle, &mut winusb_handle) == 0 {
                    CloseHandle(device_handle);
                    return Some(UsbMode::Adb);
                }

                let mut iface_desc: USB_INTERFACE_DESCRIPTOR = mem::zeroed();
                if WinUsb_QueryInterfaceSettings(winusb_handle, 0, &mut iface_desc) == 0 {
                    WinUsb_Free(winusb_handle);
                    CloseHandle(device_handle);
                    return Some(UsbMode::Adb);
                }

                WinUsb_Free(winusb_handle);
                CloseHandle(device_handle);
                if iface_desc.bInterfaceClass == IF_CLASS_VENDOR
                    && iface_desc.bInterfaceSubClass == IF_SUBCLASS_ANDROID
                    && iface_desc.bInterfaceProtocol == IF_PROTOCOL_FASTBOOT
                {
                    return Some(UsbMode::Fastboot);
                }
                if iface_desc.bInterfaceClass == IF_CLASS_VENDOR
                    && iface_desc.bInterfaceSubClass == IF_SUBCLASS_ANDROID
                    && iface_desc.bInterfaceProtocol == IF_PROTOCOL_ADB
                {
                    return Some(UsbMode::Adb);
                }
                // 描述符可读且三元组不属于 Android adb/fastboot（EDL 9008/诊断口等）：
                // 确定性排除。旧代码这里兜底返回 Adb，正是「对 EDL 口发 adb 命令」的误判源头。
                None
            }
        }
        /// 「一看 PID 就知道只可能是 fastboot」的设备。这是兼容 ID 判不出时的回退，不是主判据：
        /// 名单只覆盖常见纯 fastboot PID。另一用途：`open()` 后放宽协议号校验（部分 bootloader 不标准）。
        /// 注意：高通 EDL/下载模式的 0x9008/0x9006 绝不能进名单——那是 Sahara/Firehose 口，
        /// 不是 fastboot；对它发 fastboot 命令会搅乱 Sahara 状态机（EDL 设备由 edl_port 侧独立发现）。
        fn is_fastboot_device(info: &UsbDeviceInfo) -> bool {
            const PURE_FASTBOOT_PIDS: &[u16] = &[
                0xd00d, 0x4ee0, 0x9025, 0x900e, 0xff40, 0x2281, 0x0fff, 0x6601, 0x1057, 0x0016,
                0x9011, 0x201c, 0x0003,
            ];
            if PURE_FASTBOOT_PIDS.contains(&info.product_id) {
                return true;
            }

            false
        }
        unsafe fn get_device_info(
            dev_info: HDEVINFO,
            dev_interface_data: &mut SP_DEVICE_INTERFACE_DATA,
        ) -> Option<UsbDeviceInfo> {
            let mut required_size: DWORD = 0;
            SetupDiGetDeviceInterfaceDetailW(
                dev_info,
                dev_interface_data,
                ptr::null_mut(),
                0,
                &mut required_size,
                ptr::null_mut(),
            );

            if required_size == 0 {
                return None;
            }
            let mut buffer = vec![0u8; required_size as usize];
            let detail_data = buffer.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
            (*detail_data).cbSize = mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as DWORD;
            if SetupDiGetDeviceInterfaceDetailW(
                dev_info,
                dev_interface_data,
                detail_data,
                required_size,
                ptr::null_mut(),
                ptr::null_mut(),
            ) == 0
            {
                return None;
            }
            let device_path_ptr = &(*detail_data).DevicePath as *const u16;
            let device_path_len = (0..)
                .take_while(|&i| *device_path_ptr.offset(i) != 0)
                .count();
            let device_path_slice = std::slice::from_raw_parts(device_path_ptr, device_path_len);
            let device_path = OsString::from_wide(device_path_slice)
                .to_string_lossy()
                .to_string();
            let (vid, pid) = Self::parse_vid_pid(&device_path)?;

            let serial = crate::usb_iface::serial_for_interface(&device_path)
                .or_else(|| Self::get_serial_via_ioctl(&device_path))
                .unwrap_or_else(|| format!("{:04x}:{:04x}", vid, pid));

            Some(UsbDeviceInfo {
                vendor_id: vid,
                product_id: pid,
                serial_number: serial,
                device_path,
                is_usb3: false,
                product_name: Some("Android".to_string()),
                manufacturer: Some("Google, Inc".to_string()),
            })
        }
        pub(crate) fn parse_vid_pid(path: &str) -> Option<(u16, u16)> {
            let path_upper = path.to_uppercase();
            let vid_pos = path_upper.find("VID_")?;
            let pid_pos = path_upper.find("PID_")?;

            let vid_str = path.get(vid_pos + 4..vid_pos + 8)?;
            let pid_str = path.get(pid_pos + 4..pid_pos + 8)?;

            let vid = u16::from_str_radix(vid_str, 16).ok()?;
            let pid = u16::from_str_radix(pid_str, 16).ok()?;

            Some((vid, pid))
        }
        fn get_serial_via_ioctl(device_path: &str) -> Option<String> {
            unsafe {
                let path: Vec<u16> = OsStr::new(device_path)
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();

                let handle = CreateFileW(
                    path.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    ptr::null_mut(),
                    OPEN_EXISTING,
                    0,
                    ptr::null_mut(),
                );

                if handle == INVALID_HANDLE_VALUE {
                    return None;
                }

                let mut serial_buf = [0u16; 256];
                let mut bytes_returned: DWORD = 0;

                let result = DeviceIoControl(
                    handle,
                    ADB_IOCTL_GET_SERIAL_NUMBER,
                    ptr::null_mut(),
                    0,
                    serial_buf.as_mut_ptr() as *mut _,
                    (serial_buf.len() * 2) as DWORD,
                    &mut bytes_returned,
                    ptr::null_mut(),
                );

                CloseHandle(handle);

                if result != 0 && bytes_returned > 0 {
                    let len = serial_buf
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(serial_buf.len());
                    let serial = String::from_utf16_lossy(&serial_buf[..len]);
                    if !serial.is_empty() {
                        return Some(serial);
                    }
                }
            }
            None
        }

        pub fn open(serial: Option<&str>) -> Result<Self, TransportError> {
            Self::open_with_mode(serial, UsbMode::Fastboot)
        }
        fn open_with_mode(serial: Option<&str>, mode: UsbMode) -> Result<Self, TransportError> {
            let devices = match mode {
                UsbMode::Fastboot => Self::enumerate_devices()?,
                UsbMode::Adb => Self::enumerate_adb_devices()?,
            };

            let device_info = match serial {
                Some(s) => devices
                    .into_iter()
                    .find(|d| d.serial_number == s)
                    .ok_or_else(|| TransportError::Usb(format!("设备 '{}' 未找到", s)))?,
                None => {
                    if devices.is_empty() {
                        return Err(TransportError::Usb("没有找到设备".into()));
                    }
                    if devices.len() > 1 {
                        return Err(TransportError::Usb(
                            "发现多个设备，请用 -s 指定序列号".into(),
                        ));
                    }
                    devices.into_iter().next().unwrap()
                }
            };

            Self::open_device_with_mode(&device_info, mode)
        }
        fn open_device_with_mode(
            info: &UsbDeviceInfo,
            mode: UsbMode,
        ) -> Result<Self, TransportError> {
            unsafe {
                let path: Vec<u16> = OsStr::new(&info.device_path)
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();

                let mut device_handle = CreateFileW(
                    path.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    ptr::null_mut(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    ptr::null_mut(),
                );

                if device_handle == INVALID_HANDLE_VALUE {
                    device_handle = CreateFileW(
                        path.as_ptr(),
                        0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        ptr::null_mut(),
                        OPEN_EXISTING,
                        0,
                        ptr::null_mut(),
                    );

                    if device_handle == INVALID_HANDLE_VALUE {
                        return Err(TransportError::Usb(format!(
                            "无法打开设备: {}\n\
                             可能原因：\n\
                             1. 设备被其他程序占用\n\
                             2. 需要管理员权限\n\
                             3. 驱动未正确安装",
                            std::io::Error::last_os_error()
                        )));
                    }
                }
                let driver_type = Self::detect_driver_type(device_handle);
                CloseHandle(device_handle);

                match driver_type {
                    DriverType::Legacy => Self::open_legacy_device(info, &path),
                    DriverType::WinUsb => Self::open_winusb_device(info, &path, mode),
                }
            }
        }
        fn open_legacy_device(info: &UsbDeviceInfo, path: &[u16]) -> Result<Self, TransportError> {
            unsafe {
                let read_path = format!("{}\\BulkRead", info.device_path);
                let write_path = format!("{}\\BulkWrite", info.device_path);
                let read_h = Self::open_endpoint(&read_path, true)?;

                let write_h = match Self::open_endpoint(&write_path, false) {
                    Ok(h) => h,
                    Err(e) => {
                        CloseHandle(read_h);
                        return Err(e);
                    }
                };
                let dev_h = CreateFileW(
                    path.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    ptr::null_mut(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    ptr::null_mut(),
                );
                let write_event = CreateEventW(ptr::null_mut(), TRUE, FALSE, ptr::null());
                let read_event = CreateEventW(ptr::null_mut(), TRUE, FALSE, ptr::null());

                Ok(Self {
                    device_handle: dev_h,
                    read_handle: read_h,
                    write_handle: write_h,
                    winusb_handle: ptr::null_mut(),
                    winusb_endpoints: None,
                    driver_type: DriverType::Legacy,
                    device_path: info.device_path.clone(),
                    timeout: DEFAULT_TIMEOUT,
                    write_event,
                    read_event,
                })
            }
        }
        fn open_winusb_device(
            info: &UsbDeviceInfo,
            path: &[u16],
            mode: UsbMode,
        ) -> Result<Self, TransportError> {
            let expected_protocol = match mode {
                UsbMode::Fastboot => IF_PROTOCOL_FASTBOOT,
                UsbMode::Adb => IF_PROTOCOL_ADB,
            };

            unsafe {
                let device_handle = CreateFileW(
                    path.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    ptr::null_mut(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    ptr::null_mut(),
                );

                if device_handle == INVALID_HANDLE_VALUE {
                    return Err(TransportError::Usb(format!(
                        "WinUSB: 无法打开设备: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                let mut winusb_handle: WINUSB_INTERFACE_HANDLE = ptr::null_mut();

                if WinUsb_Initialize(device_handle, &mut winusb_handle) == 0 {
                    let err = std::io::Error::last_os_error();
                    CloseHandle(device_handle);
                    return Err(TransportError::Usb(format!("WinUSB: 初始化失败: {}", err)));
                }
                let mut iface_desc: USB_INTERFACE_DESCRIPTOR = mem::zeroed();
                if WinUsb_QueryInterfaceSettings(winusb_handle, 0, &mut iface_desc) == 0 {
                    let err = std::io::Error::last_os_error();
                    WinUsb_Free(winusb_handle);
                    CloseHandle(device_handle);
                    return Err(TransportError::Usb(format!(
                        "WinUSB: 查询接口失败: {}",
                        err
                    )));
                }
                let mut read_pipe: u8 = 0;
                let mut write_pipe: u8 = 0;

                let is_known_fastboot_pid = Self::is_fastboot_device(info);
                let protocol_ok = if mode == UsbMode::Fastboot && is_known_fastboot_pid {
                    iface_desc.bInterfaceClass == IF_CLASS_VENDOR
                        && iface_desc.bInterfaceSubClass == IF_SUBCLASS_ANDROID
                } else {
                    iface_desc.bInterfaceClass == IF_CLASS_VENDOR
                        && iface_desc.bInterfaceSubClass == IF_SUBCLASS_ANDROID
                        && iface_desc.bInterfaceProtocol == expected_protocol
                };

                if !protocol_ok {
                    WinUsb_Free(winusb_handle);
                    CloseHandle(device_handle);
                    let mode_name = match mode {
                        UsbMode::Fastboot => "Fastboot",
                        UsbMode::Adb => "ADB",
                    };
                    return Err(TransportError::Usb(format!(
                        "设备不是 {} 模式 (protocol={:02x}, 期望={:02x})",
                        mode_name, iface_desc.bInterfaceProtocol, expected_protocol
                    )));
                }

                for i in 0..iface_desc.bNumEndpoints {
                    let mut pipe_info: WINUSB_PIPE_INFORMATION = mem::zeroed();
                    if WinUsb_QueryPipe(winusb_handle, 0, i, &mut pipe_info) != 0
                        && pipe_info.PipeType == 2
                    {
                        if pipe_info.PipeId & USB_ENDPOINT_DIRECTION_IN != 0 {
                            read_pipe = pipe_info.PipeId;
                        } else {
                            write_pipe = pipe_info.PipeId;
                        }
                    }
                }
                if read_pipe == 0 {
                    read_pipe = 0x81;
                }
                if write_pipe == 0 {
                    write_pipe = 0x01;
                }
                let mut timeout_ms: DWORD = DEFAULT_TIMEOUT.as_millis() as DWORD;
                WinUsb_SetPipePolicy(
                    winusb_handle,
                    read_pipe,
                    PIPE_TRANSFER_TIMEOUT,
                    mem::size_of::<DWORD>() as DWORD,
                    &mut timeout_ms as *mut _ as *mut _,
                );
                WinUsb_SetPipePolicy(
                    winusb_handle,
                    write_pipe,
                    PIPE_TRANSFER_TIMEOUT,
                    mem::size_of::<DWORD>() as DWORD,
                    &mut timeout_ms as *mut _ as *mut _,
                );

                let endpoints = WinUsbEndpoints {
                    read_pipe,
                    write_pipe,
                };
                let write_event = CreateEventW(ptr::null_mut(), TRUE, FALSE, ptr::null());
                let read_event = CreateEventW(ptr::null_mut(), TRUE, FALSE, ptr::null());

                Ok(Self {
                    device_handle,
                    read_handle: INVALID_HANDLE_VALUE,
                    write_handle: INVALID_HANDLE_VALUE,
                    winusb_handle,
                    winusb_endpoints: Some(endpoints),
                    driver_type: DriverType::WinUsb,
                    device_path: info.device_path.clone(),
                    timeout: DEFAULT_TIMEOUT,
                    write_event,
                    read_event,
                })
            }
        }
        fn detect_driver_type(handle: HANDLE) -> DriverType {
            unsafe {
                let mut desc: UsbDeviceDescriptor = mem::zeroed();
                let mut bytes_returned: DWORD = 0;

                let result = DeviceIoControl(
                    handle,
                    ADB_IOCTL_GET_USB_DEVICE_DESCRIPTOR,
                    ptr::null_mut(),
                    0,
                    &mut desc as *mut _ as *mut _,
                    mem::size_of::<UsbDeviceDescriptor>() as DWORD,
                    &mut bytes_returned,
                    ptr::null_mut(),
                );

                if result != 0 {
                    return DriverType::Legacy;
                }

                DriverType::WinUsb
            }
        }
        fn open_endpoint(path: &str, is_read: bool) -> Result<HANDLE, TransportError> {
            unsafe {
                let path_wide: Vec<u16> = OsStr::new(path)
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();

                let access = if is_read { GENERIC_READ } else { GENERIC_WRITE };

                let handle = CreateFileW(
                    path_wide.as_ptr(),
                    access,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    ptr::null_mut(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    ptr::null_mut(),
                );

                if handle == INVALID_HANDLE_VALUE {
                    return Err(TransportError::Usb(format!(
                        "无法打开端点 {}: {}",
                        path,
                        std::io::Error::last_os_error()
                    )));
                }

                Ok(handle)
            }
        }

        pub fn bulk_write_sync(&mut self, data: &[u8]) -> Result<usize, TransportError> {
            if data.is_empty() {
                return Ok(0);
            }

            match self.driver_type {
                DriverType::Legacy => self.legacy_write(data),
                DriverType::WinUsb => self.winusb_write(data),
            }
        }

        /// 清理 OUT 端点的挂起/halt：写超时或提交失败后端点会 stall，不清则同一句柄后续写连环失败。
        /// abort 取消挂起传输、flush 清 WinUSB 内部缓冲、reset 发 CLEAR_FEATURE(ENDPOINT_HALT) 复位端点。
        fn abort_write_pipe(&self, endpoints: &WinUsbEndpoints) {
            if self.winusb_handle.is_null() {
                return;
            }
            unsafe {
                WinUsb_AbortPipe(self.winusb_handle, endpoints.write_pipe);
                WinUsb_FlushPipe(self.winusb_handle, endpoints.write_pipe);
                WinUsb_ResetPipe(self.winusb_handle, endpoints.write_pipe);
            }
        }

        fn winusb_write(&mut self, data: &[u8]) -> Result<usize, TransportError> {
            unsafe {
                let endpoints = self
                    .winusb_endpoints
                    .ok_or_else(|| TransportError::Usb("WinUSB 端点未初始化".into()))?;

                if self.winusb_handle.is_null() {
                    return Err(TransportError::Usb("WinUSB 句柄为空".into()));
                }

                let mut total_written = 0usize;
                const MAX_CHUNK: usize = 1024 * 1024;

                while total_written < data.len() {
                    let chunk_size = std::cmp::min(MAX_CHUNK, data.len() - total_written);
                    let chunk = &data[total_written..total_written + chunk_size];
                    let mut overlapped: OVERLAPPED = mem::zeroed();
                    overlapped.hEvent = self.write_event;
                    ResetEvent(self.write_event);

                    let mut written: DWORD = 0;

                    let result = WinUsb_WritePipe(
                        self.winusb_handle,
                        endpoints.write_pipe,
                        chunk.as_ptr() as *mut u8,
                        chunk_size as DWORD,
                        &mut written,
                        &mut overlapped,
                    );
                    if result == 0 {
                        let err = GetLastError();
                        if err != ERROR_IO_PENDING {
                            // 写提交即失败：端点可能已 stall，先 abort+flush+reset 清掉 halt 状态再返回，
                            // 否则残留的挂起会让同一句柄后续写连环失败、被迫整条链路重开（对齐 winusb_read
                            // 超时后调用 WinUsb_AbortPipe 的处理）。
                            self.abort_write_pipe(&endpoints);
                            return Err(TransportError::Usb(format!(
                                "WinUSB 写入失败: {}",
                                std::io::Error::from_raw_os_error(err as i32)
                            )));
                        }
                    }
                    let wait_result = WinUsb_GetOverlappedResult(
                        self.winusb_handle,
                        &mut overlapped,
                        &mut written,
                        TRUE,
                    );

                    if wait_result == 0 {
                        // PIPE_TRANSFER_TIMEOUT 到期（os error 121 / ERROR_SEM_TIMEOUT）等：OUT 端点已
                        // 挂起，必须 abort+reset 清 halt，否则句柄连带失效、后续写全废、只能整体重开链路。
                        let err = std::io::Error::last_os_error();
                        self.abort_write_pipe(&endpoints);
                        return Err(TransportError::Usb(format!("WinUSB 写入等待失败: {}", err)));
                    }

                    total_written += written as usize;
                }

                Ok(total_written)
            }
        }

        fn legacy_write(&mut self, data: &[u8]) -> Result<usize, TransportError> {
            unsafe {
                let handle = if self.write_handle != INVALID_HANDLE_VALUE {
                    self.write_handle
                } else {
                    self.device_handle
                };

                let mut total_written = 0usize;
                let timeout_ms = self.timeout.as_millis() as DWORD;
                const MAX_CHUNK: usize = 1024 * 1024;

                while total_written < data.len() {
                    let chunk_size = std::cmp::min(MAX_CHUNK, data.len() - total_written);
                    let chunk = &data[total_written..total_written + chunk_size];
                    let mut overlapped: OVERLAPPED = mem::zeroed();
                    overlapped.hEvent = self.write_event;
                    ResetEvent(self.write_event);

                    let mut written: DWORD = 0;
                    let result = WriteFile(
                        handle,
                        chunk.as_ptr() as *const _,
                        chunk_size as DWORD,
                        &mut written,
                        &mut overlapped,
                    );

                    if result == 0 {
                        let err = GetLastError();
                        if err != ERROR_IO_PENDING {
                            return Err(TransportError::Usb(format!(
                                "写入失败: {}",
                                std::io::Error::from_raw_os_error(err as i32)
                            )));
                        }
                        let wait_result = WaitForSingleObject(overlapped.hEvent, timeout_ms);
                        if wait_result != WAIT_OBJECT_0 {
                            // CancelIo 是异步的：等被取消的传输真正结束，栈上的 OVERLAPPED 才能出栈。
                            CancelIo(handle);
                            GetOverlappedResult(handle, &mut overlapped, &mut written, TRUE);
                            return Err(TransportError::Timeout);
                        }
                        if GetOverlappedResult(handle, &mut overlapped, &mut written, FALSE) == 0 {
                            return Err(TransportError::Usb(format!(
                                "获取写入结果失败: {}",
                                std::io::Error::last_os_error()
                            )));
                        }
                    }

                    total_written += written as usize;
                }

                Ok(total_written)
            }
        }
        pub fn bulk_read_sync(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
            if buf.is_empty() {
                return Ok(0);
            }

            match self.driver_type {
                DriverType::Legacy => self.legacy_read(buf),
                DriverType::WinUsb => self.winusb_read(buf),
            }
        }

        fn winusb_read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
            unsafe {
                let endpoints = self
                    .winusb_endpoints
                    .ok_or_else(|| TransportError::Usb("WinUSB 端点未初始化".into()))?;

                if self.winusb_handle.is_null() {
                    return Err(TransportError::Usb("WinUSB 句柄为空".into()));
                }
                let mut overlapped: OVERLAPPED = mem::zeroed();
                overlapped.hEvent = self.read_event;
                ResetEvent(self.read_event);

                let mut read: DWORD = 0;

                let result = WinUsb_ReadPipe(
                    self.winusb_handle,
                    endpoints.read_pipe,
                    buf.as_mut_ptr(),
                    buf.len() as DWORD,
                    &mut read,
                    &mut overlapped,
                );
                if result == 0 {
                    let err = GetLastError();
                    if err != ERROR_IO_PENDING {
                        return Err(TransportError::Usb(format!(
                            "WinUSB 读取失败: {}",
                            std::io::Error::from_raw_os_error(err as i32)
                        )));
                    }
                }
                let timeout_ms = self.timeout.as_millis() as DWORD;
                let actual_timeout = if timeout_ms == 0 {
                    INFINITE
                } else {
                    timeout_ms
                };

                let wait_result = WaitForSingleObject(overlapped.hEvent, actual_timeout);

                if wait_result != WAIT_OBJECT_0 {
                    let err = std::io::Error::last_os_error();
                    // OVERLAPPED 与 buf 都在本栈帧上：取消后必须等这次传输真正结束再返回，
                    // 否则内核回写完成状态时这块栈已被后续调用复用。
                    WinUsb_AbortPipe(self.winusb_handle, endpoints.read_pipe);
                    WinUsb_GetOverlappedResult(
                        self.winusb_handle,
                        &mut overlapped,
                        &mut read,
                        TRUE,
                    );
                    if wait_result == WAIT_TIMEOUT {
                        return Err(TransportError::Timeout);
                    }
                    return Err(TransportError::Usb(format!("WinUSB 等待失败: {}", err)));
                }
                let get_result = WinUsb_GetOverlappedResult(
                    self.winusb_handle,
                    &mut overlapped,
                    &mut read,
                    FALSE,
                );

                if get_result == 0 {
                    let err = GetLastError();
                    return Err(TransportError::Usb(format!(
                        "winusb read error: {} (code: {})",
                        std::io::Error::last_os_error(),
                        err
                    )));
                }

                Ok(read as usize)
            }
        }

        fn legacy_read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
            unsafe {
                let handle = if self.read_handle != INVALID_HANDLE_VALUE {
                    self.read_handle
                } else {
                    self.device_handle
                };
                let mut overlapped: OVERLAPPED = mem::zeroed();
                overlapped.hEvent = self.read_event;
                ResetEvent(self.read_event);

                let mut read: DWORD = 0;
                let timeout_ms = self.timeout.as_millis() as DWORD;
                let actual_timeout = if timeout_ms == 0 {
                    INFINITE
                } else {
                    timeout_ms
                };

                let result = ReadFile(
                    handle,
                    buf.as_mut_ptr() as *mut _,
                    buf.len() as DWORD,
                    &mut read,
                    &mut overlapped,
                );

                if result == 0 {
                    let err = GetLastError();
                    if err != ERROR_IO_PENDING {
                        return Err(TransportError::Usb(format!(
                            "读取失败: {}",
                            std::io::Error::from_raw_os_error(err as i32)
                        )));
                    }
                    let wait_result = WaitForSingleObject(overlapped.hEvent, actual_timeout);
                    if wait_result != WAIT_OBJECT_0 {
                        CancelIo(handle);
                        GetOverlappedResult(handle, &mut overlapped, &mut read, TRUE);
                        if wait_result == WAIT_TIMEOUT {
                            return Err(TransportError::Timeout);
                        }
                        return Err(TransportError::Usb("等待读取失败".into()));
                    }
                    if GetOverlappedResult(handle, &mut overlapped, &mut read, FALSE) == 0 {
                        return Err(TransportError::Usb(format!(
                            "获取读取结果失败: {}",
                            std::io::Error::last_os_error()
                        )));
                    }
                }

                Ok(read as usize)
            }
        }

        pub async fn bulk_write(&mut self, data: &[u8]) -> Result<usize, TransportError> {
            self.bulk_write_sync(data)
        }

        pub async fn bulk_read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
            self.bulk_read_sync(buf)
        }
    }

    impl Drop for UsbTransport {
        fn drop(&mut self) {
            unsafe {
                if !self.winusb_handle.is_null() {
                    WinUsb_Free(self.winusb_handle);
                }
                if !self.write_event.is_null() {
                    CloseHandle(self.write_event);
                }
                if !self.read_event.is_null() {
                    CloseHandle(self.read_event);
                }
                if self.write_handle != INVALID_HANDLE_VALUE {
                    CloseHandle(self.write_handle);
                }
                if self.read_handle != INVALID_HANDLE_VALUE {
                    CloseHandle(self.read_handle);
                }
                if self.device_handle != INVALID_HANDLE_VALUE {
                    CloseHandle(self.device_handle);
                }
            }
        }
    }

    impl AsyncTransport for UsbTransport {
        fn diagnostic_context(&self) -> String {
            let backend = match self.driver_type {
                DriverType::Legacy => "Legacy",
                DriverType::WinUsb => "WinUSB",
            };
            format_usb_diagnostic_context(
                backend,
                &self.device_path,
                self.winusb_endpoints.map(|ep| ep.read_pipe),
                self.winusb_endpoints.map(|ep| ep.write_pipe),
            )
        }

        fn read<'a>(
            &'a mut self,
            buf: &'a mut [u8],
        ) -> Pin<Box<dyn Future<Output = Result<usize, TransportError>> + Send + 'a>> {
            Box::pin(async move { self.bulk_read(buf).await })
        }

        fn write<'a>(
            &'a mut self,
            data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Result<usize, TransportError>> + Send + 'a>> {
            Box::pin(async move { self.bulk_write(data).await })
        }

        fn close(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>> {
            // 真正释放通信句柄（旧实现是空操作）：重连前先 close 掉 driver 里那条坏链路的 WinUSB
            // 句柄，腾出接口，避免紧接的重开 open 撞未释放的旧句柄得 ACCESS_DENIED（「端口被占用」）。
            // 句柄置空后 Drop 会跳过重复释放；close 后本对象不应再做 IO。event 句柄留给 Drop 处理。
            Box::pin(async move {
                unsafe {
                    if !self.winusb_handle.is_null() {
                        if let Some(ep) = self.winusb_endpoints {
                            let _ = WinUsb_AbortPipe(self.winusb_handle, ep.read_pipe);
                            let _ = WinUsb_AbortPipe(self.winusb_handle, ep.write_pipe);
                        }
                        WinUsb_Free(self.winusb_handle);
                        self.winusb_handle = ptr::null_mut();
                    }
                    if self.write_handle != INVALID_HANDLE_VALUE {
                        CloseHandle(self.write_handle);
                        self.write_handle = INVALID_HANDLE_VALUE;
                    }
                    if self.read_handle != INVALID_HANDLE_VALUE {
                        CloseHandle(self.read_handle);
                        self.read_handle = INVALID_HANDLE_VALUE;
                    }
                    if self.device_handle != INVALID_HANDLE_VALUE {
                        CloseHandle(self.device_handle);
                        self.device_handle = INVALID_HANDLE_VALUE;
                    }
                }
                Ok(())
            })
        }

        fn reset(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>> {
            Box::pin(async move {
                unsafe {
                    if !self.winusb_handle.is_null() {
                        if let Some(endpoints) = self.winusb_endpoints {
                            let _ = WinUsb_AbortPipe(self.winusb_handle, endpoints.read_pipe);
                            let _ = WinUsb_AbortPipe(self.winusb_handle, endpoints.write_pipe);
                            let _ = WinUsb_FlushPipe(self.winusb_handle, endpoints.read_pipe);
                            let _ = WinUsb_FlushPipe(self.winusb_handle, endpoints.write_pipe);
                            let _ = WinUsb_ResetPipe(self.winusb_handle, endpoints.read_pipe);
                            let _ = WinUsb_ResetPipe(self.winusb_handle, endpoints.write_pipe);
                        }
                    }
                }
                Ok(())
            })
        }

        fn reinitialize(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>> {
            Box::pin(async move {
                if self.driver_type != DriverType::WinUsb {
                    return Ok(());
                }

                unsafe {
                    let device_path = self.device_path.clone();
                    let timeout = self.timeout;
                    let endpoints = self.winusb_endpoints;
                    if !self.winusb_handle.is_null() {
                        if let Some(ep) = endpoints {
                            let _ = WinUsb_AbortPipe(self.winusb_handle, ep.read_pipe);
                            let _ = WinUsb_AbortPipe(self.winusb_handle, ep.write_pipe);
                        }
                    }
                    if !self.winusb_handle.is_null() {
                        WinUsb_Free(self.winusb_handle);
                        self.winusb_handle = ptr::null_mut();
                    }
                    if self.device_handle != INVALID_HANDLE_VALUE {
                        CloseHandle(self.device_handle);
                        self.device_handle = INVALID_HANDLE_VALUE;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    let path: Vec<u16> = std::ffi::OsStr::new(&device_path)
                        .encode_wide()
                        .chain(std::iter::once(0))
                        .collect();

                    let device_handle = CreateFileW(
                        path.as_ptr(),
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        ptr::null_mut(),
                        OPEN_EXISTING,
                        FILE_FLAG_OVERLAPPED,
                        ptr::null_mut(),
                    );

                    if device_handle == INVALID_HANDLE_VALUE {
                        return Err(TransportError::Usb(format!(
                            "重新打开设备失败: {}",
                            std::io::Error::last_os_error()
                        )));
                    }

                    self.device_handle = device_handle;
                    let mut winusb_handle: WINUSB_INTERFACE_HANDLE = ptr::null_mut();
                    if WinUsb_Initialize(device_handle, &mut winusb_handle) == 0 {
                        let err = std::io::Error::last_os_error();
                        CloseHandle(device_handle);
                        self.device_handle = INVALID_HANDLE_VALUE;
                        return Err(TransportError::Usb(format!(
                            "重新初始化 WinUSB 失败: {}",
                            err
                        )));
                    }

                    self.winusb_handle = winusb_handle;
                    if let Some(ep) = endpoints {
                        let mut timeout_ms: DWORD = timeout.as_millis() as DWORD;
                        WinUsb_SetPipePolicy(
                            winusb_handle,
                            ep.read_pipe,
                            PIPE_TRANSFER_TIMEOUT,
                            mem::size_of::<DWORD>() as DWORD,
                            &mut timeout_ms as *mut _ as *mut _,
                        );
                        WinUsb_SetPipePolicy(
                            winusb_handle,
                            ep.write_pipe,
                            PIPE_TRANSFER_TIMEOUT,
                            mem::size_of::<DWORD>() as DWORD,
                            &mut timeout_ms as *mut _ as *mut _,
                        );
                    }
                }

                Ok(())
            })
        }

        fn set_timeout(&mut self, timeout: Duration) {
            self.timeout = timeout;
            if self.driver_type == DriverType::WinUsb && !self.winusb_handle.is_null() {
                if let Some(endpoints) = self.winusb_endpoints {
                    let mut timeout_ms: DWORD = timeout.as_millis() as DWORD;
                    unsafe {
                        let _ = WinUsb_SetPipePolicy(
                            self.winusb_handle,
                            endpoints.read_pipe,
                            PIPE_TRANSFER_TIMEOUT,
                            std::mem::size_of::<DWORD>() as DWORD,
                            &mut timeout_ms as *mut _ as *mut _,
                        );
                        let _ = WinUsb_SetPipePolicy(
                            self.winusb_handle,
                            endpoints.write_pipe,
                            PIPE_TRANSFER_TIMEOUT,
                            std::mem::size_of::<DWORD>() as DWORD,
                            &mut timeout_ms as *mut _ as *mut _,
                        );
                    }
                }
            }
        }
    }

    unsafe impl Send for UsbTransport {}
    unsafe impl Sync for UsbTransport {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_enumerate_no_panic() {
        let result = UsbTransport::enumerate_devices();
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_vid_pid() {
        use windows_impl::UsbTransport;

        let path = r"\\?\usb#vid_18d1&pid_d00d#abc123#{f72fe0d4-cbcb-407d-8814-9ed673d0dd6b}";
        let result = UsbTransport::parse_vid_pid(path);
        assert_eq!(result, Some((0x18d1, 0xd00d)));
    }

    #[test]
    fn diagnostic_context_keeps_interface_fields_and_omits_device_instance() {
        let path = r"\\?\usb#vid_18d1&pid_d00d&mi_01#private-serial#{private-guid}";
        let context = format_usb_diagnostic_context("WinUSB", path, Some(0x83), Some(0x02));
        assert_eq!(
            context,
            "backend=WinUSB vid=0x18d1 pid=0xd00d mi=0x01 read_pipe=0x83 write_pipe=0x02"
        );
        let other_instance = r"\\?\USB#VID_18D1&PID_D00D&MI_01#different-serial#{different-guid}";
        assert_eq!(
            context,
            format_usb_diagnostic_context("WinUSB", other_instance, Some(0x83), Some(0x02))
        );
        assert!(!context.contains("private"));
        assert!(!context.contains("serial"));
        assert!(!context.contains("guid"));
    }

    #[test]
    fn diagnostic_context_does_not_extract_fields_from_device_instance() {
        let path = r"\\?\usb#vid_18d1&pid_d00d#serial&mi_ff&pid_ffff#{private-guid}";
        assert_eq!(
            format_usb_diagnostic_context("Legacy", path, None, None),
            "backend=Legacy vid=0x18d1 pid=0xd00d mi=unknown read_pipe=n/a write_pipe=n/a"
        );
        assert_eq!(
            format_usb_diagnostic_context("WinUSB", r"E:\secret-session\private-token", None, None),
            "backend=WinUSB vid=unknown pid=unknown mi=unknown read_pipe=n/a write_pipe=n/a"
        );
    }
}
