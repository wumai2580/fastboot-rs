//! Android USB 接口模式的无句柄判定，adb 侧与 fastboot 侧共用同一判据。
//! adb 与 fastboot/fastbootd 挂在同一 WinUSB 接口类 GUID 下，仅凭 GUID 分不开；权威判据
//! `bInterfaceProtocol` 须开句柄才能读，而 devices 探测每秒都在跑，开句柄会与真实命令
//! 抢 WinUSB 句柄（「USB 端口被占用」），还让 Windows 反复报设备变更（不停的插拔提示音）。
//! 故改读 Windows 由接口描述符生成的兼容 ID（`USB\Class_ff&SubClass_42&Prot_xx` 的 Prot_xx
//! 即 bInterfaceProtocol），走 cfgmgr32 属性查询全程不碰句柄，与读描述符同源、并非启发式。
//!
//! 接口三元组常量与无句柄的序列号解析（接口路径 / 复合设备父节点）也只在这里定义一份：adb 侧
//! （`adb_winusb_transport`）与 fastboot 侧（`usb_transport`）共用，打开设备后的描述符校验复用同一组常量。

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_DevNode_Registry_PropertyW, CM_Get_Device_IDW, CM_Get_Parent, CM_Locate_DevNodeW,
    CM_DRP_COMPATIBLEIDS, CM_LOCATE_DEVNODE_NORMAL, CR_SUCCESS, MAX_DEVICE_ID_LEN,
};

/// Android 接口描述符三元组（AOSP adb.h：`ADB_CLASS`/`ADB_SUBCLASS`/`ADB_PROTOCOL`）：
/// class=0xFF、subclass=0x42；protocol 区分模式——adb / sideload / recovery = 0x01，
/// fastboot 与 fastbootd = 0x03。AOSP host 对 adb 接口的判定是三元组全等（is_adb_interface）。
pub(crate) const IF_CLASS_VENDOR: u8 = 0xFF;
pub(crate) const IF_SUBCLASS_ANDROID: u8 = 0x42;
pub(crate) const IF_PROTOCOL_ADB: u8 = 0x01;
pub(crate) const IF_PROTOCOL_FASTBOOT: u8 = 0x03;

/// 一个设备接口到底是什么。`Other` = 描述符可读且确定**不是** Android adb/fastboot 接口
/// （典型：WinUSB 驱动下的 EDL 9008 / 高通诊断口是 0xFF/0xFF/0xFF，却常挂在 ADB 接口类
/// GUID 下）——调用方必须把它从 adb/fastboot 设备列表里排除，否则 GUI 会对 EDL 口发
/// adb/fastboot 命令（历史故障：「重启 EDL 失败: USB: 未找到 Bulk 端点」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AndroidIface {
    Adb,
    Fastboot,
    Other,
}

/// 判定由 ADB 接口类 GUID 枚举出的接口属于哪种模式，不打开设备。
/// 返回 `None` = 判不出来（属性缺失/解析失败）；调用方必须按自己的方向兜底，不能把
/// 「判不出来」当成某一种模式——那会在属性缺失的机器上整台设备消失，比误判更糟。
/// 与 `None` 相反，`Some(Other)` 是确定性的「非 adb 非 fastboot」，必须排除。
pub(crate) fn probe(device_path: &str) -> Option<AndroidIface> {
    interface_triple(device_path).map(classify)
}

/// 三元组 → 模式：adb / fastboot 要求 AOSP 三元组全等，其余一律 `Other`。
fn classify(triple: (u8, u8, u8)) -> AndroidIface {
    match triple {
        (IF_CLASS_VENDOR, IF_SUBCLASS_ANDROID, IF_PROTOCOL_ADB) => AndroidIface::Adb,
        (IF_CLASS_VENDOR, IF_SUBCLASS_ANDROID, IF_PROTOCOL_FASTBOOT) => AndroidIface::Fastboot,
        _ => AndroidIface::Other,
    }
}

/// 设备接口对应的 USB 序列号，全程不开句柄（理由同模块文档）。取不到返回 `None`，由调用方
/// 决定记 "unknown" 还是开句柄走 IOCTL。
///
/// - 单接口设备：序列号就在接口路径里（[`serial_from_device_path`]）。
/// - 复合设备（MTP+ADB 等，绝大多数手机）的子接口：路径里那段是 Windows 自造的子实例 ID
///   （`8&c37339&1&0001`），序列号在**父设备节点**的实例 ID（`USB\VID_xxxx&PID_xxxx\<序列号>`）上。
///   只对 `&MI_xx` 子接口取父节点：非复合设备的父节点是 USB Hub，绝不能把 Hub 的序列号当成手机的。
///
/// 大小写：接口路径是 Windows 转成的小写，实例 ID 是大写，两者都不保留设备报的原样；父节点取到的
/// 统一转小写，与路径口径一致——同一台设备无论走哪条都得到同一个串，`devices` 输出与 `-s` 匹配才对得上。
pub(crate) fn serial_for_interface(device_path: &str) -> Option<String> {
    if let Some(serial) = serial_from_device_path(device_path) {
        return Some(serial.to_string());
    }
    let instance_id = instance_id_from_device_path(device_path)?;
    let parent = parent_instance_id(&instance_id)?;
    serial_from_composite_parent(&instance_id, &parent)
}

/// 设备接口路径（`\\?\usb#vid_18d1&pid_4ee7#SERIAL#{guid}`）里的序列号：按 '#' 分割的第 3 段。
/// 该段也可能是 GUID（`{…}`）或含 '&' 的实例 ID——设备没报序列号时 Windows 自造的，那不是序列号。
fn serial_from_device_path(path: &str) -> Option<&str> {
    path.split('#').nth(2).filter(|s| is_reported_serial(s))
}

/// 实例 ID 的最后一段是不是设备自报的序列号：Windows 自造的是含 '&' 的实例号或 GUID。
fn is_reported_serial(segment: &str) -> bool {
    !segment.is_empty() && !segment.starts_with('{') && !segment.contains('&') && segment.len() < 64
}

/// 复合设备子接口实例 ID（`USB\VID_22D9&PID_2765&MI_01\8&…`）+ 其父节点实例 ID → 序列号。
/// 父节点的设备段必须恰好是子接口设备段去掉 `&MI_xx`（同一台复合设备），否则（子接口不是复合
/// 设备的一部分、父节点是 Hub）返回 `None`。
fn serial_from_composite_parent(
    child_instance_id: &str,
    parent_instance_id: &str,
) -> Option<String> {
    let child_device = child_instance_id.split('\\').nth(1)?.to_ascii_lowercase();
    let (composite_device, _interface) = child_device.split_once("&mi_")?;
    let mut parent = parent_instance_id.split('\\');
    let (_enumerator, parent_device, serial) = (parent.next()?, parent.next()?, parent.next()?);
    if parent.next().is_some() || !parent_device.eq_ignore_ascii_case(composite_device) {
        return None;
    }
    is_reported_serial(serial).then(|| serial.to_ascii_lowercase())
}

fn interface_triple(device_path: &str) -> Option<(u8, u8, u8)> {
    let instance_id = instance_id_from_device_path(device_path)?;
    let ids = compatible_ids(&instance_id)?;
    triple_from_compatible_ids(&ids)
}

/// 把设备接口路径还原成设备实例 ID：`\\?\` 之后按 `#` 分成「枚举器#设备ID#实例ID#接口类GUID」，
/// 前三段用 `\` 接起来即实例 ID（Win32 固定编码）。`CM_Locate_DevNodeW` 大小写不敏感，无需转大写。
fn instance_id_from_device_path(device_path: &str) -> Option<String> {
    let trimmed = device_path
        .strip_prefix(r"\\?\")
        .or_else(|| device_path.strip_prefix(r"\\.\"))
        .unwrap_or(device_path);
    let mut parts = trimmed.split('#');
    let enumerator = parts.next()?;
    let device = parts.next()?;
    let instance = parts.next()?;
    if enumerator.is_empty() || device.is_empty() || instance.is_empty() {
        return None;
    }
    Some(format!("{enumerator}\\{device}\\{instance}"))
}

/// 从兼容 ID 列表取 `Class_xx&SubClass_yy&Prot_zz` 完整三元组（十六进制）。这些 ID 由
/// Windows USB 栈按接口描述符生成，与读描述符同源。取三元组而非只取 Prot：EDL 9008/诊断口
/// 等非 Android 接口（如 Class_ff&SubClass_ff&Prot_ff）也要能确定性识别为「其它」。
/// 大小写不固定（实测 Class_FF/Class_ff 并存），一律小写；按 `\`/`&` 分词后前缀匹配，
/// 避免 "class_" 误命中 "subclass_" 的子串。取第一条能凑齐三元组的 ID（Windows 把最具体的
/// ID 排在前面；MS_COMP_WINUSB 等不含三元组的自动跳过）。
fn triple_from_compatible_ids(ids: &[String]) -> Option<(u8, u8, u8)> {
    for id in ids {
        let lower = id.to_ascii_lowercase();
        let mut class = None;
        let mut subclass = None;
        let mut protocol = None;
        for token in lower.split(['\\', '&']) {
            if let Some(hex) = token.strip_prefix("subclass_") {
                subclass = subclass.or_else(|| u8::from_str_radix(hex, 16).ok());
            } else if let Some(hex) = token.strip_prefix("class_") {
                class = class.or_else(|| u8::from_str_radix(hex, 16).ok());
            } else if let Some(hex) = token.strip_prefix("prot_") {
                protocol = protocol.or_else(|| u8::from_str_radix(hex, 16).ok());
            }
        }
        if let (Some(c), Some(s), Some(p)) = (class, subclass, protocol) {
            return Some((c, s, p));
        }
    }
    None
}

/// 实例 ID → 设备节点句柄（devinst 只是 PnP 树里的编号，不是设备句柄，不碰 WinUSB）。
fn locate_devnode(instance_id: &str) -> Option<u32> {
    let wide: Vec<u16> = OsStr::new(instance_id)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut devinst: u32 = 0;
    let located = unsafe {
        CM_Locate_DevNodeW(
            &mut devinst,
            PCWSTR(wide.as_ptr()),
            CM_LOCATE_DEVNODE_NORMAL,
        )
    };
    (located.0 == CR_SUCCESS.0).then_some(devinst)
}

/// 父设备节点的实例 ID（复合设备子接口的父节点即整台设备：`USB\VID_xxxx&PID_xxxx\<序列号>`）。
fn parent_instance_id(instance_id: &str) -> Option<String> {
    let child = locate_devnode(instance_id)?;
    let mut parent: u32 = 0;
    let mut buffer = [0u16; MAX_DEVICE_ID_LEN as usize + 1];
    unsafe {
        if CM_Get_Parent(&mut parent, child, 0).0 != CR_SUCCESS.0
            || CM_Get_Device_IDW(parent, &mut buffer, 0).0 != CR_SUCCESS.0
        {
            return None;
        }
    }
    let len = buffer.iter().position(|&unit| unit == 0)?;
    Some(String::from_utf16_lossy(&buffer[..len]))
}

/// 读设备实例的 `CompatibleIDs`（`REG_MULTI_SZ`）。两次调用：先问长度，再取内容。
fn compatible_ids(instance_id: &str) -> Option<Vec<String>> {
    let devinst = locate_devnode(instance_id)?;
    unsafe {
        // buffer 传 None 时 CM 只把所需字节数写回 len，返回 CR_BUFFER_SMALL——这里只关心长度，
        // 不看返回码。
        let mut len: u32 = 0;
        let _ = CM_Get_DevNode_Registry_PropertyW(
            devinst,
            CM_DRP_COMPATIBLEIDS,
            None,
            None,
            &mut len,
            0,
        );
        if len == 0 {
            return None;
        }

        let mut buffer = vec![0u8; len as usize];
        let got = CM_Get_DevNode_Registry_PropertyW(
            devinst,
            CM_DRP_COMPATIBLEIDS,
            None,
            Some(buffer.as_mut_ptr() as *mut core::ffi::c_void),
            &mut len,
            0,
        );
        if got.0 != CR_SUCCESS.0 {
            return None;
        }
        buffer.truncate(len as usize);
        Some(parse_multi_sz(&buffer))
    }
}

/// 解析 `REG_MULTI_SZ`：UTF-16LE，每串以 NUL 结尾，整体以一个空串收尾。
fn parse_multi_sz(bytes: &[u8]) -> Vec<String> {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    units
        .split(|&unit| unit == 0)
        .filter(|part| !part.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_id_recovered_from_interface_path() {
        // 单接口设备（fastboot 常见形状）
        assert_eq!(
            instance_id_from_device_path(
                r"\\?\usb#vid_18d1&pid_d00d#ha28l5b5#{f72fe0d4-cbcb-407d-8814-9ed673d0dd6b}"
            )
            .as_deref(),
            Some(r"usb\vid_18d1&pid_d00d\ha28l5b5")
        );
        // 复合设备的 adb 接口：实例段自带 `&`，不能被当成分隔符
        assert_eq!(
            instance_id_from_device_path(
                r"\\?\usb#vid_22d9&pid_2765&mi_01#8&c37339&1&0001#{f72fe0d4-cbcb-407d-8814-9ed673d0dd6b}"
            )
            .as_deref(),
            Some(r"usb\vid_22d9&pid_2765&mi_01\8&c37339&1&0001")
        );
        // 段数不足：判不出来，交给调用方兜底
        assert_eq!(instance_id_from_device_path(r"\\?\usb#vid_18d1"), None);
    }

    #[test]
    fn triple_read_from_compatible_ids_ignoring_case() {
        // 实测的 fastboot（Android Bootloader Interface）兼容 ID，注意大写 `Class_FF`
        let fastboot = vec![
            "USB\\COMPAT_VID_18D1&Class_FF&SubClass_42&Prot_03".to_string(),
            "USB\\Class_FF&SubClass_42&Prot_03".to_string(),
            "USB\\Class_FF&SubClass_42".to_string(),
        ];
        assert_eq!(
            triple_from_compatible_ids(&fastboot),
            Some((IF_CLASS_VENDOR, IF_SUBCLASS_ANDROID, IF_PROTOCOL_FASTBOOT))
        );
        // 实测的 adb 接口，小写 `Class_ff`，且首条是 MS_COMP_WINUSB（不带三元组，必须跳过）
        let adb = vec![
            "USB\\MS_COMP_WINUSB".to_string(),
            "USB\\COMPAT_VID_22d9&Class_ff&SubClass_42&Prot_01".to_string(),
            "USB\\Class_ff&SubClass_42".to_string(),
        ];
        assert_eq!(
            triple_from_compatible_ids(&adb),
            Some((IF_CLASS_VENDOR, IF_SUBCLASS_ANDROID, IF_PROTOCOL_ADB))
        );
        // 高通 EDL 9008/诊断口（WinUSB 驱动时常挂在 ADB 接口类 GUID 下）：三元组可读，非 Android
        assert_eq!(
            triple_from_compatible_ids(&["USB\\Class_ff&SubClass_ff&Prot_ff".to_string()]),
            Some((0xFF, 0xFF, 0xFF))
        );
        // 只有 Class 没有 SubClass/Prot：凑不齐三元组 → 判不出来
        assert_eq!(
            triple_from_compatible_ids(&["USB\\Class_ff".to_string()]),
            None
        );
    }

    /// probe 的三态语义：adb / fastboot 精确匹配 AOSP 三元组；可读但不匹配 = Other（确定性
    /// 排除，EDL 口绝不能落回 adb/fastboot 列表）。
    #[test]
    fn probe_classification_uses_full_triple() {
        let classify = |ids: &[&str]| {
            let owned: Vec<String> = ids.iter().map(|s| s.to_string()).collect();
            triple_from_compatible_ids(&owned).map(classify)
        };
        assert_eq!(
            classify(&["USB\\Class_ff&SubClass_42&Prot_01"]),
            Some(AndroidIface::Adb)
        );
        assert_eq!(
            classify(&["USB\\Class_ff&SubClass_42&Prot_03"]),
            Some(AndroidIface::Fastboot)
        );
        // EDL 9008 / 诊断口
        assert_eq!(
            classify(&["USB\\Class_ff&SubClass_ff&Prot_ff"]),
            Some(AndroidIface::Other)
        );
        // Android 子类下的未知协议号（非 01/03）也一样确定性排除
        assert_eq!(
            classify(&["USB\\Class_ff&SubClass_42&Prot_02"]),
            Some(AndroidIface::Other)
        );
        assert_eq!(classify(&["USB\\MS_COMP_WINUSB"]), None);
    }

    #[test]
    fn serial_is_the_third_path_segment_unless_windows_made_it_up() {
        let guid = "{f72fe0d4-cbcb-407d-8814-9ed673d0dd6b}";
        assert_eq!(
            serial_from_device_path(&format!(r"\\?\usb#vid_18d1&pid_d00d#abc123#{guid}")),
            Some("abc123")
        );
        // 设备没报序列号时 Windows 自造的实例 ID（含 '&'）与 GUID 段都不是序列号
        assert_eq!(
            serial_from_device_path(&format!(r"\\?\usb#vid_18d1&pid_d00d#6&1a2b&0&1#{guid}")),
            None
        );
        assert_eq!(
            serial_from_device_path(&format!(r"\\?\usb#vid_18d1#{guid}")),
            None
        );
        assert_eq!(serial_from_device_path(r"\\?\usb#vid_18d1"), None);
    }

    #[test]
    fn composite_child_takes_serial_from_its_own_parent_only() {
        let child = r"usb\vid_22d9&pid_2765&mi_01\8&c37339&1&0001";
        // 复合设备父节点（CM 回的实例 ID 是大写）：取序列号并转成路径口径的小写
        assert_eq!(
            serial_from_composite_parent(child, r"USB\VID_22D9&PID_2765\3B6F6KEAZ2K940F7"),
            Some("3b6f6keaz2k940f7".to_string())
        );
        // 设备没报序列号时父节点实例段也是 Windows 自造的
        assert_eq!(
            serial_from_composite_parent(child, r"USB\VID_22D9&PID_2765\7&18F74E30&0&2"),
            None
        );
        // 父节点换了 VID/PID（不是同一台复合设备，比如 Hub）：不能借它的序列号
        assert_eq!(
            serial_from_composite_parent(child, r"USB\VID_2109&PID_2817\000000000"),
            None
        );
        // 非复合设备的接口：父节点必是 Hub，一律不取
        assert_eq!(
            serial_from_composite_parent(
                r"usb\vid_18d1&pid_4e11\7&1a2b&0&1",
                r"USB\VID_18D1&PID_4E11\A7AB3AB5"
            ),
            None
        );
    }

    #[test]
    fn multi_sz_split_on_nul_and_drops_trailing_empty() {
        let mut bytes = Vec::new();
        for s in ["ab", "cd"] {
            for unit in s.encode_utf16() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            bytes.extend_from_slice(&0u16.to_le_bytes());
        }
        bytes.extend_from_slice(&0u16.to_le_bytes()); // 整体收尾的空串
        assert_eq!(parse_multi_sz(&bytes), vec!["ab", "cd"]);
    }
}
