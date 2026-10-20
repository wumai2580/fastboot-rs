use thiserror::Error;

#[derive(Debug, Error)]
pub enum FastbootError {
    #[error("传输失败：{0}")]
    Transport(#[from] TransportError),

    #[error("协议异常：{0}")]
    Protocol(String),

    #[error("设备失败：{0}")]
    Device(String),

    #[error("参数错误：{0}")]
    InvalidArg(String),

    #[error("超时")]
    Timeout,

    #[error("Sparse 处理失败：{0}")]
    Sparse(#[from] SparseError),

    #[error("IO 失败：{0}")]
    Io(#[from] std::io::Error),

    #[error("无设备")]
    NoDevice,

    #[error("多设备，请使用 -s 指定")]
    MultipleDevices,

    #[error("镜像未找到：{0}")]
    ImageNotFound(String),

    #[error("镜像过大：{0} > {1}")]
    ImageTooLarge(u64, u64),

    #[error("adb: {0}")]
    Adb(String),
}

impl FastbootError {
    pub fn recovery_hint(&self) -> Option<&'static str> {
        match self {
            FastbootError::NoDevice => Some(
                "请检查:\n\
                 1. 设备是否已连接并进入 bootloader 模式\n\
                 2. USB 线是否正常\n\
                 3. 驱动是否已安装",
            ),
            FastbootError::Transport(TransportError::Disconnected) => Some(
                "设备连接中断，请:\n\
                 1. 检查 USB 连接\n\
                 2. 重新进入 bootloader 模式\n\
                 3. 重试操作",
            ),
            FastbootError::Transport(TransportError::NoLink) => Some(
                "传输中断 (no link)，请:\n\
                 1. 拔掉 USB 线\n\
                 2. 长按电源键重启设备\n\
                 3. 重新进入 bootloader 模式\n\
                 4. 重新连接并重试",
            ),
            FastbootError::Timeout => Some(
                "设备响应超时，可能原因:\n\
                 1. 设备正在处理大文件\n\
                 2. 设备卡住了，需要重启\n\
                 3. USB 连接不稳定",
            ),
            _ => None,
        }
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            FastbootError::Timeout
                | FastbootError::Transport(TransportError::Timeout)
                | FastbootError::Transport(TransportError::Io(_))
        )
    }
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("IO：{0}")]
    Io(#[from] std::io::Error),

    #[error("超时")]
    Timeout,

    #[error("断开")]
    Disconnected,

    #[error("无链接")]
    NoLink,

    #[error("USB：{0}")]
    Usb(String),

    #[error("协议：{0}")]
    Protocol(String),

    #[error("设备忙")]
    DeviceBusy,

    /// 该 WinUSB 接口不是 ADB。AOSP 对 adb 接口的唯一判据是描述符三元组
    /// class=0xFF/subclass=0x42/protocol=0x01 且带一对 bulk 端点（adb.h `ADB_CLASS/…`）；
    /// fastboot（protocol=0x03）、EDL 9008/诊断口（0xFF/0xFF/0xFF）等其它接口可能挂在同一
    /// 接口类 GUID 下。对它们发 adb 握手会搞乱设备状态机并占住句柄，而描述符是确定性结果，
    /// 故一经识别即快速拒绝、绝不做 bulk IO、绝不重试。
    #[error("非 ADB 接口（fastboot/EDL 9008/其它厂商接口）")]
    NotAdbInterface,
}

/// 一段（已 stringify 的）USB 错误文本是否为「拒绝访问」（设备接口已被其他进程独占打开）。
/// 供 embed/adb_hub 等把 [`TransportError`] 压成 `String` 之后仍需分类的路径复用。
/// 除本地化文案外必须认 HRESULT 十六进制码 0x80070005 与 Win32 码本身：非中英文系统上
/// 两种文案都不存在，只有错误码是稳定判据。
pub fn usb_text_is_access_denied(text: &str) -> bool {
    let t = text.to_lowercase();
    t.contains("os error 5")
        || t.contains("access is denied")
        || t.contains("拒绝访问")
        || t.contains("拒绝")
        || t.contains("0x80070005")
        || t.contains("error_access_denied")
}

impl TransportError {
    pub fn is_usb_access_denied(&self) -> bool {
        match self {
            Self::Io(e) => {
                e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(5)
            }
            Self::Usb(s) => usb_text_is_access_denied(s),
            _ => false,
        }
    }

    pub fn is_no_link(&self) -> bool {
        matches!(self, TransportError::NoLink | TransportError::Disconnected)
    }

    pub fn from_usb_error(msg: &str) -> Self {
        let msg_lower = msg.to_lowercase();
        if msg_lower.contains("no link")
            || msg_lower.contains("pipe")
            || msg_lower.contains("disconnected")
            || msg_lower.contains("not found")
        {
            TransportError::NoLink
        } else if msg_lower.contains("timeout") {
            TransportError::Timeout
        } else if msg_lower.contains("busy") {
            TransportError::DeviceBusy
        } else {
            TransportError::Usb(msg.to_string())
        }
    }
}

#[cfg(test)]
mod transport_error_tests {
    use super::{usb_text_is_access_denied, TransportError};

    /// Windows API 的 `windows::core::Error` 在不同系统语言下文字不同；分类必须认 HRESULT
    /// 本身，否则英文/中文以外环境会把同一个 0x80070005 当成普通永久错误。
    #[test]
    fn classifies_access_denied_by_hresult_without_locale_text() {
        let error =
            TransportError::Usb("CreateFileW 失败，OS 错误码 HRESULT(0x80070005)".to_string());
        assert!(error.is_usb_access_denied());
    }

    /// 字符串级判定与 `TransportError::is_usb_access_denied` 同判据：embed/adb_hub 把错误
    /// 压成 String 后靠它决定「撞句柄 → 借道 5037 重试」，判漏就退化成直接报错。
    #[test]
    fn text_classifier_covers_locale_variants_and_raw_codes() {
        for text in [
            "USB：CreateFileW 失败，OS 错误码: Error { code: HRESULT(0x80070005), message: \"拒绝访问。\" }",
            "Access is denied. (os error 5)",
            "open failed: ERROR_ACCESS_DENIED",
            "CreateFileW 失败，OS 错误码 HRESULT(0x80070005)",
        ] {
            assert!(usb_text_is_access_denied(text), "应判为拒绝访问: {text}");
        }
        for text in ["设备超时", "no link", "device not found"] {
            assert!(!usb_text_is_access_denied(text), "不应判为拒绝访问: {text}");
        }
    }
}

#[derive(Debug, Error)]
pub enum SparseError {
    #[error("无效 sparse 魔数: 0x{0:08X}")]
    InvalidMagic(u32),

    #[error("无效 sparse 头: {0}")]
    InvalidHeader(String),

    #[error("不支持的 sparse 版本: {0}.{1}")]
    UnsupportedVersion(u16, u16),

    #[error("无效 chunk 类型: 0x{0:04X}")]
    InvalidChunkType(u16),

    #[error("IO：{0}")]
    Io(#[from] std::io::Error),
}
