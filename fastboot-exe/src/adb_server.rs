//! 经典 ADB host 协议服务端（127.0.0.1:5037）：让第三方工具（官方 adb 客户端 / scrcpy /
//! Android Studio 等）把本程序当 adb server 直接使用。协议层（帧、请求分类、连接生命周期）
//! 全在 [`crate::adb_host_proto`]，本模块只提供「这台设备怎么开」。
//!
//! 共存与安全：绑 5037 失败即静默退出不抢端口；设备 IO 走全局 [`USB_LOCK`] 串行且设备对象仅在
//! 本线程内使用（WinUSB 句柄 `!Send`）；触碰设备前先 `adb_daemon::ensure_released()` 交还句柄。
//!
//! 与投屏用的 [`crate::adb_mux_server`] 的分工：本 server 每个 client 一条设备连接、靠
//! USB_LOCK 串行，做不到「shell 与 reverse 并发」，故 forward 隧道与交互式服务一律明确 FAIL；
//! 需要并发的场景（scrcpy）由 mux server 承担。

use crate::adb_host_proto::{self as proto, HostBackend, Selector};
use crate::adb_winusb_transport::{serial_from_path, AdbWinUsbDevice};
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

/// 被拉起为 5037 服务端时携带的隐藏参数（对齐 `--adb-daemon` / `--adb-forwarder`）。
pub const ADB_SERVER_ARG: &str = "--adb-server";

const ADB_PORT: u16 = 5037;

/// 探测式建连的读超时：仅几次 USB 往返，毫秒级完成；给 5s 冗余容忍慢设备，绝不触发 180s 授权等待。
const CONNECT_PROBE_MS: u32 = 5_000;

/// 全局 USB 访问锁：串行化所有客户端线程的设备 IO，保证「单一拥有者」，
/// 避免两个线程同时往同一对 ADB 端点写帧而互相踩踏。
static USB_LOCK: Mutex<()> = Mutex::new(());

// ============================ 进程模式 ============================

/// 当前进程是否被拉起为 5037 服务端（argv 含 `--adb-server`）。
pub fn is_adb_server_process() -> bool {
    std::env::args().any(|a| a == ADB_SERVER_ARG)
}

/// 服务端主入口：绑定 127.0.0.1:5037，每个客户端连接一个线程。永不返回。
pub fn run_adb_server_process() -> ! {
    let listener = match TcpListener::bind(("127.0.0.1", ADB_PORT)) {
        Ok(l) => l,
        Err(_) => {
            crate::logger::log_line(
                "[adb-server] 5037 已被占用（官方 server 或本 server 已在运行）；退出",
            );
            std::process::exit(0);
        }
    };
    crate::logger::log_line("[adb-server] 启动，监听 127.0.0.1:5037");

    for stream in listener.incoming().flatten() {
        std::thread::spawn(move || {
            let _ = proto::serve_connection(stream, &ClassicBackend);
        });
    }
    std::process::exit(0);
}

// ============================ 后端实现 ============================

struct ClassicBackend;

impl HostBackend for ClassicBackend {
    fn log_tag(&self) -> &'static str {
        "[adb-server]"
    }

    fn devices(&self, long: bool) -> String {
        let _guard = USB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        crate::adb_daemon::ensure_released();
        let list = AdbWinUsbDevice::enumerate().unwrap_or_default();
        let serials: Vec<String> = list
            .iter()
            .map(|info| serial_from_path(&info.device_path))
            .collect();
        proto::refresh_transport_ids(&serials);
        let mut out = String::new();
        for info in &list {
            let serial = serial_from_path(&info.device_path);
            // 只有 -l 才值得为 banner 建一次连接：`adb devices` 是每秒都在跑的探测。
            let (state, banner) = probe_state(&info.device_path, long);
            out.push_str(&proto::device_line(&serial, state, long, banner.as_ref()));
        }
        out
    }

    fn resolve(&self, selector: &Selector) -> Result<String, String> {
        pick_device_path(selector).map(|p| serial_from_path(&p))
    }

    fn state(&self, selector: &Selector) -> Result<String, String> {
        let _guard = USB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        crate::adb_daemon::ensure_released();
        let path = pick_device_path(selector)?;
        Ok(probe_state(&path, false).0.to_string())
    }

    fn device_features(&self, selector: &Selector) -> Result<String, String> {
        let _guard = USB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        crate::adb_daemon::ensure_released();
        let path = pick_device_path(selector)?;
        let mut dev = AdbWinUsbDevice::open_device(&path).map_err(|e| e.to_string())?;
        match dev.connect_probe(CONNECT_PROBE_MS) {
            Ok(true) => Ok(crate::adb_protocol::negotiated_features(
                &dev.peer_banner().features,
            )),
            _ => Err(proto::ERR_DEVICE_UNAUTHORIZED.to_string()),
        }
    }

    fn kill(&self) {
        std::process::exit(0);
    }

    fn serve_local(&self, mut stream: TcpStream, selector: Selector, svc: &str) -> io::Result<()> {
        serve_local_service(&mut stream, &selector, svc)
    }
}

// ============================ local 服务桥接 ============================

/// 桥接一个 local 服务：只出不进走半双工透传，交互式走全双工中继，其余明确回 FAIL。
fn serve_local_service(stream: &mut TcpStream, selector: &Selector, svc: &str) -> io::Result<()> {
    let kind = classify_local_service(svc);
    if matches!(kind, LocalSvc::Unsupported) {
        return proto::write_fail(
            stream,
            &format!(
                "经典 adb server 不支持该服务（forward 隧道 / framebuffer / jdwp 需要 mux 读循环，\
                 请用投屏 mux server）: {}",
                svc
            ),
        );
    }

    let _guard = USB_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    crate::adb_daemon::ensure_released();

    let path = match pick_device_path(selector) {
        Ok(p) => p,
        Err(e) => return proto::write_fail(stream, &e),
    };
    let mut dev = match AdbWinUsbDevice::open_device(&path) {
        Ok(d) => d,
        Err(e) => return proto::write_fail(stream, &e.to_string()),
    };
    // 授权门：探测式建连，未授权/无法 IO 时快速失败（不阻塞等 180s 授权）。
    match dev.connect_probe(CONNECT_PROBE_MS) {
        Ok(true) => {}
        _ => return proto::write_fail(stream, proto::ERR_DEVICE_UNAUTHORIZED),
    }

    // 服务打开成功 → 回 OKAY，随后桥接设备流。
    proto::write_okay(stream)?;
    stream.flush()?;

    match kind {
        LocalSvc::OutputOnly => {
            // 半双工：设备单向输出，原样透传给客户端 socket。
            let mut sink_err: Option<io::Error> = None;
            let _ = dev.execute_service_streaming(svc, |bytes| {
                match stream.write_all(bytes).and_then(|_| stream.flush()) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        sink_err = Some(e);
                        Err("client socket closed".to_string())
                    }
                }
            });
            match sink_err {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
        LocalSvc::Bidirectional => {
            // 全双工带流控中继（交互式 shell / sync push·pull over server 等需客户端→设备输入的服务）。
            let _ = dev.relay_stream_tcp(svc, &*stream);
            Ok(())
        }
        LocalSvc::Unsupported => unreachable!("Unsupported 已在上方提前返回"),
    }
}

/// local 服务的桥接方式分类。
enum LocalSvc {
    /// 只出不进：设备单向输出，半双工 `execute_service_streaming` 透传。
    OutputOnly,
    /// 双向（需客户端→设备输入）：交互式 shell、`sync:`（push/pull over server）——走带 A_OKAY
    /// 窗口流控的全双工中继 `relay_stream_tcp`（内部委托 `forward_tcp_stream`）。
    Bidirectional,
    /// 暂不支持：framebuffer / jdwp / reverse 隧道等。
    Unsupported,
}

/// 判定一个 local 服务该如何桥接。
fn classify_local_service(svc: &str) -> LocalSvc {
    // 双向（需客户端→设备输入）：命令为空的交互式 shell / 显式 pty，以及 sync（push/pull over server）。
    if svc == "shell:"
        || svc == "shell,v2:"
        || svc == "shell,v2,raw:"
        || svc.starts_with("shell,v2,pty")
        || svc == "sync:"
    {
        return LocalSvc::Bidirectional;
    }
    // 只出不进（带非空命令的 shell / exec）：半双工透传即可。
    let with_arg = |prefix: &str| svc.len() > prefix.len() && svc.starts_with(prefix);
    if with_arg("shell,v2,raw:") || with_arg("shell:") || with_arg("exec:") {
        return LocalSvc::OutputOnly;
    }
    LocalSvc::Unsupported
}

// ============================ 设备选择 ============================

/// 按选择器挑出唯一一台设备的接口路径。选择判据在 [`proto::pick_serial`]（三个 server 共用）。
fn pick_device_path(selector: &Selector) -> Result<String, String> {
    let list = AdbWinUsbDevice::enumerate().map_err(|e| e.to_string())?;
    let serials: Vec<String> = list
        .iter()
        .map(|d| serial_from_path(&d.device_path))
        .collect();
    // Refresh before resolving a transport-id so an unplugged instance cannot be selected from
    // the process-global registry after it disappeared from USB enumeration.
    proto::refresh_transport_ids(&serials);
    let want = proto::pick_serial(selector, &serials)?;
    list.iter()
        .find(|d| serial_from_path(&d.device_path) == want)
        .map(|d| d.device_path.clone())
        .ok_or_else(|| proto::err_device_not_found(&want))
}

/// 探测单台设备的状态。`want_banner` 时顺带把设备 CNXN banner 带回（供 `devices -l`）。
/// 用 connect_probe（不发公钥、不弹框、不等待）。
fn probe_state(
    path: &str,
    want_banner: bool,
) -> (&'static str, Option<crate::adb_protocol::PeerBanner>) {
    match AdbWinUsbDevice::open_device(path) {
        Ok(mut d) => match d.connect_probe(CONNECT_PROBE_MS) {
            Ok(true) => {
                let banner = want_banner.then(|| d.peer_banner().clone());
                ("device", banner)
            }
            _ => ("unauthorized", None),
        },
        Err(_) => ("offline", None),
    }
}

// ============================ 客户端侧（供 adb start-server / kill-server）============================

fn server_addr() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, ADB_PORT))
}

/// 普通 start-server 也启动全功能 mux。经典后端仅保留显式 --adb-server 的兼容入口；
/// 不能由设备轮询占住 5037，否则后开的官方客户端/投屏只能借到不支持隧道的经典后端。
pub fn ensure_server_running() {
    crate::adb_mux_server::ensure_server_running();
}

/// 让 5037 server 退出（发 host:kill）。best-effort，无 server 时是一次会立刻失败的连接。
pub fn kill_server() {
    if let Ok(mut s) = TcpStream::connect_timeout(&server_addr(), Duration::from_millis(300)) {
        let _ = proto::write_len_prefixed(&mut s, "host:kill");
        let _ = s.flush();
        let mut buf = [0u8; 4];
        use std::io::Read;
        let _ = s.read(&mut buf);
    }
}

// ============================ 单元测试 ============================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_local_service_routing() {
        // 只出不进（半双工透传）
        assert!(matches!(
            classify_local_service("shell:ls"),
            LocalSvc::OutputOnly
        ));
        assert!(matches!(
            classify_local_service("shell,v2,raw:id"),
            LocalSvc::OutputOnly
        ));
        assert!(matches!(
            classify_local_service("exec:screencap -p"),
            LocalSvc::OutputOnly
        ));
        // 双向（空命令 shell / pty / sync）→ 全双工带流控中继
        assert!(matches!(
            classify_local_service("shell:"),
            LocalSvc::Bidirectional
        ));
        assert!(matches!(
            classify_local_service("shell,v2,raw:"),
            LocalSvc::Bidirectional
        ));
        assert!(matches!(
            classify_local_service("shell,v2,pty:xterm-256color"),
            LocalSvc::Bidirectional
        ));
        assert!(matches!(
            classify_local_service("sync:"),
            LocalSvc::Bidirectional
        ));
        // 暂不支持
        assert!(matches!(
            classify_local_service("framebuffer:"),
            LocalSvc::Unsupported
        ));
    }

    #[test]
    fn serial_from_path_extracts_third_segment() {
        assert_eq!(
            serial_from_path(r"\\?\usb#vid_18d1&pid_4ee7#a7ab3ab5#{6b1f9c2a}"),
            "a7ab3ab5"
        );
        assert_eq!(serial_from_path("garbage"), "unknown");
    }

    /// `-e`（网络/模拟器）在本项目没有对应 transport：必须如实说没有，
    /// 而不是把唯一那台 USB 设备顶上去让客户端在错误的设备上操作。
    #[test]
    fn local_selector_is_rejected_rather_than_silently_using_usb() {
        assert_eq!(
            Selector::Local.wanted_serial().unwrap_err(),
            proto::ERR_NO_DEVICES
        );
    }
}
