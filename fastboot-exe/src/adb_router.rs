use crate::adb_tcp_transport::{normalize_endpoint, AdbTcpDevice};
use crate::adb_winusb_transport::{serial_from_path, AdbDeviceInfo, AdbWinUsbDevice, ShellExit};
use std::env;
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

const WAIT_POLL_MS: u64 = 500;
const DEFAULT_WAIT_TIMEOUT_MS: u64 = 0;

fn invoked_as_adb() -> bool {
    env::current_exe()
        .ok()
        .as_deref()
        .and_then(Path::file_stem)
        .map(|s| s.to_string_lossy().eq_ignore_ascii_case("adb"))
        .unwrap_or(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdbSelector {
    Any,
    UsbOnly,
    EmulatorOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedAdbArgs {
    serial: Option<String>,
    selector: AdbSelector,
    args: Vec<String>,
}

enum AdbDevice {
    Usb(AdbWinUsbDevice),
    Tcp(AdbTcpDevice),
}

impl AdbDevice {
    fn connect(&mut self) -> Result<(), String> {
        match self {
            Self::Usb(dev) => dev.connect(),
            Self::Tcp(dev) => dev.connect(),
        }
    }

    fn push(&mut self, local: &str, remote: &str) -> Result<(), String> {
        match self {
            Self::Usb(dev) => dev.push(local, remote),
            Self::Tcp(dev) => dev.push(local, remote),
        }
    }

    fn pull(&mut self, remote: &str, local: &str) -> Result<(), String> {
        match self {
            Self::Usb(dev) => dev.pull(remote, local),
            Self::Tcp(dev) => dev.pull(remote, local),
        }
    }

    fn shell_command(&mut self, command: &str) -> Result<String, String> {
        match self {
            Self::Usb(dev) => dev.shell_command(command),
            Self::Tcp(dev) => dev.shell_command(command),
        }
    }

    fn shell_command_streaming<FO, FE>(
        &mut self,
        command: &str,
        on_stdout: FO,
        on_stderr: FE,
    ) -> Result<ShellExit, String>
    where
        FO: FnMut(&[u8]),
        FE: FnMut(&[u8]),
    {
        match self {
            Self::Usb(dev) => dev.shell_command_streaming(command, on_stdout, on_stderr),
            Self::Tcp(dev) => dev.shell_command_streaming(command, on_stdout, on_stderr),
        }
    }

    fn execute_service_streaming<F>(&mut self, service: &str, on_data: F) -> Result<(), String>
    where
        F: FnMut(&[u8]) -> Result<(), String>,
    {
        match self {
            Self::Usb(dev) => dev.execute_service_streaming(service, on_data),
            Self::Tcp(dev) => dev.execute_service_streaming(service, on_data),
        }
    }

    fn reboot(&mut self, target: &str) -> Result<(), String> {
        match self {
            Self::Usb(dev) => dev.reboot(target),
            Self::Tcp(dev) => dev.reboot(target),
        }
    }

    fn root(&mut self) -> Result<(), String> {
        match self {
            Self::Usb(dev) => dev.root(),
            Self::Tcp(dev) => dev.root(),
        }
    }

    fn unroot(&mut self) -> Result<(), String> {
        match self {
            Self::Usb(dev) => dev.unroot(),
            Self::Tcp(dev) => dev.unroot(),
        }
    }

    fn sideload(&mut self, package_path: &str) -> Result<(), String> {
        match self {
            Self::Usb(dev) => dev.sideload(package_path),
            Self::Tcp(dev) => dev.sideload(package_path),
        }
    }

    /// 长连接/等用户确认类服务（jdwp、backup、restore、exec-out 大输出）：取消流式静默上限，
    /// 否则默认读窗口一到就把仍在正常等待的流判成掉线。
    fn prepare_long_lived(&mut self) -> Result<(), String> {
        self.connect()?;
        if let Self::Usb(dev) = self {
            dev.set_stream_idle_window_ms(u32::MAX);
        }
        Ok(())
    }

    /// 执行服务并把 `stdin` 全部写给它（restore/install 用）。
    fn exec_stdin(&mut self, service: &[u8], stdin: &mut dyn io::Read) -> Result<Vec<u8>, String> {
        match self {
            Self::Usb(dev) => dev.exec_with_stdin(service, stdin),
            Self::Tcp(dev) => dev.exec_with_stdin(service, stdin),
        }
    }
}

/// `-d` / `-e` 选择器。进程内只解析一次命令行，故放全局，供各打开设备的入口统一判定。
static SELECTOR: std::sync::OnceLock<AdbSelector> = std::sync::OnceLock::new();

fn usb_only() -> bool {
    matches!(SELECTOR.get(), Some(AdbSelector::UsbOnly))
}

/// `-d` 时不考虑 `adb connect` 登记的网络设备。
fn tcp_candidates() -> Vec<String> {
    if usb_only() {
        Vec::new()
    } else {
        load_tcp_devices()
    }
}

/// 不针对具体设备的命令：`-e` 找不到模拟器也照常执行。
fn command_is_host_only(cmd: &str) -> bool {
    matches!(
        cmd,
        "devices"
            | "devices-l"
            | "track-devices"
            | "version"
            | "--version"
            | "help"
            | "--help"
            | "-h"
            | "start-server"
            | "kill-server"
            | "connect"
            | "disconnect"
            | "keygen"
            | "features"
            | "host-features"
    )
}

const ADB_USAGE: &str = "\
Android Debug Bridge (RMFlashTool 自研实现)

用法: adb [-s SERIAL] [-d] [-e] COMMAND [ARGS...]

general:  devices [-l] | help | version
network:  connect HOST[:PORT] | disconnect [HOST[:PORT]] | forward | reverse | tcpip PORT | usb
file:     push LOCAL REMOTE | pull REMOTE [LOCAL] | sync
shell:    shell [COMMAND] | exec-out COMMAND | logcat | abb ARGS
app:      install | install-multiple | install-multi-package | uninstall
debug:    bugreport [PATH] | jdwp | track-jdwp
security: root | unroot | remount [-R] | disable-verity | enable-verity | keygen FILE
scripting: wait-for[-TRANSPORT]-STATE | get-state | get-serialno | get-devpath
          reboot [bootloader|recovery|sideload|sideload-auto-reboot|fastboot|edl]
          sideload OTAPACKAGE
backup:   backup [-f FILE] [-apk|-noapk] [-obb|-noobb] [-shared|-noshared] [-all] [-system|-nosystem] [PACKAGE...]
          restore FILE
server:   start-server | kill-server
";

fn parse_adb_args(raw: Vec<String>) -> ParsedAdbArgs {
    let mut serial = None;
    let mut selector = AdbSelector::Any;
    let mut args = Vec::new();
    let mut iter = raw.into_iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-s" => {
                if let Some(value) = iter.next() {
                    serial = Some(value);
                }
            }
            "-d" => selector = AdbSelector::UsbOnly,
            "-e" => selector = AdbSelector::EmulatorOnly,
            _ => args.push(arg),
        }
    }

    ParsedAdbArgs {
        serial,
        selector,
        args,
    }
}

pub fn try_handle_adb_args() -> Option<i32> {
    // 仅当本进程以 `adb` 名字被调用时才接管 adb 语义，否则放行给 fastboot Cli——
    // 避免 devices/reboot 等同名动词在 fastboot 模式下被误拦（曾致 `fastboot devices` 走 adb）。
    if !invoked_as_adb() {
        return None;
    }
    let parsed = parse_adb_args(env::args().skip(1).collect());
    let serial = parsed.serial.as_deref();
    let _ = SELECTOR.set(parsed.selector);
    let args = parsed.args;

    // 与官方一致：不带命令打印用法并以非零退出（脚本不能把「什么都没做」当成功）。
    if args.is_empty() {
        eprint!("{}", ADB_USAGE);
        return Some(1);
    }

    // 子命令关键字大小写不敏感（ADB DEVICES / Adb REboot …）；args[1..] 的自由参数
    //（路径/包名/shell 内容等）原样透传，绝不改写。
    let cmd_lower = args[0].to_ascii_lowercase();
    let cmd = cmd_lower.as_str();
    // 本实现只接管 USB 与 `adb connect` 的网络设备，没有模拟器 transport：`-e` 如实报无模拟器。
    if parsed.selector == AdbSelector::EmulatorOnly && !command_is_host_only(cmd) {
        eprintln!("adb: error: no emulators found");
        return Some(1);
    }
    if cmd.starts_with("wait-for") {
        return handle_wait_for_native(serial, cmd);
    }

    match cmd {
        "start-server" => {
            // 默认启动也用持有常驻 USB 连接的 mux；已有官方服务时直接借道。
            if env::var("RMF_ADB_MUX").map(|v| v == "1").unwrap_or(false) {
                crate::adb_mux_server::ensure_server_running();
            } else {
                crate::adb_server::ensure_server_running();
            }
            Some(0)
        }
        "kill-server" => {
            // 先让 5037 服务端退出，再释放命名管道 daemon 持有的 USB 句柄。
            crate::adb_server::kill_server();
            crate::adb_daemon::ensure_released();
            Some(0)
        }
        // scrcpy 投屏专用：设备探测/等待/读信息/收尾的编排，GUI 只调这两条子命令（见 scrcpy_prep.rs）。
        "scrcpy-prep" => Some(crate::scrcpy_prep::run_prep()),
        "scrcpy-cleanup" => Some(crate::scrcpy_prep::run_cleanup()),
        "version" | "--version" => {
            println!("Android Debug Bridge version 1.0.41");
            println!("Version 34.0.5-10900879");
            Some(0)
        }
        "help" | "--help" | "-h" => {
            print!("{}", ADB_USAGE);
            Some(0)
        }
        "features" | "host-features" => {
            println!("{}", adb_feature_list());
            Some(0)
        }
        // `adb devices -l` 是官方写法（`devices-l` 只是 host 服务名），两种都认。
        "devices" | "devices-l" => {
            handle_devices_dispatch(cmd == "devices-l" || args[1..].iter().any(|a| a == "-l"))
        }
        "track-devices" => handle_track_devices_native(),
        "connect" => handle_connect_native(&args[1..]),
        "disconnect" => handle_disconnect_native(&args[1..]),
        "reverse" => handle_reverse_dispatch(serial, &args[1..]),
        "forward" => handle_forward_dispatch(serial, &args[1..]),
        "push" => handle_push_native(serial, &args[1..]),
        "pull" => handle_pull_native(serial, &args[1..]),
        "install" => handle_install_native(serial, &args[1..]),
        "install-multiple" | "install-multi" => handle_install_multiple_native(serial, &args[1..]),
        "install-multi-package" => handle_install_multi_package_native(serial, &args[1..]),
        "exec-out" => {
            if args.len() < 2 {
                eprintln!("adb exec-out requires COMMAND");
                return Some(1);
            }
            handle_stream_service(serial, &format!("exec:{}", args[1..].join(" ")), "exec-out")
        }
        "abb" => {
            if args.len() < 2 {
                eprintln!("adb abb requires ARGS");
                return Some(1);
            }
            // abb_exec 是裸输出通道（参数以 NUL 分隔、不经 shell）；拿不到退出码，输出与官方一致。
            handle_stream_service(serial, &format!("abb_exec:{}", args[1..].join("\0")), "abb")
        }
        "jdwp" => handle_stream_service(serial, "jdwp", "jdwp"),
        "track-jdwp" => handle_stream_service(serial, "track-jdwp", "track-jdwp"),
        "get-serialno" => handle_get_serialno(serial, false),
        "get-devpath" => handle_get_serialno(serial, true),
        "disable-verity" => handle_simple_service(serial, "disable-verity:", "disable-verity"),
        "enable-verity" => handle_simple_service(serial, "enable-verity:", "enable-verity"),
        "keygen" => handle_keygen(&args[1..]),
        "backup" => handle_backup(serial, &args[1..]),
        "restore" => handle_restore(serial, &args[1..]),
        "emu"
        | "ppp"
        | "pair"
        | "mdns"
        | "install-incremental"
        | "reconnect"
        | "attach"
        | "detach" => {
            eprintln!(
                "adb {}: 本实现不支持（无模拟器控制台 / 无线配对 / 增量安装 / USB 重新挂接）",
                args[0]
            );
            Some(1)
        }
        "uninstall" => handle_uninstall_native(serial, &args[1..]),
        "logcat" => handle_logcat_native(serial, &args[1..]),
        "reboot" => handle_reboot_native(serial, &args[1..]),
        "root" => handle_root_native(serial, true),
        "unroot" => handle_root_native(serial, false),
        "remount" => handle_remount_native(serial, &args[1..]),
        "tcpip" => handle_tcpip_native(serial, &args[1..]),
        "usb" => handle_usb_native(serial),
        "bugreport" => handle_bugreport_native(serial, &args[1..]),
        "sideload" => handle_sideload_native(serial, &args[1..]),
        "sync" => handle_sync_native(serial, &args[1..]),
        "get-state" => handle_get_state_dispatch(serial),
        "shell" => {
            let shell_args = &args[1..];
            // scrcpy 投屏时，长驻 shell（app_process server）必须与 reverse 隧道
            // 共享 mux server 的同一条 USB 连接，否则抢句柄起不来——先自动拉起常驻 server 再优先走 mux 客户端。
            if should_route_via_mux() {
                let cmd_string = shell_args.join(" ");
                if let Some(code) = crate::adb_mux_client::retry_via_server(|| {
                    crate::adb_mux_client::shell_command(serial, &cmd_string)
                }) {
                    return Some(code);
                }
                // mux 下绝不回退 daemon/直连：直连长驻 shell 会独占 WinUSB 句柄，把 mux server 的
                // 建连（get_or_create_hub → open_device）锁死成 CreateFileW 0x80070005（真机实测）。
                return Some(mux_no_fallback("shell"));
            }
            if !shell_args.is_empty() {
                let cmd_string = shell_args.join(" ");
                if let Some(code) = crate::adb_daemon::run_shell(serial, &cmd_string) {
                    return Some(code);
                }
            }
            handle_shell(serial, shell_args)
        }
        // 未知命令必须报错并非零退出：静默 exit(0) 会让脚本把「没实现」当成「执行成功」。
        _ => {
            eprintln!("adb: unknown command {}", args[0]);
            eprintln!("用 `adb help` 查看支持的命令");
            Some(1)
        }
    }
}

/// 一次性、只出不进的设备服务（disable-verity / enable-verity 等），路由与 tcpip/usb 相同：
/// mux → daemon → 直连。
fn handle_simple_service(serial: Option<&str>, service: &str, what: &str) -> Option<i32> {
    if should_route_via_mux() {
        return print_mux_service(serial, service, what);
    }
    if let Some(code) = crate::adb_daemon::run_service(serial, service) {
        return Some(code);
    }
    crate::adb_daemon::ensure_released();
    let mut dev = match open_adb_device_native(serial) {
        Ok(dev) => dev,
        Err(e) => {
            eprintln!("{}", e);
            return Some(1);
        }
    };
    match print_service(&mut dev, service) {
        Ok(()) => Some(0),
        Err(e) => {
            eprintln!("{} failed: {}", what, e);
            Some(1)
        }
    }
}

/// 输出原样（二进制安全）流向 stdout、直到设备关流的服务：exec-out / abb / jdwp / track-jdwp。
fn handle_stream_service(serial: Option<&str>, service: &str, what: &str) -> Option<i32> {
    let mut stdout = io::stdout();
    if should_route_via_mux() {
        return match crate::adb_mux_client::retry_via_server(|| {
            crate::adb_mux_client::stream_service_to(serial, service, &mut stdout)
        }) {
            Some(Ok(())) => Some(0),
            Some(Err(e)) => {
                eprintln!("{} failed: {}", what, e.trim());
                Some(1)
            }
            None => Some(mux_no_fallback(what)),
        };
    }
    let mut dev = match open_adb_device_native(serial) {
        Ok(dev) => dev,
        Err(e) => {
            eprintln!("{}", e);
            return Some(1);
        }
    };
    if let Err(e) = dev.prepare_long_lived() {
        eprintln!("{}", e);
        return Some(1);
    }
    let result = dev.execute_service_streaming(service, |payload| {
        stdout
            .write_all(payload)
            .and_then(|_| stdout.flush())
            .map_err(|e| format!("failed to write output: {}", e))
    });
    match result {
        Ok(()) => Some(0),
        Err(e) => {
            eprintln!("{} failed: {}", what, e);
            Some(1)
        }
    }
}

/// `adb get-serialno` / `adb get-devpath`：解析出唯一目标设备（规则与其它命令一致）后打印。
fn handle_get_serialno(serial: Option<&str>, devpath: bool) -> Option<i32> {
    let resolved = match serial.filter(|s| !s.is_empty()) {
        Some(s) => Ok(s.to_string()),
        None => {
            let serials: Vec<String> = if should_route_via_mux() {
                match crate::adb_mux_client::retry_via_server(|| {
                    crate::adb_mux_client::devices(false)
                }) {
                    Some(list) => list
                        .lines()
                        .filter_map(|l| l.split('\t').next())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect(),
                    None => return Some(mux_no_fallback("get-serialno")),
                }
            } else {
                let mut v: Vec<String> = AdbWinUsbDevice::enumerate()
                    .unwrap_or_default()
                    .iter()
                    .map(|d| serial_from_path(&d.device_path))
                    .collect();
                v.extend(tcp_candidates());
                v
            };
            crate::adb_host_proto::pick_serial(&crate::adb_host_proto::Selector::Any, &serials)
        }
    };
    match resolved {
        Ok(s) => {
            if !devpath {
                println!("{}", s);
            } else if s.contains(':') {
                // 网络设备没有 USB 路径，官方同样回 unknown。
                println!("unknown");
            } else {
                println!("usb:{}", s);
            }
            Some(0)
        }
        Err(e) => {
            eprintln!("adb: error: {}", e);
            Some(1)
        }
    }
}

/// `adb keygen FILE`：生成 FILE（私钥）与 FILE.pub（公钥），不动 ~/.android/adbkey。
fn handle_keygen(args: &[String]) -> Option<i32> {
    let Some(path) = args.first() else {
        eprintln!("adb keygen requires FILE");
        return Some(1);
    };
    match crate::crypto::keygen(Path::new(path)) {
        Ok(()) => {
            println!("adb I: generated {} and {}.pub", path, path);
            Some(0)
        }
        Err(e) => {
            eprintln!("adb keygen failed: {}", e);
            Some(1)
        }
    }
}

/// 官方 `escape_arg`：单引号包裹，内部单引号写成 `'\''`。
fn escape_arg(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "'\\''"))
}

/// backup 的服务串：`backup:` 后每个参数前加空格并转义（与官方 commandline.cpp 一致）；`-f FILE`
/// 只决定本地输出文件，不传给设备。返回（服务串, 输出文件）。
fn backup_service(args: &[String]) -> Result<(String, String), String> {
    let mut file = "backup.ab".to_string();
    let mut service = String::from("backup:");
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if arg == "-f" {
            file = it.next().ok_or("backup -f requires FILE")?.clone();
            continue;
        }
        service.push(' ');
        service.push_str(&escape_arg(arg));
    }
    Ok((service, file))
}

/// `adb backup`：设备弹窗确认后把 .ab 数据流回，写入本地文件（Android 12+ 多数应用已不参与备份）。
fn handle_backup(serial: Option<&str>, args: &[String]) -> Option<i32> {
    let (service, file) = match backup_service(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", e);
            return Some(1);
        }
    };
    let mut out = match fs::File::create(&file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("adb: backup unable to create file '{}': {}", file, e);
            return Some(1);
        }
    };
    eprintln!("Now unlock your device and confirm the backup operation...");
    let result = if should_route_via_mux() {
        match crate::adb_mux_client::retry_via_server(|| {
            crate::adb_mux_client::stream_service_to(serial, &service, &mut out)
        }) {
            Some(r) => r,
            None => return Some(mux_no_fallback("backup")),
        }
    } else {
        open_adb_device_native(serial).and_then(|mut dev| {
            dev.prepare_long_lived()?;
            dev.execute_service_streaming(&service, |payload| {
                out.write_all(payload)
                    .map_err(|e| format!("写入 {} 失败: {}", file, e))
            })
        })
    };
    match result {
        Ok(()) => Some(0),
        Err(e) => {
            eprintln!("adb backup failed: {}", e);
            Some(1)
        }
    }
}

/// `adb restore FILE`：把 .ab 文件整段写给设备的 `restore:` 服务，设备弹窗确认后恢复。
fn handle_restore(serial: Option<&str>, args: &[String]) -> Option<i32> {
    let Some(path) = args.first() else {
        eprintln!("adb restore requires FILE");
        return Some(1);
    };
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("adb: unable to open file {}: {}", path, e);
            return Some(1);
        }
    };
    eprintln!("Now unlock your device and confirm the restore operation.");
    let result = if should_route_via_mux() {
        match crate::adb_mux_client::retry_via_server(|| {
            crate::adb_mux_client::exec_with_stdin(serial, "restore:", &mut file)
        }) {
            Some(r) => r,
            None => return Some(mux_no_fallback("restore")),
        }
    } else {
        open_adb_device_native(serial).and_then(|mut dev| {
            dev.prepare_long_lived()?;
            dev.exec_stdin(b"restore:", &mut file)
        })
    };
    match result {
        Ok(out) => {
            let _ = io::stdout().write_all(&out);
            Some(0)
        }
        Err(e) => {
            eprintln!("adb restore failed: {}", e);
            Some(1)
        }
    }
}

/// `adb install-multi-package [opts] <apk...>`：参数拆分规则同 install-multiple。
fn handle_install_multi_package_native(serial: Option<&str>, args: &[String]) -> Option<i32> {
    let apks: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .collect();
    let options: Vec<String> = args
        .iter()
        .filter(|a| a.starts_with('-'))
        .cloned()
        .collect();
    if apks.is_empty() {
        eprintln!("adb install-multi-package requires at least one APK");
        return Some(1);
    }
    if let Some(missing) = apks.iter().find(|apk| !Path::new(apk.as_str()).exists()) {
        eprintln!("APK does not exist: {}", missing);
        return Some(1);
    }
    let result = if should_route_via_mux() {
        crate::adb_install::install_multi_package(
            &mut crate::adb_install::MuxConn::new(serial),
            &apks,
            &options,
        )
    } else {
        open_adb_device_native(serial).and_then(|mut dev| {
            crate::adb_install::install_multi_package(&mut dev, &apks, &options)
        })
    };
    Some(print_install_result(result))
}

fn adb_feature_list() -> &'static str {
    // 与 A_CNXN banner 同源，避免 host:features 超宣（见 adb_protocol::ADB_HOST_FEATURES）。
    crate::adb_protocol::ADB_HOST_FEATURES
}

/// 决定借道 5037 但走不通时的统一失败出口——绝不回退直连：设备句柄单一 owner 是 5037 上的
/// server，直连会与其争用 WinUSB（CreateFileW 0x80070005，投屏 push/getprop 稳定失败的根因）。
/// 如实报错退出，交上层循环（scrcpy-prep 的 ensure_server_running）重建 server 自愈。
fn mux_no_fallback(what: &str) -> i32 {
    let msg =
        format!("adb {what}: 5037 上的 adb server 不可用，已阻止直连回退（避免与它争用设备句柄）");
    eprintln!("{}", msg);
    crate::logger::log_line(&format!("[adb-mux-client] {}", msg));
    1
}

fn handle_devices_native() -> Option<i32> {
    print!("{}", device_list_text(true));
    Some(0)
}

/// 确保设备轮询先有一个可借道的 5037 server。
///
/// 端口已有官方 adb server 时，`ensure_*` 只确认它仍在，不会抢占或杀掉它；端口为空时才
/// 拉起本项目的 mux server。这样本项目先启动时，
/// 官方 adb 也能按标准 host 协议连接进来，双方不会各自打开同一条 WinUSB 设备句柄。
fn ensure_server_for_devices() {
    crate::adb_mux_server::ensure_server_running();
}

/// `adb devices [-l]` 分发：先经 5037 host 服务查询，避免每次轮询都由 CLI 自己枚举并打开
/// USB。服务不可用（例如端口被非 adb 程序占用且无法清理）时才保留旧的 daemon/直连兜底，
/// 以免无服务环境下完全失去设备识别能力。
fn handle_devices_dispatch(long: bool) -> Option<i32> {
    ensure_server_for_devices();
    if let Some(list) =
        crate::adb_mux_client::retry_via_server(|| crate::adb_mux_client::devices(long))
    {
        print!("List of devices attached\n{}", list);
        let _ = io::stdout().flush();
        return Some(0);
    }

    // server 仍在端口上但本轮 host 请求暂时没拿到回应时，也不能改开自己的 USB 句柄；
    // 否则正是轮询与 server 争用设备的竞态。交空列表给上层下一轮重试。
    if crate::adb_mux_client::device_owned_by_adb_server() {
        crate::logger::log_line(
            "[adb-mux-client] devices: server 在位但本轮查询失败，禁止直连探测",
        );
        println!("List of devices attached");
        let _ = io::stdout().flush();
        return Some(0);
    }

    // 只有端口确实没有 adb server（或被无关程序占用且无法建立服务）时才保留兜底，
    // 让无服务环境下仍能识别设备。
    crate::adb_daemon::run_devices().or_else(handle_devices_native)
}

/// `adb reverse ...` 分发：mux 活跃时优先经 mux server（与 shell 共享一条 USB 连接），失败回退既有实现。
fn handle_reverse_dispatch(serial: Option<&str>, args: &[String]) -> Option<i32> {
    if should_route_via_mux() {
        if let Some(code) = crate::adb_mux_client::retry_via_server(|| {
            crate::adb_mux_client::handle_reverse(serial, args)
        }) {
            return Some(code);
        }
    }
    Some(crate::adb_reverser::handle_reverse_command(serial, args))
}

/// `adb forward ...` 分发：5037 上有 server 时监听必须建在它那里——设备句柄被它独占，本进程
/// 转发器直连只会撞 0x80070005，它的本地注册表也看不到别人经 server 建的转发。
fn handle_forward_dispatch(serial: Option<&str>, args: &[String]) -> Option<i32> {
    if should_route_via_mux() {
        if let Some(code) = crate::adb_mux_client::retry_via_server(|| {
            crate::adb_mux_client::handle_forward(serial, args)
        }) {
            return Some(code);
        }
    }
    Some(crate::adb_forwarder::handle_forward_command(serial, args))
}

/// `adb get-state` 分发：mux 活跃时优先问 mux server（避免开被独占的设备句柄）。
fn handle_get_state_dispatch(serial: Option<&str>) -> Option<i32> {
    if should_route_via_mux() {
        if let Some(state) =
            crate::adb_mux_client::retry_via_server(|| crate::adb_mux_client::get_state(serial))
        {
            let state = state.trim();
            println!("{}", state);
            return Some(if state == "device" { 0 } else { 1 });
        }
        // mux 下不回退直连探测（会开设备句柄），如实报 unknown。
        return Some(mux_no_fallback("get-state"));
    }
    handle_get_state_native(serial)
}

fn handle_track_devices_native() -> Option<i32> {
    let mut last = String::new();
    loop {
        let next = device_list_text(false);
        if next != last {
            print!("{}", next);
            let _ = io::stdout().flush();
            last = next;
        }
        thread::sleep(Duration::from_millis(1000));
    }
}

fn device_list_text(include_header: bool) -> String {
    let mut out = String::new();
    if include_header {
        out.push_str("List of devices attached\n");
    }

    let usb_devices = AdbWinUsbDevice::enumerate().unwrap_or_default();
    for info in usb_devices {
        let serial = serial_from_path(&info.device_path);
        let state = match AdbWinUsbDevice::open_device(&info.device_path) {
            Ok(mut dev) => {
                if dev.connect_probe(5_000).unwrap_or(false) {
                    "device"
                } else {
                    "unauthorized"
                }
            }
            Err(_) => "unauthorized",
        };
        out.push_str(&format!("{}\t{}\n", serial, state));
    }

    for endpoint in load_tcp_devices() {
        let state = match AdbTcpDevice::connect_endpoint(&endpoint) {
            Ok(mut dev) => {
                if dev.connect_probe().unwrap_or(false) {
                    "device"
                } else {
                    "unauthorized"
                }
            }
            Err(_) => "offline",
        };
        out.push_str(&format!("{}\t{}\n", endpoint, state));
    }

    out
}

fn select_device_path(devices: &[AdbDeviceInfo], serial: Option<&str>) -> Result<String, String> {
    if devices.is_empty() {
        return Err("No ADB USB device found".to_string());
    }

    if let Some(wanted) = serial.filter(|s| !s.is_empty() && *s != "unknown") {
        return devices
            .iter()
            .find(|d| serial_from_path(&d.device_path) == wanted)
            .map(|d| d.device_path.clone())
            .ok_or_else(|| format!("ADB USB device with serial '{}' was not found", wanted));
    }

    if devices.len() > 1 {
        return Err("More than one ADB device is connected; use -s <serial>".to_string());
    }

    Ok(devices[0].device_path.clone())
}

fn open_adb_device_native(serial: Option<&str>) -> Result<AdbDevice, String> {
    // 任何 WinUSB 直连入口都必须先让 CLI daemon 放手；否则用户先执行
    // `adb devices` 后再执行 push/pull/reboot 等命令时，旧 owner 仍持有设备句柄。
    crate::adb_daemon::ensure_released();

    if let Some(serial) = serial.filter(|s| !s.is_empty()) {
        if let Ok(endpoint) = normalize_endpoint(serial) {
            let normalized = endpoint.serial();
            let is_tcp =
                load_tcp_devices().iter().any(|s| s == &normalized) || serial.contains(':');
            if is_tcp && usb_only() {
                return Err(format!("device '{}' is not a USB device (-d)", serial));
            }
            if is_tcp {
                let mut dev = AdbTcpDevice::open(endpoint)?;
                dev.connect()?;
                return Ok(AdbDevice::Tcp(dev));
            }
        }
    }

    let usb_devices = AdbWinUsbDevice::enumerate().map_err(|e| e.to_string())?;
    let tcp_devices = tcp_candidates();

    if serial.is_none() {
        let total = usb_devices.len() + tcp_devices.len();
        if total == 0 {
            return Err("No ADB device found".to_string());
        }
        if total > 1 {
            return Err("More than one ADB device is connected; use -s <serial>".to_string());
        }
        if usb_devices.is_empty() {
            let mut dev = AdbTcpDevice::connect_endpoint(&tcp_devices[0])?;
            dev.connect()?;
            return Ok(AdbDevice::Tcp(dev));
        }
    }

    let path = select_device_path(&usb_devices, serial)?;
    let dev = AdbWinUsbDevice::open_device(&path).map_err(|e| e.to_string())?;
    Ok(AdbDevice::Usb(dev))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn default_pull_local_path(remote: &str, local: Option<&str>) -> PathBuf {
    let fallback = remote
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("adb-pull.out");
    match local {
        Some(path) if Path::new(path).is_dir() => Path::new(path).join(fallback),
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(fallback),
    }
}

fn handle_push_native(serial: Option<&str>, args: &[String]) -> Option<i32> {
    if args.len() < 2 {
        eprintln!("adb push requires LOCAL REMOTE");
        return Some(1);
    }

    let local_path = Path::new(&args[0]);
    if !local_path.exists() {
        eprintln!("Local path does not exist: {}", args[0]);
        return Some(1);
    }

    // scrcpy 的 server.jar 也必须走 mux：prep 已经让 mux server 持有设备句柄，
    // 此时再直连 WinUSB 会稳定触发 CreateFileW 0x80070005。
    if should_route_via_mux() {
        if local_path.is_file() {
            // 首次连不上多为 server 冷启动窗口（ensure_server_running 只等端口 ≤2s 即返回，
            // 客户端 TCP 连接超时仅 500ms）：等 mux 可探测后重试一次，避免把拉起竞态放大成投屏失败。
            let outcome = crate::adb_mux_client::retry_via_server(|| {
                crate::adb_mux_client::push(serial, local_path, &args[1])
            });
            if let Some(result) = outcome {
                return match result {
                    Ok(()) => {
                        println!("{}: 1 file pushed", args[1]);
                        Some(0)
                    }
                    Err(e) => {
                        eprintln!("Push failed: {}", e);
                        Some(1)
                    }
                };
            }
        }
        // mux 下不回退直连（含目录推送）：直连会与 mux server 争用句柄（CreateFileW 0x80070005）。
        return Some(mux_no_fallback("push"));
    }

    let mut dev = match open_adb_device_native(serial) {
        Ok(dev) => dev,
        Err(e) => {
            eprintln!("{}", e);
            return Some(1);
        }
    };

    match push_path_recursive(&mut dev, local_path, &args[1], false) {
        Ok(count) => {
            println!("{}: {} file{} pushed", args[1], count, plural_s(count));
            Some(0)
        }
        Err(e) => {
            eprintln!("Push failed: {}", e);
            Some(1)
        }
    }
}

fn handle_pull_native(serial: Option<&str>, args: &[String]) -> Option<i32> {
    let Some(remote) = args.first() else {
        eprintln!("adb pull requires REMOTE [LOCAL]");
        return Some(1);
    };
    let local_path = default_pull_local_path(remote, args.get(1).map(String::as_str));

    if should_route_via_mux() {
        return match crate::adb_mux_client::retry_via_server(|| {
            crate::adb_mux_client::pull(serial, remote, &local_path)
        }) {
            Some(Ok(())) => {
                println!("{}: 1 file pulled", remote);
                Some(0)
            }
            Some(Err(e)) => {
                eprintln!("Pull failed: {}", e);
                Some(1)
            }
            None => Some(mux_no_fallback("pull")),
        };
    }

    let mut dev = match open_adb_device_native(serial) {
        Ok(dev) => dev,
        Err(e) => {
            eprintln!("{}", e);
            return Some(1);
        }
    };

    match dev.pull(remote, &local_path.to_string_lossy()) {
        Ok(()) => {
            println!("{}: 1 file pulled", remote);
            Some(0)
        }
        Err(e) => {
            eprintln!("Pull failed: {}", e);
            Some(1)
        }
    }
}

fn handle_install_native(serial: Option<&str>, args: &[String]) -> Option<i32> {
    let Some(apk) = args.last() else {
        eprintln!("adb install requires APK");
        return Some(1);
    };
    if !Path::new(apk).exists() {
        eprintln!("APK does not exist: {}", apk);
        return Some(1);
    }
    let options = &args[..args.len() - 1];
    let result = if should_route_via_mux() {
        crate::adb_install::install(&mut crate::adb_install::MuxConn::new(serial), apk, options)
    } else {
        open_adb_device_native(serial)
            .and_then(|mut dev| crate::adb_install::install(&mut dev, apk, options))
    };
    Some(print_install_result(result))
}

/// `adb install-multiple [opts] <apk...>`：非 `-` 开头的参数按顺序视为 APK，其余是交给
/// install-create 的选项。
fn handle_install_multiple_native(serial: Option<&str>, args: &[String]) -> Option<i32> {
    let apks: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .collect();
    let options: Vec<String> = args
        .iter()
        .filter(|a| a.starts_with('-'))
        .cloned()
        .collect();
    if apks.is_empty() {
        eprintln!("adb install-multiple requires at least one APK");
        return Some(1);
    }
    if let Some(missing) = apks.iter().find(|apk| !Path::new(apk.as_str()).exists()) {
        eprintln!("APK does not exist: {}", missing);
        return Some(1);
    }
    let result = if should_route_via_mux() {
        crate::adb_install::install_multiple(
            &mut crate::adb_install::MuxConn::new(serial),
            &apks,
            &options,
        )
    } else {
        open_adb_device_native(serial)
            .and_then(|mut dev| crate::adb_install::install_multiple(&mut dev, &apks, &options))
    };
    Some(print_install_result(result))
}

fn print_install_result(result: Result<String, String>) -> i32 {
    match result {
        Ok(output) => {
            println!("{}", output);
            let _ = io::stdout().flush();
            0
        }
        Err(e) => {
            eprintln!("{}", e.trim());
            1
        }
    }
}

impl crate::adb_install::InstallConn for AdbDevice {
    fn install_caps(&mut self) -> Result<crate::adb_install::InstallCaps, String> {
        match self {
            Self::Usb(dev) => crate::adb_install::InstallConn::install_caps(dev),
            Self::Tcp(dev) => {
                dev.connect()?;
                Ok(crate::adb_install::InstallCaps::from_features(
                    dev.peer_features(),
                ))
            }
        }
    }

    fn exec_stdin(&mut self, service: &[u8], stdin: &mut dyn io::Read) -> Result<String, String> {
        match self {
            Self::Usb(dev) => crate::adb_install::InstallConn::exec_stdin(dev, service, stdin),
            Self::Tcp(dev) => dev
                .exec_with_stdin(service, stdin)
                .map(|out| String::from_utf8_lossy(&out).into_owned()),
        }
    }

    fn shell(&mut self, command: &str) -> Result<String, String> {
        self.shell_command(command)
    }

    fn push_file(&mut self, local: &str, remote: &str) -> Result<(), String> {
        self.push(local, remote)
    }
}

fn handle_uninstall_native(serial: Option<&str>, args: &[String]) -> Option<i32> {
    if args.is_empty() {
        eprintln!("adb uninstall requires PACKAGE");
        return Some(1);
    }
    let cmd = format!("pm uninstall {}", args.join(" "));

    if should_route_via_mux() {
        return match crate::adb_mux_client::retry_via_server(|| {
            crate::adb_mux_client::capture_shell_result(serial, &cmd)
        }) {
            Some(Ok(output)) => {
                print!("{}", output);
                let _ = io::stdout().flush();
                Some(if output.contains("Success") { 0 } else { 1 })
            }
            Some(Err(e)) => {
                eprintln!("{}", e.trim());
                Some(1)
            }
            None => Some(mux_no_fallback("uninstall")),
        };
    }

    // pm uninstall 失败时退出码常为 0、只在输出里写 Failure：按 "Success" 判成败，与 mux 路径同口径。
    let result = match crate::adb_daemon::capture_shell(serial, &cmd) {
        Some(result) => result,
        None => open_adb_device_native(serial).and_then(|mut dev| dev.shell_command(&cmd)),
    };
    match result {
        Ok(output) => {
            print!("{}", output);
            let _ = io::stdout().flush();
            Some(if output.contains("Success") { 0 } else { 1 })
        }
        Err(e) => {
            eprintln!("{}", e.trim());
            Some(1)
        }
    }
}

fn handle_logcat_native(serial: Option<&str>, args: &[String]) -> Option<i32> {
    let command = if args.is_empty() {
        "logcat".to_string()
    } else {
        format!("logcat {}", args.join(" "))
    };

    if should_route_via_mux() {
        if let Some(code) = crate::adb_mux_client::retry_via_server(|| {
            crate::adb_mux_client::shell_command(serial, &command)
        }) {
            return Some(code);
        }
        return Some(mux_no_fallback("logcat"));
    }

    let mut dev = match open_adb_device_native(serial) {
        Ok(dev) => dev,
        Err(e) => {
            eprintln!("{}", e);
            return Some(1);
        }
    };

    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    match dev.shell_command_streaming(
        &command,
        |b| {
            let _ = stdout.write_all(b);
            let _ = stdout.flush();
        },
        |b| {
            let _ = stderr.write_all(b);
            let _ = stderr.flush();
        },
    ) {
        Ok(exit) => Some(exit.code),
        Err(e) => {
            eprintln!("logcat failed: {}", e);
            Some(1)
        }
    }
}

/// adb reboot 目标归一：AOSP 固定枚举（bootloader/recovery/sideload[-auto-reboot] 等）大小写
/// 不敏感；未知目标原样透传——设备侧 `reboot:<target>` 对厂商私有目标可能大小写敏感。
fn normalize_adb_reboot_target(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    match lower.as_str() {
        ""
        | "bootloader"
        | "recovery"
        | "fastboot"
        | "sideload"
        | "sideload-auto-reboot"
        | "edl"
        | "download" => lower,
        _ => raw.trim().to_string(),
    }
}

fn handle_reboot_native(serial: Option<&str>, args: &[String]) -> Option<i32> {
    let target = normalize_adb_reboot_target(args.first().map(String::as_str).unwrap_or(""));
    let target = target.as_str();
    if should_route_via_mux() {
        let service = if target.is_empty() {
            "reboot:".to_string()
        } else {
            format!("reboot:{}", target)
        };
        return print_mux_service(serial, &service, "reboot");
    }

    if let Some(code) = crate::adb_daemon::run_reboot(serial, target) {
        return Some(code);
    }
    crate::adb_daemon::ensure_released();

    let mut dev = match open_adb_device_native(serial) {
        Ok(dev) => dev,
        Err(e) => {
            eprintln!("{}", e);
            return Some(1);
        }
    };
    match dev.reboot(target) {
        Ok(()) => Some(0),
        Err(e) => {
            eprintln!("Reboot failed: {}", e);
            Some(1)
        }
    }
}

fn handle_root_native(serial: Option<&str>, root: bool) -> Option<i32> {
    if should_route_via_mux() {
        let (service, what) = if root {
            ("root:", "root")
        } else {
            ("unroot:", "unroot")
        };
        return print_mux_service(serial, service, what);
    }

    let service = if root { "root:" } else { "unroot:" };
    if let Some(code) = crate::adb_daemon::run_service(serial, service) {
        return Some(code);
    }
    crate::adb_daemon::ensure_released();

    let mut dev = match open_adb_device_native(serial) {
        Ok(dev) => dev,
        Err(e) => {
            eprintln!("{}", e);
            return Some(1);
        }
    };
    let result = if root { dev.root() } else { dev.unroot() };
    match result {
        Ok(()) => Some(0),
        Err(e) => {
            eprintln!("{}", e);
            Some(1)
        }
    }
}

fn handle_remount_native(serial: Option<&str>, args: &[String]) -> Option<i32> {
    let auto_reboot = args.iter().any(|a| a == "-R");
    let service_args: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| *a != "-R")
        .collect();
    let service = if service_args.is_empty() {
        "remount:".to_string()
    } else {
        format!("remount:{}", service_args.join(" "))
    };

    if should_route_via_mux() {
        let code = print_mux_service(serial, &service, "remount");
        if auto_reboot && code == Some(0) {
            let _ = print_mux_service(serial, "reboot:", "reboot");
        }
        return code;
    }

    if let Some(code) = crate::adb_daemon::run_service(serial, &service) {
        if auto_reboot && code == 0 {
            let _ = crate::adb_daemon::run_reboot(serial, "");
        }
        return Some(code);
    }
    crate::adb_daemon::ensure_released();

    let mut dev = match open_adb_device_native(serial) {
        Ok(dev) => dev,
        Err(e) => {
            eprintln!("{}", e);
            return Some(1);
        }
    };

    let result = print_service(&mut dev, &service);
    if let Err(e) = result {
        eprintln!("remount failed: {}", e);
        return Some(1);
    }
    if auto_reboot {
        let _ = dev.reboot("");
    }
    Some(0)
}

fn handle_tcpip_native(serial: Option<&str>, args: &[String]) -> Option<i32> {
    let Some(port) = args.first() else {
        eprintln!("adb tcpip requires PORT");
        return Some(1);
    };
    if port.parse::<u16>().ok().filter(|p| *p != 0).is_none() {
        eprintln!("invalid tcp port: {}", port);
        return Some(1);
    }

    if should_route_via_mux() {
        return print_mux_service(serial, &format!("tcpip:{}", port), "tcpip");
    }

    let service = format!("tcpip:{}", port);
    if let Some(code) = crate::adb_daemon::run_service(serial, &service) {
        return Some(code);
    }
    crate::adb_daemon::ensure_released();

    let mut dev = match open_adb_device_native(serial) {
        Ok(dev) => dev,
        Err(e) => {
            eprintln!("{}", e);
            return Some(1);
        }
    };
    match print_service(&mut dev, &service) {
        Ok(()) => Some(0),
        Err(e) => {
            eprintln!("tcpip failed: {}", e);
            Some(1)
        }
    }
}

fn handle_usb_native(serial: Option<&str>) -> Option<i32> {
    if should_route_via_mux() {
        return print_mux_service(serial, "usb:", "usb");
    }

    if let Some(code) = crate::adb_daemon::run_service(serial, "usb:") {
        return Some(code);
    }
    crate::adb_daemon::ensure_released();

    let mut dev = match open_adb_device_native(serial) {
        Ok(dev) => dev,
        Err(e) => {
            eprintln!("{}", e);
            return Some(1);
        }
    };
    match print_service(&mut dev, "usb:") {
        Ok(()) => Some(0),
        Err(e) => {
            eprintln!("usb failed: {}", e);
            Some(1)
        }
    }
}

fn handle_bugreport_native(serial: Option<&str>, args: &[String]) -> Option<i32> {
    if args.len() > 1 {
        eprintln!("adb bugreport accepts at most one PATH");
        return Some(1);
    }
    // 5037 上有 server（GUI 进程内 mux / 投屏 mux / 官方 adb）时借道执行，
    // 直连会与其争用 WinUSB 句柄（CreateFileW 0x80070005）。
    if should_route_via_mux() {
        return handle_bugreport_mux(serial, args);
    }
    let mut dev = match open_adb_device_native(serial) {
        Ok(dev) => dev,
        Err(e) => {
            eprintln!("{}", e);
            return Some(1);
        }
    };

    match dev.shell_command("bugreportz -p") {
        Ok(output) => {
            print!("{}", output);
            if let Some(remote) = parse_bugreportz_path(&output) {
                let local = default_bugreport_local_path(&remote, args.first().map(String::as_str));
                match dev.pull(&remote, &local.to_string_lossy()) {
                    Ok(()) => {
                        let _ = dev.shell_command(&format!("rm -f {}", shell_quote(&remote)));
                        println!("Bug report copied to {}", local.display());
                        Some(0)
                    }
                    Err(e) => {
                        eprintln!("bugreport pull failed: {}", e);
                        Some(1)
                    }
                }
            } else {
                stream_legacy_bugreport(dev, args.first().map(String::as_str))
            }
        }
        Err(_) => stream_legacy_bugreport(dev, args.first().map(String::as_str)),
    }
}

/// bugreport 的借道版：`bugreportz -p` 拿远端 zip 路径 → mux pull 回本地 → 清理远端文件。
/// 旧机型（无 bugreportz）的纯流式 bugreport 需要专用长流，借道场景下如实报错不回退直连。
fn handle_bugreport_mux(serial: Option<&str>, args: &[String]) -> Option<i32> {
    let output = match crate::adb_mux_client::retry_via_server(|| {
        crate::adb_mux_client::capture_shell_result(serial, "bugreportz -p")
    }) {
        Some(Ok(out)) => out,
        Some(Err(e)) => {
            eprintln!("{}", e.trim());
            return Some(1);
        }
        None => return Some(mux_no_fallback("bugreport")),
    };
    print!("{}", output);
    let _ = io::stdout().flush();

    let Some(remote) = parse_bugreportz_path(&output) else {
        eprintln!("bugreport: 设备不支持 bugreportz；5037 server 在位时暂不支持旧式流式 bugreport");
        return Some(1);
    };
    let local = default_bugreport_local_path(&remote, args.first().map(String::as_str));
    match crate::adb_mux_client::retry_via_server(|| {
        crate::adb_mux_client::pull(serial, &remote, &local)
    }) {
        Some(Ok(())) => {
            let cleanup = format!("rm -f {}", shell_quote(&remote));
            let _ = crate::adb_mux_client::retry_via_server(|| {
                crate::adb_mux_client::capture_shell_result(serial, &cleanup)
            });
            println!("Bug report copied to {}", local.display());
            Some(0)
        }
        Some(Err(e)) => {
            eprintln!("bugreport pull failed: {}", e);
            Some(1)
        }
        None => Some(mux_no_fallback("bugreport")),
    }
}

fn handle_sideload_native(serial: Option<&str>, args: &[String]) -> Option<i32> {
    let Some(package) = args.first() else {
        eprintln!("adb sideload requires PACKAGE");
        return Some(1);
    };
    if args.len() > 1 {
        eprintln!("adb sideload accepts exactly one PACKAGE");
        return Some(1);
    }
    if !Path::new(package).is_file() {
        eprintln!("sideload package does not exist: {}", package);
        return Some(1);
    }

    let mut dev = match open_adb_device_native(serial) {
        Ok(dev) => dev,
        Err(e) => {
            eprintln!("{}", e);
            return Some(1);
        }
    };

    match dev.sideload(package) {
        Ok(()) => Some(0),
        Err(e) => {
            eprintln!("sideload failed: {}", e);
            Some(1)
        }
    }
}

fn stream_legacy_bugreport(mut dev: AdbDevice, target: Option<&str>) -> Option<i32> {
    let mut file = match target {
        Some(path) => match fs::File::create(path) {
            Ok(file) => Some(file),
            Err(e) => {
                eprintln!("failed to create bugreport file '{}': {}", path, e);
                return Some(1);
            }
        },
        None => None,
    };
    let mut stderr = io::stderr();
    let result = dev.shell_command_streaming(
        "bugreport",
        |b| {
            if let Some(f) = file.as_mut() {
                let _ = f.write_all(b);
            } else {
                let _ = io::stdout().write_all(b);
                let _ = io::stdout().flush();
            }
        },
        |b| {
            let _ = stderr.write_all(b);
            let _ = stderr.flush();
        },
    );
    match result {
        Ok(exit) => Some(exit.code),
        Err(e) => {
            eprintln!("bugreport failed: {}", e);
            Some(1)
        }
    }
}

fn parse_bugreportz_path(output: &str) -> Option<String> {
    output
        .lines()
        .rev()
        .find_map(|line| {
            line.strip_prefix("OK:")
                .or_else(|| line.strip_prefix("BEGIN:"))
        })
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn default_bugreport_local_path(remote: &str, target: Option<&str>) -> PathBuf {
    let filename = remote
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("bugreport.zip");
    match target {
        Some(path) if Path::new(path).is_dir() => Path::new(path).join(filename),
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(filename),
    }
}

fn handle_sync_native(serial: Option<&str>, args: &[String]) -> Option<i32> {
    let mut dry_run = false;
    let mut list_only = false;
    let mut partitions = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-n" => dry_run = true,
            "-l" => list_only = true,
            "-z" => i += 1,
            "-Z" => {}
            arg if arg.starts_with('-') => {}
            arg => partitions.push(arg.to_string()),
        }
        i += 1;
    }

    let product_out = match env::var_os("ANDROID_PRODUCT_OUT").map(PathBuf::from) {
        Some(path) if path.is_dir() => path,
        _ => {
            eprintln!("adb sync requires ANDROID_PRODUCT_OUT to point to a build output directory");
            return Some(1);
        }
    };

    let partitions = resolve_sync_partitions(&product_out, &partitions);
    if partitions.is_empty() {
        eprintln!("No sync partitions found under {}", product_out.display());
        return Some(1);
    }

    let mut dev = match open_adb_device_native(serial) {
        Ok(dev) => dev,
        Err(e) => {
            eprintln!("{}", e);
            return Some(1);
        }
    };

    let mut total = 0usize;
    for partition in partitions {
        let local = product_out.join(&partition);
        let remote = format!("/{}", partition);
        match push_path_recursive(&mut dev, &local, &remote, dry_run || list_only) {
            Ok(count) => {
                total += count;
                println!(
                    "{}: {} file{} {}",
                    partition,
                    count,
                    plural_s(count),
                    if dry_run || list_only {
                        "listed"
                    } else {
                        "synced"
                    }
                );
            }
            Err(e) => {
                eprintln!("sync {} failed: {}", partition, e);
                return Some(1);
            }
        }
    }
    println!("Total: {} file{}", total, plural_s(total));
    Some(0)
}

fn resolve_sync_partitions(product_out: &Path, requested: &[String]) -> Vec<String> {
    let defaults = [
        "system",
        "system_ext",
        "vendor",
        "product",
        "odm",
        "oem",
        "data",
    ];
    let wanted: Vec<String> = if requested.is_empty() || requested.iter().any(|p| p == "all") {
        defaults.iter().map(|s| s.to_string()).collect()
    } else {
        requested.to_vec()
    };
    wanted
        .into_iter()
        .filter(|partition| product_out.join(partition).exists())
        .collect()
}

fn push_path_recursive(
    dev: &mut AdbDevice,
    local: &Path,
    remote: &str,
    dry_run: bool,
) -> Result<usize, String> {
    if local.is_file() {
        let remote_file = remote_path_for_single_file(local, remote);
        if dry_run {
            println!("{} -> {}", local.display(), remote_file);
            return Ok(1);
        }
        ensure_remote_parent(dev, &remote_file)?;
        dev.push(&local.to_string_lossy(), &remote_file)?;
        return Ok(1);
    }

    if !local.is_dir() {
        return Err(format!(
            "local path is not a file or directory: {}",
            local.display()
        ));
    }

    let mut count = 0usize;
    for entry in WalkDir::new(local).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(local)
            .map_err(|e| format!("failed to compute relative path: {}", e))?;
        let remote_file = format!(
            "{}/{}",
            remote.trim_end_matches('/'),
            path_to_adb(rel).trim_start_matches('/')
        );
        if dry_run {
            println!("{} -> {}", entry.path().display(), remote_file);
        } else {
            ensure_remote_parent(dev, &remote_file)?;
            dev.push(&entry.path().to_string_lossy(), &remote_file)?;
        }
        count += 1;
    }
    Ok(count)
}

fn remote_path_for_single_file(local: &Path, remote: &str) -> String {
    if remote.ends_with('/') {
        let name = local
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("adb-push-file");
        format!("{}{}", remote, name)
    } else {
        remote.to_string()
    }
}

fn ensure_remote_parent(dev: &mut AdbDevice, remote_file: &str) -> Result<(), String> {
    let Some(parent) = remote_file
        .rsplit_once('/')
        .map(|(p, _)| p)
        .filter(|p| !p.is_empty())
    else {
        return Ok(());
    };
    let _ = dev.shell_command(&format!("mkdir -p {}", shell_quote(parent)));
    Ok(())
}

fn path_to_adb(path: &Path) -> String {
    path.components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect::<Vec<_>>()
        .join("/")
}

fn plural_s(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

/// CLI 侧 mux 路由条件：显式开关 `RMF_ADB_MUX=1`，或 5037 上有 server 在听。
/// 判据是「设备句柄归谁」而非「投屏开没开」——mux server 或官方 adb server 都独占 WinUSB
/// 句柄且说同一套 host 协议，借道才走得通，直连只会撞 0x80070005。
fn should_route_via_mux() -> bool {
    crate::adb_mux_server::ensure_mux_server_if_enabled();
    crate::adb_mux_client::is_mux_enabled() || crate::adb_mux_client::device_owned_by_adb_server()
}

fn print_mux_text_result(result: Option<Result<String, String>>, what: &str) -> Option<i32> {
    match result {
        Some(Ok(output)) => {
            print!("{}", output);
            let _ = io::stdout().flush();
            Some(0)
        }
        Some(Err(e)) => {
            eprintln!("{}", e.trim());
            Some(1)
        }
        None => Some(mux_no_fallback(what)),
    }
}

fn print_mux_service(serial: Option<&str>, service: &str, what: &str) -> Option<i32> {
    print_mux_text_result(
        crate::adb_mux_client::retry_via_server(|| {
            crate::adb_mux_client::capture_service(serial, service)
        }),
        what,
    )
}

fn handle_get_state_native(serial: Option<&str>) -> Option<i32> {
    if should_route_via_mux() {
        if let Some(state) =
            crate::adb_mux_client::retry_via_server(|| crate::adb_mux_client::get_state(serial))
        {
            let state = state.trim();
            println!("{}", state);
            return Some(if state == "device" { 0 } else { 1 });
        }
        return Some(mux_no_fallback("get-state"));
    }

    let mut dev = match open_adb_device_native(serial) {
        Ok(dev) => dev,
        Err(_) => {
            println!("unknown");
            return Some(1);
        }
    };
    match dev.connect() {
        Ok(()) => {
            println!("device");
            Some(0)
        }
        Err(_) => {
            println!("unknown");
            Some(1)
        }
    }
}

fn handle_wait_for_native(serial: Option<&str>, command: &str) -> Option<i32> {
    // This polling path can observe the ADB transport only.  Do not silently
    // treat `wait-for-bootloader`/`recovery` as “device ready”: official adb
    // distinguishes those states, and returning early would make scripts run
    // against the wrong mode.
    let suffix = command.strip_prefix("wait-for-").unwrap_or_default();
    let mut pieces = suffix.split('-');
    let first = pieces.next().unwrap_or_default();
    let state = if matches!(first, "usb" | "local" | "any" | "transport") {
        pieces.next().unwrap_or_default()
    } else {
        first
    };
    if !matches!(state, "device" | "disconnect") {
        eprintln!(
            "adb {}: only device/disconnect waits are supported by the USB/TCP backend",
            command
        );
        return Some(1);
    }
    let wait_disconnect = state == "disconnect";
    let timeout_ms = env::var("RMF_ADB_WAIT_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_WAIT_TIMEOUT_MS);
    let deadline = if timeout_ms == 0 {
        None
    } else {
        Some(Instant::now() + Duration::from_millis(timeout_ms))
    };

    loop {
        let ready = probe_adb_ready(serial);
        if (wait_disconnect && !ready) || (!wait_disconnect && ready) {
            return Some(0);
        }
        if let Some(deadline) = deadline {
            if Instant::now() >= deadline {
                eprintln!("{} timed out", command);
                return Some(1);
            }
        }
        thread::sleep(Duration::from_millis(WAIT_POLL_MS));
    }
}

fn probe_adb_ready(serial: Option<&str>) -> bool {
    if should_route_via_mux() {
        return crate::adb_mux_client::retry_via_server(|| {
            crate::adb_mux_client::get_state(serial)
        })
        .map(|state| state.trim() == "device")
        .unwrap_or(false);
    }

    if let Some(serial) = serial.filter(|s| !s.is_empty()) {
        if let Ok(endpoint) = normalize_endpoint(serial) {
            let normalized = endpoint.serial();
            if load_tcp_devices().iter().any(|s| s == &normalized) || serial.contains(':') {
                return AdbTcpDevice::open(endpoint)
                    .and_then(|mut dev| dev.connect_probe())
                    .unwrap_or(false);
            }
        }
    }

    let usb_ready = AdbWinUsbDevice::enumerate()
        .unwrap_or_default()
        .into_iter()
        .filter(|info| {
            serial
                .map(|s| serial_from_path(&info.device_path) == s)
                .unwrap_or(true)
        })
        .any(|info| {
            AdbWinUsbDevice::open_device(&info.device_path)
                .and_then(|mut dev| {
                    dev.connect_probe(5_000)
                        .map_err(crate::error::TransportError::Usb)
                })
                .unwrap_or(false)
        });
    if usb_ready {
        return true;
    }

    if serial.is_none() {
        return tcp_candidates().into_iter().any(|endpoint| {
            AdbTcpDevice::connect_endpoint(&endpoint)
                .and_then(|mut dev| dev.connect_probe())
                .unwrap_or(false)
        });
    }

    false
}

fn handle_shell(serial: Option<&str>, args: &[String]) -> Option<i32> {
    let mut dev = match open_adb_device_native(serial) {
        Ok(dev) => dev,
        Err(e) => {
            eprintln!("{}", e);
            return Some(1);
        }
    };

    if args.is_empty() {
        match dev {
            AdbDevice::Usb(mut usb) => {
                if let Err(e) = usb.true_pty_shell() {
                    eprintln!("Terminal error: {}", e);
                    return Some(1);
                }
                return Some(0);
            }
            AdbDevice::Tcp(mut tcp) => {
                if let Err(e) = tcp.interactive_shell() {
                    eprintln!("Terminal error: {}", e);
                    return Some(1);
                }
                return Some(0);
            }
        }
    }

    let cmd_string = args.join(" ");
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    match dev.shell_command_streaming(
        &cmd_string,
        |b| {
            let _ = stdout.write_all(b);
        },
        |b| {
            let _ = stderr.write_all(b);
        },
    ) {
        Ok(exit) => {
            let _ = stdout.flush();
            let _ = stderr.flush();
            Some(exit.code)
        }
        Err(e) => {
            eprintln!("Command failed: {}", e);
            Some(1)
        }
    }
}

fn handle_connect_native(args: &[String]) -> Option<i32> {
    let Some(target) = args.first() else {
        eprintln!("adb connect requires HOST[:PORT]");
        return Some(1);
    };
    let endpoint = match normalize_endpoint(target) {
        Ok(endpoint) => endpoint,
        Err(e) => {
            eprintln!("{}", e);
            return Some(1);
        }
    };
    let serial = endpoint.serial();
    match AdbTcpDevice::open(endpoint).and_then(|mut dev| {
        dev.connect()?;
        Ok(dev)
    }) {
        Ok(_) => {
            if let Err(e) = add_tcp_device(&serial) {
                eprintln!("{}", e);
                return Some(1);
            }
            println!("connected to {}", serial);
            Some(0)
        }
        Err(e) => {
            eprintln!("failed to connect to {}: {}", serial, e);
            Some(1)
        }
    }
}

fn handle_disconnect_native(args: &[String]) -> Option<i32> {
    if args.is_empty() || args.first().is_some_and(|a| a.eq_ignore_ascii_case("all")) {
        let records = load_tcp_devices();
        let _ = save_tcp_devices(&[]);
        if records.is_empty() {
            println!("no tcp adb devices connected");
        } else {
            println!("disconnected everything");
        }
        return Some(0);
    }

    let endpoint = match normalize_endpoint(&args[0]) {
        Ok(endpoint) => endpoint.serial(),
        Err(e) => {
            eprintln!("{}", e);
            return Some(1);
        }
    };
    let mut records = load_tcp_devices();
    let before = records.len();
    records.retain(|item| item != &endpoint);
    if records.len() == before {
        eprintln!("no such device {}", endpoint);
        return Some(1);
    }
    match save_tcp_devices(&records) {
        Ok(()) => {
            println!("disconnected {}", endpoint);
            Some(0)
        }
        Err(e) => {
            eprintln!("{}", e);
            Some(1)
        }
    }
}

fn print_service(dev: &mut AdbDevice, service: &str) -> Result<(), String> {
    let mut stdout = io::stdout();
    dev.execute_service_streaming(service, |payload| {
        stdout
            .write_all(payload)
            .map_err(|e| format!("failed to write service output: {}", e))?;
        stdout
            .flush()
            .map_err(|e| format!("failed to flush service output: {}", e))?;
        Ok(())
    })
}

fn tcp_registry_path() -> PathBuf {
    let base = env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir);
    base.join("rmf-adb-fastboot").join("adb-tcp-devices.tsv")
}

fn load_tcp_devices() -> Vec<String> {
    let Ok(text) = fs::read_to_string(tcp_registry_path()) else {
        return Vec::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| normalize_endpoint(line).ok().map(|ep| ep.serial()))
        .fold(Vec::<String>::new(), |mut acc, serial| {
            if !acc.iter().any(|s| s == &serial) {
                acc.push(serial);
            }
            acc
        })
}

fn save_tcp_devices(records: &[String]) -> Result<(), String> {
    let path = tcp_registry_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create adb tcp registry: {}", e))?;
    }
    let mut text = String::new();
    for record in records {
        text.push_str(record);
        text.push('\n');
    }
    fs::write(path, text).map_err(|e| format!("failed to write adb tcp registry: {}", e))
}

fn add_tcp_device(serial: &str) -> Result<(), String> {
    let mut records = load_tcp_devices();
    if !records.iter().any(|s| s == serial) {
        records.push(serial.to_string());
    }
    save_tcp_devices(&records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_adb_args_preserves_serial() {
        let parsed = parse_adb_args(vec![
            "-s".into(),
            "ABC123".into(),
            "shell".into(),
            "id".into(),
        ]);

        assert_eq!(parsed.serial.as_deref(), Some("ABC123"));
        assert_eq!(parsed.args, vec!["shell", "id"]);
    }

    #[test]
    fn parse_adb_args_keeps_command_after_device_flags() {
        let parsed = parse_adb_args(vec!["-d".into(), "devices".into()]);
        assert_eq!(parsed.selector, AdbSelector::UsbOnly);
        assert_eq!(parsed.args, vec!["devices"]);

        let parsed = parse_adb_args(vec![
            "-e".into(),
            "shell".into(),
            "echo".into(),
            "ok".into(),
        ]);
        assert_eq!(parsed.selector, AdbSelector::EmulatorOnly);
        assert_eq!(parsed.args, vec!["shell", "echo", "ok"]);
    }

    #[test]
    fn backup_service_escapes_args_and_extracts_output_file() {
        let (svc, file) =
            backup_service(&["-f".into(), "my.ab".into(), "-apk".into(), "com.a'b".into()])
                .unwrap();
        assert_eq!(file, "my.ab");
        assert_eq!(svc, "backup: '-apk' 'com.a'\\''b'");
        let (svc, file) = backup_service(&[]).unwrap();
        assert_eq!((svc.as_str(), file.as_str()), ("backup:", "backup.ab"));
        assert!(backup_service(&["-f".into()]).is_err());
    }

    #[test]
    fn emulator_selector_only_spares_host_commands() {
        assert!(command_is_host_only("devices"));
        assert!(command_is_host_only("keygen"));
        assert!(!command_is_host_only("shell"));
        assert!(!command_is_host_only("reboot"));
    }

    #[test]
    fn default_pull_local_path_uses_remote_filename() {
        assert_eq!(
            default_pull_local_path("/sdcard/Download/a.txt", None),
            PathBuf::from("a.txt")
        );
    }

    #[test]
    fn default_bugreport_path_uses_remote_filename() {
        assert_eq!(
            default_bugreport_local_path("/bugreports/bugreport-demo.zip", None),
            PathBuf::from("bugreport-demo.zip")
        );
    }

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(
            shell_quote("/data/local/tmp/a'b.apk"),
            "'/data/local/tmp/a'\\''b.apk'"
        );
    }

    #[test]
    fn path_to_adb_uses_forward_slashes() {
        assert_eq!(
            path_to_adb(Path::new("a").join("b.txt").as_path()),
            "a/b.txt"
        );
    }

    #[test]
    fn parse_bugreportz_path_reads_ok_line() {
        assert_eq!(
            parse_bugreportz_path("BEGIN:/bugreports/a.zip\nOK:/bugreports/b.zip\n").as_deref(),
            Some("/bugreports/b.zip")
        );
    }

    #[test]
    fn adb_reboot_target_fixed_enums_are_case_insensitive() {
        // 「ADB REBOOT BOOTLOADER」「Adb REboot bootlOAdER」的 target 部分。
        assert_eq!(normalize_adb_reboot_target("BOOTLOADER"), "bootloader");
        assert_eq!(normalize_adb_reboot_target("bootlOAdER"), "bootloader");
        assert_eq!(normalize_adb_reboot_target("Recovery"), "recovery");
        assert_eq!(normalize_adb_reboot_target("EDL"), "edl");
        assert_eq!(
            normalize_adb_reboot_target("Sideload-Auto-Reboot"),
            "sideload-auto-reboot"
        );
        assert_eq!(normalize_adb_reboot_target(""), "");
        // 未知目标原样透传，不改大小写。
        assert_eq!(normalize_adb_reboot_target("VendorMode"), "VendorMode");
    }

    #[test]
    fn adb_args_keep_free_params_untouched_after_keyword() {
        // 关键字归一在 try_handle_adb_args 内做（args[0].to_ascii_lowercase）；
        // parse_adb_args 本身不得改写任何 token 的大小写。
        let parsed = parse_adb_args(vec![
            "-s".into(),
            "AbCdEf".into(),
            "PUSH".into(),
            r"C:\Data\File.TXT".into(),
            "/sdcard/File.TXT".into(),
        ]);
        assert_eq!(parsed.serial.as_deref(), Some("AbCdEf"));
        assert_eq!(
            parsed.args,
            vec!["PUSH", r"C:\Data\File.TXT", "/sdcard/File.TXT"]
        );
        assert_eq!(parsed.args[0].to_ascii_lowercase(), "push");
    }
}
