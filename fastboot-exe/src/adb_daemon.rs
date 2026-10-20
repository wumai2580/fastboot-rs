//! 轻量 ADB 复用守护进程（可选，Windows 命名管道）。每条 adb 子命令独立进程直连都要重复
//! enumerate→open→握手（连续命令慢的根因）；仿官方常驻 server 思路但走命名管道（用户态、有 ACL、
//! 无端口/防火墙弹窗）：首条命令拉起 daemon 建连一次常驻，后续命令经管道在同一连接上执行并流回输出。
//! 要点：单一拥有者——任一时刻只有 daemon 持有该连接，要直连设备必须先 [`ensure_released`]；
//! 仅确认 daemon 不存在/已死才回退直连（daemon 的退出码是权威结果）；空闲超阈值（默认 30s）
//! 或设备拔出即自退；`RMF_ADB_DAEMON=0` 显式关闭。本模块仅 Windows 下编译。

use crate::adb_winusb_transport::{serial_from_path, AdbWinUsbDevice};
use std::ffi::OsStr;
use std::io::Write;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::shared::winerror::{ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{CreateFileW, FlushFileBuffers, ReadFile, WriteFile, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::namedpipeapi::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, WaitNamedPipeW,
};
use winapi::um::processthreadsapi::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
use winapi::um::winbase::{
    CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, DETACHED_PROCESS, FILE_FLAG_FIRST_PIPE_INSTANCE,
    PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE, HANDLE};

// ---- 协议帧类型（daemon → client）----
const KIND_STDOUT: u8 = 1;
const KIND_STDERR: u8 = 2;
const KIND_EXIT: u8 = 3;

/// 哨兵退出码：daemon 无法权威处理（未授权/无设备/建连 IO 错）时示意客户端回退直连——
/// 直连能弹授权框，且此时尚未向设备下发命令、回退不会重复执行。取正常退出码绝不会出现的值。
const EXIT_FALLBACK: i32 = i32::MIN;

/// daemon 建连探测的读超时：探测只做几次 USB 往返（CNXN/AUTH/签名），毫秒级即完成；
/// 给 5s 冗余以容忍慢设备，同时保证未授权设备也能快速判定、绝不触发 180s 授权等待。
const CONNECT_PROBE_TIMEOUT_MS: u32 = 5_000;

// ---- 请求动词（client → daemon）----
const VERB_DEVICES: &[u8] = b"devices";
const VERB_SHELL: &[u8] = b"shell";
const VERB_SERVICE: &[u8] = b"service";
const VERB_REBOOT: &[u8] = b"reboot";
const VERB_RELEASE: &[u8] = b"release";

// 防御性上限：拒绝异常的超大 argc / 帧长，避免 daemon 侧巨额分配。
const MAX_ARGS: u32 = 64;
const MAX_FRAME_LEN: u32 = 64 * 1024 * 1024;

const DEFAULT_IDLE_MS: u64 = 30_000;

/// 守护进程被拉起时携带的隐藏参数。
pub const DAEMON_ARG: &str = "--adb-daemon";

/// daemon 功能是否开启（默认开启；仅 `RMF_ADB_DAEMON=0/false/off/no` 显式关闭）。
pub fn daemon_enabled() -> bool {
    match std::env::var("RMF_ADB_DAEMON") {
        Ok(v) => {
            let v = v.trim();
            // 默认开启：仅显式关闭值才回退「每命令直连」；未设置/空值/其它值一律视为开启。
            !(v == "0"
                || v.eq_ignore_ascii_case("false")
                || v.eq_ignore_ascii_case("off")
                || v.eq_ignore_ascii_case("no"))
        }
        Err(_) => true,
    }
}

/// 当前进程是否是被拉起的 daemon（argv 含 `--adb-daemon`）。
pub fn is_daemon_process() -> bool {
    std::env::args().any(|a| a == DAEMON_ARG)
}

fn idle_ms() -> u64 {
    std::env::var("RMF_ADB_DAEMON_IDLE_MS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|v| *v >= 2_000)
        .unwrap_or(DEFAULT_IDLE_MS)
}

/// 命名管道名（按用户名隔离，避免同机多用户/多会话串管道）。
fn pipe_name() -> String {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string());
    let user: String = user
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!(r"\\.\pipe\rmf-adb-daemon-v1-{}", user)
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 句柄 RAII 守卫：Drop 时 CloseHandle。仅在本模块内跨函数传递句柄用。
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

// ============================ 低层帧 IO ============================

fn write_all(h: HANDLE, mut buf: &[u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        let mut written: DWORD = 0;
        let ok = unsafe {
            WriteFile(
                h,
                buf.as_ptr() as *const _,
                buf.len() as DWORD,
                &mut written,
                ptr::null_mut(),
            )
        };
        if ok == FALSE || written == 0 {
            return Err(std::io::Error::last_os_error());
        }
        buf = &buf[written as usize..];
    }
    Ok(())
}

fn read_full(h: HANDLE, buf: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let mut read: DWORD = 0;
        let ok = unsafe {
            ReadFile(
                h,
                buf[filled..].as_mut_ptr() as *mut _,
                (buf.len() - filled) as DWORD,
                &mut read,
                ptr::null_mut(),
            )
        };
        if ok == FALSE || read == 0 {
            return Err(std::io::Error::last_os_error());
        }
        filled += read as usize;
    }
    Ok(())
}

fn write_u32(h: HANDLE, v: u32) -> std::io::Result<()> {
    write_all(h, &v.to_le_bytes())
}

fn read_u32(h: HANDLE) -> std::io::Result<u32> {
    let mut b = [0u8; 4];
    read_full(h, &mut b)?;
    Ok(u32::from_le_bytes(b))
}

/// 请求编码：`[u32 argc]`，随后每个参数 `[u32 len][bytes]`。args[0]=动词。
fn write_request(h: HANDLE, args: &[&[u8]]) -> std::io::Result<()> {
    write_u32(h, args.len() as u32)?;
    for a in args {
        write_u32(h, a.len() as u32)?;
        write_all(h, a)?;
    }
    Ok(())
}

fn read_request(h: HANDLE) -> std::io::Result<Vec<Vec<u8>>> {
    let argc = read_u32(h)?;
    if argc > MAX_ARGS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "参数过多",
        ));
    }
    let mut out = Vec::with_capacity(argc as usize);
    for _ in 0..argc {
        let len = read_u32(h)?;
        if len > MAX_FRAME_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "参数过长",
            ));
        }
        let mut buf = vec![0u8; len as usize];
        read_full(h, &mut buf)?;
        out.push(buf);
    }
    Ok(out)
}

/// 响应帧：`[u8 kind][u32 len][payload]`。
fn write_frame(h: HANDLE, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    write_all(h, &[kind])?;
    write_u32(h, payload.len() as u32)?;
    write_all(h, payload)
}

enum Frame {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(i32),
}

fn read_frame(h: HANDLE) -> std::io::Result<Frame> {
    let mut kind = [0u8; 1];
    read_full(h, &mut kind)?;
    let len = read_u32(h)?;
    if len > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "帧过长",
        ));
    }
    let mut payload = vec![0u8; len as usize];
    read_full(h, &mut payload)?;
    match kind[0] {
        KIND_STDOUT => Ok(Frame::Stdout(payload)),
        KIND_STDERR => Ok(Frame::Stderr(payload)),
        KIND_EXIT => {
            let code = if payload.len() >= 4 {
                i32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]])
            } else {
                0
            };
            Ok(Frame::Exit(code))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "未知帧类型",
        )),
    }
}

// ============================ 客户端 ============================

/// 打开到 daemon 的管道连接。`spawn_if_absent` 时若管道不存在则拉起 daemon 并等待其就绪。
/// 只在「确实连不上」时返回 None（此时调用方可安全回退直连）。
fn client_connect(spawn_if_absent: bool) -> Option<Handle> {
    let name = wide(&pipe_name());
    // 拉起场景给足预算覆盖冷启动（实测 ~0.2s）；纯 release 探测则短等即可，管道不在就立刻放手。
    let budget = if spawn_if_absent {
        Duration::from_millis(4000)
    } else {
        Duration::from_millis(400)
    };
    let deadline = Instant::now() + budget;
    let mut spawned = false;

    loop {
        let h = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null_mut(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };
        if h != INVALID_HANDLE_VALUE {
            return Some(Handle(h));
        }

        let err = unsafe { GetLastError() };
        if err == ERROR_PIPE_BUSY {
            // 有实例但都在忙：等一个空闲实例。
            unsafe {
                WaitNamedPipeW(name.as_ptr(), 300);
            }
        } else if err == ERROR_FILE_NOT_FOUND {
            // 管道不存在：需要拉起 daemon。
            if !spawn_if_absent {
                return None;
            }
            if !spawned {
                spawn_daemon();
                spawned = true;
            }
            std::thread::sleep(Duration::from_millis(30));
        } else {
            // 其它错误：短暂退避再试。
            if !spawn_if_absent {
                return None;
            }
            std::thread::sleep(Duration::from_millis(30));
        }

        if Instant::now() >= deadline {
            return None;
        }
    }
}

/// 拉起 detached 的 daemon 进程（无窗口、独立进程组，父进程退出后继续存活）。
/// 特意用 `CreateProcessW` 而非 `std::process::Command`：后者持有子进程句柄、stdio 继承语义
/// 会卡住客户端退出（实测冷启动多花数秒）；此处 bInheritHandles=FALSE + DETACHED_PROCESS，
/// 创建后立刻关闭进程/线程句柄彻底放手。
fn spawn_daemon() {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    // 命令行： "<exe>" --adb-daemon （可执行路径加引号以容忍空格）。
    let cmdline = format!("\"{}\" {}", exe.display(), DAEMON_ARG);
    let mut cmdline_w = wide(&cmdline);

    unsafe {
        let mut si: STARTUPINFOW = mem::zeroed();
        si.cb = mem::size_of::<STARTUPINFOW>() as DWORD;
        let mut pi: PROCESS_INFORMATION = mem::zeroed();

        let ok = CreateProcessW(
            ptr::null(),
            cmdline_w.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            FALSE, // bInheritHandles=FALSE：不继承客户端句柄，避免客户端退出被吊住。
            DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
            ptr::null_mut(),
            ptr::null(),
            &mut si,
            &mut pi,
        );
        if ok != FALSE {
            // 我们不 wait daemon；立即关闭句柄放手（daemon 继续独立运行）。
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }
}

/// 发送一个请求并把响应帧泵到回调，直到收到 EXIT。
/// 返回 `Some(code)`：daemon 已处理（权威结果，不应回退）；
/// 返回 `None`：连接建立或 IO 失败（daemon 不存在/已死），调用方可安全回退直连。
fn send_and_pump<FO, FE>(args: &[&[u8]], mut on_out: FO, mut on_err: FE) -> Option<i32>
where
    FO: FnMut(&[u8]),
    FE: FnMut(&[u8]),
{
    let pipe = client_connect(true)?;
    if write_request(pipe.0, args).is_err() {
        // 半死的 daemon：确保其彻底释放后再让调用方回退。
        drop(pipe);
        best_effort_release();
        return None;
    }
    loop {
        match read_frame(pipe.0) {
            Ok(Frame::Stdout(b)) => on_out(&b),
            Ok(Frame::Stderr(b)) => on_err(&b),
            // daemon 示意「我处理不了这条，请回退直连」（未授权/无设备等，尚未下发命令）。
            Ok(Frame::Exit(EXIT_FALLBACK)) => return None,
            Ok(Frame::Exit(code)) => return Some(code),
            Err(_) => {
                drop(pipe);
                best_effort_release();
                return None;
            }
        }
    }
}

fn stdout_sink(b: &[u8]) {
    let mut so = std::io::stdout();
    let _ = so.write_all(b);
    let _ = so.flush();
}

fn stderr_sink(b: &[u8]) {
    let mut se = std::io::stderr();
    let _ = se.write_all(b);
    let _ = se.flush();
}

/// `adb devices`：经 daemon 输出设备列表。None → 回退原生实现。
pub fn run_devices() -> Option<i32> {
    if !daemon_enabled() {
        return None;
    }
    send_and_pump(&[VERB_DEVICES], stdout_sink, stderr_sink)
}

/// `adb shell <cmd>` 单条命令：经 daemon 执行并把输出流回 stdout。None → 回退直连。
pub fn run_shell(serial: Option<&str>, cmd: &str) -> Option<i32> {
    if !daemon_enabled() {
        return None;
    }
    let serial = serial.unwrap_or("");
    send_and_pump(
        &[VERB_SHELL, serial.as_bytes(), cmd.as_bytes()],
        stdout_sink,
        stderr_sink,
    )
}

/// `adb reboot [target]`：经 daemon 当前持有的 ADB 连接下发，避免命令行另开 WinUSB 句柄。
pub fn run_reboot(serial: Option<&str>, target: &str) -> Option<i32> {
    if !daemon_enabled() {
        return None;
    }
    let serial = serial.unwrap_or("");
    send_and_pump(
        &[VERB_REBOOT, serial.as_bytes(), target.as_bytes()],
        stdout_sink,
        stderr_sink,
    )
}

/// 一次性 ADB service（root/remount/tcpip/usb 等）：复用 daemon 的单一 USB owner。
pub fn run_service(serial: Option<&str>, service: &str) -> Option<i32> {
    if !daemon_enabled() {
        return None;
    }
    let serial = serial.unwrap_or("");
    let mut output = Vec::new();
    let mut error = Vec::new();
    let code = send_and_pump(
        &[VERB_SERVICE, serial.as_bytes(), service.as_bytes()],
        |bytes| output.extend_from_slice(bytes),
        |bytes| error.extend_from_slice(bytes),
    )?;
    if !output.is_empty() {
        crate::progress::print_info(&String::from_utf8_lossy(&output));
    }
    if !error.is_empty() {
        crate::progress::print_error(&String::from_utf8_lossy(&error));
    }
    Some(code)
}

/// 经 daemon 执行 shell 并**捕获**输出（供需要二次加工输出的调用方，如 pm list 去前缀）。
/// 返回 None → daemon 不可用，调用方回退直连。
pub fn capture_shell(serial: Option<&str>, cmd: &str) -> Option<Result<String, String>> {
    if !daemon_enabled() {
        return None;
    }
    let serial = serial.unwrap_or("");
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let code = send_and_pump(
        &[VERB_SHELL, serial.as_bytes(), cmd.as_bytes()],
        |b| out.extend_from_slice(b),
        |b| err.extend_from_slice(b),
    )?;
    if code == 0 {
        Some(Ok(String::from_utf8_lossy(&out).to_string()))
    } else {
        let msg = if !err.is_empty() {
            String::from_utf8_lossy(&err).to_string()
        } else {
            String::from_utf8_lossy(&out).to_string()
        };
        Some(Err(msg))
    }
}

/// 让正在运行的 daemon 释放 ADB 句柄并退出（best-effort）。凡要直连设备的路径，直连前必须
/// 先调用它，保证「单一拥有者」。特意不判 `daemon_enabled()`：可能存在上次开启时留下、仍在
/// 存活期内的 daemon 正持有连接；管道不存在时只是一次立刻失败的 CreateFileW（微秒级），代价可忽略。
pub fn ensure_released() {
    best_effort_release();
}

fn best_effort_release() {
    // 不为了 release 而拉起 daemon：只在管道已存在时连上去发 release。
    let pipe = match client_connect(false) {
        Some(p) => p,
        None => return,
    };
    if write_request(pipe.0, &[VERB_RELEASE]).is_err() {
        return;
    }
    // 读到 EXIT（daemon 已丢弃句柄并即将退出）或管道被关闭即视为释放完成。
    loop {
        match read_frame(pipe.0) {
            Ok(Frame::Exit(_)) => return,
            Ok(_) => continue,
            Err(_) => return,
        }
    }
}

// ============================ 服务端（daemon） ============================

/// daemon 主入口：创建单实例命名管道，常驻循环服务客户端。永不返回。
pub fn run_daemon() -> ! {
    crate::logger::log_line("[adb-daemon] 启动");

    let name = wide(&pipe_name());
    let pipe = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            // FIRST_PIPE_INSTANCE：保证同名管道只存在一个 daemon；第二个 daemon 创建失败即退出。
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            64 * 1024,
            64 * 1024,
            0,
            ptr::null_mut(),
        )
    };
    if pipe == INVALID_HANDLE_VALUE {
        crate::logger::log_line("[adb-daemon] 命名管道创建失败（可能已有 daemon 在跑）；退出");
        std::process::exit(0);
    }

    // 跨线程共享状态：所持设备路径（供看门狗判断设备是否拔出）、忙碌标志、最后活跃时刻。
    let held_path: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let busy = Arc::new(AtomicBool::new(false));
    let last_active = Arc::new(AtomicU64::new(now_ms()));
    spawn_watchdog(held_path.clone(), busy.clone(), last_active.clone());

    // 仅主线程持有（AdbWinUsbDevice / HANDLE 均 !Send）。
    let mut device: Option<AdbWinUsbDevice> = None;
    let mut device_path: Option<String> = None;

    loop {
        let connected = unsafe { ConnectNamedPipe(pipe, ptr::null_mut()) };
        if connected == FALSE {
            let err = unsafe { GetLastError() };
            // 客户端在 CreateNamedPipe 与 ConnectNamedPipe 之间抢先连上：视为已连接。
            if err != ERROR_PIPE_CONNECTED {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
        }

        busy.store(true, Ordering::SeqCst);
        serve_one(pipe, &mut device, &mut device_path, &held_path);
        last_active.store(now_ms(), Ordering::SeqCst);
        busy.store(false, Ordering::SeqCst);

        unsafe {
            // 关键顺序：先 Flush 再 Disconnect。Disconnect 会丢弃客户端尚未读取的数据，客户端会
            // 读失败误判 daemon 死亡而回退；FlushFileBuffers 阻塞到客户端读完，确保响应完整送达。
            FlushFileBuffers(pipe);
            DisconnectNamedPipe(pipe);
        }
    }
}

fn spawn_watchdog(
    held_path: Arc<Mutex<Option<String>>>,
    busy: Arc<AtomicBool>,
    last_active: Arc<AtomicU64>,
) {
    std::thread::spawn(move || {
        let idle = idle_ms();
        loop {
            std::thread::sleep(Duration::from_millis(2000));
            if busy.load(Ordering::SeqCst) {
                continue;
            }
            // 空闲超时：退出，把 USB 让出来。
            if now_ms().saturating_sub(last_active.load(Ordering::SeqCst)) > idle {
                crate::logger::log_line("[adb-daemon] 空闲超时；退出");
                std::process::exit(0);
            }
            // 所持设备已拔出：退出，下次命令会拉起新 daemon 建新连接。
            let hp = held_path.lock().ok().and_then(|g| g.clone());
            if let Some(p) = hp {
                let present = AdbWinUsbDevice::enumerate()
                    .map(|l| l.iter().any(|d| d.device_path == p))
                    .unwrap_or(false);
                if !present {
                    crate::logger::log_line("[adb-daemon] 所持设备已拔出；退出");
                    std::process::exit(0);
                }
            }
        }
    });
}

fn serve_one(
    pipe: HANDLE,
    device: &mut Option<AdbWinUsbDevice>,
    device_path: &mut Option<String>,
    held_path: &Arc<Mutex<Option<String>>>,
) {
    let args = match read_request(pipe) {
        Ok(a) => a,
        Err(_) => return,
    };
    let verb = match args.first() {
        Some(v) => v.as_slice(),
        None => return,
    };

    match verb {
        VERB_RELEASE => {
            // 先丢弃设备（Drop 会 WinUsb_Free + CloseHandle 释放 USB 句柄），再确认给客户端，
            // 保证客户端拿到确认时句柄已释放，随后直连才安全。
            *device = None;
            *device_path = None;
            if let Ok(mut g) = held_path.lock() {
                *g = None;
            }
            let _ = write_frame(pipe, KIND_EXIT, &0i32.to_le_bytes());
            unsafe {
                FlushFileBuffers(pipe);
                DisconnectNamedPipe(pipe);
            }
            crate::logger::log_line("[adb-daemon] 收到 release；已释放句柄并退出");
            std::process::exit(0);
        }
        VERB_DEVICES => {
            serve_devices(pipe, device, device_path, held_path);
        }
        VERB_SHELL => {
            let serial = args
                .get(1)
                .map(|v| String::from_utf8_lossy(v).to_string())
                .unwrap_or_default();
            let cmd = args
                .get(2)
                .map(|v| String::from_utf8_lossy(v).to_string())
                .unwrap_or_default();
            serve_shell(pipe, device, device_path, held_path, &serial, &cmd);
        }
        VERB_REBOOT => {
            let serial = args
                .get(1)
                .map(|v| String::from_utf8_lossy(v).to_string())
                .unwrap_or_default();
            let target = args
                .get(2)
                .map(|v| String::from_utf8_lossy(v).to_string())
                .unwrap_or_default();
            serve_reboot(pipe, device, device_path, held_path, &serial, &target);
        }
        VERB_SERVICE => {
            let serial = args
                .get(1)
                .map(|v| String::from_utf8_lossy(v).to_string())
                .unwrap_or_default();
            let service = args
                .get(2)
                .map(|v| String::from_utf8_lossy(v).to_string())
                .unwrap_or_default();
            serve_service(pipe, device, device_path, held_path, &serial, &service);
        }
        _ => {
            let _ = write_frame(pipe, KIND_EXIT, &1i32.to_le_bytes());
        }
    }
}

/// [`ensure_device`] 的失败分类：决定 daemon 是「权威失败」还是「让位给直连」。
enum EnsureErr {
    /// 存在多台 ADB 设备且调用方未指定序列号。
    Ambiguous,
    /// 设备在但未授权 / 建连 IO 出错：让位直连（直连能弹授权框、有完善的退避重开）。
    Fallback,
    /// 确无设备 / 指定序列号找不到：也让位直连，由直连的独立枚举作为设备是否存在的权威判断。
    NoDevice,
}

/// 确保持有一条与 `serial`（空=任意）匹配的已授权连接；必要时开新连接。
/// 用 connect_probe 而非 connect：不发公钥、不弹框、不等待。daemon 无控制台承接不了首次授权，
/// 未授权设备必须快速判定并让位直连（Fallback），而非像 connect 一等 180s。
fn ensure_device<'a>(
    device: &'a mut Option<AdbWinUsbDevice>,
    device_path: &mut Option<String>,
    held_path: &Arc<Mutex<Option<String>>>,
    serial: &str,
) -> Result<&'a mut AdbWinUsbDevice, EnsureErr> {
    let want = if serial.is_empty() {
        None
    } else {
        Some(serial)
    };
    let mut enumerated = None;

    if want.is_none() {
        let list = AdbWinUsbDevice::enumerate().map_err(|_| EnsureErr::NoDevice)?;
        if list.is_empty() {
            return Err(EnsureErr::NoDevice);
        }
        if list.len() > 1 {
            return Err(EnsureErr::Ambiguous);
        }
        enumerated = Some(list);
    }

    // 复用已持有的连接（序列号匹配或未指定）。
    let reuse = match (device.as_ref(), device_path.as_ref()) {
        (Some(_), Some(p)) => {
            let cur = serial_from_path(p);
            want.is_none() || want == Some(cur.as_str())
        }
        _ => false,
    };
    if reuse {
        return Ok(device.as_mut().unwrap());
    }

    // 序列号变了或尚无连接：丢弃旧的、开新的。
    *device = None;
    *device_path = None;
    if let Ok(mut g) = held_path.lock() {
        *g = None;
    }

    let list = match enumerated {
        Some(list) => list,
        None => AdbWinUsbDevice::enumerate().map_err(|_| EnsureErr::NoDevice)?,
    };
    if list.is_empty() {
        return Err(EnsureErr::NoDevice);
    }
    let path = match want {
        Some(s) => list
            .iter()
            .find(|d| serial_from_path(&d.device_path) == s)
            .map(|d| d.device_path.clone())
            .ok_or(EnsureErr::NoDevice)?,
        None => list[0].device_path.clone(),
    };

    let mut dev = AdbWinUsbDevice::open_device(&path).map_err(|_| EnsureErr::Fallback)?;
    match dev.connect_probe(CONNECT_PROBE_TIMEOUT_MS) {
        Ok(true) => {}
        // 未授权或 IO/协议错误：都让位直连。
        _ => return Err(EnsureErr::Fallback),
    }

    *device = Some(dev);
    *device_path = Some(path.clone());
    if let Ok(mut g) = held_path.lock() {
        *g = Some(path);
    }
    Ok(device.as_mut().unwrap())
}

fn serve_shell(
    pipe: HANDLE,
    device: &mut Option<AdbWinUsbDevice>,
    device_path: &mut Option<String>,
    held_path: &Arc<Mutex<Option<String>>>,
    serial: &str,
    cmd: &str,
) {
    match ensure_device(device, device_path, held_path, serial) {
        Ok(dev) => match dev.shell_command_streaming(
            cmd,
            |b| {
                let _ = write_frame(pipe, KIND_STDOUT, b);
            },
            |b| {
                let _ = write_frame(pipe, KIND_STDERR, b);
            },
        ) {
            Ok(exit) => {
                let _ = write_frame(pipe, KIND_EXIT, &exit.code.to_le_bytes());
            }
            Err(e) => {
                *device = None;
                *device_path = None;
                if let Ok(mut g) = held_path.lock() {
                    *g = None;
                }
                let _ = write_frame(
                    pipe,
                    KIND_STDERR,
                    crate::response_text::format_error(&e).as_bytes(),
                );
                let _ = write_frame(pipe, KIND_EXIT, &1i32.to_le_bytes());
            }
        },
        // 建连阶段失败（未授权/无设备/IO 错）：尚未向设备下发任何命令，让客户端安全回退直连
        // （直连能弹授权框、走完善的退避重开）。
        Err(EnsureErr::Ambiguous) => {
            let _ = write_frame(
                pipe,
                KIND_STDERR,
                crate::response_text::format_error(
                    "more than one ADB device/emulator; use -s <serial>\n",
                )
                .as_bytes(),
            );
            let _ = write_frame(pipe, KIND_EXIT, &1i32.to_le_bytes());
        }
        Err(_) => {
            let _ = write_frame(pipe, KIND_EXIT, &EXIT_FALLBACK.to_le_bytes());
        }
    }
}

fn clear_device(
    device: &mut Option<AdbWinUsbDevice>,
    device_path: &mut Option<String>,
    held_path: &Arc<Mutex<Option<String>>>,
) {
    *device = None;
    *device_path = None;
    if let Ok(mut g) = held_path.lock() {
        *g = None;
    }
}

fn write_ambiguous(pipe: HANDLE) {
    let _ = write_frame(
        pipe,
        KIND_STDERR,
        crate::response_text::format_error("more than one ADB device/emulator; use -s <serial>\n")
            .as_bytes(),
    );
    let _ = write_frame(pipe, KIND_EXIT, &1i32.to_le_bytes());
}

fn serve_reboot(
    pipe: HANDLE,
    device: &mut Option<AdbWinUsbDevice>,
    device_path: &mut Option<String>,
    held_path: &Arc<Mutex<Option<String>>>,
    serial: &str,
    target: &str,
) {
    match ensure_device(device, device_path, held_path, serial) {
        Ok(dev) => {
            let result = dev.reboot(target);
            clear_device(device, device_path, held_path);
            match result {
                Ok(()) => {
                    let _ = write_frame(pipe, KIND_EXIT, &0i32.to_le_bytes());
                }
                Err(e) => {
                    let _ = write_frame(pipe, KIND_STDERR, e.as_bytes());
                    let _ = write_frame(pipe, KIND_EXIT, &1i32.to_le_bytes());
                }
            }
        }
        Err(EnsureErr::Ambiguous) => write_ambiguous(pipe),
        Err(_) => {
            let _ = write_frame(pipe, KIND_EXIT, &EXIT_FALLBACK.to_le_bytes());
        }
    }
}

fn serve_service(
    pipe: HANDLE,
    device: &mut Option<AdbWinUsbDevice>,
    device_path: &mut Option<String>,
    held_path: &Arc<Mutex<Option<String>>>,
    serial: &str,
    service: &str,
) {
    if service.trim().is_empty() {
        let _ = write_frame(pipe, KIND_STDERR, b"empty adb service\n");
        let _ = write_frame(pipe, KIND_EXIT, &1i32.to_le_bytes());
        return;
    }
    match ensure_device(device, device_path, held_path, serial) {
        Ok(dev) => {
            let result = dev.execute_service_streaming(service, |payload| {
                write_frame(pipe, KIND_STDOUT, payload).map_err(|e| e.to_string())
            });
            clear_device(device, device_path, held_path);
            match result {
                Ok(()) => {
                    let _ = write_frame(pipe, KIND_EXIT, &0i32.to_le_bytes());
                }
                Err(e) => {
                    let _ = write_frame(pipe, KIND_STDERR, e.as_bytes());
                    let _ = write_frame(pipe, KIND_EXIT, &1i32.to_le_bytes());
                }
            }
        }
        Err(EnsureErr::Ambiguous) => write_ambiguous(pipe),
        Err(_) => {
            let _ = write_frame(pipe, KIND_EXIT, &EXIT_FALLBACK.to_le_bytes());
        }
    }
}

/// `adb devices`：输出与原生实现字节一致（`List of devices attached\n` + `序列号\t状态`）。
/// 提速关键：把主设备建成常驻连接后，每次 devices 直接报 `device`、零 USB IO——
/// 这正是 GUI 每秒轮询的热路径；只有非所持设备才 open+connect 深探。
fn serve_devices(
    pipe: HANDLE,
    device: &mut Option<AdbWinUsbDevice>,
    device_path: &mut Option<String>,
    held_path: &Arc<Mutex<Option<String>>>,
) {
    let list = AdbWinUsbDevice::enumerate().unwrap_or_default();

    // 所持设备已从枚举中消失（拔出）→ 丢弃，别再报它。
    if let Some(p) = device_path.as_ref() {
        if !list.iter().any(|d| &d.device_path == p) {
            *device = None;
            *device_path = None;
            if let Ok(mut g) = held_path.lock() {
                *g = None;
            }
        }
    }

    // 尚未持有连接且有设备：尝试把首个设备建成常驻连接（成功后续 devices 秒回；未授权则保持未持有）。
    if device.is_none() && !list.is_empty() {
        let _ = ensure_device(device, device_path, held_path, "");
    }

    let mut out = String::from("List of devices attached\n");
    for info in &list {
        let serial = serial_from_path(&info.device_path);
        let is_held = device.is_some() && device_path.as_deref() == Some(info.device_path.as_str());
        let state = if is_held {
            "device"
        } else {
            // 未持有的设备才深探。用 connect_probe 秒级判 device/unauthorized；绝不能用 connect()——
            // 它会给未授权设备发公钥并阻塞等授权（最长 180s），卡死 daemon 服务循环、还乱弹授权框。
            match AdbWinUsbDevice::open_device(&info.device_path) {
                Ok(mut d) => match d.connect_probe(CONNECT_PROBE_TIMEOUT_MS) {
                    Ok(true) => "device",
                    _ => "unauthorized",
                },
                Err(_) => "unauthorized",
            }
        };
        out.push_str(&serial);
        out.push('\t');
        out.push_str(state);
        out.push('\n');
    }

    let _ = write_frame(pipe, KIND_STDOUT, out.as_bytes());
    let _ = write_frame(pipe, KIND_EXIT, &0i32.to_le_bytes());
}
