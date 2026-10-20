//! 自研 adb CLI 的「瘦客户端」：scrcpy 以子进程 exec adb，各命令若直连会独占 WinUSB，令 reverse
//! 与 shell 两条长连接互相抢句柄；故 `RMF_ADB_MUX=1` 且 5037 有 mux server 时改连 5037 走 host
//! 协议，复用 server 那一条 USB 连接（官方 adb 模型）。只要 5037 有 server 在位，失败也不回退直连
//! （server 独占句柄，直连必撞 CreateFileW 0x80070005）；冷启动窗口应先 [`wait_adb_server`] 再重试。
//!
//! 本进程自己就是 5037 上的 mux server（GUI 宿主）时，设备服务、`devices`、`get-state` 不连 5037，
//! 直接进进程内 hub（见 [`served_in_process`]）：绕 TCP 回环找自己，每条命令白付一次连接和两轮
//! host 协议往返，回环一出岔子还会被当成「server 不在」去等。

use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

const ADB_PORT: u16 = 5037;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_millis(40);
const PROBE_READ_TIMEOUT: Duration = Duration::from_millis(120);
/// 控制阶段（transport/host 查询/kill/OKAY-FAIL 应答）的读超时。5037 可能被「accept 后不应答也
/// 不断连」的进程占住，无超时会把调用方永久挂死（真机复现）；长驻数据流在 OKAY 后自行清除。
const CONTROL_READ_TIMEOUT: Duration = Duration::from_secs(2);
/// 打开设备服务时，server 可能需要先拆掉一条半死 hub，再重建 hub 后才会回
/// client 的 OKAY（服务端两次 `open_stream` 各允许 10s）。不能沿用 2s 的 host
/// 控制超时，否则 shell 会在 server 自愈完成前收到 Windows 10060，root 流程
/// 随即把一次可恢复的交接抖动误报成「shell 通道未就绪」。
const SERVICE_OPEN_READ_TIMEOUT: Duration = Duration::from_secs(25);
const SYNC_CHUNK_SIZE: usize = 64 * 1024;
const SYNC_STATUS_MAX: usize = 1024 * 1024;
const SYNC_DATA_MAX: usize = 16 * 1024 * 1024;

/// 设备服务的数据通道：本进程自己承载 5037 时是进程内 mux hub 上的流，否则是借道 5037 的 TCP。
/// 数据阶段（shell 输出 / sync / exec stdin）只依赖 `Read`/`Write`，两种形态共用同一套协议代码。
enum Conn {
    Tcp(TcpStream),
    Local(crate::adb_mux::MuxStreamIo),
}

impl Conn {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        match self {
            Conn::Tcp(s) => {
                let _ = s.set_read_timeout(timeout);
            }
            Conn::Local(s) => s.set_read_timeout(timeout),
        }
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Tcp(s) => s.read(buf),
            Conn::Local(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Tcp(s) => s.write(buf),
            Conn::Local(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Tcp(s) => s.flush(),
            Conn::Local(s) => s.flush(),
        }
    }
}

/// 本进程就是 5037 上的 mux server：设备句柄归本进程 hub，请求直接进 hub，不连 5037 绕回自己。
fn served_in_process() -> bool {
    crate::adb_mux_server::inproc_server_running()
}

/// scrcpy 投屏路径是否要求走 mux（单连接多路复用）。
pub fn is_mux_enabled() -> bool {
    std::env::var("RMF_ADB_MUX")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// 5037 端口上是谁在听。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AdbServerOnPort {
    /// TCP 都连不上：端口空着，谁也没攥着设备句柄，直连 WinUSB 是安全的。
    Absent,
    /// 本项目的 mux server（`host:rmf-mux-info` 回 OKAY）。
    RmfMux,
    /// 别的 adb server：官方 adb 对未知 host 服务回的是规规矩矩的 `FAIL`。
    /// 它同样独占设备句柄，而且说的是同一套 host 协议，所以照样能借道。
    ForeignAdb,
    /// 连上了却认不出：既没 OKAY 也没 FAIL。可能是 server 正忙没答上，
    /// 也可能是个跟 adb 毫无关系、只是占着 5037 的程序。
    Unknown,
}

/// 探测 5037 上 server 的身份，读超时由调用方给（热路径要短、确认时可以给宽一点）。
fn classify_server_on_port(read_timeout: Duration) -> AdbServerOnPort {
    let Ok(mut s) = connect_with_timeout(PROBE_CONNECT_TIMEOUT) else {
        return AdbServerOnPort::Absent;
    };
    let _ = s.set_read_timeout(Some(read_timeout));
    if send_request(&mut s, "host:rmf-mux-info").is_err() {
        return AdbServerOnPort::Unknown;
    }
    match read_status(&mut s) {
        Ok(true) => AdbServerOnPort::RmfMux,
        Ok(false) => AdbServerOnPort::ForeignAdb,
        Err(_) => AdbServerOnPort::Unknown,
    }
}

/// 认不出身份时，多久之内还认上一次确认过的 server。
const SERVER_MEMO_TTL: Duration = Duration::from_secs(3);
/// 确认阶段的读超时。热路径探测只给 120ms，投屏正忙时 server 偶尔答不上来；
/// 真要下「端口上没有 server」这种结论之前，值得多等这一会儿。
const CONFIRM_READ_TIMEOUT: Duration = Duration::from_millis(600);

/// 认真判一次 5037 上是谁：先按热路径超时探，认不出来再给一次更宽的机会。
/// 「是否抢占端口」「是否借道」这类不可逆决定都必须用它，而不是单次快探。
pub fn classify_server_confirmed() -> AdbServerOnPort {
    let kind = classify_server_on_port(PROBE_READ_TIMEOUT);
    if kind == AdbServerOnPort::Unknown {
        classify_server_on_port(CONFIRM_READ_TIMEOUT)
    } else {
        kind
    }
}

/// 设备的 WinUSB 句柄是否已被 5037 上的 adb server 持有。
///
/// 判据保守——两向判错代价不对等：多借道只慢几毫秒，错走直连必撞 CreateFileW 0x80070005 且会
/// 搅掉对方连接。故仅确证端口没人（TCP 连不上）才回 false；身份认不出时，近期确认过 server 就按
/// 「有」处理，从没确认过则放行直连（多半是无关程序占着 5037，句柄实为空）。
pub fn device_owned_by_adb_server() -> bool {
    let kind = classify_server_confirmed();

    let mut memo = match LAST_CONFIRMED_SERVER.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let recently_confirmed = memo.is_some_and(|at| at.elapsed() < SERVER_MEMO_TTL);
    match kind {
        AdbServerOnPort::RmfMux | AdbServerOnPort::ForeignAdb => *memo = Some(Instant::now()),
        AdbServerOnPort::Absent => *memo = None,
        AdbServerOnPort::Unknown => {}
    }
    server_holds_device_handle(kind, recently_confirmed)
}

static LAST_CONFIRMED_SERVER: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);

/// [`device_owned_by_adb_server`] 的判定本体，抽出来是为了能离线逐种情形验。
fn server_holds_device_handle(kind: AdbServerOnPort, recently_confirmed: bool) -> bool {
    match kind {
        AdbServerOnPort::Absent => false,
        AdbServerOnPort::RmfMux | AdbServerOnPort::ForeignAdb => true,
        AdbServerOnPort::Unknown => recently_confirmed,
    }
}

/// 等 5037 上出现能借道的 adb server（server 可能刚被投屏拉起、还在冷启动窗口）。
pub fn wait_adb_server(wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    loop {
        if device_owned_by_adb_server() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// 借道 5037 发一次请求；扑空（`None`）就等 server 可探测后再试一次，仍不行才算真的借不到道。
/// server 可能刚被投屏拉起、还在冷启动窗口，首次请求扑空不代表它不在。embed 与 CLI（`adb_router`）
/// 的每条借道请求都经这里，重试口径只此一份。
pub fn retry_via_server<T>(mut request: impl FnMut() -> Option<T>) -> Option<T> {
    request().or_else(|| {
        wait_adb_server(Duration::from_secs(3))
            .then(&mut request)
            .flatten()
    })
}

fn connect() -> Result<TcpStream, String> {
    connect_with_timeout(CONNECT_TIMEOUT)
}

fn connect_with_timeout(timeout: Duration) -> Result<TcpStream, String> {
    let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, ADB_PORT));
    let s = TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?;
    let _ = s.set_nodelay(true);
    let _ = s.set_read_timeout(Some(CONTROL_READ_TIMEOUT));
    Ok(s)
}

/// 发一条 host 协议请求：`[4 位十六进制长度][payload]`（帧格式唯一实现在 [`crate::adb_host_proto`]）。
fn send_request(s: &mut TcpStream, req: &str) -> Result<(), String> {
    crate::adb_host_proto::write_len_prefixed(s, req).map_err(|e| e.to_string())
}

/// 读 4 字节状态：`OKAY`=true，`FAIL`=false。
fn read_status(s: &mut TcpStream) -> Result<bool, String> {
    let mut b = [0u8; 4];
    s.read_exact(&mut b).map_err(|e| e.to_string())?;
    match &b {
        b"OKAY" => Ok(true),
        b"FAIL" => Ok(false),
        other => Err(format!("unexpected adb status: {:?}", other)),
    }
}

/// 读一段 `[4 位十六进制长度][payload]`。
fn read_len_prefixed(s: &mut TcpStream) -> Result<String, String> {
    crate::adb_host_proto::read_message(s).map_err(|e| e.to_string())
}

/// 选择 transport 请求串。指定 serial 用 `host:transport:<serial>`，否则 `host:transport-any`。
fn transport_req(serial: Option<&str>) -> String {
    match serial.filter(|s| !s.is_empty() && *s != "unknown") {
        Some(s) => format!("host:transport:{}", s),
        None => "host:transport-any".to_string(),
    }
}

/// transport 切换失败的两种性质，调用方的处置完全不同。
#[derive(Debug, PartialEq, Eq)]
enum TransportError {
    /// 没跟 server 说上话（连不上 / 收发中断）：server 可能还在冷启动，值得等它回来再试。
    Unreachable,
    /// server 明确回了 FAIL（设备不在 / 未授权 / 离线 / 多台）：这是有效答案，原样交给用户，
    /// 等多久也不会变。官方 server 持有设备时，设备重启、等授权期间每条命令都会走到这里。
    Refused(String),
}

impl TransportError {
    fn message(self) -> String {
        match self {
            TransportError::Unreachable => "无法连接 5037 上的 adb server".to_string(),
            TransportError::Refused(msg) => msg,
        }
    }
}

/// 连 5037 并完成一次 transport 切换，返回已就绪的 socket。
fn connect_transport(serial: Option<&str>) -> Result<TcpStream, TransportError> {
    let mut s = connect().map_err(|_| TransportError::Unreachable)?;
    send_request(&mut s, &transport_req(serial)).map_err(|_| TransportError::Unreachable)?;
    match read_status(&mut s) {
        Ok(true) => Ok(s),
        Ok(false) => {
            let msg = read_len_prefixed(&mut s).unwrap_or_default();
            Err(TransportError::Refused(if msg.is_empty() {
                "transport failed".to_string()
            } else {
                msg
            }))
        }
        Err(_) => Err(TransportError::Unreachable),
    }
}

/// 设备服务没能打开的原因：shell v2 要据此区分「设备不认这个服务名」（换 legacy 再试）与
/// 「transport 都没切过去」（换什么服务名都一样失败）。
enum OpenError {
    Unreachable,
    Transport(String),
    Service(String),
}

fn open_transport_service_detailed(serial: Option<&str>, service: &str) -> Result<Conn, OpenError> {
    if served_in_process() {
        return crate::adb_mux_server::open_local_stream(serial, service)
            .map(Conn::Local)
            .map_err(|e| {
                if crate::adb_mux::is_open_rejected_err(&e) {
                    OpenError::Service(e)
                } else {
                    OpenError::Transport(e)
                }
            });
    }
    let mut s = connect_transport(serial).map_err(|e| match e {
        TransportError::Unreachable => OpenError::Unreachable,
        TransportError::Refused(msg) => OpenError::Transport(msg),
    })?;
    send_request(&mut s, service)
        .map_err(|e| OpenError::Service(format!("发送 {} 服务失败: {}", service, e)))?;
    // `serve_local` 只有在设备侧 A_OPEN 成功（或 10s 超时后重建并再次尝试）
    // 才能回 host OKAY。这里必须给足这段恢复窗口；进入数据阶段后各调用方
    // 会按服务类型自行清除读超时。
    let _ = s.set_read_timeout(Some(SERVICE_OPEN_READ_TIMEOUT));
    match read_status(&mut s) {
        Ok(true) => Ok(Conn::Tcp(s)),
        Ok(false) => {
            let detail = read_len_prefixed(&mut s).unwrap_or_default();
            Err(OpenError::Service(if detail.is_empty() {
                format!("设备拒绝 {} 服务", service)
            } else {
                detail
            }))
        }
        Err(e) => Err(OpenError::Service(format!(
            "读取 {} 服务响应失败: {}",
            service, e
        ))),
    }
}

/// 打开 transport 后的设备服务。`None` **只**表示没跟 5037 上的 server 说上话（调用方据此等
/// server 回来再试）；server 回 FAIL（设备不在 / 未授权……）是 `Some(Err)`，不能落进那段等待。
/// 本进程直连没有这一步，成败都是 `Some`。
fn open_transport_service(serial: Option<&str>, service: &str) -> Option<Result<Conn, String>> {
    match open_transport_service_detailed(serial, service) {
        Ok(conn) => Some(Ok(conn)),
        Err(OpenError::Unreachable) => None,
        Err(OpenError::Transport(msg)) | Err(OpenError::Service(msg)) => Some(Err(msg)),
    }
}

/// 经 mux 打开 transport 后服务并捕获全部输出（embed 投屏期间跑 `remount:`/`tcpip:`/`root:` 等用）。
/// 仅在确认 mux server 在线时才应把 `None` 当错误，避免回退直连抢 WinUSB 句柄。
pub fn capture_service(serial: Option<&str>, service: &str) -> Option<Result<String, String>> {
    capture_service_bytes(serial, service)
        .map(|r| r.map(|bytes| String::from_utf8_lossy(&bytes).into_owned()))
}

/// 按原始字节收齐服务输出。shell v2 分帧是二进制（长度字段可含 ≥0x80 的字节），必须收齐后
/// 在字节层解码；逐块有损转 UTF-8 还会把跨块的多字节字符劈成乱码。
fn capture_service_bytes(serial: Option<&str>, service: &str) -> Option<Result<Vec<u8>, String>> {
    let s = match open_transport_service(serial, service)? {
        Ok(s) => s,
        Err(e) => return Some(Err(e)),
    };
    Some(read_until_eof(s, service))
}

/// 服务已进入数据阶段，不能再使用控制阶段 2s 超时；以 EOF 作为命令完成信号。
fn read_until_eof(mut s: Conn, service: &str) -> Result<Vec<u8>, String> {
    s.set_read_timeout(None);
    let mut out = Vec::new();
    let mut buf = [0u8; 32 * 1024];
    loop {
        match s.read(&mut buf) {
            Ok(0) => return Ok(out),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => return Err(format!("读取 {} 输出失败: {}", service, e)),
        }
    }
}

/// 经 mux 打开服务，把输出**逐块原样**写进 `out` 直到设备关流（exec-out 二进制输出、jdwp 长连接、
/// backup 落文件用）。不经 UTF-8 转换，不设读超时。`None` 只表示连不上 server。
pub fn stream_service_to(
    serial: Option<&str>,
    service: &str,
    out: &mut dyn Write,
) -> Option<Result<(), String>> {
    let mut s = match open_transport_service(serial, service)? {
        Ok(s) => s,
        Err(e) => return Some(Err(e)),
    };
    s.set_read_timeout(None);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match s.read(&mut buf) {
            Ok(0) => return Some(Ok(())),
            Ok(n) => {
                if let Err(e) = out.write_all(&buf[..n]).and_then(|_| out.flush()) {
                    return Some(Err(format!("写出 {} 输出失败: {}", service, e)));
                }
            }
            Err(e) => return Some(Err(format!("读取 {} 输出失败: {}", service, e))),
        }
    }
}

/// 经 mux 打开服务、把 `stdin` 全部写进去，再收齐输出直到 EOF（流式安装用）。`None` 只在连不上
/// server 时返回，此时 `stdin` 还没被读过，调用方可以安全重试。服务中途关流（pm 提前报错）时
/// 写会失败，仍把已回的输出读出来交给调用方判断。
pub fn exec_with_stdin(
    serial: Option<&str>,
    service: &str,
    stdin: &mut dyn Read,
) -> Option<Result<Vec<u8>, String>> {
    let mut s = match open_transport_service(serial, service)? {
        Ok(s) => s,
        Err(e) => return Some(Err(e)),
    };
    s.set_read_timeout(None);
    let sent = std::io::copy(stdin, &mut s);
    let mut out = Vec::new();
    let received = s.read_to_end(&mut out);
    match (sent, received) {
        (Err(e), _) if out.is_empty() => Some(Err(format!("写入 {} 失败: {}", service, e))),
        (_, Err(e)) if out.is_empty() => Some(Err(format!("读取 {} 输出失败: {}", service, e))),
        _ => Some(Ok(out)),
    }
}

/// `adb devices [-l]` 经 mux server 查询（返回 wire 文本：每行 `序列号\t状态[…]`，不含表头）。
/// 失败返回 `None`，调用方回退直连枚举。
pub fn devices(long: bool) -> Option<String> {
    if served_in_process() {
        return Some(crate::adb_mux_server::local_devices(long));
    }
    let mut s = connect().ok()?;
    let req = if long {
        "host:devices-l"
    } else {
        "host:devices"
    };
    send_request(&mut s, req).ok()?;
    if !read_status(&mut s).ok()? {
        return None;
    }
    read_len_prefixed(&mut s).ok()
}

/// `adb get-state` 经 5037 server 查询。`None` **只**表示「没能跟 server 说上话」——调用方
/// 据此判定 mux 不可用并如实报错，绝不能把「设备不在」也算进去。
///
/// server 回 FAIL 是一个**有效答案**（官方口径：没有设备 / 指定的设备不存在），归一成
/// `"unknown"`：本项目 CLI 与 embed 一直用这个字符串表示「不是 device 态」，四个调用方
/// 全都只判 `== "device"`，故语义完全对齐。
pub fn get_state(serial: Option<&str>) -> Option<String> {
    if served_in_process() {
        return Some(crate::adb_mux_server::local_state(serial));
    }
    let mut s = connect().ok()?;
    let req = match serial.filter(|s| !s.is_empty() && *s != "unknown") {
        Some(x) => format!("host-serial:{}:get-state", x),
        None => "host:get-state".to_string(),
    };
    send_request(&mut s, &req).ok()?;
    if !read_status(&mut s).ok()? {
        // 把 FAIL 详情读掉（保持帧对齐），答案归一成 unknown。
        let _ = read_len_prefixed(&mut s);
        return Some("unknown".to_string());
    }
    read_len_prefixed(&mut s).ok()
}

/// `adb reverse ...` 经 mux server 处理。`Some(code)`=已接手（成败都算）；
/// `None`=server 不可达或参数不全，交调用方回退既有实现。
pub fn handle_reverse(serial: Option<&str>, args: &[String]) -> Option<i32> {
    if args.is_empty() {
        return None;
    }

    let service = match args[0].as_str() {
        // 规则在设备 adbd 里，本地注册表只记得本进程直连时建的那些，别人经 server 建的看不到。
        "--list" | "--list-forward" => {
            print!("{}", reverse_list(serial)?);
            let _ = std::io::stdout().flush();
            return Some(0);
        }
        "--remove-all" => "reverse:killforward-all".to_string(),
        "--remove" => {
            let remote = args.get(1)?;
            format!("reverse:killforward:{}", remote)
        }
        _ => {
            // [--no-rebind] REMOTE LOCAL
            let mut pos = 0usize;
            let mut norebind = false;
            while args.get(pos).map(String::as_str) == Some("--no-rebind") {
                norebind = true;
                pos += 1;
            }
            let remote = args.get(pos)?;
            let local = args.get(pos + 1)?;
            if norebind {
                format!("reverse:forward:norebind:{};{}", remote, local)
            } else {
                format!("reverse:forward:{};{}", remote, local)
            }
        }
    };

    match reverse_request(serial, &service) {
        Ok(reply) => {
            // tcp:0 时设备回传实际端口；scrcpy 用固定端口，通常无回传。
            let trimmed = reply.trim();
            if !trimmed.is_empty() {
                if let Some(port) = trimmed.strip_prefix("tcp:") {
                    println!("{}", port);
                } else {
                    println!("{}", trimmed);
                }
            }
            Some(0)
        }
        Err(e) => {
            eprintln!("{}", e);
            Some(1)
        }
    }
}

/// 连 5037 → transport → 发一条 `reverse:*` 增删服务，读完两个状态（及可选回传）后关闭。
/// 监听规则由 adbd 持久维护、回连(A_OPEN)由 mux server 分发，故控制连接拿到结论即可关。
///
/// 第一个 OKAY 是 server 的「服务已在设备侧打开」，第二个才是设备 reverse 服务的结论
/// （`cannot rebind existing socket` / `listener ... not found` 都在这一步以 FAIL 回来）。
/// 只读一个就把设备的 FAIL 当成功吞掉了，tcp:0 的端口也会被错读成长度前缀。
fn reverse_request(serial: Option<&str>, service: &str) -> Result<String, String> {
    let mut s = connect_transport(serial).map_err(TransportError::message)?;
    send_request(&mut s, service)?;
    for _ in 0..2 {
        if !read_status(&mut s)? {
            let msg = read_len_prefixed(&mut s).unwrap_or_default();
            return Err(if msg.is_empty() {
                format!("device rejected '{}'", service)
            } else {
                msg
            });
        }
    }
    // tcp:0 时设备随后回报实际端口；其余情形设备直接关流，读到 EOF 即空。
    s.set_read_timeout(Some(Duration::from_millis(300))).ok();
    Ok(read_len_prefixed(&mut s).unwrap_or_default())
}

/// `host[-serial:<s>]:` 前缀：指定 serial 用 host-serial、否则 host（任意设备）。forward 家族是
/// **host 层**服务（无需先切 transport），主机侧监听由 5037 server（mux）建立。
fn host_selector_prefix(serial: Option<&str>) -> String {
    match serial.filter(|s| !s.is_empty() && *s != "unknown") {
        Some(s) => format!("host-serial:{}:", s),
        None => "host:".to_string(),
    }
}

/// `adb forward [--no-rebind] <local> <remote>` 经 5037 server 建立（host 层：`adb_connect`+
/// `adb_status` 两个 OKAY，tcp:0 追加一个协议串回报实际端口）。`None`=server 不可达（可回退直连）；
/// `Some(Err)`=server 已接手但失败（绝不回退直连）。返回实际本地端点（`tcp:0` 时为真实端口）。
pub fn forward_add(
    serial: Option<&str>,
    local: &str,
    remote: &str,
    norebind: bool,
) -> Option<Result<String, String>> {
    let mut s = connect().ok()?;
    let prefix = host_selector_prefix(serial);
    let svc = if norebind {
        format!("{}forward:norebind:{};{}", prefix, local, remote)
    } else {
        format!("{}forward:{};{}", prefix, local, remote)
    };
    if send_request(&mut s, &svc).is_err() {
        return None;
    }
    // 增删走 adb_connect + adb_status：两个 OKAY；失败则单个 FAIL + 原因。
    match read_status(&mut s) {
        Ok(true) => {}
        Ok(false) => {
            let m = read_len_prefixed(&mut s).unwrap_or_default();
            return Some(Err(if m.is_empty() {
                format!("cannot bind '{}'", local)
            } else {
                m
            }));
        }
        Err(_) => return None,
    }
    if !matches!(read_status(&mut s), Ok(true)) {
        return Some(Err("forward 应答帧异常".to_string()));
    }
    // 仅 `tcp:0` 会追加一个协议串回报内核实际分配的端口。
    let want_port = local
        .strip_prefix("tcp:")
        .map(|p| p == "0")
        .unwrap_or(false);
    let reply = if want_port {
        s.set_read_timeout(Some(Duration::from_millis(300))).ok();
        read_len_prefixed(&mut s).unwrap_or_default()
    } else {
        String::new()
    };
    let reply = reply.trim();
    Some(Ok(if reply.is_empty() {
        local.to_string()
    } else {
        format!("tcp:{}", reply)
    }))
}

/// `adb forward --list` 经 5037 server 查询（host 层，一个 OKAY + 协议串：每行 `<serial> <local> <remote>`）。
pub fn forward_list() -> Option<String> {
    let mut s = connect().ok()?;
    send_request(&mut s, "host:list-forward").ok()?;
    if !read_status(&mut s).ok()? {
        return None;
    }
    read_len_prefixed(&mut s).ok()
}

/// `adb forward --remove <local>`（host 层 killforward：两个 OKAY）。
pub fn forward_remove(local: &str) -> Option<Result<(), String>> {
    let mut s = connect().ok()?;
    if send_request(&mut s, &format!("host:killforward:{}", local)).is_err() {
        return None;
    }
    match read_status(&mut s) {
        Ok(true) => {
            let _ = read_status(&mut s); // 第二个 OKAY（best-effort）
            Some(Ok(()))
        }
        Ok(false) => {
            let m = read_len_prefixed(&mut s).unwrap_or_default();
            Some(Err(if m.is_empty() {
                format!("listener '{}' not found", local)
            } else {
                m
            }))
        }
        Err(_) => None,
    }
}

/// `adb forward --remove-all`（host 层 killforward-all）。返回是否成功送达。
pub fn forward_remove_all() -> bool {
    let Ok(mut s) = connect() else {
        return false;
    };
    if send_request(&mut s, "host:killforward-all").is_err() {
        return false;
    }
    let ok = matches!(read_status(&mut s), Ok(true));
    let _ = read_status(&mut s);
    ok
}

/// `adb forward ...` 经 5037 server 处理：监听建在 server 里，增删查与官方 adb 同一份表。
/// `Some(code)`=已接手（成败都算）；`None`=server 不可达或参数不全，交调用方回退既有实现。
pub fn handle_forward(serial: Option<&str>, args: &[String]) -> Option<i32> {
    match args.first()?.as_str() {
        "--list" | "--list-forward" => {
            print!("{}", forward_list()?);
            let _ = std::io::stdout().flush();
            Some(0)
        }
        "--remove-all" => forward_remove_all().then_some(0),
        "--remove" => match forward_remove(args.get(1)?)? {
            Ok(()) => Some(0),
            Err(e) => {
                eprintln!("{}", e);
                Some(1)
            }
        },
        _ => {
            // [--no-rebind] LOCAL REMOTE
            let mut pos = 0usize;
            let mut norebind = false;
            while args.get(pos).map(String::as_str) == Some("--no-rebind") {
                norebind = true;
                pos += 1;
            }
            let local = args.get(pos)?;
            let remote = args.get(pos + 1)?;
            match forward_add(serial, local, remote, norebind)? {
                Ok(actual) => {
                    if local == "tcp:0" {
                        println!("{}", actual.strip_prefix("tcp:").unwrap_or(&actual));
                    }
                    Some(0)
                }
                Err(e) => {
                    eprintln!("{}", e);
                    Some(1)
                }
            }
        }
    }
}

/// `adb reverse [--no-rebind] <remote> <local>` 经 5037 server 建立（transport 之后发 `reverse:*`，
/// 由设备侧 adbd 应答；回连由 mux 读循环分发）。`None`=server 不可达；`Some(Err)`=已接手但失败。
pub fn reverse_add(
    serial: Option<&str>,
    remote: &str,
    local: &str,
    norebind: bool,
) -> Option<Result<String, String>> {
    if connect().is_err() {
        return None;
    }
    let service = if norebind {
        format!("reverse:forward:norebind:{};{}", remote, local)
    } else {
        format!("reverse:forward:{};{}", remote, local)
    };
    Some(reverse_request(serial, &service).map(|reply| {
        let t = reply.trim();
        if t.is_empty() {
            remote.to_string()
        } else {
            t.to_string()
        }
    }))
}

/// `adb reverse --list`（transport 之后 `reverse:list-forward`）。设备只回一个协议串
/// （`[4 位十六进制长度][每行 <serial> <remote> <local>]`，前面没有状态字），要剥掉长度前缀。
pub fn reverse_list(serial: Option<&str>) -> Option<String> {
    match capture_service(serial, "reverse:list-forward") {
        Some(Ok(out)) => Some(protocol_string_payload(&out).to_string()),
        _ => None,
    }
}

/// 取协议串的正文；不像协议串（太短 / 前缀不是十六进制）就原样返回。
fn protocol_string_payload(raw: &str) -> &str {
    let Some(len) = raw
        .get(..4)
        .and_then(|hex| usize::from_str_radix(hex, 16).ok())
    else {
        return raw;
    };
    raw.get(4..4 + len).unwrap_or(&raw[4..])
}

/// `adb reverse --remove <remote>`（`reverse:killforward:<remote>`）。
pub fn reverse_remove(serial: Option<&str>, remote: &str) -> Option<Result<(), String>> {
    if connect().is_err() {
        return None;
    }
    Some(reverse_request(serial, &format!("reverse:killforward:{}", remote)).map(|_| ()))
}

/// `adb reverse --remove-all`（`reverse:killforward-all`）。返回是否成功送达。
pub fn reverse_remove_all(serial: Option<&str>) -> bool {
    if connect().is_err() {
        return false;
    }
    reverse_request(serial, "reverse:killforward-all").is_ok()
}

/// `adb shell <cmd>` 经 mux server 执行（app_process server 等长驻进程）。
/// socket↔stdio 双向桥接，阻塞至设备关闭或本进程被杀。返回 `Some(code)`；连接失败返回 `None` 回退。
pub fn shell_command(serial: Option<&str>, command: &str) -> Option<i32> {
    let mut s = match connect_transport(serial) {
        Ok(s) => s,
        Err(TransportError::Unreachable) => return None,
        // 设备不在 / 未授权：与官方 `adb shell` 一样报原因、非零退出。
        Err(TransportError::Refused(msg)) => {
            eprintln!("adb: {}", msg);
            return Some(1);
        }
    };
    if send_request(&mut s, &format!("shell:{}", command)).is_err() {
        return None;
    }
    match read_status(&mut s) {
        Ok(true) => {}
        Ok(false) => {
            let msg = read_len_prefixed(&mut s).unwrap_or_default();
            if !msg.is_empty() {
                eprintln!("{}", msg);
            }
            return Some(1);
        }
        Err(_) => return None,
    }
    // 握手完成，进入长驻数据流（app_process server 可长时间静默）：清除控制阶段读超时。
    let _ = s.set_read_timeout(None);

    // stdin → socket（子线程）：scrcpy 的 app_process shell 一般不用 stdin，但保留以支持交互输入。
    let mut sock_in = match s.try_clone() {
        Ok(c) => c,
        Err(_) => return Some(1),
    };
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 8192];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if sock_in.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // socket → stdout（本线程阻塞）：设备关闭(EOF)即结束，进程随之退出。
    let mut stdout = std::io::stdout();
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stdout.write_all(&buf[..n]).is_err() || stdout.flush().is_err() {
                    break;
                }
            }
        }
    }
    Some(0)
}

/// `adb shell <cmd>` 经 mux server 执行并**捕获全部输出**为字符串（一问一答类命令，如 getprop）。
/// 与 `shell_command` 的区别：这里把设备输出收进 String 返回，而非桥接到本进程 stdout。
///
/// 先走 shell v2，设备不认 v2 才退回 legacy `shell:`；结果语义必须与直连
/// [`crate::adb_winusb_transport::AdbWinUsbDevice::shell_command`] 一致（退出码 0 回 stdout，
/// 非 0 回错），否则同一条命令经 5037 借道与直连会得出不同结论。
pub fn capture_shell_result(serial: Option<&str>, command: &str) -> Option<Result<String, String>> {
    let result = capture_shell_v2_or_legacy(serial, command);
    if let Some(Err(e)) = &result {
        crate::logger::log_line(&format!("[adb-mux-client] shell 失败：{}", e));
    }
    result
}

fn capture_shell_v2_or_legacy(
    serial: Option<&str>,
    command: &str,
) -> Option<Result<String, String>> {
    let v2 = format!("shell,v2,raw:{}", command);
    let legacy = || capture_service(serial, &format!("shell:{}", command));
    let bytes = match open_transport_service_detailed(serial, &v2) {
        Ok(conn) => match read_until_eof(conn, &v2) {
            Ok(b) => b,
            Err(e) => return Some(Err(e)),
        },
        Err(OpenError::Unreachable) => return None,
        Err(OpenError::Transport(e)) => return Some(Err(e)),
        // transport 已切过去、设备却不开这个服务：Android 7 以前的 adbd 不认 `shell,v2`，直接关流。
        Err(OpenError::Service(_)) => return legacy(),
    };
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    match decode_shell_v2(&bytes) {
        ShellV2Reply::Complete {
            stdout,
            stderr,
            exit_code,
        } => Some(if exit_code == 0 {
            Ok(text(&stdout))
        } else if !stderr.is_empty() {
            Err(text(&stderr))
        } else {
            Err(text(&stdout))
        }),
        ShellV2Reply::Unsupported => legacy(),
        ShellV2Reply::Broken(e) => Some(Err(e)),
    }
}

/// shell v2 响应的解码结果。判据与直连的 `shell_v2_streaming` 相同：一个包都没有、或首包类型
/// 非法，视为设备不支持 v2（回退 legacy）；已见过合法包却残缺，才是真错误。
#[derive(Debug, PartialEq, Eq)]
enum ShellV2Reply {
    Complete {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        exit_code: i32,
    },
    Unsupported,
    Broken(String),
}

fn decode_shell_v2(mut rest: &[u8]) -> ShellV2Reply {
    use crate::adb_winusb_transport::{parse_shell_v2_packet, ShellV2Kind};

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut saw_packet = false;
    while rest.len() >= 5 {
        let len = u32::from_le_bytes([rest[1], rest[2], rest[3], rest[4]]) as usize;
        if rest.len() < 5 + len {
            break;
        }
        let packet = match parse_shell_v2_packet(&rest[..5 + len]) {
            Ok(p) => p,
            Err(e) => return ShellV2Reply::Broken(e),
        };
        rest = &rest[5 + len..];
        match packet.kind {
            ShellV2Kind::Stdout => stdout.extend_from_slice(&packet.payload),
            ShellV2Kind::Stderr => stderr.extend_from_slice(&packet.payload),
            ShellV2Kind::Exit => {
                return ShellV2Reply::Complete {
                    stdout,
                    stderr,
                    exit_code: packet.exit_code().unwrap_or(0),
                };
            }
            ShellV2Kind::Invalid(kind) => {
                return if saw_packet {
                    ShellV2Reply::Broken(format!("invalid shell v2 packet kind {}", kind))
                } else {
                    ShellV2Reply::Unsupported
                };
            }
            _ => {}
        }
        saw_packet = true;
    }
    if !saw_packet {
        return ShellV2Reply::Unsupported;
    }
    if !rest.is_empty() {
        return ShellV2Reply::Broken("shell v2 stream ended with a truncated packet".into());
    }
    ShellV2Reply::Broken("shell v2 stream ended without exit packet".into())
}

/// 兼容旧调用方：失败返回 `None`，不暴露错误细节。
pub fn capture_shell(serial: Option<&str>, command: &str) -> Option<String> {
    match capture_shell_result(serial, command) {
        Some(Ok(out)) => Some(out),
        _ => None,
    }
}

/// 经 host transport 打开 `sync:` 并按 Sync v1 推送文件。`None`=mux 不可用，可安全回退直连；
/// `Some(Err)`=mux 已接管但失败，不得再直连抢同一 USB 句柄。
pub fn push(
    serial: Option<&str>,
    local_path: &Path,
    remote_path: &str,
) -> Option<Result<(), String>> {
    let mut stream = match open_transport_service(serial, "sync:")? {
        Ok(s) => s,
        Err(e) => return Some(Err(e)),
    };
    stream.set_read_timeout(Some(Duration::from_secs(30)));

    let result = push_sync_file(&mut stream, serial, local_path, remote_path);
    if let Err(e) = &result {
        crate::logger::log_line(&format!("[adb-mux-client] sync push 失败: {}", e));
    }
    Some(result)
}

/// 经 host transport 打开 `sync:`，并按 ADB Sync v1 协议拉取一个文件。
pub fn pull(
    serial: Option<&str>,
    remote_path: &str,
    local_path: &Path,
) -> Option<Result<(), String>> {
    let mut stream = match open_transport_service(serial, "sync:")? {
        Ok(s) => s,
        Err(e) => return Some(Err(e)),
    };
    stream.set_read_timeout(Some(Duration::from_secs(30)));

    let result = pull_sync_file(&mut stream, serial, remote_path, local_path);
    if let Err(e) = &result {
        crate::logger::log_line(&format!("[adb-mux-client] sync pull 失败: {}", e));
    }
    Some(result)
}

fn push_sync_file(
    stream: &mut Conn,
    serial: Option<&str>,
    local_path: &Path,
    remote_path: &str,
) -> Result<(), String> {
    let mut file = File::open(local_path)
        .map_err(|e| format!("打开本地文件失败 '{}': {}", local_path.display(), e))?;

    // 传输进度接进 xfer 快照（与直连 WinUSB push 同一套，见 embed::Xfer）：走 mux 的
    // push 同样能被宿主的 `fastboot.transfer_snapshot` 轮询到实时进度。
    let push_total = file.metadata().map(|m| m.len()).unwrap_or(0);
    let xfer = crate::embed::XferRun::start(serial, push_total);

    // 与现有 WinUSB 传输保持同一套 Sync v1 SEND 形态：路径和 mode 作为
    // `remote,mode` 的 UTF-8 字符串发送，避免不同 transport 在设备端表现不一致。
    let send_spec = format!("{},{}", remote_path, 33206u32);
    write_sync_record(stream, b"SEND", send_spec.as_bytes())?;

    let mut chunk = vec![0u8; SYNC_CHUNK_SIZE];
    loop {
        let bytes_read = file
            .read(&mut chunk)
            .map_err(|e| format!("读取本地文件失败 '{}': {}", local_path.display(), e))?;
        if bytes_read == 0 {
            break;
        }
        write_sync_record(stream, b"DATA", &chunk[..bytes_read])?;
        xfer.add(bytes_read as u64);
    }

    let mtime = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "获取文件时间失败".to_string())?
        .as_secs() as u32;
    // DONE 与 SEND/DATA 不同，Sync v1 规定其后直接跟 mtime，不带长度字段。
    stream.write_all(b"DONE").map_err(|e| e.to_string())?;
    stream
        .write_all(&mtime.to_le_bytes())
        .map_err(|e| e.to_string())?;
    read_sync_status(stream)
}

fn pull_sync_file(
    stream: &mut Conn,
    serial: Option<&str>,
    remote_path: &str,
    local_path: &Path,
) -> Result<(), String> {
    let mut file = File::create(local_path)
        .map_err(|e| format!("创建本地文件失败 '{}': {}", local_path.display(), e))?;

    // 回读进度接进 xfer 快照（与直连 WinUSB pull 同一套，见 embed::Xfer）：走 mux 的
    // pull 同样能被宿主的 `fastboot.transfer_snapshot` 轮询到实时进度。RECV 不带文件大小，
    // 总量报 0，由宿主按期望大小折算百分比。
    let xfer = crate::embed::XferRun::start(serial, 0);

    write_sync_record(stream, b"RECV", remote_path.as_bytes())?;

    loop {
        let mut tag = [0u8; 4];
        stream
            .read_exact(&mut tag)
            .map_err(|e| format!("读取 pull sync 标记失败: {}", e))?;
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .map_err(|e| format!("读取 pull sync 长度失败: {}", e))?;
        let len = u32::from_le_bytes(len_buf) as usize;

        match &tag {
            b"DATA" => {
                if len > SYNC_DATA_MAX {
                    return Err(format!("sync DATA 过大: {} 字节", len));
                }
                let mut payload = vec![0u8; len];
                stream
                    .read_exact(&mut payload)
                    .map_err(|e| format!("读取 pull 数据失败: {}", e))?;
                file.write_all(&payload)
                    .map_err(|e| format!("写入本地文件失败 '{}': {}", local_path.display(), e))?;
                xfer.add(len as u64);
            }
            b"DONE" => return Ok(()),
            b"FAIL" => {
                if len > SYNC_STATUS_MAX {
                    return Err(format!("sync FAIL 消息过大: {} 字节", len));
                }
                let mut payload = vec![0u8; len];
                stream
                    .read_exact(&mut payload)
                    .map_err(|e| format!("读取 pull 失败原因失败: {}", e))?;
                let reason = String::from_utf8_lossy(&payload).trim().to_string();
                return Err(if reason.is_empty() {
                    "设备拒绝 sync pull".to_string()
                } else {
                    format!("设备拒绝 sync pull: {}", reason)
                });
            }
            other => return Err(format!("未知 sync pull 标记: {:?}", other)),
        }
    }
}

/// ADB Sync v1 的 record：4 字节 tag + 4 字节 little-endian 长度 + payload。
fn write_sync_record(stream: &mut impl Write, tag: &[u8; 4], payload: &[u8]) -> Result<(), String> {
    let len = u32::try_from(payload.len()).map_err(|_| "sync 记录过大".to_string())?;
    stream.write_all(tag).map_err(|e| e.to_string())?;
    stream
        .write_all(&len.to_le_bytes())
        .map_err(|e| e.to_string())?;
    stream.write_all(payload).map_err(|e| e.to_string())
}

fn read_sync_status(stream: &mut impl Read) -> Result<(), String> {
    let mut tag = [0u8; 4];
    stream
        .read_exact(&mut tag)
        .map_err(|e| format!("读取 sync 状态失败: {}", e))?;
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("读取 sync 状态长度失败: {}", e))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > SYNC_STATUS_MAX {
        return Err(format!("sync 状态消息过大: {} 字节", len));
    }
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .map_err(|e| format!("读取 sync 状态正文失败: {}", e))?;

    match &tag {
        b"OKAY" => Ok(()),
        b"FAIL" => {
            let reason = String::from_utf8_lossy(&payload).trim().to_string();
            Err(if reason.is_empty() {
                "设备拒绝 sync push".to_string()
            } else {
                format!("设备拒绝 sync push: {}", reason)
            })
        }
        other => Err(format!("未知 sync 状态: {:?}", other)),
    }
}

/// 请 5037 上的 server 干净退出（`host:kill`：释放端口与它持有的设备 USB 句柄）。无 server 时静默。
///
/// **调用前先确认端口上是自己人。** 对外来 adb server 发 kill 会打断别的工具正在跑的会话；
/// 只有「要腾出 5037 给自研 mux」且占用者不是 adb server 时才该动它。
pub fn kill_server() {
    if let Ok(mut s) = connect() {
        let _ = send_request(&mut s, "host:kill");
        let _ = read_status(&mut s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `reverse:list-forward` 设备只回协议串：长度前缀要剥掉，空列表是 `0000`。
    #[test]
    fn reverse_list_strips_the_protocol_length_prefix() {
        assert_eq!(
            protocol_string_payload("0023A7AB3AB5 localabstract:x tcp:27183\n"),
            "A7AB3AB5 localabstract:x tcp:27183\n"
        );
        assert_eq!(protocol_string_payload("0000"), "");
        assert_eq!(protocol_string_payload("no prefix"), "no prefix");
    }

    /// server 回 FAIL 是有效答案，不能被当成「server 不在」去白等；只有说不上话才是 Unreachable。
    #[test]
    fn refused_transport_keeps_the_servers_reason() {
        assert_eq!(
            TransportError::Refused("device 'ABC' not found".into()).message(),
            "device 'ABC' not found"
        );
        assert_ne!(
            TransportError::Unreachable,
            TransportError::Refused(String::new())
        );
    }

    #[test]
    fn transport_req_picks_serial_or_any() {
        assert_eq!(transport_req(Some("ABC123")), "host:transport:ABC123");
        assert_eq!(transport_req(None), "host:transport-any");
        assert_eq!(transport_req(Some("")), "host:transport-any");
        assert_eq!(transport_req(Some("unknown")), "host:transport-any");
    }

    #[test]
    fn sync_record_uses_little_endian_length() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"DATA");
        bytes.extend_from_slice(&(3u32).to_le_bytes());
        bytes.extend_from_slice(b"abc");
        assert_eq!(&bytes[..4], b"DATA");
        assert_eq!(&bytes[4..8], &[3, 0, 0, 0]);
        assert_eq!(&bytes[8..], b"abc");
    }

    #[test]
    fn sync_status_limit_is_bounded() {
        const {
            assert!(SYNC_STATUS_MAX >= 1024);
            assert!(SYNC_CHUNK_SIZE < SYNC_STATUS_MAX);
        }
    }

    /// 只有确证 5037 上没人才允许直连 WinUSB：判反即「投屏时重启稳定报 0x80070005」。
    /// 除 Absent 一律借道；Unknown 看近期是否确认过，从没确认过的多半是无关程序占端口，放行直连。
    #[test]
    fn only_a_confirmed_empty_port_permits_a_direct_connection() {
        use AdbServerOnPort::*;

        for confirmed in [true, false] {
            assert!(
                !server_holds_device_handle(Absent, confirmed),
                "端口上连不上人，直连是安全的"
            );
            for kind in [RmfMux, ForeignAdb] {
                assert!(
                    server_holds_device_handle(kind, confirmed),
                    "{kind:?} 独占设备句柄，必须借道而不是直连"
                );
            }
        }

        // 认不出身份：刚确认过 server 就当它还在（多半只是忙得没答上这一次）
        assert!(server_holds_device_handle(Unknown, true));
        // 从没确认过：那多半是个占着 5037 的无关程序，设备句柄是空的
        assert!(!server_holds_device_handle(Unknown, false));
    }

    /// 确认阶段的读超时必须比热路径那次宽：热路径 120ms 是为了 UI 不卡，
    /// 而「端口上到底有没有 server」这种结论值得多等一会儿再下。
    #[test]
    fn confirmation_waits_longer_than_the_hot_path_probe() {
        const {
            assert!(CONFIRM_READ_TIMEOUT.as_millis() > PROBE_READ_TIMEOUT.as_millis());
        }
    }

    /// 服务开流可能包含一次 10s open 超时和一次重建后的 10s open；客户端等待
    /// host OKAY 的窗口必须覆盖这段 server 自愈路径，不能回到 2s 控制超时。
    #[test]
    fn service_open_wait_covers_mux_rebuild_window() {
        const {
            assert!(SERVICE_OPEN_READ_TIMEOUT.as_secs() > 20);
            assert!(SERVICE_OPEN_READ_TIMEOUT.as_secs() > CONTROL_READ_TIMEOUT.as_secs());
        }
    }

    fn v2_packet(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![kind];
        p.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn shell_v2_stdout_and_exit_code_are_decoded() {
        let mut bytes = v2_packet(1, b"annibale\n");
        bytes.extend(v2_packet(3, &[0]));
        assert_eq!(
            decode_shell_v2(&bytes),
            ShellV2Reply::Complete {
                stdout: b"annibale\n".to_vec(),
                stderr: Vec::new(),
                exit_code: 0,
            }
        );
    }

    /// 属性不存在时 getprop 只回退出包：这是合法的空值，不能被当成「设备不支持 v2」
    /// 再去 legacy 通道重跑一遍，更不能当成错误。
    #[test]
    fn shell_v2_exit_without_output_is_a_legit_empty_value() {
        assert_eq!(
            decode_shell_v2(&v2_packet(3, &[0])),
            ShellV2Reply::Complete {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code: 0,
            }
        );
    }

    #[test]
    fn shell_v2_nonzero_exit_keeps_stderr_separate() {
        let mut bytes = v2_packet(2, b"Failure [not installed for 0]\n");
        bytes.extend(v2_packet(3, &[1]));
        assert_eq!(
            decode_shell_v2(&bytes),
            ShellV2Reply::Complete {
                stdout: Vec::new(),
                stderr: b"Failure [not installed for 0]\n".to_vec(),
                exit_code: 1,
            }
        );
    }

    /// 长度字段含 ≥0x80 的字节（输出 ≥128 字节）也必须按字节正确解帧。
    #[test]
    fn shell_v2_length_with_high_bytes_is_decoded() {
        let payload = vec![b'x'; 200];
        let mut bytes = v2_packet(1, &payload);
        bytes.extend(v2_packet(3, &[0]));
        match decode_shell_v2(&bytes) {
            ShellV2Reply::Complete { stdout, .. } => assert_eq!(stdout, payload),
            other => panic!("应解出完整响应: {other:?}"),
        }
    }

    /// 不认 v2 的设备会忽略 `v2` 参数直接回原始文本：首字节不是合法包类型，要回退 legacy。
    #[test]
    fn raw_legacy_output_and_empty_reply_fall_back_to_legacy() {
        assert_eq!(decode_shell_v2(b"annibale\n"), ShellV2Reply::Unsupported);
        assert_eq!(decode_shell_v2(b""), ShellV2Reply::Unsupported);
    }

    #[test]
    fn shell_v2_stream_cut_short_is_an_error() {
        let no_exit = v2_packet(1, b"partial");
        assert!(matches!(decode_shell_v2(&no_exit), ShellV2Reply::Broken(_)));

        let mut truncated = v2_packet(1, b"ok");
        truncated.extend_from_slice(&[1, 9, 0, 0, 0, b'a']);
        assert!(matches!(
            decode_shell_v2(&truncated),
            ShellV2Reply::Broken(_)
        ));
    }
}
