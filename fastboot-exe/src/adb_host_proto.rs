//! 官方 ADB host 协议（127.0.0.1:5037）前端——与官方 adb 客户端那套线上契约的**唯一**实现。
//!
//! 本项目有两个 5037 服务端：经典 [`crate::adb_server`] 与单连接多路复用的
//! [`crate::adb_mux_server`]（投屏子进程与 GUI 进程内常驻共用）。它们背后的设备后端不同，但对
//! 客户端说的是同一套协议，所以帧编解码、请求分类和**连接生命周期**只在这里实现一份，由
//! [`HostBackend`] 把「这台设备怎么开」交回各服务端。
//!
//! 三条以 platform-tools 36.0.2 实测为准、踩了就是「官方 adb 全线不可用」的契约：
//!
//! 1. **一次性 host 服务应答完必须关连接。** 官方客户端每条命令都新建连接、先问 `host:version`，
//!    读完应答后调 `ReadOrderlyShutdown` **阻塞等 EOF**。服务端要是继续留在读循环里等下一条请求，
//!    客户端就永久挂起——现象是连 `adb devices` 都没有输出、只会超时，而不是报错。
//! 2. **切 transport 用的是 `host:tport:*`，不是 `host:transport-*`。** 官方客户端只发
//!    `host:tport:any|usb|local`、`host:tport:serial:<serial>`（应答 `OKAY` + 8 字节小端
//!    transport id）或 `host:transport-id:<id>`（只应答 `OKAY`）。不认 tport 就等于除
//!    `adb devices` 外全部失败。`host:transport-*` 是老写法，本项目自研 client 仍在用，继续保留。
//! 3. **forward 家族的应答帧数不一样。** `host:forward:*` / `host:killforward*` 走
//!    `adb_connect` + `adb_status`，要 **两个 OKAY**（其后可选一个协议串回报实际端口）；
//!    `host:list-forward` 走 `adb_query`，只要 **一个 OKAY + 协议串**。发错帧数客户端会错位解析。
//!
//! `reverse:*` 不在此列：它是 transport 之后的 local 服务，由设备侧 adbd 应答，服务端只需
//! 把流原样桥接（scrcpy 的隧道正是这么跑起来的）。

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// 上报的 server 协议版本（4 位十六进制）。必须与官方 `ADB_SERVER_VERSION` 一致取 0x29(=41)：
/// 客户端发现版本不一致会 `host:kill` 掉我们再拉自己的 server，从而抢走设备 USB 句柄。
pub const SERVER_VERSION_HEX: &str = "0029";

/// 单条 host 请求的最大长度（4 位十六进制长度前缀，理论上限 0xFFFF）。
const MAX_MESSAGE_LEN: usize = 0xFFFF;

/// track-devices 的轮询间隔。
const TRACK_POLL_INTERVAL: Duration = Duration::from_millis(1000);

// ============================ 官方口径的错误文案 ============================
// 客户端与各种上层工具会按文本匹配这些串（例如等待设备的脚本），不要改写成中文。

pub const ERR_NO_DEVICES: &str = "no devices/emulators found";
pub const ERR_MULTIPLE_DEVICES: &str = "more than one device/emulator";
pub const ERR_DEVICE_UNAUTHORIZED: &str = "device unauthorized";

pub fn err_device_not_found(serial: &str) -> String {
    format!("device '{}' not found", serial)
}

// ============================ 帧编解码 ============================

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// 读取一条请求：`[4 位十六进制长度][payload]`。
pub fn read_message<R: Read>(r: &mut R) -> io::Result<String> {
    let mut len_hex = [0u8; 4];
    r.read_exact(&mut len_hex)?;
    let len_str = std::str::from_utf8(&len_hex).map_err(|_| invalid("长度前缀非 ASCII"))?;
    let len = usize::from_str_radix(len_str, 16).map_err(|_| invalid("长度前缀非十六进制"))?;
    if len > MAX_MESSAGE_LEN {
        return Err(invalid("请求过长"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// 写 `[4 位十六进制长度][data]`（超过 0xFFFF 会截断以保帧完整）。长度前缀与内容拼成一次写出：
/// 客户端与服务端都开了 `TCP_NODELAY`，分两次写会多出一个只有 4 字节的报文段。
pub fn write_len_prefixed<W: Write>(w: &mut W, data: &str) -> io::Result<()> {
    let mut bytes = data.as_bytes();
    if bytes.len() > MAX_MESSAGE_LEN {
        bytes = &bytes[..MAX_MESSAGE_LEN];
    }
    let mut frame = Vec::with_capacity(4 + bytes.len());
    frame.extend_from_slice(format!("{:04x}", bytes.len()).as_bytes());
    frame.extend_from_slice(bytes);
    w.write_all(&frame)
}

pub fn write_okay<W: Write>(w: &mut W) -> io::Result<()> {
    w.write_all(b"OKAY")
}

pub fn write_okay_data<W: Write>(w: &mut W, data: &str) -> io::Result<()> {
    write_okay(w)?;
    write_len_prefixed(w, data)
}

pub fn write_fail<W: Write>(w: &mut W, reason: &str) -> io::Result<()> {
    w.write_all(b"FAIL")?;
    write_len_prefixed(w, reason)
}

/// `host:tport:*` 的附加应答：8 字节**小端** transport id，紧跟在 OKAY 之后、客户端发服务之前。
pub fn write_transport_id<W: Write>(w: &mut W, id: u64) -> io::Result<()> {
    w.write_all(&id.to_le_bytes())
}

// ============================ transport id 注册表 ============================

/// 序列号 → transport id 的进程内注册表。transport id 属于一次 transport 实例：设备拔出
/// 后旧 id 必须失效，重新插入（即使序列号相同）也必须拿到新的、单调递增且不复用的 id。
/// `adb -t <id>` 与 `devices -l` 的 `transport_id:` 都指它。**不能拿设备在枚举里的下标
/// 充数**：拔插一台设备会让其余设备的 id 整体平移，客户端手里的 `-t` 就指到别的设备上了。
fn id_registry() -> &'static Mutex<HashMap<String, u64>> {
    static REG: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

static NEXT_TRANSPORT_ID: AtomicU64 = AtomicU64::new(1);

/// 取某序列号的 transport id（首次见到即分配）。
pub fn transport_id_of(serial: &str) -> u64 {
    let mut reg = id_registry().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(id) = reg.get(serial) {
        return *id;
    }
    let id = NEXT_TRANSPORT_ID.fetch_add(1, Ordering::Relaxed);
    reg.insert(serial.to_string(), id);
    id
}

/// 用一次设备枚举刷新 transport 实例集合。
///
/// 5037 的 `transport_id` 不是序列号的永久别名。后端每次完成枚举时都应调用本函数：不在
/// 当前集合中的序列号立即移除（使其旧 id 失效），当前新出现的序列号分配新的 id。分配器
/// 只增不减，因而拔插重连不会把旧 `-t` 指向新实例。
pub fn refresh_transport_ids<S>(serials: &[S])
where
    S: AsRef<str>,
{
    let mut reg = id_registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.retain(|serial, _| serials.iter().any(|s| s.as_ref() == serial));
    for serial in serials {
        let serial = serial.as_ref();
        if !reg.contains_key(serial) {
            let id = NEXT_TRANSPORT_ID.fetch_add(1, Ordering::Relaxed);
            reg.insert(serial.to_string(), id);
        }
    }
}

/// transport id → 序列号。分配过才有；没有即客户端拿的是过期 id。
pub fn serial_of_transport_id(id: u64) -> Option<String> {
    let reg = id_registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.iter().find(|(_, v)| **v == id).map(|(k, _)| k.clone())
}

// ============================ 请求模型 ============================

/// 客户端选择目标设备的方式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// 未指定（`host:` / `transport-any` / `tport:any`）：唯一一台设备，多台则歧义。
    Any,
    /// `transport-usb` / `tport:usb`。本项目只有 USB 设备，语义同 [`Selector::Any`]。
    Usb,
    /// `transport-local` / `tport:local`：网络（emulator/tcpip）设备，本项目不提供。
    Local,
    Serial(String),
    TransportId(u64),
}

impl Selector {
    /// 客户端明确点名的序列号（`-s`）。`transport-id` 要查注册表，故不在此返回。
    pub fn explicit_serial(&self) -> Option<&str> {
        match self {
            Selector::Serial(s)
                if !s.is_empty() && s != "unknown" && s != "any" && s != "usb" && s != "local" =>
            {
                Some(s.as_str())
            }
            _ => None,
        }
    }

    /// 归一成「按序列号筛选」的意图：后端拿它去匹配枚举结果。`None` = 任意设备。
    /// `transport-id` 在这里解开成它当初绑定的序列号（解不开说明 id 已过期）。
    pub fn wanted_serial(&self) -> Result<Option<String>, String> {
        match self {
            Selector::Any | Selector::Usb => Ok(None),
            // 本项目只有 WinUSB transport；`-e` 明确要模拟器/网络设备时如实说没有，
            // 而不是悄悄把 USB 设备顶上去（那会让客户端在错误的设备上操作）。
            Selector::Local => Err(ERR_NO_DEVICES.to_string()),
            // 空串 / "unknown" 等占位视为「任意设备」（自研 client 与老脚本会这么传）。
            Selector::Serial(_) => Ok(self.explicit_serial().map(str::to_string)),
            Selector::TransportId(id) => serial_of_transport_id(*id)
                .map(Some)
                .ok_or_else(|| format!("no device with transport id {}", id)),
        }
    }
}

/// forward 家族（主机侧监听、转发到设备端点）。`reverse:` 方向由设备实现，不走这里。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardRequest {
    /// `forward[:norebind]:<local>;<remote>`
    Add {
        norebind: bool,
        local: String,
        remote: String,
    },
    /// `killforward:<local>`
    Remove { local: String },
    /// `killforward-all`
    RemoveAll,
    /// `list-forward`
    List,
}

/// forward 家族的成功应答。帧数不同，见模块头契约 3。
pub enum ForwardReply {
    /// 两个 OKAY，无附加数据。
    Done,
    /// 两个 OKAY + 协议串（`forward tcp:0` 时回报实际分配到的端口）。
    DonePort(u16),
    /// 一个 OKAY + 协议串（每行 `<serial> <local> <remote>`）。
    List(String),
}

/// 一次性 host 服务。应答完连接必须关闭（契约 1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostSvc {
    Version,
    /// `host:host-features`：本 server 自己的特性集。
    HostFeatures,
    /// `host:features`：**设备**的特性集（与本机取交集），需要先解析出目标设备。
    Features,
    Devices {
        long: bool,
    },
    GetState,
    GetSerialNo,
    GetDevPath,
    Kill,
    Forward(ForwardRequest),
    /// `host:connect:<spec>` / `host:disconnect:<spec>` / `host:reconnect[:...]`
    Connect(String),
    Disconnect(String),
    Reconnect(String),
    /// 本项目 mux server 的身份标识。官方 server 与本项目其余 server 对它回 FAIL，
    /// 探测方据此判断 5037 上跑的是谁（见 `adb_mux_client::classify_server_on_port`）。
    MuxInfo,
    /// 认识但本实现没有的服务：必须明确 FAIL，不能静默劣化成别的行为。
    Unsupported(String),
}

/// 一条 host 请求的分类结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// 一次性服务：应答后关连接。
    Host { svc: HostSvc, selector: Selector },
    /// 切 transport：应答后同一条连接上紧跟一条 local 服务。
    Transport {
        selector: Selector,
        /// `tport:*` 要在 OKAY 之后回 8 字节 transport id；`transport*` 不回。
        echo_id: bool,
    },
    /// 长连接：设备列表变化时推帧。
    TrackDevices { long: bool },
    /// 认不出：回 FAIL。
    Unknown,
}

/// 把一条 wire 请求分类。
pub fn parse_request(req: &str) -> Request {
    // ---- 先剥掉选择目标设备的前缀，剩下的才是服务名 ----
    let (selector, svc) = match split_selector(req) {
        Some(pair) => pair,
        None => return Request::Unknown,
    };

    // ---- transport 切换（只在 host 层出现）----
    if let Some(rest) = svc.strip_prefix("tport:") {
        return match parse_tport_target(rest) {
            Some(sel) => Request::Transport {
                selector: sel,
                echo_id: true,
            },
            None => Request::Unknown,
        };
    }
    if let Some(serial) = svc.strip_prefix("transport:") {
        return Request::Transport {
            selector: Selector::Serial(serial.to_string()),
            echo_id: false,
        };
    }
    if let Some(id) = svc.strip_prefix("transport-id:") {
        return match id.parse::<u64>() {
            Ok(id) => Request::Transport {
                selector: Selector::TransportId(id),
                echo_id: false,
            },
            Err(_) => Request::Unknown,
        };
    }
    match svc {
        "transport-any" => {
            return Request::Transport {
                selector: Selector::Any,
                echo_id: false,
            }
        }
        "transport-usb" => {
            return Request::Transport {
                selector: Selector::Usb,
                echo_id: false,
            }
        }
        "transport-local" => {
            return Request::Transport {
                selector: Selector::Local,
                echo_id: false,
            }
        }
        "track-devices" => return Request::TrackDevices { long: false },
        "track-devices-l" => return Request::TrackDevices { long: true },
        _ => {}
    }

    Request::Host {
        svc: parse_host_svc(svc),
        selector,
    }
}

/// 剥掉 `host:` / `host-serial:<serial>:` / `host-transport-id:<id>:` / `host-usb:` /
/// `host-local:` 前缀，返回（目标选择器, 服务名）。
fn split_selector(req: &str) -> Option<(Selector, &str)> {
    if let Some(rest) = req.strip_prefix("host-serial:") {
        // 序列号可能是 `192.168.1.2:5555` 这种带冒号的形态，不能简单按第一个冒号切：
        // 从左往右逐个冒号试，取第一处「尾巴能认出是服务名」的切法。
        return split_at_known_service(rest)
            .map(|(serial, svc)| (Selector::Serial(serial.to_string()), svc));
    }
    if let Some(rest) = req.strip_prefix("host-transport-id:") {
        let (id, svc) = rest.split_once(':')?;
        let id = id.parse::<u64>().ok()?;
        return Some((Selector::TransportId(id), svc));
    }
    if let Some(rest) = req.strip_prefix("host-usb:") {
        return Some((Selector::Usb, rest));
    }
    if let Some(rest) = req.strip_prefix("host-local:") {
        return Some((Selector::Local, rest));
    }
    if let Some(rest) = req.strip_prefix("host:") {
        return Some((Selector::Any, rest));
    }
    None
}

/// 逐个冒号尝试切分，取第一处尾巴能被 [`parse_host_svc`] 认出的切法。
fn split_at_known_service(rest: &str) -> Option<(&str, &str)> {
    let mut last: Option<(&str, &str)> = None;
    for (i, _) in rest.match_indices(':') {
        let (head, tail) = (&rest[..i], &rest[i + 1..]);
        if head.is_empty() {
            continue;
        }
        last = Some((head, tail));
        if !matches!(parse_host_svc(tail), HostSvc::Unsupported(_)) {
            return Some((head, tail));
        }
    }
    // 一个都认不出：按最后一处冒号切，让上层以 Unsupported 明确 FAIL（而不是整条请求 Unknown，
    // 那样错误文案会丢掉服务名）。
    last
}

/// `tport:` 之后的目标。
fn parse_tport_target(rest: &str) -> Option<Selector> {
    if let Some(serial) = rest.strip_prefix("serial:") {
        return Some(Selector::Serial(serial.to_string()));
    }
    if let Some(id) = rest.strip_prefix("id:") {
        return id.parse::<u64>().ok().map(Selector::TransportId);
    }
    match rest {
        "any" => Some(Selector::Any),
        "usb" => Some(Selector::Usb),
        "local" => Some(Selector::Local),
        _ => None,
    }
}

fn parse_host_svc(svc: &str) -> HostSvc {
    if let Some(f) = parse_forward_service(svc) {
        return HostSvc::Forward(f);
    }
    if let Some(spec) = svc.strip_prefix("connect:") {
        return HostSvc::Connect(spec.to_string());
    }
    if let Some(spec) = svc.strip_prefix("disconnect:") {
        return HostSvc::Disconnect(spec.to_string());
    }
    if svc == "disconnect" {
        return HostSvc::Disconnect(String::new());
    }
    if let Some(spec) = svc.strip_prefix("reconnect:") {
        return HostSvc::Reconnect(spec.to_string());
    }
    match svc {
        "version" => HostSvc::Version,
        "host-features" => HostSvc::HostFeatures,
        "features" => HostSvc::Features,
        "devices" => HostSvc::Devices { long: false },
        "devices-l" => HostSvc::Devices { long: true },
        "get-state" => HostSvc::GetState,
        "get-serialno" => HostSvc::GetSerialNo,
        "get-devpath" => HostSvc::GetDevPath,
        "kill" => HostSvc::Kill,
        "reconnect" => HostSvc::Reconnect(String::new()),
        "rmf-mux-info" => HostSvc::MuxInfo,
        other => HostSvc::Unsupported(other.to_string()),
    }
}

/// 认 forward 家族。`host:` 与 transport 之后两处都会用到（官方 `adb forward` 是先切
/// transport 再发 `host:forward:...`，`adb forward --list` 则不切）。
pub fn parse_forward_service(svc: &str) -> Option<ForwardRequest> {
    if svc == "list-forward" {
        return Some(ForwardRequest::List);
    }
    if svc == "killforward-all" {
        return Some(ForwardRequest::RemoveAll);
    }
    if let Some(local) = svc.strip_prefix("killforward:") {
        let local = local.trim();
        if local.is_empty() {
            return None;
        }
        return Some(ForwardRequest::Remove {
            local: local.to_string(),
        });
    }
    let rest = svc.strip_prefix("forward:")?;
    let (norebind, pair) = match rest.strip_prefix("norebind:") {
        Some(r) => (true, r),
        None => (false, rest),
    };
    let (local, remote) = pair.split_once(';')?;
    if local.is_empty() || remote.is_empty() {
        return None;
    }
    Some(ForwardRequest::Add {
        norebind,
        local: local.to_string(),
        remote: remote.to_string(),
    })
}

/// 按选择器从枚举到的序列号里挑出唯一一台设备。三个 server 的设备选择判据必须完全一致，
/// 否则同一条 `-s` / `-t` 在不同 server 上会指到不同设备；判据只此一份。
pub fn pick_serial(selector: &Selector, serials: &[String]) -> Result<String, String> {
    // 点了名就按官方口径报「device 'X' not found」，哪怕一台设备都没有——脚本等的正是这句。
    match selector.wanted_serial()? {
        Some(want) => serials
            .iter()
            .find(|s| **s == want)
            .cloned()
            .ok_or_else(|| err_device_not_found(&want)),
        None => match serials {
            [] => Err(ERR_NO_DEVICES.to_string()),
            [only] => Ok(only.clone()),
            _ => Err(ERR_MULTIPLE_DEVICES.to_string()),
        },
    }
}

// ============================ 后端接口 ============================

/// 一个 5037 服务端要提供的设备侧能力。协议层只管说话，怎么开设备由实现方决定。
pub trait HostBackend {
    /// 日志前缀，如 `[adb-mux-server]`。
    fn log_tag(&self) -> &'static str;

    /// 设备列表 wire 文本（每行 `序列号\t状态[ 附加字段]`，含结尾换行）。
    fn devices(&self, long: bool) -> String;

    /// 把选择器解析成唯一目标设备的序列号；失败返回官方口径文案。
    fn resolve(&self, selector: &Selector) -> Result<String, String>;

    /// 设备状态（`device` / `recovery` / `unauthorized` / `offline`）。
    fn state(&self, selector: &Selector) -> Result<String, String>;

    /// 设备特性集（本机与设备的交集，见 [`crate::adb_protocol::negotiated_features`]）。
    fn device_features(&self, selector: &Selector) -> Result<String, String>;

    /// `host:kill`：让位。返回即表示已处理（多数实现会在此结束进程）。
    fn kill(&self);

    /// transport 之后的 local 服务：连接交给后端接管。
    fn serve_local(&self, stream: TcpStream, selector: Selector, svc: &str) -> io::Result<()>;

    /// forward 家族。默认不支持——主机侧监听要能随时向设备开新 stream，
    /// 只有 mux 那种常驻读循环做得到；做不到就明确 FAIL，不静默劣化。
    fn forward(&self, _selector: &Selector, _req: &ForwardRequest) -> Result<ForwardReply, String> {
        Err("this adb server does not support host-side forward".to_string())
    }

    /// 是否本项目 mux server（只影响 `host:rmf-mux-info` 的身份应答）。
    fn is_rmf_mux(&self) -> bool {
        false
    }

    /// track-devices 长连接是否还该继续（服务端被要求让位时置 false）。
    fn keep_serving(&self) -> bool {
        true
    }
}

// ============================ 连接驱动 ============================

/// 服务一条客户端连接：读一条请求，按其类别决定是「应答后关连接」还是「把连接交出去」。
///
/// **每条连接只处理一条 host 请求**，这不是简化而是契约（模块头 1）：官方客户端读完应答就等
/// EOF，服务端多留一秒都是挂死。transport / track-devices 例外——它们本就是长连接。
pub fn serve_connection<B: HostBackend + ?Sized>(
    mut stream: TcpStream,
    backend: &B,
) -> io::Result<()> {
    let _ = stream.set_nodelay(true);
    let req = match read_message(&mut stream) {
        Ok(r) => r,
        Err(_) => return Ok(()), // 客户端断开 / 坏帧
    };

    match parse_request(&req) {
        Request::Host { svc, selector } => answer_host(&mut stream, backend, &svc, &selector),
        Request::Transport { selector, echo_id } => {
            serve_transport(stream, backend, selector, echo_id)
        }
        Request::TrackDevices { long } => {
            write_okay(&mut stream)?;
            serve_track_devices(&mut stream, backend, long)
        }
        Request::Unknown => write_fail(&mut stream, &format!("unknown host service: {}", req)),
    }
}

fn answer_host<B: HostBackend + ?Sized>(
    stream: &mut TcpStream,
    backend: &B,
    svc: &HostSvc,
    selector: &Selector,
) -> io::Result<()> {
    match svc {
        HostSvc::Version => write_okay_data(stream, SERVER_VERSION_HEX),
        HostSvc::HostFeatures => write_okay_data(stream, crate::adb_protocol::ADB_HOST_FEATURES),
        HostSvc::Features => reply(stream, backend.device_features(selector)),
        HostSvc::Devices { long } => write_okay_data(stream, &backend.devices(*long)),
        HostSvc::GetState => reply(stream, backend.state(selector)),
        HostSvc::GetSerialNo => reply(stream, backend.resolve(selector)),
        // 官方回的是 USB 设备路径；本项目按序列号标识设备，没有可对外承诺的稳定 devpath。
        HostSvc::GetDevPath => reply(
            stream,
            backend.resolve(selector).map(|s| format!("usb:{}", s)),
        ),
        HostSvc::MuxInfo => {
            if backend.is_rmf_mux() {
                write_okay_data(stream, "mux")
            } else {
                write_fail(stream, "unknown host service: rmf-mux-info")
            }
        }
        HostSvc::Forward(req) => answer_forward(stream, backend, selector, req),
        // 网络设备（emulator / `adb tcpip` 之后的设备）本项目不接管：必须回 FAIL，
        // 否则官方客户端会把失败正文当成成功提示并把 endpoint 登记为已连接。
        HostSvc::Connect(spec) => write_fail(
            stream,
            &format!(
                "failed to connect to '{}': RMFlashTool 的 adb server 只接管 USB 设备",
                spec
            ),
        ),
        HostSvc::Disconnect(_) => write_okay_data(stream, "disconnected everything"),
        HostSvc::Reconnect(_) => write_okay_data(stream, "done"),
        HostSvc::Kill => {
            write_okay(stream)?;
            let _ = stream.flush();
            crate::logger::log_line(&format!("{} 收到 host:kill；让位", backend.log_tag()));
            backend.kill();
            Ok(())
        }
        HostSvc::Unsupported(name) => {
            write_fail(stream, &format!("unknown host service: {}", name))
        }
    }
}

fn reply(stream: &mut TcpStream, result: Result<String, String>) -> io::Result<()> {
    match result {
        Ok(data) => write_okay_data(stream, &data),
        Err(e) => write_fail(stream, &e),
    }
}

fn answer_forward<B: HostBackend + ?Sized>(
    stream: &mut TcpStream,
    backend: &B,
    selector: &Selector,
    req: &ForwardRequest,
) -> io::Result<()> {
    match backend.forward(selector, req) {
        // list 走 adb_query：一个 OKAY + 协议串。
        Ok(ForwardReply::List(text)) => write_okay_data(stream, &text),
        // 增删走 adb_connect + adb_status：两个 OKAY，其后可选一个协议串回报实际端口。
        Ok(ForwardReply::Done) => {
            write_okay(stream)?;
            write_okay(stream)
        }
        Ok(ForwardReply::DonePort(port)) => {
            write_okay(stream)?;
            write_okay(stream)?;
            write_len_prefixed(stream, &port.to_string())
        }
        Err(e) => write_fail(stream, &e),
    }
}

fn serve_transport<B: HostBackend + ?Sized>(
    mut stream: TcpStream,
    backend: &B,
    selector: Selector,
    echo_id: bool,
) -> io::Result<()> {
    // 官方 server 在切 transport 这一步就会因「设备不在」失败，客户端据此报
    // `no devices/emulators found`。先解析再 OKAY，才不会把失败推迟到服务阶段。
    let serial = match backend.resolve(&selector) {
        Ok(s) => s,
        Err(e) => return write_fail(&mut stream, &e),
    };
    write_okay(&mut stream)?;
    if echo_id {
        write_transport_id(&mut stream, transport_id_of(&serial))?;
    }
    stream.flush()?;

    let svc = match read_message(&mut stream) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };

    // transport 之后仍可能是 host 侧 forward——官方 `adb forward` 正是「先切 transport，
    // 再发 host:forward:...」。不认它就会把 forward 当 local 服务开到设备上去。
    if let Some(rest) = svc.strip_prefix("host:") {
        if let Some(fwd) = parse_forward_service(rest) {
            return answer_forward(&mut stream, backend, &selector, &fwd);
        }
    }

    backend.serve_local(stream, selector, &svc)
}

/// track-devices：初帧立即推一次，其后仅在设备列表变化时推 `[4 位十六进制长度][列表]`。
fn serve_track_devices<B: HostBackend + ?Sized>(
    stream: &mut TcpStream,
    backend: &B,
    long: bool,
) -> io::Result<()> {
    let mut last: Option<String> = None;
    loop {
        if !backend.keep_serving() {
            return Ok(());
        }
        let cur = backend.devices(long);
        if last.as_deref() != Some(cur.as_str()) {
            write_len_prefixed(stream, &cur)?;
            stream.flush()?;
            last = Some(cur);
        }
        std::thread::sleep(TRACK_POLL_INTERVAL);
    }
}

// ============================ 设备列表排版 ============================

/// 拼一行 `devices` / `devices -l` 输出。`-l` 的 `product:/model:/device:` 取自设备 CNXN
/// banner，拿不到就整段略去（官方同样是有才打），`transport_id:` 始终带上——`adb -t` 靠它。
pub fn device_line(
    serial: &str,
    state: &str,
    long: bool,
    banner: Option<&crate::adb_protocol::PeerBanner>,
) -> String {
    if !long {
        return format!("{}\t{}\n", serial, state);
    }
    let mut line = format!("{}\t{}", serial, state);
    if let Some(b) = banner {
        for (key, value) in [
            ("product", &b.product),
            ("model", &b.model),
            ("device", &b.device),
        ] {
            if !value.is_empty() {
                line.push_str(&format!(" {}:{}", key, value));
            }
        }
    }
    line.push_str(&format!(" transport_id:{}\n", transport_id_of(serial)));
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_message_parses_len_prefixed() {
        let mut c = Cursor::new(b"000Chost:version".to_vec());
        assert_eq!(read_message(&mut c).unwrap(), "host:version");
    }

    #[test]
    fn read_message_rejects_bad_hex() {
        let mut c = Cursor::new(b"zzzzabcd".to_vec());
        assert!(read_message(&mut c).is_err());
    }

    #[test]
    fn write_okay_data_is_len_prefixed() {
        let mut buf = Vec::new();
        write_okay_data(&mut buf, "0029").unwrap();
        assert_eq!(buf, b"OKAY00040029");
    }

    #[test]
    fn write_fail_encodes_reason() {
        let mut buf = Vec::new();
        write_fail(&mut buf, "boom").unwrap();
        assert_eq!(buf, b"FAIL0004boom");
    }

    /// transport id 必须是 8 字节小端——客户端 `switch_socket_transport` 直接把它读进
    /// `TransportId`（uint64）。字节序或长度错了，后续 `-t` 全指错设备。
    #[test]
    fn transport_id_is_eight_byte_little_endian() {
        let mut buf = Vec::new();
        write_transport_id(&mut buf, 0x1122_3344_5566_7788).unwrap();
        assert_eq!(buf, vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
    }

    /// 官方 adb 36 只发 tport；不认它就等于除 devices 外全部失败。
    #[test]
    fn official_transport_requests_are_recognised() {
        assert_eq!(
            parse_request("host:tport:any"),
            Request::Transport {
                selector: Selector::Any,
                echo_id: true
            }
        );
        assert_eq!(
            parse_request("host:tport:serial:ABC123"),
            Request::Transport {
                selector: Selector::Serial("ABC123".into()),
                echo_id: true
            }
        );
        assert_eq!(
            parse_request("host:transport-id:7"),
            Request::Transport {
                selector: Selector::TransportId(7),
                echo_id: false
            }
        );
        // 旧写法仍要认（本项目自研 client 与老客户端在用），但不回 transport id。
        assert_eq!(
            parse_request("host:transport-any"),
            Request::Transport {
                selector: Selector::Any,
                echo_id: false
            }
        );
        assert_eq!(
            parse_request("host:transport:ABC123"),
            Request::Transport {
                selector: Selector::Serial("ABC123".into()),
                echo_id: false
            }
        );
    }

    #[test]
    fn host_services_and_selectors() {
        assert_eq!(
            parse_request("host:version"),
            Request::Host {
                svc: HostSvc::Version,
                selector: Selector::Any
            }
        );
        assert_eq!(
            parse_request("host-serial:ABC:get-state"),
            Request::Host {
                svc: HostSvc::GetState,
                selector: Selector::Serial("ABC".into())
            }
        );
        assert_eq!(
            parse_request("host-transport-id:3:features"),
            Request::Host {
                svc: HostSvc::Features,
                selector: Selector::TransportId(3)
            }
        );
        assert_eq!(
            parse_request("host:track-devices"),
            Request::TrackDevices { long: false }
        );
    }

    /// 设备选择的报错口径与官方一致：点名找不到报 not found（即使列表为空），不点名才分无设备 / 多设备。
    #[test]
    fn pick_serial_errors_match_the_official_wording() {
        let none: Vec<String> = Vec::new();
        let two = vec!["A".to_string(), "B".to_string()];
        assert_eq!(
            pick_serial(&Selector::Serial("X".into()), &none),
            Err(err_device_not_found("X"))
        );
        assert_eq!(
            pick_serial(&Selector::Serial("X".into()), &two),
            Err(err_device_not_found("X"))
        );
        assert_eq!(
            pick_serial(&Selector::Serial("B".into()), &two),
            Ok("B".into())
        );
        assert_eq!(
            pick_serial(&Selector::Any, &none),
            Err(ERR_NO_DEVICES.into())
        );
        assert_eq!(
            pick_serial(&Selector::Any, &two),
            Err(ERR_MULTIPLE_DEVICES.into())
        );
        assert_eq!(pick_serial(&Selector::Usb, &two[..1]), Ok("A".into()));
    }

    /// 网络设备的序列号自带冒号（`192.168.1.2:5555`），按第一个冒号切会把端口当成服务名。
    #[test]
    fn host_serial_split_tolerates_colons_in_serial() {
        assert_eq!(
            parse_request("host-serial:192.168.1.2:5555:get-state"),
            Request::Host {
                svc: HostSvc::GetState,
                selector: Selector::Serial("192.168.1.2:5555".into())
            }
        );
    }

    /// forward 家族的三种形态都要认出来，否则会被当成 local 服务开到设备上。
    #[test]
    fn forward_family_is_parsed() {
        assert_eq!(
            parse_forward_service("forward:tcp:1234;tcp:5678"),
            Some(ForwardRequest::Add {
                norebind: false,
                local: "tcp:1234".into(),
                remote: "tcp:5678".into()
            })
        );
        assert_eq!(
            parse_forward_service("forward:norebind:tcp:1;localabstract:x"),
            Some(ForwardRequest::Add {
                norebind: true,
                local: "tcp:1".into(),
                remote: "localabstract:x".into()
            })
        );
        assert_eq!(
            parse_forward_service("killforward:tcp:1234"),
            Some(ForwardRequest::Remove {
                local: "tcp:1234".into()
            })
        );
        assert_eq!(
            parse_forward_service("killforward-all"),
            Some(ForwardRequest::RemoveAll)
        );
        assert_eq!(
            parse_forward_service("list-forward"),
            Some(ForwardRequest::List)
        );
        assert_eq!(parse_forward_service("shell:ls"), None);
    }

    /// 认不出的服务要带着服务名回 FAIL，方便用户看出缺了什么。
    #[test]
    fn unknown_services_keep_their_name() {
        assert_eq!(
            parse_request("host:server-status"),
            Request::Host {
                svc: HostSvc::Unsupported("server-status".into()),
                selector: Selector::Any
            }
        );
        assert_eq!(parse_request("garbage"), Request::Unknown);
    }

    /// 同一活动 transport 实例在刷新前不能变——`devices -l` 里报给客户端的 id 与随后
    /// `host:transport-id:<id>` 必须指同一台设备。
    #[test]
    fn transport_ids_are_stable_and_reversible() {
        let a = transport_id_of("SERIAL_STABLE_A");
        let b = transport_id_of("SERIAL_STABLE_B");
        assert_ne!(a, b);
        assert_eq!(transport_id_of("SERIAL_STABLE_A"), a);
        assert_eq!(
            serial_of_transport_id(a).as_deref(),
            Some("SERIAL_STABLE_A")
        );
    }

    // ==================== 线上契约（跑真 socket，锁死帧序）====================
    //
    // 这几条是「官方 adb 能不能用」的分水岭，且都只在字节层面体现（错了不会编译失败、
    // 也不会在任何纯函数测试里露馅），所以必须端到端跑一遍真 socket。

    use std::net::TcpListener;

    struct FakeBackend;

    impl HostBackend for FakeBackend {
        fn log_tag(&self) -> &'static str {
            "[fake]"
        }
        fn devices(&self, long: bool) -> String {
            device_line("FAKE1", "device", long, None)
        }
        fn resolve(&self, selector: &Selector) -> Result<String, String> {
            pick_serial(selector, &["FAKE1".to_string()])
        }
        fn state(&self, _selector: &Selector) -> Result<String, String> {
            Ok("device".to_string())
        }
        fn device_features(&self, _selector: &Selector) -> Result<String, String> {
            Ok("shell_v2".to_string())
        }
        fn kill(&self) {}
        fn forward(&self, _s: &Selector, req: &ForwardRequest) -> Result<ForwardReply, String> {
            match req {
                ForwardRequest::List => Ok(ForwardReply::List("FAKE1 tcp:1 tcp:2\n".to_string())),
                ForwardRequest::Add { local, .. } if local == "tcp:0" => {
                    Ok(ForwardReply::DonePort(41234))
                }
                _ => Ok(ForwardReply::Done),
            }
        }
        fn serve_local(
            &self,
            mut stream: TcpStream,
            _selector: Selector,
            svc: &str,
        ) -> io::Result<()> {
            // 回 OKAY 后把服务名当数据吐回去，测试据此确认「transport 之后收到的是哪条服务」。
            write_okay(&mut stream)?;
            stream.write_all(svc.as_bytes())
        }
    }

    /// 起一个只服务一条连接的 server，返回已连上的客户端 socket。
    fn serve_once() -> TcpStream {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let _ = serve_connection(stream, &FakeBackend);
            }
        });
        let client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
    }

    fn send(stream: &mut TcpStream, req: &str) {
        stream
            .write_all(format!("{:04x}{}", req.len(), req).as_bytes())
            .unwrap();
    }

    fn take(stream: &mut TcpStream, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        stream.read_exact(&mut buf).unwrap();
        buf
    }

    /// 读到流尾，返回剩余字节。对端不关连接就会一直读不到 EOF（本测试用超时兜底）。
    fn drain(stream: &mut TcpStream) -> Vec<u8> {
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).unwrap();
        rest
    }

    /// **回归护栏**：一次性 host 服务应答完必须关连接。官方客户端读完应答就调
    /// `ReadOrderlyShutdown` 阻塞等 EOF——服务端留着连接等下一条请求，客户端就永久挂死
    /// （现象是连 `adb devices` 都只会超时，而不是报错）。
    #[test]
    fn one_shot_host_service_closes_the_connection() {
        let mut c = serve_once();
        send(&mut c, "host:version");
        assert_eq!(take(&mut c, 4), b"OKAY");
        assert_eq!(take(&mut c, 4), b"0004");
        assert_eq!(take(&mut c, 4), b"0029");
        assert!(drain(&mut c).is_empty(), "应答后必须立刻 EOF");
    }

    /// **回归护栏**：`host:tport:*` 要在 OKAY 之后补 8 字节小端 transport id，
    /// 随后同一条连接上继续收 local 服务。少这 8 字节，客户端会把服务名的头 8 字节当 id 吃掉。
    #[test]
    fn tport_replies_transport_id_then_serves_local_service() {
        let mut c = serve_once();
        send(&mut c, "host:tport:any");
        assert_eq!(take(&mut c, 4), b"OKAY");
        let id = u64::from_le_bytes(take(&mut c, 8).try_into().unwrap());
        assert_eq!(id, transport_id_of("FAKE1"));

        send(&mut c, "shell,v2,raw:id");
        assert_eq!(take(&mut c, 4), b"OKAY");
        assert_eq!(drain(&mut c), b"shell,v2,raw:id");
    }

    /// 旧写法 `host:transport-any` 只回 OKAY，**不能**补 transport id
    ///（本项目自研 client 紧接着就发服务名，多 8 字节会错位）。
    #[test]
    fn legacy_transport_does_not_echo_an_id() {
        let mut c = serve_once();
        send(&mut c, "host:transport-any");
        assert_eq!(take(&mut c, 4), b"OKAY");
        send(&mut c, "shell:id");
        assert_eq!(take(&mut c, 4), b"OKAY");
        assert_eq!(drain(&mut c), b"shell:id");
    }

    /// **回归护栏**：forward 家族的帧数。增删走 `adb_connect` + `adb_status`（两个 OKAY），
    /// list 走 `adb_query`（一个 OKAY + 协议串）。发错帧数客户端会错位解析。
    #[test]
    fn forward_add_sends_two_okays_and_list_sends_one_plus_payload() {
        // 官方 `adb forward` 是「先切 transport，再在同一条连接上发 host:forward:...」。
        let mut c = serve_once();
        send(&mut c, "host:tport:any");
        assert_eq!(take(&mut c, 4), b"OKAY");
        take(&mut c, 8);
        send(&mut c, "host:forward:tcp:1;tcp:2");
        assert_eq!(take(&mut c, 8), b"OKAYOKAY");
        assert!(drain(&mut c).is_empty());

        // tcp:0 追加一个协议串回报实际端口。
        let mut c = serve_once();
        send(&mut c, "host:tport:any");
        take(&mut c, 12);
        send(&mut c, "host:forward:tcp:0;tcp:2");
        assert_eq!(take(&mut c, 8), b"OKAYOKAY");
        assert_eq!(drain(&mut c), b"000541234");

        // list 不切 transport，且只有一个 OKAY。
        let mut c = serve_once();
        send(&mut c, "host:list-forward");
        assert_eq!(take(&mut c, 4), b"OKAY");
        assert_eq!(take(&mut c, 4), b"0012");
        assert_eq!(drain(&mut c), b"FAKE1 tcp:1 tcp:2\n");
    }

    /// 认不出的服务要 FAIL 并关连接——挂着不答与答错一样致命。
    #[test]
    fn unknown_service_fails_and_closes() {
        let mut c = serve_once();
        send(&mut c, "host:no-such-thing");
        assert_eq!(take(&mut c, 4), b"FAIL");
        let len =
            usize::from_str_radix(std::str::from_utf8(&take(&mut c, 4)).unwrap(), 16).unwrap();
        let msg = String::from_utf8(take(&mut c, len)).unwrap();
        assert!(
            msg.contains("no-such-thing"),
            "错误文案要带上服务名: {}",
            msg
        );
        assert!(drain(&mut c).is_empty());
    }

    #[test]
    fn device_line_long_form_carries_transport_id() {
        let banner = crate::adb_protocol::PeerBanner {
            product: "p".into(),
            model: "m".into(),
            ..Default::default()
        };
        let line = device_line("S1", "device", true, Some(&banner));
        assert!(line.starts_with("S1\tdevice product:p model:m transport_id:"));
        // 没有 banner 时只略去 product/model/device，transport_id 仍必须在。
        assert!(device_line("S1", "device", true, None).contains("transport_id:"));
        assert_eq!(device_line("S1", "device", false, None), "S1\tdevice\n");
    }
}
