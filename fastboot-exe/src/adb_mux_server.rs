//! 基于单连接多路复用（[`crate::adb_mux`]）的 5037 ADB host 协议服务端。
//! 经典 adb_server「每 client 一条 USB 连接 + USB_LOCK 串行」跑不了 scrcpy（shell 与 reverse
//! 需并发）；本服务端按官方 adb 模型单例持一条 USB 连接、以 local_id 复用所有 stream。
//! 独立可选进程（`--adb-server-mux`，`RMF_ADB_MUX=1` 触发），与经典 server 并列互不影响；绑 5037 失败即静默退出。
//!
//! 协议层（帧、请求分类、连接生命周期、tport）全在 [`crate::adb_host_proto`]，本模块只提供
//! 设备侧能力。因为持有常驻读循环，它是两个 server 里唯一能承载主机侧 forward 隧道的那个。

use crate::adb_host_proto::{self as proto, ForwardReply, ForwardRequest, HostBackend, Selector};
use crate::adb_mux::{
    bridge_stream_tcp_blocking, tcp_port, MuxHandle, MuxSession, MuxStream, MuxStreamIo,
};
use crate::adb_protocol::PeerBanner;
use crate::adb_winusb_transport::{serial_from_path, AdbWinUsbDevice};
use std::collections::HashSet;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

/// 被拉起为 mux 5037 服务端时携带的隐藏参数。
pub const ADB_SERVER_MUX_ARG: &str = "--adb-server-mux";

const ADB_PORT: u16 = 5037;

/// 设备 hub 建立的等待上限：设备线程打开设备 + A_CNXN 握手（未授权时 connect 可能等授权）。
const HUB_SETUP_TIMEOUT: Duration = Duration::from_secs(30);

/// 拆除半死 hub 的等待上限：置 stop 后等属主设备线程退读循环、释放 WinUSB 句柄并清槽。
/// 取略大于读循环轮询周期（1s）+ 句柄释放余量，够一轮必然完成；超时即放弃重试、如实回错。
const STALE_HUB_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(4);

// ============================ 设备 Hub（单例：一条 USB 连接 + mux）============================

/// 一台设备的多路复用会话共享句柄。`handle` 可克隆给每个 client 线程并发 open_stream。
struct DeviceHub {
    serial: String,
    handle: MuxHandle,
    /// 设备 CNXN banner。`host:features` 与 `devices -l` 靠它作答（hub 是唯一拿得到的一方）。
    banner: PeerBanner,
}

/// 全局唯一的设备 hub。`None` 表示尚未建立（或设备已断开被清空）。
fn hub_slot() -> &'static Mutex<Option<Arc<DeviceHub>>> {
    static HUB: OnceLock<Mutex<Option<Arc<DeviceHub>>>> = OnceLock::new();
    HUB.get_or_init(|| Mutex::new(None))
}

type HubResult = Result<Arc<DeviceHub>, String>;

/// 建连任务归设备线程所有。调用方等候超时不会撤销它，也不能再起一条握手抢同一 USB 句柄。
#[derive(Default)]
struct HubSetup {
    result: Mutex<Option<HubResult>>,
    ready: Condvar,
}

impl HubSetup {
    fn wait(&self, timeout: Duration) -> HubResult {
        let result = self.result.lock().unwrap_or_else(|e| e.into_inner());
        let (result, _) = self
            .ready
            .wait_timeout_while(result, timeout, |result| result.is_none())
            .unwrap_or_else(|e| e.into_inner());
        result
            .clone()
            .unwrap_or_else(|| Err("device hub setup timed out".to_string()))
    }

    fn complete(&self, result: HubResult) {
        *self.result.lock().unwrap_or_else(|e| e.into_inner()) = Some(result);
        self.ready.notify_all();
    }
}

fn setup_slot() -> &'static Mutex<Option<Arc<HubSetup>>> {
    static SETUP: OnceLock<Mutex<Option<Arc<HubSetup>>>> = OnceLock::new();
    SETUP.get_or_init(|| Mutex::new(None))
}

/// 多个等待者共享同一任务；只有设备线程完成之后才能清槽、允许下一次建连。
fn complete_setup(setup: &Arc<HubSetup>, result: HubResult) {
    setup.complete(result);
    clear_if_same(
        &mut setup_slot().lock().unwrap_or_else(|e| e.into_inner()),
        setup,
    );
}

fn current_hub() -> Option<Arc<DeviceHub>> {
    hub_slot().lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// 仅当槽位空置时装入（返回是否装入）。占位即失败——绝不顶替别的设备线程已装好的 hub，
/// 否则两条读循环会同时抢一台设备的 bulk-in（scrcpy 数据被撕碎的根因）。
fn install_if_vacant<T>(slot: &mut Option<Arc<T>>, hub: &Arc<T>) -> bool {
    if slot.is_none() {
        *slot = Some(hub.clone());
        true
    } else {
        false
    }
}

/// 仅当槽内仍是同一实例时清除（compare-and-clear）。属主身份判定：迟到的孤儿设备线程
/// （建立超过 HUB_SETUP_TIMEOUT 才就绪或才退出）绝不抹掉新装的健康 hub。
fn clear_if_same<T>(slot: &mut Option<Arc<T>>, owned: &Arc<T>) -> bool {
    if slot.as_ref().is_some_and(|cur| Arc::ptr_eq(cur, owned)) {
        *slot = None;
        true
    } else {
        false
    }
}

fn install_hub_if_vacant(hub: &Arc<DeviceHub>) -> bool {
    install_if_vacant(
        &mut hub_slot().lock().unwrap_or_else(|e| e.into_inner()),
        hub,
    )
}

fn clear_hub_if_current(hub: &Arc<DeviceHub>) {
    clear_if_same(
        &mut hub_slot().lock().unwrap_or_else(|e| e.into_inner()),
        hub,
    );
}

/// 拆除一条半死 hub（握手过但设备对 A_OPEN 装死，读循环永远读不到数据、不会自行退出）。
///
/// 常见触发：设备从外部官方 adb server 交接到我们直连，adbd 仍停在上一个会话态，A_CNXN 的
/// banner 能回但拒开任何新流。此时既不能坐等（读循环现为有限轮询但无数据永不报错），也不能
/// 直接清槽后让下一个请求重建（属主线程仍活着 → 两条读循环抢同一 bulk-in，撕碎数据）。
///
/// 正确序：① `request_stop` 让属主读循环在下一轮询周期退出 → `run()` 返回 → 丢 session 释放
/// WinUSB 句柄 → compare-and-clear 清槽；② 本函数阻塞等槽位不再是这条 hub（即属主已走完上述
/// 全程），至多等 [`STALE_HUB_TEARDOWN_TIMEOUT`]。拆与重建严格串行，绝不并存两条读循环。
/// 槽位清空后设备看守线程会重新握手，刷新设备状态。
fn teardown_stale_hub(hub: &Arc<DeviceHub>) {
    hub.handle.request_stop();
    let deadline = Instant::now() + STALE_HUB_TEARDOWN_TIMEOUT;
    while Instant::now() < deadline {
        match current_hub() {
            Some(cur) if Arc::ptr_eq(&cur, hub) => thread::sleep(Duration::from_millis(50)),
            _ => return,
        }
    }
}

/// 复用已装好的 hub 前必须核对请求的 serial。hub 是全局单槽：装的是设备 A 时对
/// `host:transport:B` 静默发回 A 的 hub，client 会在错误的设备上收发；单槽装不下第二台，
/// 只能 FAIL。返回不匹配的错误文案。
fn hub_serial_mismatch(hub_serial: &str, requested: Option<&str>) -> Option<String> {
    requested
        .filter(|want| *want != hub_serial)
        .map(|want| format!("device '{}' not found (hub serves '{}')", want, hub_serial))
}

/// 取得（或惰性建立）设备 hub。设备对象 `!Send`，故必须在**独立设备线程**里打开设备、建
/// `MuxSession` 并跑读循环；本函数只把可跨线程的 hub 句柄取回。hub 的装入与清除都只由
/// **属主设备线程**执行：装入用 install-if-vacant（占位即放弃本会话），清除用 compare-and-clear
/// （只清自己那个实例）——其它任何路径（如 open_stream 失败）都不得清 hub，否则会在设备线程
/// 仍活着时拉起第二条读循环。
fn get_or_create_hub(serial: Option<&str>) -> Result<Arc<DeviceHub>, String> {
    if let Some(hub) = current_hub() {
        if let Some(err) = hub_serial_mismatch(&hub.serial, serial) {
            return Err(err);
        }
        return Ok(hub);
    }
    let mut pending = setup_slot().lock().unwrap_or_else(|e| e.into_inner());
    // 双检：可能有另一线程在我们等锁期间已建好。
    if let Some(hub) = current_hub() {
        if let Some(err) = hub_serial_mismatch(&hub.serial, serial) {
            return Err(err);
        }
        return Ok(hub);
    }

    if let Some(setup) = pending.as_ref().cloned() {
        drop(pending);
        let hub = setup.wait(HUB_SETUP_TIMEOUT)?;
        if let Some(err) = hub_serial_mismatch(&hub.serial, serial) {
            return Err(err);
        }
        return Ok(hub);
    }
    let setup = Arc::new(HubSetup::default());
    *pending = Some(setup.clone());
    drop(pending);
    let worker_setup = setup.clone();
    let want = serial.map(|s| s.to_string());
    thread::spawn(move || {
        match open_device_session(want.as_deref()) {
            // sideload 模式只跑 sideload 专用块协议，mux 承载不了任何流；`adb sideload` 走
            // embed 直连且必须独占句柄，mux 占着它就打不开。握手看到 banner 就放手（session
            // 随 drop 释放句柄），并登记下来，devices 如实报 `sideload`、不再自动握手。
            Ok((session, serial)) if session.peer_banner().kind == "sideload" => {
                sideload_devices()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(serial);
                drop(session);
                complete_setup(
                    &worker_setup,
                    Err("设备处于 sideload 模式，由 adb sideload 直连承载".to_string()),
                );
            }
            Ok((mut session, serial)) => {
                let hub = Arc::new(DeviceHub {
                    serial,
                    handle: session.handle(),
                    banner: session.peer_banner().clone(),
                });
                // 槽位被占时立即放弃多余会话，绝不覆盖现有连接
                //（session 随 drop 释放设备句柄），绝不并存两条读循环。
                if !install_hub_if_vacant(&hub) {
                    drop(session);
                    complete_setup(
                        &worker_setup,
                        Err("另一条设备会话已就绪，请重试".to_string()),
                    );
                    return;
                }
                unauthorized_auto_attempts()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&hub.serial);
                // 先把 hub 发回，再阻塞跑读循环；读循环退出（设备断开 / 被 request_stop 拆除）后
                // 先丢弃 session 释放 WinUSB 句柄，再清自己装的槽——顺序要紧：先清槽后释放会留一个
                // 窗口让重建线程抢开同一设备却撞上尚未 Free 的句柄（CreateFileW 拒绝访问）。
                complete_setup(&worker_setup, Ok(hub.clone()));
                let result = session.run();
                drop(session);
                // 清槽前先收掉旧隧道，避免下一条连接刚建好转发就被旧线程删掉。
                forward_registry().remove_all();
                clear_hub_if_current(&hub);
                if let Err(e) = result {
                    crate::logger::log_line(&format!(
                        "[adb-mux-server] 设备会话结束，将自动重新连接：{}",
                        e
                    ));
                }
            }
            Err(e) => {
                complete_setup(&worker_setup, Err(e));
            }
        }
    });

    setup.wait(HUB_SETUP_TIMEOUT)
}

/// 打开到设备 `svc` 的 stream（shell:/sync:/exec:/reverse:… 皆然）：取（或惰性建立）hub 后 A_OPEN。
/// 5037 client（[`MuxBackend::serve_local`]）与本进程直连（[`open_local_stream`]）共用这一份开流与
/// 自愈逻辑，两条路径对设备的行为完全一致。
fn open_device_stream(want: Option<&str>, svc: &str) -> Result<MuxStream, String> {
    // 设备正等用户授权时，那条握手线程独占着设备句柄：再去建 hub 只会再起一条设备线程、
    // 撞上 CreateFileW 拒绝访问，还要等满 HUB_SETUP_TIMEOUT。直接如实拒绝，授权通过后
    // 那条线程会自己把 hub 装上，下一次请求即可正常开流。
    if current_hub().is_none() {
        if let Ok(path) = pick_device_path_by_serial(want) {
            if crate::adb_winusb_transport::is_awaiting_authorization(&serial_from_path(&path)) {
                return Err(proto::ERR_DEVICE_UNAUTHORIZED.to_string());
            }
        }
    }
    let hub = match get_or_create_hub(want) {
        // 句柄可能还攥在本进程 embed 的直连缓存里（拉起 mux 前那次有界释放没等到 hub 线程），
        // 而 mux 一旦在位就再没有路径会去释放它：交出后重建一次。别的进程占着时释放是空操作，
        // 重试照旧失败、如实回错。
        Err(e) if crate::error::usb_text_is_access_denied(&e) && crate::embed::adb_release() => {
            get_or_create_hub(want)
        }
        other => other,
    }
    .map_err(|e| {
        // 失败原因（最常见：设备句柄被别的直连进程独占 → CreateFileW 0x80070005）除了回给调用方，
        // 也必须落 server 侧日志——5037 client 是瞬时进程，日志常随会话丢失。
        crate::logger::log_line(&format!(
            "[adb-mux-server] 设备 hub 建立失败（svc={}）：{}",
            svc, e
        ));
        e
    })?;

    match hub.handle.open_stream(svc) {
        Ok(s) => Ok(s),
        // 设备对 A_OPEN 装死（握手过却开不了流）：这条 hub 连接半死、不会自行退出。拆掉它
        // （停读循环、释放句柄、清槽），用一条全新 A_CNXN 连接重建后重试一次。拆→重建严格
        // 串行，绝不会两条读循环并存——正是旧注释所担心、也是投屏 checksum mismatch 的来源。
        Err(e) if crate::adb_mux::is_open_timeout_err(&e) => {
            crate::logger::log_line(&format!(
                "[adb-mux-server] open_stream 超时（svc={}）：拆除半死 hub 后重建重试",
                svc
            ));
            teardown_stale_hub(&hub);
            let fresh = get_or_create_hub(want).map_err(|e2| {
                crate::logger::log_line(&format!(
                    "[adb-mux-server] 拆除后重建 hub 失败（svc={}）：{}",
                    svc, e2
                ));
                e2
            })?;
            fresh.handle.open_stream(svc).map_err(|e2| {
                crate::logger::log_line(&format!(
                    "[adb-mux-server] 重建后 open_stream 仍失败（svc={}）：{}",
                    svc, e2
                ));
                e2
            })
        }
        // 被明确拒绝（A_CLSE）或写失败：不是半死连接，保持原策略不清 hub——连接真坏时
        // 读循环会退出、属主线程自会 compare-and-clear 自己那个实例。
        Err(e) => {
            crate::logger::log_line(&format!(
                "[adb-mux-server] open_stream 失败（svc={}）：{}",
                svc, e
            ));
            Err(e)
        }
    }
}

/// 在当前（设备）线程打开一台 ADB 模式的 WinUSB 设备并建立 mux 会话（含 A_CNXN 握手）。
fn open_device_session(serial: Option<&str>) -> Result<(MuxSession, String), String> {
    crate::adb_daemon::ensure_released();
    let path = pick_device_path_by_serial(serial)?;
    let serial = serial_from_path(&path);
    let dev = AdbWinUsbDevice::open_device(&path).map_err(|e| e.to_string())?;
    let session = MuxSession::new(dev)?;
    Ok((session, serial))
}

/// 只有已握手并建立 hub 的设备才上线；仅 USB 枚举成功、握手尚未完成或失败时均报 offline。
/// 新设备由 [`observe_enumerated`] 在后台握手，查询状态本身不开设备句柄。
fn device_state(serial: &str) -> &'static str {
    let hub = current_hub();
    let sideload = sideload_devices()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(serial);
    device_state_from_handshake(
        serial,
        hub.as_ref()
            .map(|hub| (hub.serial.as_str(), hub.banner.kind.as_str())),
        sideload,
        crate::adb_winusb_transport::is_unauthorized(serial),
    )
}

fn device_state_from_handshake(
    serial: &str,
    hub: Option<(&str, &str)>,
    sideload: bool,
    unauthorized: bool,
) -> &'static str {
    if sideload {
        "sideload"
    } else if unauthorized {
        "unauthorized"
    } else {
        match hub.filter(|(hub_serial, _)| *hub_serial == serial) {
            Some((_, "recovery")) => "recovery",
            Some(_) => "device",
            None => "offline",
        }
    }
}

/// 握手时发现处于 sideload 模式的设备（见 [`get_or_create_hub`]）。拔掉即移除。
fn sideload_devices() -> &'static Mutex<HashSet<String>> {
    static SET: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    SET.get_or_init(|| Mutex::new(HashSet::new()))
}

/// 只有完整自动握手已进入未授权状态才暂停重试。探测握手也会登记 unauthorized，
/// 但它没有发公钥，不能因此跳过首次完整握手，否则手机永远收不到授权请求。
fn unauthorized_auto_attempts() -> &'static Mutex<HashSet<String>> {
    static SET: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    SET.get_or_init(|| Mutex::new(HashSet::new()))
}

static AUTO_HANDSHAKE_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// `devices` 每轮枚举后调用：清掉已拔出设备的状态登记，并对新插上的设备自动建一次 hub。
///
/// 官方 adb server 在设备插上时就会建连，所以它能报 `unauthorized`、手机也会立刻弹「允许 USB
/// 调试吗」。我们的 `devices` 为了不抢句柄只枚举，若再没有别的动作去握手，设备会一直 offline。
/// 这里在后台建 hub：hub 本就是 mux 模式下设备句柄的唯一 owner，建好后常驻复用，不是每轮开关
/// 句柄。未授权时握手线程发公钥等用户点允许，期间与之后的结论都由握手登记，`devices` 据此报
/// `unauthorized`，不反复弹框；sideload 也不接管。IO 失败 / 连接结束后下一轮继续连接，不能把
/// 「尝试过」当成「已连上」而永久跳过。单槽 hub 已被占用（投屏等在用）时不动。
fn observe_enumerated(serials: &[String]) {
    let retain_present = |set: &Mutex<HashSet<String>>| {
        set.lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|s| serials.contains(s));
    };
    retain_present(sideload_devices());
    retain_present(unauthorized_auto_attempts());
    crate::adb_winusb_transport::forget_absent_authorization(serials);

    if current_hub().is_some()
        || AUTO_HANDSHAKE_IN_FLIGHT
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
    {
        return;
    }
    let target = {
        let sideload = sideload_devices().lock().unwrap_or_else(|e| e.into_inner());
        let unauthorized = unauthorized_auto_attempts()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let Some(serial) = serials
            .iter()
            .find(|s| !sideload.contains(*s) && !unauthorized.contains(*s))
            .cloned()
        else {
            AUTO_HANDSHAKE_IN_FLIGHT.store(false, Ordering::SeqCst);
            return;
        };
        serial
    };
    thread::spawn(move || {
        if let Err(e) = get_or_create_hub(Some(&target)) {
            crate::logger::log_line(&format!(
                "[adb-mux-server] 设备 {} 插入后自动握手未就绪：{}",
                target, e
            ));
            if crate::adb_winusb_transport::is_unauthorized(&target) {
                unauthorized_auto_attempts()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(target);
            }
        }
        AUTO_HANDSHAKE_IN_FLIGHT.store(false, Ordering::SeqCst);
    });
}

/// 选择一台设备的接口路径。选择判据在 [`proto::pick_serial`]（三个 server 共用）。
fn pick_device_path_by_serial(serial: Option<&str>) -> Result<String, String> {
    let selector = match serial {
        Some(s) => Selector::Serial(s.to_string()),
        None => Selector::Any,
    };
    let list = AdbWinUsbDevice::enumerate().map_err(|e| e.to_string())?;
    let serials: Vec<String> = list
        .iter()
        .map(|d| serial_from_path(&d.device_path))
        .collect();
    proto::refresh_transport_ids(&serials);
    let want = proto::pick_serial(&selector, &serials)?;
    list.iter()
        .find(|d| serial_from_path(&d.device_path) == want)
        .map(|d| d.device_path.clone())
        .ok_or_else(|| proto::err_device_not_found(&want))
}

// ============================ 主机侧 forward 隧道 ============================

/// 一条生效中的 `adb forward`：主机侧监听 `local`，每条进来的连接开一条 mux stream 到设备端 `remote`。
struct ForwardEntry {
    serial: String,
    /// 归一化后的主机侧端点（`tcp:<实际端口>`；`tcp:0` 会被替换成内核分配到的端口）。
    local: String,
    remote: String,
    /// 置位后 accept 循环下一轮退出。监听 socket 用非阻塞轮询，故无需另外唤醒。
    stop: Arc<AtomicBool>,
}

#[derive(Default)]
struct ForwardRegistry {
    entries: Mutex<Vec<ForwardEntry>>,
}

fn forward_registry() -> &'static ForwardRegistry {
    static REG: OnceLock<ForwardRegistry> = OnceLock::new();
    REG.get_or_init(ForwardRegistry::default)
}

impl ForwardRegistry {
    fn list(&self) -> String {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries
            .iter()
            .map(|e| format!("{} {} {}\n", e.serial, e.local, e.remote))
            .collect()
    }

    /// 撤掉某个主机侧端点上的转发。返回是否真的撤掉了。
    fn remove(&self, local: &str) -> bool {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let before = entries.len();
        entries.retain(|e| {
            let hit = e.local == local;
            if hit {
                e.stop.store(true, Ordering::SeqCst);
            }
            !hit
        });
        entries.len() != before
    }

    fn remove_all(&self) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        for e in entries.iter() {
            e.stop.store(true, Ordering::SeqCst);
        }
        entries.clear();
    }

    fn contains(&self, local: &str) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|e| e.local == local)
    }

    fn insert(&self, entry: ForwardEntry) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(entry);
    }
}

/// 建立一条 forward。返回主机侧实际使用的端口（`tcp:0` 时才与请求不同）。
fn forward_add(serial: &str, norebind: bool, local: &str, remote: &str) -> Result<u16, String> {
    // 主机侧必须是本机能监听的端点。`localabstract:` 之类是 Unix 域概念，Windows 主机侧没有
    // 对应物——如实拒绝，不能假装建好了让客户端连一个不存在的地址。
    let port = tcp_port(local)
        .ok_or_else(|| format!("cannot bind '{}': 主机侧只支持 tcp:<port>", local))?;

    if norebind && forward_registry().contains(local) {
        return Err(format!("cannot rebind existing socket '{}'", local));
    }
    // 官方语义：不带 --no-rebind 时覆盖同一主机端点上的旧转发。
    forward_registry().remove(local);

    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| format!("cannot bind '{}': {}", local, e))?;
    let actual = listener
        .local_addr()
        .map_err(|e| format!("cannot bind '{}': {}", local, e))?
        .port();
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("cannot bind '{}': {}", local, e))?;

    let stop = Arc::new(AtomicBool::new(false));
    let entry = ForwardEntry {
        serial: serial.to_string(),
        local: format!("tcp:{}", actual),
        remote: remote.to_string(),
        stop: stop.clone(),
    };
    let serial_owned = serial.to_string();
    let remote_owned = remote.to_string();
    thread::Builder::new()
        .name("rmf-adb-forward".to_string())
        .spawn(move || forward_accept_loop(listener, stop, serial_owned, remote_owned))
        .map_err(|e| format!("cannot start forward listener: {}", e))?;
    forward_registry().insert(entry);
    Ok(actual)
}

/// forward 的 accept 循环：非阻塞轮询（撤销时无需唤醒阻塞中的 accept），
/// 每条进来的连接单开一条 mux stream 并双向桥接。
fn forward_accept_loop(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    serial: String,
    remote: String,
) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((tcp, _)) => {
                let _ = tcp.set_nodelay(true);
                let serial = serial.clone();
                let remote = remote.clone();
                thread::spawn(move || {
                    // 每条连接都重新取 hub：转发可能在设备重连之后才被用到。
                    let hub = match get_or_create_hub(Some(&serial)) {
                        Ok(h) => h,
                        Err(e) => {
                            crate::logger::log_line(&format!(
                                "[adb-mux-server] forward 取 hub 失败（remote={}）：{}",
                                remote, e
                            ));
                            return;
                        }
                    };
                    match hub.handle.open_stream(&remote) {
                        Ok(stream) => bridge_stream_tcp_blocking(stream, tcp),
                        Err(e) => crate::logger::log_line(&format!(
                            "[adb-mux-server] forward open_stream 失败（remote={}）：{}",
                            remote, e
                        )),
                    }
                });
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(_) => thread::sleep(Duration::from_millis(200)),
        }
    }
}

// ============================ 进程模式 ============================

pub fn is_mux_server_process() -> bool {
    std::env::args().any(|a| a == ADB_SERVER_MUX_ARG)
}

/// mux 服务端主入口：绑定 127.0.0.1:5037，每个客户端连接一个线程。永不返回。
pub fn run_mux_server_process() -> ! {
    let listener = match TcpListener::bind(("127.0.0.1", ADB_PORT)) {
        Ok(l) => l,
        Err(_) => {
            crate::logger::log_line("[adb-mux-server] 5037 已被占用；退出");
            std::process::exit(0);
        }
    };
    crate::logger::log_line("[adb-mux-server] 启动（单连接多路复用），监听 127.0.0.1:5037");
    spawn_device_watch(|| true);

    for stream in listener.incoming().flatten() {
        thread::spawn(move || {
            let _ = proto::serve_connection(stream, &MuxBackend);
        });
    }
    std::process::exit(0);
}

// ============================ 进程内宿主（GUI 直接承载全功能 mux server）============================

/// 本进程内是否以「进程内 mux server」形态承载 5037（GUI 宿主）。置位后 [`MuxBackend::kill`] 绝不
/// `process::exit`——否则外部 `host:kill`（scrcpy-cleanup / `adb kill-server`）会把宿主 GUI 一起杀掉。
static IN_PROCESS_MODE: AtomicBool = AtomicBool::new(false);
/// 进程内 5037 监听是否已就绪（幂等启动的守卫）。
static INPROC_RUNNING: AtomicBool = AtomicBool::new(false);

/// 是否处于进程内宿主形态（供 [`MuxBackend::kill`] 判定是否可 `process::exit`）。
pub fn in_process_mode() -> bool {
    IN_PROCESS_MODE.load(Ordering::SeqCst)
}

/// 本进程的 5037 监听是否仍在：在位即设备句柄归本进程 mux 独占（监听循环退出时清零）。
pub fn inproc_server_running() -> bool {
    INPROC_RUNNING.load(Ordering::SeqCst)
}

/// GUI 宿主：在**本进程内**直接承载全功能 5037 mux server（单连接多路复用，支持 forward/reverse
/// 隧道与并发），让外部官方 adb / scrcpy 能像借道官方 server 一样**完整**借道我们（先前那个只会一问一答
/// 的 hub 桥接不支持隧道，官方 adb 落上去只会 `protocol fault ... Broken pipe`，已由本函数取代并删除）。
/// 与独立进程版 [`run_mux_server_process`] 复用同一套
/// [`MuxBackend`] 与设备 hub，仅由 [`in_process_mode`] 区分 `host:kill` 语义。
///
/// 绑不上 5037 = 已有别的 server 在位（我们自己的 / 外来官方 adb）：静默返回，调用方按
/// `device_owned_by_adb_server` 走借道。幂等：重复调用只在首次真正启动监听。
pub fn ensure_inproc_server() {
    if INPROC_RUNNING.load(Ordering::SeqCst) {
        return;
    }
    let listener = match TcpListener::bind(("127.0.0.1", ADB_PORT)) {
        Ok(l) => l,
        Err(_) => return, // 5037 已被占用：交由借道路径处理，绝不硬抢
    };
    if INPROC_RUNNING.swap(true, Ordering::SeqCst) {
        // 竞态：另一线程已抢先启动；本 listener 随作用域结束 drop 关闭。
        return;
    }
    IN_PROCESS_MODE.store(true, Ordering::SeqCst);
    crate::logger::log_line(
        "[adb-mux-inproc] 进程内 5037 mux server 就绪（全功能，外部官方 adb/scrcpy 可完整借道）",
    );
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let _ = proto::serve_connection(stream, &MuxBackend);
            });
        }
        INPROC_RUNNING.store(false, Ordering::SeqCst);
    });
    spawn_device_watch(inproc_server_running);
}

/// mux server 盯 USB 的节奏，与官方 server 的设备轮询同一量级。
const DEVICE_WATCH_INTERVAL: Duration = Duration::from_secs(1);

/// mux server（进程内 / 独立进程）在位期间像官方 server 一样主动认设备：新插上（或重启回来）的
/// adb 设备当场握手建 hub。否则握手要等到有人来问 `devices` 才开始，外部官方 adb / scrcpy 的第一问
/// 只能看到 `offline`，scrcpy 拿到 offline 就直接退出。只枚举不开句柄，空转成本是一次 SetupDi 枚举。
/// `serving` 返回 false 即停；独立进程随监听循环一起退出，传恒真即可。
fn spawn_device_watch(serving: fn() -> bool) {
    let _ = thread::Builder::new()
        .name("rmf-adb-device-watch".to_string())
        .spawn(move || {
            while serving() {
                enumerate_and_observe();
                thread::sleep(DEVICE_WATCH_INTERVAL);
            }
        });
}

/// 枚举 adb 设备并登记：刷新 transport id，对新插上的设备起一次后台握手（见 [`observe_enumerated`]）。
fn enumerate_and_observe() -> Vec<crate::adb_winusb_transport::AdbDeviceInfo> {
    let list = AdbWinUsbDevice::enumerate().unwrap_or_default();
    let serials: Vec<String> = list
        .iter()
        .map(|info| serial_from_path(&info.device_path))
        .collect();
    proto::refresh_transport_ids(&serials);
    observe_enumerated(&serials);
    list
}

// ============================ 本进程直连（不经 5037 回环）============================

/// 本进程自己的 adb 命令直接在 hub 上开 `service` 流（shell/sync/exec/reboot…）。只在
/// [`inproc_server_running`]（hub 归本进程）时用：省掉每条命令一次 TCP 连接、两轮 host 协议往返和
/// server 侧两条线程，失败也不会被当成「server 扑空」去等它回来。
pub fn open_local_stream(serial: Option<&str>, service: &str) -> Result<MuxStreamIo, String> {
    let want = local_selector(serial).wanted_serial()?;
    open_device_stream(want.as_deref(), service).map(MuxStreamIo::new)
}

/// 本进程直连版 `host:devices[-l]`：wire 文本，每行 `序列号\t状态[…]`，不含表头。
pub fn local_devices(long: bool) -> String {
    MuxBackend.devices(long)
}

/// 本进程直连版 `get-state`。查不到设备与 5037 回 FAIL 同口径，归一成 `unknown`。
pub fn local_state(serial: Option<&str>) -> String {
    MuxBackend
        .state(&local_selector(serial))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// 空串 / `unknown` 等占位按「任意设备」处理，与 5037 client 发 `host:transport-any` 同口径。
fn local_selector(serial: Option<&str>) -> Selector {
    Selector::Serial(serial.unwrap_or_default().to_string())
}

// ============================ 后端实现 ============================

struct MuxBackend;

impl MuxBackend {
    /// 把选择器归一成「hub 要服务哪台设备」。`None` = 任意（单设备场景）。
    fn wanted(selector: &Selector) -> Result<Option<String>, String> {
        selector.wanted_serial()
    }
}

impl HostBackend for MuxBackend {
    fn log_tag(&self) -> &'static str {
        "[adb-mux-server]"
    }

    fn is_rmf_mux(&self) -> bool {
        true
    }

    /// 本次查询只枚举、绝不为查询单独开句柄——否则会与 hub 未建窗口内的直连操作抢 WinUSB 句柄。
    /// 新插上的设备交给 [`observe_enumerated`] 在后台建一次常驻 hub（握手即知授权与否）；
    /// 状态列按握手结论报 `device` / `recovery` / `unauthorized` / `sideload` / `offline`
    /// （见 [`device_state`]），
    /// banner 只在 hub 已建时才有。
    fn devices(&self, long: bool) -> String {
        let list = enumerate_and_observe();
        let hub = current_hub();
        let mut out = String::new();
        for info in &list {
            let serial = serial_from_path(&info.device_path);
            let banner = hub
                .as_ref()
                .filter(|h| h.serial == serial)
                .map(|h| &h.banner);
            out.push_str(&proto::device_line(
                &serial,
                device_state(&serial),
                long,
                banner,
            ));
        }
        out
    }

    fn resolve(&self, selector: &Selector) -> Result<String, String> {
        // A transport-id is valid only for a currently enumerated transport instance. Refresh
        // the active registry before looking it up so a stale id cannot survive an unplug.
        if matches!(selector, Selector::TransportId(_)) {
            let list = AdbWinUsbDevice::enumerate().map_err(|e| e.to_string())?;
            let serials: Vec<String> = list
                .iter()
                .map(|info| serial_from_path(&info.device_path))
                .collect();
            proto::refresh_transport_ids(&serials);
        }
        let want = Self::wanted(selector)?;
        // hub 已建时以它为准：单槽 hub 服务哪台设备，transport 就只能是哪台。
        if let Some(hub) = current_hub() {
            if let Some(err) = hub_serial_mismatch(&hub.serial, want.as_deref()) {
                return Err(err);
            }
            return Ok(hub.serial.clone());
        }
        pick_device_path_by_serial(want.as_deref()).map(|p| serial_from_path(&p))
    }

    fn state(&self, selector: &Selector) -> Result<String, String> {
        // 与 devices 同理：只枚举、不开句柄，状态按握手结论报（见 device_state）。
        self.resolve(selector)
            .map(|serial| device_state(&serial).to_string())
    }

    /// hub 已建时报「设备与本机的特性交集」（banner 只有 hub 拿得到）；hub 未建时**不为此建 hub**
    /// ——官方客户端在 tport 之前就会问 features，为它开一次设备会把未授权设备上的等待
    /// （connect 要等用户点授权）搬到这条查询上。退回本机集合即可：设备本来也只被我们的 CNXN
    /// banner 通告了这些特性，不会启用更多。
    fn device_features(&self, selector: &Selector) -> Result<String, String> {
        let serial = self.resolve(selector)?;
        match current_hub().filter(|h| h.serial == serial) {
            Some(hub) => Ok(crate::adb_protocol::negotiated_features(
                &hub.banner.features,
            )),
            None => Ok(crate::adb_protocol::ADB_HOST_FEATURES.to_string()),
        }
    }

    fn kill(&self) {
        // 进程内宿主（GUI）绝不 `process::exit`：`host:kill` 来自 scrcpy-cleanup / 外部 `adb kill-server`，
        // 我们是设备句柄的合法单一属主且全功能，对方可继续借道我们——不能（也无需）连宿主一起杀。
        // 独立 mux server 进程（rmf-cli `--adb-server-mux`）仍按官方语义退出让出 5037。
        if in_process_mode() {
            return;
        }
        std::process::exit(0);
    }

    fn forward(&self, selector: &Selector, req: &ForwardRequest) -> Result<ForwardReply, String> {
        match req {
            ForwardRequest::List => Ok(ForwardReply::List(forward_registry().list())),
            ForwardRequest::RemoveAll => {
                forward_registry().remove_all();
                Ok(ForwardReply::Done)
            }
            ForwardRequest::Remove { local } => {
                if forward_registry().remove(local) {
                    Ok(ForwardReply::Done)
                } else {
                    Err(format!("listener '{}' not found", local))
                }
            }
            ForwardRequest::Add {
                norebind,
                local,
                remote,
            } => {
                let serial = self.resolve(selector)?;
                let port = forward_add(&serial, *norebind, local, remote)?;
                // 客户端只在请求 tcp:0 时才关心实际端口；其余情形回 Done 少一帧。
                if tcp_port(local) == Some(0) {
                    Ok(ForwardReply::DonePort(port))
                } else {
                    Ok(ForwardReply::Done)
                }
            }
        }
    }

    fn serve_local(&self, mut stream: TcpStream, selector: Selector, svc: &str) -> io::Result<()> {
        let want = match Self::wanted(&selector) {
            Ok(w) => w,
            Err(e) => return proto::write_fail(&mut stream, &e),
        };
        let mux_stream = match open_device_stream(want.as_deref(), svc) {
            Ok(s) => s,
            Err(e) => return proto::write_fail(&mut stream, &e),
        };

        // 服务已在设备侧打开 → 回 OKAY，随后把设备 stream 与 client socket 双向桥接（阻塞至任一端结束）。
        proto::write_okay(&mut stream)?;
        use std::io::Write;
        stream.flush()?;
        bridge_stream_tcp_blocking(mux_stream, stream);
        Ok(())
    }
}

// ============================ 客户端侧：ensure/kill ============================

fn is_server_up() -> bool {
    TcpStream::connect_timeout(
        &std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, ADB_PORT)),
        Duration::from_millis(300),
    )
    .is_ok()
}

/// 确保 5037 上有一个我们用得上的 adb server。
///
/// 三种局面（判据见 [`crate::adb_mux_client::AdbServerOnPort`]）：
/// * 本项目 mux 已在位 → 零扰动返回。
/// * **外来 adb server 在位 → 借道，不动它。** 它同样是设备句柄的单一 owner，说的也是同一套
///   host 协议，我们的 client 全部命令都能经它执行。抢过来只会把对方（Android Studio、别的
///   刷机/投屏工具）正在跑的会话打断，而我们并不会因此多拿到任何能力。
/// * 端口空着或占用者根本不是 adb server（连得上却既不 OKAY 也不 FAIL）→ 拉起自研 mux；
///   后者要先 `host:kill` 清场，端口让出来才能绑。
pub fn ensure_server_running() {
    use crate::adb_mux_client::AdbServerOnPort;
    match crate::adb_mux_client::classify_server_confirmed() {
        AdbServerOnPort::RmfMux => return,
        AdbServerOnPort::ForeignAdb => {
            crate::logger::log_line(
                "[adb-mux-server] 5037 上是外来 adb server；借道复用，不抢占端口与设备句柄",
            );
            return;
        }
        AdbServerOnPort::Unknown => {
            crate::logger::log_line(
                "[adb-mux-server] 5037 被非 adb 程序占用；host:kill 清场后重拉 mux",
            );
            crate::adb_mux_client::kill_server();
            let deadline = std::time::Instant::now() + Duration::from_millis(1500);
            while std::time::Instant::now() < deadline && is_server_up() {
                thread::sleep(Duration::from_millis(50));
            }
        }
        AdbServerOnPort::Absent => {}
    }
    spawn_server();
    let deadline = std::time::Instant::now() + Duration::from_millis(2000);
    while std::time::Instant::now() < deadline {
        if is_server_up() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// scrcpy 投屏路径（`RMF_ADB_MUX=1`）由首个设备命令自动拉起常驻 mux server，后续命令全复用其
/// USB 连接，消除「mux 未起 → 回退直连」的反复重连；非 mux 路径不受影响。
pub fn ensure_mux_server_if_enabled() {
    if crate::adb_mux_client::is_mux_enabled() {
        ensure_server_running();
    }
}

fn spawn_server() {
    // 调用方已确认 5037 上没有 server，拉起后由它等待就绪；拉起失败同样表现为等待超时。
    if let Ok(mut command) = crate::self_spawn::detached_self(ADB_SERVER_MUX_ARG) {
        let _ = command.spawn();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        clear_if_same, device_state_from_handshake, hub_serial_mismatch, install_if_vacant,
        HubSetup,
    };
    use std::sync::Arc;
    use std::time::Duration;

    /// 调用者先超时退出，设备线程随后才完成；后来的调用者仍须等待同一任务，收到同一结果。
    #[test]
    fn hub_setup_survives_waiter_timeout_and_notifies_all_waiters() {
        let setup = Arc::new(HubSetup::default());
        assert_eq!(
            setup.wait(Duration::ZERO).err().as_deref(),
            Some("device hub setup timed out")
        );
        assert!(setup.result.lock().unwrap().is_none());

        let barrier = Arc::new(std::sync::Barrier::new(3));
        let waiters: Vec<_> = (0..2)
            .map(|_| {
                let setup = setup.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    setup.wait(Duration::from_secs(5)).err().unwrap()
                })
            })
            .collect();
        barrier.wait();
        setup.complete(Err("original USB error".into()));
        for waiter in waiters {
            assert_eq!(waiter.join().unwrap(), "original USB error");
        }
        assert_eq!(
            setup.wait(Duration::ZERO).err().as_deref(),
            Some("original USB error")
        );
    }

    #[test]
    fn device_state_requires_a_matching_connected_hub() {
        assert_eq!(
            device_state_from_handshake("A", None, false, false),
            "offline"
        );
        assert_eq!(
            device_state_from_handshake("A", Some(("B", "device")), false, false),
            "offline",
            "另一台设备的连接不能证明 A 已就绪"
        );
        assert_eq!(
            device_state_from_handshake("A", Some(("A", "device")), false, false),
            "device"
        );
        assert_eq!(
            device_state_from_handshake("A", Some(("A", "recovery")), false, false),
            "recovery"
        );
        assert_eq!(
            device_state_from_handshake("A", None, false, true),
            "unauthorized"
        );
        assert_eq!(
            device_state_from_handshake("A", None, true, false),
            "sideload"
        );
    }

    /// hub 快路径必须核对请求的 serial：装的是 A 时请求 B 要 FAIL，绝不静默发回 A 的 hub
    /// （client 会对错误的设备收发）。占位序列号（空串 / "unknown"）已由
    /// `Selector::wanted_serial` 归一成 None，到这里只剩「明确点名」与「任意」两种。
    #[test]
    fn hub_fast_path_rejects_mismatched_serial() {
        let err = hub_serial_mismatch("SERIAL_A", Some("SERIAL_B"));
        assert!(err.is_some(), "hub 装的是 A、请求 B 必须失败");
        let msg = err.unwrap();
        assert!(msg.contains("SERIAL_B") && msg.contains("SERIAL_A"));

        assert_eq!(hub_serial_mismatch("SERIAL_A", Some("SERIAL_A")), None);
        assert_eq!(hub_serial_mismatch("SERIAL_A", None), None);
    }

    /// hub 槽位的属主判定：占位不顶替、非属主不清除、属主 compare-and-clear 后可重装。
    /// 覆盖两类回归：open_stream 失败清掉活 hub（双读循环）、孤儿线程迟到抹掉新 hub。
    #[test]
    fn hub_slot_install_and_clear_are_identity_guarded() {
        let mut slot: Option<Arc<u32>> = None;
        let first = Arc::new(1u32);
        let second = Arc::new(2u32);

        assert!(install_if_vacant(&mut slot, &first), "空槽应装入成功");
        assert!(
            !install_if_vacant(&mut slot, &second),
            "已被占用绝不顶替（避免双读循环）"
        );

        assert!(
            !clear_if_same(&mut slot, &second),
            "非属主（迟到的孤儿线程）不得清除"
        );
        assert!(slot.is_some(), "健康 hub 必须原样保留");

        assert!(clear_if_same(&mut slot, &first), "属主可清除自己装的实例");
        assert!(slot.is_none());
        assert!(!clear_if_same(&mut slot, &first), "重复清除是安全的空操作");

        assert!(
            install_if_vacant(&mut slot, &second),
            "清空后新设备线程可装入"
        );
    }

    /// forward 注册表：同一主机端点重复添加要覆盖旧的（官方不带 --no-rebind 的语义），
    /// 撤销要如实回报有没有撤到东西。
    #[test]
    fn forward_registry_replaces_and_reports() {
        use super::{ForwardEntry, ForwardRegistry};
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        let reg = ForwardRegistry::default();
        let mk = |local: &str| ForwardEntry {
            serial: "S".into(),
            local: local.into(),
            remote: "tcp:9".into(),
            stop: Arc::new(AtomicBool::new(false)),
        };
        reg.insert(mk("tcp:1"));
        assert!(reg.contains("tcp:1"));
        assert!(reg.list().contains("S tcp:1 tcp:9"));

        assert!(reg.remove("tcp:1"), "撤掉已存在的转发应回 true");
        assert!(
            !reg.remove("tcp:1"),
            "撤一个不存在的转发必须回 false（客户端要看到 FAIL）"
        );

        reg.insert(mk("tcp:2"));
        reg.remove_all();
        assert!(reg.list().is_empty());
    }
}
