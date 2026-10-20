//! 进程内融入接口（embed）：宿主（rm_flash_logic）以直接函数调用使用自研 adb/fastboot——
//! 不打印、不 `process::exit`、不起子进程。
//! fastboot 侧：进程内全局 tokio runtime + `open_transport` + `driver`，同步返回结构化结果。
//! adb 侧：`AdbWinUsbDevice` 为 `!Send`，用「连接复用 hub」——单一 owner 线程持有已认证连接，
//! 其它线程经 channel 投递闭包执行（原命名管道 daemon 的进程内等价物，免每条命令重复 open/握手）。
//! 输出文本刻意对齐官方/自研 exe 的可解析格式，宿主既有文本解析无需改动即可复用。

use crate::driver::FastbootDriver;
use crate::error::{FastbootError, TransportError};
use crate::flash::ImageSource;
use crate::protocol::{self, reboot_error_text, reboot_ok_text, Response};
use crate::transport::AsyncTransport;
use crate::transport_open::open_transport;
use crate::usb_transport::UsbTransport;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

/// 取消纪元：宿主「停止」按钮经 `process.cancel` 递增、永不复位。分块 flash/update 与 adb 长传输
/// 都在自身起点取快照（[`CancelToken::current`]）、每块之间比对，命中即中止——替代旧 exe 模型
/// 「杀子进程」的中断能力（进程内已无子进程可杀）。
///
/// 刻意不用「每次分派开头复位的布尔标志」：多台设备并发刷写、后台 `devices` 轮询都会开新分派，
/// 一次复位就能把用户对另一条在途长传输按下的「停止」吞掉。纪元只增不减，不存在复位。
static CANCEL_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 请求取消所有在途的进程内 adb/fastboot 操作（由宿主 process.cancel 调用）。
/// 之后才开始的新操作以新纪元为起点，不受这次取消影响。
pub fn request_cancel() {
    CANCEL_EPOCH.fetch_add(1, Ordering::SeqCst);
}

/// 当前取消纪元快照。操作起点调用一次，之后用 [`cancelled_since`] 判断「自本操作开始后
/// 是否有人按过停止」。
fn cancel_epoch() -> u64 {
    CANCEL_EPOCH.load(Ordering::SeqCst)
}

/// 自 `epoch` 快照以来是否请求过取消。
fn cancelled_since(epoch: u64) -> bool {
    CANCEL_EPOCH.load(Ordering::SeqCst) != epoch
}

/// 单次 selfdev 操作私有的协作取消句柄。分派层（`process_mgr::run_selfdev_bounded`）每次操作
/// 新建一枚：调用方超时只取消自己这一枚，不撞全局纪元——后台 `adb devices` 轮询（5s 超时）
/// 排在长 `adb pull` 后面撞自己的超时时，不会连带掐断那条无关的传输。
#[derive(Clone, Debug, Default)]
pub struct OpCancel(std::sync::Arc<AtomicBool>);

impl OpCancel {
    pub fn new() -> Self {
        Self::default()
    }

    /// 取消这一次操作；其它在途操作不受影响。
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

thread_local! {
    /// 本线程当前 selfdev 操作的私有取消句柄。`process_mgr` 在分派线程上设置，`adb_hub`
    /// 在同一线程捕获后带进 hub job（与 [`OP_TIMEOUT_SECS`] 同一条贯通路径）。
    static OP_CANCEL: std::cell::RefCell<Option<OpCancel>> =
        const { std::cell::RefCell::new(None) };
}

/// 声明本线程接下来这次 selfdev 操作的私有取消句柄（None=清除声明）。
pub fn set_op_cancel(handle: Option<OpCancel>) {
    OP_CANCEL.with(|c| *c.borrow_mut() = handle);
}

/// 一次操作的取消判据：全局纪元（用户「停止」，作用于所有在途操作）+ 本操作私有句柄
/// （调用方超时，只作用于自己）。在发起操作的线程上取快照，随 hub job 传给传输层。
#[derive(Clone, Debug)]
pub(crate) struct CancelToken {
    epoch: u64,
    op: Option<OpCancel>,
}

impl CancelToken {
    /// 在当前线程取快照：全局纪元 + 本线程已声明的操作私有句柄（未声明则只看纪元）。
    pub fn current() -> Self {
        Self {
            epoch: cancel_epoch(),
            op: OP_CANCEL.with(|c| c.borrow().clone()),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        cancelled_since(self.epoch) || self.op.as_ref().is_some_and(OpCancel::is_cancelled)
    }
}

thread_local! {
    /// 本线程当前 selfdev 操作的调用方超时（秒；0=未声明）。`process_mgr` 在分派线程上设置，
    /// `adb_hub` 在同一线程捕获后带进 hub job，用于放宽 shell 的流式静默窗口（见 #run_command
    /// 的超时贯通：长 `su dd` 备份不再被传输层 60s 空闲读超时掐断）。
    static OP_TIMEOUT_SECS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// 声明本线程接下来这次 selfdev 操作的调用方超时（秒；0=清除声明）。
pub fn set_op_timeout_secs(secs: u32) {
    OP_TIMEOUT_SECS.with(|c| c.set(secs));
}

/// 读取本线程声明的操作超时（秒；0=未声明）。
pub(crate) fn op_timeout_secs() -> u32 {
    OP_TIMEOUT_SECS.with(|c| c.get())
}

// ============================ 实时传输快照 ============================
// LineSink 的阶段行要命令结束才批量回传，刷写期间宿主拿不到进度。此处用原子计数器暴露
// 「已发/总字节」与分段状态，宿主 UI 轮询快照即可驱动实时进度条与速率。
//
// 计数按**传输通道**隔离，通道键是发起操作时的 `-s` 序列号（未指定为空串）：批量刷机多台同时
// 下发，共用一份计数会互相清零、互相累加。宿主按自己下发命令时用的序列号查询即可拿到那一台；
// 不指定设备的查询取「最近一次开始传输」的通道——单设备场景（ROOT 分区回读、欧加线刷等）
// 同一时刻只有一条传输，两种查法得到的是同一份数据。
use std::sync::atomic::AtomicU64;

#[derive(Default)]
struct XferState {
    sent: AtomicU64,
    total: AtomicU64,
    active: AtomicBool,
    // 分段刷写状态：镜像超过 max-download-size 被切段时宿主要能显示「刷到第几段」；
    // 每段 download 后设备落盘期间链路无流量，也要显示「设备端处理中」而非停摆的速率。
    seg_index: AtomicU64,
    seg_total: AtomicU64,
    dev_busy: AtomicBool,
}

fn xfer_channels() -> &'static Mutex<HashMap<String, Arc<XferState>>> {
    static CHANNELS: OnceLock<Mutex<HashMap<String, Arc<XferState>>>> = OnceLock::new();
    CHANNELS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 最近一次 [`Xfer::begin`] 的通道，供不指定设备的快照查询。
fn xfer_latest() -> &'static Mutex<Option<Arc<XferState>>> {
    static LATEST: OnceLock<Mutex<Option<Arc<XferState>>>> = OnceLock::new();
    LATEST.get_or_init(|| Mutex::new(None))
}

/// 一条传输通道的写入端。同一序列号的多次操作复用同一通道（每次 `begin` 清零），
/// 宿主看门线程对同一台设备的轮询因此不必感知命令边界。
#[derive(Clone)]
pub(crate) struct Xfer(Arc<XferState>);

impl Xfer {
    /// 取 `serial` 对应的通道（不存在则建）。不改动计数，`begin` 才开始新一轮。
    pub(crate) fn channel(serial: Option<&str>) -> Self {
        let key = serial.unwrap_or("").to_string();
        let mut channels = xfer_channels().lock().unwrap_or_else(|e| e.into_inner());
        Self(channels.entry(key).or_default().clone())
    }

    /// 新一轮传输开始（total=预计下发总字节；0 表示未知）。
    pub(crate) fn begin(&self, total: u64) {
        let s = &self.0;
        s.sent.store(0, Ordering::SeqCst);
        s.total.store(total, Ordering::SeqCst);
        s.seg_index.store(0, Ordering::SeqCst);
        s.seg_total.store(0, Ordering::SeqCst);
        s.dev_busy.store(false, Ordering::SeqCst);
        s.active.store(true, Ordering::SeqCst);
        *xfer_latest().lock().unwrap_or_else(|e| e.into_inner()) = Some(self.0.clone());
    }

    /// 累加已传输字节（driver progress 回调的 delta 语义）。
    pub(crate) fn add(&self, delta: u64) {
        self.0.sent.fetch_add(delta, Ordering::Relaxed);
    }

    /// 追加预计总字节（update 等开始时总量未知、逐任务累加的场景）。
    pub(crate) fn add_total(&self, delta: u64) {
        self.0.total.fetch_add(delta, Ordering::SeqCst);
    }

    /// 上报分段进度（index 从 1 起；total=0 表示本次刷写没有分段）。
    pub(crate) fn set_segment(&self, index: u64, total: u64) {
        self.0.seg_index.store(index, Ordering::SeqCst);
        self.0.seg_total.store(total, Ordering::SeqCst);
    }

    /// 数据已发完、设备端正在落盘（download 返回 → flash 返回之间）。
    pub(crate) fn set_device_busy(&self, busy: bool) {
        self.0.dev_busy.store(busy, Ordering::SeqCst);
    }

    /// 本轮传输结束（成功/失败/取消都要调用）。
    pub(crate) fn end(&self) {
        self.0.active.store(false, Ordering::SeqCst);
        self.0.dev_busy.store(false, Ordering::SeqCst);
    }

    fn snapshot(&self) -> XferSnapshot {
        let s = &self.0;
        XferSnapshot {
            active: s.active.load(Ordering::SeqCst),
            sent: s.sent.load(Ordering::Relaxed),
            total: s.total.load(Ordering::SeqCst),
            seg_index: s.seg_index.load(Ordering::SeqCst),
            seg_total: s.seg_total.load(Ordering::SeqCst),
            device_busy: s.dev_busy.load(Ordering::SeqCst),
        }
    }
}

/// 一轮传输的作用域守卫：构造即 `begin`，析构即 `end`——任何早退路径都不会让 active 残留、
/// 误导下一次操作的看门线程。供 adb push/pull 这类「一轮传输 = 一个函数体」的路径使用。
pub(crate) struct XferRun(Xfer);

impl XferRun {
    pub(crate) fn start(serial: Option<&str>, total: u64) -> Self {
        let xfer = Xfer::channel(serial);
        xfer.begin(total);
        Self(xfer)
    }

    pub(crate) fn add(&self, delta: u64) {
        self.0.add(delta);
    }
}

impl Drop for XferRun {
    fn drop(&mut self) {
        self.0.end();
    }
}

/// 一条传输通道的快照。段号仅在 `active` 期间有意义。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XferSnapshot {
    pub active: bool,
    pub sent: u64,
    pub total: u64,
    pub seg_index: u64,
    pub seg_total: u64,
    pub device_busy: bool,
}

/// 读传输快照。`serial` 为 `Some` 时读那台设备的通道（从未传输过则为全零的非活动快照），
/// `None` 时读最近一次开始传输的通道。
pub fn xfer_snapshot(serial: Option<&str>) -> XferSnapshot {
    match serial {
        Some(serial) => {
            let channels = xfer_channels().lock().unwrap_or_else(|e| e.into_inner());
            channels
                .get(serial)
                .map(|state| Xfer(state.clone()).snapshot())
                .unwrap_or_default()
        }
        None => xfer_latest()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .map(|state| Xfer(state).snapshot())
            .unwrap_or_default(),
    }
}

/// connect_probe 的读超时（毫秒）：只做几次 USB 往返，毫秒级完成；给 5s 冗余容忍慢设备，
/// 同时保证未授权设备也能快速判定，绝不触发长时间授权等待。
const CONNECT_PROBE_TIMEOUT_MS: u32 = 5_000;

/// 进程内全局 tokio runtime（fastboot 异步驱动用）。宿主是同步环境（无 ambient runtime），
/// 故可安全 `block_on`；懒初始化，多线程 2 worker 足够（USB IO 为主、非 CPU 密集）。
fn rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("创建 tokio runtime 失败")
    })
}

fn err_string(e: FastbootError) -> String {
    e.to_string()
}

/// 是否为「设备掉线」类错误。`oem edl`/`reboot edl` 等命令让设备立刻重启，常在回 OKAY 前断链
/// （官方 fastboot 同样容忍）；NoLink/Disconnected/Timeout 视为「命令已生效、设备已离开 fastboot」。
fn is_disconnect_err(e: &FastbootError) -> bool {
    matches!(
        e,
        FastbootError::Timeout
            | FastbootError::Transport(TransportError::Timeout)
            | FastbootError::Transport(TransportError::NoLink)
            | FastbootError::Transport(TransportError::Disconnected)
    )
}

/// 判断一条 oem/命令是否属于「会让设备立刻掉线」的重启类命令（进 EDL、reboot-* 等）。
/// 命中后即便收不到 OKAY，只要是掉线类错误就判成功。
fn is_reboot_like_cmd(cmd: &str) -> bool {
    let c = cmd.trim().to_ascii_lowercase();
    c == "edl" || c == "reboot-edl" || c.starts_with("reboot") || c.contains("edl")
}

use crate::adb_winusb_transport::serial_from_path;

/// 线程安全的日志行收集器：供 flash/update 等把「阶段/进度」行喂给宿主（批量回传，非实时流）。
#[derive(Clone, Default)]
pub struct LineSink(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl LineSink {
    pub fn new() -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())))
    }
    pub fn push(&self, s: impl Into<String>) {
        if let Ok(mut v) = self.0.lock() {
            v.push(s.into());
        }
    }
    /// 取走已收集的行（清空）。
    pub fn take(&self) -> Vec<String> {
        self.0
            .lock()
            .map(|mut v| std::mem::take(&mut *v))
            .unwrap_or_default()
    }
}

// ============================ Fastboot 侧 ============================

/// `fastboot devices`：枚举 fastboot 模式设备（不开句柄），每行 `serial\tfastboot`。
pub fn fb_devices() -> String {
    let mut out = String::new();
    if let Ok(list) = UsbTransport::enumerate_devices() {
        for d in list {
            out.push_str(&d.serial_number);
            out.push('\t');
            out.push_str("fastboot");
            out.push('\n');
        }
    }
    out
}

/// 判断某变量的值是否可能经多条 INFO 行返回（如 token / unlock_data）。这类值常超过单条
/// response payload 上限（252B），设备分多条 INFO 发送；须收集 INFO 行而非只取 OKAY payload。
fn var_returns_info_lines(var: &str) -> bool {
    let v = var.to_ascii_lowercase();
    v == "token" || v.contains("token") || v.contains("unlock")
}

/// 把 token/unlock 这类「值分散在多条 INFO 行」的回包整理成待回显的行序列——**忠实还原官方
/// fastboot 的 getvar 回显**：INFO 行原样逐行给出（每行常自带 `token:`/`blob:` 前缀，官方也是
/// 逐行打 `(bootloader) <info>`），OKAY 若带值补一行 `var: value`。拼接不在这里做，交给唯一的
/// 归一器 `parse_fastboot_auth_blob`（它按行剥 `(bootloader)`/`token:`/`blob:` 前缀再拼）。
///
/// 早先这里把各 INFO 行 trim 后 `join("")` 再套一层 `var: …`，会把每行自带的 `token:` 前缀连同
/// 内容一起并进值里（读出 `token: token: AABB…`）：解析器只剥得掉最外层一个 `token:`，内层前缀
/// 原样留在 token 里，于是自研协议读出的 token 与官方 fastboot 不一致。
pub(crate) fn info_var_reply_lines(var: &str, info: &[String], okay: &str) -> Vec<String> {
    let mut lines: Vec<String> = info
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let okay = okay.trim();
    if !okay.is_empty() {
        lines.push(format!("{}: {}", var, okay));
    }
    lines
}

/// `fastboot getvar <var>`：单变量返回 `var: value`（对齐官方便于解析）；`all` 返回逐行 key:value；
/// token/unlock 类长变量经多条 INFO 行返回，专门收集拼接。
pub fn fb_getvar(serial: Option<&str>, var: &str) -> Result<String, String> {
    rt().block_on(getvar_with_reopen(var, || open_transport(serial)))
}

/// 同一设备的只读信息批量采集：一次打开、逐项查询，结束即释放，不缓存跨设备会话。
pub fn fb_getvars(serial: Option<&str>, vars: &[&str]) -> Result<String, String> {
    rt().block_on(getvars_with_reopen(vars, || open_transport(serial)))
}

enum GetvarReply {
    All(Vec<String>),
    WithInfo(Response, Vec<String>),
    Value(String),
}

async fn query_getvar<T: AsyncTransport>(
    driver: &mut FastbootDriver<T>,
    var: &str,
) -> Result<GetvarReply, FastbootError> {
    if var.eq_ignore_ascii_case("all") {
        driver.get_var_all().await.map(GetvarReply::All)
    } else if var_returns_info_lines(var) {
        // 保留 token/unlock_data 的 INFO 行；格式化仍交给 info_var_reply_lines。
        let (response, info) = driver
            .raw_command_with_info(&format!("getvar:{}", var))
            .await?;
        match response {
            Response::Okay(_) | Response::Fail(_) => Ok(GetvarReply::WithInfo(response, info)),
            other => Err(FastbootError::Protocol(format!(
                "getvar:{var} 返回异常终态: {other:?}"
            ))),
        }
    } else {
        driver.get_var(var).await.map(GetvarReply::Value)
    }
}

fn format_getvar_reply(var: &str, reply: GetvarReply) -> Result<String, String> {
    match reply {
        GetvarReply::All(vars) => Ok(vars.join("\n")),
        GetvarReply::Value(value) => Ok(format!("{}: {}", var, value)),
        GetvarReply::WithInfo(response, info) => {
            let okay = match response {
                Response::Okay(value) => value,
                Response::Fail(message) => return Err(format!("FAILED: {}", message)),
                other => {
                    return Err(format!("协议异常：getvar:{var} 返回异常终态: {other:?}"));
                }
            };
            let lines = info_var_reply_lines(var, &info, &okay);
            if lines.is_empty() {
                return Err(format!(
                    "设备未返回 {} 数据（getvar:{} 无 INFO/OKAY 内容，可能不支持或需 oem get_token）",
                    var, var
                ));
            }
            Ok(lines.join("\n"))
        }
    }
}

/// getvar 是只读查询：协议异常后完整关闭旧连接，再新开一次连接重读。
/// 仅此入口有这次重开，DATA/flash/erase 等状态变更操作不会走这条恢复路径。
async fn getvar_with_reopen<T, Open, OpenFuture>(var: &str, open: Open) -> Result<String, String>
where
    T: AsyncTransport,
    Open: FnMut() -> OpenFuture,
    OpenFuture: std::future::Future<Output = Result<T, FastbootError>>,
{
    getvars_with_reopen(&[var], open).await
}

async fn getvars_with_reopen<T, Open, OpenFuture>(
    vars: &[&str],
    mut open: Open,
) -> Result<String, String>
where
    T: AsyncTransport,
    Open: FnMut() -> OpenFuture,
    OpenFuture: std::future::Future<Output = Result<T, FastbootError>>,
{
    if vars.is_empty() || vars.iter().any(|var| var.trim().is_empty()) {
        return Err("getvar 需要变量名".into());
    }
    let mut first_protocol_error = None;
    'reopen: loop {
        let transport = match open().await {
            Ok(transport) => transport,
            Err(error) => {
                return Err(match first_protocol_error {
                    Some(first) => format!("{first}; 重新打开 fastboot 连接失败: {error}"),
                    None => err_string(error),
                });
            }
        };
        let mut driver = FastbootDriver::new(transport);
        let mut lines = Vec::with_capacity(vars.len());
        for var in vars {
            match query_getvar(&mut driver, var).await {
                Ok(reply) => lines.push(format_getvar_reply(var, reply).map_err(|error| {
                    match &first_protocol_error {
                        Some(first) => format!("{first}; 重新连接后读取失败: {error}"),
                        None => error,
                    }
                })?),
                Err(FastbootError::Device(message)) if vars.len() > 1 => {
                    lines.push(format!("getvar:{var} FAILED ({message})"));
                }
                Err(error @ FastbootError::Protocol(_)) if first_protocol_error.is_none() => {
                    let mut detail = format!("getvar:{var} 首次读取失败: {error}");
                    if let Err(close_error) = driver.close_transport().await {
                        detail.push_str(&format!("; 关闭旧连接失败: {close_error}"));
                    }
                    // 必须先析构旧 transport，才允许下一轮 open 打开同一接口。
                    drop(driver);
                    first_protocol_error = Some(detail);
                    continue 'reopen;
                }
                Err(error) => {
                    return Err(match first_protocol_error {
                        Some(first) => format!("{first}; 重新连接后读取失败: {error}"),
                        None => err_string(error),
                    });
                }
            }
        }
        return Ok(lines.join("\n"));
    }
}

/// 依据 `--slot` 覆盖值与设备 has-slot/current-slot 把基础分区名解析为待刷分区列表（对齐官方）：
/// 已带 `_a`/`_b` 原样返回；非槽位分区返回单元素；override 支持 a/b/other/all，None 用 current-slot。
pub(crate) async fn resolve_slot_targets(
    d: &mut FastbootDriver<UsbTransport>,
    part: &str,
    slot_override: Option<&str>,
) -> Vec<String> {
    if part.ends_with("_a") || part.ends_with("_b") {
        return vec![part.to_string()];
    }
    // boot/init_boot 历史上即便设备不报 has-slot 也按槽位处理（很多 bootloader 未实现 has-slot 查询）。
    let force_slotted = part == "boot" || part == "init_boot";
    let has_slot = d
        .get_var(&format!("has-slot:{}", part))
        .await
        .map(|v| v.trim().eq_ignore_ascii_case("yes"))
        .unwrap_or(false);
    if !has_slot && !force_slotted {
        return vec![part.to_string()];
    }
    let current = d
        .get_var("current-slot")
        .await
        .map(|s| s.trim().trim_start_matches('_').to_ascii_lowercase())
        .unwrap_or_default();
    let with = |slot: &str| format!("{}_{}", part, slot);
    match slot_override
        .map(|s| s.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("all") => vec![with("a"), with("b")],
        Some("other") => match current.as_str() {
            "a" => vec![with("b")],
            "b" => vec![with("a")],
            _ => vec![part.to_string()],
        },
        Some("a") | Some("_a") => vec![with("a")],
        Some("b") | Some("_b") => vec![with("b")],
        // None 或未识别：用当前槽；查不到当前槽则原样（不强行加后缀）。
        _ => match current.as_str() {
            "a" => vec![with("a")],
            "b" => vec![with("b")],
            _ => vec![part.to_string()],
        },
    }
}

/// AVB vbmeta 头部 `flags` 字段偏移：大端 u32，位于 AvbVBMetaImageHeader 的固定偏移 120。
/// 参见 AOSP external/avb 的 avb_vbmeta_image.h（magic[4] 开头，flags 前有一串 u32/u64 字段）。
const AVB_VBMETA_FLAGS_OFFSET: usize = 120;
const AVB_MAGIC: &[u8; 4] = b"AVB0";
/// `--disable-verity`：置 HASHTREE_DISABLED 位（关闭 dm-verity）。
const AVB_FLAG_HASHTREE_DISABLED: u32 = 0x1;
/// `--disable-verification`：置 VERIFICATION_DISABLED 位（关闭整体校验）。
const AVB_FLAG_VERIFICATION_DISABLED: u32 = 0x2;

/// 对 vbmeta 镜像原地设置 AVB 禁用位（对齐官方 `--disable-verity/--disable-verification`）。
/// 仅当以 `AVB0` 魔数开头且长度足够时才改写，否则报错（拒绝盲改非 vbmeta 镜像）。返回改写后的 flags。
pub(crate) fn apply_vbmeta_disable_flags(
    data: &mut [u8],
    disable_verity: bool,
    disable_verification: bool,
) -> Result<u32, String> {
    if data.len() < AVB_VBMETA_FLAGS_OFFSET + 4 || &data[0..4] != AVB_MAGIC {
        return Err(
            "目标镜像不是有效的 vbmeta（缺少 AVB0 魔数），拒绝设置 disable-verity/verification 标志"
                .to_string(),
        );
    }
    let off = AVB_VBMETA_FLAGS_OFFSET;
    let mut flags = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
    if disable_verity {
        flags |= AVB_FLAG_HASHTREE_DISABLED;
    }
    if disable_verification {
        flags |= AVB_FLAG_VERIFICATION_DISABLED;
    }
    data[off..off + 4].copy_from_slice(&flags.to_be_bytes());
    Ok(flags)
}

// ======================== 失败分类 ========================
// 单次下发上限的判据（含为何不能信设备自报值）见 [`protocol::effective_download_limit`]。

use crate::protocol::{effective_download_limit, MIN_ADAPTIVE_DOWNLOAD_LIMIT};

/// 链路彻底失效的上报标记。编排层（`rm-flash-logic` 欧加线刷主循环）据此判定「设备已不在链路上」
/// 并立即中止后续分区，而不是拿废句柄把剩下几十个分区刷成一片红字。属跨层契约，勿改文案。
pub const FLASH_LINK_LOST_TAG: &str = "设备链路中断";

/// 刷写失败分类：区分「链路型」（USB 端点/句柄已废，必须重开连接才有可能继续）与「设备型」
/// （设备明确回 FAIL 或本地文件问题，重开连接无用）。决定是否重建会话 + 降级重试。
struct FlashFailure {
    msg: String,
    transport: bool,
}

impl FlashFailure {
    /// 本地/协议层面的确定性失败：重试无意义。
    fn device(msg: String) -> Self {
        FlashFailure {
            msg,
            transport: false,
        }
    }
    /// 由 fastboot 错误分类：只有 `Transport(_)` 才算链路型。
    fn from_fastboot(e: FastbootError) -> Self {
        let transport = matches!(e, FastbootError::Transport(_));
        FlashFailure {
            msg: err_string(e),
            transport,
        }
    }
}

/// `fastboot flash <part> <img>`：超过有效单片上限时自动按需 sparse/raw 分块。
/// `disable_verity/verification` 仅在刷 vbmeta* 时生效——原地改镜像 AVB flags，与官方等价。
pub fn fb_flash(
    serial: Option<&str>,
    partition: &str,
    image_path: &str,
    disable_verity: bool,
    disable_verification: bool,
    slot_override: Option<&str>,
    sink: &LineSink,
) -> Result<String, String> {
    let op = FlashOp::new(serial);
    let result = fb_flash_impl(
        serial,
        partition,
        image_path,
        disable_verity,
        disable_verification,
        slot_override,
        sink,
        &op,
    );
    op.xfer.end();
    result
}

/// 一次刷写操作的传输上下文：进度写哪条通道、按什么判据中止。必须在发起操作的分派线程上构造——
/// 取消判据在那里取快照，才能同时认得「停止」纪元与本操作私有的超时句柄（见 [`CancelToken`]）。
#[derive(Clone)]
struct FlashOp {
    xfer: Xfer,
    cancel: CancelToken,
}

impl FlashOp {
    fn new(serial: Option<&str>) -> Self {
        Self {
            xfer: Xfer::channel(serial),
            cancel: CancelToken::current(),
        }
    }
}

// ============================ 可复用 fastboot 会话 ============================
// 一次开 transport，后续 flash/erase 复用同一连接，消除逐分区重开 USB + 重复 getvar 的停顿。
// 会话按 `-s` 序列号各存一份（未指定为空串）：批量刷机多台同时 begin→flash×N→end，
// 只有一个全局槽位时后 begin 的那台会顶掉前一台的连接，两台的写入还会被这把锁串成一条。

struct FbSession {
    driver: FastbootDriver<UsbTransport>,
    /// 会话对应的设备序列号：链路被设备中断后要靠它重开同一台设备的 transport。
    serial: Option<String>,
    /// 当前有效的单片下发上限。会话内**单调下降**：一旦某个分区证明设备收不下这么大，
    /// 后面同样大的分区就直接用降过的粒度，不必每个都先撞一次墙。
    limit: u64,
}

type FbSessionCell = Arc<Mutex<FbSession>>;

/// 序列号 → 会话。外层锁只在查表/增删的瞬间持有；每个会话自己那把锁贯穿该设备的整次操作。
fn fb_sessions() -> &'static Mutex<HashMap<String, FbSessionCell>> {
    static SESSIONS: OnceLock<Mutex<HashMap<String, FbSessionCell>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn session_key(serial: Option<&str>) -> String {
    serial.unwrap_or("").to_string()
}

fn fb_session(serial: Option<&str>) -> Result<FbSessionCell, String> {
    fb_sessions()
        .lock()
        .map_err(|_| "fastboot 会话表损坏".to_string())?
        .get(&session_key(serial))
        .cloned()
        .ok_or_else(|| "fastboot 会话未打开".to_string())
}

/// 打开可复用会话：开 transport + 查一次 max_download，按序列号登记。同一序列号重复 begin
/// 会丢弃该台的旧会话；其它设备的会话不受影响。
pub fn fb_session_begin(serial: Option<&str>) -> Result<String, String> {
    // 先摘掉旧会话再开新 transport：旧会话的句柄还占着同一接口，不先释放新句柄打不开。
    if let Ok(mut sessions) = fb_sessions().lock() {
        sessions.remove(&session_key(serial));
    }
    rt().block_on(async {
        let t = open_transport(serial).await.map_err(err_string)?;
        let mut d = FastbootDriver::new(t);
        let max_download = d.get_max_download_size().await.unwrap_or(512 * 1024 * 1024);
        let session = FbSession {
            driver: d,
            serial: serial.map(|s| s.to_string()),
            limit: effective_download_limit(max_download),
        };
        fb_sessions()
            .lock()
            .map_err(|_| "fastboot 会话表损坏".to_string())?
            .insert(session_key(serial), Arc::new(Mutex::new(session)));
        Ok("OKAY".to_string())
    })
}

/// 在会话内刷写单分区（复用 transport）。行为与 `fb_flash` 逐字一致，仅省去每次自开 transport。
// 会话锁有意贯穿整次操作：它就是「这台设备的 transport 同一时刻只有一个使用者」的保证。
// future 由 `rt().block_on` 在调用线程上驱动，内部不会再取这把锁，其他线程只会同步等待，
// 不存在 clippy 所防的「同线程另一任务抢锁」死锁。
#[allow(clippy::await_holding_lock)]
#[allow(clippy::too_many_arguments)]
pub fn fb_session_flash(
    serial: Option<&str>,
    partition: &str,
    image_path: &str,
    disable_verity: bool,
    disable_verification: bool,
    slot_override: Option<&str>,
    sink: &LineSink,
) -> Result<String, String> {
    let path = Path::new(image_path);
    if !path.exists() {
        return Err(format!("镜像不存在: {}", image_path));
    }
    let file_size = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(e) => return Err(e.to_string()),
    };
    if file_size == 0 {
        return Err("镜像文件为空".to_string());
    }
    let cell = fb_session(serial)?;
    let op = FlashOp::new(serial);
    let start = Instant::now();
    let result = rt().block_on(async {
        let mut sess = cell.lock().map_err(|_| "fastboot 会话锁损坏".to_string())?;
        let sess = &mut *sess;
        let mut limit = sess.limit;
        let outcome = flash_adaptive(
            &mut sess.driver,
            sess.serial.as_deref(),
            &mut limit,
            partition,
            path,
            file_size,
            disable_verity,
            disable_verification,
            slot_override,
            sink,
            &op,
        )
        .await;
        // 降级后的粒度必须留在会话里：后面的 recovery/vendor_boot 与 boot 同样大，
        // 沿用降过的上限才不会一个个再撞一次中断。
        sess.limit = limit;
        outcome?;
        let secs = start.elapsed().as_secs_f64();
        sink.push(format!("OKAY [ {:>6.3}s]", secs));
        Ok::<String, String>(format!("OKAY [ {:>6.3}s]", secs))
    });
    op.xfer.end();
    result
}

/// 在会话内擦除分区（复用 transport）。
// 会话锁有意贯穿整次操作，理由同 [`fb_session_flash`]。
#[allow(clippy::await_holding_lock)]
pub fn fb_session_erase(serial: Option<&str>, partition: &str) -> Result<String, String> {
    let cell = fb_session(serial)?;
    rt().block_on(async {
        let mut sess = cell.lock().map_err(|_| "fastboot 会话锁损坏".to_string())?;
        sess.driver.erase(partition).await.map_err(err_string)?;
        Ok(format!("Erasing '{}' OKAY", partition))
    })
}

/// 关闭并释放该序列号的会话（transport 随之关闭）。无论成败都应调用；无会话时安全空操作。
/// 正在使用这条会话的操作持有它的 `Arc`，摘表后等那次操作结束才真正关闭 transport。
pub fn fb_session_end(serial: Option<&str>) -> String {
    if let Ok(mut sessions) = fb_sessions().lock() {
        sessions.remove(&session_key(serial));
    }
    "OKAY".to_string()
}

#[allow(clippy::too_many_arguments)]
fn fb_flash_impl(
    serial: Option<&str>,
    partition: &str,
    image_path: &str,
    disable_verity: bool,
    disable_verification: bool,
    slot_override: Option<&str>,
    sink: &LineSink,
    op: &FlashOp,
) -> Result<String, String> {
    let start = Instant::now();
    rt().block_on(async {
        let path = Path::new(image_path);
        if !path.exists() {
            return Err(format!("镜像不存在: {}", image_path));
        }
        let file_size = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
        if file_size == 0 {
            return Err("镜像文件为空".to_string());
        }
        let t = open_transport(serial).await.map_err(err_string)?;
        let mut d = FastbootDriver::new(t);
        let max_download = d.get_max_download_size().await.unwrap_or(512 * 1024 * 1024);
        let mut limit = effective_download_limit(max_download);

        flash_adaptive(
            &mut d,
            serial,
            &mut limit,
            partition,
            path,
            file_size,
            disable_verity,
            disable_verification,
            slot_override,
            sink,
            op,
        )
        .await?;

        let secs = start.elapsed().as_secs_f64();
        sink.push(format!("OKAY [ {:>6.3}s]", secs));
        Ok(format!("OKAY [ {:>6.3}s]", secs))
    })
}

/// 重开 transport 顶替 driver 里那条已废的链路。分两级，都保证**先释放旧 WinUSB 句柄再重开**——
/// 旧实现直接 `open_transport` 抢新句柄，而 driver 里那条坏链路的旧句柄此刻仍占着同一接口，
/// `WinUsb_Initialize` 撞未释放句柄得 ACCESS_DENIED，正是日志里「USB 端口被占用且智能路由失败」。
///
/// 一级：`deep_reset`（`reinitialize`）先 Free/Close 旧句柄、再用同一 device_path 重开。设备未被
/// 拔出、仅链路被掐断（最常见）时即可就地自愈，且天然不与自己的旧句柄抢占；重开后 100ms 内句柄可能
/// 「能开不能 IO」，故用只读 getvar 探测确认能 IO 才复用。
/// 二级：一级失败或重开句柄仍不可 IO 时，先 `close_transport` 释放（幂等，句柄已空则无操作）腾出接口，
/// 等设备落回总线后由 `open_transport`（open + getvar 探测 + 退避重开）重新枚举打开，整体替换。
async fn reopen_driver(
    driver: &mut FastbootDriver<UsbTransport>,
    serial: Option<&str>,
) -> Result<(), String> {
    // 一级：就地重开同一设备句柄（reinitialize 内部先释放旧句柄，消除「撞自己句柄」的端口占用）。
    if driver.deep_reset().await.is_ok() {
        // transport 的读写在 async 里同步阻塞，tokio 计时器抢占不了：3s 上限必须落到 driver 超时
        // （即 WinUSB 管道超时）上，否则设备还卡在 DATA 阶段时这一步会干等满常规超时。
        let prev_timeout = driver.timeout();
        driver.set_timeout(std::time::Duration::from_secs(3));
        driver.set_auto_retry(false);
        let usable = matches!(driver.check_connection().await, Ok(true));
        driver.set_auto_retry(true);
        driver.set_timeout(prev_timeout);
        if usable {
            return Ok(());
        }
    }
    // 二级：一级失败或句柄仍不可 IO。显式释放坏句柄腾出接口（避免下面的 open_transport 再撞自己），
    // 等设备落回总线后重新枚举打开。
    let _ = driver.close_transport().await;
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let t = open_transport(serial).await.map_err(err_string)?;
    *driver = FastbootDriver::new(t);
    Ok(())
}

/// 带「链路自愈 + 单片上限自适应降级」的单分区刷写。
///
/// 设备把一次下发中途掐断时（`Transport(_)`，Windows 侧表现为 WinUSB 写入失败后端点连带失效），
/// 单纯重试没有意义——必须两件事一起做：
///   1. 重开 transport：原句柄已废，继续用它发数据只会得到「设备不识别此命令」的连锁失败；
///   2. 把单片上限对折：同样的大小再发一次会在同一位置再断一次。
///
/// 降到 [`MIN_ADAPTIVE_DOWNLOAD_LIMIT`] 仍被中断，就不再是「一次发太多」，而是线材/端口/驱动
/// 问题，此时带 [`FLASH_LINK_LOST_TAG`] 上报，让编排层立即停手而不是继续刷剩下的分区。
#[allow(clippy::too_many_arguments)]
async fn flash_adaptive(
    driver: &mut FastbootDriver<UsbTransport>,
    serial: Option<&str>,
    limit: &mut u64,
    partition: &str,
    path: &Path,
    file_size: u64,
    disable_verity: bool,
    disable_verification: bool,
    slot_override: Option<&str>,
    sink: &LineSink,
    op: &FlashOp,
) -> Result<(), String> {
    // 小分区（一次性下发，file_size <= limit）被掐断时，降 download 上限没有意义（本就一片发完）——
    // 真正该做的是重置端点 + 重建链路后原样重试；给有限次数，用尽即判链路故障。只有大分区（需分片）
    // 才通过对折 limit 缩小单片来适应设备落盘能力。
    const SMALL_PART_MAX_RETRY: u32 = 3;
    let mut small_retry_left = SMALL_PART_MAX_RETRY;
    loop {
        let attempt = flash_on_open_driver(
            driver,
            partition,
            path,
            file_size,
            disable_verity,
            disable_verification,
            slot_override,
            *limit,
            sink,
            op,
        )
        .await;
        let failure = match attempt {
            Ok(()) => return Ok(()),
            Err(f) => f,
        };
        // 设备明确拒绝 / 本地文件问题：重连与降级都改变不了结果，直接上报。
        if !failure.transport {
            return Err(failure.msg);
        }
        if op.cancel.is_cancelled() {
            return Err(failure.msg);
        }

        // 小分区（一次性下发）：降 download 上限对它无效，重置端点 + 重建链路后原样重试有限次。
        // abl/xbl 这类 KB 级关键分区正走这里——旧逻辑对它反复打印「降到 N MiB」纯属空转刷红字。
        if file_size <= *limit {
            if small_retry_left == 0 {
                return Err(format!(
                    "{}：{}（{} KB 小分区重置端点并重连 {} 次仍被设备掐断，多为线材/USB 口/该分区被设备锁定，请换 USB 口或数据线后重试）",
                    FLASH_LINK_LOST_TAG,
                    failure.msg,
                    file_size / 1024,
                    SMALL_PART_MAX_RETRY
                ));
            }
            small_retry_left -= 1;
            sink.push(format!(
                "链路被设备掐断（{}）：重置端点并重建连接后原样重试 '{}'（剩余 {} 次）",
                failure.msg, partition, small_retry_left
            ));
            if let Err(e) = reopen_driver(driver, serial).await {
                return Err(format!(
                    "{}：{}（重建连接失败：{}）",
                    FLASH_LINK_LOST_TAG, failure.msg, e
                ));
            }
            continue;
        }

        // 大分区（需分片）：对折单片上限缩小单次 download，配合重连，直到降到下限。
        if *limit <= MIN_ADAPTIVE_DOWNLOAD_LIMIT {
            return Err(format!(
                "{}：{}（单片已降到 {} MiB 仍被设备掐断，请换 USB 口/数据线，重新进入 FastbootD 后重试）",
                FLASH_LINK_LOST_TAG,
                failure.msg,
                *limit / (1024 * 1024)
            ));
        }
        let next = (*limit / 2).max(MIN_ADAPTIVE_DOWNLOAD_LIMIT);
        sink.push(format!(
            "链路被设备掐断（{}）：重建连接并把单片下发降到 {} MiB 后重试 '{}'",
            failure.msg,
            next / (1024 * 1024),
            partition
        ));
        if let Err(e) = reopen_driver(driver, serial).await {
            return Err(format!(
                "{}：{}（重建连接失败：{}）",
                FLASH_LINK_LOST_TAG, failure.msg, e
            ));
        }
        *limit = next;
    }
}

/// 在已打开的 driver 上刷写单个分区（含 --slot all 多目标、vbmeta 标志、sparse/raw 分块）。
/// 供 [`flash_adaptive`] 单次尝试使用，transport/driver 生命周期由调用方掌管。
#[allow(clippy::too_many_arguments)]
async fn flash_on_open_driver(
    d: &mut FastbootDriver<UsbTransport>,
    partition: &str,
    path: &Path,
    file_size: u64,
    disable_verity: bool,
    disable_verification: bool,
    slot_override: Option<&str>,
    limit: u64,
    sink: &LineSink,
    op: &FlashOp,
) -> Result<(), FlashFailure> {
    let targets = resolve_slot_targets(d, partition, slot_override).await;
    let is_sparse = crate::sparse::is_sparse_file(path).unwrap_or(false);
    // 逻辑（super）分区在刷写前必须先按镜像**解压后真实大小**调整分区体积——与官方 fastboot
    // do_flash 一致（先 ResizePartition 再 flash_buf）。强力线刷重建 super 时逻辑分区以 size=1
    // 建出，若不 resize 直接下发，设备会判 "Value too large for defined data type"（EFBIG）。
    // sparse 用展开尺寸（total_blks*blk_sz），raw 用文件大小。
    let raw_size = image_raw_size(path, file_size, is_sparse);

    // 阶段/设备 INFO 行喂给 sink，供 realtime 路径的 FastbootProgressParser 解析。
    let sink_cb = sink.clone();
    d.set_prolog_callback(Box::new(move |msg: &str| {
        sink_cb.push(msg.to_string());
    }));
    let sink_info = sink.clone();
    d.set_info_callback(Box::new(move |msg: &str| {
        sink_info.push(format!("(bootloader) {}", msg));
    }));

    // 实时传输快照：driver 每传一个 USB 块回调一次 delta，宿主 UI 定时器轮询驱动进度/速率。
    op.xfer
        .begin(file_size.saturating_mul(targets.len() as u64));
    let xfer = op.xfer.clone();
    d.set_progress_callback(Box::new(move |delta, _total| xfer.add(delta)));

    // targets 可能是 [part] 或（--slot all）[part_a, part_b]，逐个下发（同一连接内）。
    for part in &targets {
        // 是否需要改写 vbmeta 的 AVB 禁用位：仅顶层 vbmeta 生效（对齐官方 is_vbmeta_partition；
        // vbmeta_system 等链式分区的 flags AVB 不采信，改了也无效，官方同样不动）。
        let want_vbmeta_patch =
            (disable_verity || disable_verification) && protocol::is_vbmeta_partition(part);

        // 逻辑分区：先 resize 到镜像真实大小再刷（对齐官方 do_flash）；物理分区/查询失败直接跳过。
        maybe_resize_logical(d, part, raw_size, sink).await?;

        sink.push(format!("Sending '{}' ({} KB)", part, file_size / 1024));

        let result = if file_size > limit {
            // vbmeta 恒为小文件；若在需要打标志时却走到分块路径，说明镜像异常，直接报错而非静默跳过标志。
            if want_vbmeta_patch {
                Err(FlashFailure::device(
                    "vbmeta 镜像异常过大、无法在设置 disable 标志的同时分块下发".to_string(),
                ))
            } else if is_sparse {
                flash_sparse_chunked(d, part, path, limit, sink, op).await
            } else {
                flash_raw_chunked(d, part, path, limit, sink, op).await
            }
        } else {
            let mut data = std::fs::read(path).map_err(|e| FlashFailure::device(e.to_string()))?;
            if want_vbmeta_patch {
                let flags =
                    apply_vbmeta_disable_flags(&mut data, disable_verity, disable_verification)
                        .map_err(FlashFailure::device)?;
                sink.push(format!(
                    "Setting vbmeta AVB flags = 0x{:08x} (disable-verity={}, disable-verification={})",
                    flags, disable_verity, disable_verification
                ));
            }
            d.download(&data)
                .await
                .map_err(FlashFailure::from_fastboot)?;
            sink.push(format!("Writing '{}'", part));
            // 数据发完到 flash 返回之间设备在落盘，宿主据此显示「设备端处理中」。
            op.xfer.set_device_busy(true);
            let flashed = d.flash(part).await;
            op.xfer.set_device_busy(false);
            flashed.map_err(FlashFailure::from_fastboot)?;
            Ok(())
        };
        result?;
        sink.push(format!("Writing '{}'", part));
    }
    Ok(())
}

/// 镜像刷入后在设备上占用的**真实字节数**：sparse 取展开尺寸（`total_blks*blk_sz`），raw 取文件大小。
/// 逻辑分区 resize 需要的是解压后大小，而非磁盘上的 sparse 文件大小。解析失败时回退文件大小。
fn image_raw_size(path: &Path, file_size: u64, is_sparse: bool) -> u64 {
    if !is_sparse {
        return file_size;
    }
    use crate::sparse::{SparseHeader, SPARSE_HEADER_SIZE};
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return file_size;
    };
    let mut buf = vec![0u8; SPARSE_HEADER_SIZE];
    if f.read_exact(&mut buf).is_err() {
        return file_size;
    }
    match SparseHeader::from_bytes(&buf) {
        Ok(h) => {
            let expanded = h.expanded_size();
            if expanded > 0 {
                expanded
            } else {
                file_size
            }
        }
        Err(_) => file_size,
    }
}

/// 刷写前对逻辑（super）分区按镜像真实大小 `resize-logical-partition`，对齐官方 `is_logical(part)`：
/// 仅当 `getvar is-logical:<part>` == "yes" 才 resize；物理分区或查询失败（老 bootloader 不支持该
/// 变量）按物理分区处理、直接跳过，不影响 boot/vbmeta 等既有可用路径。resize 失败视为设备硬错误上报。
async fn maybe_resize_logical(
    d: &mut FastbootDriver<UsbTransport>,
    part: &str,
    raw_size: u64,
    sink: &LineSink,
) -> Result<(), FlashFailure> {
    let is_logical = d
        .get_var(&format!("is-logical:{}", part))
        .await
        .map(|v| v.trim().eq_ignore_ascii_case("yes"))
        .unwrap_or(false);
    if !is_logical || raw_size == 0 {
        return Ok(());
    }
    sink.push(format!("Resizing '{}' to {} bytes", part, raw_size));
    d.resize_partition(part, raw_size)
        .await
        .map_err(FlashFailure::from_fastboot)?;
    Ok(())
}

async fn flash_sparse_chunked(
    driver: &mut FastbootDriver<UsbTransport>,
    partition: &str,
    path: &Path,
    limit: u64,
    sink: &LineSink,
    op: &FlashOp,
) -> Result<(), FlashFailure> {
    use crate::sparse::StreamingResparse;
    let mut resparse = StreamingResparse::new(path, limit)
        .map_err(|e| FlashFailure::device(format!("解析 sparse 文件失败: {}", e)))?;
    let total_fragments = resparse.total_fragments();

    // 分片预取：构建一片要把最多 max_download 字节读进内存，串行做时下发空转（刷 super 前后停顿数秒）。
    // rendezvous 通道（容量 0）让「构建下一片」与「下发当前片」重叠，内存峰值恒为 2 片、不随分片数增长。
    let (tx, rx) = std::sync::mpsc::sync_channel::<Result<(Vec<u8>, usize), FlashFailure>>(0);
    let producer_cancel = op.cancel.clone();
    let producer = std::thread::spawn(move || loop {
        if producer_cancel.is_cancelled() {
            break;
        }
        match resparse.next_fragment() {
            Ok(Some((data, idx, _is_last))) => {
                if tx.send(Ok((data, idx))).is_err() {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                let _ = tx.send(Err(FlashFailure::device(format!(
                    "生成 sparse fragment 失败: {}",
                    e
                ))));
                break;
            }
        }
    });

    driver.set_timeout(std::time::Duration::from_secs(300));
    let mut outcome = Ok(());
    while let Ok(item) = rx.recv() {
        if op.cancel.is_cancelled() {
            outcome = Err(FlashFailure::device("已取消".to_string()));
            break;
        }
        let (fragment_data, idx) = match item {
            Ok(pair) => pair,
            Err(e) => {
                outcome = Err(e);
                break;
            }
        };
        // 段进度进快照（宿主状态栏显示「第 i/n 段」），阶段行进 sink（排版对齐官方
        // fastboot 的 `Sending sparse 'super' i/n`，既有文本解析可直接复用）。
        op.xfer.set_segment(idx as u64 + 1, total_fragments as u64);
        sink.push(format!(
            "Sending sparse '{}' {}/{} ({} KB)",
            partition,
            idx + 1,
            total_fragments,
            fragment_data.len() / 1024
        ));
        if let Err(e) = driver.download(&fragment_data).await {
            outcome = Err(FlashFailure::from_fastboot(e));
            break;
        }
        // 每段发完设备都要落盘一次，期间链路无字节流动；置位让宿主显示「设备端处理中」
        // 而不是一个停摆的速率。
        op.xfer.set_device_busy(true);
        let flashed = driver.flash(partition).await;
        op.xfer.set_device_busy(false);
        if let Err(e) = flashed {
            outcome = Err(FlashFailure::from_fastboot(e));
            break;
        }
    }
    // 先断开通道再 join：出错提前退出时预取线程正阻塞在 send 上，rx 一 drop 它就会收到
    // 断开错误并结束，不会把这里挂死。
    drop(rx);
    let _ = producer.join();
    driver.set_timeout(std::time::Duration::from_secs(30));
    outcome
}

async fn flash_raw_chunked(
    driver: &mut FastbootDriver<UsbTransport>,
    partition: &str,
    path: &Path,
    limit: u64,
    sink: &LineSink,
    op: &FlashOp,
) -> Result<(), FlashFailure> {
    use crate::sparse::{CHUNK_HEADER_SIZE, SPARSE_HEADER_MAGIC, SPARSE_HEADER_SIZE};
    use memmap2::Mmap;
    use std::fs::File;

    let file = File::open(path).map_err(|e| FlashFailure::device(e.to_string()))?;
    let file_size = file
        .metadata()
        .map_err(|e| FlashFailure::device(e.to_string()))?
        .len();
    let mmap = unsafe { Mmap::map(&file).map_err(|e| FlashFailure::device(e.to_string()))? };

    let block_size = 4096u32;
    let max_overhead = SPARSE_HEADER_SIZE + 3 * CHUNK_HEADER_SIZE;
    let max_data = ((limit - max_overhead as u64) / block_size as u64) * block_size as u64;
    let num_chunks = file_size.div_ceil(max_data) as usize;
    let total_blocks = file_size.div_ceil(block_size as u64) as u32;

    // 与 sparse 路径同理：每块要把最多 max_download 字节从 mmap 拷进 Vec，串行做的话
    // 这段拷贝期间链路空转。rendezvous 通道让拷贝与下发重叠，内存峰值恒为 2 块。
    let (tx, rx) = std::sync::mpsc::sync_channel::<(Vec<u8>, usize)>(0);
    let producer_cancel = op.cancel.clone();
    let producer = std::thread::spawn(move || {
        for i in 0..num_chunks {
            if producer_cancel.is_cancelled() {
                break;
            }
            let offset = i as u64 * max_data;
            let chunk_data_size = std::cmp::min(max_data, file_size - offset);
            let chunk_blocks = chunk_data_size.div_ceil(block_size as u64) as u32;
            let start_block = (offset / block_size as u64) as u32;
            let end_block = start_block + chunk_blocks;
            let trailing = total_blocks.saturating_sub(end_block);
            let aligned = (chunk_blocks as usize) * (block_size as usize);

            let mut num_sparse_chunks = 1u32;
            if start_block > 0 {
                num_sparse_chunks += 1;
            }
            if trailing > 0 {
                num_sparse_chunks += 1;
            }

            let mut buf = Vec::with_capacity(max_overhead + aligned);
            buf.extend_from_slice(&SPARSE_HEADER_MAGIC.to_le_bytes());
            buf.extend_from_slice(&1u16.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(&(SPARSE_HEADER_SIZE as u16).to_le_bytes());
            buf.extend_from_slice(&(CHUNK_HEADER_SIZE as u16).to_le_bytes());
            buf.extend_from_slice(&block_size.to_le_bytes());
            buf.extend_from_slice(&total_blocks.to_le_bytes());
            buf.extend_from_slice(&num_sparse_chunks.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());

            if start_block > 0 {
                buf.extend_from_slice(&0xCAC3u16.to_le_bytes());
                buf.extend_from_slice(&0u16.to_le_bytes());
                buf.extend_from_slice(&start_block.to_le_bytes());
                buf.extend_from_slice(&(CHUNK_HEADER_SIZE as u32).to_le_bytes());
            }

            let raw_total = (CHUNK_HEADER_SIZE + aligned) as u32;
            buf.extend_from_slice(&0xCAC1u16.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(&chunk_blocks.to_le_bytes());
            buf.extend_from_slice(&raw_total.to_le_bytes());
            buf.extend_from_slice(&mmap[offset as usize..(offset + chunk_data_size) as usize]);

            if (chunk_data_size as usize) < aligned {
                buf.extend(std::iter::repeat_n(0u8, aligned - chunk_data_size as usize));
            }

            if trailing > 0 {
                buf.extend_from_slice(&0xCAC3u16.to_le_bytes());
                buf.extend_from_slice(&0u16.to_le_bytes());
                buf.extend_from_slice(&trailing.to_le_bytes());
                buf.extend_from_slice(&(CHUNK_HEADER_SIZE as u32).to_le_bytes());
            }

            if tx.send((buf, i)).is_err() {
                break;
            }
        }
    });

    driver.set_timeout(std::time::Duration::from_secs(300));
    let mut outcome = Ok(());
    while let Ok((buf, idx)) = rx.recv() {
        if op.cancel.is_cancelled() {
            outcome = Err(FlashFailure::device("已取消".to_string()));
            break;
        }
        // raw 分块同样打包成 sparse 容器下发，段进度与阶段行的口径与 sparse 路径一致。
        op.xfer.set_segment(idx as u64 + 1, num_chunks as u64);
        sink.push(format!(
            "Sending sparse '{}' {}/{} ({} KB)",
            partition,
            idx + 1,
            num_chunks,
            buf.len() / 1024
        ));
        if let Err(e) = driver.download(&buf).await {
            outcome = Err(FlashFailure::from_fastboot(e));
            break;
        }
        op.xfer.set_device_busy(true);
        let flashed = driver.flash(partition).await;
        op.xfer.set_device_busy(false);
        if let Err(e) = flashed {
            outcome = Err(FlashFailure::from_fastboot(e));
            break;
        }
    }
    // 先断开通道再 join，理由同 flash_sparse_chunked。
    drop(rx);
    let _ = producer.join();
    driver.set_timeout(std::time::Duration::from_secs(30));
    outcome
}

/// `fastboot erase <part>`。
pub fn fb_erase(serial: Option<&str>, partition: &str) -> Result<String, String> {
    rt().block_on(async {
        let t = open_transport(serial).await.map_err(err_string)?;
        let mut d = FastbootDriver::new(t);
        d.erase(partition).await.map_err(err_string)?;
        Ok(format!("Erasing '{}' OKAY", partition))
    })
}

/// `fastboot reboot [target]`（fastboot 模式设备）。target: ""/bootloader/recovery/fastboot(d)/edl。
pub fn fb_reboot(serial: Option<&str>, target: &str) -> Result<String, String> {
    let start = Instant::now();
    let target_norm = protocol::normalize_reboot_target(target);
    let target_norm = target_norm.as_str();
    rt().block_on(async {
        let t = open_transport(serial)
            .await
            .map_err(|e| reboot_error_text(target_norm, start, err_string(e)))?;
        let mut d = FastbootDriver::new(t);
        // reboot 类命令一发出设备就重启、USB 链路随之断开，常在回 OKAY 前就掉线；
        // 这里依旧容忍掉线，但对外文本必须显式给出 OKAY/ERROR 与耗时，便于上层判断。
        if target_norm.is_empty() {
            match d.reboot().await {
                Ok(_) => Ok(reboot_ok_text(target_norm, start)),
                Err(e) if is_disconnect_err(&e) => Ok(reboot_ok_text(target_norm, start)),
                Err(FastbootError::Device(msg)) => Err(reboot_error_text(
                    target_norm,
                    start,
                    format!("FAILED: {}", msg),
                )),
                Err(e) => Err(reboot_error_text(target_norm, start, err_string(e))),
            }
        } else {
            match d.reboot_to(target_norm).await {
                Ok(_) => Ok(reboot_ok_text(target_norm, start)),
                Err(e) if is_disconnect_err(&e) => Ok(reboot_ok_text(target_norm, start)),
                Err(FastbootError::Device(msg)) => Err(reboot_error_text(
                    target_norm,
                    start,
                    format!("FAILED: {}", msg),
                )),
                Err(e) => Err(reboot_error_text(target_norm, start, err_string(e))),
            }
        }
    })
}

/// `fastboot set_active <slot>`（slot: a/b）。
pub fn fb_set_active(serial: Option<&str>, slot: &str) -> Result<String, String> {
    let slot = match slot.to_lowercase().as_str() {
        "a" | "_a" | "slot_a" => "a",
        "b" | "_b" | "slot_b" => "b",
        _ => return Err(format!("非法槽位: {}", slot)),
    };
    rt().block_on(async {
        let t = open_transport(serial).await.map_err(err_string)?;
        let mut d = FastbootDriver::new(t);
        d.set_active(slot).await.map_err(err_string)?;
        Ok(format!("Setting current slot to '{}' OKAY", slot))
    })
}

/// `fastboot boot <img>`：把 boot.img 下发到内存并立即引导（不写任何分区）。
/// 常用于临时启动 recovery/patched boot 做免刷验证。引导成功后设备离开 fastboot，掉线视为成功。
pub fn fb_boot(serial: Option<&str>, image_path: &str) -> Result<String, String> {
    let start = Instant::now();
    rt().block_on(async {
        let path = Path::new(image_path);
        if !path.exists() {
            return Err(format!("镜像不存在: {}", image_path));
        }
        let data = std::fs::read(path).map_err(|e| e.to_string())?;
        if data.is_empty() {
            return Err("镜像文件为空".to_string());
        }
        let t = open_transport(serial).await.map_err(err_string)?;
        let mut d = FastbootDriver::new(t);
        d.download(&data).await.map_err(err_string)?;
        match d.boot().await {
            Ok(_) => Ok(format!(
                "Booting OKAY [ {:>6.3}s]",
                start.elapsed().as_secs_f64()
            )),
            // boot 成功后设备会立即引导、USB 断开，往往在回 OKAY 前就掉线——与 reboot 类一致，判成功。
            Err(e) if is_disconnect_err(&e) => Ok("Booting OKAY — 设备已开始引导".to_string()),
            Err(FastbootError::Device(msg)) => Err(format!("FAILED: {}", msg)),
            Err(e) => Err(err_string(e)),
        }
    })
}

/// `fastboot continue`：结束 fastboot、继续正常引导。设备随即掉线，掉线视为成功。
pub fn fb_continue(serial: Option<&str>) -> Result<String, String> {
    rt().block_on(async {
        let t = open_transport(serial).await.map_err(err_string)?;
        let mut d = FastbootDriver::new(t);
        match d.continue_boot().await {
            Ok(_) => Ok("Resuming boot OKAY".to_string()),
            Err(e) if is_disconnect_err(&e) => {
                Ok("Resuming boot OKAY — 设备已继续引导".to_string())
            }
            Err(FastbootError::Device(msg)) => Err(format!("FAILED: {}", msg)),
            Err(e) => Err(err_string(e)),
        }
    })
}

/// 把 oem 透传命令的终态响应 + 全部 INFO 行格式化成宿主端可解析的文本。
/// - `OKAY` → `Ok(text)`；OKAY 有 payload 则附在 INFO 行之后。
/// - `FAIL` / 非预期响应 → `Err(text)`，但**已收到的 INFO 一并保留回显**：少见机型会先发若干
///   token INFO 行再回 FAIL，token 就在这些 INFO 里。经 `selfdev::ExecOutput::err_text` 落到
///   stderr，宿主 `RunResult::output()`(=stdout+stderr) 仍能被 `parse_fastboot_auth_blob` 抽出
///   token；同时 `ok=false` 正确反映失败（与 CLI `cmd_oem` 的非零退出语义一致）。
///
/// 逐行 `(bootloader) <trimmed info>` 对齐解析器；**不**合成额外的裸 `token:` 行——设备自带的
/// INFO 已带 `token:`/`blob:` 前缀，再合成会叠加成双份、污染 `parse_fastboot_auth_blob` 的拼接结果。
fn format_oem_result(command: &str, resp: Response, info: &[String]) -> Result<String, String> {
    let mut lines: Vec<String> = info
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| format!("(bootloader) {}", s))
        .collect();
    match resp {
        Response::Okay(msg) => {
            let msg = msg.trim();
            if !msg.is_empty() {
                lines.push(msg.to_string());
            }
            Ok(if lines.is_empty() {
                format!("OKAY ({})", command)
            } else {
                lines.join("\n")
            })
        }
        // FAIL 也把已收 INFO 回显出来（token 可能已在其中），末尾附上失败原因；整体判失败（Err）。
        Response::Fail(msg) => {
            lines.push(format!("FAILED: {}", msg.trim()));
            Err(lines.join("\n"))
        }
        // oem 不应进入 DATA 等阶段；按协议错误处理，但仍保留已收 INFO 以便诊断。
        _ => {
            lines.push("FAILED: oem 返回了非预期响应".to_string());
            Err(lines.join("\n"))
        }
    }
}

/// `fastboot oem <...>` / `fastboot flashing <...>`：透传 oem/flashing 命令，回传设备文本。
/// 走 `oem_command_collect`：拿到终态响应 + **全部** INFO 行，FAIL 收尾时也不丢 INFO——
/// `oem get_token/get_unlock_data` 的数据全在 INFO 里（单条 payload 上限 252B、OKAY 常为空），
/// 与 CLI `cmd_oem` 行为一致。格式化细节见 [`format_oem_result`]。
pub fn fb_oem(serial: Option<&str>, command: &str) -> Result<String, String> {
    let command = command.trim();
    if command.is_empty() {
        return Err("oem 命令为空".to_string());
    }
    let reboot_like = is_reboot_like_cmd(command);
    rt().block_on(async {
        let t = open_transport(serial).await.map_err(err_string)?;
        let mut d = FastbootDriver::new(t);
        match d.oem_command_collect(command).await {
            // 终态响应(OKAY/FAIL) + 全部 INFO 行都拿到，交给格式化统一处理（FAIL 也保留 INFO）。
            Ok((resp, info)) => format_oem_result(command, resp, &info),
            // reboot 类命令（如 oem edl）：设备回 OKAY 前就掉线是预期行为，判成功。
            Err(e) if reboot_like && is_disconnect_err(&e) => {
                Ok(format!("OKAY ({}) — 设备已离开 fastboot", command))
            }
            Err(e) => Err(err_string(e)),
        }
    })
}

#[cfg(test)]
mod oem_format_tests {
    use super::*;

    #[test]
    fn fail_keeps_collected_info_lines_for_parser() {
        // 少见机型：设备先发若干 token INFO 行、随后回 FAIL。已收 INFO 必须保留回显，
        // 让上层 parse_fastboot_auth_blob 仍能抽出 token；整体仍判失败（Err）。
        let info = vec!["token: AABB".to_string(), "token: CCDD".to_string()];
        let text = format_oem_result(
            "get_token",
            Response::Fail("unknown command".to_string()),
            &info,
        )
        .unwrap_err();
        assert_eq!(
            text,
            "(bootloader) token: AABB\n(bootloader) token: CCDD\nFAILED: unknown command"
        );
        // 不得合成额外的裸 `token:` 行：仅设备自带的两条（均带 (bootloader) 前缀）。
        assert_eq!(text.matches("token:").count(), 2);
    }

    #[test]
    fn okay_appends_payload_after_info_lines() {
        let info = vec!["token: AABB".to_string()];
        let text =
            format_oem_result("get_token", Response::Okay("done".to_string()), &info).unwrap();
        assert_eq!(text, "(bootloader) token: AABB\ndone");
    }

    #[test]
    fn okay_without_info_or_payload_falls_back_to_marker() {
        let text = format_oem_result("device-info", Response::Okay(String::new()), &[]).unwrap();
        assert_eq!(text, "OKAY (device-info)");
    }
}

/// `fastboot flashing <lock|unlock|...>`：独立顶层命令，线上直接发 `flashing <op>`（空格分隔），
/// **不是** oem 子命令——不能走 fb_oem（会变成 `oem flashing ...` 被设备判 unknown command）。
pub fn fb_flashing(serial: Option<&str>, operation: &str) -> Result<String, String> {
    let command = format!("flashing {}", operation.trim());
    fb_raw_command_with_timeout(serial, &command, protocol::flashing_timeout(operation))
}

/// 通用原始 fastboot 命令下发（用于 `snapshot-update:<op>`、`gsi:<op>` 等非 oem 顶层命令）。
/// 传入完整命令串（如 `snapshot-update:cancel` / `gsi:wipe`），回传设备文本（含 INFO 行）；设备 FAIL 视为错误。
/// 这些命令都会改设备状态，超时重发会重复执行，故走不重试通道。
pub(crate) fn fb_raw_command(serial: Option<&str>, command: &str) -> Result<String, String> {
    fb_raw_command_with_timeout(serial, command, None)
}

fn fb_raw_command_with_timeout(
    serial: Option<&str>,
    command: &str,
    timeout: Option<std::time::Duration>,
) -> Result<String, String> {
    let command = command.trim();
    if command.is_empty() {
        return Err("命令为空".to_string());
    }
    rt().block_on(async {
        let t = open_transport(serial).await.map_err(err_string)?;
        let mut d = FastbootDriver::new(t);
        if let Some(timeout) = timeout {
            d.set_timeout(timeout);
        }
        let (resp, info) = d
            .command_no_retry_with_info(command)
            .await
            .map_err(err_string)?;
        format_oem_result(command, resp, &info)
    })
}

/// `fastboot snapshot-update <cancel|merge>`。
pub fn fb_snapshot_update(serial: Option<&str>, op: &str) -> Result<String, String> {
    let op = op.trim();
    if op.is_empty() {
        return Err("snapshot-update 需要子操作（cancel/merge）".to_string());
    }
    fb_raw_command(serial, &format!("snapshot-update:{}", op))
}

/// `fastboot gsi <wipe|disable|status|...>`。
pub fn fb_gsi(serial: Option<&str>, op: &str) -> Result<String, String> {
    let op = op.trim();
    if op.is_empty() {
        return Err("gsi 需要子操作（wipe/disable/status）".to_string());
    }
    fb_raw_command(serial, &format!("gsi:{}", op))
}

/// 解析 super 分区名。先问 fastbootd 的 `super-partition-name`（AOSP 唯一口径，retrofit 设备会回
/// `system_a` 这类名字）；设备不支持该变量时回退：非 A/B（has-slot:super != yes）为 `super`，
/// A/B 设备按 slot 覆盖或 current-slot 得 `super_a/_b`。
pub(crate) async fn resolve_super_partition(
    d: &mut FastbootDriver<UsbTransport>,
    slot_override: Option<&str>,
) -> String {
    if let Ok(name) = d.get_var("super-partition-name").await {
        let name = name.trim();
        if !name.is_empty() {
            return name.to_string();
        }
    }
    let has_slot = d
        .get_var("has-slot:super")
        .await
        .map(|v| v.trim().eq_ignore_ascii_case("yes"))
        .unwrap_or(false);
    if !has_slot {
        return "super".to_string();
    }
    let slot = match slot_override
        .map(|s| s.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("a") | Some("_a") => "a".to_string(),
        Some("b") | Some("_b") => "b".to_string(),
        _ => d
            .get_var("current-slot")
            .await
            .map(|s| s.trim().trim_start_matches('_').to_ascii_lowercase())
            .unwrap_or_default(),
    };
    match slot.as_str() {
        "a" => "super_a".to_string(),
        "b" => "super_b".to_string(),
        _ => "super".to_string(),
    }
}

/// `fastboot update-super <metadata_image> [wipe]`：设备侧动态分区更新，与官方 fastbootd 协议一致。
/// 先 download super 元数据镜像（lpmake 的 LpMetadata blob，如 super_empty.img），再下发
/// `update-super:<super>[:wipe]`，由设备合并/重建逻辑分区表（wipe=先清空现存逻辑分区）。
/// 注意传入的是元数据镜像（几百 KB 级），不是完整 super 镜像。
pub fn fb_update_super(
    serial: Option<&str>,
    image_path: &str,
    wipe: bool,
    slot_override: Option<&str>,
) -> Result<String, String> {
    rt().block_on(async {
        let path = Path::new(image_path);
        if !path.exists() {
            return Err(format!("super 元数据镜像不存在: {}", image_path));
        }
        let data = std::fs::read(path).map_err(|e| e.to_string())?;
        if data.is_empty() {
            return Err("super 元数据镜像为空".to_string());
        }
        let t = open_transport(serial).await.map_err(err_string)?;
        let mut d = FastbootDriver::new(t);
        let part = resolve_super_partition(&mut d, slot_override).await;

        // 元数据体积应远小于 max-download-size；超限说明传错了（给成完整 super 镜像）。
        let max_download = d.get_max_download_size().await.unwrap_or(256 * 1024 * 1024);
        if data.len() as u64 > max_download {
            return Err(format!(
                "镜像 {} 过大（{} 字节）：update-super 需要的是 super 元数据（如 super_empty.img），不是完整 super 镜像",
                image_path,
                data.len()
            ));
        }

        d.download(&data).await.map_err(err_string)?;
        let cmd = if wipe {
            format!("update-super:{}:wipe", part)
        } else {
            format!("update-super:{}", part)
        };
        // update-super 会改写动态分区表：超时重发会重复合并/清空，走不重试通道。
        match d.command_no_retry(&cmd).await {
            Ok(Response::Okay(msg)) => Ok(if msg.is_empty() {
                format!("OKAY (update-super {})", part)
            } else {
                msg
            }),
            Ok(Response::Fail(msg)) => Err(format!("FAILED: {}", msg)),
            Ok(_) => Ok(format!("OKAY (update-super {})", part)),
            Err(e) => Err(err_string(e)),
        }
    })
}

/// `fastboot wipe-super <super_empty.img>`：把 super 重置为一组空的默认动态分区（走设备侧
/// `update-super:<super>:wipe`）。需提供元数据镜像路径——脱离 build 环境无法自动定位。
pub fn fb_wipe_super(
    serial: Option<&str>,
    image_path: &str,
    slot_override: Option<&str>,
) -> Result<String, String> {
    if image_path.trim().is_empty() {
        return Err(
            "wipe-super 需要 <super_empty.img> 路径（无法在无 build 环境时自动定位）".to_string(),
        );
    }
    fb_update_super(serial, image_path, true, slot_override)
}

fn raw_ok_or_err(resp: Response, action: &str) -> Result<String, String> {
    match resp {
        Response::Okay(v) => Ok(if v.is_empty() {
            format!("{} OKAY", action)
        } else {
            v
        }),
        Response::Fail(msg) => Err(format!("FAILED: {}", msg)),
        _ => Err(format!("{}: 非预期响应", action)),
    }
}

/// `fastboot create-logical-partition <name> <size>`。
pub fn fb_create_logical_partition(
    serial: Option<&str>,
    name: &str,
    size: u64,
) -> Result<String, String> {
    rt().block_on(async {
        let t = open_transport(serial).await.map_err(err_string)?;
        let mut d = FastbootDriver::new(t);
        let resp = d
            .command_no_retry(&format!(
                "{}:{}:{}",
                protocol::FB_CMD_CREATE_PARTITION,
                name,
                size
            ))
            .await
            .map_err(err_string)?;
        raw_ok_or_err(resp, "create-logical-partition")
    })
}

/// `fastboot delete-logical-partition <name>`。
pub fn fb_delete_logical_partition(serial: Option<&str>, name: &str) -> Result<String, String> {
    rt().block_on(async {
        let t = open_transport(serial).await.map_err(err_string)?;
        let mut d = FastbootDriver::new(t);
        let resp = d
            .command_no_retry(&format!("{}:{}", protocol::FB_CMD_DELETE_PARTITION, name))
            .await
            .map_err(err_string)?;
        raw_ok_or_err(resp, "delete-logical-partition")
    })
}

/// `fastboot resize-logical-partition <name> <size>`。
pub fn fb_resize_logical_partition(
    serial: Option<&str>,
    name: &str,
    size: u64,
) -> Result<String, String> {
    rt().block_on(async {
        let t = open_transport(serial).await.map_err(err_string)?;
        let mut d = FastbootDriver::new(t);
        let resp = d
            .command_no_retry(&format!(
                "{}:{}:{}",
                protocol::FB_CMD_RESIZE_PARTITION,
                name,
                size
            ))
            .await
            .map_err(err_string)?;
        raw_ok_or_err(resp, "resize-logical-partition")
    })
}

/// `fastboot stage <file>`：把文件下载到设备暂存区（不写分区）。
pub fn fb_stage(serial: Option<&str>, input_path: &str) -> Result<String, String> {
    rt().block_on(async {
        let path = Path::new(input_path);
        if !path.exists() {
            return Err(format!("文件不存在: {}", input_path));
        }
        let data = std::fs::read(path).map_err(|e| e.to_string())?;
        if data.is_empty() {
            return Err("文件为空".to_string());
        }
        let t = open_transport(serial).await.map_err(err_string)?;
        let mut d = FastbootDriver::new(t);
        d.download(&data).await.map_err(err_string)?;
        Ok(format!("Staged {} bytes OKAY", data.len()))
    })
}

/// `fastboot update <zip> [-w]`：解析固件 zip 并顺序刷写。
pub fn fb_update(
    serial: Option<&str>,
    zip_path: &str,
    wipe: bool,
    sink: &LineSink,
) -> Result<String, String> {
    let op = FlashOp::new(serial);
    let result = fb_update_impl(serial, zip_path, wipe, sink, &op);
    op.xfer.end();
    result
}

fn fb_update_impl(
    serial: Option<&str>,
    zip_path: &str,
    wipe: bool,
    sink: &LineSink,
    op: &FlashOp,
) -> Result<String, String> {
    rt().block_on(async {
        let path = Path::new(zip_path);
        if !path.exists() {
            return Err(format!("固件包不存在: {}", zip_path));
        }
        let source = crate::flash::ZipImageSource::from_path(path).map_err(|e| e.to_string())?;
        flash_all_from_source(serial, source, wipe, "固件包中没有可刷写的镜像", sink, op).await
    })
}

/// `fastboot flashall`：从目录（散装 img）顺序刷写整套镜像。与 `update <zip>` 共用刷写内核，
/// 仅镜像来源不同（目录 vs zip）。缺省目录为当前目录。
pub fn fb_flashall(
    serial: Option<&str>,
    image_dir: &str,
    wipe: bool,
    sink: &LineSink,
) -> Result<String, String> {
    let op = FlashOp::new(serial);
    let result = rt().block_on(async {
        let dir = Path::new(image_dir);
        if !dir.is_dir() {
            return Err(format!("镜像目录不存在: {}", image_dir));
        }
        let source = crate::flash::LocalImageSource::new(dir);
        flash_all_from_source(serial, source, wipe, "目录中没有可刷写的镜像", sink, &op).await
    });
    op.xfer.end();
    result
}

/// update / flashall 共用刷写内核：解析任务清单 → 逐分区（逻辑分区先 resize 到真实大小）→
/// 可选 `-w` 擦 userdata/metadata。镜像来源由 [`ImageSource`] 抽象（zip 或目录）。
async fn flash_all_from_source<S: ImageSource>(
    serial: Option<&str>,
    source: S,
    wipe: bool,
    empty_err: &str,
    sink: &LineSink,
    op: &FlashOp,
) -> Result<String, String> {
    let plan = crate::flash::FlashingPlan::default();
    let tool = crate::flash::FlashAllTool::new(source, plan);
    tool.validate().map_err(err_string)?;
    let tasks = tool.generate_tasks().map_err(|e| e.to_string())?;
    if tasks.is_empty() {
        return Err(empty_err.to_string());
    }

    let t = open_transport(serial).await.map_err(err_string)?;
    let mut d = FastbootDriver::new(t);
    d.set_timeout(std::time::Duration::from_secs(300));
    let max_download = d.get_max_download_size().await.unwrap_or(512 * 1024 * 1024);
    // 与单分区刷写同一判据：不按设备自报值一次性整发，超过安全上限就分片。
    let limit = effective_download_limit(max_download);

    // 总量未知（逐条读取），先启动快照、逐任务累加 total。
    op.xfer.begin(0);
    let xfer = op.xfer.clone();
    d.set_progress_callback(Box::new(move |delta, _total| xfer.add(delta)));

    for (i, task) in tasks.iter().enumerate() {
        if op.cancel.is_cancelled() {
            d.set_timeout(std::time::Duration::from_secs(30));
            return Err("已取消".to_string());
        }
        sink.push(format!(
            "[{}/{}] Sending '{}' ({})",
            i + 1,
            tasks.len(),
            task.partition,
            task.filename
        ));
        let file_size = tool
            .source()
            .file_size(&task.filename)
            .map_err(|e| e.to_string())?;
        op.xfer.add_total(file_size);

        let is_sparse = tool.is_sparse(&task.filename).unwrap_or(false);
        // 逻辑（super）分区刷前 resize 到镜像真实大小（对齐官方 do_flash）；物理分区/查询失败跳过。
        let raw_size = source_raw_size(tool.source(), &task.filename, file_size, is_sparse);
        if let Err(f) = maybe_resize_logical(&mut d, &task.partition, raw_size, sink).await {
            d.set_timeout(std::time::Duration::from_secs(30));
            return Err(f.msg);
        }

        if file_size > limit {
            // 超限大镜像（super.img 等）：流式物化为临时文件后走既有分片路径，
            // 不再整读内存单次 download（会被设备按 max-download-size 拒绝）。
            let materialized = crate::flash::materialize_image(tool.source(), &task.filename)
                .map_err(|e| e.to_string())?;
            let result = if is_sparse {
                flash_sparse_chunked(
                    &mut d,
                    &task.partition,
                    materialized.path(),
                    limit,
                    sink,
                    op,
                )
                .await
            } else {
                flash_raw_chunked(
                    &mut d,
                    &task.partition,
                    materialized.path(),
                    limit,
                    sink,
                    op,
                )
                .await
            };
            if let Err(f) = result {
                d.set_timeout(std::time::Duration::from_secs(30));
                return Err(f.msg);
            }
        } else {
            let data = tool
                .source()
                .read_file(&task.filename)
                .map_err(|e| e.to_string())?;
            d.download(&data).await.map_err(err_string)?;
            sink.push(format!("Writing '{}'", task.partition));
            op.xfer.set_device_busy(true);
            let flashed = d.flash(&task.partition).await;
            op.xfer.set_device_busy(false);
            flashed.map_err(err_string)?;
        }
        sink.push(format!(
            "[{}/{}] '{}' OKAY",
            i + 1,
            tasks.len(),
            task.partition
        ));
    }

    if wipe {
        sink.push("Erasing 'userdata'".to_string());
        let _ = d.erase("userdata").await;
        sink.push("Erasing 'metadata'".to_string());
        let _ = d.erase("metadata").await;
    }
    d.set_timeout(std::time::Duration::from_secs(30));
    sink.push("Finished. Total time OKAY".to_string());
    Ok("update OKAY".to_string())
}

/// sparse 镜像刷入后在分区上占用的真实字节数（`total_blks*blk_sz`），raw 取文件大小；
/// 逻辑分区 resize 需要的是解压后大小。解析失败回退文件大小。
fn source_raw_size<S: ImageSource>(
    source: &S,
    filename: &str,
    file_size: u64,
    is_sparse: bool,
) -> u64 {
    if !is_sparse {
        return file_size;
    }
    use crate::sparse::{SparseHeader, SPARSE_HEADER_SIZE};
    match source.read_prefix(filename, SPARSE_HEADER_SIZE) {
        Ok(buf) if buf.len() >= SPARSE_HEADER_SIZE => SparseHeader::from_bytes(&buf)
            .ok()
            .map(|h| h.expanded_size())
            .filter(|&x| x > 0)
            .unwrap_or(file_size),
        _ => file_size,
    }
}

/// `fastboot -w`：擦除 userdata + metadata（等价官方 wipe；ext4/f2fs 数据分区下次开机由 init 重建 fs）。
pub fn fb_wipe(serial: Option<&str>) -> Result<String, String> {
    rt().block_on(async {
        let t = open_transport(serial).await.map_err(err_string)?;
        let mut d = FastbootDriver::new(t);
        let mut out = String::new();
        out.push_str("Erasing 'userdata'\n");
        d.erase("userdata").await.map_err(err_string)?;
        // metadata 未必存在，缺失不算失败（对齐官方 best-effort）。
        out.push_str("Erasing 'metadata'\n");
        let _ = d.erase("metadata").await;
        out.push_str("wipe OKAY");
        Ok(out)
    })
}

/// `fastboot fetch <partition>[:offset[:size]] <outfile>`：把设备分区（或片段）回读到本地文件。
/// `spec` 原样拼进 `fetch:` 命令，故同时支持 `partition`、`partition:offset:size` 两种官方写法。
pub fn fb_fetch(serial: Option<&str>, spec: &str, output_path: &str) -> Result<String, String> {
    rt().block_on(async {
        let t = open_transport(serial).await.map_err(err_string)?;
        let mut d = FastbootDriver::new(t);
        let size = d
            .read_partition(spec, Path::new(output_path))
            .await
            .map_err(err_string)?;
        Ok(format!(
            "Fetching '{}': {} bytes -> {} OKAY",
            spec, size, output_path
        ))
    })
}

/// `fastboot format[:fs_type[:size]] <part>`：格式化分区。与 CLI 版 `cmd_format` 同一安全等价策略：
/// 协议层没有设备端格式化，官方是 host 端 mkfs 生成空镜像再 flash；纯 Rust 重写 mkfs（尤其 ext4
/// journal）风险极高，元数据出错会致分区无法挂载甚至变砖。故走无变砖风险的等价路径：查询并展示
/// partition-type/size 后 erase；ext4/f2fs 数据分区下次开机由 vold/init 按 fstab 自动重建。
pub fn fb_format(
    serial: Option<&str>,
    partition: &str,
    fs_type: Option<&str>,
    size: Option<&str>,
) -> Result<String, String> {
    rt().block_on(async {
        let t = open_transport(serial).await.map_err(err_string)?;
        let mut d = FastbootDriver::new(t);

        // 命令行显式 --fs-type 优先于设备上报值；getvar 只读、安全。
        let detected_type = match fs_type {
            Some(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
            _ => d
                .get_var(&format!("partition-type:{}", partition))
                .await
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        };
        let detected_size = match size {
            Some(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
            _ => d
                .get_var(&format!("partition-size:{}", partition))
                .await
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        };

        let mut out = String::new();
        out.push_str(&format!("Formatting '{}'\n", partition));
        match &detected_type {
            Some(ty) => out.push_str(&format!("  文件系统类型: {}\n", ty)),
            None => out.push_str("  文件系统类型: 未知（设备未上报 partition-type）\n"),
        }
        if let Some(sz) = &detected_size {
            out.push_str(&format!("  分区大小: {}\n", sz));
        }

        // 擦除以清空数据（无变砖风险的格式化等价路径）。
        d.erase(partition).await.map_err(err_string)?;
        out.push_str(&format!("Formatting '{}' OKAY（已擦除）", partition));
        if let Some(ty) = &detected_type {
            let tl = ty.to_ascii_lowercase();
            if tl.contains("ext4") || tl.contains("f2fs") {
                out.push_str(&format!("\n  设备下次开机将自动重建 {} 文件系统", ty));
            }
        }
        Ok(out)
    })
}

/// `fastboot get_staged <file>`：把设备暂存区（上一次 stage / oem 命令产出）回传到本地文件。
/// 对应 driver.upload_to_file（流式写盘，不一次性入内存）。
pub fn fb_get_staged(serial: Option<&str>, output_path: &str) -> Result<String, String> {
    rt().block_on(async {
        let t = open_transport(serial).await.map_err(err_string)?;
        let mut d = FastbootDriver::new(t);
        let size = d
            .upload_to_file(Path::new(output_path))
            .await
            .map_err(err_string)?;
        Ok(format!(
            "Getting staged: {} bytes -> {} OKAY",
            size, output_path
        ))
    })
}

// ============================ ADB 侧（连接复用 hub） ============================

mod adb_hub {
    use super::{reboot_error_text, reboot_ok_text, serial_from_path, CONNECT_PROBE_TIMEOUT_MS};
    use crate::adb_winusb_transport::AdbWinUsbDevice;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    /// `release()` 有界等待上限：释放缓存句柄是纯内存操作、本应瞬时；给个很短上限，确保
    /// fastboot 侧刷写前调用 `embed::adb_release()` 时，即便 hub 线程正忙也不会被拖住太久。
    const RELEASE_EXEC_TIMEOUT: Duration = Duration::from_secs(2);

    /// owner 线程持有的连接状态（仅该线程访问，故 `AdbWinUsbDevice` 的 `!Send` 不成问题）。
    struct ConnState {
        device: Option<AdbWinUsbDevice>,
        path: Option<String>,
    }

    type Job = Box<dyn FnOnce(&mut ConnState) + Send>;

    /// owner 线程的投递端；首个真正要用连接的调用才建线程（见 [`release`] 为何不建）。
    static HUB: OnceLock<Sender<Job>> = OnceLock::new();

    fn hub() -> &'static Sender<Job> {
        HUB.get_or_init(|| {
            let (tx, rx) = channel::<Job>();
            let _ = std::thread::Builder::new()
                .name("rmf-adb-hub".to_string())
                .spawn(move || {
                    let mut st = ConnState {
                        device: None,
                        path: None,
                    };
                    while let Ok(job) = rx.recv() {
                        // panic=unwind 下 job panic（如设备回异常报文触发的断言）不能带走 owner
                        // 线程：线程一死，之后所有 exec 永远报「adb hub 不可用」直到重启。捕获
                        // 后丢弃可能已撕裂的连接状态，让后续命令重连自愈；等待方的结果通道随
                        // unwind 一起 drop，会收到「adb hub 无响应」错误。
                        let outcome =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job(&mut st)));
                        if outcome.is_err() {
                            st.device = None;
                            st.path = None;
                            crate::logger::log_line(
                                "[adb-hub] job panic 已捕获：连接缓存已重置，hub 线程继续存活",
                            );
                        }
                    }
                });
            tx
        })
    }

    /// 把闭包投递到 owner 线程执行并无限等待结果。用于 shell/push/pull 等合法长耗时操作——
    /// 时长应由传输层读/写超时约束，此处一刀切超时会误杀大文件传输。
    fn exec<R: Send + 'static>(
        f: impl FnOnce(&mut ConnState) -> R + Send + 'static,
    ) -> Result<R, String> {
        let (tx, rx) = channel::<R>();
        hub()
            .send(Box::new(move |st| {
                let _ = tx.send(f(st));
            }))
            .map_err(|_| "adb hub 不可用".to_string())?;
        rx.recv().map_err(|_| "adb hub 无响应".to_string())
    }

    /// 把闭包投递到 owner 线程并有界等待。超时即返回 Err——job 排到时仍会执行（结果因 rx 已
    /// drop 而丢弃，无害）。用于绝不能被 hub 阻塞的短操作（UI/FFI 同步线程、刷写前句柄释放）。
    fn exec_bounded<R: Send + 'static>(
        timeout: Duration,
        f: impl FnOnce(&mut ConnState) -> R + Send + 'static,
    ) -> Result<R, String> {
        let (tx, rx) = channel::<R>();
        hub()
            .send(Box::new(move |st| {
                let _ = tx.send(f(st));
            }))
            .map_err(|_| "adb hub 不可用".to_string())?;
        match rx.recv_timeout(timeout) {
            Ok(v) => Ok(v),
            Err(RecvTimeoutError::Timeout) => Err("adb hub 繁忙（有界等待超时）".to_string()),
            Err(RecvTimeoutError::Disconnected) => Err("adb hub 无响应".to_string()),
        }
    }

    /// 确保持有一条可用于实操（shell/push/pull…）的连接：优先复用缓存；否则 open + connect_probe
    /// （已授权设备秒回且可直接用），未授权/探测失败再走完整 connect()（会发公钥、必要时等手机授权）。
    fn ensure_for_op<'a>(
        st: &'a mut ConnState,
        serial: &str,
    ) -> Result<&'a mut AdbWinUsbDevice, String> {
        let want = if serial.is_empty() {
            None
        } else {
            Some(serial)
        };

        let reuse = matches!(
            (st.device.as_ref(), st.path.as_ref()),
            (Some(_), Some(p)) if want.is_none() || want == Some(serial_from_path(p).as_str())
        );
        if reuse {
            return Ok(st.device.as_mut().unwrap());
        }

        st.device = None;
        st.path = None;

        // 单一拥有者纪律：CLI 命名管道 daemon（外部终端跑过随包 adb 后的 30s 空闲窗口内）可能
        // 仍持有同一设备的 WinUSB 句柄，直接 open 必撞 CreateFileW 0x80070005。与
        // adb_router/adb_server/adb_mux_server 的直连入口同一前置动作；daemon 不存在时只是
        // 一次微秒级立即失败的管道打开，代价可忽略。
        crate::adb_daemon::ensure_released();

        let list = AdbWinUsbDevice::enumerate().map_err(|e| e.to_string())?;
        if list.is_empty() {
            return Err("未检测到处于 ADB 模式的设备".to_string());
        }
        let path = match want {
            Some(s) => list
                .iter()
                .find(|d| serial_from_path(&d.device_path) == s)
                .map(|d| d.device_path.clone())
                .ok_or_else(|| format!("未找到序列号为 {} 的 ADB 设备", s))?,
            None => {
                if list.len() > 1 {
                    return Err("检测到多台 ADB 设备，请用 -s <序列号> 指定".to_string());
                }
                list[0].device_path.clone()
            }
        };

        let mut dev = AdbWinUsbDevice::open_device(&path).map_err(|e| e.to_string())?;
        match dev.connect_probe(CONNECT_PROBE_TIMEOUT_MS) {
            Ok(true) => {}
            // 未授权 / 探测失败：走完整 connect（发公钥，必要时弹手机授权框并等待）。
            _ => {
                dev.connect()?;
            }
        }
        st.device = Some(dev);
        st.path = Some(path);
        Ok(st.device.as_mut().unwrap())
    }

    /// `devices()` 轮询是否应释放缓存连接的纯判定（与线程/WinUSB 句柄解耦，便于单测）。
    /// 页面切换和空闲都不是 runtime 生命周期边界；仅设备从 USB 枚举消失时清掉 stale 句柄。
    /// fastboot / scrcpy 等确需移交所有权的路径必须显式调用 [`release`]。
    fn cache_should_release(cached_alive: bool) -> bool {
        !cached_alive
    }

    /// `adb devices`：输出 `List of devices attached\n` + 每行 `serial\t<device|unauthorized>`。
    /// GUI 指示灯每 500ms 调一次，只做 USB 枚举，不把 TAB 激活/空闲变成连接的隐式销毁点。
    /// 活连接由进程级 hub 复用；外部命令行通过共享 adb server 借道同一 runtime。
    ///
    /// 枚举 handle-free，直接在调用线程做——**不**排队等 owner 线程：外部经 5037 借道的交互式
    /// shell / 大文件 sync 会把 owner 独占整段会话，若指示灯轮询排在其后就会卡到超时、误报
    /// “无设备”。stale 缓存回收另投递到 owner（见 [`sweep_stale_cache_async`]）。
    pub fn devices() -> String {
        let list = AdbWinUsbDevice::enumerate().unwrap_or_default();
        let present_paths: Vec<String> = list.iter().map(|d| d.device_path.clone()).collect();
        sweep_stale_cache_async(present_paths);

        let serials: Vec<String> = list
            .iter()
            .map(|info| serial_from_path(&info.device_path))
            .collect();
        crate::adb_winusb_transport::forget_absent_authorization(&serials);

        let mut out = String::from("List of devices attached\n");
        for serial in &serials {
            // 授权状态只来自握手结论（等授权中，或最近一次握手未被接受），与 mux server 同口径。
            let state = if crate::adb_winusb_transport::is_unauthorized(serial) {
                "unauthorized"
            } else {
                "device"
            };
            out.push_str(serial);
            out.push('\t');
            out.push_str(state);
            out.push('\n');
        }
        out
    }

    /// 「设备已从 USB 枚举消失即清掉 stale 缓存句柄」投递到 owner 线程执行（缓存状态仅 owner
    /// 可见）。fire-and-forget、不阻塞调用方；**单飞去重**：已有一次在途就不再排队——owner 被
    /// 长会话（交互式 shell / 大文件 sync）钉住时，避免每 500ms 积压一个 job、会话结束后一次性
    /// 回放成百上千次枚举。owner 空闲时立即执行并清标志，语义与原先「每拍回收」一致。
    fn sweep_stale_cache_async(present_paths: Vec<String>) {
        static SWEEP_INFLIGHT: AtomicBool = AtomicBool::new(false);
        if SWEEP_INFLIGHT.swap(true, Ordering::SeqCst) {
            return;
        }
        let sent = hub().send(Box::new(move |st: &mut ConnState| {
            let cached_alive = st
                .path
                .as_ref()
                .is_some_and(|p| present_paths.iter().any(|x| x == p));
            if cache_should_release(cached_alive) {
                st.device = None;
                st.path = None;
            }
            SWEEP_INFLIGHT.store(false, Ordering::SeqCst);
        }));
        if sent.is_err() {
            SWEEP_INFLIGHT.store(false, Ordering::SeqCst);
        }
    }

    /// `adb shell <cmd>`：在复用连接上执行并捕获合并输出。失败会丢弃缓存以便下次重连。
    /// 流式静默窗口按调用方操作超时放宽（`su dd` 大分区备份数分钟无输出不该被默认 60s
    /// 空闲读超时掐断）；取消令牌在调用线程快照后带进 job，排队等待期与执行期的「停止」都生效。
    pub fn shell(serial: &str, cmd: &str) -> Result<String, String> {
        let serial = serial.to_string();
        let cmd = cmd.to_string();
        let idle_ms = crate::adb_winusb_transport::shell_idle_window_ms(super::op_timeout_secs());
        let cancel = super::CancelToken::current();
        exec(move |st| {
            if cancel.is_cancelled() {
                return Err("已取消".to_string());
            }
            match ensure_for_op(st, &serial) {
                Ok(dev) => {
                    dev.set_stream_idle_window_ms(idle_ms);
                    dev.set_op_cancel(Some(cancel.clone()));
                    let r = dev.shell_command(&cmd);
                    dev.set_op_cancel(None);
                    dev.set_stream_idle_window_ms(
                        crate::adb_winusb_transport::DEFAULT_READ_TIMEOUT_MS,
                    );
                    match r {
                        Ok(o) => Ok(o),
                        Err(e) => {
                            st.device = None;
                            st.path = None;
                            Err(e)
                        }
                    }
                }
                Err(e) => Err(e),
            }
        })
        .and_then(|inner| inner)
    }

    /// `adb push <local> <remote>`。取消令牌同 shell：排队与传输中的「停止」都能及时中止。
    pub fn push(serial: &str, local: &str, remote: &str) -> Result<String, String> {
        let serial = serial.to_string();
        let local = local.to_string();
        let remote = remote.to_string();
        let cancel = super::CancelToken::current();
        exec(move |st| {
            if cancel.is_cancelled() {
                return Err("已取消".to_string());
            }
            match ensure_for_op(st, &serial) {
                Ok(dev) => {
                    dev.set_op_cancel(Some(cancel.clone()));
                    let r = dev.push(&local, &remote);
                    dev.set_op_cancel(None);
                    match r {
                        Ok(_) => Ok(format!("{}: 1 file pushed", remote)),
                        Err(e) => {
                            st.device = None;
                            st.path = None;
                            Err(e)
                        }
                    }
                }
                Err(e) => Err(e),
            }
        })
        .and_then(|inner| inner)
    }

    /// `adb pull <remote> <local>`。取消令牌同 shell：排队与传输中的「停止」都能及时中止。
    pub fn pull(serial: &str, remote: &str, local: &str) -> Result<String, String> {
        let serial = serial.to_string();
        let remote = remote.to_string();
        let local = local.to_string();
        let cancel = super::CancelToken::current();
        exec(move |st| {
            if cancel.is_cancelled() {
                return Err("已取消".to_string());
            }
            match ensure_for_op(st, &serial) {
                Ok(dev) => {
                    dev.set_op_cancel(Some(cancel.clone()));
                    let r = dev.pull(&remote, &local);
                    dev.set_op_cancel(None);
                    match r {
                        Ok(_) => Ok(format!("{} -> {}", remote, local)),
                        Err(e) => {
                            st.device = None;
                            st.path = None;
                            Err(e)
                        }
                    }
                }
                Err(e) => Err(e),
            }
        })
        .and_then(|inner| inner)
    }

    /// `adb reboot [target]`：重启后设备离开 ADB 模式，主动丢弃缓存连接。
    pub fn reboot(serial: &str, target: &str) -> Result<String, String> {
        let start = Instant::now();
        let serial = serial.to_string();
        let target = target.to_string();
        exec(move |st| {
            let r = match ensure_for_op(st, &serial) {
                Ok(dev) => dev
                    .reboot(&target)
                    .map(|_| reboot_ok_text(&target, start))
                    .map_err(|e| reboot_error_text(&target, start, e)),
                Err(e) => Err(reboot_error_text(&target, start, e)),
            };
            // 无论成败，设备即将离开 adb 模式，丢弃缓存。
            st.device = None;
            st.path = None;
            r
        })
        .and_then(|inner| inner)
    }

    /// `adb install [-r] <apk>`：复用常驻连接安装（流程见 [`crate::adb_install`]）。
    /// `replace=true` 对应 `-r`（覆盖安装保留数据）。
    pub fn install(serial: &str, apk_local: &str, replace: bool) -> Result<String, String> {
        let serial = serial.to_string();
        let apk = apk_local.to_string();
        exec(move |st| {
            let res = ensure_for_op(st, &serial).and_then(|dev| {
                crate::adb_install::install(dev, &apk, &crate::adb_install::replace_flag(replace))
            });
            if res.is_err() {
                st.device = None;
                st.path = None;
            }
            res
        })
        .and_then(|inner| inner)
    }

    /// `adb install-multiple [-r] <apk...>`：split APK 安装（`replace=true` 即 `-r`），复用同一常驻
    /// 连接，任一步失败即 install-abandon 回滚（流程见 [`crate::adb_install`]）。
    pub fn install_multiple(
        serial: &str,
        apks: &[String],
        replace: bool,
    ) -> Result<String, String> {
        let serial = serial.to_string();
        let apks: Vec<String> = apks.to_vec();
        exec(move |st| {
            let res = ensure_for_op(st, &serial).and_then(|dev| {
                crate::adb_install::install_multiple(
                    dev,
                    &apks,
                    &crate::adb_install::replace_flag(replace),
                )
            });
            if res.is_err() {
                st.device = None;
                st.path = None;
            }
            res
        })
        .and_then(|inner| inner)
    }

    /// `adb uninstall <package>`：`pm uninstall <package>`。
    pub fn uninstall(serial: &str, package: &str) -> Result<String, String> {
        let serial = serial.to_string();
        let package = package.to_string();
        exec(move |st| match ensure_for_op(st, &serial) {
            Ok(dev) => match dev.shell_command(&format!("pm uninstall {}", package)) {
                Ok(out) => {
                    if out.contains("Success") {
                        Ok(out.trim().to_string())
                    } else {
                        Err(format!("卸载失败: {}", out.trim()))
                    }
                }
                Err(e) => {
                    st.device = None;
                    st.path = None;
                    Err(e)
                }
            },
            Err(e) => Err(e),
        })
        .and_then(|inner| inner)
    }

    /// `adb sideload <package>`：按 sideload-host 协议把 OTA 包分块推给 recovery 设备。
    /// sideload 不走普通 adb 认证连接，故单独 open（不复用主连接缓存）；传输期间独占 hub 线程。
    pub fn sideload(serial: &str, package: &str) -> Result<String, String> {
        let serial = serial.to_string();
        let package = package.to_string();
        exec(move |st| {
            // 释放可能缓存的普通 adb 连接，避免与 recovery 设备句柄冲突。
            st.device = None;
            st.path = None;
            let want = if serial.is_empty() {
                None
            } else {
                Some(serial.as_str())
            };
            let list = AdbWinUsbDevice::enumerate().map_err(|e| e.to_string())?;
            if list.is_empty() {
                return Err("未检测到处于 sideload/recovery 模式的设备".to_string());
            }
            let path = match want {
                Some(s) => list
                    .iter()
                    .find(|d| serial_from_path(&d.device_path) == s)
                    .map(|d| d.device_path.clone())
                    .ok_or_else(|| format!("未找到序列号为 {} 的设备", s))?,
                None => {
                    if list.len() > 1 {
                        return Err("检测到多台设备，请用 -s <序列号> 指定".to_string());
                    }
                    list[0].device_path.clone()
                }
            };
            let mut dev = AdbWinUsbDevice::open_device(&path).map_err(|e| e.to_string())?;
            dev.sideload(&package)?;
            Ok(format!("sideload 完成: {}", package))
        })
        .and_then(|inner| inner)
    }

    /// `adb root`：重启 adbd 为 root。重启后缓存连接失效，主动丢弃。
    pub fn root(serial: &str) -> Result<String, String> {
        let serial = serial.to_string();
        exec(move |st| {
            let r = match ensure_for_op(st, &serial) {
                Ok(dev) => dev.root().map(|_| "restarting adbd as root".to_string()),
                Err(e) => Err(e),
            };
            st.device = None;
            st.path = None;
            r
        })
        .and_then(|inner| inner)
    }

    /// `adb unroot`：重启 adbd 为非 root。重启后缓存连接失效，主动丢弃。
    pub fn unroot(serial: &str) -> Result<String, String> {
        let serial = serial.to_string();
        exec(move |st| {
            let r = match ensure_for_op(st, &serial) {
                Ok(dev) => dev
                    .unroot()
                    .map(|_| "restarting adbd without root".to_string()),
                Err(e) => Err(e),
            };
            st.device = None;
            st.path = None;
            r
        })
        .and_then(|inner| inner)
    }

    /// `adb remount [args]`：重挂载 system 等分区为可写（通常需先 root）。走设备 `remount:` 服务。
    pub fn remount(serial: &str, args: &str) -> Result<String, String> {
        let serial = serial.to_string();
        let args = args.trim().to_string();
        exec(move |st| match ensure_for_op(st, &serial) {
            Ok(dev) => {
                let service = if args.is_empty() {
                    "remount:".to_string()
                } else {
                    format!("remount:{}", args)
                };
                match dev.execute_service(&service) {
                    Ok(out) => Ok(String::from_utf8_lossy(&out).trim().to_string()),
                    Err(e) => {
                        st.device = None;
                        st.path = None;
                        Err(e)
                    }
                }
            }
            Err(e) => Err(e),
        })
        .and_then(|inner| inner)
    }

    /// `adb tcpip <port>`：让 adbd 在指定 TCP 端口监听（切无线调试）。切换后 adbd 重启，丢弃缓存。
    pub fn tcpip(serial: &str, port: &str) -> Result<String, String> {
        let serial = serial.to_string();
        let port = port.to_string();
        exec(move |st| {
            let r = match ensure_for_op(st, &serial) {
                Ok(dev) => dev.execute_service(&format!("tcpip:{}", port)).map(|out| {
                    let text = String::from_utf8_lossy(&out).trim().to_string();
                    if text.is_empty() {
                        format!("restarting in TCP mode port: {}", port)
                    } else {
                        text
                    }
                }),
                Err(e) => Err(e),
            };
            st.device = None;
            st.path = None;
            r
        })
        .and_then(|inner| inner)
    }

    /// `adb get-state`：能建立已授权连接即 `device`，否则报错（对齐官方 `unknown` 退出码语义）。
    pub fn get_state(serial: &str) -> Result<String, String> {
        let serial = serial.to_string();
        exec(move |st| match ensure_for_op(st, &serial) {
            Ok(_) => Ok("device".to_string()),
            Err(e) => Err(e),
        })
        .and_then(|inner| inner)
    }

    /// `adb logcat [args]`：进程内一问一答模型无法承载持续流，故用一次性 dump（未限定时自动补 `-d`）。
    /// 需持续跟踪日志请用「打开命令行」窗口的 `adb logcat`（CLI 支持流式）。
    pub fn logcat(serial: &str, args: &str) -> Result<String, String> {
        let mut cmd = String::from("logcat");
        let a = args.trim();
        if !a.is_empty() {
            cmd.push(' ');
            cmd.push_str(a);
        }
        // 保证会退出：未显式限定 -d/-t 时补 -d（一次性 dump）。
        if !cmd.contains("-d") && !cmd.contains("-t") {
            cmd.push_str(" -d");
        }
        shell(serial, &cmd)
    }

    /// 释放缓存的 ADB 连接（kill-server / 关机清理 / fastboot 刷写前让位）。
    /// 有界等待：fastboot 侧 open 前会同步调用它，绝不能因 hub 线程正忙而被拖住太久。
    /// hub 从未建立（CLI 进程、或 GUI 尚未发过 adb 命令）时没有任何句柄可释放，直接成功返回，
    /// 不为一次释放去拉起 owner 线程。
    pub fn release() -> bool {
        if HUB.get().is_none() {
            return true;
        }
        exec_bounded(RELEASE_EXEC_TIMEOUT, |st| {
            st.device = None;
            st.path = None;
        })
        .is_ok()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// 刚用过且设备仍在枚举中 → 保留缓存：活跃期不能被 500ms 轮询强拆连接。
        #[test]
        fn keeps_cache_while_alive_and_fresh() {
            assert!(!cache_should_release(true));
        }

        /// 页面切走或暂时空闲不能成为连接生命周期边界：只要设备仍在，进程级 runtime
        /// 就应继续持有并复用同一连接，避免切回 ADB 页面时再次 open/握手。
        #[test]
        fn keeps_alive_runtime_across_long_page_idle_periods() {
            for _page_idle in [
                Duration::ZERO,
                Duration::from_secs(10),
                Duration::from_secs(24 * 60 * 60),
            ] {
                assert!(!cache_should_release(true));
            }
        }

        /// 设备已从 USB 枚举消失 → 即便刚刚用过也立即释放，不留 stale 句柄。
        #[test]
        fn releases_cache_immediately_when_device_gone() {
            assert!(cache_should_release(false));
        }

        /// job panic（panic=unwind）只能报废那一次调用，绝不能带走 owner 线程：
        /// 修复前线程一死，后续所有 exec 永远「adb hub 不可用」，进程内 ADB 全瘫直到重启。
        #[test]
        fn hub_survives_job_panic() {
            let poisoned: Result<(), String> = exec(|_st| panic!("boom"));
            assert!(poisoned.is_err(), "panic 的 job 应表现为一次失败调用");

            let alive = exec(|_st| 42u32);
            assert_eq!(alive, Ok(42), "panic 之后 hub 线程必须仍能执行后续 job");
        }
    }
}

// ==================== ADB forward/reverse 进程内隧道 ====================
// CLI 版靠子进程常驻转发；进程内改为后台 OS 线程：每条 forward/reverse 在专用线程内 open
// 自己的 AdbWinUsbDevice（同线程创建与使用，规避 !Send），内存 registry 管理增删查，
// 核心复用 transport 的 forward_tcp_stream / reverse_bridge_loop。
mod adb_tunnel {
    use super::serial_from_path;
    use crate::adb_winusb_transport::AdbWinUsbDevice;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex, OnceLock};
    use std::thread::JoinHandle;
    use std::time::Duration;

    #[derive(Clone, Copy, PartialEq)]
    enum Kind {
        Forward,
        Reverse,
    }

    struct Tunnel {
        kind: Kind,
        serial: String,
        local: String,
        remote: String,
        stop: Arc<AtomicBool>,
        handle: Option<JoinHandle<()>>,
    }

    fn registry() -> &'static Mutex<Vec<Tunnel>> {
        static REG: OnceLock<Mutex<Vec<Tunnel>>> = OnceLock::new();
        REG.get_or_init(|| Mutex::new(Vec::new()))
    }

    fn parse_local_tcp_port(local: &str) -> Result<u16, String> {
        let port = local
            .strip_prefix("tcp:")
            .ok_or_else(|| format!("仅支持 tcp:<port> 形式，收到 {}", local))?;
        if port.is_empty() {
            return Err("tcp 端口不能为空".to_string());
        }
        port.parse::<u16>()
            .map_err(|_| format!("非法 tcp 端口: {}", port))
    }

    fn resolve_serial(serial: &str) -> Result<String, String> {
        let list = AdbWinUsbDevice::enumerate().map_err(|e| e.to_string())?;
        if list.is_empty() {
            return Err("未检测到 ADB 设备".to_string());
        }
        if serial.is_empty() {
            if list.len() > 1 {
                return Err("检测到多台 ADB 设备，请用 -s <序列号> 指定".to_string());
            }
            return Ok(serial_from_path(&list[0].device_path));
        }
        list.iter()
            .find(|d| serial_from_path(&d.device_path) == serial)
            .map(|_| serial.to_string())
            .ok_or_else(|| format!("未找到序列号为 {} 的 ADB 设备", serial))
    }

    fn open_by_serial(serial: &str) -> Result<AdbWinUsbDevice, String> {
        // 与 adb_hub::ensure_for_op 同一纪律：任何直连 open 前先让 CLI daemon 交还句柄。
        crate::adb_daemon::ensure_released();
        let list = AdbWinUsbDevice::enumerate().map_err(|e| e.to_string())?;
        let path = list
            .iter()
            .find(|d| serial.is_empty() || serial_from_path(&d.device_path) == serial)
            .map(|d| d.device_path.clone())
            .ok_or_else(|| "未找到目标 ADB 设备".to_string())?;
        AdbWinUsbDevice::open_device(&path).map_err(|e| e.to_string())
    }

    /// `adb forward [--no-rebind] tcp:<local> <remote>`：在 PC 监听本地端口，把每个入站 TCP
    /// 连接桥接到设备侧服务。返回实际本地地址（`tcp:0` 自动选端口时为真实端口）。
    pub fn forward_add(
        serial: &str,
        local: &str,
        remote: &str,
        no_rebind: bool,
    ) -> Result<String, String> {
        let port = parse_local_tcp_port(local)?;
        if remote.trim().is_empty() {
            return Err("REMOTE 不能为空".to_string());
        }
        let selected = resolve_serial(serial)?;

        let exists = registry()
            .lock()
            .map(|r| {
                r.iter()
                    .any(|t| t.kind == Kind::Forward && t.local == local)
            })
            .unwrap_or(false);
        if exists {
            if no_rebind {
                return Err(format!("{} 已被 forward", local));
            }
            let _ = forward_remove(local);
        }

        let listener = TcpListener::bind(("127.0.0.1", port))
            .map_err(|e| format!("绑定 {} 失败: {}", local, e))?;
        let actual_port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let actual_local = format!("tcp:{}", actual_port);
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_t = stop.clone();
        let serial_t = selected.clone();
        let remote_t = remote.to_string();
        let handle = std::thread::Builder::new()
            .name("rmf-adb-forward".to_string())
            .spawn(move || loop {
                if stop_t.load(Ordering::SeqCst) {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        let serial = serial_t.clone();
                        let remote = remote_t.clone();
                        let _ = std::thread::Builder::new()
                            .name("rmf-adb-fwd-conn".to_string())
                            .spawn(move || {
                                if let Ok(mut dev) = open_by_serial(&serial) {
                                    let _ = dev.forward_tcp_stream(&remote, stream);
                                }
                            });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(100)),
                }
            })
            .map_err(|e| format!("启动 forward 线程失败: {}", e))?;

        if let Ok(mut reg) = registry().lock() {
            reg.push(Tunnel {
                kind: Kind::Forward,
                serial: selected,
                local: actual_local.clone(),
                remote: remote.to_string(),
                stop,
                handle: Some(handle),
            });
        }
        Ok(actual_local)
    }

    pub fn forward_list() -> String {
        let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        let mut out = String::new();
        for t in reg.iter().filter(|t| t.kind == Kind::Forward) {
            out.push_str(&format!("{} {} {}\n", t.serial, t.local, t.remote));
        }
        out
    }

    pub fn forward_remove(local: &str) -> Result<(), String> {
        let mut to_join = Vec::new();
        {
            let mut reg = registry()
                .lock()
                .map_err(|_| "registry 锁失败".to_string())?;
            let mut i = 0;
            while i < reg.len() {
                if reg[i].kind == Kind::Forward && reg[i].local == local {
                    reg[i].stop.store(true, Ordering::SeqCst);
                    let mut t = reg.remove(i);
                    if let Some(h) = t.handle.take() {
                        to_join.push(h);
                    }
                } else {
                    i += 1;
                }
            }
        }
        if to_join.is_empty() {
            return Err(format!("{} 未被 forward", local));
        }
        for h in to_join {
            let _ = h.join();
        }
        Ok(())
    }

    pub fn forward_remove_all() {
        let mut to_join = Vec::new();
        {
            let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
            let mut i = 0;
            while i < reg.len() {
                if reg[i].kind == Kind::Forward {
                    reg[i].stop.store(true, Ordering::SeqCst);
                    let mut t = reg.remove(i);
                    if let Some(h) = t.handle.take() {
                        to_join.push(h);
                    }
                } else {
                    i += 1;
                }
            }
        }
        for h in to_join {
            let _ = h.join();
        }
    }

    /// `adb reverse [--no-rebind] <remote> tcp:<local>`：让设备侧监听 remote，把连接反向桥接到
    /// PC 的本地 tcp 服务。常驻循环复用 transport 的 `reverse_bridge_loop`。
    pub fn reverse_add(
        serial: &str,
        remote: &str,
        local: &str,
        no_rebind: bool,
    ) -> Result<String, String> {
        let lport = local
            .strip_prefix("tcp:")
            .ok_or_else(|| format!("reverse 本地服务仅支持 tcp:<port>，收到 {}", local))?;
        if lport.parse::<u16>().map(|p| p == 0).unwrap_or(true) {
            return Err(format!("非法 reverse 本地 tcp 端口: {}", lport));
        }
        if remote.trim().is_empty() {
            return Err("REMOTE 不能为空".to_string());
        }
        let selected = resolve_serial(serial)?;

        let exists = registry()
            .lock()
            .map(|r| {
                r.iter()
                    .any(|t| t.kind == Kind::Reverse && t.remote == remote && t.serial == selected)
            })
            .unwrap_or(false);
        if exists {
            if no_rebind {
                return Err(format!("{} 已被 reverse", remote));
            }
            let _ = reverse_remove(Some(&selected), remote);
        }

        let stop = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = mpsc::channel::<Result<String, String>>();
        let serial_t = selected.clone();
        let remote_t = remote.to_string();
        let local_t = local.to_string();
        let handle = std::thread::Builder::new()
            .name("rmf-adb-reverse".to_string())
            .spawn(move || match open_by_serial(&serial_t) {
                Ok(mut dev) => {
                    let tx = ready_tx.clone();
                    let r = dev.reverse_bridge_loop(&remote_t, &local_t, move |actual| {
                        let _ = tx.send(Ok(actual.to_string()));
                        Ok(())
                    });
                    if let Err(e) = r {
                        let _ = ready_tx.send(Err(e));
                    }
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                }
            })
            .map_err(|e| format!("启动 reverse 线程失败: {}", e))?;

        let actual_remote = match ready_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(Ok(actual)) => actual,
            Ok(Err(e)) => return Err(e),
            Err(_) => remote.to_string(),
        };

        if let Ok(mut reg) = registry().lock() {
            reg.push(Tunnel {
                kind: Kind::Reverse,
                serial: selected,
                local: local.to_string(),
                remote: actual_remote.clone(),
                stop,
                handle: Some(handle),
            });
        }
        Ok(actual_remote)
    }

    pub fn reverse_list() -> String {
        let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        let mut out = String::new();
        for t in reg.iter().filter(|t| t.kind == Kind::Reverse) {
            out.push_str(&format!("{} {} {}\n", t.serial, t.remote, t.local));
        }
        out
    }

    /// reverse 转发循环阻塞在设备读、无法主动中断，故 remove 只「置停止标志 + 从 registry 移除 +
    /// detach 线程」：线程在设备断开或下次 IO 出错时自然退出，不 join 以免挂起。
    pub fn reverse_remove(serial: Option<&str>, remote: &str) -> Result<(), String> {
        let mut reg = registry()
            .lock()
            .map_err(|_| "registry 锁失败".to_string())?;
        let before = reg.len();
        reg.retain_mut(|t| {
            let matched = t.kind == Kind::Reverse
                && t.remote == remote
                && serial.map(|s| s == t.serial).unwrap_or(true);
            if matched {
                t.stop.store(true, Ordering::SeqCst);
                t.handle = None;
            }
            !matched
        });
        if reg.len() == before {
            Err(format!("{} 未被 reverse", remote))
        } else {
            Ok(())
        }
    }

    pub fn reverse_remove_all(serial: Option<&str>) {
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        reg.retain_mut(|t| {
            let matched = t.kind == Kind::Reverse && serial.map(|s| s == t.serial).unwrap_or(true);
            if matched {
                t.stop.store(true, Ordering::SeqCst);
                t.handle = None;
            }
            !matched
        });
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_local_tcp_port_ok() {
            assert_eq!(parse_local_tcp_port("tcp:8080").unwrap(), 8080);
            assert!(parse_local_tcp_port("localabstract:x").is_err());
            assert!(parse_local_tcp_port("tcp:").is_err());
        }
    }
}

// ---- 跨平台包装（非 Windows 仅为编译占位；本工具仅发布 Windows） ----

/// 进程内这条路要不要借道 5037 上的 adb server。判据是「设备句柄归谁」：只要 server 在听，
/// 它就独占 WinUSB 句柄，直连必撞 `CreateFileW` 0x80070005；判不准时按「有」处理。
/// 旧实现只做一次 120ms 探测、探不到就直连，投屏正忙时稳定报拒绝访问。
///
/// 所有 embed adb 入口都经过这里，顺带惰性拉起本进程的全功能 5037 mux server（绑不上 = 有别的
/// server 在位，静默退让）。拉起后设备句柄归 mux hub 独占：外部工具经 5037 借道，本进程自己的 adb
/// 命令在进程内直接进 hub（见 `adb_mux_client::served_in_process`），不经 TCP 回环绕回自己；
/// 一问一答的 shell 结果正确与否取决于 [`crate::adb_mux_client::capture_shell_result`]。
fn adb_mux_active() -> bool {
    // 本进程常驻 5037 一律用**全功能** mux server（单连接多路复用，支持 forward/reverse 隧道与并发），
    // 外部官方 adb / scrcpy 才能像借道官方 server 那样**完整**借道我们（已删除的旧 hub 桥接不支持
    // 隧道，官方 adb 落在它上面只会 `protocol fault ... Broken pipe`，且两者反复抢 5037）。
    //
    // 判据仍是「设备句柄归谁」：
    // - 5037 上已有 server（我们的 mux / 外来官方 adb）→ 直接借道；
    // - 端口空着且**确有 adb 设备**才拉起我们的 mux server（避免无设备/纯 fastboot·EDL 场景空转拉进程）。
    //   拉起前先放开进程内 adb_hub 句柄，让 mux server 能独占设备。
    // ensure_server_running 自带「外来 adb server 在位就借道、端口空才拉起我们的、绝不硬抢」的策略。
    //
    // 本进程 mux 在听时它就是句柄属主，不再每条命令经 TCP 探一次自己（探测要多开一条连接、
    // server 侧多起一个线程，忙时还会落进 120ms+600ms 的超时确认）。
    if crate::adb_mux_server::inproc_server_running()
        || crate::adb_mux_client::device_owned_by_adb_server()
    {
        return true;
    }
    let has_adb_device = crate::adb_winusb_transport::AdbWinUsbDevice::enumerate()
        .map(|list| !list.is_empty())
        .unwrap_or(false);
    if !has_adb_device {
        return false;
    }
    let _ = adb_hub::release();
    crate::adb_mux_server::ensure_inproc_server();
    crate::adb_mux_client::device_owned_by_adb_server()
}

/// hub 直连失败后是否值得改走 5037 借道重试一次：错误确为「句柄被占（拒绝访问）」，且此刻
/// 5037 上确有 server（它多半就是持有者）。`adb_mux_active` 的入口探测存在假阴性窗口
/// （server 忙没答上 120ms 探测），由这一层兜住——直连撞墙本身就是「有人持有句柄」的强证据。
fn should_retry_via_mux(err: &str) -> bool {
    crate::error::usb_text_is_access_denied(err)
        && crate::adb_mux_client::device_owned_by_adb_server()
}

fn adb_mux_unavailable(what: &str) -> String {
    format!(
        "{what}: 5037 上的 adb server 已接管设备，但当前请求失败；已阻止直连回退以避免抢占设备句柄"
    )
}

fn adb_mux_shell(serial: Option<&str>, cmd: &str) -> Result<String, String> {
    crate::adb_mux_client::retry_via_server(|| {
        crate::adb_mux_client::capture_shell_result(serial, cmd)
    })
    .unwrap_or_else(|| Err(adb_mux_unavailable("adb shell")))
}

fn adb_mux_service(serial: Option<&str>, service: &str, what: &str) -> Result<String, String> {
    crate::adb_mux_client::retry_via_server(|| {
        crate::adb_mux_client::capture_service(serial, service)
    })
    .unwrap_or_else(|| Err(adb_mux_unavailable(what)))
    .map(|out| out.trim().to_string())
}

fn adb_mux_push(serial: Option<&str>, local: &str, remote: &str) -> Result<String, String> {
    match crate::adb_mux_client::retry_via_server(|| {
        crate::adb_mux_client::push(serial, Path::new(local), remote)
    }) {
        Some(Ok(())) => Ok(format!("{}: 1 file pushed", remote)),
        Some(Err(e)) => Err(e),
        None => Err(adb_mux_unavailable("adb push")),
    }
}

fn adb_mux_pull(serial: Option<&str>, remote: &str, local: &str) -> Result<String, String> {
    match crate::adb_mux_client::retry_via_server(|| {
        crate::adb_mux_client::pull(serial, remote, Path::new(local))
    }) {
        Some(Ok(())) => Ok(format!("{} -> {}", remote, local)),
        Some(Err(e)) => Err(e),
        None => Err(adb_mux_unavailable("adb pull")),
    }
}

fn adb_mux_install(serial: Option<&str>, apk_local: &str, replace: bool) -> Result<String, String> {
    crate::adb_install::install(
        &mut crate::adb_install::MuxConn::new(serial),
        apk_local,
        &crate::adb_install::replace_flag(replace),
    )
}

fn adb_mux_install_multiple(
    serial: Option<&str>,
    apks: &[String],
    replace: bool,
) -> Result<String, String> {
    crate::adb_install::install_multiple(
        &mut crate::adb_install::MuxConn::new(serial),
        apks,
        &crate::adb_install::replace_flag(replace),
    )
}

fn adb_mux_uninstall(serial: Option<&str>, package: &str) -> Result<String, String> {
    let out = adb_mux_shell(serial, &format!("pm uninstall {}", package))?;
    if out.contains("Success") {
        Ok(out.trim().to_string())
    } else {
        Err(format!("卸载失败: {}", out.trim()))
    }
}

pub fn adb_devices() -> String {
    if adb_mux_active() {
        if let Some(list) =
            crate::adb_mux_client::retry_via_server(|| crate::adb_mux_client::devices(false))
        {
            return format!("List of devices attached\n{}", list);
        }
        crate::logger::log_line(
            "[adb-mux-client] embed devices: server 在线但查询失败，回空列表并阻止直连",
        );
        return "List of devices attached\n".to_string();
    }
    adb_hub::devices()
}
pub fn adb_shell(serial: Option<&str>, cmd: &str) -> Result<String, String> {
    if adb_mux_active() {
        return adb_mux_shell(serial, cmd);
    }
    match adb_hub::shell(serial.unwrap_or(""), cmd) {
        Err(e) if should_retry_via_mux(&e) => adb_mux_shell(serial, cmd),
        other => other,
    }
}
pub fn adb_push(serial: Option<&str>, local: &str, remote: &str) -> Result<String, String> {
    if adb_mux_active() {
        return adb_mux_push(serial, local, remote);
    }
    match adb_hub::push(serial.unwrap_or(""), local, remote) {
        Err(e) if should_retry_via_mux(&e) => adb_mux_push(serial, local, remote),
        other => other,
    }
}
pub fn adb_pull(serial: Option<&str>, remote: &str, local: &str) -> Result<String, String> {
    if adb_mux_active() {
        return adb_mux_pull(serial, remote, local);
    }
    match adb_hub::pull(serial.unwrap_or(""), remote, local) {
        Err(e) if should_retry_via_mux(&e) => adb_mux_pull(serial, remote, local),
        other => other,
    }
}
pub fn adb_reboot(serial: Option<&str>, target: &str) -> Result<String, String> {
    let start = Instant::now();
    // 固定枚举目标大小写不敏感（REBOOT BOOTLOADER / Edl 等）；未知目标原样透传（厂商私有可能大小写敏感）。
    let target_lower = target.trim().to_ascii_lowercase();
    let target: &str = match target_lower.as_str() {
        ""
        | "bootloader"
        | "recovery"
        | "fastboot"
        | "sideload"
        | "sideload-auto-reboot"
        | "edl"
        | "download" => &target_lower,
        _ => target.trim(),
    };
    let via_mux = |serial: Option<&str>| {
        let service = if target.is_empty() {
            "reboot:".to_string()
        } else {
            format!("reboot:{}", target)
        };
        adb_mux_service(serial, &service, "adb reboot")
            .map(|_| reboot_ok_text(target, start))
            .map_err(|e| reboot_error_text(target, start, e))
    };
    if adb_mux_active() {
        return via_mux(serial);
    }
    match adb_hub::reboot(serial.unwrap_or(""), target) {
        Err(e) if should_retry_via_mux(&e) => via_mux(serial),
        Ok(out) => Ok(out),
        Err(e) => Err(if e.contains(" ERROR: ") && e.contains("用时 ") {
            e
        } else {
            reboot_error_text(target, start, e)
        }),
    }
}
pub fn adb_install(serial: Option<&str>, apk_local: &str, replace: bool) -> Result<String, String> {
    if adb_mux_active() {
        return adb_mux_install(serial, apk_local, replace);
    }
    match adb_hub::install(serial.unwrap_or(""), apk_local, replace) {
        Err(e) if should_retry_via_mux(&e) => adb_mux_install(serial, apk_local, replace),
        other => other,
    }
}
pub fn adb_install_multiple(
    serial: Option<&str>,
    apks: &[String],
    replace: bool,
) -> Result<String, String> {
    if adb_mux_active() {
        return adb_mux_install_multiple(serial, apks, replace);
    }
    match adb_hub::install_multiple(serial.unwrap_or(""), apks, replace) {
        Err(e) if should_retry_via_mux(&e) => adb_mux_install_multiple(serial, apks, replace),
        other => other,
    }
}
pub fn adb_uninstall(serial: Option<&str>, package: &str) -> Result<String, String> {
    if adb_mux_active() {
        return adb_mux_uninstall(serial, package);
    }
    match adb_hub::uninstall(serial.unwrap_or(""), package) {
        Err(e) if should_retry_via_mux(&e) => adb_mux_uninstall(serial, package),
        other => other,
    }
}
pub fn adb_release() -> bool {
    // kill-server / 投屏让位 / fastboot 刷写前：交出进程内 adb_hub 缓存的设备句柄，让接管方
    //（scrcpy mux server、官方 adb、fastboot open）畅通。下一次 adb 入口按需重连。
    adb_hub::release()
}
/// 投屏让位（根治版）：确保本进程内 5037 全功能 mux 成为设备属主——有外来 server 则借道、端口空且
/// 有设备则起自研、暂无设备则维持现状。取代旧的「放 adb_hub 句柄给独立 mux 进程重抢」：那条跨进程
/// WinUSB 交接在先开工具时常抢不到句柄、投屏取不到设备。返回设备是否已归某个 5037 server 所有。
pub fn adb_ensure_inproc_mux() -> bool {
    adb_mux_active()
}
/// 本进程是否正持有进程内 5037 mux（即设备属主是我们自己，而非外来 adb / 独立 mux 进程）。
/// 投屏收尾据此决定「绝不 host:kill 自家进程内 mux，只清独立 mux 进程遗留」。
pub fn adb_inproc_mux_running() -> bool {
    crate::adb_mux_server::inproc_server_running()
}
pub fn adb_sideload(serial: Option<&str>, package: &str) -> Result<String, String> {
    // sideload 走 recovery/sideload 设备的专用块协议、必须独占设备句柄，不经 5037 借道。
    // 设备切到 sideload/recovery 模式时，进程内 mux 与它在普通模式下的原连接已随模式切换自然断开、
    // 释放了设备句柄，故此处直连即可；仍先释放进程内 adb_hub 缓存句柄，避免复合设备残留占用。
    let _ = adb_hub::release();
    adb_hub::sideload(serial.unwrap_or(""), package)
}
// forward/reverse 隧道：5037 上有 server（我们的 mux / 外来官方 adb）在位时**必须**经它建立——
// 它独占设备句柄且支持隧道，进程内 adb_tunnel 再直连设备只会撞 0x80070005。仅端口空着（无 server、
// 无设备）时才回退进程内 adb_tunnel（直连自建监听/回连线程）。增删查全部走同一侧，避免注册表分裂。
pub fn adb_forward(
    serial: Option<&str>,
    local: &str,
    remote: &str,
    no_rebind: bool,
) -> Result<String, String> {
    if adb_mux_active() {
        return crate::adb_mux_client::retry_via_server(|| {
            crate::adb_mux_client::forward_add(serial, local, remote, no_rebind)
        })
        .unwrap_or_else(|| Err(adb_mux_unavailable("adb forward")));
    }
    adb_tunnel::forward_add(serial.unwrap_or(""), local, remote, no_rebind)
}
pub fn adb_forward_list() -> String {
    if adb_mux_active() {
        return crate::adb_mux_client::retry_via_server(crate::adb_mux_client::forward_list)
            .unwrap_or_default();
    }
    adb_tunnel::forward_list()
}
pub fn adb_forward_remove(local: &str) -> Result<(), String> {
    if adb_mux_active() {
        return crate::adb_mux_client::retry_via_server(|| {
            crate::adb_mux_client::forward_remove(local)
        })
        .unwrap_or_else(|| Err(adb_mux_unavailable("adb forward --remove")));
    }
    adb_tunnel::forward_remove(local)
}
pub fn adb_forward_remove_all() {
    if adb_mux_active() {
        let _ = crate::adb_mux_client::retry_via_server(|| {
            crate::adb_mux_client::forward_remove_all().then_some(())
        });
        return;
    }
    adb_tunnel::forward_remove_all()
}
pub fn adb_reverse(
    serial: Option<&str>,
    remote: &str,
    local: &str,
    no_rebind: bool,
) -> Result<String, String> {
    if adb_mux_active() {
        return crate::adb_mux_client::retry_via_server(|| {
            crate::adb_mux_client::reverse_add(serial, remote, local, no_rebind)
        })
        .unwrap_or_else(|| Err(adb_mux_unavailable("adb reverse")));
    }
    adb_tunnel::reverse_add(serial.unwrap_or(""), remote, local, no_rebind)
}
pub fn adb_reverse_list() -> String {
    if adb_mux_active() {
        return crate::adb_mux_client::retry_via_server(|| {
            crate::adb_mux_client::reverse_list(None)
        })
        .unwrap_or_default();
    }
    adb_tunnel::reverse_list()
}
pub fn adb_reverse_remove(serial: Option<&str>, remote: &str) -> Result<(), String> {
    if adb_mux_active() {
        return crate::adb_mux_client::retry_via_server(|| {
            crate::adb_mux_client::reverse_remove(serial, remote)
        })
        .unwrap_or_else(|| Err(adb_mux_unavailable("adb reverse --remove")));
    }
    adb_tunnel::reverse_remove(serial, remote)
}
pub fn adb_reverse_remove_all(serial: Option<&str>) {
    if adb_mux_active() {
        let _ = crate::adb_mux_client::retry_via_server(|| {
            crate::adb_mux_client::reverse_remove_all(serial).then_some(())
        });
        return;
    }
    adb_tunnel::reverse_remove_all(serial)
}
pub fn adb_root(serial: Option<&str>) -> Result<String, String> {
    let via_mux = |serial: Option<&str>| {
        let out = adb_mux_service(serial, "root:", "adb root")?;
        Ok(if out.trim().is_empty() {
            "restarting adbd as root".to_string()
        } else {
            out
        })
    };
    if adb_mux_active() {
        return via_mux(serial);
    }
    match adb_hub::root(serial.unwrap_or("")) {
        Err(e) if should_retry_via_mux(&e) => via_mux(serial),
        other => other,
    }
}
pub fn adb_unroot(serial: Option<&str>) -> Result<String, String> {
    let via_mux = |serial: Option<&str>| {
        let out = adb_mux_service(serial, "unroot:", "adb unroot")?;
        Ok(if out.trim().is_empty() {
            "restarting adbd without root".to_string()
        } else {
            out
        })
    };
    if adb_mux_active() {
        return via_mux(serial);
    }
    match adb_hub::unroot(serial.unwrap_or("")) {
        Err(e) if should_retry_via_mux(&e) => via_mux(serial),
        other => other,
    }
}
pub fn adb_remount(serial: Option<&str>, args: &str) -> Result<String, String> {
    let via_mux = |serial: Option<&str>| {
        let args = args.trim();
        let service = if args.is_empty() {
            "remount:".to_string()
        } else {
            format!("remount:{}", args)
        };
        adb_mux_service(serial, &service, "adb remount")
    };
    if adb_mux_active() {
        return via_mux(serial);
    }
    match adb_hub::remount(serial.unwrap_or(""), args) {
        Err(e) if should_retry_via_mux(&e) => via_mux(serial),
        other => other,
    }
}
pub fn adb_tcpip(serial: Option<&str>, port: &str) -> Result<String, String> {
    let via_mux = |serial: Option<&str>| {
        let out = adb_mux_service(serial, &format!("tcpip:{}", port), "adb tcpip")?;
        Ok(if out.trim().is_empty() {
            format!("restarting in TCP mode port: {}", port)
        } else {
            out
        })
    };
    if adb_mux_active() {
        return via_mux(serial);
    }
    match adb_hub::tcpip(serial.unwrap_or(""), port) {
        Err(e) if should_retry_via_mux(&e) => via_mux(serial),
        other => other,
    }
}
pub fn adb_get_state(serial: Option<&str>) -> Result<String, String> {
    let via_mux = |serial: Option<&str>| {
        let state =
            crate::adb_mux_client::retry_via_server(|| crate::adb_mux_client::get_state(serial))
                .ok_or_else(|| adb_mux_unavailable("adb get-state"))?;
        let state = state.trim();
        if state == "device" {
            Ok("device".to_string())
        } else {
            Err("unknown".to_string())
        }
    };
    if adb_mux_active() {
        return via_mux(serial);
    }
    match adb_hub::get_state(serial.unwrap_or("")) {
        Err(e) if should_retry_via_mux(&e) => via_mux(serial),
        other => other,
    }
}
pub fn adb_logcat(serial: Option<&str>, args: &str) -> Result<String, String> {
    let via_mux = |serial: Option<&str>| {
        let mut cmd = String::from("logcat");
        let a = args.trim();
        if !a.is_empty() {
            cmd.push(' ');
            cmd.push_str(a);
        }
        if !cmd.contains("-d") && !cmd.contains("-t") {
            cmd.push_str(" -d");
        }
        adb_mux_shell(serial, &cmd)
    };
    if adb_mux_active() {
        return via_mux(serial);
    }
    match adb_hub::logcat(serial.unwrap_or(""), args) {
        Err(e) if should_retry_via_mux(&e) => via_mux(serial),
        other => other,
    }
}

#[cfg(test)]
mod getvar_reopen_tests {
    use super::*;
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};

    struct ReplayTransport {
        id: &'static str,
        reads: VecDeque<Result<Vec<u8>, TransportError>>,
        events: Arc<Mutex<Vec<String>>>,
        close_error: Option<TransportError>,
    }

    impl ReplayTransport {
        fn new(
            id: &'static str,
            responses: Vec<Vec<u8>>,
            events: &Arc<Mutex<Vec<String>>>,
        ) -> Self {
            Self {
                id,
                reads: responses.into_iter().map(Ok).collect(),
                events: events.clone(),
                close_error: None,
            }
        }
    }

    impl Drop for ReplayTransport {
        fn drop(&mut self) {
            self.events
                .lock()
                .unwrap()
                .push(format!("drop:{}", self.id));
        }
    }

    impl AsyncTransport for ReplayTransport {
        fn read<'a>(
            &'a mut self,
            buf: &'a mut [u8],
        ) -> Pin<Box<dyn Future<Output = Result<usize, TransportError>> + Send + 'a>> {
            Box::pin(async move {
                let data = self.reads.pop_front().expect("unexpected getvar read")?;
                assert!(data.len() <= buf.len());
                buf[..data.len()].copy_from_slice(&data);
                Ok(data.len())
            })
        }

        fn write<'a>(
            &'a mut self,
            data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Result<usize, TransportError>> + Send + 'a>> {
            Box::pin(async move {
                self.events.lock().unwrap().push(format!(
                    "write:{}:{}",
                    self.id,
                    String::from_utf8_lossy(data)
                ));
                Ok(data.len())
            })
        }

        fn close(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>> {
            Box::pin(async move {
                self.events
                    .lock()
                    .unwrap()
                    .push(format!("close:{}", self.id));
                match self.close_error.take() {
                    Some(error) => Err(error),
                    None => Ok(()),
                }
            })
        }

        fn reset(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>> {
            Box::pin(async { panic!("protocol errors must reopen, not reset the old connection") })
        }
    }

    #[tokio::test]
    async fn getvars_share_one_connection_and_keep_unsupported_fields_separate() {
        let events = Arc::default();
        let mut connection = Some(ReplayTransport::new(
            "batch",
            vec![
                b"OKAYmarble".to_vec(),
                b"FAILunknown variable".to_vec(),
                b"OKAYyes".to_vec(),
            ],
            &events,
        ));
        let output = getvars_with_reopen(&["product", "current-slot", "unlocked"], || {
            std::future::ready(Ok(connection.take().expect("batch must open only once")))
        })
        .await
        .unwrap();
        assert_eq!(
            output,
            "product: marble\ngetvar:current-slot FAILED (unknown variable)\nunlocked: yes"
        );
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                "write:batch:getvar:product",
                "write:batch:getvar:current-slot",
                "write:batch:getvar:unlocked",
                "drop:batch",
            ]
        );
    }

    #[tokio::test]
    async fn getvars_discard_partial_snapshot_and_retry_the_whole_batch() {
        let events = Arc::default();
        let mut connections = VecDeque::from([
            ReplayTransport::new(
                "old",
                vec![b"OKAYold-product".to_vec(), vec![0u8; 257]],
                &events,
            ),
            ReplayTransport::new(
                "new",
                vec![b"OKAYnew-product".to_vec(), b"OKAYb".to_vec()],
                &events,
            ),
        ]);
        let output = getvars_with_reopen(&["product", "current-slot"], || {
            std::future::ready(Ok(connections.pop_front().expect("only one reopen")))
        })
        .await
        .unwrap();
        assert_eq!(output, "product: new-product\ncurrent-slot: b");
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                "write:old:getvar:product",
                "write:old:getvar:current-slot",
                "close:old",
                "drop:old",
                "write:new:getvar:product",
                "write:new:getvar:current-slot",
                "drop:new",
            ]
        );
    }

    #[tokio::test]
    async fn getvars_reject_empty_names_without_opening_a_device() {
        for vars in [vec![], vec!["product", " "]] {
            let result = getvars_with_reopen::<ReplayTransport, _, _>(&vars, || {
                std::future::ready(Err(FastbootError::NoDevice))
            })
            .await;
            assert_eq!(result.unwrap_err(), "getvar 需要变量名");
        }
    }

    #[tokio::test]
    async fn getvar_protocol_error_reopens_only_after_closing_old_connection() {
        let events = Arc::default();
        let mut connections = VecDeque::from([
            ReplayTransport::new("old", vec![vec![0u8; 257]], &events),
            ReplayTransport::new(
                "new",
                vec![b"INFOunlocked: yes".to_vec(), b"OKAY".to_vec()],
                &events,
            ),
        ]);
        let result = getvar_with_reopen("all", || {
            let connection = connections.pop_front().expect("unexpected extra reopen");
            events
                .lock()
                .unwrap()
                .push(format!("open:{}", connection.id));
            std::future::ready(Ok(connection))
        })
        .await
        .unwrap();
        assert_eq!(result, "unlocked: yes");
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                "open:old",
                "write:old:getvar:all",
                "close:old",
                "drop:old",
                "open:new",
                "write:new:getvar:all",
                "drop:new",
            ]
        );
    }

    #[tokio::test]
    async fn getvar_protocol_error_retries_only_once_and_keeps_both_errors() {
        let events = Arc::default();
        let mut connections = VecDeque::from([
            ReplayTransport::new("old", vec![b"BAD1first response".to_vec()], &events),
            ReplayTransport::new("new", vec![b"BAD2second response".to_vec()], &events),
        ]);
        let error = getvar_with_reopen("product", || {
            std::future::ready(Ok(connections
                .pop_front()
                .expect("must not open a third connection")))
        })
        .await
        .unwrap_err();
        assert!(error.contains("BAD1"), "{error}");
        assert!(error.contains("BAD2"), "{error}");
        assert!(connections.is_empty());
        assert_eq!(
            events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| event.starts_with("write:"))
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn getvar_device_fail_does_not_reopen() {
        let events = Arc::default();
        let mut connection = Some(ReplayTransport::new(
            "only",
            vec![b"FAILunknown variable".to_vec()],
            &events,
        ));
        let error = getvar_with_reopen("product", || {
            std::future::ready(Ok(connection.take().expect("device FAIL must not reopen")))
        })
        .await
        .unwrap_err();
        assert_eq!(error, "设备失败：unknown variable");
        assert!(!events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.starts_with("close:")));
    }

    #[tokio::test]
    async fn getvar_reopen_failure_keeps_first_protocol_diagnostic() {
        let events = Arc::default();
        let mut attempts = VecDeque::from([
            Ok(ReplayTransport::new(
                "old",
                vec![b"BAD1first response".to_vec()],
                &events,
            )),
            Err(FastbootError::NoDevice),
        ]);
        let error = getvar_with_reopen("product", || {
            std::future::ready(
                attempts
                    .pop_front()
                    .expect("must not retry a failed reopen"),
            )
        })
        .await
        .unwrap_err();
        assert!(error.contains("BAD1"), "{error}");
        assert!(error.contains("无设备"), "{error}");
        assert_eq!(events.lock().unwrap().last().unwrap(), "drop:old");
    }

    #[tokio::test]
    async fn getvar_token_output_is_unchanged_after_reopen() {
        let events = Arc::default();
        let mut connections = VecDeque::from([
            ReplayTransport::new("old", vec![b"BAD1first response".to_vec()], &events),
            ReplayTransport::new(
                "new",
                vec![
                    b"INFOtoken: AABB".to_vec(),
                    b"INFOtoken: CCDD".to_vec(),
                    b"OKAY".to_vec(),
                ],
                &events,
            ),
        ]);
        let result = getvar_with_reopen("token", || {
            std::future::ready(Ok(connections.pop_front().unwrap()))
        })
        .await
        .unwrap();
        assert_eq!(result, "token: AABB\ntoken: CCDD");
    }

    #[tokio::test]
    async fn getvar_token_device_fail_keeps_output_and_does_not_reopen() {
        let events = Arc::default();
        let mut connection = Some(ReplayTransport::new(
            "only",
            vec![b"FAILunsupported token".to_vec()],
            &events,
        ));
        let error = getvar_with_reopen("token", || {
            std::future::ready(Ok(connection.take().expect("token FAIL must not reopen")))
        })
        .await
        .unwrap_err();
        assert_eq!(error, "FAILED: unsupported token");
    }

    #[tokio::test]
    async fn getvar_token_info_then_data_reopens_and_discards_partial_reply() {
        let events = Arc::default();
        let mut connections = VecDeque::from([
            ReplayTransport::new(
                "old",
                vec![b"INFOtoken: OLD".to_vec(), b"DATA00000004".to_vec()],
                &events,
            ),
            ReplayTransport::new(
                "new",
                vec![b"INFOtoken: NEW".to_vec(), b"OKAY".to_vec()],
                &events,
            ),
        ]);
        let result = getvar_with_reopen("token", || {
            std::future::ready(Ok(connections.pop_front().expect("must only reopen once")))
        })
        .await
        .unwrap();
        assert_eq!(result, "token: NEW");
        assert!(connections.is_empty());
    }

    #[tokio::test]
    async fn getvar_token_repeated_info_then_data_fails() {
        let events = Arc::default();
        let mut connections = VecDeque::from([
            ReplayTransport::new(
                "old",
                vec![b"INFOtoken: OLD".to_vec(), b"DATA00000004".to_vec()],
                &events,
            ),
            ReplayTransport::new(
                "new",
                vec![b"INFOtoken: NEW".to_vec(), b"DATA00000008".to_vec()],
                &events,
            ),
        ]);
        let error = getvar_with_reopen("token", || {
            std::future::ready(Ok(connections.pop_front().expect("must only reopen once")))
        })
        .await
        .unwrap_err();
        assert!(error.contains("Data(4)"), "{error}");
        assert!(error.contains("Data(8)"), "{error}");
        assert!(connections.is_empty());
    }

    #[tokio::test]
    async fn getvar_close_error_still_drops_old_transport_before_reopen() {
        let events = Arc::default();
        let mut old = ReplayTransport::new("old", vec![b"BAD1first response".to_vec()], &events);
        old.close_error = Some(TransportError::Usb("close failed".to_string()));
        let mut connections = VecDeque::from([
            old,
            ReplayTransport::new("new", vec![b"BAD2second response".to_vec()], &events),
        ]);
        let error = getvar_with_reopen("product", || {
            let connection = connections.pop_front().expect("must only reopen once");
            events
                .lock()
                .unwrap()
                .push(format!("open:{}", connection.id));
            std::future::ready(Ok(connection))
        })
        .await
        .unwrap_err();
        assert!(error.contains("close failed"), "{error}");
        let events = events.lock().unwrap();
        let old_dropped = events.iter().position(|event| event == "drop:old").unwrap();
        let new_opened = events.iter().position(|event| event == "open:new").unwrap();
        assert!(old_dropped < new_opened, "{events:?}");
    }
}

#[cfg(test)]
mod xfer_stage_tests {
    use super::*;

    /// 分段/设备端处理状态随 begin → segment → busy → end 的生命周期正确翻转。
    /// 通道按序列号隔离，用本测试独占的序列号即可与其它用例并发跑。
    #[test]
    fn stage_snapshot_follows_transfer_lifecycle() {
        let serial = Some("xfer-stage-test");
        let xfer = Xfer::channel(serial);
        let stage = || {
            let snap = xfer_snapshot(serial);
            (snap.seg_index, snap.seg_total, snap.device_busy)
        };
        xfer.begin(1024);
        assert_eq!(stage(), (0, 0, false), "begin 必须清掉上一轮残值");

        xfer.set_segment(3, 9);
        xfer.set_device_busy(true);
        assert_eq!(stage(), (3, 9, true));

        xfer.set_device_busy(false);
        assert_eq!(stage(), (3, 9, false));

        xfer.end();
        assert!(!stage().2, "end 后不能残留「设备端处理中」");
        assert!(!xfer_snapshot(serial).active);

        // 下一轮 begin 清段号：未分段的刷写不会顶着上一轮的段号显示
        xfer.begin(0);
        assert_eq!(stage(), (0, 0, false));
        xfer.end();
    }

    /// 批量刷机的根本前提：两台设备同时传输，各自的计数互不清零、互不累加。
    #[test]
    fn concurrent_devices_keep_separate_transfer_counters() {
        let a = Xfer::channel(Some("xfer-dev-a"));
        let b = Xfer::channel(Some("xfer-dev-b"));
        a.begin(1000);
        a.add(300);
        b.begin(5000);
        b.add(40);
        a.add(200);

        let snap_a = xfer_snapshot(Some("xfer-dev-a"));
        let snap_b = xfer_snapshot(Some("xfer-dev-b"));
        assert_eq!(
            (snap_a.active, snap_a.sent, snap_a.total),
            (true, 500, 1000)
        );
        assert_eq!((snap_b.active, snap_b.sent, snap_b.total), (true, 40, 5000));

        b.end();
        assert!(
            xfer_snapshot(Some("xfer-dev-a")).active,
            "另一台结束不能把这台标成非活动"
        );
        a.end();

        assert_eq!(
            xfer_snapshot(Some("xfer-never-used")),
            XferSnapshot::default(),
            "没传输过的设备读到的是全零的非活动快照"
        );
    }
}

#[cfg(test)]
mod link_lost_tests {
    use super::*;

    /// 链路失效标记是跨层契约（编排层据此立即中止后续分区），不能被改文案或改成空串。
    #[test]
    fn link_lost_tag_is_stable() {
        assert_eq!(FLASH_LINK_LOST_TAG, "设备链路中断");
        assert!(!FLASH_LINK_LOST_TAG.is_empty());
    }
}

#[cfg(test)]
mod vbmeta_tests {
    use super::*;

    /// 构造一个最小合法 vbmeta 头（仅魔数 + flags 字段够用），flags 初始为 0。
    fn fake_vbmeta() -> Vec<u8> {
        let mut v = vec![0u8; AVB_VBMETA_FLAGS_OFFSET + 4];
        v[0..4].copy_from_slice(AVB_MAGIC);
        v
    }

    #[test]
    fn sets_verity_bit() {
        let mut d = fake_vbmeta();
        let flags = apply_vbmeta_disable_flags(&mut d, true, false).unwrap();
        assert_eq!(flags, AVB_FLAG_HASHTREE_DISABLED);
        let off = AVB_VBMETA_FLAGS_OFFSET;
        assert_eq!(&d[off..off + 4], &1u32.to_be_bytes());
    }

    #[test]
    fn sets_both_bits() {
        let mut d = fake_vbmeta();
        let flags = apply_vbmeta_disable_flags(&mut d, true, true).unwrap();
        assert_eq!(
            flags,
            AVB_FLAG_HASHTREE_DISABLED | AVB_FLAG_VERIFICATION_DISABLED
        );
    }

    #[test]
    fn preserves_existing_flags() {
        let mut d = fake_vbmeta();
        let off = AVB_VBMETA_FLAGS_OFFSET;
        // 预置 verification 位，再只加 verity，应两位都在。
        d[off..off + 4].copy_from_slice(&AVB_FLAG_VERIFICATION_DISABLED.to_be_bytes());
        let flags = apply_vbmeta_disable_flags(&mut d, true, false).unwrap();
        assert_eq!(
            flags,
            AVB_FLAG_HASHTREE_DISABLED | AVB_FLAG_VERIFICATION_DISABLED
        );
    }

    #[test]
    fn rejects_non_vbmeta() {
        let mut d = vec![0u8; AVB_VBMETA_FLAGS_OFFSET + 4];
        d[0..4].copy_from_slice(b"NOPE");
        assert!(apply_vbmeta_disable_flags(&mut d, true, false).is_err());
    }

    #[test]
    fn rejects_too_short() {
        let mut d = AVB_MAGIC.to_vec();
        assert!(apply_vbmeta_disable_flags(&mut d, true, false).is_err());
    }

    #[test]
    fn token_var_uses_info_lines() {
        // token / unlock_data 类变量应走 INFO 行收集路径；普通变量不受影响。
        assert!(var_returns_info_lines("token"));
        assert!(var_returns_info_lines("unlock_data"));
        assert!(var_returns_info_lines("get_unlock_ability"));
        assert!(var_returns_info_lines("UnLock"));
        assert!(!var_returns_info_lines("product"));
        assert!(!var_returns_info_lines("current-slot"));
        assert!(!var_returns_info_lines("max-download-size"));
    }

    #[test]
    fn info_var_reply_keeps_prefixed_info_lines_verbatim() {
        // 设备把 token 分多条 INFO 行发、每行自带 `token:` 前缀，OKAY 为空：必须原样逐行保留，
        // 由 (bootloader) 前缀 + parse_fastboot_auth_blob 去前缀再拼接，而不是拼成一坨把
        // `token:` 前缀并进值里（那会读出 `token: token: AABB…`，与官方 fastboot 不一致）。
        let info = vec!["token: AABB".to_string(), "token: CCDD".to_string()];
        assert_eq!(
            info_var_reply_lines("token", &info, ""),
            vec!["token: AABB".to_string(), "token: CCDD".to_string()]
        );
    }

    #[test]
    fn info_var_reply_appends_okay_as_var_line() {
        // token 直接落在 OKAY payload（无 INFO 行）：补一行 `var: value`，解析器才认得。
        assert_eq!(
            info_var_reply_lines("token", &[], "DEADBEEF"),
            vec!["token: DEADBEEF".to_string()]
        );
    }

    #[test]
    fn info_var_reply_empty_when_no_info_and_no_okay() {
        // INFO 与 OKAY 都空：返回空序列，调用方据此报「设备未返回数据」。
        assert!(info_var_reply_lines("token", &[], "   ").is_empty());
    }
}

#[cfg(test)]
mod cancel_epoch_tests {
    use super::*;

    /// 两个用例都要断言全局取消纪元，cargo test 默认并发跑会互相干扰，串行执行。
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// 纪元式取消不会被并发开始的新操作吞掉：批量刷机里别的设备、后台 `devices` 轮询随时在开
    /// 新分派，它们只是取自己的快照，绝不能清掉用户对进行中长传输按下的「停止」。
    #[test]
    fn cancel_epoch_survives_concurrently_started_operations() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let op_start = CancelToken::current();
        assert!(!op_start.is_cancelled(), "尚未请求取消");

        request_cancel();
        assert!(op_start.is_cancelled(), "停止后应立即命中");

        // 停止之后才开始的新操作：以新纪元为起点，不被旧的取消误伤，也不影响旧操作的判定。
        let next_op = CancelToken::current();
        assert!(!next_op.is_cancelled());
        assert!(
            op_start.is_cancelled(),
            "并发开始的新操作不得吞掉已发出的取消"
        );
    }

    /// 回归：后台 `adb devices` 轮询（5s 超时）排在长 `adb pull` 后面撞自己的超时时，只能取消
    /// 它自己那一枚。曾因超时直接撞全局纪元，导致大分区回读整批报「已取消」。
    #[test]
    fn op_timeout_cancels_only_its_own_operation() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

        // 长传输在自己的分派线程上取快照
        let transfer = OpCancel::new();
        set_op_cancel(Some(transfer.clone()));
        let transfer_token = CancelToken::current();

        // 后台轮询另起一枚私有句柄
        let poll = OpCancel::new();
        set_op_cancel(Some(poll.clone()));
        let poll_token = CancelToken::current();
        set_op_cancel(None);

        // 轮询超时：分派层只取消它自己这一枚
        poll.cancel();
        assert!(poll_token.is_cancelled(), "超时的那次操作应当被取消");
        assert!(
            !transfer_token.is_cancelled(),
            "无关的在途传输不得被别人的超时连累"
        );

        // 用户「停止」仍走全局纪元：所有在途操作一起停
        request_cancel();
        assert!(
            transfer_token.is_cancelled(),
            "用户停止应当作用于全部在途操作"
        );
    }
}

/// 真机回归（默认不跑）：插一台已授权的 ADB 设备、关掉其它 adb / 投屏软件后手动执行
/// `cargo test -p fastboot --lib device_latency -- --ignored --nocapture`。
/// 只读：devices / get-state / getprop / pull /system/etc/hosts，不写设备。
/// 守的是「本进程承载 5037 时自家命令直连 mux hub」：热 shell 应在几十毫秒内返回，
/// 不得再出现借道回环扑空后固定约 3.7s 才失败的形态；外部工具经 5037 借道也必须照常可用。
#[cfg(test)]
mod device_latency_tests {
    use super::*;

    fn timed<T>(f: impl FnOnce() -> T) -> (T, u128) {
        let start = Instant::now();
        let out = f();
        (out, start.elapsed().as_millis())
    }

    #[test]
    #[ignore]
    fn device_latency() {
        let (list, ms) = timed(adb_devices);
        println!("adb devices: {ms} ms\n{list}");
        assert!(
            crate::adb_mux_server::inproc_server_running(),
            "有设备且 5037 空闲时应拉起进程内 mux server（检查是否有别的 adb / 投屏软件占着 5037）"
        );

        let mut warm = Vec::new();
        let mut device = String::new();
        for i in 0..10 {
            let (out, ms) = timed(|| adb_shell(None, "getprop ro.product.device"));
            println!("shell #{i}: {ms} ms -> {:?}", out.as_deref().map(str::trim));
            let out = out.expect("shell 失败");
            assert!(!out.trim().is_empty());
            if i > 0 {
                warm.push(ms);
            }
            device = out.trim().to_string();
        }
        warm.sort_unstable();
        println!(
            "warm shell: min {} / median {} / max {} ms",
            warm[0],
            warm[warm.len() / 2],
            warm[warm.len() - 1]
        );
        assert!(
            warm[warm.len() - 1] < 2000,
            "热 shell 不应再出现秒级耗时：{warm:?}"
        );

        // 首次枚举时 hub 还在后台握手，状态是 offline；shell 建好 hub 之后才是 device。
        let (state, ms) = timed(|| adb_get_state(None));
        println!("get-state: {ms} ms -> {state:?}");
        assert_eq!(state.as_deref(), Ok("device"));

        let (props, ms) = timed(|| adb_shell(None, "getprop"));
        let props = props.expect("批量 getprop 失败");
        println!("batch getprop: {ms} ms, {} lines", props.lines().count());

        // 新版系统的 SELinux 不让 shell 读 build.prop；hosts 是所有进程解析域名都要读的，必然可读。
        let local = std::env::temp_dir().join(format!("rmf-latency-{}.hosts", std::process::id()));
        let (pulled, ms) = timed(|| adb_pull(None, "/system/etc/hosts", &local.to_string_lossy()));
        let size = std::fs::metadata(&local).map(|m| m.len()).unwrap_or(0);
        let _ = std::fs::remove_file(&local);
        println!("pull /system/etc/hosts: {ms} ms, {size} bytes -> {pulled:?}");
        pulled.expect("pull 失败");
        assert!(size > 0);

        // 外部工具（scrcpy / 官方 adb）的借道路径：同一个 hub 上经 5037 host 协议开流。
        let (borrowed, ms) = timed(|| -> Result<String, String> {
            use std::io::Read;
            let mut s =
                std::net::TcpStream::connect(("127.0.0.1", 5037)).map_err(|e| e.to_string())?;
            for req in ["host:transport-any", "shell:getprop ro.product.device"] {
                crate::adb_host_proto::write_len_prefixed(&mut s, req)
                    .map_err(|e| e.to_string())?;
                let mut status = [0u8; 4];
                s.read_exact(&mut status).map_err(|e| e.to_string())?;
                if &status != b"OKAY" {
                    let detail = crate::adb_host_proto::read_message(&mut s).unwrap_or_default();
                    return Err(format!("{req}: {detail}"));
                }
            }
            let mut out = String::new();
            s.read_to_string(&mut out).map_err(|e| e.to_string())?;
            Ok(out)
        });
        println!(
            "shell via 5037: {ms} ms -> {:?}",
            borrowed.as_deref().map(str::trim)
        );
        assert_eq!(borrowed.as_deref().map(str::trim), Ok(device.as_str()));
    }
}
