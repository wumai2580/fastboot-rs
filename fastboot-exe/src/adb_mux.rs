//! ADB 单连接多路复用（Mux）：让 5037 server 在一条 USB 连接上以 local_id 并发承载多个 stream
//! （如 scrcpy 的 shell + reverse 隧道同时存活），对齐官方 adb 模型，
//! 取代旧「每 client 一条设备连接 + 全局 USB_LOCK 串行」。

/// 从 `tcp:<port>` 取端口号。
pub fn tcp_port(ep: &str) -> Option<u16> {
    ep.strip_prefix("tcp:").and_then(|p| p.parse::<u16>().ok())
}

/// `open_stream` 超时错误里嵌的稳定标记：设备对 A_OPEN 既不回 A_OKAY 也不回 A_CLSE（装死），
/// 区别于「被 A_CLSE 明确拒绝」或「写失败」。server 侧据此决定是否拆 hub 重建（半死连接自愈）。
pub const OPEN_TIMEOUT_MARKER: &str = "[open-timeout]";

/// 判定 `open_stream` 的错误是否属于「设备对 A_OPEN 装死」的超时（见 [`OPEN_TIMEOUT_MARKER`]）。
pub fn is_open_timeout_err(err: &str) -> bool {
    err.contains(OPEN_TIMEOUT_MARKER)
}

/// `open_stream` 被设备以 A_CLSE 明确拒绝时错误文案的开头：设备活着、只是不认这个服务名
/// （如 Android 7 以前的 adbd 不认 `shell,v2,...`），区别于选不到设备 / 建 hub 失败。
const OPEN_REJECTED_PREFIX: &str = "device rejected service";

pub fn is_open_rejected_err(err: &str) -> bool {
    err.starts_with(OPEN_REJECTED_PREFIX)
}

// ============================ Mux 引擎 ============================
// 持 device 的线程跑 read loop，按 local_id(arg1) 把设备帧分发到各 stream；写侧共用 AdbRawWriter
// + 全局写锁。流控沿用 forward_tcp_stream 模型（can_send + Condvar：发 A_WRTE 置 false，收 A_OKAY 置 true）。

use crate::adb_protocol::{A_CLSE, A_OKAY, A_OPEN, A_WRTE};
use crate::adb_winusb_transport::{AdbRawWriter, AdbWinUsbDevice};
use crate::error::TransportError;
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// 读循环的轮询超时（毫秒）。承载空闲隧道（scrcpy 长时间无数据）绝不能误判掉线，所以把 bulk-in
/// 设成有限超时轮询而非无限阻塞：窗口内无包即 `TransportError::Timeout`，当「空闲，继续循环」处理；
/// 每轮顺带查 stop 标志，使外部能把一条半死 hub（握手过但对 A_OPEN 装死、永远读不到数据）拆掉——
/// 置 stop 后至多一个轮询周期内读循环就会退出、让属主线程释放 WinUSB 句柄并清槽。
const READ_POLL_TIMEOUT_MS: u32 = 1000;

/// 单条 stream 收件箱的积压包数上限。达到上限即扣住对设备的 A_OKAY 续窗（ADB 每
/// A_WRTE 一 A_OKAY 的窗口语义），消费侧腾出空间后补发——快产（设备猛灌数据）慢消
/// （client socket 停滞）时内存被钉在 `上限 × maxdata`（通告 1MiB → 8MiB）内，不再无界增长。
const INBOX_MAX_QUEUED: usize = 8;

#[derive(Default)]
struct StreamCtl {
    can_send: bool,
    opened: bool,
    closed: bool,
}

struct Inbox {
    queue: VecDeque<Vec<u8>>,
    eof: bool,
    /// 满窗时欠下的 A_OKAY 续窗 `(local_id, remote_id)`；消费侧 pop 腾出空间后补发。
    deferred_ack: Option<(u32, u32)>,
}

/// 单条 stream 的共享状态（读循环线程与 client 线程共享）。
struct StreamSlot {
    remote_id: AtomicU32, // 设备侧 id，A_OKAY 后填入；0=未就绪
    ctl: Mutex<StreamCtl>,
    ctl_cv: Condvar,
    inbox: Mutex<Inbox>,
    inbox_cv: Condvar,
}

impl StreamSlot {
    fn new() -> Self {
        Self {
            remote_id: AtomicU32::new(0),
            ctl: Mutex::new(StreamCtl::default()),
            ctl_cv: Condvar::new(),
            inbox: Mutex::new(Inbox {
                queue: VecDeque::new(),
                eof: false,
                deferred_ack: None,
            }),
            inbox_cv: Condvar::new(),
        }
    }

    fn mark_closed(&self) {
        {
            let mut c = self.ctl.lock().unwrap_or_else(|e| e.into_inner());
            c.closed = true;
        }
        self.ctl_cv.notify_all();
        {
            let mut ib = self.inbox.lock().unwrap_or_else(|e| e.into_inner());
            ib.eof = true;
            // 关闭即注销欠账：流已死（A_CLSE 已发/已收），消费侧继续排空残留队列时
            // 绝不能再把陈旧 A_OKAY 补发到已关闭的 stream id 上。
            ib.deferred_ack = None;
        }
        self.inbox_cv.notify_all();
    }

    /// 设备数据进收件箱；返回是否应立即回 A_OKAY 续窗。队列达到上限则记欠账
    /// （[`Inbox::deferred_ack`]），由消费侧腾出空间后补发。
    fn push_wrte(&self, local_id: u32, remote_id: u32, payload: Vec<u8>) -> bool {
        let ack_now = {
            let mut ib = self.inbox.lock().unwrap_or_else(|e| e.into_inner());
            ib.queue.push_back(payload);
            if ib.queue.len() >= INBOX_MAX_QUEUED {
                ib.deferred_ack = Some((local_id, remote_id));
                false
            } else {
                true
            }
        };
        self.inbox_cv.notify_all();
        ack_now
    }

    /// 阻塞取下一块设备数据，并返回消费后需补发的 A_OKAY（若有欠账且队列已回落）。
    /// `(None, _)` 表示对端已关闭（EOF）。
    fn pop_blocking(&self) -> (Option<Vec<u8>>, Option<(u32, u32)>) {
        self.pop_within(None).unwrap_or((None, None))
    }

    /// 同 [`Self::pop_blocking`]，但至多等 `timeout`（`None` = 不限）；到期既无数据也未 EOF 返回 `None`。
    #[allow(clippy::type_complexity)]
    fn pop_within(
        &self,
        timeout: Option<Duration>,
    ) -> Option<(Option<Vec<u8>>, Option<(u32, u32)>)> {
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut ib = self.inbox.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(data) = ib.queue.pop_front() {
                let ack = if ib.queue.len() < INBOX_MAX_QUEUED {
                    ib.deferred_ack.take()
                } else {
                    None
                };
                return Some((Some(data), ack));
            }
            if ib.eof {
                return Some((None, None));
            }
            ib = match deadline {
                None => self.inbox_cv.wait(ib).unwrap_or_else(|e| e.into_inner()),
                Some(at) => {
                    let left = at.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return None;
                    }
                    self.inbox_cv
                        .wait_timeout(ib, left)
                        .unwrap_or_else(|e| e.into_inner())
                        .0
                }
            };
        }
    }
}

struct MuxShared {
    streams: Mutex<HashMap<u32, Arc<StreamSlot>>>,
    next_id: AtomicU32,
}

impl MuxShared {
    fn new() -> Self {
        Self {
            streams: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(1),
        }
    }

    /// 分配一个非 0 的本地 stream id（0 是无效 local_id）。
    fn alloc_id(&self) -> u32 {
        loop {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }

    fn get(&self, id: u32) -> Option<Arc<StreamSlot>> {
        self.streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .cloned()
    }

    fn remove(&self, id: u32) -> Option<Arc<StreamSlot>> {
        self.streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id)
    }
}

/// 拥有 device 的读循环端；`run()` 必须在持有 device 的线程阻塞执行（WinUSB 句柄 !Send）。
pub struct MuxSession {
    device: AdbWinUsbDevice,
    shared: Arc<MuxShared>,
    writer: AdbRawWriter,
    write_lock: Arc<Mutex<()>>,
    /// 会话存活标志：`MuxSession` drop（device 句柄随后被 WinUsb_Free）**之前**在写锁内置
    /// false。桥接线程手里的 `MuxHandle`/`MuxStream` 只持有句柄的裸拷贝，会话结束后仍可能
    /// 发 A_CLSE/A_WRTE——写前在同一把写锁下检查该标志，杜绝对已释放句柄的 use-after-free。
    alive: Arc<AtomicBool>,
    /// 停止标志：外部（server 侧发现 open_stream 对设备装死）置 true 后，读循环在下一个轮询
    /// 周期内退出，从而让属主线程走完 `run()` 后的清槽/释放句柄，供全新连接重建。
    stop: Arc<AtomicBool>,
    /// 对端 CNXN 回的 maxdata：发往设备的单个 A_WRTE 不得超过它。
    max_payload: usize,
}

/// 可跨线程克隆的操作端：client 线程用它 open_stream，随后在各 stream 上并发读写。
#[derive(Clone)]
pub struct MuxHandle {
    shared: Arc<MuxShared>,
    writer: AdbRawWriter,
    write_lock: Arc<Mutex<()>>,
    alive: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    max_payload: usize,
}

impl MuxSession {
    /// 用一台设备建立 mux 会话：确保已 A_CNXN 握手，并把读超时设为有限轮询（见
    /// [`READ_POLL_TIMEOUT_MS`]）——空闲隧道靠「Timeout 即继续」不误判掉线，同时让读循环可被
    /// stop 标志打断，使半死 hub 能被外部拆除重建。
    pub fn new(mut device: AdbWinUsbDevice) -> Result<Self, String> {
        device.connect()?;
        device.set_read_timeout(READ_POLL_TIMEOUT_MS);
        let writer = device.raw_writer();
        let max_payload = (device.max_payload() as usize).max(1);
        Ok(Self {
            device,
            shared: Arc::new(MuxShared::new()),
            writer,
            write_lock: Arc::new(Mutex::new(())),
            alive: Arc::new(AtomicBool::new(true)),
            stop: Arc::new(AtomicBool::new(false)),
            max_payload,
        })
    }

    /// 设备 CNXN banner（握手已在 [`MuxSession::new`] 里完成）。5037 server 用它作答
    /// `host:features` 与 `devices -l`——hub 是全程唯一持有设备的一方，banner 只有它拿得到。
    pub fn peer_banner(&self) -> &crate::adb_protocol::PeerBanner {
        self.device.peer_banner()
    }

    pub fn handle(&self) -> MuxHandle {
        MuxHandle {
            shared: self.shared.clone(),
            writer: self.writer,
            write_lock: self.write_lock.clone(),
            alive: self.alive.clone(),
            stop: self.stop.clone(),
            max_payload: self.max_payload,
        }
    }

    fn send(&self, command: u32, local_id: u32, remote_id: u32, data: &[u8]) {
        let _g = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let _ = self
            .writer
            .write_message(command, local_id, remote_id, data);
    }

    /// 阻塞读循环：返回即会话结束（读错误/设备断开），退出前唤醒所有 stream。
    pub fn run(&mut self) -> Result<(), String> {
        let result = self.read_loop();
        self.shutdown_all();
        result
    }

    fn read_loop(&self) -> Result<(), String> {
        loop {
            // 外部请求拆除（半死 hub）：干净退出，让属主线程走清槽/释放句柄。
            if self.stop.load(Ordering::SeqCst) {
                return Ok(());
            }
            let hdr = match self.device.read_header() {
                Ok(h) => h,
                // 轮询窗口内无包 = 空闲（承载空闲隧道的正常态）：回到循环顶再查 stop、再等。
                Err(TransportError::Timeout) => continue,
                Err(e) => return Err(format!("mux read header failed: {:?}", e)),
            };
            let mut payload = Vec::new();
            if hdr.data_length > 0 {
                // 报头已到，载荷应紧随其后；此处再超时视为真实停滞 → 退出触发自愈，不当空闲处理。
                payload = vec![0u8; hdr.data_length as usize];
                self.device
                    .read_exact(&mut payload)
                    .map_err(|e| format!("mux read payload failed: {:?}", e))?;
            }
            self.dispatch(hdr.command, hdr.arg0, hdr.arg1, payload);
        }
    }

    fn dispatch(&self, command: u32, arg0: u32, arg1: u32, payload: Vec<u8>) {
        let local_id = arg1;
        match command {
            A_OKAY => {
                if let Some(slot) = self.shared.get(local_id) {
                    if slot.remote_id.load(Ordering::Relaxed) == 0 {
                        slot.remote_id.store(arg0, Ordering::Relaxed);
                    }
                    let mut c = slot.ctl.lock().unwrap_or_else(|e| e.into_inner());
                    c.opened = true;
                    c.can_send = true;
                    slot.ctl_cv.notify_all();
                }
            }
            A_WRTE => {
                if let Some(slot) = self.shared.get(local_id) {
                    // 有界收件箱：未满立即回 A_OKAY 续窗（半双工透传/隧道都靠它推进）；
                    // 满了扣住授信，消费侧腾空后补发（见 pop_blocking），防积压吃爆内存。
                    let rid = slot.remote_id.load(Ordering::Relaxed);
                    if slot.push_wrte(local_id, rid, payload) {
                        self.send(A_OKAY, local_id, rid, &[]);
                    }
                } else {
                    // 未知 stream：请设备关闭，避免对端一直等 ack。
                    self.send(A_CLSE, local_id, arg0, &[]);
                }
            }
            A_CLSE => {
                if let Some(slot) = self.shared.remove(local_id) {
                    slot.mark_closed();
                }
            }
            A_OPEN => {
                // 设备发起的 reverse 回连：arg0=设备侧 id（本机视角 remote_id），arg1 此刻为 0。
                self.handle_inbound_open(arg0, &payload);
            }
            _ => {}
        }
    }

    /// 处理设备发起的 A_OPEN（reverse 回连）：`payload` 是 host 侧目标（scrcpy 用 `tcp:<port>`）。
    /// 连本机该 tcp、回 A_OKAY，并起两条线程把该 stream 与 tcp 双向桥接。
    fn handle_inbound_open(&self, device_remote_id: u32, payload: &[u8]) {
        let dest = String::from_utf8_lossy(payload)
            .trim_matches(char::from(0))
            .to_string();
        let Some(port) = tcp_port(&dest) else {
            // 目前只支持 host 侧 tcp:<port>（scrcpy reverse 的 local 即为此形态）。
            self.send(A_CLSE, 0, device_remote_id, &[]);
            return;
        };
        let tcp = match TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => s,
            Err(_) => {
                self.send(A_CLSE, 0, device_remote_id, &[]);
                return;
            }
        };
        let _ = tcp.set_nodelay(true);

        let local_id = self.shared.alloc_id();
        let slot = Arc::new(StreamSlot::new());
        slot.remote_id.store(device_remote_id, Ordering::Relaxed);
        {
            let mut c = slot.ctl.lock().unwrap_or_else(|e| e.into_inner());
            c.opened = true;
            c.can_send = true;
        }
        self.shared
            .streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(local_id, slot.clone());

        // 先回 A_OKAY 让设备开始发数据；随后建立桥接线程。
        self.send(A_OKAY, local_id, device_remote_id, &[]);

        let stream = MuxStream {
            local_id,
            remote_id: device_remote_id,
            slot,
            handle: self.handle(),
        };
        spawn_inbound_bridge(stream, tcp);
    }

    fn shutdown_all(&self) {
        let drained: Vec<Arc<StreamSlot>> = {
            let mut map = self
                .shared
                .streams
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            map.drain().map(|(_, slot)| slot).collect()
        };
        for slot in drained {
            slot.mark_closed();
        }
    }
}

impl Drop for MuxSession {
    fn drop(&mut self) {
        // 关键顺序：先在写锁内熄灭 alive，再让 device 随字段析构去 WinUsb_Free。
        // 拿到锁即证明没有客户端写在途；此后到来的写在锁内看到 dead 直接得错，
        // 绝不会触碰稍后释放的句柄（Rust 保证 Drop::drop 先于字段析构执行）。
        let _g = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.alive.store(false, Ordering::SeqCst);
    }
}

/// 双向桥接 MuxStream 与本机 TcpStream，阻塞至任一方向结束后清理；reverse 回连与 host 发起的服务共用。
/// 两半分跑本线程与子线程，从不跨线程共享同一 MuxStream（`AdbRawWriter` 仅 Send、不 Sync）。
pub fn bridge_stream_tcp_blocking(stream: MuxStream, tcp: TcpStream) {
    let slot = stream.slot.clone();
    let acker = stream.handle.clone();
    let mut tcp_read = match tcp.try_clone() {
        Ok(s) => s,
        Err(_) => {
            stream.close();
            return;
        }
    };
    let mut tcp_write = tcp;

    // device → tcp（子线程）：从收件箱取设备数据写给本机 tcp；消费腾出空间后补发
    // 满窗期间欠下的 A_OKAY 续窗（背压释放）。
    let pump = thread::spawn(move || {
        loop {
            let (data, ack) = slot.pop_blocking();
            if let Some((local_id, remote_id)) = ack {
                let _ = acker.send(A_OKAY, local_id, remote_id, &[]);
            }
            match data {
                Some(d) => {
                    if tcp_write.write_all(&d).is_err() || tcp_write.flush().is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
        let _ = tcp_write.shutdown(Shutdown::Both);
    });

    // tcp → device（本线程阻塞）：把本机 tcp 数据写进设备 stream。
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match tcp_read.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stream.write(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    stream.close();
    let _ = pump.join();
}

/// 非阻塞版：在独立线程里跑 [`bridge_stream_tcp_blocking`]，用于 reverse 回连（设备主动 A_OPEN），
/// 桥接需与读循环并发存活，故不能阻塞读循环线程。
fn spawn_inbound_bridge(stream: MuxStream, tcp: TcpStream) {
    thread::spawn(move || bridge_stream_tcp_blocking(stream, tcp));
}

impl MuxHandle {
    fn send(&self, command: u32, local_id: u32, remote_id: u32, data: &[u8]) -> Result<(), String> {
        let _g = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        // 与 MuxSession::drop 用同一把写锁互斥：拿到锁后 alive 仍真 → 句柄必然尚未释放；
        // 已死则快速失败，绝不把 A_WRTE/A_CLSE 写到已 WinUsb_Free 的句柄上。
        if !self.alive.load(Ordering::SeqCst) {
            return Err("mux 会话已结束（设备断开）".to_string());
        }
        self.writer
            .write_message(command, local_id, remote_id, data)
            .map_err(|e| format!("mux write failed: {:?}", e))
    }

    /// 请求读循环停止（半死 hub 自愈用）。置标志后属主设备线程在下一个轮询周期内退出 `run()`，
    /// 随即清槽并释放 WinUSB 句柄，供全新连接重建。幂等、非阻塞。
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    /// 打开一条到设备 `service`（如 `shell:...` / `sync:` / `reverse:forward:...`）的 stream。
    pub fn open_stream(&self, service: &str) -> Result<MuxStream, String> {
        let local_id = self.shared.alloc_id();
        let slot = Arc::new(StreamSlot::new());
        self.shared
            .streams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(local_id, slot.clone());

        let mut dest = service.as_bytes().to_vec();
        dest.push(0);
        if let Err(e) = self.send(A_OPEN, local_id, 0, &dest) {
            self.shared.remove(local_id);
            return Err(e);
        }

        // 等 A_OKAY(opened) 或 A_CLSE(closed=被拒)。
        let mut c = slot.ctl.lock().unwrap_or_else(|e| e.into_inner());
        while !c.opened && !c.closed {
            let (guard, timeout) = slot
                .ctl_cv
                .wait_timeout(c, OPEN_TIMEOUT)
                .unwrap_or_else(|e| e.into_inner());
            c = guard;
            if timeout.timed_out() && !c.opened && !c.closed {
                drop(c);
                self.shared.remove(local_id);
                return Err(format!(
                    "{} open '{}' timed out",
                    OPEN_TIMEOUT_MARKER, service
                ));
            }
        }
        let opened = c.opened;
        drop(c);
        if !opened {
            self.shared.remove(local_id);
            return Err(format!("{} '{}'", OPEN_REJECTED_PREFIX, service));
        }
        let remote_id = slot.remote_id.load(Ordering::Relaxed);
        Ok(MuxStream {
            local_id,
            remote_id,
            slot,
            handle: self.clone(),
        })
    }
}

/// 一条多路复用 stream；Send，可交给桥接线程做 client<->device 转发。
pub struct MuxStream {
    local_id: u32,
    remote_id: u32,
    slot: Arc<StreamSlot>,
    handle: MuxHandle,
}

impl MuxStream {
    /// 向设备写数据（按对端 maxdata 分片；每片等对端 A_OKAY 流控）。
    pub fn write(&self, data: &[u8]) -> Result<(), String> {
        for part in data.chunks(self.handle.max_payload) {
            let mut c = self.slot.ctl.lock().unwrap_or_else(|e| e.into_inner());
            while !c.can_send && !c.closed {
                c = self.slot.ctl_cv.wait(c).unwrap_or_else(|e| e.into_inner());
            }
            if c.closed {
                return Err("stream closed".to_string());
            }
            c.can_send = false;
            drop(c);
            self.handle
                .send(A_WRTE, self.local_id, self.remote_id, part)?;
        }
        Ok(())
    }

    pub fn close(&self) {
        let _ = self.handle.send(A_CLSE, self.local_id, self.remote_id, &[]);
        self.shared_remove();
        self.slot.mark_closed();
    }

    fn shared_remove(&self) {
        self.handle.shared.remove(self.local_id);
    }
}

/// 本进程自己的 adb 命令直连 mux hub 时用的流：`Read`/`Write` 直接落在设备 stream 上，不经 5037
/// TCP 回环与 host 协议。写入先攒着，满一个对端 maxdata、或转去读应答时才发——sync 的记录头与数据
/// 合成一个 A_WRTE，不让每个 8 字节头都单独等一次 A_OKAY 往返。drop 即 A_CLSE；此时还没发出的写入
/// 一并丢弃（走到 drop 还没读应答，说明协议已中途放弃）。
pub struct MuxStreamIo {
    stream: MuxStream,
    rbuf: Vec<u8>,
    rpos: usize,
    wbuf: Vec<u8>,
    read_timeout: Option<Duration>,
}

impl MuxStreamIo {
    pub fn new(stream: MuxStream) -> Self {
        Self {
            stream,
            rbuf: Vec::new(),
            rpos: 0,
            wbuf: Vec::new(),
            read_timeout: None,
        }
    }

    /// 单次 `read` 等设备数据的上限（`None` = 等到数据或 EOF），语义同 `TcpStream::set_read_timeout`。
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }

    fn send_pending(&mut self) -> io::Result<()> {
        if self.wbuf.is_empty() {
            return Ok(());
        }
        let sent = self.stream.write(&self.wbuf);
        self.wbuf.clear();
        sent.map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))
    }
}

impl Read for MuxStreamIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.send_pending()?;
        while self.rpos >= self.rbuf.len() {
            let Some((data, ack)) = self.stream.slot.pop_within(self.read_timeout) else {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "等待设备数据超时"));
            };
            if let Some((local_id, remote_id)) = ack {
                let _ = self.stream.handle.send(A_OKAY, local_id, remote_id, &[]);
            }
            match data {
                Some(chunk) => {
                    self.rbuf = chunk;
                    self.rpos = 0;
                }
                None => return Ok(0),
            }
        }
        let n = buf.len().min(self.rbuf.len() - self.rpos);
        buf[..n].copy_from_slice(&self.rbuf[self.rpos..self.rpos + n]);
        self.rpos += n;
        Ok(n)
    }
}

impl Write for MuxStreamIo {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.wbuf.extend_from_slice(data);
        if self.wbuf.len() >= self.stream.handle.max_payload {
            self.send_pending()?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_pending()
    }
}

impl Drop for MuxStreamIo {
    fn drop(&mut self) {
        self.stream.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_port_parses_only_tcp_endpoints() {
        assert_eq!(tcp_port("tcp:27183"), Some(27183));
        assert_eq!(tcp_port("localabstract:x"), None);
    }

    /// open_stream 的超时错误要能被 server 侧判出来（触发拆 hub 重建），而被明确拒绝/写失败
    /// 不得误判为超时（否则会把健康 hub 拆了）。
    #[test]
    fn open_timeout_marker_classifies_only_timeouts() {
        let timeout = format!("{} open 'shell:id' timed out", OPEN_TIMEOUT_MARKER);
        assert!(is_open_timeout_err(&timeout));
        assert!(!is_open_timeout_err("device rejected service 'shell:id'"));
        assert!(!is_open_timeout_err("mux 会话已结束（设备断开）"));

        assert!(is_open_rejected_err(
            "device rejected service 'shell,v2,raw:id'"
        ));
        assert!(!is_open_rejected_err(&timeout));
        assert!(!is_open_rejected_err("no devices/emulators found"));
    }

    #[test]
    fn mux_alloc_id_skips_zero_and_increments() {
        let shared = MuxShared::new();
        let a = shared.alloc_id();
        let b = shared.alloc_id();
        assert_ne!(a, 0);
        assert_ne!(b, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn mux_slot_close_sets_eof_and_closed() {
        let slot = StreamSlot::new();
        slot.mark_closed();
        assert!(slot.ctl.lock().unwrap().closed);
        assert!(slot.inbox.lock().unwrap().eof);
    }

    /// 收件箱背压：未满立即续窗；达到上限扣住 A_OKAY；消费腾出空间后恰好补发一次。
    #[test]
    fn inbox_backpressure_withholds_then_releases_credit() {
        let slot = StreamSlot::new();
        for i in 0..INBOX_MAX_QUEUED - 1 {
            assert!(
                slot.push_wrte(7, 9, vec![i as u8]),
                "未满前每包都应立即续窗"
            );
        }
        // 这一包让队列达到上限：授信被扣住，欠账记录在册。
        assert!(!slot.push_wrte(7, 9, vec![0xff]));
        assert_eq!(slot.inbox.lock().unwrap().deferred_ack, Some((7, 9)));

        // 消费一包 → 队列回落到上限之下 → 补发欠下的 A_OKAY，且只补一次。
        let (data, ack) = slot.pop_blocking();
        assert!(data.is_some());
        assert_eq!(ack, Some((7, 9)));
        let (_, ack_again) = slot.pop_blocking();
        assert_eq!(ack_again, None);
    }

    /// EOF 后不再欠账补发：流已死，授信没有意义。mark_closed 必须当场注销欠账——
    /// 带着满窗数据关闭的流，其后每一笔排空消费都不得把陈旧 A_OKAY 补发出去。
    #[test]
    fn inbox_eof_drops_pending_credit() {
        let slot = StreamSlot::new();
        for i in 0..INBOX_MAX_QUEUED {
            let _ = slot.push_wrte(1, 2, vec![i as u8]);
        }
        assert_eq!(slot.inbox.lock().unwrap().deferred_ack, Some((1, 2)));
        slot.mark_closed();
        assert_eq!(
            slot.inbox.lock().unwrap().deferred_ack,
            None,
            "关闭必须清掉欠账，否则残留队列的第一笔消费就会重放陈旧 A_OKAY"
        );
        // 清空队列直到 EOF，全程不得回报欠账。
        loop {
            let (data, ack) = slot.pop_blocking();
            assert_eq!(ack, None, "关闭后的消费不得补发 A_OKAY");
            if data.is_none() {
                break;
            }
        }
    }

    /// 会话已死（device 已随线程退出被释放）时，任何经 MuxHandle 的写都必须在触碰
    /// WinUSB 句柄之前快速失败——这是对句柄 use-after-free 的回归测试。
    #[test]
    fn dead_session_send_fails_before_touching_handle() {
        let handle = MuxHandle {
            shared: Arc::new(MuxShared::new()),
            writer: AdbRawWriter::dead_for_tests(),
            write_lock: Arc::new(Mutex::new(())),
            alive: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
            max_payload: crate::adb_protocol::ADB_LEGACY_MAX_PAYLOAD as usize,
        };
        let err = handle.send(A_WRTE, 1, 2, b"x").unwrap_err();
        assert!(err.contains("mux 会话已结束"));
        assert!(handle.open_stream("shell:id").is_err());

        // 死会话上的 stream 关闭也只是安静失败，不允许触碰句柄。
        let slot = Arc::new(StreamSlot::new());
        handle
            .shared
            .streams
            .lock()
            .unwrap()
            .insert(5, slot.clone());
        let stream = MuxStream {
            local_id: 5,
            remote_id: 6,
            slot,
            handle: handle.clone(),
        };
        stream.close();
        assert!(stream.slot.ctl.lock().unwrap().closed);
    }

    /// 挂在死会话上的 stream：数据只能经 `push_wrte` 喂进收件箱，任何发往设备的写都当场失败。
    fn dead_stream(local_id: u32) -> MuxStream {
        let handle = MuxHandle {
            shared: Arc::new(MuxShared::new()),
            writer: AdbRawWriter::dead_for_tests(),
            write_lock: Arc::new(Mutex::new(())),
            alive: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
            max_payload: crate::adb_protocol::ADB_LEGACY_MAX_PAYLOAD as usize,
        };
        let slot = Arc::new(StreamSlot::new());
        handle
            .shared
            .streams
            .lock()
            .unwrap()
            .insert(local_id, slot.clone());
        MuxStream {
            local_id,
            remote_id: local_id + 1,
            slot,
            handle,
        }
    }

    /// 进程内直连读：设备分块到达的数据按调用方缓冲区切分、顺序拼回，设备关流后读到 EOF。
    #[test]
    fn stream_io_reads_chunks_in_order_then_eof() {
        let stream = dead_stream(5);
        let slot = stream.slot.clone();
        let mut io = MuxStreamIo::new(stream);
        slot.push_wrte(5, 6, b"hello ".to_vec());
        slot.push_wrte(5, 6, b"world".to_vec());
        slot.mark_closed();

        let mut head = [0u8; 4];
        assert_eq!(io.read(&mut head).unwrap(), 4);
        assert_eq!(&head, b"hell");
        let mut rest = Vec::new();
        io.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"o world");
    }

    /// 设了读超时就不许无限挂住：设备不出声时按 TimedOut 报错，口径同 TcpStream。
    #[test]
    fn stream_io_read_times_out_without_data() {
        let mut io = MuxStreamIo::new(dead_stream(7));
        io.set_read_timeout(Some(Duration::from_millis(30)));
        let err = io.read(&mut [0u8; 8]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    /// 写入攒到 maxdata 或转去读应答时才发：读之前必须先把请求发出去，否则设备收不到请求、
    /// 读端永远等不到应答。死会话上「发出」即失败、且会吃掉 can_send 授信，借此观察发送时机；
    /// 每条流只触发一次发送（授信不会再回来，第二次写会按流控一直等）。
    #[test]
    fn stream_io_defers_writes_until_read_or_full() {
        let stream = dead_stream(9);
        let slot = stream.slot.clone();
        slot.ctl.lock().unwrap().can_send = true;
        let mut io = MuxStreamIo::new(stream);
        assert_eq!(io.write(b"RECV").unwrap(), 4);
        assert!(
            slot.ctl.lock().unwrap().can_send,
            "未满 maxdata 只进缓冲，不碰会话"
        );
        let err = io.read(&mut [0u8; 4]).unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::BrokenPipe,
            "读之前必须先发出攒着的请求"
        );

        let stream = dead_stream(11);
        stream.slot.ctl.lock().unwrap().can_send = true;
        let mut io = MuxStreamIo::new(stream);
        let full = vec![0u8; crate::adb_protocol::ADB_LEGACY_MAX_PAYLOAD as usize];
        assert!(io.write(&full).is_err(), "攒满一个 maxdata 必须立即发出");
    }
}
