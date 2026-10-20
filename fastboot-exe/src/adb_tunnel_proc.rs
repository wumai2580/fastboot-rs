//! `adb forward` / `adb reverse` 常驻子进程（`--adb-forwarder` / `--adb-reverser`）的公共设施：
//! 选设备、拉起子进程并完成就绪文件握手、登记表读写。
//!
//! 两条隧道的差别只在登记表文件名、TSV 列序与就绪等待时长，其余完全同一套。登记表路径与列序
//! 是既有的落盘格式（`%LOCALAPPDATA%\rmf-adb-fastboot\adb-forwards.tsv` / `adb-reverses.tsv`），
//! 升级前写下的文件必须照旧能读，改动时不得变更。

use crate::adb_winusb_transport::{serial_from_path, AdbDeviceInfo, AdbWinUsbDevice};
use crate::self_spawn::detached_self;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Child;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// 一条隧道登记：哪台设备、两端端点、承载它的子进程 PID。
#[derive(Clone, Debug)]
pub(crate) struct TunnelRecord {
    pub serial: String,
    pub local: String,
    pub remote: String,
    pub pid: u32,
}

/// 一类隧道的登记表。
pub(crate) struct Registry {
    file_name: &'static str,
    /// TSV 第二列是 remote（reverse 的历史格式）还是 local（forward）。
    remote_first: bool,
    /// 错误文案里的名字（"forward" / "reverse"）。
    what: &'static str,
}

impl Registry {
    pub(crate) const fn new(
        file_name: &'static str,
        remote_first: bool,
        what: &'static str,
    ) -> Self {
        Self {
            file_name,
            remote_first,
            what,
        }
    }

    fn path(&self) -> PathBuf {
        let base = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        base.join("rmf-adb-fastboot").join(self.file_name)
    }

    /// 一行 TSV：`serial \t 第二列 \t 第三列 \t pid`，第二、三列的含义由 `remote_first` 决定。
    fn parse_line(&self, line: &str) -> Option<TunnelRecord> {
        let mut parts = line.split('\t');
        let serial = parts.next()?.to_string();
        let first = parts.next()?.to_string();
        let second = parts.next()?.to_string();
        let pid = parts.next()?.parse::<u32>().ok()?;
        let (local, remote) = if self.remote_first {
            (second, first)
        } else {
            (first, second)
        };
        Some(TunnelRecord {
            serial,
            local,
            remote,
            pid,
        })
    }

    fn format_line(&self, record: &TunnelRecord) -> String {
        let (first, second) = if self.remote_first {
            (&record.remote, &record.local)
        } else {
            (&record.local, &record.remote)
        };
        format!("{}\t{}\t{}\t{}\n", record.serial, first, second, record.pid)
    }

    pub(crate) fn load(&self) -> Vec<TunnelRecord> {
        let Ok(text) = fs::read_to_string(self.path()) else {
            return Vec::new();
        };
        text.lines()
            .filter_map(|line| self.parse_line(line))
            .collect()
    }

    pub(crate) fn save(&self, records: &[TunnelRecord]) -> Result<(), String> {
        let path = self.path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create {} registry: {}", self.what, e))?;
        }
        let text: String = records.iter().map(|r| self.format_line(r)).collect();
        fs::write(path, text).map_err(|e| format!("failed to write {} registry: {}", self.what, e))
    }
}

/// 打开指定（或唯一在线的）ADB 设备。先让常驻 daemon 交出设备句柄，否则 WinUSB 独占打开会被拒。
pub(crate) fn open_selected_device(serial: Option<&str>) -> Result<AdbWinUsbDevice, String> {
    crate::adb_daemon::ensure_released();
    let devices = AdbWinUsbDevice::enumerate().map_err(|e| e.to_string())?;
    let path = select_device_path(&devices, serial)?;
    AdbWinUsbDevice::open_device(&path).map_err(|e| e.to_string())
}

/// 只枚举、不开设备，解析出本次隧道要登记的设备序列号。
pub(crate) fn resolve_selected_serial(serial: Option<&str>) -> Result<String, String> {
    let devices = AdbWinUsbDevice::enumerate().map_err(|e| e.to_string())?;
    let path = select_device_path(&devices, serial)?;
    Ok(serial_from_path(&path))
}

fn select_device_path(devices: &[AdbDeviceInfo], serial: Option<&str>) -> Result<String, String> {
    if devices.is_empty() {
        return Err("No ADB device found".to_string());
    }

    if let Some(wanted) = serial.filter(|s| !s.is_empty() && *s != "unknown") {
        return devices
            .iter()
            .find(|d| serial_from_path(&d.device_path) == wanted)
            .map(|d| d.device_path.clone())
            .ok_or_else(|| format!("ADB device with serial '{}' was not found", wanted));
    }

    if devices.len() > 1 {
        return Err("More than one ADB device is connected; use -s <serial>".to_string());
    }

    Ok(devices[0].device_path.clone())
}

/// 以本 exe 拉起一条隧道子进程并等它在就绪文件里回报：`OK\t<实际端点>` 或 `ERR\t<原因>`。
/// 握手失败（超时 / ERR / 回报格式不对）时杀掉子进程再返回错误，不留孤儿。
pub(crate) fn spawn_tunnel_child(
    role_arg: &str,
    endpoint_args: &[(&str, &str)],
    ready_timeout: Duration,
    what: &str,
) -> Result<(Child, String), String> {
    let ready_file = unique_ready_file(what);
    let mut command = detached_self(role_arg)?;
    for (flag, value) in endpoint_args {
        command.arg(flag).arg(value);
    }
    let mut child = command
        .arg("--ready-file")
        .arg(&ready_file)
        .spawn()
        .map_err(|e| format!("failed to start adb {}er: {}", what, e))?;

    let ready = wait_ready_file(&ready_file, ready_timeout).ok_or_else(|| {
        let _ = child.kill();
        format!("adb {}er did not become ready in time", what)
    })?;
    let _ = fs::remove_file(&ready_file);

    if let Some(msg) = ready.strip_prefix("ERR\t") {
        let _ = child.kill();
        return Err(msg.to_string());
    }
    match ready.strip_prefix("OK\t") {
        Some(endpoint) => Ok((child, endpoint.trim().to_string())),
        None => {
            let _ = child.kill();
            Err(format!(
                "invalid adb {}er readiness response: {}",
                what, ready
            ))
        }
    }
}

fn unique_ready_file(what: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    env::temp_dir().join(format!(
        "rmf-adb-{}-ready-{}-{}.txt",
        what,
        std::process::id(),
        now
    ))
}

fn wait_ready_file(path: &PathBuf, timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(text) = fs::read_to_string(path) {
            return Some(text);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// 子进程侧：把就绪/失败结果写进父进程指定的就绪文件（没指定就什么都不做）。
pub(crate) fn write_ready(path: &Option<PathBuf>, text: &str) {
    if let Some(path) = path {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(path, text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 登记表列序是既有落盘格式：forward 为 serial/local/remote/pid，reverse 为 serial/remote/local/pid。
    #[test]
    fn registry_column_order_matches_the_on_disk_format() {
        let record = TunnelRecord {
            serial: "S1".into(),
            local: "tcp:1000".into(),
            remote: "localabstract:x".into(),
            pid: 42,
        };
        for (remote_first, expected) in [
            (false, "S1\ttcp:1000\tlocalabstract:x\t42\n"),
            (true, "S1\tlocalabstract:x\ttcp:1000\t42\n"),
        ] {
            let reg = Registry::new("unused.tsv", remote_first, "test");
            let line = reg.format_line(&record);
            assert_eq!(line, expected);
            let parsed = reg
                .parse_line(line.trim_end())
                .expect("自己写出的行必须读得回");
            assert_eq!(parsed.serial, record.serial);
            assert_eq!(parsed.local, record.local);
            assert_eq!(parsed.remote, record.remote);
            assert_eq!(parsed.pid, record.pid);
        }
        // 残缺行（旧版本写坏/手改）跳过而不是 panic
        let reg = Registry::new("unused.tsv", false, "test");
        assert!(reg.parse_line("S1\ttcp:1").is_none());
        assert!(reg.parse_line("S1\ta\tb\tnot-a-pid").is_none());
    }
}
