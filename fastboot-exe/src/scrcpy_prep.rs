//! scrcpy 投屏的设备准备/收尾：GUI 只调这两条子命令，adb 编排整体在这里（rmf-app 的 `scrcpy.rs` 调用）。
//! `adb scrcpy-prep`：确保常驻 mux server → 等设备就绪 → 读设备信息 → 输出一行 JSON；
//! `adb scrcpy-cleanup`：请 mux server 干净退出（释放 5037 与设备 USB 句柄）。
//! 全程复用 mux：设备句柄一次抓住全程持有，避免「回退直连」反复重连。

use std::time::{Duration, Instant};

/// 等设备就绪 + 读设备信息，向 stdout 输出一行 JSON（`{"ready":true,"serial":...}` 或
/// `{"ready":false,"state":"unauthorized|offline|fastboot|none"}`）。有 device/recovery 设备返回 0，否则 1。
///
/// 投屏只支持 ADB 模式。`devices` 的在线状态还不足以证明 shell 能应答，所以这里要求
/// `getprop` 返回真实属性，避免设备信息全空仍报 ready、随后反复启动没有画面的 scrcpy。
/// 答不上来且旁边有 fastboot 设备，就报 `state=fastboot` 继续等
/// 设备回到系统（一键 ROOT 等流程会把手机在 adb/fastboot 之间来回重启，等到即自动接上）。
pub fn run_prep() -> i32 {
    // 1) 自动拉起常驻 mux server（首个命令即把设备句柄一次抓住全程持有）。
    crate::adb_mux_server::ensure_server_running();

    // 2) 在 30s 轮询窗口内等待 device/recovery 且 getprop 可用；单次请求自身的超时可能延长总耗时。
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut serial = String::new();
    let mut props = String::new();
    let mut last_state = "none".to_string();
    // fastboot 侧枚举对兼容 ID 判不出的接口会开一次句柄读描述符，别每 500ms 都做：
    // 只在 adb 侧没有可用设备时探，且至少间隔 2s（与 GUI 自己的 fastboot 轮询同一量级）。
    let mut fastboot_probe = Throttle::new(Duration::from_secs(2));
    while Instant::now() < deadline {
        if let Some(list) = crate::adb_mux_client::devices(false) {
            if let Some((s, _)) = first_ready_device(&list) {
                match read_props(&s) {
                    Some(p) => {
                        serial = s;
                        props = p;
                        break;
                    }
                    // 答不上 getprop 且设备此刻报 unauthorized：是这条 getprop 触发的握手在等用户
                    // 点「允许 USB 调试」（mux 只有握手开始后才知道），不算就绪、继续等——否则会
                    // 带着一台所有流都打不开的设备去起 scrcpy，窗口永远没画面。
                    None if device_now_unauthorized(&s) => {
                        last_state = "unauthorized".to_string();
                    }
                    // 枚举说是 adb 设备却答不上 getprop：不能把失败伪装成 ready，继续等真实通道就绪。
                    None if fastboot_probe.run(fastboot_device_present) => {
                        last_state = "fastboot".to_string();
                    }
                    None => {
                        last_state = "offline".to_string();
                    }
                }
            } else if let Some((_, st)) = first_any_device(&list) {
                last_state = st;
            } else if fastboot_probe.run(fastboot_device_present) {
                // adb 侧空、fastboot 侧有：给用户一句准话，而不是「未识别到 ADB 设备」。
                last_state = "fastboot".to_string();
            }
        }
        // 未授权要用户去手机上点，等满 30s 才返回只会让界面迟迟不提示（像是「识别很久」）。
        // 立刻报出去；握手线程仍在后台等授权，用户点了之后调用方下一轮 prep 即可接上。
        if last_state == "unauthorized" {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    if serial.is_empty() {
        println!(
            "{{\"ready\":false,\"state\":\"{}\"}}",
            json_escape(&last_state)
        );
        return 1;
    }
    let codename = pick_prop(
        &props,
        &[
            "ro.product.device",
            "ro.product.vendor.device",
            "ro.product.odm.device",
            "ro.product.name",
        ],
    )
    .unwrap_or_default();
    let manufacturer = pick_prop(
        &props,
        &[
            "ro.product.manufacturer",
            "ro.product.vendor.manufacturer",
            "ro.product.brand",
            "ro.product.vendor.brand",
        ],
    )
    .unwrap_or_default();
    let product = pick_prop(
        &props,
        &[
            "ro.product.marketname",
            "ro.product.vendor.marketname",
            "ro.product.model",
            "ro.product.name",
        ],
    )
    .unwrap_or_else(|| "未知设备".to_string());
    let slot = pick_prop(&props, &["ro.boot.slot_suffix"])
        .map(|s| s.trim_start_matches('_').to_string())
        .unwrap_or_default();
    let system_version = pick_prop(
        &props,
        &[
            "ro.mi.os.version.incremental",
            "ro.build.version.incremental",
            "ro.build.display.id",
            "ro.build.version.ota",
        ],
    )
    .unwrap_or_default();
    let android_version = pick_prop(
        &props,
        &[
            "ro.build.version.release",
            "ro.system.build.version.release",
        ],
    )
    .unwrap_or_default();
    let unlock_state = unlock_state_from_props(&props).unwrap_or_default();

    println!(
        "{{\"ready\":true,\"serial\":\"{}\",\"codename\":\"{}\",\"manufacturer\":\"{}\",\"product\":\"{}\",\"system\":\"{}\",\"android\":\"{}\",\"slot\":\"{}\",\"unlocked\":\"{}\"}}",
        json_escape(&serial),
        json_escape(&codename),
        json_escape(&manufacturer),
        json_escape(&product),
        json_escape(&system_version),
        json_escape(&android_version),
        json_escape(&slot),
        json_escape(&unlock_state)
    );
    0
}

/// 收尾：请**自研** mux server 干净退出（host:kill 释放 5037 与设备句柄）。总是返回 0（best-effort）。
///
/// 端口上若是外来 adb server（投屏期间我们是借道用的它，见
/// [`crate::adb_mux_server::ensure_server_running`]），绝不能 kill：那是别人的 server，
/// 杀了会连带打断对方正在跑的会话，而我们本来也没占它的资源。
pub fn run_cleanup() -> i32 {
    use crate::adb_mux_client::AdbServerOnPort;
    if crate::adb_mux_client::classify_server_confirmed() == AdbServerOnPort::RmfMux {
        crate::adb_mux_client::kill_server();
    }
    0
}

/// 经 mux 读 `getprop`。首条 shell 触发 server 惰性建 hub，窗口内可能失败一次，稍候重试；
/// capture_shell 无直连回退，绝不抢设备句柄。返回 `None` = 两次都没拿到像样的 getprop 输出。
fn read_props(serial: &str) -> Option<String> {
    crate::adb_mux_client::capture_shell(Some(serial), "getprop")
        .or_else(|| {
            std::thread::sleep(Duration::from_millis(300));
            crate::adb_mux_client::capture_shell(Some(serial), "getprop")
        })
        .filter(|out| looks_like_getprop(out))
}

/// `getprop` 全量输出至少有一行 `[key]: [value]`。空串 / 只有报错文本都不算应答——
/// 停在 fastboot 的设备根本没有 adbd，shell 只会失败或回空。
fn looks_like_getprop(output: &str) -> bool {
    output
        .lines()
        .any(|line| line.trim_start().starts_with('[') && line.contains("]: ["))
}

/// 当前是否插着 fastboot / fastbootd 态的设备（与 `fastboot devices` 同一枚举）。
fn fastboot_device_present() -> bool {
    crate::usb_transport::UsbTransport::enumerate_devices().is_ok_and(|list| !list.is_empty())
}

/// 按最小间隔节流一个探测：间隔未到时沿用上一次结果，不重新探。
struct Throttle {
    min_gap: Duration,
    last_at: Option<Instant>,
    last_result: bool,
}

impl Throttle {
    fn new(min_gap: Duration) -> Self {
        Self {
            min_gap,
            last_at: None,
            last_result: false,
        }
    }

    fn run(&mut self, probe: impl FnOnce() -> bool) -> bool {
        let due = self.last_at.is_none_or(|at| at.elapsed() >= self.min_gap);
        if due {
            self.last_result = probe();
            self.last_at = Some(Instant::now());
        }
        self.last_result
    }
}

/// 取第一台处于 device/recovery（可投屏）状态的设备。
fn first_ready_device(list: &str) -> Option<(String, String)> {
    for line in list.lines() {
        let mut it = line.split_whitespace();
        let serial = it.next().unwrap_or("");
        let state = it.next().unwrap_or("");
        if serial.is_empty() {
            continue;
        }
        if state == "device" || state == "recovery" {
            return Some((serial.to_string(), state.to_string()));
        }
    }
    None
}

/// 重新经 mux 枚举一次，看 `serial` 此刻是否报 unauthorized。
fn device_now_unauthorized(serial: &str) -> bool {
    crate::adb_mux_client::devices(false)
        .is_some_and(|list| device_state_in(&list, serial) == Some("unauthorized"))
}

/// 从 `adb devices` 线上文本里取某台设备的状态列。
fn device_state_in<'a>(list: &'a str, serial: &str) -> Option<&'a str> {
    list.lines().find_map(|line| {
        let mut it = line.split_whitespace();
        (it.next()? == serial).then(|| it.next().unwrap_or(""))
    })
}

/// 取第一台任意状态设备（用于向用户反馈 unauthorized/offline 等）。
fn first_any_device(list: &str) -> Option<(String, String)> {
    for line in list.lines() {
        let mut it = line.split_whitespace();
        let serial = it.next().unwrap_or("");
        if serial.is_empty() {
            continue;
        }
        let state = it.next().unwrap_or("").to_string();
        return Some((serial.to_string(), state));
    }
    None
}

/// 从 `getprop` 输出（每行 `[key]: [value]`）里按优先级取第一个非空值。
fn pick_prop(props: &str, keys: &[&str]) -> Option<String> {
    for key in keys {
        let needle = format!("[{}]: [", key);
        for line in props.lines() {
            if let Some(rest) = line.trim().strip_prefix(&needle) {
                if let Some(val) = rest.strip_suffix(']') {
                    let v = val.trim();
                    if !v.is_empty() {
                        return Some(v.to_string());
                    }
                }
            }
        }
    }
    None
}

fn unlock_state_from_props(props: &str) -> Option<String> {
    let flash_locked = pick_prop(props, &["ro.boot.flash.locked"]);
    match flash_locked.as_deref().map(str::trim) {
        Some("0") => return Some("已解锁".to_string()),
        Some("1") => return Some("未解锁".to_string()),
        _ => {}
    }

    let device_state = pick_prop(props, &["ro.boot.vbmeta.device_state"]);
    match device_state
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
    {
        Some(state) if state == "unlocked" => return Some("已解锁".to_string()),
        Some(state) if state == "locked" => return Some("未解锁".to_string()),
        _ => {}
    }

    let verified = pick_prop(props, &["ro.boot.verifiedbootstate"]);
    match verified.as_deref().map(|s| s.trim().to_ascii_lowercase()) {
        Some(state) if state == "orange" => Some("已解锁".to_string()),
        Some(state) if state == "green" => Some("未解锁".to_string()),
        _ => None,
    }
}

/// 最小 JSON 字符串转义（设备型号可能含特殊字符）。
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' | '\r' | '\t' => out.push(' '),
            c if (c as u32) < 0x20 => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        device_state_in, looks_like_getprop, pick_prop, unlock_state_from_props, Throttle,
    };
    use std::time::Duration;

    /// getprop 失败后要按设备那一行的状态列判断是否在等授权：取的必须是**指定序列号**那一行，
    /// 别被同一列表里的其它设备带偏。
    #[test]
    fn device_state_is_read_from_the_matching_serial_line() {
        let list = "OTHER\tdevice\na7ab3ab5\tunauthorized\n";
        assert_eq!(device_state_in(list, "a7ab3ab5"), Some("unauthorized"));
        assert_eq!(device_state_in(list, "OTHER"), Some("device"));
        assert_eq!(device_state_in(list, "missing"), None);
        // 序列号只做整词匹配，前缀相同的另一台设备不能冒名
        assert_eq!(
            device_state_in("a7ab3ab5x\tunauthorized\n", "a7ab3ab5"),
            None
        );
    }

    /// 投屏只在 ADB 模式支持：prep 判就绪必须看 getprop 真有应答，不能只信 mux 枚举的 `device`。
    /// 停在 fastboot 的设备漏进 adb 列表时 shell 回空或只回报错，此处必须判「没应答」。
    #[test]
    fn getprop_reply_must_contain_at_least_one_property_line() {
        assert!(looks_like_getprop("[ro.product.device]: [annibale]\n"));
        assert!(looks_like_getprop(
            "  [ro.build.version.release]: [16]\r\n[ro.boot.flash.locked]: [1]"
        ));
        assert!(!looks_like_getprop(""));
        assert!(!looks_like_getprop("error: device offline\n"));
        assert!(!looks_like_getprop("/system/bin/sh: getprop: not found"));
    }

    /// 节流：间隔未到时沿用上次结果、不再探测（fastboot 侧枚举可能开句柄，不能每 500ms 一次）。
    #[test]
    fn throttle_reuses_last_result_within_gap() {
        let mut calls = 0;
        let mut t = Throttle::new(Duration::from_secs(60));
        assert!(t.run(|| {
            calls += 1;
            true
        }));
        assert!(t.run(|| {
            calls += 1;
            false
        }));
        assert_eq!(calls, 1, "间隔内不得重新探测");

        let mut zero_gap = Throttle::new(Duration::ZERO);
        assert!(!zero_gap.run(|| false));
        assert!(zero_gap.run(|| true));
    }

    #[test]
    fn picks_scrcpy_props_and_unlock_state() {
        let props = r#"
[ro.product.manufacturer]: [Xiaomi]
[ro.product.brand]: [Redmi]
[ro.product.device]: [annibale]
[ro.product.marketname]: [REDMI K90]
[ro.mi.os.version.incremental]: [OS3.0.303.0.WPKCNXM]
[ro.build.version.release]: [16]
[ro.boot.flash.locked]: [1]
[ro.boot.vbmeta.device_state]: [locked]
[ro.boot.verifiedbootstate]: [orange]
"#;

        assert_eq!(
            pick_prop(props, &["ro.product.device"]).as_deref(),
            Some("annibale")
        );
        assert_eq!(
            pick_prop(props, &["ro.mi.os.version.incremental"]).as_deref(),
            Some("OS3.0.303.0.WPKCNXM")
        );
        // flash.locked 是最直接的 bootloader 锁状态；verifiedbootstate=orange 只能作为兜底。
        assert_eq!(unlock_state_from_props(props).as_deref(), Some("未解锁"));
    }
}
