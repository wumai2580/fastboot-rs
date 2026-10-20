//! 自研 `adb reverse`：每条反向隧道一个常驻子进程（`--adb-reverser`），在设备侧 `remote`
//! 监听、把连接桥接到本机 `tcp:<port>`。登记表 / 拉起 / 选设备等公共设施见
//! [`crate::adb_tunnel_proc`]。
use crate::adb_tunnel_proc::{
    open_selected_device, resolve_selected_serial, spawn_tunnel_child, write_ready, Registry,
    TunnelRecord,
};
use crate::self_spawn::kill_pid;
use std::env;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

pub const REVERSER_ARG: &str = "--adb-reverser";

/// 登记表：`adb-reverses.tsv`，列序 serial/remote/local/pid（历史格式，与 forward 相反）。
const REGISTRY: Registry = Registry::new("adb-reverses.tsv", true, "reverse");
/// 子进程要完成 ADB 握手才回报就绪，设备未授权时得等用户在手机上点允许，所以给足 180 秒。
const READY_TIMEOUT: Duration = Duration::from_secs(180);

pub fn is_reverser_process() -> bool {
    env::args().any(|arg| arg == REVERSER_ARG)
}

pub fn run_reverser_process() -> ! {
    let mut serial = String::new();
    let mut remote = String::new();
    let mut local = String::new();
    let mut ready_file: Option<PathBuf> = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            REVERSER_ARG => {}
            "--serial" => serial = args.next().unwrap_or_default(),
            "--remote" => remote = args.next().unwrap_or_default(),
            "--local" => local = args.next().unwrap_or_default(),
            "--ready-file" => ready_file = args.next().map(PathBuf::from),
            _ => {}
        }
    }

    let mut ready_sent = false;
    let result = run_reverser(&serial, &remote, &local, |actual_remote| {
        ready_sent = true;
        write_ready(&ready_file, &format!("OK\t{}", actual_remote));
        Ok(())
    });

    let code = match result {
        Ok(()) => 0,
        Err(e) => {
            if !ready_sent {
                write_ready(&ready_file, &format!("ERR\t{}", e));
            }
            eprintln!("adb reverser failed: {}", e);
            1
        }
    };
    std::process::exit(code);
}

pub fn handle_reverse_command(serial: Option<&str>, args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!(
            "usage: adb reverse [--list] [--remove REMOTE] [--remove-all] [--no-rebind] REMOTE LOCAL"
        );
        return 1;
    }

    match args[0].as_str() {
        "--list" | "--list-forward" => {
            list_reverses();
            return 0;
        }
        "--remove-all" => {
            remove_all_reverses(serial);
            return 0;
        }
        "--remove" => {
            let Some(remote) = args.get(1) else {
                eprintln!("adb reverse --remove requires REMOTE");
                return 1;
            };
            return match remove_reverse(serial, remote) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("{}", e);
                    1
                }
            };
        }
        _ => {}
    }

    let mut no_rebind = false;
    let mut position = 0usize;
    while args.get(position).map(String::as_str) == Some("--no-rebind") {
        no_rebind = true;
        position += 1;
    }

    let Some(remote) = args.get(position) else {
        eprintln!("adb reverse requires REMOTE and LOCAL");
        return 1;
    };
    let Some(local) = args.get(position + 1) else {
        eprintln!("adb reverse requires REMOTE and LOCAL");
        return 1;
    };

    match start_reverse(serial, remote, local, no_rebind) {
        Ok(actual_remote) => {
            if remote == "tcp:0" {
                if let Some(port) = actual_remote.strip_prefix("tcp:") {
                    println!("{}", port);
                } else {
                    println!("{}", actual_remote);
                }
            }
            0
        }
        Err(e) => {
            eprintln!("{}", e);
            1
        }
    }
}

fn run_reverser<F>(serial: &str, remote: &str, local: &str, on_ready: F) -> Result<(), String>
where
    F: FnOnce(&str) -> Result<(), String>,
{
    validate_host_tcp_service(local)?;
    if remote.trim().is_empty() {
        return Err("REMOTE must not be empty".to_string());
    }

    let mut dev = open_selected_device(Some(serial))?;
    dev.reverse_bridge_loop(remote, local, on_ready)
}

fn start_reverse(
    serial: Option<&str>,
    remote: &str,
    local: &str,
    no_rebind: bool,
) -> Result<String, String> {
    validate_host_tcp_service(local)?;
    if remote.trim().is_empty() {
        return Err("REMOTE must not be empty".to_string());
    }

    let selected_serial = resolve_selected_serial(serial)?;
    let existing = REGISTRY
        .load()
        .into_iter()
        .find(|record| record.serial == selected_serial && record.remote == remote);
    if let Some(record) = existing {
        if no_rebind {
            return Err(format!("{} is already reversed", remote));
        }
        kill_pid(record.pid);
        thread::sleep(Duration::from_millis(120));
        let mut records = REGISTRY.load();
        records.retain(|r| !(r.serial == selected_serial && r.remote == remote));
        REGISTRY.save(&records)?;
    }

    let (child, actual_remote) = spawn_tunnel_child(
        REVERSER_ARG,
        &[
            ("--serial", &selected_serial),
            ("--remote", remote),
            ("--local", local),
        ],
        READY_TIMEOUT,
        "reverse",
    )?;

    let mut records = REGISTRY.load();
    records.retain(|record| !(record.serial == selected_serial && record.remote == actual_remote));
    records.push(TunnelRecord {
        serial: selected_serial,
        remote: actual_remote.clone(),
        local: local.to_string(),
        pid: child.id(),
    });
    REGISTRY.save(&records)?;
    Ok(actual_remote)
}

fn list_reverses() {
    for record in REGISTRY.load() {
        println!("{} {} {}", record.serial, record.remote, record.local);
    }
}

fn remove_reverse(serial: Option<&str>, remote: &str) -> Result<(), String> {
    let mut records = REGISTRY.load();
    let matches: Vec<TunnelRecord> = records
        .iter()
        .filter(|record| {
            record.remote == remote && serial.map(|s| s == record.serial).unwrap_or(true)
        })
        .cloned()
        .collect();

    if matches.is_empty() {
        return Err(format!("{} is not reversed", remote));
    }
    if serial.is_none() && matches.len() > 1 {
        return Err(format!(
            "More than one reverse uses {}; use -s <serial>",
            remote
        ));
    }

    for record in &matches {
        kill_pid(record.pid);
    }
    thread::sleep(Duration::from_millis(120));
    records.retain(|record| {
        !matches
            .iter()
            .any(|m| m.serial == record.serial && m.remote == record.remote && m.pid == record.pid)
    });
    REGISTRY.save(&records)
}

fn remove_all_reverses(serial: Option<&str>) {
    let mut records = REGISTRY.load();
    for record in records
        .iter()
        .filter(|record| serial.map(|s| s == record.serial).unwrap_or(true))
    {
        kill_pid(record.pid);
    }
    records.retain(|record| serial.map(|s| s != record.serial).unwrap_or(false));
    let _ = REGISTRY.save(&records);
}

fn validate_host_tcp_service(local: &str) -> Result<u16, String> {
    let Some(port) = local.strip_prefix("tcp:") else {
        return Err(format!(
            "native adb reverse currently supports only host local tcp:<port>, got {}",
            local
        ));
    };
    if port.is_empty() {
        return Err("reverse local tcp port must not be empty".to_string());
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("invalid reverse local tcp port: {}", port))?;
    if port == 0 {
        return Err("reverse local tcp port must not be 0".to_string());
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_host_tcp_service_accepts_port() {
        assert_eq!(validate_host_tcp_service("tcp:8080").unwrap(), 8080);
    }

    #[test]
    fn validate_host_tcp_service_rejects_auto_port() {
        assert!(validate_host_tcp_service("tcp:0").is_err());
    }

    #[test]
    fn validate_host_tcp_service_rejects_unsupported_local() {
        assert!(validate_host_tcp_service("localabstract:test").is_err());
    }
}
