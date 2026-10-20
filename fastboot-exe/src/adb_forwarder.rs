//! 自研 `adb forward`：每条转发一个常驻子进程（`--adb-forwarder`），在本机监听 `tcp:<port>`，
//! 每个入站连接各开一条到设备 `remote` 的流。登记表 / 拉起 / 选设备等公共设施见
//! [`crate::adb_tunnel_proc`]。
use crate::adb_tunnel_proc::{
    open_selected_device, resolve_selected_serial, spawn_tunnel_child, write_ready, Registry,
    TunnelRecord,
};
use crate::self_spawn::kill_pid;
use std::env;
use std::net::TcpListener;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

pub const FORWARDER_ARG: &str = "--adb-forwarder";

/// 登记表：`adb-forwards.tsv`，列序 serial/local/remote/pid。
const REGISTRY: Registry = Registry::new("adb-forwards.tsv", false, "forward");
/// 子进程只需绑端口 + 连一次设备，5 秒内没回报就是起不来了。
const READY_TIMEOUT: Duration = Duration::from_secs(5);
pub fn is_forwarder_process() -> bool {
    env::args().any(|arg| arg == FORWARDER_ARG)
}

pub fn run_forwarder_process() -> ! {
    let mut serial = String::new();
    let mut local = String::new();
    let mut remote = String::new();
    let mut ready_file: Option<PathBuf> = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            FORWARDER_ARG => {}
            "--serial" => serial = args.next().unwrap_or_default(),
            "--local" => local = args.next().unwrap_or_default(),
            "--remote" => remote = args.next().unwrap_or_default(),
            "--ready-file" => ready_file = args.next().map(PathBuf::from),
            _ => {}
        }
    }

    let code = match run_forwarder(&serial, &local, &remote, ready_file) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("adb forwarder failed: {}", e);
            1
        }
    };
    std::process::exit(code);
}

pub fn handle_forward_command(serial: Option<&str>, args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: adb forward [--list] [--remove LOCAL] [--remove-all] [--no-rebind] LOCAL REMOTE");
        return 1;
    }

    match args[0].as_str() {
        "--list" | "--list-forward" => {
            list_forwards();
            return 0;
        }
        "--remove-all" => {
            remove_all_forwards();
            return 0;
        }
        "--remove" => {
            let Some(local) = args.get(1) else {
                eprintln!("adb forward --remove requires LOCAL");
                return 1;
            };
            return match remove_forward(local) {
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

    let Some(local) = args.get(position) else {
        eprintln!("adb forward requires LOCAL and REMOTE");
        return 1;
    };
    let Some(remote) = args.get(position + 1) else {
        eprintln!("adb forward requires LOCAL and REMOTE");
        return 1;
    };

    match start_forward(serial, local, remote, no_rebind) {
        Ok(actual_local) => {
            if local == "tcp:0" {
                if let Some(port) = actual_local.strip_prefix("tcp:") {
                    println!("{}", port);
                } else {
                    println!("{}", actual_local);
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

fn run_forwarder(
    serial: &str,
    local: &str,
    remote: &str,
    ready_file: Option<PathBuf>,
) -> Result<(), String> {
    let port = parse_local_tcp_port(local)?;
    if remote.trim().is_empty() {
        write_ready(&ready_file, "ERR\tREMOTE must not be empty");
        return Err("REMOTE must not be empty".to_string());
    }

    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(listener) => listener,
        Err(e) => {
            let msg = format!("failed to bind {}: {}", local, e);
            write_ready(&ready_file, &format!("ERR\t{}", msg));
            return Err(msg);
        }
    };
    let actual_port = listener
        .local_addr()
        .map_err(|e| format!("failed to read local listener address: {}", e))?
        .port();
    let actual_local = format!("tcp:{}", actual_port);

    if let Err(e) = open_selected_device(Some(serial)).and_then(|mut dev| dev.connect()) {
        let msg = format!("failed to connect ADB device {}: {}", serial, e);
        write_ready(&ready_file, &format!("ERR\t{}", msg));
        return Err(msg);
    }

    write_ready(&ready_file, &format!("OK\t{}", actual_local));

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let serial = serial.to_string();
                let remote = remote.to_string();
                thread::spawn(move || {
                    crate::adb_daemon::ensure_released();
                    let result = open_selected_device(Some(&serial))
                        .and_then(|mut dev| dev.forward_tcp_stream(&remote, stream));
                    if let Err(e) = result {
                        eprintln!("adb forward connection failed: {}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("adb forward accept failed: {}", e);
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    Ok(())
}

fn start_forward(
    serial: Option<&str>,
    local: &str,
    remote: &str,
    no_rebind: bool,
) -> Result<String, String> {
    parse_local_tcp_port(local)?;
    if remote.trim().is_empty() {
        return Err("REMOTE must not be empty".to_string());
    }

    let selected_serial = resolve_selected_serial(serial)?;
    let mut records = REGISTRY.load();
    if records.iter().any(|record| record.local == local) {
        if no_rebind {
            return Err(format!("{} is already forwarded", local));
        }
        remove_forward(local)?;
        records = REGISTRY.load();
    }

    let (child, actual_local) = spawn_tunnel_child(
        FORWARDER_ARG,
        &[
            ("--serial", &selected_serial),
            ("--local", local),
            ("--remote", remote),
        ],
        READY_TIMEOUT,
        "forward",
    )?;

    records.retain(|record| record.local != actual_local);
    records.push(TunnelRecord {
        serial: selected_serial,
        local: actual_local.clone(),
        remote: remote.to_string(),
        pid: child.id(),
    });
    REGISTRY.save(&records)?;
    Ok(actual_local)
}

fn list_forwards() {
    for record in REGISTRY.load() {
        println!("{} {} {}", record.serial, record.local, record.remote);
    }
}

fn remove_forward(local: &str) -> Result<(), String> {
    let mut records = REGISTRY.load();
    let mut removed = Vec::new();
    records.retain(|record| {
        if record.local == local {
            removed.push(record.clone());
            false
        } else {
            true
        }
    });

    if removed.is_empty() {
        return Err(format!("{} is not forwarded", local));
    }

    for record in removed {
        kill_pid(record.pid);
    }
    REGISTRY.save(&records)
}

fn remove_all_forwards() {
    for record in REGISTRY.load() {
        kill_pid(record.pid);
    }
    let _ = REGISTRY.save(&[]);
}

fn parse_local_tcp_port(local: &str) -> Result<u16, String> {
    let Some(port) = local.strip_prefix("tcp:") else {
        return Err(format!(
            "native adb forward currently supports only local tcp:<port>, got {}",
            local
        ));
    };
    if port.is_empty() {
        return Err("tcp forward port must not be empty".to_string());
    }
    port.parse::<u16>()
        .map_err(|_| format!("invalid tcp forward port: {}", port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_local_tcp_port_accepts_normal_port() {
        assert_eq!(parse_local_tcp_port("tcp:8080").unwrap(), 8080);
    }

    #[test]
    fn parse_local_tcp_port_accepts_auto_port() {
        assert_eq!(parse_local_tcp_port("tcp:0").unwrap(), 0);
    }

    #[test]
    fn parse_local_tcp_port_rejects_unsupported_local() {
        assert!(parse_local_tcp_port("localabstract:test").is_err());
    }
}
