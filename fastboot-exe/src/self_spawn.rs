//! 以本 exe 拉起常驻子角色（`--adb-server` / `--adb-server-mux` / `--adb-forwarder` /
//! `--adb-reverser`）的唯一入口。`--adb-daemon` 例外：它要 `bInheritHandles=FALSE`，
//! 只能直接调 `CreateProcessW`（见 `adb_daemon::spawn_daemon`）。

use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};

const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
pub(crate) const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// 构造「本 exe + 角色参数」的命令：脱离控制台、无窗口、独立进程组，调用方退出后继续存活。
/// stdio 必须全接 null：常驻子进程若继承调用方的管道句柄，会一直占着写端，调用方
/// `ReadToEnd` / `WaitAll` 永远等不到 EOF（曾致投屏失效的管道死锁）。
pub(crate) fn detached_self(role_arg: &str) -> Result<Command, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("failed to locate current executable: {}", e))?;
    let mut command = Command::new(exe);
    command
        .arg(role_arg)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    Ok(command)
}

/// 结束一个子角色进程（连同其子孙）。
pub(crate) fn kill_pid(pid: u32) {
    let _ = Command::new("taskkill")
        .arg("/PID")
        .arg(pid.to_string())
        .arg("/F")
        .arg("/T")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status();
}
