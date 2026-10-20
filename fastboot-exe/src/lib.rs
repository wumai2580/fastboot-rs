//! 项目内 ADB / Fastboot 协议栈。
//!
//! 对外入口：
//! - [`embed`]：GUI 进程内调用的同步 API（`rm-flash-logic::selfdev` 把 adb/fastboot 命令路由到这里）；
//! - [`cli_main`]：`fastboot` 二进制（出货为 `adb.exe` / `fastboot.exe` / `rmf-cli.exe`）的进程入口，
//!   `src/main.rs` 只是调用它的薄壳。
//! - [`response_text`]：无副作用的操作响应展示格式，供 CLI 与 GUI 共用。
//!
//! 其余模块一律私有，未被这些入口触达的代码会被编译器直接报成死代码。
//!
//! 只支持 Windows：设备传输全部建立在 WinUSB / SetupDi / cfgmgr32 之上，没有别的平台后端。

#[cfg(not(windows))]
compile_error!("fastboot 协议栈只支持 Windows（WinUSB 传输），没有其他平台后端");

mod adb_daemon;
mod adb_forwarder;
mod adb_host_proto;
mod adb_install;
mod adb_mux;
mod adb_mux_client;
mod adb_mux_server;
mod adb_protocol;
mod adb_reverser;
mod adb_router;
mod adb_server;
mod adb_sync;
mod adb_tcp_transport;
mod adb_tunnel_proc;
mod adb_winusb_transport;
mod cli;
pub mod cli_main;
mod crypto;
mod driver;
pub mod embed;
mod error;
mod flash;
mod logger;
mod partition;
mod progress;
mod protocol;
pub mod response_text;
mod scrcpy_prep;
mod self_spawn;
mod sparse;
mod transport;
mod transport_open;
mod usb_iface;
mod usb_transport;
