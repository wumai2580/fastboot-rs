//! `fastboot` 二进制的全部实现：出货为 `adb.exe` / `fastboot.exe` / `rmf-cli.exe` 的同一份 CLI。
//!
//! 进程角色按启动标志分派（见 [`main`]）：`--adb-forwarder` / `--adb-reverser` / `--adb-server-mux` /
//! `--adb-server` / `--adb-daemon` 是常驻服务进程，永不返回；其余按 adb 命令行（`adb_router`）或
//! fastboot 命令行（clap `Cli`）处理。放在库内而不是 `main.rs`，是为了让 bin 只做薄壳、与 GUI 进程内
//! 入口（`embed`）共用同一次编译的协议模块——此前 `main.rs` 自己再声明一整套 `mod`，同一份源码按两个
//! crate root 各编译一遍，两侧都只能靠整屏 `allow(dead_code)` 静音。

use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::io::Write;
use std::path::Path;

use clap::Parser;

use crate::cli::{Cli, Commands};
use crate::error::FastbootError;
use crate::flash::ImageSource;
use crate::progress::{format_size, print_error, print_info, print_success, Spinner};
use crate::transport_open::open_transport;
use crate::usb_transport::UsbTransport;
use crate::{
    adb_daemon, adb_forwarder, adb_mux_server, adb_reverser, adb_router, adb_server, driver, embed,
    flash, logger, partition, progress, protocol, sparse,
};

/// `fastboot flash <分区> <镜像>` 之后不接受任何尾随参数。旧版支持的
/// `patch <模块.ko> [kmi <KMI>]`（刷写前 KernelSU 修补）已移除，给出明确提示而不是静默忽略。
fn reject_flash_extra_args(extra: &[String]) -> Result<(), FastbootError> {
    match extra.first().map(String::as_str) {
        None => Ok(()),
        Some("patch") => Err(FastbootError::InvalidArg(
            "此版本已移除 KernelSU patch 功能（仅保留纯刷写）".into(),
        )),
        Some(_) => Err(FastbootError::InvalidArg(
            "尾随参数无效；语法应为：fastboot flash <分区> <镜像>".into(),
        )),
    }
}

/// 全局标志中带独立值的（值可能与子命令同形，须跳过不当子命令看）：`-s <serial>`、`--serial <serial>`、`--slot <slot>`。
/// `--serial=X`/`-sX` 等自含值写法无需跳过。
fn cli_flag_takes_value(flag: &str) -> bool {
    matches!(flag, "-s" | "--serial" | "--slot")
}

/// 指令大小写不敏感：仅把首个「子命令 token」小写化（DEVICES / Reboot / 大写别名 R‧SH 均可执行），
/// 其后的自由参数（路径/分区名/shell 内容/oem 参数等）与所有 flag 一律原样保留，交给 clap。
fn normalize_cli_args(
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Vec<std::ffi::OsString> {
    let mut out: Vec<std::ffi::OsString> = Vec::new();
    let mut skip_value = false;
    let mut subcommand_seen = false;
    for (i, arg) in args.into_iter().enumerate() {
        if i == 0 || subcommand_seen {
            out.push(arg);
            continue;
        }
        if skip_value {
            skip_value = false;
            out.push(arg);
            continue;
        }
        let text = arg.to_string_lossy();
        if text.starts_with('-') {
            if cli_flag_takes_value(&text) {
                skip_value = true;
            }
            out.push(arg);
            continue;
        }
        // 首个非标志 token 即子命令：只有它做小写化；中文子命令（截图/锁屏等）小写化为无操作。
        subcommand_seen = true;
        out.push(std::ffi::OsString::from(text.to_lowercase()));
    }
    out
}

/// 进程入口（由 `src/main.rs` 的 `#[tokio::main]` 调用）。
pub async fn main() {
    if adb_forwarder::is_forwarder_process() {
        adb_forwarder::run_forwarder_process();
    }
    if adb_reverser::is_reverser_process() {
        adb_reverser::run_reverser_process();
    }

    // 本进程若被拉起为 mux（单连接多路复用）5037 服务端，则进入监听循环，永不返回。
    // 必须早于 adb_router：否则 `--adb-server-mux` 会被当作未知 adb 命令而 exit(0)。
    if adb_mux_server::is_mux_server_process() {
        adb_mux_server::run_mux_server_process();
    }

    // 本进程若被拉起为经典 5037 ADB host 协议服务端，则进入监听循环，永不返回。
    // 必须早于 adb_router：否则 `--adb-server` 会被当作未知 adb 命令而 exit(0)。
    if adb_server::is_adb_server_process() {
        adb_server::run_adb_server_process();
    }

    // 本进程若被拉起为 ADB 复用守护进程，则进入常驻服务循环，永不返回。
    // 必须早于 adb_router：否则 `--adb-daemon` 会被当作未知 adb 命令而 exit(0)。
    if adb_daemon::is_daemon_process() {
        adb_daemon::run_daemon();
    }

    logger::log_invocation();

    if let Some(exit_code) = adb_router::try_handle_adb_args() {
        std::process::exit(exit_code);
    }

    let cli = match Cli::try_parse_from(normalize_cli_args(std::env::args_os())) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            error.exit()
        }
        Err(error) => {
            print_error(&error.to_string());
            std::process::exit(2);
        }
    };

    if let Err(e) = run(cli).await {
        print_error(&e.to_string());

        if let Some(hint) = e.recovery_hint() {
            crate::progress::print_error(&format!("\n{}", hint));
        }

        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), FastbootError> {
    if cli.json {
        progress::set_machine_readable(true);
    }

    let slot = cli.slot.clone();
    let set_active = cli.set_active.clone();
    let flash_opts = FlashOpts {
        slot: slot.clone(),
        disable_verity: cli.disable_verity,
        disable_verification: cli.disable_verification,
        verbose: cli.verbose,
    };

    match cli.command {
        Commands::Devices { long } => {
            // 到这里说明本进程以 `fastboot` 名字被调用（adb 名字会更早在 try_handle_adb_args 处理掉）。
            // 因此这里应枚举 **fastboot** 设备（bootloader/fastbootd），而非 adb 设备。
            match crate::usb_transport::UsbTransport::enumerate_devices() {
                Ok(list) => {
                    for d in list {
                        println!("{}", fastboot_device_line(&d, long));
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    crate::progress::print_error(&format!("枚举 fastboot 设备失败: {}", e));
                    std::process::exit(1);
                }
            }
        }
        Commands::Getvar { variable } => {
            cmd_getvar(&cli.serial, &variable, cli.verbose).await?;
        }
        Commands::Flash {
            partition,
            filename,
            extra_args,
        } => {
            reject_flash_extra_args(&extra_args)?;
            cmd_flash(&cli.serial, &partition, &filename, &flash_opts).await?;
        }
        Commands::Erase { partition } => {
            cmd_erase(&cli.serial, &partition).await?;
        }
        Commands::Reboot { target } => {
            cmd_reboot(&cli.serial, &target).await?;
        }
        Commands::Flashall { wipe } => {
            cmd_flashall(&cli.serial, wipe, slot.as_deref()).await?;
            finish_flash_all(
                &cli.serial,
                set_active.as_deref(),
                slot.as_deref(),
                cli.skip_reboot,
            )
            .await?;
            return Ok(());
        }
        Commands::Update { filename, wipe } => {
            cmd_update(&cli.serial, &filename, wipe, slot.as_deref()).await?;
            finish_flash_all(
                &cli.serial,
                set_active.as_deref(),
                slot.as_deref(),
                cli.skip_reboot,
            )
            .await?;
            return Ok(());
        }
        Commands::Upload {
            partition,
            filename,
        } => {
            cmd_upload(&cli.serial, &partition, &filename).await?;
        }
        Commands::Diagnose => {
            cmd_diagnose().await?;
        }
        Commands::Shell { command } => {
            if !command.is_empty() {
                let cmd_string = command.join(" ");
                // 单条 shell 命令优先走常驻 daemon 复用连接；不可用则回退直连。
                if let Some(code) = adb_daemon::run_shell(cli.serial.as_deref(), &cmd_string) {
                    std::process::exit(code);
                }
                let mut dev = match open_adb_device(cli.serial.as_deref()) {
                    Ok(d) => d,
                    Err(e) => {
                        crate::progress::print_error(&format!("{}", e));
                        std::process::exit(1);
                    }
                };
                let mut stdout = std::io::stdout();
                let mut stderr = std::io::stderr();
                let code = match dev.shell_command_streaming(
                    &cmd_string,
                    |b| {
                        let _ = stdout.write_all(b);
                    },
                    |b| {
                        let _ = stderr.write_all(b);
                    },
                ) {
                    Ok(exit) => exit.code,
                    Err(e) => {
                        crate::progress::print_error(&format!("执行失败 {}", e));
                        1
                    }
                };
                let _ = stdout.flush();
                let _ = stderr.flush();
                std::process::exit(code);
            } else {
                // 交互式终端需要 stdin/pty，不能经 daemon；open_adb_device 内部已先 ensure_released。
                let mut dev = match open_adb_device(cli.serial.as_deref()) {
                    Ok(d) => d,
                    Err(e) => {
                        crate::progress::print_error(&format!("{}", e));
                        std::process::exit(1);
                    }
                };
                if let Err(e) = dev.true_pty_shell() {
                    crate::progress::print_error(&format!("终端异常 {}", e));
                }
            }
            std::process::exit(0);
        }
        Commands::Push { local, remote } => {
            let local_str = local.to_str().unwrap_or("");
            let remote_str = remote.as_str();
            let mut dev = match open_adb_device(cli.serial.as_deref()) {
                Ok(d) => d,
                Err(e) => {
                    crate::progress::print_error(&format!("{}", e));
                    std::process::exit(1);
                }
            };
            match dev.push(local_str, remote_str) {
                Ok(_) => {
                    print_success(&format!("{}: 1 file pushed", remote_str));
                    std::process::exit(0);
                }
                Err(e) => {
                    crate::progress::print_error(&format!("Push 失败 {}", e));
                    std::process::exit(1);
                }
            }
        }
        Commands::Pull { remote, local } => {
            let mut dev = match open_adb_device(cli.serial.as_deref()) {
                Ok(d) => d,
                Err(e) => {
                    crate::progress::print_error(&format!("{}", e));
                    std::process::exit(1);
                }
            };
            let local_path = local.to_string_lossy().to_string();

            let final_path = if local_path.is_empty() {
                let path = std::path::Path::new(&remote);
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string()
            } else {
                local_path
            };

            let final_path = if final_path.is_empty() {
                "pulled_file.bin".to_string()
            } else {
                final_path
            };

            match dev.pull(&remote, &final_path) {
                Ok(_) => {
                    print_success(&format!("文件已保存至 {}", final_path));
                    std::process::exit(0);
                }
                Err(e) => {
                    crate::progress::print_error(&format!("拉取失败 {}", e));
                    std::process::exit(1);
                }
            }
        }
        Commands::Install { apk, replace: _ } => {
            let apk_str = apk.to_str().unwrap_or("");
            let mut dev = match open_adb_device(cli.serial.as_deref()) {
                Ok(d) => d,
                Err(e) => {
                    crate::progress::print_error(&format!("{}", e));
                    std::process::exit(1);
                }
            };
            match dev.install(apk_str) {
                Ok(_) => print_success("安装成功"),
                Err(e) => {
                    crate::progress::print_error(&format!("安装失败 {}", e));
                    std::process::exit(1);
                }
            }
            std::process::exit(0);
        }
        Commands::InstallMultiple { apks, replace } => {
            let apk_strs: Vec<String> = apks
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect();
            let mut dev = match open_adb_device(cli.serial.as_deref()) {
                Ok(d) => d,
                Err(e) => {
                    crate::progress::print_error(&format!("{}", e));
                    std::process::exit(1);
                }
            };
            match dev.install_multiple(&apk_strs, replace) {
                Ok(_) => print_success("安装成功"),
                Err(e) => {
                    crate::progress::print_error(&format!("安装失败 {}", e));
                    std::process::exit(1);
                }
            }
            std::process::exit(0);
        }
        Commands::Uninstall { package } => {
            cmd_adb_uninstall(&cli.serial, &package).await?;
        }
        Commands::Packages {
            third_party,
            system,
        } => {
            cmd_adb_packages(&cli.serial, third_party, system).await?;
        }
        Commands::Logcat { filter } => {
            let mut dev = match open_adb_device(cli.serial.as_deref()) {
                Ok(d) => d,
                Err(e) => {
                    crate::progress::print_error(&format!("{}", e));
                    std::process::exit(1);
                }
            };
            let mut grep_keyword = None;
            if !filter.is_empty() {
                let clean_args: Vec<String> = filter
                    .into_iter()
                    .filter(|s| s != "-s" && s != "--grep")
                    .collect();

                if !clean_args.is_empty() {
                    grep_keyword = Some(clean_args[0].clone());
                }
            }

            if let Err(e) = dev.logcat(grep_keyword.as_deref()) {
                crate::progress::print_error(&format!("{}", e));
            }
            std::process::exit(0);
        }
        Commands::Screencap { output } => {
            let output_str = output.to_str().unwrap_or("screencap.png");
            match open_adb_device(cli.serial.as_deref()) {
                Ok(mut dev) => {
                    if let Err(e) = dev.screencap(output_str) {
                        crate::progress::print_error(&format!("截图流拉取失败 {}", e));
                    }
                }
                Err(e) => print_error(&e.to_string()),
            }
            std::process::exit(0);
        }
        Commands::Jietu => {
            let filename = "screenshot.png".to_string();
            if let Ok(mut dev) = open_adb_device(cli.serial.as_deref()) {
                let _ = dev.screencap(&filename);
            }
            std::process::exit(0);
        }
        Commands::VolUp | Commands::VolDown | Commands::LockScreen => {
            let keycode = match cli.command {
                Commands::VolUp => "24",
                Commands::VolDown => "25",
                Commands::LockScreen => "26",
                _ => unreachable!(),
            };
            if let Ok(mut dev) = open_adb_device(cli.serial.as_deref()) {
                let shell_cmd = format!("input keyevent {}", keycode);
                match dev.shell_command(&shell_cmd) {
                    Ok(_) => print_success("底层按键宏执行成功"),
                    Err(e) => print_error(&format!("执行失败 {}", e)),
                }
            } else {
                crate::progress::print_error(&format!("未检测到处于 ADB 模式的设备"));
            }
            std::process::exit(0);
        }
        Commands::Custom { cmd } => match cmd.as_str() {
            "截图" => {
                let filename = "screenshot.png".to_string();
                if let Ok(mut dev) = open_adb_device(cli.serial.as_deref()) {
                    let _ = dev.screencap(&filename);
                }
                std::process::exit(0);
            }
            "音量加" | "音量减" | "锁屏" | "亮屏" => {
                let keycode = match cmd.as_str() {
                    "音量加" => "24",
                    "音量减" => "25",
                    "锁屏" | "亮屏" => "26",
                    _ => "",
                };
                if let Ok(mut dev) = open_adb_device(cli.serial.as_deref()) {
                    let shell_cmd = format!("input keyevent {}", keycode);
                    match dev.shell_command(&shell_cmd) {
                        Ok(_) => print_success(&format!("{} 执行成功", cmd)),
                        Err(e) => print_error(&format!("执行失败 {}", e)),
                    }
                } else {
                    crate::progress::print_error(&format!("未检测到处于 ADB 模式的设备"));
                }
                std::process::exit(0);
            }
            _ => {
                crate::progress::print_error(&format!("未知的中文指令 {}", cmd));
                std::process::exit(1);
            }
        },
        Commands::Screenrecord { output, time } => {
            cmd_adb_screenrecord(&cli.serial, &output, time).await?;
        }
        Commands::SetActive { slot } => {
            cmd_set_active(&cli.serial, &slot).await?;
        }
        Commands::Root => {
            match open_adb_device(cli.serial.as_deref()) {
                Ok(mut dev) => {
                    let _ = dev.root();
                    print_info("请等待 3-5 秒 让设备重新连接到电脑");
                }
                Err(e) => {
                    crate::progress::print_error(&format!("{}", e));
                    std::process::exit(1);
                }
            }
            std::process::exit(0);
        }
        Commands::Unroot => {
            match open_adb_device(cli.serial.as_deref()) {
                Ok(mut dev) => {
                    let _ = dev.unroot();
                    print_info("请等待 3-5 秒 让设备重新连接到电脑");
                }
                Err(e) => {
                    crate::progress::print_error(&format!("{}", e));
                    std::process::exit(1);
                }
            }
            std::process::exit(0);
        }
        Commands::Oem { command } => {
            cmd_oem(&cli.serial, &command).await?;
        }
        Commands::Raw { command } => {
            cmd_raw(&cli.serial, &command).await?;
        }
        Commands::Flashing { operation } => {
            cmd_flashing(&cli.serial, &operation).await?;
        }
        Commands::Format {
            partition,
            fs_type,
            size,
        } => {
            cmd_format(&cli.serial, &partition, fs_type.as_deref(), size.as_deref()).await?;
        }
        Commands::Boot { kernel, ramdisk } => {
            cmd_boot(&cli.serial, &kernel, ramdisk.as_deref()).await?;
        }
        Commands::Fetch { partition, output } => {
            cmd_upload(&cli.serial, &partition, &output).await?;
        }
        Commands::CreateLogicalPartition { name, size } => {
            cmd_create_logical_partition(&cli.serial, &name, size).await?;
        }
        Commands::DeleteLogicalPartition { name } => {
            cmd_delete_logical_partition(&cli.serial, &name).await?;
        }
        Commands::ResizeLogicalPartition { name, size } => {
            cmd_resize_logical_partition(&cli.serial, &name, size).await?;
        }
        Commands::SnapshotUpdate { operation } => {
            cmd_snapshot_update(&cli.serial, &operation).await?;
        }
        Commands::Gsi { operation } => {
            cmd_gsi(&cli.serial, &operation).await?;
        }
        Commands::WipeSuper { super_empty } => {
            cmd_wipe_super(&cli.serial, super_empty.as_deref(), slot.as_deref()).await?;
        }
        Commands::UpdateSuper { image, wipe } => {
            cmd_update_super(&cli.serial, &image, wipe, slot.as_deref()).await?;
        }
        Commands::Stage { input } => {
            cmd_stage(&cli.serial, &input).await?;
        }
        Commands::GetStaged { output } => {
            cmd_get_staged(&cli.serial, &output).await?;
        }
        Commands::Continue => {
            cmd_continue(&cli.serial).await?;
        }
        Commands::Wipe => {
            cmd_wipe(&cli.serial).await?;
        }
    }

    if let Some(target) = set_active.as_deref() {
        let target = set_active_target(target, slot.as_deref())?;
        cmd_set_active(&cli.serial, &target).await?;
    }

    Ok(())
}

/// CLI 刷写选项（全局标志汇总）。
struct FlashOpts {
    slot: Option<String>,
    disable_verity: bool,
    disable_verification: bool,
    verbose: bool,
}

/// `fastboot devices [-l]` 的一行。`-l` 附带 USB 身份信息（官方是 usb 设备路径，本实现给 VID:PID）。
fn fastboot_device_line(d: &crate::usb_transport::UsbDeviceInfo, long: bool) -> String {
    let mut line = format!("{}\tfastboot", d.serial_number);
    if long {
        line.push_str(&format!(" usb:{:04x}:{:04x}", d.vendor_id, d.product_id));
        if let Some(p) = d.product_name.as_deref().filter(|s| !s.trim().is_empty()) {
            line.push_str(&format!(" product:{}", p.trim().replace(' ', "_")));
        }
    }
    line
}

/// `--set-active[=slot]` 的目标槽：显式值优先，其次 `--slot`（仅 a/b），都没有则报错（官方同样要求可解析出槽位）。
fn set_active_target(explicit: &str, slot: Option<&str>) -> Result<String, FastbootError> {
    let pick = if explicit.trim().is_empty() {
        slot.unwrap_or("").trim()
    } else {
        explicit.trim()
    };
    let norm = pick.trim_start_matches('_').to_ascii_lowercase();
    match norm.as_str() {
        "a" | "b" => Ok(norm),
        "" => Err(FastbootError::InvalidArg(
            "--set-active 需要槽位：用 --set-active=a|b 或同时给 --slot a|b".into(),
        )),
        _ => Err(FastbootError::InvalidArg(format!(
            "--set-active 槽位非法: {pick}（只能是 a 或 b）"
        ))),
    }
}

/// flashall / update 收尾：按需切活动槽，再按官方默认重启（`--skip-reboot` 跳过）。
async fn finish_flash_all(
    serial: &Option<String>,
    set_active: Option<&str>,
    slot: Option<&str>,
    skip_reboot: bool,
) -> Result<(), FastbootError> {
    if let Some(target) = set_active {
        let target = set_active_target(target, slot)?;
        cmd_set_active(serial, &target).await?;
    }
    if skip_reboot {
        return Ok(());
    }
    cmd_reboot(serial, "").await
}

/// `fastboot continue`：结束 fastboot、继续正常启动。
async fn cmd_continue(serial: &Option<String>) -> Result<(), FastbootError> {
    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);
    driver.continue_boot().await?;
    print_success("continue 完成");
    Ok(())
}

/// `fastboot -w`：擦除 userdata + metadata（metadata 可能不存在，best-effort）。
async fn cmd_wipe(serial: &Option<String>) -> Result<(), FastbootError> {
    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);
    print_info("擦除 userdata...");
    driver.erase("userdata").await?;
    print_info("擦除 metadata...");
    let _ = driver.erase("metadata").await;
    print_success("wipe 完成");
    Ok(())
}

/// token/unlock_data 等长变量的值常经多条 INFO 行返回，需收集 INFO 行而非只取 OKAY payload。
fn getvar_returns_info_lines(var: &str) -> bool {
    let v = var.to_ascii_lowercase();
    v == "token" || v.contains("token") || v.contains("unlock")
}

async fn cmd_getvar(
    serial: &Option<String>,
    variable: &str,
    verbose: bool,
) -> Result<(), FastbootError> {
    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);

    if verbose {
        print_info(&format!(
            "连接到设备: {}",
            serial.as_deref().unwrap_or("(auto)")
        ));
    }

    if variable.eq_ignore_ascii_case("all") {
        let vars = driver.get_var_all().await?;
        for var in vars {
            println!("{}", var);
        }
    } else if getvar_returns_info_lines(variable) {
        // token/unlock_data 等长变量经多条 INFO 行返回，get_var 只取 OKAY payload 会丢数据。
        // 忠实还原官方 fastboot 回显：INFO 行逐行 (bootloader) 原样打印，拼接交给
        // parse_fastboot_auth_blob（按行剥 token:/blob: 前缀再拼）。早先额外打一行
        // `var: <join>` 会把每行的 token: 前缀并进值里，读出的 token 与官方不一致。
        let (resp, info) = driver
            .raw_command_with_info(&format!("getvar:{}", variable))
            .await?;
        let okay = match resp {
            protocol::Response::Okay(v) => v,
            protocol::Response::Fail(msg) => return Err(FastbootError::Device(msg)),
            _ => String::new(),
        };
        let lines = embed::info_var_reply_lines(variable, &info, &okay);
        if lines.is_empty() {
            return Err(FastbootError::Device(format!(
                "设备未返回 {} 数据（可能不支持或需 oem get_token）",
                variable
            )));
        }
        for line in &lines {
            println!("(bootloader) {}", line);
        }
    } else {
        let value = driver.get_var(variable).await?;
        println!("{}: {}", variable, value);
    }

    Ok(())
}

/// 给 CLI driver 接上状态回调：把命令 prolog 与设备 INFO 心跳转发到 stderr，GUI 解析后进入
/// writing 阶段并推进进度，不再卡在发送完成的 100%。用于无 steady-tick 进度条的批量刷写流程。
fn attach_cli_status_callbacks(driver: &mut driver::FastbootDriver<UsbTransport>) {
    driver.set_prolog_callback(Box::new(|msg: &str| {
        progress::print_status_stderr(msg);
    }));
    driver.set_info_callback(Box::new(|msg: &str| {
        progress::print_status_stderr(&format!("(bootloader) {}", msg));
    }));
}

/// 为批量刷写的单个分区挂实时进度条：发送阶段按增量推进并展示速率，flash 阶段转发 "Writing 'x'"
/// 与设备 INFO 心跳避免卡 100%。返回的 ProgressBar 由调用方在 download/flash 结束后 finish。
fn setup_live_progress(
    driver: &mut driver::FastbootDriver<UsbTransport>,
    label: &str,
    total: u64,
) -> std::sync::Arc<ProgressBar> {
    let pb = ProgressBar::new(total);
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} {msg} [{bar:30.cyan/blue}] {bytes:>10}/{total_bytes:10} {binary_bytes_per_sec:>11} ({eta})")
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏  "),
    );
    pb.set_message(format!("Sending '{}'", label));

    let pb_arc = std::sync::Arc::new(pb);

    let pb_inc = pb_arc.clone();
    // 进度回调是「增量」语义（见 driver::set_progress_callback），按增量累加而非设定位置。
    driver.set_progress_callback(Box::new(move |delta, _total| {
        pb_inc.inc(delta);
    }));
    // flash 阶段：把 "Writing 'x'" 显示到进度条消息位，设备 INFO 心跳打印到上方，
    // 既给人看实时状态，也让 GUI 解析 stderr 推进 writing 进度。
    let pb_prolog = pb_arc.clone();
    driver.set_prolog_callback(Box::new(move |msg: &str| {
        pb_prolog.println(crate::response_text::format_operation(msg));
        pb_prolog.set_message(msg.to_string());
    }));
    let pb_info = pb_arc.clone();
    driver.set_info_callback(Box::new(move |msg: &str| {
        pb_info.println(crate::response_text::format_status(&format!(
            "(bootloader) {}",
            msg
        )));
    }));

    pb_arc
}

async fn cmd_flash(
    serial: &Option<String>,
    partition: &str,
    filename: &Path,
    opts: &FlashOpts,
) -> Result<(), FastbootError> {
    let verbose = opts.verbose;
    if !filename.exists() {
        return Err(FastbootError::ImageNotFound(filename.display().to_string()));
    }

    let file_size = fs::metadata(filename).map_err(FastbootError::Io)?.len();

    if file_size == 0 {
        return Err(FastbootError::InvalidArg("镜像文件为空".to_string()));
    }

    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);

    // --slot a/b/other/all 与 has-slot/current-slot 共同决定目标分区（与 GUI 路径同一实现）。
    let targets = embed::resolve_slot_targets(&mut driver, partition, opts.slot.as_deref()).await;
    let want_flags = opts.disable_verity || opts.disable_verification;
    let is_sparse_img = sparse::is_sparse_file(filename).unwrap_or(false);
    let raw_size = if is_sparse_img {
        sparse_expanded_size(filename).unwrap_or(file_size)
    } else {
        file_size
    };

    // 闸门用有效上限而非设备自报值：理由见 protocol::effective_download_limit。
    let max_download_size = protocol::effective_download_limit(
        driver
            .get_max_download_size()
            .await
            .unwrap_or(512 * 1024 * 1024),
    );

    if verbose {
        print_info(&format!("文件: {}", filename.display()));
        print_info(&format!("大小: {}", format_size(file_size)));
        print_info(&format!("设备限制: {}", format_size(max_download_size)));
    }

    let is_sparse = is_sparse_img;

    use std::time::Instant;
    let start_time = Instant::now();

    let pb = ProgressBar::new(file_size.saturating_mul(targets.len() as u64));
    pb.enable_steady_tick(std::time::Duration::from_millis(50));
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes:>10}/{total_bytes:10} {binary_bytes_per_sec:>11} ({eta})")
        .unwrap()
        .progress_chars("█▉▊▋▌▍▎▏  "));

    use std::sync::Arc;
    let pb_arc = Arc::new(pb);
    let pb_clone = pb_arc.clone();

    // 进度回调是「增量」语义（见 driver::set_progress_callback），按增量累加而非设定位置。
    driver.set_progress_callback(Box::new(move |delta, _total| {
        pb_clone.inc(delta);
    }));

    // flash 阶段把 "Writing 'x'" 与设备 INFO 心跳通过进度条同步打印到 stderr，
    // GUI 解析 stderr 后进入 writing 阶段并据此推进进度，不再卡在发送完成的 100%。
    let pb_prolog = pb_arc.clone();
    driver.set_prolog_callback(Box::new(move |msg: &str| {
        pb_prolog.println(crate::response_text::format_operation(msg));
    }));
    let pb_info = pb_arc.clone();
    driver.set_info_callback(Box::new(move |msg: &str| {
        pb_info.println(crate::response_text::format_status(&format!(
            "(bootloader) {}",
            msg
        )));
    }));

    let mut out = Ok(());
    for target in &targets {
        out = flash_one_target(
            &mut driver,
            target,
            filename,
            file_size,
            raw_size,
            is_sparse,
            max_download_size,
            want_flags && protocol::is_vbmeta_partition(target),
            opts,
        )
        .await;
        if out.is_err() {
            break;
        }
    }
    if out.is_ok() {
        pb_arc.finish_and_clear();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let elapsed = start_time.elapsed().as_secs_f64();
        print_success(&format!("OKAY [{:>7.3}s]", elapsed));
    } else {
        pb_arc.finish_and_clear();
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    out
}

/// sparse 镜像展开后的真实字节数（逻辑分区 resize 需要它，而不是磁盘上的 sparse 文件大小）。
fn sparse_expanded_size(path: &Path) -> Option<u64> {
    use std::io::Read;
    let mut f = fs::File::open(path).ok()?;
    let mut buf = [0u8; sparse::SPARSE_HEADER_SIZE];
    f.read_exact(&mut buf).ok()?;
    sparse::SparseHeader::from_bytes(&buf)
        .ok()
        .map(|h| h.expanded_size())
        .filter(|&n| n > 0)
}

/// 逻辑（super）分区刷前按镜像展开大小 resize，对齐官方 do_flash。`is-logical` 查不到（bootloader
/// 不支持该变量）按物理分区处理、跳过；resize 失败是设备硬错误，上报。
async fn resize_if_logical(
    driver: &mut driver::FastbootDriver<UsbTransport>,
    partition: &str,
    raw_size: u64,
) -> Result<(), FastbootError> {
    let is_logical = driver
        .get_var(&format!("is-logical:{}", partition))
        .await
        .map(|v| v.trim().eq_ignore_ascii_case("yes"))
        .unwrap_or(false);
    if is_logical && raw_size > 0 {
        driver.resize_partition(partition, raw_size).await?;
    }
    Ok(())
}

/// 刷单个目标分区：逻辑分区先 resize（对齐官方 do_flash），vbmeta 按需改 AVB 标志，超限分片。
#[allow(clippy::too_many_arguments)]
async fn flash_one_target(
    driver: &mut driver::FastbootDriver<UsbTransport>,
    target: &str,
    filename: &Path,
    file_size: u64,
    raw_size: u64,
    is_sparse: bool,
    max_download_size: u64,
    patch_vbmeta: bool,
    opts: &FlashOpts,
) -> Result<(), FastbootError> {
    resize_if_logical(driver, target, raw_size).await?;

    if patch_vbmeta {
        if file_size > max_download_size {
            return Err(FastbootError::InvalidArg(
                "vbmeta 镜像异常过大，无法在设置 disable 标志的同时分片下发".into(),
            ));
        }
        let mut data = fs::read(filename).map_err(FastbootError::Io)?;
        let flags = embed::apply_vbmeta_disable_flags(
            &mut data,
            opts.disable_verity,
            opts.disable_verification,
        )
        .map_err(FastbootError::InvalidArg)?;
        print_info(&format!("vbmeta AVB flags = 0x{:08x}", flags));
        driver.download(&data).await?;
        return driver.flash(target).await;
    }

    if file_size > max_download_size {
        if is_sparse {
            flash_sparse_resparse(driver, target, filename, max_download_size).await
        } else {
            flash_raw_chunked(driver, target, filename, max_download_size).await
        }
    } else {
        flash_single(driver, target, filename, file_size).await
    }
}

async fn flash_sparse_resparse(
    driver: &mut driver::FastbootDriver<UsbTransport>,
    partition: &str,
    filename: &Path,
    max_download_size: u64,
) -> Result<(), FastbootError> {
    use sparse::{CHUNK_HEADER_SIZE, SPARSE_HEADER_MAGIC, SPARSE_HEADER_SIZE};
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    let mut file = File::open(filename).map_err(FastbootError::Io)?;
    let file_len = file.metadata().map_err(FastbootError::Io)?.len();

    // 1. 循环解析：支持“首尾拼接”的巨型 Sparse 镜像
    let mut chunk_metas = Vec::new();
    let mut offset = 0u64;
    let mut global_total_blocks = 0u32;
    let mut global_block_size = 4096u32;

    while offset < file_len {
        file.seek(SeekFrom::Start(offset))
            .map_err(FastbootError::Io)?;
        let mut header_buf = [0u8; SPARSE_HEADER_SIZE];

        // 如果读不到 28 字节，说明已经到文件尾部或全是 padding 00，安全退出解析
        if file.read_exact(&mut header_buf).is_err() {
            break;
        }

        let magic =
            u32::from_le_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]]);
        if magic != SPARSE_HEADER_MAGIC {
            // 遇到非魔数数据，说明拼接的有效 Sparse 块已经全部提取完毕
            break;
        }

        let block_size = u32::from_le_bytes([
            header_buf[12],
            header_buf[13],
            header_buf[14],
            header_buf[15],
        ]);
        global_block_size = block_size;
        let total_blocks = u32::from_le_bytes([
            header_buf[16],
            header_buf[17],
            header_buf[18],
            header_buf[19],
        ]);
        let total_chunks = u32::from_le_bytes([
            header_buf[20],
            header_buf[21],
            header_buf[22],
            header_buf[23],
        ]);

        global_total_blocks += total_blocks;
        offset += SPARSE_HEADER_SIZE as u64;

        // 提取当前 Sparse 片段内的所有 Chunk
        for _ in 0..total_chunks {
            file.seek(SeekFrom::Start(offset))
                .map_err(FastbootError::Io)?;
            let mut ch_buf = [0u8; CHUNK_HEADER_SIZE];
            file.read_exact(&mut ch_buf).map_err(FastbootError::Io)?;

            let ctype = u16::from_le_bytes([ch_buf[0], ch_buf[1]]);
            let cblocks = u32::from_le_bytes([ch_buf[4], ch_buf[5], ch_buf[6], ch_buf[7]]);
            let ctotal_sz = u32::from_le_bytes([ch_buf[8], ch_buf[9], ch_buf[10], ch_buf[11]]);
            let data_sz = ctotal_sz.saturating_sub(CHUNK_HEADER_SIZE as u32);

            chunk_metas.push((ctype, cblocks, data_sz, offset + CHUNK_HEADER_SIZE as u64));
            offset += ctotal_sz as u64;
        }
    }

    if chunk_metas.is_empty() {
        return Err(FastbootError::Protocol(
            "非 Sparse 文件或文件已损坏".to_string(),
        ));
    }

    // 2. 将所有解析出来的 Chunk 合并处理并发包
    let mut absolute_block_offset = 0u32;
    let mut current_chunk_idx = 0;
    let mut chunk_internal_block_offset = 0u32;

    while current_chunk_idx < chunk_metas.len() {
        let mut session_buffer = Vec::new();
        let mut session_blocks = 0u32;
        let mut session_chunks = 0u32;

        session_buffer.resize(SPARSE_HEADER_SIZE, 0);

        // 如果不是第一片，插入 DontCare 块跳过已刷入的物理偏移
        if absolute_block_offset > 0 {
            session_buffer.extend_from_slice(&0xCAC3u16.to_le_bytes());
            session_buffer.extend_from_slice(&0u16.to_le_bytes());
            session_buffer.extend_from_slice(&absolute_block_offset.to_le_bytes());
            session_buffer.extend_from_slice(&(CHUNK_HEADER_SIZE as u32).to_le_bytes());

            session_blocks += absolute_block_offset;
            session_chunks += 1;
        }

        while current_chunk_idx < chunk_metas.len() {
            let (ctype, cblocks, data_sz, data_offset) = chunk_metas[current_chunk_idx];
            let blocks_remaining = cblocks - chunk_internal_block_offset;

            let chunk_header_overhead = CHUNK_HEADER_SIZE as u64;
            let available_payload = max_download_size.saturating_sub(session_buffer.len() as u64);

            if available_payload <= chunk_header_overhead {
                break;
            }

            let available_data_payload = available_payload - chunk_header_overhead;

            if ctype == 0xCAC1 {
                let max_blocks_can_fit = (available_data_payload / global_block_size as u64) as u32;
                if max_blocks_can_fit == 0 {
                    break;
                }

                let blocks_to_take = blocks_remaining.min(max_blocks_can_fit);
                let bytes_to_take = (blocks_to_take as usize) * (global_block_size as usize);

                session_buffer.extend_from_slice(&0xCAC1u16.to_le_bytes());
                session_buffer.extend_from_slice(&0u16.to_le_bytes());
                session_buffer.extend_from_slice(&blocks_to_take.to_le_bytes());
                let total_sz = CHUNK_HEADER_SIZE as u32 + bytes_to_take as u32;
                session_buffer.extend_from_slice(&total_sz.to_le_bytes());

                let physical_offset =
                    data_offset + (chunk_internal_block_offset as u64 * global_block_size as u64);
                file.seek(SeekFrom::Start(physical_offset))
                    .map_err(FastbootError::Io)?;
                let old_len = session_buffer.len();
                session_buffer.resize(old_len + bytes_to_take, 0);
                file.read_exact(&mut session_buffer[old_len..])
                    .map_err(FastbootError::Io)?;

                session_blocks += blocks_to_take;
                session_chunks += 1;
                absolute_block_offset += blocks_to_take;
                chunk_internal_block_offset += blocks_to_take;

                if chunk_internal_block_offset < cblocks {
                    break;
                } else {
                    current_chunk_idx += 1;
                    chunk_internal_block_offset = 0;
                }
            } else {
                let bytes_to_take = data_sz as usize;
                if available_data_payload < bytes_to_take as u64 {
                    break;
                }

                session_buffer.extend_from_slice(&ctype.to_le_bytes());
                session_buffer.extend_from_slice(&0u16.to_le_bytes());
                session_buffer.extend_from_slice(&blocks_remaining.to_le_bytes());
                let total_sz = CHUNK_HEADER_SIZE as u32 + bytes_to_take as u32;
                session_buffer.extend_from_slice(&total_sz.to_le_bytes());

                if bytes_to_take > 0 {
                    file.seek(SeekFrom::Start(data_offset))
                        .map_err(FastbootError::Io)?;
                    let old_len = session_buffer.len();
                    session_buffer.resize(old_len + bytes_to_take, 0);
                    file.read_exact(&mut session_buffer[old_len..])
                        .map_err(FastbootError::Io)?;
                }

                session_blocks += blocks_remaining;
                session_chunks += 1;
                absolute_block_offset += blocks_remaining;

                current_chunk_idx += 1;
                chunk_internal_block_offset = 0;
            }
        }

        if session_chunks == 0 {
            return Err(FastbootError::Protocol(
                "max_download_size 配置过小，无法装入数据包".to_string(),
            ));
        }

        // 补齐尾部
        if current_chunk_idx >= chunk_metas.len() {
            let trailing_blocks = global_total_blocks.saturating_sub(absolute_block_offset);
            if trailing_blocks > 0 {
                session_buffer.extend_from_slice(&0xCAC3u16.to_le_bytes());
                session_buffer.extend_from_slice(&0u16.to_le_bytes());
                session_buffer.extend_from_slice(&trailing_blocks.to_le_bytes());
                session_buffer.extend_from_slice(&(CHUNK_HEADER_SIZE as u32).to_le_bytes());
                session_blocks += trailing_blocks;
                session_chunks += 1;
                absolute_block_offset += trailing_blocks;
            }
        }

        // 组装 Sparse Header
        session_buffer[0..4].copy_from_slice(&SPARSE_HEADER_MAGIC.to_le_bytes());
        session_buffer[4..6].copy_from_slice(&1u16.to_le_bytes());
        session_buffer[6..8].copy_from_slice(&0u16.to_le_bytes());
        session_buffer[8..10].copy_from_slice(&(SPARSE_HEADER_SIZE as u16).to_le_bytes());
        session_buffer[10..12].copy_from_slice(&(CHUNK_HEADER_SIZE as u16).to_le_bytes());
        session_buffer[12..16].copy_from_slice(&global_block_size.to_le_bytes());
        session_buffer[16..20].copy_from_slice(&session_blocks.to_le_bytes());
        session_buffer[20..24].copy_from_slice(&session_chunks.to_le_bytes());
        session_buffer[24..28].copy_from_slice(&0u32.to_le_bytes());

        driver.download(&session_buffer).await?;
        driver.flash(partition).await?;
    }

    Ok(())
}

async fn flash_raw_chunked(
    driver: &mut driver::FastbootDriver<UsbTransport>,
    partition: &str,
    filename: &Path,
    max_download_size: u64,
) -> Result<(), FastbootError> {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    let mut file = File::open(filename).map_err(FastbootError::Io)?;
    let file_len = file.metadata().map_err(FastbootError::Io)?.len();
    let max_payload = max_download_size.saturating_sub(4096);
    let max_data_blocks = max_payload / 4096;
    let mut offset_bytes = 0u64;

    while offset_bytes < file_len {
        let remain = file_len - offset_bytes;
        let chunk_bytes = remain.min(max_data_blocks * 4096);
        let padded_chunk_bytes = chunk_bytes.div_ceil(4096) * 4096;
        let data_blocks = (padded_chunk_bytes / 4096) as u32;
        let offset_blocks = (offset_bytes / 4096) as u32;
        let total_blocks = offset_blocks + data_blocks;
        let total_chunks: u32 = if offset_blocks > 0 { 2 } else { 1 };

        let mut header = Vec::with_capacity(28 + 12 * 2);
        header.extend_from_slice(&0xED26FF3Au32.to_le_bytes());
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&28u16.to_le_bytes());
        header.extend_from_slice(&12u16.to_le_bytes());
        header.extend_from_slice(&4096u32.to_le_bytes());
        header.extend_from_slice(&total_blocks.to_le_bytes());
        header.extend_from_slice(&total_chunks.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());

        if offset_blocks > 0 {
            header.extend_from_slice(&0xCAC3u16.to_le_bytes());
            header.extend_from_slice(&0u16.to_le_bytes());
            header.extend_from_slice(&offset_blocks.to_le_bytes());
            header.extend_from_slice(&12u32.to_le_bytes());
        }

        header.extend_from_slice(&0xCAC1u16.to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&data_blocks.to_le_bytes());
        let chunk_total_size = 12 + padded_chunk_bytes as u32;
        header.extend_from_slice(&chunk_total_size.to_le_bytes());

        file.seek(SeekFrom::Start(offset_bytes))
            .map_err(FastbootError::Io)?;

        let mut chunk_data = Vec::with_capacity(header.len() + padded_chunk_bytes as usize);
        chunk_data.extend_from_slice(&header);

        let mut buffer = vec![0u8; 1024 * 1024];
        let mut bytes_to_read = chunk_bytes;
        while bytes_to_read > 0 {
            let read_len = bytes_to_read.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..read_len])
                .map_err(FastbootError::Io)?;
            chunk_data.extend_from_slice(&buffer[..read_len]);
            bytes_to_read -= read_len as u64;
        }

        if chunk_bytes < padded_chunk_bytes {
            let pad_size = (padded_chunk_bytes - chunk_bytes) as usize;
            chunk_data.resize(chunk_data.len() + pad_size, 0);
        }

        driver.download(&chunk_data).await?;
        driver.flash(partition).await?;

        offset_bytes += chunk_bytes;
    }

    Ok(())
}

/// 不超过单片上限的镜像：整份读入、一次 download + flash（调用方已按
/// [`protocol::effective_download_limit`] 分流，超限镜像走 resparse / raw 分片，不会到这里）。
async fn flash_single(
    driver: &mut driver::FastbootDriver<UsbTransport>,
    partition: &str,
    filename: &Path,
    file_size: u64,
) -> Result<(), FastbootError> {
    let is_json = progress::is_machine_readable();

    if is_json {
        println!(
            r#"{{"type":"start","partition":"{}","size":{}}}"#,
            partition, file_size
        );
    }

    let data = fs::read(filename).map_err(FastbootError::Io)?;

    if is_json {
        println!(
            r#"{{"type":"sending","partition":"{}","size":{}}}"#,
            partition, file_size
        );
    }

    driver.download(&data).await?;
    if is_json {
        println!(r#"{{"type":"writing","partition":"{}"}}"#, partition);
    }
    driver.flash(partition).await?;

    Ok(())
}

async fn cmd_erase(serial: &Option<String>, partition: &str) -> Result<(), FastbootError> {
    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);

    let spinner = Spinner::new(&format!("擦除 '{}'...", partition));

    for _ in 0..10 {
        spinner.tick();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    driver.erase(partition).await?;
    spinner.finish(&format!("擦除 {} 完成", partition));

    Ok(())
}

async fn cmd_format(
    serial: &Option<String>,
    partition: &str,
    fs_type: Option<&str>,
    size: Option<&str>,
) -> Result<(), FastbootError> {
    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);

    // 1) 探测分区文件系统类型（getvar 只读、安全）。命令行 --fs-type 优先于设备上报值。
    let detected_type = match fs_type {
        Some(t) if !t.trim().is_empty() => Some(t.trim().to_string()),
        _ => driver
            .get_var(&format!(
                "{}:{}",
                protocol::FB_VAR_PARTITION_TYPE,
                partition
            ))
            .await
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
    };

    // 2) 探测分区大小（getvar 只读）。命令行 --size 优先。
    let detected_size = match size {
        Some(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
        _ => driver
            .get_var(&format!(
                "{}:{}",
                protocol::FB_VAR_PARTITION_SIZE,
                partition
            ))
            .await
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
    };

    print_info(&format!("格式化分区 '{}'", partition));
    match detected_type {
        Some(ref t) => print_info(&format!("  文件系统类型: {}", t)),
        None => print_info("  文件系统类型: 未知（设备未上报 partition-type）"),
    }
    if let Some(ref s) = detected_size {
        match partition::parse_partition_size(s) {
            Ok(bytes) => print_info(&format!("  分区大小: {} ({})", format_size(bytes), s)),
            Err(_) => print_info(&format!("  分区大小: {}", s)),
        }
    }

    // 3) 用「擦除分区」实现格式化：fastboot 协议无设备端格式化，主机端重写 mkfs 风险高难验证；
    //    ext4/f2fs 数据类分区下次开机由 vold/init 按 fstab 自动重建，效果等价且无变砖风险。
    driver.erase(partition).await?;

    print_success(&format!("分区 '{}' 已格式化（已擦除）", partition));
    if let Some(ref t) = detected_type {
        let tl = t.to_ascii_lowercase();
        if tl.contains("ext4") || tl.contains("f2fs") {
            print_info(&format!("  设备下次开机将自动重建 {} 文件系统", t));
        }
    }

    Ok(())
}

/// CLI reboot 的失败出口：文案口径与 embed 共用 [`protocol::reboot_error_text`]。
fn reboot_cli_error(
    target: &str,
    start: std::time::Instant,
    error: impl std::fmt::Display,
) -> FastbootError {
    FastbootError::Device(protocol::reboot_error_text(
        target,
        start,
        error.to_string(),
    ))
}

async fn cmd_reboot(serial: &Option<String>, target: &str) -> Result<(), FastbootError> {
    let target = protocol::normalize_reboot_target(target);
    let target = target.as_str();

    let start = std::time::Instant::now();
    let target_serial = serial.as_deref();

    // `fastboot reboot` 必须优先按 fastboot 设备处理。部分 bootloader 的 WinUSB 接口会被
    // ADB 枚举探针误收进候选，先走 ADB 会在 WinUsb_Initialize 阶段失败，导致 reboot 没发出。
    let fastboot_devices = UsbTransport::enumerate_devices()
        .map_err(|e| reboot_cli_error(target, start, FastbootError::Transport(e)))?;

    let has_fastboot = fastboot_devices
        .iter()
        .any(|d| target_serial.is_none_or(|s| d.serial_number == s));

    if has_fastboot && !fastboot_devices.is_empty() {
        let transport = open_transport(serial.as_deref())
            .await
            .map_err(|e| reboot_cli_error(target, start, e))?;
        let mut driver = driver::FastbootDriver::new(transport);

        // reboot 一发出链路就断，常在回 OKAY 前掉线（官方 fastboot 对此容忍）：掉线类错误
        // （NoLink/Disconnected）视为重启已触发的成功，与 embed::fb_reboot 保持一致。
        let tolerate = |r: Result<(), FastbootError>| match r {
            Ok(()) => Ok(()),
            Err(FastbootError::Transport(ref e)) if e.is_no_link() => Ok(()),
            Err(e) => Err(e),
        };

        let result = if target.is_empty() {
            tolerate(driver.reboot().await)
        } else {
            tolerate(driver.reboot_to(target).await)
        };
        result.map_err(|e| reboot_cli_error(target, start, e))?;
        print_success(&protocol::reboot_ok_text(target, start));
        return Ok(());
    }

    // 设备处于系统/recovery（ADB 模式）：WinUSB 直连发 reboot。只有没有 fastboot 设备时才走这里。
    let adb_devices = crate::adb_winusb_transport::AdbWinUsbDevice::enumerate().unwrap_or_default();
    let has_adb = adb_devices.iter().any(|d| {
        target_serial
            .is_none_or(|s| crate::adb_winusb_transport::serial_from_path(&d.device_path) == s)
    });

    if has_adb {
        let _ = crate::crypto::get_or_create_keys();
        let mut dev =
            open_adb_device(target_serial).map_err(|e| reboot_cli_error(target, start, e))?;
        dev.reboot(target)
            .map_err(|e| reboot_cli_error(target, start, FastbootError::Adb(e)))?;
        print_success(&protocol::reboot_ok_text(target, start));
        return Ok(());
    }

    Err(reboot_cli_error(target, start, FastbootError::NoDevice))
}

/// flashall/update 的 `--slot`：a/b 直接指定，other 取当前槽的另一侧；all 需逐分区双刷，不支持。
fn flashall_slot(
    slot: Option<&str>,
    current: Option<&str>,
) -> Result<Option<String>, FastbootError> {
    let Some(raw) = slot.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let norm = raw.trim_start_matches('_').to_ascii_lowercase();
    match norm.as_str() {
        "a" | "b" => Ok(Some(norm)),
        "other" => match current.map(|c| c.trim().trim_start_matches('_').to_ascii_lowercase()) {
            Some(c) if c == "a" => Ok(Some("b".into())),
            Some(c) if c == "b" => Ok(Some("a".into())),
            _ => Err(FastbootError::InvalidArg(
                "--slot other 需要设备报告 current-slot（a/b）".into(),
            )),
        },
        "all" => Err(FastbootError::InvalidArg(
            "flashall/update 不支持 --slot all，请分别用 --slot a、--slot b 执行".into(),
        )),
        _ => Err(FastbootError::InvalidArg(format!("非法槽位: {raw}"))),
    }
}

async fn cmd_flashall(
    serial: &Option<String>,
    wipe: bool,
    slot: Option<&str>,
) -> Result<(), FastbootError> {
    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);
    attach_cli_status_callbacks(&mut driver);

    print_info("准备刷写所有分区...");

    if wipe {
        print_info("将同时擦除 userdata 分区");
    }

    // 闸门用有效上限而非设备自报值：理由见 protocol::effective_download_limit。
    let max_download_size = protocol::effective_download_limit(
        driver
            .get_max_download_size()
            .await
            .unwrap_or(512 * 1024 * 1024),
    );

    let vars = driver.get_var_all().await?;
    let mut var_map = std::collections::HashMap::new();
    for var in vars {
        if let Some((key, value)) = var.split_once(':') {
            var_map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    let mut part_mgr = partition::PartitionManager::from_device_vars(&var_map);
    if let Some(s) = flashall_slot(slot, part_mgr.current_slot.as_deref())? {
        part_mgr.current_slot = Some(s);
    }

    print_info(&format!(
        "设备槽位: {}",
        if part_mgr.has_slot {
            format!(
                "A/B (当前: {})",
                part_mgr.current_slot.as_deref().unwrap_or("?")
            )
        } else {
            "单槽位".to_string()
        }
    ));

    let images = partition::get_standard_images();

    let mut found_images = Vec::new();
    for img in &images {
        let path = Path::new(&img.img_name);
        if path.exists() {
            found_images.push(img.clone());
            if !img.optional {
                print_info(&format!("找到: {}", img.img_name));
            }
        } else if !img.optional {
            return Err(FastbootError::ImageNotFound(img.img_name.clone()));
        }
    }

    if found_images.is_empty() {
        return Err(FastbootError::InvalidArg(
            "当前目录没有找到任何镜像文件".to_string(),
        ));
    }

    print_info(&format!("将刷写 {} 个分区", found_images.len()));

    let mut boot_critical: Vec<_> = found_images
        .iter()
        .filter(|i| i.image_type == partition::ImageType::BootCritical)
        .collect();
    let mut normal: Vec<_> = found_images
        .iter()
        .filter(|i| i.image_type == partition::ImageType::Normal)
        .collect();
    let mut extra: Vec<_> = found_images
        .iter()
        .filter(|i| i.image_type == partition::ImageType::Extra)
        .collect();

    let all_images: Vec<_> = boot_critical
        .drain(..)
        .chain(normal.drain(..))
        .chain(extra.drain(..))
        .collect();

    for (i, img) in all_images.iter().enumerate() {
        let part_name = part_mgr.get_partition_name(&img.part_name);
        let path = Path::new(&img.img_name);

        print_info(&format!(
            "\n[{}/{}] 刷写 {} -> {}",
            i + 1,
            all_images.len(),
            img.img_name,
            part_name
        ));

        let file_size = fs::metadata(path).map_err(FastbootError::Io)?.len();
        let raw_size = if sparse::is_sparse_file(path).unwrap_or(false) {
            sparse_expanded_size(path).unwrap_or(file_size)
        } else {
            file_size
        };
        resize_if_logical(&mut driver, &part_name, raw_size).await?;

        if file_size > max_download_size {
            // 超限大镜像（super.img 等）：走与 cmd_flash 相同的分片路径，
            // 不整读内存单次 download（会被设备按 max-download-size 拒绝）。
            let is_sparse = sparse::is_sparse_file(path).unwrap_or(false);
            let pb = setup_live_progress(&mut driver, &part_name, file_size);
            let flashed = if is_sparse {
                flash_sparse_resparse(&mut driver, &part_name, path, max_download_size).await
            } else {
                flash_raw_chunked(&mut driver, &part_name, path, max_download_size).await
            };
            pb.finish_and_clear();
            flashed?;
        } else {
            let data = fs::read(path).map_err(FastbootError::Io)?;
            let pb = setup_live_progress(&mut driver, &part_name, data.len() as u64);

            driver.download(&data).await?;
            driver.flash(&part_name).await?;

            pb.finish_and_clear();
        }
        print_success(&format!(
            "[{}/{}] Writing '{}' ({})                    OKAY",
            i + 1,
            all_images.len(),
            part_name,
            format_size(file_size)
        ));
    }

    if wipe {
        wipe_user_data(&mut driver).await?;
    }

    print_success("\n所有分区刷写完成!");
    Ok(())
}

/// `-w`：擦除 userdata，metadata 可能不存在（best-effort），与官方一致。
async fn wipe_user_data(
    driver: &mut driver::FastbootDriver<UsbTransport>,
) -> Result<(), FastbootError> {
    print_info("\n擦除 userdata...");
    driver.erase("userdata").await?;
    let _ = driver.erase("metadata").await;
    print_success("userdata / metadata 已擦除");
    Ok(())
}

async fn cmd_update(
    serial: &Option<String>,
    filename: &Path,
    wipe: bool,
    slot: Option<&str>,
) -> Result<(), FastbootError> {
    if !filename.exists() {
        return Err(FastbootError::ImageNotFound(filename.display().to_string()));
    }

    print_info(&format!("从 {} 更新...", filename.display()));

    let source = flash::ZipImageSource::from_path(filename).map_err(FastbootError::Io)?;

    // 槽位后缀在连上设备后按 has-slot 逐分区追加（非 A/B 分区如 userdata 不能加），故 plan 不带 slot。
    let plan = flash::FlashingPlan {
        wants_wipe: wipe,
        ..Default::default()
    };
    let tool = flash::FlashAllTool::new(source, plan);

    tool.validate()?;

    let tasks = tool.generate_tasks().map_err(FastbootError::Io)?;

    if tasks.is_empty() {
        return Err(FastbootError::InvalidArg(
            "ZIP 包中没有找到可刷写的镜像".to_string(),
        ));
    }

    print_info(&format!("将刷写 {} 个分区", tasks.len()));

    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);
    attach_cli_status_callbacks(&mut driver);

    // 闸门用有效上限而非设备自报值：理由见 protocol::effective_download_limit。
    let max_download_size = protocol::effective_download_limit(
        driver
            .get_max_download_size()
            .await
            .unwrap_or(512 * 1024 * 1024),
    );

    let current = driver
        .get_var("current-slot")
        .await
        .ok()
        .map(|s| s.trim().to_string());
    let slot = flashall_slot(slot, current.as_deref())?;

    for (i, task) in tasks.iter().enumerate() {
        let partition = match slot.as_deref() {
            Some(s) if !task.partition.ends_with("_a") && !task.partition.ends_with("_b") => {
                let slotted = driver
                    .get_var(&format!("has-slot:{}", task.partition))
                    .await
                    .map(|v| v.trim().eq_ignore_ascii_case("yes"))
                    .unwrap_or(false);
                if slotted {
                    format!("{}_{}", task.partition, s)
                } else {
                    task.partition.clone()
                }
            }
            _ => task.partition.clone(),
        };
        print_info(&format!(
            "\n[{}/{}] 刷写 {} -> {}",
            i + 1,
            tasks.len(),
            task.filename,
            partition
        ));

        let file_size = tool
            .source()
            .file_size(&task.filename)
            .map_err(FastbootError::Io)?;
        let is_sparse = tool.is_sparse(&task.filename).unwrap_or(false);
        let raw_size = if is_sparse {
            tool.source()
                .read_prefix(&task.filename, sparse::SPARSE_HEADER_SIZE)
                .ok()
                .and_then(|b| sparse::SparseHeader::from_bytes(&b).ok())
                .map(|h| h.expanded_size())
                .filter(|&n| n > 0)
                .unwrap_or(file_size)
        } else {
            file_size
        };
        resize_if_logical(&mut driver, &partition, raw_size).await?;

        if file_size > max_download_size {
            // 超限大镜像（zip 内 super.img 等）：物化为文件路径后走与 cmd_flash 相同的
            // 分片路径（sparse resparse / raw 包 sparse 容器），不再整读内存单次 download
            // ——那样会被设备按 max-download-size 拒绝，宿主内存峰值也等于镜像大小。
            let materialized = flash::materialize_image(tool.source(), &task.filename)
                .map_err(FastbootError::Io)?;
            let image_path = materialized.path();
            let pb = setup_live_progress(&mut driver, &partition, file_size);
            let flashed = if is_sparse {
                flash_sparse_resparse(&mut driver, &partition, image_path, max_download_size).await
            } else {
                flash_raw_chunked(&mut driver, &partition, image_path, max_download_size).await
            };
            pb.finish_and_clear();
            flashed?;
        } else {
            let data = tool
                .source()
                .read_file(&task.filename)
                .map_err(FastbootError::Io)?;

            let pb = setup_live_progress(&mut driver, &partition, data.len() as u64);

            driver.download(&data).await?;
            driver.flash(&partition).await?;

            pb.finish_and_clear();
        }
        print_success(&format!(
            "[{}/{}] Writing '{}' ({})                    OKAY",
            i + 1,
            tasks.len(),
            partition,
            format_size(file_size)
        ));
    }

    if wipe {
        wipe_user_data(&mut driver).await?;
    }

    print_success("\n更新完成!");
    Ok(())
}

async fn cmd_upload(
    serial: &Option<String>,
    partition: &str,
    filename: &Path,
) -> Result<(), FastbootError> {
    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);

    print_info(&format!(
        "读取分区 '{}' 到 '{}'...",
        partition,
        filename.display()
    ));

    let size = driver.read_partition(partition, filename).await?;

    print_success(&format!("读取完成: {}", format_size(size)));
    Ok(())
}

async fn cmd_diagnose() -> Result<(), FastbootError> {
    println!("USB jiancha \n");

    println!("检查 USB 设备...");
    let devices = UsbTransport::enumerate_devices().map_err(FastbootError::Transport)?;

    if devices.is_empty() {
        println!("  未发现 fastboot 设备\n");
        println!("排查建议:");
        println!("  1. 确认设备已进入 fastboot 模式");
        println!("  2. 检查 USB 线连接");
        println!("  3. 尝试其他 USB 端口（推荐 USB 3.0）");
        println!("  4. 检查 fastboot 驱动是否已安装");
    } else {
        println!("  发现 {} 个设备:\n", devices.len());
        for dev in &devices {
            println!("  设备: {}", dev.serial_number);
            println!("    VID:PID = {:04x}:{:04x}", dev.vendor_id, dev.product_id);
            println!(
                "    USB 版本: {}",
                if dev.is_usb3 {
                    "3.0 (SuperSpeed)"
                } else {
                    "2.0 (High Speed)"
                }
            );
            if let Some(ref name) = dev.product_name {
                println!("    产品名: {}", name);
            }
            if let Some(ref mfr) = dev.manufacturer {
                println!("    制造商: {}", mfr);
            }
            println!();
        }

        if let Some(dev) = devices.first() {
            println!("尝试连接 {}...", dev.serial_number);
            match UsbTransport::open(Some(&dev.serial_number)) {
                Ok(transport) => {
                    let mut driver = driver::FastbootDriver::new(transport);
                    match driver.get_var("version").await {
                        Ok(version) => {
                            print_success(&format!("连接成功! Fastboot 版本: {}", version));
                        }
                        Err(e) => {
                            print_error(&format!("连接失败: {}", e));
                        }
                    }
                }
                Err(e) => {
                    print_error(&format!("无法打开设备: {}", e));
                }
            }
        }
    }

    println!("\n完成");
    Ok(())
}

/// 打开一台 ADB 模式的 WinUSB 设备（按 serial 匹配）。直连前先 [`adb_daemon::ensure_released`]
/// 让常驻 daemon 释放句柄，保证同一对端点任一时刻只有单一拥有者跑 ADB 帧；无 daemon 时是廉价 no-op。
fn open_adb_device(
    serial: Option<&str>,
) -> Result<crate::adb_winusb_transport::AdbWinUsbDevice, FastbootError> {
    use crate::adb_winusb_transport::AdbWinUsbDevice;
    adb_daemon::ensure_released();
    let devices = AdbWinUsbDevice::enumerate().map_err(|e| FastbootError::Adb(e.to_string()))?;
    if devices.is_empty() {
        return Err(FastbootError::NoDevice);
    }
    let path = match serial {
        Some(s) if !s.is_empty() && s != "unknown" => devices
            .iter()
            .find(|d| crate::adb_winusb_transport::serial_from_path(&d.device_path) == s)
            .map(|d| d.device_path.clone())
            .ok_or_else(|| {
                FastbootError::Adb(format!("ADB device with serial '{}' was not found", s))
            })?,
        _ if devices.len() > 1 => {
            return Err(FastbootError::Adb(
                "more than one ADB device/emulator; use -s <serial>".to_string(),
            ));
        }
        _ => devices[0].device_path.clone(),
    };
    AdbWinUsbDevice::open_device(&path).map_err(|e| FastbootError::Adb(e.to_string()))
}

async fn cmd_adb_uninstall(serial: &Option<String>, package: &str) -> Result<(), FastbootError> {
    let cmd = format!("pm uninstall {}", package);
    // 优先经 daemon 复用连接执行；不可用则回退直连。
    if let Some(res) = adb_daemon::capture_shell(serial.as_deref(), &cmd) {
        let output = res.map_err(FastbootError::Adb)?;
        print_success(&output);
        return Ok(());
    }
    let mut dev = open_adb_device(serial.as_deref())?;
    let output = dev.shell_command(&cmd).map_err(FastbootError::Adb)?;
    print_success(&output);
    Ok(())
}

async fn cmd_adb_packages(
    serial: &Option<String>,
    third_party: bool,
    system: bool,
) -> Result<(), FastbootError> {
    let cmd = if third_party {
        "pm list packages -3"
    } else if system {
        "pm list packages -s"
    } else {
        "pm list packages"
    };
    // 优先经 daemon 复用连接执行；不可用则回退直连。
    let output = if let Some(res) = adb_daemon::capture_shell(serial.as_deref(), cmd) {
        res.map_err(FastbootError::Adb)?
    } else {
        let mut dev = open_adb_device(serial.as_deref())?;
        dev.shell_command(cmd).map_err(FastbootError::Adb)?
    };
    for line in output.lines() {
        if let Some(pkg) = line.strip_prefix("package:") {
            println!("{}", pkg);
        }
    }
    Ok(())
}

async fn cmd_adb_screenrecord(
    serial: &Option<String>,
    output: &Path,
    time: u32,
) -> Result<(), FastbootError> {
    print_info(&format!(
        "Recording for {} seconds... (Ctrl+C to stop early)",
        time
    ));
    let mut dev = open_adb_device(serial.as_deref())?;
    dev.screenrecord(&output.to_string_lossy(), time)
        .map_err(FastbootError::Adb)?;
    print_success(&format!("Recording saved to {}", output.display()));
    Ok(())
}

async fn cmd_set_active(serial: &Option<String>, slot: &str) -> Result<(), FastbootError> {
    // 官方同时接受 `a` 与 `_a` 写法，线上发不带下划线的槽名。
    let slot = slot.trim().trim_start_matches('_').to_lowercase();
    if slot != "a" && slot != "b" {
        return Err(FastbootError::InvalidArg("槽位必须是 a 或 b".to_string()));
    }

    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);

    driver.set_active(&slot).await?;
    print_success(&format!("活动槽位已设置为: {}", slot));
    Ok(())
}

/// 设备在命令执行期间回的 INFO / TEXT，按到达顺序拼成官方 fastboot 的回显：INFO 加
/// "(bootloader) " 前缀并逐条换行；TEXT 原样拼接，换行由设备自带（对齐 AOSP 的
/// InfoMessage / TextMessage）。driver 默认的 text 回调是空操作，不接这里 TEXT 就被静默丢掉。
#[derive(Clone, Default)]
struct DeviceEcho(std::sync::Arc<std::sync::Mutex<String>>);

impl DeviceEcho {
    fn callbacks(&self) -> driver::DriverCallbacks {
        let info = self.clone();
        let text = self.clone();
        driver::DriverCallbacks {
            info: Box::new(move |msg| info.push(&format!("(bootloader) {msg}\n"))),
            text: Box::new(move |msg| text.push(msg)),
            ..Default::default()
        }
    }

    fn push(&self, chunk: &str) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_str(chunk);
    }

    /// 取走已收到的回显。末尾补一个换行：设备最后一段 TEXT 不一定带换行，
    /// 不补的话后面的输出会粘在同一行上。
    fn take(&self) -> String {
        let mut echo = std::mem::take(&mut *self.0.lock().unwrap_or_else(|e| e.into_inner()));
        if !echo.is_empty() && !echo.ends_with('\n') {
            echo.push('\n');
        }
        echo
    }
}

async fn cmd_oem(serial: &Option<String>, command: &[String]) -> Result<(), FastbootError> {
    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);
    let echo = DeviceEcho::default();
    driver.set_callbacks(echo.callbacks());

    let cmd = command.join(" ");
    // `oem get_token` / `oem get_unlock_data` 等命令的数据在设备回的多条 INFO 行里（单条 payload
    // 上限 252B，OKAY 往往为空），也有 bootloader 改用 TEXT 回：两种都必须完整回显，只读 OKAY
    // 会把 token 整个丢掉。INFO 行的 "(bootloader) " 前缀与 cmd_raw / cmd_getvar 及 GUI 端解析
    // (rm-flash-logic::commander::parse_fastboot_auth_blob) 的格式对齐；OKAY 视为成功、FAIL 视为失败。
    // 中途断链/超时也先把已收到的回显打出来，半截 token 比什么都没有好排查。
    let result = driver.oem_command_collect(&cmd).await;
    let echo = echo.take();
    print!("{echo}");
    let (resp, _) = result?;
    match resp {
        protocol::Response::Okay(msg) => {
            let msg = msg.trim();
            if !msg.is_empty() {
                println!("{}", msg);
            }
            // 仅当设备既无 INFO/TEXT 也无 OKAY 文本时，才补一条通用成功提示，避免污染 token 回显。
            if echo.is_empty() && msg.is_empty() {
                print_success(&format!("OEM 命令已执行: {}", cmd));
            }
            Ok(())
        }
        protocol::Response::Fail(msg) => Err(FastbootError::Device(msg)),
        _ => Err(FastbootError::Protocol("oem 返回了非预期响应".into())),
    }
}

/// `fastboot raw <cmd...>`：把参数原样发给设备（不加 "oem " 前缀、不做转换），用于厂商私有指令
/// （如 VIVO/BBK 只认自定义字符串命令）；设备的 INFO 行与 OKAY/FAIL 结果都会打印。
async fn cmd_raw(serial: &Option<String>, command: &[String]) -> Result<(), FastbootError> {
    let cmd = command.join(" ");
    if cmd.trim().is_empty() {
        return Err(FastbootError::InvalidArg("raw 命令不能为空".into()));
    }

    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);

    // 厂商私有指令多半会改设备状态：超时重发可能执行两次，走不重试通道。
    let (resp, info) = driver.command_no_retry_with_info(&cmd).await?;
    for line in &info {
        println!("(bootloader) {}", line);
    }
    match resp {
        protocol::Response::Okay(msg) => {
            if !msg.is_empty() {
                println!("{}", msg);
            }
            print_success(&format!("raw 命令已执行: {}", cmd));
            Ok(())
        }
        protocol::Response::Fail(msg) => Err(FastbootError::Device(msg)),
        _ => Err(FastbootError::Protocol("raw 命令返回了非预期响应".into())),
    }
}

async fn cmd_flashing(serial: &Option<String>, operation: &str) -> Result<(), FastbootError> {
    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);

    // `fastboot flashing <op>` 是独立顶层命令，线上直接发 "flashing <op>"（空格分隔），
    // 不是 oem 子命令——不能加 "oem " 前缀，否则设备回 FAIL: unknown command。
    // lock/unlock 要等用户按键确认：放宽超时且绝不重发（重发会让设备再弹一次确认甚至误执行）。
    let cmd = format!("flashing {}", operation.trim());
    if let Some(timeout) = protocol::flashing_timeout(operation) {
        driver.set_timeout(timeout);
        print_info("请在设备上用音量键选择、电源键确认…");
    }
    let (response, info) = driver.command_no_retry_with_info(&cmd).await?;
    for line in &info {
        println!("(bootloader) {}", line);
    }
    match response {
        protocol::Response::Okay(msg) => {
            if msg.is_empty() {
                print_success(&format!("flashing {} 完成", operation));
            } else {
                println!("{}", msg);
            }
            Ok(())
        }
        protocol::Response::Fail(msg) => Err(FastbootError::Device(msg)),
        _ => Err(FastbootError::Protocol("flashing 返回了非预期响应".into())),
    }
}

async fn cmd_create_logical_partition(
    serial: &Option<String>,
    name: &str,
    size: u64,
) -> Result<(), FastbootError> {
    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);
    driver.create_partition(name, size).await?;
    print_success(&format!("逻辑分区 {} 已创建 ({})", name, format_size(size)));
    Ok(())
}

async fn cmd_delete_logical_partition(
    serial: &Option<String>,
    name: &str,
) -> Result<(), FastbootError> {
    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);
    driver.delete_partition(name).await?;
    print_success(&format!("逻辑分区 {} 已删除", name));
    Ok(())
}

async fn cmd_resize_logical_partition(
    serial: &Option<String>,
    name: &str,
    size: u64,
) -> Result<(), FastbootError> {
    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);
    driver.resize_partition(name, size).await?;
    print_success(&format!("逻辑分区 {} 已调整为 {}", name, format_size(size)));
    Ok(())
}

/// fastboot boot <image>：下载完整 boot 镜像并临时引导（不写分区）。host 端合成 kernel+ramdisk
/// 需 mkbootimg、未实现，故只支持完整 boot/recovery 镜像（覆盖绝大多数用法）。
async fn cmd_boot(
    serial: &Option<String>,
    kernel: &Path,
    ramdisk: Option<&Path>,
) -> Result<(), FastbootError> {
    if ramdisk.is_some() {
        return Err(FastbootError::InvalidArg(
            "boot 仅支持引导完整 boot 镜像（fastboot boot boot.img）；\
             host 端合成 kernel+ramdisk 需 mkbootimg，未实现。请传入完整镜像。"
                .into(),
        ));
    }
    if !kernel.exists() {
        return Err(FastbootError::ImageNotFound(kernel.display().to_string()));
    }
    let data = fs::read(kernel).map_err(FastbootError::Io)?;
    if data.is_empty() {
        return Err(FastbootError::InvalidArg("镜像文件为空".into()));
    }

    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);

    print_info(&format!(
        "下载并引导 {} ({})",
        kernel.display(),
        format_size(data.len() as u64)
    ));

    let pb = setup_live_progress(&mut driver, "boot", data.len() as u64);
    driver.download(&data).await?;
    driver.boot().await?;
    pb.finish_and_clear();

    print_success("已发送 boot，设备应正在引导该镜像");
    Ok(())
}

/// fastboot stage <file>：把文件下载到设备暂存区（不写分区、不引导），供后续 oem / get_staged 使用。
async fn cmd_stage(serial: &Option<String>, input: &Path) -> Result<(), FastbootError> {
    if !input.exists() {
        return Err(FastbootError::ImageNotFound(input.display().to_string()));
    }
    let data = fs::read(input).map_err(FastbootError::Io)?;
    if data.is_empty() {
        return Err(FastbootError::InvalidArg("文件为空".into()));
    }

    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);

    print_info(&format!(
        "暂存 {} ({}) 到设备",
        input.display(),
        format_size(data.len() as u64)
    ));

    let pb = setup_live_progress(&mut driver, "stage", data.len() as u64);
    driver.download(&data).await?;
    pb.finish_and_clear();

    print_success(&format!("已暂存 {}", format_size(data.len() as u64)));
    Ok(())
}

/// fastboot get_staged <output>：把设备暂存区数据回传到主机文件（upload 协议命令）。
async fn cmd_get_staged(serial: &Option<String>, output: &Path) -> Result<(), FastbootError> {
    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);

    print_info(&format!("从设备取回暂存数据到 {}...", output.display()));
    let size = driver.upload_to_file(output).await?;

    print_success(&format!(
        "已取回 {} -> {}",
        format_size(size),
        output.display()
    ));
    Ok(())
}

/// fastboot gsi <wipe|disable|enable|status>：管理设备上的 GSI/DSU（设备端 `gsi:<op>` 命令）。
async fn cmd_gsi(serial: &Option<String>, operation: &str) -> Result<(), FastbootError> {
    let op = operation.trim().to_ascii_lowercase();
    if op.is_empty() {
        return Err(FastbootError::InvalidArg(
            "gsi 需指定操作：wipe / disable / enable / status".into(),
        ));
    }

    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);

    // gsi wipe/disable 改设备状态，不重试。
    let (resp, info) = driver
        .command_no_retry_with_info(&format!("gsi:{}", op))
        .await?;
    for line in &info {
        println!("(bootloader) {}", line);
    }
    match resp {
        protocol::Response::Okay(v) => {
            if !v.is_empty() {
                println!("{}", v);
            }
            print_success(&format!("gsi {} 完成", op));
            Ok(())
        }
        protocol::Response::Fail(msg) => Err(FastbootError::Device(msg)),
        _ => Err(FastbootError::Protocol("gsi 返回了非预期响应".into())),
    }
}

/// fastboot snapshot-update <cancel|merge>：虚拟 A/B 快照管理（设备端 `snapshot-update:<op>` 命令）。
async fn cmd_snapshot_update(
    serial: &Option<String>,
    operation: &str,
) -> Result<(), FastbootError> {
    let op = operation.trim().to_ascii_lowercase();
    if op != "cancel" && op != "merge" {
        return Err(FastbootError::InvalidArg(
            "snapshot-update 仅支持 cancel 或 merge".into(),
        ));
    }

    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);

    // cancel/merge 改快照状态，不重试。
    let (resp, info) = driver
        .command_no_retry_with_info(&format!("snapshot-update:{}", op))
        .await?;
    for line in &info {
        println!("(bootloader) {}", line);
    }
    match resp {
        protocol::Response::Okay(v) => {
            if !v.is_empty() {
                println!("{}", v);
            }
            print_success(&format!("snapshot-update {} 完成", op));
            Ok(())
        }
        protocol::Response::Fail(msg) => Err(FastbootError::Device(msg)),
        _ => Err(FastbootError::Protocol(
            "snapshot-update 返回了非预期响应".into(),
        )),
    }
}

/// fastboot wipe-super <super_empty.img>：用空 super 镜像重置动态分区元数据（需 fastbootd 模式）。
/// 主机端生成空 super 需 liblp、未实现，故要求传入固件包内的 super_empty.img。
async fn cmd_wipe_super(
    serial: &Option<String>,
    super_empty: Option<&Path>,
    slot: Option<&str>,
) -> Result<(), FastbootError> {
    let img = match super_empty {
        Some(p) => p,
        None => {
            return Err(FastbootError::InvalidArg(
                "wipe-super 需要提供 super_empty.img：fastboot wipe-super super_empty.img\n  \
                 （主机端凭设备 super 元数据生成空镜像需 liblp、未实现；请用固件包内的 super_empty.img）"
                    .into(),
            ))
        }
    };
    if !img.exists() {
        return Err(FastbootError::ImageNotFound(img.display().to_string()));
    }
    let data = fs::read(img).map_err(FastbootError::Io)?;
    if data.is_empty() {
        return Err(FastbootError::InvalidArg("super_empty 镜像为空".into()));
    }

    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);

    // wipe-super = download 元数据后发 `update-super:<super>:wipe`。绝不能 `flash super`——
    // 那会把几百 KB 元数据当整分区裸写、破坏 super。与 embed/lib 两入口保持同一协议。
    // super 分区名：先问 super-partition-name（官方口径），不支持再按 has-slot/current-slot 推断。
    let part = embed::resolve_super_partition(&mut driver, slot).await;

    print_info(&format!(
        "重置 super 分区元数据（{}）到 {}。注意：需设备处于 fastbootd 模式。",
        format_size(data.len() as u64),
        part
    ));

    let pb = setup_live_progress(&mut driver, &part, data.len() as u64);
    driver.download(&data).await?;
    // 改写动态分区表：超时重发会重复清空，不重试。
    let result = driver
        .command_no_retry(&format!("update-super:{}:wipe", part))
        .await;
    pb.finish_and_clear();

    match result? {
        protocol::Response::Okay(_) => {
            print_success("super 分区已重置（wipe-super 完成）");
            Ok(())
        }
        protocol::Response::Fail(msg) => Err(FastbootError::Device(msg)),
        _ => Err(FastbootError::Protocol("Unexpected response".into())),
    }
}

/// `fastboot update-super <image> [--wipe]`：设备侧动态分区更新（fastbootd 的 `update-super:<super>[:wipe]`）。
/// image 为 lpmake 生成的 super 元数据（如 super_empty.img），download 暂存后由设备合并/重建逻辑分区表。
async fn cmd_update_super(
    serial: &Option<String>,
    image: &Path,
    wipe: bool,
    slot: Option<&str>,
) -> Result<(), FastbootError> {
    if !image.exists() {
        return Err(FastbootError::ImageNotFound(image.display().to_string()));
    }
    let data = fs::read(image).map_err(FastbootError::Io)?;
    if data.is_empty() {
        return Err(FastbootError::InvalidArg("super 元数据镜像为空".into()));
    }

    let transport = open_transport(serial.as_deref()).await?;
    let mut driver = driver::FastbootDriver::new(transport);

    // super 分区名：A/B 设备按 current-slot 得 super_a/_b，否则 super。
    // super 分区名：先问 super-partition-name（官方口径），不支持再按 has-slot/current-slot 推断。
    let part = embed::resolve_super_partition(&mut driver, slot).await;

    print_info(&format!(
        "update-super：下发 super 元数据（{}）到 {}{}。需设备处于 fastbootd 模式。",
        format_size(data.len() as u64),
        part,
        if wipe { "（wipe）" } else { "" }
    ));

    driver.download(&data).await?;
    let cmd = if wipe {
        format!("update-super:{}:wipe", part)
    } else {
        format!("update-super:{}", part)
    };
    match driver.command_no_retry(&cmd).await? {
        protocol::Response::Okay(_) => {
            print_success("update-super 完成");
            Ok(())
        }
        protocol::Response::Fail(msg) => Err(FastbootError::Device(msg)),
        _ => Err(FastbootError::Protocol("Unexpected response".into())),
    }
}

#[cfg(test)]
mod cli_case_tests {
    use super::*;
    use std::ffi::OsString;

    fn argv(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    fn texts(items: Vec<OsString>) -> Vec<String> {
        items
            .into_iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn lowercases_only_the_subcommand_token() {
        let out = texts(normalize_cli_args(argv(&[
            "fastboot",
            "FLASH",
            "Boot_a",
            r"C:\Img\BOOT.IMG",
        ])));
        assert_eq!(out, ["fastboot", "flash", "Boot_a", r"C:\Img\BOOT.IMG"]);
    }

    #[test]
    fn serial_value_is_not_mistaken_for_subcommand() {
        let out = texts(normalize_cli_args(argv(&[
            "fastboot", "-s", "ABCDEF", "GETVAR", "Product",
        ])));
        // -s 的值 ABCDEF 原样；GETVAR 才是子命令被小写；自由参数 Product 原样。
        assert_eq!(out, ["fastboot", "-s", "ABCDEF", "getvar", "Product"]);
    }

    #[test]
    fn equals_form_flags_do_not_consume_next_token() {
        let out = texts(normalize_cli_args(argv(&[
            "fastboot",
            "--serial=ABCDEF",
            "DEVICES",
        ])));
        assert_eq!(out, ["fastboot", "--serial=ABCDEF", "devices"]);
    }

    #[test]
    fn shell_body_after_subcommand_keeps_case() {
        let out = texts(normalize_cli_args(argv(&[
            "fastboot",
            "SH",
            "echo",
            "Hello World",
        ])));
        assert_eq!(out, ["fastboot", "sh", "echo", "Hello World"]);
    }

    #[test]
    fn mixed_case_commands_parse_via_clap() {
        // 「FASTBOOT FLASH boot boot.img」与混合大小写「Adb REboot bootlOAdER」级别的写法必须可解析。
        let cli = Cli::try_parse_from(normalize_cli_args(argv(&[
            "fastboot", "FLASH", "Boot_a", "boot.img",
        ])))
        .expect("大写 FLASH 应可解析");
        match cli.command {
            Commands::Flash { partition, .. } => assert_eq!(partition, "Boot_a"),
            _ => panic!("应解析为 flash 子命令"),
        }

        let cli = Cli::try_parse_from(normalize_cli_args(argv(&[
            "fastboot",
            "REboot",
            "bootlOAdER",
        ])))
        .expect("混合大小写 REboot 应可解析");
        match cli.command {
            Commands::Reboot { target } => {
                // 自由参数保持原样，由 protocol::normalize_reboot_target 在 handler 内归一。
                assert_eq!(target, "bootlOAdER");
                assert_eq!(protocol::normalize_reboot_target(&target), "bootloader");
            }
            _ => panic!("应解析为 reboot 子命令"),
        }

        let cli = Cli::try_parse_from(normalize_cli_args(argv(&["fastboot", "GETVAR", "all"])))
            .expect("大写 GETVAR 应可解析");
        assert!(matches!(cli.command, Commands::Getvar { .. }));

        // 大写别名 R（reboot）。
        let cli = Cli::try_parse_from(normalize_cli_args(argv(&["fastboot", "R"])))
            .expect("大写别名 R 应可解析");
        assert!(matches!(cli.command, Commands::Reboot { .. }));
    }
}

#[cfg(test)]
mod oem_echo_tests {
    use super::*;
    use crate::error::TransportError;
    use crate::transport::AsyncTransport;
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::Pin;

    /// 按顺序回放设备回包的假传输层；写出去的命令一律当成功。
    struct ScriptedDevice(VecDeque<&'static [u8]>);

    impl AsyncTransport for ScriptedDevice {
        fn read<'a>(
            &'a mut self,
            buf: &'a mut [u8],
        ) -> Pin<Box<dyn Future<Output = Result<usize, TransportError>> + Send + 'a>> {
            Box::pin(async move {
                let frame = self.0.pop_front().ok_or(TransportError::Timeout)?;
                buf[..frame.len()].copy_from_slice(frame);
                Ok(frame.len())
            })
        }

        fn write<'a>(
            &'a mut self,
            data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Result<usize, TransportError>> + Send + 'a>> {
            Box::pin(async move { Ok(data.len()) })
        }

        fn close(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>> {
            Box::pin(async { Ok(()) })
        }

        fn reset(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn oem_echo_keeps_token_sent_in_text_frames() {
        // 有的 bootloader 把 `oem get_token` 的 token 放在 TEXT 帧里、OKAY 为空：
        // 漏收 TEXT 时命令行只剩一句「OEM 命令已执行」。
        let device = ScriptedDevice(VecDeque::from([
            &b"INFOUnlock token:"[..],
            &b"TEXTAABBCCDD\n"[..],
            &b"TEXTEEFF"[..],
            &b"OKAY"[..],
        ]));
        let mut driver = driver::FastbootDriver::new(device);
        let echo = DeviceEcho::default();
        driver.set_callbacks(echo.callbacks());

        let (resp, info) = driver.oem_command_collect("get_token").await.unwrap();

        assert_eq!(resp, protocol::Response::Okay(String::new()));
        assert_eq!(info, vec!["Unlock token:".to_string()]);
        assert_eq!(echo.take(), "(bootloader) Unlock token:\nAABBCCDD\nEEFF\n");
        assert!(echo.take().is_empty());
    }

    #[tokio::test]
    async fn oem_echo_keeps_partial_output_when_device_stops_answering() {
        let device = ScriptedDevice(VecDeque::from([&b"INFOtoken: AABB"[..]]));
        let mut driver = driver::FastbootDriver::new(device);
        let echo = DeviceEcho::default();
        driver.set_callbacks(echo.callbacks());

        let result = driver.oem_command_collect("get_token").await;

        assert!(matches!(result, Err(FastbootError::Timeout)));
        assert_eq!(echo.take(), "(bootloader) token: AABB\n");
    }
}
