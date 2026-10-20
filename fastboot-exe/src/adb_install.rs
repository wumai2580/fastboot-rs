//! APK 安装的唯一实现：CLI、embed 常驻连接与 5037 mux 三条路径共用。
//!
//! 设备有 `cmd`（Android 7+）时走流式安装：`exec:cmd package install -S <size>` 直接把 APK 字节
//! 灌给 pm，不在 `/data/local/tmp` 落临时文件；设备还有 `abb_exec` 时改走 `abb_exec:package…`
//! （参数以 NUL 分隔、不经 shell）。更老的设备退回「push 到临时目录 + pm install」。

use std::fs::File;
use std::io::Read;

use crate::adb_winusb_transport::AdbWinUsbDevice;

/// 设备侧可用的安装通道。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct InstallCaps {
    /// `cmd package install -S` 流式安装（设备特性 `cmd`）。
    pub streamed: bool,
    /// `abb_exec:` 服务（设备特性 `abb_exec`），只在 `streamed` 时生效。
    pub abb_exec: bool,
}

impl InstallCaps {
    pub(crate) fn from_features(features: &[String]) -> Self {
        let has = |f: &str| features.iter().any(|d| d == f);
        Self {
            streamed: has("cmd"),
            abb_exec: has("cmd") && has("abb_exec"),
        }
    }

    /// 拿不到设备特性列表的通道按系统版本推断：`cmd` 自 Android 7（API 24）起就有。
    pub(crate) fn from_sdk(sdk: u32) -> Self {
        Self {
            streamed: sdk >= 24,
            abb_exec: false,
        }
    }
}

/// 安装流程用到的设备操作；直连设备与 5037 mux 各实现一份。
pub(crate) trait InstallConn {
    fn install_caps(&mut self) -> Result<InstallCaps, String>;
    /// 执行 pm 服务并把 `stdin` 整段写给它，返回服务输出。
    fn exec_stdin(&mut self, service: &[u8], stdin: &mut dyn Read) -> Result<String, String>;
    fn shell(&mut self, command: &str) -> Result<String, String>;
    fn push_file(&mut self, local: &str, remote: &str) -> Result<(), String>;
}

pub(crate) fn replace_flag(replace: bool) -> Vec<String> {
    if replace {
        vec!["-r".to_string()]
    } else {
        Vec::new()
    }
}

/// 从 `install-create` 输出（如 `Success: created install session [1234567]`）取方括号内的会话 ID。
pub(crate) fn parse_install_session_id(output: &str) -> Option<String> {
    let start = output.find('[')?;
    let rel_end = output[start + 1..].find(']')?;
    let id = output[start + 1..start + 1 + rel_end].trim();
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        None
    } else {
        Some(id.to_string())
    }
}

fn shell_quote(arg: &str) -> String {
    let plain = !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./:=+,@%".contains(&b));
    if plain {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

/// pm 服务串：`abb_exec:package\0arg\0…`，否则是经设备 shell 解析的 `exec:cmd package arg …`。
fn pm_service(caps: InstallCaps, args: &[&str]) -> Vec<u8> {
    if caps.abb_exec {
        let mut service = b"abb_exec:package".to_vec();
        for arg in args {
            service.push(0);
            service.extend_from_slice(arg.as_bytes());
        }
        service
    } else {
        let mut service = String::from("exec:cmd package");
        for arg in args {
            service.push(' ');
            service.push_str(&shell_quote(arg));
        }
        service.into_bytes()
    }
}

fn pm_exec(
    conn: &mut dyn InstallConn,
    caps: InstallCaps,
    args: &[&str],
    stdin: &mut dyn Read,
) -> Result<String, String> {
    conn.exec_stdin(&pm_service(caps, args), stdin)
}

fn pm_command(command: &str, options: &[String]) -> String {
    let mut line = format!("pm {}", command);
    for option in options {
        line.push(' ');
        line.push_str(&shell_quote(option));
    }
    line
}

fn expect_success(output: String, what: &str) -> Result<String, String> {
    if output.contains("Success") {
        Ok(output.trim().to_string())
    } else {
        Err(format!("{}: {}", what, output.trim()))
    }
}

fn apk_size(path: &str) -> Result<u64, String> {
    std::fs::metadata(path)
        .map(|m| m.len())
        .map_err(|e| format!("读取 APK 失败 {}: {}", path, e))
}

fn open_apk(path: &str) -> Result<File, String> {
    File::open(path).map_err(|e| format!("打开 APK 失败 {}: {}", path, e))
}

/// `adb install [options] <apk>`。`options` 原样交给 pm（如 `-r`/`-d`/`-g`）。
pub(crate) fn install(
    conn: &mut dyn InstallConn,
    apk: &str,
    options: &[String],
) -> Result<String, String> {
    let size = apk_size(apk)?;
    let caps = conn.install_caps()?;
    if !caps.streamed {
        return install_legacy(conn, apk, options);
    }
    let size = size.to_string();
    let mut args: Vec<&str> = vec!["install"];
    args.extend(options.iter().map(String::as_str));
    args.extend(["-S", size.as_str()]);
    let output = pm_exec(conn, caps, &args, &mut open_apk(apk)?)?;
    expect_success(output, "安装失败")
}

fn install_legacy(
    conn: &mut dyn InstallConn,
    apk: &str,
    options: &[String],
) -> Result<String, String> {
    // 固定远端临时名，避免文件名里的空格/中文/特殊字符影响 shell 命令拼接。
    let remote = "/data/local/tmp/rmf_install.apk";
    conn.push_file(apk, remote)?;
    let output = conn.shell(&format!("{} {}", pm_command("install", options), remote));
    let _ = conn.shell(&format!("rm -f {}", remote));
    expect_success(output?, "安装失败")
}

/// `adb install-multiple [options] <apk...>`：install-create → 逐个 install-write → install-commit，
/// 任一步失败则 install-abandon 回滚。`options` 交给 install-create。
pub(crate) fn install_multiple(
    conn: &mut dyn InstallConn,
    apks: &[String],
    options: &[String],
) -> Result<String, String> {
    if apks.is_empty() {
        return Err("install-multiple 需要至少一个 APK".to_string());
    }
    let sizes = apks
        .iter()
        .map(|apk| apk_size(apk))
        .collect::<Result<Vec<_>, _>>()?;
    let caps = conn.install_caps()?;

    let session = create_session(conn, caps, options, sizes.iter().sum(), &[])?;
    let committed = write_apks(conn, caps, &session, apks, &sizes)
        .and_then(|()| session_verb(conn, caps, "install-commit", &[&session]));
    if committed.is_err() {
        let _ = session_verb(conn, caps, "install-abandon", &[&session]);
    }
    committed
}

/// `adb install-multi-package [options] <apk...>`：每个 APK 是一个独立的包，放进同一个父会话里
/// 原子提交（全部成功或全部不装）。流程与官方一致：
/// `install-create --multi-package` 建父会话 → 每个 APK 各建子会话并写入 → `install-add-session`
/// 挂到父会话 → 提交父会话。任一步失败则放弃父会话与已建子会话。
pub(crate) fn install_multi_package(
    conn: &mut dyn InstallConn,
    apks: &[String],
    options: &[String],
) -> Result<String, String> {
    if apks.is_empty() {
        return Err("install-multi-package 需要至少一个 APK".to_string());
    }
    let sizes = apks
        .iter()
        .map(|apk| apk_size(apk))
        .collect::<Result<Vec<_>, _>>()?;
    let caps = conn.install_caps()?;

    let parent = create_session(conn, caps, options, 0, &["--multi-package"])?;
    let mut children: Vec<String> = Vec::new();
    let mut run = || -> Result<String, String> {
        for (apk, size) in apks.iter().zip(&sizes) {
            let child = create_session(conn, caps, options, *size, &[])?;
            children.push(child.clone());
            write_apks(
                conn,
                caps,
                &child,
                std::slice::from_ref(apk),
                std::slice::from_ref(size),
            )?;
            session_verb(conn, caps, "install-add-session", &[&parent, &child])?;
        }
        session_verb(conn, caps, "install-commit", &[&parent])
    };
    let result = run();
    if result.is_err() {
        for child in &children {
            let _ = session_verb(conn, caps, "install-abandon", &[child]);
        }
        let _ = session_verb(conn, caps, "install-abandon", &[&parent]);
    }
    result
}

/// `install-create [extra] [options] [-S total]`，返回会话 ID。`total == 0` 时不带 `-S`
/// （父会话本身不装字节）。
fn create_session(
    conn: &mut dyn InstallConn,
    caps: InstallCaps,
    options: &[String],
    total: u64,
    extra: &[&str],
) -> Result<String, String> {
    let create_out = if caps.streamed {
        let total = total.to_string();
        let mut args: Vec<&str> = vec!["install-create"];
        args.extend_from_slice(extra);
        args.extend(options.iter().map(String::as_str));
        if total != "0" {
            args.extend(["-S", total.as_str()]);
        }
        pm_exec(conn, caps, &args, &mut std::io::empty())?
    } else {
        let mut opts: Vec<String> = extra.iter().map(|s| s.to_string()).collect();
        opts.extend(options.iter().cloned());
        conn.shell(&pm_command("install-create", &opts))?
    };
    parse_install_session_id(&create_out)
        .ok_or_else(|| format!("无法解析安装会话 ID: {}", create_out.trim()))
}

/// 把 APK 逐个 install-write 进会话。
fn write_apks(
    conn: &mut dyn InstallConn,
    caps: InstallCaps,
    session: &str,
    apks: &[String],
    sizes: &[u64],
) -> Result<(), String> {
    apks.iter()
        .zip(sizes)
        .enumerate()
        .try_for_each(|(idx, (apk, size))| {
            let output = if caps.streamed {
                let size = size.to_string();
                let name = format!("{}.apk", idx);
                let args = ["install-write", "-S", &size, session, &name, "-"];
                pm_exec(conn, caps, &args, &mut open_apk(apk)?)?
            } else {
                let remote = format!("/data/local/tmp/rmf_split_{}.apk", idx);
                conn.push_file(apk, &remote)?;
                let output =
                    conn.shell(&format!("pm install-write {} {} {}", session, idx, remote));
                let _ = conn.shell(&format!("rm -f {}", remote));
                output?
            };
            expect_success(output, "install-write 失败").map(|_| ())
        })
}

/// 不带数据的会话动词（install-commit / install-abandon / install-add-session）。
fn session_verb(
    conn: &mut dyn InstallConn,
    caps: InstallCaps,
    verb: &str,
    args: &[&str],
) -> Result<String, String> {
    let output = if caps.streamed {
        let mut full: Vec<&str> = vec![verb];
        full.extend_from_slice(args);
        pm_exec(conn, caps, &full, &mut std::io::empty())?
    } else {
        conn.shell(&format!("pm {} {}", verb, args.join(" ")))?
    };
    expect_success(output, &format!("{verb} 失败"))
}

impl InstallConn for AdbWinUsbDevice {
    fn install_caps(&mut self) -> Result<InstallCaps, String> {
        self.connect()?;
        Ok(InstallCaps::from_features(&self.peer_banner().features))
    }

    fn exec_stdin(&mut self, service: &[u8], stdin: &mut dyn Read) -> Result<String, String> {
        self.exec_with_stdin(service, stdin)
            .map(|out| String::from_utf8_lossy(&out).into_owned())
    }

    fn shell(&mut self, command: &str) -> Result<String, String> {
        self.shell_command(command)
    }

    fn push_file(&mut self, local: &str, remote: &str) -> Result<(), String> {
        self.push(local, remote)
    }
}

/// 经 5037 上的 adb server（mux）安装：它独占设备句柄时本进程不能直连。
pub(crate) struct MuxConn<'a> {
    serial: Option<&'a str>,
}

impl<'a> MuxConn<'a> {
    pub(crate) fn new(serial: Option<&'a str>) -> Self {
        Self { serial }
    }
}

/// server 暂时不在时等它回来再试一次（[`crate::adb_mux_client::retry_via_server`]）；仍不在就报错，
/// 绝不回退直连去抢设备句柄。
fn retry_mux<T>(request: impl FnMut() -> Option<T>) -> Result<T, String> {
    crate::adb_mux_client::retry_via_server(request).ok_or_else(|| {
        "5037 上的 adb server 不可用，已阻止直连回退（避免与它争用设备句柄）".to_string()
    })
}

impl InstallConn for MuxConn<'_> {
    fn install_caps(&mut self) -> Result<InstallCaps, String> {
        let sdk = self.shell("getprop ro.build.version.sdk")?;
        Ok(sdk
            .trim()
            .parse()
            .map(InstallCaps::from_sdk)
            .unwrap_or_default())
    }

    fn exec_stdin(&mut self, service: &[u8], stdin: &mut dyn Read) -> Result<String, String> {
        let service =
            std::str::from_utf8(service).map_err(|_| "mux 通道的服务串必须是文本".to_string())?;
        let serial = self.serial;
        retry_mux(|| crate::adb_mux_client::exec_with_stdin(serial, service, &mut *stdin))?
            .map(|out| String::from_utf8_lossy(&out).into_owned())
    }

    fn shell(&mut self, command: &str) -> Result<String, String> {
        let serial = self.serial;
        retry_mux(|| crate::adb_mux_client::capture_shell_result(serial, command))?
    }

    fn push_file(&mut self, local: &str, remote: &str) -> Result<(), String> {
        let serial = self.serial;
        retry_mux(|| crate::adb_mux_client::push(serial, std::path::Path::new(local), remote))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[derive(Default)]
    struct FakeConn {
        caps: InstallCaps,
        services: Vec<Vec<u8>>,
        stdin_bytes: Vec<usize>,
        shells: Vec<String>,
        pushes: Vec<(String, String)>,
        /// 按调用顺序回的 exec 输出；耗尽后回 "Success"。
        exec_replies: Vec<String>,
    }

    impl InstallConn for FakeConn {
        fn install_caps(&mut self) -> Result<InstallCaps, String> {
            Ok(self.caps)
        }

        fn exec_stdin(&mut self, service: &[u8], stdin: &mut dyn Read) -> Result<String, String> {
            let mut data = Vec::new();
            stdin.read_to_end(&mut data).unwrap();
            self.services.push(service.to_vec());
            self.stdin_bytes.push(data.len());
            Ok(if self.exec_replies.is_empty() {
                "Success".to_string()
            } else {
                self.exec_replies.remove(0)
            })
        }

        fn shell(&mut self, command: &str) -> Result<String, String> {
            self.shells.push(command.to_string());
            Ok(if command.starts_with("pm install-create") {
                "Success: created install session [42]".to_string()
            } else {
                "Success".to_string()
            })
        }

        fn push_file(&mut self, local: &str, remote: &str) -> Result<(), String> {
            self.pushes.push((local.to_string(), remote.to_string()));
            Ok(())
        }
    }

    fn temp_apk(dir: &tempfile::TempDir, name: &str, len: usize) -> String {
        let path = dir.path().join(name);
        File::create(&path)
            .unwrap()
            .write_all(&vec![0x5a; len])
            .unwrap();
        path.to_string_lossy().into_owned()
    }

    fn text(service: &[u8]) -> String {
        String::from_utf8_lossy(service).replace('\0', "|")
    }

    #[test]
    fn multi_package_nests_child_sessions_under_parent() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = temp_apk(&dir, "a.apk", 10);
        let b = temp_apk(&dir, "b.apk", 20);
        let mut conn = FakeConn {
            caps: InstallCaps {
                streamed: true,
                abb_exec: false,
            },
            exec_replies: vec![
                "Success: created install session [100]".into(),
                "Success: created install session [201]".into(),
                "Success".into(),
                "Success".into(),
                "Success: created install session [202]".into(),
            ],
            ..Default::default()
        };
        install_multi_package(&mut conn, &[a, b], &[]).unwrap();
        let services: Vec<String> = conn.services.iter().map(|s| text(s)).collect();
        assert_eq!(
            services,
            vec![
                "exec:cmd package install-create --multi-package",
                "exec:cmd package install-create -S 10",
                "exec:cmd package install-write -S 10 201 0.apk -",
                "exec:cmd package install-add-session 100 201",
                "exec:cmd package install-create -S 20",
                "exec:cmd package install-write -S 20 202 0.apk -",
                "exec:cmd package install-add-session 100 202",
                "exec:cmd package install-commit 100",
            ]
        );
    }

    #[test]
    fn parses_install_session_id() {
        assert_eq!(
            parse_install_session_id("Success: created install session [536012345]").as_deref(),
            Some("536012345")
        );
        assert_eq!(parse_install_session_id("Success"), None);
        assert_eq!(parse_install_session_id("session [abc]"), None);
        assert_eq!(parse_install_session_id("session []"), None);
    }

    #[test]
    fn caps_follow_device_features() {
        let f = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            InstallCaps::from_features(&f(&["shell_v2"])),
            InstallCaps::default()
        );
        assert_eq!(
            InstallCaps::from_features(&f(&["cmd"])),
            InstallCaps {
                streamed: true,
                abb_exec: false
            }
        );
        assert_eq!(
            InstallCaps::from_features(&f(&["cmd", "abb_exec"])),
            InstallCaps {
                streamed: true,
                abb_exec: true
            }
        );
        assert!(!InstallCaps::from_sdk(23).streamed);
        assert!(InstallCaps::from_sdk(24).streamed);
    }

    #[test]
    fn streamed_install_pipes_apk_into_pm_without_temp_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let apk = temp_apk(&dir, "a b.apk", 1000);
        let mut conn = FakeConn {
            caps: InstallCaps {
                streamed: true,
                abb_exec: false,
            },
            ..Default::default()
        };
        install(&mut conn, &apk, &replace_flag(true)).unwrap();
        assert_eq!(
            text(&conn.services[0]),
            "exec:cmd package install -r -S 1000"
        );
        assert_eq!(conn.stdin_bytes, vec![1000]);
        assert!(conn.pushes.is_empty() && conn.shells.is_empty());

        let mut conn = FakeConn {
            caps: InstallCaps {
                streamed: true,
                abb_exec: true,
            },
            ..Default::default()
        };
        install(&mut conn, &apk, &[]).unwrap();
        assert_eq!(text(&conn.services[0]), "abb_exec:package|install|-S|1000");
    }

    #[test]
    fn streamed_install_reports_pm_failure() {
        let dir = tempfile::TempDir::new().unwrap();
        let apk = temp_apk(&dir, "a.apk", 10);
        let mut conn = FakeConn {
            caps: InstallCaps {
                streamed: true,
                abb_exec: false,
            },
            exec_replies: vec!["Failure [INSTALL_FAILED_VERSION_DOWNGRADE]".to_string()],
            ..Default::default()
        };
        let err = install(&mut conn, &apk, &[]).unwrap_err();
        assert!(err.contains("INSTALL_FAILED_VERSION_DOWNGRADE"), "{err}");
    }

    #[test]
    fn legacy_install_pushes_then_runs_pm() {
        let dir = tempfile::TempDir::new().unwrap();
        let apk = temp_apk(&dir, "a.apk", 10);
        let mut conn = FakeConn::default();
        install(&mut conn, &apk, &["-r".to_string(), "-t".to_string()]).unwrap();
        assert_eq!(conn.pushes[0].1, "/data/local/tmp/rmf_install.apk");
        assert_eq!(
            conn.shells,
            vec![
                "pm install -r -t /data/local/tmp/rmf_install.apk".to_string(),
                "rm -f /data/local/tmp/rmf_install.apk".to_string(),
            ]
        );
        assert!(conn.services.is_empty());
    }

    #[test]
    fn streamed_install_multiple_writes_each_split_then_commits() {
        let dir = tempfile::TempDir::new().unwrap();
        let apks = vec![
            temp_apk(&dir, "base.apk", 300),
            temp_apk(&dir, "split.apk", 200),
        ];
        let mut conn = FakeConn {
            caps: InstallCaps {
                streamed: true,
                abb_exec: false,
            },
            exec_replies: vec!["Success: created install session [77]".to_string()],
            ..Default::default()
        };
        install_multiple(&mut conn, &apks, &replace_flag(true)).unwrap();
        let services: Vec<String> = conn.services.iter().map(|s| text(s)).collect();
        assert_eq!(
            services,
            vec![
                "exec:cmd package install-create -r -S 500",
                "exec:cmd package install-write -S 300 77 0.apk -",
                "exec:cmd package install-write -S 200 77 1.apk -",
                "exec:cmd package install-commit 77",
            ]
        );
        assert_eq!(conn.stdin_bytes, vec![0, 300, 200, 0]);
    }

    #[test]
    fn failed_split_write_abandons_session() {
        let dir = tempfile::TempDir::new().unwrap();
        let apks = vec![temp_apk(&dir, "base.apk", 3)];
        let mut conn = FakeConn {
            caps: InstallCaps {
                streamed: true,
                abb_exec: false,
            },
            exec_replies: vec![
                "Success: created install session [9]".to_string(),
                "Failure [INSTALL_FAILED_INVALID_APK]".to_string(),
            ],
            ..Default::default()
        };
        let err = install_multiple(&mut conn, &apks, &[]).unwrap_err();
        assert!(err.contains("INSTALL_FAILED_INVALID_APK"), "{err}");
        let last = text(conn.services.last().unwrap());
        assert_eq!(last, "exec:cmd package install-abandon 9");
    }

    #[test]
    fn legacy_install_multiple_uses_temp_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let apks = vec![temp_apk(&dir, "base.apk", 3)];
        let mut conn = FakeConn::default();
        install_multiple(&mut conn, &apks, &[]).unwrap();
        assert_eq!(
            conn.shells,
            vec![
                "pm install-create".to_string(),
                "pm install-write 42 0 /data/local/tmp/rmf_split_0.apk".to_string(),
                "rm -f /data/local/tmp/rmf_split_0.apk".to_string(),
                "pm install-commit 42".to_string(),
            ]
        );
    }
}
