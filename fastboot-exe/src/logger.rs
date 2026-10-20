// 轻量 best-effort 日志：仅在宿主提供的受控运行时目录内建档；独立运行时刻意不落盘。

use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, OnceLock};

static LOG_FILE: OnceLock<Option<Mutex<fs::File>>> = OnceLock::new();

/// 返回完整本地时间戳串（仅用于日志行前缀；文件名已改用随机 hex，见 `open_log`）。
fn now_string() -> String {
    use winapi::um::minwinbase::SYSTEMTIME;
    use winapi::um::sysinfoapi::GetLocalTime;
    let mut st: SYSTEMTIME = unsafe { std::mem::zeroed() };
    unsafe {
        GetLocalTime(&mut st);
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds
    )
}

fn resolve_log_dir() -> Option<PathBuf> {
    let runtime_root = PathBuf::from(std::env::var_os("RMF_RUNTIME_ROOT")?);
    let configured_log_dir = PathBuf::from(std::env::var_os("RMFLASH_LOG_DIR")?);
    let log_dir = controlled_log_dir(&runtime_root, &configured_log_dir)?;
    fs::create_dir_all(&log_dir).ok()?;
    Some(log_dir)
}

fn controlled_log_dir(runtime_root: &Path, log_dir: &Path) -> Option<PathBuf> {
    let runtime_root = normalize_absolute_path(runtime_root)?;
    let log_dir = normalize_absolute_path(log_dir)?;
    log_dir.starts_with(&runtime_root).then_some(log_dir)
}

fn open_log() -> Option<Mutex<fs::File>> {
    let dir = resolve_log_dir()?;
    let path = controlled_log_path(&dir, &random_hex(20)?)?;
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .ok()?;
    Some(Mutex::new(file))
}

fn controlled_log_path(dir: &Path, stem: &str) -> Option<PathBuf> {
    if stem.len() != 40
        || !stem
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    Some(dir.join(format!("{stem}.log")))
}

fn normalize_absolute_path(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
        }
    }
    Some(normalized)
}

fn random_hex(bytes: usize) -> Option<String> {
    let mut data = vec![0u8; bytes];
    rand::rngs::OsRng.try_fill_bytes(&mut data).ok()?;
    Some(data.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn redact_runtime_paths(value: &str) -> String {
    let mut output = value.to_string();
    for key in ["RMF_RUNTIME_ROOT", "RMFLASH_LOG_DIR", "TEMP", "TMP"] {
        if let Some(path) = std::env::var_os(key) {
            let path = path.to_string_lossy();
            if !path.is_empty() {
                output = output.replace(path.as_ref(), "<runtime>");
                output = output.replace(&path.replace('\\', "/"), "<runtime>");
            }
        }
    }
    output
}

fn handle() -> Option<&'static Mutex<fs::File>> {
    LOG_FILE.get_or_init(open_log).as_ref()
}

/// 追加一行带时间戳的日志（错误静默忽略）。
pub fn log_line(msg: &str) {
    if let Some(m) = handle() {
        if let Ok(mut f) = m.lock() {
            let ts = now_string();
            let _ = writeln!(f, "[{}] {}", ts, redact_runtime_paths(msg));
            let _ = f.flush();
        }
    }
}

/// 记录一次进程调用的开始（命令行 + 版本）。
pub fn log_invocation() {
    let argv: Vec<String> = std::env::args().collect();
    let cmdline = argv.join(" ");
    log_line(&format!(
        "==== fastboot v{} | {} ====",
        env!("CARGO_PKG_VERSION"),
        cmdline
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_name_is_random_and_non_semantic() {
        let dir = PathBuf::from(r"C:\runtime\logs");
        let path = controlled_log_path(&dir, "0123456789abcdef0123456789abcdef01234567")
            .expect("valid name");
        assert!(path.starts_with(&dir));
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("0123456789abcdef0123456789abcdef01234567.log")
        );
        assert!(controlled_log_path(&dir, "fastboot-20260710").is_none());
    }

    #[test]
    fn log_directory_must_descend_from_runtime() {
        let runtime = PathBuf::from(r"C:\runtime\session");
        let logs = runtime.join("aa").join("bb");
        let outside = PathBuf::from(r"D:\logs");

        assert_eq!(controlled_log_dir(&runtime, &logs), Some(logs));
        assert!(controlled_log_dir(&runtime, &outside).is_none());
        assert!(controlled_log_dir(&runtime, Path::new("relative")).is_none());
    }
}
