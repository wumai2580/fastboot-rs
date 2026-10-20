//! CLI 的终端输出：`--json` 机器可读开关、人类可读的大小格式与转圈提示。
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
static MACHINE_READABLE: AtomicBool = AtomicBool::new(false);
pub fn set_machine_readable(enabled: bool) {
    MACHINE_READABLE.store(enabled, Ordering::SeqCst);
}
pub fn is_machine_readable() -> bool {
    MACHINE_READABLE.load(Ordering::SeqCst)
}

pub fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / 1024.0 / 1024.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
    }
}
pub fn print_success(message: &str) {
    crate::logger::log_line(message);
    if !is_machine_readable() {
        println!("{}", message);
    }
}
pub fn print_error(message: &str) {
    crate::logger::log_line(&format!("错误: {}", message));
    eprintln!("{}", message);
}
pub fn print_info(message: &str) {
    crate::logger::log_line(message);
    if !is_machine_readable() {
        println!("{}", message);
    }
}

pub struct Spinner {
    bar: ProgressBar,
}

impl Spinner {
    pub fn new(message: &str) -> Self {
        let bar = if is_machine_readable() {
            ProgressBar::hidden()
        } else {
            let bar = ProgressBar::new_spinner();
            bar.set_draw_target(ProgressDrawTarget::stderr_with_hz(10));
            bar.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.cyan} {msg}")
                    .expect("Invalid spinner template"),
            );
            bar.set_message(message.to_string());
            bar.enable_steady_tick(Duration::from_millis(100));
            bar
        };

        Self { bar }
    }

    pub fn tick(&self) {
        self.bar.tick();
    }

    pub fn finish(&self, message: &str) {
        if is_machine_readable() {
            return;
        }
        self.bar.finish_and_clear();
        println!("{}", message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_machine_readable_mode() {
        set_machine_readable(true);
        assert!(is_machine_readable());
        set_machine_readable(false);
        assert!(!is_machine_readable());
    }
}
