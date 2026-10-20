//! fastboot 传输打开的共享实现：带「句柄竞争保护」的 `open_transport`。
//! 连续/批量刷写下，上个会话的 WinUSB 句柄由内核释放有秒级延迟，期间新句柄能 open 却无法 IO；
//! 故 open 后用只读 `getvar:version` 探测，失败则丢弃坏句柄、退避重开。
//! CLI 与 GUI 统一复用本模块，避免竞争修复只在 CLI 生效的落差。

use crate::driver;
use crate::error::FastbootError;
use crate::transport::AsyncTransport;
use crate::usb_transport::UsbTransport;

pub const USB_SMART_ROUTE_MSG: &str =
    "   USB 端口被占用且智能路由失败。请检查设备是否已授权，或尝试以管理员身份运行。";

/// 句柄竞争退避（毫秒）：第 `attempt` 次重试（从 0 起）等待 `min(base << attempt, cap)`。
/// 先快后慢的高频轮询——极短间隔起步、指数增长封顶，句柄刚释放即快速命中，避免线性长退避空等。
fn handle_race_backoff_ms(attempt: u32, base: u64, cap: u64) -> u64 {
    base.saturating_mul(1u64 << attempt.min(20)).min(cap)
}

/// 节流释放本进程 adb 常驻缓存句柄：一次刷写往往 getvar→flash 多次 open_transport，每次都释放
/// 会反复把复合设备抖下 USB 总线、永远无法 settle。至多每 12s 释放一次，后续 open 复用已回稳设备。
fn release_adb_handle_throttled() {
    use std::sync::Mutex;
    use std::time::Instant;
    static LAST_RELEASE: Mutex<Option<Instant>> = Mutex::new(None);
    let mut guard = match LAST_RELEASE.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let now = Instant::now();
    let should = match *guard {
        Some(t) => now.duration_since(t) >= std::time::Duration::from_secs(12),
        None => true,
    };
    if should {
        *guard = Some(now);
        drop(guard);
        crate::embed::adb_release();
    }
}

/// 打开 fastboot 传输，带句柄竞争保护（探测 + 高频轮询退避重开）。
/// 多设备是确定性结果，直接返回不重试；无设备及坏句柄退避重开直到时限。
/// 不再无条件 taskkill adb.exe：fastboot 模式下 adb.exe 并不占用设备，taskkill 每条命令
/// 多起一个进程（数百毫秒）且会误杀用户的官方 adb/scrcpy；句柄竞争由探测+退避重开兜底。
pub async fn open_transport(serial: Option<&str>) -> Result<UsbTransport, FastbootError> {
    // 复合设备 ACCESS_DENIED/“端口被占用”/“无设备”的根因：本进程 adb 常驻缓存（adb_hub）持有
    // 同一复合设备的 WinUSB 句柄，设备切到 fastboot 后未释放，fastboot 打开被拒（os error 5）。
    // 须释放该句柄，但释放会让设备短暂掉线重枚举（“无设备”抖动数秒）——故开头只节流释放一次，
    // 再用带时限的退避重试覆盖抖动期（CLI 进程从未建过 hub，释放是空操作）。
    release_adb_handle_throttled();

    // 时限：覆盖释放句柄后设备重枚举的抖动窗口（实测抖动以约 1s 为周期持续数秒）。
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    let mut first_protocol_error = None;
    let mut attempt: u32 = 0;

    loop {
        match try_open_transport_probed(serial).await {
            Ok(transport) => return Ok(transport),
            // 多设备是确定性结果（需 -s 指定），立即返回不重试。
            Err(e @ FastbootError::MultipleDevices) => return Err(e),
            // 无设备 / 坏句柄 / 占用：都可能是释放句柄后的重枚举抖动，退避重试直到时限。
            Err(e) => {
                if matches!(e, FastbootError::Protocol(_)) && first_protocol_error.is_none() {
                    first_protocol_error = Some(e.to_string());
                }
                if std::time::Instant::now() >= deadline {
                    return Err(open_failure_with_protocol_context(
                        e,
                        first_protocol_error.as_deref(),
                    ));
                }
                // 注意：这里**不再**重复调用 release，避免反复把设备抖下线导致永远无法稳定。
                tokio::time::sleep(std::time::Duration::from_millis(handle_race_backoff_ms(
                    attempt, 5, 300,
                )))
                .await;
                attempt += 1;
            }
        }
    }
}

/// 重枚举期间最后一次错误可能变成「无设备」，不能因此丢掉先前异常回包的诊断。
fn open_failure_with_protocol_context(
    last_error: FastbootError,
    first_protocol_error: Option<&str>,
) -> FastbootError {
    match first_protocol_error {
        Some(first) if first != last_error.to_string() => FastbootError::Protocol(format!(
            "首次连接探测失败: {first}; 最终连接失败: {last_error}"
        )),
        _ => last_error,
    }
}

/// 打开 fastboot 传输并用只读 getvar 探测句柄是否真正可用（单次尝试，重试/退避由 open_transport 统一负责）。
async fn try_open_transport_probed(serial: Option<&str>) -> Result<UsbTransport, FastbootError> {
    let devices = UsbTransport::enumerate_devices().map_err(FastbootError::Transport)?;

    if devices.is_empty() {
        return Err(FastbootError::NoDevice);
    }

    if devices.len() > 1 && serial.is_none() {
        return Err(FastbootError::MultipleDevices);
    }

    let transport = UsbTransport::open(serial).map_err(|e| {
        if e.is_usb_access_denied() {
            FastbootError::InvalidArg(USB_SMART_ROUTE_MSG.into())
        } else {
            FastbootError::Transport(e)
        }
    })?;

    probe_transport(transport).await
}

/// 探测必须完整读到合法终态，不能把协议异常当成可继续使用的连接。
/// version 不被设备支持时，合法 FAIL 仍能证明 fastboot 命令和响应通道可用。
async fn probe_transport<T: AsyncTransport>(transport: T) -> Result<T, FastbootError> {
    // 用临时 driver 只读探测 getvar:version：确认句柄真能 IO（坏句柄会在发包即失败）。
    // 单发不自重试。3s 上限必须设在 driver 上（落到 WinUSB 管道超时）：transport 的读写在 async 里
    // 同步阻塞，外面套 tokio::time::timeout 抢占不了，坏句柄会干等满常规 30s。
    let mut probe = driver::FastbootDriver::new(transport);
    probe.set_auto_retry(false);
    let normal_timeout = probe.timeout();
    probe.set_timeout(std::time::Duration::from_secs(3));
    let probed = probe.get_var("version").await;
    probe.set_timeout(normal_timeout);
    match probed {
        Ok(_) | Err(FastbootError::Device(_)) => Ok(probe.into_transport()),
        // 显式关闭再丢弃异常连接，原始错误（含原始回包诊断）交给外层退避重开。
        Err(error) => {
            let _ = probe.close_transport().await;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TransportError;
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};

    #[test]
    fn open_failure_retains_bad_probe_diagnostic_if_device_disappears() {
        let diagnostic = "协议异常：command=getvar:version actual=257 all_zero=true";
        let error = open_failure_with_protocol_context(FastbootError::NoDevice, Some(diagnostic));
        assert!(matches!(error, FastbootError::Protocol(_)));
        let message = error.to_string();
        assert!(message.contains(diagnostic));
        assert!(message.contains("最终连接失败: 无设备"));
        assert!(matches!(
            open_failure_with_protocol_context(FastbootError::NoDevice, None),
            FastbootError::NoDevice
        ));
    }

    #[derive(Debug)]
    struct ReplayTransport {
        reads: VecDeque<Result<Vec<u8>, TransportError>>,
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
        closed: Arc<Mutex<bool>>,
        timeouts: Arc<Mutex<Vec<std::time::Duration>>>,
    }

    impl ReplayTransport {
        fn new(reads: Vec<Result<Vec<u8>, TransportError>>) -> Self {
            Self {
                reads: reads.into(),
                writes: Arc::default(),
                closed: Arc::default(),
                timeouts: Arc::default(),
            }
        }
    }

    impl AsyncTransport for ReplayTransport {
        fn read<'a>(
            &'a mut self,
            buf: &'a mut [u8],
        ) -> Pin<Box<dyn Future<Output = Result<usize, TransportError>> + Send + 'a>> {
            Box::pin(async move {
                let data = self.reads.pop_front().expect("unexpected probe read")?;
                assert!(data.len() <= buf.len());
                buf[..data.len()].copy_from_slice(&data);
                Ok(data.len())
            })
        }

        fn write<'a>(
            &'a mut self,
            data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Result<usize, TransportError>> + Send + 'a>> {
            Box::pin(async move {
                self.writes.lock().unwrap().push(data.to_vec());
                Ok(data.len())
            })
        }

        fn close(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>> {
            Box::pin(async move {
                *self.closed.lock().unwrap() = true;
                Ok(())
            })
        }

        fn reset(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>> {
            Box::pin(async { panic!("probe must not retry on the same connection") })
        }

        fn set_timeout(&mut self, timeout: std::time::Duration) {
            self.timeouts.lock().unwrap().push(timeout);
        }
    }

    #[tokio::test]
    async fn probe_accepts_info_then_okay_and_restores_timeout() {
        let transport = ReplayTransport::new(vec![
            Ok(b"INFOchecking version".to_vec()),
            Ok(b"OKAY0.4".to_vec()),
        ]);
        let transport = probe_transport(transport).await.unwrap();
        assert!(transport.reads.is_empty());
        assert_eq!(
            *transport.writes.lock().unwrap(),
            vec![b"getvar:version".to_vec()]
        );
        assert!(!*transport.closed.lock().unwrap());
        let timeouts = transport.timeouts.lock().unwrap();
        assert_eq!(timeouts[0], std::time::Duration::from_secs(3));
        assert_eq!(
            timeouts.last().copied(),
            Some(std::time::Duration::from_secs(30))
        );
    }

    #[tokio::test]
    async fn probe_accepts_valid_device_fail() {
        let transport = ReplayTransport::new(vec![Ok(b"FAILunknown variable".to_vec())]);
        let transport = probe_transport(transport).await.unwrap();
        assert!(transport.reads.is_empty());
        assert!(!*transport.closed.lock().unwrap());
    }

    #[tokio::test]
    async fn probe_rejects_malformed_and_zero_status_and_closes_connection() {
        for response in [b"BOGUinvalid status".to_vec(), vec![0u8; 257]] {
            let transport = ReplayTransport::new(vec![Ok(response)]);
            let closed = transport.closed.clone();
            let error = probe_transport(transport).await.unwrap_err();
            assert!(matches!(error, FastbootError::Protocol(_)), "{error}");
            assert!(*closed.lock().unwrap());
        }
    }

    #[tokio::test]
    async fn probe_rejects_unexpected_data_phase() {
        let transport = ReplayTransport::new(vec![Ok(b"DATA00000004".to_vec())]);
        let closed = transport.closed.clone();
        assert!(matches!(
            probe_transport(transport).await,
            Err(FastbootError::Protocol(_))
        ));
        assert!(*closed.lock().unwrap());
    }

    #[tokio::test]
    async fn probe_preserves_timeout_and_transport_errors() {
        for transport_error in [
            TransportError::Timeout,
            TransportError::Usb("read completion failed".to_string()),
        ] {
            let transport = ReplayTransport::new(vec![Err(transport_error)]);
            let closed = transport.closed.clone();
            let error = probe_transport(transport).await.unwrap_err();
            assert!(matches!(
                error,
                FastbootError::Timeout | FastbootError::Transport(_)
            ));
            if let FastbootError::Transport(_) = &error {
                assert!(error.to_string().contains("read completion failed"));
            }
            assert!(*closed.lock().unwrap());
        }
    }
}
