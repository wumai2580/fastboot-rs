//! fastboot 传输抽象：`FastbootDriver` 只依赖这一个 trait，生产实现是 `usb_transport::UsbTransport`
//! （WinUSB），测试里换成回放设备回包的假传输层。
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::error::TransportError;

pub trait AsyncTransport: Send + Sync {
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize, TransportError>> + Send + 'a>>;

    fn write<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<usize, TransportError>> + Send + 'a>>;
    fn close(&mut self) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>>;
    fn reset(&mut self) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>>;
    fn reinitialize(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + '_>> {
        self.reset()
    }
    fn set_timeout(&mut self, _timeout: Duration) {}
    /// 有限的传输诊断字段。实现应只返回后端与接口元数据，不包含命令、回复或设备序列号。
    fn diagnostic_context(&self) -> String {
        "backend=generic".to_string()
    }
}

pub trait AsyncTransportExt: AsyncTransport {
    async fn write_all(&mut self, data: &[u8]) -> Result<(), TransportError> {
        let mut total = 0;
        while total < data.len() {
            let n = self.write(&data[total..]).await?;
            if n == 0 {
                return Err(TransportError::Disconnected);
            }
            total += n;
        }
        Ok(())
    }
    async fn read_with_timeout(
        &mut self,
        buf: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, TransportError> {
        self.set_timeout(timeout);
        tokio::time::timeout(timeout, self.read(buf))
            .await
            .map_err(|_| TransportError::Timeout)?
    }
}
impl<T: AsyncTransport + ?Sized> AsyncTransportExt for T {}
