use std::path::Path;
use std::time::Duration;

use tokio::fs::File;
use tokio::io::AsyncWriteExt;

use crate::error::{FastbootError, TransportError};
use crate::protocol::{self, Response, FB_COMMAND_SZ, FB_RESPONSE_SZ};
use crate::transport::{AsyncTransport, AsyncTransportExt};
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// flash 擦写阶段的独立长超时：super 等大分区擦写期间设备可能长时间不回包，
/// 用 30s 常规超时会误判超时并打断正在进行的刷写。600s 远大于单次 flash 实际耗时，足够安全。
const FLASH_TIMEOUT: Duration = Duration::from_secs(600);
/// reboot/boot/continue 这类命令一旦写出，设备会离开 fastboot，很多 bootloader 来不及回 OKAY。
/// 因此只给一个短确认窗口：能收到 FAIL 就报告失败；收到 OKAY、断链或超时都说明动作已下发。
const EXIT_FASTBOOT_RESPONSE_TIMEOUT: Duration = Duration::from_millis(1500);
const DOWNLOAD_CHUNK_SIZE: usize = 1024 * 1024;
const UPLOAD_CHUNK_SIZE: usize = 1024 * 1024;
const MAX_RETRY_COUNT: u32 = 3;
const RETRY_DELAY_MS: u64 = 500;
/// 超时重试前排空 IN 管道时的「安静」判据：这么久读不到任何字节就认为没有迟到的旧响应了。
const DRAIN_QUIET_WINDOW: Duration = Duration::from_millis(200);
const MAX_DRAINED_RESPONSES: usize = 64;
const RECOVER_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

pub type ProgressCallback = Box<dyn Fn(u64, u64) + Send + Sync>;
pub type InfoCallback = Box<dyn Fn(&str) + Send + Sync>;
pub struct DriverCallbacks {
    pub prolog: Box<dyn Fn(&str) + Send + Sync>,
    pub info: InfoCallback,
    pub text: Box<dyn Fn(&str) + Send + Sync>,
    pub progress: Option<ProgressCallback>,
}

impl Default for DriverCallbacks {
    fn default() -> Self {
        Self {
            prolog: Box::new(|_| {}),
            info: Box::new(|_| {}),
            text: Box::new(|_| {}),
            progress: None,
        }
    }
}

pub struct FastbootDriver<T: AsyncTransport> {
    transport: T,
    callbacks: DriverCallbacks,
    timeout: Duration,
    max_download_size: Option<u64>,
    auto_retry: bool,
}

impl<T: AsyncTransport> FastbootDriver<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            callbacks: DriverCallbacks::default(),
            timeout: DEFAULT_TIMEOUT,
            max_download_size: None,
            auto_retry: true,
        }
    }
    /// 消费 driver，取回底层 transport。
    /// 用于 open 阶段：用临时 driver 探测句柄能否真正 IO 后，把可用连接交还调用方。
    pub fn into_transport(self) -> T {
        self.transport
    }
    pub fn set_callbacks(&mut self, callbacks: DriverCallbacks) {
        self.callbacks = callbacks;
    }
    /// 设置传输进度回调。统一语义：回调收到 `(delta, total)`，`delta` 是本块字节增量（非累计），
    /// send/recv 两侧一致，调用方按增量累加得到当前进度。
    pub fn set_progress_callback(&mut self, callback: ProgressCallback) {
        self.callbacks.progress = Some(callback);
    }
    /// 设置 INFO 回调（设备在 flash/erase 等阶段回传的 INFO 心跳，含进度文本时调用方可据此推进进度）。
    /// 单独设置，不影响已设置的 progress 回调。
    pub fn set_info_callback(&mut self, callback: Box<dyn Fn(&str) + Send + Sync>) {
        self.callbacks.info = callback;
    }
    /// 设置 prolog 回调（命令开始时触发，如 "Writing 'super'" / "Erasing 'userdata'"）。
    pub fn set_prolog_callback(&mut self, callback: Box<dyn Fn(&str) + Send + Sync>) {
        self.callbacks.prolog = callback;
    }
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
        self.transport.set_timeout(timeout);
    }
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
    pub fn set_auto_retry(&mut self, enabled: bool) {
        self.auto_retry = enabled;
    }

    pub async fn deep_reset(&mut self) -> Result<(), FastbootError> {
        self.transport
            .reinitialize()
            .await
            .map_err(FastbootError::Transport)
    }

    /// 主动释放底层 transport 的通信句柄（不重开）。用于重连前先腾出接口：driver 里那条坏链路的
    /// 旧句柄若不先释放，紧接的重开 open 会撞未释放句柄得 ACCESS_DENIED（Windows 侧「端口被占用」）。
    pub async fn close_transport(&mut self) -> Result<(), FastbootError> {
        self.transport
            .close()
            .await
            .map_err(FastbootError::Transport)
    }

    /// 超时后、重发命令前的链路自检。fastboot 响应不带序号：原命令的响应可能只是来晚了，
    /// 不先排空的话探测会读到它、重发的命令又读到探测的响应，此后每条命令都错一位。
    /// 迟到的响应也可能落在第一次排空之后，故「排空 → 探测 → 再排空」。
    /// transport 的读在 async 里同步阻塞，超时必须设到 transport 上，tokio 计时器抢占不了。
    async fn try_recover(&mut self) -> Result<(), FastbootError> {
        // reset 失败不致命：接下来的探测才是链路是否可用的判据。
        let _ = self.transport.reset().await;
        tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
        self.drain_stale_responses().await;
        let probed = self.probe_version().await;
        self.drain_stale_responses().await;
        self.transport.set_timeout(self.timeout);
        probed
    }

    async fn probe_version(&mut self) -> Result<(), FastbootError> {
        let previous_timeout = self.timeout;
        self.set_timeout(RECOVER_PROBE_TIMEOUT);
        let result = self.send_command_internal("getvar:version").await;
        self.set_timeout(previous_timeout);
        match result? {
            // 不支持 version 的合法 FAIL 同样证明状态通道可用；垃圾字节不算应答。
            (Response::Okay(_) | Response::Fail(_), _) => Ok(()),
            _ => Err(FastbootError::Protocol(
                "getvar:version 探测返回了非终态响应".into(),
            )),
        }
    }

    /// 以短超时连续读，直到 IN 管道安静，丢掉迟到的旧响应。
    async fn drain_stale_responses(&mut self) {
        self.transport.set_timeout(DRAIN_QUIET_WINDOW);
        let mut buf = [0u8; FB_RESPONSE_SZ + 1];
        for _ in 0..MAX_DRAINED_RESPONSES {
            match self.transport.read(&mut buf).await {
                Ok(n) if n > 0 => {}
                _ => break,
            }
        }
    }

    pub async fn check_connection(&mut self) -> Result<bool, FastbootError> {
        match self.get_var("version").await {
            Ok(_) => Ok(true),
            Err(FastbootError::Transport(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub async fn get_var(&mut self, key: &str) -> Result<String, FastbootError> {
        let cmd = format!("{}:{}", protocol::FB_CMD_GETVAR, key);
        let response = self.raw_command(&cmd).await?;

        match response {
            Response::Okay(val) => Ok(val),
            Response::Fail(msg) => Err(FastbootError::Device(msg)),
            _ => Err(FastbootError::Protocol("Unexpected response".into())),
        }
    }
    pub async fn get_var_all(&mut self) -> Result<Vec<String>, FastbootError> {
        let cmd = format!("{}:all", protocol::FB_CMD_GETVAR);
        let (response, info_messages) = self.raw_command_with_info(&cmd).await?;
        match response {
            Response::Okay(_) => Ok(info_messages),
            Response::Fail(msg) => Err(FastbootError::Device(msg)),
            _ => Err(FastbootError::Protocol(
                "getvar:all 返回了非终态响应".into(),
            )),
        }
    }
    pub async fn get_max_download_size(&mut self) -> Result<u64, FastbootError> {
        if let Some(size) = self.max_download_size {
            return Ok(size);
        }

        let size = match self.get_var("max-download-size").await {
            Ok(size_str) => parse_size(&size_str).unwrap_or(256 * 1024 * 1024),
            Err(_) => 256 * 1024 * 1024,
        };
        self.max_download_size = Some(size);
        Ok(size)
    }

    pub async fn download(&mut self, data: &[u8]) -> Result<(), FastbootError> {
        if data.is_empty() {
            return Err(FastbootError::InvalidArg("待下载数据为空".into()));
        }
        check_download_len(data.len() as u64)?;
        let cmd = format!("{}:{:08x}", protocol::FB_CMD_DOWNLOAD, data.len());
        // DATA 阶段命令绝不能 auto_retry：`download:SIZE` 发出后设备即进入收数据阶段，超时重发
        // （含 try_recover 先写的 getvar:version）会被设备当成镜像内容吞掉，协议错位/写坏分区。
        // 与 flash() 同理，走不重试的 send_command_internal。
        let (response, _) = self.send_command_internal(&cmd).await?;
        let expected_size = match response {
            Response::Data(size) => size as usize,
            Response::Fail(msg) => return Err(FastbootError::Device(msg)),
            _ => return Err(FastbootError::Protocol("Expected DATA response".into())),
        };

        if expected_size != data.len() {
            return Err(FastbootError::Protocol(format!(
                "Size mismatch: expected {}, got {}",
                data.len(),
                expected_size
            )));
        }
        self.send_data(data).await?;
        let (final_response, _) = self.read_response_with_info(&cmd).await?;
        match final_response {
            Response::Okay(_) => Ok(()),
            Response::Fail(msg) => Err(FastbootError::Device(msg)),
            _ => Err(FastbootError::Protocol(
                "Expected OKAY after download".into(),
            )),
        }
    }

    pub async fn upload_to_file(&mut self, path: &Path) -> Result<u64, FastbootError> {
        // 同 upload()：进入发数据阶段的握手不重试。
        let (response, _) = self.send_command_internal(protocol::FB_CMD_UPLOAD).await?;

        let size = match response {
            Response::Data(size) => size as u64,
            Response::Fail(msg) => return Err(FastbootError::Device(msg)),
            _ => return Err(FastbootError::Protocol("Expected DATA response".into())),
        };
        let mut file = File::create(path).await.map_err(FastbootError::Io)?;
        let received = self.recv_data_to_file(&mut file, size).await?;
        let (final_response, _) = self
            .read_response_with_info(protocol::FB_CMD_UPLOAD)
            .await?;
        match final_response {
            Response::Okay(_) => Ok(received),
            Response::Fail(msg) => Err(FastbootError::Device(msg)),
            _ => Err(FastbootError::Protocol("Expected OKAY after upload".into())),
        }
    }

    /// `fastboot fetch`：把分区（或其片段）回读到本地文件。
    ///
    /// `spec` 形如 `partition` 或 `partition:offset[:size]`（offset/size 支持十进制与 `0x` 十六进制）。
    /// 与 AOSP `do_fetch` 一致：指定了 offset 就单发一条；否则设备报了 `max-fetch-size` 与
    /// `partition-size` 时按 max-fetch-size 分块，逐块 `fetch:<part>:0x<off>:0x<len>` 追加写入；
    /// 两者任一查不到则退回单条 `fetch:<part>`。
    pub async fn read_partition(&mut self, spec: &str, path: &Path) -> Result<u64, FastbootError> {
        let (partition, offset, size) = parse_fetch_spec(spec)?;
        let mut file = File::create(path).await.map_err(FastbootError::Io)?;

        if offset.is_some() {
            return self
                .fetch_to_file(&partition, offset, size, &mut file)
                .await;
        }

        let max_fetch = match self.get_var("max-fetch-size").await {
            Ok(v) => parse_size(&v).ok().filter(|&n| n > 0),
            Err(_) => None,
        };
        let part_size = match max_fetch {
            Some(_) => match self
                .get_var(&format!(
                    "{}:{}",
                    protocol::FB_VAR_PARTITION_SIZE,
                    partition
                ))
                .await
            {
                Ok(v) => parse_size(&v).ok().filter(|&n| n > 0),
                Err(_) => None,
            },
            None => None,
        };

        let (Some(chunk), Some(total)) = (max_fetch, part_size) else {
            return self.fetch_to_file(&partition, None, None, &mut file).await;
        };
        let mut done = 0u64;
        while done < total {
            let len = chunk.min(total - done);
            let got = self
                .fetch_to_file(&partition, Some(done), Some(len), &mut file)
                .await?;
            if got == 0 {
                return Err(FastbootError::Protocol(format!(
                    "fetch {partition} 在偏移 0x{done:x} 处设备回了 0 字节"
                )));
            }
            done += got;
        }
        Ok(done)
    }

    /// 单条 fetch：AOSP 语义是设备直接回 `DATA<len>`、随后发 len 字节、再回 OKAY（与 upload 同构）。
    /// 兼容少数厂商旧实现：fetch 先回 OKAY 把数据暂存，再由 `upload` 取回。
    /// fetch 是只读命令，但进入 DATA 阶段后绝不能重发（会与在途数据错位），故走不重试通道。
    async fn fetch_to_file(
        &mut self,
        partition: &str,
        offset: Option<u64>,
        size: Option<u64>,
        file: &mut File,
    ) -> Result<u64, FastbootError> {
        let mut cmd = format!("{}:{}", protocol::FB_CMD_FETCH, partition);
        if let Some(off) = offset {
            cmd.push_str(&format!(":0x{:08x}", off));
            if let Some(len) = size {
                cmd.push_str(&format!(":0x{:08x}", len));
            }
        }
        check_command_len(&cmd)?;
        (self.callbacks.prolog)(&format!("Fetching '{}'", partition));
        let (response, _) = self.send_command_internal(&cmd).await?;
        match response {
            Response::Data(len) => {
                let received = self.recv_data_to_file(file, len as u64).await?;
                let (final_response, _) = self.read_response_with_info(&cmd).await?;
                match final_response {
                    Response::Okay(_) => Ok(received),
                    Response::Fail(msg) => Err(FastbootError::Device(msg)),
                    _ => Err(FastbootError::Protocol("Expected OKAY after fetch".into())),
                }
            }
            Response::Okay(_) => {
                let (response, _) = self.send_command_internal(protocol::FB_CMD_UPLOAD).await?;
                let len = match response {
                    Response::Data(len) => len as u64,
                    Response::Fail(msg) => return Err(FastbootError::Device(msg)),
                    _ => return Err(FastbootError::Protocol("Expected DATA response".into())),
                };
                let received = self.recv_data_to_file(file, len).await?;
                let (final_response, _) = self
                    .read_response_with_info(protocol::FB_CMD_UPLOAD)
                    .await?;
                match final_response {
                    Response::Okay(_) => Ok(received),
                    Response::Fail(msg) => Err(FastbootError::Device(msg)),
                    _ => Err(FastbootError::Protocol("Expected OKAY after upload".into())),
                }
            }
            Response::Fail(msg) => Err(FastbootError::Device(msg)),
            _ => Err(FastbootError::Protocol(
                "Expected DATA or OKAY for fetch".into(),
            )),
        }
    }

    pub async fn flash(&mut self, partition: &str) -> Result<(), FastbootError> {
        let cmd = format!("{}:{}", protocol::FB_CMD_FLASH, partition);
        (self.callbacks.prolog)(&format!("Writing '{}'", partition));

        // flash 期间设备擦除+写入，super 等大分区可能数分钟不回包：
        // 1) 用独立长超时（FLASH_TIMEOUT）代替常规 30s，避免把进行中的擦写误判为超时；
        // 2) 不重试：flash 发出后超时重发会打断正在进行的擦写（连续刷写卡顿/打断的根因）。
        // send_command_internal 会把 INFO 心跳转给 callbacks.info，flash 期间可持续更新进度。
        let prev_timeout = self.timeout;
        self.set_timeout(FLASH_TIMEOUT.max(prev_timeout));

        let result = self.send_command_internal(&cmd).await;

        self.set_timeout(prev_timeout);

        let (response, _info) = result?;
        match response {
            Response::Okay(_) => Ok(()),
            Response::Fail(msg) => Err(FastbootError::Device(msg)),
            _ => Err(FastbootError::Protocol("Unexpected response".into())),
        }
    }
    pub async fn erase(&mut self, partition: &str) -> Result<(), FastbootError> {
        let cmd = format!("{}:{}", protocol::FB_CMD_ERASE, partition);
        (self.callbacks.prolog)(&format!("Erasing '{}'", partition));

        // 擦除是状态变更且可能长耗时：超时重发会打断进行中的擦除，故走不重试通道。
        let response = self.command_no_retry(&cmd).await?;
        match response {
            Response::Okay(_) => Ok(()),
            Response::Fail(msg) => Err(FastbootError::Device(msg)),
            _ => Err(FastbootError::Protocol("Unexpected response".into())),
        }
    }

    pub async fn boot(&mut self) -> Result<(), FastbootError> {
        // 一次性动作（跳转到已下载镜像）：设备可能在 OKAY 前断开，按离开 fastboot 的语义收尾。
        let response = self.command_exiting_fastboot(protocol::FB_CMD_BOOT).await?;
        match response {
            Response::Okay(_) => Ok(()),
            Response::Fail(msg) => Err(FastbootError::Device(msg)),
            _ => Err(FastbootError::Protocol("Unexpected response".into())),
        }
    }
    pub async fn continue_boot(&mut self) -> Result<(), FastbootError> {
        // 一次性动作（继续引导）：设备可能在 OKAY 前断开，按离开 fastboot 的语义收尾。
        let response = self
            .command_exiting_fastboot(protocol::FB_CMD_CONTINUE)
            .await?;
        match response {
            Response::Okay(_) => Ok(()),
            Response::Fail(msg) => Err(FastbootError::Device(msg)),
            _ => Err(FastbootError::Protocol("Unexpected response".into())),
        }
    }
    pub async fn reboot(&mut self) -> Result<(), FastbootError> {
        // 重启是一次性动作、之后链路即断：不重试，且不能把“没来得及回 OKAY”当失败/长时间卡住。
        let response = self
            .command_exiting_fastboot(protocol::FB_CMD_REBOOT)
            .await?;
        match response {
            Response::Okay(_) => Ok(()),
            Response::Fail(msg) => Err(FastbootError::Device(msg)),
            _ => Err(FastbootError::Protocol("Unexpected response".into())),
        }
    }
    pub async fn reboot_to(&mut self, target: &str) -> Result<(), FastbootError> {
        let cmd = format!("reboot-{}", target);
        // 定向重启同样是一次性动作，设备可能在 OKAY 前就切到目标模式。
        let response = self.command_exiting_fastboot(&cmd).await?;
        match response {
            Response::Okay(_) => Ok(()),
            Response::Fail(msg) => Err(FastbootError::Device(msg)),
            _ => Err(FastbootError::Protocol("Unexpected response".into())),
        }
    }
    pub async fn set_active(&mut self, slot: &str) -> Result<(), FastbootError> {
        let cmd = format!("{}:{}", protocol::FB_CMD_SET_ACTIVE, slot);
        // 切换活动槽是状态变更：不重试。
        let response = self.command_no_retry(&cmd).await?;
        match response {
            Response::Okay(_) => Ok(()),
            Response::Fail(msg) => Err(FastbootError::Device(msg)),
            _ => Err(FastbootError::Protocol("Unexpected response".into())),
        }
    }

    pub async fn create_partition(&mut self, name: &str, size: u64) -> Result<(), FastbootError> {
        let cmd = format!("{}:{}:{}", protocol::FB_CMD_CREATE_PARTITION, name, size);
        // 非幂等：重发会二次创建、误报“已存在”。不重试。
        let response = self.command_no_retry(&cmd).await?;
        match response {
            Response::Okay(_) => Ok(()),
            Response::Fail(msg) => Err(FastbootError::Device(msg)),
            _ => Err(FastbootError::Protocol("Unexpected response".into())),
        }
    }
    pub async fn delete_partition(&mut self, name: &str) -> Result<(), FastbootError> {
        let cmd = format!("{}:{}", protocol::FB_CMD_DELETE_PARTITION, name);
        // 非幂等：重发会误报“不存在”。不重试。
        let response = self.command_no_retry(&cmd).await?;
        match response {
            Response::Okay(_) => Ok(()),
            Response::Fail(msg) => Err(FastbootError::Device(msg)),
            _ => Err(FastbootError::Protocol("Unexpected response".into())),
        }
    }
    pub async fn resize_partition(&mut self, name: &str, size: u64) -> Result<(), FastbootError> {
        let cmd = format!("{}:{}:{}", protocol::FB_CMD_RESIZE_PARTITION, name, size);
        // 逻辑分区状态变更：不重试。
        let response = self.command_no_retry(&cmd).await?;
        match response {
            Response::Okay(_) => Ok(()),
            Response::Fail(msg) => Err(FastbootError::Device(msg)),
            _ => Err(FastbootError::Protocol("Unexpected response".into())),
        }
    }

    /// oem 透传命令的「完整回显」通道：返回设备的**终态响应**（OKAY/FAIL/…）与**全部** INFO 行，
    /// 二者都不丢弃、也不把 FAIL 映射成错误——成败与回显策略交由调用方决定（CLI / raw 风格）。
    /// `oem get_token` / `oem get_unlock_data` 这类命令的数据全部分布在多条 INFO 行里（单条 payload
    /// 上限 252B，OKAY 往往为空），只读 OKAY 或在 FAIL 时丢 INFO 都会把 token 截断。
    /// 按官方线上格式以 "oem " 空格前缀下发（小米等 bootloader 按 "oem " 前缀匹配，`oem:edl` 会回
    /// unknown command）；oem 多为非幂等的厂商动作，不自动重试。
    pub async fn oem_command_collect(
        &mut self,
        cmd: &str,
    ) -> Result<(Response, Vec<String>), FastbootError> {
        let full_cmd = format!("{} {}", protocol::FB_CMD_OEM, cmd);
        self.command_no_retry_with_info(&full_cmd).await
    }

    pub async fn raw_command(&mut self, cmd: &str) -> Result<Response, FastbootError> {
        let (response, _) = self.raw_command_with_info(cmd).await?;
        Ok(response)
    }
    /// 非幂等/状态变更类命令的单发通道：保留命令长度校验，但绝不 auto_retry——这类命令发出后
    /// 可能已在设备侧生效，超时重发会重复执行（oem 触发两次、create/delete 分区误报、erase 被
    /// 打断）。只读命令（如 getvar）仍走 raw_command 重试。
    pub async fn command_no_retry(&mut self, cmd: &str) -> Result<Response, FastbootError> {
        let (response, _) = self.command_no_retry_with_info(cmd).await?;
        Ok(response)
    }

    /// 同 [`Self::command_no_retry`]，但把设备的 INFO 行一并返回（供 `oem get_token` 等靠 INFO
    /// 分行回数据的命令使用）。
    pub async fn command_no_retry_with_info(
        &mut self,
        cmd: &str,
    ) -> Result<(Response, Vec<String>), FastbootError> {
        check_command_len(cmd)?;
        self.send_command_internal(cmd).await
    }

    /// 发送会让设备离开 fastboot 的动作命令。协议允许先回 OKAY 再断开，但不少 bootloader 直接断 USB：
    /// 仅当命令字节已成功写出后，才把响应阶段的 NoLink/Disconnected/Timeout 视为「设备开始离开
    /// fastboot」；写命令失败仍必须报错。
    async fn command_exiting_fastboot(&mut self, cmd: &str) -> Result<Response, FastbootError> {
        check_command_len(cmd)?;

        self.transport
            .write_all(cmd.as_bytes())
            .await
            .map_err(map_transport_error)?;

        let previous_timeout = self.timeout;
        self.set_timeout(EXIT_FASTBOOT_RESPONSE_TIMEOUT);

        let result = loop {
            match self.handle_response(cmd).await {
                Ok(Response::Info(msg)) => {
                    (self.callbacks.info)(&msg);
                }
                Ok(Response::Text(msg)) => {
                    (self.callbacks.text)(&msg);
                }
                Ok(response) => break Ok(response),
                Err(error) if is_exit_fastboot_completion(&error) => {
                    break Ok(Response::Okay(String::new()));
                }
                Err(error) => break Err(error),
            }
        };

        self.set_timeout(previous_timeout);
        result
    }

    /// 只读/幂等命令的通道：可恢复错误（超时、IO）时先 [`Self::try_recover`] 再按指数退避重发，
    /// 最多 [`MAX_RETRY_COUNT`] 次（`set_auto_retry(false)` 时只发一次）。
    pub async fn raw_command_with_info(
        &mut self,
        cmd: &str,
    ) -> Result<(Response, Vec<String>), FastbootError> {
        check_command_len(cmd)?;
        let max_attempts = if self.auto_retry { MAX_RETRY_COUNT } else { 1 };
        let mut last_error = None;

        for attempt in 0..max_attempts {
            match self.send_command_internal(cmd).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if !e.is_recoverable() || attempt + 1 >= max_attempts {
                        return Err(e);
                    }
                    last_error = Some(e);
                    if self.try_recover().await.is_err() {
                        return Err(
                            last_error.unwrap_or(FastbootError::Transport(TransportError::NoLink))
                        );
                    }
                    let delay = RETRY_DELAY_MS * (1 << attempt);
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
            }
        }

        Err(last_error.unwrap_or(FastbootError::Timeout))
    }
    async fn send_command_internal(
        &mut self,
        cmd: &str,
    ) -> Result<(Response, Vec<String>), FastbootError> {
        self.transport
            .write_all(cmd.as_bytes())
            .await
            .map_err(map_transport_error)?;
        self.read_response_with_info(cmd).await
    }

    /// 命令应答与 DATA 完成应答共用状态循环：INFO/TEXT 是中间消息，必须读到终态。
    /// 此处只读响应，绝不重发命令或 DATA。
    async fn read_response_with_info(
        &mut self,
        cmd: &str,
    ) -> Result<(Response, Vec<String>), FastbootError> {
        let mut info_messages = Vec::new();
        loop {
            let response = self.handle_response(cmd).await?;

            match &response {
                Response::Info(msg) => {
                    (self.callbacks.info)(msg);
                    info_messages.push(msg.clone());
                }
                Response::Text(msg) => {
                    (self.callbacks.text)(msg);
                }
                _ => {
                    return Ok((response, info_messages));
                }
            }
        }
    }
    async fn handle_response(&mut self, cmd: &str) -> Result<Response, FastbootError> {
        let mut buf = [0u8; FB_RESPONSE_SZ + 1];

        let n = self
            .transport
            .read_with_timeout(&mut buf, self.timeout)
            .await
            .map_err(|e| match &e {
                TransportError::Timeout => FastbootError::Timeout,
                TransportError::Disconnected | TransportError::NoLink => {
                    FastbootError::Transport(TransportError::NoLink)
                }
                TransportError::Usb(msg) => {
                    FastbootError::Transport(TransportError::from_usb_error(msg))
                }
                _ => FastbootError::Transport(e),
            })?;

        if n == 0 {
            return Err(FastbootError::Transport(TransportError::NoLink));
        }

        // 多留的一字节用于识别超长状态包，不应把它当作合法 257 字节状态。
        // 同时防止异常后端返回超出缓冲区的计数时因切片越界而 panic。
        if n > FB_RESPONSE_SZ {
            return Err(self.response_error(cmd, &buf, n, "设备返回超长状态包"));
        }

        let (response, _) = Response::parse(&buf[..n]).map_err(|e| {
            let reason = match e {
                protocol::ParseError::UnknownPrefix { .. } => "设备返回未知状态行",
                protocol::ParseError::TooShort { .. } => "设备返回过短状态包",
                protocol::ParseError::InvalidDataSize { .. } => "设备返回无效 DATA 大小",
            };
            self.response_error(cmd, &buf, n, reason)
        })?;

        Ok(response)
    }

    fn response_error(&self, cmd: &str, buf: &[u8], n: usize, reason: &str) -> FastbootError {
        let actual = &buf[..n.min(buf.len())];
        let (command, preview_allowed) = response_diagnostic_command(cmd);
        let all_zero = !actual.is_empty() && actual.iter().all(|&byte| byte == 0);
        let preview = if preview_allowed {
            let hex = actual
                .iter()
                .take(32)
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
            format!(
                "prefix_hex=[{hex}] preview={:?}",
                String::from_utf8_lossy(&actual[..actual.len().min(64)])
            )
        } else {
            "preview=<redacted>".to_string()
        };
        FastbootError::Protocol(format!(
            "{reason}: command={command} requested={} actual={n} max={FB_RESPONSE_SZ} all_zero={all_zero} {} {preview}",
            buf.len(),
            self.transport.diagnostic_context(),
        ))
    }
    async fn send_data(&mut self, data: &[u8]) -> Result<(), FastbootError> {
        let total = data.len() as u64;

        for chunk in data.chunks(DOWNLOAD_CHUNK_SIZE) {
            self.transport
                .write_all(chunk)
                .await
                .map_err(FastbootError::Transport)?;

            // 进度统一语义：上报「本块增量 / 总字节」，与 recv 侧一致（详见 set_progress_callback）。
            if let Some(ref progress) = self.callbacks.progress {
                progress(chunk.len() as u64, total);
            }
        }

        Ok(())
    }
    async fn recv_data_to_file(
        &mut self,
        file: &mut File,
        total: u64,
    ) -> Result<u64, FastbootError> {
        let mut buf = vec![0u8; UPLOAD_CHUNK_SIZE];
        let mut received = 0u64;

        while received < total {
            let to_read = std::cmp::min(buf.len() as u64, total - received) as usize;
            let n = self
                .transport
                .read(&mut buf[..to_read])
                .await
                .map_err(FastbootError::Transport)?;

            if n == 0 {
                return Err(FastbootError::Transport(TransportError::Disconnected));
            }

            file.write_all(&buf[..n]).await.map_err(FastbootError::Io)?;
            received += n as u64;

            // 进度统一语义：上报「本次读取增量 / 总字节」（详见 set_progress_callback）。
            if let Some(ref progress) = self.callbacks.progress {
                progress(n as u64, total);
            }
        }

        file.flush().await.map_err(FastbootError::Io)?;
        Ok(received)
    }
}

/// 只保留可识别的命令名和变量名；OEM/解锁参数与敏感变量的异常正文不能写入诊断。
fn response_diagnostic_command(cmd: &str) -> (String, bool) {
    if let Some(var) = cmd.strip_prefix("getvar:") {
        if var.len() <= 80
            && !var.is_empty()
            && var
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-:".contains(&byte))
        {
            let preview_allowed = matches!(
                var,
                "all"
                    | "version"
                    | "version-bootloader"
                    | "product"
                    | "is-userspace"
                    | "current-slot"
                    | "unlocked"
                    | "slot-count"
                    | "max-download-size"
            );
            return (cmd.to_string(), preview_allowed);
        }
        return ("getvar:<redacted>".to_string(), false);
    }
    if let Some(size) = cmd.strip_prefix("download:") {
        if size.len() == 8 && size.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return (cmd.to_string(), true);
        }
        return ("download:<redacted>".to_string(), false);
    }
    if cmd == "upload" {
        return (cmd.to_string(), true);
    }
    let name = cmd.split([':', ' ']).next().unwrap_or_default();
    let label = match name {
        "oem" | "flashing" => format!("{name} <redacted>"),
        "flash"
        | "erase"
        | "fetch"
        | "boot"
        | "continue"
        | "set_active"
        | "reboot"
        | "reboot-bootloader"
        | "reboot-fastboot"
        | "reboot-recovery"
        | "reboot-edl"
        | "create-logical-partition"
        | "delete-logical-partition"
        | "resize-logical-partition" => name.to_string(),
        _ => "<redacted>".to_string(),
    };
    (label, false)
}

/// `download:%08x` 的长度字段是 8 位十六进制（u32）。超过 4 GiB−1 时 `{:08x}` 会静默
/// 产出 9+ 位十六进制，设备按前 8 位或未定义方式解析，随后的数据流必然错位；
/// 与 AOSP fastboot 一致，在发起握手前就拒绝（官方对超限直接报 "file is too large"）。
fn check_download_len(len: u64) -> Result<(), FastbootError> {
    if len > u32::MAX as u64 {
        return Err(FastbootError::ImageTooLarge(len, u32::MAX as u64));
    }
    Ok(())
}

/// 命令包上限 [`FB_COMMAND_SZ`]（AOSP `FB_COMMAND_SZ`）：超长命令设备会截断执行，发之前就拒绝。
fn check_command_len(cmd: &str) -> Result<(), FastbootError> {
    if cmd.len() > FB_COMMAND_SZ {
        return Err(FastbootError::InvalidArg(format!(
            "Command too long: {} bytes (max {})",
            cmd.len(),
            FB_COMMAND_SZ
        )));
    }
    Ok(())
}

/// 拆 `partition[:offset[:size]]`。offset/size 接受十进制或 `0x` 十六进制。
pub(crate) fn parse_fetch_spec(
    spec: &str,
) -> Result<(String, Option<u64>, Option<u64>), FastbootError> {
    let mut parts = spec.trim().split(':');
    let partition = parts.next().unwrap_or_default().trim().to_string();
    if partition.is_empty() {
        return Err(FastbootError::InvalidArg("fetch 需要分区名".into()));
    }
    let mut num = |what: &str| -> Result<Option<u64>, FastbootError> {
        match parts.next().map(str::trim) {
            None | Some("") => Ok(None),
            Some(v) => parse_size(v)
                .map(Some)
                .map_err(|_| FastbootError::InvalidArg(format!("fetch 的 {what} 非法: {v}"))),
        }
    };
    let offset = num("offset")?;
    let size = num("size")?;
    if parts.next().is_some() {
        return Err(FastbootError::InvalidArg(format!(
            "fetch 参数过多: {spec}（格式 partition[:offset[:size]]）"
        )));
    }
    if size.is_some() && offset.is_none() {
        return Err(FastbootError::InvalidArg(
            "指定 size 时必须同时指定 offset".into(),
        ));
    }
    Ok((partition, offset, size))
}

fn parse_size(s: &str) -> Result<u64, FastbootError> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16)
    } else {
        s.parse()
    }
    .map_err(|_| FastbootError::Protocol(format!("Invalid size: {}", s)))
}

fn map_transport_error(error: TransportError) -> FastbootError {
    match &error {
        TransportError::Usb(message) => {
            FastbootError::Transport(TransportError::from_usb_error(message))
        }
        _ => FastbootError::Transport(error),
    }
}

fn is_exit_fastboot_completion(error: &FastbootError) -> bool {
    match error {
        FastbootError::Timeout => true,
        FastbootError::Transport(TransportError::Timeout) => true,
        FastbootError::Transport(TransportError::NoLink | TransportError::Disconnected) => true,
        FastbootError::Transport(TransportError::Io(io)) => matches!(
            io.kind(),
            std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::NotConnected
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn response_diagnostics_hide_auth_arguments_and_response_bytes() {
        let driver = FastbootDriver::new(MockTransport::new(Vec::new()));
        let reply = b"secret-signature";
        let diagnostic = driver
            .response_error("oem auth secret-token", reply, reply.len(), "bad response")
            .to_string();
        assert!(!diagnostic.contains("secret-token"));
        assert!(!diagnostic.contains("secret-signature"));
        assert!(diagnostic.contains("preview=<redacted>"));
        assert!(diagnostic.contains("command=oem"));
        assert_eq!(
            response_diagnostic_command("getvar:version"),
            ("getvar:version".into(), true)
        );
        assert!(!response_diagnostic_command("getvar:token").1);
        assert!(!response_diagnostic_command("custom secret-token").1);
    }

    use super::*;
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::Pin;

    struct MockTransport {
        writes: Vec<Vec<u8>>,
        reads: VecDeque<Result<Vec<u8>, TransportError>>,
        write_error: Option<TransportError>,
        reported_read_len: Option<usize>,
        timeout: Duration,
    }

    impl MockTransport {
        fn new(reads: Vec<Result<Vec<u8>, TransportError>>) -> Self {
            Self {
                writes: Vec::new(),
                reads: reads.into(),
                write_error: None,
                reported_read_len: None,
                timeout: DEFAULT_TIMEOUT,
            }
        }

        fn with_write_error(error: TransportError) -> Self {
            Self {
                writes: Vec::new(),
                reads: VecDeque::new(),
                write_error: Some(error),
                reported_read_len: None,
                timeout: DEFAULT_TIMEOUT,
            }
        }
    }

    impl AsyncTransport for MockTransport {
        fn read<'a>(
            &'a mut self,
            buf: &'a mut [u8],
        ) -> Pin<Box<dyn Future<Output = Result<usize, TransportError>> + Send + 'a>> {
            Box::pin(async move {
                match self
                    .reads
                    .pop_front()
                    .unwrap_or(Err(TransportError::Timeout))
                {
                    Ok(data) => {
                        let n = data.len().min(buf.len());
                        buf[..n].copy_from_slice(&data[..n]);
                        Ok(self.reported_read_len.unwrap_or(n))
                    }
                    Err(error) => Err(error),
                }
            })
        }

        fn write<'a>(
            &'a mut self,
            data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Result<usize, TransportError>> + Send + 'a>> {
            Box::pin(async move {
                if let Some(error) = self.write_error.take() {
                    return Err(error);
                }
                self.writes.push(data.to_vec());
                Ok(data.len())
            })
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

        fn set_timeout(&mut self, timeout: Duration) {
            self.timeout = timeout;
        }
    }

    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("1234").unwrap(), 1234);
        assert_eq!(parse_size("0x1234").unwrap(), 0x1234);
        assert_eq!(parse_size("0X1234").unwrap(), 0x1234);
        assert_eq!(parse_size("  1234  ").unwrap(), 1234);
        assert!(parse_size("invalid").is_err());
    }

    #[test]
    fn fetch_spec_parses_offset_and_size() {
        assert_eq!(
            parse_fetch_spec("boot").unwrap(),
            ("boot".into(), None, None)
        );
        assert_eq!(
            parse_fetch_spec("boot:0x1000:4096").unwrap(),
            ("boot".into(), Some(0x1000), Some(4096))
        );
        assert_eq!(
            parse_fetch_spec("boot:16").unwrap(),
            ("boot".into(), Some(16), None)
        );
        assert!(parse_fetch_spec("").is_err());
        assert!(parse_fetch_spec("boot::10").is_err());
        assert!(parse_fetch_spec("boot:1:2:3").is_err());
        assert!(parse_fetch_spec("boot:xyz").is_err());
    }

    fn temp_out(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("rmf-fetch-{}-{}", name, std::process::id()))
    }

    /// AOSP fetch：设备直接回 DATA，不能再等 OKAY、也不能多发 upload。
    #[tokio::test]
    async fn fetch_follows_aosp_data_flow_and_chunks_by_max_fetch_size() {
        let reads = vec![
            Ok(b"OKAY0x4".to_vec()), // max-fetch-size
            Ok(b"OKAY0x6".to_vec()), // partition-size:boot
            Ok(b"DATA00000004".to_vec()),
            Ok(b"abcd".to_vec()),
            Ok(b"OKAY".to_vec()),
            Ok(b"DATA00000002".to_vec()),
            Ok(b"ef".to_vec()),
            Ok(b"OKAY".to_vec()),
        ];
        let mut driver = FastbootDriver::new(MockTransport::new(reads));
        let out = temp_out("chunk");
        let n = driver.read_partition("boot", &out).await.unwrap();
        assert_eq!(n, 6);
        assert_eq!(std::fs::read(&out).unwrap(), b"abcdef");
        let writes: Vec<String> = driver
            .transport
            .writes
            .iter()
            .map(|w| String::from_utf8_lossy(w).into_owned())
            .collect();
        assert_eq!(
            writes,
            vec![
                "getvar:max-fetch-size",
                "getvar:partition-size:boot",
                "fetch:boot:0x00000000:0x00000004",
                "fetch:boot:0x00000004:0x00000002",
            ]
        );
        let _ = std::fs::remove_file(&out);
    }

    /// 旧厂商实现：fetch 先回 OKAY 暂存，再由 upload 取回。
    #[tokio::test]
    async fn fetch_falls_back_to_upload_when_device_answers_okay() {
        let reads = vec![
            Ok(b"OKAY".to_vec()),
            Ok(b"DATA00000003".to_vec()),
            Ok(b"xyz".to_vec()),
            Ok(b"OKAY".to_vec()),
        ];
        let mut driver = FastbootDriver::new(MockTransport::new(reads));
        let out = temp_out("legacy");
        let n = driver.read_partition("misc:0:3", &out).await.unwrap();
        assert_eq!(n, 3);
        assert_eq!(std::fs::read(&out).unwrap(), b"xyz");
        assert_eq!(
            driver.transport.writes[0],
            b"fetch:misc:0x00000000:0x00000003"
        );
        assert_eq!(driver.transport.writes[1], b"upload");
        let _ = std::fs::remove_file(&out);
    }

    /// `download:%08x` 的长度字段是 u32：超过 4 GiB−1 必须在握手前拒绝，
    /// 否则 `{:08x}` 静默产出 9 位十六进制，设备解析错位后把后续数据流写坏。
    #[test]
    fn test_check_download_len_rejects_over_u32() {
        assert!(check_download_len(0).is_ok());
        assert!(check_download_len(u32::MAX as u64).is_ok());
        assert!(matches!(
            check_download_len(u32::MAX as u64 + 1),
            Err(FastbootError::ImageTooLarge(_, _))
        ));
    }

    /// 未知状态保留有限回包预览及有效长度，不能只报 4 字节前缀。
    #[tokio::test]
    async fn unknown_status_line_error_carries_full_response() {
        let transport = MockTransport::new(vec![Ok(b"BOGUled weird line".to_vec())]);
        let mut driver = FastbootDriver::new(transport);
        driver.set_auto_retry(false);

        let error = driver.get_var("version").await.unwrap_err();

        let text = error.to_string();
        assert!(
            text.contains("BOGUled weird line"),
            "错误文本应包含整行回包，实际: {text}"
        );
        assert!(text.contains("command=getvar:version"));
        assert!(text.contains("requested=257 actual=18"));
        assert!(text.contains("prefix_hex=[42 4F 47 55"));
        assert!(text.contains("backend=generic"));
    }

    #[tokio::test]
    async fn getvar_all_rejects_device_fail_and_partial_info() {
        for reads in [
            vec![Ok(b"FAILunknown variable".to_vec())],
            vec![
                Ok(b"INFOpartition-size:system:0x1000".to_vec()),
                Ok(b"FAILunknown variable".to_vec()),
            ],
        ] {
            let mut driver = FastbootDriver::new(MockTransport::new(reads));
            assert!(matches!(
                driver.get_var_all().await,
                Err(FastbootError::Device(message)) if message == "unknown variable"
            ));
            let transport = driver.into_transport();
            assert_eq!(transport.writes, vec![b"getvar:all".to_vec()]);
            assert!(transport.reads.is_empty());
        }
    }

    #[tokio::test]
    async fn getvar_all_preserves_info_only_after_okay_and_rejects_data() {
        let mut driver = FastbootDriver::new(MockTransport::new(vec![
            Ok(b"INFOproduct:test-device".to_vec()),
            Ok(b"OKAY".to_vec()),
            Ok(b"INFOpartial".to_vec()),
            Ok(b"DATA00000004".to_vec()),
        ]));
        assert_eq!(
            driver.get_var_all().await.unwrap(),
            vec!["product:test-device"]
        );
        assert!(matches!(
            driver.get_var_all().await,
            Err(FastbootError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn download_consumes_info_and_text_then_okay_before_next_command() {
        use std::sync::{Arc, Mutex};

        let info = Arc::new(Mutex::new(Vec::new()));
        let text = Arc::new(Mutex::new(Vec::new()));
        let captured_info = info.clone();
        let captured_text = text.clone();
        let mut driver = FastbootDriver::new(MockTransport::new(vec![
            Ok(b"DATA00000004".to_vec()),
            Ok(b"INFOreceived image".to_vec()),
            Ok(b"TEXTchecking image".to_vec()),
            Ok(b"OKAY".to_vec()),
            Ok(b"OKAYa".to_vec()),
        ]));
        driver.set_callbacks(DriverCallbacks {
            info: Box::new(move |message| {
                captured_info.lock().unwrap().push(message.to_string());
            }),
            text: Box::new(move |message| {
                captured_text.lock().unwrap().push(message.to_string());
            }),
            ..DriverCallbacks::default()
        });

        driver.download(b"abcd").await.unwrap();
        assert_eq!(driver.get_var("current-slot").await.unwrap(), "a");
        assert_eq!(*info.lock().unwrap(), vec!["received image"]);
        assert_eq!(*text.lock().unwrap(), vec!["checking image"]);
        let transport = driver.into_transport();
        assert!(transport.reads.is_empty());
        assert_eq!(
            transport.writes,
            vec![
                b"download:00000004".to_vec(),
                b"abcd".to_vec(),
                b"getvar:current-slot".to_vec(),
            ]
        );
    }

    #[tokio::test]
    async fn download_final_fail_or_timeout_never_resends_command_or_data() {
        for final_response in [
            Ok(b"FAILinvalid image".to_vec()),
            Err(TransportError::Timeout),
            Ok(b"DATA00000004".to_vec()),
        ] {
            let mut driver = FastbootDriver::new(MockTransport::new(vec![
                Ok(b"DATA00000004".to_vec()),
                Ok(b"INFOchecking image".to_vec()),
                final_response,
            ]));
            let error = driver.download(b"abcd").await.unwrap_err();
            assert!(matches!(
                error,
                FastbootError::Device(_) | FastbootError::Timeout | FastbootError::Protocol(_)
            ));
            let transport = driver.into_transport();
            assert!(transport.reads.is_empty());
            assert_eq!(
                transport.writes,
                vec![b"download:00000004".to_vec(), b"abcd".to_vec()]
            );
        }
    }

    #[tokio::test]
    async fn upload_consumes_info_and_text_then_terminal_without_resending() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("upload.img");
        for final_response in [b"OKAY".to_vec(), b"FAILreadback failed".to_vec()] {
            let succeeds = final_response == b"OKAY";
            let mut driver = FastbootDriver::new(MockTransport::new(vec![
                Ok(b"DATA00000004".to_vec()),
                Ok(b"abcd".to_vec()),
                Ok(b"INFOread complete".to_vec()),
                Ok(b"TEXTchecking transfer".to_vec()),
                Ok(final_response),
                Ok(b"OKAYtest-device".to_vec()),
            ]));
            let result = driver.upload_to_file(&path).await;
            if succeeds {
                assert_eq!(result.unwrap(), 4);
            } else {
                assert!(matches!(result, Err(FastbootError::Device(_))));
            }
            assert_eq!(tokio::fs::read(&path).await.unwrap(), b"abcd");
            assert_eq!(driver.get_var("product").await.unwrap(), "test-device");
            let transport = driver.into_transport();
            assert!(transport.reads.is_empty());
            assert_eq!(
                transport.writes,
                vec![b"upload".to_vec(), b"getvar:product".to_vec()]
            );
        }
    }

    #[tokio::test]
    async fn zero_and_short_status_reports_actual_length_and_bounds_preview() {
        for response in [vec![0u8; 257], vec![0u8; 256], b"OK".to_vec()] {
            let length = response.len();
            let mut driver = FastbootDriver::new(MockTransport::new(vec![Ok(response)]));
            let error = driver.get_var_all().await.unwrap_err();
            assert!(matches!(error, FastbootError::Protocol(_)));
            let diagnostic = error.to_string();
            assert!(diagnostic.contains("command=getvar:all"));
            assert!(diagnostic.contains(&format!("actual={length}")));
            assert!(diagnostic.contains("requested=257"));
            assert!(diagnostic.len() < 600, "{diagnostic}");
            if length >= 256 {
                assert!(diagnostic.contains("all_zero=true"));
            }
        }
    }

    #[tokio::test]
    async fn full_size_legal_status_uses_only_bytes_read() {
        let mut response = b"OKAY".to_vec();
        response.resize(FB_RESPONSE_SZ, b'x');
        let mut driver = FastbootDriver::new(MockTransport::new(vec![
            Ok(response),
            Ok(b"OKAYa".to_vec()),
        ]));
        assert_eq!(driver.get_var("product").await.unwrap().len(), 252);
        assert_eq!(driver.get_var("current-slot").await.unwrap(), "a");
    }

    #[tokio::test]
    async fn invalid_transport_read_count_returns_protocol_error_without_panicking() {
        let mut transport = MockTransport::new(vec![Ok(b"OKAY".to_vec())]);
        transport.reported_read_len = Some(300);
        let mut driver = FastbootDriver::new(transport);
        let error = driver.get_var_all().await.unwrap_err();
        assert!(matches!(error, FastbootError::Protocol(_)));
        assert!(error.to_string().contains("requested=257 actual=300"));
    }

    #[tokio::test]
    async fn protocol_diagnostic_redacts_oem_arguments_and_token_payloads() {
        for command in [
            "oem unlock PRIVATE_ARGUMENT",
            "getvar:token",
            "flashing unlock PRIVATE_ARGUMENT",
            "PRIVATE_ARGUMENT",
        ] {
            let mut driver =
                FastbootDriver::new(MockTransport::new(vec![
                    Ok(b"BOGUPRIVATE_PAYLOAD".to_vec()),
                ]));
            let error = driver.command_no_retry(command).await.unwrap_err();
            let diagnostic = error.to_string();
            assert!(!diagnostic.contains("PRIVATE_ARGUMENT"), "{diagnostic}");
            assert!(!diagnostic.contains("PRIVATE_PAYLOAD"), "{diagnostic}");
            assert!(!diagnostic.contains("prefix_hex"), "{diagnostic}");
            assert!(diagnostic.contains("preview=<redacted>"));
        }
    }

    #[tokio::test]
    async fn recovery_probe_rejects_garbage_and_consumes_valid_status_chain() {
        for response in [vec![0u8; 257], b"BOGUgarbage".to_vec()] {
            let mut driver = FastbootDriver::new(MockTransport::new(vec![Ok(response)]));
            assert!(matches!(
                driver.probe_version().await,
                Err(FastbootError::Protocol(_))
            ));
            assert_eq!(driver.timeout(), DEFAULT_TIMEOUT);
        }
        for terminal in [b"OKAY0.4".to_vec(), b"FAILunsupported".to_vec()] {
            let mut driver = FastbootDriver::new(MockTransport::new(vec![
                Ok(b"INFOversion query".to_vec()),
                Ok(b"TEXTready".to_vec()),
                Ok(terminal),
            ]));
            driver.probe_version().await.unwrap();
            let transport = driver.into_transport();
            assert!(transport.reads.is_empty());
            assert_eq!(transport.writes, vec![b"getvar:version".to_vec()]);
            assert_eq!(transport.timeout, DEFAULT_TIMEOUT);
        }
    }

    /// 原命令的响应只是来晚了：恢复阶段必须把它排掉，重发的命令才读得到自己的响应。
    #[tokio::test]
    async fn retry_after_timeout_drains_late_response_before_probe() {
        let transport = MockTransport::new(vec![
            Err(TransportError::Timeout),
            // 第一次排空：原命令迟到的响应，随后管道安静
            Ok(b"OKAYa".to_vec()),
            Err(TransportError::Timeout),
            // 探测
            Ok(b"OKAY0.4".to_vec()),
            // 第二次排空：安静
            Err(TransportError::Timeout),
            // 重发命令的响应
            Ok(b"OKAYa".to_vec()),
        ]);
        let mut driver = FastbootDriver::new(transport);
        assert_eq!(driver.get_var("current-slot").await.unwrap(), "a");
    }

    /// 迟到的响应落在第一次排空之后、被探测读走：探测自己的响应必须在第二次排空里丢掉，
    /// 否则重发的 current-slot 会读成 "0.4"。
    #[tokio::test]
    async fn retry_after_timeout_drops_probe_reply_displaced_by_late_response() {
        let transport = MockTransport::new(vec![
            Err(TransportError::Timeout),
            Err(TransportError::Timeout),
            Ok(b"OKAYa".to_vec()),
            Ok(b"OKAY0.4".to_vec()),
            Err(TransportError::Timeout),
            Ok(b"OKAYa".to_vec()),
        ]);
        let mut driver = FastbootDriver::new(transport);
        assert_eq!(driver.get_var("current-slot").await.unwrap(), "a");
        let transport = driver.into_transport();
        assert_eq!(
            transport.writes,
            vec![
                b"getvar:current-slot".to_vec(),
                b"getvar:version".to_vec(),
                b"getvar:current-slot".to_vec(),
            ]
        );
        assert_eq!(transport.timeout, DEFAULT_TIMEOUT, "恢复后要还原常规超时");
    }

    #[tokio::test]
    async fn reboot_accepts_okay_response() {
        let transport = MockTransport::new(vec![Ok(b"OKAY".to_vec())]);
        let mut driver = FastbootDriver::new(transport);

        driver.reboot().await.unwrap();

        let transport = driver.into_transport();
        assert_eq!(transport.writes, vec![b"reboot".to_vec()]);
        assert_eq!(transport.timeout, DEFAULT_TIMEOUT);
    }

    #[tokio::test]
    async fn reboot_treats_disconnect_after_write_as_success() {
        let transport = MockTransport::new(vec![Err(TransportError::NoLink)]);
        let mut driver = FastbootDriver::new(transport);

        driver.reboot().await.unwrap();

        let transport = driver.into_transport();
        assert_eq!(transport.writes, vec![b"reboot".to_vec()]);
        assert_eq!(transport.timeout, DEFAULT_TIMEOUT);
    }

    #[tokio::test]
    async fn reboot_treats_response_timeout_after_write_as_success() {
        let transport = MockTransport::new(vec![Err(TransportError::Timeout)]);
        let mut driver = FastbootDriver::new(transport);

        driver.reboot().await.unwrap();

        let transport = driver.into_transport();
        assert_eq!(transport.writes, vec![b"reboot".to_vec()]);
        assert_eq!(transport.timeout, DEFAULT_TIMEOUT);
    }

    #[tokio::test]
    async fn reboot_preserves_device_failures() {
        let transport = MockTransport::new(vec![Ok(b"FAILnope".to_vec())]);
        let mut driver = FastbootDriver::new(transport);

        let error = driver.reboot().await.unwrap_err();

        assert!(matches!(error, FastbootError::Device(msg) if msg == "nope"));
    }

    #[tokio::test]
    async fn reboot_does_not_treat_write_failure_as_success() {
        let transport = MockTransport::with_write_error(TransportError::Timeout);
        let mut driver = FastbootDriver::new(transport);

        let error = driver.reboot().await.unwrap_err();

        assert!(matches!(
            error,
            FastbootError::Transport(TransportError::Timeout)
        ));
    }

    #[tokio::test]
    async fn reboot_to_uses_official_wire_command() {
        let transport = MockTransport::new(vec![Ok(b"OKAY".to_vec())]);
        let mut driver = FastbootDriver::new(transport);

        driver.reboot_to("fastboot").await.unwrap();

        let transport = driver.into_transport();
        assert_eq!(transport.writes, vec![b"reboot-fastboot".to_vec()]);
    }

    #[tokio::test]
    async fn oem_command_collects_all_info_lines_before_okay() {
        // 模拟 `oem get_token`：设备把 token 分成多条 INFO 行连发，最后回 OKAY。
        // 必须完整累加所有 INFO 行（不能只读一次就返回），否则 token 被截断。
        let transport = MockTransport::new(vec![
            Ok(b"INFOtoken: AABB".to_vec()),
            Ok(b"INFOtoken: CCDD".to_vec()),
            Ok(b"INFOtoken: EEFF".to_vec()),
            Ok(b"OKAY".to_vec()),
        ]);
        let mut driver = FastbootDriver::new(transport);

        let (resp, info) = driver.oem_command_collect("get_token").await.unwrap();

        assert_eq!(resp, Response::Okay(String::new()));
        assert_eq!(
            info,
            vec![
                "token: AABB".to_string(),
                "token: CCDD".to_string(),
                "token: EEFF".to_string(),
            ]
        );

        // 按官方线上格式以空格分隔下发（"oem get_token"），而非冒号（部分 bootloader 只认 "oem " 前缀）。
        let transport = driver.into_transport();
        assert_eq!(transport.writes, vec![b"oem get_token".to_vec()]);
    }

    #[tokio::test]
    async fn oem_command_collect_preserves_info_on_fail() {
        // 设备先回 INFO 再回 FAIL：INFO 不能中途丢弃，终态 FAIL 交由调用方判定失败。
        let transport = MockTransport::new(vec![
            Ok(b"INFOpartial data".to_vec()),
            Ok(b"FAILunknown command".to_vec()),
        ]);
        let mut driver = FastbootDriver::new(transport);

        let (resp, info) = driver.oem_command_collect("get_token").await.unwrap();

        assert_eq!(resp, Response::Fail("unknown command".to_string()));
        assert_eq!(info, vec!["partial data".to_string()]);
    }

    /// 复刻 `rm_flash_logic::commander::parse_fastboot_auth_blob` 的按行归一：逐行去
    /// `(bootloader)` 与 `token:`/`blob:` 前缀后拼接。就地复算是为了在本 crate 内自证「设备字节
    /// → 干净 token」这条链路（真解析器在另一 crate，那边另有回归测试钉同一格式）。
    fn parse_auth_blob(output: &str) -> String {
        let mut parts = Vec::new();
        for raw in output.split(['\r', '\n']) {
            let mut line = raw.trim();
            if line.to_ascii_lowercase().starts_with("(bootloader)") {
                line = line[12..].trim_start();
            }
            let lower = line.to_ascii_lowercase();
            let value = if lower.starts_with("token:") {
                line[6..].trim()
            } else if lower.starts_with("blob:") {
                line[5..].trim()
            } else {
                ""
            };
            if !value.is_empty() {
                parts.push(value.to_string());
            }
        }
        parts.concat()
    }

    #[tokio::test]
    async fn getvar_token_reads_clean_token_like_official_fastboot() {
        // 复刻真实故障：`getvar:token` 时设备把 unlock token 分多条 INFO 行返回，每行自带
        // `token:` 前缀，OKAY 为空——正是自研协议读出的 token 与官方对不上的那种机型。
        let transport = MockTransport::new(vec![
            Ok(b"INFOtoken: AABB".to_vec()),
            Ok(b"INFOtoken: CCDD".to_vec()),
            Ok(b"INFOtoken: EEFF".to_vec()),
            Ok(b"OKAY".to_vec()),
        ]);
        let mut driver = FastbootDriver::new(transport);

        // 走真实读路径：发 getvar:token、累加全部 INFO 行、收 OKAY。
        let (resp, info) = driver.raw_command_with_info("getvar:token").await.unwrap();
        let okay = match resp {
            Response::Okay(v) => v,
            other => panic!("期望 OKAY，实际 {other:?}"),
        };
        let transport = driver.into_transport();
        assert_eq!(transport.writes, vec![b"getvar:token".to_vec()]);

        // 新逻辑：INFO 行原样逐行保留（不拼一坨、不重复套 token: 前缀）。
        let lines = crate::embed::info_var_reply_lines("token", &info, &okay);
        assert_eq!(
            lines,
            vec![
                "token: AABB".to_string(),
                "token: CCDD".to_string(),
                "token: EEFF".to_string(),
            ]
        );

        // selfdev 逐行加 (bootloader) 前缀后的回显 = 官方 fastboot 的回显格式。
        let selfdev_stderr = lines
            .iter()
            .map(|l| format!("(bootloader) {l}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            selfdev_stderr,
            "(bootloader) token: AABB\n(bootloader) token: CCDD\n(bootloader) token: EEFF"
        );
        // 端到端：解析器读出干净 token，与官方一致。
        assert_eq!(parse_auth_blob(&selfdev_stderr), "AABBCCDDEEFF");

        // 反证旧 bug：老逻辑把各行 trim 后 join("") 再套一层 token:，token: 前缀被并进值里，
        // 经 selfdev 压成一行后解析器再也拆不开——读出的 token 与官方不一致。
        let old_join = info.iter().map(|s| s.trim()).collect::<Vec<_>>().join("");
        let old_output = format!("(bootloader) token: {old_join}");
        assert_eq!(
            old_output,
            "(bootloader) token: token: AABBtoken: CCDDtoken: EEFF"
        );
        assert_ne!(parse_auth_blob(&old_output), "AABBCCDDEEFF");
    }
}
