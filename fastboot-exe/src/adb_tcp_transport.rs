use crate::adb_protocol::{
    validate_handshake_payload, validate_payload, AdbMessageHeader, A_AUTH, A_CLSE, A_CNXN, A_OKAY,
    A_OPEN, A_WRTE,
};
use crate::adb_winusb_transport::{parse_shell_v2_packet, ShellExit, ShellProtocol, ShellV2Kind};
use crate::error::TransportError;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DEFAULT_ADB_TCP_PORT: u16 = 5555;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const AUTH_WAIT_TIMEOUT: Duration = Duration::from_secs(180);
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(60);
const PROBE_READ_TIMEOUT: Duration = Duration::from_secs(5);

fn new_stream_id() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1)
        | 1
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdbTcpEndpoint {
    pub host: String,
    pub port: u16,
}

impl AdbTcpEndpoint {
    pub fn serial(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

pub fn normalize_endpoint(value: &str) -> Result<AdbTcpEndpoint, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("adb connect requires HOST[:PORT]".to_string());
    }

    let (host, port) = match value.rsplit_once(':') {
        Some((host, port_text))
            if !host.is_empty() && port_text.chars().all(|c| c.is_ascii_digit()) =>
        {
            let port = port_text
                .parse::<u16>()
                .map_err(|_| format!("invalid adb tcp port: {}", port_text))?;
            (host.to_string(), port)
        }
        _ => (value.to_string(), DEFAULT_ADB_TCP_PORT),
    };

    if host.is_empty() {
        return Err("adb tcp host must not be empty".to_string());
    }

    Ok(AdbTcpEndpoint { host, port })
}

pub struct AdbTcpDevice {
    stream: TcpStream,
    is_connected: bool,
    /// 协商后的协议版本（初始 MIN：CNXN/AUTH 全带校验和，旧设备才收得下；见 adb_protocol）。
    protocol_version: u32,
    /// 对端通告的单包最大载荷（出向上限）。
    max_payload: u32,
    /// 对端 CNXN banner 里的特性列表（决定 sync 能否走 v2 压缩）。
    peer_features: Vec<String>,
    /// Header read immediately precedes payload read.  Keeping it here lets
    /// the transport verify the inbound checksum before exposing bytes to a
    /// service handler.
    pending_header: Option<AdbMessageHeader>,
}

/// 单个 stream 上读到的一个包（其他 stream 的包已被读掉丢弃）。
enum StreamPacket {
    Okay,
    Data,
    Closed,
}

impl AdbTcpDevice {
    pub(crate) fn peer_features(&self) -> &[String] {
        &self.peer_features
    }
    pub fn connect_endpoint(value: &str) -> Result<Self, String> {
        let endpoint = normalize_endpoint(value)?;
        Self::open(endpoint)
    }

    pub fn open(endpoint: AdbTcpEndpoint) -> Result<Self, String> {
        let addr = resolve_socket_addr(&endpoint)?;
        let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
            .map_err(|e| format!("failed to connect to {}: {}", endpoint.serial(), e))?;
        stream
            .set_nodelay(true)
            .map_err(|e| format!("failed to configure tcp adb stream: {}", e))?;
        stream
            .set_read_timeout(Some(DEFAULT_READ_TIMEOUT))
            .map_err(|e| format!("failed to configure tcp adb read timeout: {}", e))?;
        stream
            .set_write_timeout(Some(DEFAULT_READ_TIMEOUT))
            .map_err(|e| format!("failed to configure tcp adb write timeout: {}", e))?;

        Ok(Self {
            stream,
            is_connected: false,
            protocol_version: crate::adb_protocol::ADB_VERSION_MIN,
            max_payload: crate::adb_protocol::ADB_LEGACY_MAX_PAYLOAD,
            peer_features: Vec::new(),
            pending_header: None,
        })
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) {
        let _ = self.stream.set_read_timeout(timeout);
    }

    fn write_pipe(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.stream.write_all(data).map_err(TransportError::Io)
    }

    fn read_exact_pipe(&mut self, buf: &mut [u8]) -> Result<(), TransportError> {
        self.stream.read_exact(buf).map_err(TransportError::Io)
    }

    fn write_header(&mut self, header: &AdbMessageHeader) -> Result<(), TransportError> {
        self.write_pipe(&header.encode())
    }

    fn read_header(&mut self) -> Result<AdbMessageHeader, TransportError> {
        let mut buf = [0u8; 24];
        self.read_exact_pipe(&mut buf)?;
        let header =
            AdbMessageHeader::decode(&buf).map_err(|e| TransportError::Protocol(e.to_string()))?;
        if !crate::adb_protocol::is_known_command(header.command) {
            return Err(TransportError::Protocol(format!(
                "unknown ADB command 0x{:08x}",
                header.command
            )));
        }
        if header.command == crate::adb_protocol::A_STLS {
            return Err(TransportError::Protocol(
                "ADB TLS upgrade (A_STLS) is not supported by this transport".to_string(),
            ));
        }
        self.pending_header = Some(header);
        Ok(header)
    }

    fn read_payload(&mut self, len: u32) -> Result<Vec<u8>, TransportError> {
        let mut data = vec![0u8; len as usize];
        if !data.is_empty() {
            self.read_exact_pipe(&mut data)?;
        }
        let header = self.pending_header.take().ok_or_else(|| {
            TransportError::Protocol("ADB payload read without a header".to_string())
        })?;
        if header.data_length != len {
            return Err(TransportError::Protocol(
                "ADB payload length does not match header".to_string(),
            ));
        }
        let validated = if self.is_connected {
            validate_payload(&header, &data, self.protocol_version)
        } else {
            validate_handshake_payload(&header, &data)
        };
        validated.map_err(|e| TransportError::Protocol(e.to_string()))?;
        Ok(data)
    }

    fn write_message(
        &mut self,
        command: u32,
        local_id: u32,
        remote_id: u32,
        data: &[u8],
    ) -> Result<(), TransportError> {
        let header = AdbMessageHeader::for_payload(
            command,
            local_id,
            remote_id,
            data,
            self.protocol_version,
        );
        self.write_header(&header)?;
        if !data.is_empty() {
            self.write_pipe(data)?;
        }
        Ok(())
    }

    /// 输入线程用的独立写端。`protocol_version` 取交互会话建立时的协商结果（connect 之后
    /// 版本已定型），旧协议设备照样拿到正确校验和。
    fn write_message_to(
        stream: &mut TcpStream,
        command: u32,
        local_id: u32,
        remote_id: u32,
        data: &[u8],
        protocol_version: u32,
    ) -> Result<(), TransportError> {
        let header =
            AdbMessageHeader::for_payload(command, local_id, remote_id, data, protocol_version);
        stream
            .write_all(&header.encode())
            .map_err(TransportError::Io)?;
        if !data.is_empty() {
            stream.write_all(data).map_err(TransportError::Io)?;
        }
        Ok(())
    }

    /// 收到对端 A_CNXN 后套用协商结果（AOSP `atransport::update_version`）。
    fn apply_peer_cnxn(&mut self, header: &AdbMessageHeader, banner: &[u8]) {
        let (version, max_payload) = crate::adb_protocol::negotiate(header.arg0, header.arg1);
        self.protocol_version = version;
        self.max_payload = max_payload;
        self.peer_features =
            crate::adb_protocol::parse_banner(&String::from_utf8_lossy(banner)).features;
    }

    pub fn connect(&mut self) -> Result<(), String> {
        if self.is_connected {
            return Ok(());
        }
        self.set_read_timeout(Some(AUTH_WAIT_TIMEOUT));
        let result = self.try_connect();
        self.set_read_timeout(Some(DEFAULT_READ_TIMEOUT));
        result
    }

    pub fn connect_probe(&mut self) -> Result<bool, String> {
        if self.is_connected {
            return Ok(true);
        }
        self.set_read_timeout(Some(PROBE_READ_TIMEOUT));
        let result = self.try_connect_probe();
        self.set_read_timeout(Some(DEFAULT_READ_TIMEOUT));
        result
    }

    fn send_cnxn(&mut self) -> Result<(), String> {
        let (header, banner) = crate::adb_protocol::make_connection_message();
        self.write_header(&header)
            .map_err(|e| format!("failed to send A_CNXN header: {:?}", e))?;
        self.write_pipe(&banner)
            .map_err(|e| format!("failed to send A_CNXN payload: {:?}", e))
    }

    fn try_connect(&mut self) -> Result<(), String> {
        self.send_cnxn()?;
        let mut auth_attempts = 0;

        loop {
            let header = self
                .read_header()
                .map_err(|e| format!("failed to read adb tcp header: {:?}", e))?;
            let payload = self
                .read_payload(header.data_length)
                .map_err(|e| format!("failed to read adb tcp payload: {:?}", e))?;

            match header.command {
                A_CNXN => {
                    self.apply_peer_cnxn(&header, &payload);
                    self.is_connected = true;
                    return Ok(());
                }
                A_AUTH if header.arg0 == 1 => {
                    let (priv_pem, mut pub_key) =
                        crate::crypto::get_or_create_keys().map_err(|_| "adb key engine failed")?;
                    if auth_attempts == 0 {
                        auth_attempts += 1;
                        if let Ok(signature) = crate::crypto::sign_token(&priv_pem, &payload) {
                            self.write_message(A_AUTH, 2, 0, &signature).map_err(|e| {
                                format!("failed to send adb auth signature: {:?}", e)
                            })?;
                            continue;
                        }
                    }

                    if pub_key.last() != Some(&0) {
                        pub_key.push(0);
                    }
                    if auth_attempts == 1 {
                        crate::progress::print_info("Please confirm the wireless debugging authorization prompt on the device.");
                    }
                    auth_attempts += 1;
                    self.write_message(A_AUTH, 3, 0, &pub_key)
                        .map_err(|e| format!("failed to send adb public key: {:?}", e))?;
                }
                _ => {}
            }
        }
    }

    fn try_connect_probe(&mut self) -> Result<bool, String> {
        self.send_cnxn()?;
        let mut signed = false;

        loop {
            let header = self
                .read_header()
                .map_err(|e| format!("failed to read adb tcp probe header: {:?}", e))?;
            let payload = self
                .read_payload(header.data_length)
                .map_err(|e| format!("failed to read adb tcp probe payload: {:?}", e))?;

            match header.command {
                A_CNXN => {
                    self.apply_peer_cnxn(&header, &payload);
                    self.is_connected = true;
                    return Ok(true);
                }
                A_AUTH if header.arg0 == 1 => {
                    if signed {
                        return Ok(false);
                    }
                    signed = true;
                    let (priv_pem, _) =
                        crate::crypto::get_or_create_keys().map_err(|_| "adb key engine failed")?;
                    let Ok(signature) = crate::crypto::sign_token(&priv_pem, &payload) else {
                        return Ok(false);
                    };
                    self.write_message(A_AUTH, 2, 0, &signature)
                        .map_err(|e| format!("failed to send adb probe signature: {:?}", e))?;
                }
                _ => {}
            }
        }
    }

    pub fn execute_service_streaming<F>(
        &mut self,
        service: &str,
        mut on_data: F,
    ) -> Result<(), String>
    where
        F: FnMut(&[u8]) -> Result<(), String>,
    {
        self.connect()?;
        let local_id = new_stream_id();
        let mut destination = service.as_bytes().to_vec();
        if !destination.ends_with(&[0]) {
            destination.push(0);
        }

        self.write_message(A_OPEN, local_id, 0, &destination)
            .map_err(|e| format!("failed to open adb service '{}': {:?}", service, e))?;

        loop {
            let header = self
                .read_header()
                .map_err(|e| format!("failed to read adb service header: {:?}", e))?;
            let payload = self
                .read_payload(header.data_length)
                .map_err(|e| format!("failed to read adb service payload: {:?}", e))?;

            if header.arg1 != local_id {
                continue;
            }

            match header.command {
                A_OKAY => {}
                A_WRTE => {
                    on_data(&payload)?;
                    self.write_message(A_OKAY, local_id, header.arg0, &[])
                        .map_err(|e| format!("failed to acknowledge adb service data: {:?}", e))?;
                }
                // AOSP protocol: receiving CLOSE terminates the stream and must not
                // generate a second CLOSE in response.
                A_CLSE => break,
                _ => {}
            }
        }

        Ok(())
    }

    pub fn shell_command_streaming<FO, FE>(
        &mut self,
        command: &str,
        mut on_stdout: FO,
        mut on_stderr: FE,
    ) -> Result<ShellExit, String>
    where
        FO: FnMut(&[u8]),
        FE: FnMut(&[u8]),
    {
        match self.shell_v2_streaming(command, &mut on_stdout, &mut on_stderr) {
            Ok(exit) => Ok(exit),
            Err(e) if e.starts_with("shell v2 unsupported:") => {
                self.shell_legacy_streaming(command, &mut on_stdout)
            }
            Err(e) => Err(e),
        }
    }

    fn shell_v2_streaming<FO, FE>(
        &mut self,
        command: &str,
        on_stdout: &mut FO,
        on_stderr: &mut FE,
    ) -> Result<ShellExit, String>
    where
        FO: FnMut(&[u8]),
        FE: FnMut(&[u8]),
    {
        let service = format!("shell,v2,raw:{}", command);
        let mut pending = Vec::new();
        let mut exit_code = 0;
        let mut saw_exit = false;
        let mut saw_packet = false;

        self.execute_service_streaming(&service, |payload| {
            if saw_exit {
                return Ok(());
            }
            pending.extend_from_slice(payload);
            loop {
                if pending.len() < 5 {
                    break;
                }
                let payload_len =
                    u32::from_le_bytes([pending[1], pending[2], pending[3], pending[4]]) as usize;
                let packet_len = 5 + payload_len;
                if pending.len() < packet_len {
                    break;
                }

                let had_packet = saw_packet;
                let packet = parse_shell_v2_packet(&pending[..packet_len])?;
                pending.drain(..packet_len);
                match packet.kind {
                    ShellV2Kind::Stdout => on_stdout(&packet.payload),
                    ShellV2Kind::Stderr => on_stderr(&packet.payload),
                    ShellV2Kind::Exit => {
                        exit_code = packet.exit_code().unwrap_or(0);
                        saw_exit = true;
                        saw_packet = true;
                        break;
                    }
                    ShellV2Kind::Invalid(kind) => {
                        if !had_packet {
                            return Err(format!(
                                "shell v2 unsupported: invalid packet kind {}",
                                kind
                            ));
                        }
                        return Err(format!("invalid shell v2 packet kind {}", kind));
                    }
                    _ => {}
                }
                saw_packet = true;
            }
            Ok(())
        })?;

        if !saw_exit {
            if !saw_packet {
                return Err("shell v2 unsupported: empty or invalid response".to_string());
            }
            if !pending.is_empty() {
                return Err("shell v2 stream ended with a truncated packet".to_string());
            }
            return Err("shell v2 stream ended without exit packet".to_string());
        }

        Ok(ShellExit {
            code: exit_code,
            protocol: ShellProtocol::V2,
        })
    }

    fn shell_legacy_streaming<FO>(
        &mut self,
        command: &str,
        on_stdout: &mut FO,
    ) -> Result<ShellExit, String>
    where
        FO: FnMut(&[u8]),
    {
        let service = format!("shell:{}", command);
        self.execute_service_streaming(&service, |payload| {
            on_stdout(payload);
            Ok(())
        })?;
        Ok(ShellExit {
            code: 0,
            protocol: ShellProtocol::Legacy,
        })
    }

    pub fn interactive_shell(&mut self) -> Result<(), String> {
        self.connect()?;
        let local_id = new_stream_id();
        self.write_message(A_OPEN, local_id, 0, b"shell:\0")
            .map_err(|e| format!("failed to open interactive shell: {:?}", e))?;

        let remote_id = loop {
            let header = self
                .read_header()
                .map_err(|e| format!("failed to read interactive shell open response: {:?}", e))?;
            let _ = self.read_payload(header.data_length);
            if header.arg1 != local_id {
                continue;
            }
            match header.command {
                A_OKAY => break header.arg0,
                A_CLSE => return Err("device rejected interactive shell".to_string()),
                _ => {}
            }
        };

        self.set_read_timeout(None);
        let result = self.interactive_shell_loop(local_id, remote_id);
        self.set_read_timeout(Some(DEFAULT_READ_TIMEOUT));
        result
    }

    fn interactive_shell_loop(&mut self, local_id: u32, remote_id: u32) -> Result<(), String> {
        let mut input_stream = self
            .stream
            .try_clone()
            .map_err(|e| format!("failed to clone adb tcp stream for shell input: {}", e))?;
        let write_lock = Arc::new(Mutex::new(()));
        let input_write_lock = Arc::clone(&write_lock);
        // 会话已建立，协商版本定型；输入线程按同一版本决定校验和策略。
        let protocol_version = self.protocol_version;

        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            let mut stdin = stdin.lock();
            let mut buf = [0u8; 4096];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => {
                        let Ok(_guard) = input_write_lock.lock() else {
                            break;
                        };
                        let _ = Self::write_message_to(
                            &mut input_stream,
                            A_CLSE,
                            local_id,
                            remote_id,
                            &[],
                            protocol_version,
                        );
                        break;
                    }
                    Ok(read) => {
                        let Ok(_guard) = input_write_lock.lock() else {
                            break;
                        };
                        if Self::write_message_to(
                            &mut input_stream,
                            A_WRTE,
                            local_id,
                            remote_id,
                            &buf[..read],
                            protocol_version,
                        )
                        .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        loop {
            let header = self
                .read_header()
                .map_err(|e| format!("interactive shell read failed: {:?}", e))?;
            let payload = self
                .read_payload(header.data_length)
                .map_err(|e| format!("interactive shell payload read failed: {:?}", e))?;
            if header.arg1 != local_id {
                continue;
            }

            match header.command {
                A_WRTE => {
                    stdout
                        .write_all(&payload)
                        .map_err(|e| format!("failed to write shell output: {}", e))?;
                    stdout
                        .flush()
                        .map_err(|e| format!("failed to flush shell output: {}", e))?;
                    let _guard = write_lock
                        .lock()
                        .map_err(|_| "interactive shell write lock poisoned".to_string())?;
                    self.write_message(A_OKAY, local_id, header.arg0, &[])
                        .map_err(|e| format!("failed to acknowledge shell output: {:?}", e))?;
                }
                A_CLSE => {
                    return Ok(());
                }
                A_OKAY => {}
                _ => {}
            }
        }
    }

    pub fn shell_command(&mut self, command: &str) -> Result<String, String> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = self.shell_command_streaming(
            command,
            |b| stdout.extend_from_slice(b),
            |b| stderr.extend_from_slice(b),
        )?;

        if exit.code == 0 {
            Ok(String::from_utf8_lossy(&stdout).to_string())
        } else if !stderr.is_empty() {
            Err(String::from_utf8_lossy(&stderr).to_string())
        } else {
            Err(String::from_utf8_lossy(&stdout).to_string())
        }
    }

    pub fn reboot(&mut self, target: &str) -> Result<(), String> {
        self.connect()?;
        let service = if target.is_empty() {
            "reboot:".to_string()
        } else {
            format!("reboot:{}", target)
        };
        self.write_message(
            A_OPEN,
            new_stream_id(),
            0,
            nul_terminated(&service).as_slice(),
        )
        .map_err(|e| format!("failed to send reboot request: {:?}", e))
    }

    pub fn root(&mut self) -> Result<(), String> {
        self.print_service("root:")
    }

    /// Stream stdin into an exec/abb service over TCP.  Each WRTE waits for
    /// READY; service output may arrive while the input is still being sent.
    pub(crate) fn exec_with_stdin(
        &mut self,
        service: &[u8],
        stdin: &mut dyn Read,
    ) -> Result<Vec<u8>, String> {
        self.connect()?;
        let local_id = new_stream_id();
        let mut destination = service.to_vec();
        destination.push(0);
        self.write_message(A_OPEN, local_id, 0, &destination)
            .map_err(|e| format!("failed to open input service: {:?}", e))?;
        let remote_id = loop {
            let header = self.read_header().map_err(|e| e.to_string())?;
            self.read_payload(header.data_length)
                .map_err(|e| e.to_string())?;
            if header.arg1 != local_id {
                continue;
            }
            match header.command {
                A_OKAY => break header.arg0,
                A_CLSE => return Err("device rejected input service".into()),
                _ => {}
            }
        };
        let mut packet = vec![0u8; self.max_payload as usize];
        let mut output = Vec::new();
        let mut closed = false;
        while !closed {
            let n = crate::adb_sync::read_full(stdin, &mut packet)
                .map_err(|e| format!("failed to read stdin: {}", e))?;
            if n == 0 {
                break;
            }
            closed = self.send_packet(local_id, remote_id, &packet[..n], &mut output)?;
        }
        while !closed {
            closed = matches!(
                self.read_stream_packet(local_id, &mut output)?,
                StreamPacket::Closed
            );
        }
        Ok(output)
    }

    pub fn unroot(&mut self) -> Result<(), String> {
        self.print_service("unroot:")
    }

    pub fn print_service(&mut self, service: &str) -> Result<(), String> {
        let mut output = Vec::new();
        self.execute_service_streaming(service, |payload| {
            output.extend_from_slice(payload);
            Ok(())
        })?;
        crate::progress::print_info(&String::from_utf8_lossy(&output));
        Ok(())
    }

    pub fn sideload(&mut self, package_path: &str) -> Result<(), String> {
        const BLOCK_SIZE: usize = 64 * 1024;

        let mut file = fs::File::open(package_path)
            .map_err(|e| format!("failed to open sideload package '{}': {}", package_path, e))?;
        let size = file
            .metadata()
            .map_err(|e| format!("failed to stat sideload package '{}': {}", package_path, e))?
            .len();
        if size == 0 {
            return Err("sideload package is empty".to_string());
        }

        self.connect()?;
        self.set_read_timeout(None);
        // 单块必须装进一个 A_WRTE（≤ 协商 maxdata）；块长在 sideload-host 服务串里声明。
        let block_size = BLOCK_SIZE.min((self.max_payload as usize).max(1));
        let result = self.sideload_host(&mut file, size, block_size);
        self.set_read_timeout(Some(DEFAULT_READ_TIMEOUT));
        result
    }

    fn sideload_host(
        &mut self,
        file: &mut fs::File,
        size: u64,
        block_size: usize,
    ) -> Result<(), String> {
        let service = format!("sideload-host:{}:{}", size, block_size);
        let local_id = new_stream_id();
        let mut destination = service.into_bytes();
        destination.push(0);

        self.write_message(A_OPEN, local_id, 0, &destination)
            .map_err(|e| format!("failed to open sideload-host service: {:?}", e))?;

        let remote_id = loop {
            let header = self
                .read_header()
                .map_err(|e| format!("failed to read sideload open response: {:?}", e))?;
            let _ = self.read_payload(header.data_length);
            if header.arg1 != local_id {
                continue;
            }
            match header.command {
                A_OKAY => break header.arg0,
                A_CLSE => return Err("device rejected sideload-host service".to_string()),
                _ => {}
            }
        };

        let mut sent: u64 = 0;
        loop {
            let header = self
                .read_header()
                .map_err(|e| format!("failed to read sideload request: {:?}", e))?;
            let payload = self
                .read_payload(header.data_length)
                .map_err(|e| format!("failed to read sideload request payload: {:?}", e))?;
            if header.arg1 != local_id {
                continue;
            }
            match header.command {
                A_WRTE => {
                    self.write_message(A_OKAY, local_id, header.arg0, &[])
                        .map_err(|e| format!("failed to ack sideload request: {:?}", e))?;

                    if payload == b"DONEDONE" {
                        println!("\rTotal xfer: {:.2}x", sent as f64 / size as f64);
                        let _ = self.write_message(A_CLSE, local_id, remote_id, &[]);
                        return Ok(());
                    }
                    if payload == b"FAILFAIL" {
                        return Err("device reported sideload failure".to_string());
                    }
                    if payload.len() != 8 {
                        return Err(format!("invalid sideload block request: {:?}", payload));
                    }

                    let block_text = String::from_utf8_lossy(&payload);
                    let block = block_text
                        .parse::<u64>()
                        .map_err(|_| format!("invalid sideload block number: {}", block_text))?;
                    let offset = block.saturating_mul(block_size as u64);
                    if offset >= size {
                        return Err(format!(
                            "device requested sideload block beyond EOF: {}",
                            block
                        ));
                    }
                    let to_read = ((size - offset).min(block_size as u64)) as usize;
                    let mut data = vec![0u8; to_read];
                    file.seek(SeekFrom::Start(offset))
                        .map_err(|e| format!("failed to seek sideload package: {}", e))?;
                    file.read_exact(&mut data)
                        .map_err(|e| format!("failed to read sideload package: {}", e))?;
                    self.write_message(A_WRTE, local_id, remote_id, &data)
                        .map_err(|e| format!("failed to send sideload block: {:?}", e))?;
                    self.wait_stream_okay(local_id)?;
                    sent = sent.saturating_add(to_read as u64);
                    print!("\rTotal xfer: {:.2}x", sent as f64 / size as f64);
                    let _ = std::io::stdout().flush();
                }
                A_CLSE => return Err("device closed sideload stream".to_string()),
                A_OKAY => {}
                _ => {}
            }
        }
    }

    pub fn push(&mut self, local_path: &str, remote_path: &str) -> Result<(), String> {
        self.connect()?;
        let mode = crate::adb_sync::SyncMode::for_device(&self.peer_features);
        match self.push_with_mode(local_path, remote_path, mode) {
            Err(e) if mode != crate::adb_sync::SyncMode::V1 => {
                crate::logger::log_line(&format!("sync v2 push 失败，回退 v1 重试: {}", e));
                self.push_with_mode(local_path, remote_path, crate::adb_sync::SyncMode::V1)
            }
            other => other,
        }
    }

    /// sync 字节流按协商 maxdata 连续打包进 A_WRTE（多块共用一包），每包等一个 A_OKAY；
    /// 设备中途回的 FAIL 随时收下并停止发送。
    fn push_with_mode(
        &mut self,
        local_path: &str,
        remote_path: &str,
        mode: crate::adb_sync::SyncMode,
    ) -> Result<(), String> {
        use crate::adb_sync::{parse_status, read_full, PushStream};

        let file = fs::File::open(local_path)
            .map_err(|e| format!("failed to open local file '{}': {}", local_path, e))?;
        let local_id = new_stream_id();
        let remote_id = self.open_sync(local_id)?;
        let mtime = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        let mut stream = PushStream::new(
            file,
            remote_path,
            file_mode_for_push(local_path),
            mtime,
            mode,
        )
        .map_err(|e| format!("failed to start sync stream: {}", e))?;
        let mut packet = vec![0u8; (self.max_payload as usize).max(1)];
        let mut status = Vec::new();
        let mut closed = false;
        loop {
            let n = read_full(&mut stream, &mut packet)
                .map_err(|e| format!("failed to read local file '{}': {}", local_path, e))?;
            if n == 0 {
                break;
            }
            closed = self.send_packet(local_id, remote_id, &packet[..n], &mut status)?;
            if closed || parse_status(&status).is_some() {
                break;
            }
        }
        while !closed && parse_status(&status).is_none() {
            closed = matches!(
                self.read_stream_packet(local_id, &mut status)?,
                StreamPacket::Closed
            );
        }
        if !closed {
            let _ = self.write_message(A_CLSE, local_id, remote_id, &[]);
        }
        match parse_status(&status) {
            Some(Ok(())) => Ok(()),
            Some(Err(reason)) => Err(format!("device rejected push: {}", reason)),
            None => Err("device closed sync stream".to_string()),
        }
    }

    pub fn pull(&mut self, remote_path: &str, local_path: &str) -> Result<(), String> {
        self.connect()?;
        let mode = crate::adb_sync::SyncMode::for_device(&self.peer_features);
        match self.pull_with_mode(remote_path, local_path, mode) {
            Err(e) if mode != crate::adb_sync::SyncMode::V1 => {
                crate::logger::log_line(&format!("sync v2 pull 失败，回退 v1 重试: {}", e));
                self.pull_with_mode(remote_path, local_path, crate::adb_sync::SyncMode::V1)
            }
            other => other,
        }
    }

    fn pull_with_mode(
        &mut self,
        remote_path: &str,
        local_path: &str,
        mode: crate::adb_sync::SyncMode,
    ) -> Result<(), String> {
        use crate::adb_sync::{recv_request, PullProgress, PullSink};

        let local_id = new_stream_id();
        let remote_id = self.open_sync(local_id)?;
        let file = fs::File::create(local_path)
            .map_err(|e| format!("failed to create local file '{}': {}", local_path, e))?;
        let mut sink = PullSink::new(std::io::BufWriter::new(file), mode)
            .map_err(|e| format!("failed to start sync stream: {}", e))?;
        self.write_message(
            A_WRTE,
            local_id,
            remote_id,
            &recv_request(remote_path, mode),
        )
        .map_err(|e| format!("failed to send RECV request: {:?}", e))?;

        let mut inbound = Vec::new();
        let outcome = loop {
            match self.read_stream_packet(local_id, &mut inbound)? {
                StreamPacket::Okay => {}
                StreamPacket::Data => {
                    let progress = sink.feed(&inbound);
                    inbound.clear();
                    match progress {
                        Ok(PullProgress::Done) => break Ok(()),
                        Ok(PullProgress::More) => {}
                        Err(e) => break Err(e),
                    }
                }
                StreamPacket::Closed => {
                    break Err("device closed sync stream before DONE".to_string())
                }
            }
        };
        let _ = self.write_message(A_CLSE, local_id, remote_id, &[]);
        outcome
    }

    /// 读本 stream 的下一个包：A_WRTE 的载荷追加进 `inbound` 并立即回 A_OKAY；其他 stream 的包读掉丢弃。
    fn read_stream_packet(
        &mut self,
        local_id: u32,
        inbound: &mut Vec<u8>,
    ) -> Result<StreamPacket, String> {
        loop {
            let header = self
                .read_header()
                .map_err(|e| format!("failed to read stream header: {:?}", e))?;
            let payload = self
                .read_payload(header.data_length)
                .map_err(|e| format!("failed to read stream payload: {:?}", e))?;
            if header.arg1 != local_id {
                continue;
            }
            match header.command {
                A_OKAY => return Ok(StreamPacket::Okay),
                A_WRTE => {
                    inbound.extend_from_slice(&payload);
                    self.write_message(A_OKAY, local_id, header.arg0, &[])
                        .map_err(|e| format!("failed to acknowledge stream data: {:?}", e))?;
                    return Ok(StreamPacket::Data);
                }
                A_CLSE => return Ok(StreamPacket::Closed),
                _ => {}
            }
        }
    }

    /// 发一个 A_WRTE 并等它的 A_OKAY；等待期间设备回的数据收进 `inbound`。返回 true 表示对端已关流。
    fn send_packet(
        &mut self,
        local_id: u32,
        remote_id: u32,
        data: &[u8],
        inbound: &mut Vec<u8>,
    ) -> Result<bool, String> {
        self.write_message(A_WRTE, local_id, remote_id, data)
            .map_err(|e| format!("failed to send stream data: {:?}", e))?;
        loop {
            match self.read_stream_packet(local_id, inbound)? {
                StreamPacket::Okay => return Ok(false),
                StreamPacket::Data => {}
                StreamPacket::Closed => return Ok(true),
            }
        }
    }

    fn open_sync(&mut self, local_id: u32) -> Result<u32, String> {
        self.write_message(A_OPEN, local_id, 0, b"sync:\0")
            .map_err(|e| format!("failed to open sync service: {:?}", e))?;
        loop {
            let header = self
                .read_header()
                .map_err(|e| format!("failed to read sync open response: {:?}", e))?;
            let _ = self.read_payload(header.data_length);
            if header.arg1 != local_id {
                continue;
            }
            match header.command {
                A_OKAY => return Ok(header.arg0),
                A_CLSE => return Err("device rejected sync service".to_string()),
                _ => {}
            }
        }
    }

    fn wait_stream_okay(&mut self, local_id: u32) -> Result<(), String> {
        loop {
            let header = self
                .read_header()
                .map_err(|e| format!("failed to read stream OKAY: {:?}", e))?;
            let _ = self.read_payload(header.data_length);
            if header.arg1 == local_id && header.command == A_OKAY {
                return Ok(());
            }
            if header.arg1 == local_id && header.command == A_CLSE {
                return Err("device closed stream".to_string());
            }
        }
    }
}

fn resolve_socket_addr(endpoint: &AdbTcpEndpoint) -> Result<SocketAddr, String> {
    let addr_text = format!("{}:{}", endpoint.host, endpoint.port);
    addr_text
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve {}: {}", addr_text, e))?
        .next()
        .ok_or_else(|| format!("failed to resolve {}", addr_text))
}

fn nul_terminated(value: &str) -> Vec<u8> {
    let mut out = value.as_bytes().to_vec();
    if !out.ends_with(&[0]) {
        out.push(0);
    }
    out
}

fn file_mode_for_push(local_path: &str) -> u32 {
    if Path::new(local_path).is_dir() {
        0o040755
    } else {
        0o100666
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adb_protocol::{
        payload_checksum, ADB_LEGACY_MAX_PAYLOAD, ADB_MAX_PAYLOAD, ADB_VERSION_MIN,
        ADB_VERSION_SKIP_CHECKSUM,
    };
    use std::io;
    use std::net::{Shutdown, TcpListener};

    const TEST_BANNER: &[u8] = b"device::ro.product.device=loopback;features=shell_v2";

    // Only loopback sockets are opened.  In particular, AUTH cases below read
    // the packet directly and never enter the RSA key-loading path.
    fn loopback_device() -> (AdbTcpDevice, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let device = AdbTcpDevice::connect_endpoint(&address.to_string()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_nodelay(true).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        (device, peer)
    }

    fn send_packet(
        peer: &mut TcpStream,
        command: u32,
        arg0: u32,
        arg1: u32,
        payload: &[u8],
        checksum: u32,
    ) -> io::Result<()> {
        let mut header = AdbMessageHeader::new(command, arg0, arg1, payload.len() as u32);
        header.data_checksum = checksum;
        peer.write_all(&header.encode())?;
        peer.write_all(payload)
    }

    fn receive_packet(peer: &mut TcpStream) -> io::Result<(AdbMessageHeader, Vec<u8>)> {
        let mut bytes = [0u8; 24];
        peer.read_exact(&mut bytes)?;
        let header = AdbMessageHeader::decode(&bytes)?;
        let mut payload = vec![0; header.data_length as usize];
        peer.read_exact(&mut payload)?;
        Ok((header, payload))
    }

    fn connect_with_reply(
        version: u32,
        checksum: u32,
        probe: bool,
    ) -> (AdbTcpDevice, Result<(), String>) {
        let (mut device, mut peer) = loopback_device();
        let max_payload = if version < ADB_VERSION_SKIP_CHECKSUM {
            ADB_LEGACY_MAX_PAYLOAD
        } else {
            ADB_MAX_PAYLOAD
        };
        send_packet(
            &mut peer,
            A_CNXN,
            version,
            max_payload,
            TEST_BANNER,
            checksum,
        )
        .unwrap();
        peer.shutdown(Shutdown::Write).unwrap();
        let result = if probe {
            device.connect_probe().and_then(|ready| {
                if ready {
                    Ok(())
                } else {
                    Err("probe did not connect".to_string())
                }
            })
        } else {
            device.connect()
        };
        let (hello, payload) = receive_packet(&mut peer).unwrap();
        assert_eq!(hello.command, A_CNXN);
        // Outbound compatibility is independent of the peer's zero checksum.
        assert_eq!(hello.data_checksum, payload_checksum(&payload));
        (device, result)
    }

    #[test]
    fn modern_zero_checksum_cnxn_connects() {
        let (device, result) = connect_with_reply(ADB_VERSION_SKIP_CHECKSUM, 0, false);
        result.unwrap();
        assert!(device.is_connected);
        assert_eq!(device.protocol_version, ADB_VERSION_SKIP_CHECKSUM);
        assert_eq!(device.max_payload, ADB_MAX_PAYLOAD);
        assert!(device
            .peer_features
            .iter()
            .any(|feature| feature == "shell_v2"));
    }

    #[test]
    fn modern_zero_checksum_cnxn_probe_connects() {
        let (device, result) = connect_with_reply(ADB_VERSION_SKIP_CHECKSUM, 0, true);
        result.unwrap();
        assert!(device.is_connected);
        assert_eq!(device.protocol_version, ADB_VERSION_SKIP_CHECKSUM);
    }

    #[test]
    fn legacy_checksummed_cnxn_connects_and_probes() {
        for probe in [false, true] {
            let (device, result) =
                connect_with_reply(ADB_VERSION_MIN, payload_checksum(TEST_BANNER), probe);
            result.unwrap();
            assert!(device.is_connected);
            assert_eq!(device.protocol_version, ADB_VERSION_MIN);
            assert_eq!(device.max_payload, ADB_LEGACY_MAX_PAYLOAD);
        }
    }

    #[test]
    fn corrupted_legacy_cnxn_is_rejected_by_connect_and_probe() {
        for probe in [false, true] {
            let (device, result) =
                connect_with_reply(ADB_VERSION_MIN, payload_checksum(TEST_BANNER) ^ 1, probe);
            assert!(result.unwrap_err().contains("checksum mismatch"));
            assert!(!device.is_connected);
            assert!(device.peer_features.is_empty());
        }
    }

    #[test]
    fn zero_checksum_auth_token_does_not_mark_device_authorized() {
        let (mut device, mut peer) = loopback_device();
        let token = [0x42; 20];
        send_packet(&mut peer, A_AUTH, 1, 0, &token, 0).unwrap();
        peer.shutdown(Shutdown::Write).unwrap();
        let header = device.read_header().unwrap();
        let payload = device.read_payload(header.data_length).unwrap();
        assert_eq!(header.command, A_AUTH);
        assert_eq!(payload, token);
        assert!(!device.is_connected);
        assert_eq!(device.protocol_version, ADB_VERSION_MIN);
        assert!(device.peer_features.is_empty());
    }

    #[test]
    fn modern_zero_checksum_handshake_allows_getprop_shell_output() {
        let (mut device, mut peer) = loopback_device();
        let server = std::thread::spawn(move || -> io::Result<()> {
            let (hello, _) = receive_packet(&mut peer)?;
            assert_eq!(hello.command, A_CNXN);
            send_packet(
                &mut peer,
                A_CNXN,
                ADB_VERSION_SKIP_CHECKSUM,
                ADB_MAX_PAYLOAD,
                TEST_BANNER,
                0,
            )?;

            let (open, service) = receive_packet(&mut peer)?;
            assert_eq!(open.command, A_OPEN);
            assert_eq!(service, b"shell,v2,raw:getprop ro.product.device\0");
            let remote_id = 7;
            send_packet(&mut peer, A_OKAY, remote_id, open.arg0, &[], 0)?;
            let marker = b"loopback-marker\n";
            let mut shell_payload = vec![1];
            shell_payload.extend_from_slice(&(marker.len() as u32).to_le_bytes());
            shell_payload.extend_from_slice(marker);
            shell_payload.extend_from_slice(&[3, 1, 0, 0, 0, 0]);
            send_packet(&mut peer, A_WRTE, remote_id, open.arg0, &shell_payload, 0)?;
            let (ack, _) = receive_packet(&mut peer)?;
            assert_eq!(ack.command, A_OKAY);
            assert_eq!((ack.arg0, ack.arg1), (open.arg0, remote_id));
            send_packet(&mut peer, A_CLSE, remote_id, open.arg0, &[], 0)?;
            peer.shutdown(Shutdown::Write)
        });
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let result = device.shell_command_streaming(
            "getprop ro.product.device",
            |bytes| stdout.extend_from_slice(bytes),
            |bytes| stderr.extend_from_slice(bytes),
        );
        drop(device);
        let server_result = server.join().unwrap();
        assert!(
            result.is_ok(),
            "shell failed: {result:?}; peer: {server_result:?}"
        );
        server_result.unwrap();
        assert_eq!(
            result.unwrap(),
            ShellExit {
                code: 0,
                protocol: ShellProtocol::V2
            }
        );
        assert_eq!(stdout, b"loopback-marker\n");
        assert!(stderr.is_empty());
    }

    #[test]
    fn normalize_endpoint_adds_default_port() {
        let ep = normalize_endpoint("192.168.1.5").unwrap();
        assert_eq!(ep.serial(), "192.168.1.5:5555");
    }

    #[test]
    fn normalize_endpoint_keeps_explicit_port() {
        let ep = normalize_endpoint("localhost:5556").unwrap();
        assert_eq!(ep.host, "localhost");
        assert_eq!(ep.port, 5556);
    }

    #[test]
    fn normalize_endpoint_rejects_empty_value() {
        assert!(normalize_endpoint("").is_err());
    }
}
