use std::io;

/// 本端通告的 ADB 协议版本（AOSP adb.h `A_VERSION`）。0x01000001 表示支持「协商后跳过
/// 校验和」；实际是否跳过取决于与对端 CNXN 的 min 协商（见 [`negotiate`]）。
pub const ADB_VERSION: u32 = 0x01000001;
/// 协议最低版本（AOSP `A_VERSION_MIN`）。在收到对端 CNXN 前，发出的 CNXN/AUTH
/// 保留校验和以兼容旧设备；收到的握手包则按 [`validate_handshake_payload`] 处理。
/// 对端已读到我们的 CNXN，可能比本端更早切到跳过校验和的版本。
pub const ADB_VERSION_MIN: u32 = 0x01000000;
/// 从该版本起双方跳过载荷校验和（AOSP `A_VERSION_SKIP_CHECKSUM`，2017-12 引入）。
pub const ADB_VERSION_SKIP_CHECKSUM: u32 = 0x01000001;
/// 本端通告的单包最大载荷（我们能接收的上限），与 AOSP `MAX_PAYLOAD` 相同。
/// 只约束设备发给我们的包；我们发往设备的包一律按对端 CNXN 回的 maxdata（[`negotiate`]）切块。
pub const ADB_MAX_PAYLOAD: u32 = 1024 * 1024;
/// 旧协议设备的最小 maxdata（AOSP `MAX_PAYLOAD_V1` = 4KiB）：对端 CNXN 未带有效
/// maxdata 时的保守回退值。
pub const ADB_LEGACY_MAX_PAYLOAD: u32 = 4 * 1024;

/// 单条 ADB 报文载荷的硬上限（1MiB，与 AOSP `MAX_PAYLOAD` 相同）：
/// 异常/恶意设备回超大 data_length 时 `decode` 直接拒绝，避免上层按声明长度分配导致 OOM。
pub const ADB_MAX_MESSAGE_PAYLOAD: u32 = 1024 * 1024;

/// ADB 载荷校验和（AOSP `calculate_apacket_checksum`）：全部字节按无符号累加，允许回绕。
pub fn payload_checksum(data: &[u8]) -> u32 {
    data.iter()
        .fold(0u32, |sum, &b| sum.wrapping_add(u32::from(b)))
}

/// 收到对端 A_CNXN 后的版本/载荷协商（AOSP `atransport::update_version`）：
/// 版本取双方较小者；对端 maxdata 是我们后续单包载荷的出向上限，钳到 [4KiB, 1MiB]。
/// 返回 `(协商版本, 出向单包载荷上限)`。
pub fn negotiate(peer_version: u32, peer_max_payload: u32) -> (u32, u32) {
    let version = peer_version.min(ADB_VERSION);
    let max_payload = if peer_max_payload == 0 {
        ADB_LEGACY_MAX_PAYLOAD
    } else {
        peer_max_payload.min(ADB_MAX_MESSAGE_PAYLOAD)
    };
    (version, max_payload)
}

pub const A_CNXN: u32 = 0x4e584e43;
pub const A_AUTH: u32 = 0x48545541;
pub const A_OPEN: u32 = 0x4e45504f;
pub const A_OKAY: u32 = 0x59414b4f;
pub const A_CLSE: u32 = 0x45534c43;
pub const A_WRTE: u32 = 0x45545257;
/// TLS upgrade request (ADB 1.0.41+).  The wire value is the little-endian
/// encoding of the four ASCII bytes `STLS`.
pub const A_STLS: u32 = 0x534c5453;

/// Commands currently defined by the ADB transport protocol.  A transport
/// must tear down the connection when it receives anything else; silently
/// skipping an unknown command leaves the following payload to be parsed as
/// a header and desynchronises the stream.
pub fn is_known_command(command: u32) -> bool {
    matches!(
        command,
        A_CNXN | A_AUTH | A_OPEN | A_OKAY | A_CLSE | A_WRTE | A_STLS
    )
}

/// Validate a complete inbound packet on an established connection.
/// Legacy sessions retain their byte-sum check; negotiated modern sessions
/// ignore that field. Handshake packets need the separate policy below.
pub fn validate_payload(
    header: &AdbMessageHeader,
    payload: &[u8],
    protocol_version: u32,
) -> io::Result<()> {
    if payload.len() != header.data_length as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ADB payload length does not match header",
        ));
    }
    if protocol_version < ADB_VERSION_SKIP_CHECKSUM
        && header.data_checksum != payload_checksum(payload)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ADB payload checksum mismatch",
        ));
    }
    Ok(())
}

/// The device processes our CNXN and updates its version before sending AUTH
/// or CNXN back (AOSP adb.cpp::handle_new_connection / transport.cpp::send_packet).
/// Our local version is still MIN at that point, so it cannot determine how
/// those replies were encoded. CNXN carries the peer version itself; AUTH
/// has no version field and may legitimately omit its checksum.
///
/// This only accepts the packet framing. AUTH still goes through the normal
/// signature/authorization exchange; only CNXN can mark the device connected.
pub fn validate_handshake_payload(header: &AdbMessageHeader, payload: &[u8]) -> io::Result<()> {
    let version = match header.command {
        A_CNXN => negotiate(header.arg0, header.arg1).0,
        A_AUTH if header.data_checksum == 0 => ADB_VERSION,
        _ => ADB_VERSION_MIN,
    };
    validate_payload(header, payload, version)
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct AdbMessageHeader {
    pub command: u32,
    pub arg0: u32,
    pub arg1: u32,
    pub data_length: u32,
    pub data_checksum: u32,
    pub magic: u32,
}

impl AdbMessageHeader {
    /// 裸构造：data_checksum 恒 0。仅适用于「确知对端不校验」的场景（mux 桥接原样转发等）。
    /// 凡是本端**发起**的报文一律走 [`Self::for_payload`]——它按协商版本决定是否带校验和，
    /// 与 AOSP `send_packet` 一致；用错构造器会让旧设备静默丢包。
    pub fn new(command: u32, arg0: u32, arg1: u32, data_len: u32) -> Self {
        let magic = command ^ 0xFFFFFFFF;
        Self {
            command,
            arg0,
            arg1,
            data_length: data_len,
            data_checksum: 0,
            magic,
        }
    }

    /// 按载荷构造报头（AOSP `send_packet` 语义）：协商版本 < [`ADB_VERSION_SKIP_CHECKSUM`]
    /// 时计算载荷校验和（覆盖握手期与旧设备全程），达到则置 0（新设备跳过校验，省 CPU）。
    pub fn for_payload(
        command: u32,
        arg0: u32,
        arg1: u32,
        data: &[u8],
        protocol_version: u32,
    ) -> Self {
        let mut header = Self::new(command, arg0, arg1, data.len() as u32);
        if protocol_version < ADB_VERSION_SKIP_CHECKSUM {
            header.data_checksum = payload_checksum(data);
        }
        header
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&self.command.to_le_bytes());
        buf.extend_from_slice(&self.arg0.to_le_bytes());
        buf.extend_from_slice(&self.arg1.to_le_bytes());
        buf.extend_from_slice(&self.data_length.to_le_bytes());
        buf.extend_from_slice(&self.data_checksum.to_le_bytes());
        buf.extend_from_slice(&self.magic.to_le_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> io::Result<Self> {
        if data.len() < 24 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "报头长度不足 24 字节",
            ));
        }
        let command = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let arg0 = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let arg1 = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let data_length = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let data_checksum = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let magic = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

        if magic != (command ^ 0xFFFFFFFF) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Magic 校验失败"));
        }

        // 超过硬上限即拒绝解码，防上层按声明长度分配导致 OOM（见 ADB_MAX_MESSAGE_PAYLOAD）。
        if data_length > ADB_MAX_MESSAGE_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "报文声明载荷过大：{} 字节（上限 {} 字节）",
                    data_length, ADB_MAX_MESSAGE_PAYLOAD
                ),
            ));
        }

        Ok(Self {
            command,
            arg0,
            arg1,
            data_length,
            data_checksum,
            magic,
        })
    }
}

/// A_CNXN 通告的 host 特性列表——只列真正实现的特性：超宣会让对端按 banner 走我们不支持的路径
/// （如回压缩 sync 数据）而出错。此处为单一事实源，
/// adb_router 的 `adb features` 与 adb_server 的 `host:features` 共用，杜绝漂移。
pub const ADB_HOST_FEATURES: &str = "shell_v2,cmd,abb_exec,sendrecv_v2,sendrecv_v2_zstd";

/// 构造首个 A_CNXN。arg0 通告我们的最高版本（0x01000001），但报文本身**必须**按
/// [`ADB_VERSION_MIN`] 携带校验和——此刻还不知对端版本，旧设备（收包必校验）只认带
/// 校验和的包；新设备收包不校验、多带无害。与 AOSP「构造时 protocol_version=MIN、
/// 收到对端 CNXN 才 update_version」的时序完全一致。
pub fn make_connection_message() -> (AdbMessageHeader, Vec<u8>) {
    let banner = format!("host::features={}", ADB_HOST_FEATURES).into_bytes();
    let header = AdbMessageHeader::for_payload(
        A_CNXN,
        ADB_VERSION,
        ADB_MAX_PAYLOAD,
        &banner,
        ADB_VERSION_MIN,
    );
    (header, banner)
}

/// 设备 A_CNXN banner 的解析结果。形如
/// `device::ro.product.name=x;ro.product.model=y;ro.product.device=z;features=shell_v2,cmd`。
///
/// 为什么要留着它：5037 上的 `host:features` 按官方语义回的是**设备**特性集（客户端据此决定
/// 走不走 shell v2 / sendrecv_v2 等分支），`devices -l` 的 `product:/model:/device:` 也只有
/// banner 里有。丢掉 banner 就只能瞎报，客户端会按不存在的能力发包。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerBanner {
    /// `::` 之前的连接类型（device / recovery / sideload / rescue…），即 `adb devices` 的状态列。
    pub kind: String,
    pub product: String,
    pub model: String,
    pub device: String,
    pub features: Vec<String>,
}

/// 解析设备 CNXN banner。字段缺失一律留空——banner 是设备侧自由文本，宁可少报不可臆造。
pub fn parse_banner(raw: &str) -> PeerBanner {
    let raw = raw.trim_end_matches('\0');
    let (kind, rest) = match raw.split_once("::") {
        Some((k, r)) => (k, r),
        None => ("", raw),
    };
    let mut out = PeerBanner {
        kind: kind.to_string(),
        ..Default::default()
    };
    for field in rest.split(';') {
        let Some((key, value)) = field.split_once('=') else {
            continue;
        };
        match key {
            "ro.product.name" => out.product = value.to_string(),
            "ro.product.model" => out.model = value.to_string(),
            "ro.product.device" => out.device = value.to_string(),
            "features" => {
                out.features = value
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            }
            _ => {}
        }
    }
    out
}

/// 本机与设备都支持的特性交集，逗号分隔（顺序随 [`ADB_HOST_FEATURES`]，保证输出稳定）。
///
/// 官方 server 的 `host:features` 正是这个交集：只报交集才诚实——设备有而我们没通告的特性，
/// 设备本就不会启用（我们的 CNXN banner 只宣告了 [`ADB_HOST_FEATURES`]）；我们有而设备没有的，
/// 客户端一旦当真就会发出设备解不了的帧。设备特性未知时（banner 没拿到）退回本机集合。
pub fn negotiated_features(device_features: &[String]) -> String {
    if device_features.is_empty() {
        return ADB_HOST_FEATURES.to_string();
    }
    ADB_HOST_FEATURES
        .split(',')
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .filter(|f| device_features.iter().any(|d| d == f))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod protocol_tests {
    use super::*;

    #[test]
    fn checksum_is_wrapping_byte_sum() {
        assert_eq!(payload_checksum(b""), 0);
        assert_eq!(
            payload_checksum(b"host::\0"),
            0x68 + 0x6f + 0x73 + 0x74 + 0x3a + 0x3a
        );
    }

    /// 首个 CNXN 必须带校验和（对端版本未知，按 MIN 行事）——AOSP send_packet 对
    /// connection/auth 包 "for compatibility reasons" 计算校验和。
    #[test]
    fn connection_message_carries_checksum() {
        let (header, banner) = make_connection_message();
        assert_eq!(header.command, A_CNXN);
        assert_eq!(header.arg0, ADB_VERSION);
        assert_eq!(header.arg1, ADB_MAX_PAYLOAD);
        assert_eq!(header.data_length, banner.len() as u32);
        assert_eq!(header.data_checksum, payload_checksum(&banner));
    }

    /// 设备 banner 是 `host:features` 与 `devices -l` 的唯一信息来源，字段缺失要留空而不是臆造。
    #[test]
    fn banner_fields_and_features_are_parsed() {
        let b = parse_banner(
            "device::ro.product.name=annibale;ro.product.model=REDMI K90;\
             ro.product.device=annibale;features=shell_v2,cmd,stat_v2\0",
        );
        assert_eq!(b.kind, "device");
        assert_eq!(b.product, "annibale");
        assert_eq!(b.model, "REDMI K90");
        assert_eq!(b.device, "annibale");
        assert_eq!(b.features, vec!["shell_v2", "cmd", "stat_v2"]);

        // recovery / sideload 的 banner 常常只有类型段，其余必须留空。
        let bare = parse_banner("recovery::");
        assert_eq!(bare.kind, "recovery");
        assert!(bare.product.is_empty() && bare.features.is_empty());
    }

    /// `host:features` 报的必须是交集：设备没有的不能报（客户端会发设备解不了的帧），
    /// 我们没通告的也不该报（设备根本不会启用）。设备特性未知时退回本机集合。
    #[test]
    fn negotiated_features_is_an_intersection() {
        assert_eq!(
            negotiated_features(&["shell_v2".into(), "cmd".into()]),
            "shell_v2,cmd",
            "设备多出来的特性只有在本端 CNXN 宣告后才能算进去"
        );
        assert_eq!(
            negotiated_features(&["cmd".into()]),
            "cmd",
            "本端已实现并宣告 cmd，设备支持时应回交集"
        );
        assert_eq!(negotiated_features(&[]), ADB_HOST_FEATURES);
    }

    /// 协商到跳过校验和的版本后，报头校验和置 0（AOSP 同款行为）。
    #[test]
    fn for_payload_skips_checksum_after_negotiation() {
        let with = AdbMessageHeader::for_payload(A_WRTE, 1, 2, b"data", ADB_VERSION_MIN);
        assert_eq!(with.data_checksum, payload_checksum(b"data"));
        let without =
            AdbMessageHeader::for_payload(A_WRTE, 1, 2, b"data", ADB_VERSION_SKIP_CHECKSUM);
        assert_eq!(without.data_checksum, 0);
    }

    #[test]
    fn inbound_payload_validation_rejects_corruption_before_skip_checksum() {
        let mut header = AdbMessageHeader::for_payload(A_WRTE, 1, 2, b"good", ADB_VERSION_MIN);
        assert!(validate_payload(&header, b"good", ADB_VERSION_MIN).is_ok());
        header.data_checksum ^= 1;
        assert!(validate_payload(&header, b"good", ADB_VERSION_MIN).is_err());
        header.data_checksum = 0;
        assert!(validate_payload(&header, b"good", ADB_VERSION_SKIP_CHECKSUM).is_ok());
    }

    #[test]
    fn unknown_transport_commands_are_not_accepted() {
        assert!(is_known_command(A_CNXN));
        assert!(is_known_command(A_STLS));
        assert!(!is_known_command(u32::from_le_bytes(*b"NOPE")));
    }

    #[test]
    fn handshake_accepts_modern_auth_without_weakening_legacy_sessions() {
        let token = [0x42; 20];
        let mut header = AdbMessageHeader::new(A_AUTH, 1, 0, token.len() as u32);
        assert!(validate_handshake_payload(&header, &token).is_ok());
        assert!(validate_payload(&header, &token, ADB_VERSION_MIN).is_err());
        header.data_checksum = payload_checksum(&token);
        assert!(validate_handshake_payload(&header, &token).is_ok());
        header.data_checksum ^= 1;
        assert!(validate_handshake_payload(&header, &token).is_err());
    }

    #[test]
    fn handshake_never_accepts_wrong_lengths_or_unchecksummed_legacy_data() {
        let bytes = b"device::";
        for command in [A_AUTH, A_CNXN] {
            let header = AdbMessageHeader::new(command, ADB_VERSION, 4096, bytes.len() as u32);
            assert!(validate_handshake_payload(&header, &bytes[..3]).is_err());
        }
        for command in [A_CNXN, A_WRTE] {
            let header = AdbMessageHeader::new(command, ADB_VERSION_MIN, 4096, bytes.len() as u32);
            assert!(validate_handshake_payload(&header, bytes).is_err());
        }
    }

    /// 协商语义（AOSP update_version）：版本取 min；maxdata 无效时回退旧协议 4KiB，
    /// 超过 1MiB 时钳到 1MiB。
    #[test]
    fn negotiate_matches_aosp_update_version() {
        assert_eq!(negotiate(0x01000000, 4096), (0x01000000, 4096));
        assert_eq!(
            negotiate(0x01000001, 1024 * 1024),
            (0x01000001, 1024 * 1024)
        );
        assert_eq!(
            negotiate(0x01000002, 16 * 1024 * 1024),
            (ADB_VERSION, 1024 * 1024)
        );
        assert_eq!(
            negotiate(0x01000001, 0),
            (0x01000001, ADB_LEGACY_MAX_PAYLOAD)
        );
    }
}
