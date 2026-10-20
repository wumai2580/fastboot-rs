pub const FB_CMD_GETVAR: &str = "getvar";
pub const FB_CMD_DOWNLOAD: &str = "download";
pub const FB_CMD_UPLOAD: &str = "upload";
pub const FB_CMD_FLASH: &str = "flash";
pub const FB_CMD_ERASE: &str = "erase";
pub const FB_CMD_BOOT: &str = "boot";
pub const FB_CMD_SET_ACTIVE: &str = "set_active";
pub const FB_CMD_CONTINUE: &str = "continue";
pub const FB_CMD_REBOOT: &str = "reboot";
pub const FB_CMD_CREATE_PARTITION: &str = "create-logical-partition";
pub const FB_CMD_DELETE_PARTITION: &str = "delete-logical-partition";
pub const FB_CMD_RESIZE_PARTITION: &str = "resize-logical-partition";
pub const FB_CMD_OEM: &str = "oem";
pub const FB_CMD_FETCH: &str = "fetch";
pub const FB_COMMAND_SZ: usize = 4096;
pub const FB_RESPONSE_SZ: usize = 256;
pub const FB_RESPONSE_PREFIX_LEN: usize = 4;
pub const FB_VAR_PARTITION_SIZE: &str = "partition-size";
pub const FB_VAR_PARTITION_TYPE: &str = "partition-type";

// ==================== 单次下发上限（全 crate 唯一权威） ====================
// `max-download-size` 只是设备**声明**愿意接收的量，部分机型（尤其 userspace fastboot/
// fastbootd）明显虚高：一加 ACE5 Pro（Android 16 / 16.2.700）fastbootd 报 0x10000000(256MB)，
// 但一次性发 96MB 的 boot，传到约 60MB 时设备就掐断传输（Windows 侧表现为 WinUSB
// ERROR_GEN_FAILURE），紧接着 bulk 端点失效、同一会话里剩余分区全线失败；同一台设备在
// bootloader 下同样大小却刷得进去——所以症结不是线材/驱动，而是不能无条件相信自报值。
// 分片下发只多几次 download/flash 往返，写入结果与一次性下发等价（官方 fastboot 对超限镜像
// 走的也是 resparse 分片），故所有刷写出口一律以本上限为闸门，不直接拿自报值判。

/// 单次 `download:` 的安全上限：超过即改走 sparse 分片，不再一次性整发。
pub const SAFE_SINGLE_DOWNLOAD_LIMIT: u64 = 48 * 1024 * 1024;

/// 传输被设备掐断后自适应降级的下限：降到这个粒度还断，就不是「一次发太多」，
/// 而是线材/端口/驱动问题，继续对折只会拖长失败时间。
pub const MIN_ADAPTIVE_DOWNLOAD_LIMIT: u64 = 8 * 1024 * 1024;

/// 有效单片上限：取设备自报值与安全上限的较小者（自报值本身更小时以它为准）。
pub fn effective_download_limit(max_download: u64) -> u64 {
    max_download.min(SAFE_SINGLE_DOWNLOAD_LIMIT)
}

/// `flashing lock/unlock[_critical]` 要等用户在设备上按键确认，常规 30s 超时会在用户还没按时就判失败。
/// 官方 fastboot 对这类命令一直阻塞等待；这里给 5 分钟上限。其余子命令（get_unlock_ability 等）用默认超时。
pub fn flashing_timeout(operation: &str) -> Option<std::time::Duration> {
    let op = operation.trim().to_ascii_lowercase();
    matches!(
        op.as_str(),
        "lock"
            | "unlock"
            | "lock_critical"
            | "unlock_critical"
            | "lock_bootloader"
            | "unlock_bootloader"
    )
    .then(|| std::time::Duration::from_secs(300))
}

/// 与 AOSP `is_vbmeta_partition` 一致：只有顶层 vbmeta（含 `_a/_b` 槽后缀）的 flags 才被 AVB 采信，
/// `--disable-verity/--disable-verification` 只改它；vbmeta_system 等链式 vbmeta 的 flags 会被忽略。
pub fn is_vbmeta_partition(partition: &str) -> bool {
    partition.ends_with("vbmeta")
        || partition.ends_with("vbmeta_a")
        || partition.ends_with("vbmeta_b")
}

// ==================== reboot 出口（fastboot 侧唯一权威） ====================
// 所有 fastboot reboot 出口（embed 单发、CLI）都必须显式回传 OKAY / ERROR 并带「用时 x.xxxs」，
// 不得只打印 `Rebooting` 这类无状态提示——上层按这段文本判定重启是否已下发。

/// reboot 目标归一：固定枚举（bootloader/recovery/fastboot/edl/sideload 及别名）大小写不敏感；
/// 未知目标原样（仅去首尾空白）透传——厂商私有目标可能大小写敏感，不能替用户改写。
/// 返回空串表示重启回系统（`reboot`）。
pub fn normalize_reboot_target(raw: &str) -> String {
    let lower = raw.trim().to_lowercase();
    match lower.as_str() {
        "" | "system" => String::new(),
        "bl" | "fb" | "bootloader" => "bootloader".into(),
        "rec" | "recovery" => "recovery".into(),
        "sideload" | "sideload-auto-reboot" => "sideload".into(),
        "fbd" | "fastbootd" | "fastboot" => "fastboot".into(),
        // 曾经 `_ => 原样` 让「reboot EDL」以大写下发（reboot-EDL），bootloader 不认——edl 必须显式归一。
        "edl" => "edl".into(),
        _ => raw.trim().to_string(),
    }
}

fn reboot_action_text(target: &str) -> String {
    match target.trim() {
        "" => "Rebooting".to_string(),
        // 线上命令是 reboot-fastboot，但它进的是 userspace 的 fastbootd，文案按用户认知写。
        "fastboot" => "Rebooting into fastbootd".to_string(),
        other => format!("Rebooting into {}", other),
    }
}

pub fn reboot_ok_text(target: &str, start: std::time::Instant) -> String {
    format!(
        "{} OKAY 用时 {:.3}s",
        reboot_action_text(target),
        start.elapsed().as_secs_f64()
    )
}

pub fn reboot_error_text(
    target: &str,
    start: std::time::Instant,
    error: impl AsRef<str>,
) -> String {
    let error = error.as_ref().trim();
    let detail = if error.is_empty() {
        "unknown error"
    } else {
        error
    };
    format!(
        "{} ERROR: {} 用时 {:.3}s",
        reboot_action_text(target),
        detail,
        start.elapsed().as_secs_f64()
    )
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Okay(String),
    Fail(String),
    Data(u32),
    Info(String),
    Text(String),
}

impl Response {
    pub fn parse(data: &[u8]) -> Result<(Self, bool), ParseError> {
        if data.len() < FB_RESPONSE_PREFIX_LEN {
            return Err(ParseError::TooShort {
                expected: FB_RESPONSE_PREFIX_LEN,
                actual: data.len(),
            });
        }

        let prefix = &data[..FB_RESPONSE_PREFIX_LEN];
        let payload_bytes = &data[FB_RESPONSE_PREFIX_LEN..];

        let payload = extract_payload(payload_bytes);

        match prefix {
            b"OKAY" => Ok((Response::Okay(payload), false)),
            b"FAIL" => Ok((Response::Fail(payload), false)),
            b"DATA" => {
                let size = parse_data_size(&payload)?;
                Ok((Response::Data(size), false))
            }
            b"INFO" => Ok((Response::Info(payload), true)),
            b"TEXT" => Ok((Response::Text(payload), true)),
            _ => Err(ParseError::UnknownPrefix {
                prefix: prefix.to_vec(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TooShort { expected: usize, actual: usize },
    UnknownPrefix { prefix: Vec<u8> },
    InvalidDataSize { raw: String },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::TooShort { expected, actual } => {
                write!(
                    f,
                    "响应太短: 需要至少 {} 字节，实际 {} 字节",
                    expected, actual
                )
            }
            ParseError::UnknownPrefix { prefix } => {
                write!(f, "未知响应前缀: {:?}", String::from_utf8_lossy(prefix))
            }
            ParseError::InvalidDataSize { raw } => {
                write!(f, "无效的 DATA 大小: '{}'，应该是 8 位十六进制", raw)
            }
        }
    }
}

impl std::error::Error for ParseError {}

fn extract_payload(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
fn parse_data_size(payload: &str) -> Result<u32, ParseError> {
    // 对齐 AOSP（strtoul 语义）：跳过前导空白、取前导十六进制位、容忍尾部杂字节。
    // 个别 bootloader 会在 8 位长度后跟 \r\n 或残留缓冲，整串严格解析会把合法 DATA 回包判死。
    // 但一位十六进制都没有仍是硬错误（strtoul 静默返回 0 反而会把协议错位吞掉）。
    let s = payload.trim_start();
    let end = s.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(s.len());
    let hex = &s[..end];
    if hex.is_empty() {
        return Err(ParseError::InvalidDataSize {
            raw: payload.to_string(),
        });
    }
    u32::from_str_radix(hex, 16).map_err(|_| ParseError::InvalidDataSize {
        raw: payload.to_string(),
    })
}

#[cfg(test)]
mod download_limit_tests {
    use super::*;

    /// 设备自报值虚高时必须被安全上限压住：一加 ACE5 Pro fastbootd 报 256MB，一次性发 96MB 的
    /// boot 会被设备掐断链路，因此有效上限只能是 48MB（超出即分片）。
    #[test]
    fn caps_inflated_device_reported_limit() {
        assert_eq!(
            effective_download_limit(256 * 1024 * 1024),
            SAFE_SINGLE_DOWNLOAD_LIMIT
        );
        assert_eq!(
            effective_download_limit(512 * 1024 * 1024),
            SAFE_SINGLE_DOWNLOAD_LIMIT
        );
    }

    /// 自报值本身更小的设备以它为准——不能反过来把上限抬到设备收不下的量。
    #[test]
    fn keeps_device_limit_when_it_is_already_smaller() {
        assert_eq!(effective_download_limit(16 * 1024 * 1024), 16 * 1024 * 1024);
        assert_eq!(effective_download_limit(1024), 1024);
    }

    /// 降级序列对折且不越过下限：48 → 24 → 12 → 8，到 8MB 停止（再降属线材/端口问题）。
    #[test]
    fn adaptive_halving_stops_at_floor() {
        let mut limit = SAFE_SINGLE_DOWNLOAD_LIMIT;
        let mut seen = Vec::new();
        while limit > MIN_ADAPTIVE_DOWNLOAD_LIMIT {
            limit = (limit / 2).max(MIN_ADAPTIVE_DOWNLOAD_LIMIT);
            seen.push(limit / (1024 * 1024));
        }
        assert_eq!(seen, vec![24, 12, 8]);
        assert_eq!(limit, MIN_ADAPTIVE_DOWNLOAD_LIMIT);
    }
}

#[cfg(test)]
mod reboot_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn reboot_status_text_always_contains_state_and_elapsed_time() {
        let ok = reboot_ok_text("fastboot", Instant::now());
        assert!(ok.starts_with("Rebooting into fastbootd OKAY 用时 "));
        assert!(ok.ends_with('s'));
        assert!(reboot_ok_text("", Instant::now()).starts_with("Rebooting OKAY 用时 "));

        let err = reboot_error_text("recovery", Instant::now(), "device rejected");
        assert!(err.starts_with("Rebooting into recovery ERROR: device rejected 用时 "));
        assert!(err.ends_with('s'));
        let blank = reboot_error_text("recovery", Instant::now(), "  ");
        assert!(blank.starts_with("Rebooting into recovery ERROR: unknown error 用时 "));
    }

    #[test]
    fn reboot_target_fixed_enums_are_case_insensitive() {
        assert_eq!(normalize_reboot_target("EDL"), "edl");
        assert_eq!(normalize_reboot_target("BootLoader"), "bootloader");
        assert_eq!(normalize_reboot_target("bl"), "bootloader");
        assert_eq!(normalize_reboot_target("FB"), "bootloader");
        assert_eq!(normalize_reboot_target("REC"), "recovery");
        assert_eq!(normalize_reboot_target("FastBootD"), "fastboot");
        assert_eq!(normalize_reboot_target("SIDELOAD-AUTO-REBOOT"), "sideload");
        assert_eq!(normalize_reboot_target("SYSTEM"), "");
        assert_eq!(normalize_reboot_target("  "), "");
        // 未知目标（厂商私有）原样透传，不改大小写。
        assert_eq!(normalize_reboot_target(" MyVendorMode "), "MyVendorMode");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_okay_empty() {
        let data = b"OKAY";
        let (response, cont) = Response::parse(data).unwrap();
        assert_eq!(response, Response::Okay(String::new()));
        assert!(!cont);
    }

    #[test]
    fn test_parse_okay_with_message() {
        let data = b"OKAY0.4";
        let (response, cont) = Response::parse(data).unwrap();
        assert_eq!(response, Response::Okay("0.4".to_string()));
        assert!(!cont);
    }

    #[test]
    fn test_parse_fail_with_message() {
        let data = b"FAILunknown command";
        let (response, cont) = Response::parse(data).unwrap();
        assert_eq!(response, Response::Fail("unknown command".to_string()));
        assert!(!cont);
    }

    #[test]
    fn test_parse_data_normal() {
        let data = b"DATA00001234";
        let (response, cont) = Response::parse(data).unwrap();
        assert_eq!(response, Response::Data(0x1234));
        assert!(!cont);
    }

    #[test]
    fn test_parse_data_max() {
        let data = b"DATAffffffff";
        let (response, cont) = Response::parse(data).unwrap();
        assert_eq!(response, Response::Data(0xFFFFFFFF));
        assert!(!cont);
    }

    #[test]
    fn test_parse_info() {
        let data = b"INFOerasing flash";
        let (response, cont) = Response::parse(data).unwrap();
        assert_eq!(response, Response::Info("erasing flash".to_string()));
        assert!(cont);
    }

    #[test]
    fn test_parse_text() {
        let data = b"TEXT50%";
        let (response, cont) = Response::parse(data).unwrap();
        assert_eq!(response, Response::Text("50%".to_string()));
        assert!(cont);
    }

    #[test]
    fn test_parse_with_null_terminator() {
        let data = b"OKAYtest\0garbage";
        let (response, _) = Response::parse(data).unwrap();
        assert_eq!(response, Response::Okay("test".to_string()));
    }

    #[test]
    fn test_parse_too_short() {
        let data = b"OK";
        let err = Response::parse(data).unwrap_err();
        assert!(matches!(err, ParseError::TooShort { .. }));
    }

    #[test]
    fn test_parse_unknown_prefix() {
        let data = b"WTFxxx";
        let err = Response::parse(data).unwrap_err();
        assert!(matches!(err, ParseError::UnknownPrefix { .. }));
    }

    #[test]
    fn test_parse_invalid_data_size() {
        let data = b"DATAnothex!";
        let err = Response::parse(data).unwrap_err();
        assert!(matches!(err, ParseError::InvalidDataSize { .. }));
    }

    #[test]
    fn test_parse_data_strtoul_semantics() {
        // 尾部杂字节（\r\n / 厂商残留缓冲）容忍：取前导十六进制位（AOSP strtoul 同语义）
        let (response, _) = Response::parse(b"DATA00001000\r\n").unwrap();
        assert_eq!(response, Response::Data(0x1000));
        // 前导空白跳过
        let (response, _) = Response::parse(b"DATA  0800").unwrap();
        assert_eq!(response, Response::Data(0x800));
        // 首个非十六进制字符处截断
        let (response, _) = Response::parse(b"DATA12min").unwrap();
        assert_eq!(response, Response::Data(0x12));
    }

    #[test]
    fn test_parse_data_no_hex_digits_is_error() {
        // 一位十六进制都没有：不能学 strtoul 静默给 0，否则协议错位被吞掉
        assert!(matches!(
            Response::parse(b"DATA").unwrap_err(),
            ParseError::InvalidDataSize { .. }
        ));
        assert!(matches!(
            Response::parse(b"DATA \r\n").unwrap_err(),
            ParseError::InvalidDataSize { .. }
        ));
    }

    #[test]
    fn test_error_display() {
        let err = ParseError::TooShort {
            expected: 4,
            actual: 2,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("2"));
        assert!(msg.contains("4"));

        let err = ParseError::UnknownPrefix {
            prefix: b"XXXX".to_vec(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("XXXX"));

        let err = ParseError::InvalidDataSize {
            raw: "notahex".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("notahex"));
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    /// 按设备侧线格式编码一条回包（只供往返测试喂给 `Response::parse`；主机侧从不发回包）。
    fn encode(response: &Response) -> Vec<u8> {
        let (prefix, payload) = match response {
            Response::Okay(s) => (b"OKAY", s.clone()),
            Response::Fail(s) => (b"FAIL", s.clone()),
            Response::Data(size) => (b"DATA", format!("{:08x}", size)),
            Response::Info(s) => (b"INFO", s.clone()),
            Response::Text(s) => (b"TEXT", s.clone()),
        };
        let mut out = prefix.to_vec();
        out.extend_from_slice(payload.as_bytes());
        out
    }

    fn valid_payload() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::char::range('\x01', '\x7f'), 0..200)
            .prop_map(|chars| chars.into_iter().collect())
    }
    fn any_response() -> impl Strategy<Value = Response> {
        prop_oneof![
            valid_payload().prop_map(Response::Okay),
            valid_payload().prop_map(Response::Fail),
            (0u32..=0xFFFFFFFF).prop_map(Response::Data),
            valid_payload().prop_map(Response::Info),
            valid_payload().prop_map(Response::Text),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn prop_roundtrip_okay(payload in valid_payload()) {
            let original = Response::Okay(payload);
            let encoded = encode(&original);
            let (parsed, cont) = Response::parse(&encoded).unwrap();
            prop_assert_eq!(&original, &parsed);
            prop_assert!(!cont, "OKAY 不应该需要继续等待");
        }

        #[test]
        fn prop_roundtrip_fail(payload in valid_payload()) {
            let original = Response::Fail(payload);
            let encoded = encode(&original);
            let (parsed, cont) = Response::parse(&encoded).unwrap();
            prop_assert_eq!(&original, &parsed);
            prop_assert!(!cont, "FAIL 不应该需要继续等待");
        }

        #[test]
        fn prop_roundtrip_data(size: u32) {
            let original = Response::Data(size);
            let encoded = encode(&original);
            let (parsed, cont) = Response::parse(&encoded).unwrap();
            prop_assert_eq!(&original, &parsed);
            prop_assert!(!cont, "DATA 不应该需要继续等待");
        }

        #[test]
        fn prop_roundtrip_info(payload in valid_payload()) {
            let original = Response::Info(payload);
            let encoded = encode(&original);
            let (parsed, cont) = Response::parse(&encoded).unwrap();
            prop_assert_eq!(&original, &parsed);
            prop_assert!(cont, "INFO 应该需要继续等待");
        }

        #[test]
        fn prop_roundtrip_text(payload in valid_payload()) {
            let original = Response::Text(payload);
            let encoded = encode(&original);
            let (parsed, cont) = Response::parse(&encoded).unwrap();
            prop_assert_eq!(&original, &parsed);
            prop_assert!(cont, "TEXT 应该需要继续等待");
        }
        #[test]
        fn prop_roundtrip_any(response in any_response()) {
            let encoded = encode(&response);
            let (parsed, cont) = Response::parse(&encoded).unwrap();
            prop_assert_eq!(&response, &parsed);
            let expected_cont = matches!(response, Response::Info(_) | Response::Text(_));
            prop_assert_eq!(cont, expected_cont);
        }

        #[test]
        fn prop_reject_short_input(data in prop::collection::vec(any::<u8>(), 0..4)) {
            let result = Response::parse(&data);
            prop_assert!(result.is_err());
            if let Err(ParseError::TooShort { expected, actual }) = result {
                prop_assert_eq!(expected, 4);
                prop_assert_eq!(actual, data.len());
            }
        }

        #[test]
        fn prop_reject_invalid_prefix(
            prefix in prop::collection::vec(any::<u8>(), 4..=4)
                .prop_filter("排除合法前缀", |p| {
                    p != b"OKAY" && p != b"FAIL" && p != b"DATA" &&
                    p != b"INFO" && p != b"TEXT"
                }),
            suffix in prop::collection::vec(any::<u8>(), 0..50)
        ) {
            let mut data = prefix;
            data.extend(suffix);
            let result = Response::parse(&data);
            prop_assert!(result.is_err());
            match result {
                Err(ParseError::UnknownPrefix { .. }) => {}
                other => prop_assert!(false, "期望 UnknownPrefix 错误，实际是 {:?}", other),
            }
        }

        #[test]
        fn prop_data_hex_encoding(size: u32) {
            let response = Response::Data(size);
            let encoded = encode(&response);
            prop_assert_eq!(&encoded[..4], b"DATA");
            let hex_part = std::str::from_utf8(&encoded[4..]).unwrap();
            prop_assert_eq!(hex_part.len(), 8);
            let parsed_size = u32::from_str_radix(hex_part, 16).unwrap();
            prop_assert_eq!(size, parsed_size);
        }
    }
}
