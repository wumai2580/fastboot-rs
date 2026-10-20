//! 操作响应的展示格式。协议帧、查询值、shell/exec-out 字节流仍由调用方原样传递。
//!
//! 原文用于排错和既有状态判定；译文只在展示出口追加，不能送回设备或参与数据解析。

const ZH_PREFIX: &str = "中文：";

/// 错误原文之后追加一行中文，保留原文中的路径、分区名、数值与错误码。
pub fn format_error(raw: &str) -> String {
    format_operation(raw)
}

/// 只汉化已识别的操作状态；设备列表、属性、认证数据及任意 shell 输出不变。
pub fn format_status(raw: &str) -> String {
    if has_translation(raw) {
        return raw.to_string();
    }
    // INFO 与属性/token 可以混在同一次回应中；只译状态行，不能再复制一次数据值。
    let translated = raw
        .lines()
        .filter(|line| is_status_line(line))
        .map(translate_line)
        .collect::<Vec<_>>()
        .join("；");
    append_translation(raw, &translated)
}

/// 已确认是给用户看的操作提示时使用；已有中文提示也按双行契约输出。
pub fn format_operation(raw: &str) -> String {
    if has_translation(raw) {
        return raw.to_string();
    }
    let translated = raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(translate_line)
        .collect::<Vec<_>>()
        .join("；");
    append_translation(raw, &translated)
}

fn has_translation(raw: &str) -> bool {
    raw.lines()
        .last()
        .is_some_and(|line| line.starts_with(ZH_PREFIX))
}

fn append_translation(raw: &str, translated: &str) -> String {
    if translated.is_empty() {
        return raw.to_string();
    }
    let separator = if raw.ends_with('\n') { "" } else { "\n" };
    format!("{raw}{separator}{ZH_PREFIX}{translated}")
}

fn is_status_line(line: &str) -> bool {
    let line = line
        .trim()
        .strip_prefix("(bootloader) ")
        .unwrap_or(line.trim());
    let lower = line.to_ascii_lowercase();
    if line.starts_with(ZH_PREFIX) {
        return false;
    }
    let line = if lower.starts_with('[') {
        lower
            .split_once("] ")
            .map_or(lower.as_str(), |(_, rest)| rest)
    } else {
        &lower
    };
    line == "success"
        || line == "okay"
        || line.starts_with("okay ")
        || line.starts_with("okay[")
        || line.starts_with("failure [")
        || line.starts_with("failed")
        || line.starts_with("error:")
        || line.starts_with("adb: error:")
        || [
            "sending '",
            "sending sparse '",
            "writing '",
            "erasing '",
            "resizing '",
            "rebooting",
            "booting",
            "resuming boot",
            "finished.",
            "setting vbmeta ",
            "connected to ",
            "disconnected ",
            "no tcp adb devices connected",
            "restarting ",
            "adbd is already ",
            "adbd cannot ",
            "remount succeeded",
            "remount failed",
            "performing ",
            "total xfer:",
            "total: ",
            "bug report copied to ",
            "recording ",
            "please confirm ",
            "setting current slot ",
            "staged ",
            "fetched ",
            "formatting ",
            "creating logical partition ",
            "deleting logical partition ",
            "resizing logical partition ",
            "update okay",
            "wipe okay",
            "format okay",
            "sideload 完成",
            "fetching '",
            "received ",
            "please unlock ",
            "please authorize ",
            "please confirm the ",
        ]
        .iter()
        .any(|prefix| line.starts_with(prefix))
        || [
            " file pushed",
            " files pushed",
            " file pulled",
            " files pulled",
            " file synced",
            " files synced",
            " file listed",
            " files listed",
        ]
        .iter()
        .any(|suffix| line.ends_with(suffix))
        || ["传输失败", "协议异常", "设备失败"]
            .iter()
            .any(|marker| line.contains(marker))
}

// 长句先于短词：避免把 "not allowed" 的否定拆丢，或把 "not found" 误译成成功。
// 厂商自由文本无法穷举；未识别部分必须明示，不能猜测成功或把不同失败归成同一种原因。
const PHRASES: &[(&str, &str)] = &[
    ("partition table doesn't exist", "分区表不存在"),
    ("partition table does not exist", "分区表不存在"),
    ("partition doesn't exist", "分区不存在"),
    ("partition does not exist", "分区不存在"),
    ("partition not exist", "分区不存在"),
    ("device is not unlocked", "引导加载程序未解锁"),
    ("bootloader is locked", "引导加载程序已锁定"),
    ("write to device failed", "向设备写入失败"),
    ("data transfer failure", "数据传输失败"),
    ("remote failure", "设备端执行失败"),
    ("getvar:", "读取设备变量："),
    ("readback failed", "回读数据失败"),
    ("failed to read response", "读取响应失败"),
    (
        "flashing is not allowed in lock state",
        "引导加载程序已锁定，不允许刷写",
    ),
    (
        "flashing is not allowed in locked state",
        "引导加载程序已锁定，不允许刷写",
    ),
    ("flashing is not allowed", "不允许刷写"),
    ("flashing unlock is not allowed", "不允许解锁引导加载程序"),
    ("device is locked", "引导加载程序已锁定"),
    ("device is already unlocked", "引导加载程序已解锁"),
    ("not enough space", "空间不足"),
    ("no space left on device", "设备剩余空间不足"),
    ("no such file or directory", "文件或目录不存在"),
    ("no such partition", "指定分区不存在"),
    ("partition not found", "未找到分区"),
    ("getvar variable not found", "未找到查询的设备变量"),
    ("variable not found", "未找到查询的设备变量"),
    ("no devices/emulators found", "未检测到设备或模拟器"),
    ("no emulators found", "未检测到模拟器"),
    (
        "more than one adb device/emulator",
        "连接了多台 ADB 设备或模拟器",
    ),
    ("more than one device/emulator", "连接了多台设备或模拟器"),
    (
        "device unauthorized",
        "设备未授权 USB 调试，请在手机上允许本机调试",
    ),
    ("device offline", "设备离线，ADB 通道尚不可用"),
    ("device hub setup timed out", "设备复用连接初始化超时"),
    ("access is denied", "拒绝访问"),
    ("permission denied", "权限不足"),
    ("operation not permitted", "不允许执行此操作"),
    ("operation not supported", "不支持此操作"),
    ("unknown command", "设备不支持此命令"),
    ("unknown error", "未知错误"),
    ("unknown partition", "未知分区"),
    (
        "invalid sparse file format at header",
        "稀疏镜像文件头格式无效",
    ),
    ("invalid image", "镜像无效"),
    ("image is too large", "镜像过大"),
    ("file is too large", "文件过大"),
    ("size mismatch: expected", "大小不匹配，预期"),
    ("expected okay after download", "下载数据后未收到成功终态"),
    ("expected okay after upload", "上传数据后未收到成功终态"),
    ("expected okay after fetch", "读取分区数据后未收到成功终态"),
    (
        "expected data or okay for fetch",
        "读取分区时未收到数据或成功响应",
    ),
    ("expected data after download", "下载请求后未收到数据响应"),
    ("unexpected response", "收到非预期响应"),
    ("unexpected adb status", "收到非预期 ADB 状态"),
    (
        "adb payload length does not match header",
        "ADB 数据长度与帧头声明不一致",
    ),
    (
        "adb tls upgrade (a_stls) is not supported by this transport",
        "此传输方式不支持 ADB TLS 加密升级",
    ),
    ("adb key engine failed", "ADB 认证密钥处理失败"),
    (
        "adbd cannot run as root in production builds",
        "正式系统不允许 ADB 服务以管理员权限运行",
    ),
    (
        "adbd is already running as root",
        "ADB 服务已在管理员权限下运行",
    ),
    (
        "adbd is already running as non root",
        "ADB 服务已在普通权限下运行",
    ),
    (
        "restarting adbd as root",
        "正在以管理员权限重新启动 ADB 服务",
    ),
    (
        "restarting adbd as non root",
        "正在以普通权限重新启动 ADB 服务",
    ),
    (
        "restarting in tcp mode port:",
        "正在重启到 TCP 网络模式，端口：",
    ),
    ("restarting in usb mode", "正在重启到 USB 模式"),
    ("remount succeeded", "重新挂载成功"),
    ("remount failed", "重新挂载失败"),
    ("performing streamed install", "正在流式安装应用"),
    ("performing push install", "正在传输并安装应用"),
    ("not installed for", "未为指定用户安装，用户编号"),
    (
        "install_failed_insufficient_storage",
        "安装失败：存储空间不足",
    ),
    (
        "install_failed_update_incompatible",
        "安装失败：与已安装应用的签名不一致",
    ),
    (
        "install_failed_version_downgrade",
        "安装失败：不允许降低应用版本",
    ),
    ("install_failed_already_exists", "安装失败：应用已安装"),
    (
        "install_failed_no_matching_abis",
        "安装失败：应用不支持设备的处理器架构",
    ),
    ("install_failed_invalid_apk", "安装失败：APK 文件无效"),
    (
        "install_failed_missing_split",
        "安装失败：缺少必需的拆分安装包",
    ),
    (
        "install_failed_user_restricted",
        "安装失败：用户或系统策略限制安装",
    ),
    (
        "install_failed_verification_failure",
        "安装失败：应用验证未通过",
    ),
    (
        "install_failed_test_only",
        "安装失败：测试应用需要允许测试安装参数",
    ),
    (
        "install_parse_failed_no_certificates",
        "安装失败：安装包缺少有效签名",
    ),
    ("delete_failed_internal_error", "卸载失败：系统内部错误"),
    ("failed to connect to", "连接失败，目标"),
    ("connection refused", "连接被拒绝"),
    ("connection reset by peer", "对端重置了连接"),
    ("connection aborted", "连接已中止"),
    ("broken pipe", "通信管道已断开"),
    ("device closed sideload stream", "设备关闭了旁加载数据流"),
    (
        "device closed sync stream before done",
        "设备在同步完成前关闭了数据流",
    ),
    ("device closed sync stream", "设备关闭了文件同步数据流"),
    ("device closed stream", "设备关闭了数据流"),
    ("client socket closed", "客户端网络连接已关闭"),
    ("stream closed", "数据流已关闭"),
    ("shell v2 unsupported", "不支持第二版终端协议"),
    ("does not exist", "不存在"),
    ("was not found", "未找到"),
    ("not found", "未找到"),
    ("must not be empty", "不能为空"),
    ("must not be 0", "不能为零"),
    ("not a usb device", "不是 USB 设备"),
    ("does not support", "不支持"),
    ("not supported", "不支持"),
    ("not allowed", "不允许"),
    ("timed out", "超时"),
    ("read-only file system", "文件系统只读"),
    ("no link", "设备连接已断开"),
    ("too many links", "系统链接数超限"),
    (
        "only device/disconnect waits are supported by the usb/tcp backend",
        "USB/TCP 后端仅支持等待设备连接或断开",
    ),
    ("requires at least one apk", "至少需要一个 APK 安装包"),
    ("accepts exactly one package", "必须且只能指定一个安装包"),
    ("accepts at most one path", "最多允许指定一个保存路径"),
    (
        "requires android_product_out to point to a build output directory",
        "需要将 ANDROID_PRODUCT_OUT 设置为系统构建输出目录",
    ),
    (
        "please confirm the wireless debugging authorization prompt on the device.",
        "请在设备上确认无线调试授权提示。",
    ),
    (
        "no tcp adb devices connected",
        "当前没有连接 TCP 网络 ADB 设备",
    ),
    ("disconnected everything", "已断开所有网络设备"),
    ("connected to", "已连接到"),
    ("finished. total time", "操作结束，总用时"),
    ("total xfer:", "总传输比例："),
    ("bug report copied to", "错误报告已保存到"),
    ("ctrl+c to stop early", "按 Ctrl+C 可提前停止"),
    ("recording for", "正在录屏，时长"),
    ("recording saved to", "录屏已保存到"),
    ("use -s <serial>", "请使用 -s <serial> 指定设备"),
    ("adb device with serial", "ADB 设备序列号"),
    ("adb usb device with serial", "ADB USB 设备序列号"),
    ("usb device with serial", "USB 设备序列号"),
    (
        "no sync partitions found under",
        "该目录下未找到可同步的分区",
    ),
    ("status read failed", "读取操作状态失败"),
    ("failed to", "未能"),
    ("unable to", "无法"),
    ("resuming boot", "正在继续系统引导"),
    ("rebooting into", "正在重启到"),
    ("setting current slot to", "正在设置当前活动槽位为"),
    ("setting active slot", "正在设置活动槽位"),
    ("creating logical partition", "正在创建逻辑分区"),
    ("deleting logical partition", "正在删除逻辑分区"),
    ("resizing logical partition", "正在调整逻辑分区大小"),
    ("at least one", "至少一个"),
    ("device reported sideload failure", "设备报告旁加载失败"),
    (
        "device requested sideload block beyond eof",
        "设备请求的旁加载数据块超出文件范围",
    ),
    ("no such device", "没有该设备"),
    ("command too long", "命令过长"),
    ("output file", "输出文件"),
    ("read timeout", "读取超时"),
    ("write timeout", "写入超时"),
    ("tcp adb", "TCP 网络 ADB"),
    ("snapshot-update cancel", "取消系统快照更新"),
    ("snapshot-update merge", "合并系统更新快照"),
    ("create-logical-partition", "创建逻辑分区"),
    ("delete-logical-partition", "删除逻辑分区"),
    ("resize-logical-partition", "调整逻辑分区大小"),
    ("update-super", "更新超级分区元数据"),
    ("wipe-super", "清除超级分区元数据"),
    ("sending sparse", "正在发送稀疏镜像"),
    ("setting vbmeta avb flags", "正在设置 vbmeta 启动验证标志"),
    ("os error", "系统错误码"),
    ("max-download-size", "最大下载大小"),
];

const WORDS: &[(&str, &str)] = &[
    ("okay", "成功"),
    ("success", "成功"),
    ("failed", "失败"),
    ("fail", "失败"),
    ("failure", "失败"),
    ("error", "错误"),
    ("remote", "设备端"),
    ("sending", "正在发送"),
    ("writing", "正在写入"),
    ("erasing", "正在擦除"),
    ("resizing", "正在调整大小"),
    ("sparse", "稀疏镜像"),
    ("rebooting", "正在重启"),
    ("booting", "正在引导"),
    ("resuming", "正在继续"),
    ("recovery", "恢复模式"),
    ("bootloader", "引导加载程序模式"),
    ("fastbootd", "用户空间 Fastboot 模式"),
    ("edl", "紧急下载模式"),
    ("sideload", "旁加载"),
    ("boot", "启动"),
    ("root", "管理员权限"),
    ("unroot", "普通权限"),
    ("remount", "重新挂载"),
    ("tcpip", "网络模式"),
    ("install", "安装"),
    ("uninstall", "卸载"),
    ("push", "推送文件"),
    ("pull", "拉取文件"),
    ("pushed", "已推送"),
    ("pulled", "已拉取"),
    ("sync", "同步"),
    ("synced", "已同步"),
    ("listed", "已列出"),
    ("file", "文件"),
    ("files", "文件"),
    ("directory", "目录"),
    ("local", "本地"),
    ("path", "路径"),
    ("package", "安装包"),
    ("command", "命令"),
    ("commands", "命令"),
    ("args", "参数"),
    ("requires", "需要"),
    ("usage", "用法"),
    ("invalid", "无效"),
    ("unsupported", "不支持"),
    ("unexpected", "非预期"),
    ("expected", "预期"),
    ("got", "实际收到"),
    ("missing", "缺少"),
    ("empty", "为空"),
    ("header", "帧头"),
    ("payload", "数据内容"),
    ("packet", "数据包"),
    ("kind", "类型"),
    ("length", "长度"),
    ("size", "大小"),
    ("bytes", "字节"),
    ("byte", "字节"),
    ("max", "最大值"),
    ("device", "设备"),
    ("devices", "设备"),
    ("emulator", "模拟器"),
    ("serial", "序列号"),
    ("port", "端口"),
    ("host", "主机"),
    ("transport", "传输"),
    ("protocol", "协议"),
    ("timeout", "超时"),
    ("disconnected", "已断开"),
    ("busy", "被占用"),
    ("offline", "离线"),
    ("unauthorized", "未授权 USB 调试"),
    ("read", "读取"),
    ("write", "写入"),
    ("open", "打开"),
    ("create", "创建"),
    ("configure", "配置"),
    ("stat", "读取文件信息"),
    ("flush", "刷新"),
    ("output", "输出"),
    ("terminal", "终端"),
    ("interactive", "交互式"),
    ("shell", "终端"),
    ("mux", "复用连接"),
    ("server", "服务端"),
    ("listener", "监听器"),
    ("socket", "网络连接"),
    ("bind", "绑定"),
    ("rebind", "重新绑定"),
    ("accept", "接收连接"),
    ("connection", "连接"),
    ("forward", "正向端口转发"),
    ("forwarder", "正向转发服务"),
    ("reverse", "反向端口转发"),
    ("reverser", "反向转发服务"),
    ("bugreport", "错误报告"),
    ("backup", "备份"),
    ("restore", "恢复备份"),
    ("keygen", "生成密钥"),
    ("key", "密钥"),
    ("engine", "处理模块"),
    ("recording", "正在录屏"),
    ("seconds", "秒"),
    ("total", "合计"),
    ("setting", "正在设置"),
    ("flags", "标志位"),
    ("true", "是"),
    ("false", "否"),
    ("into", "到"),
    ("to", "到"),
    ("from", "从"),
    ("after", "之后"),
    ("before", "之前"),
    ("for", "用于"),
    ("and", "和"),
    ("or", "或"),
    ("with", "带有"),
    ("at", "位于"),
    ("in", "在"),
    ("of", "的"),
    ("the", ""),
    ("a", ""),
    ("an", ""),
    ("is", ""),
    ("was", ""),
    ("not", "不"),
    ("no", "没有"),
    ("only", "仅"),
    ("cannot", "无法"),
    ("unable", "无法"),
    ("start", "启动"),
    ("under", "位于"),
    ("uses", "使用"),
    ("continue", "继续启动"),
    ("oem", "厂商命令"),
    ("raw", "原始命令"),
    ("flashing", "引导加载程序操作"),
    ("gsi", "通用系统镜像"),
    ("wipe", "清除"),
    ("disable", "禁用"),
    ("enable", "启用"),
    ("status", "状态"),
    ("cancel", "取消"),
    ("merge", "合并"),
    ("disable-verity", "禁用完整性校验"),
    ("disable-verification", "禁用签名验证"),
    ("closed", "已关闭"),
    ("done", "完成"),
    ("data", "数据"),
    ("staged", "已暂存"),
    ("fetched", "已读取"),
    ("formatting", "正在格式化"),
    ("formatted", "已格式化"),
    ("created", "已创建"),
    ("deleted", "已删除"),
    ("update", "更新"),
    ("stage", "暂存数据"),
    ("fetch", "读取分区数据"),
    ("current", "当前"),
    ("active", "活动"),
    ("slot", "槽位"),
    ("ack", "确认"),
    ("block", "数据块"),
    ("number", "编号"),
    ("request", "请求"),
    ("seek", "定位文件位置"),
    ("send", "发送"),
    ("product", "产品"),
    ("client", "客户端"),
    ("fetching", "正在读取分区数据"),
    ("received", "已接收"),
];

fn translate_line(raw: &str) -> String {
    let raw = raw.trim();
    let raw = raw.strip_prefix("(bootloader) ").unwrap_or(raw);
    // 分区、文件及网络目标是动态标识，按句型抽取后不再逐词翻译，避免把 boot 等分区名改掉。
    for (prefix, label) in [
        ("Sending sparse '", "正在发送稀疏镜像到分区"),
        ("Sending '", "正在发送分区"),
        ("Writing '", "正在写入分区"),
        ("Erasing '", "正在擦除分区"),
        ("Resizing '", "正在调整分区大小"),
        ("Fetching '", "正在读取分区"),
    ] {
        if let Some(rest) = raw.strip_prefix(prefix) {
            if let Some((name, suffix)) = rest.split_once('\'') {
                return format!("{label} '{name}'{}", translate_line(suffix));
            }
        }
    }
    for (suffix, action) in [
        (" pushed", "推送"),
        (" pulled", "拉取"),
        (" synced", "同步"),
        (" listed", "列出"),
    ] {
        if let Some(head) = raw.strip_suffix(suffix) {
            if let Some((target, count)) = head.rsplit_once(": ") {
                if let Some(count) = count
                    .strip_suffix(" files")
                    .or_else(|| count.strip_suffix(" file"))
                {
                    return format!("{target}：已{action} {count} 个文件");
                }
            }
        }
    }
    let lower = raw.to_ascii_lowercase();
    let mut translated = String::new();
    let mut unrecognized = false;
    let mut offset = 0;
    while offset < raw.len() {
        let rest = &raw[offset..];
        let lower_rest = &lower[offset..];
        let boundary = offset == 0 || !raw.as_bytes()[offset - 1].is_ascii_alphanumeric();
        if boundary {
            if let Some((phrase, chinese)) = PHRASES
                .iter()
                .filter(|(phrase, _)| {
                    lower_rest.starts_with(phrase)
                        && !lower_rest
                            .as_bytes()
                            .get(phrase.len())
                            .is_some_and(u8::is_ascii_alphanumeric)
                })
                .max_by_key(|(phrase, _)| phrase.len())
            {
                translated.push_str(chinese);
                offset += phrase.len();
                continue;
            }
        }
        let ch = rest.chars().next().unwrap();
        // 引号内的分区名/路径、带冒号的地址、十六进制码、单位和命令标志原样保留。
        // 被引号包裹的整句错误仍递归翻译，不能把 remote: 'Flashing is not allowed' 漏掉。
        if ch == '\'' || ch == '"' {
            // doesn't / can't 的词内撇号不是错误字符串的结束引号。
            if let Some(end) = rest[1..].char_indices().find_map(|(index, candidate)| {
                let inside_word = ch == '\''
                    && rest
                        .as_bytes()
                        .get(index)
                        .is_some_and(u8::is_ascii_alphabetic)
                    && rest
                        .as_bytes()
                        .get(index + 2)
                        .is_some_and(u8::is_ascii_alphabetic);
                (candidate == ch && !inside_word).then_some(index)
            }) {
                let value = &rest[1..end + 1];
                translated.push(ch);
                if value.contains(' ') && !looks_like_path(value) {
                    translated.push_str(&translate_line(value));
                } else {
                    translated.push_str(value);
                }
                translated.push(ch);
                offset += end + 2;
                continue;
            }
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '/' | '\\' | '-') {
            let end = rest
                .find(|c: char| {
                    !c.is_ascii()
                        || c.is_whitespace()
                        || matches!(c, ',' | ';' | '(' | ')' | '[' | ']' | '=' | '\'' | '"')
                })
                .unwrap_or(rest.len());
            let token = &rest[..end];
            let word = token.trim_end_matches([':', '.', '!', '?']);
            let punctuation = &token[word.len()..];
            if let Some((_, chinese)) = WORDS
                .iter()
                .find(|(known, _)| word.eq_ignore_ascii_case(known))
            {
                translated.push_str(chinese);
                translated.push_str(punctuation);
            } else {
                translated.push_str(token);
                if word.bytes().any(|b| b.is_ascii_alphabetic()) && !is_identifier(word) {
                    unrecognized = true;
                }
            }
            offset += end;
        } else {
            translated.push(ch);
            offset += ch.len_utf8();
        }
    }
    let translated = translated.split_whitespace().collect::<Vec<_>>().join(" ");
    if unrecognized {
        format!("{translated}（含暂未收录的设备或系统用语，请对照上方原文）")
    } else {
        translated
    }
}

fn looks_like_path(value: &str) -> bool {
    value.contains('/') || value.contains('\\')
}

fn is_identifier(word: &str) -> bool {
    looks_like_path(word)
        || word.contains([':', '_', '.', '<', '>'])
        || word.starts_with('-')
        || word.bytes().any(|b| b.is_ascii_digit())
        || matches!(
            word,
            "ADB"
                | "USB"
                | "TCP"
                | "APK"
                | "AVB"
                | "INFO"
                | "TEXT"
                | "DATA"
                | "DONE"
                | "KB"
                | "MB"
                | "GB"
                | "HRESULT"
                | "Ctrl+C"
        )
}
