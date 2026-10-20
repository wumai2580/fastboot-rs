use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "fastboot")]
#[command(author = "Fastboot Rust Port")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Android Fastboot/ADB tool rewritten in Rust", long_about = None)]
pub struct Cli {
    #[arg(short = 's', long, global = true)]
    pub serial: Option<String>,

    /// 目标槽位：a / b / other / all（对齐官方 `--slot`）。flash/flashall/update/wipe-super/update-super 生效。
    #[arg(long, global = true)]
    pub slot: Option<String>,

    /// 刷 vbmeta 时置 HASHTREE_DISABLED 位（关闭 dm-verity）。
    #[arg(long = "disable-verity", global = true)]
    pub disable_verity: bool,

    /// 刷 vbmeta 时置 VERIFICATION_DISABLED 位（关闭 AVB 校验）。
    #[arg(long = "disable-verification", global = true)]
    pub disable_verification: bool,

    /// flashall / update 完成后不重启（官方默认会重启）。
    #[arg(long = "skip-reboot", global = true)]
    pub skip_reboot: bool,

    /// 命令成功后切换活动槽：`--set-active` 用 `--slot`（缺省当前槽），`--set-active=b` 指定槽位。
    #[arg(
        long = "set-active",
        global = true,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = ""
    )]
    pub set_active: Option<String>,

    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Devices {
        /// 附带 USB VID:PID / 产品名等信息。
        #[arg(short = 'l', long)]
        long: bool,
    },

    Getvar {
        variable: String,
    },

    Flash {
        partition: String,
        filename: PathBuf,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        extra_args: Vec<String>,
    },

    Erase {
        partition: String,
    },

    #[command(visible_alias = "r")]
    Reboot {
        #[arg(default_value = "")]
        target: String,
    },

    Flashall {
        #[arg(short, long)]
        wipe: bool,
    },

    Update {
        filename: PathBuf,
        /// 同时擦除 userdata + metadata。
        #[arg(short, long)]
        wipe: bool,
    },

    Diagnose,

    Upload {
        partition: String,
        filename: PathBuf,
    },

    #[command(visible_alias = "sh")]
    Shell {
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    Push {
        local: PathBuf,
        remote: String,
    },

    Pull {
        remote: String,
        local: PathBuf,
    },

    #[command(visible_alias = "i")]
    Install {
        apk: PathBuf,
        #[arg(short, long)]
        replace: bool,
    },

    #[command(name = "install-multiple", visible_alias = "install-multi")]
    InstallMultiple {
        #[arg(required = true, num_args = 1..)]
        apks: Vec<PathBuf>,
        #[arg(short, long)]
        replace: bool,
    },

    Uninstall {
        package: String,
    },

    #[command(visible_alias = "pm")]
    Packages {
        #[arg(short = '3', long)]
        third_party: bool,
        #[arg(short = 's', long)]
        system: bool,
    },

    Logcat {
        #[arg(trailing_var_arg = true)]
        filter: Vec<String>,
    },

    Screencap {
        #[arg(default_value = "screenshot.png")]
        output: PathBuf,
    },

    Screenrecord {
        #[arg(default_value = "recording.mp4")]
        output: PathBuf,
        #[arg(short, long, default_value = "180")]
        time: u32,
    },

    #[command(name = "set_active", visible_alias = "set-active")]
    SetActive {
        slot: String,
    },

    Oem {
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// 原样透传：把 raw 之后的整串作为 fastboot 命令直接发给设备（不加 "oem " 前缀、不做任何包装）。
    /// 用于厂商私有指令（如 VIVO BBK 只认字符串命令）：`fastboot raw <厂商指令>` → 设备收到 `<厂商指令>`。
    Raw {
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    Flashing {
        operation: String,
    },

    Format {
        partition: String,
        #[arg(short = 't', long)]
        fs_type: Option<String>,
        #[arg(short = 's', long)]
        size: Option<String>,
    },

    Boot {
        kernel: PathBuf,
        ramdisk: Option<PathBuf>,
    },

    /// `fetch <partition>[:offset[:size]] <outfile>`：回读分区（fastbootd）。
    Fetch {
        partition: String,
        output: PathBuf,
    },

    Root,

    Unroot,

    #[command(name = "create-logical-partition")]
    CreateLogicalPartition {
        name: String,
        size: u64,
    },

    #[command(name = "delete-logical-partition")]
    DeleteLogicalPartition {
        name: String,
    },

    #[command(name = "resize-logical-partition")]
    ResizeLogicalPartition {
        name: String,
        size: u64,
    },

    #[command(name = "snapshot-update")]
    SnapshotUpdate {
        operation: String,
    },

    Gsi {
        operation: String,
    },

    #[command(name = "wipe-super")]
    WipeSuper {
        super_empty: Option<PathBuf>,
    },

    #[command(name = "update-super")]
    UpdateSuper {
        /// super 元数据镜像（lpmake 生成，如 super_empty.img）。
        image: PathBuf,
        /// 附加 `wipe`：先清空所有现存逻辑分区再合并。
        #[arg(long)]
        wipe: bool,
    },

    Stage {
        input: PathBuf,
    },

    #[command(name = "get_staged")]
    GetStaged {
        output: PathBuf,
    },

    /// `fastboot continue`：结束 fastboot、继续正常启动。
    Continue,

    /// 擦除 userdata + metadata（等价官方 `fastboot -w`）。
    Wipe,

    #[command(name = "截图")]
    Jietu,

    #[command(name = "音量加")]
    VolUp,

    #[command(name = "音量减")]
    VolDown,

    #[command(name = "锁屏")]
    LockScreen,

    Custom {
        cmd: String,
    },
}
