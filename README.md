# fastboot-rs

Windows 上的 Rust ADB / Fastboot 协议栈、CLI 和进程内 Rust API。保留 GriefRedd、AndyWu
的作者归属，协议包使用 [BSD-3-Clause](fastboot-exe/LICENSE)。

本文是唯一权威项目总文档；[版本变更](RELEASE_NOTES.md) 记录版本差异，
[旧交付文档](fastboot-exe/交付文档-改进与组件说明.md) 仅保留历史入口。

## 范围与当前状态

- `fastboot-exe/` 同步 RMFlashTool 当前使用的协议源码，版本 **2.0.0**，尚未发布正式 tag。
- 目标为 Windows 10+ x64 和 WinUSB / 兼容 Android 驱动；非 Windows 明确拒绝编译。
- CLI 与 `fastboot::embed` 共用同一份协议实现，不依赖官方 platform-tools。
- `ksud/` 是工作区内独立的 KernelSU 相关工具，不属于 ADB / Fastboot 协议实现。
- 旧 DLL C ABI、Fastboot TCP/UDP 和 CLI 内联 KernelSU 修补的迁移边界见下文。

## 架构与目录

```text
fastboot-rs/
├── Cargo.toml / Cargo.lock       工作区与统一依赖锁
├── .cargo/config.toml            Windows x64 静态 CRT
├── .github/workflows/            Windows 构建与 tag 发布
├── fastboot-exe/
│   ├── Cargo.toml / build.rs     协议库、CLI 与独立构建的版本资源
│   └── src/
│       ├── lib.rs / main.rs      Rust 库入口与 CLI 薄入口
│       ├── cli_main.rs / cli.rs  命令定义与编排
│       ├── embed.rs              同步 API、取消、批量会话、按设备传输快照
│       ├── adb_protocol.rs       ADB 帧、版本协商、校验和、设备 banner
│       ├── adb_winusb_transport.rs / crypto.rs
│       │                         USB 读写与持久化 RSA 认证
│       ├── adb_mux*.rs / adb_host_proto.rs
│       │                         单连接复用、5037 host 协议与客户端
│       ├── adb_sync.rs / adb_install.rs / scrcpy_prep.rs
│       │                         文件同步、安装、投屏准备
│       ├── adb_tcp_transport.rs  传统 ADB TCP 连接
│       ├── protocol.rs / driver.rs / transport_open.rs
│       │                         Fastboot 协议、驱动、连接探测
│       ├── usb_iface.rs / usb_transport.rs
│       │                         无占用接口识别与 WinUSB 传输
│       └── flash.rs / sparse.rs  刷写编排与 sparse 镜像处理
└── ksud/                         独立工具，按其自身平台约束使用
```

ADB 多路流共享一条 USB 连接，server 持有设备时客户端不能回退直连。
Fastboot 探测与实际命令使用同一套协议判据。设备对象、会话属主与跨线程句柄的生命周期由各模块管理。

## 依赖、构建与运行

当前同步环境为 Rust 1.96、Windows x64 MSVC；CI 使用 stable。
需要 Git、Rust MSVC 工具链，以及 Visual Studio 的 C++ 桌面开发工具和 Windows SDK。
依赖由 Cargo 管理，根目录 `Cargo.lock` 是工作区唯一依赖锁；协议包没有必需的产品账号或云端服务。

在根目录构建协议包：

```powershell
cargo build --locked --release -p fastboot --lib --bin fastboot
Copy-Item target/release/fastboot.exe target/release/adb.exe
Copy-Item target/release/fastboot.exe target/release/rmf-cli.exe

.\target\release\adb.exe devices -l
.\target\release\adb.exe shell getprop ro.product.model
.\target\release\fastboot.exe devices
.\target\release\fastboot.exe getvar product
```

三份 EXE 来自同一个二进制，按进程文件名选择 adb / fastboot 语义。`rmf-cli.exe` 是宿主分发用名；
宿主要运行 adb 命令时应复制或改名为 `adb.exe`。命令和参数以各自 `--help` 为准。
支持 shell、push/pull、安装、forward/reverse、sideload，以及 getvar、flash/update、槽位、
逻辑分区、stage/fetch 和 reboot 等命令。

普通 GitHub Actions 构建产出三个 Windows EXE；推送 `v*` tag 时发布相同的三个文件。
更新源代码不会自动创建 tag 或 GitHub Release。

开发入口：

```powershell
cargo check --locked -p fastboot --lib --bin fastboot
cargo test --locked -p fastboot --lib
cargo doc --locked -p fastboot --no-deps
cargo build --locked -p ksud
```

单测包含协议回放、socket 帧序、sparse 解析；需要外部大镜像的用例保持 ignored。
编译和静态检查不操作手机，实际刷写命令会操作设备。

## Rust 进程内 API

消费方通过路径依赖链接 `fastboot-exe`，调用 `fastboot::embed`：

```rust
use fastboot::embed;

fn read_device() -> Result<String, String> {
    embed::adb_shell(None, "getprop ro.product.model")
}

fn read_bootloader(serial: &str) -> Result<String, String> {
    embed::fb_getvar(Some(serial), "product")
}
```

| 用途 | 接口 |
| --- | --- |
| ADB 设备、shell、文件、安装、重启 | `adb_devices`、`adb_shell`、`adb_push`、`adb_pull`、`adb_install`、`adb_reboot` |
| 宿主内完整 5037 mux | `adb_ensure_inproc_mux`、`adb_inproc_mux_running` |
| Fastboot 查询、刷写、重启 | `fb_devices`、`fb_getvar`、`fb_getvars`、`fb_flash`、`fb_erase`、`fb_reboot` |
| 单设备批量会话 | `fb_session_begin`、`fb_session_flash`、`fb_session_erase`、`fb_session_end` |
| 取消与超时 | `request_cancel`、`OpCancel`、`set_op_cancel`、`set_op_timeout_secs` |
| 按设备隔离的进度 | `xfer_snapshot(serial)` |

结果以字符串 / `Result<T, String>` 返回；传输快照区分设备、总量、已传量与设备写入阶段。
宿主必须保留设备选择与取消边界，不能因后台查询超时取消其他设备的长传输。

## 连接、认证与配置

- 当前用户的 `~/.android/adbkey` 持久化 RSA 私钥，兼容 PKCS#8 和 PKCS#1；已有可读密钥复用，
  公钥核对配对。手机第一次连接仍须允许 USB 调试。
- USB 接口按 class/subclass/protocol 三元组区分 ADB、Fastboot 与其他接口，枚举不抢设备句柄。
- 5037 已有官方或兼容 ADB server 时复用；端口空闲时启动自己的 mux。
- USB ZLP 不视为断线；普通握手读窗口 5 秒，发公钥后才进入 180 秒人工授权等待。
- 建连任务由设备线程持有，调用方超时不会再拉一条握手争抢句柄；瞬态失败后允许重新连接。
- `scrcpy-prep` 仅在真实 `getprop` 应答后报告 ready，未授权 / offline / fastboot 状态如实返回。
- 长驻 mux 支持 shell、sync、forward/reverse 等并发流，同一设备只有一个 USB 属主。

| 配置 | 作用 |
| --- | --- |
| `RMF_ADB_MUX=1` | CLI 设备命令自动复用 / 启动 5037 mux，供 scrcpy 等多连接客户端使用 |
| `RMF_ADB_DAEMON=0` | 关闭 CLI 命名管道 daemon；默认启用 |
| `RMF_ADB_DAEMON_IDLE_MS` | daemon 空闲退出窗口，至少 2000 毫秒 |
| `RMF_ADB_WAIT_TIMEOUT_MS` | wait-for 类命令超时，0 为不限 |
| `RMF_RUNTIME_ROOT`、`RMFLASH_LOG_DIR` | 可选日志配置；日志目录必须位于受控运行时根下，未配置时独立 CLI 不落日志 |

传统 ADB TCP 设备和独立转发登记在 `%LOCALAPPDATA%/rmf-adb-fastboot/` 的状态文件中。
这些文件和 RSA 私钥是运行时数据，不能加入版本库。

## Fastboot 正确性约束

- 连接探测消费 INFO / TEXT 至合法终态，不能仅凭收到字节就认定正常。
- `getvar all`、DATA 收发均检查最终 OKAY / FAIL，保留明确失败，不能把部分输出当成功。
- 只读查询在边界内可重建一次连接；刷写、擦除、重启、分区变更和 DATA 阶段不能因此盲目重发。
- `oem`、`flashing` 按 AOSP 格式发送，重启结果明确返回成功 / 失败及耗时。
- 大镜像按设备限制与 sparse 结构分块，多设备的进度、会话与取消不得相互覆盖。

## 2.0 接口迁移与限制

本次同步存在公开接口变化，合并前应按以下边界审阅：

1. 库目标改为 **Rust rlib**，不再产出旧 `fastboot.dll` C ABI。旧 DLL 调用方需要迁移到自己的
   FFI 边界或新的 Rust 宿主 API，不能直接替换 DLL 文件。
2. CLI 不再接受 `flash ... patch ...` 的内联 KernelSU 修补参数，输入镜像应在刷写前准备好。
   `ksud` 独立组件的使用与协议包分开。
3. 不保留旧 Fastboot TCP/UDP 后端与辅助测试 EXE；当前 Fastboot 传输目标是 Windows USB。
4. ADB mux 为单设备 hub，多设备连接时须明确选择，不是多设备并发投屏服务器。
5. 不提供现代 ADB TLS / 无线配对或模拟器 transport；传统 ADB TCP 是另一条独立路径。
6. 实际命令能力受 bootloader / adbd 限制，不能仅凭命令同名宣称与官方工具完全等价。

## 验证、排错与后续计划

导入前同一协议源码在宿主工程完成库测试 **287 通过 / 0 失败 / 3 忽略**；最终 ADB 调整后，
相关用例 **121 通过 / 0 失败**。本次复用记录，不重新运行单元测试或设备测试。

2026-10-19 在已授权的 REDMI K90 / Android 17 上验证：官方 ADB 后台退出、5037 空闲后，
独立 CLI 读取设备信息成功；宿主先启动后下载并投屏成功，投屏中查询及停启投屏正常。
这些记录不覆盖首次授权、实体拔插、所有驱动组合或新一轮 Fastboot 真机刷写。

offline / unauthorized 应先核对手机授权、驱动、5037 属主和受控日志；不能靠杀其他程序的 ADB
或重置设备端点掩盖握手问题。Fastboot 故障须保留终态与 USB 上下文，区分设备 FAIL、坏协议与断开。
本次独立工作区已通过 `cargo check --locked --offline -p fastboot --lib --bin fastboot`，
并完成源码一致性与差异审查；没有重新运行单元测试或设备测试。

后续重点是不同电脑 / 驱动组合验证，以及在维持单一协议实现的前提下评估新的宿主接口需求。
