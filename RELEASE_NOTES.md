# 版本变更

现行架构、使用方式和限制以 [README](README.md) 为准。

## 2026-10-20 操作响应中文解释

- CLI 人类可读操作提示和错误保留原文，随后一行中文解释；新增公开纯函数 response_text，供宿主复用。
- 保留设备查询、认证数据、shell/exec-out 和 JSON 数据的解析契约；未收录的厂商用语明确标注。
- 普通 Fastboot 脚本页保留阶段/成功摘要，仅错误详情采用双行格式；批量页仅展示进度与结果状态（页面改动在宿主工程）。
- CLI 与宿主编译检查通过；未运行单元或设备测试，未创建 tag/Release。

## 2.0.0 — 2026-10-20 协议同步，尚未打正式 tag

- 同步现用 Windows ADB / Fastboot 协议源码，CLI 与 Rust embed 共用同一份实现。
- 新增完整 5037 host 协议、单连接 mux、forward/reverse、scrcpy 准备、安装和 sync 支持。
- 修正 USB ZLP、握手等待窗口、重复建连争抢句柄、首次失败后不再连接和空属性仍报告投屏就绪。
- 同步 Fastboot 终态校验、连接探测、只读查询恢复与按设备隔离的传输和会话管理。
- 明确 Rust rlib 与旧 DLL C ABI、内联 KernelSU 修补、Fastboot TCP/UDP 的迁移边界。
- Windows CI 和 tag 发布选择协议包，产出 fastboot.exe、adb.exe、rmf-cli.exe。
- 复用导入前的协议测试与 K90 真机记录，本次不重复运行单元测试或设备测试。
