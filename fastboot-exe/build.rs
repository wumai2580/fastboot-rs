// 构建脚本 - 嵌入 Windows 版本信息

fn main() {
    #[cfg(windows)]
    {
        // 仅当本 crate 是命令行直接构建的包（CARGO_PRIMARY_PACKAGE）时才写 VERSIONINFO：
        // 无条件写会把 "Fastboot-RS"/固定版本塞给所有把 fastboot 当依赖的二进制——静态链接的
        // RMFlashTool.exe 会对外报错误产品名，版本恒 1.0.0 还被自动更新逻辑判成永远需更新，
        // 把用户卡在更新死循环里。库 crate 不该替链接方决定 VERSIONINFO。
        if std::env::var_os("CARGO_PRIMARY_PACKAGE").is_none() {
            return;
        }

        let mut res = winres::WindowsResource::new();
        res.set("ProductName", "Fastboot-RS")
            .set(
                "FileDescription",
                "Android Fastboot Tool - High Performance",
            )
            .set(
                "LegalCopyright",
                "Copyright (C) 2024-2026 GriefRedd & AndyWu",
            )
            .set("CompanyName", "GriefRedd & AndyWu")
            .set("OriginalFilename", "fastboot.exe")
            .set("ProductVersion", env!("CARGO_PKG_VERSION"))
            .set("FileVersion", env!("CARGO_PKG_VERSION"));

        if let Err(e) = res.compile() {
            eprintln!("Warning: Failed to compile Windows resources: {}", e);
        }
    }
}
