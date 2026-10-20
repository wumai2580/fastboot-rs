//! `fastboot` 二进制薄壳：出货为 `adb.exe` / `fastboot.exe` / `rmf-cli.exe`。
//!
//! 全部实现都在库内 [`fastboot::cli_main`]，bin 与 GUI 进程内入口（`fastboot::embed`）共用同一次编译的
//! 协议模块；这里不得再声明任何 `mod`，否则同一份源码会按两个 crate root 各编译一遍。

#[tokio::main]
async fn main() {
    fastboot::cli_main::main().await;
}
