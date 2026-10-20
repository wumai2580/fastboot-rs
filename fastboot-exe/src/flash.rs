use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use zip::ZipArchive;

use crate::error::FastbootError;
use crate::sparse::SPARSE_HEADER_MAGIC;

pub trait ImageSource: Send + Sync {
    fn read_file(&self, name: &str) -> io::Result<Vec<u8>>;
    fn exists(&self, name: &str) -> bool;
    fn file_size(&self, name: &str) -> io::Result<u64>;
    fn get_file_path(&self, name: &str) -> Option<PathBuf>;
    /// 只读文件开头至多 `len` 字节（探测 sparse 魔数等）。默认实现退化为整文件读取；
    /// 本地/ZIP 源都覆写成真前缀读——为了看 4 字节魔数把数 GB 的 super.img
    /// 全部读进内存是此前流程里最大的一笔无谓开销。
    fn read_prefix(&self, name: &str, len: usize) -> io::Result<Vec<u8>> {
        let mut data = self.read_file(name)?;
        data.truncate(len);
        Ok(data)
    }
    /// 把镜像内容流式写入 `out`（分块搬运，不整读进内存），返回写出的字节数。
    /// 默认实现退化为整文件读取；本地/ZIP 源覆写为真流式——超限大镜像
    /// 物化到临时文件时靠它避免「先整读再落盘」的内存峰值。
    fn copy_to(&self, name: &str, out: &mut dyn Write) -> io::Result<u64> {
        let data = self.read_file(name)?;
        out.write_all(&data)?;
        Ok(data.len() as u64)
    }
}
pub struct LocalImageSource {
    path: PathBuf,
}

impl LocalImageSource {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

impl ImageSource for LocalImageSource {
    fn read_file(&self, name: &str) -> io::Result<Vec<u8>> {
        let file_path = self.path.join(name);
        let mut file = File::open(&file_path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn exists(&self, name: &str) -> bool {
        self.path.join(name).exists()
    }

    fn file_size(&self, name: &str) -> io::Result<u64> {
        let file_path = self.path.join(name);
        let metadata = std::fs::metadata(&file_path)?;
        Ok(metadata.len())
    }

    fn get_file_path(&self, name: &str) -> Option<PathBuf> {
        let path = self.path.join(name);
        if path.exists() {
            Some(path)
        } else {
            None
        }
    }

    fn read_prefix(&self, name: &str, len: usize) -> io::Result<Vec<u8>> {
        let mut file = File::open(self.path.join(name))?;
        let mut buf = vec![0u8; len];
        let mut read = 0;
        while read < len {
            let n = file.read(&mut buf[read..])?;
            if n == 0 {
                break;
            }
            read += n;
        }
        buf.truncate(read);
        Ok(buf)
    }

    fn copy_to(&self, name: &str, out: &mut dyn Write) -> io::Result<u64> {
        let mut file = File::open(self.path.join(name))?;
        io::copy(&mut file, out)
    }
}

pub struct ZipImageSource<R: Read + Seek> {
    archive: Arc<Mutex<ZipArchive<R>>>,
    file_list: Vec<String>,
}

impl ZipImageSource<File> {
    pub fn from_path(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = File::open(path.as_ref())?;
        Self::new(file)
    }
}

impl<R: Read + Seek> ZipImageSource<R> {
    pub fn new(reader: R) -> io::Result<Self> {
        let mut archive = ZipArchive::new(reader).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("无效的 ZIP 文件: {}", e),
            )
        })?;
        let file_list: Vec<String> = (0..archive.len())
            .filter_map(|i| archive.by_index(i).ok().map(|f| f.name().to_string()))
            .collect();

        Ok(Self {
            archive: Arc::new(Mutex::new(archive)),
            file_list,
        })
    }
    fn find_file_index(&self, name: &str) -> Option<usize> {
        for (i, file_name) in self.file_list.iter().enumerate() {
            if file_name == name {
                return Some(i);
            }
            if file_name.ends_with(&format!("/{}", name)) {
                return Some(i);
            }
            if let Some(base_name) = file_name.rsplit('/').next() {
                if base_name == name {
                    return Some(i);
                }
            }
        }
        None
    }
}

impl<R: Read + Seek + Send + Sync> ImageSource for ZipImageSource<R> {
    fn read_file(&self, name: &str) -> io::Result<Vec<u8>> {
        let idx = self.find_file_index(name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("ZIP 中找不到文件 {}", name),
            )
        })?;

        let mut archive = self.archive.lock();
        let mut file = archive.by_index(idx).map_err(|e| {
            io::Error::new(io::ErrorKind::NotFound, format!("读取 ZIP 文件失败: {}", e))
        })?;

        let mut buf = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn exists(&self, name: &str) -> bool {
        self.find_file_index(name).is_some()
    }

    fn file_size(&self, name: &str) -> io::Result<u64> {
        let idx = self.find_file_index(name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("ZIP 中找不到文件 {}", name),
            )
        })?;

        let mut archive = self.archive.lock();
        let file = archive.by_index(idx).map_err(|e| {
            io::Error::new(io::ErrorKind::NotFound, format!("读取 ZIP 文件失败: {}", e))
        })?;

        Ok(file.size())
    }

    fn get_file_path(&self, _name: &str) -> Option<PathBuf> {
        None
    }

    fn read_prefix(&self, name: &str, len: usize) -> io::Result<Vec<u8>> {
        let idx = self.find_file_index(name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("ZIP 中找不到文件 {}", name),
            )
        })?;

        let mut archive = self.archive.lock();
        let file = archive.by_index(idx).map_err(|e| {
            io::Error::new(io::ErrorKind::NotFound, format!("读取 ZIP 文件失败: {}", e))
        })?;

        // ZipFile 支持流式读：只解压前 len 字节，探测魔数不用展开整个条目。
        let mut buf = Vec::with_capacity(len);
        file.take(len as u64).read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn copy_to(&self, name: &str, out: &mut dyn Write) -> io::Result<u64> {
        let idx = self.find_file_index(name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("ZIP 中找不到文件 {}", name),
            )
        })?;

        let mut archive = self.archive.lock();
        let mut file = archive.by_index(idx).map_err(|e| {
            io::Error::new(io::ErrorKind::NotFound, format!("读取 ZIP 文件失败: {}", e))
        })?;
        io::copy(&mut file, out)
    }
}

/// 超限大镜像的「按路径访问」物化结果：分片刷写路径（StreamingResparse/mmap/raw 分块）
/// 都要求真实文件路径。本地源直接借用原路径（零拷贝）；zip 等无路径源流式解压到
/// 临时文件，`Temp` 守卫在 drop 时自动删除。
pub enum MaterializedImage {
    Borrowed(PathBuf),
    Temp(tempfile::NamedTempFile),
}

impl MaterializedImage {
    pub fn path(&self) -> &Path {
        match self {
            MaterializedImage::Borrowed(p) => p,
            MaterializedImage::Temp(t) => t.path(),
        }
    }
}

/// 把镜像物化为可按路径访问的文件（超限镜像走分片刷写前的准备步骤）。
/// 流式搬运，宿主内存不随镜像大小增长。
pub fn materialize_image<S: ImageSource + ?Sized>(
    source: &S,
    name: &str,
) -> io::Result<MaterializedImage> {
    if let Some(path) = source.get_file_path(name) {
        return Ok(MaterializedImage::Borrowed(path));
    }
    let mut tmp = tempfile::NamedTempFile::new()?;
    source.copy_to(name, tmp.as_file_mut())?;
    tmp.as_file_mut().flush()?;
    Ok(MaterializedImage::Temp(tmp))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageType {
    BootCritical,
    Normal,
    Extra,
}
#[derive(Debug, Clone)]
pub struct Image {
    pub img_name: String,
    pub part_name: String,
    pub image_type: ImageType,
    pub optional: bool,
}

pub fn get_default_images() -> Vec<Image> {
    vec![
        Image {
            img_name: "bootloader.img".to_string(),
            part_name: "bootloader".to_string(),
            image_type: ImageType::BootCritical,
            optional: true,
        },
        Image {
            img_name: "radio.img".to_string(),
            part_name: "radio".to_string(),
            image_type: ImageType::BootCritical,
            optional: true,
        },
        Image {
            img_name: "boot.img".to_string(),
            part_name: "boot".to_string(),
            image_type: ImageType::Normal,
            optional: false,
        },
        Image {
            img_name: "init_boot.img".to_string(),
            part_name: "init_boot".to_string(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "vendor_boot.img".to_string(),
            part_name: "vendor_boot".to_string(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "dtbo.img".to_string(),
            part_name: "dtbo".to_string(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "vbmeta.img".to_string(),
            part_name: "vbmeta".to_string(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "vbmeta_system.img".to_string(),
            part_name: "vbmeta_system".to_string(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "vbmeta_vendor.img".to_string(),
            part_name: "vbmeta_vendor".to_string(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "super.img".to_string(),
            part_name: "super".to_string(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "system.img".to_string(),
            part_name: "system".to_string(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "system_ext.img".to_string(),
            part_name: "system_ext".to_string(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "vendor.img".to_string(),
            part_name: "vendor".to_string(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "vendor_dlkm.img".to_string(),
            part_name: "vendor_dlkm".to_string(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "odm.img".to_string(),
            part_name: "odm".to_string(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "odm_dlkm.img".to_string(),
            part_name: "odm_dlkm".to_string(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "product.img".to_string(),
            part_name: "product".to_string(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "userdata.img".to_string(),
            part_name: "userdata".to_string(),
            image_type: ImageType::Extra,
            optional: true,
        },
        Image {
            img_name: "cache.img".to_string(),
            part_name: "cache".to_string(),
            image_type: ImageType::Extra,
            optional: true,
        },
    ]
}
/// flashall / update 的刷写选项。
/// - `wants_wipe`：是否执行 fastboot-info.txt 里 `if-wipe` 块内的任务、以及默认镜像表里的 Extra 项；
/// - `slot_override`：显式指定槽位时给所有分区名追加 `_<slot>`；不指定则按原名下发
///   （本实现不查询设备活动槽，交由 bootloader 自行解析）。
#[derive(Debug, Default)]
pub struct FlashingPlan {
    pub wants_wipe: bool,
    pub slot_override: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlashCommand {
    Flash { partition: String, filename: String },
    Erase { partition: String },
    RebootBootloader,
    RebootFastboot,
    GetVar { name: String },
    IfWipe,
    EndIf,
    UpdateSuper { partition: String },
}

pub fn parse_fastboot_info(content: &str) -> Vec<FlashCommand> {
    let mut commands = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        // AOSP fastboot-info.txt 里 `if-wipe` 是行内条件前缀（如 `if-wipe erase userdata`）：
        // 展开成 IfWipe + <内层命令> + EndIf，与旧块式（单独 if-wipe / endif 行）共用同一套
        // 消费逻辑（tasks_from_fastboot_info 的块过滤）。单独一行的 `if-wipe` 仍按块式开始处理。
        if parts[0] == "if-wipe" && parts.len() > 1 {
            if let Some(inner) = parse_fastboot_info_command(&parts[1..]) {
                commands.push(FlashCommand::IfWipe);
                commands.push(inner);
                commands.push(FlashCommand::EndIf);
            }
            continue;
        }

        if let Some(cmd) = parse_fastboot_info_command(&parts) {
            commands.push(cmd);
        }
    }

    commands
}

/// 解析 fastboot-info.txt 的单条命令（已按空白分词）。不认识的命令返回 None（跳过）。
fn parse_fastboot_info_command(parts: &[&str]) -> Option<FlashCommand> {
    match parts[0] {
        // AOSP 语法：flash [--flag…] PARTITION [FILENAME]，FILENAME 缺省为 <PARTITION>.img
        // （官方 factory 包普遍用双词形式 `flash boot`，此前要求三词会把整个任务表解析成空）。
        "flash" if parts.len() >= 2 => {
            let mut idx = 1;
            let mut slot_other = false;
            while idx < parts.len() && parts[idx].starts_with("--") {
                if parts[idx] == "--slot-other" {
                    slot_other = true;
                }
                idx += 1;
            }
            // --slot-other 语义是「刷到另一槽」（system_other 等），本实现未支持槽切换：
            // 跳过该行——按当前槽照刷会把 other 镜像错写进正在运行的槽。
            if slot_other {
                return None;
            }
            let partition = parts.get(idx)?;
            let filename = parts
                .get(idx + 1)
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("{}.img", partition));
            Some(FlashCommand::Flash {
                partition: partition.to_string(),
                filename,
            })
        }
        "erase" if parts.len() >= 2 => Some(FlashCommand::Erase {
            partition: parts[1].to_string(),
        }),
        "reboot-bootloader" => Some(FlashCommand::RebootBootloader),
        "reboot-fastboot" => Some(FlashCommand::RebootFastboot),
        // AOSP 写法是双词 `reboot fastboot` / `reboot bootloader`，与连字符别名同义。
        "reboot" if parts.len() >= 2 && parts[1] == "bootloader" => {
            Some(FlashCommand::RebootBootloader)
        }
        "reboot" if parts.len() >= 2 && parts[1] == "fastboot" => {
            Some(FlashCommand::RebootFastboot)
        }
        "getvar" if parts.len() >= 2 => Some(FlashCommand::GetVar {
            name: parts[1].to_string(),
        }),
        "if-wipe" => Some(FlashCommand::IfWipe),
        "endif" => Some(FlashCommand::EndIf),
        "update-super" if parts.len() >= 2 => Some(FlashCommand::UpdateSuper {
            partition: parts[1].to_string(),
        }),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct FlashTask {
    pub partition: String,
    pub filename: String,
    pub optional: bool,
}

pub struct FlashAllTool<S: ImageSource> {
    source: S,
    plan: FlashingPlan,
}

impl<S: ImageSource> FlashAllTool<S> {
    pub fn new(source: S, plan: FlashingPlan) -> Self {
        Self { source, plan }
    }
    pub fn source(&self) -> &S {
        &self.source
    }

    pub fn generate_tasks(&self) -> io::Result<Vec<FlashTask>> {
        if self.source.exists("fastboot-info.txt") {
            let content = self.source.read_file("fastboot-info.txt")?;
            let content = String::from_utf8_lossy(&content);
            return Ok(self.tasks_from_fastboot_info(&content));
        }
        Ok(self.tasks_from_default_images())
    }
    fn tasks_from_fastboot_info(&self, content: &str) -> Vec<FlashTask> {
        let commands = parse_fastboot_info(content);
        let mut tasks = Vec::new();
        let mut in_wipe_block = false;

        for cmd in commands {
            match cmd {
                FlashCommand::IfWipe => {
                    in_wipe_block = true;
                }
                FlashCommand::EndIf => {
                    in_wipe_block = false;
                }
                FlashCommand::Flash {
                    partition,
                    filename,
                } => {
                    if in_wipe_block && !self.plan.wants_wipe {
                        continue;
                    }
                    let partition = self.add_slot_suffix(&partition);

                    tasks.push(FlashTask {
                        partition,
                        filename,
                        optional: true,
                    });
                }
                _ => {}
            }
        }

        tasks
    }
    fn tasks_from_default_images(&self) -> Vec<FlashTask> {
        let images = get_default_images();
        let mut tasks = Vec::new();

        for image in images {
            if image.image_type == ImageType::Extra && !self.plan.wants_wipe {
                continue;
            }
            if image.optional && !self.source.exists(&image.img_name) {
                continue;
            }
            let partition = self.add_slot_suffix(&image.part_name);

            tasks.push(FlashTask {
                partition,
                filename: image.img_name,
                optional: image.optional,
            });
        }

        tasks
    }
    fn add_slot_suffix(&self, partition: &str) -> String {
        match self.plan.slot_override {
            Some(ref slot) => format!("{}_{}", partition, slot),
            None => partition.to_string(),
        }
    }
    pub fn is_sparse(&self, filename: &str) -> io::Result<bool> {
        // 只探测 4 字节魔数：走 read_prefix，绝不为判断格式把整个镜像读进内存。
        let data = self.source.read_prefix(filename, 4)?;
        if data.len() < 4 {
            return Ok(false);
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        Ok(magic == SPARSE_HEADER_MAGIC)
    }
    pub fn validate(&self) -> Result<(), FastbootError> {
        let tasks = self.generate_tasks()?;

        for task in tasks {
            if !task.optional && !self.source.exists(&task.filename) {
                return Err(FastbootError::ImageNotFound(task.filename));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use tempfile::TempDir;

    #[test]
    fn test_local_image_source() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.img");
        let mut file = File::create(&test_file).unwrap();
        file.write_all(b"test data").unwrap();

        let source = LocalImageSource::new(temp_dir.path());
        assert!(source.exists("test.img"));
        assert!(!source.exists("nonexistent.img"));
        let data = source.read_file("test.img").unwrap();
        assert_eq!(data, b"test data");
        let size = source.file_size("test.img").unwrap();
        assert_eq!(size, 9);
    }

    #[test]
    fn test_default_images() {
        let images = get_default_images();
        assert!(images.iter().any(|i| i.part_name == "boot"));
        assert!(images.iter().any(|i| i.part_name == "system"));
        assert!(images.iter().any(|i| i.part_name == "vendor"));
        let boot = images.iter().find(|i| i.part_name == "boot").unwrap();
        assert!(!boot.optional);
    }

    #[test]
    fn test_zip_image_source() {
        let mut zip_data = Vec::new();
        {
            let cursor = Cursor::new(&mut zip_data);
            let mut zip = zip::ZipWriter::new(cursor);

            let options = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            zip.start_file("boot.img", options).unwrap();
            zip.write_all(b"boot image data").unwrap();

            zip.start_file("images/system.img", options).unwrap();
            zip.write_all(b"system image data").unwrap();

            zip.finish().unwrap();
        }

        let cursor = Cursor::new(zip_data);
        let source = ZipImageSource::new(cursor).unwrap();
        assert!(source.exists("boot.img"));
        assert!(source.exists("system.img"));
        assert!(!source.exists("nonexistent.img"));
        let data = source.read_file("boot.img").unwrap();
        assert_eq!(data, b"boot image data");
        let data = source.read_file("system.img").unwrap();
        assert_eq!(data, b"system image data");
    }

    #[test]
    fn test_parse_fastboot_info_basic() {
        let content = r#"
# 这是注释
flash bootloader bootloader.img
flash boot boot.img
erase userdata
reboot-bootloader
"#;

        let commands = parse_fastboot_info(content);
        assert_eq!(commands.len(), 4);

        assert_eq!(
            commands[0],
            FlashCommand::Flash {
                partition: "bootloader".to_string(),
                filename: "bootloader.img".to_string(),
            }
        );
        assert_eq!(
            commands[1],
            FlashCommand::Flash {
                partition: "boot".to_string(),
                filename: "boot.img".to_string(),
            }
        );
        assert_eq!(
            commands[2],
            FlashCommand::Erase {
                partition: "userdata".to_string(),
            }
        );
        assert_eq!(commands[3], FlashCommand::RebootBootloader);
    }

    #[test]
    fn test_parse_fastboot_info_with_wipe() {
        let content = r#"
flash boot boot.img
if-wipe
erase userdata
flash userdata userdata.img
endif
flash system system.img
"#;

        let commands = parse_fastboot_info(content);
        assert_eq!(commands.len(), 6);

        assert_eq!(commands[1], FlashCommand::IfWipe);
        assert_eq!(commands[4], FlashCommand::EndIf);
    }

    /// AOSP 官方 factory 包的 fastboot-info.txt 语法：`flash <part>`（文件名缺省 <part>.img）、
    /// 行内条件前缀 `if-wipe erase userdata`、双词 `reboot fastboot`。此前要求 flash 必须三词，
    /// 官方包会被解析成空任务表（update 直接报「没有可刷写的镜像」）。
    #[test]
    fn test_parse_fastboot_info_aosp_official_format() {
        let content = r#"
version 1
flash boot
flash init_boot
flash --apply-vbmeta vbmeta
reboot fastboot
update-super
flash system
if-wipe erase userdata
if-wipe erase metadata
"#;

        let commands = parse_fastboot_info(content);
        assert_eq!(
            commands,
            vec![
                FlashCommand::Flash {
                    partition: "boot".to_string(),
                    filename: "boot.img".to_string(),
                },
                FlashCommand::Flash {
                    partition: "init_boot".to_string(),
                    filename: "init_boot.img".to_string(),
                },
                FlashCommand::Flash {
                    partition: "vbmeta".to_string(),
                    filename: "vbmeta.img".to_string(),
                },
                FlashCommand::RebootFastboot,
                FlashCommand::Flash {
                    partition: "system".to_string(),
                    filename: "system.img".to_string(),
                },
                FlashCommand::IfWipe,
                FlashCommand::Erase {
                    partition: "userdata".to_string(),
                },
                FlashCommand::EndIf,
                FlashCommand::IfWipe,
                FlashCommand::Erase {
                    partition: "metadata".to_string(),
                },
                FlashCommand::EndIf,
            ]
        );
    }

    /// `--slot-other` 表示刷到另一槽（system_other 等）；本实现不支持槽切换，必须整行跳过——
    /// 按当前槽照刷会把 other 镜像错写进正在运行的槽。
    #[test]
    fn test_parse_fastboot_info_skips_slot_other() {
        let commands =
            parse_fastboot_info("flash --slot-other system system_other.img\nflash boot\n");
        assert_eq!(
            commands,
            vec![FlashCommand::Flash {
                partition: "boot".to_string(),
                filename: "boot.img".to_string(),
            }]
        );
    }

    /// 行内 if-wipe 展开后 wants_wipe 闸门必须生效：不 wipe 时跳过、wipe 时收进任务表。
    #[test]
    fn test_inline_if_wipe_respects_wants_wipe() {
        let temp_dir = TempDir::new().unwrap();
        let mut info_file = File::create(temp_dir.path().join("fastboot-info.txt")).unwrap();
        info_file
            .write_all(b"flash boot\nif-wipe flash userdata userdata.img\n")
            .unwrap();

        let source = LocalImageSource::new(temp_dir.path());
        let tool = FlashAllTool::new(source, FlashingPlan::default());
        let tasks = tool.generate_tasks().unwrap();
        assert_eq!(tasks.len(), 1, "不 wipe 时 if-wipe 行必须被跳过");
        assert_eq!(tasks[0].partition, "boot");
        assert_eq!(tasks[0].filename, "boot.img");

        let source = LocalImageSource::new(temp_dir.path());
        let plan = FlashingPlan {
            wants_wipe: true,
            ..Default::default()
        };
        let tool = FlashAllTool::new(source, plan);
        let tasks = tool.generate_tasks().unwrap();
        assert_eq!(tasks.len(), 2, "wipe 时 if-wipe 行必须收进任务表");
        assert_eq!(tasks[1].partition, "userdata");
    }

    #[test]
    fn test_flash_all_tool_generate_tasks() {
        let temp_dir = TempDir::new().unwrap();
        File::create(temp_dir.path().join("boot.img")).unwrap();
        File::create(temp_dir.path().join("system.img")).unwrap();

        let source = LocalImageSource::new(temp_dir.path());
        let plan = FlashingPlan::default();
        let tool = FlashAllTool::new(source, plan);

        let tasks = tool.generate_tasks().unwrap();

        assert!(tasks.iter().any(|t| t.filename == "boot.img"));
    }

    #[test]
    fn test_flash_all_tool_with_fastboot_info() {
        let temp_dir = TempDir::new().unwrap();
        let mut info_file = File::create(temp_dir.path().join("fastboot-info.txt")).unwrap();
        info_file
            .write_all(b"flash boot boot.img\nflash system system.img\n")
            .unwrap();
        File::create(temp_dir.path().join("boot.img")).unwrap();
        File::create(temp_dir.path().join("system.img")).unwrap();

        let source = LocalImageSource::new(temp_dir.path());
        let plan = FlashingPlan::default();
        let tool = FlashAllTool::new(source, plan);

        let tasks = tool.generate_tasks().unwrap();
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0].partition, "boot");
        assert_eq!(tasks[1].partition, "system");
    }

    #[test]
    fn test_flash_all_tool_slot_suffix() {
        let temp_dir = TempDir::new().unwrap();
        File::create(temp_dir.path().join("boot.img")).unwrap();

        let source = LocalImageSource::new(temp_dir.path());
        let plan = FlashingPlan {
            slot_override: Some("a".to_string()),
            ..Default::default()
        };
        let tool = FlashAllTool::new(source, plan);

        let tasks = tool.generate_tasks().unwrap();
        let boot_task = tasks.iter().find(|t| t.filename == "boot.img").unwrap();
        assert_eq!(boot_task.partition, "boot_a");
    }

    #[test]
    fn test_flash_all_tool_validate() {
        let temp_dir = TempDir::new().unwrap();
        let source = LocalImageSource::new(temp_dir.path());
        let plan = FlashingPlan::default();
        let tool = FlashAllTool::new(source, plan);
        let result = tool.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_read_prefix_local_and_zip() {
        // Local：真前缀读；请求长度超过文件时按实际长度截断，不报错
        let temp_dir = TempDir::new().unwrap();
        let mut file = File::create(temp_dir.path().join("boot.img")).unwrap();
        file.write_all(b"0123456789").unwrap();
        drop(file);
        let source = LocalImageSource::new(temp_dir.path());
        assert_eq!(source.read_prefix("boot.img", 4).unwrap(), b"0123");
        assert_eq!(source.read_prefix("boot.img", 64).unwrap(), b"0123456789");

        // Zip：流式解压前缀，同样语义
        let mut zip_data = Vec::new();
        {
            let cursor = Cursor::new(&mut zip_data);
            let mut zip = zip::ZipWriter::new(cursor);
            let options = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("boot.img", options).unwrap();
            zip.write_all(b"abcdefgh").unwrap();
            zip.finish().unwrap();
        }
        let source = ZipImageSource::new(Cursor::new(zip_data)).unwrap();
        assert_eq!(source.read_prefix("boot.img", 3).unwrap(), b"abc");
        assert_eq!(source.read_prefix("boot.img", 100).unwrap(), b"abcdefgh");
        assert!(source.read_prefix("missing.img", 4).is_err());
    }

    #[test]
    fn test_is_sparse_by_magic_prefix() {
        let temp_dir = TempDir::new().unwrap();
        let mut sparse = File::create(temp_dir.path().join("sparse.img")).unwrap();
        sparse
            .write_all(&SPARSE_HEADER_MAGIC.to_le_bytes())
            .unwrap();
        sparse.write_all(&[0u8; 64]).unwrap();
        drop(sparse);
        let mut raw = File::create(temp_dir.path().join("raw.img")).unwrap();
        raw.write_all(b"ANDROID!not sparse").unwrap();
        drop(raw);
        // 不足 4 字节的文件不可能是 sparse，也不允许报错
        File::create(temp_dir.path().join("tiny.img"))
            .unwrap()
            .write_all(b"ab")
            .unwrap();

        let source = LocalImageSource::new(temp_dir.path());
        let tool = FlashAllTool::new(source, FlashingPlan::default());
        assert!(tool.is_sparse("sparse.img").unwrap());
        assert!(!tool.is_sparse("raw.img").unwrap());
        assert!(!tool.is_sparse("tiny.img").unwrap());
    }

    /// 28B 头 + 单个 RAW chunk 的最小合法 sparse 镜像。
    fn build_sparse_image(blocks: u32) -> Vec<u8> {
        let block_size = 4096u32;
        let mut img = Vec::new();
        img.extend_from_slice(&SPARSE_HEADER_MAGIC.to_le_bytes());
        img.extend_from_slice(&1u16.to_le_bytes());
        img.extend_from_slice(&0u16.to_le_bytes());
        img.extend_from_slice(&28u16.to_le_bytes());
        img.extend_from_slice(&12u16.to_le_bytes());
        img.extend_from_slice(&block_size.to_le_bytes());
        img.extend_from_slice(&blocks.to_le_bytes());
        img.extend_from_slice(&1u32.to_le_bytes());
        img.extend_from_slice(&0u32.to_le_bytes());
        img.extend_from_slice(&0xCAC1u16.to_le_bytes());
        img.extend_from_slice(&0u16.to_le_bytes());
        img.extend_from_slice(&blocks.to_le_bytes());
        img.extend_from_slice(&(12 + blocks * block_size).to_le_bytes());
        img.extend(std::iter::repeat_n(0xA5u8, (blocks * block_size) as usize));
        img
    }

    #[test]
    fn zip_over_limit_image_materializes_and_resparses() {
        // 「超限 zip 镜像 → 流式物化 → 分片」逻辑层验证（不触设备）：
        // 32KB sparse 镜像 + 16KB max-download-size → 物化为临时文件并切成 ≥2 片。
        let img = build_sparse_image(8);
        let mut zip_data = Vec::new();
        {
            let cursor = Cursor::new(&mut zip_data);
            let mut zip = zip::ZipWriter::new(cursor);
            let options = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("super.img", options).unwrap();
            zip.write_all(&img).unwrap();
            zip.finish().unwrap();
        }
        let source = ZipImageSource::new(Cursor::new(zip_data)).unwrap();

        let max_download = 16 * 1024u64;
        let file_size = source.file_size("super.img").unwrap();
        assert!(file_size > max_download, "测试前提：镜像超限");

        let tool = FlashAllTool::new(source, FlashingPlan::default());
        assert!(tool.is_sparse("super.img").unwrap());

        let materialized = materialize_image(tool.source(), "super.img").unwrap();
        assert!(
            matches!(materialized, MaterializedImage::Temp(_)),
            "zip 源必须物化为临时文件"
        );
        assert_eq!(
            std::fs::read(materialized.path()).unwrap(),
            img,
            "物化内容必须逐字节一致"
        );

        let resparse =
            crate::sparse::StreamingResparse::new(materialized.path(), max_download).unwrap();
        assert!(
            resparse.total_fragments() >= 2,
            "超限镜像必须切成多片，实得 {}",
            resparse.total_fragments()
        );
    }

    #[test]
    fn local_source_materializes_as_borrowed_path() {
        let temp_dir = TempDir::new().unwrap();
        let mut f = File::create(temp_dir.path().join("boot.img")).unwrap();
        f.write_all(b"raw image").unwrap();
        drop(f);

        let source = LocalImageSource::new(temp_dir.path());
        let m = materialize_image(&source, "boot.img").unwrap();
        assert!(
            matches!(m, MaterializedImage::Borrowed(_)),
            "本地源应零拷贝借用原路径"
        );
        assert_eq!(m.path(), temp_dir.path().join("boot.img"));
    }
}
