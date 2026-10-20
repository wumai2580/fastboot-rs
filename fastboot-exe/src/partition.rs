//! CLI `fastboot flashall` 用的分区辅助：`getvar all` 解析出的槽位/分区表、标准镜像清单，
//! 以及 `partition-size` 的数值口径。
use crate::error::FastbootError;
use std::collections::{HashMap, HashSet};

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

/// 解析 `getvar partition-size` 的回包值。对齐 AOSP `fb_fix_numeric_var`（fastboot.cpp）：
/// 该字段**无论有无 0x 前缀一律按十六进制**——不少 bootloader（AOSP 注释点名的 hammerhead、
/// 常见的 MTK LK）回裸十六进制（如 "10000000" = 256 MiB），按十进制读会把分区大小缩小几个
/// 数量级：分区表显示失真，刷写容量闸门还会误拦合法镜像。
pub fn parse_partition_size(s: &str) -> Result<u64, FastbootError> {
    let s = s.trim();
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(hex, 16)
        .map_err(|_| FastbootError::Protocol(format!("无效的分区大小: {}", s)))
}
pub fn get_standard_images() -> Vec<Image> {
    vec![
        Image {
            img_name: "bootloader.img".into(),
            part_name: "bootloader".into(),
            image_type: ImageType::BootCritical,
            optional: true,
        },
        Image {
            img_name: "radio.img".into(),
            part_name: "radio".into(),
            image_type: ImageType::BootCritical,
            optional: true,
        },
        Image {
            img_name: "boot.img".into(),
            part_name: "boot".into(),
            image_type: ImageType::Normal,
            optional: false,
        },
        Image {
            img_name: "init_boot.img".into(),
            part_name: "init_boot".into(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "vendor_boot.img".into(),
            part_name: "vendor_boot".into(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "recovery.img".into(),
            part_name: "recovery".into(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "system.img".into(),
            part_name: "system".into(),
            image_type: ImageType::Normal,
            optional: false,
        },
        Image {
            img_name: "system_ext.img".into(),
            part_name: "system_ext".into(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "vendor.img".into(),
            part_name: "vendor".into(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "vendor_dlkm.img".into(),
            part_name: "vendor_dlkm".into(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "odm.img".into(),
            part_name: "odm".into(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "odm_dlkm.img".into(),
            part_name: "odm_dlkm".into(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "product.img".into(),
            part_name: "product".into(),
            image_type: ImageType::Normal,
            optional: true,
        },
        Image {
            img_name: "vbmeta.img".into(),
            part_name: "vbmeta".into(),
            image_type: ImageType::Extra,
            optional: true,
        },
        Image {
            img_name: "vbmeta_system.img".into(),
            part_name: "vbmeta_system".into(),
            image_type: ImageType::Extra,
            optional: true,
        },
        Image {
            img_name: "vbmeta_vendor.img".into(),
            part_name: "vbmeta_vendor".into(),
            image_type: ImageType::Extra,
            optional: true,
        },
        Image {
            img_name: "dtbo.img".into(),
            part_name: "dtbo".into(),
            image_type: ImageType::Extra,
            optional: true,
        },
    ]
}

/// 从 `getvar all` 的键值表得到的槽位信息与设备上存在的分区名（带槽后缀的原名）。
#[derive(Debug, Clone, Default)]
pub struct PartitionManager {
    pub has_slot: bool,
    pub current_slot: Option<String>,
    partitions: HashSet<String>,
}
impl PartitionManager {
    pub fn from_device_vars(vars: &HashMap<String, String>) -> Self {
        let mut mgr = Self::default();
        if let Some(slot_count) = vars.get("slot-count") {
            mgr.has_slot = slot_count.parse::<u32>().unwrap_or(0) > 1;
        }
        if let Some(slot) = vars.get("current-slot") {
            mgr.current_slot = Some(slot.clone());
        }
        // 设备通过 `partition-size:<名>` / `is-logical:<名>` 两类变量暴露分区；两者都算「存在」。
        for key in vars.keys() {
            if let Some(part_name) = key
                .strip_prefix("partition-size:")
                .or_else(|| key.strip_prefix("is-logical:"))
            {
                mgr.partitions.insert(part_name.to_string());
            }
        }
        mgr
    }
    /// 把镜像表里的基名解析成设备上要刷的分区名：已带 `_a`/`_b` 的原样返回；A/B 设备上若
    /// 「基名_当前槽」确实存在就用它，否则用基名（非 A/B 分区如 userdata）。
    pub fn get_partition_name(&self, base_name: &str) -> String {
        if base_name.ends_with("_a") || base_name.ends_with("_b") {
            return base_name.to_string();
        }
        if self.has_slot {
            if let Some(ref slot) = self.current_slot {
                let with_slot = format!("{}_{}", base_name, slot);
                if self.partitions.contains(&with_slot) {
                    return with_slot;
                }
            }
        }
        base_name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_partition_size() {
        assert_eq!(parse_partition_size("0x400").unwrap(), 1024);
        assert_eq!(parse_partition_size("0X400").unwrap(), 1024);
        // AOSP fb_fix_numeric_var 语义：无 0x 前缀同样按十六进制（MTK 裸 hex 修复的回归护栏）
        assert_eq!(parse_partition_size("400").unwrap(), 1024);
        assert_eq!(parse_partition_size("10000000").unwrap(), 0x1000_0000);
        assert_eq!(parse_partition_size("  0x400  ").unwrap(), 1024);
        assert!(parse_partition_size("invalid").is_err());
        assert!(parse_partition_size("0x").is_err());
        assert!(parse_partition_size("").is_err());
    }
    #[test]
    fn test_standard_images() {
        let images = get_standard_images();
        assert!(images.iter().any(|i| i.part_name == "boot"));
        assert!(images.iter().any(|i| i.part_name == "system"));
        let boot = images.iter().find(|i| i.part_name == "boot").unwrap();
        assert!(!boot.optional);
        let system = images.iter().find(|i| i.part_name == "system").unwrap();
        assert!(!system.optional);
    }
    #[test]
    fn test_image_type_ordering() {
        let images = get_standard_images();
        let bootloader = images.iter().find(|i| i.part_name == "bootloader").unwrap();
        assert_eq!(bootloader.image_type, ImageType::BootCritical);
        let boot = images.iter().find(|i| i.part_name == "boot").unwrap();
        assert_eq!(boot.image_type, ImageType::Normal);
        let vbmeta = images.iter().find(|i| i.part_name == "vbmeta").unwrap();
        assert_eq!(vbmeta.image_type, ImageType::Extra);
    }
    #[test]
    fn test_partition_manager_from_vars() {
        let mut vars = HashMap::new();
        vars.insert("slot-count".to_string(), "2".to_string());
        vars.insert("current-slot".to_string(), "a".to_string());
        vars.insert("partition-size:boot_a".to_string(), "0x4000000".to_string());
        vars.insert("is-logical:system_a".to_string(), "yes".to_string());
        let mgr = PartitionManager::from_device_vars(&vars);
        assert!(mgr.has_slot);
        assert_eq!(mgr.current_slot, Some("a".to_string()));
        // is-logical 变量同样表明分区存在
        assert_eq!(mgr.get_partition_name("system"), "system_a");
        let single = PartitionManager::from_device_vars(&HashMap::new());
        assert!(!single.has_slot);
        assert!(single.current_slot.is_none());
    }
    #[test]
    fn test_partition_manager_get_partition_name() {
        let mut vars = HashMap::new();
        vars.insert("slot-count".to_string(), "2".to_string());
        vars.insert("current-slot".to_string(), "a".to_string());
        vars.insert("partition-size:boot_a".to_string(), "0x4000000".to_string());
        vars.insert("partition-size:boot_b".to_string(), "0x4000000".to_string());
        vars.insert(
            "partition-size:userdata".to_string(),
            "0x100000000".to_string(),
        );
        let mgr = PartitionManager::from_device_vars(&vars);
        assert_eq!(mgr.get_partition_name("boot"), "boot_a");
        assert_eq!(mgr.get_partition_name("userdata"), "userdata");
        assert_eq!(mgr.get_partition_name("boot_b"), "boot_b");
    }
}
#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    proptest! {
        #[test]
        fn prop_partition_size_implicit_hex(size in 1u64..0xFFFFFFFF) {
            // AOSP fb_fix_numeric_var 语义：有无 0x 前缀都按十六进制解析，三种写法必须同值
            let bare = format!("{:x}", size);
            let hex = format!("0x{:x}", size);
            let hex_upper = format!("0X{:X}", size);
            let parsed_bare = parse_partition_size(&bare).unwrap();
            let parsed_hex = parse_partition_size(&hex).unwrap();
            let parsed_hex_upper = parse_partition_size(&hex_upper).unwrap();
            prop_assert_eq!(parsed_bare, size);
            prop_assert_eq!(parsed_hex, size);
            prop_assert_eq!(parsed_hex_upper, size);
        }
    }
}
