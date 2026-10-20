use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::SparseError;

pub const SPARSE_HEADER_MAGIC: u32 = 0xED26FF3A;
pub const SPARSE_MAJOR_VERSION: u16 = 1;
pub const SPARSE_HEADER_SIZE: usize = 28;
pub const CHUNK_HEADER_SIZE: usize = 12;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkType {
    Raw = 0xCAC1,
    Fill = 0xCAC2,
    DontCare = 0xCAC3,
    Crc32 = 0xCAC4,
}

impl ChunkType {
    pub fn from_u16(value: u16) -> Result<Self, SparseError> {
        match value {
            0xCAC1 => Ok(ChunkType::Raw),
            0xCAC2 => Ok(ChunkType::Fill),
            0xCAC3 => Ok(ChunkType::DontCare),
            0xCAC4 => Ok(ChunkType::Crc32),
            _ => Err(SparseError::InvalidChunkType(value)),
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub struct SparseHeader {
    pub magic: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub file_hdr_sz: u16,
    pub chunk_hdr_sz: u16,
    pub blk_sz: u32,
    pub total_blks: u32,
    pub total_chunks: u32,
}

impl SparseHeader {
    pub fn from_bytes(data: &[u8]) -> Result<Self, SparseError> {
        if data.len() < SPARSE_HEADER_SIZE {
            return Err(SparseError::InvalidHeader("数据太短".into()));
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let major_version = u16::from_le_bytes([data[4], data[5]]);
        let minor_version = u16::from_le_bytes([data[6], data[7]]);
        let file_hdr_sz = u16::from_le_bytes([data[8], data[9]]);
        let chunk_hdr_sz = u16::from_le_bytes([data[10], data[11]]);
        let blk_sz = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let total_blks = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let total_chunks = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        // [24..28] 是整包 image_checksum：分片后必然失效，本实现不校验，下发的分片里恒写 0。

        Ok(Self {
            magic,
            major_version,
            minor_version,
            file_hdr_sz,
            chunk_hdr_sz,
            blk_sz,
            total_blks,
            total_chunks,
        })
    }
    pub fn validate(&self) -> Result<(), SparseError> {
        if self.magic != SPARSE_HEADER_MAGIC {
            return Err(SparseError::InvalidMagic(self.magic));
        }
        if self.major_version != SPARSE_MAJOR_VERSION {
            return Err(SparseError::UnsupportedVersion(
                self.major_version,
                self.minor_version,
            ));
        }
        // AOSP libsparse（sparse_read.cpp）要求两个头长度不小于结构体本身：允许更大
        // （多出的字节按未知扩展跳过），小于则后续所有偏移计算都是错的，必须在头部就拒绝。
        if (self.file_hdr_sz as usize) < SPARSE_HEADER_SIZE {
            return Err(SparseError::InvalidHeader(format!(
                "file_hdr_sz {} 小于 sparse 头长度 {}",
                self.file_hdr_sz, SPARSE_HEADER_SIZE
            )));
        }
        if (self.chunk_hdr_sz as usize) < CHUNK_HEADER_SIZE {
            return Err(SparseError::InvalidHeader(format!(
                "chunk_hdr_sz {} 小于 chunk 头长度 {}",
                self.chunk_hdr_sz, CHUNK_HEADER_SIZE
            )));
        }
        if self.blk_sz == 0 || !self.blk_sz.is_multiple_of(4) {
            // AOSP 同样要求 blk_sz 为 4 的倍数（FILL 值是 4 字节模式，块必须能整除）。
            return Err(SparseError::InvalidHeader(format!(
                "块大小 {} 非法（必须为 4 的正整数倍）",
                self.blk_sz
            )));
        }
        Ok(())
    }
    pub fn expanded_size(&self) -> u64 {
        self.blk_sz as u64 * self.total_blks as u64
    }
}
#[derive(Debug, Clone, Copy)]
pub struct ChunkHeader {
    pub chunk_type: u16,
    pub chunk_sz: u32,
    pub total_sz: u32,
}

impl ChunkHeader {
    pub fn from_bytes(data: &[u8]) -> Result<Self, SparseError> {
        if data.len() < CHUNK_HEADER_SIZE {
            return Err(SparseError::InvalidHeader("Chunk 头数据太短".into()));
        }

        let chunk_type = u16::from_le_bytes([data[0], data[1]]);
        // [2..4] 是保留字段（AOSP reserved1），不参与任何判定。
        let chunk_sz = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let total_sz = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

        Ok(Self {
            chunk_type,
            chunk_sz,
            total_sz,
        })
    }
    pub fn get_type(&self) -> Result<ChunkType, SparseError> {
        ChunkType::from_u16(self.chunk_type)
    }
}

/// 按镜像声明的 `chunk_hdr_sz` 算出第 `index` 个 chunk 的数据区字节数。
/// total_sz 连头都装不下只可能是镜像损坏，必须报错而不是 saturating 归零——
/// 归零会让扫描游标原地踏步或把头字节当数据发给设备。
fn chunk_data_size(
    chunk_header: &ChunkHeader,
    chunk_hdr_sz: u16,
    index: u32,
) -> Result<u32, SparseError> {
    chunk_header
        .total_sz
        .checked_sub(chunk_hdr_sz as u32)
        .ok_or_else(|| {
            SparseError::InvalidHeader(format!(
                "Chunk {} 的 total_sz {} 小于 chunk 头长度 {}",
                index, chunk_header.total_sz, chunk_hdr_sz
            ))
        })
}

/// AOSP libsparse `process_chunk` 的逐 chunk 几何校验：total_sz 与 chunk 类型声明的
/// 数据长度必须严格一致（Raw = 块数×块大小，Fill/Crc32 = 4，DontCare = 0）。
/// 这不只是防御：`plan_fragments` 以「Raw 数据恰好块对齐」为前提做切分点运算，
/// 未对齐的 Raw 会让块游标计数错位、分片起始块整体偏移，刷完直接起不来。
fn validate_chunk_geometry(
    chunk_type: ChunkType,
    output_blocks: u32,
    data_size: u32,
    blk_sz: u32,
    index: u32,
) -> Result<(), SparseError> {
    let ok = match chunk_type {
        ChunkType::Raw => data_size as u64 == output_blocks as u64 * blk_sz as u64,
        ChunkType::Fill => data_size == 4,
        ChunkType::DontCare => data_size == 0,
        // CRC32 不产出块（libsparse 恒写 0）；非 0 会让块游标/守恒计数各处不一致。
        ChunkType::Crc32 => data_size == 4 && output_blocks == 0,
    };
    if ok {
        Ok(())
    } else {
        Err(SparseError::InvalidHeader(format!(
            "Chunk {} ({:?}) 声明 {} 块却带 {} 字节数据（blk_sz={}），total_sz 与类型不符",
            index, chunk_type, output_blocks, data_size, blk_sz
        )))
    }
}

/// AOSP libsparse `sparse_file_read_sparse` 收尾校验：所有 chunk 的输出块数之和必须
/// 等于头部声明的 total_blks。守恒被破坏时 resparse 的尾部 DONT_CARE 补位、每片
/// total_blks 声明都会跟着错，设备端逐片校验必然失败。
fn validate_block_conservation(counted: u64, declared: u32) -> Result<(), SparseError> {
    if counted == declared as u64 {
        Ok(())
    } else {
        Err(SparseError::InvalidHeader(format!(
            "总块数不守恒：头部声明 {} 块，chunk 表累计 {} 块",
            declared, counted
        )))
    }
}

#[derive(Debug, Clone)]
pub struct ChunkMeta {
    pub chunk_type: ChunkType,
    pub output_blocks: u32,
    pub file_offset: u64,
    pub data_size: u32,
}

pub struct StreamingResparse {
    file_path: std::path::PathBuf,
    header: SparseHeader,
    chunk_metas: Vec<ChunkMeta>,
    current_fragment: usize,
    total_fragments: usize,
    fragment_ranges: Vec<FragmentRange>,
}
#[derive(Debug, Clone)]
pub struct FragmentRange {
    pub start_chunk: usize,
    pub end_chunk: usize,
    pub start_block: u32,
    pub end_block: u32,
    pub first_chunk_offset: usize,
    pub last_chunk_size: usize,
}

impl StreamingResparse {
    pub fn new(path: &std::path::Path, max_fragment_size: u64) -> Result<Self, SparseError> {
        let mut file = File::open(path).map_err(SparseError::Io)?;
        let mut header_buf = [0u8; SPARSE_HEADER_SIZE];
        file.read_exact(&mut header_buf).map_err(SparseError::Io)?;

        let header = SparseHeader::from_bytes(&header_buf)?;
        header.validate()?;
        let mut chunk_metas = Vec::with_capacity(header.total_chunks as usize);
        let mut offset = header.file_hdr_sz as u64;
        // u64 累计：损坏镜像的 chunk_sz 累加可能越过 u32，u32 累计在 debug 下 panic、
        // release 下静默回绕成「看似守恒」的假象。
        let mut current_block = 0u64;

        // 逐 chunk seek+read 会对几十万 chunk 的 super 镜像发同量级系统调用（开刷前白等数秒）；
        // 改带缓冲顺序读 + `seek_relative` 跳过数据区，短跳距在缓冲区内零系统调用。
        let mut reader = BufReader::with_capacity(1 << 20, file);
        reader
            .seek(SeekFrom::Start(offset))
            .map_err(SparseError::Io)?;

        for i in 0..header.total_chunks {
            let mut chunk_buf = [0u8; CHUNK_HEADER_SIZE];
            reader.read_exact(&mut chunk_buf).map_err(SparseError::Io)?;

            let chunk_header = ChunkHeader::from_bytes(&chunk_buf)?;
            let chunk_type = chunk_header.get_type()?;
            // total_sz 装不下头 / 与类型声明的数据长度不符，都在扫描期报错（AOSP
            // process_chunk 同判据）：损坏镜像必须拦在下发之前，而不是刷完起不来。
            let data_size = chunk_data_size(&chunk_header, header.chunk_hdr_sz, i)?;
            validate_chunk_geometry(
                chunk_type,
                chunk_header.chunk_sz,
                data_size,
                header.blk_sz,
                i,
            )?;

            // CRC32 是整包校验值，分片后抄进每片必然不成立，严格校验的 bootloader 会拒收；
            // 官方 libsparse resparse 同样丢弃它。其 chunk_sz 为 0，丢掉不影响块计数。
            if chunk_type != ChunkType::Crc32 {
                if current_block > u32::MAX as u64 {
                    return Err(SparseError::InvalidHeader(format!(
                        "Chunk {} 起始块超出 u32 范围（累计 {} 块）",
                        i, current_block
                    )));
                }
                chunk_metas.push(ChunkMeta {
                    chunk_type,
                    output_blocks: chunk_header.chunk_sz,
                    // 数据区按头部声明的 chunk_hdr_sz 之后起算（多出的字节是未知扩展）。
                    file_offset: offset + header.chunk_hdr_sz as u64,
                    data_size,
                });
            }

            current_block += chunk_header.chunk_sz as u64;
            let next_offset = offset + chunk_header.total_sz as u64;
            let skip = next_offset - (offset + CHUNK_HEADER_SIZE as u64);
            if skip > 0 {
                reader.seek_relative(skip as i64).map_err(SparseError::Io)?;
            }
            offset = next_offset;
        }
        // 块数守恒：chunk 表铺出的总块数必须等于头部声明，否则每片的尾部 DONT_CARE
        // 补位与 total_blks 声明都会错位（AOSP sparse_file_read_sparse 同判据）。
        validate_block_conservation(current_block, header.total_blks)?;
        // 数据区截断：扫描用 seek 跳过数据区，越过 EOF 不会报错，只能拿 chunk 表铺到的末尾
        // 与文件长度比。不在这里拦，截断镜像会刷到一半才在 read_exact 上失败，分区已半写。
        let file_len = reader.get_ref().metadata().map_err(SparseError::Io)?.len();
        if offset > file_len {
            return Err(SparseError::InvalidHeader(format!(
                "镜像被截断：chunk 表铺到 {} 字节，文件只有 {} 字节",
                offset, file_len
            )));
        }
        let fragment_ranges = plan_fragments(&chunk_metas, header.blk_sz, max_fragment_size);

        let total_fragments = fragment_ranges.len();

        Ok(Self {
            file_path: path.to_path_buf(),
            header,
            chunk_metas,
            current_fragment: 0,
            total_fragments,
            fragment_ranges,
        })
    }
}

/// 把 chunk 表切成不超过 `max_size` 的下发分片——crate 唯一的切分依据，流式刷写与整包更新共用。
/// 预算口径必须对齐厂商 `flash_gen_crc_list.py`（设备逐片 CRC 校验基准，差一点每片边界就对不上）：
/// 可用预算 = max_size − 整包头 − 首尾 DONT_CARE 头 − 4 字节余量；Fill/DontCare 按线上字节（4/0）
/// 计入而非展开块数；chunk 装不下时按块对齐劈开填满当前片，已装到 7/8 以上则整块留给下一片。
pub fn plan_fragments(chunk_metas: &[ChunkMeta], blk_sz: u32, max_size: u64) -> Vec<FragmentRange> {
    /// 正在累积的分片；`take()` 交出成品并复位。
    #[derive(Default)]
    struct Accum {
        started: bool,
        start_chunk: usize,
        end_chunk: usize,
        start_block: u32,
        end_block: u32,
        first_chunk_offset: usize,
        last_chunk_size: usize,
    }

    impl Accum {
        /// 放入第 `idx` 个 chunk 的一段（自 `offset` 起 `bytes` 字节、占 `blocks` 块），
        /// 返回推进后的块游标。
        fn push(
            &mut self,
            idx: usize,
            offset: usize,
            bytes: usize,
            blocks: u32,
            block_cursor: u32,
        ) -> u32 {
            if !self.started {
                self.started = true;
                self.start_chunk = idx;
                self.first_chunk_offset = offset;
                self.start_block = block_cursor;
            }
            self.end_chunk = idx + 1;
            self.end_block = block_cursor + blocks;
            self.last_chunk_size = bytes;
            self.end_block
        }

        fn take(&mut self) -> Option<FragmentRange> {
            if !self.started {
                return None;
            }
            let range = FragmentRange {
                start_chunk: self.start_chunk,
                end_chunk: self.end_chunk,
                start_block: self.start_block,
                end_block: self.end_block,
                first_chunk_offset: self.first_chunk_offset,
                last_chunk_size: self.last_chunk_size,
            };
            *self = Self::default();
            Some(range)
        }
    }

    let block_size = blk_sz as usize;
    let base_overhead = SPARSE_HEADER_SIZE as u64 + 2 * CHUNK_HEADER_SIZE as u64 + 4;
    // 设备回报的 max-download-size 异常小时 saturating_sub 会归零，切分步长随之为 0
    // → 死循环。兜底成一个块：宁可分片多，也不能转不动。
    let split_max_len = max_size
        .saturating_sub(base_overhead)
        .max(block_size as u64);

    let mut ranges = Vec::new();
    let mut part = Accum::default();
    // 官方脚本里的 backed_sz：当前片按其口径累计的字节数，起点是整包头。
    let mut backed_sz = SPARSE_HEADER_SIZE as u64;
    let mut block_cursor = 0u32;
    let mut idx = 0usize;
    let mut consumed = 0usize;

    while idx < chunk_metas.len() {
        let meta = &chunk_metas[idx];
        let (data_sz, blocks_left) = match meta.chunk_type {
            ChunkType::Raw => {
                let left = meta.data_size as usize - consumed;
                (left, (left / block_size) as u32)
            }
            ChunkType::Fill | ChunkType::Crc32 => (4usize, meta.output_blocks),
            ChunkType::DontCare => (0usize, meta.output_blocks),
        };
        let total_sz = CHUNK_HEADER_SIZE as u64 + data_sz as u64;
        let backed_real = backed_sz.saturating_sub(CHUNK_HEADER_SIZE as u64 + 4);
        // 只有 Raw 值得劈：Fill/DontCare 线上就 4/0 字节，切开毫无意义。
        let splittable = meta.chunk_type == ChunkType::Raw && data_sz > block_size;

        if backed_real + data_sz as u64 <= split_max_len {
            backed_sz += total_sz;
            block_cursor = part.push(idx, consumed, data_sz, blocks_left, block_cursor);
            idx += 1;
            consumed = 0;
        } else if !splittable || backed_real >= split_max_len / 8 * 7 {
            if !splittable || total_sz <= split_max_len {
                // 当前片收尾，整块挪进下一片。
                ranges.extend(part.take());
                backed_sz = total_sz + SPARSE_HEADER_SIZE as u64 + CHUNK_HEADER_SIZE as u64;
                block_cursor = part.push(idx, consumed, data_sz, blocks_left, block_cursor);
                idx += 1;
                consumed = 0;
            } else {
                // 单块就撑破一整片：当前片收尾，新片从这块的开头切起。
                let take = ((split_max_len as usize / block_size) * block_size)
                    .max(block_size)
                    .min(data_sz);
                ranges.extend(part.take());
                block_cursor = part.push(
                    idx,
                    consumed,
                    take,
                    (take / block_size) as u32,
                    block_cursor,
                );
                backed_sz = CHUNK_HEADER_SIZE as u64 + take as u64;
                consumed += take;
            }
        } else {
            // 当前片还有空间：劈开这块，用前半段把它填满。
            let mut room = ((split_max_len - backed_real) as usize / block_size) * block_size;
            if room == 0 {
                if part.started {
                    // 连一个块都塞不下：收尾，下一轮用空片重新判断。
                    ranges.extend(part.take());
                    backed_sz = SPARSE_HEADER_SIZE as u64;
                    continue;
                }
                // 空片都放不下一个块，说明预算小于块大小：只能超发一块，否则不前进。
                room = block_size;
            }
            let take = room.min(data_sz);
            block_cursor = part.push(
                idx,
                consumed,
                take,
                (take / block_size) as u32,
                block_cursor,
            );
            ranges.extend(part.take());
            backed_sz = SPARSE_HEADER_SIZE as u64 + CHUNK_HEADER_SIZE as u64;
            consumed += take;
        }

        if consumed > 0 && consumed >= meta.data_size as usize {
            idx += 1;
            consumed = 0;
        }
    }
    ranges.extend(part.take());

    ranges
}

impl StreamingResparse {
    pub fn total_fragments(&self) -> usize {
        self.total_fragments
    }

    pub fn next_fragment(&mut self) -> Result<Option<(Vec<u8>, usize, bool)>, SparseError> {
        if self.current_fragment >= self.total_fragments {
            return Ok(None);
        }

        let range = &self.fragment_ranges[self.current_fragment];
        let fragment_index = self.current_fragment;
        let is_last = fragment_index + 1 >= self.total_fragments;
        let mut file = File::open(&self.file_path).map_err(SparseError::Io)?;
        let mut read_at = |offset: u64, out: &mut [u8]| -> Result<(), SparseError> {
            file.seek(SeekFrom::Start(offset))
                .map_err(SparseError::Io)?;
            file.read_exact(out).map_err(SparseError::Io)
        };
        let data = emit_fragment(&self.header, &self.chunk_metas, range, &mut read_at)?;

        self.current_fragment += 1;

        Ok(Some((data, fragment_index, is_last)))
    }
}

/// [`emit_fragment`] 读原镜像的回调：`(偏移, 缓冲)`，把缓冲读满或报错。
pub type ReadAt<'a> = dyn FnMut(u64, &mut [u8]) -> Result<(), SparseError> + 'a;

/// 按 [`plan_fragments`] 的边界拼出一片可直接 `download` 的 sparse 包——crate 唯一的分片发射器。
/// 片首/片尾各补一个 DONT_CARE 把数据钉在正确块偏移上，故每片都是自洽的完整 sparse 镜像。
/// `read_at(偏移, 缓冲)` 按偏移读原镜像的数据区（调用方决定怎么读，本函数只管拼装）。
pub fn emit_fragment(
    header: &SparseHeader,
    chunk_metas: &[ChunkMeta],
    range: &FragmentRange,
    read_at: &mut ReadAt<'_>,
) -> Result<Vec<u8>, SparseError> {
    let block_size = header.blk_sz;
    let total_blks = header.total_blks;

    let start_block = range.start_block;
    let end_block = range.end_block;
    let trailing_blocks = total_blks.saturating_sub(end_block);

    let mut num_chunks = (range.end_chunk - range.start_chunk) as u32;
    if start_block > 0 {
        num_chunks += 1;
    }
    if trailing_blocks > 0 {
        num_chunks += 1;
    }

    // 按线上实际字节预留，而不是按本片覆盖的块数。DontCare 覆盖的块可以多达数百 MB
    // 却一个字节都不传，照块数预留会白白 commit 出几百 MB 内存（预取时还要 ×2）。
    let payload: usize = chunk_metas[range.start_chunk..range.end_chunk]
        .iter()
        .enumerate()
        .map(|(offset, meta)| match meta.chunk_type {
            ChunkType::Raw => {
                let i = range.start_chunk + offset;
                if i == range.end_chunk - 1 {
                    range.last_chunk_size
                } else if i == range.start_chunk {
                    meta.data_size as usize - range.first_chunk_offset
                } else {
                    meta.data_size as usize
                }
            }
            ChunkType::Fill | ChunkType::Crc32 => 4,
            ChunkType::DontCare => 0,
        })
        .sum();
    let mut buffer =
        Vec::with_capacity(SPARSE_HEADER_SIZE + num_chunks as usize * CHUNK_HEADER_SIZE + payload);

    buffer.extend_from_slice(&SPARSE_HEADER_MAGIC.to_le_bytes());
    buffer.extend_from_slice(&1u16.to_le_bytes());
    buffer.extend_from_slice(&0u16.to_le_bytes());
    buffer.extend_from_slice(&(SPARSE_HEADER_SIZE as u16).to_le_bytes());
    buffer.extend_from_slice(&(CHUNK_HEADER_SIZE as u16).to_le_bytes());
    buffer.extend_from_slice(&block_size.to_le_bytes());
    buffer.extend_from_slice(&total_blks.to_le_bytes());
    buffer.extend_from_slice(&num_chunks.to_le_bytes());
    buffer.extend_from_slice(&0u32.to_le_bytes());

    if start_block > 0 {
        buffer.extend_from_slice(&0xCAC3u16.to_le_bytes());
        buffer.extend_from_slice(&0u16.to_le_bytes());
        buffer.extend_from_slice(&start_block.to_le_bytes());
        buffer.extend_from_slice(&(CHUNK_HEADER_SIZE as u32).to_le_bytes());
    }

    for (offset, meta) in chunk_metas[range.start_chunk..range.end_chunk]
        .iter()
        .enumerate()
    {
        let is_first = offset == 0;
        let is_last = range.start_chunk + offset == range.end_chunk - 1;

        match meta.chunk_type {
            ChunkType::Raw => {
                let start_offset = if is_first {
                    range.first_chunk_offset
                } else {
                    0
                };
                let take_bytes = if is_last {
                    range.last_chunk_size
                } else {
                    meta.data_size as usize - start_offset
                };

                let output_blocks = take_bytes.div_ceil(block_size as usize) as u32;
                let aligned_bytes = (output_blocks as usize) * (block_size as usize);
                let total_sz = (CHUNK_HEADER_SIZE + aligned_bytes) as u32;

                buffer.extend_from_slice(&0xCAC1u16.to_le_bytes());
                buffer.extend_from_slice(&0u16.to_le_bytes());
                buffer.extend_from_slice(&output_blocks.to_le_bytes());
                buffer.extend_from_slice(&total_sz.to_le_bytes());

                let old_len = buffer.len();
                buffer.resize(old_len + take_bytes, 0);
                read_at(
                    meta.file_offset + start_offset as u64,
                    &mut buffer[old_len..],
                )?;

                if take_bytes < aligned_bytes {
                    buffer.extend(std::iter::repeat_n(0u8, aligned_bytes - take_bytes));
                }
            }
            ChunkType::Fill => {
                let total_sz = (CHUNK_HEADER_SIZE + 4) as u32;
                buffer.extend_from_slice(&0xCAC2u16.to_le_bytes());
                buffer.extend_from_slice(&0u16.to_le_bytes());
                buffer.extend_from_slice(&meta.output_blocks.to_le_bytes());
                buffer.extend_from_slice(&total_sz.to_le_bytes());

                let mut fill_val = [0u8; 4];
                read_at(meta.file_offset, &mut fill_val)?;
                buffer.extend_from_slice(&fill_val);
            }
            ChunkType::DontCare => {
                buffer.extend_from_slice(&0xCAC3u16.to_le_bytes());
                buffer.extend_from_slice(&0u16.to_le_bytes());
                buffer.extend_from_slice(&meta.output_blocks.to_le_bytes());
                buffer.extend_from_slice(&(CHUNK_HEADER_SIZE as u32).to_le_bytes());
            }
            ChunkType::Crc32 => {
                let total_sz = (CHUNK_HEADER_SIZE + 4) as u32;
                buffer.extend_from_slice(&0xCAC4u16.to_le_bytes());
                buffer.extend_from_slice(&0u16.to_le_bytes());
                buffer.extend_from_slice(&0u32.to_le_bytes());
                buffer.extend_from_slice(&total_sz.to_le_bytes());

                let mut crc_val = [0u8; 4];
                read_at(meta.file_offset, &mut crc_val)?;
                buffer.extend_from_slice(&crc_val);
            }
        }
    }

    if trailing_blocks > 0 {
        buffer.extend_from_slice(&0xCAC3u16.to_le_bytes());
        buffer.extend_from_slice(&0u16.to_le_bytes());
        buffer.extend_from_slice(&trailing_blocks.to_le_bytes());
        buffer.extend_from_slice(&(CHUNK_HEADER_SIZE as u32).to_le_bytes());
    }

    Ok(buffer)
}

// ============================ 测试镜像构造器 ============================
// 生产路径只读 sparse、从不生成；下面两个类型仅供单测拼装各种形态的 sparse 镜像。

#[cfg(test)]
struct SparseWriter {
    block_size: u32,
    chunks: Vec<SparseChunk>,
    current_size: u64,
    current_blocks: u32,
}
#[cfg(test)]
#[derive(Clone, Debug)]
enum SparseChunk {
    Raw(Vec<u8>),
    Fill { value: u32, blocks: u32 },
    DontCare { blocks: u32 },
    Crc32(u32),
}

#[cfg(test)]
impl SparseChunk {
    fn transfer_size(&self) -> u64 {
        let data_size = match self {
            SparseChunk::Raw(data) => data.len() as u64,
            SparseChunk::Fill { .. } => 4,
            SparseChunk::DontCare { .. } => 0,
            SparseChunk::Crc32(_) => 4,
        };
        CHUNK_HEADER_SIZE as u64 + data_size
    }
    fn output_blocks(&self, block_size: u32) -> u32 {
        match self {
            SparseChunk::Raw(data) => (data.len() as u32).div_ceil(block_size),
            SparseChunk::Fill { blocks, .. } => *blocks,
            SparseChunk::DontCare { blocks } => *blocks,
            SparseChunk::Crc32(_) => 0,
        }
    }
    fn chunk_type(&self) -> ChunkType {
        match self {
            SparseChunk::Raw(_) => ChunkType::Raw,
            SparseChunk::Fill { .. } => ChunkType::Fill,
            SparseChunk::DontCare { .. } => ChunkType::DontCare,
            SparseChunk::Crc32(_) => ChunkType::Crc32,
        }
    }
}

#[cfg(test)]
impl SparseWriter {
    fn new(block_size: u32) -> Self {
        Self {
            block_size,
            chunks: Vec::new(),
            current_size: SPARSE_HEADER_SIZE as u64,
            current_blocks: 0,
        }
    }
    fn add_chunk(&mut self, chunk: SparseChunk) {
        let blocks = chunk.output_blocks(self.block_size);
        self.current_size += chunk.transfer_size();
        self.current_blocks += blocks;
        self.chunks.push(chunk);
    }
    fn build(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.current_size as usize);
        output.extend_from_slice(&SPARSE_HEADER_MAGIC.to_le_bytes());
        output.extend_from_slice(&1u16.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&(SPARSE_HEADER_SIZE as u16).to_le_bytes());
        output.extend_from_slice(&(CHUNK_HEADER_SIZE as u16).to_le_bytes());
        output.extend_from_slice(&self.block_size.to_le_bytes());
        output.extend_from_slice(&self.current_blocks.to_le_bytes());
        output.extend_from_slice(&(self.chunks.len() as u32).to_le_bytes());
        output.extend_from_slice(&0u32.to_le_bytes());

        for chunk in &self.chunks {
            let chunk_type = chunk.chunk_type() as u16;
            let output_blocks = chunk.output_blocks(self.block_size);
            let total_sz = chunk.transfer_size() as u32;
            output.extend_from_slice(&chunk_type.to_le_bytes());
            output.extend_from_slice(&0u16.to_le_bytes());
            output.extend_from_slice(&output_blocks.to_le_bytes());
            output.extend_from_slice(&total_sz.to_le_bytes());
            match chunk {
                SparseChunk::Raw(data) => output.extend_from_slice(data),
                SparseChunk::Fill { value, .. } => output.extend_from_slice(&value.to_le_bytes()),
                SparseChunk::DontCare { .. } => {}
                SparseChunk::Crc32(crc) => output.extend_from_slice(&crc.to_le_bytes()),
            }
        }

        output
    }
}

pub fn is_sparse_file(path: &Path) -> Result<bool, io::Error> {
    let mut file = File::open(path)?;
    let mut magic_buf = [0u8; 4];

    if file.read_exact(&mut magic_buf).is_err() {
        return Ok(false);
    }

    let magic = u32::from_le_bytes(magic_buf);
    Ok(magic == SPARSE_HEADER_MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_type_from_u16() {
        assert_eq!(ChunkType::from_u16(0xCAC1).unwrap(), ChunkType::Raw);
        assert_eq!(ChunkType::from_u16(0xCAC2).unwrap(), ChunkType::Fill);
        assert_eq!(ChunkType::from_u16(0xCAC3).unwrap(), ChunkType::DontCare);
        assert_eq!(ChunkType::from_u16(0xCAC4).unwrap(), ChunkType::Crc32);
        assert!(ChunkType::from_u16(0x0000).is_err());
    }

    #[test]
    fn test_sparse_header_size() {
        assert_eq!(SPARSE_HEADER_SIZE, 28);
        assert_eq!(CHUNK_HEADER_SIZE, 12);
    }

    #[test]
    fn test_sparse_header_from_bytes() {
        let mut data = vec![0u8; SPARSE_HEADER_SIZE];
        data[0..4].copy_from_slice(&SPARSE_HEADER_MAGIC.to_le_bytes());
        data[4..6].copy_from_slice(&1u16.to_le_bytes());
        data[6..8].copy_from_slice(&0u16.to_le_bytes());
        data[8..10].copy_from_slice(&28u16.to_le_bytes());
        data[10..12].copy_from_slice(&12u16.to_le_bytes());
        data[12..16].copy_from_slice(&4096u32.to_le_bytes());
        data[16..20].copy_from_slice(&1000u32.to_le_bytes());
        data[20..24].copy_from_slice(&10u32.to_le_bytes());
        data[24..28].copy_from_slice(&0u32.to_le_bytes());

        let header = SparseHeader::from_bytes(&data).unwrap();
        assert!(header.validate().is_ok());
        assert_eq!(header.magic, SPARSE_HEADER_MAGIC);
        assert_eq!(header.major_version, 1);
        assert_eq!(header.blk_sz, 4096);
        assert_eq!(header.total_blks, 1000);
        assert_eq!(header.expanded_size(), 4096 * 1000);
    }

    #[test]
    fn test_sparse_header_validate() {
        let mut data = vec![0u8; SPARSE_HEADER_SIZE];
        data[0..4].copy_from_slice(&SPARSE_HEADER_MAGIC.to_le_bytes());
        data[4..6].copy_from_slice(&1u16.to_le_bytes());
        data[8..10].copy_from_slice(&(SPARSE_HEADER_SIZE as u16).to_le_bytes());
        data[10..12].copy_from_slice(&(CHUNK_HEADER_SIZE as u16).to_le_bytes());
        data[12..16].copy_from_slice(&4096u32.to_le_bytes());
        data[16..20].copy_from_slice(&100u32.to_le_bytes());

        let header = SparseHeader::from_bytes(&data).unwrap();
        assert!(header.validate().is_ok());
        let mut bad_magic = data.clone();
        bad_magic[0..4].copy_from_slice(&0x12345678u32.to_le_bytes());
        let header = SparseHeader::from_bytes(&bad_magic).unwrap();
        assert!(matches!(
            header.validate(),
            Err(SparseError::InvalidMagic(_))
        ));
        let mut bad_version = data.clone();
        bad_version[4..6].copy_from_slice(&2u16.to_le_bytes());
        let header = SparseHeader::from_bytes(&bad_version).unwrap();
        assert!(matches!(
            header.validate(),
            Err(SparseError::UnsupportedVersion(_, _))
        ));
        let mut bad_blk_sz = data.clone();
        bad_blk_sz[12..16].copy_from_slice(&0u32.to_le_bytes());
        let header = SparseHeader::from_bytes(&bad_blk_sz).unwrap();
        assert!(matches!(
            header.validate(),
            Err(SparseError::InvalidHeader(_))
        ));
        // AOSP 语义：blk_sz 必须为 4 的倍数；两个头长度不得小于结构体本身
        let mut unaligned_blk_sz = data.clone();
        unaligned_blk_sz[12..16].copy_from_slice(&4094u32.to_le_bytes());
        let header = SparseHeader::from_bytes(&unaligned_blk_sz).unwrap();
        assert!(matches!(
            header.validate(),
            Err(SparseError::InvalidHeader(_))
        ));
        let mut small_file_hdr = data.clone();
        small_file_hdr[8..10].copy_from_slice(&((SPARSE_HEADER_SIZE - 1) as u16).to_le_bytes());
        let header = SparseHeader::from_bytes(&small_file_hdr).unwrap();
        assert!(matches!(
            header.validate(),
            Err(SparseError::InvalidHeader(_))
        ));
        let mut small_chunk_hdr = data.clone();
        small_chunk_hdr[10..12].copy_from_slice(&((CHUNK_HEADER_SIZE - 1) as u16).to_le_bytes());
        let header = SparseHeader::from_bytes(&small_chunk_hdr).unwrap();
        assert!(matches!(
            header.validate(),
            Err(SparseError::InvalidHeader(_))
        ));
    }

    #[test]
    fn test_chunk_header_from_bytes() {
        let mut data = vec![0u8; CHUNK_HEADER_SIZE];
        data[0..2].copy_from_slice(&0xCAC1u16.to_le_bytes());
        data[2..4].copy_from_slice(&0u16.to_le_bytes());
        data[4..8].copy_from_slice(&10u32.to_le_bytes());
        data[8..12].copy_from_slice(&40972u32.to_le_bytes());

        let chunk = ChunkHeader::from_bytes(&data).unwrap();
        assert_eq!(chunk.get_type().unwrap(), ChunkType::Raw);
        assert_eq!(chunk.chunk_sz, 10);
    }

    #[test]
    fn test_sparse_writer_basic() {
        let mut writer = SparseWriter::new(4096);
        writer.add_chunk(SparseChunk::Raw(vec![0xAB; 4096]));
        writer.add_chunk(SparseChunk::Fill {
            value: 0,
            blocks: 5,
        });
        writer.add_chunk(SparseChunk::DontCare { blocks: 4 });

        let data = writer.build();
        let header = SparseHeader::from_bytes(&data).unwrap();
        assert!(header.validate().is_ok());
        assert_eq!(header.blk_sz, 4096);
        assert_eq!(header.total_chunks, 3);
        assert_eq!(header.total_blks, 10);
    }

    #[test]
    fn test_sparse_writer_roundtrip() {
        let mut writer = SparseWriter::new(4096);
        writer.add_chunk(SparseChunk::Raw(vec![0x11; 4096 * 2]));
        writer.add_chunk(SparseChunk::Fill {
            value: 0xDEADBEEF,
            blocks: 10,
        });
        writer.add_chunk(SparseChunk::DontCare { blocks: 88 });

        let data = writer.build();
        let header = SparseHeader::from_bytes(&data).unwrap();
        assert!(header.validate().is_ok());
        assert_eq!(header.total_blks, 100);
        assert_eq!(header.total_chunks, 3);
    }

    #[test]
    fn test_sparse_chunk_transfer_size() {
        let raw = SparseChunk::Raw(vec![0; 1000]);
        assert_eq!(raw.transfer_size(), CHUNK_HEADER_SIZE as u64 + 1000);
        let fill = SparseChunk::Fill {
            value: 0,
            blocks: 100,
        };
        assert_eq!(fill.transfer_size(), CHUNK_HEADER_SIZE as u64 + 4);
        let dont_care = SparseChunk::DontCare { blocks: 100 };
        assert_eq!(dont_care.transfer_size(), CHUNK_HEADER_SIZE as u64);
        let crc = SparseChunk::Crc32(0x12345678);
        assert_eq!(crc.transfer_size(), CHUNK_HEADER_SIZE as u64 + 4);
    }

    #[test]
    fn test_sparse_chunk_output_blocks() {
        let block_size = 4096u32;
        let raw = SparseChunk::Raw(vec![0; 4096 * 3]);
        assert_eq!(raw.output_blocks(block_size), 3);
        let raw_small = SparseChunk::Raw(vec![0; 100]);
        assert_eq!(raw_small.output_blocks(block_size), 1);
        let fill = SparseChunk::Fill {
            value: 0,
            blocks: 50,
        };
        assert_eq!(fill.output_blocks(block_size), 50);
        let dont_care = SparseChunk::DontCare { blocks: 25 };
        assert_eq!(dont_care.output_blocks(block_size), 25);
        let crc = SparseChunk::Crc32(0);
        assert_eq!(crc.output_blocks(block_size), 0);
    }
    fn create_test_sparse(block_size: u32, chunks: &[SparseChunk]) -> Vec<u8> {
        let mut writer = SparseWriter::new(block_size);
        for chunk in chunks {
            writer.add_chunk(chunk.clone());
        }
        writer.build()
    }

    #[test]
    fn test_resparse_no_split_needed() {
        let block_size = 4096u32;
        let chunks = vec![
            SparseChunk::Raw(vec![0xAB; 4096]),
            SparseChunk::Fill {
                value: 0,
                blocks: 2,
            },
        ];
        let data = create_test_sparse(block_size, &chunks);

        let header = SparseHeader::from_bytes(&data).unwrap();
        assert!(header.validate().is_ok());
        assert_eq!(header.total_blks, 3);
    }

    /// chunk 头表扫描改成「带缓冲顺序读 + seek_relative 跳过数据区」后的回归护栏：
    /// 跳距只要算错一次，后续所有 chunk 的类型/起始块/数据区偏移都会整体串位。
    #[test]
    fn resparse_scan_matches_chunk_layout() {
        let block_size = 4096u32;
        let chunks = vec![
            SparseChunk::Raw(vec![0xAB; 4096 * 2]),
            SparseChunk::DontCare { blocks: 5 },
            SparseChunk::Fill {
                value: 0xDEADBEEF,
                blocks: 3,
            },
            SparseChunk::Raw(vec![0xCD; 4096]),
        ];
        let data = create_test_sparse(block_size, &chunks);
        let path = std::env::temp_dir().join("rmf_resparse_scan_layout.img");
        std::fs::write(&path, &data).unwrap();

        let resparse = StreamingResparse::new(&path, 64 * 1024 * 1024).unwrap();
        let metas = resparse.chunk_metas.clone();

        assert_eq!(metas.len(), chunks.len());
        assert_eq!(
            metas.iter().map(|m| m.chunk_type).collect::<Vec<_>>(),
            vec![
                ChunkType::Raw,
                ChunkType::DontCare,
                ChunkType::Fill,
                ChunkType::Raw
            ]
        );

        // 逐 chunk 的块数与源镜像一致（CRC32 以外不丢不并），起始块由顺序累加决定。
        for (meta, chunk) in metas.iter().zip(chunks.iter()) {
            assert_eq!(meta.output_blocks, chunk.output_blocks(block_size));
        }

        // file_offset 必须落在该 chunk 的数据区本体上
        for (meta, expect) in [(&metas[0], 0xABu8), (&metas[3], 0xCDu8)] {
            let start = meta.file_offset as usize;
            let end = start + meta.data_size as usize;
            assert!(data[start..end].iter().all(|b| *b == expect));
        }

        let _ = std::fs::remove_file(&path);
    }

    /// 模拟设备端收到一个 sparse 包后的落盘行为：Raw/Fill 按块号写入，DontCare 只推进
    /// 块游标（设备不动那段），Crc32 不产出数据。
    fn apply_sparse_to_disk(packet: &[u8], disk: &mut [u8], block_size: usize) {
        let header = SparseHeader::from_bytes(&packet[..SPARSE_HEADER_SIZE]).unwrap();
        header.validate().unwrap();
        assert_eq!(header.blk_sz as usize, block_size);

        let mut offset = header.file_hdr_sz as usize;
        let mut block = 0usize;

        for i in 0..header.total_chunks {
            let ch = ChunkHeader::from_bytes(&packet[offset..offset + CHUNK_HEADER_SIZE]).unwrap();
            let data_start = offset + CHUNK_HEADER_SIZE;
            let data_len = ch.total_sz as usize - CHUNK_HEADER_SIZE;
            let out_blocks = ch.chunk_sz as usize;
            let dst = block * block_size;

            match ch.get_type().unwrap() {
                ChunkType::Raw => {
                    assert_eq!(
                        data_len,
                        out_blocks * block_size,
                        "chunk {i} 声明 {out_blocks} 块却带了 {data_len} 字节"
                    );
                    disk[dst..dst + data_len]
                        .copy_from_slice(&packet[data_start..data_start + data_len]);
                }
                ChunkType::Fill => {
                    let value = &packet[data_start..data_start + 4];
                    for (k, b) in disk[dst..dst + out_blocks * block_size]
                        .iter_mut()
                        .enumerate()
                    {
                        *b = value[k % 4];
                    }
                }
                ChunkType::DontCare | ChunkType::Crc32 => {}
            }

            block += out_blocks;
            offset += ch.total_sz as usize;
        }

        assert_eq!(
            block, header.total_blks as usize,
            "包里的 chunk 没有铺满 header 声明的总块数"
        );
    }

    /// resparse 核心契约：分片逐片下发的落盘结果必须与整包一次下发逐字节一致——起始块、
    /// DontCare 补位、Raw 拆分点任一算错都会写错偏移，真机上只表现为「刷完起不来」。
    fn assert_fragments_reassemble(block_size: u32, max_download: u64, tag: &str) {
        let bs = block_size as usize;

        // 三段 Raw 用互不相同且块内不重复的模式，任何错位都对不上
        let raw_a: Vec<u8> = (0..bs * 12).map(|i| (i % 251) as u8).collect();
        let raw_b: Vec<u8> = (0..bs * 20).map(|i| ((i / 7 + 13) % 253) as u8).collect();
        let raw_c: Vec<u8> = (0..bs * 9).map(|i| ((i * 3 + 89) % 249) as u8).collect();

        let chunks = vec![
            SparseChunk::Raw(raw_a),
            SparseChunk::DontCare { blocks: 6 },
            SparseChunk::Fill {
                value: 0xDEADBEEF,
                blocks: 5,
            },
            SparseChunk::Raw(raw_b),
            SparseChunk::Fill {
                value: 0x5A5A5A5A,
                blocks: 3,
            },
            SparseChunk::DontCare { blocks: 4 },
            SparseChunk::Raw(raw_c),
        ];

        let image = create_test_sparse(block_size, &chunks);
        let total_blocks: u32 = chunks.iter().map(|c| c.output_blocks(block_size)).sum();
        let disk_len = total_blocks as usize * bs;

        let path = std::env::temp_dir().join(format!("rmf_resparse_roundtrip_{tag}.img"));
        std::fs::write(&path, &image).unwrap();

        let mut expected = vec![0u8; disk_len];
        apply_sparse_to_disk(&image, &mut expected, bs);

        let mut resparse = StreamingResparse::new(&path, max_download).unwrap();
        assert!(
            resparse.total_fragments() > 1,
            "上限太大没触发分片，这个用例就白跑了"
        );

        let mut actual = vec![0u8; disk_len];
        let mut seen = 0usize;
        while let Some((fragment, idx, _)) = resparse.next_fragment().unwrap() {
            assert_eq!(idx, seen);
            assert!(
                fragment.len() as u64 <= max_download,
                "第 {idx} 片 {} 字节，超过 max-download-size {max_download}，设备会直接拒收",
                fragment.len()
            );
            apply_sparse_to_disk(&fragment, &mut actual, bs);
            seen += 1;
        }

        assert_eq!(seen, resparse.total_fragments());
        assert_eq!(actual, expected, "分片重组结果与整包下发不一致");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn streaming_resparse_fragments_reassemble_to_original() {
        // 上限取得远小于单个 Raw 段，逼出「一个 chunk 跨多片」的拆分路径
        assert_fragments_reassemble(4096, 24 * 1024, "blk4096");
    }

    /// 小块 blk_sz（512）同样要满足重组契约：切分点运算全程以 blk_sz 为步长，
    /// 只测 4096 盖不住「预算/块大小」比值悬殊时的边界取整。
    #[test]
    fn streaming_resparse_reassembles_with_small_block_size() {
        assert_fragments_reassemble(512, 8 * 1024, "blk512");
    }

    /// 原镜像带 CRC32 chunk 时的分片行为：整包校验值抄进分片必然不成立，
    /// 官方 libsparse resparse 直接丢弃 CRC chunk，此用例固化同样的做法。
    #[test]
    fn streaming_resparse_handles_crc32_chunk() {
        let block_size = 4096u32;
        let bs = block_size as usize;

        let raw: Vec<u8> = (0..bs * 16).map(|i| (i % 241) as u8).collect();
        let chunks = vec![
            SparseChunk::Raw(raw),
            SparseChunk::Fill {
                value: 0x11223344,
                blocks: 4,
            },
            SparseChunk::Crc32(0xA5A5_5A5A),
        ];

        let image = create_test_sparse(block_size, &chunks);
        let path = std::env::temp_dir().join("rmf_resparse_crc32.img");
        std::fs::write(&path, &image).unwrap();

        let max_download = 24 * 1024u64;
        let mut resparse = StreamingResparse::new(&path, max_download).unwrap();
        assert!(resparse.total_fragments() > 1);

        let mut crc_chunks_emitted = 0usize;
        while let Some((fragment, _, _)) = resparse.next_fragment().unwrap() {
            let header = SparseHeader::from_bytes(&fragment[..SPARSE_HEADER_SIZE]).unwrap();
            let mut offset = header.file_hdr_sz as usize;
            for _ in 0..header.total_chunks {
                let ch =
                    ChunkHeader::from_bytes(&fragment[offset..offset + CHUNK_HEADER_SIZE]).unwrap();
                if ch.get_type().unwrap() == ChunkType::Crc32 {
                    crc_chunks_emitted += 1;
                }
                offset += ch.total_sz as usize;
            }
        }

        assert_eq!(
            crc_chunks_emitted, 0,
            "分片里不该出现 CRC32 chunk：整包的校验值套在分片上必然对不上，\
             严格校验的 bootloader 会直接拒收"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// AOSP 语义：file_hdr_sz/chunk_hdr_sz 允许大于结构体本身，多出的字节是未知扩展、
    /// 解析时必须按声明的头长度跳过。硬编码 28/12 会把扩展字节当数据，后续偏移全部串位。
    /// 扫描与重切分都要吃得下这种镜像。
    #[test]
    fn extended_header_sizes_are_honored() {
        let blk = 4096u32;
        let bs = blk as usize;
        let file_hdr = (SPARSE_HEADER_SIZE + 4) as u16;
        let chunk_hdr = (CHUNK_HEADER_SIZE + 4) as u16;
        let raw: Vec<u8> = (0..bs).map(|i| (i % 254) as u8).collect();
        let fill_val = 0x11223344u32;

        let mut img = Vec::new();
        img.extend_from_slice(&SPARSE_HEADER_MAGIC.to_le_bytes());
        img.extend_from_slice(&1u16.to_le_bytes());
        img.extend_from_slice(&0u16.to_le_bytes());
        img.extend_from_slice(&file_hdr.to_le_bytes());
        img.extend_from_slice(&chunk_hdr.to_le_bytes());
        img.extend_from_slice(&blk.to_le_bytes());
        img.extend_from_slice(&4u32.to_le_bytes()); // total_blks：1 Raw + 2 Fill + 1 DontCare
        img.extend_from_slice(&3u32.to_le_bytes()); // total_chunks
        img.extend_from_slice(&0u32.to_le_bytes());
        img.extend_from_slice(&[0xEE; 4]); // 整包头扩展字节

        fn put_chunk(img: &mut Vec<u8>, ty: u16, blocks: u32, chunk_hdr: u16, data: &[u8]) {
            img.extend_from_slice(&ty.to_le_bytes());
            img.extend_from_slice(&0u16.to_le_bytes());
            img.extend_from_slice(&blocks.to_le_bytes());
            img.extend_from_slice(&(chunk_hdr as u32 + data.len() as u32).to_le_bytes());
            img.extend_from_slice(&[0xEE; 4]); // chunk 头扩展字节
            img.extend_from_slice(data);
        }
        put_chunk(&mut img, 0xCAC1, 1, chunk_hdr, &raw);
        put_chunk(&mut img, 0xCAC2, 2, chunk_hdr, &fill_val.to_le_bytes());
        put_chunk(&mut img, 0xCAC3, 1, chunk_hdr, &[]);

        let path = std::env::temp_dir().join("rmf_sparse_ext_hdr.img");
        std::fs::write(&path, &img).unwrap();

        // 扫描：每个 chunk 的数据区必须精确落在扩展头之后
        let scan = StreamingResparse::new(&path, 64 * 1024 * 1024).unwrap();
        let metas = &scan.chunk_metas;
        assert_eq!(
            metas.iter().map(|m| m.chunk_type).collect::<Vec<_>>(),
            vec![ChunkType::Raw, ChunkType::Fill, ChunkType::DontCare]
        );
        let data_at = |m: &ChunkMeta| &img[m.file_offset as usize..][..m.data_size as usize];
        assert_eq!(data_at(&metas[0]), &raw[..]);
        assert_eq!(data_at(&metas[1]), &fill_val.to_le_bytes());
        assert_eq!(metas[2].data_size, 0);

        // 重切分路径：emit 重拼标准头后的落盘结果必须与原镜像语义一致
        let mut expected = vec![0u8; 4 * bs];
        expected[..bs].copy_from_slice(&raw);
        for (k, b) in expected[bs..3 * bs].iter_mut().enumerate() {
            *b = fill_val.to_le_bytes()[k % 4];
        }
        let mut resparse = StreamingResparse::new(&path, 1 << 20).unwrap();
        let mut actual = vec![0u8; 4 * bs];
        while let Some((frag, _, _)) = resparse.next_fragment().unwrap() {
            apply_sparse_to_disk(&frag, &mut actual, bs);
        }
        assert_eq!(actual, expected, "扩展头镜像经重切分后落盘结果错位");

        let _ = std::fs::remove_file(&path);
    }

    /// 损坏镜像必须拦在下发之前：几何不符、块数不守恒、数据区越界任何一种溜进设备，
    /// 轻则协议错位重则写坏分区。重切分扫描（下发前唯一的解析入口）必须拒收。
    #[test]
    fn corrupt_images_are_rejected_before_flashing() {
        let block_size = 4096u32;
        let chunks = vec![
            SparseChunk::Raw(vec![0xAB; 4096]),
            SparseChunk::Fill {
                value: 0,
                blocks: 2,
            },
            SparseChunk::DontCare { blocks: 1 },
        ];
        let good = create_test_sparse(block_size, &chunks);

        // 扫描期就必须拒收；needle 断言错误文本里带出具体原因
        fn assert_rejected(bytes: &[u8], tag: &str, needle: Option<&str>) {
            let path = std::env::temp_dir().join(format!("rmf_sparse_corrupt_{tag}.img"));
            std::fs::write(&path, bytes).unwrap();
            let err = StreamingResparse::new(&path, 1 << 20)
                .err()
                .unwrap_or_else(|| panic!("{tag}: 重切分扫描必须拒收"))
                .to_string();
            let _ = std::fs::remove_file(&path);
            if let Some(needle) = needle {
                assert!(
                    err.contains(needle),
                    "{tag}: 错误文本缺少 {needle:?}: {err}"
                );
            }
        }

        // 基准镜像本身必须合法
        let base_path = std::env::temp_dir().join("rmf_sparse_corrupt_base.img");
        std::fs::write(&base_path, &good).unwrap();
        assert!(StreamingResparse::new(&base_path, 1 << 20).is_ok());
        let _ = std::fs::remove_file(&base_path);

        // ① 几何不符：Raw chunk 的 total_sz 少 1 字节，与声明块数对不上
        let mut bad_geometry = good.clone();
        let total_sz_at = SPARSE_HEADER_SIZE + 8;
        bad_geometry[total_sz_at..total_sz_at + 4]
            .copy_from_slice(&((CHUNK_HEADER_SIZE + 4095) as u32).to_le_bytes());
        assert_rejected(&bad_geometry, "geometry", Some("total_sz 与类型不符"));

        // ② 块数不守恒：头部声明的 total_blks 比 chunk 表多 1
        let mut bad_conservation = good.clone();
        bad_conservation[16..20].copy_from_slice(&5u32.to_le_bytes());
        assert_rejected(&bad_conservation, "conservation", Some("不守恒"));

        // ③ 数据区越界：文件在 Raw 数据中间被截断
        assert_rejected(
            &good[..SPARSE_HEADER_SIZE + CHUNK_HEADER_SIZE + 100],
            "truncated",
            None,
        );

        // ④ CRC32 带块数：libsparse 恒写 0，非 0 会让块游标各处不一致
        let mut crc_writer = SparseWriter::new(block_size);
        crc_writer.add_chunk(SparseChunk::Raw(vec![0xCD; 4096]));
        crc_writer.add_chunk(SparseChunk::Crc32(0x1234_5678));
        let mut bad_crc = crc_writer.build();
        let crc_hdr_at = SPARSE_HEADER_SIZE + CHUNK_HEADER_SIZE + 4096;
        bad_crc[crc_hdr_at + 4..crc_hdr_at + 8].copy_from_slice(&1u32.to_le_bytes());
        assert_rejected(&bad_crc, "crc_blocks", Some("total_sz 与类型不符"));
    }

    /// 用真机 super.img 跑完整分片，校验每片自洽且块覆盖不漏不重（小镜像盖不到真实规模）。
    /// 手工跑：$env:RMF_TEST_SPARSE_IMG="...\super.img"
    ///   cargo test -p fastboot --lib real_sparse -- --ignored --nocapture
    #[test]
    #[ignore = "需要外部大镜像，手工排查时按注释里的方式跑"]
    fn real_sparse_image_resparse_covers_every_block() {
        let Ok(img) = std::env::var("RMF_TEST_SPARSE_IMG") else {
            eprintln!("未设置 RMF_TEST_SPARSE_IMG，跳过");
            return;
        };
        let max_download: u64 = std::env::var("RMF_TEST_MAX_DOWNLOAD")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(128 * 1024 * 1024);

        let mut resparse =
            StreamingResparse::new(std::path::Path::new(&img), max_download).unwrap();
        let header = resparse.header;
        let metas = resparse.chunk_metas.clone();

        println!(
            "镜像 blk_sz={} total_blks={} chunks={} max-download={:.0} MB",
            header.blk_sz,
            header.total_blks,
            metas.len(),
            max_download as f64 / 1048576.0
        );

        // 原镜像里 Raw/Fill 覆盖的块才需要真正落盘，DontCare 不算
        let mut expected = vec![0u8; header.total_blks as usize];
        let mut start_block = 0u32;
        for m in &metas {
            if matches!(m.chunk_type, ChunkType::Raw | ChunkType::Fill) {
                for b in start_block..start_block + m.output_blocks {
                    expected[b as usize] = 1;
                }
            }
            start_block += m.output_blocks;
        }

        let mut actual = vec![0u8; header.total_blks as usize];
        let mut fragments = 0usize;
        let mut peak = 0usize;
        let mut oversize = 0usize;

        while let Some((packet, idx, _)) = resparse.next_fragment().unwrap() {
            fragments += 1;
            peak = peak.max(packet.len());
            if packet.len() as u64 > max_download {
                oversize += 1;
                eprintln!("第 {idx} 片 {} 字节，超过 max-download-size", packet.len());
            }

            let h = SparseHeader::from_bytes(&packet[..SPARSE_HEADER_SIZE]).unwrap();
            h.validate().unwrap();
            assert_eq!(h.blk_sz, header.blk_sz, "第 {idx} 片 blk_sz 与原镜像不符");
            assert_eq!(
                h.total_blks, header.total_blks,
                "第 {idx} 片 total_blks 与原镜像不符"
            );

            let mut off = h.file_hdr_sz as usize;
            let mut blk = 0u32;
            for c in 0..h.total_chunks {
                let ch = ChunkHeader::from_bytes(&packet[off..off + CHUNK_HEADER_SIZE]).unwrap();
                let ty = ch.get_type().unwrap();
                if matches!(ty, ChunkType::Raw | ChunkType::Fill) {
                    for b in blk..blk + ch.chunk_sz {
                        assert_eq!(actual[b as usize], 0, "块 {b} 被第 {idx} 片重复写入");
                        actual[b as usize] = 1;
                    }
                }
                if ty == ChunkType::Raw {
                    assert_eq!(
                        ch.total_sz as usize - CHUNK_HEADER_SIZE,
                        ch.chunk_sz as usize * header.blk_sz as usize,
                        "第 {idx} 片 chunk {c} 声明块数与数据长度对不上"
                    );
                }
                blk += ch.chunk_sz;
                off += ch.total_sz as usize;
            }
            assert_eq!(blk, h.total_blks, "第 {idx} 片没铺满声明的总块数");
            assert_eq!(off, packet.len(), "第 {idx} 片有尾部冗余或被截断");
        }

        let missing = expected
            .iter()
            .zip(&actual)
            .filter(|(e, a)| **e == 1 && **a == 0)
            .count();
        let extra = expected
            .iter()
            .zip(&actual)
            .filter(|(e, a)| **e == 0 && **a == 1)
            .count();

        println!(
            "分片数={fragments} 峰值单片={:.1} MB 超限片数={oversize} 漏写块={missing} 多写块={extra}",
            peak as f64 / 1048576.0
        );

        assert_eq!(oversize, 0, "有分片超过 max-download-size，设备会拒收");
        assert_eq!(missing, 0, "有块没被任何分片写到");
        assert_eq!(extra, 0, "写了原镜像里并不存在的块");
    }

    /// zlib 口径的流式 CRC32（等价于 `binascii.crc32(buf, prev)`），用来和厂商清单对账。
    fn crc32_continue(prev: u32, bytes: &[u8]) -> u32 {
        static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
        let table = TABLE.get_or_init(|| {
            let mut t = [0u32; 256];
            for (i, entry) in t.iter_mut().enumerate() {
                let mut c = i as u32;
                for _ in 0..8 {
                    c = if c & 1 != 0 {
                        (c >> 1) ^ 0xEDB8_8320
                    } else {
                        c >> 1
                    };
                }
                *entry = c;
            }
            t
        });
        let mut crc = !prev;
        for &b in bytes {
            crc = table[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
        }
        !crc
    }

    /// 用厂商 `sparsecrclist.txt`（flash_gen_crc_list.py 生成，设备逐片 CRC 比对的基准）
    /// 给分片边界做终判：边界差一个块，从该片起 CRC 全部错位。手工跑：
    ///   $env:RMF_TEST_SPARSE_IMG="...\images\super.img"
    ///   $env:RMF_TEST_SPARSE_CRCLIST="...\images\sparsecrclist.txt"
    ///   cargo test -p fastboot --lib official_crc -- --ignored --nocapture
    #[test]
    #[ignore = "需要外部固件包，手工排查时按注释里的方式跑"]
    fn resparse_fragments_match_official_crc_list() {
        let (Ok(img), Ok(list)) = (
            std::env::var("RMF_TEST_SPARSE_IMG"),
            std::env::var("RMF_TEST_SPARSE_CRCLIST"),
        ) else {
            eprintln!("未设置 RMF_TEST_SPARSE_IMG / RMF_TEST_SPARSE_CRCLIST，跳过");
            return;
        };
        let part = std::env::var("RMF_TEST_SPARSE_PART").unwrap_or_else(|_| "super".to_string());
        let max_download: u64 = std::env::var("RMF_TEST_MAX_DOWNLOAD")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(128 * 1024 * 1024);

        let text = std::fs::read_to_string(&list).unwrap();
        let expected: Vec<u32> = text
            .lines()
            .find(|l| l.split_whitespace().next() == Some(part.as_str()))
            .unwrap_or_else(|| panic!("{list} 里没有 {part} 条目"))
            .split_whitespace()
            .skip(2)
            .map(|h| u32::from_str_radix(h.trim_start_matches("0x"), 16).unwrap())
            .collect();

        let mut resparse =
            StreamingResparse::new(std::path::Path::new(&img), max_download).unwrap();
        let blk_sz = resparse.header.blk_sz as usize;
        let mut actual = Vec::new();

        while let Some((packet, _, _)) = resparse.next_fragment().unwrap() {
            let h = SparseHeader::from_bytes(&packet[..SPARSE_HEADER_SIZE]).unwrap();
            let mut off = h.file_hdr_sz as usize;
            let mut crc = 0u32;
            for _ in 0..h.total_chunks {
                let ch = ChunkHeader::from_bytes(&packet[off..off + CHUNK_HEADER_SIZE]).unwrap();
                let body = &packet[off + CHUNK_HEADER_SIZE..off + ch.total_sz as usize];
                match ch.get_type().unwrap() {
                    ChunkType::Raw => crc = crc32_continue(crc, body),
                    // 设备落盘的是展开后的整块，校验也按展开后逐块累加
                    ChunkType::Fill => {
                        let block: Vec<u8> = body.iter().copied().cycle().take(blk_sz).collect();
                        for _ in 0..ch.chunk_sz {
                            crc = crc32_continue(crc, &block);
                        }
                    }
                    _ => {}
                }
                off += ch.total_sz as usize;
            }
            actual.push(crc);
        }

        println!("分片数 我们={} 官方={}", actual.len(), expected.len());
        assert_eq!(actual.len(), expected.len(), "分片数与官方清单不一致");

        let bad: Vec<usize> = (0..actual.len())
            .filter(|&i| actual[i] != expected[i])
            .collect();
        assert!(
            bad.is_empty(),
            "{} 片 CRC 与官方清单不符，首个错位在第 {} 片（我们=0x{:08x} 官方=0x{:08x}）",
            bad.len(),
            bad[0] + 1,
            actual[bad[0]],
            expected[bad[0]]
        );
    }

    #[test]
    fn test_sparse_writer_preserves_expanded_size() {
        let block_size = 4096u32;
        let test_cases = vec![
            vec![SparseChunk::Raw(vec![0; 4096 * 5])],
            vec![SparseChunk::Fill {
                value: 0xDEAD,
                blocks: 10,
            }],
            vec![SparseChunk::DontCare { blocks: 20 }],
            vec![
                SparseChunk::Raw(vec![0x11; 4096 * 2]),
                SparseChunk::Fill {
                    value: 0,
                    blocks: 5,
                },
                SparseChunk::DontCare { blocks: 3 },
            ],
        ];

        for chunks in test_cases {
            let expected_blocks: u32 = chunks.iter().map(|c| c.output_blocks(block_size)).sum();
            let expected_size = block_size as u64 * expected_blocks as u64;

            let data = create_test_sparse(block_size, &chunks);
            let header = SparseHeader::from_bytes(&data).unwrap();

            assert_eq!(
                header.expanded_size(),
                expected_size,
                "展开大小不匹配: expected {}, got {}",
                expected_size,
                header.expanded_size()
            );
        }
    }

    #[test]
    fn test_sparse_transfer_size_calculation() {
        let block_size = 4096u32;
        let chunks = vec![
            SparseChunk::Raw(vec![0xAB; 4096 * 2]),
            SparseChunk::Fill {
                value: 0,
                blocks: 5,
            },
            SparseChunk::DontCare { blocks: 3 },
        ];

        let expected_transfer = SPARSE_HEADER_SIZE as u64
            + (CHUNK_HEADER_SIZE as u64 + 4096 * 2)
            + (CHUNK_HEADER_SIZE as u64 + 4)
            + CHUNK_HEADER_SIZE as u64;

        let data = create_test_sparse(block_size, &chunks);
        assert_eq!(data.len() as u64, expected_transfer);
    }

    /// 就地解析一片 sparse 包并做设备侧口径的完整性检查：头合法、逐 chunk 几何一致、
    /// 片内块数守恒、无尾部冗余。用来断言「重切分后的每一片都是独立合法的 sparse 镜像」。
    fn assert_fragment_self_contained(packet: &[u8], blk_sz: u32, total_blks: u32) {
        let header = SparseHeader::from_bytes(&packet[..SPARSE_HEADER_SIZE]).unwrap();
        header.validate().unwrap();
        assert_eq!(header.blk_sz, blk_sz);
        assert_eq!(header.total_blks, total_blks, "每片都必须声明整幅块数");

        let mut offset = header.file_hdr_sz as usize;
        let mut blocks = 0u64;
        for i in 0..header.total_chunks {
            let ch = ChunkHeader::from_bytes(&packet[offset..offset + CHUNK_HEADER_SIZE]).unwrap();
            let ty = ch.get_type().unwrap();
            let data_size = ch.total_sz as usize - header.chunk_hdr_sz as usize;
            let ok = match ty {
                ChunkType::Raw => data_size as u64 == ch.chunk_sz as u64 * blk_sz as u64,
                ChunkType::Fill | ChunkType::Crc32 => data_size == 4,
                ChunkType::DontCare => data_size == 0,
            };
            assert!(ok, "chunk {i} ({ty:?}) total_sz 与类型声明的数据长度不符");
            offset += ch.total_sz as usize;
            blocks += ch.chunk_sz as u64;
        }
        assert_eq!(offset, packet.len(), "包尾有冗余或被截断");
        assert_eq!(blocks, total_blks as u64, "片内块数不守恒");
    }

    /// 头部下限校验（AOSP sparse_read 同判据）：file_hdr_sz/chunk_hdr_sz 小于结构体、
    /// blk_sz 非 4 的正整数倍都必须在头部就拒绝，否则后续所有偏移都在错误基础上运算。
    #[test]
    fn header_rejects_undersized_declared_sizes() {
        let base = {
            let mut d = vec![0u8; SPARSE_HEADER_SIZE];
            d[0..4].copy_from_slice(&SPARSE_HEADER_MAGIC.to_le_bytes());
            d[4..6].copy_from_slice(&1u16.to_le_bytes());
            d[8..10].copy_from_slice(&28u16.to_le_bytes());
            d[10..12].copy_from_slice(&12u16.to_le_bytes());
            d[12..16].copy_from_slice(&4096u32.to_le_bytes());
            d
        };
        assert!(SparseHeader::from_bytes(&base).unwrap().validate().is_ok());

        let mut small_file_hdr = base.clone();
        small_file_hdr[8..10].copy_from_slice(&27u16.to_le_bytes());
        assert!(SparseHeader::from_bytes(&small_file_hdr)
            .unwrap()
            .validate()
            .is_err());

        let mut small_chunk_hdr = base.clone();
        small_chunk_hdr[10..12].copy_from_slice(&8u16.to_le_bytes());
        assert!(SparseHeader::from_bytes(&small_chunk_hdr)
            .unwrap()
            .validate()
            .is_err());

        let mut unaligned_blk = base.clone();
        unaligned_blk[12..16].copy_from_slice(&4094u32.to_le_bytes());
        assert!(SparseHeader::from_bytes(&unaligned_blk)
            .unwrap()
            .validate()
            .is_err());
    }

    /// 几何/守恒校验：total_sz 与类型不符、total_sz 装不下头、总块数不守恒、数据区
    /// 截断的损坏镜像，解析路径必须在下发前拒绝——刷进设备远比报错危险。
    #[test]
    fn corrupted_images_are_rejected_before_flash() {
        let block_size = 4096u32;
        let chunks = vec![
            SparseChunk::Raw(vec![0xAB; 4096 * 2]),
            SparseChunk::Fill {
                value: 0x11223344,
                blocks: 3,
            },
            SparseChunk::DontCare { blocks: 2 },
        ];
        let good = create_test_sparse(block_size, &chunks);
        // 布局：header 28B | Raw 头 28..40 + 数据 8192B | Fill 头 8232..8244 + 4B | DC 头 8248..8260
        let fill_hdr = 28 + 12 + 4096 * 2;

        let assert_rejected = |img: &[u8], why: &str| {
            let path = std::env::temp_dir().join(format!("rmf_a5_corrupt_{why}.img"));
            std::fs::write(&path, img).unwrap();
            assert!(
                StreamingResparse::new(&path, 64 * 1024 * 1024).is_err(),
                "重切分扫描未拒绝: {why}"
            );
            let _ = std::fs::remove_file(&path);
        };

        // Raw chunk 声明块数 +1：数据长度与块数不再一致
        let mut raw_bad_blocks = good.clone();
        raw_bad_blocks[32..36].copy_from_slice(&3u32.to_le_bytes());
        assert_rejected(&raw_bad_blocks, "raw_geometry");

        // Fill chunk 的 total_sz 改成裸头：数据 0 字节 ≠ 4
        let mut fill_no_data = good.clone();
        fill_no_data[fill_hdr + 8..fill_hdr + 12].copy_from_slice(&12u32.to_le_bytes());
        assert_rejected(&fill_no_data, "fill_geometry");

        // total_sz 连 chunk 头都装不下：绝不能 saturating 归零原地踏步
        let mut tiny_total = good.clone();
        tiny_total[36..40].copy_from_slice(&4u32.to_le_bytes());
        assert_rejected(&tiny_total, "total_sz_lt_header");

        // 头部声明总块数 +1（实际 7 块）：chunk 表守恒被破坏
        let mut bad_conservation = good.clone();
        bad_conservation[16..20].copy_from_slice(&8u32.to_le_bytes());
        assert_rejected(&bad_conservation, "conservation");

        // 数据区被截断：扫描只读头表、seek 跳过数据区，靠「chunk 表末尾 vs 文件长度」拦下
        let mut truncated = good.clone();
        truncated.truncate(fill_hdr + 12 + 2);
        assert_rejected(&truncated, "truncated");
    }

    /// 扩展头镜像（file_hdr_sz=32 / chunk_hdr_sz=16，AOSP 允许的未知扩展）：扫描与
    /// 重切分都必须按声明的头长度跳过扩展字节，落盘结果与标准头镜像一致。
    #[test]
    fn extended_headers_are_honored_by_scan_and_resparse() {
        const FILE_HDR: usize = 32;
        const CHUNK_HDR: usize = 16;
        let bs = 512usize;
        let blk_sz = bs as u32;
        let raw_a: Vec<u8> = (0..bs * 3).map(|i| (i % 199) as u8).collect();
        let raw_b: Vec<u8> = (0..bs * 2).map(|i| ((i * 7 + 31) % 211) as u8).collect();
        let total_blks = 3u32 + 4 + 2 + 5;

        let chunk_specs: Vec<(u16, u32, Vec<u8>)> = vec![
            (0xCAC1, 3, raw_a.clone()),
            (0xCAC2, 4, 0xA5A5_5A5Au32.to_le_bytes().to_vec()),
            (0xCAC1, 2, raw_b.clone()),
            (0xCAC3, 5, Vec::new()),
        ];

        let mut img = Vec::new();
        img.extend_from_slice(&SPARSE_HEADER_MAGIC.to_le_bytes());
        img.extend_from_slice(&1u16.to_le_bytes());
        img.extend_from_slice(&0u16.to_le_bytes());
        img.extend_from_slice(&(FILE_HDR as u16).to_le_bytes());
        img.extend_from_slice(&(CHUNK_HDR as u16).to_le_bytes());
        img.extend_from_slice(&blk_sz.to_le_bytes());
        img.extend_from_slice(&total_blks.to_le_bytes());
        img.extend_from_slice(&(chunk_specs.len() as u32).to_le_bytes());
        img.extend_from_slice(&0u32.to_le_bytes());
        img.extend_from_slice(&[0xEE; FILE_HDR - SPARSE_HEADER_SIZE]);

        for (ty, blocks, data) in &chunk_specs {
            img.extend_from_slice(&ty.to_le_bytes());
            img.extend_from_slice(&0u16.to_le_bytes());
            img.extend_from_slice(&blocks.to_le_bytes());
            img.extend_from_slice(&((CHUNK_HDR + data.len()) as u32).to_le_bytes());
            img.extend_from_slice(&[0xEE; CHUNK_HDR - CHUNK_HEADER_SIZE]);
            img.extend_from_slice(data);
        }

        let path = std::env::temp_dir().join("rmf_a5_ext_hdr.img");
        std::fs::write(&path, &img).unwrap();

        // 扫描：数据区必须正好指到本体（跳过 0xEE 扩展字节）
        let scan = StreamingResparse::new(&path, 64 * 1024 * 1024).unwrap();
        let metas = &scan.chunk_metas;
        assert_eq!(metas.len(), 4);
        let data_at = |m: &ChunkMeta| &img[m.file_offset as usize..][..m.data_size as usize];
        assert_eq!(data_at(&metas[0]), &raw_a[..]);
        assert_eq!(data_at(&metas[2]), &raw_b[..]);

        // 重切分：扩展头镜像分片落盘必须与「同内容标准头镜像整包下发」逐字节一致
        let std_chunks = vec![
            SparseChunk::Raw(raw_a.clone()),
            SparseChunk::Fill {
                value: 0xA5A5_5A5A,
                blocks: 4,
            },
            SparseChunk::Raw(raw_b.clone()),
            SparseChunk::DontCare { blocks: 5 },
        ];
        let std_img = create_test_sparse(blk_sz, &std_chunks);
        let mut expected = vec![0u8; total_blks as usize * bs];
        apply_sparse_to_disk(&std_img, &mut expected, bs);

        let max_download = 2048u64;
        let mut resparse = StreamingResparse::new(&path, max_download).unwrap();
        assert!(resparse.total_fragments() > 1, "上限太大没触发分片");
        let mut actual = vec![0u8; total_blks as usize * bs];
        while let Some((frag, _, _)) = resparse.next_fragment().unwrap() {
            assert!(frag.len() as u64 <= max_download);
            assert_fragment_self_contained(&frag, blk_sz, total_blks);
            apply_sparse_to_disk(&frag, &mut actual, bs);
        }
        assert_eq!(actual, expected, "扩展头镜像分片落盘与标准头整包不一致");

        let _ = std::fs::remove_file(&path);
    }

    /// 小块设备（blk_sz=512）+ 首尾 DontCare/Fill 边界 + 极小 max-download：每片必须
    /// 独立合法、片内块数守恒、不超限，且逐片落盘与整包下发逐字节一致。
    #[test]
    fn small_block_size_with_fill_dontcare_boundaries_resparse() {
        let blk_sz = 512u32;
        let bs = blk_sz as usize;

        let raw_a: Vec<u8> = (0..bs * 5).map(|i| (i % 233) as u8).collect();
        let raw_b: Vec<u8> = (0..bs * 7).map(|i| ((i * 11 + 3) % 239) as u8).collect();

        // 首尾都是「不落盘」类 chunk、中间 Fill/DontCare 交错，专打分片边界补位逻辑
        let chunks = vec![
            SparseChunk::DontCare { blocks: 3 },
            SparseChunk::Fill {
                value: 0x0F0F_F0F0,
                blocks: 4,
            },
            SparseChunk::Raw(raw_a),
            SparseChunk::DontCare { blocks: 2 },
            SparseChunk::Raw(raw_b),
            SparseChunk::Fill {
                value: 0xDEAD_BEEF,
                blocks: 6,
            },
            SparseChunk::DontCare { blocks: 5 },
        ];
        let total_blks: u32 = chunks.iter().map(|c| c.output_blocks(blk_sz)).sum();
        let image = create_test_sparse(blk_sz, &chunks);

        let path = std::env::temp_dir().join("rmf_a5_small_blk.img");
        std::fs::write(&path, &image).unwrap();

        let mut expected = vec![0u8; total_blks as usize * bs];
        apply_sparse_to_disk(&image, &mut expected, bs);

        let max_download = 3 * 1024u64;
        let mut resparse = StreamingResparse::new(&path, max_download).unwrap();
        assert!(resparse.total_fragments() > 2, "上限没逼出足够分片");

        let mut actual = vec![0u8; total_blks as usize * bs];
        while let Some((frag, _, _)) = resparse.next_fragment().unwrap() {
            assert!(
                frag.len() as u64 <= max_download,
                "分片 {} 字节超出 max-download-size {max_download}",
                frag.len()
            );
            assert_fragment_self_contained(&frag, blk_sz, total_blks);
            apply_sparse_to_disk(&frag, &mut actual, bs);
        }
        assert_eq!(actual, expected, "小块镜像分片落盘与整包不一致");

        let _ = std::fs::remove_file(&path);
    }

    /// 起始块累计越过 u32 的损坏镜像：u64 游标必须显式报错，而不是 debug 下 panic、
    /// release 下静默回绕成「看似守恒」的假象。
    #[test]
    fn resparse_rejects_block_cursor_overflow() {
        let mut img = Vec::new();
        img.extend_from_slice(&SPARSE_HEADER_MAGIC.to_le_bytes());
        img.extend_from_slice(&1u16.to_le_bytes());
        img.extend_from_slice(&0u16.to_le_bytes());
        img.extend_from_slice(&28u16.to_le_bytes());
        img.extend_from_slice(&12u16.to_le_bytes());
        img.extend_from_slice(&4096u32.to_le_bytes());
        img.extend_from_slice(&u32::MAX.to_le_bytes());
        img.extend_from_slice(&3u32.to_le_bytes());
        img.extend_from_slice(&0u32.to_le_bytes());
        for blocks in [u32::MAX, 1u32, 1u32] {
            img.extend_from_slice(&0xCAC3u16.to_le_bytes());
            img.extend_from_slice(&0u16.to_le_bytes());
            img.extend_from_slice(&blocks.to_le_bytes());
            img.extend_from_slice(&12u32.to_le_bytes());
        }
        let path = std::env::temp_dir().join("rmf_a5_cursor_overflow.img");
        std::fs::write(&path, &img).unwrap();

        let err = StreamingResparse::new(&path, 64 * 1024 * 1024)
            .err()
            .expect("必须拒绝块游标越过 u32 的镜像");
        assert!(
            err.to_string().contains("u32"),
            "错误应指明块游标越界: {err}"
        );

        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    fn arb_sparse_chunk(block_size: u32) -> impl Strategy<Value = SparseChunk> {
        prop_oneof![
            (1u32..=10).prop_map(move |blocks| {
                SparseChunk::Raw(vec![0xAB; (block_size * blocks) as usize])
            }),
            (any::<u32>(), 1u32..=20)
                .prop_map(|(value, blocks)| { SparseChunk::Fill { value, blocks } }),
            (1u32..=50).prop_map(|blocks| { SparseChunk::DontCare { blocks } }),
        ]
    }

    proptest! {


        #[test]
        fn prop_resparse_preserves_expanded_size(
            chunks in prop::collection::vec(arb_sparse_chunk(4096), 1..5)
        ) {
            let block_size = 4096u32;
            let total_blocks: u32 = chunks.iter().map(|c| c.output_blocks(block_size)).sum();

            if total_blocks == 0 {
                return Ok(());
            }

            let mut writer = SparseWriter::new(block_size);
            for chunk in &chunks {
                writer.add_chunk(chunk.clone());
            }
            let data = writer.build();
            let header = SparseHeader::from_bytes(&data).unwrap();
            prop_assert!(header.validate().is_ok());
            let expected_expanded = block_size as u64 * total_blocks as u64;
            prop_assert_eq!(header.expanded_size(), expected_expanded);
        }
        #[test]
        fn prop_sparse_writer_produces_valid_header(
            block_size in prop::sample::select(vec![512u32, 1024, 2048, 4096, 8192]),
            num_blocks in 1u32..100
        ) {
            let mut writer = SparseWriter::new(block_size);
            writer.add_chunk(SparseChunk::DontCare { blocks: num_blocks });

            let data = writer.build();
            let header = SparseHeader::from_bytes(&data).unwrap();

            prop_assert!(header.validate().is_ok());
            prop_assert_eq!(header.magic, SPARSE_HEADER_MAGIC);
            prop_assert_eq!(header.major_version, 1);
            prop_assert_eq!(header.blk_sz, block_size);
            prop_assert_eq!(header.total_blks, num_blocks);
        }
        #[test]
        fn prop_chunk_transfer_size_correct(
            raw_size in 1usize..10000,
            fill_blocks in 1u32..100,
            dont_care_blocks in 1u32..100
        ) {
            let raw = SparseChunk::Raw(vec![0; raw_size]);
            prop_assert_eq!(raw.transfer_size(), CHUNK_HEADER_SIZE as u64 + raw_size as u64);
            let fill = SparseChunk::Fill { value: 0, blocks: fill_blocks };
            prop_assert_eq!(fill.transfer_size(), CHUNK_HEADER_SIZE as u64 + 4);
            let dont_care = SparseChunk::DontCare { blocks: dont_care_blocks };
            prop_assert_eq!(dont_care.transfer_size(), CHUNK_HEADER_SIZE as u64);
        }
    }
}
