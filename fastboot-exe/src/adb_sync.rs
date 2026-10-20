//! adb sync（push/pull）协议的字节流编解码，与承载它的 transport 无关。
//!
//! sync 跑在一条 stream 上，是纯字节流：请求、DATA 块、DONE 可以任意跨 A_WRTE 边界，也可以
//! 多块共用一个 A_WRTE（AOSP server 就是把 socket 流按 maxdata 打包成 apacket 发的）。
//! transport 只负责把 [`PushStream`] 读出的字节按协商 maxdata 切包、把收到的载荷原样喂给
//! [`PullSink`]。

use std::io::{self, Read, Write};

/// AOSP `SYNC_DATA_MAX`：单个 DATA 块的数据上限（v1/v2 相同）。
pub(crate) const SYNC_DATA_MAX: usize = 64 * 1024;

const FEATURE_SENDRECV_V2: &str = "sendrecv_v2";
const FEATURE_SENDRECV_V2_ZSTD: &str = "sendrecv_v2_zstd";
/// AOSP `kSyncFlagZstd`。
const SYNC_FLAG_ZSTD: u32 = 4;
/// 压缩只为省线上字节：取最快档，USB3 下也不让 CPU 成为瓶颈。
const ZSTD_LEVEL: i32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyncMode {
    V1,
    /// SND2/RCV2 + zstd 流压缩（设备须同时通告 `sendrecv_v2` 与 `sendrecv_v2_zstd`，Android 11+）。
    V2Zstd,
}

impl SyncMode {
    pub(crate) fn for_device(features: &[String]) -> Self {
        let has = |f: &str| features.iter().any(|d| d == f);
        if has(FEATURE_SENDRECV_V2) && has(FEATURE_SENDRECV_V2_ZSTD) {
            SyncMode::V2Zstd
        } else {
            SyncMode::V1
        }
    }
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn request(id: &[u8; 4], path: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + path.len() + 12);
    out.extend_from_slice(id);
    put_u32(&mut out, path.len() as u32);
    out.extend_from_slice(path.as_bytes());
    out
}

/// 读满 `buf` 或读到 EOF，返回读到的字节数。
pub(crate) fn read_full<R: Read + ?Sized>(src: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match src.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// pull 请求：v1 `RECV`+路径；v2 `RCV2`+路径，后跟 `RCV2`+flags 的 setup。
pub(crate) fn recv_request(remote_path: &str, mode: SyncMode) -> Vec<u8> {
    match mode {
        SyncMode::V1 => request(b"RECV", remote_path),
        SyncMode::V2Zstd => {
            let mut out = request(b"RCV2", remote_path);
            out.extend_from_slice(b"RCV2");
            put_u32(&mut out, SYNC_FLAG_ZSTD);
            out
        }
    }
}

/// push 的完整 sync 字节流：请求 → DATA 块（v2 为 zstd 压缩流切块）→ DONE。
pub(crate) struct PushStream<R: Read> {
    src: R,
    mode: SyncMode,
    mtime: u32,
    staged: Vec<u8>,
    staged_pos: usize,
    finished: bool,
    src_eof: bool,
    file_bytes: u64,
    input: Vec<u8>,
    encoder: Option<zstd::stream::write::Encoder<'static, Vec<u8>>>,
    /// 压缩输出里已经切进 DATA 块的字节数。
    framed: usize,
}

impl<R: Read> PushStream<R> {
    pub(crate) fn new(
        src: R,
        remote_path: &str,
        file_mode: u32,
        mtime: u32,
        mode: SyncMode,
    ) -> io::Result<Self> {
        let (staged, encoder) = match mode {
            SyncMode::V1 => (
                request(b"SEND", &format!("{},{}", remote_path, file_mode)),
                None,
            ),
            SyncMode::V2Zstd => {
                let mut head = request(b"SND2", remote_path);
                head.extend_from_slice(b"SND2");
                put_u32(&mut head, file_mode);
                put_u32(&mut head, SYNC_FLAG_ZSTD);
                let encoder = zstd::stream::write::Encoder::new(Vec::new(), ZSTD_LEVEL)?;
                (head, Some(encoder))
            }
        };
        Ok(Self {
            src,
            mode,
            mtime,
            staged,
            staged_pos: 0,
            finished: false,
            src_eof: false,
            file_bytes: 0,
            input: vec![0u8; SYNC_DATA_MAX],
            encoder,
            framed: 0,
        })
    }

    /// 已从源读出的字节数（进度按源文件字节报，与是否压缩无关）。
    pub(crate) fn file_bytes(&self) -> u64 {
        self.file_bytes
    }

    fn stage_next(&mut self) -> io::Result<()> {
        self.staged.clear();
        self.staged_pos = 0;
        match self.mode {
            SyncMode::V1 => {
                let n = read_full(&mut self.src, &mut self.input)?;
                if n == 0 {
                    self.stage_done();
                } else {
                    self.file_bytes += n as u64;
                    self.staged.extend_from_slice(b"DATA");
                    put_u32(&mut self.staged, n as u32);
                    self.staged.extend_from_slice(&self.input[..n]);
                }
            }
            SyncMode::V2Zstd => self.stage_compressed()?,
        }
        Ok(())
    }

    fn stage_compressed(&mut self) -> io::Result<()> {
        let Some(encoder) = self.encoder.as_mut() else {
            self.stage_done();
            return Ok(());
        };
        // 压缩器按内部块攒输出：喂到至少凑满一个 DATA 块或源读完为止。
        while !self.src_eof && encoder.get_ref().len() - self.framed < SYNC_DATA_MAX {
            let n = read_full(&mut self.src, &mut self.input)?;
            if n == 0 {
                encoder.do_finish()?;
                self.src_eof = true;
            } else {
                self.file_bytes += n as u64;
                encoder.write_all(&self.input[..n])?;
            }
        }
        let out = encoder.get_mut();
        let available = out.len() - self.framed;
        if available == 0 {
            self.stage_done();
            return Ok(());
        }
        let take = available.min(SYNC_DATA_MAX);
        self.staged.extend_from_slice(b"DATA");
        put_u32(&mut self.staged, take as u32);
        self.staged
            .extend_from_slice(&out[self.framed..self.framed + take]);
        self.framed += take;
        if self.framed == out.len() {
            out.clear();
            self.framed = 0;
        }
        Ok(())
    }

    fn stage_done(&mut self) {
        self.staged.extend_from_slice(b"DONE");
        put_u32(&mut self.staged, self.mtime);
        self.finished = true;
    }
}

impl<R: Read> Read for PushStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.staged_pos < self.staged.len() {
                let n = (self.staged.len() - self.staged_pos).min(buf.len());
                buf[..n].copy_from_slice(&self.staged[self.staged_pos..self.staged_pos + n]);
                self.staged_pos += n;
                return Ok(n);
            }
            if self.finished {
                return Ok(0);
            }
            self.stage_next()?;
        }
    }
}

/// push 发完 DONE 后设备回的终态：`OKAY` 或 `FAIL`+原因。字节还不够时返回 `None`。
pub(crate) fn parse_status(buf: &[u8]) -> Option<Result<(), String>> {
    if buf.len() < 8 {
        return None;
    }
    let len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    match &buf[..4] {
        b"OKAY" => Some(Ok(())),
        b"FAIL" => {
            if buf.len() < 8 + len {
                return None;
            }
            Some(Err(String::from_utf8_lossy(&buf[8..8 + len]).into_owned()))
        }
        other => Some(Err(format!(
            "未知的 sync 响应 {:?}",
            String::from_utf8_lossy(other)
        ))),
    }
}

struct CountingWriter<W: Write> {
    inner: W,
    written: u64,
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

enum PullOut<W: Write> {
    Raw(CountingWriter<W>),
    Zstd(zstd::stream::write::Decoder<'static, CountingWriter<W>>),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PullProgress {
    More,
    Done,
}

/// pull 收到的 sync 字节流：DATA 写入目标（v2 先解压），DONE 结束，FAIL 报错。
pub(crate) struct PullSink<W: Write> {
    out: PullOut<W>,
    pending: Vec<u8>,
    done: bool,
}

impl<W: Write> PullSink<W> {
    pub(crate) fn new(out: W, mode: SyncMode) -> io::Result<Self> {
        let counting = CountingWriter {
            inner: out,
            written: 0,
        };
        let out = match mode {
            SyncMode::V1 => PullOut::Raw(counting),
            SyncMode::V2Zstd => PullOut::Zstd(zstd::stream::write::Decoder::new(counting)?),
        };
        Ok(Self {
            out,
            pending: Vec::new(),
            done: false,
        })
    }

    /// 已写入目标的字节数（v2 为解压后字节）。
    pub(crate) fn bytes_written(&self) -> u64 {
        match &self.out {
            PullOut::Raw(w) => w.written,
            PullOut::Zstd(d) => d.get_ref().written,
        }
    }

    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Result<PullProgress, String> {
        if self.done {
            return Ok(PullProgress::Done);
        }
        self.pending.extend_from_slice(bytes);
        let mut pos = 0;
        let result = loop {
            let rest = self.pending.len() - pos;
            if rest < 8 {
                break Ok(PullProgress::More);
            }
            let head = &self.pending[pos..pos + 8];
            let id = [head[0], head[1], head[2], head[3]];
            let len = u32::from_le_bytes([head[4], head[5], head[6], head[7]]) as usize;
            match &id {
                b"DATA" => {
                    if len > SYNC_DATA_MAX {
                        break Err(format!("协议错乱：sync DATA 块 {} 字节超过上限", len));
                    }
                    if rest < 8 + len {
                        break Ok(PullProgress::More);
                    }
                    let data = &self.pending[pos + 8..pos + 8 + len];
                    let written = match &mut self.out {
                        PullOut::Raw(w) => w.write_all(data),
                        PullOut::Zstd(d) => d.write_all(data),
                    };
                    if let Err(e) = written {
                        break Err(format!("写入本地文件失败: {}", e));
                    }
                    pos += 8 + len;
                }
                b"DONE" => {
                    pos += 8;
                    let flushed = match &mut self.out {
                        PullOut::Raw(w) => w.flush(),
                        PullOut::Zstd(d) => d.flush(),
                    };
                    if let Err(e) = flushed {
                        break Err(format!("写入本地文件失败: {}", e));
                    }
                    self.done = true;
                    break Ok(PullProgress::Done);
                }
                b"FAIL" => {
                    if rest < 8 + len {
                        break Ok(PullProgress::More);
                    }
                    let reason =
                        String::from_utf8_lossy(&self.pending[pos + 8..pos + 8 + len]).into_owned();
                    break Err(format!("手机拒绝了拉取: {}", reason));
                }
                other => {
                    break Err(format!(
                        "协议错乱：未知的 SYNC 块标记 {:?}",
                        String::from_utf8_lossy(other)
                    ))
                }
            }
        };
        self.pending.drain(..pos);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ParsedPush {
        head: Vec<u8>,
        blocks: Vec<Vec<u8>>,
        mtime: u32,
    }

    /// 按 sync 格式拆开 push 字节流：请求头（到第一个 DATA/DONE 之前）、各 DATA 块、DONE 的 mtime。
    fn parse_push(stream: &[u8], head_len: usize) -> ParsedPush {
        let head = stream[..head_len].to_vec();
        let mut pos = head_len;
        let mut blocks = Vec::new();
        loop {
            let id = &stream[pos..pos + 4];
            let len = u32::from_le_bytes(stream[pos + 4..pos + 8].try_into().unwrap());
            pos += 8;
            if id == b"DONE" {
                assert_eq!(pos, stream.len(), "DONE 之后不该再有字节");
                return ParsedPush {
                    head,
                    blocks,
                    mtime: len,
                };
            }
            assert_eq!(id, b"DATA");
            let len = len as usize;
            assert!(len > 0 && len <= SYNC_DATA_MAX, "DATA 块长度越界: {}", len);
            blocks.push(stream[pos..pos + len].to_vec());
            pos += len;
        }
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 % 251) as u8).collect()
    }

    fn drain(mut stream: impl Read) -> Vec<u8> {
        let mut out = Vec::new();
        stream.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn v1_push_stream_frames_file_into_data_blocks() {
        for len in [0usize, 1, 65535, 65536, 65537, 300_000] {
            let data = pattern(len);
            let stream = drain(
                PushStream::new(&data[..], "/sdcard/a.bin", 33206, 1234, SyncMode::V1).unwrap(),
            );
            let head = request(b"SEND", "/sdcard/a.bin,33206");
            let parsed = parse_push(&stream, head.len());
            assert_eq!(parsed.head, head);
            assert_eq!(parsed.mtime, 1234);
            assert_eq!(parsed.blocks.concat(), data, "len={len}");
        }
    }

    #[test]
    fn v2_push_stream_is_a_zstd_frame_split_into_data_blocks() {
        let mut data = pattern(200_000);
        data.extend(std::iter::repeat_n(0u8, 3 * 1024 * 1024));
        let mut push =
            PushStream::new(&data[..], "/sdcard/b.img", 33206, 7, SyncMode::V2Zstd).unwrap();
        let stream = drain(&mut push);
        assert_eq!(push.file_bytes(), data.len() as u64);

        let mut head = request(b"SND2", "/sdcard/b.img");
        head.extend_from_slice(b"SND2");
        head.extend_from_slice(&33206u32.to_le_bytes());
        head.extend_from_slice(&SYNC_FLAG_ZSTD.to_le_bytes());
        let parsed = parse_push(&stream, head.len());
        assert_eq!(parsed.head, head);
        assert_eq!(parsed.mtime, 7);
        let compressed = parsed.blocks.concat();
        assert!(
            compressed.len() < data.len() / 4,
            "零块多的数据应被明显压缩"
        );
        assert_eq!(zstd::stream::decode_all(&compressed[..]).unwrap(), data);
    }

    /// 按 maxdata 读包时每包都装满（最后一包除外）：多个 sync 块共用一个 A_WRTE。
    #[test]
    fn push_stream_packs_many_blocks_per_packet() {
        let data = pattern(5 * 1024 * 1024 + 123);
        let whole = drain(PushStream::new(&data[..], "/x", 33206, 0, SyncMode::V1).unwrap());
        let mut push = PushStream::new(&data[..], "/x", 33206, 0, SyncMode::V1).unwrap();
        let max = 1024 * 1024;
        let mut packet = vec![0u8; max];
        let mut packets = Vec::new();
        loop {
            let n = read_full(&mut push, &mut packet).unwrap();
            if n == 0 {
                break;
            }
            packets.push(packet[..n].to_vec());
        }
        let (last, full) = packets.split_last().unwrap();
        assert!(full.iter().all(|p| p.len() == max));
        assert!(!last.is_empty() && last.len() <= max);
        assert_eq!(packets.concat(), whole);
    }

    fn sync_stream(blocks: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for b in blocks {
            out.extend_from_slice(b"DATA");
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(b);
        }
        out.extend_from_slice(b"DONE");
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    fn feed_in_pieces<W: Write>(
        sink: &mut PullSink<W>,
        stream: &[u8],
        piece: usize,
    ) -> PullProgress {
        let mut last = PullProgress::More;
        for chunk in stream.chunks(piece) {
            last = sink.feed(chunk).unwrap();
        }
        last
    }

    #[test]
    fn v1_pull_sink_reassembles_blocks_split_anywhere() {
        let data = pattern(150_000);
        let blocks: Vec<&[u8]> = data.chunks(SYNC_DATA_MAX).collect();
        let stream = sync_stream(&blocks);
        for piece in [1usize, 7, 1000, 65544, 1 << 20] {
            let mut out = Vec::new();
            let mut sink = PullSink::new(&mut out, SyncMode::V1).unwrap();
            assert_eq!(
                feed_in_pieces(&mut sink, &stream, piece),
                PullProgress::Done
            );
            assert_eq!(sink.bytes_written(), data.len() as u64);
            drop(sink);
            assert_eq!(out, data, "piece={piece}");
        }
    }

    #[test]
    fn v2_pull_sink_decompresses_zstd_stream() {
        let mut data = pattern(70_000);
        data.extend(std::iter::repeat_n(0u8, 2 * 1024 * 1024));
        let compressed = zstd::stream::encode_all(&data[..], 3).unwrap();
        let blocks: Vec<&[u8]> = compressed.chunks(SYNC_DATA_MAX).collect();
        let stream = sync_stream(&blocks);
        let mut out = Vec::new();
        let mut sink = PullSink::new(&mut out, SyncMode::V2Zstd).unwrap();
        assert_eq!(feed_in_pieces(&mut sink, &stream, 4096), PullProgress::Done);
        assert_eq!(sink.bytes_written(), data.len() as u64);
        drop(sink);
        assert_eq!(out, data);
    }

    #[test]
    fn pull_sink_reports_device_failure_and_protocol_errors() {
        let mut fail = b"FAIL".to_vec();
        fail.extend_from_slice(&(9u32).to_le_bytes());
        fail.extend_from_slice(b"no access");
        let mut sink = PullSink::new(Vec::new(), SyncMode::V1).unwrap();
        assert_eq!(sink.feed(&fail[..10]).unwrap(), PullProgress::More);
        let err = sink.feed(&fail[10..]).unwrap_err();
        assert!(err.contains("no access"), "{err}");

        let mut sink = PullSink::new(Vec::new(), SyncMode::V1).unwrap();
        assert!(sink.feed(b"WHAT\0\0\0\0").unwrap_err().contains("WHAT"));

        let mut huge = b"DATA".to_vec();
        huge.extend_from_slice(&((SYNC_DATA_MAX + 1) as u32).to_le_bytes());
        let mut sink = PullSink::new(Vec::new(), SyncMode::V1).unwrap();
        assert!(sink.feed(&huge).is_err());
    }

    #[test]
    fn status_parsing() {
        assert_eq!(parse_status(b"OKA"), None);
        assert_eq!(parse_status(b"OKAY\0\0\0\0"), Some(Ok(())));
        let mut fail = b"FAIL".to_vec();
        fail.extend_from_slice(&(4u32).to_le_bytes());
        assert_eq!(parse_status(&fail), None, "原因还没收全");
        fail.extend_from_slice(b"full");
        assert_eq!(parse_status(&fail), Some(Err("full".to_string())));
        assert!(matches!(parse_status(b"ZZZZ\0\0\0\0"), Some(Err(_))));
    }

    #[test]
    fn recv_request_formats() {
        assert_eq!(recv_request("/a", SyncMode::V1), request(b"RECV", "/a"));
        let mut v2 = request(b"RCV2", "/a");
        v2.extend_from_slice(b"RCV2");
        v2.extend_from_slice(&SYNC_FLAG_ZSTD.to_le_bytes());
        assert_eq!(recv_request("/a", SyncMode::V2Zstd), v2);
    }

    #[test]
    fn mode_needs_both_v2_and_zstd_features() {
        let f = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(SyncMode::for_device(&f(&["shell_v2"])), SyncMode::V1);
        assert_eq!(SyncMode::for_device(&f(&["sendrecv_v2"])), SyncMode::V1);
        assert_eq!(
            SyncMode::for_device(&f(&["sendrecv_v2", "sendrecv_v2_zstd"])),
            SyncMode::V2Zstd
        );
    }
}
