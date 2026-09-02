//! Append side of the raw vault.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use ulpf_core::RawRef;

use crate::error::{Result, VaultError};
use crate::format::*;

/// Tuning for a vault.
#[derive(Debug, Clone, Copy)]
pub struct VaultConfig {
    /// Uncompressed bytes buffered before a block is compressed and written.
    ///
    /// Larger blocks compress better but cost more to decompress for a single
    /// record retrieval. A megabyte keeps a point lookup at roughly one disk
    /// read plus one decompress, while still giving zstd enough context to find
    /// the heavy repetition in device logs.
    pub block_size: usize,
    /// Uncompressed bytes per segment before rotating to a new file.
    pub segment_size: u64,
    /// zstd compression level.
    pub level: i32,
    /// Whether to fsync after every block.
    ///
    /// Off by default: the block is already durable against process death, and
    /// fsync-per-block turns a sequential archive into a latency problem. Turn
    /// it on where the deployment must survive host power loss without losing
    /// the tail block.
    pub sync_on_flush: bool,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            block_size: 1 << 20,     // 1 MiB
            segment_size: 256 << 20, // 256 MiB uncompressed
            level: 3,
            sync_on_flush: false,
        }
    }
}

/// Appends raw events to a vault, returning a durable pointer for each.
pub struct VaultWriter {
    dir: PathBuf,
    config: VaultConfig,
    segment: u64,
    file: BufWriter<File>,
    /// Offset in the uncompressed stream where the current block starts.
    block_start: u64,
    /// Offset in the uncompressed stream where the next record will go.
    cursor: u64,
    /// Uncompressed bytes buffered for the current block.
    buffer: Vec<u8>,
    /// Byte offset in the file where the next block header will be written.
    file_cursor: u64,
    index: Vec<BlockLoc>,
}

impl VaultWriter {
    /// Open a vault directory, starting a fresh segment.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        Self::open_with(dir, VaultConfig::default())
    }

    pub fn open_with(dir: impl AsRef<Path>, config: VaultConfig) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let segment = next_segment_number(&dir)?;
        let (file, file_cursor) = create_segment(&dir, segment)?;

        Ok(Self {
            dir,
            config,
            segment,
            file: BufWriter::new(file),
            block_start: 0,
            cursor: 0,
            buffer: Vec::with_capacity(config.block_size + 4096),
            file_cursor,
            index: Vec::new(),
        })
    }

    pub fn segment(&self) -> u64 {
        self.segment
    }

    /// Append one raw event. The returned reference is stable for the life of
    /// the vault, and is what a normalized event carries to satisfy (d).
    ///
    /// The record is durable once its containing block is flushed; call
    /// [`VaultWriter::flush`] to force that at a batch boundary.
    pub fn append(&mut self, payload: &[u8]) -> Result<RawRef> {
        let len =
            u32::try_from(payload.len()).map_err(|_| VaultError::RecordTooLarge(payload.len()))?;

        let offset = self.cursor;
        self.buffer.extend_from_slice(&len.to_le_bytes());
        self.buffer.extend_from_slice(payload);
        self.cursor += RECORD_HEADER_LEN + payload.len() as u64;

        let raw_ref = RawRef::new(self.segment, offset, len);

        if self.buffer.len() >= self.config.block_size {
            self.flush_block()?;
        }
        if self.cursor >= self.config.segment_size {
            self.rotate()?;
        }
        Ok(raw_ref)
    }

    /// Flush the pending block so everything appended so far is retrievable.
    pub fn flush(&mut self) -> Result<()> {
        self.flush_block()?;
        self.file.flush()?;
        Ok(())
    }

    fn flush_block(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let uncompressed_len = u32::try_from(self.buffer.len())
            .map_err(|_| VaultError::RecordTooLarge(self.buffer.len()))?;
        let crc = crc32(&self.buffer);
        let compressed = zstd::encode_all(self.buffer.as_slice(), self.config.level)?;
        let compressed_len = u32::try_from(compressed.len())
            .map_err(|_| VaultError::RecordTooLarge(compressed.len()))?;

        // Header first, so a scanning reader can always find its way forward
        // even when the index is missing.
        self.file.write_all(&BLOCK_MAGIC.to_le_bytes())?;
        self.file.write_all(&self.block_start.to_le_bytes())?;
        self.file.write_all(&uncompressed_len.to_le_bytes())?;
        self.file.write_all(&compressed_len.to_le_bytes())?;
        self.file.write_all(&crc.to_le_bytes())?;
        self.file.write_all(&compressed)?;

        self.index.push(BlockLoc {
            uncompressed_start: self.block_start,
            uncompressed_len,
            file_offset: self.file_cursor,
            compressed_len,
        });

        self.file_cursor += BLOCK_HEADER_LEN + compressed.len() as u64;
        self.block_start = self.cursor;
        self.buffer.clear();

        if self.config.sync_on_flush {
            self.file.flush()?;
            self.file.get_ref().sync_data()?;
        }
        Ok(())
    }

    /// Write the index and footer, then start a new segment.
    fn rotate(&mut self) -> Result<()> {
        self.finish_segment()?;
        self.segment += 1;
        let (file, file_cursor) = create_segment(&self.dir, self.segment)?;
        self.file = BufWriter::new(file);
        self.file_cursor = file_cursor;
        self.block_start = 0;
        self.cursor = 0;
        self.index.clear();
        Ok(())
    }

    fn finish_segment(&mut self) -> Result<()> {
        self.flush_block()?;

        let index_offset = self.file_cursor;
        for block in &self.index {
            self.file
                .write_all(&block.uncompressed_start.to_le_bytes())?;
            self.file.write_all(&block.uncompressed_len.to_le_bytes())?;
            self.file.write_all(&block.file_offset.to_le_bytes())?;
            self.file.write_all(&block.compressed_len.to_le_bytes())?;
        }
        let block_count = u32::try_from(self.index.len())
            .map_err(|_| VaultError::RecordTooLarge(self.index.len()))?;
        self.file.write_all(&index_offset.to_le_bytes())?;
        self.file.write_all(&block_count.to_le_bytes())?;
        self.file.write_all(FOOTER_MAGIC)?;
        self.file.flush()?;
        self.file.get_ref().sync_data()?;
        Ok(())
    }

    /// Seal the current segment. Always call this on a clean shutdown; without
    /// it the segment is still readable, but only via index recovery.
    pub fn close(mut self) -> Result<()> {
        self.finish_segment()
    }
}

fn segment_path(dir: &Path, segment: u64) -> PathBuf {
    dir.join(format!("{segment:016x}.vlt"))
}

fn create_segment(dir: &Path, segment: u64) -> Result<(File, u64)> {
    let path = segment_path(dir, segment);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .map_err(|e| VaultError::Segment {
            path: path.clone(),
            source: e,
        })?;
    file.write_all(SEGMENT_MAGIC)?;
    file.write_all(&FORMAT_VERSION.to_le_bytes())?;
    file.write_all(&0u16.to_le_bytes())?; // flags, reserved
    Ok((file, SEGMENT_HEADER_LEN))
}

/// Scan the directory for existing segments and return the next free number.
fn next_segment_number(dir: &Path) -> Result<u64> {
    let mut max: Option<u64> = None;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(stem) = name.strip_suffix(".vlt") else {
            continue;
        };
        if let Ok(n) = u64::from_str_radix(stem, 16) {
            max = Some(max.map_or(n, |m: u64| m.max(n)));
        }
    }
    Ok(max.map_or(0, |m| m + 1))
}
