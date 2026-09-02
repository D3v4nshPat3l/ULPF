//! Read side of the raw vault: retrieve an original event from a [`RawRef`].

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use ulpf_core::RawRef;

use crate::error::{Result, VaultError};
use crate::format::*;

/// Reads original event bytes back out of a vault.
///
/// Retrieval is one seek, one block read, one decompress, one slice — constant
/// work regardless of how many events the vault holds. That is what turns
/// requirement (d) from "we could search for it" into "click the event, get the
/// original".
pub struct VaultReader {
    dir: PathBuf,
    /// Block indexes, loaded lazily per segment and then cached.
    segments: HashMap<u64, Vec<BlockLoc>>,
    /// Most recently decompressed block, keyed by (segment, block start).
    cache: Option<((u64, u64), Vec<u8>)>,
}

impl VaultReader {
    pub fn open(dir: impl AsRef<Path>) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
            segments: HashMap::new(),
            cache: None,
        }
    }

    /// Retrieve the exact bytes recorded for `raw_ref`.
    pub fn get(&mut self, raw_ref: RawRef) -> Result<Vec<u8>> {
        let block = self.locate_block(raw_ref)?;
        let data = self.block_bytes(raw_ref.segment, block)?;

        let local = (raw_ref.offset - block.uncompressed_start) as usize;
        let header_end = local + RECORD_HEADER_LEN as usize;
        if header_end > data.len() {
            return Err(VaultError::CorruptRecord {
                raw_ref,
                detail: "record header runs past the end of its block".into(),
            });
        }

        let stated = u32::from_le_bytes(
            data[local..header_end]
                .try_into()
                .expect("slice is exactly four bytes"),
        );
        if stated != raw_ref.len {
            return Err(VaultError::CorruptRecord {
                raw_ref,
                detail: format!(
                    "length mismatch: reference says {}, record header says {stated}",
                    raw_ref.len
                ),
            });
        }

        let end = header_end + stated as usize;
        if end > data.len() {
            return Err(VaultError::CorruptRecord {
                raw_ref,
                detail: "record payload runs past the end of its block".into(),
            });
        }
        Ok(data[header_end..end].to_vec())
    }

    /// Retrieve and interpret as UTF-8, replacing invalid sequences.
    pub fn get_lossy(&mut self, raw_ref: RawRef) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.get(raw_ref)?).into_owned())
    }

    /// Read every record in a segment, in write order.
    pub fn scan_segment(&mut self, segment: u64) -> Result<Vec<Vec<u8>>> {
        let blocks = self.index_for(segment)?.clone();
        let mut out = Vec::new();
        for block in blocks {
            let data = self.block_bytes(segment, block)?;
            let mut pos = 0usize;
            while pos + RECORD_HEADER_LEN as usize <= data.len() {
                let len =
                    u32::from_le_bytes(data[pos..pos + 4].try_into().expect("four bytes")) as usize;
                pos += RECORD_HEADER_LEN as usize;
                if pos + len > data.len() {
                    break;
                }
                out.push(data[pos..pos + len].to_vec());
                pos += len;
            }
        }
        Ok(out)
    }

    /// Segment numbers present in the vault, ascending.
    pub fn segments(&self) -> Result<Vec<u64>> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(stem) = name.strip_suffix(".vlt") else {
                continue;
            };
            if let Ok(n) = u64::from_str_radix(stem, 16) {
                found.push(n);
            }
        }
        found.sort_unstable();
        Ok(found)
    }

    fn locate_block(&mut self, raw_ref: RawRef) -> Result<BlockLoc> {
        let blocks = self.index_for(raw_ref.segment)?;
        // Blocks are written in ascending order, so binary search applies.
        let idx = blocks
            .binary_search_by(|b| {
                if b.contains(raw_ref.offset) {
                    std::cmp::Ordering::Equal
                } else if b.uncompressed_end() <= raw_ref.offset {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Greater
                }
            })
            .map_err(|_| VaultError::OffsetNotFound(raw_ref))?;
        Ok(blocks[idx])
    }

    fn block_bytes(&mut self, segment: u64, block: BlockLoc) -> Result<Vec<u8>> {
        let key = (segment, block.uncompressed_start);
        if let Some((cached_key, data)) = &self.cache {
            if *cached_key == key {
                return Ok(data.clone());
            }
        }

        let path = self.segment_path(segment);
        let mut file = File::open(&path).map_err(|e| VaultError::Segment {
            path: path.clone(),
            source: e,
        })?;

        // The footer index is only an acceleration structure. Re-read and
        // validate the authoritative block header before trusting its offsets,
        // lengths, or checksum. This detects both corrupted index entries and
        // bit rot in a payload that still happens to be a valid zstd frame.
        file.seek(SeekFrom::Start(block.file_offset))?;
        let mut header = [0u8; BLOCK_HEADER_LEN as usize];
        file.read_exact(&mut header)?;
        let magic = u32::from_le_bytes(header[0..4].try_into().expect("four bytes"));
        let stated_start = u64::from_le_bytes(header[4..12].try_into().expect("eight bytes"));
        let stated_ulen = u32::from_le_bytes(header[12..16].try_into().expect("four bytes"));
        let stated_clen = u32::from_le_bytes(header[16..20].try_into().expect("four bytes"));
        let stated_crc = u32::from_le_bytes(header[20..24].try_into().expect("four bytes"));

        if magic != BLOCK_MAGIC
            || stated_start != block.uncompressed_start
            || stated_ulen != block.uncompressed_len
            || stated_clen != block.compressed_len
        {
            return Err(VaultError::CorruptBlock {
                segment,
                detail: "block header disagrees with the segment index".into(),
            });
        }

        let mut compressed = vec![0u8; block.compressed_len as usize];
        file.read_exact(&mut compressed)?;

        let data = zstd::decode_all(compressed.as_slice())?;
        if data.len() != block.uncompressed_len as usize {
            return Err(VaultError::CorruptBlock {
                segment,
                detail: format!(
                    "block decompressed to {} bytes, index says {}",
                    data.len(),
                    block.uncompressed_len
                ),
            });
        }
        let actual_crc = crc32(&data);
        if actual_crc != stated_crc {
            return Err(VaultError::CorruptBlock {
                segment,
                detail: format!(
                    "CRC-32 mismatch: header says {stated_crc:08x}, computed {actual_crc:08x}"
                ),
            });
        }

        self.cache = Some((key, data.clone()));
        Ok(data)
    }

    fn index_for(&mut self, segment: u64) -> Result<&Vec<BlockLoc>> {
        if !self.segments.contains_key(&segment) {
            let index = self.load_index(segment)?;
            self.segments.insert(segment, index);
        }
        Ok(&self.segments[&segment])
    }

    /// Load a segment's block index, falling back to a forward scan.
    fn load_index(&self, segment: u64) -> Result<Vec<BlockLoc>> {
        let path = self.segment_path(segment);
        let mut file = File::open(&path).map_err(|e| VaultError::Segment {
            path: path.clone(),
            source: e,
        })?;

        let size = file.metadata()?.len();
        if size < SEGMENT_HEADER_LEN {
            return Err(VaultError::CorruptBlock {
                segment,
                detail: "segment is shorter than its header".into(),
            });
        }

        let mut magic = [0u8; 8];
        file.read_exact(&mut magic)?;
        if &magic != SEGMENT_MAGIC {
            return Err(VaultError::CorruptBlock {
                segment,
                detail: "bad segment magic".into(),
            });
        }

        if size >= SEGMENT_HEADER_LEN + FOOTER_LEN {
            if let Some(index) = read_footer_index(&mut file, size, segment)? {
                return Ok(index);
            }
        }

        // No usable footer: the writer was killed before sealing. Rebuild by
        // walking block headers, which is exactly why they exist.
        tracing::warn!(
            segment,
            "vault segment has no footer; rebuilding index by scan (unclean shutdown)"
        );
        recover_index(&mut file, size, segment)
    }

    fn segment_path(&self, segment: u64) -> PathBuf {
        self.dir.join(format!("{segment:016x}.vlt"))
    }
}

fn read_footer_index(file: &mut File, size: u64, segment: u64) -> Result<Option<Vec<BlockLoc>>> {
    file.seek(SeekFrom::Start(size - FOOTER_LEN))?;
    let mut footer = [0u8; FOOTER_LEN as usize];
    file.read_exact(&mut footer)?;

    if &footer[12..20] != FOOTER_MAGIC {
        return Ok(None);
    }
    let index_offset = u64::from_le_bytes(footer[0..8].try_into().expect("eight bytes"));
    let block_count = u32::from_le_bytes(footer[8..12].try_into().expect("four bytes")) as u64;

    let expected_end = index_offset + block_count * INDEX_ENTRY_LEN + FOOTER_LEN;
    if expected_end != size {
        return Err(VaultError::CorruptBlock {
            segment,
            detail: "footer disagrees with file length".into(),
        });
    }

    file.seek(SeekFrom::Start(index_offset))?;
    let mut buf = vec![0u8; (block_count * INDEX_ENTRY_LEN) as usize];
    file.read_exact(&mut buf)?;

    let mut index = Vec::with_capacity(block_count as usize);
    for chunk in buf.chunks_exact(INDEX_ENTRY_LEN as usize) {
        index.push(BlockLoc {
            uncompressed_start: u64::from_le_bytes(chunk[0..8].try_into().expect("eight")),
            uncompressed_len: u32::from_le_bytes(chunk[8..12].try_into().expect("four")),
            file_offset: u64::from_le_bytes(chunk[12..20].try_into().expect("eight")),
            compressed_len: u32::from_le_bytes(chunk[20..24].try_into().expect("four")),
        });
    }
    Ok(Some(index))
}

/// Rebuild a block index by walking block headers from the start of the file.
///
/// Stops at the first header that does not parse, which is the torn tail of an
/// interrupted write. Everything before it is intact and is returned.
fn recover_index(file: &mut File, size: u64, segment: u64) -> Result<Vec<BlockLoc>> {
    let mut index = Vec::new();
    let mut pos = SEGMENT_HEADER_LEN;

    while pos + BLOCK_HEADER_LEN <= size {
        file.seek(SeekFrom::Start(pos))?;
        let mut header = [0u8; BLOCK_HEADER_LEN as usize];
        if file.read_exact(&mut header).is_err() {
            break;
        }
        let magic = u32::from_le_bytes(header[0..4].try_into().expect("four"));
        if magic != BLOCK_MAGIC {
            break;
        }
        let uncompressed_start = u64::from_le_bytes(header[4..12].try_into().expect("eight"));
        let uncompressed_len = u32::from_le_bytes(header[12..16].try_into().expect("four"));
        let compressed_len = u32::from_le_bytes(header[16..20].try_into().expect("four"));

        if pos + BLOCK_HEADER_LEN + compressed_len as u64 > size {
            // Block header survived but its payload did not.
            break;
        }

        index.push(BlockLoc {
            uncompressed_start,
            uncompressed_len,
            file_offset: pos,
            compressed_len,
        });
        pos += BLOCK_HEADER_LEN + compressed_len as u64;
    }

    if index.is_empty() {
        return Err(VaultError::CorruptBlock {
            segment,
            detail: "no recoverable blocks".into(),
        });
    }
    Ok(index)
}
