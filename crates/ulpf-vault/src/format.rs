//! On-disk format for vault segments.
//!
//! A segment is a sequence of self-describing compressed blocks, optionally
//! followed by an index. The index is an *optimization*, never the source of
//! truth: every block carries a header stating where it belongs in the
//! uncompressed stream, so a segment whose process died mid-write can be fully
//! recovered by scanning forward. That property is why the vault can promise
//! requirement (a) — a crash costs you the tail block, not the archive.
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │ SEGMENT HEADER    magic "ULPFVLT1" · version · flags     │
//! ├──────────────────────────────────────────────────────────┤
//! │ BLOCK 0                                                  │
//! │   magic · uncompressed_start · uncompressed_len          │
//! │   compressed_len · crc32(uncompressed) · payload         │
//! ├──────────────────────────────────────────────────────────┤
//! │ BLOCK 1 …                                                │
//! ├──────────────────────────────────────────────────────────┤
//! │ INDEX   n × (uncompressed_start, uncompressed_len,       │
//! │              file_offset, compressed_len)                │
//! ├──────────────────────────────────────────────────────────┤
//! │ FOOTER  index_offset · block_count · magic "ULPFIDX1"    │
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! Within the *uncompressed* byte stream, records are framed as a little-endian
//! `u32` length followed by that many payload bytes. A [`RawRef`] holds the
//! offset of a record's length prefix in that stream, so retrieval is: find the
//! block covering the offset, decompress it once, slice.
//!
//! [`RawRef`]: ulpf_core::RawRef

pub const SEGMENT_MAGIC: &[u8; 8] = b"ULPFVLT1";
pub const FOOTER_MAGIC: &[u8; 8] = b"ULPFIDX1";
pub const BLOCK_MAGIC: u32 = 0x5546_4C42; // "UFLB"

pub const SEGMENT_HEADER_LEN: u64 = 12; // magic(8) + version(2) + flags(2)
pub const BLOCK_HEADER_LEN: u64 = 24; // magic(4) + start(8) + ulen(4) + clen(4) + crc(4)
pub const FOOTER_LEN: u64 = 20; // index_offset(8) + block_count(4) + magic(8)
pub const INDEX_ENTRY_LEN: u64 = 24; // start(8) + ulen(4) + file_offset(8) + clen(4)

pub const FORMAT_VERSION: u16 = 1;

/// Segment header `flags` bit meaning every block in this segment's payload
/// is `nonce || AEAD-ciphertext` rather than a bare zstd frame. Kept as a
/// per-segment flag rather than a per-vault setting recorded elsewhere, so
/// a segment is self-describing to a reader that has no other context about
/// it — the same reasoning that makes the block header carry its own
/// coordinates instead of trusting the index.
pub const ENCRYPTED_FLAG: u16 = 0x0001;

/// Record framing: a little-endian `u32` length precedes each payload.
pub const RECORD_HEADER_LEN: u64 = 4;

/// Where one compressed block sits, in both coordinate systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockLoc {
    /// Offset of this block's first record in the uncompressed stream.
    pub uncompressed_start: u64,
    /// Total uncompressed size of this block.
    pub uncompressed_len: u32,
    /// Byte offset of the block header within the segment file.
    pub file_offset: u64,
    /// Size of the compressed payload, excluding the block header.
    pub compressed_len: u32,
}

impl BlockLoc {
    /// Whether an uncompressed-stream offset falls inside this block.
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.uncompressed_start
            && offset < self.uncompressed_start + self.uncompressed_len as u64
    }

    pub fn uncompressed_end(&self) -> u64 {
        self.uncompressed_start + self.uncompressed_len as u64
    }
}

/// CRC-32 (IEEE) over a block's uncompressed bytes.
///
/// zstd already detects corruption of its own frames, but this covers the
/// framing around it — a truncated write that leaves a structurally valid but
/// short frame, or bit rot in the header fields themselves. For an archive that
/// exists to be trusted, the extra four bytes per block are worth it.
pub fn crc32(data: &[u8]) -> u32 {
    // Bitwise CRC-32, table-free. The vault is not CRC-bound: a block is a
    // megabyte of zstd compression away from this call mattering.
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_known_vectors() {
        // Standard IEEE CRC-32 check values.
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
    }

    #[test]
    fn crc32_detects_a_single_bit_flip() {
        let a = crc32(b"srcip=10.0.0.1 action=accept");
        let b = crc32(b"srcip=10.0.0.1 action=accepu");
        assert_ne!(a, b);
    }

    #[test]
    fn block_containment_is_half_open() {
        let b = BlockLoc {
            uncompressed_start: 100,
            uncompressed_len: 50,
            file_offset: 12,
            compressed_len: 30,
        };
        assert!(!b.contains(99));
        assert!(b.contains(100));
        assert!(b.contains(149));
        // The end offset belongs to the next block, not this one.
        assert!(!b.contains(150));
        assert_eq!(b.uncompressed_end(), 150);
    }
}
