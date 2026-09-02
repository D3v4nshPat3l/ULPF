//! The raw vault: an append-only, block-compressed archive of original events.
//!
//! This crate is requirement (a) of PS 26156 — preserve complete raw event data
//! without information loss — and half of requirement (d), because the
//! [`RawRef`] it hands back is what lets a normalized event point at the exact
//! bytes it came from.
//!
//! Two properties shape the design:
//!
//! * **Bytes are stored before they are understood.** The pipeline appends to
//!   the vault as the first action after receipt, ahead of any parsing. A
//!   decoder panic, an unknown format, or a malformed frame therefore cannot
//!   cost you the original.
//! * **Compression must not cost random access.** Per-record compression would
//!   waste the redundancy that makes log data compress well; one giant stream
//!   would make retrieving a single event mean decompressing a segment. Records
//!   are batched into blocks of roughly a megabyte, so a point lookup costs one
//!   seek and one block decompress while zstd still sees enough context.
//!
//! ```no_run
//! use ulpf_vault::{VaultReader, VaultWriter};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut writer = VaultWriter::open("data/vault")?;
//! let reference = writer.append(b"<134>FGT-01 srcip=10.2.4.7 action=accept")?;
//! writer.flush()?;
//!
//! let mut reader = VaultReader::open("data/vault");
//! assert_eq!(reader.get(reference)?, b"<134>FGT-01 srcip=10.2.4.7 action=accept");
//! # Ok(())
//! # }
//! ```

pub mod error;
pub mod format;
mod reader;
mod writer;

pub use error::{Result, VaultError};
pub use reader::VaultReader;
pub use writer::{VaultConfig, VaultWriter};

#[cfg(test)]
mod tests {
    use super::*;
    use ulpf_core::RawRef;

    fn small_blocks() -> VaultConfig {
        // Tiny blocks so tests exercise multi-block behaviour without writing
        // megabytes.
        VaultConfig {
            block_size: 256,
            segment_size: 4096,
            level: 1,
            sync_on_flush: false,
        }
    }

    #[test]
    fn round_trips_a_single_record() {
        let dir = tempfile::tempdir().unwrap();
        let line = b"<134>date=2026-08-31 devname=FGT-01 srcip=10.2.4.7 action=accept";

        let mut w = VaultWriter::open(dir.path()).unwrap();
        let r = w.append(line).unwrap();
        w.close().unwrap();

        let mut reader = VaultReader::open(dir.path());
        assert_eq!(reader.get(r).unwrap(), line);
    }

    #[test]
    fn preserves_bytes_exactly_including_non_utf8() {
        // Requirement (a) is about bytes, not text. A device emitting Latin-1
        // or a truncated multi-byte sequence must still round-trip untouched.
        let dir = tempfile::tempdir().unwrap();
        let payload = vec![0xff, 0xfe, 0x00, 0x41, 0x80, 0x0a];

        let mut w = VaultWriter::open(dir.path()).unwrap();
        let r = w.append(&payload).unwrap();
        w.close().unwrap();

        let mut reader = VaultReader::open(dir.path());
        assert_eq!(reader.get(r).unwrap(), payload);
    }

    #[test]
    fn round_trips_many_records_across_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = VaultWriter::open_with(dir.path(), small_blocks()).unwrap();

        let mut refs = Vec::new();
        for i in 0..500 {
            let line = format!("event {i} srcip=10.0.{}.{} action=accept", i / 256, i % 256);
            refs.push((w.append(line.as_bytes()).unwrap(), line));
        }
        w.close().unwrap();

        let mut reader = VaultReader::open(dir.path());
        // Read back out of order: retrieval must not depend on access pattern.
        for (r, expected) in refs.iter().rev() {
            assert_eq!(reader.get(*r).unwrap(), expected.as_bytes());
        }
    }

    #[test]
    fn records_are_retrievable_after_flush_without_close() {
        // The live pipeline never closes the vault; retrieval has to work
        // against a segment that is still being appended to.
        let dir = tempfile::tempdir().unwrap();
        let mut w = VaultWriter::open_with(dir.path(), small_blocks()).unwrap();
        let r = w.append(b"first").unwrap();
        w.flush().unwrap();

        let mut reader = VaultReader::open(dir.path());
        assert_eq!(reader.get(r).unwrap(), b"first");
    }

    #[test]
    fn rotates_segments_and_reads_across_them() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = VaultWriter::open_with(dir.path(), small_blocks()).unwrap();

        let mut refs = Vec::new();
        for i in 0..400 {
            let line = format!("padding-to-force-rotation-{i:06}");
            refs.push((w.append(line.as_bytes()).unwrap(), line));
        }
        w.close().unwrap();

        let segments: std::collections::BTreeSet<u64> =
            refs.iter().map(|(r, _)| r.segment).collect();
        assert!(segments.len() > 1, "expected rotation, got {segments:?}");

        let mut reader = VaultReader::open(dir.path());
        for (r, expected) in &refs {
            assert_eq!(reader.get(*r).unwrap(), expected.as_bytes());
        }
    }

    #[test]
    fn recovers_an_unsealed_segment_by_scanning() {
        // Simulate a kill -9: blocks were flushed, but no footer was written.
        let dir = tempfile::tempdir().unwrap();
        let mut w = VaultWriter::open_with(dir.path(), small_blocks()).unwrap();
        let mut refs = Vec::new();
        for i in 0..50 {
            let line = format!("survivor {i}");
            refs.push((w.append(line.as_bytes()).unwrap(), line));
        }
        w.flush().unwrap();
        drop(w); // no close(), so no index and no footer

        let mut reader = VaultReader::open(dir.path());
        for (r, expected) in &refs {
            assert_eq!(
                reader.get(*r).unwrap(),
                expected.as_bytes(),
                "record lost after unclean shutdown"
            );
        }
    }

    #[test]
    fn recovers_what_it_can_from_a_truncated_segment() {
        // Torn write: the tail block is cut in half. Everything before it must
        // still be readable — losing the archive because of one bad block would
        // defeat the point.
        let dir = tempfile::tempdir().unwrap();
        let mut w = VaultWriter::open_with(dir.path(), small_blocks()).unwrap();
        let mut refs = Vec::new();
        for i in 0..60 {
            let line = format!("record {i:04}");
            refs.push((w.append(line.as_bytes()).unwrap(), line));
        }
        w.flush().unwrap();
        drop(w);

        let path = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == "vlt"))
            .unwrap();
        let len = std::fs::metadata(&path).unwrap().len();
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(len - 40).unwrap();
        drop(file);

        let mut reader = VaultReader::open(dir.path());
        let recovered = refs
            .iter()
            .filter(|(r, expected)| {
                reader
                    .get(*r)
                    .map(|b| b == expected.as_bytes())
                    .unwrap_or(false)
            })
            .count();
        assert!(
            recovered > 0,
            "truncation destroyed the whole segment; recovery should be partial"
        );
    }

    #[test]
    fn scan_returns_records_in_write_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = VaultWriter::open_with(dir.path(), small_blocks()).unwrap();
        for i in 0..100 {
            w.append(format!("line {i}").as_bytes()).unwrap();
        }
        w.close().unwrap();

        let mut reader = VaultReader::open(dir.path());
        let all = reader.scan_segment(0).unwrap();
        assert_eq!(all.len(), 100);
        assert_eq!(all[0], b"line 0");
        assert_eq!(all[99], b"line 99");
    }

    #[test]
    fn a_bogus_reference_is_rejected_rather_than_returning_junk() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = VaultWriter::open(dir.path()).unwrap();
        w.append(b"only record").unwrap();
        w.close().unwrap();

        let mut reader = VaultReader::open(dir.path());
        // Offset past the end of everything written.
        let bogus = RawRef::new(0, 999_999, 10);
        assert!(matches!(
            reader.get(bogus),
            Err(VaultError::OffsetNotFound(_))
        ));
    }

    #[test]
    fn a_reference_with_the_wrong_length_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = VaultWriter::open(dir.path()).unwrap();
        let mut r = w.append(b"eleven byte").unwrap();
        w.close().unwrap();

        r.len = 5; // claim a shorter record than was stored
        let mut reader = VaultReader::open(dir.path());
        assert!(matches!(
            reader.get(r),
            Err(VaultError::CorruptRecord { .. })
        ));
    }

    #[test]
    fn corrupted_block_checksum_is_rejected() {
        use std::io::{Seek, SeekFrom, Write};

        let dir = tempfile::tempdir().unwrap();
        let mut w = VaultWriter::open(dir.path()).unwrap();
        let reference = w.append(b"forensic evidence").unwrap();
        w.close().unwrap();

        let path = dir.path().join("0000000000000000.vlt");
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        // CRC is the final u32 in the first block header.
        file.seek(SeekFrom::Start(
            crate::format::SEGMENT_HEADER_LEN + crate::format::BLOCK_HEADER_LEN - 4,
        ))
        .unwrap();
        file.write_all(&0xDEAD_BEEFu32.to_le_bytes()).unwrap();
        file.flush().unwrap();

        let mut reader = VaultReader::open(dir.path());
        assert!(matches!(
            reader.get(reference),
            Err(VaultError::CorruptBlock { .. })
        ));
    }

    #[test]
    fn empty_payloads_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = VaultWriter::open(dir.path()).unwrap();
        let r = w.append(b"").unwrap();
        let r2 = w.append(b"after empty").unwrap();
        w.close().unwrap();

        let mut reader = VaultReader::open(dir.path());
        assert_eq!(reader.get(r).unwrap(), b"");
        assert_eq!(reader.get(r2).unwrap(), b"after empty");
    }

    #[test]
    fn reopening_a_vault_starts_a_new_segment_without_clobbering() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = VaultWriter::open(dir.path()).unwrap();
        let first = w.append(b"from first run").unwrap();
        w.close().unwrap();

        let mut w2 = VaultWriter::open(dir.path()).unwrap();
        let second = w2.append(b"from second run").unwrap();
        w2.close().unwrap();

        assert_ne!(first.segment, second.segment);
        let mut reader = VaultReader::open(dir.path());
        assert_eq!(reader.get(first).unwrap(), b"from first run");
        assert_eq!(reader.get(second).unwrap(), b"from second run");
    }

    #[test]
    fn compresses_repetitive_device_logs() {
        // Perimeter logs are extremely repetitive; if the vault were not
        // beating 4:1 on this shape of data, the block design would be wrong.
        let dir = tempfile::tempdir().unwrap();
        let mut w = VaultWriter::open(dir.path()).unwrap();
        let mut raw_bytes = 0usize;
        for i in 0..5000 {
            let line = format!(
                "date=2026-08-31 time=10:{:02}:{:02} devname=\"FGT-DEL-01\" devid=\"FG100F\" \
                 type=traffic subtype=forward level=notice srcip=10.2.4.{} srcport={} \
                 dstip=8.8.8.8 dstport=443 proto=6 action=accept policyid=42",
                i / 60 % 60,
                i % 60,
                i % 256,
                40000 + i % 20000
            );
            raw_bytes += line.len();
            w.append(line.as_bytes()).unwrap();
        }
        w.close().unwrap();

        let stored: u64 = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum();
        let ratio = raw_bytes as f64 / stored as f64;
        assert!(ratio > 4.0, "compression ratio only {ratio:.1}:1");
    }
}
