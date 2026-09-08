use std::path::PathBuf;

use thiserror::Error;
use ulpf_core::RawRef;

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("record of {0} bytes exceeds the 4 GiB frame limit")]
    RecordTooLarge(usize),

    #[error("no block in segment {} covers offset {}", .0.segment, .0.offset)]
    OffsetNotFound(RawRef),

    #[error("record at {raw_ref} is corrupt: {detail}")]
    CorruptRecord { raw_ref: RawRef, detail: String },

    #[error("segment {segment} is corrupt: {detail}")]
    CorruptBlock { segment: u64, detail: String },

    #[error("segment file {path}: {source}")]
    Segment {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("vault encryption: {0}")]
    Encryption(String),
}
