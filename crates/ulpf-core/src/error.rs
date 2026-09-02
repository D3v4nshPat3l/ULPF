//! Error type shared by the core crates.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("malformed raw locator: {0}")]
    BadLocator(String),

    #[error("raw locator field `{0}` is missing or not valid hex")]
    LocatorField(&'static str),

    #[error("field `{field}` expected {expected}, found {found}")]
    FieldType {
        field: String,
        expected: &'static str,
        found: &'static str,
    },

    #[error("required field `{0}` is absent")]
    MissingField(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
