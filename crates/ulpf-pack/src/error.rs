use thiserror::Error;

pub type Result<T> = std::result::Result<T, PackError>;

#[derive(Debug, Error)]
pub enum PackError {
    #[error("invalid pack: {0}")]
    Invalid(String),

    #[error("unknown decoder `{0}`")]
    UnknownDecoder(String),

    #[error("pack `{pack}` step {step} (`{decoder}`) failed: {source}")]
    Extract {
        pack: String,
        step: usize,
        decoder: String,
        #[source]
        source: ulpf_decode::DecodeError,
    },

    #[error("pack `{pack}` mapping `{path}`: {detail}")]
    Mapping {
        pack: String,
        path: String,
        detail: String,
    },

    #[error("parsing {path}: {source}")]
    Yaml {
        path: String,
        #[source]
        source: serde_yaml::Error,
    },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
