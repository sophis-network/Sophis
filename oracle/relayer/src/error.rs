//! Top-level relayer error type. Wraps every layer (config, pipeline, sign,
//! submit) so the CLI gets a single `Result<(), RelayerError>`.

use crate::config::ConfigError;

#[derive(Debug, thiserror::Error)]
pub enum RelayerError {
    #[error("config error: {0}")]
    Config(#[from] ConfigError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not implemented yet (sub-phase {0})")]
    NotImplemented(&'static str),
    #[error("{0}")]
    Other(String),
}
