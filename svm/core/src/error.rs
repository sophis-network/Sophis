use thiserror::Error;

use crate::capability::Capability;

#[derive(Debug, Error)]
pub enum SvmError {
    #[error("contract execution trapped: {0}")]
    ExecutionTrapped(String),

    #[error("capability not declared in manifest: {0}")]
    UndeclaredCapability(Capability),

    #[error("upgrade timelock not elapsed: need {required} blocks, currently at {current}")]
    UpgradeTimelockActive { required: u64, current: u64 },

    #[error("gas exhausted: budget {budget}, consumed {used}")]
    GasExhausted { budget: u64, used: u64 },

    #[error("datum exceeds maximum size: {0} bytes")]
    DatumTooLarge(usize),

    #[error("invalid contract manifest: {0}")]
    InvalidManifest(String),

    #[error("contract not found: {0}")]
    ContractNotFound(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

pub type SvmResult<T> = Result<T, SvmError>;
