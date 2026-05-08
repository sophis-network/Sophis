use thiserror::Error;

use sophis_svm_core::SvmError;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("float instruction forbidden in contract bytecode")]
    FloatForbidden,

    #[error("WASM threads forbidden in contract bytecode")]
    ThreadsForbidden,

    #[error("memory declaration exceeds limit: {0} pages (limit: {1} pages / 16 MiB)")]
    MemoryTooLarge(u64, u64),

    #[error("memory declaration has no maximum — unbounded memory forbidden")]
    MemoryUnbounded,

    #[error("bytecode exceeds maximum size: {0} bytes (limit: {1})")]
    BytecodeTooLarge(usize, usize),

    #[error("WASM validation failed: {0}")]
    ValidationFailed(String),

    #[error("module compilation failed: {0}")]
    CompilationFailed(String),

    #[error("instantiation failed: {0}")]
    InstantiationFailed(String),

    #[error("contract has no `validate` export")]
    MissingValidateExport,

    #[error("execution error: {0}")]
    Execution(String),

    #[error(transparent)]
    Svm(#[from] SvmError),
}

pub type RuntimeResult<T> = Result<T, RuntimeError>;
