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

    /// Audit/F-10 (Session 8, 2026-05-15): a contract imports an `(env, fn_name)`
    /// pair that is not in the canonical host-fn registry. Catches stale ABI
    /// references, typos in extern "C" declarations, and attempts to call
    /// host fns from a future protocol version against an older node.
    #[error("unknown host import in `env` namespace: `{0}` (not registered in HOST_FN_CAPABILITY_MAP)")]
    UnknownHostImport(String),

    /// Audit/F-10 (Session 8, 2026-05-15): a contract imports `(env, fn_name)`
    /// whose corresponding Capability is missing from the deploy manifest's
    /// `required_capabilities`. The runtime trap path would still fire at
    /// every host call site (defense-in-depth), but the deploy-time check
    /// catches the silent-third-party-library scenario described in
    /// AUDIT_REPORT.md F-10.
    #[error("contract imports host fn `{host_fn}` but manifest does not declare {capability:?}")]
    CapabilityNotDeclared { host_fn: String, capability: SvmCapability },

    #[error(transparent)]
    Svm(#[from] SvmError),
}

// Re-export under a private alias so the error type's signature doesn't pull
// `sophis_svm_core::Capability` into every downstream crate that just wants to
// `match` on RuntimeError.
pub use sophis_svm_core::Capability as SvmCapability;

pub type RuntimeResult<T> = Result<T, RuntimeError>;
