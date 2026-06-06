use std::sync::Arc;

use wasmtime::{Config, Engine};

use crate::config::RuntimeConfig;
use crate::error::{RuntimeError, RuntimeResult};

/// Shared, thread-safe Wasmtime engine.
/// One instance per node — expensive to create, cheap to clone (Arc inside).
/// Configured for deterministic execution: fuel metering on, NaN canonicalization on,
/// no async, no WASI, no component model.
#[derive(Clone)]
pub struct SvmEngine {
    pub(crate) inner: Arc<Engine>,
    pub(crate) config: Arc<RuntimeConfig>,
}

impl SvmEngine {
    pub fn new(config: RuntimeConfig) -> RuntimeResult<Self> {
        let mut wt_config = Config::new();

        // Deterministic execution
        wt_config.consume_fuel(true);
        wt_config.cranelift_nan_canonicalization(true);

        // SIMD allowed — float SIMD opcodes are rejected by validate_bytecode before
        // compilation; plain integer SIMD is deterministic; NaN canonicalization above covers edge cases.
        // Threads and component model disabled by not including those cargo features.
        //
        // F-30 — relaxed SIMD must be forced deterministic. Wasmtime enables the
        // relaxed-SIMD proposal by default with non-deterministic (platform-native)
        // lowering, and validate_bytecode only rejects the *float* relaxed ops — the
        // pure-integer relaxed ops (relaxed_swizzle / relaxed_laneselect /
        // relaxed_q15mulr / relaxed_dot) would otherwise produce x86-vs-ARM-divergent
        // results, forking consensus across a heterogeneous validator set. Forcing
        // deterministic lowering makes every relaxed op produce the canonical,
        // architecture-independent result regardless of the host CPU.
        wt_config.relaxed_simd_deterministic(true);

        // Memory limits enforced per-Store, not globally
        wt_config.max_wasm_stack(512 * 1024); // 512 KiB call stack

        let engine = Engine::new(&wt_config).map_err(|e| RuntimeError::CompilationFailed(e.to_string()))?;

        Ok(Self { inner: Arc::new(engine), config: Arc::new(config) })
    }

    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    /// Borrows the underlying Wasmtime engine. Used by integration tests
    /// that need to compile a `Module` and instantiate it directly without
    /// going through `ContractExecutor` (which only exposes a boolean
    /// validation result, not the host-fn return value).
    pub fn inner(&self) -> &Engine {
        &self.inner
    }
}

impl std::fmt::Debug for SvmEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SvmEngine").field("config", &self.config).finish_non_exhaustive()
    }
}
