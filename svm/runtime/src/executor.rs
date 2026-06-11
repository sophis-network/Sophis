use std::sync::Arc;

use wasmtime::{Linker, Store};

use sophis_svm_core::{ContractId, Gas};

use crate::cache::ModuleCache;
use crate::context::{BufferedEvent, ExecutionContext};
use crate::engine::SvmEngine;
use crate::error::{RuntimeError, RuntimeResult};
use crate::host::{HostCrypto, register_host_functions};

pub struct ExecutionResult {
    /// 1 = validation passed (contract accepted the tx), 0 = rejected.
    pub valid: bool,
    pub gas_used: Gas,
    /// J4 — events emitted by the contract during execution. Empty for
    /// contracts that do not declare `Capability::EmitEvent` or that
    /// declare it but never call `sophis_emit_event`. The runtime does
    /// not promote these to canonical `EventLog` records — that is the
    /// consensus commit hook's job (J4.4), which fills the chain
    /// coordinates the runtime cannot know.
    pub events: Vec<BufferedEvent>,
}

pub struct ContractExecutor {
    cache: ModuleCache,
    #[allow(dead_code)] // retained for future use (e.g. Linker pre-warming)
    engine: SvmEngine,
}

impl ContractExecutor {
    pub fn new(engine: SvmEngine) -> Self {
        Self { cache: ModuleCache::new(engine.clone()), engine }
    }

    pub fn execute(
        &self,
        contract_id: ContractId,
        wasm: &[u8],
        ctx: ExecutionContext,
        fuel_budget: u64,
    ) -> RuntimeResult<ExecutionResult> {
        let module = self.cache.get_or_compile(contract_id, wasm)?;
        let engine = module.engine();
        let crypto: Arc<dyn HostCrypto> = Arc::clone(&ctx.crypto);

        let mut store = Store::new(engine, ctx);
        store.set_fuel(fuel_budget).map_err(|e| RuntimeError::Execution(e.to_string()))?;

        let mut linker: Linker<ExecutionContext> = Linker::new(engine);
        register_host_functions(&mut linker, crypto)?;

        let instance = linker.instantiate(&mut store, &module).map_err(|e| RuntimeError::InstantiationFailed(e.to_string()))?;

        let validate_fn =
            instance.get_typed_func::<(), i32>(&mut store, "validate").map_err(|_| RuntimeError::MissingValidateExport)?;

        let result = validate_fn.call(&mut store, ()).map_err(|e| RuntimeError::Execution(e.to_string()))?;

        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let fuel_used = fuel_budget.saturating_sub(fuel_remaining);
        let ratio = store.data().gas_config.wasm_fuel_ratio;
        // F-37 — `saturating_mul` so a large fuel_used × ratio cannot wrap u64
        // (a config-dependent overflow would underreport gas); saturating to
        // u64::MAX deterministically exceeds any gas budget → the tx is rejected.
        let gas_used = Gas(fuel_used.saturating_mul(ratio));

        // Recover the post-execution context to extract any events the
        // contract emitted via `sophis_emit_event` (J4). For contracts
        // that did not emit (the common case), this is a cheap empty Vec.
        let events = std::mem::take(&mut store.into_data().events);

        Ok(ExecutionResult { valid: result == 1, gas_used, events })
    }
}
