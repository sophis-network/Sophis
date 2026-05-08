use std::sync::Arc;

use dashmap::DashMap;
use wasmtime::Module;

use sophis_svm_core::ContractId;

use crate::engine::SvmEngine;
use crate::error::{RuntimeError, RuntimeResult};
use crate::validator;

/// Thread-safe cache of compiled WASM modules keyed by ContractId.
/// Compilation is expensive (~ms); cache ensures each unique bytecode is compiled once.
#[derive(Clone)]
pub struct ModuleCache {
    engine: SvmEngine,
    modules: Arc<DashMap<ContractId, Arc<Module>>>,
}

impl ModuleCache {
    pub fn new(engine: SvmEngine) -> Self {
        Self { engine, modules: Arc::new(DashMap::new()) }
    }

    /// Returns a compiled Module for the given bytecode, compiling and caching on first call.
    pub fn get_or_compile(&self, contract_id: ContractId, wasm: &[u8]) -> RuntimeResult<Arc<Module>> {
        if let Some(module) = self.modules.get(&contract_id) {
            return Ok(Arc::clone(&module));
        }

        // Validate before handing to Wasmtime
        validator::validate_bytecode(wasm, self.engine.config().max_bytecode_size)?;

        let module = Module::new(&self.engine.inner, wasm).map_err(|e| RuntimeError::CompilationFailed(e.to_string()))?;

        let module = Arc::new(module);
        self.modules.insert(contract_id, Arc::clone(&module));
        Ok(module)
    }

    pub fn len(&self) -> usize {
        self.modules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }
}
