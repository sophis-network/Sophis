use std::sync::Arc;

use sophis_svm_core::{Capability, ContractManifest, Gas, GasConfig};

use crate::host::{HostCrypto, HostDa, StubDa};

/// Data threaded through the Wasmtime Store during a single contract execution.
/// Host functions receive a `Caller<ExecutionContext>` and read/write this.
///
/// UTXOs are raw bytes (borsh-serialized) — svm/host converts between
/// consensus-core types and this representation, keeping svm/runtime free of
/// any sophis-consensus-core dependency (B3 separation).
pub struct ExecutionContext {
    pub input_utxos: Vec<Vec<u8>>,
    pub output_utxos: Vec<Vec<u8>>,
    pub block_height: u64,
    pub gas_used: Gas,
    pub gas_config: GasConfig,
    pub manifest: ContractManifest,
    pub crypto: Arc<dyn HostCrypto>,
    /// Phase 6 — DA presence backend. Stub by default; consensus injects
    /// `SophisDaBackend` (bound to `DbDaStore` + sink blue score) at the
    /// transaction-validator layer.
    pub da: Arc<dyn HostDa>,
}

impl ExecutionContext {
    pub fn new(
        input_utxos: Vec<Vec<u8>>,
        output_utxos: Vec<Vec<u8>>,
        block_height: u64,
        manifest: ContractManifest,
        gas_config: GasConfig,
        crypto: Arc<dyn HostCrypto>,
    ) -> Self {
        Self { input_utxos, output_utxos, block_height, gas_used: Gas::default(), gas_config, manifest, crypto, da: Arc::new(StubDa) }
    }

    /// Phase 6 builder — variant of `new` that injects a real DA backend.
    /// Used by the consensus transaction validator; tests / wasm sandbox
    /// stick with the default `StubDa` via `new`.
    pub fn new_with_da(
        input_utxos: Vec<Vec<u8>>,
        output_utxos: Vec<Vec<u8>>,
        block_height: u64,
        manifest: ContractManifest,
        gas_config: GasConfig,
        crypto: Arc<dyn HostCrypto>,
        da: Arc<dyn HostDa>,
    ) -> Self {
        Self { input_utxos, output_utxos, block_height, gas_used: Gas::default(), gas_config, manifest, crypto, da }
    }

    pub fn check_capability(&self, cap: &Capability) -> Result<(), sophis_svm_core::SvmError> {
        if self.manifest.has_capability(cap) { Ok(()) } else { Err(sophis_svm_core::SvmError::UndeclaredCapability(cap.clone())) }
    }

    pub fn charge(&mut self, gas: Gas) -> Result<(), sophis_svm_core::SvmError> {
        let new_total = self.gas_used.saturating_add(gas);
        if new_total.0 > self.gas_config.max_gas_per_tx {
            return Err(sophis_svm_core::SvmError::GasExhausted { budget: self.gas_config.max_gas_per_tx, used: new_total.0 });
        }
        self.gas_used = new_total;
        Ok(())
    }
}
