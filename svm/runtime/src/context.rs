use std::sync::Arc;

use sophis_svm_core::{Capability, ContractManifest, Gas, GasConfig};

use crate::host::{HostAlt, HostCrypto, HostDa, HostVrf, StubAlt, StubDa, StubVrf};

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
    /// L1 — Address Lookup Table backend. Stub by default; consensus
    /// injects `SophisAltBackend` (bound to `DbAltStore`) at the
    /// transaction-validator layer. Sub-fase L1.4.
    pub alt: Arc<dyn HostAlt>,
    /// J3 — Verifiable Randomness backend. Stub by default; consensus
    /// injects `SophisVrfBackend` (bound to `selected_chain_store`) at
    /// the transaction-validator layer.
    pub vrf: Arc<dyn HostVrf>,
    /// J4 — identifier of the contract whose code is currently executing,
    /// stamped onto every event the contract emits via `sophis_emit_event`.
    /// `[0u8; 32]` in unit tests / wasm sandbox; the consensus transaction
    /// validator (J4.4) populates the real `ContractId` from the spending
    /// Contract UTXO before invoking the executor.
    pub contract_id: [u8; 32],
    /// J4 — events buffered during execution by `sophis_emit_event`.
    /// Each entry carries `(contract_id, topics, data)`; the chain-coordinate
    /// fields (`tx_id`, `tx_index`, `log_index`, `block_hash`, `daa_score`)
    /// are filled at commit time (J4.4) once they are known.
    pub events: Vec<BufferedEvent>,
}

/// Runtime-internal buffered event. Mirrors the consensus-core `EventLog`
/// shape minus the chain-coordinate fields, which the runtime cannot know
/// at emission time. Promoted to `EventLog` by the J4.4 commit hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferedEvent {
    pub contract_id: [u8; 32],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
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
        Self {
            input_utxos,
            output_utxos,
            block_height,
            gas_used: Gas::default(),
            gas_config,
            manifest,
            crypto,
            da: Arc::new(StubDa),
            alt: Arc::new(StubAlt),
            vrf: Arc::new(StubVrf),
            contract_id: [0u8; 32],
            events: Vec::new(),
        }
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
        Self {
            input_utxos,
            output_utxos,
            block_height,
            gas_used: Gas::default(),
            gas_config,
            manifest,
            crypto,
            da,
            alt: Arc::new(StubAlt),
            vrf: Arc::new(StubVrf),
            contract_id: [0u8; 32],
            events: Vec::new(),
        }
    }

    /// L1 builder — `new_with_da` plus an ALT backend. Production path; tests
    /// stick with the default `StubAlt` via `new` / `new_with_da`.
    pub fn new_with_da_and_alt(
        input_utxos: Vec<Vec<u8>>,
        output_utxos: Vec<Vec<u8>>,
        block_height: u64,
        manifest: ContractManifest,
        gas_config: GasConfig,
        crypto: Arc<dyn HostCrypto>,
        da: Arc<dyn HostDa>,
        alt: Arc<dyn HostAlt>,
    ) -> Self {
        Self {
            input_utxos,
            output_utxos,
            block_height,
            gas_used: Gas::default(),
            gas_config,
            manifest,
            crypto,
            da,
            alt,
            vrf: Arc::new(StubVrf),
            contract_id: [0u8; 32],
            events: Vec::new(),
        }
    }

    /// J3 builder — chain method to inject a real `HostVrf` backend. The
    /// transaction-validator path calls this after one of the `new_*`
    /// constructors when the consensus storage carries a chain store.
    /// Tests leave the default `StubVrf` (always returns `None`).
    pub fn with_vrf_backend(mut self, vrf: Arc<dyn HostVrf>) -> Self {
        self.vrf = vrf;
        self
    }

    /// J4 — set the contract identifier stamped onto emitted events.
    /// Builder-style chain method used by the consensus transaction
    /// validator after one of the `new*` constructors. Tests that don't
    /// care leave the default `[0u8; 32]`.
    pub fn with_contract_id(mut self, contract_id: [u8; 32]) -> Self {
        self.contract_id = contract_id;
        self
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
