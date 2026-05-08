pub mod errors;
#[cfg(test)]
mod native_token_tests;
#[cfg(test)]
mod svm_integration_tests;
pub mod tx_validation_in_header_context;
pub mod tx_validation_in_isolation;
pub mod tx_validation_in_utxo_context;
use std::sync::Arc;

use sophis_svm_core::ContractStore;
use sophis_svm_runtime::{ContractExecutor, RuntimeConfig, SvmEngine};
use sophis_txscript::{
    SigCacheKey,
    caches::{Cache, TxScriptCacheCounters},
};

use sophis_consensus_core::{KType, mass::MassCalculator};

use crate::model::stores::da::DbDaStore;
use crate::model::stores::virtual_state::LkgVirtualState;

/// sVM execution context held by the validator.
/// `None` means no contracts deployed yet — Contract UTXOs return ContractNotDeployed.
#[derive(Clone)]
pub struct SvmContext {
    pub executor: Arc<ContractExecutor>,
    pub store: Arc<dyn ContractStore>,
    /// Phase 6 — DA store handle injected once the consensus storage is wired.
    /// `None` keeps existing tests + lite builds working; with `Some(_)` the
    /// transaction validator hands a real `SophisDaBackend` to every contract
    /// that requested `Capability::VerifyDataAvailability`.
    pub da_store: Option<Arc<DbDaStore>>,
    /// Phase 6.5.b — last-known-good virtual state, used by the DA backend
    /// to read the chain-tip blue score without propagating it through every
    /// validator API. `LkgVirtualState` is a lock-free arc-swap, cheap to
    /// clone, deterministic at consensus time. `None` preserves the
    /// pre-6.5.b conservative-zero behavior.
    pub lkg_virtual_state: Option<LkgVirtualState>,
}

impl SvmContext {
    pub fn new(store: Arc<dyn ContractStore>) -> Result<Self, sophis_svm_runtime::RuntimeError> {
        let engine = SvmEngine::new(RuntimeConfig::default())?;
        Ok(Self { executor: Arc::new(ContractExecutor::new(engine)), store, da_store: None, lkg_virtual_state: None })
    }

    /// Builder — attach a DA store handle. Production uses
    /// `consensus.storage.da_store.clone()`; tests omit and get StubDa
    /// behavior (every DA query returns false).
    pub fn with_da_store(mut self, da_store: Arc<DbDaStore>) -> Self {
        self.da_store = Some(da_store);
        self
    }

    /// Builder — attach the last-known-good virtual state handle so the
    /// DA backend can read the chain-tip blue score on demand
    /// (sub-fase 6.5.b).
    pub fn with_lkg_virtual_state(mut self, lkg: LkgVirtualState) -> Self {
        self.lkg_virtual_state = Some(lkg);
        self
    }
}

#[derive(Clone)]
pub struct TransactionValidator {
    max_tx_inputs: usize,
    max_tx_outputs: usize,
    max_signature_script_len: usize,
    max_script_public_key_len: usize,
    coinbase_payload_script_public_key_max_len: u8,
    coinbase_maturity: u64,
    ghostdag_k: KType,
    sig_cache: Cache<SigCacheKey, bool>,
    pub(crate) mass_calculator: MassCalculator,
    pub(crate) svm: Option<SvmContext>,
}

impl TransactionValidator {
    pub fn new(
        max_tx_inputs: usize,
        max_tx_outputs: usize,
        max_signature_script_len: usize,
        max_script_public_key_len: usize,
        coinbase_payload_script_public_key_max_len: u8,
        coinbase_maturity: u64,
        ghostdag_k: KType,
        counters: Arc<TxScriptCacheCounters>,
        mass_calculator: MassCalculator,
    ) -> Self {
        Self {
            max_tx_inputs,
            max_tx_outputs,
            max_signature_script_len,
            max_script_public_key_len,
            coinbase_payload_script_public_key_max_len,
            coinbase_maturity,
            ghostdag_k,
            sig_cache: Cache::with_counters(10_000, counters),
            mass_calculator,
            svm: None,
        }
    }

    pub fn with_svm(mut self, svm: SvmContext) -> Self {
        self.svm = Some(svm);
        self
    }

    pub fn new_for_tests(
        max_tx_inputs: usize,
        max_tx_outputs: usize,
        max_signature_script_len: usize,
        max_script_public_key_len: usize,
        coinbase_payload_script_public_key_max_len: u8,
        coinbase_maturity: u64,
        ghostdag_k: KType,
        counters: Arc<TxScriptCacheCounters>,
    ) -> Self {
        Self {
            max_tx_inputs,
            max_tx_outputs,
            max_signature_script_len,
            max_script_public_key_len,
            coinbase_payload_script_public_key_max_len,
            coinbase_maturity,
            ghostdag_k,
            sig_cache: Cache::with_counters(10_000, counters),
            mass_calculator: MassCalculator::new(0, 0, 0, 0),
            svm: None,
        }
    }
}
