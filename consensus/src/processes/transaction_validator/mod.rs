pub mod errors;
#[cfg(test)]
mod native_token_tests;
#[cfg(test)]
mod svm_integration_tests;
pub mod tx_validation_in_header_context;
pub mod tx_validation_in_isolation;
pub mod tx_validation_in_utxo_context;
use std::sync::Arc;

use dashmap::DashMap;
use sophis_svm_core::ContractStore;
use sophis_svm_runtime::context::BufferedEvent;
use sophis_svm_runtime::{ContractExecutor, RuntimeConfig, SvmEngine};
use sophis_txscript::{
    SigCacheKey,
    caches::{Cache, TxScriptCacheCounters},
};

use sophis_consensus_core::tx::TransactionId;
use sophis_consensus_core::{KType, mass::MassCalculator};

use parking_lot::RwLock;

use crate::model::stores::alt::DbAltStore;
use crate::model::stores::da::DbDaStore;
use crate::model::stores::selected_chain::DbSelectedChainStore;
use crate::model::stores::virtual_state::LkgVirtualState;

/// J4 — sparse side-channel collector that the transaction validator uses
/// to publish per-tx events to the consensus commit hook
/// (`virtual_processor::index_events_in_block`). Keyed by `TransactionId`
/// so insertions across parallel-validated txs do not contend.
///
/// The collector is **drained** at commit time: `index_events_in_block`
/// removes each entry it consumes, so live memory stays bounded by the
/// largest in-flight chain block. Re-validation on a reorg simply
/// overwrites prior entries with the latest sVM execution result.
///
/// `Arc` so cheap clones can be shared across the validator and the
/// virtual processor without lifetime gymnastics.
pub type EventsCollector = Arc<DashMap<TransactionId, Vec<BufferedEvent>>>;

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
    /// L1 — Address Lookup Table store handle injected once consensus
    /// storage is wired. `None` preserves pre-L1 test/lite-build behavior:
    /// ALT references skip rules 15-16 enforcement (the structural rule 14
    /// from L1.3.a still fires either way). Production validators MUST set
    /// this; otherwise dangling references would be silently accepted.
    pub alt_store: Option<Arc<DbAltStore>>,
    /// J4 — events collector populated at sVM execution time and drained
    /// by `virtual_processor::index_events_in_block` at commit time.
    /// Always present (cheap empty `DashMap`); contracts that never call
    /// `sophis_emit_event` simply leave it empty for that tx.
    pub events_collector: EventsCollector,
    /// J3 — selected-chain store handle injected once consensus storage
    /// is wired. `None` preserves test/lite-build behavior: VRF queries
    /// fall back to `StubVrf` (every lookup returns `None`). Production
    /// validators MUST set this; otherwise `vrf_random_at` returns -6
    /// (unknown chain_index) for every call.
    pub selected_chain_store: Option<Arc<RwLock<DbSelectedChainStore>>>,
}

impl SvmContext {
    pub fn new(store: Arc<dyn ContractStore>) -> Result<Self, sophis_svm_runtime::RuntimeError> {
        let engine = SvmEngine::new(RuntimeConfig::default())?;
        Ok(Self {
            executor: Arc::new(ContractExecutor::new(engine)),
            store,
            da_store: None,
            lkg_virtual_state: None,
            alt_store: None,
            events_collector: Arc::new(DashMap::new()),
            selected_chain_store: None,
        })
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

    /// Builder — attach the L1 ALT store handle. Production uses
    /// `consensus.storage.alt_store.clone()`; tests omit and skip ALT
    /// reference resolution (rules 15-16 of `docs/L1_ALT_DESIGN.md` §5).
    pub fn with_alt_store(mut self, alt_store: Arc<DbAltStore>) -> Self {
        self.alt_store = Some(alt_store);
        self
    }

    /// J3 builder — attach the selected-chain store handle so the VRF
    /// backend can resolve `chain_index → block_hash`. Production uses
    /// `consensus.storage.selected_chain_store.clone()`; tests omit and
    /// fall back to `StubVrf` (every VRF query returns -6 unknown_index).
    pub fn with_selected_chain_store(mut self, store: Arc<RwLock<DbSelectedChainStore>>) -> Self {
        self.selected_chain_store = Some(store);
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
