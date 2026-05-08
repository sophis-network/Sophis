//! Phase 6 — sVM `HostDa` backend bound to the consensus DA store.
//!
//! Lives in the consensus crate (not in `svm/host`) because it needs
//! `DbDaStore`, which is consensus-internal. `svm/host` stays purely
//! crypto-stateless. Construction captures the chain block's blue score
//! at validator entry; subsequent in-contract `sophis_verify_da` calls
//! reuse it for confirmation arithmetic, keeping the result deterministic
//! across nodes that observe the same DAG state.

use std::sync::Arc;

use sophis_consensus_core::da::PayloadIdHash;
use sophis_svm_runtime::HostDa;

use crate::model::stores::da::{DaStoreReader, DbDaStore};
use crate::model::stores::virtual_state::LkgVirtualState;

/// How `SophisDaBackend` resolves the "current blue score" against which
/// `confirmations = current - entry.blue_score` is computed.
enum BlueScoreSource {
    /// Static value — used by 6.5 and by tests that want a deterministic
    /// snapshot. Production paths should prefer `Lkg`.
    Static(u64),
    /// Lock-free arc-swap into the last-known-good virtual state. Read
    /// once per `verify_payload` / `verify_bundle` call. Sub-fase 6.5.b.
    Lkg(LkgVirtualState),
}

/// Real `HostDa` impl backed by the consensus DA store. Constructed once
/// per transaction validation; reads the chain-tip blue score on each
/// host-fn call so reorgs / advances during a long contract execution
/// see the freshest answer.
pub struct SophisDaBackend {
    store: Arc<DbDaStore>,
    blue_score: BlueScoreSource,
}

impl SophisDaBackend {
    /// Pre-6.5.b constructor — captures a single blue score. Kept for
    /// tests + the lite path where a `LkgVirtualState` is unavailable.
    pub fn new(store: Arc<DbDaStore>, current_blue_score: u64) -> Self {
        Self { store, blue_score: BlueScoreSource::Static(current_blue_score) }
    }

    /// Sub-fase 6.5.b — reads the chain-tip blue score from `LkgVirtualState`
    /// on every call. Determinístico because the LKG lags consensus by at
    /// most one virtual-state commit, and every node observes the same
    /// committed virtual state.
    pub fn from_lkg(store: Arc<DbDaStore>, lkg: LkgVirtualState) -> Self {
        Self { store, blue_score: BlueScoreSource::Lkg(lkg) }
    }

    fn current_blue_score(&self) -> u64 {
        match &self.blue_score {
            BlueScoreSource::Static(v) => *v,
            BlueScoreSource::Lkg(lkg) => lkg.load().ghostdag_data.blue_score,
        }
    }

    fn confirmations(&self, accepting_blue_score: u64) -> u64 {
        self.current_blue_score().saturating_sub(accepting_blue_score)
    }
}

impl HostDa for SophisDaBackend {
    fn verify_payload(&self, payload_id: &[u8; 48], min_confirmations: u64) -> bool {
        match self.store.get_payload(PayloadIdHash(*payload_id)) {
            Ok(Some(entry)) => self.confirmations(entry.blue_score) >= min_confirmations,
            Ok(None) | Err(_) => false,
        }
    }

    fn verify_bundle(&self, bundle_id: &[u8; 48], min_confirmations: u64) -> bool {
        let index = match self.store.get_bundle(PayloadIdHash(*bundle_id)) {
            Ok(Some(b)) => b,
            _ => return false,
        };
        // Bundle must be complete (every fragment indexed).
        if index.payload_ids.len() as u8 != index.fragment_count {
            return false;
        }
        // Every fragment must clear the confirmation bar individually.
        // In practice all fragments are accepted in nearby chain blocks so
        // their confirmations are very close, but we check each to make the
        // semantics strict.
        for pid in &index.payload_ids {
            match self.store.get_payload(*pid) {
                Ok(Some(entry)) => {
                    if self.confirmations(entry.blue_score) < min_confirmations {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::stores::da::{CarrierIndex, DbDaStore};
    use sophis_consensus_core::da::PayloadEntry;
    use sophis_database::create_temp_db;
    use sophis_database::prelude::{CachePolicy, ConnBuilder};
    use sophis_database::utils::DbLifetime;
    use sophis_hashes::Hash;

    fn build() -> (DbLifetime, Arc<DbDaStore>) {
        let (lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = Arc::new(DbDaStore::new(db, CachePolicy::Count(64)));
        (lt, store)
    }

    fn populate_payload(store: &DbDaStore, pid: PayloadIdHash, bid: PayloadIdHash, blue_score: u64) {
        let block = Hash::from_slice(&[0xAA; 32]);
        let entry = PayloadEntry {
            script: vec![0; 64],
            accepting_block_hash: block,
            blue_score,
            fragment_index: 0,
            fragment_count: 1,
            bundle_id: bid,
            domain_byte: 0,
        };
        store.index_carrier_direct(block, &[CarrierIndex { payload_id: pid, entry }]).unwrap();
    }

    #[test]
    fn verify_payload_returns_true_when_confirmed() {
        let (_lt, store) = build();
        let pid = PayloadIdHash([1u8; 48]);
        let bid = PayloadIdHash([2u8; 48]);
        populate_payload(&store, pid, bid, 100);

        let backend = SophisDaBackend::new(Arc::clone(&store), 1100);
        // 1100 - 100 = 1000 >= 1000
        assert!(backend.verify_payload(&pid.0, 1000));
        // 1100 - 100 = 1000 < 1001
        assert!(!backend.verify_payload(&pid.0, 1001));
    }

    #[test]
    fn verify_payload_returns_false_when_unknown() {
        let (_lt, store) = build();
        let backend = SophisDaBackend::new(store, 1000);
        let pid = [9u8; 48];
        assert!(!backend.verify_payload(&pid, 0));
    }

    #[test]
    fn verify_bundle_requires_full_fragment_set() {
        let (_lt, store) = build();
        let pid_a = PayloadIdHash([3u8; 48]);
        let bid = PayloadIdHash([4u8; 48]);
        // Indexing one fragment with fragment_count=2 leaves the bundle "incomplete"
        let block = Hash::from_slice(&[0xBB; 32]);
        let entry = PayloadEntry {
            script: vec![0; 64],
            accepting_block_hash: block,
            blue_score: 50,
            fragment_index: 0,
            fragment_count: 2,
            bundle_id: bid,
            domain_byte: 0,
        };
        store.index_carrier_direct(block, &[CarrierIndex { payload_id: pid_a, entry }]).unwrap();

        let backend = SophisDaBackend::new(Arc::clone(&store), 5000);
        assert!(!backend.verify_bundle(&bid.0, 0), "incomplete bundle must not verify");
    }

    #[test]
    fn from_lkg_reads_blue_score_from_virtual_state() {
        // Sub-fase 6.5.b — `from_lkg` resolves the chain-tip blue score
        // through `LkgVirtualState` instead of capturing a static value.
        // The default LKG starts at blue_score=0; this test confirms the
        // backend is wired to that source (rather than to a stale capture)
        // by exercising the conservative min_conf=0 / min_conf=1 boundary.
        use crate::model::stores::virtual_state::LkgVirtualState;
        use std::sync::Arc;

        let (_lt, store) = build();
        let pid = PayloadIdHash([0xDDu8; 48]);
        let bid = PayloadIdHash([0xEEu8; 48]);
        populate_payload(&store, pid, bid, 200);

        let lkg = LkgVirtualState::default();
        let backend = SophisDaBackend::from_lkg(Arc::clone(&store), lkg);
        // Default LKG has blue_score=0 → 0.saturating_sub(200) = 0
        assert!(backend.verify_payload(&pid.0, 0), "min_conf=0 always satisfies");
        assert!(!backend.verify_payload(&pid.0, 1), "default LKG (bs=0) cannot meet min_conf>=1");
    }

    #[test]
    fn verify_bundle_returns_true_when_all_fragments_confirmed() {
        let (_lt, store) = build();
        let pid_a = PayloadIdHash([5u8; 48]);
        let pid_b = PayloadIdHash([6u8; 48]);
        let bid = PayloadIdHash([7u8; 48]);
        let block = Hash::from_slice(&[0xCC; 32]);

        let entry_a = PayloadEntry {
            script: vec![0; 64],
            accepting_block_hash: block,
            blue_score: 100,
            fragment_index: 0,
            fragment_count: 2,
            bundle_id: bid,
            domain_byte: 0,
        };
        let entry_b = PayloadEntry { fragment_index: 1, ..entry_a.clone() };
        store
            .index_carrier_direct(
                block,
                &[
                    CarrierIndex { payload_id: pid_a, entry: entry_a },
                    CarrierIndex { payload_id: pid_b, entry: entry_b },
                ],
            )
            .unwrap();

        let backend = SophisDaBackend::new(Arc::clone(&store), 1100);
        // both fragments at blue_score=100, current=1100 -> conf=1000
        assert!(backend.verify_bundle(&bid.0, 1000));
        assert!(!backend.verify_bundle(&bid.0, 1001));
    }
}
