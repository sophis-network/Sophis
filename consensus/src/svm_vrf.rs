//! J3 — sVM `HostVrf` backend bound to the consensus selected-chain store.
//!
//! Lives in the consensus crate (not in `svm/host`) because it needs
//! `DbSelectedChainStore`, which is consensus-internal. `svm/host` stays
//! purely crypto-stateless. Construction captures only the store handle;
//! lookups are deterministic at consensus time because the chain store is
//! committed during virtual_processor commit before any contract runs
//! against the same chain block.
//!
//! ABI (mirrored by `sophis_vrf_random_at` host fn): on hit, returns 32
//! bytes derived as
//!
//! ```text
//! SHA3-384(b"sophis-vrf-v1\0" || chain_index_le_8 || chain_block_hash)[..32]
//! ```
//!
//! Domain separator `b"sophis-vrf-v1\0"` (14 bytes including the trailing
//! null) prevents collision with other uses of the same block hash
//! across Sophis subsystems (consensus, Phase 6 DA, L1 ALT, J4 events).
//! See `docs/J3_VRF_DESIGN.md` §3.3.

use std::sync::Arc;

use parking_lot::RwLock;
use sha3::{Digest, Sha3_384};
use sophis_svm_runtime::HostVrf;

use crate::model::stores::selected_chain::{DbSelectedChainStore, SelectedChainStoreReader};

/// Domain separator prepended to the SHA3-384 input. Frozen ABI; any
/// change requires a hard fork. The trailing `\0` byte is part of the
/// separator (14 bytes total including the null) — it makes the
/// separator unambiguous against any future `sophis-vrf-vN` extension.
pub const VRF_DOMAIN_SEPARATOR: &[u8] = b"sophis-vrf-v1\0";

/// Real `HostVrf` impl backed by the consensus selected-chain store.
pub struct SophisVrfBackend {
    chain: Arc<RwLock<DbSelectedChainStore>>,
}

impl SophisVrfBackend {
    pub fn new(chain: Arc<RwLock<DbSelectedChainStore>>) -> Self {
        Self { chain }
    }
}

impl HostVrf for SophisVrfBackend {
    fn vrf_random_at(&self, chain_index: u64) -> Option<[u8; 32]> {
        let block_hash = self.chain.read().get_by_index(chain_index).ok()?;
        let mut hasher = Sha3_384::new();
        hasher.update(VRF_DOMAIN_SEPARATOR);
        hasher.update(chain_index.to_le_bytes());
        hasher.update(block_hash.as_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest[..32]);
        Some(out)
    }

    fn current_tip_index(&self) -> u64 {
        self.chain.read().get_tip().map(|(idx, _hash)| idx).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocksdb::WriteBatch;
    use sophis_consensus_core::ChainPath;
    use sophis_consensus_core::blockstatus::BlockStatus;
    use sophis_database::create_temp_db;
    use sophis_database::prelude::{CachePolicy, ConnBuilder};
    use sophis_database::utils::DbLifetime;
    use sophis_hashes::Hash;

    use crate::model::stores::selected_chain::SelectedChainStore;

    fn build() -> (DbLifetime, Arc<RwLock<DbSelectedChainStore>>) {
        let (lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = Arc::new(RwLock::new(DbSelectedChainStore::new(db, CachePolicy::Count(64))));
        (lt, store)
    }

    /// Seeds the chain with a sequence of fake block hashes starting at
    /// chain_index 1 (init_with_pruning_point assigns genesis → index 0).
    fn seed_chain(store: &Arc<RwLock<DbSelectedChainStore>>, hashes: &[Hash]) {
        let mut batch = WriteBatch::default();
        // init_with_pruning_point seats genesis at index 0
        let genesis = Hash::from_slice(&[0xAB; 32]);
        store.write().init_with_pruning_point(&mut batch, genesis).unwrap();
        // apply_changes adds new blocks; index assignment is genesis + i + 1
        let changes = ChainPath { added: hashes.to_vec(), removed: Vec::new() };
        store.write().apply_changes(&mut batch, &changes).unwrap();
        // Fake-write to commit; the test DB swallows it.
        let _ = BlockStatus::StatusUTXOValid;
    }

    #[test]
    fn domain_separator_is_frozen() {
        assert_eq!(VRF_DOMAIN_SEPARATOR, b"sophis-vrf-v1\0");
        assert_eq!(VRF_DOMAIN_SEPARATOR.len(), 14);
    }

    #[test]
    fn vrf_is_deterministic() {
        let (_lt, store) = build();
        let hashes = vec![Hash::from_slice(&[1u8; 32]), Hash::from_slice(&[2u8; 32])];
        seed_chain(&store, &hashes);
        let backend = SophisVrfBackend::new(Arc::clone(&store));

        let a1 = backend.vrf_random_at(1).expect("chain_index 1 must resolve");
        let a2 = backend.vrf_random_at(1).expect("chain_index 1 must resolve");
        assert_eq!(a1, a2, "VRF must be deterministic for the same chain_index");
    }

    #[test]
    fn vrf_differs_per_index_even_for_similar_block_hashes() {
        let (_lt, store) = build();
        // Two blocks with very similar hashes
        let mut h1 = [0xAAu8; 32];
        let mut h2 = [0xAAu8; 32];
        h1[31] = 0x00;
        h2[31] = 0x01;
        seed_chain(&store, &[Hash::from_slice(&h1), Hash::from_slice(&h2)]);
        let backend = SophisVrfBackend::new(Arc::clone(&store));

        let a = backend.vrf_random_at(1).expect("chain_index 1");
        let b = backend.vrf_random_at(2).expect("chain_index 2");
        assert_ne!(a, b, "different chain_index must produce different VRF");
    }

    #[test]
    fn vrf_returns_none_for_unknown_chain_index() {
        let (_lt, store) = build();
        let hashes = vec![Hash::from_slice(&[1u8; 32])];
        seed_chain(&store, &hashes);
        let backend = SophisVrfBackend::new(Arc::clone(&store));
        // Index 99 is unseeded.
        assert!(backend.vrf_random_at(99).is_none());
    }

    #[test]
    fn current_tip_index_matches_seeded_count() {
        let (_lt, store) = build();
        let hashes: Vec<Hash> = (0..5).map(|i| Hash::from_slice(&[i as u8; 32])).collect();
        seed_chain(&store, &hashes);
        let backend = SophisVrfBackend::new(Arc::clone(&store));
        // Genesis at 0 + 5 added → tip = 5.
        assert_eq!(backend.current_tip_index(), 5);
    }

    #[test]
    fn vrf_output_includes_domain_separator() {
        // Hand-roll the expected hash for chain_index 1, block hash [7; 32]
        let (_lt, store) = build();
        let block_hash = Hash::from_slice(&[7u8; 32]);
        seed_chain(&store, &[block_hash]);
        let backend = SophisVrfBackend::new(Arc::clone(&store));
        let actual = backend.vrf_random_at(1).expect("chain_index 1");

        let mut hasher = Sha3_384::new();
        hasher.update(VRF_DOMAIN_SEPARATOR);
        hasher.update(1u64.to_le_bytes());
        hasher.update(block_hash.as_bytes());
        let digest = hasher.finalize();
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&digest[..32]);

        assert_eq!(actual, expected, "VRF must equal SHA3-384(domain || index || block_hash)[..32]");
    }
}
