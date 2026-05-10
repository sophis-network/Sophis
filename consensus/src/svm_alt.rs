//! L1 — sVM `HostAlt` backend bound to the consensus ALT store.
//!
//! Lives in the consensus crate (not in `svm/host`) because it needs
//! `DbAltStore`, which is consensus-internal. `svm/host` stays purely
//! crypto-stateless. Construction captures only the store handle; lookups
//! are deterministic at consensus time because the ALT store is populated
//! during virtual_processor commit (sub-fase L1.3.d) before any contract
//! runs against the same chain block.
//!
//! ABI (mirrored by `sophis_alt_lookup` host fn): on hit, the resolved
//! `ScriptPublicKey` script bytes are written into the caller's buffer
//! and the `ScriptPublicKey` version is returned via the host-fn return
//! value. On miss, the buffer is left empty and the host fn returns the
//! corresponding negative status code.

use std::sync::Arc;

use sophis_consensus_core::alt::AltHandleHash;
use sophis_svm_runtime::HostAlt;

use crate::model::stores::alt::{AltStoreReader, DbAltStore};

/// Real `HostAlt` impl backed by the consensus ALT store.
pub struct SophisAltBackend {
    store: Arc<DbAltStore>,
}

impl SophisAltBackend {
    pub fn new(store: Arc<DbAltStore>) -> Self {
        Self { store }
    }
}

impl HostAlt for SophisAltBackend {
    fn resolve_reference(&self, handle: &[u8; 6], index: u8, out: &mut Vec<u8>) -> Option<u16> {
        out.clear();
        let entry = match self.store.get_entry(AltHandleHash::new(*handle)) {
            Ok(Some(e)) => e,
            _ => return None,
        };
        let record = entry.entries.get(index as usize)?;
        out.extend_from_slice(&record.spk_script);
        Some(record.spk_version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::stores::alt::{AltCreationIndex, DbAltStore};
    use sophis_consensus_core::alt::{AltEntry, AltEntryRecord};
    use sophis_database::create_temp_db;
    use sophis_database::prelude::{CachePolicy, ConnBuilder};
    use sophis_database::utils::DbLifetime;
    use sophis_hashes::Hash;

    fn build() -> (DbLifetime, Arc<DbAltStore>) {
        let (lt, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = Arc::new(DbAltStore::new(db, CachePolicy::Count(64)));
        (lt, store)
    }

    fn seed_alt(store: &DbAltStore, handle: [u8; 6], entries: Vec<(u16, Vec<u8>)>) {
        let block = Hash::from_slice(&[0xAB; 32]);
        let entry = AltEntry {
            handle: AltHandleHash::new(handle),
            entries: entries.into_iter().map(|(v, b)| AltEntryRecord { spk_version: v, spk_script: b }).collect(),
            creating_block_hash: block,
            creating_daa_score: 1,
        };
        store.index_alt_creations_direct(block, &[AltCreationIndex { handle: AltHandleHash::new(handle), entry }]).unwrap();
    }

    #[test]
    fn resolve_reference_returns_spk_on_hit() {
        let (_lt, store) = build();
        let handle = [0xDEu8, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        seed_alt(&store, handle, vec![(0, vec![0xAA, 0xBB, 0xCC]), (5, vec![1, 2, 3, 4, 5])]);
        let backend = SophisAltBackend::new(Arc::clone(&store));

        let mut out = Vec::new();
        let v = backend.resolve_reference(&handle, 0, &mut out).expect("entry 0 must resolve");
        assert_eq!(v, 0);
        assert_eq!(out, vec![0xAA, 0xBB, 0xCC]);

        out.clear();
        let v = backend.resolve_reference(&handle, 1, &mut out).expect("entry 1 must resolve");
        assert_eq!(v, 5);
        assert_eq!(out, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn resolve_reference_returns_none_for_unknown_handle() {
        let (_lt, store) = build();
        let backend = SophisAltBackend::new(store);
        let mut out = vec![0xFFu8; 16]; // ensure backend clears
        assert_eq!(backend.resolve_reference(&[0u8; 6], 0, &mut out), None);
        assert!(out.is_empty(), "out must be cleared on miss");
    }

    #[test]
    fn resolve_reference_returns_none_for_out_of_range_index() {
        let (_lt, store) = build();
        let handle = [1u8; 6];
        seed_alt(&store, handle, vec![(0, vec![0xAA])]);
        let backend = SophisAltBackend::new(store);
        let mut out = Vec::new();
        assert!(backend.resolve_reference(&handle, 0, &mut out).is_some());
        assert_eq!(backend.resolve_reference(&handle, 1, &mut out), None);
    }

    #[test]
    fn resolve_reference_handles_empty_script_entry() {
        let (_lt, store) = build();
        let handle = [2u8; 6];
        seed_alt(&store, handle, vec![(7, vec![])]);
        let backend = SophisAltBackend::new(store);
        let mut out = vec![0xCCu8; 8];
        let v = backend.resolve_reference(&handle, 0, &mut out).expect("empty entry resolves");
        assert_eq!(v, 7);
        assert!(out.is_empty(), "empty spk_script clears caller buffer");
    }
}
