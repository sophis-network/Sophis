//! L1 — Address Lookup Table stores.
//!
//! Indexes ALT-creation outputs across three RocksDB column-family-equivalent
//! prefixes. See `database/src/registry.rs` (`AltEntries`,
//! `AltCreatedInBlock`, `AltHandleResolutions` prefixes 200-202) and
//! `docs/L1_ALT_DESIGN.md` §4.
//!
//! All three sub-stores are populated atomically by
//! `DbAltStore::index_alt_creations`, invoked from
//! `virtual_processor::commit_utxo_state` (sub-fase L1.3 pipeline hook).
//!
//! Idempotency: ALT entries are immutable and content-addressed. A second
//! creation with the same handle is a no-op; the first writer always wins.
//! This makes reorg replay safe — re-accepting a block that contains an
//! already-known ALT does nothing.

use rocksdb::WriteBatch;
use sophis_consensus_core::BlockHasher;
use sophis_consensus_core::alt::{AltBlockHandles, AltEntry, AltHandleHash, AltResolution};
use sophis_database::prelude::CachePolicy;
use sophis_database::prelude::DB;
use sophis_database::prelude::StoreError;
use sophis_database::prelude::{BatchDbWriter, CachedDbAccess};
use sophis_database::registry::DatabaseStorePrefixes;
use sophis_hashes::Hash;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Reader trait
// ---------------------------------------------------------------------------

pub trait AltStoreReader {
    fn get_entry(&self, handle: AltHandleHash) -> Result<Option<AltEntry>, StoreError>;
    fn has_entry(&self, handle: AltHandleHash) -> Result<bool, StoreError>;
    fn get_resolution(&self, handle: AltHandleHash) -> Result<Option<AltResolution>, StoreError>;
    fn list_created_in_block(&self, block_hash: Hash) -> Result<Option<AltBlockHandles>, StoreError>;
}

// ---------------------------------------------------------------------------
// DbAltStore
// ---------------------------------------------------------------------------

/// One indexed ALT-creation entry, ready to be inserted into the three ALT
/// columns by `DbAltStore::index_alt_creations`.
#[derive(Debug, Clone)]
pub struct AltCreationIndex {
    pub handle: AltHandleHash,
    pub entry: AltEntry,
}

#[derive(Clone)]
pub struct DbAltStore {
    db: Arc<DB>,
    entries: CachedDbAccess<AltHandleHash, AltEntry>,
    created_in_block: CachedDbAccess<Hash, AltBlockHandles, BlockHasher>,
    resolutions: CachedDbAccess<AltHandleHash, AltResolution>,
}

impl DbAltStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        let entries = CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::AltEntries.into());
        let created_in_block = CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::AltCreatedInBlock.into());
        let resolutions = CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::AltHandleResolutions.into());
        Self { db, entries, created_in_block, resolutions }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    /// Indexes a batch of ALT creations accepted by `accepting_block_hash`.
    /// All three sub-stores are written within the same `WriteBatch` so the
    /// operation is atomic at the RocksDB layer.
    ///
    /// Idempotency: if `handle` already exists in `entries`, this creation
    /// is skipped (no double-insert into resolutions / created_in_block).
    /// Reorgs that re-accept the same chain block re-enter here harmlessly.
    pub fn index_alt_creations(
        &self,
        batch: &mut WriteBatch,
        accepting_block_hash: Hash,
        creations: &[AltCreationIndex],
    ) -> Result<(), StoreError> {
        if creations.is_empty() {
            return Ok(());
        }

        let mut block_handles: Vec<AltHandleHash> = Vec::with_capacity(creations.len());

        for ci in creations {
            // Skip if we already saw this handle (prior block accept, or
            // earlier creation within this same batch). Content-addressed
            // means same bytes ⇒ same handle ⇒ same payload, so the second
            // creator's intent is already satisfied by the first writer.
            if self.entries.has(ci.handle)? {
                continue;
            }

            self.entries.write(BatchDbWriter::new(batch), ci.handle, ci.entry.clone())?;

            let resolution =
                AltResolution { creating_block_hash: ci.entry.creating_block_hash, creating_daa_score: ci.entry.creating_daa_score };
            self.resolutions.write(BatchDbWriter::new(batch), ci.handle, resolution)?;

            block_handles.push(ci.handle);
        }

        // Append to created_in_block index. If the block already had ALTs
        // recorded (e.g. via a partial earlier write), extend rather than
        // overwrite, preserving tx-index order from the caller.
        if !block_handles.is_empty() {
            let mut block_record = match self.created_in_block.read(accepting_block_hash) {
                Ok(b) => b,
                Err(StoreError::KeyNotFound(_)) => AltBlockHandles::default(),
                Err(e) => return Err(e),
            };
            block_record.handles.extend(block_handles);
            self.created_in_block.write(BatchDbWriter::new(batch), accepting_block_hash, block_record)?;
        }

        Ok(())
    }

    /// Direct (non-batched) variant of `index_alt_creations`. Mostly for
    /// tests and ad-hoc reindexing — production callers should always go
    /// through the batched path so other consensus state lands in the same
    /// atomic write.
    pub fn index_alt_creations_direct(&self, accepting_block_hash: Hash, creations: &[AltCreationIndex]) -> Result<(), StoreError> {
        let mut batch = WriteBatch::default();
        self.index_alt_creations(&mut batch, accepting_block_hash, creations)?;
        self.db.write(batch).map_err(StoreError::DbError)?;
        Ok(())
    }

    /// Removes a `created_in_block` row when its block is being pruned.
    /// The `entries` and `resolutions` rows are NOT removed — they live
    /// forever (per design §4.4). Called by pruning logic in L1.3+.
    pub fn forget_block_index(&self, batch: &mut WriteBatch, block_hash: Hash) -> Result<(), StoreError> {
        if self.created_in_block.has(block_hash)? {
            self.created_in_block.delete(BatchDbWriter::new(batch), block_hash)?;
        }
        Ok(())
    }
}

impl AltStoreReader for DbAltStore {
    fn get_entry(&self, handle: AltHandleHash) -> Result<Option<AltEntry>, StoreError> {
        match self.entries.read(handle) {
            Ok(e) => Ok(Some(e)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn has_entry(&self, handle: AltHandleHash) -> Result<bool, StoreError> {
        self.entries.has(handle)
    }

    fn get_resolution(&self, handle: AltHandleHash) -> Result<Option<AltResolution>, StoreError> {
        match self.resolutions.read(handle) {
            Ok(r) => Ok(Some(r)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn list_created_in_block(&self, block_hash: Hash) -> Result<Option<AltBlockHandles>, StoreError> {
        match self.created_in_block.read(block_hash) {
            Ok(b) => Ok(Some(b)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sophis_consensus_core::alt::{ALT_HANDLE_LEN, AltEntryRecord};
    use sophis_database::create_temp_db;
    use sophis_database::prelude::ConnBuilder;
    use sophis_database::utils::DbLifetime;

    // Tuple order is intentional: Rust drops bindings in reverse — `store`
    // (last) drops first and releases its Arc<DB> clones before `lifetime`
    // checks `Arc::strong_count == 0`.
    fn build_store() -> (DbLifetime, DbAltStore) {
        let (lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbAltStore::new(db, CachePolicy::Count(64));
        (lifetime, store)
    }

    fn make_entry(handle: AltHandleHash, block: Hash, daa_score: u64, n_records: usize) -> AltEntry {
        let entries: Vec<AltEntryRecord> =
            (0..n_records).map(|i| AltEntryRecord { spk_version: 0, spk_script: vec![i as u8; 16] }).collect();
        AltEntry { handle, entries, creating_block_hash: block, creating_daa_score: daa_score }
    }

    #[test]
    fn round_trip_single_creation() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[1u8; 32]);
        let h = AltHandleHash([0xABu8; ALT_HANDLE_LEN]);
        let entry = make_entry(h, block, 100, 3);
        store.index_alt_creations_direct(block, &[AltCreationIndex { handle: h, entry: entry.clone() }]).unwrap();

        // entries
        let read = store.get_entry(h).unwrap().unwrap();
        assert_eq!(read.handle, h);
        assert_eq!(read.entries.len(), 3);
        assert!(store.has_entry(h).unwrap());

        // resolutions
        let res = store.get_resolution(h).unwrap().unwrap();
        assert_eq!(res.creating_block_hash, block);
        assert_eq!(res.creating_daa_score, 100);

        // created_in_block
        let bc = store.list_created_in_block(block).unwrap().unwrap();
        assert_eq!(bc.handles, vec![h]);
    }

    #[test]
    fn missing_keys_return_none_not_err() {
        let (_lt, store) = build_store();
        assert!(store.get_entry(AltHandleHash([0u8; ALT_HANDLE_LEN])).unwrap().is_none());
        assert!(store.get_resolution(AltHandleHash([1u8; ALT_HANDLE_LEN])).unwrap().is_none());
        assert!(store.list_created_in_block(Hash::from_slice(&[2u8; 32])).unwrap().is_none());
        assert!(!store.has_entry(AltHandleHash([3u8; ALT_HANDLE_LEN])).unwrap());
    }

    #[test]
    fn duplicate_handle_is_idempotent() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[3u8; 32]);
        let h = AltHandleHash([0xEFu8; ALT_HANDLE_LEN]);
        let entry = make_entry(h, block, 50, 2);
        // Insert twice
        store.index_alt_creations_direct(block, &[AltCreationIndex { handle: h, entry: entry.clone() }]).unwrap();
        store.index_alt_creations_direct(block, &[AltCreationIndex { handle: h, entry }]).unwrap();
        // Block index should still have only one entry (no double-insert)
        let bc = store.list_created_in_block(block).unwrap().unwrap();
        assert_eq!(bc.handles.len(), 1);
        assert_eq!(bc.handles[0], h);
    }

    #[test]
    fn block_index_extends_on_repeated_calls_with_new_handles() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[4u8; 32]);
        let h1 = AltHandleHash([1u8; ALT_HANDLE_LEN]);
        let h2 = AltHandleHash([2u8; ALT_HANDLE_LEN]);
        store.index_alt_creations_direct(block, &[AltCreationIndex { handle: h1, entry: make_entry(h1, block, 0, 1) }]).unwrap();
        store.index_alt_creations_direct(block, &[AltCreationIndex { handle: h2, entry: make_entry(h2, block, 0, 1) }]).unwrap();
        let bc = store.list_created_in_block(block).unwrap().unwrap();
        assert_eq!(bc.handles.len(), 2);
        assert!(bc.handles.contains(&h1));
        assert!(bc.handles.contains(&h2));
    }

    #[test]
    fn batch_creation_writes_atomically() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[5u8; 32]);
        let h1 = AltHandleHash([1u8; ALT_HANDLE_LEN]);
        let h2 = AltHandleHash([2u8; ALT_HANDLE_LEN]);
        let h3 = AltHandleHash([3u8; ALT_HANDLE_LEN]);
        let cs = vec![
            AltCreationIndex { handle: h1, entry: make_entry(h1, block, 10, 1) },
            AltCreationIndex { handle: h2, entry: make_entry(h2, block, 11, 2) },
            AltCreationIndex { handle: h3, entry: make_entry(h3, block, 12, 3) },
        ];
        store.index_alt_creations_direct(block, &cs).unwrap();
        // All three present
        for h in [h1, h2, h3] {
            assert!(store.has_entry(h).unwrap());
            assert!(store.get_resolution(h).unwrap().is_some());
        }
        let bc = store.list_created_in_block(block).unwrap().unwrap();
        assert_eq!(bc.handles, vec![h1, h2, h3]);
    }

    #[test]
    fn empty_creation_batch_is_noop() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[6u8; 32]);
        store.index_alt_creations_direct(block, &[]).unwrap();
        // Block has no row written.
        assert!(store.list_created_in_block(block).unwrap().is_none());
    }

    #[test]
    fn forget_block_index_removes_created_in_block_row() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[7u8; 32]);
        let h = AltHandleHash([0xAAu8; ALT_HANDLE_LEN]);
        store.index_alt_creations_direct(block, &[AltCreationIndex { handle: h, entry: make_entry(h, block, 0, 1) }]).unwrap();
        assert!(store.list_created_in_block(block).unwrap().is_some());

        let mut batch = WriteBatch::default();
        store.forget_block_index(&mut batch, block).unwrap();
        store.db.write(batch).unwrap();

        assert!(store.list_created_in_block(block).unwrap().is_none());
        // entries and resolutions survive (immutability per §4.4)
        assert!(store.has_entry(h).unwrap());
        assert!(store.get_resolution(h).unwrap().is_some());
    }

    #[test]
    fn forget_block_index_on_missing_row_is_noop() {
        let (_lt, store) = build_store();
        let mut batch = WriteBatch::default();
        store.forget_block_index(&mut batch, Hash::from_slice(&[8u8; 32])).unwrap();
        // Should not error; just produce an empty (or near-empty) batch.
        store.db.write(batch).unwrap();
    }

    #[test]
    fn alt_with_max_size_entries_round_trips() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[9u8; 32]);
        let h = AltHandleHash([0xCCu8; ALT_HANDLE_LEN]);
        // 256 entries, each 64 bytes — well below 4096 cap; total ~16 KB.
        let entries: Vec<AltEntryRecord> =
            (0..256).map(|i| AltEntryRecord { spk_version: (i % 6) as u16, spk_script: vec![i as u8; 64] }).collect();
        let entry = AltEntry { handle: h, entries, creating_block_hash: block, creating_daa_score: 999 };
        store.index_alt_creations_direct(block, &[AltCreationIndex { handle: h, entry: entry.clone() }]).unwrap();
        let read = store.get_entry(h).unwrap().unwrap();
        assert_eq!(read.entries.len(), 256);
        assert_eq!(read.entries[42].spk_script.len(), 64);
        assert_eq!(read.entries[42].spk_script[0], 42);
    }

    #[test]
    fn idempotent_creation_still_writes_block_index_for_first_writer() {
        let (_lt, store) = build_store();
        let block_a = Hash::from_slice(&[10u8; 32]);
        let block_b = Hash::from_slice(&[11u8; 32]);
        let h = AltHandleHash([0x55u8; ALT_HANDLE_LEN]);
        // First creation in block A
        store.index_alt_creations_direct(block_a, &[AltCreationIndex { handle: h, entry: make_entry(h, block_a, 0, 1) }]).unwrap();
        // Second creation (same handle) in block B — handle already exists, skipped
        store.index_alt_creations_direct(block_b, &[AltCreationIndex { handle: h, entry: make_entry(h, block_b, 0, 1) }]).unwrap();
        // Block A has the handle, block B does not (because the second creation was skipped)
        assert_eq!(store.list_created_in_block(block_a).unwrap().unwrap().handles, vec![h]);
        assert!(store.list_created_in_block(block_b).unwrap().is_none());
        // Resolution still points to block A (first writer wins)
        let res = store.get_resolution(h).unwrap().unwrap();
        assert_eq!(res.creating_block_hash, block_a);
    }
}
