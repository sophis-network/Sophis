//! K2 — Compact Block Filters store (BIP-157/158-equivalent).
//!
//! Two RocksDB prefixes:
//!   * `BlockFilters = 207`        — `block_hash → BlockFilter`
//!   * `BlockFilterHeaders = 208`  — `block_hash → BlockFilterHeader`
//!
//! Both are populated atomically by `index_filters_in_block` from
//! `virtual_processor::commit_utxo_state` (sub-fase K2.3). See
//! `docs/K2_COMPACT_FILTERS_DESIGN.md` §3 for the canonical algorithm.
//!
//! Idempotency: filters are derived deterministically from chain
//! state. A second commit of the same chain block produces byte-equal
//! filter bytes and overwrites the existing rows with the same bytes
//! — re-acceptance on a reorg is safe.

use borsh::{BorshDeserialize, BorshSerialize};
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use sophis_consensus_core::BlockHasher;
use sophis_database::prelude::CachePolicy;
use sophis_database::prelude::DB;
use sophis_database::prelude::StoreError;
use sophis_database::prelude::{BatchDbWriter, CachedDbAccess};
use sophis_database::registry::DatabaseStorePrefixes;
use sophis_hashes::Hash;
use sophis_utils::mem_size::MemSizeEstimator;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Stored types
// ---------------------------------------------------------------------------

/// Per-block filter as persisted. Carries the on-the-wire filter
/// bytes (compact-size element count + Golomb-Rice bitstream) and the
/// 32-byte `SHA3-384(filter_bytes)[..32]` so RPC consumers can verify
/// the bytes against the header chain without rehashing.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct BlockFilter {
    pub filter_bytes: Vec<u8>,
    pub filter_hash: [u8; 32],
}

impl MemSizeEstimator for BlockFilter {
    fn estimate_mem_bytes(&self) -> usize {
        size_of::<Self>() + self.filter_bytes.capacity()
    }
}

/// Per-block filter header as persisted. Carries:
/// * `prev_header`  — `filter_header` of the GHOSTDAG selected parent
/// * `filter_hash`  — `SHA3-384(filter_bytes)[..32]` of *this* block
/// * `filter_header` — `SHA3-384(prev_header || filter_hash)[..32]`
///
/// The triple is enough for a light client to (a) verify a filter it
/// fetched separately and (b) chain to the next block's header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct BlockFilterHeader {
    pub prev_header: [u8; 32],
    pub filter_hash: [u8; 32],
    pub filter_header: [u8; 32],
}

impl MemSizeEstimator for BlockFilterHeader {}

// ---------------------------------------------------------------------------
// Reader trait
// ---------------------------------------------------------------------------

pub trait BlockFiltersStoreReader {
    fn get_filter(&self, block_hash: Hash) -> Result<Option<BlockFilter>, StoreError>;
    fn get_filter_header(&self, block_hash: Hash) -> Result<Option<BlockFilterHeader>, StoreError>;
}

// ---------------------------------------------------------------------------
// DbBlockFiltersStore
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DbBlockFiltersStore {
    db: Arc<DB>,
    filters: CachedDbAccess<Hash, BlockFilter, BlockHasher>,
    headers: CachedDbAccess<Hash, BlockFilterHeader, BlockHasher>,
}

impl DbBlockFiltersStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        let filters = CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::BlockFilters.into());
        let headers = CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::BlockFilterHeaders.into());
        Self { db, filters, headers }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    /// Indexes one block's filter + header atomically into the batched
    /// `WriteBatch`. Caller (commit hook) is responsible for the actual
    /// `db.write(batch)`.
    pub fn index_filter(
        &self,
        batch: &mut WriteBatch,
        block_hash: Hash,
        filter: BlockFilter,
        header: BlockFilterHeader,
    ) -> Result<(), StoreError> {
        self.filters.write(BatchDbWriter::new(batch), block_hash, filter)?;
        self.headers.write(BatchDbWriter::new(batch), block_hash, header)?;
        Ok(())
    }

    /// Direct (non-batched) variant for tests + ad-hoc reindexing.
    pub fn index_filter_direct(
        &self,
        block_hash: Hash,
        filter: BlockFilter,
        header: BlockFilterHeader,
    ) -> Result<(), StoreError> {
        let mut batch = WriteBatch::default();
        self.index_filter(&mut batch, block_hash, filter, header)?;
        self.db.write(batch).map_err(StoreError::DbError)?;
        Ok(())
    }

    /// Removes the filter bytes for a pruned block. The filter header
    /// is NOT touched per design §6 — header chain stays intact for
    /// SPV resync.
    pub fn forget_filter_for_pruned_block(&self, batch: &mut WriteBatch, block_hash: Hash) -> Result<(), StoreError> {
        if self.filters.has(block_hash)? {
            self.filters.delete(BatchDbWriter::new(batch), block_hash)?;
        }
        Ok(())
    }
}

impl BlockFiltersStoreReader for DbBlockFiltersStore {
    fn get_filter(&self, block_hash: Hash) -> Result<Option<BlockFilter>, StoreError> {
        match self.filters.read(block_hash) {
            Ok(f) => Ok(Some(f)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn get_filter_header(&self, block_hash: Hash) -> Result<Option<BlockFilterHeader>, StoreError> {
        match self.headers.read(block_hash) {
            Ok(h) => Ok(Some(h)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sophis_database::create_temp_db;
    use sophis_database::prelude::ConnBuilder;
    use sophis_database::utils::DbLifetime;

    fn build_store() -> (DbLifetime, DbBlockFiltersStore) {
        let (lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbBlockFiltersStore::new(db, CachePolicy::Count(64));
        (lifetime, store)
    }

    fn sample_filter() -> BlockFilter {
        BlockFilter { filter_bytes: vec![0x01, 0x02, 0x03], filter_hash: [0xAB; 32] }
    }

    fn sample_header() -> BlockFilterHeader {
        BlockFilterHeader { prev_header: [0x10; 32], filter_hash: [0xAB; 32], filter_header: [0xCD; 32] }
    }

    #[test]
    fn round_trip_single_block() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[1u8; 32]);
        store.index_filter_direct(block, sample_filter(), sample_header()).unwrap();
        assert_eq!(store.get_filter(block).unwrap(), Some(sample_filter()));
        assert_eq!(store.get_filter_header(block).unwrap(), Some(sample_header()));
    }

    #[test]
    fn missing_block_returns_none() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[2u8; 32]);
        assert!(store.get_filter(block).unwrap().is_none());
        assert!(store.get_filter_header(block).unwrap().is_none());
    }

    #[test]
    fn forget_prunes_filter_keeps_header() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[3u8; 32]);
        store.index_filter_direct(block, sample_filter(), sample_header()).unwrap();
        let mut batch = WriteBatch::default();
        store.forget_filter_for_pruned_block(&mut batch, block).unwrap();
        store.db.write(batch).unwrap();
        assert!(store.get_filter(block).unwrap().is_none(), "filter pruned");
        assert!(store.get_filter_header(block).unwrap().is_some(), "header survives pruning");
    }

    #[test]
    fn re_index_overwrites_with_same_bytes() {
        // Determinism check: re-indexing the same (block, filter, header)
        // is a no-op semantically.
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[4u8; 32]);
        store.index_filter_direct(block, sample_filter(), sample_header()).unwrap();
        store.index_filter_direct(block, sample_filter(), sample_header()).unwrap();
        assert_eq!(store.get_filter(block).unwrap(), Some(sample_filter()));
    }

    #[test]
    fn forget_missing_block_is_noop() {
        let (_lt, store) = build_store();
        let mut batch = WriteBatch::default();
        store.forget_filter_for_pruned_block(&mut batch, Hash::from_slice(&[99u8; 32])).unwrap();
        // Empty batch write is fine.
        store.db.write(batch).unwrap();
    }

    #[test]
    fn block_filter_estimates_capacity() {
        let bf = BlockFilter { filter_bytes: vec![0u8; 1000], filter_hash: [0; 32] };
        // The estimate should at least exceed the bare struct size.
        assert!(bf.estimate_mem_bytes() >= size_of::<BlockFilter>());
    }
}
