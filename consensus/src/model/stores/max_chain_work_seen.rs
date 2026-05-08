//! Anti long-range attack — `max_chain_work_seen` store.
//!
//! Tracks the highest cumulative `blue_work` that virtual state has ever
//! committed on this node. The value is monotonically non-decreasing:
//! `seen_after = max(seen_before, new_virtual.blue_work)` at every virtual
//! state commit.
//!
//! Used by the header processor: when deciding whether to promote a header
//! to `headers_selected_tip` (the "best known chain" pointer), the candidate
//! must satisfy `header.blue_work >= seen`. A peer announcing a chain whose
//! tip carries less work than what we have already validated locally cannot
//! roll us back.
//!
//! In-memory hot-path access goes through `CachedDbItem`'s internal
//! `Arc<RwLock<Option<BlueWorkType>>>`, so reads after the first hit are a
//! single cheap rwlock read. Boot-time read pulls from disk; absent value
//! (fresh DB) defaults to `BlueWorkType::ZERO`.
//!
//! Persistence is appended to the same `WriteBatch` used by
//! `commit_virtual_state`, so the floor update is atomic with the new
//! virtual state — there is no window where the new state is committed
//! but the floor lags, or vice versa.

use std::sync::Arc;

use rocksdb::WriteBatch;
use sophis_consensus_core::BlueWorkType;
use sophis_database::prelude::DB;
use sophis_database::prelude::StoreResult;
use sophis_database::prelude::{BatchDbWriter, CachedDbItem};
use sophis_database::registry::DatabaseStorePrefixes;

/// Reader API for `MaxChainWorkSeenStore`.
pub trait MaxChainWorkSeenStoreReader {
    /// Returns the persisted floor. A fresh database (no prior virtual state
    /// commit) reports `BlueWorkType::ZERO`.
    fn get(&self) -> BlueWorkType;
}

pub trait MaxChainWorkSeenStore: MaxChainWorkSeenStoreReader {
    /// Atomically merges `candidate` into the floor (`max(current, candidate)`)
    /// inside the supplied `WriteBatch`. Returns the new floor.
    fn update_max_batch(&mut self, batch: &mut WriteBatch, candidate: BlueWorkType) -> StoreResult<BlueWorkType>;
}

/// A DB + cache implementation of `MaxChainWorkSeenStore`.
///
/// The struct is `Clone` so `clone_with_new_cache` mirrors the other store
/// constructors in the project (a fresh in-memory cache layered over the
/// same DB handle is useful for staging consensus and tests).
#[derive(Clone)]
pub struct DbMaxChainWorkSeenStore {
    db: Arc<DB>,
    access: CachedDbItem<BlueWorkType>,
}

impl DbMaxChainWorkSeenStore {
    pub fn new(db: Arc<DB>) -> Self {
        Self { db: Arc::clone(&db), access: CachedDbItem::new(db, DatabaseStorePrefixes::MaxChainWorkSeen.into()) }
    }

    pub fn clone_with_new_cache(&self) -> Self {
        Self::new(Arc::clone(&self.db))
    }
}

impl MaxChainWorkSeenStoreReader for DbMaxChainWorkSeenStore {
    fn get(&self) -> BlueWorkType {
        match self.access.read() {
            Ok(value) => value,
            Err(sophis_database::prelude::StoreError::KeyNotFound(_)) => BlueWorkType::ZERO,
            Err(e) => {
                // RocksDB I/O error reading a 24-byte cell would mean the
                // database is in a worse state than this floor can recover
                // from. Surfacing ZERO would silently disable the protection,
                // so we panic loudly instead.
                panic!("MaxChainWorkSeenStore read failed: {e}");
            }
        }
    }
}

impl MaxChainWorkSeenStore for DbMaxChainWorkSeenStore {
    fn update_max_batch(&mut self, batch: &mut WriteBatch, candidate: BlueWorkType) -> StoreResult<BlueWorkType> {
        let current = self.get();
        let new_floor = if candidate > current { candidate } else { current };
        if new_floor != current {
            self.access.write(BatchDbWriter::new(batch), &new_floor)?;
        }
        Ok(new_floor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sophis_database::create_temp_db;
    use sophis_database::prelude::ConnBuilder;

    /// Helper returns `(lifetime, store)` in that order so that destructuring
    /// at the test call site (`let (_lifetime, store) = fresh_store();`)
    /// places `store` after `_lifetime` in declaration order, ensuring `store`
    /// is dropped before `_lifetime` (Rust drops locals in reverse order).
    fn fresh_store() -> (sophis_database::utils::DbLifetime, DbMaxChainWorkSeenStore) {
        let (lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbMaxChainWorkSeenStore::new(db);
        (lifetime, store)
    }

    #[test]
    fn fresh_store_reports_zero() {
        let (_lifetime, store) = fresh_store();
        assert_eq!(store.get(), BlueWorkType::ZERO);
    }

    #[test]
    fn update_max_only_increases() {
        let (_lifetime, mut store) = fresh_store();

        // First update sets the floor.
        let mut batch = WriteBatch::default();
        let new_floor = store.update_max_batch(&mut batch, BlueWorkType::from_u64(100)).unwrap();
        store.db.write(batch).unwrap();
        assert_eq!(new_floor, BlueWorkType::from_u64(100));
        assert_eq!(store.get(), BlueWorkType::from_u64(100));

        // Higher candidate raises the floor.
        let mut batch = WriteBatch::default();
        let new_floor = store.update_max_batch(&mut batch, BlueWorkType::from_u64(250)).unwrap();
        store.db.write(batch).unwrap();
        assert_eq!(new_floor, BlueWorkType::from_u64(250));
        assert_eq!(store.get(), BlueWorkType::from_u64(250));

        // Lower candidate is ignored — the floor never regresses.
        let mut batch = WriteBatch::default();
        let new_floor = store.update_max_batch(&mut batch, BlueWorkType::from_u64(150)).unwrap();
        store.db.write(batch).unwrap();
        assert_eq!(new_floor, BlueWorkType::from_u64(250));
        assert_eq!(store.get(), BlueWorkType::from_u64(250));

        // Equal candidate is also a no-op (no DB write necessary).
        let mut batch = WriteBatch::default();
        let new_floor = store.update_max_batch(&mut batch, BlueWorkType::from_u64(250)).unwrap();
        store.db.write(batch).unwrap();
        assert_eq!(new_floor, BlueWorkType::from_u64(250));
        assert_eq!(store.get(), BlueWorkType::from_u64(250));
    }

    #[test]
    fn floor_persists_across_reopen() {
        // First handle: write a value.
        let (lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        {
            let mut store = DbMaxChainWorkSeenStore::new(Arc::clone(&db));
            let mut batch = WriteBatch::default();
            store.update_max_batch(&mut batch, BlueWorkType::from_u64(7777)).unwrap();
            db.write(batch).unwrap();
            assert_eq!(store.get(), BlueWorkType::from_u64(7777));
        }
        // New cache, same DB: value is loaded from disk on first read.
        let store_again = DbMaxChainWorkSeenStore::new(Arc::clone(&db));
        assert_eq!(store_again.get(), BlueWorkType::from_u64(7777));
        drop(store_again);
        drop(db);
        drop(lifetime);
    }
}
