//! Phase 6 — Data Availability stores.
//!
//! Indexes V5 carrier outputs across four RocksDB column-family-equivalent
//! prefixes. See `database/src/registry.rs` (DaCarrier* prefixes 196-199)
//! and `oracle/docs/PHASE6_DA_DESIGN.md` §6.
//!
//! All four sub-stores are populated atomically by `DbDaStore::index_carrier_batch`,
//! invoked from `virtual_processor::commit_utxo_state` (sub-fase 6.2.b
//! pipeline hook).

use rocksdb::WriteBatch;
use sophis_consensus_core::BlockHasher;
use sophis_consensus_core::da::{
    BlockCarriers, BundleIndex, DOMAIN_BUCKET_SIZE, DomainBucket, PayloadEntry, PayloadIdHash, domain_bucket_key_bytes,
};
use sophis_database::prelude::CachePolicy;
use sophis_database::prelude::DB;
use sophis_database::prelude::StoreError;
use sophis_database::prelude::{BatchDbWriter, CachedDbAccess, DirectDbWriter};
use sophis_database::registry::DatabaseStorePrefixes;
use sophis_hashes::Hash;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Key wrappers
// ---------------------------------------------------------------------------

/// Composite key for the `DaCarrierByDomain` index: `[domain_byte, bucket_le_8B]`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct DomainBucketKey(pub [u8; 9]);

impl DomainBucketKey {
    pub fn new(domain_byte: u8, blue_score: u64) -> Self {
        Self(domain_bucket_key_bytes(domain_byte, blue_score))
    }
}

impl AsRef<[u8]> for DomainBucketKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for DomainBucketKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bucket = u64::from_le_bytes(self.0[1..].try_into().unwrap());
        write!(f, "DomainBucketKey(domain=0x{:02x}, bucket={bucket})", self.0[0])
    }
}

// ---------------------------------------------------------------------------
// Reader / writer traits
// ---------------------------------------------------------------------------

pub trait DaStoreReader {
    fn get_payload(&self, payload_id: PayloadIdHash) -> Result<Option<PayloadEntry>, StoreError>;
    fn has_payload(&self, payload_id: PayloadIdHash) -> Result<bool, StoreError>;
    fn get_bundle(&self, bundle_id: PayloadIdHash) -> Result<Option<BundleIndex>, StoreError>;
    fn list_by_block(&self, block_hash: Hash) -> Result<Option<BlockCarriers>, StoreError>;
    fn list_by_domain(&self, domain_byte: u8, blue_score: u64) -> Result<Option<DomainBucket>, StoreError>;
}

// ---------------------------------------------------------------------------
// DbDaStore — unified handle to the four sub-stores
// ---------------------------------------------------------------------------

/// One indexed carrier fragment, ready to be inserted into the four DA
/// columns by `DbDaStore::index_carrier_batch`.
#[derive(Debug, Clone)]
pub struct CarrierIndex {
    pub payload_id: PayloadIdHash,
    pub entry: PayloadEntry,
}

#[derive(Clone)]
pub struct DbDaStore {
    db: Arc<DB>,
    payloads: CachedDbAccess<PayloadIdHash, PayloadEntry>,
    bundles: CachedDbAccess<PayloadIdHash, BundleIndex>,
    by_block: CachedDbAccess<Hash, BlockCarriers, BlockHasher>,
    by_domain: CachedDbAccess<DomainBucketKey, DomainBucket>,
}

impl DbDaStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        let payloads = CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::DaCarrierPayloads.into());
        let bundles = CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::DaCarrierBundles.into());
        let by_block = CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::DaCarrierByBlock.into());
        let by_domain = CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::DaCarrierByDomain.into());
        Self { db, payloads, bundles, by_block, by_domain }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    /// Indexes a batch of carrier fragments accepted by `accepting_block_hash`
    /// at `blue_score`. All four sub-stores are written within the same
    /// `WriteBatch` so the operation is atomic at the RocksDB layer.
    ///
    /// Idempotency: if `payload_id` already exists in `payloads`, this
    /// fragment is skipped (no double-insert into bundle / by_block /
    /// by_domain). Reorgs that re-accept the same chain block re-enter
    /// here harmlessly.
    pub fn index_carrier_batch(
        &self,
        batch: &mut WriteBatch,
        accepting_block_hash: Hash,
        carriers: &[CarrierIndex],
    ) -> Result<(), StoreError> {
        if carriers.is_empty() {
            return Ok(());
        }

        // Deduplicate within this batch by payload_id.
        let mut block_payload_ids: Vec<PayloadIdHash> = Vec::with_capacity(carriers.len());

        for ci in carriers {
            // Skip if we already saw this payload_id (prior block accept,
            // or earlier carrier within this same batch).
            if self.payloads.has(ci.payload_id)? {
                continue;
            }
            self.payloads.write(BatchDbWriter::new(batch), ci.payload_id, ci.entry.clone())?;
            block_payload_ids.push(ci.payload_id);

            // Append to bundle index. Read-modify-write; later fragments
            // extend the same vector in-place.
            let mut bundle = match self.bundles.read(ci.entry.bundle_id) {
                Ok(b) => b,
                Err(StoreError::KeyNotFound(_)) => BundleIndex { fragment_count: ci.entry.fragment_count, payload_ids: Vec::new() },
                Err(e) => return Err(e),
            };
            // Defensive: a producer that lies about fragment_count across
            // fragments with the same bundle_id would corrupt the index.
            // Trust the first writer; ignore later mismatches.
            bundle.payload_ids.push(ci.payload_id);
            // Keep the index ordered by fragment_index to keep reassembly cheap.
            bundle.payload_ids.sort_by_key(|p| {
                // Lookup the entry to extract fragment_index. For the
                // entry we just wrote, we already know it; for older
                // entries we read on demand.
                if *p == ci.payload_id {
                    ci.entry.fragment_index as u32
                } else {
                    match self.payloads.read(*p) {
                        Ok(e) => e.fragment_index as u32,
                        Err(_) => u32::MAX, // tolerate; missing rows are out-of-band
                    }
                }
            });
            self.bundles.write(BatchDbWriter::new(batch), ci.entry.bundle_id, bundle)?;

            // Append to by_domain index for non-zero domain bytes.
            // Unclassified (domain_byte == 0) carriers are not indexed by
            // domain — they only show up in the global stream via by_block.
            if ci.entry.domain_byte != 0 {
                let bucket_key = DomainBucketKey::new(ci.entry.domain_byte, ci.entry.blue_score);
                let mut bucket = match self.by_domain.read(bucket_key) {
                    Ok(b) => b,
                    Err(StoreError::KeyNotFound(_)) => DomainBucket::default(),
                    Err(e) => return Err(e),
                };
                bucket.payload_ids.push(ci.payload_id);
                self.by_domain.write(BatchDbWriter::new(batch), bucket_key, bucket)?;
            }
        }

        // Append to by_block index. If the block already had carriers
        // recorded (e.g. via a partial earlier write), extend rather than
        // overwrite.
        if !block_payload_ids.is_empty() {
            let mut block_carriers = match self.by_block.read(accepting_block_hash) {
                Ok(b) => b,
                Err(StoreError::KeyNotFound(_)) => BlockCarriers::default(),
                Err(e) => return Err(e),
            };
            block_carriers.payload_ids.extend(block_payload_ids);
            self.by_block.write(BatchDbWriter::new(batch), accepting_block_hash, block_carriers)?;
        }

        Ok(())
    }
}

impl DaStoreReader for DbDaStore {
    fn get_payload(&self, payload_id: PayloadIdHash) -> Result<Option<PayloadEntry>, StoreError> {
        match self.payloads.read(payload_id) {
            Ok(e) => Ok(Some(e)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn has_payload(&self, payload_id: PayloadIdHash) -> Result<bool, StoreError> {
        self.payloads.has(payload_id)
    }

    fn get_bundle(&self, bundle_id: PayloadIdHash) -> Result<Option<BundleIndex>, StoreError> {
        match self.bundles.read(bundle_id) {
            Ok(b) => Ok(Some(b)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn list_by_block(&self, block_hash: Hash) -> Result<Option<BlockCarriers>, StoreError> {
        match self.by_block.read(block_hash) {
            Ok(b) => Ok(Some(b)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn list_by_domain(&self, domain_byte: u8, blue_score: u64) -> Result<Option<DomainBucket>, StoreError> {
        let key = DomainBucketKey::new(domain_byte, blue_score);
        match self.by_domain.read(key) {
            Ok(b) => Ok(Some(b)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Direct (non-batched) writer used in tests and admin tooling.
// ---------------------------------------------------------------------------

impl DbDaStore {
    /// Direct (non-batched) variant of `index_carrier_batch`. Mostly for tests
    /// and ad-hoc reindexing — production callers should always go through
    /// the batched path so other consensus state lands in the same atomic
    /// write.
    pub fn index_carrier_direct(&self, accepting_block_hash: Hash, carriers: &[CarrierIndex]) -> Result<(), StoreError> {
        let mut batch = WriteBatch::default();
        self.index_carrier_batch(&mut batch, accepting_block_hash, carriers)?;
        // We can't use BatchDbWriter outside a real WriteBatch context; the
        // simplest path is to hand the batch to the DB.
        self.db.write(batch).map_err(StoreError::DbError)?;
        Ok(())
    }

    /// Re-exposes the underlying `DirectDbWriter` shape used by other
    /// stores. Currently unused — kept alongside `index_carrier_direct`
    /// for symmetry with `acceptance_data` etc.
    #[doc(hidden)]
    pub fn _direct_writer(&self) -> DirectDbWriter<'_> {
        DirectDbWriter::new(&self.db)
    }
}

#[allow(dead_code)]
const _CACHE_POLICY_HINT: u64 = DOMAIN_BUCKET_SIZE; // surface symbol for grep audits

#[cfg(test)]
mod tests {
    use super::*;
    use sophis_database::create_temp_db;
    use sophis_database::prelude::ConnBuilder;
    use sophis_database::utils::DbLifetime;

    // Tuple order is intentional: Rust drops bindings in reverse — `store`
    // (last) drops first and releases its Arc<DB> clones before `lifetime`
    // checks `Arc::strong_count == 0`.
    fn build_store() -> (DbLifetime, DbDaStore) {
        let (lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbDaStore::new(db, CachePolicy::Count(64));
        (lifetime, store)
    }

    fn make_entry(
        bundle_id: PayloadIdHash,
        block: Hash,
        blue_score: u64,
        fragment_index: u8,
        fragment_count: u8,
        domain_byte: u8,
    ) -> PayloadEntry {
        PayloadEntry {
            script: vec![0xAA; 100],
            accepting_block_hash: block,
            blue_score,
            fragment_index,
            fragment_count,
            bundle_id,
            domain_byte,
        }
    }

    #[test]
    fn round_trip_single_payload() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[1u8; 32]);
        let pid = PayloadIdHash([0xAB; 48]);
        let bid = PayloadIdHash([0xCD; 48]);
        let entry = make_entry(bid, block, 100, 0, 1, sophis_consensus_core::da::CARRIER_FLAG_DOMAIN_ROLLUP);
        store.index_carrier_direct(block, &[CarrierIndex { payload_id: pid, entry: entry.clone() }]).unwrap();

        // payloads
        let read = store.get_payload(pid).unwrap().unwrap();
        assert_eq!(read.bundle_id, bid);
        assert_eq!(read.blue_score, 100);
        assert!(store.has_payload(pid).unwrap());

        // bundles
        let bundle = store.get_bundle(bid).unwrap().unwrap();
        assert_eq!(bundle.fragment_count, 1);
        assert_eq!(bundle.payload_ids, vec![pid]);

        // by_block
        let bc = store.list_by_block(block).unwrap().unwrap();
        assert_eq!(bc.payload_ids, vec![pid]);

        // by_domain (rollup bucket)
        let dom = store.list_by_domain(sophis_consensus_core::da::CARRIER_FLAG_DOMAIN_ROLLUP, 100).unwrap().unwrap();
        assert_eq!(dom.payload_ids, vec![pid]);
    }

    #[test]
    fn missing_keys_return_none_not_err() {
        let (_lt, store) = build_store();
        assert!(store.get_payload(PayloadIdHash([0u8; 48])).unwrap().is_none());
        assert!(store.get_bundle(PayloadIdHash([1u8; 48])).unwrap().is_none());
        assert!(store.list_by_block(Hash::from_slice(&[2u8; 32])).unwrap().is_none());
        assert!(store.list_by_domain(0x10, 0).unwrap().is_none());
    }

    #[test]
    fn duplicate_payload_id_is_idempotent() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[3u8; 32]);
        let pid = PayloadIdHash([0xEF; 48]);
        let bid = PayloadIdHash([0x12; 48]);
        let entry = make_entry(bid, block, 50, 0, 1, 0);
        // Insert twice
        store.index_carrier_direct(block, &[CarrierIndex { payload_id: pid, entry: entry.clone() }]).unwrap();
        store.index_carrier_direct(block, &[CarrierIndex { payload_id: pid, entry }]).unwrap();
        // Bundle should still have only one entry
        let bundle = store.get_bundle(bid).unwrap().unwrap();
        assert_eq!(bundle.payload_ids.len(), 1);
        // Block should still have only one entry
        let bc = store.list_by_block(block).unwrap().unwrap();
        assert_eq!(bc.payload_ids.len(), 1);
    }

    #[test]
    fn bundle_aggregates_multiple_fragments_sorted() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[4u8; 32]);
        let bid = PayloadIdHash([0x77; 48]);
        // Insert 3 fragments out of order: index 2 first, then 0, then 1
        let p2 = PayloadIdHash([2u8; 48]);
        let p0 = PayloadIdHash([0u8; 48]);
        let p1 = PayloadIdHash([1u8; 48]);
        let mk = |pid, idx| CarrierIndex { payload_id: pid, entry: make_entry(bid, block, 0, idx, 3, 0) };
        store.index_carrier_direct(block, &[mk(p2, 2)]).unwrap();
        store.index_carrier_direct(block, &[mk(p0, 0)]).unwrap();
        store.index_carrier_direct(block, &[mk(p1, 1)]).unwrap();

        let bundle = store.get_bundle(bid).unwrap().unwrap();
        assert_eq!(bundle.fragment_count, 3);
        assert_eq!(bundle.payload_ids.len(), 3);
        // Sorted by fragment_index after each insertion
        assert_eq!(bundle.payload_ids[0], p0);
        assert_eq!(bundle.payload_ids[1], p1);
        assert_eq!(bundle.payload_ids[2], p2);
    }

    #[test]
    fn unclassified_domain_byte_skips_by_domain_index() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[5u8; 32]);
        let pid = PayloadIdHash([0x88; 48]);
        let bid = PayloadIdHash([0x99; 48]);
        let entry = make_entry(bid, block, 0, 0, 1, 0); // domain_byte = 0
        store.index_carrier_direct(block, &[CarrierIndex { payload_id: pid, entry }]).unwrap();
        // Payload, bundle, by_block all populated; by_domain stays empty
        assert!(store.get_payload(pid).unwrap().is_some());
        assert!(store.list_by_domain(0, 0).unwrap().is_none());
    }

    #[test]
    fn by_block_extends_on_repeated_calls_with_new_carriers() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[6u8; 32]);
        let bid = PayloadIdHash([0xAA; 48]);
        let p1 = PayloadIdHash([1u8; 48]);
        let p2 = PayloadIdHash([2u8; 48]);
        store.index_carrier_direct(block, &[CarrierIndex { payload_id: p1, entry: make_entry(bid, block, 0, 0, 2, 0) }]).unwrap();
        store.index_carrier_direct(block, &[CarrierIndex { payload_id: p2, entry: make_entry(bid, block, 0, 1, 2, 0) }]).unwrap();
        let bc = store.list_by_block(block).unwrap().unwrap();
        assert_eq!(bc.payload_ids.len(), 2);
        assert!(bc.payload_ids.contains(&p1));
        assert!(bc.payload_ids.contains(&p2));
    }
}
