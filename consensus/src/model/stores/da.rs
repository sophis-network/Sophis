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
    BlockCarriers, BodyGcWatermark, BundleIndex, DOMAIN_BUCKET_SIZE, DomainBucket, PayloadBody, PayloadEntry, PayloadIdHash,
    PayloadMeta, domain_bucket_key_bytes,
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
    payloads: CachedDbAccess<PayloadIdHash, PayloadMeta>,
    bodies: CachedDbAccess<PayloadIdHash, PayloadBody>,
    body_gc_watermark: CachedDbAccess<Hash, BodyGcWatermark>,
    bundles: CachedDbAccess<PayloadIdHash, BundleIndex>,
    by_block: CachedDbAccess<Hash, BlockCarriers, BlockHasher>,
    by_domain: CachedDbAccess<DomainBucketKey, DomainBucket>,
}

impl DbDaStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        let payloads = CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::DaCarrierPayloads.into());
        let bodies = CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::DaCarrierBodies.into());
        let body_gc_watermark = CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::DaBodyGcWatermark.into());
        let bundles = CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::DaCarrierBundles.into());
        let by_block = CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::DaCarrierByBlock.into());
        let by_domain = CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::DaCarrierByDomain.into());
        Self { db, payloads, bodies, body_gc_watermark, bundles, by_block, by_domain }
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
            // F-26 Fix B — split metadata (196, kept to pruning_depth) from
            // the body (209, droppable on a short horizon). Same WriteBatch.
            let (meta, body) = ci.entry.clone().into_meta_and_body();
            self.payloads.write(BatchDbWriter::new(batch), ci.payload_id, meta)?;
            self.bodies.write(BatchDbWriter::new(batch), ci.payload_id, body)?;
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

    /// Fix A (F-26) — inverse of `index_carrier_batch`: removes every DA
    /// index entry for `accepting_block_hash`, which is being pruned at the
    /// consensus pruning point. Idempotent (missing keys are skipped, so a
    /// re-prune or a partially-pruned block is harmless) and batch-atomic
    /// (all writes go through the caller's `WriteBatch`, landing together
    /// with the rest of the consensus prune). The RMW on `bundles`/
    /// `by_domain` mirrors the same cache-coherent pattern that
    /// `index_carrier_batch` already relies on.
    pub fn prune_block_batch(&self, batch: &mut WriteBatch, accepting_block_hash: Hash) -> Result<(), StoreError> {
        let pids = match self.by_block.read(accepting_block_hash) {
            Ok(bc) => bc.payload_ids,
            Err(StoreError::KeyNotFound(_)) => return Ok(()),
            Err(e) => return Err(e),
        };
        for pid in pids {
            // Read metadata first to locate the bundle / domain back-refs.
            let entry = match self.payloads.read(pid) {
                Ok(e) => e,
                Err(StoreError::KeyNotFound(_)) => continue, // already removed
                Err(e) => return Err(e),
            };
            self.payloads.delete(BatchDbWriter::new(batch), pid)?;
            // Body lives in a separate store (F-26 Fix B) — drop it too.
            self.bodies.delete(BatchDbWriter::new(batch), pid)?;

            // Shrink (or drop) the bundle index.
            match self.bundles.read(entry.bundle_id) {
                Ok(mut bundle) => {
                    bundle.payload_ids.retain(|p| *p != pid);
                    if bundle.payload_ids.is_empty() {
                        self.bundles.delete(BatchDbWriter::new(batch), entry.bundle_id)?;
                    } else {
                        self.bundles.write(BatchDbWriter::new(batch), entry.bundle_id, bundle)?;
                    }
                }
                Err(StoreError::KeyNotFound(_)) => {}
                Err(e) => return Err(e),
            }

            // Shrink (or drop) the by_domain bucket — non-zero domains only,
            // keyed by the same (domain_byte, blue_score) used at index time.
            if entry.domain_byte != 0 {
                let key = DomainBucketKey::new(entry.domain_byte, entry.blue_score);
                match self.by_domain.read(key) {
                    Ok(mut bucket) => {
                        bucket.payload_ids.retain(|p| *p != pid);
                        if bucket.payload_ids.is_empty() {
                            self.by_domain.delete(BatchDbWriter::new(batch), key)?;
                        } else {
                            self.by_domain.write(BatchDbWriter::new(batch), key, bucket)?;
                        }
                    }
                    Err(StoreError::KeyNotFound(_)) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        // Finally drop the by_block entry itself.
        self.by_block.delete(BatchDbWriter::new(batch), accepting_block_hash)?;
        Ok(())
    }

    // --- F-26 Fix B (M3.2): short body-retention horizon GC ---------------
    // The body store (209) is dropped well before the pruning point so the
    // unbounded-growth window shrinks from ~pruning_depth to ~H_body. The
    // metadata (196) + indexes stay to pruning_depth (Fix A prunes those).
    // Consensus never reads the body (H1), so this is non-consensus and runs
    // outside the consensus WriteBatch.

    fn body_gc_wm_key() -> Hash {
        Hash::from_slice(&[0u8; 32])
    }

    /// Selected-chain index up to which carrier bodies have already been
    /// GC'd. `0` if the GC has never run.
    pub fn body_gc_watermark(&self) -> u64 {
        match self.body_gc_watermark.read(Self::body_gc_wm_key()) {
            Ok(w) => w.0,
            _ => 0,
        }
    }

    pub fn set_body_gc_watermark(&self, batch: &mut WriteBatch, idx: u64) -> Result<(), StoreError> {
        self.body_gc_watermark.write(BatchDbWriter::new(batch), Self::body_gc_wm_key(), BodyGcWatermark(idx))
    }

    /// Drop only the bodies (209) of every carrier accepted by `block_hash`,
    /// leaving metadata/bundle/by_block intact (those are pruned later at
    /// `pruning_depth` by `prune_block_batch`). Idempotent.
    pub fn gc_block_bodies(&self, batch: &mut WriteBatch, block_hash: Hash) -> Result<(), StoreError> {
        let pids = match self.by_block.read(block_hash) {
            Ok(bc) => bc.payload_ids,
            Err(StoreError::KeyNotFound(_)) => return Ok(()),
            Err(e) => return Err(e),
        };
        for pid in pids {
            self.bodies.delete(BatchDbWriter::new(batch), pid)?;
        }
        Ok(())
    }
}

impl DaStoreReader for DbDaStore {
    fn get_payload(&self, payload_id: PayloadIdHash) -> Result<Option<PayloadEntry>, StoreError> {
        let meta = match self.payloads.read(payload_id) {
            Ok(m) => m,
            Err(StoreError::KeyNotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        // F-26 Fix B — body may already be dropped by the short retention
        // horizon while metadata is kept to pruning_depth; return empty
        // script in that case (consensus never reads the body — H1).
        let body = match self.bodies.read(payload_id) {
            Ok(b) => b.0,
            Err(StoreError::KeyNotFound(_)) => Vec::new(),
            Err(e) => return Err(e),
        };
        Ok(Some(PayloadEntry::reassemble(meta, body)))
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

    /// Direct (non-batched) variant of `prune_block_batch` — tests / admin
    /// tooling, symmetric with `index_carrier_direct`.
    pub fn prune_block_direct(&self, accepting_block_hash: Hash) -> Result<(), StoreError> {
        let mut batch = WriteBatch::default();
        self.prune_block_batch(&mut batch, accepting_block_hash)?;
        self.db.write(batch).map_err(StoreError::DbError)?;
        Ok(())
    }

    /// Direct (non-batched) F-26 Fix B body GC — tests/admin.
    pub fn gc_block_bodies_direct(&self, block_hash: Hash) -> Result<(), StoreError> {
        let mut batch = WriteBatch::default();
        self.gc_block_bodies(&mut batch, block_hash)?;
        self.db.write(batch).map_err(StoreError::DbError)?;
        Ok(())
    }

    /// Direct (non-batched) watermark setter — tests/admin.
    pub fn set_body_gc_watermark_direct(&self, idx: u64) -> Result<(), StoreError> {
        let mut batch = WriteBatch::default();
        self.set_body_gc_watermark(&mut batch, idx)?;
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
        assert_eq!(read.script, entry.script, "F-26 Fix B: body roundtrips through the metadata/body store split");
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

    // ----- Fix A (F-26): prune_block_batch -----------------------------

    #[test]
    fn prune_block_removes_single_payload_everywhere() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[7u8; 32]);
        let pid = PayloadIdHash([0x10; 48]);
        let bid = PayloadIdHash([0x20; 48]);
        let dom = sophis_consensus_core::da::CARRIER_FLAG_DOMAIN_ROLLUP;
        store.index_carrier_direct(block, &[CarrierIndex { payload_id: pid, entry: make_entry(bid, block, 42, 0, 1, dom) }]).unwrap();
        assert!(store.get_payload(pid).unwrap().is_some());

        store.prune_block_direct(block).unwrap();

        assert!(store.get_payload(pid).unwrap().is_none());
        assert!(store.get_bundle(bid).unwrap().is_none());
        assert!(store.list_by_block(block).unwrap().is_none());
        assert!(store.list_by_domain(dom, 42).unwrap().is_none());
    }

    #[test]
    fn prune_is_idempotent_and_tolerates_missing_block() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[8u8; 32]);
        // Missing block → Ok, no panic.
        store.prune_block_direct(block).unwrap();
        // Index, then prune twice — second prune is a no-op.
        let pid = PayloadIdHash([0x33; 48]);
        let bid = PayloadIdHash([0x44; 48]);
        store.index_carrier_direct(block, &[CarrierIndex { payload_id: pid, entry: make_entry(bid, block, 1, 0, 1, 0) }]).unwrap();
        store.prune_block_direct(block).unwrap();
        store.prune_block_direct(block).unwrap();
        assert!(store.get_payload(pid).unwrap().is_none());
        assert!(store.get_bundle(bid).unwrap().is_none());
    }

    #[test]
    fn prune_straddling_bundle_keeps_unpruned_fragment() {
        let (_lt, store) = build_store();
        let block_a = Hash::from_slice(&[9u8; 32]);
        let block_b = Hash::from_slice(&[10u8; 32]);
        let bid = PayloadIdHash([0x55; 48]);
        let p0 = PayloadIdHash([0u8; 48]);
        let p1 = PayloadIdHash([1u8; 48]);
        store.index_carrier_direct(block_a, &[CarrierIndex { payload_id: p0, entry: make_entry(bid, block_a, 10, 0, 2, 0) }]).unwrap();
        store.index_carrier_direct(block_b, &[CarrierIndex { payload_id: p1, entry: make_entry(bid, block_b, 11, 1, 2, 0) }]).unwrap();

        store.prune_block_direct(block_a).unwrap();

        // Pruned fragment gone; the other survives; the bundle survives
        // PARTIAL (len 1 != fragment_count 2) — i.e. verify_bundle → false,
        // the §10.7 "post-prune ⇒ not present" semantics. No panic.
        assert!(store.get_payload(p0).unwrap().is_none());
        assert!(store.get_payload(p1).unwrap().is_some());
        let bundle = store.get_bundle(bid).unwrap().unwrap();
        assert_eq!(bundle.payload_ids, vec![p1]);
        assert_eq!(bundle.fragment_count, 2);
        assert!(store.list_by_block(block_a).unwrap().is_none());
        assert!(store.list_by_block(block_b).unwrap().is_some());
    }

    #[test]
    fn prune_shrinks_then_deletes_by_domain_bucket() {
        let (_lt, store) = build_store();
        let dom = sophis_consensus_core::da::CARRIER_FLAG_DOMAIN_ROLLUP;
        let ba = Hash::from_slice(&[11u8; 32]);
        let bb = Hash::from_slice(&[12u8; 32]);
        let pa = PayloadIdHash([0xA1; 48]);
        let pb = PayloadIdHash([0xB1; 48]);
        let ba_bid = PayloadIdHash([0xA2; 48]);
        let bb_bid = PayloadIdHash([0xB2; 48]);
        // Same domain + same blue_score ⇒ same by_domain bucket.
        store.index_carrier_direct(ba, &[CarrierIndex { payload_id: pa, entry: make_entry(ba_bid, ba, 500, 0, 1, dom) }]).unwrap();
        store.index_carrier_direct(bb, &[CarrierIndex { payload_id: pb, entry: make_entry(bb_bid, bb, 500, 0, 1, dom) }]).unwrap();

        store.prune_block_direct(ba).unwrap();
        // Bucket shrunk, not deleted.
        let bucket = store.list_by_domain(dom, 500).unwrap().unwrap();
        assert_eq!(bucket.payload_ids, vec![pb]);

        store.prune_block_direct(bb).unwrap();
        assert!(store.list_by_domain(dom, 500).unwrap().is_none());
    }

    // ----- F-26 Fix B (M3.2): body GC -----------------------------------

    #[test]
    fn body_gc_drops_body_keeps_metadata() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[0x6Au8; 32]);
        let pid = PayloadIdHash([0x6Bu8; 48]);
        let bid = PayloadIdHash([0x6Cu8; 48]);
        let entry = make_entry(bid, block, 77, 0, 1, sophis_consensus_core::da::CARRIER_FLAG_DOMAIN_ROLLUP);
        store.index_carrier_direct(block, &[CarrierIndex { payload_id: pid, entry: entry.clone() }]).unwrap();
        assert_eq!(store.get_payload(pid).unwrap().unwrap().script, entry.script, "body present before GC");

        store.gc_block_bodies_direct(block).unwrap();

        // Body dropped by the short horizon; metadata + indexes retained
        // (those are pruned later at pruning_depth by Fix A).
        let after = store.get_payload(pid).unwrap().unwrap();
        assert!(after.script.is_empty(), "F-26 Fix B: body dropped by horizon GC");
        assert_eq!(after.bundle_id, bid, "metadata retained after body GC");
        assert_eq!(after.blue_score, 77, "metadata retained after body GC");
        assert!(store.has_payload(pid).unwrap(), "payload metadata still present");
        assert!(store.get_bundle(bid).unwrap().is_some(), "bundle index retained");
        assert!(store.list_by_block(block).unwrap().is_some(), "by_block retained");

        // Idempotent.
        store.gc_block_bodies_direct(block).unwrap();
        assert!(store.get_payload(pid).unwrap().unwrap().script.is_empty());
    }

    #[test]
    fn body_gc_watermark_roundtrip() {
        let (_lt, store) = build_store();
        assert_eq!(store.body_gc_watermark(), 0, "watermark defaults to 0");
        store.set_body_gc_watermark_direct(123_456).unwrap();
        assert_eq!(store.body_gc_watermark(), 123_456);
        store.set_body_gc_watermark_direct(200_000).unwrap();
        assert_eq!(store.body_gc_watermark(), 200_000);
    }
}
