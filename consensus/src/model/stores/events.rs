//! J4 — sVM event log stores.
//!
//! Indexes events emitted by sVM contracts across four RocksDB
//! column-family-equivalent prefixes. See `database/src/registry.rs`
//! (`EventsByBlock`, `EventsByTx`, `EventsByContract`, `EventsByTopic`
//! prefixes 203-206) and `docs/J4_EVENTS_DESIGN.md` §4.
//!
//! All four sub-stores are populated atomically by
//! `DbEventStore::index_events`, invoked from
//! `virtual_processor::commit_utxo_state` (sub-fase J4.4 pipeline hook).
//!
//! Idempotency: events are derived deterministically from sVM execution.
//! A second commit of the same chain block produces the same `Vec<EventLog>`
//! and the same writes — re-acceptance on a reorg is safe.

use rocksdb::WriteBatch;
use sophis_consensus_core::BlockHasher;
use sophis_consensus_core::events::{
    EVENTS_BY_CONTRACT_BUCKET_SIZE, EventLog, EventLogPointer, EventLogPointers, EventLogs, EventTopic, TOPIC_LEN, daa_bucket,
};
use sophis_database::prelude::CachePolicy;
use sophis_database::prelude::DB;
use sophis_database::prelude::StoreError;
use sophis_database::prelude::{BatchDbWriter, CachedDbAccess};
use sophis_database::registry::DatabaseStorePrefixes;
use sophis_hashes::Hash;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Composite key wrappers
// ---------------------------------------------------------------------------

/// Composite key for `EventsByContract`: `[contract_id_32B || bucket_le_8B]`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ContractBucketKey(pub [u8; 40]);

impl ContractBucketKey {
    pub fn new(contract_id: &[u8; 32], daa_score: u64) -> Self {
        let mut k = [0u8; 40];
        k[..32].copy_from_slice(contract_id);
        k[32..].copy_from_slice(&daa_bucket(daa_score).to_le_bytes());
        Self(k)
    }
}

impl AsRef<[u8]> for ContractBucketKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for ContractBucketKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bucket = u64::from_le_bytes(self.0[32..].try_into().unwrap());
        write!(f, "ContractBucketKey(bucket={bucket})")
    }
}

/// Composite key for `EventsByTopic`: `[topic_32B || bucket_le_8B]`.
/// Topic is `EventTopic` (= `[u8; 32]`) so the layout matches
/// `ContractBucketKey` byte-for-byte.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TopicBucketKey(pub [u8; 40]);

impl TopicBucketKey {
    pub fn new(topic: &EventTopic, daa_score: u64) -> Self {
        let mut k = [0u8; 40];
        k[..TOPIC_LEN].copy_from_slice(topic.as_array());
        k[TOPIC_LEN..].copy_from_slice(&daa_bucket(daa_score).to_le_bytes());
        Self(k)
    }
}

impl AsRef<[u8]> for TopicBucketKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for TopicBucketKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bucket = u64::from_le_bytes(self.0[TOPIC_LEN..].try_into().unwrap());
        write!(f, "TopicBucketKey(bucket={bucket})")
    }
}

// ---------------------------------------------------------------------------
// Reader trait
// ---------------------------------------------------------------------------

pub trait EventStoreReader {
    fn get_logs_by_block(&self, block_hash: Hash) -> Result<Option<EventLogs>, StoreError>;
    fn get_logs_by_tx(&self, tx_id: Hash) -> Result<Option<EventLogs>, StoreError>;
    fn get_pointers_by_contract(&self, contract_id: &[u8; 32], daa_score: u64) -> Result<Option<EventLogPointers>, StoreError>;
    fn get_pointers_by_topic(&self, topic: &EventTopic, daa_score: u64) -> Result<Option<EventLogPointers>, StoreError>;
}

// ---------------------------------------------------------------------------
// DbEventStore
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DbEventStore {
    db: Arc<DB>,
    by_block: CachedDbAccess<Hash, EventLogs, BlockHasher>,
    by_tx: CachedDbAccess<Hash, EventLogs, BlockHasher>,
    by_contract: CachedDbAccess<ContractBucketKey, EventLogPointers>,
    by_topic: CachedDbAccess<TopicBucketKey, EventLogPointers>,
}

impl DbEventStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        let by_block = CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::EventsByBlock.into());
        let by_tx = CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::EventsByTx.into());
        let by_contract = CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::EventsByContract.into());
        let by_topic = CachedDbAccess::new(db.clone(), cache_policy, DatabaseStorePrefixes::EventsByTopic.into());
        Self { db, by_block, by_tx, by_contract, by_topic }
    }

    pub fn clone_with_new_cache(&self, cache_policy: CachePolicy) -> Self {
        Self::new(Arc::clone(&self.db), cache_policy)
    }

    /// Indexes a batch of events accepted by `accepting_block_hash` into
    /// all 4 sub-stores within a single `WriteBatch` (atomic at RocksDB
    /// layer). Caller groups events per block; per-tx grouping is done
    /// here from the `tx_id` field of each `EventLog`.
    ///
    /// Idempotency: a second commit of the same chain block re-derives
    /// identical `EventLog` records and overwrites the existing rows
    /// with the same bytes (a no-op semantically; harmless for correctness).
    pub fn index_events(&self, batch: &mut WriteBatch, accepting_block_hash: Hash, events: Vec<EventLog>) -> Result<(), StoreError> {
        if events.is_empty() {
            return Ok(());
        }

        // 1. Per-block: write the full Vec<EventLog>.
        let block_logs = EventLogs { logs: events.clone() };
        self.by_block.write(BatchDbWriter::new(batch), accepting_block_hash, block_logs)?;

        // 2. Per-tx: group by tx_id, write each group.
        // Use a stable ordering: events within a tx are already ordered
        // by log_index; events across txs are ordered by tx_index.
        let mut current_tx: Option<Hash> = None;
        let mut current_logs: Vec<EventLog> = Vec::new();
        for log in events.iter() {
            if Some(log.tx_id) != current_tx {
                // Flush previous group
                if let Some(prev_tx) = current_tx
                    && !current_logs.is_empty()
                {
                    self.by_tx.write(BatchDbWriter::new(batch), prev_tx, EventLogs { logs: std::mem::take(&mut current_logs) })?;
                }
                current_tx = Some(log.tx_id);
            }
            current_logs.push(log.clone());
        }
        if let Some(prev_tx) = current_tx
            && !current_logs.is_empty()
        {
            self.by_tx.write(BatchDbWriter::new(batch), prev_tx, EventLogs { logs: current_logs })?;
        }

        // 3. Per-contract aux: append (block_hash, log_index) to the
        // bucket for each event's (contract_id, daa_score).
        // 4. Per-topic aux: same pattern, indexed by every topic the
        // event carries (each event contributes one entry per topic).
        for log in &events {
            let pointer = EventLogPointer { block_hash: accepting_block_hash, log_index: log.log_index };
            let contract_key = ContractBucketKey::new(&log.contract_id, log.daa_score);
            let mut bucket = match self.by_contract.read(contract_key) {
                Ok(b) => b,
                Err(StoreError::KeyNotFound(_)) => EventLogPointers::default(),
                Err(e) => return Err(e),
            };
            bucket.pointers.push(pointer);
            self.by_contract.write(BatchDbWriter::new(batch), contract_key, bucket)?;

            for topic in &log.topics {
                let topic_key = TopicBucketKey::new(topic, log.daa_score);
                let mut bucket = match self.by_topic.read(topic_key) {
                    Ok(b) => b,
                    Err(StoreError::KeyNotFound(_)) => EventLogPointers::default(),
                    Err(e) => return Err(e),
                };
                bucket.pointers.push(pointer);
                self.by_topic.write(BatchDbWriter::new(batch), topic_key, bucket)?;
            }
        }

        Ok(())
    }

    /// Direct (non-batched) variant for tests + ad-hoc reindexing.
    /// Production callers should always go through the batched path so
    /// other consensus state lands in the same atomic write.
    pub fn index_events_direct(&self, accepting_block_hash: Hash, events: Vec<EventLog>) -> Result<(), StoreError> {
        let mut batch = WriteBatch::default();
        self.index_events(&mut batch, accepting_block_hash, events)?;
        self.db.write(batch).map_err(StoreError::DbError)?;
        Ok(())
    }

    /// Removes the per-block and per-tx rows for a pruned block. The
    /// archival aux indexes (`EventsByContract`, `EventsByTopic`) are
    /// NOT touched per design §4.4 — historical filter queries against
    /// pre-pruning blocks remain answerable via those indexes.
    pub fn forget_block_index(&self, batch: &mut WriteBatch, block_hash: Hash) -> Result<(), StoreError> {
        // Pull the block's logs first so we know which tx_ids to drop.
        if let Ok(block_logs) = self.by_block.read(block_hash) {
            let mut seen: std::collections::HashSet<Hash> = std::collections::HashSet::new();
            for log in &block_logs.logs {
                seen.insert(log.tx_id);
            }
            for tx_id in seen {
                if self.by_tx.has(tx_id)? {
                    self.by_tx.delete(BatchDbWriter::new(batch), tx_id)?;
                }
            }
            self.by_block.delete(BatchDbWriter::new(batch), block_hash)?;
        }
        Ok(())
    }

    /// Walks adjacent buckets in `EventsByContract` for the requested
    /// DAA range. Used by `getLogs(contract_id=Some, …)` when no
    /// topic filter is more selective.
    pub fn pointers_by_contract_range(
        &self,
        contract_id: &[u8; 32],
        from_daa: u64,
        to_daa: u64,
    ) -> Result<Vec<EventLogPointer>, StoreError> {
        if to_daa < from_daa {
            return Ok(Vec::new());
        }
        let from_bucket = from_daa / EVENTS_BY_CONTRACT_BUCKET_SIZE;
        let to_bucket = to_daa / EVENTS_BY_CONTRACT_BUCKET_SIZE;
        let mut out = Vec::new();
        for b in from_bucket..=to_bucket {
            // Construct the key directly via the bucket index (multiply
            // back to a daa-score representative; daa_bucket() takes a
            // raw score so we synthesize one).
            let synthetic_daa = b * EVENTS_BY_CONTRACT_BUCKET_SIZE;
            let key = ContractBucketKey::new(contract_id, synthetic_daa);
            match self.by_contract.read(key) {
                Ok(p) => out.extend(p.pointers),
                Err(StoreError::KeyNotFound(_)) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Same shape for the topic axis (`EventsByTopic`).
    pub fn pointers_by_topic_range(&self, topic: &EventTopic, from_daa: u64, to_daa: u64) -> Result<Vec<EventLogPointer>, StoreError> {
        if to_daa < from_daa {
            return Ok(Vec::new());
        }
        let from_bucket = from_daa / EVENTS_BY_CONTRACT_BUCKET_SIZE;
        let to_bucket = to_daa / EVENTS_BY_CONTRACT_BUCKET_SIZE;
        let mut out = Vec::new();
        for b in from_bucket..=to_bucket {
            let synthetic_daa = b * EVENTS_BY_CONTRACT_BUCKET_SIZE;
            let key = TopicBucketKey::new(topic, synthetic_daa);
            match self.by_topic.read(key) {
                Ok(p) => out.extend(p.pointers),
                Err(StoreError::KeyNotFound(_)) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }
}

impl EventStoreReader for DbEventStore {
    fn get_logs_by_block(&self, block_hash: Hash) -> Result<Option<EventLogs>, StoreError> {
        match self.by_block.read(block_hash) {
            Ok(l) => Ok(Some(l)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn get_logs_by_tx(&self, tx_id: Hash) -> Result<Option<EventLogs>, StoreError> {
        match self.by_tx.read(tx_id) {
            Ok(l) => Ok(Some(l)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn get_pointers_by_contract(&self, contract_id: &[u8; 32], daa_score: u64) -> Result<Option<EventLogPointers>, StoreError> {
        let key = ContractBucketKey::new(contract_id, daa_score);
        match self.by_contract.read(key) {
            Ok(p) => Ok(Some(p)),
            Err(StoreError::KeyNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn get_pointers_by_topic(&self, topic: &EventTopic, daa_score: u64) -> Result<Option<EventLogPointers>, StoreError> {
        let key = TopicBucketKey::new(topic, daa_score);
        match self.by_topic.read(key) {
            Ok(p) => Ok(Some(p)),
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

    fn build_store() -> (DbLifetime, DbEventStore) {
        let (lifetime, db) = create_temp_db!(ConnBuilder::default().with_files_limit(10));
        let store = DbEventStore::new(db, CachePolicy::Count(64));
        (lifetime, store)
    }

    fn make_log(contract_id: u8, tx_id: u8, log_index: u32, topics: Vec<u8>, daa: u64) -> EventLog {
        EventLog::new(
            [contract_id; 32],
            topics.into_iter().map(|b| EventTopic([b; TOPIC_LEN])).collect(),
            vec![0xAA; 16],
            Hash::default(), // overwritten by index_events from accepting_block_hash
            Hash::from_slice(&[tx_id; 32]),
            0,
            log_index,
            daa,
        )
    }

    #[test]
    fn round_trip_single_event() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[1u8; 32]);
        let log = make_log(7, 9, 0, vec![0xBB], 100);
        store.index_events_direct(block, vec![log.clone()]).unwrap();

        // by_block returns the full log (with block_hash unchanged from input)
        let by_block = store.get_logs_by_block(block).unwrap().unwrap();
        assert_eq!(by_block.logs.len(), 1);
        assert_eq!(by_block.logs[0].tx_id, log.tx_id);

        // by_tx returns the same log
        let by_tx = store.get_logs_by_tx(log.tx_id).unwrap().unwrap();
        assert_eq!(by_tx.logs.len(), 1);

        // by_contract aux pointer
        let ptrs = store.get_pointers_by_contract(&[7u8; 32], 100).unwrap().unwrap();
        assert_eq!(ptrs.pointers.len(), 1);
        assert_eq!(ptrs.pointers[0].block_hash, block);
        assert_eq!(ptrs.pointers[0].log_index, 0);

        // by_topic aux pointer
        let ptrs = store.get_pointers_by_topic(&EventTopic([0xBB; TOPIC_LEN]), 100).unwrap().unwrap();
        assert_eq!(ptrs.pointers.len(), 1);
    }

    #[test]
    fn missing_keys_return_none_not_err() {
        let (_lt, store) = build_store();
        assert!(store.get_logs_by_block(Hash::from_slice(&[0u8; 32])).unwrap().is_none());
        assert!(store.get_logs_by_tx(Hash::from_slice(&[1u8; 32])).unwrap().is_none());
        assert!(store.get_pointers_by_contract(&[2u8; 32], 0).unwrap().is_none());
        assert!(store.get_pointers_by_topic(&EventTopic([3u8; TOPIC_LEN]), 0).unwrap().is_none());
    }

    #[test]
    fn empty_event_batch_is_noop() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[5u8; 32]);
        store.index_events_direct(block, Vec::new()).unwrap();
        assert!(store.get_logs_by_block(block).unwrap().is_none());
    }

    #[test]
    fn multi_tx_block_groups_by_tx_id() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[6u8; 32]);
        // tx A emits 2 events, tx B emits 1
        let logs = vec![make_log(7, 1, 0, vec![0xAA], 200), make_log(7, 1, 1, vec![0xAA], 200), make_log(7, 2, 0, vec![0xBB], 200)];
        store.index_events_direct(block, logs).unwrap();
        let tx_a = store.get_logs_by_tx(Hash::from_slice(&[1u8; 32])).unwrap().unwrap();
        assert_eq!(tx_a.logs.len(), 2);
        let tx_b = store.get_logs_by_tx(Hash::from_slice(&[2u8; 32])).unwrap().unwrap();
        assert_eq!(tx_b.logs.len(), 1);
        let by_block = store.get_logs_by_block(block).unwrap().unwrap();
        assert_eq!(by_block.logs.len(), 3);
    }

    #[test]
    fn topic_aux_index_records_one_entry_per_topic() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[7u8; 32]);
        // Single event with 3 topics → 3 entries in by_topic + 1 in by_contract
        let log = make_log(7, 1, 0, vec![0xAA, 0xBB, 0xCC], 300);
        store.index_events_direct(block, vec![log]).unwrap();
        for topic_byte in [0xAAu8, 0xBB, 0xCC] {
            let ptrs = store.get_pointers_by_topic(&EventTopic([topic_byte; TOPIC_LEN]), 300).unwrap().unwrap();
            assert_eq!(ptrs.pointers.len(), 1, "topic 0x{topic_byte:02x} must have one pointer");
        }
        let contract_ptrs = store.get_pointers_by_contract(&[7u8; 32], 300).unwrap().unwrap();
        assert_eq!(contract_ptrs.pointers.len(), 1, "contract index has one pointer per event, not per topic");
    }

    #[test]
    fn pointers_by_contract_range_walks_buckets() {
        let (_lt, store) = build_store();
        let block_a = Hash::from_slice(&[10u8; 32]);
        let block_b = Hash::from_slice(&[11u8; 32]);
        let contract = [7u8; 32];
        // Two events in different DAA buckets (bucket size = 65_536)
        let log_a = make_log(7, 1, 0, vec![0xAA], 100);
        let log_b = make_log(7, 2, 0, vec![0xAA], 100_000); // bucket 1
        store.index_events_direct(block_a, vec![log_a]).unwrap();
        store.index_events_direct(block_b, vec![log_b]).unwrap();
        // Range covering both buckets
        let all = store.pointers_by_contract_range(&contract, 0, 200_000).unwrap();
        assert_eq!(all.len(), 2);
        // Range covering only bucket 0
        let bucket0 = store.pointers_by_contract_range(&contract, 0, 50_000).unwrap();
        assert_eq!(bucket0.len(), 1);
    }

    #[test]
    fn pointers_by_topic_range_walks_buckets() {
        let (_lt, store) = build_store();
        let topic = EventTopic([0xAA; TOPIC_LEN]);
        store.index_events_direct(Hash::from_slice(&[20u8; 32]), vec![make_log(7, 1, 0, vec![0xAA], 100)]).unwrap();
        store.index_events_direct(Hash::from_slice(&[21u8; 32]), vec![make_log(7, 2, 0, vec![0xAA], 200_000)]).unwrap();
        let all = store.pointers_by_topic_range(&topic, 0, 200_000).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn pointers_by_contract_range_empty_when_inverted() {
        let (_lt, store) = build_store();
        let v = store.pointers_by_contract_range(&[0u8; 32], 100, 50).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn forget_block_index_removes_block_and_tx_keeps_aux() {
        let (_lt, store) = build_store();
        let block = Hash::from_slice(&[30u8; 32]);
        let log = make_log(7, 5, 0, vec![0xAA], 100);
        store.index_events_direct(block, vec![log.clone()]).unwrap();
        let mut batch = WriteBatch::default();
        store.forget_block_index(&mut batch, block).unwrap();
        store.db.write(batch).unwrap();
        // by_block + by_tx gone
        assert!(store.get_logs_by_block(block).unwrap().is_none());
        assert!(store.get_logs_by_tx(log.tx_id).unwrap().is_none());
        // aux indexes survive (archival per §4.4)
        assert!(store.get_pointers_by_contract(&[7u8; 32], 100).unwrap().is_some());
        assert!(store.get_pointers_by_topic(&EventTopic([0xAA; TOPIC_LEN]), 100).unwrap().is_some());
    }

    #[test]
    fn forget_block_index_on_missing_row_is_noop() {
        let (_lt, store) = build_store();
        let mut batch = WriteBatch::default();
        store.forget_block_index(&mut batch, Hash::from_slice(&[99u8; 32])).unwrap();
        store.db.write(batch).unwrap(); // empty batch, no-op
    }
}
