//! Types persisted by the J4 event store. Lives in `consensus-core` so
//! both the consensus crate (which owns the RocksDB stores) and the host
//! RPC crate (which serves them) can depend on a single source of truth.
//!
//! Serialization: borsh + serde, matching the rest of the consensus
//! database. The 32-byte topic is wrapped in `EventTopic` for type
//! safety; `[u8; 32]` itself does derive serde, so the wrapper is purely
//! for clarity at the call-site.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sophis_hashes::Hash;
use sophis_utils::mem_size::MemSizeEstimator;

use super::TOPIC_LEN;

// ---------------------------------------------------------------------------
// EventTopic — 32-byte topic newtype
// ---------------------------------------------------------------------------

/// Type-safe wrapper around a 32-byte event topic. Two topics compare
/// equal if and only if their underlying bytes are byte-wise identical.
#[derive(Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct EventTopic(pub [u8; TOPIC_LEN]);

impl EventTopic {
    pub const ZERO: Self = Self([0u8; TOPIC_LEN]);

    pub const fn new(bytes: [u8; TOPIC_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_array(&self) -> &[u8; TOPIC_LEN] {
        &self.0
    }

    pub const fn into_array(self) -> [u8; TOPIC_LEN] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Default for EventTopic {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; TOPIC_LEN]> for EventTopic {
    fn from(value: [u8; TOPIC_LEN]) -> Self {
        Self(value)
    }
}

impl From<EventTopic> for [u8; TOPIC_LEN] {
    fn from(value: EventTopic) -> Self {
        value.0
    }
}

impl AsRef<[u8]> for EventTopic {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for EventTopic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EventTopic(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl std::fmt::Display for EventTopic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl MemSizeEstimator for EventTopic {}

// ---------------------------------------------------------------------------
// EventLog — full record stored under prefix 203 / 204 / etc.
// ---------------------------------------------------------------------------

/// Canonical persisted form of an event. Contains everything an RPC
/// caller (`getLogs`) needs without a second store lookup: the emitting
/// contract, every topic, the data payload, and the chain coordinates
/// (block, tx, ordinals, DAA score) that locate it.
///
/// `topics` carries 0..=`MAX_TOPICS_PER_EVENT` (= 4) entries. The
/// emitter (sub-fase J4.3) ensures this invariant at host-fn time;
/// downstream code may rely on it (`topics.len() <= 4`).
///
/// `data` is bounded by `MAX_EVENT_DATA_BYTES` (= 4096).
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct EventLog {
    /// 32-byte sVM contract identifier (`ContractId` in `sophis-svm-core`,
    /// represented here as raw bytes to keep `consensus-core` free of
    /// any svm dependency — same B3 separation rule as
    /// `ExecutionContext::input_utxos: Vec<Vec<u8>>`).
    pub contract_id: [u8; 32],
    pub topics: Vec<EventTopic>,
    pub data: Vec<u8>,
    pub block_hash: Hash,
    pub tx_id: Hash,
    pub tx_index: u32,
    pub log_index: u32,
    pub daa_score: u64,
}

impl EventLog {
    /// Convenience constructor used by tests and the SDK; production
    /// values are always populated by the commit hook (J4.4) which
    /// fills the chain-coordinate fields from acceptance_data.
    pub fn new(
        contract_id: [u8; 32],
        topics: Vec<EventTopic>,
        data: Vec<u8>,
        block_hash: Hash,
        tx_id: Hash,
        tx_index: u32,
        log_index: u32,
        daa_score: u64,
    ) -> Self {
        Self { contract_id, topics, data, block_hash, tx_id, tx_index, log_index, daa_score }
    }
}

impl MemSizeEstimator for EventLog {
    fn estimate_mem_bytes(&self) -> usize {
        size_of::<Self>() + self.topics.len() * TOPIC_LEN + self.data.capacity()
    }
}

// ---------------------------------------------------------------------------
// EventLogs — Vec<EventLog> wrapper for `EventsByBlock` / `EventsByTx`
// ---------------------------------------------------------------------------

/// Ordered list of events stored under a single key in `EventsByBlock`
/// or `EventsByTx`. Newtype so the cached-store API has a stable shape.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct EventLogs {
    pub logs: Vec<EventLog>,
}

impl MemSizeEstimator for EventLogs {
    fn estimate_mem_bytes(&self) -> usize {
        size_of::<Self>() + self.logs.iter().map(|e| e.estimate_mem_bytes()).sum::<usize>()
    }
}

// ---------------------------------------------------------------------------
// EventLogPointer — auxiliary index entry for `EventsByContract` / `EventsByTopic`
// ---------------------------------------------------------------------------

/// Pointer to an event in the canonical `EventsByBlock` (or `EventsByTx`)
/// store. Aux indexes carry these instead of full `EventLog`s to keep the
/// archival footprint small (~36 bytes per event) while still supporting
/// efficient filter walks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct EventLogPointer {
    pub block_hash: Hash,
    pub log_index: u32,
}

impl MemSizeEstimator for EventLogPointer {}

/// Ordered list of pointers under a single `(contract_id, bucket)` or
/// `(topic, bucket)` key.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct EventLogPointers {
    pub pointers: Vec<EventLogPointer>,
}

impl MemSizeEstimator for EventLogPointers {
    fn estimate_mem_bytes(&self) -> usize {
        size_of::<Self>() + self.pointers.len() * size_of::<EventLogPointer>()
    }
}

/// Computes the bucket index for a given DAA score, used as the second
/// half of the composite key in `EventsByContract` and `EventsByTopic`.
/// Mirrors the Phase 6 `domain_bucket_key_bytes` partitioning function;
/// callers concatenate `(32-byte prefix) || (bucket.to_le_bytes())` to
/// form the full RocksDB key.
pub const fn daa_bucket(daa_score: u64) -> u64 {
    daa_score / super::EVENTS_BY_CONTRACT_BUCKET_SIZE
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_round_trips_borsh() {
        let t = EventTopic([0xAAu8; TOPIC_LEN]);
        let bytes = borsh::to_vec(&t).unwrap();
        let decoded: EventTopic = borsh::from_slice(&bytes).unwrap();
        assert_eq!(t, decoded);
    }

    #[test]
    fn topic_display_is_lowercase_hex() {
        let t = EventTopic([0xDE, 0xAD, 0xBE, 0xEF].iter().chain([0u8; 28].iter()).copied().collect::<Vec<_>>().try_into().unwrap());
        let s = format!("{t}");
        assert!(s.starts_with("deadbeef"));
        assert_eq!(s.len(), TOPIC_LEN * 2);
    }

    #[test]
    fn event_log_round_trips_borsh() {
        let log = EventLog::new(
            [7u8; 32],
            vec![EventTopic([1u8; TOPIC_LEN]), EventTopic([2u8; TOPIC_LEN])],
            vec![0xAA, 0xBB, 0xCC],
            Hash::from_slice(&[3u8; 32]),
            Hash::from_slice(&[4u8; 32]),
            5,
            7,
            42_000,
        );
        let bytes = borsh::to_vec(&log).unwrap();
        let decoded: EventLog = borsh::from_slice(&bytes).unwrap();
        assert_eq!(log, decoded);
    }

    #[test]
    fn event_log_default_has_empty_collections() {
        let log = EventLog::default();
        assert!(log.topics.is_empty());
        assert!(log.data.is_empty());
        assert_eq!(log.contract_id, [0u8; 32]);
        assert_eq!(log.tx_index, 0);
        assert_eq!(log.log_index, 0);
        assert_eq!(log.daa_score, 0);
    }

    #[test]
    fn mem_size_includes_topics_and_data() {
        let log = EventLog::new([0u8; 32], vec![EventTopic::ZERO; 4], vec![0u8; 1024], Hash::default(), Hash::default(), 0, 0, 0);
        // At least the 4 topics * 32 + 1024 data bytes counted.
        assert!(log.estimate_mem_bytes() >= 4 * TOPIC_LEN + 1024);
    }
}
