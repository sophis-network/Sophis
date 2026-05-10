//! J4 — sVM event logs.
//!
//! Canonical reference: `docs/J4_EVENTS_DESIGN.md`. The constants and
//! parsers in this module form the **ABI freeze** of sub-fase J4.0. Any
//! change requires a hard fork of the sVM ABI.
//!
//! Events are pure execution side effects: a sVM contract emits zero or
//! more events during transaction execution via the `sophis_emit_event`
//! host function (J4.3). The execution context buffers them; at
//! `commit_utxo_state` (J4.4) the consensus layer persists them into
//! the four RocksDB indexes (J4.2). Events do **not** appear on-wire in
//! transactions — there is no script discriminator or magic prefix to
//! allocate.
//!
//! Layout of a single emission payload as the contract writes it into
//! linear memory (read by `sophis_emit_event`):
//! ```text
//!   0..1     topic_count: u8       (must be 0..=MAX_TOPICS_PER_EVENT = 4)
//!   1..N     topics:      [u8; 32 * topic_count]
//!   N..N+4   data_len:    u32 LE   (must be ≤ MAX_EVENT_DATA_BYTES = 4096)
//!  N+4..end  data:        [u8; data_len]
//! ```
//! Total wire size: `1 + 32*topic_count + 4 + data_len`.
//!
//! The 6 emission-time consensus rules of §5 are enforced by:
//! * rules 1-2 (capability + gas): `sophis_emit_event` host fn (J4.3)
//! * rules 3-5 (structural): `parse_emission_payload` returns Err
//! * rule 6 (per-tx cap): `ExecutionContext.events.len()` check (J4.3)
//!
//! Rules 7-8 (per-block cap, no events in coinbase) belong to the
//! commit-hook layer (J4.4) and are not enforced here.

use std::fmt;

pub mod codec;
pub mod store_types;

pub use codec::{encode_emission_payload, parse_emission_payload, topic_signature_hash};
pub use store_types::{EventLog, EventTopic};

// --- caps and limits ---------------------------------------------------

/// Maximum topics attached to a single event. Mirrors the Ethereum LOG0..LOG4
/// convention. Frozen ABI.
pub const MAX_TOPICS_PER_EVENT: u8 = 4;

/// Length in bytes of a single topic. Frozen ABI; matches Ethereum's
/// 32-byte topic shape so existing indexer tooling speaks the same idiom.
pub const TOPIC_LEN: usize = 32;

/// Maximum bytes in the `data` section of a single event. Mirrors
/// `MAX_ALT_ENTRY_SCRIPT_BYTES` so operators only need to remember one
/// number for "biggest single sVM-side payload".
pub const MAX_EVENT_DATA_BYTES: u32 = 4_096;

/// Maximum events a single transaction may emit. Anti-spam cap;
/// per-block cap (J4.4) is `MAX_EVENTS_PER_BLOCK = 1024`.
pub const MAX_EVENTS_PER_TX: usize = 32;

/// Maximum events a single block may contain across all its transactions.
/// Enforced at commit time (J4.4); a tx that would push the block over
/// this cap has its trailing events silently dropped at indexing time
/// (the transaction itself is still accepted because it stayed within
/// its own per-tx budget).
pub const MAX_EVENTS_PER_BLOCK: usize = 1_024;

/// Maximum events returned in a single `getLogs` RPC response. Server
/// always caps regardless of the client's `limit` field.
pub const MAX_LOGS_PER_RESPONSE: u32 = 1_000;

/// Bucket size for `EventsByContract` and `EventsByTopic` archival
/// indexes. Matches `DOMAIN_BUCKET_SIZE` from Phase 6 DA so archival
/// stores share the same partitioning convention.
pub const EVENTS_BY_CONTRACT_BUCKET_SIZE: u64 = 65_536;

// --- view types --------------------------------------------------------

/// Decoded view of a single emission payload. Returned by
/// `parse_emission_payload`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEmissionPayload {
    /// Number of topics in `topics`. `0..=MAX_TOPICS_PER_EVENT`.
    pub topic_count: u8,
    /// Borrowed topics (each exactly `TOPIC_LEN` bytes). Allocated by
    /// the parser from the input slice; ownership stays with the parser.
    pub topics: Vec<[u8; TOPIC_LEN]>,
    /// Borrowed data bytes (length ≤ `MAX_EVENT_DATA_BYTES`).
    pub data: Vec<u8>,
}

// --- errors ------------------------------------------------------------

/// Reasons the consensus / sVM may reject an event emission. Each
/// numbered variant maps to a rule from §5 of the design document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventError {
    /// Rule 3 — `topic_count` byte exceeds `MAX_TOPICS_PER_EVENT`.
    TopicCountOutOfRange(u8),
    /// Rule 4 — declared `data_len` exceeds `MAX_EVENT_DATA_BYTES`.
    DataTooLarge { data_len: u32 },
    /// Rule 5 — wire payload is shorter than the structural minimum
    /// (1 + 32 * topic_count + 4 + data_len).
    Truncated { actual: usize, expected: usize },
    /// Wire payload is longer than the structural exact-length (extra
    /// trailing bytes). Distinct from `Truncated` so producer bugs are
    /// easy to triage.
    LengthMismatch { actual: usize, expected: usize },
}

impl fmt::Display for EventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TopicCountOutOfRange(c) => {
                write!(f, "event topic_count={c} exceeds MAX_TOPICS_PER_EVENT={MAX_TOPICS_PER_EVENT}")
            }
            Self::DataTooLarge { data_len } => {
                write!(f, "event data_len={data_len} exceeds MAX_EVENT_DATA_BYTES={MAX_EVENT_DATA_BYTES}")
            }
            Self::Truncated { actual, expected } => {
                write!(f, "event emission payload is {actual} bytes, expected at least {expected} (header + topics + data_len)")
            }
            Self::LengthMismatch { actual, expected } => {
                write!(f, "event emission payload is {actual} bytes, expected exactly {expected} (header + topics + data_len + data)")
            }
        }
    }
}

impl std::error::Error for EventError {}

// --- helpers -----------------------------------------------------------

/// Computes the structural exact length of an emission payload given a
/// topic count and a data length. Used by both the parser and the
/// codec to keep the size formula in one place.
pub const fn payload_exact_len(topic_count: u8, data_len: u32) -> usize {
    1 + (topic_count as usize) * TOPIC_LEN + 4 + (data_len as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- payload_exact_len ------------------------------------------------

    #[test]
    fn payload_exact_len_zero_topics_zero_data() {
        // Just topic_count(1) + data_len(4) = 5 bytes.
        assert_eq!(payload_exact_len(0, 0), 5);
    }

    #[test]
    fn payload_exact_len_max_topics_max_data() {
        // 1 + 4*32 + 4 + 4096 = 4229.
        assert_eq!(payload_exact_len(MAX_TOPICS_PER_EVENT, MAX_EVENT_DATA_BYTES), 4229);
    }

    #[test]
    fn payload_exact_len_two_topics_arbitrary_data() {
        // 1 + 2*32 + 4 + 100 = 169.
        assert_eq!(payload_exact_len(2, 100), 169);
    }

    // --- size constants sanity ------------------------------------------

    #[test]
    fn constants_are_consistent() {
        assert_eq!(MAX_TOPICS_PER_EVENT, 4);
        assert_eq!(TOPIC_LEN, 32);
        assert_eq!(MAX_EVENT_DATA_BYTES, 4_096);
        assert_eq!(MAX_EVENTS_PER_TX, 32);
        assert_eq!(MAX_EVENTS_PER_BLOCK, 1_024);
        assert_eq!(MAX_LOGS_PER_RESPONSE, 1_000);
        assert_eq!(EVENTS_BY_CONTRACT_BUCKET_SIZE, 65_536);
        // Per-block cap must be at least per-tx cap (so a single-tx
        // block can fully exercise its budget).
        assert!(MAX_EVENTS_PER_BLOCK >= MAX_EVENTS_PER_TX);
    }

    // --- error display --------------------------------------------------

    #[test]
    fn error_display_includes_offending_values() {
        assert!(EventError::TopicCountOutOfRange(5).to_string().contains("topic_count=5"));
        assert!(EventError::DataTooLarge { data_len: 9999 }.to_string().contains("data_len=9999"));
        assert!(EventError::Truncated { actual: 3, expected: 5 }.to_string().contains("3 bytes"));
        assert!(EventError::LengthMismatch { actual: 10, expected: 8 }.to_string().contains("10 bytes"));
    }
}
