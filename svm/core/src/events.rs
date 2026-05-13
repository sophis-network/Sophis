//! J4 — sVM-side event emission ABI.
//!
//! This module owns the **runtime-facing** half of the J4 event system:
//! the wire format a sVM contract writes into linear memory when it calls
//! `sophis_emit_event` (J4.3) and the constants the runtime enforces at
//! emission time.
//!
//! The **storage-facing** half (RocksDB-persisted `EventLog`,
//! `EventLogPointer`, per-block / per-response caps) lives in
//! `sophis-consensus-core::events`. The two modules are sibling halves of
//! the same ABI; the constants defined here MUST stay byte-equal to those
//! declared in `consensus-core/src/events/mod.rs`. Frozen ABI — any change
//! requires a hard fork.
//!
//! Cross-references kept in sync manually because `sophis-svm-core` and
//! `sophis-consensus-core` are deliberately sibling crates with no
//! direct dependency (B3 separation; same rule that keeps `Vec<Vec<u8>>`
//! at the runtime/consensus boundary).
//!
//! Wire format of one emission payload:
//! ```text
//!   0..1     topic_count: u8       (must be 0..=MAX_TOPICS_PER_EVENT = 4)
//!   1..N     topics:      [u8; 32 * topic_count]
//!   N..N+4   data_len:    u32 LE   (must be ≤ MAX_EVENT_DATA_BYTES = 4096)
//!  N+4..end  data:        [u8; data_len]
//! ```

use std::fmt;

// --- frozen ABI constants ---------------------------------------------
//
// MUST stay in lockstep with `sophis_consensus_core::events`:
//   MAX_TOPICS_PER_EVENT, TOPIC_LEN, MAX_EVENT_DATA_BYTES, MAX_EVENTS_PER_TX
//
// `MAX_EVENTS_PER_BLOCK`, `MAX_LOGS_PER_RESPONSE` and
// `EVENTS_BY_CONTRACT_BUCKET_SIZE` are storage-layer concerns and live
// only in `consensus-core`.

/// Maximum topics attached to a single event. Mirrors Ethereum's
/// `LOG0..LOG4` convention. Frozen ABI.
pub const MAX_TOPICS_PER_EVENT: u8 = 4;

/// Length in bytes of a single topic. Frozen ABI; matches Ethereum's
/// 32-byte topic shape so existing indexer tooling speaks the same idiom.
pub const TOPIC_LEN: usize = 32;

/// Maximum bytes in the `data` section of a single event. Mirrors
/// `MAX_ALT_ENTRY_SCRIPT_BYTES` so operators only need to remember one
/// number for "biggest single sVM-side payload".
pub const MAX_EVENT_DATA_BYTES: u32 = 4_096;

/// Maximum events a single transaction may emit. Anti-spam cap;
/// per-block cap (`MAX_EVENTS_PER_BLOCK = 1024`) lives at the consensus
/// layer because it is a commit-time invariant, not an emission-time one.
pub const MAX_EVENTS_PER_TX: usize = 32;

// --- view types --------------------------------------------------------

/// Decoded view of a single emission payload. Returned by
/// `parse_emission_payload` to the J4.3 host fn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEmissionPayload {
    /// Number of topics in `topics`. `0..=MAX_TOPICS_PER_EVENT`.
    pub topic_count: u8,
    /// Owned topics (each exactly `TOPIC_LEN` bytes). Allocated by the
    /// parser from the input slice.
    pub topics: Vec<[u8; TOPIC_LEN]>,
    /// Owned data bytes (length ≤ `MAX_EVENT_DATA_BYTES`).
    pub data: Vec<u8>,
}

// --- errors ------------------------------------------------------------

/// Reasons the sVM may reject an event emission. Each variant maps to a
/// status code surfaced by `sophis_emit_event` (J4.3):
///
/// | Variant                  | Host-fn status |
/// |--------------------------|----------------|
/// | TopicCountOutOfRange     | -3             |
/// | DataTooLarge             | -4             |
/// | Truncated / LengthMismatch | -5           |
///
/// Status `-1` (capability) and `-2` (gas) are checked before parsing,
/// so they do not appear here. Status `-6` (per-tx cap) is enforced in
/// the host fn after a successful parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventError {
    /// `topic_count` byte exceeds `MAX_TOPICS_PER_EVENT`.
    TopicCountOutOfRange(u8),
    /// Declared `data_len` exceeds `MAX_EVENT_DATA_BYTES`.
    DataTooLarge { data_len: u32 },
    /// Wire payload is shorter than the structural minimum
    /// (`1 + 32 * topic_count + 4 + data_len`).
    Truncated { actual: usize, expected: usize },
    /// Wire payload length does not match the exact structural total.
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
                write!(f, "event emission payload is {actual} bytes, expected at least {expected}")
            }
            Self::LengthMismatch { actual, expected } => {
                write!(f, "event emission payload is {actual} bytes, expected exactly {expected}")
            }
        }
    }
}

impl std::error::Error for EventError {}

// --- helpers -----------------------------------------------------------

/// Computes the exact wire length of an emission payload for a given
/// topic count and data length. Single source of truth for the size
/// formula — `parse_emission_payload` and any encoder MUST agree.
pub const fn payload_exact_len(topic_count: u8, data_len: u32) -> usize {
    1 + (topic_count as usize) * TOPIC_LEN + 4 + (data_len as usize)
}

/// Parses and validates an event emission payload as written into sVM
/// linear memory. On `Ok`, the payload is structurally well-formed.
pub fn parse_emission_payload(payload: &[u8]) -> Result<EventEmissionPayload, EventError> {
    // Minimum payload: topic_count(1) + data_len(4) = 5 bytes.
    if payload.len() < 5 {
        return Err(EventError::Truncated { actual: payload.len(), expected: 5 });
    }

    let topic_count = payload[0];
    if topic_count > MAX_TOPICS_PER_EVENT {
        return Err(EventError::TopicCountOutOfRange(topic_count));
    }

    let topics_end = 1 + (topic_count as usize) * TOPIC_LEN;
    let data_len_field_end = topics_end + 4;
    if payload.len() < data_len_field_end {
        return Err(EventError::Truncated { actual: payload.len(), expected: data_len_field_end });
    }

    let mut topics: Vec<[u8; TOPIC_LEN]> = Vec::with_capacity(topic_count as usize);
    for i in 0..topic_count as usize {
        let start = 1 + i * TOPIC_LEN;
        let mut t = [0u8; TOPIC_LEN];
        t.copy_from_slice(&payload[start..start + TOPIC_LEN]);
        topics.push(t);
    }

    let data_len =
        u32::from_le_bytes([payload[topics_end], payload[topics_end + 1], payload[topics_end + 2], payload[topics_end + 3]]);
    if data_len > MAX_EVENT_DATA_BYTES {
        return Err(EventError::DataTooLarge { data_len });
    }

    let expected_total = payload_exact_len(topic_count, data_len);
    if payload.len() != expected_total {
        return Err(EventError::LengthMismatch { actual: payload.len(), expected: expected_total });
    }

    let data_start = data_len_field_end;
    let data = payload[data_start..data_start + data_len as usize].to_vec();
    Ok(EventEmissionPayload { topic_count, topics, data })
}

/// Builds an emission payload from typed inputs. Round-trips through
/// `parse_emission_payload` perfectly. Used by the SDK and by tests.
pub fn encode_emission_payload(topics: &[[u8; TOPIC_LEN]], data: &[u8]) -> Result<Vec<u8>, EventError> {
    let topic_count = topics.len();
    if topic_count > MAX_TOPICS_PER_EVENT as usize {
        return Err(EventError::TopicCountOutOfRange(topic_count as u8));
    }
    if data.len() > MAX_EVENT_DATA_BYTES as usize {
        return Err(EventError::DataTooLarge { data_len: data.len() as u32 });
    }

    let total = payload_exact_len(topic_count as u8, data.len() as u32);
    let mut out = Vec::with_capacity(total);
    out.push(topic_count as u8);
    for t in topics {
        out.extend_from_slice(t);
    }
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_consensus_abi_freeze() {
        // Hand-written cross-check against `consensus-core/src/events/mod.rs`.
        // These four constants are the J4 ABI surface that crosses the
        // svm/consensus boundary; if they ever drift the build still
        // compiles but the chain forks. Hard fork required to change.
        assert_eq!(MAX_TOPICS_PER_EVENT, 4);
        assert_eq!(TOPIC_LEN, 32);
        assert_eq!(MAX_EVENT_DATA_BYTES, 4_096);
        assert_eq!(MAX_EVENTS_PER_TX, 32);
    }

    #[test]
    fn payload_exact_len_zero_topics_zero_data() {
        assert_eq!(payload_exact_len(0, 0), 5);
    }

    #[test]
    fn payload_exact_len_max_topics_max_data() {
        assert_eq!(payload_exact_len(MAX_TOPICS_PER_EVENT, MAX_EVENT_DATA_BYTES), 4229);
    }

    #[test]
    fn round_trip_zero_topics_zero_data() {
        let bytes = encode_emission_payload(&[], &[]).unwrap();
        assert_eq!(bytes.len(), 5);
        let parsed = parse_emission_payload(&bytes).unwrap();
        assert_eq!(parsed.topic_count, 0);
        assert!(parsed.topics.is_empty());
        assert!(parsed.data.is_empty());
    }

    #[test]
    fn round_trip_two_topics_with_data() {
        let topics = [[0x01u8; TOPIC_LEN], [0x02u8; TOPIC_LEN]];
        let data = vec![0xAAu8; 100];
        let bytes = encode_emission_payload(&topics, &data).unwrap();
        assert_eq!(bytes.len(), 169);
        let parsed = parse_emission_payload(&bytes).unwrap();
        assert_eq!(parsed.topic_count, 2);
        assert_eq!(parsed.topics, topics);
        assert_eq!(parsed.data, data);
    }

    #[test]
    fn round_trip_max_topics_max_data() {
        let topics = [[0xCCu8; TOPIC_LEN]; MAX_TOPICS_PER_EVENT as usize];
        let data = vec![0xDDu8; MAX_EVENT_DATA_BYTES as usize];
        let bytes = encode_emission_payload(&topics, &data).unwrap();
        let parsed = parse_emission_payload(&bytes).unwrap();
        assert_eq!(parsed.topic_count, MAX_TOPICS_PER_EVENT);
        assert_eq!(parsed.topics, topics);
        assert_eq!(parsed.data.len(), MAX_EVENT_DATA_BYTES as usize);
    }

    #[test]
    fn rejects_topic_count_above_max() {
        let mut bad = vec![5u8];
        bad.extend_from_slice(&[0u8; 5 * TOPIC_LEN]);
        bad.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(parse_emission_payload(&bad), Err(EventError::TopicCountOutOfRange(5)));
    }

    #[test]
    fn rejects_data_len_above_max() {
        let bad_data_len = MAX_EVENT_DATA_BYTES + 1;
        let mut bad = vec![0u8];
        bad.extend_from_slice(&bad_data_len.to_le_bytes());
        assert_eq!(parse_emission_payload(&bad), Err(EventError::DataTooLarge { data_len: bad_data_len }));
    }

    #[test]
    fn rejects_truncated_below_minimum() {
        let bad = vec![0u8; 4];
        assert_eq!(parse_emission_payload(&bad), Err(EventError::Truncated { actual: 4, expected: 5 }));
    }

    #[test]
    fn rejects_truncated_after_topics() {
        let mut bad = vec![2u8];
        bad.extend_from_slice(&[0u8; 64]);
        assert_eq!(parse_emission_payload(&bad), Err(EventError::Truncated { actual: 65, expected: 69 }));
    }

    #[test]
    fn rejects_extra_trailing_byte() {
        let mut bytes = encode_emission_payload(&[], b"hi").unwrap();
        bytes.push(0xFF);
        match parse_emission_payload(&bytes) {
            Err(EventError::LengthMismatch { actual, expected }) => {
                assert_eq!(actual, expected + 1);
            }
            other => panic!("expected LengthMismatch, got {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_data_byte() {
        let mut bytes = encode_emission_payload(&[], b"hi").unwrap();
        bytes.pop();
        match parse_emission_payload(&bytes) {
            Err(EventError::LengthMismatch { actual, expected }) => {
                assert_eq!(actual + 1, expected);
            }
            other => panic!("expected LengthMismatch, got {other:?}"),
        }
    }

    #[test]
    fn encoder_rejects_too_many_topics() {
        let topics = vec![[0u8; TOPIC_LEN]; (MAX_TOPICS_PER_EVENT + 1) as usize];
        assert_eq!(encode_emission_payload(&topics, b""), Err(EventError::TopicCountOutOfRange(MAX_TOPICS_PER_EVENT + 1)));
    }

    #[test]
    fn encoder_rejects_oversized_data() {
        let big = vec![0u8; (MAX_EVENT_DATA_BYTES + 1) as usize];
        assert_eq!(encode_emission_payload(&[], &big), Err(EventError::DataTooLarge { data_len: MAX_EVENT_DATA_BYTES + 1 }));
    }
}
