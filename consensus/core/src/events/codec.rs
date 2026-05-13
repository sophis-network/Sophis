//! J4 — codec for event emission payloads.
//!
//! Pure helpers, no I/O, no consensus state. Owns three primitives:
//!
//! * `parse_emission_payload`  — validate the wire bytes the contract
//!   passed via `sophis_emit_event` (host fn — J4.3)
//! * `encode_emission_payload` — build the same wire format from typed
//!   inputs (used by tests and the future SDK)
//! * `topic_signature_hash`    — convenience helper that hashes an
//!   event signature string into the canonical `topic[0]` value
//!
//! Cross-references:
//! * §3 of `docs/J4_EVENTS_DESIGN.md` — wire format
//! * `events::EventError`              — structural rejection codes
//! * `events::payload_exact_len`       — single source of truth for the
//!   length formula (kept in `mod.rs` so the parser and the codec
//!   cannot drift)

use sha3::{Digest, Sha3_384};

use super::{EventError, MAX_EVENT_DATA_BYTES, MAX_TOPICS_PER_EVENT, TOPIC_LEN, payload_exact_len};

/// Parses and validates an event emission payload as written into sVM
/// linear memory. On `Ok`, the payload is structurally well-formed and
/// satisfies rules 3-5 of §5 of the design doc.
///
/// Layout (must match `parse_emission_payload`):
/// ```text
///   0..1     topic_count: u8       (must be 0..=MAX_TOPICS_PER_EVENT = 4)
///   1..N     topics:      [u8; 32 * topic_count]
///   N..N+4   data_len:    u32 LE   (must be ≤ MAX_EVENT_DATA_BYTES = 4096)
///  N+4..end  data:        [u8; data_len]
/// ```
///
/// On error, the variant precisely identifies which rule was violated;
/// see `EventError` for the mapping.
pub fn parse_emission_payload(payload: &[u8]) -> Result<super::EventEmissionPayload, EventError> {
    // The minimum payload is `topic_count(1) + data_len(4)` = 5 bytes;
    // shorter payloads cannot even encode an empty event.
    if payload.len() < 5 {
        return Err(EventError::Truncated { actual: payload.len(), expected: 5 });
    }

    // Rule 3 — topic count bounds.
    let topic_count = payload[0];
    if topic_count > MAX_TOPICS_PER_EVENT {
        return Err(EventError::TopicCountOutOfRange(topic_count));
    }

    // Header + topics must fit before we read data_len.
    let topics_end = 1 + (topic_count as usize) * TOPIC_LEN;
    let data_len_field_end = topics_end + 4;
    if payload.len() < data_len_field_end {
        return Err(EventError::Truncated { actual: payload.len(), expected: data_len_field_end });
    }

    // Pull out topics into owned buffers (cheap; topic_count ≤ 4).
    let mut topics: Vec<[u8; TOPIC_LEN]> = Vec::with_capacity(topic_count as usize);
    for i in 0..topic_count as usize {
        let start = 1 + i * TOPIC_LEN;
        let mut t = [0u8; TOPIC_LEN];
        t.copy_from_slice(&payload[start..start + TOPIC_LEN]);
        topics.push(t);
    }

    // Rule 4 — data length bounds.
    let data_len =
        u32::from_le_bytes([payload[topics_end], payload[topics_end + 1], payload[topics_end + 2], payload[topics_end + 3]]);
    if data_len > MAX_EVENT_DATA_BYTES {
        return Err(EventError::DataTooLarge { data_len });
    }

    // Rule 5 — exact length match.
    let expected_total = payload_exact_len(topic_count, data_len);
    if payload.len() != expected_total {
        return Err(EventError::LengthMismatch { actual: payload.len(), expected: expected_total });
    }

    let data_start = data_len_field_end;
    let data = payload[data_start..data_start + data_len as usize].to_vec();
    Ok(super::EventEmissionPayload { topic_count, topics, data })
}

/// Builds an emission payload from typed inputs. Returns `Err` so
/// producer tooling cannot silently emit bytes consensus would reject:
///
/// * more than `MAX_TOPICS_PER_EVENT` topics → `TopicCountOutOfRange(n)`
/// * `data.len() > MAX_EVENT_DATA_BYTES`     → `DataTooLarge`
///
/// On success the returned `Vec<u8>` round-trips through
/// `parse_emission_payload` perfectly.
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

/// Convenience helper: derives the canonical `topic[0]` for an event
/// signature string. Matches the convention `topic[0] =
/// SHA3-384(signature)[..32]` documented in §2 (D1) of the design doc.
///
/// The 32-byte truncation makes the result Ethereum-shaped while keeping
/// Sophis's SHA3-384 default. No padding bytes — the upper 16 bytes of
/// the 384-bit hash are simply discarded.
pub fn topic_signature_hash(event_signature: &str) -> [u8; TOPIC_LEN] {
    let mut hasher = Sha3_384::new();
    hasher.update(event_signature.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; TOPIC_LEN];
    out.copy_from_slice(&digest[..TOPIC_LEN]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- happy paths ----------------------------------------------------

    #[test]
    fn round_trip_zero_topics_zero_data() {
        let bytes = encode_emission_payload(&[], &[]).unwrap();
        // 1 (count=0) + 4 (data_len=0) = 5 bytes.
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
        // 1 + 64 + 4 + 100 = 169.
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

    // --- Rule 3 — topic count bounds (parser side) ----------------------

    #[test]
    fn rule_3_topic_count_above_max_is_rejected() {
        // Construct a hand-rolled buffer; encoder won't allow this.
        let mut bad = vec![5u8]; // topic_count = 5 (> MAX = 4)
        bad.extend_from_slice(&[0u8; 5 * TOPIC_LEN]);
        bad.extend_from_slice(&0u32.to_le_bytes());
        match parse_emission_payload(&bad) {
            Err(EventError::TopicCountOutOfRange(5)) => {}
            other => panic!("expected TopicCountOutOfRange(5), got {other:?}"),
        }
    }

    #[test]
    fn rule_3_topic_count_at_max_is_accepted() {
        let topics = [[0u8; TOPIC_LEN]; MAX_TOPICS_PER_EVENT as usize];
        let bytes = encode_emission_payload(&topics, b"").unwrap();
        let p = parse_emission_payload(&bytes).unwrap();
        assert_eq!(p.topic_count, MAX_TOPICS_PER_EVENT);
    }

    // --- Rule 4 — data length bounds ------------------------------------

    #[test]
    fn rule_4_data_too_large_is_rejected_by_parser() {
        // We can't actually feed a 4097-byte payload through the encoder
        // (it rejects up-front). Build a hand-rolled header that lies
        // about its data_len.
        let bad_data_len = MAX_EVENT_DATA_BYTES + 1;
        let mut bad = vec![0u8]; // topic_count = 0
        bad.extend_from_slice(&bad_data_len.to_le_bytes());
        // Don't bother allocating bad_data_len bytes — the parser fails
        // on the data_len bounds check before reading the body.
        match parse_emission_payload(&bad) {
            Err(EventError::DataTooLarge { data_len }) => assert_eq!(data_len, bad_data_len),
            other => panic!("expected DataTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn rule_4_data_at_max_is_accepted() {
        let bytes = encode_emission_payload(&[], &vec![0xAAu8; MAX_EVENT_DATA_BYTES as usize]).unwrap();
        let p = parse_emission_payload(&bytes).unwrap();
        assert_eq!(p.data.len(), MAX_EVENT_DATA_BYTES as usize);
    }

    // --- Rule 5 — structural length ------------------------------------

    #[test]
    fn rule_5_truncated_below_minimum_is_rejected() {
        // 4 bytes — can't even encode topic_count + empty data_len.
        let bad = vec![0u8; 4];
        match parse_emission_payload(&bad) {
            Err(EventError::Truncated { actual: 4, expected: 5 }) => {}
            other => panic!("expected Truncated(4, 5), got {other:?}"),
        }
    }

    #[test]
    fn rule_5_truncated_after_topics_is_rejected() {
        // topic_count = 2 → expected data_len at offset 1 + 64 = 65.
        // Only provide 65 bytes (no data_len field).
        let mut bad = vec![2u8];
        bad.extend_from_slice(&[0u8; 64]); // topics
        // missing data_len
        match parse_emission_payload(&bad) {
            Err(EventError::Truncated { actual: 65, expected: 69 }) => {}
            other => panic!("expected Truncated(65, 69), got {other:?}"),
        }
    }

    #[test]
    fn rule_5_length_mismatch_extra_trailing_byte() {
        let mut bytes = encode_emission_payload(&[], b"hi").unwrap();
        bytes.push(0xFF); // extra byte
        match parse_emission_payload(&bytes) {
            Err(EventError::LengthMismatch { actual, expected }) => {
                assert_eq!(actual, expected + 1);
            }
            other => panic!("expected LengthMismatch (extra), got {other:?}"),
        }
    }

    #[test]
    fn rule_5_length_mismatch_missing_data_byte() {
        let mut bytes = encode_emission_payload(&[], b"hi").unwrap();
        bytes.pop(); // drop one byte from the data section
        match parse_emission_payload(&bytes) {
            Err(EventError::LengthMismatch { actual, expected }) => {
                assert_eq!(actual + 1, expected);
            }
            other => panic!("expected LengthMismatch (missing), got {other:?}"),
        }
    }

    // --- encoder rejections --------------------------------------------

    #[test]
    fn encoder_rejects_too_many_topics() {
        let topics = vec![[0u8; TOPIC_LEN]; (MAX_TOPICS_PER_EVENT + 1) as usize];
        match encode_emission_payload(&topics, b"") {
            Err(EventError::TopicCountOutOfRange(n)) => {
                assert_eq!(n, MAX_TOPICS_PER_EVENT + 1);
            }
            other => panic!("expected TopicCountOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn encoder_rejects_oversized_data() {
        let big = vec![0u8; (MAX_EVENT_DATA_BYTES + 1) as usize];
        match encode_emission_payload(&[], &big) {
            Err(EventError::DataTooLarge { data_len }) => {
                assert_eq!(data_len, MAX_EVENT_DATA_BYTES + 1);
            }
            other => panic!("expected DataTooLarge, got {other:?}"),
        }
    }

    // --- topic_signature_hash ------------------------------------------

    #[test]
    fn topic_signature_hash_deterministic() {
        let h1 = topic_signature_hash("Transfer(address,address,uint256)");
        let h2 = topic_signature_hash("Transfer(address,address,uint256)");
        assert_eq!(h1, h2);
    }

    #[test]
    fn topic_signature_hash_distinguishes_signatures() {
        let h1 = topic_signature_hash("Transfer(address,address,uint256)");
        let h2 = topic_signature_hash("Approval(address,address,uint256)");
        assert_ne!(h1, h2);
    }

    #[test]
    fn topic_signature_hash_returns_32_bytes() {
        let h = topic_signature_hash("anything");
        assert_eq!(h.len(), TOPIC_LEN);
    }

    // --- canonical first 32 bytes of SHA3-384 --------------------------

    #[test]
    fn topic_signature_hash_is_sha3_384_truncated() {
        // SHA3-384("") canonical first 32 bytes; lock the truncation
        // semantics so it never silently changes.
        let h = topic_signature_hash("");
        let mut hasher = sha3::Sha3_384::new();
        hasher.update(b"");
        let full = hasher.finalize();
        assert_eq!(&h[..], &full[..TOPIC_LEN]);
    }
}
