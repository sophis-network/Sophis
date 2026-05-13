//! # Phase 9 PQC-Native Oracle — Submission Validator Contract
//!
//! Stateless sVM contract that gates publisher submissions for the Phase 9
//! oracle. Each submission transaction carries exactly one borsh-encoded
//! [`PriceAttestation`] in the datum of input UTXO 0. This contract
//! validates the Dilithium ML-DSA-44 signature over the canonical
//! signing-hash (domain separator `sophis-oracle-pqc-v1\0` + length-prefixed
//! attestation core, SHA3-384-truncated-to-32) and emits a structured J4
//! event so off-chain indexers can ingest the attested price.
//!
//! ## What this contract does NOT do (deferred to follow-up sessions)
//!
//! - **Publisher registry check.** This v1 contract accepts any
//!   well-formed Dilithium signature. A companion registry contract
//!   (9.1.x) will gate on registered publisher keys. Off-chain indexers
//!   filter by registered publishers in the interim.
//! - **Per-publisher monotonic sequence check.** Replay protection is
//!   defence-in-depth at the indexer / consumer layer for v1; the
//!   registry-state contract (9.1.x) will enforce sequence advance
//!   on-chain via consumed/produced PublisherState UTXOs.
//! - **Rate limit (D8).** Off-chain mempool policy for v1.
//! - **Timestamp staleness (D5).** Consumer-side check via
//!   `oracle_pqc_core::verify_attestation(attestation, now)`. The
//!   contract has no wall-clock primitive in v1 (DAA score is the only
//!   chain-time primitive exposed; mapping DAA→wall-clock is approximate
//!   at 10 BPS).
//! - **Median computation.** Indexer aggregates over the J4 event log
//!   per asset within a time window.
//!
//! These deferrals match the design doc's "v1 lite" framing
//! (`docs/PQC_NATIVE_ORACLE_DESIGN.md` §4 + §9). Strong on-chain
//! enforcement of registry / sequence / rate-limit lands in 9.1.x as a
//! companion registry-state contract; the wire format defined in
//! `oracle/pqc-core` is unchanged across that evolution.
//!
//! ## Wire integration
//!
//! Submission transactions carry the borsh-encoded `PriceAttestation`
//! in input UTXO 0's `script_public_key.script` bytes (excluding any
//! routing prefix). The contract reads the script field directly. A
//! companion consensus change (Phase 9.x) will reserve a dedicated
//! `ScriptPublicKey` version byte for "Phase 9 oracle submission" so
//! consensus dispatch routes such txs to this contract without ambiguity;
//! until then, deployments call this contract by setting its manifest as
//! the spending policy of a one-off contract UTXO whose script bytes are
//! the attestation payload.
//!
//! ## Event layout (J4)
//!
//! Emitted on accept:
//!
//! - `topic[0]` = [`event_id_phase9_attestation()`] (event signature hash)
//! - `topic[1]` = `attestation.core.asset_id` (32 bytes, canonical SIP-11 D7)
//! - `topic[2]` = `SHA3-384(attestation.publisher_pubkey)[..32]` (32-byte
//!               publisher fingerprint so indexers can group by publisher
//!               without storing the full 1312-byte key in topics)
//! - `data`    = borsh-encoded `(price_e8: i64, conf_e8: u64, publish_ts: u64, sequence: u64)`
//!               = 32 bytes
//!
//! Three topics fits comfortably inside `MAX_TOPICS_PER_EVENT` (= 4).

use borsh::{BorshDeserialize, BorshSerialize};
use sha3::{Digest, Sha3_384};
use sophis_oracle_pqc_core::{DOMAIN_SEPARATOR, OraclePqcError, PriceAttestation, compute_signing_hash};
use sophis_sdk::env::EmitEventError;
use sophis_sdk::prelude::*;

/// Canonical event-signature topic for Phase 9 price attestations.
///
/// Returns `SHA3-384(b"sophis-oracle-pqc-v1/PriceAttestation")[..32]`.
/// Computed at runtime each time it is needed; indexers call this same
/// function (or copy the byte derivation) to pin to the canonical tag.
pub fn event_id_phase9_attestation() -> [u8; 32] {
    let mut hasher = Sha3_384::new();
    hasher.update(b"sophis-oracle-pqc-v1/PriceAttestation");
    let full = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

/// 32-byte borsh-encoded `(price_e8, conf_e8, publish_ts, sequence)` carried
/// in the event `data` field. Frozen layout per SIP-11.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EventDataV1 {
    pub price_e8: i64,
    pub conf_e8: u64,
    pub publish_ts: u64,
    pub sequence: u64,
}

/// Submission-validator entry point.
///
/// Returns `true` to accept the submission; `false` to reject.
///
/// On accept, the contract emits a J4 event (topics + data per the module
/// doc); off-chain indexers ingest the event stream to feed consumers.
#[sophis_contract]
pub fn validate_submission(env: Env) -> bool {
    let attestation = match read_attestation(&env) {
        Some(a) => a,
        None => return false,
    };

    if !verify_signature(&env, &attestation) {
        return false;
    }

    emit_attestation_event(&env, &attestation).is_ok()
}

// ---------------------------------------------------------------------------
// Logic decomposition — Env-touching wrappers plus pure helpers that can be
// unit-tested natively without the WASM runtime.
// ---------------------------------------------------------------------------

/// Reads the borsh-encoded [`PriceAttestation`] from input UTXO 0's
/// `script_public_key.script` field. Returns `None` on missing UTXO
/// or decode error.
///
/// Pure decoding logic lives in [`decode_attestation_bytes`] so it is
/// native-testable; this wrapper only performs the env call.
fn read_attestation(env: &Env) -> Option<PriceAttestation> {
    let utxo = env.input_utxo(0)?;
    decode_attestation_bytes(&utxo.script_public_key.script)
}

/// Pure decoder: borsh-deserialize a `PriceAttestation` from raw bytes,
/// returning `None` on any parse error. Native-testable.
pub fn decode_attestation_bytes(bytes: &[u8]) -> Option<PriceAttestation> {
    PriceAttestation::from_bytes(bytes).ok()
}

/// Calls the host `verify_dilithium` capability against the canonical
/// Phase 9 signing-hash. Returns `false` if the signature is invalid or
/// the capability is unavailable.
fn verify_signature(env: &Env, attestation: &PriceAttestation) -> bool {
    let signing_hash = compute_signing_hash(DOMAIN_SEPARATOR, &attestation.core);
    env.verify_dilithium(&attestation.publisher_pubkey, &signing_hash, attestation.signature.as_ref())
}

/// Computes the canonical event-data payload from the attestation core.
/// Pure function; native-testable.
pub fn build_event_data(attestation: &PriceAttestation) -> EventDataV1 {
    EventDataV1 {
        price_e8: attestation.core.price_e8,
        conf_e8: attestation.core.conf_e8,
        publish_ts: attestation.core.publish_ts,
        sequence: attestation.core.sequence,
    }
}

/// Computes the publisher fingerprint topic — SHA3-384 of the 1312-byte
/// publisher pubkey, truncated to 32 bytes. Pure function; uses the
/// `sha3` crate so it is identical on WASM and native (the host
/// `sha3_384` capability would only work in WASM).
pub fn publisher_fingerprint(pubkey: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_384::new();
    hasher.update(pubkey);
    let full = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

/// Emits the J4 attestation event. Returns `Ok(())` on accept,
/// `Err(EmitEventError)` if the host rejects (capability missing,
/// gas exhausted, per-tx cap reached, etc).
fn emit_attestation_event(env: &Env, attestation: &PriceAttestation) -> Result<(), EmitEventError> {
    let event_data = build_event_data(attestation);
    let data_bytes = borsh::to_vec(&event_data).map_err(|_| EmitEventError::StructuralError)?;

    let topics = [event_id_phase9_attestation(), attestation.core.asset_id, publisher_fingerprint(&attestation.publisher_pubkey)];

    env.emit_event(&topics, &data_bytes)
}

// ---------------------------------------------------------------------------
// Surface helpers exposed for downstream consumers (indexers, consumer
// contracts) so they decode events with the same canonical types the
// contract emits.
// ---------------------------------------------------------------------------

/// Decode a J4 event `data` payload produced by this contract.
pub fn decode_event_data(data: &[u8]) -> Result<EventDataV1, OraclePqcError> {
    borsh::from_slice::<EventDataV1>(data).map_err(|_| OraclePqcError::DecodeFailed)
}

// ---------------------------------------------------------------------------
// Unit tests — run with `cargo test` on native (no WASM toolchain needed)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sophis_oracle_pqc_core::{PriceAttestationCore, asset_id_from_symbol};

    fn fixture_attestation() -> PriceAttestation {
        // Build a deterministic, never-verified placeholder attestation —
        // these tests exercise the pure-logic helpers; signature checks
        // live in the WASM integration tests.
        PriceAttestation {
            core: PriceAttestationCore {
                asset_id: asset_id_from_symbol(b"BTC/USD"),
                price_e8: 65_000_00000000,
                conf_e8: 50_00000000,
                publish_ts: 1_700_000_000,
                sequence: 7,
            },
            publisher_pubkey: [0xab; sophis_oracle_pqc_core::DILITHIUM_PUBKEY_SIZE],
            signature: Box::new([0xcd; sophis_oracle_pqc_core::DILITHIUM_SIG_SIZE]),
        }
    }

    #[test]
    fn build_event_data_preserves_core_fields() {
        let attestation = fixture_attestation();
        let event = build_event_data(&attestation);
        assert_eq!(event.price_e8, attestation.core.price_e8);
        assert_eq!(event.conf_e8, attestation.core.conf_e8);
        assert_eq!(event.publish_ts, attestation.core.publish_ts);
        assert_eq!(event.sequence, attestation.core.sequence);
    }

    #[test]
    fn event_data_borsh_roundtrip_is_32_bytes() {
        let attestation = fixture_attestation();
        let event = build_event_data(&attestation);
        let bytes = borsh::to_vec(&event).unwrap();
        assert_eq!(bytes.len(), 8 + 8 + 8 + 8);
        let decoded = decode_event_data(&bytes).unwrap();
        assert_eq!(decoded, event);
    }

    #[test]
    fn decode_event_data_rejects_malformed_bytes() {
        let res = decode_event_data(b"not an event payload");
        assert!(res.is_err());
    }

    #[test]
    fn event_id_is_deterministic() {
        // Calling twice yields the same bytes (no statefulness in the hasher).
        let a = event_id_phase9_attestation();
        let b = event_id_phase9_attestation();
        assert_eq!(a, b);
    }

    #[test]
    fn event_id_distinct_from_canonical_asset_ids() {
        // Sanity: the event-id constant must not collide with any asset_id
        // an indexer would compute via `asset_id_from_symbol`, otherwise
        // topic[0] and topic[1] could be confused.
        let event_id = event_id_phase9_attestation();
        let common_assets: &[&[u8]] = &[b"BTC/USD", b"ETH/USD", b"SPHS/USD", b"SOL/USD", b"USDC/USD"];
        for symbol in common_assets {
            assert_ne!(event_id, asset_id_from_symbol(symbol));
        }
    }

    #[test]
    fn publisher_fingerprint_is_deterministic_and_pubkey_sensitive() {
        let a = fixture_attestation();
        let fp_a1 = publisher_fingerprint(&a.publisher_pubkey);
        let fp_a2 = publisher_fingerprint(&a.publisher_pubkey);
        assert_eq!(fp_a1, fp_a2);

        // Different pubkey → different fingerprint.
        let other_pubkey = [0x12u8; sophis_oracle_pqc_core::DILITHIUM_PUBKEY_SIZE];
        let fp_other = publisher_fingerprint(&other_pubkey);
        assert_ne!(fp_a1, fp_other);
    }

    #[test]
    fn decode_attestation_bytes_roundtrips_via_borsh() {
        let original = fixture_attestation();
        let bytes = original.to_bytes().unwrap();
        let decoded = decode_attestation_bytes(&bytes).expect("borsh roundtrip must succeed");
        assert_eq!(decoded.core, original.core);
        assert_eq!(decoded.publisher_pubkey, original.publisher_pubkey);
        assert_eq!(*decoded.signature, *original.signature);
    }

    #[test]
    fn decode_attestation_bytes_rejects_garbage() {
        assert!(decode_attestation_bytes(b"not a valid attestation").is_none());
        assert!(decode_attestation_bytes(&[]).is_none());
    }

    #[test]
    fn publisher_fingerprint_uses_canonical_sha3_384_truncated() {
        // Pin the fingerprint derivation against drift: it MUST be the
        // first 32 bytes of SHA3-384(pubkey), nothing else.
        let pubkey = [0x42u8; sophis_oracle_pqc_core::DILITHIUM_PUBKEY_SIZE];
        let mut hasher = Sha3_384::new();
        hasher.update(pubkey);
        let full = hasher.finalize();
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&full[..32]);
        assert_eq!(publisher_fingerprint(&pubkey), expected);
    }
}
