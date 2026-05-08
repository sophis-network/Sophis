//! Phase 5 — Plonky3 prover host.
//!
//! Sub-phase 5.2 landed the AIR + soundness check. Sub-phase 5.2.0.1
//! (this commit) wires the full STARK plumbing — `prove()` now returns
//! real opaque proof bytes and `verify()` round-trips them.
//!
//! Stack:
//!   - Field: BabyBear (~31 bits, two-adicity 27)
//!   - Extension: BinomialExtensionField<BabyBear, 4> (~120-bit security)
//!   - Hash: Poseidon2 width-16 BabyBear-native (canonical Plonky3 constants)
//!   - PCS: TwoAdicFriPcs with log_blowup=1, 100 queries, 16-bit query PoW
//!   - Challenger: DuplexChallenger over the same Poseidon2
//!
//! See `config.rs` for type aliases and the `oracle_stark_config()`
//! constructor that both prover and verifier use.
//!
//! Still deferred:
//!   - Sub-phase 5.2.1: ed25519 verification chip in AIR (~4-8 weeks).
//!   - Sub-phase 5.2.2: Solana tx-message parser chip.
//!   - Range proofs as lookup arguments (currently soundness depends on
//!     witness-side pre-checks for non-negativity helpers; the AIR is
//!     sound modulo BabyBear field overflow which is ruled out by the
//!     pre-checks rejecting any value ≥ 2^30).

pub mod air;
pub mod chips;
pub mod config;
pub mod decompress_air_stark;
pub mod decompress_air_stark_chunked;
pub mod reduce_mod_l_air_stark;
pub mod scalar_mul_air_stark;
pub mod scalar_mul_air_stark_chunked;
pub mod sha512_air_stark;
pub mod verify_air_stark;
pub mod verify_air_stark_chunked;

use sophis_oracle_core::{OracleJournal, SignedPriceUpdate};

use crate::air::{OraclePublicInputs, OracleWitness};
use crate::config::{Val, oracle_stark_config};

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("witness violates a pre-check (out-of-bounds price, stale time, replayed sequence)")]
    InvalidWitness,
    #[error("trace generation failed")]
    TraceGenerationFailed,
    #[error("proof serialization failed: {0}")]
    Serialization(String),
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("proof deserialization failed: {0}")]
    Deserialization(String),
    #[error("STARK verification failed: {0}")]
    StarkRejected(String),
}

/// Witnesses plus public inputs for the oracle circuit.
pub struct ProveInputs<'a> {
    pub signed: &'a SignedPriceUpdate,
    pub now_secs: u64,
    pub min_price: i64,
    pub max_price: i64,
    pub max_age_secs: u64,
    pub sequence: u64,
    pub last_sequence: u64,
}

pub struct OracleProof {
    /// Bincode-serialized `p3_uni_stark::Proof<OracleStarkConfig>`.
    pub bytes: Vec<u8>,
    pub journal: OracleJournal,
}

/// Build the witness + public inputs from an externally-fetched
/// `SignedPriceUpdate`. Returns `None` if the witness fails the
/// pre-check that the AIR's range/freshness/sequence chips would catch.
pub fn build_witness(inputs: &ProveInputs<'_>) -> Option<(OracleWitness, OraclePublicInputs)> {
    if inputs.signed.update.price < inputs.min_price || inputs.signed.update.price > inputs.max_price {
        return None;
    }
    if inputs.signed.update.publish_time + inputs.max_age_secs < inputs.now_secs {
        return None;
    }
    if inputs.sequence <= inputs.last_sequence {
        return None;
    }

    let witness = OracleWitness {
        price: inputs.signed.update.price as u64,
        publish_time: inputs.signed.update.publish_time,
        sequence: inputs.sequence,
    };
    let public = OraclePublicInputs {
        min_price: inputs.min_price as u64,
        max_price: inputs.max_price as u64,
        now_minus_max_age: inputs.now_secs.saturating_sub(inputs.max_age_secs),
        last_sequence: inputs.last_sequence,
        payload_commitment: OraclePublicInputs::commit(&witness),
    };
    Some((witness, public))
}

/// Generate a real Plonky3 STARK proof for the given inputs.
///
/// On success, `OracleProof.bytes` contains a bincode-serialized
/// `p3_uni_stark::Proof` that `verify_proof` can round-trip.
pub fn prove(inputs: ProveInputs<'_>) -> Result<OracleProof, ProverError> {
    let (witness, public) = build_witness(&inputs).ok_or(ProverError::InvalidWitness)?;

    let trace = air::generate_trace::<Val>(&witness, &public).ok_or(ProverError::TraceGenerationFailed)?;
    let public_field = air::public_values_field::<Val>(&public);

    let (_perm, config) = oracle_stark_config();
    let proof = p3_uni_stark::prove(&config, &air::OracleAir, trace, &public_field);

    let bytes = bincode::serialize(&proof).map_err(|e| ProverError::Serialization(e.to_string()))?;

    // The journal is the contract-facing public commitment. We keep the same
    // shape as oracle/core's `OracleJournal` so callers can persist + ship it
    // alongside the proof.
    let journal = OracleJournal {
        sequence: inputs.sequence,
        feed: inputs.signed.update.feed,
        publisher: inputs.signed.update.publisher,
        price: inputs.signed.update.price,
        exponent: inputs.signed.update.exponent,
        publish_time: inputs.signed.update.publish_time,
        min_price: inputs.min_price,
        max_price: inputs.max_price,
        max_age_secs: inputs.max_age_secs,
        payload_hash: sophis_oracle_core::hash_oracle_payload(&inputs.signed.update),
    };
    Ok(OracleProof { bytes, journal })
}

/// Verify a proof produced by `prove()` against the public inputs derived
/// from a journal. The caller is expected to have already validated the
/// journal's fields against its own policy (publisher allow-list, bounds
/// sanity); this function only checks the STARK validity.
pub fn verify_proof(proof_bytes: &[u8], journal: &OracleJournal, now_secs: u64) -> Result<(), VerifyError> {
    let proof: p3_uni_stark::Proof<config::OracleStarkConfig> =
        bincode::deserialize(proof_bytes).map_err(|e| VerifyError::Deserialization(e.to_string()))?;

    // Re-derive the public inputs from the journal. They MUST match what
    // the prover committed to or verification will reject.
    let public = OraclePublicInputs {
        min_price: journal.min_price as u64,
        max_price: journal.max_price as u64,
        now_minus_max_age: now_secs.saturating_sub(journal.max_age_secs),
        last_sequence: journal.sequence.saturating_sub(1),
        payload_commitment: OraclePublicInputs::commit(&OracleWitness {
            price: journal.price as u64,
            publish_time: journal.publish_time,
            sequence: journal.sequence,
        }),
    };
    let public_field = air::public_values_field::<Val>(&public);

    let (_perm, config) = oracle_stark_config();
    p3_uni_stark::verify(&config, &air::OracleAir, &proof, &public_field).map_err(|e| VerifyError::StarkRejected(format!("{e:?}")))
}

/// Run the full AIR against a generated trace (debug-only soundness check).
/// Used by tests in this and downstream crates to confirm the cryptographic
/// claims are well-formed end-to-end. Panics on failure.
#[cfg(test)]
pub fn validate_witness_against_air(witness: &OracleWitness, public: &OraclePublicInputs) {
    let trace = air::generate_trace::<Val>(witness, public).expect("witness should pass pre-checks");
    let pub_field = air::public_values_field::<Val>(public);
    p3_air::check_constraints(&air::OracleAir, &trace, &pub_field);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sophis_oracle_core::{FeedId, PriceUpdate, PublisherKey};

    fn signed(price: i64, publish_time: u64) -> SignedPriceUpdate {
        SignedPriceUpdate {
            update: PriceUpdate {
                feed: FeedId(*b"BTC/USD\0"),
                publisher: PublisherKey([1u8; 32]),
                price,
                conf: 0,
                exponent: -8,
                publish_time,
            },
            signature: Box::new([0u8; 64]),
        }
    }

    fn inputs<'a>(s: &'a SignedPriceUpdate) -> ProveInputs<'a> {
        ProveInputs {
            signed: s,
            now_secs: 1_700_000_120,
            min_price: 1_000_00,
            max_price: 1_000_000_00,
            max_age_secs: 60,
            sequence: 100,
            last_sequence: 99,
        }
    }

    #[test]
    fn build_witness_happy_path() {
        let s = signed(65_000_00, 1_700_000_080);
        let (w, p) = build_witness(&inputs(&s)).expect("should build");
        assert_eq!(w.price, 65_000_00);
        assert_eq!(p.last_sequence, 99);
        assert_eq!(p.now_minus_max_age, 1_700_000_060);
    }

    #[test]
    fn build_witness_rejects_oob_price() {
        let s = signed(1, 1_700_000_080);
        assert!(build_witness(&inputs(&s)).is_none());
    }

    #[test]
    fn build_witness_rejects_stale() {
        let s = signed(65_000_00, 1);
        assert!(build_witness(&inputs(&s)).is_none());
    }

    #[test]
    fn build_witness_rejects_replay() {
        let s = signed(65_000_00, 1_700_000_080);
        let mut i = inputs(&s);
        i.sequence = 99;
        assert!(build_witness(&i).is_none());
    }

    #[test]
    fn happy_witness_satisfies_air() {
        let s = signed(65_000_00, 1_700_000_080);
        let (w, p) = build_witness(&inputs(&s)).unwrap();
        validate_witness_against_air(&w, &p);
    }

    #[test]
    fn prove_then_verify_round_trip() {
        let s = signed(65_000_00, 1_700_000_080);
        let proof = prove(inputs(&s)).expect("prove should succeed");
        assert!(!proof.bytes.is_empty(), "proof bytes should be non-empty");
        verify_proof(&proof.bytes, &proof.journal, 1_700_000_120).expect("verify should succeed");
    }

    #[test]
    fn verify_rejects_tampered_journal_price() {
        let s = signed(65_000_00, 1_700_000_080);
        let proof = prove(inputs(&s)).unwrap();
        let mut bad_journal = proof.journal.clone();
        bad_journal.price = 12_345_67; // mutate; commitment no longer matches
        let r = verify_proof(&proof.bytes, &bad_journal, 1_700_000_120);
        assert!(r.is_err(), "verify must reject tampered journal");
    }

    #[test]
    fn verify_rejects_corrupted_proof_bytes() {
        let s = signed(65_000_00, 1_700_000_080);
        let mut proof = prove(inputs(&s)).unwrap();
        // Flip a byte deep inside the opened-values payload (well past the
        // structural varint tags, far from the trailing degree_bits varint).
        // This survives deserialization but produces an invalid challenge,
        // so the STARK verifier rejects it cleanly.
        let off = proof.bytes.len() / 2;
        proof.bytes[off] ^= 0x01;
        let r = verify_proof(&proof.bytes, &proof.journal, 1_700_000_120);
        assert!(r.is_err(), "verify must reject corrupted proof");
    }
}
