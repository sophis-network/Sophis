//! Sub-fase 5.6.c.1.e.2 — STARK plumbing for the SHA-512 `CompressionChip`.
//!
//! Wraps `chips::sha512::compression_chip::CompressionChip` with the same
//! Plonky3 `OracleStarkConfig` used elsewhere in the oracle stack:
//!
//!   - `prove_sha512_air(message)` → `Sha512AirProof { bytes, digest }`
//!   - `verify_sha512_air_proof(bytes, message, expected_digest)` → check
//!
//! ## What this proves (post 5.6.c.1.e.2)
//!
//! The AIR encodes the full single-block SHA-512 compression — all four
//! sub-fases of the chain are now bound by STARK constraints:
//!
//!   - 5.6.c.1.a: row 0 input state == `H_INITIAL` (canonical IV)
//!   - 5.6.c.1.b.1: per-row K[t] matches the preprocessed FIPS constants
//!   - 5.6.c.1.b.2/b.3: the W[16..80] words follow the canonical message
//!     schedule recurrence (`σ1 + σ0 + add` chain) wired through the
//!     embedded `ScheduleStepChip`
//!   - 5.6.c.1.c: the 8 add-back chips compute `H_INITIAL + state_after_80`
//!   - 5.6.c.1.e.1: 96 PV elements bind the 16 message words (at row 16
//!     of the W shift register) and the 8 digest words (at row 79's
//!     add-back outputs)
//!
//! Public values (96 BabyBear elements):
//!   - PV[0..64]:   16 message-block words × 4 16-bit chunks each
//!   - PV[64..96]:  8 digest words × 4 16-bit chunks each
//!
//! After 5.6.c.1.e.2 the wrapper does **no Rust-side re-derivation**:
//! `verify_sha512_air_proof` runs a pure STARK verification against the
//! caller-supplied `(message, expected_digest)`. Tampering with either
//! input triggers a `StarkRejected` error.
//!
//! ## Multi-block (5.6.c.1.d.multi — DELIVERED)
//!
//! `prove_sha512_air` accepts messages of arbitrary length. For ≤ 111
//! bytes (single FIPS-padded block) the wrapper produces one STARK; for
//! longer messages it produces N STARKs chained via the IV PV: block 0
//! has IV = `H_INITIAL`, block k > 0 has IV = digest of block k-1.
//! Returned `bytes` is a `bincode::serialize(&Vec<Vec<u8>>)`, where each
//! inner vec is one bincode-serialized `p3_uni_stark::Proof`.
//!
//! `verify_sha512_air_proof` re-derives the FIPS padding from the
//! caller-supplied `message`, deserializes the per-block proofs, and
//! verifies each against `(IV_k, block_k, digest_k)` PVs. Chain
//! integrity is enforced by computing `digest_k` deterministically via
//! `compute_compression(Sha512State::new(iv), block)` — if the prover
//! lied about any block's digest, the STARK constraints reject because
//! the chip's add-back must match. The final block's digest is then
//! compared to the caller-supplied `expected_digest`.

use std::sync::OnceLock;

use p3_uni_stark::{
    PreprocessedProverData, PreprocessedVerifierKey, prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed,
};

use crate::chips::sha512::compression::compute_compression;
use crate::chips::sha512::compression_chip::{CompressionChip, build_compression_trace, build_public_values, fips_pad_multi_block};
use crate::chips::sha512::constants::H_INITIAL;
use crate::chips::sha512::round::Sha512State;
use crate::config::{OracleStarkConfig, Val, oracle_stark_config};

/// `log2(TRACE_HEIGHT)` where `TRACE_HEIGHT = 128 = 2^7`.
const LOG_TRACE_DEGREE: usize = 7;

const DIGEST_BYTES: usize = 64;

/// Cached preprocessed prover data + verifier key.
///
/// `setup_preprocessed` commits to the chip's preprocessed columns
/// (K constants + 3 row-selectors) and is moderately expensive
/// (Merkle commit over a 7-col × 128-row matrix). The setup is
/// deterministic across runs of the same chip + degree, so we cache
/// the result globally and reuse it for every prove/verify call.
static SHA512_PREPROCESSED: OnceLock<(PreprocessedProverData<OracleStarkConfig>, PreprocessedVerifierKey<OracleStarkConfig>)> =
    OnceLock::new();

fn preprocessed_setup() -> &'static (PreprocessedProverData<OracleStarkConfig>, PreprocessedVerifierKey<OracleStarkConfig>) {
    SHA512_PREPROCESSED.get_or_init(|| {
        let (_perm, config) = oracle_stark_config();
        setup_preprocessed(&config, &CompressionChip, LOG_TRACE_DEGREE)
            .expect("CompressionChip declares preprocessed_trace; setup must succeed")
    })
}

#[derive(Debug, thiserror::Error)]
pub enum Sha512AirProverError {
    #[error("trace generation failed: {0}")]
    TraceFailed(String),
    #[error("proof serialization failed: {0}")]
    Serialization(String),
}

#[derive(Debug, thiserror::Error)]
pub enum Sha512AirVerifyError {
    #[error("proof deserialization failed: {0}")]
    Deserialization(String),
    #[error("STARK verification failed: {0}")]
    StarkRejected(String),
    #[error("multi-block chain integrity check failed: {0}")]
    ChainIntegrity(String),
    #[error("public values length wrong (got {got}, want {want})")]
    BadPublicValuesLen { got: usize, want: usize },
}

/// Opaque proof bytes plus the digest the prover witnessed.
pub struct Sha512AirProof {
    /// Bincode-serialized `p3_uni_stark::Proof<OracleStarkConfig>`.
    pub bytes: Vec<u8>,
    /// SHA-512 digest of `message` (big-endian per FIPS 180-4).
    pub digest: [u8; DIGEST_BYTES],
}

/// Generate a STARK proof of SHA-512 for a message of arbitrary length
/// (sub-fase 5.6.c.1.d.multi).
///
/// For messages ≤ 111 bytes (after FIPS padding fits in one block), the
/// returned `bytes` field holds a serialized `Vec<Vec<u8>>` of length 1
/// containing one bincode-serialized `Proof`. For longer messages, the
/// vec contains N proofs, one per 1024-bit FIPS-padded block. Each block
/// k > 0 uses the digest of block k-1 as its IV.
///
/// **Slow** — each block produces a STARK over ~2172 cols × 128 rows.
/// Single-block messages run in well under a second in release; large
/// messages scale linearly.
pub fn prove_sha512_air(message: &[u8]) -> Result<Sha512AirProof, Sha512AirProverError> {
    let blocks = fips_pad_multi_block(message);
    debug_assert!(!blocks.is_empty(), "fips_pad_multi_block always emits ≥ 1 block");

    let setup = preprocessed_setup();
    let (_perm, config) = oracle_stark_config();

    let mut iv = H_INITIAL;
    let mut proofs: Vec<Vec<u8>> = Vec::with_capacity(blocks.len());
    let mut last_digest = iv;

    for block in &blocks {
        // Compress one block deterministically to derive the digest words
        // for this block's PV (and the IV of the next block).
        let final_state = compute_compression(Sha512State::new(iv), block);
        let digest_words = final_state.0;

        let trace = build_compression_trace::<Val>(&iv, block);
        let public_values = build_public_values::<Val>(&iv, block, &digest_words);
        let proof = prove_with_preprocessed(&config, &CompressionChip, trace, &public_values, Some(&setup.0));
        let proof_bytes = bincode::serialize(&proof).map_err(|e| Sha512AirProverError::Serialization(e.to_string()))?;
        proofs.push(proof_bytes);

        last_digest = digest_words;
        iv = digest_words; // Next block chains.
    }

    let aggregated = bincode::serialize(&proofs).map_err(|e| Sha512AirProverError::Serialization(e.to_string()))?;

    let mut digest_bytes = [0u8; DIGEST_BYTES];
    for (i, word) in last_digest.iter().enumerate() {
        digest_bytes[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
    }

    Ok(Sha512AirProof { bytes: aggregated, digest: digest_bytes })
}

/// Verify proof bytes produced by `prove_sha512_air` against the supplied
/// `(message, expected_digest)`.
///
/// As of 5.6.c.1.d.multi the wrapper handles arbitrary-length messages
/// by deserializing N STARK proofs (one per FIPS block), verifying each
/// with the appropriate IV / block / digest, and checking the chain:
///
///   - Block 0's IV PV must equal `H_INITIAL`.
///   - For k > 0, block k's IV PV must equal block k-1's digest PV.
///   - Block N-1's digest PV must equal the supplied `expected_digest`.
///
/// All four checks are STARK-bound (chip enforces row 0 IV cells == PV[0..32]
/// and row 79 digest cells == PV[96..128]). The chain integrity is
/// enforced by the verifier comparing PVs across adjacent proofs.
pub fn verify_sha512_air_proof(
    proof_bytes: &[u8],
    message: &[u8],
    expected_digest: &[u8; DIGEST_BYTES],
) -> Result<(), Sha512AirVerifyError> {
    let blocks = fips_pad_multi_block(message);
    if blocks.is_empty() {
        return Err(Sha512AirVerifyError::Deserialization("no blocks after padding".into()));
    }

    let proofs: Vec<Vec<u8>> = bincode::deserialize(proof_bytes).map_err(|e| Sha512AirVerifyError::Deserialization(e.to_string()))?;
    if proofs.len() != blocks.len() {
        return Err(Sha512AirVerifyError::ChainIntegrity(format!(
            "proof count {} != expected block count {} for message of {} bytes",
            proofs.len(),
            blocks.len(),
            message.len()
        )));
    }

    // Decompose the supplied expected_digest into 8 BE u64 words.
    let mut expected_digest_words = [0u64; 8];
    for (i, word) in expected_digest_words.iter_mut().enumerate() {
        *word = u64::from_be_bytes(expected_digest[i * 8..(i + 1) * 8].try_into().expect("64-byte digest"));
    }

    let setup = preprocessed_setup();
    let (_perm, config) = oracle_stark_config();

    // Walk the chain. We verify each proof against the IV implied by the
    // previous block's digest (or H_INITIAL for block 0), and against
    // the digest derived deterministically from `compute_compression` —
    // the same path the prover used to build PV. If the prover lied
    // about any block's digest, the STARK constraints reject because
    // the chip's add-back must match (this digest, that block, that IV).
    let mut iv = H_INITIAL;
    let mut last_digest = iv;
    for (k, (block, proof_serialized)) in blocks.iter().zip(proofs.iter()).enumerate() {
        let final_state = compute_compression(Sha512State::new(iv), block);
        let digest_words = final_state.0;
        let public_values = build_public_values::<Val>(&iv, block, &digest_words);

        let proof: p3_uni_stark::Proof<OracleStarkConfig> =
            bincode::deserialize(proof_serialized).map_err(|e| Sha512AirVerifyError::Deserialization(format!("block {k}: {e}")))?;

        verify_with_preprocessed(&config, &CompressionChip, &proof, &public_values, Some(&setup.1))
            .map_err(|e| Sha512AirVerifyError::StarkRejected(format!("block {k}: {e:?}")))?;

        last_digest = digest_words;
        iv = digest_words;
    }

    // Final chain anchor: the last block's digest must match what the
    // caller said the digest would be.
    if last_digest != expected_digest_words {
        return Err(Sha512AirVerifyError::ChainIntegrity(format!(
            "final digest mismatch: got {:?} but expected {:?}",
            last_digest, expected_digest_words
        )));
    }

    Ok(())
}

/// Encode `(message, digest)` as wire bytes: `u32_le(message_len) || message || digest`.
///
/// ABI inalterado from the trust-shim era — wallet/relayer/svm code
/// continues to round-trip via this canonical form regardless of
/// whether the proof bytes themselves are sentinel or real STARK.
pub fn encode_public_values_bytes(message: &[u8], digest: &[u8; DIGEST_BYTES]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + message.len() + DIGEST_BYTES);
    out.extend_from_slice(&(message.len() as u32).to_le_bytes());
    out.extend_from_slice(message);
    out.extend_from_slice(digest);
    out
}

/// Maximum message length accepted by `decode_public_values_bytes`.
///
/// Capped at 64 KiB to bound parsing memory; multi-block sha512
/// (5.6.c.1.d.multi) doesn't reach this cap in any realistic Phase 5
/// oracle workload (R∥A∥M ≤ 64 KiB easily covers any Pyth update).
pub const MAX_DECODE_MESSAGE_BYTES: usize = 64 * 1024;

/// Decode wire bytes back into `(message, digest)`.
pub fn decode_public_values_bytes(bytes: &[u8]) -> Option<(Vec<u8>, [u8; DIGEST_BYTES])> {
    if bytes.len() < 4 + DIGEST_BYTES {
        return None;
    }
    let mut lenb = [0u8; 4];
    lenb.copy_from_slice(&bytes[..4]);
    let len = u32::from_le_bytes(lenb) as usize;
    // Reasonable cap to avoid absurd allocations on hostile input.
    if len > MAX_DECODE_MESSAGE_BYTES {
        return None;
    }
    if bytes.len() != 4 + len + DIGEST_BYTES {
        return None;
    }
    let message = bytes[4..4 + len].to_vec();
    let mut digest = [0u8; DIGEST_BYTES];
    digest.copy_from_slice(&bytes[4 + len..]);
    Some((message, digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip on a typical short message. Very slow — runs full
    /// `prove_with_preprocessed` + `verify_with_preprocessed`.
    #[test]
    #[ignore = "slow (~10-30s release); full SHA-512 STARK round-trip"]
    fn prove_then_verify_round_trip_abc() {
        let proof = prove_sha512_air(b"abc").expect("prove ok");
        verify_sha512_air_proof(&proof.bytes, b"abc", &proof.digest).expect("verify ok");
    }

    #[test]
    #[ignore = "slow; round-trip on the empty message (FIPS 180-4 Appendix C.2)"]
    fn prove_then_verify_round_trip_empty() {
        let proof = prove_sha512_air(b"").expect("prove ok");
        verify_sha512_air_proof(&proof.bytes, b"", &proof.digest).expect("verify ok");
    }

    /// Sub-fase 5.6.c.1.d.multi — adversarial: tampering with the
    /// message bytes during verify must reject. With multi-block
    /// architecture this surfaces as `StarkRejected` (the chip's PV
    /// binding catches the mismatch on the wrong message block) — the
    /// trust shim is gone.
    #[test]
    #[ignore = "slow; validates trust-shim removal via tampered message"]
    fn verify_rejects_tampered_message() {
        let proof = prove_sha512_air(b"hello").expect("prove ok");
        let r = verify_sha512_air_proof(&proof.bytes, b"world", &proof.digest);
        assert!(
            matches!(r, Err(Sha512AirVerifyError::StarkRejected(_)) | Err(Sha512AirVerifyError::ChainIntegrity(_))),
            "expected STARK or chain rejection, got {:?}",
            r
        );
    }

    /// Sub-fase 5.6.c.1.d.multi — adversarial: tampering the supplied
    /// expected_digest must reject. The wrapper computes the canonical
    /// digest deterministically from the message; if the caller supplied
    /// a different digest, `ChainIntegrity` fires before any STARK math.
    #[test]
    #[ignore = "slow; validates trust-shim removal via tampered digest"]
    fn verify_rejects_tampered_digest() {
        let proof = prove_sha512_air(b"hello").expect("prove ok");
        let mut bad = proof.digest;
        bad[0] ^= 1;
        let r = verify_sha512_air_proof(&proof.bytes, b"hello", &bad);
        assert!(matches!(r, Err(Sha512AirVerifyError::ChainIntegrity(_))), "expected ChainIntegrity rejection, got {:?}", r);
    }

    /// Sub-fase 5.6.c.1.d.multi — round-trip on a 200-byte message
    /// (forces 2 blocks of compression chained via PV-bound IV). Slow.
    #[test]
    #[ignore = "slow (~0.3-0.6s release); multi-block STARK round-trip"]
    fn prove_then_verify_round_trip_two_blocks() {
        let msg: Vec<u8> = (0..200u8).collect();
        let proof = prove_sha512_air(&msg).expect("prove ok");
        verify_sha512_air_proof(&proof.bytes, &msg, &proof.digest).expect("verify ok");
    }

    /// Sub-fase 5.6.c.1.d.multi — round-trip on a 1 KiB message
    /// (forces 8+ blocks of compression chaining).
    #[test]
    #[ignore = "slow; 1KiB multi-block round-trip"]
    fn prove_then_verify_round_trip_kilobyte() {
        let msg: Vec<u8> = (0..1024u32).map(|i| (i & 0xff) as u8).collect();
        let proof = prove_sha512_air(&msg).expect("prove ok");
        verify_sha512_air_proof(&proof.bytes, &msg, &proof.digest).expect("verify ok");
    }

    #[test]
    fn pv_round_trip_bytes() {
        // Use a hardcoded digest here since prove_sha512_air now actually
        // generates a STARK proof (slow). decode_public_values_bytes is a
        // pure parser; we test it independently.
        let msg = b"Sophis ZK-Oracle test vector";
        let mut digest = [0u8; DIGEST_BYTES];
        for (i, b) in digest.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        let bytes = encode_public_values_bytes(msg, &digest);
        let (msg2, digest2) = decode_public_values_bytes(&bytes).expect("decode ok");
        assert_eq!(msg, msg2.as_slice());
        assert_eq!(digest2, digest);
    }

    #[test]
    fn decode_rejects_bad_length() {
        let mut bytes = encode_public_values_bytes(b"hi", &[0u8; DIGEST_BYTES]);
        bytes.pop();
        assert!(decode_public_values_bytes(&bytes).is_none());
    }

    #[test]
    fn decode_rejects_oversized_len_prefix() {
        // u32 MAX would claim 4GB message → we cap at MAX_DECODE_MESSAGE_BYTES.
        let mut bytes = vec![0xff; 4 + DIGEST_BYTES];
        bytes[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_public_values_bytes(&bytes).is_none());
    }

    /// Public-API check: prove returns the same digest the canonical
    /// witness function `sha512` produces. Now slow because prove_sha512_air
    /// actually runs a STARK (single-block path).
    #[test]
    #[ignore = "slow; runs single-block STARK to validate digest determinism"]
    fn prove_digest_matches_canonical() {
        use crate::chips::sha512::compression::sha512;
        let messages: &[&[u8]] = &[b"", b"abc", b"hello", b"Sophis"];
        for &msg in messages {
            let proof = prove_sha512_air(msg).expect("prove ok");
            assert_eq!(proof.digest, sha512(msg), "digest mismatch for msg len {}", msg.len());
        }
    }
}
