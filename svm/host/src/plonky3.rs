//! Plonky3 STARK proof verification for sVM contracts (Phase 5 sub-fase 5.3).
//!
//! Dispatches by `air_id` (32-byte tag) to the appropriate AIR verifier
//! exposed by `sophis-oracle-host`. Two AIRs are registered today; more
//! can be added without a hard fork because dispatch is closed-set
//! (unknown air_id returns `false` cleanly, contracts hard-code which
//! AIRs they accept).
//!
//! ## Air ID derivation
//!
//! Air IDs are SHA3-384-truncated commitments to a versioned domain string.
//! Compute once and hardcode in both the host (this file) and the contract
//! WASM (callers of `Env::verify_plonky3_proof`). Changing the AIR's
//! constraints means bumping the version suffix → a new `air_id` — old
//! contracts continue to reject the new proof, no chain split.
//!
//! ```ignore
//! ORACLE_AIR_ID_V1     := SHA3-384("sophis-oracle-air-v1")[..32]
//! VERIFY_AIR_ID_V1     := SHA3-384("sophis-verify-air-v1")[..32]
//! ```
//!
//! ## Public-values format
//!
//! For `OracleAir`: `public_values` is a borsh-encoded `OracleJournal`
//! plus `now_secs: u64` appended (so the host can re-derive the same
//! field-element vector the prover used).
//!
//! For `VerifyAirChip` (post sub-fase 5.6.0): `public_values` is 672
//! bytes: 96 raw (pk||sig) + 144 × 4 LE (R/A/sB/hA limbs as u32 LE).
//! The host reconstructs the same `Vec<F>` the prover committed to and
//! the AIR enforces equality with its boundary cells, so the proof
//! binds to exactly that `(pk, sig, R, A, sB, hA)` tuple. Message
//! binding closes in 5.6.a-d via the companion proof aggregation chain.

use sha3::{Digest, Sha3_384};

/// Air IDs registered with the host. New AIRs append below; existing
/// constants MUST NOT change (contracts pin against these values).
pub fn oracle_air_id_v1() -> [u8; 32] {
    air_id_from_domain(b"sophis-oracle-air-v1")
}

pub fn verify_air_id_v1() -> [u8; 32] {
    air_id_from_domain(b"sophis-verify-air-v1")
}

/// Sub-fase 5.6.a — STARK plumbing for ed25519 point decompression.
pub fn decompress_air_id_v1() -> [u8; 32] {
    air_id_from_domain(b"sophis-decompress-air-v1")
}

/// Sub-fase 5.6.b — STARK plumbing for ed25519 scalar multiplication.
pub fn scalar_mul_air_id_v1() -> [u8; 32] {
    air_id_from_domain(b"sophis-scalar-mul-air-v1")
}

/// Sub-fase 5.6.c — STARK plumbing for SHA-512 single-block compression.
pub fn sha512_air_id_v1() -> [u8; 32] {
    air_id_from_domain(b"sophis-sha512-air-v1")
}

/// Sub-fase 5.6.d — STARK plumbing for reduce_mod_l (SHA-512 digest → ed25519 scalar).
pub fn reduce_mod_l_air_id_v1() -> [u8; 32] {
    air_id_from_domain(b"sophis-reduce-mod-l-air-v1")
}

fn air_id_from_domain(domain: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_384::new();
    hasher.update(domain);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// Verify a Plonky3 STARK proof. Dispatches by `air_id` to the matching
/// `sophis-oracle-host` verifier. Returns `false` on any malformed input,
/// unknown air_id, or verification failure.
pub fn verify_plonky3_proof_bytes(proof: &[u8], public_values: &[u8], air_id: &[u8]) -> bool {
    if air_id.len() != 32 {
        return false;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(air_id);

    if id == oracle_air_id_v1() {
        verify_oracle_air(proof, public_values)
    } else if id == verify_air_id_v1() {
        verify_verify_air_dispatch(proof, public_values)
    } else if id == decompress_air_id_v1() {
        verify_decompress_air_dispatch(proof, public_values)
    } else if id == scalar_mul_air_id_v1() {
        verify_scalar_mul_air_dispatch(proof, public_values)
    } else if id == sha512_air_id_v1() {
        verify_sha512_air_dispatch(proof, public_values)
    } else if id == reduce_mod_l_air_id_v1() {
        verify_reduce_mod_l_air_dispatch(proof, public_values)
    } else {
        // Unknown air_id — no dispatch path. Fail closed.
        false
    }
}

/// Verify an `OracleAir` proof. `public_values` is `(OracleJournal_borsh || now_secs_le_u64)`.
fn verify_oracle_air(proof: &[u8], public_values: &[u8]) -> bool {
    use borsh::BorshDeserialize;
    use sophis_oracle_core::OracleJournal;
    use sophis_oracle_host::verify_proof;

    if public_values.len() < 8 {
        return false;
    }
    let journal_end = public_values.len() - 8;
    let journal_bytes = &public_values[..journal_end];
    let now_bytes = &public_values[journal_end..];
    let mut now_arr = [0u8; 8];
    now_arr.copy_from_slice(now_bytes);
    let now_secs = u64::from_le_bytes(now_arr);

    let Ok(journal) = OracleJournal::try_from_slice(journal_bytes) else {
        return false;
    };
    verify_proof(proof, &journal, now_secs).is_ok()
}

/// Verify a `VerifyAirChip` proof. As of sub-fase 5.6.0, `public_values`
/// is 672 bytes: 96 raw bytes (pk||sig) + 144 × 4 LE bytes (limbs as u32 LE)
/// for R_point/A_point/sB/hA. The AIR boundary-binds all of this to its
/// witness columns so the proof is bound to a specific `(pk, sig, R, A, sB, hA)`
/// tuple. Companion proofs (5.6.a-d) attest those points come from
/// honest decompress/scalar_mul/sha512 chains; without them the contract
/// trusts the relayer for the (R, A, sB, hA) values.
fn verify_verify_air_dispatch(proof: &[u8], public_values: &[u8]) -> bool {
    use sophis_oracle_host::verify_air_stark::{decode_public_values_bytes, verify_verify_air_proof};
    let Some((pk, sig, boundary)) = decode_public_values_bytes(public_values) else {
        return false;
    };
    verify_verify_air_proof(proof, &pk, &sig, &boundary).is_ok()
}

/// Sub-fase 5.6.a + 5.6.a.1 — Verify a `DecompressAirChip` proof.
/// `public_values` is 177 bytes: 32 raw (compressed_bytes) + 144 LE
/// limbs (output point) + 1 byte valid. Boundary binding is internalized
/// inside the AIR (5.6.a.1) so the wrapper just routes the bytes.
fn verify_decompress_air_dispatch(proof: &[u8], public_values: &[u8]) -> bool {
    use sophis_oracle_host::decompress_air_stark::{decode_public_values_bytes, verify_decompress_air_proof};
    let Some((compressed, output, valid)) = decode_public_values_bytes(public_values) else {
        return false;
    };
    verify_decompress_air_proof(proof, &compressed, &output, valid).is_ok()
}

/// Sub-fase 5.6.b — Verify a `ScalarMulAirChip` proof (trust-shim wrapper).
/// `public_values` is 320 bytes: 32 (scalar) + 144 (base limbs) + 144 (output limbs).
/// Internal AIR binding deferred to 5.6.b.1.
fn verify_scalar_mul_air_dispatch(proof: &[u8], public_values: &[u8]) -> bool {
    use sophis_oracle_host::scalar_mul_air_stark::{decode_public_values_bytes, verify_scalar_mul_air_proof};
    let Some((scalar, base, output)) = decode_public_values_bytes(public_values) else {
        return false;
    };
    verify_scalar_mul_air_proof(proof, &scalar, &base, &output).is_ok()
}

/// Sub-fase 5.6.c — Verify a `Sha512Air` proof (trust-shim wrapper).
/// `public_values` is the full pre-image plus the 64-byte digest;
/// see `sha512_air_stark` for the exact wire format.
fn verify_sha512_air_dispatch(proof: &[u8], public_values: &[u8]) -> bool {
    use sophis_oracle_host::sha512_air_stark::{decode_public_values_bytes, verify_sha512_air_proof};
    let Some((message, digest)) = decode_public_values_bytes(public_values) else {
        return false;
    };
    verify_sha512_air_proof(proof, &message, &digest).is_ok()
}

/// Sub-fase 5.6.d — Verify a `ReduceModLAirChip` proof (trust-shim wrapper).
/// `public_values` is 96 bytes: 64 (input digest) + 32 (output scalar mod ℓ).
fn verify_reduce_mod_l_air_dispatch(proof: &[u8], public_values: &[u8]) -> bool {
    use sophis_oracle_host::reduce_mod_l_air_stark::{decode_public_values_bytes, verify_reduce_mod_l_air_proof};
    let Some((digest, scalar)) = decode_public_values_bytes(public_values) else {
        return false;
    };
    verify_reduce_mod_l_air_proof(proof, &digest, &scalar).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_air_id_length_rejected() {
        assert!(!verify_plonky3_proof_bytes(&[], &[], &[0u8; 31]));
        assert!(!verify_plonky3_proof_bytes(&[], &[], &[0u8; 33]));
    }

    #[test]
    fn unknown_air_id_rejected() {
        assert!(!verify_plonky3_proof_bytes(&[0xab; 64], &[], &[0xff; 32]));
    }

    #[test]
    fn garbage_proof_rejected_oracle_air() {
        let id = oracle_air_id_v1();
        // Need at least 8 bytes (now_secs); empty journal will fail borsh first.
        let pv = vec![0u8; 16];
        assert!(!verify_plonky3_proof_bytes(b"garbage", &pv, &id));
    }

    #[test]
    fn garbage_proof_rejected_verify_air() {
        use sophis_oracle_host::verify_air_stark::PUBLIC_VALUES_WIRE_BYTES;
        let id = verify_air_id_v1();
        // Empty public_values fails the wire-length check upfront.
        assert!(!verify_plonky3_proof_bytes(b"garbage", &[], &id));
        // Well-shaped wire-length public values can't make garbage decode either.
        let pv = vec![0u8; PUBLIC_VALUES_WIRE_BYTES];
        assert!(!verify_plonky3_proof_bytes(b"garbage", &pv, &id));
        // Wrong-length public_values is rejected before decode.
        let bad_len = vec![0u8; PUBLIC_VALUES_WIRE_BYTES - 1];
        assert!(!verify_plonky3_proof_bytes(b"garbage", &bad_len, &id));
    }

    #[test]
    fn air_ids_are_deterministic_and_distinct() {
        assert_eq!(oracle_air_id_v1(), oracle_air_id_v1());
        assert_eq!(verify_air_id_v1(), verify_air_id_v1());
        assert_eq!(decompress_air_id_v1(), decompress_air_id_v1());
        // All three IDs are pairwise distinct.
        assert_ne!(oracle_air_id_v1(), verify_air_id_v1());
        assert_ne!(oracle_air_id_v1(), decompress_air_id_v1());
        assert_ne!(verify_air_id_v1(), decompress_air_id_v1());
    }

    #[test]
    fn garbage_proof_rejected_decompress_air() {
        use sophis_oracle_host::decompress_air_stark::PUBLIC_VALUES_WIRE_BYTES as DECOMPRESS_PV;
        let id = decompress_air_id_v1();
        // Empty PV fails length check.
        assert!(!verify_plonky3_proof_bytes(b"garbage", &[], &id));
        // Well-shaped PV but garbage proof — rejected at STARK verify.
        let pv = vec![0u8; DECOMPRESS_PV];
        assert!(!verify_plonky3_proof_bytes(b"garbage", &pv, &id));
    }

    /// Real-proof round-trip: build with oracle::prove, serialize journal +
    /// now_secs, verify via the dispatch shim. This exercises the actual
    /// path a sVM contract would use for a Phase 5 oracle update.
    #[test]
    fn oracle_air_real_proof_round_trip() {
        use borsh::BorshSerialize;
        use sophis_oracle_core::{FeedId, PriceUpdate, PublisherKey, SignedPriceUpdate};
        use sophis_oracle_host::{prove, ProveInputs};

        let signed = SignedPriceUpdate {
            update: PriceUpdate {
                feed: FeedId(*b"BTC/USD\0"),
                publisher: PublisherKey([1u8; 32]),
                price: 65_000_00,
                conf: 0,
                exponent: -8,
                publish_time: 1_700_000_080,
            },
            signature: Box::new([0u8; 64]),
        };
        let now_secs: u64 = 1_700_000_120;
        let inputs = ProveInputs {
            signed: &signed,
            now_secs,
            min_price: 1_000_00,
            max_price: 1_000_000_00,
            max_age_secs: 60,
            sequence: 100,
            last_sequence: 99,
        };
        let proof = prove(inputs).expect("prove must succeed");

        // public_values = borsh(journal) || u64_le(now_secs)
        let mut pv = Vec::with_capacity(256);
        proof.journal.serialize(&mut pv).expect("borsh ok");
        pv.extend_from_slice(&now_secs.to_le_bytes());

        let id = oracle_air_id_v1();
        assert!(verify_plonky3_proof_bytes(&proof.bytes, &pv, &id));

        // Tampered now_secs → re-derived public inputs differ → reject.
        let mut pv_bad = pv.clone();
        let n = pv_bad.len();
        pv_bad[n - 8] ^= 1;
        assert!(!verify_plonky3_proof_bytes(&proof.bytes, &pv_bad, &id));
    }
}
