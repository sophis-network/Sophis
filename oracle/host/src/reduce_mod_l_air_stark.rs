//! Sub-fase 5.6.d.1.e — STARK plumbing for `ReduceModLAirChip`.
//!
//! Wraps `chips::scalar25519::reduce_mod_l_air::ReduceModLAirChip` with
//! the same Plonky3 `OracleStarkConfig` used elsewhere in the oracle
//! stack:
//!
//!   - `prove_reduce_mod_l_air(digest)` → `ReduceModLAirProof { bytes, scalar }`
//!   - `verify_reduce_mod_l_air_proof(bytes, digest, scalar)` → check
//!
//! ## What this proves (post 5.6.d.1.e)
//!
//! The AIR encodes the full mod-ℓ reduction:
//!
//!   - 5.6.d.1.b: byte-level schoolbook `q · ℓ + scalar = h`
//!   - 5.6.d.1.c: range checks (q, product, mul carries) via bit decomp
//!   - 5.6.d.1.d: `scalar < ℓ` strict-less-than via byte borrow chain
//!   - 5.6.d.1.e: `digest` and `scalar` bound to public values; digest
//!     bytes range-checked via 8-bit decomposition
//!
//! Public values (96 BabyBear elements):
//!   - PV[0..64]:  digest bytes (one cell per byte)
//!   - PV[64..96]: scalar bytes (one cell per byte)
//!
//! After 5.6.d.1.e the wrapper does **no Rust-side re-derivation**.
//! Tampering with `digest` or `scalar` triggers `StarkRejected` —
//! the entire reduction is enforced by the STARK proof.
//!
//! ## Aggregation chain role
//!
//! reduce_mod_l sits between sha512 and scalar_mul:
//!
//! ```text
//! sha512(R || A || M)  ─────►  64-byte digest
//! reduce_mod_l(digest) ─────►  32-byte scalar h (mod ℓ)
//! scalar_mul(h, A)     ─────►  hA point
//! ```
//!
//! With the trust shim removed the entire ed25519 verification chain is
//! now a chain of STARK proofs (decompress + sha512 + reduce_mod_l +
//! scalar_mul + verify_air), all bound by their public values. The
//! contract aggregator checks PV equality across adjacent proofs to
//! confirm the chain is consistent.

use p3_uni_stark::{prove, verify};

use crate::chips::scalar25519::reduce_mod_l_air::{
    NUM_PUBLIC_VALUES, ReduceModLAirChip, build_public_values, build_reduce_mod_l_trace,
};
use crate::config::{OracleStarkConfig, Val, oracle_stark_config};

const DIGEST_BYTES: usize = 64;
const SCALAR_BYTES: usize = 32;
/// Wire format: digest || scalar = 96 bytes fixed.
pub const PUBLIC_VALUES_WIRE_BYTES: usize = DIGEST_BYTES + SCALAR_BYTES;

#[derive(Debug, thiserror::Error)]
pub enum ReduceModLAirProverError {
    #[error("trace generation failed: {0}")]
    TraceFailed(String),
    #[error("proof serialization failed: {0}")]
    Serialization(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ReduceModLAirVerifyError {
    #[error("proof deserialization failed: {0}")]
    Deserialization(String),
    #[error("STARK verification failed: {0}")]
    StarkRejected(String),
    #[error("public values length wrong (got {got}, want {want})")]
    BadPublicValuesLen { got: usize, want: usize },
}

/// Opaque proof bytes plus the scalar the prover witnessed.
pub struct ReduceModLAirProof {
    /// Bincode-serialized `p3_uni_stark::Proof<OracleStarkConfig>`.
    pub bytes: Vec<u8>,
    /// `scalar = digest mod ℓ` (32 bytes LE).
    pub scalar: [u8; SCALAR_BYTES],
}

/// Generate a STARK proof of mod-ℓ reduction for a 64-byte digest.
///
/// **Slow** — the AIR has ~3106 columns × HEIGHT=4 (small) and runs in
/// well under a second in release mode.
pub fn prove_reduce_mod_l_air(digest: &[u8; DIGEST_BYTES]) -> Result<ReduceModLAirProof, ReduceModLAirProverError> {
    // Build trace and derive scalar via the witness function.
    let trace = build_reduce_mod_l_trace::<Val>(digest);
    let scalar = crate::chips::ed25519::verify::reduce_mod_l(digest);
    let public_values = build_public_values::<Val>(digest, &scalar);

    let (_perm, config) = oracle_stark_config();
    let proof = prove(&config, &ReduceModLAirChip, trace, &public_values);
    let bytes = bincode::serialize(&proof).map_err(|e| ReduceModLAirProverError::Serialization(e.to_string()))?;
    Ok(ReduceModLAirProof { bytes, scalar })
}

/// Verify a STARK proof against the supplied `(digest, expected_scalar)`.
///
/// As of 5.6.d.1.e the AIR's PV bind constraints enforce that the
/// trace's witnessed digest and scalar match the supplied public
/// values exactly. A mismatch on either input — or any tampering with
/// the underlying mul/add/borrow chains — triggers `StarkRejected`.
pub fn verify_reduce_mod_l_air_proof(
    proof_bytes: &[u8],
    digest: &[u8; DIGEST_BYTES],
    expected_scalar: &[u8; SCALAR_BYTES],
) -> Result<(), ReduceModLAirVerifyError> {
    let public_values = build_public_values::<Val>(digest, expected_scalar);
    if public_values.len() != NUM_PUBLIC_VALUES {
        return Err(ReduceModLAirVerifyError::BadPublicValuesLen { got: public_values.len(), want: NUM_PUBLIC_VALUES });
    }

    let proof: p3_uni_stark::Proof<OracleStarkConfig> =
        bincode::deserialize(proof_bytes).map_err(|e| ReduceModLAirVerifyError::Deserialization(e.to_string()))?;

    let (_perm, config) = oracle_stark_config();
    verify(&config, &ReduceModLAirChip, &proof, &public_values).map_err(|e| ReduceModLAirVerifyError::StarkRejected(format!("{e:?}")))
}

/// Encode `(digest, scalar)` as wire bytes: 64 + 32 = 96 bytes fixed.
pub fn encode_public_values_bytes(digest: &[u8; DIGEST_BYTES], scalar: &[u8; SCALAR_BYTES]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PUBLIC_VALUES_WIRE_BYTES);
    out.extend_from_slice(digest);
    out.extend_from_slice(scalar);
    out
}

/// Decode wire bytes back into `(digest, scalar)`.
pub fn decode_public_values_bytes(bytes: &[u8]) -> Option<([u8; DIGEST_BYTES], [u8; SCALAR_BYTES])> {
    if bytes.len() != PUBLIC_VALUES_WIRE_BYTES {
        return None;
    }
    let mut digest = [0u8; DIGEST_BYTES];
    let mut scalar = [0u8; SCALAR_BYTES];
    digest.copy_from_slice(&bytes[..DIGEST_BYTES]);
    scalar.copy_from_slice(&bytes[DIGEST_BYTES..]);
    Some((digest, scalar))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Slow: full STARK round-trip on a typical digest.
    #[test]
    #[ignore = "slow (~1s release); full reduce_mod_l STARK round-trip"]
    fn prove_then_verify_round_trip_zero() {
        let proof = prove_reduce_mod_l_air(&[0u8; DIGEST_BYTES]).expect("prove ok");
        verify_reduce_mod_l_air_proof(&proof.bytes, &[0u8; DIGEST_BYTES], &proof.scalar).expect("verify ok");
    }

    #[test]
    #[ignore = "slow; round-trip on an arbitrary digest"]
    fn prove_then_verify_round_trip_arbitrary() {
        let digest: [u8; DIGEST_BYTES] = core::array::from_fn(|i| (i as u8).wrapping_mul(13));
        let proof = prove_reduce_mod_l_air(&digest).expect("prove ok");
        verify_reduce_mod_l_air_proof(&proof.bytes, &digest, &proof.scalar).expect("verify ok");
    }

    /// Sub-fase 5.6.d.1.e — adversarial: tampering with the supplied
    /// scalar during verify must trigger `StarkRejected`, not a Rust-side
    /// re-derivation mismatch (the trust shim is gone).
    #[test]
    #[ignore = "slow; validates trust-shim removal via tampered scalar"]
    fn verify_rejects_tampered_scalar() {
        let digest = [42u8; DIGEST_BYTES];
        let proof = prove_reduce_mod_l_air(&digest).expect("prove ok");
        let mut bad = proof.scalar;
        bad[0] ^= 1;
        let r = verify_reduce_mod_l_air_proof(&proof.bytes, &digest, &bad);
        assert!(matches!(r, Err(ReduceModLAirVerifyError::StarkRejected(_))), "expected StarkRejected, got {:?}", r);
    }

    /// Sub-fase 5.6.d.1.e — adversarial: tampering with the digest
    /// during verify must also trigger `StarkRejected`.
    #[test]
    #[ignore = "slow; validates trust-shim removal via tampered digest"]
    fn verify_rejects_tampered_digest() {
        let digest = [42u8; DIGEST_BYTES];
        let proof = prove_reduce_mod_l_air(&digest).expect("prove ok");
        let mut bad_digest = digest;
        bad_digest[0] ^= 1;
        let r = verify_reduce_mod_l_air_proof(&proof.bytes, &bad_digest, &proof.scalar);
        assert!(matches!(r, Err(ReduceModLAirVerifyError::StarkRejected(_))), "expected StarkRejected, got {:?}", r);
    }

    /// Public-API check: `prove_reduce_mod_l_air` returns the same scalar
    /// the canonical `reduce_mod_l` witness function produces. Fast.
    #[test]
    fn prove_scalar_matches_canonical() {
        use crate::chips::ed25519::verify::reduce_mod_l;
        let digests: &[[u8; DIGEST_BYTES]] =
            &[[0u8; DIGEST_BYTES], core::array::from_fn(|i| (i as u8).wrapping_mul(7)), [0xffu8; DIGEST_BYTES]];
        for digest in digests {
            let proof = prove_reduce_mod_l_air(digest).expect("prove ok");
            assert_eq!(proof.scalar, reduce_mod_l(digest));
        }
    }

    #[test]
    fn pv_round_trip() {
        let digest = [7u8; DIGEST_BYTES];
        let proof = prove_reduce_mod_l_air(&digest).expect("prove ok");
        let bytes = encode_public_values_bytes(&digest, &proof.scalar);
        let (digest2, scalar2) = decode_public_values_bytes(&bytes).expect("decode ok");
        assert_eq!(digest2, digest);
        assert_eq!(scalar2, proof.scalar);
    }

    #[test]
    fn decode_rejects_bad_length() {
        assert!(decode_public_values_bytes(&[0u8; PUBLIC_VALUES_WIRE_BYTES - 1]).is_none());
        assert!(decode_public_values_bytes(&[0u8; PUBLIC_VALUES_WIRE_BYTES + 1]).is_none());
    }
}
