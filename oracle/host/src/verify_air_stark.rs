//! Sub-fase 5.2.1.x + 5.6.0 — STARK plumbing for the ed25519 `VerifyAirChip`.
//!
//! Wraps `chips::ed25519::verify_air::VerifyAirChip` with the same Plonky3
//! `OracleStarkConfig` we use for `OracleAir`, exposing:
//!
//!   - `prove_verify_air(pk, sig, msg)` → `VerifyAirProof { bytes, boundary }`
//!   - `verify_verify_air_proof(bytes, pk, sig, &boundary)` → round-trip check
//!
//! ## What this proves (post 5.6.0)
//!
//! The AIR encodes the **final group equation** of ed25519 verification —
//! `[s]B == R + [h]A`, asserted via projective cross-products — plus the
//! single embedded `point_add` that produces `R + [h]A`.
//!
//! As of 5.6.0, the boundary cells are now exposed as STARK public values:
//!   - `(public_key, signature)` — 96 bytes (pk || sig), one BabyBear element per byte
//!   - `(R_point, A_point, sB, hA)` — 144 BabyBear elements (4 × 36 limbs)
//!
//! Bound to the witness columns by `assert_eq` constraints, so the proof
//! demonstrates:
//!
//!   *"There exist points `(R, A, sB, hA)` consistent with the embedded
//!    `point_add` such that `sB ≡ R + hA` projectively, AND `public_key`,
//!    `signature`, AND those four points equal the supplied public values."*
//!
//! 5.6.0 unlocks **companion proof aggregation** (sub-fases 5.6.a-d):
//! future `decompress_air` / `scalar_mul_air` / `sha512` proofs each
//! expose their own outputs as public values, and the contract checks
//! they equal the corresponding `R/A/sB/hA` slot here. Without 5.6.0
//! those boundary cells were invisible to the contract, so companion
//! proofs could not be bound.

use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::chips::ed25519::point::ExtendedPoint;
use crate::chips::ed25519::verify_air::{NUM_BOUNDARY_LIMBS, NUM_COLS, NUM_PUBLIC_VALUES, VerifyAirChip, build_verify_trace};
use crate::chips::field25519::NUM_LIMBS;
use crate::config::{Val, oracle_stark_config};

const PUBLIC_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
#[allow(dead_code)] // Reserved for future companion-proof aggregation refactor.
const POINT_LIMBS: usize = 4 * NUM_LIMBS; // 36

/// Number of bytes in the wire-format encoding of the public values:
///   96 raw bytes (pk || sig) + 144 × 4 LE bytes (limbs as u32 LE) = 672.
pub const PUBLIC_VALUES_WIRE_BYTES: usize = PUBLIC_KEY_BYTES + SIGNATURE_BYTES + NUM_BOUNDARY_LIMBS * 4;

/// The four ExtendedPoints witnessed at the boundary of `VerifyAirChip`.
/// Returned by `prove_verify_air` and required by `verify_verify_air_proof`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryPoints {
    pub r_point: ExtendedPoint,
    pub a_point: ExtendedPoint,
    pub sb: ExtendedPoint,
    pub ha: ExtendedPoint,
}

/// Errors specific to ed25519-verify proof generation.
#[derive(Debug, thiserror::Error)]
pub enum VerifyAirProverError {
    #[error("trace generation failed (trace width mismatch: got {got}, want {want})")]
    BadTraceShape { got: usize, want: usize },
    #[error("proof serialization failed: {0}")]
    Serialization(String),
}

/// Errors specific to ed25519-verify proof verification.
#[derive(Debug, thiserror::Error)]
pub enum VerifyAirVerifyError {
    #[error("proof deserialization failed: {0}")]
    Deserialization(String),
    #[error("public values length wrong (got {got}, want {want})")]
    BadPublicValuesLen { got: usize, want: usize },
    #[error("STARK verification failed: {0}")]
    StarkRejected(String),
}

/// Opaque proof bytes for the ed25519-verify AIR plus the boundary
/// points the prover witnessed. The caller MUST ship `boundary`
/// alongside `bytes` — verification needs both.
pub struct VerifyAirProof {
    /// Bincode-serialized `p3_uni_stark::Proof<OracleStarkConfig>`.
    pub bytes: Vec<u8>,
    /// Boundary points the prover computed from `(pk, sig, msg)`.
    /// Future companion proofs (5.6.a-d) attest these come from
    /// honest `decompress`/`scalar_mul`/`sha512` chains; without
    /// companions they're trusted-relayer.
    pub boundary: BoundaryPoints,
}

/// Compute the four boundary points the AIR uses, given `(pk, sig, msg)`.
/// This is the same chain the AIR's `build_verify_trace` runs internally.
///
/// Exposed as a public helper so callers (relayer) can pre-compute the
/// boundary points without re-running the full witness chain.
pub fn derive_boundary_points(public_key: &[u8; 32], signature: &[u8; 64], message: &[u8]) -> BoundaryPoints {
    use crate::chips::ed25519::decompress::decompress;
    use crate::chips::ed25519::point::point_add;
    use crate::chips::ed25519::scalar_mul_air::derive_scalar_mul_air_output;
    use crate::chips::ed25519::verify::reduce_mod_l;
    use crate::chips::sha512::compression::sha512;

    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[0..32]);
    s_bytes.copy_from_slice(&signature[32..64]);

    let r_point = decompress(&r_bytes).unwrap_or_else(ExtendedPoint::neutral);
    let a_point = decompress(public_key).unwrap_or_else(ExtendedPoint::neutral);

    // h = SHA-512(R || A || M) reduced mod ℓ.
    let mut hash_input = Vec::with_capacity(64 + message.len());
    hash_input.extend_from_slice(&r_bytes);
    hash_input.extend_from_slice(public_key);
    hash_input.extend_from_slice(message);
    let h_full = sha512(&hash_input);
    let h_mod_l = reduce_mod_l(&h_full);

    let mut basepoint_compressed = [0x66u8; 32];
    basepoint_compressed[0] = 0x58;
    let basepoint = decompress(&basepoint_compressed).expect("basepoint must decompress");

    // Sub-fase 5.6.b.1.d — boundary sB/hA must use the AIR's projective
    // form (matching `chips::ed25519::scalar_mul_air`) so contract-level
    // aggregation against scalar_mul_air proofs binds via cell-wise PV
    // equality. See verify_air::build_verify_trace for the same change.
    let sb = derive_scalar_mul_air_output(&s_bytes, &basepoint);
    let ha = derive_scalar_mul_air_output(&h_mod_l, &a_point);
    let _rhs = point_add(&r_point, &ha); // not exposed; AIR re-derives via point_add

    BoundaryPoints { r_point, a_point, sb, ha }
}

/// Build the public-values vector from `(pk, sig, boundary)`.
///
/// Layout matches the trace's `[col::PUBLIC_KEY..col::HA+POINT_LIMBS]`
/// region one-to-one. One BabyBear element per byte (bytes region) and
/// one BabyBear element per 30-bit limb (limbs region).
pub fn build_public_values(public_key: &[u8; 32], signature: &[u8; 64], boundary: &BoundaryPoints) -> Vec<Val> {
    let mut out = Vec::with_capacity(NUM_PUBLIC_VALUES);
    for &b in public_key {
        out.push(Val::from_u64(b as u64));
    }
    for &b in signature {
        out.push(Val::from_u64(b as u64));
    }
    push_point(&mut out, &boundary.r_point);
    push_point(&mut out, &boundary.a_point);
    push_point(&mut out, &boundary.sb);
    push_point(&mut out, &boundary.ha);
    debug_assert_eq!(out.len(), NUM_PUBLIC_VALUES);
    out
}

fn push_point(out: &mut Vec<Val>, p: &ExtendedPoint) {
    for &l in &p.x.limbs {
        out.push(Val::from_u64(l));
    }
    for &l in &p.y.limbs {
        out.push(Val::from_u64(l));
    }
    for &l in &p.z.limbs {
        out.push(Val::from_u64(l));
    }
    for &l in &p.t.limbs {
        out.push(Val::from_u64(l));
    }
}

/// Encode `(pk, sig, boundary)` as the canonical wire-format byte slice
/// expected by `svm/host/plonky3.rs::verify_verify_air`.
///
/// Layout: 96 raw bytes (pk || sig) followed by 144 × 4 LE bytes (each
/// 30-bit limb serialized as u32 LE).
pub fn encode_public_values_bytes(public_key: &[u8; 32], signature: &[u8; 64], boundary: &BoundaryPoints) -> Vec<u8> {
    let mut out = Vec::with_capacity(PUBLIC_VALUES_WIRE_BYTES);
    out.extend_from_slice(public_key);
    out.extend_from_slice(signature);
    push_point_bytes(&mut out, &boundary.r_point);
    push_point_bytes(&mut out, &boundary.a_point);
    push_point_bytes(&mut out, &boundary.sb);
    push_point_bytes(&mut out, &boundary.ha);
    debug_assert_eq!(out.len(), PUBLIC_VALUES_WIRE_BYTES);
    out
}

fn push_point_bytes(out: &mut Vec<u8>, p: &ExtendedPoint) {
    for &l in &p.x.limbs {
        out.extend_from_slice(&(l as u32).to_le_bytes());
    }
    for &l in &p.y.limbs {
        out.extend_from_slice(&(l as u32).to_le_bytes());
    }
    for &l in &p.z.limbs {
        out.extend_from_slice(&(l as u32).to_le_bytes());
    }
    for &l in &p.t.limbs {
        out.extend_from_slice(&(l as u32).to_le_bytes());
    }
}

/// Decode the wire-format byte slice back into `(pk, sig, boundary)`.
/// Returns `None` if the length is wrong or any limb deserialization fails.
pub fn decode_public_values_bytes(bytes: &[u8]) -> Option<([u8; 32], [u8; 64], BoundaryPoints)> {
    use crate::chips::field25519::Field25519Element;

    if bytes.len() != PUBLIC_VALUES_WIRE_BYTES {
        return None;
    }
    let mut pk = [0u8; 32];
    let mut sig = [0u8; 64];
    pk.copy_from_slice(&bytes[..32]);
    sig.copy_from_slice(&bytes[32..96]);

    let mut cur = 96usize;
    let mut read_point = || -> ExtendedPoint {
        let mut x = [0u64; NUM_LIMBS];
        let mut y = [0u64; NUM_LIMBS];
        let mut z = [0u64; NUM_LIMBS];
        let mut t = [0u64; NUM_LIMBS];
        for limb in &mut x {
            *limb = read_u32_le(bytes, &mut cur) as u64;
        }
        for limb in &mut y {
            *limb = read_u32_le(bytes, &mut cur) as u64;
        }
        for limb in &mut z {
            *limb = read_u32_le(bytes, &mut cur) as u64;
        }
        for limb in &mut t {
            *limb = read_u32_le(bytes, &mut cur) as u64;
        }
        ExtendedPoint {
            x: Field25519Element { limbs: x },
            y: Field25519Element { limbs: y },
            z: Field25519Element { limbs: z },
            t: Field25519Element { limbs: t },
        }
    };
    let r_point = read_point();
    let a_point = read_point();
    let sb = read_point();
    let ha = read_point();
    Some((pk, sig, BoundaryPoints { r_point, a_point, sb, ha }))
}

fn read_u32_le(bytes: &[u8], cur: &mut usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[*cur..*cur + 4]);
    *cur += 4;
    u32::from_le_bytes(buf)
}

/// Generate a real Plonky3 STARK proof of the ed25519 verify AIR for
/// `(public_key, signature, message)`. Returns the opaque proof bytes
/// AND the boundary points the prover computed (caller MUST ship both).
///
/// **Slow** — the AIR is ~51,828 columns wide; expect single-digit
/// seconds in release mode.
pub fn prove_verify_air(public_key: &[u8; 32], signature: &[u8; 64], message: &[u8]) -> Result<VerifyAirProof, VerifyAirProverError> {
    let trace: RowMajorMatrix<Val> = build_verify_trace::<Val>(public_key, signature, message);

    if !trace.values.len().is_multiple_of(NUM_COLS) {
        return Err(VerifyAirProverError::BadTraceShape { got: trace.values.len(), want: NUM_COLS });
    }

    let boundary = derive_boundary_points(public_key, signature, message);
    let public_values = build_public_values(public_key, signature, &boundary);

    let (_perm, config) = oracle_stark_config();
    let proof = p3_uni_stark::prove(&config, &VerifyAirChip, trace, &public_values);
    let bytes = bincode::serialize(&proof).map_err(|e| VerifyAirProverError::Serialization(e.to_string()))?;
    Ok(VerifyAirProof { bytes, boundary })
}

/// Verify proof bytes produced by `prove_verify_air` against the supplied
/// `(pk, sig, boundary)`. Reconstructs the public-values vector and
/// invokes the STARK verifier. Returns `Ok(())` iff the proof is valid
/// AND its committed public values match the supplied data.
pub fn verify_verify_air_proof(
    proof_bytes: &[u8],
    public_key: &[u8; 32],
    signature: &[u8; 64],
    boundary: &BoundaryPoints,
) -> Result<(), VerifyAirVerifyError> {
    let proof: p3_uni_stark::Proof<crate::config::OracleStarkConfig> =
        bincode::deserialize(proof_bytes).map_err(|e| VerifyAirVerifyError::Deserialization(e.to_string()))?;

    let public_values = build_public_values(public_key, signature, boundary);
    if public_values.len() != NUM_PUBLIC_VALUES {
        return Err(VerifyAirVerifyError::BadPublicValuesLen { got: public_values.len(), want: NUM_PUBLIC_VALUES });
    }

    let (_perm, config) = oracle_stark_config();
    p3_uni_stark::verify(&config, &VerifyAirChip, &proof, &public_values)
        .map_err(|e| VerifyAirVerifyError::StarkRejected(format!("{e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc8032_test_1() -> ([u8; 32], [u8; 64]) {
        (
            [
                0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72,
                0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
            ],
            [
                0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a, 0x84, 0x87, 0x7f,
                0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3,
                0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65,
                0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
            ],
        )
    }

    /// RFC 8032 Test 1 — the canonical ed25519 verify vector.
    /// SLOW (~5-10s release with the post-Etapa-3.9 ~51_828 cols layout).
    #[test]
    #[ignore = "slow (~5-10s release); full prove → bytes → verify of ed25519 verify_air"]
    fn prove_then_verify_round_trip_rfc8032_test_1() {
        let (pk, sig) = rfc8032_test_1();
        let proof = prove_verify_air(&pk, &sig, b"").expect("prove must succeed");
        assert!(!proof.bytes.is_empty(), "proof bytes must be non-empty");
        verify_verify_air_proof(&proof.bytes, &pk, &sig, &proof.boundary).expect("verify must succeed on honest proof");
    }

    /// Tampering pk during verify must reject.
    #[test]
    #[ignore = "slow; validates 5.4.b binding by mutating verify-side pk"]
    fn verify_rejects_tampered_pk() {
        let (pk, sig) = rfc8032_test_1();
        let proof = prove_verify_air(&pk, &sig, b"").expect("prove ok");
        let mut bad_pk = pk;
        bad_pk[0] ^= 1;
        let r = verify_verify_air_proof(&proof.bytes, &bad_pk, &sig, &proof.boundary);
        assert!(r.is_err(), "verify must reject when supplied pk differs from proof's bound pk");
    }

    /// Tampering R_point during verify must reject (5.6.0 boundary binding).
    #[test]
    #[ignore = "slow; validates 5.6.0 binding by mutating verify-side R_point"]
    fn verify_rejects_tampered_r_point() {
        let (pk, sig) = rfc8032_test_1();
        let proof = prove_verify_air(&pk, &sig, b"").expect("prove ok");
        let mut bad = proof.boundary.clone();
        // Flip a limb in R_point.x.
        bad.r_point.x.limbs[0] ^= 1;
        let r = verify_verify_air_proof(&proof.bytes, &pk, &sig, &bad);
        assert!(r.is_err(), "verify must reject when supplied R_point differs from proof's bound R_point");
    }

    /// Cheap sanity test — confirms the wiring compiles.
    #[test]
    fn verify_air_chip_has_expected_width() {
        assert!(NUM_COLS >= 1000, "expected wide AIR, got {} cols", NUM_COLS);
        assert_eq!(NUM_PUBLIC_VALUES, 240);
        assert_eq!(PUBLIC_VALUES_WIRE_BYTES, 96 + 144 * 4);
    }

    /// Verify rejects malformed bytes cleanly.
    #[test]
    fn verify_rejects_garbage_bytes() {
        let (pk, sig) = rfc8032_test_1();
        // Build a dummy boundary of all-zero points just to populate the call.
        let boundary = BoundaryPoints {
            r_point: ExtendedPoint::neutral(),
            a_point: ExtendedPoint::neutral(),
            sb: ExtendedPoint::neutral(),
            ha: ExtendedPoint::neutral(),
        };
        let r = verify_verify_air_proof(&[0xff; 16], &pk, &sig, &boundary);
        assert!(r.is_err(), "verify must reject garbage bytes");
    }

    #[test]
    fn public_values_round_trip_bytes() {
        let (pk, sig) = rfc8032_test_1();
        let boundary = derive_boundary_points(&pk, &sig, b"");
        let bytes = encode_public_values_bytes(&pk, &sig, &boundary);
        assert_eq!(bytes.len(), PUBLIC_VALUES_WIRE_BYTES);
        let (pk2, sig2, boundary2) = decode_public_values_bytes(&bytes).expect("decode ok");
        assert_eq!(pk2, pk);
        assert_eq!(sig2, sig);
        assert_eq!(boundary2, boundary);
        // Field encoding has the right length too.
        let pv = build_public_values(&pk, &sig, &boundary);
        assert_eq!(pv.len(), NUM_PUBLIC_VALUES);
    }

    #[test]
    fn decode_rejects_bad_length() {
        assert!(decode_public_values_bytes(&[0u8; PUBLIC_VALUES_WIRE_BYTES - 1]).is_none());
        assert!(decode_public_values_bytes(&[0u8; PUBLIC_VALUES_WIRE_BYTES + 1]).is_none());
    }
}
