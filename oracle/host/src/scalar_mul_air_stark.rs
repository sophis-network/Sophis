//! Sub-fase 5.6.b + 5.6.b.1 — STARK plumbing for `ScalarMulAirChip`.
//!
//! Wraps `chips::ed25519::scalar_mul_air::ScalarMulAirChip` with the same
//! Plonky3 `OracleStarkConfig` used elsewhere in the oracle stack:
//!
//!   - `prove_scalar_mul_air(scalar_bytes, &base_point)` → `ScalarMulAirProof`
//!   - `verify_scalar_mul_air_proof(bytes, &scalar, &base, &output)` → check
//!
//! ## What this proves (post 5.6.b.1.c)
//!
//! The AIR encodes one bit step of fixed-position MSB-first
//! double-and-add per row, for exactly 256 rows:
//!
//! ```text
//! PRE_ACC[0] = O                     (boundary, neutral element)
//! doubled[r] = PRE_ACC[r] + PRE_ACC[r]
//! added[r]   = doubled[r] + BASE_POINT
//! POST_ACC[r] = bit_(255-r) ? added[r] : doubled[r]
//! PRE_ACC[r+1] = POST_ACC[r]
//! ```
//!
//! After 256 rounds `POST_ACC[255]` holds `[scalar] · BASE_POINT` in the
//! AIR's chosen projective representation.
//!
//! Public values (104 BabyBear elements) bind:
//!   - PV[0..32]   scalar bytes (canonical LE) — bound to the bit shift
//!                 register at row 0 via byte decomposition
//!   - PV[32..68]  base_point limbs (X || Y || Z || T) — bound to row 0
//!                 BASE_POINT cells
//!   - PV[68..104] output limbs at POST_ACC of row 255 (when_last_row)
//!
//! After 5.6.b.1.c the wrapper does **no Rust-side re-derivation**: the
//! STARK constraints inside the AIR enforce equality between PV and the
//! trace cells. Tampering with the supplied scalar/base/output causes
//! `StarkRejected`.
//!
//! ## Aggregation with verify_air (5.6.0)
//!
//! On-chain, the contract verifies this proof and checks
//! `output == verify_air.sB_point` (or `hA_point`). Combined with
//! `verify_air`'s binding (5.6.0) that `sB`/`hA` match its witnessed
//! boundary, this transitively proves: the scalar/base committed in the
//! oracle's bundle are exactly the inputs the verify_air group equation
//! consumed.

use p3_matrix::dense::RowMajorMatrix;

use crate::chips::ed25519::point::ExtendedPoint;
use crate::chips::ed25519::scalar_mul_air::{
    NUM_BOUNDARY_LIMBS, NUM_COLS, NUM_PUBLIC_VALUES, ScalarMulAirChip, build_public_values, build_scalar_mul_trace,
    derive_scalar_mul_air_output,
};
use crate::config::{Val, oracle_stark_config};

const SCALAR_BYTES: usize = 32;

/// Wire-format size: 32 (scalar) + 144 (base limbs as u32 LE) + 144 (output limbs) = 320.
pub const PUBLIC_VALUES_WIRE_BYTES: usize = SCALAR_BYTES + NUM_BOUNDARY_LIMBS * 4 + NUM_BOUNDARY_LIMBS * 4;

#[derive(Debug, thiserror::Error)]
pub enum ScalarMulAirProverError {
    #[error("trace generation failed (trace width mismatch: got {got}, want {want})")]
    BadTraceShape { got: usize, want: usize },
    #[error("proof serialization failed: {0}")]
    Serialization(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ScalarMulAirVerifyError {
    #[error("proof deserialization failed: {0}")]
    Deserialization(String),
    #[error("STARK verification failed: {0}")]
    StarkRejected(String),
    #[error("public values length wrong (got {got}, want {want})")]
    BadPublicValuesLen { got: usize, want: usize },
}

/// Opaque proof + the boundary output the prover witnessed at POST_ACC[255].
pub struct ScalarMulAirProof {
    pub bytes: Vec<u8>,
    pub output: ExtendedPoint,
}

/// Compute `[scalar]base` in the AIR's canonical projective representation.
///
/// Public helper so the relayer can pre-compute outputs for bundle
/// construction without re-running the full trace builder. This **must**
/// be used in place of `chips::ed25519::scalar_mul::scalar_mul` when
/// preparing PV for this AIR — the witness function and the AIR use
/// equivalent group elements but different projective representations.
pub fn derive_scalar_mul_output(scalar_le_bytes: &[u8; 32], base_point: &ExtendedPoint) -> ExtendedPoint {
    derive_scalar_mul_air_output(scalar_le_bytes, base_point)
}

/// Generate a STARK proof of scalar_mul_air for `(scalar, base_point)`.
/// Returns proof bytes + the output point in the AIR's projective form.
///
/// **Slow** — multi-row AIR with ~72_635 cols × 256 rows.
pub fn prove_scalar_mul_air(
    scalar_le_bytes: &[u8; 32],
    base_point: &ExtendedPoint,
) -> Result<ScalarMulAirProof, ScalarMulAirProverError> {
    let trace: RowMajorMatrix<Val> = build_scalar_mul_trace::<Val>(scalar_le_bytes, base_point);

    if !trace.values.len().is_multiple_of(NUM_COLS) {
        return Err(ScalarMulAirProverError::BadTraceShape { got: trace.values.len(), want: NUM_COLS });
    }

    let output = derive_scalar_mul_air_output(scalar_le_bytes, base_point);
    let public_values = build_public_values::<Val>(scalar_le_bytes, base_point, &output);

    let (_perm, config) = oracle_stark_config();
    let proof = p3_uni_stark::prove(&config, &ScalarMulAirChip, trace, &public_values);
    let bytes = bincode::serialize(&proof).map_err(|e| ScalarMulAirProverError::Serialization(e.to_string()))?;
    Ok(ScalarMulAirProof { bytes, output })
}

/// Verify proof bytes against the supplied `(scalar, base, expected_output)`.
///
/// As of 5.6.b.1.c, the AIR constraints enforce equality between the
/// supplied PV and the trace's bit register / base / POST_ACC[255] cells.
/// A mismatch on any of (scalar, base, output) yields `StarkRejected`.
pub fn verify_scalar_mul_air_proof(
    proof_bytes: &[u8],
    scalar_le_bytes: &[u8; 32],
    base_point: &ExtendedPoint,
    expected_output: &ExtendedPoint,
) -> Result<(), ScalarMulAirVerifyError> {
    let proof: p3_uni_stark::Proof<crate::config::OracleStarkConfig> =
        bincode::deserialize(proof_bytes).map_err(|e| ScalarMulAirVerifyError::Deserialization(e.to_string()))?;

    let public_values = build_public_values::<Val>(scalar_le_bytes, base_point, expected_output);
    if public_values.len() != NUM_PUBLIC_VALUES {
        return Err(ScalarMulAirVerifyError::BadPublicValuesLen { got: public_values.len(), want: NUM_PUBLIC_VALUES });
    }

    let (_perm, config) = oracle_stark_config();
    p3_uni_stark::verify(&config, &ScalarMulAirChip, &proof, &public_values)
        .map_err(|e| ScalarMulAirVerifyError::StarkRejected(format!("{e:?}")))
}

/// Encode `(scalar, base, output)` as wire-format bytes (320 bytes).
pub fn encode_public_values_bytes(scalar_le_bytes: &[u8; 32], base_point: &ExtendedPoint, output: &ExtendedPoint) -> Vec<u8> {
    let mut out = Vec::with_capacity(PUBLIC_VALUES_WIRE_BYTES);
    out.extend_from_slice(scalar_le_bytes);
    push_point_bytes(&mut out, base_point);
    push_point_bytes(&mut out, output);
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

/// Decode wire-format bytes back into `(scalar, base, output)`.
pub fn decode_public_values_bytes(bytes: &[u8]) -> Option<([u8; 32], ExtendedPoint, ExtendedPoint)> {
    use crate::chips::field25519::{Field25519Element, NUM_LIMBS};

    if bytes.len() != PUBLIC_VALUES_WIRE_BYTES {
        return None;
    }
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&bytes[..32]);

    let mut cur = 32usize;
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
    let base = read_point();
    let output = read_point();
    Some((scalar, base, output))
}

fn read_u32_le(bytes: &[u8], cur: &mut usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[*cur..*cur + 4]);
    *cur += 4;
    u32::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basepoint() -> ExtendedPoint {
        use crate::chips::ed25519::decompress::decompress;
        let mut bp = [0x66u8; 32];
        bp[0] = 0x58;
        decompress(&bp).expect("basepoint")
    }

    #[test]
    fn derive_basepoint_times_one() {
        let mut s = [0u8; 32];
        s[0] = 1;
        let out = derive_scalar_mul_output(&s, &basepoint());
        // [1]·B in the AIR's projective form: 256 rounds of doubling-from-O
        // ending in `O + O + ... + O + B`. Group element matches B but Z
        // representation differs from the witness-function output.
        let (ax, ay) = crate::chips::ed25519::point::to_affine(&out);
        let (bx, by) = crate::chips::ed25519::point::to_affine(&basepoint());
        assert_eq!(ax, bx);
        assert_eq!(ay, by);
    }

    #[test]
    fn public_values_round_trip_bytes() {
        let mut s = [0u8; 32];
        s[0] = 7;
        let bp = basepoint();
        let out = derive_scalar_mul_output(&s, &bp);
        let bytes = encode_public_values_bytes(&s, &bp, &out);
        let (s2, bp2, out2) = decode_public_values_bytes(&bytes).unwrap();
        assert_eq!(s, s2);
        assert_eq!(bp, bp2);
        assert_eq!(out, out2);
    }

    #[test]
    fn pv_wire_size_matches() {
        assert_eq!(PUBLIC_VALUES_WIRE_BYTES, 32 + 144 + 144);
    }

    #[test]
    fn decode_rejects_bad_length() {
        assert!(decode_public_values_bytes(&[0u8; PUBLIC_VALUES_WIRE_BYTES - 1]).is_none());
    }

    /// Slow STARK round-trip on a small scalar (multi-row AIR is heavy).
    #[test]
    #[ignore = "slow (multi-row scalar_mul AIR ~72K cols × 256 rows)"]
    fn prove_then_verify_round_trip_small_scalar() {
        let mut s = [0u8; 32];
        s[0] = 5;
        let proof = prove_scalar_mul_air(&s, &basepoint()).expect("prove ok");
        verify_scalar_mul_air_proof(&proof.bytes, &s, &basepoint(), &proof.output).expect("verify ok");
    }

    /// Tampering the supplied output during verify must reject (now via STARK constraints).
    #[test]
    #[ignore = "slow; validates 5.6.b.1.c internal binding by mutating verify-side output"]
    fn verify_rejects_tampered_output() {
        let mut s = [0u8; 32];
        s[0] = 3;
        let proof = prove_scalar_mul_air(&s, &basepoint()).expect("prove ok");
        let mut bad = proof.output.clone();
        bad.x.limbs[0] ^= 1;
        let r = verify_scalar_mul_air_proof(&proof.bytes, &s, &basepoint(), &bad);
        assert!(r.is_err(), "verify must reject when supplied output differs from proof's bound output");
    }

    /// Tampering the scalar bytes must reject.
    #[test]
    #[ignore = "slow; validates 5.6.b.1.c internal binding by mutating verify-side scalar"]
    fn verify_rejects_tampered_scalar() {
        let mut s = [0u8; 32];
        s[0] = 3;
        let proof = prove_scalar_mul_air(&s, &basepoint()).expect("prove ok");
        let mut bad_scalar = s;
        bad_scalar[0] ^= 1;
        let r = verify_scalar_mul_air_proof(&proof.bytes, &bad_scalar, &basepoint(), &proof.output);
        assert!(r.is_err(), "verify must reject when supplied scalar differs from proof's bound scalar");
    }

    /// Tampering the base point must reject.
    #[test]
    #[ignore = "slow; validates 5.6.b.1.c internal binding by mutating verify-side base"]
    fn verify_rejects_tampered_base() {
        let mut s = [0u8; 32];
        s[0] = 3;
        let proof = prove_scalar_mul_air(&s, &basepoint()).expect("prove ok");
        let mut bad_base = basepoint();
        bad_base.x.limbs[0] ^= 1;
        let r = verify_scalar_mul_air_proof(&proof.bytes, &s, &bad_base, &proof.output);
        assert!(r.is_err(), "verify must reject when supplied base differs from proof's bound base");
    }
}
