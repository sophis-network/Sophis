//! Chunked-sound STARK plumbing for `ScalarMulAirChunkedChip` (Etapa 3.10.4).
//!
//! Drop-in compatible com `scalar_mul_air_stark` — mesma API pública,
//! mesmo wire format, mesmo `NUM_PUBLIC_VALUES = 104`. Diferença: a
//! prova STARK usa `ScalarMulAirChunkedChip` com 2× `PointAddAirChunkedChip`
//! per row (chunked-sound).
//!
//! **Custo**: a chunked AIR é ~24× wider que a não-chunked (cada row
//! ~199198 cols vs ~8163). Prova full em release: ~5-10 minutos. Para
//! produção mainnet, considerar parallelization ou hardware accelerator.

use p3_matrix::dense::RowMajorMatrix;

use crate::chips::ed25519::point::ExtendedPoint;
use crate::chips::ed25519::scalar_mul_air_chunked::{
    build_public_values, build_scalar_mul_trace_chunked, ScalarMulAirChunkedChip, NUM_BOUNDARY_LIMBS,
    NUM_COLS, NUM_PUBLIC_VALUES,
};
use crate::chips::ed25519::scalar_mul_air::derive_scalar_mul_air_output;
use crate::config::{oracle_stark_config, Val};

const SCALAR_BYTES: usize = 32;

pub const PUBLIC_VALUES_WIRE_BYTES: usize =
    SCALAR_BYTES + NUM_BOUNDARY_LIMBS * 4 + NUM_BOUNDARY_LIMBS * 4;

#[derive(Debug, thiserror::Error)]
pub enum ScalarMulAirChunkedProverError {
    #[error("trace generation failed (trace width mismatch: got {got}, want {want})")]
    BadTraceShape { got: usize, want: usize },
    #[error("proof serialization failed: {0}")]
    Serialization(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ScalarMulAirChunkedVerifyError {
    #[error("proof deserialization failed: {0}")]
    Deserialization(String),
    #[error("STARK verification failed: {0}")]
    StarkRejected(String),
    #[error("public values length wrong (got {got}, want {want})")]
    BadPublicValuesLen { got: usize, want: usize },
}

pub struct ScalarMulAirChunkedProof {
    pub bytes: Vec<u8>,
    pub output: ExtendedPoint,
}

pub fn derive_scalar_mul_output(
    scalar_le_bytes: &[u8; 32],
    base_point: &ExtendedPoint,
) -> ExtendedPoint {
    derive_scalar_mul_air_output(scalar_le_bytes, base_point)
}

pub fn prove_scalar_mul_air_chunked(
    scalar_le_bytes: &[u8; 32],
    base_point: &ExtendedPoint,
) -> Result<ScalarMulAirChunkedProof, ScalarMulAirChunkedProverError> {
    let trace: RowMajorMatrix<Val> =
        build_scalar_mul_trace_chunked::<Val>(scalar_le_bytes, base_point);

    if trace.values.len() % NUM_COLS != 0 {
        return Err(ScalarMulAirChunkedProverError::BadTraceShape {
            got: trace.values.len(),
            want: NUM_COLS,
        });
    }

    let output = derive_scalar_mul_air_output(scalar_le_bytes, base_point);
    let public_values = build_public_values::<Val>(scalar_le_bytes, base_point, &output);

    let (_perm, config) = oracle_stark_config();
    let proof = p3_uni_stark::prove(&config, &ScalarMulAirChunkedChip, trace, &public_values);
    let bytes = bincode::serialize(&proof)
        .map_err(|e| ScalarMulAirChunkedProverError::Serialization(e.to_string()))?;
    Ok(ScalarMulAirChunkedProof { bytes, output })
}

pub fn verify_scalar_mul_air_chunked_proof(
    proof_bytes: &[u8],
    scalar_le_bytes: &[u8; 32],
    base_point: &ExtendedPoint,
    expected_output: &ExtendedPoint,
) -> Result<(), ScalarMulAirChunkedVerifyError> {
    let proof: p3_uni_stark::Proof<crate::config::OracleStarkConfig> =
        bincode::deserialize(proof_bytes)
            .map_err(|e| ScalarMulAirChunkedVerifyError::Deserialization(e.to_string()))?;

    let public_values = build_public_values::<Val>(scalar_le_bytes, base_point, expected_output);
    if public_values.len() != NUM_PUBLIC_VALUES {
        return Err(ScalarMulAirChunkedVerifyError::BadPublicValuesLen {
            got: public_values.len(),
            want: NUM_PUBLIC_VALUES,
        });
    }

    let (_perm, config) = oracle_stark_config();
    p3_uni_stark::verify(&config, &ScalarMulAirChunkedChip, &proof, &public_values)
        .map_err(|e| ScalarMulAirChunkedVerifyError::StarkRejected(format!("{e:?}")))
}

pub fn encode_public_values_bytes(
    scalar_le_bytes: &[u8; 32],
    base_point: &ExtendedPoint,
    output: &ExtendedPoint,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(PUBLIC_VALUES_WIRE_BYTES);
    out.extend_from_slice(scalar_le_bytes);
    push_point_bytes(&mut out, base_point);
    push_point_bytes(&mut out, output);
    debug_assert_eq!(out.len(), PUBLIC_VALUES_WIRE_BYTES);
    out
}

fn push_point_bytes(out: &mut Vec<u8>, p: &ExtendedPoint) {
    for &l in &p.x.limbs { out.extend_from_slice(&(l as u32).to_le_bytes()); }
    for &l in &p.y.limbs { out.extend_from_slice(&(l as u32).to_le_bytes()); }
    for &l in &p.z.limbs { out.extend_from_slice(&(l as u32).to_le_bytes()); }
    for &l in &p.t.limbs { out.extend_from_slice(&(l as u32).to_le_bytes()); }
}

pub fn decode_public_values_bytes(
    bytes: &[u8],
) -> Option<([u8; 32], ExtendedPoint, ExtendedPoint)> {
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
        for limb in &mut x { *limb = read_u32_le(bytes, &mut cur) as u64; }
        for limb in &mut y { *limb = read_u32_le(bytes, &mut cur) as u64; }
        for limb in &mut z { *limb = read_u32_le(bytes, &mut cur) as u64; }
        for limb in &mut t { *limb = read_u32_le(bytes, &mut cur) as u64; }
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
    fn pv_wire_size_matches() {
        assert_eq!(PUBLIC_VALUES_WIRE_BYTES, 32 + 144 + 144);
    }

    #[test]
    fn decode_rejects_bad_length() {
        assert!(decode_public_values_bytes(&[0u8; PUBLIC_VALUES_WIRE_BYTES - 1]).is_none());
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
    #[ignore = "very slow (~5-10 min release); chunked scalar_mul ~199K cols × 256 rows"]
    fn prove_then_verify_chunked_round_trip() {
        let mut s = [0u8; 32];
        s[0] = 1;
        let bp = basepoint();
        let proof = prove_scalar_mul_air_chunked(&s, &bp).expect("prove ok");
        verify_scalar_mul_air_chunked_proof(&proof.bytes, &s, &bp, &proof.output)
            .expect("verify ok");
    }
}
