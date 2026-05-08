//! Chunked-sound STARK plumbing for `VerifyAirChunkedChip` (Etapa 3.10.4).
//!
//! Drop-in compatible com `verify_air_stark` — mesma API pública, mesmo
//! wire format, mesmo `NUM_PUBLIC_VALUES = 240`. Diferença: a prova STARK
//! usa `VerifyAirChunkedChip` (com PointAddAirChunkedChip + 4×
//! MulCanonicalFullChunkedChip; todas BB-wrap collision classes fechadas).
//!
//! **Custo**: AIR ~280K cols (vs 51_828 não-chunked). Prova full em
//! release: tens of seconds.

use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::chips::ed25519::point::ExtendedPoint;
use crate::chips::ed25519::verify_air_chunked::{
    build_verify_trace_chunked, VerifyAirChunkedChip, NUM_BOUNDARY_LIMBS, NUM_COLS,
    NUM_PUBLIC_VALUES,
};
use crate::chips::field25519::NUM_LIMBS;
use crate::config::{oracle_stark_config, Val};

const PUBLIC_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const POINT_LIMBS: usize = 4 * NUM_LIMBS;

pub const PUBLIC_VALUES_WIRE_BYTES: usize =
    PUBLIC_KEY_BYTES + SIGNATURE_BYTES + NUM_BOUNDARY_LIMBS * 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryPoints {
    pub r_point: ExtendedPoint,
    pub a_point: ExtendedPoint,
    pub sb: ExtendedPoint,
    pub ha: ExtendedPoint,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyAirChunkedProverError {
    #[error("trace generation failed (trace width mismatch: got {got}, want {want})")]
    BadTraceShape { got: usize, want: usize },
    #[error("proof serialization failed: {0}")]
    Serialization(String),
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyAirChunkedVerifyError {
    #[error("proof deserialization failed: {0}")]
    Deserialization(String),
    #[error("public values length wrong (got {got}, want {want})")]
    BadPublicValuesLen { got: usize, want: usize },
    #[error("STARK verification failed: {0}")]
    StarkRejected(String),
}

pub struct VerifyAirChunkedProof {
    pub bytes: Vec<u8>,
    pub boundary: BoundaryPoints,
}

pub fn derive_boundary_points(
    public_key: &[u8; 32],
    signature: &[u8; 64],
    message: &[u8],
) -> BoundaryPoints {
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

    let mut hash_input = Vec::with_capacity(64 + message.len());
    hash_input.extend_from_slice(&r_bytes);
    hash_input.extend_from_slice(public_key);
    hash_input.extend_from_slice(message);
    let h_full = sha512(&hash_input);
    let h_mod_l = reduce_mod_l(&h_full);

    let mut basepoint_compressed = [0x66u8; 32];
    basepoint_compressed[0] = 0x58;
    let basepoint = decompress(&basepoint_compressed).expect("basepoint must decompress");

    let sb = derive_scalar_mul_air_output(&s_bytes, &basepoint);
    let ha = derive_scalar_mul_air_output(&h_mod_l, &a_point);
    let _rhs = point_add(&r_point, &ha);

    BoundaryPoints { r_point, a_point, sb, ha }
}

pub fn build_public_values(
    public_key: &[u8; 32],
    signature: &[u8; 64],
    boundary: &BoundaryPoints,
) -> Vec<Val> {
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
    for &l in &p.x.limbs { out.push(Val::from_u64(l)); }
    for &l in &p.y.limbs { out.push(Val::from_u64(l)); }
    for &l in &p.z.limbs { out.push(Val::from_u64(l)); }
    for &l in &p.t.limbs { out.push(Val::from_u64(l)); }
}

pub fn encode_public_values_bytes(
    public_key: &[u8; 32],
    signature: &[u8; 64],
    boundary: &BoundaryPoints,
) -> Vec<u8> {
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
    for &l in &p.x.limbs { out.extend_from_slice(&(l as u32).to_le_bytes()); }
    for &l in &p.y.limbs { out.extend_from_slice(&(l as u32).to_le_bytes()); }
    for &l in &p.z.limbs { out.extend_from_slice(&(l as u32).to_le_bytes()); }
    for &l in &p.t.limbs { out.extend_from_slice(&(l as u32).to_le_bytes()); }
}

pub fn decode_public_values_bytes(
    bytes: &[u8],
) -> Option<([u8; 32], [u8; 64], BoundaryPoints)> {
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

pub fn prove_verify_air_chunked(
    public_key: &[u8; 32],
    signature: &[u8; 64],
    message: &[u8],
) -> Result<VerifyAirChunkedProof, VerifyAirChunkedProverError> {
    let trace: RowMajorMatrix<Val> = build_verify_trace_chunked::<Val>(public_key, signature, message);

    if trace.values.len() % NUM_COLS != 0 {
        return Err(VerifyAirChunkedProverError::BadTraceShape {
            got: trace.values.len(),
            want: NUM_COLS,
        });
    }

    let boundary = derive_boundary_points(public_key, signature, message);
    let public_values = build_public_values(public_key, signature, &boundary);

    let (_perm, config) = oracle_stark_config();
    let proof = p3_uni_stark::prove(&config, &VerifyAirChunkedChip, trace, &public_values);
    let bytes = bincode::serialize(&proof)
        .map_err(|e| VerifyAirChunkedProverError::Serialization(e.to_string()))?;
    Ok(VerifyAirChunkedProof { bytes, boundary })
}

pub fn verify_verify_air_chunked_proof(
    proof_bytes: &[u8],
    public_key: &[u8; 32],
    signature: &[u8; 64],
    boundary: &BoundaryPoints,
) -> Result<(), VerifyAirChunkedVerifyError> {
    let proof: p3_uni_stark::Proof<crate::config::OracleStarkConfig> =
        bincode::deserialize(proof_bytes)
            .map_err(|e| VerifyAirChunkedVerifyError::Deserialization(e.to_string()))?;

    let public_values = build_public_values(public_key, signature, boundary);
    if public_values.len() != NUM_PUBLIC_VALUES {
        return Err(VerifyAirChunkedVerifyError::BadPublicValuesLen {
            got: public_values.len(),
            want: NUM_PUBLIC_VALUES,
        });
    }

    let (_perm, config) = oracle_stark_config();
    p3_uni_stark::verify(&config, &VerifyAirChunkedChip, &proof, &public_values)
        .map_err(|e| VerifyAirChunkedVerifyError::StarkRejected(format!("{e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pv_wire_size_matches() {
        assert_eq!(PUBLIC_VALUES_WIRE_BYTES, 32 + 64 + 144 * 4);
    }

    #[test]
    fn num_public_values_matches_air() {
        assert_eq!(NUM_PUBLIC_VALUES, 32 + 64 + 144);
    }

    #[test]
    fn public_values_round_trip_bytes() {
        let pk = [0xd7u8; 32];
        let sig = [0x55u8; 64];
        let boundary = BoundaryPoints {
            r_point: ExtendedPoint::neutral(),
            a_point: ExtendedPoint::neutral(),
            sb: ExtendedPoint::neutral(),
            ha: ExtendedPoint::neutral(),
        };
        let bytes = encode_public_values_bytes(&pk, &sig, &boundary);
        let (pk2, sig2, bound2) = decode_public_values_bytes(&bytes).unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(sig, sig2);
        assert_eq!(boundary, bound2);
    }

    #[test]
    #[ignore = "very slow (~1-2 min release); chunked verify_air ~280K cols"]
    fn prove_then_verify_chunked_round_trip() {
        let pk: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
            0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
        ];
        let sig: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
            0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
            0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
            0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];
        let proof = prove_verify_air_chunked(&pk, &sig, b"").expect("prove ok");
        verify_verify_air_chunked_proof(&proof.bytes, &pk, &sig, &proof.boundary).expect("verify ok");
    }
}
