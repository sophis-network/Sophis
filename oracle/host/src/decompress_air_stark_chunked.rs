//! Chunked-sound STARK plumbing for `DecompressAirChunkedChip` (Etapa 3.10.4).
//!
//! Drop-in compatible com `decompress_air_stark` — mesma API pública
//! (`prove_decompress_air_chunked`, `verify_decompress_air_chunked_proof`,
//! `build_public_values`, `encode_public_values_bytes`,
//! `decode_public_values_bytes`), mesmo wire format, mesmo `NUM_PUBLIC_VALUES = 69`.
//!
//! Diferença: a prova STARK usa `DecompressAirChunkedChip` (com BB-wrap
//! collision classes fechadas) em vez do `DecompressAirChip` original.
//!
//! ## Aggregação
//!
//! Wire format invariance preservada → contratos on-chain podem migrar
//! de plumbing não-chunked → chunked sem mudar PV decoders.

use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::chips::ed25519::decompress_air_chunked::{
    DecompressAirChunkedChip, NUM_COLS, NUM_PUBLIC_VALUES, build_decompress_trace_chunked,
};
use crate::chips::ed25519::point::ExtendedPoint;
use crate::chips::field25519::{Field25519Element, NUM_LIMBS};
use crate::config::{Val, oracle_stark_config};

const COMPRESSED_BYTES: usize = 32;
const POINT_LIMBS: usize = 4 * NUM_LIMBS;

pub const PUBLIC_VALUES_WIRE_BYTES: usize = COMPRESSED_BYTES + POINT_LIMBS * 4 + 1;

#[derive(Debug, thiserror::Error)]
pub enum DecompressAirChunkedProverError {
    #[error("trace generation failed (trace width mismatch: got {got}, want {want})")]
    BadTraceShape { got: usize, want: usize },
    #[error("proof serialization failed: {0}")]
    Serialization(String),
}

#[derive(Debug, thiserror::Error)]
pub enum DecompressAirChunkedVerifyError {
    #[error("proof deserialization failed: {0}")]
    Deserialization(String),
    #[error("STARK verification failed: {0}")]
    StarkRejected(String),
    #[error("public values length wrong (got {got}, want {want})")]
    BadPublicValuesLen { got: usize, want: usize },
}

pub struct DecompressAirChunkedProof {
    pub bytes: Vec<u8>,
    pub output: ExtendedPoint,
    pub valid: bool,
}

pub fn derive_decompress_output(compressed_bytes: &[u8; 32]) -> (ExtendedPoint, bool) {
    use crate::chips::ed25519::decompress::decompress;

    match decompress(compressed_bytes) {
        Some(point) => (point, true),
        None => (
            ExtendedPoint {
                x: Field25519Element::ZERO,
                y: Field25519Element::from_canonical_bytes(compressed_bytes),
                z: Field25519Element {
                    limbs: {
                        let mut o = [0u64; NUM_LIMBS];
                        o[0] = 1;
                        o
                    },
                },
                t: Field25519Element::ZERO,
            },
            false,
        ),
    }
}

pub fn build_public_values(compressed_bytes: &[u8; 32], output: &ExtendedPoint, valid: bool) -> Vec<Val> {
    let mut out = Vec::with_capacity(NUM_PUBLIC_VALUES);
    for &b in compressed_bytes {
        out.push(Val::from_u64(b as u64));
    }
    for &l in &output.x.limbs {
        out.push(Val::from_u64(l));
    }
    for &l in &output.y.limbs {
        out.push(Val::from_u64(l));
    }
    for &l in &output.z.limbs {
        out.push(Val::from_u64(l));
    }
    for &l in &output.t.limbs {
        out.push(Val::from_u64(l));
    }
    out.push(Val::from_u64(if valid { 1 } else { 0 }));
    debug_assert_eq!(out.len(), NUM_PUBLIC_VALUES);
    out
}

/// Generate a STARK proof of the chunked decompress AIR.
///
/// **Slow** — a chunked AIR é ~3× wider que a não-chunked. Expect ~30s
/// release for a single point.
pub fn prove_decompress_air_chunked(
    compressed_bytes: &[u8; 32],
) -> Result<DecompressAirChunkedProof, DecompressAirChunkedProverError> {
    let trace: RowMajorMatrix<Val> = build_decompress_trace_chunked::<Val>(compressed_bytes);

    if !trace.values.len().is_multiple_of(NUM_COLS) {
        return Err(DecompressAirChunkedProverError::BadTraceShape { got: trace.values.len(), want: NUM_COLS });
    }

    let (output, valid) = derive_decompress_output(compressed_bytes);
    let public_values = build_public_values(compressed_bytes, &output, valid);

    let (_perm, config) = oracle_stark_config();
    let proof = p3_uni_stark::prove(&config, &DecompressAirChunkedChip, trace, &public_values);
    let bytes = bincode::serialize(&proof).map_err(|e| DecompressAirChunkedProverError::Serialization(e.to_string()))?;
    Ok(DecompressAirChunkedProof { bytes, output, valid })
}

pub fn verify_decompress_air_chunked_proof(
    proof_bytes: &[u8],
    compressed_bytes: &[u8; 32],
    expected_output: &ExtendedPoint,
    expected_valid: bool,
) -> Result<(), DecompressAirChunkedVerifyError> {
    let proof: p3_uni_stark::Proof<crate::config::OracleStarkConfig> =
        bincode::deserialize(proof_bytes).map_err(|e| DecompressAirChunkedVerifyError::Deserialization(e.to_string()))?;

    let public_values = build_public_values(compressed_bytes, expected_output, expected_valid);
    if public_values.len() != NUM_PUBLIC_VALUES {
        return Err(DecompressAirChunkedVerifyError::BadPublicValuesLen { got: public_values.len(), want: NUM_PUBLIC_VALUES });
    }

    let (_perm, config) = oracle_stark_config();
    p3_uni_stark::verify(&config, &DecompressAirChunkedChip, &proof, &public_values)
        .map_err(|e| DecompressAirChunkedVerifyError::StarkRejected(format!("{e:?}")))
}

pub fn encode_public_values_bytes(compressed_bytes: &[u8; 32], output: &ExtendedPoint, valid: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(PUBLIC_VALUES_WIRE_BYTES);
    out.extend_from_slice(compressed_bytes);
    for &l in &output.x.limbs {
        out.extend_from_slice(&(l as u32).to_le_bytes());
    }
    for &l in &output.y.limbs {
        out.extend_from_slice(&(l as u32).to_le_bytes());
    }
    for &l in &output.z.limbs {
        out.extend_from_slice(&(l as u32).to_le_bytes());
    }
    for &l in &output.t.limbs {
        out.extend_from_slice(&(l as u32).to_le_bytes());
    }
    out.push(if valid { 1 } else { 0 });
    debug_assert_eq!(out.len(), PUBLIC_VALUES_WIRE_BYTES);
    out
}

pub fn decode_public_values_bytes(bytes: &[u8]) -> Option<([u8; 32], ExtendedPoint, bool)> {
    if bytes.len() != PUBLIC_VALUES_WIRE_BYTES {
        return None;
    }
    let mut compressed = [0u8; 32];
    compressed.copy_from_slice(&bytes[..32]);

    let mut cur = 32usize;
    let mut read_limbs = || -> [u64; NUM_LIMBS] {
        let mut out = [0u64; NUM_LIMBS];
        for limb in &mut out {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes[cur..cur + 4]);
            cur += 4;
            *limb = u32::from_le_bytes(buf) as u64;
        }
        out
    };
    let x = Field25519Element { limbs: read_limbs() };
    let y = Field25519Element { limbs: read_limbs() };
    let z = Field25519Element { limbs: read_limbs() };
    let t = Field25519Element { limbs: read_limbs() };
    let valid = bytes[cur] != 0;
    Some((compressed, ExtendedPoint { x, y, z, t }, valid))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basepoint_compressed() -> [u8; 32] {
        let mut b = [0x66u8; 32];
        b[0] = 0x58;
        b
    }

    #[test]
    fn pv_wire_size_matches_documented() {
        assert_eq!(PUBLIC_VALUES_WIRE_BYTES, 32 + 144 + 1);
    }

    #[test]
    fn num_public_values_matches_air() {
        assert_eq!(NUM_PUBLIC_VALUES, 32 + 36 + 1);
    }

    #[test]
    fn build_public_values_length_matches_air() {
        let bp = basepoint_compressed();
        let (output, valid) = derive_decompress_output(&bp);
        let pv = build_public_values(&bp, &output, valid);
        assert_eq!(pv.len(), NUM_PUBLIC_VALUES);
    }

    #[test]
    fn public_values_round_trip_bytes() {
        let bp = basepoint_compressed();
        let (output, valid) = derive_decompress_output(&bp);
        let bytes = encode_public_values_bytes(&bp, &output, valid);
        assert_eq!(bytes.len(), PUBLIC_VALUES_WIRE_BYTES);
        let (bp2, output2, valid2) = decode_public_values_bytes(&bytes).expect("decode ok");
        assert_eq!(bp2, bp);
        assert_eq!(output2, output);
        assert_eq!(valid2, valid);
    }

    #[test]
    #[ignore = "slow (~30s release); chunked decompress AIR full prove→verify"]
    fn prove_then_verify_chunked_round_trip() {
        let bp = basepoint_compressed();
        let proof = prove_decompress_air_chunked(&bp).expect("prove must succeed");
        assert!(!proof.bytes.is_empty());
        assert!(proof.valid);
        verify_decompress_air_chunked_proof(&proof.bytes, &bp, &proof.output, proof.valid).expect("verify must succeed");
    }
}
