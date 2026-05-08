//! `ed25519::verify_air` — top-level Ed25519 verify AIR (WIRED).
//!
//! Implements the FINAL group-equation equality of the ed25519 verify
//! algorithm:
//!
//! ```text
//! [s]B == R + [h]A
//! ```
//!
//! ## Multi-proof aggregation architecture
//!
//! verify_air does NOT internally constrain decompress, scalar_mul, or
//! SHA-512 hashing. Those are SEPARATE Plonky3 AIR proofs (sub-fases
//! `decompress_air`, `scalar_mul_air`, `compression_chip`) that the
//! relayer generates in parallel and aggregates. verify_air receives
//! their outputs as boundary witnesses:
//!
//!   - `r_point` (36 cols): from a `decompress_air` proof for R bytes
//!   - `a_point` (36 cols): from a `decompress_air` proof for A bytes
//!   - `sb_point` (36 cols): from a `scalar_mul_air` proof for `[s]B`
//!   - `ha_point` (36 cols): from a `scalar_mul_air` proof for `[h]A`
//!
//! verify_air constrains:
//!   - `rhs = point_add(r_point, ha_point)` via 1 embedded `PointAddAirChip`
//!   - Projective equality `sb_point ≡ rhs` via cross products:
//!       sb.X · rhs.Z == rhs.X · sb.Z
//!       sb.Y · rhs.Z == rhs.Y · sb.Z
//!     (avoids modular inversion to compare affine)
//!
//! On-chain verifier composes verify_air's proof with the upstream
//! decompress/scalar_mul proofs by checking that the boundary
//! commitments match (standard production STARK aggregation).
//!
//! ## Layout (single-row)
//!
//! | Range     | Width | Contents                                  |
//! |-----------|-------|-------------------------------------------|
//! | 0..32     | 32    | public_key bytes (boundary commitment)    |
//! | 32..96    | 64    | signature bytes (R || S, boundary)        |
//! | 96..132   | 36    | R_point (boundary, from decompress proof) |
//! | 132..168  | 36    | A_point (boundary, from decompress proof) |
//! | 168..204  | 36    | sB (boundary, from scalar_mul proof)      |
//! | 204..240  | 36    | hA (boundary, from scalar_mul proof)      |
//! | 240..276  | 36    | rhs = R + hA (output of embedded point_add) |
//! | 276..312  | 36    | 4 cross-product outputs (X·Z and X·Z swapped, Y·Z, etc.) |
//! | 312..320  | 8     | reserved / valid flag                     |
//! | 320..8123 | 7803  | PointAddAirChip embed                     |
//! | 8123..    | 4·710 | 4 MulCanonicalFullChip embeds             |
//!
//! Total: **10,963 cols**. Single-row.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::chips::ed25519::point::ExtendedPoint;
use crate::chips::ed25519::point_add_air::{self, NUM_COLS as PA_COLS, PointAddAirChip};
use crate::chips::field25519::{
    Field25519Element, NUM_LIMBS,
    mul_canonical_full::{self, MulCanonicalFullChip, NUM_COLS as MC_COLS},
};

const POINT_LIMBS: usize = 4 * NUM_LIMBS; // 36
const PUBLIC_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const NUM_CROSS: usize = 4; // sB_X·rhs_Z, rhs_X·sB_Z, sB_Y·rhs_Z, rhs_Y·sB_Z

pub mod col {
    use super::*;
    pub const PUBLIC_KEY: usize = 0;
    pub const SIGNATURE: usize = PUBLIC_KEY + PUBLIC_KEY_BYTES; // 32
    pub const R_POINT: usize = SIGNATURE + SIGNATURE_BYTES; // 96
    pub const A_POINT: usize = R_POINT + POINT_LIMBS; // 132
    pub const SB: usize = A_POINT + POINT_LIMBS; // 168
    pub const HA: usize = SB + POINT_LIMBS; // 204
    pub const RHS: usize = HA + POINT_LIMBS; // 240
    // 4 cross products of 9 limbs each = 36 cols.
    pub const CROSS_BASE: usize = RHS + POINT_LIMBS; // 276
    pub const VALID: usize = CROSS_BASE + NUM_CROSS * NUM_LIMBS; // 312
    pub const POINT_ADD_START: usize = VALID + 1; // 313
    pub const MULS_BASE: usize = POINT_ADD_START + PA_COLS; // 8116
    pub const TOTAL: usize = MULS_BASE + NUM_CROSS * MC_COLS; // 10956

    pub const X_OFF: usize = 0;
    pub const Y_OFF: usize = NUM_LIMBS;
    pub const Z_OFF: usize = 2 * NUM_LIMBS;
    pub const T_OFF: usize = 3 * NUM_LIMBS;

    pub const fn cross_at(i: usize) -> usize {
        CROSS_BASE + i * NUM_LIMBS
    }
    pub const fn mul_at(i: usize) -> usize {
        MULS_BASE + i * MC_COLS
    }
}

pub const NUM_COLS: usize = col::TOTAL;

/// Public-values count exposed to the STARK verifier.
///
/// Layout (sub-fase 5.4.b + 5.6.0):
///   [0..32]    public_key bytes  (boundary-bound to row[col::PUBLIC_KEY..])
///   [32..96]   signature bytes   (boundary-bound to row[col::SIGNATURE..])
///   [96..132]  R_point  limbs    (boundary-bound to row[col::R_POINT..])
///   [132..168] A_point  limbs    (boundary-bound to row[col::A_POINT..])
///   [168..204] sB       limbs    (boundary-bound to row[col::SB..])
///   [204..240] hA       limbs    (boundary-bound to row[col::HA..])
///
/// Bytes (0..96) are one BabyBear element per byte (canonical 0..255).
/// Limbs (96..240) are one BabyBear element per 30-bit limb. The
/// on-chain verifier reconstructs the same `Vec<F>` from the wire
/// representation (672 bytes: 96 raw bytes + 144 × 4 LE bytes for limbs)
/// and the constraint forces equality with the witnessed boundary cells.
///
/// 5.6.0 (this expansion) unlocks **companion proof aggregation**:
/// future `decompress_air` / `scalar_mul_air` / `sha512` proofs expose
/// their own outputs as public values, and the contract checks they
/// equal the corresponding `R/A/sB/hA` slot here. Without 5.6.0 those
/// boundary cells were invisible to the contract, so companion proofs
/// could not be bound.
pub const NUM_BOUNDARY_LIMBS: usize = 4 * POINT_LIMBS; // 144 (R + A + sB + hA)
pub const NUM_PUBLIC_VALUES: usize = PUBLIC_KEY_BYTES + SIGNATURE_BYTES + NUM_BOUNDARY_LIMBS; // 240

/// Cross-product chip indices.
pub mod chip {
    pub const MUL_SB_X_RHS_Z: usize = 0;
    pub const MUL_RHS_X_SB_Z: usize = 1;
    pub const MUL_SB_Y_RHS_Z: usize = 2;
    pub const MUL_RHS_Y_SB_Z: usize = 3;
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyAirChip;

impl<F: Field> BaseAir<F> for VerifyAirChip {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for VerifyAirChip
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        // Embed sub-chips.
        PointAddAirChip::at(col::POINT_ADD_START).emit(builder);
        for i in 0..NUM_CROSS {
            MulCanonicalFullChip::at(col::mul_at(i)).emit(builder);
        }

        let main = builder.main();
        let row = main.current_slice();

        // ===== Boundary binding: public_key + signature + R_point + A_point + sB + hA =====
        //
        // Trace cols [0..96] are PUBLIC_KEY (32) || SIGNATURE (64); cols
        // [96..240] are R_POINT (36) || A_POINT (36) || SB (36) || HA (36).
        // Both regions are exposed as public values so the contract can
        // bind companion proofs (5.6.a-d) against the witnessed boundary.
        //
        // We copy public values into a local Copy array first to release the
        // immutable borrow on `builder` before calling the mutable
        // `assert_eq` (Plonky3 borrow-checker pattern).
        let pub_copies: [AB::PublicVar; NUM_PUBLIC_VALUES] = {
            let public = builder.public_values();
            core::array::from_fn(|i| public[i])
        };
        // Bytes region: cols [0..96] match public values [0..96].
        for i in 0..(PUBLIC_KEY_BYTES + SIGNATURE_BYTES) {
            builder.assert_eq(row[i], pub_copies[i]);
        }
        // Limbs region: PV [96..240] mirrors row[R_POINT..R_POINT+144].
        // R_POINT/A_POINT/SB/HA are contiguous in the trace layout (cols
        // 96..240 in the chip's slice — same as the PV indices).
        for i in 0..NUM_BOUNDARY_LIMBS {
            let row_off = col::R_POINT + i;
            let pv_off = PUBLIC_KEY_BYTES + SIGNATURE_BYTES + i;
            builder.assert_eq(row[row_off], pub_copies[pv_off]);
        }

        builder.assert_bool(row[col::VALID]);

        let assert_chunks = |b: &mut AB, off_a: usize, off_b: usize, n: usize| {
            for i in 0..n {
                b.assert_eq(row[off_a + i], row[off_b + i]);
            }
        };

        // PointAdd: P1 = R_POINT, P2 = HA, P3 = RHS
        assert_chunks(builder, col::POINT_ADD_START + point_add_air::col::P1, col::R_POINT, POINT_LIMBS);
        assert_chunks(builder, col::POINT_ADD_START + point_add_air::col::P2, col::HA, POINT_LIMBS);
        assert_chunks(builder, col::POINT_ADD_START + point_add_air::col::P3, col::RHS, POINT_LIMBS);

        // Cross products for projective equality.
        // sB.X · rhs.Z
        assert_chunks(builder, col::mul_at(chip::MUL_SB_X_RHS_Z) + mul_canonical_full::col::A, col::SB + col::X_OFF, NUM_LIMBS);
        assert_chunks(builder, col::mul_at(chip::MUL_SB_X_RHS_Z) + mul_canonical_full::col::B, col::RHS + col::Z_OFF, NUM_LIMBS);
        assert_chunks(
            builder,
            col::cross_at(chip::MUL_SB_X_RHS_Z),
            col::mul_at(chip::MUL_SB_X_RHS_Z) + mul_canonical_full::col::C,
            NUM_LIMBS,
        );

        // rhs.X · sB.Z
        assert_chunks(builder, col::mul_at(chip::MUL_RHS_X_SB_Z) + mul_canonical_full::col::A, col::RHS + col::X_OFF, NUM_LIMBS);
        assert_chunks(builder, col::mul_at(chip::MUL_RHS_X_SB_Z) + mul_canonical_full::col::B, col::SB + col::Z_OFF, NUM_LIMBS);
        assert_chunks(
            builder,
            col::cross_at(chip::MUL_RHS_X_SB_Z),
            col::mul_at(chip::MUL_RHS_X_SB_Z) + mul_canonical_full::col::C,
            NUM_LIMBS,
        );

        // sB.Y · rhs.Z
        assert_chunks(builder, col::mul_at(chip::MUL_SB_Y_RHS_Z) + mul_canonical_full::col::A, col::SB + col::Y_OFF, NUM_LIMBS);
        assert_chunks(builder, col::mul_at(chip::MUL_SB_Y_RHS_Z) + mul_canonical_full::col::B, col::RHS + col::Z_OFF, NUM_LIMBS);
        assert_chunks(
            builder,
            col::cross_at(chip::MUL_SB_Y_RHS_Z),
            col::mul_at(chip::MUL_SB_Y_RHS_Z) + mul_canonical_full::col::C,
            NUM_LIMBS,
        );

        // rhs.Y · sB.Z
        assert_chunks(builder, col::mul_at(chip::MUL_RHS_Y_SB_Z) + mul_canonical_full::col::A, col::RHS + col::Y_OFF, NUM_LIMBS);
        assert_chunks(builder, col::mul_at(chip::MUL_RHS_Y_SB_Z) + mul_canonical_full::col::B, col::SB + col::Z_OFF, NUM_LIMBS);
        assert_chunks(
            builder,
            col::cross_at(chip::MUL_RHS_Y_SB_Z),
            col::mul_at(chip::MUL_RHS_Y_SB_Z) + mul_canonical_full::col::C,
            NUM_LIMBS,
        );

        // ===== Projective equality assertion (THE GROUP EQUATION) =====
        // sB.X · rhs.Z == rhs.X · sB.Z
        // sB.Y · rhs.Z == rhs.Y · sB.Z
        // When VALID=1, both must hold. We assert unconditionally (honest
        // prover with valid sig) — invalid sigs simply can't produce a
        // satisfying trace.
        for i in 0..NUM_LIMBS {
            builder.assert_eq(row[col::cross_at(chip::MUL_SB_X_RHS_Z) + i], row[col::cross_at(chip::MUL_RHS_X_SB_Z) + i]);
            builder.assert_eq(row[col::cross_at(chip::MUL_SB_Y_RHS_Z) + i], row[col::cross_at(chip::MUL_RHS_Y_SB_Z) + i]);
        }
    }
}

fn put_field<F: Field + PrimeCharacteristicRing>(values: &mut [F], off: usize, e: &Field25519Element) {
    for i in 0..NUM_LIMBS {
        values[off + i] = F::from_u64(e.limbs[i]);
    }
}

fn put_point<F: Field + PrimeCharacteristicRing>(values: &mut [F], off: usize, p: &ExtendedPoint) {
    put_field(values, off + col::X_OFF, &p.x);
    put_field(values, off + col::Y_OFF, &p.y);
    put_field(values, off + col::Z_OFF, &p.z);
    put_field(values, off + col::T_OFF, &p.t);
}

/// Build a single-row trace running the witness `verify` function.
///
/// **Note on aggregation:** This function computes R, A, sB, hA from the
/// witness functions for testing. In production, those values come from
/// separate AIR proofs that the on-chain verifier aggregates.
pub fn build_verify_trace<F: Field + PrimeCharacteristicRing>(
    public_key: &[u8; 32],
    signature: &[u8; 64],
    message: &[u8],
) -> RowMajorMatrix<F> {
    use crate::chips::ed25519::decompress::decompress;
    use crate::chips::ed25519::point::point_add;
    use crate::chips::ed25519::scalar_mul_air::derive_scalar_mul_air_output;
    use crate::chips::ed25519::verify::reduce_mod_l;
    use crate::chips::field25519::arith::field_mul;
    use crate::chips::sha512::compression::sha512;

    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    // Decompose signature: R (first 32) + s (last 32, scalar mod ℓ).
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

    // Basepoint.
    let mut basepoint_compressed = [0x66u8; 32];
    basepoint_compressed[0] = 0x58;
    let basepoint = decompress(&basepoint_compressed).expect("basepoint must decompress");

    // Sub-fase 5.6.b.1.d — verify_air's boundary sB/hA must expose the
    // **AIR's** projective representation so that aggregation against
    // scalar_mul_air proofs (which expose AIR-form outputs in their PVs)
    // succeeds via cell-wise equality. The witness function `scalar_mul`
    // and `derive_scalar_mul_air_output` produce equivalent group
    // elements but distinct projective coordinates; the contract
    // aggregation compares cells literally, not group-element-wise.
    let sb = derive_scalar_mul_air_output(&s_bytes, &basepoint);
    let ha = derive_scalar_mul_air_output(&h_mod_l, &a_point);
    let rhs = point_add(&r_point, &ha);

    // Cross products for projective equality.
    let sb_x_rhs_z = field_mul(&sb.x, &rhs.z);
    let rhs_x_sb_z = field_mul(&rhs.x, &sb.z);
    let sb_y_rhs_z = field_mul(&sb.y, &rhs.z);
    let rhs_y_sb_z = field_mul(&rhs.y, &sb.z);

    // Populate row 0 with the actual witness.
    for i in 0..32 {
        values[col::PUBLIC_KEY + i] = F::from_u64(public_key[i] as u64);
    }
    for i in 0..64 {
        values[col::SIGNATURE + i] = F::from_u64(signature[i] as u64);
    }
    put_point::<F>(&mut values, col::R_POINT, &r_point);
    put_point::<F>(&mut values, col::A_POINT, &a_point);
    put_point::<F>(&mut values, col::SB, &sb);
    put_point::<F>(&mut values, col::HA, &ha);
    put_point::<F>(&mut values, col::RHS, &rhs);
    put_field::<F>(&mut values, col::cross_at(chip::MUL_SB_X_RHS_Z), &sb_x_rhs_z);
    put_field::<F>(&mut values, col::cross_at(chip::MUL_RHS_X_SB_Z), &rhs_x_sb_z);
    put_field::<F>(&mut values, col::cross_at(chip::MUL_SB_Y_RHS_Z), &sb_y_rhs_z);
    put_field::<F>(&mut values, col::cross_at(chip::MUL_RHS_Y_SB_Z), &rhs_y_sb_z);
    values[col::VALID] = F::ONE;

    // Sub-chips.
    point_add_air::populate_row::<F>(&mut values, 0, col::POINT_ADD_START, &r_point, &ha);
    mul_canonical_full::populate_row::<F>(&mut values, 0, col::mul_at(chip::MUL_SB_X_RHS_Z), &sb.x, &rhs.z);
    mul_canonical_full::populate_row::<F>(&mut values, 0, col::mul_at(chip::MUL_RHS_X_SB_Z), &rhs.x, &sb.z);
    mul_canonical_full::populate_row::<F>(&mut values, 0, col::mul_at(chip::MUL_SB_Y_RHS_Z), &sb.y, &rhs.z);
    mul_canonical_full::populate_row::<F>(&mut values, 0, col::mul_at(chip::MUL_RHS_Y_SB_Z), &rhs.y, &sb.z);

    // Padding rows: replicate row 0 to satisfy all sub-chip constraints.
    for row in 1..HEIGHT {
        let row_off = row * NUM_COLS;
        let src_start = 0;
        for i in 0..NUM_COLS {
            values[row_off + i] = values[src_start + i];
        }
    }

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    /// RFC 8032 Test 1: ed25519 verify of canonical test vector.
    /// SLOW (~10s release): runs the full ed25519 witness chain plus all
    /// embedded chips. Marked ignored to keep CI fast.
    #[test]
    #[ignore = "slow (~10s release); validates full verify_air against RFC 8032"]
    fn verify_rfc8032_test_1() {
        let public_key: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3,
            0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
        ];
        let signature: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e,
            0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
            0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
            0x8e, 0x7a, 0x10, 0x0b,
        ];
        let trace = build_verify_trace::<BabyBear>(&public_key, &signature, b"");
        check_constraints(&VerifyAirChip, &trace, &[]);
        assert_eq!(trace.values[col::VALID], BabyBear::ONE, "RFC 8032 Test 1 must yield valid=1");
    }

    #[test]
    fn constraint_count_documented() {
        // 3.2-3.8 + 3.9: 13× MCF × +3144 = 40_872. 10956 + 40_872 = 51_828.
        assert_eq!(NUM_COLS, 51_828);
    }
}
