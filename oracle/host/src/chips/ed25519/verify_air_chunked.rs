//! `ed25519::verify_air_chunked` — chunked-sound verify AIR (Etapa 3.10.3).
//!
//! Drop-in chunked variant de `VerifyAirChip`. Substitui:
//!   - 1× PointAddAirChip → PointAddAirChunkedChip
//!   - 4× MulCanonicalFullChip → MulCanonicalFullChunkedChip
//!
//! Wire format invariance preservada: PUBLIC_KEY/SIGNATURE/R_POINT/A_POINT/
//! SB/HA/RHS/CROSS_BASE/VALID nos mesmos offsets, todas as connection
//! constraints e PV bindings idênticas.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::chips::ed25519::point::ExtendedPoint;
use crate::chips::ed25519::point_add_air_chunked::{self, NUM_COLS as PA_COLS, PointAddAirChunkedChip};
use crate::chips::field25519::{
    Field25519Element, NUM_LIMBS,
    mul_canonical_full_chunked::{self, MulCanonicalFullChunkedChip, NUM_COLS as MC_COLS},
};

const POINT_LIMBS: usize = 4 * NUM_LIMBS;
const PUBLIC_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const NUM_CROSS: usize = 4;

pub mod col {
    use super::*;
    pub const PUBLIC_KEY: usize = 0;
    pub const SIGNATURE: usize = PUBLIC_KEY + PUBLIC_KEY_BYTES;
    pub const R_POINT: usize = SIGNATURE + SIGNATURE_BYTES;
    pub const A_POINT: usize = R_POINT + POINT_LIMBS;
    pub const SB: usize = A_POINT + POINT_LIMBS;
    pub const HA: usize = SB + POINT_LIMBS;
    pub const RHS: usize = HA + POINT_LIMBS;
    pub const CROSS_BASE: usize = RHS + POINT_LIMBS;
    pub const VALID: usize = CROSS_BASE + NUM_CROSS * NUM_LIMBS;
    pub const POINT_ADD_START: usize = VALID + 1;
    pub const MULS_BASE: usize = POINT_ADD_START + PA_COLS;
    pub const TOTAL: usize = MULS_BASE + NUM_CROSS * MC_COLS;

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

pub const NUM_BOUNDARY_LIMBS: usize = 4 * POINT_LIMBS;
pub const NUM_PUBLIC_VALUES: usize = PUBLIC_KEY_BYTES + SIGNATURE_BYTES + NUM_BOUNDARY_LIMBS;

pub mod chip {
    pub const MUL_SB_X_RHS_Z: usize = 0;
    pub const MUL_RHS_X_SB_Z: usize = 1;
    pub const MUL_SB_Y_RHS_Z: usize = 2;
    pub const MUL_RHS_Y_SB_Z: usize = 3;
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyAirChunkedChip;

impl<F: Field> BaseAir<F> for VerifyAirChunkedChip {
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

impl<AB: AirBuilder> Air<AB> for VerifyAirChunkedChip
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        PointAddAirChunkedChip::at(col::POINT_ADD_START).emit(builder);
        for i in 0..NUM_CROSS {
            MulCanonicalFullChunkedChip::at(col::mul_at(i)).emit(builder);
        }

        let main = builder.main();
        let row = main.current_slice();

        let pub_copies: [AB::PublicVar; NUM_PUBLIC_VALUES] = {
            let public = builder.public_values();
            core::array::from_fn(|i| public[i])
        };
        for i in 0..(PUBLIC_KEY_BYTES + SIGNATURE_BYTES) {
            builder.assert_eq(row[i], pub_copies[i]);
        }
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
        assert_chunks(builder, col::POINT_ADD_START + point_add_air_chunked::col::P1, col::R_POINT, POINT_LIMBS);
        assert_chunks(builder, col::POINT_ADD_START + point_add_air_chunked::col::P2, col::HA, POINT_LIMBS);
        assert_chunks(builder, col::POINT_ADD_START + point_add_air_chunked::col::P3, col::RHS, POINT_LIMBS);

        // sB.X · rhs.Z
        assert_chunks(
            builder,
            col::mul_at(chip::MUL_SB_X_RHS_Z) + mul_canonical_full_chunked::col::A,
            col::SB + col::X_OFF,
            NUM_LIMBS,
        );
        assert_chunks(
            builder,
            col::mul_at(chip::MUL_SB_X_RHS_Z) + mul_canonical_full_chunked::col::B,
            col::RHS + col::Z_OFF,
            NUM_LIMBS,
        );
        assert_chunks(
            builder,
            col::cross_at(chip::MUL_SB_X_RHS_Z),
            col::mul_at(chip::MUL_SB_X_RHS_Z) + mul_canonical_full_chunked::col::C,
            NUM_LIMBS,
        );

        // rhs.X · sB.Z
        assert_chunks(
            builder,
            col::mul_at(chip::MUL_RHS_X_SB_Z) + mul_canonical_full_chunked::col::A,
            col::RHS + col::X_OFF,
            NUM_LIMBS,
        );
        assert_chunks(
            builder,
            col::mul_at(chip::MUL_RHS_X_SB_Z) + mul_canonical_full_chunked::col::B,
            col::SB + col::Z_OFF,
            NUM_LIMBS,
        );
        assert_chunks(
            builder,
            col::cross_at(chip::MUL_RHS_X_SB_Z),
            col::mul_at(chip::MUL_RHS_X_SB_Z) + mul_canonical_full_chunked::col::C,
            NUM_LIMBS,
        );

        // sB.Y · rhs.Z
        assert_chunks(
            builder,
            col::mul_at(chip::MUL_SB_Y_RHS_Z) + mul_canonical_full_chunked::col::A,
            col::SB + col::Y_OFF,
            NUM_LIMBS,
        );
        assert_chunks(
            builder,
            col::mul_at(chip::MUL_SB_Y_RHS_Z) + mul_canonical_full_chunked::col::B,
            col::RHS + col::Z_OFF,
            NUM_LIMBS,
        );
        assert_chunks(
            builder,
            col::cross_at(chip::MUL_SB_Y_RHS_Z),
            col::mul_at(chip::MUL_SB_Y_RHS_Z) + mul_canonical_full_chunked::col::C,
            NUM_LIMBS,
        );

        // rhs.Y · sB.Z
        assert_chunks(
            builder,
            col::mul_at(chip::MUL_RHS_Y_SB_Z) + mul_canonical_full_chunked::col::A,
            col::RHS + col::Y_OFF,
            NUM_LIMBS,
        );
        assert_chunks(
            builder,
            col::mul_at(chip::MUL_RHS_Y_SB_Z) + mul_canonical_full_chunked::col::B,
            col::SB + col::Z_OFF,
            NUM_LIMBS,
        );
        assert_chunks(
            builder,
            col::cross_at(chip::MUL_RHS_Y_SB_Z),
            col::mul_at(chip::MUL_RHS_Y_SB_Z) + mul_canonical_full_chunked::col::C,
            NUM_LIMBS,
        );

        // Projective equality
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

pub fn build_verify_trace_chunked<F: Field + PrimeCharacteristicRing>(
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
    let rhs = point_add(&r_point, &ha);

    let sb_x_rhs_z = field_mul(&sb.x, &rhs.z);
    let rhs_x_sb_z = field_mul(&rhs.x, &sb.z);
    let sb_y_rhs_z = field_mul(&sb.y, &rhs.z);
    let rhs_y_sb_z = field_mul(&rhs.y, &sb.z);

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

    point_add_air_chunked::populate_row::<F>(&mut values, 0, col::POINT_ADD_START, &r_point, &ha);
    mul_canonical_full_chunked::populate_row::<F>(&mut values, 0, col::mul_at(chip::MUL_SB_X_RHS_Z), &sb.x, &rhs.z);
    mul_canonical_full_chunked::populate_row::<F>(&mut values, 0, col::mul_at(chip::MUL_RHS_X_SB_Z), &rhs.x, &sb.z);
    mul_canonical_full_chunked::populate_row::<F>(&mut values, 0, col::mul_at(chip::MUL_SB_Y_RHS_Z), &sb.y, &rhs.z);
    mul_canonical_full_chunked::populate_row::<F>(&mut values, 0, col::mul_at(chip::MUL_RHS_Y_SB_Z), &rhs.y, &sb.z);

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

    #[test]
    #[ignore = "slow (~30s release); validates full verify_air_chunked against RFC 8032"]
    fn verify_chunked_rfc8032_test_1() {
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
        let trace = build_verify_trace_chunked::<BabyBear>(&public_key, &signature, b"");
        let pv: Vec<BabyBear> = (0..NUM_PUBLIC_VALUES).map(|i| trace.values[i]).collect();
        check_constraints(&VerifyAirChunkedChip, &trace, &pv);
        assert_eq!(trace.values[col::VALID], BabyBear::ONE, "RFC 8032 Test 1 must yield valid=1");
    }

    #[test]
    fn layout_documented() {
        assert_eq!(col::PUBLIC_KEY, 0);
        assert_eq!(col::SIGNATURE, 32);
        assert_eq!(col::R_POINT, 96);
        assert_eq!(col::A_POINT, 132);
        assert_eq!(col::SB, 168);
        assert_eq!(col::HA, 204);
        assert_eq!(col::RHS, 240);
        assert_eq!(col::CROSS_BASE, 276);
        assert_eq!(col::VALID, 312);
        assert_eq!(col::POINT_ADD_START, 313);
        assert!(col::MULS_BASE > col::POINT_ADD_START);
        assert!(NUM_COLS > col::MULS_BASE);
    }
}
