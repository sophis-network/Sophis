//! `ed25519::decompress_air_chunked` — chunked-sound decompress AIR
//! (Etapa 3.10.3).
//!
//! Drop-in chunked variant de `DecompressAirChip`. Substitui os
//! sub-chips por chunked-sound variants:
//!   - 1× AddCanonicalChunkedChip
//!   - 1× SubCanonicalChunkedChip
//!   - 11× MulCanonicalFullChunkedChip
//!
//! Wire format invariance: BYTES/Y/Y2/.../X_OUT/T_OUT/Z_OUT/SIGN_BIT/
//! VALID nos mesmos offsets do DecompressAirChip original. Connection
//! constraints idênticas (substituição literal de tipos).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::chips::field25519::{
    Field25519Element, NUM_LIMBS,
    add_canonical_chunked::{self, AddCanonicalChunkedChip, NUM_COLS as ADC_COLS},
    mul_canonical_full_chunked::{self, MulCanonicalFullChunkedChip, NUM_COLS as MC_COLS},
    sub_canonical_chunked::{self, NUM_COLS as SC_COLS, SubCanonicalChunkedChip},
};

const NUM_MULS: usize = 11;

pub mod col {
    use super::*;
    pub const BYTES: usize = 0;
    pub const Y: usize = BYTES + 32;
    pub const Y2: usize = Y + NUM_LIMBS;
    pub const D_Y2: usize = Y2 + NUM_LIMBS;
    pub const U: usize = D_Y2 + NUM_LIMBS;
    pub const V: usize = U + NUM_LIMBS;
    pub const V2: usize = V + NUM_LIMBS;
    pub const V3: usize = V2 + NUM_LIMBS;
    pub const V4: usize = V3 + NUM_LIMBS;
    pub const V7: usize = V4 + NUM_LIMBS;
    pub const UV3: usize = V7 + NUM_LIMBS;
    pub const UV7: usize = UV3 + NUM_LIMBS;
    pub const POW_RESULT: usize = UV7 + NUM_LIMBS;
    pub const CAND_X: usize = POW_RESULT + NUM_LIMBS;
    pub const X_SQ: usize = CAND_X + NUM_LIMBS;
    pub const V_X2: usize = X_SQ + NUM_LIMBS;
    pub const D_CONST: usize = V_X2 + NUM_LIMBS;
    pub const ONE_CONST: usize = D_CONST + NUM_LIMBS;
    pub const X_OUT: usize = ONE_CONST + NUM_LIMBS;
    pub const T_OUT: usize = X_OUT + NUM_LIMBS;
    pub const Z_OUT: usize = T_OUT + NUM_LIMBS;
    pub const SIGN_BIT: usize = Z_OUT + NUM_LIMBS;
    pub const VALID: usize = SIGN_BIT + 1;

    pub const ADD_START: usize = VALID + 1;
    pub const SUB_START: usize = ADD_START + ADC_COLS;
    pub const MULS_BASE: usize = SUB_START + SC_COLS;
    pub const TOTAL: usize = MULS_BASE + NUM_MULS * MC_COLS;

    pub const fn mul_at(i: usize) -> usize {
        MULS_BASE + i * MC_COLS
    }
}

pub const NUM_COLS: usize = col::TOTAL;

pub const NUM_BOUNDARY_LIMBS: usize = 4 * NUM_LIMBS;
pub const NUM_PUBLIC_VALUES: usize = 32 + NUM_BOUNDARY_LIMBS + 1;

pub mod chip {
    pub const MUL_Y2: usize = 0;
    pub const MUL_D_Y2: usize = 1;
    pub const MUL_V2: usize = 2;
    pub const MUL_V3: usize = 3;
    pub const MUL_V4: usize = 4;
    pub const MUL_V7: usize = 5;
    pub const MUL_UV3: usize = 6;
    pub const MUL_UV7: usize = 7;
    pub const MUL_CAND: usize = 8;
    pub const MUL_X_SQ: usize = 9;
    pub const MUL_V_X2: usize = 10;
}

#[derive(Debug, Clone, Copy)]
pub struct DecompressAirChunkedChip;

fn one_limbs() -> [u64; NUM_LIMBS] {
    let mut o = [0u64; NUM_LIMBS];
    o[0] = 1;
    o
}

fn d_limbs() -> [u64; NUM_LIMBS] {
    use crate::chips::ed25519::point::d_constant;
    d_constant().limbs
}

impl<F: Field> BaseAir<F> for DecompressAirChunkedChip {
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

impl<AB: AirBuilder> Air<AB> for DecompressAirChunkedChip
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        AddCanonicalChunkedChip::at(col::ADD_START).emit(builder);
        SubCanonicalChunkedChip::at(col::SUB_START).emit(builder);
        for i in 0..NUM_MULS {
            MulCanonicalFullChunkedChip::at(col::mul_at(i)).emit(builder);
        }

        let main = builder.main();
        let row = main.current_slice();

        let one = one_limbs();
        let d = d_limbs();
        for i in 0..NUM_LIMBS {
            builder.assert_eq(row[col::ONE_CONST + i], AB::Expr::from_u64(one[i]));
            builder.assert_eq(row[col::D_CONST + i], AB::Expr::from_u64(d[i]));
            builder.assert_eq(row[col::Z_OUT + i], AB::Expr::from_u64(one[i]));
        }
        builder.assert_bool(row[col::SIGN_BIT]);
        builder.assert_bool(row[col::VALID]);

        let assert_chunks = |b: &mut AB, off_a: usize, off_b: usize| {
            for i in 0..NUM_LIMBS {
                b.assert_eq(row[off_a + i], row[off_b + i]);
            }
        };

        // y² = y · y
        assert_chunks(builder, col::mul_at(chip::MUL_Y2) + mul_canonical_full_chunked::col::A, col::Y);
        assert_chunks(builder, col::mul_at(chip::MUL_Y2) + mul_canonical_full_chunked::col::B, col::Y);
        assert_chunks(builder, col::Y2, col::mul_at(chip::MUL_Y2) + mul_canonical_full_chunked::col::C);

        // d·y²
        assert_chunks(builder, col::mul_at(chip::MUL_D_Y2) + mul_canonical_full_chunked::col::A, col::D_CONST);
        assert_chunks(builder, col::mul_at(chip::MUL_D_Y2) + mul_canonical_full_chunked::col::B, col::Y2);
        assert_chunks(builder, col::D_Y2, col::mul_at(chip::MUL_D_Y2) + mul_canonical_full_chunked::col::C);

        // u = y² - 1
        assert_chunks(builder, col::SUB_START + sub_canonical_chunked::col::A, col::Y2);
        assert_chunks(builder, col::SUB_START + sub_canonical_chunked::col::B, col::ONE_CONST);
        assert_chunks(builder, col::U, col::SUB_START + sub_canonical_chunked::col::C);

        // v = d·y² + 1
        assert_chunks(builder, col::ADD_START + add_canonical_chunked::col::A, col::D_Y2);
        assert_chunks(builder, col::ADD_START + add_canonical_chunked::col::B, col::ONE_CONST);
        assert_chunks(builder, col::V, col::ADD_START + add_canonical_chunked::col::C);

        // v²
        assert_chunks(builder, col::mul_at(chip::MUL_V2) + mul_canonical_full_chunked::col::A, col::V);
        assert_chunks(builder, col::mul_at(chip::MUL_V2) + mul_canonical_full_chunked::col::B, col::V);
        assert_chunks(builder, col::V2, col::mul_at(chip::MUL_V2) + mul_canonical_full_chunked::col::C);

        // v³
        assert_chunks(builder, col::mul_at(chip::MUL_V3) + mul_canonical_full_chunked::col::A, col::V2);
        assert_chunks(builder, col::mul_at(chip::MUL_V3) + mul_canonical_full_chunked::col::B, col::V);
        assert_chunks(builder, col::V3, col::mul_at(chip::MUL_V3) + mul_canonical_full_chunked::col::C);

        // v⁴
        assert_chunks(builder, col::mul_at(chip::MUL_V4) + mul_canonical_full_chunked::col::A, col::V2);
        assert_chunks(builder, col::mul_at(chip::MUL_V4) + mul_canonical_full_chunked::col::B, col::V2);
        assert_chunks(builder, col::V4, col::mul_at(chip::MUL_V4) + mul_canonical_full_chunked::col::C);

        // v⁷
        assert_chunks(builder, col::mul_at(chip::MUL_V7) + mul_canonical_full_chunked::col::A, col::V4);
        assert_chunks(builder, col::mul_at(chip::MUL_V7) + mul_canonical_full_chunked::col::B, col::V3);
        assert_chunks(builder, col::V7, col::mul_at(chip::MUL_V7) + mul_canonical_full_chunked::col::C);

        // u·v³
        assert_chunks(builder, col::mul_at(chip::MUL_UV3) + mul_canonical_full_chunked::col::A, col::U);
        assert_chunks(builder, col::mul_at(chip::MUL_UV3) + mul_canonical_full_chunked::col::B, col::V3);
        assert_chunks(builder, col::UV3, col::mul_at(chip::MUL_UV3) + mul_canonical_full_chunked::col::C);

        // u·v⁷
        assert_chunks(builder, col::mul_at(chip::MUL_UV7) + mul_canonical_full_chunked::col::A, col::U);
        assert_chunks(builder, col::mul_at(chip::MUL_UV7) + mul_canonical_full_chunked::col::B, col::V7);
        assert_chunks(builder, col::UV7, col::mul_at(chip::MUL_UV7) + mul_canonical_full_chunked::col::C);

        // candidate_x
        assert_chunks(builder, col::mul_at(chip::MUL_CAND) + mul_canonical_full_chunked::col::A, col::UV3);
        assert_chunks(builder, col::mul_at(chip::MUL_CAND) + mul_canonical_full_chunked::col::B, col::POW_RESULT);
        assert_chunks(builder, col::CAND_X, col::mul_at(chip::MUL_CAND) + mul_canonical_full_chunked::col::C);

        // x_sq
        assert_chunks(builder, col::mul_at(chip::MUL_X_SQ) + mul_canonical_full_chunked::col::A, col::CAND_X);
        assert_chunks(builder, col::mul_at(chip::MUL_X_SQ) + mul_canonical_full_chunked::col::B, col::CAND_X);
        assert_chunks(builder, col::X_SQ, col::mul_at(chip::MUL_X_SQ) + mul_canonical_full_chunked::col::C);

        // v_x2
        assert_chunks(builder, col::mul_at(chip::MUL_V_X2) + mul_canonical_full_chunked::col::A, col::V);
        assert_chunks(builder, col::mul_at(chip::MUL_V_X2) + mul_canonical_full_chunked::col::B, col::X_SQ);
        assert_chunks(builder, col::V_X2, col::mul_at(chip::MUL_V_X2) + mul_canonical_full_chunked::col::C);

        // ===== Boundary binding for STARK public values =====
        let pub_copies: [AB::PublicVar; NUM_PUBLIC_VALUES] = {
            let public = builder.public_values();
            core::array::from_fn(|i| public[i])
        };
        for i in 0..32 {
            builder.assert_eq(row[col::BYTES + i], pub_copies[i]);
        }
        for i in 0..NUM_LIMBS {
            builder.assert_eq(row[col::X_OUT + i], pub_copies[32 + i]);
        }
        for i in 0..NUM_LIMBS {
            builder.assert_eq(row[col::Y + i], pub_copies[32 + NUM_LIMBS + i]);
        }
        for i in 0..NUM_LIMBS {
            builder.assert_eq(row[col::Z_OUT + i], pub_copies[32 + 2 * NUM_LIMBS + i]);
        }
        for i in 0..NUM_LIMBS {
            builder.assert_eq(row[col::T_OUT + i], pub_copies[32 + 3 * NUM_LIMBS + i]);
        }
        builder.assert_eq(row[col::VALID], pub_copies[32 + NUM_BOUNDARY_LIMBS]);
    }
}

pub fn populate_row<F: Field + PrimeCharacteristicRing>(values: &mut [F], row_off: usize, compressed: &[u8; 32]) {
    use crate::chips::ed25519::decompress::decompress;
    use crate::chips::field25519::arith::{field_add, field_mul, field_sub};

    let one = Field25519Element { limbs: one_limbs() };
    let d = Field25519Element { limbs: d_limbs() };

    let y = Field25519Element::from_canonical_bytes(compressed);
    let sign_bit = (compressed[31] >> 7) & 1;

    let y2 = field_mul(&y, &y);
    let d_y2 = field_mul(&d, &y2);
    let u = field_sub(&y2, &one);
    let v = field_add(&d_y2, &one);
    let v2 = field_mul(&v, &v);
    let v3 = field_mul(&v2, &v);
    let v4 = field_mul(&v2, &v2);
    let v7 = field_mul(&v4, &v3);
    let uv3 = field_mul(&u, &v3);
    let uv7 = field_mul(&u, &v7);

    use crate::chips::ed25519::decompress::{P_MINUS_5_OVER_8, field_pow};
    let pow_result = field_pow(&uv7, &P_MINUS_5_OVER_8);

    let cand_x = field_mul(&uv3, &pow_result);
    let x_sq = field_mul(&cand_x, &cand_x);
    let v_x2 = field_mul(&v, &x_sq);

    let result = decompress(compressed);
    let (final_x, final_t, valid) = match result {
        Some(point) => (point.x, point.t, 1u8),
        None => (Field25519Element::ZERO, Field25519Element::ZERO, 0u8),
    };

    let put_field = |values: &mut [F], off: usize, e: &Field25519Element| {
        for i in 0..NUM_LIMBS {
            values[off + i] = F::from_u64(e.limbs[i]);
        }
    };
    let base = row_off;

    for i in 0..32 {
        values[base + col::BYTES + i] = F::from_u64(compressed[i] as u64);
    }
    put_field(values, base + col::Y, &y);
    put_field(values, base + col::Y2, &y2);
    put_field(values, base + col::D_Y2, &d_y2);
    put_field(values, base + col::U, &u);
    put_field(values, base + col::V, &v);
    put_field(values, base + col::V2, &v2);
    put_field(values, base + col::V3, &v3);
    put_field(values, base + col::V4, &v4);
    put_field(values, base + col::V7, &v7);
    put_field(values, base + col::UV3, &uv3);
    put_field(values, base + col::UV7, &uv7);
    put_field(values, base + col::POW_RESULT, &pow_result);
    put_field(values, base + col::CAND_X, &cand_x);
    put_field(values, base + col::X_SQ, &x_sq);
    put_field(values, base + col::V_X2, &v_x2);
    put_field(values, base + col::D_CONST, &d);
    put_field(values, base + col::ONE_CONST, &one);
    put_field(values, base + col::X_OUT, &final_x);
    put_field(values, base + col::T_OUT, &final_t);
    put_field(values, base + col::Z_OUT, &one);
    values[base + col::SIGN_BIT] = F::from_u64(sign_bit as u64);
    values[base + col::VALID] = F::from_u64(valid as u64);

    add_canonical_chunked::populate_row::<F>(values, row_off, col::ADD_START, &d_y2, &one);
    sub_canonical_chunked::populate_row::<F>(values, row_off, col::SUB_START, &y2, &one);
    mul_canonical_full_chunked::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_Y2), &y, &y);
    mul_canonical_full_chunked::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_D_Y2), &d, &y2);
    mul_canonical_full_chunked::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_V2), &v, &v);
    mul_canonical_full_chunked::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_V3), &v2, &v);
    mul_canonical_full_chunked::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_V4), &v2, &v2);
    mul_canonical_full_chunked::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_V7), &v4, &v3);
    mul_canonical_full_chunked::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_UV3), &u, &v3);
    mul_canonical_full_chunked::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_UV7), &u, &v7);
    mul_canonical_full_chunked::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_CAND), &uv3, &pow_result);
    mul_canonical_full_chunked::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_X_SQ), &cand_x, &cand_x);
    mul_canonical_full_chunked::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_V_X2), &v, &x_sq);
}

pub fn build_decompress_trace_chunked<F: Field + PrimeCharacteristicRing>(compressed: &[u8; 32]) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    for row in 0..HEIGHT {
        populate_row::<F>(&mut values, row * NUM_COLS, compressed);
    }

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    fn pv_for<F: p3_field::Field + p3_field::PrimeCharacteristicRing>(compressed: &[u8; 32]) -> Vec<F> {
        use crate::chips::ed25519::decompress::decompress;
        let (point, valid) = match decompress(compressed) {
            Some(p) => (p, 1u64),
            None => (
                crate::chips::ed25519::point::ExtendedPoint {
                    x: Field25519Element::ZERO,
                    y: Field25519Element::from_canonical_bytes(compressed),
                    z: Field25519Element {
                        limbs: {
                            let mut o = [0u64; NUM_LIMBS];
                            o[0] = 1;
                            o
                        },
                    },
                    t: Field25519Element::ZERO,
                },
                0u64,
            ),
        };
        let mut out = Vec::with_capacity(NUM_PUBLIC_VALUES);
        for &b in compressed {
            out.push(F::from_u64(b as u64));
        }
        for &l in &point.x.limbs {
            out.push(F::from_u64(l));
        }
        for &l in &point.y.limbs {
            out.push(F::from_u64(l));
        }
        for &l in &point.z.limbs {
            out.push(F::from_u64(l));
        }
        for &l in &point.t.limbs {
            out.push(F::from_u64(l));
        }
        out.push(F::from_u64(valid));
        out
    }

    #[test]
    fn decompress_chunked_basepoint() {
        let mut compressed = [0x66u8; 32];
        compressed[0] = 0x58;
        let trace = build_decompress_trace_chunked::<BabyBear>(&compressed);
        let pv = pv_for::<BabyBear>(&compressed);
        check_constraints(&DecompressAirChunkedChip, &trace, &pv);
    }

    #[test]
    fn decompress_chunked_neutral_element() {
        let mut compressed = [0u8; 32];
        compressed[0] = 1;
        let trace = build_decompress_trace_chunked::<BabyBear>(&compressed);
        let pv = pv_for::<BabyBear>(&compressed);
        check_constraints(&DecompressAirChunkedChip, &trace, &pv);
    }

    #[test]
    fn layout_documented() {
        assert_eq!(col::BYTES, 0);
        assert_eq!(col::Y, 32);
        assert_eq!(col::ADD_START, 214);
        assert!(col::SUB_START > col::ADD_START);
        assert!(col::MULS_BASE > col::SUB_START);
        assert!(NUM_COLS > col::MULS_BASE);
    }
}
