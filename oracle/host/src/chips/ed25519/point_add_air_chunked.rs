//! `ed25519::point_add_air_chunked` — chunked-sound point addition AIR
//! (Etapa 3.10.3).
//!
//! Drop-in replacement de `PointAddAirChip` usando os chunked-sound
//! sub-chips. Wire format invariance preservada (P1/P2/P3/TWO_D nos
//! mesmos offsets) → composers downstream (verify_air, scalar_mul_air)
//! podem trocar PointAddAirChip → PointAddAirChunkedChip via simples
//! ajuste de NUM_COLS.
//!
//! Sub-chips:
//!   - 5 × AddCanonicalChunkedChip
//!   - 4 × SubCanonicalChunkedChip
//!   - 9 × MulCanonicalFullChunkedChip
//!
//! Layout: P1 + P2 + P3 + TWO_D = 117 cols + 5·1503 + 4·1809 +
//! 9·~9430 = ~99540 cols (vs 7803 do PointAddAirChip não-chunked).
//! O custo extra reflete o range checking exhaustivo necessário pra
//! fechar BB-wrap structurally — preço da soundness pre-mainnet.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::chips::field25519::{
    Field25519Element, NUM_LIMBS,
    add_canonical_chunked::{self, AddCanonicalChunkedChip, NUM_COLS as ADC_COLS},
    mul_canonical_full_chunked::{self, MulCanonicalFullChunkedChip, NUM_COLS as MC_COLS},
    sub_canonical_chunked::{self, NUM_COLS as SC_COLS, SubCanonicalChunkedChip},
};

const POINT_LIMBS: usize = 4 * NUM_LIMBS; // 36

const NUM_ADDS: usize = 5;
const NUM_SUBS: usize = 4;
const NUM_MULS: usize = 9;

pub mod col {
    use super::*;
    pub const P1: usize = 0;
    pub const P2: usize = P1 + POINT_LIMBS; // 36
    pub const P3: usize = P2 + POINT_LIMBS; // 72
    pub const TWO_D: usize = P3 + POINT_LIMBS; // 108

    pub const ADDS_BASE: usize = TWO_D + NUM_LIMBS; // 117
    pub const SUBS_BASE: usize = ADDS_BASE + NUM_ADDS * ADC_COLS;
    pub const MULS_BASE: usize = SUBS_BASE + NUM_SUBS * SC_COLS;

    pub const TOTAL: usize = MULS_BASE + NUM_MULS * MC_COLS;

    pub const fn add_at(i: usize) -> usize {
        ADDS_BASE + i * ADC_COLS
    }
    pub const fn sub_at(i: usize) -> usize {
        SUBS_BASE + i * SC_COLS
    }
    pub const fn mul_at(i: usize) -> usize {
        MULS_BASE + i * MC_COLS
    }

    // Within-point limb offsets.
    pub const X_OFF: usize = 0;
    pub const Y_OFF: usize = NUM_LIMBS;
    pub const Z_OFF: usize = 2 * NUM_LIMBS;
    pub const T_OFF: usize = 3 * NUM_LIMBS;
}

pub const NUM_COLS: usize = col::TOTAL;

/// Sub-chip indices (matching `PointAddAirChip::chip`).
pub mod chip {
    pub const ADD_YX1: usize = 0;
    pub const ADD_YX2: usize = 1;
    pub const ADD_ZZ: usize = 2;
    pub const ADD_G: usize = 3;
    pub const ADD_H: usize = 4;

    pub const SUB_YX1: usize = 0;
    pub const SUB_YX2: usize = 1;
    pub const SUB_E: usize = 2;
    pub const SUB_F: usize = 3;

    pub const MUL_A: usize = 0;
    pub const MUL_B: usize = 1;
    pub const MUL_T1_2D: usize = 2;
    pub const MUL_C: usize = 3;
    pub const MUL_D: usize = 4;
    pub const MUL_X3: usize = 5;
    pub const MUL_Y3: usize = 6;
    pub const MUL_T3: usize = 7;
    pub const MUL_Z3: usize = 8;
}

/// 2d mod p in 9-limb canonical form.
pub fn two_d_limbs() -> [u64; NUM_LIMBS] {
    use crate::chips::ed25519::point::two_d_constant;
    two_d_constant().limbs
}

#[derive(Debug, Clone, Copy)]
pub struct PointAddAirChunkedChip {
    pub start_col: usize,
}

impl Default for PointAddAirChunkedChip {
    fn default() -> Self {
        Self::new()
    }
}

impl PointAddAirChunkedChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let s = self.start_col;
        for i in 0..NUM_ADDS {
            AddCanonicalChunkedChip::at(s + col::add_at(i)).emit(builder);
        }
        for i in 0..NUM_SUBS {
            SubCanonicalChunkedChip::at(s + col::sub_at(i)).emit(builder);
        }
        for i in 0..NUM_MULS {
            MulCanonicalFullChunkedChip::at(s + col::mul_at(i)).emit(builder);
        }

        let main = builder.main();
        let row = main.current_slice();

        // Boundary: TWO_D limbs equal the constant.
        let two_d = two_d_limbs();
        for i in 0..NUM_LIMBS {
            builder.assert_eq(row[s + col::TWO_D + i], AB::Expr::from_u64(two_d[i]));
        }

        let assert_chunks = |b: &mut AB, off_a: usize, off_b: usize| {
            for i in 0..NUM_LIMBS {
                b.assert_eq(row[off_a + i], row[off_b + i]);
            }
        };

        // ===== Connection constraints (idênticas ao PointAddAirChip) =====
        // ADD_YX1: (Y1 + X1)
        assert_chunks(builder, s + col::add_at(chip::ADD_YX1) + add_canonical_chunked::col::A, s + col::P1 + col::Y_OFF);
        assert_chunks(builder, s + col::add_at(chip::ADD_YX1) + add_canonical_chunked::col::B, s + col::P1 + col::X_OFF);
        // ADD_YX2: (Y2 + X2)
        assert_chunks(builder, s + col::add_at(chip::ADD_YX2) + add_canonical_chunked::col::A, s + col::P2 + col::Y_OFF);
        assert_chunks(builder, s + col::add_at(chip::ADD_YX2) + add_canonical_chunked::col::B, s + col::P2 + col::X_OFF);
        // ADD_ZZ: (Z1 + Z1)
        assert_chunks(builder, s + col::add_at(chip::ADD_ZZ) + add_canonical_chunked::col::A, s + col::P1 + col::Z_OFF);
        assert_chunks(builder, s + col::add_at(chip::ADD_ZZ) + add_canonical_chunked::col::B, s + col::P1 + col::Z_OFF);

        // SUB_YX1: (Y1 - X1)
        assert_chunks(builder, s + col::sub_at(chip::SUB_YX1) + sub_canonical_chunked::col::A, s + col::P1 + col::Y_OFF);
        assert_chunks(builder, s + col::sub_at(chip::SUB_YX1) + sub_canonical_chunked::col::B, s + col::P1 + col::X_OFF);
        // SUB_YX2: (Y2 - X2)
        assert_chunks(builder, s + col::sub_at(chip::SUB_YX2) + sub_canonical_chunked::col::A, s + col::P2 + col::Y_OFF);
        assert_chunks(builder, s + col::sub_at(chip::SUB_YX2) + sub_canonical_chunked::col::B, s + col::P2 + col::X_OFF);

        // MUL_A: (Y1-X1) · (Y2-X2)
        assert_chunks(
            builder,
            s + col::mul_at(chip::MUL_A) + mul_canonical_full_chunked::col::A,
            s + col::sub_at(chip::SUB_YX1) + sub_canonical_chunked::col::C,
        );
        assert_chunks(
            builder,
            s + col::mul_at(chip::MUL_A) + mul_canonical_full_chunked::col::B,
            s + col::sub_at(chip::SUB_YX2) + sub_canonical_chunked::col::C,
        );
        // MUL_B: (Y1+X1) · (Y2+X2)
        assert_chunks(
            builder,
            s + col::mul_at(chip::MUL_B) + mul_canonical_full_chunked::col::A,
            s + col::add_at(chip::ADD_YX1) + add_canonical_chunked::col::C,
        );
        assert_chunks(
            builder,
            s + col::mul_at(chip::MUL_B) + mul_canonical_full_chunked::col::B,
            s + col::add_at(chip::ADD_YX2) + add_canonical_chunked::col::C,
        );
        // MUL_T1_2D: T1 · 2d
        assert_chunks(builder, s + col::mul_at(chip::MUL_T1_2D) + mul_canonical_full_chunked::col::A, s + col::P1 + col::T_OFF);
        assert_chunks(builder, s + col::mul_at(chip::MUL_T1_2D) + mul_canonical_full_chunked::col::B, s + col::TWO_D);
        // MUL_C: (T1·2d) · T2
        assert_chunks(
            builder,
            s + col::mul_at(chip::MUL_C) + mul_canonical_full_chunked::col::A,
            s + col::mul_at(chip::MUL_T1_2D) + mul_canonical_full_chunked::col::C,
        );
        assert_chunks(builder, s + col::mul_at(chip::MUL_C) + mul_canonical_full_chunked::col::B, s + col::P2 + col::T_OFF);
        // MUL_D: (Z1+Z1) · Z2
        assert_chunks(
            builder,
            s + col::mul_at(chip::MUL_D) + mul_canonical_full_chunked::col::A,
            s + col::add_at(chip::ADD_ZZ) + add_canonical_chunked::col::C,
        );
        assert_chunks(builder, s + col::mul_at(chip::MUL_D) + mul_canonical_full_chunked::col::B, s + col::P2 + col::Z_OFF);

        // SUB_E: B - A
        assert_chunks(
            builder,
            s + col::sub_at(chip::SUB_E) + sub_canonical_chunked::col::A,
            s + col::mul_at(chip::MUL_B) + mul_canonical_full_chunked::col::C,
        );
        assert_chunks(
            builder,
            s + col::sub_at(chip::SUB_E) + sub_canonical_chunked::col::B,
            s + col::mul_at(chip::MUL_A) + mul_canonical_full_chunked::col::C,
        );
        // SUB_F: D - C
        assert_chunks(
            builder,
            s + col::sub_at(chip::SUB_F) + sub_canonical_chunked::col::A,
            s + col::mul_at(chip::MUL_D) + mul_canonical_full_chunked::col::C,
        );
        assert_chunks(
            builder,
            s + col::sub_at(chip::SUB_F) + sub_canonical_chunked::col::B,
            s + col::mul_at(chip::MUL_C) + mul_canonical_full_chunked::col::C,
        );
        // ADD_G: D + C
        assert_chunks(
            builder,
            s + col::add_at(chip::ADD_G) + add_canonical_chunked::col::A,
            s + col::mul_at(chip::MUL_D) + mul_canonical_full_chunked::col::C,
        );
        assert_chunks(
            builder,
            s + col::add_at(chip::ADD_G) + add_canonical_chunked::col::B,
            s + col::mul_at(chip::MUL_C) + mul_canonical_full_chunked::col::C,
        );
        // ADD_H: B + A
        assert_chunks(
            builder,
            s + col::add_at(chip::ADD_H) + add_canonical_chunked::col::A,
            s + col::mul_at(chip::MUL_B) + mul_canonical_full_chunked::col::C,
        );
        assert_chunks(
            builder,
            s + col::add_at(chip::ADD_H) + add_canonical_chunked::col::B,
            s + col::mul_at(chip::MUL_A) + mul_canonical_full_chunked::col::C,
        );

        // MUL_X3: E · F
        assert_chunks(
            builder,
            s + col::mul_at(chip::MUL_X3) + mul_canonical_full_chunked::col::A,
            s + col::sub_at(chip::SUB_E) + sub_canonical_chunked::col::C,
        );
        assert_chunks(
            builder,
            s + col::mul_at(chip::MUL_X3) + mul_canonical_full_chunked::col::B,
            s + col::sub_at(chip::SUB_F) + sub_canonical_chunked::col::C,
        );
        // MUL_Y3: G · H
        assert_chunks(
            builder,
            s + col::mul_at(chip::MUL_Y3) + mul_canonical_full_chunked::col::A,
            s + col::add_at(chip::ADD_G) + add_canonical_chunked::col::C,
        );
        assert_chunks(
            builder,
            s + col::mul_at(chip::MUL_Y3) + mul_canonical_full_chunked::col::B,
            s + col::add_at(chip::ADD_H) + add_canonical_chunked::col::C,
        );
        // MUL_T3: E · H
        assert_chunks(
            builder,
            s + col::mul_at(chip::MUL_T3) + mul_canonical_full_chunked::col::A,
            s + col::sub_at(chip::SUB_E) + sub_canonical_chunked::col::C,
        );
        assert_chunks(
            builder,
            s + col::mul_at(chip::MUL_T3) + mul_canonical_full_chunked::col::B,
            s + col::add_at(chip::ADD_H) + add_canonical_chunked::col::C,
        );
        // MUL_Z3: F · G
        assert_chunks(
            builder,
            s + col::mul_at(chip::MUL_Z3) + mul_canonical_full_chunked::col::A,
            s + col::sub_at(chip::SUB_F) + sub_canonical_chunked::col::C,
        );
        assert_chunks(
            builder,
            s + col::mul_at(chip::MUL_Z3) + mul_canonical_full_chunked::col::B,
            s + col::add_at(chip::ADD_G) + add_canonical_chunked::col::C,
        );

        // P3 outputs ← MUL_{X3,Y3,T3,Z3}.C
        assert_chunks(builder, s + col::P3 + col::X_OFF, s + col::mul_at(chip::MUL_X3) + mul_canonical_full_chunked::col::C);
        assert_chunks(builder, s + col::P3 + col::Y_OFF, s + col::mul_at(chip::MUL_Y3) + mul_canonical_full_chunked::col::C);
        assert_chunks(builder, s + col::P3 + col::T_OFF, s + col::mul_at(chip::MUL_T3) + mul_canonical_full_chunked::col::C);
        assert_chunks(builder, s + col::P3 + col::Z_OFF, s + col::mul_at(chip::MUL_Z3) + mul_canonical_full_chunked::col::C);
    }
}

impl<F: Field> BaseAir<F> for PointAddAirChunkedChip {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for PointAddAirChunkedChip
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        self.emit(builder);
    }
}

/// Populate one row at `(row_off, start_col)` for two input points.
pub fn populate_row<F: Field + PrimeCharacteristicRing>(
    values: &mut [F],
    row_off: usize,
    start_col: usize,
    p1: &super::point::ExtendedPoint,
    p2: &super::point::ExtendedPoint,
) {
    use crate::chips::field25519::arith::{field_add, field_mul, field_sub};

    let two_d = Field25519Element { limbs: two_d_limbs() };
    let base = row_off + start_col;

    let put_field = |values: &mut [F], off: usize, e: &Field25519Element| {
        for i in 0..NUM_LIMBS {
            values[off + i] = F::from_u64(e.limbs[i]);
        }
    };
    put_field(values, base + col::P1 + col::X_OFF, &p1.x);
    put_field(values, base + col::P1 + col::Y_OFF, &p1.y);
    put_field(values, base + col::P1 + col::Z_OFF, &p1.z);
    put_field(values, base + col::P1 + col::T_OFF, &p1.t);
    put_field(values, base + col::P2 + col::X_OFF, &p2.x);
    put_field(values, base + col::P2 + col::Y_OFF, &p2.y);
    put_field(values, base + col::P2 + col::Z_OFF, &p2.z);
    put_field(values, base + col::P2 + col::T_OFF, &p2.t);
    put_field(values, base + col::TWO_D, &two_d);

    let yx1_sum = field_add(&p1.y, &p1.x);
    let yx2_sum = field_add(&p2.y, &p2.x);
    let zz_sum = field_add(&p1.z, &p1.z);
    let yx1_diff = field_sub(&p1.y, &p1.x);
    let yx2_diff = field_sub(&p2.y, &p2.x);

    let a_val = field_mul(&yx1_diff, &yx2_diff);
    let b_val = field_mul(&yx1_sum, &yx2_sum);
    let t1_2d = field_mul(&p1.t, &two_d);
    let c_val = field_mul(&t1_2d, &p2.t);
    let d_val = field_mul(&zz_sum, &p2.z);

    let e_val = field_sub(&b_val, &a_val);
    let f_val = field_sub(&d_val, &c_val);
    let g_val = field_add(&d_val, &c_val);
    let h_val = field_add(&b_val, &a_val);

    let x3 = field_mul(&e_val, &f_val);
    let y3 = field_mul(&g_val, &h_val);
    let t3 = field_mul(&e_val, &h_val);
    let z3 = field_mul(&f_val, &g_val);

    // Sub-chips chunked variants.
    add_canonical_chunked::populate_row::<F>(values, row_off, start_col + col::add_at(chip::ADD_YX1), &p1.y, &p1.x);
    add_canonical_chunked::populate_row::<F>(values, row_off, start_col + col::add_at(chip::ADD_YX2), &p2.y, &p2.x);
    add_canonical_chunked::populate_row::<F>(values, row_off, start_col + col::add_at(chip::ADD_ZZ), &p1.z, &p1.z);
    add_canonical_chunked::populate_row::<F>(values, row_off, start_col + col::add_at(chip::ADD_G), &d_val, &c_val);
    add_canonical_chunked::populate_row::<F>(values, row_off, start_col + col::add_at(chip::ADD_H), &b_val, &a_val);

    sub_canonical_chunked::populate_row::<F>(values, row_off, start_col + col::sub_at(chip::SUB_YX1), &p1.y, &p1.x);
    sub_canonical_chunked::populate_row::<F>(values, row_off, start_col + col::sub_at(chip::SUB_YX2), &p2.y, &p2.x);
    sub_canonical_chunked::populate_row::<F>(values, row_off, start_col + col::sub_at(chip::SUB_E), &b_val, &a_val);
    sub_canonical_chunked::populate_row::<F>(values, row_off, start_col + col::sub_at(chip::SUB_F), &d_val, &c_val);

    mul_canonical_full_chunked::populate_row::<F>(values, row_off, start_col + col::mul_at(chip::MUL_A), &yx1_diff, &yx2_diff);
    mul_canonical_full_chunked::populate_row::<F>(values, row_off, start_col + col::mul_at(chip::MUL_B), &yx1_sum, &yx2_sum);
    mul_canonical_full_chunked::populate_row::<F>(values, row_off, start_col + col::mul_at(chip::MUL_T1_2D), &p1.t, &two_d);
    mul_canonical_full_chunked::populate_row::<F>(values, row_off, start_col + col::mul_at(chip::MUL_C), &t1_2d, &p2.t);
    mul_canonical_full_chunked::populate_row::<F>(values, row_off, start_col + col::mul_at(chip::MUL_D), &zz_sum, &p2.z);
    mul_canonical_full_chunked::populate_row::<F>(values, row_off, start_col + col::mul_at(chip::MUL_X3), &e_val, &f_val);
    mul_canonical_full_chunked::populate_row::<F>(values, row_off, start_col + col::mul_at(chip::MUL_Y3), &g_val, &h_val);
    mul_canonical_full_chunked::populate_row::<F>(values, row_off, start_col + col::mul_at(chip::MUL_T3), &e_val, &h_val);
    mul_canonical_full_chunked::populate_row::<F>(values, row_off, start_col + col::mul_at(chip::MUL_Z3), &f_val, &g_val);

    put_field(values, base + col::P3 + col::X_OFF, &x3);
    put_field(values, base + col::P3 + col::Y_OFF, &y3);
    put_field(values, base + col::P3 + col::Z_OFF, &z3);
    put_field(values, base + col::P3 + col::T_OFF, &t3);
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(
    p1: &super::point::ExtendedPoint,
    p2: &super::point::ExtendedPoint,
) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    let neutral = super::point::ExtendedPoint::neutral();
    for row in 0..HEIGHT {
        populate_row::<F>(&mut values, row * NUM_COLS, 0, &neutral, &neutral);
    }
    populate_row::<F>(&mut values, 0, 0, p1, p2);

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::super::point::{ExtendedPoint, point_add};
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeField32;

    fn read_p3(values: &[BabyBear]) -> ExtendedPoint {
        let read = |off: usize| {
            let mut limbs = [0u64; NUM_LIMBS];
            for i in 0..NUM_LIMBS {
                limbs[i] = values[off + i].as_canonical_u32() as u64;
            }
            Field25519Element { limbs }
        };
        ExtendedPoint {
            x: read(col::P3 + col::X_OFF),
            y: read(col::P3 + col::Y_OFF),
            z: read(col::P3 + col::Z_OFF),
            t: read(col::P3 + col::T_OFF),
        }
    }

    #[test]
    fn point_add_chunked_neutral_plus_neutral() {
        let neutral = ExtendedPoint::neutral();
        let trace = build_test_trace::<BabyBear>(&neutral, &neutral);
        check_constraints(&PointAddAirChunkedChip::new(), &trace, &[]);
        let result = read_p3(&trace.values);
        let expected = point_add(&neutral, &neutral);
        assert_eq!(result, expected);
    }

    #[test]
    fn point_add_chunked_basepoint_plus_neutral() {
        use super::super::decompress::decompress;
        let mut basepoint_compressed = [0x66u8; 32];
        basepoint_compressed[0] = 0x58;
        let basepoint = decompress(&basepoint_compressed).expect("basepoint must decompress");
        let neutral = ExtendedPoint::neutral();

        let trace = build_test_trace::<BabyBear>(&basepoint, &neutral);
        check_constraints(&PointAddAirChunkedChip::new(), &trace, &[]);
        let expected = point_add(&basepoint, &neutral);
        assert_eq!(read_p3(&trace.values), expected);
    }

    #[test]
    fn point_add_chunked_basepoint_doubling() {
        use super::super::decompress::decompress;
        let mut basepoint_compressed = [0x66u8; 32];
        basepoint_compressed[0] = 0x58;
        let basepoint = decompress(&basepoint_compressed).expect("basepoint must decompress");

        let trace = build_test_trace::<BabyBear>(&basepoint, &basepoint);
        check_constraints(&PointAddAirChunkedChip::new(), &trace, &[]);
        let expected = point_add(&basepoint, &basepoint);
        assert_eq!(read_p3(&trace.values), expected);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn point_add_chunked_rejects_tampered_output() {
        let neutral = ExtendedPoint::neutral();
        let mut trace = build_test_trace::<BabyBear>(&neutral, &neutral);
        trace.values[col::P3 + col::X_OFF] += BabyBear::from_u64(1);
        check_constraints(&PointAddAirChunkedChip::new(), &trace, &[]);
    }

    #[test]
    fn layout_documented() {
        assert_eq!(col::P1, 0);
        assert_eq!(col::P2, 36);
        assert_eq!(col::P3, 72);
        assert_eq!(col::TWO_D, 108);
        assert_eq!(col::ADDS_BASE, 117);
        assert!(col::SUBS_BASE > col::ADDS_BASE);
        assert!(col::MULS_BASE > col::SUBS_BASE);
        assert!(NUM_COLS > col::MULS_BASE);
    }
}
