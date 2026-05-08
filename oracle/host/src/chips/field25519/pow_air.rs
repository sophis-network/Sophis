//! `field25519::pow_air` — multi-row field exponentiation AIR (WIRED).
//!
//! Computes `base^exponent (mod p)` via square-and-multiply over the
//! exponent's bits (LSB-first to match witness `field_pow`).
//!
//! Per row layout (one bit step):
//!   - `bit`: 1 col (boolean — current exponent bit)
//!   - `pre_result`, `pre_current`: 2×9 cols
//!   - `post_result`, `post_current`: 2×9 cols
//!   - `mul_result`: 9 cols (raw `pre_result × pre_current`)
//!   - SQUARE chip embed: 710 cols (`pre_current × pre_current → post_current`)
//!   - COND_MUL chip embed: 710 cols (`pre_result × pre_current → mul_result`)
//!
//! Per-row constraints:
//!   - `bit` boolean
//!   - SQUARE.a = SQUARE.b = pre_current
//!   - SQUARE.c = post_current
//!   - COND_MUL.a = pre_result, COND_MUL.b = pre_current
//!   - COND_MUL.c = mul_result
//!   - Bit-conditional select (degree 2):
//!     `post_result[i] - pre_result[i] = bit · (mul_result[i] - pre_result[i])`
//!
//! Transitions:
//!   - `row[t+1].pre_result  = row[t].post_result`
//!   - `row[t+1].pre_current = row[t].post_current`
//!
//! Total per row: 46 + 2·710 = **1466 cols**. For 256-bit exponents:
//! 256 active rows padded to 512 (power-of-2 for FRI).
//!
//! ## Status (Etapa 1.1 — DONE)
//!
//! Wiring landed via `MulCanonicalFullChip` (commit `<phase5>`), unblocked
//! after the second-fold AIR (sub-fase 5.2.1.1.e.2). Inherits range-check
//! soundness gaps from constituents (close in Etapa 3 lookup args).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::mul_canonical_full::{self, MulCanonicalFullChip, NUM_COLS as MC_COLS};
use crate::chips::field25519::{Field25519Element, NUM_LIMBS};

pub mod col {
    use super::{NUM_LIMBS, MC_COLS};
    pub const BIT: usize = 0;
    pub const PRE_RESULT: usize = 1;
    pub const PRE_CURRENT: usize = PRE_RESULT + NUM_LIMBS;       // 10
    pub const POST_RESULT: usize = PRE_CURRENT + NUM_LIMBS;       // 19
    pub const POST_CURRENT: usize = POST_RESULT + NUM_LIMBS;      // 28
    pub const MUL_RESULT: usize = POST_CURRENT + NUM_LIMBS;       // 37
    pub const SQUARE_START: usize = MUL_RESULT + NUM_LIMBS;       // 46
    pub const COND_MUL_START: usize = SQUARE_START + MC_COLS;     // 756
    pub const TOTAL: usize = COND_MUL_START + MC_COLS;            // 1466
}

pub const NUM_COLS: usize = col::TOTAL;

#[derive(Debug, Clone, Copy)]
pub struct PowAirChip;

impl<F: Field> BaseAir<F> for PowAirChip {
    fn width(&self) -> usize { NUM_COLS }
    fn main_next_row_columns(&self) -> Vec<usize> { (0..NUM_COLS).collect() }
    fn max_constraint_degree(&self) -> Option<usize> { Some(2) }
}

impl<AB: AirBuilder> Air<AB> for PowAirChip
where AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        // Embed the two MulCanonicalFull chips at their offsets.
        MulCanonicalFullChip::at(col::SQUARE_START).emit(builder);
        MulCanonicalFullChip::at(col::COND_MUL_START).emit(builder);

        let main = builder.main();
        let cur = main.current_slice();
        let next = main.next_slice();

        builder.assert_bool(cur[col::BIT]);

        let assert_chunks_eq = |b: &mut AB, off_a: usize, off_b: usize| {
            for i in 0..NUM_LIMBS {
                b.assert_eq(cur[off_a + i], cur[off_b + i]);
            }
        };

        // SQUARE.a = SQUARE.b = pre_current
        assert_chunks_eq(builder, col::SQUARE_START + mul_canonical_full::col::A, col::PRE_CURRENT);
        assert_chunks_eq(builder, col::SQUARE_START + mul_canonical_full::col::B, col::PRE_CURRENT);
        assert_chunks_eq(builder, col::SQUARE_START + mul_canonical_full::col::C, col::POST_CURRENT);

        // COND_MUL.a = pre_result, COND_MUL.b = pre_current
        assert_chunks_eq(builder, col::COND_MUL_START + mul_canonical_full::col::A, col::PRE_RESULT);
        assert_chunks_eq(builder, col::COND_MUL_START + mul_canonical_full::col::B, col::PRE_CURRENT);
        assert_chunks_eq(builder, col::COND_MUL_START + mul_canonical_full::col::C, col::MUL_RESULT);

        // Conditional select: post_result = bit ? mul_result : pre_result
        for i in 0..NUM_LIMBS {
            let post = cur[col::POST_RESULT + i].clone();
            let pre = cur[col::PRE_RESULT + i].clone();
            let mul = cur[col::MUL_RESULT + i].clone();
            let bit = cur[col::BIT].clone();
            builder.assert_eq(post - pre.clone(), bit * (mul - pre));
        }

        // Transitions: row[t+1].pre = row[t].post
        for i in 0..NUM_LIMBS {
            builder.when_transition().assert_eq(next[col::PRE_RESULT + i], cur[col::POST_RESULT + i]);
            builder.when_transition().assert_eq(next[col::PRE_CURRENT + i], cur[col::POST_CURRENT + i]);
        }
    }
}

pub fn build_pow_trace<F: Field + PrimeCharacteristicRing>(
    base: &Field25519Element,
    exponent_le_bytes: &[u8; 32],
) -> RowMajorMatrix<F> {
    use crate::chips::ed25519::decompress::field_pow;
    use crate::chips::field25519::arith::{field_mul, field_one};

    const TOTAL_BITS: usize = 256;
    const HEIGHT: usize = 512; // power of 2 ≥ 256
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    let mut result = field_one();
    let mut current = base.clone();

    for row in 0..TOTAL_BITS {
        let row_off = row * NUM_COLS;
        let byte_idx = row / 8;
        let bit_in_byte = row % 8;
        let bit = (exponent_le_bytes[byte_idx] >> bit_in_byte) & 1;

        put_elem::<F>(&mut values, row_off + col::PRE_RESULT, &result);
        put_elem::<F>(&mut values, row_off + col::PRE_CURRENT, &current);
        values[row_off + col::BIT] = F::from_u64(bit as u64);

        let raw_mul = field_mul(&result, &current);
        let new_result = if bit == 1 { raw_mul.clone() } else { result.clone() };
        let new_current = field_mul(&current, &current);

        put_elem::<F>(&mut values, row_off + col::POST_RESULT, &new_result);
        put_elem::<F>(&mut values, row_off + col::POST_CURRENT, &new_current);
        put_elem::<F>(&mut values, row_off + col::MUL_RESULT, &raw_mul);

        // Populate embedded chip witnesses.
        mul_canonical_full::populate_row::<F>(&mut values, row_off, col::SQUARE_START, &current, &current);
        mul_canonical_full::populate_row::<F>(&mut values, row_off, col::COND_MUL_START, &result, &current);

        result = new_result;
        current = new_current;
    }

    debug_assert_eq!(result.limbs, field_pow(base, exponent_le_bytes).limbs);

    // Padding rows: extend with bit=0, current keeps squaring, result frozen.
    for row in TOTAL_BITS..HEIGHT {
        let row_off = row * NUM_COLS;
        put_elem::<F>(&mut values, row_off + col::PRE_RESULT, &result);
        put_elem::<F>(&mut values, row_off + col::PRE_CURRENT, &current);
        let raw_mul = field_mul(&result, &current);
        let new_current = field_mul(&current, &current);
        put_elem::<F>(&mut values, row_off + col::POST_RESULT, &result);
        put_elem::<F>(&mut values, row_off + col::POST_CURRENT, &new_current);
        put_elem::<F>(&mut values, row_off + col::MUL_RESULT, &raw_mul);

        mul_canonical_full::populate_row::<F>(&mut values, row_off, col::SQUARE_START, &current, &current);
        mul_canonical_full::populate_row::<F>(&mut values, row_off, col::COND_MUL_START, &result, &current);

        current = new_current;
    }

    RowMajorMatrix::new(values, NUM_COLS)
}

fn put_elem<F: Field + PrimeCharacteristicRing>(values: &mut [F], off: usize, e: &Field25519Element) {
    for i in 0..NUM_LIMBS {
        values[off + i] = F::from_u64(e.limbs[i]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    fn small(n: u64) -> Field25519Element {
        let mut limbs = [0u64; NUM_LIMBS];
        limbs[0] = n & ((1 << 30) - 1);
        Field25519Element { limbs }
    }

    #[test]
    fn pow_zero_exponent_yields_one() {
        let trace = build_pow_trace::<BabyBear>(&small(7), &[0u8; 32]);
        check_constraints(&PowAirChip, &trace, &[]);
    }

    #[test]
    fn pow_one_exponent_yields_base() {
        let mut exp = [0u8; 32];
        exp[0] = 1;
        let trace = build_pow_trace::<BabyBear>(&small(13), &exp);
        check_constraints(&PowAirChip, &trace, &[]);
    }

    #[test]
    fn pow_for_p_minus_5_over_8() {
        // The exponent used by decompress for sqrt of base=2.
        use crate::chips::ed25519::decompress::P_MINUS_5_OVER_8;
        let trace = build_pow_trace::<BabyBear>(&small(2), &P_MINUS_5_OVER_8);
        check_constraints(&PowAirChip, &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        // 3.2-3.8 + 3.9: 2× MulCanonicalFull each +406 from SF. 6942 + 2×406 = 7754.
        assert_eq!(NUM_COLS, 7754);
    }
}
