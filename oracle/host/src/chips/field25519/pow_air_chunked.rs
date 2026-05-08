//! `field25519::pow_air_chunked` — chunked-sound variant of `pow_air` (Etapa 3.10.3).
//!
//! Idêntico ao `PowAirChip` exceto pelo uso de `MulCanonicalFullChunkedChip`
//! no lugar do `MulCanonicalFullChip` original. Wire format invariance
//! preservada (A/B/C 30-bit cols a offsets 0/9/18 dentro de cada sub-chip)
//! → wiring constraints idênticas à versão não-chunked.
//!
//! Per row layout (one bit step):
//!   - `bit`: 1 col (boolean — current exponent bit)
//!   - `pre_result`, `pre_current`: 2×9 cols
//!   - `post_result`, `post_current`: 2×9 cols
//!   - `mul_result`: 9 cols (raw `pre_result × pre_current`)
//!   - SQUARE chip embed: MC_COLS chunked (~9430 cols)
//!   - COND_MUL chip embed: MC_COLS chunked
//!
//! Total per row ≈ 2·9430 + 46 = ~18906 cols.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::mul_canonical_full_chunked::{
    self, MulCanonicalFullChunkedChip, NUM_COLS as MC_COLS,
};
use crate::chips::field25519::{Field25519Element, NUM_LIMBS};

pub mod col {
    use super::{MC_COLS, NUM_LIMBS};
    pub const BIT: usize = 0;
    pub const PRE_RESULT: usize = 1;
    pub const PRE_CURRENT: usize = PRE_RESULT + NUM_LIMBS;
    pub const POST_RESULT: usize = PRE_CURRENT + NUM_LIMBS;
    pub const POST_CURRENT: usize = POST_RESULT + NUM_LIMBS;
    pub const MUL_RESULT: usize = POST_CURRENT + NUM_LIMBS;
    pub const SQUARE_START: usize = MUL_RESULT + NUM_LIMBS;
    pub const COND_MUL_START: usize = SQUARE_START + MC_COLS;
    pub const TOTAL: usize = COND_MUL_START + MC_COLS;
}

pub const NUM_COLS: usize = col::TOTAL;

#[derive(Debug, Clone, Copy)]
pub struct PowAirChunkedChip;

impl<F: Field> BaseAir<F> for PowAirChunkedChip {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        (0..NUM_COLS).collect()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for PowAirChunkedChip
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        MulCanonicalFullChunkedChip::at(col::SQUARE_START).emit(builder);
        MulCanonicalFullChunkedChip::at(col::COND_MUL_START).emit(builder);

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
        assert_chunks_eq(
            builder,
            col::SQUARE_START + mul_canonical_full_chunked::col::A,
            col::PRE_CURRENT,
        );
        assert_chunks_eq(
            builder,
            col::SQUARE_START + mul_canonical_full_chunked::col::B,
            col::PRE_CURRENT,
        );
        assert_chunks_eq(
            builder,
            col::SQUARE_START + mul_canonical_full_chunked::col::C,
            col::POST_CURRENT,
        );

        // COND_MUL.a = pre_result, COND_MUL.b = pre_current
        assert_chunks_eq(
            builder,
            col::COND_MUL_START + mul_canonical_full_chunked::col::A,
            col::PRE_RESULT,
        );
        assert_chunks_eq(
            builder,
            col::COND_MUL_START + mul_canonical_full_chunked::col::B,
            col::PRE_CURRENT,
        );
        assert_chunks_eq(
            builder,
            col::COND_MUL_START + mul_canonical_full_chunked::col::C,
            col::MUL_RESULT,
        );

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
            builder
                .when_transition()
                .assert_eq(next[col::PRE_RESULT + i], cur[col::POST_RESULT + i]);
            builder
                .when_transition()
                .assert_eq(next[col::PRE_CURRENT + i], cur[col::POST_CURRENT + i]);
        }
    }
}

pub fn build_pow_trace_chunked<F: Field + PrimeCharacteristicRing>(
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
        let new_result = if bit == 1 {
            raw_mul.clone()
        } else {
            result.clone()
        };
        let new_current = field_mul(&current, &current);

        put_elem::<F>(&mut values, row_off + col::POST_RESULT, &new_result);
        put_elem::<F>(&mut values, row_off + col::POST_CURRENT, &new_current);
        put_elem::<F>(&mut values, row_off + col::MUL_RESULT, &raw_mul);

        // Populate embedded chunked chip witnesses.
        mul_canonical_full_chunked::populate_row::<F>(
            &mut values,
            row_off,
            col::SQUARE_START,
            &current,
            &current,
        );
        mul_canonical_full_chunked::populate_row::<F>(
            &mut values,
            row_off,
            col::COND_MUL_START,
            &result,
            &current,
        );

        result = new_result;
        current = new_current;
    }

    debug_assert_eq!(result.limbs, field_pow(base, exponent_le_bytes).limbs);

    // Padding rows.
    for row in TOTAL_BITS..HEIGHT {
        let row_off = row * NUM_COLS;
        put_elem::<F>(&mut values, row_off + col::PRE_RESULT, &result);
        put_elem::<F>(&mut values, row_off + col::PRE_CURRENT, &current);
        let raw_mul = field_mul(&result, &current);
        let new_current = field_mul(&current, &current);
        put_elem::<F>(&mut values, row_off + col::POST_RESULT, &result);
        put_elem::<F>(&mut values, row_off + col::POST_CURRENT, &new_current);
        put_elem::<F>(&mut values, row_off + col::MUL_RESULT, &raw_mul);

        mul_canonical_full_chunked::populate_row::<F>(
            &mut values,
            row_off,
            col::SQUARE_START,
            &current,
            &current,
        );
        mul_canonical_full_chunked::populate_row::<F>(
            &mut values,
            row_off,
            col::COND_MUL_START,
            &result,
            &current,
        );

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
    fn pow_chunked_zero_exponent_yields_one() {
        let trace = build_pow_trace_chunked::<BabyBear>(&small(7), &[0u8; 32]);
        check_constraints(&PowAirChunkedChip, &trace, &[]);
    }

    #[test]
    fn pow_chunked_one_exponent_yields_base() {
        let mut exp = [0u8; 32];
        exp[0] = 1;
        let trace = build_pow_trace_chunked::<BabyBear>(&small(13), &exp);
        check_constraints(&PowAirChunkedChip, &trace, &[]);
    }

    #[test]
    fn pow_chunked_layout_documented() {
        assert_eq!(col::BIT, 0);
        assert_eq!(col::PRE_RESULT, 1);
        assert_eq!(col::SQUARE_START, 46);
        assert_eq!(col::COND_MUL_START, 46 + MC_COLS);
        assert_eq!(NUM_COLS, 46 + 2 * MC_COLS);
    }
}
