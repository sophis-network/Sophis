//! `sha512::word64_shr_const` — 64-bit right-shift by a constant.
//!
//! Like `word64_rotr_const` but bits that "shift out" become 0 instead
//! of wrapping. SHA-512 uses `SHR(x, 7)` in `σ0` and `SHR(x, 6)` in `σ1`.
//!
//! `c_bit[i] = a_bit[i + SHIFT]` if `i + SHIFT < 64`, else `0`.
//!
//! ## Layout
//!
//! Same as `word64_rotr_const`:
//!
//! | offset    | width | name      |
//! |-----------|-------|-----------|
//! | 0         | 4     | a chunks  |
//! | 4         | 4     | c chunks  |
//! | 8         | 64    | a bits    |
//!
//! Total: **72 columns**, **72 constraints** (degree 2 from bool checks).
//!
//! ## Constraints
//!
//! - 64 boolean checks on `a_bits`.
//! - 4 chunk-recomposition for `a`.
//! - 4 chunk-recomposition for `c` using shifted bit weights (with implicit
//!   zero-fill for high bits).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

pub const NUM_CHUNKS: usize = 4;
pub const CHUNK_BITS: usize = 16;
pub const NUM_BITS: usize = 64;

pub mod col {
    use super::NUM_CHUNKS;
    pub const A_CHUNKS: usize = 0;
    pub const C_CHUNKS: usize = A_CHUNKS + NUM_CHUNKS; // 4
    pub const A_BITS: usize = C_CHUNKS + NUM_CHUNKS; // 8
}

pub const NUM_COLS: usize = col::A_BITS + NUM_BITS; // 72

#[derive(Debug, Clone, Copy)]
pub struct Word64ShrChip<const SHIFT: usize> {
    pub start_col: usize,
}

impl<const SHIFT: usize> Default for Word64ShrChip<SHIFT> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SHIFT: usize> Word64ShrChip<SHIFT> {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();

        // Boolean checks on a_bits.
        for i in 0..NUM_BITS {
            builder.assert_bool(row[self.start_col + col::A_BITS + i]);
        }

        // Recompose a from a_bits.
        for chunk_idx in 0..NUM_CHUNKS {
            let bit_base = chunk_idx * CHUNK_BITS;
            let mut acc = AB::Expr::ZERO;
            let mut weight: u64 = 1;
            for k in 0..CHUNK_BITS {
                let bit = row[self.start_col + col::A_BITS + bit_base + k];
                acc += AB::Expr::from_u64(weight) * bit.into();
                weight <<= 1;
            }
            builder.assert_eq(row[self.start_col + col::A_CHUNKS + chunk_idx], acc);
        }

        // Recompose c from shifted a_bits.
        // c_bit[i] = a_bit[i + SHIFT] if i + SHIFT < 64, else 0.
        for chunk_idx in 0..NUM_CHUNKS {
            let bit_base = chunk_idx * CHUNK_BITS;
            let mut acc = AB::Expr::ZERO;
            let mut weight: u64 = 1;
            for k in 0..CHUNK_BITS {
                let src = bit_base + k + SHIFT;
                if src < NUM_BITS {
                    let bit = row[self.start_col + col::A_BITS + src];
                    acc += AB::Expr::from_u64(weight) * bit.into();
                }
                // else: implicit zero (no contribution to acc).
                weight <<= 1;
            }
            builder.assert_eq(row[self.start_col + col::C_CHUNKS + chunk_idx], acc);
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Word64ShrTestAir<const SHIFT: usize>;

impl<F: Field, const SHIFT: usize> BaseAir<F> for Word64ShrTestAir<SHIFT> {
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

impl<AB: AirBuilder, const SHIFT: usize> Air<AB> for Word64ShrTestAir<SHIFT>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        Word64ShrChip::<SHIFT>::new().emit(builder);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Word64ShrWitness {
    pub a_chunks: [u64; NUM_CHUNKS],
    pub c_chunks: [u64; NUM_CHUNKS],
    pub a_bits: [u64; NUM_BITS],
}

pub fn compute_shr64(a: u64, shift: u32) -> Word64ShrWitness {
    let c = a >> shift;
    let mut a_bits = [0u64; NUM_BITS];
    for i in 0..NUM_BITS {
        a_bits[i] = (a >> i) & 1;
    }
    Word64ShrWitness { a_chunks: super::word64_add::decompose_u64(a), c_chunks: super::word64_add::decompose_u64(c), a_bits }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(w: &Word64ShrWitness) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];
    for i in 0..NUM_CHUNKS {
        values[col::A_CHUNKS + i] = F::from_u64(w.a_chunks[i]);
        values[col::C_CHUNKS + i] = F::from_u64(w.c_chunks[i]);
    }
    for i in 0..NUM_BITS {
        values[col::A_BITS + i] = F::from_u64(w.a_bits[i]);
    }
    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::super::word64_add::recompose_u64;
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    #[test]
    fn shr_zero_amount_is_identity() {
        let w = compute_shr64(0xCAFE_BABE_1234_5678, 0);
        assert_eq!(recompose_u64(&w.c_chunks), 0xCAFE_BABE_1234_5678);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64ShrTestAir::<0>, &trace, &[]);
    }

    #[test]
    fn shr_7_for_small_sigma0() {
        let a = 0xDEAD_BEEF_CAFE_BABE;
        let w = compute_shr64(a, 7);
        assert_eq!(recompose_u64(&w.c_chunks), a >> 7);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64ShrTestAir::<7>, &trace, &[]);
    }

    #[test]
    fn shr_6_for_small_sigma1() {
        let a = 0x1234_5678_9ABC_DEF0;
        let w = compute_shr64(a, 6);
        assert_eq!(recompose_u64(&w.c_chunks), a >> 6);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64ShrTestAir::<6>, &trace, &[]);
    }

    #[test]
    fn shr_full_64_is_zero() {
        // Shifting by 64 in C/Rust is UB, but we test by setting all a bits and
        // SHIFT=63: top bit of a (bit 63) ends at bit 0 of c, all higher bits zero.
        let w = compute_shr64(u64::MAX, 63);
        assert_eq!(recompose_u64(&w.c_chunks), u64::MAX >> 63);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64ShrTestAir::<63>, &trace, &[]);
    }

    #[test]
    fn shr_high_bits_get_zeroed() {
        // 0x80000000_00000000 >> 1 = 0x40000000_00000000 (top bit moves down, no wrap).
        let w = compute_shr64(0x8000_0000_0000_0000, 1);
        assert_eq!(recompose_u64(&w.c_chunks), 0x4000_0000_0000_0000);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64ShrTestAir::<1>, &trace, &[]);
    }

    #[test]
    fn shr_distinct_from_rotr() {
        // For inputs with bits in the low part, SHR and ROTR diverge: SHR
        // zeros the high bits while ROTR wraps them around.
        let a: u64 = 1; // bit 0 only set
        let shr_w = compute_shr64(a, 1);
        let rotr_a = a.rotate_right(1);
        assert_eq!(recompose_u64(&shr_w.c_chunks), 0); // 1 >> 1 = 0
        assert_eq!(rotr_a, 1u64 << 63); // wraps
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn shr_rejects_tampered_c_chunk() {
        let w = compute_shr64(0xFFFF, 7);
        let mut trace = build_test_trace::<BabyBear>(&w);
        trace.values[col::C_CHUNKS] += BabyBear::ONE;
        check_constraints(&Word64ShrTestAir::<7>, &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        assert_eq!(NUM_COLS, 72);
    }
}
