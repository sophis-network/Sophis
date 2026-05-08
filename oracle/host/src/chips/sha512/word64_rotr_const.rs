//! `sha512::word64_rotr_const` — 64-bit right-rotation by a constant.
//!
//! Rotation is pure bit relabeling: `c_bit[i] = a_bit[(i + ROT) mod 64]`.
//! No per-bit "operation" constraints are needed; we just decompose `a`
//! into 64 boolean cols, then directly **recompose `c` from the rotated
//! a-bits**. The `c` chunks are constrained via the rotated weighting,
//! eliminating the need for separate `c` bit columns.
//!
//! Parameterised by `const ROT: usize` so SHA-512 can instantiate the
//! specific rotations it needs (1, 8, 14, 18, 19, 28, 34, 39, 41, 61).
//!
//! ## Layout (one operation per row, allocated at `start_col`)
//!
//! | offset    | width | name      |
//! |-----------|-------|-----------|
//! | 0         | 4     | a chunks  |
//! | 4         | 4     | c chunks  |
//! | 8         | 64    | a bits    |
//!
//! Total: **72 columns**.
//!
//! ## Constraints
//!
//! - 64 boolean checks on `a_bits`.
//! - 4 chunk-recomposition checks for `a`.
//! - 4 chunk-recomposition checks for `c` using rotated bit weights.
//!
//! Total: **72 constraints** (degree 2 from the bool checks).
//!
//! ## Soundness
//!
//! Sound stand-alone — the same boolean + recomposition story as the
//! other bitwise chips. No lookup arguments needed.

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
    pub const A_BITS: usize = C_CHUNKS + NUM_CHUNKS;   // 8
}

pub const NUM_COLS: usize = col::A_BITS + NUM_BITS; // 72

#[derive(Debug, Clone, Copy)]
pub struct Word64RotrChip<const ROT: usize> {
    pub start_col: usize,
}

impl<const ROT: usize> Word64RotrChip<ROT> {
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
                acc = acc + AB::Expr::from_u64(weight) * bit.into();
                weight <<= 1;
            }
            builder.assert_eq(row[self.start_col + col::A_CHUNKS + chunk_idx], acc);
        }

        // Recompose c from rotated a_bits.
        // c_bit[i] = a_bit[(i + ROT) mod 64]
        // c_chunk[chunk_idx] = sum_{k=0..16} c_bit[chunk_idx*16 + k] * 2^k
        //                    = sum_{k=0..16} a_bit[(chunk_idx*16 + k + ROT) mod 64] * 2^k
        for chunk_idx in 0..NUM_CHUNKS {
            let bit_base = chunk_idx * CHUNK_BITS;
            let mut acc = AB::Expr::ZERO;
            let mut weight: u64 = 1;
            for k in 0..CHUNK_BITS {
                let src = (bit_base + k + ROT) % NUM_BITS;
                let bit = row[self.start_col + col::A_BITS + src];
                acc = acc + AB::Expr::from_u64(weight) * bit.into();
                weight <<= 1;
            }
            builder.assert_eq(row[self.start_col + col::C_CHUNKS + chunk_idx], acc);
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Word64RotrTestAir<const ROT: usize>;

impl<F: Field, const ROT: usize> BaseAir<F> for Word64RotrTestAir<ROT> {
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

impl<AB: AirBuilder, const ROT: usize> Air<AB> for Word64RotrTestAir<ROT>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        Word64RotrChip::<ROT>::new().emit(builder);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Word64RotrWitness {
    pub a_chunks: [u64; NUM_CHUNKS],
    pub c_chunks: [u64; NUM_CHUNKS],
    pub a_bits: [u64; NUM_BITS],
}

pub fn compute_rotr64(a: u64, rot: u32) -> Word64RotrWitness {
    let c = a.rotate_right(rot);
    let mut a_bits = [0u64; NUM_BITS];
    for i in 0..NUM_BITS {
        a_bits[i] = (a >> i) & 1;
    }
    Word64RotrWitness {
        a_chunks: super::word64_add::decompose_u64(a),
        c_chunks: super::word64_add::decompose_u64(c),
        a_bits,
    }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(w: &Word64RotrWitness) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];
    for i in 0..NUM_CHUNKS {
        values[col::A_CHUNKS + i] = F::from_u64(w.a_chunks[i]);
        values[col::C_CHUNKS + i] = F::from_u64(w.c_chunks[i]);
    }
    for i in 0..NUM_BITS {
        values[col::A_BITS + i] = F::from_u64(w.a_bits[i]);
    }
    // Padding rows: a=0, c=rotr(0)=0, all bits 0 — trivially satisfies.
    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::word64_add::recompose_u64;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    #[test]
    fn rotr_zero_amount_is_identity() {
        let w = compute_rotr64(0xCAFE_BABE_1234_5678, 0);
        assert_eq!(recompose_u64(&w.c_chunks), 0xCAFE_BABE_1234_5678);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64RotrTestAir::<0>, &trace, &[]);
    }

    #[test]
    fn rotr_1_basic() {
        let w = compute_rotr64(0b1011, 1);
        assert_eq!(recompose_u64(&w.c_chunks), 0b1011u64.rotate_right(1));
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64RotrTestAir::<1>, &trace, &[]);
    }

    #[test]
    fn rotr_high_bit_wraps() {
        // Rotating 1 right by 1 should land in bit 63.
        let w = compute_rotr64(1, 1);
        assert_eq!(recompose_u64(&w.c_chunks), 1u64 << 63);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64RotrTestAir::<1>, &trace, &[]);
    }

    #[test]
    fn rotr_28_round_constant_for_big_sigma0() {
        let a = 0xDEAD_BEEF_CAFE_BABE;
        let w = compute_rotr64(a, 28);
        assert_eq!(recompose_u64(&w.c_chunks), a.rotate_right(28));
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64RotrTestAir::<28>, &trace, &[]);
    }

    #[test]
    fn rotr_all_sha512_amounts() {
        // SHA-512 uses these rotation amounts: 1, 8, 14, 18, 19, 28, 34, 39, 41, 61.
        let a = 0x1234_5678_9ABC_DEF0;
        macro_rules! check_rot {
            ($amount:expr) => {{
                let w = compute_rotr64(a, $amount);
                assert_eq!(recompose_u64(&w.c_chunks), a.rotate_right($amount));
                let trace = build_test_trace::<BabyBear>(&w);
                check_constraints(&Word64RotrTestAir::<{ $amount as usize }>, &trace, &[]);
            }};
        }
        check_rot!(1u32);
        check_rot!(8u32);
        check_rot!(14u32);
        check_rot!(18u32);
        check_rot!(19u32);
        check_rot!(28u32);
        check_rot!(34u32);
        check_rot!(39u32);
        check_rot!(41u32);
        check_rot!(61u32);
    }

    #[test]
    fn rotr_64_is_identity() {
        // Rotating by 64 returns the original value (full rotation).
        let w = compute_rotr64(0xCAFE_BABE_1234_5678, 64);
        assert_eq!(recompose_u64(&w.c_chunks), 0xCAFE_BABE_1234_5678);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rotr_rejects_tampered_c_chunk() {
        let w = compute_rotr64(0xFFFF, 8);
        let mut trace = build_test_trace::<BabyBear>(&w);
        trace.values[col::C_CHUNKS] = trace.values[col::C_CHUNKS] + BabyBear::ONE;
        check_constraints(&Word64RotrTestAir::<8>, &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        assert_eq!(NUM_COLS, 72);
    }
}
