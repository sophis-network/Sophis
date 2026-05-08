//! `sha512::small_sigma` — composed chip computing
//! `σ(x) = ROTR(x, ROT_A) ⊕ ROTR(x, ROT_B) ⊕ SHR(x, SHIFT)`.
//!
//! Used for SHA-512's `σ0` (1, 8, SHR 7) and `σ1` (19, 61, SHR 6) in
//! the message schedule.
//!
//! Same layout as `big_sigma` but the third operand is a SHR (out-of-range
//! bits zeroed) instead of a third ROTR (wrap-around).
//!
//! ## Layout (one operation per row, allocated at `start_col`)
//!
//! | offset    | width | name        |
//! |-----------|-------|-------------|
//! | 0         | 4     | x chunks    |
//! | 4         | 4     | c chunks    | (= σ(x))
//! | 8         | 64    | x bits      |
//! | 72        | 64    | mid bits    | (= ROTR(x,A) ⊕ ROTR(x,B))
//! | 136       | 64    | c bits      | (= mid ⊕ SHR(x, SHIFT))
//!
//! Total: **200 columns**, **328 constraints** (degree 2).
//!
//! For the SHR component, bits at index `(i + SHIFT)` are used directly
//! when `i + SHIFT < 64`, else treated as zero (no contribution to the
//! XOR — `mid_bit ⊕ 0 = mid_bit`).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

pub const NUM_CHUNKS: usize = 4;
pub const CHUNK_BITS: usize = 16;
pub const NUM_BITS: usize = 64;

pub mod col {
    use super::{NUM_BITS, NUM_CHUNKS};
    pub const X_CHUNKS: usize = 0;
    pub const C_CHUNKS: usize = X_CHUNKS + NUM_CHUNKS; // 4
    pub const X_BITS: usize = C_CHUNKS + NUM_CHUNKS;   // 8
    pub const MID_BITS: usize = X_BITS + NUM_BITS;     // 72
    pub const C_BITS: usize = MID_BITS + NUM_BITS;     // 136
}

pub const NUM_COLS: usize = col::C_BITS + NUM_BITS; // 200

#[derive(Debug, Clone, Copy)]
pub struct SmallSigmaChip<const ROT_A: usize, const ROT_B: usize, const SHIFT: usize> {
    pub start_col: usize,
}

impl<const ROT_A: usize, const ROT_B: usize, const SHIFT: usize> SmallSigmaChip<ROT_A, ROT_B, SHIFT> {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let two = AB::Expr::from_u64(2);

        // Boolean checks.
        for i in 0..NUM_BITS {
            builder.assert_bool(row[self.start_col + col::X_BITS + i]);
            builder.assert_bool(row[self.start_col + col::MID_BITS + i]);
            builder.assert_bool(row[self.start_col + col::C_BITS + i]);
        }

        // Chunk recomposition for x and c.
        for chunk_idx in 0..NUM_CHUNKS {
            let bit_base = chunk_idx * CHUNK_BITS;
            let mut x_acc = AB::Expr::ZERO;
            let mut c_acc = AB::Expr::ZERO;
            let mut weight: u64 = 1;
            for k in 0..CHUNK_BITS {
                let x_bit = row[self.start_col + col::X_BITS + bit_base + k];
                let c_bit = row[self.start_col + col::C_BITS + bit_base + k];
                let w = AB::Expr::from_u64(weight);
                x_acc = x_acc + w.clone() * x_bit.into();
                c_acc = c_acc + w * c_bit.into();
                weight <<= 1;
            }
            builder.assert_eq(row[self.start_col + col::X_CHUNKS + chunk_idx], x_acc);
            builder.assert_eq(row[self.start_col + col::C_CHUNKS + chunk_idx], c_acc);
        }

        // Per-bit XOR for mid: mid_bit = ROTR(x,A)_bit XOR ROTR(x,B)_bit.
        for i in 0..NUM_BITS {
            let a_idx = (i + ROT_A) % NUM_BITS;
            let b_idx = (i + ROT_B) % NUM_BITS;
            let a_bit = row[self.start_col + col::X_BITS + a_idx];
            let b_bit = row[self.start_col + col::X_BITS + b_idx];
            let mid_bit = row[self.start_col + col::MID_BITS + i];
            builder.assert_eq(mid_bit, a_bit.into() + b_bit.into() - two.clone() * (a_bit.into() * b_bit.into()));
        }

        // Per-bit XOR for c: c_bit = mid_bit XOR SHR(x, SHIFT)_bit.
        // For i + SHIFT >= 64, the SHR bit is 0 and c_bit = mid_bit.
        for i in 0..NUM_BITS {
            let mid_bit = row[self.start_col + col::MID_BITS + i];
            let c_bit = row[self.start_col + col::C_BITS + i];
            let src = i + SHIFT;
            if src < NUM_BITS {
                let r_bit = row[self.start_col + col::X_BITS + src];
                builder.assert_eq(c_bit, mid_bit.into() + r_bit.into() - two.clone() * (mid_bit.into() * r_bit.into()));
            } else {
                // SHR bit is 0; c_bit = mid_bit.
                builder.assert_eq(c_bit, mid_bit);
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SmallSigmaTestAir<const ROT_A: usize, const ROT_B: usize, const SHIFT: usize>;

impl<F: Field, const ROT_A: usize, const ROT_B: usize, const SHIFT: usize> BaseAir<F> for SmallSigmaTestAir<ROT_A, ROT_B, SHIFT> {
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

impl<AB: AirBuilder, const ROT_A: usize, const ROT_B: usize, const SHIFT: usize> Air<AB> for SmallSigmaTestAir<ROT_A, ROT_B, SHIFT>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        SmallSigmaChip::<ROT_A, ROT_B, SHIFT>::new().emit(builder);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SmallSigmaWitness {
    pub x_chunks: [u64; NUM_CHUNKS],
    pub c_chunks: [u64; NUM_CHUNKS],
    pub x_bits: [u64; NUM_BITS],
    pub mid_bits: [u64; NUM_BITS],
    pub c_bits: [u64; NUM_BITS],
}

pub fn compute_small_sigma(x: u64, rot_a: u32, rot_b: u32, shift: u32) -> SmallSigmaWitness {
    let mid = x.rotate_right(rot_a) ^ x.rotate_right(rot_b);
    let c = mid ^ (x >> shift);
    let mut x_bits = [0u64; NUM_BITS];
    let mut mid_bits = [0u64; NUM_BITS];
    let mut c_bits = [0u64; NUM_BITS];
    for i in 0..NUM_BITS {
        x_bits[i] = (x >> i) & 1;
        mid_bits[i] = (mid >> i) & 1;
        c_bits[i] = (c >> i) & 1;
    }
    SmallSigmaWitness {
        x_chunks: super::word64_add::decompose_u64(x),
        c_chunks: super::word64_add::decompose_u64(c),
        x_bits,
        mid_bits,
        c_bits,
    }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(w: &SmallSigmaWitness) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];
    for i in 0..NUM_CHUNKS {
        values[col::X_CHUNKS + i] = F::from_u64(w.x_chunks[i]);
        values[col::C_CHUNKS + i] = F::from_u64(w.c_chunks[i]);
    }
    for i in 0..NUM_BITS {
        values[col::X_BITS + i] = F::from_u64(w.x_bits[i]);
        values[col::MID_BITS + i] = F::from_u64(w.mid_bits[i]);
        values[col::C_BITS + i] = F::from_u64(w.c_bits[i]);
    }
    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::word64_add::recompose_u64;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    fn native_small_sigma(x: u64, a: u32, b: u32, shift: u32) -> u64 {
        x.rotate_right(a) ^ x.rotate_right(b) ^ (x >> shift)
    }

    #[test]
    fn small_sigma_zero_is_zero() {
        let w = compute_small_sigma(0, 1, 8, 7);
        assert_eq!(recompose_u64(&w.c_chunks), 0);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&SmallSigmaTestAir::<1, 8, 7>, &trace, &[]);
    }

    /// σ0(x) for SHA-512: ROTR 1, ROTR 8, SHR 7.
    #[test]
    fn small_sigma_0_against_native() {
        let inputs: [u64; 5] = [
            0x6162638000000000, // SHA-512("abc") W[0]
            0xDEAD_BEEF_CAFE_BABE,
            0x1234_5678_9ABC_DEF0,
            u64::MAX,
            0,
        ];
        for x in inputs {
            let w = compute_small_sigma(x, 1, 8, 7);
            assert_eq!(recompose_u64(&w.c_chunks), native_small_sigma(x, 1, 8, 7));
            let trace = build_test_trace::<BabyBear>(&w);
            check_constraints(&SmallSigmaTestAir::<1, 8, 7>, &trace, &[]);
        }
    }

    /// σ1(x) for SHA-512: ROTR 19, ROTR 61, SHR 6.
    #[test]
    fn small_sigma_1_against_native() {
        let inputs: [u64; 5] = [
            0x0000000000000018, // SHA-512("abc") W[15] (length in bits = 24)
            0xCAFE_BABE_DEAD_BEEF,
            0x0123_4567_89AB_CDEF,
            u64::MAX,
            0,
        ];
        for x in inputs {
            let w = compute_small_sigma(x, 19, 61, 6);
            assert_eq!(recompose_u64(&w.c_chunks), native_small_sigma(x, 19, 61, 6));
            let trace = build_test_trace::<BabyBear>(&w);
            check_constraints(&SmallSigmaTestAir::<19, 61, 6>, &trace, &[]);
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn small_sigma_rejects_tampered_c_bit() {
        let w = compute_small_sigma(0xCAFE, 1, 8, 7);
        let mut trace = build_test_trace::<BabyBear>(&w);
        trace.values[col::C_BITS] = trace.values[col::C_BITS] + BabyBear::ONE;
        check_constraints(&SmallSigmaTestAir::<1, 8, 7>, &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        assert_eq!(NUM_COLS, 200);
    }
}
