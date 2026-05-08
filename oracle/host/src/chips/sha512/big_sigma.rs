//! `sha512::big_sigma` — composed chip computing
//! `Σ(x) = ROTR(x, ROT_A) ⊕ ROTR(x, ROT_B) ⊕ ROTR(x, ROT_C)`.
//!
//! Used for SHA-512's `Σ0` (28/34/39) and `Σ1` (14/18/41).
//!
//! Composing three primitive `Word64RotrChip` instances + two
//! `Word64XorChip` instances would require 3·72 + 2·204 = 624 cols and
//! many connection constraints. We instead inline the entire computation
//! into one chip that **shares `x`'s bit decomposition** across all
//! three rotations and uses the rotated bit indices directly in the XOR
//! constraints — saving ~400 columns relative to naive composition.
//!
//! ## Layout (one operation per row, allocated at `start_col`)
//!
//! | offset    | width | name        |
//! |-----------|-------|-------------|
//! | 0         | 4     | x chunks    |
//! | 4         | 4     | c chunks    | (= Σ(x))
//! | 8         | 64    | x bits      |
//! | 72        | 64    | mid bits    | (= ROTR(x,A) ⊕ ROTR(x,B))
//! | 136       | 64    | c bits      | (= mid ⊕ ROTR(x,C))
//!
//! Total: **200 columns**, **328 constraints** (degree 2).
//!
//! ## Constraints
//!
//! - 192 boolean checks (64 each on x, mid, c bits).
//! - 4 chunk-recomposition for `x` (chunk = Σ x_bit[k] · 2^k).
//! - 4 chunk-recomposition for `c`.
//! - 64 mid XOR: `mid_bit[i] = a_bit + b_bit - 2·a_bit·b_bit` where
//!   `a_bit = x_bit[(i + ROT_A) mod 64]` and similarly `b_bit`.
//! - 64 c XOR: `c_bit[i] = mid_bit[i] + r_bit - 2·mid_bit[i]·r_bit`
//!   where `r_bit = x_bit[(i + ROT_C) mod 64]`.
//!
//! ## Soundness
//!
//! Sound stand-alone — same boolean + recomposition story as the
//! primitive bitwise chips. No lookup gap.

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
pub struct BigSigmaChip<const ROT_A: usize, const ROT_B: usize, const ROT_C: usize> {
    pub start_col: usize,
}

impl<const ROT_A: usize, const ROT_B: usize, const ROT_C: usize> BigSigmaChip<ROT_A, ROT_B, ROT_C> {
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

        // Boolean checks on x_bits, mid_bits, c_bits.
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

        // Per-bit XOR for mid: mid_bit[i] = rot_A_bit XOR rot_B_bit.
        for i in 0..NUM_BITS {
            let a_idx = (i + ROT_A) % NUM_BITS;
            let b_idx = (i + ROT_B) % NUM_BITS;
            let a_bit = row[self.start_col + col::X_BITS + a_idx];
            let b_bit = row[self.start_col + col::X_BITS + b_idx];
            let mid_bit = row[self.start_col + col::MID_BITS + i];
            builder.assert_eq(mid_bit, a_bit.into() + b_bit.into() - two.clone() * (a_bit.into() * b_bit.into()));
        }

        // Per-bit XOR for c: c_bit[i] = mid_bit XOR rot_C_bit.
        for i in 0..NUM_BITS {
            let c_idx = (i + ROT_C) % NUM_BITS;
            let r_bit = row[self.start_col + col::X_BITS + c_idx];
            let mid_bit = row[self.start_col + col::MID_BITS + i];
            let c_bit = row[self.start_col + col::C_BITS + i];
            builder.assert_eq(c_bit, mid_bit.into() + r_bit.into() - two.clone() * (mid_bit.into() * r_bit.into()));
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BigSigmaTestAir<const ROT_A: usize, const ROT_B: usize, const ROT_C: usize>;

impl<F: Field, const ROT_A: usize, const ROT_B: usize, const ROT_C: usize> BaseAir<F> for BigSigmaTestAir<ROT_A, ROT_B, ROT_C> {
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

impl<AB: AirBuilder, const ROT_A: usize, const ROT_B: usize, const ROT_C: usize> Air<AB> for BigSigmaTestAir<ROT_A, ROT_B, ROT_C>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        BigSigmaChip::<ROT_A, ROT_B, ROT_C>::new().emit(builder);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BigSigmaWitness {
    pub x_chunks: [u64; NUM_CHUNKS],
    pub c_chunks: [u64; NUM_CHUNKS],
    pub x_bits: [u64; NUM_BITS],
    pub mid_bits: [u64; NUM_BITS],
    pub c_bits: [u64; NUM_BITS],
}

pub fn compute_big_sigma(x: u64, rot_a: u32, rot_b: u32, rot_c: u32) -> BigSigmaWitness {
    let rot_a_v = x.rotate_right(rot_a);
    let rot_b_v = x.rotate_right(rot_b);
    let rot_c_v = x.rotate_right(rot_c);
    let mid = rot_a_v ^ rot_b_v;
    let c = mid ^ rot_c_v;
    let mut x_bits = [0u64; NUM_BITS];
    let mut mid_bits = [0u64; NUM_BITS];
    let mut c_bits = [0u64; NUM_BITS];
    for i in 0..NUM_BITS {
        x_bits[i] = (x >> i) & 1;
        mid_bits[i] = (mid >> i) & 1;
        c_bits[i] = (c >> i) & 1;
    }
    BigSigmaWitness {
        x_chunks: super::word64_add::decompose_u64(x),
        c_chunks: super::word64_add::decompose_u64(c),
        x_bits,
        mid_bits,
        c_bits,
    }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(w: &BigSigmaWitness) -> RowMajorMatrix<F> {
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

    fn native_big_sigma(x: u64, a: u32, b: u32, c: u32) -> u64 {
        x.rotate_right(a) ^ x.rotate_right(b) ^ x.rotate_right(c)
    }

    #[test]
    fn big_sigma_zero_is_zero() {
        let w = compute_big_sigma(0, 28, 34, 39);
        assert_eq!(recompose_u64(&w.c_chunks), 0);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&BigSigmaTestAir::<28, 34, 39>, &trace, &[]);
    }

    /// Σ0(x) for SHA-512: rotations 28, 34, 39.
    #[test]
    fn big_sigma_0_against_native() {
        let inputs: [u64; 5] = [
            0x6a09e667f3bcc908, // SHA-512 IV[0]
            0xDEAD_BEEF_CAFE_BABE,
            0x1234_5678_9ABC_DEF0,
            u64::MAX,
            0xAAAA_AAAA_AAAA_AAAA,
        ];
        for x in inputs {
            let w = compute_big_sigma(x, 28, 34, 39);
            assert_eq!(recompose_u64(&w.c_chunks), native_big_sigma(x, 28, 34, 39));
            let trace = build_test_trace::<BabyBear>(&w);
            check_constraints(&BigSigmaTestAir::<28, 34, 39>, &trace, &[]);
        }
    }

    /// Σ1(x) for SHA-512: rotations 14, 18, 41.
    #[test]
    fn big_sigma_1_against_native() {
        let inputs: [u64; 5] = [
            0x510e527fade682d1, // SHA-512 IV[4]
            0xCAFE_BABE_DEAD_BEEF,
            0x0123_4567_89AB_CDEF,
            0,
            u64::MAX,
        ];
        for x in inputs {
            let w = compute_big_sigma(x, 14, 18, 41);
            assert_eq!(recompose_u64(&w.c_chunks), native_big_sigma(x, 14, 18, 41));
            let trace = build_test_trace::<BabyBear>(&w);
            check_constraints(&BigSigmaTestAir::<14, 18, 41>, &trace, &[]);
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn big_sigma_rejects_tampered_c_bit() {
        let w = compute_big_sigma(0xFFFF, 28, 34, 39);
        let mut trace = build_test_trace::<BabyBear>(&w);
        trace.values[col::C_BITS] = trace.values[col::C_BITS] + BabyBear::ONE;
        check_constraints(&BigSigmaTestAir::<28, 34, 39>, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn big_sigma_rejects_tampered_mid_bit() {
        let w = compute_big_sigma(0xCAFE, 28, 34, 39);
        let mut trace = build_test_trace::<BabyBear>(&w);
        trace.values[col::MID_BITS] = trace.values[col::MID_BITS] + BabyBear::ONE;
        check_constraints(&BigSigmaTestAir::<28, 34, 39>, &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        assert_eq!(NUM_COLS, 200);
    }
}
