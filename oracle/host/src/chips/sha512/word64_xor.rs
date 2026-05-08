//! `sha512::word64_xor` — 64-bit bitwise XOR AIR chip.
//!
//! XOR is fundamentally bit-level: there is no chunk-level shortcut
//! without lookup arguments. We bit-decompose every word and constrain
//! the XOR per bit. The chip also exposes the inputs/outputs in the
//! same 4×16-bit chunk form as `word64_add` so the two chips compose
//! without an intermediate "bits-to-chunks" gadget.
//!
//! ## Layout (one operation per row, allocated at `start_col`)
//!
//! | offset    | width | name      |
//! |-----------|-------|-----------|
//! | 0         | 4     | a chunks  |
//! | 4         | 4     | b chunks  |
//! | 8         | 4     | c chunks  |
//! | 12        | 64    | a bits    |
//! | 76        | 64    | b bits    |
//! | 140       | 64    | c bits    |
//!
//! Total: **204 columns**, **268 constraints** (degree 2 max).
//!
//! ## Constraints
//!
//! - 192 boolean checks: each of the 192 bit columns satisfies `b·(1-b) = 0`.
//! - 12 chunk-recomposition checks: each chunk equals `Σ_{k=0..16} bit[k] · 2ᵏ`.
//! - 64 per-bit XOR checks: `c_bit[i] = a_bit[i] + b_bit[i] - 2·a_bit[i]·b_bit[i]`.
//!
//! ## Soundness
//!
//! Boolean and chunk-recomposition constraints make the bit cols sound
//! on their own — no separate range checks needed for the bits. The
//! chunk cols are bound to their bit cols by the recomposition
//! constraints; if a malicious prover puts an out-of-range chunk it
//! cannot decompose into 16 bools matching the recomposition. So this
//! chip is fully sound stand-alone — no lookup gap.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

pub const NUM_CHUNKS: usize = 4;
pub const CHUNK_BITS: usize = 16;
pub const NUM_BITS: usize = 64;

pub mod col {
    use super::{NUM_BITS, NUM_CHUNKS};
    pub const A_CHUNKS: usize = 0;
    pub const B_CHUNKS: usize = A_CHUNKS + NUM_CHUNKS; // 4
    pub const C_CHUNKS: usize = B_CHUNKS + NUM_CHUNKS; // 8
    pub const A_BITS: usize = C_CHUNKS + NUM_CHUNKS;   // 12
    pub const B_BITS: usize = A_BITS + NUM_BITS;       // 76
    pub const C_BITS: usize = B_BITS + NUM_BITS;       // 140
}

pub const NUM_COLS: usize = col::C_BITS + NUM_BITS; // 204
pub const NUM_CONSTRAINTS: usize = 3 * NUM_BITS // bool checks
    + 3 * NUM_CHUNKS                            // chunk recompositions
    + NUM_BITS;                                  // per-bit XOR

#[derive(Debug, Clone, Copy)]
pub struct Word64XorChip {
    pub start_col: usize,
}

impl Word64XorChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();

        // ── Boolean checks on every bit column ────────────────────────
        for i in 0..NUM_BITS {
            let a_bit = row[self.start_col + col::A_BITS + i];
            let b_bit = row[self.start_col + col::B_BITS + i];
            let c_bit = row[self.start_col + col::C_BITS + i];
            builder.assert_bool(a_bit);
            builder.assert_bool(b_bit);
            builder.assert_bool(c_bit);
        }

        // ── Chunk recomposition: chunk = Σ bit[k] · 2^k ──────────────
        for chunk_idx in 0..NUM_CHUNKS {
            let bit_base = chunk_idx * CHUNK_BITS;

            let mut a_acc = AB::Expr::ZERO;
            let mut b_acc = AB::Expr::ZERO;
            let mut c_acc = AB::Expr::ZERO;
            let mut weight: u64 = 1;
            for k in 0..CHUNK_BITS {
                let a_bit = row[self.start_col + col::A_BITS + bit_base + k];
                let b_bit = row[self.start_col + col::B_BITS + bit_base + k];
                let c_bit = row[self.start_col + col::C_BITS + bit_base + k];
                let w = AB::Expr::from_u64(weight);
                a_acc = a_acc + w.clone() * a_bit.into();
                b_acc = b_acc + w.clone() * b_bit.into();
                c_acc = c_acc + w * c_bit.into();
                weight <<= 1;
            }
            let a_chunk = row[self.start_col + col::A_CHUNKS + chunk_idx];
            let b_chunk = row[self.start_col + col::B_CHUNKS + chunk_idx];
            let c_chunk = row[self.start_col + col::C_CHUNKS + chunk_idx];
            builder.assert_eq(a_chunk, a_acc);
            builder.assert_eq(b_chunk, b_acc);
            builder.assert_eq(c_chunk, c_acc);
        }

        // ── Per-bit XOR: c_bit = a_bit + b_bit - 2·a_bit·b_bit ───────
        let two = AB::Expr::from_u64(2);
        for i in 0..NUM_BITS {
            let a_bit = row[self.start_col + col::A_BITS + i];
            let b_bit = row[self.start_col + col::B_BITS + i];
            let c_bit = row[self.start_col + col::C_BITS + i];
            builder.assert_eq(c_bit, a_bit.into() + b_bit.into() - two.clone() * (a_bit.into() * b_bit.into()));
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Word64XorTestAir;

impl<F: Field> BaseAir<F> for Word64XorTestAir {
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

impl<AB: AirBuilder> Air<AB> for Word64XorTestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        Word64XorChip::new().emit(builder);
    }
}

/// Witness layout for one 64-bit XOR.
#[derive(Debug, Clone, Copy)]
pub struct Word64XorWitness {
    pub a_chunks: [u64; NUM_CHUNKS],
    pub b_chunks: [u64; NUM_CHUNKS],
    pub c_chunks: [u64; NUM_CHUNKS],
    pub a_bits: [u64; NUM_BITS],
    pub b_bits: [u64; NUM_BITS],
    pub c_bits: [u64; NUM_BITS],
}

/// Compute `c = a ^ b` and return all witness columns.
pub fn compute_xor64(a: u64, b: u64) -> Word64XorWitness {
    let c = a ^ b;
    let mut a_bits = [0u64; NUM_BITS];
    let mut b_bits = [0u64; NUM_BITS];
    let mut c_bits = [0u64; NUM_BITS];
    for i in 0..NUM_BITS {
        a_bits[i] = (a >> i) & 1;
        b_bits[i] = (b >> i) & 1;
        c_bits[i] = (c >> i) & 1;
    }
    Word64XorWitness {
        a_chunks: super::word64_add::decompose_u64(a),
        b_chunks: super::word64_add::decompose_u64(b),
        c_chunks: super::word64_add::decompose_u64(c),
        a_bits,
        b_bits,
        c_bits,
    }
}

/// Build a single-row test trace exercising one XOR. Pads rows 1..3 with
/// zeros (which trivially satisfy: 0 = 0, 0·(1-0) = 0).
pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(w: &Word64XorWitness) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];
    for i in 0..NUM_CHUNKS {
        values[col::A_CHUNKS + i] = F::from_u64(w.a_chunks[i]);
        values[col::B_CHUNKS + i] = F::from_u64(w.b_chunks[i]);
        values[col::C_CHUNKS + i] = F::from_u64(w.c_chunks[i]);
    }
    for i in 0..NUM_BITS {
        values[col::A_BITS + i] = F::from_u64(w.a_bits[i]);
        values[col::B_BITS + i] = F::from_u64(w.b_bits[i]);
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

    #[test]
    fn xor64_zero_xor_zero_is_zero() {
        let w = compute_xor64(0, 0);
        assert_eq!(recompose_u64(&w.c_chunks), 0);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64XorTestAir, &trace, &[]);
    }

    #[test]
    fn xor64_self_is_zero() {
        let w = compute_xor64(0xDEAD_BEEF_CAFE_BABE, 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(recompose_u64(&w.c_chunks), 0);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64XorTestAir, &trace, &[]);
    }

    #[test]
    fn xor64_with_zero_is_identity() {
        let w = compute_xor64(0xCAFE_BABE_1234_5678, 0);
        assert_eq!(recompose_u64(&w.c_chunks), 0xCAFE_BABE_1234_5678);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64XorTestAir, &trace, &[]);
    }

    #[test]
    fn xor64_with_all_ones_is_negation() {
        let w = compute_xor64(0xCAFE_BABE_1234_5678, u64::MAX);
        assert_eq!(recompose_u64(&w.c_chunks), !0xCAFE_BABE_1234_5678);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64XorTestAir, &trace, &[]);
    }

    #[test]
    fn xor64_commutativity() {
        let a = 0x1234_5678_9ABC_DEF0;
        let b = 0xFEDC_BA09_8765_4321;
        let w_ab = compute_xor64(a, b);
        let w_ba = compute_xor64(b, a);
        assert_eq!(w_ab.c_chunks, w_ba.c_chunks);
    }

    #[test]
    fn xor64_involution() {
        // (a XOR b) XOR b = a
        let a = 0xCAFE_BABE_DEAD_BEEF;
        let b = 0x1234_5678_9ABC_DEF0;
        let ab = a ^ b;
        let w = compute_xor64(ab, b);
        assert_eq!(recompose_u64(&w.c_chunks), a);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64XorTestAir, &trace, &[]);
    }

    #[test]
    fn xor64_matches_native_for_corner_cases() {
        let cases: [(u64, u64); 8] = [
            (0, 0),
            (1, 1),
            (0xAAAA_AAAA_AAAA_AAAA, 0x5555_5555_5555_5555),
            (u64::MAX, 0),
            (u64::MAX, u64::MAX),
            (0xDEAD_BEEF_CAFE_BABE, 0x0123_4567_89AB_CDEF),
            (0x8000_0000_0000_0000, 0x0000_0000_0000_0001),
            (0x0F0F_0F0F_0F0F_0F0F, 0xF0F0_F0F0_F0F0_F0F0),
        ];
        for (a, b) in cases {
            let w = compute_xor64(a, b);
            assert_eq!(recompose_u64(&w.c_chunks), a ^ b, "mismatch for {a:#x} XOR {b:#x}");
            let trace = build_test_trace::<BabyBear>(&w);
            check_constraints(&Word64XorTestAir, &trace, &[]);
        }
    }

    #[test]
    fn xor64_bit_decomposition_round_trip() {
        let a = 0xCAFE_BABE_1234_5678;
        let w = compute_xor64(a, 0);
        // Reconstruct a from a_bits.
        let mut acc = 0u64;
        for i in 0..NUM_BITS {
            acc |= w.a_bits[i] << i;
        }
        assert_eq!(acc, a, "a_bits should reconstruct to a");
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn xor64_rejects_tampered_c_bit() {
        let w = compute_xor64(0x1234, 0x5678);
        let mut trace = build_test_trace::<BabyBear>(&w);
        // Flip c bit 0 — XOR constraint must reject.
        trace.values[col::C_BITS] = trace.values[col::C_BITS] + BabyBear::ONE;
        check_constraints(&Word64XorTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn xor64_rejects_non_boolean_a_bit() {
        let w = compute_xor64(0, 0);
        let mut trace = build_test_trace::<BabyBear>(&w);
        // Set a_bit 0 to 2 — boolean check must reject.
        trace.values[col::A_BITS] = BabyBear::from_u64(2);
        check_constraints(&Word64XorTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn xor64_rejects_chunk_inconsistent_with_bits() {
        let w = compute_xor64(0x1111, 0x2222);
        let mut trace = build_test_trace::<BabyBear>(&w);
        // Mutate a_chunks[0] without updating a_bits — recomposition rejects.
        trace.values[col::A_CHUNKS] = trace.values[col::A_CHUNKS] + BabyBear::ONE;
        check_constraints(&Word64XorTestAir, &trace, &[]);
    }

    #[test]
    fn constraint_count_matches_documented() {
        assert_eq!(NUM_COLS, 204);
        assert_eq!(NUM_CONSTRAINTS, 268);
    }
}
