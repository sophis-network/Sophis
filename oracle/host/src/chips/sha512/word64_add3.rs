//! `sha512::word64_add3` — 3-input 64-bit modular addition AIR chip.
//!
//! Computes `out = (a + b + c) mod 2⁶⁴` in a single chip. Useful for
//! SHA-512's round where many 3-way and longer sums occur — replacing
//! a chain of two `Word64AddChip` instances with a single `Word64Add3Chip`
//! saves ~12 columns (one chip's footprint minus a few connection cols)
//! per substitution.
//!
//! ## Decomposition
//!
//! Same 4×16-bit chunking as `word64_add`. Per-chunk add chains a single
//! carry, but now the maximum chunk-level RHS is `3·(2¹⁶-1) + carry`,
//! so the carry can grow up to `3` (vs `2` in the 2-input case).
//!
//! ## Layout (one operation per row, allocated at `start_col`)
//!
//! | offset | width | name           |
//! |--------|-------|----------------|
//! | 0      | 4     | a chunks       |
//! | 4      | 4     | b chunks       |
//! | 8      | 4     | c chunks       |
//! | 12     | 4     | out chunks     |
//! | 16     | 4     | carry[1..5]    |
//!
//! Total: **284 columns**, **288 constraints**, max degree 2.
//!
//! ## Layout (post sub-fase 3.7.1)
//!
//! | offset   | width | name             |
//! |----------|-------|------------------|
//! | 0        | 4     | a chunks         |
//! | 4        | 4     | b chunks         |
//! | 8        | 4     | c chunks         |
//! | 12       | 4     | out chunks       |
//! | 16       | 4     | carry[1..5]      |
//! | 20       | 64    | a bits (4×16)    |
//! | 84       | 64    | b bits (4×16)    |
//! | 148      | 64    | c bits (4×16)    |
//! | 212      | 64    | out bits (4×16)  |
//! | 276      | 8     | carry bits (4×2) |
//!
//! ## Soundness (sub-fase 3.7.1)
//!
//! Bit decomposition closes the BabyBear-overflow gap stand-alone:
//!
//! - 16-bit range checks on `a`, `b`, `c`, `out` chunks — boolean +
//!   recomposition via [`Range16Chip`](crate::chips::lookup::range_n::Range16Chip).
//! - 2-bit range checks on each carry — `carry ∈ [0, 4)`. Max
//!   carry-out is `⌊(3·(2¹⁶-1) + 3) / 2¹⁶⌋ = 3`, so 2 bits is exact.
//!
//! With all chunks ∈ [0, 2¹⁶) and all carries ∈ [0, 4), the linear add
//! chain `out_i + 2¹⁶·carry_out = a_i + b_i + c_i + carry_in` becomes
//! injective: `out_i` is uniquely determined as the field element in
//! [0, 2¹⁶) that satisfies the equation, so a malicious prover cannot
//! pick a non-canonical `(out, carry_out)` pair.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::chips::lookup::range_n::{Range16Chip, RangeNChip};

pub const NUM_CHUNKS: usize = 4;
pub const CHUNK_BITS: usize = 16;
pub const CHUNK_MOD: u64 = 1u64 << CHUNK_BITS;
pub const CARRY_BITS: usize = 2;

pub mod col {
    use super::{CARRY_BITS, NUM_CHUNKS};
    pub const A: usize = 0;
    pub const B: usize = A + NUM_CHUNKS;       // 4
    pub const C: usize = B + NUM_CHUNKS;       // 8
    pub const OUT: usize = C + NUM_CHUNKS;     // 12
    pub const CARRY: usize = OUT + NUM_CHUNKS; // 16
    pub const A_BITS: usize = CARRY + NUM_CHUNKS;          // 20
    pub const B_BITS: usize = A_BITS + NUM_CHUNKS * 16;    // 84
    pub const C_BITS: usize = B_BITS + NUM_CHUNKS * 16;    // 148
    pub const OUT_BITS: usize = C_BITS + NUM_CHUNKS * 16;  // 212
    pub const CARRY_BITS_OFF: usize = OUT_BITS + NUM_CHUNKS * 16; // 276
}

pub const NUM_COLS: usize = col::CARRY_BITS_OFF + NUM_CHUNKS * CARRY_BITS; // 284
pub const NUM_CONSTRAINTS: usize =
    NUM_CHUNKS                                  // 4: linear add chain
    + 4 * NUM_CHUNKS * (1 + 16)                 // 4 vars × 4 chunks × (16 bool + 1 recomp) = 272
    + NUM_CHUNKS * (1 + CARRY_BITS);            // 4 carries × (2 bool + 1 recomp) = 12
// Total: 4 + 272 + 12 = 288.

#[derive(Debug, Clone, Copy)]
pub struct Word64Add3Chip {
    pub start_col: usize,
}

impl Word64Add3Chip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        // Sub-fase 3.7.1: 16-bit range checks on a, b, c, out chunks +
        // 2-bit range checks on carries. See module docs for soundness
        // argument.
        for i in 0..NUM_CHUNKS {
            Range16Chip::split(self.start_col + col::A + i, self.start_col + col::A_BITS + i * 16).emit(builder);
            Range16Chip::split(self.start_col + col::B + i, self.start_col + col::B_BITS + i * 16).emit(builder);
            Range16Chip::split(self.start_col + col::C + i, self.start_col + col::C_BITS + i * 16).emit(builder);
            Range16Chip::split(self.start_col + col::OUT + i, self.start_col + col::OUT_BITS + i * 16).emit(builder);
            RangeNChip::<2>::split(
                self.start_col + col::CARRY + i,
                self.start_col + col::CARRY_BITS_OFF + i * CARRY_BITS,
            )
            .emit(builder);
        }

        let main = builder.main();
        let row = main.current_slice();
        let two_pow_16 = AB::Expr::from_u64(CHUNK_MOD);

        let mut carry_in: AB::Expr = AB::Expr::ZERO;
        for i in 0..NUM_CHUNKS {
            let a_i = row[self.start_col + col::A + i];
            let b_i = row[self.start_col + col::B + i];
            let c_i = row[self.start_col + col::C + i];
            let out_i = row[self.start_col + col::OUT + i];
            let carry_out = row[self.start_col + col::CARRY + i];

            // out[i] + 2^16 * carry_out = a[i] + b[i] + c[i] + carry_in
            builder.assert_eq(
                out_i.into() + two_pow_16.clone() * carry_out.into(),
                a_i.into() + b_i.into() + c_i.into() + carry_in,
            );

            carry_in = carry_out.into();
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Word64Add3TestAir;

impl<F: Field> BaseAir<F> for Word64Add3TestAir {
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

impl<AB: AirBuilder> Air<AB> for Word64Add3TestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        Word64Add3Chip::new().emit(builder);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Word64Add3Witness {
    pub a_chunks: [u64; NUM_CHUNKS],
    pub b_chunks: [u64; NUM_CHUNKS],
    pub c_chunks: [u64; NUM_CHUNKS],
    pub out_chunks: [u64; NUM_CHUNKS],
    pub carries: [u64; NUM_CHUNKS],
}

pub fn compute_add3_64(a: u64, b: u64, c: u64) -> Word64Add3Witness {
    let a_chunks = super::word64_add::decompose_u64(a);
    let b_chunks = super::word64_add::decompose_u64(b);
    let c_chunks = super::word64_add::decompose_u64(c);
    let mut out_chunks = [0u64; NUM_CHUNKS];
    let mut carries = [0u64; NUM_CHUNKS];
    let mut carry: u64 = 0;
    for i in 0..NUM_CHUNKS {
        let total = a_chunks[i] + b_chunks[i] + c_chunks[i] + carry;
        out_chunks[i] = total & (CHUNK_MOD - 1);
        carry = total >> CHUNK_BITS;
        carries[i] = carry;
    }
    Word64Add3Witness { a_chunks, b_chunks, c_chunks, out_chunks, carries }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(w: &Word64Add3Witness) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];
    for i in 0..NUM_CHUNKS {
        values[col::A + i] = F::from_u64(w.a_chunks[i]);
        values[col::B + i] = F::from_u64(w.b_chunks[i]);
        values[col::C + i] = F::from_u64(w.c_chunks[i]);
        values[col::OUT + i] = F::from_u64(w.out_chunks[i]);
        values[col::CARRY + i] = F::from_u64(w.carries[i]);
        Range16Chip::populate_bits::<F>(&mut values, col::A_BITS + i * 16, w.a_chunks[i]);
        Range16Chip::populate_bits::<F>(&mut values, col::B_BITS + i * 16, w.b_chunks[i]);
        Range16Chip::populate_bits::<F>(&mut values, col::C_BITS + i * 16, w.c_chunks[i]);
        Range16Chip::populate_bits::<F>(&mut values, col::OUT_BITS + i * 16, w.out_chunks[i]);
        RangeNChip::<2>::populate_bits::<F>(&mut values, col::CARRY_BITS_OFF + i * CARRY_BITS, w.carries[i]);
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
    fn add3_zero_zero_zero() {
        let w = compute_add3_64(0, 0, 0);
        assert_eq!(recompose_u64(&w.out_chunks), 0);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64Add3TestAir, &trace, &[]);
    }

    #[test]
    fn add3_one_two_three_is_six() {
        let w = compute_add3_64(1, 2, 3);
        assert_eq!(recompose_u64(&w.out_chunks), 6);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64Add3TestAir, &trace, &[]);
    }

    #[test]
    fn add3_three_max_chunks_carry_2() {
        // a = b = c = 0xFFFF in chunk 0: sum = 3 * 0xFFFF = 0x2FFFD.
        // out chunk 0 = 0xFFFD, carry to chunk 1 = 2.
        let w = compute_add3_64(0xFFFF, 0xFFFF, 0xFFFF);
        assert_eq!(w.out_chunks[0], 0xFFFD);
        assert_eq!(w.carries[0], 2);
        // Chunks 1..3 of a,b,c are 0; with carry_in=2: out[1] = 2, carries[1] = 0.
        assert_eq!(w.out_chunks[1], 2);
        assert_eq!(w.carries[1], 0);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64Add3TestAir, &trace, &[]);
    }

    #[test]
    fn add3_full_overflow_wraps() {
        // (2^64 - 1) + 1 + 0 = 2^64 ≡ 0 mod 2^64.
        let w = compute_add3_64(u64::MAX, 1, 0);
        assert_eq!(recompose_u64(&w.out_chunks), 0);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64Add3TestAir, &trace, &[]);
    }

    #[test]
    fn add3_3max_wraps_correctly() {
        // 3 * (2^64 - 1) mod 2^64 = -3 mod 2^64 = 2^64 - 3.
        let w = compute_add3_64(u64::MAX, u64::MAX, u64::MAX);
        assert_eq!(recompose_u64(&w.out_chunks), u64::MAX - 2);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64Add3TestAir, &trace, &[]);
    }

    #[test]
    fn add3_matches_native_for_corner_cases() {
        let cases: [(u64, u64, u64); 7] = [
            (0, 0, 0),
            (1, 1, 1),
            (0xAAAA_AAAA_AAAA_AAAA, 0x5555_5555_5555_5555, u64::MAX),
            (u64::MAX, 0, 0),
            (u64::MAX, u64::MAX, 1),
            (0xDEAD_BEEF_CAFE_BABE, 0x0123_4567_89AB_CDEF, 0xFEDC_BA09_8765_4321),
            (0x8000_0000_0000_0000, 0x4000_0000_0000_0000, 0x2000_0000_0000_0000),
        ];
        for (a, b, c) in cases {
            let w = compute_add3_64(a, b, c);
            assert_eq!(
                recompose_u64(&w.out_chunks),
                a.wrapping_add(b).wrapping_add(c),
                "mismatch for {a:#x} + {b:#x} + {c:#x}"
            );
            let trace = build_test_trace::<BabyBear>(&w);
            check_constraints(&Word64Add3TestAir, &trace, &[]);
        }
    }

    #[test]
    fn add3_matches_chained_word64_add() {
        // a + b + c via Word64Add3Chip should equal (a + b) + c via two Word64Add chips.
        let a = 0x1234_5678_9ABC_DEF0u64;
        let b = 0xFEDC_BA09_8765_4321u64;
        let c = 0xDEAD_BEEF_CAFE_BABEu64;
        let w_3 = compute_add3_64(a, b, c);
        let chained = a.wrapping_add(b).wrapping_add(c);
        assert_eq!(recompose_u64(&w_3.out_chunks), chained);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add3_rejects_tampered_out() {
        let w = compute_add3_64(0xCAFE, 0xBABE, 0xDEAD);
        let mut trace = build_test_trace::<BabyBear>(&w);
        trace.values[col::OUT] = trace.values[col::OUT] + BabyBear::ONE;
        check_constraints(&Word64Add3TestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add3_rejects_tampered_carry() {
        // Force a real carry, then tamper.
        let w = compute_add3_64(0xFFFF, 0xFFFF, 0xFFFF);
        let mut trace = build_test_trace::<BabyBear>(&w);
        trace.values[col::CARRY] = trace.values[col::CARRY] + BabyBear::ONE;
        check_constraints(&Word64Add3TestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add3_rejects_out_of_range_a_chunk() {
        // Sub-fase 3.7.1: a[0] = 65536 must be rejected by Range16Chip
        // even though the bits stay zero. Without 3.7.1 a malicious
        // prover could embed a non-canonical chunk.
        let w = compute_add3_64(0, 0, 0);
        let mut trace = build_test_trace::<BabyBear>(&w);
        trace.values[col::A] = BabyBear::from_u64(65_536);
        check_constraints(&Word64Add3TestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add3_rejects_carry_above_3() {
        // Carry max is 3 (= 2 bits). A carry of 4 must be rejected.
        let w = compute_add3_64(0xFFFF, 0xFFFF, 0xFFFF);
        let mut trace = build_test_trace::<BabyBear>(&w);
        // Real carry[0] = 2 → tamper to 4 (overflows 2-bit cap).
        trace.values[col::CARRY] = BabyBear::from_u64(4);
        check_constraints(&Word64Add3TestAir, &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        // Sub-fase 3.7.1: NUM_COLS 20 → 284 (+264 bit cells: 4×4×16 +
        // 4×2). NUM_CONSTRAINTS 4 → 288 (+272 chunk range checks +
        // 12 carry range checks).
        assert_eq!(NUM_COLS, 284);
        assert_eq!(NUM_CONSTRAINTS, 288);
    }
}
