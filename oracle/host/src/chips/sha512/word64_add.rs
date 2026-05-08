//! `sha512::word64_add` — 64-bit modular addition AIR chip.
//!
//! SHA-512 performs many `(a + b) mod 2⁶⁴` operations: T1, T2, the
//! final-state add-back, every step of the message schedule. This chip
//! constrains one such addition.
//!
//! ## Decomposition
//!
//! 64-bit values do not fit a single BabyBear element (~2³¹). We split
//! every word into **four 16-bit chunks** (LSB-first):
//!
//!   `w = w[0] + 2¹⁶·w[1] + 2³²·w[2] + 2⁴⁸·w[3]`   with `0 ≤ w[i] < 2¹⁶`
//!
//! The chunk-level add chains a single carry:
//!
//!   `c[i] + 2¹⁶ · carry[i+1] = a[i] + b[i] + carry[i]`   for `i ∈ [0, 4)`
//!
//! `carry[0] = 0` (boundary); `carry[4]` is the 65th-bit overflow, which
//! the caller discards (mod 2⁶⁴ semantics) or wires elsewhere.
//!
//! ## BabyBear sizing
//!
//! Each chunk is `< 2¹⁶`. Per-step RHS bound:
//!   `a[i] + b[i] + carry[i] ≤ 2 · (2¹⁶ - 1) + 2 ≈ 2¹⁷`.
//! Comfortably below BabyBear's ~2³¹.
//!
//! ## Trace layout (one operation per row, allocated at `start_col`)
//!
//! | offset      | width | name                  |
//! |-------------|-------|-----------------------|
//! | 0           | 4     | a chunks (16-bit)     |
//! | 4           | 4     | b chunks (16-bit)     |
//! | 8           | 4     | c chunks (16-bit)     |
//! | 12          | 4     | carry[1..5] (bool)    |
//! | 16..80      | 64    | a chunk bit decomp    |  (sub-fase 3.7.0)
//! | 80..144     | 64    | b chunk bit decomp    |
//! | 144..208    | 64    | c chunk bit decomp    |
//!
//! Total: **208 columns** (was 16 pre-3.7.0).
//!
//! ## Soundness (closed in sub-fase 3.7.0)
//!
//! Sub-fase 3.7.0 (Etapa 3.7) closes the BabyBear-overflow soundness gap
//! that was previously documented as "closes when the shared 16-bit
//! lookup table lands". Bit decomposition (`Range16Chip` split layout)
//! forces every `a[i]`, `b[i]`, `c[i]` chunk into `[0, 2¹⁶)`. Each
//! `carry[i]` cell is also `assert_bool`-checked in `[0, 1)` since the
//! sum of two 16-bit chunks plus a 1-bit carry-in caps at `2¹⁷ - 1` so
//! the carry-out is always 0 or 1. After this sub-fase a malicious
//! prover can no longer exploit BabyBear overflow via out-of-range
//! chunks to satisfy the linear equation with wrong arithmetic.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::chips::lookup::range_n::Range16Chip;

pub const NUM_CHUNKS: usize = 4;
pub const CHUNK_BITS: usize = 16;
pub const CHUNK_MOD: u64 = 1u64 << CHUNK_BITS; // 65536

pub mod col {
    use super::NUM_CHUNKS;
    pub const A: usize = 0;
    pub const B: usize = A + NUM_CHUNKS; // 4
    pub const C: usize = B + NUM_CHUNKS; // 8
    pub const CARRY: usize = C + NUM_CHUNKS; // 12 (holds carry[1..5])
    /// Sub-fase 3.7.0 — bit decomposition for `a` chunks (4 × 16 bits = 64 cells).
    pub const A_BITS: usize = CARRY + NUM_CHUNKS; // 16
    /// Sub-fase 3.7.0 — bit decomposition for `b` chunks.
    pub const B_BITS: usize = A_BITS + NUM_CHUNKS * 16; // 80
    /// Sub-fase 3.7.0 — bit decomposition for `c` chunks.
    pub const C_BITS: usize = B_BITS + NUM_CHUNKS * 16; // 144
}

pub const NUM_COLS: usize = col::C_BITS + NUM_CHUNKS * 16; // 208
pub const NUM_CONSTRAINTS: usize = NUM_CHUNKS; // 4 (linear adds only; range/bool extras are degree 2)

#[derive(Debug, Clone, Copy)]
pub struct Word64AddChip {
    pub start_col: usize,
}

impl Word64AddChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        // Sub-fase 3.7.0 — emit 16-bit range checks on every a/b/c chunk
        // BEFORE the linear add chain so the linear equation can't be
        // satisfied via out-of-range BabyBear values.
        for i in 0..NUM_CHUNKS {
            Range16Chip::split(
                self.start_col + col::A + i,
                self.start_col + col::A_BITS + i * 16,
            )
            .emit(builder);
            Range16Chip::split(
                self.start_col + col::B + i,
                self.start_col + col::B_BITS + i * 16,
            )
            .emit(builder);
            Range16Chip::split(
                self.start_col + col::C + i,
                self.start_col + col::C_BITS + i * 16,
            )
            .emit(builder);
        }

        let main = builder.main();
        let row = main.current_slice();
        let two_pow_16 = AB::Expr::from_u64(CHUNK_MOD);

        // Sub-fase 3.7.0 — carry cells are bool (0 or 1), since a sum of
        // two 16-bit chunks + a 1-bit carry-in is at most 2·(2¹⁶-1) + 1 =
        // 131_071 < 2¹⁷, so the next carry-out fits in 1 bit.
        for i in 0..NUM_CHUNKS {
            builder.assert_bool(row[self.start_col + col::CARRY + i]);
        }

        let mut carry_in: AB::Expr = AB::Expr::ZERO;
        for i in 0..NUM_CHUNKS {
            let a_i = row[self.start_col + col::A + i];
            let b_i = row[self.start_col + col::B + i];
            let c_i = row[self.start_col + col::C + i];
            let carry_out = row[self.start_col + col::CARRY + i];

            // c[i] + 2^16 * carry_out = a[i] + b[i] + carry_in
            builder.assert_eq(
                c_i.into() + two_pow_16.clone() * carry_out.into(),
                a_i.into() + b_i.into() + carry_in,
            );

            carry_in = carry_out.into();
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Word64AddTestAir;

impl<F: Field> BaseAir<F> for Word64AddTestAir {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        // Sub-fase 3.7.0 boolean checks (assert_bool) are degree 2.
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for Word64AddTestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        Word64AddChip::new().emit(builder);
    }
}

/// Witness layout for one 64-bit modular addition.
#[derive(Debug, Clone, Copy)]
pub struct Word64AddWitness {
    pub a_chunks: [u64; NUM_CHUNKS],
    pub b_chunks: [u64; NUM_CHUNKS],
    pub c_chunks: [u64; NUM_CHUNKS],
    /// `carries[i]` = carry out of chunk `i` (i.e. carry into chunk `i+1`).
    /// `carries[NUM_CHUNKS - 1]` is the 65th-bit overflow.
    pub carries: [u64; NUM_CHUNKS],
}

/// Compute `c = (a + b) mod 2⁶⁴` and return all witness columns.
pub fn compute_add64(a: u64, b: u64) -> Word64AddWitness {
    let a_chunks = decompose_u64(a);
    let b_chunks = decompose_u64(b);
    let mut c_chunks = [0u64; NUM_CHUNKS];
    let mut carries = [0u64; NUM_CHUNKS];
    let mut carry: u64 = 0;
    for i in 0..NUM_CHUNKS {
        let total = a_chunks[i] + b_chunks[i] + carry;
        c_chunks[i] = total & (CHUNK_MOD - 1);
        carry = total >> CHUNK_BITS;
        carries[i] = carry;
    }
    Word64AddWitness { a_chunks, b_chunks, c_chunks, carries }
}

/// Decompose a `u64` into 4 little-endian 16-bit chunks.
pub fn decompose_u64(w: u64) -> [u64; NUM_CHUNKS] {
    [
        w & 0xFFFF,
        (w >> 16) & 0xFFFF,
        (w >> 32) & 0xFFFF,
        (w >> 48) & 0xFFFF,
    ]
}

/// Recompose 4 16-bit chunks back into a `u64` (low chunk first).
pub fn recompose_u64(chunks: &[u64; NUM_CHUNKS]) -> u64 {
    chunks[0] | (chunks[1] << 16) | (chunks[2] << 32) | (chunks[3] << 48)
}

/// Build a single-row test trace exercising one add. Pads rows 1..3 with
/// zeros (which trivially satisfy 0 + 0 + 0 = 0 + 0, including the new
/// bit decomposition cells which all become zero — and zero is in
/// range / boolean).
pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(w: &Word64AddWitness) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];
    for i in 0..NUM_CHUNKS {
        values[col::A + i] = F::from_u64(w.a_chunks[i]);
        values[col::B + i] = F::from_u64(w.b_chunks[i]);
        values[col::C + i] = F::from_u64(w.c_chunks[i]);
        values[col::CARRY + i] = F::from_u64(w.carries[i]);
        // Sub-fase 3.7.0 — populate bit decomposition cells.
        Range16Chip::populate_bits::<F>(&mut values, col::A_BITS + i * 16, w.a_chunks[i]);
        Range16Chip::populate_bits::<F>(&mut values, col::B_BITS + i * 16, w.b_chunks[i]);
        Range16Chip::populate_bits::<F>(&mut values, col::C_BITS + i * 16, w.c_chunks[i]);
    }
    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    #[test]
    fn add64_zero_plus_zero() {
        let w = compute_add64(0, 0);
        assert_eq!(recompose_u64(&w.c_chunks), 0);
        assert_eq!(w.carries, [0u64; NUM_CHUNKS]);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64AddTestAir, &trace, &[]);
    }

    #[test]
    fn add64_no_carry() {
        let w = compute_add64(0x0001_0002_0003_0004, 0x1000_2000_3000_4000);
        assert_eq!(recompose_u64(&w.c_chunks), 0x0001_0002_0003_0004 + 0x1000_2000_3000_4000);
        assert_eq!(w.carries, [0u64; NUM_CHUNKS]);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64AddTestAir, &trace, &[]);
    }

    #[test]
    fn add64_chunk_carry_propagates() {
        // 0xFFFF + 1 = 0x10000: chunk 0 overflows, carry goes into chunk 1.
        let w = compute_add64(0xFFFF, 1);
        assert_eq!(w.c_chunks[0], 0);
        assert_eq!(w.c_chunks[1], 1);
        assert_eq!(w.c_chunks[2], 0);
        assert_eq!(w.c_chunks[3], 0);
        assert_eq!(w.carries[0], 1);
        assert_eq!(w.carries[1], 0);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64AddTestAir, &trace, &[]);
    }

    #[test]
    fn add64_full_overflow_wraps_to_zero() {
        // (2^64 - 1) + 1 = 2^64 ≡ 0 (mod 2^64). Carry-out from chunk 3 = 1, discarded.
        let w = compute_add64(u64::MAX, 1);
        assert_eq!(recompose_u64(&w.c_chunks), 0);
        for i in 0..NUM_CHUNKS - 1 {
            assert_eq!(w.carries[i], 1, "carry out of chunk {i} should be 1 (chain)");
        }
        assert_eq!(w.carries[NUM_CHUNKS - 1], 1, "65th-bit overflow recorded");
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64AddTestAir, &trace, &[]);
    }

    #[test]
    fn add64_random_arithmetic() {
        let a = 0x1234_5678_9ABC_DEF0u64;
        let b = 0xFEDC_BA09_8765_4321u64;
        let w = compute_add64(a, b);
        assert_eq!(recompose_u64(&w.c_chunks), a.wrapping_add(b));
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64AddTestAir, &trace, &[]);
    }

    #[test]
    fn add64_chain_of_carries() {
        // a = 0xFFFF_FFFF_FFFF_FFFE, b = 1: chunks 0,1,2 are FFFF; only chunk 3 differs.
        // Adding 1 forces chunk 0 to wrap, carry through 1, 2; chunk 3 stays the same with carry consumed.
        let a = 0xFFFE_FFFF_FFFF_FFFFu64;
        let b = 1u64;
        let w = compute_add64(a, b);
        assert_eq!(recompose_u64(&w.c_chunks), a.wrapping_add(b));
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64AddTestAir, &trace, &[]);
    }

    #[test]
    fn add64_matches_native_wrapping_add_for_many_inputs() {
        let cases: [(u64, u64); 8] = [
            (0, 0),
            (1, 1),
            (0xDEAD_BEEF_CAFE_BABE, 0x0123_4567_89AB_CDEF),
            (u64::MAX, 0),
            (u64::MAX, 1),
            (u64::MAX, u64::MAX),
            (0x8000_0000_0000_0000, 0x8000_0000_0000_0000),
            (0xAAAA_AAAA_AAAA_AAAA, 0x5555_5555_5555_5555),
        ];
        for (a, b) in cases {
            let w = compute_add64(a, b);
            assert_eq!(recompose_u64(&w.c_chunks), a.wrapping_add(b), "mismatch for {a:#x} + {b:#x}");
            let trace = build_test_trace::<BabyBear>(&w);
            check_constraints(&Word64AddTestAir, &trace, &[]);
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add64_rejects_tampered_chunk() {
        let w = compute_add64(0xCAFE, 0xBABE);
        let mut trace = build_test_trace::<BabyBear>(&w);
        // Flip output chunk 0.
        trace.values[col::C] = trace.values[col::C] + BabyBear::ONE;
        check_constraints(&Word64AddTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add64_rejects_tampered_carry() {
        // Force a real carry, then mutate the carry column.
        let w = compute_add64(0xFFFF, 1);
        let mut trace = build_test_trace::<BabyBear>(&w);
        trace.values[col::CARRY] = trace.values[col::CARRY] + BabyBear::ONE; // bogus carry
        check_constraints(&Word64AddTestAir, &trace, &[]);
    }

    #[test]
    fn decompose_recompose_round_trip() {
        let cases: [u64; 5] = [0, 1, 0xFFFF, 0xCAFEBABE, 0xDEADBEEFCAFEBABE];
        for w in cases {
            assert_eq!(recompose_u64(&decompose_u64(w)), w);
        }
    }

    #[test]
    fn constraint_count_matches_documented() {
        // Sub-fase 3.7.0: 16 (chunks/carries) + 3 × 4 × 16 (a/b/c bits) = 208.
        assert_eq!(NUM_COLS, 208);
        assert_eq!(NUM_CONSTRAINTS, 4);
    }

    /// Sub-fase 3.7.0 — out-of-range chunk (≥ 2¹⁶) must be rejected by
    /// the bit recomposition. Without 3.7.0 this would silently pass
    /// any value < 2³¹ (BabyBear-overflow soundness gap).
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add64_rejects_out_of_range_a_chunk() {
        let w = compute_add64(0xCAFE, 0xBABE);
        let mut trace = build_test_trace::<BabyBear>(&w);
        // Force a[0] to 2^16 (= 65_536). The bit cells are still zero from
        // the trace builder (since w.a_chunks[0] was 0xCAFE, fitting in 16
        // bits), so the recomposition Σ b·2^i = 0 ≠ 65_536.
        trace.values[col::A] = BabyBear::from_u64(65_536);
        check_constraints(&Word64AddTestAir, &trace, &[]);
    }

    /// Sub-fase 3.7.0 — non-bool carry must be rejected. Carry is bool
    /// since (2¹⁶-1) + (2¹⁶-1) + 1 = 2¹⁷-1 < 2 · 2¹⁶, so the carry-out
    /// is always 0 or 1.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add64_rejects_non_bool_carry() {
        let w = compute_add64(0xFFFF, 1);
        let mut trace = build_test_trace::<BabyBear>(&w);
        // Original carry[0] is 1; bumping to 2 violates assert_bool AND
        // makes the linear equation impossible to satisfy.
        trace.values[col::CARRY] = BabyBear::from_u64(2);
        check_constraints(&Word64AddTestAir, &trace, &[]);
    }
}
