//! N-bit range check via bit decomposition (Etapa 3.0/3.1).
//!
//! Generalises `Range8Chip` to any `NUM_BITS` ≤ 30 (BabyBear safe). Proves
//! `x ∈ [0, 2^NUM_BITS)` by exposing `NUM_BITS` boolean witness columns
//! and asserting:
//!
//!   1. each bit is in `{0, 1}` (NUM_BITS boolean constraints, degree 2)
//!   2. `x = b[0] + 2·b[1] + 4·b[2] + … + 2^(N-1)·b[N-1]` (1 recomposition,
//!      degree 1)
//!
//! Total: `NUM_BITS + 1` constraints, all degree ≤ 2.
//!
//! ## Design rationale (Etapa 3 redesign)
//!
//! The original Etapa 3 plan (`project_phase5_lookup_args_design.md`)
//! proposed a 16-bit shared `Range16Chip` table referenced via a
//! permutation argument. **Investigation 2026-05-05 confirmed Risk #1
//! from that plan**: `p3-uni-stark` 0.5.2 does NOT consume permutation
//! traces (only `p3-air::PermutationAirBuilder` exists; the prover side
//! is absent), and `p3-machine` is not in the workspace.
//!
//! Bit decomposition is sound stand-alone, requires no new prover
//! plumbing, and adds `NUM_BITS + 1` columns per range check — perfectly
//! tractable for our volume (a few hundred range checks total across the
//! ed25519 stack). For `NUM_BITS=10` (mul pieces): 11 cols/check ×
//! ~54 pieces/MulChip = ~594 cols extra. For `NUM_BITS=16` (sha512
//! chunks): 17 cols/check.
//!
//! ## Layout (one operation per row, allocated at `start_col`)
//!
//! | offset             | name             |
//! |--------------------|------------------|
//! | 0                  | x (value)        |
//! | 1..(NUM_BITS+1)    | b[0..NUM_BITS]   |
//!
//! Total width: `NUM_BITS + 1` columns.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

/// Maximum bits we support per range check. BabyBear's prime is just over
/// 2^31, so a value field that itself stays below 2^30 leaves headroom
/// for any add-of-two-bits ops the constraint compiler may apply. We
/// pick 30 as the hard cap.
pub const MAX_BITS: usize = 30;

/// Generic `N`-bit range chip. `N` must be in `1..=MAX_BITS`.
///
/// Two layouts:
///
///   - **Adjacent** (`new()`, `at(col)`): value at `col`, bits at
///     `col+1..col+1+N`. Requires the chip to "own" `1 + N` contiguous
///     columns.
///   - **Split** (`split(value_col, bits_col)`): value at `value_col`,
///     bits at `bits_col..bits_col+N`. The value can live in any
///     pre-existing column; only the `N` bit columns need fresh space.
///     Used to range-check columns that an outer chip already produced
///     (e.g. piece decompositions in `field25519/mul`).
#[derive(Debug, Clone, Copy)]
pub struct RangeNChip<const NUM_BITS: usize> {
    pub value_col: usize,
    pub bits_col: usize,
}

impl<const NUM_BITS: usize> RangeNChip<NUM_BITS> {
    /// Compile-time width of one **adjacent** range check.
    pub const NUM_COLS: usize = 1 + NUM_BITS;
    /// Compile-time width of just the bit columns of a **split** range check.
    pub const BIT_COLS: usize = NUM_BITS;
    pub const NUM_CONSTRAINTS: usize = 1 + NUM_BITS;

    pub const fn new() -> Self {
        let _: () = Self::ASSERT_VALID;
        Self { value_col: 0, bits_col: 1 }
    }

    /// Adjacent layout: value at `start_col`, bits at `start_col+1..`.
    pub const fn at(start_col: usize) -> Self {
        let _: () = Self::ASSERT_VALID;
        Self { value_col: start_col, bits_col: start_col + 1 }
    }

    /// Split layout: value column and bit columns are at independent
    /// offsets. Use when the value already lives somewhere else in the
    /// trace and you only want to allocate `NUM_BITS` extra columns.
    pub const fn split(value_col: usize, bits_col: usize) -> Self {
        let _: () = Self::ASSERT_VALID;
        Self { value_col, bits_col }
    }

    /// Compile-time guard so a misuse like `RangeNChip::<0>` or
    /// `RangeNChip::<31>` fires at monomorphisation.
    const ASSERT_VALID: () = {
        assert!(NUM_BITS >= 1, "RangeNChip requires NUM_BITS >= 1");
        assert!(NUM_BITS <= MAX_BITS, "RangeNChip requires NUM_BITS <= 30 (BabyBear safe)");
    };

    /// Emit the boolean + recomposition constraints. Reads
    /// `value_col` and `bits_col..bits_col+NUM_BITS` from the current row.
    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let x = row[self.value_col];

        // 1. Each bit must be boolean.
        for i in 0..NUM_BITS {
            let b = row[self.bits_col + i];
            builder.assert_bool(b);
        }

        // 2. Recomposition: x = sum 2^i * b[i].
        let mut acc = AB::Expr::ZERO;
        let mut weight: u64 = 1;
        for i in 0..NUM_BITS {
            let b = row[self.bits_col + i];
            acc += AB::Expr::from_u64(weight) * b.into();
            weight <<= 1;
        }
        builder.assert_eq(x, acc);
    }

    /// Populate the value + bit columns starting at absolute offset
    /// `start_off` (= `row * row_width + start_col`). Adjacent layout.
    /// Caller guarantees `value < 2^NUM_BITS`.
    pub fn populate_row<F: Field + PrimeCharacteristicRing>(values: &mut [F], start_off: usize, value: u64) {
        values[start_off] = F::from_u64(value);
        for i in 0..NUM_BITS {
            let bit = (value >> i) & 1;
            values[start_off + 1 + i] = if bit == 1 { F::ONE } else { F::ZERO };
        }
    }

    /// Populate ONLY the bit columns starting at absolute offset
    /// `bits_off`. Split layout — the value column itself is assumed
    /// to be already populated by the outer chip.
    pub fn populate_bits<F: Field + PrimeCharacteristicRing>(values: &mut [F], bits_off: usize, value: u64) {
        for i in 0..NUM_BITS {
            let bit = (value >> i) & 1;
            values[bits_off + i] = if bit == 1 { F::ONE } else { F::ZERO };
        }
    }
}

impl<const NUM_BITS: usize> Default for RangeNChip<NUM_BITS> {
    fn default() -> Self {
        Self::new()
    }
}

/// Specific aliases for the two sizes we actually use in Phase 5.
/// Adopting a public type alias keeps call sites readable while leaving
/// the underlying chip generic.
pub type Range10Chip = RangeNChip<10>;
pub type Range16Chip = RangeNChip<16>;

// =============================================================================
// Test AIR + harness — exercises the chip stand-alone.
// =============================================================================

#[derive(Debug, Clone, Copy)]
pub struct RangeNTestAir<const NUM_BITS: usize>;

impl<const NUM_BITS: usize, F: Field> BaseAir<F> for RangeNTestAir<NUM_BITS> {
    fn width(&self) -> usize {
        RangeNChip::<NUM_BITS>::NUM_COLS
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<const NUM_BITS: usize, AB: AirBuilder> Air<AB> for RangeNTestAir<NUM_BITS>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        RangeNChip::<NUM_BITS>::new().emit(builder);
    }
}

/// Build a single-row trace witnessing `value < 2^NUM_BITS`. Pads to 4
/// rows with zeros (which trivially satisfy the constraint).
pub fn build_test_trace<F: Field + PrimeCharacteristicRing, const NUM_BITS: usize>(value: u64) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let row_width = RangeNChip::<NUM_BITS>::NUM_COLS;
    let mut values = vec![F::ZERO; row_width * HEIGHT];
    RangeNChip::<NUM_BITS>::populate_row::<F>(&mut values, 0, value);
    RowMajorMatrix::new(values, row_width)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    // ===== 10-bit chip =====

    #[test]
    fn range10_accepts_zero() {
        let trace = build_test_trace::<BabyBear, 10>(0);
        check_constraints(&RangeNTestAir::<10>, &trace, &[]);
    }

    #[test]
    fn range10_accepts_max() {
        let trace = build_test_trace::<BabyBear, 10>(1023);
        check_constraints(&RangeNTestAir::<10>, &trace, &[]);
    }

    #[test]
    fn range10_accepts_arbitrary() {
        for v in [1u64, 7, 42, 100, 511, 768, 1000] {
            let trace = build_test_trace::<BabyBear, 10>(v);
            check_constraints(&RangeNTestAir::<10>, &trace, &[]);
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn range10_rejects_value_above_max() {
        // Value = 1024 (2^10) cannot be represented in 10 bits.
        let mut trace = build_test_trace::<BabyBear, 10>(0);
        trace.values[0] = BabyBear::from_u64(1024);
        check_constraints(&RangeNTestAir::<10>, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn range10_rejects_non_boolean_bit() {
        let mut trace = build_test_trace::<BabyBear, 10>(0);
        trace.values[1] = BabyBear::from_u64(2);
        check_constraints(&RangeNTestAir::<10>, &trace, &[]);
    }

    // ===== 16-bit chip =====

    #[test]
    fn range16_accepts_zero() {
        let trace = build_test_trace::<BabyBear, 16>(0);
        check_constraints(&RangeNTestAir::<16>, &trace, &[]);
    }

    #[test]
    fn range16_accepts_max() {
        let trace = build_test_trace::<BabyBear, 16>(65_535);
        check_constraints(&RangeNTestAir::<16>, &trace, &[]);
    }

    #[test]
    fn range16_accepts_arbitrary() {
        for v in [1u64, 256, 4096, 32_767, 50_000, 65_534] {
            let trace = build_test_trace::<BabyBear, 16>(v);
            check_constraints(&RangeNTestAir::<16>, &trace, &[]);
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn range16_rejects_value_above_max() {
        let mut trace = build_test_trace::<BabyBear, 16>(0);
        trace.values[0] = BabyBear::from_u64(65_536);
        check_constraints(&RangeNTestAir::<16>, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn range16_rejects_value_with_wrong_bits() {
        let mut trace = build_test_trace::<BabyBear, 16>(12_345);
        trace.values[0] = BabyBear::from_u64(12_346); // mutate value, bits no longer match
        check_constraints(&RangeNTestAir::<16>, &trace, &[]);
    }

    // ===== Edge cases =====

    /// 1-bit chip is just a boolean assertion.
    #[test]
    fn range1_accepts_bool() {
        for v in [0u64, 1] {
            let trace = build_test_trace::<BabyBear, 1>(v);
            check_constraints(&RangeNTestAir::<1>, &trace, &[]);
        }
    }

    /// 30-bit chip (BabyBear cap).
    #[test]
    fn range30_accepts_arbitrary() {
        for v in [1u64, 1 << 15, 1 << 25, (1u64 << 30) - 1] {
            let trace = build_test_trace::<BabyBear, 30>(v);
            check_constraints(&RangeNTestAir::<30>, &trace, &[]);
        }
    }

    #[test]
    fn num_cols_matches_bits_plus_one() {
        assert_eq!(RangeNChip::<10>::NUM_COLS, 11);
        assert_eq!(RangeNChip::<16>::NUM_COLS, 17);
        assert_eq!(RangeNChip::<8>::NUM_COLS, 9);
        assert_eq!(RangeNChip::<10>::BIT_COLS, 10);
    }

    /// Split layout end-to-end: a small AIR with value_col=0 and bits at col 5..15,
    /// emitting the chip and a separate identity constraint on col 0.
    #[derive(Debug, Clone, Copy)]
    struct SplitLayoutAir;
    impl<F: Field> BaseAir<F> for SplitLayoutAir {
        fn width(&self) -> usize {
            15
        } // value at 0, padding 1..5, bits at 5..15
        fn main_next_row_columns(&self) -> Vec<usize> {
            Vec::new()
        }
        fn max_constraint_degree(&self) -> Option<usize> {
            Some(2)
        }
    }
    impl<AB: AirBuilder> Air<AB> for SplitLayoutAir
    where
        AB::F: Field,
    {
        fn eval(&self, builder: &mut AB) {
            RangeNChip::<10>::split(0, 5).emit(builder);
        }
    }

    #[test]
    fn split_layout_accepts_valid_value() {
        const HEIGHT: usize = 4;
        let row_width = 15;
        let mut values = vec![BabyBear::ZERO; row_width * HEIGHT];
        // Place value 777 at col 0, bits at col 5.
        values[0] = BabyBear::from_u64(777);
        RangeNChip::<10>::populate_bits::<BabyBear>(&mut values, 5, 777);
        let trace = RowMajorMatrix::new(values, row_width);
        check_constraints(&SplitLayoutAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn split_layout_rejects_value_above_max() {
        const HEIGHT: usize = 4;
        let row_width = 15;
        let mut values = vec![BabyBear::ZERO; row_width * HEIGHT];
        // Place value 1024 (too big for 10 bits) at col 0, all-zero bits.
        values[0] = BabyBear::from_u64(1024);
        let trace = RowMajorMatrix::new(values, row_width);
        check_constraints(&SplitLayoutAir, &trace, &[]);
    }
}
