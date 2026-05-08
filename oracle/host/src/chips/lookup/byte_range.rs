//! 8-bit byte range check via bit decomposition.
//!
//! Proves a witness value `x` is in `[0, 256)` by exposing 8 boolean
//! witness columns and asserting:
//!
//!   1. each bit is in `{0, 1}` (8 boolean constraints)
//!   2. `x = b[0] + 2·b[1] + 4·b[2] + … + 128·b[7]` (1 recomposition)
//!
//! Total: 9 constraints, all degree ≤ 2 (the boolean check `b·(1-b) = 0`
//! is degree 2; the recomposition is degree 1).
//!
//! This is the simplest form of a sound 8-bit range proof — no lookup
//! arguments required, trivially auditable. The lookup-table-based
//! variant (cheaper for many parallel range checks across multiple chips)
//! lands in sub-phase 5.2.1.7 when `PermutationAirBuilder` plumbing
//! goes live.
//!
//! Trace layout (one operation per row, allocated at `start_col`):
//!
//! | offset | name        |
//! |--------|-------------|
//! | 0      | x (value)   |
//! | 1..9   | b[0..8] bits |
//!
//! Total width: 9 columns.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

pub const NUM_BITS: usize = 8;
pub const NUM_COLS: usize = 1 + NUM_BITS;
pub const NUM_CONSTRAINTS: usize = 1 + NUM_BITS;

#[derive(Debug, Clone, Copy)]
pub struct Range8Chip {
    pub start_col: usize,
}

impl Default for Range8Chip {
    fn default() -> Self {
        Self::new()
    }
}

impl Range8Chip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let x = row[self.start_col];

        // 1. Each bit must be boolean.
        for i in 0..NUM_BITS {
            let b = row[self.start_col + 1 + i];
            builder.assert_bool(b);
        }

        // 2. Recomposition: x = sum 2^i * b[i].
        let mut acc = AB::Expr::ZERO;
        let mut weight: u64 = 1;
        for i in 0..NUM_BITS {
            let b = row[self.start_col + 1 + i];
            acc += AB::Expr::from_u64(weight) * b.into();
            weight <<= 1;
        }
        builder.assert_eq(x, acc);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Range8TestAir;

impl<F: Field> BaseAir<F> for Range8TestAir {
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

impl<AB: AirBuilder> Air<AB> for Range8TestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        Range8Chip::new().emit(builder);
    }
}

/// Build a single-row trace witnessing `value ∈ [0, 256)`. Pads to 4
/// rows with zeros (which trivially satisfy: x=0, all bits=0).
pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(value: u8) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];
    values[0] = F::from_u64(value as u64);
    for i in 0..NUM_BITS {
        if (value >> i) & 1 == 1 {
            values[1 + i] = F::ONE;
        }
    }
    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    #[test]
    fn accepts_zero() {
        let trace = build_test_trace::<BabyBear>(0);
        check_constraints(&Range8TestAir, &trace, &[]);
    }

    #[test]
    fn accepts_max_byte() {
        let trace = build_test_trace::<BabyBear>(255);
        check_constraints(&Range8TestAir, &trace, &[]);
    }

    #[test]
    fn accepts_arbitrary() {
        for v in [1u8, 7, 42, 100, 200, 254] {
            let trace = build_test_trace::<BabyBear>(v);
            check_constraints(&Range8TestAir, &trace, &[]);
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_value_with_wrong_bits() {
        // Witness value = 100 but bits = 99 — recomposition constraint must reject.
        let mut trace = build_test_trace::<BabyBear>(99);
        trace.values[0] = BabyBear::from_u64(100);
        check_constraints(&Range8TestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_non_boolean_bit() {
        let mut trace = build_test_trace::<BabyBear>(0);
        trace.values[1] = BabyBear::from_u64(2); // bit must be 0 or 1
        check_constraints(&Range8TestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn cannot_prove_value_above_255() {
        // Try to claim x = 256 with bits all-zero — recomposition rejects.
        let mut trace = build_test_trace::<BabyBear>(0);
        trace.values[0] = BabyBear::from_u64(256);
        check_constraints(&Range8TestAir, &trace, &[]);
    }
}
