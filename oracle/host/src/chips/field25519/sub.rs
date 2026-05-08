//! `field25519::sub` — lazy modular subtraction chip.
//!
//! Computes `c = a - b (mod p)` per limb without underflow by adding `p`
//! first:
//!
//!   `c[i] = a[i] + p[i] - b[i]`   (constraint per limb)
//!
//! Adding `p` keeps every limb non-negative as a u64. Like the add chip,
//! the result is "lazy" — output limbs may exceed `2³⁰` and need a later
//! `reduce` chip pass (sub-phase 5.2.1.1).
//!
//! Trace layout (one operation per row, allocated at `start_col`):
//!
//! | offset | name    |
//! |--------|---------|
//! | 0..9   | a limbs |
//! | 9..18  | b limbs |
//! | 18..27 | c limbs |
//!
//! Note: `p` is a public constant baked into the constraint — it is not
//! a witness column. Number of constraints emitted: 9.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::{Field25519Element, NUM_LIMBS, P_LIMBS};

pub const NUM_COLS: usize = 3 * NUM_LIMBS;
pub const NUM_CONSTRAINTS: usize = NUM_LIMBS;

#[derive(Debug, Clone, Copy)]
pub struct SubChip {
    pub start_col: usize,
}

impl Default for SubChip {
    fn default() -> Self {
        Self::new()
    }
}

impl SubChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    /// Emit `NUM_CONSTRAINTS` constraints. Each is degree 1:
    /// `a[i] + p[i] - b[i] - c[i] = 0`.
    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        for i in 0..NUM_LIMBS {
            let a = row[self.start_col + i];
            let b = row[self.start_col + NUM_LIMBS + i];
            let c = row[self.start_col + 2 * NUM_LIMBS + i];
            let p_i = AB::Expr::from_u64(P_LIMBS[i]);
            builder.assert_eq(a + p_i - b.into(), c);
        }
    }
}

/// Standalone test AIR wrapping the chip.
#[derive(Debug, Clone, Copy)]
pub struct SubTestAir;

impl<F: Field> BaseAir<F> for SubTestAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(1)
    }
}

impl<AB: AirBuilder> Air<AB> for SubTestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        SubChip::new().emit(builder);
    }
}

/// Compute the witness `c = a - b + p` (lazy, no reduction).
pub fn compute_sub(a: &Field25519Element, b: &Field25519Element) -> Field25519Element {
    let mut c = [0u64; NUM_LIMBS];
    for i in 0..NUM_LIMBS {
        c[i] = a.limbs[i] + P_LIMBS[i] - b.limbs[i];
    }
    Field25519Element { limbs: c }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(
    a: &Field25519Element,
    b: &Field25519Element,
    c: &Field25519Element,
) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];
    // Padding rows still need to satisfy the constraint a+p-b-c = 0.
    // With a=b=c=0 we'd get p ≠ 0, which fails. So we set the c-limbs of
    // padding rows to P_LIMBS (so that a=0, b=0, c=p satisfies the constraint).
    for row in 0..HEIGHT {
        let row_off = row * NUM_COLS;
        for i in 0..NUM_LIMBS {
            values[row_off + 2 * NUM_LIMBS + i] = F::from_u64(P_LIMBS[i]);
        }
    }
    // Active row (row 0) overwrites the c-limbs with the real witness.
    for i in 0..NUM_LIMBS {
        values[i] = F::from_u64(a.limbs[i]);
        values[NUM_LIMBS + i] = F::from_u64(b.limbs[i]);
        values[2 * NUM_LIMBS + i] = F::from_u64(c.limbs[i]);
    }
    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    fn elem_from_u64(n: u64) -> Field25519Element {
        let mut limbs = [0u64; NUM_LIMBS];
        limbs[0] = n & ((1 << 30) - 1);
        limbs[1] = (n >> 30) & ((1 << 30) - 1);
        Field25519Element { limbs }
    }

    #[test]
    fn sub_satisfies_air_for_known_values() {
        let a = elem_from_u64(0xFFFF_FFFF);
        let b = elem_from_u64(0x1234_5678);
        let c = compute_sub(&a, &b);
        let trace = build_test_trace::<BabyBear>(&a, &b, &c);
        check_constraints(&SubTestAir, &trace, &[]);
    }

    #[test]
    fn sub_self_yields_p() {
        // a - a + p = p — sanity check that compute_sub matches the constraint.
        let a = elem_from_u64(42);
        let c = compute_sub(&a, &a);
        for i in 0..NUM_LIMBS {
            assert_eq!(c.limbs[i], P_LIMBS[i], "limb {i} should equal p");
        }
        let trace = build_test_trace::<BabyBear>(&a, &a, &c);
        check_constraints(&SubTestAir, &trace, &[]);
    }

    #[test]
    fn sub_zero_minus_zero_is_p() {
        let z = Field25519Element::ZERO;
        let c = compute_sub(&z, &z);
        // c == p (loose representation of 0 mod p).
        assert_eq!(c.limbs, P_LIMBS);
        let trace = build_test_trace::<BabyBear>(&z, &z, &c);
        check_constraints(&SubTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn sub_rejects_tampered_output() {
        let a = elem_from_u64(0xDEAD);
        let b = elem_from_u64(0xBEEF);
        let c = compute_sub(&a, &b);
        let mut trace = build_test_trace::<BabyBear>(&a, &b, &c);
        // Flip output limb 0.
        let off = 2 * NUM_LIMBS;
        trace.values[off] += BabyBear::ONE;
        check_constraints(&SubTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn sub_rejects_swapped_inputs() {
        let a = elem_from_u64(0xDEAD);
        let b = elem_from_u64(0xBEEF);
        let c = compute_sub(&a, &b);
        // Build a trace claiming `compute_sub(b, a)` produced this c.
        let trace = build_test_trace::<BabyBear>(&b, &a, &c);
        check_constraints(&SubTestAir, &trace, &[]);
    }
}
