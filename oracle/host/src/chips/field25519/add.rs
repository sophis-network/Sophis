//! `field25519::add` — lazy modular addition chip.
//!
//! Constraint:  `c[i] = a[i] + b[i]`  for each of the 9 limbs.
//!
//! "Lazy" means we do **not** perform reduction modulo `p` here — the
//! output limbs are in `[0, 2³¹)` (i.e. one bit wider than canonical).
//! A subsequent `reduce` chip (sub-phase 5.2.1.1) brings them back into
//! canonical range. This split is standard practice in field-AIR design
//! because it keeps each chip's degree low and lets the prover delay
//! reduction across multiple operations.
//!
//! Trace layout (one operation per row; chip is allocated `WIDTH` columns
//! starting at `start_col`):
//!
//! | offset | name      |
//! |--------|-----------|
//! | 0..9   | a limbs   |
//! | 9..18  | b limbs   |
//! | 18..27 | c limbs   |
//!
//! Number of constraints emitted: 9 (one per limb).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use super::{Field25519Element, NUM_LIMBS};

pub const NUM_COLS: usize = 3 * NUM_LIMBS; // 27
pub const NUM_CONSTRAINTS: usize = NUM_LIMBS; // 9

/// Layout descriptor: where in the parent trace this chip's columns live.
#[derive(Debug, Clone, Copy)]
pub struct AddChip {
    pub start_col: usize,
}

impl Default for AddChip {
    fn default() -> Self {
        Self::new()
    }
}

impl AddChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    /// Emit `NUM_CONSTRAINTS` constraints into the supplied builder.
    /// Reads columns `start_col..start_col+NUM_COLS` from the current row.
    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        for i in 0..NUM_LIMBS {
            let a = row[self.start_col + i];
            let b = row[self.start_col + NUM_LIMBS + i];
            let c = row[self.start_col + 2 * NUM_LIMBS + i];
            builder.assert_eq(a + b, c);
        }
    }
}

/// Standalone test AIR wrapping the chip — used by integration tests
/// that prove a single add operation in isolation. The top-level
/// `OracleAir` (sub-phase 5.2.1.7) will instead embed `AddChip::emit`
/// inside its own `eval`.
#[derive(Debug, Clone, Copy)]
pub struct AddTestAir;

impl<F: Field> BaseAir<F> for AddTestAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new() // single-row constraints only
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(1) // a + b - c is degree 1
    }
}

impl<AB: AirBuilder> Air<AB> for AddTestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        AddChip::new().emit(builder);
    }
}

/// Compute the witness `c = a + b` (lazy, no reduction). Returns the c
/// limbs alongside the inputs so callers can lay out a trace row.
pub fn compute_add(a: &Field25519Element, b: &Field25519Element) -> Field25519Element {
    let mut c = [0u64; NUM_LIMBS];
    for i in 0..NUM_LIMBS {
        c[i] = a.limbs[i] + b.limbs[i];
    }
    Field25519Element { limbs: c }
}

/// Build a single-row trace exercising one add operation. Pads to 4 rows
/// (smallest power of two FRI accepts) with zeros, which trivially
/// satisfy the constraint (0+0=0).
pub fn build_test_trace<F: Field + p3_field::PrimeCharacteristicRing>(
    a: &Field25519Element,
    b: &Field25519Element,
    c: &Field25519Element,
) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];
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
    fn add_satisfies_air_for_known_values() {
        let a = elem_from_u64(0x12345678);
        let b = elem_from_u64(0x9ABCDEF0);
        let c = compute_add(&a, &b);
        let trace = build_test_trace::<BabyBear>(&a, &b, &c);
        check_constraints(&AddTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add_rejects_tampered_output() {
        let a = elem_from_u64(0x12345678);
        let b = elem_from_u64(0x9ABCDEF0);
        let c = compute_add(&a, &b);
        let mut trace = build_test_trace::<BabyBear>(&a, &b, &c);
        // Mutate output limb 0 — constraint a + b = c must reject.
        let off = 2 * NUM_LIMBS;
        trace.values[off] += BabyBear::ONE;
        check_constraints(&AddTestAir, &trace, &[]);
    }

    #[test]
    fn add_with_zero_is_identity() {
        let a = elem_from_u64(0xDEADBEEF);
        let z = Field25519Element::ZERO;
        let c = compute_add(&a, &z);
        assert_eq!(c, a);
        let trace = build_test_trace::<BabyBear>(&a, &z, &c);
        check_constraints(&AddTestAir, &trace, &[]);
    }

    #[test]
    fn add_p_plus_zero_satisfies_air() {
        // p + 0 = p is a perfectly valid lazy add (output limbs unreduced).
        let p = Field25519Element::P;
        let z = Field25519Element::ZERO;
        let c = compute_add(&p, &z);
        let trace = build_test_trace::<BabyBear>(&p, &z, &c);
        check_constraints(&AddTestAir, &trace, &[]);
    }

    #[test]
    fn add_chip_at_offset_works() {
        // Same constraint but the chip's columns are shifted by an arbitrary
        // offset. We test with a wrapper AIR that pads on the left.
        const OFFSET: usize = 5;
        const TOTAL_WIDTH: usize = NUM_COLS + OFFSET;

        struct OffsetAddAir;
        impl<F: Field> BaseAir<F> for OffsetAddAir {
            fn width(&self) -> usize {
                TOTAL_WIDTH
            }
            fn main_next_row_columns(&self) -> Vec<usize> {
                Vec::new()
            }
            fn max_constraint_degree(&self) -> Option<usize> {
                Some(1)
            }
        }
        impl<AB: AirBuilder> Air<AB> for OffsetAddAir
        where
            AB::F: Field,
        {
            fn eval(&self, builder: &mut AB) {
                AddChip::at(OFFSET).emit(builder);
            }
        }

        let a = elem_from_u64(100);
        let b = elem_from_u64(200);
        let c = compute_add(&a, &b);

        const HEIGHT: usize = 4;
        let mut values = vec![BabyBear::ZERO; TOTAL_WIDTH * HEIGHT];
        for i in 0..NUM_LIMBS {
            values[OFFSET + i] = BabyBear::from_u64(a.limbs[i]);
            values[OFFSET + NUM_LIMBS + i] = BabyBear::from_u64(b.limbs[i]);
            values[OFFSET + 2 * NUM_LIMBS + i] = BabyBear::from_u64(c.limbs[i]);
        }
        let trace = RowMajorMatrix::new(values, TOTAL_WIDTH);
        check_constraints(&OffsetAddAir, &trace, &[]);
    }
}
