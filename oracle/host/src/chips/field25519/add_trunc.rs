//! `field25519::add_trunc` — composed chip producing canonical
//! `c = (a + b) mod 2²⁷⁰` from two canonical 9-limb inputs.
//!
//! Composes the existing primitive chips:
//!
//!   - `AddChip`     — lazy per-limb add (output limbs may exceed 2³⁰)
//!   - `ReduceChip`  — carry propagation to canonical 30-bit limbs
//!
//! ## What this chip does NOT do
//!
//! It does **not** reduce mod `p = 2²⁵⁵ - 19`. The output is the integer
//! sum truncated at bit 270 (the 9-limb window). For `a, b < p`, the
//! integer sum is `< 2 · p < 2²⁵⁶ < 2²⁷⁰`, so no actual truncation
//! happens — the output equals the integer sum, but represented in 9
//! 30-bit limbs which may encode a value `> p`. A subsequent mod-`p`
//! reduction step (pending — see `field25519/mod_p.rs`) brings the
//! value into `[0, p)`.
//!
//! Useful as a building block for ed25519 chips that can tolerate
//! "loose" canonical output (limbs `< 2³⁰` but value possibly `≥ p`).
//!
//! ## Layout
//!
//! | Range     | Width | Contents                              |
//! |-----------|-------|---------------------------------------|
//! | 0..9      | 9     | a chunks (input)                      |
//! | 9..18     | 9     | b chunks (input)                      |
//! | 18..27    | 9     | c chunks (output, canonical 30-bit)   |
//! | 27..54    | 27    | AddChip                               |
//! | 54..81    | 27    | ReduceChip                            |
//!
//! Total: **81 columns**, ~64 constraints (degree 1 max).
//!
//! ## Soundness
//!
//! Sound for canonical inputs (each input limb `< 2³⁰`). Soundness gap
//! same as the underlying ReduceChip: output `c[i]` and the carries are
//! NOT range-checked inline (closes globally in 5.2.1.7 with lookup
//! args). A malicious prover with adversarial inputs could exploit
//! BabyBear field overflow to satisfy the linear equations dishonestly.
//! For the canonical-input regime, the bounds are tight enough that
//! the equations enforce the intended arithmetic.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::add::{AddChip, NUM_COLS as ADD_COLS};
use super::reduce::{NUM_COLS as RED_COLS, ReduceChip};
use super::{Field25519Element, NUM_LIMBS};

pub mod col {
    use super::*;
    pub const A: usize = 0;
    pub const B: usize = A + NUM_LIMBS; // 9
    pub const C: usize = B + NUM_LIMBS; // 18
    pub const ADD_START: usize = C + NUM_LIMBS; // 27
    pub const REDUCE_START: usize = ADD_START + ADD_COLS; // 54

    pub const TOTAL: usize = REDUCE_START + RED_COLS; // 81
}

pub const NUM_COLS: usize = col::TOTAL;

#[derive(Debug, Clone, Copy)]
pub struct AddTruncChip {
    pub start_col: usize,
}

impl Default for AddTruncChip {
    fn default() -> Self {
        Self::new()
    }
}

impl AddTruncChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        AddChip::at(self.start_col + col::ADD_START).emit(builder);
        ReduceChip::at(self.start_col + col::REDUCE_START).emit(builder);

        let main = builder.main();
        let row = main.current_slice();

        let assert_chunks_eq = |b: &mut AB, off_a: usize, off_b: usize, n: usize| {
            for i in 0..n {
                b.assert_eq(row[off_a + i], row[off_b + i]);
            }
        };

        assert_chunks_eq(builder, self.start_col + col::ADD_START, self.start_col + col::A, NUM_LIMBS);
        assert_chunks_eq(builder, self.start_col + col::ADD_START + NUM_LIMBS, self.start_col + col::B, NUM_LIMBS);
        assert_chunks_eq(builder, self.start_col + col::REDUCE_START, self.start_col + col::ADD_START + 2 * NUM_LIMBS, NUM_LIMBS);
        assert_chunks_eq(builder, self.start_col + col::C, self.start_col + col::REDUCE_START + NUM_LIMBS, NUM_LIMBS);
    }
}

impl<F: Field> BaseAir<F> for AddTruncChip {
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

impl<AB: AirBuilder> Air<AB> for AddTruncChip
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        self.emit(builder);
    }
}

/// Build a single-row trace exercising one composed add+reduce.
pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(a: &Field25519Element, b: &Field25519Element) -> RowMajorMatrix<F> {
    use super::add::compute_add;
    use super::reduce::compute_reduce;

    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    // Compute via witness functions.
    let loose_c = compute_add(a, b);
    let (canonical_c, carries) = compute_reduce(&loose_c);

    // Top-level inputs and output.
    for i in 0..NUM_LIMBS {
        values[col::A + i] = F::from_u64(a.limbs[i]);
        values[col::B + i] = F::from_u64(b.limbs[i]);
        values[col::C + i] = F::from_u64(canonical_c.limbs[i]);
    }

    // Populate AddChip.
    for i in 0..NUM_LIMBS {
        values[col::ADD_START + i] = F::from_u64(a.limbs[i]);
        values[col::ADD_START + NUM_LIMBS + i] = F::from_u64(b.limbs[i]);
        values[col::ADD_START + 2 * NUM_LIMBS + i] = F::from_u64(loose_c.limbs[i]);
    }

    // Populate ReduceChip.
    for i in 0..NUM_LIMBS {
        values[col::REDUCE_START + i] = F::from_u64(loose_c.limbs[i]);
        values[col::REDUCE_START + NUM_LIMBS + i] = F::from_u64(canonical_c.limbs[i]);
        values[col::REDUCE_START + 2 * NUM_LIMBS + i] = F::from_u64(carries[i]);
    }

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::super::P_LIMBS;
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeField32;

    fn small(n: u64) -> Field25519Element {
        let mut limbs = [0u64; NUM_LIMBS];
        limbs[0] = n & ((1 << 30) - 1);
        limbs[1] = (n >> 30) & ((1 << 30) - 1);
        Field25519Element { limbs }
    }

    fn read_c(values: &[BabyBear]) -> [u64; NUM_LIMBS] {
        let mut out = [0u64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            out[i] = values[col::C + i].as_canonical_u32() as u64;
        }
        out
    }

    #[test]
    fn add_trunc_zero_plus_zero() {
        let trace = build_test_trace::<BabyBear>(&Field25519Element::ZERO, &Field25519Element::ZERO);
        check_constraints(&AddTruncChip::new(), &trace, &[]);
        assert_eq!(read_c(&trace.values), [0u64; NUM_LIMBS]);
    }

    #[test]
    fn add_trunc_three_plus_seven() {
        let trace = build_test_trace::<BabyBear>(&small(3), &small(7));
        check_constraints(&AddTruncChip::new(), &trace, &[]);
        let c = read_c(&trace.values);
        assert_eq!(c[0], 10);
        for i in 1..NUM_LIMBS {
            assert_eq!(c[i], 0);
        }
    }

    #[test]
    fn add_trunc_p_plus_zero_yields_p() {
        let p = Field25519Element::P;
        let trace = build_test_trace::<BabyBear>(&p, &Field25519Element::ZERO);
        check_constraints(&AddTruncChip::new(), &trace, &[]);
        assert_eq!(read_c(&trace.values), P_LIMBS);
    }

    #[test]
    fn add_trunc_max_plus_one_propagates_carry() {
        // Limb 0 = 2^30 - 1, then add 1 → carry into limb 1.
        let mut a = Field25519Element::ZERO;
        a.limbs[0] = (1 << 30) - 1;
        let mut one = Field25519Element::ZERO;
        one.limbs[0] = 1;
        let trace = build_test_trace::<BabyBear>(&a, &one);
        check_constraints(&AddTruncChip::new(), &trace, &[]);
        let c = read_c(&trace.values);
        assert_eq!(c[0], 0);
        assert_eq!(c[1], 1);
    }

    #[test]
    fn add_trunc_chain_of_carries() {
        // Each limb at 2^30 - 1; adding small value to limb 0 cascades carries.
        let max = Field25519Element { limbs: [(1 << 30) - 1; NUM_LIMBS] };
        let mut delta = Field25519Element::ZERO;
        delta.limbs[0] = 1;
        let trace = build_test_trace::<BabyBear>(&max, &delta);
        check_constraints(&AddTruncChip::new(), &trace, &[]);
        let c = read_c(&trace.values);
        // After cascade: every limb 0..8 becomes 0 (with overflow above bit 270 absorbed).
        for i in 0..NUM_LIMBS {
            assert_eq!(c[i], 0, "limb {i} should be 0 after full cascade");
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add_trunc_rejects_tampered_c() {
        let trace_init = build_test_trace::<BabyBear>(&small(7), &small(13));
        let mut trace = trace_init;
        trace.values[col::C] += BabyBear::ONE;
        check_constraints(&AddTruncChip::new(), &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add_trunc_rejects_tampered_a() {
        let trace_init = build_test_trace::<BabyBear>(&small(7), &small(13));
        let mut trace = trace_init;
        trace.values[col::A] += BabyBear::ONE;
        check_constraints(&AddTruncChip::new(), &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        assert_eq!(NUM_COLS, 81);
    }
}
