//! `field25519::eq` — equality predicate AIR chip for two 9-limb field
//! elements: `eq = 1 iff a == b` (every corresponding limb pair is equal).
//!
//! Mirror of `sha512::word64_eq` scaled from 4 to 9 limbs. Used by
//! ed25519 chips that need to compare field elements (e.g. the final
//! `[S]B == R + [h]A` check in `verify`, point negation/identity tests
//! in higher-level point chips).
//!
//! ## Layout (one operation per row, allocated at `start_col`)
//!
//! | offset    | width | name                          |
//! |-----------|-------|-------------------------------|
//! | 0         | 9     | a limbs                       |
//! | 9         | 9     | b limbs                       |
//! | 18        | 9     | diff per limb (= a - b)       |
//! | 27        | 9     | inv per limb                  |
//! | 36        | 9     | limb_eq                       |
//! | 45        | 8     | m1..m8 (chained ANDs)         |
//! | 53        | 1     | eq (output)                   |
//!
//! Total: **54 columns**, ~46 constraints (degree 2).
//!
//! ## Constraints
//!
//! Per limb `i ∈ 0..9`:
//!   - `diff = a - b` (degree 1)
//!   - `limb_eq` boolean
//!   - `diff · inv = 1 - limb_eq` (inverse trick)
//!   - `diff · limb_eq = 0`
//!
//! Chain: `m1 = liz[0] · liz[1]`, `m_k = m_{k-1} · liz[k+1]` for k ∈ 1..8.
//! Output: `eq = m8`. Plus boolean check on `eq`.
//!
//! ## Soundness
//!
//! Stand-alone for canonical-limb inputs (each limb `< 2³⁰`). Same
//! semantics caveat as `field25519/is_zero`: the predicate tests "field
//! elements are equal", which coincides with "9-limb representations
//! are equal" for canonical inputs.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::{Field25519Element, NUM_LIMBS};

pub mod col {
    use super::NUM_LIMBS;
    pub const A: usize = 0;
    pub const B: usize = A + NUM_LIMBS;             // 9
    pub const DIFF: usize = B + NUM_LIMBS;          // 18
    pub const INV: usize = DIFF + NUM_LIMBS;        // 27
    pub const LE: usize = INV + NUM_LIMBS;          // 36 (limb_eq)
    pub const M_BASE: usize = LE + NUM_LIMBS;       // 45 (intermediates m1..m8)
    pub const NUM_INTERMEDIATES: usize = NUM_LIMBS - 1; // 8
    pub const EQ: usize = M_BASE + NUM_INTERMEDIATES;   // 53
}

pub const NUM_COLS: usize = col::EQ + 1; // 54

#[derive(Debug, Clone, Copy)]
pub struct EqChip {
    pub start_col: usize,
}

impl EqChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;

        for i in 0..NUM_LIMBS {
            let a_i = row[self.start_col + col::A + i];
            let b_i = row[self.start_col + col::B + i];
            let diff_i = row[self.start_col + col::DIFF + i];
            let inv_i = row[self.start_col + col::INV + i];
            let le_i = row[self.start_col + col::LE + i];

            // diff = a - b
            builder.assert_eq(diff_i, a_i.into() - b_i.into());

            // limb_eq boolean
            builder.assert_bool(le_i);

            // diff · inv = 1 - limb_eq
            builder.assert_eq(diff_i.into() * inv_i.into(), one.clone() - le_i.into());

            // diff · limb_eq = 0
            builder.assert_zero(diff_i.into() * le_i.into());
        }

        // Chained ANDs.
        let le0 = row[self.start_col + col::LE + 0];
        let le1 = row[self.start_col + col::LE + 1];
        let m1 = row[self.start_col + col::M_BASE + 0];
        builder.assert_eq(m1, le0.into() * le1.into());

        for k in 1..col::NUM_INTERMEDIATES {
            let prev = row[self.start_col + col::M_BASE + k - 1];
            let le_next = row[self.start_col + col::LE + k + 1];
            let m_k = row[self.start_col + col::M_BASE + k];
            builder.assert_eq(m_k, prev.into() * le_next.into());
        }

        let m_last = row[self.start_col + col::M_BASE + col::NUM_INTERMEDIATES - 1];
        let eq = row[self.start_col + col::EQ];
        builder.assert_eq(eq, m_last);
        builder.assert_bool(eq);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EqTestAir;

impl<F: Field> BaseAir<F> for EqTestAir {
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

impl<AB: AirBuilder> Air<AB> for EqTestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        EqChip::new().emit(builder);
    }
}

#[derive(Debug, Clone)]
pub struct EqWitness {
    pub a_limbs: [u64; NUM_LIMBS],
    pub b_limbs: [u64; NUM_LIMBS],
    pub diff: [u64; NUM_LIMBS],
    pub inv: [u64; NUM_LIMBS],
    pub limb_eq: [u64; NUM_LIMBS],
    pub intermediates: [u64; col::NUM_INTERMEDIATES],
    pub eq: u64,
}

pub fn compute_eq<F>(a: &Field25519Element, b: &Field25519Element) -> EqWitness
where
    F: Field + PrimeCharacteristicRing + p3_field::PrimeField64,
{
    let mut diff = [0u64; NUM_LIMBS];
    let mut inv = [0u64; NUM_LIMBS];
    let mut limb_eq = [0u64; NUM_LIMBS];

    for i in 0..NUM_LIMBS {
        let a_f = F::from_u64(a.limbs[i]);
        let b_f = F::from_u64(b.limbs[i]);
        let diff_f = a_f - b_f;
        diff[i] = p3_field::PrimeField64::as_canonical_u64(&diff_f);
        if diff_f == F::ZERO {
            limb_eq[i] = 1;
            inv[i] = 0;
        } else {
            limb_eq[i] = 0;
            let inv_f = diff_f.try_inverse().expect("nonzero diff has inverse");
            inv[i] = p3_field::PrimeField64::as_canonical_u64(&inv_f);
        }
    }

    let mut intermediates = [0u64; col::NUM_INTERMEDIATES];
    intermediates[0] = limb_eq[0] * limb_eq[1];
    for k in 1..col::NUM_INTERMEDIATES {
        intermediates[k] = intermediates[k - 1] * limb_eq[k + 1];
    }
    let eq = intermediates[col::NUM_INTERMEDIATES - 1];

    EqWitness { a_limbs: a.limbs, b_limbs: b.limbs, diff, inv, limb_eq, intermediates, eq }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing + p3_field::PrimeField64>(
    w: &EqWitness,
) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    // Padding rows: a = b = 0 → diff = 0, limb_eq = all 1, intermediates = 1, eq = 1.
    for row in 0..HEIGHT {
        let off = row * NUM_COLS;
        for i in 0..NUM_LIMBS {
            values[off + col::LE + i] = F::ONE;
        }
        for k in 0..col::NUM_INTERMEDIATES {
            values[off + col::M_BASE + k] = F::ONE;
        }
        values[off + col::EQ] = F::ONE;
    }

    // Overwrite row 0 with witness.
    for i in 0..NUM_LIMBS {
        values[col::A + i] = F::from_u64(w.a_limbs[i]);
        values[col::B + i] = F::from_u64(w.b_limbs[i]);
        values[col::DIFF + i] = F::from_u64(w.diff[i]);
        values[col::INV + i] = F::from_u64(w.inv[i]);
        values[col::LE + i] = F::from_u64(w.limb_eq[i]);
    }
    for k in 0..col::NUM_INTERMEDIATES {
        values[col::M_BASE + k] = F::from_u64(w.intermediates[k]);
    }
    values[col::EQ] = F::from_u64(w.eq);

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    fn small(n: u64) -> Field25519Element {
        let mut limbs = [0u64; NUM_LIMBS];
        limbs[0] = n & ((1 << 30) - 1);
        limbs[1] = (n >> 30) & ((1 << 30) - 1);
        Field25519Element { limbs }
    }

    #[test]
    fn eq_self_yields_one() {
        let cases: [Field25519Element; 4] = [
            Field25519Element::ZERO,
            small(0xCAFE_BABE),
            Field25519Element::P,
            Field25519Element { limbs: [(1 << 30) - 1; NUM_LIMBS] },
        ];
        for a in cases {
            let w = compute_eq::<BabyBear>(&a, &a);
            assert_eq!(w.eq, 1);
            let trace = build_test_trace::<BabyBear>(&w);
            check_constraints(&EqTestAir, &trace, &[]);
        }
    }

    #[test]
    fn eq_distinct_yields_zero() {
        let pairs: [(Field25519Element, Field25519Element); 4] = [
            (Field25519Element::ZERO, small(1)),
            (small(0xCAFE), small(0xBABE)),
            (Field25519Element::ZERO, Field25519Element::P),
            (Field25519Element::P, small(1)),
        ];
        for (a, b) in pairs {
            let w = compute_eq::<BabyBear>(&a, &b);
            assert_eq!(w.eq, 0);
            let trace = build_test_trace::<BabyBear>(&w);
            check_constraints(&EqTestAir, &trace, &[]);
        }
    }

    #[test]
    fn eq_only_high_limb_differs() {
        let mut a = Field25519Element::ZERO;
        let mut b = Field25519Element::ZERO;
        a.limbs[8] = 1;
        b.limbs[8] = 2;
        let w = compute_eq::<BabyBear>(&a, &b);
        assert_eq!(w.eq, 0);
        for i in 0..8 {
            assert_eq!(w.limb_eq[i], 1, "limb {i} should match");
        }
        assert_eq!(w.limb_eq[8], 0);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&EqTestAir, &trace, &[]);
    }

    #[test]
    fn eq_zero_vs_p_yields_zero() {
        // ZERO and P are different 9-limb representations even though both
        // are congruent to 0 mod p — the chip checks representation equality.
        let w = compute_eq::<BabyBear>(&Field25519Element::ZERO, &Field25519Element::P);
        assert_eq!(w.eq, 0);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&EqTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn eq_rejects_lying_about_equality() {
        let mut w = compute_eq::<BabyBear>(&small(0xCAFE), &small(0xBABE));
        w.eq = 1; // lie
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&EqTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn eq_rejects_lying_about_limb_eq() {
        let mut w = compute_eq::<BabyBear>(&small(0xCAFE), &small(0xCAFE));
        w.limb_eq[0] = 0;
        for k in 0..col::NUM_INTERMEDIATES {
            w.intermediates[k] = 0;
        }
        w.eq = 0;
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&EqTestAir, &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        assert_eq!(NUM_COLS, 54);
        assert_eq!(col::NUM_INTERMEDIATES, 8);
    }
}
