//! `field25519::is_zero` — boolean predicate AIR chip for 9-limb field
//! elements: `is_zero = 1 iff a == 0` (zero in every limb).
//!
//! Same inverse-trick pattern as `sha512::word64_is_zero`, scaled up to
//! 9 30-bit limbs. Used by ed25519 chips that need to detect the
//! all-zero element (e.g., `decompress`'s `x = 0 ∧ sign_bit = 1` reject
//! case).
//!
//! ## Layout (one operation per row, allocated at `start_col`)
//!
//! | offset    | width | name              |
//! |-----------|-------|-------------------|
//! | 0         | 9     | a limbs           |
//! | 9         | 9     | inv per limb      |
//! | 18        | 9     | limb_is_zero      |
//! | 27        | 8     | m1..m8 (chained ANDs) |
//! | 35        | 1     | is_zero (output)  |
//!
//! Total: **36 columns**, ~37 constraints (degree 2).
//!
//! ## Constraints
//!
//! Per limb `i ∈ 0..9`:
//!   - `limb_is_zero` boolean
//!   - `a · inv = 1 - limb_is_zero`
//!   - `a · limb_is_zero = 0`
//!
//! Chain: `m1 = liz[0] · liz[1]`, `m2 = m1 · liz[2]`, …, `m8 = m7 · liz[8]`.
//! Output: `is_zero = m8`. Plus boolean check on `is_zero`.
//!
//! ## Soundness
//!
//! Stand-alone sound for canonical inputs (each limb `< 2³⁰`). For
//! looser inputs (limbs `< 2³¹`), the predicate still correctly answers
//! "is the field element zero" but no longer corresponds to "is the
//! integer value zero" — caller ensures canonical input.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::{Field25519Element, NUM_LIMBS};

pub mod col {
    use super::NUM_LIMBS;
    pub const A: usize = 0;
    pub const INV: usize = A + NUM_LIMBS; // 9
    pub const LIZ: usize = INV + NUM_LIMBS; // 18 (limb_is_zero)
    pub const M_BASE: usize = LIZ + NUM_LIMBS; // 27 (intermediates m1..m8)
    pub const NUM_INTERMEDIATES: usize = NUM_LIMBS - 1; // 8
    pub const IS_ZERO: usize = M_BASE + NUM_INTERMEDIATES; // 35
}

pub const NUM_COLS: usize = col::IS_ZERO + 1; // 36

#[derive(Debug, Clone, Copy)]
pub struct IsZeroChip {
    pub start_col: usize,
}

impl Default for IsZeroChip {
    fn default() -> Self {
        Self::new()
    }
}

impl IsZeroChip {
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

        // Per-limb is-zero detection.
        for i in 0..NUM_LIMBS {
            let a_i = row[self.start_col + col::A + i];
            let inv_i = row[self.start_col + col::INV + i];
            let liz_i = row[self.start_col + col::LIZ + i];

            builder.assert_bool(liz_i);
            builder.assert_eq(a_i.into() * inv_i.into(), one.clone() - liz_i.into());
            builder.assert_zero(a_i.into() * liz_i.into());
        }

        // Chained ANDs: m_k = m_{k-1} · liz[k+1] for k in 0..8.
        // m1 reads liz[0] · liz[1]; m_k for k≥1 reads m_{k-1} · liz[k+1].
        let liz0 = row[self.start_col + col::LIZ];
        let liz1 = row[self.start_col + col::LIZ + 1];
        let m1 = row[self.start_col + col::M_BASE];
        builder.assert_eq(m1, liz0.into() * liz1.into());

        for k in 1..col::NUM_INTERMEDIATES {
            let prev = row[self.start_col + col::M_BASE + k - 1];
            let liz_next = row[self.start_col + col::LIZ + k + 1];
            let m_k = row[self.start_col + col::M_BASE + k];
            builder.assert_eq(m_k, prev.into() * liz_next.into());
        }

        let m_last = row[self.start_col + col::M_BASE + col::NUM_INTERMEDIATES - 1];
        let is_zero = row[self.start_col + col::IS_ZERO];
        builder.assert_eq(is_zero, m_last);
        builder.assert_bool(is_zero);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IsZeroTestAir;

impl<F: Field> BaseAir<F> for IsZeroTestAir {
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

impl<AB: AirBuilder> Air<AB> for IsZeroTestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        IsZeroChip::new().emit(builder);
    }
}

#[derive(Debug, Clone)]
pub struct IsZeroWitness {
    pub a_limbs: [u64; NUM_LIMBS],
    pub inv: [u64; NUM_LIMBS],
    pub limb_is_zero: [u64; NUM_LIMBS],
    pub intermediates: [u64; col::NUM_INTERMEDIATES],
    pub is_zero: u64,
}

pub fn compute_is_zero<F>(elem: &Field25519Element) -> IsZeroWitness
where
    F: Field + PrimeCharacteristicRing + p3_field::PrimeField64,
{
    let mut inv = [0u64; NUM_LIMBS];
    let mut liz = [0u64; NUM_LIMBS];
    for i in 0..NUM_LIMBS {
        if elem.limbs[i] == 0 {
            liz[i] = 1;
            inv[i] = 0;
        } else {
            liz[i] = 0;
            let f = F::from_u64(elem.limbs[i]);
            let f_inv = f.try_inverse().expect("nonzero limb has inverse");
            inv[i] = p3_field::PrimeField64::as_canonical_u64(&f_inv);
        }
    }

    let mut intermediates = [0u64; col::NUM_INTERMEDIATES];
    intermediates[0] = liz[0] * liz[1];
    for k in 1..col::NUM_INTERMEDIATES {
        intermediates[k] = intermediates[k - 1] * liz[k + 1];
    }
    let is_zero = intermediates[col::NUM_INTERMEDIATES - 1];

    IsZeroWitness { a_limbs: elem.limbs, inv, limb_is_zero: liz, intermediates, is_zero }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing + p3_field::PrimeField64>(w: &IsZeroWitness) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    // Padding rows: a = 0 everywhere → liz = all 1, intermediates = all 1, is_zero = 1.
    for row in 0..HEIGHT {
        let off = row * NUM_COLS;
        for i in 0..NUM_LIMBS {
            values[off + col::LIZ + i] = F::ONE;
        }
        for k in 0..col::NUM_INTERMEDIATES {
            values[off + col::M_BASE + k] = F::ONE;
        }
        values[off + col::IS_ZERO] = F::ONE;
    }

    // Overwrite row 0 with witness.
    for i in 0..NUM_LIMBS {
        values[col::A + i] = F::from_u64(w.a_limbs[i]);
        values[col::INV + i] = F::from_u64(w.inv[i]);
        values[col::LIZ + i] = F::from_u64(w.limb_is_zero[i]);
    }
    for k in 0..col::NUM_INTERMEDIATES {
        values[col::M_BASE + k] = F::from_u64(w.intermediates[k]);
    }
    values[col::IS_ZERO] = F::from_u64(w.is_zero);

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
    fn is_zero_zero_yields_one() {
        let w = compute_is_zero::<BabyBear>(&Field25519Element::ZERO);
        assert_eq!(w.is_zero, 1);
        for liz in w.limb_is_zero {
            assert_eq!(liz, 1);
        }
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&IsZeroTestAir, &trace, &[]);
    }

    #[test]
    fn is_zero_one_yields_zero() {
        let w = compute_is_zero::<BabyBear>(&small(1));
        assert_eq!(w.is_zero, 0);
        assert_eq!(w.limb_is_zero[0], 0); // limb 0 is non-zero
        for i in 1..NUM_LIMBS {
            assert_eq!(w.limb_is_zero[i], 1);
        }
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&IsZeroTestAir, &trace, &[]);
    }

    #[test]
    fn is_zero_p_yields_zero_field_element_check() {
        // P_LIMBS represents p, NOT zero in the field-element sense (it's
        // the integer p which is congruent to 0 mod p, but as raw 9-limb
        // representation it has non-zero limbs).
        let w = compute_is_zero::<BabyBear>(&Field25519Element::P);
        assert_eq!(w.is_zero, 0); // P is non-zero in its 9-limb form
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&IsZeroTestAir, &trace, &[]);
    }

    #[test]
    fn is_zero_only_high_limb_set() {
        let mut e = Field25519Element::ZERO;
        e.limbs[8] = 0x1234;
        let w = compute_is_zero::<BabyBear>(&e);
        assert_eq!(w.is_zero, 0);
        for i in 0..8 {
            assert_eq!(w.limb_is_zero[i], 1);
        }
        assert_eq!(w.limb_is_zero[8], 0);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&IsZeroTestAir, &trace, &[]);
    }

    #[test]
    fn is_zero_arbitrary_inputs() {
        let cases: [Field25519Element; 4] = [
            Field25519Element::ZERO,
            small(0xCAFE_BABE),
            Field25519Element::P,
            Field25519Element { limbs: [(1 << 30) - 1; NUM_LIMBS] },
        ];
        for e in cases {
            let w = compute_is_zero::<BabyBear>(&e);
            let expected = if e.limbs.iter().all(|&l| l == 0) { 1 } else { 0 };
            assert_eq!(w.is_zero, expected);
            let trace = build_test_trace::<BabyBear>(&w);
            check_constraints(&IsZeroTestAir, &trace, &[]);
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn is_zero_rejects_lying_about_nonzero() {
        let mut w = compute_is_zero::<BabyBear>(&small(0xCAFE));
        w.is_zero = 1;
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&IsZeroTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn is_zero_rejects_wrong_liz() {
        // Zero input but witness claims limb_is_zero[0] = 0.
        let mut w = compute_is_zero::<BabyBear>(&Field25519Element::ZERO);
        w.limb_is_zero[0] = 0;
        // Cascade-invalidate intermediates so the chain still computes.
        for k in 0..col::NUM_INTERMEDIATES {
            w.intermediates[k] = 0;
        }
        w.is_zero = 0;
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&IsZeroTestAir, &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        assert_eq!(NUM_COLS, 36);
        assert_eq!(col::NUM_INTERMEDIATES, 8);
    }
}
