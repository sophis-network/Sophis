//! `field25519::cond_p_sub` — conditional `p`-subtraction AIR chip.
//!
//! Final canonicalization step of mod-`p` reduction. Takes a canonical
//! 9-limb input `a` (each limb `< 2³⁰`) and produces a canonical 9-limb
//! output `c` such that:
//!
//!   - `c = a - p`  if  `a >= p`
//!   - `c = a`      otherwise
//!
//! ## Algorithm
//!
//! Compute `t = a - p` with a per-limb borrow chain. The final borrow
//! out of limb 8 indicates `a < p` (when `borrow_out_8 = 1`). Then
//! select `c = a` if `borrow_out_8 = 1`, else `c = t`.
//!
//! Per-limb sub (with `borrow_in[0] = 0`):
//!   `t[i] + p[i] + borrow_in[i] = a[i] + 2³⁰ · borrow_out[i]`
//!
//! Per-limb select (with `bf = borrow_out_8`):
//!   `c[i] = (1 - bf) · t[i] + bf · a[i]`
//!
//! ## Layout (one operation per row, allocated at `start_col`)
//!
//! | offset | width | name           |
//! |--------|-------|----------------|
//! | 0      | 9     | a limbs        |
//! | 9      | 9     | c limbs        |
//! | 18     | 9     | t (= a - p)    |
//! | 27     | 9     | borrow[0..9]   |
//!
//! Total: **36 columns**, **27 constraints** (degree 2).
//!
//! ## Soundness gap (closes in 5.2.1.7 with lookup args)
//!
//! `t[i]`, `c[i]`, `borrow[i]` are not range-checked inline. With each
//! of `t[i]`, `a[i]`, `p[i]` near `2³⁰` and BabyBear ≈ `2³⁰·⁹⁷`, the
//! per-limb subtraction equation has both LHS and RHS in `[0, 2³¹)`,
//! a range where BabyBear wrap-around exploits ARE possible in
//! adversarial witness assignments. For the canonical-input regime
//! (`a < 2³⁰`, prover honest), the equations enforce the intended
//! arithmetic. Closing the formal soundness gap requires either:
//!   - 16-bit lookup-arg range checks on every output limb (5.2.1.7), or
//!   - bit-decomposition of every output limb (~270 extra bool cols), or
//!   - representation refactor to 15-bit halves throughout.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::{Field25519Element, LIMB_MOD, NUM_LIMBS, P_LIMBS};

pub mod col {
    use super::NUM_LIMBS;
    pub const A: usize = 0;
    pub const C: usize = A + NUM_LIMBS;        // 9
    pub const T: usize = C + NUM_LIMBS;        // 18
    pub const BORROW: usize = T + NUM_LIMBS;   // 27
}

pub const NUM_COLS: usize = col::BORROW + NUM_LIMBS; // 36

#[derive(Debug, Clone, Copy)]
pub struct CondPSubChip {
    pub start_col: usize,
}

impl CondPSubChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let two_pow_30 = AB::Expr::from_u64(LIMB_MOD);

        // Per-limb subtraction with borrow chain.
        let mut borrow_in: AB::Expr = AB::Expr::ZERO;
        for i in 0..NUM_LIMBS {
            let a_i = row[self.start_col + col::A + i];
            let t_i = row[self.start_col + col::T + i];
            let borrow_out = row[self.start_col + col::BORROW + i];
            let p_i = AB::Expr::from_u64(P_LIMBS[i]);

            // Boolean check on borrow.
            builder.assert_bool(borrow_out);

            // t[i] + p[i] + borrow_in = a[i] + 2^30 * borrow_out
            builder.assert_eq(t_i.into() + p_i + borrow_in, a_i.into() + two_pow_30.clone() * borrow_out.into());

            borrow_in = borrow_out.into();
        }

        // Final borrow = borrow[NUM_LIMBS - 1]. Select c = (1-bf)*t + bf*a.
        let final_borrow = row[self.start_col + col::BORROW + NUM_LIMBS - 1];
        for i in 0..NUM_LIMBS {
            let a_i = row[self.start_col + col::A + i];
            let c_i = row[self.start_col + col::C + i];
            let t_i = row[self.start_col + col::T + i];

            // c = (1 - bf) * t + bf * a
            //   = t + bf * (a - t)
            // Use the second form to keep the constraint degree 2 cleanly.
            builder.assert_eq(
                c_i,
                t_i.into() + final_borrow.into() * (a_i.into() - t_i.into()),
            );
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CondPSubTestAir;

impl<F: Field> BaseAir<F> for CondPSubTestAir {
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

impl<AB: AirBuilder> Air<AB> for CondPSubTestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        CondPSubChip::new().emit(builder);
    }
}

#[derive(Debug, Clone)]
pub struct CondPSubWitness {
    pub a_limbs: [u64; NUM_LIMBS],
    pub c_limbs: [u64; NUM_LIMBS],
    pub t_limbs: [u64; NUM_LIMBS],
    pub borrow: [u64; NUM_LIMBS],
}

pub fn compute_cond_p_sub(a: &Field25519Element) -> CondPSubWitness {
    let mut t_limbs = [0u64; NUM_LIMBS];
    let mut borrow = [0u64; NUM_LIMBS];
    let mut borrow_in: i64 = 0;
    for i in 0..NUM_LIMBS {
        let lhs = a.limbs[i] as i64;
        let rhs = P_LIMBS[i] as i64;
        let diff = lhs - rhs - borrow_in;
        if diff < 0 {
            t_limbs[i] = (diff + LIMB_MOD as i64) as u64;
            borrow[i] = 1;
            borrow_in = 1;
        } else {
            t_limbs[i] = diff as u64;
            borrow[i] = 0;
            borrow_in = 0;
        }
    }

    let final_borrow = borrow[NUM_LIMBS - 1];
    let c_limbs: [u64; NUM_LIMBS] = if final_borrow == 1 { a.limbs } else { t_limbs };

    CondPSubWitness { a_limbs: a.limbs, c_limbs, t_limbs, borrow }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(w: &CondPSubWitness) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    // Padding rows: a = 0, c = 0, t and borrow consistent with 0 - p.
    // Compute padding witness for a = 0:
    let zero_witness = compute_cond_p_sub(&Field25519Element::ZERO);
    for row in 0..HEIGHT {
        let off = row * NUM_COLS;
        for i in 0..NUM_LIMBS {
            values[off + col::A + i] = F::from_u64(zero_witness.a_limbs[i]);
            values[off + col::C + i] = F::from_u64(zero_witness.c_limbs[i]);
            values[off + col::T + i] = F::from_u64(zero_witness.t_limbs[i]);
            values[off + col::BORROW + i] = F::from_u64(zero_witness.borrow[i]);
        }
    }

    // Overwrite row 0.
    for i in 0..NUM_LIMBS {
        values[col::A + i] = F::from_u64(w.a_limbs[i]);
        values[col::C + i] = F::from_u64(w.c_limbs[i]);
        values[col::T + i] = F::from_u64(w.t_limbs[i]);
        values[col::BORROW + i] = F::from_u64(w.borrow[i]);
    }

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
    fn cond_p_sub_zero_unchanged() {
        let w = compute_cond_p_sub(&Field25519Element::ZERO);
        assert_eq!(w.c_limbs, [0u64; NUM_LIMBS]);
        // 0 < p so final borrow = 1
        assert_eq!(w.borrow[NUM_LIMBS - 1], 1);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&CondPSubTestAir, &trace, &[]);
    }

    #[test]
    fn cond_p_sub_p_yields_zero() {
        let w = compute_cond_p_sub(&Field25519Element::P);
        // P >= P, so final borrow = 0, c = t = P - P = 0.
        assert_eq!(w.borrow[NUM_LIMBS - 1], 0);
        assert_eq!(w.c_limbs, [0u64; NUM_LIMBS]);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&CondPSubTestAir, &trace, &[]);
    }

    #[test]
    fn cond_p_sub_small_unchanged() {
        let a = small(0xCAFE_BABE);
        let w = compute_cond_p_sub(&a);
        // a < p, so final borrow = 1, c = a.
        assert_eq!(w.borrow[NUM_LIMBS - 1], 1);
        assert_eq!(w.c_limbs, a.limbs);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&CondPSubTestAir, &trace, &[]);
    }

    #[test]
    fn cond_p_sub_p_plus_one_yields_one() {
        // a = P + 1 > P, so output c = (P + 1) - P = 1.
        let mut a = Field25519Element::P;
        a.limbs[0] += 1; // P[0] = 0x3FFFFFED, +1 = 0x3FFFFFEE, still < 2^30
        let w = compute_cond_p_sub(&a);
        assert_eq!(w.borrow[NUM_LIMBS - 1], 0);
        assert_eq!(w.c_limbs[0], 1);
        for i in 1..NUM_LIMBS {
            assert_eq!(w.c_limbs[i], 0);
        }
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&CondPSubTestAir, &trace, &[]);
    }

    #[test]
    fn cond_p_sub_p_minus_one_unchanged() {
        // a = P - 1 < P, so output c = a unchanged.
        let mut a = Field25519Element::P;
        a.limbs[0] -= 1;
        let w = compute_cond_p_sub(&a);
        assert_eq!(w.borrow[NUM_LIMBS - 1], 1);
        assert_eq!(w.c_limbs, a.limbs);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&CondPSubTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn cond_p_sub_rejects_tampered_c() {
        let w = compute_cond_p_sub(&small(42));
        let mut trace = build_test_trace::<BabyBear>(&w);
        trace.values[col::C] = trace.values[col::C] + BabyBear::ONE;
        check_constraints(&CondPSubTestAir, &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        assert_eq!(NUM_COLS, 36);
    }
}
