//! `field25519::reduce` — lazy carry propagation chip.
//!
//! Takes a "loose" 9-limb `Field25519Element` whose limbs may be in
//! `[0, 2³³)` (e.g. the output of an `add` followed by an unreduced
//! mul fold) and propagates carries so the canonical limbs are in
//! `[0, 2³⁰)`. This is **not** a full mod-`p` reduction yet — that
//! requires a final conditional subtraction of `p` and lands together
//! with the canonical-form chip in a later sub-phase. "Lazy" reduce
//! is sufficient for the intermediate normalisation needed between
//! field operations.
//!
//! Algorithm (per limb `i`, with `carry[0] = 0`):
//!
//!   `out[i] + 2³⁰ · carry[i+1] = in[i] + carry[i]`
//!
//! After `i = 8`, `carry[9]` captures the overflow above bit 270. For
//! the loose-input regime this overflow is bounded; the contract layer
//! is required to keep inputs in range so `carry[9] < 2⁴`.
//!
//! Trace layout (one operation per row, allocated at `start_col`):
//!
//! | offset  | name        |
//! |---------|-------------|
//! | 0..9    | in limbs    |
//! | 9..18   | out limbs   |
//! | 18..27  | carries[1..10] |
//!
//! Total width: 27 columns. 9 carry equations as constraints.
//!
//! ## Soundness gap (acknowledged, closed in 5.2.1.7)
//!
//! This chip does **not** range-check `out[i] < 2³⁰` or `carry[i] < 2⁴`
//! inline. A malicious prover could set arbitrary `out[i]` and matching
//! `carry[i+1]` to satisfy the equation. The downstream consumer
//! (a `Field25519Element` flowing into the next chip) is therefore
//! responsible for the range proof — typically by routing the `out`
//! limbs through `Range8Chip` (or a future 15-bit / 30-bit chip)
//! before they're consumed in a multiplicative position.
//!
//! In sub-phase 5.2.1.7 (top-level integration) the entire wiring uses
//! permutation arguments to pin every output limb to a range table,
//! closing this gap globally without bloating individual chips.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::{Field25519Element, LIMB_MOD, NUM_LIMBS};

pub const NUM_COLS: usize = 3 * NUM_LIMBS;
pub const NUM_CONSTRAINTS: usize = NUM_LIMBS;

#[derive(Debug, Clone, Copy)]
pub struct ReduceChip {
    pub start_col: usize,
}

impl ReduceChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    /// Emit `NUM_CONSTRAINTS` carry equations into the supplied builder.
    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let two_pow_30 = AB::Expr::from_u64(LIMB_MOD);

        // carry_in[0] is the boundary, set to 0.
        let mut carry_in: AB::Expr = AB::Expr::ZERO;
        for i in 0..NUM_LIMBS {
            let in_i = row[self.start_col + i];
            let out_i = row[self.start_col + NUM_LIMBS + i];
            let carry_out = row[self.start_col + 2 * NUM_LIMBS + i];

            // out[i] + 2^30 * carry_out = in[i] + carry_in
            builder.assert_eq(out_i.into() + two_pow_30.clone() * carry_out.into(), in_i.into() + carry_in);

            // Next iteration's carry_in is this iteration's carry_out.
            carry_in = carry_out.into();
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ReduceTestAir;

impl<F: Field> BaseAir<F> for ReduceTestAir {
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

impl<AB: AirBuilder> Air<AB> for ReduceTestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        ReduceChip::new().emit(builder);
    }
}

/// Witness computation. Returns `(canonical_out, carry_witness)` where
/// `canonical_out.limbs[i] ∈ [0, 2³⁰)` and `carry_witness[i]` is the
/// value that gets written into the carry column at position `i` (i.e.
/// `carry_out` from limb position `i`, or equivalently `carry_in` for
/// position `i+1`). The final carry (out of limb 8) is `carry_witness[8]`.
pub fn compute_reduce(input: &Field25519Element) -> (Field25519Element, [u64; NUM_LIMBS]) {
    let mut out = [0u64; NUM_LIMBS];
    let mut carries = [0u64; NUM_LIMBS];
    let mut carry: u64 = 0;
    for i in 0..NUM_LIMBS {
        let total = input.limbs[i] + carry;
        out[i] = total & (LIMB_MOD - 1); // bottom 30 bits
        carry = total >> 30;
        carries[i] = carry;
    }
    (Field25519Element { limbs: out }, carries)
}

/// Build a single-row test trace exercising one reduce operation. Pads
/// rows 1..3 with zeros, which trivially satisfy the carry equations
/// (in=0, out=0, carry=0).
pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(
    input: &Field25519Element,
    out: &Field25519Element,
    carries: &[u64; NUM_LIMBS],
) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];
    for i in 0..NUM_LIMBS {
        values[i] = F::from_u64(input.limbs[i]);
        values[NUM_LIMBS + i] = F::from_u64(out.limbs[i]);
        values[2 * NUM_LIMBS + i] = F::from_u64(carries[i]);
    }
    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    fn loose_elem(limbs: [u64; NUM_LIMBS]) -> Field25519Element {
        Field25519Element { limbs }
    }

    #[test]
    fn reduce_zero_is_zero() {
        let z = Field25519Element::ZERO;
        let (out, carries) = compute_reduce(&z);
        assert_eq!(out.limbs, [0u64; NUM_LIMBS]);
        assert_eq!(carries, [0u64; NUM_LIMBS]);
        let trace = build_test_trace::<BabyBear>(&z, &out, &carries);
        check_constraints(&ReduceTestAir, &trace, &[]);
    }

    #[test]
    fn reduce_already_canonical_is_identity() {
        // P_LIMBS happens to have all limbs already canonical (< 2^30).
        let p = Field25519Element::P;
        let (out, carries) = compute_reduce(&p);
        assert_eq!(out, p);
        assert_eq!(carries, [0u64; NUM_LIMBS]);
        let trace = build_test_trace::<BabyBear>(&p, &out, &carries);
        check_constraints(&ReduceTestAir, &trace, &[]);
    }

    #[test]
    fn reduce_propagates_single_carry() {
        // One limb above 2^30: limb 0 = 2^30 should carry 1 into limb 1.
        let input = loose_elem([LIMB_MOD, 0, 0, 0, 0, 0, 0, 0, 0]);
        let (out, carries) = compute_reduce(&input);
        assert_eq!(out.limbs[0], 0);
        assert_eq!(out.limbs[1], 1);
        assert_eq!(carries[0], 1);
        assert_eq!(carries[1], 0);
        let trace = build_test_trace::<BabyBear>(&input, &out, &carries);
        check_constraints(&ReduceTestAir, &trace, &[]);
    }

    #[test]
    fn reduce_propagates_chain_of_carries() {
        // Each limb is 2^30 - 1, plus limb 0 has +1 to trigger a chain.
        let mut limbs = [LIMB_MOD - 1; NUM_LIMBS];
        limbs[0] = LIMB_MOD; // forces carry that chains through all higher limbs
        let input = loose_elem(limbs);
        let (out, carries) = compute_reduce(&input);
        // After cascade: out[0] = 0 (from limb 0 = 2^30, carry=1).
        // out[1] = 0 (from (2^30-1)+1 = 2^30, carry=1). And so on for limbs 2..8.
        assert_eq!(out.limbs[0], 0);
        for i in 1..NUM_LIMBS {
            assert_eq!(out.limbs[i], 0, "out limb {i} should chain to 0");
            assert_eq!(carries[i - 1], 1, "carry into limb {i} should be 1");
        }
        // Final carry out is 1 (overflow above bit 270).
        assert_eq!(carries[NUM_LIMBS - 1], 1);
        let trace = build_test_trace::<BabyBear>(&input, &out, &carries);
        check_constraints(&ReduceTestAir, &trace, &[]);
    }

    #[test]
    fn reduce_handles_large_loose_limbs() {
        // Limbs near 2^33 (still bounded — within loose regime).
        let large: u64 = (1 << 33) - 7;
        let input = loose_elem([large, large, 0, 0, 0, 0, 0, 0, 0]);
        let (out, carries) = compute_reduce(&input);
        // out[0] = large mod 2^30 = (2^33 - 7) - 7*2^30 = 2^30 - 7
        // wait: 2^33 - 7 = 8 * 2^30 - 7 = 7 * 2^30 + (2^30 - 7).
        // So out[0] = 2^30 - 7, carry[0] = 7.
        assert_eq!(out.limbs[0], LIMB_MOD - 7);
        assert_eq!(carries[0], 7);
        let trace = build_test_trace::<BabyBear>(&input, &out, &carries);
        check_constraints(&ReduceTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn reduce_rejects_tampered_carry() {
        let input = loose_elem([LIMB_MOD, 0, 0, 0, 0, 0, 0, 0, 0]);
        let (out, mut carries) = compute_reduce(&input);
        carries[0] = 0; // claim no carry — out[1] = 1 is now inconsistent
        let trace = build_test_trace::<BabyBear>(&input, &out, &carries);
        check_constraints(&ReduceTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn reduce_rejects_tampered_output() {
        let input = loose_elem([42, 0, 0, 0, 0, 0, 0, 0, 0]);
        let (mut out, carries) = compute_reduce(&input);
        out.limbs[0] = 41; // off-by-one
        let trace = build_test_trace::<BabyBear>(&input, &out, &carries);
        check_constraints(&ReduceTestAir, &trace, &[]);
    }

    #[test]
    fn reduce_after_lazy_add_normalises() {
        use super::super::add::compute_add;
        // Compute (P + 1) lazily, then reduce. Should produce limbs
        // canonical (since P + 1 < 2 * P, fits in 256 bits).
        let one_limbs = {
            let mut l = [0u64; NUM_LIMBS];
            l[0] = 1;
            l
        };
        let one = Field25519Element { limbs: one_limbs };
        let lazy_sum = compute_add(&Field25519Element::P, &one);
        let (canonical, _carries) = compute_reduce(&lazy_sum);
        // Canonical value of P+1 in 9-limb: limb 0 = 2^30 - 18 (since 2^30-19+1 carries 0)
        // wait: P[0] = 2^30 - 19 = 0x3FFFFFED. +1 = 0x3FFFFFEE. Still < 2^30. No carry.
        assert_eq!(canonical.limbs[0], 0x3FFFFFEE);
        // Higher limbs unchanged.
        for i in 1..NUM_LIMBS {
            assert_eq!(canonical.limbs[i], super::super::P_LIMBS[i]);
        }
    }
}
