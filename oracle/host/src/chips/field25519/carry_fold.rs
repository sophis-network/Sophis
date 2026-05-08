//! `field25519::carry_fold` — canonicalise the 53 polynomial output
//! positions of the mul chip into 53 base-2¹⁰ positions in `[0, 2¹⁰)`.
//!
//! The mul chip outputs polynomial coefficients (one per position `2¹⁰ᵏ`)
//! that can be as large as `27 · (2¹⁰)² ≈ 2²⁵` because they accumulate
//! up to 27 cross-products. To bring the polynomial into a canonical
//! "every coefficient < 2¹⁰" form, we propagate carries left to right:
//!
//!   `canonical[k] + 2¹⁰ · carry[k+1] = pos[k] + carry[k]`
//!
//! with `carry[0] = 0` and `carry[k] ≤ 2¹⁶` (since the position values
//! are `≤ 2²⁵` and carries cumulate at most a few extra bits per step).
//!
//! After this chip, the 53 canonicalised positions can be cleanly
//! repacked into 30-bit limbs by the limb-assembly chip (sub-phase
//! 5.2.1.1.d), which is also where the `mod p` fold lands using
//! `2²⁵⁵ ≡ 19 (mod p)`.
//!
//! Trace layout (one operation per row, allocated at `start_col`):
//!
//! | offset    | width | name                                |
//! |-----------|-------|-------------------------------------|
//! | 0         | 53    | pos    — input polynomial positions |
//! | 53        | 53    | can    — canonical positions output |
//! | 106       | 53    | carry  — carry[i+1] for i ∈ 0..53   |
//!
//! Total: **159 columns**, **53 constraints**, max degree 1.
//!
//! ## Soundness gap (closed in 5.2.1.7)
//!
//! `can[k]` and `carry[k]` are not range-checked inline. A malicious
//! prover could spread the value across `(can, carry)` arbitrarily as
//! long as the linear equation holds. Range checks (each `can[k] < 2¹⁰`,
//! each `carry[k] < 2¹⁶`) close the gap in 5.2.1.7 via permutation
//! arguments to a shared range table.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::mul::{OUTPUT_POSITIONS, PIECE_BITS, PIECE_MOD};
use crate::chips::lookup::range_n::RangeNChip;

/// Number of polynomial positions handled by this chip (matches mul output).
pub const NUM_POSITIONS: usize = OUTPUT_POSITIONS; // 53

/// Range-check widths (Etapa 3.8).
/// `canonical[k] < 2^10` because the carry-fold equation forces it.
/// `carry[k]` accumulates `pos[k] + carry_in` then divides by 2^10. Max:
/// `pos[k] ≤ 27·(2^10)^2 ≈ 2^25`, `carry_in ≤ 2^15`, sum ≤ 2^25, divided
/// by 2^10 → carry ≤ 2^15. We pick **Range16** for headroom (covers up to
/// 2^16 = 65536, easily generous).
pub const CANONICAL_BITS: usize = 10;
pub const CARRY_BITS: usize = 16;

/// Trace column offsets within the chip's slice.
pub mod col {
    use super::*;
    pub const POS: usize = 0;
    pub const CAN: usize = POS + NUM_POSITIONS; // 53
    pub const CARRY: usize = CAN + NUM_POSITIONS; // 106
    pub const CAN_BITS_BASE: usize = CARRY + NUM_POSITIONS; // 159 — Etapa 3.8
    pub const CARRY_BITS_BASE: usize = CAN_BITS_BASE + NUM_POSITIONS * CANONICAL_BITS; // 689
    pub const TOTAL: usize = CARRY_BITS_BASE + NUM_POSITIONS * CARRY_BITS; // 1537
}

pub const NUM_COLS: usize = col::TOTAL;
/// 53 carry equations + 53 × (10+1) canonical range + 53 × (16+1) carry range
pub const NUM_CONSTRAINTS: usize = NUM_POSITIONS + NUM_POSITIONS * (CANONICAL_BITS + 1) + NUM_POSITIONS * (CARRY_BITS + 1);

#[derive(Debug, Clone, Copy)]
pub struct CarryFoldChip {
    pub start_col: usize,
}

impl CarryFoldChip {
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
        let two_pow_10 = AB::Expr::from_u64(PIECE_MOD);

        // carry_in[0] is the boundary, set to 0.
        let mut carry_in: AB::Expr = AB::Expr::ZERO;
        for k in 0..NUM_POSITIONS {
            let pos = row[self.start_col + col::POS + k];
            let can = row[self.start_col + col::CAN + k];
            let carry_out = row[self.start_col + col::CARRY + k];

            // can[k] + 2^10 * carry_out = pos[k] + carry_in
            builder.assert_eq(can.into() + two_pow_10.clone() * carry_out.into(), pos.into() + carry_in);

            carry_in = carry_out.into();
        }

        // ── 10-bit range checks on every canonical[k] (Etapa 3.8) ──────
        for k in 0..NUM_POSITIONS {
            RangeNChip::<CANONICAL_BITS>::split(
                self.start_col + col::CAN + k,
                self.start_col + col::CAN_BITS_BASE + k * CANONICAL_BITS,
            )
            .emit(builder);
        }

        // ── 16-bit range checks on every carry[k] (Etapa 3.8) ──────────
        for k in 0..NUM_POSITIONS {
            RangeNChip::<CARRY_BITS>::split(
                self.start_col + col::CARRY + k,
                self.start_col + col::CARRY_BITS_BASE + k * CARRY_BITS,
            )
            .emit(builder);
        }
    }
}

/// Standalone test AIR wrapping the chip.
#[derive(Debug, Clone, Copy)]
pub struct CarryFoldTestAir;

impl<F: Field> BaseAir<F> for CarryFoldTestAir {
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

impl<AB: AirBuilder> Air<AB> for CarryFoldTestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        CarryFoldChip::new().emit(builder);
    }
}

/// Witness layout returned by `compute_carry_fold`.
#[derive(Debug, Clone)]
pub struct CarryFoldWitness {
    pub canonical: [u64; NUM_POSITIONS],
    /// `carries[k]` = the carry out of position `k` (i.e. carry_in for `k+1`).
    /// `carries[NUM_POSITIONS - 1]` holds the final overflow.
    pub carries: [u64; NUM_POSITIONS],
}

/// Compute canonicalised positions and carry witness.
pub fn compute_carry_fold(positions: &[u64; NUM_POSITIONS]) -> CarryFoldWitness {
    let mut canonical = [0u64; NUM_POSITIONS];
    let mut carries = [0u64; NUM_POSITIONS];
    let mut carry: u64 = 0;
    for k in 0..NUM_POSITIONS {
        let total = positions[k] + carry;
        canonical[k] = total & (PIECE_MOD - 1);
        carry = total >> PIECE_BITS;
        carries[k] = carry;
    }
    CarryFoldWitness { canonical, carries }
}

/// Build a single-row test trace exercising one carry-fold operation.
/// Pads rows 1..3 with zeros (which trivially satisfy: 0=0+0).
pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(
    positions: &[u64; NUM_POSITIONS],
    w: &CarryFoldWitness,
) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];
    for k in 0..NUM_POSITIONS {
        values[col::POS + k] = F::from_u64(positions[k]);
        values[col::CAN + k] = F::from_u64(w.canonical[k]);
        values[col::CARRY + k] = F::from_u64(w.carries[k]);
        // Etapa 3.8 range bits.
        RangeNChip::<CANONICAL_BITS>::populate_bits::<F>(
            values.as_mut_slice(),
            col::CAN_BITS_BASE + k * CANONICAL_BITS,
            w.canonical[k],
        );
        RangeNChip::<CARRY_BITS>::populate_bits::<F>(
            values.as_mut_slice(),
            col::CARRY_BITS_BASE + k * CARRY_BITS,
            w.carries[k],
        );
    }
    RowMajorMatrix::new(values, NUM_COLS)
}

/// Reconstruct the integer value (mod 2¹²⁸ for ergonomics) from canonical
/// 10-bit positions plus the final carry. Used by tests to confirm the
/// fold preserves the underlying integer value.
pub fn reconstruct_canonical(w: &CarryFoldWitness) -> u128 {
    let mut acc: u128 = 0;
    for k in (0..NUM_POSITIONS).rev() {
        if 10 * k >= 128 {
            continue;
        }
        acc = acc.wrapping_add((w.canonical[k] as u128) << (10 * k));
    }
    // Add the final carry at position NUM_POSITIONS (one beyond the last).
    if 10 * NUM_POSITIONS < 128 {
        acc = acc.wrapping_add((w.carries[NUM_POSITIONS - 1] as u128) << (10 * NUM_POSITIONS));
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::mul::{OUTPUT_POSITIONS, compute_mul, reconstruct_product};
    use super::super::{Field25519Element, NUM_LIMBS};
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    fn elem_from_u64(n: u64) -> Field25519Element {
        let mut limbs = [0u64; NUM_LIMBS];
        limbs[0] = n & ((1 << 30) - 1);
        limbs[1] = (n >> 30) & ((1 << 30) - 1);
        Field25519Element { limbs }
    }

    #[test]
    fn fold_zero_is_zero() {
        let positions = [0u64; OUTPUT_POSITIONS];
        let w = compute_carry_fold(&positions);
        assert_eq!(w.canonical, [0u64; OUTPUT_POSITIONS]);
        assert_eq!(w.carries, [0u64; OUTPUT_POSITIONS]);
        let trace = build_test_trace::<BabyBear>(&positions, &w);
        check_constraints(&CarryFoldTestAir, &trace, &[]);
    }

    #[test]
    fn fold_already_canonical_is_identity() {
        let mut positions = [0u64; OUTPUT_POSITIONS];
        positions[0] = 100;
        positions[5] = 999;
        let w = compute_carry_fold(&positions);
        assert_eq!(w.canonical[0], 100);
        assert_eq!(w.canonical[5], 999);
        assert_eq!(w.carries, [0u64; OUTPUT_POSITIONS]);
        let trace = build_test_trace::<BabyBear>(&positions, &w);
        check_constraints(&CarryFoldTestAir, &trace, &[]);
    }

    #[test]
    fn fold_single_carry_to_next_position() {
        let mut positions = [0u64; OUTPUT_POSITIONS];
        positions[0] = PIECE_MOD; // 2^10
        let w = compute_carry_fold(&positions);
        assert_eq!(w.canonical[0], 0);
        assert_eq!(w.canonical[1], 1);
        assert_eq!(w.carries[0], 1);
        assert_eq!(w.carries[1], 0);
        let trace = build_test_trace::<BabyBear>(&positions, &w);
        check_constraints(&CarryFoldTestAir, &trace, &[]);
    }

    #[test]
    fn fold_max_position_value_chains() {
        // Set position 0 to 2^25 (max plausible mul output position).
        // Carry should be 2^15 = 32768 into position 1.
        let mut positions = [0u64; OUTPUT_POSITIONS];
        positions[0] = 1 << 25;
        let w = compute_carry_fold(&positions);
        assert_eq!(w.canonical[0], 0);
        assert_eq!(w.carries[0], 1 << 15);
        // carry of 32768 into position 1: 32768 = 32 * 1024, so canonical[1] = 0, carries[1] = 32.
        assert_eq!(w.canonical[1], 0);
        assert_eq!(w.carries[1], 32);
        let trace = build_test_trace::<BabyBear>(&positions, &w);
        check_constraints(&CarryFoldTestAir, &trace, &[]);
    }

    #[test]
    fn fold_then_reconstruct_preserves_small_integer() {
        // Construct a polynomial encoding the integer 12345*67890 = 838,102,050.
        let a = elem_from_u64(12345);
        let b = elem_from_u64(67890);
        let mul_w = compute_mul(&a, &b);
        let fold_w = compute_carry_fold(&mul_w.out_positions);
        // Verify both reconstructions agree on the integer value.
        let from_mul = reconstruct_product(&mul_w.out_positions);
        let from_fold = reconstruct_canonical(&fold_w);
        assert_eq!(from_mul, 12345u128 * 67890u128);
        assert_eq!(from_fold, from_mul);
    }

    #[test]
    fn fold_satisfies_air_for_real_mul_output() {
        // End-to-end: real mul chip output flows through carry fold.
        let a = elem_from_u64(0xABCDEF);
        let b = elem_from_u64(0x123456);
        let mul_w = compute_mul(&a, &b);
        let fold_w = compute_carry_fold(&mul_w.out_positions);
        let trace = build_test_trace::<BabyBear>(&mul_w.out_positions, &fold_w);
        check_constraints(&CarryFoldTestAir, &trace, &[]);
    }

    #[test]
    fn fold_handles_max_canonical_mul_output() {
        // Max canonical mul: every limb 2^30-1, every piece 2^10-1.
        // Middle position k=26 has 27 cross products of (2^10-1)^2.
        let max_elem = Field25519Element { limbs: [(1 << 30) - 1; NUM_LIMBS] };
        let mul_w = compute_mul(&max_elem, &max_elem);
        let fold_w = compute_carry_fold(&mul_w.out_positions);
        let trace = build_test_trace::<BabyBear>(&mul_w.out_positions, &fold_w);
        check_constraints(&CarryFoldTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn fold_rejects_tampered_canonical() {
        let mut positions = [0u64; OUTPUT_POSITIONS];
        positions[0] = 42;
        let w = compute_carry_fold(&positions);
        let mut trace = build_test_trace::<BabyBear>(&positions, &w);
        trace.values[col::CAN] = trace.values[col::CAN] + BabyBear::ONE;
        check_constraints(&CarryFoldTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn fold_rejects_tampered_carry() {
        let mut positions = [0u64; OUTPUT_POSITIONS];
        positions[0] = PIECE_MOD; // forces a real carry
        let w = compute_carry_fold(&positions);
        let mut trace = build_test_trace::<BabyBear>(&positions, &w);
        trace.values[col::CARRY] = trace.values[col::CARRY] + BabyBear::ONE; // bogus carry
        check_constraints(&CarryFoldTestAir, &trace, &[]);
    }

    #[test]
    fn constraint_count_matches_documented() {
        assert_eq!(NUM_POSITIONS, 53);
        // Etapa 3.8: 159 (POS+CAN+CARRY) + 530 (53×10 canonical bits) + 848 (53×16 carry bits) = 1537.
        assert_eq!(NUM_COLS, 1537);
        // 53 (carry equations) + 53×11 (canonical bool+recomp) + 53×17 (carry bool+recomp) = 1537.
        assert_eq!(NUM_CONSTRAINTS, 1537);
    }

    // ===== Etapa 3.8 — adversarial range-check rejection =====

    /// Tampering canonical[k] above 2^10 must be rejected.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_canonical_above_2_to_10() {
        let positions = [0u64; OUTPUT_POSITIONS];
        let w = compute_carry_fold(&positions);
        let mut trace = build_test_trace::<BabyBear>(&positions, &w);
        trace.values[col::CAN] = BabyBear::from_u64(1024);
        check_constraints(&CarryFoldTestAir, &trace, &[]);
    }

    /// Tampering carry[k] above 2^16 must be rejected.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_carry_above_2_to_16() {
        let positions = [0u64; OUTPUT_POSITIONS];
        let w = compute_carry_fold(&positions);
        let mut trace = build_test_trace::<BabyBear>(&positions, &w);
        trace.values[col::CARRY] = BabyBear::from_u64(1u64 << 16);
        check_constraints(&CarryFoldTestAir, &trace, &[]);
    }
}
