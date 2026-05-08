//! `field25519::limb_assembly` — pack 53 canonical base-2¹⁰ positions
//! plus the carry-fold overflow into 18 30-bit limbs.
//!
//! Output of `carry_fold`:
//!   - 53 canonical positions `can[0..53]`, each `< 2¹⁰`
//!   - 1 overflow carry `ovf` from position 52, which sits at bit 530
//!     (weight `2⁵³⁰`) and is `< 2¹⁰` for any real-mul-derived input
//!
//! Every 30-bit limb consumes 3 base-2¹⁰ positions:
//!
//!   `L[k] = can[3k] + 2¹⁰·can[3k+1] + 2²⁰·can[3k+2]`   for `k ∈ [0, 17)`
//!   `L[17] = can[51] + 2¹⁰·can[52] + 2²⁰·ovf`
//!
//! With `can[i] < 2¹⁰`, each limb's value is bounded by
//! `(2¹⁰-1)·(1 + 2¹⁰ + 2²⁰) ≈ 2³⁰` — comfortably below BabyBear's
//! ~2³¹ field, leaving a 2× margin.
//!
//! After this chip, the 18 30-bit limbs encode the full 540-bit
//! unreduced product `A·B`. The mod-`p` fold (using `2²⁵⁵ ≡ 19 (mod p)`)
//! lands in sub-phase 5.2.1.1.e and brings the value back to 9 canonical
//! limbs in `[0, p)`.
//!
//! Trace layout (one operation per row, allocated at `start_col`):
//!
//! | offset    | width | name                              |
//! |-----------|-------|-----------------------------------|
//! | 0         | 53    | can — canonical positions (input) |
//! | 53        | 1     | ovf — carry-fold overflow (input) |
//! | 54        | 18    | L   — output 30-bit limbs         |
//!
//! Total: **72 columns**, **18 constraints**, max degree 1.
//!
//! ## Soundness gap (closed in 5.2.1.7)
//!
//! Inputs `can[k]` and `ovf` are not range-checked inline (`< 2¹⁰`).
//! The downstream mod-p fold consumer must enforce the bound — either
//! by routing through a 10-bit lookup table (5.2.1.7) or by trusting
//! the upstream `carry_fold` chip's output range.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::carry_fold::{CarryFoldWitness, NUM_POSITIONS};
use super::mul::{PIECE_BITS, PIECE_MOD};

/// Number of 30-bit output limbs (`ceil(540 / 30) = 18`).
pub const NUM_OUTPUT_LIMBS: usize = 18;

/// Trace column offsets within the chip's slice.
pub mod col {
    use super::*;
    pub const CAN: usize = 0;
    pub const OVF: usize = CAN + NUM_POSITIONS; // 53
    pub const L: usize = OVF + 1; // 54
}

pub const NUM_COLS: usize = col::L + NUM_OUTPUT_LIMBS; // 72
pub const NUM_CONSTRAINTS: usize = NUM_OUTPUT_LIMBS; // 18

#[derive(Debug, Clone, Copy)]
pub struct LimbAssemblyChip {
    pub start_col: usize,
}

impl Default for LimbAssemblyChip {
    fn default() -> Self {
        Self::new()
    }
}

impl LimbAssemblyChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let two_pow_10 = AB::Expr::from_u64(PIECE_MOD);
        let two_pow_20 = AB::Expr::from_u64(PIECE_MOD * PIECE_MOD);

        for k in 0..NUM_OUTPUT_LIMBS {
            let p0 = if 3 * k < NUM_POSITIONS { row[self.start_col + col::CAN + 3 * k] } else { row[self.start_col + col::OVF] };
            let p1 = if 3 * k + 1 < NUM_POSITIONS {
                row[self.start_col + col::CAN + 3 * k + 1]
            } else if 3 * k + 1 == NUM_POSITIONS {
                row[self.start_col + col::OVF]
            } else {
                // Beyond OVF — for k=17, the third slot is OVF; for k>17 we'd
                // need more carry slots, but NUM_OUTPUT_LIMBS=18 means k<=17
                // and 3·17+1 = 52 which is still in CAN range, so this branch
                // is unreachable. Defensive: use a zero-valued column index 0.
                row[self.start_col + col::CAN]
            };
            let p2 = if 3 * k + 2 < NUM_POSITIONS {
                row[self.start_col + col::CAN + 3 * k + 2]
            } else if 3 * k + 2 == NUM_POSITIONS {
                row[self.start_col + col::OVF]
            } else {
                row[self.start_col + col::CAN]
            };

            let l_k = row[self.start_col + col::L + k];
            let recomposed = p0.into() + two_pow_10.clone() * p1.into() + two_pow_20.clone() * p2.into();
            builder.assert_eq(l_k, recomposed);
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LimbAssemblyTestAir;

impl<F: Field> BaseAir<F> for LimbAssemblyTestAir {
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

impl<AB: AirBuilder> Air<AB> for LimbAssemblyTestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        LimbAssemblyChip::new().emit(builder);
    }
}

/// Witness layout for limb assembly.
#[derive(Debug, Clone)]
pub struct LimbAssemblyWitness {
    pub limbs: [u64; NUM_OUTPUT_LIMBS],
}

/// Compute the 18-limb output from canonical positions and overflow carry.
///
/// `positions[k]` for `k ∈ [0, 53)` should be `< 2¹⁰` (output of carry_fold);
/// `overflow` is the final carry from carry_fold (also `< 2¹⁰` for real
/// mul-derived inputs).
pub fn compute_limb_assembly(positions: &[u64; NUM_POSITIONS], overflow: u64) -> LimbAssemblyWitness {
    let mut limbs = [0u64; NUM_OUTPUT_LIMBS];
    let get = |idx: usize| -> u64 {
        if idx < NUM_POSITIONS {
            positions[idx]
        } else if idx == NUM_POSITIONS {
            overflow
        } else {
            0
        }
    };
    for k in 0..NUM_OUTPUT_LIMBS {
        limbs[k] = get(3 * k) + (get(3 * k + 1) << PIECE_BITS) + (get(3 * k + 2) << (2 * PIECE_BITS));
    }
    LimbAssemblyWitness { limbs }
}

/// Convenience: compose with carry_fold output.
pub fn compute_limb_assembly_from_carry_fold(carry_fold_witness: &CarryFoldWitness) -> LimbAssemblyWitness {
    compute_limb_assembly(&carry_fold_witness.canonical, carry_fold_witness.carries[NUM_POSITIONS - 1])
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(
    positions: &[u64; NUM_POSITIONS],
    overflow: u64,
    w: &LimbAssemblyWitness,
) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];
    for k in 0..NUM_POSITIONS {
        values[col::CAN + k] = F::from_u64(positions[k]);
    }
    values[col::OVF] = F::from_u64(overflow);
    for k in 0..NUM_OUTPUT_LIMBS {
        values[col::L + k] = F::from_u64(w.limbs[k]);
    }
    RowMajorMatrix::new(values, NUM_COLS)
}

/// Reconstruct the integer value (mod 2¹²⁸ for ergonomics) from 18
/// 30-bit limbs.
pub fn reconstruct_limbs(w: &LimbAssemblyWitness) -> u128 {
    let mut acc: u128 = 0;
    for k in (0..NUM_OUTPUT_LIMBS).rev() {
        if 30 * k >= 128 {
            continue;
        }
        acc = acc.wrapping_add((w.limbs[k] as u128) << (30 * k));
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::super::carry_fold::compute_carry_fold;
    use super::super::mul::{compute_mul, reconstruct_product};
    use super::super::{Field25519Element, NUM_LIMBS};
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    fn elem_from_u64(n: u64) -> Field25519Element {
        let mut limbs = [0u64; NUM_LIMBS];
        limbs[0] = n & ((1 << 30) - 1);
        limbs[1] = (n >> 30) & ((1 << 30) - 1);
        Field25519Element { limbs }
    }

    #[test]
    fn assembly_zero_is_zero() {
        let positions = [0u64; NUM_POSITIONS];
        let w = compute_limb_assembly(&positions, 0);
        assert_eq!(w.limbs, [0u64; NUM_OUTPUT_LIMBS]);
        let trace = build_test_trace::<BabyBear>(&positions, 0, &w);
        check_constraints(&LimbAssemblyTestAir, &trace, &[]);
    }

    #[test]
    fn assembly_single_position_correct_limb() {
        // Set position 5 (= bit 50, inside limb 1 [bits 30..59], specifically bit 20 of limb 1).
        let mut positions = [0u64; NUM_POSITIONS];
        positions[5] = 0x3ff; // 10 bits all set
        let w = compute_limb_assembly(&positions, 0);
        // Limb 0 (positions 0,1,2): all zero -> 0
        assert_eq!(w.limbs[0], 0);
        // Limb 1 (positions 3,4,5): position 5 contributes at 2^20 within the limb
        assert_eq!(w.limbs[1], 0x3ff << 20);
        for k in 2..NUM_OUTPUT_LIMBS {
            assert_eq!(w.limbs[k], 0, "limb {k} should be zero");
        }
        let trace = build_test_trace::<BabyBear>(&positions, 0, &w);
        check_constraints(&LimbAssemblyTestAir, &trace, &[]);
    }

    #[test]
    fn assembly_overflow_lands_in_limb_17() {
        // OVF goes at position 53 (bit 530), which is bit 20 of limb 17 (bits 510..539).
        let positions = [0u64; NUM_POSITIONS];
        let overflow = 0x3ff;
        let w = compute_limb_assembly(&positions, overflow);
        // Only limb 17 should be non-zero, with value = overflow << 20.
        assert_eq!(w.limbs[17], overflow << 20);
        for k in 0..17 {
            assert_eq!(w.limbs[k], 0, "limb {k} should be zero");
        }
        let trace = build_test_trace::<BabyBear>(&positions, overflow, &w);
        check_constraints(&LimbAssemblyTestAir, &trace, &[]);
    }

    #[test]
    fn assembly_max_canonical_satisfies_air() {
        // Every position at 2^10 - 1, overflow at 2^10 - 1.
        let positions = [PIECE_MOD - 1; NUM_POSITIONS];
        let overflow = PIECE_MOD - 1;
        let w = compute_limb_assembly(&positions, overflow);
        // Each limb value = (2^10-1) * (1 + 2^10 + 2^20) ≈ 2^30 - just under BabyBear.
        let expected_limb = (PIECE_MOD - 1) * (1 + PIECE_MOD + PIECE_MOD * PIECE_MOD);
        for k in 0..NUM_OUTPUT_LIMBS {
            assert_eq!(w.limbs[k], expected_limb, "limb {k} mismatch");
        }
        let trace = build_test_trace::<BabyBear>(&positions, overflow, &w);
        check_constraints(&LimbAssemblyTestAir, &trace, &[]);
    }

    #[test]
    fn end_to_end_mul_carry_fold_assembly_preserves_integer() {
        let a = elem_from_u64(0x1234_5678);
        let b = elem_from_u64(0x9ABC_DEF0);
        let mul_w = compute_mul(&a, &b);
        let fold_w = compute_carry_fold(&mul_w.out_positions);
        let assembly_w = compute_limb_assembly_from_carry_fold(&fold_w);

        let from_mul = reconstruct_product(&mul_w.out_positions);
        let from_assembly = reconstruct_limbs(&assembly_w);
        let expected = (0x1234_5678u128) * (0x9ABC_DEF0u128);

        assert_eq!(from_mul, expected, "mul reconstruction wrong");
        assert_eq!(from_assembly, expected, "assembly reconstruction wrong");

        // Also verify the AIR is satisfied for this real input.
        let trace = build_test_trace::<BabyBear>(&fold_w.canonical, fold_w.carries[NUM_POSITIONS - 1], &assembly_w);
        check_constraints(&LimbAssemblyTestAir, &trace, &[]);
    }

    #[test]
    fn assembly_max_canonical_mul_satisfies_air() {
        // End-to-end: every input limb 2^30-1.
        let max_elem = Field25519Element { limbs: [(1 << 30) - 1; NUM_LIMBS] };
        let mul_w = compute_mul(&max_elem, &max_elem);
        let fold_w = compute_carry_fold(&mul_w.out_positions);
        let assembly_w = compute_limb_assembly_from_carry_fold(&fold_w);
        let trace = build_test_trace::<BabyBear>(&fold_w.canonical, fold_w.carries[NUM_POSITIONS - 1], &assembly_w);
        check_constraints(&LimbAssemblyTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn assembly_rejects_tampered_limb() {
        let mut positions = [0u64; NUM_POSITIONS];
        positions[0] = 42;
        let w = compute_limb_assembly(&positions, 0);
        let mut trace = build_test_trace::<BabyBear>(&positions, 0, &w);
        trace.values[col::L] += BabyBear::ONE;
        check_constraints(&LimbAssemblyTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn assembly_rejects_tampered_position() {
        let mut positions = [0u64; NUM_POSITIONS];
        positions[1] = 7;
        let w = compute_limb_assembly(&positions, 0);
        let mut trace = build_test_trace::<BabyBear>(&positions, 0, &w);
        trace.values[col::CAN + 1] += BabyBear::ONE;
        check_constraints(&LimbAssemblyTestAir, &trace, &[]);
    }

    #[test]
    fn constraint_count_matches_documented() {
        assert_eq!(NUM_OUTPUT_LIMBS, 18);
        assert_eq!(NUM_COLS, 72);
        assert_eq!(NUM_CONSTRAINTS, 18);
    }
}
