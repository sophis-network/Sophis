//! `field25519::first_fold` — first-fold AIR for mod-p reduction.
//!
//! Computes `out = V_lo + V_hi · M (mod 2³⁰⁰)` where:
//!   - `V_lo`: low 9 limbs of input (`L[0..9]`)
//!   - `V_hi`: high 9 limbs (`L[9..18]`)
//!   - `M = 19 · 2¹⁵ = 622592` (the fold multiplier from `2²⁷⁰ ≡ M (mod p)`)
//!
//! Output is 10 30-bit limbs (canonical via inline carry propagation).
//! The 10th limb is the leftover from `L[17] · M`'s high half — needs
//! one more fold pass (handled by `cond_p_sub` + iteration in the
//! composing `mod_p_chip`).
//!
//! ## Strategy
//!
//! For each high limb `L[k+9]` (`k ∈ 0..9`):
//!   1. Decompose into 3 10-bit pieces: `L[k+9] = a_k + 2¹⁰·b_k + 2²⁰·c_k`.
//!   2. Compute partial products `q_a = M·a_k`, `q_b = M·b_k`, `q_c = M·c_k`
//!      (each `< 2³⁰`, fits BabyBear).
//!   3. Witness the split of `L[k+9]·M` into `low_30 + 2³⁰·high_20`:
//!        `low_30[k] + 2³⁰·high_20[k] = q_a + 2¹⁰·q_b + 2²⁰·q_c`
//!
//! Then for each output limb `m`:
//!   `out[m] + 2³⁰·carry[m+1] = (V_lo[m] if m<9 else 0)`
//!                            `+ (low_30[m] if m<9 else 0)`
//!                            `+ (high_20[m-1] if m>=1 else 0)`
//!                            `+ carry[m]`
//!
//! ## Layout (one operation per row, allocated at `start_col`)
//!
//! | Range       | Width | Contents                              |
//! |-------------|-------|---------------------------------------|
//! | 0..18       | 18    | L (input limbs 0..18)                 |
//! | 18..28      | 10    | out (canonical 30-bit output limbs)   |
//! | 28..38      | 10    | carry[1..11] (boundary carry[0] = 0)  |
//! | 38..65      | 27    | pieces (a_k, b_k, c_k for each high limb) |
//! | 65..92      | 27    | partial products q_a, q_b, q_c        |
//! | 92..101     | 9     | low_30[k] for k ∈ 0..9                |
//! | 101..110    | 9     | high_20[k] for k ∈ 0..9               |
//!
//! Total: **110 columns**, **~78 constraints** (degree 2 max).
//!
//! ## Soundness gap (closes in 5.2.1.7 with lookup args)
//!
//! Range checks on pieces (< 2¹⁰), low_30 (< 2³⁰), high_20 (< 2²⁰), and
//! carries are deferred. Without them, an adversarial prover could
//! exploit BabyBear wrap-around to satisfy the equations dishonestly.
//! For canonical inputs in the regime expected (mul output of two
//! canonical 9-limb elements), the witness function is correct and the
//! AIR enforces the intended arithmetic.
//!
//! Cross-validation: tested against `compute_first_fold` witness
//! function bit-for-bit, which is itself FIPS-grade tested via
//! end-to-end pipeline RFC 8032 vectors.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::mod_p::{FOLD_M, compute_first_fold};
use super::{LIMB_MOD, NUM_LIMBS};
use crate::chips::lookup::range_n::RangeNChip;

const NUM_INPUT_LIMBS: usize = 18;
const NUM_OUTPUT_LIMBS: usize = 10;
const NUM_HIGH: usize = 9;
const PIECES_PER_HIGH: usize = 3;
const PIECE_BITS: usize = 10;

/// Bit widths of LOW_30 / HIGH_20 (Etapa 3.6 range check sizes).
pub const LOW_30_BITS: usize = 30;
pub const HIGH_20_BITS: usize = 20;

/// Bit width for first_fold carries (Etapa 3.8). RHS at each step is
/// V_lo[m] + low_30[m] + high_20[m-1] + carry_in ≤ 2^30 + 2^30 + 2^20 + carry_in
/// ≤ ~2^31 (BabyBear-safe by construction). After /2^30 → carry ≤ 2,
/// but with iteration carry can reach ~4. Range10 (1024 max) is far
/// above the real bound and uniformly cheap.
pub const CARRY_BITS: usize = 10;

pub mod col {
    use super::*;
    pub const L: usize = 0;
    pub const OUT: usize = L + NUM_INPUT_LIMBS;        // 18
    pub const CARRY: usize = OUT + NUM_OUTPUT_LIMBS;   // 28
    pub const PIECES: usize = CARRY + NUM_OUTPUT_LIMBS; // 38
    pub const PRODUCTS: usize = PIECES + NUM_HIGH * PIECES_PER_HIGH; // 65
    pub const LOW_30: usize = PRODUCTS + NUM_HIGH * PIECES_PER_HIGH; // 92
    pub const HIGH_20: usize = LOW_30 + NUM_HIGH;       // 101
    pub const PIECE_BITS_BASE: usize = HIGH_20 + NUM_HIGH; // 110 — Etapa 3.3
    pub const LOW_30_BITS_BASE: usize = PIECE_BITS_BASE + NUM_HIGH * PIECES_PER_HIGH * PIECE_BITS; // 380 — Etapa 3.6
    pub const HIGH_20_BITS_BASE: usize = LOW_30_BITS_BASE + NUM_HIGH * LOW_30_BITS; // 650 — Etapa 3.6
    pub const CARRY_BITS_BASE: usize = HIGH_20_BITS_BASE + NUM_HIGH * HIGH_20_BITS; // 830 — Etapa 3.8
    pub const TOTAL: usize = CARRY_BITS_BASE + NUM_OUTPUT_LIMBS * CARRY_BITS; // 930
}

pub const NUM_COLS: usize = col::TOTAL;

#[derive(Debug, Clone, Copy)]
pub struct FirstFoldChip {
    pub start_col: usize,
}

impl FirstFoldChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let two_pow_10 = AB::Expr::from_u64(1u64 << 10);
        let two_pow_20 = AB::Expr::from_u64(1u64 << 20);
        let two_pow_30 = AB::Expr::from_u64(LIMB_MOD);

        // Per high limb constraints (k in 0..9).
        for k in 0..NUM_HIGH {
            let l_high = row[self.start_col + col::L + NUM_LIMBS + k]; // L[k+9]
            let a_k = row[self.start_col + col::PIECES + 3 * k];
            let b_k = row[self.start_col + col::PIECES + 3 * k + 1];
            let c_k = row[self.start_col + col::PIECES + 3 * k + 2];
            let q_a = row[self.start_col + col::PRODUCTS + 3 * k];
            let q_b = row[self.start_col + col::PRODUCTS + 3 * k + 1];
            let q_c = row[self.start_col + col::PRODUCTS + 3 * k + 2];
            let low_k = row[self.start_col + col::LOW_30 + k];
            let high_k = row[self.start_col + col::HIGH_20 + k];

            let m_const = AB::Expr::from_u64(FOLD_M);

            // Decomposition: L[k+9] = a + 2^10·b + 2^20·c
            builder.assert_eq(
                l_high,
                a_k.into() + two_pow_10.clone() * b_k.into() + two_pow_20.clone() * c_k.into(),
            );

            // Partial products: q_x = M · piece_x.
            builder.assert_eq(q_a, m_const.clone() * a_k.into());
            builder.assert_eq(q_b, m_const.clone() * b_k.into());
            builder.assert_eq(q_c, m_const.clone() * c_k.into());

            // Split: low + 2^30·high = q_a + 2^10·q_b + 2^20·q_c.
            builder.assert_eq(
                low_k.into() + two_pow_30.clone() * high_k.into(),
                q_a.into() + two_pow_10.clone() * q_b.into() + two_pow_20.clone() * q_c.into(),
            );
        }

        // Per output limb constraints (m in 0..10).
        let mut carry_in: AB::Expr = AB::Expr::ZERO;
        for m in 0..NUM_OUTPUT_LIMBS {
            let out_m = row[self.start_col + col::OUT + m];
            let carry_out = row[self.start_col + col::CARRY + m];

            let mut rhs: AB::Expr = carry_in;
            // V_lo[m] contribution (only if m < 9)
            if m < NUM_LIMBS {
                rhs = rhs + row[self.start_col + col::L + m].into();
            }
            // low_30[m] contribution (m < 9)
            if m < NUM_HIGH {
                rhs = rhs + row[self.start_col + col::LOW_30 + m].into();
            }
            // high_20[m-1] contribution (m >= 1)
            if m >= 1 && m - 1 < NUM_HIGH {
                rhs = rhs + row[self.start_col + col::HIGH_20 + (m - 1)].into();
            }

            // out[m] + 2^30 · carry_out = rhs
            builder.assert_eq(out_m.into() + two_pow_30.clone() * carry_out.into(), rhs);

            carry_in = carry_out.into();
        }

        // ── 10-bit range checks on every piece (Etapa 3.3) ─────────────
        // The 27 pieces (a_k, b_k, c_k for k ∈ 0..9) feed the partial
        // products and the limb decomposition. Range-check each via
        // split-layout RangeNChip<10>; bit columns live in the
        // PIECE_BITS_BASE region.
        let total_pieces = NUM_HIGH * PIECES_PER_HIGH;
        for i in 0..total_pieces {
            RangeNChip::<PIECE_BITS>::split(
                self.start_col + col::PIECES + i,
                self.start_col + col::PIECE_BITS_BASE + i * PIECE_BITS,
            )
            .emit(builder);
        }

        // ── 30-bit range checks on LOW_30 (Etapa 3.6) ──────────────────
        // Each `low_30[k]` holds the canonical 30-bit residue of
        // `M·L[k+9]`'s low half. Without a range check, an adversarial
        // prover could pick a value > 2^30 that wraps around in BabyBear
        // (~2^31) to satisfy `low + 2^30·high == q_a + 2^10·q_b + 2^20·q_c`.
        // The bit-decomposition + recomposition forces low_30[k] ∈ [0, 2^30).
        for k in 0..NUM_HIGH {
            RangeNChip::<LOW_30_BITS>::split(
                self.start_col + col::LOW_30 + k,
                self.start_col + col::LOW_30_BITS_BASE + k * LOW_30_BITS,
            )
            .emit(builder);
        }

        // ── 20-bit range checks on HIGH_20 (Etapa 3.6) ─────────────────
        // Each `high_20[k]` holds the high half of `M·L[k+9]`. M = 19·2^15
        // and L[k+9] ≤ 2^30 - 1, so the product fits in 49 bits and the
        // high half is ≤ 2^20 - 1. Range check enforces this exactly.
        for k in 0..NUM_HIGH {
            RangeNChip::<HIGH_20_BITS>::split(
                self.start_col + col::HIGH_20 + k,
                self.start_col + col::HIGH_20_BITS_BASE + k * HIGH_20_BITS,
            )
            .emit(builder);
        }

        // ── 10-bit range checks on per-limb carries (Etapa 3.8) ────────
        // Each `carry[m]` is the overflow of the per-output-limb sum.
        // Real bound is ≤ ~4, but Range10 is uniform with other chips
        // and safely covers any future RHS adjustment.
        for m in 0..NUM_OUTPUT_LIMBS {
            RangeNChip::<CARRY_BITS>::split(
                self.start_col + col::CARRY + m,
                self.start_col + col::CARRY_BITS_BASE + m * CARRY_BITS,
            )
            .emit(builder);
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FirstFoldTestAir;

impl<F: Field> BaseAir<F> for FirstFoldTestAir {
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

impl<AB: AirBuilder> Air<AB> for FirstFoldTestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        FirstFoldChip::new().emit(builder);
    }
}

#[derive(Debug, Clone)]
pub struct FirstFoldWitness {
    pub l: [u64; NUM_INPUT_LIMBS],
    pub out: [u64; NUM_OUTPUT_LIMBS],
    pub carries: [u64; NUM_OUTPUT_LIMBS],
    pub pieces: [u64; NUM_HIGH * PIECES_PER_HIGH],
    pub products: [u64; NUM_HIGH * PIECES_PER_HIGH],
    pub low_30: [u64; NUM_HIGH],
    pub high_20: [u64; NUM_HIGH],
}

pub fn compute_first_fold_witness(input: &[u64; NUM_INPUT_LIMBS]) -> FirstFoldWitness {
    // Use existing witness fn for output canonical limbs and carries.
    let acc_loose = compute_first_fold(input);

    // Extract output limbs and carries from acc_loose.
    let mut out = [0u64; NUM_OUTPUT_LIMBS];
    let mut carries = [0u64; NUM_OUTPUT_LIMBS];

    // Re-derive the per-limb computation that compute_first_fold does:
    // acc_loose already has carry-propagation done (each limb < 2^30).
    // We need the per-limb carry chain that the AIR enforces.
    // Re-compute from scratch matching the AIR's constraint structure.
    let mut pieces = [0u64; NUM_HIGH * PIECES_PER_HIGH];
    let mut products = [0u64; NUM_HIGH * PIECES_PER_HIGH];
    let mut low_30 = [0u64; NUM_HIGH];
    let mut high_20 = [0u64; NUM_HIGH];

    let mask_10 = (1u64 << PIECE_BITS) - 1;

    for k in 0..NUM_HIGH {
        let l_high = input[NUM_LIMBS + k];
        let a = l_high & mask_10;
        let b = (l_high >> PIECE_BITS) & mask_10;
        let c = (l_high >> (2 * PIECE_BITS)) & mask_10;
        pieces[3 * k] = a;
        pieces[3 * k + 1] = b;
        pieces[3 * k + 2] = c;

        let q_a = FOLD_M * a;
        let q_b = FOLD_M * b;
        let q_c = FOLD_M * c;
        products[3 * k] = q_a;
        products[3 * k + 1] = q_b;
        products[3 * k + 2] = q_c;

        let total = q_a + (q_b << PIECE_BITS) + (q_c << (2 * PIECE_BITS));
        low_30[k] = total & ((1u64 << 30) - 1);
        high_20[k] = total >> 30;
    }

    // Per-output-limb carry chain
    let mut carry: u64 = 0;
    for m in 0..NUM_OUTPUT_LIMBS {
        let mut rhs = carry;
        if m < NUM_LIMBS {
            rhs += input[m];
        }
        if m < NUM_HIGH {
            rhs += low_30[m];
        }
        if m >= 1 && m - 1 < NUM_HIGH {
            rhs += high_20[m - 1];
        }
        out[m] = rhs & ((1u64 << 30) - 1);
        carry = rhs >> 30;
        carries[m] = carry;
    }

    // Sanity: matches compute_first_fold's output (which already does carry-propagation).
    debug_assert_eq!(out[0] as u128, acc_loose[0]);

    FirstFoldWitness { l: *input, out, carries, pieces, products, low_30, high_20 }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(w: &FirstFoldWitness) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    // Padding rows: input = all zero. All-zero input → witness all zero, all
    // constraints trivially satisfied.
    let zero_witness = compute_first_fold_witness(&[0u64; NUM_INPUT_LIMBS]);
    for row in 0..HEIGHT {
        let off = row * NUM_COLS;
        for i in 0..NUM_INPUT_LIMBS {
            values[off + col::L + i] = F::from_u64(zero_witness.l[i]);
        }
        for i in 0..NUM_OUTPUT_LIMBS {
            values[off + col::OUT + i] = F::from_u64(zero_witness.out[i]);
            values[off + col::CARRY + i] = F::from_u64(zero_witness.carries[i]);
            // Etapa 3.8: 10-bit range bits for first_fold carry[i].
            RangeNChip::<CARRY_BITS>::populate_bits::<F>(
                values.as_mut_slice(),
                off + col::CARRY_BITS_BASE + i * CARRY_BITS,
                zero_witness.carries[i],
            );
        }
        for i in 0..NUM_HIGH * PIECES_PER_HIGH {
            values[off + col::PIECES + i] = F::from_u64(zero_witness.pieces[i]);
            values[off + col::PRODUCTS + i] = F::from_u64(zero_witness.products[i]);
            // Etapa 3.3: 10-bit range bits for piece[i].
            RangeNChip::<PIECE_BITS>::populate_bits::<F>(
                values.as_mut_slice(),
                off + col::PIECE_BITS_BASE + i * PIECE_BITS,
                zero_witness.pieces[i],
            );
        }
        for i in 0..NUM_HIGH {
            values[off + col::LOW_30 + i] = F::from_u64(zero_witness.low_30[i]);
            values[off + col::HIGH_20 + i] = F::from_u64(zero_witness.high_20[i]);
            // Etapa 3.6: 30-bit and 20-bit range bits.
            RangeNChip::<LOW_30_BITS>::populate_bits::<F>(
                values.as_mut_slice(),
                off + col::LOW_30_BITS_BASE + i * LOW_30_BITS,
                zero_witness.low_30[i],
            );
            RangeNChip::<HIGH_20_BITS>::populate_bits::<F>(
                values.as_mut_slice(),
                off + col::HIGH_20_BITS_BASE + i * HIGH_20_BITS,
                zero_witness.high_20[i],
            );
        }
    }

    // Overwrite row 0 with the actual witness.
    for i in 0..NUM_INPUT_LIMBS {
        values[col::L + i] = F::from_u64(w.l[i]);
    }
    for i in 0..NUM_OUTPUT_LIMBS {
        values[col::OUT + i] = F::from_u64(w.out[i]);
        values[col::CARRY + i] = F::from_u64(w.carries[i]);
        // Etapa 3.8: 10-bit range bits for first_fold carry[i].
        RangeNChip::<CARRY_BITS>::populate_bits::<F>(
            values.as_mut_slice(),
            col::CARRY_BITS_BASE + i * CARRY_BITS,
            w.carries[i],
        );
    }
    for i in 0..NUM_HIGH * PIECES_PER_HIGH {
        values[col::PIECES + i] = F::from_u64(w.pieces[i]);
        values[col::PRODUCTS + i] = F::from_u64(w.products[i]);
        RangeNChip::<PIECE_BITS>::populate_bits::<F>(
            values.as_mut_slice(),
            col::PIECE_BITS_BASE + i * PIECE_BITS,
            w.pieces[i],
        );
    }
    for i in 0..NUM_HIGH {
        values[col::LOW_30 + i] = F::from_u64(w.low_30[i]);
        values[col::HIGH_20 + i] = F::from_u64(w.high_20[i]);
        // Etapa 3.6: 30-bit and 20-bit range bits.
        RangeNChip::<LOW_30_BITS>::populate_bits::<F>(
            values.as_mut_slice(),
            col::LOW_30_BITS_BASE + i * LOW_30_BITS,
            w.low_30[i],
        );
        RangeNChip::<HIGH_20_BITS>::populate_bits::<F>(
            values.as_mut_slice(),
            col::HIGH_20_BITS_BASE + i * HIGH_20_BITS,
            w.high_20[i],
        );
    }

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    #[test]
    fn first_fold_zero_is_zero() {
        let input = [0u64; NUM_INPUT_LIMBS];
        let w = compute_first_fold_witness(&input);
        assert_eq!(w.out, [0u64; NUM_OUTPUT_LIMBS]);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&FirstFoldTestAir, &trace, &[]);
    }

    #[test]
    fn first_fold_low_only_passthrough() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[0] = 100;
        input[5] = 999;
        let w = compute_first_fold_witness(&input);
        assert_eq!(w.out[0], 100);
        assert_eq!(w.out[5], 999);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&FirstFoldTestAir, &trace, &[]);
    }

    #[test]
    fn first_fold_single_high_limb_yields_m() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[NUM_LIMBS] = 1; // L[9] = 1
        let w = compute_first_fold_witness(&input);
        assert_eq!(w.out[0], FOLD_M);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&FirstFoldTestAir, &trace, &[]);
    }

    #[test]
    fn first_fold_max_high_limb_spans_two() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[NUM_LIMBS] = (1u64 << 30) - 1; // L[9] = max canonical
        let w = compute_first_fold_witness(&input);
        // (2^30 - 1) * M = ~2^50. low_30 is the low 30 bits, high_20 the rest.
        let total = ((1u64 << 30) - 1) * FOLD_M;
        assert_eq!(w.low_30[0], total & ((1u64 << 30) - 1));
        assert_eq!(w.high_20[0], total >> 30);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&FirstFoldTestAir, &trace, &[]);
    }

    #[test]
    fn first_fold_matches_compute_first_fold() {
        // Cross-validation against the witness function (already FIPS-tested).
        let mut input = [0u64; NUM_INPUT_LIMBS];
        // Some non-trivial input with both V_lo and V_hi populated.
        input[0] = 0x1234;
        input[3] = 0x5678;
        input[NUM_LIMBS] = 0x9ABC;
        input[NUM_LIMBS + 5] = 0xDEAD;
        let w = compute_first_fold_witness(&input);
        let acc_loose = compute_first_fold(&input);
        for i in 0..NUM_OUTPUT_LIMBS {
            assert_eq!(w.out[i] as u128, acc_loose[i], "limb {i} mismatch");
        }
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&FirstFoldTestAir, &trace, &[]);
    }

    #[test]
    fn first_fold_max_canonical_input() {
        // Stress: every limb at 2^30 - 1.
        let input = [(1u64 << 30) - 1; NUM_INPUT_LIMBS];
        let w = compute_first_fold_witness(&input);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&FirstFoldTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn first_fold_rejects_tampered_out() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[0] = 0x1234;
        input[NUM_LIMBS] = 0x5678;
        let w = compute_first_fold_witness(&input);
        let mut trace = build_test_trace::<BabyBear>(&w);
        trace.values[col::OUT] = trace.values[col::OUT] + BabyBear::ONE;
        check_constraints(&FirstFoldTestAir, &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        // Etapa 3.3 (+270 piece bits) + 3.6 (+270 low_30 + +180 high_20) + 3.8 (+100 carry) = +820.
        assert_eq!(NUM_COLS, 930);
    }

    // ===== Etapa 3.4 — adversarial range-check rejection =====

    /// Tampering a piece column to > 2^10 must be rejected by the
    /// 10-bit range chip's recomposition constraint.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_piece_above_2_to_10() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[NUM_LIMBS] = 1; // smallest non-trivial high-limb value
        let w = compute_first_fold_witness(&input);
        let mut trace = build_test_trace::<BabyBear>(&w);
        // Mutate piece a_0 (= input low 10 bits) to 1024.
        trace.values[col::PIECES] = BabyBear::from_u64(1024);
        check_constraints(&FirstFoldTestAir, &trace, &[]);
    }

    /// Setting a piece-bit column to a non-boolean value must fail.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_non_boolean_piece_bit() {
        let input = [0u64; NUM_INPUT_LIMBS];
        let w = compute_first_fold_witness(&input);
        let mut trace = build_test_trace::<BabyBear>(&w);
        // Set bit 0 of piece 5 to non-boolean value.
        let bit_off = col::PIECE_BITS_BASE + 5 * PIECE_BITS;
        trace.values[bit_off] = BabyBear::from_u64(7);
        check_constraints(&FirstFoldTestAir, &trace, &[]);
    }

    // ===== Etapa 3.6 — adversarial range-check rejection on LOW_30 / HIGH_20 =====

    /// Tampering low_30[k] to ≥ 2^30 must be rejected by the 30-bit
    /// recomposition constraint.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_low_30_above_2_to_30() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[NUM_LIMBS] = 1; // smallest non-trivial high-limb value
        let w = compute_first_fold_witness(&input);
        let mut trace = build_test_trace::<BabyBear>(&w);
        // Mutate low_30[0] to 2^30. The 30 bits encode the original
        // (in-range) value; recomposition constraint must reject.
        trace.values[col::LOW_30] = BabyBear::from_u64(1u64 << 30);
        check_constraints(&FirstFoldTestAir, &trace, &[]);
    }

    /// Tampering high_20[k] to ≥ 2^20 must be rejected by the 20-bit
    /// recomposition constraint.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_high_20_above_2_to_20() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[NUM_LIMBS] = 1;
        let w = compute_first_fold_witness(&input);
        let mut trace = build_test_trace::<BabyBear>(&w);
        // Mutate high_20[0] to 2^20.
        trace.values[col::HIGH_20] = BabyBear::from_u64(1u64 << 20);
        check_constraints(&FirstFoldTestAir, &trace, &[]);
    }

    /// Setting a low_30 bit column to non-boolean must fail.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_non_boolean_low_30_bit() {
        let input = [0u64; NUM_INPUT_LIMBS];
        let w = compute_first_fold_witness(&input);
        let mut trace = build_test_trace::<BabyBear>(&w);
        let bit_off = col::LOW_30_BITS_BASE + 3 * LOW_30_BITS + 7;
        trace.values[bit_off] = BabyBear::from_u64(2);
        check_constraints(&FirstFoldTestAir, &trace, &[]);
    }

    /// Setting a high_20 bit column to non-boolean must fail.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_non_boolean_high_20_bit() {
        let input = [0u64; NUM_INPUT_LIMBS];
        let w = compute_first_fold_witness(&input);
        let mut trace = build_test_trace::<BabyBear>(&w);
        let bit_off = col::HIGH_20_BITS_BASE + 4 * HIGH_20_BITS + 11;
        trace.values[bit_off] = BabyBear::from_u64(3);
        check_constraints(&FirstFoldTestAir, &trace, &[]);
    }
}
