//! `field25519::second_fold` — single-pass second-fold AIR for mod-p reduction.
//!
//! Pre-condition input: 10 30-bit-loose limbs from `first_fold` output
//! (acc[9] ≤ 2²¹ assuming caller provided FirstFold's canonicalized
//! output; acc[8] possibly with high bits ≥ 2¹⁵).
//!
//! Computes one pass of:
//!
//! ```text
//! limb_9 = acc_in[9]
//! high_8 = acc_in[8] >> 15
//! acc_in[8] := acc_in[8] & 0x7FFF        (low 15 bits stay in limb 8)
//! prod_9 = limb_9 · M     (M = 19 · 2¹⁵ = 622592)
//! prod_8 = high_8 · 19    (limb 8 high bits have weight 2²⁵⁵ ≡ 19 mod p)
//! acc_out[0] += (prod_9 + prod_8) low 30 bits
//! acc_out[1] += (prod_9 + prod_8) high bits
//! carry-propagate limbs 0..9
//! ```
//!
//! Output: 10 30-bit limbs. For canonical mul inputs, after composing two
//! `SecondFoldOnePassChip` instances, the result has limb 9 = 0 and is
//! ready for `cond_p_sub`.
//!
//! ## Strategy
//!
//! BabyBear ~2³¹ vs witness values:
//!   - `limb_9 ≤ 2²¹`, `M ≈ 2¹⁹·⁵` → `limb_9 · M ≤ 2⁴¹`. Direct mul
//!     overflows BabyBear, so `limb_9` is decomposed into 3 pieces of
//!     7 bits each. Partial products `pi · M < 2²⁷` fit comfortably.
//!   - `high_8 ≤ 2¹⁵`, `19 < 2⁵` → `high_8 · 19 < 2²⁰` (no decomposition).
//!
//! ## Layout (one operation per row, allocated at `start_col`)
//!
//! | Range   | Width | Contents                               |
//! |---------|-------|----------------------------------------|
//! | 0..10   | 10    | `acc_in[0..10]`                        |
//! | 10..20  | 10    | `acc_out[0..10]`                       |
//! | 20..23  | 3     | limb_9 pieces (a_lo, a_mid, a_hi each 7 bits) |
//! | 23..26  | 3     | partial products (q_lo, q_mid, q_hi)   |
//! | 26..28  | 2     | prod_9 split (low_30, high)            |
//! | 28..30  | 2     | limb_8 decomp (high_8 ≤ 2¹⁵, low_15)   |
//! | 30..32  | 2     | prod_8 split (low_30, high)            |
//! | 32..41  | 9     | carry[1..10] (carry[0] implicit = 0)   |
//!
//! Total: **41 columns**, **27 constraints** (degree 2).
//!
//! ## Soundness gap (closes in Etapa 3 lookup args)
//!
//! Range checks on pieces (< 2⁷), high_8 (< 2¹⁵), low_15 (< 2¹⁵), prod_*
//! components, and carries are deferred. Witness function is correct;
//! adversarial wrap-around exploitable until lookup args land. Same gap
//! pattern as `first_fold`.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::mod_p::FOLD_M;
use crate::chips::lookup::range_n::RangeNChip;

const NUM_LIMBS_OUT: usize = 10;
const NUM_LIMBS_IN: usize = 10;
const PIECE_BITS_9: usize = 7;
const PIECE_MOD_9: u64 = 1 << PIECE_BITS_9; // 128

/// Range-check widths (Etapa 3.9). Bounds derived from the per-witness analysis
/// at the top of the file. Q_PIECES are NOT range-checked because they are
/// fully constrained by `q_x = piece_x · M` and `piece_x` is range-checked here.
/// PROD_8_HIGH is NOT range-checked because it is asserted == 0.
pub const LIMB9_BITS: usize = 7;
pub const PROD_9_LOW_BITS: usize = 30;
pub const PROD_9_HIGH_BITS: usize = 12;
pub const HIGH_8_BITS: usize = 15;
pub const LOW_15_BITS: usize = 15;
pub const PROD_8_LOW_BITS: usize = 20;
pub const CARRY_BITS: usize = 10;
pub const NUM_CARRY: usize = 9;
pub const NUM_LIMB9_PIECES: usize = 3;

pub mod col {
    use super::*;
    pub const ACC_IN: usize = 0;
    pub const ACC_OUT: usize = ACC_IN + 10;            // 10
    pub const LIMB_9_PIECES: usize = ACC_OUT + 10;     // 20
    pub const Q_PIECES: usize = LIMB_9_PIECES + 3;     // 23
    pub const PROD_9_LOW: usize = Q_PIECES + 3;        // 26
    pub const PROD_9_HIGH: usize = PROD_9_LOW + 1;     // 27
    pub const HIGH_8: usize = PROD_9_HIGH + 1;         // 28
    pub const LOW_15: usize = HIGH_8 + 1;              // 29
    pub const PROD_8_LOW: usize = LOW_15 + 1;          // 30
    pub const PROD_8_HIGH: usize = PROD_8_LOW + 1;     // 31
    pub const CARRY: usize = PROD_8_HIGH + 1;          // 32 (carry[1..10])

    // Etapa 3.9 — range bit regions appended after CARRY.
    pub const LIMB9_BITS_BASE: usize = CARRY + NUM_CARRY;                            // 41
    pub const PROD_9_LOW_BITS_BASE: usize = LIMB9_BITS_BASE + NUM_LIMB9_PIECES * LIMB9_BITS; // 62
    pub const PROD_9_HIGH_BITS_BASE: usize = PROD_9_LOW_BITS_BASE + PROD_9_LOW_BITS; // 92
    pub const HIGH_8_BITS_BASE: usize = PROD_9_HIGH_BITS_BASE + PROD_9_HIGH_BITS;    // 104
    pub const LOW_15_BITS_BASE: usize = HIGH_8_BITS_BASE + HIGH_8_BITS;              // 119
    pub const PROD_8_LOW_BITS_BASE: usize = LOW_15_BITS_BASE + LOW_15_BITS;          // 134
    pub const CARRY_BITS_BASE: usize = PROD_8_LOW_BITS_BASE + PROD_8_LOW_BITS;       // 154

    pub const TOTAL: usize = CARRY_BITS_BASE + NUM_CARRY * CARRY_BITS;               // 244
}

pub const NUM_COLS: usize = col::TOTAL;

#[derive(Debug, Clone, Copy)]
pub struct SecondFoldOnePassChip {
    pub start_col: usize,
}

impl SecondFoldOnePassChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();

        let s = self.start_col;
        let m_field = AB::Expr::from_u64(FOLD_M);
        let two_to_7 = AB::Expr::from_u64(1 << 7);
        let two_to_14 = AB::Expr::from_u64(1 << 14);
        let two_to_15 = AB::Expr::from_u64(1 << 15);
        let two_to_30 = AB::Expr::from_u64(1u64 << 30);
        let nineteen = AB::Expr::from_u64(19);

        // 1. limb_9 piece reassembly: a_lo + 128·a_mid + 16384·a_hi = acc_in[9]
        let a_lo = row[s + col::LIMB_9_PIECES + 0].clone();
        let a_mid = row[s + col::LIMB_9_PIECES + 1].clone();
        let a_hi = row[s + col::LIMB_9_PIECES + 2].clone();
        builder.assert_eq(
            a_lo.clone() + two_to_7.clone() * a_mid.clone() + two_to_14.clone() * a_hi.clone(),
            row[s + col::ACC_IN + 9].clone(),
        );

        // 2. q_lo = a_lo · M, q_mid = a_mid · M, q_hi = a_hi · M
        let q_lo = row[s + col::Q_PIECES + 0].clone();
        let q_mid = row[s + col::Q_PIECES + 1].clone();
        let q_hi = row[s + col::Q_PIECES + 2].clone();
        builder.assert_eq(q_lo.clone(), a_lo * m_field.clone());
        builder.assert_eq(q_mid.clone(), a_mid * m_field.clone());
        builder.assert_eq(q_hi.clone(), a_hi * m_field.clone());

        // 3. prod_9 split: prod_9_low + 2³⁰ · prod_9_high
        //               = q_lo + 2⁷ · q_mid + 2¹⁴ · q_hi
        let prod_9_low = row[s + col::PROD_9_LOW].clone();
        let prod_9_high = row[s + col::PROD_9_HIGH].clone();
        builder.assert_eq(
            prod_9_low.clone() + two_to_30.clone() * prod_9_high.clone(),
            q_lo + two_to_7 * q_mid + two_to_14 * q_hi,
        );

        // 4. limb_8 decomp: high_8 · 2¹⁵ + low_15 = acc_in[8]
        let high_8 = row[s + col::HIGH_8].clone();
        let low_15 = row[s + col::LOW_15].clone();
        builder.assert_eq(
            high_8.clone() * two_to_15.clone() + low_15.clone(),
            row[s + col::ACC_IN + 8].clone(),
        );

        // 5. prod_8 split: prod_8_low + 2³⁰ · prod_8_high = high_8 · 19
        let prod_8_low = row[s + col::PROD_8_LOW].clone();
        let prod_8_high = row[s + col::PROD_8_HIGH].clone();
        builder.assert_eq(
            prod_8_low.clone() + two_to_30.clone() * prod_8_high.clone(),
            high_8 * nineteen,
        );

        // 6. Carry chain limbs 0..9.
        // carry[0] = 0 (implicit), carry[1..10] live in CARRY..CARRY+9.
        for i in 0..NUM_LIMBS_OUT {
            let acc_out_i = row[s + col::ACC_OUT + i].clone();
            let carry_in: AB::Expr = if i == 0 {
                AB::Expr::from_u64(0)
            } else {
                row[s + col::CARRY + (i - 1)].clone().into()
            };
            let carry_out: AB::Expr = if i < NUM_LIMBS_OUT - 1 {
                row[s + col::CARRY + i].clone().into()
            } else {
                // No carry beyond limb 9; chip caller must guarantee acc_out[9] is final.
                AB::Expr::from_u64(0)
            };
            // RHS additions per limb position.
            let rhs = match i {
                0 => row[s + col::ACC_IN + 0].clone().into() + prod_9_low.clone() + prod_8_low.clone() + carry_in,
                1 => row[s + col::ACC_IN + 1].clone().into() + prod_9_high.clone() + prod_8_high.clone() + carry_in,
                8 => low_15.clone().into() + carry_in, // limb 8 replaced by low_15
                9 => carry_in.clone(), // limb 9 cleared, only carry-in remains
                _ => row[s + col::ACC_IN + i].clone().into() + carry_in,
            };
            builder.assert_eq(acc_out_i + two_to_30.clone() * carry_out, rhs);
        }

        // ── Etapa 3.9: range checks on every witness column ────────────
        // PROD_8_HIGH = 0 always (since high_8 ≤ 2^15 and 19 < 2^5,
        // prod_8 < 2^20 < 2^30 → high half is 0).
        builder.assert_zero(row[s + col::PROD_8_HIGH].clone());

        // 3 limb_9 pieces × 7 bits.
        for i in 0..NUM_LIMB9_PIECES {
            RangeNChip::<LIMB9_BITS>::split(
                s + col::LIMB_9_PIECES + i,
                s + col::LIMB9_BITS_BASE + i * LIMB9_BITS,
            )
            .emit(builder);
        }
        // PROD_9_LOW: 30 bits.
        RangeNChip::<PROD_9_LOW_BITS>::split(s + col::PROD_9_LOW, s + col::PROD_9_LOW_BITS_BASE).emit(builder);
        // PROD_9_HIGH: 12 bits.
        RangeNChip::<PROD_9_HIGH_BITS>::split(s + col::PROD_9_HIGH, s + col::PROD_9_HIGH_BITS_BASE).emit(builder);
        // HIGH_8: 15 bits.
        RangeNChip::<HIGH_8_BITS>::split(s + col::HIGH_8, s + col::HIGH_8_BITS_BASE).emit(builder);
        // LOW_15: 15 bits.
        RangeNChip::<LOW_15_BITS>::split(s + col::LOW_15, s + col::LOW_15_BITS_BASE).emit(builder);
        // PROD_8_LOW: 20 bits.
        RangeNChip::<PROD_8_LOW_BITS>::split(s + col::PROD_8_LOW, s + col::PROD_8_LOW_BITS_BASE).emit(builder);
        // 9 carries × 10 bits.
        for i in 0..NUM_CARRY {
            RangeNChip::<CARRY_BITS>::split(
                s + col::CARRY + i,
                s + col::CARRY_BITS_BASE + i * CARRY_BITS,
            )
            .emit(builder);
        }
    }
}

impl<F: Field> BaseAir<F> for SecondFoldOnePassChip {
    fn width(&self) -> usize { NUM_COLS }
    fn main_next_row_columns(&self) -> Vec<usize> { Vec::new() }
    fn max_constraint_degree(&self) -> Option<usize> { Some(2) }
}

impl<AB: AirBuilder> Air<AB> for SecondFoldOnePassChip
where AB::F: Field,
{
    fn eval(&self, builder: &mut AB) { self.emit(builder); }
}

/// Witness for one second-fold pass.
#[derive(Debug, Clone)]
pub struct SecondFoldWitness {
    pub acc_in: [u128; 10],
    pub acc_out: [u64; 10],
    pub limb_9_pieces: [u64; 3],
    pub q_pieces: [u64; 3],
    pub prod_9_low: u64,
    pub prod_9_high: u64,
    pub high_8: u64,
    pub low_15: u64,
    pub prod_8_low: u64,
    pub prod_8_high: u64,
    pub carry: [u64; 9], // carry[1..10]
}

/// Compute one pass of second-fold canonicalization.
pub fn compute_second_fold_one_pass(acc_in: &[u128; 10]) -> SecondFoldWitness {
    let limb_9 = acc_in[9] as u64;
    let high_8 = (acc_in[8] >> 15) as u64;
    let low_15 = (acc_in[8] & ((1u128 << 15) - 1)) as u64;

    // Decompose limb_9 into 3 pieces of 7 bits.
    let a_lo = limb_9 & (PIECE_MOD_9 - 1);
    let a_mid = (limb_9 >> 7) & (PIECE_MOD_9 - 1);
    let a_hi = (limb_9 >> 14) & (PIECE_MOD_9 - 1);
    debug_assert_eq!(a_lo + (a_mid << 7) + (a_hi << 14), limb_9, "limb_9 piece decomposition");

    let q_lo = a_lo * FOLD_M;
    let q_mid = a_mid * FOLD_M;
    let q_hi = a_hi * FOLD_M;

    // prod_9 = q_lo + 2⁷·q_mid + 2¹⁴·q_hi  (compute via u128 to avoid overflow)
    let prod_9 = (q_lo as u128) + ((q_mid as u128) << 7) + ((q_hi as u128) << 14);
    let prod_9_low = (prod_9 & ((1u128 << 30) - 1)) as u64;
    let prod_9_high = (prod_9 >> 30) as u64;

    let prod_8 = high_8 * 19;
    let prod_8_low = prod_8 & ((1u64 << 30) - 1);
    let prod_8_high = prod_8 >> 30;

    // Carry chain for limbs 0..9.
    let mut acc = [0u128; 10];
    for i in 0..10 {
        acc[i] = acc_in[i];
    }
    acc[8] = low_15 as u128;
    acc[9] = 0;
    acc[0] += prod_9_low as u128 + prod_8_low as u128;
    acc[1] += prod_9_high as u128 + prod_8_high as u128;

    let mut carry = [0u64; 9];
    let mut acc_out = [0u64; 10];
    let mut c: u128 = 0;
    for i in 0..10 {
        let total = acc[i] + c;
        acc_out[i] = (total & ((1u128 << 30) - 1)) as u64;
        c = total >> 30;
        if i < 9 {
            carry[i] = c as u64;
        }
    }
    debug_assert_eq!(c, 0, "second_fold one pass: carry past limb 9 must be 0; input acc[9]={}", limb_9);

    SecondFoldWitness {
        acc_in: *acc_in,
        acc_out,
        limb_9_pieces: [a_lo, a_mid, a_hi],
        q_pieces: [q_lo, q_mid, q_hi],
        prod_9_low,
        prod_9_high,
        high_8,
        low_15,
        prod_8_low,
        prod_8_high,
        carry,
    }
}

/// Populate one row of trace at `(row_off, start_col)`.
pub fn populate_row<F: Field + PrimeCharacteristicRing>(
    values: &mut [F],
    row_off: usize,
    start_col: usize,
    acc_in: &[u128; 10],
) -> SecondFoldWitness {
    let w = compute_second_fold_one_pass(acc_in);
    let base = row_off + start_col;

    for i in 0..NUM_LIMBS_IN {
        values[base + col::ACC_IN + i] = F::from_u64(acc_in[i] as u64);
    }
    for i in 0..NUM_LIMBS_OUT {
        values[base + col::ACC_OUT + i] = F::from_u64(w.acc_out[i]);
    }
    for i in 0..3 {
        values[base + col::LIMB_9_PIECES + i] = F::from_u64(w.limb_9_pieces[i]);
        values[base + col::Q_PIECES + i] = F::from_u64(w.q_pieces[i]);
    }
    values[base + col::PROD_9_LOW] = F::from_u64(w.prod_9_low);
    values[base + col::PROD_9_HIGH] = F::from_u64(w.prod_9_high);
    values[base + col::HIGH_8] = F::from_u64(w.high_8);
    values[base + col::LOW_15] = F::from_u64(w.low_15);
    values[base + col::PROD_8_LOW] = F::from_u64(w.prod_8_low);
    values[base + col::PROD_8_HIGH] = F::from_u64(w.prod_8_high);
    for i in 0..9 {
        values[base + col::CARRY + i] = F::from_u64(w.carry[i]);
    }

    // Etapa 3.9: range bits.
    for i in 0..NUM_LIMB9_PIECES {
        RangeNChip::<LIMB9_BITS>::populate_bits::<F>(values, base + col::LIMB9_BITS_BASE + i * LIMB9_BITS, w.limb_9_pieces[i]);
    }
    RangeNChip::<PROD_9_LOW_BITS>::populate_bits::<F>(values, base + col::PROD_9_LOW_BITS_BASE, w.prod_9_low);
    RangeNChip::<PROD_9_HIGH_BITS>::populate_bits::<F>(values, base + col::PROD_9_HIGH_BITS_BASE, w.prod_9_high);
    RangeNChip::<HIGH_8_BITS>::populate_bits::<F>(values, base + col::HIGH_8_BITS_BASE, w.high_8);
    RangeNChip::<LOW_15_BITS>::populate_bits::<F>(values, base + col::LOW_15_BITS_BASE, w.low_15);
    RangeNChip::<PROD_8_LOW_BITS>::populate_bits::<F>(values, base + col::PROD_8_LOW_BITS_BASE, w.prod_8_low);
    for i in 0..NUM_CARRY {
        RangeNChip::<CARRY_BITS>::populate_bits::<F>(values, base + col::CARRY_BITS_BASE + i * CARRY_BITS, w.carry[i]);
    }

    w
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(
    acc_in: &[u128; 10],
) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    let zero = [0u128; 10];
    for row in 0..HEIGHT {
        populate_row::<F>(&mut values, row * NUM_COLS, 0, &zero);
    }
    populate_row::<F>(&mut values, 0, 0, acc_in);

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeField32;

    fn read_acc_out(values: &[BabyBear]) -> [u64; 10] {
        let mut out = [0u64; 10];
        for i in 0..10 {
            out[i] = values[col::ACC_OUT + i].as_canonical_u32() as u64;
        }
        out
    }

    #[test]
    fn second_fold_zero_input() {
        let acc_in = [0u128; 10];
        let trace = build_test_trace::<BabyBear>(&acc_in);
        check_constraints(&SecondFoldOnePassChip::new(), &trace, &[]);
        assert_eq!(read_acc_out(&trace.values), [0u64; 10]);
    }

    #[test]
    fn second_fold_only_limb_9_set() {
        // acc_in[9] = 1 → fold contributes M = 622592 to limb 0.
        let mut acc_in = [0u128; 10];
        acc_in[9] = 1;
        let trace = build_test_trace::<BabyBear>(&acc_in);
        check_constraints(&SecondFoldOnePassChip::new(), &trace, &[]);
        let out = read_acc_out(&trace.values);
        assert_eq!(out[0], FOLD_M);
        for i in 1..10 {
            assert_eq!(out[i], 0, "limb {i} should be zero");
        }
    }

    #[test]
    fn second_fold_only_limb_8_high_bits() {
        // acc_in[8] = 2¹⁵ (one bit above 15-bit canonical limit) →
        // high_8 = 1, fold contributes 19 to limb 0; low_15 = 0.
        let mut acc_in = [0u128; 10];
        acc_in[8] = 1u128 << 15;
        let trace = build_test_trace::<BabyBear>(&acc_in);
        check_constraints(&SecondFoldOnePassChip::new(), &trace, &[]);
        let out = read_acc_out(&trace.values);
        assert_eq!(out[0], 19);
        for i in 1..10 {
            assert_eq!(out[i], 0, "limb {i} should be zero");
        }
    }

    #[test]
    fn second_fold_max_limb_9_within_bound() {
        // Worst-case limb_9 = 2²¹ - 1 (the documented bound).
        let mut acc_in = [0u128; 10];
        acc_in[9] = (1u128 << 21) - 1;
        let trace = build_test_trace::<BabyBear>(&acc_in);
        check_constraints(&SecondFoldOnePassChip::new(), &trace, &[]);
        // Sanity: acc_out[9] must be 0 (fully cleared).
        let out = read_acc_out(&trace.values);
        assert_eq!(out[9], 0);
    }

    #[test]
    fn second_fold_combined_limb_8_and_9_overflow() {
        // Both overflows present.
        let mut acc_in = [0u128; 10];
        acc_in[0] = 12345;
        acc_in[8] = (1u128 << 15) + 7; // high_8 = 1, low_15 = 7
        acc_in[9] = 100;
        let trace = build_test_trace::<BabyBear>(&acc_in);
        check_constraints(&SecondFoldOnePassChip::new(), &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn second_fold_rejects_tampered_output() {
        let mut acc_in = [0u128; 10];
        acc_in[9] = 5;
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        trace.values[col::ACC_OUT] = trace.values[col::ACC_OUT] + BabyBear::from_u64(1);
        check_constraints(&SecondFoldOnePassChip::new(), &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        // Etapa 3.9: 41 base + 21 (3×7 limb9) + 30 + 12 + 15 + 15 + 20 + 90 (9×10 carry) = 244.
        assert_eq!(NUM_COLS, 244);
    }

    // ===== Etapa 3.9 — adversarial range-check rejection =====

    /// Tampering a limb_9 piece above 2^7 must be rejected.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_limb9_piece_above_2_to_7() {
        let acc_in = [0u128; 10];
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        trace.values[col::LIMB_9_PIECES] = BabyBear::from_u64(128);
        check_constraints(&SecondFoldOnePassChip::new(), &trace, &[]);
    }

    /// Tampering high_8 above 2^15 must be rejected.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_high_8_above_2_to_15() {
        let acc_in = [0u128; 10];
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        trace.values[col::HIGH_8] = BabyBear::from_u64(1u64 << 15);
        check_constraints(&SecondFoldOnePassChip::new(), &trace, &[]);
    }

    /// Tampering PROD_8_HIGH to non-zero must be rejected (assert_zero).
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_nonzero_prod_8_high() {
        let acc_in = [0u128; 10];
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        trace.values[col::PROD_8_HIGH] = BabyBear::from_u64(1);
        check_constraints(&SecondFoldOnePassChip::new(), &trace, &[]);
    }
}
