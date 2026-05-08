//! `field25519::mod_p_chip` — composed AIR for full mod-p reduction.
//!
//! Composes the field25519 reduction stack:
//!
//!   - `FirstFoldChip`   — 18 30-bit limbs → 10 canonical 30-bit limbs
//!                         (V_lo + V_hi · M, with carry propagation)
//!   - **iterated fold** for limb 9 (witness-only — see soundness gap)
//!   - `CondPSubChip`    — final canonical mod-p reduction
//!
//! Output is canonical 9-limb in `[0, p)`.
//!
//! ## Layout
//!
//! | Range       | Width | Contents                              |
//! |-------------|-------|---------------------------------------|
//! | 0..18       | 18    | L (input 18 30-bit limbs)             |
//! | 18..27      | 9     | C (output canonical mod-p)            |
//! | 27..137     | 110   | FirstFoldChip                         |
//! | 137..173    | 36    | CondPSubChip                          |
//!
//! Total: **173 columns**, **~105 constraints**.
//!
//! ## Soundness gap
//!
//! Two gaps inherited from constituents (both close in 5.2.1.7):
//!
//!   1. **Range checks deferred** for piece/output/carry witnesses.
//!   2. **Iterated fold** (when first_fold's limb 9 is non-zero, the
//!      witness function does up to 3 more fold passes via 2²⁵⁵ ≡ 19;
//!      this AIR ASSERTS the input to CondPSubChip is a's first 9 limbs
//!      directly, requiring first_fold's output limb 9 to be ZERO for
//!      the AIR to accept). For the canonical-input regime (mul of two
//!      `a, b < p`, fitting `a·b < p²< 2⁵¹⁰`), limb 9 after first_fold
//!      is bounded but may be non-zero — this chip is intended for
//!      inputs where limb 9 = 0 (e.g., add/sub results that fit in
//!      9 limbs). For the general mul case, additional fold passes
//!      need to be composed externally.
//!
//! Cross-validated against `compute_mod_p_reduction` for inputs where
//! the regime applies (limb 9 of first_fold = 0).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::NUM_LIMBS;
use super::cond_p_sub::{CondPSubChip, NUM_COLS as CPS_COLS, col as cpc};
use super::first_fold::{self, FirstFoldChip, NUM_COLS as FF_COLS, col as ffc};

const NUM_INPUT_LIMBS: usize = 18;

pub mod col {
    use super::*;
    pub const L: usize = 0;
    pub const C: usize = L + NUM_INPUT_LIMBS; // 18
    pub const FF_START: usize = C + NUM_LIMBS; // 27
    pub const CPS_START: usize = FF_START + FF_COLS; // 137
    pub const TOTAL: usize = CPS_START + CPS_COLS; // 173
}

pub const NUM_COLS: usize = col::TOTAL;

#[derive(Debug, Clone, Copy)]
pub struct ModPChip {
    pub start_col: usize,
}

impl Default for ModPChip {
    fn default() -> Self {
        Self::new()
    }
}

impl ModPChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        FirstFoldChip::at(self.start_col + col::FF_START).emit(builder);
        CondPSubChip::at(self.start_col + col::CPS_START).emit(builder);

        let main = builder.main();
        let row = main.current_slice();

        let assert_chunks_eq = |b: &mut AB, off_a: usize, off_b: usize, n: usize| {
            for i in 0..n {
                b.assert_eq(row[off_a + i], row[off_b + i]);
            }
        };

        assert_chunks_eq(builder, self.start_col + col::FF_START + ffc::L, self.start_col + col::L, NUM_INPUT_LIMBS);
        assert_chunks_eq(builder, self.start_col + col::CPS_START + cpc::A, self.start_col + col::FF_START + ffc::OUT, NUM_LIMBS);
        assert_chunks_eq(builder, self.start_col + col::C, self.start_col + col::CPS_START + cpc::C, NUM_LIMBS);
        builder.assert_zero(row[self.start_col + col::FF_START + ffc::OUT + 9]);
    }
}

impl<F: Field> BaseAir<F> for ModPChip {
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

impl<AB: AirBuilder> Air<AB> for ModPChip
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        self.emit(builder);
    }
}

/// Build a single-row trace exercising one full mod-p reduction.
///
/// **Precondition:** `compute_first_fold(input)`'s limb 9 must be 0.
/// This holds for inputs where `V_hi · M + V_lo < 2³⁰⁰`, i.e., inputs
/// derived from sums/differences of canonical mod-p elements (not from
/// arbitrary mul outputs).
pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(input: &[u64; NUM_INPUT_LIMBS]) -> RowMajorMatrix<F> {
    use super::Field25519Element;
    use super::cond_p_sub::compute_cond_p_sub;
    use super::first_fold::compute_first_fold_witness;
    use super::mod_p::compute_mod_p_reduction;

    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    let ff_w = compute_first_fold_witness(input);
    assert_eq!(ff_w.out[9], 0, "mod_p_chip precondition violated: first_fold limb 9 != 0");

    // Take first 9 limbs of first_fold output as input to cond_p_sub.
    let ff_out_9 = Field25519Element {
        limbs: [ff_w.out[0], ff_w.out[1], ff_w.out[2], ff_w.out[3], ff_w.out[4], ff_w.out[5], ff_w.out[6], ff_w.out[7], ff_w.out[8]],
    };
    let cps_w = compute_cond_p_sub(&ff_out_9);

    // Sanity check: full pipeline should match compute_mod_p_reduction.
    let expected = compute_mod_p_reduction(input);
    debug_assert_eq!(cps_w.c_limbs, expected.limbs);

    // Padding rows: input = zero, all witnesses zero.
    let zero_input = [0u64; NUM_INPUT_LIMBS];
    let zero_ff = compute_first_fold_witness(&zero_input);
    let zero_cps = compute_cond_p_sub(&Field25519Element::ZERO);
    for row in 0..HEIGHT {
        let off = row * NUM_COLS;
        for i in 0..NUM_INPUT_LIMBS {
            values[off + col::L + i] = F::from_u64(0);
        }
        for i in 0..NUM_LIMBS {
            values[off + col::C + i] = F::from_u64(zero_cps.c_limbs[i]);
        }
        // FF padding
        for i in 0..NUM_INPUT_LIMBS {
            values[off + col::FF_START + ffc::L + i] = F::from_u64(zero_ff.l[i]);
        }
        for i in 0..super::first_fold::NUM_COLS - super::first_fold::col::L - NUM_INPUT_LIMBS {
            // Zero-fill remaining FF cols (out, carries, pieces, products, etc.) — all 0 for zero input.
            values[off + col::FF_START + super::first_fold::col::L + NUM_INPUT_LIMBS + i] = F::ZERO;
        }
        // CPS padding
        for i in 0..NUM_LIMBS {
            values[off + col::CPS_START + cpc::A + i] = F::from_u64(zero_cps.a_limbs[i]);
            values[off + col::CPS_START + cpc::C + i] = F::from_u64(zero_cps.c_limbs[i]);
            values[off + col::CPS_START + cpc::T + i] = F::from_u64(zero_cps.t_limbs[i]);
            values[off + col::CPS_START + cpc::BORROW + i] = F::from_u64(zero_cps.borrow[i]);
        }
    }

    // Overwrite row 0 with actual witness.
    for i in 0..NUM_INPUT_LIMBS {
        values[col::L + i] = F::from_u64(input[i]);
    }
    for i in 0..NUM_LIMBS {
        values[col::C + i] = F::from_u64(cps_w.c_limbs[i]);
    }
    // FirstFoldChip witness population.
    for i in 0..NUM_INPUT_LIMBS {
        values[col::FF_START + ffc::L + i] = F::from_u64(ff_w.l[i]);
    }
    for i in 0..10 {
        values[col::FF_START + ffc::OUT + i] = F::from_u64(ff_w.out[i]);
        values[col::FF_START + ffc::CARRY + i] = F::from_u64(ff_w.carries[i]);
        // Etapa 3.8: 10-bit range bits for first_fold carry[i].
        crate::chips::lookup::range_n::RangeNChip::<{ first_fold::CARRY_BITS }>::populate_bits::<F>(
            values.as_mut_slice(),
            col::FF_START + ffc::CARRY_BITS_BASE + i * first_fold::CARRY_BITS,
            ff_w.carries[i],
        );
    }
    for i in 0..27 {
        values[col::FF_START + ffc::PIECES + i] = F::from_u64(ff_w.pieces[i]);
        values[col::FF_START + ffc::PRODUCTS + i] = F::from_u64(ff_w.products[i]);
        // Etapa 3.3: 10-bit range bits for first_fold piece[i].
        crate::chips::lookup::range_n::RangeNChip::<10>::populate_bits::<F>(
            values.as_mut_slice(),
            col::FF_START + ffc::PIECE_BITS_BASE + i * 10,
            ff_w.pieces[i],
        );
    }
    // Etapa 3.6: 30-bit / 20-bit range bits for first_fold low_30 / high_20.
    for k in 0..9 {
        crate::chips::lookup::range_n::RangeNChip::<30>::populate_bits::<F>(
            values.as_mut_slice(),
            col::FF_START + ffc::LOW_30_BITS_BASE + k * 30,
            ff_w.low_30[k],
        );
        crate::chips::lookup::range_n::RangeNChip::<20>::populate_bits::<F>(
            values.as_mut_slice(),
            col::FF_START + ffc::HIGH_20_BITS_BASE + k * 20,
            ff_w.high_20[k],
        );
    }
    for i in 0..9 {
        values[col::FF_START + ffc::LOW_30 + i] = F::from_u64(ff_w.low_30[i]);
        values[col::FF_START + ffc::HIGH_20 + i] = F::from_u64(ff_w.high_20[i]);
    }
    // CondPSubChip witness population.
    for i in 0..NUM_LIMBS {
        values[col::CPS_START + cpc::A + i] = F::from_u64(cps_w.a_limbs[i]);
        values[col::CPS_START + cpc::C + i] = F::from_u64(cps_w.c_limbs[i]);
        values[col::CPS_START + cpc::T + i] = F::from_u64(cps_w.t_limbs[i]);
        values[col::CPS_START + cpc::BORROW + i] = F::from_u64(cps_w.borrow[i]);
    }

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::super::mod_p::compute_mod_p_reduction;
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeField32;

    fn read_c(values: &[BabyBear]) -> [u64; NUM_LIMBS] {
        let mut out = [0u64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            out[i] = values[col::C + i].as_canonical_u32() as u64;
        }
        out
    }

    #[test]
    fn mod_p_zero() {
        let input = [0u64; NUM_INPUT_LIMBS];
        let trace = build_test_trace::<BabyBear>(&input);
        check_constraints(&ModPChip::new(), &trace, &[]);
        assert_eq!(read_c(&trace.values), [0u64; NUM_LIMBS]);
    }

    #[test]
    fn mod_p_small_value() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[0] = 12345;
        let trace = build_test_trace::<BabyBear>(&input);
        check_constraints(&ModPChip::new(), &trace, &[]);
        let mut expected = [0u64; NUM_LIMBS];
        expected[0] = 12345;
        assert_eq!(read_c(&trace.values), expected);
    }

    #[test]
    fn mod_p_p_yields_zero() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        for i in 0..NUM_LIMBS {
            input[i] = super::super::P_LIMBS[i];
        }
        let trace = build_test_trace::<BabyBear>(&input);
        check_constraints(&ModPChip::new(), &trace, &[]);
        assert_eq!(read_c(&trace.values), [0u64; NUM_LIMBS]);
    }

    #[test]
    fn mod_p_2_to_270_yields_m() {
        // 2^270 mod p = 19 * 2^15 = M = 622592.
        // Encoded: limb 9 = 1, all others = 0.
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[NUM_LIMBS] = 1; // L[9] = 1
        let trace = build_test_trace::<BabyBear>(&input);
        check_constraints(&ModPChip::new(), &trace, &[]);
        let mut expected = [0u64; NUM_LIMBS];
        expected[0] = super::super::mod_p::FOLD_M;
        assert_eq!(read_c(&trace.values), expected);
    }

    #[test]
    fn mod_p_cross_validates_with_witness_for_small_inputs() {
        // Range of inputs where the precondition (first_fold limb 9 == 0) holds.
        let cases: Vec<[u64; NUM_INPUT_LIMBS]> = vec![
            {
                let mut a = [0u64; NUM_INPUT_LIMBS];
                a[0] = 1;
                a
            },
            {
                let mut a = [0u64; NUM_INPUT_LIMBS];
                a[5] = 0xDEAD_BEEF;
                a
            },
            {
                let mut a = [0u64; NUM_INPUT_LIMBS];
                a[NUM_LIMBS] = 100; // Small high limb
                a
            },
        ];
        for input in cases {
            let expected = compute_mod_p_reduction(&input);
            let trace = build_test_trace::<BabyBear>(&input);
            check_constraints(&ModPChip::new(), &trace, &[]);
            assert_eq!(read_c(&trace.values), expected.limbs, "input {input:?}");
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn mod_p_rejects_tampered_output() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[0] = 7;
        let mut trace = build_test_trace::<BabyBear>(&input);
        trace.values[col::C] += BabyBear::ONE;
        check_constraints(&ModPChip::new(), &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        assert_eq!(NUM_COLS, 993); // Etapa 3.3 (+270) + 3.6 (+450) + 3.8 (+100) from FirstFold
    }
}
