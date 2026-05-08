//! `field25519::mod_p_chip_full` — full mod-p reduction AIR.
//!
//! Accepts arbitrary 18-limb inputs (e.g., direct mul outputs `< 2⁵¹⁰`)
//! and produces a canonical 9-limb output `< p`. Composes:
//!
//!   - `FirstFoldChip`         — 18 30-bit → 10 loose 30-bit
//!   - `SecondFoldOnePassChip` — pass 1 (clears typical limb-9 overflow)
//!   - `SecondFoldOnePassChip` — pass 2 (paranoid: handles edge cases
//!                               where pass 1 leaves limb 9 != 0)
//!   - `CondPSubChip`          — pass 1 (subtract p if needed)
//!   - `CondPSubChip`          — pass 2 (paranoid: handles `a >= 2p`)
//!
//! After two SecondFold passes, limb 9 is enforced to 0 (assert). After
//! two CondPSub passes, the result is canonical `< p`.
//!
//! Replaces `mod_p_chip` for callers that need full mul-output handling
//! (`mul_canonical`, `pow_air`, ed25519 chips). The lighter `mod_p_chip`
//! is kept for callers that already guarantee first_fold limb 9 = 0
//! (add/sub-derived chains).
//!
//! ## Layout
//!
//! | Range           | Width | Contents                              |
//! |-----------------|-------|---------------------------------------|
//! | 0..18           | 18    | L (input 18 30-bit limbs)             |
//! | 18..27          | 9     | C (output canonical mod-p)            |
//! | 27..137         | 110   | FirstFoldChip                         |
//! | 137..178        | 41    | SecondFoldOnePassChip[1]              |
//! | 178..219        | 41    | SecondFoldOnePassChip[2]              |
//! | 219..255        | 36    | CondPSubChip[1]                       |
//! | 255..291        | 36    | CondPSubChip[2]                       |
//!
//! Total: **291 columns**, **~205 constraints**.
//!
//! ## Soundness
//!
//! Inherits gaps from constituents (range checks deferred to Etapa 3
//! lookup args). The compositional asserts (limb 9 == 0 after pass 2,
//! cond_p_sub chained) are sound provided the constituent witness
//! functions are honest.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::NUM_LIMBS;
use super::cond_p_sub::{CondPSubChip, NUM_COLS as CPS_COLS, col as cpc};
use super::first_fold::{FirstFoldChip, NUM_COLS as FF_COLS, col as ffc};
use super::second_fold::{NUM_COLS as SF_COLS, SecondFoldOnePassChip, col as sfc};

const NUM_INPUT_LIMBS: usize = 18;

pub mod col {
    use super::*;
    pub const L: usize = 0;
    pub const C: usize = L + NUM_INPUT_LIMBS; // 18
    pub const FF_START: usize = C + NUM_LIMBS; // 27
    pub const SF1_START: usize = FF_START + FF_COLS; // 137
    pub const SF2_START: usize = SF1_START + SF_COLS; // 178
    pub const CPS1_START: usize = SF2_START + SF_COLS; // 219
    pub const CPS2_START: usize = CPS1_START + CPS_COLS; // 255
    pub const TOTAL: usize = CPS2_START + CPS_COLS; // 291
}

pub const NUM_COLS: usize = col::TOTAL;

#[derive(Debug, Clone, Copy)]
pub struct ModPChipFull {
    pub start_col: usize,
}

impl Default for ModPChipFull {
    fn default() -> Self {
        Self::new()
    }
}

impl ModPChipFull {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        FirstFoldChip::at(self.start_col + col::FF_START).emit(builder);
        SecondFoldOnePassChip::at(self.start_col + col::SF1_START).emit(builder);
        SecondFoldOnePassChip::at(self.start_col + col::SF2_START).emit(builder);
        CondPSubChip::at(self.start_col + col::CPS1_START).emit(builder);
        CondPSubChip::at(self.start_col + col::CPS2_START).emit(builder);

        let main = builder.main();
        let row = main.current_slice();

        let assert_chunks_eq = |b: &mut AB, off_a: usize, off_b: usize, n: usize| {
            for i in 0..n {
                b.assert_eq(row[off_a + i], row[off_b + i]);
            }
        };

        // FirstFold.L ← top-level L (18 limbs)
        assert_chunks_eq(builder, self.start_col + col::FF_START + ffc::L, self.start_col + col::L, NUM_INPUT_LIMBS);

        // SF1.acc_in ← FirstFold.OUT (10 limbs)
        assert_chunks_eq(builder, self.start_col + col::SF1_START + sfc::ACC_IN, self.start_col + col::FF_START + ffc::OUT, 10);

        // SF2.acc_in ← SF1.acc_out (10 limbs)
        assert_chunks_eq(builder, self.start_col + col::SF2_START + sfc::ACC_IN, self.start_col + col::SF1_START + sfc::ACC_OUT, 10);

        // After SF2, limb 9 must be zero (canonical-input regime).
        builder.assert_zero(row[self.start_col + col::SF2_START + sfc::ACC_OUT + 9]);

        // CPS1.A ← SF2.acc_out[0..9]
        assert_chunks_eq(
            builder,
            self.start_col + col::CPS1_START + cpc::A,
            self.start_col + col::SF2_START + sfc::ACC_OUT,
            NUM_LIMBS,
        );

        // CPS2.A ← CPS1.C
        assert_chunks_eq(builder, self.start_col + col::CPS2_START + cpc::A, self.start_col + col::CPS1_START + cpc::C, NUM_LIMBS);

        // Top-level C ← CPS2.C
        assert_chunks_eq(builder, self.start_col + col::C, self.start_col + col::CPS2_START + cpc::C, NUM_LIMBS);
    }
}

impl<F: Field> BaseAir<F> for ModPChipFull {
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

impl<AB: AirBuilder> Air<AB> for ModPChipFull
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        self.emit(builder);
    }
}

/// Populate one row at `(row_off, start_col)`.
pub fn populate_row<F: Field + PrimeCharacteristicRing>(
    values: &mut [F],
    row_off: usize,
    start_col: usize,
    input: &[u64; NUM_INPUT_LIMBS],
) {
    use super::Field25519Element;
    use super::cond_p_sub::compute_cond_p_sub;
    use super::first_fold::compute_first_fold_witness;
    use super::second_fold::populate_row as sf_populate;

    let base = row_off + start_col;

    // Top-level input.
    for i in 0..NUM_INPUT_LIMBS {
        values[base + col::L + i] = F::from_u64(input[i]);
    }

    // FirstFold witness.
    let ff_w = compute_first_fold_witness(input);
    for i in 0..NUM_INPUT_LIMBS {
        values[base + col::FF_START + ffc::L + i] = F::from_u64(ff_w.l[i]);
    }
    for i in 0..10 {
        values[base + col::FF_START + ffc::OUT + i] = F::from_u64(ff_w.out[i]);
        values[base + col::FF_START + ffc::CARRY + i] = F::from_u64(ff_w.carries[i]);
        // Etapa 3.8: 10-bit range bits for first_fold carry[i].
        crate::chips::lookup::range_n::RangeNChip::<{ super::first_fold::CARRY_BITS }>::populate_bits::<F>(
            values,
            base + col::FF_START + ffc::CARRY_BITS_BASE + i * super::first_fold::CARRY_BITS,
            ff_w.carries[i],
        );
    }
    for i in 0..27 {
        values[base + col::FF_START + ffc::PIECES + i] = F::from_u64(ff_w.pieces[i]);
        values[base + col::FF_START + ffc::PRODUCTS + i] = F::from_u64(ff_w.products[i]);
        // Etapa 3.3: 10-bit range bits for first_fold piece[i].
        crate::chips::lookup::range_n::RangeNChip::<10>::populate_bits::<F>(
            values,
            base + col::FF_START + ffc::PIECE_BITS_BASE + i * 10,
            ff_w.pieces[i],
        );
    }
    // Etapa 3.6: 30-bit / 20-bit range bits for first_fold low_30 / high_20.
    for k in 0..9 {
        crate::chips::lookup::range_n::RangeNChip::<30>::populate_bits::<F>(
            values,
            base + col::FF_START + ffc::LOW_30_BITS_BASE + k * 30,
            ff_w.low_30[k],
        );
        crate::chips::lookup::range_n::RangeNChip::<20>::populate_bits::<F>(
            values,
            base + col::FF_START + ffc::HIGH_20_BITS_BASE + k * 20,
            ff_w.high_20[k],
        );
    }
    for i in 0..9 {
        values[base + col::FF_START + ffc::LOW_30 + i] = F::from_u64(ff_w.low_30[i]);
        values[base + col::FF_START + ffc::HIGH_20 + i] = F::from_u64(ff_w.high_20[i]);
    }

    // SF1: input = FirstFold output (as u128).
    let sf1_in: [u128; 10] = std::array::from_fn(|i| ff_w.out[i] as u128);
    let sf1_w = sf_populate::<F>(values, row_off, start_col + col::SF1_START, &sf1_in);

    // SF2: input = SF1 output.
    let sf2_in: [u128; 10] = std::array::from_fn(|i| sf1_w.acc_out[i] as u128);
    let sf2_w = sf_populate::<F>(values, row_off, start_col + col::SF2_START, &sf2_in);
    debug_assert_eq!(sf2_w.acc_out[9], 0, "ModPChipFull: limb 9 must be 0 after 2 second_fold passes");

    // CPS1: input = SF2 output[0..9].
    let cps1_in = Field25519Element {
        limbs: [
            sf2_w.acc_out[0],
            sf2_w.acc_out[1],
            sf2_w.acc_out[2],
            sf2_w.acc_out[3],
            sf2_w.acc_out[4],
            sf2_w.acc_out[5],
            sf2_w.acc_out[6],
            sf2_w.acc_out[7],
            sf2_w.acc_out[8],
        ],
    };
    let cps1_w = compute_cond_p_sub(&cps1_in);
    for i in 0..NUM_LIMBS {
        values[base + col::CPS1_START + cpc::A + i] = F::from_u64(cps1_w.a_limbs[i]);
        values[base + col::CPS1_START + cpc::C + i] = F::from_u64(cps1_w.c_limbs[i]);
        values[base + col::CPS1_START + cpc::T + i] = F::from_u64(cps1_w.t_limbs[i]);
        values[base + col::CPS1_START + cpc::BORROW + i] = F::from_u64(cps1_w.borrow[i]);
    }

    // CPS2: input = CPS1 output (one more pass for safety, though typically idempotent).
    let cps2_in = Field25519Element { limbs: cps1_w.c_limbs };
    let cps2_w = compute_cond_p_sub(&cps2_in);
    for i in 0..NUM_LIMBS {
        values[base + col::CPS2_START + cpc::A + i] = F::from_u64(cps2_w.a_limbs[i]);
        values[base + col::CPS2_START + cpc::C + i] = F::from_u64(cps2_w.c_limbs[i]);
        values[base + col::CPS2_START + cpc::T + i] = F::from_u64(cps2_w.t_limbs[i]);
        values[base + col::CPS2_START + cpc::BORROW + i] = F::from_u64(cps2_w.borrow[i]);
    }

    // Top-level C output.
    for i in 0..NUM_LIMBS {
        values[base + col::C + i] = F::from_u64(cps2_w.c_limbs[i]);
    }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(input: &[u64; NUM_INPUT_LIMBS]) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    let zero = [0u64; NUM_INPUT_LIMBS];
    for row in 0..HEIGHT {
        populate_row::<F>(&mut values, row * NUM_COLS, 0, &zero);
    }
    populate_row::<F>(&mut values, 0, 0, input);

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::super::P_LIMBS;
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
    fn full_mod_p_zero() {
        let input = [0u64; NUM_INPUT_LIMBS];
        let trace = build_test_trace::<BabyBear>(&input);
        check_constraints(&ModPChipFull::new(), &trace, &[]);
        assert_eq!(read_c(&trace.values), [0u64; NUM_LIMBS]);
    }

    #[test]
    fn full_mod_p_small() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[0] = 12345;
        let trace = build_test_trace::<BabyBear>(&input);
        check_constraints(&ModPChipFull::new(), &trace, &[]);
        let mut expected = [0u64; NUM_LIMBS];
        expected[0] = 12345;
        assert_eq!(read_c(&trace.values), expected);
    }

    #[test]
    fn full_mod_p_p_yields_zero() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        for i in 0..NUM_LIMBS {
            input[i] = P_LIMBS[i];
        }
        let trace = build_test_trace::<BabyBear>(&input);
        check_constraints(&ModPChipFull::new(), &trace, &[]);
        assert_eq!(read_c(&trace.values), [0u64; NUM_LIMBS]);
    }

    #[test]
    fn full_mod_p_high_limb_set() {
        // Input that produces non-zero limb 9 after first_fold: requires
        // second_fold to clear. Set input limb 17 high to maximize V_hi.
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[17] = (1u64 << 30) - 1;
        let trace = build_test_trace::<BabyBear>(&input);
        check_constraints(&ModPChipFull::new(), &trace, &[]);
        let expected = compute_mod_p_reduction(&input);
        assert_eq!(read_c(&trace.values), expected.limbs);
    }

    #[test]
    fn full_mod_p_cross_validates_for_general_inputs() {
        // Various inputs covering small, mid, and high-limb cases.
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
                // Mid-range with high limb non-zero.
                let mut a = [0u64; NUM_INPUT_LIMBS];
                a[NUM_LIMBS] = 100;
                a
            },
            {
                // Large value in many limbs (simulates mul output).
                let mut a = [0u64; NUM_INPUT_LIMBS];
                for i in 0..NUM_INPUT_LIMBS {
                    a[i] = 0x1234_5678 + i as u64;
                }
                a
            },
            {
                // Maximum saturated mul output magnitude.
                let mut a = [0u64; NUM_INPUT_LIMBS];
                for i in 0..NUM_INPUT_LIMBS {
                    a[i] = (1u64 << 30) - 1;
                }
                a
            },
        ];
        for input in cases {
            let expected = compute_mod_p_reduction(&input);
            let trace = build_test_trace::<BabyBear>(&input);
            check_constraints(&ModPChipFull::new(), &trace, &[]);
            assert_eq!(read_c(&trace.values), expected.limbs, "input {input:?}");
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn full_mod_p_rejects_tampered() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[0] = 7;
        let mut trace = build_test_trace::<BabyBear>(&input);
        trace.values[col::C] += BabyBear::from_u64(1);
        check_constraints(&ModPChipFull::new(), &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        // 3.3+3.6+3.8 (FirstFold) + 3.9 (2× SecondFold +203 each) = 1111 + 406 = 1517.
        assert_eq!(NUM_COLS, 1517);
    }
}
