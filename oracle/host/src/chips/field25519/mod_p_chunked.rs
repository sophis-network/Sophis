//! `field25519::mod_p_chunked` — full mod-p reduction AIR (Etapa 3.10.2.4).
//!
//! Composer chunked equivalente ao `ModPChipFull` para uso pelo `pow_air`,
//! `mul_canonical_full`, ed25519 chips, etc. Compõe os chunked sound chips:
//!
//!   - `FirstFoldChunkedChip`         — 18 30-bit → 10 loose 30-bit
//!   - `SecondFoldChunkedChip` (×2)   — passes para clear limb 9
//!   - `CondPSubChunkedChip` (×2)     — finalização canônica `< p`
//!
//! Após dois SecondFoldChunked passes, `limb 9 = 0` (assert). Após dois
//! CondPSubChunked passes, output é canônico `< p`.
//!
//! Wire format invariance: input `L` (18 30-bit cols) e output `C` (9
//! 30-bit cols) preservam mesma semântica do `ModPChipFull` original →
//! drop-in replacement.
//!
//! ## Conversão de tipos entre chips
//!
//! - FirstFoldChunked.out (10 30-bit) → SecondFoldChunked[1].acc_in
//!   (10 30-bit): direto, mesma representação.
//! - SecondFoldChunked[1].acc_out (10 30-bit) → SecondFoldChunked[2]
//!   .acc_in: direto.
//! - SecondFoldChunked[2].acc_out[0..9] (9 30-bit) → CondPSubChunked[1]
//!   .a_lo + 2¹⁶·a_hi (chunked 16+14): linear constraint (sound, < 2³⁰
//!   < p).
//! - CondPSubChunked[1].c_lo/c_hi → CondPSubChunked[2].a_lo/a_hi:
//!   direto, mesma representação chunked.
//! - CondPSubChunked[2].c_lo/c_hi → top-level C (30-bit cols): linear
//!   constraint (sound).
//!
//! ## Layout
//!
//! | Range                | Width      | Contents                     |
//! |----------------------|------------|------------------------------|
//! | 0..18                | 18         | L (input 18 30-bit limbs)    |
//! | 18..27               | 9          | C (output canonical mod-p)   |
//! | 27..(27+FFC)         | 2668       | FirstFoldChunkedChip         |
//! | (27+FFC)..(...+SFC)  | 1073       | SecondFoldChunkedChip[1]     |
//! | ...                  | 1073       | SecondFoldChunkedChip[2]     |
//! | ...                  | 882        | CondPSubChunkedChip[1]       |
//! | ...                  | 882        | CondPSubChunkedChip[2]       |
//!
//! Total: ~6605 columns.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::add_canonical_chunked::{p_hi as _p_hi, split_limb, CHUNK_LO_BITS, CHUNK_LO_MOD};
use super::cond_p_sub_chunked::{
    col as cps_col, CondPSubChunkedChip, NUM_COLS as CPS_COLS,
};
use super::first_fold_chunked::{
    col as ff_col, FirstFoldChunkedChip, NUM_COLS as FF_COLS,
};
use super::second_fold_chunked::{
    col as sf_col, SecondFoldChunkedChip, NUM_COLS as SF_COLS,
};
use super::NUM_LIMBS;

const NUM_INPUT_LIMBS: usize = 18;

pub mod col {
    use super::*;
    pub const L: usize = 0;
    pub const C: usize = L + NUM_INPUT_LIMBS; // 18
    pub const FF_START: usize = C + NUM_LIMBS; // 27
    pub const SF1_START: usize = FF_START + FF_COLS;
    pub const SF2_START: usize = SF1_START + SF_COLS;
    pub const CPS1_START: usize = SF2_START + SF_COLS;
    pub const CPS2_START: usize = CPS1_START + CPS_COLS;
    pub const TOTAL: usize = CPS2_START + CPS_COLS;
}

pub const NUM_COLS: usize = col::TOTAL;

/// Layout descriptor and constraint emitter.
#[derive(Debug, Clone, Copy)]
pub struct ModPChunkedChip {
    pub start_col: usize,
}

impl ModPChunkedChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let s = self.start_col;

        // Emit each constituent chip's constraints at its sub-region.
        FirstFoldChunkedChip::at(s + col::FF_START).emit(builder);
        SecondFoldChunkedChip::at(s + col::SF1_START).emit(builder);
        SecondFoldChunkedChip::at(s + col::SF2_START).emit(builder);
        CondPSubChunkedChip::at(s + col::CPS1_START).emit(builder);
        CondPSubChunkedChip::at(s + col::CPS2_START).emit(builder);

        let main = builder.main();
        let row = main.current_slice();
        let two_pow_lo = AB::Expr::from_u64(CHUNK_LO_MOD);

        // ── Wiring constraints ────────────────────────────────────────
        // FirstFoldChunked.L ← top-level L (18 limbs)
        for i in 0..NUM_INPUT_LIMBS {
            builder.assert_eq(
                row[s + col::FF_START + ff_col::L + i],
                row[s + col::L + i],
            );
        }

        // SecondFoldChunked[1].acc_in ← FirstFoldChunked.out (10 limbs)
        for i in 0..10 {
            builder.assert_eq(
                row[s + col::SF1_START + sf_col::ACC_IN + i],
                row[s + col::FF_START + ff_col::OUT + i],
            );
        }

        // SecondFoldChunked[2].acc_in ← SecondFoldChunked[1].acc_out (10 limbs)
        for i in 0..10 {
            builder.assert_eq(
                row[s + col::SF2_START + sf_col::ACC_IN + i],
                row[s + col::SF1_START + sf_col::ACC_OUT + i],
            );
        }

        // After SF2, limb 9 must be zero (canonical-input regime).
        builder.assert_zero(row[s + col::SF2_START + sf_col::ACC_OUT + 9]);

        // CPS1: a_lo + 2^16·a_hi = SecondFoldChunked[2].acc_out[i] for i ∈ 0..9.
        // (Sound: RHS = 30-bit limb < 2^30 < p; LHS bounded by Range16/Range14
        // checks on a_lo/a_hi.)
        for i in 0..NUM_LIMBS {
            let a_lo = row[s + col::CPS1_START + cps_col::A_LO + i];
            let a_hi = row[s + col::CPS1_START + cps_col::A_HI + i];
            builder.assert_eq(
                row[s + col::SF2_START + sf_col::ACC_OUT + i],
                a_lo.into() + two_pow_lo.clone() * a_hi.into(),
            );
        }

        // CPS2.a_lo/a_hi ← CPS1.c_lo/c_hi (direct chunked-to-chunked passthrough).
        for i in 0..NUM_LIMBS {
            builder.assert_eq(
                row[s + col::CPS2_START + cps_col::A_LO + i],
                row[s + col::CPS1_START + cps_col::C_LO + i],
            );
            builder.assert_eq(
                row[s + col::CPS2_START + cps_col::A_HI + i],
                row[s + col::CPS1_START + cps_col::C_HI + i],
            );
        }

        // Top-level C[i] = CPS2.c_lo[i] + 2^16·CPS2.c_hi[i] (sound, < 2^30 < p).
        for i in 0..NUM_LIMBS {
            let c_lo = row[s + col::CPS2_START + cps_col::C_LO + i];
            let c_hi = row[s + col::CPS2_START + cps_col::C_HI + i];
            builder.assert_eq(
                row[s + col::C + i],
                c_lo.into() + two_pow_lo.clone() * c_hi.into(),
            );
        }

        let _ = _p_hi;
    }
}

impl<F: Field> BaseAir<F> for ModPChunkedChip {
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

impl<AB: AirBuilder> Air<AB> for ModPChunkedChip
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
    use super::cond_p_sub_chunked::populate_row_to as cps_populate_to;
    use super::first_fold_chunked::populate_row_to as ff_populate_to;
    use super::second_fold_chunked::populate_row as sf_populate;

    let base = row_off + start_col;

    // Top-level input.
    for i in 0..NUM_INPUT_LIMBS {
        values[base + col::L + i] = F::from_u64(input[i]);
    }

    // FirstFoldChunked witness.
    let ff_w = super::first_fold_chunked::compute_first_fold_chunked_witness(input);
    ff_populate_to::<F>(values, base + col::FF_START, &ff_w);

    // SecondFoldChunked[1]: input = FirstFoldChunked.out.
    let sf1_in: [u128; 10] = std::array::from_fn(|i| ff_w.out[i] as u128);
    let sf1_w = sf_populate::<F>(values, row_off, start_col + col::SF1_START, &sf1_in);

    // SecondFoldChunked[2]: input = SecondFoldChunked[1].acc_out.
    let sf2_in: [u128; 10] = std::array::from_fn(|i| sf1_w.acc_out[i] as u128);
    let sf2_w = sf_populate::<F>(values, row_off, start_col + col::SF2_START, &sf2_in);
    debug_assert_eq!(
        sf2_w.acc_out[9], 0,
        "ModPChunkedChip: limb 9 must be 0 after 2 second_fold passes"
    );

    // CondPSubChunked[1]: input = SF2.acc_out[0..9] (canonical-loose 30-bit).
    let cps1_a_limbs: [u64; NUM_LIMBS] = std::array::from_fn(|i| sf2_w.acc_out[i]);
    let cps1_w = compute_cps_chunked_witness(&cps1_a_limbs);
    cps_populate_to::<F>(values, base + col::CPS1_START, &cps1_w);

    // CondPSubChunked[2]: input = CPS1.c (chunked passthrough).
    let cps2_a_limbs: [u64; NUM_LIMBS] = std::array::from_fn(|i| {
        cps1_w.c_lo[i] | (cps1_w.c_hi[i] << CHUNK_LO_BITS)
    });
    let cps2_w = compute_cps_chunked_witness(&cps2_a_limbs);
    cps_populate_to::<F>(values, base + col::CPS2_START, &cps2_w);

    // Top-level C output: reconstitute from CPS2.c chunks.
    for i in 0..NUM_LIMBS {
        let c_limb = cps2_w.c_lo[i] | (cps2_w.c_hi[i] << CHUNK_LO_BITS);
        values[base + col::C + i] = F::from_u64(c_limb);
    }
}

/// Compute CondPSubChunkedWitness from canonical-loose 30-bit limbs.
fn compute_cps_chunked_witness(
    a_limbs: &[u64; NUM_LIMBS],
) -> super::cond_p_sub_chunked::CondPSubChunkedWitness {
    use super::cond_p_sub_chunked::compute_cond_p_sub_chunked;
    use super::Field25519Element;
    let elem = Field25519Element { limbs: *a_limbs };
    compute_cond_p_sub_chunked(&elem)
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(
    input: &[u64; NUM_INPUT_LIMBS],
) -> RowMajorMatrix<F> {
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
    use super::super::mod_p::compute_mod_p_reduction;
    use super::super::P_LIMBS;
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
    fn mod_p_chunked_zero() {
        let input = [0u64; NUM_INPUT_LIMBS];
        let trace = build_test_trace::<BabyBear>(&input);
        check_constraints(&ModPChunkedChip::new(), &trace, &[]);
        assert_eq!(read_c(&trace.values), [0u64; NUM_LIMBS]);
    }

    #[test]
    fn mod_p_chunked_small() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[0] = 12345;
        let trace = build_test_trace::<BabyBear>(&input);
        check_constraints(&ModPChunkedChip::new(), &trace, &[]);
        let mut expected = [0u64; NUM_LIMBS];
        expected[0] = 12345;
        assert_eq!(read_c(&trace.values), expected);
    }

    #[test]
    fn mod_p_chunked_p_yields_zero() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        for i in 0..NUM_LIMBS {
            input[i] = P_LIMBS[i];
        }
        let trace = build_test_trace::<BabyBear>(&input);
        check_constraints(&ModPChunkedChip::new(), &trace, &[]);
        assert_eq!(read_c(&trace.values), [0u64; NUM_LIMBS]);
    }

    #[test]
    fn mod_p_chunked_high_limb_set() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[17] = (1u64 << 30) - 1;
        let trace = build_test_trace::<BabyBear>(&input);
        check_constraints(&ModPChunkedChip::new(), &trace, &[]);
        let expected = compute_mod_p_reduction(&input);
        assert_eq!(read_c(&trace.values), expected.limbs);
    }

    #[test]
    fn mod_p_chunked_cross_validates_vs_witness() {
        let cases: Vec<[u64; NUM_INPUT_LIMBS]> = vec![
            {
                let mut a = [0u64; NUM_INPUT_LIMBS];
                a[0] = 1;
                a
            },
            {
                let mut a = [0u64; NUM_INPUT_LIMBS];
                a[5] = 0x1EAD_BEEF; // < 2^30
                a
            },
            {
                let mut a = [0u64; NUM_INPUT_LIMBS];
                a[NUM_LIMBS] = 100;
                a
            },
            {
                let mut a = [0u64; NUM_INPUT_LIMBS];
                for i in 0..NUM_INPUT_LIMBS {
                    a[i] = 0x1234_5678 + i as u64;
                }
                a
            },
            {
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
            check_constraints(&ModPChunkedChip::new(), &trace, &[]);
            assert_eq!(read_c(&trace.values), expected.limbs, "input {input:?}");
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn mod_p_chunked_rejects_tampered_c() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[0] = 7;
        let mut trace = build_test_trace::<BabyBear>(&input);
        trace.values[col::C] = trace.values[col::C] + BabyBear::from_u64(1);
        check_constraints(&ModPChunkedChip::new(), &trace, &[]);
    }

    #[test]
    fn layout_documented() {
        assert_eq!(col::L, 0);
        assert_eq!(col::C, 18);
        assert_eq!(col::FF_START, 27);
        // FF chunked = 2668 cols
        assert_eq!(col::SF1_START, 27 + 2668);
        // SF chunked = 1073 cols
        assert_eq!(col::SF2_START, 27 + 2668 + 1073);
        assert_eq!(col::CPS1_START, 27 + 2668 + 2 * 1073);
        // CPS chunked = 882 cols
        assert_eq!(col::CPS2_START, 27 + 2668 + 2 * 1073 + 882);
        assert_eq!(NUM_COLS, 27 + 2668 + 2 * 1073 + 2 * 882);
    }
}

// ─── helpers ─────────────────────────────────────────────────────────────

#[allow(dead_code)] // exposed for wider future composition; kept silent for now
fn split(limb: u64) -> (u64, u64) {
    split_limb(limb)
}
