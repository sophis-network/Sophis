//! `field25519::mul_pipeline_chunked` — chunked-sound MulPipeline (Etapa 3.10.2.5).
//!
//! Composer chunked equivalente ao `MulPipelineChip` que prova
//! `L[0..18] = a × b` para a/b canônicos 9-limb, usando os componentes
//! sound:
//!
//!   - `MulChip`                     — schoolbook 10-bit pieces (sound per audit)
//!   - `CarryFoldChip`               — propaga carries (sound per audit)
//!   - `LimbAssemblyChunkedChip`     — pack 53 + ovf → 18 30-bit limbs +
//!                                      chunked 16+14 (Etapa 3.10.2.2 sound)
//!
//! Drop-in replacement do `MulPipelineChip` original com mesma semântica
//! wire-format (a, b 9 cols cada + L 18 cols), porém usando o
//! `LimbAssemblyChunkedChip` no lugar do `LimbAssemblyChip` original
//! (que estava marcado como PROBABLE GAP no audit 3.10.2).
//!
//! Wire format invariance: `a/b/L` preservam offsets e semântica originais.
//! Output adicional: `L_LO[0..18]` + `L_HI[0..18]` (16+14 chunks) expostos
//! via LimbAssemblyChunked → permite consumidores chunked downstream
//! (mod_p_chunked, mul_canonical_full_chunked) saltarem a re-decomposição.
//!
//! ## Layout
//!
//! | Range            | Width | Contents                                |
//! |------------------|-------|-----------------------------------------|
//! | 0..9             | 9     | a chunks (input, canonical 30-bit)      |
//! | 9..18            | 9     | b chunks (input)                        |
//! | 18..36           | 18    | L chunks (output, 18 30-bit limbs)      |
//! | 36..(36+MUL)     | MUL   | MulChip                                 |
//! | ...              | CF    | CarryFoldChip                           |
//! | ...              | LAC   | LimbAssemblyChunkedChip                 |
//!
//! Total: ~2825 colunas (vs ~2310 do MulPipelineChip não-chunked).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::carry_fold::{
    col as cfc, CarryFoldChip, NUM_COLS as CF_COLS, NUM_POSITIONS as CF_POSITIONS,
};
use super::limb_assembly_chunked::{
    col as lac, LimbAssemblyChunkedChip, NUM_COLS as LA_COLS,
    NUM_OUTPUT_LIMBS as LA_LIMBS,
};
use super::mul::{
    col as mlc, MulChip, NUM_COLS as MUL_COLS, OUTPUT_POSITIONS as MUL_POSITIONS,
};
use super::Field25519Element;
use super::NUM_LIMBS;

pub mod col {
    use super::*;

    pub const A: usize = 0; // 9 cols
    pub const B: usize = A + NUM_LIMBS; // 9
    pub const L: usize = B + NUM_LIMBS; // 18 (output)

    pub const MUL_START: usize = L + LA_LIMBS; // 36
    pub const CARRY_FOLD_START: usize = MUL_START + MUL_COLS;
    pub const LIMB_ASSEMBLY_START: usize = CARRY_FOLD_START + CF_COLS;

    pub const TOTAL: usize = LIMB_ASSEMBLY_START + LA_COLS;
}

pub const NUM_COLS: usize = col::TOTAL;

#[derive(Debug, Clone, Copy)]
pub struct MulPipelineChunkedChip {
    pub start_col: usize,
}

impl MulPipelineChunkedChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let s = self.start_col;
        MulChip::at(s + col::MUL_START).emit(builder);
        CarryFoldChip::at(s + col::CARRY_FOLD_START).emit(builder);
        LimbAssemblyChunkedChip::at(s + col::LIMB_ASSEMBLY_START).emit(builder);

        let main = builder.main();
        let row = main.current_slice();

        let assert_chunks_eq = |b: &mut AB, off_a: usize, off_b: usize, n: usize| {
            for i in 0..n {
                b.assert_eq(row[off_a + i], row[off_b + i]);
            }
        };

        // a/b inputs to MulChip
        assert_chunks_eq(
            builder,
            s + col::MUL_START + mlc::A_LIMBS,
            s + col::A,
            NUM_LIMBS,
        );
        assert_chunks_eq(
            builder,
            s + col::MUL_START + mlc::B_LIMBS,
            s + col::B,
            NUM_LIMBS,
        );
        // MulChip.OUT_POS → CarryFoldChip.POS
        assert_chunks_eq(
            builder,
            s + col::CARRY_FOLD_START + cfc::POS,
            s + col::MUL_START + mlc::OUT_POS,
            MUL_POSITIONS,
        );
        // CarryFoldChip.CAN → LimbAssemblyChunked.CAN
        assert_chunks_eq(
            builder,
            s + col::LIMB_ASSEMBLY_START + lac::CAN,
            s + col::CARRY_FOLD_START + cfc::CAN,
            CF_POSITIONS,
        );
        // CarryFoldChip last carry → LimbAssemblyChunked.OVF
        builder.assert_eq(
            row[s + col::LIMB_ASSEMBLY_START + lac::OVF],
            row[s + col::CARRY_FOLD_START + cfc::CARRY + CF_POSITIONS - 1],
        );
        // LimbAssemblyChunked.L → top-level L
        assert_chunks_eq(
            builder,
            s + col::L,
            s + col::LIMB_ASSEMBLY_START + lac::L,
            LA_LIMBS,
        );
    }
}

impl<F: Field> BaseAir<F> for MulPipelineChunkedChip {
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

impl<AB: AirBuilder> Air<AB> for MulPipelineChunkedChip
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        self.emit(builder);
    }
}

/// Build a single-row trace exercising the chunked multiplication pipeline.
pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(
    a: &Field25519Element,
    b: &Field25519Element,
) -> RowMajorMatrix<F> {
    use super::carry_fold::compute_carry_fold;
    use super::limb_assembly_chunked::{compute_limb_assembly_chunked, populate_row_to as la_populate};
    use super::mul::compute_mul;

    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    // Witness chain.
    let mul_w = compute_mul(a, b);
    let fold_w = compute_carry_fold(&mul_w.out_positions);
    let ovf = fold_w.carries[CF_POSITIONS - 1];
    let assembly_w = compute_limb_assembly_chunked(&fold_w.canonical, ovf);

    // Top-level inputs/output.
    for i in 0..NUM_LIMBS {
        values[col::A + i] = F::from_u64(a.limbs[i]);
        values[col::B + i] = F::from_u64(b.limbs[i]);
    }
    for i in 0..LA_LIMBS {
        values[col::L + i] = F::from_u64(assembly_w.l[i]);
    }

    // MulChip
    super::mul::populate_row::<F>(&mut values, col::MUL_START, a, b, &mul_w);

    // CarryFoldChip
    use super::carry_fold::{CANONICAL_BITS as CF_CAN_BITS, CARRY_BITS as CF_CARRY_BITS};
    use crate::chips::lookup::range_n::RangeNChip;
    for i in 0..CF_POSITIONS {
        values[col::CARRY_FOLD_START + cfc::POS + i] = F::from_u64(mul_w.out_positions[i]);
        values[col::CARRY_FOLD_START + cfc::CAN + i] = F::from_u64(fold_w.canonical[i]);
        values[col::CARRY_FOLD_START + cfc::CARRY + i] = F::from_u64(fold_w.carries[i]);
        RangeNChip::<CF_CAN_BITS>::populate_bits::<F>(
            &mut values,
            col::CARRY_FOLD_START + cfc::CAN_BITS_BASE + i * CF_CAN_BITS,
            fold_w.canonical[i],
        );
        RangeNChip::<CF_CARRY_BITS>::populate_bits::<F>(
            &mut values,
            col::CARRY_FOLD_START + cfc::CARRY_BITS_BASE + i * CF_CARRY_BITS,
            fold_w.carries[i],
        );
    }

    // LimbAssemblyChunkedChip
    la_populate::<F>(&mut values, col::LIMB_ASSEMBLY_START, &assembly_w);

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeField32;

    fn small(n: u64) -> Field25519Element {
        let mut limbs = [0u64; NUM_LIMBS];
        limbs[0] = n & ((1 << 30) - 1);
        limbs[1] = (n >> 30) & ((1 << 30) - 1);
        Field25519Element { limbs }
    }

    fn read_l(values: &[BabyBear]) -> u128 {
        let mut acc: u128 = 0;
        for i in (0..LA_LIMBS).rev() {
            if 30 * i >= 128 {
                continue;
            }
            let v = values[col::L + i].as_canonical_u32() as u128;
            acc = acc.wrapping_add(v << (30 * i));
        }
        acc
    }

    #[test]
    fn pipeline_chunked_zero_times_zero() {
        let trace = build_test_trace::<BabyBear>(&Field25519Element::ZERO, &Field25519Element::ZERO);
        check_constraints(&MulPipelineChunkedChip::new(), &trace, &[]);
        for i in 0..LA_LIMBS {
            assert_eq!(trace.values[col::L + i].as_canonical_u32(), 0);
        }
    }

    #[test]
    fn pipeline_chunked_three_times_seven() {
        let trace = build_test_trace::<BabyBear>(&small(3), &small(7));
        check_constraints(&MulPipelineChunkedChip::new(), &trace, &[]);
        assert_eq!(read_l(&trace.values), 21);
    }

    #[test]
    fn pipeline_chunked_arbitrary_product() {
        let a = 0x1234_5678u64;
        let b = 0x9ABC_DEF0u64;
        let trace = build_test_trace::<BabyBear>(&small(a), &small(b));
        check_constraints(&MulPipelineChunkedChip::new(), &trace, &[]);
        assert_eq!(read_l(&trace.values), (a as u128) * (b as u128));
    }

    #[test]
    fn pipeline_chunked_max_canonical_inputs() {
        use super::super::carry_fold::compute_carry_fold;
        use super::super::limb_assembly::{compute_limb_assembly_from_carry_fold, reconstruct_limbs};
        use super::super::mul::compute_mul;

        let max = Field25519Element {
            limbs: [(1 << 30) - 1; NUM_LIMBS],
        };
        let trace = build_test_trace::<BabyBear>(&max, &max);
        check_constraints(&MulPipelineChunkedChip::new(), &trace, &[]);

        let mul_w = compute_mul(&max, &max);
        let fold_w = compute_carry_fold(&mul_w.out_positions);
        let assembly_w = compute_limb_assembly_from_carry_fold(&fold_w);
        let expected_low_128 = reconstruct_limbs(&assembly_w);
        assert_eq!(read_l(&trace.values), expected_low_128);
    }

    #[test]
    fn pipeline_chunked_p_times_one_yields_p() {
        let p = Field25519Element::P;
        let mut one = Field25519Element::ZERO;
        one.limbs[0] = 1;
        let trace = build_test_trace::<BabyBear>(&p, &one);
        check_constraints(&MulPipelineChunkedChip::new(), &trace, &[]);
        for i in 0..NUM_LIMBS {
            assert_eq!(
                trace.values[col::L + i].as_canonical_u32() as u64,
                super::super::P_LIMBS[i]
            );
        }
        for i in NUM_LIMBS..LA_LIMBS {
            assert_eq!(trace.values[col::L + i].as_canonical_u32(), 0);
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn pipeline_chunked_rejects_tampered_l() {
        let mut trace = build_test_trace::<BabyBear>(&small(7), &small(13));
        trace.values[col::L] = trace.values[col::L] + BabyBear::ONE;
        check_constraints(&MulPipelineChunkedChip::new(), &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn pipeline_chunked_rejects_tampered_a() {
        let mut trace = build_test_trace::<BabyBear>(&small(7), &small(13));
        trace.values[col::A] = trace.values[col::A] + BabyBear::ONE;
        check_constraints(&MulPipelineChunkedChip::new(), &trace, &[]);
    }

    #[test]
    fn layout_documented() {
        // Matches expected sub-chip widths.
        assert_eq!(col::A, 0);
        assert_eq!(col::B, 9);
        assert_eq!(col::L, 18);
        assert_eq!(col::MUL_START, 36);
        // Sanity: MUL_COLS, CF_COLS, LA_COLS all positive and offsets monotonic.
        assert!(col::CARRY_FOLD_START > col::MUL_START);
        assert!(col::LIMB_ASSEMBLY_START > col::CARRY_FOLD_START);
        assert!(NUM_COLS > col::LIMB_ASSEMBLY_START);
    }
}

