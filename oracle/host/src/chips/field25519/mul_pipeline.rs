//! `field25519::mul_pipeline` — composed chip proving that 18 30-bit
//! limbs are the **unreduced** product `a × b` of two canonical 9-limb
//! field elements.
//!
//! Composes the three chips that take a multiplication from "two
//! canonical inputs" all the way to "18-limb integer product":
//!
//!   - `MulChip`           — schoolbook with 10-bit pieces, outputs 53
//!                           polynomial coefficients in base 2¹⁰
//!   - `CarryFoldChip`     — propagates carries so each polynomial
//!                           position becomes `< 2¹⁰`, plus an overflow carry
//!   - `LimbAssemblyChip`  — packs the 53 base-2¹⁰ + overflow into 18
//!                           30-bit limbs covering the full 540-bit product
//!
//! ## What this chip does NOT do
//!
//! It does **not** reduce mod `p = 2²⁵⁵ - 19`. The output `L[0..18]`
//! is the integer product, possibly larger than `p`. Reduction mod `p`
//! lands in a separate chip (`mod_p` AIR — sub-phase 5.2.1.1.e.1+,
//! the BabyBear-overflow design challenge documented in `mod_p.rs`).
//!
//! Until mod-p AIR ships, downstream chips that need canonical mod-p
//! output (e.g. ed25519 point ops) must wire the `mod_p` witness
//! through with explicit constraints in their own composition layer.
//!
//! ## Layout
//!
//! | Range       | Width | Contents                            |
//! |-------------|-------|-------------------------------------|
//! | 0..9        | 9     | a chunks (input, canonical 30-bit)  |
//! | 9..18       | 9     | b chunks (input)                    |
//! | 18..36      | 18    | L chunks (output, 18 30-bit limbs)  |
//! | 36..161     | 125   | MulChip                             |
//! | 161..320    | 159   | CarryFoldChip                       |
//! | 320..392    | 72    | LimbAssemblyChip                    |
//!
//! Total: **392 columns**, ~285 constraints (degree 2 max from MulChip).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::Field25519Element;
use super::NUM_LIMBS;
use super::carry_fold::{CarryFoldChip, NUM_COLS as CF_COLS, NUM_POSITIONS as CF_POSITIONS, col as cfc};
use super::limb_assembly::{LimbAssemblyChip, NUM_COLS as LA_COLS, NUM_OUTPUT_LIMBS as LA_LIMBS, col as lac};
use super::mul::{MulChip, NUM_COLS as MUL_COLS, OUTPUT_POSITIONS as MUL_POSITIONS, col as mlc};

pub mod col {
    use super::*;

    pub const A: usize = 0; // 9 cols
    pub const B: usize = A + NUM_LIMBS; // 9
    pub const L: usize = B + NUM_LIMBS; // 18 (output)

    pub const MUL_START: usize = L + LA_LIMBS; // 36
    pub const CARRY_FOLD_START: usize = MUL_START + MUL_COLS; // 161
    pub const LIMB_ASSEMBLY_START: usize = CARRY_FOLD_START + CF_COLS; // 320

    pub const TOTAL: usize = LIMB_ASSEMBLY_START + LA_COLS; // 392
}

pub const NUM_COLS: usize = col::TOTAL;

#[derive(Debug, Clone, Copy)]
pub struct MulPipelineChip {
    pub start_col: usize,
}

impl Default for MulPipelineChip {
    fn default() -> Self {
        Self::new()
    }
}

impl MulPipelineChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        MulChip::at(self.start_col + col::MUL_START).emit(builder);
        CarryFoldChip::at(self.start_col + col::CARRY_FOLD_START).emit(builder);
        LimbAssemblyChip::at(self.start_col + col::LIMB_ASSEMBLY_START).emit(builder);

        let main = builder.main();
        let row = main.current_slice();

        let assert_chunks_eq = |b: &mut AB, off_a: usize, off_b: usize, n: usize| {
            for i in 0..n {
                b.assert_eq(row[off_a + i], row[off_b + i]);
            }
        };

        assert_chunks_eq(builder, self.start_col + col::MUL_START + mlc::A_LIMBS, self.start_col + col::A, NUM_LIMBS);
        assert_chunks_eq(builder, self.start_col + col::MUL_START + mlc::B_LIMBS, self.start_col + col::B, NUM_LIMBS);
        assert_chunks_eq(
            builder,
            self.start_col + col::CARRY_FOLD_START + cfc::POS,
            self.start_col + col::MUL_START + mlc::OUT_POS,
            MUL_POSITIONS,
        );
        assert_chunks_eq(
            builder,
            self.start_col + col::LIMB_ASSEMBLY_START + lac::CAN,
            self.start_col + col::CARRY_FOLD_START + cfc::CAN,
            CF_POSITIONS,
        );
        builder.assert_eq(
            row[self.start_col + col::LIMB_ASSEMBLY_START + lac::OVF],
            row[self.start_col + col::CARRY_FOLD_START + cfc::CARRY + CF_POSITIONS - 1],
        );
        assert_chunks_eq(builder, self.start_col + col::L, self.start_col + col::LIMB_ASSEMBLY_START + lac::L, LA_LIMBS);
    }
}

impl<F: Field> BaseAir<F> for MulPipelineChip {
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

impl<AB: AirBuilder> Air<AB> for MulPipelineChip
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        self.emit(builder);
    }
}

/// Build a single-row trace exercising one full multiplication pipeline.
pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(a: &Field25519Element, b: &Field25519Element) -> RowMajorMatrix<F> {
    use super::carry_fold::compute_carry_fold;
    use super::limb_assembly::compute_limb_assembly_from_carry_fold;
    use super::mul::compute_mul;

    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    // Compute everything via witness functions.
    let mul_w = compute_mul(a, b);
    let fold_w = compute_carry_fold(&mul_w.out_positions);
    let assembly_w = compute_limb_assembly_from_carry_fold(&fold_w);

    // Top-level inputs and outputs.
    for i in 0..NUM_LIMBS {
        values[col::A + i] = F::from_u64(a.limbs[i]);
        values[col::B + i] = F::from_u64(b.limbs[i]);
    }
    for i in 0..LA_LIMBS {
        values[col::L + i] = F::from_u64(assembly_w.limbs[i]);
    }

    // Populate MulChip cols (limbs + pieces + positions + 10-bit range bits).
    super::mul::populate_row::<F>(&mut values, col::MUL_START, a, b, &mul_w);

    // Populate CarryFoldChip cols (Etapa 3.8: + 10-bit canonical bits + 16-bit carry bits).
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

    // Populate LimbAssemblyChip cols.
    for i in 0..CF_POSITIONS {
        values[col::LIMB_ASSEMBLY_START + lac::CAN + i] = F::from_u64(fold_w.canonical[i]);
    }
    values[col::LIMB_ASSEMBLY_START + lac::OVF] = F::from_u64(fold_w.carries[CF_POSITIONS - 1]);
    for i in 0..LA_LIMBS {
        values[col::LIMB_ASSEMBLY_START + lac::L + i] = F::from_u64(assembly_w.limbs[i]);
    }

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::super::limb_assembly::reconstruct_limbs;
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
    fn pipeline_zero_times_zero() {
        let trace = build_test_trace::<BabyBear>(&Field25519Element::ZERO, &Field25519Element::ZERO);
        check_constraints(&MulPipelineChip::new(), &trace, &[]);
        for i in 0..LA_LIMBS {
            assert_eq!(trace.values[col::L + i].as_canonical_u32(), 0);
        }
    }

    #[test]
    fn pipeline_three_times_seven() {
        let trace = build_test_trace::<BabyBear>(&small(3), &small(7));
        check_constraints(&MulPipelineChip::new(), &trace, &[]);
        assert_eq!(read_l(&trace.values), 21);
    }

    #[test]
    fn pipeline_arbitrary_product() {
        let a = 0x1234_5678u64;
        let b = 0x9ABC_DEF0u64;
        let trace = build_test_trace::<BabyBear>(&small(a), &small(b));
        check_constraints(&MulPipelineChip::new(), &trace, &[]);
        assert_eq!(read_l(&trace.values), (a as u128) * (b as u128));
    }

    /// Stress test: maximum canonical inputs (every limb = 2^30 - 1).
    /// Product fits in 18 limbs but exceeds u128 — we verify via
    /// `reconstruct_limbs` that the chip's L output matches what
    /// `compute_limb_assembly_from_carry_fold` produces.
    #[test]
    fn pipeline_max_canonical_inputs() {
        use super::super::carry_fold::compute_carry_fold;
        use super::super::limb_assembly::compute_limb_assembly_from_carry_fold;
        use super::super::mul::compute_mul;

        let max = Field25519Element { limbs: [(1 << 30) - 1; NUM_LIMBS] };
        let trace = build_test_trace::<BabyBear>(&max, &max);
        check_constraints(&MulPipelineChip::new(), &trace, &[]);

        let mul_w = compute_mul(&max, &max);
        let fold_w = compute_carry_fold(&mul_w.out_positions);
        let assembly_w = compute_limb_assembly_from_carry_fold(&fold_w);
        let expected_low_128 = reconstruct_limbs(&assembly_w);
        assert_eq!(read_l(&trace.values), expected_low_128);
    }

    #[test]
    fn pipeline_p_times_one_yields_p() {
        let p = Field25519Element::P;
        let mut one = Field25519Element::ZERO;
        one.limbs[0] = 1;
        let trace = build_test_trace::<BabyBear>(&p, &one);
        check_constraints(&MulPipelineChip::new(), &trace, &[]);
        // L[i] should equal P_LIMBS[i] for i < 9, zero for i >= 9 (since p × 1 < 2^256).
        for i in 0..NUM_LIMBS {
            assert_eq!(trace.values[col::L + i].as_canonical_u32() as u64, super::super::P_LIMBS[i]);
        }
        for i in NUM_LIMBS..LA_LIMBS {
            assert_eq!(trace.values[col::L + i].as_canonical_u32(), 0);
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn pipeline_rejects_tampered_l() {
        let trace_init = build_test_trace::<BabyBear>(&small(7), &small(13));
        let mut trace = trace_init;
        trace.values[col::L] += BabyBear::ONE;
        check_constraints(&MulPipelineChip::new(), &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn pipeline_rejects_tampered_a() {
        let trace_init = build_test_trace::<BabyBear>(&small(7), &small(13));
        let mut trace = trace_init;
        trace.values[col::A] += BabyBear::ONE;
        check_constraints(&MulPipelineChip::new(), &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        assert_eq!(NUM_COLS, 2310); // Etapa 3.2 (+540 mul) + 3.8 (+1378 carry_fold) = +1918
    }
}
