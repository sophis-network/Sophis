//! `field25519::mul_canonical_full` — canonical mod-p multiplication AIR
//! for ARBITRARY canonical inputs `a, b < p`.
//!
//! Identical structure to `mul_canonical` but uses `ModPChipFull` (with
//! 2 second_fold passes + 2 cond_p_sub passes) instead of the lighter
//! `mod_p_chip` (which only handles inputs where first_fold limb 9 = 0).
//!
//! ## Layout
//!
//! | Range       | Width | Contents                              |
//! |-------------|-------|---------------------------------------|
//! | 0..9        | 9     | a chunks (input, canonical mod-p)     |
//! | 9..18       | 9     | b chunks (input, canonical mod-p)     |
//! | 18..27      | 9     | c chunks (output, canonical mod-p)    |
//! | 27..419     | 392   | MulPipelineChip                       |
//! | 419..710    | 291   | ModPChipFull                          |
//!
//! Total: **710 columns**, ~510 constraints (degree 2).
//!
//! Use this chip when you need to mul two arbitrary canonical mod-p
//! inputs (ed25519 point ops, scalar mul, decompress sqrt, etc.).
//! For the small-input regime where first_fold limb 9 stays 0, the
//! lighter `mul_canonical` (592 cols) is preferred.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::mod_p_chip_full::{self, ModPChipFull, NUM_COLS as MP_COLS};
use super::mul_pipeline::{self, MulPipelineChip, NUM_COLS as MP_PIPE_COLS};
use super::{Field25519Element, NUM_LIMBS};

pub mod col {
    use super::*;
    pub const A: usize = 0;
    pub const B: usize = A + NUM_LIMBS;
    pub const C: usize = B + NUM_LIMBS;
    pub const PIPE_START: usize = C + NUM_LIMBS;
    pub const MP_START: usize = PIPE_START + MP_PIPE_COLS;
    pub const TOTAL: usize = MP_START + MP_COLS;
}

pub const NUM_COLS: usize = col::TOTAL;

#[derive(Debug, Clone, Copy)]
pub struct MulCanonicalFullChip {
    pub start_col: usize,
}

impl MulCanonicalFullChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        MulPipelineChip::at(self.start_col + col::PIPE_START).emit(builder);
        ModPChipFull::at(self.start_col + col::MP_START).emit(builder);

        let main = builder.main();
        let row = main.current_slice();

        let assert_chunks_eq = |b: &mut AB, off_a: usize, off_b: usize, n: usize| {
            for i in 0..n {
                b.assert_eq(row[off_a + i], row[off_b + i]);
            }
        };

        assert_chunks_eq(builder, self.start_col + col::PIPE_START + mul_pipeline::col::A, self.start_col + col::A, NUM_LIMBS);
        assert_chunks_eq(builder, self.start_col + col::PIPE_START + mul_pipeline::col::B, self.start_col + col::B, NUM_LIMBS);
        assert_chunks_eq(builder, self.start_col + col::MP_START + mod_p_chip_full::col::L, self.start_col + col::PIPE_START + mul_pipeline::col::L, 18);
        assert_chunks_eq(builder, self.start_col + col::C, self.start_col + col::MP_START + mod_p_chip_full::col::C, NUM_LIMBS);
    }
}

impl<F: Field> BaseAir<F> for MulCanonicalFullChip {
    fn width(&self) -> usize { NUM_COLS }
    fn main_next_row_columns(&self) -> Vec<usize> { Vec::new() }
    fn max_constraint_degree(&self) -> Option<usize> { Some(2) }
}

impl<AB: AirBuilder> Air<AB> for MulCanonicalFullChip
where AB::F: Field,
{
    fn eval(&self, builder: &mut AB) { self.emit(builder); }
}

/// Populate one row at `(row_off, start_col)`.
pub fn populate_row<F: Field + PrimeCharacteristicRing>(
    values: &mut [F],
    row_off: usize,
    start_col: usize,
    a: &Field25519Element,
    b: &Field25519Element,
) {
    use super::carry_fold::compute_carry_fold;
    use super::limb_assembly::compute_limb_assembly_from_carry_fold;
    use super::mul::compute_mul;
    use super::carry_fold::NUM_POSITIONS as CF_POS;
    use super::limb_assembly::NUM_OUTPUT_LIMBS as LA_L;
    use super::carry_fold::col as cfc;
    use super::limb_assembly::col as lac;

    let mul_w = compute_mul(a, b);
    let fold_w = compute_carry_fold(&mul_w.out_positions);
    let assembly_w = compute_limb_assembly_from_carry_fold(&fold_w);

    let base = row_off + start_col;

    // Top-level a, b.
    for i in 0..NUM_LIMBS {
        values[base + col::A + i] = F::from_u64(a.limbs[i]);
        values[base + col::B + i] = F::from_u64(b.limbs[i]);
    }

    // MulPipeline witness.
    for i in 0..NUM_LIMBS {
        values[base + col::PIPE_START + mul_pipeline::col::A + i] = F::from_u64(a.limbs[i]);
        values[base + col::PIPE_START + mul_pipeline::col::B + i] = F::from_u64(b.limbs[i]);
    }
    for i in 0..LA_L {
        values[base + col::PIPE_START + mul_pipeline::col::L + i] = F::from_u64(assembly_w.limbs[i]);
    }
    // MulChip witness (limbs + pieces + positions + 10-bit range bits, Etapa 3.2).
    super::mul::populate_row::<F>(
        values,
        base + col::PIPE_START + mul_pipeline::col::MUL_START,
        a,
        b,
        &mul_w,
    );
    {
        use super::carry_fold::{CANONICAL_BITS as CF_CAN_BITS, CARRY_BITS as CF_CARRY_BITS};
        for i in 0..CF_POS {
            values[base + col::PIPE_START + mul_pipeline::col::CARRY_FOLD_START + cfc::POS + i] = F::from_u64(mul_w.out_positions[i]);
            values[base + col::PIPE_START + mul_pipeline::col::CARRY_FOLD_START + cfc::CAN + i] = F::from_u64(fold_w.canonical[i]);
            values[base + col::PIPE_START + mul_pipeline::col::CARRY_FOLD_START + cfc::CARRY + i] = F::from_u64(fold_w.carries[i]);
            // Etapa 3.8: range bits.
            crate::chips::lookup::range_n::RangeNChip::<CF_CAN_BITS>::populate_bits::<F>(
                values,
                base + col::PIPE_START + mul_pipeline::col::CARRY_FOLD_START + cfc::CAN_BITS_BASE + i * CF_CAN_BITS,
                fold_w.canonical[i],
            );
            crate::chips::lookup::range_n::RangeNChip::<CF_CARRY_BITS>::populate_bits::<F>(
                values,
                base + col::PIPE_START + mul_pipeline::col::CARRY_FOLD_START + cfc::CARRY_BITS_BASE + i * CF_CARRY_BITS,
                fold_w.carries[i],
            );
        }
    }
    for i in 0..CF_POS {
        values[base + col::PIPE_START + mul_pipeline::col::LIMB_ASSEMBLY_START + lac::CAN + i] = F::from_u64(fold_w.canonical[i]);
    }
    values[base + col::PIPE_START + mul_pipeline::col::LIMB_ASSEMBLY_START + lac::OVF] = F::from_u64(fold_w.carries[CF_POS - 1]);
    for i in 0..LA_L {
        values[base + col::PIPE_START + mul_pipeline::col::LIMB_ASSEMBLY_START + lac::L + i] = F::from_u64(assembly_w.limbs[i]);
    }

    // ModPChipFull witness population (delegates to its own populate_row).
    mod_p_chip_full::populate_row::<F>(values, row_off, start_col + col::MP_START, &assembly_w.limbs);

    // Copy the canonical output from ModPChipFull's C slot to the
    // top-level C slot of mul_canonical_full.
    for i in 0..NUM_LIMBS {
        let mp_c = values[base + col::MP_START + mod_p_chip_full::col::C + i].clone();
        values[base + col::C + i] = mp_c;
    }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(
    a: &Field25519Element,
    b: &Field25519Element,
) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    let zero = Field25519Element::ZERO;
    for row in 0..HEIGHT {
        populate_row::<F>(&mut values, row * NUM_COLS, 0, &zero, &zero);
    }
    populate_row::<F>(&mut values, 0, 0, a, b);

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::arith::field_mul;
    use super::super::P_LIMBS;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeField32;

    fn small(n: u64) -> Field25519Element {
        let mut limbs = [0u64; NUM_LIMBS];
        limbs[0] = n & ((1 << 30) - 1);
        Field25519Element { limbs }
    }

    fn read_c(values: &[BabyBear]) -> [u64; NUM_LIMBS] {
        let mut out = [0u64; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            out[i] = values[col::C + i].as_canonical_u32() as u64;
        }
        out
    }

    #[test]
    fn mul_full_zero() {
        let trace = build_test_trace::<BabyBear>(&Field25519Element::ZERO, &Field25519Element::ZERO);
        check_constraints(&MulCanonicalFullChip::new(), &trace, &[]);
        assert_eq!(read_c(&trace.values), [0u64; NUM_LIMBS]);
    }

    #[test]
    fn mul_full_three_times_seven() {
        let trace = build_test_trace::<BabyBear>(&small(3), &small(7));
        check_constraints(&MulCanonicalFullChip::new(), &trace, &[]);
        let mut expected = [0u64; NUM_LIMBS];
        expected[0] = 21;
        assert_eq!(read_c(&trace.values), expected);
    }

    #[test]
    fn mul_full_large_canonical_inputs() {
        // Inputs near p (the regime mul_canonical CANNOT handle).
        let mut a = Field25519Element::ZERO;
        let mut b = Field25519Element::ZERO;
        for i in 0..NUM_LIMBS {
            a.limbs[i] = P_LIMBS[i] / 2;
            b.limbs[i] = P_LIMBS[i] / 3;
        }
        let expected = field_mul(&a, &b);
        let trace = build_test_trace::<BabyBear>(&a, &b);
        check_constraints(&MulCanonicalFullChip::new(), &trace, &[]);
        assert_eq!(read_c(&trace.values), expected.limbs);
    }

    #[test]
    fn mul_full_p_minus_1_squared() {
        // (p-1)² mod p = 1 (since (p-1) ≡ -1 mod p).
        let mut p_minus_1 = Field25519Element::ZERO;
        for i in 0..NUM_LIMBS {
            p_minus_1.limbs[i] = P_LIMBS[i];
        }
        p_minus_1.limbs[0] -= 1;
        let trace = build_test_trace::<BabyBear>(&p_minus_1, &p_minus_1);
        check_constraints(&MulCanonicalFullChip::new(), &trace, &[]);
        let mut expected = [0u64; NUM_LIMBS];
        expected[0] = 1;
        assert_eq!(read_c(&trace.values), expected);
    }

    #[test]
    fn mul_full_cross_validates_with_arith() {
        let cases: Vec<(Field25519Element, Field25519Element)> = vec![
            (small(0xCAFE), small(0xBABE)),
            (small(0xDEAD_BEEF), small(0xFEDC_BA98)),
            (small(2), small(3)),
        ];
        for (a, b) in cases {
            let expected = field_mul(&a, &b);
            let trace = build_test_trace::<BabyBear>(&a, &b);
            check_constraints(&MulCanonicalFullChip::new(), &trace, &[]);
            assert_eq!(read_c(&trace.values), expected.limbs);
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn mul_full_rejects_tampered() {
        let mut trace = build_test_trace::<BabyBear>(&small(7), &small(13));
        trace.values[col::C] = trace.values[col::C] + BabyBear::from_u64(1);
        check_constraints(&MulCanonicalFullChip::new(), &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        // 3.2 + 3.3 + 3.6 + 3.8 + 3.9 (+406 from 2× SecondFold) = 3448 + 406 = 3854.
        assert_eq!(NUM_COLS, 3854);
    }
}
