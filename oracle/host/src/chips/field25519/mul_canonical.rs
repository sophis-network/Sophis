//! `field25519::mul_canonical` — canonical mod-p multiplication AIR chip.
//!
//! Composes `MulPipelineChip` + `ModPChip` to produce a canonical mod-p
//! result `c = (a · b) mod p` with `c < p`.
//!
//! ## Layout
//!
//! | Range       | Width | Contents                              |
//! |-------------|-------|---------------------------------------|
//! | 0..9        | 9     | a chunks (input, canonical mod-p)     |
//! | 9..18       | 9     | b chunks (input, canonical mod-p)     |
//! | 18..27      | 9     | c chunks (output, canonical mod-p)    |
//! | 27..419     | 392   | MulPipelineChip                       |
//! | 419..592    | 173   | ModPChip                              |
//!
//! Total: **592 columns**, ~390 constraints (degree 2).
//!
//! ## Soundness
//!
//! Inherits gaps from `mul_pipeline` (range checks deferred) and
//! `mod_p_chip` (iterated fold not in AIR — single-pass only).
//!
//! **Important:** the inherited `mod_p_chip` precondition `first_fold
//! limb 9 == 0` may NOT hold for arbitrary mul outputs (which can be
//! up to ~2⁵¹⁰, so V_hi · M can be up to ~2³⁰⁰ which spills into
//! limb 9). For canonical inputs `a, b < p ≈ 2²⁵⁵`: `a·b < p² ≈ 2⁵¹⁰`.
//! After mul_pipeline, the 18-limb output represents this 510-bit value.
//! After first_fold (V_lo + V_hi · M), the result fits in ~10 limbs
//! and limb 9 may be non-zero in some cases. This chip is sound for
//! the SUBSET of inputs where the precondition holds (typically
//! requires additional fold passes for full canonical mul). For
//! production ed25519, an extended `mul_canonical_full` chip with
//! iterated folds is needed (multi-week design).
//!
//! Tests cover the regime where the precondition holds (small inputs,
//! `a · b < 2³⁰⁰`).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::mod_p_chip::{self, ModPChip, NUM_COLS as MP_COLS};
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
pub struct MulCanonicalChip {
    pub start_col: usize,
}

impl MulCanonicalChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        MulPipelineChip::at(self.start_col + col::PIPE_START).emit(builder);
        ModPChip::at(self.start_col + col::MP_START).emit(builder);

        let main = builder.main();
        let row = main.current_slice();

        let assert_chunks_eq = |b: &mut AB, off_a: usize, off_b: usize, n: usize| {
            for i in 0..n {
                b.assert_eq(row[off_a + i], row[off_b + i]);
            }
        };

        // MulPipeline's a, b ← top-level a, b
        assert_chunks_eq(builder, self.start_col + col::PIPE_START + mul_pipeline::col::A, self.start_col + col::A, NUM_LIMBS);
        assert_chunks_eq(builder, self.start_col + col::PIPE_START + mul_pipeline::col::B, self.start_col + col::B, NUM_LIMBS);

        // ModP's L input ← MulPipeline's L output (18 limbs)
        assert_chunks_eq(builder, self.start_col + col::MP_START + mod_p_chip::col::L, self.start_col + col::PIPE_START + mul_pipeline::col::L, 18);

        // top-level c ← ModP's C output
        assert_chunks_eq(builder, self.start_col + col::C, self.start_col + col::MP_START + mod_p_chip::col::C, NUM_LIMBS);
    }
}

impl<F: Field> BaseAir<F> for MulCanonicalChip {
    fn width(&self) -> usize { NUM_COLS }
    fn main_next_row_columns(&self) -> Vec<usize> { Vec::new() }
    fn max_constraint_degree(&self) -> Option<usize> { Some(2) }
}

impl<AB: AirBuilder> Air<AB> for MulCanonicalChip
where AB::F: Field,
{
    fn eval(&self, builder: &mut AB) { self.emit(builder); }
}

/// Populate witness columns for one MulCanonicalChip instance at a
/// given (row offset, start column). Reusable by composing chips
/// (pow_air, scalar_mul_air, decompress_air, point_add_air, verify_air)
/// that embed `MulCanonicalChip` at non-zero column offsets.
///
/// **Precondition** (mirrors `MulCanonicalChip` doc): `compute_first_fold(
/// a · b)`'s limb 9 must be 0. Holds when `a · b < 2³⁰⁰`.
///
/// `values` must be at least `start_col + NUM_COLS` wide per row.
/// `row_off` is the absolute byte offset into `values` (typically
/// `row_index * trace_width`).
pub fn populate_row<F: Field + PrimeCharacteristicRing>(
    values: &mut [F],
    row_off: usize,
    start_col: usize,
    a: &Field25519Element,
    b: &Field25519Element,
) {
    use super::carry_fold::compute_carry_fold;
    use super::cond_p_sub::compute_cond_p_sub;
    use super::first_fold::compute_first_fold_witness;
    use super::limb_assembly::compute_limb_assembly_from_carry_fold;
    use super::mul::compute_mul;
    use super::carry_fold::NUM_POSITIONS as CF_POS;
    use super::limb_assembly::NUM_OUTPUT_LIMBS as LA_L;
    use super::carry_fold::col as cfc;
    use super::limb_assembly::col as lac;
    use super::cond_p_sub::col as cpc;
    use super::first_fold::col as ffc;

    let mul_w = compute_mul(a, b);
    let fold_w = compute_carry_fold(&mul_w.out_positions);
    let assembly_w = compute_limb_assembly_from_carry_fold(&fold_w);
    let ff_w = compute_first_fold_witness(&assembly_w.limbs);
    debug_assert_eq!(ff_w.out[9], 0, "mul_canonical::populate_row precondition: first_fold limb 9 must be 0 (a·b too large for single-pass mod_p)");

    let ff_out_9 = Field25519Element {
        limbs: [
            ff_w.out[0], ff_w.out[1], ff_w.out[2], ff_w.out[3], ff_w.out[4],
            ff_w.out[5], ff_w.out[6], ff_w.out[7], ff_w.out[8],
        ],
    };
    let cps_w = compute_cond_p_sub(&ff_out_9);

    let base = row_off + start_col;

    // Top-level
    for i in 0..NUM_LIMBS {
        values[base + col::A + i] = F::from_u64(a.limbs[i]);
        values[base + col::B + i] = F::from_u64(b.limbs[i]);
        values[base + col::C + i] = F::from_u64(cps_w.c_limbs[i]);
    }
    // MulPipeline witness
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
    // ModPChip witness
    for i in 0..18 {
        values[base + col::MP_START + mod_p_chip::col::L + i] = F::from_u64(assembly_w.limbs[i]);
    }
    for i in 0..NUM_LIMBS {
        values[base + col::MP_START + mod_p_chip::col::C + i] = F::from_u64(cps_w.c_limbs[i]);
    }
    for i in 0..18 {
        values[base + col::MP_START + mod_p_chip::col::FF_START + ffc::L + i] = F::from_u64(ff_w.l[i]);
    }
    for i in 0..10 {
        values[base + col::MP_START + mod_p_chip::col::FF_START + ffc::OUT + i] = F::from_u64(ff_w.out[i]);
        values[base + col::MP_START + mod_p_chip::col::FF_START + ffc::CARRY + i] = F::from_u64(ff_w.carries[i]);
        // Etapa 3.8: 10-bit range bits for first_fold carry[i].
        crate::chips::lookup::range_n::RangeNChip::<{super::first_fold::CARRY_BITS}>::populate_bits::<F>(
            values,
            base + col::MP_START + mod_p_chip::col::FF_START + ffc::CARRY_BITS_BASE + i * super::first_fold::CARRY_BITS,
            ff_w.carries[i],
        );
    }
    for i in 0..27 {
        values[base + col::MP_START + mod_p_chip::col::FF_START + ffc::PIECES + i] = F::from_u64(ff_w.pieces[i]);
        values[base + col::MP_START + mod_p_chip::col::FF_START + ffc::PRODUCTS + i] = F::from_u64(ff_w.products[i]);
        // Etapa 3.3: 10-bit range bits for first_fold piece[i].
        crate::chips::lookup::range_n::RangeNChip::<10>::populate_bits::<F>(
            values,
            base + col::MP_START + mod_p_chip::col::FF_START + ffc::PIECE_BITS_BASE + i * 10,
            ff_w.pieces[i],
        );
    }
    // Etapa 3.6: 30-bit / 20-bit range bits for first_fold low_30 / high_20.
    for k in 0..9 {
        crate::chips::lookup::range_n::RangeNChip::<30>::populate_bits::<F>(
            values,
            base + col::MP_START + mod_p_chip::col::FF_START + ffc::LOW_30_BITS_BASE + k * 30,
            ff_w.low_30[k],
        );
        crate::chips::lookup::range_n::RangeNChip::<20>::populate_bits::<F>(
            values,
            base + col::MP_START + mod_p_chip::col::FF_START + ffc::HIGH_20_BITS_BASE + k * 20,
            ff_w.high_20[k],
        );
    }
    for i in 0..9 {
        values[base + col::MP_START + mod_p_chip::col::FF_START + ffc::LOW_30 + i] = F::from_u64(ff_w.low_30[i]);
        values[base + col::MP_START + mod_p_chip::col::FF_START + ffc::HIGH_20 + i] = F::from_u64(ff_w.high_20[i]);
    }
    for i in 0..NUM_LIMBS {
        values[base + col::MP_START + mod_p_chip::col::CPS_START + cpc::A + i] = F::from_u64(cps_w.a_limbs[i]);
        values[base + col::MP_START + mod_p_chip::col::CPS_START + cpc::C + i] = F::from_u64(cps_w.c_limbs[i]);
        values[base + col::MP_START + mod_p_chip::col::CPS_START + cpc::T + i] = F::from_u64(cps_w.t_limbs[i]);
        values[base + col::MP_START + mod_p_chip::col::CPS_START + cpc::BORROW + i] = F::from_u64(cps_w.borrow[i]);
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
    fn mul_canonical_zero() {
        let trace = build_test_trace::<BabyBear>(&Field25519Element::ZERO, &Field25519Element::ZERO);
        check_constraints(&MulCanonicalChip::new(), &trace, &[]);
        assert_eq!(read_c(&trace.values), [0u64; NUM_LIMBS]);
    }

    #[test]
    fn mul_canonical_three_times_seven() {
        let trace = build_test_trace::<BabyBear>(&small(3), &small(7));
        check_constraints(&MulCanonicalChip::new(), &trace, &[]);
        let mut expected = [0u64; NUM_LIMBS];
        expected[0] = 21;
        assert_eq!(read_c(&trace.values), expected);
    }

    #[test]
    fn mul_canonical_small_inputs() {
        // Limit to small values where first_fold limb 9 = 0 (precondition).
        let cases: Vec<(Field25519Element, Field25519Element)> = vec![
            (small(2), small(3)),
            (small(0xFFFF), small(0xFF)),
            (small(0xCAFE), small(0xBABE)),
        ];
        for (a, b) in cases {
            let expected = field_mul(&a, &b);
            let trace = build_test_trace::<BabyBear>(&a, &b);
            check_constraints(&MulCanonicalChip::new(), &trace, &[]);
            assert_eq!(read_c(&trace.values), expected.limbs);
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn mul_canonical_rejects_tampered() {
        let mut trace = build_test_trace::<BabyBear>(&small(7), &small(13));
        trace.values[col::C] = trace.values[col::C] + BabyBear::ONE;
        check_constraints(&MulCanonicalChip::new(), &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        // 3.2 (+540 mul) + 3.3 (+270 ff pieces) + 3.6 (+450 ff low/high) + 3.8 (+1378 cf + +100 ff carry).
        assert_eq!(NUM_COLS, 3330);
    }
}
