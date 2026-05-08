//! `field25519::mul_canonical_full_chunked` — top-level chunked-sound
//! canonical mod-p multiplication AIR (Etapa 3.10.2.6).
//!
//! Substitui `MulCanonicalFullChip` compondo os chunked-sound chips:
//!
//!   - `MulPipelineChunkedChip` (Etapa 3.10.2.5) — 18-limb integer product
//!   - `ModPChunkedChip`        (Etapa 3.10.2.4) — full mod-p reduction
//!
//! Drop-in replacement do `MulCanonicalFullChip` original. Para inputs
//! `a, b < p` canônicos 9-limb, calcula `c = (a · b) mod p` com **todas
//! as BB-wrap collision classes fechadas estruturalmente**.
//!
//! Wire format invariance: a/b/c preservam offsets e semântica originais.
//!
//! ## Layout
//!
//! | Range            | Width | Contents                                |
//! |------------------|-------|-----------------------------------------|
//! | 0..9             | 9     | a chunks (input, canonical mod-p)       |
//! | 9..18            | 9     | b chunks (input, canonical mod-p)       |
//! | 18..27           | 9     | c chunks (output, canonical mod-p)      |
//! | 27..(27+MPC)     | MPC   | MulPipelineChunkedChip                  |
//! | ...              | MOD   | ModPChunkedChip                         |
//!
//! Total: ~9430 columns (vs ~3854 do MulCanonicalFullChip não-chunked).
//! O custo extra reflete o range checking exhaustivo necessário pra
//! fechar BB-wrap structurally — esse é o preço da soundness pre-mainnet.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::mod_p_chunked::{self, ModPChunkedChip, NUM_COLS as MOD_COLS};
use super::mul_pipeline_chunked::{self, MulPipelineChunkedChip, NUM_COLS as MPC_COLS};
use super::{Field25519Element, NUM_LIMBS};

pub mod col {
    use super::*;
    pub const A: usize = 0;
    pub const B: usize = A + NUM_LIMBS;
    pub const C: usize = B + NUM_LIMBS;
    pub const PIPE_START: usize = C + NUM_LIMBS;
    pub const MOD_START: usize = PIPE_START + MPC_COLS;
    pub const TOTAL: usize = MOD_START + MOD_COLS;
}

pub const NUM_COLS: usize = col::TOTAL;

#[derive(Debug, Clone, Copy)]
pub struct MulCanonicalFullChunkedChip {
    pub start_col: usize,
}

impl Default for MulCanonicalFullChunkedChip {
    fn default() -> Self {
        Self::new()
    }
}

impl MulCanonicalFullChunkedChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let s = self.start_col;
        MulPipelineChunkedChip::at(s + col::PIPE_START).emit(builder);
        ModPChunkedChip::at(s + col::MOD_START).emit(builder);

        let main = builder.main();
        let row = main.current_slice();

        let assert_chunks_eq = |b: &mut AB, off_a: usize, off_b: usize, n: usize| {
            for i in 0..n {
                b.assert_eq(row[off_a + i], row[off_b + i]);
            }
        };

        // MulPipelineChunked.A = top.A
        assert_chunks_eq(builder, s + col::PIPE_START + mul_pipeline_chunked::col::A, s + col::A, NUM_LIMBS);
        // MulPipelineChunked.B = top.B
        assert_chunks_eq(builder, s + col::PIPE_START + mul_pipeline_chunked::col::B, s + col::B, NUM_LIMBS);
        // ModPChunked.L = MulPipelineChunked.L (18 limbs)
        assert_chunks_eq(builder, s + col::MOD_START + mod_p_chunked::col::L, s + col::PIPE_START + mul_pipeline_chunked::col::L, 18);
        // top.C = ModPChunked.C
        assert_chunks_eq(builder, s + col::C, s + col::MOD_START + mod_p_chunked::col::C, NUM_LIMBS);
    }
}

impl<F: Field> BaseAir<F> for MulCanonicalFullChunkedChip {
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

impl<AB: AirBuilder> Air<AB> for MulCanonicalFullChunkedChip
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
    a: &Field25519Element,
    b: &Field25519Element,
) {
    use super::carry_fold::NUM_POSITIONS as CF_POS;
    use super::carry_fold::col as cfc;
    use super::carry_fold::compute_carry_fold;
    use super::limb_assembly_chunked::NUM_OUTPUT_LIMBS as LA_L;
    use super::limb_assembly_chunked::compute_limb_assembly_chunked;
    use super::limb_assembly_chunked::populate_row_to as la_populate_to;
    use super::mul::compute_mul;

    let base = row_off + start_col;

    // Top-level a, b.
    for i in 0..NUM_LIMBS {
        values[base + col::A + i] = F::from_u64(a.limbs[i]);
        values[base + col::B + i] = F::from_u64(b.limbs[i]);
    }

    // MulPipelineChunked witness population.
    let mul_w = compute_mul(a, b);
    let fold_w = compute_carry_fold(&mul_w.out_positions);
    let ovf = fold_w.carries[CF_POS - 1];
    let assembly_w = compute_limb_assembly_chunked(&fold_w.canonical, ovf);

    // a/b/L cells of MulPipelineChunked.
    for i in 0..NUM_LIMBS {
        values[base + col::PIPE_START + mul_pipeline_chunked::col::A + i] = F::from_u64(a.limbs[i]);
        values[base + col::PIPE_START + mul_pipeline_chunked::col::B + i] = F::from_u64(b.limbs[i]);
    }
    for i in 0..LA_L {
        values[base + col::PIPE_START + mul_pipeline_chunked::col::L + i] = F::from_u64(assembly_w.l[i]);
    }
    // MulChip witness.
    super::mul::populate_row::<F>(values, base + col::PIPE_START + mul_pipeline_chunked::col::MUL_START, a, b, &mul_w);
    // CarryFoldChip witness.
    {
        use super::carry_fold::{CANONICAL_BITS as CF_CAN_BITS, CARRY_BITS as CF_CARRY_BITS};
        for i in 0..CF_POS {
            values[base + col::PIPE_START + mul_pipeline_chunked::col::CARRY_FOLD_START + cfc::POS + i] =
                F::from_u64(mul_w.out_positions[i]);
            values[base + col::PIPE_START + mul_pipeline_chunked::col::CARRY_FOLD_START + cfc::CAN + i] =
                F::from_u64(fold_w.canonical[i]);
            values[base + col::PIPE_START + mul_pipeline_chunked::col::CARRY_FOLD_START + cfc::CARRY + i] =
                F::from_u64(fold_w.carries[i]);
            crate::chips::lookup::range_n::RangeNChip::<CF_CAN_BITS>::populate_bits::<F>(
                values,
                base + col::PIPE_START + mul_pipeline_chunked::col::CARRY_FOLD_START + cfc::CAN_BITS_BASE + i * CF_CAN_BITS,
                fold_w.canonical[i],
            );
            crate::chips::lookup::range_n::RangeNChip::<CF_CARRY_BITS>::populate_bits::<F>(
                values,
                base + col::PIPE_START + mul_pipeline_chunked::col::CARRY_FOLD_START + cfc::CARRY_BITS_BASE + i * CF_CARRY_BITS,
                fold_w.carries[i],
            );
        }
    }
    // LimbAssemblyChunked witness.
    la_populate_to::<F>(values, base + col::PIPE_START + mul_pipeline_chunked::col::LIMB_ASSEMBLY_START, &assembly_w);

    // ModPChunked witness population.
    mod_p_chunked::populate_row::<F>(values, row_off, start_col + col::MOD_START, &assembly_w.l);

    // Copy ModPChunked.C to top-level C.
    for i in 0..NUM_LIMBS {
        let mp_c = values[base + col::MOD_START + mod_p_chunked::col::C + i];
        values[base + col::C + i] = mp_c;
    }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(a: &Field25519Element, b: &Field25519Element) -> RowMajorMatrix<F> {
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
    use super::super::P_LIMBS;
    use super::super::arith::field_mul;
    use super::*;
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
    fn mul_full_chunked_zero() {
        let trace = build_test_trace::<BabyBear>(&Field25519Element::ZERO, &Field25519Element::ZERO);
        check_constraints(&MulCanonicalFullChunkedChip::new(), &trace, &[]);
        assert_eq!(read_c(&trace.values), [0u64; NUM_LIMBS]);
    }

    #[test]
    fn mul_full_chunked_three_times_seven() {
        let trace = build_test_trace::<BabyBear>(&small(3), &small(7));
        check_constraints(&MulCanonicalFullChunkedChip::new(), &trace, &[]);
        let mut expected = [0u64; NUM_LIMBS];
        expected[0] = 21;
        assert_eq!(read_c(&trace.values), expected);
    }

    #[test]
    fn mul_full_chunked_large_canonical_inputs() {
        let mut a = Field25519Element::ZERO;
        let mut b = Field25519Element::ZERO;
        for i in 0..NUM_LIMBS {
            a.limbs[i] = P_LIMBS[i] / 2;
            b.limbs[i] = P_LIMBS[i] / 3;
        }
        let expected = field_mul(&a, &b);
        let trace = build_test_trace::<BabyBear>(&a, &b);
        check_constraints(&MulCanonicalFullChunkedChip::new(), &trace, &[]);
        assert_eq!(read_c(&trace.values), expected.limbs);
    }

    #[test]
    fn mul_full_chunked_p_minus_1_squared() {
        let mut p_minus_1 = Field25519Element::ZERO;
        for i in 0..NUM_LIMBS {
            p_minus_1.limbs[i] = P_LIMBS[i];
        }
        p_minus_1.limbs[0] -= 1;
        let trace = build_test_trace::<BabyBear>(&p_minus_1, &p_minus_1);
        check_constraints(&MulCanonicalFullChunkedChip::new(), &trace, &[]);
        let mut expected = [0u64; NUM_LIMBS];
        expected[0] = 1;
        assert_eq!(read_c(&trace.values), expected);
    }

    #[test]
    fn mul_full_chunked_cross_validates_with_arith() {
        let cases: Vec<(Field25519Element, Field25519Element)> = vec![
            (small(0xCAFE), small(0xBABE)),
            (small(0x1EAD_BEEF), small(0x0EDC_BA98)), // < 2^30 to fit limb 0
            (small(2), small(3)),
        ];
        for (a, b) in cases {
            let expected = field_mul(&a, &b);
            let trace = build_test_trace::<BabyBear>(&a, &b);
            check_constraints(&MulCanonicalFullChunkedChip::new(), &trace, &[]);
            assert_eq!(read_c(&trace.values), expected.limbs);
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn mul_full_chunked_rejects_tampered() {
        let mut trace = build_test_trace::<BabyBear>(&small(7), &small(13));
        trace.values[col::C] += BabyBear::from_u64(1);
        check_constraints(&MulCanonicalFullChunkedChip::new(), &trace, &[]);
    }

    #[test]
    fn layout_documented() {
        assert_eq!(col::A, 0);
        assert_eq!(col::B, 9);
        assert_eq!(col::C, 18);
        assert_eq!(col::PIPE_START, 27);
        assert!(col::MOD_START > col::PIPE_START);
        assert!(NUM_COLS > col::MOD_START);
    }
}
