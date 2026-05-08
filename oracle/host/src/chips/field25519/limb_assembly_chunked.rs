//! `field25519::limb_assembly_chunked` — sound limb assembly (Etapa 3.10.2.2).
//!
//! Substitui `LimbAssemblyChip` com:
//!   1. Range checks inline em `can[k]` e `ovf` (10-bit) — fecha gap standalone.
//!   2. Decomposição chunked 16+14 bit per output limb — produz output
//!      compatível com chunked downstream consumers.
//!
//! ## Soundness analysis (inputs canônicos)
//!
//! Constraint per output limb `k`:
//!   `L[k] = p0 + 2¹⁰·p1 + 2²⁰·p2`
//!
//! Com `p0/p1/p2 ∈ [0, 2¹⁰)` (range-checked aqui inline):
//!   - LHS = L[k]
//!   - RHS_max = (2¹⁰-1)·(1 + 2¹⁰ + 2²⁰) = 2³⁰ − 1
//!   - Both `< p ≈ 2³¹`. **Sound k=0 unique.** ✅
//!
//! Decomposição chunked `L[k] = L_lo[k] + 2¹⁶·L_hi[k]`:
//!   - L_lo[k] range-checked 16-bit
//!   - L_hi[k] range-checked 14-bit
//!   - LHS = L[k] ≤ 2³⁰ − 1
//!   - RHS_max = (2¹⁶-1) + 2¹⁶·(2¹⁴-1) = 2³⁰ − 1
//!   - Both `< p`. **Sound.** ✅
//!
//! ## Layout
//!
//! | offset      | width | conteúdo                              |
//! |-------------|-------|---------------------------------------|
//! | 0..53       | 53    | can — canonical positions (input)     |
//! | 53          | 1     | ovf — overflow (input)                |
//! | 54..72      | 18    | L — output 30-bit limbs (single cell) |
//! | 72..90      | 18    | L_lo — output chunks 16-bit           |
//! | 90..108     | 18    | L_hi — output chunks 14-bit           |
//! | 108..638    | 530   | Range10 bit decomp para can[0..53]    |
//! | 638..648    | 10    | Range10 bit decomp para ovf           |
//! | 648..936    | 288   | Range16 bit decomp para L_lo[0..18]   |
//! | 936..1188   | 252   | Range14 bit decomp para L_hi[0..18]   |
//!
//! Total: **1188 colunas**.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::add_canonical_chunked::{split_limb, CHUNK_HI_BITS, CHUNK_LO_BITS, CHUNK_LO_MOD};
use super::carry_fold::NUM_POSITIONS;
use super::mul::{PIECE_BITS, PIECE_MOD};
use crate::chips::lookup::range_n::{Range16Chip, RangeNChip};

pub const NUM_OUTPUT_LIMBS: usize = 18;

pub mod col {
    use super::*;
    pub const CAN: usize = 0;
    pub const OVF: usize = CAN + NUM_POSITIONS;       // 53
    pub const L: usize = OVF + 1;                      // 54
    pub const L_LO: usize = L + NUM_OUTPUT_LIMBS;     // 72
    pub const L_HI: usize = L_LO + NUM_OUTPUT_LIMBS;  // 90
    pub const STRUCTURAL_END: usize = L_HI + NUM_OUTPUT_LIMBS; // 108

    /// Range10 bit decomp para 53 can cells.
    pub const CAN_BITS: usize = STRUCTURAL_END;       // 108
    /// Range10 bit decomp para ovf.
    pub const OVF_BITS: usize = CAN_BITS + NUM_POSITIONS * PIECE_BITS; // 648
    /// Range16 bit decomp para L_lo.
    pub const L_LO_BITS: usize = OVF_BITS + PIECE_BITS;                // 658
    /// Range14 bit decomp para L_hi.
    pub const L_HI_BITS: usize = L_LO_BITS + NUM_OUTPUT_LIMBS * CHUNK_LO_BITS; // 946

    pub const TOTAL: usize = L_HI_BITS + NUM_OUTPUT_LIMBS * CHUNK_HI_BITS;     // 1198
}

pub const NUM_COLS: usize = col::TOTAL;

#[derive(Debug, Clone, Copy)]
pub struct LimbAssemblyChunkedChip {
    pub start_col: usize,
}

impl LimbAssemblyChunkedChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let s = self.start_col;

        // Range10 inline checks for can[0..53] e ovf — fecha gap standalone.
        for k in 0..NUM_POSITIONS {
            RangeNChip::<PIECE_BITS>::split(s + col::CAN + k, s + col::CAN_BITS + k * PIECE_BITS).emit(builder);
        }
        RangeNChip::<PIECE_BITS>::split(s + col::OVF, s + col::OVF_BITS).emit(builder);

        // Range checks no output chunked (16-bit lo, 14-bit hi).
        for k in 0..NUM_OUTPUT_LIMBS {
            Range16Chip::split(s + col::L_LO + k, s + col::L_LO_BITS + k * CHUNK_LO_BITS).emit(builder);
            RangeNChip::<14>::split(s + col::L_HI + k, s + col::L_HI_BITS + k * CHUNK_HI_BITS).emit(builder);
        }

        let main = builder.main();
        let row = main.current_slice();
        let two_pow_10 = AB::Expr::from_u64(PIECE_MOD);
        let two_pow_20 = AB::Expr::from_u64(PIECE_MOD * PIECE_MOD);
        let two_pow_16 = AB::Expr::from_u64(CHUNK_LO_MOD);

        // Recomposição L[k] = p0 + 2^10·p1 + 2^20·p2 (constraint original; sound com inputs range-checked).
        for k in 0..NUM_OUTPUT_LIMBS {
            let pos0 = 3 * k;
            let pos1 = 3 * k + 1;
            let pos2 = 3 * k + 2;

            let p0 = if pos0 < NUM_POSITIONS {
                row[s + col::CAN + pos0]
            } else {
                row[s + col::OVF]
            };
            let p1 = if pos1 < NUM_POSITIONS {
                row[s + col::CAN + pos1]
            } else if pos1 == NUM_POSITIONS {
                row[s + col::OVF]
            } else {
                row[s + col::CAN]
            };
            let p2 = if pos2 < NUM_POSITIONS {
                row[s + col::CAN + pos2]
            } else if pos2 == NUM_POSITIONS {
                row[s + col::OVF]
            } else {
                row[s + col::CAN]
            };

            let l_k = row[s + col::L + k];
            let recomp = p0.into() + two_pow_10.clone() * p1.into() + two_pow_20.clone() * p2.into();
            builder.assert_eq(l_k, recomp);

            // Decomposição chunked: L[k] = L_lo[k] + 2^16·L_hi[k]
            let l_lo = row[s + col::L_LO + k];
            let l_hi = row[s + col::L_HI + k];
            builder.assert_eq(l_k.into(), l_lo.into() + two_pow_16.clone() * l_hi.into());
        }
    }
}

#[derive(Debug, Clone)]
pub struct LimbAssemblyChunkedWitness {
    pub can: [u64; NUM_POSITIONS],
    pub ovf: u64,
    pub l: [u64; NUM_OUTPUT_LIMBS],
    pub l_lo: [u64; NUM_OUTPUT_LIMBS],
    pub l_hi: [u64; NUM_OUTPUT_LIMBS],
}

pub fn compute_limb_assembly_chunked(
    can: &[u64; NUM_POSITIONS],
    ovf: u64,
) -> LimbAssemblyChunkedWitness {
    let mut l = [0u64; NUM_OUTPUT_LIMBS];
    for k in 0..NUM_OUTPUT_LIMBS {
        let pos0 = 3 * k;
        let pos1 = 3 * k + 1;
        let pos2 = 3 * k + 2;

        let p0 = if pos0 < NUM_POSITIONS { can[pos0] } else { ovf };
        let p1 = if pos1 < NUM_POSITIONS { can[pos1] } else if pos1 == NUM_POSITIONS { ovf } else { 0 };
        let p2 = if pos2 < NUM_POSITIONS { can[pos2] } else if pos2 == NUM_POSITIONS { ovf } else { 0 };

        l[k] = p0 + (p1 << PIECE_BITS) + (p2 << (2 * PIECE_BITS));
    }

    let mut l_lo = [0u64; NUM_OUTPUT_LIMBS];
    let mut l_hi = [0u64; NUM_OUTPUT_LIMBS];
    for k in 0..NUM_OUTPUT_LIMBS {
        let (lo, hi) = split_limb(l[k]);
        l_lo[k] = lo;
        l_hi[k] = hi;
    }

    LimbAssemblyChunkedWitness { can: *can, ovf, l, l_lo, l_hi }
}

#[derive(Debug, Clone, Copy)]
pub struct LimbAssemblyChunkedTestAir;

impl<F: Field> BaseAir<F> for LimbAssemblyChunkedTestAir {
    fn width(&self) -> usize { NUM_COLS }
    fn main_next_row_columns(&self) -> Vec<usize> { Vec::new() }
    fn max_constraint_degree(&self) -> Option<usize> { Some(2) }
}

impl<AB: AirBuilder> Air<AB> for LimbAssemblyChunkedTestAir
where AB::F: Field
{
    fn eval(&self, builder: &mut AB) {
        LimbAssemblyChunkedChip::new().emit(builder);
    }
}

pub fn populate_row_to<F: Field + PrimeCharacteristicRing>(
    values: &mut [F],
    start_off: usize,
    w: &LimbAssemblyChunkedWitness,
) {
    for k in 0..NUM_POSITIONS {
        values[start_off + col::CAN + k] = F::from_u64(w.can[k]);
        RangeNChip::<PIECE_BITS>::populate_bits::<F>(values, start_off + col::CAN_BITS + k * PIECE_BITS, w.can[k]);
    }
    values[start_off + col::OVF] = F::from_u64(w.ovf);
    RangeNChip::<PIECE_BITS>::populate_bits::<F>(values, start_off + col::OVF_BITS, w.ovf);

    for k in 0..NUM_OUTPUT_LIMBS {
        values[start_off + col::L + k] = F::from_u64(w.l[k]);
        values[start_off + col::L_LO + k] = F::from_u64(w.l_lo[k]);
        values[start_off + col::L_HI + k] = F::from_u64(w.l_hi[k]);
        Range16Chip::populate_bits::<F>(values, start_off + col::L_LO_BITS + k * CHUNK_LO_BITS, w.l_lo[k]);
        RangeNChip::<14>::populate_bits::<F>(values, start_off + col::L_HI_BITS + k * CHUNK_HI_BITS, w.l_hi[k]);
    }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(
    can: &[u64; NUM_POSITIONS],
    ovf: u64,
) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    let w = compute_limb_assembly_chunked(can, ovf);
    populate_row_to::<F>(&mut values, 0, &w);

    let zeros = [0u64; NUM_POSITIONS];
    let pad_w = compute_limb_assembly_chunked(&zeros, 0);
    for row_idx in 1..HEIGHT {
        populate_row_to::<F>(&mut values, row_idx * NUM_COLS, &pad_w);
    }

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    #[test]
    fn limb_assembly_chunked_zero_input() {
        let can = [0u64; NUM_POSITIONS];
        let trace = build_test_trace::<BabyBear>(&can, 0);
        check_constraints(&LimbAssemblyChunkedTestAir, &trace, &[]);
        let w = compute_limb_assembly_chunked(&can, 0);
        for k in 0..NUM_OUTPUT_LIMBS {
            assert_eq!(w.l[k], 0);
            assert_eq!(w.l_lo[k], 0);
            assert_eq!(w.l_hi[k], 0);
        }
    }

    #[test]
    fn limb_assembly_chunked_known_pattern() {
        // can[0] = 1, can[3] = 2 → L[0] = 1, L[1] = 2.
        let mut can = [0u64; NUM_POSITIONS];
        can[0] = 1;
        can[3] = 2;
        let trace = build_test_trace::<BabyBear>(&can, 0);
        check_constraints(&LimbAssemblyChunkedTestAir, &trace, &[]);
        let w = compute_limb_assembly_chunked(&can, 0);
        assert_eq!(w.l[0], 1);
        assert_eq!(w.l[1], 2);
    }

    #[test]
    fn limb_assembly_chunked_max_canonical() {
        // All can[k] = 2^10 - 1, ovf = 2^10 - 1.
        let mut can = [0u64; NUM_POSITIONS];
        for k in 0..NUM_POSITIONS {
            can[k] = (1 << PIECE_BITS) - 1;
        }
        let ovf = (1 << PIECE_BITS) - 1;
        let trace = build_test_trace::<BabyBear>(&can, ovf);
        check_constraints(&LimbAssemblyChunkedTestAir, &trace, &[]);
        let w = compute_limb_assembly_chunked(&can, ovf);
        // L[0] = (2^10 - 1) * (1 + 2^10 + 2^20) ≈ 2^30 - 1.
        let expected = ((1u64 << PIECE_BITS) - 1) * (1 + (1u64 << PIECE_BITS) + (1u64 << (2 * PIECE_BITS)));
        assert_eq!(w.l[0], expected);
    }

    #[test]
    fn limb_assembly_chunked_ovf_used_at_top() {
        // L[17] = can[51] + 2^10·can[52] + 2^20·ovf.
        let mut can = [0u64; NUM_POSITIONS];
        can[51] = 100;
        can[52] = 200;
        let ovf = 7;
        let trace = build_test_trace::<BabyBear>(&can, ovf);
        check_constraints(&LimbAssemblyChunkedTestAir, &trace, &[]);
        let w = compute_limb_assembly_chunked(&can, ovf);
        let expected = 100u64 + (200u64 << PIECE_BITS) + (7u64 << (2 * PIECE_BITS));
        assert_eq!(w.l[17], expected);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn limb_assembly_chunked_rejects_can_above_2_to_10() {
        let mut can = [0u64; NUM_POSITIONS];
        let trace_init = build_test_trace::<BabyBear>(&can, 0);
        let mut trace = trace_init;
        trace.values[col::CAN] = BabyBear::from_u64(1 << 10);
        check_constraints(&LimbAssemblyChunkedTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn limb_assembly_chunked_rejects_ovf_above_2_to_10() {
        let can = [0u64; NUM_POSITIONS];
        let mut trace = build_test_trace::<BabyBear>(&can, 0);
        trace.values[col::OVF] = BabyBear::from_u64(1 << 10);
        check_constraints(&LimbAssemblyChunkedTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn limb_assembly_chunked_rejects_tampered_l() {
        let mut can = [0u64; NUM_POSITIONS];
        can[0] = 5;
        let mut trace = build_test_trace::<BabyBear>(&can, 0);
        trace.values[col::L] = trace.values[col::L] + BabyBear::ONE;
        check_constraints(&LimbAssemblyChunkedTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn limb_assembly_chunked_rejects_l_lo_l_hi_mismatch() {
        let mut can = [0u64; NUM_POSITIONS];
        can[0] = 5;
        let mut trace = build_test_trace::<BabyBear>(&can, 0);
        // Tamper L_lo: flip a bit. L_hi unchanged so recomp fails.
        trace.values[col::L_LO] = trace.values[col::L_LO] + BabyBear::ONE;
        check_constraints(&LimbAssemblyChunkedTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn limb_assembly_chunked_rejects_l_hi_above_2_to_14() {
        let can = [0u64; NUM_POSITIONS];
        let mut trace = build_test_trace::<BabyBear>(&can, 0);
        trace.values[col::L_HI] = BabyBear::from_u64(1 << 14);
        check_constraints(&LimbAssemblyChunkedTestAir, &trace, &[]);
    }

    #[test]
    fn num_cols_documented() {
        // STRUCTURAL_END(108) + CAN_BITS(530) + OVF_BITS(10) + L_LO_BITS(288) + L_HI_BITS(252) = 1188.
        assert_eq!(NUM_COLS, 1188);
    }
}
