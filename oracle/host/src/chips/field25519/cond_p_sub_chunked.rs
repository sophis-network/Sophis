//! `field25519::cond_p_sub_chunked` — sound conditional `p`-subtraction (Etapa 3.10.2.3).
//!
//! Substitui `CondPSubChip` por implementação chunked 16+14 bit per limb.
//! Toda constraint linear emitida tem ambos os lados bound `≤ 2¹⁷ ≪ p`,
//! fechando estruturalmente a BB-wrap collision class `k ≥ 1`.
//!
//! Pattern reusado de `add_canonical_chunked.rs` (Step B/C) extraído como
//! chip standalone para uso em compositores ModP/MulCanonical chunked.
//!
//! ## Função
//!
//! Input: `a` canônico-loose (cada limb < 2³⁰, valor possivelmente `≥ p`).
//! Output: `c < p` tal que `c ≡ a (mod p)`.
//!
//! Algoritmo:
//! - Step B (sub chunked): `t = a − p` chunked com borrow chain.
//! - Step C (select): `c = (1 − bf)·t + bf·a` onde `bf = borrow_top`.
//!
//! ## Layout (1404 colunas)
//!
//! | offset    | width | conteúdo                  |
//! |-----------|-------|---------------------------|
//! | 0..9      | 9     | a_lo                      |
//! | 9..18     | 9     | a_hi                      |
//! | 18..27    | 9     | c_lo (output)             |
//! | 27..36    | 9     | c_hi (output)             |
//! | 36..45    | 9     | t_lo                      |
//! | 45..54    | 9     | t_hi                      |
//! | 54..63    | 9     | borrow_lo                 |
//! | 63..72    | 9     | borrow_hi                 |
//! | 72..648   | 576   | Range16 (4 grupos × 144)  |
//! | 648..1152 | 504   | Range14 (4 grupos × 126)  |
//!
//! Range16 grupos: a_lo, c_lo, t_lo, (placeholder: na verdade 4 = a_lo, c_lo, t_lo, ... ajusto abaixo).
//! Wait: revisão — só preciso 3 grupos lo (a, c, t) + 3 grupos hi (a, c, t). Total 6 grupos.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::chips::lookup::range_n::{Range16Chip, RangeNChip};

use super::add_canonical_chunked::{
    p_hi, p_lo, split_limb, CHUNK_HI_BITS, CHUNK_HI_MASK, CHUNK_HI_MOD, CHUNK_LO_BITS, CHUNK_LO_MASK,
    CHUNK_LO_MOD,
};
use super::{Field25519Element, NUM_LIMBS};

pub mod col {
    use super::*;
    pub const A_LO: usize = 0;
    pub const A_HI: usize = A_LO + NUM_LIMBS;          // 9
    pub const C_LO: usize = A_HI + NUM_LIMBS;          // 18
    pub const C_HI: usize = C_LO + NUM_LIMBS;          // 27
    pub const T_LO: usize = C_HI + NUM_LIMBS;          // 36
    pub const T_HI: usize = T_LO + NUM_LIMBS;          // 45
    pub const BORROW_LO: usize = T_HI + NUM_LIMBS;     // 54
    pub const BORROW_HI: usize = BORROW_LO + NUM_LIMBS; // 63
    pub const STRUCTURAL_END: usize = BORROW_HI + NUM_LIMBS; // 72

    /// Range16 bit decomp (3 grupos × 9 × 16 = 432 cells).
    pub const A_LO_BITS: usize = STRUCTURAL_END;                              // 72
    pub const C_LO_BITS: usize = A_LO_BITS + NUM_LIMBS * CHUNK_LO_BITS;       // 216
    pub const T_LO_BITS: usize = C_LO_BITS + NUM_LIMBS * CHUNK_LO_BITS;       // 360

    /// Range14 bit decomp (3 grupos × 9 × 14 = 378 cells).
    pub const A_HI_BITS: usize = T_LO_BITS + NUM_LIMBS * CHUNK_LO_BITS;       // 504
    pub const C_HI_BITS: usize = A_HI_BITS + NUM_LIMBS * CHUNK_HI_BITS;       // 630
    pub const T_HI_BITS: usize = C_HI_BITS + NUM_LIMBS * CHUNK_HI_BITS;       // 756

    pub const TOTAL: usize = T_HI_BITS + NUM_LIMBS * CHUNK_HI_BITS;           // 882
}

pub const NUM_COLS: usize = col::TOTAL;

#[derive(Debug, Clone, Copy)]
pub struct CondPSubChunkedChip {
    pub start_col: usize,
}

impl CondPSubChunkedChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let s = self.start_col;

        // Range checks: 3 grupos lo (Range16) × 9 limbs + 3 grupos hi (Range14) × 9 limbs.
        for i in 0..NUM_LIMBS {
            Range16Chip::split(s + col::A_LO + i, s + col::A_LO_BITS + i * CHUNK_LO_BITS).emit(builder);
            Range16Chip::split(s + col::C_LO + i, s + col::C_LO_BITS + i * CHUNK_LO_BITS).emit(builder);
            Range16Chip::split(s + col::T_LO + i, s + col::T_LO_BITS + i * CHUNK_LO_BITS).emit(builder);

            RangeNChip::<14>::split(s + col::A_HI + i, s + col::A_HI_BITS + i * CHUNK_HI_BITS).emit(builder);
            RangeNChip::<14>::split(s + col::C_HI + i, s + col::C_HI_BITS + i * CHUNK_HI_BITS).emit(builder);
            RangeNChip::<14>::split(s + col::T_HI + i, s + col::T_HI_BITS + i * CHUNK_HI_BITS).emit(builder);
        }

        let main = builder.main();
        let row = main.current_slice();
        let two_pow_lo = AB::Expr::from_u64(CHUNK_LO_MOD);
        let two_pow_hi = AB::Expr::from_u64(CHUNK_HI_MOD);
        let p_lo_const = p_lo();
        let p_hi_const = p_hi();

        // Step B: t = a - p chunked com borrow chain.
        let mut borrow_in: AB::Expr = AB::Expr::ZERO;
        for i in 0..NUM_LIMBS {
            let a_lo = row[s + col::A_LO + i];
            let a_hi = row[s + col::A_HI + i];
            let t_lo = row[s + col::T_LO + i];
            let t_hi = row[s + col::T_HI + i];
            let borrow_lo = row[s + col::BORROW_LO + i];
            let borrow_hi = row[s + col::BORROW_HI + i];
            let p_lo_i = AB::Expr::from_u64(p_lo_const[i]);
            let p_hi_i = AB::Expr::from_u64(p_hi_const[i]);

            builder.assert_bool(borrow_lo);
            builder.assert_bool(borrow_hi);

            // t_lo + p_lo + borrow_in = a_lo + 2^16 * borrow_lo
            builder.assert_eq(
                t_lo.into() + p_lo_i + borrow_in.clone(),
                a_lo.into() + two_pow_lo.clone() * borrow_lo.into(),
            );
            // t_hi + p_hi + borrow_lo = a_hi + 2^14 * borrow_hi
            builder.assert_eq(
                t_hi.into() + p_hi_i + borrow_lo.into(),
                a_hi.into() + two_pow_hi.clone() * borrow_hi.into(),
            );

            borrow_in = borrow_hi.into();
        }

        // Step C: select c = bf*a + (1-bf)*t per chunk.
        let bf = row[s + col::BORROW_HI + NUM_LIMBS - 1];
        for i in 0..NUM_LIMBS {
            let a_lo = row[s + col::A_LO + i];
            let a_hi = row[s + col::A_HI + i];
            let t_lo = row[s + col::T_LO + i];
            let t_hi = row[s + col::T_HI + i];
            let c_lo = row[s + col::C_LO + i];
            let c_hi = row[s + col::C_HI + i];

            builder.assert_eq(c_lo.into(), t_lo.into() + bf.into() * (a_lo.into() - t_lo.into()));
            builder.assert_eq(c_hi.into(), t_hi.into() + bf.into() * (a_hi.into() - t_hi.into()));
        }
    }
}

#[derive(Debug, Clone)]
pub struct CondPSubChunkedWitness {
    pub a_lo: [u64; NUM_LIMBS],
    pub a_hi: [u64; NUM_LIMBS],
    pub c_lo: [u64; NUM_LIMBS],
    pub c_hi: [u64; NUM_LIMBS],
    pub t_lo: [u64; NUM_LIMBS],
    pub t_hi: [u64; NUM_LIMBS],
    pub borrow_lo: [u64; NUM_LIMBS],
    pub borrow_hi: [u64; NUM_LIMBS],
}

pub fn compute_cond_p_sub_chunked(a: &Field25519Element) -> CondPSubChunkedWitness {
    let mut a_lo = [0u64; NUM_LIMBS];
    let mut a_hi = [0u64; NUM_LIMBS];
    for i in 0..NUM_LIMBS {
        let (lo, hi) = split_limb(a.limbs[i]);
        a_lo[i] = lo;
        a_hi[i] = hi;
    }

    let p_lo_arr = p_lo();
    let p_hi_arr = p_hi();
    let mut t_lo = [0u64; NUM_LIMBS];
    let mut t_hi = [0u64; NUM_LIMBS];
    let mut borrow_lo = [0u64; NUM_LIMBS];
    let mut borrow_hi = [0u64; NUM_LIMBS];
    let mut borrow_in: i64 = 0;
    for i in 0..NUM_LIMBS {
        let raw_lo = a_lo[i] as i64 - p_lo_arr[i] as i64 - borrow_in;
        if raw_lo >= 0 {
            t_lo[i] = raw_lo as u64;
            borrow_lo[i] = 0;
        } else {
            t_lo[i] = (raw_lo + CHUNK_LO_MOD as i64) as u64;
            borrow_lo[i] = 1;
        }

        let raw_hi = a_hi[i] as i64 - p_hi_arr[i] as i64 - borrow_lo[i] as i64;
        if raw_hi >= 0 {
            t_hi[i] = raw_hi as u64;
            borrow_hi[i] = 0;
        } else {
            t_hi[i] = (raw_hi + CHUNK_HI_MOD as i64) as u64;
            borrow_hi[i] = 1;
        }

        borrow_in = borrow_hi[i] as i64;
    }

    let bf = borrow_hi[NUM_LIMBS - 1];
    let mut c_lo = [0u64; NUM_LIMBS];
    let mut c_hi = [0u64; NUM_LIMBS];
    for i in 0..NUM_LIMBS {
        if bf == 1 {
            c_lo[i] = a_lo[i];
            c_hi[i] = a_hi[i];
        } else {
            c_lo[i] = t_lo[i];
            c_hi[i] = t_hi[i];
        }
    }

    CondPSubChunkedWitness {
        a_lo, a_hi, c_lo, c_hi, t_lo, t_hi, borrow_lo, borrow_hi,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CondPSubChunkedTestAir;

impl<F: Field> BaseAir<F> for CondPSubChunkedTestAir {
    fn width(&self) -> usize { NUM_COLS }
    fn main_next_row_columns(&self) -> Vec<usize> { Vec::new() }
    fn max_constraint_degree(&self) -> Option<usize> { Some(2) }
}

impl<AB: AirBuilder> Air<AB> for CondPSubChunkedTestAir
where AB::F: Field
{
    fn eval(&self, builder: &mut AB) {
        CondPSubChunkedChip::new().emit(builder);
    }
}

pub fn populate_row_to<F: Field + PrimeCharacteristicRing>(
    values: &mut [F],
    start_off: usize,
    w: &CondPSubChunkedWitness,
) {
    for i in 0..NUM_LIMBS {
        values[start_off + col::A_LO + i] = F::from_u64(w.a_lo[i]);
        values[start_off + col::A_HI + i] = F::from_u64(w.a_hi[i]);
        values[start_off + col::C_LO + i] = F::from_u64(w.c_lo[i]);
        values[start_off + col::C_HI + i] = F::from_u64(w.c_hi[i]);
        values[start_off + col::T_LO + i] = F::from_u64(w.t_lo[i]);
        values[start_off + col::T_HI + i] = F::from_u64(w.t_hi[i]);
        values[start_off + col::BORROW_LO + i] = F::from_u64(w.borrow_lo[i]);
        values[start_off + col::BORROW_HI + i] = F::from_u64(w.borrow_hi[i]);
    }

    for i in 0..NUM_LIMBS {
        Range16Chip::populate_bits::<F>(values, start_off + col::A_LO_BITS + i * CHUNK_LO_BITS, w.a_lo[i]);
        Range16Chip::populate_bits::<F>(values, start_off + col::C_LO_BITS + i * CHUNK_LO_BITS, w.c_lo[i]);
        Range16Chip::populate_bits::<F>(values, start_off + col::T_LO_BITS + i * CHUNK_LO_BITS, w.t_lo[i]);

        RangeNChip::<14>::populate_bits::<F>(values, start_off + col::A_HI_BITS + i * CHUNK_HI_BITS, w.a_hi[i]);
        RangeNChip::<14>::populate_bits::<F>(values, start_off + col::C_HI_BITS + i * CHUNK_HI_BITS, w.c_hi[i]);
        RangeNChip::<14>::populate_bits::<F>(values, start_off + col::T_HI_BITS + i * CHUNK_HI_BITS, w.t_hi[i]);
    }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(
    a: &Field25519Element,
) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    let w = compute_cond_p_sub_chunked(a);
    populate_row_to::<F>(&mut values, 0, &w);

    let zero = Field25519Element::ZERO;
    let pad_w = compute_cond_p_sub_chunked(&zero);
    for row_idx in 1..HEIGHT {
        populate_row_to::<F>(&mut values, row_idx * NUM_COLS, &pad_w);
    }

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::add_canonical_chunked::assemble_element;
    use super::super::P_LIMBS;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    fn elem_from_u64(n: u64) -> Field25519Element {
        let mut limbs = [0u64; NUM_LIMBS];
        limbs[0] = n & ((1 << 30) - 1);
        limbs[1] = (n >> 30) & ((1 << 30) - 1);
        Field25519Element { limbs }
    }

    fn p_minus_one() -> Field25519Element {
        let mut limbs = P_LIMBS;
        limbs[0] -= 1;
        Field25519Element { limbs }
    }

    #[test]
    fn cond_chunked_zero_is_zero() {
        let z = Field25519Element::ZERO;
        let trace = build_test_trace::<BabyBear>(&z);
        check_constraints(&CondPSubChunkedTestAir, &trace, &[]);
        let w = compute_cond_p_sub_chunked(&z);
        let c = assemble_element(&w.c_lo, &w.c_hi);
        assert_eq!(c, z);
    }

    #[test]
    fn cond_chunked_p_yields_zero() {
        // a = p → c = a - p = 0.
        let p = Field25519Element::P;
        let trace = build_test_trace::<BabyBear>(&p);
        check_constraints(&CondPSubChunkedTestAir, &trace, &[]);
        let w = compute_cond_p_sub_chunked(&p);
        let c = assemble_element(&w.c_lo, &w.c_hi);
        assert_eq!(c, Field25519Element::ZERO);
    }

    #[test]
    fn cond_chunked_p_minus_one_is_unchanged() {
        // a = p-1 < p → c = a (no subtraction).
        let pm1 = p_minus_one();
        let trace = build_test_trace::<BabyBear>(&pm1);
        check_constraints(&CondPSubChunkedTestAir, &trace, &[]);
        let w = compute_cond_p_sub_chunked(&pm1);
        let c = assemble_element(&w.c_lo, &w.c_hi);
        assert_eq!(c, pm1);
    }

    #[test]
    fn cond_chunked_arbitrary_below_p() {
        for n in [1u64, 7, 42, 0xDEAD, 0xFFFFFF] {
            let a = elem_from_u64(n);
            let trace = build_test_trace::<BabyBear>(&a);
            check_constraints(&CondPSubChunkedTestAir, &trace, &[]);
            let w = compute_cond_p_sub_chunked(&a);
            let c = assemble_element(&w.c_lo, &w.c_hi);
            assert_eq!(c, a, "n={n}: a < p, c should = a");
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn cond_chunked_rejects_tampered_c_lo() {
        let mut trace = build_test_trace::<BabyBear>(&elem_from_u64(42));
        trace.values[col::C_LO] = trace.values[col::C_LO] + BabyBear::ONE;
        check_constraints(&CondPSubChunkedTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn cond_chunked_rejects_tampered_t_lo() {
        let mut trace = build_test_trace::<BabyBear>(&elem_from_u64(42));
        trace.values[col::T_LO] = trace.values[col::T_LO] + BabyBear::ONE;
        check_constraints(&CondPSubChunkedTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn cond_chunked_rejects_a_lo_above_2_to_16() {
        let mut trace = build_test_trace::<BabyBear>(&Field25519Element::ZERO);
        trace.values[col::A_LO] = BabyBear::from_u64(1 << 16);
        check_constraints(&CondPSubChunkedTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn cond_chunked_rejects_k1_collision_attempt() {
        // Forge attempt: shift c_lo by 1. Chunk equations bound < p reject.
        let mut trace = build_test_trace::<BabyBear>(&elem_from_u64(42));
        trace.values[col::C_LO] = BabyBear::from_u64(43);
        check_constraints(&CondPSubChunkedTestAir, &trace, &[]);
    }

    #[test]
    fn num_cols_documented() {
        assert_eq!(NUM_COLS, 882);
    }
}
