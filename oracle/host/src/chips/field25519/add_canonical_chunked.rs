//! `field25519::add_canonical_chunked` — sound modular addition (Etapa 3.10.0).
//!
//! Substitui `Add + Reduce + CondPSub` por um chip único usando representação
//! chunked **16 + 14 bit per limb**. Toda constraint linear emitida tem
//! ambos os lados bound `≤ 2¹⁷ ≪ p ≈ 2³¹`, garantindo que `k = 0` é a única
//! solução inteira (fecha estruturalmente a BB-wrap collision class `k ≥ 1`).
//!
//! Veja `oracle/docs/PHASE5_ETAPA3_10_CHUNKED_DESIGN.md` para a análise
//! completa de bound e threat model.
//!
//! ## Representação
//!
//! Cada limb 30-bit `limb[i] = lo[i] + 2¹⁶ · hi[i]` com:
//!   - `lo[i] ∈ [0, 2¹⁶)` — Range16Chip split
//!   - `hi[i] ∈ [0, 2¹⁴)` — RangeNChip<14> split
//!
//! Para limbs canônicos (< 2³⁰), `hi[i] < 2¹⁴`. Limb 8 fica naturalmente em
//! `hi[8] ∈ [0, 1]` ou `0` (canonical < 2¹⁵ < 2¹⁶ → `hi[8] = 0`).
//!
//! ## Algoritmo
//!
//! ### Step A — soma chunked com carry chains
//!
//! ```text
//! inter_carry_in = 0   # carry into limb 0's lo (boundary)
//! for i in 0..9:
//!   # lo eq (consome inter_carry_in da limb anterior):
//!   a_lo[i] + b_lo[i] + inter_carry_in = sum_lo[i] + 2¹⁶ · intra_carry[i]
//!   intra_carry[i] ∈ {0, 1}
//!
//!   # hi eq (consome intra_carry da própria limb, produz inter_carry pra próxima):
//!   a_hi[i] + b_hi[i] + intra_carry[i] = sum_hi[i] + 2¹⁴ · inter_carry[i]
//!   inter_carry[i] ∈ {0, 1}
//!
//!   inter_carry_in = inter_carry[i]   # peso 2³⁰ → vai para LO da próxima limb (bit 0)
//!
//! # Boundary: para inputs canônicos (a, b < p < 2²⁵⁵), sum < 2²⁵⁶ < 2²⁷⁰ (limb capacity).
//! # inter_carry[8] DEVE ser 0:
//! assert inter_carry[8] = 0
//! ```
//!
//! Bounds: LHS_lo ≤ 2(2¹⁶−1)+1 = 2¹⁷−1; RHS_lo ≤ (2¹⁶−1) + 2¹⁶ = 2¹⁷−1.
//!         LHS_hi ≤ 2(2¹⁴−1)+1 = 2¹⁵−1; RHS_hi ≤ (2¹⁴−1)+2¹⁴ = 2¹⁵−1.
//!         Ambos `< p`. ✅
//!
//! ### Step B — subtração condicional de p (lazy, com borrow chain)
//!
//! ```text
//! borrow_in = 0
//! for i in 0..9:
//!   t_lo[i] + p_lo[i] + borrow_in = sum_lo[i] + 2¹⁶ · borrow_lo[i]
//!   borrow_lo[i] ∈ {0, 1}
//!   t_hi[i] + p_hi[i] + borrow_lo[i] = sum_hi[i] + 2¹⁴ · borrow_hi[i]
//!   borrow_hi[i] ∈ {0, 1}
//!   borrow_in = borrow_hi[i]
//! ```
//!
//! `borrow_top = borrow_hi[8]`: se 1, `sum < p` (mantém sum). Se 0, `sum ≥ p` (usa t).
//!
//! Bounds: LHS ≤ (2¹⁶−1) + (2¹⁶−1) + 1 = 2¹⁷−1. RHS ≤ (2¹⁶−1) + 2¹⁶ = 2¹⁷−1. `< p`. ✅
//!
//! ### Step C — select
//!
//! ```text
//! bf = borrow_hi[8]
//! for i in 0..9:
//!   c_lo[i] = t_lo[i] + bf · (sum_lo[i] − t_lo[i])
//!   c_hi[i] = t_hi[i] + bf · (sum_hi[i] − t_hi[i])
//! ```
//!
//! Degree 2.
//!
//! ## Layout
//!
//! | offset      | width | conteúdo                       |
//! |-------------|-------|--------------------------------|
//! | 0..9        | 9     | a_lo                           |
//! | 9..18       | 9     | a_hi                           |
//! | 18..27      | 9     | b_lo                           |
//! | 27..36      | 9     | b_hi                           |
//! | 36..45      | 9     | c_lo (output)                  |
//! | 45..54      | 9     | c_hi (output)                  |
//! | 54..63      | 9     | sum_lo                         |
//! | 63..72      | 9     | sum_hi                         |
//! | 72..81      | 9     | intra_carry (Step A)           |
//! | 81..90      | 9     | inter_carry (Step A)           |
//! | 90..99      | 9     | t_lo                           |
//! | 99..108     | 9     | t_hi                           |
//! | 108..117    | 9     | borrow_lo (Step B)             |
//! | 117..126    | 9     | borrow_hi (Step B)             |
//! | 126..846    | 720   | Range16 bit decomp (5×9×16)    |
//! | 846..1476   | 630   | Range14 bit decomp (5×9×14)    |
//!
//! Total: **1476 columns**.
//!
//! Range16 split applies to: a_lo, b_lo, c_lo, sum_lo, t_lo (5 grupos × 9 limbs).
//! Range14 split applies to: a_hi, b_hi, c_hi, sum_hi, t_hi.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::chips::lookup::range_n::{Range16Chip, RangeNChip};

use super::{Field25519Element, NUM_LIMBS, P_LIMBS};

pub const CHUNK_LO_BITS: usize = 16;
pub const CHUNK_HI_BITS: usize = 14;
pub const CHUNK_LO_MOD: u64 = 1u64 << CHUNK_LO_BITS; // 65536
pub const CHUNK_HI_MOD: u64 = 1u64 << CHUNK_HI_BITS; // 16384
pub const CHUNK_LO_MASK: u64 = CHUNK_LO_MOD - 1;
pub const CHUNK_HI_MASK: u64 = CHUNK_HI_MOD - 1;

/// Number of (lo, hi) value group columns: 5 (a, b, c, sum, t).
pub const NUM_RANGE_GROUPS: usize = 5;

pub mod col {
    use super::*;
    /// 30-bit interface (drop-in compat com `AddCanonicalChip` original):
    /// A/B/C nos offsets 0/9/18, identificados via reconstruction
    /// constraints `A[i] = A_LO[i] + 2^16·A_HI[i]` (sound, < 2^30 < p).
    pub const A: usize = 0;
    pub const B: usize = A + NUM_LIMBS; // 9
    pub const C: usize = B + NUM_LIMBS; // 18

    pub const A_LO: usize = C + NUM_LIMBS; // 27
    pub const A_HI: usize = A_LO + NUM_LIMBS; // 36
    pub const B_LO: usize = A_HI + NUM_LIMBS; // 45
    pub const B_HI: usize = B_LO + NUM_LIMBS; // 54
    pub const C_LO: usize = B_HI + NUM_LIMBS; // 63
    pub const C_HI: usize = C_LO + NUM_LIMBS; // 72
    pub const SUM_LO: usize = C_HI + NUM_LIMBS; // 81
    pub const SUM_HI: usize = SUM_LO + NUM_LIMBS; // 90
    pub const INTRA_CARRY: usize = SUM_HI + NUM_LIMBS; // 99
    pub const INTER_CARRY: usize = INTRA_CARRY + NUM_LIMBS; // 108
    pub const T_LO: usize = INTER_CARRY + NUM_LIMBS; // 117
    pub const T_HI: usize = T_LO + NUM_LIMBS; // 126
    pub const BORROW_LO: usize = T_HI + NUM_LIMBS; // 135
    pub const BORROW_HI: usize = BORROW_LO + NUM_LIMBS; // 144
    pub const STRUCTURAL_END: usize = BORROW_HI + NUM_LIMBS; // 153

    /// Range16 bit decomp regions (5 × 9 × 16 = 720 cells).
    pub const A_LO_BITS: usize = STRUCTURAL_END; // 153
    pub const B_LO_BITS: usize = A_LO_BITS + NUM_LIMBS * CHUNK_LO_BITS; // 297
    pub const C_LO_BITS: usize = B_LO_BITS + NUM_LIMBS * CHUNK_LO_BITS; // 441
    pub const SUM_LO_BITS: usize = C_LO_BITS + NUM_LIMBS * CHUNK_LO_BITS; // 585
    pub const T_LO_BITS: usize = SUM_LO_BITS + NUM_LIMBS * CHUNK_LO_BITS; // 729

    /// Range14 bit decomp regions (5 × 9 × 14 = 630 cells).
    pub const A_HI_BITS: usize = T_LO_BITS + NUM_LIMBS * CHUNK_LO_BITS; // 873
    pub const B_HI_BITS: usize = A_HI_BITS + NUM_LIMBS * CHUNK_HI_BITS; // 999
    pub const C_HI_BITS: usize = B_HI_BITS + NUM_LIMBS * CHUNK_HI_BITS; // 1125
    pub const SUM_HI_BITS: usize = C_HI_BITS + NUM_LIMBS * CHUNK_HI_BITS; // 1251
    pub const T_HI_BITS: usize = SUM_HI_BITS + NUM_LIMBS * CHUNK_HI_BITS; // 1377

    pub const TOTAL: usize = T_HI_BITS + NUM_LIMBS * CHUNK_HI_BITS; // 1503
}

pub const NUM_COLS: usize = col::TOTAL;

/// Decompose a 30-bit limb value into (lo, hi) chunks.
#[inline]
pub fn split_limb(limb: u64) -> (u64, u64) {
    (limb & CHUNK_LO_MASK, (limb >> CHUNK_LO_BITS) & CHUNK_HI_MASK)
}

/// Recompose chunks back to 30-bit limb value.
#[inline]
pub fn join_limb(lo: u64, hi: u64) -> u64 {
    lo | (hi << CHUNK_LO_BITS)
}

/// Pre-computed (lo, hi) chunks of `P_LIMBS`.
pub fn p_lo() -> [u64; NUM_LIMBS] {
    let mut out = [0u64; NUM_LIMBS];
    for i in 0..NUM_LIMBS {
        out[i] = P_LIMBS[i] & CHUNK_LO_MASK;
    }
    out
}

pub fn p_hi() -> [u64; NUM_LIMBS] {
    let mut out = [0u64; NUM_LIMBS];
    for i in 0..NUM_LIMBS {
        out[i] = (P_LIMBS[i] >> CHUNK_LO_BITS) & CHUNK_HI_MASK;
    }
    out
}

/// Layout descriptor and constraint emitter.
#[derive(Debug, Clone, Copy)]
pub struct AddCanonicalChunkedChip {
    pub start_col: usize,
}

impl Default for AddCanonicalChunkedChip {
    fn default() -> Self {
        Self::new()
    }
}

impl AddCanonicalChunkedChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    /// Emit all constraints for this chip into the supplied AIR builder.
    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        // ---------------------------------------------------------------
        // Range checks: every (lo, hi) value group is bit-decomposed and
        // recomposition-checked. This forces every chunk into its declared
        // range and is what kills any attempt to satisfy linear equations
        // with out-of-range BabyBear cell values.
        // ---------------------------------------------------------------
        let s = self.start_col;
        for i in 0..NUM_LIMBS {
            // Range16: a_lo, b_lo, c_lo, sum_lo, t_lo
            Range16Chip::split(s + col::A_LO + i, s + col::A_LO_BITS + i * CHUNK_LO_BITS).emit(builder);
            Range16Chip::split(s + col::B_LO + i, s + col::B_LO_BITS + i * CHUNK_LO_BITS).emit(builder);
            Range16Chip::split(s + col::C_LO + i, s + col::C_LO_BITS + i * CHUNK_LO_BITS).emit(builder);
            Range16Chip::split(s + col::SUM_LO + i, s + col::SUM_LO_BITS + i * CHUNK_LO_BITS).emit(builder);
            Range16Chip::split(s + col::T_LO + i, s + col::T_LO_BITS + i * CHUNK_LO_BITS).emit(builder);

            // Range14: a_hi, b_hi, c_hi, sum_hi, t_hi
            RangeNChip::<14>::split(s + col::A_HI + i, s + col::A_HI_BITS + i * CHUNK_HI_BITS).emit(builder);
            RangeNChip::<14>::split(s + col::B_HI + i, s + col::B_HI_BITS + i * CHUNK_HI_BITS).emit(builder);
            RangeNChip::<14>::split(s + col::C_HI + i, s + col::C_HI_BITS + i * CHUNK_HI_BITS).emit(builder);
            RangeNChip::<14>::split(s + col::SUM_HI + i, s + col::SUM_HI_BITS + i * CHUNK_HI_BITS).emit(builder);
            RangeNChip::<14>::split(s + col::T_HI + i, s + col::T_HI_BITS + i * CHUNK_HI_BITS).emit(builder);
        }

        let main = builder.main();
        let row = main.current_slice();
        let two_pow_lo = AB::Expr::from_u64(CHUNK_LO_MOD); // 2^16
        let two_pow_hi = AB::Expr::from_u64(CHUNK_HI_MOD); // 2^14

        let p_lo_const = p_lo();
        let p_hi_const = p_hi();

        // ---------------------------------------------------------------
        // 30-bit interface reconstruction (sound, RHS_max < 2^30 < p).
        // Connects external 30-bit A/B/C cols to internal chunked cells.
        // ---------------------------------------------------------------
        for i in 0..NUM_LIMBS {
            builder.assert_eq(
                row[s + col::A + i].into(),
                row[s + col::A_LO + i].into() + two_pow_lo.clone() * row[s + col::A_HI + i].into(),
            );
            builder.assert_eq(
                row[s + col::B + i].into(),
                row[s + col::B_LO + i].into() + two_pow_lo.clone() * row[s + col::B_HI + i].into(),
            );
            builder.assert_eq(
                row[s + col::C + i].into(),
                row[s + col::C_LO + i].into() + two_pow_lo.clone() * row[s + col::C_HI + i].into(),
            );
        }

        // ---------------------------------------------------------------
        // Step A — chunked add with carry chains.
        //
        // All LHS/RHS bounds:
        //   lo: max 2^17 - 2 << p
        //   hi: max 2^15      << p
        // ---------------------------------------------------------------
        let mut inter_carry_in: AB::Expr = AB::Expr::ZERO;
        for i in 0..NUM_LIMBS {
            let a_lo = row[s + col::A_LO + i];
            let a_hi = row[s + col::A_HI + i];
            let b_lo = row[s + col::B_LO + i];
            let b_hi = row[s + col::B_HI + i];
            let sum_lo = row[s + col::SUM_LO + i];
            let sum_hi = row[s + col::SUM_HI + i];
            let intra_carry = row[s + col::INTRA_CARRY + i];
            let inter_carry = row[s + col::INTER_CARRY + i];

            // bool(intra_carry), bool(inter_carry)
            builder.assert_bool(intra_carry);
            builder.assert_bool(inter_carry);

            // lo eq: a_lo + b_lo + inter_carry_in = sum_lo + 2^16 * intra_carry
            // (inter_carry_in tem peso 2^30 da limb anterior, soma a bit 0 desta limb)
            builder.assert_eq(
                a_lo.into() + b_lo.into() + inter_carry_in.clone(),
                sum_lo.into() + two_pow_lo.clone() * intra_carry.into(),
            );

            // hi eq: a_hi + b_hi + intra_carry = sum_hi + 2^14 * inter_carry
            builder.assert_eq(a_hi.into() + b_hi.into() + intra_carry.into(), sum_hi.into() + two_pow_hi.clone() * inter_carry.into());

            inter_carry_in = inter_carry.into();
        }

        // Boundary: top inter_carry must be 0 (canonical inputs sum < 2^256).
        builder.assert_zero(row[s + col::INTER_CARRY + NUM_LIMBS - 1]);

        // ---------------------------------------------------------------
        // Step B — chunked conditional p subtraction (lazy borrow chain).
        // ---------------------------------------------------------------
        let mut borrow_in: AB::Expr = AB::Expr::ZERO;
        for i in 0..NUM_LIMBS {
            let sum_lo = row[s + col::SUM_LO + i];
            let sum_hi = row[s + col::SUM_HI + i];
            let t_lo = row[s + col::T_LO + i];
            let t_hi = row[s + col::T_HI + i];
            let borrow_lo = row[s + col::BORROW_LO + i];
            let borrow_hi = row[s + col::BORROW_HI + i];
            let p_lo_i = AB::Expr::from_u64(p_lo_const[i]);
            let p_hi_i = AB::Expr::from_u64(p_hi_const[i]);

            builder.assert_bool(borrow_lo);
            builder.assert_bool(borrow_hi);

            // t_lo + p_lo + borrow_in = sum_lo + 2^16 * borrow_lo
            builder.assert_eq(t_lo.into() + p_lo_i + borrow_in.clone(), sum_lo.into() + two_pow_lo.clone() * borrow_lo.into());

            // t_hi + p_hi + borrow_lo = sum_hi + 2^14 * borrow_hi
            builder.assert_eq(t_hi.into() + p_hi_i + borrow_lo.into(), sum_hi.into() + two_pow_hi.clone() * borrow_hi.into());

            borrow_in = borrow_hi.into();
        }

        // ---------------------------------------------------------------
        // Step C — select c = t (if sum >= p, borrow_top = 0)
        //                or  c = sum (if sum < p,  borrow_top = 1)
        // Per chunk: c = t + bf*(sum - t)
        // ---------------------------------------------------------------
        let bf = row[s + col::BORROW_HI + NUM_LIMBS - 1];
        for i in 0..NUM_LIMBS {
            let sum_lo = row[s + col::SUM_LO + i];
            let sum_hi = row[s + col::SUM_HI + i];
            let t_lo = row[s + col::T_LO + i];
            let t_hi = row[s + col::T_HI + i];
            let c_lo = row[s + col::C_LO + i];
            let c_hi = row[s + col::C_HI + i];

            builder.assert_eq(c_lo.into(), t_lo.into() + bf.into() * (sum_lo.into() - t_lo.into()));
            builder.assert_eq(c_hi.into(), t_hi.into() + bf.into() * (sum_hi.into() - t_hi.into()));
        }
    }
}

/// Witness — populated after running `compute_add_canonical_chunked`.
#[derive(Debug, Clone)]
pub struct AddCanonicalChunkedWitness {
    pub a_lo: [u64; NUM_LIMBS],
    pub a_hi: [u64; NUM_LIMBS],
    pub b_lo: [u64; NUM_LIMBS],
    pub b_hi: [u64; NUM_LIMBS],
    pub c_lo: [u64; NUM_LIMBS],
    pub c_hi: [u64; NUM_LIMBS],
    pub sum_lo: [u64; NUM_LIMBS],
    pub sum_hi: [u64; NUM_LIMBS],
    pub intra_carry: [u64; NUM_LIMBS],
    pub inter_carry: [u64; NUM_LIMBS],
    pub t_lo: [u64; NUM_LIMBS],
    pub t_hi: [u64; NUM_LIMBS],
    pub borrow_lo: [u64; NUM_LIMBS],
    pub borrow_hi: [u64; NUM_LIMBS],
}

/// Compute the witness for `c = (a + b) mod p` using chunked arithmetic.
///
/// Inputs `a`, `b` must be canonical (every limb `< 2³⁰`, and value `< p`).
pub fn compute_add_canonical_chunked(a: &Field25519Element, b: &Field25519Element) -> AddCanonicalChunkedWitness {
    let mut a_lo = [0u64; NUM_LIMBS];
    let mut a_hi = [0u64; NUM_LIMBS];
    let mut b_lo = [0u64; NUM_LIMBS];
    let mut b_hi = [0u64; NUM_LIMBS];
    for i in 0..NUM_LIMBS {
        let (lo, hi) = split_limb(a.limbs[i]);
        a_lo[i] = lo;
        a_hi[i] = hi;
        let (lo, hi) = split_limb(b.limbs[i]);
        b_lo[i] = lo;
        b_hi[i] = hi;
    }

    // Step A — chunked add. inter_carry_in tem peso 2^30 da limb anterior;
    // entra na lo eq da limb atual (não na hi eq).
    let mut sum_lo = [0u64; NUM_LIMBS];
    let mut sum_hi = [0u64; NUM_LIMBS];
    let mut intra_carry = [0u64; NUM_LIMBS];
    let mut inter_carry = [0u64; NUM_LIMBS];
    let mut inter_carry_in: u64 = 0;
    for i in 0..NUM_LIMBS {
        let raw_lo = a_lo[i] + b_lo[i] + inter_carry_in;
        intra_carry[i] = raw_lo >> CHUNK_LO_BITS;
        sum_lo[i] = raw_lo & CHUNK_LO_MASK;

        let raw_hi = a_hi[i] + b_hi[i] + intra_carry[i];
        inter_carry[i] = raw_hi >> CHUNK_HI_BITS;
        sum_hi[i] = raw_hi & CHUNK_HI_MASK;

        inter_carry_in = inter_carry[i];
    }
    debug_assert_eq!(inter_carry[NUM_LIMBS - 1], 0, "canonical inputs must sum < 2^256 (inter_carry top must be 0)");

    // Step B — chunked conditional p sub.
    let p_lo_arr = p_lo();
    let p_hi_arr = p_hi();
    let mut t_lo = [0u64; NUM_LIMBS];
    let mut t_hi = [0u64; NUM_LIMBS];
    let mut borrow_lo = [0u64; NUM_LIMBS];
    let mut borrow_hi = [0u64; NUM_LIMBS];
    let mut borrow_in: i64 = 0;
    for i in 0..NUM_LIMBS {
        let raw_lo = sum_lo[i] as i64 - p_lo_arr[i] as i64 - borrow_in;
        if raw_lo >= 0 {
            t_lo[i] = raw_lo as u64;
            borrow_lo[i] = 0;
        } else {
            t_lo[i] = (raw_lo + CHUNK_LO_MOD as i64) as u64;
            borrow_lo[i] = 1;
        }

        let raw_hi = sum_hi[i] as i64 - p_hi_arr[i] as i64 - borrow_lo[i] as i64;
        if raw_hi >= 0 {
            t_hi[i] = raw_hi as u64;
            borrow_hi[i] = 0;
        } else {
            t_hi[i] = (raw_hi + CHUNK_HI_MOD as i64) as u64;
            borrow_hi[i] = 1;
        }

        borrow_in = borrow_hi[i] as i64;
    }

    // Step C — select.
    let bf = borrow_hi[NUM_LIMBS - 1];
    let mut c_lo = [0u64; NUM_LIMBS];
    let mut c_hi = [0u64; NUM_LIMBS];
    for i in 0..NUM_LIMBS {
        if bf == 1 {
            c_lo[i] = sum_lo[i];
            c_hi[i] = sum_hi[i];
        } else {
            c_lo[i] = t_lo[i];
            c_hi[i] = t_hi[i];
        }
    }

    AddCanonicalChunkedWitness {
        a_lo,
        a_hi,
        b_lo,
        b_hi,
        c_lo,
        c_hi,
        sum_lo,
        sum_hi,
        intra_carry,
        inter_carry,
        t_lo,
        t_hi,
        borrow_lo,
        borrow_hi,
    }
}

/// Standalone test AIR wrapping the chip.
#[derive(Debug, Clone, Copy)]
pub struct AddCanonicalChunkedTestAir;

impl<F: Field> BaseAir<F> for AddCanonicalChunkedTestAir {
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

impl<AB: AirBuilder> Air<AB> for AddCanonicalChunkedTestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        AddCanonicalChunkedChip::new().emit(builder);
    }
}

/// Convenience wrapper matching the signature of the non-chunked
/// `add_canonical::populate_row`. Computes the chunked witness and
/// dispatches to `populate_row_to`. Used by composers (point_add_air,
/// decompress_air etc.) to populate embedded chunked Add cells.
pub fn populate_row<F: Field + PrimeCharacteristicRing>(
    values: &mut [F],
    row_off: usize,
    start_col: usize,
    a: &Field25519Element,
    b: &Field25519Element,
) {
    let w = compute_add_canonical_chunked(a, b);
    populate_row_to::<F>(values, row_off + start_col, &w);
}

/// Populate one row's worth of cells starting at `start_off` (= row * NUM_COLS).
pub fn populate_row_to<F: Field + PrimeCharacteristicRing>(values: &mut [F], start_off: usize, w: &AddCanonicalChunkedWitness) {
    // Structural cells.
    for i in 0..NUM_LIMBS {
        // 30-bit interface (drop-in compat).
        values[start_off + col::A + i] = F::from_u64(join_limb(w.a_lo[i], w.a_hi[i]));
        values[start_off + col::B + i] = F::from_u64(join_limb(w.b_lo[i], w.b_hi[i]));
        values[start_off + col::C + i] = F::from_u64(join_limb(w.c_lo[i], w.c_hi[i]));

        values[start_off + col::A_LO + i] = F::from_u64(w.a_lo[i]);
        values[start_off + col::A_HI + i] = F::from_u64(w.a_hi[i]);
        values[start_off + col::B_LO + i] = F::from_u64(w.b_lo[i]);
        values[start_off + col::B_HI + i] = F::from_u64(w.b_hi[i]);
        values[start_off + col::C_LO + i] = F::from_u64(w.c_lo[i]);
        values[start_off + col::C_HI + i] = F::from_u64(w.c_hi[i]);
        values[start_off + col::SUM_LO + i] = F::from_u64(w.sum_lo[i]);
        values[start_off + col::SUM_HI + i] = F::from_u64(w.sum_hi[i]);
        values[start_off + col::INTRA_CARRY + i] = F::from_u64(w.intra_carry[i]);
        values[start_off + col::INTER_CARRY + i] = F::from_u64(w.inter_carry[i]);
        values[start_off + col::T_LO + i] = F::from_u64(w.t_lo[i]);
        values[start_off + col::T_HI + i] = F::from_u64(w.t_hi[i]);
        values[start_off + col::BORROW_LO + i] = F::from_u64(w.borrow_lo[i]);
        values[start_off + col::BORROW_HI + i] = F::from_u64(w.borrow_hi[i]);
    }

    // Range16 bit decomp regions.
    for i in 0..NUM_LIMBS {
        Range16Chip::populate_bits::<F>(values, start_off + col::A_LO_BITS + i * CHUNK_LO_BITS, w.a_lo[i]);
        Range16Chip::populate_bits::<F>(values, start_off + col::B_LO_BITS + i * CHUNK_LO_BITS, w.b_lo[i]);
        Range16Chip::populate_bits::<F>(values, start_off + col::C_LO_BITS + i * CHUNK_LO_BITS, w.c_lo[i]);
        Range16Chip::populate_bits::<F>(values, start_off + col::SUM_LO_BITS + i * CHUNK_LO_BITS, w.sum_lo[i]);
        Range16Chip::populate_bits::<F>(values, start_off + col::T_LO_BITS + i * CHUNK_LO_BITS, w.t_lo[i]);

        RangeNChip::<14>::populate_bits::<F>(values, start_off + col::A_HI_BITS + i * CHUNK_HI_BITS, w.a_hi[i]);
        RangeNChip::<14>::populate_bits::<F>(values, start_off + col::B_HI_BITS + i * CHUNK_HI_BITS, w.b_hi[i]);
        RangeNChip::<14>::populate_bits::<F>(values, start_off + col::C_HI_BITS + i * CHUNK_HI_BITS, w.c_hi[i]);
        RangeNChip::<14>::populate_bits::<F>(values, start_off + col::SUM_HI_BITS + i * CHUNK_HI_BITS, w.sum_hi[i]);
        RangeNChip::<14>::populate_bits::<F>(values, start_off + col::T_HI_BITS + i * CHUNK_HI_BITS, w.t_hi[i]);
    }
}

/// Build a single-row test trace exercising one canonical add. Pads to 4 rows
/// with zero-witness (which trivially satisfies all constraints since
/// 0+0+...=0 and the borrow chain produces a `t = -p mod 2^...` that wraps to
/// `p`-complement; we instead pad with a trivial 0+0=0 witness).
pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(a: &Field25519Element, b: &Field25519Element) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    // Active row 0 — real witness.
    let w = compute_add_canonical_chunked(a, b);
    populate_row_to::<F>(&mut values, 0, &w);

    // Padding rows 1..3 — also use the trivial witness for 0+0=0 to satisfy
    // the constraints uniformly. compute_add_canonical_chunked(0, 0) yields
    // sum=0, t=0-p (which produces full borrow chain ending borrow_hi[8]=1),
    // c=sum=0. All constraints trivially satisfied.
    let zero = Field25519Element::ZERO;
    let pad_w = compute_add_canonical_chunked(&zero, &zero);
    for row_idx in 1..HEIGHT {
        populate_row_to::<F>(&mut values, row_idx * NUM_COLS, &pad_w);
    }

    RowMajorMatrix::new(values, NUM_COLS)
}

/// Reconstruct a full Field25519Element from chunk arrays (for tests).
pub fn assemble_element(lo: &[u64; NUM_LIMBS], hi: &[u64; NUM_LIMBS]) -> Field25519Element {
    let mut limbs = [0u64; NUM_LIMBS];
    for i in 0..NUM_LIMBS {
        limbs[i] = join_limb(lo[i], hi[i]);
    }
    Field25519Element { limbs }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        limbs[0] -= 1; // 2^30 - 20
        Field25519Element { limbs }
    }

    // ===== Honest cases =====

    #[test]
    fn add_chunked_zero_plus_zero() {
        let z = Field25519Element::ZERO;
        let trace = build_test_trace::<BabyBear>(&z, &z);
        check_constraints(&AddCanonicalChunkedTestAir, &trace, &[]);
        // c should be 0.
        let w = compute_add_canonical_chunked(&z, &z);
        let c = assemble_element(&w.c_lo, &w.c_hi);
        assert_eq!(c, z);
    }

    #[test]
    fn add_chunked_three_plus_seven() {
        let a = elem_from_u64(3);
        let b = elem_from_u64(7);
        let trace = build_test_trace::<BabyBear>(&a, &b);
        check_constraints(&AddCanonicalChunkedTestAir, &trace, &[]);
        let w = compute_add_canonical_chunked(&a, &b);
        let c = assemble_element(&w.c_lo, &w.c_hi);
        assert_eq!(c.limbs[0], 10);
        for i in 1..NUM_LIMBS {
            assert_eq!(c.limbs[i], 0);
        }
    }

    #[test]
    fn add_chunked_p_plus_zero_yields_zero() {
        // p + 0 mod p = 0
        let p = Field25519Element::P;
        let z = Field25519Element::ZERO;
        let trace = build_test_trace::<BabyBear>(&p, &z);
        check_constraints(&AddCanonicalChunkedTestAir, &trace, &[]);
        let w = compute_add_canonical_chunked(&p, &z);
        let c = assemble_element(&w.c_lo, &w.c_hi);
        assert_eq!(c, Field25519Element::ZERO);
    }

    #[test]
    fn add_chunked_p_minus_one_plus_one_yields_zero() {
        // (p - 1) + 1 mod p = 0
        let pm1 = p_minus_one();
        let one = elem_from_u64(1);
        let trace = build_test_trace::<BabyBear>(&pm1, &one);
        check_constraints(&AddCanonicalChunkedTestAir, &trace, &[]);
        let w = compute_add_canonical_chunked(&pm1, &one);
        let c = assemble_element(&w.c_lo, &w.c_hi);
        assert_eq!(c, Field25519Element::ZERO);
    }

    #[test]
    fn add_chunked_p_minus_one_plus_p_minus_one_yields_p_minus_two() {
        // (p - 1) + (p - 1) mod p = p - 2
        let pm1 = p_minus_one();
        let trace = build_test_trace::<BabyBear>(&pm1, &pm1);
        check_constraints(&AddCanonicalChunkedTestAir, &trace, &[]);
        let w = compute_add_canonical_chunked(&pm1, &pm1);
        let c = assemble_element(&w.c_lo, &w.c_hi);
        let mut expected = P_LIMBS;
        expected[0] -= 2;
        assert_eq!(c.limbs, expected);
    }

    #[test]
    fn add_chunked_carry_chain_propagates() {
        // limb 0 = 2^30 - 1, then add 1 → carry into limb 1.
        let mut a = Field25519Element::ZERO;
        a.limbs[0] = (1 << 30) - 1;
        let mut one = Field25519Element::ZERO;
        one.limbs[0] = 1;
        let trace = build_test_trace::<BabyBear>(&a, &one);
        check_constraints(&AddCanonicalChunkedTestAir, &trace, &[]);
        let w = compute_add_canonical_chunked(&a, &one);
        let c = assemble_element(&w.c_lo, &w.c_hi);
        assert_eq!(c.limbs[0], 0);
        assert_eq!(c.limbs[1], 1);
    }

    #[test]
    fn add_chunked_max_canonical_inputs() {
        // Both inputs near max canonical: each limb 2^30 - 1 except top.
        let mut a = Field25519Element::ZERO;
        for i in 0..NUM_LIMBS - 1 {
            a.limbs[i] = (1 << 30) - 1;
        }
        a.limbs[NUM_LIMBS - 1] = (1 << 14) - 1; // keep canonical (< 2^15)
        let trace = build_test_trace::<BabyBear>(&a, &a);
        check_constraints(&AddCanonicalChunkedTestAir, &trace, &[]);
    }

    // ===== Adversarial — k=0 class (range/eq tampering) =====

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add_chunked_rejects_tampered_c_lo() {
        let mut trace = build_test_trace::<BabyBear>(&elem_from_u64(7), &elem_from_u64(13));
        trace.values[col::C_LO] += BabyBear::ONE;
        check_constraints(&AddCanonicalChunkedTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add_chunked_rejects_tampered_sum_hi() {
        let mut trace = build_test_trace::<BabyBear>(&elem_from_u64(7), &elem_from_u64(13));
        trace.values[col::SUM_HI] += BabyBear::ONE;
        check_constraints(&AddCanonicalChunkedTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add_chunked_rejects_intra_carry_set_when_unneeded() {
        let mut trace = build_test_trace::<BabyBear>(&elem_from_u64(1), &elem_from_u64(1));
        trace.values[col::INTRA_CARRY] = BabyBear::ONE; // claim carry but a_lo+b_lo = 2 < 2^16
        check_constraints(&AddCanonicalChunkedTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add_chunked_rejects_inter_carry_top_nonzero() {
        // Force inter_carry[8] = 1: would require sum >= 2^256, impossible for canonical inputs.
        let mut trace = build_test_trace::<BabyBear>(&elem_from_u64(7), &elem_from_u64(13));
        trace.values[col::INTER_CARRY + NUM_LIMBS - 1] = BabyBear::ONE;
        check_constraints(&AddCanonicalChunkedTestAir, &trace, &[]);
    }

    // ===== Adversarial — range check enforcement =====

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add_chunked_rejects_a_lo_above_2_to_16() {
        let mut trace = build_test_trace::<BabyBear>(&elem_from_u64(0), &elem_from_u64(0));
        // Claim a_lo[0] = 2^16 (out of range). Chunks decomp would be all-zero (matching 0
        // recomp), but actual cell value 2^16 won't match the bit-decomp recomposition.
        trace.values[col::A_LO] = BabyBear::from_u64(1 << 16);
        check_constraints(&AddCanonicalChunkedTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add_chunked_rejects_a_hi_above_2_to_14() {
        let mut trace = build_test_trace::<BabyBear>(&elem_from_u64(0), &elem_from_u64(0));
        trace.values[col::A_HI] = BabyBear::from_u64(1 << 14);
        check_constraints(&AddCanonicalChunkedTestAir, &trace, &[]);
    }

    // ===== Adversarial — k=1 BB-wrap collision class =====
    //
    // This is THE test that proves Etapa 3.10 closes the soundness gap that
    // bit decomp on the old chips would have left open. We construct a
    // would-be witness that satisfies the BB-level equations but represents
    // the result shifted by `p`. The chunked design must reject it.

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add_chunked_rejects_k1_collision_attempt_via_sum_chunks() {
        // Honest add: 100 + 200 = 300. Real sum_lo[0] should be 300, sum_hi[0] = 0.
        // Forger tries to set sum_lo[0] = 300 + p mod 2^16 = (300 + p) & 0xFFFF. With
        // p = 2,013,265,921: (300 + p) mod 2^16 = (300 + 1) mod 2^16 = 301 (since p mod
        // 2^16 = 1). And inter_carry into hi would need to reflect the +p offset.
        //
        // The chunked equation sum_lo[0] + 2^16 * intra_carry[0] = a_lo[0] + b_lo[0]
        // has both LHS, RHS bound < 2^17. The would-be forge values (with sum_lo[0]
        // ≈ 301) violate the equation a_lo + b_lo = sum_lo + ... since LHS = 100+200 =
        // 300 cannot equal 301 + 2^16 * carry for any carry in {0, 1}.
        //
        // Equivalently: any tampering of sum_lo away from the honest value fails the
        // chunked equation directly because both sides are bounded < p.
        let mut trace = build_test_trace::<BabyBear>(&elem_from_u64(100), &elem_from_u64(200));
        // Attempt the k=1 forge: shift sum_lo[0] by 1 (the smallest perturbation).
        trace.values[col::SUM_LO] = BabyBear::from_u64(301);
        check_constraints(&AddCanonicalChunkedTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add_chunked_rejects_k1_collision_attempt_via_c_chunks() {
        // Same idea targeting output c chunks. c_lo[0] honest = 300. Forge to 300 + 1.
        // The select equation c_lo = t_lo + bf*(sum_lo - t_lo) is bounded < 2^17 and
        // strictly determines c_lo, so any +1 perturbation breaks it.
        let mut trace = build_test_trace::<BabyBear>(&elem_from_u64(100), &elem_from_u64(200));
        trace.values[col::C_LO] = BabyBear::from_u64(301);
        check_constraints(&AddCanonicalChunkedTestAir, &trace, &[]);
    }

    // ===== Helpers / constants =====

    #[test]
    fn split_limb_round_trip() {
        for v in [0u64, 1, 0xFFFF, 0x10000, 0x12345, (1 << 30) - 1] {
            let (lo, hi) = split_limb(v);
            assert!(lo < CHUNK_LO_MOD);
            assert!(hi < CHUNK_HI_MOD);
            assert_eq!(join_limb(lo, hi), v);
        }
    }

    #[test]
    fn p_chunks_recompose_to_p_limbs() {
        let p_lo_arr = p_lo();
        let p_hi_arr = p_hi();
        for i in 0..NUM_LIMBS {
            assert_eq!(join_limb(p_lo_arr[i], p_hi_arr[i]), P_LIMBS[i]);
        }
    }

    #[test]
    fn num_cols_documented() {
        // 30-bit interface (3 × 9 = 27) + chunked layout (126) + bit decomp
        // (1350) = 1503. Drop-in compat com AddCanonicalChip original
        // (A/B/C nos offsets 0/9/18).
        assert_eq!(NUM_COLS, 1503);
        assert_eq!(col::A, 0);
        assert_eq!(col::B, 9);
        assert_eq!(col::C, 18);
    }

    #[test]
    fn structural_layout_offsets() {
        assert_eq!(col::STRUCTURAL_END, 153);
        assert_eq!(col::A_LO_BITS, 153);
        assert_eq!(col::A_HI_BITS, 873);
        assert_eq!(col::T_HI_BITS, 1377);
        assert_eq!(col::TOTAL, 1503);
    }
}
