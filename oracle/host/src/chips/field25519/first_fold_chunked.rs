//! `field25519::first_fold_chunked` — sound first-fold AIR (Etapa 3.10.2.0).
//!
//! Substitui `FirstFoldChip` fechando AS DUAS BB-wrap collision classes:
//!
//!   - **Constraint #3** (q-product split, original LHS_max ≈ 2⁵⁰):
//!     `low_30[k] + 2³⁰·high_20[k] = q_a + 2¹⁰·q_b + 2²⁰·q_c`
//!     forge surface enorme (~2¹⁹ classes). Closure: substituído por
//!     **5 equações de posição encadeadas com chunk_carry de 10 bits**,
//!     cada uma com LHS/RHS `< 2¹⁴ ≪ p ≈ 2³¹`.
//!
//!   - **Constraint #4** (per-output-limb chain, original LHS_max ≈ 2³¹):
//!     `out[m] + 2³⁰·carry[m+1] = V_lo[m] + low_30[m] + high_20[m-1] + carry[m]`
//!     RHS pode atingir ~2³¹ + 2²⁰, ultrapassando p por ~2²⁷ → forge k=1.
//!     Closure: **3 equações de posição por limb (10-bit chunks) + 4-bit
//!     out_chunk_carry**, cada uma com LHS/RHS `< 2¹³ ≪ p`.
//!
//! Wire format invariance preservada: `out[0..10]` (30-bit cols) continua
//! sendo a interface consumida pelo `mod_p_chip_full` / second_fold.
//!
//! ## Algoritmo (alinhado com `compute_first_fold`)
//!
//! ```text
//! L[0..18] = 18 30-bit limbs (input)
//! M = 19·2¹⁵ = 622592
//!
//! For each high limb k ∈ 0..9:
//!   piece_a, piece_b, piece_c = 10-bit decomp of L[k+9]
//!   q_a, q_b, q_c            = M·piece_a, M·piece_b, M·piece_c   (each < 2³⁰)
//!   q_a = qa[k][0] + 2¹⁰·qa[k][1] + 2²⁰·qa[k][2]                 (10-bit pieces)
//!   q_b, q_c idem
//!
//!   Position chain (10-bit chunked accum, carry chain):
//!     pos 0:  acc[k][0] + 2¹⁰·cc_q[k][0] = qa[0]
//!     pos 1:  acc[k][1] + 2¹⁰·cc_q[k][1] = qa[1] + qb[0] + cc_q[k][0]
//!     pos 2:  acc[k][2] + 2¹⁰·cc_q[k][2] = qa[2] + qb[1] + qc[0] + cc_q[k][1]
//!     pos 3:  acc[k][3] + 2¹⁰·cc_q[k][3] = qb[2] + qc[1] + cc_q[k][2]
//!     pos 4:  acc[k][4]                  = qc[2] + cc_q[k][3]
//!
//!   Identities (sound: LHS, RHS < 2³⁰ < p):
//!     low_30[k]  := acc[k][0] + 2¹⁰·acc[k][1] + 2²⁰·acc[k][2]
//!     high_20[k] := acc[k][3] + 2¹⁰·acc[k][4]
//!
//! For each output limb m ∈ 0..10:
//!   out_chunk[m][0..3] = 10-bit chunks of out[m]
//!   out[m] = out_chunk[m][0] + 2¹⁰·out_chunk[m][1] + 2²⁰·out_chunk[m][2]
//!
//!   Position chain:
//!     pos 0:  out_chunk[m][0] + 2¹⁰·cc_o[m][0] =
//!               L_pieces[m][0] (m<9) + acc[m][0] (m<9) + acc[m-1][3] (m≥1)
//!               + prev_inter
//!     pos 1:  out_chunk[m][1] + 2¹⁰·cc_o[m][1] =
//!               L_pieces[m][1] (m<9) + acc[m][1] (m<9) + acc[m-1][4] (m≥1)
//!               + cc_o[m][0]
//!     pos 2:  out_chunk[m][2] + 2¹⁰·cc_o[m][2] =
//!               L_pieces[m][2] (m<9) + acc[m][2] (m<9)
//!               + cc_o[m][1]
//!     prev_inter for m+1 = cc_o[m][2]
//! ```
//!
//! ## Bounds (sound)
//!
//! Q-product chain (per high limb k):
//!   pos 0 RHS_max = 2¹⁰−1 ≈ 2¹⁰
//!   pos 1 RHS_max = 2·(2¹⁰−1) + cc ≤ ~2¹¹
//!   pos 2 RHS_max = 3·(2¹⁰−1) + cc ≤ ~2¹²
//!   pos 3 RHS_max = 2·(2¹⁰−1) + cc ≤ ~2¹¹
//!   pos 4 RHS_max =      2¹⁰−1  + cc ≤ ~2¹⁰
//!   LHS_max ≤ (2¹⁰−1) + 2¹⁰·15 ≈ 2¹⁴
//!   Todos `≪ p ≈ 2³¹`. ✅ k=0 única solução estrutural.
//!
//! Output chain (per output limb m, per position):
//!   RHS_max ≤ 4·(2¹⁰−1) ≈ 2¹²
//!   LHS_max ≤ (2¹⁰−1) + 2¹⁰·15 ≈ 2¹⁴
//!   Todos `≪ p`. ✅ k=0 única solução estrutural.
//!
//! ## Layout
//!
//! | offset            | width | conteúdo                              |
//! |-------------------|-------|---------------------------------------|
//! | 0..18             | 18    | L (input, 30-bit cada)                |
//! | 18..72            | 54    | L_pieces (18 × 3 × 10-bit)            |
//! | 72..153           | 81    | q_pieces (9 high limbs × 9 × 10-bit)  |
//! | 153..198          | 45    | acc (9 × 5 × 10-bit)                  |
//! | 198..234          | 36    | q_chunk_carry (9 × 4 × 4-bit)         |
//! | 234..244          | 10    | out (output, 30-bit cada)             |
//! | 244..274          | 30    | out_chunk (10 × 3 × 10-bit)           |
//! | 274..304          | 30    | out_chunk_carry (10 × 3 × 4-bit)      |
//! | 304..844          | 540   | L_pieces bit decomp (54 × 10)         |
//! | 844..1654         | 810   | q_pieces bit decomp (81 × 10)         |
//! | 1654..2104        | 450   | acc bit decomp (45 × 10)              |
//! | 2104..2248        | 144   | q_chunk_carry bit decomp (36 × 4)     |
//! | 2248..2548        | 300   | out_chunk bit decomp (30 × 10)        |
//! | 2548..2668        | 120   | out_chunk_carry bit decomp (30 × 4)   |
//!
//! Total: **2668 columns**.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::mod_p::{FOLD_M, compute_first_fold};
use super::{LIMB_MOD, NUM_LIMBS};
use crate::chips::lookup::range_n::RangeNChip;

const NUM_INPUT_LIMBS: usize = 18;
const NUM_OUTPUT_LIMBS: usize = 10;
const NUM_HIGH: usize = 9;

const PIECE_BITS: usize = 10;
const PIECES_PER_LIMB: usize = 3; // 30 bits / 10 = 3 chunks
const Q_PIECES_PER_HIGH: usize = 9; // 3 q's × 3 pieces each
const ACC_PER_HIGH: usize = 5;
const Q_CARRY_PER_HIGH: usize = 4;
const Q_CARRY_BITWIDTH: usize = 4;

const OUT_CHUNKS_PER_LIMB: usize = 3;
const OUT_CARRY_PER_LIMB: usize = 3;
const OUT_CARRY_BITWIDTH: usize = 4;

const L_PIECES_TOTAL: usize = NUM_INPUT_LIMBS * PIECES_PER_LIMB; // 54
const Q_PIECES_TOTAL: usize = NUM_HIGH * Q_PIECES_PER_HIGH; // 81
const ACC_TOTAL: usize = NUM_HIGH * ACC_PER_HIGH; // 45
const Q_CARRY_TOTAL: usize = NUM_HIGH * Q_CARRY_PER_HIGH; // 36
const OUT_CHUNK_TOTAL: usize = NUM_OUTPUT_LIMBS * OUT_CHUNKS_PER_LIMB; // 30
const OUT_CARRY_TOTAL: usize = NUM_OUTPUT_LIMBS * OUT_CARRY_PER_LIMB; // 30

pub mod col {
    use super::*;
    pub const L: usize = 0;
    pub const L_PIECES: usize = L + NUM_INPUT_LIMBS; // 18
    pub const Q_PIECES: usize = L_PIECES + L_PIECES_TOTAL; // 72
    pub const ACC: usize = Q_PIECES + Q_PIECES_TOTAL; // 153
    pub const Q_CARRY: usize = ACC + ACC_TOTAL; // 198
    pub const OUT: usize = Q_CARRY + Q_CARRY_TOTAL; // 234
    pub const OUT_CHUNK: usize = OUT + NUM_OUTPUT_LIMBS; // 244
    pub const OUT_CARRY: usize = OUT_CHUNK + OUT_CHUNK_TOTAL; // 274
    pub const STRUCTURAL_END: usize = OUT_CARRY + OUT_CARRY_TOTAL; // 304

    /// Bit-decomposition regions.
    pub const L_PIECES_BITS: usize = STRUCTURAL_END; // 304
    pub const Q_PIECES_BITS: usize = L_PIECES_BITS + L_PIECES_TOTAL * PIECE_BITS; // 844
    pub const ACC_BITS: usize = Q_PIECES_BITS + Q_PIECES_TOTAL * PIECE_BITS; // 1654
    pub const Q_CARRY_BITS: usize = ACC_BITS + ACC_TOTAL * PIECE_BITS; // 2104
    pub const OUT_CHUNK_BITS: usize = Q_CARRY_BITS + Q_CARRY_TOTAL * Q_CARRY_BITWIDTH; // 2248
    pub const OUT_CARRY_BITS: usize = OUT_CHUNK_BITS + OUT_CHUNK_TOTAL * PIECE_BITS; // 2548

    pub const TOTAL: usize = OUT_CARRY_BITS + OUT_CARRY_TOTAL * OUT_CARRY_BITWIDTH; // 2668
}

pub const NUM_COLS: usize = col::TOTAL;

/// Layout descriptor and constraint emitter.
#[derive(Debug, Clone, Copy)]
pub struct FirstFoldChunkedChip {
    pub start_col: usize,
}

impl FirstFoldChunkedChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let s = self.start_col;
        let two_pow_10 = AB::Expr::from_u64(1u64 << PIECE_BITS); // 2^10
        let two_pow_20 = AB::Expr::from_u64(1u64 << (2 * PIECE_BITS)); // 2^20
        let two_pow_30 = AB::Expr::from_u64(LIMB_MOD); // 2^30
        let m_const = AB::Expr::from_u64(FOLD_M);

        // -----------------------------------------------------------------
        // Range checks: every 10-bit value chunk and every 4-bit carry
        // gets a bit-decomposition recomposition constraint. Without them
        // an adversary could BB-wrap any of the linear equations.
        // -----------------------------------------------------------------
        for i in 0..L_PIECES_TOTAL {
            RangeNChip::<PIECE_BITS>::split(
                s + col::L_PIECES + i,
                s + col::L_PIECES_BITS + i * PIECE_BITS,
            )
            .emit(builder);
        }
        for i in 0..Q_PIECES_TOTAL {
            RangeNChip::<PIECE_BITS>::split(
                s + col::Q_PIECES + i,
                s + col::Q_PIECES_BITS + i * PIECE_BITS,
            )
            .emit(builder);
        }
        for i in 0..ACC_TOTAL {
            RangeNChip::<PIECE_BITS>::split(
                s + col::ACC + i,
                s + col::ACC_BITS + i * PIECE_BITS,
            )
            .emit(builder);
        }
        for i in 0..Q_CARRY_TOTAL {
            RangeNChip::<Q_CARRY_BITWIDTH>::split(
                s + col::Q_CARRY + i,
                s + col::Q_CARRY_BITS + i * Q_CARRY_BITWIDTH,
            )
            .emit(builder);
        }
        for i in 0..OUT_CHUNK_TOTAL {
            RangeNChip::<PIECE_BITS>::split(
                s + col::OUT_CHUNK + i,
                s + col::OUT_CHUNK_BITS + i * PIECE_BITS,
            )
            .emit(builder);
        }
        for i in 0..OUT_CARRY_TOTAL {
            RangeNChip::<OUT_CARRY_BITWIDTH>::split(
                s + col::OUT_CARRY + i,
                s + col::OUT_CARRY_BITS + i * OUT_CARRY_BITWIDTH,
            )
            .emit(builder);
        }

        let main = builder.main();
        let row = main.current_slice();

        // -----------------------------------------------------------------
        // L_pieces decomposition: L[i] = p0 + 2^10·p1 + 2^20·p2.
        // Sound: RHS_max = (2^10-1)·(1+2^10+2^20) ≈ 2^30 < p.
        // -----------------------------------------------------------------
        for i in 0..NUM_INPUT_LIMBS {
            let l_i = row[s + col::L + i];
            let p0 = row[s + col::L_PIECES + 3 * i];
            let p1 = row[s + col::L_PIECES + 3 * i + 1];
            let p2 = row[s + col::L_PIECES + 3 * i + 2];
            builder.assert_eq(
                l_i,
                p0.into() + two_pow_10.clone() * p1.into() + two_pow_20.clone() * p2.into(),
            );
        }

        // -----------------------------------------------------------------
        // Per high limb k ∈ 0..9:
        //   - q-piece sum constraints:
        //       q_pieces[k][0..3]   = decomp of M·a_k   (a_k = L_pieces[k+9][0])
        //       q_pieces[k][3..6]   = decomp of M·b_k   (b_k = L_pieces[k+9][1])
        //       q_pieces[k][6..9]   = decomp of M·c_k   (c_k = L_pieces[k+9][2])
        //   Sound: M·(2^10-1) < 2^30 < p; piece sum < 2^30 < p.
        //
        //   - position chain (5 equations, RHS, LHS < 2^14 < p).
        //
        //   - low_30/high_20 are virtual (linear comb of acc), no extra cols.
        // -----------------------------------------------------------------
        for k in 0..NUM_HIGH {
            let a_k = row[s + col::L_PIECES + 3 * (NUM_LIMBS + k)];
            let b_k = row[s + col::L_PIECES + 3 * (NUM_LIMBS + k) + 1];
            let c_k = row[s + col::L_PIECES + 3 * (NUM_LIMBS + k) + 2];

            let qa0 = row[s + col::Q_PIECES + 9 * k];
            let qa1 = row[s + col::Q_PIECES + 9 * k + 1];
            let qa2 = row[s + col::Q_PIECES + 9 * k + 2];
            let qb0 = row[s + col::Q_PIECES + 9 * k + 3];
            let qb1 = row[s + col::Q_PIECES + 9 * k + 4];
            let qb2 = row[s + col::Q_PIECES + 9 * k + 5];
            let qc0 = row[s + col::Q_PIECES + 9 * k + 6];
            let qc1 = row[s + col::Q_PIECES + 9 * k + 7];
            let qc2 = row[s + col::Q_PIECES + 9 * k + 8];

            // q-piece sum identities: M·piece = p0 + 2^10·p1 + 2^20·p2.
            builder.assert_eq(
                m_const.clone() * a_k.into(),
                qa0.into() + two_pow_10.clone() * qa1.into() + two_pow_20.clone() * qa2.into(),
            );
            builder.assert_eq(
                m_const.clone() * b_k.into(),
                qb0.into() + two_pow_10.clone() * qb1.into() + two_pow_20.clone() * qb2.into(),
            );
            builder.assert_eq(
                m_const.clone() * c_k.into(),
                qc0.into() + two_pow_10.clone() * qc1.into() + two_pow_20.clone() * qc2.into(),
            );

            let acc0 = row[s + col::ACC + 5 * k];
            let acc1 = row[s + col::ACC + 5 * k + 1];
            let acc2 = row[s + col::ACC + 5 * k + 2];
            let acc3 = row[s + col::ACC + 5 * k + 3];
            let acc4 = row[s + col::ACC + 5 * k + 4];

            let cc0 = row[s + col::Q_CARRY + 4 * k];
            let cc1 = row[s + col::Q_CARRY + 4 * k + 1];
            let cc2 = row[s + col::Q_CARRY + 4 * k + 2];
            let cc3 = row[s + col::Q_CARRY + 4 * k + 3];

            // Position chain (5 equations, all bounds < 2^14 < p).
            // pos 0
            builder.assert_eq(
                acc0.into() + two_pow_10.clone() * cc0.into(),
                qa0.into(),
            );
            // pos 1
            builder.assert_eq(
                acc1.into() + two_pow_10.clone() * cc1.into(),
                qa1.into() + qb0.into() + cc0.into(),
            );
            // pos 2
            builder.assert_eq(
                acc2.into() + two_pow_10.clone() * cc2.into(),
                qa2.into() + qb1.into() + qc0.into() + cc1.into(),
            );
            // pos 3
            builder.assert_eq(
                acc3.into() + two_pow_10.clone() * cc3.into(),
                qb2.into() + qc1.into() + cc2.into(),
            );
            // pos 4 (final, no outgoing carry)
            builder.assert_eq(
                acc4.into(),
                qc2.into() + cc3.into(),
            );
        }

        // -----------------------------------------------------------------
        // out[m] = out_chunk[m][0] + 2^10·out_chunk[m][1] + 2^20·out_chunk[m][2].
        // Sound: LHS_max < 2^30 < p; RHS_max < 2^30 < p.
        // -----------------------------------------------------------------
        for m in 0..NUM_OUTPUT_LIMBS {
            let out_m = row[s + col::OUT + m];
            let oc0 = row[s + col::OUT_CHUNK + 3 * m];
            let oc1 = row[s + col::OUT_CHUNK + 3 * m + 1];
            let oc2 = row[s + col::OUT_CHUNK + 3 * m + 2];
            builder.assert_eq(
                out_m,
                oc0.into() + two_pow_10.clone() * oc1.into() + two_pow_20.clone() * oc2.into(),
            );
        }

        // -----------------------------------------------------------------
        // Per-output-limb chunked accumulation (3 positions × 10 limbs).
        //
        // Contributions per position p of limb m:
        //
        //   pos 0 (weight 2^0 within limb m):
        //     L_pieces[m][0]   if m < 9
        //     acc[m][0]        if m < 9   (low_30[m] chunk 0)
        //     acc[m-1][3]      if m ≥ 1   (high_20[m-1] chunk 0)
        //     prev_inter       (cc_o[m-1][2] for m ≥ 1, else 0)
        //
        //   pos 1 (weight 2^10):
        //     L_pieces[m][1]   if m < 9
        //     acc[m][1]        if m < 9
        //     acc[m-1][4]      if m ≥ 1
        //     cc_o[m][0]
        //
        //   pos 2 (weight 2^20):
        //     L_pieces[m][2]   if m < 9
        //     acc[m][2]        if m < 9
        //     cc_o[m][1]
        //
        // Bounds (per equation): RHS ≤ 4·(2^10-1) = ~2^12; LHS ≤ (2^10-1) +
        // 2^10·15 = ~2^14. Both ≪ p. ✅
        // -----------------------------------------------------------------
        let mut prev_inter: AB::Expr = AB::Expr::ZERO;
        for m in 0..NUM_OUTPUT_LIMBS {
            let oc0 = row[s + col::OUT_CHUNK + 3 * m];
            let oc1 = row[s + col::OUT_CHUNK + 3 * m + 1];
            let oc2 = row[s + col::OUT_CHUNK + 3 * m + 2];
            let cc_o0 = row[s + col::OUT_CARRY + 3 * m];
            let cc_o1 = row[s + col::OUT_CARRY + 3 * m + 1];
            let cc_o2 = row[s + col::OUT_CARRY + 3 * m + 2];

            // Position 0 RHS
            let mut rhs_p0: AB::Expr = prev_inter.clone();
            if m < NUM_LIMBS {
                rhs_p0 = rhs_p0 + row[s + col::L_PIECES + 3 * m].into();
            }
            if m < NUM_HIGH {
                rhs_p0 = rhs_p0 + row[s + col::ACC + 5 * m].into();
            }
            if m >= 1 && (m - 1) < NUM_HIGH {
                rhs_p0 = rhs_p0 + row[s + col::ACC + 5 * (m - 1) + 3].into();
            }
            builder.assert_eq(
                oc0.into() + two_pow_10.clone() * cc_o0.into(),
                rhs_p0,
            );

            // Position 1 RHS
            let mut rhs_p1: AB::Expr = cc_o0.into();
            if m < NUM_LIMBS {
                rhs_p1 = rhs_p1 + row[s + col::L_PIECES + 3 * m + 1].into();
            }
            if m < NUM_HIGH {
                rhs_p1 = rhs_p1 + row[s + col::ACC + 5 * m + 1].into();
            }
            if m >= 1 && (m - 1) < NUM_HIGH {
                rhs_p1 = rhs_p1 + row[s + col::ACC + 5 * (m - 1) + 4].into();
            }
            builder.assert_eq(
                oc1.into() + two_pow_10.clone() * cc_o1.into(),
                rhs_p1,
            );

            // Position 2 RHS
            let mut rhs_p2: AB::Expr = cc_o1.into();
            if m < NUM_LIMBS {
                rhs_p2 = rhs_p2 + row[s + col::L_PIECES + 3 * m + 2].into();
            }
            if m < NUM_HIGH {
                rhs_p2 = rhs_p2 + row[s + col::ACC + 5 * m + 2].into();
            }
            // No high_20 contribution at position 2 (high_20 has only 2 chunks).
            builder.assert_eq(
                oc2.into() + two_pow_10.clone() * cc_o2.into(),
                rhs_p2,
            );

            prev_inter = cc_o2.into();
        }

        // No boundary == 0: first_fold output has up to 10 limbs and the
        // final inter-limb carry can be > 0 (compositor `mod_p_chip_full`
        // performs additional fold passes to canonicalize).
        // The carry IS range-checked (4-bit, so ≤ 15), more than enough
        // for the real bound (≤ 4).
        let _ = two_pow_30;
    }
}

/// Witness for one `FirstFoldChunkedChip` row.
#[derive(Debug, Clone)]
pub struct FirstFoldChunkedWitness {
    pub l: [u64; NUM_INPUT_LIMBS],
    pub l_pieces: [u64; L_PIECES_TOTAL],
    pub q_pieces: [u64; Q_PIECES_TOTAL],
    pub acc: [u64; ACC_TOTAL],
    pub q_carry: [u64; Q_CARRY_TOTAL],
    pub out: [u64; NUM_OUTPUT_LIMBS],
    pub out_chunk: [u64; OUT_CHUNK_TOTAL],
    pub out_carry: [u64; OUT_CARRY_TOTAL],
}

/// Compute the chunked witness for `compute_first_fold(input)`.
pub fn compute_first_fold_chunked_witness(
    input: &[u64; NUM_INPUT_LIMBS],
) -> FirstFoldChunkedWitness {
    let mask_10 = (1u64 << PIECE_BITS) - 1;

    // L_pieces: 10-bit decomp of every input limb.
    let mut l_pieces = [0u64; L_PIECES_TOTAL];
    for i in 0..NUM_INPUT_LIMBS {
        l_pieces[3 * i] = input[i] & mask_10;
        l_pieces[3 * i + 1] = (input[i] >> PIECE_BITS) & mask_10;
        l_pieces[3 * i + 2] = (input[i] >> (2 * PIECE_BITS)) & mask_10;
    }

    let mut q_pieces = [0u64; Q_PIECES_TOTAL];
    let mut acc = [0u64; ACC_TOTAL];
    let mut q_carry = [0u64; Q_CARRY_TOTAL];

    // Q-product chain per high limb k.
    for k in 0..NUM_HIGH {
        let a = l_pieces[3 * (NUM_LIMBS + k)];
        let b = l_pieces[3 * (NUM_LIMBS + k) + 1];
        let c = l_pieces[3 * (NUM_LIMBS + k) + 2];

        let q_a = FOLD_M * a;
        let q_b = FOLD_M * b;
        let q_c = FOLD_M * c;

        let qa = [q_a & mask_10, (q_a >> PIECE_BITS) & mask_10, (q_a >> (2 * PIECE_BITS)) & mask_10];
        let qb = [q_b & mask_10, (q_b >> PIECE_BITS) & mask_10, (q_b >> (2 * PIECE_BITS)) & mask_10];
        let qc = [q_c & mask_10, (q_c >> PIECE_BITS) & mask_10, (q_c >> (2 * PIECE_BITS)) & mask_10];

        q_pieces[9 * k] = qa[0];
        q_pieces[9 * k + 1] = qa[1];
        q_pieces[9 * k + 2] = qa[2];
        q_pieces[9 * k + 3] = qb[0];
        q_pieces[9 * k + 4] = qb[1];
        q_pieces[9 * k + 5] = qb[2];
        q_pieces[9 * k + 6] = qc[0];
        q_pieces[9 * k + 7] = qc[1];
        q_pieces[9 * k + 8] = qc[2];

        // Position chain (5 positions, 10-bit chunks).
        let r0 = qa[0];
        acc[5 * k] = r0 & mask_10;
        let cc0 = r0 >> PIECE_BITS;

        let r1 = qa[1] + qb[0] + cc0;
        acc[5 * k + 1] = r1 & mask_10;
        let cc1 = r1 >> PIECE_BITS;

        let r2 = qa[2] + qb[1] + qc[0] + cc1;
        acc[5 * k + 2] = r2 & mask_10;
        let cc2 = r2 >> PIECE_BITS;

        let r3 = qb[2] + qc[1] + cc2;
        acc[5 * k + 3] = r3 & mask_10;
        let cc3 = r3 >> PIECE_BITS;

        let r4 = qc[2] + cc3;
        // r4 must fit in 10 bits — honest M·L_high < 2^49 ensures bit
        // 40..49 ≤ M·2^30/2^40 = M/2^10 < 2^10.
        debug_assert!(r4 < (1u64 << PIECE_BITS), "acc[k][4] overflow: r4={r4}");
        acc[5 * k + 4] = r4;

        q_carry[4 * k] = cc0;
        q_carry[4 * k + 1] = cc1;
        q_carry[4 * k + 2] = cc2;
        q_carry[4 * k + 3] = cc3;
    }

    // Output chain: 3 positions per limb × 10 limbs.
    let mut out_chunk = [0u64; OUT_CHUNK_TOTAL];
    let mut out_carry = [0u64; OUT_CARRY_TOTAL];
    let mut out = [0u64; NUM_OUTPUT_LIMBS];

    let mut prev_inter: u64 = 0;
    for m in 0..NUM_OUTPUT_LIMBS {
        // Position 0
        let mut rhs_p0 = prev_inter;
        if m < NUM_LIMBS {
            rhs_p0 += l_pieces[3 * m];
        }
        if m < NUM_HIGH {
            rhs_p0 += acc[5 * m];
        }
        if m >= 1 && (m - 1) < NUM_HIGH {
            rhs_p0 += acc[5 * (m - 1) + 3];
        }
        out_chunk[3 * m] = rhs_p0 & mask_10;
        let cc_o0 = rhs_p0 >> PIECE_BITS;

        // Position 1
        let mut rhs_p1 = cc_o0;
        if m < NUM_LIMBS {
            rhs_p1 += l_pieces[3 * m + 1];
        }
        if m < NUM_HIGH {
            rhs_p1 += acc[5 * m + 1];
        }
        if m >= 1 && (m - 1) < NUM_HIGH {
            rhs_p1 += acc[5 * (m - 1) + 4];
        }
        out_chunk[3 * m + 1] = rhs_p1 & mask_10;
        let cc_o1 = rhs_p1 >> PIECE_BITS;

        // Position 2
        let mut rhs_p2 = cc_o1;
        if m < NUM_LIMBS {
            rhs_p2 += l_pieces[3 * m + 2];
        }
        if m < NUM_HIGH {
            rhs_p2 += acc[5 * m + 2];
        }
        out_chunk[3 * m + 2] = rhs_p2 & mask_10;
        let cc_o2 = rhs_p2 >> PIECE_BITS;

        out_carry[3 * m] = cc_o0;
        out_carry[3 * m + 1] = cc_o1;
        out_carry[3 * m + 2] = cc_o2;

        out[m] = out_chunk[3 * m]
            + (out_chunk[3 * m + 1] << PIECE_BITS)
            + (out_chunk[3 * m + 2] << (2 * PIECE_BITS));

        prev_inter = cc_o2;
    }

    // Cross-validate against `compute_first_fold` (the pre-existing FIPS-grade
    // witness function). Both must produce identical 30-bit limb values.
    let acc_loose = compute_first_fold(input);
    for i in 0..NUM_OUTPUT_LIMBS {
        debug_assert_eq!(
            out[i] as u128, acc_loose[i],
            "first_fold_chunked diverges from compute_first_fold at limb {i}"
        );
    }

    FirstFoldChunkedWitness {
        l: *input,
        l_pieces,
        q_pieces,
        acc,
        q_carry,
        out,
        out_chunk,
        out_carry,
    }
}

/// Standalone test AIR wrapping the chip.
#[derive(Debug, Clone, Copy)]
pub struct FirstFoldChunkedTestAir;

impl<F: Field> BaseAir<F> for FirstFoldChunkedTestAir {
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

impl<AB: AirBuilder> Air<AB> for FirstFoldChunkedTestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        FirstFoldChunkedChip::new().emit(builder);
    }
}

/// Populate one row's worth of cells starting at `start_off`.
pub fn populate_row_to<F: Field + PrimeCharacteristicRing>(
    values: &mut [F],
    start_off: usize,
    w: &FirstFoldChunkedWitness,
) {
    // Structural cells.
    for i in 0..NUM_INPUT_LIMBS {
        values[start_off + col::L + i] = F::from_u64(w.l[i]);
    }
    for i in 0..L_PIECES_TOTAL {
        values[start_off + col::L_PIECES + i] = F::from_u64(w.l_pieces[i]);
    }
    for i in 0..Q_PIECES_TOTAL {
        values[start_off + col::Q_PIECES + i] = F::from_u64(w.q_pieces[i]);
    }
    for i in 0..ACC_TOTAL {
        values[start_off + col::ACC + i] = F::from_u64(w.acc[i]);
    }
    for i in 0..Q_CARRY_TOTAL {
        values[start_off + col::Q_CARRY + i] = F::from_u64(w.q_carry[i]);
    }
    for m in 0..NUM_OUTPUT_LIMBS {
        values[start_off + col::OUT + m] = F::from_u64(w.out[m]);
    }
    for i in 0..OUT_CHUNK_TOTAL {
        values[start_off + col::OUT_CHUNK + i] = F::from_u64(w.out_chunk[i]);
    }
    for i in 0..OUT_CARRY_TOTAL {
        values[start_off + col::OUT_CARRY + i] = F::from_u64(w.out_carry[i]);
    }

    // Bit decomposition regions.
    for i in 0..L_PIECES_TOTAL {
        RangeNChip::<PIECE_BITS>::populate_bits::<F>(
            values,
            start_off + col::L_PIECES_BITS + i * PIECE_BITS,
            w.l_pieces[i],
        );
    }
    for i in 0..Q_PIECES_TOTAL {
        RangeNChip::<PIECE_BITS>::populate_bits::<F>(
            values,
            start_off + col::Q_PIECES_BITS + i * PIECE_BITS,
            w.q_pieces[i],
        );
    }
    for i in 0..ACC_TOTAL {
        RangeNChip::<PIECE_BITS>::populate_bits::<F>(
            values,
            start_off + col::ACC_BITS + i * PIECE_BITS,
            w.acc[i],
        );
    }
    for i in 0..Q_CARRY_TOTAL {
        RangeNChip::<Q_CARRY_BITWIDTH>::populate_bits::<F>(
            values,
            start_off + col::Q_CARRY_BITS + i * Q_CARRY_BITWIDTH,
            w.q_carry[i],
        );
    }
    for i in 0..OUT_CHUNK_TOTAL {
        RangeNChip::<PIECE_BITS>::populate_bits::<F>(
            values,
            start_off + col::OUT_CHUNK_BITS + i * PIECE_BITS,
            w.out_chunk[i],
        );
    }
    for i in 0..OUT_CARRY_TOTAL {
        RangeNChip::<OUT_CARRY_BITWIDTH>::populate_bits::<F>(
            values,
            start_off + col::OUT_CARRY_BITS + i * OUT_CARRY_BITWIDTH,
            w.out_carry[i],
        );
    }
}

/// Build a 4-row test trace exercising one fold. Padding rows reuse the
/// zero-input witness (all zeros, all constraints trivially satisfied).
pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(
    input: &[u64; NUM_INPUT_LIMBS],
) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    // Active row 0 — real witness.
    let w = compute_first_fold_chunked_witness(input);
    populate_row_to::<F>(&mut values, 0, &w);

    // Padding rows — all-zero input. Every constraint reduces to 0 == 0.
    let zero_w = compute_first_fold_chunked_witness(&[0u64; NUM_INPUT_LIMBS]);
    for row in 1..HEIGHT {
        populate_row_to::<F>(&mut values, row * NUM_COLS, &zero_w);
    }

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    #[test]
    fn num_cols_documented() {
        assert_eq!(NUM_COLS, 2668);
    }

    #[test]
    fn first_fold_chunked_zero() {
        let input = [0u64; NUM_INPUT_LIMBS];
        let w = compute_first_fold_chunked_witness(&input);
        assert_eq!(w.out, [0u64; NUM_OUTPUT_LIMBS]);
        let trace = build_test_trace::<BabyBear>(&input);
        check_constraints(&FirstFoldChunkedTestAir, &trace, &[]);
    }

    #[test]
    fn first_fold_chunked_low_only_passthrough() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[0] = 100;
        input[5] = 999;
        let w = compute_first_fold_chunked_witness(&input);
        assert_eq!(w.out[0], 100);
        assert_eq!(w.out[5], 999);
        let trace = build_test_trace::<BabyBear>(&input);
        check_constraints(&FirstFoldChunkedTestAir, &trace, &[]);
    }

    #[test]
    fn first_fold_chunked_single_high_limb_yields_m() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[NUM_LIMBS] = 1; // L[9] = 1
        let w = compute_first_fold_chunked_witness(&input);
        assert_eq!(w.out[0], FOLD_M);
        let trace = build_test_trace::<BabyBear>(&input);
        check_constraints(&FirstFoldChunkedTestAir, &trace, &[]);
    }

    #[test]
    fn first_fold_chunked_max_high_limb_spans_two() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[NUM_LIMBS] = (1u64 << 30) - 1; // L[9] = max canonical
        let w = compute_first_fold_chunked_witness(&input);
        let total = ((1u64 << 30) - 1) * FOLD_M;
        // low_30 == acc[0] + 2^10·acc[1] + 2^20·acc[2] for k=0
        let low_30 = w.acc[0] + (w.acc[1] << PIECE_BITS) + (w.acc[2] << (2 * PIECE_BITS));
        let high_20 = w.acc[3] + (w.acc[4] << PIECE_BITS);
        assert_eq!(low_30, total & ((1u64 << 30) - 1));
        assert_eq!(high_20, total >> 30);
        let trace = build_test_trace::<BabyBear>(&input);
        check_constraints(&FirstFoldChunkedTestAir, &trace, &[]);
    }

    #[test]
    fn first_fold_chunked_matches_compute_first_fold() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[0] = 0x1234;
        input[3] = 0x5678;
        input[NUM_LIMBS] = 0x9ABC;
        input[NUM_LIMBS + 5] = 0xDEAD;
        let w = compute_first_fold_chunked_witness(&input);
        let acc_loose = compute_first_fold(&input);
        for i in 0..NUM_OUTPUT_LIMBS {
            assert_eq!(w.out[i] as u128, acc_loose[i], "limb {i} mismatch");
        }
        let trace = build_test_trace::<BabyBear>(&input);
        check_constraints(&FirstFoldChunkedTestAir, &trace, &[]);
    }

    #[test]
    fn first_fold_chunked_max_canonical_input() {
        // Stress: every limb at 2^30 - 1.
        let input = [(1u64 << 30) - 1; NUM_INPUT_LIMBS];
        let w = compute_first_fold_chunked_witness(&input);
        // Sanity: out reconstructs from chunks.
        for m in 0..NUM_OUTPUT_LIMBS {
            let recomp = w.out_chunk[3 * m]
                + (w.out_chunk[3 * m + 1] << PIECE_BITS)
                + (w.out_chunk[3 * m + 2] << (2 * PIECE_BITS));
            assert_eq!(w.out[m], recomp, "out[{m}] != chunk recomp");
        }
        let trace = build_test_trace::<BabyBear>(&input);
        check_constraints(&FirstFoldChunkedTestAir, &trace, &[]);
    }

    // ===== Soundness: tampered cell rejection =====

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn first_fold_chunked_rejects_tampered_out() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[0] = 0x1234;
        input[NUM_LIMBS] = 0x5678;
        let mut trace = build_test_trace::<BabyBear>(&input);
        trace.values[col::OUT] = trace.values[col::OUT] + BabyBear::ONE;
        check_constraints(&FirstFoldChunkedTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn first_fold_chunked_rejects_tampered_acc() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[NUM_LIMBS] = 1;
        let mut trace = build_test_trace::<BabyBear>(&input);
        // Mutate acc[0] (= low chunk of low_30[0]).
        trace.values[col::ACC] = trace.values[col::ACC] + BabyBear::ONE;
        check_constraints(&FirstFoldChunkedTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn first_fold_chunked_rejects_l_piece_above_2_to_10() {
        let input = [0u64; NUM_INPUT_LIMBS];
        let mut trace = build_test_trace::<BabyBear>(&input);
        trace.values[col::L_PIECES] = BabyBear::from_u64(1024);
        check_constraints(&FirstFoldChunkedTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn first_fold_chunked_rejects_q_piece_above_2_to_10() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[NUM_LIMBS] = 1;
        let mut trace = build_test_trace::<BabyBear>(&input);
        trace.values[col::Q_PIECES] = BabyBear::from_u64(1024);
        check_constraints(&FirstFoldChunkedTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn first_fold_chunked_rejects_q_carry_above_4_bits() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[NUM_LIMBS] = 1;
        let mut trace = build_test_trace::<BabyBear>(&input);
        trace.values[col::Q_CARRY] = BabyBear::from_u64(16);
        check_constraints(&FirstFoldChunkedTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn first_fold_chunked_rejects_out_chunk_above_2_to_10() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[0] = 0x1234;
        let mut trace = build_test_trace::<BabyBear>(&input);
        trace.values[col::OUT_CHUNK] = BabyBear::from_u64(1024);
        check_constraints(&FirstFoldChunkedTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn first_fold_chunked_rejects_out_carry_above_4_bits() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[0] = 0x1234;
        let mut trace = build_test_trace::<BabyBear>(&input);
        trace.values[col::OUT_CARRY] = BabyBear::from_u64(16);
        check_constraints(&FirstFoldChunkedTestAir, &trace, &[]);
    }

    // ===== BB-wrap collision class k=1 rejection =====
    //
    // The original FirstFoldChip's constraint #3
    //   `low_30 + 2^30·high_20 = q_a + 2^10·q_b + 2^20·q_c`
    // had LHS_max ≈ 2^50, way above p ≈ 2^31, so an adversary could pick
    // (low_30', high_20') with `low_30' + 2^30·high_20' = honest + k·p`
    // for k ∈ [1, ~2^19].
    //
    // In the chunked design that constraint is *replaced* by 5 short
    // equations whose LHS, RHS bounds are all `< 2^14 ≪ p`. There is no
    // single linear equation with bound exceeding p, so no BB-wrap class
    // exists. The tests below exercise the most adversarial scenarios.

    /// k=1 forge attempt on the reduced equation `acc[0] + 2^10·cc[0] = qa[0]`.
    /// In the original chip, LHS could reach 2^14 at worst; in BB (p ≈ 2^31)
    /// a forge would need to add ≥ p ≈ 2^31 — but range checks force every
    /// value `< 2^14`, so any modification fails recomposition.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn first_fold_chunked_rejects_bb_wrap_acc0_forge() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[NUM_LIMBS] = 1; // q_a = M, qa[0] = M & 0x3ff = 0
        let mut trace = build_test_trace::<BabyBear>(&input);
        // Attempt to set acc[0] = honest + 1024 (would BB-wrap if range
        // checks were absent). 1024 fits in range only if all 11 bits of
        // the bit decomp are coherent — but only 10 bit cols exist, so
        // range check rejects.
        let honest = trace.values[col::ACC];
        trace.values[col::ACC] = honest + BabyBear::from_u64(1024);
        check_constraints(&FirstFoldChunkedTestAir, &trace, &[]);
    }

    /// Another k=1 forge probe: tamper an acc bit decomposition. If
    /// adversary changes a bit but not the value, recomp fails.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn first_fold_chunked_rejects_acc_bit_tampering() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[NUM_LIMBS] = 1;
        let mut trace = build_test_trace::<BabyBear>(&input);
        // Flip a low bit of acc[0]'s decomp without updating the value.
        let bit_off = col::ACC_BITS;
        trace.values[bit_off] = trace.values[bit_off] + BabyBear::ONE;
        check_constraints(&FirstFoldChunkedTestAir, &trace, &[]);
    }

    /// Forge on the per-output-limb chain (closes constraint #4 BB-wrap).
    /// Original: out + 2^30·carry = V_lo + low_30 + high_20_prev + carry_in,
    /// RHS could exceed p by ~2^27. Chunked: each position equation has
    /// bound ≤ 2^13 ≪ p. Tampering fails.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn first_fold_chunked_rejects_bb_wrap_out_chunk_forge() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        for i in 0..NUM_INPUT_LIMBS {
            input[i] = (1u64 << 30) - 1;
        }
        let mut trace = build_test_trace::<BabyBear>(&input);
        // Tamper out_chunk[0] (= low chunk of out[0]) by 1024 (would BB-
        // wrap if range checks absent).
        let honest = trace.values[col::OUT_CHUNK];
        trace.values[col::OUT_CHUNK] = honest + BabyBear::from_u64(1024);
        check_constraints(&FirstFoldChunkedTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn first_fold_chunked_rejects_q_piece_sum_mismatch() {
        let mut input = [0u64; NUM_INPUT_LIMBS];
        input[NUM_LIMBS] = 1; // a_0 = 1, q_a = M = 622592
        let mut trace = build_test_trace::<BabyBear>(&input);
        // Original: q_pieces[0..3] = decomp of 622592 = [0, 608, 0]
        //   actually 622592 = 0x98000, so qa0=0, qa1=0x200=512, qa2=0x9=9? Let me compute.
        //   622592 in hex = 0x98000. bits 0..9 = 0x000 = 0. bits 10..19 = 0x200 = 512. bits 20..29 = 0x9 = 9.
        //   So qa0=0, qa1=512, qa2=9.
        // Tamper qa0 to 1 (breaks q_a = qa0+2^10·qa1+2^20·qa2 identity).
        trace.values[col::Q_PIECES] = BabyBear::from_u64(1);
        check_constraints(&FirstFoldChunkedTestAir, &trace, &[]);
    }
}
