//! `field25519::second_fold_chunked` — sound second-fold AIR (Etapa 3.10.2.1).
//!
//! Substitui `SecondFoldOnePassChip` fechando estruturalmente **todas** as
//! BB-wrap collision classes do chip original:
//!
//!   - **Gap #1** (prod_9 split, LHS_max ≈ 2⁴² > p): equação
//!     `prod_9_low + 2³⁰·prod_9_high = q_lo + 2⁷·q_mid + 2¹⁴·q_hi`
//!     fechada via 6 equações de posição encadeadas com chunk_carry de
//!     7 bits (alinhadas com shifts 2⁷/2¹⁴). Cada equação LHS/RHS < 2¹¹.
//!
//!   - **Gap #2** (limb 0 carry chain, RHS_max ≈ 3·2³⁰ > p): equação
//!     `acc_out[0] + 2³⁰·carry[0] = acc_in[0] + prod_9_low + prod_8_low`
//!     fechada via 3 equações de posição 10-bit + chunk_carry 4-bit.
//!     Cada equação LHS/RHS < 2¹⁴.
//!
//!   - **Gap #3** (acc_out range checks ausentes em todos os limbs): chip
//!     original não range-checava `acc_out[0..10]`, permitindo forge BB-
//!     wrap mesmo quando RHS < p (alt_int = honest + p, alt_carry = honest +1
//!     dentro de 10-bit range, alt_acc_out < 2³⁰). Closure via 10-bit
//!     decomp por limb (10·3 chunks + reconstruction constraints).
//!
//!   - **Gap #4 (extensão do #3)** — mesmo com acc_out range-checked, o
//!     bound LHS = acc_out + 2³⁰·carry pode exceder p se carry tem range
//!     loose (10-bit). Closure: chunked carry chain em **todos os 10
//!     limbs** com cc_chain[m][p] (4-bit, real bound ≤ 4).
//!
//! Todas as equações chunked têm LHS/RHS bound `< 2¹⁴ ≪ p ≈ 2³¹`. Não
//! há solução BB-wrap k≥1 — `k=0` é única.
//!
//! Wire format invariance: `acc_in/acc_out` (10 30-bit cols) e
//! `prod_9_low/prod_9_high` (cols 30-bit / 12-bit) continuam expostos
//! com mesma semântica → drop-in replacement do chip original.
//!
//! ## Algoritmo (alinhado com `compute_second_fold_one_pass`)
//!
//! ```text
//! limb_9 = acc_in[9]
//! a_lo + 2⁷·a_mid + 2¹⁴·a_hi = limb_9              (7-bit pieces)
//! q_lo = a_lo·M,  q_mid = a_mid·M,  q_hi = a_hi·M  (each < 2²⁷)
//!
//! Q-chunk decomp (4 pieces per q, widths 7/7/7/6):
//!   q = q_chunks[0] + 2⁷·q_chunks[1] + 2¹⁴·q_chunks[2] + 2²¹·q_chunks[3]
//!
//! Prod_9 position chain (6 equations, 7-bit chunks; closes Gap #1):
//!   pos 0..5 (per design doc)
//!
//! Acc4 split (acc_p9[4] = acc4_low + 4·acc4_high):
//!   prod_9_low  := acc_p9[0..3] + 2²⁸·acc4_low      (sound, < 2³⁰ < p)
//!   prod_9_high := acc4_high + 2⁵·acc_p9[5]         (sound, < 2¹² < p)
//!
//! limb_8 = high_8·2¹⁵ + low_15                      (sound, < 2³⁰ < p)
//! prod_8_low + 2³⁰·prod_8_high = high_8·19          (RHS < 2²⁰; prod_8_high = 0)
//!
//! Output chunked carry chain (closes Gaps #2/#3/#4):
//!   acc_in[m] = ai[m][0] + 2¹⁰·ai[m][1] + 2²⁰·ai[m][2]   (m∈0..7)
//!   prod_9_low = pl[0] + 2¹⁰·pl[1] + 2²⁰·pl[2]
//!   prod_9_high = ph[0] + 2¹⁰·ph[1]                       (12-bit = 10+2)
//!   prod_8_low = pe[0] + 2¹⁰·pe[1]                        (20-bit = 10+10)
//!   low_15 = l15[0] + 2¹⁰·l15[1]                          (15-bit = 10+5)
//!   acc_out[m] = oc[m][0] + 2¹⁰·oc[m][1] + 2²⁰·oc[m][2]   (m∈0..9, Gap #3)
//!
//!   For each output limb m, 3 position equations:
//!     pos p (weight 2^(10p) within limb):
//!       oc[m][p] + 2¹⁰·cc_chain[m][p] = (chunk contribs at pos p) + cc_chain[m][p-1] (or prev_inter for p=0)
//!
//!   Contribs by limb:
//!     m=0:   ai[0][p] + pl[p] + (pe[p] if p<2 else 0)
//!     m=1:   ai[1][p] + (ph[p] if p<2 else 0)
//!     m∈2..7: ai[m][p]
//!     m=8:   l15[p] (l15[2] = 0)
//!     m=9:   0
//!   prev_inter for limb m+1 = cc_chain[m][2]
//!   Boundary: cc_chain[9][2] = 0
//! ```
//!
//! ## Bounds (sound)
//!
//! Each output position equation: RHS_max ≤ 3·(2¹⁰−1) + cc ≤ ~2¹². LHS_max
//! ≤ (2¹⁰−1) + 2¹⁰·15 ≈ 2¹⁴. Both ≪ p. ✅
//!
//! ## Layout (1097 cols total)
//!
//! Reorganized layout (CARRY array dropped — superseded by cc_chain):
//!
//! | offset            | width | conteúdo                              |
//! |-------------------|-------|---------------------------------------|
//! | 0..10             | 10    | acc_in[0..10]                         |
//! | 10..20            | 10    | acc_out[0..10]                        |
//! | 20..23            | 3     | limb_9_pieces (a_lo, a_mid, a_hi)     |
//! | 23..26            | 3     | q_pieces (q_lo, q_mid, q_hi)          |
//! | 26..27            | 1     | prod_9_low (30-bit derived)           |
//! | 27..28            | 1     | prod_9_high (12-bit derived)          |
//! | 28..29            | 1     | high_8                                |
//! | 29..30            | 1     | low_15                                |
//! | 30..31            | 1     | prod_8_low                            |
//! | 31..32            | 1     | prod_8_high (asserted zero)           |
//! | 32..44            | 12    | q_chunks (3 q's × 4 chunks)           |
//! | 44..50            | 6     | acc_p9 (Gap #1)                       |
//! | 50..51            | 1     | acc4_low (2-bit)                      |
//! | 51..52            | 1     | acc4_high (5-bit)                     |
//! | 52..57            | 5     | cc_p9 (Gap #1 chunk carries)          |
//! | 57..81            | 24    | ai_chunks (limbs 0..7 × 3 each)       |
//! | 81..84            | 3     | pl_chunks (prod_9_low → 3 chunks)     |
//! | 84..86            | 2     | ph_chunks (prod_9_high → 2 chunks)    |
//! | 86..88            | 2     | pe_chunks (prod_8_low → 2 chunks)     |
//! | 88..90            | 2     | l15_chunks (low_15 → 2 chunks)        |
//! | 90..120           | 30    | oc_chunks (10 limbs × 3 chunks, Gap #3) |
//! | 120..150          | 30    | cc_chain (10 limbs × 3 chunk carries) |
//! | 150..STRUCTURAL_END | --  | (= 150)                               |

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::mod_p::FOLD_M;
use crate::chips::lookup::range_n::RangeNChip;

const NUM_LIMBS_OUT: usize = 10;
const NUM_LIMB9_PIECES: usize = 3;

// Gap #1 constants
const PIECE_BITS_9: usize = 7;
const PIECE_MOD_9: u64 = 1 << PIECE_BITS_9;
const Q_CHUNKS_PER_Q: usize = 4;
const NUM_QS: usize = 3;
const Q_CHUNKS_TOTAL: usize = NUM_QS * Q_CHUNKS_PER_Q; // 12
const Q_CHUNK_BITS_LOW: usize = 7;
const Q_CHUNK_BITS_HIGH: usize = 6;
const ACC_P9_LEN: usize = 6;
const ACC_P9_WIDTH: usize = 7;
const NUM_CC_P9: usize = 5;
const CC_P9_WIDTH: usize = 4;
const ACC4_LOW_WIDTH: usize = 2;
const ACC4_HIGH_WIDTH: usize = 5;

// Gap #2/#3/#4 constants — output chunked chain
const PIECE_BITS_OUT: usize = 10;
const NUM_AI_LIMBS: usize = 8; // limbs 0..7 (limb 8 uses low_15, limb 9 has no contrib)
const AI_CHUNKS_PER_LIMB: usize = 3;
const AI_CHUNKS_TOTAL: usize = NUM_AI_LIMBS * AI_CHUNKS_PER_LIMB; // 24
const PL_CHUNKS_TOTAL: usize = 3; // prod_9_low: 3 × 10 bits = 30 bits
const PH_CHUNKS_TOTAL: usize = 2; // prod_9_high: 10 + 2 bits = 12 bits
const PH_CHUNK_HI_BITS: usize = 2;
const PE_CHUNKS_TOTAL: usize = 2; // prod_8_low: 10 + 10 bits = 20 bits
const L15_CHUNKS_TOTAL: usize = 2; // low_15: 10 + 5 bits = 15 bits
const L15_CHUNK_HI_BITS: usize = 5;
const OC_CHUNKS_PER_LIMB: usize = 3;
const OC_CHUNKS_TOTAL: usize = NUM_LIMBS_OUT * OC_CHUNKS_PER_LIMB; // 30
const CC_CHAIN_PER_LIMB: usize = 3;
const CC_CHAIN_TOTAL: usize = NUM_LIMBS_OUT * CC_CHAIN_PER_LIMB; // 30
const CC_CHAIN_BITS: usize = 4;

// Original ranges preserved for non-chunked sections
const HIGH_8_BITS: usize = 15;

pub mod col {
    use super::*;

    pub const ACC_IN: usize = 0;
    pub const ACC_OUT: usize = ACC_IN + NUM_LIMBS_OUT; // 10
    pub const LIMB_9_PIECES: usize = ACC_OUT + NUM_LIMBS_OUT; // 20
    pub const Q_PIECES: usize = LIMB_9_PIECES + NUM_LIMB9_PIECES; // 23
    pub const PROD_9_LOW: usize = Q_PIECES + NUM_QS; // 26
    pub const PROD_9_HIGH: usize = PROD_9_LOW + 1; // 27
    pub const HIGH_8: usize = PROD_9_HIGH + 1; // 28
    pub const LOW_15: usize = HIGH_8 + 1; // 29
    pub const PROD_8_LOW: usize = LOW_15 + 1; // 30
    pub const PROD_8_HIGH: usize = PROD_8_LOW + 1; // 31

    // Gap #1 closure
    pub const Q_CHUNKS: usize = PROD_8_HIGH + 1; // 32
    pub const ACC_P9: usize = Q_CHUNKS + Q_CHUNKS_TOTAL; // 44
    pub const ACC4_LOW: usize = ACC_P9 + ACC_P9_LEN; // 50
    pub const ACC4_HIGH: usize = ACC4_LOW + 1; // 51
    pub const CC_P9: usize = ACC4_HIGH + 1; // 52

    // Gap #2/#3/#4 closure — output chunked chain
    pub const AI_CHUNKS: usize = CC_P9 + NUM_CC_P9; // 57
    pub const PL_CHUNKS: usize = AI_CHUNKS + AI_CHUNKS_TOTAL; // 81
    pub const PH_CHUNKS: usize = PL_CHUNKS + PL_CHUNKS_TOTAL; // 84
    pub const PE_CHUNKS: usize = PH_CHUNKS + PH_CHUNKS_TOTAL; // 86
    pub const L15_CHUNKS: usize = PE_CHUNKS + PE_CHUNKS_TOTAL; // 88
    pub const OC_CHUNKS: usize = L15_CHUNKS + L15_CHUNKS_TOTAL; // 90
    pub const CC_CHAIN: usize = OC_CHUNKS + OC_CHUNKS_TOTAL; // 120
    pub const STRUCTURAL_END: usize = CC_CHAIN + CC_CHAIN_TOTAL; // 150

    // ── Range bit decomp regions ────────────────────────────────────────
    pub const LIMB9_BITS_BASE: usize = STRUCTURAL_END; // 150
    pub const Q_CHUNKS_BITS_BASE: usize = LIMB9_BITS_BASE + NUM_LIMB9_PIECES * PIECE_BITS_9; // 171
    pub const ACC_P9_BITS_BASE: usize = Q_CHUNKS_BITS_BASE + NUM_QS * (3 * Q_CHUNK_BITS_LOW + Q_CHUNK_BITS_HIGH); // 252
    pub const ACC4_LOW_BITS_BASE: usize = ACC_P9_BITS_BASE + ACC_P9_LEN * ACC_P9_WIDTH; // 294
    pub const ACC4_HIGH_BITS_BASE: usize = ACC4_LOW_BITS_BASE + ACC4_LOW_WIDTH; // 296
    pub const CC_P9_BITS_BASE: usize = ACC4_HIGH_BITS_BASE + ACC4_HIGH_WIDTH; // 301
    pub const HIGH_8_BITS_BASE: usize = CC_P9_BITS_BASE + NUM_CC_P9 * CC_P9_WIDTH; // 321
    pub const AI_CHUNKS_BITS_BASE: usize = HIGH_8_BITS_BASE + HIGH_8_BITS; // 336
    pub const PL_CHUNKS_BITS_BASE: usize = AI_CHUNKS_BITS_BASE + AI_CHUNKS_TOTAL * PIECE_BITS_OUT; // 576
    pub const PH_CHUNKS_BITS_BASE: usize = PL_CHUNKS_BITS_BASE + PL_CHUNKS_TOTAL * PIECE_BITS_OUT; // 606
    pub const PE_CHUNKS_BITS_BASE: usize = PH_CHUNKS_BITS_BASE + PIECE_BITS_OUT + PH_CHUNK_HI_BITS; // 618
    pub const L15_CHUNKS_BITS_BASE: usize = PE_CHUNKS_BITS_BASE + PE_CHUNKS_TOTAL * PIECE_BITS_OUT; // 638
    pub const OC_CHUNKS_BITS_BASE: usize = L15_CHUNKS_BITS_BASE + PIECE_BITS_OUT + L15_CHUNK_HI_BITS; // 653
    pub const CC_CHAIN_BITS_BASE: usize = OC_CHUNKS_BITS_BASE + OC_CHUNKS_TOTAL * PIECE_BITS_OUT; // 953

    pub const TOTAL: usize = CC_CHAIN_BITS_BASE + CC_CHAIN_TOTAL * CC_CHAIN_BITS; // 1073
}

pub const NUM_COLS: usize = col::TOTAL;

/// Layout descriptor and constraint emitter.
#[derive(Debug, Clone, Copy)]
pub struct SecondFoldChunkedChip {
    pub start_col: usize,
}

impl Default for SecondFoldChunkedChip {
    fn default() -> Self {
        Self::new()
    }
}

impl SecondFoldChunkedChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let s = self.start_col;
        let m_field = AB::Expr::from_u64(FOLD_M);
        let two_to_2 = AB::Expr::from_u64(1 << 2);
        let two_to_5 = AB::Expr::from_u64(1 << 5);
        let two_to_7 = AB::Expr::from_u64(1 << 7);
        let two_to_10 = AB::Expr::from_u64(1 << 10);
        let two_to_14 = AB::Expr::from_u64(1 << 14);
        let two_to_15 = AB::Expr::from_u64(1 << 15);
        let two_to_20 = AB::Expr::from_u64(1u64 << 20);
        let two_to_21 = AB::Expr::from_u64(1u64 << 21);
        let two_to_28 = AB::Expr::from_u64(1u64 << 28);
        let two_to_30 = AB::Expr::from_u64(1u64 << 30);
        let nineteen = AB::Expr::from_u64(19);

        // -----------------------------------------------------------------
        // Range checks — every chunked value gets bit-decomposition recomp.
        // -----------------------------------------------------------------
        // limb_9 pieces (7-bit each)
        for i in 0..NUM_LIMB9_PIECES {
            RangeNChip::<PIECE_BITS_9>::split(s + col::LIMB_9_PIECES + i, s + col::LIMB9_BITS_BASE + i * PIECE_BITS_9).emit(builder);
        }
        // q_chunks (per q: 3 × 7-bit + 1 × 6-bit)
        for q_idx in 0..NUM_QS {
            for chunk_idx in 0..Q_CHUNKS_PER_Q {
                let value_col = s + col::Q_CHUNKS + q_idx * Q_CHUNKS_PER_Q + chunk_idx;
                let bits_col = s
                    + col::Q_CHUNKS_BITS_BASE
                    + q_idx * (3 * Q_CHUNK_BITS_LOW + Q_CHUNK_BITS_HIGH)
                    + if chunk_idx < 3 { chunk_idx * Q_CHUNK_BITS_LOW } else { 3 * Q_CHUNK_BITS_LOW };
                if chunk_idx < 3 {
                    RangeNChip::<Q_CHUNK_BITS_LOW>::split(value_col, bits_col).emit(builder);
                } else {
                    RangeNChip::<Q_CHUNK_BITS_HIGH>::split(value_col, bits_col).emit(builder);
                }
            }
        }
        // acc_p9 (7-bit each)
        for i in 0..ACC_P9_LEN {
            RangeNChip::<ACC_P9_WIDTH>::split(s + col::ACC_P9 + i, s + col::ACC_P9_BITS_BASE + i * ACC_P9_WIDTH).emit(builder);
        }
        RangeNChip::<ACC4_LOW_WIDTH>::split(s + col::ACC4_LOW, s + col::ACC4_LOW_BITS_BASE).emit(builder);
        RangeNChip::<ACC4_HIGH_WIDTH>::split(s + col::ACC4_HIGH, s + col::ACC4_HIGH_BITS_BASE).emit(builder);
        // cc_p9 (4-bit)
        for i in 0..NUM_CC_P9 {
            RangeNChip::<CC_P9_WIDTH>::split(s + col::CC_P9 + i, s + col::CC_P9_BITS_BASE + i * CC_P9_WIDTH).emit(builder);
        }
        // high_8 (15-bit)
        RangeNChip::<HIGH_8_BITS>::split(s + col::HIGH_8, s + col::HIGH_8_BITS_BASE).emit(builder);

        // ── Output chunked chain range checks (Gap #2/#3/#4) ────────────
        // ai_chunks (10-bit each, 24 chunks for limbs 0..7)
        for i in 0..AI_CHUNKS_TOTAL {
            RangeNChip::<PIECE_BITS_OUT>::split(s + col::AI_CHUNKS + i, s + col::AI_CHUNKS_BITS_BASE + i * PIECE_BITS_OUT)
                .emit(builder);
        }
        // pl_chunks (3 × 10-bit)
        for i in 0..PL_CHUNKS_TOTAL {
            RangeNChip::<PIECE_BITS_OUT>::split(s + col::PL_CHUNKS + i, s + col::PL_CHUNKS_BITS_BASE + i * PIECE_BITS_OUT)
                .emit(builder);
        }
        // ph_chunks (10-bit + 2-bit)
        RangeNChip::<PIECE_BITS_OUT>::split(s + col::PH_CHUNKS, s + col::PH_CHUNKS_BITS_BASE).emit(builder);
        RangeNChip::<PH_CHUNK_HI_BITS>::split(s + col::PH_CHUNKS + 1, s + col::PH_CHUNKS_BITS_BASE + PIECE_BITS_OUT).emit(builder);
        // pe_chunks (2 × 10-bit)
        for i in 0..PE_CHUNKS_TOTAL {
            RangeNChip::<PIECE_BITS_OUT>::split(s + col::PE_CHUNKS + i, s + col::PE_CHUNKS_BITS_BASE + i * PIECE_BITS_OUT)
                .emit(builder);
        }
        // l15_chunks (10-bit + 5-bit)
        RangeNChip::<PIECE_BITS_OUT>::split(s + col::L15_CHUNKS, s + col::L15_CHUNKS_BITS_BASE).emit(builder);
        RangeNChip::<L15_CHUNK_HI_BITS>::split(s + col::L15_CHUNKS + 1, s + col::L15_CHUNKS_BITS_BASE + PIECE_BITS_OUT).emit(builder);
        // oc_chunks (30 × 10-bit) — closes Gap #3
        for i in 0..OC_CHUNKS_TOTAL {
            RangeNChip::<PIECE_BITS_OUT>::split(s + col::OC_CHUNKS + i, s + col::OC_CHUNKS_BITS_BASE + i * PIECE_BITS_OUT)
                .emit(builder);
        }
        // cc_chain (30 × 4-bit)
        for i in 0..CC_CHAIN_TOTAL {
            RangeNChip::<CC_CHAIN_BITS>::split(s + col::CC_CHAIN + i, s + col::CC_CHAIN_BITS_BASE + i * CC_CHAIN_BITS).emit(builder);
        }

        let main = builder.main();
        let row = main.current_slice();

        // -----------------------------------------------------------------
        // limb_9 piece reassembly: a_lo + 128·a_mid + 16384·a_hi = acc_in[9]
        // -----------------------------------------------------------------
        let a_lo = row[s + col::LIMB_9_PIECES];
        let a_mid = row[s + col::LIMB_9_PIECES + 1];
        let a_hi = row[s + col::LIMB_9_PIECES + 2];
        builder.assert_eq(
            a_lo.into() + two_to_7.clone() * a_mid.into() + two_to_14.clone() * a_hi.into(),
            row[s + col::ACC_IN + 9].into(),
        );

        // q-products
        let q_lo = row[s + col::Q_PIECES];
        let q_mid = row[s + col::Q_PIECES + 1];
        let q_hi = row[s + col::Q_PIECES + 2];
        builder.assert_eq(q_lo.into(), m_field.clone() * a_lo.into());
        builder.assert_eq(q_mid.into(), m_field.clone() * a_mid.into());
        builder.assert_eq(q_hi.into(), m_field.clone() * a_hi.into());

        // -----------------------------------------------------------------
        // Q-chunk decomposition: q = c0 + 2^7·c1 + 2^14·c2 + 2^21·c3
        // -----------------------------------------------------------------
        for q_idx in 0..NUM_QS {
            let q_col = match q_idx {
                0 => q_lo,
                1 => q_mid,
                2 => q_hi,
                _ => unreachable!(),
            };
            let c0 = row[s + col::Q_CHUNKS + q_idx * Q_CHUNKS_PER_Q];
            let c1 = row[s + col::Q_CHUNKS + q_idx * Q_CHUNKS_PER_Q + 1];
            let c2 = row[s + col::Q_CHUNKS + q_idx * Q_CHUNKS_PER_Q + 2];
            let c3 = row[s + col::Q_CHUNKS + q_idx * Q_CHUNKS_PER_Q + 3];
            builder.assert_eq(
                q_col.into(),
                c0.into() + two_to_7.clone() * c1.into() + two_to_14.clone() * c2.into() + two_to_21.clone() * c3.into(),
            );
        }

        // -----------------------------------------------------------------
        // Position chain (Gap #1 closure) — 6 equations, 7-bit chunks.
        // -----------------------------------------------------------------
        let q_lo_c0 = row[s + col::Q_CHUNKS];
        let q_lo_c1 = row[s + col::Q_CHUNKS + 1];
        let q_lo_c2 = row[s + col::Q_CHUNKS + 2];
        let q_lo_c3 = row[s + col::Q_CHUNKS + 3];
        let q_mid_c0 = row[s + col::Q_CHUNKS + 4];
        let q_mid_c1 = row[s + col::Q_CHUNKS + 5];
        let q_mid_c2 = row[s + col::Q_CHUNKS + 6];
        let q_mid_c3 = row[s + col::Q_CHUNKS + 7];
        let q_hi_c0 = row[s + col::Q_CHUNKS + 8];
        let q_hi_c1 = row[s + col::Q_CHUNKS + 9];
        let q_hi_c2 = row[s + col::Q_CHUNKS + 10];
        let q_hi_c3 = row[s + col::Q_CHUNKS + 11];

        let acc0 = row[s + col::ACC_P9];
        let acc1 = row[s + col::ACC_P9 + 1];
        let acc2 = row[s + col::ACC_P9 + 2];
        let acc3 = row[s + col::ACC_P9 + 3];
        let acc4 = row[s + col::ACC_P9 + 4];
        let acc5 = row[s + col::ACC_P9 + 5];

        let cc0 = row[s + col::CC_P9];
        let cc1 = row[s + col::CC_P9 + 1];
        let cc2 = row[s + col::CC_P9 + 2];
        let cc3 = row[s + col::CC_P9 + 3];
        let cc4 = row[s + col::CC_P9 + 4];

        builder.assert_eq(acc0.into() + two_to_7.clone() * cc0.into(), q_lo_c0.into());
        builder.assert_eq(acc1.into() + two_to_7.clone() * cc1.into(), q_lo_c1.into() + q_mid_c0.into() + cc0.into());
        builder.assert_eq(acc2.into() + two_to_7.clone() * cc2.into(), q_lo_c2.into() + q_mid_c1.into() + q_hi_c0.into() + cc1.into());
        builder.assert_eq(acc3.into() + two_to_7.clone() * cc3.into(), q_lo_c3.into() + q_mid_c2.into() + q_hi_c1.into() + cc2.into());
        builder.assert_eq(acc4.into() + two_to_7.clone() * cc4.into(), q_mid_c3.into() + q_hi_c2.into() + cc3.into());
        builder.assert_eq(acc5.into(), q_hi_c3.into() + cc4.into());

        // -----------------------------------------------------------------
        // acc4 split + prod_9_low/high identifications.
        // -----------------------------------------------------------------
        let acc4_low = row[s + col::ACC4_LOW];
        let acc4_high = row[s + col::ACC4_HIGH];
        builder.assert_eq(acc4.into(), acc4_low.into() + two_to_2.clone() * acc4_high.into());

        let prod_9_low = row[s + col::PROD_9_LOW];
        let prod_9_high = row[s + col::PROD_9_HIGH];
        builder.assert_eq(
            prod_9_low.into(),
            acc0.into()
                + two_to_7.clone() * acc1.into()
                + two_to_14.clone() * acc2.into()
                + two_to_21.clone() * acc3.into()
                + two_to_28.clone() * acc4_low.into(),
        );
        builder.assert_eq(prod_9_high.into(), acc4_high.into() + two_to_5.clone() * acc5.into());

        // -----------------------------------------------------------------
        // limb_8 decomp + prod_8 split.
        // -----------------------------------------------------------------
        let high_8 = row[s + col::HIGH_8];
        let low_15 = row[s + col::LOW_15];
        builder.assert_eq(high_8.into() * two_to_15.clone() + low_15.into(), row[s + col::ACC_IN + 8].into());

        let prod_8_low = row[s + col::PROD_8_LOW];
        let prod_8_high = row[s + col::PROD_8_HIGH];
        builder.assert_eq(prod_8_low.into() + two_to_30.clone() * prod_8_high.into(), high_8.into() * nineteen);
        builder.assert_zero(prod_8_high);

        // -----------------------------------------------------------------
        // Gap #2/#3/#4 closure — output chunked chain.
        //
        // Step 1: identifications (decompose contributors and outputs into
        // 10-bit chunks; all sound, RHS_max < 2^30 < p).
        // -----------------------------------------------------------------
        // ai_chunks: acc_in[m] = ai[m][0] + 2^10·ai[m][1] + 2^20·ai[m][2]
        // for m ∈ 0..7 (limbs 8 and 9 don't contribute via acc_in directly).
        for m in 0..NUM_AI_LIMBS {
            let ai0 = row[s + col::AI_CHUNKS + 3 * m];
            let ai1 = row[s + col::AI_CHUNKS + 3 * m + 1];
            let ai2 = row[s + col::AI_CHUNKS + 3 * m + 2];
            builder.assert_eq(
                row[s + col::ACC_IN + m].into(),
                ai0.into() + two_to_10.clone() * ai1.into() + two_to_20.clone() * ai2.into(),
            );
        }

        // pl_chunks: prod_9_low = pl[0] + 2^10·pl[1] + 2^20·pl[2]
        let pl0 = row[s + col::PL_CHUNKS];
        let pl1 = row[s + col::PL_CHUNKS + 1];
        let pl2 = row[s + col::PL_CHUNKS + 2];
        builder.assert_eq(prod_9_low.into(), pl0.into() + two_to_10.clone() * pl1.into() + two_to_20.clone() * pl2.into());

        // ph_chunks: prod_9_high = ph[0] + 2^10·ph[1]  (12-bit total)
        let ph0 = row[s + col::PH_CHUNKS];
        let ph1 = row[s + col::PH_CHUNKS + 1];
        builder.assert_eq(prod_9_high.into(), ph0.into() + two_to_10.clone() * ph1.into());

        // pe_chunks: prod_8_low = pe[0] + 2^10·pe[1]  (20-bit total)
        let pe0 = row[s + col::PE_CHUNKS];
        let pe1 = row[s + col::PE_CHUNKS + 1];
        builder.assert_eq(prod_8_low.into(), pe0.into() + two_to_10.clone() * pe1.into());

        // l15_chunks: low_15 = l15[0] + 2^10·l15[1]  (15-bit total)
        let l15_0 = row[s + col::L15_CHUNKS];
        let l15_1 = row[s + col::L15_CHUNKS + 1];
        builder.assert_eq(low_15.into(), l15_0.into() + two_to_10.clone() * l15_1.into());

        // oc_chunks: acc_out[m] = oc[m][0] + 2^10·oc[m][1] + 2^20·oc[m][2]
        // (Gap #3 closure — range-checks acc_out via chunks.)
        for m in 0..NUM_LIMBS_OUT {
            let oc0 = row[s + col::OC_CHUNKS + 3 * m];
            let oc1 = row[s + col::OC_CHUNKS + 3 * m + 1];
            let oc2 = row[s + col::OC_CHUNKS + 3 * m + 2];
            builder.assert_eq(
                row[s + col::ACC_OUT + m].into(),
                oc0.into() + two_to_10.clone() * oc1.into() + two_to_20.clone() * oc2.into(),
            );
        }

        // -----------------------------------------------------------------
        // Step 2: chunked carry chain — 3 position equations per output
        // limb. Each equation has LHS, RHS bounds < 2^14 << p.
        //
        // Contributions per limb m, position p:
        //   m=0:   ai[0][p] + pl[p] + (pe[p] if p<2 else 0)
        //   m=1:   ai[1][p] + (ph[p] if p<2 else 0)
        //   m∈2..7: ai[m][p]
        //   m=8:   l15[p] (l15[2] = 0)
        //   m=9:   0
        // -----------------------------------------------------------------
        let mut prev_inter: AB::Expr = AB::Expr::ZERO;
        for m in 0..NUM_LIMBS_OUT {
            let oc0 = row[s + col::OC_CHUNKS + 3 * m];
            let oc1 = row[s + col::OC_CHUNKS + 3 * m + 1];
            let oc2 = row[s + col::OC_CHUNKS + 3 * m + 2];
            let cc_chain_0 = row[s + col::CC_CHAIN + 3 * m];
            let cc_chain_1 = row[s + col::CC_CHAIN + 3 * m + 1];
            let cc_chain_2 = row[s + col::CC_CHAIN + 3 * m + 2];

            // Position 0
            let mut rhs_p0: AB::Expr = prev_inter.clone();
            match m {
                0 => {
                    rhs_p0 = rhs_p0 + row[s + col::AI_CHUNKS].into() + pl0.into() + pe0.into();
                }
                1 => {
                    rhs_p0 = rhs_p0 + row[s + col::AI_CHUNKS + 3].into() + ph0.into();
                }
                m if (2..=7).contains(&m) => {
                    rhs_p0 += row[s + col::AI_CHUNKS + 3 * m].into();
                }
                8 => {
                    rhs_p0 += l15_0.into();
                }
                9 => { /* no contribution beyond prev_inter */ }
                _ => unreachable!(),
            }
            builder.assert_eq(oc0.into() + two_to_10.clone() * cc_chain_0.into(), rhs_p0);

            // Position 1
            let mut rhs_p1: AB::Expr = cc_chain_0.into();
            match m {
                0 => {
                    rhs_p1 = rhs_p1 + row[s + col::AI_CHUNKS + 1].into() + pl1.into() + pe1.into();
                }
                1 => {
                    rhs_p1 = rhs_p1 + row[s + col::AI_CHUNKS + 4].into() + ph1.into();
                }
                m if (2..=7).contains(&m) => {
                    rhs_p1 += row[s + col::AI_CHUNKS + 3 * m + 1].into();
                }
                8 => {
                    rhs_p1 += l15_1.into();
                }
                9 => { /* no contribution */ }
                _ => unreachable!(),
            }
            builder.assert_eq(oc1.into() + two_to_10.clone() * cc_chain_1.into(), rhs_p1);

            // Position 2
            let mut rhs_p2: AB::Expr = cc_chain_1.into();
            match m {
                0 => {
                    // No prod_8_low contribution at pos 2 (prod_8_low < 2^20 fits in pos 0+1).
                    rhs_p2 = rhs_p2 + row[s + col::AI_CHUNKS + 2].into() + pl2.into();
                }
                1 => {
                    // ph_chunks[2] doesn't exist (prod_9_high < 2^12 fits in pos 0+1).
                    rhs_p2 += row[s + col::AI_CHUNKS + 5].into();
                }
                m if (2..=7).contains(&m) => {
                    rhs_p2 += row[s + col::AI_CHUNKS + 3 * m + 2].into();
                }
                8 | 9 => { /* no contribution at pos 2 */ }
                _ => unreachable!(),
            }
            builder.assert_eq(oc2.into() + two_to_10.clone() * cc_chain_2.into(), rhs_p2);

            prev_inter = cc_chain_2.into();
        }

        // Boundary: cc_chain[9][2] must be 0 (no overflow past limb 9).
        builder.assert_zero(row[s + col::CC_CHAIN + 3 * (NUM_LIMBS_OUT - 1) + 2]);
    }
}

/// Witness for one chunked second-fold pass (full closure version).
#[derive(Debug, Clone)]
pub struct SecondFoldChunkedWitness {
    pub acc_in: [u128; 10],
    pub acc_out: [u64; 10],
    pub limb_9_pieces: [u64; NUM_LIMB9_PIECES],
    pub q_pieces: [u64; NUM_QS],
    pub q_chunks: [u64; Q_CHUNKS_TOTAL],
    pub acc_p9: [u64; ACC_P9_LEN],
    pub cc_p9: [u64; NUM_CC_P9],
    pub acc4_low: u64,
    pub acc4_high: u64,
    pub prod_9_low: u64,
    pub prod_9_high: u64,
    pub high_8: u64,
    pub low_15: u64,
    pub prod_8_low: u64,
    pub prod_8_high: u64,
    pub ai_chunks: [u64; AI_CHUNKS_TOTAL],
    pub pl_chunks: [u64; PL_CHUNKS_TOTAL],
    pub ph_chunks: [u64; PH_CHUNKS_TOTAL],
    pub pe_chunks: [u64; PE_CHUNKS_TOTAL],
    pub l15_chunks: [u64; L15_CHUNKS_TOTAL],
    pub oc_chunks: [u64; OC_CHUNKS_TOTAL],
    pub cc_chain: [u64; CC_CHAIN_TOTAL],
}

/// Compute one pass of second-fold canonicalization (full chunked).
pub fn compute_second_fold_chunked_witness(acc_in: &[u128; 10]) -> SecondFoldChunkedWitness {
    let limb_9 = acc_in[9] as u64;
    let high_8 = (acc_in[8] >> 15) as u64;
    let low_15 = (acc_in[8] & ((1u128 << 15) - 1)) as u64;

    let a_lo = limb_9 & (PIECE_MOD_9 - 1);
    let a_mid = (limb_9 >> 7) & (PIECE_MOD_9 - 1);
    let a_hi = (limb_9 >> 14) & (PIECE_MOD_9 - 1);

    let q_lo = a_lo * FOLD_M;
    let q_mid = a_mid * FOLD_M;
    let q_hi = a_hi * FOLD_M;

    // Q-chunk decomposition.
    let mask_7 = (1u64 << 7) - 1;
    let mask_6 = (1u64 << 6) - 1;
    let mask_10 = (1u64 << 10) - 1;
    let mut q_chunks = [0u64; Q_CHUNKS_TOTAL];
    for (q_idx, &q_val) in [q_lo, q_mid, q_hi].iter().enumerate() {
        q_chunks[q_idx * 4] = q_val & mask_7;
        q_chunks[q_idx * 4 + 1] = (q_val >> 7) & mask_7;
        q_chunks[q_idx * 4 + 2] = (q_val >> 14) & mask_7;
        q_chunks[q_idx * 4 + 3] = (q_val >> 21) & mask_6;
    }

    // Gap #1 position chain.
    let qa = [q_chunks[0], q_chunks[1], q_chunks[2], q_chunks[3]];
    let qb = [q_chunks[4], q_chunks[5], q_chunks[6], q_chunks[7]];
    let qc = [q_chunks[8], q_chunks[9], q_chunks[10], q_chunks[11]];

    let mut acc_p9 = [0u64; ACC_P9_LEN];
    let mut cc_p9 = [0u64; NUM_CC_P9];

    let r0 = qa[0];
    acc_p9[0] = r0 & mask_7;
    cc_p9[0] = r0 >> 7;
    let r1 = qa[1] + qb[0] + cc_p9[0];
    acc_p9[1] = r1 & mask_7;
    cc_p9[1] = r1 >> 7;
    let r2 = qa[2] + qb[1] + qc[0] + cc_p9[1];
    acc_p9[2] = r2 & mask_7;
    cc_p9[2] = r2 >> 7;
    let r3 = qa[3] + qb[2] + qc[1] + cc_p9[2];
    acc_p9[3] = r3 & mask_7;
    cc_p9[3] = r3 >> 7;
    let r4 = qb[3] + qc[2] + cc_p9[3];
    acc_p9[4] = r4 & mask_7;
    cc_p9[4] = r4 >> 7;
    let r5 = qc[3] + cc_p9[4];
    acc_p9[5] = r5;

    let acc4_low = acc_p9[4] & 0b11;
    let acc4_high = acc_p9[4] >> 2;

    let prod_9_low = acc_p9[0] + (acc_p9[1] << 7) + (acc_p9[2] << 14) + (acc_p9[3] << 21) + (acc4_low << 28);
    let prod_9_high = acc4_high + (acc_p9[5] << 5);

    let prod_8 = high_8 * 19;
    let prod_8_low = prod_8 & ((1u64 << 30) - 1);
    let prod_8_high = prod_8 >> 30;

    // Output chunked chain.
    let mut ai_chunks = [0u64; AI_CHUNKS_TOTAL];
    for m in 0..NUM_AI_LIMBS {
        let v = acc_in[m] as u64;
        ai_chunks[3 * m] = v & mask_10;
        ai_chunks[3 * m + 1] = (v >> 10) & mask_10;
        ai_chunks[3 * m + 2] = (v >> 20) & mask_10;
    }

    let mut pl_chunks = [0u64; PL_CHUNKS_TOTAL];
    pl_chunks[0] = prod_9_low & mask_10;
    pl_chunks[1] = (prod_9_low >> 10) & mask_10;
    pl_chunks[2] = (prod_9_low >> 20) & mask_10;

    let mut ph_chunks = [0u64; PH_CHUNKS_TOTAL];
    ph_chunks[0] = prod_9_high & mask_10;
    ph_chunks[1] = (prod_9_high >> 10) & ((1u64 << PH_CHUNK_HI_BITS) - 1);

    let mut pe_chunks = [0u64; PE_CHUNKS_TOTAL];
    pe_chunks[0] = prod_8_low & mask_10;
    pe_chunks[1] = (prod_8_low >> 10) & mask_10;

    let mut l15_chunks = [0u64; L15_CHUNKS_TOTAL];
    l15_chunks[0] = low_15 & mask_10;
    l15_chunks[1] = (low_15 >> 10) & ((1u64 << L15_CHUNK_HI_BITS) - 1);

    // Compute output chunks via position chain (10-bit).
    let mut oc_chunks = [0u64; OC_CHUNKS_TOTAL];
    let mut cc_chain = [0u64; CC_CHAIN_TOTAL];
    let mut acc_out = [0u64; 10];
    let mut prev_inter: u64 = 0;

    for m in 0..NUM_LIMBS_OUT {
        // Position 0
        let mut rhs_p0 = prev_inter;
        match m {
            0 => rhs_p0 += ai_chunks[0] + pl_chunks[0] + pe_chunks[0],
            1 => rhs_p0 += ai_chunks[3] + ph_chunks[0],
            m if (2..=7).contains(&m) => rhs_p0 += ai_chunks[3 * m],
            8 => rhs_p0 += l15_chunks[0],
            9 => {}
            _ => unreachable!(),
        }
        oc_chunks[3 * m] = rhs_p0 & mask_10;
        let cc0 = rhs_p0 >> 10;
        cc_chain[3 * m] = cc0;

        // Position 1
        let mut rhs_p1 = cc0;
        match m {
            0 => rhs_p1 += ai_chunks[1] + pl_chunks[1] + pe_chunks[1],
            1 => rhs_p1 += ai_chunks[4] + ph_chunks[1],
            m if (2..=7).contains(&m) => rhs_p1 += ai_chunks[3 * m + 1],
            8 => rhs_p1 += l15_chunks[1],
            9 => {}
            _ => unreachable!(),
        }
        oc_chunks[3 * m + 1] = rhs_p1 & mask_10;
        let cc1 = rhs_p1 >> 10;
        cc_chain[3 * m + 1] = cc1;

        // Position 2
        let mut rhs_p2 = cc1;
        match m {
            0 => rhs_p2 += ai_chunks[2] + pl_chunks[2],
            1 => rhs_p2 += ai_chunks[5],
            m if (2..=7).contains(&m) => rhs_p2 += ai_chunks[3 * m + 2],
            8 | 9 => {}
            _ => unreachable!(),
        }
        oc_chunks[3 * m + 2] = rhs_p2 & mask_10;
        let cc2 = rhs_p2 >> 10;
        cc_chain[3 * m + 2] = cc2;

        acc_out[m] = oc_chunks[3 * m] + (oc_chunks[3 * m + 1] << 10) + (oc_chunks[3 * m + 2] << 20);

        prev_inter = cc2;
    }

    debug_assert_eq!(cc_chain[3 * (NUM_LIMBS_OUT - 1) + 2], 0, "second_fold_chunked: cc_chain[9][2] must be 0 (no carry past limb 9)");

    SecondFoldChunkedWitness {
        acc_in: *acc_in,
        acc_out,
        limb_9_pieces: [a_lo, a_mid, a_hi],
        q_pieces: [q_lo, q_mid, q_hi],
        q_chunks,
        acc_p9,
        cc_p9,
        acc4_low,
        acc4_high,
        prod_9_low,
        prod_9_high,
        high_8,
        low_15,
        prod_8_low,
        prod_8_high,
        ai_chunks,
        pl_chunks,
        ph_chunks,
        pe_chunks,
        l15_chunks,
        oc_chunks,
        cc_chain,
    }
}

impl<F: Field> BaseAir<F> for SecondFoldChunkedChip {
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

impl<AB: AirBuilder> Air<AB> for SecondFoldChunkedChip
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        self.emit(builder);
    }
}

/// Populate one row of trace at `(row_off, start_col)`.
pub fn populate_row<F: Field + PrimeCharacteristicRing>(
    values: &mut [F],
    row_off: usize,
    start_col: usize,
    acc_in: &[u128; 10],
) -> SecondFoldChunkedWitness {
    let w = compute_second_fold_chunked_witness(acc_in);
    let base = row_off + start_col;

    // Structural cells.
    for i in 0..NUM_LIMBS_OUT {
        values[base + col::ACC_IN + i] = F::from_u64(acc_in[i] as u64);
        values[base + col::ACC_OUT + i] = F::from_u64(w.acc_out[i]);
    }
    for i in 0..NUM_LIMB9_PIECES {
        values[base + col::LIMB_9_PIECES + i] = F::from_u64(w.limb_9_pieces[i]);
    }
    for i in 0..NUM_QS {
        values[base + col::Q_PIECES + i] = F::from_u64(w.q_pieces[i]);
    }
    values[base + col::PROD_9_LOW] = F::from_u64(w.prod_9_low);
    values[base + col::PROD_9_HIGH] = F::from_u64(w.prod_9_high);
    values[base + col::HIGH_8] = F::from_u64(w.high_8);
    values[base + col::LOW_15] = F::from_u64(w.low_15);
    values[base + col::PROD_8_LOW] = F::from_u64(w.prod_8_low);
    values[base + col::PROD_8_HIGH] = F::from_u64(w.prod_8_high);

    // Gap #1 cells.
    for i in 0..Q_CHUNKS_TOTAL {
        values[base + col::Q_CHUNKS + i] = F::from_u64(w.q_chunks[i]);
    }
    for i in 0..ACC_P9_LEN {
        values[base + col::ACC_P9 + i] = F::from_u64(w.acc_p9[i]);
    }
    values[base + col::ACC4_LOW] = F::from_u64(w.acc4_low);
    values[base + col::ACC4_HIGH] = F::from_u64(w.acc4_high);
    for i in 0..NUM_CC_P9 {
        values[base + col::CC_P9 + i] = F::from_u64(w.cc_p9[i]);
    }

    // Gap #2/#3/#4 cells.
    for i in 0..AI_CHUNKS_TOTAL {
        values[base + col::AI_CHUNKS + i] = F::from_u64(w.ai_chunks[i]);
    }
    for i in 0..PL_CHUNKS_TOTAL {
        values[base + col::PL_CHUNKS + i] = F::from_u64(w.pl_chunks[i]);
    }
    for i in 0..PH_CHUNKS_TOTAL {
        values[base + col::PH_CHUNKS + i] = F::from_u64(w.ph_chunks[i]);
    }
    for i in 0..PE_CHUNKS_TOTAL {
        values[base + col::PE_CHUNKS + i] = F::from_u64(w.pe_chunks[i]);
    }
    for i in 0..L15_CHUNKS_TOTAL {
        values[base + col::L15_CHUNKS + i] = F::from_u64(w.l15_chunks[i]);
    }
    for i in 0..OC_CHUNKS_TOTAL {
        values[base + col::OC_CHUNKS + i] = F::from_u64(w.oc_chunks[i]);
    }
    for i in 0..CC_CHAIN_TOTAL {
        values[base + col::CC_CHAIN + i] = F::from_u64(w.cc_chain[i]);
    }

    // Bit decomp populations.
    for i in 0..NUM_LIMB9_PIECES {
        RangeNChip::<PIECE_BITS_9>::populate_bits::<F>(values, base + col::LIMB9_BITS_BASE + i * PIECE_BITS_9, w.limb_9_pieces[i]);
    }
    for q_idx in 0..NUM_QS {
        let group_off = base + col::Q_CHUNKS_BITS_BASE + q_idx * (3 * Q_CHUNK_BITS_LOW + Q_CHUNK_BITS_HIGH);
        for chunk_idx in 0..Q_CHUNKS_PER_Q {
            let value = w.q_chunks[q_idx * Q_CHUNKS_PER_Q + chunk_idx];
            if chunk_idx < 3 {
                RangeNChip::<Q_CHUNK_BITS_LOW>::populate_bits::<F>(values, group_off + chunk_idx * Q_CHUNK_BITS_LOW, value);
            } else {
                RangeNChip::<Q_CHUNK_BITS_HIGH>::populate_bits::<F>(values, group_off + 3 * Q_CHUNK_BITS_LOW, value);
            }
        }
    }
    for i in 0..ACC_P9_LEN {
        RangeNChip::<ACC_P9_WIDTH>::populate_bits::<F>(values, base + col::ACC_P9_BITS_BASE + i * ACC_P9_WIDTH, w.acc_p9[i]);
    }
    RangeNChip::<ACC4_LOW_WIDTH>::populate_bits::<F>(values, base + col::ACC4_LOW_BITS_BASE, w.acc4_low);
    RangeNChip::<ACC4_HIGH_WIDTH>::populate_bits::<F>(values, base + col::ACC4_HIGH_BITS_BASE, w.acc4_high);
    for i in 0..NUM_CC_P9 {
        RangeNChip::<CC_P9_WIDTH>::populate_bits::<F>(values, base + col::CC_P9_BITS_BASE + i * CC_P9_WIDTH, w.cc_p9[i]);
    }
    RangeNChip::<HIGH_8_BITS>::populate_bits::<F>(values, base + col::HIGH_8_BITS_BASE, w.high_8);

    for i in 0..AI_CHUNKS_TOTAL {
        RangeNChip::<PIECE_BITS_OUT>::populate_bits::<F>(values, base + col::AI_CHUNKS_BITS_BASE + i * PIECE_BITS_OUT, w.ai_chunks[i]);
    }
    for i in 0..PL_CHUNKS_TOTAL {
        RangeNChip::<PIECE_BITS_OUT>::populate_bits::<F>(values, base + col::PL_CHUNKS_BITS_BASE + i * PIECE_BITS_OUT, w.pl_chunks[i]);
    }
    RangeNChip::<PIECE_BITS_OUT>::populate_bits::<F>(values, base + col::PH_CHUNKS_BITS_BASE, w.ph_chunks[0]);
    RangeNChip::<PH_CHUNK_HI_BITS>::populate_bits::<F>(values, base + col::PH_CHUNKS_BITS_BASE + PIECE_BITS_OUT, w.ph_chunks[1]);
    for i in 0..PE_CHUNKS_TOTAL {
        RangeNChip::<PIECE_BITS_OUT>::populate_bits::<F>(values, base + col::PE_CHUNKS_BITS_BASE + i * PIECE_BITS_OUT, w.pe_chunks[i]);
    }
    RangeNChip::<PIECE_BITS_OUT>::populate_bits::<F>(values, base + col::L15_CHUNKS_BITS_BASE, w.l15_chunks[0]);
    RangeNChip::<L15_CHUNK_HI_BITS>::populate_bits::<F>(values, base + col::L15_CHUNKS_BITS_BASE + PIECE_BITS_OUT, w.l15_chunks[1]);
    for i in 0..OC_CHUNKS_TOTAL {
        RangeNChip::<PIECE_BITS_OUT>::populate_bits::<F>(values, base + col::OC_CHUNKS_BITS_BASE + i * PIECE_BITS_OUT, w.oc_chunks[i]);
    }
    for i in 0..CC_CHAIN_TOTAL {
        RangeNChip::<CC_CHAIN_BITS>::populate_bits::<F>(values, base + col::CC_CHAIN_BITS_BASE + i * CC_CHAIN_BITS, w.cc_chain[i]);
    }

    w
}

/// Build a 4-row test trace exercising one chunked fold pass.
pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(acc_in: &[u128; 10]) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    let zero = [0u128; 10];
    for row in 0..HEIGHT {
        populate_row::<F>(&mut values, row * NUM_COLS, 0, &zero);
    }
    populate_row::<F>(&mut values, 0, 0, acc_in);

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeField32;

    fn read_acc_out(values: &[BabyBear]) -> [u64; 10] {
        let mut out = [0u64; 10];
        for i in 0..10 {
            out[i] = values[col::ACC_OUT + i].as_canonical_u32() as u64;
        }
        out
    }

    #[test]
    fn second_fold_chunked_zero_input() {
        let acc_in = [0u128; 10];
        let trace = build_test_trace::<BabyBear>(&acc_in);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
        assert_eq!(read_acc_out(&trace.values), [0u64; 10]);
    }

    #[test]
    fn second_fold_chunked_only_limb_9_set() {
        let mut acc_in = [0u128; 10];
        acc_in[9] = 1;
        let trace = build_test_trace::<BabyBear>(&acc_in);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
        let out = read_acc_out(&trace.values);
        assert_eq!(out[0], FOLD_M);
        for i in 1..10 {
            assert_eq!(out[i], 0, "limb {i} should be zero");
        }
    }

    #[test]
    fn second_fold_chunked_only_limb_8_high_bits() {
        let mut acc_in = [0u128; 10];
        acc_in[8] = 1u128 << 15;
        let trace = build_test_trace::<BabyBear>(&acc_in);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
        let out = read_acc_out(&trace.values);
        assert_eq!(out[0], 19);
        for i in 1..10 {
            assert_eq!(out[i], 0, "limb {i} should be zero");
        }
    }

    #[test]
    fn second_fold_chunked_max_limb_9_within_bound() {
        let mut acc_in = [0u128; 10];
        acc_in[9] = (1u128 << 21) - 1;
        let trace = build_test_trace::<BabyBear>(&acc_in);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
        let out = read_acc_out(&trace.values);
        assert_eq!(out[9], 0);
    }

    #[test]
    fn second_fold_chunked_combined_overflow() {
        let mut acc_in = [0u128; 10];
        acc_in[0] = 12345;
        acc_in[8] = (1u128 << 15) + 7;
        acc_in[9] = 100;
        let trace = build_test_trace::<BabyBear>(&acc_in);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
    }

    #[test]
    fn second_fold_chunked_max_canonical_acc_in() {
        // Stress: every acc_in limb at 2^30 - 1 (max canonical from FirstFoldChunked).
        let mut acc_in = [0u128; 10];
        for i in 0..8 {
            acc_in[i] = (1u128 << 30) - 1;
        }
        // limb 8: max canonical (high_8 max + low_15 max)
        acc_in[8] = ((1u128 << 15) - 1) | (((1u128 << 15) - 1) << 15);
        // limb 9: max within 2^21 (the documented bound).
        acc_in[9] = (1u128 << 21) - 1;
        let trace = build_test_trace::<BabyBear>(&acc_in);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
    }

    #[test]
    fn second_fold_chunked_matches_witness_function() {
        let mut acc_in = [0u128; 10];
        // Use values within 2^30 bound (FirstFoldChunked output guarantee).
        acc_in[0] = 0x1EAD_BEEF; // 0xDEAD_BEEF & 0x3FFF_FFFF
        acc_in[3] = 0x0AFE_F00D; // 0xCAFE_F00D & 0x3FFF_FFFF
        acc_in[8] = (1u128 << 15) + 0x1234;
        acc_in[9] = 0x1F_FFFF;
        let w = compute_second_fold_chunked_witness(&acc_in);
        let prod_9_full = w.prod_9_low + (w.prod_9_high << 30);
        let q_lo = w.q_pieces[0] as u128;
        let q_mid = w.q_pieces[1] as u128;
        let q_hi = w.q_pieces[2] as u128;
        let prod_9_direct = (q_lo + (q_mid << 7) + (q_hi << 14)) as u64;
        assert_eq!(prod_9_full, prod_9_direct);
        // Validate output chunk recomp.
        for m in 0..NUM_LIMBS_OUT {
            let recomp = w.oc_chunks[3 * m] + (w.oc_chunks[3 * m + 1] << 10) + (w.oc_chunks[3 * m + 2] << 20);
            assert_eq!(w.acc_out[m], recomp, "acc_out[{m}] != chunk recomp");
        }
        let trace = build_test_trace::<BabyBear>(&acc_in);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
    }

    #[test]
    fn layout_offsets_documented() {
        assert_eq!(col::ACC_IN, 0);
        assert_eq!(col::ACC_OUT, 10);
        assert_eq!(col::Q_CHUNKS, 32);
        assert_eq!(col::ACC_P9, 44);
        assert_eq!(col::CC_P9, 52);
        assert_eq!(col::AI_CHUNKS, 57);
        assert_eq!(col::PL_CHUNKS, 81);
        assert_eq!(col::PH_CHUNKS, 84);
        assert_eq!(col::PE_CHUNKS, 86);
        assert_eq!(col::L15_CHUNKS, 88);
        assert_eq!(col::OC_CHUNKS, 90);
        assert_eq!(col::CC_CHAIN, 120);
        assert_eq!(col::STRUCTURAL_END, 150);
    }

    // ===== Soundness: tampered cell rejection =====

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_tampered_acc_out() {
        let mut acc_in = [0u128; 10];
        acc_in[9] = 5;
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        trace.values[col::ACC_OUT] += BabyBear::from_u64(1);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_limb9_piece_above_2_to_7() {
        let acc_in = [0u128; 10];
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        trace.values[col::LIMB_9_PIECES] = BabyBear::from_u64(128);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_high_8_above_2_to_15() {
        let acc_in = [0u128; 10];
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        trace.values[col::HIGH_8] = BabyBear::from_u64(1u64 << 15);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_nonzero_prod_8_high() {
        let acc_in = [0u128; 10];
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        trace.values[col::PROD_8_HIGH] = BabyBear::from_u64(1);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_q_chunk_above_2_to_7() {
        let mut acc_in = [0u128; 10];
        acc_in[9] = 1;
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        trace.values[col::Q_CHUNKS] = BabyBear::from_u64(128);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_q_chunk3_above_2_to_6() {
        let mut acc_in = [0u128; 10];
        acc_in[9] = (1u128 << 21) - 1;
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        trace.values[col::Q_CHUNKS + 3] = BabyBear::from_u64(64);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_acc_p9_bit_tampering() {
        let mut acc_in = [0u128; 10];
        acc_in[9] = (1u128 << 21) - 1;
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        let bit_off = col::ACC_P9_BITS_BASE;
        trace.values[bit_off] += BabyBear::ONE;
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
    }

    // ===== Gap #2 closure: output chunked chain rejection =====

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_oc_chunk_above_2_to_10() {
        let mut acc_in = [0u128; 10];
        acc_in[0] = 12345;
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        trace.values[col::OC_CHUNKS] = BabyBear::from_u64(1024);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_cc_chain_above_4_bits() {
        let mut acc_in = [0u128; 10];
        acc_in[0] = 12345;
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        trace.values[col::CC_CHAIN] = BabyBear::from_u64(16);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_ai_chunk_above_2_to_10() {
        let mut acc_in = [0u128; 10];
        acc_in[5] = 0x12345;
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        // ai_chunks for limb 5 are at offset 5*3 = 15.
        trace.values[col::AI_CHUNKS + 15] = BabyBear::from_u64(1024);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_pl_chunk_above_2_to_10() {
        let mut acc_in = [0u128; 10];
        acc_in[9] = 100;
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        trace.values[col::PL_CHUNKS] = BabyBear::from_u64(1024);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_ph_chunk_hi_above_2_to_2() {
        let mut acc_in = [0u128; 10];
        acc_in[9] = (1u128 << 21) - 1;
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        // ph_chunks[1] is the 2-bit hi chunk of prod_9_high.
        trace.values[col::PH_CHUNKS + 1] = BabyBear::from_u64(4);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_l15_chunk_hi_above_2_to_5() {
        let mut acc_in = [0u128; 10];
        acc_in[8] = 0x4321;
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        // l15_chunks[1] is the 5-bit hi chunk of low_15.
        trace.values[col::L15_CHUNKS + 1] = BabyBear::from_u64(32);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
    }

    /// k=1 BB-wrap forge attempt on acc_out[0]. Original chip had
    /// `acc_out[0] + 2^30·carry[0] = acc_in[0] + prod_9_low + prod_8_low`
    /// with RHS_max ≈ 3·2^30 > p, allowing alt = honest - p forge. In
    /// the chunked design every position equation has bound < 2^14 ≪ p,
    /// so no BB-wrap class is reachable. Tampering breaks the chain.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_bb_wrap_acc_out_0_forge() {
        let mut acc_in = [0u128; 10];
        for i in 0..8 {
            acc_in[i] = (1u128 << 30) - 1;
        }
        acc_in[9] = (1u128 << 21) - 1;
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        // Tamper acc_out[0] by 1024 (would BB-wrap if range checks absent).
        let honest = trace.values[col::ACC_OUT];
        trace.values[col::ACC_OUT] = honest + BabyBear::from_u64(1024);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
    }

    /// Forge attempt on a non-limb-0 output: even though limbs 1..9 had
    /// RHS < p in the original chip, the loose carry range allowed
    /// (carry_alt = honest_carry + 1, acc_out_alt = honest_alt - 2^30 + p)
    /// to pass. Chunked closure prevents this universally.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_bb_wrap_acc_out_5_forge() {
        let mut acc_in = [0u128; 10];
        for i in 0..8 {
            acc_in[i] = (1u128 << 30) - 1;
        }
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        let honest = trace.values[col::ACC_OUT + 5];
        trace.values[col::ACC_OUT + 5] = honest + BabyBear::from_u64(1024);
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
    }

    /// Tampering oc_chunks[0] (low chunk of acc_out[0]) breaks acc_out
    /// reconstruction.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_oc_chunk_value_mismatch() {
        let mut acc_in = [0u128; 10];
        acc_in[0] = 0xABCD;
        let mut trace = build_test_trace::<BabyBear>(&acc_in);
        let honest = trace.values[col::OC_CHUNKS];
        trace.values[col::OC_CHUNKS] = honest + BabyBear::ONE;
        check_constraints(&SecondFoldChunkedChip::new(), &trace, &[]);
    }
}
