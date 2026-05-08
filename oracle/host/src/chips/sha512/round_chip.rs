//! `sha512::round_chip` — full SHA-512 round AIR.
//!
//! Composes the higher-order and primitive SHA-512 chips into a single
//! AIR that constrains one round of the compression function. The
//! biggest single chip in the SHA-512 stack.
//!
//! ## Round transform (FIPS 180-4 §6.4.2)
//!
//! ```text
//! T1   = h + Σ1(e) + Ch(e, f, g) + K[i] + W[i]   (mod 2⁶⁴)
//! T2   = Σ0(a) + Maj(a, b, c)                     (mod 2⁶⁴)
//! new_a = T1 + T2
//! new_e = d + T1
//! new_b = a, new_c = b, new_d = c
//! new_f = e, new_g = f, new_h = g
//! ```
//!
//! ## Composition strategy
//!
//! Each constituent chip occupies its own private column slice. Inputs
//! and outputs are wired via chunk-level `assert_eq` connection
//! constraints rather than column sharing — verbose but auditable.
//!
//! Constituent chips:
//!
//!   - `BigSigmaChip<14, 18, 41>`  → Σ1(e)
//!   - `BigSigmaChip<28, 34, 39>`  → Σ0(a)
//!   - `ChChip`                    → Ch(e, f, g)
//!   - `MajChip`                   → Maj(a, b, c)
//!   - 7 × `Word64AddChip`         → T1 chain (4) + T2 + new_e + new_a
//!
//! ## Layout
//!
//! | Range       | Width | Contents                             |
//! |-------------|-------|--------------------------------------|
//! | 0..40       | 40    | state inputs: a..h chunks, K, W      |
//! | 40..72      | 32    | state outputs: new_a..new_h chunks   |
//! | 72..272     | 200   | BigSigmaChip<14,18,41>  (Σ1 of e)    |
//! | 272..672    | 400   | ChChip                  (Ch(e,f,g))  |
//! | 672..872    | 200   | BigSigmaChip<28,34,39>  (Σ0 of a)    |
//! | 872..1400   | 528   | MajChip                 (Maj(a,b,c)) |
//! | 1400..1416  | 16    | Word64AddChip  (h + Σ1)            t11 |
//! | 1416..1432  | 16    | Word64AddChip  (t11 + Ch)         t12 |
//! | 1432..1448  | 16    | Word64AddChip  (t12 + K)          t13 |
//! | 1448..1464  | 16    | Word64AddChip  (t13 + W)          T1  |
//! | 1464..1480  | 16    | Word64AddChip  (Σ0 + Maj)         T2  |
//! | 1480..1496  | 16    | Word64AddChip  (d + T1)         new_e |
//! | 1496..1512  | 16    | Word64AddChip  (T1 + T2)        new_a |
//!
//! Total: **1512 columns**, **~1860 constraints** (degree 2 max).
//! After sub-fase 3.7.0 (7 word64_add embeds × +192 bit cells):
//! **2856 columns**.
//!
//! ## Soundness (audit 3.7.2)
//!
//! The 18 chunk slots in cols 0..72 (state inputs `A..H`, `K`, `W`,
//! state outputs `NEW_A..NEW_H`) are **transitively range-checked**
//! via the connection asserts to bit-decomposed sub-chips:
//!
//!   - `A` ↔ `BigSigma_a.x_chunks`, `Maj.A_CHUNKS` (sound: bit decomp)
//!   - `B` ↔ `Maj.B_CHUNKS` (sound)
//!   - `C` ↔ `Maj.C_CHUNKS` (sound)
//!   - `D` ↔ `add_new_e.A` (sound: 3.7.0)
//!   - `E` ↔ `BigSigma_e.x_chunks`, `Ch.E_CHUNKS` (sound)
//!   - `F` ↔ `Ch.F_CHUNKS` (sound)
//!   - `G` ↔ `Ch.G_CHUNKS` (sound)
//!   - `H` ↔ `add_t1_1.A` (sound: 3.7.0)
//!   - `K` ↔ `add_t1_3.B` (sound: 3.7.0)
//!   - `W` ↔ `add_t1_4.B` (sound: 3.7.0)
//!   - `NEW_A` ↔ `add_new_a.C` (sound)
//!   - `NEW_B`/`NEW_C`/`NEW_D` ↔ `A`/`B`/`C` (transitively sound)
//!   - `NEW_E` ↔ `add_new_e.C` (sound)
//!   - `NEW_F`/`NEW_G`/`NEW_H` ↔ `E`/`F`/`G` (transitively sound)
//!
//! Hence `round_chip` has no standalone range-check gap once 3.7.0 is
//! in place. No additional witness cells needed for soundness — the
//! `assert_chunks_eq` constraints carry the canonical-chunk property
//! through the chip's connection mesh.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::big_sigma::{BigSigmaChip, NUM_COLS as BIG_SIGMA_COLS, col as bsc};
use super::ch::{ChChip, NUM_COLS as CH_COLS, col as chc};
use super::maj::{MajChip, NUM_COLS as MAJ_COLS, col as mjc};
use super::word64_add::{NUM_COLS as ADD_COLS, Word64AddChip, col as adc};

pub const NUM_CHUNKS: usize = 4;

pub mod col {
    use super::*;

    // State inputs (40 cols).
    pub const A: usize = 0;
    pub const B: usize = A + NUM_CHUNKS;       // 4
    pub const C: usize = B + NUM_CHUNKS;       // 8
    pub const D: usize = C + NUM_CHUNKS;       // 12
    pub const E: usize = D + NUM_CHUNKS;       // 16
    pub const F: usize = E + NUM_CHUNKS;       // 20
    pub const G: usize = F + NUM_CHUNKS;       // 24
    pub const H: usize = G + NUM_CHUNKS;       // 28
    pub const K: usize = H + NUM_CHUNKS;       // 32
    pub const W: usize = K + NUM_CHUNKS;       // 36

    // State outputs (32 cols).
    pub const NEW_A: usize = W + NUM_CHUNKS;   // 40
    pub const NEW_B: usize = NEW_A + NUM_CHUNKS; // 44
    pub const NEW_C: usize = NEW_B + NUM_CHUNKS; // 48
    pub const NEW_D: usize = NEW_C + NUM_CHUNKS; // 52
    pub const NEW_E: usize = NEW_D + NUM_CHUNKS; // 56
    pub const NEW_F: usize = NEW_E + NUM_CHUNKS; // 60
    pub const NEW_G: usize = NEW_F + NUM_CHUNKS; // 64
    pub const NEW_H: usize = NEW_G + NUM_CHUNKS; // 68

    pub const STATE_END: usize = NEW_H + NUM_CHUNKS; // 72

    // Chip slots (allocated sequentially after state).
    pub const BIG_SIGMA_E_START: usize = STATE_END;                              // 72
    pub const CH_START: usize = BIG_SIGMA_E_START + BIG_SIGMA_COLS;              // 272
    pub const BIG_SIGMA_A_START: usize = CH_START + CH_COLS;                     // 672
    pub const MAJ_START: usize = BIG_SIGMA_A_START + BIG_SIGMA_COLS;             // 872
    pub const ADD_T1_1_START: usize = MAJ_START + MAJ_COLS;                       // 1400
    pub const ADD_T1_2_START: usize = ADD_T1_1_START + ADD_COLS;                  // 1416
    pub const ADD_T1_3_START: usize = ADD_T1_2_START + ADD_COLS;                  // 1432
    pub const ADD_T1_4_START: usize = ADD_T1_3_START + ADD_COLS;                  // 1448
    pub const ADD_T2_START: usize = ADD_T1_4_START + ADD_COLS;                    // 1464
    pub const ADD_NEW_E_START: usize = ADD_T2_START + ADD_COLS;                   // 1480
    pub const ADD_NEW_A_START: usize = ADD_NEW_E_START + ADD_COLS;                // 1496

    pub const TOTAL: usize = ADD_NEW_A_START + ADD_COLS;                          // 1512
}

pub const NUM_COLS: usize = col::TOTAL;

#[derive(Debug, Clone, Copy)]
pub struct RoundChip;

impl RoundChip {
    pub const fn new() -> Self {
        Self
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        // Emit each constituent chip's constraints at its allocated start_col.
        BigSigmaChip::<14, 18, 41>::at(col::BIG_SIGMA_E_START).emit(builder);
        ChChip::at(col::CH_START).emit(builder);
        BigSigmaChip::<28, 34, 39>::at(col::BIG_SIGMA_A_START).emit(builder);
        MajChip::at(col::MAJ_START).emit(builder);
        Word64AddChip::at(col::ADD_T1_1_START).emit(builder);
        Word64AddChip::at(col::ADD_T1_2_START).emit(builder);
        Word64AddChip::at(col::ADD_T1_3_START).emit(builder);
        Word64AddChip::at(col::ADD_T1_4_START).emit(builder);
        Word64AddChip::at(col::ADD_T2_START).emit(builder);
        Word64AddChip::at(col::ADD_NEW_E_START).emit(builder);
        Word64AddChip::at(col::ADD_NEW_A_START).emit(builder);

        // Connection constraints — wire chip inputs to upstream sources via
        // chunk-level assert_eq.
        let main = builder.main();
        let row = main.current_slice();

        // Helper to assert two 4-chunk slices are equal.
        let assert_chunks_eq = |b: &mut AB, a_off: usize, b_off: usize| {
            for i in 0..NUM_CHUNKS {
                b.assert_eq(row[a_off + i], row[b_off + i]);
            }
        };

        // BigSigma_e.x_chunks ← e
        assert_chunks_eq(builder, col::BIG_SIGMA_E_START + bsc::X_CHUNKS, col::E);

        // ChChip.{e,f,g}_chunks ← e, f, g
        assert_chunks_eq(builder, col::CH_START + chc::E_CHUNKS, col::E);
        assert_chunks_eq(builder, col::CH_START + chc::F_CHUNKS, col::F);
        assert_chunks_eq(builder, col::CH_START + chc::G_CHUNKS, col::G);

        // BigSigma_a.x_chunks ← a
        assert_chunks_eq(builder, col::BIG_SIGMA_A_START + bsc::X_CHUNKS, col::A);

        // MajChip.{a,b,c}_chunks ← a, b, c
        assert_chunks_eq(builder, col::MAJ_START + mjc::A_CHUNKS, col::A);
        assert_chunks_eq(builder, col::MAJ_START + mjc::B_CHUNKS, col::B);
        assert_chunks_eq(builder, col::MAJ_START + mjc::C_CHUNKS, col::C);

        // T1 chain wiring:
        //   add1: a=h, b=Σ1.c
        assert_chunks_eq(builder, col::ADD_T1_1_START + adc::A, col::H);
        assert_chunks_eq(builder, col::ADD_T1_1_START + adc::B, col::BIG_SIGMA_E_START + bsc::C_CHUNKS);
        //   add2: a=add1.c, b=Ch.c
        assert_chunks_eq(builder, col::ADD_T1_2_START + adc::A, col::ADD_T1_1_START + adc::C);
        assert_chunks_eq(builder, col::ADD_T1_2_START + adc::B, col::CH_START + chc::C_CHUNKS);
        //   add3: a=add2.c, b=K
        assert_chunks_eq(builder, col::ADD_T1_3_START + adc::A, col::ADD_T1_2_START + adc::C);
        assert_chunks_eq(builder, col::ADD_T1_3_START + adc::B, col::K);
        //   add4: a=add3.c, b=W → T1 = add4.c
        assert_chunks_eq(builder, col::ADD_T1_4_START + adc::A, col::ADD_T1_3_START + adc::C);
        assert_chunks_eq(builder, col::ADD_T1_4_START + adc::B, col::W);

        // T2: a=Σ0.c, b=Maj.out → T2 = add5.c
        assert_chunks_eq(builder, col::ADD_T2_START + adc::A, col::BIG_SIGMA_A_START + bsc::C_CHUNKS);
        assert_chunks_eq(builder, col::ADD_T2_START + adc::B, col::MAJ_START + mjc::OUT_CHUNKS);

        // new_e: a=d, b=T1 → new_e = add6.c
        assert_chunks_eq(builder, col::ADD_NEW_E_START + adc::A, col::D);
        assert_chunks_eq(builder, col::ADD_NEW_E_START + adc::B, col::ADD_T1_4_START + adc::C);

        // new_a: a=T1, b=T2 → new_a = add7.c
        assert_chunks_eq(builder, col::ADD_NEW_A_START + adc::A, col::ADD_T1_4_START + adc::C);
        assert_chunks_eq(builder, col::ADD_NEW_A_START + adc::B, col::ADD_T2_START + adc::C);

        // State output assignments.
        assert_chunks_eq(builder, col::NEW_A, col::ADD_NEW_A_START + adc::C);
        assert_chunks_eq(builder, col::NEW_B, col::A);
        assert_chunks_eq(builder, col::NEW_C, col::B);
        assert_chunks_eq(builder, col::NEW_D, col::C);
        assert_chunks_eq(builder, col::NEW_E, col::ADD_NEW_E_START + adc::C);
        assert_chunks_eq(builder, col::NEW_F, col::E);
        assert_chunks_eq(builder, col::NEW_G, col::F);
        assert_chunks_eq(builder, col::NEW_H, col::G);
    }
}

impl<F: Field> BaseAir<F> for RoundChip {
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

impl<AB: AirBuilder> Air<AB> for RoundChip
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        self.emit(builder);
    }
}

/// Build a single-row trace exercising one full SHA-512 round.
///
/// `state` = `[a, b, c, d, e, f, g, h]` input. `k` = round constant `K[i]`.
/// `w` = message schedule word `W[i]`. Returns the populated trace.
pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(
    state: &[u64; 8],
    k: u64,
    w: u64,
) -> RowMajorMatrix<F> {
    use super::round::{Sha512State, big_sigma0, big_sigma1, ch, compute_round, maj};

    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    // Compute everything in u64 first.
    let [a, b, c, d, e, f, g, h] = *state;
    let sigma1_e = big_sigma1(e);
    let ch_efg = ch(e, f, g);
    let sigma0_a = big_sigma0(a);
    let maj_abc = maj(a, b, c);
    let t11 = h.wrapping_add(sigma1_e);
    let t12 = t11.wrapping_add(ch_efg);
    let t13 = t12.wrapping_add(k);
    let t1 = t13.wrapping_add(w);
    let t2 = sigma0_a.wrapping_add(maj_abc);
    let new_e_val = d.wrapping_add(t1);
    let new_a_val = t1.wrapping_add(t2);
    let next = compute_round(Sha512State::new(*state), k, w);

    // Populate state inputs.
    let put_chunks = |values: &mut [F], off: usize, w: u64| {
        let chunks = super::word64_add::decompose_u64(w);
        for i in 0..NUM_CHUNKS {
            values[off + i] = F::from_u64(chunks[i]);
        }
    };
    put_chunks(&mut values, col::A, a);
    put_chunks(&mut values, col::B, b);
    put_chunks(&mut values, col::C, c);
    put_chunks(&mut values, col::D, d);
    put_chunks(&mut values, col::E, e);
    put_chunks(&mut values, col::F, f);
    put_chunks(&mut values, col::G, g);
    put_chunks(&mut values, col::H, h);
    put_chunks(&mut values, col::K, k);
    put_chunks(&mut values, col::W, w);

    // State outputs.
    put_chunks(&mut values, col::NEW_A, next.a());
    put_chunks(&mut values, col::NEW_B, next.b());
    put_chunks(&mut values, col::NEW_C, next.c());
    put_chunks(&mut values, col::NEW_D, next.d());
    put_chunks(&mut values, col::NEW_E, next.e());
    put_chunks(&mut values, col::NEW_F, next.f());
    put_chunks(&mut values, col::NEW_G, next.g());
    put_chunks(&mut values, col::NEW_H, next.h());

    // Populate BigSigma_e (x = e, c = sigma1_e).
    let bs_e = super::big_sigma::compute_big_sigma(e, 14, 18, 41);
    populate_big_sigma(&mut values, col::BIG_SIGMA_E_START, &bs_e);

    // Populate ChChip.
    let ch_w = super::ch::compute_ch(e, f, g);
    populate_ch(&mut values, col::CH_START, &ch_w);

    // Populate BigSigma_a (x = a, c = sigma0_a).
    let bs_a = super::big_sigma::compute_big_sigma(a, 28, 34, 39);
    populate_big_sigma(&mut values, col::BIG_SIGMA_A_START, &bs_a);

    // Populate MajChip.
    let maj_w = super::maj::compute_maj(a, b, c);
    populate_maj(&mut values, col::MAJ_START, &maj_w);

    // Populate the 7 word64_add chips.
    let add1_w = super::word64_add::compute_add64(h, sigma1_e);
    populate_add(&mut values, col::ADD_T1_1_START, &add1_w);
    let add2_w = super::word64_add::compute_add64(t11, ch_efg);
    populate_add(&mut values, col::ADD_T1_2_START, &add2_w);
    let add3_w = super::word64_add::compute_add64(t12, k);
    populate_add(&mut values, col::ADD_T1_3_START, &add3_w);
    let add4_w = super::word64_add::compute_add64(t13, w);
    populate_add(&mut values, col::ADD_T1_4_START, &add4_w);
    let add5_w = super::word64_add::compute_add64(sigma0_a, maj_abc);
    populate_add(&mut values, col::ADD_T2_START, &add5_w);
    let add6_w = super::word64_add::compute_add64(d, t1);
    populate_add(&mut values, col::ADD_NEW_E_START, &add6_w);
    let add7_w = super::word64_add::compute_add64(t1, t2);
    populate_add(&mut values, col::ADD_NEW_A_START, &add7_w);

    // Sanity: independently-computed `next` agrees with the chip wiring.
    debug_assert_eq!(new_a_val, next.a());
    debug_assert_eq!(new_e_val, next.e());

    RowMajorMatrix::new(values, NUM_COLS)
}

fn populate_big_sigma<F: Field + PrimeCharacteristicRing>(values: &mut [F], start: usize, w: &super::big_sigma::BigSigmaWitness) {
    use super::big_sigma::{NUM_BITS, NUM_CHUNKS};
    for i in 0..NUM_CHUNKS {
        values[start + bsc::X_CHUNKS + i] = F::from_u64(w.x_chunks[i]);
        values[start + bsc::C_CHUNKS + i] = F::from_u64(w.c_chunks[i]);
    }
    for i in 0..NUM_BITS {
        values[start + bsc::X_BITS + i] = F::from_u64(w.x_bits[i]);
        values[start + bsc::MID_BITS + i] = F::from_u64(w.mid_bits[i]);
        values[start + bsc::C_BITS + i] = F::from_u64(w.c_bits[i]);
    }
}

fn populate_ch<F: Field + PrimeCharacteristicRing>(values: &mut [F], start: usize, w: &super::ch::ChWitness) {
    use super::ch::{NUM_BITS, NUM_CHUNKS};
    for i in 0..NUM_CHUNKS {
        values[start + chc::E_CHUNKS + i] = F::from_u64(w.e_chunks[i]);
        values[start + chc::F_CHUNKS + i] = F::from_u64(w.f_chunks[i]);
        values[start + chc::G_CHUNKS + i] = F::from_u64(w.g_chunks[i]);
        values[start + chc::C_CHUNKS + i] = F::from_u64(w.c_chunks[i]);
    }
    for i in 0..NUM_BITS {
        values[start + chc::E_BITS + i] = F::from_u64(w.e_bits[i]);
        values[start + chc::F_BITS + i] = F::from_u64(w.f_bits[i]);
        values[start + chc::G_BITS + i] = F::from_u64(w.g_bits[i]);
        values[start + chc::C_BITS + i] = F::from_u64(w.c_bits[i]);
        values[start + chc::EF_BITS + i] = F::from_u64(w.ef_bits[i]);
        values[start + chc::NEF_G_BITS + i] = F::from_u64(w.nef_g_bits[i]);
    }
}

fn populate_maj<F: Field + PrimeCharacteristicRing>(values: &mut [F], start: usize, w: &super::maj::MajWitness) {
    use super::maj::{NUM_BITS, NUM_CHUNKS};
    for i in 0..NUM_CHUNKS {
        values[start + mjc::A_CHUNKS + i] = F::from_u64(w.a_chunks[i]);
        values[start + mjc::B_CHUNKS + i] = F::from_u64(w.b_chunks[i]);
        values[start + mjc::C_CHUNKS + i] = F::from_u64(w.c_chunks[i]);
        values[start + mjc::OUT_CHUNKS + i] = F::from_u64(w.out_chunks[i]);
    }
    for i in 0..NUM_BITS {
        values[start + mjc::A_BITS + i] = F::from_u64(w.a_bits[i]);
        values[start + mjc::B_BITS + i] = F::from_u64(w.b_bits[i]);
        values[start + mjc::C_BITS + i] = F::from_u64(w.c_bits[i]);
        values[start + mjc::OUT_BITS + i] = F::from_u64(w.out_bits[i]);
        values[start + mjc::AB_BITS + i] = F::from_u64(w.ab_bits[i]);
        values[start + mjc::AC_BITS + i] = F::from_u64(w.ac_bits[i]);
        values[start + mjc::BC_BITS + i] = F::from_u64(w.bc_bits[i]);
        values[start + mjc::MID_BITS + i] = F::from_u64(w.mid_bits[i]);
    }
}

fn populate_add<F: Field + PrimeCharacteristicRing>(values: &mut [F], start: usize, w: &super::word64_add::Word64AddWitness) {
    use super::word64_add::NUM_CHUNKS;
    use crate::chips::lookup::range_n::Range16Chip;
    for i in 0..NUM_CHUNKS {
        values[start + adc::A + i] = F::from_u64(w.a_chunks[i]);
        values[start + adc::B + i] = F::from_u64(w.b_chunks[i]);
        values[start + adc::C + i] = F::from_u64(w.c_chunks[i]);
        values[start + adc::CARRY + i] = F::from_u64(w.carries[i]);
        // Sub-fase 3.7.0 — populate 16-bit decomposition cells.
        Range16Chip::populate_bits::<F>(values, start + adc::A_BITS + i * 16, w.a_chunks[i]);
        Range16Chip::populate_bits::<F>(values, start + adc::B_BITS + i * 16, w.b_chunks[i]);
        Range16Chip::populate_bits::<F>(values, start + adc::C_BITS + i * 16, w.c_chunks[i]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::constants::{H_INITIAL, K};
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeField32;

    /// Round 0 of SHA-512("abc"): the single most-canonical SHA-512 test vector.
    /// Validated end-to-end against FIPS 180-4 Appendix C.1 intermediate state.
    #[test]
    fn round_zero_of_sha512_abc_satisfies_air() {
        let state = H_INITIAL;
        let k = K[0];
        let w = 0x6162638000000000u64; // 'abc' || 0x80 || zeros
        let trace = build_test_trace::<BabyBear>(&state, k, w);
        check_constraints(&RoundChip, &trace, &[]);
    }

    #[test]
    fn round_zero_of_zero_state_satisfies_air() {
        let state = [0u64; 8];
        let trace = build_test_trace::<BabyBear>(&state, 0, 0);
        check_constraints(&RoundChip, &trace, &[]);
    }

    #[test]
    fn round_with_random_inputs_satisfies_air() {
        let state: [u64; 8] = [
            0x1234_5678_9ABC_DEF0,
            0xFEDC_BA09_8765_4321,
            0xCAFE_BABE_DEAD_BEEF,
            0x0000_0000_FFFF_FFFF,
            0xAAAA_AAAA_AAAA_AAAA,
            0x5555_5555_5555_5555,
            u64::MAX,
            0,
        ];
        let trace = build_test_trace::<BabyBear>(&state, 0xDEADBEEF_CAFEBABE, 0xBADCFE_12345678);
        check_constraints(&RoundChip, &trace, &[]);
    }

    #[test]
    fn round_zero_intermediate_matches_fips_appendix_c() {
        // After round 0 of SHA-512("abc"), state should be the FIPS-published
        // intermediate. Reading the chip's NEW_* output cols.
        let state = H_INITIAL;
        let k = K[0];
        let w = 0x6162638000000000u64;
        let trace = build_test_trace::<BabyBear>(&state, k, w);

        // Read NEW_A chunks back as a u64.
        let read_word = |off: usize| -> u64 {
            let mut chunks = [0u64; 4];
            for i in 0..4 {
                chunks[i] = trace.values[off + i].as_canonical_u32() as u64;
            }
            chunks[0] | (chunks[1] << 16) | (chunks[2] << 32) | (chunks[3] << 48)
        };
        // FIPS 180-4 Appendix C.1, t=0 row: a = 0xf6afceb8bcfcddf5.
        assert_eq!(read_word(col::NEW_A), 0xf6afceb8bcfcddf5);
        // e = 0x58cb02347ab51f91
        assert_eq!(read_word(col::NEW_E), 0x58cb02347ab51f91);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn round_rejects_tampered_new_a() {
        let state = H_INITIAL;
        let k = K[0];
        let w = 0x6162638000000000u64;
        let mut trace = build_test_trace::<BabyBear>(&state, k, w);
        trace.values[col::NEW_A] = trace.values[col::NEW_A] + BabyBear::ONE;
        check_constraints(&RoundChip, &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        // Sub-fase 3.7.0: 7 word64_add embeds × +192 bit cells = +1344.
        // 1512 + 1344 = 2856.
        assert_eq!(NUM_COLS, 2856);
    }
}
