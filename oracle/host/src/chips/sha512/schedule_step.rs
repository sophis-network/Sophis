//! `sha512::schedule_step` — single message-schedule extension step.
//!
//! Implements one iteration of the SHA-512 message schedule:
//!
//!   `W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]   (mod 2⁶⁴)`
//!
//! for `t ∈ [16, 80)`. Composing 64 of these chips (one per `t`) plus the
//! direct `W[0..16]` block words gives the full 80-word schedule used by
//! the SHA-512 compression function.
//!
//! ## Composition strategy
//!
//! Same chunk-level connection-constraint pattern as `RoundChip`. Each
//! constituent chip occupies its private column slot; chip inputs and
//! outputs are wired via `assert_eq` on chunk slices.
//!
//! Constituent chips:
//!
//!   - `SmallSigmaChip<19, 61, 6>`  → σ1(W[t-2])
//!   - `SmallSigmaChip<1, 8, 7>`    → σ0(W[t-15])
//!   - 3 × `Word64AddChip`           → chain (σ1 + W[t-7]) + σ0 + W[t-16]
//!
//! ## Layout
//!
//! | Range       | Width | Contents                             |
//! |-------------|-------|--------------------------------------|
//! | 0..4        | 4     | W[t-2]   chunks (input)              |
//! | 4..8        | 4     | W[t-7]   chunks (input)              |
//! | 8..12       | 4     | W[t-15]  chunks (input)              |
//! | 12..16      | 4     | W[t-16]  chunks (input)              |
//! | 16..20      | 4     | W[t]     chunks (output)             |
//! | 20..220     | 200   | SmallSigmaChip<19,61,6>  (σ1)        |
//! | 220..420    | 200   | SmallSigmaChip<1,8,7>    (σ0)        |
//! | 420..436    | 16    | Word64AddChip   (σ1 + W[t-7])    s1  |
//! | 436..452    | 16    | Word64AddChip   (s1 + σ0)        s2  |
//! | 452..468    | 16    | Word64AddChip   (s2 + W[t-16])  W[t] |
//!
//! Total: **468 columns**, ~728 constraints (degree 2 max).
//! After sub-fase 3.7.0 (word64_add gains 192 bit-decomp cells per
//! embed): **1044 columns**.
//!
//! ## Soundness (audit 3.7.2)
//!
//! The five chunk slots `W_T_2`, `W_T_7`, `W_T_15`, `W_T_16`, `W_T`
//! are **transitively range-checked** via the connection asserts:
//!
//!   - `W_T_2`  ↔ `σ1.x_chunks`     (range-checked via bit decomp in `small_sigma`)
//!   - `W_T_15` ↔ `σ0.x_chunks`     (same)
//!   - `W_T_7`  ↔ `add_s1.b_chunks` (range-checked via 3.7.0 in `word64_add`)
//!   - `W_T_16` ↔ `add_out.b_chunks` (same)
//!   - `W_T`    ↔ `add_out.c_chunks` (same)
//!
//! Hence `schedule_step` has no standalone range-check gap once the
//! sub-chips' 3.7.0/3.7.1 bit decompositions are in place — the
//! `assert_chunks_eq` constraints propagate the canonical-chunk
//! property through this chip without any additional witness cells.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::small_sigma::{NUM_COLS as SS_COLS, SmallSigmaChip, col as ssc};
use super::word64_add::{NUM_COLS as ADD_COLS, Word64AddChip, col as adc};

pub const NUM_CHUNKS: usize = 4;

pub mod col {
    use super::*;

    pub const W_T_2: usize = 0;          // input W[t-2]
    pub const W_T_7: usize = W_T_2 + NUM_CHUNKS;   // 4
    pub const W_T_15: usize = W_T_7 + NUM_CHUNKS;  // 8
    pub const W_T_16: usize = W_T_15 + NUM_CHUNKS; // 12
    pub const W_T: usize = W_T_16 + NUM_CHUNKS;    // 16 (output)

    pub const SIGMA1_START: usize = W_T + NUM_CHUNKS;            // 20
    pub const SIGMA0_START: usize = SIGMA1_START + SS_COLS;      // 220
    pub const ADD_S1_START: usize = SIGMA0_START + SS_COLS;      // 420
    pub const ADD_S2_START: usize = ADD_S1_START + ADD_COLS;     // 436
    pub const ADD_OUT_START: usize = ADD_S2_START + ADD_COLS;    // 452

    pub const TOTAL: usize = ADD_OUT_START + ADD_COLS;            // 468
}

pub const NUM_COLS: usize = col::TOTAL;

#[derive(Debug, Clone, Copy)]
pub struct ScheduleStepChip;

impl ScheduleStepChip {
    pub const fn new() -> Self {
        Self
    }

    /// Emit constraints with the chip occupying columns `[0, NUM_COLS)`.
    /// Equivalent to `emit_at(builder, 0)`.
    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        self.emit_at(builder, 0);
    }

    /// Emit constraints with the chip embedded at `base..base + NUM_COLS`.
    /// All column offsets are interpreted relative to `base`. Constituent
    /// sub-chips are wired with their `at(...)` constructors at the
    /// corresponding absolute positions.
    ///
    /// Used by `CompressionChip` (sub-fase 5.6.c.1.b.3) to embed one
    /// schedule_step per row without reserving the chip's columns at the
    /// front of the trace.
    pub fn emit_at<AB: AirBuilder>(&self, builder: &mut AB, base: usize) {
        // Constituent chips at their absolute slots.
        SmallSigmaChip::<19, 61, 6>::at(base + col::SIGMA1_START).emit(builder);
        SmallSigmaChip::<1, 8, 7>::at(base + col::SIGMA0_START).emit(builder);
        Word64AddChip::at(base + col::ADD_S1_START).emit(builder);
        Word64AddChip::at(base + col::ADD_S2_START).emit(builder);
        Word64AddChip::at(base + col::ADD_OUT_START).emit(builder);

        // Connection constraints.
        let main = builder.main();
        let row = main.current_slice();

        let assert_chunks_eq = |b: &mut AB, off_a: usize, off_b: usize| {
            for i in 0..NUM_CHUNKS {
                b.assert_eq(row[off_a + i], row[off_b + i]);
            }
        };

        // σ1.x_chunks ← W[t-2]
        assert_chunks_eq(builder, base + col::SIGMA1_START + ssc::X_CHUNKS, base + col::W_T_2);
        // σ0.x_chunks ← W[t-15]
        assert_chunks_eq(builder, base + col::SIGMA0_START + ssc::X_CHUNKS, base + col::W_T_15);

        // s1 = σ1 + W[t-7]
        assert_chunks_eq(builder, base + col::ADD_S1_START + adc::A, base + col::SIGMA1_START + ssc::C_CHUNKS);
        assert_chunks_eq(builder, base + col::ADD_S1_START + adc::B, base + col::W_T_7);

        // s2 = s1 + σ0
        assert_chunks_eq(builder, base + col::ADD_S2_START + adc::A, base + col::ADD_S1_START + adc::C);
        assert_chunks_eq(builder, base + col::ADD_S2_START + adc::B, base + col::SIGMA0_START + ssc::C_CHUNKS);

        // W[t] = s2 + W[t-16]
        assert_chunks_eq(builder, base + col::ADD_OUT_START + adc::A, base + col::ADD_S2_START + adc::C);
        assert_chunks_eq(builder, base + col::ADD_OUT_START + adc::B, base + col::W_T_16);

        // Output assignment: W[t] (col 16..20) = add_out.c
        assert_chunks_eq(builder, base + col::W_T, base + col::ADD_OUT_START + adc::C);
    }
}

impl<F: Field> BaseAir<F> for ScheduleStepChip {
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

impl<AB: AirBuilder> Air<AB> for ScheduleStepChip
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        self.emit(builder);
    }
}

/// Populate one full schedule_step chip witness at row offset `row_off + base`.
///
/// `values` is the parent trace's flat values vector. `base` is the chip's
/// offset relative to the row start (use `0` for a standalone trace, or
/// `parent_chip_offset` when embedded).
///
/// Sub-fase 5.6.c.1.b.3 uses this from `CompressionChip::build_compression_trace`
/// to populate the embedded ScheduleStep witness for every row of the
/// compression trace.
pub fn populate_schedule_step_at<F: Field + PrimeCharacteristicRing>(
    values: &mut [F],
    row_off: usize,
    base: usize,
    w_t_2: u64,
    w_t_7: u64,
    w_t_15: u64,
    w_t_16: u64,
) {
    use super::schedule::{small_sigma0, small_sigma1};
    let sigma1_v = small_sigma1(w_t_2);
    let sigma0_v = small_sigma0(w_t_15);
    let s1 = sigma1_v.wrapping_add(w_t_7);
    let s2 = s1.wrapping_add(sigma0_v);
    let w_t_val = s2.wrapping_add(w_t_16);

    let put_chunks = |values: &mut [F], off: usize, w: u64| {
        let chunks = super::word64_add::decompose_u64(w);
        for i in 0..NUM_CHUNKS {
            values[off + i] = F::from_u64(chunks[i]);
        }
    };
    put_chunks(values, row_off + base + col::W_T_2, w_t_2);
    put_chunks(values, row_off + base + col::W_T_7, w_t_7);
    put_chunks(values, row_off + base + col::W_T_15, w_t_15);
    put_chunks(values, row_off + base + col::W_T_16, w_t_16);
    put_chunks(values, row_off + base + col::W_T, w_t_val);

    // σ1, σ0
    let ss1_w = super::small_sigma::compute_small_sigma(w_t_2, 19, 61, 6);
    populate_small_sigma(values, row_off + base + col::SIGMA1_START, &ss1_w);
    let ss0_w = super::small_sigma::compute_small_sigma(w_t_15, 1, 8, 7);
    populate_small_sigma(values, row_off + base + col::SIGMA0_START, &ss0_w);

    // 3 word64_adds
    let add_s1 = super::word64_add::compute_add64(sigma1_v, w_t_7);
    populate_add(values, row_off + base + col::ADD_S1_START, &add_s1);
    let add_s2 = super::word64_add::compute_add64(s1, sigma0_v);
    populate_add(values, row_off + base + col::ADD_S2_START, &add_s2);
    let add_out = super::word64_add::compute_add64(s2, w_t_16);
    populate_add(values, row_off + base + col::ADD_OUT_START, &add_out);
}

/// Build a single-row trace exercising one schedule step.
pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(
    w_t_2: u64,
    w_t_7: u64,
    w_t_15: u64,
    w_t_16: u64,
) -> RowMajorMatrix<F> {
    use super::schedule::{small_sigma0, small_sigma1};

    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    let sigma1_v = small_sigma1(w_t_2);
    let sigma0_v = small_sigma0(w_t_15);
    let s1 = sigma1_v.wrapping_add(w_t_7);
    let s2 = s1.wrapping_add(sigma0_v);
    let w_t_val = s2.wrapping_add(w_t_16);

    let put_chunks = |values: &mut [F], off: usize, w: u64| {
        let chunks = super::word64_add::decompose_u64(w);
        for i in 0..NUM_CHUNKS {
            values[off + i] = F::from_u64(chunks[i]);
        }
    };
    put_chunks(&mut values, col::W_T_2, w_t_2);
    put_chunks(&mut values, col::W_T_7, w_t_7);
    put_chunks(&mut values, col::W_T_15, w_t_15);
    put_chunks(&mut values, col::W_T_16, w_t_16);
    put_chunks(&mut values, col::W_T, w_t_val);

    // Populate σ1, σ0 chips.
    let ss1_w = super::small_sigma::compute_small_sigma(w_t_2, 19, 61, 6);
    populate_small_sigma(&mut values, col::SIGMA1_START, &ss1_w);
    let ss0_w = super::small_sigma::compute_small_sigma(w_t_15, 1, 8, 7);
    populate_small_sigma(&mut values, col::SIGMA0_START, &ss0_w);

    // Populate the 3 word64_add chips.
    let add_s1 = super::word64_add::compute_add64(sigma1_v, w_t_7);
    populate_add(&mut values, col::ADD_S1_START, &add_s1);
    let add_s2 = super::word64_add::compute_add64(s1, sigma0_v);
    populate_add(&mut values, col::ADD_S2_START, &add_s2);
    let add_out = super::word64_add::compute_add64(s2, w_t_16);
    populate_add(&mut values, col::ADD_OUT_START, &add_out);

    RowMajorMatrix::new(values, NUM_COLS)
}

fn populate_small_sigma<F: Field + PrimeCharacteristicRing>(values: &mut [F], start: usize, w: &super::small_sigma::SmallSigmaWitness) {
    use super::small_sigma::{NUM_BITS, NUM_CHUNKS};
    for i in 0..NUM_CHUNKS {
        values[start + ssc::X_CHUNKS + i] = F::from_u64(w.x_chunks[i]);
        values[start + ssc::C_CHUNKS + i] = F::from_u64(w.c_chunks[i]);
    }
    for i in 0..NUM_BITS {
        values[start + ssc::X_BITS + i] = F::from_u64(w.x_bits[i]);
        values[start + ssc::MID_BITS + i] = F::from_u64(w.mid_bits[i]);
        values[start + ssc::C_BITS + i] = F::from_u64(w.c_bits[i]);
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
        // Sub-fase 3.7.0 — populate 16-bit decomposition cells for a/b/c.
        Range16Chip::populate_bits::<F>(values, start + adc::A_BITS + i * 16, w.a_chunks[i]);
        Range16Chip::populate_bits::<F>(values, start + adc::B_BITS + i * 16, w.b_chunks[i]);
        Range16Chip::populate_bits::<F>(values, start + adc::C_BITS + i * 16, w.c_chunks[i]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::schedule::compute_schedule;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeField32;

    fn read_word(values: &[BabyBear], off: usize) -> u64 {
        let mut chunks = [0u64; 4];
        for i in 0..4 {
            chunks[i] = values[off + i].as_canonical_u32() as u64;
        }
        chunks[0] | (chunks[1] << 16) | (chunks[2] << 32) | (chunks[3] << 48)
    }

    #[test]
    fn schedule_step_zero_inputs() {
        let trace = build_test_trace::<BabyBear>(0, 0, 0, 0);
        check_constraints(&ScheduleStepChip, &trace, &[]);
        assert_eq!(read_word(&trace.values, col::W_T), 0);
    }

    /// Cross-validate against the SHA-512("abc") schedule.
    /// W[16] in FIPS comes from W[14], W[9], W[1], W[0] = (0, 0, 0, 0x6162638000000000).
    /// σ1(0) = 0, σ0(0) = 0, so W[16] = 0 + 0 + 0 + 0x6162638000000000.
    #[test]
    fn schedule_step_w16_for_sha512_abc() {
        // For SHA-512("abc"), padded block has W[0] = 'abc' || 0x80 || zeros.
        let mut block = [0u64; 16];
        block[0] = 0x6162638000000000;
        block[15] = 0x0000000000000018;
        let w_full = compute_schedule(&block);

        // Compute W[16] via the chip: t=16 reads W[14]=0, W[9]=0, W[1]=0, W[0]=block[0].
        let trace = build_test_trace::<BabyBear>(/*W[14]*/ 0, /*W[9]*/ 0, /*W[1]*/ 0, /*W[0]*/ 0x6162638000000000);
        check_constraints(&ScheduleStepChip, &trace, &[]);
        assert_eq!(read_word(&trace.values, col::W_T), w_full[16]);
    }

    /// Cross-validate W[17] for SHA-512("abc"): reads W[15]=0x18, W[10]=0, W[2]=0, W[1]=0.
    /// σ1(0x18) is non-zero, σ0(0) = 0, so W[17] = σ1(0x18) + 0 + 0 + 0.
    #[test]
    fn schedule_step_w17_for_sha512_abc() {
        let mut block = [0u64; 16];
        block[0] = 0x6162638000000000;
        block[15] = 0x0000000000000018;
        let w_full = compute_schedule(&block);

        let trace = build_test_trace::<BabyBear>(/*W[15]*/ 0x18, /*W[10]*/ 0, /*W[2]*/ 0, /*W[1]*/ 0);
        check_constraints(&ScheduleStepChip, &trace, &[]);
        assert_eq!(read_word(&trace.values, col::W_T), w_full[17]);
    }

    /// W[20] picks up genuine non-zero σ1 + σ0 contributions.
    #[test]
    fn schedule_step_w20_for_sha512_abc() {
        let mut block = [0u64; 16];
        block[0] = 0x6162638000000000;
        block[15] = 0x0000000000000018;
        let w_full = compute_schedule(&block);

        // t=20 reads W[18], W[13], W[5], W[4]. The first two are non-zero by t=20.
        let trace = build_test_trace::<BabyBear>(w_full[18], w_full[13], w_full[5], w_full[4]);
        check_constraints(&ScheduleStepChip, &trace, &[]);
        assert_eq!(read_word(&trace.values, col::W_T), w_full[20]);
    }

    #[test]
    fn schedule_step_random_inputs() {
        let trace = build_test_trace::<BabyBear>(
            0xCAFE_BABE_DEAD_BEEF,
            0x1234_5678_9ABC_DEF0,
            0xFEDC_BA09_8765_4321,
            0xAAAA_AAAA_AAAA_AAAA,
        );
        check_constraints(&ScheduleStepChip, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn schedule_step_rejects_tampered_output() {
        let mut trace = build_test_trace::<BabyBear>(0x18, 0, 0, 0);
        trace.values[col::W_T] = trace.values[col::W_T] + BabyBear::ONE;
        check_constraints(&ScheduleStepChip, &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        // Sub-fase 3.7.0: word64_add NUM_COLS 16 → 208 (+192 bit cells per
        // chip × 3 embeds = +576). 468 + 576 = 1044.
        assert_eq!(NUM_COLS, 1044);
    }
}
