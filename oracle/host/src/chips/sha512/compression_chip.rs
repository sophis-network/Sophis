//! `sha512::compression_chip` — multi-row SHA-512 compression AIR.
//!
//! Multi-row design: each row of the trace corresponds to one round
//! (`t = 0..80`). Per row, the AIR uses one `RoundChip` instance whose
//! state inputs come from the previous row's state outputs. The first
//! row's input state is the initial state (IV for first block, or
//! previous compression output for chained blocks). The final row's
//! state outputs are added back to the initial state to produce the
//! compression output.
//!
//! ## Trace layout
//!
//! Per-row width: `RoundChip::NUM_COLS` (1512) + 8 boundary columns for
//! initial state + 8 boundary columns for final state = 1528.
//!
//! Trace height: 80 rows for the rounds + boundary handling.
//!
//! Transition constraints: row[t+1].A..H = row[t].new_A..new_H.
//!
//! Each row also pulls K[t] and W[t] from preprocessed columns (K is a
//! fixed schedule of 80 constants; W is computed from the message block
//! plus 64 schedule_step extensions, also as preprocessed columns or as
//! witness derived from the input block).
//!
//! ## Status
//!
//! This is the natural "AIR for full hash" structure but full
//! implementation requires:
//!   - Preprocessed column infrastructure for K[t] and W[t]
//!   - Transition constraints linking row[t+1] to row[t]
//!   - Boundary constraints (first row = IV, last row + IV = output)
//!   - Multi-block chaining for arbitrary-length messages
//!
//! For Phase 5's needs (single 1024-bit block input from R || A || M
//! that fits in one or two blocks for typical Pyth tx messages), a
//! one-block compression AIR is sufficient. Multi-block chaining is a
//! straightforward extension once the one-block path lands.
//!
//! **Note:** Plonky3's `p3-uni-stark` supports transition constraints
//! via `is_transition()`, and preprocessed columns via `preprocessed_trace()`
//! on `BaseAir`. This chip uses both.
//!
//! Witness scaffold (compute_compression_trace) and AIR skeleton
//! shipped here; the full transition constraint implementation lands
//! incrementally — this file currently provides the trace generation
//! and a single-row `RoundChipWithBoundary` test that confirms the
//! per-row round logic composes correctly.
//!
//! ## Soundness for non-sub-chip slots (audit 3.7.2)
//!
//! All chunk slots that are NOT inside a sub-chip's bit-decomposed
//! body fall into three groups, each with a documented soundness
//! chain:
//!
//!   1. **`W_HIST` shift register** (cols `W_HIST_START..+64`). Slots
//!      `[14]`, `[9]`, `[1]`, `[0]` are wired via `assert_eq` to the
//!      embedded `ScheduleStepChip`'s `W_T_2`/`W_T_7`/`W_T_15`/`W_T_16`
//!      inputs at every row, which themselves connect to range-checked
//!      sub-chips (sound). The other 12 slots are propagated through
//!      shift transitions until they land in a routed slot at a later
//!      row — by induction every cell ends up bound to a range-checked
//!      column. PV[32..96] additionally pins row 16's whole register
//!      to the message block.
//!
//!   2. **`ADD_BACK` chips** (8 × `Word64AddChip` from `ADD_BACK_START`).
//!      Each chip's internal `A`/`B`/`C`/`carry` cells are
//!      bit-decomposed by 3.7.0. The chip-input wiring binds `A` to
//!      `PV[i*4..]` (verifier-controlled IV) and `B` to round-chip
//!      `NEW_state[i]` (range-checked transitively via 3.7.2's
//!      round_chip audit). `C` is the chip's range-checked output.
//!
//!   3. **Round-chip state slots** (cols `0..72` of every row). Audited
//!      in `round_chip.rs`'s 3.7.2 doc: every slot routes to a sub-chip
//!      that bit-decomposes its inputs.
//!
//! Hence `compression_chip` has no standalone range-check gap once
//! 3.7.0 + 3.7.1 are in place — soundness propagates through the
//! connection mesh without any extra witness cells.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::constants::{H_INITIAL, K};
use super::round::{Sha512State, big_sigma0, big_sigma1, ch, compute_round, maj};
use super::round_chip::{NUM_COLS as ROUND_COLS, RoundChip, col as rc};
use super::schedule::compute_schedule;
use super::schedule_step::{
    NUM_COLS as SS_TOTAL_COLS, ScheduleStepChip, col as ssc, populate_schedule_step_at,
};
use super::word64_add::{
    NUM_COLS as ADD_COLS, Word64AddChip, col as adc, compute_add64, decompose_u64,
};

/// Number of rounds per SHA-512 compression.
pub const NUM_ROUNDS: usize = 80;

/// Trace height (must be a power of two for FRI). 80 active rounds + 48
/// padding rows = 128.
pub const TRACE_HEIGHT: usize = 128;

/// Number of words in the W shift register (matches the SHA-512 message
/// schedule's lookback window: `W[t]` reads from `W[t-2], W[t-7], W[t-15], W[t-16]`).
pub const W_HIST_LEN: usize = 16;

/// Number of 16-bit chunks per 64-bit word (same as round_chip).
pub const HIST_CHUNKS: usize = 4;

/// Width of the W shift register columns.
pub const W_HIST_COLS: usize = W_HIST_LEN * HIST_CHUNKS;

/// Sub-fase 5.6.c.1.b.2 — extension of the main trace width to include the
/// rolling 16-word W history. At row `t`, slot `i` (`i in 0..16`) holds
/// `W[t-16+i]` (so slot 0 is the oldest, slot 15 is the newest = `W[t-1]`).
pub const W_HIST_START: usize = ROUND_COLS;

/// Sub-fase 5.6.c.1.b.3.embed — start of the embedded `ScheduleStepChip`.
/// 468 cols (σ1, σ0, 3 word64_adds, plus inputs/output).
pub const SCHEDULE_STEP_START: usize = W_HIST_START + W_HIST_COLS;

/// Sub-fase 5.6.c.1.c — start of the 8 add-back `Word64AddChip` instances.
/// Each chip occupies 16 cols (4 chunks × 4 fields = A, B, C, CARRY).
/// At row 79 the gated PV binding (5.6.c.1.e) will read each chip's C
/// chunks as the corresponding digest word.
pub const ADD_BACK_START: usize = SCHEDULE_STEP_START + SS_TOTAL_COLS;

/// Number of add-back chips (one per state word A..H).
pub const ADD_BACK_COUNT: usize = 8;

/// Total trace width: round chip + W shift register + schedule_step + 8 add-backs.
pub const NUM_COLS: usize = ADD_BACK_START + ADD_BACK_COUNT * ADD_COLS;

/// Width of the preprocessed trace.
///
/// Layout:
///   - cols 0..4 (sub-fase 5.6.c.1.b.1): `K[t]` chunks (4 chunks per
///     u64 = 4 cells). Padding rows `t ≥ 80` carry zero.
///   - col 4 (sub-fase 5.6.c.1.b.3.embed): `IS_SCHEDULE_ROW` selector
///     — `1` for rows `16..80` (where the schedule_step recurrence
///     applies), `0` elsewhere (rows `0..16` where W[t] = M[t] comes
///     directly from the message block, plus padding rows).
///   - col 5 (sub-fase 5.6.c.1.c): `IS_LAST_ACTIVE_ROUND` selector —
///     `1` only at row 79 (the last active SHA-512 round; the row at
///     which `state_after_80_rounds` lives in `NEW_A..NEW_H`). Used by
///     5.6.c.1.e to gate the digest PV binding.
///   - col 6 (sub-fase 5.6.c.1.e.1): `IS_FIRST_SCHEDULE_ROW` selector
///     — `1` only at row 16. At row 16 the W shift register holds
///     `(W[0], W[1], …, W[15]) = (M[0], M[1], …, M[15])`, the entire
///     1024-bit message block. Used to bind those 16 words to PV.
pub const NUM_PREPROCESSED_COLS: usize = 7;

/// Column offset of the `IS_SCHEDULE_ROW` selector inside the preprocessed
/// trace.
pub const IS_SCHEDULE_ROW_COL: usize = 4;

/// Column offset of the `IS_LAST_ACTIVE_ROUND` selector inside the
/// preprocessed trace.
pub const IS_LAST_ACTIVE_ROUND_COL: usize = 5;

/// Column offset of the `IS_FIRST_SCHEDULE_ROW` selector inside the
/// preprocessed trace.
pub const IS_FIRST_SCHEDULE_ROW_COL: usize = 6;

/// Number of public values exposed to the STARK verifier.
///
/// Layout (128 BabyBear elements total — sub-fase 5.6.c.1.d.multi):
///   - PV[0..32]:   8 IV words × 4 chunks each (the input chaining state)
///                  (slot order: PV[i*4..i*4+4] = chunk decomposition of `iv_word[i]`).
///                  For block 0, IV = `H_INITIAL`. For block k > 0 in a
///                  multi-block hash, IV = digest of block k-1.
///   - PV[32..96]:  16 message-block words × 4 chunks each.
///   - PV[96..128]: 8 digest words × 4 chunks each (= IV + state_after_80_rounds).
///
/// Boundary bindings:
///   - PV[0..32] are tied to row 0's state input cells (A..H) — replaces
///     the hardcoded `H_INITIAL` boundary from sub-fase 5.6.c.1.a.
///   - PV[32..96] are tied to row 16's W shift register via `IS_FIRST_SCHEDULE_ROW`.
///   - PV[96..128] are tied to row 79's `add_back[i].C` via `IS_LAST_ACTIVE_ROUND`.
pub const NUM_PUBLIC_VALUES: usize = 32 + 64 + 32;

/// Multi-row compression chip. Each row constrains one round transform.
/// Transition constraints link state across rows.
#[derive(Debug, Clone, Copy)]
pub struct CompressionChip;

impl<F: Field + PrimeCharacteristicRing> BaseAir<F> for CompressionChip {
    fn width(&self) -> usize {
        NUM_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        // Round chip's NEW_* columns feed into next row's state inputs.
        // Conservative: declare all input cols (a..h, K, W) as needing next-row access.
        (0..40).chain(40..72).collect()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }

    /// Preprocessed trace combining:
    ///   - `K[t]` chunks (sub-fase 5.6.c.1.b.1) at cols 0..4
    ///   - `IS_SCHEDULE_ROW` selector (sub-fase 5.6.c.1.b.3.embed) at col 4
    ///
    /// The selector is 1 for `16 ≤ t < 80` (rows where the schedule_step
    /// recurrence binds `W[t]`) and 0 elsewhere.
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut values = vec![F::ZERO; NUM_PREPROCESSED_COLS * TRACE_HEIGHT];
        for t in 0..TRACE_HEIGHT {
            let off = t * NUM_PREPROCESSED_COLS;
            // K chunks for active rounds; zero for padding rows.
            if t < NUM_ROUNDS {
                let chunks = decompose_u64(K[t]);
                for (j, chunk) in chunks.iter().enumerate() {
                    values[off + j] = F::from_u64(*chunk);
                }
            }
            // IS_SCHEDULE_ROW: 1 for 16..80, 0 elsewhere.
            if (16..NUM_ROUNDS).contains(&t) {
                values[off + IS_SCHEDULE_ROW_COL] = F::ONE;
            }
            // IS_LAST_ACTIVE_ROUND: 1 only at row NUM_ROUNDS - 1 = 79.
            if t == NUM_ROUNDS - 1 {
                values[off + IS_LAST_ACTIVE_ROUND_COL] = F::ONE;
            }
            // IS_FIRST_SCHEDULE_ROW: 1 only at row 16 (the row at which
            // the W shift register first contains the full message block).
            if t == 16 {
                values[off + IS_FIRST_SCHEDULE_ROW_COL] = F::ONE;
            }
        }
        Some(RowMajorMatrix::new(values, NUM_PREPROCESSED_COLS))
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        // Constraints only read the current row's preprocessed K cells.
        Vec::new()
    }
}

impl<AB: AirBuilder> Air<AB> for CompressionChip
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        // Each row is a self-contained round chip.
        RoundChip::new().emit(builder);

        // Transition constraints: row[t+1].state = row[t].new_state.
        let main = builder.main();
        let cur = main.current_slice();
        let next = main.next_slice();

        for j in 0..4 {
            builder.when_transition().assert_eq(next[rc::A + j], cur[rc::NEW_A + j]);
            builder.when_transition().assert_eq(next[rc::B + j], cur[rc::NEW_B + j]);
            builder.when_transition().assert_eq(next[rc::C + j], cur[rc::NEW_C + j]);
            builder.when_transition().assert_eq(next[rc::D + j], cur[rc::NEW_D + j]);
            builder.when_transition().assert_eq(next[rc::E + j], cur[rc::NEW_E + j]);
            builder.when_transition().assert_eq(next[rc::F + j], cur[rc::NEW_F + j]);
            builder.when_transition().assert_eq(next[rc::G + j], cur[rc::NEW_G + j]);
            builder.when_transition().assert_eq(next[rc::H + j], cur[rc::NEW_H + j]);
        }

        // Sub-fase 5.6.c.1.a — IV boundary constraint.
        //
        // Row 0's state inputs (A..H) must equal the SHA-512 initial hash
        // value `H_INITIAL` (FIPS 180-4 §5.3.5). Each word is decomposed
        // into 4 × 16-bit chunks matching the round chip's column layout.
        // After this constraint, a malicious prover cannot start the
        // 80-round chain from a fabricated state — the IV is now part of
        // the AIR's promise rather than a witness.
        //
        // Subsequent sub-fases will close the remaining gaps:
        //   5.6.c.1.b — bind K[t] (round constants) to row t via
        //               preprocessed_trace; bind W schedule via embedded
        //               schedule_step chips for rows 16..79
        //   5.6.c.1.c — add-back step (digest = IV + state_after_round_79)
        //   5.6.c.1.d — multi-block chaining + FIPS 180-4 padding helper
        //   5.6.c.1.e — PV bind to message bytes + digest; remove trust shim
        //
        // Sub-fase 5.6.c.1.d.multi — IV is now provided via public values
        // (PV[0..32]) instead of being hardcoded as `H_INITIAL`. This lets
        // the wrapper chain compressions across multiple blocks: block 0's
        // IV must equal `H_INITIAL` (enforced wrapper-side); block k's IV
        // must equal block k-1's digest (enforced wrapper-side via PV
        // equality between adjacent proofs). The chip itself is now
        // chaining-agnostic — it proves "given this IV and this block,
        // the resulting digest is correct".
        //
        // The actual `cur[A..H] == PV[0..32]` constraint lands below
        // alongside the other PV bindings (sub-fase 5.6.c.1.e.1 logic).

        // Sub-fase 5.6.c.1.b.1 — K binding via preprocessed trace.
        //
        // The preprocessed trace exposes the canonical `K[t]` round
        // constants per row. We assert that the prover's main K column
        // matches the preprocessed K column at every row. After this
        // constraint, a malicious prover cannot substitute fabricated
        // round constants to land on a chosen output — K is now part
        // of the AIR's promise (committed once at AIR setup time) and
        // not a free witness.
        //
        // The main K column is preserved (instead of replacing it
        // outright with the preprocessed cells) because the embedded
        // RoundChip's internal arithmetic still reads K from the
        // current main row — refactoring that to consume preprocessed
        // directly would touch every sub-chip and is not in scope
        // here. The redundancy costs 4 main columns × 128 rows; the
        // soundness gap closes either way.
        // Copy preprocessed cells into Copy variables before invoking
        // mutable `assert_eq` (otherwise the borrow checker rejects the
        // simultaneous &builder + &mut builder use).
        let prep_copies: [AB::Var; NUM_PREPROCESSED_COLS] = {
            let prep = builder.preprocessed();
            let prep_cur = prep.current_slice();
            core::array::from_fn(|i| prep_cur[i])
        };
        for j in 0..4 {
            builder.assert_eq(cur[rc::K + j].clone(), prep_copies[j]);
        }

        // Sub-fase 5.6.c.1.b.2 — W shift register infrastructure.
        //
        // The register holds the last 16 W values produced. Layout:
        //   slot i (i in 0..16) holds W[t - 16 + i] at row t, so slot 0
        //   is the oldest entry (W[t-16]) and slot 15 is the newest
        //   (W[t-1]). At row 0 every slot is zero (no W has been
        //   produced yet — pre-history values are not used by the
        //   schedule_step recurrence which only fires from row 16
        //   onward in the gated 5.6.c.1.b.3 sub-fase).
        //
        // Transition rule:
        //   next.HIST[i] = cur.HIST[i+1]   for i in 0..15  (shift left)
        //   next.HIST[15] = cur.W                          (append cur.W)
        //
        // This does NOT yet bind W[t] to the schedule_step recurrence;
        // 5.6.c.1.b.3 adds the gated constraint cur.W ==
        // schedule_step.W_T using a preprocessed `IS_SCHEDULE_ROW`
        // selector that's 1 only on rows 16..79.

        // Boundary at row 0: every HIST slot is zero.
        for c in 0..W_HIST_COLS {
            builder.when_first_row().assert_eq(cur[W_HIST_START + c].clone(), AB::Expr::ZERO);
        }

        // Transitions: shift left by 1 word (4 chunks), append cur.W at slot 15.
        for slot in 0..(W_HIST_LEN - 1) {
            let cur_off = W_HIST_START + (slot + 1) * HIST_CHUNKS;
            let nxt_off = W_HIST_START + slot * HIST_CHUNKS;
            for j in 0..HIST_CHUNKS {
                builder
                    .when_transition()
                    .assert_eq(next[nxt_off + j].clone(), cur[cur_off + j].clone());
            }
        }
        // Append: next.HIST[15] = cur.W
        for j in 0..HIST_CHUNKS {
            builder
                .when_transition()
                .assert_eq(next[W_HIST_START + (W_HIST_LEN - 1) * HIST_CHUNKS + j].clone(), cur[rc::W + j].clone());
        }

        // Sub-fase 5.6.c.1.b.3.embed — embed ScheduleStepChip and gate it
        // by the IS_SCHEDULE_ROW preprocessed selector.
        //
        // `emit_at` wires the chip's internal arithmetic at offset
        // `SCHEDULE_STEP_START`. These constraints fire on EVERY row
        // (the chip's σ0/σ1/word64_add internals are universal sanity
        // checks). The trace builder must populate the chip's witness
        // cells consistently on every row, including padding rows.
        ScheduleStepChip::new().emit_at(builder, SCHEDULE_STEP_START);

        // Connection constraints: route W shift register cells to
        // schedule_step inputs. At row `t`, slot mapping (per b.2 docs):
        //   schedule_step.W_T_2  ← HIST[14] (= W[t-2])
        //   schedule_step.W_T_7  ← HIST[ 9] (= W[t-7])
        //   schedule_step.W_T_15 ← HIST[ 1] (= W[t-15])
        //   schedule_step.W_T_16 ← HIST[ 0] (= W[t-16])
        let connect_input = |b: &mut AB, ss_off: usize, hist_slot: usize| {
            let ss_base = SCHEDULE_STEP_START + ss_off;
            let hist_base = W_HIST_START + hist_slot * HIST_CHUNKS;
            for j in 0..HIST_CHUNKS {
                b.assert_eq(cur[ss_base + j].clone(), cur[hist_base + j].clone());
            }
        };
        connect_input(builder, ssc::W_T_2, 14);
        connect_input(builder, ssc::W_T_7, 9);
        connect_input(builder, ssc::W_T_15, 1);
        connect_input(builder, ssc::W_T_16, 0);

        // Gated W binding: on rows 16..80 (where IS_SCHEDULE_ROW = 1),
        // assert cur.W = schedule_step.W_T per chunk. Outside that
        // range the gate is 0 and the constraint is trivially satisfied
        // — W[0..16] still come from the message block (bound to PV in
        // 5.6.c.1.e), and padding rows have w_pad = 0.
        let is_schedule = prep_copies[IS_SCHEDULE_ROW_COL].clone();
        for j in 0..HIST_CHUNKS {
            let lhs = cur[rc::W + j].clone();
            let rhs = cur[SCHEDULE_STEP_START + ssc::W_T + j].clone();
            builder.assert_eq(is_schedule.clone() * (lhs - rhs), AB::Expr::ZERO);
        }

        // Sub-fase 5.6.c.1.c (updated by 5.6.c.1.d.multi) — add-back chips.
        //
        // Eight `Word64AddChip` instances compute `IV[i] + state[i]` per
        // row. The `state[i]` input is wired to the round chip's
        // `NEW_state[i]` (the working state after this row's round).
        // The `IV[i]` input is wired to row 0's state inputs (A..H),
        // which the PV binding below pins to PV[0..32].
        //
        // At row `NUM_ROUNDS - 1 = 79`, `NEW_state[i]` is the working
        // state after all 80 rounds, so `add_back[i].C = digest[i]`
        // (= IV + state_after_80_rounds). At other rows, the chip is
        // doing valid arithmetic but not against the round-79 state —
        // the digest is read at row 79 only via the gated PV binding
        // below. Note that A reads from the SAME-row state input cells:
        // since those are propagated by transition constraints from row
        // 0, every row sees the same IV at A — wait, that's WRONG.
        //
        // Actually transitions propagate `NEW_state` not `state` itself.
        // To wire `IV[i]` consistently across rows we'd need a separate
        // shift-register-like column for IV. Easier alternative: pull A
        // straight from PV[0..32] via boundary at every row (since PV
        // is the same at every row). The PV bind for IV below also
        // satisfies this.
        let new_state_offsets = [
            rc::NEW_A, rc::NEW_B, rc::NEW_C, rc::NEW_D,
            rc::NEW_E, rc::NEW_F, rc::NEW_G, rc::NEW_H,
        ];
        // Copy IV PV cells (8 words × 4 chunks = 32 cells).
        let iv_pv_copies: [AB::PublicVar; 32] = {
            let public = builder.public_values();
            core::array::from_fn(|i| public[i])
        };
        for i in 0..ADD_BACK_COUNT {
            let chip_base = ADD_BACK_START + i * ADD_COLS;
            // Embed the chip's internal arithmetic.
            Word64AddChip::at(chip_base).emit(builder);

            // A = IV[i] (chunked) — bound to PV[i*4..i*4+4].
            for j in 0..HIST_CHUNKS {
                let pv_idx = i * HIST_CHUNKS + j;
                let pv_expr: AB::Expr = iv_pv_copies[pv_idx].into();
                builder.assert_eq(cur[chip_base + adc::A + j].clone(), pv_expr);
            }

            // B = NEW_state[i] (chunked).
            let state_off = new_state_offsets[i];
            for j in 0..HIST_CHUNKS {
                builder.assert_eq(
                    cur[chip_base + adc::B + j].clone(),
                    cur[state_off + j].clone(),
                );
            }
            // The chip's internal constraints already validate
            // `C = A + B (mod 2^64)` and the carry chain. C cells hold
            // the digest at row 79; gated PV binding lands below.
        }

        // Sub-fase 5.6.c.1.e.1 (updated by 5.6.c.1.d.multi) — PV bindings.
        //
        // `PV[0..32]`   ↔ row 0's state input cells (A..H)  — IV
        // `PV[32..96]`  ↔ row 16's W shift register cells   — message block
        // `PV[96..128]` ↔ row 79's add_back[i].C cells       — digest
        //
        // The IV binding fires at row 0 via `when_first_row()`. The
        // message-block and digest bindings are gated by preprocessed
        // selectors (`IS_FIRST_SCHEDULE_ROW`, `IS_LAST_ACTIVE_ROUND`)
        // so they only fire on rows 16 and 79 respectively.
        //
        // After this commit, every block in a multi-block hash is a
        // self-contained STARK — block 0 has IV = `H_INITIAL`, block k
        // has IV = digest of block k-1. The wrapper handles chaining.
        let pub_copies: [AB::PublicVar; NUM_PUBLIC_VALUES] = {
            let public = builder.public_values();
            core::array::from_fn(|i| public[i])
        };

        // PV[0..32] — IV via row 0's A..H state inputs.
        //
        // Replaces the hardcoded `H_INITIAL` boundary from sub-fase
        // 5.6.c.1.a. The wrapper passes `H_INITIAL` for block 0 and the
        // previous block's digest for block k > 0.
        let iv_state_offsets = [rc::A, rc::B, rc::C, rc::D, rc::E, rc::F, rc::G, rc::H];
        for (word_idx, off) in iv_state_offsets.iter().enumerate() {
            for j in 0..HIST_CHUNKS {
                let cell = cur[off + j].clone();
                let pv = pub_copies[word_idx * HIST_CHUNKS + j];
                let pv_expr: AB::Expr = pv.into();
                builder.when_first_row().assert_eq(cell, pv_expr);
            }
        }

        // PV[32..96] — message block via W shift register at row 16.
        //
        // At row 16, HIST[i] holds W[i] = M[i] for i in 0..16. We
        // assert chunk-by-chunk that the shift register matches the
        // public-input message block.
        let is_first_schedule = prep_copies[IS_FIRST_SCHEDULE_ROW_COL].clone();
        for slot in 0..W_HIST_LEN {
            for j in 0..HIST_CHUNKS {
                let cell = cur[W_HIST_START + slot * HIST_CHUNKS + j].clone();
                let pv = pub_copies[32 + slot * HIST_CHUNKS + j];
                let pv_expr: AB::Expr = pv.into();
                builder.assert_eq(is_first_schedule.clone() * (cell - pv_expr), AB::Expr::ZERO);
            }
        }

        // PV[96..128] — digest via add_back[i].C cells at row 79.
        let is_last_active = prep_copies[IS_LAST_ACTIVE_ROUND_COL].clone();
        for i in 0..ADD_BACK_COUNT {
            let chip_base = ADD_BACK_START + i * ADD_COLS;
            for j in 0..HIST_CHUNKS {
                let cell = cur[chip_base + adc::C + j].clone();
                let pv = pub_copies[96 + i * HIST_CHUNKS + j];
                let pv_expr: AB::Expr = pv.into();
                builder.assert_eq(is_last_active.clone() * (cell - pv_expr), AB::Expr::ZERO);
            }
        }
    }
}

/// Build a multi-row trace for one full compression. Trace has `NUM_ROUNDS`
/// rounds rows. Row `t` runs the t-th round transform with K[t] and W[t].
///
/// **Note:** the AIR's transition constraints check that row[t+1]'s state
/// inputs equal row[t]'s state outputs. K[t] and W[t] for each row are
/// witnessed; the AIR currently does NOT verify they match the schedule
/// (caller is trusted). A future extension would add preprocessed columns
/// for K and witness columns for W with schedule-step constraints.
/// Build the public-values vector from `(iv_words, message_block, digest_words)`.
///
/// Layout (128 BabyBear elements — sub-fase 5.6.c.1.d.multi):
///   - PV[0..32]:   8 IV words × 4 chunks = 32 cells (input chaining state)
///   - PV[32..96]:  16 message words × 4 chunks = 64 cells
///   - PV[96..128]: 8 digest words × 4 chunks = 32 cells
///
/// Each u64 is decomposed via `decompose_u64` into 4 × 16-bit chunks (LE).
///
/// For block 0 in a hash (or any single-block hash), pass `H_INITIAL` as
/// `iv_words`. For block k > 0, pass the digest of block k-1.
pub fn build_public_values<F: Field + PrimeCharacteristicRing>(
    iv_words: &[u64; 8],
    message_block: &[u64; 16],
    digest_words: &[u64; 8],
) -> Vec<F> {
    let mut out = Vec::with_capacity(NUM_PUBLIC_VALUES);
    for &word in iv_words {
        for chunk in decompose_u64(word) {
            out.push(F::from_u64(chunk));
        }
    }
    for &word in message_block {
        for chunk in decompose_u64(word) {
            out.push(F::from_u64(chunk));
        }
    }
    for &word in digest_words {
        for chunk in decompose_u64(word) {
            out.push(F::from_u64(chunk));
        }
    }
    debug_assert_eq!(out.len(), NUM_PUBLIC_VALUES);
    out
}

/// Maximum byte length of a message that fits in a single SHA-512 block
/// after FIPS 180-4 §5.1.2 padding.
///
/// One block is 128 bytes. Padding requires:
///   - `0x80` terminator (1 byte)
///   - 128-bit length suffix (16 bytes) at the end of the last block
///   - Zero pad to align
///
/// So the message itself can be at most `128 - 1 - 16 = 111` bytes if it
/// is to compress in one block. Longer messages need multi-block chaining
/// (sub-fase 5.6.c.1.d.multi, future).
pub const MAX_SINGLE_BLOCK_MESSAGE_BYTES: usize = 111;

/// Apply FIPS 180-4 §5.1.2 padding to a short message and pack it into a
/// single 1024-bit block (16 big-endian u64 words).
///
/// Returns `None` if the message exceeds `MAX_SINGLE_BLOCK_MESSAGE_BYTES`.
/// Multi-block padding lives in `compression::sha512`; this helper exists
/// specifically so the AIR's single-block trace builder can be invoked
/// directly from arbitrary short byte messages.
pub fn fips_pad_single_block(message_bytes: &[u8]) -> Option<[u64; 16]> {
    if message_bytes.len() > MAX_SINGLE_BLOCK_MESSAGE_BYTES {
        return None;
    }
    let bit_len: u128 = (message_bytes.len() as u128) * 8;
    let mut padded = [0u8; 128];
    padded[..message_bytes.len()].copy_from_slice(message_bytes);
    padded[message_bytes.len()] = 0x80;
    // Bytes [message_bytes.len() + 1 .. 112) are already zero.
    padded[112..128].copy_from_slice(&bit_len.to_be_bytes());

    let mut block = [0u64; 16];
    for (i, word_bytes) in padded.chunks_exact(8).enumerate() {
        block[i] = u64::from_be_bytes(word_bytes.try_into().unwrap());
    }
    Some(block)
}

/// Apply FIPS 180-4 §5.1.2 padding to a message of arbitrary length and
/// pack it into one or more 1024-bit blocks (16 big-endian u64 words each).
///
/// Returns the sequence of blocks. For short messages (≤ 111 bytes) this
/// is a single-element vec equivalent to `fips_pad_single_block`; for
/// longer messages, two or more blocks are produced via the standard
/// FIPS padding rules:
///
///   - Append `0x80`
///   - Zero-pad until total length ≡ 112 (mod 128)
///   - Append the 128-bit big-endian bit length
///
/// The returned vec always has at least one block; total bytes is a
/// multiple of 128 (= one 1024-bit block).
pub fn fips_pad_multi_block(message_bytes: &[u8]) -> Vec<[u64; 16]> {
    let bit_len: u128 = (message_bytes.len() as u128) * 8;
    let mut padded = Vec::with_capacity(message_bytes.len() + 128 + 16);
    padded.extend_from_slice(message_bytes);
    padded.push(0x80);
    while padded.len() % 128 != 112 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut blocks = Vec::with_capacity(padded.len() / 128);
    for chunk in padded.chunks_exact(128) {
        let mut block = [0u64; 16];
        for (i, word_bytes) in chunk.chunks_exact(8).enumerate() {
            block[i] = u64::from_be_bytes(word_bytes.try_into().expect("8-byte word"));
        }
        blocks.push(block);
    }
    blocks
}

/// Build a single-block SHA-512 trace from raw byte input. Wraps
/// `fips_pad_single_block` + `build_compression_trace` with the canonical
/// `H_INITIAL` IV.
///
/// At the trace's row 79 the 8 add-back chips (sub-fase 5.6.c.1.c) hold
/// `H_INITIAL[i] + state_after_80_rounds[i]` = the 8 SHA-512 digest words.
/// 5.6.c.1.e exposes these as STARK public values via the
/// `IS_LAST_ACTIVE_ROUND` selector.
///
/// Returns `None` for messages that don't fit in a single block.
pub fn build_sha512_trace_short<F: Field + PrimeCharacteristicRing>(
    message_bytes: &[u8],
) -> Option<RowMajorMatrix<F>> {
    let block = fips_pad_single_block(message_bytes)?;
    Some(build_compression_trace::<F>(&H_INITIAL, &block))
}

pub fn build_compression_trace<F: Field + PrimeCharacteristicRing>(
    initial_state: &[u64; 8],
    message_block: &[u64; 16],
) -> RowMajorMatrix<F> {
    let w_full = compute_schedule(message_block);
    // We need a trace height that's a power of two for FRI.
    // 80 rounds rounded up to next power of 2 = 128.
    const HEIGHT: usize = 128;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    let mut state = Sha512State::new(*initial_state);
    for t in 0..NUM_ROUNDS {
        let row_off = t * NUM_COLS;
        let k = K[t];
        let w = w_full[t];

        // Use round_chip's build_test_trace logic in-place for one row.
        // We populate the row directly via RoundChip's witness pattern.
        let next = compute_round(state, k, w);

        // Populate state inputs.
        let put_chunks = |values: &mut [F], off: usize, w: u64| {
            let chunks = super::word64_add::decompose_u64(w);
            for i in 0..4 {
                values[off + i] = F::from_u64(chunks[i]);
            }
        };

        let [a, b, c, d, e, f, g, h] = state.0;
        put_chunks(&mut values, row_off + rc::A, a);
        put_chunks(&mut values, row_off + rc::B, b);
        put_chunks(&mut values, row_off + rc::C, c);
        put_chunks(&mut values, row_off + rc::D, d);
        put_chunks(&mut values, row_off + rc::E, e);
        put_chunks(&mut values, row_off + rc::F, f);
        put_chunks(&mut values, row_off + rc::G, g);
        put_chunks(&mut values, row_off + rc::H, h);
        put_chunks(&mut values, row_off + rc::K, k);
        put_chunks(&mut values, row_off + rc::W, w);

        // State outputs.
        put_chunks(&mut values, row_off + rc::NEW_A, next.a());
        put_chunks(&mut values, row_off + rc::NEW_B, next.b());
        put_chunks(&mut values, row_off + rc::NEW_C, next.c());
        put_chunks(&mut values, row_off + rc::NEW_D, next.d());
        put_chunks(&mut values, row_off + rc::NEW_E, next.e());
        put_chunks(&mut values, row_off + rc::NEW_F, next.f());
        put_chunks(&mut values, row_off + rc::NEW_G, next.g());
        put_chunks(&mut values, row_off + rc::NEW_H, next.h());

        // Populate internal chip witnesses.
        let sigma1_e = big_sigma1(e);
        let ch_efg = ch(e, f, g);
        let sigma0_a = big_sigma0(a);
        let maj_abc = maj(a, b, c);
        let t11 = h.wrapping_add(sigma1_e);
        let t12 = t11.wrapping_add(ch_efg);
        let t13 = t12.wrapping_add(k);
        let t1 = t13.wrapping_add(w);
        let t2 = sigma0_a.wrapping_add(maj_abc);

        let bs_e = super::big_sigma::compute_big_sigma(e, 14, 18, 41);
        populate_big_sigma(&mut values, row_off + rc::BIG_SIGMA_E_START, &bs_e);
        let ch_w = super::ch::compute_ch(e, f, g);
        populate_ch(&mut values, row_off + rc::CH_START, &ch_w);
        let bs_a = super::big_sigma::compute_big_sigma(a, 28, 34, 39);
        populate_big_sigma(&mut values, row_off + rc::BIG_SIGMA_A_START, &bs_a);
        let maj_w = super::maj::compute_maj(a, b, c);
        populate_maj(&mut values, row_off + rc::MAJ_START, &maj_w);

        let add1 = super::word64_add::compute_add64(h, sigma1_e);
        populate_add(&mut values, row_off + rc::ADD_T1_1_START, &add1);
        let add2 = super::word64_add::compute_add64(t11, ch_efg);
        populate_add(&mut values, row_off + rc::ADD_T1_2_START, &add2);
        let add3 = super::word64_add::compute_add64(t12, k);
        populate_add(&mut values, row_off + rc::ADD_T1_3_START, &add3);
        let add4 = super::word64_add::compute_add64(t13, w);
        populate_add(&mut values, row_off + rc::ADD_T1_4_START, &add4);
        let add5 = super::word64_add::compute_add64(sigma0_a, maj_abc);
        populate_add(&mut values, row_off + rc::ADD_T2_START, &add5);
        let add6 = super::word64_add::compute_add64(d, t1);
        populate_add(&mut values, row_off + rc::ADD_NEW_E_START, &add6);
        let add7 = super::word64_add::compute_add64(t1, t2);
        populate_add(&mut values, row_off + rc::ADD_NEW_A_START, &add7);

        // Sub-fase 5.6.c.1.b.2 — populate W shift register for row t.
        // At row t, slot i holds W[t-16+i]. Indices below 0 are padded
        // with zero (no W has been produced yet pre-history).
        populate_w_hist::<F>(&mut values, row_off, t, &w_full);

        // Sub-fase 5.6.c.1.b.3.embed — populate the embedded
        // ScheduleStepChip with the canonical recurrence inputs from
        // the W history. Even on rows 0..16 where the gated constraint
        // does not fire, the chip's INTERNAL constraints (σ0/σ1/adds)
        // must hold; the trace builder satisfies them by computing the
        // recurrence on the (mostly zero) pre-history HIST values.
        let (w2, w7, w15, w16) = w_hist_lookup(&w_full, t);
        populate_schedule_step_at::<F>(&mut values, row_off, SCHEDULE_STEP_START, w2, w7, w15, w16);

        // Sub-fase 5.6.c.1.c — populate add-back chips for this row.
        // A_i = iv[i] (PV-bound), B_i = next_state.<word_i>. C_i = A_i + B_i.
        let next_words = [next.a(), next.b(), next.c(), next.d(), next.e(), next.f(), next.g(), next.h()];
        populate_add_back_chips::<F>(&mut values, row_off, initial_state, &next_words);

        state = next;
    }

    // Padding rows (NUM_ROUNDS..HEIGHT): replicate last state with k=0, w=0.
    // This satisfies round constraints with k=0, w=0 producing predictable output.
    // For simplicity, we use round 0's values for padding (it satisfies all
    // constraints since each row is independent under the AIR).
    // Actually padding rows must be self-consistent under RoundChip constraints
    // AND satisfy transition constraints to/from real rows.
    // For simplicity we re-run round logic with k=0, w=0 starting from final state.
    let mut padding_state = state;
    for t in NUM_ROUNDS..HEIGHT {
        let row_off = t * NUM_COLS;
        let k_pad = 0u64;
        let w_pad = 0u64;
        let next_pad = compute_round(padding_state, k_pad, w_pad);

        let put_chunks = |values: &mut [F], off: usize, w: u64| {
            let chunks = super::word64_add::decompose_u64(w);
            for i in 0..4 {
                values[off + i] = F::from_u64(chunks[i]);
            }
        };

        let [a, b, c, d, e, f, g, h] = padding_state.0;
        put_chunks(&mut values, row_off + rc::A, a);
        put_chunks(&mut values, row_off + rc::B, b);
        put_chunks(&mut values, row_off + rc::C, c);
        put_chunks(&mut values, row_off + rc::D, d);
        put_chunks(&mut values, row_off + rc::E, e);
        put_chunks(&mut values, row_off + rc::F, f);
        put_chunks(&mut values, row_off + rc::G, g);
        put_chunks(&mut values, row_off + rc::H, h);
        put_chunks(&mut values, row_off + rc::K, k_pad);
        put_chunks(&mut values, row_off + rc::W, w_pad);

        put_chunks(&mut values, row_off + rc::NEW_A, next_pad.a());
        put_chunks(&mut values, row_off + rc::NEW_B, next_pad.b());
        put_chunks(&mut values, row_off + rc::NEW_C, next_pad.c());
        put_chunks(&mut values, row_off + rc::NEW_D, next_pad.d());
        put_chunks(&mut values, row_off + rc::NEW_E, next_pad.e());
        put_chunks(&mut values, row_off + rc::NEW_F, next_pad.f());
        put_chunks(&mut values, row_off + rc::NEW_G, next_pad.g());
        put_chunks(&mut values, row_off + rc::NEW_H, next_pad.h());

        let sigma1_e = big_sigma1(e);
        let ch_efg = ch(e, f, g);
        let sigma0_a = big_sigma0(a);
        let maj_abc = maj(a, b, c);
        let t11 = h.wrapping_add(sigma1_e);
        let t12 = t11.wrapping_add(ch_efg);
        let t13 = t12.wrapping_add(k_pad);
        let t1 = t13.wrapping_add(w_pad);
        let t2 = sigma0_a.wrapping_add(maj_abc);

        let bs_e = super::big_sigma::compute_big_sigma(e, 14, 18, 41);
        populate_big_sigma(&mut values, row_off + rc::BIG_SIGMA_E_START, &bs_e);
        let ch_w = super::ch::compute_ch(e, f, g);
        populate_ch(&mut values, row_off + rc::CH_START, &ch_w);
        let bs_a = super::big_sigma::compute_big_sigma(a, 28, 34, 39);
        populate_big_sigma(&mut values, row_off + rc::BIG_SIGMA_A_START, &bs_a);
        let maj_w = super::maj::compute_maj(a, b, c);
        populate_maj(&mut values, row_off + rc::MAJ_START, &maj_w);

        let add1 = super::word64_add::compute_add64(h, sigma1_e);
        populate_add(&mut values, row_off + rc::ADD_T1_1_START, &add1);
        let add2 = super::word64_add::compute_add64(t11, ch_efg);
        populate_add(&mut values, row_off + rc::ADD_T1_2_START, &add2);
        let add3 = super::word64_add::compute_add64(t12, k_pad);
        populate_add(&mut values, row_off + rc::ADD_T1_3_START, &add3);
        let add4 = super::word64_add::compute_add64(t13, w_pad);
        populate_add(&mut values, row_off + rc::ADD_T1_4_START, &add4);
        let add5 = super::word64_add::compute_add64(sigma0_a, maj_abc);
        populate_add(&mut values, row_off + rc::ADD_T2_START, &add5);
        let add6 = super::word64_add::compute_add64(d, t1);
        populate_add(&mut values, row_off + rc::ADD_NEW_E_START, &add6);
        let add7 = super::word64_add::compute_add64(t1, t2);
        populate_add(&mut values, row_off + rc::ADD_NEW_A_START, &add7);

        // Sub-fase 5.6.c.1.b.2 — extend the W shift register through
        // padding rows so the transition `next.HIST[15] = cur.W` keeps
        // holding (cur.W = 0 in padding, so HIST keeps absorbing zeros).
        populate_w_hist::<F>(&mut values, row_off, t, &w_full);

        // Sub-fase 5.6.c.1.b.3.embed — populate schedule_step in the
        // padding rows too. The gated constraint is 0 here (selector
        // off) but the chip's internal arithmetic still has to hold.
        let (w2, w7, w15, w16) = w_hist_lookup(&w_full, t);
        populate_schedule_step_at::<F>(&mut values, row_off, SCHEDULE_STEP_START, w2, w7, w15, w16);

        // Sub-fase 5.6.c.1.c — populate add-back chips in padding too.
        // The chips' internal arithmetic must hold even for rows whose
        // output is irrelevant to the digest.
        let next_words = [
            next_pad.a(), next_pad.b(), next_pad.c(), next_pad.d(),
            next_pad.e(), next_pad.f(), next_pad.g(), next_pad.h(),
        ];
        populate_add_back_chips::<F>(&mut values, row_off, initial_state, &next_words);

        padding_state = next_pad;
    }

    RowMajorMatrix::new(values, NUM_COLS)
}

/// Sub-fase 5.6.c.1.c (updated by 5.6.c.1.d.multi) — populate the 8
/// add-back chips at a row.
///
/// Each chip computes `iv[i] + next_state[i] (mod 2^64)`. The `iv`
/// argument was hardcoded `H_INITIAL` before 5.6.c.1.d.multi; now it
/// comes from the trace builder so that chained-block compressions
/// (block k's IV = block k-1's digest) populate the add-back chips
/// consistently with the PV[0..32] binding.
fn populate_add_back_chips<F: Field + PrimeCharacteristicRing>(
    values: &mut [F],
    row_off: usize,
    iv: &[u64; 8],
    next_words: &[u64; 8],
) {
    use crate::chips::lookup::range_n::Range16Chip;
    for i in 0..ADD_BACK_COUNT {
        let chip_base = row_off + ADD_BACK_START + i * ADD_COLS;
        let a = iv[i];
        let b = next_words[i];
        let w = compute_add64(a, b);
        // word64_add::col layout: A = 0, B = 4, C = 8, CARRY = 12 (each NUM_CHUNKS = 4 wide).
        let put_chunks = |values: &mut [F], off: usize, chunks: &[u64; 4]| {
            for j in 0..4 {
                values[off + j] = F::from_u64(chunks[j]);
            }
        };
        put_chunks(values, chip_base + adc::A, &w.a_chunks);
        put_chunks(values, chip_base + adc::B, &w.b_chunks);
        put_chunks(values, chip_base + adc::C, &w.c_chunks);
        put_chunks(values, chip_base + adc::CARRY, &w.carries);
        // Sub-fase 3.7.0 — populate 16-bit decomposition cells for a/b/c.
        for j in 0..4 {
            Range16Chip::populate_bits::<F>(values, chip_base + adc::A_BITS + j * 16, w.a_chunks[j]);
            Range16Chip::populate_bits::<F>(values, chip_base + adc::B_BITS + j * 16, w.b_chunks[j]);
            Range16Chip::populate_bits::<F>(values, chip_base + adc::C_BITS + j * 16, w.c_chunks[j]);
        }
    }
}

/// Sub-fase 5.6.c.1.b.3.embed helper — look up the four W values that
/// the embedded ScheduleStepChip consumes at row `t`:
///
///   W[t-2], W[t-7], W[t-15], W[t-16]
///
/// Indices outside `[0, NUM_ROUNDS)` clamp to zero, matching the W shift
/// register's pre-history (rows 0..16) and padding (rows ≥ 80) policies.
fn w_hist_lookup(w_full: &[u64; 80], t: usize) -> (u64, u64, u64, u64) {
    let lookup = |offset: isize| -> u64 {
        let idx = t as isize - offset;
        if (0..NUM_ROUNDS as isize).contains(&idx) { w_full[idx as usize] } else { 0 }
    };
    // Note: schedule_step's W_T_2 is W[t-2] etc.
    (lookup(2), lookup(7), lookup(15), lookup(16))
}

/// Populate the W shift register at row `t`. Slot `i` holds `W[t-16+i]`,
/// with negative indices clamped to zero (no W has been produced yet
/// pre-history). For `t > NUM_ROUNDS`, slots referencing `W[idx]` with
/// `idx >= NUM_ROUNDS` are also zero (matching `w_pad = 0` in the
/// padding loop).
fn populate_w_hist<F: Field + PrimeCharacteristicRing>(
    values: &mut [F],
    row_off: usize,
    t: usize,
    w_full: &[u64; 80],
) {
    for slot in 0..W_HIST_LEN {
        let signed_idx = t as isize - W_HIST_LEN as isize + slot as isize;
        let w_value: u64 = if (0..NUM_ROUNDS as isize).contains(&signed_idx) {
            w_full[signed_idx as usize]
        } else {
            0
        };
        let chunks = super::word64_add::decompose_u64(w_value);
        let off = row_off + W_HIST_START + slot * HIST_CHUNKS;
        for j in 0..HIST_CHUNKS {
            values[off + j] = F::from_u64(chunks[j]);
        }
    }
}

fn populate_big_sigma<F: Field + PrimeCharacteristicRing>(values: &mut [F], start: usize, w: &super::big_sigma::BigSigmaWitness) {
    use super::big_sigma::{NUM_BITS, NUM_CHUNKS, col as bsc};
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
    use super::ch::{NUM_BITS, NUM_CHUNKS, col as chc};
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
    use super::maj::{NUM_BITS, NUM_CHUNKS, col as mjc};
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
    use super::word64_add::{NUM_CHUNKS, col as adc};
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
    use super::super::constants::H_INITIAL;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeField32;

    fn read_state(values: &[BabyBear], row_off: usize, base: usize) -> u64 {
        let mut chunks = [0u64; 4];
        for i in 0..4 {
            chunks[i] = values[row_off + base + i].as_canonical_u32() as u64;
        }
        chunks[0] | (chunks[1] << 16) | (chunks[2] << 32) | (chunks[3] << 48)
    }

    /// Helper: derive the digest_words for a given block from H_INITIAL.
    fn digest_words_for(block: &[u64; 16]) -> [u64; 8] {
        digest_words_for_iv(&H_INITIAL, block)
    }

    /// Helper: derive digest_words from arbitrary IV (used by multi-block tests).
    fn digest_words_for_iv(iv: &[u64; 8], block: &[u64; 16]) -> [u64; 8] {
        let final_state = super::super::compression::compute_compression(
            super::super::round::Sha512State::new(*iv),
            block,
        );
        final_state.0
    }

    /// Build single-block PV from (block, digest), defaulting IV to H_INITIAL.
    fn pv_for_h_initial(block: &[u64; 16], digest: &[u64; 8]) -> Vec<BabyBear> {
        build_public_values::<BabyBear>(&H_INITIAL, block, digest)
    }

    /// Verify the multi-row compression AIR validates a full SHA-512("abc")
    /// compression: 80 rounds + state transitions all consistent.
    #[test]
    fn compression_sha512_abc() {
        let initial = H_INITIAL;
        let mut block = [0u64; 16];
        block[0] = 0x6162638000000000;
        block[15] = 0x0000000000000018;

        let trace = build_compression_trace::<BabyBear>(&initial, &block);
        let pv = pv_for_h_initial(&block, &digest_words_for(&block));
        check_constraints(&CompressionChip, &trace, &pv);

        // Verify last round's NEW_A matches what compute_compression produces.
        let _final_state = super::super::compression::compute_compression(
            super::super::round::Sha512State::new(initial),
            &block,
        );
        // NOTE: compute_compression also adds the working state back into the
        // initial state. The CompressionChip currently does NOT do that step
        // (transition constraints chain rounds, but the final add-back is
        // out of scope of the per-round AIR — would require extra rows or
        // boundary constraints). So we check that round 79's outputs match
        // the working state before the final add-back.

        // For now, just verify the 80-round chain ran consistently.
        let row_79_off = 79 * NUM_COLS;
        let new_a_row79 = read_state(&trace.values, row_79_off, rc::NEW_A);
        let new_a_independent = {
            let mut state = super::super::round::Sha512State::new(initial);
            let w_full = super::super::schedule::compute_schedule(&block);
            for t in 0..80 {
                state = super::super::round::compute_round(state, K[t], w_full[t]);
            }
            state.a()
        };
        assert_eq!(new_a_row79, new_a_independent, "round 79 NEW_A should match independent computation");
    }

    /// Sub-fase 5.6.c.1.d.multi — chip is now IV-agnostic; the row 0 PV
    /// binding only requires `cur[A..H] == PV[0..32]`. Tampering with
    /// the trace's row 0 state (without matching PV) must be rejected.
    /// (The wrapper sha512_air_stark.rs is what enforces "IV = H_INITIAL
    /// for block 0".)
    #[test]
    fn compression_rejects_iv_pv_mismatch() {
        use std::panic;
        let block = [0u64; 16];
        let mut trace = build_compression_trace::<BabyBear>(&H_INITIAL, &block);

        // Build PV consistent with H_INITIAL (honest), then tamper trace's
        // row 0 A_chunk[0]: now trace[A] != PV[0].
        let pv = pv_for_h_initial(&block, &digest_words_for(&block));
        trace.values[rc::A] = BabyBear::from_u64((trace.values[rc::A].as_canonical_u32() as u64) ^ 1);

        let res = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            check_constraints(&CompressionChip, &trace, &pv);
        }));
        assert!(res.is_err(), "row 0 IV cell != PV.IV must be rejected");
    }

    /// Trace with the correct H_INITIAL applied to an all-zero block —
    /// validates that the IV binding accepts the canonical IV regardless
    /// of message contents.
    #[test]
    fn compression_canonical_iv_with_zero_block() {
        let block = [0u64; 16];
        let trace = build_compression_trace::<BabyBear>(&H_INITIAL, &block);
        let pv = pv_for_h_initial(&block, &digest_words_for(&block));
        check_constraints(&CompressionChip, &trace, &pv);
    }

    /// Sub-fase 5.6.c.1.b.2 — W shift register rejects a non-zero
    /// boundary at row 0. The boundary constraint forces every HIST
    /// slot to be zero on the first row (no pre-history exists).
    #[test]
    fn compression_rejects_nonzero_hist_at_row_zero() {
        use std::panic;
        let mut block = [0u64; 16];
        block[0] = 0x6162638000000000;
        block[15] = 0x0000000000000018;
        let mut trace = build_compression_trace::<BabyBear>(&H_INITIAL, &block);

        // Plant a non-zero value in HIST[0] at row 0.
        trace.values[W_HIST_START] = BabyBear::from_u64(1);

        let pv = pv_for_h_initial(&block, &digest_words_for(&block));
        let res = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            check_constraints(&CompressionChip, &trace, &pv);
        }));
        assert!(res.is_err(), "non-zero W_HIST at row 0 must be rejected");
    }

    /// Sub-fase 5.6.c.1.b.2 — shift register rejects a transition
    /// violation: `next.HIST[i] == cur.HIST[i+1]` for `i in 0..15`.
    #[test]
    fn compression_rejects_broken_hist_shift() {
        use std::panic;
        let mut block = [0u64; 16];
        block[0] = 0x6162638000000000;
        block[15] = 0x0000000000000018;
        let mut trace = build_compression_trace::<BabyBear>(&H_INITIAL, &block);

        // Tamper with row 1's HIST[14]: should equal row 0's HIST[15].
        // Row 0 HIST[15] is 0 by boundary; flipping the lowest chunk to 1
        // breaks the transition `next.HIST[14] = cur.HIST[15]`.
        let row1_hist14_off = NUM_COLS + W_HIST_START + 14 * HIST_CHUNKS;
        trace.values[row1_hist14_off] = BabyBear::from_u64(0xBEEF);

        let pv = pv_for_h_initial(&block, &digest_words_for(&block));
        let res = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            check_constraints(&CompressionChip, &trace, &pv);
        }));
        assert!(res.is_err(), "broken HIST shift must be rejected");
    }

    /// Sub-fase 5.6.c.1.b.3.embed — gated W binding rejects a tampered W
    /// inside the schedule_step range (rows 16..80). The constraint
    /// `IS_SCHEDULE_ROW · (cur.W − schedule_step.W_T) = 0` should fail
    /// because at row 16 the selector is 1.
    #[test]
    fn compression_rejects_tampered_w_in_schedule_range() {
        use std::panic;
        let mut block = [0u64; 16];
        block[0] = 0x6162638000000000;
        block[15] = 0x0000000000000018;
        let mut trace = build_compression_trace::<BabyBear>(&H_INITIAL, &block);

        // Flip the lowest W chunk at row 16 (where the gate is on).
        let row16_w_off = 16 * NUM_COLS + rc::W;
        let cur = trace.values[row16_w_off];
        trace.values[row16_w_off] = BabyBear::from_u64(cur.as_canonical_u32() as u64 ^ 1);

        let pv = pv_for_h_initial(&block, &digest_words_for(&block));
        let res = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            check_constraints(&CompressionChip, &trace, &pv);
        }));
        assert!(res.is_err(), "tampered W in schedule range must be rejected");
    }

    /// Sub-fase 5.6.c.1.b.3.embed — outside the schedule range the gate
    /// is 0 so an inconsistent W cannot be detected by *this* constraint.
    /// (Round-chip arithmetic might still catch it via downstream
    /// transitions, but the gating semantics specifically allow rows
    /// 0..15 / 80..127 to carry a W untied to the recurrence — those
    /// rows draw W from the message block / padding instead.)
    /// The point of this test: confirm the gate is actually doing the
    /// gating job, not silently always-on.
    #[test]
    fn compression_gate_silent_on_padding_rows() {
        // Build trace as usual; padding rows 80..127 already have W=0
        // and schedule_step.W_T computed from the real W history (not
        // zero). The trace must still validate — meaning the gate is
        // correctly suppressing the equality check there.
        let mut block = [0u64; 16];
        block[0] = 0x6162638000000000;
        block[15] = 0x0000000000000018;
        let trace = build_compression_trace::<BabyBear>(&H_INITIAL, &block);
        let pv = pv_for_h_initial(&block, &digest_words_for(&block));
        check_constraints(&CompressionChip, &trace, &pv);
    }

    /// Sub-fase 5.6.c.1.d — `fips_pad_single_block` produces a block that
    /// hashes to the same digest as the standalone `sha512` helper for
    /// any message ≤ 111 bytes.
    #[test]
    fn fips_pad_round_trip_against_sha512_witness() {
        use super::super::compression::sha512;
        let cases: &[&[u8]] = &[
            b"",
            b"a",
            b"abc",
            b"The quick brown fox jumps over the lazy dog",
            // 55 bytes (boundary just below message_byte_len + 0x80 + length crossing)
            b"012345678901234567890123456789012345678901234567890123\x00\x00",
            // 111 bytes — exact maximum for single-block.
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ];
        for &msg in cases {
            assert!(msg.len() <= MAX_SINGLE_BLOCK_MESSAGE_BYTES, "test setup error");
            let block = fips_pad_single_block(msg).expect("padding fits");
            // Independently compute via compute_compression starting from H_INITIAL.
            let final_state = super::super::compression::compute_compression(
                super::super::round::Sha512State::new(H_INITIAL),
                &block,
            );
            // sha512(msg) for ≤ 111-byte input is exactly one compression block.
            let expected = sha512(msg);
            let mut actual = [0u8; 64];
            for (i, word) in final_state.0.iter().enumerate() {
                actual[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
            }
            assert_eq!(actual, expected, "digest mismatch for message len {}", msg.len());
        }
    }

    /// Sub-fase 5.6.c.1.d — `fips_pad_single_block` rejects oversize input.
    #[test]
    fn fips_pad_rejects_oversize_message() {
        let too_long = vec![0u8; MAX_SINGLE_BLOCK_MESSAGE_BYTES + 1];
        assert!(fips_pad_single_block(&too_long).is_none());
    }

    /// Sub-fase 5.6.c.1.d — `build_sha512_trace_short` produces a trace
    /// whose row-79 add_back outputs match `sha512(message)`. End-to-end
    /// validation of padding + AIR + add-back for arbitrary short input.
    #[test]
    fn build_short_trace_digest_matches_sha512() {
        use super::super::compression::sha512;

        let messages: &[&[u8]] = &[b"", b"abc", b"Sophis ZK-Oracle test vector for SHA-512"];
        for &msg in messages {
            let trace = build_sha512_trace_short::<BabyBear>(msg).expect("fits in one block");
            let block = fips_pad_single_block(msg).expect("fits");
            let pv = pv_for_h_initial(&block, &digest_words_for(&block));
            check_constraints(&CompressionChip, &trace, &pv);

            // Read row 79's add_back.C words and compare to sha512(msg).
            let row_off = (NUM_ROUNDS - 1) * NUM_COLS; // row 79
            let mut actual_words = [0u64; 8];
            for i in 0..ADD_BACK_COUNT {
                let c_off = row_off + ADD_BACK_START + i * ADD_COLS + adc::C;
                actual_words[i] = read_state(&trace.values, 0, c_off);
            }
            let expected = sha512(msg);
            let mut expected_words = [0u64; 8];
            for i in 0..8 {
                expected_words[i] = u64::from_be_bytes(expected[i * 8..(i + 1) * 8].try_into().unwrap());
            }
            assert_eq!(actual_words, expected_words, "trace digest mismatch for msg len {}", msg.len());
        }
    }

    /// Sub-fase 5.6.c.1.d — `build_sha512_trace_short` returns None for
    /// messages > MAX_SINGLE_BLOCK_MESSAGE_BYTES.
    #[test]
    fn build_short_trace_rejects_oversize() {
        let too_long = vec![0u8; MAX_SINGLE_BLOCK_MESSAGE_BYTES + 1];
        assert!(build_sha512_trace_short::<BabyBear>(&too_long).is_none());
    }

    /// Sub-fase 5.6.c.1.e.1 — supplying the wrong digest in PV must
    /// fail the gated `IS_LAST_ACTIVE_ROUND` constraint at row 79.
    #[test]
    fn pv_digest_mismatch_rejected() {
        use std::panic;
        let mut block = [0u64; 16];
        block[0] = 0x6162638000000000;
        block[15] = 0x0000000000000018;
        let trace = build_compression_trace::<BabyBear>(&H_INITIAL, &block);

        // Flip a digest word in the PV (still 4 chunks per word, lowest chunk).
        let mut digest = digest_words_for(&block);
        digest[0] ^= 1; // tamper digest word 0
        let pv = pv_for_h_initial(&block, &digest);

        let res = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            check_constraints(&CompressionChip, &trace, &pv);
        }));
        assert!(res.is_err(), "PV with wrong digest must be rejected at row 79");
    }

    /// Sub-fase 5.6.c.1.e.1 — supplying the wrong message-block in PV
    /// must fail the gated `IS_FIRST_SCHEDULE_ROW` constraint at row 16.
    #[test]
    fn pv_message_block_mismatch_rejected() {
        use std::panic;
        let mut block = [0u64; 16];
        block[0] = 0x6162638000000000;
        block[15] = 0x0000000000000018;
        let trace = build_compression_trace::<BabyBear>(&H_INITIAL, &block);

        // Build PV with a different message block — digest still
        // matches the *trace's* block (so digest binding doesn't fire).
        let mut wrong_block = block;
        wrong_block[0] ^= 1;
        let pv = pv_for_h_initial(&wrong_block, &digest_words_for(&block));

        let res = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            check_constraints(&CompressionChip, &trace, &pv);
        }));
        assert!(res.is_err(), "PV with wrong message block must be rejected at row 16");
    }

    /// Sub-fase 5.6.c.1.c — at row 79's last-active-round, add_back.C
    /// must equal the canonical SHA-512 digest words (= IV + state
    /// after 80 rounds). Cross-validated against `compute_compression`.
    #[test]
    fn add_back_at_row_79_matches_digest() {
        let mut block = [0u64; 16];
        block[0] = 0x6162638000000000;
        block[15] = 0x0000000000000018;
        let trace = build_compression_trace::<BabyBear>(&H_INITIAL, &block);
        let pv = pv_for_h_initial(&block, &digest_words_for(&block));
        check_constraints(&CompressionChip, &trace, &pv);

        // Independent reference: compute the full digest in Rust.
        let final_state = super::super::compression::compute_compression(
            super::super::round::Sha512State::new(H_INITIAL),
            &block,
        );
        let expected = [
            final_state.a(), final_state.b(), final_state.c(), final_state.d(),
            final_state.e(), final_state.f(), final_state.g(), final_state.h(),
        ];

        let row_off = (NUM_ROUNDS - 1) * NUM_COLS; // row 79
        for i in 0..ADD_BACK_COUNT {
            let c_off = row_off + ADD_BACK_START + i * ADD_COLS + adc::C;
            let actual = read_state(&trace.values, 0, c_off);
            assert_eq!(actual, expected[i], "digest[{i}] mismatch");
        }
    }

    /// Sub-fase 5.6.c.1.c — tampering an add_back input (B = NEW_state)
    /// is caught by the chip's connection constraint at every row.
    #[test]
    fn add_back_rejects_tampered_b_input() {
        use std::panic;
        let mut block = [0u64; 16];
        block[0] = 0x6162638000000000;
        block[15] = 0x0000000000000018;
        let mut trace = build_compression_trace::<BabyBear>(&H_INITIAL, &block);

        // Flip the lowest chunk of add_back[0].B at row 0.
        let off = ADD_BACK_START + 0 * ADD_COLS + adc::B;
        let cur = trace.values[off];
        trace.values[off] = BabyBear::from_u64(cur.as_canonical_u32() as u64 ^ 1);

        let pv = pv_for_h_initial(&block, &digest_words_for(&block));
        let res = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            check_constraints(&CompressionChip, &trace, &pv);
        }));
        assert!(res.is_err(), "tampered add_back B input must be rejected");
    }

    /// Sub-fase 5.6.c.1.b.1 — K preprocessed binding rejects a tampered K.
    /// We mutate the K column at row 0 in the main trace; the constraint
    /// `main.K == preprocessed.K` must catch this independently of any
    /// downstream round-chip arithmetic that may also flag inconsistencies.
    #[test]
    fn compression_rejects_tampered_k_in_main() {
        use std::panic;
        let mut block = [0u64; 16];
        block[0] = 0x6162638000000000;
        block[15] = 0x0000000000000018;
        let mut trace = build_compression_trace::<BabyBear>(&H_INITIAL, &block);

        // Flip the lowest chunk of K at row 0 (rc::K is 32; chunk 0 lives
        // at index 32 in row 0). XOR-ing with 1 keeps the value within
        // BabyBear's 16-bit range.
        let cur = trace.values[rc::K];
        let perturbed = BabyBear::from_u64(cur.as_canonical_u32() as u64 ^ 1);
        trace.values[rc::K] = perturbed;

        let pv = pv_for_h_initial(&block, &digest_words_for(&block));
        let res = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            check_constraints(&CompressionChip, &trace, &pv);
        }));
        assert!(res.is_err(), "tampered main-K must be rejected by the AIR");
    }

    #[test]
    fn constraint_count_documented() {
        // Sub-fase 5.6.c.1.b.2 added 64 W shift register columns
        // (16 slots × 4 chunks per slot) on top of the round chip cols.
        // Sub-fase 5.6.c.1.b.3.embed adds the 468-col embedded
        // ScheduleStepChip after the shift register.
        // Sub-fase 5.6.c.1.c adds 8 × 16 = 128 cols for the add-back
        // word64_add chips, and a sixth preprocessed selector for the
        // last-active-round gate.
        // Sub-fase 5.6.c.1.e.1 adds NUM_PUBLIC_VALUES = 96 (16 message
        // words + 8 digest words, 4 chunks each) and a seventh
        // preprocessed selector for the first-schedule-row gate.
        // Sub-fase 5.6.c.1.d.multi expands NUM_PUBLIC_VALUES to 128
        // (adding 8 IV words × 4 chunks = 32 cells at PV[0..32]) so the
        // chip becomes chaining-agnostic and the wrapper can stitch
        // multi-block hashes together via PV equality.
        // Sub-fase 3.7.0 propagates +192 bit cells per word64_add embed.
        // round_chip: 7 embeds → +1344. schedule_step: 3 embeds → +576.
        // compression_chip add-back: 8 embeds → +1536. Total +3456.
        // 2172 + 3456 = 5628.
        assert_eq!(NUM_COLS, ROUND_COLS + W_HIST_COLS + SS_TOTAL_COLS + ADD_BACK_COUNT * ADD_COLS);
        assert_eq!(NUM_COLS, 5628);
        assert_eq!(NUM_PREPROCESSED_COLS, 7);
        assert_eq!(NUM_PUBLIC_VALUES, 128);
    }
}
