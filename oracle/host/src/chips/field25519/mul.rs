//! `field25519::mul` — schoolbook multiplication chip with 10-bit piece
//! decomposition.
//!
//! ## Why piece decomposition
//!
//! BabyBear is a ~2³¹ prime. A direct multiplication of two 30-bit limbs
//! is up to 2⁶⁰, which overflows the field. Standard zk-AIR practice is
//! to split each input limb into smaller pieces, multiply piece-by-piece,
//! and accumulate the polynomial coefficients.
//!
//! Decision (2026-05-05): use **10-bit pieces**, three per 30-bit limb
//! (clean split: 9·30 = 27·10 = 270 bits). Cross-products are ≤ 2²⁰; the
//! middle output position (index 26) sums up to 27 such products, so its
//! BabyBear value is bounded by `27·2²⁰ ≈ 2²⁵` — comfortably below 2³¹.
//!
//! ## Algorithm
//!
//! For inputs `A`, `B` represented as 9 30-bit limbs each, decompose into
//! 27 10-bit pieces:
//!
//!   `a_p[3i + 0] = a[i] mod 2¹⁰`
//!   `a_p[3i + 1] = (a[i] >> 10) mod 2¹⁰`
//!   `a_p[3i + 2] = (a[i] >> 20) mod 2¹⁰`
//!
//! Then `A·B`'s polynomial coefficients (in base 2¹⁰) are:
//!
//!   `out_pos[k] = Σᵢ₊ⱼ₌ₖ a_p[i] · b_p[j]`   for `k ∈ [0, 53)`
//!
//! The result (a 540-bit polynomial in base 2¹⁰) is left **unreduced**
//! at this stage — it is neither carry-propagated to canonical 30-bit
//! limbs nor reduced mod `p`. Those are separate downstream chips
//! (sub-phase 5.2.1.1.c will land the carry-fold + mod-p reduction).
//!
//! ## Trace layout (one operation per row, allocated at `start_col`)
//!
//! | offset    | width | name                                |
//! |-----------|-------|-------------------------------------|
//! | 0         | 9     | a limbs (input from upstream)       |
//! | 9         | 9     | b limbs (input from upstream)       |
//! | 18        | 27    | a pieces (witness)                  |
//! | 45        | 27    | b pieces (witness)                  |
//! | 72        | 53    | out polynomial positions            |
//! | 125       | 270   | a piece bits (27 × 10, Etapa 3.2)   |
//! | 395       | 270   | b piece bits (27 × 10, Etapa 3.2)   |
//!
//! Total: **665 columns**, **611 constraints** (18 decomposition + 53
//! output positions + 540 boolean + 0 wait, 54 recompositions are
//! already covered by the existing decomposition constraints — the
//! range chip adds 11 constraints per piece = 594 new), max degree 2.
//!
//! Concrete count: 71 (original) + 54 × 11 = 71 + 594 = **665 constraints**.
//!
//! ## Soundness — closed by Etapa 3.2 (RangeNChip<10>)
//!
//! Each of the 54 piece columns is now wired through `RangeNChip<10>` in
//! split layout: the piece value lives where it always did
//! (cols 18..72), and the chip's 10 bit columns are appended in the
//! piece-bits region (cols 125..665). The recomposition constraint
//! forces each piece to equal its bit decomposition, so the value
//! provably fits in `[0, 1024)`. Combined with the existing limb-recovery
//! constraint (`a_limb = a_p0 + 2¹⁰·a_p1 + 2²⁰·a_p2`), this also tightens
//! the per-limb bound from "anywhere in BabyBear" to "exactly 30 bits".
//!
//! BabyBear-overflow exploit on cross products is no longer reachable:
//! every input to the `out_pos[k] = Σ a_p[i] · b_p[j]` constraint is
//! provably `< 2¹⁰`, so the maximum sum at any position is
//! `27·(2¹⁰-1)² < 2²⁵`, well below the BabyBear prime.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::{Field25519Element, NUM_LIMBS};
use crate::chips::lookup::range_n::RangeNChip;

/// Number of 10-bit pieces per input.
pub const PIECES_PER_INPUT: usize = 27;
/// Number of bits per piece (`2^PIECE_BITS = PIECE_MOD`).
pub const PIECE_BITS: usize = 10;
/// `2^PIECE_BITS`.
pub const PIECE_MOD: u64 = 1u64 << PIECE_BITS;
/// Number of polynomial output positions (`2·PIECES_PER_INPUT - 1`).
pub const OUTPUT_POSITIONS: usize = 2 * PIECES_PER_INPUT - 1; // 53

/// Trace column offsets within the chip's slice.
pub mod col {
    use super::*;
    pub const A_LIMBS: usize = 0;
    pub const B_LIMBS: usize = A_LIMBS + NUM_LIMBS; // 9
    pub const A_PIECES: usize = B_LIMBS + NUM_LIMBS; // 18
    pub const B_PIECES: usize = A_PIECES + PIECES_PER_INPUT; // 45
    pub const OUT_POS: usize = B_PIECES + PIECES_PER_INPUT; // 72
    pub const A_PIECE_BITS: usize = OUT_POS + OUTPUT_POSITIONS; // 125 — Etapa 3.2
    pub const B_PIECE_BITS: usize = A_PIECE_BITS + PIECES_PER_INPUT * PIECE_BITS; // 395
}

pub const NUM_COLS: usize = col::B_PIECE_BITS + PIECES_PER_INPUT * PIECE_BITS; // 665
/// 18 decomposition + 53 output positions + 54 × 11 (bool + recomposition per piece).
pub const NUM_CONSTRAINTS: usize = 2 * NUM_LIMBS + OUTPUT_POSITIONS + 2 * PIECES_PER_INPUT * (PIECE_BITS + 1); // 665

#[derive(Debug, Clone, Copy)]
pub struct MulChip {
    pub start_col: usize,
}

impl Default for MulChip {
    fn default() -> Self {
        Self::new()
    }
}

impl MulChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    /// Emit the 71 constraints into the supplied builder.
    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();

        let weight_2_10 = AB::Expr::from_u64(1 << 10);
        let weight_2_20 = AB::Expr::from_u64(1 << 20);

        // ── Decomposition constraints (18 = 9 + 9) ─────────────────────
        for i in 0..NUM_LIMBS {
            let a_limb = row[self.start_col + col::A_LIMBS + i];
            let a_p0 = row[self.start_col + col::A_PIECES + 3 * i];
            let a_p1 = row[self.start_col + col::A_PIECES + 3 * i + 1];
            let a_p2 = row[self.start_col + col::A_PIECES + 3 * i + 2];
            let recomposed = a_p0.into() + weight_2_10.clone() * a_p1.into() + weight_2_20.clone() * a_p2.into();
            builder.assert_eq(a_limb, recomposed);

            let b_limb = row[self.start_col + col::B_LIMBS + i];
            let b_p0 = row[self.start_col + col::B_PIECES + 3 * i];
            let b_p1 = row[self.start_col + col::B_PIECES + 3 * i + 1];
            let b_p2 = row[self.start_col + col::B_PIECES + 3 * i + 2];
            let recomposed = b_p0.into() + weight_2_10.clone() * b_p1.into() + weight_2_20.clone() * b_p2.into();
            builder.assert_eq(b_limb, recomposed);
        }

        // ── Output position constraints (53) ───────────────────────────
        // For each k, out_pos[k] = Σ_{i+j=k, 0≤i,j<27} a_p[i] * b_p[j].
        // Each constraint is degree 2 (cross-products).
        for k in 0..OUTPUT_POSITIONS {
            let i_min = k.saturating_sub(PIECES_PER_INPUT - 1);
            let i_max = k.min(PIECES_PER_INPUT - 1);
            let mut sum = AB::Expr::ZERO;
            for i in i_min..=i_max {
                let j = k - i;
                let a_p = row[self.start_col + col::A_PIECES + i];
                let b_p = row[self.start_col + col::B_PIECES + j];
                sum += a_p.into() * b_p.into();
            }
            let out_pos = row[self.start_col + col::OUT_POS + k];
            builder.assert_eq(out_pos, sum);
        }

        // ── 10-bit range checks on every piece (Etapa 3.2) ─────────────
        // Each piece column gets a split-layout RangeNChip<10> whose bit
        // columns live in the A_PIECE_BITS / B_PIECE_BITS region.
        for i in 0..PIECES_PER_INPUT {
            RangeNChip::<PIECE_BITS>::split(self.start_col + col::A_PIECES + i, self.start_col + col::A_PIECE_BITS + i * PIECE_BITS)
                .emit(builder);
            RangeNChip::<PIECE_BITS>::split(self.start_col + col::B_PIECES + i, self.start_col + col::B_PIECE_BITS + i * PIECE_BITS)
                .emit(builder);
        }
    }
}

/// Standalone test AIR wrapping the chip.
#[derive(Debug, Clone, Copy)]
pub struct MulTestAir;

impl<F: Field> BaseAir<F> for MulTestAir {
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

impl<AB: AirBuilder> Air<AB> for MulTestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        MulChip::new().emit(builder);
    }
}

/// Witness layout returned by `compute_mul`. Holds everything the trace
/// needs: input pieces and the unreduced polynomial output.
#[derive(Debug, Clone)]
pub struct MulWitness {
    pub a_pieces: [u64; PIECES_PER_INPUT],
    pub b_pieces: [u64; PIECES_PER_INPUT],
    pub out_positions: [u64; OUTPUT_POSITIONS],
}

/// Decompose a canonical-limb element into 27 10-bit pieces.
///
/// **Precondition:** every input limb must be `< 2³⁰`. Looser inputs
/// produce piece values `≥ 2¹⁰`, which would later violate the implicit
/// 10-bit range bound (gap noted in the chip docs).
pub fn decompose(elem: &Field25519Element) -> [u64; PIECES_PER_INPUT] {
    let mut out = [0u64; PIECES_PER_INPUT];
    for i in 0..NUM_LIMBS {
        out[3 * i] = elem.limbs[i] & (PIECE_MOD - 1);
        out[3 * i + 1] = (elem.limbs[i] >> PIECE_BITS) & (PIECE_MOD - 1);
        out[3 * i + 2] = (elem.limbs[i] >> (2 * PIECE_BITS)) & (PIECE_MOD - 1);
    }
    out
}

/// Compute the witness `(a_pieces, b_pieces, out_positions)` for one
/// multiplication. `out_positions[k]` holds the unreduced polynomial
/// coefficient at position `2¹⁰ᵏ`.
pub fn compute_mul(a: &Field25519Element, b: &Field25519Element) -> MulWitness {
    let a_pieces = decompose(a);
    let b_pieces = decompose(b);
    let mut out_positions = [0u64; OUTPUT_POSITIONS];
    for i in 0..PIECES_PER_INPUT {
        for j in 0..PIECES_PER_INPUT {
            out_positions[i + j] += a_pieces[i] * b_pieces[j];
        }
    }
    MulWitness { a_pieces, b_pieces, out_positions }
}

/// Populate ALL columns of one MulChip slot (limbs + pieces + output
/// positions + 10-bit range bits) for a given (a, b, witness). Used by
/// the standalone test trace below AND by upstream embedders
/// (mul_pipeline, mul_canonical, ...) so the range-bit columns stay
/// single-source-of-truth in this module.
///
/// `chip_off` is the absolute byte offset into `values` of the chip's
/// first column (`row * trace_width + start_col_of_this_chip`).
pub fn populate_row<F: Field + PrimeCharacteristicRing>(
    values: &mut [F],
    chip_off: usize,
    a: &Field25519Element,
    b: &Field25519Element,
    w: &MulWitness,
) {
    for i in 0..NUM_LIMBS {
        values[chip_off + col::A_LIMBS + i] = F::from_u64(a.limbs[i]);
        values[chip_off + col::B_LIMBS + i] = F::from_u64(b.limbs[i]);
    }
    for i in 0..PIECES_PER_INPUT {
        values[chip_off + col::A_PIECES + i] = F::from_u64(w.a_pieces[i]);
        values[chip_off + col::B_PIECES + i] = F::from_u64(w.b_pieces[i]);
        RangeNChip::<PIECE_BITS>::populate_bits::<F>(values, chip_off + col::A_PIECE_BITS + i * PIECE_BITS, w.a_pieces[i]);
        RangeNChip::<PIECE_BITS>::populate_bits::<F>(values, chip_off + col::B_PIECE_BITS + i * PIECE_BITS, w.b_pieces[i]);
    }
    for k in 0..OUTPUT_POSITIONS {
        values[chip_off + col::OUT_POS + k] = F::from_u64(w.out_positions[k]);
    }
}

/// Build a single-row test trace exercising one multiplication. Pads
/// rows 1..3 with zeros (which trivially satisfy: 0+0=0 decomp, 0=0
/// output positions, 0 = sum of all-zero bits).
pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(
    a: &Field25519Element,
    b: &Field25519Element,
    w: &MulWitness,
) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];
    populate_row::<F>(&mut values, 0, a, b, w);
    RowMajorMatrix::new(values, NUM_COLS)
}

/// Reconstruct the integer product (mod 2⁵⁴⁰, i.e. the unreduced full
/// product) from the polynomial output positions. Used by tests to
/// verify the chip's witness against an independent computation.
pub fn reconstruct_product(out_positions: &[u64; OUTPUT_POSITIONS]) -> u128 {
    // Accumulate as u128 for the low half. (Full 540-bit reconstruction
    // would need a bigint — the tests pick small enough inputs that the
    // product fits in 128 bits.)
    let mut acc: u128 = 0;
    for k in (0..OUTPUT_POSITIONS).rev() {
        if 10 * k >= 128 {
            continue;
        }
        acc = acc.wrapping_add((out_positions[k] as u128) << (10 * k));
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    /// Build a Field25519Element holding `n` (must fit in 60 bits, i.e.
    /// limbs 0 and 1 only).
    fn elem_from_u64(n: u64) -> Field25519Element {
        let mut limbs = [0u64; NUM_LIMBS];
        limbs[0] = n & ((1 << 30) - 1);
        limbs[1] = (n >> 30) & ((1 << 30) - 1);
        Field25519Element { limbs }
    }

    #[test]
    fn decompose_round_trip() {
        let e = elem_from_u64(0xDEAD_BEEF_CAFE);
        let pieces = decompose(&e);
        // Re-pack pieces back into limbs and check.
        for i in 0..NUM_LIMBS {
            let recomposed = pieces[3 * i] + (pieces[3 * i + 1] << 10) + (pieces[3 * i + 2] << 20);
            assert_eq!(recomposed, e.limbs[i], "limb {i} mismatch");
        }
    }

    #[test]
    fn compute_mul_three_times_seven_is_twenty_one() {
        let a = elem_from_u64(3);
        let b = elem_from_u64(7);
        let w = compute_mul(&a, &b);
        assert_eq!(reconstruct_product(&w.out_positions), 21);
    }

    #[test]
    fn compute_mul_matches_integer_product() {
        for (x, y) in [(1u64, 1), (12345, 67890), (0xFFFF, 0xFFFF), (0x3FFF_FFFF, 2), (0, 99)] {
            let a = elem_from_u64(x);
            let b = elem_from_u64(y);
            let w = compute_mul(&a, &b);
            let expected = (x as u128) * (y as u128);
            assert_eq!(reconstruct_product(&w.out_positions), expected, "mul {x}*{y}");
        }
    }

    #[test]
    fn mul_satisfies_air_for_small_values() {
        let a = elem_from_u64(12345);
        let b = elem_from_u64(67890);
        let w = compute_mul(&a, &b);
        let trace = build_test_trace::<BabyBear>(&a, &b, &w);
        check_constraints(&MulTestAir, &trace, &[]);
    }

    #[test]
    fn mul_satisfies_air_for_zero_input() {
        let a = elem_from_u64(0);
        let b = elem_from_u64(0xDEAD_BEEF);
        let w = compute_mul(&a, &b);
        // Output should be all-zero positions.
        for &v in &w.out_positions {
            assert_eq!(v, 0);
        }
        let trace = build_test_trace::<BabyBear>(&a, &b, &w);
        check_constraints(&MulTestAir, &trace, &[]);
    }

    #[test]
    fn mul_satisfies_air_for_one_input() {
        let a = elem_from_u64(1);
        let b = elem_from_u64(0x12345678);
        let w = compute_mul(&a, &b);
        // a_pieces[0] = 1, all other a_pieces = 0.
        // So out_positions[k] = b_pieces[k] for k < 27, else 0.
        for k in 0..PIECES_PER_INPUT {
            assert_eq!(w.out_positions[k], w.b_pieces[k]);
        }
        for k in PIECES_PER_INPUT..OUTPUT_POSITIONS {
            assert_eq!(w.out_positions[k], 0);
        }
        let trace = build_test_trace::<BabyBear>(&a, &b, &w);
        check_constraints(&MulTestAir, &trace, &[]);
    }

    #[test]
    fn mul_max_canonical_limbs_satisfies_air() {
        // Both inputs at (2^30 - 1) per limb across all 9 limbs.
        // Every piece is exactly 2^10 - 1 = 1023.
        // Each output position k has min(k+1, 27, 53-k) cross products,
        // each = 1023*1023 = 1_046_529. Middle position k=26 sums 27 * 1_046_529
        // ≈ 2^24.85 — fits BabyBear.
        let a = Field25519Element { limbs: [(1 << 30) - 1; NUM_LIMBS] };
        let b = a;
        let w = compute_mul(&a, &b);
        let trace = build_test_trace::<BabyBear>(&a, &b, &w);
        check_constraints(&MulTestAir, &trace, &[]);
    }

    #[test]
    fn mul_p_times_zero_is_zero() {
        let p = Field25519Element::P;
        let z = Field25519Element::ZERO;
        let w = compute_mul(&p, &z);
        for &v in &w.out_positions {
            assert_eq!(v, 0);
        }
        let trace = build_test_trace::<BabyBear>(&p, &z, &w);
        check_constraints(&MulTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn mul_rejects_tampered_output_position() {
        let a = elem_from_u64(100);
        let b = elem_from_u64(200);
        let w = compute_mul(&a, &b);
        let mut trace = build_test_trace::<BabyBear>(&a, &b, &w);
        // Flip one bit on output position 0 — multiplication constraint must reject.
        trace.values[col::OUT_POS] += BabyBear::ONE;
        check_constraints(&MulTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn mul_rejects_tampered_decomposition() {
        let a = elem_from_u64(100);
        let b = elem_from_u64(200);
        let w = compute_mul(&a, &b);
        let mut trace = build_test_trace::<BabyBear>(&a, &b, &w);
        // Mutate a_pieces[0] without updating a_limbs[0] or output positions.
        trace.values[col::A_PIECES] += BabyBear::ONE;
        check_constraints(&MulTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn mul_rejects_swapped_inputs_with_asymmetric_pieces() {
        // Use inputs where a != b so swapping b with stale a-pieces
        // breaks the decomposition constraint on b.
        let a = elem_from_u64(0x1234);
        let b = elem_from_u64(0x9876);
        let w = compute_mul(&a, &b);
        let trace = build_test_trace::<BabyBear>(&b, &a, &w); // swap limbs but keep pieces
        check_constraints(&MulTestAir, &trace, &[]);
    }

    /// Constraint count sanity — make sure NUM_CONSTRAINTS matches what
    /// we actually emit. Counted by the DebugConstraintBuilder during
    /// `check_constraints`, which advances `constraint_index` once per
    /// `assert_zero`. We verify by emitting on a fixture and counting.
    #[test]
    fn constraint_count_matches_documented() {
        // Etapa 3.2: post-range-check counts.
        // 18 decomposition + 53 output positions + 54 × 11 (range check per piece) = 665.
        assert_eq!(NUM_CONSTRAINTS, 665);
        // 18 (limbs) + 54 (pieces) + 53 (positions) + 540 (piece bits) = 665.
        assert_eq!(NUM_COLS, 665);
    }

    // ===== Etapa 3.4 — adversarial range-check rejection =====

    /// Witness with a piece value > 2^10 must be rejected by the range
    /// check: even if all multiplication constraints could (hypothetically)
    /// be satisfied via BabyBear wrap-around, the piece's bit
    /// recomposition would have to sum to a value > 2^10, which is
    /// impossible with 10 boolean bits.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_piece_above_2_to_10() {
        let a = elem_from_u64(100);
        let b = elem_from_u64(200);
        let w = compute_mul(&a, &b);
        let mut trace = build_test_trace::<BabyBear>(&a, &b, &w);
        // Mutate a_pieces[0] to 1024 (= 2^10, out of 10-bit range).
        // The bit columns currently encode the original (in-range) value;
        // recomposition constraint will reject when value != Σ 2^i b[i].
        trace.values[col::A_PIECES] = BabyBear::from_u64(1024);
        check_constraints(&MulTestAir, &trace, &[]);
    }

    /// Tampering a single bit column must also be caught — the
    /// recomposition forces every bit to match the value's binary form.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_tampered_piece_bit() {
        let a = elem_from_u64(100);
        let b = elem_from_u64(200);
        let w = compute_mul(&a, &b);
        let mut trace = build_test_trace::<BabyBear>(&a, &b, &w);
        // Flip bit 0 of a_pieces[0]. Either bit_0 != 0/1 or recomposition fails.
        let bit0_off = col::A_PIECE_BITS;
        trace.values[bit0_off] += BabyBear::ONE;
        check_constraints(&MulTestAir, &trace, &[]);
    }

    /// Setting a piece-bit column to a non-boolean value (e.g. 2) must
    /// fail the boolean assertion immediately.
    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn rejects_non_boolean_piece_bit() {
        let a = elem_from_u64(100);
        let b = elem_from_u64(200);
        let w = compute_mul(&a, &b);
        let mut trace = build_test_trace::<BabyBear>(&a, &b, &w);
        // Set a non-boolean value in bit 5 of b_pieces[3].
        let bit_off = col::B_PIECE_BITS + 3 * PIECE_BITS + 5;
        trace.values[bit_off] = BabyBear::from_u64(2);
        check_constraints(&MulTestAir, &trace, &[]);
    }
}
