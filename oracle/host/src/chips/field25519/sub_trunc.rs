//! `field25519::sub_trunc` — composed chip producing canonical
//! `c = (a + p - b) mod 2²⁷⁰` from two canonical 9-limb inputs.
//!
//! Mirrors `add_trunc` structure but uses `SubChip` (which adds `p`
//! per-limb to keep values non-negative) instead of `AddChip`.
//!
//! Composes:
//!
//!   - `SubChip`     — per-limb `c[i] = a[i] + p[i] - b[i]` (loose)
//!   - `ReduceChip`  — carry propagation to canonical 30-bit limbs
//!
//! ## Output semantics
//!
//! For canonical inputs `a, b < p`:
//!
//!   `output_value = (a + p - b) mod 2²⁷⁰ = a - b + p (in [0, 2p))`
//!
//! This is congruent to `a - b` mod `p` but shifted by `p`. To recover
//! the canonical `[0, p)` representative, a downstream conditional
//! `p`-subtraction step is needed (pending — same mod-p AIR work).
//!
//! Useful as a building block for ed25519 chips that tolerate "shifted"
//! canonical output.
//!
//! ## Layout
//!
//! Same as `add_trunc`:
//!
//! | Range     | Width | Contents                              |
//! |-----------|-------|---------------------------------------|
//! | 0..9      | 9     | a chunks (input)                      |
//! | 9..18     | 9     | b chunks (input)                      |
//! | 18..27    | 9     | c chunks (output, canonical 30-bit)   |
//! | 27..54    | 27    | SubChip                               |
//! | 54..81    | 27    | ReduceChip                            |
//!
//! Total: **81 columns**, ~64 constraints (degree 1 max).
//!
//! ## Soundness
//!
//! Same gap as the underlying ReduceChip: output and carries not
//! range-checked inline. Closes globally with lookup args in 5.2.1.7.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::reduce::{NUM_COLS as RED_COLS, ReduceChip};
use super::sub::{NUM_COLS as SUB_COLS, SubChip};
use super::{Field25519Element, NUM_LIMBS};

pub mod col {
    use super::*;
    pub const A: usize = 0;
    pub const B: usize = A + NUM_LIMBS;          // 9
    pub const C: usize = B + NUM_LIMBS;          // 18
    pub const SUB_START: usize = C + NUM_LIMBS;  // 27
    pub const REDUCE_START: usize = SUB_START + SUB_COLS; // 54

    pub const TOTAL: usize = REDUCE_START + RED_COLS; // 81
}

pub const NUM_COLS: usize = col::TOTAL;

#[derive(Debug, Clone, Copy)]
pub struct SubTruncChip {
    pub start_col: usize,
}

impl SubTruncChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        SubChip::at(self.start_col + col::SUB_START).emit(builder);
        ReduceChip::at(self.start_col + col::REDUCE_START).emit(builder);

        let main = builder.main();
        let row = main.current_slice();

        let assert_chunks_eq = |b: &mut AB, off_a: usize, off_b: usize, n: usize| {
            for i in 0..n {
                b.assert_eq(row[off_a + i], row[off_b + i]);
            }
        };

        assert_chunks_eq(builder, self.start_col + col::SUB_START + 0, self.start_col + col::A, NUM_LIMBS);
        assert_chunks_eq(builder, self.start_col + col::SUB_START + NUM_LIMBS, self.start_col + col::B, NUM_LIMBS);
        assert_chunks_eq(
            builder,
            self.start_col + col::REDUCE_START + 0,
            self.start_col + col::SUB_START + 2 * NUM_LIMBS,
            NUM_LIMBS,
        );
        assert_chunks_eq(builder, self.start_col + col::C, self.start_col + col::REDUCE_START + NUM_LIMBS, NUM_LIMBS);
    }
}

impl<F: Field> BaseAir<F> for SubTruncChip {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(1)
    }
}

impl<AB: AirBuilder> Air<AB> for SubTruncChip
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        self.emit(builder);
    }
}

/// Build a single-row trace exercising one composed sub+reduce.
pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(
    a: &Field25519Element,
    b: &Field25519Element,
) -> RowMajorMatrix<F> {
    use super::reduce::compute_reduce;
    use super::sub::compute_sub;

    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    let loose_c = compute_sub(a, b);
    let (canonical_c, carries) = compute_reduce(&loose_c);

    // Padding rows must satisfy the SubChip constraint c = a + p - b.
    // With a=b=0, that means c=p. So pre-populate every row's SubChip c slot,
    // ReduceChip input, ReduceChip output, and top-level c with P_LIMBS;
    // then overwrite row 0 with the actual witness below.
    use super::P_LIMBS;
    for row in 0..HEIGHT {
        let row_off = row * NUM_COLS;
        for i in 0..NUM_LIMBS {
            // Top-level c: equals canonical reduce output, which for the
            // padding case (loose c = P) carry-propagates to P (since P
            // is already canonical) with zero carries.
            values[row_off + col::C + i] = F::from_u64(P_LIMBS[i]);
            // SubChip c output: P (since 0 + P - 0 = P).
            values[row_off + col::SUB_START + 2 * NUM_LIMBS + i] = F::from_u64(P_LIMBS[i]);
            // ReduceChip in: same P.
            values[row_off + col::REDUCE_START + 0 + i] = F::from_u64(P_LIMBS[i]);
            // ReduceChip out: P (already canonical).
            values[row_off + col::REDUCE_START + NUM_LIMBS + i] = F::from_u64(P_LIMBS[i]);
            // ReduceChip carries: all zero.
        }
    }

    // Overwrite row 0 with the actual witness.
    for i in 0..NUM_LIMBS {
        values[col::A + i] = F::from_u64(a.limbs[i]);
        values[col::B + i] = F::from_u64(b.limbs[i]);
        values[col::C + i] = F::from_u64(canonical_c.limbs[i]);
    }
    for i in 0..NUM_LIMBS {
        values[col::SUB_START + 0 + i] = F::from_u64(a.limbs[i]);
        values[col::SUB_START + NUM_LIMBS + i] = F::from_u64(b.limbs[i]);
        values[col::SUB_START + 2 * NUM_LIMBS + i] = F::from_u64(loose_c.limbs[i]);
    }
    for i in 0..NUM_LIMBS {
        values[col::REDUCE_START + 0 + i] = F::from_u64(loose_c.limbs[i]);
        values[col::REDUCE_START + NUM_LIMBS + i] = F::from_u64(canonical_c.limbs[i]);
        values[col::REDUCE_START + 2 * NUM_LIMBS + i] = F::from_u64(carries[i]);
    }

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::P_LIMBS;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeField32;

    fn small(n: u64) -> Field25519Element {
        let mut limbs = [0u64; NUM_LIMBS];
        limbs[0] = n & ((1 << 30) - 1);
        limbs[1] = (n >> 30) & ((1 << 30) - 1);
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
    fn sub_trunc_zero_minus_zero_is_p() {
        // 0 - 0 + p = p
        let trace = build_test_trace::<BabyBear>(&Field25519Element::ZERO, &Field25519Element::ZERO);
        check_constraints(&SubTruncChip::new(), &trace, &[]);
        assert_eq!(read_c(&trace.values), P_LIMBS);
    }

    #[test]
    fn sub_trunc_self_yields_p() {
        // a - a + p = p
        let a = small(0xCAFE_BABE);
        let trace = build_test_trace::<BabyBear>(&a, &a);
        check_constraints(&SubTruncChip::new(), &trace, &[]);
        assert_eq!(read_c(&trace.values), P_LIMBS);
    }

    #[test]
    fn sub_trunc_p_minus_zero_is_2p() {
        // p - 0 + p = 2p, canonical 9-limb representation.
        let p = Field25519Element::P;
        let trace = build_test_trace::<BabyBear>(&p, &Field25519Element::ZERO);
        check_constraints(&SubTruncChip::new(), &trace, &[]);
        // 2p in 9-limb form: each limb = 2 * P_LIMBS[i] with carry propagation.
        // Compute expected via reduce.
        use super::super::reduce::compute_reduce;
        use super::super::sub::compute_sub;
        let loose = compute_sub(&p, &Field25519Element::ZERO);
        let (canonical, _) = compute_reduce(&loose);
        assert_eq!(read_c(&trace.values), canonical.limbs);
    }

    #[test]
    fn sub_trunc_one_minus_zero_is_1_plus_p() {
        // 1 - 0 + p = 1 + p (low limb = p[0] + 1, others = p[i]).
        let mut one = Field25519Element::ZERO;
        one.limbs[0] = 1;
        let trace = build_test_trace::<BabyBear>(&one, &Field25519Element::ZERO);
        check_constraints(&SubTruncChip::new(), &trace, &[]);
        let c = read_c(&trace.values);
        assert_eq!(c[0], P_LIMBS[0] + 1); // limb 0 = p[0] + 1, no carry since p[0] + 1 < 2^30
        for i in 1..NUM_LIMBS {
            assert_eq!(c[i], P_LIMBS[i]);
        }
    }

    #[test]
    fn sub_trunc_round_trip_via_add() {
        // (a + b) - b == a + p (truncated semantics: sub_trunc adds p).
        // Carry cascade through the high p[i] = 2^30 - 1 limbs makes the
        // direct limb-by-limb prediction painful, so just compare against
        // an independent compute pass through the same chip.
        use super::super::add::compute_add;
        use super::super::reduce::compute_reduce;
        use super::super::sub::compute_sub;

        let a = small(0x1234);
        let b = small(0x5678);

        let sum_loose = compute_add(&a, &b);
        let (sum_canonical, _) = compute_reduce(&sum_loose);

        let diff_loose = compute_sub(&sum_canonical, &b);
        let (diff_canonical, _) = compute_reduce(&diff_loose);

        // Independent computation of (a + p) canonicalised:
        let a_plus_p_loose = compute_add(&a, &Field25519Element::P);
        let (a_plus_p_canonical, _) = compute_reduce(&a_plus_p_loose);

        // (a + b) + p - b should equal (a + p) modulo 2^270, hence the
        // canonical 9-limb forms must match.
        assert_eq!(diff_canonical.limbs, a_plus_p_canonical.limbs);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn sub_trunc_rejects_tampered_c() {
        let trace_init = build_test_trace::<BabyBear>(&small(7), &small(13));
        let mut trace = trace_init;
        trace.values[col::C] = trace.values[col::C] + BabyBear::ONE;
        check_constraints(&SubTruncChip::new(), &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn sub_trunc_rejects_tampered_b() {
        let trace_init = build_test_trace::<BabyBear>(&small(7), &small(13));
        let mut trace = trace_init;
        trace.values[col::B] = trace.values[col::B] + BabyBear::ONE;
        check_constraints(&SubTruncChip::new(), &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        assert_eq!(NUM_COLS, 81);
    }
}
