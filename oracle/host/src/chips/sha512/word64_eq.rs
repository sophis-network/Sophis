//! `sha512::word64_eq` — equality predicate AIR chip.
//!
//! Computes `eq ∈ {0, 1}` such that `eq = 1 iff a == b` for two 64-bit
//! values. Uses the same chunked-input form as the rest of the
//! `Word64*` family.
//!
//! ## Algorithm
//!
//! For each chunk `i`, compute `diff[i] = a[i] - b[i]` in the field.
//! Then apply the standard inverse trick to detect whether `diff[i]`
//! is zero:
//!
//!   - `diff · inv = 1 - chunk_eq`
//!   - `diff · chunk_eq = 0`
//!
//! Finally chain the four `chunk_eq` flags into a single `eq` via
//! three product-witness intermediates.
//!
//! ## Layout (one operation per row, allocated at `start_col`)
//!
//! | offset | width | name                          |
//! |--------|-------|-------------------------------|
//! | 0      | 4     | a chunks                      |
//! | 4      | 4     | b chunks                      |
//! | 8      | 4     | diff per chunk (= a - b)      |
//! | 12     | 4     | inv per chunk                 |
//! | 16     | 4     | chunk_eq                      |
//! | 20     | 3     | m1, m2, m3 (chained ANDs)     |
//! | 23     | 1     | eq (output)                   |
//!
//! Total: **24 columns**, **21 constraints** (degree 2).
//!
//! ## Soundness
//!
//! Stand-alone sound for canonical chunks. Same caveat as `word64_is_zero`:
//! semantics is "field elements are equal", which coincides with "integer
//! values are equal" iff chunks are within their canonical 16-bit range.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

pub const NUM_CHUNKS: usize = 4;

pub mod col {
    use super::NUM_CHUNKS;
    pub const A: usize = 0;
    pub const B: usize = A + NUM_CHUNKS; // 4
    pub const DIFF: usize = B + NUM_CHUNKS; // 8
    pub const INV: usize = DIFF + NUM_CHUNKS; // 12
    pub const CE: usize = INV + NUM_CHUNKS; // 16 (chunk_eq)
    pub const M1: usize = CE + NUM_CHUNKS; // 20
    pub const M2: usize = M1 + 1; // 21
    pub const M3: usize = M2 + 1; // 22
    pub const EQ: usize = M3 + 1; // 23
}

pub const NUM_COLS: usize = col::EQ + 1; // 24

#[derive(Debug, Clone, Copy)]
pub struct Word64EqChip {
    pub start_col: usize,
}

impl Default for Word64EqChip {
    fn default() -> Self {
        Self::new()
    }
}

impl Word64EqChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let one = AB::Expr::ONE;

        for i in 0..NUM_CHUNKS {
            let a_i = row[self.start_col + col::A + i];
            let b_i = row[self.start_col + col::B + i];
            let diff_i = row[self.start_col + col::DIFF + i];
            let inv_i = row[self.start_col + col::INV + i];
            let ce_i = row[self.start_col + col::CE + i];

            // diff = a - b
            builder.assert_eq(diff_i, a_i.into() - b_i.into());

            // chunk_eq must be boolean.
            builder.assert_bool(ce_i);

            // diff · inv = 1 - chunk_eq
            builder.assert_eq(diff_i.into() * inv_i.into(), one.clone() - ce_i.into());

            // diff · chunk_eq = 0
            builder.assert_zero(diff_i.into() * ce_i.into());
        }

        // Chain ANDs.
        let ce0 = row[self.start_col + col::CE];
        let ce1 = row[self.start_col + col::CE + 1];
        let ce2 = row[self.start_col + col::CE + 2];
        let ce3 = row[self.start_col + col::CE + 3];
        let m1 = row[self.start_col + col::M1];
        let m2 = row[self.start_col + col::M2];
        let m3 = row[self.start_col + col::M3];
        let eq = row[self.start_col + col::EQ];

        builder.assert_eq(m1, ce0.into() * ce1.into());
        builder.assert_eq(m2, m1.into() * ce2.into());
        builder.assert_eq(m3, m2.into() * ce3.into());
        builder.assert_eq(eq, m3);
        builder.assert_bool(eq);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Word64EqTestAir;

impl<F: Field> BaseAir<F> for Word64EqTestAir {
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

impl<AB: AirBuilder> Air<AB> for Word64EqTestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        Word64EqChip::new().emit(builder);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Word64EqWitness {
    pub a_chunks: [u64; NUM_CHUNKS],
    pub b_chunks: [u64; NUM_CHUNKS],
    /// `diff[i]` stored as the canonical u64 representation of the field
    /// element `a[i] - b[i]`. For `a >= b`, this is `a - b`; for `a < b`,
    /// it's `(a - b + BabyBear_prime)`.
    pub diff: [u64; NUM_CHUNKS],
    pub inv: [u64; NUM_CHUNKS],
    pub chunk_eq: [u64; NUM_CHUNKS],
    pub m1: u64,
    pub m2: u64,
    pub m3: u64,
    pub eq: u64,
}

pub fn compute_eq64<F>(a: u64, b: u64) -> Word64EqWitness
where
    F: Field + PrimeCharacteristicRing + p3_field::PrimeField64,
{
    let a_chunks = super::word64_add::decompose_u64(a);
    let b_chunks = super::word64_add::decompose_u64(b);
    let mut diff = [0u64; NUM_CHUNKS];
    let mut inv = [0u64; NUM_CHUNKS];
    let mut chunk_eq = [0u64; NUM_CHUNKS];
    for i in 0..NUM_CHUNKS {
        let a_f = F::from_u64(a_chunks[i]);
        let b_f = F::from_u64(b_chunks[i]);
        let diff_f = a_f - b_f;
        diff[i] = p3_field::PrimeField64::as_canonical_u64(&diff_f);
        if diff_f == F::ZERO {
            chunk_eq[i] = 1;
            inv[i] = 0;
        } else {
            chunk_eq[i] = 0;
            let inv_f = diff_f.try_inverse().expect("nonzero diff has inverse");
            inv[i] = p3_field::PrimeField64::as_canonical_u64(&inv_f);
        }
    }
    let m1 = chunk_eq[0] * chunk_eq[1];
    let m2 = m1 * chunk_eq[2];
    let m3 = m2 * chunk_eq[3];
    let eq = m3;
    Word64EqWitness { a_chunks, b_chunks, diff, inv, chunk_eq, m1, m2, m3, eq }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing + p3_field::PrimeField64>(w: &Word64EqWitness) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    // Padding rows: a = b = 0, diff = 0, chunk_eq = 1, m* = 1, eq = 1, inv = 0.
    for row in 0..HEIGHT {
        let off = row * NUM_COLS;
        for i in 0..NUM_CHUNKS {
            values[off + col::CE + i] = F::ONE;
        }
        values[off + col::M1] = F::ONE;
        values[off + col::M2] = F::ONE;
        values[off + col::M3] = F::ONE;
        values[off + col::EQ] = F::ONE;
    }

    // Overwrite row 0 with the witness.
    for i in 0..NUM_CHUNKS {
        values[col::A + i] = F::from_u64(w.a_chunks[i]);
        values[col::B + i] = F::from_u64(w.b_chunks[i]);
        values[col::DIFF + i] = F::from_u64(w.diff[i]);
        values[col::INV + i] = F::from_u64(w.inv[i]);
        values[col::CE + i] = F::from_u64(w.chunk_eq[i]);
    }
    values[col::M1] = F::from_u64(w.m1);
    values[col::M2] = F::from_u64(w.m2);
    values[col::M3] = F::from_u64(w.m3);
    values[col::EQ] = F::from_u64(w.eq);

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    #[test]
    fn eq_self_yields_one() {
        let cases: [u64; 5] = [0, 1, 0xCAFE_BABE_DEAD_BEEF, u64::MAX, 1u64 << 48];
        for a in cases {
            let w = compute_eq64::<BabyBear>(a, a);
            assert_eq!(w.eq, 1, "a == a should yield eq=1 for {a:#x}");
            let trace = build_test_trace::<BabyBear>(&w);
            check_constraints(&Word64EqTestAir, &trace, &[]);
        }
    }

    #[test]
    fn eq_distinct_yields_zero() {
        let cases: [(u64, u64); 5] = [(0, 1), (1, 2), (0xCAFE, 0xBABE), (u64::MAX, 0), (1u64 << 48, 1u64 << 32)];
        for (a, b) in cases {
            let w = compute_eq64::<BabyBear>(a, b);
            assert_eq!(w.eq, 0, "a != b should yield eq=0 for ({a:#x}, {b:#x})");
            let trace = build_test_trace::<BabyBear>(&w);
            check_constraints(&Word64EqTestAir, &trace, &[]);
        }
    }

    #[test]
    fn eq_only_chunk_3_differs() {
        // a and b match in chunks 0..3 but differ in chunk 3.
        let a = 0x0001_0000_0000_0000u64;
        let b = 0x0002_0000_0000_0000u64;
        let w = compute_eq64::<BabyBear>(a, b);
        assert_eq!(w.eq, 0);
        assert_eq!(w.chunk_eq[0], 1);
        assert_eq!(w.chunk_eq[1], 1);
        assert_eq!(w.chunk_eq[2], 1);
        assert_eq!(w.chunk_eq[3], 0);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64EqTestAir, &trace, &[]);
    }

    #[test]
    fn eq_a_zero_b_max_yields_zero() {
        let w = compute_eq64::<BabyBear>(0, u64::MAX);
        assert_eq!(w.eq, 0);
        for i in 0..NUM_CHUNKS {
            assert_eq!(w.chunk_eq[i], 0, "chunk {i} should differ");
        }
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64EqTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn eq_rejects_lying_about_equality() {
        // Witness claims eq = 1 for distinct values.
        let mut w = compute_eq64::<BabyBear>(0xCAFE, 0xBABE);
        w.eq = 1; // lie
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64EqTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn eq_rejects_lying_about_chunk_eq() {
        // Equal inputs but witness claims chunk_eq[0] = 0.
        let mut w = compute_eq64::<BabyBear>(0xCAFE, 0xCAFE);
        w.chunk_eq[0] = 0;
        // For diff[0] = 0 and chunk_eq[0] = 0: constraint diff*inv = 1-cz
        // becomes 0*inv = 1, no solution. Reject.
        w.m1 = 0;
        w.m2 = 0;
        w.m3 = 0;
        w.eq = 0;
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64EqTestAir, &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        assert_eq!(NUM_COLS, 24);
    }
}
