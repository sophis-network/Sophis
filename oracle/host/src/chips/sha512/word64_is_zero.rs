//! `sha512::word64_is_zero` — boolean predicate AIR chip computing
//! `is_zero ∈ {0, 1}` such that `is_zero = 1 iff input == 0`.
//!
//! Useful primitive for conditional logic chips (e.g. equality checks
//! between 64-bit words). Operates on 4×16-bit chunked input matching
//! the `Word64Add` family's representation.
//!
//! ## Algorithm
//!
//! Per-chunk is-zero via the standard inverse trick: for each chunk
//! `x`, prover supplies a witness `inv` such that:
//!
//!   - `x · inv = 1 - chunk_is_zero`   (if `x == 0`, RHS = 1; else RHS = 0)
//!   - `x · chunk_is_zero = 0`         (forces `chunk_is_zero = 0` when `x != 0`)
//!
//! Then the four `chunk_is_zero` flags are AND'd into a single `is_zero`
//! via a chain of three product-witness intermediates.
//!
//! ## Layout (one operation per row, allocated at `start_col`)
//!
//! | offset | width | name              |
//! |--------|-------|-------------------|
//! | 0      | 4     | a chunks          |
//! | 4      | 4     | inv per chunk     |
//! | 8      | 4     | chunk_is_zero     |
//! | 12     | 3     | intermediates m1, m2, m3 |
//! | 15     | 1     | is_zero (output)  |
//!
//! Total: **16 columns**, **17 constraints** (degree 2).
//!
//! ## Soundness
//!
//! Stand-alone sound. The inverse-trick equations force each
//! `chunk_is_zero` to correctly represent whether the corresponding
//! chunk is zero (no lookup args needed). Boolean checks on the four
//! `chunk_is_zero` flags + `is_zero` close the soundness loop. Note that
//! for inputs where chunks are NOT canonical (e.g., chunk values ≥ 2¹⁶
//! supplied by an upstream chip without range checks), the predicate
//! still correctly answers "is the field element zero" but no longer
//! corresponds to "is the integer 64-bit value zero" — the caller is
//! responsible for ensuring chunk range.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

pub const NUM_CHUNKS: usize = 4;

pub mod col {
    use super::NUM_CHUNKS;
    pub const A: usize = 0;
    pub const INV: usize = A + NUM_CHUNKS; // 4
    pub const CZ: usize = INV + NUM_CHUNKS; // 8 (chunk_is_zero)
    pub const M1: usize = CZ + NUM_CHUNKS; // 12
    pub const M2: usize = M1 + 1; // 13
    pub const M3: usize = M2 + 1; // 14 (= is_zero)
    pub const IS_ZERO: usize = M3 + 1; // 15

    pub const _UNUSED_PAD: usize = IS_ZERO + 1; // 16 (we keep IS_ZERO as a separate
    // explicit output column for caller
    // ergonomics, even though it equals m3)
}

pub const NUM_COLS: usize = col::_UNUSED_PAD; // 16

#[derive(Debug, Clone, Copy)]
pub struct Word64IsZeroChip {
    pub start_col: usize,
}

impl Default for Word64IsZeroChip {
    fn default() -> Self {
        Self::new()
    }
}

impl Word64IsZeroChip {
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

        // Per-chunk is-zero detection via the inverse trick.
        for i in 0..NUM_CHUNKS {
            let a_i = row[self.start_col + col::A + i];
            let inv_i = row[self.start_col + col::INV + i];
            let cz_i = row[self.start_col + col::CZ + i];

            // chunk_is_zero must be boolean.
            builder.assert_bool(cz_i);
            // a · inv = 1 - chunk_is_zero
            builder.assert_eq(a_i.into() * inv_i.into(), one.clone() - cz_i.into());
            // a · chunk_is_zero = 0
            builder.assert_zero(a_i.into() * cz_i.into());
        }

        // Chain ANDs: m1 = cz[0] · cz[1], m2 = m1 · cz[2], m3 = m2 · cz[3].
        let cz0 = row[self.start_col + col::CZ];
        let cz1 = row[self.start_col + col::CZ + 1];
        let cz2 = row[self.start_col + col::CZ + 2];
        let cz3 = row[self.start_col + col::CZ + 3];
        let m1 = row[self.start_col + col::M1];
        let m2 = row[self.start_col + col::M2];
        let m3 = row[self.start_col + col::M3];
        let is_zero = row[self.start_col + col::IS_ZERO];

        builder.assert_eq(m1, cz0.into() * cz1.into());
        builder.assert_eq(m2, m1.into() * cz2.into());
        builder.assert_eq(m3, m2.into() * cz3.into());

        // Output mirror.
        builder.assert_eq(is_zero, m3);
        builder.assert_bool(is_zero);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Word64IsZeroTestAir;

impl<F: Field> BaseAir<F> for Word64IsZeroTestAir {
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

impl<AB: AirBuilder> Air<AB> for Word64IsZeroTestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        Word64IsZeroChip::new().emit(builder);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Word64IsZeroWitness {
    pub a_chunks: [u64; NUM_CHUNKS],
    /// Per-chunk inverse: `chunk^-1 mod p` if chunk != 0, else any value
    /// (we use 0 by convention).
    pub inv: [u64; NUM_CHUNKS],
    pub chunk_is_zero: [u64; NUM_CHUNKS],
    pub m1: u64,
    pub m2: u64,
    pub m3: u64,
    pub is_zero: u64,
}

/// Compute the witness, given the input value as a `u64`.
///
/// The inverse computation is done in field `F` via `try_inverse`. The
/// result is converted back to a `u64` for storage in the witness;
/// callers using non-`PrimeField64` fields can compute their own
/// inverses and construct the witness directly.
pub fn compute_is_zero64<F>(a: u64) -> Word64IsZeroWitness
where
    F: Field + PrimeCharacteristicRing + p3_field::PrimeField64,
{
    let a_chunks = super::word64_add::decompose_u64(a);
    let mut inv = [0u64; NUM_CHUNKS];
    let mut chunk_is_zero = [0u64; NUM_CHUNKS];
    for i in 0..NUM_CHUNKS {
        if a_chunks[i] == 0 {
            chunk_is_zero[i] = 1;
            inv[i] = 0; // any value works
        } else {
            chunk_is_zero[i] = 0;
            let f = F::from_u64(a_chunks[i]);
            let f_inv = f.try_inverse().expect("nonzero chunk has inverse");
            inv[i] = p3_field::PrimeField64::as_canonical_u64(&f_inv);
        }
    }
    let m1 = chunk_is_zero[0] * chunk_is_zero[1];
    let m2 = m1 * chunk_is_zero[2];
    let m3 = m2 * chunk_is_zero[3];
    let is_zero = m3;
    Word64IsZeroWitness { a_chunks, inv, chunk_is_zero, m1, m2, m3, is_zero }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing + p3_field::PrimeField64>(w: &Word64IsZeroWitness) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    // Padding rows: a = 0 in every chunk, chunk_is_zero = 1 everywhere,
    // m1=m2=m3=is_zero=1, inv=0 (since chunks are zero).
    for row in 0..HEIGHT {
        let off = row * NUM_COLS;
        for i in 0..NUM_CHUNKS {
            values[off + col::CZ + i] = F::ONE;
        }
        values[off + col::M1] = F::ONE;
        values[off + col::M2] = F::ONE;
        values[off + col::M3] = F::ONE;
        values[off + col::IS_ZERO] = F::ONE;
    }

    // Overwrite row 0 with the actual witness.
    for i in 0..NUM_CHUNKS {
        values[col::A + i] = F::from_u64(w.a_chunks[i]);
        values[col::INV + i] = F::from_u64(w.inv[i]);
        values[col::CZ + i] = F::from_u64(w.chunk_is_zero[i]);
    }
    values[col::M1] = F::from_u64(w.m1);
    values[col::M2] = F::from_u64(w.m2);
    values[col::M3] = F::from_u64(w.m3);
    values[col::IS_ZERO] = F::from_u64(w.is_zero);

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    #[test]
    fn is_zero_zero_yields_one() {
        let w = compute_is_zero64::<BabyBear>(0);
        assert_eq!(w.is_zero, 1);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64IsZeroTestAir, &trace, &[]);
    }

    #[test]
    fn is_zero_one_yields_zero() {
        let w = compute_is_zero64::<BabyBear>(1);
        assert_eq!(w.is_zero, 0);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64IsZeroTestAir, &trace, &[]);
    }

    #[test]
    fn is_zero_max_yields_zero() {
        let w = compute_is_zero64::<BabyBear>(u64::MAX);
        assert_eq!(w.is_zero, 0);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64IsZeroTestAir, &trace, &[]);
    }

    #[test]
    fn is_zero_only_chunk_3_set() {
        // a has only the high chunk non-zero.
        let a = 1u64 << 48;
        let w = compute_is_zero64::<BabyBear>(a);
        assert_eq!(w.is_zero, 0);
        // chunk_is_zero[3] = 0 (chunk 3 has value 1), all others = 1.
        assert_eq!(w.chunk_is_zero[0], 1);
        assert_eq!(w.chunk_is_zero[1], 1);
        assert_eq!(w.chunk_is_zero[2], 1);
        assert_eq!(w.chunk_is_zero[3], 0);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64IsZeroTestAir, &trace, &[]);
    }

    #[test]
    fn is_zero_arbitrary_inputs() {
        let cases: [u64; 7] = [0, 1, 0xCAFE_BABE_DEAD_BEEF, u64::MAX, 1u64 << 32, (1u64 << 16) - 1, 0x0001_0000_0000_0001];
        for a in cases {
            let w = compute_is_zero64::<BabyBear>(a);
            assert_eq!(w.is_zero, if a == 0 { 1 } else { 0 }, "is_zero({a:#x})");
            let trace = build_test_trace::<BabyBear>(&w);
            check_constraints(&Word64IsZeroTestAir, &trace, &[]);
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn is_zero_rejects_lying_about_nonzero() {
        // Witness claims is_zero = 1 for a non-zero input.
        let mut w = compute_is_zero64::<BabyBear>(0xCAFE);
        w.is_zero = 1; // lie
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64IsZeroTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn is_zero_rejects_wrong_chunk_is_zero_for_zero_chunk() {
        // Witness claims chunk_is_zero[0] = 0 even though chunk 0 is 0.
        let mut w = compute_is_zero64::<BabyBear>(0);
        w.chunk_is_zero[0] = 0;
        // For chunk 0 = 0 and cz[0] = 0: constraint a*inv = 1-cz becomes
        // 0*inv = 1, which has no solution (LHS = 0, RHS = 1). Reject.
        // We also need to invalidate the m1 chain to make it fail
        // consistently via the assertion path.
        w.m1 = 0;
        w.m2 = 0;
        w.m3 = 0;
        w.is_zero = 0;
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64IsZeroTestAir, &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        assert_eq!(NUM_COLS, 16);
    }
}
