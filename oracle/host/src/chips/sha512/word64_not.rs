//! `sha512::word64_not` — 64-bit bitwise NOT AIR chip.
//!
//! Single-input variant of the bitwise primitives. Each output bit is
//! `1 - a_bit` — degree-1 constraint, the simplest of the bitwise chips.
//!
//! ## Layout (one operation per row, allocated at `start_col`)
//!
//! | offset    | width | name      |
//! |-----------|-------|-----------|
//! | 0         | 4     | a chunks  |
//! | 4         | 4     | c chunks  |
//! | 8         | 64    | a bits    |
//! | 72        | 64    | c bits    |
//!
//! Total: **136 columns**, **200 constraints**.
//!
//! ## Constraints
//!
//! - 128 boolean checks: every bit cell satisfies `b·(1-b) = 0`.
//! - 8 chunk-recomposition checks (4 for `a`, 4 for `c`).
//! - 64 per-bit NOT: `c_bit + a_bit - 1 = 0`.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

pub const NUM_CHUNKS: usize = 4;
pub const CHUNK_BITS: usize = 16;
pub const NUM_BITS: usize = 64;

pub mod col {
    use super::{NUM_BITS, NUM_CHUNKS};
    pub const A_CHUNKS: usize = 0;
    pub const C_CHUNKS: usize = A_CHUNKS + NUM_CHUNKS; // 4
    pub const A_BITS: usize = C_CHUNKS + NUM_CHUNKS;   // 8
    pub const C_BITS: usize = A_BITS + NUM_BITS;       // 72
}

pub const NUM_COLS: usize = col::C_BITS + NUM_BITS; // 136
pub const NUM_CONSTRAINTS: usize = 2 * NUM_BITS + 2 * NUM_CHUNKS + NUM_BITS; // 200

#[derive(Debug, Clone, Copy)]
pub struct Word64NotChip {
    pub start_col: usize,
}

impl Word64NotChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();

        // Boolean checks.
        for i in 0..NUM_BITS {
            builder.assert_bool(row[self.start_col + col::A_BITS + i]);
            builder.assert_bool(row[self.start_col + col::C_BITS + i]);
        }

        // Chunk recompositions for a and c.
        for chunk_idx in 0..NUM_CHUNKS {
            let bit_base = chunk_idx * CHUNK_BITS;
            let mut a_acc = AB::Expr::ZERO;
            let mut c_acc = AB::Expr::ZERO;
            let mut weight: u64 = 1;
            for k in 0..CHUNK_BITS {
                let a_bit = row[self.start_col + col::A_BITS + bit_base + k];
                let c_bit = row[self.start_col + col::C_BITS + bit_base + k];
                let w = AB::Expr::from_u64(weight);
                a_acc = a_acc + w.clone() * a_bit.into();
                c_acc = c_acc + w * c_bit.into();
                weight <<= 1;
            }
            builder.assert_eq(row[self.start_col + col::A_CHUNKS + chunk_idx], a_acc);
            builder.assert_eq(row[self.start_col + col::C_CHUNKS + chunk_idx], c_acc);
        }

        // Per-bit NOT: c_bit = 1 - a_bit.
        for i in 0..NUM_BITS {
            let a_bit = row[self.start_col + col::A_BITS + i];
            let c_bit = row[self.start_col + col::C_BITS + i];
            builder.assert_eq(c_bit, AB::Expr::ONE - a_bit.into());
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Word64NotTestAir;

impl<F: Field> BaseAir<F> for Word64NotTestAir {
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

impl<AB: AirBuilder> Air<AB> for Word64NotTestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        Word64NotChip::new().emit(builder);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Word64NotWitness {
    pub a_chunks: [u64; NUM_CHUNKS],
    pub c_chunks: [u64; NUM_CHUNKS],
    pub a_bits: [u64; NUM_BITS],
    pub c_bits: [u64; NUM_BITS],
}

pub fn compute_not64(a: u64) -> Word64NotWitness {
    let c = !a;
    let mut a_bits = [0u64; NUM_BITS];
    let mut c_bits = [0u64; NUM_BITS];
    for i in 0..NUM_BITS {
        a_bits[i] = (a >> i) & 1;
        c_bits[i] = (c >> i) & 1;
    }
    Word64NotWitness {
        a_chunks: super::word64_add::decompose_u64(a),
        c_chunks: super::word64_add::decompose_u64(c),
        a_bits,
        c_bits,
    }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(w: &Word64NotWitness) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];
    for i in 0..NUM_CHUNKS {
        values[col::A_CHUNKS + i] = F::from_u64(w.a_chunks[i]);
        values[col::C_CHUNKS + i] = F::from_u64(w.c_chunks[i]);
    }
    for i in 0..NUM_BITS {
        values[col::A_BITS + i] = F::from_u64(w.a_bits[i]);
        values[col::C_BITS + i] = F::from_u64(w.c_bits[i]);
    }
    // Padding rows: a=0 → c=NOT 0 = u64::MAX. Need to populate so constraints
    // hold (otherwise padding fails the c = 1 - a constraint with c=0, a=0).
    let max_w = compute_not64(0);
    for row in 1..HEIGHT {
        let row_off = row * NUM_COLS;
        for i in 0..NUM_CHUNKS {
            values[row_off + col::A_CHUNKS + i] = F::from_u64(max_w.a_chunks[i]);
            values[row_off + col::C_CHUNKS + i] = F::from_u64(max_w.c_chunks[i]);
        }
        for i in 0..NUM_BITS {
            values[row_off + col::A_BITS + i] = F::from_u64(max_w.a_bits[i]);
            values[row_off + col::C_BITS + i] = F::from_u64(max_w.c_bits[i]);
        }
    }
    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::word64_add::recompose_u64;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    #[test]
    fn not64_zero_is_max() {
        let w = compute_not64(0);
        assert_eq!(recompose_u64(&w.c_chunks), u64::MAX);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64NotTestAir, &trace, &[]);
    }

    #[test]
    fn not64_max_is_zero() {
        let w = compute_not64(u64::MAX);
        assert_eq!(recompose_u64(&w.c_chunks), 0);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64NotTestAir, &trace, &[]);
    }

    #[test]
    fn not64_involution() {
        let a = 0xCAFE_BABE_DEAD_BEEF;
        let w = compute_not64(!a);
        assert_eq!(recompose_u64(&w.c_chunks), a);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&Word64NotTestAir, &trace, &[]);
    }

    #[test]
    fn not64_matches_native_for_corner_cases() {
        let cases: [u64; 6] = [0, 1, u64::MAX, 0xCAFE_BABE_1234_5678, 0xAAAA_AAAA_AAAA_AAAA, 0x8000_0000_0000_0000];
        for a in cases {
            let w = compute_not64(a);
            assert_eq!(recompose_u64(&w.c_chunks), !a, "mismatch for !{a:#x}");
            let trace = build_test_trace::<BabyBear>(&w);
            check_constraints(&Word64NotTestAir, &trace, &[]);
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn not64_rejects_tampered_c_bit() {
        let w = compute_not64(0xFFFF);
        let mut trace = build_test_trace::<BabyBear>(&w);
        trace.values[col::C_BITS] = trace.values[col::C_BITS] + BabyBear::ONE;
        check_constraints(&Word64NotTestAir, &trace, &[]);
    }

    #[test]
    fn constraint_count_matches_documented() {
        assert_eq!(NUM_COLS, 136);
        assert_eq!(NUM_CONSTRAINTS, 200);
    }
}
