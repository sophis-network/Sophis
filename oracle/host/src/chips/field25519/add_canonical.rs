//! `field25519::add_canonical` — canonical mod-p addition AIR chip.
//!
//! Composes `AddTruncChip` + `CondPSubChip` to produce a canonical
//! mod-p result `c = (a + b) mod p` with `c < p`.
//!
//! For canonical inputs `a, b < p`: `a + b < 2p`, so a single
//! `cond_p_sub` is sufficient to bring the result into `[0, p)`.
//!
//! ## Layout
//!
//! | Range     | Width | Contents                              |
//! |-----------|-------|---------------------------------------|
//! | 0..9      | 9     | a chunks (input, canonical mod-p)     |
//! | 9..18     | 9     | b chunks (input, canonical mod-p)     |
//! | 18..27    | 9     | c chunks (output, canonical mod-p)    |
//! | 27..108   | 81    | AddTruncChip                          |
//! | 108..144  | 36    | CondPSubChip                          |
//!
//! Total: **144 columns**, ~91 constraints (degree 2).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::add_trunc::{self, AddTruncChip, NUM_COLS as AT_COLS};
use super::cond_p_sub::{self, CondPSubChip, NUM_COLS as CPS_COLS};
use super::{Field25519Element, NUM_LIMBS};

pub mod col {
    use super::*;
    pub const A: usize = 0;
    pub const B: usize = A + NUM_LIMBS; // 9
    pub const C: usize = B + NUM_LIMBS; // 18
    pub const AT_START: usize = C + NUM_LIMBS; // 27
    pub const CPS_START: usize = AT_START + AT_COLS; // 108
    pub const TOTAL: usize = CPS_START + CPS_COLS; // 144
}

pub const NUM_COLS: usize = col::TOTAL;

#[derive(Debug, Clone, Copy)]
pub struct AddCanonicalChip {
    pub start_col: usize,
}

impl Default for AddCanonicalChip {
    fn default() -> Self {
        Self::new()
    }
}

impl AddCanonicalChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        AddTruncChip::at(self.start_col + col::AT_START).emit(builder);
        CondPSubChip::at(self.start_col + col::CPS_START).emit(builder);

        let main = builder.main();
        let row = main.current_slice();

        let assert_chunks_eq = |b: &mut AB, off_a: usize, off_b: usize| {
            for i in 0..NUM_LIMBS {
                b.assert_eq(row[off_a + i], row[off_b + i]);
            }
        };

        // AddTrunc's a, b ← top-level a, b
        assert_chunks_eq(builder, self.start_col + col::AT_START + add_trunc::col::A, self.start_col + col::A);
        assert_chunks_eq(builder, self.start_col + col::AT_START + add_trunc::col::B, self.start_col + col::B);

        // CondPSub's a ← AddTrunc's c output
        assert_chunks_eq(
            builder,
            self.start_col + col::CPS_START + cond_p_sub::col::A,
            self.start_col + col::AT_START + add_trunc::col::C,
        );

        // top-level c ← CondPSub's c
        assert_chunks_eq(builder, self.start_col + col::C, self.start_col + col::CPS_START + cond_p_sub::col::C);
    }
}

impl<F: Field> BaseAir<F> for AddCanonicalChip {
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

impl<AB: AirBuilder> Air<AB> for AddCanonicalChip
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        self.emit(builder);
    }
}

/// Populate one row at `(row_off, start_col)`. Reusable by composing chips.
pub fn populate_row<F: Field + PrimeCharacteristicRing>(
    values: &mut [F],
    row_off: usize,
    start_col: usize,
    a: &Field25519Element,
    b: &Field25519Element,
) {
    use super::add::compute_add;
    use super::cond_p_sub::compute_cond_p_sub;
    use super::reduce::compute_reduce;

    let loose = compute_add(a, b);
    let (canonical_loose, carries) = compute_reduce(&loose);
    let cps_w = compute_cond_p_sub(&canonical_loose);

    let base = row_off + start_col;

    for i in 0..NUM_LIMBS {
        values[base + col::A + i] = F::from_u64(a.limbs[i]);
        values[base + col::B + i] = F::from_u64(b.limbs[i]);
        values[base + col::C + i] = F::from_u64(cps_w.c_limbs[i]);

        values[base + col::AT_START + add_trunc::col::A + i] = F::from_u64(a.limbs[i]);
        values[base + col::AT_START + add_trunc::col::B + i] = F::from_u64(b.limbs[i]);
        values[base + col::AT_START + add_trunc::col::C + i] = F::from_u64(canonical_loose.limbs[i]);

        values[(base + col::AT_START + add_trunc::col::ADD_START) + i] = F::from_u64(a.limbs[i]);
        values[base + col::AT_START + add_trunc::col::ADD_START + NUM_LIMBS + i] = F::from_u64(b.limbs[i]);
        values[base + col::AT_START + add_trunc::col::ADD_START + 2 * NUM_LIMBS + i] = F::from_u64(loose.limbs[i]);

        values[(base + col::AT_START + add_trunc::col::REDUCE_START) + i] = F::from_u64(loose.limbs[i]);
        values[base + col::AT_START + add_trunc::col::REDUCE_START + NUM_LIMBS + i] = F::from_u64(canonical_loose.limbs[i]);
        values[base + col::AT_START + add_trunc::col::REDUCE_START + 2 * NUM_LIMBS + i] = F::from_u64(carries[i]);

        values[base + col::CPS_START + cond_p_sub::col::A + i] = F::from_u64(cps_w.a_limbs[i]);
        values[base + col::CPS_START + cond_p_sub::col::C + i] = F::from_u64(cps_w.c_limbs[i]);
        values[base + col::CPS_START + cond_p_sub::col::T + i] = F::from_u64(cps_w.t_limbs[i]);
        values[base + col::CPS_START + cond_p_sub::col::BORROW + i] = F::from_u64(cps_w.borrow[i]);
    }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(a: &Field25519Element, b: &Field25519Element) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    let zero = Field25519Element::ZERO;
    for row in 0..HEIGHT {
        populate_row::<F>(&mut values, row * NUM_COLS, 0, &zero, &zero);
    }
    populate_row::<F>(&mut values, 0, 0, a, b);

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::super::arith::field_add;
    use super::*;
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
    fn add_canonical_zero_plus_zero() {
        let trace = build_test_trace::<BabyBear>(&Field25519Element::ZERO, &Field25519Element::ZERO);
        check_constraints(&AddCanonicalChip::new(), &trace, &[]);
        assert_eq!(read_c(&trace.values), [0u64; NUM_LIMBS]);
    }

    #[test]
    fn add_canonical_three_plus_seven() {
        let trace = build_test_trace::<BabyBear>(&small(3), &small(7));
        check_constraints(&AddCanonicalChip::new(), &trace, &[]);
        let mut expected = [0u64; NUM_LIMBS];
        expected[0] = 10;
        assert_eq!(read_c(&trace.values), expected);
    }

    #[test]
    fn add_canonical_p_plus_zero_yields_zero() {
        // p + 0 mod p = 0.
        let trace = build_test_trace::<BabyBear>(&Field25519Element::P, &Field25519Element::ZERO);
        check_constraints(&AddCanonicalChip::new(), &trace, &[]);
        assert_eq!(read_c(&trace.values), [0u64; NUM_LIMBS]);
    }

    #[test]
    fn add_canonical_cross_validates_with_arith() {
        let cases: Vec<(Field25519Element, Field25519Element)> =
            vec![(small(0xCAFE), small(0xBABE)), (Field25519Element::ZERO, small(1)), (small(0xDEADBEEF), small(0xFEDCBA98))];
        for (a, b) in cases {
            let expected = field_add(&a, &b);
            let trace = build_test_trace::<BabyBear>(&a, &b);
            check_constraints(&AddCanonicalChip::new(), &trace, &[]);
            assert_eq!(read_c(&trace.values), expected.limbs);
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn add_canonical_rejects_tampered() {
        let mut trace = build_test_trace::<BabyBear>(&small(7), &small(13));
        trace.values[col::C] += BabyBear::ONE;
        check_constraints(&AddCanonicalChip::new(), &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        assert_eq!(NUM_COLS, 144);
    }
}
