//! `field25519::sub_canonical` — canonical mod-p subtraction AIR chip.
//!
//! Composes `SubTruncChip` + `CondPSubChip` to produce a canonical
//! mod-p result `c = (a - b) mod p` with `c < p`.
//!
//! For canonical inputs `a, b < p`: SubTrunc produces `(a - b + p) mod 2²⁷⁰`
//! which is in `[0, 2p)`. A single `cond_p_sub` brings it to `[0, p)`.
//!
//! ## Layout
//!
//! Same as add_canonical, with SubTrunc instead of AddTrunc.
//!
//! Total: **144 columns**, ~91 constraints (degree 2).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::cond_p_sub::{self, CondPSubChip, NUM_COLS as CPS_COLS};
use super::sub_trunc::{self, NUM_COLS as ST_COLS, SubTruncChip};
use super::{Field25519Element, NUM_LIMBS};

pub mod col {
    use super::*;
    pub const A: usize = 0;
    pub const B: usize = A + NUM_LIMBS;
    pub const C: usize = B + NUM_LIMBS;
    pub const ST_START: usize = C + NUM_LIMBS;
    pub const CPS_START: usize = ST_START + ST_COLS;
    pub const TOTAL: usize = CPS_START + CPS_COLS;
}

pub const NUM_COLS: usize = col::TOTAL;

#[derive(Debug, Clone, Copy)]
pub struct SubCanonicalChip {
    pub start_col: usize,
}

impl Default for SubCanonicalChip {
    fn default() -> Self {
        Self::new()
    }
}

impl SubCanonicalChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        SubTruncChip::at(self.start_col + col::ST_START).emit(builder);
        CondPSubChip::at(self.start_col + col::CPS_START).emit(builder);

        let main = builder.main();
        let row = main.current_slice();

        let assert_chunks_eq = |b: &mut AB, off_a: usize, off_b: usize| {
            for i in 0..NUM_LIMBS {
                b.assert_eq(row[off_a + i], row[off_b + i]);
            }
        };

        assert_chunks_eq(builder, self.start_col + col::ST_START + sub_trunc::col::A, self.start_col + col::A);
        assert_chunks_eq(builder, self.start_col + col::ST_START + sub_trunc::col::B, self.start_col + col::B);
        assert_chunks_eq(
            builder,
            self.start_col + col::CPS_START + cond_p_sub::col::A,
            self.start_col + col::ST_START + sub_trunc::col::C,
        );
        assert_chunks_eq(builder, self.start_col + col::C, self.start_col + col::CPS_START + cond_p_sub::col::C);
    }
}

impl<F: Field> BaseAir<F> for SubCanonicalChip {
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

impl<AB: AirBuilder> Air<AB> for SubCanonicalChip
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
    use super::cond_p_sub::compute_cond_p_sub;
    use super::reduce::compute_reduce;
    use super::sub::compute_sub;

    let loose = compute_sub(a, b);
    let (canonical_loose, carries) = compute_reduce(&loose);
    let cps_w = compute_cond_p_sub(&canonical_loose);

    let base = row_off + start_col;

    for i in 0..NUM_LIMBS {
        values[base + col::A + i] = F::from_u64(a.limbs[i]);
        values[base + col::B + i] = F::from_u64(b.limbs[i]);
        values[base + col::C + i] = F::from_u64(cps_w.c_limbs[i]);
        values[base + col::ST_START + sub_trunc::col::A + i] = F::from_u64(a.limbs[i]);
        values[base + col::ST_START + sub_trunc::col::B + i] = F::from_u64(b.limbs[i]);
        values[base + col::ST_START + sub_trunc::col::C + i] = F::from_u64(canonical_loose.limbs[i]);
        values[(base + col::ST_START + sub_trunc::col::SUB_START) + i] = F::from_u64(a.limbs[i]);
        values[base + col::ST_START + sub_trunc::col::SUB_START + NUM_LIMBS + i] = F::from_u64(b.limbs[i]);
        values[base + col::ST_START + sub_trunc::col::SUB_START + 2 * NUM_LIMBS + i] = F::from_u64(loose.limbs[i]);
        values[(base + col::ST_START + sub_trunc::col::REDUCE_START) + i] = F::from_u64(loose.limbs[i]);
        values[base + col::ST_START + sub_trunc::col::REDUCE_START + NUM_LIMBS + i] = F::from_u64(canonical_loose.limbs[i]);
        values[base + col::ST_START + sub_trunc::col::REDUCE_START + 2 * NUM_LIMBS + i] = F::from_u64(carries[i]);
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
    use super::super::arith::field_sub;
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
    fn sub_canonical_zero_minus_zero() {
        let trace = build_test_trace::<BabyBear>(&Field25519Element::ZERO, &Field25519Element::ZERO);
        check_constraints(&SubCanonicalChip::new(), &trace, &[]);
        assert_eq!(read_c(&trace.values), [0u64; NUM_LIMBS]);
    }

    #[test]
    fn sub_canonical_self_yields_zero() {
        let a = small(0xCAFE_BABE);
        let trace = build_test_trace::<BabyBear>(&a, &a);
        check_constraints(&SubCanonicalChip::new(), &trace, &[]);
        assert_eq!(read_c(&trace.values), [0u64; NUM_LIMBS]);
    }

    #[test]
    fn sub_canonical_cross_validates_with_arith() {
        let cases: Vec<(Field25519Element, Field25519Element)> = vec![
            (small(0xCAFE), small(0xBABE)),
            (small(100), small(50)),
            (small(50), small(100)), // negative result, wraps mod p
        ];
        for (a, b) in cases {
            let expected = field_sub(&a, &b);
            let trace = build_test_trace::<BabyBear>(&a, &b);
            check_constraints(&SubCanonicalChip::new(), &trace, &[]);
            assert_eq!(read_c(&trace.values), expected.limbs);
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn sub_canonical_rejects_tampered() {
        let mut trace = build_test_trace::<BabyBear>(&small(7), &small(13));
        trace.values[col::C] += BabyBear::ONE;
        check_constraints(&SubCanonicalChip::new(), &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        assert_eq!(NUM_COLS, 144);
    }
}
