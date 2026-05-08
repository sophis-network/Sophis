//! `sha512::maj` — Majority function chip:
//! `Maj(a, b, c) = (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c)`.
//!
//! Per-bit majority of three inputs. Used in every SHA-512 round.
//!
//! ## Layout (one operation per row, allocated at `start_col`)
//!
//! | offset    | width | name       |
//! |-----------|-------|------------|
//! | 0         | 4     | a chunks   |
//! | 4         | 4     | b chunks   |
//! | 8         | 4     | c chunks   |
//! | 12        | 4     | out chunks | (= Maj(a, b, c))
//! | 16        | 64    | a bits     |
//! | 80        | 64    | b bits     |
//! | 144       | 64    | c bits     |
//! | 208       | 64    | out bits   |
//! | 272       | 64    | ab bits    | (= a ∧ b)
//! | 336       | 64    | ac bits    | (= a ∧ c)
//! | 400       | 64    | bc bits    | (= b ∧ c)
//! | 464       | 64    | mid bits   | (= ab ⊕ ac)
//!
//! Total: **528 columns**, **592 constraints** (degree 2).
//!
//! ## Constraints
//!
//! - 256 boolean checks (a, b, c, out bits).
//! - 16 chunk recomposition.
//! - 64 ab = a · b
//! - 64 ac = a · c
//! - 64 bc = b · c
//! - 64 mid = ab + ac - 2·ab·ac (XOR)
//! - 64 out = mid + bc - 2·mid·bc (XOR)

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

pub const NUM_CHUNKS: usize = 4;
pub const CHUNK_BITS: usize = 16;
pub const NUM_BITS: usize = 64;

pub mod col {
    use super::{NUM_BITS, NUM_CHUNKS};
    pub const A_CHUNKS: usize = 0;
    pub const B_CHUNKS: usize = A_CHUNKS + NUM_CHUNKS;     // 4
    pub const C_CHUNKS: usize = B_CHUNKS + NUM_CHUNKS;     // 8
    pub const OUT_CHUNKS: usize = C_CHUNKS + NUM_CHUNKS;   // 12
    pub const A_BITS: usize = OUT_CHUNKS + NUM_CHUNKS;     // 16
    pub const B_BITS: usize = A_BITS + NUM_BITS;           // 80
    pub const C_BITS: usize = B_BITS + NUM_BITS;           // 144
    pub const OUT_BITS: usize = C_BITS + NUM_BITS;         // 208
    pub const AB_BITS: usize = OUT_BITS + NUM_BITS;        // 272
    pub const AC_BITS: usize = AB_BITS + NUM_BITS;         // 336
    pub const BC_BITS: usize = AC_BITS + NUM_BITS;         // 400
    pub const MID_BITS: usize = BC_BITS + NUM_BITS;        // 464
}

pub const NUM_COLS: usize = col::MID_BITS + NUM_BITS; // 528

#[derive(Debug, Clone, Copy)]
pub struct MajChip {
    pub start_col: usize,
}

impl MajChip {
    pub const fn new() -> Self {
        Self { start_col: 0 }
    }

    pub const fn at(start_col: usize) -> Self {
        Self { start_col }
    }

    pub fn emit<AB: AirBuilder>(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let two = AB::Expr::from_u64(2);

        // Boolean checks on inputs and final output.
        for i in 0..NUM_BITS {
            builder.assert_bool(row[self.start_col + col::A_BITS + i]);
            builder.assert_bool(row[self.start_col + col::B_BITS + i]);
            builder.assert_bool(row[self.start_col + col::C_BITS + i]);
            builder.assert_bool(row[self.start_col + col::OUT_BITS + i]);
        }

        // Chunk recomposition.
        for chunk_idx in 0..NUM_CHUNKS {
            let bit_base = chunk_idx * CHUNK_BITS;
            let mut a_acc = AB::Expr::ZERO;
            let mut b_acc = AB::Expr::ZERO;
            let mut c_acc = AB::Expr::ZERO;
            let mut out_acc = AB::Expr::ZERO;
            let mut weight: u64 = 1;
            for k in 0..CHUNK_BITS {
                let w = AB::Expr::from_u64(weight);
                a_acc = a_acc + w.clone() * row[self.start_col + col::A_BITS + bit_base + k].into();
                b_acc = b_acc + w.clone() * row[self.start_col + col::B_BITS + bit_base + k].into();
                c_acc = c_acc + w.clone() * row[self.start_col + col::C_BITS + bit_base + k].into();
                out_acc = out_acc + w * row[self.start_col + col::OUT_BITS + bit_base + k].into();
                weight <<= 1;
            }
            builder.assert_eq(row[self.start_col + col::A_CHUNKS + chunk_idx], a_acc);
            builder.assert_eq(row[self.start_col + col::B_CHUNKS + chunk_idx], b_acc);
            builder.assert_eq(row[self.start_col + col::C_CHUNKS + chunk_idx], c_acc);
            builder.assert_eq(row[self.start_col + col::OUT_CHUNKS + chunk_idx], out_acc);
        }

        // Per-bit AND products + chained XORs.
        for i in 0..NUM_BITS {
            let a_bit = row[self.start_col + col::A_BITS + i];
            let b_bit = row[self.start_col + col::B_BITS + i];
            let c_bit = row[self.start_col + col::C_BITS + i];
            let ab = row[self.start_col + col::AB_BITS + i];
            let ac = row[self.start_col + col::AC_BITS + i];
            let bc = row[self.start_col + col::BC_BITS + i];
            let mid = row[self.start_col + col::MID_BITS + i];
            let out = row[self.start_col + col::OUT_BITS + i];

            builder.assert_eq(ab, a_bit.into() * b_bit.into());
            builder.assert_eq(ac, a_bit.into() * c_bit.into());
            builder.assert_eq(bc, b_bit.into() * c_bit.into());
            builder.assert_eq(mid, ab.into() + ac.into() - two.clone() * (ab.into() * ac.into()));
            builder.assert_eq(out, mid.into() + bc.into() - two.clone() * (mid.into() * bc.into()));
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MajTestAir;

impl<F: Field> BaseAir<F> for MajTestAir {
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

impl<AB: AirBuilder> Air<AB> for MajTestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        MajChip::new().emit(builder);
    }
}

#[derive(Debug, Clone)]
pub struct MajWitness {
    pub a_chunks: [u64; NUM_CHUNKS],
    pub b_chunks: [u64; NUM_CHUNKS],
    pub c_chunks: [u64; NUM_CHUNKS],
    pub out_chunks: [u64; NUM_CHUNKS],
    pub a_bits: [u64; NUM_BITS],
    pub b_bits: [u64; NUM_BITS],
    pub c_bits: [u64; NUM_BITS],
    pub out_bits: [u64; NUM_BITS],
    pub ab_bits: [u64; NUM_BITS],
    pub ac_bits: [u64; NUM_BITS],
    pub bc_bits: [u64; NUM_BITS],
    pub mid_bits: [u64; NUM_BITS],
}

pub fn compute_maj(a: u64, b: u64, c: u64) -> MajWitness {
    let ab = a & b;
    let ac = a & c;
    let bc = b & c;
    let mid = ab ^ ac;
    let out = mid ^ bc;
    let mut a_bits = [0u64; NUM_BITS];
    let mut b_bits = [0u64; NUM_BITS];
    let mut c_bits = [0u64; NUM_BITS];
    let mut out_bits = [0u64; NUM_BITS];
    let mut ab_bits = [0u64; NUM_BITS];
    let mut ac_bits = [0u64; NUM_BITS];
    let mut bc_bits = [0u64; NUM_BITS];
    let mut mid_bits = [0u64; NUM_BITS];
    for i in 0..NUM_BITS {
        a_bits[i] = (a >> i) & 1;
        b_bits[i] = (b >> i) & 1;
        c_bits[i] = (c >> i) & 1;
        out_bits[i] = (out >> i) & 1;
        ab_bits[i] = (ab >> i) & 1;
        ac_bits[i] = (ac >> i) & 1;
        bc_bits[i] = (bc >> i) & 1;
        mid_bits[i] = (mid >> i) & 1;
    }
    MajWitness {
        a_chunks: super::word64_add::decompose_u64(a),
        b_chunks: super::word64_add::decompose_u64(b),
        c_chunks: super::word64_add::decompose_u64(c),
        out_chunks: super::word64_add::decompose_u64(out),
        a_bits,
        b_bits,
        c_bits,
        out_bits,
        ab_bits,
        ac_bits,
        bc_bits,
        mid_bits,
    }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(w: &MajWitness) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];
    for i in 0..NUM_CHUNKS {
        values[col::A_CHUNKS + i] = F::from_u64(w.a_chunks[i]);
        values[col::B_CHUNKS + i] = F::from_u64(w.b_chunks[i]);
        values[col::C_CHUNKS + i] = F::from_u64(w.c_chunks[i]);
        values[col::OUT_CHUNKS + i] = F::from_u64(w.out_chunks[i]);
    }
    for i in 0..NUM_BITS {
        values[col::A_BITS + i] = F::from_u64(w.a_bits[i]);
        values[col::B_BITS + i] = F::from_u64(w.b_bits[i]);
        values[col::C_BITS + i] = F::from_u64(w.c_bits[i]);
        values[col::OUT_BITS + i] = F::from_u64(w.out_bits[i]);
        values[col::AB_BITS + i] = F::from_u64(w.ab_bits[i]);
        values[col::AC_BITS + i] = F::from_u64(w.ac_bits[i]);
        values[col::BC_BITS + i] = F::from_u64(w.bc_bits[i]);
        values[col::MID_BITS + i] = F::from_u64(w.mid_bits[i]);
    }
    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::word64_add::recompose_u64;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    fn native_maj(a: u64, b: u64, c: u64) -> u64 {
        (a & b) ^ (a & c) ^ (b & c)
    }

    #[test]
    fn maj_zero_is_zero() {
        let w = compute_maj(0, 0, 0);
        assert_eq!(recompose_u64(&w.out_chunks), 0);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&MajTestAir, &trace, &[]);
    }

    #[test]
    fn maj_two_majority_one_minority() {
        // bits 0..1 set in a, bit 0 set in b: majority of (1,1,0) = 1, (1,0,0) = 0 etc.
        // a = 0b11, b = 0b01, c = 0
        // bit 0: maj(1,1,0) = 1
        // bit 1: maj(1,0,0) = 0
        let w = compute_maj(0b11, 0b01, 0);
        assert_eq!(recompose_u64(&w.out_chunks), 0b01);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&MajTestAir, &trace, &[]);
    }

    #[test]
    fn maj_all_ones_is_all_ones() {
        let w = compute_maj(u64::MAX, u64::MAX, u64::MAX);
        assert_eq!(recompose_u64(&w.out_chunks), u64::MAX);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&MajTestAir, &trace, &[]);
    }

    #[test]
    fn maj_against_native_for_sha512_iv_state() {
        let cases: [(u64, u64, u64); 5] = [
            (0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b), // IV[0..3]
            (0xDEAD_BEEF_CAFE_BABE, 0x0123_4567_89AB_CDEF, 0xFEDC_BA09_8765_4321),
            (0xAAAA_AAAA_AAAA_AAAA, 0x5555_5555_5555_5555, 0xCCCC_CCCC_CCCC_CCCC),
            (0, u64::MAX, 0),
            (u64::MAX, 0, u64::MAX),
        ];
        for (a, b, c) in cases {
            let w = compute_maj(a, b, c);
            assert_eq!(recompose_u64(&w.out_chunks), native_maj(a, b, c), "Maj({a:#x}, {b:#x}, {c:#x})");
            let trace = build_test_trace::<BabyBear>(&w);
            check_constraints(&MajTestAir, &trace, &[]);
        }
    }

    #[test]
    fn maj_commutativity_in_first_two() {
        // Maj is symmetric in all three args, but easy to test pairwise.
        let a = 0xDEAD_BEEF;
        let b = 0xCAFE_BABE;
        let c = 0x1234_5678;
        let w_abc = compute_maj(a, b, c);
        let w_bac = compute_maj(b, a, c);
        assert_eq!(w_abc.out_chunks, w_bac.out_chunks);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn maj_rejects_tampered_out_bit() {
        let w = compute_maj(0xFFFF, 0xFFFF, 0xFFFF);
        let mut trace = build_test_trace::<BabyBear>(&w);
        trace.values[col::OUT_BITS] = trace.values[col::OUT_BITS] - BabyBear::ONE;
        check_constraints(&MajTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn maj_rejects_tampered_mid_bit() {
        let w = compute_maj(0x1234, 0x5678, 0x9ABC);
        let mut trace = build_test_trace::<BabyBear>(&w);
        trace.values[col::MID_BITS] = trace.values[col::MID_BITS] + BabyBear::ONE;
        check_constraints(&MajTestAir, &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        assert_eq!(NUM_COLS, 528);
    }
}
