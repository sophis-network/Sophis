//! `sha512::ch` — Choice function chip: `Ch(e, f, g) = (e ∧ f) ⊕ (¬e ∧ g)`.
//!
//! Selects bits from `f` where `e=1` and from `g` where `e=0`. Used in
//! every SHA-512 round.
//!
//! ## Layout (one operation per row, allocated at `start_col`)
//!
//! | offset    | width | name        |
//! |-----------|-------|-------------|
//! | 0         | 4     | e chunks    |
//! | 4         | 4     | f chunks    |
//! | 8         | 4     | g chunks    |
//! | 12        | 4     | c chunks    | (= Ch(e, f, g))
//! | 16        | 64    | e bits      |
//! | 80        | 64    | f bits      |
//! | 144       | 64    | g bits      |
//! | 208       | 64    | c bits      |
//! | 272       | 64    | ef bits     | (= e ∧ f)
//! | 336       | 64    | nef_g bits  | (= ¬e ∧ g = (1 - e) · g)
//!
//! Total: **400 columns**, **464 constraints** (degree 2).
//!
//! ## Constraints
//!
//! - 256 boolean checks (e, f, g, c bits — ef and nef_g are products of
//!   booleans so automatically boolean; no extra check needed).
//! - 16 chunk-recomposition (e, f, g, c).
//! - 64 ef = e · f.
//! - 64 nef_g = (1 - e) · g.
//! - 64 c = ef + nef_g - 2·ef·nef_g (the final XOR).

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

pub const NUM_CHUNKS: usize = 4;
pub const CHUNK_BITS: usize = 16;
pub const NUM_BITS: usize = 64;

pub mod col {
    use super::{NUM_BITS, NUM_CHUNKS};
    pub const E_CHUNKS: usize = 0;
    pub const F_CHUNKS: usize = E_CHUNKS + NUM_CHUNKS; // 4
    pub const G_CHUNKS: usize = F_CHUNKS + NUM_CHUNKS; // 8
    pub const C_CHUNKS: usize = G_CHUNKS + NUM_CHUNKS; // 12
    pub const E_BITS: usize = C_CHUNKS + NUM_CHUNKS; // 16
    pub const F_BITS: usize = E_BITS + NUM_BITS; // 80
    pub const G_BITS: usize = F_BITS + NUM_BITS; // 144
    pub const C_BITS: usize = G_BITS + NUM_BITS; // 208
    pub const EF_BITS: usize = C_BITS + NUM_BITS; // 272
    pub const NEF_G_BITS: usize = EF_BITS + NUM_BITS; // 336
}

pub const NUM_COLS: usize = col::NEF_G_BITS + NUM_BITS; // 400

#[derive(Debug, Clone, Copy)]
pub struct ChChip {
    pub start_col: usize,
}

impl Default for ChChip {
    fn default() -> Self {
        Self::new()
    }
}

impl ChChip {
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
            builder.assert_bool(row[self.start_col + col::E_BITS + i]);
            builder.assert_bool(row[self.start_col + col::F_BITS + i]);
            builder.assert_bool(row[self.start_col + col::G_BITS + i]);
            builder.assert_bool(row[self.start_col + col::C_BITS + i]);
        }

        // Chunk recomposition for e, f, g, c.
        for chunk_idx in 0..NUM_CHUNKS {
            let bit_base = chunk_idx * CHUNK_BITS;
            let mut e_acc = AB::Expr::ZERO;
            let mut f_acc = AB::Expr::ZERO;
            let mut g_acc = AB::Expr::ZERO;
            let mut c_acc = AB::Expr::ZERO;
            let mut weight: u64 = 1;
            for k in 0..CHUNK_BITS {
                let w = AB::Expr::from_u64(weight);
                e_acc += w.clone() * row[self.start_col + col::E_BITS + bit_base + k].into();
                f_acc += w.clone() * row[self.start_col + col::F_BITS + bit_base + k].into();
                g_acc += w.clone() * row[self.start_col + col::G_BITS + bit_base + k].into();
                c_acc += w * row[self.start_col + col::C_BITS + bit_base + k].into();
                weight <<= 1;
            }
            builder.assert_eq(row[self.start_col + col::E_CHUNKS + chunk_idx], e_acc);
            builder.assert_eq(row[self.start_col + col::F_CHUNKS + chunk_idx], f_acc);
            builder.assert_eq(row[self.start_col + col::G_CHUNKS + chunk_idx], g_acc);
            builder.assert_eq(row[self.start_col + col::C_CHUNKS + chunk_idx], c_acc);
        }

        // ef = e · f, nef_g = (1 - e) · g, c = ef XOR nef_g.
        for i in 0..NUM_BITS {
            let e_bit = row[self.start_col + col::E_BITS + i];
            let f_bit = row[self.start_col + col::F_BITS + i];
            let g_bit = row[self.start_col + col::G_BITS + i];
            let ef_bit = row[self.start_col + col::EF_BITS + i];
            let nef_g_bit = row[self.start_col + col::NEF_G_BITS + i];
            let c_bit = row[self.start_col + col::C_BITS + i];

            builder.assert_eq(ef_bit, e_bit.into() * f_bit.into());
            builder.assert_eq(nef_g_bit, (AB::Expr::ONE - e_bit.into()) * g_bit.into());
            builder.assert_eq(c_bit, ef_bit.into() + nef_g_bit.into() - two.clone() * (ef_bit.into() * nef_g_bit.into()));
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ChTestAir;

impl<F: Field> BaseAir<F> for ChTestAir {
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

impl<AB: AirBuilder> Air<AB> for ChTestAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        ChChip::new().emit(builder);
    }
}

#[derive(Debug, Clone)]
pub struct ChWitness {
    pub e_chunks: [u64; NUM_CHUNKS],
    pub f_chunks: [u64; NUM_CHUNKS],
    pub g_chunks: [u64; NUM_CHUNKS],
    pub c_chunks: [u64; NUM_CHUNKS],
    pub e_bits: [u64; NUM_BITS],
    pub f_bits: [u64; NUM_BITS],
    pub g_bits: [u64; NUM_BITS],
    pub c_bits: [u64; NUM_BITS],
    pub ef_bits: [u64; NUM_BITS],
    pub nef_g_bits: [u64; NUM_BITS],
}

pub fn compute_ch(e: u64, f: u64, g: u64) -> ChWitness {
    let ef = e & f;
    let nef_g = (!e) & g;
    let c = ef ^ nef_g;
    let mut e_bits = [0u64; NUM_BITS];
    let mut f_bits = [0u64; NUM_BITS];
    let mut g_bits = [0u64; NUM_BITS];
    let mut c_bits = [0u64; NUM_BITS];
    let mut ef_bits = [0u64; NUM_BITS];
    let mut nef_g_bits = [0u64; NUM_BITS];
    for i in 0..NUM_BITS {
        e_bits[i] = (e >> i) & 1;
        f_bits[i] = (f >> i) & 1;
        g_bits[i] = (g >> i) & 1;
        c_bits[i] = (c >> i) & 1;
        ef_bits[i] = (ef >> i) & 1;
        nef_g_bits[i] = (nef_g >> i) & 1;
    }
    ChWitness {
        e_chunks: super::word64_add::decompose_u64(e),
        f_chunks: super::word64_add::decompose_u64(f),
        g_chunks: super::word64_add::decompose_u64(g),
        c_chunks: super::word64_add::decompose_u64(c),
        e_bits,
        f_bits,
        g_bits,
        c_bits,
        ef_bits,
        nef_g_bits,
    }
}

pub fn build_test_trace<F: Field + PrimeCharacteristicRing>(w: &ChWitness) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];
    for i in 0..NUM_CHUNKS {
        values[col::E_CHUNKS + i] = F::from_u64(w.e_chunks[i]);
        values[col::F_CHUNKS + i] = F::from_u64(w.f_chunks[i]);
        values[col::G_CHUNKS + i] = F::from_u64(w.g_chunks[i]);
        values[col::C_CHUNKS + i] = F::from_u64(w.c_chunks[i]);
    }
    for i in 0..NUM_BITS {
        values[col::E_BITS + i] = F::from_u64(w.e_bits[i]);
        values[col::F_BITS + i] = F::from_u64(w.f_bits[i]);
        values[col::G_BITS + i] = F::from_u64(w.g_bits[i]);
        values[col::C_BITS + i] = F::from_u64(w.c_bits[i]);
        values[col::EF_BITS + i] = F::from_u64(w.ef_bits[i]);
        values[col::NEF_G_BITS + i] = F::from_u64(w.nef_g_bits[i]);
    }
    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::super::word64_add::recompose_u64;
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    #[test]
    fn ch_zero_is_zero() {
        let w = compute_ch(0, 0, 0);
        assert_eq!(recompose_u64(&w.c_chunks), 0);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&ChTestAir, &trace, &[]);
    }

    #[test]
    fn ch_e_all_ones_selects_f() {
        let w = compute_ch(u64::MAX, 0xCAFE_BABE_DEAD_BEEF, 0xFEDC_BA09_8765_4321);
        assert_eq!(recompose_u64(&w.c_chunks), 0xCAFE_BABE_DEAD_BEEF);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&ChTestAir, &trace, &[]);
    }

    #[test]
    fn ch_e_zero_selects_g() {
        let w = compute_ch(0, 0xCAFE_BABE_DEAD_BEEF, 0xFEDC_BA09_8765_4321);
        assert_eq!(recompose_u64(&w.c_chunks), 0xFEDC_BA09_8765_4321);
        let trace = build_test_trace::<BabyBear>(&w);
        check_constraints(&ChTestAir, &trace, &[]);
    }

    /// FIPS-derived test: the very first round of SHA-512("abc") reads
    /// e = IV[4] = 0x510e527fade682d1, f = IV[5] = 0x9b05688c2b3e6c1f,
    /// g = IV[6] = 0x1f83d9abfb41bd6b. Cross-validated against native u64.
    #[test]
    fn ch_against_native_for_sha512_iv_state() {
        let cases: [(u64, u64, u64); 5] = [
            (0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b),
            (0xDEAD_BEEF_CAFE_BABE, 0x0123_4567_89AB_CDEF, 0xFEDC_BA09_8765_4321),
            (0xAAAA_AAAA_AAAA_AAAA, 0x5555_5555_5555_5555, u64::MAX),
            (0, u64::MAX, u64::MAX),
            (u64::MAX, u64::MAX, 0),
        ];
        for (e, f, g) in cases {
            let w = compute_ch(e, f, g);
            let expected = (e & f) ^ (!e & g);
            assert_eq!(recompose_u64(&w.c_chunks), expected, "Ch({e:#x}, {f:#x}, {g:#x})");
            let trace = build_test_trace::<BabyBear>(&w);
            check_constraints(&ChTestAir, &trace, &[]);
        }
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn ch_rejects_tampered_c_bit() {
        let w = compute_ch(0xFFFF, 0xCAFE, 0xBABE);
        let mut trace = build_test_trace::<BabyBear>(&w);
        trace.values[col::C_BITS] += BabyBear::ONE;
        check_constraints(&ChTestAir, &trace, &[]);
    }

    #[test]
    #[should_panic(expected = "constraints not satisfied")]
    fn ch_rejects_tampered_ef_bit() {
        let w = compute_ch(0xFFFF, 0xFFFF, 0);
        let mut trace = build_test_trace::<BabyBear>(&w);
        trace.values[col::EF_BITS] -= BabyBear::ONE;
        check_constraints(&ChTestAir, &trace, &[]);
    }

    #[test]
    fn constraint_count_documented() {
        assert_eq!(NUM_COLS, 400);
    }
}
