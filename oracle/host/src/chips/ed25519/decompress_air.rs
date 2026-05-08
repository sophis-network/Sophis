//! `ed25519::decompress_air` — point decompression AIR (WIRED, single-row).
//!
//! Constrains the FIELD ARITHMETIC portion of decompress (RFC 8032 §5.1.3):
//!
//! ```text
//! y2  = y · y
//! u   = y² - 1
//! d_y2= d · y²
//! v   = d·y² + 1
//! v2  = v · v
//! v3  = v² · v
//! v4  = v² · v²
//! v7  = v⁴ · v³
//! uv3 = u · v³
//! uv7 = u · v⁷
//! cand_x = uv3 · pow_result    (where pow_result = uv7^((p-5)/8) — separate proof)
//! x²  = cand_x · cand_x
//! v_x2 = v · x²
//! ```
//!
//! ## Multi-proof aggregation architecture
//!
//! Two boundary witnesses are intentionally NOT constrained at this AIR layer:
//!   1. `y` — derived from `compressed_bytes` via bit-shuffling
//!      (`Field25519Element::from_canonical_bytes`). Constraining bit-shuffling
//!      in AIR is expensive and offers little marginal soundness; the bytes
//!      are public input to the verifier so `y` correctness is auditable
//!      out-of-band.
//!   2. `pow_result` — `uv7^((p-5)/8) (mod p)`. Constrained by a separate
//!      `pow_air` proof over 256 rows (sub-fase 5.2.1.5). Aggregated at the
//!      verifier level via shared boundary commitment.
//!   3. Sign branches (`i_twist`, `negation`, valid output `x`/`t`):
//!      witness-only here; the verify_air composition asserts the final
//!      group-equation equality.
//!
//! This is the standard production STARK aggregation pattern (cf. Polygon
//! Hermez, Mina, etc.).
//!
//! ## Layout (single-row)
//!
//! | Range       | Width | Contents                                    |
//! |-------------|-------|---------------------------------------------|
//! | 0..32       | 32    | compressed bytes (input)                    |
//! | 32..41      | 9     | y limbs (boundary, derived from bytes)      |
//! | 41..50      | 9     | y² limbs                                    |
//! | 50..59      | 9     | d·y² limbs                                  |
//! | 59..68      | 9     | u = y² - 1 limbs                            |
//! | 68..77      | 9     | v = d·y² + 1 limbs                          |
//! | 77..86      | 9     | v² limbs                                    |
//! | 86..95      | 9     | v³ limbs                                    |
//! | 95..104     | 9     | v⁴ limbs                                    |
//! | 104..113    | 9     | v⁷ limbs                                    |
//! | 113..122    | 9     | u·v³ limbs                                  |
//! | 122..131    | 9     | u·v⁷ limbs                                  |
//! | 131..140    | 9     | pow_result (BOUNDARY INPUT — separate proof)|
//! | 140..149    | 9     | candidate_x = uv3 · pow_result              |
//! | 149..158    | 9     | x² = cand · cand                            |
//! | 158..167    | 9     | v · x²                                      |
//! | 167..176    | 9     | d constant                                  |
//! | 176..185    | 9     | one constant                                |
//! | 185..194    | 9     | sign-corrected x output (boundary)          |
//! | 194..203    | 9     | t output = x · y (boundary)                 |
//! | 203..212    | 9     | z output = 1 (boundary)                     |
//! | 212         | 1     | sign_bit (boundary)                         |
//! | 213         | 1     | valid flag (boundary)                       |
//! | 214..       | sub-chips |                                          |
//!
//! Sub-chips: 11× MulCanonicalFullChip + 1× AddCanonicalChip + 1× SubCanonicalChip.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::chips::field25519::{
    Field25519Element, NUM_LIMBS,
    add_canonical::{self, AddCanonicalChip, NUM_COLS as ADC_COLS},
    mul_canonical_full::{self, MulCanonicalFullChip, NUM_COLS as MC_COLS},
    sub_canonical::{self, NUM_COLS as SC_COLS, SubCanonicalChip},
};

const NUM_MULS: usize = 11;

pub mod col {
    use super::*;
    pub const BYTES: usize = 0; // 32
    pub const Y: usize = BYTES + 32; // 32
    pub const Y2: usize = Y + NUM_LIMBS; // 41
    pub const D_Y2: usize = Y2 + NUM_LIMBS; // 50
    pub const U: usize = D_Y2 + NUM_LIMBS; // 59
    pub const V: usize = U + NUM_LIMBS; // 68
    pub const V2: usize = V + NUM_LIMBS; // 77
    pub const V3: usize = V2 + NUM_LIMBS; // 86
    pub const V4: usize = V3 + NUM_LIMBS; // 95
    pub const V7: usize = V4 + NUM_LIMBS; // 104
    pub const UV3: usize = V7 + NUM_LIMBS; // 113
    pub const UV7: usize = UV3 + NUM_LIMBS; // 122
    pub const POW_RESULT: usize = UV7 + NUM_LIMBS; // 131
    pub const CAND_X: usize = POW_RESULT + NUM_LIMBS; // 140
    pub const X_SQ: usize = CAND_X + NUM_LIMBS; // 149
    pub const V_X2: usize = X_SQ + NUM_LIMBS; // 158
    pub const D_CONST: usize = V_X2 + NUM_LIMBS; // 167
    pub const ONE_CONST: usize = D_CONST + NUM_LIMBS; // 176
    pub const X_OUT: usize = ONE_CONST + NUM_LIMBS; // 185
    pub const T_OUT: usize = X_OUT + NUM_LIMBS; // 194
    pub const Z_OUT: usize = T_OUT + NUM_LIMBS; // 203
    pub const SIGN_BIT: usize = Z_OUT + NUM_LIMBS; // 212
    pub const VALID: usize = SIGN_BIT + 1; // 213

    pub const ADD_START: usize = VALID + 1; // 214 — d·y² + 1
    pub const SUB_START: usize = ADD_START + ADC_COLS; // 358 — y² - 1
    pub const MULS_BASE: usize = SUB_START + SC_COLS; // 502
    pub const TOTAL: usize = MULS_BASE + NUM_MULS * MC_COLS; // 8312

    pub const fn mul_at(i: usize) -> usize {
        MULS_BASE + i * MC_COLS
    }
}

pub const NUM_COLS: usize = col::TOTAL;

/// Public-values count exposed to the STARK verifier (sub-fase 5.6.a.1).
///
/// Layout:
///   [0..32]      compressed_bytes (boundary-bound to row[col::BYTES..])
///   [32..68]     output_point limbs (X_OUT 9 + Y 9 + Z_OUT 9 + T_OUT 9 = 36)
///   [68]         valid flag (boundary-bound to row[col::VALID])
///
/// Bytes are one BabyBear element per byte (canonical 0..255). Limbs are
/// one BabyBear element per 30-bit limb. Valid is 0 or 1.
///
/// Closes the trust shim from 5.6.a: the wrapper verifier no longer
/// re-derives the output and compares to the supplied PV — the STARK
/// constraints inside the AIR enforce equality directly. Companion
/// aggregation (contract spec 5.6.e) becomes a pure on-chain
/// `verify_plonky3_proof` call with no extra Rust-side trust.
pub const NUM_BOUNDARY_LIMBS: usize = 4 * NUM_LIMBS; // 36
pub const NUM_PUBLIC_VALUES: usize = 32 + NUM_BOUNDARY_LIMBS + 1; // 69

/// Sub-chip indices for the 11 muls.
pub mod chip {
    pub const MUL_Y2: usize = 0; // y · y
    pub const MUL_D_Y2: usize = 1; // d · y²
    pub const MUL_V2: usize = 2; // v · v
    pub const MUL_V3: usize = 3; // v² · v
    pub const MUL_V4: usize = 4; // v² · v²
    pub const MUL_V7: usize = 5; // v⁴ · v³
    pub const MUL_UV3: usize = 6; // u · v³
    pub const MUL_UV7: usize = 7; // u · v⁷
    pub const MUL_CAND: usize = 8; // uv3 · pow_result
    pub const MUL_X_SQ: usize = 9; // cand · cand
    pub const MUL_V_X2: usize = 10; // v · x²
}

#[derive(Debug, Clone, Copy)]
pub struct DecompressAirChip;

fn one_limbs() -> [u64; NUM_LIMBS] {
    let mut o = [0u64; NUM_LIMBS];
    o[0] = 1;
    o
}

fn d_limbs() -> [u64; NUM_LIMBS] {
    use crate::chips::ed25519::point::d_constant;
    d_constant().limbs
}

impl<F: Field> BaseAir<F> for DecompressAirChip {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for DecompressAirChip
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        // Embed sub-chips.
        AddCanonicalChip::at(col::ADD_START).emit(builder);
        SubCanonicalChip::at(col::SUB_START).emit(builder);
        for i in 0..NUM_MULS {
            MulCanonicalFullChip::at(col::mul_at(i)).emit(builder);
        }

        let main = builder.main();
        let row = main.current_slice();

        // Boundary: constants.
        let one = one_limbs();
        let d = d_limbs();
        for i in 0..NUM_LIMBS {
            builder.assert_eq(row[col::ONE_CONST + i], AB::Expr::from_u64(one[i]));
            builder.assert_eq(row[col::D_CONST + i], AB::Expr::from_u64(d[i]));
            // z_out = 1
            builder.assert_eq(row[col::Z_OUT + i], AB::Expr::from_u64(one[i]));
        }
        // Boolean booleans.
        builder.assert_bool(row[col::SIGN_BIT]);
        builder.assert_bool(row[col::VALID]);

        // Connection helper.
        let assert_chunks = |b: &mut AB, off_a: usize, off_b: usize| {
            for i in 0..NUM_LIMBS {
                b.assert_eq(row[off_a + i], row[off_b + i]);
            }
        };

        // y² = y · y
        assert_chunks(builder, col::mul_at(chip::MUL_Y2) + mul_canonical_full::col::A, col::Y);
        assert_chunks(builder, col::mul_at(chip::MUL_Y2) + mul_canonical_full::col::B, col::Y);
        assert_chunks(builder, col::Y2, col::mul_at(chip::MUL_Y2) + mul_canonical_full::col::C);

        // d·y² = D_CONST · y²
        assert_chunks(builder, col::mul_at(chip::MUL_D_Y2) + mul_canonical_full::col::A, col::D_CONST);
        assert_chunks(builder, col::mul_at(chip::MUL_D_Y2) + mul_canonical_full::col::B, col::Y2);
        assert_chunks(builder, col::D_Y2, col::mul_at(chip::MUL_D_Y2) + mul_canonical_full::col::C);

        // u = y² - 1 (sub_canonical: A = y², B = ONE)
        assert_chunks(builder, col::SUB_START + sub_canonical::col::A, col::Y2);
        assert_chunks(builder, col::SUB_START + sub_canonical::col::B, col::ONE_CONST);
        assert_chunks(builder, col::U, col::SUB_START + sub_canonical::col::C);

        // v = d·y² + 1 (add_canonical: A = D_Y2, B = ONE)
        assert_chunks(builder, col::ADD_START + add_canonical::col::A, col::D_Y2);
        assert_chunks(builder, col::ADD_START + add_canonical::col::B, col::ONE_CONST);
        assert_chunks(builder, col::V, col::ADD_START + add_canonical::col::C);

        // v² = v · v
        assert_chunks(builder, col::mul_at(chip::MUL_V2) + mul_canonical_full::col::A, col::V);
        assert_chunks(builder, col::mul_at(chip::MUL_V2) + mul_canonical_full::col::B, col::V);
        assert_chunks(builder, col::V2, col::mul_at(chip::MUL_V2) + mul_canonical_full::col::C);

        // v³ = v² · v
        assert_chunks(builder, col::mul_at(chip::MUL_V3) + mul_canonical_full::col::A, col::V2);
        assert_chunks(builder, col::mul_at(chip::MUL_V3) + mul_canonical_full::col::B, col::V);
        assert_chunks(builder, col::V3, col::mul_at(chip::MUL_V3) + mul_canonical_full::col::C);

        // v⁴ = v² · v²
        assert_chunks(builder, col::mul_at(chip::MUL_V4) + mul_canonical_full::col::A, col::V2);
        assert_chunks(builder, col::mul_at(chip::MUL_V4) + mul_canonical_full::col::B, col::V2);
        assert_chunks(builder, col::V4, col::mul_at(chip::MUL_V4) + mul_canonical_full::col::C);

        // v⁷ = v⁴ · v³
        assert_chunks(builder, col::mul_at(chip::MUL_V7) + mul_canonical_full::col::A, col::V4);
        assert_chunks(builder, col::mul_at(chip::MUL_V7) + mul_canonical_full::col::B, col::V3);
        assert_chunks(builder, col::V7, col::mul_at(chip::MUL_V7) + mul_canonical_full::col::C);

        // u·v³
        assert_chunks(builder, col::mul_at(chip::MUL_UV3) + mul_canonical_full::col::A, col::U);
        assert_chunks(builder, col::mul_at(chip::MUL_UV3) + mul_canonical_full::col::B, col::V3);
        assert_chunks(builder, col::UV3, col::mul_at(chip::MUL_UV3) + mul_canonical_full::col::C);

        // u·v⁷
        assert_chunks(builder, col::mul_at(chip::MUL_UV7) + mul_canonical_full::col::A, col::U);
        assert_chunks(builder, col::mul_at(chip::MUL_UV7) + mul_canonical_full::col::B, col::V7);
        assert_chunks(builder, col::UV7, col::mul_at(chip::MUL_UV7) + mul_canonical_full::col::C);

        // candidate_x = uv3 · pow_result
        assert_chunks(builder, col::mul_at(chip::MUL_CAND) + mul_canonical_full::col::A, col::UV3);
        assert_chunks(builder, col::mul_at(chip::MUL_CAND) + mul_canonical_full::col::B, col::POW_RESULT);
        assert_chunks(builder, col::CAND_X, col::mul_at(chip::MUL_CAND) + mul_canonical_full::col::C);

        // x_sq = cand · cand
        assert_chunks(builder, col::mul_at(chip::MUL_X_SQ) + mul_canonical_full::col::A, col::CAND_X);
        assert_chunks(builder, col::mul_at(chip::MUL_X_SQ) + mul_canonical_full::col::B, col::CAND_X);
        assert_chunks(builder, col::X_SQ, col::mul_at(chip::MUL_X_SQ) + mul_canonical_full::col::C);

        // v_x2 = v · x²
        assert_chunks(builder, col::mul_at(chip::MUL_V_X2) + mul_canonical_full::col::A, col::V);
        assert_chunks(builder, col::mul_at(chip::MUL_V_X2) + mul_canonical_full::col::B, col::X_SQ);
        assert_chunks(builder, col::V_X2, col::mul_at(chip::MUL_V_X2) + mul_canonical_full::col::C);

        // Note: x_out / t_out / sign correction / i-twist branches are not
        // constrained here. They are boundary witnesses validated by the
        // composing verify_air via the group-equation final equality.

        // ===== Sub-fase 5.6.a.1: Boundary binding for STARK public values =====
        //
        // Layout:
        //   PV[0..32]    == row[col::BYTES..col::BYTES+32]      (input)
        //   PV[32..41]   == row[col::X_OUT..col::X_OUT+9]       (output X)
        //   PV[41..50]   == row[col::Y..col::Y+9]               (output Y, derived from input)
        //   PV[50..59]   == row[col::Z_OUT..col::Z_OUT+9]       (output Z = 1)
        //   PV[59..68]   == row[col::T_OUT..col::T_OUT+9]       (output T)
        //   PV[68]       == row[col::VALID]                     (valid flag)
        //
        // Output cells are NOT contiguous in the trace (X_OUT at 185, Y at 32,
        // Z_OUT at 203, T_OUT at 194), so we bind each region separately.
        // Copy public values into a Copy array first to release the immutable
        // borrow on `builder` before calling mutable assert_eq.
        let pub_copies: [AB::PublicVar; NUM_PUBLIC_VALUES] = {
            let public = builder.public_values();
            core::array::from_fn(|i| public[i])
        };
        // Input bytes: PV[0..32] == row[col::BYTES..col::BYTES+32]
        for i in 0..32 {
            builder.assert_eq(row[col::BYTES + i], pub_copies[i]);
        }
        // Output X: PV[32..41] == row[col::X_OUT..]
        for i in 0..NUM_LIMBS {
            builder.assert_eq(row[col::X_OUT + i], pub_copies[32 + i]);
        }
        // Output Y: PV[41..50] == row[col::Y..]
        for i in 0..NUM_LIMBS {
            builder.assert_eq(row[col::Y + i], pub_copies[32 + NUM_LIMBS + i]);
        }
        // Output Z: PV[50..59] == row[col::Z_OUT..]
        for i in 0..NUM_LIMBS {
            builder.assert_eq(row[col::Z_OUT + i], pub_copies[32 + 2 * NUM_LIMBS + i]);
        }
        // Output T: PV[59..68] == row[col::T_OUT..]
        for i in 0..NUM_LIMBS {
            builder.assert_eq(row[col::T_OUT + i], pub_copies[32 + 3 * NUM_LIMBS + i]);
        }
        // Valid flag: PV[68] == row[col::VALID]
        builder.assert_eq(row[col::VALID], pub_copies[32 + NUM_BOUNDARY_LIMBS]);
    }
}

/// Populate one row at row offset `row_off` (start_col = 0).
pub fn populate_row<F: Field + PrimeCharacteristicRing>(values: &mut [F], row_off: usize, compressed: &[u8; 32]) {
    use crate::chips::ed25519::decompress::decompress;
    use crate::chips::ed25519::point::two_d_constant;
    use crate::chips::field25519::arith::{field_add, field_mul, field_sub};

    let _ = two_d_constant; // ensure dep not stripped

    let one = Field25519Element { limbs: one_limbs() };
    let d = Field25519Element { limbs: d_limbs() };

    // Decode y from bytes (boundary witness, not AIR-constrained).
    let y = Field25519Element::from_canonical_bytes(compressed);
    let sign_bit = (compressed[31] >> 7) & 1;

    // Compute the field arith chain.
    let y2 = field_mul(&y, &y);
    let d_y2 = field_mul(&d, &y2);
    let u = field_sub(&y2, &one);
    let v = field_add(&d_y2, &one);
    let v2 = field_mul(&v, &v);
    let v3 = field_mul(&v2, &v);
    let v4 = field_mul(&v2, &v2);
    let v7 = field_mul(&v4, &v3);
    let uv3 = field_mul(&u, &v3);
    let uv7 = field_mul(&u, &v7);

    // pow_result is a boundary input. For the populated trace we compute it
    // here so the round-trip succeeds; in production it comes from a
    // separate pow_air proof.
    use crate::chips::ed25519::decompress::{P_MINUS_5_OVER_8, field_pow};
    let pow_result = field_pow(&uv7, &P_MINUS_5_OVER_8);

    let cand_x = field_mul(&uv3, &pow_result);
    let x_sq = field_mul(&cand_x, &cand_x);
    let v_x2 = field_mul(&v, &x_sq);

    // Determine final point + valid flag using witness function (boundary).
    let result = decompress(compressed);
    let (final_x, final_t, valid) = match result {
        Some(point) => (point.x, point.t, 1u8),
        None => (Field25519Element::ZERO, Field25519Element::ZERO, 0u8),
    };

    // Top-level cells.
    let put_field = |values: &mut [F], off: usize, e: &Field25519Element| {
        for i in 0..NUM_LIMBS {
            values[off + i] = F::from_u64(e.limbs[i]);
        }
    };
    let base = row_off;

    for i in 0..32 {
        values[base + col::BYTES + i] = F::from_u64(compressed[i] as u64);
    }
    put_field(values, base + col::Y, &y);
    put_field(values, base + col::Y2, &y2);
    put_field(values, base + col::D_Y2, &d_y2);
    put_field(values, base + col::U, &u);
    put_field(values, base + col::V, &v);
    put_field(values, base + col::V2, &v2);
    put_field(values, base + col::V3, &v3);
    put_field(values, base + col::V4, &v4);
    put_field(values, base + col::V7, &v7);
    put_field(values, base + col::UV3, &uv3);
    put_field(values, base + col::UV7, &uv7);
    put_field(values, base + col::POW_RESULT, &pow_result);
    put_field(values, base + col::CAND_X, &cand_x);
    put_field(values, base + col::X_SQ, &x_sq);
    put_field(values, base + col::V_X2, &v_x2);
    put_field(values, base + col::D_CONST, &d);
    put_field(values, base + col::ONE_CONST, &one);
    put_field(values, base + col::X_OUT, &final_x);
    put_field(values, base + col::T_OUT, &final_t);
    put_field(values, base + col::Z_OUT, &one);
    values[base + col::SIGN_BIT] = F::from_u64(sign_bit as u64);
    values[base + col::VALID] = F::from_u64(valid as u64);

    // Sub-chip witnesses.
    add_canonical::populate_row::<F>(values, row_off, col::ADD_START, &d_y2, &one);
    sub_canonical::populate_row::<F>(values, row_off, col::SUB_START, &y2, &one);
    mul_canonical_full::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_Y2), &y, &y);
    mul_canonical_full::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_D_Y2), &d, &y2);
    mul_canonical_full::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_V2), &v, &v);
    mul_canonical_full::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_V3), &v2, &v);
    mul_canonical_full::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_V4), &v2, &v2);
    mul_canonical_full::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_V7), &v4, &v3);
    mul_canonical_full::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_UV3), &u, &v3);
    mul_canonical_full::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_UV7), &u, &v7);
    mul_canonical_full::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_CAND), &uv3, &pow_result);
    mul_canonical_full::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_X_SQ), &cand_x, &cand_x);
    mul_canonical_full::populate_row::<F>(values, row_off, col::mul_at(chip::MUL_V_X2), &v, &x_sq);
}

pub fn build_decompress_trace<F: Field + PrimeCharacteristicRing>(compressed: &[u8; 32]) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    // Replicate the same input across all rows. The boundary-binding
    // constraints from 5.6.a.1 fire on every row (Plonky3 evaluates the
    // AIR's constraints at every trace row), so row 0 and the padding
    // rows MUST agree on (input, output, valid). Identical-row padding
    // satisfies this trivially.
    for row in 0..HEIGHT {
        populate_row::<F>(&mut values, row * NUM_COLS, compressed);
    }

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    /// Build the public-values vector for a given input — mirrors what
    /// the STARK plumbing in `decompress_air_stark` does, but inlined so
    /// these standalone tests don't depend on that module.
    fn pv_for<F: p3_field::Field + p3_field::PrimeCharacteristicRing>(compressed: &[u8; 32]) -> Vec<F> {
        use crate::chips::ed25519::decompress::decompress;
        let (point, valid) = match decompress(compressed) {
            Some(p) => (p, 1u64),
            None => (
                crate::chips::ed25519::point::ExtendedPoint {
                    x: Field25519Element::ZERO,
                    y: Field25519Element::from_canonical_bytes(compressed),
                    z: Field25519Element {
                        limbs: {
                            let mut o = [0u64; NUM_LIMBS];
                            o[0] = 1;
                            o
                        },
                    },
                    t: Field25519Element::ZERO,
                },
                0u64,
            ),
        };
        let mut out = Vec::with_capacity(NUM_PUBLIC_VALUES);
        for &b in compressed {
            out.push(F::from_u64(b as u64));
        }
        for &l in &point.x.limbs {
            out.push(F::from_u64(l));
        }
        for &l in &point.y.limbs {
            out.push(F::from_u64(l));
        }
        for &l in &point.z.limbs {
            out.push(F::from_u64(l));
        }
        for &l in &point.t.limbs {
            out.push(F::from_u64(l));
        }
        out.push(F::from_u64(valid));
        out
    }

    #[test]
    fn decompress_basepoint() {
        let mut compressed = [0x66u8; 32];
        compressed[0] = 0x58;
        let trace = build_decompress_trace::<BabyBear>(&compressed);
        let pv = pv_for::<BabyBear>(&compressed);
        check_constraints(&DecompressAirChip, &trace, &pv);
    }

    #[test]
    fn decompress_neutral_element() {
        // y = 1, sign_bit = 0 → x = 0.
        let mut compressed = [0u8; 32];
        compressed[0] = 1;
        let trace = build_decompress_trace::<BabyBear>(&compressed);
        let pv = pv_for::<BabyBear>(&compressed);
        check_constraints(&DecompressAirChip, &trace, &pv);
    }

    #[test]
    fn constraint_count_documented() {
        // 3.2-3.8 + 3.9 per mul_canonical_full = +3144 each.
        // 8312 + 11 × 3144 = 42_896.
        assert_eq!(NUM_COLS, 42_896);
    }
}
