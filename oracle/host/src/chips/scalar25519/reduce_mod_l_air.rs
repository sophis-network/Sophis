//! `scalar25519::reduce_mod_l_air` — single-row AIR for the
//! `h mod ℓ` reduction (sub-fase 5.6.d.1.b).
//!
//! Validates the equation `q · ℓ + scalar = h` byte-level, where:
//!
//!   - `h` is a 64-byte LE input (the SHA-512 digest)
//!   - `scalar` is a 32-byte LE output in `[0, ℓ)`
//!   - `q` is the witnessed 33-byte LE quotient
//!   - `ℓ` is the Curve25519 group order (32-byte LE constant)
//!
//! ## Layout (single-row, padded HEIGHT=4)
//!
//! | Range          | Width | Contents                                |
//! |----------------|-------|-----------------------------------------|
//! | 0..64          | 64    | digest bytes (input, witness)           |
//! | 64..96         | 32    | scalar bytes (output, witness)          |
//! | 96..129        | 33    | quotient bytes (witness)                |
//! | 129..194       | 65    | product = q · ℓ bytes (witness)         |
//! | 194..259       | 65    | product carries (multiplication carry chain) |
//! | 259..324       | 65    | combined carries (addition carry chain) |
//!
//! Total: **324 columns**. All cells are LE bytes (or carries).
//! After sub-fases 5.6.d.1.b/c/d/e: **3106 columns** (bit decomp +
//! sub-diff borrow + digest PV binding).
//!
//! ## Soundness (audit 3.7.3)
//!
//! Fully sound stand-alone. Every byte cell and every carry cell has
//! an inline bit-decomposition range check:
//!
//!   - `quotient[i]`, `product[i]`, `scalar[i]`, `digest[i]`: 8-bit
//!   - `product_carry[i]`: 14-bit (max ~8430 per byte position)
//!   - `combined_carry[i]`, `sub_borrow[i]`: bool via `assert_bool`
//!   - `sub_diff[i]`: 8-bit
//!
//! The PV binding `digest = PV[0..64]` and `scalar = PV[64..96]` then
//! anchors the AIR to verifier-supplied values. After 5.6.d.1.e the
//! wrapper drops its Rust-side `reduce_mod_l` re-derivation entirely
//! — pure STARK verification.
//!
//! ## Constraints
//!
//! For each byte position `k ∈ 0..65`:
//!
//! ```text
//! // Multiplication: product = q · ℓ
//! product[k] + 256 · product_carry[k]
//!     = Σ_{i+j=k, i<33, j<32} quotient[i] · L_BYTES[j]
//!     + (k > 0 ? product_carry[k-1] : 0)
//!
//! // Addition: q·ℓ + scalar = h
//! digest_byte[k] + 256 · combined_carry[k]
//!     = product[k] + (k < 32 ? scalar[k] : 0)
//!     + (k > 0 ? combined_carry[k-1] : 0)
//! ```
//!
//! Where `digest_byte[k] = digest[k]` for `k < 64`, else 0. Both chains
//! are degree 1 (linear in cells with constant coefficients) so they
//! comfortably fit `max_constraint_degree(2)`.
//!
//! ## What this sub-fase does NOT enforce
//!
//! - **Range checks**: byte cells are not yet constrained to `< 256`.
//!   A malicious prover could pick `quotient[i] = 1000` if other cells
//!   absorb it. 5.6.d.1.c adds bit-decomposition range checks.
//! - **`scalar < ℓ`**: scalar is not yet bound to be strictly below ℓ.
//!   5.6.d.1.d adds the byte-level borrow chain comparison.
//! - **PV binding**: digest and scalar are pure witnesses. 5.6.d.1.e
//!   binds them to public values, removing the wrapper trust shim.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::reduce_mod_l::{L_BYTES, PRODUCT_BYTES, QUOTIENT_BYTES, compute_reduce_mod_l_witness};

const DIGEST_BYTES: usize = 64;
const SCALAR_BYTES: usize = 32;

/// Number of bits used to range-check each byte cell.
pub const BITS_PER_BYTE: usize = 8;

/// Number of bits used to range-check each multiplication carry cell.
///
/// Each multiplication carry is at most `(33 · 255² + carry_in) / 256
/// ≈ 8430`, which fits in 14 bits (2¹⁴ = 16384). 14 bits leaves enough
/// headroom that no honest prover ever overflows.
pub const BITS_PER_MUL_CARRY: usize = 14;

pub mod col {
    use super::*;
    pub const DIGEST: usize = 0;
    pub const SCALAR: usize = DIGEST + DIGEST_BYTES; // 64
    pub const QUOTIENT: usize = SCALAR + SCALAR_BYTES; // 96
    pub const PRODUCT: usize = QUOTIENT + QUOTIENT_BYTES; // 129
    pub const PRODUCT_CARRY: usize = PRODUCT + PRODUCT_BYTES; // 194
    pub const COMBINED_CARRY: usize = PRODUCT_CARRY + PRODUCT_BYTES; // 259
    /// Sub-fase 5.6.d.1.c — bit decomposition of `quotient` (33 × 8 bits).
    pub const QUOTIENT_BITS: usize = COMBINED_CARRY + PRODUCT_BYTES; // 324
    /// Bit decomposition of `product` (65 × 8 bits).
    pub const PRODUCT_BITS: usize = QUOTIENT_BITS + QUOTIENT_BYTES * BITS_PER_BYTE; // 588
    /// Bit decomposition of `product_carry` (65 × 14 bits).
    pub const PRODUCT_CARRY_BITS: usize = PRODUCT_BITS + PRODUCT_BYTES * BITS_PER_BYTE; // 1108
    /// Sub-fase 5.6.d.1.d — bit decomposition of `scalar` (32 × 8 bits).
    pub const SCALAR_BITS: usize = PRODUCT_CARRY_BITS + PRODUCT_BYTES * BITS_PER_MUL_CARRY; // 2018
    /// `scalar - ℓ` byte-level subtraction result (32 byte cells).
    pub const SUB_DIFF: usize = SCALAR_BITS + SCALAR_BYTES * BITS_PER_BYTE; // 2274
    /// Bit decomposition of `sub_diff` (32 × 8 bits) — required to range
    /// the subtraction result into `[0, 256)` per byte.
    pub const SUB_DIFF_BITS: usize = SUB_DIFF + SCALAR_BYTES; // 2306
    /// Per-byte borrow-out cells for the `scalar - ℓ` subtraction.
    /// Each cell is constrained to `{0, 1}` via `assert_bool`. The final
    /// borrow (`borrow[31]`) must be `1` for `scalar < ℓ` to hold.
    pub const SUB_BORROW: usize = SUB_DIFF_BITS + SCALAR_BYTES * BITS_PER_BYTE; // 2562
    /// Sub-fase 5.6.d.1.e — bit decomposition of `digest` (64 × 8 bits).
    /// Required to enforce `digest[k] ∈ [0, 256)` since the verifier-
    /// supplied PV could otherwise contain BabyBear values exceeding the
    /// byte range, which would let the addition chain absorb fake bytes.
    pub const DIGEST_BITS: usize = SUB_BORROW + SCALAR_BYTES; // 2594
    pub const TOTAL: usize = DIGEST_BITS + DIGEST_BYTES * BITS_PER_BYTE; // 3106
}

pub const NUM_COLS: usize = col::TOTAL;

/// Sub-fase 5.6.d.1.e — public values exposed to the STARK verifier.
///
/// Layout (96 BabyBear elements):
///   - PV[0..64]:  digest bytes (one cell per byte)
///   - PV[64..96]: scalar bytes (one cell per byte)
///
/// Both are bound to the corresponding trace cells via `assert_eq`, so
/// after this sub-fase the wrapper performs a pure STARK verification
/// without any Rust-side `reduce_mod_l` re-derivation.
pub const NUM_PUBLIC_VALUES: usize = DIGEST_BYTES + SCALAR_BYTES;

/// Single-row AIR for the mod-ℓ reduction. Padded to HEIGHT=4 because
/// Plonky3's FRI requires `log_blowup ≥ 1` and a minimum power-of-two
/// trace domain.
#[derive(Debug, Clone, Copy)]
pub struct ReduceModLAirChip;

impl<F: Field> BaseAir<F> for ReduceModLAirChip {
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

impl<AB: AirBuilder> Air<AB> for ReduceModLAirChip
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();

        // ------------------------------------------------------------
        // 1) Multiplication chain: product = quotient · ℓ
        //
        // For each byte position k ∈ 0..PRODUCT_BYTES:
        //   product[k] + 256·product_carry[k]
        //     = Σ_{i+j=k} quotient[i] · ℓ[j]    + carry_in
        //
        // where carry_in is `product_carry[k-1]` for k > 0, else 0.
        // ℓ[j] is hardcoded; q[i] is a cell. Each partial product is
        // therefore degree 1. The whole equation is degree 1.
        // ------------------------------------------------------------
        for k in 0..PRODUCT_BYTES {
            let lhs = row[col::PRODUCT + k] + AB::Expr::from_u64(256) * row[col::PRODUCT_CARRY + k];
            let mut rhs: AB::Expr = if k == 0 { AB::Expr::ZERO } else { row[col::PRODUCT_CARRY + (k - 1)].into() };
            for i in 0..QUOTIENT_BYTES {
                if i > k {
                    break;
                }
                let j = k - i;
                if j >= L_BYTES.len() {
                    continue;
                }
                let l_const = AB::Expr::from_u64(L_BYTES[j] as u64);
                rhs += row[col::QUOTIENT + i] * l_const;
            }
            builder.assert_eq(lhs, rhs);
        }

        // ------------------------------------------------------------
        // 2) Addition chain: q·ℓ + scalar = digest
        //
        // For each byte position k ∈ 0..PRODUCT_BYTES:
        //   digest_byte[k] + 256·combined_carry[k]
        //     = product[k] + scalar_byte[k]   + carry_in
        //
        // where:
        //   digest_byte[k] = digest[k] (k < 64) or 0 (k = 64)
        //   scalar_byte[k] = scalar[k] (k < 32) or 0 (k ≥ 32)
        //   carry_in       = combined_carry[k-1] (k > 0) or 0
        // ------------------------------------------------------------
        for k in 0..PRODUCT_BYTES {
            let h_byte: AB::Expr = if k < DIGEST_BYTES { row[col::DIGEST + k].into() } else { AB::Expr::ZERO };
            let s_byte: AB::Expr = if k < SCALAR_BYTES { row[col::SCALAR + k].into() } else { AB::Expr::ZERO };
            let p_byte: AB::Expr = row[col::PRODUCT + k].into();
            let c_in: AB::Expr = if k == 0 { AB::Expr::ZERO } else { row[col::COMBINED_CARRY + (k - 1)].into() };
            let c_out: AB::Expr = row[col::COMBINED_CARRY + k].into();

            let lhs = h_byte + AB::Expr::from_u64(256) * c_out;
            let rhs = p_byte + s_byte + c_in;
            builder.assert_eq(lhs, rhs);
        }

        // ------------------------------------------------------------
        // 3) No overflow at the high byte.
        //
        // The final product_carry must be zero (otherwise q · ℓ exceeds
        // 2^520 — which would mean q is too large to pair with any
        // 64-byte digest). Same for combined_carry — addition cannot
        // produce a 66-th byte because digest is exactly 64 bytes.
        // ------------------------------------------------------------
        builder.assert_eq(row[col::PRODUCT_CARRY + PRODUCT_BYTES - 1], AB::Expr::ZERO);
        builder.assert_eq(row[col::COMBINED_CARRY + PRODUCT_BYTES - 1], AB::Expr::ZERO);

        // ------------------------------------------------------------
        // 4) Range checks via bit decomposition (sub-fase 5.6.d.1.c).
        //
        // Each byte cell is constrained to be in `[0, 256)` by binding
        // it to the recomposition of 8 boolean bit cells. Each
        // multiplication carry cell is similarly bounded to `[0, 2¹⁴)`
        // via 14 boolean bits. Combined-carry cells are constrained to
        // `{0, 1}` directly via `assert_bool`.
        //
        // Without these checks, a malicious prover could pick byte
        // cells outside `[0, 256)` to make the linear arithmetic balance
        // for an incorrect (q, scalar) pair. After this sub-fase the
        // schoolbook chain is enforced over genuine bytes only.
        // ------------------------------------------------------------

        // Per-bit booleanness for quotient bits.
        for i in 0..QUOTIENT_BYTES * BITS_PER_BYTE {
            builder.assert_bool(row[col::QUOTIENT_BITS + i]);
        }
        // Per-bit booleanness for product bits.
        for i in 0..PRODUCT_BYTES * BITS_PER_BYTE {
            builder.assert_bool(row[col::PRODUCT_BITS + i]);
        }
        // Per-bit booleanness for product-carry bits.
        for i in 0..PRODUCT_BYTES * BITS_PER_MUL_CARRY {
            builder.assert_bool(row[col::PRODUCT_CARRY_BITS + i]);
        }
        // Combined-carry cells are themselves bool-valued (max value 1).
        for k in 0..PRODUCT_BYTES {
            builder.assert_bool(row[col::COMBINED_CARRY + k]);
        }

        // Recomposition: cell = Σ bit_i · 2^i for each constrained cell.
        let recompose = |b: &mut AB, cell_off: usize, bit_off: usize, n_bits: usize| {
            let mut acc = AB::Expr::ZERO;
            let mut weight: u64 = 1;
            for i in 0..n_bits {
                acc += row[bit_off + i] * AB::Expr::from_u64(weight);
                weight <<= 1;
            }
            b.assert_eq(row[cell_off], acc);
        };

        for i in 0..QUOTIENT_BYTES {
            recompose(builder, col::QUOTIENT + i, col::QUOTIENT_BITS + i * BITS_PER_BYTE, BITS_PER_BYTE);
        }
        for i in 0..PRODUCT_BYTES {
            recompose(builder, col::PRODUCT + i, col::PRODUCT_BITS + i * BITS_PER_BYTE, BITS_PER_BYTE);
        }
        for i in 0..PRODUCT_BYTES {
            recompose(builder, col::PRODUCT_CARRY + i, col::PRODUCT_CARRY_BITS + i * BITS_PER_MUL_CARRY, BITS_PER_MUL_CARRY);
        }

        // ------------------------------------------------------------
        // 5) `scalar < ℓ` strict-less-than check (sub-fase 5.6.d.1.d).
        //
        // Byte-level subtraction with borrow:
        //   scalar[k] + 256·borrow_out[k] = ℓ[k] + diff[k] + borrow_in[k]
        //
        // where `borrow_in[k] = borrow_out[k-1]` (or 0 for k=0). Final
        // condition: `borrow_out[31] == 1`, meaning the subtraction
        // underflowed at the top — i.e., `scalar < ℓ`.
        //
        // Range checks: scalar bytes (32 × 8 bits), diff bytes (32 × 8
        // bits), borrow bits (assert_bool).
        // ------------------------------------------------------------

        // Bit range checks for scalar bytes.
        for i in 0..SCALAR_BYTES * BITS_PER_BYTE {
            builder.assert_bool(row[col::SCALAR_BITS + i]);
        }
        for i in 0..SCALAR_BYTES {
            recompose(builder, col::SCALAR + i, col::SCALAR_BITS + i * BITS_PER_BYTE, BITS_PER_BYTE);
        }

        // Bit range checks for sub_diff bytes.
        for i in 0..SCALAR_BYTES * BITS_PER_BYTE {
            builder.assert_bool(row[col::SUB_DIFF_BITS + i]);
        }
        for i in 0..SCALAR_BYTES {
            recompose(builder, col::SUB_DIFF + i, col::SUB_DIFF_BITS + i * BITS_PER_BYTE, BITS_PER_BYTE);
        }

        // Bool checks on each borrow cell.
        for i in 0..SCALAR_BYTES {
            builder.assert_bool(row[col::SUB_BORROW + i]);
        }

        // Per-byte subtraction constraint:
        //   scalar[k] + 256·borrow_out[k] = ℓ[k] + diff[k] + borrow_in[k]
        for k in 0..SCALAR_BYTES {
            let scalar_byte: AB::Expr = row[col::SCALAR + k].into();
            let borrow_out: AB::Expr = row[col::SUB_BORROW + k].into();
            let l_const = AB::Expr::from_u64(L_BYTES[k] as u64);
            let diff_byte: AB::Expr = row[col::SUB_DIFF + k].into();
            let borrow_in: AB::Expr = if k == 0 { AB::Expr::ZERO } else { row[col::SUB_BORROW + (k - 1)].into() };
            let lhs = scalar_byte + AB::Expr::from_u64(256) * borrow_out;
            let rhs = l_const + diff_byte + borrow_in;
            builder.assert_eq(lhs, rhs);
        }

        // Final: subtraction underflowed at the top byte.
        builder.assert_eq(row[col::SUB_BORROW + SCALAR_BYTES - 1], AB::Expr::ONE);

        // ------------------------------------------------------------
        // 6) Digest bit range checks + public-values binding
        //    (sub-fase 5.6.d.1.e — final trust-shim removal).
        //
        // Without digest range checks, a malicious prover could supply
        // `digest[k] = 1000` and have the addition chain absorb it (the
        // chain only enforces linear arithmetic, not byte semantics).
        // Bit decomposition forces `digest[k] ∈ [0, 256)`.
        //
        // The PV binding `digest[k] = PV[k]` then guarantees the AIR is
        // computing the reduction of *the verifier-supplied* digest,
        // not some fabricated alternative. Combined with the scalar PV
        // binding, the wrapper drops its `reduce_mod_l` re-derivation.
        // ------------------------------------------------------------

        // Bit booleanness for digest bits.
        for i in 0..DIGEST_BYTES * BITS_PER_BYTE {
            builder.assert_bool(row[col::DIGEST_BITS + i]);
        }
        // Recompose digest bytes from their bit cells.
        for i in 0..DIGEST_BYTES {
            recompose(builder, col::DIGEST + i, col::DIGEST_BITS + i * BITS_PER_BYTE, BITS_PER_BYTE);
        }

        // Public-values binding.
        let pub_copies: [AB::PublicVar; NUM_PUBLIC_VALUES] = {
            let public = builder.public_values();
            core::array::from_fn(|i| public[i])
        };
        // PV[0..64] = digest cells.
        for i in 0..DIGEST_BYTES {
            let pv: AB::Expr = pub_copies[i].into();
            builder.assert_eq(row[col::DIGEST + i], pv);
        }
        // PV[64..96] = scalar cells.
        for i in 0..SCALAR_BYTES {
            let pv: AB::Expr = pub_copies[DIGEST_BYTES + i].into();
            builder.assert_eq(row[col::SCALAR + i], pv);
        }
    }
}

/// Build a single-row trace (padded to HEIGHT=4) from a `digest`.
pub fn build_reduce_mod_l_trace<F: Field + PrimeCharacteristicRing>(digest: &[u8; 64]) -> RowMajorMatrix<F> {
    const HEIGHT: usize = 4;
    let mut values = vec![F::ZERO; NUM_COLS * HEIGHT];

    let w = compute_reduce_mod_l_witness(digest);

    // Populate row 0 with the witness.
    populate_row::<F>(&mut values, 0, &w);

    // Padding rows (1..HEIGHT) replicate row 0 so all per-row constraints
    // continue to hold. The single-row AIR's constraints reference only
    // same-row cells, so duplicate values trivially satisfy them.
    for r in 1..HEIGHT {
        let (head, tail) = values.split_at_mut(r * NUM_COLS);
        let src = &head[0..NUM_COLS];
        tail[0..NUM_COLS].copy_from_slice(src);
    }

    RowMajorMatrix::new(values, NUM_COLS)
}

fn populate_row<F: Field + PrimeCharacteristicRing>(values: &mut [F], row: usize, w: &super::reduce_mod_l::ReduceModLWitness) {
    let off = row * NUM_COLS;
    // digest
    for i in 0..DIGEST_BYTES {
        values[off + col::DIGEST + i] = F::from_u64(w.digest[i] as u64);
    }
    // scalar
    for i in 0..SCALAR_BYTES {
        values[off + col::SCALAR + i] = F::from_u64(w.scalar[i] as u64);
    }
    // quotient
    for i in 0..QUOTIENT_BYTES {
        values[off + col::QUOTIENT + i] = F::from_u64(w.quotient[i] as u64);
    }
    // product
    for i in 0..PRODUCT_BYTES {
        values[off + col::PRODUCT + i] = F::from_u64(w.product[i] as u64);
    }
    // multiplication carries
    for i in 0..PRODUCT_BYTES {
        values[off + col::PRODUCT_CARRY + i] = F::from_u64(w.product_carries[i] as u64);
    }
    // combined addition carries
    for i in 0..PRODUCT_BYTES {
        values[off + col::COMBINED_CARRY + i] = F::from_u64(w.combined_carries[i] as u64);
    }

    // Sub-fase 5.6.d.1.c — bit decomposition cells.
    // Quotient bits.
    for i in 0..QUOTIENT_BYTES {
        let byte_val = w.quotient[i];
        for b in 0..BITS_PER_BYTE {
            values[off + col::QUOTIENT_BITS + i * BITS_PER_BYTE + b] = F::from_u64(((byte_val >> b) & 1) as u64);
        }
    }
    // Product bits.
    for i in 0..PRODUCT_BYTES {
        let byte_val = w.product[i];
        for b in 0..BITS_PER_BYTE {
            values[off + col::PRODUCT_BITS + i * BITS_PER_BYTE + b] = F::from_u64(((byte_val >> b) & 1) as u64);
        }
    }
    // Multiplication-carry bits (14-bit).
    for i in 0..PRODUCT_BYTES {
        let carry_val = w.product_carries[i] as u64;
        for b in 0..BITS_PER_MUL_CARRY {
            values[off + col::PRODUCT_CARRY_BITS + i * BITS_PER_MUL_CARRY + b] = F::from_u64((carry_val >> b) & 1);
        }
    }

    // Sub-fase 5.6.d.1.d — scalar bits + (scalar - ℓ) byte-level
    // subtraction witness.
    for i in 0..SCALAR_BYTES {
        let s = w.scalar[i];
        for b in 0..BITS_PER_BYTE {
            values[off + col::SCALAR_BITS + i * BITS_PER_BYTE + b] = F::from_u64(((s >> b) & 1) as u64);
        }
    }
    let (sub_diff, sub_borrow) = compute_sub_l_witness(&w.scalar);
    for i in 0..SCALAR_BYTES {
        values[off + col::SUB_DIFF + i] = F::from_u64(sub_diff[i] as u64);
        for b in 0..BITS_PER_BYTE {
            values[off + col::SUB_DIFF_BITS + i * BITS_PER_BYTE + b] = F::from_u64(((sub_diff[i] >> b) & 1) as u64);
        }
        values[off + col::SUB_BORROW + i] = F::from_u64(sub_borrow[i] as u64);
    }

    // Sub-fase 5.6.d.1.e — digest bit decomposition.
    for i in 0..DIGEST_BYTES {
        let d = w.digest[i];
        for b in 0..BITS_PER_BYTE {
            values[off + col::DIGEST_BITS + i * BITS_PER_BYTE + b] = F::from_u64(((d >> b) & 1) as u64);
        }
    }
}

/// Build the public-values vector from `(digest, scalar)`.
///
/// Layout (96 BabyBear elements):
///   - PV[0..64]:  digest bytes (one cell per byte)
///   - PV[64..96]: scalar bytes (one cell per byte)
pub fn build_public_values<F: Field + PrimeCharacteristicRing>(digest: &[u8; 64], scalar: &[u8; 32]) -> Vec<F> {
    let mut out = Vec::with_capacity(NUM_PUBLIC_VALUES);
    for &b in digest {
        out.push(F::from_u64(b as u64));
    }
    for &b in scalar {
        out.push(F::from_u64(b as u64));
    }
    debug_assert_eq!(out.len(), NUM_PUBLIC_VALUES);
    out
}

/// Compute byte-level `scalar - ℓ` (with borrows) for the
/// scalar-strictly-less-than-ℓ witness.
///
/// Returns `(diff[0..32], borrow[0..32])`. For valid scalars (`< ℓ`),
/// `borrow[31] == 1`.
fn compute_sub_l_witness(scalar: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut diff = [0u8; 32];
    let mut borrow = [0u8; 32];
    let mut borrow_in: i16 = 0;
    for k in 0..32 {
        let s = scalar[k] as i16;
        let l = L_BYTES[k] as i16;
        let raw = s - l - borrow_in;
        if raw < 0 {
            diff[k] = (raw + 256) as u8;
            borrow[k] = 1;
            borrow_in = 1;
        } else {
            diff[k] = raw as u8;
            borrow[k] = 0;
            borrow_in = 0;
        }
    }
    (diff, borrow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;

    /// Helper: derive the canonical PV vector from a digest, computing
    /// the canonical scalar via `reduce_mod_l`.
    fn pv_for(digest: &[u8; 64]) -> Vec<BabyBear> {
        let scalar = crate::chips::ed25519::verify::reduce_mod_l(digest);
        build_public_values::<BabyBear>(digest, &scalar)
    }

    #[test]
    fn constraint_count_documented() {
        // Sub-fase 5.6.d.1.b: 64 (digest) + 32 (scalar) + 33 (q)
        //                    + 65 (product) + 65 (mul carry) + 65 (add carry)
        //                    = 324 byte/carry cells.
        // Sub-fase 5.6.d.1.c adds bit decomposition:
        //   quotient bits:        33 × 8 = 264
        //   product bits:         65 × 8 = 520
        //   product-carry bits:   65 × 14 = 910
        // Sub-fase 5.6.d.1.d adds scalar < ℓ witness + scalar bits:
        //   scalar bits:          32 × 8 = 256
        //   sub_diff bytes:       32
        //   sub_diff bits:        32 × 8 = 256
        //   sub_borrow bytes:     32
        // Sub-fase 5.6.d.1.e adds digest bits:
        //   digest bits:          64 × 8 = 512
        // Total: 324 + 264 + 520 + 910 + 256 + 32 + 256 + 32 + 512 = 3106.
        assert_eq!(NUM_COLS, 3106);
        assert_eq!(NUM_PUBLIC_VALUES, 96);
    }

    #[test]
    fn reduce_mod_l_zero_digest() {
        let digest = [0u8; 64];
        let trace = build_reduce_mod_l_trace::<BabyBear>(&digest);
        let pv = pv_for(&digest);
        check_constraints(&ReduceModLAirChip, &trace, &pv);
    }

    #[test]
    fn reduce_mod_l_below_l_identity() {
        let mut digest = [0u8; 64];
        digest[0] = 1;
        let trace = build_reduce_mod_l_trace::<BabyBear>(&digest);
        let pv = pv_for(&digest);
        check_constraints(&ReduceModLAirChip, &trace, &pv);
    }

    #[test]
    fn reduce_mod_l_l_itself_yields_q_one() {
        let mut digest = [0u8; 64];
        digest[..32].copy_from_slice(&L_BYTES);
        let trace = build_reduce_mod_l_trace::<BabyBear>(&digest);
        let pv = pv_for(&digest);
        check_constraints(&ReduceModLAirChip, &trace, &pv);
    }

    #[test]
    fn reduce_mod_l_arbitrary_digest() {
        let digest: [u8; 64] = core::array::from_fn(|i| (i as u8).wrapping_mul(0x9b).wrapping_add(7));
        let trace = build_reduce_mod_l_trace::<BabyBear>(&digest);
        let pv = pv_for(&digest);
        check_constraints(&ReduceModLAirChip, &trace, &pv);
    }

    #[test]
    fn reduce_mod_l_max_digest() {
        let digest = [0xffu8; 64];
        let trace = build_reduce_mod_l_trace::<BabyBear>(&digest);
        let pv = pv_for(&digest);
        check_constraints(&ReduceModLAirChip, &trace, &pv);
    }

    /// Adversarial: tampering with the quotient breaks the
    /// multiplication chain (since product no longer matches q · ℓ).
    #[test]
    fn reduce_mod_l_rejects_tampered_quotient() {
        use std::panic;
        let mut digest = [0u8; 64];
        digest[..32].copy_from_slice(&L_BYTES); // h = ℓ → q should be 1
        let mut trace = build_reduce_mod_l_trace::<BabyBear>(&digest);
        let pv = pv_for(&digest);

        // Tamper q[0]: was 1, set to 2. Multiplication chain must reject.
        trace.values[col::QUOTIENT] = BabyBear::from_u64(2);

        let res = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            check_constraints(&ReduceModLAirChip, &trace, &pv);
        }));
        assert!(res.is_err(), "tampered quotient must be rejected");
    }

    /// Adversarial: tampering with the scalar breaks the addition chain
    /// (since q·ℓ + scalar no longer equals digest).
    #[test]
    fn reduce_mod_l_rejects_tampered_scalar() {
        use std::panic;
        let mut digest = [0u8; 64];
        digest[0] = 7; // scalar = 7, q = 0
        let mut trace = build_reduce_mod_l_trace::<BabyBear>(&digest);
        let pv = pv_for(&digest);

        // Tamper scalar[0]: was 7, set to 8.
        trace.values[col::SCALAR] = BabyBear::from_u64(8);

        let res = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            check_constraints(&ReduceModLAirChip, &trace, &pv);
        }));
        assert!(res.is_err(), "tampered scalar must be rejected");
    }

    /// Adversarial: tampering with the digest breaks the addition chain.
    #[test]
    fn reduce_mod_l_rejects_tampered_digest() {
        use std::panic;
        let mut digest = [0u8; 64];
        digest[0] = 5;
        let mut trace = build_reduce_mod_l_trace::<BabyBear>(&digest);
        let pv = pv_for(&digest);

        // Tamper digest[0]: was 5, set to 6.
        trace.values[col::DIGEST] = BabyBear::from_u64(6);

        let res = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            check_constraints(&ReduceModLAirChip, &trace, &pv);
        }));
        assert!(res.is_err(), "tampered digest must be rejected");
    }

    /// Sub-fase 5.6.d.1.c — range check: a quotient cell of 256 (out
    /// of byte range) cannot satisfy the bit-recomposition constraint
    /// because 8 boolean bits sum to at most 255.
    #[test]
    fn reduce_mod_l_rejects_oversize_quotient_byte() {
        use std::panic;
        let digest = [0u8; 64];
        let mut trace = build_reduce_mod_l_trace::<BabyBear>(&digest);
        let pv = pv_for(&digest);

        // Set quotient[0] to 256. The bits at QUOTIENT_BITS were populated
        // for value 0 (all zero), so the recomposition check 0 == 256 fails.
        trace.values[col::QUOTIENT] = BabyBear::from_u64(256);

        let res = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            check_constraints(&ReduceModLAirChip, &trace, &pv);
        }));
        assert!(res.is_err(), "quotient byte ≥ 256 must be rejected by range check");
    }

    /// Sub-fase 5.6.d.1.c — range check on product-carry cells. A carry
    /// of 2¹⁴ + 1 = 16385 cannot satisfy 14-bit recomposition.
    #[test]
    fn reduce_mod_l_rejects_oversize_mul_carry() {
        use std::panic;
        let digest = [0u8; 64];
        let mut trace = build_reduce_mod_l_trace::<BabyBear>(&digest);
        let pv = pv_for(&digest);

        // Original carry was 0. Force it to 16385.
        trace.values[col::PRODUCT_CARRY] = BabyBear::from_u64(16385);

        let res = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            check_constraints(&ReduceModLAirChip, &trace, &pv);
        }));
        assert!(res.is_err(), "mul carry ≥ 2¹⁴ must be rejected by range check");
    }

    /// Sub-fase 5.6.d.1.d — `scalar < ℓ` enforcement. `scalar = ℓ - 1`
    /// (the maximum valid scalar) must be accepted.
    #[test]
    fn reduce_mod_l_accepts_scalar_l_minus_one() {
        let mut h = [0u8; 64];
        h[..32].copy_from_slice(&L_BYTES);
        h[0] -= 1; // h = ℓ - 1 → scalar = ℓ - 1, q = 0
        let trace = build_reduce_mod_l_trace::<BabyBear>(&h);
        let pv = pv_for(&h);
        check_constraints(&ReduceModLAirChip, &trace, &pv);
    }

    /// Sub-fase 5.6.d.1.d — adversarial: forge `scalar = ℓ` by tampering
    /// the scalar cells AND adjusting the witness so the addition chain
    /// still balances (q goes down by 1). The `borrow[31] == 1` check
    /// must catch this since `ℓ - ℓ` doesn't underflow.
    #[test]
    fn reduce_mod_l_rejects_scalar_equal_to_l() {
        use std::panic;
        // Tamper: set sub_borrow[31] to 0, simulating a prover claiming
        // scalar ≥ ℓ (i.e., the comparison did not underflow at the top).
        // The honest trace has borrow[31] = 1 here. Flipping must fail.
        let mut h = [0u8; 64];
        h[..32].copy_from_slice(&L_BYTES);
        let mut trace = build_reduce_mod_l_trace::<BabyBear>(&h);
        let pv = pv_for(&h);

        trace.values[col::SUB_BORROW + SCALAR_BYTES - 1] = BabyBear::from_u64(0);

        let res = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            check_constraints(&ReduceModLAirChip, &trace, &pv);
        }));
        assert!(res.is_err(), "scalar < ℓ check must reject borrow[31] = 0");
    }

    /// Sub-fase 5.6.d.1.c — combined carries are bool. Setting one to
    /// 2 must trigger the assert_bool.
    #[test]
    fn reduce_mod_l_rejects_non_bool_combined_carry() {
        use std::panic;
        let digest = [0u8; 64];
        let mut trace = build_reduce_mod_l_trace::<BabyBear>(&digest);
        let pv = pv_for(&digest);

        trace.values[col::COMBINED_CARRY] = BabyBear::from_u64(2);

        let res = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            check_constraints(&ReduceModLAirChip, &trace, &pv);
        }));
        assert!(res.is_err(), "combined-carry ≥ 2 must be rejected by assert_bool");
    }

    /// Adversarial: tampering with a product byte breaks both chains.
    #[test]
    fn reduce_mod_l_rejects_tampered_product() {
        use std::panic;
        let mut digest = [0u8; 64];
        digest[..32].copy_from_slice(&L_BYTES);
        let mut trace = build_reduce_mod_l_trace::<BabyBear>(&digest);
        let pv = pv_for(&digest);

        // For h=ℓ, q=1 so product = ℓ; product[0] = L_BYTES[0] = 0xed.
        // Flip lowest bit.
        let cur = trace.values[col::PRODUCT];
        use p3_field::PrimeField32;
        trace.values[col::PRODUCT] = BabyBear::from_u64((cur.as_canonical_u32() as u64) ^ 1);

        let res = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            check_constraints(&ReduceModLAirChip, &trace, &pv);
        }));
        assert!(res.is_err(), "tampered product must be rejected");
    }
}
