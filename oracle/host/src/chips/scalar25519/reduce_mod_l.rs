//! `scalar25519::reduce_mod_l` — witness foundation for the
//! mod-ℓ reduction AIR (sub-fase 5.6.d.1).
//!
//! Computes the reduction `scalar = h mod ℓ` for an arbitrary 64-byte
//! little-endian integer `h`, plus the **quotient** `q` such that
//!
//! ```text
//! h = scalar + q · ℓ      (unsigned 512-bit integer arithmetic)
//! 0 ≤ scalar < ℓ
//! q ≥ 0
//! ```
//!
//! The quotient is what the AIR will witness — the chip's central
//! constraint will be the byte-level schoolbook validation of
//! `q · ℓ + scalar = h`. The reduction itself is computed here in
//! pure Rust, mirroring `chips::ed25519::verify::reduce_mod_l`.
//!
//! ## Sizing
//!
//! - `h`: 64 bytes (≤ 2⁵¹²)
//! - `ℓ`: 32 bytes (≈ 2²⁵²)
//! - `q ≤ ⌊2⁵¹² / ℓ⌋ < 2²⁶¹`, so `q` fits in 33 bytes
//! - `q · ℓ`: up to 2⁵¹², so 65 bytes (one extra to absorb potential carry)
//! - `scalar`: 32 bytes
//!
//! All values are stored as little-endian byte arrays. Future AIR work
//! (5.6.d.1.b…e) consumes these LE byte arrays directly as 8-bit chunks.

use crate::chips::ed25519::verify::reduce_mod_l;

/// Curve25519 group order ℓ as 32 little-endian bytes.
/// `ℓ = 2²⁵² + 27742317777372353535851937790883648493`.
pub const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Number of bytes in the witnessed quotient.
///
/// `q ≤ ⌊(2⁵¹² - 1) / ℓ⌋ < 2²⁶¹`, so 33 bytes (264 bits) is always
/// sufficient. The 33rd byte (`q[32]`) carries at most 5 bits of value.
pub const QUOTIENT_BYTES: usize = 33;

/// Number of bytes in the witnessed product `q · ℓ`.
///
/// Worst case `q · ℓ ≈ h ≤ 2⁵¹² - 1`, so 65 bytes is enough (the upper
/// limit is technically 2⁵¹² which is exactly 64 bytes, but allowing
/// 65 simplifies the schoolbook carry chain).
pub const PRODUCT_BYTES: usize = 65;

/// Witness for one reduce-mod-ℓ proof.
///
/// All byte arrays are little-endian. The future AIR will treat each
/// byte as one BabyBear cell (values `0..=255` fit comfortably in the
/// 31-bit field).
#[derive(Debug, Clone)]
pub struct ReduceModLWitness {
    /// Input — the 64-byte SHA-512 digest viewed as a little-endian integer.
    pub digest: [u8; 64],
    /// Output — the 32-byte canonical scalar in `[0, ℓ)`.
    pub scalar: [u8; 32],
    /// Witness quotient, 33 bytes (LE).
    pub quotient: [u8; QUOTIENT_BYTES],
    /// Witness product `q · ℓ`, 65 bytes (LE). Computed via schoolbook
    /// for chip cross-validation.
    pub product: [u8; PRODUCT_BYTES],
    /// Per-position byte-level multiplication carries (65 entries). The
    /// carry-out at position `k` is the integer `(sum_at_k) >> 8`, where
    /// `sum_at_k = Σ_{i+j=k} q[i]·ℓ[j] + carry_in[k]`.
    /// The byte-position equation in the AIR will be:
    /// `product[k] + 256 · carry_out[k] = sum_at_k`.
    pub product_carries: [u32; PRODUCT_BYTES],
    /// Per-position addition carries for `q · ℓ + scalar = h`.
    /// `combined_carry[k]` is the carry-out at byte position `k` of the
    /// final addition chain.
    pub combined_carries: [u8; PRODUCT_BYTES],
}

/// Compute the witness for `h mod ℓ`.
///
/// Cross-validated against `chips::ed25519::verify::reduce_mod_l` (the
/// existing canonical witness function used by SHA-512 → scalar in the
/// ed25519 verifier path).
pub fn compute_reduce_mod_l_witness(digest: &[u8; 64]) -> ReduceModLWitness {
    let scalar = reduce_mod_l(digest);

    // Compute the quotient: q = (h - scalar) / ℓ via schoolbook subtraction
    // followed by division. Since (h - scalar) is exactly q · ℓ and ℓ is
    // ≈ 2²⁵², the quotient cleanly recovers via long division.
    let q = compute_quotient(digest, &scalar);

    // Compute the product q · ℓ via byte-level schoolbook, capturing the
    // per-position carry sequence the AIR will commit to.
    let (product, product_carries) = schoolbook_q_times_l(&q);

    // Compute combined addition carries for q·ℓ + scalar = h.
    // (We don't need the byte-level addition output — it must equal the
    // padded digest — but the AIR will use the carry chain.)
    let combined_carries = combined_addition_carries(&product, &scalar, digest);

    ReduceModLWitness { digest: *digest, scalar, quotient: q, product, product_carries, combined_carries }
}

/// Compute `q = (h - scalar) / ℓ`, byte-level. Returns `q` as 33-byte LE.
fn compute_quotient(h: &[u8; 64], scalar: &[u8; 32]) -> [u8; QUOTIENT_BYTES] {
    // First subtract scalar from h (h is 64 bytes, scalar is 32). The
    // result is q · ℓ — a non-negative 64-byte integer.
    let mut diff = [0u8; 64];
    let mut borrow: i16 = 0;
    for i in 0..64 {
        let s_byte = if i < 32 { scalar[i] as i16 } else { 0 };
        let d = (h[i] as i16) - s_byte - borrow;
        if d < 0 {
            diff[i] = (d + 256) as u8;
            borrow = 1;
        } else {
            diff[i] = d as u8;
            borrow = 0;
        }
    }
    debug_assert_eq!(borrow, 0, "scalar > h impossible (scalar = h mod ℓ ≤ h)");

    // Now `diff = q · ℓ`. Divide by ℓ via repeated subtraction at
    // increasing bit shifts (similar to `reduce_mod_l`'s shift-and-
    // subtract loop, but in reverse: we extract the quotient bits).
    let mut q = [0u8; QUOTIENT_BYTES];
    let mut acc = diff.to_vec();
    // Extend acc to 65 bytes so shifts up to 260 don't overflow.
    acc.push(0);

    // Quotient is at most 261 bits, so iterate from shift 260 down to 0.
    // At each shift we test whether (ℓ << shift) ≤ acc; if so subtract
    // and set the corresponding bit of q.
    for shift in (0..=260).rev() {
        if le_bytes_ge_shifted(&acc, &L_BYTES, shift) {
            sub_bytes_shifted(&mut acc, &L_BYTES, shift);
            // Set bit `shift` of q.
            let byte_idx = shift / 8;
            let bit = shift % 8;
            q[byte_idx] |= 1u8 << bit;
        }
    }

    // After the loop, `acc` should be zero (we've fully divided out ℓ).
    debug_assert!(acc.iter().all(|&b| b == 0), "quotient extraction left a non-zero remainder");
    q
}

/// `acc >= b << shift` for LE byte buffers (`b` exactly 32 bytes,
/// `acc` arbitrary length). Returns `false` if shifting `b` would
/// produce a value larger than `acc` could hold.
fn le_bytes_ge_shifted(acc: &[u8], b: &[u8; 32], shift: usize) -> bool {
    let mut shifted = vec![0u8; acc.len()];
    let byte_shift = shift / 8;
    let bit_shift = shift % 8;
    for (i, &v) in b.iter().enumerate() {
        let dst = i + byte_shift;
        if dst >= shifted.len() {
            if v != 0 {
                return false;
            }
            continue;
        }
        let lo = (v as u16) << bit_shift;
        shifted[dst] = shifted[dst].wrapping_add((lo & 0xff) as u8);
        if dst + 1 < shifted.len() {
            shifted[dst + 1] = shifted[dst + 1].wrapping_add((lo >> 8) as u8);
        } else if (lo >> 8) != 0 {
            return false;
        }
    }
    !lt_le_bytes(acc, &shifted)
}

/// Compare two LE byte buffers of identical length: `a < b`.
fn lt_le_bytes(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    for i in (0..a.len()).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// Subtract `b << shift` from `acc` in place. Caller guarantees
/// `acc >= b << shift` (panics in debug otherwise).
fn sub_bytes_shifted(acc: &mut [u8], b: &[u8; 32], shift: usize) {
    let mut shifted = vec![0u8; acc.len()];
    let byte_shift = shift / 8;
    let bit_shift = shift % 8;
    for (i, &v) in b.iter().enumerate() {
        let dst = i + byte_shift;
        if dst >= shifted.len() {
            break;
        }
        let lo = (v as u16) << bit_shift;
        shifted[dst] = shifted[dst].wrapping_add((lo & 0xff) as u8);
        if dst + 1 < shifted.len() {
            shifted[dst + 1] = shifted[dst + 1].wrapping_add((lo >> 8) as u8);
        }
    }

    let mut borrow: i16 = 0;
    for i in 0..acc.len() {
        let d = (acc[i] as i16) - (shifted[i] as i16) - borrow;
        if d < 0 {
            acc[i] = (d + 256) as u8;
            borrow = 1;
        } else {
            acc[i] = d as u8;
            borrow = 0;
        }
    }
    debug_assert_eq!(borrow, 0);
}

/// Schoolbook multiplication `product = q · ℓ` byte-level.
///
/// At each output position `k ∈ 0..PRODUCT_BYTES`:
///   `sum_at_k = (Σ_{i+j=k, 0≤i<33, 0≤j<32} q[i]·ℓ[j]) + carry_in[k]`
///   `product[k] = sum_at_k mod 256`
///   `carry_out[k] = sum_at_k >> 8`
///
/// Returns `(product, carry_out)` arrays. The maximum value of any
/// `sum_at_k` is bounded by `33 · 255² + max_carry ≤ 2.15M + ε`,
/// which fits in BabyBear (`< 2³¹`). `carry_out[k]` is bounded by
/// `≈ 8400 < 2¹⁴`.
fn schoolbook_q_times_l(q: &[u8; QUOTIENT_BYTES]) -> ([u8; PRODUCT_BYTES], [u32; PRODUCT_BYTES]) {
    let mut product = [0u8; PRODUCT_BYTES];
    let mut carries = [0u32; PRODUCT_BYTES];
    let mut carry_in: u32 = 0;
    for k in 0..PRODUCT_BYTES {
        let mut sum: u32 = carry_in;
        // i ranges over q indices, j = k - i over ℓ indices.
        for i in 0..QUOTIENT_BYTES {
            if i > k {
                break;
            }
            let j = k - i;
            if j >= 32 {
                continue;
            }
            sum += (q[i] as u32) * (L_BYTES[j] as u32);
        }
        product[k] = (sum & 0xff) as u8;
        carries[k] = sum >> 8;
        carry_in = carries[k];
    }
    debug_assert!(carry_in == 0, "schoolbook overflow — q exceeds 33 bytes worth?");
    (product, carries)
}

/// Compute carry chain of `product + scalar = digest` over `PRODUCT_BYTES`
/// LE byte positions (where `digest` is 64 bytes, treat extra position
/// as zero; `scalar` is 32 bytes).
///
/// Each `combined_carries[k]` is `(sum_at_k) >> 8` of the addition
/// position. AIR constraint will enforce `digest[k] (or 0) + 256·c_out
/// = product[k] + scalar[k] (or 0) + c_in`.
fn combined_addition_carries(product: &[u8; PRODUCT_BYTES], scalar: &[u8; 32], digest: &[u8; 64]) -> [u8; PRODUCT_BYTES] {
    let mut carries = [0u8; PRODUCT_BYTES];
    let mut carry_in: u16 = 0;
    for k in 0..PRODUCT_BYTES {
        let s_byte = if k < 32 { scalar[k] as u16 } else { 0 };
        let p_byte = product[k] as u16;
        let h_byte = if k < 64 { digest[k] as u16 } else { 0 };
        let sum = p_byte + s_byte + carry_in;
        // Constraint: `h_byte + 256·carry_out = sum`
        let c_out = (sum.wrapping_sub(h_byte)) / 256;
        // (c_out fits in u8 since sum ≤ 2·255 + 1 = 511 and h_byte ≤ 255,
        // so c_out ∈ {0, 1} for the addition.)
        carries[k] = c_out as u8;
        carry_in = c_out;
    }
    debug_assert!(carry_in == 0, "addition overflow — product + scalar > 2^520?");
    carries
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The witness function and the canonical `reduce_mod_l` agree.
    #[test]
    fn witness_matches_canonical_for_zero_digest() {
        let w = compute_reduce_mod_l_witness(&[0u8; 64]);
        assert_eq!(w.scalar, [0u8; 32], "0 mod ℓ = 0");
        assert_eq!(w.quotient, [0u8; QUOTIENT_BYTES], "quotient is zero for digest=0");
        assert_eq!(w.product, [0u8; PRODUCT_BYTES], "product is zero");
    }

    #[test]
    fn witness_for_l_itself_yields_q_one() {
        // h = ℓ (padded to 64 bytes) → scalar = 0, q = 1.
        let mut h = [0u8; 64];
        h[..32].copy_from_slice(&L_BYTES);
        let w = compute_reduce_mod_l_witness(&h);
        assert_eq!(w.scalar, [0u8; 32]);
        assert_eq!(w.quotient[0], 1);
        for i in 1..QUOTIENT_BYTES {
            assert_eq!(w.quotient[i], 0, "quotient[{i}] should be 0 for h = ℓ");
        }
    }

    #[test]
    fn witness_below_l_is_identity() {
        // h < ℓ → scalar = h, q = 0.
        let mut h = [0u8; 64];
        h[0] = 1;
        let w = compute_reduce_mod_l_witness(&h);
        assert_eq!(w.quotient, [0u8; QUOTIENT_BYTES]);
        assert_eq!(w.scalar[0], 1);
        for i in 1..32 {
            assert_eq!(w.scalar[i], 0);
        }
    }

    /// The fundamental invariant: `q · ℓ + scalar = h`.
    #[test]
    fn invariant_q_times_l_plus_scalar_equals_h() {
        let test_digests: &[[u8; 64]] = &[
            [0u8; 64],
            core::array::from_fn(|i| (i as u8).wrapping_mul(13)),
            core::array::from_fn(|i| (i as u8).wrapping_mul(0x9b).wrapping_add(7)),
            [0xffu8; 64],
            // ℓ - 1 (max in-range scalar)
            {
                let mut h = [0u8; 64];
                h[..32].copy_from_slice(&L_BYTES);
                h[0] -= 1; // 0xed - 1
                h
            },
        ];
        for digest in test_digests {
            let w = compute_reduce_mod_l_witness(digest);

            // Reconstruct h from product + scalar (byte-level addition).
            let mut reconstructed = [0u8; 65];
            let mut carry: u16 = 0;
            for k in 0..PRODUCT_BYTES {
                let s = if k < 32 { w.scalar[k] as u16 } else { 0 };
                let p = w.product[k] as u16;
                let sum = s + p + carry;
                reconstructed[k] = (sum & 0xff) as u8;
                carry = sum >> 8;
            }
            // Compare against digest padded to 65 bytes.
            for i in 0..64 {
                assert_eq!(reconstructed[i], digest[i], "byte {i} mismatch: q·ℓ + scalar != h");
            }
            assert_eq!(reconstructed[64], 0, "high byte should be zero");
        }
    }

    /// Cross-validation: the witness's `scalar` matches what
    /// `reduce_mod_l` produces.
    #[test]
    fn witness_scalar_matches_reduce_mod_l() {
        for seed in [0u8, 1, 13, 42, 0xff, 0x9b] {
            let digest: [u8; 64] = core::array::from_fn(|i| seed.wrapping_mul(i as u8 + 1));
            let w = compute_reduce_mod_l_witness(&digest);
            let canonical = crate::chips::ed25519::verify::reduce_mod_l(&digest);
            assert_eq!(w.scalar, canonical, "scalar mismatch for seed {seed}");
        }
    }

    /// `scalar < ℓ` for all valid witness outputs.
    #[test]
    fn witness_scalar_strictly_less_than_l() {
        for seed in [0u8, 1, 13, 42, 0xff] {
            let digest: [u8; 64] = core::array::from_fn(|i| seed.wrapping_mul((i as u8).wrapping_add(1)));
            let w = compute_reduce_mod_l_witness(&digest);
            assert!(lt_le_bytes(&w.scalar, &L_BYTES), "scalar ≥ ℓ for seed {seed}");
        }
    }

    /// Schoolbook multiplication carries match what byte-level
    /// arithmetic produces at each position.
    #[test]
    fn schoolbook_carries_self_consistent() {
        // Build a non-trivial q with ~half the bytes set.
        let q: [u8; QUOTIENT_BYTES] = core::array::from_fn(|i| (i as u8).wrapping_mul(0x33));
        let (product, carries) = schoolbook_q_times_l(&q);

        // Recompute and verify `product[k] + 256·carry_out[k] = sum_at_k`.
        let mut carry_in: u32 = 0;
        for k in 0..PRODUCT_BYTES {
            let mut sum_at_k = carry_in;
            for i in 0..QUOTIENT_BYTES {
                if i > k {
                    break;
                }
                let j = k - i;
                if j >= 32 {
                    continue;
                }
                sum_at_k += (q[i] as u32) * (L_BYTES[j] as u32);
            }
            assert_eq!((product[k] as u32) + 256 * carries[k], sum_at_k, "schoolbook constraint failed at byte {k}");
            carry_in = carries[k];
        }
    }
}
