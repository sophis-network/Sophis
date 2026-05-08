//! Top-level Ed25519 signature verification (RFC 8032 §5.1.7).
//!
//! Given:
//!   - A: 32-byte compressed public key
//!   - M: arbitrary-length message
//!   - signature = R || S, 64 bytes total (R compressed point, S scalar LE)
//!
//! Accept iff:
//!   1. A and R both decompress to valid curve points.
//!   2. S < ℓ (group order).
//!   3. `[S] · B == R + [h] · A` where `h = SHA-512(R || A || M) mod ℓ`
//!      and `B` is the standard basepoint.
//!
//! ## Status (sub-phase 5.2.1.7)
//!
//! Witness function only. The full AIR (top-level integration) composes
//! every chip in the field25519 / sha512 / ed25519 stack — the chip
//! footprint is by far the largest of the project. It lands as the final
//! step of the ed25519 AIR work, after every constituent sub-phase chip
//! has been individually validated.

use super::decompress::decompress;
use super::point::{ExtendedPoint, point_add, to_affine};
use super::scalar_mul::scalar_mul;
use crate::chips::field25519::arith::{field_sub, field_zero};
use crate::chips::sha512::sha512;

/// Edwards25519 group order `ℓ = 2²⁵² + 27742317777372353535851937790883648493`.
///
/// In hex (BE): `0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED`.
///
/// Stored as 32 little-endian bytes (the canonical representation used
/// for scalar arithmetic and the `S < ℓ` check).
pub const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// The Ed25519 basepoint `B`, decompressed from the canonical encoding
/// `[0x58, 0x66 × 31]`.
pub fn basepoint() -> ExtendedPoint {
    let mut compressed = [0x66u8; 32];
    compressed[0] = 0x58;
    decompress(&compressed).expect("basepoint encoding must decompress")
}

/// Edwards-curve point negation in extended coordinates: `-P = (-X, Y, Z, -T)`.
pub fn point_negate(p: &ExtendedPoint) -> ExtendedPoint {
    ExtendedPoint {
        x: field_sub(&field_zero(), &p.x),
        y: p.y.clone(),
        z: p.z.clone(),
        t: field_sub(&field_zero(), &p.t),
    }
}

/// Compare two arbitrary-length little-endian unsigned integers.
/// Returns `true` iff `a < b`.
fn lt_le_bytes(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    for i in (0..a.len()).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// `s < ℓ` check for a 32-byte scalar.
pub fn scalar_lt_l(s: &[u8; 32]) -> bool {
    lt_le_bytes(s, &L_BYTES)
}

/// Subtract `b << shift` from `acc` in place (LE byte buffer).
/// Caller guarantees `acc >= b << shift`.
fn sub_shifted(acc: &mut [u8], b: &[u8; 32], shift: usize) {
    // Materialize `b << shift` into a 65-byte buffer (covers shifts up to 260).
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
        // Carry into next byte
        if dst + 1 < shifted.len() {
            shifted[dst + 1] = shifted[dst + 1].wrapping_add((lo >> 8) as u8);
        }
    }

    let mut borrow: i16 = 0;
    for i in 0..acc.len() {
        let diff = (acc[i] as i16) - (shifted[i] as i16) - borrow;
        if diff < 0 {
            acc[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            acc[i] = diff as u8;
            borrow = 0;
        }
    }
    debug_assert_eq!(borrow, 0, "sub_shifted underflow — caller violated precondition");
}

/// Compare `acc >= b << shift` (LE byte buffers, `b` is 32 bytes).
fn ge_shifted(acc: &[u8], b: &[u8; 32], shift: usize) -> bool {
    let byte_shift = shift / 8;
    let bit_shift = shift % 8;
    // Walk from the high byte of `acc` down. Compare against the corresponding
    // byte of `b << shift`. Materialize the shifted value lazily.
    let mut shifted = vec![0u8; acc.len()];
    for (i, &v) in b.iter().enumerate() {
        let dst = i + byte_shift;
        if dst >= shifted.len() {
            // Any non-zero high byte past the buffer means b << shift > acc.
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

/// Reduce a 64-byte little-endian integer modulo ℓ. Output is a 32-byte
/// LE value strictly less than ℓ.
///
/// Algorithm: iterative shift-and-subtract from the highest possible
/// shift down to 0. ℓ ≈ 2²⁵², so shifts 0..=260 cover any 64-byte input.
pub fn reduce_mod_l(h: &[u8; 64]) -> [u8; 32] {
    let mut acc = h.to_vec();
    for shift in (0..=260).rev() {
        if ge_shifted(&acc, &L_BYTES, shift) {
            sub_shifted(&mut acc, &L_BYTES, shift);
        }
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&acc[..32]);
    result
}

/// Top-level Ed25519 verify. Returns `true` iff the signature is valid
/// for the given public key and message.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let r_bytes: [u8; 32] = signature[0..32].try_into().unwrap();
    let s_bytes: [u8; 32] = signature[32..64].try_into().unwrap();

    // 1. Decompress A and R.
    let a = match decompress(public_key) {
        Some(p) => p,
        None => return false,
    };
    let r = match decompress(&r_bytes) {
        Some(p) => p,
        None => return false,
    };

    // 2. S < ℓ.
    if !scalar_lt_l(&s_bytes) {
        return false;
    }

    // 3. h = SHA-512(R || A || M) reduced mod ℓ.
    let mut hash_input = Vec::with_capacity(64 + message.len());
    hash_input.extend_from_slice(&r_bytes);
    hash_input.extend_from_slice(public_key);
    hash_input.extend_from_slice(message);
    let h_full = sha512(&hash_input);
    let h_reduced = reduce_mod_l(&h_full);

    // 4. Check [S] · B == R + [h] · A.
    let s_b = scalar_mul(&s_bytes, &basepoint());
    let h_a = scalar_mul(&h_reduced, &a);
    let r_plus_h_a = point_add(&r, &h_a);

    let (lx, ly) = to_affine(&s_b);
    let (rx, ry) = to_affine(&r_plus_h_a);
    lx == rx && ly == ry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chips::field25519::arith::{field_one, field_zero};

    #[test]
    fn basepoint_decompresses_with_z_one() {
        let b = basepoint();
        assert_eq!(b.z, field_one(), "basepoint z should be 1 (decompressed canonical form)");
    }

    #[test]
    fn point_negate_neutral_is_neutral() {
        let n = ExtendedPoint::neutral();
        let neg_n = point_negate(&n);
        // -O = (-0, 1, 1, -0) = (0, 1, 1, 0) = O
        assert_eq!(neg_n.y, field_one());
        let (x, y) = to_affine(&neg_n);
        assert_eq!(x, field_zero());
        assert_eq!(y, field_one());
    }

    #[test]
    fn point_negate_double_is_identity() {
        let b = basepoint();
        let neg_b = point_negate(&b);
        let neg_neg_b = point_negate(&neg_b);
        assert_eq!(neg_neg_b.x, b.x);
        assert_eq!(neg_neg_b.y, b.y);
        assert_eq!(neg_neg_b.t, b.t);
    }

    #[test]
    fn scalar_lt_l_basic() {
        let zero = [0u8; 32];
        assert!(scalar_lt_l(&zero));
        // ℓ - 1 must be < ℓ.
        let mut l_minus_1 = L_BYTES;
        l_minus_1[0] -= 1;
        assert!(scalar_lt_l(&l_minus_1));
        // ℓ itself is NOT < ℓ.
        assert!(!scalar_lt_l(&L_BYTES));
        // Anything ≥ 2²⁵³ is way above ℓ.
        let mut huge = [0u8; 32];
        huge[31] = 0x80;
        assert!(!scalar_lt_l(&huge));
    }

    #[test]
    fn reduce_mod_l_zero_is_zero() {
        let r = reduce_mod_l(&[0u8; 64]);
        assert_eq!(r, [0u8; 32]);
    }

    #[test]
    fn reduce_mod_l_below_l_is_identity() {
        // 32-byte value < ℓ should pass through unchanged when zero-extended.
        let mut h = [0u8; 64];
        h[0] = 0xab;
        h[1] = 0xcd;
        h[10] = 0xff;
        let r = reduce_mod_l(&h);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&h[..32]);
        assert_eq!(r, expected);
    }

    #[test]
    fn reduce_mod_l_l_itself_is_zero() {
        let mut h = [0u8; 64];
        h[..32].copy_from_slice(&L_BYTES);
        let r = reduce_mod_l(&h);
        assert_eq!(r, [0u8; 32], "ℓ should reduce to 0");
    }

    #[test]
    fn reduce_mod_l_2l_is_zero() {
        // 2ℓ as 64-byte LE.
        let mut h = [0u8; 64];
        let mut carry = 0u16;
        for i in 0..32 {
            let v = 2 * (L_BYTES[i] as u16) + carry;
            h[i] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            h[32] = carry as u8;
        }
        let r = reduce_mod_l(&h);
        assert_eq!(r, [0u8; 32], "2ℓ should reduce to 0");
    }

    /// RFC 8032 Appendix A.4 Test 1 — empty message signature.
    ///
    /// Public key, signature, and message all from the RFC. Verifying
    /// against the basepoint+SHA-512+scalar_mul stack we just built
    /// validates the entire ed25519 chain end-to-end.
    ///
    /// **Slow test:** ~30 seconds in debug builds because each scalar_mul
    /// runs 250+ doublings, each doubling = 9 field_muls, each field_mul
    /// = full mul→carry_fold→limb_assembly→mod_p pipeline. Marked
    /// `#[ignore]` so day-to-day `cargo test` stays fast; run with
    /// `cargo test --ignored` to exercise it.
    #[test]
    #[ignore = "slow (~30s); the full ed25519 stack runs ~7000 field_muls"]
    fn rfc8032_test_1_empty_message_verifies() {
        let public_key: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
            0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
        ];
        let signature: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
            0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
            0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
            0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];
        let message: &[u8] = b"";
        assert!(verify(&public_key, message, &signature), "RFC 8032 Test 1 must verify");
    }

    #[test]
    #[ignore = "slow; depends on rfc8032_test_1_empty_message_verifies setup"]
    fn rfc8032_test_1_with_tampered_message_rejects() {
        // Same key/signature as Test 1 but with a tampered message — must reject.
        let public_key: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
            0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
        ];
        let signature: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
            0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
            0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
            0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];
        let message: &[u8] = b"x"; // not empty
        assert!(!verify(&public_key, message, &signature), "tampered message must reject");
    }

    #[test]
    fn verify_rejects_invalid_pubkey() {
        // All-bits-set public key likely doesn't decompress to a valid point.
        let public_key = [0xffu8; 32];
        let signature = [0u8; 64];
        let message: &[u8] = b"";
        assert!(!verify(&public_key, message, &signature), "invalid pubkey must reject");
    }

    #[test]
    fn verify_rejects_s_at_or_above_l() {
        // Valid pubkey (basepoint encoding), but S = ℓ which violates the bound.
        let mut public_key = [0x66u8; 32];
        public_key[0] = 0x58;
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&public_key); // R = basepoint encoding
        signature[32..].copy_from_slice(&L_BYTES);    // S = ℓ — must reject
        assert!(!verify(&public_key, b"hello", &signature), "S = ℓ must reject");
    }
}
