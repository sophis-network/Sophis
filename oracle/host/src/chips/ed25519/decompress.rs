//! Edwards point decompression (RFC 8032 §5.1.3).
//!
//! Ed25519 encodes a point as 32 little-endian bytes: 255 bits for `y`
//! and 1 bit for the sign of `x` (high bit of byte 31). Decompression
//! recovers `(x, y)` by solving the curve equation
//!
//!   `-x² + y² = 1 + d · x² · y²`
//!
//! for `x`:
//!
//!   `x² = (y² - 1) / (1 + d · y²)`
//!
//! Since `p ≡ 5 (mod 8)`, the standard square-root method uses one
//! exponentiation by `(p-5)/8 = 2²⁵² - 3`:
//!
//! ```text
//! u = y² - 1
//! v = 1 + d · y²
//! candidate x = u · v³ · (u · v⁷)^((p-5)/8)
//! if v · x² == u   :  x is correct
//! if v · x² == -u  :  x ← x · sqrt(-1)        (apply the i twist)
//! else             :  not a square — point is not on the curve
//! ```
//!
//! Sign correction: if `x mod 2 ≠ sign_bit`, negate `x ← p - x`. The
//! special case `x == 0 ∧ sign_bit == 1` fails.
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc8032#section-5.1.3>.
//!
//! ## Status (sub-phase 5.2.1.6)
//!
//! Witness function only. The AIR chip (5.2.1.6.air) needs to express
//! the 252-bit exponentiation via square-and-multiply with a fixed
//! window of multiplications (~378 field_muls per decompression),
//! plus the conditional sign / `i`-twist branches via selector columns.
//! Lands in a dedicated session.

use super::point::{ExtendedPoint, d_constant};
use crate::chips::field25519::Field25519Element;
use crate::chips::field25519::arith::{field_add, field_mul, field_one, field_sub, field_zero};

/// `(p - 5) / 8 = 2²⁵² - 3` in 32 little-endian bytes.
///
/// Bits: every bit `0..251` is 1 except bit 1 (since `2²⁵² - 3` flips bits 0
/// and 1 of `2²⁵² - 1` and back, ending with `...11111101`). Bits 252..255 = 0.
pub const P_MINUS_5_OVER_8: [u8; 32] = [
    0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F,
];

/// `(p - 1) / 4 = 2²⁵³ - 5` in 32 little-endian bytes.
/// Used to compute `i = sqrt(-1) = 2^((p-1)/4) mod p`.
pub const P_MINUS_1_OVER_4: [u8; 32] = [
    0xFB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F,
];

/// Generic modular exponentiation: `base^exponent (mod p)` via
/// LSB-first square-and-multiply over arbitrary-length little-endian
/// exponent bytes.
pub fn field_pow(base: &Field25519Element, exponent_le_bytes: &[u8]) -> Field25519Element {
    let mut result = field_one();
    let mut current = *base;
    for byte in exponent_le_bytes {
        for bit_idx in 0..8 {
            if (byte >> bit_idx) & 1 == 1 {
                result = field_mul(&result, &current);
            }
            current = field_mul(&current, &current);
        }
    }
    result
}

/// `i = sqrt(-1) (mod p) = 2^((p-1)/4) (mod p)`.
pub fn sqrt_minus_1() -> Field25519Element {
    let mut two = Field25519Element::ZERO;
    two.limbs[0] = 2;
    field_pow(&two, &P_MINUS_1_OVER_4)
}

/// Decompress a 32-byte Ed25519 point encoding into extended coordinates.
/// Returns `None` if the encoding does not represent a point on the curve.
pub fn decompress(compressed: &[u8; 32]) -> Option<ExtendedPoint> {
    let sign_bit = (compressed[31] >> 7) & 1;
    // `from_canonical_bytes` masks the high bit of byte 31 (Ed25519 convention).
    let y = Field25519Element::from_canonical_bytes(compressed);

    let y2 = field_mul(&y, &y);
    let u = field_sub(&y2, &field_one()); // y² - 1
    let v = field_add(&field_mul(&d_constant(), &y2), &field_one()); // d·y² + 1

    // Compute helper powers of v: v² = v·v, v³ = v²·v, v⁷ = v³·v³·v.
    let v2 = field_mul(&v, &v);
    let v3 = field_mul(&v2, &v);
    let v7 = field_mul(&field_mul(&v3, &v3), &v);

    let uv3 = field_mul(&u, &v3);
    let uv7 = field_mul(&u, &v7);

    // candidate x = u·v³ · (u·v⁷)^((p-5)/8)
    let beta = field_pow(&uv7, &P_MINUS_5_OVER_8);
    let mut x = field_mul(&uv3, &beta);

    // Validate: either v·x² == u (correct) or v·x² == -u (apply i twist).
    let vx2 = field_mul(&v, &field_mul(&x, &x));
    if vx2 == u {
        // x is the right square root.
    } else {
        let neg_u = field_sub(&field_zero(), &u);
        if vx2 == neg_u {
            x = field_mul(&x, &sqrt_minus_1());
        } else {
            return None; // Not on the curve.
        }
    }

    // Sign correction: low bit of x must match `sign_bit`.
    let x_low_bit = (x.limbs[0] & 1) as u8;
    if x_low_bit != sign_bit {
        x = field_sub(&field_zero(), &x);
    }

    // Special case: x must not be 0 with sign_bit = 1 (no negative-zero encoding).
    let x_is_zero = x.limbs.iter().all(|&l| l == 0);
    if x_is_zero && sign_bit == 1 {
        return None;
    }

    let t = field_mul(&x, &y);
    Some(ExtendedPoint { x, y, z: field_one(), t })
}

/// Inverse of `decompress`. Encodes an extended-coordinate point as 32
/// little-endian bytes with the high bit of byte 31 storing the sign of `x`.
pub fn compress(point: &ExtendedPoint) -> [u8; 32] {
    let (x, y) = super::point::to_affine(point);
    let mut bytes = y.to_canonical_bytes();
    bytes[31] |= ((x.limbs[0] & 1) as u8) << 7;
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chips::field25519::P_LIMBS;

    fn small(n: u64) -> Field25519Element {
        let mut limbs = [0u64; 9];
        limbs[0] = n & ((1 << 30) - 1);
        Field25519Element { limbs }
    }

    #[test]
    fn field_pow_zero_exponent_is_one() {
        let r = field_pow(&small(7), &[0u8; 32]);
        assert_eq!(r, field_one());
    }

    #[test]
    fn field_pow_one_exponent_is_base() {
        let mut exp = [0u8; 32];
        exp[0] = 1;
        let r = field_pow(&small(0xDEAD_BEEF), &exp);
        assert_eq!(r, small(0xDEAD_BEEF));
    }

    #[test]
    fn field_pow_two_exponent_is_square() {
        let mut exp = [0u8; 32];
        exp[0] = 2;
        let r = field_pow(&small(13), &exp);
        let expected = field_mul(&small(13), &small(13));
        assert_eq!(r, expected, "13² should equal field_pow(13, 2)");
    }

    #[test]
    fn sqrt_minus_1_squared_is_negative_1() {
        // i² = -1 (mod p) = p - 1.
        let i = sqrt_minus_1();
        let i2 = field_mul(&i, &i);
        let neg_one = field_sub(&field_zero(), &field_one());
        assert_eq!(i2, neg_one, "sqrt(-1)² should equal -1 mod p");
    }

    /// Decompress the Ed25519 basepoint and verify against the published
    /// affine `Bx` value (RFC 8032 §5.1).
    #[test]
    fn decompress_basepoint_matches_rfc_8032() {
        // Compressed basepoint: `By` LE bytes with sign(`Bx`) = 0 in byte 31's high bit.
        // By = 4/5 mod p; published encoding starts with 0x58 then 0x66 × 31.
        let mut compressed = [0x66u8; 32];
        compressed[0] = 0x58;
        // High bit of byte 31 is already 0 (0x66 = 0b01100110).

        let p = decompress(&compressed).expect("basepoint must decompress");

        // Bx published in RFC 8032:
        //   Bx = 15112221349535400772501151409588531511454012693041857206046113283949847762202
        //   In LE bytes (32 bytes):
        let bx_expected_bytes: [u8; 32] = [
            0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd,
            0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
        ];
        let bx_expected = Field25519Element::from_canonical_bytes(&bx_expected_bytes);
        assert_eq!(p.x, bx_expected, "basepoint Bx mismatch");

        // y must equal 4/5 mod p (which round-trips through to_canonical_bytes
        // back to [0x58, 0x66, 0x66, ..., 0x66]).
        let y_bytes = p.y.to_canonical_bytes();
        let mut y_expected = [0x66u8; 32];
        y_expected[0] = 0x58;
        // High bit of last byte of y itself (no sign bit yet) is 0.
        y_expected[31] = 0x66; // unchanged
        assert_eq!(y_bytes, y_expected, "basepoint By mismatch");
    }

    #[test]
    fn compress_decompress_round_trip_basepoint() {
        let mut compressed = [0x66u8; 32];
        compressed[0] = 0x58;
        let p = decompress(&compressed).expect("basepoint must decompress");
        let recomp = compress(&p);
        assert_eq!(recomp, compressed, "compress(decompress(B)) should equal B");
    }

    #[test]
    fn compress_decompress_round_trip_with_sign_bit_set() {
        // Same y as basepoint but flip the sign bit of x. decompress yields
        // (-Bx, By). compress yields back the encoding with sign bit set.
        let mut compressed = [0x66u8; 32];
        compressed[0] = 0x58;
        compressed[31] |= 0x80; // set sign bit

        let p = decompress(&compressed).expect("negation of basepoint must decompress");
        // x must be -Bx (i.e., p - Bx_canonical).
        let bx_expected_bytes: [u8; 32] = [
            0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd,
            0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
        ];
        let bx_canonical = Field25519Element::from_canonical_bytes(&bx_expected_bytes);
        let neg_bx = field_sub(&field_zero(), &bx_canonical);
        assert_eq!(p.x, neg_bx, "negated basepoint x should be p - Bx");

        // Round-trip
        let recomp = compress(&p);
        assert_eq!(recomp, compressed);
    }

    #[test]
    fn neutral_decompress_round_trip() {
        // Neutral element is (0, 1): y = 1, x = 0, sign = 0.
        // Encoding: y = 1 in LE bytes = [0x01, 0x00 × 31], with high bit of byte 31 = 0.
        let mut compressed = [0u8; 32];
        compressed[0] = 0x01;

        let p = decompress(&compressed).expect("neutral element must decompress");
        assert_eq!(p.x, field_zero(), "neutral x should be 0");
        assert_eq!(p.y, field_one(), "neutral y should be 1");

        let recomp = compress(&p);
        assert_eq!(recomp, compressed);
    }

    #[test]
    fn neutral_with_sign_bit_set_fails() {
        // Encoding (y=1, sign=1) is invalid because x must be 0 here, and
        // sign bit 1 + x = 0 is the explicitly forbidden case.
        let mut compressed = [0u8; 32];
        compressed[0] = 0x01;
        compressed[31] = 0x80;
        assert!(decompress(&compressed).is_none(), "x=0 + sign=1 must fail");
    }

    #[test]
    fn decompress_zero_y_satisfies_curve() {
        // y = 0: u = -1, v = 1, x² = -1 (mod p). x exists iff -1 is a QR mod p.
        // For p ≡ 1 (mod 4), -1 IS a QR (we use sqrt_minus_1). So decompression
        // should succeed.
        let mut compressed = [0u8; 32];
        // sign bit 0, low bit of x must be 0 (sqrt_minus_1's low bit determined
        // by the specific value).
        let i = sqrt_minus_1();
        let i_low_bit = (i.limbs[0] & 1) as u8;
        // To match the algorithm: it chooses x = sqrt_minus_1 first, then
        // negates if low bit ≠ sign_bit. Set sign_bit to whatever i's low bit is.
        compressed[31] = i_low_bit << 7;

        let p = decompress(&compressed).expect("y=0 should decompress when sign matches sqrt(-1)");
        assert_eq!(p.y, field_zero());
        // x² should equal -1.
        let x2 = field_mul(&p.x, &p.x);
        let neg_one = field_sub(&field_zero(), &field_one());
        assert_eq!(x2, neg_one, "x² should equal -1");
    }

    #[test]
    fn p_minus_5_over_8_constant_smoke() {
        // Independent sanity: byte 0 = 0xFD, last non-zero byte = 0x0F,
        // middle bytes all 0xFF.
        assert_eq!(P_MINUS_5_OVER_8[0], 0xFD);
        assert_eq!(P_MINUS_5_OVER_8[31], 0x0F);
        for &b in &P_MINUS_5_OVER_8[1..31] {
            assert_eq!(b, 0xFF);
        }
    }

    #[test]
    fn p_minus_1_over_4_constant_smoke() {
        assert_eq!(P_MINUS_1_OVER_4[0], 0xFB);
        assert_eq!(P_MINUS_1_OVER_4[31], 0x1F);
    }

    #[test]
    fn p_limbs_unchanged_by_field_pow_small() {
        // Sanity that field_pow doesn't mutate any global state.
        let _ = field_pow(&small(2), &P_MINUS_5_OVER_8);
        // P_LIMBS is a const, can't change. Just spot-check it remains as expected.
        assert_eq!(P_LIMBS[0], 0x3FFFFFED);
    }
}
