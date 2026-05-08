//! Edwards point addition in extended coordinates (RFC 8032 §5.1.4).
//!
//! Curve25519's twisted Edwards form:
//!
//!   `-x² + y² = 1 + d · x² · y²`   where `d = -121665 / 121666 (mod p)`
//!
//! Extended coordinates `(X, Y, Z, T)` with the invariants:
//!
//!   `x = X/Z`, `y = Y/Z`, `T = X·Y/Z`, `Z·T = X·Y`.
//!
//! ## Addition formula (8 multiplications + 1 multiplication by 2d)
//!
//! Given `P1 = (X1, Y1, Z1, T1)` and `P2 = (X2, Y2, Z2, T2)`:
//!
//! ```text
//! A = (Y1 - X1) · (Y2 - X2)
//! B = (Y1 + X1) · (Y2 + X2)
//! C = T1 · 2d · T2
//! D = Z1 · 2  · Z2
//! E = B - A
//! F = D - C
//! G = D + C
//! H = B + A
//! X3 = E · F
//! Y3 = G · H
//! T3 = E · H
//! Z3 = F · G
//! ```
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc8032#section-5.1.4>
//! and Hisil et al., "Twisted Edwards Curves Revisited" (2008), §3.1.
//!
//! ## Status (sub-phase 5.2.1.4)
//!
//! This module ships the **witness function** only. The AIR chip
//! constraining one point addition (sub-phase 5.2.1.4.air) needs to
//! emit constraints for the 9 underlying field multiplications, the 4
//! field additions, and the 4 field subtractions — composing the full
//! field25519 chip stack we just built. The chip cost is roughly
//! `9 × 125` (mul chip width) + supporting columns for add/sub
//! intermediate results, putting the per-point-add chip at well over
//! 1500 columns. It lands in a dedicated session.

use crate::chips::field25519::arith::{field_add, field_mul, field_sub, field_zero};
use crate::chips::field25519::Field25519Element;

/// An Edwards curve point in extended coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPoint {
    pub x: Field25519Element,
    pub y: Field25519Element,
    pub z: Field25519Element,
    pub t: Field25519Element,
}

impl ExtendedPoint {
    /// The neutral element of the Edwards group: `(0, 1, 1, 0)`
    /// (since `x = 0/1 = 0`, `y = 1/1 = 1`, `T = 0·1/1 = 0`).
    pub fn neutral() -> Self {
        let mut one = Field25519Element::ZERO;
        one.limbs[0] = 1;
        Self {
            x: field_zero(),
            y: one.clone(),
            z: one,
            t: field_zero(),
        }
    }
}

/// Curve25519's `d = -121665/121666 (mod p)`.
///
/// Hex (big-endian, 256 bits):
///   `0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3`
///
/// Stored as the 32-byte little-endian encoding accepted by
/// `Field25519Element::from_canonical_bytes`.
pub fn d_constant() -> Field25519Element {
    let bytes: [u8; 32] = [
        0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
        0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
    ];
    Field25519Element::from_canonical_bytes(&bytes)
}

/// `2d (mod p)`. Used directly in the addition formula.
pub fn two_d_constant() -> Field25519Element {
    let d = d_constant();
    field_add(&d, &d)
}

/// Edwards extended point addition. Returns `P1 + P2`.
pub fn point_add(p1: &ExtendedPoint, p2: &ExtendedPoint) -> ExtendedPoint {
    let two_d = two_d_constant();

    let a = field_mul(&field_sub(&p1.y, &p1.x), &field_sub(&p2.y, &p2.x));
    let b = field_mul(&field_add(&p1.y, &p1.x), &field_add(&p2.y, &p2.x));
    let c = field_mul(&field_mul(&p1.t, &two_d), &p2.t);
    let d = field_mul(&field_add(&p1.z, &p1.z), &p2.z);
    let e = field_sub(&b, &a);
    let f = field_sub(&d, &c);
    let g = field_add(&d, &c);
    let h = field_add(&b, &a);

    ExtendedPoint {
        x: field_mul(&e, &f),
        y: field_mul(&g, &h),
        t: field_mul(&e, &h),
        z: field_mul(&f, &g),
    }
}

/// Convert an extended point to its affine `(x, y)` coordinates by
/// dividing through by `Z`. Used in tests to compare points whose
/// projective representations may differ even though they encode the
/// same group element.
///
/// Computing `1/Z` requires modular inversion, which is expensive
/// (Fermat: `Z^(p-2)` via square-and-multiply over 254 bits). We use a
/// minimal exponentiation here purely for testing.
pub fn to_affine(p: &ExtendedPoint) -> (Field25519Element, Field25519Element) {
    let z_inv = field_invert(&p.z);
    (field_mul(&p.x, &z_inv), field_mul(&p.y, &z_inv))
}

/// Modular inverse via Fermat's little theorem: `a^(p-2) mod p`.
/// Square-and-multiply over the 255-bit binary representation of `p-2`.
pub fn field_invert(a: &Field25519Element) -> Field25519Element {
    // p - 2 in little-endian 32-byte form: same as p but with byte 0 decremented by 2.
    // p in LE bytes = [0xed, 0xff, ..., 0xff, 0x7f]; p-2 = [0xeb, 0xff, ..., 0xff, 0x7f].
    let mut p_minus_2 = [0xffu8; 32];
    p_minus_2[0] = 0xeb;
    p_minus_2[31] = 0x7f;

    let mut result = {
        let mut one_limbs = [0u64; 9];
        one_limbs[0] = 1;
        Field25519Element { limbs: one_limbs }
    };
    let mut base = a.clone();
    // Square-and-multiply: scan bits of p_minus_2 from LSB to MSB.
    for byte in p_minus_2.iter() {
        for bit_idx in 0..8 {
            if (byte >> bit_idx) & 1 == 1 {
                result = field_mul(&result, &base);
            }
            base = field_mul(&base, &base); // square
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chips::field25519::arith::field_one;

    fn small(n: u64) -> Field25519Element {
        let mut limbs = [0u64; 9];
        limbs[0] = n & ((1 << 30) - 1);
        limbs[1] = (n >> 30) & ((1 << 30) - 1);
        Field25519Element { limbs }
    }

    /// A non-neutral test point. Not necessarily on the curve — used only
    /// to check that the addition formula's algebraic invariants hold.
    fn synthetic_point(seed: u64) -> ExtendedPoint {
        ExtendedPoint {
            x: small(seed.wrapping_mul(0x9E3779B97F4A7C15)),
            y: small(seed.wrapping_mul(0xBF58476D1CE4E5B9).wrapping_add(1)),
            z: field_one(),
            t: small(seed.wrapping_mul(0x94D049BB133111EB)),
        }
    }

    #[test]
    fn neutral_is_identity_in_addition_left() {
        let p = synthetic_point(0xCAFE);
        let sum = point_add(&ExtendedPoint::neutral(), &p);
        let (x_sum, y_sum) = to_affine(&sum);
        let (x_p, y_p) = to_affine(&p);
        assert_eq!(x_sum, x_p, "x-affine of O + P should equal x of P");
        assert_eq!(y_sum, y_p, "y-affine of O + P should equal y of P");
    }

    #[test]
    fn neutral_is_identity_in_addition_right() {
        let p = synthetic_point(0xBEEF);
        let sum = point_add(&p, &ExtendedPoint::neutral());
        let (x_sum, y_sum) = to_affine(&sum);
        let (x_p, y_p) = to_affine(&p);
        assert_eq!(x_sum, x_p);
        assert_eq!(y_sum, y_p);
    }

    #[test]
    fn neutral_plus_neutral_is_neutral() {
        let n = ExtendedPoint::neutral();
        let sum = point_add(&n, &n);
        let (x, y) = to_affine(&sum);
        assert_eq!(x, field_zero());
        assert_eq!(y, field_one());
    }

    #[test]
    fn addition_is_commutative_for_synthetic_points() {
        // The Edwards extended addition formula is provably commutative.
        // We don't need on-curve points to verify this — just that
        // P1 + P2 produces the same affine coords as P2 + P1.
        let p1 = synthetic_point(0x1234);
        let p2 = synthetic_point(0x5678);
        let s12 = point_add(&p1, &p2);
        let s21 = point_add(&p2, &p1);
        let (x12, y12) = to_affine(&s12);
        let (x21, y21) = to_affine(&s21);
        assert_eq!(x12, x21, "x of P1+P2 should equal x of P2+P1");
        assert_eq!(y12, y21, "y of P1+P2 should equal y of P2+P1");
    }

    #[test]
    fn d_constant_canonical_byte_round_trip() {
        // The d constant must round-trip through to_canonical_bytes —
        // sanity that our hardcoded LE bytes are well-formed.
        let d = d_constant();
        let bytes = d.to_canonical_bytes();
        let expected: [u8; 32] = [
            0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
            0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
        ];
        assert_eq!(bytes, expected);
    }

    #[test]
    fn two_d_equals_d_plus_d() {
        // 2d should be d + d (canonical mod p).
        let d = d_constant();
        let two_d = two_d_constant();
        let d_plus_d = field_add(&d, &d);
        assert_eq!(two_d, d_plus_d);
    }

    #[test]
    fn field_invert_round_trip_on_small_value() {
        // a · a^(-1) = 1 (mod p). Test on a small invertible value.
        let a = small(7);
        let a_inv = field_invert(&a);
        let prod = field_mul(&a, &a_inv);
        assert_eq!(prod, field_one(), "7 · 7^(-1) should equal 1 mod p");
    }

    #[test]
    fn field_invert_round_trip_on_large_value() {
        let a = small(0xDEAD_BEEF_CAFE);
        let a_inv = field_invert(&a);
        let prod = field_mul(&a, &a_inv);
        assert_eq!(prod, field_one());
    }

    #[test]
    fn to_affine_then_back_invariant() {
        // For a synthetic point, taking affine coords and reconstructing
        // a Z=1 ExtendedPoint should produce the same affine coords.
        let p = synthetic_point(42);
        let (x, y) = to_affine(&p);
        let p_z1 = ExtendedPoint {
            x: x.clone(),
            y: y.clone(),
            z: field_one(),
            t: field_mul(&x, &y),
        };
        let (x2, y2) = to_affine(&p_z1);
        assert_eq!(x, x2);
        assert_eq!(y, y2);
    }
}
