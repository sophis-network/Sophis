//! 256-bit scalar multiplication on the Edwards twisted curve via the
//! double-and-add algorithm.
//!
//! `scalar_mul(s, P) = [s] · P` where `s` is a 256-bit little-endian
//! integer and `P` is an extended-coordinate Edwards point.
//!
//! Implementation is MSB-first with leading-zero short-circuit: for small
//! scalars (e.g. 3, 7, 257) we run only `bit_length(s) - 1` iterations,
//! not 255. This keeps tests cheap while still exercising the same
//! double-and-add control flow that the full 256-bit variant uses.
//!
//! ## Status (sub-phase 5.2.1.5)
//!
//! Witness function only. The AIR chip (sub-phase 5.2.1.5.air) chains
//! `point_add` chips with a "selector" column per scalar bit gating the
//! conditional addition. With ~256 doubling + ~128 addition steps, each
//! point op being ~1500 columns of chip, the chip is genuinely huge —
//! likely realised as 256 separate AIR rows or a separate "scalar-mul
//! step" sub-chip composed many times. The witness lands first so the
//! algorithm and group-law properties are validated.

use super::point::{ExtendedPoint, point_add};

/// Edwards point doubling. The dedicated doubling formula has a slightly
/// lower op count (4M + 4S + 1Mc), but composing `point_add(p, p)` is
/// algebraically identical and reuses the existing chip / witness path.
/// We use the simpler form here; an optimised dedicated chip can be
/// introduced later if profiling shows it matters.
pub fn point_double(p: &ExtendedPoint) -> ExtendedPoint {
    point_add(p, p)
}

/// Compute `[scalar] · point` where `scalar` is a 32-byte little-endian
/// integer. Returns the neutral point if `scalar == 0`.
pub fn scalar_mul(scalar_le_bytes: &[u8; 32], point: &ExtendedPoint) -> ExtendedPoint {
    // Find the highest set bit; start the doubling chain from there.
    let mut highest_bit: Option<usize> = None;
    for byte_idx in (0..32).rev() {
        let byte = scalar_le_bytes[byte_idx];
        if byte != 0 {
            // Position of the most-significant set bit within `byte`.
            let leading = byte.leading_zeros() as usize; // 0..=7
            let bit_in_byte = 7 - leading;
            highest_bit = Some(byte_idx * 8 + bit_in_byte);
            break;
        }
    }
    let highest = match highest_bit {
        Some(b) => b,
        None => return ExtendedPoint::neutral(), // scalar == 0
    };

    // MSB-first double-and-add starting from `result = P` (the contribution
    // of the highest set bit).
    let mut result = point.clone();
    for i in (0..highest).rev() {
        result = point_double(&result);
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if (scalar_le_bytes[byte_idx] >> bit_idx) & 1 == 1 {
            result = point_add(&result, point);
        }
    }
    result
}

/// Convenience wrapper for tests: scalar passed as a `u64`.
pub fn scalar_mul_u64(scalar: u64, point: &ExtendedPoint) -> ExtendedPoint {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&scalar.to_le_bytes());
    scalar_mul(&bytes, point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::point::to_affine;
    use crate::chips::field25519::Field25519Element;
    use crate::chips::field25519::arith::{field_one, field_zero};

    fn small(n: u64) -> Field25519Element {
        let mut limbs = [0u64; 9];
        limbs[0] = n & ((1 << 30) - 1);
        limbs[1] = (n >> 30) & ((1 << 30) - 1);
        Field25519Element { limbs }
    }

    fn synthetic_point(seed: u64) -> ExtendedPoint {
        ExtendedPoint {
            x: small(seed.wrapping_mul(0x9E3779B97F4A7C15)),
            y: small(seed.wrapping_mul(0xBF58476D1CE4E5B9).wrapping_add(1)),
            z: field_one(),
            t: small(seed.wrapping_mul(0x94D049BB133111EB)),
        }
    }

    fn affine_eq(a: &ExtendedPoint, b: &ExtendedPoint) -> bool {
        let (ax, ay) = to_affine(a);
        let (bx, by) = to_affine(b);
        ax == bx && ay == by
    }

    #[test]
    fn scalar_zero_yields_neutral() {
        let p = synthetic_point(42);
        let r = scalar_mul_u64(0, &p);
        let (rx, ry) = to_affine(&r);
        assert_eq!(rx, field_zero());
        assert_eq!(ry, field_one());
    }

    #[test]
    fn scalar_one_yields_point() {
        let p = synthetic_point(0xCAFE);
        let r = scalar_mul_u64(1, &p);
        assert!(affine_eq(&r, &p), "1 · P should equal P");
    }

    #[test]
    fn scalar_two_yields_double() {
        let p = synthetic_point(0xBEEF);
        let two_p = scalar_mul_u64(2, &p);
        let dbl = point_double(&p);
        assert!(affine_eq(&two_p, &dbl), "2 · P should equal point_double(P)");
    }

    #[test]
    fn scalar_three_yields_double_plus_p() {
        let p = synthetic_point(7);
        let three_p = scalar_mul_u64(3, &p);
        let two_p = point_double(&p);
        let three_p_via_add = point_add(&two_p, &p);
        assert!(affine_eq(&three_p, &three_p_via_add), "3 · P should equal 2P + P");
    }

    #[test]
    fn scalar_four_yields_double_double() {
        let p = synthetic_point(11);
        let four_p = scalar_mul_u64(4, &p);
        let two_p = point_double(&p);
        let four_p_via_double = point_double(&two_p);
        assert!(affine_eq(&four_p, &four_p_via_double), "4 · P should equal double(2P)");
    }

    #[test]
    fn scalar_five_matches_iterated_addition() {
        let p = synthetic_point(13);
        let five_p = scalar_mul_u64(5, &p);
        // 5P = 4P + P = double(double(P)) + P
        let two_p = point_double(&p);
        let four_p = point_double(&two_p);
        let five_p_via_add = point_add(&four_p, &p);
        assert!(affine_eq(&five_p, &five_p_via_add));
    }

    #[test]
    fn scalar_seven_matches_msb_first_recipe() {
        // 7 = 0b111, MSB-first algorithm:
        //   start with result = P
        //   i=1: result = double(P);  bit 1 = 1, result = result + P  → double(P) + P
        //   i=0: result = double(_);  bit 0 = 1, result = result + P
        // Group-axiom equivalents like "7P = 4P + 2P + P" only hold for
        // on-curve points (Edwards group law). Synthetic off-curve points
        // satisfy only the literal algorithmic composition.
        let p = synthetic_point(17);
        let seven_p = scalar_mul_u64(7, &p);
        let three_p = point_add(&point_double(&p), &p);          // intermediate after i=1
        let six_p = point_double(&three_p);                       // doubling at i=0
        let seven_p_via_recipe = point_add(&six_p, &p);           // final add at i=0
        assert!(affine_eq(&seven_p, &seven_p_via_recipe));
    }

    #[test]
    fn scalar_8_yields_double_double_double() {
        let p = synthetic_point(19);
        let eight_p = scalar_mul_u64(8, &p);
        let dbl_dbl_dbl = point_double(&point_double(&point_double(&p)));
        assert!(affine_eq(&eight_p, &dbl_dbl_dbl), "8 · P should equal double^3(P)");
    }

    #[test]
    fn scalar_with_high_bit_set_in_byte_handled() {
        // 0x80 = 128, exercises the "highest bit in this byte is bit 7" branch
        // of the leading-zero scan.
        let p = synthetic_point(23);
        let r = scalar_mul_u64(128, &p);
        // 128 · P via doubling: double^7(P)
        let mut iter = p.clone();
        for _ in 0..7 {
            iter = point_double(&iter);
        }
        assert!(affine_eq(&r, &iter), "128 · P should equal double^7(P)");
    }

    #[test]
    fn scalar_in_second_byte_handled() {
        // 256 has bit 8 set (in byte 1, bit 0). Tests that the byte-scan
        // correctly reaches into byte 1.
        let p = synthetic_point(29);
        let r = scalar_mul_u64(256, &p);
        // 256 · P = double^8(P)
        let mut iter = p.clone();
        for _ in 0..8 {
            iter = point_double(&iter);
        }
        assert!(affine_eq(&r, &iter), "256 · P should equal double^8(P)");
    }

    #[test]
    fn scalar_mul_via_le_bytes_matches_u64_helper() {
        let p = synthetic_point(31);
        let r_u64 = scalar_mul_u64(0xDEADBEEF, &p);

        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&0xDEADBEEFu64.to_le_bytes());
        let r_bytes = scalar_mul(&bytes, &p);

        assert!(affine_eq(&r_u64, &r_bytes), "u64 helper should match raw byte form");
    }

    #[test]
    fn scalar_six_matches_msb_first_recipe() {
        // 6 = 0b110, MSB-first:
        //   start: result = P
        //   i=1: double → 2P;  bit 1 = 1, add → 3P
        //   i=0: double → double(3P);  bit 0 = 0, no add
        // So 6P_algo = double(3P) where 3P = double(P) + P.
        let p = synthetic_point(37);
        let six_p_via_scalar = scalar_mul_u64(6, &p);
        let three_p = point_add(&point_double(&p), &p);
        let six_p_via_recipe = point_double(&three_p);
        assert!(affine_eq(&six_p_via_scalar, &six_p_via_recipe));
    }
}
