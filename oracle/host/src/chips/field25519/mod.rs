//! GF(2²⁵⁵-19) limb arithmetic chips.
//!
//! Representation: 9 limbs of 30 bits each (270-bit window with 1 bit of
//! carry headroom — BabyBear's prime is ~2³¹). The Curve25519 prime
//! `p = 2²⁵⁵ - 19` is decomposed into the constant `P_LIMBS`.
//!
//! "Loose" (un-reduced) elements have limbs in `[0, 2³¹)`. The reduce
//! chip (sub-phase 5.2.1.1) brings them back to canonical form with limbs
//! in `[0, 2³⁰)`. This module currently exposes:
//!
//! - `Field25519Element` — convenience wrapper around `[u64; 9]` with
//!   `from_canonical_bytes`/`to_canonical_bytes` helpers.
//! - `P_LIMBS` — limb decomposition of `2²⁵⁵ - 19`.
//! - `add` chip — per-limb modular add (5.2.1.0)
//! - `sub` chip — per-limb modular sub (5.2.1.0)

pub mod add;
pub mod add_canonical;
pub mod add_canonical_chunked;
pub mod add_trunc;
pub mod arith;
pub mod carry_fold;
pub mod cond_p_sub;
pub mod cond_p_sub_chunked;
pub mod eq;
pub mod first_fold;
pub mod first_fold_chunked;
pub mod is_zero;
pub mod limb_assembly;
pub mod limb_assembly_chunked;
pub mod mod_p;
pub mod mod_p_chip;
pub mod mod_p_chip_full;
pub mod mod_p_chunked;
pub mod mul;
pub mod mul_canonical;
pub mod mul_canonical_full;
pub mod mul_canonical_full_chunked;
pub mod mul_pipeline;
pub mod mul_pipeline_chunked;
pub mod pow_air;
pub mod pow_air_chunked;
pub mod reduce;
pub mod second_fold;
pub mod second_fold_chunked;
pub mod sub;
pub mod sub_canonical;
pub mod sub_canonical_chunked;
pub mod sub_trunc;

/// Number of 30-bit limbs in the canonical representation.
pub const NUM_LIMBS: usize = 9;

/// Number of bits per limb.
pub const LIMB_BITS: usize = 30;

/// `2³⁰` — useful for reduction logic and bound checks.
pub const LIMB_MOD: u64 = 1u64 << LIMB_BITS;

/// Curve25519 prime `p = 2²⁵⁵ - 19` decomposed into 9 limbs of 30 bits each.
///
/// Verification (telescoping):
///   `(2³⁰ - 19) + (2³⁰ - 1)·2³⁰ + … + (2³⁰ - 1)·2²¹⁰ + (2¹⁵ - 1)·2²⁴⁰`
/// `= 2²⁵⁵ - 19`.
pub const P_LIMBS: [u64; NUM_LIMBS] = [
    0x3FFFFFED, // 2³⁰ - 19
    0x3FFFFFFF, // 2³⁰ - 1
    0x3FFFFFFF,
    0x3FFFFFFF,
    0x3FFFFFFF,
    0x3FFFFFFF,
    0x3FFFFFFF,
    0x3FFFFFFF,
    0x00007FFF, // 2¹⁵ - 1
];

/// Convenience wrapper around 9 BabyBear-sized limbs. Stored as `u64` so
/// callers can do plain integer arithmetic when computing witnesses; the
/// AIR side accepts these as `BabyBear` field elements via `F::from_u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field25519Element {
    pub limbs: [u64; NUM_LIMBS],
}

impl Field25519Element {
    pub const ZERO: Self = Self { limbs: [0; NUM_LIMBS] };
    pub const P: Self = Self { limbs: P_LIMBS };

    /// Decode a 32-byte little-endian Curve25519 element into 9 limbs of
    /// 30 bits each. The high bit of byte 31 is masked off (Curve25519
    /// convention — top bit is unused).
    pub fn from_canonical_bytes(bytes: &[u8; 32]) -> Self {
        let mut acc: u64 = 0;
        let mut bits: usize = 0;
        let mut limbs = [0u64; NUM_LIMBS];
        let mut out = 0;
        for (i, &b) in bytes.iter().enumerate() {
            // Mask the high bit of the top byte (Curve25519 convention).
            let byte = if i == 31 { b & 0x7F } else { b };
            acc |= (byte as u64) << bits;
            bits += 8;
            while bits >= LIMB_BITS && out < NUM_LIMBS {
                limbs[out] = acc & ((1u64 << LIMB_BITS) - 1);
                acc >>= LIMB_BITS;
                bits -= LIMB_BITS;
                out += 1;
            }
        }
        if out < NUM_LIMBS {
            limbs[out] = acc;
        }
        Self { limbs }
    }

    /// Re-pack 9 30-bit limbs back into a 32-byte little-endian
    /// representation. The caller is responsible for ensuring the value
    /// is canonically reduced (`< p`) — this function does not enforce it.
    pub fn to_canonical_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut acc: u64 = 0;
        let mut bits: usize = 0;
        let mut byte_off = 0;
        for &limb in &self.limbs {
            acc |= limb << bits;
            bits += LIMB_BITS;
            while bits >= 8 && byte_off < 32 {
                out[byte_off] = (acc & 0xff) as u8;
                acc >>= 8;
                bits -= 8;
                byte_off += 1;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `2²⁵⁵ - 19` reconstructed from `P_LIMBS` must equal what we expect.
    #[test]
    fn p_limbs_reconstruct_curve25519_prime() {
        // Sum P_LIMBS[i] * 2^(30*i) using a 256-bit-style accumulator
        // (we use BigInt-style manual computation in u128 chunks).
        // Instead of pulling a bignum dep, validate via the round-trip
        // with `to_canonical_bytes`.
        let p = Field25519Element::P;
        let bytes = p.to_canonical_bytes();
        // Expected: little-endian (2²⁵⁵ - 19) = 0xed,0xff,…,0xff,0x7f
        let mut expected = [0xffu8; 32];
        expected[0] = 0xed;
        expected[31] = 0x7f;
        assert_eq!(bytes, expected);
    }

    #[test]
    fn from_canonical_bytes_round_trip() {
        // Pick a non-trivial value: 2²⁵⁴ + 12345.
        let mut bytes = [0u8; 32];
        bytes[31] = 0x40; // 2²⁵⁴ in bit 254
        bytes[0] = 0x39; // 12345 = 0x3039
        bytes[1] = 0x30;
        let e = Field25519Element::from_canonical_bytes(&bytes);
        let back = e.to_canonical_bytes();
        assert_eq!(back, bytes);
    }

    #[test]
    fn from_canonical_bytes_masks_top_bit() {
        // Curve25519 convention: high bit of byte 31 is ignored.
        let mut bytes = [0u8; 32];
        bytes[31] = 0xff; // top bit set
        let e = Field25519Element::from_canonical_bytes(&bytes);
        let back = e.to_canonical_bytes();
        // Round trip clears bit 255: byte 31 becomes 0x7f.
        assert_eq!(back[31], 0x7f);
    }

    #[test]
    fn zero_round_trips() {
        let z = Field25519Element::ZERO;
        assert_eq!(z.to_canonical_bytes(), [0u8; 32]);
        assert_eq!(Field25519Element::from_canonical_bytes(&[0u8; 32]), z);
    }
}
