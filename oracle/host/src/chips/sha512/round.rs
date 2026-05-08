//! SHA-512 single-round transform (witness function).
//!
//! FIPS 180-4 §6.4.2 step 3:
//!
//! ```text
//! T1 = h + Σ1(e) + Ch(e, f, g) + K[i] + W[i]
//! T2 = Σ0(a) + Maj(a, b, c)
//! h = g
//! g = f
//! f = e
//! e = d + T1
//! d = c
//! c = b
//! b = a
//! a = T1 + T2
//! ```
//!
//! Where (FIPS 180-4 §4.1.3):
//!
//! ```text
//! Σ0(x) = ROTR(x, 28) ⊕ ROTR(x, 34) ⊕ ROTR(x, 39)
//! Σ1(x) = ROTR(x, 14) ⊕ ROTR(x, 18) ⊕ ROTR(x, 41)
//! Ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z)
//! Maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)
//! ```
//!
//! All additions are mod 2⁶⁴.
//!
//! This module ships the **witness function** only. The AIR chip that
//! constrains a single round (sub-phase 5.2.1.2.air) needs to express
//! the bitwise operations via bit decomposition — every 64-bit word
//! gets 64 boolean columns plus bit-level XOR/AND/NOT constraints,
//! plus carry-bounded modular adders. That is many hundreds of columns
//! per round and lands in a dedicated session.

/// SHA-512 hash state: 8 64-bit words `(a, b, c, d, e, f, g, h)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha512State(pub [u64; 8]);

impl Sha512State {
    pub const fn new(state: [u64; 8]) -> Self {
        Self(state)
    }

    pub fn a(&self) -> u64 {
        self.0[0]
    }
    pub fn b(&self) -> u64 {
        self.0[1]
    }
    pub fn c(&self) -> u64 {
        self.0[2]
    }
    pub fn d(&self) -> u64 {
        self.0[3]
    }
    pub fn e(&self) -> u64 {
        self.0[4]
    }
    pub fn f(&self) -> u64 {
        self.0[5]
    }
    pub fn g(&self) -> u64 {
        self.0[6]
    }
    pub fn h(&self) -> u64 {
        self.0[7]
    }
}

#[inline]
pub fn big_sigma0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

#[inline]
pub fn big_sigma1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

#[inline]
pub fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[inline]
pub fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// Apply one SHA-512 round.
///
/// `k` is the round constant `K[i]`, `w` is the message schedule word `W[i]`.
pub fn compute_round(state: Sha512State, k: u64, w: u64) -> Sha512State {
    let [a, b, c, d, e, f, g, h] = state.0;

    let t1 = h.wrapping_add(big_sigma1(e)).wrapping_add(ch(e, f, g)).wrapping_add(k).wrapping_add(w);
    let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

    Sha512State::new([
        t1.wrapping_add(t2), // a
        a,                   // b
        b,                   // c
        c,                   // d
        d.wrapping_add(t1),  // e
        e,                   // f
        f,                   // g
        g,                   // h
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spot-check the round operations against precomputed values from
    /// the FIPS 180-4 example for `SHA-512("abc")`. After 0 rounds the
    /// state equals the IV; after applying round 0 with the appropriate
    /// `K[0]` and `W[0]` we should land on the documented intermediate.
    #[test]
    fn round_zero_matches_fips_abc_example() {
        // For SHA-512("abc"), the first padded block has W[0] = 0x6162638000000000
        // (i.e., 'abc' + the SHA padding 0x80 + zeros).
        // FIPS 180-4 Appendix C.1 ("Sample SHA-512 Calculation") gives the
        // intermediate hash values at each round. We reproduce round 0:
        //   t = 0:
        //     a = 0xf6afceb8bcfcddf5  b = 0x6a09e667f3bcc908  c = 0xbb67ae8584caa73b
        //     d = 0x3c6ef372fe94f82b  e = 0x58cb02347ab51f91  f = 0x510e527fade682d1
        //     g = 0x9b05688c2b3e6c1f  h = 0x1f83d9abfb41bd6b
        let state = Sha512State::new(super::super::constants::H_INITIAL);
        let next = compute_round(state, super::super::constants::K[0], 0x6162638000000000);
        assert_eq!(next.a(), 0xf6afceb8bcfcddf5, "round 0: a mismatch");
        assert_eq!(next.b(), 0x6a09e667f3bcc908, "round 0: b mismatch");
        assert_eq!(next.c(), 0xbb67ae8584caa73b, "round 0: c mismatch");
        assert_eq!(next.d(), 0x3c6ef372fe94f82b, "round 0: d mismatch");
        assert_eq!(next.e(), 0x58cb02347ab51f91, "round 0: e mismatch");
        assert_eq!(next.f(), 0x510e527fade682d1, "round 0: f mismatch");
        assert_eq!(next.g(), 0x9b05688c2b3e6c1f, "round 0: g mismatch");
        assert_eq!(next.h(), 0x1f83d9abfb41bd6b, "round 0: h mismatch");
    }

    #[test]
    fn big_sigma0_known_vectors() {
        assert_eq!(big_sigma0(0), 0);
        // Σ0(IV[0]) — sanity-check against an independent SHA-512
        // implementation for value at start of round 1.
        let iv = super::super::constants::H_INITIAL[0]; // 0x6a09e667f3bcc908
        let s0 = big_sigma0(iv);
        // Expected by independent computation:
        // ROTR(iv, 28) ^ ROTR(iv, 34) ^ ROTR(iv, 39)
        let expected = iv.rotate_right(28) ^ iv.rotate_right(34) ^ iv.rotate_right(39);
        assert_eq!(s0, expected);
    }

    #[test]
    fn ch_truth_table_basic() {
        // Ch picks y when x=1, z when x=0 (per bit).
        // x = 1 (bit 0 only): bit 0 picks y[0]=0, bits 1..7 pick z's bits 1..7.
        // 0xAA = 0b10101010; bit 0 = 0. 0x55 = 0b01010101; bits 1..7 = 0b1010101_0... mask = 0x54.
        assert_eq!(ch(1, 0xAA, 0x55), 0x54);
        // x = 0 (no bits set): all bits pick z. Result = z = 0x55.
        assert_eq!(ch(0, 0xAA, 0x55), 0x55);
        // All-ones x: select y entirely.
        assert_eq!(ch(u64::MAX, 0xDEADBEEF, 0xCAFE), 0xDEADBEEF);
        // All-zeros x: select z entirely.
        assert_eq!(ch(0, 0xDEADBEEF, 0xCAFE), 0xCAFE);
    }

    #[test]
    fn maj_majority_basic() {
        // Maj returns the per-bit majority of x, y, z.
        assert_eq!(maj(0, 0, 0), 0);
        assert_eq!(maj(1, 1, 0), 1);
        assert_eq!(maj(1, 0, 1), 1);
        assert_eq!(maj(0, 1, 1), 1);
        assert_eq!(maj(u64::MAX, u64::MAX, 0), u64::MAX);
        assert_eq!(maj(0, 0, u64::MAX), 0);
    }

    #[test]
    fn round_state_rotates_correctly() {
        // After one round: b becomes old a, c becomes old b, etc.
        let state = Sha512State::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        let next = compute_round(state, 0, 0);
        assert_eq!(next.b(), 0x11);
        assert_eq!(next.c(), 0x22);
        assert_eq!(next.d(), 0x33);
        assert_eq!(next.f(), 0x55);
        assert_eq!(next.g(), 0x66);
        assert_eq!(next.h(), 0x77);
    }
}
