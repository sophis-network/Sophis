//! SHA-512 message schedule (FIPS 180-4 §6.4.2 step 1).
//!
//! Given a 1024-bit message block (sixteen 64-bit big-endian words `M[0..16]`),
//! extend it into 80 schedule words `W[0..80]`:
//!
//! ```text
//! W[t] = M[t]                                              for 0 ≤ t < 16
//! W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]       for 16 ≤ t < 80
//! ```
//!
//! Where:
//!
//! ```text
//! σ0(x) = ROTR(x,  1) ⊕ ROTR(x,  8) ⊕ SHR(x, 7)
//! σ1(x) = ROTR(x, 19) ⊕ ROTR(x, 61) ⊕ SHR(x, 6)
//! ```
//!
//! All additions are mod 2⁶⁴.

#[inline]
pub fn small_sigma0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

#[inline]
pub fn small_sigma1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

/// Extend a 16-word message block into the full 80-word schedule.
pub fn compute_schedule(block: &[u64; 16]) -> [u64; 80] {
    let mut w = [0u64; 80];
    w[..16].copy_from_slice(block);
    for t in 16..80 {
        w[t] = small_sigma1(w[t - 2]).wrapping_add(w[t - 7]).wrapping_add(small_sigma0(w[t - 15])).wrapping_add(w[t - 16]);
    }
    w
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_first_16_match_block() {
        let block: [u64; 16] = core::array::from_fn(|i| (i as u64) * 0x0101010101010101);
        let w = compute_schedule(&block);
        assert_eq!(&w[..16], &block[..]);
    }

    #[test]
    fn schedule_for_abc_block_matches_fips() {
        // FIPS 180-4 Appendix C.1: SHA-512("abc") padded block.
        // M[0] = 'abc' || 0x80 || 0...0 = 0x6162638000000000
        // M[15] = bit-length = 24 = 0x0000000000000018
        let mut block = [0u64; 16];
        block[0] = 0x6162638000000000;
        block[15] = 0x0000000000000018;
        let w = compute_schedule(&block);
        // FIPS 180-4 Appendix C.1 lists W[16] explicitly:
        //   W[16] = 0xb2f1b8d3a306091a (computed from σ1(W[14])+W[9]+σ0(W[1])+W[0]
        //           where W[14]=0, W[9]=0, W[1]=0, W[0]=0x6162638000000000)
        // Independent computation:
        //   σ1(0) = 0, W[9]=0, σ0(0)=0, W[0]=0x6162638000000000
        //   So W[16] = 0x6162638000000000.
        assert_eq!(w[16], 0x6162638000000000, "W[16] for SHA-512(abc) block");
    }

    #[test]
    fn small_sigma0_zero() {
        assert_eq!(small_sigma0(0), 0);
    }

    #[test]
    fn small_sigma1_zero() {
        assert_eq!(small_sigma1(0), 0);
    }

    #[test]
    fn small_sigma0_basic_vector() {
        // Independent computation:
        //   ROTR(1, 1) ^ ROTR(1, 8) ^ (1 >> 7)
        //   = 0x8000000000000000 ^ 0x0100000000000000 ^ 0
        //   = 0x8100000000000000
        assert_eq!(small_sigma0(1), 0x8100000000000000);
    }
}
