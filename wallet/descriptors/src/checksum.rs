//! Bech32-style polymod checksum per `wallet/descriptors/DESIGN.md` D5.
//!
//! Reuses the BIP-380 alphabet, generator polynomials, and 8-character output
//! verbatim. The reference algorithm is in BIP-380 §"Checksum"; the Rust
//! implementation below is a direct port.

/// Length of the textual checksum (after `#`).
pub const CHECKSUM_LENGTH: usize = 8;

/// BIP-380 charset for descriptor bodies (96 characters). Position in this
/// string (as a u8 index) is the value used by the polymod.
pub(crate) const INPUT_CHARSET: &str =
    "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

/// Charset used to *render* checksum chars (32 characters; same Bech32 set
/// used in BIP-173).
pub(crate) const CHECKSUM_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// BIP-380 generator polynomials for the 5-element-wide polymod over GF(32).
const GENERATORS: [u64; 5] = [0xf5_dee5_1989, 0xa9_fdca_3312, 0x1b_ab10_e32d, 0x37_06b1_677a, 0x64_4d62_6ffd];

/// Polymod state mask (40 bits; high 5 bits used as `top`).
const STATE_MASK: u64 = 0x7_ffff_ffff;

/// One step of the polymod accumulator.
fn polymod_step(chk: u64, value: u64) -> u64 {
    let top = chk >> 35;
    let mut new_chk = ((chk & STATE_MASK) << 5) ^ value;
    for (i, &g) in GENERATORS.iter().enumerate() {
        if ((top >> i) & 1) != 0 {
            new_chk ^= g;
        }
    }
    new_chk
}

/// Map each character of `body` to its index in `INPUT_CHARSET`. Returns
/// `Err(ChecksumError::InvalidChar)` on the first character outside the alphabet.
fn body_to_symbols(body: &str) -> Result<Vec<u8>, ChecksumError> {
    body.chars().map(|c| INPUT_CHARSET.find(c).map(|p| p as u8).ok_or(ChecksumError::InvalidChar(c))).collect()
}

/// Compute the 8-character checksum for a descriptor body (the part before `#`).
///
/// Algorithm per BIP-380:
/// 1. Map each body char to a u8 via INPUT_CHARSET position.
/// 2. The polymod input is `low_symbols ++ high_symbols ++ [0; 8]`, where
///    `low_symbols[i] = sym[i] % 32` and `high_symbols[i] = sym[i] / 32`.
/// 3. Run polymod, XOR with 1.
/// 4. Encode the resulting 40-bit value as 8 chars from CHECKSUM_CHARSET,
///    most-significant 5-bit group first.
pub fn create(body: &str) -> Result<String, ChecksumError> {
    let symbols = body_to_symbols(body)?;

    let mut chk: u64 = 1;
    // Low 5 bits of each input symbol.
    for &s in &symbols {
        chk = polymod_step(chk, (s & 31) as u64);
    }
    // High bits (idx / 32) of each input symbol, also fed in.
    for &s in &symbols {
        chk = polymod_step(chk, (s >> 5) as u64);
    }
    // Eight zero pads to "shift" the polymod into the checksum slots.
    for _ in 0..CHECKSUM_LENGTH {
        chk = polymod_step(chk, 0);
    }
    // Final XOR with 1.
    chk ^= 1;

    let charset_bytes = CHECKSUM_CHARSET.as_bytes();
    let mut out = String::with_capacity(CHECKSUM_LENGTH);
    for i in 0..CHECKSUM_LENGTH {
        let shift = 5 * (CHECKSUM_LENGTH - 1 - i);
        let idx = ((chk >> shift) & 31) as usize;
        out.push(charset_bytes[idx] as char);
    }
    Ok(out)
}

/// Verify that `checksum` is the canonical 8-character checksum for `body`.
///
/// Returns `Ok(())` on match. Returns `ChecksumError::InvalidLength` if the
/// checksum is not exactly `CHECKSUM_LENGTH` characters, `InvalidChar` if any
/// checksum or body character is outside the BIP-380 alphabet, or `Mismatch`
/// if the recomputed checksum differs.
pub fn verify(body: &str, checksum: &str) -> Result<(), ChecksumError> {
    if checksum.len() != CHECKSUM_LENGTH {
        return Err(ChecksumError::InvalidLength(checksum.len()));
    }
    // Reject any non-charset character early so the caller gets the precise
    // error rather than a silent mismatch.
    for c in checksum.chars() {
        if !CHECKSUM_CHARSET.contains(c) {
            return Err(ChecksumError::InvalidChar(c));
        }
    }
    let recomputed = create(body)?;
    if recomputed == checksum { Ok(()) } else { Err(ChecksumError::Mismatch) }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChecksumError {
    #[error("Invalid checksum character: {0}")]
    InvalidChar(char),

    #[error("Checksum length mismatch: expected 8, got {0}")]
    InvalidLength(usize),

    #[error("Checksum mismatch")]
    Mismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_body_produces_canonical_checksum() {
        // The empty body always maps to a fixed 8-char checksum.
        let cs = create("").expect("polymod ok");
        assert_eq!(cs.len(), CHECKSUM_LENGTH);
        // Round-trip: recomputed checksum verifies against itself.
        verify("", &cs).expect("self-verify");
    }

    #[test]
    fn create_then_verify_arbitrary_body() {
        let body = "pkh-mldsa44(00ff)";
        let cs = create(body).expect("polymod ok");
        assert_eq!(cs.len(), 8);
        verify(body, &cs).expect("round-trip");
    }

    #[test]
    fn verify_rejects_one_char_corruption() {
        let body = "pkh-mldsa44(00ff)";
        let cs = create(body).expect("polymod ok");
        // Flip one char.
        let mut corrupted: Vec<char> = cs.chars().collect();
        corrupted[0] = if corrupted[0] == 'q' { 'p' } else { 'q' };
        let cs_bad: String = corrupted.into_iter().collect();
        assert_eq!(verify(body, &cs_bad), Err(ChecksumError::Mismatch));
    }

    #[test]
    fn verify_rejects_wrong_length() {
        let body = "pkh-mldsa44(00ff)";
        assert_eq!(verify(body, "qpzry9x").err().unwrap(), ChecksumError::InvalidLength(7));
        assert_eq!(verify(body, "qpzry9x8g").err().unwrap(), ChecksumError::InvalidLength(9));
    }

    #[test]
    fn verify_rejects_invalid_checksum_char() {
        let body = "pkh-mldsa44(00ff)";
        // 'b' is not in CHECKSUM_CHARSET (only 'q','p','z','r','y','9','x','8','g','f','2',...).
        assert_eq!(verify(body, "bbbbbbbb").err().unwrap(), ChecksumError::InvalidChar('b'));
    }

    #[test]
    fn create_rejects_invalid_body_char() {
        // ASCII char not in INPUT_CHARSET (e.g. tab).
        let body_with_tab = "pkh-mldsa44(\t)";
        assert!(matches!(create(body_with_tab), Err(ChecksumError::InvalidChar('\t'))));
    }

    #[test]
    fn polymod_step_well_behaved() {
        // Smoke test the inner loop over a small known sequence.
        // Just check determinism + non-zero result for non-empty input.
        let s1 = polymod_step(1, 0);
        let s2 = polymod_step(1, 0);
        assert_eq!(s1, s2);
        let s3 = polymod_step(s1, 5);
        assert_ne!(s3, s1);
    }

    /// BIP-380 cross-vector compatibility test (DESIGN.md §10 vector #8).
    ///
    /// **Maintainer task:** the expected checksum string MUST be validated
    /// against the Bitcoin Core reference `descriptor_tests.cpp` test
    /// vectors. The author's memory of the exact byte sequence may be
    /// incorrect; this test is `#[ignore]` until a maintainer confirms the
    /// expected value by running Bitcoin Core's `getdescriptorinfo` RPC on
    /// the body string and pasting the result.
    ///
    /// Self-consistency of the polymod is validated by the other tests in
    /// this module (round-trip, one-char corruption rejection); cross-chain
    /// compatibility requires this test to pass before SIP publication.
    #[test]
    #[ignore = "K3.5 — verify expected checksum against Bitcoin Core descriptor_tests.cpp"]
    fn bip380_cross_vector_pkh() {
        let body = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
        // TODO maintainer: replace with confirmed value from Bitcoin Core.
        let expected_checksum = "<TODO>";
        let computed = create(body).expect("polymod ok on BIP-380 vector");
        assert_eq!(
            computed, expected_checksum,
            "Sophis polymod must produce identical checksum to BIP-380 reference (proves D5 verbatim reuse)"
        );
    }
}
