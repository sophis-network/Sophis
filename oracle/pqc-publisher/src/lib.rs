//! Library surface for `sophis-oracle-publisher` — pure helpers that the
//! CLI calls. Exposing them here makes them native-testable without
//! launching the binary.
//!
//! No I/O lives in this module; the binary handles file reads, stdout
//! writes, and clap parsing.

use sophis_bip39::{Language, Mnemonic};
use sophis_oracle_pqc_core::{
    DILITHIUM_PUBKEY_SIZE, DILITHIUM_SIGNING_KEY_SIZE, KEY_GENERATION_RANDOMNESS_SIZE,
    OraclePqcError, PriceAttestation, PriceAttestationCore, SIGNING_RANDOMNESS_SIZE,
    asset_id_from_symbol, generate_keypair, sign_attestation, verify_attestation,
};
use thiserror::Error;

/// Fixed-point exponent applied to decimal price / confidence strings.
/// Per SIP-11 D9 the wire format pins the exponent at -8 (price_e8 =
/// price × 10^8). Match Pyth conventions for direct interoperability.
pub const FIXED_POINT_EXPONENT: u32 = 8;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PublisherError {
    #[error("invalid mnemonic phrase: {0}")]
    InvalidMnemonic(String),

    #[error("decimal parse error: '{0}' is not a base-10 number with at most 8 fractional digits")]
    InvalidDecimal(String),

    #[error("decimal value overflows i64 at the e8 fixed-point scale")]
    DecimalOverflow,

    #[error("negative confidence interval is not permitted")]
    NegativeConfidence,

    #[error("expected hex bytes, got malformed input")]
    InvalidHex,

    #[error("signing key must be exactly {DILITHIUM_SIGNING_KEY_SIZE} bytes")]
    SigningKeyLength,

    #[error("public key must be exactly {DILITHIUM_PUBKEY_SIZE} bytes")]
    PublicKeyLength,

    #[error("attestation core could not be signed: {0:?}")]
    SignFailed(OraclePqcError),

    #[error("attestation could not be verified: {0:?}")]
    VerifyFailed(OraclePqcError),
}

/// Parse a base-10 decimal string like `"65000.00"` into `i64`-scaled
/// price_e8 (price × 10^8). Accepts optional minus sign and up to 8
/// fractional digits; rejects scientific notation and more granular
/// fractions to keep parsing deterministic.
pub fn parse_decimal_e8_signed(s: &str) -> Result<i64, PublisherError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(PublisherError::InvalidDecimal(s.to_string()));
    }

    let (negative, body) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };

    let (int_part, frac_part) = match body.split_once('.') {
        Some((i, f)) => (i, f),
        None => (body, ""),
    };

    if int_part.is_empty() && frac_part.is_empty() {
        return Err(PublisherError::InvalidDecimal(s.to_string()));
    }
    if int_part.contains(|c: char| !c.is_ascii_digit()) {
        return Err(PublisherError::InvalidDecimal(s.to_string()));
    }
    if frac_part.contains(|c: char| !c.is_ascii_digit()) {
        return Err(PublisherError::InvalidDecimal(s.to_string()));
    }
    if frac_part.len() > FIXED_POINT_EXPONENT as usize {
        return Err(PublisherError::InvalidDecimal(s.to_string()));
    }

    // Compose the e8-scaled value: int_part * 10^8 + frac_part * 10^(8 - len(frac_part))
    let int_value: i64 = if int_part.is_empty() {
        0
    } else {
        int_part.parse::<i64>().map_err(|_| PublisherError::DecimalOverflow)?
    };
    let scale = 10i64.pow(FIXED_POINT_EXPONENT);
    let int_scaled = int_value.checked_mul(scale).ok_or(PublisherError::DecimalOverflow)?;

    let frac_padded_scaled: i64 = if frac_part.is_empty() {
        0
    } else {
        let frac_value: i64 = frac_part.parse::<i64>().map_err(|_| PublisherError::DecimalOverflow)?;
        let pad = FIXED_POINT_EXPONENT as usize - frac_part.len();
        frac_value
            .checked_mul(10i64.pow(pad as u32))
            .ok_or(PublisherError::DecimalOverflow)?
    };

    let unsigned = int_scaled.checked_add(frac_padded_scaled).ok_or(PublisherError::DecimalOverflow)?;
    let signed = if negative {
        unsigned.checked_neg().ok_or(PublisherError::DecimalOverflow)?
    } else {
        unsigned
    };
    Ok(signed)
}

/// Parse a base-10 decimal as `u64` price_e8; rejects negative values.
/// Used for confidence intervals which the wire format types as `u64`.
pub fn parse_decimal_e8_unsigned(s: &str) -> Result<u64, PublisherError> {
    let signed = parse_decimal_e8_signed(s)?;
    if signed < 0 {
        return Err(PublisherError::NegativeConfidence);
    }
    Ok(signed as u64)
}

/// Derive a Dilithium ML-DSA-44 keypair from a BIP-39 mnemonic phrase
/// using the same path `dilithium-wallet` uses: BIP-39 PBKDF2-HMAC-SHA-512
/// → 64-byte seed → first 32 bytes as ML-DSA-44 key-generation randomness.
pub fn derive_keypair_from_mnemonic(
    phrase: &str,
) -> Result<([u8; DILITHIUM_PUBKEY_SIZE], [u8; DILITHIUM_SIGNING_KEY_SIZE]), PublisherError> {
    let mnemonic = Mnemonic::new(phrase.trim(), Language::English)
        .map_err(|e| PublisherError::InvalidMnemonic(e.to_string()))?;
    let seed = mnemonic.to_seed("");
    let mut randomness = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
    randomness.copy_from_slice(&seed.as_bytes()[..KEY_GENERATION_RANDOMNESS_SIZE]);
    let (vk, sk) = generate_keypair(randomness);
    randomness.iter_mut().for_each(|b| *b = 0);
    Ok((vk, sk))
}

/// Build and sign a price attestation. The caller supplies the keypair
/// (derived from a mnemonic or loaded from a raw signing-key file) and
/// the per-update randomness (typically OS-generated).
#[allow(clippy::too_many_arguments)]
pub fn build_and_sign_attestation(
    symbol: &[u8],
    price_e8: i64,
    conf_e8: u64,
    publish_ts: u64,
    sequence: u64,
    pubkey: [u8; DILITHIUM_PUBKEY_SIZE],
    signing_key: &[u8; DILITHIUM_SIGNING_KEY_SIZE],
    sign_randomness: [u8; SIGNING_RANDOMNESS_SIZE],
) -> Result<PriceAttestation, PublisherError> {
    let core = PriceAttestationCore {
        asset_id: asset_id_from_symbol(symbol),
        price_e8,
        conf_e8,
        publish_ts,
        sequence,
    };
    sign_attestation(core, pubkey, signing_key, sign_randomness).map_err(PublisherError::SignFailed)
}

/// Encode a `PriceAttestation` as lowercase hex (no `0x` prefix).
pub fn encode_attestation_hex(attestation: &PriceAttestation) -> Result<String, PublisherError> {
    let bytes = attestation.to_bytes().map_err(PublisherError::SignFailed)?;
    let mut buf = vec![0u8; bytes.len() * 2];
    faster_hex::hex_encode(&bytes, &mut buf).map_err(|_| PublisherError::InvalidHex)?;
    String::from_utf8(buf).map_err(|_| PublisherError::InvalidHex)
}

/// Decode a `PriceAttestation` from lowercase hex (no `0x` prefix).
pub fn decode_attestation_hex(hex: &str) -> Result<PriceAttestation, PublisherError> {
    let trimmed = hex.trim();
    if trimmed.len() % 2 != 0 {
        return Err(PublisherError::InvalidHex);
    }
    let mut bytes = vec![0u8; trimmed.len() / 2];
    faster_hex::hex_decode(trimmed.as_bytes(), &mut bytes).map_err(|_| PublisherError::InvalidHex)?;
    PriceAttestation::from_bytes(&bytes).map_err(|_| PublisherError::InvalidHex)
}

/// Verify a `PriceAttestation` against the canonical Phase 9 domain
/// separator and a caller-supplied `now`. Thin wrapper over the
/// `oracle-pqc-core` verifier; surfaces a `PublisherError::VerifyFailed`
/// so the CLI can report uniformly.
pub fn verify_attestation_at(
    attestation: &PriceAttestation,
    now: u64,
) -> Result<(), PublisherError> {
    verify_attestation(attestation, now).map_err(PublisherError::VerifyFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- decimal parsing ---

    #[test]
    fn parse_decimal_integer_only() {
        assert_eq!(parse_decimal_e8_signed("65000").unwrap(), 65_000_00000000);
        assert_eq!(parse_decimal_e8_signed("0").unwrap(), 0);
        assert_eq!(parse_decimal_e8_signed("-1").unwrap(), -1_00000000);
    }

    #[test]
    fn parse_decimal_with_fraction() {
        assert_eq!(parse_decimal_e8_signed("1.5").unwrap(), 1_50000000);
        assert_eq!(parse_decimal_e8_signed("0.00000001").unwrap(), 1);
        assert_eq!(parse_decimal_e8_signed("65000.00").unwrap(), 65_000_00000000);
        assert_eq!(parse_decimal_e8_signed("-0.5").unwrap(), -50_000_000);
    }

    #[test]
    fn parse_decimal_rejects_too_many_fractional_digits() {
        assert!(parse_decimal_e8_signed("1.123456789").is_err());
    }

    #[test]
    fn parse_decimal_rejects_garbage() {
        assert!(parse_decimal_e8_signed("not a number").is_err());
        assert!(parse_decimal_e8_signed("1.2.3").is_err());
        assert!(parse_decimal_e8_signed("1e5").is_err());
        assert!(parse_decimal_e8_signed("").is_err());
        assert!(parse_decimal_e8_signed(".").is_err());
    }

    #[test]
    fn parse_decimal_unsigned_rejects_negative() {
        assert_eq!(parse_decimal_e8_unsigned("0").unwrap(), 0);
        assert_eq!(parse_decimal_e8_unsigned("1.5").unwrap(), 1_50000000);
        assert_eq!(parse_decimal_e8_unsigned("-1").err(), Some(PublisherError::NegativeConfidence));
    }

    // --- key derivation ---

    const FIXTURE_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn keypair_derivation_is_deterministic() {
        let (vk1, sk1) = derive_keypair_from_mnemonic(FIXTURE_MNEMONIC).unwrap();
        let (vk2, sk2) = derive_keypair_from_mnemonic(FIXTURE_MNEMONIC).unwrap();
        assert_eq!(vk1, vk2);
        assert_eq!(sk1, sk2);
    }

    #[test]
    fn keypair_derivation_rejects_bad_mnemonic() {
        let res = derive_keypair_from_mnemonic("clearly not a valid bip39 phrase");
        assert!(matches!(res, Err(PublisherError::InvalidMnemonic(_))));
    }

    // --- sign + verify roundtrip ---

    #[test]
    fn sign_verify_roundtrip_through_hex() {
        let (vk, sk) = derive_keypair_from_mnemonic(FIXTURE_MNEMONIC).unwrap();
        let sign_randomness = [0x33u8; SIGNING_RANDOMNESS_SIZE];
        let attestation = build_and_sign_attestation(
            b"BTC/USD",
            65_000_00000000,
            50_00000000,
            1_700_000_000,
            42,
            vk,
            &sk,
            sign_randomness,
        )
        .unwrap();

        let hex = encode_attestation_hex(&attestation).unwrap();
        // SIP-11 § 3.2 frozen size 3796 bytes → 7592 hex chars.
        assert_eq!(hex.len(), 7592);

        let decoded = decode_attestation_hex(&hex).unwrap();
        verify_attestation_at(&decoded, 1_700_000_000).unwrap();
    }

    #[test]
    fn decode_rejects_odd_length_hex() {
        assert_eq!(decode_attestation_hex("abc").err(), Some(PublisherError::InvalidHex));
    }

    #[test]
    fn decode_rejects_non_hex_characters() {
        assert_eq!(decode_attestation_hex("zz").err(), Some(PublisherError::InvalidHex));
    }

    #[test]
    fn verify_rejects_tampered_hex() {
        let (vk, sk) = derive_keypair_from_mnemonic(FIXTURE_MNEMONIC).unwrap();
        let sign_randomness = [0x77u8; SIGNING_RANDOMNESS_SIZE];
        let attestation = build_and_sign_attestation(
            b"ETH/USD",
            3_500_00000000,
            10_00000000,
            1_700_000_001,
            7,
            vk,
            &sk,
            sign_randomness,
        )
        .unwrap();

        let mut hex = encode_attestation_hex(&attestation).unwrap().into_bytes();
        // Mutate one hex character deep inside the signature region.
        let pivot = hex.len() / 2;
        hex[pivot] = if hex[pivot] == b'a' { b'b' } else { b'a' };
        let mutated = String::from_utf8(hex).unwrap();

        let decoded = decode_attestation_hex(&mutated).unwrap();
        assert!(matches!(
            verify_attestation_at(&decoded, 1_700_000_001),
            Err(PublisherError::VerifyFailed(_)),
        ));
    }
}
