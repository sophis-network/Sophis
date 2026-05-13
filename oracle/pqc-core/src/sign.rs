//! Sign / verify helpers for `PriceAttestation` using
//! Dilithium ML-DSA-44 via `libcrux-ml-dsa`.
//!
//! Same primitive Sophis L1 consensus uses for transaction signing.
//! See `docs/PQC_NATIVE_ORACLE_DESIGN.md` § 3.4 for the signing-hash
//! construction.

use libcrux_ml_dsa::ml_dsa_44::{self, MLDSA44Signature, MLDSA44SigningKey, MLDSA44VerificationKey};

use crate::error::OraclePqcError;
use crate::types::{
    DILITHIUM_PUBKEY_SIZE, DILITHIUM_SIG_SIZE, DILITHIUM_SIGNING_KEY_SIZE, DOMAIN_SEPARATOR, PriceAttestation, PriceAttestationCore,
    compute_signing_hash,
};

/// Bytes of fresh randomness `generate_keypair` needs.
pub const KEY_GENERATION_RANDOMNESS_SIZE: usize = libcrux_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE;

/// Bytes of fresh randomness `sign_attestation` needs.
pub const SIGNING_RANDOMNESS_SIZE: usize = libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE;

/// Generate a fresh Dilithium ML-DSA-44 keypair from caller-supplied
/// randomness. Suitable for tests and for a publisher's offline
/// keygen tool; production publishers should derive from a BIP-39
/// mnemonic via the same path `dilithium-wallet` uses (first 32 bytes
/// of the PBKDF2-SHA-512 seed).
pub fn generate_keypair(
    randomness: [u8; KEY_GENERATION_RANDOMNESS_SIZE],
) -> ([u8; DILITHIUM_PUBKEY_SIZE], [u8; DILITHIUM_SIGNING_KEY_SIZE]) {
    let kp = ml_dsa_44::generate_key_pair(randomness);
    let vk: [u8; DILITHIUM_PUBKEY_SIZE] = *kp.verification_key.as_ref();
    let sk: [u8; DILITHIUM_SIGNING_KEY_SIZE] = *kp.signing_key.as_ref();
    (vk, sk)
}

/// Sign a `PriceAttestationCore` under the canonical Phase 9 domain
/// separator. Returns the assembled `PriceAttestation` ready for
/// borsh-encoding into a transaction payload.
pub fn sign_attestation(
    core: PriceAttestationCore,
    publisher_pubkey: [u8; DILITHIUM_PUBKEY_SIZE],
    signing_key: &[u8; DILITHIUM_SIGNING_KEY_SIZE],
    randomness: [u8; SIGNING_RANDOMNESS_SIZE],
) -> Result<PriceAttestation, OraclePqcError> {
    let signing_hash = compute_signing_hash(DOMAIN_SEPARATOR, &core);
    let sk = MLDSA44SigningKey::new(*signing_key);
    let sig: MLDSA44Signature = ml_dsa_44::sign(&sk, &signing_hash, b"", randomness).map_err(|_| OraclePqcError::InvalidSignature)?;
    let sig_bytes: [u8; DILITHIUM_SIG_SIZE] = *sig.as_ref();
    Ok(PriceAttestation { core, publisher_pubkey, signature: Box::new(sig_bytes) })
}

/// Verify an attestation under the canonical Phase 9 domain
/// separator. Cheap shape checks run first (price sentinel,
/// confidence overflow, timestamp skew against `now`); Dilithium
/// verify runs last because it is the expensive step.
///
/// Returns `Ok(())` if the attestation is valid and `now` falls within
/// `MAX_SKEW_SECS` of `core.publish_ts`. Otherwise returns the
/// corresponding `OraclePqcError`.
pub fn verify_attestation(attestation: &PriceAttestation, now: u64) -> Result<(), OraclePqcError> {
    verify_attestation_with_domain(attestation, now, DOMAIN_SEPARATOR)
}

/// Variant of [`verify_attestation`] that accepts a custom domain
/// separator. Exposed for test coverage of cross-domain replay
/// rejection; production consumers MUST use [`verify_attestation`]
/// to pin themselves to the canonical Phase 9 domain.
pub fn verify_attestation_with_domain(attestation: &PriceAttestation, now: u64, domain: &[u8]) -> Result<(), OraclePqcError> {
    attestation.validate_shape(now)?;

    let signing_hash = compute_signing_hash(domain, &attestation.core);
    let vk = MLDSA44VerificationKey::new(attestation.publisher_pubkey);
    let sig = MLDSA44Signature::new(*attestation.signature);
    ml_dsa_44::verify(&vk, &signing_hash, b"", &sig).map_err(|_| OraclePqcError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::asset_id_from_symbol;

    fn fixed_keypair() -> ([u8; DILITHIUM_PUBKEY_SIZE], [u8; DILITHIUM_SIGNING_KEY_SIZE]) {
        let randomness = [7u8; KEY_GENERATION_RANDOMNESS_SIZE];
        generate_keypair(randomness)
    }

    fn fixed_core() -> PriceAttestationCore {
        PriceAttestationCore {
            asset_id: asset_id_from_symbol(b"BTC/USD"),
            price_e8: 65_000_00000000,
            conf_e8: 50_00000000,
            publish_ts: 1_700_000_000,
            sequence: 42,
        }
    }

    #[test]
    fn sign_then_verify_happy_path() {
        let (vk, sk) = fixed_keypair();
        let core = fixed_core();
        let randomness = [3u8; SIGNING_RANDOMNESS_SIZE];
        let attestation = sign_attestation(core, vk, &sk, randomness).unwrap();
        assert!(verify_attestation(&attestation, core.publish_ts).is_ok());
    }

    #[test]
    fn borsh_roundtrip_preserves_attestation() {
        let (vk, sk) = fixed_keypair();
        let core = fixed_core();
        let randomness = [11u8; SIGNING_RANDOMNESS_SIZE];
        let original = sign_attestation(core, vk, &sk, randomness).unwrap();
        let bytes = original.to_bytes().unwrap();
        // SIP-11 § 3.2 frozen total size.
        assert_eq!(bytes.len(), 64 + DILITHIUM_PUBKEY_SIZE + DILITHIUM_SIG_SIZE);
        let decoded = PriceAttestation::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.core, original.core);
        assert_eq!(decoded.publisher_pubkey, original.publisher_pubkey);
        assert_eq!(*decoded.signature, *original.signature);
        // Decoded attestation must still verify.
        assert!(verify_attestation(&decoded, core.publish_ts).is_ok());
    }

    #[test]
    fn malformed_bytes_rejected_at_decode() {
        let res = PriceAttestation::from_bytes(b"this is not a valid attestation");
        assert_eq!(res.err(), Some(OraclePqcError::DecodeFailed));
    }

    #[test]
    fn tampered_signature_fails_verify() {
        let (vk, sk) = fixed_keypair();
        let core = fixed_core();
        let randomness = [5u8; SIGNING_RANDOMNESS_SIZE];
        let mut attestation = sign_attestation(core, vk, &sk, randomness).unwrap();
        // Flip a bit in the signature middle (well inside the encoded sig).
        attestation.signature[1000] ^= 0x01;
        assert_eq!(verify_attestation(&attestation, core.publish_ts).err(), Some(OraclePqcError::InvalidSignature),);
    }

    #[test]
    fn tampered_core_fails_verify() {
        let (vk, sk) = fixed_keypair();
        let core = fixed_core();
        let randomness = [9u8; SIGNING_RANDOMNESS_SIZE];
        let mut attestation = sign_attestation(core, vk, &sk, randomness).unwrap();
        // Move the price by $1 — the signing-hash no longer matches.
        attestation.core.price_e8 += 100_000_000;
        assert_eq!(verify_attestation(&attestation, core.publish_ts).err(), Some(OraclePqcError::InvalidSignature),);
    }

    #[test]
    fn wrong_publisher_pubkey_fails_verify() {
        let (_vk_a, sk_a) = fixed_keypair();
        // Different randomness → different keypair.
        let randomness_b = [13u8; KEY_GENERATION_RANDOMNESS_SIZE];
        let (vk_b, _sk_b) = generate_keypair(randomness_b);
        let core = fixed_core();
        let sign_randomness = [17u8; SIGNING_RANDOMNESS_SIZE];
        // Sign with A's signing key, but stamp B's pubkey onto the attestation.
        let mut attestation = sign_attestation(core, vk_b, &sk_a, sign_randomness).unwrap();
        // (The pubkey on the attestation is already B's; sign_attestation accepted
        // whatever we passed.) Verification under B's pubkey must fail because A
        // produced the signature.
        let _ = &mut attestation;
        assert_eq!(verify_attestation(&attestation, core.publish_ts).err(), Some(OraclePqcError::InvalidSignature),);
    }

    #[test]
    fn cross_domain_replay_rejected() {
        let (vk, sk) = fixed_keypair();
        let core = fixed_core();
        let randomness = [19u8; SIGNING_RANDOMNESS_SIZE];
        let attestation = sign_attestation(core, vk, &sk, randomness).unwrap();
        // Same attestation, wrong domain — must not validate.
        let other_domain = b"sophis-other-domain\0";
        assert_eq!(
            verify_attestation_with_domain(&attestation, core.publish_ts, other_domain).err(),
            Some(OraclePqcError::InvalidSignature),
        );
    }

    #[test]
    fn far_future_timestamp_rejected() {
        let (vk, sk) = fixed_keypair();
        let core = fixed_core();
        let randomness = [21u8; SIGNING_RANDOMNESS_SIZE];
        let attestation = sign_attestation(core, vk, &sk, randomness).unwrap();
        // `now` is far in the past relative to publish_ts.
        let now = core.publish_ts - super::super::types::MAX_SKEW_SECS - 1;
        assert_eq!(verify_attestation(&attestation, now).err(), Some(OraclePqcError::TimestampOutOfSkew));
    }

    #[test]
    fn far_past_timestamp_rejected() {
        let (vk, sk) = fixed_keypair();
        let core = fixed_core();
        let randomness = [23u8; SIGNING_RANDOMNESS_SIZE];
        let attestation = sign_attestation(core, vk, &sk, randomness).unwrap();
        // `now` is far in the future relative to publish_ts.
        let now = core.publish_ts + super::super::types::MAX_SKEW_SECS + 1;
        assert_eq!(verify_attestation(&attestation, now).err(), Some(OraclePqcError::TimestampOutOfSkew));
    }

    #[test]
    fn price_sentinel_rejected_in_shape_check() {
        let (vk, sk) = fixed_keypair();
        let core = PriceAttestationCore { price_e8: i64::MIN, ..fixed_core() };
        let randomness = [25u8; SIGNING_RANDOMNESS_SIZE];
        let attestation = sign_attestation(core, vk, &sk, randomness).unwrap();
        assert_eq!(verify_attestation(&attestation, core.publish_ts).err(), Some(OraclePqcError::InvalidPrice),);
    }

    #[test]
    fn confidence_overflow_rejected_in_shape_check() {
        let (vk, sk) = fixed_keypair();
        let core = PriceAttestationCore { conf_e8: u64::MAX, ..fixed_core() };
        let randomness = [27u8; SIGNING_RANDOMNESS_SIZE];
        let attestation = sign_attestation(core, vk, &sk, randomness).unwrap();
        assert_eq!(verify_attestation(&attestation, core.publish_ts).err(), Some(OraclePqcError::InvalidConfidence),);
    }

    #[test]
    fn asset_id_deterministic_and_separator_sensitive() {
        let with_slash = asset_id_from_symbol(b"BTC/USD");
        let without_slash = asset_id_from_symbol(b"BTCUSD");
        assert_ne!(with_slash, without_slash);
        // Determinism: hashing the same input twice yields the same id.
        assert_eq!(with_slash, asset_id_from_symbol(b"BTC/USD"));
    }
}
