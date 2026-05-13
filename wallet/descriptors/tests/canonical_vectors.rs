//! Canonical test vectors for the Sophis descriptor language.
//!
//! These vectors use the same deterministic Dilithium seeds as the PSBS
//! K1.3 tests (`wallet/pskt/src/bundle.rs::tests`), so descriptor output
//! is reproducible across the wallet stack and across implementations.
//!
//! See `wallet/descriptors/DESIGN.md` §10 for the test plan rationale.

use libcrux_ml_dsa::ml_dsa_44;
use sophis_wallet_descriptors::fingerprint::fingerprint;
use sophis_wallet_descriptors::types::{Descriptor, DescriptorKey, KeyData};
use sophis_wallet_descriptors::{ParseError, ResolveError};
use sophis_wallet_pskt::crypto::{DILITHIUM44_VK_SIZE, DilithiumPubKey};

/// Same canonical seed used in `wallet/pskt/src/bundle.rs` K1.3 tests.
const PSBS_TEST_SEED_ALPHA: [u8; 32] = *b"PSBS_test_seed_alpha____________";
const PSBS_TEST_SEED_BETA: [u8; 32] = *b"PSBS_test_seed_beta_____________";

fn vk_from_seed(seed: [u8; 32]) -> DilithiumPubKey {
    let kp = ml_dsa_44::generate_key_pair(seed);
    DilithiumPubKey::from_bytes(*kp.verification_key.as_ref())
}

#[test]
fn canonical_vector_pkh_round_trip() {
    let vk = vk_from_seed(PSBS_TEST_SEED_ALPHA);
    let original = Descriptor::Pkh { key: DescriptorKey::new_literal(vk.clone()) };
    let canonical_text = original.to_string();

    // Spot-check structural form.
    assert!(canonical_text.starts_with("pkh-mldsa44("));
    assert!(canonical_text.contains('#'));
    assert_eq!(canonical_text.matches('#').count(), 1, "exactly one `#` separator");

    // Round-trip MUST be byte-identical.
    let parsed: Descriptor = canonical_text.parse().expect("parse canonical");
    assert_eq!(original, parsed);
    assert_eq!(canonical_text, parsed.to_string());

    // Resolve produces a singleton non-empty SPK.
    let spks = parsed.resolve().expect("resolve");
    assert_eq!(spks.len(), 1);
    assert!(!spks[0].script().is_empty());
}

#[test]
fn canonical_vector_pkh_with_origin_round_trip() {
    let vk = vk_from_seed(PSBS_TEST_SEED_ALPHA);
    let fp = fingerprint(&vk);

    use sophis_wallet_descriptors::types::{DerivationStep, KeyOrigin};
    let origin = KeyOrigin {
        fingerprint: fp,
        derivation_path: vec![
            DerivationStep { index: 44, hardened: true },
            DerivationStep { index: 2025, hardened: true },
            DerivationStep { index: 0, hardened: true },
        ],
    };
    let original = Descriptor::Pkh { key: DescriptorKey { origin: Some(origin), data: KeyData::VkHex(Box::new(vk)) } };
    let canonical_text = original.to_string();

    assert!(canonical_text.contains(&format!("[{}/", fp.to_hex())));

    let parsed: Descriptor = canonical_text.parse().expect("parse with origin");
    assert_eq!(original, parsed);
    assert_eq!(canonical_text, parsed.to_string());
}

#[test]
fn canonical_vector_multi_2of3_round_trip_but_resolve_fails() {
    let vk_a = vk_from_seed(PSBS_TEST_SEED_ALPHA);
    let vk_b = vk_from_seed(PSBS_TEST_SEED_BETA);
    let mut seed_c = PSBS_TEST_SEED_ALPHA;
    seed_c[0] ^= 0xff;
    let vk_c = vk_from_seed(seed_c);

    let original = Descriptor::Multi {
        threshold: 2,
        keys: vec![DescriptorKey::new_literal(vk_a), DescriptorKey::new_literal(vk_b), DescriptorKey::new_literal(vk_c)],
    };
    let canonical_text = original.to_string();
    let parsed: Descriptor = canonical_text.parse().expect("parse multi");
    assert_eq!(original, parsed);
    assert_eq!(canonical_text, parsed.to_string());

    // Per D2: multi resolves to MultiSigNotYetSupported in v1.
    assert_eq!(parsed.resolve().unwrap_err(), ResolveError::MultiSigNotYetSupported);
}

#[test]
fn canonical_vector_xpub_parsed_but_resolve_rejects() {
    use sophis_wallet_descriptors::checksum;
    let body = "pkh-mldsa44(xpub6ASuArnXKPbf...placeholder/0/*)";
    let cs = checksum::create(body).expect("checksum");
    let input = format!("{}#{}", body, cs);

    let parsed: Descriptor = input.parse().expect("xpub syntax parses");
    match &parsed {
        Descriptor::Pkh { key } => match &key.data {
            KeyData::XpubReserved(s) => assert!(s.starts_with("xpub")),
            _ => panic!("expected XpubReserved"),
        },
        _ => panic!("expected Pkh"),
    }

    // Per D1: xpub resolves to HdDerivationNotYetSupported in v1.
    assert_eq!(parsed.resolve().unwrap_err(), ResolveError::HdDerivationNotYetSupported);
}

#[test]
fn canonical_vector_one_char_corruption_rejected_by_checksum() {
    let vk = vk_from_seed(PSBS_TEST_SEED_ALPHA);
    let original = Descriptor::Pkh { key: DescriptorKey::new_literal(vk) };
    let canonical_text = original.to_string();

    // Corrupt one character in the checksum portion.
    let pound_pos = canonical_text.rfind('#').unwrap();
    let mut corrupted: Vec<char> = canonical_text.chars().collect();
    let cs_first_char_pos = canonical_text[..pound_pos].chars().count() + 1;
    corrupted[cs_first_char_pos] = if corrupted[cs_first_char_pos] == 'q' { 'p' } else { 'q' };
    let corrupted_text: String = corrupted.into_iter().collect();

    assert!(matches!(corrupted_text.parse::<Descriptor>(), Err(ParseError::ChecksumMismatch { .. })));
}

#[test]
fn canonical_vector_resolve_matches_dilithium_redeem_script_path() {
    use sophis_txscript::standard::{dilithium_redeem_script, pay_to_script_hash_script};

    let vk = vk_from_seed(PSBS_TEST_SEED_ALPHA);
    let d = Descriptor::Pkh { key: DescriptorKey::new_literal(vk.clone()) };
    let descriptor_spk = &d.resolve().expect("ok")[0];

    // Independent path: same vk → same redeem_script → same SPK.
    let redeem = dilithium_redeem_script(vk.as_bytes()).expect("redeem");
    let direct_spk = pay_to_script_hash_script(&redeem);

    assert_eq!(
        descriptor_spk, &direct_spk,
        "Descriptor resolve MUST match direct dilithium_redeem_script + pay_to_script_hash_script"
    );
}

#[test]
fn canonical_vector_fingerprint_deterministic_alpha() {
    let vk = vk_from_seed(PSBS_TEST_SEED_ALPHA);
    let fp1 = fingerprint(&vk);
    let fp2 = fingerprint(&vk);
    assert_eq!(fp1, fp2);
    // Spot-check that the fingerprint is non-zero (defense against silent
    // SHA3-384 implementation bug).
    assert_ne!(fp1.as_bytes(), &[0u8; 4]);
}

#[test]
fn canonical_vector_threshold_boundaries() {
    use sophis_wallet_descriptors::checksum;

    // Construct multi-mldsa44(0,...) which MUST be rejected (threshold = 0).
    let vk_hex = hex::encode([0x42u8; DILITHIUM44_VK_SIZE]);
    let body_zero = format!("multi-mldsa44(0,{})", vk_hex);
    let cs_zero = checksum::create(&body_zero).expect("checksum");
    let input_zero = format!("{}#{}", body_zero, cs_zero);
    assert!(matches!(input_zero.parse::<Descriptor>(), Err(ParseError::ThresholdOutOfRange { .. })));

    // multi-mldsa44(2,k) with only 1 key MUST be rejected (threshold > count).
    let body_overflow = format!("multi-mldsa44(2,{})", vk_hex);
    let cs_over = checksum::create(&body_overflow).expect("checksum");
    let input_over = format!("{}#{}", body_overflow, cs_over);
    assert!(matches!(input_over.parse::<Descriptor>(), Err(ParseError::ThresholdOutOfRange { .. })));
}
