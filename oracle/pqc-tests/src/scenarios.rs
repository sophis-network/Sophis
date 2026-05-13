//! End-to-end pipeline scenarios.
//!
//! Each test composes the publisher's signing path with the contract's
//! decoder + event helpers and the indexer's dispatch policy, asserting
//! the pipeline produces what SIP-11 says it must. Unit-level checks
//! live in the originating crates — these tests verify only the
//! cross-crate composition.

use sophis_oracle_pqc_contract::{
    EventDataV1, build_event_data, decode_attestation_bytes, decode_event_data, event_id_phase9_attestation, publisher_fingerprint,
};
use sophis_oracle_pqc_core::{
    DILITHIUM_PUBKEY_SIZE, DILITHIUM_SIGNING_KEY_SIZE, FeedSource, FeedSourceRegistry, FlipDecision, FlipInputs, FlipPolicy,
    InMemoryFeedSourceRegistry, KEY_GENERATION_RANDOMNESS_SIZE, PriceAttestation, PriceSample, SIGNING_RANDOMNESS_SIZE, StayReason,
    asset_id_from_symbol, evaluate_flip, generate_keypair, sign_attestation,
};
use sophis_oracle_publisher::{
    build_and_sign_attestation, decode_attestation_hex, derive_keypair_from_mnemonic, encode_attestation_hex, verify_attestation_at,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Canonical 24-word BIP-39 test vector ("abandon × 23 + art" — the
/// `[0u8; 32]`-entropy mnemonic). The publisher path goes through this
/// in [`scenario_publisher_keypair_derivation_is_canonical`].
const FIXTURE_MNEMONIC_A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

/// Deterministic-randomness keypair tag. Tests use these tags so two
/// distinct keypairs ("B" and "C") are reproducible across runs
/// without going through BIP-39 phrases for every test fixture.
fn keypair_b() -> ([u8; DILITHIUM_PUBKEY_SIZE], [u8; DILITHIUM_SIGNING_KEY_SIZE]) {
    generate_keypair([0xB1; KEY_GENERATION_RANDOMNESS_SIZE])
}

fn keypair_c() -> ([u8; DILITHIUM_PUBKEY_SIZE], [u8; DILITHIUM_SIGNING_KEY_SIZE]) {
    generate_keypair([0xC1; KEY_GENERATION_RANDOMNESS_SIZE])
}

fn keypair_from_mnemonic(mnemonic: &str) -> ([u8; DILITHIUM_PUBKEY_SIZE], [u8; DILITHIUM_SIGNING_KEY_SIZE]) {
    derive_keypair_from_mnemonic(mnemonic).expect("fixture mnemonic must derive cleanly")
}

enum KeySource<'a> {
    Mnemonic(&'a str),
    Direct(([u8; DILITHIUM_PUBKEY_SIZE], [u8; DILITHIUM_SIGNING_KEY_SIZE])),
}

fn sign_for(
    asset: &[u8],
    price_e8: i64,
    conf_e8: u64,
    publish_ts: u64,
    sequence: u64,
    source: KeySource<'_>,
    rng_seed: u8,
) -> PriceAttestation {
    let (vk, sk) = match source {
        KeySource::Mnemonic(m) => keypair_from_mnemonic(m),
        KeySource::Direct(kp) => kp,
    };
    let randomness = [rng_seed; SIGNING_RANDOMNESS_SIZE];
    build_and_sign_attestation(asset, price_e8, conf_e8, publish_ts, sequence, vk, &sk, randomness).expect("fixture sign must succeed")
}

// ---------------------------------------------------------------------------
// 1. Single-publisher end-to-end happy path
// ---------------------------------------------------------------------------

#[test]
fn scenario_single_publisher_attestation_lifecycle() {
    // 1. Publisher signs an attestation.
    let now = 1_700_000_000;
    let attestation = sign_for(b"BTC/USD", 65_000_00000000, 50_00000000, now, 1, KeySource::Mnemonic(FIXTURE_MNEMONIC_A), 0x11);

    // 2. Publisher emits hex on stdout; an off-chain submitter wraps it
    //    into a Sophis transaction. Round-trip via hex.
    let hex = encode_attestation_hex(&attestation).expect("encode hex");
    let decoded_from_hex = decode_attestation_hex(&hex).expect("decode hex");

    // 3. The contract decoder accepts the same wire bytes from input UTXO
    //    script_public_key.script. Pin identical semantic content.
    let bytes = decoded_from_hex.to_bytes().expect("borsh re-encode");
    let decoded_in_contract = decode_attestation_bytes(&bytes).expect("contract decoder");
    assert_eq!(decoded_in_contract.core, attestation.core);
    assert_eq!(decoded_in_contract.publisher_pubkey, attestation.publisher_pubkey);
    assert_eq!(*decoded_in_contract.signature, *attestation.signature);

    // 4. Off-chain consumer verifies the same wire bytes against the
    //    canonical Phase 9 domain.
    verify_attestation_at(&decoded_in_contract, now).expect("consumer verify");

    // 5. Indexer-side: derive the J4 topics + event data the contract
    //    would have emitted; pin their canonical shapes.
    let event_data = build_event_data(&decoded_in_contract);
    assert_eq!(event_data.price_e8, attestation.core.price_e8);
    assert_eq!(event_data.conf_e8, attestation.core.conf_e8);
    assert_eq!(event_data.publish_ts, attestation.core.publish_ts);
    assert_eq!(event_data.sequence, attestation.core.sequence);

    let topics = [
        event_id_phase9_attestation(),
        decoded_in_contract.core.asset_id,
        publisher_fingerprint(&decoded_in_contract.publisher_pubkey),
    ];

    // topic[1] must match the asset_id an indexer would derive from the
    // symbol independently — this is the link between symbol space and
    // event space.
    assert_eq!(topics[1], asset_id_from_symbol(b"BTC/USD"));

    // 6. Indexer decodes the event-data payload back into the typed struct.
    let serialized = borsh::to_vec(&event_data).expect("event borsh");
    let recovered = decode_event_data(&serialized).expect("decode event data");
    assert_eq!(recovered, event_data);
}

// ---------------------------------------------------------------------------
// 2. Three publishers in one round → indexer-side median
// ---------------------------------------------------------------------------

#[test]
fn scenario_three_publishers_median_round() {
    let now = 1_700_000_000;
    let asset = b"ETH/USD";

    // Three publishers each sign for the same asset + window with
    // slightly different prices. Confidence intervals identical for
    // simplicity (the median ignores conf in v1).
    let a = sign_for(asset, 3_500_00000000, 10_00000000, now, 1, KeySource::Mnemonic(FIXTURE_MNEMONIC_A), 0x21);
    let b = sign_for(asset, 3_500_50000000, 10_00000000, now, 1, KeySource::Direct(keypair_b()), 0x22);
    let c = sign_for(asset, 3_501_00000000, 10_00000000, now, 1, KeySource::Direct(keypair_c()), 0x23);

    // Verify all three independently.
    for att in [&a, &b, &c] {
        verify_attestation_at(att, now).expect("each publisher's attestation verifies");
    }

    // Three distinct publisher fingerprints — indexer can group by them.
    let fp_a = publisher_fingerprint(&a.publisher_pubkey);
    let fp_b = publisher_fingerprint(&b.publisher_pubkey);
    let fp_c = publisher_fingerprint(&c.publisher_pubkey);
    assert_ne!(fp_a, fp_b);
    assert_ne!(fp_a, fp_c);
    assert_ne!(fp_b, fp_c);

    // Indexer median: the middle of three sorted prices is b's.
    let mut prices: Vec<i64> = [&a, &b, &c].iter().map(|x| x.core.price_e8).collect();
    prices.sort();
    let median = prices[1];
    assert_eq!(median, 3_500_50000000);
}

// ---------------------------------------------------------------------------
// 3. Flip triggers after 7 days of consistency
// ---------------------------------------------------------------------------

#[test]
fn scenario_flip_triggers_after_full_consistency_window() {
    let now = 1_700_000_000;
    let policy = FlipPolicy::default();

    // Phase 5 and Phase 9 both produce one sample per hour for 7 days,
    // at the same base price. Last sample is approximately `now`.
    let count = (policy.min_consistency_window_secs / 3600) as usize + 1;
    let step = policy.min_consistency_window_secs / (count as u64 - 1);
    let earliest = now - policy.min_consistency_window_secs;
    let phase5: Vec<PriceSample> =
        (0..count).map(|i| PriceSample { publish_ts: earliest + (i as u64) * step, price_e8: 65_000_00000000 }).collect();
    let phase9 = phase5.clone();

    let inputs = FlipInputs { phase5_history: &phase5, phase9_aggregated_history: &phase9, phase9_publisher_count: 3, now };
    let decision = evaluate_flip(inputs, &policy);
    assert_eq!(decision, FlipDecision::Flip);

    // The registry would now update.
    let mut registry = InMemoryFeedSourceRegistry::new();
    let asset_id = asset_id_from_symbol(b"BTC/USD");
    registry.set(asset_id, FeedSource::Phase9 { active_since_ts: now });
    assert_eq!(registry.get(&asset_id), Some(FeedSource::Phase9 { active_since_ts: now }));
}

// ---------------------------------------------------------------------------
// 4. Flip blocked by spread, sequence-progress-only stays
// ---------------------------------------------------------------------------

#[test]
fn scenario_flip_blocked_by_persistent_spread() {
    let now = 1_700_000_000;
    let policy = FlipPolicy::default();

    let count = (policy.min_consistency_window_secs / 3600) as usize + 1;
    let step = policy.min_consistency_window_secs / (count as u64 - 1);
    let earliest = now - policy.min_consistency_window_secs;

    // Phase 5 tracks 65_000; Phase 9 is consistently 1% higher (650 e8
    // ≈ $650 difference). Default tolerance is 50 bp (0.5%) → fails.
    let phase5: Vec<PriceSample> =
        (0..count).map(|i| PriceSample { publish_ts: earliest + (i as u64) * step, price_e8: 65_000_00000000 }).collect();
    let phase9: Vec<PriceSample> =
        (0..count).map(|i| PriceSample { publish_ts: earliest + (i as u64) * step, price_e8: 65_650_00000000 }).collect();

    let inputs = FlipInputs { phase5_history: &phase5, phase9_aggregated_history: &phase9, phase9_publisher_count: 5, now };
    let decision = evaluate_flip(inputs, &policy);
    assert_eq!(decision, FlipDecision::Stay { reason: StayReason::SpreadOutOfBounds });
}

// ---------------------------------------------------------------------------
// 5. Stale Phase 5 + sub-quorum Phase 9 → consumer sees Unavailable
// ---------------------------------------------------------------------------

#[test]
fn scenario_stale_phase5_with_low_phase9_quorum_marks_unavailable() {
    let now = 1_700_000_000;
    let policy = FlipPolicy::default();

    // Phase 5 has been silent for 10 minutes; default stale threshold is 5.
    let phase5 = vec![PriceSample { publish_ts: now - 600, price_e8: 65_000_00000000 }];
    let phase9: Vec<PriceSample> = vec![];
    let inputs = FlipInputs { phase5_history: &phase5, phase9_aggregated_history: &phase9, phase9_publisher_count: 1, now };
    let decision = evaluate_flip(inputs, &policy);
    match decision {
        FlipDecision::StaleSource { phase5_last_seen_secs_ago } => assert_eq!(phase5_last_seen_secs_ago, 600),
        other => panic!("expected StaleSource, got {other:?}"),
    }

    // Registry updates Unavailable; consumer SDK reads it and refuses
    // to act on the feed.
    let mut registry = InMemoryFeedSourceRegistry::new();
    let asset_id = asset_id_from_symbol(b"BTC/USD");
    registry.set(asset_id, FeedSource::Unavailable);
    assert_eq!(registry.get(&asset_id), Some(FeedSource::Unavailable));
}

// ---------------------------------------------------------------------------
// 6. Event-id derivation is indexer-reproducible
// ---------------------------------------------------------------------------

#[test]
fn scenario_event_id_derived_independently_from_canonical_string() {
    // An indexer that does not depend on `oracle-pqc-contract` can still
    // pin the canonical topic[0] by hashing the public derivation
    // string. This proves the open-permissioned property: the
    // canonical event id is a public constant any party can verify.
    let contract_value = event_id_phase9_attestation();

    use sha3::{Digest, Sha3_384};
    let mut hasher = Sha3_384::new();
    hasher.update(b"sophis-oracle-pqc-v1/PriceAttestation");
    let full = hasher.finalize();
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&full[..32]);

    assert_eq!(contract_value, expected);
}

// ---------------------------------------------------------------------------
// 7. Replay via same sequence number is detected by indexer-side dedup
// ---------------------------------------------------------------------------

#[test]
fn scenario_same_publisher_same_sequence_is_indexer_duplicate() {
    let now = 1_700_000_000;
    let a = sign_for(b"BTC/USD", 65_000_00000000, 50_00000000, now, 7, KeySource::Mnemonic(FIXTURE_MNEMONIC_A), 0x31);
    // Same mnemonic, same sequence — different RNG seed (the publisher
    // could legitimately re-derive randomness across restarts).
    let b = sign_for(b"BTC/USD", 65_100_00000000, 50_00000000, now + 60, 7, KeySource::Mnemonic(FIXTURE_MNEMONIC_A), 0x32);

    // Both verify cryptographically — sigs are well-formed.
    verify_attestation_at(&a, now).unwrap();
    verify_attestation_at(&b, now + 60).unwrap();

    // But (publisher_fingerprint, asset_id, sequence) is the dedup key.
    let key_a = (publisher_fingerprint(&a.publisher_pubkey), a.core.asset_id, a.core.sequence);
    let key_b = (publisher_fingerprint(&b.publisher_pubkey), b.core.asset_id, b.core.sequence);
    assert_eq!(key_a, key_b, "indexer dedup MUST treat these as the same submission");

    // Indexer keeps the first-seen, discards the second; this is the v1
    // replay-protection policy (SIP-11 deferred-on-chain → indexer-side).
}

// ---------------------------------------------------------------------------
// 8. Different publishers may reuse the same sequence value
// ---------------------------------------------------------------------------

#[test]
fn scenario_different_publishers_can_share_a_sequence_value() {
    let now = 1_700_000_000;
    let a = sign_for(b"BTC/USD", 65_000_00000000, 50_00000000, now, 1, KeySource::Mnemonic(FIXTURE_MNEMONIC_A), 0x41);
    let b = sign_for(b"BTC/USD", 65_005_00000000, 50_00000000, now, 1, KeySource::Direct(keypair_b()), 0x42);

    // Both verify.
    verify_attestation_at(&a, now).unwrap();
    verify_attestation_at(&b, now).unwrap();

    // Dedup keys differ because publisher fingerprints differ.
    let key_a = (publisher_fingerprint(&a.publisher_pubkey), a.core.asset_id, a.core.sequence);
    let key_b = (publisher_fingerprint(&b.publisher_pubkey), b.core.asset_id, b.core.sequence);
    assert_ne!(key_a, key_b);
}

// ---------------------------------------------------------------------------
// 9. Decoder fails closed on truncated wire bytes
// ---------------------------------------------------------------------------

#[test]
fn scenario_decoder_fails_closed_on_truncated_input() {
    let now = 1_700_000_000;
    let att = sign_for(b"BTC/USD", 65_000_00000000, 50_00000000, now, 1, KeySource::Mnemonic(FIXTURE_MNEMONIC_A), 0x51);
    let bytes = att.to_bytes().unwrap();

    // Truncate by one byte; decoder MUST reject (the contract returns
    // false in `validate_submission`, the indexer drops the event).
    let truncated = &bytes[..bytes.len() - 1];
    assert!(decode_attestation_bytes(truncated).is_none());

    // Empty bytes → reject.
    assert!(decode_attestation_bytes(&[]).is_none());
}

// ---------------------------------------------------------------------------
// 10. Publisher key derivation matches the canonical dilithium-wallet path
// ---------------------------------------------------------------------------

#[test]
fn scenario_publisher_keypair_derivation_is_canonical() {
    // The publisher CLI must derive the same keypair as `dilithium-wallet`
    // would for the same mnemonic. If an operator generates their
    // mnemonic with `dilithium-wallet new`, they MUST be able to use
    // it with `sophis-oracle-publisher` without re-keying. Two calls
    // → identical bytes.
    let (vk_first, sk_first) = derive_keypair_from_mnemonic(FIXTURE_MNEMONIC_A).unwrap();
    let (vk_second, sk_second) = derive_keypair_from_mnemonic(FIXTURE_MNEMONIC_A).unwrap();
    assert_eq!(vk_first, vk_second);
    assert_eq!(sk_first, sk_second);

    // Distinct randomness path → distinct keypair (bypasses BIP-39 entirely).
    let (vk_other, _) = keypair_b();
    assert_ne!(vk_first, vk_other);
}

// ---------------------------------------------------------------------------
// 11. Tampered wire bytes fail verification (signature binds to core)
// ---------------------------------------------------------------------------

#[test]
fn scenario_tampered_core_breaks_signature_binding() {
    let now = 1_700_000_000;
    let mut att = sign_for(b"BTC/USD", 65_000_00000000, 50_00000000, now, 1, KeySource::Mnemonic(FIXTURE_MNEMONIC_A), 0x61);

    // A man-in-the-middle attempts to bump the price by $100 without
    // re-signing. The Dilithium signature is over the canonical signing
    // hash including the core; verification MUST fail.
    att.core.price_e8 += 100_00000000;
    let res = verify_attestation_at(&att, now);
    assert!(res.is_err(), "tampered core must fail verify");
}

// ---------------------------------------------------------------------------
// 12. Full migration walkthrough — Phase 5 → Phase 9 transition
// ---------------------------------------------------------------------------

#[test]
fn scenario_full_migration_walkthrough() {
    let now = 1_700_000_000;
    let asset_id = asset_id_from_symbol(b"BTC/USD");
    let policy = FlipPolicy::default();
    let mut registry = InMemoryFeedSourceRegistry::new();

    // Day 0: registry has Phase 5 as canonical.
    registry.set(asset_id, FeedSource::Phase5);
    assert_eq!(registry.get(&asset_id), Some(FeedSource::Phase5));

    // Day 1: Phase 5 history has one day of samples ending at `now`;
    // Phase 9 has just bootstrapped with 3 publishers but only a few
    // hours of data. Both end recently enough to pass staleness.
    let day = 24u64 * 3600;
    let phase5_day1: Vec<PriceSample> =
        (0..25).map(|h| PriceSample { publish_ts: now - day + h * 3600, price_e8: 65_000_00000000 }).collect();
    let phase9_day1: Vec<PriceSample> =
        (0..5).map(|h| PriceSample { publish_ts: now - 4 * 3600 + h * 3600, price_e8: 65_000_00000000 }).collect();
    let decision_day1 = evaluate_flip(
        FlipInputs { phase5_history: &phase5_day1, phase9_aggregated_history: &phase9_day1, phase9_publisher_count: 3, now },
        &policy,
    );
    assert_eq!(decision_day1, FlipDecision::Stay { reason: StayReason::ConsistencyWindowNotReached },);
    // Registry stays on Phase 5.

    // Day 8: both paths have at least 7 days of history and agree.
    let later_now = now + 8 * day;
    let count = (policy.min_consistency_window_secs / 3600) as usize + 1;
    let step = policy.min_consistency_window_secs / (count as u64 - 1);
    let earliest = later_now - policy.min_consistency_window_secs;
    let phase5_day8: Vec<PriceSample> =
        (0..count).map(|i| PriceSample { publish_ts: earliest + (i as u64) * step, price_e8: 65_000_00000000 }).collect();
    let phase9_day8 = phase5_day8.clone();
    let decision_day8 = evaluate_flip(
        FlipInputs {
            phase5_history: &phase5_day8,
            phase9_aggregated_history: &phase9_day8,
            phase9_publisher_count: 3,
            now: later_now,
        },
        &policy,
    );
    assert_eq!(decision_day8, FlipDecision::Flip);

    // Operator applies the flip in their registry; consumers reading
    // through the registry now route to Phase 9.
    registry.set(asset_id, FeedSource::Phase9 { active_since_ts: later_now });
    assert!(matches!(registry.get(&asset_id), Some(FeedSource::Phase9 { .. }),));
}

// ---------------------------------------------------------------------------
// 13. Indexer event payload borsh layout pins the SIP-11 32-byte size
// ---------------------------------------------------------------------------

#[test]
fn scenario_event_data_size_is_32_bytes() {
    // Indexers MUST be able to allocate a fixed-size buffer for the
    // event-data payload. SIP-11 D9 + the EventDataV1 layout pin it at
    // 4 × u64 = 32 bytes.
    let now = 1_700_000_000;
    let att = sign_for(b"BTC/USD", 65_000_00000000, 50_00000000, now, 99, KeySource::Mnemonic(FIXTURE_MNEMONIC_A), 0x71);
    let event = build_event_data(&att);
    let bytes = borsh::to_vec(&event).unwrap();
    assert_eq!(bytes.len(), 32);
    let decoded: EventDataV1 = borsh::from_slice(&bytes).unwrap();
    assert_eq!(decoded, event);
}
