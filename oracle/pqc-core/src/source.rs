//! Phase 5 / Phase 9 dual-path source dispatch.
//!
//! Implements SIP-11 D11 (migration path). The dispatch is a
//! **consumer-side** SDK pattern: indexers and consumer SDKs read price
//! data from both paths and consult [`evaluate_flip`] to decide which
//! source is canonical for a given asset at a given moment. There is no
//! on-chain coordinator contract in Phase 9.3 v1 — each indexer is free
//! to apply the same deterministic policy to public data and arrive at
//! the same answer. An on-chain announcement contract is reserved for a
//! future Phase 9.3.x post-mainnet SIP if real demand surfaces.

use borsh::{BorshDeserialize, BorshSerialize};

/// Which ingestion path is canonical for a given feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum FeedSource {
    /// Phase 5 (Plonky3 STARK aggregator over Pyth ed25519 attestations) is
    /// the active source. Default state for every feed at mainnet T+0.
    Phase5,
    /// Phase 9 (per-publisher Dilithium attestations) has been validated
    /// against Phase 5 per SIP-11 D11 and is the active source. Phase 5
    /// continues to ingest but its output is marked deprecated; consumers
    /// reading Phase 5 SHOULD emit a deprecation warning.
    Phase9 {
        /// Unix-seconds timestamp at which the flip became effective.
        active_since_ts: u64,
    },
    /// Phase 5 ingestion has fallen stale (no new attestations within the
    /// configured staleness window) and Phase 9 quorum has not yet been
    /// reached. Consumers SHOULD treat the feed as unavailable until one
    /// path recovers.
    Unavailable,
}

/// Tunables that pin SIP-11 D11 / D5 / D6 thresholds to concrete values.
/// Frozen for Phase 9.3 v1; revisions ship as a follow-up SIP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlipPolicy {
    /// Minimum number of Sophis-native publishers required for a flip
    /// (SIP-11 D6 quorum, default 3).
    pub min_publishers: u8,
    /// How long Phase 9 publishers must have been contributing
    /// consistently before a flip is permitted (default 7 days =
    /// 7 × 24 × 3600 seconds).
    pub min_consistency_window_secs: u64,
    /// Maximum permitted spread between the Phase 5 reference price and
    /// the Phase 9 median, in basis points (default 50 bp = 0.5%).
    pub max_spread_bp: u32,
    /// Maximum age of the most recent Phase 5 sample before the feed is
    /// flagged stale (SIP-11 D5 default 5 minutes = 300 seconds).
    pub stale_after_secs: u64,
}

impl Default for FlipPolicy {
    /// Returns the SIP-11 D11 / D5 / D6 default thresholds.
    fn default() -> Self {
        Self {
            min_publishers: 3,
            min_consistency_window_secs: 7 * 24 * 3600,
            max_spread_bp: 50,
            stale_after_secs: 300,
        }
    }
}

/// One observation in the rolling history a dispatcher feeds into
/// [`evaluate_flip`]. Captures the canonical comparison surface: when a
/// sample was published and what price it carried (already e8-scaled per
/// SIP-11 D9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriceSample {
    pub publish_ts: u64,
    pub price_e8: i64,
}

/// Inputs into the flip decision. The caller assembles this from indexer
/// state before invoking [`evaluate_flip`]; the function itself is pure
/// so consumers can verify the same answer independently.
#[derive(Debug, Clone, Copy)]
pub struct FlipInputs<'a> {
    /// Phase 5 samples sorted by `publish_ts` ascending (oldest first).
    /// May be empty if Phase 5 ingestion has not yet caught up.
    pub phase5_history: &'a [PriceSample],
    /// Phase 9 *aggregated* samples sorted by `publish_ts` ascending. Each
    /// sample represents the median of one Phase 9 round, not an individual
    /// publisher submission. May be empty if no rounds have produced
    /// quorum yet.
    pub phase9_aggregated_history: &'a [PriceSample],
    /// Distinct Sophis-native publishers currently registered for this
    /// asset. The same value the indexer derives from the J4
    /// PriceAttestation event log over the consistency window.
    pub phase9_publisher_count: u8,
    /// Caller-supplied "now" for skew-free testing. Use OS wall-clock in
    /// production.
    pub now: u64,
}

/// Outcome of an [`evaluate_flip`] call. Each variant carries enough
/// context for the caller to log a clear reason; indexers SHOULD surface
/// the reason in their public flip-history record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlipDecision {
    /// Keep the current source. Carries a static reason string for
    /// human-readable logging.
    Stay { reason: StayReason },
    /// All SIP-11 D11 criteria are met; the feed SHOULD flip to Phase 9.
    Flip,
    /// Phase 5 has gone silent and Phase 9 has not yet reached quorum.
    /// Consumers SHOULD treat the feed as unavailable.
    StaleSource { phase5_last_seen_secs_ago: u64 },
}

/// Why a [`FlipDecision::Stay`] was returned. Enumerated so consumers can
/// branch on the reason without parsing free-form strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StayReason {
    /// Phase 9 has fewer than [`FlipPolicy::min_publishers`] active
    /// publishers; quorum not met.
    BelowQuorum,
    /// Phase 9 has not been ingesting for the full consistency window
    /// yet — keep observing.
    ConsistencyWindowNotReached,
    /// Phase 9 median diverges from Phase 5 by more than
    /// [`FlipPolicy::max_spread_bp`] over the window.
    SpreadOutOfBounds,
    /// Both paths are tracking but Phase 5 is still the active source by
    /// configuration — caller decided not to flip yet despite criteria.
    /// (Currently unused; reserved for explicit operator overrides.)
    OperatorHold,
}

/// Pure policy: decide whether a feed should flip to Phase 9, stay on
/// Phase 5, or be reported unavailable.
///
/// Idempotent and deterministic over the same inputs; two indexers
/// observing the same public chain state arrive at the same decision.
pub fn evaluate_flip(inputs: FlipInputs<'_>, policy: &FlipPolicy) -> FlipDecision {
    // Stale-source check runs first — if Phase 5 has gone dark and
    // Phase 9 isn't ready, return unavailability so consumers don't
    // pretend Phase 5 is still good.
    let phase5_stale = match inputs.phase5_history.last() {
        Some(latest) => inputs.now.saturating_sub(latest.publish_ts) > policy.stale_after_secs,
        None => true,
    };
    let phase9_ready = inputs.phase9_publisher_count >= policy.min_publishers
        && phase9_window_satisfied(inputs.phase9_aggregated_history, policy, inputs.now);

    if phase5_stale && !phase9_ready {
        let secs_ago = inputs.phase5_history.last().map_or(u64::MAX, |s| inputs.now.saturating_sub(s.publish_ts));
        return FlipDecision::StaleSource { phase5_last_seen_secs_ago: secs_ago };
    }

    if inputs.phase9_publisher_count < policy.min_publishers {
        return FlipDecision::Stay { reason: StayReason::BelowQuorum };
    }
    if !phase9_window_satisfied(inputs.phase9_aggregated_history, policy, inputs.now) {
        return FlipDecision::Stay { reason: StayReason::ConsistencyWindowNotReached };
    }
    if !spread_within_bounds(
        inputs.phase5_history,
        inputs.phase9_aggregated_history,
        policy,
        inputs.now,
    ) {
        return FlipDecision::Stay { reason: StayReason::SpreadOutOfBounds };
    }
    FlipDecision::Flip
}

/// Returns true if the Phase 9 aggregated history covers at least the
/// consistency window ending at `now`.
fn phase9_window_satisfied(
    phase9_history: &[PriceSample],
    policy: &FlipPolicy,
    now: u64,
) -> bool {
    let Some(oldest) = phase9_history.first() else {
        return false;
    };
    let Some(latest) = phase9_history.last() else {
        return false;
    };
    if now < latest.publish_ts {
        // Future-dated samples are nonsensical; bail.
        return false;
    }
    let window_start = now.saturating_sub(policy.min_consistency_window_secs);
    oldest.publish_ts <= window_start && latest.publish_ts >= window_start
}

/// Returns true if every Phase 9 sample within the consistency window has
/// a matching-bucket Phase 5 sample within `max_spread_bp` of the Phase 9
/// price. Conservative: a single out-of-bounds sample fails the check.
fn spread_within_bounds(
    phase5_history: &[PriceSample],
    phase9_history: &[PriceSample],
    policy: &FlipPolicy,
    now: u64,
) -> bool {
    if phase5_history.is_empty() || phase9_history.is_empty() {
        return false;
    }
    let window_start = now.saturating_sub(policy.min_consistency_window_secs);

    for p9 in phase9_history.iter().filter(|s| s.publish_ts >= window_start) {
        // Find the nearest Phase 5 sample whose publish_ts is at most
        // `stale_after_secs` from this Phase 9 sample.
        let nearest_phase5 = phase5_history
            .iter()
            .filter(|s| s.publish_ts.abs_diff(p9.publish_ts) <= policy.stale_after_secs)
            .min_by_key(|s| s.publish_ts.abs_diff(p9.publish_ts));

        let Some(p5) = nearest_phase5 else {
            // No Phase 5 sample close enough to compare → fail-closed.
            return false;
        };

        if !within_spread_bp(p5.price_e8, p9.price_e8, policy.max_spread_bp) {
            return false;
        }
    }
    true
}

/// Returns true if `lhs` and `rhs` differ by at most `max_bp` basis points
/// (relative to the Phase 5 reference). Zero / negative reference prices
/// fall back to exact equality (defence-in-depth against div-by-zero).
fn within_spread_bp(reference_e8: i64, candidate_e8: i64, max_bp: u32) -> bool {
    if reference_e8 <= 0 {
        return reference_e8 == candidate_e8;
    }
    let diff = (reference_e8 - candidate_e8).unsigned_abs();
    // diff / reference ≤ max_bp / 10_000  ⇔  diff × 10_000 ≤ reference × max_bp
    let lhs = (diff as u128).saturating_mul(10_000);
    let rhs = (reference_e8 as u128).saturating_mul(max_bp as u128);
    lhs <= rhs
}

// ---------------------------------------------------------------------------
// InMemoryFeedSourceRegistry — operator-side dispatch registry
// ---------------------------------------------------------------------------

/// Minimal interface a price-routing consumer SDK calls. v1 ships only
/// the in-memory implementation below; future revisions can plug in a
/// chain-anchored registry that pulls from an on-chain announcement
/// contract.
pub trait FeedSourceRegistry {
    /// Returns the currently active source for `asset_id`, or `None` if
    /// the registry has no opinion about it.
    fn get(&self, asset_id: &[u8; 32]) -> Option<FeedSource>;
}

/// Operator-side registry — a flat map from `asset_id` to [`FeedSource`].
/// Operators populate this from their indexer state and refresh whenever
/// [`evaluate_flip`] returns [`FlipDecision::Flip`] for a tracked feed.
#[derive(Debug, Clone, Default)]
pub struct InMemoryFeedSourceRegistry {
    entries: alloc::vec::Vec<([u8; 32], FeedSource)>,
}

impl InMemoryFeedSourceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts or updates the source for an asset.
    pub fn set(&mut self, asset_id: [u8; 32], source: FeedSource) {
        if let Some(slot) = self.entries.iter_mut().find(|(id, _)| *id == asset_id) {
            slot.1 = source;
        } else {
            self.entries.push((asset_id, source));
        }
    }

    /// Returns the number of registered assets.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no assets are registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns an iterator over `(asset_id, source)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = &([u8; 32], FeedSource)> {
        self.entries.iter()
    }
}

impl FeedSourceRegistry for InMemoryFeedSourceRegistry {
    fn get(&self, asset_id: &[u8; 32]) -> Option<FeedSource> {
        self.entries.iter().find(|(id, _)| id == asset_id).map(|(_, src)| *src)
    }
}

extern crate alloc;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::asset_id_from_symbol;

    const SEVEN_DAYS: u64 = 7 * 24 * 3600;

    fn dense_samples(window_secs: u64, count: usize, base_price_e8: i64, now: u64) -> Vec<PriceSample> {
        let count = count.max(2);
        let step = window_secs / (count as u64 - 1);
        let earliest = now.saturating_sub(window_secs);
        (0..count)
            .map(|i| PriceSample {
                publish_ts: earliest + (i as u64) * step,
                price_e8: base_price_e8 + (i as i64) * 100, // gentle drift
            })
            .collect()
    }

    // --- FlipPolicy defaults ---

    #[test]
    fn default_policy_matches_sip11() {
        let p = FlipPolicy::default();
        assert_eq!(p.min_publishers, 3);
        assert_eq!(p.min_consistency_window_secs, 7 * 24 * 3600);
        assert_eq!(p.max_spread_bp, 50);
        assert_eq!(p.stale_after_secs, 300);
    }

    // --- spread maths ---

    #[test]
    fn spread_within_bp_basic() {
        // 50 bp = 0.5% tolerance
        // reference 100.0 → ± 0.5 absolute → ± 50_000_000 in e8 units
        assert!(within_spread_bp(100_00000000, 100_00000000, 50));
        assert!(within_spread_bp(100_00000000, 100_50000000, 50));
        assert!(within_spread_bp(100_00000000, 99_50000000, 50));
        assert!(!within_spread_bp(100_00000000, 100_60000000, 50));
        assert!(!within_spread_bp(100_00000000, 99_40000000, 50));
    }

    #[test]
    fn spread_handles_zero_reference() {
        // Zero reference → fall back to exact equality.
        assert!(within_spread_bp(0, 0, 50));
        assert!(!within_spread_bp(0, 1, 50));
    }

    // --- evaluate_flip ---

    #[test]
    fn flip_below_quorum_stays() {
        let now = 1_700_000_000;
        let inputs = FlipInputs {
            phase5_history: &dense_samples(SEVEN_DAYS, 168, 65_000_00000000, now),
            phase9_aggregated_history: &dense_samples(SEVEN_DAYS, 168, 65_000_00000000, now),
            phase9_publisher_count: 2, // below default quorum 3
            now,
        };
        let decision = evaluate_flip(inputs, &FlipPolicy::default());
        assert_eq!(decision, FlipDecision::Stay { reason: StayReason::BelowQuorum });
    }

    #[test]
    fn flip_consistency_window_short_stays() {
        let now = 1_700_000_000;
        // Phase 9 history only covers the most recent 6 hours, not 7 days.
        let inputs = FlipInputs {
            phase5_history: &dense_samples(SEVEN_DAYS, 168, 65_000_00000000, now),
            phase9_aggregated_history: &dense_samples(6 * 3600, 6, 65_000_00000000, now),
            phase9_publisher_count: 5,
            now,
        };
        let decision = evaluate_flip(inputs, &FlipPolicy::default());
        assert_eq!(decision, FlipDecision::Stay { reason: StayReason::ConsistencyWindowNotReached });
    }

    #[test]
    fn flip_spread_too_wide_stays() {
        let now = 1_700_000_000;
        // Phase 9 reports 1% higher than Phase 5 → fails 50 bp tolerance.
        let phase5 = dense_samples(SEVEN_DAYS, 168, 65_000_00000000, now);
        let phase9: Vec<_> = phase5
            .iter()
            .map(|s| PriceSample { publish_ts: s.publish_ts, price_e8: s.price_e8 + 650_00000000 })
            .collect();
        let inputs = FlipInputs {
            phase5_history: &phase5,
            phase9_aggregated_history: &phase9,
            phase9_publisher_count: 3,
            now,
        };
        let decision = evaluate_flip(inputs, &FlipPolicy::default());
        assert_eq!(decision, FlipDecision::Stay { reason: StayReason::SpreadOutOfBounds });
    }

    #[test]
    fn flip_all_criteria_satisfied() {
        let now = 1_700_000_000;
        let phase5 = dense_samples(SEVEN_DAYS, 168, 65_000_00000000, now);
        let phase9 = dense_samples(SEVEN_DAYS, 168, 65_000_00000000, now);
        let inputs = FlipInputs {
            phase5_history: &phase5,
            phase9_aggregated_history: &phase9,
            phase9_publisher_count: 5,
            now,
        };
        let decision = evaluate_flip(inputs, &FlipPolicy::default());
        assert_eq!(decision, FlipDecision::Flip);
    }

    #[test]
    fn stale_source_when_phase5_silent_and_phase9_below_quorum() {
        let now = 1_700_000_000;
        // Phase 5 last sample 10 minutes ago → stale (default window 5 min).
        let phase5 = vec![PriceSample { publish_ts: now - 600, price_e8: 65_000_00000000 }];
        let phase9: Vec<PriceSample> = vec![];
        let inputs = FlipInputs {
            phase5_history: &phase5,
            phase9_aggregated_history: &phase9,
            phase9_publisher_count: 1,
            now,
        };
        let decision = evaluate_flip(inputs, &FlipPolicy::default());
        match decision {
            FlipDecision::StaleSource { phase5_last_seen_secs_ago } => {
                assert_eq!(phase5_last_seen_secs_ago, 600);
            }
            other => panic!("expected StaleSource, got {other:?}"),
        }
    }

    #[test]
    fn empty_phase5_and_empty_phase9_returns_stale() {
        let now = 1_700_000_000;
        let inputs = FlipInputs {
            phase5_history: &[],
            phase9_aggregated_history: &[],
            phase9_publisher_count: 0,
            now,
        };
        let decision = evaluate_flip(inputs, &FlipPolicy::default());
        assert!(matches!(decision, FlipDecision::StaleSource { .. }));
    }

    // --- InMemoryFeedSourceRegistry ---

    #[test]
    fn registry_get_returns_none_for_unknown() {
        let registry = InMemoryFeedSourceRegistry::new();
        assert!(registry.get(&[0u8; 32]).is_none());
    }

    #[test]
    fn registry_set_and_get_roundtrip() {
        let mut registry = InMemoryFeedSourceRegistry::new();
        let btc = asset_id_from_symbol(b"BTC/USD");
        let eth = asset_id_from_symbol(b"ETH/USD");
        registry.set(btc, FeedSource::Phase5);
        registry.set(eth, FeedSource::Phase9 { active_since_ts: 1_700_000_000 });

        assert_eq!(registry.get(&btc), Some(FeedSource::Phase5));
        assert_eq!(registry.get(&eth), Some(FeedSource::Phase9 { active_since_ts: 1_700_000_000 }));
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn registry_set_overwrites_existing_entry() {
        let mut registry = InMemoryFeedSourceRegistry::new();
        let btc = asset_id_from_symbol(b"BTC/USD");
        registry.set(btc, FeedSource::Phase5);
        registry.set(btc, FeedSource::Phase9 { active_since_ts: 42 });
        assert_eq!(registry.get(&btc), Some(FeedSource::Phase9 { active_since_ts: 42 }));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn registry_iter_yields_inserted_entries() {
        let mut registry = InMemoryFeedSourceRegistry::new();
        let btc = asset_id_from_symbol(b"BTC/USD");
        let eth = asset_id_from_symbol(b"ETH/USD");
        registry.set(btc, FeedSource::Phase5);
        registry.set(eth, FeedSource::Unavailable);
        let collected: Vec<_> = registry.iter().copied().collect();
        assert_eq!(collected.len(), 2);
        assert!(collected.contains(&(btc, FeedSource::Phase5)));
        assert!(collected.contains(&(eth, FeedSource::Unavailable)));
    }

    #[test]
    fn feed_source_borsh_roundtrip() {
        let cases = [
            FeedSource::Phase5,
            FeedSource::Phase9 { active_since_ts: 1_700_000_000 },
            FeedSource::Unavailable,
        ];
        for source in cases {
            let bytes = borsh::to_vec(&source).unwrap();
            let decoded: FeedSource = borsh::from_slice(&bytes).unwrap();
            assert_eq!(decoded, source);
        }
    }
}
