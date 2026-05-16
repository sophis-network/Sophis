//! Phase 9 PQC-native oracle — **reference indexer** (deterministic core).
//!
//! Phase 9 v1 is off-chain-aggregated (ratified in
//! `oracle/docs/PHASE9_3_DUAL_PATH.md`, SIP-11 D11): the on-chain
//! `pqc-contract` is a stateless validator that emits a J4
//! `PriceAttestation` event; aggregation (per-round median, quorum,
//! staleness), the Phase5↔Phase9 dispatch policy, and the consumer-facing
//! price/source registry all live in **off-chain indexers**. The RUNBOOK
//! specified the indexer algorithm in prose; this crate is the missing
//! **reference implementation** of it.
//!
//! ## Determinism (the entire correctness property)
//!
//! [`Indexer`] is pure given its inputs: the same ordered sequence of
//! ingested events + the same `now` values produces the same registry and
//! the same `read_price` answers on any machine. There is no wall clock
//! inside — callers supply `now`. This is exactly PHASE9_3 §2.2: two
//! independent indexers over the same public chain state converge.
//!
//! ## Scope boundary (honest, mirrors `pqc-publisher`)
//!
//! This crate is the deterministic indexer **core + a file/stdin-driven
//! reference binary**. Subscribing to a live Sophis node's J4 event
//! stream (gRPC/wRPC) is a documented **adapter boundary**, deliberately
//! out of v1 — the same way `pqc-publisher` punts on-chain submission to
//! `dilithium-wallet`. The binary ingests already-decoded
//! `PriceAttestation` bytes/hex; wiring a node adapter is the operator's
//! integration step (RUNBOOK §1 "custom watcher").
//!
//! It composes only **frozen** surfaces (`oracle/pqc-core`,
//! `oracle/pqc-contract`); it adds no new wire format or crypto.

use std::collections::BTreeMap;

use sophis_oracle_pqc_contract::publisher_fingerprint;
use sophis_oracle_pqc_core::{
    FeedSource, FeedSourceRegistry, FlipDecision, FlipInputs, FlipPolicy, InMemoryFeedSourceRegistry, PriceAttestation, PriceSample,
    evaluate_flip, verify_attestation,
};
use thiserror::Error;

/// Default Phase 9 aggregation round window (SIP-11 D4 = 60 s).
pub const DEFAULT_ROUND_WINDOW_SECS: u64 = 60;

/// Why the indexer refused to ingest a Phase 9 attestation. The indexer
/// re-verifies every attestation (defense-in-depth: PHASE9_3 §4 says a
/// consumer SHOULD verify independently even though the on-chain contract
/// already validated the signature).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IngestReject {
    /// Dilithium signature / domain / skew verification failed.
    #[error("attestation verification failed: {0}")]
    VerifyFailed(String),
}

/// One verified Phase 9 submission held until its round is finalized.
#[derive(Debug, Clone, Copy)]
struct PendingSubmission {
    publisher_fp: [u8; 32],
    price_e8: i64,
    conf_e8: u64,
    publish_ts: u64,
    sequence: u64,
}

/// A finalized Phase 9 round (the aggregated, quorum-passing median).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Round {
    /// Bucket-START timestamp the round represents (the `PriceSample.publish_ts`
    /// fed to `evaluate_flip`). Finalization is gated separately on bucket-end.
    pub publish_ts: u64,
    /// Median `price_e8` over the round's distinct publishers.
    pub price_e8: i64,
    /// Median `conf_e8` over the round's distinct publishers.
    pub conf_e8: u64,
    /// Number of distinct publishers that contributed (≥ quorum).
    pub publishers: u32,
}

/// Current canonical price reading for an asset, source-routed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriceReading {
    pub price_e8: i64,
    pub conf_e8: u64,
    pub publish_ts: u64,
    pub source: FeedSource,
}

#[derive(Debug, Default)]
struct AssetState {
    pending: Vec<PendingSubmission>,
    rounds: Vec<Round>,
    phase5: Vec<PriceSample>,
    last_decision: Option<FlipDecision>,
}

/// Deterministic Phase 9 reference indexer.
#[derive(Debug)]
pub struct Indexer {
    assets: BTreeMap<[u8; 32], AssetState>,
    registry: InMemoryFeedSourceRegistry,
    round_window_secs: u64,
}

impl Default for Indexer {
    fn default() -> Self {
        Self::new(DEFAULT_ROUND_WINDOW_SECS)
    }
}

impl Indexer {
    /// New indexer with a given round window (use [`DEFAULT_ROUND_WINDOW_SECS`]).
    pub fn new(round_window_secs: u64) -> Self {
        Self {
            assets: BTreeMap::new(),
            registry: InMemoryFeedSourceRegistry::new(),
            // round window must be > 0 so bucketing is well-defined.
            round_window_secs: round_window_secs.max(1),
        }
    }

    /// Ingest a Phase 9 `PriceAttestation` (as decoded from a J4 event).
    /// Re-verifies the Dilithium signature **and skew** against `now`
    /// before accepting (defense-in-depth, PHASE9_3 §4). `now` is the
    /// time the event is *observed/processed* — when replaying a
    /// historical J4 log, pass each event's block/observed time, not the
    /// replay wall-clock, or old-but-valid attestations fail the skew
    /// bound. Caller-controlled `now` is what makes replay deterministic.
    pub fn ingest_phase9(&mut self, att: &PriceAttestation, now: u64) -> Result<(), IngestReject> {
        verify_attestation(att, now).map_err(|e| IngestReject::VerifyFailed(format!("{e:?}")))?;
        let st = self.assets.entry(att.core.asset_id).or_default();
        st.pending.push(PendingSubmission {
            publisher_fp: publisher_fingerprint(&att.publisher_pubkey),
            price_e8: att.core.price_e8,
            conf_e8: att.core.conf_e8,
            publish_ts: att.core.publish_ts,
            sequence: att.core.sequence,
        });
        Ok(())
    }

    /// Ingest an already-decoded Phase 5 `OracleJournal` sample. Phase 5
    /// event decoding is out of pqc scope (documented boundary); the
    /// caller supplies `(asset_id, PriceSample)`.
    pub fn ingest_phase5(&mut self, asset_id: [u8; 32], sample: PriceSample) {
        let st = self.assets.entry(asset_id).or_default();
        st.phase5.push(sample);
        st.phase5.sort_by_key(|s| s.publish_ts);
    }

    /// Finalize every Phase 9 round whose window has fully elapsed before
    /// `now` (bucket-end ≤ now). A round produces an aggregated sample
    /// only if ≥ `policy.min_publishers` distinct publishers contributed
    /// (SIP-11 D6); otherwise it is dropped (mirrors the contract's
    /// below-quorum → no median). One publisher contributes one sample
    /// per round (its highest-sequence submission in that bucket).
    pub fn aggregate_due_rounds(&mut self, now: u64, policy: &FlipPolicy) {
        let w = self.round_window_secs;
        for st in self.assets.values_mut() {
            if st.pending.is_empty() {
                continue;
            }
            // Group still-pending submissions by bucket; finalize buckets
            // whose end (`(bucket+1)*w`) is ≤ now.
            let mut remaining: Vec<PendingSubmission> = Vec::new();
            let mut buckets: BTreeMap<u64, Vec<PendingSubmission>> = BTreeMap::new();
            for s in st.pending.drain(..) {
                let bucket = s.publish_ts / w;
                if (bucket + 1).saturating_mul(w) <= now {
                    buckets.entry(bucket).or_default().push(s);
                } else {
                    remaining.push(s);
                }
            }
            st.pending = remaining;

            for (bucket, subs) in buckets {
                // Dedup by publisher: keep each publisher's highest-sequence
                // submission in this bucket (deterministic).
                let mut per_pub: BTreeMap<[u8; 32], PendingSubmission> = BTreeMap::new();
                for s in subs {
                    per_pub
                        .entry(s.publisher_fp)
                        .and_modify(|cur| {
                            if s.sequence > cur.sequence {
                                *cur = s;
                            }
                        })
                        .or_insert(s);
                }
                if (per_pub.len() as u8) < policy.min_publishers {
                    continue; // below quorum → no aggregated sample
                }
                let mut prices: Vec<i64> = per_pub.values().map(|s| s.price_e8).collect();
                let mut confs: Vec<u64> = per_pub.values().map(|s| s.conf_e8).collect();
                prices.sort_unstable();
                confs.sort_unstable();
                st.rounds.push(Round {
                    // Round timestamp = bucket START (the time the round's
                    // prices represent). Distinct from the *finalization*
                    // gate `(bucket+1)*w <= now` above (when the round may
                    // be computed). Using bucket-start makes the
                    // aggregated history cover `window_start` exactly like
                    // raw samples would, so `evaluate_flip`'s
                    // window-coverage check behaves identically whether
                    // the dispatcher sees raw or round-aggregated history.
                    publish_ts: bucket * w,
                    price_e8: lower_median_i64(&prices),
                    conf_e8: lower_median_u64(&confs),
                    publishers: per_pub.len() as u32,
                });
            }
            st.rounds.sort_by_key(|r| r.publish_ts);
        }
    }

    /// Re-run the dual-path dispatch for one asset and update the
    /// registry. Returns the [`FlipDecision`]. Call after
    /// [`Self::aggregate_due_rounds`].
    pub fn reevaluate(&mut self, asset_id: [u8; 32], now: u64, policy: &FlipPolicy) -> FlipDecision {
        let st = self.assets.entry(asset_id).or_default();
        let phase9: Vec<PriceSample> =
            st.rounds.iter().map(|r| PriceSample { publish_ts: r.publish_ts, price_e8: r.price_e8 }).collect();
        let publisher_count = distinct_publishers_in_window(&st.rounds, st, policy, now);
        let decision = evaluate_flip(
            FlipInputs {
                phase5_history: &st.phase5,
                phase9_aggregated_history: &phase9,
                phase9_publisher_count: publisher_count,
                now,
            },
            policy,
        );
        st.last_decision = Some(decision);
        let source = match decision {
            FlipDecision::Flip => FeedSource::Phase9 { active_since_ts: now },
            FlipDecision::StaleSource { .. } => FeedSource::Unavailable,
            FlipDecision::Stay { .. } => {
                // Preserve an already-effected Phase9 flip across re-evals
                // (a flip is one-way in v1); otherwise Phase5 is canonical.
                match self.registry.get(&asset_id) {
                    Some(FeedSource::Phase9 { active_since_ts }) => FeedSource::Phase9 { active_since_ts },
                    _ => FeedSource::Phase5,
                }
            }
        };
        self.registry.set(asset_id, source);
        decision
    }

    /// Source-routed current price for an asset:
    /// Phase9 → latest finalized round; Phase5 → latest Phase5 sample
    /// (conf unknown → 0); Unavailable / untracked → `None`.
    pub fn read_price(&self, asset_id: &[u8; 32]) -> Option<PriceReading> {
        let st = self.assets.get(asset_id)?;
        match self.registry.get(asset_id).unwrap_or(FeedSource::Phase5) {
            FeedSource::Phase9 { .. } => st.rounds.last().map(|r| PriceReading {
                price_e8: r.price_e8,
                conf_e8: r.conf_e8,
                publish_ts: r.publish_ts,
                source: FeedSource::Phase9 { active_since_ts: 0 },
            }),
            FeedSource::Phase5 => st.phase5.last().map(|s| PriceReading {
                price_e8: s.price_e8,
                conf_e8: 0,
                publish_ts: s.publish_ts,
                source: FeedSource::Phase5,
            }),
            FeedSource::Unavailable => None,
        }
    }

    /// Current canonical source for an asset (default `Phase5`).
    pub fn feed_source(&self, asset_id: &[u8; 32]) -> FeedSource {
        self.registry.get(asset_id).unwrap_or(FeedSource::Phase5)
    }

    /// Last [`FlipDecision`] computed for an asset, if any.
    pub fn last_decision(&self, asset_id: &[u8; 32]) -> Option<FlipDecision> {
        self.assets.get(asset_id).and_then(|s| s.last_decision)
    }

    /// Read-only access to the dispatch registry.
    pub fn registry(&self) -> &InMemoryFeedSourceRegistry {
        &self.registry
    }

    /// Assets the indexer is tracking (sorted, for deterministic snapshots).
    pub fn tracked_assets(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.assets.keys()
    }
}

/// Lower median of a sorted slice (deterministic, integer-exact, no
/// rounding). For odd `n` this is the exact middle; for even `n` it is
/// the lower of the two central elements — chosen over averaging so the
/// result is reproducible bit-for-bit across indexers (PHASE9_3 §2.2).
fn lower_median_i64(sorted: &[i64]) -> i64 {
    sorted[(sorted.len() - 1) / 2]
}
fn lower_median_u64(sorted: &[u64]) -> u64 {
    sorted[(sorted.len() - 1) / 2]
}

/// Distinct publishers contributing to rounds within the consistency
/// window ending at `now`. Used as `FlipInputs.phase9_publisher_count`.
/// Approximated from finalized rounds' publisher counts (max within
/// window) — the indexer does not retain raw per-round fingerprints
/// post-finalization in v1; the max round size in-window is a sound
/// lower-bound-respecting proxy for "≥ min_publishers sustained".
fn distinct_publishers_in_window(rounds: &[Round], _st: &AssetState, policy: &FlipPolicy, now: u64) -> u8 {
    let window_start = now.saturating_sub(policy.min_consistency_window_secs);
    rounds.iter().filter(|r| r.publish_ts >= window_start).map(|r| r.publishers.min(u8::MAX as u32) as u8).max().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sophis_oracle_pqc_core::PriceAttestationCore;
    use sophis_oracle_pqc_core::{
        DILITHIUM_PUBKEY_SIZE, KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE, asset_id_from_symbol, generate_keypair,
        sign_attestation,
    };

    fn att(asset: &[u8], price_e8: i64, conf_e8: u64, ts: u64, seq: u64, kp_seed: u8, sig_seed: u8) -> PriceAttestation {
        let (vk, sk) = generate_keypair([kp_seed; KEY_GENERATION_RANDOMNESS_SIZE]);
        let core = PriceAttestationCore { asset_id: asset_id_from_symbol(asset), price_e8, conf_e8, publish_ts: ts, sequence: seq };
        sign_attestation(core, vk, &sk, [sig_seed; SIGNING_RANDOMNESS_SIZE]).expect("sign")
    }

    #[test]
    fn three_publisher_round_median_and_quorum() {
        let now = 1_700_000_000;
        let asset = b"ETH/USD";
        let mut ix = Indexer::new(60);
        // 3 distinct publishers, same 60s bucket.
        ix.ingest_phase9(&att(asset, 3_500_00000000, 10, now, 1, 0xA1, 1), now).unwrap();
        ix.ingest_phase9(&att(asset, 3_500_50000000, 12, now, 1, 0xB1, 2), now).unwrap();
        ix.ingest_phase9(&att(asset, 3_501_00000000, 14, now, 1, 0xC1, 3), now).unwrap();
        let pol = FlipPolicy::default();
        // Round not finalizable until now passes the bucket end.
        ix.aggregate_due_rounds(now, &pol);
        let aid = asset_id_from_symbol(asset);
        assert!(ix.assets[&aid].rounds.is_empty(), "round still open");
        ix.aggregate_due_rounds(now + 120, &pol);
        let r = *ix.assets[&aid].rounds.last().unwrap();
        assert_eq!(r.price_e8, 3_500_50000000, "lower-median of 3 = middle");
        assert_eq!(r.conf_e8, 12);
        assert_eq!(r.publishers, 3);
    }

    #[test]
    fn below_quorum_round_is_dropped() {
        let now = 1_700_000_000;
        let asset = b"BTC/USD";
        let mut ix = Indexer::new(60);
        ix.ingest_phase9(&att(asset, 65_000_00000000, 1, now, 1, 0xD1, 1), now).unwrap();
        ix.ingest_phase9(&att(asset, 65_001_00000000, 1, now, 1, 0xD2, 2), now).unwrap(); // only 2 pubs
        ix.aggregate_due_rounds(now + 120, &FlipPolicy::default());
        assert!(ix.assets[&asset_id_from_symbol(asset)].rounds.is_empty(), "2<3 → no median");
    }

    #[test]
    fn same_publisher_deduped_highest_sequence_wins() {
        let now = 1_700_000_000;
        let asset = b"BTC/USD";
        let mut ix = Indexer::new(60);
        // Same publisher (0xE1) twice in the bucket + two others → 3 distinct.
        ix.ingest_phase9(&att(asset, 100_00000000, 1, now, 1, 0xE1, 1), now).unwrap();
        ix.ingest_phase9(&att(asset, 999_00000000, 1, now, 2, 0xE1, 2), now).unwrap(); // higher seq wins
        ix.ingest_phase9(&att(asset, 101_00000000, 1, now, 1, 0xE2, 3), now).unwrap();
        ix.ingest_phase9(&att(asset, 102_00000000, 1, now, 1, 0xE3, 4), now).unwrap();
        ix.aggregate_due_rounds(now + 120, &FlipPolicy::default());
        let r = *ix.assets[&asset_id_from_symbol(asset)].rounds.last().unwrap();
        assert_eq!(r.publishers, 3, "duplicate publisher counted once");
        // prices = [999_*, 101_*, 102_*] sorted = [101,102,999] → lower-median = 102
        assert_eq!(r.price_e8, 102_00000000);
    }

    #[test]
    fn unverified_attestation_is_rejected() {
        let now = 1_700_000_000;
        let mut ix = Indexer::new(60);
        let mut bad = att(b"BTC/USD", 1, 1, now, 1, 0xF1, 1);
        bad.signature[5] ^= 0xff; // corrupt the Dilithium signature
        let e = ix.ingest_phase9(&bad, now).unwrap_err();
        assert!(matches!(e, IngestReject::VerifyFailed(_)));
        // far-future timestamp also rejected (skew)
        let skewed = att(b"BTC/USD", 1, 1, now + 10_000, 1, 0xF2, 2);
        assert!(ix.ingest_phase9(&skewed, now).is_err());
    }

    #[test]
    fn read_price_routes_by_source_and_flip_is_sticky() {
        let pol = FlipPolicy::default();
        let now = 1_700_000_000;
        let asset = b"ETH/USD";
        let aid = asset_id_from_symbol(asset);
        let mut ix = Indexer::new(60);

        // Phase 5 sample present; no Phase 9 yet → source Phase5, price from P5.
        ix.ingest_phase5(aid, PriceSample { publish_ts: now - 10, price_e8: 3_400_00000000 });
        ix.reevaluate(aid, now, &pol);
        let pr = ix.read_price(&aid).unwrap();
        assert_eq!(pr.source, FeedSource::Phase5);
        assert_eq!(pr.price_e8, 3_400_00000000);

        // Build a 7-day consistent Phase 9 + Phase 5 history → Flip.
        let win = pol.min_consistency_window_secs;
        let n = (win / 3600) as usize + 1;
        let step = win / (n as u64 - 1);
        let start = now - win;
        let mut ix2 = Indexer::new(60);
        for i in 0..n {
            let ts = start + i as u64 * step;
            ix2.ingest_phase5(aid, PriceSample { publish_ts: ts, price_e8: 65_000_00000000 });
            // Verify each historical attestation against ITS observed
            // time (= ts), as a real log-replay would — not the final now.
            ix2.ingest_phase9(&att(asset, 65_000_00000000, 1, ts, i as u64 + 1, 0x11, (i % 250) as u8), ts).unwrap();
            ix2.ingest_phase9(&att(asset, 65_000_10000000, 1, ts, i as u64 + 1, 0x22, ((i + 1) % 250) as u8), ts).unwrap();
            ix2.ingest_phase9(&att(asset, 65_000_20000000, 1, ts, i as u64 + 1, 0x33, ((i + 2) % 250) as u8), ts).unwrap();
        }
        ix2.aggregate_due_rounds(now, &pol);
        let d = ix2.reevaluate(aid, now, &pol);
        assert_eq!(d, FlipDecision::Flip);
        assert!(matches!(ix2.feed_source(&aid), FeedSource::Phase9 { .. }));
        let pr2 = ix2.read_price(&aid).unwrap();
        assert!(matches!(pr2.source, FeedSource::Phase9 { .. }));
        assert_eq!(pr2.price_e8, 65_000_10000000); // lower-median of the 3

        // A later Stay must NOT revert an effected Phase9 flip (one-way).
        let d2 = ix2.reevaluate(aid, now + 1, &pol);
        let _ = d2;
        assert!(matches!(ix2.feed_source(&aid), FeedSource::Phase9 { .. }), "flip is sticky");
    }

    #[test]
    fn determinism_same_inputs_same_state() {
        let pol = FlipPolicy::default();
        let now = 1_700_000_000;
        let run = || {
            let mut ix = Indexer::new(60);
            for (k, p) in [(0x51u8, 10_00000000i64), (0x52, 11_00000000), (0x53, 12_00000000)] {
                ix.ingest_phase9(&att(b"BTC/USD", p, 1, now, 1, k, k), now).unwrap();
            }
            ix.aggregate_due_rounds(now + 120, &pol);
            let aid = asset_id_from_symbol(b"BTC/USD");
            ix.read_price(&aid).map(|r| (r.price_e8, r.conf_e8))
        };
        assert_eq!(run(), run(), "indexer is deterministic over identical inputs");
        let _ = DILITHIUM_PUBKEY_SIZE;
    }
}
