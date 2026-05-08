//! Sub-fase 5.4.c — pull → prove → bundle pipeline.
//!
//! Given a `PriceFeed`, a `FeedPolicy`, and a wall-clock `now_secs`, this
//! module:
//!
//!   1. Pulls the latest `PythnetSubmission` for `(feed, publisher)`.
//!   2. Builds an `OracleAir` proof binding `(price, publish_time, sequence)`
//!      via `oracle::prove`.
//!   3. (If `verify_air_companion` is enabled) builds a `VerifyAirChip`
//!      proof binding the publisher's `(public_key, signature)` via the
//!      sub-fase 5.4.b boundary exposure.
//!   4. Returns a `RelayerBundle` ready for `sign` (5.4.d) + `submit` (5.4.e).
//!
//! The companion proof is **slow** (~1-30s release for the ed25519 verify
//! AIR), so the pipeline runs `prove_verify_air` inside a `spawn_blocking`
//! wrapper so the daemon's tokio runtime is not starved.
//!
//! Soundness today: OracleAir proves the Sophis-controlled bounds/freshness/
//! sequence/binding side; verify_air proves the publisher's signature was
//! valid over *some* `(R, A, sB, hA)` tuple. Message binding (i.e. that
//! the signed bytes encode the price the journal claims) is still deferred
//! to the companion-aggregation chain (5.4 future work).

use async_trait::async_trait;
use sophis_oracle_core::{FeedId, OracleJournal, PriceUpdate, PublisherKey, PythnetSubmission};
use sophis_oracle_feeds::{FeedError, PriceFeed};
use sophis_oracle_host::{prove, ProveInputs, ProverError};
use sophis_oracle_host::verify_air_stark::{encode_public_values_bytes, prove_verify_air, VerifyAirProverError};
use sophis_oracle_host::decompress_air_stark::{
    encode_public_values_bytes as decompress_encode_pv,
    prove_decompress_air,
};
use sophis_oracle_host::sha512_air_stark::{
    encode_public_values_bytes as sha512_encode_pv,
    prove_sha512_air,
};
use sophis_oracle_host::reduce_mod_l_air_stark::{
    encode_public_values_bytes as reduce_encode_pv,
    prove_reduce_mod_l_air,
};
use sophis_oracle_host::scalar_mul_air_stark::{
    encode_public_values_bytes as scalar_mul_encode_pv,
    prove_scalar_mul_air,
};

/// What the relayer ships to L1 in one update.
///
/// Layout chosen so the contract can verify in one pass:
///   1. Decode `journal` from `journal_borsh`.
///   2. Verify `oracle_proof` against `oracle_air_id_v1` with public values
///      `(borsh(journal) || u64_le(now_secs))`.
///   3. (If present) verify `verify_air_proof` against `verify_air_id_v1`
///      with public values `verify_air_public_values` (96 bytes: pk || sig).
///   4. Confirm `verify_air_public_values[..32] == journal.publisher.0` so
///      the proven signature belongs to the publisher the journal claims.
///   5. Verify the relayer's Dilithium signature over the bundle commitment.
#[derive(Debug, Clone)]
pub struct RelayerBundle {
    pub journal: OracleJournal,
    pub oracle_proof_bytes: Vec<u8>,
    pub verify_air_proof_bytes: Option<Vec<u8>>,
    pub verify_air_public_values: Option<Vec<u8>>,
    /// Wall-clock seconds at the moment the proof was produced — must be
    /// echoed in the contract's public-values reconstruction.
    pub now_secs: u64,

    // Sub-fase 5.6.a-f — companion proofs that close message binding.
    // All `Option<(proof_bytes, public_values_bytes)>` for graceful
    // degradation when companion=false.
    pub decompress_r_proof: Option<(Vec<u8>, Vec<u8>)>,
    pub decompress_a_proof: Option<(Vec<u8>, Vec<u8>)>,
    pub sha512_proof: Option<(Vec<u8>, Vec<u8>)>,
    pub reduce_mod_l_proof: Option<(Vec<u8>, Vec<u8>)>,
    pub scalar_mul_sb_proof: Option<(Vec<u8>, Vec<u8>)>,
    pub scalar_mul_ha_proof: Option<(Vec<u8>, Vec<u8>)>,
}

/// Static policy the pipeline enforces before invoking the prover. Mirrors
/// the on-chain `FeedPolicy` in `sophis-oracle-contract` so the relayer
/// rejects upstream what the contract would reject downstream.
#[derive(Debug, Clone)]
pub struct PipelinePolicy {
    pub feed: FeedId,
    pub publisher: PublisherKey,
    pub min_price: i64,
    pub max_price: i64,
    pub max_age_secs: u64,
    pub verify_air_companion: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("feed transport error: {0}")]
    Feed(#[from] FeedError),
    #[error("oracle prover error: {0}")]
    Prover(#[from] ProverError),
    #[error("verify_air prover error: {0}")]
    VerifyAirProver(#[from] VerifyAirProverError),
    #[error("publisher mismatch: pulled {pulled} but configured {configured}")]
    PublisherMismatch { pulled: PublisherKey, configured: PublisherKey },
    #[error("feed mismatch: pulled {pulled:?} but configured {configured:?}")]
    FeedMismatch { pulled: FeedId, configured: FeedId },
    #[error("background task panicked: {0}")]
    Join(String),
}

/// Synchronous core of the pipeline. Exposed separately so tests can drive
/// it without awaiting; the async wrapper `run_once` adds spawn_blocking
/// for the slow STARK provers.
pub fn build_bundle(
    submission: PythnetSubmission,
    policy: &PipelinePolicy,
    sequence: u64,
    last_sequence: u64,
    now_secs: u64,
) -> Result<RelayerBundle, PipelineError> {
    if submission.update.feed != policy.feed {
        return Err(PipelineError::FeedMismatch { pulled: submission.update.feed, configured: policy.feed });
    }
    if submission.update.publisher != policy.publisher {
        return Err(PipelineError::PublisherMismatch {
            pulled: submission.update.publisher,
            configured: policy.publisher,
        });
    }

    // Build the OracleAir proof + journal.
    let signed = sophis_oracle_core::SignedPriceUpdate {
        update: submission.update.clone(),
        signature: submission.signature.clone(),
    };
    let inputs = ProveInputs {
        signed: &signed,
        now_secs,
        min_price: policy.min_price,
        max_price: policy.max_price,
        max_age_secs: policy.max_age_secs,
        sequence,
        last_sequence,
    };
    let oracle_proof = prove(inputs)?;

    // Optional verify_air companion + 5.6.a-f aggregation chain.
    let mut verify_air_proof_bytes = None;
    let mut verify_air_public_values = None;
    let mut decompress_r_proof = None;
    let mut decompress_a_proof = None;
    let mut sha512_proof = None;
    let mut reduce_mod_l_proof = None;
    let mut scalar_mul_sb_proof = None;
    let mut scalar_mul_ha_proof = None;

    if policy.verify_air_companion {
        use sophis_oracle_host::chips::ed25519::decompress::decompress;
        use sophis_oracle_host::chips::ed25519::point::ExtendedPoint;
        use sophis_oracle_host::chips::ed25519::verify::reduce_mod_l;

        let pk = submission.update.publisher.0;
        let sig: [u8; 64] = *submission.signature;
        let msg = &submission.tx_message;

        // verify_air (5.6.0).
        let va_proof = prove_verify_air(&pk, &sig, msg)?;
        let va_pv = encode_public_values_bytes(&pk, &sig, &va_proof.boundary);
        verify_air_proof_bytes = Some(va_proof.bytes);
        verify_air_public_values = Some(va_pv);

        // 5.6.a — decompress(R_bytes) → R_point. R = sig[0..32].
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&sig[0..32]);
        let dec_r = prove_decompress_air(&r_bytes).map_err(|e| {
            PipelineError::Join(format!("decompress(R) prove failed: {e}"))
        })?;
        let dec_r_pv = decompress_encode_pv(&r_bytes, &dec_r.output, dec_r.valid);
        decompress_r_proof = Some((dec_r.bytes, dec_r_pv));

        // 5.6.b — decompress(A_bytes) → A_point. A = pk.
        let dec_a = prove_decompress_air(&pk).map_err(|e| {
            PipelineError::Join(format!("decompress(A) prove failed: {e}"))
        })?;
        let dec_a_pv = decompress_encode_pv(&pk, &dec_a.output, dec_a.valid);
        decompress_a_proof = Some((dec_a.bytes, dec_a_pv));

        // 5.6.c — sha512(R || A || M).
        let mut hash_input = Vec::with_capacity(64 + msg.len());
        hash_input.extend_from_slice(&r_bytes);
        hash_input.extend_from_slice(&pk);
        hash_input.extend_from_slice(msg);
        let sha = prove_sha512_air(&hash_input).map_err(|e| PipelineError::Join(format!("sha512 prove: {e}")))?;
        let sha_pv = sha512_encode_pv(&hash_input, &sha.digest);
        sha512_proof = Some((sha.bytes, sha_pv));

        // 5.6.d — reduce_mod_l(digest) → h.
        let red = prove_reduce_mod_l_air(&sha.digest)
            .map_err(|e| PipelineError::Join(format!("reduce_mod_l prove: {e}")))?;
        let red_pv = reduce_encode_pv(&sha.digest, &red.scalar);
        reduce_mod_l_proof = Some((red.bytes, red_pv));

        // 5.6.e — scalar_mul(s, basepoint) → sB. s = sig[32..64].
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&sig[32..64]);
        let mut basepoint_compressed = [0x66u8; 32];
        basepoint_compressed[0] = 0x58;
        let basepoint = decompress(&basepoint_compressed).unwrap_or_else(ExtendedPoint::neutral);
        let sm_sb = prove_scalar_mul_air(&s_bytes, &basepoint).map_err(|e| {
            PipelineError::Join(format!("scalar_mul(s,B) prove: {e}"))
        })?;
        let sm_sb_pv = scalar_mul_encode_pv(&s_bytes, &basepoint, &sm_sb.output);
        scalar_mul_sb_proof = Some((sm_sb.bytes, sm_sb_pv));

        // 5.6.f — scalar_mul(h, A_point) → hA.
        // Sanity: red.scalar should equal what we'd get re-running reduce_mod_l on the digest.
        let h_scalar = reduce_mod_l(&sha.digest);
        debug_assert_eq!(h_scalar, red.scalar);
        let sm_ha = prove_scalar_mul_air(&h_scalar, &dec_a.output).map_err(|e| {
            PipelineError::Join(format!("scalar_mul(h,A) prove: {e}"))
        })?;
        let sm_ha_pv = scalar_mul_encode_pv(&h_scalar, &dec_a.output, &sm_ha.output);
        scalar_mul_ha_proof = Some((sm_ha.bytes, sm_ha_pv));
    }

    Ok(RelayerBundle {
        journal: oracle_proof.journal,
        oracle_proof_bytes: oracle_proof.bytes,
        verify_air_proof_bytes,
        verify_air_public_values,
        now_secs,
        decompress_r_proof,
        decompress_a_proof,
        sha512_proof,
        reduce_mod_l_proof,
        scalar_mul_sb_proof,
        scalar_mul_ha_proof,
    })
}

/// Async pipeline driver: pulls one Pythnet submission and builds a bundle.
/// The slow STARK provers run on `tokio::task::spawn_blocking` so the tokio
/// reactor stays responsive even under long proving cycles.
pub async fn run_once(
    feed: &dyn PriceFeed,
    policy: &PipelinePolicy,
    sequence: u64,
    last_sequence: u64,
    now_secs: u64,
) -> Result<RelayerBundle, PipelineError> {
    let submission = feed.latest_submission(policy.feed, policy.publisher).await?;
    let policy = policy.clone();
    let bundle = tokio::task::spawn_blocking(move || {
        build_bundle(submission, &policy, sequence, last_sequence, now_secs)
    })
    .await
    .map_err(|e| PipelineError::Join(e.to_string()))??;
    Ok(bundle)
}

/// In-process stub feed used by integration tests. Returns a fixed
/// `PythnetSubmission` so the pipeline can be exercised without HTTP.
pub struct StubFeed {
    pub submission: PythnetSubmission,
}

#[async_trait]
impl PriceFeed for StubFeed {
    async fn latest_submission(
        &self,
        _feed: FeedId,
        _publisher: PublisherKey,
    ) -> Result<PythnetSubmission, FeedError> {
        Ok(self.submission.clone())
    }
}

/// Convenience helper to build a fixed `PythnetSubmission` for tests.
pub fn fixture_submission(price: i64, publish_time: u64, publisher: [u8; 32]) -> PythnetSubmission {
    PythnetSubmission {
        update: PriceUpdate {
            feed: FeedId(*b"BTC/USD\0"),
            publisher: PublisherKey(publisher),
            price,
            conf: 0,
            exponent: -8,
            publish_time,
        },
        tx_message: b"stub-tx-message".to_vec(),
        signature: Box::new([0u8; 64]),
        slot: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_policy() -> PipelinePolicy {
        PipelinePolicy {
            feed: FeedId(*b"BTC/USD\0"),
            publisher: PublisherKey([1u8; 32]),
            min_price: 1_000_00,
            max_price: 1_000_000_00,
            max_age_secs: 60,
            verify_air_companion: false, // companion is slow; off by default in tests
        }
    }

    #[test]
    fn build_bundle_happy_path_no_companion() {
        let sub = fixture_submission(65_000_00, 1_700_000_080, [1u8; 32]);
        let bundle = build_bundle(sub, &ok_policy(), 100, 99, 1_700_000_120).expect("ok");
        assert_eq!(bundle.journal.sequence, 100);
        assert_eq!(bundle.journal.price, 65_000_00);
        assert_eq!(bundle.now_secs, 1_700_000_120);
        assert!(!bundle.oracle_proof_bytes.is_empty());
        assert!(bundle.verify_air_proof_bytes.is_none());
        assert!(bundle.verify_air_public_values.is_none());
    }

    #[test]
    fn build_bundle_rejects_publisher_mismatch() {
        let sub = fixture_submission(65_000_00, 1_700_000_080, [9u8; 32]);
        let r = build_bundle(sub, &ok_policy(), 100, 99, 1_700_000_120);
        assert!(matches!(r, Err(PipelineError::PublisherMismatch { .. })));
    }

    #[test]
    fn build_bundle_rejects_feed_mismatch() {
        let mut sub = fixture_submission(65_000_00, 1_700_000_080, [1u8; 32]);
        sub.update.feed = FeedId(*b"ETH/USD\0");
        let r = build_bundle(sub, &ok_policy(), 100, 99, 1_700_000_120);
        assert!(matches!(r, Err(PipelineError::FeedMismatch { .. })));
    }

    #[test]
    fn build_bundle_rejects_oob_price() {
        // Price below min — OracleAir prover refuses witness.
        let sub = fixture_submission(1, 1_700_000_080, [1u8; 32]);
        let r = build_bundle(sub, &ok_policy(), 100, 99, 1_700_000_120);
        assert!(matches!(r, Err(PipelineError::Prover(ProverError::InvalidWitness))));
    }

    #[test]
    fn build_bundle_rejects_replayed_sequence() {
        let sub = fixture_submission(65_000_00, 1_700_000_080, [1u8; 32]);
        let r = build_bundle(sub, &ok_policy(), 50, 99, 1_700_000_120);
        assert!(matches!(r, Err(PipelineError::Prover(ProverError::InvalidWitness))));
    }

    #[tokio::test]
    async fn run_once_with_stub_feed() {
        let stub = StubFeed { submission: fixture_submission(65_000_00, 1_700_000_080, [1u8; 32]) };
        let bundle = run_once(&stub, &ok_policy(), 100, 99, 1_700_000_120).await.expect("ok");
        assert_eq!(bundle.journal.sequence, 100);
    }

    /// Slow end-to-end with companion ON. Builds an OracleAir proof AND a
    /// VerifyAirChip proof against an all-zero pk/sig (the AIR doesn't
    /// validate ed25519 cryptographically — it just proves the witness
    /// trace satisfies the algebraic constraints, and zeros yield the
    /// neutral point chain). Run with --include-ignored.
    #[test]
    #[ignore = "slow (~30-60s release); end-to-end pipeline with verify_air companion"]
    fn build_bundle_with_companion_full_e2e() {
        let mut policy = ok_policy();
        policy.verify_air_companion = true;
        let sub = fixture_submission(65_000_00, 1_700_000_080, [0u8; 32]);
        let mut policy_with_zero_pub = policy;
        policy_with_zero_pub.publisher = PublisherKey([0u8; 32]);
        let bundle = build_bundle(sub, &policy_with_zero_pub, 100, 99, 1_700_000_120).expect("ok");
        assert!(bundle.verify_air_proof_bytes.is_some());
        let pv = bundle.verify_air_public_values.as_ref().unwrap();
        assert_eq!(pv.len(), 96);
        assert_eq!(&pv[..32], &[0u8; 32], "pk part of pv must be zeros");
    }
}
