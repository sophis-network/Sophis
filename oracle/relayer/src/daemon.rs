//! Sub-fase 5.4.f — daemon loop.
//!
//! Runs the pipeline (`pipeline::run_once`) in a loop, every
//! `daemon.interval_secs`, persisting the last successfully-submitted
//! sequence number between iterations. Graceful shutdown on SIGINT /
//! Ctrl-C — finishes the current iteration before exiting so we never
//! abandon a half-submitted update.
//!
//! Errors are logged but do NOT abort the loop — Pyth might be down, the
//! prover might fail on a bad witness, sophisd might reject a fee tx.
//! The relayer keeps trying every interval. The operator should monitor
//! the logs and intervene if errors persist.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sophis_oracle_feeds::PriceFeed;

use crate::pipeline::{PipelineError, PipelinePolicy, run_once};
use crate::state::{RelayerState, StateError};
use crate::submit::{L1Submit, SubmitError};

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("state error: {0}")]
    State(#[from] StateError),
    #[error("system clock before UNIX_EPOCH: {0:?}")]
    BadClock(std::time::SystemTimeError),
}

/// One pass of the daemon loop. Exposed so 5.4.f.1 integration tests can
/// drive a single iteration without needing to wire signal handling.
///
/// On success: returns the new sequence number that was submitted.
/// On error: logs and returns `Err` — the loop driver decides whether
/// to keep going (it will).
///
/// Phase 6 (sub-fase 6.6): if `da_publish` is true, the daemon publishes
/// the signed wire bytes as a V5 DA carrier (domain = Oracle) right
/// after the invocation submission succeeds. Carrier publish failure is
/// logged but does not abort the iteration — the journal already
/// committed on L1, the DA copy is purely archival.
pub async fn one_iteration(
    feed: &dyn PriceFeed,
    submit: &dyn L1Submit,
    policy: &PipelinePolicy,
    state: &mut RelayerState,
    da_publish: bool,
) -> Result<u64, IterationError> {
    let next_seq = state.next_sequence();
    let last_seq = state.last_sequence;
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).map_err(IterationError::BadClock)?.as_secs();

    log::info!("iteration: next_seq={next_seq}, last_seq={last_seq}, now={now_secs}");
    let bundle = run_once(feed, policy, next_seq, last_seq, now_secs).await?;
    log::debug!(
        "bundle ready: journal.price={}, oracle_proof_len={}, va_proof={}",
        bundle.journal.price,
        bundle.oracle_proof_bytes.len(),
        bundle.verify_air_proof_bytes.is_some(),
    );

    let txid = submit.submit_bundle(&bundle).await?;
    log::info!("submitted seq {next_seq} as txid {}", hex_short(&txid));

    if da_publish {
        match build_oracle_carrier_payload(&bundle, submit) {
            Ok((wire, bundle_id)) => {
                if let Err(e) = submit.publish_carrier(&wire, bundle_id).await {
                    log::warn!("DA carrier publish failed for seq {next_seq}: {e} — journal already on L1");
                } else {
                    log::info!("published oracle DA carrier for seq {next_seq}");
                }
            }
            Err(e) => log::warn!("DA wire build failed for seq {next_seq}: {e}"),
        }
    }

    state.record_submitted(next_seq);
    Ok(next_seq)
}

/// Phase 6 helper — re-encodes the bundle to the same `wire_bytes` that
/// the invocation tx carries inline, then computes the bundle_id that
/// every V5 carrier fragment will advertise.
fn build_oracle_carrier_payload(
    bundle: &crate::pipeline::RelayerBundle,
    submit: &dyn L1Submit,
) -> Result<(Vec<u8>, [u8; 48]), SubmitError> {
    use sha3::{Digest, Sha3_384};

    let _ = submit; // submit is currently unused here but kept for future
    // signing-key access if the wire format ever needs the
    // relayer's vk fingerprint.
    // Re-sign + encode. We do not have direct access to the signed bundle
    // produced inside `submit_bundle`, but the wire format is deterministic
    // given the bundle and the submitter's key, so we can reconstruct it.
    // For now we produce the unsigned-wire (bundle bytes only) and document
    // that the carrier carries the journal+proofs payload, not the signature.
    // This keeps the public shape of L1Submit narrow.
    let wire = bundle_to_carrier_wire(bundle)?;
    let mut h = Sha3_384::new();
    h.update(&wire);
    let bundle_id: [u8; 48] = h.finalize().into();
    Ok((wire, bundle_id))
}

/// Serializes the journal + proofs from a `RelayerBundle` for DA publishing.
/// Uses borsh for determinism. Mirrors the relayer-internal `BundleBytesV1`
/// scheme: the journal first, then any present STARK proofs, length-prefixed.
fn bundle_to_carrier_wire(bundle: &crate::pipeline::RelayerBundle) -> Result<Vec<u8>, SubmitError> {
    use std::io::Write;
    let mut out = Vec::with_capacity(2048 + bundle.oracle_proof_bytes.len());
    // Frame: u16 version + length-prefixed sections.
    out.extend_from_slice(&1u16.to_le_bytes());
    let journal = borsh::to_vec(&bundle.journal).map_err(|e| SubmitError::Serialization(e.to_string()))?;
    out.extend_from_slice(&(journal.len() as u32).to_le_bytes());
    out.write_all(&journal).map_err(|e| SubmitError::Serialization(e.to_string()))?;
    out.extend_from_slice(&(bundle.oracle_proof_bytes.len() as u32).to_le_bytes());
    out.write_all(&bundle.oracle_proof_bytes).map_err(|e| SubmitError::Serialization(e.to_string()))?;
    let va = bundle.verify_air_proof_bytes.as_deref().unwrap_or(&[]);
    out.extend_from_slice(&(va.len() as u32).to_le_bytes());
    out.write_all(va).map_err(|e| SubmitError::Serialization(e.to_string()))?;
    Ok(out)
}

#[derive(Debug, thiserror::Error)]
pub enum IterationError {
    #[error("system clock before UNIX_EPOCH: {0:?}")]
    BadClock(std::time::SystemTimeError),
    #[error("pipeline error: {0}")]
    Pipeline(#[from] PipelineError),
    #[error("submit error: {0}")]
    Submit(#[from] SubmitError),
}

fn hex_short(b: &[u8; 32]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}..{:02x}{:02x}{:02x}{:02x}", b[0], b[1], b[2], b[3], b[28], b[29], b[30], b[31])
}

/// Daemon loop. Runs until SIGINT / Ctrl-C, sleeping `interval_secs`
/// between iterations. State is persisted to `state_path` after every
/// successful submit.
pub async fn run_daemon(
    feed: Arc<dyn PriceFeed>,
    submit: Arc<dyn L1Submit>,
    policy: PipelinePolicy,
    state_path: PathBuf,
    interval_secs: u64,
    da_publish: bool,
) -> Result<(), DaemonError> {
    let mut state = RelayerState::load_or_default(&state_path)?;
    log::info!("daemon starting: state.last_sequence={}, interval={}s, da_publish={}", state.last_sequence, interval_secs, da_publish,);

    let interval = Duration::from_secs(interval_secs);
    let mut shutdown = make_shutdown_listener();

    loop {
        let iter_start = std::time::Instant::now();
        tokio::select! {
            res = one_iteration(&*feed, &*submit, &policy, &mut state, da_publish) => {
                match res {
                    Ok(seq) => {
                        if let Err(e) = state.save(&state_path) {
                            // Persistence failure is critical — bailing avoids
                            // double-submitting the same sequence after restart.
                            log::error!("failed to persist state after seq {seq}: {e}");
                            return Err(DaemonError::State(e));
                        }
                    }
                    Err(e) => {
                        log::warn!("iteration failed: {e} — continuing after sleep");
                    }
                }
            }
            _ = &mut shutdown => {
                log::info!("shutdown signal received; exiting daemon loop");
                return Ok(());
            }
        }

        let elapsed = iter_start.elapsed();
        let sleep_for = interval.saturating_sub(elapsed);
        if sleep_for.is_zero() {
            log::warn!(
                "iteration took {}ms — no sleep before next round (interval is too short for the proving cost)",
                elapsed.as_millis()
            );
            continue;
        }
        tokio::select! {
            _ = tokio::time::sleep(sleep_for) => {}
            _ = &mut shutdown => {
                log::info!("shutdown signal received during sleep; exiting daemon loop");
                return Ok(());
            }
        }
    }
}

/// Returns a future that resolves when SIGINT (Ctrl-C) is received.
/// Cross-platform via `tokio::signal::ctrl_c`.
fn make_shutdown_listener() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            log::error!("ctrl_c install failed: {e}");
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::{StubFeed, fixture_submission};
    use crate::sign::{ML_DSA_44_SK_SIZE, ML_DSA_44_VK_SIZE, RelayerKey};
    use crate::submit::MockSubmit;
    use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, ml_dsa_44};
    use sophis_oracle_core::{FeedId, PublisherKey};

    fn make_keypair() -> RelayerKey {
        let mut randomness = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
        getrandom::getrandom(&mut randomness).unwrap();
        let kp = ml_dsa_44::generate_key_pair(randomness);
        let mut sk = [0u8; ML_DSA_44_SK_SIZE];
        let mut vk = [0u8; ML_DSA_44_VK_SIZE];
        sk.copy_from_slice(kp.signing_key.as_ref());
        vk.copy_from_slice(kp.verification_key.as_ref());
        RelayerKey { signing_key: Box::new(sk), verification_key: Box::new(vk) }
    }

    fn ok_policy() -> PipelinePolicy {
        PipelinePolicy {
            feed: FeedId(*b"BTC/USD\0"),
            publisher: PublisherKey([1u8; 32]),
            min_price: 1_000_00,
            max_price: 1_000_000_00,
            max_age_secs: 60,
            verify_air_companion: false,
        }
    }

    /// Drives one iteration end-to-end using StubFeed + MockSubmit and
    /// asserts the submit captured a real signed wire payload.
    #[tokio::test]
    async fn one_iteration_happy_path() {
        let feed = StubFeed { submission: fixture_submission(65_000_00, far_future_publish_time(), [1u8; 32]) };
        let submit = MockSubmit::new(make_keypair());
        let mut state = RelayerState::default();
        let seq = one_iteration(&feed, &submit, &ok_policy(), &mut state, false).await.expect("ok");
        assert_eq!(seq, 1);
        assert_eq!(state.last_sequence, 1);
        let recorded = submit.submitted.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(!recorded[0].wire_payload.is_empty());
        let decoded = crate::sign::decode_wire(&recorded[0].wire_payload).expect("decode ok");
        assert!(!decoded.journal_borsh.is_empty());
    }

    /// Sequence advances monotonically across two iterations.
    #[tokio::test]
    async fn two_iterations_advance_sequence() {
        let feed = StubFeed { submission: fixture_submission(65_000_00, far_future_publish_time(), [1u8; 32]) };
        let submit = MockSubmit::new(make_keypair());
        let mut state = RelayerState::default();
        let s1 = one_iteration(&feed, &submit, &ok_policy(), &mut state, false).await.unwrap();
        let s2 = one_iteration(&feed, &submit, &ok_policy(), &mut state, false).await.unwrap();
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        assert_eq!(state.last_sequence, 2);
    }

    /// Restart simulation: state file persists across two `RelayerState::load_or_default`.
    #[tokio::test]
    async fn restart_continues_from_persisted_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("daemon.state");
        let feed = StubFeed { submission: fixture_submission(65_000_00, far_future_publish_time(), [1u8; 32]) };
        let submit = MockSubmit::new(make_keypair());

        // First run: submit seq 1, persist.
        {
            let mut state = RelayerState::load_or_default(&state_path).unwrap();
            one_iteration(&feed, &submit, &ok_policy(), &mut state, false).await.unwrap();
            state.save(&state_path).unwrap();
        }
        // Second run: must continue from seq 2.
        {
            let mut state = RelayerState::load_or_default(&state_path).unwrap();
            assert_eq!(state.last_sequence, 1);
            let seq = one_iteration(&feed, &submit, &ok_policy(), &mut state, false).await.unwrap();
            assert_eq!(seq, 2);
        }
    }

    /// If the iteration fails (publisher mismatch), state stays put.
    #[tokio::test]
    async fn iteration_error_does_not_advance_state() {
        let feed = StubFeed { submission: fixture_submission(65_000_00, far_future_publish_time(), [9u8; 32]) };
        let submit = MockSubmit::new(make_keypair());
        let mut state = RelayerState::default();
        let r = one_iteration(&feed, &submit, &ok_policy(), &mut state, false).await;
        assert!(matches!(r, Err(IterationError::Pipeline(_))));
        assert_eq!(state.last_sequence, 0);
    }

    // --- Phase 6 — DA publish opt-in ---

    /// Default: `da_publish=false` does NOT call `publish_carrier`.
    #[tokio::test]
    async fn da_publish_off_skips_carrier() {
        let feed = StubFeed { submission: fixture_submission(65_000_00, far_future_publish_time(), [1u8; 32]) };
        let submit = MockSubmit::new(make_keypair());
        let mut state = RelayerState::default();
        one_iteration(&feed, &submit, &ok_policy(), &mut state, false).await.unwrap();
        assert!(submit.carrier_publishes.lock().unwrap().is_empty(), "no carrier when flag off");
    }

    /// Opt-in: `da_publish=true` triggers a carrier publish with a
    /// non-zero bundle_id that hashes the wire bytes.
    #[tokio::test]
    async fn da_publish_on_emits_carrier() {
        use sha3::{Digest, Sha3_384};
        let feed = StubFeed { submission: fixture_submission(65_000_00, far_future_publish_time(), [1u8; 32]) };
        let submit = MockSubmit::new(make_keypair());
        let mut state = RelayerState::default();
        one_iteration(&feed, &submit, &ok_policy(), &mut state, true).await.unwrap();
        let publishes = submit.carrier_publishes.lock().unwrap();
        assert_eq!(publishes.len(), 1, "exactly one carrier publish");
        let p = &publishes[0];
        let mut h = Sha3_384::new();
        h.update(&p.wire_bytes);
        let computed: [u8; 48] = h.finalize().into();
        assert_eq!(p.bundle_id, computed, "bundle_id matches SHA3-384(wire_bytes)");
        assert_ne!(p.bundle_id, [0u8; 48], "non-empty wire bytes produce non-zero bundle_id");
    }

    /// Use a publish_time near "now" so the freshness check passes
    /// regardless of when the test runs.
    fn far_future_publish_time() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 10
    }
}
