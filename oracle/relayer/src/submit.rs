//! Sub-fase 5.4.e + 5.4.f.1 — L1 submission.
//!
//! Two implementations of the `L1Submit` trait:
//!
//!   - `MockSubmit` — always available; signs the bundle and records
//!     (bundle, wire_payload, signature) tuples. Used by the daemon by
//!     default and by integration tests.
//!   - `GrpcSubmit` — production submitter, gated by the `grpc-submit`
//!     feature flag. Connects to sophisd via gRPC, builds + signs the
//!     invocation tx, calls `submit_transaction`. See `grpc.rs`.
//!
//! Wire layout of the submitted tx:
//!
//! ```text
//! Inputs:  [0..N]  relayer's spendable Dilithium P2SH UTXOs (fee)
//! Outputs: [0]     ORACLE_INVOKE_VERSION SPK with encode_wire bytes,
//!                  value = INVOCATION_UTXO_VALUE sompi
//!          [1]     change back to relayer (P2SH Dilithium), if > 0
//! ```

use async_trait::async_trait;

use crate::pipeline::RelayerBundle;
use crate::sign::{RelayerKey, SignError, SignedBundle, sign_bundle};

#[cfg(feature = "grpc-submit")]
pub mod grpc;

/// Sompi locked in each oracle invocation UTXO. Will be reclaimed when
/// the contract spends it as input. Keep small — relayer pays this every
/// update.
pub const INVOCATION_UTXO_VALUE: u64 = 1_000;

/// Fixed fee per invocation tx. Generous to cover Dilithium sig mass +
/// storage mass for the (potentially large) invocation SPK script.
pub const SUBMIT_TX_FEE: u64 = 50_000;

/// gRPC connection timeout (ms).
pub const GRPC_CONNECT_TIMEOUT_MS: u64 = 15_000;

/// Non-coinbase UTXO maturity used by the sequencer rollup pattern.
/// We mirror it here for the relayer's fee UTXO selection.
pub const NON_COINBASE_MATURITY: u64 = 10;
pub const COINBASE_MATURITY_DEVNET: u64 = 20;

#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    #[error("sign error: {0}")]
    Sign(#[from] SignError),
    #[error("gRPC transport error: {0}")]
    Transport(String),
    #[error("transaction rejected by node: {0}")]
    Rejected(String),
    #[error("invalid contract/relayer address: {0}")]
    BadAddress(String),
    #[error("no spendable UTXOs at relayer address")]
    NoSpendableUtxos,
    #[error("fee UTXO too small: have {have} sompi, need {need}")]
    InsufficientFunds { have: u64, need: u64 },
    #[error("submit not implemented yet (rebuild with --features grpc-submit)")]
    NotImplemented,
    #[error("serialization: {0}")]
    Serialization(String),
}

/// L1 submission interface. Production impl is `GrpcSubmit`; tests use
/// `MockSubmit`.
#[async_trait]
pub trait L1Submit: Send + Sync {
    /// Sign + encode + submit one bundle. Returns the resulting L1 txid.
    async fn submit_bundle(&self, bundle: &RelayerBundle) -> Result<[u8; 32], SubmitError>;

    /// Phase 6 — optionally publish `wire_bytes` as a V5 DA carrier
    /// (domain = Oracle). `expected_bundle_id` is `SHA3-384(wire_bytes)`;
    /// implementations MAY assert that every fragment header carries it.
    /// Default impl is a no-op so existing tests keep compiling.
    async fn publish_carrier(&self, _wire_bytes: &[u8], _expected_bundle_id: [u8; 48]) -> Result<(), SubmitError> {
        Ok(())
    }
}

// =============================================================================
// MockSubmit — used by tests + daemon default
// =============================================================================

/// Test/dev no-op that records what was submitted. Useful for the daemon
/// loop integration tests which assert the daemon assembled the expected
/// payload without spinning up a sophisd.
pub struct MockSubmit {
    pub key: RelayerKey,
    pub submitted: std::sync::Mutex<Vec<MockSubmitted>>,
    pub carrier_publishes: std::sync::Mutex<Vec<MockCarrierPublished>>,
}

#[derive(Debug, Clone)]
pub struct MockSubmitted {
    pub bundle: RelayerBundle,
    pub wire_payload: Vec<u8>,
    pub signature: [u8; crate::sign::ML_DSA_44_SIG_SIZE],
}

/// Records carrier publishes (for Phase 6 daemon tests).
#[derive(Debug, Clone)]
pub struct MockCarrierPublished {
    pub wire_bytes: Vec<u8>,
    pub bundle_id: [u8; 48],
}

impl MockSubmit {
    pub fn new(key: RelayerKey) -> Self {
        Self { key, submitted: std::sync::Mutex::new(Vec::new()), carrier_publishes: std::sync::Mutex::new(Vec::new()) }
    }
}

#[async_trait]
impl L1Submit for MockSubmit {
    async fn submit_bundle(&self, bundle: &RelayerBundle) -> Result<[u8; 32], SubmitError> {
        let signature = sign_bundle(bundle, &self.key)?;
        let signed = SignedBundle { bundle: bundle.clone(), signature, verification_key: self.key.verification_key.clone() };
        let wire = signed.encode_wire()?;
        self.submitted.lock().unwrap().push(MockSubmitted { bundle: bundle.clone(), wire_payload: wire, signature });
        // Pretend-txid: deterministic over sequence so tests can assert on it.
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&bundle.journal.sequence.to_le_bytes());
        Ok(out)
    }

    async fn publish_carrier(&self, wire_bytes: &[u8], expected_bundle_id: [u8; 48]) -> Result<(), SubmitError> {
        self.carrier_publishes
            .lock()
            .unwrap()
            .push(MockCarrierPublished { wire_bytes: wire_bytes.to_vec(), bundle_id: expected_bundle_id });
        Ok(())
    }
}

// =============================================================================
// GrpcSubmit — production, gated behind the `grpc-submit` feature
// =============================================================================

/// Production submitter. Holds a relayer key + L1 endpoint info.
///
/// With feature `grpc-submit` ON: opens a fresh gRPC connection per call,
/// builds and signs the invocation tx, submits via `submit_transaction`.
/// No connection pooling — one tx per `daemon.interval_secs` is not
/// latency-sensitive.
///
/// With feature `grpc-submit` OFF (default): `submit_bundle` returns
/// `SubmitError::NotImplemented`. The struct still exists so the daemon
/// can take a `Box<dyn L1Submit>` from config without conditional
/// compilation in the caller.
pub struct GrpcSubmit {
    pub endpoint: String,
    pub contract_address: String,
    pub key: RelayerKey,
    /// Sophis network prefix used to derive the relayer's L1 address.
    /// Production typically uses `Mainnet` / `Testnet`; devnet smoke
    /// tests use `Devnet`. Stored as a string so the relayer config
    /// can drive it without leaking sophis-addresses into the API
    /// surface when the feature is OFF.
    pub network_prefix: String,
}

impl GrpcSubmit {
    pub fn new(
        endpoint: impl Into<String>,
        contract_address: impl Into<String>,
        network_prefix: impl Into<String>,
        key: RelayerKey,
    ) -> Self {
        Self { endpoint: endpoint.into(), contract_address: contract_address.into(), network_prefix: network_prefix.into(), key }
    }
}

#[cfg(not(feature = "grpc-submit"))]
#[async_trait]
impl L1Submit for GrpcSubmit {
    async fn submit_bundle(&self, _bundle: &RelayerBundle) -> Result<[u8; 32], SubmitError> {
        Err(SubmitError::NotImplemented)
    }
    // publish_carrier inherits the trait default (no-op) when grpc-submit is off.
}

#[cfg(feature = "grpc-submit")]
#[async_trait]
impl L1Submit for GrpcSubmit {
    async fn submit_bundle(&self, bundle: &RelayerBundle) -> Result<[u8; 32], SubmitError> {
        grpc::submit_bundle_grpc(self, bundle).await
    }

    /// Phase 6 — opt-in DA publish (sub-fase 6.6 wire + this real impl).
    /// Builds a single tx with V5 carriers (domain = Oracle) for the
    /// signed bundle bytes and submits it via the same gRPC endpoint.
    async fn publish_carrier(&self, wire_bytes: &[u8], expected_bundle_id: [u8; 48]) -> Result<(), SubmitError> {
        grpc::publish_carrier_grpc(self, wire_bytes, expected_bundle_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::{PipelinePolicy, build_bundle, fixture_submission};
    use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, ml_dsa_44};
    use sophis_oracle_core::{FeedId, ORACLE_INVOKE_VERSION, PublisherKey};

    fn make_keypair() -> RelayerKey {
        let mut randomness = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
        getrandom::getrandom(&mut randomness).unwrap();
        let kp = ml_dsa_44::generate_key_pair(randomness);
        let mut sk = [0u8; crate::sign::ML_DSA_44_SK_SIZE];
        let mut vk = [0u8; crate::sign::ML_DSA_44_VK_SIZE];
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

    fn ok_bundle() -> RelayerBundle {
        let sub = fixture_submission(65_000_00, 1_700_000_080, [1u8; 32]);
        build_bundle(sub, &ok_policy(), 100, 99, 1_700_000_120).unwrap()
    }

    #[tokio::test]
    async fn mock_submit_records_bundle_and_signs() {
        let mock = MockSubmit::new(make_keypair());
        let bundle = ok_bundle();
        let txid = mock.submit_bundle(&bundle).await.expect("submit ok");
        let mut expected_txid = [0u8; 32];
        expected_txid[..8].copy_from_slice(&bundle.journal.sequence.to_le_bytes());
        assert_eq!(txid, expected_txid);

        let recorded = mock.submitted.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        let entry = &recorded[0];
        assert_eq!(entry.bundle.journal.sequence, 100);
        assert!(!entry.wire_payload.is_empty());
        let decoded = crate::sign::decode_wire(&entry.wire_payload).expect("decode ok");
        assert_eq!(decoded.now_secs, bundle.now_secs);
        assert_eq!(*decoded.signature, entry.signature);
    }

    #[tokio::test]
    async fn mock_submit_two_bundles_distinct_txids() {
        let mock = MockSubmit::new(make_keypair());
        let mut b1 = ok_bundle();
        b1.journal.sequence = 100;
        let mut b2 = ok_bundle();
        b2.journal.sequence = 101;
        let t1 = mock.submit_bundle(&b1).await.unwrap();
        let t2 = mock.submit_bundle(&b2).await.unwrap();
        assert_ne!(t1, t2);
        assert_eq!(mock.submitted.lock().unwrap().len(), 2);
    }

    #[cfg(not(feature = "grpc-submit"))]
    #[tokio::test]
    async fn grpc_submit_returns_not_implemented_without_feature() {
        let key = make_keypair();
        let submit = GrpcSubmit::new("127.0.0.1:46110", "sophis:qx", "devnet", key);
        let bundle = ok_bundle();
        let r = submit.submit_bundle(&bundle).await;
        assert!(matches!(r, Err(SubmitError::NotImplemented)));
    }

    /// With the feature ON, `submit_bundle` will try to connect to
    /// 127.0.0.1:1 (no listener) and fail with a Transport error rather
    /// than NotImplemented — proves the dispatch path is wired.
    #[cfg(feature = "grpc-submit")]
    #[tokio::test]
    async fn grpc_submit_with_feature_on_attempts_real_connect() {
        let key = make_keypair();
        // 127.0.0.1:1 is reserved/unbound — connect will fail fast.
        let submit = GrpcSubmit::new("127.0.0.1:1", "sophis:qx", "devnet", key);
        let bundle = ok_bundle();
        let r = submit.submit_bundle(&bundle).await;
        assert!(
            matches!(r, Err(SubmitError::Transport(_)) | Err(SubmitError::BadAddress(_))),
            "expected Transport or BadAddress error, got {r:?}",
        );
    }

    #[test]
    fn invoke_version_constant_is_seven() {
        assert_eq!(ORACLE_INVOKE_VERSION, 7);
    }
}
