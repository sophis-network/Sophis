//! `sophis-oracle-sdk` — consumer-side SDK for Phase 5 ZK-Oracle.
//!
//! Apps that want to read a Pyth-derived price feed off the Sophis L1
//! call this SDK rather than reimplementing the on-chain contract decode
//! path. The SDK abstracts:
//!
//!   - Connecting to a sophisd RPC endpoint (or a mock for tests)
//!   - Locating the oracle contract's feed-state UTXO
//!   - Decoding the [`FeedSnapshot`] from its `ScriptPublicKey`
//!
//! ## Basic usage
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use sophis_oracle_sdk::{FeedReader, MockBackend, FeedSnapshot};
//! use sophis_oracle_core::FeedId;
//!
//! // Tests: in-memory snapshots.
//! let backend = MockBackend::new();
//! backend.insert(FeedId(*b"BTC/USD\0"), FeedSnapshot {
//!     price: 65_000_00,
//!     exponent: -8,
//!     publish_time: 1_700_000_000,
//!     sequence: 42,
//!     publisher: [1u8; 32],
//! });
//! let reader = FeedReader::new(Box::new(backend));
//! let snap = reader.read(FeedId(*b"BTC/USD\0")).await?;
//! assert_eq!(snap.unwrap().price, 65_000_00);
//! # Ok(()) }
//! ```
//!
//! Production replaces `MockBackend` with `GrpcBackend` (gated by the
//! `grpc-read` feature):
//!
//! ```ignore
//! use sophis_oracle_sdk::{FeedReader, GrpcBackend};
//! let backend = GrpcBackend::new("127.0.0.1:46110", "sophis:qx<contract>", "mainnet");
//! let reader = FeedReader::new(Box::new(backend));
//! let snap = reader.read(feed_id).await?;
//! ```

use async_trait::async_trait;
use borsh::{BorshDeserialize, BorshSerialize};
use sophis_oracle_core::{FeedId, PublisherKey};

#[cfg(feature = "grpc-read")]
pub mod grpc;

#[cfg(feature = "grpc-read")]
pub use grpc::GrpcBackend;

/// Latest accepted price observation for one feed, as the on-chain
/// contract persists it.
///
/// `price * 10^exponent` is the human-readable price (Pyth convention).
/// `sequence` is the monotonic counter the contract uses to reject
/// replays — apps MAY use it to detect missed updates between polls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct FeedSnapshot {
    pub price: i64,
    pub exponent: i32,
    pub publish_time: u64,
    pub sequence: u64,
    pub publisher: [u8; 32],
}

impl FeedSnapshot {
    /// Convert to the high-level `PublisherKey` newtype used by
    /// `sophis-oracle-core`. Apps that only display the publisher in hex
    /// can read `self.publisher` directly.
    pub fn publisher_key(&self) -> PublisherKey {
        PublisherKey(self.publisher)
    }

    /// Render `price · 10^exponent` as `f64`. Convenient for UI; do NOT
    /// use for value-bearing computations (precision lossy for very
    /// large/small magnitudes).
    pub fn price_as_f64(&self) -> f64 {
        (self.price as f64) * 10f64.powi(self.exponent)
    }
}

/// Errors surfaced by the reader. Production callers typically log and
/// retry on `Transport`/`Stale`, and abort on `BadDecode` (indicates a
/// contract-protocol mismatch).
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("bad address: {0}")]
    BadAddress(String),
    #[error("feed not found: {0:?}")]
    FeedNotFound(FeedId),
    #[error("malformed feed-state UTXO at the contract address: {0}")]
    BadDecode(String),
    #[error("backend not implemented (rebuild with --features grpc-read)")]
    NotImplemented,
}

/// Backend trait — implementations decide HOW to fetch the FeedSnapshot
/// (in-memory mock, gRPC against sophisd, future wRPC, etc.).
#[async_trait]
pub trait Backend: Send + Sync {
    async fn read(&self, feed: FeedId) -> Result<Option<FeedSnapshot>, SdkError>;
}

/// High-level reader the app uses. Wraps any `Backend`. Adds
/// convenience methods (read, read_or_err) so the app doesn't always
/// need to handle `Option` explicitly.
pub struct FeedReader {
    backend: Box<dyn Backend>,
}

impl FeedReader {
    pub fn new(backend: Box<dyn Backend>) -> Self {
        Self { backend }
    }

    /// Returns `Ok(None)` if the feed has never been published. Returns
    /// `Err(_)` only on transport / decode failures.
    pub async fn read(&self, feed: FeedId) -> Result<Option<FeedSnapshot>, SdkError> {
        self.backend.read(feed).await
    }

    /// Returns `Err(SdkError::FeedNotFound)` instead of `Ok(None)`.
    /// Convenient for callers that treat a missing feed as a hard error.
    pub async fn read_or_err(&self, feed: FeedId) -> Result<FeedSnapshot, SdkError> {
        match self.backend.read(feed).await? {
            Some(snap) => Ok(snap),
            None => Err(SdkError::FeedNotFound(feed)),
        }
    }
}

// =============================================================================
// MockBackend — used by app tests + SDK self-tests
// =============================================================================

/// In-memory backend with a manually-controlled snapshot map. Useful
/// for unit tests in apps that consume the SDK — no gRPC, no sophisd,
/// no relayer.
pub struct MockBackend {
    snapshots: tokio::sync::RwLock<std::collections::HashMap<FeedId, FeedSnapshot>>,
}

impl MockBackend {
    pub fn new() -> Self {
        Self { snapshots: tokio::sync::RwLock::new(std::collections::HashMap::new()) }
    }

    /// Insert / overwrite the snapshot for `feed`. Synchronous because
    /// `tokio::sync::RwLock::blocking_write` is fine in a test fixture.
    pub fn insert(&self, feed: FeedId, snap: FeedSnapshot) {
        self.snapshots.blocking_write().insert(feed, snap);
    }

    /// Async insert — for callers already inside an async context
    /// (e.g. a tokio test).
    pub async fn insert_async(&self, feed: FeedId, snap: FeedSnapshot) {
        self.snapshots.write().await.insert(feed, snap);
    }

    /// Remove all snapshots — useful between test cases.
    pub async fn clear(&self) {
        self.snapshots.write().await.clear();
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Backend for MockBackend {
    async fn read(&self, feed: FeedId) -> Result<Option<FeedSnapshot>, SdkError> {
        let snaps = self.snapshots.read().await;
        Ok(snaps.get(&feed).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(price: i64) -> FeedSnapshot {
        FeedSnapshot { price, exponent: -8, publish_time: 1_700_000_000, sequence: 1, publisher: [1u8; 32] }
    }

    #[tokio::test]
    async fn mock_returns_none_for_missing_feed() {
        let backend = MockBackend::new();
        let reader = FeedReader::new(Box::new(backend));
        let r = reader.read(FeedId(*b"BTC/USD\0")).await.unwrap();
        assert!(r.is_none());
    }

    #[tokio::test]
    async fn mock_returns_inserted_snapshot() {
        let backend = MockBackend::new();
        backend.insert_async(FeedId(*b"BTC/USD\0"), snap(65_000_00)).await;
        let reader = FeedReader::new(Box::new(backend));
        let r = reader.read(FeedId(*b"BTC/USD\0")).await.unwrap().expect("ok");
        assert_eq!(r.price, 65_000_00);
        assert_eq!(r.publisher_key().0, [1u8; 32]);
    }

    #[tokio::test]
    async fn read_or_err_returns_feed_not_found() {
        let backend = MockBackend::new();
        let reader = FeedReader::new(Box::new(backend));
        let r = reader.read_or_err(FeedId(*b"BTC/USD\0")).await;
        assert!(matches!(r, Err(SdkError::FeedNotFound(_))));
    }

    #[tokio::test]
    async fn snapshot_borsh_round_trip() {
        let s = snap(65_000_00);
        let bytes = borsh::to_vec(&s).unwrap();
        let s2: FeedSnapshot = borsh::from_slice(&bytes).unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn price_as_f64_basic() {
        // 65_000_00 with exponent -2 → 65000.00
        let s = FeedSnapshot { price: 65_000_00, exponent: -2, publish_time: 0, sequence: 0, publisher: [0u8; 32] };
        let f = s.price_as_f64();
        assert!((f - 65_000.00).abs() < 1e-6);
    }

    #[test]
    fn price_as_f64_negative_price() {
        // Pyth supports negative prices (e.g. some commodities). SDK must too.
        let s = FeedSnapshot { price: -1_000, exponent: -2, publish_time: 0, sequence: 0, publisher: [0u8; 32] };
        let f = s.price_as_f64();
        assert!((f + 10.00).abs() < 1e-6);
    }

    #[tokio::test]
    async fn multiple_feeds_isolated() {
        let backend = MockBackend::new();
        backend.insert_async(FeedId(*b"BTC/USD\0"), snap(65_000_00)).await;
        backend.insert_async(FeedId(*b"ETH/USD\0"), snap(3_000_00)).await;
        let reader = FeedReader::new(Box::new(backend));
        assert_eq!(reader.read(FeedId(*b"BTC/USD\0")).await.unwrap().unwrap().price, 65_000_00);
        assert_eq!(reader.read(FeedId(*b"ETH/USD\0")).await.unwrap().unwrap().price, 3_000_00);
    }

    #[tokio::test]
    async fn mock_clear_drops_all_snapshots() {
        let backend = MockBackend::new();
        backend.insert_async(FeedId(*b"BTC/USD\0"), snap(65_000_00)).await;
        backend.clear().await;
        let reader = FeedReader::new(Box::new(backend));
        let r = reader.read(FeedId(*b"BTC/USD\0")).await.unwrap();
        assert!(r.is_none());
    }
}
