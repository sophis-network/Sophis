//! Production gRPC backend for the SDK (sub-fase 5.5.a, gated by `grpc-read`).
//!
//! Connects to a sophisd RPC endpoint and reads the oracle contract's
//! feed-state UTXO directly from the L1 UTXO set. Each call opens a
//! fresh `GrpcClient` — apps that read frequently should add their own
//! cache layer (the SDK intentionally leaves caching policy to the
//! caller because TTL trades freshness vs RPC load and depends on the
//! app's risk profile).
//!
//! ## Wire layout
//!
//! The relayer (sub-fase 5.4.f.1) submits one tx per update with
//! `output[0]` carrying `ScriptPublicKey { version = ORACLE_INVOKE_VERSION,
//! script = encode_wire(SignedBundle) }`. The on-chain contract decodes
//! the wire payload, runs all proof checks, and writes the resulting
//! `FeedSnapshot` into a different UTXO at the contract's own address
//! using a contract-owned SPK version (the SDK does NOT consume the
//! invocation UTXO directly — that's the contract's input).
//!
//! For sub-fase 5.5.a we use a **simple polling model**: query all
//! UTXOs at the contract address, filter by version tag
//! `FEED_STATE_VERSION` (defined in the contract spec), borsh-decode
//! the script as `(FeedId, FeedSnapshot)` pairs, and return the one
//! matching the requested feed. The contract MUST emit one feed-state
//! UTXO per active feed so this lookup is bounded by the number of
//! active feeds (typically <100).
//!
//! Cross-version compatibility: the SDK pins `FEED_STATE_VERSION = 8`
//! (the next free SPK version after `ORACLE_INVOKE_VERSION = 7`). A
//! contract bumping this version requires an SDK upgrade in lockstep.

use async_trait::async_trait;
use borsh::BorshDeserialize;
use sophis_addresses::Address;
use sophis_grpc_client::GrpcClient;
use sophis_notify::subscription::context::SubscriptionContext;
use sophis_oracle_core::FeedId;
use sophis_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};

use crate::{Backend, FeedSnapshot, SdkError};

/// SPK version the oracle contract uses for its feed-state UTXOs.
/// Pinned at SDK compile time; a contract bumping this version requires
/// a coordinated SDK upgrade. See `oracle/docs/CONTRACT_DISPATCH.md`.
pub const FEED_STATE_VERSION: u16 = 8;

/// gRPC connection timeout (ms).
pub const GRPC_CONNECT_TIMEOUT_MS: u64 = 15_000;

/// Production backend. Holds the L1 endpoint + contract address.
pub struct GrpcBackend {
    pub endpoint: String,
    pub contract_address: String,
}

impl GrpcBackend {
    pub fn new(endpoint: impl Into<String>, contract_address: impl Into<String>) -> Self {
        Self { endpoint: endpoint.into(), contract_address: contract_address.into() }
    }

    async fn connect(&self) -> Result<GrpcClient, SdkError> {
        let ctx = SubscriptionContext::new();
        GrpcClient::connect_with_args(
            NotificationMode::Direct,
            format!("grpc://{}", self.endpoint),
            Some(ctx),
            false,
            None,
            false,
            Some(GRPC_CONNECT_TIMEOUT_MS),
            Default::default(),
        )
        .await
        .map_err(|e| SdkError::Transport(format!("gRPC connect to {}: {e}", self.endpoint)))
    }
}

#[async_trait]
impl Backend for GrpcBackend {
    async fn read(&self, feed: FeedId) -> Result<Option<FeedSnapshot>, SdkError> {
        let rpc = self.connect().await?;

        let addr = Address::try_from(self.contract_address.clone()).map_err(|e| SdkError::BadAddress(format!("{e}")))?;

        let entries =
            rpc.get_utxos_by_addresses(vec![addr]).await.map_err(|e| SdkError::Transport(format!("get_utxos_by_addresses: {e}")))?;

        for entry in entries {
            if entry.utxo_entry.script_public_key.version != FEED_STATE_VERSION {
                continue;
            }
            // Wire format: borsh((FeedId, FeedSnapshot)).
            let script = entry.utxo_entry.script_public_key.script();
            let Ok(decoded) = <(FeedId, FeedSnapshot)>::try_from_slice(script) else {
                log::warn!("feed-state UTXO at {} has unparseable script ({} bytes); skipping", self.contract_address, script.len(),);
                continue;
            };
            if decoded.0 == feed {
                return Ok(Some(decoded.1));
            }
        }

        Ok(None)
    }
}
