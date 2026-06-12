//! J5 — Sophis SPV light client library.
//!
//! Building blocks for wallet implementers writing an SPV light
//! client against Sophis: header chain validation, K2 filter chain
//! verification, wallet-scan helper, and Merkle-proof verification
//! re-exported from `sophis-merkle`.
//!
//! Canonical reference: `docs/J5_LIGHT_CLIENT_DESIGN.md`. See also
//! `SIPS/SIP-7-LIGHT-CLIENT.md`.
//!
//! # Quick start
//!
//! ```rust
//! use sophis_spv::{SyncCheckpoint, FilterChain, WalletScan, verify_merkle_proof};
//! use sophis_hashes::Hash;
//!
//! // Wallet starts from a trusted checkpoint (ship-with-binary or cached).
//! let checkpoint = SyncCheckpoint {
//!     block_hash:    Hash::from_slice(&[0u8; 32]),
//!     blue_score:    0,
//!     daa_score:     0,
//!     filter_header: [0u8; 32],
//! };
//!
//! // Walk forward: header chain, then filter chain, then per-block scan.
//! // (See docs/J5_LIGHT_CLIENT_DESIGN.md §3.1 for the full protocol.)
//! ```

pub mod checkpoint;
pub mod filter_chain;
pub mod header_chain;
pub mod scan;

pub use checkpoint::SyncCheckpoint;
pub use filter_chain::{FilterChain, FilterChainEntry, FilterChainError};
pub use header_chain::{HeaderChainError, MinHeader, validate_header_link};
#[cfg(feature = "randomx")]
pub use header_chain::{validate_header_link_and_pow, verify_pow};
pub use scan::{ScanResult, WalletScan};
// Re-exported for convenience: light clients verify per-tx proofs
// against block headers' `hash_merkle_root` via this function.
pub use sophis_merkle::{TxMerkleProof, build_merkle_proof, verify_merkle_proof};
