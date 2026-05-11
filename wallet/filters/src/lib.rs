//! K2 — Sophis compact block filters.
//!
//! BIP-157/158-equivalent per-block filter for SPV light clients,
//! adapted to Sophis's SHA3-384 hash family. Canonical reference:
//! `docs/K2_COMPACT_FILTERS_DESIGN.md`. Frozen ABI per design §7.
//!
//! # Quick start
//!
//! ```rust
//! use sophis_compact_filters::{build_basic_filter, filter_hash, filter_matches};
//! use sophis_hashes::Hash;
//!
//! // Per-block items: every output SPK + every spent-input SPK.
//! let items: Vec<&[u8]> = vec![&[0x01, 0x02], &[0x03, 0x04, 0x05]];
//! let block_hash = Hash::from_slice(&[0xABu8; 32]);
//!
//! let filter = build_basic_filter(&block_hash, &items);
//! let h = filter_hash(&filter);
//! assert_eq!(h.len(), 32);
//!
//! // Membership query: known item present.
//! assert!(filter_matches(&filter, &block_hash, &[0x01, 0x02]).unwrap());
//! // Unknown item very unlikely to match (1/M ≈ 1.9e-6).
//! assert!(!filter_matches(&filter, &block_hash, &[0xFFu8; 32]).unwrap());
//! ```

pub mod codec;
pub mod error;
pub mod filter;

pub use codec::{decode_compact_size, encode_compact_size};
pub use error::{FilterError, FilterResult};
pub use filter::{
    DOMAIN_SEPARATOR, GOLOMB_RICE_P, build_basic_filter, build_filter_header, filter_hash, filter_matches, hash_item, map_to_range,
};
