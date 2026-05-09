//! Sophis wallet descriptor language — BIP-380-style adapted for Dilithium ML-DSA-44.
//!
//! See `wallet/descriptors/DESIGN.md` for the canonical specification of the
//! grammar, decisions D1–D5, and the test-vector plan. This crate is the
//! reference implementation; it will graduate to formal SIP-2 once K3.7
//! completes.
//!
//! # Quick example
//!
//! ```ignore
//! use sophis_wallet_descriptors::{Descriptor, KeyData};
//! use sophis_wallet_pskt::crypto::DilithiumPubKey;
//!
//! let vk = DilithiumPubKey::from_bytes([0u8; 1312]);
//! let descriptor = Descriptor::Pkh {
//!     key: DescriptorKey::new_literal(vk),
//! };
//! let canonical_text = descriptor.to_string(); // pkh-mldsa44(...)#checksum
//! let parsed = canonical_text.parse::<Descriptor>().unwrap();
//! assert_eq!(descriptor, parsed);
//! ```
//!
//! # Layered modules
//!
//! - [`fingerprint`] — SHA3-384[..4] computation (D4).
//! - [`checksum`] — BIP-380 Bech32-style polymod (D5).
//! - [`parse`] — descriptor parser (K3.3, forthcoming).
//! - [`display`] — descriptor `Display` impl (K3.4, forthcoming).
//! - [`resolve`] — descriptor → ScriptPublicKey (K3.6, forthcoming).
//!
//! # Reading order for new contributors
//!
//! 1. `wallet/descriptors/DESIGN.md` end to end.
//! 2. `SIPS/SIP-1-PSBS.md` for analogous "design + spec → implementation" pattern.
//! 3. This module's `lib.rs` for the public API surface.
//! 4. `wallet/descriptors/tests/canonical_vectors.rs` (K3.7) for the
//!    invariants the implementation must satisfy.

pub mod checksum;
pub mod display;
pub mod error;
pub mod fingerprint;
pub mod parse;
pub mod resolve;
pub mod types;

pub use error::{ParseError, ResolveError};
pub use fingerprint::{Fingerprint, fingerprint};
pub use types::{Descriptor, DescriptorKey, KeyData, KeyOrigin};
