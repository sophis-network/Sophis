//! J2 — Sophis Typed Data Signing.
//!
//! EIP-712-equivalent typed-message signing adapted to Sophis's
//! SHA3-384 hash and Dilithium ML-DSA-44 signature primitives.
//!
//! Canonical reference: `docs/J2_TYPED_SIGNING_DESIGN.md`. Frozen ABI
//! per design §7 — any change requires a hard fork of the typed-signing
//! convention (no on-chain consensus impact, but signatures from
//! incompatible versions will not verify against compatible code).
//!
//! # Quick start
//!
//! ```rust
//! use sophis_typed_data::{TypedDataDomain, TypedField, TypedStruct, TypedValue, compute_typed_digest, NETWORK_DEVNET};
//!
//! // 1. Define your dApp's domain
//! let domain = TypedDataDomain::new("MyDApp", "1.0", NETWORK_DEVNET);
//!
//! // 2. Define your message schema
//! let schema = TypedStruct {
//!     name: "Mail".into(),
//!     fields: vec![
//!         TypedField { name: "from".into(), type_str: "address".into() },
//!         TypedField { name: "to".into(),   type_str: "address".into() },
//!         TypedField { name: "contents".into(), type_str: "string".into() },
//!     ],
//! };
//!
//! // 3. Provide values matching the schema (ordered)
//! let values = vec![
//!     TypedValue::Address([0xAA; 32]),
//!     TypedValue::Address([0xBB; 32]),
//!     TypedValue::String("gm".into()),
//! ];
//!
//! // 4. Compute the 32-byte digest to sign
//! let digest = compute_typed_digest(&domain, &schema, &values, &[]).unwrap();
//! assert_eq!(digest.len(), 32);
//! // sign `digest` with Dilithium
//! ```

pub mod digest;
pub mod domain;
pub mod encoder;
pub mod error;
pub mod types;

pub use digest::{TYPED_SIGNING_PREFIX, compute_typed_digest, sha3_384_truncated};
pub use domain::{NETWORK_DEVNET, NETWORK_MAINNET, NETWORK_SIMNET, NETWORK_TESTNET, TypedDataDomain};
pub use encoder::{canonical_type_string, encode_field_value, struct_hash, type_hash};
pub use error::{TypedDataError, TypedDataResult};
pub use types::{TypedField, TypedStruct, TypedValue};
