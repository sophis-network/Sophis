//! Phase 9 PQC-native oracle — frozen wire-format types + Dilithium
//! ML-DSA-44 sign / verify helpers.
//!
//! See `docs/PQC_NATIVE_ORACLE_DESIGN.md` and `SIPS/SIP-11-PQC-ORACLE.md`
//! for the design rationale and ratified decisions. The wire format
//! defined here is ABI-frozen — any change requires a new SIP.

mod error;
mod sign;
mod source;
mod types;

pub use error::OraclePqcError;
pub use sign::{
    KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE, generate_keypair, sign_attestation, verify_attestation,
    verify_attestation_with_domain,
};
pub use source::{
    FeedSource, FeedSourceRegistry, FlipDecision, FlipInputs, FlipPolicy, InMemoryFeedSourceRegistry, PriceSample, StayReason,
    evaluate_flip,
};
pub use types::{
    DILITHIUM_PUBKEY_SIZE, DILITHIUM_SIG_SIZE, DILITHIUM_SIGNING_KEY_SIZE, DOMAIN_SEPARATOR, MAX_SKEW_SECS, PriceAttestation,
    PriceAttestationCore, asset_id_from_symbol, compute_signing_hash,
};
