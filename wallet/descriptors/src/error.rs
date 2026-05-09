//! Error types for descriptor parse and resolve operations.
//!
//! See `wallet/descriptors/DESIGN.md` §9.

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseError {
    #[error("Unknown script type: {0}")]
    InvalidScriptType(String),

    #[error("Unclosed parenthesis")]
    UnclosedParenthesis,

    #[error("Unclosed bracket in key origin")]
    UnclosedBracket,

    #[error("multi-mldsa44 requires at least one key")]
    EmptyKeyList,

    #[error("Threshold {threshold} out of range; max is {max}")]
    ThresholdOutOfRange { threshold: u32, max: u32 },

    #[error("Too many keys in multi-mldsa44: {provided} provided, max {max}")]
    TooManyKeys { provided: usize, max: usize },

    #[error("Invalid Dilithium verification key length: {provided} hex chars (expected {expected})")]
    InvalidVkLength { provided: usize, expected: usize },

    #[error("Invalid hex characters in verification key: {0}")]
    InvalidVkHex(String),

    #[error("Invalid fingerprint length (expected 8 hex chars)")]
    InvalidFingerprintLength,

    #[error("Invalid hex characters in fingerprint")]
    InvalidFingerprintHex,

    #[error("Invalid derivation step: {0}")]
    InvalidDerivationStep(String),

    #[error("Missing checksum suffix (#xxxxxxxx)")]
    MissingChecksum,

    #[error("Invalid checksum character: {0}")]
    InvalidChecksumChar(char),

    #[error("Checksum mismatch — expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("Fingerprint in key origin does not match derived fingerprint of key")]
    FingerprintMismatch,

    #[error("Empty descriptor input")]
    EmptyInput,

    #[error("Unexpected token: {0}")]
    UnexpectedToken(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ResolveError {
    #[error("Hierarchical deterministic derivation is not supported in PSBS v1 (see DESIGN.md D1)")]
    HdDerivationNotYetSupported,

    #[error("Multisig resolution is not supported in v1; depends on Account Abstraction (see wallet/aa-spec/)")]
    MultiSigNotYetSupported,

    #[error("Failed to construct redeem script: {0}")]
    RedeemScriptError(String),
}
