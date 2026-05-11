use thiserror::Error;

/// Errors returned by the Phase 9 PQC oracle wire-format helpers.
///
/// Every variant maps to a concrete validation rule in the design doc
/// (`docs/PQC_NATIVE_ORACLE_DESIGN.md` § 4.2) so an aggregator contract
/// implementer can map error→reject reason 1:1.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OraclePqcError {
    /// Borsh decode failed (input bytes are not a well-formed
    /// `PriceAttestation`).
    #[error("attestation: borsh decode failed")]
    DecodeFailed,

    /// Borsh encode of the signed payload failed. This should be
    /// unreachable in practice (fixed-size struct); kept for parity.
    #[error("attestation: borsh encode failed")]
    EncodeFailed,

    /// Dilithium signature did not validate against the supplied
    /// public key and signing-hash. Covers tampered core, tampered
    /// signature, wrong public key, and cross-domain replay attempts
    /// (the verifier reconstructs the signing-hash from the domain
    /// separator the caller supplies).
    #[error("attestation: signature verification failed")]
    InvalidSignature,

    /// `price_e8` is `i64::MIN` (used as a sentinel; reject).
    #[error("attestation: price sentinel value rejected")]
    InvalidPrice,

    /// `conf_e8` would overflow when cast to `i64` for comparison.
    /// `i64::MAX` is the largest acceptable confidence interval.
    #[error("attestation: confidence interval too large")]
    InvalidConfidence,

    /// `publish_ts` differs from the verifier-supplied `now` by more
    /// than `MAX_SKEW_SECS` in either direction. Rules out far-future
    /// and far-past submissions (replay-by-time).
    #[error("attestation: timestamp out of acceptable skew window")]
    TimestampOutOfSkew,
}
