//! Frozen wire-format types for the Phase 9 PQC-native oracle.
//!
//! Every constant and struct in this file is ABI-locked per SIP-11.
//! Changing a layout, field order, or byte size requires a new SIP.
//!
//! Wire-format byte sizes (borsh-encoded):
//!
//! - `PriceAttestationCore`: 64 bytes
//! - `PriceAttestation`:     `64 + 1312 + 2420 = 3796` bytes
//!
//! Plus tx framing (≈200 bytes) yields ≈4 KB per submission on chain.

use borsh::{BorshDeserialize, BorshSerialize};
use sha3::{Digest, Sha3_384};

use crate::error::OraclePqcError;

/// Dilithium ML-DSA-44 public-key size (FIPS 204, parameter set 2).
pub const DILITHIUM_PUBKEY_SIZE: usize = 1312;

/// Dilithium ML-DSA-44 signing-key size (FIPS 204, parameter set 2).
pub const DILITHIUM_SIGNING_KEY_SIZE: usize = 2560;

/// Dilithium ML-DSA-44 signature size (FIPS 204, parameter set 2).
pub const DILITHIUM_SIG_SIZE: usize = 2420;

/// Domain separator for Phase 9 oracle signatures. The trailing `\0`
/// is mandatory and hashed in. Bumping the `v1` suffix is a hard fork
/// of the oracle wire format (but not of the L1 chain).
pub const DOMAIN_SEPARATOR: &[u8] = b"sophis-oracle-pqc-v1\0";

/// Maximum acceptable skew between a publisher's wall-clock
/// `publish_ts` and the verifier-supplied `now` (seconds, each
/// direction). Rejects far-future and far-past submissions to
/// neutralise replay-by-time attacks. Per SIP-11 § 4.2 step 8.
pub const MAX_SKEW_SECS: u64 = 600;

/// The bytes that go into the Dilithium signature. Borsh-encoded.
///
/// Fixed-size: 32 + 8 + 8 + 8 + 8 = 64 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PriceAttestationCore {
    /// Canonical 32-byte asset id, per SIP-11 D7:
    /// `SHA3-384(symbol)[..32]` where `symbol` is e.g. `b"BTC/USD"`.
    /// The `/` separator is mandatory.
    pub asset_id: [u8; 32],

    /// Price × 10^8, signed. Negative values permitted (futures basis,
    /// interest rates). The sentinel `i64::MIN` is rejected at verify.
    pub price_e8: i64,

    /// 1-sigma confidence interval × 10^8, unsigned. Must fit in
    /// `i64::MAX` when cast (the verifier checks the cast).
    pub conf_e8: u64,

    /// Publisher wall-clock timestamp, seconds since Unix epoch. The
    /// verifier compares this against its supplied `now` and rejects
    /// submissions further than `MAX_SKEW_SECS` in either direction.
    pub publish_ts: u64,

    /// Monotonic per-publisher per-asset sequence number. The
    /// aggregator contract enforces strict monotonicity to rule out
    /// replays and out-of-order delivery.
    pub sequence: u64,
}

/// Signed wire format submitted to the aggregator contract.
///
/// Fixed-size: 64 + 1312 + 2420 = 3796 bytes.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct PriceAttestation {
    pub core: PriceAttestationCore,

    /// Dilithium ML-DSA-44 public key (1,312 bytes).
    pub publisher_pubkey: [u8; DILITHIUM_PUBKEY_SIZE],

    /// Dilithium ML-DSA-44 signature over `compute_signing_hash(core)`.
    /// Boxed to keep `PriceAttestation` cheap to move; 2,420 bytes on
    /// the stack would be wasteful in queues and hot paths.
    pub signature: Box<[u8; DILITHIUM_SIG_SIZE]>,
}

impl PriceAttestation {
    /// Borsh-decode a `PriceAttestation` from raw transaction-payload
    /// bytes. Returns `OraclePqcError::DecodeFailed` on any parse error.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OraclePqcError> {
        borsh::from_slice(bytes).map_err(|_| OraclePqcError::DecodeFailed)
    }

    /// Borsh-encode this attestation. Errors are propagated as
    /// `OraclePqcError::EncodeFailed` though the fixed-size struct
    /// makes failure unreachable in practice.
    pub fn to_bytes(&self) -> Result<Vec<u8>, OraclePqcError> {
        borsh::to_vec(self).map_err(|_| OraclePqcError::EncodeFailed)
    }

    /// Static-shape validation that runs before signature verification.
    /// Surfaces the cheap rejects (price sentinel, confidence overflow,
    /// timestamp skew) so callers fail fast and don't pay the Dilithium
    /// verify cost on obvious garbage.
    pub fn validate_shape(&self, now: u64) -> Result<(), OraclePqcError> {
        if self.core.price_e8 == i64::MIN {
            return Err(OraclePqcError::InvalidPrice);
        }
        if self.core.conf_e8 > i64::MAX as u64 {
            return Err(OraclePqcError::InvalidConfidence);
        }
        let skew = self.core.publish_ts.abs_diff(now);
        if skew > MAX_SKEW_SECS {
            return Err(OraclePqcError::TimestampOutOfSkew);
        }
        Ok(())
    }
}

/// Compute the 32-byte signing-hash for an attestation core, under a
/// given domain separator. Splits domain bytes and core bytes into
/// length-prefixed fields before hashing, eliminating any ambiguity
/// about where the domain ends and the payload begins.
///
/// Returns the first 32 bytes of `SHA3-384(...)` (matches the
/// chain-wide SHA3-384-truncated-to-32 convention).
pub fn compute_signing_hash(domain: &[u8], core: &PriceAttestationCore) -> [u8; 32] {
    let mut hasher = Sha3_384::new();
    hasher.update((domain.len() as u32).to_le_bytes());
    hasher.update(domain);

    let core_bytes = borsh::to_vec(core).expect("PriceAttestationCore is fixed-size and always encodes");
    hasher.update((core_bytes.len() as u32).to_le_bytes());
    hasher.update(&core_bytes);

    let full = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

/// Canonical asset-id derivation per SIP-11 D7.
///
/// `asset_id_from_symbol(b"BTC/USD")` returns `SHA3-384("BTC/USD")[..32]`.
/// The `/` separator is mandatory by convention; this function does
/// not enforce that — callers should ensure their input matches the
/// canonical form.
pub fn asset_id_from_symbol(symbol: &[u8]) -> [u8; 32] {
    let full = Sha3_384::digest(symbol);
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}
