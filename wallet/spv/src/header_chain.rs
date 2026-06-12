//! J5 — Header chain validation.
//!
//! Light-client-side validation of the cheap parent-link invariants
//! between consecutive headers in the GHOSTDAG selected chain.
//! PoW verification is delegated to the consumer (typically via
//! `sophis-pow`); this module focuses on the structural checks the
//! wallet needs to walk the chain forward.

use serde::{Deserialize, Serialize};
use sophis_hashes::Hash;
use thiserror::Error;

/// Minimum header info a light client needs to walk the chain.
/// Subset of the full `Header`; populated from `getHeaders` RPC
/// responses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinHeader {
    pub hash: Hash,
    pub selected_parent_hash: Hash,
    pub blue_score: u64,
    pub daa_score: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HeaderChainError {
    /// `next.selected_parent_hash != prev.hash`.
    #[error("parent linkage broken: prev={prev:?}, next.selected_parent={next_parent:?}")]
    ParentLinkageBroken { prev: Hash, next_parent: Hash },

    /// `next.blue_score <= prev.blue_score`.
    #[error("blue_score did not increase: prev={prev}, next={next}")]
    BlueScoreNonIncreasing { prev: u64, next: u64 },

    /// `next.daa_score < prev.daa_score`. Strictly less; equality is
    /// allowed because DAA score can be the same for blocks separated
    /// only by GHOSTDAG mergeset moves (rare but legal).
    #[error("daa_score went backwards: prev={prev}, next={next}")]
    DaaScoreWentBackwards { prev: u64, next: u64 },

    /// RandomX cache / dataset allocation failed (transient resource error).
    /// The caller should retry or fall back to trusting the peer.
    #[error("PoW state init failed: {msg}")]
    PowInitFailed { msg: String },

    /// The header's nonce does not satisfy its declared difficulty target.
    #[error("invalid PoW for block {hash:?}")]
    PowInvalid { hash: Hash },
}

/// Validates that `next` legitimately extends `prev` in the selected chain.
///
/// Pure structural check (parent linkage, blue_score, daa_score).
/// For full security use [`validate_header_link_and_pow`] which also
/// verifies the RandomX proof-of-work.
///
/// Checks:
/// * `next.selected_parent_hash == prev.hash`
/// * `next.blue_score > prev.blue_score`
/// * `next.daa_score >= prev.daa_score`
pub fn validate_header_link(prev: &MinHeader, next: &MinHeader) -> Result<(), HeaderChainError> {
    if next.selected_parent_hash != prev.hash {
        return Err(HeaderChainError::ParentLinkageBroken { prev: prev.hash, next_parent: next.selected_parent_hash });
    }
    if next.blue_score <= prev.blue_score {
        return Err(HeaderChainError::BlueScoreNonIncreasing { prev: prev.blue_score, next: next.blue_score });
    }
    if next.daa_score < prev.daa_score {
        return Err(HeaderChainError::DaaScoreWentBackwards { prev: prev.daa_score, next: next.daa_score });
    }
    Ok(())
}

/// Verifies that a block header's nonce satisfies its declared RandomX
/// proof-of-work target.
///
/// Uses light mode (256 MB cache, shared per epoch via thread-local) so it
/// does not allocate a 2 GB dataset. Expect ~5–10 ms per header on modern
/// hardware — acceptable for cold-sync, budget ~50–100 s for 10k headers.
///
/// Returns [`HeaderChainError::PowInitFailed`] on transient RandomX
/// allocation failure; the caller should retry or fall back to trusting
/// the full node. Returns [`HeaderChainError::PowInvalid`] when the nonce
/// does not meet the target.
#[cfg(feature = "randomx")]
pub fn verify_pow(header: &sophis_consensus_core::header::Header) -> Result<(), HeaderChainError> {
    use sophis_pow::State;
    let state = State::try_new(header).map_err(|e| HeaderChainError::PowInitFailed { msg: e.to_string() })?;
    let (passed, _pow) = state.check_pow(header.nonce);
    if !passed {
        return Err(HeaderChainError::PowInvalid { hash: header.hash });
    }
    Ok(())
}

/// Validates structural chain linkage **and** RandomX proof-of-work for
/// `next_full` in a single call.
///
/// `prev` and `next` carry the structural fields (hash, selected_parent_hash,
/// blue_score, daa_score). `next_full` is the complete header used for PoW
/// verification; callers typically construct both from the same RPC response.
///
/// Structural checks run first; PoW is only evaluated when they pass.
#[cfg(feature = "randomx")]
pub fn validate_header_link_and_pow(
    prev: &MinHeader,
    next: &MinHeader,
    next_full: &sophis_consensus_core::header::Header,
) -> Result<(), HeaderChainError> {
    validate_header_link(prev, next)?;
    verify_pow(next_full)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> Hash {
        Hash::from_slice(&[byte; 32])
    }

    fn header(hash: u8, parent: u8, blue: u64, daa: u64) -> MinHeader {
        MinHeader { hash: h(hash), selected_parent_hash: h(parent), blue_score: blue, daa_score: daa }
    }

    #[test]
    fn valid_link_accepted() {
        let prev = header(1, 0, 100, 100);
        let next = header(2, 1, 101, 101);
        assert!(validate_header_link(&prev, &next).is_ok());
    }

    #[test]
    fn equal_daa_score_accepted() {
        // GHOSTDAG can produce consecutive selected-chain blocks with
        // the same DAA score (mergeset reorganisation).
        let prev = header(1, 0, 100, 100);
        let next = header(2, 1, 101, 100);
        assert!(validate_header_link(&prev, &next).is_ok());
    }

    #[test]
    fn parent_linkage_broken_rejected() {
        let prev = header(1, 0, 100, 100);
        let next = header(2, 99, 101, 101); // wrong parent
        let err = validate_header_link(&prev, &next).unwrap_err();
        assert!(matches!(err, HeaderChainError::ParentLinkageBroken { .. }));
    }

    #[test]
    fn non_increasing_blue_score_rejected() {
        let prev = header(1, 0, 100, 100);
        let next = header(2, 1, 100, 101); // blue_score equal
        let err = validate_header_link(&prev, &next).unwrap_err();
        assert!(matches!(err, HeaderChainError::BlueScoreNonIncreasing { .. }));
    }

    #[test]
    fn backward_daa_score_rejected() {
        let prev = header(1, 0, 100, 100);
        let next = header(2, 1, 101, 99);
        let err = validate_header_link(&prev, &next).unwrap_err();
        assert!(matches!(err, HeaderChainError::DaaScoreWentBackwards { .. }));
    }

    // PoW verification tests require the `randomx` feature.
    #[cfg(feature = "randomx")]
    mod pow_tests {
        use super::*;
        use sophis_consensus_core::{header::Header, subnets::SUBNETWORK_ID_COINBASE};
        use sophis_hashes::Hash;

        fn zero_hash() -> Hash {
            Hash::from_slice(&[0u8; 32])
        }

        fn make_header(nonce: u64, bits: u32) -> Header {
            Header::new_finalized(
                sophis_consensus_core::constants::BLOCK_VERSION,
                vec![vec![zero_hash()]].try_into().unwrap(), // parents_by_level
                Default::default(),                          // hash_merkle_root
                Default::default(),                          // accepted_id_merkle_root
                zero_hash(),                                 // utxo_commitment
                1_000_000,                                   // timestamp (ms)
                bits,
                nonce,
                0,                  // daa_score (epoch 0)
                Default::default(), // blue_work
                1,                  // blue_score
                zero_hash(),        // pruning_point
            )
        }

        #[test]
        fn verify_pow_rejects_invalid_nonce() {
            // nonce=0 with max-difficulty bits is astronomically unlikely
            // to satisfy PoW — treated as "invalid" for the test.
            // bits=0x1d00ffff is Bitcoin-genesis difficulty (low); still
            // virtually certain to fail for nonce=0 with RandomX.
            let header = make_header(0, 0x1d00ffff);
            let result = verify_pow(&header);
            // Either PowInvalid (expected) or PowInitFailed (CI without
            // hugepages); both are non-Ok, which is the invariant.
            assert!(result.is_err(), "nonce=0 should not satisfy PoW");
        }

        #[test]
        fn validate_link_and_pow_structural_error_first() {
            // Broken parent linkage must be caught before PoW is checked.
            let prev = header(1, 0, 100, 100);
            let next = header(2, 99, 101, 101); // wrong parent
            let next_full = make_header(0, 0x1d00ffff);
            let err = validate_header_link_and_pow(&prev, &next, &next_full).unwrap_err();
            assert!(matches!(err, HeaderChainError::ParentLinkageBroken { .. }), "expected ParentLinkageBroken, got {err:?}");
        }

        #[test]
        fn validate_link_and_pow_rejects_invalid_pow_after_valid_structure() {
            let prev = header(1, 0, 100, 100);
            let next = header(2, 1, 101, 101); // valid structure
            let next_full = make_header(0, 0x1d00ffff); // invalid PoW
            let err = validate_header_link_and_pow(&prev, &next, &next_full).unwrap_err();
            assert!(
                matches!(err, HeaderChainError::PowInvalid { .. } | HeaderChainError::PowInitFailed { .. }),
                "expected PoW error after valid structure, got {err:?}"
            );
        }
    }
}
