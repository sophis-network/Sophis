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
}

/// Validates that `next` legitimately extends `prev` in the selected
/// chain. Pure function; PoW verification is the caller's
/// responsibility (delegate to `sophis-pow`).
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
}
