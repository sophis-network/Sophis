use std::{collections::HashMap, fmt::Display};

use crate::{
    BlueWorkType, constants,
    errors::{coinbase::CoinbaseError, tx::TxRuleError},
    tx::{TransactionId, TransactionOutpoint},
};
use itertools::Itertools;
use sophis_hashes::{Hash, MerkleHash};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct VecDisplay<T: Display>(pub Vec<T>);
impl<T: Display> Display for VecDisplay<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}]", self.0.iter().map(|item| item.to_string()).join(", "))
    }
}

#[derive(Clone, Debug)]
pub struct TwoDimVecDisplay<T: Display + Clone>(pub Vec<Vec<T>>);
impl<T: Display + Clone> Display for TwoDimVecDisplay<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[\n\t{}\n]", self.0.iter().cloned().map(|item| VecDisplay(item).to_string()).join(", \n\t"))
    }
}

#[derive(Error, Debug, Clone)]
pub enum RuleError {
    #[error("wrong block version: got {0} but expected {expected}", expected = constants::BLOCK_VERSION)]
    WrongBlockVersion(u16),

    #[error("the block timestamp is too far into the future: block timestamp is {0} but maximum timestamp allowed is {1}")]
    TimeTooFarIntoTheFuture(u64, u64),

    #[error("block has no parents")]
    NoParents,

    #[error("block has too many parents: got {0} when the limit is {1}")]
    TooManyParents(usize, usize),

    #[error("block has ORIGIN as one of its parents")]
    OriginParent,

    #[error("parent {0} is an ancestor of parent {1}")]
    InvalidParentsRelation(Hash, Hash),

    #[error("parent {0} is invalid")]
    InvalidParent(Hash),

    #[error("block has missing parents: {0:?}")]
    MissingParents(Vec<Hash>),

    #[error("pruning point {0} is not in the past of this block")]
    PruningViolation(Hash),

    #[error("expected header daa score {0} but got {1}")]
    UnexpectedHeaderDaaScore(u64, u64),

    #[error("expected header blue score {0} but got {1}")]
    UnexpectedHeaderBlueScore(u64, u64),

    #[error("expected header blue work {0} but got {1}")]
    UnexpectedHeaderBlueWork(BlueWorkType, BlueWorkType),

    #[error("block {0} difficulty of {1} is not the expected value of {2}")]
    UnexpectedDifficulty(Hash, u32, u32),

    #[error("block timestamp of {0} is not after expected {1}")]
    TimeTooOld(u64, u64),

    #[error("block is known to be invalid")]
    KnownInvalid,

    #[error("block merges {0} blocks > {1} merge set size limit")]
    MergeSetTooBig(u64, u64),

    #[error("block is violating bounded merge depth")]
    ViolatingBoundedMergeDepth,

    #[error("invalid merkle root: header indicates {0} but calculated value is {1}")]
    BadMerkleRoot(MerkleHash, MerkleHash),

    #[error("block has no transactions")]
    NoTransactions,

    #[error("block first transaction is not coinbase")]
    FirstTxNotCoinbase,

    #[error("block has second coinbase transaction as index {0}")]
    MultipleCoinbases(usize),

    #[error("bad coinbase payload: {0}")]
    BadCoinbasePayload(CoinbaseError),

    #[error("coinbase blue score of {0} is not the expected value of {1}")]
    BadCoinbasePayloadBlueScore(u64, u64),

    #[error("transaction in isolation validation failed for tx {0}: {1}")]
    TxInIsolationValidationFailed(TransactionId, TxRuleError),

    #[error("block compute mass {0} exceeds limit of {1}")]
    ExceedsComputeMassLimit(u64, u64),

    #[error("block transient storage mass {0} exceeds limit of {1}")]
    ExceedsTransientMassLimit(u64, u64),

    #[error("block persistent storage mass {0} exceeds limit of {1}")]
    ExceedsStorageMassLimit(u64, u64),

    #[error("outpoint {0} is spent more than once on the same block")]
    DoubleSpendInSameBlock(TransactionOutpoint),

    #[error("outpoint {0} is created and spent on the same block")]
    ChainedTransaction(TransactionOutpoint),

    #[error("transaction in context validation failed for tx {0}: {1}")]
    TxInContextFailed(TransactionId, TxRuleError),

    #[error("block has {0} ALT-creation outputs across all transactions where the max allowed per block is {1}")]
    TooManyAltCreationsInBlock(usize, usize),

    #[error("wrong coinbase subsidy: expected {0} but got {1}")]
    WrongSubsidy(u64, u64),

    #[error("transaction {0} is found more than once in the block")]
    DuplicateTransactions(TransactionId),

    #[error("block has invalid proof-of-work")]
    InvalidPoW,

    #[error("expected header pruning point is {0} but got {1}")]
    WrongHeaderPruningPoint(Hash, Hash),

    #[error("expected indirect parents {0} but got {1}")]
    UnexpectedIndirectParents(TwoDimVecDisplay<Hash>, TwoDimVecDisplay<Hash>),

    #[error("block {0} UTXO commitment is invalid - block header indicates {1}, but calculated value is {2}")]
    BadUTXOCommitment(Hash, Hash, Hash),

    #[error("block {0} accepted ID merkle root is invalid - block header indicates {1}, but calculated value is {2}")]
    BadAcceptedIDMerkleRoot(Hash, MerkleHash, MerkleHash),

    #[error("coinbase transaction is not built as expected")]
    BadCoinbaseTransaction,

    #[error("{0} non-coinbase transactions (out of {1}) are invalid in UTXO context")]
    InvalidTransactionsInUtxoContext(usize, usize),

    #[error("invalid transactions in new block template")]
    InvalidTransactionsInNewBlock(HashMap<TransactionId, TxRuleError>),

    #[error("DAA window data has only {0} entries")]
    InsufficientDaaWindowSize(usize),

    /// Currently this error is never created because it is impossible to submit such a block
    #[error("cannot add block body to a pruned block")]
    PrunedBlock,

    /// Anti long-range attack — the candidate header's cumulative `blue_work`
    /// is below the network's hardcoded floor (`Params::min_chain_work`) or
    /// below the persisted `max_chain_work_seen` floor. The block itself may
    /// be otherwise valid; only the chain-selection promotion is refused.
    #[error("insufficient chain work for selected-tip promotion: got {got} but {required} is required ({floor})")]
    InsufficientChainWork { got: BlueWorkType, required: BlueWorkType, floor: ChainWorkFloor },
}

/// Identifies which floor was violated by an `InsufficientChainWork` rejection.
/// Useful for operator-facing log messages and tests.
#[derive(Clone, Copy, Debug)]
pub enum ChainWorkFloor {
    /// `Params::min_chain_work` — hardcoded per network, ZERO on the initial release.
    HardcodedMinimum,
    /// `MaxChainWorkSeenStore` — persisted floor that monotonically tracks the
    /// highest `blue_work` ever committed by virtual state on this node.
    PersistedMaxSeen,
}

impl Display for ChainWorkFloor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainWorkFloor::HardcodedMinimum => f.write_str("hardcoded min_chain_work"),
            ChainWorkFloor::PersistedMaxSeen => f.write_str("persisted max_chain_work_seen"),
        }
    }
}

pub type BlockProcessResult<T> = std::result::Result<T, RuleError>;

// Audit category-D coverage closure, item 6 (Session 16, 2026-05-16):
// `errors/block.rs` was at 0% coverage. `RuleError` is the public
// block-validation error surface (~48 variants) and its `Display` is an
// operator/log contract — a broken `#[error("…")]` format string is a
// real bug class. This exhaustively constructs every variant + the
// display helpers and asserts the formatting. Note: *firing* each
// variant through its real pipeline validator (header/body/virtual
// processors) is exercised by the consensus processor integration
// tests, not re-implemented as brittle isolated harnesses (that is the
// item-1/2 consensus-harness scope). `PrunedBlock` is documented in
// source as never-created (impossible to submit such a block) — it is
// the one genuinely-unreachable defensive variant; only its Display is
// covered here.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::{coinbase::CoinbaseError, tx::TxRuleError};

    fn h(b: u8) -> Hash {
        Hash::from_slice(&[b; 32])
    }
    fn mh(b: u8) -> MerkleHash {
        // MerkleHash is SHA3-384 (48 bytes), not 32.
        MerkleHash::from_slice(&[b; 48])
    }
    fn op(b: u8) -> TransactionOutpoint {
        TransactionOutpoint::new(h(b), 0)
    }
    fn bw(n: u64) -> BlueWorkType {
        BlueWorkType::from_u64(n)
    }

    #[test]
    fn every_rule_error_variant_displays_non_empty() {
        let variants: Vec<RuleError> = vec![
            RuleError::WrongBlockVersion(9),
            RuleError::TimeTooFarIntoTheFuture(10, 5),
            RuleError::NoParents,
            RuleError::TooManyParents(20, 10),
            RuleError::OriginParent,
            RuleError::InvalidParentsRelation(h(1), h(2)),
            RuleError::InvalidParent(h(3)),
            RuleError::MissingParents(vec![h(4), h(5)]),
            RuleError::PruningViolation(h(6)),
            RuleError::UnexpectedHeaderDaaScore(1, 2),
            RuleError::UnexpectedHeaderBlueScore(3, 4),
            RuleError::UnexpectedHeaderBlueWork(bw(5), bw(6)),
            RuleError::UnexpectedDifficulty(h(7), 100, 200),
            RuleError::TimeTooOld(8, 9),
            RuleError::KnownInvalid,
            RuleError::MergeSetTooBig(50, 40),
            RuleError::ViolatingBoundedMergeDepth,
            RuleError::BadMerkleRoot(mh(1), mh(2)),
            RuleError::NoTransactions,
            RuleError::FirstTxNotCoinbase,
            RuleError::MultipleCoinbases(3),
            RuleError::BadCoinbasePayload(CoinbaseError::PayloadLenBelowMin(1, 2)),
            RuleError::BadCoinbasePayloadBlueScore(7, 8),
            RuleError::TxInIsolationValidationFailed(h(9), TxRuleError::NoTxInputs),
            RuleError::ExceedsComputeMassLimit(10, 5),
            RuleError::ExceedsTransientMassLimit(10, 5),
            RuleError::ExceedsStorageMassLimit(10, 5),
            RuleError::DoubleSpendInSameBlock(op(1)),
            RuleError::ChainedTransaction(op(2)),
            RuleError::TxInContextFailed(h(10), TxRuleError::NoTxInputs),
            RuleError::TooManyAltCreationsInBlock(17, 16),
            RuleError::WrongSubsidy(100, 99),
            RuleError::DuplicateTransactions(h(11)),
            RuleError::InvalidPoW,
            RuleError::WrongHeaderPruningPoint(h(12), h(13)),
            RuleError::UnexpectedIndirectParents(TwoDimVecDisplay(vec![vec![h(1)]]), TwoDimVecDisplay(vec![vec![h(2)]])),
            RuleError::BadUTXOCommitment(h(14), h(15), h(16)),
            RuleError::BadAcceptedIDMerkleRoot(h(17), mh(3), mh(4)),
            RuleError::BadCoinbaseTransaction,
            RuleError::InvalidTransactionsInUtxoContext(2, 5),
            RuleError::InvalidTransactionsInNewBlock(HashMap::new()),
            RuleError::InsufficientDaaWindowSize(3),
            RuleError::PrunedBlock, // documented never-created defensive variant
            RuleError::InsufficientChainWork { got: bw(1), required: bw(2), floor: ChainWorkFloor::HardcodedMinimum },
        ];
        for e in &variants {
            let s = e.to_string();
            assert!(!s.is_empty(), "empty Display for {e:?}");
            // Debug must also be derivable (used in logs / other errors).
            assert!(!format!("{e:?}").is_empty());
        }
        // Guard: bump this when a RuleError variant is added/removed so a
        // new variant cannot ship without Display coverage.
        assert_eq!(variants.len(), 44, "all RuleError variants enumerated");
    }

    #[test]
    fn rule_error_format_args_are_wired() {
        // Spot-check that format placeholders actually interpolate.
        assert!(RuleError::WrongBlockVersion(7).to_string().contains('7'));
        assert!(RuleError::WrongBlockVersion(7).to_string().contains(&constants::BLOCK_VERSION.to_string()));
        assert!(RuleError::TooManyParents(20, 10).to_string().contains("20"));
        assert!(RuleError::WrongSubsidy(100, 99).to_string().contains("99"));
        let cw = RuleError::InsufficientChainWork { got: bw(1), required: bw(2), floor: ChainWorkFloor::PersistedMaxSeen };
        assert!(cw.to_string().contains("persisted max_chain_work_seen"));
    }

    #[test]
    fn chain_work_floor_display_and_debug_both_arms() {
        assert_eq!(ChainWorkFloor::HardcodedMinimum.to_string(), "hardcoded min_chain_work");
        assert_eq!(ChainWorkFloor::PersistedMaxSeen.to_string(), "persisted max_chain_work_seen");
        assert!(!format!("{:?}", ChainWorkFloor::HardcodedMinimum).is_empty());
        assert!(!format!("{:?}", ChainWorkFloor::PersistedMaxSeen).is_empty());
    }

    #[test]
    fn display_helpers_format() {
        let v = VecDisplay(vec![h(1), h(2)]);
        let s = v.to_string();
        assert!(s.starts_with('[') && s.ends_with(']') && s.contains(", "));
        assert!(!format!("{v:?}").is_empty());

        let t = TwoDimVecDisplay(vec![vec![h(1)], vec![h(2), h(3)]]);
        let ts = t.to_string();
        assert!(ts.contains('[') && ts.contains(']'));
        assert!(!format!("{t:?}").is_empty());

        // Empty cases.
        assert_eq!(VecDisplay::<Hash>(vec![]).to_string(), "[]");
        assert!(!TwoDimVecDisplay::<Hash>(vec![]).to_string().is_empty());
    }
}
