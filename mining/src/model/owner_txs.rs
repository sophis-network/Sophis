use sophis_consensus_core::tx::{MutableTransaction, ScriptPublicKey, TransactionId};
use std::collections::{HashMap, HashSet};

use super::TransactionIdSet;

pub type ScriptPublicKeySet = HashSet<ScriptPublicKey>;

/// Transaction ids involved in either sending to or receiving from an
/// address or its [`ScriptPublicKey`] equivalent.
#[derive(Default)]
pub struct OwnerTransactions {
    pub sending_txs: TransactionIdSet,
    pub receiving_txs: TransactionIdSet,
}

impl OwnerTransactions {
    pub fn is_empty(&self) -> bool {
        self.sending_txs.is_empty() && self.receiving_txs.is_empty()
    }
}

/// Transactions grouped by owning addresses
#[derive(Default)]
pub struct GroupedOwnerTransactions {
    pub transactions: HashMap<TransactionId, MutableTransaction>,
    pub owners: HashMap<ScriptPublicKey, OwnerTransactions>,
}

// Audit category-D coverage closure, item 4 (Session 16, 2026-05-16):
// owner_txs.rs was 0% — the `is_empty` predicate + Default ctors.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_transactions_is_empty_semantics() {
        let mut o = OwnerTransactions::default();
        assert!(o.is_empty());
        o.sending_txs.insert(TransactionId::from_slice(&[1u8; 32]));
        assert!(!o.is_empty());
        let mut o2 = OwnerTransactions::default();
        o2.receiving_txs.insert(TransactionId::from_slice(&[2u8; 32]));
        assert!(!o2.is_empty());
    }

    #[test]
    fn grouped_owner_transactions_default_is_empty() {
        let g = GroupedOwnerTransactions::default();
        assert!(g.transactions.is_empty());
        assert!(g.owners.is_empty());
    }
}
