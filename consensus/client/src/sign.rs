//!
//! Utilities for signing transactions.
//!

use crate::transaction::Transaction;

/// A wrapper enum that represents the transaction signed state. A transaction
/// contained by this enum can be either fully signed or partially signed.
pub enum Signed<'a> {
    Fully(&'a Transaction),
    Partially(&'a Transaction),
}

impl<'a> Signed<'a> {
    /// Returns the transaction regardless of whether it is fully or partially signed
    pub fn unwrap(self) -> &'a Transaction {
        match self {
            Signed::Fully(tx) => tx,
            Signed::Partially(tx) => tx,
        }
    }
}
