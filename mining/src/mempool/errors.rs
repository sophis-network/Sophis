/// Re-export errors
pub use sophis_mining_errors::mempool::*;

use crate::model::topological_index::TopologicalIndexError;

impl From<TopologicalIndexError> for RuleError {
    fn from(_: TopologicalIndexError) -> Self {
        RuleError::RejectCycleInMempoolTransactions
    }
}

// Audit category-D coverage closure, item 4 (Session 16, 2026-05-16):
// errors.rs was 0% — the `From<TopologicalIndexError>` mapping (every
// variant collapses to `RejectCycleInMempoolTransactions`).
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topological_index_error_maps_to_cycle_rejection() {
        for e in [
            TopologicalIndexError::HasCycle,
            TopologicalIndexError::IndexHasNonUniqueKey,
            TopologicalIndexError::IndexHasWrongKeySet,
            TopologicalIndexError::IndexIsNotTopological,
        ] {
            assert!(matches!(RuleError::from(e), RuleError::RejectCycleInMempoolTransactions));
        }
    }
}
