use std::sync::Arc;

use sophis_database::{
    prelude::{CachePolicy, CachedDbAccess, DB, DirectDbWriter},
    registry::DatabaseStorePrefixes,
};
use sophis_svm_core::{ContractId, ContractStore};

/// RocksDB-backed contract store used by production nodes (sophisd).
/// Contracts survive node restarts and chain pruning.
/// Uses a small LRU cache (256 entries) — WASM modules can be several hundred KB.
pub struct DbContractStore {
    db: Arc<DB>,
    access: CachedDbAccess<ContractId, Vec<u8>>,
}

impl DbContractStore {
    pub fn new(db: Arc<DB>) -> Self {
        let access = CachedDbAccess::new(db.clone(), CachePolicy::Count(256), DatabaseStorePrefixes::ContractWasm.into());
        Self { db, access }
    }
}

impl ContractStore for DbContractStore {
    fn get_wasm(&self, id: &ContractId) -> Option<Vec<u8>> {
        self.access.read(*id).ok()
    }

    fn contains(&self, id: &ContractId) -> bool {
        self.access.has(*id).unwrap_or(false)
    }

    fn deploy_if_absent(&self, id: ContractId, wasm: Vec<u8>) {
        if self.access.has(id).unwrap_or(false) {
            return;
        }
        let _ = self.access.write(DirectDbWriter::new(&self.db), id, wasm);
    }
}
