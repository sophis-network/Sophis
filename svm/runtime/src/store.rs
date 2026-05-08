use std::collections::HashMap;
use std::sync::RwLock;

use sophis_svm_core::{ContractId, ContractStore};

/// In-memory contract store for tests and devnet.
/// Production nodes use a RocksDB-backed implementation in sophisd.
pub struct InMemoryContractStore {
    map: RwLock<HashMap<ContractId, Vec<u8>>>,
}

impl InMemoryContractStore {
    pub fn new() -> Self {
        Self { map: RwLock::new(HashMap::new()) }
    }

    pub fn deploy(&self, id: ContractId, wasm: Vec<u8>) {
        self.map.write().expect("lock poisoned").insert(id, wasm);
    }
}

impl Default for InMemoryContractStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ContractStore for InMemoryContractStore {
    fn get_wasm(&self, id: &ContractId) -> Option<Vec<u8>> {
        self.map.read().expect("lock poisoned").get(id).cloned()
    }

    fn deploy_if_absent(&self, id: ContractId, wasm: Vec<u8>) {
        let mut map = self.map.write().expect("lock poisoned");
        map.entry(id).or_insert(wasm);
    }
}
