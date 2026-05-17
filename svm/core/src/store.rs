use crate::utxo::ContractId;

/// Contract bytecode registry.
/// Maps ContractId (blake2b-256 "ContractWasm" domain of WASM) → WASM bytes.
/// The full DB-backed implementation lives in sophisd; InMemoryContractStore
/// is used for tests and devnet.
pub trait ContractStore: Send + Sync + 'static {
    fn get_wasm(&self, id: &ContractId) -> Option<Vec<u8>>;
    fn contains(&self, id: &ContractId) -> bool {
        self.get_wasm(id).is_some()
    }
    /// Stores WASM only if not already present (idempotent — re-orgs may replay deploy txs).
    fn deploy_if_absent(&self, id: ContractId, wasm: Vec<u8>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sophis_hashes::Hash;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct TestStore(Mutex<HashMap<ContractId, Vec<u8>>>);

    impl ContractStore for TestStore {
        fn get_wasm(&self, id: &ContractId) -> Option<Vec<u8>> {
            self.0.lock().unwrap().get(id).cloned()
        }
        fn deploy_if_absent(&self, id: ContractId, wasm: Vec<u8>) {
            self.0.lock().unwrap().entry(id).or_insert(wasm);
        }
    }

    #[test]
    fn default_contains_reflects_get_wasm() {
        let s = TestStore::default();
        let id = Hash::from_bytes([7u8; 32]);
        assert!(!s.contains(&id));
        s.deploy_if_absent(id, vec![1, 2, 3]);
        assert!(s.contains(&id));
        assert_eq!(s.get_wasm(&id), Some(vec![1, 2, 3]));
    }

    #[test]
    fn deploy_if_absent_is_idempotent() {
        let s = TestStore::default();
        let id = Hash::from_bytes([9u8; 32]);
        s.deploy_if_absent(id, vec![1]);
        s.deploy_if_absent(id, vec![2, 2]);
        assert_eq!(s.get_wasm(&id), Some(vec![1]));
    }
}
