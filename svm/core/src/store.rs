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
