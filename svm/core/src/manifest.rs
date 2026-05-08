use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sophis_hashes::Hash;

use crate::capability::Capability;
use crate::upgrade_policy::UpgradePolicy;

/// Declared once at deploy time and stored with the Contract UTXO.
/// The runtime enforces required_capabilities — any undeclared host call traps.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct ContractManifest {
    /// Blake2b hash of the deployed WASM bytecode.
    pub script_hash: Hash,
    pub upgrade_policy: UpgradePolicy,
    pub required_capabilities: Vec<Capability>,
}

impl ContractManifest {
    pub fn new(script_hash: Hash, upgrade_policy: UpgradePolicy, required_capabilities: Vec<Capability>) -> Self {
        Self { script_hash, upgrade_policy, required_capabilities }
    }

    pub fn has_capability(&self, cap: &Capability) -> bool {
        self.required_capabilities.contains(cap)
    }
}
