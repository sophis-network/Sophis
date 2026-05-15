use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sophis_hashes::Hash;

use crate::capability::Capability;
use crate::upgrade_policy::UpgradePolicy;

/// Declared once at deploy time and stored with the Contract UTXO.
///
/// Enforcement of `required_capabilities` is two-layered (Audit/F-10):
///   - Consensus rejects deploys whose WASM imports map to a Capability
///     not in this list — see
///     `svm/runtime/src/validator.rs::validate_imports_against_manifest`.
///   - Every runtime host fn call site re-checks `check_capability` as
///     defense-in-depth, returning a typed error code (not a trap) when
///     the capability is missing.
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
