use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::token::{TokenId, hash_mint_policy};

/// Payload embedded in a Minting Policy deploy transaction (`tx.payload`).
/// The tx must be native subnetwork, have a non-empty payload, and have at least
/// one Token UTXO output (version=2) whose `token_id == token_id()`.
///
/// Structurally identical to ContractDeployPayload but domain-separated via
/// `hash_mint_policy` — the same WASM deployed as a contract vs a minting policy
/// produces different IDs and occupies different slots in the ContractStore.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct MintingPolicyPayload {
    pub wasm: Vec<u8>,
}

impl MintingPolicyPayload {
    pub fn token_id(&self) -> TokenId {
        hash_mint_policy(&self.wasm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_id_is_deterministic_and_matches_hash_mint_policy() {
        let p = MintingPolicyPayload { wasm: vec![0x00, 0x61, 0x73, 0x6d, 1, 2, 3] };
        assert_eq!(p.token_id(), p.token_id());
        assert_eq!(p.token_id(), hash_mint_policy(&p.wasm));
    }

    #[test]
    fn token_id_differs_for_different_wasm() {
        let a = MintingPolicyPayload { wasm: vec![1, 2, 3] };
        let b = MintingPolicyPayload { wasm: vec![1, 2, 4] };
        assert_ne!(a.token_id(), b.token_id());
    }

    #[test]
    fn borsh_roundtrip() {
        let p = MintingPolicyPayload { wasm: vec![9, 9, 9, 9] };
        let bytes = borsh::to_vec(&p).unwrap();
        let back: MintingPolicyPayload = borsh::from_slice(&bytes).unwrap();
        assert_eq!(back.wasm, p.wasm);
        assert_eq!(back.token_id(), p.token_id());
    }
}
