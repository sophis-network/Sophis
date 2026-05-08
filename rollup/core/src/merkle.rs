// Binary Merkle tree over the L2 UTXO set.
// Uses SHA3-384 — consistent with L1 MerkleHash ([u8;48], blake2b-384 on L1,
// but we use SHA3-384 here to avoid pulling in blake2b for the guest zkVM).
// Leaves are domain-separated to prevent second-preimage attacks.

use crate::types::{L2Utxo, StateRoot};
use sha3::{Digest, Sha3_384};

const LEAF_DOMAIN: &[u8] = b"sophis-l2-leaf:";
const NODE_DOMAIN: &[u8] = b"sophis-l2-node:";

fn hash_leaf(utxo: &L2Utxo) -> [u8; 48] {
    let bytes = borsh::to_vec(utxo).unwrap_or_default();
    let mut h = Sha3_384::new();
    h.update(LEAF_DOMAIN);
    h.update(&bytes);
    h.finalize().into()
}

fn hash_pair(left: &[u8; 48], right: &[u8; 48]) -> [u8; 48] {
    let mut h = Sha3_384::new();
    h.update(NODE_DOMAIN);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Compute the Merkle root of the given UTXO set.
/// UTXOs must be sorted by ID before calling — caller is responsible.
/// Empty set → zero root.
pub fn compute_state_root(utxos: &[L2Utxo]) -> StateRoot {
    if utxos.is_empty() {
        return StateRoot::default();
    }

    let mut layer: Vec<[u8; 48]> = utxos.iter().map(hash_leaf).collect();

    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i < layer.len() {
            let left = &layer[i];
            let right = if i + 1 < layer.len() { &layer[i + 1] } else { left };
            next.push(hash_pair(left, right));
            i += 2;
        }
        layer = next;
    }

    StateRoot(layer[0])
}

/// Sort a mutable UTXO slice by ID for deterministic root computation.
pub fn sort_utxos(utxos: &mut [L2Utxo]) {
    utxos.sort_by(|a, b| a.id.cmp(&b.id));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{L2Address, L2UtxoId};

    fn make_utxo(txid_byte: u8, index: u32, amount: u64) -> L2Utxo {
        let mut txid = [0u8; 32];
        txid[0] = txid_byte;
        L2Utxo { id: L2UtxoId { txid, index }, address: L2Address([42u8; 48]), amount }
    }

    #[test]
    fn empty_set_is_zero_root() {
        assert_eq!(compute_state_root(&[]), StateRoot::default());
    }

    #[test]
    fn single_utxo_root_is_leaf_hash() {
        let u = make_utxo(1, 0, 1_000_000);
        let root = compute_state_root(std::slice::from_ref(&u));
        // root must equal hash_leaf of the single utxo (odd leaf → hashed with itself)
        let leaf = hash_leaf(&u);
        // With 1 element, layer=[leaf], len==1, we stop → root=leaf
        assert_eq!(root.0, leaf);
    }

    #[test]
    fn two_utxo_root_is_pair_hash() {
        let u1 = make_utxo(1, 0, 1_000);
        let u2 = make_utxo(2, 0, 2_000);
        let root = compute_state_root(&[u1.clone(), u2.clone()]);
        let expected = hash_pair(&hash_leaf(&u1), &hash_leaf(&u2));
        assert_eq!(root.0, expected);
    }

    #[test]
    fn root_changes_when_utxo_set_changes() {
        let mut utxos = vec![make_utxo(1, 0, 100), make_utxo(2, 0, 200)];
        let root_before = compute_state_root(&utxos);
        utxos[0].amount = 999;
        let root_after = compute_state_root(&utxos);
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn sort_utxos_is_deterministic() {
        let mut a = vec![make_utxo(3, 0, 1), make_utxo(1, 0, 2), make_utxo(2, 0, 3)];
        let mut b = vec![make_utxo(1, 0, 2), make_utxo(2, 0, 3), make_utxo(3, 0, 1)];
        sort_utxos(&mut a);
        sort_utxos(&mut b);
        assert_eq!(compute_state_root(&a), compute_state_root(&b),);
    }
}
