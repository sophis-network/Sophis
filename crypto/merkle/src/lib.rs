use sophis_hashes::{Hash, HasherBase, MerkleBranchHash, MerkleHash, ZERO_HASH, ZERO_MERKLE_HASH};

/// Computes the Merkle root over a set of transaction hashes.
///
/// Returns a `MerkleHash` (48 bytes, blake2b-384) — 2^128 quantum collision resistance.
/// All inputs are `Hash` (32 bytes, tx IDs); internal nodes and root are `MerkleHash`.
pub fn calc_merkle_root(hashes: impl ExactSizeIterator<Item = Hash>) -> MerkleHash {
    let leaves: Vec<Hash> = hashes.collect();
    match leaves.len() {
        0 => return ZERO_MERKLE_HASH,
        1 => return merkle_hash_from_tx(leaves[0], ZERO_HASH),
        _ => {}
    }

    let next_pot = leaves.len().next_power_of_two();

    // Level 0 → 1: Hash leaf pairs into MerkleHash nodes
    let mut nodes: Vec<Option<MerkleHash>> = (0..next_pot)
        .step_by(2)
        .map(|i| {
            if i >= leaves.len() {
                None
            } else {
                let right = if i + 1 < leaves.len() { leaves[i + 1] } else { ZERO_HASH };
                Some(merkle_hash_from_tx(leaves[i], right))
            }
        })
        .collect();

    // Level 1+ : MerkleHash pairs → MerkleHash parent
    while nodes.len() > 1 {
        nodes = nodes
            .chunks(2)
            .map(|pair| match pair[0] {
                None => None,
                Some(left) => {
                    let right = pair.get(1).copied().flatten().unwrap_or(ZERO_MERKLE_HASH);
                    Some(merkle_hash_from_node(left, right))
                }
            })
            .collect();
    }

    nodes[0].unwrap_or(ZERO_MERKLE_HASH)
}

/// Hashes a pair of leaf-level hashes (Hash) into a MerkleHash node.
pub fn merkle_hash_from_tx(left: Hash, right: Hash) -> MerkleHash {
    let mut hasher = MerkleBranchHash::new();
    hasher.update(left).update(right);
    hasher.finalize()
}

/// Hashes a pair of internal MerkleHash nodes into a parent MerkleHash.
pub fn merkle_hash_from_node(left: MerkleHash, right: MerkleHash) -> MerkleHash {
    let mut hasher = MerkleBranchHash::new();
    hasher.update(left).update(right);
    hasher.finalize()
}

/// Alias for the common bottom-level case.
#[inline]
pub fn merkle_hash(left: Hash, right: Hash) -> MerkleHash {
    merkle_hash_from_tx(left, right)
}
