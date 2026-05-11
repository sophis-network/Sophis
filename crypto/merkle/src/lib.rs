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

// ---------------------------------------------------------------------------
// J5 — Merkle proof construction + verification
// ---------------------------------------------------------------------------

/// J5 — Per-transaction Merkle proof against a block's `hash_merkle_root`.
///
/// Allows a light client to prove "tx_id is at `position` within
/// block.transactions" without downloading the full block. Verified
/// against the block header's `hash_merkle_root` (a `MerkleHash`)
/// which the client trusts via the header chain it already verified.
///
/// Wire layout: see `docs/J5_LIGHT_CLIENT_DESIGN.md` §4.1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxMerkleProof {
    /// The transaction this proof is for.
    pub tx_id: Hash,
    /// The block this proof anchors to.
    pub block_hash: Hash,
    /// The leaf-level sibling. `ZERO_HASH` if `tx_id` was the odd-out
    /// leaf at the bottom level (paired with implicit zero per
    /// `calc_merkle_root` line 24).
    pub leaf_sibling: Hash,
    /// MerkleHash siblings going up the tree, leaf-direction first
    /// (i.e. the level-1 sibling first, root-direction last). The
    /// length equals `ceil(log2(num_txs)) - 1`.
    pub node_siblings: Vec<MerkleHash>,
    /// Position of `tx_id` within `block.transactions`. Bit 0 is the
    /// leaf-level orientation (`0` = `tx_id` is the LEFT input to the
    /// level-1 hash; `1` = `tx_id` is the RIGHT input). Bits `1..n`
    /// are the internal-level orientations.
    pub position: u32,
}

/// Builds the Merkle proof for the transaction at `position` within
/// `tx_ids`. Returns `None` if `position >= tx_ids.len()` or if
/// `tx_ids` is empty.
///
/// Cost: rebuilds the Merkle tree, retaining only the siblings on the
/// path from leaf to root. O(n) hashes for n transactions.
pub fn build_merkle_proof(tx_ids: &[Hash], position: u32, block_hash: Hash) -> Option<TxMerkleProof> {
    let n = tx_ids.len();
    if n == 0 || (position as usize) >= n {
        return None;
    }
    let pos = position as usize;
    let tx_id = tx_ids[pos];

    // Special case: single-tx block. `calc_merkle_root` pairs with
    // ZERO_HASH and computes one level-1 hash; no internal levels.
    if n == 1 {
        return Some(TxMerkleProof { tx_id, block_hash, leaf_sibling: ZERO_HASH, node_siblings: Vec::new(), position });
    }

    // Compute leaf sibling.
    let leaf_sibling = if pos.is_multiple_of(2) {
        if pos + 1 < n { tx_ids[pos + 1] } else { ZERO_HASH }
    } else {
        tx_ids[pos - 1]
    };

    // Build the level-1 nodes (mirrors `calc_merkle_root` lines 17-28).
    let next_pot = n.next_power_of_two();
    let mut nodes: Vec<Option<MerkleHash>> = (0..next_pot)
        .step_by(2)
        .map(|i| {
            if i >= n {
                None
            } else {
                let right = if i + 1 < n { tx_ids[i + 1] } else { ZERO_HASH };
                Some(merkle_hash_from_tx(tx_ids[i], right))
            }
        })
        .collect();

    // Track the index our tx is at, in the level-1 nodes.
    let mut current_idx = pos / 2;
    let mut node_siblings: Vec<MerkleHash> = Vec::new();

    // Walk up the tree. At each level, capture the sibling, then build
    // the next level. Stop when only the root remains.
    while nodes.len() > 1 {
        // Sibling at the current level.
        let sibling_idx = current_idx ^ 1;
        let sibling = nodes.get(sibling_idx).copied().flatten().unwrap_or(ZERO_MERKLE_HASH);
        node_siblings.push(sibling);

        // Build the next level (mirrors `calc_merkle_root` lines 31-41).
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
        current_idx /= 2;
    }

    Some(TxMerkleProof { tx_id, block_hash, leaf_sibling, node_siblings, position })
}

/// Verifies a `TxMerkleProof` against an expected `hash_merkle_root`.
/// Returns `true` iff the proof is well-formed AND the recomputed
/// root equals `expected_root`. Pure function; no chain access.
pub fn verify_merkle_proof(proof: &TxMerkleProof, expected_root: &MerkleHash) -> bool {
    let pos = proof.position as usize;
    // Compute the level-1 node from tx_id + leaf_sibling, oriented
    // by position bit 0.
    let mut acc: MerkleHash = if pos & 1 == 0 {
        merkle_hash_from_tx(proof.tx_id, proof.leaf_sibling)
    } else {
        merkle_hash_from_tx(proof.leaf_sibling, proof.tx_id)
    };
    // Walk up using node_siblings.
    let mut idx = pos >> 1;
    for sibling in &proof.node_siblings {
        acc = if idx & 1 == 0 {
            merkle_hash_from_node(acc, *sibling)
        } else {
            merkle_hash_from_node(*sibling, acc)
        };
        idx >>= 1;
    }
    acc == *expected_root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> Hash {
        Hash::from_slice(&[byte; 32])
    }

    #[test]
    fn proof_round_trips_two_txs() {
        let txs = vec![h(1), h(2)];
        let root = calc_merkle_root(txs.iter().copied());
        let block = h(0xAA);

        let p0 = build_merkle_proof(&txs, 0, block).unwrap();
        assert!(verify_merkle_proof(&p0, &root));

        let p1 = build_merkle_proof(&txs, 1, block).unwrap();
        assert!(verify_merkle_proof(&p1, &root));
    }

    #[test]
    fn proof_round_trips_single_tx() {
        let txs = vec![h(7)];
        let root = calc_merkle_root(txs.iter().copied());
        let p = build_merkle_proof(&txs, 0, h(0xBB)).unwrap();
        assert!(verify_merkle_proof(&p, &root));
        assert_eq!(p.leaf_sibling, ZERO_HASH);
        assert!(p.node_siblings.is_empty());
    }

    #[test]
    fn proof_round_trips_4_txs_each_position() {
        let txs: Vec<Hash> = (1..=4u8).map(h).collect();
        let root = calc_merkle_root(txs.iter().copied());
        for pos in 0..4u32 {
            let p = build_merkle_proof(&txs, pos, h(0)).unwrap();
            assert!(verify_merkle_proof(&p, &root), "verify failed at pos {pos}");
        }
    }

    #[test]
    fn proof_round_trips_odd_count_5_txs() {
        // Tests the odd-leaf padding (last leaf paired with ZERO_HASH).
        let txs: Vec<Hash> = (1..=5u8).map(h).collect();
        let root = calc_merkle_root(txs.iter().copied());
        for pos in 0..5u32 {
            let p = build_merkle_proof(&txs, pos, h(0)).unwrap();
            assert!(verify_merkle_proof(&p, &root), "verify failed at pos {pos}");
        }
    }

    #[test]
    fn proof_round_trips_seven_txs_each_position() {
        // Non-power-of-two; tests both leaf-level and internal-level padding.
        let txs: Vec<Hash> = (1..=7u8).map(h).collect();
        let root = calc_merkle_root(txs.iter().copied());
        for pos in 0..7u32 {
            let p = build_merkle_proof(&txs, pos, h(0)).unwrap();
            assert!(verify_merkle_proof(&p, &root), "verify failed at pos {pos}");
        }
    }

    #[test]
    fn proof_rejects_wrong_root() {
        let txs = vec![h(1), h(2), h(3)];
        let bad_root = MerkleHash::from_slice(&[0xFFu8; 48]);
        let p = build_merkle_proof(&txs, 0, h(0)).unwrap();
        assert!(!verify_merkle_proof(&p, &bad_root));
    }

    #[test]
    fn proof_rejects_wrong_tx_id() {
        let txs = vec![h(1), h(2), h(3)];
        let root = calc_merkle_root(txs.iter().copied());
        let mut p = build_merkle_proof(&txs, 0, h(0)).unwrap();
        p.tx_id = h(99); // tamper
        assert!(!verify_merkle_proof(&p, &root));
    }

    #[test]
    fn proof_rejects_wrong_position() {
        let txs = vec![h(1), h(2), h(3), h(4)];
        let root = calc_merkle_root(txs.iter().copied());
        let mut p = build_merkle_proof(&txs, 0, h(0)).unwrap();
        p.position = 1; // claim wrong position
        assert!(!verify_merkle_proof(&p, &root));
    }

    #[test]
    fn build_returns_none_for_out_of_range() {
        let txs = vec![h(1), h(2)];
        assert!(build_merkle_proof(&txs, 5, h(0)).is_none());
    }

    #[test]
    fn build_returns_none_for_empty_block() {
        assert!(build_merkle_proof(&[], 0, h(0)).is_none());
    }
}
