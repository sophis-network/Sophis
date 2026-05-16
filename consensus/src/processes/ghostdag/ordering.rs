use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use sophis_consensus_core::BlueWorkType;
use sophis_hashes::Hash;

use crate::model::{
    services::reachability::ReachabilityService,
    stores::{ghostdag::GhostdagStoreReader, headers::HeaderStoreReader, relations::RelationsStoreReader},
};

use super::protocol::GhostdagManager;

#[derive(Eq, Clone, Serialize, Deserialize)]
pub struct SortableBlock {
    pub hash: Hash,
    pub blue_work: BlueWorkType,
}

impl SortableBlock {
    pub fn new(hash: Hash, blue_work: BlueWorkType) -> Self {
        Self { hash, blue_work }
    }
}

impl PartialEq for SortableBlock {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl PartialOrd for SortableBlock {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SortableBlock {
    fn cmp(&self, other: &Self) -> Ordering {
        self.blue_work.cmp(&other.blue_work).then_with(|| self.hash.cmp(&other.hash))
    }
}

impl<T: GhostdagStoreReader, S: RelationsStoreReader, U: ReachabilityService, V: HeaderStoreReader> GhostdagManager<T, S, U, V> {
    pub fn sort_blocks(&self, blocks: impl IntoIterator<Item = Hash>) -> Vec<Hash> {
        let mut sorted_blocks: Vec<Hash> = blocks.into_iter().collect();
        sorted_blocks
            .sort_by_cached_key(|block| SortableBlock { hash: *block, blue_work: self.ghostdag_store.get_blue_work(*block).unwrap() });
        sorted_blocks
    }
}

// Audit category-D coverage closure, item 5 (Session 16, 2026-05-16):
// scope decision = GHOSTDAG **key invariants**, NOT 100% line-by-line of
// inherited Kaspa code. `SortableBlock` is the consensus-critical
// GHOSTDAG tie-break total order: `cmp` = blue_work, then hash. All
// nodes must agree on this ordering or the DAG forks (selected-parent /
// mergeset / pruning all depend on it — `apply.rs` uses it directly).
// The full `ghostdag()` algorithm (`protocol.rs`) + `mergeset.rs` need a
// DAG/store harness and are exercised by the consensus integration
// suite + devnet real-network GHOSTDAG (Phase 1 10/10) — intentionally
// not re-unit-tested line-by-line per the scope decision.
#[cfg(test)]
mod tests {
    use super::*;

    fn sb(hash: u8, bw: u64) -> SortableBlock {
        SortableBlock::new(Hash::from_slice(&[hash; 32]), BlueWorkType::from_u64(bw))
    }

    #[test]
    fn primary_order_is_blue_work() {
        // Higher blue_work is greater regardless of hash bytes.
        assert!(sb(0xff, 10) < sb(0x00, 20), "lower blue_work must be Less even with a larger hash");
        assert!(sb(0x00, 30) > sb(0xff, 5));
        assert_eq!(sb(1, 10).cmp(&sb(2, 20)), Ordering::Less);
    }

    #[test]
    fn tie_break_is_hash_when_blue_work_equal() {
        // Equal blue_work → deterministic order by hash (this is the
        // anti-fork tie-break: every node computes the same result).
        assert!(sb(1, 100) < sb(2, 100));
        assert!(sb(9, 100) > sb(8, 100));
        assert_eq!(sb(5, 100).cmp(&sb(5, 100)), Ordering::Equal);
    }

    #[test]
    fn partial_eq_is_hash_only_a_deliberate_asymmetry() {
        // INVARIANT (non-obvious, load-bearing): `eq` compares ONLY the
        // hash, while `cmp` compares blue_work first. Two SortableBlocks
        // with the same hash but different blue_work are `==` (used for
        // set/dedup semantics) yet `cmp` does NOT return Equal for them.
        // Pinning this so a well-meaning "fix" to eq is caught.
        let a = sb(7, 100);
        let b = sb(7, 999);
        assert!(a == b, "eq is hash-only by design"); // SortableBlock has no Debug derive
        assert_ne!(a.cmp(&b), Ordering::Equal, "cmp still orders by blue_work");
        assert_eq!(a.cmp(&b), Ordering::Less);
    }

    #[test]
    fn ordering_is_a_consistent_strict_weak_order() {
        // Antisymmetry on a small representative set.
        let xs = [sb(1, 10), sb(2, 10), sb(1, 20), sb(3, 5)];
        for i in &xs {
            for j in &xs {
                assert_eq!(i.cmp(j), j.cmp(i).reverse());
            }
        }
        // Transitivity: a < b < c ⟹ a < c.
        let (a, b, c) = (sb(3, 5), sb(1, 10), sb(1, 20));
        assert!(a < b && b < c && a < c);
        // Sorting yields blue_work-major, hash-minor order. (SortableBlock
        // has no Debug derive, so compare the resulting hash sequence.)
        let mut v = [sb(2, 20), sb(1, 20), sb(9, 5)];
        v.sort();
        let hashes: Vec<Hash> = v.iter().map(|x| x.hash).collect();
        assert_eq!(hashes, vec![Hash::from_slice(&[9; 32]), Hash::from_slice(&[1; 32]), Hash::from_slice(&[2; 32])]);
    }

    #[test]
    fn serde_roundtrip_preserves_ordering_key() {
        let s = sb(4, 42);
        let back: SortableBlock = bincode::deserialize(&bincode::serialize(&s).unwrap()).unwrap();
        assert_eq!(back.hash, s.hash);
        assert_eq!(back.blue_work, s.blue_work);
        assert_eq!(back.cmp(&s), Ordering::Equal);
    }
}
