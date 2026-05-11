//! J5 — Wallet scan.
//!
//! Given a wallet's SPK set and a sequence of (block_hash,
//! filter_bytes) pairs (typically the result of stepping forward
//! through the filter chain and fetching each filter), returns the
//! blocks that may contain a relevant transaction.
//!
//! False positives are bounded by `1/M ≈ 1.9 × 10⁻⁶` per
//! (block, SPK) pair (K2 design §7). For wallets with N SPKs over B
//! blocks, expected spurious matches ≈ N · B / M.

use sophis_compact_filters::filter_matches;
use sophis_hashes::Hash;

/// One scan result: a block whose filter matched at least one
/// wallet SPK. The `matched_spk_index` indicates which SPK in the
/// wallet's set triggered the match (the first one found; finding
/// any single match is enough to require a full-block fetch, since
/// the wallet has to scan all txs in the block once it fetches it
/// anyway).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanResult {
    pub block_hash: Hash,
    pub matched_spk_index: usize,
}

/// Stateless scanner. Wallets typically construct one of these per
/// scan range and call `scan_block` for each (block, filter) pair as
/// they fetch them.
pub struct WalletScan<'a> {
    spks: &'a [&'a [u8]],
}

impl<'a> WalletScan<'a> {
    /// Constructs a scanner over the given SPK set. The references
    /// stay borrowed for the lifetime of the scanner; production
    /// wallets typically keep their SPK set in a long-lived
    /// `Vec<Vec<u8>>` and pass slice references.
    pub fn new(spks: &'a [&'a [u8]]) -> Self {
        Self { spks }
    }

    /// Returns `Some(ScanResult)` if any of the wallet's SPKs match
    /// in `filter_bytes`, `None` otherwise. Empty SPK sets always
    /// return `None`. Returns the FIRST match — finding more than
    /// one is unnecessary because the wallet has to fetch the
    /// full block on any positive match.
    pub fn scan_block(&self, block_hash: Hash, filter_bytes: &[u8]) -> Option<ScanResult> {
        for (idx, spk) in self.spks.iter().enumerate() {
            // `filter_matches` returns Ok(false) on absence (authoritative)
            // and Ok(true) on presence (with K2's 1/M false-positive rate).
            // Err is a malformed filter — treat as miss for the scan
            // helper (caller can re-fetch / blame the node).
            if filter_matches(filter_bytes, &block_hash, spk).unwrap_or(false) {
                return Some(ScanResult { block_hash, matched_spk_index: idx });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sophis_compact_filters::build_basic_filter;

    fn h(byte: u8) -> Hash {
        Hash::from_slice(&[byte; 32])
    }

    #[test]
    fn scan_finds_known_spk() {
        let block = h(1);
        let spk_a: &[u8] = b"address-a";
        let spk_b: &[u8] = b"address-b";
        let filter = build_basic_filter(&block, &[spk_a]);

        let wallet_spks = [spk_a, spk_b];
        let spk_refs: Vec<&[u8]> = wallet_spks.to_vec();
        let scanner = WalletScan::new(&spk_refs);
        let result = scanner.scan_block(block, &filter).expect("must match");
        assert_eq!(result.matched_spk_index, 0);
        assert_eq!(result.block_hash, block);
    }

    #[test]
    fn scan_misses_unknown_spk() {
        let block = h(2);
        let spk_in_block: &[u8] = b"in-block";
        let spk_wallet: &[u8] = b"not-in-block";
        let filter = build_basic_filter(&block, &[spk_in_block]);

        let spk_refs: Vec<&[u8]> = vec![spk_wallet];
        let scanner = WalletScan::new(&spk_refs);
        // 1/M false-positive rate — almost always None
        assert!(scanner.scan_block(block, &filter).is_none());
    }

    #[test]
    fn empty_spk_set_returns_none() {
        let block = h(3);
        let filter = build_basic_filter(&block, &[b"x" as &[u8]]);
        let spk_refs: Vec<&[u8]> = Vec::new();
        let scanner = WalletScan::new(&spk_refs);
        assert!(scanner.scan_block(block, &filter).is_none());
    }

    #[test]
    fn empty_filter_misses_everything() {
        let block = h(4);
        let filter = build_basic_filter(&block, &[]);
        let spk_refs: Vec<&[u8]> = vec![b"a"];
        let scanner = WalletScan::new(&spk_refs);
        assert!(scanner.scan_block(block, &filter).is_none());
    }

    #[test]
    fn scan_returns_first_match_on_multiple_hits() {
        let block = h(5);
        let spk_a: &[u8] = b"alpha";
        let spk_b: &[u8] = b"beta";
        let spk_c: &[u8] = b"gamma";
        // Filter has both alpha and gamma
        let filter = build_basic_filter(&block, &[spk_a, spk_c]);

        let spk_refs: Vec<&[u8]> = vec![spk_b, spk_a, spk_c]; // wallet looks for b, a, c
        let scanner = WalletScan::new(&spk_refs);
        let result = scanner.scan_block(block, &filter).expect("must match");
        // First match in wallet order: a is at index 1
        assert_eq!(result.matched_spk_index, 1);
    }

    #[test]
    fn malformed_filter_treated_as_miss() {
        let block = h(6);
        let bad_filter = vec![0xFFu8, 0xFF, 0xFF]; // garbage
        let spk_refs: Vec<&[u8]> = vec![b"x"];
        let scanner = WalletScan::new(&spk_refs);
        // Do not panic; treat as miss.
        assert!(scanner.scan_block(block, &bad_filter).is_none());
    }
}
