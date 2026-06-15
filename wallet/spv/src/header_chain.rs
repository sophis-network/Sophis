//! J5 — Header chain validation.
//!
//! Light-client-side validation of the cheap parent-link invariants
//! between consecutive headers in the GHOSTDAG selected chain.
//! PoW verification is delegated to the consumer (typically via
//! `sophis-pow`); this module focuses on the structural checks the
//! wallet needs to walk the chain forward.

use serde::{Deserialize, Serialize};
use sophis_hashes::Hash;
use sophis_math::Uint192;
use thiserror::Error;

/// Minimum header info a light client needs to walk the chain.
/// Subset of the full `Header`; populated from `getHeaders` RPC
/// responses.
///
/// `timestamp` (ms since Unix epoch) and `bits` (compact difficulty
/// target) are both required for independent DAA target computation
/// (SPV-01 fix). Without them the SPV client would have to trust the
/// server-supplied difficulty, which is an attacker-controlled field.
///
/// `blue_work` is the accumulated proof-of-work (SPV-02 fix). It is
/// required for correct chain selection: the honest chain is the one
/// with the highest blue_work, not simply the longest selected chain.
/// Without it an attacker can present a longer-but-weaker chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinHeader {
    pub hash: Hash,
    pub selected_parent_hash: Hash,
    pub blue_score: u64,
    pub daa_score: u64,
    /// Accumulated proof-of-work (192-bit big-integer).
    /// Required for correct chain selection (heaviest chain, not
    /// longest).
    pub blue_work: Uint192,
    /// Block timestamp in milliseconds since Unix epoch.
    /// Required for DAA target recomputation.
    pub timestamp: u64,
    /// Compact difficulty target (same encoding as Bitcoin `nBits`).
    /// Required for DAA target recomputation.
    pub bits: u32,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HeaderChainError {
    /// `next.selected_parent_hash != prev.hash`.
    #[error("parent linkage broken: prev={prev:?}, next.selected_parent={next_parent:?}")]
    ParentLinkageBroken { prev: Hash, next_parent: Hash },

    /// `next.blue_score <= prev.blue_score`.
    #[error("blue_score did not increase: prev={prev}, next={next}")]
    BlueScoreNonIncreasing { prev: u64, next: u64 },

    /// `next.daa_score < prev.daa_score`. Strictly less; equality is
    /// allowed because DAA score can be the same for blocks separated
    /// only by GHOSTDAG mergeset moves (rare but legal).
    #[error("daa_score went backwards: prev={prev}, next={next}")]
    DaaScoreWentBackwards { prev: u64, next: u64 },

    /// RandomX cache / dataset allocation failed (transient resource error).
    /// The caller should retry or fall back to trusting the peer.
    #[error("PoW state init failed: {msg}")]
    PowInitFailed { msg: String },

    /// The header's nonce does not satisfy its declared difficulty target.
    #[error("invalid PoW for block {hash:?}")]
    PowInvalid { hash: Hash },

    /// SPV-02 — `next.blue_work <= prev.blue_work`.  The selected chain
    /// must accumulate strictly increasing proof-of-work.  A server that
    /// omits or lies about `blue_work` cannot present the heaviest chain.
    #[error("blue_work did not increase: prev={prev}, next={next}")]
    BlueWorkNonIncreasing { prev: Uint192, next: Uint192 },

    /// SPV-01 — the `bits` field in the full header does not match the
    /// DAA-computed expected target.  A server that lies about difficulty
    /// can be detected here before expensive RandomX verification.
    #[error("bits mismatch for block {hash:?}: header declares {declared:#010x}, DAA expects {expected:#010x}")]
    BitsMismatch { hash: Hash, declared: u32, expected: u32 },

    /// SPV-03 — the `MinHeader` and the full `Header` represent different
    /// blocks (hash mismatch). The validator can only bind PoW to the
    /// correct block when both refer to the same block.
    #[error("MinHeader hash {min:?} != full Header hash {full:?}")]
    HeaderHashMismatch { min: Hash, full: Hash },
}

/// Validates that `next` legitimately extends `prev` in the selected chain.
///
/// Pure structural check (parent linkage, blue_score, daa_score, blue_work).
/// For full security use [`validate_header_link_and_pow`] which also
/// verifies the RandomX proof-of-work.
///
/// Checks:
/// * `next.selected_parent_hash == prev.hash`
/// * `next.blue_score > prev.blue_score`
/// * `next.daa_score >= prev.daa_score`
/// * `next.blue_work > prev.blue_work` (SPV-02)
pub fn validate_header_link(prev: &MinHeader, next: &MinHeader) -> Result<(), HeaderChainError> {
    if next.selected_parent_hash != prev.hash {
        return Err(HeaderChainError::ParentLinkageBroken { prev: prev.hash, next_parent: next.selected_parent_hash });
    }
    if next.blue_score <= prev.blue_score {
        return Err(HeaderChainError::BlueScoreNonIncreasing { prev: prev.blue_score, next: next.blue_score });
    }
    if next.daa_score < prev.daa_score {
        return Err(HeaderChainError::DaaScoreWentBackwards { prev: prev.daa_score, next: next.daa_score });
    }
    // SPV-02: blue_work must strictly increase along the selected chain.
    // This is the "heaviest chain" invariant; without it a peer can present
    // a longer-but-weaker (lower accumulated PoW) chain.
    if next.blue_work <= prev.blue_work {
        return Err(HeaderChainError::BlueWorkNonIncreasing { prev: prev.blue_work, next: next.blue_work });
    }
    Ok(())
}

/// DAA parameters needed by the SPV client to independently compute the
/// expected difficulty target for each block.
///
/// These mirror the consensus-level parameters in `Params` and must be
/// initialised from the same constants the full node uses.  The Sophis
/// mainnet/testnet values are available via
/// [`SpvDaaParams::sophis_mainnet`] / [`SpvDaaParams::sophis_testnet`].
#[cfg(feature = "randomx")]
#[derive(Clone, Debug)]
pub struct SpvDaaParams {
    /// Compact-encoded difficulty target for the genesis block.
    /// Used when the window is too small for a stable calculation.
    pub genesis_bits: u32,
    /// Maximum allowed difficulty target (compact-encoded `2^255 - 1`
    /// for Sophis).  Computed targets above this are clamped to it.
    pub max_difficulty_target_bits: u32,
    /// Number of sampled blocks in the difficulty window
    /// (`DIFFICULTY_SAMPLED_WINDOW_SIZE` = 661 for Sophis).
    pub difficulty_window_size: usize,
    /// Minimum window size before DA kicks in
    /// (`MIN_DIFFICULTY_WINDOW_SIZE` = 150 for Sophis).
    pub min_difficulty_window_size: usize,
    /// Distance in block units between consecutive window samples
    /// (`difficulty_sample_rate` = 40 for 10 BPS Sophis).
    pub difficulty_sample_rate: u64,
    /// Target block interval in **milliseconds**
    /// (100 ms for 10 BPS Sophis).
    pub target_time_per_block: u64,
}

#[cfg(feature = "randomx")]
impl SpvDaaParams {
    // Sophis constants (same for mainnet and testnet):
    //   DIFFICULTY_WINDOW_DURATION     = 2641 s
    //   DIFFICULTY_WINDOW_SAMPLE_INTERVAL = 4 s
    //   DIFFICULTY_SAMPLED_WINDOW_SIZE = ceil(2641/4) = 661
    //   MIN_DIFFICULTY_WINDOW_SIZE     = 150
    //   BPS = 10  →  target_time_per_block = 100 ms
    //             →  difficulty_sample_rate = BPS * 4 = 40
    //   MAX_DIFFICULTY_TARGET = 2^255 - 1
    //     compact = 0x1f7fffff  (exponent 31, mantissa 0x7fffff → 2^(8*28)*0x7fffff)
    //     actual compact: size=32 bytes, mantissa=0x7fffff → 0x207fffff? Let me check.
    //
    //   Actually: for Sophis, genesis mainnet bits = 486722099 = 0x1d0e5073
    //   MAX target (2^255-1): largest bit position is 255, so size = ceil(255/8) = 32 bytes,
    //   the top 3 bytes are [0x7f, 0xff, 0xff], compact = 0x207fffff.
    //
    // Sophis MAINNET genesis bits = 486722099 (0x1d0e5073)
    // Sophis TESTNET genesis bits = 0x1e7fffff

    /// DAA parameters for the Sophis mainnet.
    pub fn sophis_mainnet() -> Self {
        Self {
            genesis_bits: 486_722_099, // 0x1d0e5073 — mainnet genesis
            max_difficulty_target_bits: 0x207f_ffff,
            difficulty_window_size: 661,
            min_difficulty_window_size: 150,
            difficulty_sample_rate: 40, // 10 BPS * 4 s interval
            target_time_per_block: 100, // 1000 ms / 10 BPS
        }
    }

    /// DAA parameters for the Sophis testnet.
    pub fn sophis_testnet() -> Self {
        Self {
            genesis_bits: 0x1e7f_ffff, // testnet genesis (low difficulty)
            max_difficulty_target_bits: 0x207f_ffff,
            difficulty_window_size: 661,
            min_difficulty_window_size: 150,
            difficulty_sample_rate: 40,
            target_time_per_block: 100,
        }
    }
}

/// Recompute the expected difficulty target from a sampled DAA window.
///
/// `window` must contain the `difficulty_window_size` most-recent
/// **sampled** headers (one every `difficulty_sample_rate` blocks in
/// the selected chain), ordered oldest-first.  If fewer than
/// `params.min_difficulty_window_size` samples are available (i.e.
/// near genesis), the function returns `params.genesis_bits`.
///
/// Algorithm mirrors `SampledDifficultyManager::calculate_difficulty_bits`
/// in the full node.
#[cfg(feature = "randomx")]
pub fn compute_expected_bits(window: &[MinHeader], params: &SpvDaaParams) -> u32 {
    use sophis_math::{Uint256, Uint320};

    if window.len() < params.min_difficulty_window_size {
        return params.genesis_bits;
    }

    // Locate the block with the minimum timestamp (tie-break by hash
    // byte order for determinism).  This block is excluded from the
    // target average, following the full-node algorithm.
    let min_ts_pos = window
        .iter()
        .enumerate()
        .min_by(|(_, a), (_, b)| a.timestamp.cmp(&b.timestamp).then_with(|| a.hash.as_bytes().cmp(&b.hash.as_bytes())))
        .map(|(i, _)| i)
        .expect("window non-empty after size check");
    let max_ts_pos = window
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| a.timestamp.cmp(&b.timestamp).then_with(|| a.hash.as_bytes().cmp(&b.hash.as_bytes())))
        .map(|(i, _)| i)
        .expect("window non-empty after size check");

    let min_ts = window[min_ts_pos].timestamp;
    let max_ts = window[max_ts_pos].timestamp;

    // Sum the difficulty targets of all blocks EXCEPT the min-ts block.
    let mut targets_sum = Uint320::ZERO;
    let mut count = 0u64;
    for (i, h) in window.iter().enumerate() {
        if i != min_ts_pos {
            targets_sum = targets_sum + Uint320::from(Uint256::from_compact_target_bits(h.bits));
            count += 1;
        }
    }

    if count == 0 {
        return params.genesis_bits;
    }

    let average_target = targets_sum / count;
    let measured_duration = (max_ts - min_ts).max(1);
    let expected_duration = params.target_time_per_block * params.difficulty_sample_rate * count;
    let new_target = average_target * measured_duration / expected_duration;

    let max_target = Uint320::from(Uint256::from_compact_target_bits(params.max_difficulty_target_bits));
    Uint256::try_from(new_target.min(max_target)).expect("clamped to max_difficulty_target < Uint256::MAX").compact_target_bits()
}

/// Verifies that a block header's nonce satisfies its declared RandomX
/// proof-of-work target.
///
/// Uses light mode (256 MB cache, shared per epoch via thread-local) so it
/// does not allocate a 2 GB dataset. Expect ~5–10 ms per header on modern
/// hardware — acceptable for cold-sync, budget ~50–100 s for 10k headers.
///
/// Returns [`HeaderChainError::PowInitFailed`] on transient RandomX
/// allocation failure; the caller should retry or fall back to trusting
/// the full node. Returns [`HeaderChainError::PowInvalid`] when the nonce
/// does not meet the target.
///
/// Does **not** independently verify the difficulty target — call
/// [`validate_header_link_and_pow`] (which supplies `expected_bits` from a
/// DAA window) to guard against SPV-01 attacks.
#[cfg(feature = "randomx")]
pub fn verify_pow(header: &sophis_consensus_core::header::Header) -> Result<(), HeaderChainError> {
    use sophis_pow::State;
    let state = State::try_new(header).map_err(|e| HeaderChainError::PowInitFailed { msg: e.to_string() })?;
    let (passed, _pow) = state.check_pow(header.nonce);
    if !passed {
        return Err(HeaderChainError::PowInvalid { hash: header.hash });
    }
    Ok(())
}

/// Validates structural chain linkage **and** RandomX proof-of-work for
/// `next_full` in a single call.
///
/// **SPV-03 fix**: asserts that `next.hash == next_full.hash` so that an
/// attacker cannot supply a valid-PoW block with a different hash from the
/// one being linked into the chain.
///
/// **SPV-01 fix**: `expected_bits` must be computed independently via
/// [`compute_expected_bits`] before calling this function. The function
/// checks that `next_full.bits == expected_bits` before invoking the
/// expensive RandomX verifier, short-circuiting the attack where a server
/// declares `bits = min_difficulty` to make chain fabrication cheap.
///
/// `prev` and `next` carry the structural fields (hash, selected_parent_hash,
/// blue_score, daa_score). `next_full` is the complete header used for PoW
/// verification; callers typically construct both from the same RPC response.
///
/// Structural checks run first (cheap), then bits check, then PoW (expensive).
#[cfg(feature = "randomx")]
pub fn validate_header_link_and_pow(
    prev: &MinHeader,
    next: &MinHeader,
    next_full: &sophis_consensus_core::header::Header,
    expected_bits: u32,
) -> Result<(), HeaderChainError> {
    // SPV-03: bind the full header to the MinHeader being linked.
    if next_full.hash != next.hash {
        return Err(HeaderChainError::HeaderHashMismatch { min: next.hash, full: next_full.hash });
    }
    validate_header_link(prev, next)?;
    // SPV-01: reject mismatched difficulty before spending RandomX cycles.
    if next_full.bits != expected_bits {
        return Err(HeaderChainError::BitsMismatch { hash: next_full.hash, declared: next_full.bits, expected: expected_bits });
    }
    verify_pow(next_full)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> Hash {
        Hash::from_slice(&[byte; 32])
    }

    fn header(hash: u8, parent: u8, blue: u64, daa: u64) -> MinHeader {
        MinHeader {
            hash: h(hash),
            selected_parent_hash: h(parent),
            blue_score: blue,
            daa_score: daa,
            blue_work: Uint192::from_u64(blue), // monotone proxy for testing
            timestamp: daa * 100,
            bits: 0x207fffff,
        }
    }

    #[test]
    fn valid_link_accepted() {
        let prev = header(1, 0, 100, 100);
        let next = header(2, 1, 101, 101);
        assert!(validate_header_link(&prev, &next).is_ok());
    }

    #[test]
    fn equal_daa_score_accepted() {
        // GHOSTDAG can produce consecutive selected-chain blocks with
        // the same DAA score (mergeset reorganisation).
        let prev = header(1, 0, 100, 100);
        let next = header(2, 1, 101, 100);
        assert!(validate_header_link(&prev, &next).is_ok());
    }

    #[test]
    fn parent_linkage_broken_rejected() {
        let prev = header(1, 0, 100, 100);
        let next = header(2, 99, 101, 101); // wrong parent
        let err = validate_header_link(&prev, &next).unwrap_err();
        assert!(matches!(err, HeaderChainError::ParentLinkageBroken { .. }));
    }

    #[test]
    fn non_increasing_blue_score_rejected() {
        let prev = header(1, 0, 100, 100);
        let next = header(2, 1, 100, 101); // blue_score equal
        let err = validate_header_link(&prev, &next).unwrap_err();
        assert!(matches!(err, HeaderChainError::BlueScoreNonIncreasing { .. }));
    }

    #[test]
    fn backward_daa_score_rejected() {
        let prev = header(1, 0, 100, 100);
        let next = header(2, 1, 101, 99);
        let err = validate_header_link(&prev, &next).unwrap_err();
        assert!(matches!(err, HeaderChainError::DaaScoreWentBackwards { .. }));
    }

    #[test]
    fn non_increasing_blue_work_rejected() {
        // SPV-02: blue_work must strictly increase. Construct next with
        // blue_work equal to prev's blue_work by overriding the field.
        let prev = header(1, 0, 100, 100);
        let mut next = header(2, 1, 101, 101);
        next.blue_work = prev.blue_work; // same accumulated PoW → weaker chain
        let err = validate_header_link(&prev, &next).unwrap_err();
        assert!(matches!(err, HeaderChainError::BlueWorkNonIncreasing { .. }));
    }

    // DAA and PoW verification tests require the `randomx` feature.
    #[cfg(feature = "randomx")]
    mod pow_tests {
        use super::*;
        use sophis_consensus_core::{header::Header, subnets::SUBNETWORK_ID_COINBASE};
        use sophis_hashes::Hash;

        fn zero_hash() -> Hash {
            Hash::from_slice(&[0u8; 32])
        }

        fn make_full_header(nonce: u64, bits: u32, hash_override: Option<Hash>) -> Header {
            let mut h = Header::new_finalized(
                sophis_consensus_core::constants::BLOCK_VERSION,
                vec![vec![zero_hash()]].try_into().unwrap(), // parents_by_level
                Default::default(),                          // hash_merkle_root
                Default::default(),                          // accepted_id_merkle_root
                zero_hash(),                                 // utxo_commitment
                1_000_000,                                   // timestamp (ms)
                bits,
                nonce,
                0,                  // daa_score (epoch 0)
                Default::default(), // blue_work
                1,                  // blue_score
                zero_hash(),        // pruning_point
            );
            if let Some(hash) = hash_override {
                h.hash = hash;
            }
            h
        }

        #[test]
        fn verify_pow_rejects_invalid_nonce() {
            // nonce=0 with max-difficulty bits is astronomically unlikely
            // to satisfy PoW — treated as "invalid" for the test.
            // bits=0x1d00ffff is Bitcoin-genesis difficulty (low); still
            // virtually certain to fail for nonce=0 with RandomX.
            let header = make_full_header(0, 0x1d00ffff, None);
            let result = verify_pow(&header);
            // Either PowInvalid (expected) or PowInitFailed (CI without
            // hugepages); both are non-Ok, which is the invariant.
            assert!(result.is_err(), "nonce=0 should not satisfy PoW");
        }

        #[test]
        fn validate_link_and_pow_structural_error_first() {
            // Broken parent linkage must be caught before PoW is checked.
            let prev = header(1, 0, 100, 100);
            let next_min = header(2, 99, 101, 101); // wrong parent
            let next_full = make_full_header(0, 0x1d00ffff, Some(next_min.hash));
            let err = validate_header_link_and_pow(&prev, &next_min, &next_full, 0x1d00ffff).unwrap_err();
            assert!(matches!(err, HeaderChainError::ParentLinkageBroken { .. }), "expected ParentLinkageBroken, got {err:?}");
        }

        #[test]
        fn validate_link_and_pow_rejects_hash_mismatch() {
            // SPV-03: next.hash != next_full.hash must be caught first.
            let prev = header(1, 0, 100, 100);
            let next_min = header(2, 1, 101, 101); // valid structure
            // next_full has a different hash (not overridden to match next_min.hash)
            let next_full = make_full_header(0, 0x1d00ffff, None);
            // next_full.hash != next_min.hash (they were constructed differently)
            let err = validate_header_link_and_pow(&prev, &next_min, &next_full, 0x1d00ffff).unwrap_err();
            assert!(matches!(err, HeaderChainError::HeaderHashMismatch { .. }), "expected HeaderHashMismatch, got {err:?}");
        }

        #[test]
        fn validate_link_and_pow_rejects_bits_mismatch() {
            // SPV-01: declared bits != expected bits must be caught before RandomX.
            let prev = header(1, 0, 100, 100);
            let next_min = header(2, 1, 101, 101); // valid structure
            let next_full = make_full_header(0, 0x1e7fffff, Some(next_min.hash)); // easy difficulty
            // expected_bits = hard difficulty; declared = easy → BitsMismatch
            let err = validate_header_link_and_pow(&prev, &next_min, &next_full, 0x1d00ffff).unwrap_err();
            assert!(matches!(err, HeaderChainError::BitsMismatch { .. }), "expected BitsMismatch, got {err:?}");
        }

        #[test]
        fn validate_link_and_pow_rejects_invalid_pow_after_valid_structure() {
            let prev = header(1, 0, 100, 100);
            let next_min = header(2, 1, 101, 101); // valid structure
            let next_full = make_full_header(0, 0x1d00ffff, Some(next_min.hash)); // invalid PoW
            let err = validate_header_link_and_pow(&prev, &next_min, &next_full, 0x1d00ffff).unwrap_err();
            assert!(
                matches!(err, HeaderChainError::PowInvalid { .. } | HeaderChainError::PowInitFailed { .. }),
                "expected PoW error after valid structure, got {err:?}"
            );
        }
    }

    // DAA unit tests do not need RandomX.
    #[cfg(feature = "randomx")]
    mod daa_tests {
        use super::*;

        fn make_window(size: usize, base_ts: u64, step_ms: u64, bits: u32) -> Vec<MinHeader> {
            (0..size)
                .map(|i| MinHeader {
                    hash: Hash::from_slice(&[i as u8; 32]),
                    selected_parent_hash: Hash::from_slice(&[0u8; 32]),
                    blue_score: i as u64,
                    daa_score: i as u64,
                    blue_work: Uint192::from_u64(i as u64),
                    timestamp: base_ts + i as u64 * step_ms,
                    bits,
                })
                .collect()
        }

        #[test]
        fn small_window_returns_genesis_bits() {
            let params = SpvDaaParams::sophis_testnet();
            let window = make_window(10, 0, 400, 0x207fffff); // well below min=150
            assert_eq!(compute_expected_bits(&window, &params), params.genesis_bits);
        }

        #[test]
        fn stable_difficulty_returns_same_bits() {
            let params = SpvDaaParams::sophis_testnet();
            // Window where block timing matches target exactly: no adjustment.
            // With target_time_per_block=100ms, sample_rate=40:
            //   expected_duration = 100 * 40 * (window_size - 1) ms (after removing min)
            //   measured_duration = same → ratio = 1 → new_target == average_target
            let step = params.target_time_per_block * params.difficulty_sample_rate; // 4000 ms
            let bits = 0x207fffff;
            let window = make_window(params.difficulty_window_size, 1_000_000, step, bits);
            let result = compute_expected_bits(&window, &params);
            // Result should equal the input bits (stable difficulty).
            // Tiny rounding in compact encoding is possible; accept ±1 bit position.
            assert_eq!(result, bits, "stable timing should preserve difficulty");
        }

        #[test]
        fn fast_blocks_increase_difficulty() {
            let params = SpvDaaParams::sophis_testnet();
            // Blocks arrive twice as fast as expected → difficulty doubles.
            let step = params.target_time_per_block * params.difficulty_sample_rate / 2;
            // max-target bits would clamp to itself; use a lower value.
            let bits2 = 0x1e7fffff;
            let window2 = make_window(params.difficulty_window_size, 1_000_000, step, bits2);
            let result2 = compute_expected_bits(&window2, &params);
            // Result target should be smaller (higher difficulty) than input.
            use sophis_math::Uint256;
            let t_in = Uint256::from_compact_target_bits(bits2);
            let t_out = Uint256::from_compact_target_bits(result2);
            assert!(t_out < t_in, "fast blocks should increase difficulty (lower target)");
        }
    }
}
