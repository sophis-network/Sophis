// Audit guard (Session 1 finding F-1, 2026-05-14; condition refined Session 5
// after CI revealed a regression on the WASM32 build job):
//
// A *native* build of `sophis-pow` without the `randomx` feature compiles the
// legacy `Matrix::heavy_hash` + `PowHash` fallback path. That path predates
// Sophis's switch to RandomX (PoW = RandomX only, per CLAUDE.md invariants) and
// is consensus-incompatible with the mainnet/testnet protocol: a node built
// without RandomX would reject every block produced by the network.
//
// Exemptions to the guard:
//   1. `feature = "wasm32-sdk"` — explicit browser-miner build that
//      ships kHeavyHash for display + connects to a real miner via Stratum.
//   2. `target_arch = "wasm32"` — any wasm32 target (WASM SDK, web bindings,
//      compact-filters JS bridge). `randomx-rs` does not compile to wasm32
//      anyway; the workspace exposes WASM crates that pull `sophis-pow`
//      transitively for type definitions, not for hashing. Forcing the
//      `randomx` feature on a wasm32 build would break every downstream
//      wasm32 consumer.
//
// The CI WASM32 job (`cargo clippy -p sophis-wasm --target
// wasm32-unknown-unknown`) needs both exemptions: it does not enable the
// `wasm32-sdk` feature on sophis-pow, but it does build for wasm32, so the
// `target_arch` exemption is what unblocks it.
#[cfg(all(not(feature = "randomx"), not(feature = "wasm32-sdk"), not(target_arch = "wasm32"),))]
compile_error!(
    "sophis-pow requires either the 'randomx' feature (mainnet/testnet — default) \
     or the 'wasm32-sdk' feature (browser display) on native targets. Building \
     without RandomX on a native target compiles the legacy kHeavyHash fallback, \
     which is incompatible with the network's PoW consensus rules. Either remove \
     `--no-default-features` or add `--features randomx`. wasm32 targets are \
     exempt — randomx-rs does not build on wasm32."
);

// public for benchmarks
#[doc(hidden)]
pub mod matrix;
#[cfg(feature = "wasm32-sdk")]
pub mod wasm;
#[doc(hidden)]
pub mod xoshiro;

use std::cmp::max;
use std::sync::Arc;

use sophis_consensus_core::{BlockLevel, hashing, header::Header};
use sophis_hashes::Hash;
use sophis_math::Uint256;

#[cfg(feature = "randomx")]
use randomx_rs::{RandomXCache, RandomXDataset, RandomXFlag, RandomXVM};

#[cfg(feature = "randomx")]
use std::cell::RefCell;

/// RandomX epoch length in DAA score units.
/// The cache / dataset is rebuilt once per epoch; all block templates within the same
/// epoch share the same cache key, so the per-thread VM is reused across templates.
pub const EPOCH_LENGTH: u64 = 2048;

#[cfg(feature = "randomx")]
fn epoch_seed(daa_score: u64) -> [u8; 8] {
    (daa_score / EPOCH_LENGTH).to_le_bytes()
}

// ---------------------------------------------------------------------------
// Thread-local state
//   THREAD_EPOCH_CACHE — one RandomX cache per epoch per thread (light mode).
//   THREAD_VM          — one VM per epoch per thread (light or fast mode).
//     Keyed by epoch_num: the VM is reused for every block template in the
//     same epoch, because the underlying RandomX program only depends on the
//     cache/dataset key, not on the per-block pre_pow_hash.
// ---------------------------------------------------------------------------
#[cfg(feature = "randomx")]
thread_local! {
    static THREAD_EPOCH_CACHE: RefCell<Option<(u64, RandomXCache)>> = const { RefCell::new(None) };
    static THREAD_VM: RefCell<Option<(u64, RandomXVM)>> = const { RefCell::new(None) };
}

// ---------------------------------------------------------------------------
// SharedDataset — wraps RandomXDataset to be Send + Sync.
// Safety: RandomXDataset is read-only after RandomXDataset::new() returns;
// multiple threads may hash concurrently using distinct VMs that share it.
// ---------------------------------------------------------------------------
#[cfg(feature = "randomx")]
pub struct SharedDataset {
    pub epoch_num: u64,
    pub dataset: RandomXDataset,
}

#[cfg(feature = "randomx")]
unsafe impl Send for SharedDataset {}
#[cfg(feature = "randomx")]
unsafe impl Sync for SharedDataset {}

/// Builds a RandomX dataset for the epoch containing `daa_score`.
/// Allocates ~2 GB of RAM and takes 1–2 minutes on a modern CPU.
/// Returns a `SharedDataset` that can be wrapped in `Arc` and shared across threads.
#[cfg(feature = "randomx")]
pub fn build_epoch_dataset(daa_score: u64) -> SharedDataset {
    let epoch_num = daa_score / EPOCH_LENGTH;
    let seed = epoch_seed(daa_score);
    let cache_flags = RandomXFlag::get_recommended_flags();
    let cache = RandomXCache::new(cache_flags, &seed).expect("RandomX: failed to initialize cache for dataset build");
    let dataset = RandomXDataset::new(RandomXFlag::FLAG_DEFAULT, cache, 0).expect("RandomX: failed to initialize dataset");
    SharedDataset { epoch_num, dataset }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

pub struct State {
    pub(crate) target: Uint256,
    pub(crate) pre_pow_hash: Hash,
    pub(crate) timestamp: u64,
    pub(crate) epoch_num: u64,
    #[cfg(feature = "randomx")]
    pub(crate) flags: RandomXFlag,
    #[cfg(feature = "randomx")]
    pub(crate) cache: RandomXCache,
    #[cfg(feature = "randomx")]
    pub(crate) fast_dataset: Option<Arc<SharedDataset>>,
    #[cfg(not(feature = "randomx"))]
    pub(crate) matrix: crate::matrix::Matrix,
    #[cfg(not(feature = "randomx"))]
    pub(crate) hasher: sophis_hashes::PowHash,
}

// RandomXCache / SharedDataset are read-only after init — safe to share across threads.
#[cfg(feature = "randomx")]
unsafe impl Send for State {}
#[cfg(feature = "randomx")]
unsafe impl Sync for State {}

impl State {
    /// Light-mode constructor (256 MB cache).
    /// The cache is reused across templates in the same epoch via a thread-local.
    #[inline]
    pub fn new(header: &Header) -> Self {
        let target = Uint256::from_compact_target_bits(header.bits);
        let pre_pow_hash = hashing::header::hash_override_nonce_time(header, 0, 0);
        let epoch_num = header.daa_score / EPOCH_LENGTH;

        #[cfg(feature = "randomx")]
        {
            let flags = RandomXFlag::get_recommended_flags();

            // Reuse or rebuild the RandomX cache depending on the current epoch.
            let cache = THREAD_EPOCH_CACHE.with(|cell| {
                let mut slot = cell.borrow_mut();
                if let Some((cached_epoch, ref cached_cache)) = *slot
                    && cached_epoch == epoch_num
                {
                    return cached_cache.clone(); // cheap Arc clone
                }
                let seed = epoch_seed(header.daa_score);
                let new_cache = RandomXCache::new(flags, &seed).expect("RandomX: failed to initialize cache");
                *slot = Some((epoch_num, new_cache.clone()));
                new_cache
            });

            Self { target, pre_pow_hash, timestamp: header.timestamp, epoch_num, flags, cache, fast_dataset: None }
        }

        #[cfg(not(feature = "randomx"))]
        {
            use crate::matrix::Matrix;
            use sophis_hashes::PowHash;
            let hasher = PowHash::new(pre_pow_hash, header.timestamp);
            let matrix = Matrix::generate(pre_pow_hash);
            Self { target, pre_pow_hash, timestamp: header.timestamp, epoch_num, matrix, hasher }
        }
    }

    /// Fast-mode constructor (~2 GB dataset, ~10x hashrate).
    /// The caller is responsible for building and caching the `SharedDataset`
    /// (see `build_epoch_dataset`) and for rebuilding it on epoch boundaries.
    #[cfg(feature = "randomx")]
    #[inline]
    pub fn new_fast(header: &Header, dataset: Arc<SharedDataset>) -> Self {
        let target = Uint256::from_compact_target_bits(header.bits);
        let pre_pow_hash = hashing::header::hash_override_nonce_time(header, 0, 0);
        let epoch_num = header.daa_score / EPOCH_LENGTH;
        let flags = RandomXFlag::get_recommended_flags() | RandomXFlag::FLAG_FULL_MEM;
        // Reuse the thread-local cache (same RandomX cache build cost as light mode — once per epoch).
        // The cache is not used for hashing in fast mode (VM uses the dataset),
        // but THREAD_EPOCH_CACHE avoids rebuilding the RandomX cache on every template call.
        let cache_flags = RandomXFlag::get_recommended_flags();
        let cache = THREAD_EPOCH_CACHE.with(|cell| {
            let mut slot = cell.borrow_mut();
            if let Some((cached_epoch, ref cached_cache)) = *slot
                && cached_epoch == epoch_num
            {
                return cached_cache.clone();
            }
            let seed = epoch_seed(header.daa_score);
            let new_cache = RandomXCache::new(cache_flags, &seed).expect("RandomX: failed to initialize cache");
            *slot = Some((epoch_num, new_cache.clone()));
            new_cache
        });
        Self { target, pre_pow_hash, timestamp: header.timestamp, epoch_num, flags, cache, fast_dataset: Some(dataset) }
    }

    #[inline]
    #[must_use]
    pub fn calculate_pow(&self, nonce: u64) -> Uint256 {
        #[cfg(feature = "randomx")]
        {
            // Input: pre_pow_hash (32) || timestamp (8 LE) || nonce (8 LE) = 48 bytes
            let mut input = [0u8; 48];
            input[..32].copy_from_slice(&self.pre_pow_hash.as_bytes());
            input[32..40].copy_from_slice(&self.timestamp.to_le_bytes());
            input[40..48].copy_from_slice(&nonce.to_le_bytes());

            THREAD_VM.with(|cell| {
                let mut slot = cell.borrow_mut();

                let vm_epoch_matches = slot.as_ref().map(|(e, _)| *e == self.epoch_num).unwrap_or(false);

                if !vm_epoch_matches {
                    let vm = if let Some(ref ds) = self.fast_dataset {
                        // Fast mode: VM uses the shared dataset (no cache needed).
                        RandomXVM::new(
                            RandomXFlag::get_recommended_flags() | RandomXFlag::FLAG_FULL_MEM,
                            None,
                            Some(ds.dataset.clone()),
                        )
                        .expect("RandomX: failed to create fast VM")
                    } else {
                        // Light mode: VM uses the per-thread cache stored in State.
                        RandomXVM::new(self.flags, Some(self.cache.clone()), None).expect("RandomX: failed to create light VM")
                    };
                    *slot = Some((self.epoch_num, vm));
                }

                let (_, vm) = slot.as_mut().unwrap();
                let hash_bytes = vm.calculate_hash(&input).expect("RandomX: hash failed");
                let bytes: [u8; 32] = hash_bytes.try_into().expect("RandomX: unexpected hash length");
                Uint256::from_le_bytes(bytes)
            })
        }

        #[cfg(not(feature = "randomx"))]
        {
            let hash = self.hasher.clone().finalize_with_nonce(nonce);
            let hash = self.matrix.heavy_hash(hash);
            Uint256::from_le_bytes(hash.as_bytes())
        }
    }

    #[inline]
    #[must_use]
    pub fn check_pow(&self, nonce: u64) -> (bool, Uint256) {
        let pow = self.calculate_pow(nonce);
        (pow <= self.target, pow)
    }
}

pub fn calc_block_level(header: &Header, max_block_level: BlockLevel) -> BlockLevel {
    let (block_level, _) = calc_block_level_check_pow(header, max_block_level);
    block_level
}

pub fn calc_block_level_check_pow(header: &Header, max_block_level: BlockLevel) -> (BlockLevel, bool) {
    if header.parents_by_level.is_empty() {
        return (max_block_level, true); // Genesis has the max block level
    }

    let state = State::new(header);
    let (passed, pow) = state.check_pow(header.nonce);
    let block_level = calc_level_from_pow(pow, max_block_level);
    (block_level, passed)
}

pub fn calc_level_from_pow(pow: Uint256, max_block_level: BlockLevel) -> BlockLevel {
    let signed_block_level = max_block_level as i64 - pow.bits() as i64;
    max(signed_block_level, 0) as BlockLevel
}
