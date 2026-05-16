// Build guard (originated as Session-1 audit finding F-1, 2026-05-14;
// upgraded to Option 3 — full kHeavyHash removal — 2026-05-16 per founder
// decision; the WASM32 exemption history from Session 5 is preserved).
//
// Sophis is RandomX-only (PoW = RandomX, per CLAUDE.md invariants). The
// legacy kHeavyHash `Matrix`/`PowHash` fallback PoW has been deleted
// entirely — there is no longer a second compilable PoW algorithm in this
// crate. What remains on the `not(feature = "randomx")` path is a
// type-only stub: `State` still exists but `calculate_pow` is
// `unreachable!()` (no algorithm), so wasm32 consumers can pull sophis-pow
// transitively for type definitions while never hashing.
//
// A *native* build without `randomx` would therefore have no working PoW
// (every `calculate_pow` panics). That is almost certainly a build
// misconfiguration for a node, so we fail fast at compile time instead of
// shipping a binary that panics at the first PoW check.
//
// Exemptions to the guard:
//   1. `feature = "wasm32-sdk"` — browser SDK build (ships Stratum helpers
//      such as `wasm::calculate_target`; no in-browser PoW).
//   2. `target_arch = "wasm32"` — any wasm32 target (WASM SDK, web
//      bindings, compact-filters JS bridge). `randomx-rs` does not compile
//      to wasm32; these consumers pull `sophis-pow` for type definitions,
//      not hashing. Forcing `randomx` on wasm32 would break every
//      downstream wasm32 consumer.
//
// The CI WASM32 job (`cargo clippy -p sophis-wasm --target
// wasm32-unknown-unknown`) needs both exemptions: it does not enable the
// `wasm32-sdk` feature on sophis-pow, but it does build for wasm32, so the
// `target_arch` exemption is what unblocks it.
#[cfg(all(not(feature = "randomx"), not(feature = "wasm32-sdk"), not(target_arch = "wasm32"),))]
compile_error!(
    "sophis-pow requires the 'randomx' feature (mainnet/testnet — default) on \
     native targets. The legacy kHeavyHash fallback has been removed (F-1 \
     Option 3); a non-randomx native build has no working PoW (calculate_pow \
     is unreachable!). Either remove `--no-default-features` or add \
     `--features randomx`. wasm32 targets are exempt — randomx-rs does not \
     build on wasm32 and pulls sophis-pow for type definitions only."
);

#[cfg(feature = "wasm32-sdk")]
pub mod wasm;

use std::cmp::max;
#[cfg(feature = "randomx")]
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

// ---------------------------------------------------------------------------
// F-24 (pre-testnet audit, Session 15, 2026-05-16): RandomX allocation
// resilience.
//
// `RandomXCache::new` (256 MB light cache) and `RandomXDataset::new`
// (~2 GB fast dataset) allocate large contiguous buffers. Under host RAM
// contention — canonical repro: a co-located devnet (5 sophisd + observer
// + da-stress) hitting an epoch transition while the miner rebuilds the
// 2 GB dataset — the allocator transiently fails with
// `RandomXError::CreationError("Could not allocate cache")`. The pre-F-24
// code `.expect()`ed this and panicked the whole miner / validator
// process on the *first* failure.
//
// The spike is transient: once a competing process releases memory the
// next attempt succeeds. So we add bounded retry with exponential backoff
// for the alloc-failure class only — flag/parameter errors are
// deterministic config bugs and fail fast (retrying a bad flag never
// helps). The infallible `build_epoch_dataset` / `State::new` keep their
// panic-on-failure contract for the consensus-validation path, but only
// after retries are exhausted (strictly safer: a transient OOM during
// block validation now recovers instead of taking the node down; the
// rebuilt cache is byte-identical — deterministic from the epoch seed —
// so consensus correctness is unchanged, only timing). New fallible
// `try_*` variants let the miner downgrade fast → light instead of dying.
//
// Intentionally no logging here: sophis-pow is an audited consensus crate
// and its dependency surface is frozen. The caller (miner) logs the
// fallback decision; the exhausted-retry case still surfaces via the
// `.expect()` panic message or the returned `Err`.
// ---------------------------------------------------------------------------

#[cfg(feature = "randomx")]
const MAX_ALLOC_ATTEMPTS: u32 = 5;

/// Is this RandomX error worth retrying? Only the allocation-failure
/// class (`CreationError`) is transient under RAM pressure. Flag /
/// parameter / conversion errors are deterministic — retrying never helps.
#[cfg(feature = "randomx")]
fn is_retryable(err: &randomx_rs::RandomXError) -> bool {
    matches!(err, randomx_rs::RandomXError::CreationError(_))
}

/// Backoff before retry attempt `attempt` (1-based: the delay *preceding*
/// the Nth retry). Attempt 0 is the initial try and has no delay.
/// 2 s, 4 s, 8 s, 16 s, then capped at 30 s.
#[cfg(feature = "randomx")]
fn backoff_delay(attempt: u32) -> std::time::Duration {
    if attempt == 0 {
        return std::time::Duration::ZERO;
    }
    let secs = (1u64 << attempt.min(5)).min(30); // 2, 4, 8, 16, 30
    std::time::Duration::from_secs(secs)
}

/// Run a large RandomX allocation with bounded retry + exponential
/// backoff on the transient alloc-failure class.
#[cfg(feature = "randomx")]
fn retry_alloc<T>(mut f: impl FnMut() -> Result<T, randomx_rs::RandomXError>) -> Result<T, randomx_rs::RandomXError> {
    let mut attempt = 0u32;
    loop {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) => {
                let is_last = attempt + 1 >= MAX_ALLOC_ATTEMPTS;
                if is_last || !is_retryable(&e) {
                    return Err(e);
                }
                attempt += 1;
                std::thread::sleep(backoff_delay(attempt));
            }
        }
    }
}

/// Reuse the per-thread RandomX cache for `epoch_num`, or build it (with
/// retry) on miss. Fallible: callers choose panic (`State::new`) or
/// graceful degrade (`State::try_new`).
#[cfg(feature = "randomx")]
fn get_or_build_thread_cache(epoch_num: u64, flags: RandomXFlag, seed: [u8; 8]) -> Result<RandomXCache, randomx_rs::RandomXError> {
    THREAD_EPOCH_CACHE.with(|cell| {
        let mut slot = cell.borrow_mut();
        if let Some((cached_epoch, ref cached_cache)) = *slot
            && cached_epoch == epoch_num
        {
            return Ok(cached_cache.clone()); // cheap Arc clone
        }
        let new_cache = retry_alloc(|| RandomXCache::new(flags, &seed))?;
        *slot = Some((epoch_num, new_cache.clone()));
        Ok(new_cache)
    })
}

/// Fallible variant of [`build_epoch_dataset`]. Returns the underlying
/// `RandomXError` (after retries are exhausted) instead of panicking, so
/// the miner can fall back to light mode.
/// Allocates ~2 GB of RAM and takes 1–2 minutes on a modern CPU.
#[cfg(feature = "randomx")]
pub fn try_build_epoch_dataset(daa_score: u64) -> Result<SharedDataset, randomx_rs::RandomXError> {
    let epoch_num = daa_score / EPOCH_LENGTH;
    let seed = epoch_seed(daa_score);
    let cache_flags = RandomXFlag::get_recommended_flags();
    let cache = retry_alloc(|| RandomXCache::new(cache_flags, &seed))?;
    let dataset = retry_alloc(|| RandomXDataset::new(RandomXFlag::FLAG_DEFAULT, cache.clone(), 0))?;
    Ok(SharedDataset { epoch_num, dataset })
}

/// Builds a RandomX dataset for the epoch containing `daa_score`.
/// Allocates ~2 GB of RAM and takes 1–2 minutes on a modern CPU.
/// Returns a `SharedDataset` that can be wrapped in `Arc` and shared across threads.
/// Panics only if the allocation still fails after [`MAX_ALLOC_ATTEMPTS`]
/// retries — see the F-24 note above.
#[cfg(feature = "randomx")]
pub fn build_epoch_dataset(daa_score: u64) -> SharedDataset {
    try_build_epoch_dataset(daa_score).expect("RandomX: failed to initialize cache for dataset build")
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

// On the `not(feature = "randomx")` type-only path (wasm32 transitive
// consumers) `calculate_pow` is `unreachable!()`, so `pre_pow_hash`,
// `timestamp` and `epoch_num` are constructed but never read. They exist
// solely so the type-shape matches the randomx build. The allow is scoped
// to that cfg only — on the randomx build the dead-code lint stays active.
#[cfg_attr(not(feature = "randomx"), allow(dead_code))]
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
}

// RandomXCache / SharedDataset are read-only after init — safe to share across threads.
#[cfg(feature = "randomx")]
unsafe impl Send for State {}
#[cfg(feature = "randomx")]
unsafe impl Sync for State {}

impl State {
    /// Light-mode constructor (256 MB cache). The cache is reused across
    /// templates in the same epoch via a thread-local. Panics only if the
    /// allocation still fails after [`MAX_ALLOC_ATTEMPTS`] retries (F-24);
    /// use [`State::try_new`] for graceful degradation.
    #[inline]
    pub fn new(header: &Header) -> Self {
        #[cfg(feature = "randomx")]
        {
            Self::try_new(header).expect("RandomX: failed to initialize cache")
        }

        #[cfg(not(feature = "randomx"))]
        {
            // Type-only path (wasm32 transitive consumers). No PoW
            // algorithm — `calculate_pow` is `unreachable!()`; these fields
            // exist solely so the type compiles and `calc_block_level`
            // type-checks. Never executed for hashing on wasm32.
            let target = Uint256::from_compact_target_bits(header.bits);
            let pre_pow_hash = hashing::header::hash_override_nonce_time(header, 0, 0);
            let epoch_num = header.daa_score / EPOCH_LENGTH;
            Self { target, pre_pow_hash, timestamp: header.timestamp, epoch_num }
        }
    }

    /// Fallible light-mode constructor (F-24): returns the `RandomXError`
    /// after retries are exhausted instead of panicking, so the caller can
    /// degrade gracefully (the miner sleeps and retries the mining loop).
    #[cfg(feature = "randomx")]
    #[inline]
    pub fn try_new(header: &Header) -> Result<Self, randomx_rs::RandomXError> {
        let target = Uint256::from_compact_target_bits(header.bits);
        let pre_pow_hash = hashing::header::hash_override_nonce_time(header, 0, 0);
        let epoch_num = header.daa_score / EPOCH_LENGTH;
        let flags = RandomXFlag::get_recommended_flags();
        let seed = epoch_seed(header.daa_score);
        let cache = get_or_build_thread_cache(epoch_num, flags, seed)?;
        Ok(Self { target, pre_pow_hash, timestamp: header.timestamp, epoch_num, flags, cache, fast_dataset: None })
    }

    /// Fast-mode constructor (~2 GB dataset, ~10x hashrate). The caller
    /// builds and caches the `SharedDataset` (see `build_epoch_dataset`)
    /// and rebuilds it on epoch boundaries. Panics only if the cache
    /// allocation fails after retries (F-24); see [`State::try_new_fast`].
    #[cfg(feature = "randomx")]
    #[inline]
    pub fn new_fast(header: &Header, dataset: Arc<SharedDataset>) -> Self {
        Self::try_new_fast(header, dataset).expect("RandomX: failed to initialize cache")
    }

    /// Fallible fast-mode constructor (F-24).
    /// The thread-local cache is reused per epoch (same build cost as
    /// light mode, once per epoch). It is not used for hashing in fast
    /// mode (the VM uses the dataset) but caching it avoids rebuilding the
    /// RandomX cache on every template call.
    #[cfg(feature = "randomx")]
    #[inline]
    pub fn try_new_fast(header: &Header, dataset: Arc<SharedDataset>) -> Result<Self, randomx_rs::RandomXError> {
        let target = Uint256::from_compact_target_bits(header.bits);
        let pre_pow_hash = hashing::header::hash_override_nonce_time(header, 0, 0);
        let epoch_num = header.daa_score / EPOCH_LENGTH;
        let flags = RandomXFlag::get_recommended_flags() | RandomXFlag::FLAG_FULL_MEM;
        let cache_flags = RandomXFlag::get_recommended_flags();
        let seed = epoch_seed(header.daa_score);
        let cache = get_or_build_thread_cache(epoch_num, cache_flags, seed)?;
        Ok(Self { target, pre_pow_hash, timestamp: header.timestamp, epoch_num, flags, cache, fast_dataset: Some(dataset) })
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
            let _ = nonce;
            unreachable!(
                "sophis-pow has no PoW without the 'randomx' feature: the \
                 legacy kHeavyHash fallback was removed (F-1 Option 3). The \
                 non-randomx path is type-only for wasm32 transitive \
                 consumers; browsers must use Stratum to a real RandomX \
                 miner. A native node reaching this is a build \
                 misconfiguration the module-level compile guard prevents."
            )
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

// F-24 (pre-testnet audit, Session 15): unit coverage for the RandomX
// allocation retry decision logic. These exercise the pure parts of the
// fix — which errors retry, the backoff schedule, and the retry loop's
// control flow — without forcing a real 256 MB / 2 GB allocation (covered
// end-to-end by the devnet mining suite and the Phase 6 soak ladder).
#[cfg(all(test, feature = "randomx"))]
mod f24_retry_tests {
    use std::cell::Cell;
    use std::time::Duration;

    use randomx_rs::RandomXError;

    use super::{MAX_ALLOC_ATTEMPTS, backoff_delay, is_retryable, retry_alloc};

    #[test]
    fn only_alloc_failure_is_retryable() {
        // The transient OOM class — retrying after backoff can succeed.
        assert!(is_retryable(&RandomXError::CreationError("Could not allocate cache".into())));
        // Deterministic config/usage errors — retrying never helps, fail fast.
        assert!(!is_retryable(&RandomXError::ParameterError("key is empty".into())));
        assert!(!is_retryable(&RandomXError::FlagConfigError("bad flags".into())));
        assert!(!is_retryable(&RandomXError::Other("misc".into())));
    }

    #[test]
    fn backoff_is_zero_then_exponential_capped_at_30s() {
        assert_eq!(backoff_delay(0), Duration::ZERO); // initial try: no wait
        assert_eq!(backoff_delay(1), Duration::from_secs(2));
        assert_eq!(backoff_delay(2), Duration::from_secs(4));
        assert_eq!(backoff_delay(3), Duration::from_secs(8));
        assert_eq!(backoff_delay(4), Duration::from_secs(16));
        assert_eq!(backoff_delay(5), Duration::from_secs(30)); // cap
        assert_eq!(backoff_delay(99), Duration::from_secs(30)); // stays capped
    }

    #[test]
    fn succeeds_on_first_try_without_retry() {
        let calls = Cell::new(0u32);
        let r: Result<u32, RandomXError> = retry_alloc(|| {
            calls.set(calls.get() + 1);
            Ok(42)
        });
        assert_eq!(r.unwrap(), 42);
        assert_eq!(calls.get(), 1, "must not retry on success");
    }

    #[test]
    fn non_retryable_error_fails_immediately() {
        let calls = Cell::new(0u32);
        let r: Result<u32, RandomXError> = retry_alloc(|| {
            calls.set(calls.get() + 1);
            Err(RandomXError::ParameterError("deterministic".into()))
        });
        assert!(r.is_err());
        assert_eq!(calls.get(), 1, "config errors must not be retried");
    }

    #[test]
    fn retries_transient_failure_then_succeeds() {
        // One transient failure → one retry (sleeps backoff_delay(1)=2s) → ok.
        let calls = Cell::new(0u32);
        let r: Result<u32, RandomXError> = retry_alloc(|| {
            calls.set(calls.get() + 1);
            if calls.get() < 2 { Err(RandomXError::CreationError("Could not allocate cache".into())) } else { Ok(7) }
        });
        assert_eq!(r.unwrap(), 7);
        assert_eq!(calls.get(), 2, "must retry exactly once then succeed");
    }

    #[test]
    fn attempt_cap_is_five() {
        // Guards the F-24 contract: the loop bounds retries so a permanent
        // OOM eventually surfaces (panic on the consensus path / Err on the
        // miner path) instead of hanging forever.
        assert_eq!(MAX_ALLOC_ATTEMPTS, 5);
    }
}
