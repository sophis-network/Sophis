//! # Example: Time-Lock Contract
//!
//! Makes a UTXO unspendable until a specific block height is reached.
//!
//! This is the simplest meaningful Sophis contract: one rule, one host call,
//! fully testable without a WASM toolchain.
//!
//! ## Rule enforced
//!
//! The transaction is rejected unless `env.block_height() >= LOCK_UNTIL`.
//!
//! ## Key patterns demonstrated
//!
//! - Minimal `#[sophis_contract]` structure.
//! - `env.block_height()` — the only host call needed for time-based rules.
//! - Extracting the condition into a pure function for clean unit tests.
//! - Checked arithmetic even for simple comparisons (overflow safety habit).
//!
//! ## Customisation
//!
//! Change [`LOCK_UNTIL`] to the block height after which spending is allowed.
//! At 10 BPS, 1 day ≈ 864 000 blocks; 1 year ≈ 315 360 000 blocks.

use sophis_sdk::prelude::*;

// ---------------------------------------------------------------------------
// Lock parameter
// ---------------------------------------------------------------------------

/// Block height after which this UTXO can be spent.
///
/// Example schedule (10 BPS):
///   ~1 hour  =    36_000 blocks
///   ~1 day   =   864_000 blocks
///   ~1 year  = 315_360_000 blocks
const LOCK_UNTIL: u64 = 864_000; // approximately 1 day after genesis

// ---------------------------------------------------------------------------
// Contract entry point
// ---------------------------------------------------------------------------

/// Time-lock entry point.
///
/// Returns `true` (spend allowed) once `block_height >= LOCK_UNTIL`.
#[sophis_contract]
pub fn time_lock(env: Env) -> bool {
    is_unlocked(env.block_height(), LOCK_UNTIL)
}

// ---------------------------------------------------------------------------
// Pure logic
// ---------------------------------------------------------------------------

/// Returns `true` if `current_height >= lock_until`.
fn is_unlocked(current_height: u64, lock_until: u64) -> bool {
    current_height >= lock_until
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_before_threshold() {
        assert!(!is_unlocked(0, 864_000));
        assert!(!is_unlocked(863_999, 864_000));
    }

    #[test]
    fn unlocked_at_threshold() {
        assert!(is_unlocked(864_000, 864_000));
    }

    #[test]
    fn unlocked_after_threshold() {
        assert!(is_unlocked(864_001, 864_000));
        assert!(is_unlocked(u64::MAX, 864_000));
    }

    #[test]
    fn zero_lock_always_unlocked() {
        // A lock_until of 0 means "always spendable" — valid degenerate case.
        assert!(is_unlocked(0, 0));
        assert!(is_unlocked(1_000_000, 0));
    }

    #[test]
    fn max_lock_only_at_max_height() {
        assert!(!is_unlocked(u64::MAX.checked_sub(1).unwrap(), u64::MAX));
        assert!(is_unlocked(u64::MAX, u64::MAX));
    }

    // Demonstrates the block schedule at 10 BPS
    #[test]
    fn schedule_reference() {
        let blocks_per_hour: u64 = 36_000;
        let blocks_per_day = blocks_per_hour.checked_mul(24).unwrap();
        let blocks_per_year = blocks_per_day.checked_mul(365).unwrap();

        // Sanity check the constants used in comments
        assert_eq!(blocks_per_day, 864_000);
        assert_eq!(blocks_per_year, 315_360_000);
    }
}
