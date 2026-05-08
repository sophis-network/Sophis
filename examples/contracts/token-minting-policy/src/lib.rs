//! # Example: Token Minting Policy
//!
//! Controls when and how much of a native token can be minted.
//!
//! ## Rules enforced
//!
//! 1. **Time window**: minting is only allowed during blocks [`MINT_START`]..=[`MINT_END`].
//! 2. **Per-tx cap**: total minted per transaction cannot exceed [`MAX_MINT_SOMPI`].
//! 3. **Non-empty**: at least one token output must be present.
//!
//! ## Key patterns demonstrated
//!
//! - `#[sophis_contract]` — entry point macro; generates the `validate() -> i32` WASM export.
//! - `Resource<T>` — linear wrapper that panics if an amount is silently discarded.
//! - Pure logic functions — separated from `Env` calls so they can be unit-tested natively.
//! - Checked arithmetic — `+` is banned by the macro; use `.checked_add()` instead.

use sophis_sdk::prelude::*;

// ---------------------------------------------------------------------------
// Policy parameters — change these to customise your token's minting rules
// ---------------------------------------------------------------------------

/// First block at which minting is allowed.
const MINT_START: u64 = 1_000;

/// Last block at which minting is allowed.
const MINT_END: u64 = 10_000_000;

/// Maximum total token units (sompi) that can be minted in a single transaction.
/// 1_000_000_000 = 1 000 SPHS-equivalent at 1 000 000 sompi per unit.
const MAX_MINT_SOMPI: u64 = 1_000_000_000;

// ---------------------------------------------------------------------------
// Contract entry point
// ---------------------------------------------------------------------------

/// Minting policy entry point.
///
/// Returns `true` to approve the mint; `false` to reject it.
/// Rejection aborts the transaction with no state change.
#[sophis_contract]
pub fn minting_policy(env: Env) -> bool {
    // Gate 1: block height must be within the minting window
    if !in_minting_window(env.block_height()) {
        return false;
    }

    // Gate 2: sum all output values and check the per-tx cap
    let (total, count) = match collect_output_total(&env) {
        Some(pair) => pair,
        None => return false, // arithmetic overflow — reject
    };

    validate_mint(total, count)
}

// ---------------------------------------------------------------------------
// Pure logic — no Env calls; fully testable on native targets
// ---------------------------------------------------------------------------

/// Returns true if `height` is within the minting window.
fn in_minting_window(height: u64) -> bool {
    (MINT_START..=MINT_END).contains(&height)
}

/// Returns true if the mint is valid given `total` sompi across `count` outputs.
fn validate_mint(total: u64, count: u32) -> bool {
    count > 0 && total <= MAX_MINT_SOMPI
}

// ---------------------------------------------------------------------------
// Env-touching logic — tested via integration/WASM tests only
// ---------------------------------------------------------------------------

/// Sums the `value` field of every output UTXO in the transaction.
///
/// Returns `Some((total_sompi, output_count))` or `None` on overflow.
///
/// `Resource<u64>` wraps each output value so that accidentally ignoring an
/// amount causes a compile-detectable panic rather than a silent logic error.
fn collect_output_total(env: &Env) -> Option<(u64, u32)> {
    let mut total = 0u64;
    let mut count = 0u32;

    let mut i = 0u32;
    while let Some(output) = env.output_utxo(i) {
        // Wrap in Resource: the amount MUST be explicitly consumed below.
        // If you remove the .consume() call this panics — intentional by design.
        let amount = Resource::new(output.value);
        total = total.checked_add(amount.consume())?;
        count = count.checked_add(1)?;
        i = i.checked_add(1)?;
    }

    Some((total, count))
}

// ---------------------------------------------------------------------------
// Unit tests — run with `cargo test` on native (no WASM toolchain needed)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- in_minting_window ---

    #[test]
    fn window_before_start_rejected() {
        assert!(!in_minting_window(0));
        assert!(!in_minting_window(999));
    }

    #[test]
    fn window_start_inclusive() {
        assert!(in_minting_window(MINT_START));
    }

    #[test]
    fn window_middle_accepted() {
        assert!(in_minting_window(5_000_000));
    }

    #[test]
    fn window_end_inclusive() {
        assert!(in_minting_window(MINT_END));
    }

    #[test]
    fn window_after_end_rejected() {
        assert!(!in_minting_window(MINT_END.checked_add(1).unwrap()));
    }

    // --- validate_mint ---

    #[test]
    fn zero_outputs_rejected() {
        assert!(!validate_mint(0, 0));
    }

    #[test]
    fn within_cap_accepted() {
        assert!(validate_mint(MAX_MINT_SOMPI, 1));
        assert!(validate_mint(1, 1));
        assert!(validate_mint(MAX_MINT_SOMPI, 5));
    }

    #[test]
    fn exactly_at_cap_accepted() {
        assert!(validate_mint(MAX_MINT_SOMPI, 1));
    }

    #[test]
    fn exceeds_cap_rejected() {
        assert!(!validate_mint(MAX_MINT_SOMPI.checked_add(1).unwrap(), 1));
        assert!(!validate_mint(u64::MAX, 1));
    }

    #[test]
    fn output_count_nonzero_required() {
        // total=0 with count=0 is rejected even though total ≤ cap
        assert!(!validate_mint(0, 0));
        // total=0 with count=1 is accepted (mint of zero is valid structurally)
        assert!(validate_mint(0, 1));
    }

    // --- Resource<T>: demonstrate the linear-type guarantee ---

    #[test]
    fn resource_must_be_consumed() {
        let amount = Resource::new(500u64);
        assert_eq!(amount.consume(), 500);
    }

    #[test]
    #[should_panic(expected = "Resource<u64> dropped without consuming")]
    fn resource_panics_if_dropped_silently() {
        let _forgotten = Resource::new(999u64);
        // Not consumed → panic on drop
    }
}
