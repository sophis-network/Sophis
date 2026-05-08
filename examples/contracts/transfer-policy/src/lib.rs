//! # Example: Transfer Policy
//!
//! Enforces that a token transfer transaction does not create value out of thin air.
//!
//! ## Rule enforced
//!
//! `sum(outputs) <= sum(inputs)` — total value sent cannot exceed total value received.
//!
//! The difference (inputs − outputs) is the implicit fee consumed by the network.
//!
//! ## Key patterns demonstrated
//!
//! - Iterating multiple inputs and outputs via `env.input_utxo(i)` / `env.output_utxo(i)`.
//! - Using `Resource<u64>` to ensure every UTXO value is explicitly accounted for.
//! - Separating accumulation logic (`sum_utxos`) from validation logic (`is_conserved`)
//!   so both are independently testable.

use sophis_sdk::prelude::*;

// ---------------------------------------------------------------------------
// Contract entry point
// ---------------------------------------------------------------------------

/// Transfer policy entry point.
///
/// Approves the transaction if and only if total output value ≤ total input value.
#[sophis_contract]
pub fn transfer_policy(env: Env) -> bool {
    let input_total = match sum_inputs(&env) {
        Some(t) => t,
        None => return false,
    };
    let output_total = match sum_outputs(&env) {
        Some(t) => t,
        None => return false,
    };
    is_conserved(input_total, output_total)
}

// ---------------------------------------------------------------------------
// Pure logic
// ---------------------------------------------------------------------------

/// Returns `true` if `output_total <= input_total` (value conservation holds).
fn is_conserved(input_total: u64, output_total: u64) -> bool {
    output_total <= input_total
}

// ---------------------------------------------------------------------------
// Env-touching logic
// ---------------------------------------------------------------------------

/// Sums the `amount` of every input UTXO.
///
/// Returns `None` on overflow (which causes the contract to reject).
fn sum_inputs(env: &Env) -> Option<u64> {
    let mut total = 0u64;
    let mut i = 0u32;
    while let Some(utxo) = env.input_utxo(i) {
        let amount = Resource::new(utxo.amount);
        total = total.checked_add(amount.consume())?;
        i = i.checked_add(1)?;
    }
    Some(total)
}

/// Sums the `value` of every output UTXO.
///
/// Returns `None` on overflow (which causes the contract to reject).
fn sum_outputs(env: &Env) -> Option<u64> {
    let mut total = 0u64;
    let mut i = 0u32;
    while let Some(output) = env.output_utxo(i) {
        let value = Resource::new(output.value);
        total = total.checked_add(value.consume())?;
        i = i.checked_add(1)?;
    }
    Some(total)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_conserved ---

    #[test]
    fn equal_totals_accepted() {
        assert!(is_conserved(1_000, 1_000));
    }

    #[test]
    fn outputs_less_than_inputs_accepted() {
        // The remainder (500) is the implicit fee — perfectly valid.
        assert!(is_conserved(1_000, 500));
    }

    #[test]
    fn zero_values_accepted() {
        assert!(is_conserved(0, 0));
    }

    #[test]
    fn outputs_exceed_inputs_rejected() {
        assert!(!is_conserved(500, 501));
        assert!(!is_conserved(0, 1));
        assert!(!is_conserved(u64::MAX.checked_sub(1).unwrap(), u64::MAX));
    }

    #[test]
    fn large_values_conserved() {
        // Typical mainnet scenario: many satoshis in, same out minus fees
        let input = 21_000_000u64.checked_mul(100_000_000).unwrap();
        let output = input.checked_sub(50_000).unwrap();
        assert!(is_conserved(input, output));
    }

    // --- Resource<T>: show that each UTXO value is accounted for ---

    #[test]
    fn resource_forces_explicit_handling() {
        // Simulates manually accumulating values the way sum_inputs does
        let values = [100u64, 200, 300];
        let mut total = 0u64;
        for &v in &values {
            let amount = Resource::new(v);
            total = total.checked_add(amount.consume()).unwrap();
        }
        assert_eq!(total, 600);
    }

    #[test]
    #[should_panic(expected = "Resource<u64> dropped without consuming")]
    fn forgotten_utxo_value_panics() {
        // If you read a UTXO value into a Resource but forget to use it,
        // the contract panics rather than silently ignoring the amount.
        let _unaccounted = Resource::new(9_999u64);
    }
}
