// A clean contract — uses checked arithmetic, no floats, no unsafe.
// This file must compile without any sophis_lint warnings.

const BASIS: u64 = 10_000; // 100.00%

fn apply_fee(amount: u64, fee_bps: u64) -> Option<u64> {
    let fee = amount.checked_mul(fee_bps)?.checked_div(BASIS)?;
    amount.checked_sub(fee)
}

fn validate_transfer(balance: u64, amount: u64, fee_bps: u64) -> bool {
    let Some(total) = apply_fee(amount, fee_bps) else { return false };
    balance >= total
}

fn main() {
    assert!(validate_transfer(1_000_000, 500_000, 100)); // 1% fee
}
