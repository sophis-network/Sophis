use sophis_sdk::prelude::*;

const MIN_HEIGHT: u64 = 1_000;
const FEE_BPS: u64 = 100; // 1%
const BASIS: u64 = 10_000;

#[sophis_contract]
pub fn timelock_with_fee(env: Env) -> bool {
    let height = env.block_height();
    if height < MIN_HEIGHT {
        return false;
    }
    let Some(utxo) = env.input_utxo(0) else { return false };
    let fee = utxo
        .amount
        .checked_mul(FEE_BPS)
        .and_then(|v| v.checked_div(BASIS));
    fee.is_some()
}

fn main() {}
