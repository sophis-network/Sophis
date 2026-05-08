use sophis_sdk::prelude::*;

#[sophis_contract]
pub fn bad_contract(env: Env) -> bool {
    let utxo = env.input_utxo(0).unwrap();
    utxo.amount * 2 > 1000
}

fn main() {}
