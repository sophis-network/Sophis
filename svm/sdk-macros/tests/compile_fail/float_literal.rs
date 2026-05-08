use sophis_sdk::prelude::*;

#[sophis_contract]
pub fn bad_contract(env: Env) -> bool {
    let _rate = 0.05_f64;
    env.block_height() > 0
}

fn main() {}
