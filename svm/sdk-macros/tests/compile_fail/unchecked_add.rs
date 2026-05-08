use sophis_sdk::prelude::*;

#[sophis_contract]
pub fn bad_contract(env: Env) -> bool {
    let height = env.block_height();
    height + 1000 > 5000
}

fn main() {}
