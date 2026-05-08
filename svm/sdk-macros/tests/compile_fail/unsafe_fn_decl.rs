use sophis_sdk::prelude::*;

#[sophis_contract]
pub unsafe fn bad_contract(env: Env) -> bool {
    env.block_height() > 0
}

fn main() {}
