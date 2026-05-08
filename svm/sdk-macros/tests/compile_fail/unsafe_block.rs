use sophis_sdk::prelude::*;

#[sophis_contract]
pub fn bad_contract(env: Env) -> bool {
    let _x = unsafe { 42_u64 };
    env.block_height() > 0
}

fn main() {}
