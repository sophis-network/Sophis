use sophis_sdk::prelude::*;

fn bps_to_float(bps: u64) -> f64 {
    bps as f64 / 10_000.0
}

#[sophis_contract]
pub fn bad_contract(env: Env) -> bool {
    let _rate: f64 = bps_to_float(100);
    env.block_height() > 0
}

fn main() {}
