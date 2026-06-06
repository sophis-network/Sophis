//! WASM/browser helpers for Sophis mining.
//!
//! Sophis is RandomX-only. RandomX does not run in WebAssembly, and the
//! legacy in-browser kHeavyHash "miner" was removed (audit finding F-1,
//! Option 3, 2026-05-16): it could only ever hash a now-deleted algorithm
//! and never produce a block valid under the network's RandomX consensus
//! rules, so shipping it was actively misleading. Browser clients must
//! connect to a real RandomX miner via Stratum. Only the Stratum-side
//! difficulty→target helper remains here.

use js_sys::BigInt;
use num::Float;
use sophis_math::Uint256;
use wasm_bindgen::prelude::*;
use workflow_wasm::error::Error;
use workflow_wasm::result::Result;

// https://github.com/tmrlvi/sophis-miner/blob/bf361d02a46c580f55f46b5dfa773477634a5753/src/client/stratum.rs#L36
const DIFFICULTY_1_TARGET: (u64, i16) = (0xffffu64, 208); // 0xffff 2^208

/// Calculates target from difficulty, based on set_difficulty function on
/// <https://github.com/tmrlvi/sophis-miner/blob/bf361d02a46c580f55f46b5dfa773477634a5753/src/client/stratum.rs#L375>
/// @category Mining
#[wasm_bindgen(js_name = calculateTarget)]
pub fn calculate_target(difficulty: f32) -> Result<BigInt> {
    let mut buf = [0u64, 0u64, 0u64, 0u64];
    let (mantissa, exponent, _) = difficulty.recip().integer_decode();
    let new_mantissa = mantissa * DIFFICULTY_1_TARGET.0;
    let new_exponent = (DIFFICULTY_1_TARGET.1 + exponent) as u64;
    let start = (new_exponent / 64) as usize;
    let remainder = new_exponent % 64;

    buf[start] = new_mantissa << remainder;
    if start < 3 {
        // F-37 — when `remainder == 0` the carry shift would be `>> 64`, which
        // panics in debug and wraps in release. In that case the mantissa fits
        // entirely in `buf[start]` and the high word carries nothing.
        buf[start + 1] = if remainder == 0 { 0 } else { new_mantissa >> (64 - remainder) };
    } else if new_mantissa.leading_zeros() < remainder as u32 {
        return Err(Error::custom("Target is too big"));
    }

    Uint256(buf).try_into().map_err(Error::custom)
}
