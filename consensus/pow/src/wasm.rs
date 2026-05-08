use js_sys::BigInt;
use num::Float;
use sophis_consensus_client::Header;
use sophis_consensus_client::HeaderT;
use sophis_consensus_core::hashing;
use sophis_hashes::Hash;
use sophis_math::Uint256;
use sophis_utils::hex::FromHex;
use wasm_bindgen::prelude::*;
use workflow_wasm::convert::TryCastFromJs;
use workflow_wasm::error::Error;
use workflow_wasm::result::Result;

// RandomX does not run in WebAssembly environments.
// WASM mining uses the legacy kHeavyHash as a fallback.
// Production browser mining should connect to a mining pool via Stratum.
use crate::matrix::Matrix;
use sophis_hashes::PowHash;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends = js_sys::Array, typescript_type = "[boolean, bigint]")]
    pub type WorkT;
}

/// Represents a Sophis header PoW manager (WASM/browser — kHeavyHash fallback)
/// @category Mining
#[wasm_bindgen(inspectable)]
pub struct PoW {
    target: Uint256,
    hasher: PowHash,
    matrix: Matrix,
    pre_pow_hash: Hash,
}

#[wasm_bindgen]
impl PoW {
    #[wasm_bindgen(constructor)]
    pub fn new(header: &HeaderT, timestamp: Option<u64>) -> Result<PoW> {
        let header = Header::try_cast_from(header).map_err(Error::custom)?;
        let header = header.as_ref();
        let header = header.inner();

        let target = Uint256::from_compact_target_bits(header.bits);
        let pre_pow_hash = hashing::header::hash_override_nonce_time(header, 0, 0);
        let hasher = PowHash::new(pre_pow_hash, timestamp.unwrap_or(header.timestamp));
        let matrix = Matrix::generate(pre_pow_hash);

        Ok(Self { target, hasher, matrix, pre_pow_hash })
    }

    /// The target based on the provided bits.
    #[wasm_bindgen(getter)]
    pub fn target(&self) -> Result<BigInt> {
        self.target.try_into().map_err(|err| Error::custom(format!("{err:?}")))
    }

    /// Checks if the computed target meets or exceeds the difficulty specified in the template.
    /// @returns A boolean indicating if it reached the target and a bigint representing the reached target.
    #[wasm_bindgen(js_name=checkWork)]
    pub fn check_work(&self, nonce: u64) -> Result<WorkT> {
        let hash = self.hasher.clone().finalize_with_nonce(nonce);
        let hash = self.matrix.heavy_hash(hash);
        let pow = Uint256::from_le_bytes(hash.as_bytes());
        let passed = pow <= self.target;

        let array = js_sys::Array::new();
        array.push(&JsValue::from(passed));
        array.push(&pow.to_bigint().map_err(|err| Error::custom(format!("{err:?}")))?.into());
        Ok(array.unchecked_into())
    }

    /// Hash of the header without timestamp and nonce.
    #[wasm_bindgen(getter = prePoWHash)]
    pub fn get_pre_pow_hash(&self) -> String {
        use sophis_utils::hex::ToHex;
        self.pre_pow_hash.to_hex()
    }

    /// Can be used for parsing Stratum templates.
    #[wasm_bindgen(js_name=fromRaw)]
    pub fn from_raw(pre_pow_hash: &str, timestamp: u64, target_bits: Option<u32>) -> Result<PoW> {
        let pre_pow_hash = Hash::from_hex(pre_pow_hash).map_err(|err| Error::custom(format!("{err:?}")))?;
        let target = Uint256::from_compact_target_bits(target_bits.unwrap_or_default());
        let matrix = Matrix::generate(pre_pow_hash);
        let hasher = PowHash::new(pre_pow_hash, timestamp);
        Ok(PoW { target, hasher, matrix, pre_pow_hash })
    }
}

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
        buf[start + 1] = new_mantissa >> (64 - remainder);
    } else if new_mantissa.leading_zeros() < remainder as u32 {
        return Err(Error::custom("Target is too big"));
    }

    Uint256(buf).try_into().map_err(Error::custom)
}
