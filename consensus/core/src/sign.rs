use crate::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_signature_hash},
        sighash_type::SigHashType,
    },
    tx::VerifiableTransaction,
};
use libcrux_ml_dsa::ml_dsa_44::{self, MLDSA44SigningKey};
use thiserror::Error;

// Dilithium-2 (ML-DSA-44) sizes per FIPS 204 — private in libcrux crate
const DILITHIUM2_SIGNING_KEY_SIZE: usize = 2560;

#[derive(Error, Debug, Clone)]
pub enum Error {
    #[error("{0}")]
    Message(String),

    #[error("Dilithium signing error")]
    DilithiumError,
}

/// Sign a transaction input with Dilithium-2 (ML-DSA-44, FIPS 204).
///
/// The signing key is 2560 bytes (ML-DSA-44 signing key size).
/// Returns the signature script: OP_PUSHDATA2 <sig+sighash_type>
/// encoded as P2SH input (signature + redeem script).
///
/// For P2SH spending, the caller must also provide the redeem script bytes.
pub fn sign_input_dilithium(
    tx: &impl VerifiableTransaction,
    input_index: usize,
    signing_key_bytes: &[u8; DILITHIUM2_SIGNING_KEY_SIZE],
    hash_type: SigHashType,
) -> Result<Vec<u8>, Error> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_signature_hash(tx, input_index, hash_type, &reused_values);
    let message = &sig_hash.as_bytes()[..];

    let sk = MLDSA44SigningKey::new(*signing_key_bytes);
    let randomness = {
        let mut r = [0u8; libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE];
        getrandom::getrandom(&mut r).map_err(|_| Error::DilithiumError)?;
        r
    };

    let signature = ml_dsa_44::sign(&sk, message, b"", randomness).map_err(|_| Error::DilithiumError)?;
    let sig_bytes = signature.as_ref();

    // Signature script for P2SH Dilithium input:
    // OP_PUSHDATA2 <2421 bytes: sig(2420) + hash_type(1)>
    let sig_with_type: Vec<u8> = sig_bytes.iter().copied().chain([hash_type.to_u8()]).collect();
    // Prepend OP_PUSHDATA2 (0x4d) + 2-byte LE length
    let sig_len = sig_with_type.len() as u16;
    let mut script = vec![0x4d, sig_len as u8, (sig_len >> 8) as u8];
    script.extend_from_slice(&sig_with_type);
    Ok(script)
}
