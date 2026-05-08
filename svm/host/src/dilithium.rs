use libcrux_ml_dsa::ml_dsa_44::{self, MLDSA44Signature, MLDSA44VerificationKey};

const VK_SIZE: usize = 1312;
const SIG_SIZE: usize = 2420;

/// Verifies a raw ML-DSA-44 (Dilithium2) signature per FIPS 204.
/// pk:  1312-byte verification key
/// msg: message of any length (sighash or arbitrary bytes)
/// sig: 2420-byte signature
pub fn verify_dilithium_ml_dsa44(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if pk.len() != VK_SIZE || sig.len() != SIG_SIZE {
        return false;
    }
    let Ok(vk_bytes) = <[u8; VK_SIZE]>::try_from(pk) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; SIG_SIZE]>::try_from(sig) else {
        return false;
    };
    let vk = MLDSA44VerificationKey::new(vk_bytes);
    let signature = MLDSA44Signature::new(sig_bytes);
    ml_dsa_44::verify(&vk, msg, b"", &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_lengths_rejected() {
        assert!(!verify_dilithium_ml_dsa44(&[0u8; VK_SIZE - 1], &[], &[0u8; SIG_SIZE]));
        assert!(!verify_dilithium_ml_dsa44(&[0u8; VK_SIZE], &[], &[0u8; SIG_SIZE - 1]));
    }

    #[test]
    fn invalid_sig_returns_false() {
        assert!(!verify_dilithium_ml_dsa44(&[0u8; VK_SIZE], b"test", &[0u8; SIG_SIZE]));
    }
}
