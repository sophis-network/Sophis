use risc0_zkvm::{InnerReceipt, Receipt};

/// Verify a Risc0 STARK proof offline (no re-execution).
///
/// - `seal`:     raw bytes of the Groth16 or STARK seal produced by the prover.
/// - `journal`:  public output bytes (borsh-encoded, as committed by `env::commit_slice`).
/// - `image_id`: 32-byte image ID of the expected guest ELF.
///
/// Returns `true` if the proof is valid for the given image_id and journal.
/// Returns `false` on any malformed input or verification failure.
pub fn verify_risc0_proof_bytes(seal: &[u8], journal: &[u8], image_id: &[u8]) -> bool {
    if image_id.len() != 32 {
        return false;
    }
    let Ok(id_bytes) = <[u8; 32]>::try_from(image_id) else {
        return false;
    };
    // Convert [u8; 32] → [u32; 8] (Risc0 image ID format: 8× big-endian u32)
    let mut image_id_words = [0u32; 8];
    for (i, chunk) in id_bytes.chunks_exact(4).enumerate() {
        image_id_words[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }

    // Attempt to deserialize the receipt from the seal bytes.
    // Risc0 seals are bincode-serialized InnerReceipt.
    let inner: InnerReceipt = match bincode::deserialize(seal) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let receipt = Receipt::new(inner, journal.to_vec());
    receipt.verify(image_id_words).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_image_id_length_rejected() {
        assert!(!verify_risc0_proof_bytes(&[], &[], &[0u8; 31]));
        assert!(!verify_risc0_proof_bytes(&[], &[], &[0u8; 33]));
    }

    #[test]
    fn garbage_seal_rejected() {
        assert!(!verify_risc0_proof_bytes(b"garbage", b"journal", &[0u8; 32]));
    }
}
