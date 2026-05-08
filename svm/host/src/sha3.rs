use sha3::{Digest, Sha3_384};

/// Computes SHA3-384 of `data`, returning 48 bytes.
pub fn sha3_384_hash(data: &[u8]) -> [u8; 48] {
    let mut hasher = Sha3_384::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_known_hash() {
        // SHA3-384("") — NIST test vector
        let expected =
            hex::decode("0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004").unwrap();
        assert_eq!(&sha3_384_hash(b"")[..], expected.as_slice());
    }

    #[test]
    fn output_is_48_bytes() {
        assert_eq!(sha3_384_hash(b"sophis").len(), 48);
    }
}
