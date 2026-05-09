//! Fingerprint computation per `wallet/descriptors/DESIGN.md` D4.
//!
//! K3.2 is the full implementation + tests; this module is established in K3.1
//! with the type and stub function so dependent modules (`types`, `parse`)
//! can compile.

use sophis_wallet_pskt::crypto::DilithiumPubKey;

/// 4-byte fingerprint identifying a Dilithium verification key.
///
/// Encoded textually as 8 lowercase hex characters in descriptor key-origin
/// blocks (`[fingerprint/derivation/path]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint(pub [u8; 4]);

impl Fingerprint {
    /// Construct from raw bytes.
    pub const fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    /// Borrow the 4 raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Encode as 8 lowercase hex characters (the canonical textual form).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from 8-character hex string. Case-insensitive at parse time;
    /// returns `None` if length != 8 or input contains non-hex characters.
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 8 {
            return None;
        }
        let bytes = hex::decode(s).ok()?;
        let arr: [u8; 4] = bytes.try_into().ok()?;
        Some(Self(arr))
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Compute the canonical SHA3-384[..4] fingerprint of a Dilithium verification key.
///
/// This is the source-of-truth implementation. K3.2 adds canonical test vectors.
pub fn fingerprint(vk: &DilithiumPubKey) -> Fingerprint {
    use sha3::{Digest, Sha3_384};
    let hash = Sha3_384::digest(vk.as_bytes());
    let mut fp = [0u8; 4];
    fp.copy_from_slice(&hash[..4]);
    Fingerprint(fp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sophis_wallet_pskt::crypto::DILITHIUM44_VK_SIZE;

    #[test]
    fn fingerprint_is_deterministic() {
        let vk = DilithiumPubKey::from_bytes([0u8; DILITHIUM44_VK_SIZE]);
        let fp1 = fingerprint(&vk);
        let fp2 = fingerprint(&vk);
        assert_eq!(fp1, fp2, "Same input must produce same fingerprint");
    }

    #[test]
    fn fingerprint_differs_for_different_keys() {
        let vk_a = DilithiumPubKey::from_bytes([0u8; DILITHIUM44_VK_SIZE]);
        let mut b_bytes = [0u8; DILITHIUM44_VK_SIZE];
        b_bytes[0] = 1;
        let vk_b = DilithiumPubKey::from_bytes(b_bytes);
        assert_ne!(fingerprint(&vk_a), fingerprint(&vk_b));
    }

    #[test]
    fn fingerprint_hex_roundtrip() {
        let fp = Fingerprint::from_bytes([0xab, 0xcd, 0x12, 0x34]);
        let hex = fp.to_hex();
        assert_eq!(hex, "abcd1234");
        let parsed = Fingerprint::from_hex(&hex).expect("valid hex");
        assert_eq!(parsed, fp);
    }

    #[test]
    fn fingerprint_hex_rejects_wrong_length() {
        assert!(Fingerprint::from_hex("abcd").is_none()); // too short
        assert!(Fingerprint::from_hex("abcd1234ef").is_none()); // too long
    }

    #[test]
    fn fingerprint_hex_rejects_non_hex_chars() {
        assert!(Fingerprint::from_hex("xyz12345").is_none());
    }
}
