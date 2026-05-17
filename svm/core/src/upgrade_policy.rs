use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// ML-DSA-44 verification key (1312 bytes per FIPS 204 §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DilithiumPublicKey(pub [u8; 1312]);

impl BorshSerialize for DilithiumPublicKey {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        w.write_all(&self.0)
    }
}

impl BorshDeserialize for DilithiumPublicKey {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let mut arr = [0u8; 1312];
        r.read_exact(&mut arr)?;
        Ok(DilithiumPublicKey(arr))
    }
}

impl Serialize for DilithiumPublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for DilithiumPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = <Vec<u8> as serde::Deserialize>::deserialize(d)?;
        if bytes.len() != 1312 {
            return Err(serde::de::Error::invalid_length(bytes.len(), &"1312 bytes for ML-DSA-44 public key"));
        }
        let mut arr = [0u8; 1312];
        arr.copy_from_slice(&bytes);
        Ok(DilithiumPublicKey(arr))
    }
}

/// Minimum timelock enforced by the protocol — not bypassable by the contract owner.
/// ~17 minutes at 10 BPS. Users always have an exit window during this period.
pub const UPGRADE_MIN_BLOCKS: u64 = 10_000;

/// Maximum number of keys in a MultisigTimelock upgrade policy.
/// Dilithium keys are 1312 bytes each; 16 keys = ~21 KiB, a reasonable on-chain limit.
pub const MAX_MULTISIG_KEYS: usize = 16;

/// Upgrade policy declared by a contract at deploy time.
/// Migrations are explicit on-chain transactions — no silent upgrades (unlike EVM proxies).
/// Protocol contracts (token policies, Transfer Policy of SOF) must be Immutable.
/// L1 core upgrades via sophisd hard fork — not via this policy.
// Variants differ by ~1.3 KiB (a single Dilithium pubkey). Boxing would require
// every construction site to wrap in Box<>; the cost is paid once per contract deploy,
// so the size disparity is acceptable.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub enum UpgradePolicy {
    Immutable,
    OwnerTimelock {
        owner_pk: DilithiumPublicKey,
        /// Must be >= UPGRADE_MIN_BLOCKS; validated at deploy time.
        min_blocks: u64,
    },
    MultisigTimelock {
        threshold: u8,
        keys: Vec<DilithiumPublicKey>,
        /// Must be >= UPGRADE_MIN_BLOCKS; validated at deploy time.
        min_blocks: u64,
    },
}

impl UpgradePolicy {
    pub fn min_blocks(&self) -> Option<u64> {
        match self {
            Self::Immutable => None,
            Self::OwnerTimelock { min_blocks, .. } => Some(*min_blocks),
            Self::MultisigTimelock { min_blocks, .. } => Some(*min_blocks),
        }
    }

    pub fn is_valid(&self) -> bool {
        match self {
            Self::Immutable => true,
            Self::OwnerTimelock { min_blocks, .. } => *min_blocks >= UPGRADE_MIN_BLOCKS,
            Self::MultisigTimelock { threshold, keys, min_blocks } => {
                let n = keys.len();
                *min_blocks >= UPGRADE_MIN_BLOCKS && *threshold > 0 && n > 0 && n <= MAX_MULTISIG_KEYS && (*threshold as usize) <= n
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(b: u8) -> DilithiumPublicKey {
        DilithiumPublicKey([b; 1312])
    }

    #[test]
    fn dilithium_pubkey_borsh_roundtrip() {
        let k = pk(0xab);
        let bytes = borsh::to_vec(&k).unwrap();
        assert_eq!(bytes.len(), 1312);
        let back: DilithiumPublicKey = borsh::from_slice(&bytes).unwrap();
        assert_eq!(back, k);
    }

    #[test]
    fn dilithium_pubkey_serde_json_roundtrip() {
        let k = pk(0x42);
        let j = serde_json::to_string(&k).unwrap();
        let back: DilithiumPublicKey = serde_json::from_str(&j).unwrap();
        assert_eq!(back, k);
    }

    #[test]
    fn dilithium_pubkey_serde_rejects_wrong_length() {
        let err = serde_json::from_str::<DilithiumPublicKey>("[1,2,3]");
        assert!(err.is_err(), "must reject a byte vec whose length != 1312");
    }

    #[test]
    fn min_blocks_per_variant() {
        assert_eq!(UpgradePolicy::Immutable.min_blocks(), None);
        assert_eq!(UpgradePolicy::OwnerTimelock { owner_pk: pk(1), min_blocks: 12_345 }.min_blocks(), Some(12_345));
        assert_eq!(
            UpgradePolicy::MultisigTimelock { threshold: 2, keys: vec![pk(1), pk(2)], min_blocks: 99_999 }.min_blocks(),
            Some(99_999)
        );
    }

    #[test]
    fn is_valid_immutable_and_owner_timelock() {
        assert!(UpgradePolicy::Immutable.is_valid());
        assert!(UpgradePolicy::OwnerTimelock { owner_pk: pk(1), min_blocks: UPGRADE_MIN_BLOCKS }.is_valid());
        assert!(!UpgradePolicy::OwnerTimelock { owner_pk: pk(1), min_blocks: UPGRADE_MIN_BLOCKS - 1 }.is_valid());
    }

    #[test]
    fn is_valid_multisig_timelock_branches() {
        let ok = UpgradePolicy::MultisigTimelock { threshold: 2, keys: vec![pk(1), pk(2), pk(3)], min_blocks: UPGRADE_MIN_BLOCKS };
        assert!(ok.is_valid());

        // min_blocks too low
        assert!(!UpgradePolicy::MultisigTimelock { threshold: 1, keys: vec![pk(1)], min_blocks: UPGRADE_MIN_BLOCKS - 1 }.is_valid());
        // threshold == 0
        assert!(!UpgradePolicy::MultisigTimelock { threshold: 0, keys: vec![pk(1)], min_blocks: UPGRADE_MIN_BLOCKS }.is_valid());
        // no keys
        assert!(!UpgradePolicy::MultisigTimelock { threshold: 1, keys: vec![], min_blocks: UPGRADE_MIN_BLOCKS }.is_valid());
        // threshold > n
        assert!(
            !UpgradePolicy::MultisigTimelock { threshold: 3, keys: vec![pk(1), pk(2)], min_blocks: UPGRADE_MIN_BLOCKS }.is_valid()
        );
        // too many keys (> MAX_MULTISIG_KEYS)
        let many: Vec<DilithiumPublicKey> = (0..(MAX_MULTISIG_KEYS as u32 + 1)).map(|i| pk(i as u8)).collect();
        assert!(!UpgradePolicy::MultisigTimelock { threshold: 1, keys: many, min_blocks: UPGRADE_MIN_BLOCKS }.is_valid());
    }

    #[test]
    fn upgrade_policy_borsh_roundtrip_all_variants() {
        for p in [
            UpgradePolicy::Immutable,
            UpgradePolicy::OwnerTimelock { owner_pk: pk(7), min_blocks: UPGRADE_MIN_BLOCKS },
            UpgradePolicy::MultisigTimelock { threshold: 2, keys: vec![pk(1), pk(2)], min_blocks: UPGRADE_MIN_BLOCKS },
        ] {
            let bytes = borsh::to_vec(&p).unwrap();
            let back: UpgradePolicy = borsh::from_slice(&bytes).unwrap();
            assert_eq!(back.min_blocks(), p.min_blocks());
            assert_eq!(back.is_valid(), p.is_valid());
        }
    }
}
