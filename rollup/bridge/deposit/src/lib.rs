use borsh::{BorshDeserialize, BorshSerialize};

/// Script version for bridge vault UTXOs.
/// The sVM runtime dispatches to `sophis-bridge-withdrawal` when spending
/// a UTXO with this version.
pub const BRIDGE_VAULT_VERSION: u16 = 3;

/// Script version for the withdrawal claim UTXO (input 1 in a release tx).
pub const BRIDGE_CLAIM_VERSION: u16 = 4;

/// Metadata embedded in the `script_public_key.script` of a bridge vault UTXO.
///
/// ## How a deposit works
///
/// 1. User creates an L1 tx:
///    - Input: SPHS to lock
///    - Output 0: UTXO with `script_public_key.version = BRIDGE_VAULT_VERSION`,
///      `script = borsh(DepositRecord { l2_address, amount })`, `value = amount`
///    - Output 1+: change
///
/// 2. Sequencer polls UTXOs with `BRIDGE_VAULT_VERSION`, reads `DepositRecord`,
///    and verifies `utxo.amount == record.amount` before including as a `Deposit`
///    in the next batch.
///
/// 3. Guest mints a new L2 UTXO at `l2_address` with `amount` sompi.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DepositRecord {
    /// SHA3-384 of the L2 Dilithium verification key (derivation path m/44'/111111'/0'/1/0).
    pub l2_address: [u8; 48],
    /// Amount in sompi (must equal the vault UTXO's `value` field).
    pub amount: u64,
}

impl DepositRecord {
    pub fn new(l2_address: [u8; 48], amount: u64) -> Self {
        Self { l2_address, amount }
    }

    pub fn validate(&self) -> bool {
        self.amount > 0
    }

    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).unwrap_or_default()
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        borsh::from_slice(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let r = DepositRecord::new([7u8; 48], 5_000_000_000);
        let enc = r.encode();
        let dec = DepositRecord::decode(&enc).unwrap();
        assert_eq!(dec, r);
    }

    #[test]
    fn zero_amount_invalid() {
        assert!(!DepositRecord::new([0u8; 48], 0).validate());
    }

    #[test]
    fn nonzero_amount_valid() {
        assert!(DepositRecord::new([0u8; 48], 1).validate());
    }

    #[test]
    fn bad_bytes_decode_none() {
        assert!(DepositRecord::decode(b"garbage").is_none());
    }

    #[test]
    fn constants_are_distinct() {
        assert_ne!(BRIDGE_VAULT_VERSION, BRIDGE_CLAIM_VERSION);
    }
}
