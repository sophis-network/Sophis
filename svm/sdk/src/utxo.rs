use borsh::{BorshDeserialize, BorshSerialize};

/// Borsh-compatible mirror of `sophis_consensus_core::tx::ScriptPublicKey`.
///
/// The binary layout matches exactly: `u16` version + `Vec<u8>` script
/// (4-byte LE length prefix then bytes), which is how the consensus type serialises.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ScriptPublicKey {
    pub version: u16,
    pub script: Vec<u8>,
}

/// Borsh-compatible mirror of `sophis_consensus_core::tx::UtxoEntry`.
///
/// Received from [`crate::Env::input_utxo`].
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct UtxoEntry {
    pub amount: u64,
    pub script_public_key: ScriptPublicKey,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
}

/// Borsh-compatible mirror of `sophis_consensus_core::tx::TransactionOutput`.
///
/// Received from [`crate::Env::output_utxo`].
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct TxOutput {
    pub value: u64,
    pub script_public_key: ScriptPublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utxo_entry_roundtrip() {
        let entry = UtxoEntry {
            amount: 100_000,
            script_public_key: ScriptPublicKey { version: 0, script: vec![0x20, 0xaa, 0xbb, 0xcc] },
            block_daa_score: 12345,
            is_coinbase: false,
        };
        let bytes = borsh::to_vec(&entry).unwrap();
        let decoded: UtxoEntry = borsh::from_slice(&bytes).unwrap();
        assert_eq!(decoded.amount, entry.amount);
        assert_eq!(decoded.script_public_key.version, 0);
        assert_eq!(decoded.script_public_key.script, vec![0x20, 0xaa, 0xbb, 0xcc]);
        assert_eq!(decoded.block_daa_score, 12345);
        assert!(!decoded.is_coinbase);
    }

    #[test]
    fn tx_output_roundtrip() {
        let out = TxOutput { value: 9_876_543, script_public_key: ScriptPublicKey { version: 0, script: vec![0x20, 0x11, 0x22] } };
        let bytes = borsh::to_vec(&out).unwrap();
        let decoded: TxOutput = borsh::from_slice(&bytes).unwrap();
        assert_eq!(decoded.value, 9_876_543);
        assert_eq!(decoded.script_public_key.script, vec![0x20, 0x11, 0x22]);
    }

    #[test]
    fn coinbase_entry_roundtrip() {
        let entry = UtxoEntry {
            amount: 5_000_000_000,
            script_public_key: ScriptPublicKey { version: 0, script: vec![] },
            block_daa_score: 0,
            is_coinbase: true,
        };
        let bytes = borsh::to_vec(&entry).unwrap();
        let decoded: UtxoEntry = borsh::from_slice(&bytes).unwrap();
        assert!(decoded.is_coinbase);
        assert_eq!(decoded.amount, 5_000_000_000);
    }
}
