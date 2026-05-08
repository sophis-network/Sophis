pub mod error;
pub mod merkle;
pub mod types;

pub use error::RollupError;
pub use merkle::{compute_state_root, sort_utxos};
pub use types::{hash_withdrawals, *};

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_addr() -> L2Address {
        L2Address([7u8; 48])
    }

    fn make_utxo(txid_byte: u8, idx: u32, amount: u64) -> L2Utxo {
        let mut txid = [0u8; 32];
        txid[0] = txid_byte;
        L2Utxo { id: L2UtxoId { txid, index: idx }, address: dummy_addr(), amount }
    }

    #[test]
    fn l2_address_from_verkey_is_48_bytes() {
        let vk = [0u8; 1312];
        let addr = L2Address::from_verkey(&vk);
        assert_eq!(addr.0.len(), 48);
    }

    #[test]
    fn batch_hash_is_deterministic() {
        let batch = Batch {
            sequence: 1,
            l1_anchor_block: 42,
            prev_state_root: StateRoot::default(),
            txs: vec![],
            deposits: vec![],
            withdrawals: vec![],
        };
        assert_eq!(batch.hash(), batch.hash());
    }

    #[test]
    fn tx_sig_hash_excludes_signatures() {
        let body = L2TxBody {
            input_utxo_ids: vec![L2UtxoId { txid: [1u8; 32], index: 0 }],
            outputs: vec![L2TxOutput { address: dummy_addr(), amount: 500 }],
            fee: 10,
        };
        let tx1 = L2Tx {
            body: body.clone(),
            inputs: vec![L2TxInput {
                utxo_id: L2UtxoId { txid: [1u8; 32], index: 0 },
                verification_key: Box::new([0u8; 1312]),
                signature: Box::new([1u8; 2420]),
            }],
        };
        let tx2 = L2Tx {
            body: body.clone(),
            inputs: vec![L2TxInput {
                utxo_id: L2UtxoId { txid: [1u8; 32], index: 0 },
                verification_key: Box::new([0u8; 1312]),
                signature: Box::new([2u8; 2420]), // different sig
            }],
        };
        // sig_hash must be identical regardless of the actual signature bytes
        assert_eq!(tx1.sig_hash(), tx2.sig_hash());
        // but txid must differ (includes signature)
        assert_ne!(tx1.txid(), tx2.txid());
    }

    #[test]
    fn utxo_borsh_roundtrip() {
        let u = make_utxo(5, 3, 1_000_000);
        let encoded = borsh::to_vec(&u).unwrap();
        let decoded: L2Utxo = borsh::from_slice(&encoded).unwrap();
        assert_eq!(decoded.id, u.id);
        assert_eq!(decoded.amount, u.amount);
    }

    #[test]
    fn batch_journal_borsh_roundtrip() {
        let j = BatchJournal {
            sequence: 7,
            prev_state_root: StateRoot::default(),
            new_state_root: StateRoot([1u8; 48]),
            batch_hash: [2u8; 32],
            deposit_count: 3,
            withdrawal_count: 1,
            withdrawals_hash: [0u8; 48],
            l1_anchor_block: 100,
            da_bundle_id: [3u8; 48],
        };
        let encoded = borsh::to_vec(&j).unwrap();
        let decoded: BatchJournal = borsh::from_slice(&encoded).unwrap();
        assert_eq!(decoded.sequence, 7);
        assert_eq!(decoded.deposit_count, 3);
        assert_eq!(decoded.da_bundle_id, [3u8; 48]);
    }
}
