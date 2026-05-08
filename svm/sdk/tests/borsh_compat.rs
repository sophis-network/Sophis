/// Verifies that SDK utxo types deserialise identically to consensus-core types.
///
/// The sVM host serialises `UtxoEntry` / `TransactionOutput` from consensus-core
/// and passes the bytes into WASM memory.  SDK contracts then deserialise them.
/// This test pins that round-trip so a layout change is caught immediately.
use smallvec::smallvec;
use sophis_consensus_core::tx::{ScriptPublicKey as ConsensusSpk, TransactionOutput as ConsensusTxOut, UtxoEntry as ConsensusEntry};
use sophis_sdk::utxo::{TxOutput, UtxoEntry};

#[test]
fn utxo_entry_layout_matches_consensus() {
    let consensus = ConsensusEntry {
        amount: 12_345_678,
        script_public_key: ConsensusSpk::new(0, smallvec![0x20, 0xaa, 0xbb, 0xcc, 0xdd]),
        block_daa_score: 9_999,
        is_coinbase: false,
    };
    let bytes = borsh::to_vec(&consensus).unwrap();
    let sdk: UtxoEntry = borsh::from_slice(&bytes).unwrap();

    assert_eq!(sdk.amount, 12_345_678);
    assert_eq!(sdk.script_public_key.version, 0);
    assert_eq!(sdk.script_public_key.script, vec![0x20, 0xaa, 0xbb, 0xcc, 0xdd]);
    assert_eq!(sdk.block_daa_score, 9_999);
    assert!(!sdk.is_coinbase);
}

#[test]
fn coinbase_entry_layout_matches_consensus() {
    let consensus = ConsensusEntry {
        amount: 5_000_000_000,
        script_public_key: ConsensusSpk::new(0, smallvec![]),
        block_daa_score: 0,
        is_coinbase: true,
    };
    let bytes = borsh::to_vec(&consensus).unwrap();
    let sdk: UtxoEntry = borsh::from_slice(&bytes).unwrap();

    assert!(sdk.is_coinbase);
    assert_eq!(sdk.amount, 5_000_000_000);
    assert!(sdk.script_public_key.script.is_empty());
}

#[test]
fn tx_output_layout_matches_consensus() {
    let consensus = ConsensusTxOut { value: 7_777_777, script_public_key: ConsensusSpk::new(0, smallvec![0x20, 0x11, 0x22, 0x33]) };
    let bytes = borsh::to_vec(&consensus).unwrap();
    let sdk: TxOutput = borsh::from_slice(&bytes).unwrap();

    assert_eq!(sdk.value, 7_777_777);
    assert_eq!(sdk.script_public_key.script, vec![0x20, 0x11, 0x22, 0x33]);
}

#[test]
fn script_version_preserved() {
    let consensus = ConsensusEntry {
        amount: 1,
        script_public_key: ConsensusSpk::new(1, smallvec![0xde, 0xad]),
        block_daa_score: 0,
        is_coinbase: false,
    };
    let bytes = borsh::to_vec(&consensus).unwrap();
    let sdk: UtxoEntry = borsh::from_slice(&bytes).unwrap();
    assert_eq!(sdk.script_public_key.version, 1);
    assert_eq!(sdk.script_public_key.script, vec![0xde, 0xad]);
}
