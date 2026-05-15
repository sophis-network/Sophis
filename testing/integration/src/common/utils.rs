use super::client::ListeningClient;
use itertools::Itertools;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use sophis_addresses::Address;
use sophis_consensus_core::{
    constants::TX_VERSION,
    hashing::sighash_type::SIG_HASH_ALL,
    header::Header,
    sign::sign_input_dilithium,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        MutableTransaction, ScriptPublicKey, SignableTransaction, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry,
    },
    utxo::{
        utxo_collection::{UtxoCollection, UtxoCollectionExtensions},
        utxo_diff::UtxoDiff,
    },
};
use sophis_core::info;
use sophis_grpc_client::GrpcClient;
use sophis_rpc_core::{BlockAddedNotification, Notification, RpcUtxoEntry, VirtualDaaScoreChangedNotification, api::rpc::RpcApi};
use sophis_txscript::{
    pay_to_address_script,
    standard::{dilithium_redeem_script, pay_to_script_hash_signature_script},
};
use std::{
    collections::{HashMap, HashSet, hash_map::Entry::Occupied},
    future::Future,
    sync::Arc,
    time::Duration,
};
use tokio::time::timeout;

pub(crate) const EXPAND_FACTOR: u64 = 1;
pub(crate) const CONTRACT_FACTOR: u64 = 1;

const fn estimated_mass(num_inputs: usize, num_outputs: u64) -> u64 {
    200 + 34 * num_outputs + 1000 * (num_inputs as u64)
}

pub const fn required_fee(num_inputs: usize, num_outputs: u64) -> u64 {
    const FEE_RATE: u64 = 10;
    FEE_RATE * estimated_mass(num_inputs, num_outputs)
}

/// Builds a TX DAG based on the initial UTXO set and on constant params.
/// NOTE: transactions are unsigned (signature_script = []); Dilithium signing
/// integration is pending.
pub fn generate_tx_dag(
    mut utxoset: UtxoCollection,
    spk: ScriptPublicKey,
    target_levels: usize,
    target_width: usize,
) -> Vec<Arc<Transaction>> {
    let num_inputs = CONTRACT_FACTOR as usize;
    let num_outputs = EXPAND_FACTOR;

    let mut txs = Vec::with_capacity(target_levels * target_width);

    for i in 0..target_levels {
        let mut utxo_diff = UtxoDiff::default();
        utxoset
            .iter()
            .take(num_inputs * target_width)
            .chunks(num_inputs)
            .into_iter()
            .map(|c| c.into_iter().map(|(o, e)| (TransactionInput::new(*o, vec![], 0, 1), e.clone())).unzip())
            .collect::<Vec<(Vec<_>, Vec<_>)>>()
            .into_par_iter()
            .map(|(inputs, entries)| {
                let total_in = entries.iter().map(|e| e.amount).sum::<u64>();
                let total_out = total_in - required_fee(num_inputs, num_outputs);
                let outputs = (0..num_outputs)
                    .map(|_| TransactionOutput { value: total_out / num_outputs, script_public_key: spk.clone() })
                    .collect_vec();
                // Unsigned — signature_script = [] (Dilithium signing pending)
                let tx = Transaction::new(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
                SignableTransaction::with_entries(tx, entries)
            })
            .collect::<Vec<_>>()
            .into_iter()
            .for_each(|signable_tx: SignableTransaction| {
                utxo_diff.add_transaction(&signable_tx.as_verifiable(), 0).unwrap();
                txs.push(Arc::new(signable_tx.tx));
            });
        utxoset.remove_collection(&utxo_diff.remove);
        utxoset.add_collection(&utxo_diff.add);

        if i % (target_levels / 10).max(1) == 0 {
            info!("Generated {} txs", txs.len());
        }
    }

    txs
}

/// Sanity test verifying that the generated TX DAG is valid, topologically ordered and has no double spends
pub fn verify_tx_dag(initial_utxoset: &UtxoCollection, txs: &[Arc<Transaction>]) {
    let mut prev_txs: HashMap<TransactionId, Arc<Transaction>> = HashMap::new();
    let mut used_outpoints = HashSet::with_capacity(txs.len() * 2);
    for tx in txs.iter() {
        for input in tx.inputs.iter() {
            assert!(used_outpoints.insert(input.previous_outpoint));
            if let Occupied(e) = prev_txs.entry(input.previous_outpoint.transaction_id) {
                assert!(e.get().outputs.len() > input.previous_outpoint.index as usize);
            } else {
                assert!(initial_utxoset.contains_key(&input.previous_outpoint));
            }
        }
        assert!(prev_txs.insert(tx.id(), tx.clone()).is_none());
    }
}

pub async fn wait_for<Fut>(sleep_millis: u64, max_iterations: u64, success: impl Fn() -> Fut, panic_message: &'static str)
where
    Fut: Future<Output = bool>,
{
    let mut i: u64 = 0;
    loop {
        i += 1;
        tokio::time::sleep(Duration::from_millis(sleep_millis)).await;
        if success().await {
            break;
        } else if i >= max_iterations {
            panic!("{}", panic_message);
        }
    }
}

/// Generates a Dilithium-signed transaction spending the supplied UTXOs to
/// `output_address`. Each input is signed with `signing_key` against the
/// caller's `verification_key` (1312-byte ML-DSA-44 VK); the resulting
/// `signature_script` is a P2SH redeem-script reveal + Dilithium signature
/// matching `dilithium_redeem_script(verification_key)`. The transaction is
/// returned non-finalized; callers serialize via `.into()` for RPC submit.
///
/// Audit/F-20 (Session 6, 2026-05-14): rewritten to actually sign with
/// Dilithium; the previous unsigned form (signature_script = []) was a
/// Schnorr-era holdover that the post-pivot strict-mempool rejects with
/// `failed to verify empty signature script. Inner error: opcode requires
/// at least 1 but stack has only 0`.
pub fn generate_tx(
    utxos: &[(TransactionOutpoint, UtxoEntry)],
    amount: u64,
    num_outputs: u64,
    output_address: &Address,
    signing_key: &[u8; 2560],
    verification_key: &[u8; 1312],
) -> Transaction {
    let total_in = utxos.iter().map(|x| x.1.amount).sum::<u64>();
    assert!(amount <= total_in - required_fee(utxos.len(), num_outputs));
    let script_public_key = pay_to_address_script(output_address);
    let inputs = utxos
        .iter()
        .map(|(op, _)| TransactionInput { previous_outpoint: *op, signature_script: vec![], sequence: 0, sig_op_count: 1 })
        .collect_vec();

    let outputs = (0..num_outputs)
        .map(|_| TransactionOutput { value: amount / num_outputs, script_public_key: script_public_key.clone() })
        .collect_vec();
    let unsigned = Transaction::new_non_finalized(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let entries: Vec<UtxoEntry> = utxos.iter().map(|(_, e)| e.clone()).collect();
    let mut mutable = MutableTransaction::with_entries(unsigned, entries);
    let redeem = dilithium_redeem_script(verification_key).expect("dilithium_redeem_script");
    for i in 0..mutable.tx.inputs.len() {
        let sig = sign_input_dilithium(&mutable.as_verifiable(), i, signing_key, SIG_HASH_ALL).expect("sign_input_dilithium");
        mutable.tx.inputs[i].signature_script = pay_to_script_hash_signature_script(redeem.clone(), sig).expect("p2sh sig script");
    }
    // Recompute cached `id` over the now-signed tx so `tx.id()` matches the
    // daemon-side hashing::tx::id() that the mempool indexer keys on.
    mutable.tx.finalize();
    mutable.tx
}

pub async fn fetch_spendable_utxos(
    client: &GrpcClient,
    address: Address,
    coinbase_maturity: u64,
) -> Vec<(TransactionOutpoint, UtxoEntry)> {
    let resp = client.get_utxos_by_addresses(vec![address.clone()]).await.unwrap();
    let virtual_daa_score = client.get_server_info().await.unwrap().virtual_daa_score;
    let mut utxos = Vec::with_capacity(resp.len());
    // Audit/F-19 (Session 5, 2026-05-14): script-space equivalence — `address`
    // and `resp_entry.address` may have *different version shapes* (e.g., caller
    // passed `Version::PubKeyDilithium` but the indexer stores the canonical
    // `Version::ScriptHash` representation of the same pay_to_address_script).
    // The downstream caller's invariant is that the UTXO's `script_public_key`
    // matches what the address would produce, not that the address strings
    // serialize identically. Compare via `pay_to_address_script` to bridge the
    // shape gap.
    let expected_spk = sophis_txscript::standard::pay_to_address_script(&address);
    for resp_entry in
        resp.into_iter().filter(|resp_entry| is_utxo_spendable(&resp_entry.utxo_entry, virtual_daa_score, coinbase_maturity))
    {
        assert!(resp_entry.address.is_some());
        let returned_addr = resp_entry.address.as_ref().unwrap();
        let returned_spk = sophis_txscript::standard::pay_to_address_script(returned_addr);
        assert_eq!(
            returned_spk, expected_spk,
            "F-19: indexer returned an address whose pay_to_address_script differs from the queried address — returned={returned_addr:?}, queried={address:?}"
        );
        utxos.push((TransactionOutpoint::from(resp_entry.outpoint), UtxoEntry::from(resp_entry.utxo_entry)));
    }
    utxos.sort_by(|a, b| b.1.amount.cmp(&a.1.amount));
    utxos
}

pub fn is_utxo_spendable(entry: &RpcUtxoEntry, virtual_daa_score: u64, coinbase_maturity: u64) -> bool {
    let needed_confirmations = if !entry.is_coinbase { 10 } else { coinbase_maturity };
    entry.block_daa_score + needed_confirmations <= virtual_daa_score
}

pub async fn mine_block(pay_address: Address, submitting_client: &GrpcClient, listening_clients: &[ListeningClient]) {
    // Discard all unreceived block added notifications in each listening client
    listening_clients.iter().for_each(|x| x.block_added_listener().unwrap().drain());

    // Mine a block
    let template = submitting_client.get_block_template(pay_address.clone(), vec![]).await.unwrap();
    let header: Header = (&template.block.header).try_into().unwrap();
    let block_hash = header.hash;
    submitting_client.submit_block(template.block, false).await.unwrap();

    let timeout_duration = Duration::from_millis(10_000);

    // Wait for each listening client to get notified the submitted block was added to the DAG
    for client in listening_clients.iter() {
        let block_daa_score: u64 =
            match timeout(timeout_duration, client.block_added_listener().unwrap().receiver.recv()).await.unwrap().unwrap() {
                Notification::BlockAdded(BlockAddedNotification { block }) => {
                    assert_eq!(block.header.hash, block_hash);
                    block.header.daa_score
                }
                _ => panic!("wrong notification type"),
            };
        match timeout(timeout_duration, client.virtual_daa_score_changed_listener().unwrap().receiver.recv()).await.unwrap().unwrap() {
            Notification::VirtualDaaScoreChanged(VirtualDaaScoreChangedNotification { virtual_daa_score }) => {
                assert_eq!(virtual_daa_score, block_daa_score + 1);
            }
            _ => panic!("wrong notification type"),
        }
    }
}
