//! Production gRPC submit (sub-fase 5.4.f.1).
//!
//! Mirrors `rollup/sequencer/src/l1_client.rs::GrpcL1Client` with a
//! simpler tx layout: ONE transaction per bundle.
//!
//!   Inputs:  [0..N]  relayer's spendable Dilithium P2SH UTXOs (fee)
//!   Outputs: [0]     ORACLE_INVOKE_VERSION SPK with encode_wire bytes,
//!                    value = INVOCATION_UTXO_VALUE sompi
//!            [1]     change back to relayer (P2SH Dilithium), if > 0
//!
//! No prep tx needed — the rollup needs one because the state UTXO
//! requires a separate Submission UTXO input; the oracle contract reads
//! the invocation directly from output [0]'s SPK script field.
//!
//! Connection model: fresh `GrpcClient::connect_with_args` per call.
//! One call per `daemon.interval_secs` (>= 30s typical) is not
//! latency-sensitive, and avoids long-lived connection state.

use sophis_addresses::Prefix;
use sophis_consensus_core::{
    constants::TX_VERSION,
    hashing::sighash_type::SIG_HASH_ALL,
    sign::sign_input_dilithium,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{MutableTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry},
};
use sophis_grpc_client::GrpcClient;
use sophis_notify::subscription::context::SubscriptionContext;
use sophis_oracle_core::ORACLE_INVOKE_VERSION;
use sophis_rpc_core::{
    api::rpc::RpcApi,
    model::{RpcTransaction, RpcTransactionInput, RpcTransactionOutput},
    notify::mode::NotificationMode,
};
use sophis_txscript::standard::{
    dilithium_address, dilithium_redeem_script, pay_to_address_script, pay_to_script_hash_signature_script,
};

use crate::pipeline::RelayerBundle;
use crate::sign::{SignedBundle, sign_bundle};
use crate::submit::{
    COINBASE_MATURITY_DEVNET, GRPC_CONNECT_TIMEOUT_MS, GrpcSubmit, INVOCATION_UTXO_VALUE, NON_COINBASE_MATURITY, SUBMIT_TX_FEE,
    SubmitError,
};

/// Top-level submit driver invoked by `<GrpcSubmit as L1Submit>::submit_bundle`.
///
/// 1. Sign the bundle and encode the wire payload.
/// 2. Connect to sophisd via gRPC.
/// 3. Fetch DAA score + relayer's spendable fee UTXOs.
/// 4. Build and Dilithium-sign the invocation tx.
/// 5. Submit and return the resulting txid.
pub async fn submit_bundle_grpc(submit: &GrpcSubmit, bundle: &RelayerBundle) -> Result<[u8; 32], SubmitError> {
    // Sign + encode (no I/O).
    let signature = sign_bundle(bundle, &submit.key)?;
    let signed = SignedBundle { bundle: bundle.clone(), signature, verification_key: submit.key.verification_key.clone() };
    let wire = signed.encode_wire()?;

    // Connect.
    let rpc = connect(&submit.endpoint).await?;

    // Determine the relayer's L1 address from the configured network prefix.
    let prefix = parse_prefix(&submit.network_prefix)?;
    let relayer_addr = dilithium_address(&submit.key.verification_key, prefix)
        .map_err(|e| SubmitError::BadAddress(format!("dilithium_address: {e}")))?;

    // Fetch DAA + UTXOs.
    let dag_info = rpc.get_block_dag_info().await.map_err(|e| SubmitError::Transport(format!("get_block_dag_info: {e}")))?;
    let daa_score = dag_info.virtual_daa_score;

    let raw_utxos = rpc
        .get_utxos_by_addresses(vec![relayer_addr.clone()])
        .await
        .map_err(|e| SubmitError::Transport(format!("get_utxos_by_addresses: {e}")))?;

    let mut fee_utxos: Vec<(TransactionOutpoint, UtxoEntry)> = raw_utxos
        .into_iter()
        .filter(|e| {
            let maturity = if e.utxo_entry.is_coinbase { COINBASE_MATURITY_DEVNET } else { NON_COINBASE_MATURITY };
            e.utxo_entry.block_daa_score + maturity < daa_score
        })
        .map(|e| (TransactionOutpoint::from(e.outpoint), UtxoEntry::from(e.utxo_entry)))
        .collect();

    if fee_utxos.is_empty() {
        return Err(SubmitError::NoSpendableUtxos);
    }
    // Prefer larger UTXOs first.
    fee_utxos.sort_by(|a, b| b.1.amount.cmp(&a.1.amount));
    let fee_utxo = fee_utxos.into_iter().next().unwrap();

    let required = INVOCATION_UTXO_VALUE + SUBMIT_TX_FEE;
    if fee_utxo.1.amount < required {
        return Err(SubmitError::InsufficientFunds { have: fee_utxo.1.amount, need: required });
    }
    let change = fee_utxo.1.amount - required;

    // Build SPKs.
    let invocation_spk = ScriptPublicKey::from_vec(ORACLE_INVOKE_VERSION, wire);
    let change_spk = pay_to_address_script(&relayer_addr);
    let redeem_script = dilithium_redeem_script(&submit.key.verification_key)
        .map_err(|e| SubmitError::BadAddress(format!("dilithium_redeem_script: {e}")))?;

    // Build + sign tx.
    let tx = build_signed_invocation_tx(&fee_utxo, change, invocation_spk, change_spk, &redeem_script, &submit.key.signing_key)?;

    // Submit.
    let txid = rpc
        .submit_transaction(consensus_tx_to_rpc(tx), false)
        .await
        .map_err(|e| SubmitError::Rejected(format!("submit_transaction: {e}")))?;

    let txid_bytes: [u8; 32] = txid.as_bytes();
    log::info!(
        "oracle invocation seq={} submitted to L1 (txid={}, daa={daa_score})",
        bundle.journal.sequence,
        hex::encode(txid_bytes),
    );
    Ok(txid_bytes)
}

/// Phase 6 — publish a single tx with V5 DA carriers (domain = Oracle)
/// for the signed bundle bytes. Mirrors `submit_bundle_grpc` but with:
///
///   Output[0..K]  V5 carrier outputs (value = 0), encode_bundle chunks
///   Output[K]     change to relayer (P2SH Dilithium), if > 0
///
/// Capped at 8 fragments (= 512 KiB calldata) per the design's
/// MAX_CARRIER_OUTPUTS_PER_TX. Larger blobs would need multi-tx
/// splitting (future enhancement).
pub async fn publish_carrier_grpc(submit: &GrpcSubmit, wire_bytes: &[u8], expected_bundle_id: [u8; 48]) -> Result<(), SubmitError> {
    use sophis_consensus_core::constants::SCRIPT_VERSION_CARRIER;
    use sophis_consensus_core::da::{CarrierDomain, MAX_CARRIER_OUTPUTS_PER_TX, encode_bundle};

    /// Conservative fee for the carrier tx. Larger than the invocation
    /// tx's SUBMIT_TX_FEE because carriers can carry up to 512 KiB.
    const CARRIER_TX_FEE: u64 = 50_000;

    // 1. Encode bundle and validate fragment count.
    let scripts = encode_bundle(wire_bytes, Some(CarrierDomain::Oracle))
        .map_err(|e| SubmitError::Serialization(format!("encode_bundle: {e}")))?;
    if scripts.len() > MAX_CARRIER_OUTPUTS_PER_TX {
        return Err(SubmitError::Serialization(format!(
            "calldata too large for a single carrier tx: {} fragments > MAX {}",
            scripts.len(),
            MAX_CARRIER_OUTPUTS_PER_TX
        )));
    }
    // 2. Defense in depth: every fragment must claim the expected bundle_id.
    for s in &scripts {
        if s.len() < 64 {
            return Err(SubmitError::Serialization("carrier script truncated below header".into()));
        }
        let claimed: [u8; 48] = s[16..64].try_into().expect("48 bytes");
        if claimed != expected_bundle_id {
            return Err(SubmitError::Serialization("carrier bundle_id mismatch with expected".into()));
        }
    }

    // 3. Connect + fetch UTXOs.
    let rpc = connect(&submit.endpoint).await?;
    let prefix = parse_prefix(&submit.network_prefix)?;
    let relayer_addr = dilithium_address(&submit.key.verification_key, prefix)
        .map_err(|e| SubmitError::BadAddress(format!("dilithium_address: {e}")))?;

    let dag_info = rpc.get_block_dag_info().await.map_err(|e| SubmitError::Transport(format!("get_block_dag_info: {e}")))?;
    let daa_score = dag_info.virtual_daa_score;

    let raw_utxos = rpc
        .get_utxos_by_addresses(vec![relayer_addr.clone()])
        .await
        .map_err(|e| SubmitError::Transport(format!("get_utxos_by_addresses: {e}")))?;
    let mut fee_utxos: Vec<(TransactionOutpoint, UtxoEntry)> = raw_utxos
        .into_iter()
        .filter(|e| {
            let maturity = if e.utxo_entry.is_coinbase { COINBASE_MATURITY_DEVNET } else { NON_COINBASE_MATURITY };
            e.utxo_entry.block_daa_score + maturity < daa_score
        })
        .map(|e| (TransactionOutpoint::from(e.outpoint), UtxoEntry::from(e.utxo_entry)))
        .collect();
    if fee_utxos.is_empty() {
        return Err(SubmitError::NoSpendableUtxos);
    }
    fee_utxos.sort_by(|a, b| b.1.amount.cmp(&a.1.amount));
    let fee_utxo = fee_utxos.into_iter().next().unwrap();

    if fee_utxo.1.amount < CARRIER_TX_FEE {
        return Err(SubmitError::InsufficientFunds { have: fee_utxo.1.amount, need: CARRIER_TX_FEE });
    }
    let change = fee_utxo.1.amount - CARRIER_TX_FEE;

    let redeem_script = dilithium_redeem_script(&submit.key.verification_key)
        .map_err(|e| SubmitError::BadAddress(format!("dilithium_redeem_script: {e}")))?;
    let change_spk = pay_to_address_script(&relayer_addr);

    // 4. Build outputs: V5 carriers (value=0) + change.
    let mut outputs: Vec<TransactionOutput> = scripts
        .into_iter()
        .map(|script| TransactionOutput { value: 0, script_public_key: ScriptPublicKey::from_vec(SCRIPT_VERSION_CARRIER, script) })
        .collect();
    if change > 0 {
        outputs.push(TransactionOutput { value: change, script_public_key: change_spk });
    }

    let inputs = vec![TransactionInput { previous_outpoint: fee_utxo.0, signature_script: vec![], sequence: 0, sig_op_count: 1 }];
    let unsigned = Transaction::new_non_finalized(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let entries = vec![fee_utxo.1.clone()];
    let mut mutable = MutableTransaction::with_entries(unsigned, entries);

    let sig = sign_input_dilithium(&mutable.as_verifiable(), 0, &submit.key.signing_key, SIG_HASH_ALL)
        .map_err(|e| SubmitError::BadAddress(format!("sign_input_dilithium: {e}")))?;
    mutable.tx.inputs[0].signature_script = pay_to_script_hash_signature_script(redeem_script, sig)
        .map_err(|e| SubmitError::BadAddress(format!("p2sh sig script: {e}")))?;

    let txid = rpc
        .submit_transaction(consensus_tx_to_rpc(mutable.tx), false)
        .await
        .map_err(|e| SubmitError::Rejected(format!("submit_transaction: {e}")))?;

    log::info!(
        "oracle DA carrier published (bundle_id={}, txid={}, daa={daa_score})",
        hex::encode(expected_bundle_id),
        hex::encode(txid.as_bytes()),
    );
    Ok(())
}

async fn connect(endpoint: &str) -> Result<GrpcClient, SubmitError> {
    let ctx = SubscriptionContext::new();
    GrpcClient::connect_with_args(
        NotificationMode::Direct,
        format!("grpc://{endpoint}"),
        Some(ctx),
        false, // no auto-reconnect
        None,  // no request timeout
        false, // no TLS
        Some(GRPC_CONNECT_TIMEOUT_MS),
        Default::default(),
    )
    .await
    .map_err(|e| SubmitError::Transport(format!("gRPC connect to {endpoint}: {e}")))
}

fn parse_prefix(s: &str) -> Result<Prefix, SubmitError> {
    match s.to_ascii_lowercase().as_str() {
        "mainnet" => Ok(Prefix::Mainnet),
        "testnet" => Ok(Prefix::Testnet),
        "devnet" => Ok(Prefix::Devnet),
        "simnet" => Ok(Prefix::Simnet),
        other => Err(SubmitError::BadAddress(format!("unknown network prefix {other:?}"))),
    }
}

fn build_signed_invocation_tx(
    fee_utxo: &(TransactionOutpoint, UtxoEntry),
    change: u64,
    invocation_spk: ScriptPublicKey,
    change_spk: ScriptPublicKey,
    redeem_script: &[u8],
    signing_key: &[u8; 2560],
) -> Result<Transaction, SubmitError> {
    let inputs = vec![TransactionInput { previous_outpoint: fee_utxo.0, signature_script: vec![], sequence: 0, sig_op_count: 1 }];
    let mut outputs = vec![TransactionOutput { value: INVOCATION_UTXO_VALUE, script_public_key: invocation_spk }];
    if change > 0 {
        outputs.push(TransactionOutput { value: change, script_public_key: change_spk });
    }

    let unsigned = Transaction::new_non_finalized(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let entries = vec![fee_utxo.1.clone()];
    let mut mutable = MutableTransaction::with_entries(unsigned, entries);

    let sig = sign_input_dilithium(&mutable.as_verifiable(), 0, signing_key, SIG_HASH_ALL)
        .map_err(|e| SubmitError::BadAddress(format!("sign_input_dilithium: {e}")))?;
    mutable.tx.inputs[0].signature_script = pay_to_script_hash_signature_script(redeem_script.to_vec(), sig)
        .map_err(|e| SubmitError::BadAddress(format!("p2sh sig script: {e}")))?;

    Ok(mutable.tx)
}

fn consensus_tx_to_rpc(tx: Transaction) -> RpcTransaction {
    RpcTransaction {
        version: tx.version,
        inputs: tx
            .inputs
            .into_iter()
            .map(|inp| RpcTransactionInput {
                previous_outpoint: inp.previous_outpoint.into(),
                signature_script: inp.signature_script,
                sequence: inp.sequence,
                sig_op_count: inp.sig_op_count,
                verbose_data: None,
            })
            .collect(),
        outputs: tx
            .outputs
            .into_iter()
            .map(|out| RpcTransactionOutput { value: out.value, script_public_key: out.script_public_key, verbose_data: None })
            .collect(),
        lock_time: tx.lock_time,
        subnetwork_id: tx.subnetwork_id,
        gas: tx.gas,
        payload: tx.payload,
        mass: 0,
        verbose_data: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_prefix_known_networks() {
        assert!(matches!(parse_prefix("mainnet").unwrap(), Prefix::Mainnet));
        assert!(matches!(parse_prefix("Testnet").unwrap(), Prefix::Testnet));
        assert!(matches!(parse_prefix("DEVNET").unwrap(), Prefix::Devnet));
        assert!(matches!(parse_prefix("simnet").unwrap(), Prefix::Simnet));
    }

    #[test]
    fn parse_prefix_rejects_unknown() {
        assert!(parse_prefix("foo").is_err());
    }
}
