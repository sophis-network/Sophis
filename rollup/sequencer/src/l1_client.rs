use async_trait::async_trait;
use borsh::BorshDeserialize;
use sophis_addresses::{Address, Prefix};
use sophis_consensus_core::{
    constants::TX_VERSION,
    hashing::sighash_type::SIG_HASH_ALL,
    sign::sign_input_dilithium,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
        UtxoEntry,
    },
};
use sophis_grpc_client::GrpcClient;
use sophis_notify::subscription::context::SubscriptionContext;
use sophis_rollup_verifier::{ROLLUP_STATE_VERSION, ROLLUP_SUBMISSION_VERSION, RollupState, RollupSubmission};
use sophis_rpc_core::{
    api::rpc::RpcApi,
    model::{RpcTransaction, RpcTransactionInput, RpcTransactionOutput},
    notify::mode::NotificationMode,
};
use sophis_txscript::standard::{
    dilithium_address, dilithium_redeem_script, pay_to_address_script, pay_to_script_hash_signature_script,
};

use crate::error::SequencerError;

// Sompi locked in each ephemeral Submission UTXO (absorbed into state UTXO on update).
const SUBMISSION_UTXO_VALUE: u64 = 1_000;
// Fixed fee per transaction (generous; covers Dilithium sig mass + storage mass).
const PREP_TX_FEE: u64 = 10_000;
const STATE_UPDATE_TX_FEE: u64 = 10_000;
/// Phase 6 — fee for the T_carrier transaction. Higher than the others
/// because the V5 carrier outputs can carry up to ~512 KiB of calldata
/// which dominates storage mass. Conservative — we'd rather pay extra
/// than have the tx rejected for under-fee.
const CARRIER_TX_FEE: u64 = 50_000;
// Non-coinbase UTXO spendability maturity (devnet).
const NON_COINBASE_MATURITY: u64 = 10;
const COINBASE_MATURITY_DEVNET: u64 = 20;
// gRPC connection timeout in milliseconds.
const GRPC_CONNECT_TIMEOUT_MS: u64 = 15_000;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Reference to a live L1 UTXO that holds the rollup state.
#[derive(Debug, Clone)]
pub struct RollupUtxoRef {
    pub txid: [u8; 32],
    pub index: u32,
    pub amount: u64,
}

/// Snapshot of the current on-chain rollup state.
#[derive(Debug, Clone)]
pub struct L1RollupSnapshot {
    pub state: RollupState,
    pub utxo_ref: RollupUtxoRef,
    pub l1_block_height: u64,
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Abstract L1 interface used by the sequencer.
/// Implemented by GrpcL1Client for production; mock in tests.
#[async_trait]
pub trait L1Client: Send + Sync {
    /// Fetch the current rollup state from the L1 UTXO set.
    async fn get_rollup_snapshot(&self) -> Result<L1RollupSnapshot, SequencerError>;

    /// Submit a state update transaction to L1.
    async fn submit_state_update(
        &self,
        snapshot: &L1RollupSnapshot,
        new_state: &RollupState,
        submission: &RollupSubmission,
    ) -> Result<(), SequencerError>;

    /// Phase 6 — publish the batch calldata as V5 DA carriers in a separate
    /// L1 transaction. `expected_bundle_id` is `SHA3-384(calldata)` and is
    /// the same value the sequencer baked into the BatchJournal it just
    /// signed. Implementations split the calldata into `MAX_DATA_PER_CARRIER`
    /// chunks via `consensus_core::da::encode_bundle` (domain = Rollup).
    ///
    /// Default impl is a no-op so existing test mocks compile unchanged.
    /// `GrpcL1Client` overrides to actually submit the tx.
    async fn submit_carrier_calldata(&self, _calldata: &[u8], _expected_bundle_id: [u8; 48]) -> Result<(), SequencerError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// gRPC production client
// ---------------------------------------------------------------------------

/// L1 client that connects to a live sophisd node via gRPC.
///
/// Each operation opens a fresh connection; this is intentionally simple for
/// Phase 3b (one batch every 30 s is not latency-sensitive at this stage).
///
/// `endpoint` is `host:port` without scheme (e.g. `"127.0.0.1:46610"`).
pub struct GrpcL1Client {
    pub endpoint: String,
    /// Bech32m address of the Rollup State UTXO (set at rollup genesis).
    pub state_address: String,
    /// ML-DSA-44 signing key (2560 bytes) — used to sign L1 fee inputs.
    pub signing_key: Box<[u8; 2560]>,
    /// ML-DSA-44 verification key (1312 bytes) — derives the sequencer's L1 address.
    pub verification_key: Box<[u8; 1312]>,
}

impl GrpcL1Client {
    async fn connect(&self) -> Result<GrpcClient, SequencerError> {
        let ctx = SubscriptionContext::new();
        GrpcClient::connect_with_args(
            NotificationMode::Direct,
            format!("grpc://{}", self.endpoint),
            Some(ctx),
            false, // no auto-reconnect
            None,  // no request timeout
            false, // no TLS
            Some(GRPC_CONNECT_TIMEOUT_MS),
            Default::default(),
        )
        .await
        .map_err(|e| SequencerError::L1Client(format!("gRPC connect to {}: {e}", self.endpoint)))
    }

    fn l1_address(&self) -> Result<Address, SequencerError> {
        // Use devnet prefix; rollup-node targets devnet for Phase 3b.
        dilithium_address(&self.verification_key, Prefix::Devnet)
            .map_err(|e| SequencerError::L1Client(format!("L1 address derivation: {e}")))
    }
}

#[async_trait]
impl L1Client for GrpcL1Client {
    async fn get_rollup_snapshot(&self) -> Result<L1RollupSnapshot, SequencerError> {
        if self.state_address.is_empty() {
            return Err(SequencerError::L1Client("state_address not configured (set via --state-address or config file)".into()));
        }

        let rpc = self.connect().await?;

        // Current DAA score → used as l1_block_height.
        let dag_info = rpc.get_block_dag_info().await.map_err(|e| SequencerError::L1Client(format!("get_block_dag_info: {e}")))?;
        let l1_block_height = dag_info.virtual_daa_score;

        // Parse the rollup state address.
        let state_addr = Address::try_from(self.state_address.clone())
            .map_err(|e| SequencerError::L1Client(format!("invalid state_address: {e}")))?;

        // Fetch all UTXOs at the state address.
        let entries = rpc
            .get_utxos_by_addresses(vec![state_addr])
            .await
            .map_err(|e| SequencerError::L1Client(format!("get_utxos_by_addresses: {e}")))?;

        // Identify the UTXO carrying the RollupState (version == ROLLUP_STATE_VERSION).
        let state_entry =
            entries.iter().find(|e| e.utxo_entry.script_public_key.version == ROLLUP_STATE_VERSION).ok_or_else(|| {
                SequencerError::L1Client(format!(
                    "rollup state UTXO (version={ROLLUP_STATE_VERSION}) not found at {}",
                    self.state_address
                ))
            })?;

        let state = RollupState::try_from_slice(state_entry.utxo_entry.script_public_key.script())
            .map_err(|e| SequencerError::L1Client(format!("deserialize RollupState: {e}")))?;

        let txid: [u8; 32] = state_entry.outpoint.transaction_id.as_bytes();

        Ok(L1RollupSnapshot {
            state,
            utxo_ref: RollupUtxoRef { txid, index: state_entry.outpoint.index, amount: state_entry.utxo_entry.amount },
            l1_block_height,
        })
    }

    async fn submit_state_update(
        &self,
        snapshot: &L1RollupSnapshot,
        new_state: &RollupState,
        submission: &RollupSubmission,
    ) -> Result<(), SequencerError> {
        let rpc = self.connect().await?;

        let submission_bytes = borsh::to_vec(submission).map_err(|e| SequencerError::Serialization(e.to_string()))?;
        let new_state_bytes = borsh::to_vec(new_state).map_err(|e| SequencerError::Serialization(e.to_string()))?;

        let seq_addr = self.l1_address()?;

        // Fetch DAA score + sequencer's fee UTXOs.
        let dag_info = rpc.get_block_dag_info().await.map_err(|e| SequencerError::L1Client(format!("get_block_dag_info: {e}")))?;
        let daa_score = dag_info.virtual_daa_score;

        let raw_utxos = rpc
            .get_utxos_by_addresses(vec![seq_addr.clone()])
            .await
            .map_err(|e| SequencerError::L1Client(format!("get_utxos_by_addresses: {e}")))?;

        let mut fee_utxos: Vec<(TransactionOutpoint, UtxoEntry)> = raw_utxos
            .into_iter()
            .filter(|e| {
                let maturity = if e.utxo_entry.is_coinbase { COINBASE_MATURITY_DEVNET } else { NON_COINBASE_MATURITY };
                e.utxo_entry.block_daa_score + maturity < daa_score
            })
            .map(|e| (TransactionOutpoint::from(e.outpoint), UtxoEntry::from(e.utxo_entry)))
            .collect();
        // Prefer larger UTXOs first.
        fee_utxos.sort_by(|a, b| b.1.amount.cmp(&a.1.amount));

        let fee_utxo =
            fee_utxos.into_iter().next().ok_or_else(|| SequencerError::L1Client("no spendable fee UTXOs for sequencer".into()))?;

        let redeem_script = dilithium_redeem_script(&self.verification_key)
            .map_err(|e| SequencerError::L1Client(format!("dilithium_redeem_script: {e}")))?;

        let total_available = fee_utxo.1.amount;
        let required = SUBMISSION_UTXO_VALUE + PREP_TX_FEE + STATE_UPDATE_TX_FEE;
        if total_available < required {
            return Err(SequencerError::L1Client(format!("fee UTXO too small: have {total_available} sompi, need {required}")));
        }
        // Change returned to sequencer after prep tx (before state update fee deduction).
        let prep_change = total_available - SUBMISSION_UTXO_VALUE - PREP_TX_FEE;

        // ── Prep TX (creates Submission UTXO) ───────────────────────────────────

        let submission_spk = ScriptPublicKey::from_vec(ROLLUP_SUBMISSION_VERSION, submission_bytes.clone());
        let seq_p2sh_spk = pay_to_address_script(&seq_addr);

        let prep_tx = build_signed_prep_tx(
            &fee_utxo,
            SUBMISSION_UTXO_VALUE,
            prep_change,
            submission_spk,
            seq_p2sh_spk.clone(),
            &redeem_script,
            &self.signing_key,
        )?;

        let prep_txid = rpc
            .submit_transaction(consensus_tx_to_rpc(prep_tx), false)
            .await
            .map_err(|e| SequencerError::L1Client(format!("submit prep tx: {e}")))?;

        let prep_txid_bytes: [u8; 32] = prep_txid.as_bytes();

        // ── State Update TX ─────────────────────────────────────────────────────
        //
        // Input layout (matches verifier contract expectations):
        //   [0] Rollup State UTXO   — sVM controlled, no Dilithium sig
        //   [1] Submission UTXO     — sVM controlled, no Dilithium sig (from prep tx output 0)
        //   [2] Change from prep tx — P2SH Dilithium, signed by sequencer (from prep tx output 1)
        //
        // Output layout:
        //   [0] New Rollup State UTXO — absorbs SUBMISSION_UTXO_VALUE
        //   [1] Change to sequencer

        let old_state_bytes = borsh::to_vec(&snapshot.state).map_err(|e| SequencerError::Serialization(e.to_string()))?;
        let old_state_spk = ScriptPublicKey::from_vec(ROLLUP_STATE_VERSION, old_state_bytes);
        let submission_spk_entry = ScriptPublicKey::from_vec(ROLLUP_SUBMISSION_VERSION, submission_bytes);
        let new_state_spk = ScriptPublicKey::from_vec(ROLLUP_STATE_VERSION, new_state_bytes);

        let new_state_value = snapshot.utxo_ref.amount.checked_add(SUBMISSION_UTXO_VALUE).ok_or(SequencerError::Overflow)?;
        let state_update_change = prep_change - STATE_UPDATE_TX_FEE;

        let state_update_tx = build_signed_state_update_tx(
            snapshot,
            prep_txid_bytes,
            new_state_value,
            state_update_change,
            new_state_spk,
            &seq_addr,
            old_state_spk,
            submission_spk_entry,
            prep_change,
            &redeem_script,
            &self.signing_key,
        )?;

        rpc.submit_transaction(consensus_tx_to_rpc(state_update_tx), true)
            .await
            .map_err(|e| SequencerError::L1Client(format!("submit state update tx: {e}")))?;

        println!(
            "[l1_client] batch {} committed on L1 (prep={}, daa={})",
            new_state.sequence,
            hex::encode(prep_txid_bytes),
            daa_score,
        );
        Ok(())
    }

    async fn submit_carrier_calldata(&self, calldata: &[u8], expected_bundle_id: [u8; 48]) -> Result<(), SequencerError> {
        use sophis_consensus_core::constants::SCRIPT_VERSION_CARRIER;
        use sophis_consensus_core::da::{CarrierDomain, MAX_CARRIER_OUTPUTS_PER_TX, encode_bundle};

        // Encode the calldata as V5 carrier scripts in one shot.
        let scripts = encode_bundle(calldata, Some(CarrierDomain::Rollup))
            .map_err(|e| SequencerError::L1Client(format!("encode_bundle: {e}")))?;
        // Phase 6.3 simplification: a single T_carrier tx must fit all fragments.
        // Batches large enough to exceed 8 * 64 KiB = 512 KiB are rejected here;
        // multi-tx splitting is a future enhancement.
        if scripts.len() > MAX_CARRIER_OUTPUTS_PER_TX {
            return Err(SequencerError::L1Client(format!(
                "calldata too large for a single T_carrier tx: {} fragments > MAX {}",
                scripts.len(),
                MAX_CARRIER_OUTPUTS_PER_TX,
            )));
        }
        // Defense in depth: the bundle_id encoded in every fragment header
        // must match the value the sequencer baked into the journal.
        for s in &scripts {
            if s.len() < 64 {
                return Err(SequencerError::L1Client("carrier script truncated below header".into()));
            }
            let claimed: [u8; 48] = s[16..64].try_into().expect("48 bytes");
            if claimed != expected_bundle_id {
                return Err(SequencerError::L1Client("carrier bundle_id mismatch with journal".into()));
            }
        }

        let rpc = self.connect().await?;
        let dag_info = rpc.get_block_dag_info().await.map_err(|e| SequencerError::L1Client(format!("get_block_dag_info: {e}")))?;
        let daa_score = dag_info.virtual_daa_score;

        let seq_addr = self.l1_address()?;
        let raw_utxos = rpc
            .get_utxos_by_addresses(vec![seq_addr.clone()])
            .await
            .map_err(|e| SequencerError::L1Client(format!("get_utxos_by_addresses: {e}")))?;

        let mut fee_utxos: Vec<(TransactionOutpoint, UtxoEntry)> = raw_utxos
            .into_iter()
            .filter(|e| {
                let maturity = if e.utxo_entry.is_coinbase { COINBASE_MATURITY_DEVNET } else { NON_COINBASE_MATURITY };
                e.utxo_entry.block_daa_score + maturity < daa_score
            })
            .map(|e| (TransactionOutpoint::from(e.outpoint), UtxoEntry::from(e.utxo_entry)))
            .collect();
        fee_utxos.sort_by(|a, b| b.1.amount.cmp(&a.1.amount));

        let fee_utxo =
            fee_utxos.into_iter().next().ok_or_else(|| SequencerError::L1Client("no spendable fee UTXOs for carrier tx".into()))?;

        if fee_utxo.1.amount < CARRIER_TX_FEE {
            return Err(SequencerError::L1Client(format!(
                "fee UTXO too small for carrier tx: have {} sompi, need {CARRIER_TX_FEE}",
                fee_utxo.1.amount
            )));
        }

        let redeem_script = dilithium_redeem_script(&self.verification_key)
            .map_err(|e| SequencerError::L1Client(format!("dilithium_redeem_script: {e}")))?;

        let change = fee_utxo.1.amount - CARRIER_TX_FEE;
        let seq_p2sh_spk = pay_to_address_script(&seq_addr);

        // Build outputs: V5 carriers (value=0) + change.
        let mut outputs: Vec<TransactionOutput> = scripts
            .into_iter()
            .map(|script| TransactionOutput { value: 0, script_public_key: ScriptPublicKey::from_vec(SCRIPT_VERSION_CARRIER, script) })
            .collect();
        if change > 0 {
            outputs.push(TransactionOutput { value: change, script_public_key: seq_p2sh_spk.clone() });
        }

        let inputs = vec![TransactionInput { previous_outpoint: fee_utxo.0, signature_script: vec![], sequence: 0, sig_op_count: 1 }];
        let unsigned = Transaction::new_non_finalized(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
        let entries = vec![fee_utxo.1.clone()];
        let mut mutable = MutableTransaction::with_entries(unsigned, entries);

        let sig = sign_input_dilithium(&mutable.as_verifiable(), 0, &self.signing_key, SIG_HASH_ALL)
            .map_err(|_| SequencerError::SigningFailed)?;
        mutable.tx.inputs[0].signature_script = pay_to_script_hash_signature_script(redeem_script, sig)
            .map_err(|e| SequencerError::L1Client(format!("p2sh sig script: {e}")))?;

        let txid = rpc
            .submit_transaction(consensus_tx_to_rpc(mutable.tx), false)
            .await
            .map_err(|e| SequencerError::L1Client(format!("submit T_carrier tx: {e}")))?;

        println!(
            "[l1_client] T_carrier published: bundle_id={} txid={}",
            hex::encode(expected_bundle_id),
            hex::encode(txid.as_bytes()),
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Transaction builders
// ---------------------------------------------------------------------------

fn build_signed_prep_tx(
    fee_utxo: &(TransactionOutpoint, UtxoEntry),
    submission_value: u64,
    change: u64,
    submission_spk: ScriptPublicKey,
    change_spk: ScriptPublicKey,
    redeem_script: &[u8],
    signing_key: &[u8; 2560],
) -> Result<Transaction, SequencerError> {
    let inputs = vec![TransactionInput { previous_outpoint: fee_utxo.0, signature_script: vec![], sequence: 0, sig_op_count: 1 }];
    let mut outputs = vec![TransactionOutput { value: submission_value, script_public_key: submission_spk }];
    if change > 0 {
        outputs.push(TransactionOutput { value: change, script_public_key: change_spk });
    }
    let unsigned = Transaction::new_non_finalized(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let entries = vec![fee_utxo.1.clone()];
    let mut mutable = MutableTransaction::with_entries(unsigned, entries);

    let sig =
        sign_input_dilithium(&mutable.as_verifiable(), 0, signing_key, SIG_HASH_ALL).map_err(|_| SequencerError::SigningFailed)?;
    mutable.tx.inputs[0].signature_script = pay_to_script_hash_signature_script(redeem_script.to_vec(), sig)
        .map_err(|e| SequencerError::L1Client(format!("p2sh sig script: {e}")))?;

    Ok(mutable.tx)
}

#[allow(clippy::too_many_arguments)]
fn build_signed_state_update_tx(
    snapshot: &L1RollupSnapshot,
    prep_txid: [u8; 32],
    new_state_value: u64,
    change_value: u64,
    new_state_spk: ScriptPublicKey,
    seq_addr: &Address,
    old_state_spk: ScriptPublicKey,
    submission_spk: ScriptPublicKey,
    fee_input_amount: u64,
    redeem_script: &[u8],
    signing_key: &[u8; 2560],
) -> Result<Transaction, SequencerError> {
    let state_outpoint =
        TransactionOutpoint { transaction_id: TransactionId::from_bytes(snapshot.utxo_ref.txid), index: snapshot.utxo_ref.index };
    let submission_outpoint = TransactionOutpoint {
        transaction_id: TransactionId::from_bytes(prep_txid),
        index: 0, // prep tx output 0
    };
    let fee_outpoint = TransactionOutpoint {
        transaction_id: TransactionId::from_bytes(prep_txid),
        index: 1, // prep tx output 1 (change from prep tx)
    };

    let seq_p2sh_spk = pay_to_address_script(seq_addr);

    let inputs = vec![
        TransactionInput {
            previous_outpoint: state_outpoint,
            signature_script: vec![],
            sequence: 0,
            sig_op_count: 0, // sVM controlled — verifier contract handles validation
        },
        TransactionInput {
            previous_outpoint: submission_outpoint,
            signature_script: vec![],
            sequence: 0,
            sig_op_count: 0, // sVM controlled — ephemeral, no traditional sig needed
        },
        TransactionInput {
            previous_outpoint: fee_outpoint,
            signature_script: vec![],
            sequence: 0,
            sig_op_count: 1, // signed below with sequencer's L1 Dilithium key
        },
    ];
    let mut outputs = vec![TransactionOutput { value: new_state_value, script_public_key: new_state_spk }];
    if change_value > 0 {
        outputs.push(TransactionOutput { value: change_value, script_public_key: seq_p2sh_spk.clone() });
    }

    let utxo_entries = vec![
        UtxoEntry { amount: snapshot.utxo_ref.amount, script_public_key: old_state_spk, block_daa_score: 0, is_coinbase: false },
        UtxoEntry { amount: SUBMISSION_UTXO_VALUE, script_public_key: submission_spk, block_daa_score: 0, is_coinbase: false },
        UtxoEntry { amount: fee_input_amount, script_public_key: seq_p2sh_spk, block_daa_score: 0, is_coinbase: false },
    ];

    let unsigned = Transaction::new_non_finalized(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let mut mutable = MutableTransaction::with_entries(unsigned, utxo_entries);

    // Sign only the fee input at index 2.
    let sig =
        sign_input_dilithium(&mutable.as_verifiable(), 2, signing_key, SIG_HASH_ALL).map_err(|_| SequencerError::SigningFailed)?;
    mutable.tx.inputs[2].signature_script = pay_to_script_hash_signature_script(redeem_script.to_vec(), sig)
        .map_err(|e| SequencerError::L1Client(format!("p2sh sig script: {e}")))?;

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

// ---------------------------------------------------------------------------
// Mock for tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::sync::{Arc, Mutex};

    pub struct MockL1Client {
        pub snapshot: Arc<Mutex<L1RollupSnapshot>>,
        pub submitted: Arc<Mutex<Vec<(RollupState, RollupSubmission)>>>,
    }

    impl MockL1Client {
        pub fn new(state: RollupState) -> Self {
            Self {
                snapshot: Arc::new(Mutex::new(L1RollupSnapshot {
                    state,
                    utxo_ref: RollupUtxoRef { txid: [0u8; 32], index: 0, amount: 0 },
                    l1_block_height: 100,
                })),
                submitted: Arc::new(Mutex::new(vec![])),
            }
        }
    }

    #[async_trait]
    impl L1Client for MockL1Client {
        async fn get_rollup_snapshot(&self) -> Result<L1RollupSnapshot, SequencerError> {
            Ok(self.snapshot.lock().unwrap().clone())
        }

        async fn submit_state_update(
            &self,
            _snapshot: &L1RollupSnapshot,
            new_state: &RollupState,
            submission: &RollupSubmission,
        ) -> Result<(), SequencerError> {
            self.submitted.lock().unwrap().push((new_state.clone(), submission.clone()));
            let mut snap = self.snapshot.lock().unwrap();
            snap.state = new_state.clone();
            Ok(())
        }
    }
}
