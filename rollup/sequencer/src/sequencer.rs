use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use sophis_rollup_core::{L2Utxo, compute_state_root};
use sophis_rollup_verifier::RollupState;

use crate::{
    batch::{BatchTrigger, apply_batch, batch_calldata, build_and_sign_submission, compute_da_bundle_id},
    config::SequencerConfig,
    error::SequencerError,
    l1_client::L1Client,
    mempool::Mempool,
};

pub struct Sequencer<C: L1Client> {
    config: SequencerConfig,
    mempool: Arc<Mempool>,
    l1: Arc<C>,
    trigger: BatchTrigger,
}

impl<C: L1Client> Sequencer<C> {
    pub fn new(config: SequencerConfig, mempool: Arc<Mempool>, l1: Arc<C>) -> Self {
        let trigger = BatchTrigger::new(config.max_batch_txs, config.batch_timeout_secs);
        Self { config, mempool, l1, trigger }
    }

    /// Main sequencer loop. Runs until the process is killed.
    /// Polls every 1 second; flushes when trigger fires.
    pub async fn run(&mut self, utxo_state: Vec<L2Utxo>) -> Result<(), SequencerError> {
        let mut current_utxos = utxo_state;

        loop {
            sleep(Duration::from_secs(1)).await;

            let pending = self.mempool.len();
            if !self.trigger.should_flush(pending) {
                continue;
            }
            if pending == 0 {
                // Timeout fired but no txs — just reset timer
                self.trigger.mark_flushed();
                continue;
            }

            match self.flush_batch(&mut current_utxos).await {
                Ok(()) => {}
                Err(e) => eprintln!("[sequencer] batch flush error: {e}"),
            }
        }
    }

    /// Drain mempool, apply state transition, sign journal, submit to L1.
    pub async fn flush_batch(&mut self, current_utxos: &mut Vec<L2Utxo>) -> Result<(), SequencerError> {
        // Fetch current on-chain state
        let snapshot = self.l1.get_rollup_snapshot().await?;

        // Check we're the authorized sequencer
        if !self.config.is_authorized_sequencer(&snapshot.state.sequencer_vk) {
            return Err(SequencerError::NotAuthorized);
        }

        let txs = self.mempool.drain(self.config.max_batch_txs);
        let batch = sophis_rollup_core::Batch {
            sequence: snapshot.state.sequence.checked_add(1).ok_or(SequencerError::Overflow)?,
            l1_anchor_block: snapshot.l1_block_height,
            prev_state_root: sophis_rollup_core::StateRoot(snapshot.state.state_root),
            txs,
            deposits: vec![],    // TODO: detect pending deposits from L1
            withdrawals: vec![], // TODO: detect pending withdrawals
        };

        // Apply state transition natively to compute new root
        let new_utxos = apply_batch(&batch, current_utxos.clone())?;
        let new_root = compute_state_root(&new_utxos);

        // Phase 6 — DA: serialize the batch as calldata and compute the
        // bundle_id that will (a) embed in the BatchJournal and (b) tag
        // the V5 carrier outputs of the companion T_carrier transaction.
        let calldata = batch_calldata(&batch)?;
        let da_bundle_id = compute_da_bundle_id(&calldata);

        // Build + sign submission with the DA bundle_id baked into the journal.
        let submission = build_and_sign_submission(&batch, new_root.clone(), da_bundle_id, &self.config.signing_key)?;

        // Build new L1 state
        let new_state =
            RollupState { sequence: batch.sequence, state_root: new_root.0, sequencer_vk: *self.config.verification_key.clone() };

        // Phase 6 — publish the calldata as V5 carriers BEFORE the state update.
        // Failures are non-fatal in the mock path (no L1 to talk to); production
        // GrpcL1Client returns Err and the whole batch is retried.
        self.l1.submit_carrier_calldata(&calldata, da_bundle_id).await?;

        // Submit to L1
        self.l1.submit_state_update(&snapshot, &new_state, &submission).await?;

        // Advance local UTXO set
        *current_utxos = new_utxos;
        self.trigger.mark_flushed();

        println!("[sequencer] batch {} submitted: {} txs, new root {:?}", batch.sequence, batch.txs.len(), &new_state.state_root[..4],);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l1_client::mock::MockL1Client;
    use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, ml_dsa_44};
    use rand::TryRngCore;

    fn gen_keypair() -> ([u8; 2560], [u8; 1312]) {
        let mut seed = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
        rand::rngs::OsRng.try_fill_bytes(&mut seed).expect("os entropy");
        let kp = ml_dsa_44::generate_key_pair(seed);
        let sk: [u8; 2560] = *kp.signing_key.as_ref();
        let vk: [u8; 1312] = *kp.verification_key.as_ref();
        (sk, vk)
    }

    fn make_sequencer(sk: [u8; 2560], vk: [u8; 1312]) -> (Sequencer<MockL1Client>, Arc<MockL1Client>) {
        let cfg = SequencerConfig {
            signing_key: Box::new(sk),
            verification_key: Box::new(vk),
            l1_rpc_url: "ws://127.0.0.1:47610".into(),
            max_batch_txs: 10,
            batch_timeout_secs: 30,
            http_port: 9944,
        };

        let initial_state = RollupState { sequence: 0, state_root: [0u8; 48], sequencer_vk: vk };

        let l1 = Arc::new(MockL1Client::new(initial_state));
        let mempool = Arc::new(Mempool::new());
        let seq = Sequencer::new(cfg, mempool, l1.clone());
        (seq, l1)
    }

    #[tokio::test]
    async fn flush_empty_mempool_does_nothing_meaningful() {
        let (sk, vk) = gen_keypair();
        let (mut seq, l1) = make_sequencer(sk, vk);
        // mempool is empty → flush_batch should still succeed (empty batch)
        let result = seq.flush_batch(&mut vec![]).await;
        // Will succeed — empty batch is valid
        assert!(result.is_ok(), "flush of empty mempool failed: {:?}", result);
        assert_eq!(l1.submitted.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn flush_advances_sequence() {
        let (sk, vk) = gen_keypair();
        let (mut seq, l1) = make_sequencer(sk, vk);

        seq.flush_batch(&mut vec![]).await.unwrap();
        seq.flush_batch(&mut vec![]).await.unwrap();

        let submitted = l1.submitted.lock().unwrap();
        assert_eq!(submitted[0].0.sequence, 1);
        assert_eq!(submitted[1].0.sequence, 2);
    }

    #[tokio::test]
    async fn not_authorized_returns_error() {
        let (sk, vk) = gen_keypair();
        let (_, other_vk) = gen_keypair(); // different key

        let cfg = SequencerConfig {
            signing_key: Box::new(sk),
            verification_key: Box::new(vk),
            l1_rpc_url: "ws://127.0.0.1:47610".into(),
            max_batch_txs: 10,
            batch_timeout_secs: 30,
            http_port: 9944,
        };

        // State has other_vk as sequencer → we are not authorized
        let state = RollupState { sequence: 0, state_root: [0u8; 48], sequencer_vk: other_vk };
        let l1 = Arc::new(MockL1Client::new(state));
        let mempool = Arc::new(Mempool::new());
        let mut seq = Sequencer::new(cfg, mempool, l1);

        let err = seq.flush_batch(&mut vec![]).await.unwrap_err();
        assert!(matches!(err, SequencerError::NotAuthorized));
    }
}
