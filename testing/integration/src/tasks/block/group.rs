use crate::{
    common::daemon::ClientManager,
    tasks::{
        Stopper, Task,
        block::{miner::BlockMinerTask, submitter::BlockSubmitterTask, template_receiver::BlockTemplateReceiverTask},
    },
};
use async_trait::async_trait;
use itertools::chain;
use sophis_addresses::Address;
use sophis_consensus_core::network::NetworkId;
use sophis_core::debug;
use sophis_utils::triggers::SingleTrigger;
use std::sync::Arc;
use tokio::task::JoinHandle;

pub struct MinerGroupTask {
    submitter: Arc<BlockSubmitterTask>,
    receiver: Arc<BlockTemplateReceiverTask>,
    miner: Arc<BlockMinerTask>,
}

impl MinerGroupTask {
    pub fn new(submitter: Arc<BlockSubmitterTask>, receiver: Arc<BlockTemplateReceiverTask>, miner: Arc<BlockMinerTask>) -> Self {
        Self { submitter, receiver, miner }
    }

    pub async fn build(
        network: NetworkId,
        client_manager: Arc<ClientManager>,
        submitter_pool_size: usize,
        bps: u64,
        block_count: usize,
        stopper: Stopper,
    ) -> Arc<Self> {
        // Block submitter
        let submitter = BlockSubmitterTask::build(client_manager.clone(), submitter_pool_size, stopper).await;

        // Mining address — tests do not sign, so a deterministic 32-byte
        // payload is sufficient for routing coinbase rewards in fixtures.
        let pay_address =
            Address::new(network.network_type().into(), sophis_addresses::Version::PubKeyDilithium, &[0u8; 32]);
        debug!("Test mining address {}", pay_address);

        // Block template receiver
        let client = Arc::new(client_manager.new_client().await);
        let receiver = BlockTemplateReceiverTask::build(client.clone(), pay_address.clone(), stopper).await;

        // Miner
        let miner =
            BlockMinerTask::build(client, bps, block_count, submitter.sender(), receiver.template(), pay_address, stopper).await;

        Arc::new(Self::new(submitter, receiver, miner))
    }
}

#[async_trait]
impl Task for MinerGroupTask {
    fn start(&self, stop_signal: SingleTrigger) -> Vec<JoinHandle<()>> {
        chain![
            self.submitter.start(stop_signal.clone()),
            self.receiver.start(stop_signal.clone()),
            self.miner.start(stop_signal.clone())
        ]
        .collect()
    }
}
