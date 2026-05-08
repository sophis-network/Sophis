use std::time::Duration;

use serde::Serialize;
use sophis_consensus_core::{Hash, subnets::SUBNETWORK_ID_COINBASE};
use sophis_grpc_client::GrpcClient;
use sophis_rpc_core::api::rpc::RpcApi;

pub type RpcError = Box<dyn std::error::Error + Send + Sync>;

const RPC_TIMEOUT: Duration = Duration::from_secs(10);

macro_rules! rpc {
    ($client:expr, $method:ident($($arg:expr),*)) => {
        tokio::time::timeout(RPC_TIMEOUT, $client.$method($($arg),*))
            .await
            .map_err(|_| "RPC timeout")?
            .map_err(|e| format!("RPC error: {e}"))?
    };
}

// ─── Response types ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone)]
pub struct NetworkInfo {
    pub network: String,
    pub block_count: u64,
    pub header_count: u64,
    pub virtual_daa_score: u64,
    pub difficulty: f64,
    pub hashrate_ghs: f64,
    pub mempool_size: u64,
    pub tip_hashes: Vec<String>,
    pub is_synced: bool,
    pub sink: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct BlockSummary {
    pub hash: String,
    pub daa_score: u64,
    pub blue_score: u64,
    pub timestamp_ms: u64,
    pub tx_count: usize,
    pub difficulty: f64,
    pub is_chain_block: bool,
    pub is_header_only: bool,
    pub parents: Vec<String>,
    pub selected_parent: String,
}

#[derive(Debug, Serialize)]
pub struct TxSummary {
    pub tx_id: String,
    pub is_coinbase: bool,
    pub input_count: usize,
    pub output_count: usize,
    pub total_out_sompi: u64,
    pub mass: u64,
}

#[derive(Debug, Serialize)]
pub struct BlockDetail {
    pub hash: String,
    pub version: u16,
    pub daa_score: u64,
    pub blue_score: u64,
    pub timestamp_ms: u64,
    pub bits: u32,
    pub nonce: u64,
    pub blue_work: String,
    pub hash_merkle_root: String,
    pub selected_parent: String,
    pub parents: Vec<String>,
    pub children: Vec<String>,
    pub merge_set_blues: Vec<String>,
    pub merge_set_reds: Vec<String>,
    pub is_chain_block: bool,
    pub difficulty: f64,
    pub transactions: Vec<TxSummary>,
}

#[derive(Debug, Serialize)]
pub struct InputInfo {
    pub previous_tx_id: String,
    pub previous_index: u32,
    pub sequence: u64,
    pub sig_op_count: u8,
}

#[derive(Debug, Serialize)]
pub struct OutputInfo {
    pub amount_sompi: u64,
    pub address: Option<String>,
    pub script_type: String,
}

#[derive(Debug, Serialize)]
pub struct TxDetail {
    pub tx_id: String,
    pub version: u16,
    pub is_coinbase: bool,
    pub inputs: Vec<InputInfo>,
    pub outputs: Vec<OutputInfo>,
    pub lock_time: u64,
    pub mass: u64,
    pub block_hash: String,
    pub block_time_ms: u64,
    pub in_mempool: bool,
}

#[derive(Debug, Serialize)]
pub struct UtxoInfo {
    pub tx_id: String,
    pub index: u32,
    pub amount_sompi: u64,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
}

#[derive(Debug, Serialize)]
pub struct AddressInfo {
    pub address: String,
    pub balance_sompi: u64,
    pub utxo_count: usize,
    pub utxos: Vec<UtxoInfo>,
}

// ─── RPC helpers ─────────────────────────────────────────────────────────────

pub async fn get_network_info(rpc: &GrpcClient) -> Result<NetworkInfo, RpcError> {
    let dag = rpc!(rpc, get_block_dag_info());
    let info = rpc!(rpc, get_info());
    let hps: u64 = rpc!(rpc, estimate_network_hashes_per_second(100, None));

    Ok(NetworkInfo {
        network: dag.network.to_string(),
        block_count: dag.block_count,
        header_count: dag.header_count,
        virtual_daa_score: dag.virtual_daa_score,
        difficulty: dag.difficulty,
        hashrate_ghs: hps as f64 / 1e9,
        mempool_size: info.mempool_size,
        tip_hashes: dag.tip_hashes.iter().map(|h| h.to_string()).collect(),
        is_synced: info.is_synced,
        sink: dag.sink.to_string(),
    })
}

pub async fn get_recent_blocks(rpc: &GrpcClient, limit: usize) -> Result<Vec<BlockSummary>, RpcError> {
    let sink_resp = rpc!(rpc, get_sink());
    let genesis_sentinel = Hash::from_bytes([0u8; 32]);
    let mut hash = sink_resp.sink;
    let mut summaries = Vec::with_capacity(limit);

    for _ in 0..limit {
        if hash == genesis_sentinel {
            break;
        }
        let block = tokio::time::timeout(RPC_TIMEOUT, rpc.get_block(hash, false))
            .await
            .map_err(|_| "RPC timeout")?
            .map_err(|e| format!("RPC error: {e}"))?;

        let header = &block.header;
        let vd = match block.verbose_data {
            Some(v) => v,
            None => break,
        };

        let parents = header.parents_by_level.first().map(|lvl| lvl.iter().map(|h| h.to_string()).collect()).unwrap_or_default();

        summaries.push(BlockSummary {
            hash: header.hash.to_string(),
            daa_score: header.daa_score,
            blue_score: header.blue_score,
            timestamp_ms: header.timestamp,
            tx_count: vd.transaction_ids.len(),
            difficulty: vd.difficulty,
            is_chain_block: vd.is_chain_block,
            is_header_only: vd.is_header_only,
            selected_parent: vd.selected_parent_hash.to_string(),
            parents,
        });

        hash = vd.selected_parent_hash;
    }

    Ok(summaries)
}

pub async fn get_block_detail(rpc: &GrpcClient, hash_str: &str) -> Result<BlockDetail, RpcError> {
    let hash = hash_str.parse::<Hash>().map_err(|e| format!("Invalid hash: {e}"))?;
    let block = rpc!(rpc, get_block(hash, true));

    let header = &block.header;
    let vd = block.verbose_data.as_ref().ok_or("No verbose data")?;

    let parents = header.parents_by_level.first().map(|lvl| lvl.iter().map(|h| h.to_string()).collect()).unwrap_or_default();

    let transactions = block
        .transactions
        .iter()
        .map(|tx| {
            let tx_id = tx.verbose_data.as_ref().map(|v| v.transaction_id.to_string()).unwrap_or_default();
            TxSummary {
                tx_id,
                is_coinbase: tx.subnetwork_id == SUBNETWORK_ID_COINBASE,
                input_count: tx.inputs.len(),
                output_count: tx.outputs.len(),
                total_out_sompi: tx.outputs.iter().map(|o| o.value).sum(),
                mass: tx.mass,
            }
        })
        .collect();

    Ok(BlockDetail {
        hash: header.hash.to_string(),
        version: header.version,
        daa_score: header.daa_score,
        blue_score: header.blue_score,
        timestamp_ms: header.timestamp,
        bits: header.bits,
        nonce: header.nonce,
        blue_work: header.blue_work.to_string(),
        hash_merkle_root: header.hash_merkle_root.to_string(),
        selected_parent: vd.selected_parent_hash.to_string(),
        parents,
        children: vd.children_hashes.iter().map(|h| h.to_string()).collect(),
        merge_set_blues: vd.merge_set_blues_hashes.iter().map(|h| h.to_string()).collect(),
        merge_set_reds: vd.merge_set_reds_hashes.iter().map(|h| h.to_string()).collect(),
        is_chain_block: vd.is_chain_block,
        difficulty: vd.difficulty,
        transactions,
    })
}

pub async fn get_tx_detail(rpc: &GrpcClient, txid_str: &str) -> Result<TxDetail, RpcError> {
    let tx_id_hash = txid_str.parse::<Hash>().map_err(|e| format!("Invalid tx ID: {e}"))?;

    let mempool = tokio::time::timeout(RPC_TIMEOUT, rpc.get_mempool_entry(tx_id_hash, true, false)).await.ok().and_then(|r| r.ok());

    if let Some(entry) = mempool {
        let tx = &entry.transaction;
        let tx_id = tx.verbose_data.as_ref().map(|v| v.transaction_id.to_string()).unwrap_or_else(|| txid_str.to_string());

        let inputs = tx
            .inputs
            .iter()
            .map(|i| InputInfo {
                previous_tx_id: i.previous_outpoint.transaction_id.to_string(),
                previous_index: i.previous_outpoint.index,
                sequence: i.sequence,
                sig_op_count: i.sig_op_count,
            })
            .collect();

        let outputs = tx
            .outputs
            .iter()
            .map(|o| OutputInfo {
                amount_sompi: o.value,
                address: o.verbose_data.as_ref().map(|v| v.script_public_key_address.to_string()),
                script_type: o.verbose_data.as_ref().map(|v| v.script_public_key_type.to_string()).unwrap_or_default(),
            })
            .collect();

        return Ok(TxDetail {
            tx_id,
            version: tx.version,
            is_coinbase: tx.subnetwork_id == SUBNETWORK_ID_COINBASE,
            inputs,
            outputs,
            lock_time: tx.lock_time,
            mass: tx.mass,
            block_hash: String::new(),
            block_time_ms: 0,
            in_mempool: true,
        });
    }

    Err("Transaction not found in mempool. If confirmed, open the block it was included in.".into())
}

pub async fn get_address_info(rpc: &GrpcClient, address_str: &str) -> Result<AddressInfo, RpcError> {
    use sophis_addresses::Address;
    let address: Address = Address::try_from(address_str).map_err(|e| format!("Invalid address: {e}"))?;

    let balance: u64 = rpc!(rpc, get_balance_by_address(address.clone()));
    let utxo_entries = rpc!(rpc, get_utxos_by_addresses(vec![address]));

    let utxos: Vec<UtxoInfo> = utxo_entries
        .iter()
        .map(|e| UtxoInfo {
            tx_id: e.outpoint.transaction_id.to_string(),
            index: e.outpoint.index,
            amount_sompi: e.utxo_entry.amount,
            block_daa_score: e.utxo_entry.block_daa_score,
            is_coinbase: e.utxo_entry.is_coinbase,
        })
        .collect();

    let utxo_count = utxos.len();

    Ok(AddressInfo { address: address_str.to_string(), balance_sompi: balance, utxo_count, utxos })
}
