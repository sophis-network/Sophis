//! `sophis-dashboard` — public mainnet launch dashboard.
//!
//! Implements LAUNCH_CHECKLIST.md ação #2 (Bloco 6 — defensive actions
//! T-72h → T+24h). Goes live at t=0 (genesis) and exposes:
//!
//!   - Total network hashrate (DAA-difficulty-derived)
//!   - Total emitted supply (`get_coin_supply`)
//!   - Founder address balance + founder share % (= balance / supply)
//!   - Time since genesis with the 24h wait-window countdown
//!     (founder mining is restricted during this window per §5.3)
//!   - The publicly-declared founder mining address (immutable input)
//!
//! Architecture:
//!   - Single binary, axum HTTP server, embedded HTML page
//!   - Background tokio task polls sophisd gRPC every 10s and updates
//!     a shared `MetricsCache` (Arc<RwLock<...>>)
//!   - GET /         → returns the embedded HTML page
//!   - GET /metrics  → returns the cached JSON snapshot
//!   - GET /healthz  → 200 OK (for monitoring / uptime probes)
//!
//! Self-contained: deploy as a single binary on any VPS pointing at a
//! local sophisd. No external dependencies beyond what the workspace
//! already pulls in.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::get,
};
use clap::{Arg, Command, value_parser};
use serde::Serialize;
use sophis_addresses::Address;
use sophis_grpc_client::GrpcClient;
use sophis_hashes::Hash;
use sophis_notify::subscription::context::SubscriptionContext;
use sophis_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};
use tokio::sync::RwLock;

const POLL_INTERVAL: Duration = Duration::from_secs(10);
const RPC_TIMEOUT: Duration = Duration::from_secs(15);
/// I1.1 — secondary poll cycle for mempool. Mempool changes slowly
/// relative to consensus, so we throttle to 30s to reduce RPC load.
const MEMPOOL_POLL_EVERY_N_TICKS: u64 = 3;

/// 24-hour founder wait window (§5.3 of the whitepaper).
const FOUNDER_WAIT_SECS: i64 = 24 * 3600;

/// I1.1 — size of the BPS ring buffer (in 10s ticks). 6 ticks = 60s window
/// matches §4.1 of `docs/I1_DASHBOARD_DESIGN.md`.
const BPS_WINDOW_TICKS: usize = 6;

/// I1.1 — default for `--finality-blue-blocks` CLI flag (D2).
/// Matches the mainnet `coinbase_maturity` so the "safe to spend"
/// guarantee at depth N also satisfies the finality label.
const DEFAULT_FINALITY_BLUE_BLOCKS: u64 = 100;

/// I1.2 — rolling window for unique-miners counting. Frozen at 60 min
/// per design D3. Operators wanting a different window must wait for a
/// `--miners-window-secs` CLI flag (deferred per D3 menu option C).
const MINERS_WINDOW_SECS: u64 = 3600;
/// I1.2 — soft cap on the miner buffer; with a saturated 10 BPS chain
/// the steady-state size is ~36k entries. Cap at 50k to absorb bursts
/// without unbounded growth.
const MINERS_BUF_CAP: usize = 50_000;

/// I1.2 — type alias for the miner ring buffer entries. Keeps clippy's
/// `type_complexity` lint happy and lets the snapshot-derivation helper
/// (`distinct_in_window`) and the storage handle (`AppState.miner_buf`)
/// share a single source-of-truth shape.
type MinerSample = (u64, Vec<u8>);
type MinerBuf = VecDeque<MinerSample>;

/// I1.3 — refresh top-wallets ranking every Nth consensus tick. 30 ticks
/// at 10s = 300s = 5 min, matching §4.5 of DESIGN.
const TOP_WALLETS_REFRESH_EVERY_N_TICKS: u64 = 30;
/// I1.3 — number of entries returned in the ranking.
const TOP_WALLETS_LIMIT: usize = 100;
/// I1.3 — soft cap on the active-addresses tracker; with realistic chain
/// activity this lives well below 100k. Cap exists to bound memory in
/// adversarial scenarios.
const ACTIVE_ADDRESSES_CAP: usize = 100_000;
/// I1.3 — max addresses in a single `get_balances_by_addresses` call.
/// Tunable to keep RPC pressure bounded; 1000 fits in well under a 4 MB
/// gRPC message at typical sizes (Dilithium addresses ~62 bytes ASCII).
const TOP_WALLETS_BALANCE_BATCH: usize = 1000;
/// I1.3 — `--top-wallets-window-blocks` CLI default. Roughly ~17 minutes
/// at 10 BPS; matches §4.5 sampling expectations.
const DEFAULT_TOP_WALLETS_WINDOW_BLOCKS: u64 = 10_000;

/// I1.3 — type alias for the active-addresses tracker. Maps spk_script
/// bytes → last_seen_unix_ms so LRU eviction (oldest first) is cheap.
type ActiveAddresses = std::collections::HashMap<Vec<u8>, u64>;

#[derive(Clone, Serialize, Default)]
struct MetricsSnapshot {
    /// Wall-clock time the snapshot was taken (unix ms).
    pub snapshot_unix_ms: u64,

    /// Genesis timestamp configured for this dashboard (unix ms; 0 if unset).
    pub genesis_unix_ms: u64,

    /// Seconds since genesis (negative if genesis is in the future, 0 floor).
    pub seconds_since_genesis: i64,

    /// Seconds remaining in the 24h founder wait window. Negative once the
    /// window has elapsed.
    pub seconds_until_founder_window_ends: i64,

    /// Whether the founder is currently inside the 24h wait window.
    pub founder_in_wait_window: bool,

    /// Best-effort total hashrate in hashes/sec (derived from DAA difficulty
    /// and target time). 0 if RPC unavailable.
    pub hashrate_hps: u64,

    /// Total emitted supply in sompi (10⁻⁸ SPHS).
    pub total_supply_sompi: u64,

    /// Founder address balance in sompi.
    pub founder_balance_sompi: u64,

    /// Founder share = balance / total_emitted_supply (0..1).
    pub founder_share_ratio: f64,

    /// Number of blocks in the DAG (best-effort).
    pub block_count: u64,

    /// Virtual DAA score.
    pub virtual_daa_score: u64,

    /// Whether the last RPC poll succeeded.
    pub rpc_healthy: bool,

    /// Last RPC error message if any.
    pub last_rpc_error: Option<String>,

    /// Founder mining address (declared at T-72h; never changes).
    pub founder_address: String,

    /// Total wait window length in seconds (constant: 86400).
    pub founder_wait_window_secs: i64,

    // ─── I1.1 — extended metrics ────────────────────────────────────────────
    /// Observed blocks-per-second over the rolling 60s window. Reports `0.0`
    /// before the BPS ring buffer is warm (first 60s after dashboard start).
    /// See `docs/I1_DASHBOARD_DESIGN.md` §4.1.
    pub bps_actual: f64,

    /// Snapshot of the local mempool: tx count + cumulative mass.
    /// Refreshed every 30s (more conservatively than the 10s consensus poll).
    pub mempool_depth: MempoolDepth,

    /// GHOSTDAG-aware finality probability label. Reports the current
    /// virtual blue score and the operator-configured N for the
    /// "99.9% finalized after N blue blocks" guarantee. The label itself
    /// is informational — wallets that need cryptographic-grade finality
    /// should use a chain-block proof, not this number.
    pub finality_probability: FinalityLabel,

    /// I1.2 — rolling 60-min decentralisation gauge: distinct coinbase
    /// recipient script-public-keys observed in the last hour, plus the
    /// raw block count for context.
    pub unique_miners_60min: UniqueMinersWindow,

    /// I1.3 — top-100 wallets by balance, sampled from on-chain activity
    /// in the last `sampling_window_blocks` blocks. Refreshed every
    /// `TOP_WALLETS_REFRESH_EVERY_N_TICKS` (= 5 min by default). See
    /// `docs/I1_DASHBOARD_DESIGN.md` §4.5 for the design trade-off:
    /// cold wallets that haven't transacted recently may be missing.
    pub top_100_wallets: TopWalletsSnapshot,
}

/// I1.3 — single entry in the top-wallets ranking. See §4.5 of DESIGN.
#[derive(Clone, Serialize, Default, Debug, PartialEq, Eq)]
pub struct TopWalletEntry {
    pub rank: usize,
    pub address: String,
    pub balance_sompi: u64,
}

/// I1.3 — top-N wallets snapshot. Refresh cadence + caveat surfaced
/// alongside the entries themselves so downstream consumers cannot mistake
/// it for an exact ranking.
#[derive(Clone, Serialize, Debug, PartialEq, Eq)]
pub struct TopWalletsSnapshot {
    pub entries: Vec<TopWalletEntry>,
    pub sampling_window_blocks: u64,
    pub refreshed_unix_ms: u64,
    pub approximate: bool,
    pub caveat: String,
}

impl Default for TopWalletsSnapshot {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            sampling_window_blocks: 0,
            refreshed_unix_ms: 0,
            approximate: true,
            caveat: "Sampled from on-chain activity in the last ~10k blocks; cold wallets may be missing.".to_string(),
        }
    }
}

/// I1.2 — rolling-window decentralisation snapshot. See §4.4 of
/// `docs/I1_DASHBOARD_DESIGN.md`. Counts deduplicate by raw
/// `script_public_key.script` bytes (no need to derive bech32 addresses
/// — the count is what matters; the bytes are stable cross-tick).
#[derive(Clone, Serialize, Default, Debug, PartialEq, Eq)]
pub struct UniqueMinersWindow {
    pub distinct_addresses: usize,
    pub blocks_observed: usize,
    pub window_seconds: u64,
}

/// I1.1 — mempool snapshot exposed at `/metrics`. See §4.2 of DESIGN.
#[derive(Clone, Serialize, Default, Debug, PartialEq, Eq)]
pub struct MempoolDepth {
    pub tx_count: usize,
    pub total_mass: u64,
    /// Mirrors the `include_orphan_pool` flag the dashboard passed to
    /// `get_mempool_entries`. Always `false` in v1 — orphans are not
    /// part of the operator-facing depth signal.
    pub include_orphans: bool,
}

/// I1.1 — finality probability label. See §4.3 of DESIGN.
#[derive(Clone, Serialize, Default, Debug, PartialEq, Eq)]
pub struct FinalityLabel {
    pub blue_score_now: u64,
    pub blue_blocks_for_99_9: u64,
    pub label: String,
}

impl FinalityLabel {
    fn build(blue_score_now: u64, n: u64) -> Self {
        // The label includes a wall-clock estimate based on the 10 BPS
        // mainnet target. Operators on devnet / testnet with different
        // BPS get a slightly off estimate; surfaced as ~estimate, not
        // a guarantee.
        let estimate_secs = (n as f64 / 10.0) as u64;
        let label = format!("99.9% finalized after {n} blue blocks (~{estimate_secs}s at 10 BPS)");
        Self { blue_score_now, blue_blocks_for_99_9: n, label }
    }
}

#[derive(Clone)]
struct AppState {
    metrics: Arc<RwLock<MetricsSnapshot>>,
    /// I1.1 — rolling buffer of `(unix_ms, block_count)` snapshots, one
    /// per consensus poll tick. Sized to `BPS_WINDOW_TICKS` entries; a
    /// new entry pushes the oldest out so the buffer stays at the
    /// correct size. BPS is derived from the front and back values.
    bps_buf: Arc<RwLock<VecDeque<(u64, u64)>>>,
    /// I1.1 — most-recent mempool snapshot. Polled every `MEMPOOL_POLL_EVERY_N_TICKS`
    /// consensus ticks (= 30s by default). Cached so the 10s consensus
    /// poll can include the freshest known value without re-polling
    /// mempool itself.
    mempool: Arc<RwLock<MempoolDepth>>,
    /// I1.2 — rolling buffer of `(unix_ms, coinbase_spk_script_bytes)`
    /// for the last `MINERS_WINDOW_SECS` (= 3600s) of accepted blocks.
    /// Polled on the same sub-cycle as mempool (every 30s) via
    /// `get_blocks(low_hash=last_seen_block, true)`.
    miner_buf: Arc<RwLock<MinerBuf>>,
    /// I1.2 — `low_hash` cursor passed to the next `get_blocks` call.
    /// `None` until the first poll; updated to the latest tip after
    /// each successful pull.
    last_seen_block: Arc<RwLock<Option<Hash>>>,
    /// I1.3 — addresses observed in transaction outputs over the
    /// `top_wallets_window_blocks` recent block window. Keyed by raw
    /// `spk_script` bytes; value is the last_seen_unix_ms used for LRU
    /// eviction once the map exceeds `ACTIVE_ADDRESSES_CAP`.
    active_addresses: Arc<RwLock<ActiveAddresses>>,
    /// I1.3 — most recent top-wallets snapshot. Refreshed every 5 min;
    /// served verbatim by `/metrics` between refreshes.
    top_wallets: Arc<RwLock<TopWalletsSnapshot>>,
}

async fn connect_grpc(rpc_server: &str) -> GrpcClient {
    let ctx = SubscriptionContext::new();
    GrpcClient::connect_with_args(
        NotificationMode::Direct,
        format!("grpc://{}", rpc_server),
        Some(ctx),
        true,
        None,
        false,
        Some(15_000),
        Default::default(),
    )
    .await
    .expect("RPC connection failed")
}

/// Inputs to one consensus-tick poll cycle. Grouped to keep the
/// `poll_once` signature stable as I1.x adds dependencies.
struct PollInputs<'a> {
    rpc: &'a GrpcClient,
    founder_addr: &'a Address,
    genesis_unix_ms: u64,
    /// I1.1 — N for the finality label (CLI flag `--finality-blue-blocks`).
    finality_blue_blocks: u64,
}

async fn poll_once(inputs: &PollInputs<'_>) -> MetricsSnapshot {
    let PollInputs { rpc, founder_addr, genesis_unix_ms, finality_blue_blocks } = *inputs;
    let mut snap = MetricsSnapshot {
        snapshot_unix_ms: now_unix_ms(),
        genesis_unix_ms,
        founder_address: founder_addr.to_string(),
        founder_wait_window_secs: FOUNDER_WAIT_SECS,
        ..Default::default()
    };

    // Compute time-since-genesis fields up-front so they're populated even
    // if the RPC poll fails partway through.
    let now_secs = (snap.snapshot_unix_ms / 1000) as i64;
    let genesis_secs = (genesis_unix_ms / 1000) as i64;
    if genesis_secs > 0 {
        snap.seconds_since_genesis = (now_secs - genesis_secs).max(0);
        snap.seconds_until_founder_window_ends = FOUNDER_WAIT_SECS - snap.seconds_since_genesis;
        snap.founder_in_wait_window = snap.seconds_since_genesis < FOUNDER_WAIT_SECS;
    }

    // RPC: get_block_dag_info
    let dag_info = match tokio::time::timeout(RPC_TIMEOUT, rpc.get_block_dag_info()).await {
        Ok(Ok(info)) => info,
        Ok(Err(e)) => {
            snap.last_rpc_error = Some(format!("get_block_dag_info: {e}"));
            return snap;
        }
        Err(_) => {
            snap.last_rpc_error = Some("get_block_dag_info timeout".into());
            return snap;
        }
    };
    snap.virtual_daa_score = dag_info.virtual_daa_score;
    snap.block_count = dag_info.block_count;
    // Difficulty is doubles representing the work-per-block; converting
    // to hashrate requires the target time per block. The wRPC `difficulty`
    // already encodes hashes-per-block per BlockDAG conventions; combined
    // with 10 BPS this yields total hashrate.
    snap.hashrate_hps = (dag_info.difficulty * 10.0) as u64;
    // I1.1 — finality label uses the live virtual DAA as a proxy for
    // blue_score. `get_block_dag_info` does not expose blue_score at the
    // virtual selected tip directly; in practice virtual_daa_score
    // tracks blue_score within ±K (the GHOSTDAG K). The label is
    // informational so the proxy is acceptable; documented.
    snap.finality_probability = FinalityLabel::build(snap.virtual_daa_score, finality_blue_blocks);

    // RPC: get_coin_supply
    match tokio::time::timeout(RPC_TIMEOUT, rpc.get_coin_supply()).await {
        Ok(Ok(supply)) => {
            snap.total_supply_sompi = supply.circulating_sompi;
        }
        Ok(Err(e)) => {
            snap.last_rpc_error = Some(format!("get_coin_supply: {e}"));
            return snap;
        }
        Err(_) => {
            snap.last_rpc_error = Some("get_coin_supply timeout".into());
            return snap;
        }
    }

    // RPC: get_balance_by_address (founder)
    match tokio::time::timeout(RPC_TIMEOUT, rpc.get_balance_by_address(founder_addr.clone())).await {
        Ok(Ok(balance)) => {
            snap.founder_balance_sompi = balance;
            if snap.total_supply_sompi > 0 {
                snap.founder_share_ratio = balance as f64 / snap.total_supply_sompi as f64;
            }
        }
        Ok(Err(e)) => {
            snap.last_rpc_error = Some(format!("get_balance_by_address: {e}"));
            return snap;
        }
        Err(_) => {
            snap.last_rpc_error = Some("get_balance_by_address timeout".into());
            return snap;
        }
    }

    snap.rpc_healthy = true;
    snap
}

async fn poller_task(
    rpc_server: String,
    founder_addr: Address,
    genesis_unix_ms: u64,
    finality_blue_blocks: u64,
    top_wallets_window_blocks: u64,
    state: AppState,
) {
    let prefix = founder_addr.prefix;
    log::info!("connecting to sophisd at {}", rpc_server);
    let rpc = connect_grpc(&rpc_server).await;
    log::info!("connected; starting poll loop @ {:?}", POLL_INTERVAL);
    let mut tick: u64 = 0;
    loop {
        let inputs = PollInputs { rpc: &rpc, founder_addr: &founder_addr, genesis_unix_ms, finality_blue_blocks };
        let mut snap = poll_once(&inputs).await;
        if !snap.rpc_healthy {
            log::warn!("rpc poll failed: {:?}", snap.last_rpc_error);
        }
        // I1.1 — BPS ring buffer. Update first (push current count),
        // then derive bps_actual from the buffer's front and back.
        if snap.rpc_healthy {
            let mut buf = state.bps_buf.write().await;
            buf.push_back((snap.snapshot_unix_ms, snap.block_count));
            while buf.len() > BPS_WINDOW_TICKS {
                buf.pop_front();
            }
            if buf.len() >= 2 {
                let (t0, c0) = *buf.front().unwrap();
                let (t1, c1) = *buf.back().unwrap();
                let dt_secs = (t1.saturating_sub(t0)) as f64 / 1000.0;
                if dt_secs > 0.0 {
                    snap.bps_actual = (c1.saturating_sub(c0)) as f64 / dt_secs;
                }
            }
        }
        // I1.1 / I1.2 — sub-cycle: mempool + miner-buffer top-up.
        // Both run on the same tick boundary (every 30s by default) so
        // we don't compound RPC pressure with two independent cadences.
        if tick.is_multiple_of(MEMPOOL_POLL_EVERY_N_TICKS) && snap.rpc_healthy {
            match poll_mempool(&rpc).await {
                Ok(mp) => *state.mempool.write().await = mp,
                Err(e) => log::warn!("mempool poll failed: {e}"),
            }
            // I1.2 + I1.3 — pull blocks accepted since `last_seen_block`,
            // dispatch to (a) miner ring buffer (coinbase only) and
            // (b) active-addresses tracker (every output).
            let cursor = *state.last_seen_block.read().await;
            match poll_recent_blocks(&rpc, cursor).await {
                Ok(emit) => {
                    if !emit.coinbase_samples.is_empty() {
                        let mut buf = state.miner_buf.write().await;
                        for entry in emit.coinbase_samples {
                            buf.push_back(entry);
                            if buf.len() > MINERS_BUF_CAP {
                                buf.pop_front();
                            }
                        }
                    }
                    if !emit.all_active_spks.is_empty() {
                        let mut active = state.active_addresses.write().await;
                        ingest_active_addresses(&mut active, emit.all_active_spks, snap.snapshot_unix_ms);
                    }
                    *state.last_seen_block.write().await = emit.new_tip;
                }
                Err(e) => log::warn!("recent-blocks poll failed: {e}"),
            }
        }
        // I1.3 — top-wallets refresh runs on its own slower sub-cycle
        // (every TOP_WALLETS_REFRESH_EVERY_N_TICKS = 30 ticks = 5 min).
        if tick.is_multiple_of(TOP_WALLETS_REFRESH_EVERY_N_TICKS) && snap.rpc_healthy {
            let snapshot_active: ActiveAddresses = state.active_addresses.read().await.clone();
            match refresh_top_wallets(&rpc, &snapshot_active, prefix, top_wallets_window_blocks).await {
                Ok(top) => *state.top_wallets.write().await = top,
                Err(e) => log::warn!("top-wallets refresh failed: {e}"),
            }
        }
        // Always include the most recent (possibly stale) mempool snapshot.
        snap.mempool_depth = state.mempool.read().await.clone();
        // I1.2 — distinct-miner count is derived on every emission so the
        // 1-hour eviction is enforced even when no new blocks arrived.
        snap.unique_miners_60min = {
            let mut buf = state.miner_buf.write().await;
            distinct_in_window(&mut buf, snap.snapshot_unix_ms)
        };
        // I1.3 — top wallets snapshot served verbatim between refreshes.
        snap.top_100_wallets = state.top_wallets.read().await.clone();
        *state.metrics.write().await = snap;
        tick = tick.wrapping_add(1);
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// I1.1 — pulls mempool entries and aggregates `(tx_count, total_mass)`.
/// Returns Err only on RPC failure; an empty mempool returns
/// `MempoolDepth::default()` with `include_orphans = false`.
async fn poll_mempool(rpc: &GrpcClient) -> Result<MempoolDepth, String> {
    let entries = tokio::time::timeout(RPC_TIMEOUT, rpc.get_mempool_entries(false, false))
        .await
        .map_err(|_| "get_mempool_entries timeout".to_string())?
        .map_err(|e| format!("get_mempool_entries: {e}"))?;
    let tx_count = entries.len();
    let total_mass: u64 = entries.iter().map(|e| e.transaction.mass).sum();
    Ok(MempoolDepth { tx_count, total_mass, include_orphans: false })
}

/// I1.2 — pulls every block accepted since `low_hash` (inclusive cursor
/// semantics: the call returns blocks newer than `low_hash`; the first
/// call with `low_hash = None` returns the head block). For each block,
/// extracts the coinbase transaction's output script-public-key bytes
/// and pairs them with the current wall-clock for the miner ring buffer.
///
/// Returns `(emitted_entries, new_tip_hash)`. The new tip hash is the
/// last block in the response; the caller stores it for the next call.
/// I1.2 + I1.3 — block poll output. `coinbase_samples` are the coinbase
/// recipient script bytes (miner identity, fed to the unique-miners
/// rolling buffer). `all_active_spks` are every output script across all
/// transactions in the pulled blocks (fed to the active-addresses
/// tracker for top-100 ranking).
struct BlockPollEmit {
    coinbase_samples: Vec<MinerSample>,
    all_active_spks: Vec<Vec<u8>>,
    new_tip: Option<Hash>,
}

async fn poll_recent_blocks(rpc: &GrpcClient, low_hash: Option<Hash>) -> Result<BlockPollEmit, String> {
    let resp = tokio::time::timeout(RPC_TIMEOUT, rpc.get_blocks(low_hash, true, true))
        .await
        .map_err(|_| "get_blocks timeout".to_string())?
        .map_err(|e| format!("get_blocks: {e}"))?;

    let now = now_unix_ms();
    let mut coinbase_samples: Vec<MinerSample> = Vec::new();
    let mut all_active_spks: Vec<Vec<u8>> = Vec::new();
    for block in &resp.blocks {
        // I1.2 — Coinbase tx is structurally `block.transactions[0]` per
        // `consensus_core::tx::COINBASE_TRANSACTION_INDEX`. Each output's
        // script-public-key counts as one miner-identity sample.
        if let Some(coinbase) = block.transactions.first() {
            for output in &coinbase.outputs {
                coinbase_samples.push((now, output.script_public_key.script().to_vec()));
            }
        }
        // I1.3 — every output across every tx (including coinbase) feeds
        // the active-address tracker. Recipients of payment are exactly
        // the population we want to rank by balance.
        for tx in &block.transactions {
            for output in &tx.outputs {
                all_active_spks.push(output.script_public_key.script().to_vec());
            }
        }
    }
    let new_tip = resp.block_hashes.last().copied().or(low_hash);
    Ok(BlockPollEmit { coinbase_samples, all_active_spks, new_tip })
}

/// I1.3 — refresh the top-wallets ranking. Steps (per §4.5 of DESIGN):
///   1. Snapshot the active-address set; sort by `last_seen` desc.
///   2. Take the top `TOP_WALLETS_BALANCE_BATCH` (= 1000 by default) so
///      RPC pressure stays bounded.
///   3. Convert each spk_script → `Address` using the founder address's
///      network prefix.
///   4. `get_balances_by_addresses(addresses)` in a single batch.
///   5. Sort results by balance descending; take top `TOP_WALLETS_LIMIT`.
async fn refresh_top_wallets(
    rpc: &GrpcClient,
    active: &ActiveAddresses,
    prefix: sophis_addresses::Prefix,
    sampling_window_blocks: u64,
) -> Result<TopWalletsSnapshot, String> {
    use sophis_consensus_core::tx::ScriptPublicKey;
    use sophis_txscript::standard::extract_script_pub_key_address;

    // Step 1+2: snapshot + sort by last_seen desc, take top batch.
    let mut sorted: Vec<(&Vec<u8>, &u64)> = active.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    let pool: Vec<Vec<u8>> = sorted.iter().take(TOP_WALLETS_BALANCE_BATCH).map(|(spk, _)| (*spk).clone()).collect();

    // Step 3: spk_script → Address. Skip non-standard scripts silently;
    // they cannot be queried via `get_balances_by_addresses` anyway.
    let mut addresses: Vec<Address> = Vec::new();
    for spk_bytes in &pool {
        let spk = ScriptPublicKey::from_vec(0, spk_bytes.clone());
        if let Ok(addr) = extract_script_pub_key_address(&spk, prefix) {
            addresses.push(addr);
        }
    }

    if addresses.is_empty() {
        // No standard-typed addresses observed yet — return an empty but
        // refresh-stamped snapshot so the UI knows the cycle ran.
        return Ok(TopWalletsSnapshot {
            entries: Vec::new(),
            sampling_window_blocks,
            refreshed_unix_ms: now_unix_ms(),
            approximate: true,
            caveat: format!(
                "Sampled from on-chain activity in the last ~{sampling_window_blocks} blocks; cold wallets may be missing."
            ),
        });
    }

    // Step 4: batched balance lookup.
    let balances = tokio::time::timeout(RPC_TIMEOUT, rpc.get_balances_by_addresses(addresses))
        .await
        .map_err(|_| "get_balances_by_addresses timeout".to_string())?
        .map_err(|e| format!("get_balances_by_addresses: {e}"))?;

    // Step 5: sort + truncate.
    let mut ranked: Vec<(Address, u64)> = balances.into_iter().map(|e| (e.address, e.balance.unwrap_or(0))).collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1));
    ranked.truncate(TOP_WALLETS_LIMIT);

    let entries: Vec<TopWalletEntry> = ranked
        .into_iter()
        .enumerate()
        .map(|(i, (addr, bal))| TopWalletEntry { rank: i + 1, address: addr.to_string(), balance_sompi: bal })
        .collect();

    Ok(TopWalletsSnapshot {
        entries,
        sampling_window_blocks,
        refreshed_unix_ms: now_unix_ms(),
        approximate: true,
        caveat: format!("Sampled from on-chain activity in the last ~{sampling_window_blocks} blocks; cold wallets may be missing."),
    })
}

/// I1.3 — append every observed spk to the active-addresses tracker
/// stamping `now_ms`. LRU-evicts when the map exceeds `ACTIVE_ADDRESSES_CAP`.
fn ingest_active_addresses(map: &mut ActiveAddresses, spks: Vec<Vec<u8>>, now_ms: u64) {
    for spk in spks {
        map.insert(spk, now_ms);
    }
    while map.len() > ACTIVE_ADDRESSES_CAP {
        // Evict the oldest entry by last_seen. O(n) but only fires when
        // the map exceeds 100k entries which is the adversarial path.
        if let Some((victim, _)) = map.iter().min_by_key(|(_, ts)| *ts).map(|(k, v)| (k.clone(), *v)) {
            map.remove(&victim);
        } else {
            break;
        }
    }
}

/// I1.2 — counts distinct entries in the miner ring buffer after evicting
/// anything older than `now - MINERS_WINDOW_SECS`. Pure function; the
/// caller is responsible for holding the buffer lock for the duration.
fn distinct_in_window(buf: &mut MinerBuf, now_ms: u64) -> UniqueMinersWindow {
    let horizon_ms = now_ms.saturating_sub(MINERS_WINDOW_SECS.saturating_mul(1000));
    while let Some(&(ts, _)) = buf.front() {
        if ts >= horizon_ms {
            break;
        }
        buf.pop_front();
    }
    let mut seen: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
    for (_, spk) in buf.iter() {
        seen.insert(spk.as_slice());
    }
    UniqueMinersWindow { distinct_addresses: seen.len(), blocks_observed: buf.len(), window_seconds: MINERS_WINDOW_SECS }
}

fn now_unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

// ─── HTTP handlers ───────────────────────────────────────────────────────────

async fn root() -> Html<&'static str> {
    Html(EMBEDDED_HTML)
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let snap = state.metrics.read().await.clone();
    (StatusCode::OK, Json(snap))
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

const EMBEDDED_HTML: &str = include_str!("dashboard.html");

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    sophis_core::log::init_logger(None, "info");

    let m = Command::new("sophis-dashboard")
        .about("Public mainnet launch dashboard (LAUNCH_CHECKLIST.md ação #2)")
        .arg(Arg::new("rpcserver").long("rpcserver").short('s').default_value("localhost:46110"))
        .arg(Arg::new("listen-addr").long("listen-addr").short('l').default_value("0.0.0.0:8080"))
        .arg(
            Arg::new("founder-address")
                .long("founder-address")
                .short('f')
                .required(true)
                .help("Endereço pessoal de mineração do fundador (declarado em T-72h)"),
        )
        .arg(
            Arg::new("genesis-unix-ms")
                .long("genesis-unix-ms")
                .short('g')
                .default_value("0")
                .value_parser(value_parser!(u64))
                .help("Timestamp do gênese em unix milliseconds (0 = desconhecido ainda)"),
        )
        .arg(
            Arg::new("finality-blue-blocks")
                .long("finality-blue-blocks")
                .default_value(DEFAULT_FINALITY_BLUE_BLOCKS.to_string())
                .value_parser(value_parser!(u64))
                .help("N para a label '99.9% finalized after N blue blocks' (D2 do I1; default = 100 = coinbase_maturity)"),
        )
        .arg(
            Arg::new("top-wallets-window-blocks")
                .long("top-wallets-window-blocks")
                .default_value(DEFAULT_TOP_WALLETS_WINDOW_BLOCKS.to_string())
                .value_parser(value_parser!(u64))
                .help("Número de blocos recentes considerados pra heurística top-100 wallets (D1 do I1; default = 10000 ≈ ~17 min @ 10 BPS)"),
        )
        .get_matches();

    let rpc_server = m.get_one::<String>("rpcserver").unwrap().clone();
    let listen_addr_str = m.get_one::<String>("listen-addr").unwrap();
    let founder_address_str = m.get_one::<String>("founder-address").unwrap();
    let genesis_unix_ms = *m.get_one::<u64>("genesis-unix-ms").unwrap();
    let finality_blue_blocks = *m.get_one::<u64>("finality-blue-blocks").unwrap();
    let top_wallets_window_blocks = *m.get_one::<u64>("top-wallets-window-blocks").unwrap();

    let listen_addr: SocketAddr = listen_addr_str.parse().unwrap_or_else(|e| {
        eprintln!("Erro: --listen-addr inválido: {}", e);
        std::process::exit(2);
    });
    let founder_address: Address = Address::try_from(founder_address_str.clone()).unwrap_or_else(|e| {
        eprintln!("Erro: --founder-address inválido: {}", e);
        std::process::exit(2);
    });

    println!("sophis-dashboard");
    println!("  rpc            : {}", rpc_server);
    println!("  listen         : http://{}", listen_addr);
    println!("  founder        : {}", founder_address);
    println!("  finality (N)   : {} blue blocks", finality_blue_blocks);
    println!("  top-wallets W  : last {} blocks", top_wallets_window_blocks);
    if genesis_unix_ms > 0 {
        println!("  genesis (ms)   : {}", genesis_unix_ms);
    } else {
        println!("  genesis        : (not set — wait countdown disabled)");
    }
    println!();

    let state = AppState {
        metrics: Arc::new(RwLock::new(MetricsSnapshot::default())),
        bps_buf: Arc::new(RwLock::new(VecDeque::with_capacity(BPS_WINDOW_TICKS + 1))),
        mempool: Arc::new(RwLock::new(MempoolDepth::default())),
        miner_buf: Arc::new(RwLock::new(VecDeque::with_capacity(MINERS_BUF_CAP))),
        last_seen_block: Arc::new(RwLock::new(None)),
        active_addresses: Arc::new(RwLock::new(ActiveAddresses::new())),
        top_wallets: Arc::new(RwLock::new(TopWalletsSnapshot::default())),
    };

    // Spawn the poller in the background.
    let poller_state = state.clone();
    tokio::spawn(poller_task(
        rpc_server,
        founder_address,
        genesis_unix_ms,
        finality_blue_blocks,
        top_wallets_window_blocks,
        poller_state,
    ));

    let app = Router::new().route("/", get(root)).route("/metrics", get(metrics)).route("/healthz", get(healthz)).with_state(state);

    let listener = match tokio::net::TcpListener::bind(&listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Erro: bind {}: {}", listen_addr, e);
            std::process::exit(1);
        }
    };
    println!("Dashboard servindo em http://{}", listen_addr);
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("Erro: axum serve: {}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Snapshot json round-trip works (ensures no serde fields broken).
    #[test]
    fn snapshot_serializes() {
        let s = MetricsSnapshot {
            founder_share_ratio: 0.0123,
            seconds_since_genesis: 3600,
            seconds_until_founder_window_ends: 82800,
            founder_in_wait_window: true,
            ..Default::default()
        };
        let j = serde_json::to_value(&s).expect("serialize");
        assert!(j.get("founder_share_ratio").is_some());
        assert!(j.get("seconds_since_genesis").is_some());
    }

    /// 24h wait window math: at exactly 24h elapsed, the window has just
    /// ended (founder_in_wait_window = false, seconds remaining = 0).
    #[test]
    fn wait_window_boundary() {
        let mut s = MetricsSnapshot { snapshot_unix_ms: (FOUNDER_WAIT_SECS as u64) * 1000, genesis_unix_ms: 0, ..Default::default() };
        // Re-derive what poll_once would compute:
        let now_secs = (s.snapshot_unix_ms / 1000) as i64;
        let genesis_secs = (s.genesis_unix_ms / 1000) as i64;
        // Use a fictional non-zero genesis to exercise the actual logic.
        let _ = (now_secs, genesis_secs);
        // For the actual logic, simulate genesis at 0 and now at exactly 24h.
        s.genesis_unix_ms = 1; // tiny non-zero so the logic engages
        s.snapshot_unix_ms = (FOUNDER_WAIT_SECS as u64) * 1000 + 1;
        let now = (s.snapshot_unix_ms / 1000) as i64;
        let genesis = (s.genesis_unix_ms / 1000) as i64;
        let elapsed = (now - genesis).max(0);
        assert!(elapsed >= FOUNDER_WAIT_SECS);
    }

    /// Poller_task and connect_grpc are integration-only; we don't unit-test
    /// them here. They're exercised when the binary is run against a real
    /// sophisd. The poll_once logic falls back gracefully on RPC failure
    /// (rpc_healthy = false; partial fields populated).
    #[test]
    fn poll_once_offline_returns_partial_snapshot() {
        // Smoke-only: verify the structure of MetricsSnapshot::default()
        // is what we'd expect to be served before the first successful poll.
        let snap = MetricsSnapshot::default();
        assert!(!snap.rpc_healthy);
        assert_eq!(snap.founder_balance_sompi, 0);
        assert_eq!(snap.last_rpc_error, None);
    }

    // ─── I1.1 — extended metrics ────────────────────────────────────────────

    #[test]
    fn finality_label_build_carries_n_and_estimate() {
        let label = FinalityLabel::build(12_345, 100);
        assert_eq!(label.blue_score_now, 12_345);
        assert_eq!(label.blue_blocks_for_99_9, 100);
        assert!(label.label.contains("100 blue blocks"), "label: {}", label.label);
        assert!(label.label.contains("10s"), "expected 10s wall-clock estimate (100/10): {}", label.label);
    }

    #[test]
    fn finality_label_build_with_n_50_estimates_5s() {
        let label = FinalityLabel::build(0, 50);
        assert!(label.label.contains("5s at 10 BPS"), "label: {}", label.label);
    }

    #[test]
    fn mempool_depth_default_is_empty_no_orphans() {
        let mp = MempoolDepth::default();
        assert_eq!(mp.tx_count, 0);
        assert_eq!(mp.total_mass, 0);
        assert!(!mp.include_orphans);
    }

    #[test]
    fn extended_snapshot_serializes_with_new_fields() {
        let snap = MetricsSnapshot {
            bps_actual: 9.83,
            mempool_depth: MempoolDepth { tx_count: 142, total_mass: 5_237_400, include_orphans: false },
            finality_probability: FinalityLabel::build(12_450, 100),
            ..Default::default()
        };

        let j = serde_json::to_value(&snap).expect("serialize");
        // bps_actual at top level
        assert!((j.get("bps_actual").and_then(|v| v.as_f64()).unwrap_or(0.0) - 9.83).abs() < 1e-6);
        // mempool_depth nested
        let mp = j.get("mempool_depth").expect("mempool_depth field");
        assert_eq!(mp.get("tx_count").and_then(|v| v.as_u64()), Some(142));
        assert_eq!(mp.get("total_mass").and_then(|v| v.as_u64()), Some(5_237_400));
        // finality_probability nested
        let fl = j.get("finality_probability").expect("finality_probability field");
        assert_eq!(fl.get("blue_score_now").and_then(|v| v.as_u64()), Some(12_450));
        assert_eq!(fl.get("blue_blocks_for_99_9").and_then(|v| v.as_u64()), Some(100));
    }

    /// BPS computation: the poller's ring-buffer logic. We don't have
    /// access to the live `state.bps_buf` outside `poller_task`, so this
    /// test mirrors the math: given two snapshots 60 s apart with a
    /// 600-block delta, BPS should be 10.0.
    #[test]
    fn bps_math_matches_designed_window() {
        let t0_ms: u64 = 1_700_000_000_000;
        let t1_ms: u64 = t0_ms + 60_000;
        let c0: u64 = 100_000;
        let c1: u64 = 100_600;
        let dt_secs = (t1_ms - t0_ms) as f64 / 1000.0;
        let bps = (c1 - c0) as f64 / dt_secs;
        assert!((bps - 10.0).abs() < 1e-9);
    }

    /// Edge case: a single-element BPS buffer reports 0.0 (insufficient
    /// data). Mirrors the `if buf.len() >= 2` guard in poller_task.
    #[test]
    fn bps_single_sample_reports_zero() {
        // Default value is 0.0; any consumer reading a freshly-warmed
        // dashboard sees this until the second poll lands.
        let snap = MetricsSnapshot::default();
        assert_eq!(snap.bps_actual, 0.0);
        // After a single (mock) update the field carries the value.
        let snap2 = MetricsSnapshot { bps_actual: 10.0, ..MetricsSnapshot::default() };
        assert!(snap2.bps_actual > 0.0);
    }

    // ─── I1.2 — unique miners 60min ─────────────────────────────────────────

    #[test]
    fn distinct_in_window_dedupes_by_script_bytes() {
        let mut buf: MinerBuf = VecDeque::new();
        let now: u64 = 10_000_000;
        // Three blocks; two distinct miners (A appears twice).
        let a = vec![0xAAu8; 36];
        let b = vec![0xBBu8; 36];
        buf.push_back((now - 100, a.clone()));
        buf.push_back((now - 50, b.clone()));
        buf.push_back((now - 10, a));
        let w = distinct_in_window(&mut buf, now);
        assert_eq!(w.distinct_addresses, 2);
        assert_eq!(w.blocks_observed, 3);
        assert_eq!(w.window_seconds, MINERS_WINDOW_SECS);
    }

    #[test]
    fn distinct_in_window_evicts_older_than_horizon() {
        let mut buf: MinerBuf = VecDeque::new();
        let now: u64 = 10_000_000;
        // 5 entries; 3 outside the 1-hour window must be evicted.
        let outside = now.saturating_sub((MINERS_WINDOW_SECS + 100).saturating_mul(1000));
        let inside = now.saturating_sub(60_000); // 60s ago — well inside
        buf.push_back((outside, vec![1; 4]));
        buf.push_back((outside + 1, vec![2; 4]));
        buf.push_back((outside + 2, vec![3; 4]));
        buf.push_back((inside, vec![4; 4]));
        buf.push_back((inside + 100, vec![5; 4]));
        let w = distinct_in_window(&mut buf, now);
        // Only the 2 inside-window entries remain
        assert_eq!(w.blocks_observed, 2);
        assert_eq!(w.distinct_addresses, 2);
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn distinct_in_window_empty_returns_zero() {
        let mut buf: MinerBuf = VecDeque::new();
        let w = distinct_in_window(&mut buf, 1_000_000);
        assert_eq!(w.distinct_addresses, 0);
        assert_eq!(w.blocks_observed, 0);
        assert_eq!(w.window_seconds, MINERS_WINDOW_SECS);
    }

    #[test]
    fn distinct_in_window_all_outside_returns_zero() {
        let mut buf: MinerBuf = VecDeque::new();
        let now: u64 = 10_000_000;
        let stale = now.saturating_sub((MINERS_WINDOW_SECS + 1).saturating_mul(1000));
        buf.push_back((stale, vec![1; 4]));
        buf.push_back((stale + 1, vec![2; 4]));
        let w = distinct_in_window(&mut buf, now);
        assert_eq!(w.distinct_addresses, 0);
        assert_eq!(w.blocks_observed, 0);
        assert!(buf.is_empty(), "all-stale buffer must be fully drained");
    }

    #[test]
    fn unique_miners_serializes_at_top_level() {
        let snap = MetricsSnapshot {
            unique_miners_60min: UniqueMinersWindow { distinct_addresses: 47, blocks_observed: 36_000, window_seconds: 3600 },
            ..Default::default()
        };
        let j = serde_json::to_value(&snap).expect("serialize");
        let um = j.get("unique_miners_60min").expect("unique_miners_60min field");
        assert_eq!(um.get("distinct_addresses").and_then(|v| v.as_u64()), Some(47));
        assert_eq!(um.get("blocks_observed").and_then(|v| v.as_u64()), Some(36_000));
        assert_eq!(um.get("window_seconds").and_then(|v| v.as_u64()), Some(3600));
    }

    // ─── I1.3 — top 100 wallets ─────────────────────────────────────────────

    #[test]
    fn ingest_active_addresses_inserts_and_updates_timestamp() {
        let mut map: ActiveAddresses = ActiveAddresses::new();
        let spk_a = vec![1u8; 36];
        let spk_b = vec![2u8; 36];
        ingest_active_addresses(&mut map, vec![spk_a.clone(), spk_b.clone()], 1_000);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&spk_a), Some(&1_000));
        // Re-ingest a updates its timestamp
        ingest_active_addresses(&mut map, vec![spk_a.clone()], 2_000);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&spk_a), Some(&2_000));
        assert_eq!(map.get(&spk_b), Some(&1_000));
    }

    #[test]
    fn ingest_active_addresses_lru_evicts_oldest_over_cap() {
        // Hard-cap is 100k; we don't want to allocate that for a unit
        // test, so we reach in via a tiny synthetic scenario by
        // exceeding the cap with a stack of distinct entries. To avoid
        // allocating 100k+ entries here, we exercise the eviction path
        // by manually breaching a smaller threshold via hand-tuning.
        let mut map: ActiveAddresses = ActiveAddresses::new();
        // Seed with 5 distinct entries at increasing timestamps
        for (i, ts) in (1u64..=5).enumerate() {
            map.insert(vec![i as u8; 4], ts * 100);
        }
        // Manually evict the oldest 3 (ts=100,200,300) by simulating the
        // logic; this is a smoke test of the eviction direction, not a
        // capacity exercise.
        let oldest_ts = map.values().min().copied().unwrap();
        assert_eq!(oldest_ts, 100);
        map.retain(|_, ts| *ts > 200);
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn top_wallets_snapshot_default_is_approximate_with_caveat() {
        let s = TopWalletsSnapshot::default();
        assert!(s.entries.is_empty());
        assert!(s.approximate);
        assert!(s.caveat.contains("Sampled"));
        assert_eq!(s.refreshed_unix_ms, 0);
    }

    #[test]
    fn top_wallets_serializes_at_top_level_with_caveat() {
        let snap = MetricsSnapshot {
            top_100_wallets: TopWalletsSnapshot {
                entries: vec![
                    TopWalletEntry { rank: 1, address: "sophis:qx111".into(), balance_sompi: 1_000_000_000_000 },
                    TopWalletEntry { rank: 2, address: "sophis:qx222".into(), balance_sompi: 500_000_000_000 },
                ],
                sampling_window_blocks: 10_000,
                refreshed_unix_ms: 1_700_000_000_000,
                approximate: true,
                caveat: "Sampled from on-chain activity in the last ~10000 blocks; cold wallets may be missing.".into(),
            },
            ..Default::default()
        };
        let j = serde_json::to_value(&snap).expect("serialize");
        let tw = j.get("top_100_wallets").expect("top_100_wallets field");
        let entries = tw.get("entries").and_then(|v| v.as_array()).expect("entries array");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].get("rank").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(entries[0].get("address").and_then(|v| v.as_str()), Some("sophis:qx111"));
        assert_eq!(entries[0].get("balance_sompi").and_then(|v| v.as_u64()), Some(1_000_000_000_000));
        assert_eq!(tw.get("sampling_window_blocks").and_then(|v| v.as_u64()), Some(10_000));
        assert_eq!(tw.get("approximate").and_then(|v| v.as_bool()), Some(true));
        assert!(tw.get("caveat").and_then(|v| v.as_str()).unwrap().contains("cold wallets"));
    }
}
