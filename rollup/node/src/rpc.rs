use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use std::sync::Arc;
use std::time::Instant;

use sophis_rollup_sequencer::Mempool;

pub struct NodeState {
    pub mempool: Arc<Mempool>,
    pub start_time: Instant,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct StatsResponse {
    mempool_size: usize,
    uptime_secs: u64,
    version: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok", version: env!("CARGO_PKG_VERSION") })
}

async fn stats(State(state): State<Arc<NodeState>>) -> Json<StatsResponse> {
    Json(StatsResponse {
        mempool_size: state.mempool.len(),
        uptime_secs: state.start_time.elapsed().as_secs(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Builds the full HTTP router: sequencer routes + node management routes.
///
/// Routes:
///   POST /submit_tx  — submit an L2 transaction (hex-encoded borsh L2Tx)
///   GET  /health     — liveness probe
///   GET  /stats      — mempool size + uptime
pub fn router(mempool: Arc<Mempool>, start_time: Instant) -> Router {
    let node_state = Arc::new(NodeState { mempool: mempool.clone(), start_time });
    let node_routes = Router::new().route("/health", get(health)).route("/stats", get(stats)).with_state(node_state);
    sophis_rollup_sequencer::rpc::router(mempool).merge(node_routes)
}
