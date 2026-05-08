use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::mempool::Mempool;
use sophis_rollup_core::L2Tx;

// ---------------------------------------------------------------------------
// HTTP API types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SubmitTxRequest {
    /// Hex-encoded borsh-serialized L2Tx.
    pub tx_hex: String,
}

#[derive(Serialize)]
pub struct SubmitTxResponse {
    pub txid: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

pub struct RpcState {
    pub mempool: Arc<Mempool>,
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

pub fn router(mempool: Arc<Mempool>) -> Router {
    Router::new().route("/submit_tx", post(handle_submit_tx)).with_state(Arc::new(RpcState { mempool }))
}

async fn handle_submit_tx(
    State(state): State<Arc<RpcState>>,
    Json(req): Json<SubmitTxRequest>,
) -> Result<Json<SubmitTxResponse>, (StatusCode, Json<ErrorResponse>)> {
    let bytes =
        hex::decode(&req.tx_hex).map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: format!("invalid hex: {e}") })))?;

    let tx: L2Tx =
        borsh::from_slice(&bytes).map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: format!("invalid tx: {e}") })))?;

    let txid = tx.txid();

    state.mempool.push(tx).map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e.to_string() })))?;

    Ok(Json(SubmitTxResponse { txid: hex::encode(txid) }))
}

// ---------------------------------------------------------------------------
// Helper: decode a hex-encoded borsh L2Tx (used by tests / CLI)
// ---------------------------------------------------------------------------

pub fn decode_tx_hex(hex_str: &str) -> Result<L2Tx, String> {
    let bytes = hex::decode(hex_str).map_err(|e| e.to_string())?;
    borsh::from_slice(&bytes).map_err(|e| e.to_string())
}
