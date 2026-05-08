use std::collections::HashMap;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::{AppState, rpc};

// ─── Error helper ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ErrBody {
    error: String,
}

fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(ErrBody { error: msg.into() })).into_response()
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

pub async fn handle_info(State(state): State<AppState>) -> Response {
    match rpc::get_network_info(&state.rpc).await {
        Ok(info) => (StatusCode::OK, Json(info)).into_response(),
        Err(e) => err(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

pub async fn handle_blocks(State(state): State<AppState>, Query(params): Query<HashMap<String, String>>) -> Response {
    let limit = params.get("limit").and_then(|s| s.parse::<usize>().ok()).unwrap_or(20).min(50);

    {
        let cache = state.blocks_cache.lock().await;
        if let Some(ref c) = *cache
            && c.expires > std::time::Instant::now()
            && c.blocks.len() >= limit
        {
            let slice: Vec<_> = c.blocks.iter().take(limit).cloned().collect();
            return (StatusCode::OK, Json(slice)).into_response();
        }
    }

    match rpc::get_recent_blocks(&state.rpc, 50).await {
        Ok(blocks) => {
            let mut cache = state.blocks_cache.lock().await;
            *cache = Some(crate::BlocksCache { blocks: blocks.clone(), expires: std::time::Instant::now() + crate::BLOCKS_CACHE_TTL });
            let slice: Vec<_> = blocks.into_iter().take(limit).collect();
            (StatusCode::OK, Json(slice)).into_response()
        }
        Err(e) => err(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

pub async fn handle_block(State(state): State<AppState>, Path(hash): Path<String>) -> Response {
    match rpc::get_block_detail(&state.rpc, &hash).await {
        Ok(block) => (StatusCode::OK, Json(block)).into_response(),
        Err(e) => err(StatusCode::NOT_FOUND, e.to_string()),
    }
}

pub async fn handle_tx(State(state): State<AppState>, Path(txid): Path<String>) -> Response {
    match rpc::get_tx_detail(&state.rpc, &txid).await {
        Ok(tx) => (StatusCode::OK, Json(tx)).into_response(),
        Err(e) => err(StatusCode::NOT_FOUND, e.to_string()),
    }
}

pub async fn handle_address(State(state): State<AppState>, Path(address): Path<String>) -> Response {
    match rpc::get_address_info(&state.rpc, &address).await {
        Ok(info) => (StatusCode::OK, Json(info)).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}
