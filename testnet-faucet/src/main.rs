/// testnet-faucet — HTTP faucet for Sophis testnet
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::State,
    http::{Method, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use clap::{Arg, Command, value_parser};
use faster_hex::hex_encode;
use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, ml_dsa_44};
use serde::{Deserialize, Serialize};
use sophis_addresses::{Address, Prefix};
use sophis_consensus_core::{
    config::params::TESTNET_PARAMS,
    constants::{SOMPI_PER_SOPHIS, TX_VERSION},
    hashing::sighash_type::SIG_HASH_ALL,
    sign::sign_input_dilithium,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{MutableTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry},
};
use sophis_core::sophisd_env::version;
use sophis_grpc_client::GrpcClient;
use sophis_notify::subscription::context::SubscriptionContext;
use sophis_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};
use sophis_txscript::standard::{
    dilithium_address, dilithium_redeem_script, pay_to_address_script, pay_to_script_hash_signature_script,
};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const VK_SIZE: usize = 1312;
const SK_SIZE: usize = 2560;
const RPC_TIMEOUT: Duration = Duration::from_secs(15);
const STORAGE_MASS_PARAMETER: u64 = SOMPI_PER_SOPHIS * 10_000;
const MASS_PER_TX_BYTE: u64 = 1;
const MASS_PER_SCRIPT_PUB_KEY_BYTE: u64 = 10;
const MASS_PER_SIG_OP: u64 = 1000;
const P2SH_SCRIPT_PUB_KEY_SIZE: u64 = 36;
const DILITHIUM_SIG_SCRIPT_SIZE: u64 = 3744;
const FEE_RATE_PER_GRAM: u64 = 1;
const MINIMUM_FEE: u64 = 1_000;

// ─── Fee helpers ─────────────────────────────────────────────────────────────

fn calc_storage_mass(inputs: &[(TransactionOutpoint, UtxoEntry)], send: u64, change: u64) -> u64 {
    let out_send = STORAGE_MASS_PARAMETER.div_ceil(send);
    let out_change = if change > 0 { STORAGE_MASS_PARAMETER.div_ceil(change) } else { 0 };
    let sum_in: u64 = inputs.iter().map(|(_, e)| STORAGE_MASS_PARAMETER / e.amount).sum();
    (out_send + out_change).saturating_sub(sum_in)
}

fn estimate_tx_mass(selected: &[(TransactionOutpoint, UtxoEntry)], send_amount: u64, fee: u64) -> (u64, u64) {
    let n_in = selected.len() as u64;
    let total_in: u64 = selected.iter().map(|(_, e)| e.amount).sum();
    let change = total_in.saturating_sub(send_amount + fee);
    let n_out = if change > 0 { 2u64 } else { 1u64 };
    let tx_size = 20 + n_in * (8 + 8 + 4 + 2 + DILITHIUM_SIG_SCRIPT_SIZE) + n_out * (8 + 2 + 34);
    let compute_mass =
        tx_size * MASS_PER_TX_BYTE + n_out * P2SH_SCRIPT_PUB_KEY_SIZE * MASS_PER_SCRIPT_PUB_KEY_BYTE + n_in * MASS_PER_SIG_OP;
    let storage_mass = calc_storage_mass(selected, send_amount, change);
    (compute_mass, storage_mass)
}

fn calc_fee(selected: &[(TransactionOutpoint, UtxoEntry)], send_amount: u64) -> u64 {
    let mut fee = MINIMUM_FEE;
    for _ in 0..8 {
        let (cm, sm) = estimate_tx_mass(selected, send_amount, fee);
        let new_fee = (cm.max(sm) * FEE_RATE_PER_GRAM * 105 / 100).max(MINIMUM_FEE);
        if new_fee == fee || new_fee > 0 && new_fee.abs_diff(fee) * 1000 < new_fee {
            fee = new_fee;
            break;
        }
        fee = new_fee;
    }
    fee
}

// ─── Wallet ───────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct WalletFile {
    #[serde(default = "WalletFile::default_version")]
    version: u32,
    network: String,
    address: String,
    verification_key_hex: String,
    signing_key_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mnemonic: Option<String>,
}

impl WalletFile {
    fn default_version() -> u32 {
        1
    }
}

fn build_hex(bytes: &[u8]) -> String {
    let mut buf = vec![0u8; bytes.len() * 2];
    hex_encode(bytes, &mut buf).unwrap();
    String::from_utf8(buf).unwrap()
}

// ─── TX ───────────────────────────────────────────────────────────────────────

fn build_and_sign_dilithium_tx(
    utxos: &[(TransactionOutpoint, UtxoEntry)],
    send_amount: u64,
    fee: u64,
    to_address: &Address,
    change_address: &Address,
    vk_bytes: &[u8; VK_SIZE],
    sk_bytes: &[u8; SK_SIZE],
) -> Result<Transaction> {
    let total: u64 = utxos.iter().map(|(_, e)| e.amount).sum();
    let change = total.saturating_sub(send_amount + fee);
    let mut outputs = vec![TransactionOutput { value: send_amount, script_public_key: pay_to_address_script(to_address) }];
    if change > 0 {
        outputs.push(TransactionOutput { value: change, script_public_key: pay_to_address_script(change_address) });
    }
    let inputs: Vec<TransactionInput> = utxos
        .iter()
        .map(|(op, _)| TransactionInput { previous_outpoint: *op, signature_script: vec![], sequence: 0, sig_op_count: 1 })
        .collect();
    let unsigned_tx = Transaction::new_non_finalized(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let utxo_entries: Vec<UtxoEntry> = utxos.iter().map(|(_, e)| e.clone()).collect();
    let mut mutable_tx = MutableTransaction::with_entries(unsigned_tx, utxo_entries);
    let redeem_script = dilithium_redeem_script(vk_bytes)?;
    for i in 0..mutable_tx.tx.inputs.len() {
        let sig_script = sign_input_dilithium(&mutable_tx.as_verifiable(), i, sk_bytes, SIG_HASH_ALL)?;
        mutable_tx.tx.inputs[i].signature_script = pay_to_script_hash_signature_script(redeem_script.clone(), sig_script)?;
    }
    Ok(mutable_tx.tx)
}

// ─── State ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    inner: Arc<Mutex<Inner>>,
    config: Arc<Config>,
}

struct Inner {
    rpc: GrpcClient,
    /// address → unix timestamp of last drip
    drip_history: HashMap<String, u64>,
    total_drips: u64,
    total_sompi_sent: u64,
}

struct Config {
    wallet_address: Address,
    vk_bytes: [u8; VK_SIZE],
    sk_bytes: [u8; SK_SIZE],
    amount_sompi: u64,
    cooldown_secs: u64,
    network: String,
    expected_prefix: String,
    history_file: PathBuf,
    coinbase_maturity: u64,
}

// ─── Drip history persistence ─────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Default)]
struct HistoryFile {
    drip_history: HashMap<String, u64>,
    total_drips: u64,
    total_sompi_sent: u64,
}

fn load_history(path: &PathBuf) -> HistoryFile {
    if path.exists()
        && let Ok(s) = std::fs::read_to_string(path)
        && let Ok(h) = serde_json::from_str::<HistoryFile>(&s)
    {
        return h;
    }
    HistoryFile::default()
}

fn save_history(path: &PathBuf, inner: &Inner) {
    let h = HistoryFile {
        drip_history: inner.drip_history.clone(),
        total_drips: inner.total_drips,
        total_sompi_sent: inner.total_sompi_sent,
    };
    if let Ok(s) = serde_json::to_string_pretty(&h) {
        let _ = std::fs::write(path, s);
    }
}

// ─── RPC helpers ─────────────────────────────────────────────────────────────

async fn connect_rpc(server: &str) -> GrpcClient {
    let ctx = SubscriptionContext::new();
    GrpcClient::connect_with_args(
        NotificationMode::Direct,
        format!("grpc://{}", server),
        Some(ctx),
        true,
        None,
        false,
        Some(15_000),
        Default::default(),
    )
    .await
    .expect("Falha ao conectar ao gRPC")
}

async fn spendable_utxos(rpc: &GrpcClient, address: &Address, coinbase_maturity: u64) -> Vec<(TransactionOutpoint, UtxoEntry)> {
    let dag_info = tokio::time::timeout(RPC_TIMEOUT, rpc.get_block_dag_info()).await.ok().and_then(|r| r.ok());
    let daa = dag_info.map(|d| d.virtual_daa_score).unwrap_or(0);

    let entries = tokio::time::timeout(RPC_TIMEOUT, rpc.get_utxos_by_addresses(vec![address.clone()]))
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default();

    let mut utxos: Vec<_> = entries
        .into_iter()
        .filter(|e| {
            let needed = if e.utxo_entry.is_coinbase { coinbase_maturity } else { 10 };
            e.utxo_entry.block_daa_score + needed < daa
        })
        .map(|e| (TransactionOutpoint::from(e.outpoint), UtxoEntry::from(e.utxo_entry)))
        .collect();
    utxos.sort_by(|a, b| b.1.amount.cmp(&a.1.amount));
    utxos
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ─── HTTP handlers ────────────────────────────────────────────────────────────

fn fmt_sphs(amount: f64) -> String {
    if amount == 0.0 {
        "0".to_string()
    } else if amount >= 1.0 {
        format!("{:.4}", amount)
    } else if amount >= 0.0001 {
        format!("{:.6}", amount)
    } else {
        format!("{:.8}", amount)
    }
}

async fn handle_index(State(state): State<AppState>) -> Html<String> {
    let cfg = &state.config;
    let amount_sphs = cfg.amount_sompi as f64 / SOMPI_PER_SOPHIS as f64;
    let cooldown_h = cfg.cooldown_secs / 3600;
    let cooldown_m = (cfg.cooldown_secs % 3600) / 60;
    let cooldown_s = cfg.cooldown_secs % 60;
    let cooldown_str = if cooldown_h > 0 {
        format!("{}h", cooldown_h)
    } else if cooldown_m > 0 {
        format!("{}m", cooldown_m)
    } else {
        format!("{}s", cooldown_s)
    };

    let (total_drips, total_sphs) = {
        let inner = state.inner.lock().await;
        (inner.total_drips, inner.total_sompi_sent as f64 / SOMPI_PER_SOPHIS as f64)
    };

    let amount_str = fmt_sphs(amount_sphs);
    let total_sphs_str = fmt_sphs(total_sphs);
    let faucet_addr = String::from(&cfg.wallet_address);

    Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sophis {network} Faucet</title>
  <meta name="description" content="Sophis (SPHS) {network} faucet — post-quantum L1 blockchain. Request testnet SPHS for development.">
  <meta name="robots" content="index, follow">
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0e1a; color: #e0e6f0; min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 20px; }}
    .topbar {{ width: 100%; max-width: 560px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; font-size: 0.88rem; }}
    .topbar a {{ color: #7a8fa6; text-decoration: none; }}
    .topbar a:hover {{ color: #4f9ef8; }}
    .card {{ background: #131929; border: 1px solid #1e2d4a; border-radius: 16px; padding: 36px; max-width: 560px; width: 100%; }}
    h1 {{ font-size: 1.7rem; font-weight: 700; color: #e0e6f0; margin-bottom: 6px; letter-spacing: -0.01em; }}
    h1 .sphs {{ color: #4f9ef8; }}
    .subtitle {{ color: #7a8fa6; font-size: 0.92rem; margin-bottom: 24px; line-height: 1.5; }}
    .network-badge {{ display: inline-block; background: #1a2d4a; color: #4f9ef8; border-radius: 20px; padding: 3px 12px; font-size: 0.75rem; font-weight: 600; margin-bottom: 18px; text-transform: uppercase; letter-spacing: 0.05em; }}
    .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 24px; }}
    .info-box {{ background: #0f1824; border: 1px solid #1e2d4a; border-radius: 10px; padding: 12px 14px; }}
    .info-label {{ font-size: 0.7rem; color: #4a6280; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 4px; }}
    .info-value {{ font-size: 1.05rem; font-weight: 600; color: #4f9ef8; font-variant-numeric: tabular-nums; }}
    input {{ width: 100%; background: #0f1824; border: 1px solid #1e2d4a; border-radius: 8px; padding: 12px 14px; color: #e0e6f0; font-size: 0.88rem; font-family: 'SF Mono', Consolas, monospace; margin-bottom: 14px; outline: none; transition: border-color 0.15s; }}
    input:focus {{ border-color: #4f9ef8; }}
    button {{ width: 100%; background: #4f9ef8; color: #0a0e1a; border: none; border-radius: 8px; padding: 13px; font-size: 0.95rem; font-weight: 700; cursor: pointer; transition: background 0.15s; }}
    button:hover {{ background: #6ab3ff; }}
    button:disabled {{ background: #1e2d4a; color: #4a6280; cursor: not-allowed; }}
    .help {{ margin-top: 14px; font-size: 0.78rem; color: #4a6280; line-height: 1.5; }}
    .help code {{ background: #0f1824; padding: 1px 5px; border-radius: 4px; color: #7ab8ff; font-size: 0.78rem; }}
    .result {{ margin-top: 18px; padding: 13px; border-radius: 8px; font-size: 0.85rem; display: none; }}
    .result.success {{ background: #0d2a1e; border: 1px solid #1a6b3a; color: #4dbe82; }}
    .result.error {{ background: #2a0d0d; border: 1px solid #6b1a1a; color: #e05555; }}
    .tx-id {{ word-break: break-all; font-family: 'SF Mono', Consolas, monospace; font-size: 0.75rem; margin-top: 6px; color: #7ab8ff; }}
    .tx-note {{ font-size: 0.72rem; color: #7a8fa6; margin-top: 6px; }}
    .footer {{ width: 100%; max-width: 560px; margin-top: 24px; font-size: 0.72rem; color: #4a6280; text-align: center; line-height: 1.6; }}
    .footer a {{ color: #7a8fa6; text-decoration: none; }}
    .footer a:hover {{ color: #4f9ef8; }}
    .footer .disclaimer {{ color: #6b1a1a; background: #1a0d0d; border: 1px solid #2a0d0d; border-radius: 6px; padding: 8px 12px; margin-bottom: 12px; color: #e05555; font-weight: 500; }}
    .faucet-addr {{ font-family: 'SF Mono', Consolas, monospace; font-size: 0.68rem; word-break: break-all; color: #4a6280; margin-top: 4px; }}
  </style>
</head>
<body>
  <div class="topbar">
    <a href="https://sophis.org">← sophis.org</a>
    <a href="https://github.com/sophis-network/Sophis" target="_blank" rel="noopener">GitHub</a>
  </div>
  <div class="card">
    <div class="network-badge">{network}</div>
    <h1>Sophis <span class="sphs">SPHS</span> Faucet</h1>
    <p class="subtitle">Request {amount_str} SPHS for testing on the Sophis {network}. Post-quantum L1 blockchain — Dilithium ML-DSA-44 signatures from block 0.</p>
    <div class="info-grid">
      <div class="info-box">
        <div class="info-label">Drip Amount</div>
        <div class="info-value">{amount_str} SPHS</div>
      </div>
      <div class="info-box">
        <div class="info-label">Cooldown</div>
        <div class="info-value">{cooldown_str}</div>
      </div>
      <div class="info-box">
        <div class="info-label">Total Drips</div>
        <div class="info-value">{total_drips}</div>
      </div>
      <div class="info-box">
        <div class="info-label">Total Sent</div>
        <div class="info-value">{total_sphs_str} SPHS</div>
      </div>
    </div>
    <input type="text" id="address" placeholder="{prefix}:q..." autocomplete="off" spellcheck="false" />
    <button id="btn" onclick="requestDrip()">Request SPHS</button>
    <div class="help">Don't have a wallet? Generate one with <code>dilithium-wallet keygen --network {network}</code>. One request per address every {cooldown_str}.</div>
    <div class="result" id="result"></div>
  </div>
  <div class="footer">
    <div class="disclaimer">⚠ {network} tokens have no monetary value and exist only for development and testing.</div>
    <div>Faucet wallet: <span class="faucet-addr">{faucet_addr}</span></div>
    <div style="margin-top: 10px;">
      <a href="https://sophis.org/whitepaper.html" target="_blank" rel="noopener">Whitepaper</a> ·
      <a href="https://sophis.org/docs.html" target="_blank" rel="noopener">Docs</a> ·
      <a href="https://github.com/sophis-network/Sophis" target="_blank" rel="noopener">Source</a>
    </div>
  </div>
  <script>
    async function requestDrip() {{
      const address = document.getElementById('address').value.trim();
      const btn = document.getElementById('btn');
      const result = document.getElementById('result');
      if (!address) {{ result.style.display='block'; result.className='result error'; result.innerHTML='&#10007; Please enter a {prefix}: address.'; return; }}
      btn.disabled = true;
      btn.textContent = 'Sending…';
      result.style.display = 'none';
      try {{
        const resp = await fetch('/drip', {{ method: 'POST', headers: {{'Content-Type': 'application/json'}}, body: JSON.stringify({{address}}) }});
        const data = await resp.json();
        if (resp.ok) {{
          result.className = 'result success';
          result.innerHTML = '&#10003; Transaction submitted! ' + (data.amount_sphs || 0).toFixed(8).replace(/0+$/,'').replace(/\.$/,'') + ' SPHS sent.<div class="tx-id">TX: ' + data.tx_id + '</div><div class="tx-note">Wait a few seconds for the transaction to be mined.</div>';
        }} else {{
          result.className = 'result error';
          result.innerHTML = '&#10007; ' + (data.error || 'Unknown error');
        }}
      }} catch(e) {{ result.className='result error'; result.innerHTML='&#10007; Network error: ' + e.message; }}
      result.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Request SPHS';
    }}
    document.getElementById('address').addEventListener('keydown', function(e) {{ if (e.key === 'Enter') requestDrip(); }});
  </script>
</body>
</html>
"#,
        network = cfg.network,
        amount_str = amount_str,
        cooldown_str = cooldown_str,
        total_drips = total_drips,
        total_sphs_str = total_sphs_str,
        prefix = cfg.expected_prefix,
        faucet_addr = faucet_addr,
    ))
}

#[derive(Deserialize)]
struct DripRequest {
    address: String,
}

#[derive(Serialize)]
struct DripResponse {
    tx_id: String,
    amount_sompi: u64,
    amount_sphs: f64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn error_response(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(ErrorResponse { error: msg.into() })).into_response()
}

async fn handle_drip(State(state): State<AppState>, Json(req): Json<DripRequest>) -> Response {
    let address_str = req.address.trim().to_string();

    // Validate prefix
    if !address_str.starts_with(&state.config.expected_prefix) {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!("Invalid address prefix. Expected '{}:...' for {}.", state.config.expected_prefix, state.config.network),
        );
    }

    let to_address = match Address::try_from(address_str.clone()) {
        Ok(a) => a,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, format!("Invalid address: {e}")),
    };

    let mut inner = state.inner.lock().await;
    let now = now_unix();

    // Rate limit check
    if let Some(&last_drip) = inner.drip_history.get(&address_str) {
        let elapsed = now.saturating_sub(last_drip);
        if elapsed < state.config.cooldown_secs {
            let remaining = state.config.cooldown_secs - elapsed;
            let h = remaining / 3600;
            let m = (remaining % 3600) / 60;
            let s = remaining % 60;
            let wait = if h > 0 {
                format!("{}h {}m", h, m)
            } else if m > 0 {
                format!("{}m {}s", m, s)
            } else {
                format!("{}s", s)
            };
            return error_response(
                StatusCode::TOO_MANY_REQUESTS,
                format!("This address already received SPHS. Try again in {}.", wait),
            );
        }
    }

    // Get UTXOs
    let utxos = spendable_utxos(&inner.rpc, &state.config.wallet_address, state.config.coinbase_maturity).await;
    if utxos.is_empty() {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "Faucet has no spendable funds. Try again later.");
    }

    let fee = calc_fee(&utxos[..1.min(utxos.len())], state.config.amount_sompi);
    let needed = state.config.amount_sompi + fee;
    let total_available: u64 = utxos.iter().map(|(_, e)| e.amount).sum();
    if total_available < needed {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Faucet balance too low ({:.4} SPHS). Try again later.", total_available as f64 / SOMPI_PER_SOPHIS as f64),
        );
    }

    // Select UTXOs
    let mut selected = vec![];
    let mut acc = 0u64;
    for (op, entry) in &utxos {
        selected.push((*op, entry.clone()));
        acc += entry.amount;
        if acc >= needed {
            break;
        }
    }

    let final_fee = calc_fee(&selected, state.config.amount_sompi);

    // Build and sign TX
    let tx = match build_and_sign_dilithium_tx(
        &selected,
        state.config.amount_sompi,
        final_fee,
        &to_address,
        &state.config.wallet_address,
        &state.config.vk_bytes,
        &state.config.sk_bytes,
    ) {
        Ok(t) => t,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, format!("TX build failed: {e}")),
    };

    let tx_id = {
        let mut t = tx.clone();
        t.finalize();
        t.id()
    };

    // Submit TX
    let submit = tokio::time::timeout(RPC_TIMEOUT, inner.rpc.submit_transaction((&tx).into(), false)).await;
    match submit {
        Err(_) => return error_response(StatusCode::GATEWAY_TIMEOUT, "RPC timeout submitting transaction."),
        Ok(Err(e)) => return error_response(StatusCode::BAD_GATEWAY, format!("Node rejected transaction: {e}")),
        Ok(Ok(_)) => {}
    }

    // Update history
    inner.drip_history.insert(address_str, now);
    inner.total_drips += 1;
    inner.total_sompi_sent += state.config.amount_sompi;
    save_history(&state.config.history_file, &inner);

    log::info!("Drip {} sompi → {} (tx {})", state.config.amount_sompi, to_address, tx_id);

    (
        StatusCode::OK,
        Json(DripResponse {
            tx_id: tx_id.to_string(),
            amount_sompi: state.config.amount_sompi,
            amount_sphs: state.config.amount_sompi as f64 / SOMPI_PER_SOPHIS as f64,
        }),
    )
        .into_response()
}

#[derive(Serialize)]
struct StatusResponse {
    network: String,
    faucet_address: String,
    amount_sompi: u64,
    amount_sphs: f64,
    cooldown_secs: u64,
    total_drips: u64,
    total_sompi_sent: u64,
    total_sphs_sent: f64,
    balance_sompi: u64,
    balance_sphs: f64,
    spendable_utxos: usize,
}

async fn handle_status(State(state): State<AppState>) -> Response {
    let inner = state.inner.lock().await;
    let utxos = spendable_utxos(&inner.rpc, &state.config.wallet_address, state.config.coinbase_maturity).await;
    let balance: u64 = utxos.iter().map(|(_, e)| e.amount).sum();

    (
        StatusCode::OK,
        Json(StatusResponse {
            network: state.config.network.clone(),
            faucet_address: String::from(&state.config.wallet_address),
            amount_sompi: state.config.amount_sompi,
            amount_sphs: state.config.amount_sompi as f64 / SOMPI_PER_SOPHIS as f64,
            cooldown_secs: state.config.cooldown_secs,
            total_drips: inner.total_drips,
            total_sompi_sent: inner.total_sompi_sent,
            total_sphs_sent: inner.total_sompi_sent as f64 / SOMPI_PER_SOPHIS as f64,
            balance_sompi: balance,
            balance_sphs: balance as f64 / SOMPI_PER_SOPHIS as f64,
            spendable_utxos: utxos.len(),
        }),
    )
        .into_response()
}

// ─── Setup ────────────────────────────────────────────────────────────────────

fn prefix_str(network: &str) -> &'static str {
    match network {
        "mainnet" => "sophis",
        "testnet" => "sophistest",
        "simnet" => "sophissim",
        _ => "sophisdev",
    }
}

fn network_prefix(network: &str) -> Prefix {
    match network {
        "mainnet" => Prefix::Mainnet,
        "testnet" => Prefix::Testnet,
        "simnet" => Prefix::Simnet,
        _ => Prefix::Devnet,
    }
}

fn load_wallet(path: &PathBuf) -> Result<(Address, [u8; VK_SIZE], [u8; SK_SIZE])> {
    let s = std::fs::read_to_string(path)?;
    let w: WalletFile = serde_json::from_str(&s)?;
    let vk_raw = hex::decode(&w.verification_key_hex)?;
    let sk_raw = hex::decode(&w.signing_key_hex)?;
    let vk: [u8; VK_SIZE] = vk_raw.try_into().map_err(|_| "VK size mismatch")?;
    let sk: [u8; SK_SIZE] = sk_raw.try_into().map_err(|_| "SK size mismatch")?;
    let address = Address::try_from(w.address).map_err(|e| format!("{e}"))?;
    Ok((address, vk, sk))
}

fn generate_wallet(path: &PathBuf, network: &str) -> Result<()> {
    let prefix = network_prefix(network);
    let mut randomness = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
    getrandom::getrandom(&mut randomness)?;
    let keypair = ml_dsa_44::generate_key_pair(randomness);
    randomness.iter_mut().for_each(|b| *b = 0);
    let vk: [u8; VK_SIZE] = *keypair.verification_key.as_ref();
    let sk: [u8; SK_SIZE] = *keypair.signing_key.as_ref();
    let address = dilithium_address(&vk, prefix)?;
    let w = WalletFile {
        version: 1,
        network: network.to_string(),
        address: String::from(&address),
        verification_key_hex: build_hex(&vk),
        signing_key_hex: build_hex(&sk),
        mnemonic: None,
    };
    std::fs::write(path, serde_json::to_string_pretty(&w)?)?;
    println!("Faucet wallet generated:");
    println!("  Address : {}", address);
    println!("  File    : {}", path.display());
    println!();
    println!("Fund this address before starting the faucet.");
    Ok(())
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    sophis_core::log::init_logger(None, "info");

    let m = Command::new("testnet-faucet")
        .about(format!("Sophis Testnet Faucet v{}", version()))
        .subcommand_required(true)
        .subcommand(
            Command::new("generate-wallet")
                .about("Generate a new Dilithium faucet wallet")
                .arg(Arg::new("wallet").long("wallet").short('w').default_value("faucet_wallet.json"))
                .arg(
                    Arg::new("network")
                        .long("network")
                        .short('n')
                        .default_value("testnet")
                        .value_parser(["devnet", "testnet", "simnet", "mainnet"]),
                ),
        )
        .subcommand(
            Command::new("start")
                .about("Start the faucet HTTP server")
                .arg(Arg::new("wallet").long("wallet").short('w').default_value("faucet_wallet.json"))
                .arg(Arg::new("rpcserver").long("rpcserver").short('s').default_value("localhost:46610"))
                .arg(
                    Arg::new("amount")
                        .long("amount")
                        .short('a')
                        .default_value("1000000000")
                        .value_parser(value_parser!(u64))
                        .help("Drip amount in sompi (default: 10 SPHS)"),
                )
                .arg(
                    Arg::new("cooldown")
                        .long("cooldown")
                        .short('c')
                        .default_value("86400")
                        .value_parser(value_parser!(u64))
                        .help("Cooldown in seconds between drips per address (default: 24h)"),
                )
                .arg(Arg::new("port").long("port").short('p').default_value("8080").value_parser(value_parser!(u16)))
                .arg(
                    Arg::new("network")
                        .long("network")
                        .short('n')
                        .default_value("testnet")
                        .value_parser(["devnet", "testnet", "simnet", "mainnet"]),
                )
                .arg(Arg::new("history").long("history").default_value("faucet_history.json").help("Path to drip history file")),
        )
        .get_matches();

    match m.subcommand() {
        Some(("generate-wallet", sub)) => {
            let path = PathBuf::from(sub.get_one::<String>("wallet").unwrap());
            let network = sub.get_one::<String>("network").unwrap();
            if let Err(e) = generate_wallet(&path, network) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Some(("start", sub)) => {
            let wallet_path = PathBuf::from(sub.get_one::<String>("wallet").unwrap());
            let rpc_server = sub.get_one::<String>("rpcserver").unwrap().clone();
            let amount_sompi = *sub.get_one::<u64>("amount").unwrap();
            let cooldown_secs = *sub.get_one::<u64>("cooldown").unwrap();
            let port = *sub.get_one::<u16>("port").unwrap();
            let network = sub.get_one::<String>("network").unwrap().clone();
            let history_file = PathBuf::from(sub.get_one::<String>("history").unwrap());

            let (wallet_address, vk_bytes, sk_bytes) = match load_wallet(&wallet_path) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("Failed to load wallet '{}': {}", wallet_path.display(), e);
                    eprintln!("Run 'testnet-faucet generate-wallet' first.");
                    std::process::exit(1);
                }
            };

            let history = load_history(&history_file);
            let rpc = connect_rpc(&rpc_server).await;

            let coinbase_maturity = if network == "testnet" {
                TESTNET_PARAMS.blockrate.coinbase_maturity
            } else {
                sophis_consensus_core::config::params::DEVNET_PARAMS.blockrate.coinbase_maturity
            };

            let config = Arc::new(Config {
                wallet_address: wallet_address.clone(),
                vk_bytes,
                sk_bytes,
                amount_sompi,
                cooldown_secs,
                network: network.clone(),
                expected_prefix: prefix_str(&network).to_string(),
                history_file,
                coinbase_maturity,
            });

            let state = AppState {
                inner: Arc::new(Mutex::new(Inner {
                    rpc,
                    drip_history: history.drip_history,
                    total_drips: history.total_drips,
                    total_sompi_sent: history.total_sompi_sent,
                })),
                config,
            };

            let cors = CorsLayer::new()
                .allow_methods([Method::GET, Method::POST])
                .allow_headers([header::CONTENT_TYPE])
                .allow_origin(tower_http::cors::Any);

            let app = Router::new()
                .route("/", get(handle_index))
                .route("/drip", post(handle_drip))
                .route("/status", get(handle_status))
                .layer(cors)
                .with_state(state);

            let addr = SocketAddr::from(([0, 0, 0, 0], port));
            let listener = tokio::net::TcpListener::bind(addr).await.expect("Failed to bind");

            println!("=== Sophis Testnet Faucet v{} ===", version());
            println!("  Network   : {}", network);
            println!("  Address   : {}", wallet_address);
            println!("  Amount    : {} sompi ({:.2} SPHS)", amount_sompi, amount_sompi as f64 / SOMPI_PER_SOPHIS as f64);
            println!("  Cooldown  : {}s ({}h)", cooldown_secs, cooldown_secs / 3600);
            println!("  RPC       : {}", rpc_server);
            println!("  Listening : http://0.0.0.0:{}", port);
            println!();

            axum::serve(listener, app).await.expect("Server error");
        }
        _ => unreachable!(),
    }
}
