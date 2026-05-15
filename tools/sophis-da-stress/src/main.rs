//! `sophis-da-stress` — Phase 6 DA layer synthetic load generator.
//!
//! Sub-fase 6.8.b. Companion to `devnet/da_stress_check.py` (which
//! observes; this generates).
//!
//! ## Profiles
//!
//!   - `mixed` (default) — the canonical PHASE6_STRESS_PLAN.md §2.2 mix:
//!       70% single-fragment, 1-32 KiB
//!       20% 5-fragment bundles, ~64 KiB each (= 320 KiB payload)
//!       10% 32-fragment bundles, 64 KiB each (= 2 MiB payload, max bundle)
//!   - `uniform` — back-compat with the original generator: one random
//!     payload of size `[min_size, max_size]` per iteration.
//!
//! Bundles larger than `MAX_CARRIER_OUTPUTS_PER_TX` (= 8) are split
//! across N sequential txs sharing the same `bundle_id`; consensus
//! reassembles by bundle_id regardless of how many txs the fragments
//! arrived in. The 32-fragment class therefore fires 4 sub-txs.
//!
//! Mempool back-pressure: before each iteration the generator polls
//! `get_mempool_entries`; if the entry count exceeds the threshold (CLI
//! `--mempool-threshold`, default 100), the iteration is skipped and a
//! `backpressure_skip` event is logged to the CSV. This implements the
//! plan §2.1 rule: "drop to zero submissions on observed mempool
//! back-pressure".
//!
//! ## Usage
//!
//! ```text
//! sophis-da-stress \
//!   --wallet dilithium_wallet.json \
//!   --rpcserver localhost:46610 \
//!   --duration 72h \
//!   --profile mixed \
//!   --target-mb-per-s 0.625 \
//!   --csv stress.csv
//! ```
//!
//! Each iteration:
//!   1. Selects a `MixClass` via weighted random (mixed profile only).
//!   2. Generates a random payload of the class size.
//!   3. Encodes via `encode_bundle` (1..32 V5 carrier scripts, all sharing bundle_id).
//!   4. Chunks the scripts at `MAX_CARRIER_OUTPUTS_PER_TX` and builds N sequential txs.
//!   5. Dilithium-signs and submits each via gRPC.
//!   6. Records one CSV row per sub-tx with bundle_id, class, sub_tx_idx, status.
//!
//! Stops when `duration` elapses or `Ctrl+C` is pressed.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Arg, Command, value_parser};
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use sophis_addresses::Address;
use sophis_consensus_core::{
    constants::{SCRIPT_VERSION_CARRIER, TX_VERSION},
    da::{CarrierDomain, MAX_CARRIER_OUTPUTS_PER_TX, MAX_DATA_PER_CARRIER, MAX_FRAGMENTS, encode_bundle},
    hashing::sighash_type::SIG_HASH_ALL,
    sign::sign_input_dilithium,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        MutableTransaction, ScriptPublicKey, ScriptVec, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
        UtxoEntry,
    },
};
use sophis_grpc_client::GrpcClient;
use sophis_notify::subscription::context::SubscriptionContext;
use sophis_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};
use sophis_txscript::standard::{dilithium_redeem_script, pay_to_address_script, pay_to_script_hash_signature_script};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const VK_SIZE: usize = 1312;
const SK_SIZE: usize = 2560;
const RPC_TIMEOUT: Duration = Duration::from_secs(15);

/// Conservative fee per sub-tx in sompi. Sized to cover the largest
/// carrier-bundle tx in the mixed profile (32-fragment chunked at 8
/// fragments/tx requires ~6 M sompi fee at the standard relay-fee
/// rate). Set to 10 M as a generous bound; the change output absorbs
/// the surplus. Tuned after Audit/F-22 unblocked submit-side
/// acceptance (Session 11, 2026-05-15).
const FEE_PER_SUB_TX: u64 = 10_000_000;

/// How long to wait between sub-txs of a multi-tx bundle. Lets the
/// previous tx land in the mempool and produce a spendable change UTXO.
/// At 10 BPS one block is 100 ms; 250 ms gives ~2.5 blocks of slack.
const INTER_SUB_TX_DELAY_MS: u64 = 250;

// ─── Wallet (JSON-on-disk; mirror of dilithium-wallet's format) ──────────────

#[derive(Serialize, Deserialize)]
struct Wallet {
    #[serde(default)]
    version: u32,
    network: String,
    address: String,
    verification_key_hex: String,
    signing_key_hex: String,
    #[serde(default)]
    mnemonic: Option<String>,
}

impl Wallet {
    fn load(path: &PathBuf) -> Result<Self> {
        let s = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&s)?)
    }

    fn address(&self) -> Result<Address> {
        Address::try_from(self.address.clone()).map_err(|e| format!("{e}").into())
    }

    fn verification_key(&self) -> Result<[u8; VK_SIZE]> {
        hex::decode(&self.verification_key_hex)?.try_into().map_err(|_| "VK size mismatch".into())
    }

    fn signing_key(&self) -> Result<[u8; SK_SIZE]> {
        hex::decode(&self.signing_key_hex)?.try_into().map_err(|_| "SK size mismatch".into())
    }
}

// ─── RPC ─────────────────────────────────────────────────────────────────────

async fn connect(rpc_server: &str) -> GrpcClient {
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

async fn fetch_spendable_utxos(rpc: &GrpcClient, address: &Address) -> Vec<(TransactionOutpoint, UtxoEntry)> {
    let dag_info = match tokio::time::timeout(RPC_TIMEOUT, rpc.get_block_dag_info()).await {
        Ok(Ok(info)) => info,
        _ => return Vec::new(),
    };
    let daa = dag_info.virtual_daa_score;
    let entries = match tokio::time::timeout(RPC_TIMEOUT, rpc.get_utxos_by_addresses(vec![address.clone()])).await {
        Ok(Ok(e)) => e,
        _ => return Vec::new(),
    };
    let mut utxos: Vec<(TransactionOutpoint, UtxoEntry)> = entries
        .into_iter()
        .filter(|e| {
            // Coinbase maturity is much higher than tx maturity. Use 1000 as a
            // conservative bound; honest test wallets exceed that quickly.
            let needed = if e.utxo_entry.is_coinbase { 1000 } else { 10 };
            e.utxo_entry.block_daa_score + needed < daa
        })
        .map(|e| (TransactionOutpoint::from(e.outpoint), UtxoEntry::from(e.utxo_entry)))
        .collect();
    // Prefer larger UTXOs first — covers fees more reliably.
    utxos.sort_by(|a, b| b.1.amount.cmp(&a.1.amount));
    utxos
}

/// Polls the mempool size. Returns the entry count, or `None` if the RPC
/// call fails (callers should treat unknown state as "no back-pressure"
/// to avoid stalling the loop on a transient RPC issue).
async fn mempool_entry_count(rpc: &GrpcClient) -> Option<usize> {
    match tokio::time::timeout(RPC_TIMEOUT, rpc.get_mempool_entries(false, false)).await {
        Ok(Ok(entries)) => Some(entries.len()),
        _ => None,
    }
}

// ─── Transaction construction (carrier outputs) ──────────────────────────────

fn build_signed_da_tx(
    utxos: &[(TransactionOutpoint, UtxoEntry)],
    carrier_scripts: &[Vec<u8>],
    fee: u64,
    change_address: &Address,
    vk_bytes: &[u8; VK_SIZE],
    sk_bytes: &[u8; SK_SIZE],
) -> Result<Transaction> {
    let total_in: u64 = utxos.iter().map(|(_, e)| e.amount).sum();
    if total_in < fee {
        return Err(format!("UTXOs insuficientes ({} < {})", total_in, fee).into());
    }
    let change = total_in - fee;
    let mut outputs = Vec::with_capacity(carrier_scripts.len() + 1);
    for script in carrier_scripts {
        outputs.push(TransactionOutput {
            value: 0,
            script_public_key: ScriptPublicKey::new(SCRIPT_VERSION_CARRIER, ScriptVec::from_slice(script)),
        });
    }
    if change > 0 {
        outputs.push(TransactionOutput { value: change, script_public_key: pay_to_address_script(change_address) });
    }
    let inputs: Vec<TransactionInput> = utxos
        .iter()
        .map(|(op, _)| TransactionInput { previous_outpoint: *op, signature_script: vec![], sequence: 0, sig_op_count: 1 })
        .collect();
    let unsigned = Transaction::new_non_finalized(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let utxo_entries: Vec<UtxoEntry> = utxos.iter().map(|(_, e)| e.clone()).collect();
    let mut mtx = MutableTransaction::with_entries(unsigned, utxo_entries);
    let redeem = dilithium_redeem_script(vk_bytes)?;
    for i in 0..mtx.tx.inputs.len() {
        let sig = sign_input_dilithium(&mtx.as_verifiable(), i, sk_bytes, SIG_HASH_ALL)?;
        mtx.tx.inputs[i].signature_script = pay_to_script_hash_signature_script(redeem.clone(), sig)?;
    }
    Ok(mtx.tx)
}

// ─── Duration parser ─────────────────────────────────────────────────────────

fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let (num_part, unit) = if let Some(stripped) = s.strip_suffix("ms") {
        (stripped, 1u64)
    } else if let Some(stripped) = s.strip_suffix('s') {
        (stripped, 1_000)
    } else if let Some(stripped) = s.strip_suffix('m') {
        (stripped, 60_000)
    } else if let Some(stripped) = s.strip_suffix('h') {
        (stripped, 3_600_000)
    } else {
        return Err(format!("duração inválida '{}': use Ns, Nm, Nh, Nms", s).into());
    };
    let n: u64 = num_part.parse().map_err(|_| format!("número inválido '{}'", num_part))?;
    Ok(Duration::from_millis(n * unit))
}

fn parse_domain(s: &str) -> Result<Option<CarrierDomain>> {
    match s.to_ascii_lowercase().as_str() {
        "none" | "" => Ok(None),
        "rollup" => Ok(Some(CarrierDomain::Rollup)),
        "oracle" => Ok(Some(CarrierDomain::Oracle)),
        "user" => Ok(Some(CarrierDomain::User)),
        other => Err(format!("domain inválido '{}'", other).into()),
    }
}

// ─── Mix profile (PHASE6_STRESS_PLAN.md §2.2) ────────────────────────────────

/// Generator profile. `Mixed` is the canonical 72h-soak profile; `Uniform`
/// is back-compat with the original generator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Mixed,
    Uniform { min_size: usize, max_size: usize },
}

fn parse_profile(s: &str) -> Result<Profile> {
    match s.to_ascii_lowercase().as_str() {
        "mixed" => Ok(Profile::Mixed),
        "uniform" => Ok(Profile::Uniform { min_size: 32, max_size: 1024 }),
        other => Err(format!("profile inválido '{}': use 'mixed' ou 'uniform'", other).into()),
    }
}

/// One of the three weighted classes from PHASE6_STRESS_PLAN.md §2.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MixClass {
    /// 70% — single-fragment, 1-32 KiB random.
    Single,
    /// 20% — 5 fragments ~64 KiB each (320 KiB payload).
    FiveFrag,
    /// 10% — 32 fragments × 64 KiB each (2 MiB payload, MAX_FRAGMENTS edge).
    ThirtyTwoFrag,
}

impl MixClass {
    fn label(&self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::FiveFrag => "5frag",
            Self::ThirtyTwoFrag => "32frag",
        }
    }
}

/// Weighted random selection over the §2.2 mix: 70% Single, 20% FiveFrag,
/// 10% ThirtyTwoFrag. Uses an integer roll in `[0, 100)` so the weights
/// are deterministic given the RNG seed.
fn select_class<R: Rng + ?Sized>(rng: &mut R) -> MixClass {
    let roll = rng.random_range(0u32..100);
    match roll {
        0..=69 => MixClass::Single,
        70..=89 => MixClass::FiveFrag,
        _ => MixClass::ThirtyTwoFrag,
    }
}

/// Generates a random payload for the given class. Sizes follow §2.2:
///   - Single: 1024..=32_768 bytes (`1 KiB..32 KiB`)
///   - FiveFrag: 5 fragments × 64 KiB = 327_680 bytes (full chunks → 5 fragments after encode_bundle)
///   - ThirtyTwoFrag: 32 fragments × 64 KiB = 2_097_152 bytes (MAX_BUNDLE_BYTES)
fn generate_payload_for_class<R: Rng + ?Sized + RngCore>(rng: &mut R, class: MixClass) -> Vec<u8> {
    let size = match class {
        MixClass::Single => rng.random_range(1024..=32_768usize),
        // Pick a size that encode_bundle will chunk into exactly 5 fragments:
        // (5 - 1) * MAX_DATA_PER_CARRIER + 1 ..= 5 * MAX_DATA_PER_CARRIER
        // We pick 5 * MAX_DATA_PER_CARRIER for a tight max bundle.
        MixClass::FiveFrag => 5 * MAX_DATA_PER_CARRIER as usize,
        // MAX_FRAGMENTS * MAX_DATA_PER_CARRIER = 32 × 65_536 = 2 MiB.
        MixClass::ThirtyTwoFrag => MAX_FRAGMENTS as usize * MAX_DATA_PER_CARRIER as usize,
    };
    let mut out = vec![0u8; size];
    rng.fill_bytes(&mut out);
    out
}

/// Average payload bytes per iteration in the mixed profile. Used to map
/// `--target-mb-per-s` to a rate.
///
/// 0.7 × avg(1..32 KiB)  = 0.7 × 16_896.5 ≈ 11_828
/// 0.2 × 320 KiB          = 0.2 × 327_680  = 65_536
/// 0.1 × 2 MiB            = 0.1 × 2_097_152 = 209_715.2
/// Total                  ≈ 287_080 bytes/iter
fn mixed_avg_bytes_per_iter() -> f64 {
    let single_avg = (1024.0 + 32_768.0) / 2.0;
    let five = (5 * MAX_DATA_PER_CARRIER) as f64;
    let thirty_two = (MAX_FRAGMENTS as u64 * MAX_DATA_PER_CARRIER as u64) as f64;
    0.7 * single_avg + 0.2 * five + 0.1 * thirty_two
}

/// Converts a target throughput (MB/s, decimal megabytes) to an iteration
/// rate using the mixed profile's average bytes/iter.
fn rate_for_target_mb_per_s(target_mb_per_s: f64) -> f64 {
    let target_bytes_per_s = target_mb_per_s * 1_000_000.0;
    target_bytes_per_s / mixed_avg_bytes_per_iter()
}

// ─── Main loop ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct LoopParams {
    rate_per_sec: f64,
    profile: Profile,
    domain: Option<CarrierDomain>,
    duration: Duration,
    mempool_threshold: usize,
}

#[allow(clippy::too_many_arguments)]
async fn run_stress_loop(
    rpc: GrpcClient,
    address: Address,
    vk: [u8; VK_SIZE],
    sk: [u8; SK_SIZE],
    params: LoopParams,
    csv_path: Option<PathBuf>,
) -> Result<()> {
    let mut rng = StdRng::seed_from_u64({
        let mut seed_bytes = [0u8; 8];
        rand::rng().fill_bytes(&mut seed_bytes);
        u64::from_le_bytes(seed_bytes)
    });

    let interval = if params.rate_per_sec > 0.0 { Duration::from_secs_f64(1.0 / params.rate_per_sec) } else { Duration::from_secs(1) };

    let mut csv_writer: Option<std::fs::File> = match &csv_path {
        Some(p) => {
            let mut f = std::fs::File::create(p)?;
            use std::io::Write;
            writeln!(
                f,
                "iso_timestamp,unix_ms,class,bundle_id,sub_tx_idx,sub_tx_count,fragments_in_tx,payload_bytes_in_tx,tx_id,latency_ms,status,error"
            )?;
            Some(f)
        }
        None => None,
    };

    let start = Instant::now();
    let mut iter: u64 = 0;
    let mut ok_count: u64 = 0;
    let mut err_count: u64 = 0;
    let mut backpressure_count: u64 = 0;
    let mut total_payload_bytes: u64 = 0;
    let mut sub_txs_sent: u64 = 0;

    while start.elapsed() < params.duration {
        let iter_start = Instant::now();
        iter += 1;

        // 1. Mempool back-pressure check (PHASE6_STRESS_PLAN.md §2.1).
        if let Some(n) = mempool_entry_count(&rpc).await
            && n > params.mempool_threshold
        {
            backpressure_count += 1;
            csv_log(
                &mut csv_writer,
                iter_start,
                "backpressure",
                "",
                0,
                0,
                0,
                0,
                "",
                0,
                "skipped",
                &format!("mempool_size={n} > threshold={}", params.mempool_threshold),
            );
            tokio::time::sleep(interval).await;
            continue;
        }

        // 2. Select class + generate payload + encode bundle.
        let (class, payload) = match params.profile {
            Profile::Mixed => {
                let c = select_class(&mut rng);
                (c, generate_payload_for_class(&mut rng, c))
            }
            Profile::Uniform { min_size, max_size } => {
                let size = if min_size == max_size { min_size } else { rng.random_range(min_size..=max_size) };
                let mut buf = vec![0u8; size];
                rng.fill_bytes(&mut buf);
                // For CSV labelling, treat uniform as "single" (it's a single bundle).
                (MixClass::Single, buf)
            }
        };

        let total_payload = payload.len();
        let scripts = match encode_bundle(&payload, params.domain) {
            Ok(s) => s,
            Err(e) => {
                log::error!("encode_bundle error: {:?}", e);
                err_count += 1;
                csv_log(
                    &mut csv_writer,
                    iter_start,
                    class.label(),
                    "",
                    0,
                    0,
                    0,
                    total_payload,
                    "",
                    0,
                    "encode_error",
                    &format!("{e}"),
                );
                continue;
            }
        };

        // bundle_id is shared by all fragments — copy it once from the first script (offset 16..64).
        let bundle_id_hex =
            if scripts.first().is_some_and(|s| s.len() >= 64) { hex::encode(&scripts[0][16..64]) } else { String::new() };

        // 3. Chunk by MAX_CARRIER_OUTPUTS_PER_TX and submit each sub-tx sequentially.
        let chunks: Vec<&[Vec<u8>]> = scripts.chunks(MAX_CARRIER_OUTPUTS_PER_TX).collect();
        let sub_tx_count = chunks.len();
        let mut iter_ok = 0u64;
        let mut iter_err = 0u64;
        let mut iter_bytes = 0u64;

        for (sub_idx, chunk) in chunks.iter().enumerate() {
            // Refresh UTXOs every sub-tx — the previous sub-tx's change UTXO
            // needs ~250 ms to appear; we wait below.
            let utxos = fetch_spendable_utxos(&rpc, &address).await;
            if utxos.is_empty() {
                log::warn!("no spendable UTXOs available — sleeping 5s");
                iter_err += 1;
                csv_log(
                    &mut csv_writer,
                    iter_start,
                    class.label(),
                    &bundle_id_hex,
                    sub_idx,
                    sub_tx_count,
                    chunk.len(),
                    chunk.iter().map(|s| s.len().saturating_sub(64)).sum(),
                    "",
                    0,
                    "no_utxos",
                    "",
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
                break;
            }

            // Audit/F-22 (Session 11, 2026-05-15): take as many UTXOs as
            // needed to cover the fee. Devnet coinbase outputs are
            // small (~6 M sompi per block) and the largest carrier tx
            // needs up to 10 M (FEE_PER_SUB_TX), so a single UTXO is
            // not always sufficient.
            let mut accumulated = 0u64;
            let single_input: Vec<_> = utxos
                .into_iter()
                .take_while(|(_, e)| {
                    if accumulated >= FEE_PER_SUB_TX {
                        false
                    } else {
                        accumulated = accumulated.saturating_add(e.amount);
                        true
                    }
                })
                .collect();

            let chunk_vec: Vec<Vec<u8>> = chunk.to_vec();
            let payload_bytes_in_tx: usize = chunk_vec.iter().map(|s| s.len().saturating_sub(64)).sum();
            let tx = match build_signed_da_tx(&single_input, &chunk_vec, FEE_PER_SUB_TX, &address, &vk, &sk) {
                Ok(t) => t,
                Err(e) => {
                    log::error!("build_signed_da_tx error: {}", e);
                    iter_err += 1;
                    csv_log(
                        &mut csv_writer,
                        iter_start,
                        class.label(),
                        &bundle_id_hex,
                        sub_idx,
                        sub_tx_count,
                        chunk_vec.len(),
                        payload_bytes_in_tx,
                        "",
                        0,
                        "build_error",
                        &e.to_string(),
                    );
                    break;
                }
            };

            let submit_start = Instant::now();
            let (status_label, error_msg, tx_id_str) =
                match tokio::time::timeout(RPC_TIMEOUT, rpc.submit_transaction((&tx).into(), false)).await {
                    Ok(Ok(tx_id)) => ("ok", String::new(), tx_id.to_string()),
                    Ok(Err(e)) => ("rejected", e.to_string(), String::new()),
                    Err(_) => ("timeout", String::new(), String::new()),
                };
            let latency_ms = submit_start.elapsed().as_millis() as i64;

            if status_label == "ok" {
                iter_ok += 1;
                iter_bytes += payload_bytes_in_tx as u64;
            } else {
                iter_err += 1;
            }
            sub_txs_sent += 1;

            csv_log(
                &mut csv_writer,
                iter_start,
                class.label(),
                &bundle_id_hex,
                sub_idx,
                sub_tx_count,
                chunk_vec.len(),
                payload_bytes_in_tx,
                &tx_id_str,
                latency_ms,
                status_label,
                &error_msg,
            );

            // If this is not the last sub-tx, give the change UTXO time to appear.
            if sub_idx + 1 < sub_tx_count {
                tokio::time::sleep(Duration::from_millis(INTER_SUB_TX_DELAY_MS)).await;
            }
        }

        ok_count += iter_ok;
        err_count += iter_err;
        total_payload_bytes += iter_bytes;

        if iter.is_multiple_of(10) {
            println!(
                "[{:>5}] iters={} sub_txs={} ok={} err={} bp_skips={} bytes={} elapsed={:?}",
                iter,
                iter,
                sub_txs_sent,
                ok_count,
                err_count,
                backpressure_count,
                total_payload_bytes,
                start.elapsed(),
            );
        }

        // Rate limit — sleep until next iteration slot.
        let elapsed_iter = iter_start.elapsed();
        if elapsed_iter < interval {
            tokio::time::sleep(interval - elapsed_iter).await;
        }
    }

    println!("\n=== sophis-da-stress summary ===");
    println!("Iterations          : {}", iter);
    println!("Sub-txs submitted   : {}", sub_txs_sent);
    println!("OK                  : {}", ok_count);
    println!("Errors              : {}", err_count);
    println!("Backpressure skips  : {}", backpressure_count);
    println!("Payload bytes total : {}", total_payload_bytes);
    println!("Wall time           : {:?}", start.elapsed());
    if let Some(p) = &csv_path {
        println!("CSV                 : {}", p.display());
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn csv_log(
    f: &mut Option<std::fs::File>,
    when: Instant,
    class: &str,
    bundle_id: &str,
    sub_tx_idx: usize,
    sub_tx_count: usize,
    fragments_in_tx: usize,
    payload_bytes_in_tx: usize,
    tx_id: &str,
    latency_ms: i64,
    status: &str,
    error: &str,
) {
    use std::io::Write;
    let Some(file) = f else { return };
    let unix_ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    let _ = when; // reserved for future intra-iteration timing logging.
    let iso = format_iso8601_ms(unix_ms as u64);
    let safe_err = error.replace(',', ";").replace('\n', " ");
    let _ = writeln!(
        file,
        "{},{},{},{},{},{},{},{},{},{},{},{}",
        iso,
        unix_ms,
        class,
        bundle_id,
        sub_tx_idx,
        sub_tx_count,
        fragments_in_tx,
        payload_bytes_in_tx,
        tx_id,
        latency_ms,
        status,
        safe_err,
    );
}

fn format_iso8601_ms(unix_ms: u64) -> String {
    // Minimal ISO-8601 UTC formatter to avoid pulling in chrono.
    // Format: YYYY-MM-DDTHH:MM:SS.mmmZ
    let secs = unix_ms / 1000;
    let ms = unix_ms % 1000;
    // Days since epoch.
    let days = secs / 86_400;
    let secs_in_day = secs % 86_400;
    let h = secs_in_day / 3600;
    let m = (secs_in_day % 3600) / 60;
    let s = secs_in_day % 60;
    let (y, mo, d) = days_to_ymd(days as i64);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", y, mo, d, h, m, s, ms)
}

/// Convert "days since 1970-01-01" into (year, month, day). Algorithm:
/// Howard Hinnant's date algorithm (proleptic Gregorian).
fn days_to_ymd(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    sophis_core::log::init_logger(None, "warn");

    let m = Command::new("sophis-da-stress")
        .about("Sophis Phase 6 DA layer synthetic load generator (sub-fase 6.8.b)")
        .arg(Arg::new("wallet").long("wallet").short('w').default_value("dilithium_wallet.json"))
        .arg(Arg::new("rpcserver").long("rpcserver").short('s').default_value("localhost:46610"))
        .arg(Arg::new("duration").long("duration").short('d').default_value("60s").help("Tempo total: Ns / Nm / Nh / Nms"))
        .arg(
            Arg::new("profile")
                .long("profile")
                .default_value("mixed")
                .help("Mixed (70/20/10 PHASE6_STRESS_PLAN.md §2.2) ou Uniform (back-compat)"),
        )
        .arg(
            Arg::new("rate")
                .long("rate")
                .short('r')
                .default_value("1")
                .value_parser(value_parser!(f64))
                .help("Iterações por segundo (ignorado se --target-mb-per-s passado)"),
        )
        .arg(
            Arg::new("target-mb-per-s")
                .long("target-mb-per-s")
                .value_parser(value_parser!(f64))
                .help("Alvo de throughput em MB/s (decimal). Sobrescreve --rate quando definido. Plan §2.1 alvo = 0.625"),
        )
        .arg(
            Arg::new("min-size")
                .long("min-size")
                .default_value("32")
                .value_parser(value_parser!(usize))
                .help("Profile=uniform: tamanho mínimo do payload em bytes"),
        )
        .arg(
            Arg::new("max-size")
                .long("max-size")
                .default_value("1024")
                .value_parser(value_parser!(usize))
                .help("Profile=uniform: tamanho máximo do payload em bytes"),
        )
        .arg(Arg::new("domain").long("domain").default_value("user").help("Rollup|Oracle|User|None"))
        .arg(
            Arg::new("mempool-threshold")
                .long("mempool-threshold")
                .default_value("100")
                .value_parser(value_parser!(usize))
                .help("Skip iteration quando get_mempool_entries() > threshold (PHASE6_STRESS_PLAN.md §2.1)"),
        )
        .arg(Arg::new("csv").long("csv").help("Caminho de saída para CSV de métricas (opcional)"))
        .get_matches();

    let wallet_path = PathBuf::from(m.get_one::<String>("wallet").unwrap());
    let rpc_server = m.get_one::<String>("rpcserver").unwrap().clone();
    let duration = parse_duration(m.get_one::<String>("duration").unwrap()).unwrap_or_else(|e| {
        eprintln!("Erro: {}", e);
        std::process::exit(2);
    });
    let mut profile = parse_profile(m.get_one::<String>("profile").unwrap()).unwrap_or_else(|e| {
        eprintln!("Erro: {}", e);
        std::process::exit(2);
    });
    // For uniform profile, honor --min-size/--max-size.
    if let Profile::Uniform { .. } = profile {
        let min_size = *m.get_one::<usize>("min-size").unwrap();
        let max_size = *m.get_one::<usize>("max-size").unwrap();
        if min_size > max_size {
            eprintln!("Erro: --min-size > --max-size");
            std::process::exit(2);
        }
        profile = Profile::Uniform { min_size, max_size };
    }
    let rate = match m.get_one::<f64>("target-mb-per-s") {
        Some(&mb_per_s) if profile == Profile::Mixed => rate_for_target_mb_per_s(mb_per_s),
        Some(&mb_per_s) => {
            // For uniform profile, --target-mb-per-s is ambiguous without a fixed payload
            // size; fall back to --rate but warn.
            eprintln!("Aviso: --target-mb-per-s ignorado com profile=uniform; usando --rate");
            let _ = mb_per_s;
            *m.get_one::<f64>("rate").unwrap()
        }
        None => *m.get_one::<f64>("rate").unwrap(),
    };
    let domain = parse_domain(m.get_one::<String>("domain").unwrap()).unwrap_or_else(|e| {
        eprintln!("Erro: {}", e);
        std::process::exit(2);
    });
    let mempool_threshold = *m.get_one::<usize>("mempool-threshold").unwrap();
    let csv_path = m.get_one::<String>("csv").map(PathBuf::from);

    let wallet = Wallet::load(&wallet_path).expect("Wallet não encontrada");
    let address = wallet.address().expect("endereço inválido na wallet");
    let vk = wallet.verification_key().expect("VK inválida na wallet");
    let sk = wallet.signing_key().expect("SK inválida na wallet");

    println!("sophis-da-stress");
    println!("  wallet              : {}", wallet_path.display());
    println!("  rpcserver           : {}", rpc_server);
    println!("  address             : {}", address);
    println!("  duration            : {:?}", duration);
    println!("  profile             : {:?}", profile);
    println!("  rate                : {:.4} iter/s", rate);
    if profile == Profile::Mixed {
        println!("  avg bytes/iter      : {:.0}", mixed_avg_bytes_per_iter());
        println!("  effective MB/s      : {:.4}", rate * mixed_avg_bytes_per_iter() / 1_000_000.0);
    }
    println!("  domain              : {:?}", domain);
    println!("  mempool threshold   : {}", mempool_threshold);
    if let Some(p) = &csv_path {
        println!("  csv                 : {}", p.display());
    }
    println!();

    let rpc = connect(&rpc_server).await;
    let params = LoopParams { rate_per_sec: rate, profile, domain, duration, mempool_threshold };

    if let Err(e) = run_stress_loop(rpc, address, vk, sk, params, csv_path).await {
        eprintln!("Erro: {}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
    }

    #[test]
    fn parse_duration_invalid() {
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("30").is_err());
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn parse_domain_variants() {
        assert!(parse_domain("None").unwrap().is_none());
        assert!(matches!(parse_domain("Oracle").unwrap(), Some(CarrierDomain::Oracle)));
        assert!(matches!(parse_domain("rollup").unwrap(), Some(CarrierDomain::Rollup)));
        assert!(matches!(parse_domain("USER").unwrap(), Some(CarrierDomain::User)));
        assert!(parse_domain("foo").is_err());
    }

    /// Sanity: known epoch dates render to expected ISO 8601.
    #[test]
    fn days_to_ymd_sanity() {
        // 1970-01-01
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
        // 2000-01-01 = 30·365 + 8 leap = 10957 days
        assert_eq!(days_to_ymd(10_957), (2000, 1, 1));
        // 2024-02-29 (leap year): 19_782 days from 1970-01-01
        assert_eq!(days_to_ymd(19_782), (2024, 2, 29));
    }

    #[test]
    fn iso8601_format_basic() {
        // 1970-01-01T00:00:00.000Z
        assert_eq!(format_iso8601_ms(0), "1970-01-01T00:00:00.000Z");
        // 2024-02-29 noon-ish
        let unix = (19_782u64 * 86_400 + 12 * 3600) * 1000 + 345;
        assert_eq!(format_iso8601_ms(unix), "2024-02-29T12:00:00.345Z");
    }

    // --- Mix profile tests (sub-fase 6.8.b additions) -----------------------

    #[test]
    fn parse_profile_known() {
        assert_eq!(parse_profile("mixed").unwrap(), Profile::Mixed);
        assert!(matches!(parse_profile("Uniform").unwrap(), Profile::Uniform { .. }));
    }

    #[test]
    fn parse_profile_rejects_unknown() {
        assert!(parse_profile("burst").is_err());
        assert!(parse_profile("").is_err());
    }

    /// Statistical check that select_class hits the 70/20/10 weights
    /// within a 2% absolute tolerance over 10_000 samples. Seeded RNG so
    /// the assertion is deterministic — no flakes.
    #[test]
    fn select_class_hits_70_20_10() {
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);
        let n = 10_000u32;
        let mut single = 0u32;
        let mut five = 0u32;
        let mut thirty_two = 0u32;
        for _ in 0..n {
            match select_class(&mut rng) {
                MixClass::Single => single += 1,
                MixClass::FiveFrag => five += 1,
                MixClass::ThirtyTwoFrag => thirty_two += 1,
            }
        }
        let pct_single = single as f64 / n as f64;
        let pct_five = five as f64 / n as f64;
        let pct_32 = thirty_two as f64 / n as f64;
        assert!((pct_single - 0.70).abs() < 0.02, "single = {pct_single} (expected 0.70 ± 0.02)");
        assert!((pct_five - 0.20).abs() < 0.02, "5frag  = {pct_five} (expected 0.20 ± 0.02)");
        assert!((pct_32 - 0.10).abs() < 0.02, "32frag = {pct_32} (expected 0.10 ± 0.02)");
    }

    /// Payload sizes per class must be inside the §2.2 envelope, and
    /// encode_bundle's chunking must produce the expected fragment count.
    #[test]
    fn generate_payload_single_produces_one_fragment() {
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..20 {
            let blob = generate_payload_for_class(&mut rng, MixClass::Single);
            assert!((1024..=32_768).contains(&blob.len()), "single size {} outside 1..=32 KiB", blob.len());
            let scripts = encode_bundle(&blob, Some(CarrierDomain::User)).unwrap();
            assert_eq!(scripts.len(), 1, "single class must yield 1 fragment, got {}", scripts.len());
        }
    }

    #[test]
    fn generate_payload_five_frag_produces_five_fragments() {
        let mut rng = StdRng::seed_from_u64(2);
        let blob = generate_payload_for_class(&mut rng, MixClass::FiveFrag);
        assert_eq!(blob.len(), 5 * MAX_DATA_PER_CARRIER as usize);
        let scripts = encode_bundle(&blob, Some(CarrierDomain::User)).unwrap();
        assert_eq!(scripts.len(), 5, "5frag class must yield exactly 5 fragments");
    }

    #[test]
    fn generate_payload_thirty_two_frag_produces_max_fragments() {
        let mut rng = StdRng::seed_from_u64(3);
        let blob = generate_payload_for_class(&mut rng, MixClass::ThirtyTwoFrag);
        assert_eq!(blob.len(), MAX_FRAGMENTS as usize * MAX_DATA_PER_CARRIER as usize);
        let scripts = encode_bundle(&blob, Some(CarrierDomain::User)).unwrap();
        assert_eq!(scripts.len(), MAX_FRAGMENTS as usize, "32frag class must yield MAX_FRAGMENTS fragments");
    }

    /// All fragments of a bundle must share the same bundle_id (offset 16..64).
    #[test]
    fn bundle_id_is_consistent_across_fragments() {
        let mut rng = StdRng::seed_from_u64(4);
        let blob = generate_payload_for_class(&mut rng, MixClass::ThirtyTwoFrag);
        let scripts = encode_bundle(&blob, Some(CarrierDomain::User)).unwrap();
        let expected = &scripts[0][16..64];
        for (i, s) in scripts.iter().enumerate() {
            assert_eq!(&s[16..64], expected, "fragment {i} has divergent bundle_id");
        }
    }

    /// Multi-tx chunking: a 32-fragment bundle must split into
    /// ceil(32 / MAX_CARRIER_OUTPUTS_PER_TX) = ceil(32/8) = 4 sub-txs.
    #[test]
    fn thirty_two_frag_bundle_chunks_into_4_sub_txs() {
        let mut rng = StdRng::seed_from_u64(5);
        let blob = generate_payload_for_class(&mut rng, MixClass::ThirtyTwoFrag);
        let scripts = encode_bundle(&blob, Some(CarrierDomain::User)).unwrap();
        let chunks: Vec<&[Vec<u8>]> = scripts.chunks(MAX_CARRIER_OUTPUTS_PER_TX).collect();
        assert_eq!(chunks.len(), 4);
        // Each chunk should have exactly MAX_CARRIER_OUTPUTS_PER_TX fragments (32 / 8 = 4 even).
        for chunk in &chunks {
            assert_eq!(chunk.len(), MAX_CARRIER_OUTPUTS_PER_TX);
        }
    }

    /// FiveFrag stays within MAX_CARRIER_OUTPUTS_PER_TX so it's one sub-tx.
    #[test]
    fn five_frag_bundle_fits_in_one_sub_tx() {
        let mut rng = StdRng::seed_from_u64(6);
        let blob = generate_payload_for_class(&mut rng, MixClass::FiveFrag);
        let scripts = encode_bundle(&blob, Some(CarrierDomain::User)).unwrap();
        let chunks: Vec<&[Vec<u8>]> = scripts.chunks(MAX_CARRIER_OUTPUTS_PER_TX).collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 5);
    }

    /// Round-trip the mixed profile through encode_bundle for every class
    /// and confirm the consensus parser would accept each fragment. This
    /// catches any drift between the generator and the parse rules.
    #[test]
    fn mixed_profile_roundtrips_all_classes_through_parser() {
        use sophis_consensus_core::da::parse_carrier_header;
        let mut rng = StdRng::seed_from_u64(7);
        for class in [MixClass::Single, MixClass::FiveFrag, MixClass::ThirtyTwoFrag] {
            let blob = generate_payload_for_class(&mut rng, class);
            let scripts = encode_bundle(&blob, Some(CarrierDomain::User)).unwrap();
            for (i, s) in scripts.iter().enumerate() {
                let h = parse_carrier_header(s).unwrap_or_else(|e| panic!("class={class:?} frag={i} rejected: {e:?}"));
                assert_eq!(h.fragment_count as usize, scripts.len());
                assert_eq!(h.fragment_index as usize, i);
            }
        }
    }

    /// Average bytes/iter is dominated by the 32-fragment class (10% × 2 MiB ≈ 210 KiB);
    /// total should land near 287 KB. Loose bound: 200 KB..400 KB.
    #[test]
    fn mixed_avg_bytes_per_iter_is_in_expected_band() {
        let avg = mixed_avg_bytes_per_iter();
        assert!((200_000.0..400_000.0).contains(&avg), "avg bytes/iter = {avg:.1} outside [200_000, 400_000]");
    }

    /// 0.625 MB/s with mixed profile should land near rate ≈ 2.18 iter/s.
    #[test]
    fn rate_for_625_kbps_target_is_about_2_per_sec() {
        let r = rate_for_target_mb_per_s(0.625);
        assert!((1.5..3.5).contains(&r), "rate {r:.3} outside [1.5, 3.5] for 0.625 MB/s");
    }
}
