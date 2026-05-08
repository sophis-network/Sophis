//! `sophis-da-stress` — Phase 6 DA layer synthetic load generator.
//!
//! Sub-fase 6.8.b. Companion to `devnet/da_stress_check.py` (which
//! observes; this generates).
//!
//! ## Usage
//!
//! ```text
//! sophis-da-stress \
//!   --wallet dilithium_wallet.json \
//!   --rpcserver localhost:46610 \
//!   --duration 60s \
//!   --rate 1 \
//!   --min-size 32 --max-size 1024 \
//!   --domain Oracle \
//!   --csv stress.csv
//! ```
//!
//! Each iteration:
//!   1. Generates a random payload of size `[min_size, max_size]`.
//!   2. Encodes via `encode_bundle` (1+ V5 carrier scripts).
//!   3. Builds a transaction with carrier outputs + change.
//!   4. Dilithium-signs and submits via gRPC.
//!   5. Records timestamp, size, fragments, tx_id, latency, status to CSV.
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
    da::{CarrierDomain, encode_bundle},
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
    entries
        .into_iter()
        .filter(|e| {
            // Coinbase maturity is much higher than tx maturity. Use 1000 as a
            // conservative bound; honest test wallets exceed that quickly.
            let needed = if e.utxo_entry.is_coinbase { 1000 } else { 10 };
            e.utxo_entry.block_daa_score + needed < daa
        })
        .map(|e| (TransactionOutpoint::from(e.outpoint), UtxoEntry::from(e.utxo_entry)))
        .collect()
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

// ─── Main loop ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct LoopParams {
    rate_per_sec: f64,
    min_size: usize,
    max_size: usize,
    domain: Option<CarrierDomain>,
    duration: Duration,
}

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
            writeln!(f, "iso_timestamp,unix_ms,payload_bytes,fragments,tx_id,latency_ms,status,error")?;
            Some(f)
        }
        None => None,
    };

    let start = Instant::now();
    let mut iter: u64 = 0;
    let mut ok_count: u64 = 0;
    let mut err_count: u64 = 0;
    let mut total_payload_bytes: u64 = 0;

    while start.elapsed() < params.duration {
        let iter_start = Instant::now();
        iter += 1;

        // Random payload size in [min_size, max_size].
        let size =
            if params.min_size == params.max_size { params.min_size } else { rng.random_range(params.min_size..=params.max_size) };
        let mut payload = vec![0u8; size];
        rng.fill_bytes(&mut payload);

        // Refresh UTXOs every iteration (could optimize by caching with TTL,
        // but at typical rates the freshness matters).
        let utxos = fetch_spendable_utxos(&rpc, &address).await;
        if utxos.is_empty() {
            log::warn!("no spendable UTXOs available — sleeping 5s");
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        let scripts = match encode_bundle(&payload, params.domain) {
            Ok(s) => s,
            Err(e) => {
                log::error!("encode_bundle error: {:?}", e);
                err_count += 1;
                continue;
            }
        };
        let n_fragments = scripts.len();
        let fee: u64 = 100_000 * (1 + n_fragments as u64);

        let tx = match build_signed_da_tx(&utxos, &scripts, fee, &address, &vk, &sk) {
            Ok(t) => t,
            Err(e) => {
                log::error!("build_signed_da_tx error: {}", e);
                err_count += 1;
                csv_log(&mut csv_writer, iter_start, size, n_fragments, "", -1, "build_error", &e.to_string());
                continue;
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
            ok_count += 1;
            total_payload_bytes += size as u64;
        } else {
            err_count += 1;
        }

        csv_log(&mut csv_writer, iter_start, size, n_fragments, &tx_id_str, latency_ms, status_label, &error_msg);
        if iter.is_multiple_of(10) {
            println!(
                "[{:>5}] sent={} ok={} err={} bytes={} elapsed={:?}",
                iter,
                iter,
                ok_count,
                err_count,
                total_payload_bytes,
                start.elapsed(),
            );
        }

        // Rate limit — sleep until next slot.
        let elapsed_iter = iter_start.elapsed();
        if elapsed_iter < interval {
            tokio::time::sleep(interval - elapsed_iter).await;
        }
    }

    println!("\n=== sophis-da-stress summary ===");
    println!("Iterations  : {}", iter);
    println!("OK          : {}", ok_count);
    println!("Errors      : {}", err_count);
    println!("Bytes total : {}", total_payload_bytes);
    println!("Wall time   : {:?}", start.elapsed());
    if let Some(p) = &csv_path {
        println!("CSV         : {}", p.display());
    }

    Ok(())
}

fn csv_log(
    f: &mut Option<std::fs::File>,
    when: Instant,
    size: usize,
    fragments: usize,
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
    let _ = writeln!(file, "{},{},{},{},{},{},{},{}", iso, unix_ms, size, fragments, tx_id, latency_ms, status, safe_err);
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
            Arg::new("rate")
                .long("rate")
                .short('r')
                .default_value("1")
                .value_parser(value_parser!(f64))
                .help("Submissões por segundo (alvo)"),
        )
        .arg(Arg::new("min-size").long("min-size").default_value("32").value_parser(value_parser!(usize)))
        .arg(Arg::new("max-size").long("max-size").default_value("1024").value_parser(value_parser!(usize)))
        .arg(Arg::new("domain").long("domain").default_value("user").help("Rollup|Oracle|User|None"))
        .arg(Arg::new("csv").long("csv").help("Caminho de saída para CSV de métricas (opcional)"))
        .get_matches();

    let wallet_path = PathBuf::from(m.get_one::<String>("wallet").unwrap());
    let rpc_server = m.get_one::<String>("rpcserver").unwrap().clone();
    let duration = parse_duration(m.get_one::<String>("duration").unwrap()).unwrap_or_else(|e| {
        eprintln!("Erro: {}", e);
        std::process::exit(2);
    });
    let rate = *m.get_one::<f64>("rate").unwrap();
    let min_size = *m.get_one::<usize>("min-size").unwrap();
    let max_size = *m.get_one::<usize>("max-size").unwrap();
    if min_size > max_size {
        eprintln!("Erro: --min-size > --max-size");
        std::process::exit(2);
    }
    let domain = parse_domain(m.get_one::<String>("domain").unwrap()).unwrap_or_else(|e| {
        eprintln!("Erro: {}", e);
        std::process::exit(2);
    });
    let csv_path = m.get_one::<String>("csv").map(PathBuf::from);

    let wallet = Wallet::load(&wallet_path).expect("Wallet não encontrada");
    let address = wallet.address().expect("endereço inválido na wallet");
    let vk = wallet.verification_key().expect("VK inválida na wallet");
    let sk = wallet.signing_key().expect("SK inválida na wallet");

    println!("sophis-da-stress");
    println!("  wallet     : {}", wallet_path.display());
    println!("  rpcserver  : {}", rpc_server);
    println!("  address    : {}", address);
    println!("  duration   : {:?}", duration);
    println!("  rate       : {} tx/s", rate);
    println!("  size range : {}..={} bytes", min_size, max_size);
    println!("  domain     : {:?}", domain);
    if let Some(p) = &csv_path {
        println!("  csv        : {}", p.display());
    }
    println!();

    let rpc = connect(&rpc_server).await;
    let params = LoopParams { rate_per_sec: rate, min_size, max_size, domain, duration };

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
}
