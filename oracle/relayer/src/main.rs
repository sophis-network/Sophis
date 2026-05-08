//! sophis-oracle-relayer — Phase 5 ZK-Oracle relayer binary.
//!
//! Sub-phase 5.4 status:
//!   - 5.4.a: CLI + config + skeleton (this file)
//!   - 5.4.b: VerifyAirChip boundary exposure (oracle-host)
//!   - 5.4.c: pipeline pull → prove → bundle (`pipeline::run_once`)
//!   - 5.4.d: Dilithium sign + wire payload (`sign`)
//!   - 5.4.e: L1 submit trait (gRPC scaffold + MockSubmit) (`submit`)
//!   - 5.4.f: daemon loop + sequence persistence (`daemon`, `state`)
//!
//! Subcommands:
//!   inspect      Load + validate the config and print a summary; no I/O.
//!   relay-once   Pull → prove → sign → submit one update via MockSubmit.
//!   daemon       Run the loop forever via MockSubmit.
//!
//! Production gRPC submission (`GrpcSubmit`) is feature-gated for sub-fase
//! 5.4.f.1 — the binary today wires `MockSubmit` so the operator can
//! validate the full pipeline locally without sophisd. To target a real
//! L1, rebuild with the future `grpc-submit` feature flag.

use clap::{Parser, Subcommand};
use sophis_oracle_core::PublisherKey;
use sophis_oracle_feeds::{PriceFeed, PythnetClient, PythnetConfig};
use sophis_oracle_relayer::config::RelayerConfig;
use sophis_oracle_relayer::daemon::{one_iteration, run_daemon};
use sophis_oracle_relayer::error::RelayerError;
use sophis_oracle_relayer::pipeline::PipelinePolicy;
use sophis_oracle_relayer::sign::RelayerKey;
use sophis_oracle_relayer::state::RelayerState;
use sophis_oracle_relayer::submit::L1Submit;
#[cfg(not(feature = "grpc-submit"))]
use sophis_oracle_relayer::submit::MockSubmit;
#[cfg(feature = "grpc-submit")]
use sophis_oracle_relayer::submit::GrpcSubmit;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "sophis-oracle-relayer",
    about = "Sophis Phase 5 ZK-Oracle relayer (Pyth → Plonky3 → Dilithium → L1)",
    version
)]
struct Cli {
    /// Path to the relayer TOML config.
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,

    /// Log filter (e.g. info, debug, sophis_oracle_relayer=debug).
    #[arg(long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Pull → prove → sign → submit one oracle update and exit.
    RelayOnce,
    /// Run forever, one update every `daemon.interval_secs`.
    Daemon,
    /// Load and validate the config; print a summary; do not touch I/O.
    Inspect,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    sophis_core::log::init_logger(None, &cli.log_level);

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("relayer exited with error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), RelayerError> {
    let config = RelayerConfig::load(&cli.config)?;
    log::info!("loaded config from {}", cli.config.display());

    match cli.cmd {
        Cmd::Inspect => {
            inspect(&config);
            Ok(())
        }
        Cmd::RelayOnce => relay_once(&config).await,
        Cmd::Daemon => daemon(&config).await,
    }
}

fn inspect(cfg: &RelayerConfig) {
    println!("Pythnet:");
    println!("  endpoint        : {}", cfg.pythnet.rpc_endpoint);
    println!("  price account   : {}", cfg.pythnet.price_account);
    println!("  publisher       : {}", cfg.pythnet.publisher);
    println!("Feed:");
    println!("  id              : {:?} (8-byte: {:02x?})", cfg.feed.id, cfg.feed_id_bytes());
    println!("  bounds          : [{}, {}]", cfg.feed.min_price, cfg.feed.max_price);
    println!("  max_age_secs    : {}", cfg.feed.max_age_secs);
    println!("Proving:");
    println!("  verify_air comp : {}", cfg.verify_air_companion());
    println!("Signing:");
    println!("  key_path        : {}", cfg.signing.key_path.display());
    println!("Submit:");
    println!("  grpc            : {}", cfg.submit.grpc_endpoint);
    println!("  contract        : {}", cfg.submit.contract_address);
    println!("  state_path      : {}", cfg.submit.state_path.display());
    println!("Daemon:");
    println!("  interval_secs   : {}", cfg.daemon.interval_secs);
}

/// Build a `PipelinePolicy` from the loaded config.
fn build_policy(cfg: &RelayerConfig) -> Result<PipelinePolicy, RelayerError> {
    let publisher_bytes = decode_b58_pubkey(&cfg.pythnet.publisher)
        .map_err(|e| RelayerError::Other(format!("invalid publisher base58: {e}")))?;
    Ok(PipelinePolicy {
        feed: sophis_oracle_core::FeedId(cfg.feed_id_bytes()),
        publisher: PublisherKey(publisher_bytes),
        min_price: cfg.feed.min_price,
        max_price: cfg.feed.max_price,
        max_age_secs: cfg.feed.max_age_secs,
        verify_air_companion: cfg.verify_air_companion(),
    })
}

/// Standalone base58 decoder so we don't pull in `bs58` for one call.
fn decode_b58_pubkey(s: &str) -> Result<[u8; 32], String> {
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut num: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let v = alphabet.iter().position(|&x| x == c).ok_or_else(|| format!("invalid base58 char: {c:?}"))?;
        let mut carry = v;
        for byte in num.iter_mut() {
            carry += (*byte as usize) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            num.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    for c in s.bytes() {
        if c == b'1' {
            num.push(0);
        } else {
            break;
        }
    }
    num.reverse();
    if num.len() != 32 {
        return Err(format!("expected 32-byte pubkey, decoded {} bytes", num.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&num);
    Ok(out)
}

async fn relay_once(cfg: &RelayerConfig) -> Result<(), RelayerError> {
    let policy = build_policy(cfg)?;
    let pyth = build_pyth_client(cfg);
    let submit = build_submit(cfg)?;

    let mut state = RelayerState::load_or_default(&cfg.submit.state_path)
        .map_err(|e| RelayerError::Io(std::io::Error::other(e.to_string())))?;
    let seq = one_iteration(pyth.as_ref(), submit.as_ref(), &policy, &mut state, cfg.submit.da_publish)
        .await
        .map_err(|e| RelayerError::Io(std::io::Error::other(e.to_string())))?;
    state.save(&cfg.submit.state_path).map_err(|e| RelayerError::Io(std::io::Error::other(e.to_string())))?;
    log::info!("relay-once done: submitted sequence {seq}");
    Ok(())
}

async fn daemon(cfg: &RelayerConfig) -> Result<(), RelayerError> {
    let policy = build_policy(cfg)?;
    let pyth: Arc<dyn PriceFeed> = build_pyth_client(cfg);
    let submit = build_submit(cfg)?;

    run_daemon(pyth, submit, policy, cfg.submit.state_path.clone(), cfg.daemon.interval_secs, cfg.submit.da_publish)
        .await
        .map_err(|e| RelayerError::Io(std::io::Error::other(e.to_string())))
}

/// Pick the L1Submit implementation based on the `grpc-submit` feature.
/// Production (feature ON) uses GrpcSubmit; default (OFF) uses MockSubmit
/// so the binary works without sophisd for local validation.
fn build_submit(cfg: &RelayerConfig) -> Result<Arc<dyn L1Submit>, RelayerError> {
    let key = RelayerKey::load(&cfg.signing.key_path).map_err(|e| RelayerError::Io(std::io::Error::other(e.to_string())))?;
    #[cfg(feature = "grpc-submit")]
    {
        log::info!(
            "submit: GrpcSubmit (endpoint={}, contract={}, prefix={})",
            cfg.submit.grpc_endpoint,
            cfg.submit.contract_address,
            cfg.submit.network_prefix,
        );
        Ok(Arc::new(GrpcSubmit::new(
            cfg.submit.grpc_endpoint.clone(),
            cfg.submit.contract_address.clone(),
            cfg.submit.network_prefix.clone(),
            key,
        )))
    }
    #[cfg(not(feature = "grpc-submit"))]
    {
        // Touch the network_prefix field so it stays "used" when feature is OFF.
        let _ = &cfg.submit.network_prefix;
        log::info!("submit: MockSubmit (rebuild with --features grpc-submit for production L1)");
        Ok(Arc::new(MockSubmit::new(key)))
    }
}

fn build_pyth_client(cfg: &RelayerConfig) -> Arc<dyn PriceFeed> {
    Arc::new(PythnetClient::new(PythnetConfig {
        rpc_endpoint: cfg.pythnet.rpc_endpoint.clone(),
        price_account_b58: cfg.pythnet.price_account.clone(),
        publisher_b58: cfg.pythnet.publisher.clone(),
    }))
}
