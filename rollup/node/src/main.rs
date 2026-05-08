use std::sync::Arc;
use std::time::Instant;

use clap::Parser;
use sophis_rollup_core::L2Address;
use sophis_rollup_sequencer::{Mempool, Sequencer, SequencerConfig, l1_client::GrpcL1Client};

mod config;
mod rpc;

#[tokio::main]
async fn main() {
    let cli = config::Cli::parse();
    let result = match cli.command {
        config::Command::Start(args) => run_start(args).await,
        config::Command::GenKey(args) => run_gen_key(args),
    };
    if let Err(e) = result {
        eprintln!("[rollup-node] error: {e}");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// start
// ---------------------------------------------------------------------------

async fn run_start(args: config::StartArgs) -> Result<(), String> {
    let cfg = config::NodeConfig::resolve(&args);
    let (sk, vk) = config::load_key_file(&cfg.key_file)?;
    let l2_addr = L2Address::from_verkey(&vk);

    let seq_cfg = SequencerConfig {
        signing_key: Box::new(sk),
        verification_key: Box::new(vk),
        l1_rpc_url: cfg.l1_rpc_url.clone(),
        max_batch_txs: cfg.max_batch_txs,
        batch_timeout_secs: cfg.batch_timeout_secs,
        http_port: cfg.http_port,
    };

    let mempool = Arc::new(Mempool::new());
    let l1 = Arc::new(GrpcL1Client {
        endpoint: cfg.l1_rpc_url.clone(),
        state_address: cfg.state_address.clone(),
        signing_key: Box::new(sk),
        verification_key: Box::new(vk),
    });

    println!("[rollup-node] sequencer L2 address : {}", hex::encode(l2_addr.0));
    println!("[rollup-node] L1 gRPC endpoint      : {}", cfg.l1_rpc_url);
    println!(
        "[rollup-node] rollup state address  : {}",
        if cfg.state_address.is_empty() { "(not set — configure via --state-address)" } else { &cfg.state_address }
    );
    println!("[rollup-node] batch trigger          : {} txs OR {} s", cfg.max_batch_txs, cfg.batch_timeout_secs);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", cfg.http_port))
        .await
        .map_err(|e| format!("bind 0.0.0.0:{} failed: {e}", cfg.http_port))?;
    println!("[rollup-node] HTTP listening on      : 0.0.0.0:{}", cfg.http_port);

    let start_time = Instant::now();
    let router = rpc::router(mempool.clone(), start_time);
    let mut http_task = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("HTTP server crashed");
    });

    let mut seq = Sequencer::new(seq_cfg, mempool, l1);
    let mut seq_task = tokio::spawn(async move {
        seq.run(vec![]).await.unwrap_or_else(|e| eprintln!("[sequencer] fatal: {e}"));
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("\n[rollup-node] received Ctrl+C — shutting down");
        }
        res = &mut http_task => {
            eprintln!("[rollup-node] HTTP task ended unexpectedly: {:?}", res);
        }
        res = &mut seq_task => {
            eprintln!("[rollup-node] sequencer task ended unexpectedly: {:?}", res);
        }
    }

    http_task.abort();
    seq_task.abort();
    Ok(())
}

// ---------------------------------------------------------------------------
// gen-key
// ---------------------------------------------------------------------------

fn run_gen_key(args: config::GenKeyArgs) -> Result<(), String> {
    let (sk, vk) = config::gen_keypair();
    config::save_key_file(&args.output, &sk, &vk)?;
    let l2_addr = L2Address::from_verkey(&vk);
    println!("[rollup-node] key file written  : {}", args.output.display());
    println!("[rollup-node] L2 address (hex)  : {}", hex::encode(l2_addr.0));
    println!("[rollup-node] verif. key (hex)  : {}", hex::encode(vk));
    println!("[rollup-node] NOTE: register this address as sequencer_vk in the L1 rollup state UTXO");
    Ok(())
}
