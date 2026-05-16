//! `sophis-oracle-indexer` — Phase 9 reference indexer CLI.
//!
//! Deterministic, file/stdin-driven. Ingests already-decoded Phase 9
//! `PriceAttestation`s (hex, one per line — as a J4 event log dump would
//! yield) plus optional Phase 5 samples (CSV), aggregates per SIP-11 D4
//! rounds, runs the PHASE9_3 dual-path dispatch, and prints a
//! deterministic per-asset snapshot (canonical source + price + last
//! flip decision).
//!
//! **Scope boundary:** subscribing to a live Sophis node's J4 event
//! stream (gRPC/wRPC) is the operator's integration step (RUNBOOK §1
//! "custom watcher") — deliberately out of v1, exactly as
//! `sophis-oracle-publisher` punts on-chain submission to
//! `dilithium-wallet`. This binary proves the deterministic core; the
//! node adapter is a thin documented seam, not core logic.
//!
//! Usage:
//!   sophis-oracle-indexer snapshot --events att.hex [--phase5 p5.csv]
//!                                  [--now <unix>] [--round-window-secs 60]
//! `--events -` reads hex lines from stdin. Phase 5 CSV rows:
//! `SYMBOL,publish_ts,price_e8` (e.g. `BTC/USD,1700000000,6500000000000`).

use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Arg, ArgMatches, Command};
use sophis_oracle_pqc_core::{FeedSource, FlipPolicy, PriceAttestation, PriceSample, asset_id_from_symbol};
use sophis_oracle_pqc_indexer::{DEFAULT_ROUND_WINDOW_SECS, Indexer};

fn main() -> ExitCode {
    match build_cli().get_matches().subcommand() {
        Some(("snapshot", sub)) => match run_snapshot(sub) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sophis-oracle-indexer: {e}");
                ExitCode::FAILURE
            }
        },
        _ => {
            let _ = build_cli().print_help();
            ExitCode::from(2)
        }
    }
}

fn build_cli() -> Command {
    Command::new("sophis-oracle-indexer")
        .about("Phase 9 PQC-native oracle reference indexer (SIP-11 / PHASE9_3_DUAL_PATH)")
        .version(env!("CARGO_PKG_VERSION"))
        .arg_required_else_help(true)
        .subcommand(
            Command::new("snapshot")
                .about("Ingest events, aggregate + dispatch, print a deterministic per-asset snapshot")
                .arg(
                    Arg::new("events")
                        .long("events")
                        .required(true)
                        .help("File of hex-encoded PriceAttestations (one per line); '-' = stdin"),
                )
                .arg(
                    Arg::new("phase5")
                        .long("phase5")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Optional CSV of Phase 5 samples: SYMBOL,publish_ts,price_e8"),
                )
                .arg(
                    Arg::new("now")
                        .long("now")
                        .value_parser(clap::value_parser!(u64))
                        .help("Unix-seconds 'now' for aggregation/dispatch. Default: OS time"),
                )
                .arg(
                    Arg::new("round-window-secs")
                        .long("round-window-secs")
                        .value_parser(clap::value_parser!(u64))
                        .help(format!("Aggregation round window (SIP-11 D4 default {DEFAULT_ROUND_WINDOW_SECS}s)")),
                ),
        )
}

fn run_snapshot(m: &ArgMatches) -> Result<(), String> {
    let now: u64 = m.get_one::<u64>("now").copied().unwrap_or_else(unix_now);
    let window: u64 = m.get_one::<u64>("round-window-secs").copied().unwrap_or(DEFAULT_ROUND_WINDOW_SECS);
    let policy = FlipPolicy::default();
    let mut ix = Indexer::new(window);

    // --- Phase 9 attestations (hex lines; '-' = stdin) ---
    let events_arg: &String = m.get_one("events").expect("required by clap");
    let raw = if events_arg == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).map_err(|e| format!("cannot read stdin: {e}"))?;
        s
    } else {
        fs::read_to_string(events_arg).map_err(|e| format!("cannot read events file {events_arg}: {e}"))?
    };
    let (mut ingested, mut rejected) = (0u64, 0u64);
    for (lineno, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.len().is_multiple_of(2) {
            return Err(format!("events line {}: odd-length hex", lineno + 1));
        }
        let mut bytes = vec![0u8; line.len() / 2];
        faster_hex::hex_decode(line.as_bytes(), &mut bytes).map_err(|_| format!("events line {}: invalid hex", lineno + 1))?;
        let att = PriceAttestation::from_bytes(&bytes).map_err(|e| format!("events line {}: decode failed: {e:?}", lineno + 1))?;
        match ix.ingest_phase9(&att, now) {
            Ok(()) => ingested += 1,
            Err(_) => rejected += 1, // verification-rejected attestations are dropped (defense-in-depth)
        }
    }

    // --- Optional Phase 5 samples ---
    if let Some(p5path) = m.get_one::<PathBuf>("phase5") {
        let csv = fs::read_to_string(p5path).map_err(|e| format!("cannot read phase5 csv {}: {e}", p5path.display()))?;
        for (lineno, line) in csv.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() != 3 {
                return Err(format!("phase5 csv line {}: expected SYMBOL,publish_ts,price_e8", lineno + 1));
            }
            let asset_id = asset_id_from_symbol(parts[0].trim().as_bytes());
            let publish_ts: u64 = parts[1].trim().parse().map_err(|_| format!("phase5 csv line {}: bad ts", lineno + 1))?;
            let price_e8: i64 = parts[2].trim().parse().map_err(|_| format!("phase5 csv line {}: bad price", lineno + 1))?;
            ix.ingest_phase5(asset_id, PriceSample { publish_ts, price_e8 });
        }
    }

    // --- Aggregate + dispatch (deterministic) ---
    ix.aggregate_due_rounds(now, &policy);
    let assets: Vec<[u8; 32]> = ix.tracked_assets().copied().collect();
    for aid in &assets {
        ix.reevaluate(*aid, now, &policy);
    }

    // --- Deterministic snapshot ---
    println!("# sophis-oracle-indexer snapshot  now={now}  round_window_secs={window}");
    println!("# phase9 events: ingested={ingested} rejected={rejected}  assets={}", assets.len());
    for aid in &assets {
        let mut hex = vec![0u8; 64];
        faster_hex::hex_encode(aid, &mut hex).expect("hex fits");
        let asset_hex = String::from_utf8(hex).expect("ascii");
        let src = match ix.feed_source(aid) {
            FeedSource::Phase5 => "Phase5".to_string(),
            FeedSource::Phase9 { active_since_ts } => format!("Phase9(since={active_since_ts})"),
            FeedSource::Unavailable => "Unavailable".to_string(),
        };
        let price = ix
            .read_price(aid)
            .map(|r| format!("price_e8={} conf_e8={} ts={}", r.price_e8, r.conf_e8, r.publish_ts))
            .unwrap_or_else(|| "price=<none>".to_string());
        let decision = ix.last_decision(aid).map(|d| format!("{d:?}")).unwrap_or_else(|| "<none>".to_string());
        println!("asset={asset_hex}  source={src}  {price}  decision={decision}");
    }
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
