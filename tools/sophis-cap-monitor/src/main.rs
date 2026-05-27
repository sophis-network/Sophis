// sophis-cap-monitor — founder self-restriction watchdog.
//
// Queries a local sophisd node periodically and tracks the running balance of
// a single declared address against the network's circulating supply. When the
// observed high-water-mark of that address crosses a configurable share of the
// supply (default 4.9%), the watchdog kills the local miner process and exits
// non-zero. Spending from the address does NOT lower the effective cap because
// the high-water-mark is monotone and persisted to a JSON state file.
//
// Public + verifiable: anyone can run this against any node with --utxoindex
// to independently audit the founder's stated cap. The kill action is the
// only side-effect; in --dry-run it is suppressed for off-side verifiers.

mod state;

use std::path::PathBuf;
use std::process::Command as ProcCommand;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Arg, ArgAction, Command};
use sophis_addresses::Address;
use sophis_core::{error, info, warn};
use sophis_grpc_client::GrpcClient;
use sophis_notify::subscription::context::SubscriptionContext;
use sophis_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};
use tokio::time::sleep;

use crate::state::State;

const RPC_CALL_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_RPC_SERVER: &str = "127.0.0.1:46110"; // mainnet
const DEFAULT_STATE_FILE: &str = "cap-monitor-state.json";

#[cfg(windows)]
const DEFAULT_MINER_PROC: &str = "sophis-miner.exe";
#[cfg(not(windows))]
const DEFAULT_MINER_PROC: &str = "sophis-miner";

#[tokio::main]
async fn main() {
    sophis_core::log::init_logger(None, "");

    let m = Command::new("sophis-cap-monitor")
        .about("Sophis founder self-restriction watchdog (auto-pause at configurable supply share).")
        .arg(
            Arg::new("rpc-server")
                .long("rpc-server")
                .short('s')
                .default_value(DEFAULT_RPC_SERVER)
                .help("gRPC endpoint of the local sophisd node (host:port). Mainnet=46110, testnet=46210, devnet=46610."),
        )
        .arg(
            Arg::new("address")
                .long("address")
                .short('a')
                .required(true)
                .help("Single declared founder address to monitor (sophis:..., sophistest:..., sophisdev:...). Must match the address the miner pays to."),
        )
        .arg(
            Arg::new("threshold-bps")
                .long("threshold-bps")
                .default_value("490")
                .value_parser(clap::value_parser!(u32))
                .help("Pause threshold in basis points of circulating supply. Default 490 = 4.9%. The public commitment is 5.0% — keep this strictly below it."),
        )
        .arg(
            Arg::new("interval-secs")
                .long("interval-secs")
                .default_value("300")
                .value_parser(clap::value_parser!(u64))
                .help("Seconds between checks. Default 300 (5 min)."),
        )
        .arg(
            Arg::new("state-file")
                .long("state-file")
                .default_value(DEFAULT_STATE_FILE)
                .help("Path to the JSON state file (persists the address balance high-water-mark across restarts)."),
        )
        .arg(
            Arg::new("miner-process")
                .long("miner-process")
                .default_value(DEFAULT_MINER_PROC)
                .help("Process name passed to taskkill (Windows) or pkill (Unix) when the cap is hit."),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .action(ArgAction::SetTrue)
                .help("Log only — never kill the miner. Use this for independent third-party verification."),
        )
        .get_matches();

    let rpc_server = m.get_one::<String>("rpc-server").unwrap().clone();
    let address_str = m.get_one::<String>("address").unwrap().clone();
    let threshold_bps: u32 = *m.get_one::<u32>("threshold-bps").unwrap();
    let interval_secs: u64 = *m.get_one::<u64>("interval-secs").unwrap();
    let state_path: PathBuf = PathBuf::from(m.get_one::<String>("state-file").unwrap());
    let miner_proc: String = m.get_one::<String>("miner-process").unwrap().clone();
    let dry_run = m.get_flag("dry-run");

    if threshold_bps == 0 || threshold_bps > 10_000 {
        eprintln!("invalid --threshold-bps={threshold_bps}: must be in 1..=10000");
        std::process::exit(1);
    }
    if threshold_bps > 500 {
        warn!(
            "--threshold-bps={threshold_bps} exceeds the 5.0% public commitment (500); proceeding anyway, but this defeats the purpose of the cap."
        );
    }
    if interval_secs == 0 {
        eprintln!("invalid --interval-secs=0");
        std::process::exit(1);
    }

    let address = match Address::try_from(address_str.as_str()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("invalid --address {address_str:?}: {e}");
            std::process::exit(1);
        }
    };

    let mut st = match State::load_or_init(&state_path, &address_str) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("state file error: {e}");
            std::process::exit(1);
        }
    };

    info!(
        "cap-monitor starting: rpc={} address={} threshold_bps={} interval={}s dry_run={} state={} miner_proc={}",
        rpc_server,
        address_str,
        threshold_bps,
        interval_secs,
        dry_run,
        state_path.display(),
        miner_proc
    );
    if st.paused {
        warn!(
            "state file says paused=true (event at unix {:?}). Watchdog will refuse to issue another kill until you clear the state file manually.",
            st.pause_event_unix
        );
    }

    let mut rpc = reconnect_grpc(&rpc_server).await;

    loop {
        let now = unix_now();

        // --- get_coin_supply ----------------------------------------------
        let supply_fut = rpc.get_coin_supply();
        let supply = match tokio::time::timeout(RPC_CALL_TIMEOUT, supply_fut).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                warn!("get_coin_supply failed: {e}. Reconnecting.");
                rpc = reconnect_grpc(&rpc_server).await;
                sleep(Duration::from_secs(5)).await;
                continue;
            }
            Err(_) => {
                warn!("get_coin_supply timed out after {}s — reconnecting gRPC.", RPC_CALL_TIMEOUT.as_secs());
                rpc = reconnect_grpc(&rpc_server).await;
                continue;
            }
        };

        // --- get_balance_by_address --------------------------------------
        let bal_fut = rpc.get_balance_by_address(address.clone());
        let balance = match tokio::time::timeout(RPC_CALL_TIMEOUT, bal_fut).await {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => {
                warn!("get_balance_by_address failed: {e}. Reconnecting (is sophisd running with --utxoindex?).");
                rpc = reconnect_grpc(&rpc_server).await;
                sleep(Duration::from_secs(5)).await;
                continue;
            }
            Err(_) => {
                warn!("get_balance_by_address timed out after {}s — reconnecting gRPC.", RPC_CALL_TIMEOUT.as_secs());
                rpc = reconnect_grpc(&rpc_server).await;
                continue;
            }
        };

        // --- Update high-water-mark --------------------------------------
        if balance > st.hwm_sompi {
            st.hwm_sompi = balance;
            st.hwm_observed_at_unix = now;
        }

        // --- Compute ratio ----------------------------------------------
        // Denominator = circulating_sompi (issued minus burned). Using
        // circulating instead of issued is strictly more conservative for
        // a cap on the founder's share: if anyone burns, the denominator
        // shrinks and the watchdog trips earlier rather than later.
        let denom = supply.circulating_sompi;
        let ratio_bps: u64 = if denom == 0 { 0 } else { (st.hwm_sompi as u128 * 10_000u128 / denom as u128) as u64 };

        st.last_check_unix = now;
        st.last_circulating_sompi = denom;
        st.last_balance_sompi = balance;
        st.last_ratio_bps = ratio_bps;

        info!(
            "tick: balance={} hwm={} circulating={} ratio_bps={} (threshold={}) paused={}",
            balance, st.hwm_sompi, denom, ratio_bps, threshold_bps, st.paused
        );

        if ratio_bps >= threshold_bps as u64 && !st.paused {
            warn!(
                "THRESHOLD REACHED: hwm={} circulating={} ratio_bps={} >= threshold={}",
                st.hwm_sompi, denom, ratio_bps, threshold_bps
            );
            if dry_run {
                warn!("--dry-run set: NOT killing {miner_proc}. (Set --dry-run off in production.)");
            } else {
                kill_miner(&miner_proc);
                st.paused = true;
                st.pause_event_unix = Some(now);
                if let Err(e) = st.save(&state_path) {
                    error!("failed to persist paused state: {e}");
                }
                error!("MINER PAUSED. Watchdog exiting (status=2).");
                std::process::exit(2);
            }
        }

        if let Err(e) = st.save(&state_path) {
            warn!("state save failed (will retry next tick): {e}");
        }

        sleep(Duration::from_secs(interval_secs)).await;
    }
}

// gRPC connect with exponential backoff. Mirrors the helper in miner/main.rs
// so a stuck stream causes a clean reconnect rather than blocking the loop.
async fn reconnect_grpc(rpc_server: &str) -> GrpcClient {
    let mut backoff_ms: u64 = 250;
    loop {
        let sub_ctx = SubscriptionContext::new();
        match GrpcClient::connect_with_args(
            NotificationMode::Direct,
            format!("grpc://{}", rpc_server),
            Some(sub_ctx),
            true,
            None,
            false,
            Some(500_000),
            Default::default(),
        )
        .await
        {
            Ok(r) => {
                info!("connected: grpc://{}", rpc_server);
                return r;
            }
            Err(e) => {
                warn!("connect failed ({e}); retry in {backoff_ms}ms");
                sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms.saturating_mul(2)).min(5_000);
            }
        }
    }
}

#[cfg(windows)]
fn kill_miner(name: &str) {
    let exe = if name.to_ascii_lowercase().ends_with(".exe") { name.to_string() } else { format!("{name}.exe") };
    match ProcCommand::new("taskkill").args(["/F", "/IM", &exe]).output() {
        Ok(o) => warn!(
            "taskkill /F /IM {}: status={:?} stdout={} stderr={}",
            exe,
            o.status,
            String::from_utf8_lossy(&o.stdout).trim(),
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => warn!("taskkill failed to spawn: {e}"),
    }
}

#[cfg(not(windows))]
fn kill_miner(name: &str) {
    let bare = name.trim_end_matches(".exe");
    match ProcCommand::new("pkill").args(["-f", bare]).output() {
        Ok(o) => warn!(
            "pkill -f {}: status={:?} stdout={} stderr={}",
            bare,
            o.status,
            String::from_utf8_lossy(&o.stdout).trim(),
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => warn!("pkill failed to spawn: {e}"),
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
