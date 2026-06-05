//! sophis-da-inspect — read-only per-prefix breakdown of the consensus RocksDB.
//!
//! Opens the DB as a **secondary instance** so it can run concurrently with a
//! live `sophisd` (no lock contention; secondary mode is read-only and
//! catches up from the primary's WAL/MANIFEST). Iterates the whole keyspace
//! once and groups by 1-byte prefix (the `DatabaseStorePrefixes` scheme in
//! `database/src/registry.rs`). The DA-carrier prefixes are named so the
//! readout immediately tells F-26 Fix A's coverage from non-DA growth.
//!
//! Usage:
//!   sophis-da-inspect --db <consensus-NNN path> --secondary <empty scratch dir>

use clap::Parser;
use rocksdb::{DBWithThreadMode, IteratorMode, MultiThreaded, Options};
use std::collections::BTreeMap;
use std::error::Error;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "sophis-da-inspect", about = "Per-prefix consensus RocksDB breakdown (secondary mode; no lock).")]
struct Args {
    /// Path to the consensus RocksDB directory, e.g.
    /// <appdir>/sophis-devnet/datadir/consensus/consensus-001
    #[arg(long)]
    db: PathBuf,
    /// Scratch path for the secondary instance's catch-up files (created if absent).
    #[arg(long)]
    secondary: PathBuf,
}

// Named DA-carrier prefixes — keep in sync with database/src/registry.rs.
// (F-26 Fix B split: 196 carries PayloadMeta, the heavy bodies moved to 209.)
const NAMED: &[(u8, &str)] = &[
    (196, "DaCarrierPayloads/PayloadMeta (F-26 Fix B split)"),
    (197, "DaCarrierBundles"),
    (198, "DaCarrierByBlock"),
    (199, "DaCarrierByDomain"),
    (209, "DaCarrierBodies (F-26 Fix B body-horizon GC)"),
];

fn main() -> Result<(), Box<dyn Error>> {
    let a = Args::parse();
    std::fs::create_dir_all(&a.secondary)?;

    let mut opts = Options::default();
    opts.create_if_missing(false);
    let db = DBWithThreadMode::<MultiThreaded>::open_as_secondary(&opts, &a.db, &a.secondary)?;
    // Best-effort catch-up — we want a recent-but-not-strictly-live snapshot.
    let _ = db.try_catch_up_with_primary();

    let mut counts: BTreeMap<u8, (u64, u64)> = BTreeMap::new();
    for kv in db.iterator(IteratorMode::Start) {
        let (k, v) = kv?;
        if k.is_empty() {
            continue;
        }
        let p = k[0];
        let e = counts.entry(p).or_insert((0, 0));
        e.0 += 1;
        e.1 += (k.len() + v.len()) as u64;
    }

    println!("prefix  n_keys         bytes_kv         MB     name");
    let (mut da_n, mut da_b, mut tot_n, mut tot_b) = (0u64, 0u64, 0u64, 0u64);
    for (p, (n, b)) in &counts {
        let name = NAMED.iter().find(|(pp, _)| pp == p).map(|(_, n)| *n).unwrap_or("(other)");
        let mb = (*b as f64) / (1024.0 * 1024.0);
        println!("{:>5}  {:>10}  {:>15}  {:>8.1}  {}", p, n, b, mb, name);
        tot_n += n;
        tot_b += b;
        if NAMED.iter().any(|(pp, _)| pp == p) {
            da_n += n;
            da_b += b;
        }
    }
    println!("---");
    println!("DA-carrier total (196/197/198/199/209): n={}, MB={:.1}", da_n, da_b as f64 / (1024.0 * 1024.0));
    println!("Non-DA total:                           n={}, MB={:.1}", tot_n - da_n, (tot_b - da_b) as f64 / (1024.0 * 1024.0));
    println!(
        "All prefixes total:                     n={}, MB={:.1} (logical k+v; physical SST is larger due to write-amp/headers)",
        tot_n,
        tot_b as f64 / (1024.0 * 1024.0)
    );

    for prop in
        ["rocksdb.estimate-num-keys", "rocksdb.live-sst-files-size", "rocksdb.total-sst-files-size", "rocksdb.estimate-live-data-size"]
    {
        if let Ok(Some(v)) = db.property_int_value(prop) {
            println!("{} = {}", prop, v);
        }
    }
    Ok(())
}
