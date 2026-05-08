use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rollup-node", version, about = "Sophis ZK-Rollup sequencer node")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Start the rollup sequencer node.
    Start(StartArgs),
    /// Generate a new Dilithium ML-DSA-44 sequencer key pair.
    GenKey(GenKeyArgs),
}

#[derive(clap::Args)]
pub struct StartArgs {
    /// TOML config file [default: rollup-node.toml]
    #[arg(long, default_value = "rollup-node.toml")]
    pub config: PathBuf,

    /// L1 wRPC endpoint (overrides config file)
    #[arg(long, env = "ROLLUP_L1_RPC")]
    pub l1_rpc: Option<String>,

    /// HTTP port for L2 tx submissions (overrides config file)
    #[arg(long)]
    pub http_port: Option<u16>,

    /// Dilithium key file path (overrides config file)
    #[arg(long)]
    pub key_file: Option<PathBuf>,

    /// Rollup state UTXO address on L1 (overrides config file)
    #[arg(long)]
    pub state_address: Option<String>,

    /// Maximum txs per batch (overrides config file)
    #[arg(long)]
    pub max_batch_txs: Option<usize>,

    /// Batch flush timeout in seconds (overrides config file)
    #[arg(long)]
    pub batch_timeout: Option<u64>,
}

#[derive(clap::Args)]
pub struct GenKeyArgs {
    /// Output key file path
    #[arg(long, short, default_value = "sequencer.key")]
    pub output: PathBuf,
}

// ---------------------------------------------------------------------------
// TOML config file
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct FileConfig {
    pub l1_rpc_url: Option<String>,
    pub http_port: Option<u16>,
    pub key_file: Option<String>,
    pub state_address: Option<String>,
    pub max_batch_txs: Option<usize>,
    pub batch_timeout_secs: Option<u64>,
}

impl FileConfig {
    pub fn load(path: &PathBuf) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| toml::from_str(&s).map_err(|e| eprintln!("[rollup-node] warning: {}: {e}", path.display())).ok())
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Merged configuration (file + CLI overrides)
// ---------------------------------------------------------------------------

pub struct NodeConfig {
    pub l1_rpc_url: String,
    pub http_port: u16,
    pub key_file: PathBuf,
    pub state_address: String,
    pub max_batch_txs: usize,
    pub batch_timeout_secs: u64,
}

impl NodeConfig {
    pub fn resolve(args: &StartArgs) -> Self {
        let file = FileConfig::load(&args.config);
        NodeConfig {
            l1_rpc_url: args.l1_rpc.clone().or(file.l1_rpc_url).unwrap_or_else(|| "127.0.0.1:46610".into()),
            http_port: args.http_port.or(file.http_port).unwrap_or(9944),
            key_file: args.key_file.clone().or_else(|| file.key_file.map(PathBuf::from)).unwrap_or_else(|| "sequencer.key".into()),
            state_address: args.state_address.clone().or(file.state_address).unwrap_or_default(),
            max_batch_txs: args.max_batch_txs.or(file.max_batch_txs).unwrap_or(100),
            batch_timeout_secs: args.batch_timeout.or(file.batch_timeout_secs).unwrap_or(30),
        }
    }
}

// ---------------------------------------------------------------------------
// Key file: 3872 bytes = 2560 (signing key) || 1312 (verification key)
// ---------------------------------------------------------------------------

const KEY_FILE_LEN: usize = 2560 + 1312;

pub fn load_key_file(path: &PathBuf) -> Result<([u8; 2560], [u8; 1312]), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if bytes.len() != KEY_FILE_LEN {
        return Err(format!("{}: expected {} bytes, got {}", path.display(), KEY_FILE_LEN, bytes.len()));
    }
    let mut sk = [0u8; 2560];
    let mut vk = [0u8; 1312];
    sk.copy_from_slice(&bytes[..2560]);
    vk.copy_from_slice(&bytes[2560..]);
    Ok((sk, vk))
}

pub fn save_key_file(path: &PathBuf, sk: &[u8; 2560], vk: &[u8; 1312]) -> Result<(), String> {
    let mut bytes = Vec::with_capacity(KEY_FILE_LEN);
    bytes.extend_from_slice(sk);
    bytes.extend_from_slice(vk);
    std::fs::write(path, bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

pub fn gen_keypair() -> ([u8; 2560], [u8; 1312]) {
    use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, ml_dsa_44};
    use rand::TryRngCore;
    let mut seed = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
    rand::rngs::OsRng.try_fill_bytes(&mut seed).expect("os entropy");
    let kp = ml_dsa_44::generate_key_pair(seed);
    (*kp.signing_key.as_ref(), *kp.verification_key.as_ref())
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn key_file_round_trip() {
        let sk = [1u8; 2560];
        let vk = [2u8; 1312];
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_path_buf();
        save_key_file(&path, &sk, &vk).unwrap();
        let (sk2, vk2) = load_key_file(&path).unwrap();
        assert_eq!(sk, sk2);
        assert_eq!(vk, vk2);
    }

    #[test]
    fn load_rejects_wrong_size() {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(f.path(), b"too short").unwrap();
        let err = load_key_file(&f.path().to_path_buf()).unwrap_err();
        assert!(err.contains("expected"), "unexpected error: {err}");
    }
}
