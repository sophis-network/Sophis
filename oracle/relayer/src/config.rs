//! Relayer configuration loaded from a TOML file.
//!
//! Example `relayer.toml`:
//!
//! ```toml
//! [pythnet]
//! rpc_endpoint     = "https://pythnet.rpcpool.com"
//! price_account    = "GVXRSBjFk6e6J3NbVPXohDJetcTjaeeuykUpbQF8UoMU"
//! publisher        = "5j5xK4U7yeC1RVH4MM7yAHzkhdJYuBjFFyMvmaq2HBXM"
//!
//! [feed]
//! id               = "BTC/USD"
//! min_price        = 100_00
//! max_price        = 100_000_000_00
//! max_age_secs     = 60
//!
//! [proving]
//! # Whether to also prove ed25519 verify_air as a companion (sub-phase 5.4.c).
//! verify_air_companion = true
//!
//! [signing]
//! # Path to a file containing the relayer's ML-DSA-44 secret key (2560 bytes, raw).
//! key_path         = "./relayer-dilithium.sk"
//!
//! [submit]
//! grpc_endpoint    = "127.0.0.1:46110"           # sophisd gRPC
//! contract_address = "sophis:qx..."              # oracle sVM contract bech32m address
//! state_path       = "./relayer-state.json"      # sequence number persistence
//!
//! [daemon]
//! interval_secs    = 30
//! ```

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("io error reading {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("toml parse error: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid feed id {0:?} (must be 1-8 ASCII bytes)")]
    BadFeedId(String),
    #[error("min_price ({min}) must be < max_price ({max})")]
    BadPriceBounds { min: i64, max: i64 },
    #[error("max_age_secs must be > 0")]
    ZeroMaxAge,
    #[error("interval_secs must be > 0")]
    ZeroInterval,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PythnetSection {
    pub rpc_endpoint: String,
    pub price_account: String,
    pub publisher: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FeedSection {
    pub id: String,
    pub min_price: i64,
    pub max_price: i64,
    pub max_age_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProvingSection {
    #[serde(default = "default_true")]
    pub verify_air_companion: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct SigningSection {
    pub key_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubmitSection {
    pub grpc_endpoint: String,
    pub contract_address: String,
    pub state_path: PathBuf,
    /// Network prefix used by `GrpcSubmit` to derive the relayer's L1
    /// Dilithium address. One of `"mainnet" | "testnet" | "devnet" | "simnet"`.
    /// Defaults to `"devnet"` to match the local-dev workflow.
    #[serde(default = "default_devnet")]
    pub network_prefix: String,
    /// Phase 6 — opt-in publishing of the signed bundle bytes as a V5 DA
    /// carrier (domain = Oracle) right after each successful invocation
    /// submission. Default `false`: the relayer remains a single-tx
    /// publisher. Operators that want third parties to replay history
    /// without RPC access set this to `true`.
    #[serde(default)]
    pub da_publish: bool,
}

fn default_devnet() -> String {
    "devnet".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct DaemonSection {
    pub interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelayerConfig {
    pub pythnet: PythnetSection,
    pub feed: FeedSection,
    #[serde(default)]
    pub proving: Option<ProvingSection>,
    pub signing: SigningSection,
    pub submit: SubmitSection,
    pub daemon: DaemonSection,
}

impl RelayerConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let bytes = std::fs::read_to_string(path).map_err(|source| ConfigError::Io { path: path.to_path_buf(), source })?;
        let cfg: RelayerConfig = toml::from_str(&bytes)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let f = &self.feed.id;
        if f.is_empty() || f.len() > 8 || !f.is_ascii() {
            return Err(ConfigError::BadFeedId(f.clone()));
        }
        if self.feed.min_price >= self.feed.max_price {
            return Err(ConfigError::BadPriceBounds { min: self.feed.min_price, max: self.feed.max_price });
        }
        if self.feed.max_age_secs == 0 {
            return Err(ConfigError::ZeroMaxAge);
        }
        if self.daemon.interval_secs == 0 {
            return Err(ConfigError::ZeroInterval);
        }
        Ok(())
    }

    /// Pad the feed id to 8 bytes with NUL (matches `FeedId([u8; 8])`).
    pub fn feed_id_bytes(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        let src = self.feed.id.as_bytes();
        out[..src.len()].copy_from_slice(src);
        out
    }

    pub fn verify_air_companion(&self) -> bool {
        self.proving.as_ref().map(|p| p.verify_air_companion).unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(body: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(body.as_bytes()).unwrap();
        f
    }

    fn good_toml() -> &'static str {
        r#"
[pythnet]
rpc_endpoint = "https://pythnet.rpcpool.com"
price_account = "GVXRSBjFk6e6J3NbVPXohDJetcTjaeeuykUpbQF8UoMU"
publisher = "5j5xK4U7yeC1RVH4MM7yAHzkhdJYuBjFFyMvmaq2HBXM"

[feed]
id = "BTC/USD"
min_price = 10000
max_price = 10000000000
max_age_secs = 60

[signing]
key_path = "./relayer-dilithium.sk"

[submit]
grpc_endpoint = "127.0.0.1:46110"
contract_address = "sophis:qxxxxx"
state_path = "./relayer-state.json"

[daemon]
interval_secs = 30
"#
    }

    #[test]
    fn loads_minimal_valid_config() {
        let f = write_tmp(good_toml());
        let cfg = RelayerConfig::load(f.path()).expect("load ok");
        assert_eq!(cfg.feed.id, "BTC/USD");
        assert_eq!(cfg.daemon.interval_secs, 30);
        assert!(cfg.verify_air_companion(), "default companion=true");
        assert_eq!(&cfg.feed_id_bytes()[..7], b"BTC/USD");
        assert_eq!(cfg.feed_id_bytes()[7], 0);
    }

    #[test]
    fn rejects_empty_feed_id() {
        let body = good_toml().replace("id = \"BTC/USD\"", "id = \"\"");
        let f = write_tmp(&body);
        assert!(matches!(RelayerConfig::load(f.path()), Err(ConfigError::BadFeedId(_))));
    }

    #[test]
    fn rejects_too_long_feed_id() {
        let body = good_toml().replace("id = \"BTC/USD\"", "id = \"TOOLONGID9\"");
        let f = write_tmp(&body);
        assert!(matches!(RelayerConfig::load(f.path()), Err(ConfigError::BadFeedId(_))));
    }

    #[test]
    fn rejects_inverted_bounds() {
        let body = good_toml().replace("min_price = 10000", "min_price = 99999999999");
        let f = write_tmp(&body);
        assert!(matches!(RelayerConfig::load(f.path()), Err(ConfigError::BadPriceBounds { .. })));
    }

    #[test]
    fn rejects_zero_max_age() {
        let body = good_toml().replace("max_age_secs = 60", "max_age_secs = 0");
        let f = write_tmp(&body);
        assert!(matches!(RelayerConfig::load(f.path()), Err(ConfigError::ZeroMaxAge)));
    }

    #[test]
    fn rejects_zero_interval() {
        let body = good_toml().replace("interval_secs = 30", "interval_secs = 0");
        let f = write_tmp(&body);
        assert!(matches!(RelayerConfig::load(f.path()), Err(ConfigError::ZeroInterval)));
    }

    #[test]
    fn companion_can_be_disabled() {
        let body = format!("{}\n[proving]\nverify_air_companion = false\n", good_toml());
        let f = write_tmp(&body);
        let cfg = RelayerConfig::load(f.path()).unwrap();
        assert!(!cfg.verify_air_companion());
    }

    #[test]
    fn da_publish_defaults_off() {
        let f = write_tmp(good_toml());
        let cfg = RelayerConfig::load(f.path()).unwrap();
        assert!(!cfg.submit.da_publish);
    }

    #[test]
    fn da_publish_can_be_enabled() {
        let body =
            good_toml().replace("state_path = \"./relayer-state.json\"", "state_path = \"./relayer-state.json\"\nda_publish = true");
        let f = write_tmp(&body);
        let cfg = RelayerConfig::load(f.path()).unwrap();
        assert!(cfg.submit.da_publish);
    }
}
