use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct State {
    pub address: String,
    pub hwm_sompi: u64,
    pub hwm_observed_at_unix: u64,
    pub last_check_unix: u64,
    pub last_circulating_sompi: u64,
    pub last_balance_sompi: u64,
    pub last_ratio_bps: u64,
    pub paused: bool,
    pub pause_event_unix: Option<u64>,
}

impl State {
    pub fn fresh(address: &str) -> Self {
        Self {
            address: address.to_string(),
            hwm_sompi: 0,
            hwm_observed_at_unix: 0,
            last_check_unix: 0,
            last_circulating_sompi: 0,
            last_balance_sompi: 0,
            last_ratio_bps: 0,
            paused: false,
            pause_event_unix: None,
        }
    }

    pub fn load_or_init(path: &Path, address: &str) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(s) => {
                let loaded: State =
                    serde_json::from_str(&s).map_err(|e| format!("state file malformed at {}: {e}", path.display()))?;
                if loaded.address != address {
                    return Err(format!(
                        "state file address mismatch: file has {}, CLI gave {}. Refuse to reuse — point --state-file to a fresh path, or fix --address.",
                        loaded.address, address
                    ));
                }
                Ok(loaded)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::fresh(address)),
            Err(e) => Err(format!("read state file {}: {e}", path.display())),
        }
    }

    // Atomic write: dump to <path>.tmp then rename. Crash-safe — either the old
    // file remains intact or the new one is fully written.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let s = serde_json::to_string_pretty(self).map_err(|e| format!("serialize state: {e}"))?;
        let tmp = path.with_extension("json.tmp");
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        std::fs::write(&tmp, &s).map_err(|e| format!("write tmp {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("rename {} -> {}: {e}", tmp.display(), path.display()))?;
        Ok(())
    }
}
