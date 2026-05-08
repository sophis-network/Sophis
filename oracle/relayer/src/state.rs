//! Sub-fase 5.4.f — sequence-number persistence.
//!
//! Persists the relayer's last successfully-submitted sequence number so a
//! restart does not recommence at sequence 1 (which the contract would
//! reject as a replay of the very first update).
//!
//! Format is intentionally trivial — a single line `last_sequence=<u64>`
//! in a UTF-8 file. Loadable by inspection. The atomic-rename pattern
//! (`write to *.tmp` + `rename` over the target) protects against partial
//! writes if the relayer is killed mid-write.

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("io error on {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("malformed state file: {0}")]
    Malformed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelayerState {
    pub last_sequence: u64,
}

impl RelayerState {
    /// Load from disk, or return `Default` (last_sequence = 0) if the file
    /// does not exist. Any other I/O or parse error is propagated.
    pub fn load_or_default(path: &Path) -> Result<Self, StateError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path).map_err(|source| StateError::Io { path: path.to_path_buf(), source })?;
        Self::parse(&text)
    }

    fn parse(text: &str) -> Result<Self, StateError> {
        let mut last_sequence = None;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (k, v) = line.split_once('=').ok_or_else(|| StateError::Malformed(format!("missing '=': {line}")))?;
            match k.trim() {
                "last_sequence" => {
                    let n: u64 = v.trim().parse().map_err(|e| StateError::Malformed(format!("last_sequence parse: {e}")))?;
                    last_sequence = Some(n);
                }
                other => return Err(StateError::Malformed(format!("unknown key: {other}"))),
            }
        }
        Ok(Self { last_sequence: last_sequence.unwrap_or(0) })
    }

    /// Atomically write to disk. Writes to `<path>.tmp` then renames over
    /// the destination so a crash mid-write leaves the previous value
    /// intact.
    pub fn save(&self, path: &Path) -> Result<(), StateError> {
        let body = format!("# sophis-oracle-relayer state file\nlast_sequence={}\n", self.last_sequence);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, body).map_err(|source| StateError::Io { path: tmp.clone(), source })?;
        std::fs::rename(&tmp, path).map_err(|source| StateError::Io { path: path.to_path_buf(), source })?;
        Ok(())
    }

    /// Next sequence number the relayer should publish. Always
    /// `last_sequence + 1` — the contract rejects equal-or-lower
    /// sequences as replays.
    pub fn next_sequence(&self) -> u64 {
        self.last_sequence + 1
    }

    /// Mark `seq` as successfully submitted.
    pub fn record_submitted(&mut self, seq: u64) {
        if seq > self.last_sequence {
            self.last_sequence = seq;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_returns_default_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("missing.state");
        let s = RelayerState::load_or_default(&p).unwrap();
        assert_eq!(s.last_sequence, 0);
    }

    #[test]
    fn save_then_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("round.state");
        let s = RelayerState { last_sequence: 42 };
        s.save(&p).unwrap();
        let r = RelayerState::load_or_default(&p).unwrap();
        assert_eq!(r.last_sequence, 42);
    }

    #[test]
    fn parse_ignores_blank_and_comments() {
        let s = RelayerState::parse("# comment\n\nlast_sequence=7\n# trailing\n").unwrap();
        assert_eq!(s.last_sequence, 7);
    }

    #[test]
    fn parse_rejects_unknown_key() {
        assert!(matches!(RelayerState::parse("bogus=1"), Err(StateError::Malformed(_))));
    }

    #[test]
    fn parse_rejects_missing_equals() {
        assert!(matches!(RelayerState::parse("last_sequence 1"), Err(StateError::Malformed(_))));
    }

    #[test]
    fn record_submitted_is_monotone() {
        let mut s = RelayerState::default();
        s.record_submitted(5);
        assert_eq!(s.last_sequence, 5);
        s.record_submitted(3);
        assert_eq!(s.last_sequence, 5, "recording lower seq must not regress");
        s.record_submitted(10);
        assert_eq!(s.last_sequence, 10);
    }

    #[test]
    fn next_sequence_is_last_plus_one() {
        assert_eq!(RelayerState::default().next_sequence(), 1);
        assert_eq!(RelayerState { last_sequence: 99 }.next_sequence(), 100);
    }

    #[test]
    fn atomic_rename_leaves_no_tmp_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("atomic.state");
        let tmp = p.with_extension("tmp");
        RelayerState { last_sequence: 1 }.save(&p).unwrap();
        assert!(p.exists());
        assert!(!tmp.exists(), "rename must remove the .tmp source");
    }
}
