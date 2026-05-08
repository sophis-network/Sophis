/// Sequencer configuration.
#[derive(Debug, Clone)]
pub struct SequencerConfig {
    /// Dilithium ML-DSA-44 signing key (L2 path m/44'/111111'/0'/1/0).
    pub signing_key: Box<[u8; 2560]>,
    /// Corresponding verification key.
    pub verification_key: Box<[u8; 1312]>,
    /// wRPC Borsh endpoint of the local L1 node (e.g. "ws://127.0.0.1:47610").
    pub l1_rpc_url: String,
    /// Maximum L2 txs per batch before forcing a flush. Default: 100.
    pub max_batch_txs: usize,
    /// Seconds of inactivity before flushing a non-empty batch. Default: 30.
    pub batch_timeout_secs: u64,
    /// HTTP port to listen on for L2 tx submissions. Default: 9944.
    pub http_port: u16,
}

impl SequencerConfig {
    pub fn new(signing_key: Box<[u8; 2560]>, verification_key: Box<[u8; 1312]>, l1_rpc_url: String) -> Self {
        Self { signing_key, verification_key, l1_rpc_url, max_batch_txs: 100, batch_timeout_secs: 30, http_port: 9944 }
    }

    pub fn is_authorized_sequencer(&self, state_sequencer_vk: &[u8; 1312]) -> bool {
        self.verification_key.as_ref() == state_sequencer_vk
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(vk_byte: u8) -> SequencerConfig {
        let mut vk = Box::new([0u8; 1312]);
        vk[0] = vk_byte;
        SequencerConfig {
            signing_key: Box::new([0u8; 2560]),
            verification_key: vk,
            l1_rpc_url: "ws://127.0.0.1:47610".into(),
            max_batch_txs: 100,
            batch_timeout_secs: 30,
            http_port: 9944,
        }
    }

    #[test]
    fn authorized_when_vk_matches() {
        let cfg = make_config(7);
        let mut state_vk = [0u8; 1312];
        state_vk[0] = 7;
        assert!(cfg.is_authorized_sequencer(&state_vk));
    }

    #[test]
    fn not_authorized_when_vk_differs() {
        let cfg = make_config(7);
        let state_vk = [99u8; 1312];
        assert!(!cfg.is_authorized_sequencer(&state_vk));
    }
}
