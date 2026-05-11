use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Permission a contract must declare at deploy time.
/// Wasmtime traps immediately if the contract calls a host function
/// not listed in its ContractManifest.required_capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub enum Capability {
    ReadUtxo,
    ProduceOutput,
    VerifyDilithium,
    ReadBlockHeight,
    HashSha3,
    /// Phase 3 ZK-Rollup — verify a Risc0 STARK proof inside a sVM contract.
    /// Required by rollup state-update verifier contracts.
    /// Security review required before testnet; see CLAUDE.md sVM invariants.
    VerifyRisc0Proof,
    /// Phase 5 ZK-Oracle — verify a Plonky3 STARK proof inside a sVM contract.
    /// Required by oracle journal-binding verifier contracts.
    /// `(proof_bytes, public_values_bytes, air_id[32])`. The host backend
    /// dispatches by `air_id` to the correct AIR (OracleAir, VerifyAirChip).
    /// Security review required before testnet; see CLAUDE.md sVM invariants.
    VerifyPlonky3Proof,
    /// Phase 6 — verify that a 48-byte DA hash is present in the L1's DA store
    /// (`DbDaStore`) with at least N confirmations. Used by the rollup
    /// withdrawal contract and by the oracle relayer to bind on-chain bytes
    /// to a journal. `(payload_or_bundle_id[48], min_confirmations, query_kind)`.
    /// See `oracle/docs/PHASE6_DA_DESIGN.md` §7.
    VerifyDataAvailability,
    /// L1 — resolve an Address Lookup Table reference to its underlying
    /// `ScriptPublicKey`. `(handle[6], index)`; the host returns the
    /// resolved bytes via the standard sVM linear-memory ABI. Required by
    /// any sVM contract that wants to interpret v=1 transaction outputs
    /// that use ALT references rather than inline scripts.
    /// See `docs/L1_ALT_DESIGN.md` §8 (sVM integration).
    ResolveAlt,
    /// J4 — emit a structured event log from a sVM contract. Payload is
    /// `topic_count(1) || topics[32 * count] || data_len(4) || data[..]`
    /// (see `events::parse_emission_payload`). Events accumulate in
    /// `ExecutionContext.events` and are persisted by the consensus
    /// commit hook (J4.4) into the four `EventsBy*` RocksDB indexes.
    /// Strictly additive — does not affect transaction wire format or
    /// state roots. See `docs/J4_EVENTS_DESIGN.md`.
    EmitEvent,
    /// J3 — read 32 bytes of bias-resistant VRF entropy derived from a
    /// past selected-chain block hash via `sophis_vrf_random_at`. Output
    /// is `SHA3-384(b"sophis-vrf-v1\0" || chain_index_le || block_hash)[..32]`.
    /// Bias-resistance comes from RandomX PoW grinding cost ≥ block
    /// reward per output bit. See `docs/J3_VRF_DESIGN.md`.
    VrfRandomness,
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadUtxo => write!(f, "ReadUtxo"),
            Self::ProduceOutput => write!(f, "ProduceOutput"),
            Self::VerifyDilithium => write!(f, "VerifyDilithium"),
            Self::ReadBlockHeight => write!(f, "ReadBlockHeight"),
            Self::HashSha3 => write!(f, "HashSha3"),
            Self::VerifyRisc0Proof => write!(f, "VerifyRisc0Proof"),
            Self::VerifyPlonky3Proof => write!(f, "VerifyPlonky3Proof"),
            Self::VerifyDataAvailability => write!(f, "VerifyDataAvailability"),
            Self::ResolveAlt => write!(f, "ResolveAlt"),
            Self::EmitEvent => write!(f, "EmitEvent"),
            Self::VrfRandomness => write!(f, "VrfRandomness"),
        }
    }
}
