use crate::utxo::{TxOutput, UtxoEntry};

#[cfg(target_arch = "wasm32")]
use borsh::BorshDeserialize;

// Maximum size of a single borsh-serialised UTXO passed from the host.
// Generous upper bound — typical UTXOs are < 100 bytes.
#[cfg(target_arch = "wasm32")]
const UTXO_BUF_SIZE: usize = 8192;

// Host imports — only visible in WASM builds.
// The Sophis sVM runtime registers all functions under module "env".
#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "env")]
extern "C" {
    fn get_input_utxo(index: i32, out_ptr: i32, out_len_ptr: i32) -> i32;
    fn get_output_utxo(index: i32, out_ptr: i32, out_len_ptr: i32) -> i32;
    fn get_block_height() -> i64;
    fn verify_dilithium(pk_ptr: i32, pk_len: i32, msg_ptr: i32, msg_len: i32, sig_ptr: i32, sig_len: i32) -> i32;
    fn sha3_384(in_ptr: i32, in_len: i32, out_ptr: i32) -> i32;
    // Phase 4 Sprint B
    fn verify_risc0_proof(
        seal_ptr: i32,
        seal_len: i32,
        journal_ptr: i32,
        journal_len: i32,
        image_id_ptr: i32, // 32 bytes, no length
    ) -> i32;
    // Phase 5 sub-fase 5.3 — Plonky3 STARK proof verification
    fn verify_plonky3_proof(
        proof_ptr: i32,
        proof_len: i32,
        pubvals_ptr: i32,
        pubvals_len: i32,
        air_id_ptr: i32, // 32 bytes, no length
    ) -> i32;
    // J4 — emit a structured event log
    fn sophis_emit_event(payload_ptr: i32, payload_len: i32) -> i32;
    // J3 — read 32 bytes of VRF entropy at out_ptr
    fn sophis_vrf_random_at(chain_index: i64, out_ptr: i32) -> i32;
}

/// J4 — frozen ABI mirror of `sophis_svm_core::events::*` constants.
/// Duplicated here because the SDK is a no-deps wasm32 crate and must
/// not pull `sophis-svm-core` (which carries serde + hashes). Any change
/// requires a hard fork — keep in lockstep with svm-core/events.
pub const MAX_TOPICS_PER_EVENT: u8 = 4;
pub const EVENT_TOPIC_LEN: usize = 32;
pub const MAX_EVENT_DATA_BYTES: u32 = 4_096;

/// J4 — non-zero status returned by `Env::emit_event`. Numbering matches
/// the host fn (`-1`..`-6`); kept positive here so callers can compare
/// in safe arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitEventError {
    CapabilityMissing = 1,
    GasExhausted = 2,
    TopicCountTooLarge = 3,
    DataTooLarge = 4,
    StructuralError = 5,
    PerTxCapReached = 6,
}

/// J3 — non-zero status returned by `Env::vrf_random_at_chain_index`.
/// Numbering matches the host fn (`-1`..`-6`); positive here so callers
/// can compare in safe arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VrfError {
    CapabilityMissing = 1,
    GasExhausted = 2,
    /// Requested chain_index is at or beyond the current chain tip;
    /// the contract should retry once the chain advances. Common
    /// commit-reveal pattern: write a commitment now, read VRF later.
    FutureBlock = 3,
    /// Requested chain_index was negative (cast underflow at producer).
    NegativeIndex = 4,
    /// out_ptr write would land out of WASM linear memory.
    OutputBufferOob = 5,
    /// Requested chain_index < tip but the store cannot resolve it
    /// (likely pruned). Should not happen on a healthy node within the
    /// recent-history window.
    UnknownIndex = 6,
}

/// The contract execution environment — provides access to all sVM host APIs.
///
/// Zero-sized. Instantiated automatically by [`sophis_sdk_macros::sophis_contract`];
/// do not construct directly.
pub struct Env(());

impl Env {
    #[doc(hidden)]
    pub fn new() -> Self {
        Env(())
    }

    /// Returns the borsh-decoded input UTXO at `index`, or `None` if out of range.
    pub fn input_utxo(&self, index: u32) -> Option<UtxoEntry> {
        #[cfg(target_arch = "wasm32")]
        {
            let mut buf = [0u8; UTXO_BUF_SIZE];
            let mut len: u32 = 0;
            let ok = unsafe { get_input_utxo(index as i32, buf.as_mut_ptr() as i32, &mut len as *mut u32 as i32) };
            if ok != 1 {
                return None;
            }
            UtxoEntry::try_from_slice(&buf[..len as usize]).ok()
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = index;
            None
        }
    }

    /// Returns the borsh-decoded output at `index`, or `None` if out of range.
    pub fn output_utxo(&self, index: u32) -> Option<TxOutput> {
        #[cfg(target_arch = "wasm32")]
        {
            let mut buf = [0u8; UTXO_BUF_SIZE];
            let mut len: u32 = 0;
            let ok = unsafe { get_output_utxo(index as i32, buf.as_mut_ptr() as i32, &mut len as *mut u32 as i32) };
            if ok != 1 {
                return None;
            }
            TxOutput::try_from_slice(&buf[..len as usize]).ok()
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = index;
            None
        }
    }

    /// Returns the current DAA score (block height) of the block being validated.
    /// Returns 0 if the capability is not declared.
    pub fn block_height(&self) -> u64 {
        #[cfg(target_arch = "wasm32")]
        {
            let h = unsafe { get_block_height() };
            if h < 0 { 0 } else { h as u64 }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            0
        }
    }

    /// Verifies an ML-DSA-44 (Dilithium) signature (FIPS 204).
    ///
    /// - `pk`:  1312-byte verification key
    /// - `msg`: message of any length
    /// - `sig`: 2420-byte signature
    ///
    /// Returns `true` on valid signature. Always returns `false` outside WASM.
    pub fn verify_dilithium(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        #[cfg(target_arch = "wasm32")]
        {
            unsafe {
                verify_dilithium(
                    pk.as_ptr() as i32,
                    pk.len() as i32,
                    msg.as_ptr() as i32,
                    msg.len() as i32,
                    sig.as_ptr() as i32,
                    sig.len() as i32,
                ) == 1
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (pk, msg, sig);
            false
        }
    }

    /// Computes SHA3-384 of `data` and returns the 48-byte digest.
    /// Returns `[0u8; 48]` outside WASM.
    pub fn sha3_384(&self, data: &[u8]) -> [u8; 48] {
        #[cfg(target_arch = "wasm32")]
        {
            let mut out = [0u8; 48];
            unsafe {
                sha3_384(data.as_ptr() as i32, data.len() as i32, out.as_mut_ptr() as i32);
            }
            out
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = data;
            [0u8; 48]
        }
    }

    /// Verify a Risc0 STARK proof (Phase 4 Sprint B — `VerifyRisc0Proof` capability required).
    ///
    /// - `seal`:     raw seal bytes from the Risc0 prover.
    /// - `journal`:  public output bytes (borsh-encoded guest journal).
    /// - `image_id`: exactly 32 bytes identifying the expected guest program.
    ///
    /// Returns `true` on valid proof. Always returns `false` outside WASM.
    pub fn verify_risc0_proof(&self, seal: &[u8], journal: &[u8], image_id: &[u8; 32]) -> bool {
        #[cfg(target_arch = "wasm32")]
        {
            unsafe {
                verify_risc0_proof(
                    seal.as_ptr() as i32,
                    seal.len() as i32,
                    journal.as_ptr() as i32,
                    journal.len() as i32,
                    image_id.as_ptr() as i32,
                ) == 1
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (seal, journal, image_id);
            false
        }
    }

    /// Emit a structured event log (J4 — `EmitEvent` capability required).
    ///
    /// - `topics`: zero up to `MAX_TOPICS_PER_EVENT` (= 4) 32-byte topics.
    ///   By convention `topics[0]` is the event signature hash.
    /// - `data`:   payload bytes; capped at `MAX_EVENT_DATA_BYTES` (= 4096).
    ///
    /// Returns `Ok(())` if the host accepted the event. Returns
    /// `Err(EmitEventError::*)` mirroring the host fn status code on any
    /// rejection. Outside WASM (off-chain dev), always returns `Ok(())`.
    ///
    /// Encoding is performed in-place into a small stack buffer when the
    /// payload fits (≤ 256 bytes) and falls back to a heap allocation
    /// otherwise.
    pub fn emit_event(&self, topics: &[[u8; EVENT_TOPIC_LEN]], data: &[u8]) -> Result<(), EmitEventError> {
        // SDK-side guards mirror the parser; they let producer bugs fail
        // fast instead of round-tripping through the host fn.
        if topics.len() > MAX_TOPICS_PER_EVENT as usize {
            return Err(EmitEventError::TopicCountTooLarge);
        }
        if data.len() > MAX_EVENT_DATA_BYTES as usize {
            return Err(EmitEventError::DataTooLarge);
        }

        let topic_count = topics.len() as u8;
        let total = 1usize + topics.len() * EVENT_TOPIC_LEN + 4 + data.len();
        let mut buf: Vec<u8> = Vec::with_capacity(total);
        buf.push(topic_count);
        for t in topics {
            buf.extend_from_slice(t);
        }
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(data);

        #[cfg(target_arch = "wasm32")]
        {
            let status = unsafe { sophis_emit_event(buf.as_ptr() as i32, buf.len() as i32) };
            match status {
                0 => Ok(()),
                -1 => Err(EmitEventError::CapabilityMissing),
                -2 => Err(EmitEventError::GasExhausted),
                -3 => Err(EmitEventError::TopicCountTooLarge),
                -4 => Err(EmitEventError::DataTooLarge),
                -5 => Err(EmitEventError::StructuralError),
                -6 => Err(EmitEventError::PerTxCapReached),
                // Any other value is a host-fn ABI bug; treat as structural.
                _ => Err(EmitEventError::StructuralError),
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            // Off-chain test/dev: pretend the host accepted. The buffer was
            // already shape-checked above.
            let _ = buf;
            Ok(())
        }
    }

    /// Reads 32 bytes of VRF entropy derived from the selected-chain
    /// block at `chain_index` (J3 — `VrfRandomness` capability required).
    ///
    /// Output is `SHA3-384(b"sophis-vrf-v1\0" || chain_index_le || block_hash)[..32]`.
    /// Bias-resistant because RandomX PoW grinding cost ≥ block reward
    /// per output bit; deterministic because the input is a function of
    /// committed chain state. See `docs/J3_VRF_DESIGN.md`.
    ///
    /// Safety note: callers SHOULD use `chain_index <= current_tip - finality_depth`
    /// to avoid reorg-driven VRF flips. Reading the very tip is unsafe.
    /// Outside WASM (off-chain dev), always returns `Ok([0u8; 32])`.
    pub fn vrf_random_at_chain_index(&self, chain_index: u64) -> Result<[u8; 32], VrfError> {
        #[cfg(target_arch = "wasm32")]
        {
            let mut out = [0u8; 32];
            let status = unsafe { sophis_vrf_random_at(chain_index as i64, out.as_mut_ptr() as i32) };
            match status {
                0 => Ok(out),
                -1 => Err(VrfError::CapabilityMissing),
                -2 => Err(VrfError::GasExhausted),
                -3 => Err(VrfError::FutureBlock),
                -4 => Err(VrfError::NegativeIndex),
                -5 => Err(VrfError::OutputBufferOob),
                -6 => Err(VrfError::UnknownIndex),
                // Any other value is a host-fn ABI bug; treat as unknown.
                _ => Err(VrfError::UnknownIndex),
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = chain_index;
            Ok([0u8; 32])
        }
    }

    /// Verify a Plonky3 STARK proof (Phase 5 sub-fase 5.3 — `VerifyPlonky3Proof` capability required).
    ///
    /// - `proof`:         bincode-serialized `p3_uni_stark::Proof<OracleStarkConfig>`.
    /// - `public_values`: serialized public-values vector (interpretation depends on `air_id`).
    /// - `air_id`:        exactly 32 bytes; selects the AIR (OracleAir vs VerifyAirChip vs …).
    ///
    /// Known AIR IDs are constants exposed by the host backend; contracts
    /// must hard-code which AIR they accept (no dynamic dispatch in WASM).
    /// Returns `true` on valid proof. Always returns `false` outside WASM.
    pub fn verify_plonky3_proof(&self, proof: &[u8], public_values: &[u8], air_id: &[u8; 32]) -> bool {
        #[cfg(target_arch = "wasm32")]
        {
            unsafe {
                verify_plonky3_proof(
                    proof.as_ptr() as i32,
                    proof.len() as i32,
                    public_values.as_ptr() as i32,
                    public_values.len() as i32,
                    air_id.as_ptr() as i32,
                ) == 1
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (proof, public_values, air_id);
            false
        }
    }
}
