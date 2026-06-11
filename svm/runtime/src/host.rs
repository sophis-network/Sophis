use std::sync::Arc;

use wasmtime::{AsContext, AsContextMut, Caller, Linker};

use sophis_svm_core::events::{EventError, MAX_EVENTS_PER_TX, parse_emission_payload};
use sophis_svm_core::{Capability, Gas};

use crate::context::{BufferedEvent, ExecutionContext};
use crate::error::{RuntimeError, RuntimeResult};

/// Phase 6 — Data Availability backend.
///
/// Stateless from the runtime's point of view: every call from a contract
/// is answered by looking up the L1's DA store. The runtime holds an
/// `Arc<dyn HostDa>` so the consensus layer can inject a real backend
/// (`SophisDaBackend`) bound to `DbDaStore` plus the current-tip blue
/// score.
///
/// Lookups are **deterministic** at consensus time: every full node
/// answers the same query the same way because the DA store is populated
/// during virtual_processor commit (sub-fase 6.2.b) before any contract
/// runs against the same chain block.
pub trait HostDa: Send + Sync + 'static {
    /// Returns true if `payload_id` is present in the DA store with
    /// `confirmations >= min_confirmations`. Confirmations are computed
    /// against whatever blue-score the backend captured at construction.
    fn verify_payload(&self, payload_id: &[u8; 48], min_confirmations: u64) -> bool;

    /// Returns true if every fragment of `bundle_id` is present and each
    /// has `confirmations >= min_confirmations`.
    fn verify_bundle(&self, bundle_id: &[u8; 48], min_confirmations: u64) -> bool;
}

/// Stub — every DA query returns `false`. Used in svm/runtime unit tests
/// and as a default in environments that have no DA store yet.
pub struct StubDa;
impl HostDa for StubDa {
    fn verify_payload(&self, _: &[u8; 48], _: u64) -> bool {
        false
    }
    fn verify_bundle(&self, _: &[u8; 48], _: u64) -> bool {
        false
    }
}

/// J3 — Verifiable Randomness backend.
///
/// Stateless from the runtime's point of view: every call from a contract
/// is answered by looking up the chain block at the requested chain
/// index and returning a SHA3-384-domain-separated 32-byte digest. The
/// runtime holds an `Arc<dyn HostVrf>` so the consensus layer can inject
/// a real backend (`SophisVrfBackend`) bound to `selected_chain_store`.
///
/// Lookups are **deterministic** at consensus time: every full node
/// answers the same query the same way because `selected_chain_store`
/// is committed during virtual_processor commit before any contract
/// runs against the same chain block. See `docs/J3_VRF_DESIGN.md` §2 D5.
pub trait HostVrf: Send + Sync + 'static {
    /// Returns 32 bytes of VRF entropy for the given chain index, or
    /// `None` if the index is unknown / pruned / in the future.
    /// `None` callers MUST distinguish from the cap by tracking the
    /// current tip themselves; the backend does not signal "future"
    /// vs "pruned" separately at this layer.
    fn vrf_random_at(&self, chain_index: u64) -> Option<[u8; 32]>;

    /// Returns the current chain tip index. Used by the host fn to
    /// distinguish "future block" (status -3) from "unknown index"
    /// (status -6) without requiring a second call.
    fn current_tip_index(&self) -> u64;
}

/// Stub — every VRF query returns `None`. Used in svm/runtime unit tests
/// and as a default in environments that have no chain store yet.
pub struct StubVrf;
impl HostVrf for StubVrf {
    fn vrf_random_at(&self, _: u64) -> Option<[u8; 32]> {
        None
    }
    fn current_tip_index(&self) -> u64 {
        0
    }
}

/// L1 — Address Lookup Table backend.
///
/// Stateless from the runtime's point of view: every call from a contract
/// is answered by looking up the L1's ALT store. The runtime holds an
/// `Arc<dyn HostAlt>` so the consensus layer can inject a real backend
/// (`SophisAltBackend`) bound to `DbAltStore`.
///
/// Lookups are **deterministic** at consensus time: every full node
/// answers the same query the same way because the ALT store is populated
/// during virtual_processor commit (sub-fase L1.3.d) before any contract
/// runs against the same chain block.
pub trait HostAlt: Send + Sync + 'static {
    /// Resolves an ALT reference to its underlying `ScriptPublicKey` bytes
    /// and writes them into `out`. Returns `Some(spk_version)` on hit,
    /// `None` if the handle is unknown OR the index is out of range.
    ///
    /// `out` is not pre-sized; the backend is responsible for clearing and
    /// extending it. Caller MUST NOT assume the buffer is intact on miss.
    fn resolve_reference(&self, handle: &[u8; 6], index: u8, out: &mut Vec<u8>) -> Option<u16>;
}

/// Stub — every ALT query returns `None`. Used in svm/runtime unit tests
/// and as a default when no ALT store is wired.
pub struct StubAlt;
impl HostAlt for StubAlt {
    fn resolve_reference(&self, _: &[u8; 6], _: u8, _: &mut Vec<u8>) -> Option<u16> {
        None
    }
}

/// Crypto backend injected into the runtime at execution time.
/// svm/runtime defines the interface; svm/host provides the real implementation
/// backed by libcrux-ml-dsa (ML-DSA-44) + SHA3-384 + Risc0 STARK verifier.
pub trait HostCrypto: Send + Sync + 'static {
    fn verify_dilithium(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool;
    fn sha3_384(&self, data: &[u8]) -> [u8; 48];
    /// Verify a Risc0 STARK proof.
    /// - `seal`:     raw proof bytes (Groth16 or STARK seal from risc0 prover)
    /// - `journal`:  public output bytes (borsh-encoded)
    /// - `image_id`: 32-byte image ID of the expected guest program
    fn verify_risc0_proof(&self, seal: &[u8], journal: &[u8], image_id: &[u8]) -> bool;
    /// Verify a Plonky3 STARK proof (Phase 5 ZK-Oracle).
    /// - `proof`:          bincode-serialized `p3_uni_stark::Proof<OracleStarkConfig>`
    /// - `public_values`:  serialized public-values vector (interpretation depends on `air_id`)
    /// - `air_id`:         32-byte AIR identifier; the host backend dispatches
    ///   to the correct AIR (OracleAir, VerifyAirChip, …).
    fn verify_plonky3_proof(&self, proof: &[u8], public_values: &[u8], air_id: &[u8]) -> bool;
}

/// Stub — all crypto returns false/zeros. Used in svm/runtime unit tests.
pub struct StubCrypto;
impl HostCrypto for StubCrypto {
    fn verify_dilithium(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool {
        false
    }
    fn sha3_384(&self, _: &[u8]) -> [u8; 48] {
        [0u8; 48]
    }
    fn verify_risc0_proof(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool {
        false
    }
    fn verify_plonky3_proof(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool {
        false
    }
}

/// Registers all host functions into the Linker using the provided crypto backend.
pub fn register_host_functions(linker: &mut Linker<ExecutionContext>, crypto: Arc<dyn HostCrypto>) -> RuntimeResult<()> {
    let c_dilithium = Arc::clone(&crypto);
    let c_sha3 = Arc::clone(&crypto);
    let c_risc0 = Arc::clone(&crypto);
    let c_plonky3 = Arc::clone(&crypto);

    // get_input_utxo(index, out_ptr, out_len_ptr) -> i32
    linker
        .func_wrap(
            "env",
            "get_input_utxo",
            |mut caller: Caller<ExecutionContext>, index: i32, out_ptr: i32, out_len_ptr: i32| -> i32 {
                if caller.data().check_capability(&Capability::ReadUtxo).is_err() {
                    return 0;
                }
                let bytes = match caller.data().input_utxos.get(index as usize) {
                    Some(b) => b.clone(),
                    None => return 0,
                };
                write_to_memory(&mut caller, &bytes, out_ptr, out_len_ptr)
            },
        )
        .map_err(|e| RuntimeError::InstantiationFailed(e.to_string()))?;

    // get_output_utxo(index, out_ptr, out_len_ptr) -> i32
    linker
        .func_wrap(
            "env",
            "get_output_utxo",
            |mut caller: Caller<ExecutionContext>, index: i32, out_ptr: i32, out_len_ptr: i32| -> i32 {
                if caller.data().check_capability(&Capability::ReadUtxo).is_err() {
                    return 0;
                }
                let bytes = match caller.data().output_utxos.get(index as usize) {
                    Some(b) => b.clone(),
                    None => return 0,
                };
                write_to_memory(&mut caller, &bytes, out_ptr, out_len_ptr)
            },
        )
        .map_err(|e| RuntimeError::InstantiationFailed(e.to_string()))?;

    // get_block_height() -> i64
    linker
        .func_wrap("env", "get_block_height", |caller: Caller<ExecutionContext>| -> i64 {
            if caller.data().check_capability(&Capability::ReadBlockHeight).is_err() {
                return -1;
            }
            caller.data().block_height as i64
        })
        .map_err(|e| RuntimeError::InstantiationFailed(e.to_string()))?;

    // verify_dilithium(pk_ptr, pk_len, msg_ptr, msg_len, sig_ptr, sig_len) -> i32
    linker
        .func_wrap(
            "env",
            "verify_dilithium",
            move |mut caller: Caller<ExecutionContext>,
                  pk_ptr: i32,
                  pk_len: i32,
                  msg_ptr: i32,
                  msg_len: i32,
                  sig_ptr: i32,
                  sig_len: i32|
                  -> i32 {
                if caller.data().check_capability(&Capability::VerifyDilithium).is_err() {
                    return 0;
                }
                let cost = caller.data().gas_config.dilithium_verify_cost;
                if caller.data_mut().charge(Gas(cost)).is_err() {
                    return 0;
                }
                let Some((pk, msg, sig)) = read_three(&mut caller, pk_ptr, pk_len, msg_ptr, msg_len, sig_ptr, sig_len) else {
                    return 0;
                };
                if c_dilithium.verify_dilithium(&pk, &msg, &sig) { 1 } else { 0 }
            },
        )
        .map_err(|e| RuntimeError::InstantiationFailed(e.to_string()))?;

    // sha3_384(in_ptr, in_len, out_ptr) -> i32 — writes 48 bytes at out_ptr
    linker
        .func_wrap("env", "sha3_384", move |mut caller: Caller<ExecutionContext>, in_ptr: i32, in_len: i32, out_ptr: i32| -> i32 {
            if caller.data().check_capability(&Capability::HashSha3).is_err() {
                return 0;
            }
            let cost = caller.data().gas_config.sha3_cost;
            if caller.data_mut().charge(Gas(cost)).is_err() {
                return 0;
            }
            let Some(input) = read_one(&mut caller, in_ptr, in_len) else {
                return 0;
            };
            let hash = c_sha3.sha3_384(&input);
            write_to_memory(&mut caller, &hash, out_ptr, -1)
        })
        .map_err(|e| RuntimeError::InstantiationFailed(e.to_string()))?;

    // verify_risc0_proof(seal_ptr, seal_len, journal_ptr, journal_len, image_id_ptr) -> i32
    // image_id is always 32 bytes; no length param needed.
    linker
        .func_wrap(
            "env",
            "verify_risc0_proof",
            move |mut caller: Caller<ExecutionContext>,
                  seal_ptr: i32,
                  seal_len: i32,
                  journal_ptr: i32,
                  journal_len: i32,
                  image_id_ptr: i32|
                  -> i32 {
                if caller.data().check_capability(&Capability::VerifyRisc0Proof).is_err() {
                    return 0;
                }
                let cost = caller.data().gas_config.risc0_verify_cost;
                if caller.data_mut().charge(Gas(cost)).is_err() {
                    return 0;
                }
                let Some((seal, journal)) = read_two(&mut caller, seal_ptr, seal_len, journal_ptr, journal_len) else {
                    return 0;
                };
                let Some(image_id) = read_fixed_32(&mut caller, image_id_ptr) else {
                    return 0;
                };
                if c_risc0.verify_risc0_proof(&seal, &journal, &image_id) { 1 } else { 0 }
            },
        )
        .map_err(|e| RuntimeError::InstantiationFailed(e.to_string()))?;

    // verify_plonky3_proof(proof_ptr, proof_len, pubvals_ptr, pubvals_len, air_id_ptr) -> i32
    // air_id is always 32 bytes; no length param needed.
    linker
        .func_wrap(
            "env",
            "verify_plonky3_proof",
            move |mut caller: Caller<ExecutionContext>,
                  proof_ptr: i32,
                  proof_len: i32,
                  pubvals_ptr: i32,
                  pubvals_len: i32,
                  air_id_ptr: i32|
                  -> i32 {
                if caller.data().check_capability(&Capability::VerifyPlonky3Proof).is_err() {
                    return 0;
                }
                let cost = caller.data().gas_config.plonky3_verify_cost;
                if caller.data_mut().charge(Gas(cost)).is_err() {
                    return 0;
                }
                let Some((proof, pubvals)) = read_two(&mut caller, proof_ptr, proof_len, pubvals_ptr, pubvals_len) else {
                    return 0;
                };
                let Some(air_id) = read_fixed_32(&mut caller, air_id_ptr) else {
                    return 0;
                };
                if c_plonky3.verify_plonky3_proof(&proof, &pubvals, &air_id) { 1 } else { 0 }
            },
        )
        .map_err(|e| RuntimeError::InstantiationFailed(e.to_string()))?;

    // sophis_alt_lookup(ptr_handle, index, out_ptr, out_len_ptr) -> i32
    //
    // Args:
    //   ptr_handle    : *const u8 — 6 bytes in guest memory (ALT handle)
    //   index         : i32       — entry index in [0, entry_count)
    //   out_ptr       : *mut u8   — guest buffer to receive resolved spk_script
    //   out_len_ptr   : *mut u32  — i/o; in: capacity of out_ptr, out: actual bytes written
    //
    // Returns: i32
    //   spk_version (0..=u16::MAX) on hit (caller should also check out_len_ptr)
    //   -1   capability not granted
    //   -2   gas exhaustion
    //   -3   memory read out of bounds (handle)
    //   -4   handle not found in ALT registry
    //   -5   index out of range OR resolved spk_script too large for the
    //        caller's buffer (caller should retry with a larger buffer; the
    //        out_len_ptr is updated to reflect the required size)
    //   -6   memory write out of bounds (out buffer)
    linker
        .func_wrap(
            "env",
            "sophis_alt_lookup",
            |mut caller: Caller<ExecutionContext>, ptr_handle: i32, index: i32, out_ptr: i32, out_len_ptr: i32| -> i32 {
                if caller.data().check_capability(&Capability::ResolveAlt).is_err() {
                    return -1;
                }
                let cost = caller.data().gas_config.alt_resolve_cost;
                if caller.data_mut().charge(Gas(cost)).is_err() {
                    return -2;
                }
                let Some(handle) = read_fixed_6(&mut caller, ptr_handle) else {
                    return -3;
                };
                if !(0..=u8::MAX as i32).contains(&index) {
                    return -5;
                }
                let mut buf = Vec::new();
                let alt = Arc::clone(&caller.data().alt);
                let Some(spk_version) = alt.resolve_reference(&handle, index as u8, &mut buf) else {
                    return -4;
                };
                // Surface the resolved bytes via the standard out_ptr/out_len_ptr
                // ABI used by every other reader-style host fn (mirrors
                // get_input_utxo). Uses 0/-6 internally; we translate -6 here.
                if write_to_memory(&mut caller, &buf, out_ptr, out_len_ptr) == 0 {
                    return -6;
                }
                spk_version as i32
            },
        )
        .map_err(|e| RuntimeError::InstantiationFailed(e.to_string()))?;

    // sophis_emit_event(payload_ptr, payload_len) -> i32
    //
    // Emits a structured event log from the running sVM contract. Payload
    // wire format is documented in `sophis-svm-core::events`:
    //   topic_count(1) || topics[32 * count] || data_len(4 LE) || data[..]
    //
    // Args:
    //   payload_ptr : *const u8 — start of the emission payload in guest memory
    //   payload_len : i32       — length of the emission payload
    //
    // Returns: i32
    //   0    success — event appended to ExecutionContext.events
    //  -1    capability not granted (`Capability::EmitEvent` missing)
    //  -2    gas exhaustion
    //  -3    topic_count > MAX_TOPICS_PER_EVENT (= 4)
    //  -4    data_len > MAX_EVENT_DATA_BYTES (= 4096)
    //  -5    memory read out of bounds OR structural payload error
    //        (truncated / length mismatch / payload_len < 0)
    //  -6    per-tx event cap reached (= MAX_EVENTS_PER_TX = 32)
    linker
        .func_wrap("env", "sophis_emit_event", |mut caller: Caller<ExecutionContext>, payload_ptr: i32, payload_len: i32| -> i32 {
            if caller.data().check_capability(&Capability::EmitEvent).is_err() {
                return -1;
            }
            // Per-tx cap is checked before we charge gas so a contract
            // hitting the cap wastes nothing.
            if caller.data().events.len() >= MAX_EVENTS_PER_TX {
                return -6;
            }
            // Reject negative or absurd lengths before touching memory.
            if payload_len < 0 {
                return -5;
            }
            // Charge gas based on declared length up-front. The data-byte
            // share covers worst-case before we know the parsed data_len;
            // if the parser later rejects the payload the gas is still
            // burned (matches the convention used by `verify_dilithium`
            // and friends).
            let base = caller.data().gas_config.event_emit_base_cost;
            let per_byte = caller.data().gas_config.event_emit_per_byte_cost;
            let cost = base.saturating_add(per_byte.saturating_mul(payload_len as u64));
            if caller.data_mut().charge(Gas(cost)).is_err() {
                return -2;
            }
            let Some(payload) = read_one(&mut caller, payload_ptr, payload_len) else {
                return -5;
            };
            let parsed = match parse_emission_payload(&payload) {
                Ok(p) => p,
                Err(EventError::TopicCountOutOfRange(_)) => return -3,
                Err(EventError::DataTooLarge { .. }) => return -4,
                Err(EventError::Truncated { .. } | EventError::LengthMismatch { .. }) => return -5,
            };
            let contract_id = caller.data().contract_id;
            caller.data_mut().events.push(BufferedEvent { contract_id, topics: parsed.topics, data: parsed.data });
            0
        })
        .map_err(|e| RuntimeError::InstantiationFailed(e.to_string()))?;

    // sophis_vrf_random_at(chain_index, out_ptr) -> i32
    //
    // Writes 32 bytes of VRF entropy at out_ptr derived from the
    // selected-chain block at `chain_index`. Output is
    //   SHA3-384(b"sophis-vrf-v1\0" || chain_index_le_8 || block_hash)[..32]
    // (the SHA3 mixing happens inside the SophisVrfBackend, not the host
    // fn — the trait surface returns the already-mixed [u8; 32]).
    //
    // Args:
    //   chain_index : i64       — selected-chain index
    //   out_ptr     : *mut u8   — guest buffer, must accommodate 32 bytes
    //
    // Returns: i32
    //   0    success — 32 bytes written at out_ptr
    //  -1    capability not granted (`Capability::VrfRandomness` missing)
    //  -2    gas exhaustion
    //  -3    chain_index >= current chain tip index (future block)
    //  -4    chain_index < 0
    //  -5    out_ptr write would land out of WASM linear memory
    //  -6    chain_index < tip but the store cannot resolve it (pruned / unhealthy node)
    linker
        .func_wrap("env", "sophis_vrf_random_at", |mut caller: Caller<ExecutionContext>, chain_index: i64, out_ptr: i32| -> i32 {
            if caller.data().check_capability(&Capability::VrfRandomness).is_err() {
                return -1;
            }
            let cost = caller.data().gas_config.vrf_random_cost;
            if caller.data_mut().charge(Gas(cost)).is_err() {
                return -2;
            }
            if chain_index < 0 {
                return -4;
            }
            let chain_index = chain_index as u64;
            let vrf = Arc::clone(&caller.data().vrf);
            if chain_index >= vrf.current_tip_index() {
                return -3;
            }
            let Some(bytes) = vrf.vrf_random_at(chain_index) else {
                return -6;
            };
            // Use the standard write helper but fix-size: pass -1 for
            // out_len_ptr since the size is fixed (32 bytes); the helper
            // skips the length write when the pointer is negative.
            if write_to_memory(&mut caller, &bytes, out_ptr, -1) == 0 {
                return -5;
            }
            0
        })
        .map_err(|e| RuntimeError::InstantiationFailed(e.to_string()))?;

    // sophis_verify_da(ptr_payload_id, _padding, min_confirmations, query_kind) -> i32
    //
    // Args:
    //   ptr_payload_id    : *const u8 — 48 bytes in guest memory (payload_id or bundle_id)
    //   _padding          : i32       — reserved, MUST be 0
    //   min_confirmations : i64       — minimum confirmation count
    //   query_kind        : i32       — 0 = payload_id, 1 = bundle_id
    //
    // Returns: i32
    //   0    not found / confirmations < min
    //   1    present with confirmations >= min
    //  -1    query_kind invalid
    //  -2    capability not granted
    //  -3    gas exhaustion
    //  -4    memory read out of bounds / padding non-zero
    linker
        .func_wrap(
            "env",
            "sophis_verify_da",
            |mut caller: Caller<ExecutionContext>,
             ptr_payload_id: i32,
             padding: i32,
             min_confirmations: i64,
             query_kind: i32|
             -> i32 {
                if caller.data().check_capability(&Capability::VerifyDataAvailability).is_err() {
                    return -2;
                }
                let cost = caller.data().gas_config.da_verify_cost;
                if caller.data_mut().charge(Gas(cost)).is_err() {
                    return -3;
                }
                if padding != 0 {
                    return -4;
                }
                if !(0..=1).contains(&query_kind) {
                    return -1;
                }
                if min_confirmations < 0 {
                    return -1;
                }
                let Some(id) = read_fixed_48(&mut caller, ptr_payload_id) else {
                    return -4;
                };
                let min_conf = min_confirmations as u64;
                let da = Arc::clone(&caller.data().da);
                let present = match query_kind {
                    0 => da.verify_payload(&id, min_conf),
                    1 => da.verify_bundle(&id, min_conf),
                    _ => unreachable!(),
                };
                if present { 1 } else { 0 }
            },
        )
        .map_err(|e| RuntimeError::InstantiationFailed(e.to_string()))?;

    Ok(())
}

// --- memory helpers ---

fn wasm_memory(caller: &mut Caller<ExecutionContext>) -> Option<wasmtime::Memory> {
    match caller.get_export("memory") {
        Some(wasmtime::Extern::Memory(m)) => Some(m),
        _ => None,
    }
}

fn read_one(caller: &mut Caller<ExecutionContext>, ptr: i32, len: i32) -> Option<Vec<u8>> {
    let mem = wasm_memory(caller)?;
    let data = mem.data(caller.as_context());
    let s = ptr as usize;
    let e = s.checked_add(len as usize)?;
    if e > data.len() {
        return None;
    }
    Some(data[s..e].to_vec())
}

fn read_two(caller: &mut Caller<ExecutionContext>, p1: i32, l1: i32, p2: i32, l2: i32) -> Option<(Vec<u8>, Vec<u8>)> {
    let mem = wasm_memory(caller)?;
    let data = mem.data(caller.as_context());
    let v1 = bounded(data, p1, l1)?;
    let v2 = bounded(data, p2, l2)?;
    Some((v1, v2))
}

fn read_three(
    caller: &mut Caller<ExecutionContext>,
    p1: i32,
    l1: i32,
    p2: i32,
    l2: i32,
    p3: i32,
    l3: i32,
) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mem = wasm_memory(caller)?;
    let data = mem.data(caller.as_context());
    let v1 = bounded(data, p1, l1)?;
    let v2 = bounded(data, p2, l2)?;
    let v3 = bounded(data, p3, l3)?;
    Some((v1, v2, v3))
}

fn read_fixed_32(caller: &mut Caller<ExecutionContext>, ptr: i32) -> Option<[u8; 32]> {
    let mem = wasm_memory(caller)?;
    let data = mem.data(caller.as_context());
    let s = ptr as usize;
    let e = s.checked_add(32)?;
    if e > data.len() {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&data[s..e]);
    Some(out)
}

fn read_fixed_48(caller: &mut Caller<ExecutionContext>, ptr: i32) -> Option<[u8; 48]> {
    let mem = wasm_memory(caller)?;
    let data = mem.data(caller.as_context());
    let s = ptr as usize;
    let e = s.checked_add(48)?;
    if e > data.len() {
        return None;
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(&data[s..e]);
    Some(out)
}

fn read_fixed_6(caller: &mut Caller<ExecutionContext>, ptr: i32) -> Option<[u8; 6]> {
    let mem = wasm_memory(caller)?;
    let data = mem.data(caller.as_context());
    let s = ptr as usize;
    let e = s.checked_add(6)?;
    if e > data.len() {
        return None;
    }
    let mut out = [0u8; 6];
    out.copy_from_slice(&data[s..e]);
    Some(out)
}

fn bounded(data: &[u8], ptr: i32, len: i32) -> Option<Vec<u8>> {
    let s = ptr as usize;
    let e = s.checked_add(len as usize)?;
    if e > data.len() {
        return None;
    }
    Some(data[s..e].to_vec())
}

fn write_to_memory(caller: &mut Caller<ExecutionContext>, bytes: &[u8], out_ptr: i32, out_len_ptr: i32) -> i32 {
    let mem = match wasm_memory(caller) {
        Some(m) => m,
        None => return 0,
    };
    let data = mem.data_mut(caller.as_context_mut());
    let ptr = out_ptr as usize;
    // F-37 — `checked_add` so a near-usize::MAX `out_ptr` cannot wrap the bound
    // check and let the copy below run out of bounds (the prior `ptr + len`
    // could overflow and spuriously pass the `> data.len()` test).
    match ptr.checked_add(bytes.len()) {
        Some(end) if end <= data.len() => {}
        _ => return 0,
    }
    data[ptr..ptr + bytes.len()].copy_from_slice(bytes);
    if out_len_ptr >= 0 {
        let lp = out_len_ptr as usize;
        if lp.checked_add(4).is_some_and(|end| end <= data.len()) {
            data[lp..lp + 4].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        }
    }
    1
}
