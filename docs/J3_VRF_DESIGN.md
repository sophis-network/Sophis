# J3 — Native VRF via Selected-Chain Block Hash

> **Status:** design frozen for sub-fase J3.0 — ready for J3.1 implementation.
> **Originating roadmap:** Roadmap J (Ethereum lessons), item J3.
> **Companion docs:** future `docs/J3_RUNBOOK.md` (developer + operator
> guide, deferred follow-up) and `SIPS/SIP-5-VRF.md` (also deferred
> follow-up; not part of J3 v1 ship).
> **Pre-existing baseline:** **none**. Sophis sVM ships today with no
> source of in-contract entropy except contract-supplied `data` bytes
> or external oracles. J3 adds a free, deterministic, bias-resistant
> VRF derived from chain state.

## 1. Motivation

Every production smart-contract platform either ships a native source of
in-contract randomness or forces dApps to glue on an external oracle:

- **Ethereum** had `block.difficulty` (now `block.prevrandao`),
  bias-vulnerable because validators choose the next slot's RANDAO.
  Production dApps therefore use **Chainlink VRF** off-chain: latency,
  external trust, $5–$50 per call.
- **Solana** has the `SlotHashes` sysvar, deterministic and free, but
  vulnerable to grinding by leaders since the leader can withhold a slot
  to influence the hash.
- **Cosmos** chains usually integrate **Drand** as a layer-2 dependency.

Sophis does not have this gap because **RandomX PoW headers are already
the perfect VRF input**:

- A miner cannot grind RandomX cheaply (RandomX is memory-hard, ~2 min
  to warm up the dataset, then ~kH/s per CPU). Withholding a block to
  re-roll a more favourable hash costs the miner the entire block reward
  every attempt.
- Block hashes are deterministic: every full node observing the same
  chain agrees on the same hash for chain index N.
- Block hashes are unbiased: no single party (validator, leader,
  proposer) selects them; the open mining race does.

J3 exposes this directly to sVM contracts via a single host function.
Cost: O(1) RocksDB lookup + ~1 µs SHA3 mixing. Latency: same block.
External trust: zero.

This is a **technical differentiator** vs every other smart-contract
platform — Sophis is the only one in production where in-contract
verifiable randomness is a one-line SDK call against the same security
the chain itself is built on.

## 2. Ratified design decisions

These decisions were committed by the founder on 2026-05-10 and are
frozen for the J3 implementation. Re-opening any of them requires a
new SIP.

| ID | Question | Choice | Rationale |
|----|----------|--------|-----------|
| **D1** | Parameter type | `chain_index: u64` (1-to-1 with selected-chain block hash) | Zero ambiguity in DAG. `selected_chain_store.get_by_index(N) -> Hash` is a single O(1) RocksDB read. DAA score would force a "find-the-canonical-chain-block-with-this-DAA" lookup that may straddle multiple blocks; chain_index sidesteps the question entirely. Contracts that want "block_height" can read the current chain tip index via a future helper. |
| **D2** | Output derivation | `SHA3-384(b"sophis-vrf-v1\0" \|\| chain_index_le_8 \|\| chain_block_hash)[..32]` | Domain separator (`b"sophis-vrf-v1\0"`) prevents collision with other uses of the same block hash (consensus, Phase 6 DA, L1 ALT). `chain_index` in the input ensures the same physical block (e.g. after a soft-fork-introduced extra index level) cannot accidentally produce the same VRF for two queries. Truncation 384→256 bits matches the J4 `topic[0]` convention so SDK helpers compose. |
| **D3** | Status codes | -1 capability / -2 gas / -3 future index / -4 negative index / -5 OOB write / -6 chain_index unknown | Mirrors L1 ALT (`sophis_alt_lookup`) and J4 (`sophis_emit_event`) numbering exactly. Negative index (-4) is checked separately from "future index" (-3) so contract-side error handling can distinguish "you typed garbage" from "wait for the next block to be mined". |
| **D4** | Gas cost | `GAS_VRF_RANDOM = 500` | Cheaper than `GAS_ALT_RESOLVE = 1500` because there is no buffer-write back to linear memory beyond a fixed 32 bytes (vs ALT's variable spk_script). Same order of magnitude as `GAS_DA_VERIFY = 2000` because the cost is dominated by RocksDB lookup overhead, not compute. Re-calibration deferred to post-devnet measurements. |
| **D5** | Source of truth | `selected_chain_store` (= GHOSTDAG selected chain) | The selected chain is the canonical "linear projection" of the DAG. By construction every full node agrees on it once a block is committed. Using it instead of, say, the raw `headers_store` means contracts get one block per `chain_index` with no DAG ambiguity. Re-orgs that touch the chain naturally invalidate the contract's prior VRF reads (the contract MUST have used a `chain_index <= current_tip - finality_depth` to be safe). |

## 3. Wire format

### 3.1 Host function signature

```text
extern "C" {
    /// Writes 32 bytes of VRF entropy at out_ptr.
    /// Returns 0 on success, negative status on error (see §3.2).
    fn sophis_vrf_random_at(chain_index: i64, out_ptr: i32) -> i32;
}
```

Single fixed-size output (32 bytes), no out_len_ptr — caller knows the
size up-front. No length parameter on input — `chain_index` is a fixed
8-byte signed integer (negative checked at -4).

### 3.2 Status codes

| Status | Meaning | Contract recovery |
|--------|---------|-------------------|
| 0 | 32 bytes written at `out_ptr` | use the entropy |
| -1 | `Capability::VrfRandomness` not declared in manifest | revert deploy or remove the call |
| -2 | per-tx gas budget exhausted | revert tx |
| -3 | `chain_index >= current chain tip index` | wait until the chain advances; commit-reveal pattern |
| -4 | `chain_index < 0` (cast from negative i64) | producer-side bug; revert |
| -5 | `out_ptr` write would land out of WASM linear memory | producer-side bug; revert |
| -6 | `chain_index` is < tip but the store cannot resolve it | should not happen on a healthy node; revert + investigate |

### 3.3 Output derivation

The 32 bytes the host writes at `out_ptr` are computed as:

```text
let chain_block_hash = selected_chain_store.get_by_index(chain_index);  // [u8; 32]
let mut hasher = Sha3_384::new();
hasher.update(b"sophis-vrf-v1\0");
hasher.update(&chain_index.to_le_bytes());          // 8 bytes
hasher.update(chain_block_hash.as_bytes());         // 32 bytes
let digest = hasher.finalize();                     // 48 bytes
out[..32].copy_from_slice(&digest[..32]);
```

The full 384-bit digest is computed but only 256 bits are returned. The
upper 128 bits are discarded.

## 4. Threat model

| ID | Threat | Mitigation |
|----|--------|------------|
| T1 | Miner grinds the block hash to bias the VRF output | RandomX is memory-hard; grinding 1 bit costs ~100 ms of dataset-warm CPU work and forfeits the block reward on every miss. Total economic cost to bias one bit ≈ block subsidy. Multi-bit grinding scales exponentially. |
| T2 | Contract reads VRF for a block that gets reorg'd | Contract MUST use `chain_index <= current_tip - finality_depth`. Reading the very tip is documented as unsafe in the runbook and SDK comments. Finality depth on Sophis mainnet (= 1000-2000 blocks per `project_finality_decisao.md`) makes reorg-driven VRF flips negligible. |
| T3 | Contract reads VRF for a block before the block is mined | Status code -3 fires; contract gets no entropy. Pure pull-only API; no future-block oracle. |
| T4 | Two contracts on the same chain read the same VRF and trivially collude | Domain separation prevents accidental collision *between Sophis subsystems* (DA, ALT, J4 events). It does **not** prevent two intentionally-cooperating contracts from agreeing on the same entropy — that is a feature, not a bug, for protocols like commit-reveal lotteries that need a shared random seed. |
| T5 | Eclipse attack — adversary serves a custom chain to the victim | Out of scope for J3. Eclipse defenses are at the P2P / sync layer. A victim under eclipse sees a forged chain with forged VRF; same as for any consensus-derived data. |
| T6 | sVM contract uses VRF as a private key seed | Documented anti-pattern in the runbook. The VRF output is *public* — it is derived from public chain state. Anyone observing the chain can recompute the same 32 bytes. Use `verify_dilithium` for keys; the VRF is only for unbiased random selection. |
| T7 | Determinism failure — different nodes see different VRF for the same chain block | Cannot happen by construction: the input is `(chain_index, block_hash)`, both derived from `selected_chain_store` which is identical across full nodes after the same chain block is committed. The SHA3-384 derivation is deterministic. |

## 5. Comparison vs alternatives

| System | Source | Bias-resistant? | On-chain cost | External trust |
|--------|--------|-----------------|---------------|----------------|
| Ethereum `block.prevrandao` | beacon chain RANDAO mixed at slot N | ❌ — proposer of slot N can choose to skip | ~free | none |
| Chainlink VRF (Ethereum) | off-chain VRF + on-chain proof verify | ✅ | $5–$50 per call (LINK + gas) | Chainlink network |
| Solana `SlotHashes` | recent slot hash chain | ❌ — leader can withhold a slot | ~free | none |
| Drand (Cosmos integrations) | t-of-n threshold beacon | ✅ if t honest | bridging gas + delay | Drand network |
| **Sophis J3 VRF** | selected-chain RandomX block hash | ✅ — RandomX grinding cost ≥ block reward per bit | `GAS_VRF_RANDOM = 500` per call | none |

Sophis is the only entry that is simultaneously bias-resistant AND
trust-free AND ~free at the call site. The reason is structural:
RandomX PoW is uniquely suited as a VRF input (memory-hard grinding cost
is prohibitive), and Sophis's L1 already mints these hashes for every
block as a cost of doing consensus.

## 6. Out-of-scope (for J3)

The following are deliberately deferred:

- **Range / multi-block aggregation** (`vrf_random_over_range(from, to)`)
  — contract can do this themselves by reading multiple chain_index VRFs
  and SHA3-mixing.
- **Per-contract sub-keys** (`vrf_random_at(chain_index, contract_seed)`)
  — same as above; contract calls SHA3 with its own seed.
- **Pre-image proof for off-chain consumers** — anyone with chain access
  can recompute the VRF; no prover/verifier asymmetry to expose.
- **Subscription / push notifications** — pull-only in v1.
- **VRF for blocks before pruning point** — `selected_chain_store`
  prunes its older index; contract requesting a pruned chain_index gets
  status -6. Deep history VRF would require an archive node and is out
  of scope for v1.

## 7. Frozen ABI surface

The following are **frozen** as of the J3 implementation merge. Any
change requires a hard fork.

| Item | Value |
|------|-------|
| `Capability::VrfRandomness` | enum variant (no on-wire opcode) |
| Host fn name | `sophis_vrf_random_at` |
| Host fn signature | `(chain_index: i64, out_ptr: i32) -> i32` |
| Output length | always 32 bytes |
| Domain separator | `b"sophis-vrf-v1\0"` (14 bytes including the trailing null) |
| `GAS_VRF_RANDOM` | 500 |
| Status codes | -1 / -2 / -3 / -4 / -5 / -6 (per §3.2) |

## 8. Reference implementation map

| Sub-fase | Scope |
|---------|-------|
| J3.0 | This design document |
| J3.1 | `Capability::VrfRandomness` + `GAS_VRF_RANDOM` + `GasConfig` field |
| J3.2 | `HostVrf` trait + `StubVrf` + `ExecutionContext.vrf` + `sophis_vrf_random_at` host fn registered in linker |
| J3.3 | `Env::vrf_random_at_chain_index` SDK helper + `VrfError` enum |
| J3.4 | `SophisVrfBackend` real impl (selected_chain_store + SHA3-384) wired through `SvmContext` and `services.rs` |
| J3.5 | Integration tests (WAT contracts exercising every status code) + unit tests for `SophisVrfBackend` determinism |
| J3.6 | Workspace check + clippy strict + single commit |

## 9. Glossary

| Term | Meaning |
|------|---------|
| VRF | Verifiable Random Function — a deterministic function of public state whose output is unpredictable to anyone who doesn't know the input. Sophis J3 satisfies the verifiability requirement (recompute from chain state) and the bias-resistance requirement (RandomX grinding cost ≥ block reward) but is NOT a cryptographic VRF in the strict sense (no signing key, no Dilithium proof) — it is a *chain-derived* VRF. |
| Selected chain | The GHOSTDAG canonical "main chain" projection of the DAG. One block per `chain_index`. |
| Chain index | The strictly-increasing integer position of a block within the selected chain. Index 0 = genesis. |
| Domain separator | Byte string prefix (`b"sophis-vrf-v1\0"`) prepended to the SHA3 input so VRF outputs cannot accidentally collide with hashes computed for other Sophis subsystems. |
