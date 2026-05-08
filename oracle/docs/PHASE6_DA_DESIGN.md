# Sophis Phase 6 — Self Data Availability design (sub-fase 6.0)

This document is the **canonical design** of the Phase 6 Data Availability
layer. It is the binding contract between the consensus layer (V3 carrier
output), the rollup sequencer (Phase 3 batch publication), the oracle
relayer (Phase 5 bundle publication), the sVM (`Capability::VerifyDataAvailability`),
the host RPC, and any third-party indexer / light client that wants to
read carrier blobs from the Sophis DAG.

**Status:** v1, locked at sub-fase 6.0 (2026-05-06). The wire format,
constants, and capability signature in §3, §4, §5, §7, and §8 form the
**ABI freeze**. Bumping any value in those sections is a hard fork —
do not change without a coordinated rollout.

**Position in the roadmap:** Phase 6 ships at genesis with no activation
gate (see `project_phase6_schedule_activation.md` — zero-gates strategy).
Sub-fase 6.0 (this doc) is the foundation for sub-fases 6.1-6.9. None of
them reference external chains or external DA committees: Sophis ships
its own DA on its own L1.

---

## 1. Goal and non-goals

### 1.1 Goal

Provide an **L1-native data availability primitive** so that L2 rollups,
the ZK-Oracle, and any future Sophis-aware application can publish
arbitrary calldata to the Sophis DAG with three guarantees:

1. **Inclusion** — once a transaction with a V3 carrier output is accepted
   by the consensus rules, every full node has the bytes.
2. **Addressability** — every carrier blob has a deterministic 48-byte
   `payload_id = SHA3-384(SPHS-DA1 || header || data)`. Anyone with the
   id can ask any full node for the bytes.
3. **Verifiability inside the sVM** — a contract can call
   `Capability::VerifyDataAvailability` and learn, deterministically and
   at consensus time, whether a given `payload_id` is present in the DAG
   with at least N confirmations.

### 1.2 Non-goals

| Non-goal | Why |
|---|---|
| External DA layer (Avail, Celestia, EigenDA) | Pivô regulatório 2026-05-04 + zero-gates strategy; we publish on our own L1 |
| Erasure coding / DAS | Sophis pays storage cost upfront. Honest majority of full nodes is the same trust assumption as the L1 itself |
| Pruning / archival split | Out of scope for v1. Carrier outputs live in the same UTXO/pruning regime as any other transaction byte |
| Encrypted blobs | The L1 is transparent (decisão #5 of pivô); applications can encrypt off-chain before publishing if they want, but the consensus layer treats every blob as opaque public bytes |
| Bridging carrier blobs to other chains | Out of scope for the core team (decisão #4). Third parties can build readers of the carrier byte stream |
| DA fees market separate from L1 fees | Carrier outputs pay block mass like any other byte. No separate DA gas token. KISS |
| L1 reads of arbitrary L2 calldata for execution | The L1 only stores the bytes. Decoding/executing is the consumer's job |

## 2. Why Self-DA, not external DA

The previous Phase 6 proposal (`project_phase6_avail_da.md`, 2026-05-05)
called for an Avail integration. That proposal is **superseded**. Reasons:

| Vector | External DA (Avail) | Self-DA (this design) |
|---|---|---|
| **PQC posture** | Avail uses BLS12-381 + Ed25519 (pre-quantum); a CRQC adversary can forge DA committee attestations and feed Sophis a fake "data is available" signal | Sophis uses Dilithium ML-DSA-44 + RandomX PoW; carrier inclusion inherits the same PQC guarantees as the L1 |
| **Operational dependency** | Sophis L2 dies if Avail dies; rollup operators must hold AVAIL or swap | Sophis L2 inherits Sophis L1 liveness |
| **Regulatory surface** | Bridging to a non-PQC DA layer reintroduces the cross-chain dependency the 2026-05-04 pivot eliminated | Stays within the L1; no third-party legal entity in the trust path |
| **Zero-gates fit** | Activation gate would be required (Avail must be live; testnet bridge must be tested) | Ships at genesis; testnet covers it pre-mainnet |
| **Cost** | US$ 100-300k all-in + ongoing AVAIL fees | Marginal; storage cost amortized into the block mass model |
| **Throughput** | Avail KZG-DAS targets ~100 MB/s; far above Sophis's near-term L2 needs | Limited by Sophis block mass (sufficient for Phase 3 rollup at 10 BPS — see §11) |

The Avail proposal solved a problem (DA throughput at multi-rollup
scale) that Sophis does not have at launch and will not have for years.
Self-DA solves the problem Sophis actually has (publishing batch
calldata so the rollup verifier and the oracle relayer can be queried
honestly), with zero external dependency and full PQC alignment.

## 3. Wire format — V3 ScriptPubKey carrier output

A **carrier output** is a transaction output whose `ScriptPublicKey` has
`version = 5`. The output is **unspendable**: no transaction may consume
it as an input, and the consensus layer prunes it from the active UTXO
set immediately after acceptance (it is indexed separately — see §6).

The carrier was assigned to SPK version 5 to avoid collisions with the
Phase 3 internal rollup bridge: versions 3 and 4 are reserved by
`BRIDGE_VAULT_VERSION` (deposit) and `BRIDGE_CLAIM_VERSION` (withdrawal
claim) respectively. See `consensus/core/src/constants.rs` for the
authoritative SPK version registry.

### 3.1 ScriptPublicKey layout

```
ScriptPublicKey {
    version: u16 = 5,                   // SCRIPT_VERSION_CARRIER
    script:  Vec<u8>,                   // see §3.2
}
```

The transaction output that owns this `ScriptPublicKey` MUST have
`value = 0`. A non-zero value is a hard rule violation and the
transaction is rejected by the consensus.

### 3.2 Script payload

```
+--------+---------------------------+
| offset | content                   |
+========+===========================+
|  0..8  | magic = b"SPHS-DA1"       |   // 8 bytes
|  8..9  | flags: u8                 |   // see §3.3
|  9..10 | reserved: u8 = 0          |
| 10..11 | fragment_count: u8        |   // 1..=MAX_FRAGMENTS
| 11..12 | fragment_index: u8        |   // 0..fragment_count
| 12..16 | data_len: u32 (LE)        |   // length of `data` in bytes
| 16..64 | bundle_id: [u8; 48]       |   // SHA3-384 of the full reassembled blob
| 64..N  | data: Vec<u8>             |   // raw payload bytes, this fragment
+--------+---------------------------+
```

Total fixed header: **64 bytes**. Variable body: `data_len` bytes.

The **carrier `payload_id`** of this output is:

```
payload_id := SHA3-384( script[0..(64 + data_len)] )    // 48 bytes
```

Note: `payload_id ≠ bundle_id`. `payload_id` identifies one fragment.
`bundle_id` identifies the complete reassembled blob across fragments.
For a single-fragment blob the two are NOT equal because `payload_id`
hashes the framed script (header + data) while `bundle_id` hashes the
raw data. This is intentional: indexers can address fragments without
knowing the bundle, and contracts can address bundles without enumerating
fragments.

### 3.3 Flags byte

```
bit 0 (0x01)  CARRIER_FLAG_FRAGMENTED   set iff fragment_count > 1
bit 1 (0x02)  CARRIER_FLAG_LAST         set iff fragment_index == fragment_count - 1
bit 2 (0x04)  reserved (must be 0)
bit 3 (0x08)  reserved (must be 0)
bit 4 (0x10)  CARRIER_FLAG_DOMAIN_ROLLUP   informational, see §3.4
bit 5 (0x20)  CARRIER_FLAG_DOMAIN_ORACLE   informational, see §3.4
bit 6 (0x40)  CARRIER_FLAG_DOMAIN_USER     informational, see §3.4
bit 7 (0x80)  reserved (must be 0)
```

Reserved bits MUST be zero. The consensus rejects any output where
reserved bits are set.

The three domain bits are **mutually exclusive** (exactly one must be
set, or all three may be unset for unclassified). They do not change
consensus validity — they only let indexers route carriers to the right
subscriber without parsing payloads. Having no domain bit set is legal
("unclassified") and gets indexed only into the global stream.

### 3.4 Fragment semantics

A bundle can be split into up to `MAX_FRAGMENTS` (= 32) carrier outputs.
All fragments share the same `bundle_id`. Reassembly is purely additive:

```
data_full = concat( fragment[0].data, fragment[1].data, ..., fragment[N-1].data )
assert SHA3-384(data_full) == bundle_id
```

Fragments may live in **different transactions** in **different blocks**.
Order is given by `fragment_index`. The bundle is not "complete" from
the consensus point of view (consensus does not track this) — it is
complete from the consumer's point of view once they have all `N`
fragments and the SHA3-384 reassembly check passes. Consumers decide
their own freshness window.

A single-fragment bundle is just `fragment_count = 1`, `fragment_index = 0`,
`CARRIER_FLAG_FRAGMENTED = 0`, `CARRIER_FLAG_LAST = 1`.

## 4. Constants

These constants form the **ABI freeze** of sub-fase 6.0. Any change
requires a hard fork.

| Name | Value | Purpose |
|---|---|---|
| `SCRIPT_VERSION_CARRIER` | `5` (u16) | SPK version of a carrier output |
| `MAX_SCRIPT_PUBLIC_KEY_VERSION` | bumped from `2` to `5` | Highest accepted SPK version (3, 4 = bridge legacy; 5 = carrier) |
| `CARRIER_MAGIC` | `b"SPHS-DA1"` (8 bytes) | First 8 bytes of every carrier script |
| `CARRIER_HEADER_LEN` | `64` | Fixed header bytes before `data` |
| `CARRIER_PAYLOAD_HASH_ALG` | `SHA3-384` | Both for `payload_id` and `bundle_id` |
| `CARRIER_PAYLOAD_HASH_LEN` | `48` | bytes |
| `MAX_FRAGMENTS` | `32` | Max carrier outputs per bundle |
| `MAX_DATA_PER_CARRIER` | `65_536` (64 KiB) | Max `data_len` per carrier output |
| `MAX_BUNDLE_BYTES` | `MAX_FRAGMENTS * MAX_DATA_PER_CARRIER = 2_097_152` (2 MiB) | Max reassembled bundle size |
| `CARRIER_OUTPUT_VALUE` | `0` sompi | Mandatory: any non-zero value is rejected |
| `CARRIER_FLAG_FRAGMENTED` | `0x01` (u8) | Set iff `fragment_count > 1` |
| `CARRIER_FLAG_LAST` | `0x02` (u8) | Set iff `fragment_index == fragment_count - 1` |
| `CARRIER_FLAG_DOMAIN_ROLLUP` | `0x10` (u8) | Informational: Phase 3 batch payload |
| `CARRIER_FLAG_DOMAIN_ORACLE` | `0x20` (u8) | Informational: Phase 5 oracle bundle |
| `CARRIER_FLAG_DOMAIN_USER` | `0x40` (u8) | Informational: third-party application |
| `MAX_CARRIER_OUTPUTS_PER_TX` | `8` | Anti-spam cap per transaction |
| `DEFAULT_DA_CONFIRMATIONS` | `1000` (blue score gap) | Default `min_confirmations` parameter for `VerifyDataAvailability` |

The values are chosen so that:

- 64 KiB per output × 8 outputs per tx = 512 KiB max per tx, which fits
  inside the existing block mass envelope (block mass cap remains
  unchanged at 500_000 mass units; carrier bytes pay the same
  `TRANSIENT_BYTE_TO_MASS_FACTOR = 4` as any other tx byte).
- 2 MiB max bundle size covers Phase 3 batch calldata for up to ~5,000
  L2 transactions (typical 400 bytes each), which is well above the
  100-tx batch trigger and the 30-second time trigger.
- 48-byte SHA3-384 hash gives 192-bit classical preimage and 96-bit
  Grover-bound quantum preimage resistance. SHA3-256 (128-bit / 64-bit)
  was rejected as insufficient margin for a long-lived L1 primitive.
- `DEFAULT_DA_CONFIRMATIONS = 1000` mirrors the Sophis probabilistic
  finality recommendation (~100 seconds at 10 BPS).

## 5. Consensus rules for V3 outputs

A transaction containing one or more outputs with `script_public_key.version == 5`
is valid iff **all** of the following hold for **every** such output:

1. `script_public_key.script.len() >= CARRIER_HEADER_LEN` (64 bytes).
2. `script[0..8] == CARRIER_MAGIC`.
3. `script[9] == 0` (reserved-1).
4. `flags = script[8]` has reserved bits 2, 3, 7 unset.
5. At most one of bits 4, 5, 6 of `flags` is set.
6. `fragment_count = script[10]` is in `1..=MAX_FRAGMENTS`.
7. `fragment_index = script[11]` is in `0..fragment_count`.
8. `(flags & CARRIER_FLAG_FRAGMENTED) != 0` iff `fragment_count > 1`.
9. `(flags & CARRIER_FLAG_LAST) != 0` iff `fragment_index == fragment_count - 1`.
10. `data_len = u32::from_le_bytes(script[12..16])` is in `0..=MAX_DATA_PER_CARRIER`.
11. `script.len() == CARRIER_HEADER_LEN + data_len` exactly.
12. `output.value == 0`.

Plus, at the transaction level:

13. The transaction has at most `MAX_CARRIER_OUTPUTS_PER_TX` (= 8)
    outputs with `version == 5`.
14. Carrier outputs are NOT permitted to be coinbase outputs in v1 —
    only spendable transactions may carry V3 outputs. (This keeps the
    coinbase rule simple: 100% to miner, no carriers. See §10.)

If any of 1-14 fail, the transaction is rejected. Carrier outputs are
**immediately removed from the active UTXO set** after the containing
block is accepted into the selected parent chain. They never appear in
`ConsensusManager::utxos_by_outpoints` lookups or in the merkle UTXO
commitment.

A separate **DA store** (§6) holds the body of every accepted carrier
output, keyed by `payload_id` and `bundle_id`. The store is part of full
node state but NOT part of the consensus state commitment for v1 (see
§9 for the rationale).

## 6. Indexation — DA store

Every full node maintains a key-value store under the data dir:

```
<data_dir>/<network>/da-store/
    payloads/        // key = payload_id (48 B);  value = (script bytes, accepting_block_hash, blue_score, fragment_index, bundle_id)
    bundles/         // key = bundle_id  (48 B);  value = sorted list of payload_ids by fragment_index
    by_block/        // key = block_hash;         value = list of payload_ids accepted in that block
    by_domain/       // key = (domain_byte, blue_score_bucket); value = list of payload_ids
```

Backed by RocksDB column families inside the existing consensus
database. No new process, no new daemon — the indexer is a hook in the
block acceptance pipeline.

### 6.1 Retention

Same retention as the rest of the consensus state. A pruned block does
not erase its carrier data on its own — pruning carrier bodies follows
the same rules as pruning transactions (configurable `--archival` flag
keeps everything; default keeps last `pruning_depth` blue scores).

### 6.2 Read API

The host RPC (Phase 6.4) exposes:

```text
da_get_payload(payload_id)      -> Option<{ data: Bytes, metadata: PayloadMeta }>
da_get_bundle(bundle_id)        -> Option<{ data: Bytes, fragments: Vec<PayloadMeta> }>
da_list_by_block(block_hash)    -> Vec<PayloadMeta>
da_list_by_domain(domain, blue_score_range) -> Vec<PayloadMeta>
da_status(payload_id)           -> Option<{ accepted: bool, blue_score: u64, confirmations: u64 }>
```

`PayloadMeta` is the full record minus the body (so callers can paginate
without dragging megabytes).

`da_get_bundle` reassembles fragments transparently and verifies
`SHA3-384(reassembled) == bundle_id` before returning. If the bundle is
incomplete (some fragments missing or unaccepted), it returns `None`.

## 7. sVM integration — `Capability::VerifyDataAvailability`

A new capability is added to the sVM capability enum (next ordinal after
the current set: `ReadUtxo`, `ProduceOutput`, `VerifyDilithium`,
`ReadBlockHeight`, `HashSha3`, `VerifyRisc0Proof`, `VerifyPlonky3Proof`,
`VerifyDataAvailability`).

### 7.1 Host function

```rust
// In svm/host/src/da.rs (new file)
//
// Linker symbol: "sophis_verify_da"
// Wasm signature: (i32, i32, i64, i32) -> i32
//
// Args:
//   ptr_payload_id     : *const u8        (48 bytes guest memory)
//   _padding           : i32              (must be 0; reserved)
//   min_confirmations  : i64              (LE)
//   query_kind         : i32              (0 = payload_id, 1 = bundle_id)
//
// Returns: i32
//   0   not found / not yet sufficiently confirmed
//   1   present with `confirmations >= min_confirmations`
//  -1   query_kind invalid
//  -2   capability not granted to this contract
//  -3   gas exhaustion
```

Gas cost: `DA_VERIFY_BASE = 2_000` + `DA_VERIFY_PER_CONF = 0` (the lookup
is O(1) into RocksDB; confirmations are derived from the cached blue
score of the accepting block, no scan needed).

### 7.2 Determinism

The host function MUST return the same result for every node validating
the same block. This holds because:

- The DA store is populated as part of block acceptance, before any
  contract executes (sVM runs in a deterministic post-acceptance hook).
- `confirmations` is computed as `current_blue_score - accepting_block.blue_score`,
  both of which are consensus-deterministic at the point a contract is
  executed.

Pruning interaction: if a node has pruned the carrier body but kept the
metadata (the `PayloadMeta` record), `VerifyDataAvailability` still
returns `1` — presence in the DAG is the consensus-relevant fact, not
local availability of the bytes. Reading the bytes via `da_get_*` is a
local-state operation (returns `None` on a pruned node) that contracts
cannot call.

Contracts that need the bytes for their logic must declare a stronger
capability (TBD — see §9 "Future work"); v1 only offers presence
verification.

## 8. Producer integrations (Phase 3 rollup, Phase 5 oracle, user dapps)

### 8.1 Phase 3 rollup sequencer (sub-fase 6.3)

Today (Phase 3): the sequencer publishes each batch as **2 transactions**
on L1 — `Prep` (commits batch root) and `StateUpdate` (advances rollup
state UTXO).

With Phase 6, a **third transaction** is published immediately after
`Prep`:

```
T_carrier:
    fee input(s) from sequencer's L1 wallet
    output 0..K: V3 carriers with the borsh-serialized batch calldata
                 (split into K fragments if calldata > MAX_DATA_PER_CARRIER)
                 flags: CARRIER_FLAG_DOMAIN_ROLLUP set
                 bundle_id: SHA3-384(calldata)
    output K+1: change back to sequencer
```

The `Prep` transaction is extended to carry the `bundle_id` of `T_carrier`
in its existing batch metadata. A rollup verifier checks:

```
require da_get_bundle(prep.bundle_id) != None      // data available
require sha3_384(decoded_batch.calldata) == prep.bundle_id
require risc0_verify(prep.proof, decoded_batch.calldata) ok
```

### 8.2 Phase 5 oracle relayer (sub-fase 6.6)

Today (Phase 5): the relayer signs an oracle bundle with Dilithium and
submits an invocation tx with the bundle inline (~few hundred bytes).
Bundles fit in one transaction without fragmentation.

With Phase 6, the relayer **optionally** publishes a verifiable
historical record:

```
T_oracle_da:
    output 0: V3 carrier with the full bundle bytes
              flags: CARRIER_FLAG_DOMAIN_ORACLE
              bundle_id: SHA3-384(bundle)
```

This is informational — the oracle contract still verifies the bundle
inline as today. The carrier exists for archival and external audit
(e.g., third parties replaying the relayer history without RPC access
to the sequencer).

The relayer config gains a single new flag: `da_publish = true|false`
(default: `false` for v1 — opt-in). Operators that opt in pay the
additional fee (one extra invocation tx per bundle).

### 8.3 User dapps

Any user with a Dilithium-funded address can publish carrier data by
constructing a tx with V3 outputs. SDKs (Phase 6.6) ship convenience
functions:

```rust
let bundle = b"...".to_vec();
let tx = wallet.build_da_tx(bundle, /* domain */ Domain::User)?;
wallet.submit(tx).await?;
```

No special permission. Anti-spam is handled by:

- Block mass / fee market (each carrier byte costs the same as any tx byte).
- `MAX_CARRIER_OUTPUTS_PER_TX = 8` cap.
- Per-block organic mass cap (existing rule).

## 9. Threat model

### 9.1 Adversary model

We consider a relayer/sequencer adversary, a miner adversary, a
network adversary, and a CRQC adversary.

| Adversary | Capability assumed |
|---|---|
| Relayer | Honest signing key; may withhold or delay submissions |
| Sequencer | Honest signing key; may produce invalid batches |
| Miner (rational) | Includes any tx that pays sufficient fee |
| Miner (Byzantine) | Up to `< 50% blue score`; may censor or front-run |
| Network | Drop, delay, reorder; cannot forge Dilithium signatures |
| CRQC | Quantum computer that breaks pre-quantum cryptography (BLS/Ed25519/secp256k1) but NOT Dilithium ML-DSA-44 or RandomX |

### 9.2 Attacks and mitigations

| # | Attack | Vector | Mitigation |
|---|---|---|---|
| T1 | **Withholding** — adversary publishes the `bundle_id` reference but never publishes the carrier | Sequencer publishes Prep with bundle_id but skips T_carrier | Rollup verifier requires `da_get_bundle(bundle_id) != None` before accepting batch; without bytes, no settlement |
| T2 | **Partial withholding via fragments** — fragments 0..N-1 published, fragment N never | Sequencer or third party | Verifier requires `da_get_bundle` to succeed (which checks all fragments + SHA3-384 reassembly); incomplete bundle returns None |
| T3 | **Hash collision** — two different blobs map to the same bundle_id | Cryptographic | SHA3-384 collision resistance ~2^192; not exploitable |
| T4 | **Pre-image attack** under quantum** — CRQC inverts SHA3-384 to forge a payload matching a published bundle_id | Quantum | Grover gives ~2^96 work for 384-bit SHA-3; sufficient margin for the L1 lifetime |
| T5 | **Spam / mass exhaustion** — adversary fills blocks with V3 carriers | Any user with funds | Existing block mass cap + `MAX_CARRIER_OUTPUTS_PER_TX = 8` + organic mass formula apply byte-for-byte; no DA-specific subsidy |
| T6 | **Censorship** — Byzantine miners refuse to include V3 transactions | Miner control over local mempool | Same threat as any tx censorship on a permissionless L1; mitigated by mining decentralization, not protocol |
| T7 | **Carrier replay** — same blob republished | Any user | Not an attack: payload_id is deterministic; later inclusion has higher blue score and is treated as an additional copy. Consumer logic dedupes by bundle_id |
| T8 | **Reorgs of acceptance** — carrier accepted in block B, B reorged out | DAG dynamics | `min_confirmations` parameter on `VerifyDataAvailability`; default 1000 blue score gap (~100s) gives the same safety as any L1 settlement |
| T9 | **Index poisoning** — malformed carrier bypasses validator and confuses indexer | Validator bug | All consensus checks in §5 happen before indexation; indexer trusts the consensus output. Fuzzing in 6.7 |
| T10 | **Domain confusion** — adversary publishes blob with wrong domain bit to exfiltrate | Any user | Domain bits are advisory; consumers MUST verify the inner payload format. Indexer routes by bit but contracts decode and reject mismatches |
| T11 | **Storage griefing** — adversary publishes max-size junk repeatedly to inflate node disk | Any user with funds | Pay-per-byte fee market is the economic mitigation; archival is opt-in (`--archival`), pruned nodes drop bodies. No protocol-level rate limit |
| T12 | **CRQC against ML-DSA-44 of relayer/sequencer key** | Far-future quantum | Out of scope for v1; same posture as the rest of the L1. If a CRQC defeats ML-DSA-44, every Sophis tx is forgeable, not just DA |
| T13 | **Sybil indexer reads** — adversary serves wrong bytes for a valid payload_id | Light client | Light clients verify `SHA3-384(received_bytes) == payload_id` before trusting; no signature needed because the hash is consensus-bound |

### 9.3 Out-of-scope threats (v1)

- DAS (data availability sampling) for light clients. v1 light clients
  trust honest-majority full nodes plus hash verification (T13). DAS is
  a v2 candidate (see §11).
- Privacy of carrier blobs. Anyone can read any blob by id. Encrypt
  off-chain if needed.
- Sub-second latency. Carriers settle on the same finality clock as
  ordinary L1 transactions (`DEFAULT_DA_CONFIRMATIONS = 1000`).

## 10. Interaction with the rest of the protocol

### 10.1 Coinbase

Coinbase outputs MUST NOT use `version = 5`. The coinbase rule remains
"100% to miner" (see `coinbase.rs` after the 2026-05-04 pivot, commit
`cffe1d1`). Carriers attach to spendable transactions only. Reason: keep
the coinbase rule simple and non-controversial; donate flag (`e54fcd9`)
already covers founder-discretion edge cases.

### 10.2 Donate flag (miner)

Unaffected. The donate flag rewrites the coinbase tx, which has no V3
outputs.

### 10.3 Phase 3 ZK-Rollup

The Phase 3 internal rollup already owns SPK versions 3
(`BRIDGE_VAULT_VERSION`, deposit) and 4 (`BRIDGE_CLAIM_VERSION`,
withdrawal claim). Carriers are therefore allocated to SPK version 5,
leaving the existing rollup payloads untouched. Rollup deposit/claim
flows are unchanged; only the sequencer's batch publication path gains
the optional `T_carrier` tx (sub-fase 6.3).

> Errata: an earlier draft of this document placed carriers at SPK
> version 3 and incorrectly described `BRIDGE_VAULT_VERSION` as a borsh
> tag inside the contract version. That was wrong: vault and claim are
> distinct SPK versions allocated at the consensus level. Sub-fase 6.1
> moved the carrier to version 5 to remove the collision before any
> code shipped.

### 10.4 Phase 5 ZK-Oracle

`Capability::VerifyDataAvailability` lives next to
`Capability::VerifyPlonky3Proof` (sub-fase 5.3) and is governed by the
same per-contract capability allowlist. An oracle contract that wants to
attest "this bundle was historically published" gains the capability;
contracts that don't need DA stay capability-free.

### 10.5 Native tokens

Unaffected. Native token UTXOs are SPK version `2`. No interaction.

### 10.6 Mass and fees

Carrier bytes use the existing `TRANSIENT_BYTE_TO_MASS_FACTOR = 4` and
the existing block mass cap. No new fee tier. A 64 KiB max-size carrier
costs `64 * 1024 * 4 = 262_144` mass, which is a substantial fraction
of the 500_000 cap but legal — any single tx with such a carrier is
near-mass-saturated by design (this is a feature, not a bug: it limits
spam).

### 10.7 Pruning

Carrier bodies follow the same pruning regime as transactions. Pruned
nodes drop bodies; the metadata hash record (in `payloads/` CF) is kept
through the pruning depth so `VerifyDataAvailability` keeps working for
finalized state. After full pruning, the metadata is also dropped — at
that point `da_get_*` returns `None` and `VerifyDataAvailability`
returns `0` (treated as not present, which is consensus-equivalent to
"this carrier is older than the prune horizon").

## 11. Capacity envelope

At 10 BPS and 500_000 mass per block:

| Scenario | Result |
|---|---|
| Block fully dedicated to one max carrier (262_144 mass) | ~64 KiB carrier per block, ~640 KiB/s sustained |
| Block with 1 carrier of 64 KiB + normal txs | ~640 KiB/s carrier + remaining capacity for txs |
| Phase 3 batch of 100 L2 txs × 400 bytes = 40 KiB calldata | Fits in 1 carrier; sequencer publishes ~1 batch / 30 s naturally |
| Phase 5 oracle bundle (~few KB) | Fits in 1 carrier with kilobytes of headroom |
| User dapp publishing 2 MiB blob | Spans ~32 fragments across 4 transactions (8 carriers each) — at 10 BPS, fits in <1 second of block production |

These numbers are deliberate: they ensure Phase 3 + Phase 5 fit into
the existing protocol envelope without contention, while leaving headroom
for third-party dapps. They do not match the throughput of an external
DA layer (Avail's 100 MB/s target) — they don't need to.

## 12. ABI freeze

The following items are **frozen** as of sub-fase 6.0. Changing any of
them is a hard fork:

1. `SCRIPT_VERSION_CARRIER = 5`
2. `CARRIER_MAGIC = b"SPHS-DA1"` (8 bytes)
3. The 64-byte header layout in §3.2
4. The `flags` byte semantics in §3.3
5. SHA3-384 as the hash for both `payload_id` and `bundle_id`
6. `MAX_FRAGMENTS = 32`, `MAX_DATA_PER_CARRIER = 64 KiB`, `MAX_CARRIER_OUTPUTS_PER_TX = 8`
7. The 14 consensus rules in §5
8. `Capability::VerifyDataAvailability` host function signature in §7.1
9. The unspendable + value=0 invariant in §3.1 and §5.12

The following items are **soft-frozen** (changeable with a minor version
bump signaled via a future flag bit):

- `DEFAULT_DA_CONFIRMATIONS` (default value can be tuned, but contracts
  override via the `min_confirmations` argument)
- The DA store on-disk layout (§6) — internal to each node; producers
  and contracts don't see it
- The host RPC method names (§6.2) — additive evolution allowed

## 13. Audit playbook (DIY) — sub-fase 6.9

Self-auditing approach, no paid third-party audit:

### 13.1 Spec review

Before code: post the design (this document) as an RFC on GitHub. Open
a 14-day comment window before merging the consensus rules. Feedback
captured in `oracle/docs/PHASE6_RFC_RESPONSES.md`.

### 13.2 Fuzzing

Three corpora:

1. **Script fuzzer** — random byte strings into the V3 validator;
   expectation: no panic, only `Reject(reason)`. Target ~1B iterations
   on devnet hardware before mainnet.
2. **Fragment reassembly fuzzer** — random fragment counts, indices,
   bytes; expectation: `da_get_bundle` returns `None` on any inconsistent
   set, `Some` only when a bit-exact reassembly hashes to the claimed
   bundle_id.
3. **Capability fuzzer** — random `(payload_id, min_confirmations,
   query_kind)` tuples into the host fn; expectation: deterministic
   return, no out-of-bounds reads, gas accounted.

Fuzzing harness lives in `oracle/fuzz/` (cargo-fuzz). Coverage report
embedded in `PHASE6_AUDIT.md` at sub-fase 6.9.

### 13.3 Adversarial devnet (sub-fase 6.7)

Run all 13 attacks from §9.2 as scripted devnet scenarios. Each test
script verifies that the attack fails. Tests live in
`devnet/test_phase6_da_attacks.py`. Pass criterion: 100% of expected
rejections, zero spurious accepts, zero panics.

### 13.4 Pre-mainnet stress (sub-fase 6.8)

72-hour run on a 5-node devnet at 50% block-mass saturation by carriers.
Metrics tracked: indexation latency, RocksDB growth, RAM, CPU, prune
correctness. Acceptance gates documented in `PHASE6_AUDIT.md`.

### 13.5 Public RFC and bug bounty

Sub-fase 6.9:

- Publish RFC document on GitHub (this design + diffs from review).
- Announce a 30-day bug bounty pre-mainnet, scoped to consensus rules
  and capability host fn.
- Bounty pool funded from the founder's pre-genesis discretionary
  budget (no on-chain treasury — see `project_no_entity_decision.md`).
- Acknowledged findings: append to `PHASE6_AUDIT.md`.

## 14. Open questions deferred to v2

These are explicitly **out of scope** for v1 and are listed only to
prevent re-litigation:

1. **DAS for light clients** — would require erasure coding of carrier
   payloads. Reconsider when light clients exist (post-mainnet, post-
   testnet stability, when a light client implementer asks for it).
2. **Encrypted carriers** — applications can encrypt before publishing.
   No protocol-level work for v1. If a privacy-preserving variant ever
   becomes desirable it must clear the no-privacy-on-L1 invariant first.
3. **`Capability::ReadDataAvailability`** — letting a contract read the
   bytes (not just verify presence) is desirable but raises gas-metering
   and pruning-determinism issues. Defer to a future capability whose
   gas formula accounts for body size.
4. **Multi-bundle aggregation** — coalescing many small bundles into a
   single carrier with merkle indexing. Not needed at our throughput;
   reconsider if a high-frequency producer asks.
5. **Off-chain commitments / signed receipts** — relayers / sequencers
   could emit signed receipts of carrier inclusion to skip RPC. Out of
   scope: every full node already serves the same answer.

## 15. Roadmap — sub-fases 6.1 through 6.9

| Sub | Title | Scope summary | Sessions |
|---|---|---|---|
| 6.0 | DA design | This document. ABI freeze + threat model + roadmap | 1 (done) |
| 6.1 | V3 carrier consensus | Implement §5 rules in `consensus/src/processes/transaction_validator/script_validator.rs` + bump `MAX_SCRIPT_PUBLIC_KEY_VERSION` to 3 + unspendability hook + 14-rule unit tests | 2 |
| 6.2 | Codec + indexation | `consensus/core/src/da/{codec,store}.rs` + RocksDB CFs + `by_block` / `by_domain` / `bundles` indexes + reassembly logic | 1-2 |
| 6.3 | Sequencer integration | Phase 3 sequencer emits `T_carrier` per batch + `Prep` carries `bundle_id` + rollup verifier checks `da_get_bundle` | 2 |
| 6.4 | Host + RPC | gRPC + wRPC methods from §6.2 + JSON serialization + sophisd flag `--da-archival` | 1-2 |
| 6.5 | sVM `VerifyDataAvailability` | `svm/host/src/da.rs` + capability registration + linker symbol + Kani harness | 1 |
| 6.6 | RUNBOOK + tooling | `oracle/docs/PHASE6_RUNBOOK.md` (operator guide), wallet/CLI helpers, oracle relayer `da_publish` flag | 1 |
| 6.7 | Adversarial devnet | 13 attack scripts + reassembly fuzzer corpus + CI integration | 1 |
| 6.8 | Pre-mainnet stress | 72h devnet run + metrics report in `PHASE6_AUDIT.md` | 1 |
| 6.9 | DIY audit + RFC + bug bounty | Public RFC, fuzz coverage report, bounty announcement, response addendum | embedded |

Total: 10-12 sessions to ship Phase 6 at genesis.

## 16. Anchors and reference symbols

To be created in subsequent sub-fases. Listed here so downstream sub-fases
have an authoritative target list.

| Symbol | File | Sub-fase |
|---|---|---|
| `SCRIPT_VERSION_CARRIER` (=5) | `consensus/core/src/constants.rs` | 6.1 (done) |
| `MAX_SCRIPT_PUBLIC_KEY_VERSION` (bumped to 5) | `consensus/core/src/constants.rs:10` | 6.1 (done) |
| `CARRIER_MAGIC`, `CARRIER_HEADER_LEN`, all flags, `parse_carrier_header` | `consensus/core/src/da/mod.rs` | 6.1 (done) |
| `validate_carrier_outputs(...)` (rules 12-13) + coinbase-rule-14 hook | `consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs` | 6.1 (done) |
| `payload_id`, `bundle_id_of`, `encode_*`, `reassemble`, `parse_and_reassemble` | `consensus/core/src/da/codec.rs` | 6.2.a (done) |
| `PayloadIdHash`, `PayloadEntry`, `BundleIndex`, `BlockCarriers`, `DomainBucket`, `DOMAIN_BUCKET_SIZE`, `domain_bucket_key_bytes` | `consensus/core/src/da/store_types.rs` | 6.2.b (done) |
| `DbDaStore::{index_carrier_batch, get_payload, get_bundle, list_by_block, list_by_domain, has_payload}` + `DomainBucketKey` + `CarrierIndex` | `consensus/src/model/stores/da.rs` | 6.2.b (done) |
| `DaCarrierPayloads/Bundles/ByBlock/ByDomain` (prefixes 196-199) | `database/src/registry.rs` | 6.2.b (done) |
| `index_carriers_in_block` hook in `commit_utxo_state` | `consensus/src/pipeline/virtual_processor/processor.rs` | 6.2.b (done) |
| `BatchJournal::da_bundle_id` field | `rollup/core/src/types.rs` | 6.3 (done) |
| `batch_calldata`, `compute_da_bundle_id` helpers | `rollup/sequencer/src/batch.rs` | 6.3 (done) |
| `L1Client::submit_carrier_calldata` trait method + `GrpcL1Client` impl | `rollup/sequencer/src/l1_client.rs` | 6.3 (done) |
| Sequencer `flush_batch` Phase 6 wiring | `rollup/sequencer/src/sequencer.rs` | 6.3 (done) |
| Guest computes `da_bundle_id` from `borsh(batch)` | `rollup/host/guest/src/main.rs` | 6.3 (done) |
| `RpcApi::get_da_*_call` (5 trait methods) + helper defaults | `rpc/core/src/api/rpc.rs` | 6.4.a (done) |
| `RpcApiOps::GetDa*` (152-156) | `rpc/core/src/api/ops.rs` | 6.4.a (done) |
| `RpcDaPayload`, `RpcDaBundle`, `RpcDaPayloadStatus` + 5 Request/Response | `rpc/core/src/model/da.rs` | 6.4.a (done) |
| `ConsensusApi::da_*` accessors + impl in `Consensus` | `consensus/core/src/api/mod.rs`, `consensus/src/consensus/mod.rs` | 6.4.a (done) |
| `ConsensusSession::async_da_*` wrappers | `components/consensusmanager/src/session.rs` | 6.4.a (done) |
| `RpcCoreService::get_da_*_call` (real impl, reassembles bundles) | `rpc/service/src/service.rs` | 6.4.a (done) |
| gRPC binding (proto + dispatch + real `GrpcClient::route!()` invocations) | `rpc/grpc/core/proto/{rpc,messages}.proto`, `rpc/grpc/core/src/{ops,convert/{message,sophisd}}.rs`, `rpc/grpc/client/src/lib.rs`, `rpc/grpc/server/src/request_handler/factory.rs` | 6.4.b (done) |
| wRPC binding (5 ops in `build_wrpc_client_interface!` + server router) | `rpc/wrpc/client/src/client.rs`, `rpc/wrpc/server/src/router.rs` | 6.4.c (done) |
| `Capability::VerifyDataAvailability` enum variant | `svm/core/src/capability.rs` | 6.5 (done) |
| `GAS_DA_VERIFY = 2_000` + `GasConfig::da_verify_cost` | `svm/core/src/gas.rs` | 6.5 (done) |
| `HostDa` trait + `StubDa` default | `svm/runtime/src/host.rs` | 6.5 (done) |
| `sophis_verify_da` host fn (wasm linker symbol) | `svm/runtime/src/host.rs` | 6.5 (done) |
| `ExecutionContext::new_with_da` builder + `da: Arc<dyn HostDa>` field | `svm/runtime/src/context.rs` | 6.5 (done) |
| `SophisDaBackend` (real `HostDa` impl bound to `DbDaStore`) | `consensus/src/svm_da.rs` | 6.5 (done) |
| `SvmContext::with_da_store` injector + `services.rs` wiring | `consensus/src/processes/transaction_validator/mod.rs`, `consensus/src/consensus/services.rs` | 6.5 (done) |
| `current_blue_score` plumbing via `LkgVirtualState` | `consensus/src/svm_da.rs::SophisDaBackend::from_lkg`, `mod.rs::SvmContext::lkg_virtual_state`, `services.rs` wiring | 6.5.b (done) |
| `[submit] da_publish` flag in relayer config | `oracle/relayer/src/config.rs::SubmitSection` | 6.6 (done) |
| `L1Submit::publish_carrier` trait method + `MockSubmit` recorder | `oracle/relayer/src/submit.rs` | 6.6 (done) |
| Daemon `one_iteration(.., da_publish: bool)` + `bundle_to_carrier_wire` | `oracle/relayer/src/daemon.rs` | 6.6 (done) |
| Operator runbook (~359 lines) | `oracle/docs/PHASE6_RUNBOOK.md` | 6.6 (done) |
| `GrpcSubmit::publish_carrier` real impl (encode_bundle domain=Oracle, sign + submit) | `oracle/relayer/src/submit/grpc.rs::publish_carrier_grpc` | follow-up (done) |
| `dilithium-wallet` DA helpers (CLI publish/inspect commands) | wallet | post-mainnet (deferred) |
| Adversarial test runner + threat × defense matrix (13 entries) | `devnet/test_phase6_da_attacks.py` | 6.7 (done) |
| 72h stress plan + 9 acceptance gates | `oracle/docs/PHASE6_STRESS_PLAN.md` | 6.8 (done) |
| Stress observability helper (--once / --interval / --report) | `devnet/da_stress_check.py` | 6.8 (done) |
| Synthetic carrier traffic generator (load knob for §5.3) | `sophis-da-stress` binary | 6.8.b (pending; depends on 6.4.b) |
| 6 property/fuzz tests in `da::tests` and `da::codec::tests` | `consensus/core/src/da/{mod,codec}.rs` | 6.9 (done) |
| DIY audit playbook + findings ledger | `oracle/docs/PHASE6_AUDIT.md` | 6.9 (done) |
| 30-day pre-mainnet bug bounty announcement | `oracle/docs/PHASE6_BUG_BOUNTY.md` | 6.9 (done) |
| Public RFC consolidating Phase 6 docs | `oracle/docs/PHASE6_RFC.md` | 6.9 (done) |
| `gRPC: da_get_payload, da_get_bundle, da_list_by_block, da_list_by_domain, da_status` | `rpc/grpc/server/src/da.rs` (new) | 6.4 |
| `Capability::VerifyDataAvailability` | `svm/host/src/capabilities.rs` | 6.5 |
| `sophis_verify_da` linker symbol | `svm/host/src/da.rs` (new) | 6.5 |
| `DA_VERIFY_BASE = 2_000` gas | `svm/host/src/gas.rs` | 6.5 |
| `oracle/docs/PHASE6_RUNBOOK.md` | new | 6.6 |
| `devnet/test_phase6_da_attacks.py` | new | 6.7 |
| `oracle/fuzz/fuzz_targets/{v3_validator,reassembly,capability}.rs` | new | 6.7-6.9 |
| `oracle/docs/PHASE6_AUDIT.md` | new | 6.9 |
| `oracle/docs/PHASE6_RFC_RESPONSES.md` | new | 6.9 |

---

**End of sub-fase 6.0 design document.**

Next sub-fase: 6.1 — implement the V3 carrier consensus rules and the
constants table from §4 in `consensus/`.
