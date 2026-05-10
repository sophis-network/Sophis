# J4 — sVM Event Logs (Standardized Emission + Filterable RPC)

> **Status:** design frozen for sub-fase J4.0 — ready for J4.1 implementation.
> **Originating roadmap:** Roadmap J (Ethereum lessons), item J4.
> **Companion docs:** future `docs/J4_RUNBOOK.md` (operator + indexer guide,
> sub-fase J4.6) and `SIPS/SIP-4-EVENTS.md` (also J4.6).
> **Pre-existing baseline:** **none**. The Sophis sVM ships today with
> zero event/log infrastructure (verified 2026-05-10 via grep across
> `svm/`). J4 adds it from scratch.

## 1. Motivation

Every production smart-contract platform exposes a way for contracts to
emit *events* — small structured records that get persisted alongside
the transaction and become queryable by indexers, wallets, and
explorers. Ethereum has `LOG0..LOG4` opcodes + `eth_getLogs`. Solana
has `program logs` + Helius/Triton RPCs. Cosmos has `abci.event`.
Sophis has nothing.

Without events:

- **Indexers cannot reconstruct contract state without re-executing every
  transaction.** Subgraph-style services have to maintain their own
  full-node infrastructure, raising the integrator cost from "consume an
  RPC" to "run a node". This is a structural barrier to ecosystem.
- **Wallets cannot show "what happened" in a transaction.** The user
  signs a tx, sees `accepted`, and that's it — no "you received 1 SPHS
  from sophis:qx…" notification. Every wallet has to invent its own
  ad-hoc parsing.
- **dApps cannot react to chain state changes** without polling
  `getUtxos*` constantly. Polling is wasteful and racy; subscription
  to filtered events is the standard pattern.

J4 solves the *structural* problem (emit + persist + filter via RPC).
The dApp / wallet / indexer ergonomics layered on top — ABI decoding,
WebSocket subscription, helper SDK — are deliberately out of scope for
J4 (see §9). Third-parties build those.

This is a P1 deliverable per the original Roadmap J priorities and
unblocks the entire indexer ecosystem story documented in
`project_ethereum_lessons.md`.

## 2. Ratified design decisions

These decisions were committed by the founder on 2026-05-10 and are
frozen for the J4 implementation. Re-opening any of them requires a
new SIP.

| ID | Question | Choice | Rationale |
|----|----------|--------|-----------|
| **D1** | Topic format | `[u8; 32]` fixed (Ethereum-style) | Predictable storage; fixed-size index keys; aligns with the standard hash-of-event-signature pattern (`SHA3-384(signature)[..32]`). Variable-length topics complicate every index without a real use case in v1. |
| **D2** | Topics per event | Up to 4 (Ethereum-style: 0..=4) | The 0–4 range covers ~99% of observed Ethereum patterns: typically `topic[0]` = event signature hash and 0–3 indexed parameters. Fixed-cardinality keeps the storage layout simple. The on-wire encoding uses `u8` count + that many topics, so empty-topic events (just data, no filter keys) are a single byte cheaper than fixed-4. |
| **D3** | Storage indexes | Both per-block AND per-tx (plus per-contract + per-topic) | Indexers want both block-anchored and tx-anchored queries (D3=C of the original menu). Disk overhead is negligible vs query flexibility — indexers cannot perform efficient cross-cuts otherwise. Total = 4 RocksDB prefixes. |
| **D4** | Event data size cap | 4 096 bytes (= `MAX_ALT_ENTRY_SCRIPT_BYTES`) | Consistent footprint with the L1 ALT module so operators only have one number to remember for "how big can a single sVM-side payload be". 4 KB is large enough for routine events (typed-data signatures, NFT metadata refs) without enabling free DA via event spam. |
| **D5** | RPC method shape | Unified `getLogs(filter)` (Ethereum `eth_getLogs`) | Indexers, ABI decoders, and explorer software already speak this filter shape. Multiple specific endpoints (`getLogsByContract`, `getLogsByBlock`, ...) would be slightly faster but force every consumer to learn a Sophis-specific API. The unified filter walks the most-selective index server-side. |

### D1 — note on `SHA3-384` vs Ethereum's keccak256

Ethereum hashes event signatures with keccak256 (32-byte output). Sophis's
canonical hash is SHA3-384 (48-byte output). For topic[0] we follow the
Sophis convention: `topic[0] = SHA3-384(event_signature)[..32]`. The
truncation is documented in §3.5 and reflected in the SDK helpers.

## 3. Wire format

### 3.1 The `EventLog` record

Persisted form, written by the consensus layer at `commit_utxo_state`
time:

```text
EventLog {
    contract_id:  [u8; 32],   // emitting sVM contract id
    topic_count:  u8,         // 0..=4 (rule 4)
    topics:       Vec<[u8; 32]>,  // length == topic_count
    data:         Vec<u8>,    // 0..=4096 bytes (rule 5)
    block_hash:   [u8; 32],   // chain-block that accepted the tx
    tx_id:        [u8; 32],   // accepting tx
    tx_index:     u32,        // index_within_block of the tx
    log_index:    u32,        // ordinal of this event within the tx
    daa_score:    u64,        // creating block's DAA
}
```

Borsh-serialized. Total fixed overhead = 32 + 1 + 32 + 32 + 4 + 4 + 8 = **113 bytes per event** before topics and data.

### 3.2 sVM-side encoding (the wire format the contract uses)

The host function `sophis_emit_event` reads from contract linear memory
the following packed layout:

```text
   topic_count: u8       (must be 0..=4)
   topics:      [u8; 32 * topic_count]
   data_len:    u32 LE   (must be ≤ MAX_EVENT_DATA_BYTES)
   data:        [u8; data_len]
```

Total encoded size in linear memory: `1 + 32*topic_count + 4 + data_len`.

The contract is responsible for laying this out at `out_ptr`; the host
reads exactly `1 + 32*N + 4 + D` bytes where `N` and `D` are derived
from the leading bytes.

### 3.3 Magic / framing

Unlike L1 ALT and Phase 6 DA, **events do not appear on-wire in
transactions**. They are pure execution side effects, so there is no
magic prefix or discriminator byte to allocate. Storage is
consensus-internal only.

Equivalently: events are not first-class transaction outputs (no
`SCRIPT_VERSION_*` bump). The transaction body is unchanged; events
appear *only* in the indexed RocksDB stores.

## 4. On-chain layout

### 4.1 RocksDB stores

A new module `consensus/src/model/stores/events.rs` introduces
`DbEventStore` with **four prefixes**, allocated immediately after the
L1 ALT range:

| Prefix | Constant | Key | Value | Use case |
|--------|----------|-----|-------|----------|
| 203 | `EventsByBlock` | `block_hash` | `Vec<EventLog>` ordered by `(tx_index, log_index)` | "give me every event in block H" |
| 204 | `EventsByTx` | `tx_id` | `Vec<EventLog>` ordered by `log_index` | "give me every event the tx X emitted" |
| 205 | `EventsByContract` | `(contract_id, daa_score_bucket)` | `Vec<(block_hash, log_index)>` | "give me every event ever emitted by contract C" (paginated by DAA) |
| 206 | `EventsByTopic` | `(topic_0, daa_score_bucket)` | `Vec<(block_hash, log_index)>` | "give me every event whose topic[0] equals T" |

**Bucketing:** `EventsByContract` and `EventsByTopic` partition by a
DAA-score bucket of 65 536 (matching Phase 6 `DOMAIN_BUCKET_SIZE`) so
single-key reads stay bounded. The RPC method walks adjacent buckets
sequentially when the requested block range spans them.

**Why no per-`(contract, topic)` joint index?** A naïve cross product
would balloon the index space. Filters that combine both contract and
topic walk whichever index is more selective and post-filter the
remainder; this matches the Ethereum reference implementation.

### 4.2 Commit hook

Events are populated inside the existing `commit_utxo_state` write
batch — same atomic boundary as Phase 6 DA carriers and L1 ALT
creations:

1. For each accepted block, walk `acceptance_data.iter()` for accepted
   transactions.
2. For each tx, ask the sVM execution context (cached during validation)
   for the `Vec<EventLog>` it emitted, if any.
3. Write into all 4 indexes within the same `WriteBatch`.

If indexing fails, the chain advances anyway (non-fatal, mirroring DA);
operator log surfaces the error.

### 4.3 In-memory cache

A small `LruCache<TxId, Arc<Vec<EventLog>>>` (default 4 096 entries)
sits in front of `EventsByTx`. Most consumer queries are recent-tx
lookups; the cache absorbs the long tail.

`EventsByContract` and `EventsByTopic` reads always go to disk; their
result sets can be unboundedly large and caching them would invite
memory pressure.

### 4.4 Pruning interaction

Events follow the same lifecycle as the chain block that emitted them:

- `EventsByBlock` and `EventsByTx` rows are **pruned with the block**
  (consistent with `block_transactions_store`).
- `EventsByContract` and `EventsByTopic` are **archival** (never pruned)
  so historical filter queries against pre-pruning blocks remain
  answerable. The size impact is tiny: per-event auxiliary index entries
  are ~36 bytes each.

## 5. Validation rules

Enforced inside the sVM host function and the consensus commit path
(no transaction-validator changes — events are runtime side effects,
not tx-body content).

### Rules at emission time (`sophis_emit_event` host fn)

| #  | Rule | Error code |
|----|------|------------|
| 1  | Capability `Capability::EmitEvent` must be declared in the manifest | `-1` (capability not granted) |
| 2  | Gas cost `GAS_EVENT_EMIT_BASE + data_len * GAS_EVENT_EMIT_PER_BYTE` available | `-2` (gas exhausted) |
| 3  | `topic_count` MUST be in `[0, MAX_TOPICS_PER_EVENT = 4]` | `-3` (topic count out of range) |
| 4  | `data_len` MUST be ≤ `MAX_EVENT_DATA_BYTES = 4096` | `-4` (data too large) |
| 5  | Memory read at `(out_ptr, total_len)` must be in-bounds | `-5` (memory read out of bounds) |
| 6  | Per-tx event cap: ≤ `MAX_EVENTS_PER_TX = 32` | `-6` (per-tx cap exceeded) |

### Rules at commit time

| #  | Rule | Error |
|----|------|-------|
| 7  | Per-block event cap across all txs: ≤ `MAX_EVENTS_PER_BLOCK = 1024` | `EventBlockCapExceeded` (logged, indexing skipped for the overflow; tx still accepted because the cap is conservative and the contract emitted within its own per-tx budget) |
| 8  | Coinbase txs MUST NOT emit events (sVM never executes inside coinbase) | structurally impossible; defended via assertion |

### Determinism

Event emission is **deterministic at consensus time**: every full node
executing the same transaction inputs against the same contract bytecode
produces the same `Vec<EventLog>` (sVM is deterministic). The commit
hook therefore writes identical bytes across all nodes — events cannot
fork.

## 6. Gas / mass model

Events are sVM execution side effects, so they cost gas (not
transaction mass). Two new constants in `sophis_svm_core::gas`:

```rust
pub const GAS_EVENT_EMIT_BASE: u64 = 1_000;     // per emit call
pub const GAS_EVENT_EMIT_PER_BYTE: u64 = 8;     // for data section
```

With `MAX_EVENT_DATA_BYTES = 4096` the worst-case per-emit gas is
`1000 + 4096*8 = 33_768` gas. Combined with `MAX_EVENTS_PER_TX = 32`,
the absolute per-tx ceiling on event-related gas is ~1.08 M gas — well
within the default `max_gas_per_tx = 10_000_000`.

There is **no mass surcharge** for events. They do not appear on the
wire (§3.3), and the gas already pays for the storage write at the
storage layer (1 mass per byte stored, mirroring the existing
`STORAGE_MASS_PARAMETER` shape).

## 7. RPC API

A new method on the `RpcApi` trait exposed by `sophis_rpc_core`:

```rust
async fn get_logs(&self, filter: GetLogsRequest) -> RpcResult<GetLogsResponse> {
    self.get_logs_call(None, filter).await
}
async fn get_logs_call(&self, connection: Option<&DynRpcConnection>, request: GetLogsRequest) -> RpcResult<GetLogsResponse>;
```

### 7.1 Request

```rust
pub struct GetLogsRequest {
    pub contract_id:  Option<[u8; 32]>,           // filter by emitting contract
    pub topics:       Vec<Option<[u8; 32]>>,      // up to 4; None = wildcard
    pub from_block:   Option<RpcHash>,            // inclusive lower bound
    pub to_block:     Option<RpcHash>,            // inclusive upper bound
    pub limit:        Option<u32>,                // server caps at 1000
}
```

Semantics:

- All filter fields are AND-combined.
- `topics` is positional: `topics[0] = Some(t)` means "topic[0] equals t";
  `topics[0] = None` is a wildcard. An empty `topics` vector matches any
  topic configuration.
- `from_block` / `to_block` use chain-block hashes (matching the Phase 6
  DA convention). Operators can resolve hash from height via the existing
  `getBlocks` walk.
- `limit` is server-capped at `MAX_LOGS_PER_RESPONSE = 1000` to bound
  memory; clients paginate by sliding `from_block`.

### 7.2 Response

```rust
pub struct GetLogsResponse {
    pub logs: Vec<RpcEventLog>,
}

pub struct RpcEventLog {
    pub contract_id:  [u8; 32],
    pub topics:       Vec<[u8; 32]>,
    pub data:         Vec<u8>,
    pub block_hash:   RpcHash,
    pub tx_id:        RpcHash,
    pub tx_index:     u32,
    pub log_index:    u32,
    pub daa_score:    u64,
}
```

### 7.3 Server-side query strategy

Pseudo-code for the resolver in `RpcCoreService::get_logs_call`:

```text
1. Determine the most selective index:
     if topics[0] is Some            → walk EventsByTopic
     elif contract_id is Some        → walk EventsByContract
     else if (from_block, to_block) provided  → walk EventsByBlock
     else                            → reject (must specify at least one filter axis)

2. For each candidate (block_hash, log_index) from the chosen index:
     load EventLog from EventsByTx (or EventsByBlock)
     check the AND of remaining filter axes
     emit if matches

3. Truncate at min(client_limit, MAX_LOGS_PER_RESPONSE).
```

This keeps the server-side cost tied to the *selectivity* of the
filter, not to the cardinality of the chain.

## 8. Threat model

### 8.1 In scope

| # | Threat | Mitigation |
|---|--------|------------|
| T1 | DoS via event spam (one contract emits many events) | Per-tx cap (32) + per-block cap (1024) + gas cost (1000 base + 8/byte). Sustained spam costs the spammer at the gas market price; consensus throughput unaffected. |
| T2 | Storage bloat | Auxiliary indexes are per-event small (~36 B); main payload stored once in `EventsByTx` (pruned with block) and `EventsByBlock` (also pruned). Archival indexes (`EventsByContract`, `EventsByTopic`) carry only `(block_hash, log_index)` pointers. Worst-case yearly growth at full block saturation: ~50 GB on the auxiliary indexes alone (1024 events/block × 10 BPS × 36 B × 86400 × 365 ≈ 11.6 TB raw payload, ~50 GB indexes), well bounded. |
| T3 | Wrong-block-hash injection | Event records are written by consensus, not contracts. Contracts can write whatever bytes they want into `data` and `topics` but cannot forge `block_hash` / `tx_id` / `daa_score` — those are filled by the commit hook from chain state. |
| T4 | Privacy leak via topic dictionary attack | All events are public (Sophis is transparency-by-default). Wallets that don't want their patterns indexed should not emit identifiable topics. |
| T5 | Unbounded `getLogs` response | `MAX_LOGS_PER_RESPONSE = 1000`, server enforced regardless of client `limit`. Clients paginate. |
| T6 | Determinism failure | sVM is deterministic; events derive from sVM execution; therefore identical across nodes. No race condition. |

### 8.2 Out of scope

| # | Non-threat | Why excluded |
|---|------------|--------------|
| N1 | Event tampering by node operators | Events are part of the consensus state; tampering produces a fork detectable by every honest node. Standard Sophis safety. |
| N2 | Cross-chain event forwarding | Decision 4: bridges out-of-scope for the core team. |
| N3 | Authentication of who-emitted-what | Topic[0] convention is "hash of event signature" but not enforced. Contract authors can put whatever they like in topics. ABI-level authenticity is the caller's contract; not consensus. |
| N4 | Live event streaming via WebSocket | Deferred (§9). Pull-only `getLogs` in v1. |

## 9. Out-of-scope (for J4)

The following are deliberately deferred:

- **WebSocket subscriptions** (`subscribeLogs(filter)`) — pull-only in
  v1; push semantics deferred to a future SIP. dApps polling
  `getLogs(from_block=last_seen)` is the recommended pattern.
- **ABI decoding helpers in the SDK** — third-party tooling can decode
  `data` bytes per their own ABI conventions. Sophis does not bless
  any specific encoding.
- **Indexer service / TheGraph-equivalent** — third-party builders.
- **Event emission from native subnetwork transactions** — only sVM
  contracts can emit. Tokens (Native Tokens L1) and Phase 3 ZK-Rollup
  bridges are silent at the event layer in v1.
- **`getBlockReceipts`-style aggregated query** — derivable from
  `EventsByBlock`; no separate endpoint added.
- **Backfill of historical events** — events only exist for blocks
  accepted *after* J4 ships. Pre-J4 chain history has no events to
  backfill (sVM didn't emit any).

## 10. Activation summary

J4 is gated by the `Capability::EmitEvent` declaration in a contract's
`ContractManifest`. Existing contracts deployed before J4 ships *cannot*
emit events (the capability didn't exist when they were deployed); they
can still upgrade via their `UpgradePolicy` to redeclare with the new
capability.

There is **no consensus rule change** (no fork, no `MAX_TX_VERSION` bump).
Activation = "merge the J4.x commits, redeploy nodes". Old nodes that
have not been upgraded will:

- Accept v=1 contracts that declare `Capability::EmitEvent` (the
  manifest is opaque to them).
- Reject the contract at *first call* if the contract calls
  `sophis_emit_event` (host function unknown), causing a `WasmTrap`.

This is the same activation pattern as L1.4 (`Capability::ResolveAlt`).

## 11. Constants summary

| Constant | Value | File |
|----------|-------|------|
| `Capability::EmitEvent` | new variant | `svm/core/src/capability.rs` |
| `MAX_TOPICS_PER_EVENT` | 4 | `consensus/core/src/events/mod.rs` |
| `MAX_EVENT_DATA_BYTES` | 4 096 | same |
| `MAX_EVENTS_PER_TX` | 32 | same |
| `MAX_EVENTS_PER_BLOCK` | 1 024 | same |
| `MAX_LOGS_PER_RESPONSE` | 1 000 | `consensus/core/src/events/mod.rs` |
| `EVENTS_BY_CONTRACT_BUCKET_SIZE` | 65 536 (DAA score units) | same |
| `GAS_EVENT_EMIT_BASE` | 1 000 | `svm/core/src/gas.rs` |
| `GAS_EVENT_EMIT_PER_BYTE` | 8 | same |
| `DatabaseStorePrefixes::EventsByBlock` | 203 | `database/src/registry.rs` |
| `DatabaseStorePrefixes::EventsByTx` | 204 | same |
| `DatabaseStorePrefixes::EventsByContract` | 205 | same |
| `DatabaseStorePrefixes::EventsByTopic` | 206 | same |

## 12. Glossary

| Term | Meaning |
|------|---------|
| Event | A structured side effect emitted by a sVM contract during execution. Persisted in 4 RocksDB indexes; queryable via `getLogs`. |
| Topic | A 32-byte indexed key attached to an event. Convention: `topic[0]` = `SHA3-384(event_signature)[..32]`; topics 1..3 = indexed parameters. |
| Data | Free-form bytes in the event payload, capped at 4 096 bytes. ABI-decoded by callers, not by consensus. |
| Log | Synonym for event in Ethereum-style terminology; used interchangeably in the RPC API (`getLogs`). |
| Filter | The combined `(contract_id, topics, from_block, to_block, limit)` predicate passed to `getLogs`. |
| Bucket | A DAA-score range (`bucket_size = 65 536`) used to partition the archival indexes (`EventsByContract`, `EventsByTopic`) for bounded single-key reads. |

## 13. Document history

| Date       | Change |
|------------|--------|
| 2026-05-10 | Initial design (sub-fase J4.0). Decisions D1–D5 ratified. |
