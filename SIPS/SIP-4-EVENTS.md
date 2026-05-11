```
SIP: 4
Title: sVM Event Logs (Standardised Emission + Filterable RPC)
Author: Marcelo Delgado <sophis-network@proton.me>
Status: Draft
Type: Standards
Created: 2026-05-10
Requires: 0
```

# SIP-4: sVM Event Logs

> **Status note:** this document is the *stub* that accompanies the J4
> reference implementation merged in commits `504faeb`..`f700c85` (8
> commits, ~2 400 LOC + ~78 tests). The full SIP body is intentionally
> deferred until after at least 30 days of testnet usage with non-trivial
> event-emit workloads, so the Rationale and Security Considerations
> sections can cite real measurements rather than projections. SIP-0 §6
> ("Standards Track") permits this two-phase pattern: a *stub* anchors
> the proposal in the SIP series and freezes the wire format and
> decision IDs; the *full body* lands when measurements support it.

## 1. Abstract

Sophis sVM contracts have, until now, had no way to emit structured
side-effect records. Indexers had to re-execute every transaction to
reconstruct contract state; wallets could not show "what happened" in a
transaction beyond `accepted`/`rejected`; dApps had to poll
`getUtxos*` to react to chain state changes. SIP-4 introduces **sVM
Event Logs**: an Ethereum-`LOG0..LOG4`-equivalent emit primitive
(`Capability::EmitEvent` + `sophis_emit_event` host fn), four RocksDB
indexes (`EventsByBlock`, `EventsByTx`, `EventsByContract`,
`EventsByTopic`), and a unified `getLogs(filter)` RPC method available
on all three Sophis transports (in-process, gRPC, wRPC JSON).

Events are **pure execution side effects**: they do not appear on the
transaction wire format and do not affect transaction validity beyond
the per-emit gas they burn. The four indexes ride atomically with each
chain-block commit; failures are non-fatal.

J4 is gated on `Capability::EmitEvent` per-contract and activated at
genesis on every Sophis network.

## 2. Motivation

See `docs/J4_EVENTS_DESIGN.md` §1 for the canonical motivation: the
absence of any event/log infrastructure in Sophis pre-J4, the
structural cost imposed on indexers (forced to run full nodes), the UX
cost imposed on wallets (forced to invent ad-hoc parsing), and the
ecosystem cost imposed on dApps (forced to poll instead of subscribe).

J4 is a P1 deliverable from Roadmap J ("Ethereum lessons") and unblocks
the entire indexer ecosystem story documented in
`project_ethereum_lessons.md`.

## 3. Specification

The technically complete specification is published at
`docs/J4_EVENTS_DESIGN.md` in the reference implementation tree
(`sophis-network/Sophis@f700c85` and forward). It enumerates:

- 8 numbered consensus rules (§5)
- Wire format with byte-level layout (§3)
- On-chain RocksDB layout and prefix allocation 203..206 (§4)
- Gas model (§6) — `GAS_EVENT_EMIT_BASE = 1000` + `GAS_EVENT_EMIT_PER_BYTE = 8`
- RPC API spec — `getLogs(filter)` shape and server-side query strategy (§7)
- Threat model with 6 in-scope and 4 out-of-scope items (§8)
- 5 ratified design decisions (D1–D5, §2)

This SIP body will be re-issued in **Review** once testnet measurements
are available; readers should treat the DESIGN doc as the authoritative
specification until that re-issue.

## 4. Frozen ABI surface

The following constants and identifiers are **frozen** as of commit
`f700c85`. Any change requires a hard fork.

### 4.1 Capability + opcodes

| Item | Value | Source |
|------|-------|--------|
| `Capability::EmitEvent` | enum variant (no on-wire opcode) | `svm/core/src/capability.rs` |
| `RpcApiOps::GetLogs` | `157` | `rpc/core/src/api/ops.rs` |
| Host fn name | `sophis_emit_event` | `svm/runtime/src/host.rs` |
| Host fn signature | `(payload_ptr: i32, payload_len: i32) -> i32` | same |

### 4.2 Numerical constants

| Constant | Value | Source |
|----------|-------|--------|
| `MAX_TOPICS_PER_EVENT` | `4` | `consensus-core::events`, `svm-core::events` |
| `TOPIC_LEN` | `32` | same |
| `MAX_EVENT_DATA_BYTES` | `4_096` | same |
| `MAX_EVENTS_PER_TX` | `32` | same |
| `MAX_EVENTS_PER_BLOCK` | `1_024` | `consensus-core::events` |
| `MAX_LOGS_PER_RESPONSE` | `1_000` | `consensus-core::events`, `rpc-core::model::events` |
| `EVENTS_BY_CONTRACT_BUCKET_SIZE` | `65_536` | `consensus-core::events` |
| `GAS_EVENT_EMIT_BASE` | `1_000` | `svm-core::gas` |
| `GAS_EVENT_EMIT_PER_BYTE` | `8` | same |

### 4.3 RocksDB prefixes

| Prefix | Constant |
|--------|----------|
| 203 | `EventsByBlock` |
| 204 | `EventsByTx` |
| 205 | `EventsByContract` |
| 206 | `EventsByTopic` |

### 4.4 gRPC oneof slots

| Slot | Message |
|------|---------|
| 1126 | `GetLogsRequestMessage` |
| 1127 | `GetLogsResponseMessage` |

### 4.5 Host-fn status codes

| Status | Meaning |
|--------|---------|
| 0 | Success |
| -1 | `Capability::EmitEvent` missing from manifest |
| -2 | Per-tx gas budget exhausted |
| -3 | `topic_count > MAX_TOPICS_PER_EVENT` |
| -4 | `data_len > MAX_EVENT_DATA_BYTES` |
| -5 | OOB memory read OR structural payload error (truncated / length mismatch / negative len) |
| -6 | Per-tx event cap (`MAX_EVENTS_PER_TX = 32`) reached |

## 5. Rationale

Deferred to the full SIP body. The DESIGN doc §2 already enumerates the
five ratified decisions (D1–D5) and their rationales; what changes in the
full SIP is the addition of empirical numbers (event-emission frequency
per contract, average payload size, getLogs response-size distribution
from devnet/testnet runs) to justify the conservative defaults.

The most likely points of testnet-driven revision are:

- D2 — extending positional topics from 4 to 8 (defaulted to "no" per
  Ethereum-pattern alignment; may be revisited if dApps show genuine
  demand for additional indexed parameters)
- D4 — `MAX_EVENT_DATA_BYTES` calibration (currently 4 096; could move
  up if NFT metadata / typed-data signatures dominate measurements, or
  down if events spam dominates)
- D5 — adding **WebSocket subscription** as a complement to pull-based
  `getLogs` (deferred per DESIGN §9; tracked as a separate future SIP)
- Gas calibration — `GAS_EVENT_EMIT_PER_BYTE` may need adjustment once
  RocksDB write-amplification is measured under load

## 6. Backwards Compatibility

**Activated at genesis.** Sophis has not launched mainnet, so there is
no soft-fork window. Contracts that do not declare
`Capability::EmitEvent` are entirely unaffected; the host fn returns
`-1` if a contract calls `sophis_emit_event` without the capability.

Wallets, indexers, and explorers that wish to consume events implement
the `getLogs` RPC client according to the type definitions published in
`rpc/core/src/model/events.rs`. They MAY ignore J4 entirely if their use
case has no need for event-driven UX.

## 7. Reference Implementation

Reference implementation: `sophis-network/Sophis` commits
`504faeb`..`f700c85` (8 commits over the J4.0–J4.5.c sub-fases, plus
J4.6 documentation):

| Commit | Sub-fase | Scope |
|--------|---------|-------|
| `504faeb` | J4.0 | Design document (`docs/J4_EVENTS_DESIGN.md`, ~399 lines) |
| `4457433` | J4.1 | Consensus types: `consensus/core/src/events/` (parser, codec, store_types) |
| `46e66b8` | J4.2 | RocksDB store: `consensus/src/model/stores/events.rs` (4 indexes, 10 tests) |
| `7a83072` | J4.3 | sVM `Capability::EmitEvent` + `sophis_emit_event` host fn (svm-core::events module + ExecutionContext.contract_id+events + SDK Env::emit_event + 26 tests) |
| `8165c38` | J4.4 | Consensus commit hook + `EventsCollector` DashMap + `index_events_in_block` (9 tests) |
| `aa10748` | J4.5.a | RPC `getLogs` trait + service impl + consensus accessor (6 round-trip tests) |
| `78553f4` | J4.5.b | gRPC binding (proto messages + ops + conversions + route + factory) |
| `f700c85` | J4.5.c | wRPC JSON binding (server router + macro list) |

Operational sub-fase J4.6 (this stub + RUNBOOK) closes the core team's
J4 deliverables.

## 8. Security Considerations

Comprehensive threat model in DESIGN §8. Highlights:

- **Determinism:** sVM execution is deterministic; events derive directly
  from sVM execution; therefore identical across nodes. No race condition.
- **Reorg safety:** events are re-derived from re-execution on a reorg
  replay. The validator's `EventsCollector` is overwritten on
  re-validation; the `index_events_in_block` commit hook drains it
  per-tx, so memory stays bounded. Archival indexes (205, 206) are never
  pruned, so historical filter queries against pre-pruning blocks remain
  answerable.
- **DoS:** capped via `MAX_EVENTS_PER_TX = 32`,
  `MAX_EVENTS_PER_BLOCK = 1024`, `MAX_EVENT_DATA_BYTES = 4096`, and
  per-emit gas (`base + per_byte * payload_len`). Per-block cap truncates
  trailing events with a `warn!` log; the accepted tx itself is never
  rejected for emit-overflow.
- **Wrong-block-hash forgery:** event records are written by consensus,
  not contracts. Contracts can write whatever bytes they want into
  `data` and `topics` but cannot forge `block_hash` / `tx_id` /
  `daa_score` — those are filled by the commit hook from chain state.
- **Privacy:** all events are public (Sophis is transparency-by-default).
  Wallets that don't want their patterns indexed should not emit
  identifiable topics. No on-chain mixing of any kind is in scope.
- **Unbounded RPC response:** server-enforced `MAX_LOGS_PER_RESPONSE =
  1000` regardless of client `limit` field. Whole-chain scans
  (no filter axis specified) rejected by the service layer.
- **PQC:** J4 introduces no new cryptographic primitive. `topic[0]`
  convention uses SHA3-384 (Sophis's existing hash) truncated to 32
  bytes. PQC posture preserved.

## 9. Test Vectors

Canonical vectors live with the reference implementation in:

- `consensus/core/src/events/codec.rs` (`tests` module) — emission
  payload codec round-trip + structural rejection
- `consensus/core/src/events/mod.rs` (`tests` module) — constants
  consistency + error display
- `consensus/core/src/events/store_types.rs` (`tests` module) — borsh
  round-trip for `EventLog`, `EventTopic`, `EventLogPointer`
- `consensus/src/model/stores/events.rs` (`tests` module) — full
  RocksDB index lifecycle including pruning behaviour
- `consensus/src/pipeline/virtual_processor/processor.rs`
  (`j4_index_events_tests` module) — commit-hook drain semantics +
  per-block cap + multi-tx ordering
- `svm/core/src/events.rs` (`tests` module) — parser + encoder
  round-trip + size-cap rejection
- `svm/runtime/tests/emit_event_host_fn.rs` — end-to-end WAT contracts
  exercising every host-fn status code + gas metering + contract_id
  propagation
- `rpc/core/src/model/events.rs` (`tests` module) — workflow_serializer
  round-trip for `RpcEventLog`, `GetLogsRequest`, `GetLogsResponse`
- `testing/integration/src/rpc_tests.rs` — gRPC round-trip integration
  test for the `GetLogs` payload op

The wire format is frozen as of `4457433` (consensus types), `7a83072`
(host-fn ABI), and `aa10748` (RPC types).

## 10. References

- Ethereum `eth_getLogs` JSON-RPC method — original conceptual ancestor
  for the filter shape; Solana `program logs` and Cosmos `abci.event`
  are nearer alternatives but Sophis chose the Ethereum filter for
  indexer-tooling compatibility (decision D5)
- `docs/J4_EVENTS_DESIGN.md` — authoritative wire-format spec
- `docs/J4_RUNBOOK.md` — operator + indexer + contract-developer guide
- `project_ethereum_lessons.md` — strategic context for Roadmap J
- `SIPS/SIP-3-ALT.md` — sibling SIP (L1 ALT); shares the
  "stub + design doc + later full body" pattern

## 11. Copyright

This SIP is released into the public domain (CC0).
