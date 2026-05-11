# J8 — Pruning Architecture Audit + ABI Freeze

> **Status:** audit + decisions frozen for sub-fase J8.0 — companion
> to the operator-facing `docs/PRUNING_POLICY.md` and `SIPS/SIP-8-PRUNING-POLICY.md`.
> **Originating roadmap:** Roadmap J item J8.
> **Pre-existing baseline:** **substantial.** Sophis already ships
> `--archival` CLI flag, `Config.is_archival` parameter, a 694-line
> `PruningProcessor`, multi-consensus management metadata that
> remembers archival status across restarts, RocksDB cache budgets
> tuned for HDD archival storage, and an existing 416-line
> `docs/archival.md` operator guide. J8 audits this baseline and
> formalises the policy + ABI surface that operators and explorers
> rely on.

## 1. Motivation

Pruning is the mechanism by which a node deletes block data older than
a network-defined depth, freeing disk space at the cost of historical
queryability. The trade-off has two natural answers — **pruned** (cheap
to run, can serve recent queries) and **archival** (resource-intensive,
serves all of history) — and Sophis ships both.

What was missing pre-J8:

- **No canonical operator-facing policy doc.** `docs/archival.md`
  covers the archival side; the pruned-side perspective ("what gets
  pruned, when, with what guarantees") was scattered across consensus
  source comments and a few CLI flag descriptions.
- **No RPC to inspect pruning state.** Operators and explorers had to
  read the daemon's startup logs or the consensus DB directly to
  answer "is this node archival? what's the current pruning point?
  how deep does it retain?" Even simple monitoring required SSH
  access.
- **No frozen ABI surface for the pruning_depth + finality_depth
  numbers** — they're in `Params` but were not formally part of the
  long-term operator contract.

J8 fills these three gaps. **No code is rewritten** — the pruning
machinery audit confirms the existing implementation is solid; the
deliverable is documentation + a small read-only RPC + an SIP that
formalises the operator-facing surface for the long term.

This is item #10 in the sequential roadmap. Originally estimated
"1-2 months, year 1-2 post-mainnet"; condensed to a single bundle
because the underlying machinery already exists and only the
documentation + RPC layer were missing.

## 2. Existing implementation map (audit findings)

### 2.1 Pruning depth + finality depth

| Item | Source | Value (mainnet, BPS=10) |
|------|--------|--------------------------|
| `Params::finality_depth()` | `consensus-core/src/config/bps.rs::finality_depth()` | `BPS × FINALITY_DURATION = 10 × 43_200 = 432 000` blocks (≈ 12 h) |
| `Params::pruning_depth()` | same file `pruning_depth()` | derived from finality_depth + merge_depth_bound + ghostdag-k-driven margin; computed as `finality_depth + merge_depth_bound × 2 + 4 × mergeset_size_limit × ghostdag_k + 2 × ghostdag_k + 2`, clamped to at least `BPS × PRUNING_DURATION` |
| `MERGE_DEPTH_DURATION` | `consensus-core/src/config/constants.rs:81` | 3600 s (1 h) — sets merge_depth_bound = `BPS × 3600` |
| `FINALITY_DURATION` | same file `:70` | 43_200 s (12 h) |
| `PRUNING_DURATION` | same file | (lower bound; actual `pruning_depth` typically dominated by safety margin formula) |

Operators and explorers MUST treat the formula above as **frozen ABI**
for any consensus-relevant computation. Changes to BPS, finality
duration, or the safety-margin formula require a hard fork.

### 2.2 Archival mode lifecycle

`--archival` CLI flag (sophisd/src/args.rs:71) maps directly to
`Config.is_archival` (consensus-core/src/config/mod.rs:36). The
`MultiConsensusManagementStore` (consensus/src/consensus/factory.rs:206)
persists archival status across restarts, so a node started once with
`--archival` remembers it. Daemon (sophisd/src/daemon.rs:543) prompts
for confirmation before allowing a transition from archival → pruned
because it would delete archived data.

### 2.3 Pruning processor

`consensus/src/pipeline/pruning_processor/processor.rs` (694 lines)
implements:
- `prune(new_pruning_point, retention_period_root)` — main entry point
- `confirm_pruning_depth_below_virtual` — refuses to prune if pruning
  point is not yet `pruning_depth` blocks below virtual
- Idempotent re-pruning on restart
- Atomic batch of deletions per pruning step (no half-pruned state)

In archival mode (`is_archival = true`), the processor performs all
the bookkeeping but skips actual block-data deletion — the management
store still updates the pruning point so the rest of consensus
maintains the same notion of "what's beyond the pruning point". This
makes archival nodes a strict superset of pruned nodes: the same
chain state, plus historical block bodies + UTXO diffs + acceptance
data.

### 2.4 Storage budgets

`consensus/src/consensus/storage.rs` (the K2 + L1 + Phase 6 +
existing) sets RocksDB cache budgets per-store with `RamScale` factor.
HDD archival nodes should use `--rocksdb-preset=hdd` per
`docs/archival.md`. The budgets are not part of the J8 frozen ABI
because they are operational tuning, not a wire-format commitment.

### 2.5 What J8 adds

| Artefact | Purpose |
|----------|---------|
| `docs/PRUNING_POLICY.md` (new) | Operator-facing policy doc. Pairs with the existing `docs/archival.md`. Covers retention guarantees, pruning lifecycle, monitoring, disaster recovery. |
| `getPruningInfo` RPC (new, `RpcApiOps::GetPruningInfo = 162`) | Read-only inspection of `pruning_depth`, `finality_depth`, current `pruning_point`, `pruning_point_blue_score`, and `is_archival`. Across all 3 transports. |
| `SIPS/SIP-8-PRUNING-POLICY.md` (new stub) | Standards-track formalisation of the policy + ABI surface. |

## 3. Ratified design decisions

These decisions were committed by the founder on 2026-05-11 and are
frozen for the J8 deliverable. Re-opening any of them requires a
new SIP.

| ID | Question | Choice | Rationale |
|----|----------|--------|-----------|
| **D1** | Pruning depth formula | `Params::pruning_depth()` as currently computed (finality + merge_depth × 2 + ghostdag-k driven margin, clamped to `BPS × PRUNING_DURATION`) | Already shipping; well-tested; matches the GHOSTDAG safety analysis cited in the source comment. Hard fork to change. |
| **D2** | Archival is operator opt-in (CLI flag), not network-wide | `--archival` as a per-node flag; consensus does not distinguish archival from pruned at the protocol layer | Standard design. The chain itself doesn't care; archival is purely a per-node retention policy. Lets operators choose without forking the network. |
| **D3** | Pruned-→-archival transition allowed; archival-→-pruned requires explicit confirmation | Already implemented (sophisd/src/daemon.rs:543) | Pruned → archival is harmless (just keeps more data going forward). Archival → pruned would delete archived data the operator may have promised consumers; the daemon's prompt prevents accidental data loss. |
| **D4** | Pruning is irreversible per node | Once a node prunes a block, that data is gone from local storage; resync is the only recovery | Industry standard. Restoring requires either a full resync from another node or explicitly switching to archival mode and restoring from a backup. The CLI prompt in D3 makes this explicit. |
| **D5** | `getPruningInfo` returns 5 fields: `pruning_depth`, `finality_depth`, `current_pruning_point`, `pruning_point_blue_score`, `is_archival` | All fields trivially computable from existing accessors; no new state | Minimum surface for monitoring + explorers. Future expansions (`pruning_point_daa_score`, `oldest_retained_block_hash`, `pruning_history`) are deferred until real demand surfaces. |
| **D6** | RPC is read-only | No `setArchival` or `setPruningDepth` RPC; archival mode + pruning depth are operator-controlled at startup, not at runtime | Mirrors the existing Operational Boundaries — equipe non-custodial, operators control their own nodes. Runtime mutation would expand the attack surface unnecessarily. |
| **D7** | Pruning-side data retention guarantees in `PRUNING_POLICY.md` are SLAs, not consensus rules | The doc states what pruned nodes MUST retain and MAY discard; consensus only enforces "you must keep at least up to your virtual pruning point" | Operators running pruned nodes commit to D7's retention contract via the documented policy; exceeding the contract (deeper retention) is fine. Falling short would surface as failed RPC queries — which is detectable but not consensus-fatal. |

## 4. Frozen ABI surface

| Item | Value |
|------|-------|
| `RpcApiOps::GetPruningInfo` | `162` |
| Method name (gRPC) | `GetPruningInfo` |
| Method name (wRPC JSON) | `getPruningInfo` |
| gRPC oneof slots | request `1136`, response `1137` |
| Response fields | `pruning_depth: u64`, `finality_depth: u64`, `current_pruning_point: RpcHash`, `pruning_point_blue_score: u64`, `is_archival: bool` |
| Doc paths | `docs/PRUNING_POLICY.md` (operator), `docs/archival.md` (existing archival operator guide), `docs/J8_PRUNING_AUDIT.md` (this doc) |
| SIP path | `SIPS/SIP-8-PRUNING-POLICY.md` |

## 5. Out-of-scope (for J8)

- **Pruning depth tuning per network** — `pruning_depth()` is fixed
  per BPS at code level. Per-network override (e.g. testnet shallower
  for fast resyncs) deferred to a future SIP.
- **State pruning** (UTXO snapshot pruning beyond what the existing
  PruningProcessor does) — current implementation prunes block data;
  full state-history pruning is a separate axis not covered here.
- **`setArchival` / `setPruningDepth` runtime RPC** — D6.
- **Archival distribution** (light-client sync, DA bridges, IPFS-style
  distribution of pruned data) — separate ecosystem concern, not core.
- **Per-store retention overrides** — operators can already tune
  RocksDB cache budgets via `--ram-scale` and `--rocksdb-preset`;
  per-prefix retention overrides would be operational complexity
  without a clear use case.

## 6. Reference implementation map

| Sub-fase | Scope |
|---------|-------|
| J8.0 | This audit document + operator-facing `docs/PRUNING_POLICY.md` |
| J8.1 | `rpc-core::model::pruning_info` types + `RpcApiOps::GetPruningInfo = 162` + `RpcApi::get_pruning_info` trait + service impl + 2 mock stubs + gRPC binding (proto + ops + conversions + route + factory) + wRPC binding (server router + client macro) + integration test |
| J8.2 | `SIPS/SIP-8-PRUNING-POLICY.md` stub + `SIPS/README.md` index update |
| J8.3 | Workspace check + clippy strict + single commit |

## 7. Glossary

| Term | Meaning |
|------|---------|
| Pruning | Deletion of block data older than `pruning_depth` blocks below the virtual selected tip. Reclaims disk space; sacrifices ability to serve historical queries. |
| Pruning point | The deepest block whose data the node is committed to retaining. Computed per the safety-margin formula in `Params::pruning_depth()`; advances forward as the chain advances. |
| Archival mode | Per-node opt-in via `--archival`. Skips the deletion step; node retains all historical block data. |
| Pruned mode | Default. Node deletes block data below the pruning point. |
| Retention period | Synonym for `pruning_depth` from the operator's POV: "how deep we keep". |
| Finality depth | `Params::finality_depth() = 432 000 blocks` at mainnet BPS — the depth at which a block is considered consensus-final (per L3 commitment levels). Distinct from pruning depth, which is deeper for safety margin. |
