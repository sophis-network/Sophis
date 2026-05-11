```
SIP: 8
Title: Pruning Policy + getPruningInfo RPC
Author: Marcelo Delgado <sophis-network@proton.me>
Status: Draft
Type: Standards
Created: 2026-05-11
Requires: 0
```

# SIP-8: Pruning Policy + getPruningInfo RPC

> **Status note:** this document is the *stub* that accompanies the J8
> reference implementation merged in commit `<TBD>` (single commit,
> ~1 200 LOC docs + ~150 LOC code + 3 unit tests). The full SIP body
> is intentionally deferred until at least 30 days of operator usage
> with non-trivial archival deployments. Same two-phase pattern as
> SIP-1, SIP-3, SIP-4, SIP-7.

## 1. Abstract

Sophis already ships pruning + archival mode at the implementation
layer (`PruningProcessor` consensus pipeline, `--archival` CLI flag,
`Config.is_archival`, multi-consensus management metadata). What was
missing was (a) a canonical operator-facing policy doc covering the
pruned-side perspective, (b) a read-only RPC for monitoring + explorer
inspection of pruning state, and (c) an SIP formalising the policy +
RPC ABI surface for the long term.

SIP-8 adds all three:

* `docs/J8_PRUNING_AUDIT.md` — audit findings + 7 ratified decisions +
  frozen ABI.
* `docs/PRUNING_POLICY.md` — operator-facing SLA: what pruned nodes
  retain, what they discard, RPC behaviour for pruned-block queries,
  disaster recovery.
* `getPruningInfo` RPC (`RpcApiOps::GetPruningInfo = 162`): 5 fields
  (`pruning_depth`, `finality_depth`, `current_pruning_point`,
  `pruning_point_blue_score`, `is_archival`).

J8 introduces **no new cryptographic primitive, no new on-chain state,
no consensus rule changes.** The RPC is read-only by design (D6); all
underlying machinery already exists.

## 2. Motivation

See `docs/J8_PRUNING_AUDIT.md` §1 for the canonical motivation: the
existing implementation is solid but operator-facing documentation +
monitoring RPC were missing. SIP-8 closes the loop.

J8 is item #10 in the sequential roadmap. Originally estimated
"1-2 months, year 1-2 post-mainnet"; condensed because the underlying
implementation already shipped, leaving only documentation + a small
RPC layer.

## 3. Specification

The technically complete specification is published at
`docs/J8_PRUNING_AUDIT.md` and `docs/PRUNING_POLICY.md` in the
reference implementation tree. The audit doc enumerates:

- Existing implementation map (audit findings)
- 7 ratified design decisions (D1–D7)
- Frozen ABI surface
- Out-of-scope items

The operator-facing policy doc enumerates:

- Pruning SLA: always-retained vs window-only data
- The retention window in numbers (mainnet defaults)
- Pruning lifecycle (5 steps)
- Disk usage estimates (pruned vs archival)
- Monitoring + queryability via `getPruningInfo`
- Disaster recovery procedures

This SIP body will be re-issued in **Review** once operators have run
non-trivial archival deployments long enough to surface real
operational patterns. Until then the AUDIT + POLICY docs are
authoritative.

## 4. Frozen ABI surface

### 4.1 RPC

| Item | Value |
|------|-------|
| `RpcApiOps::GetPruningInfo` | `162` |
| Method name (gRPC) | `GetPruningInfo` |
| Method name (wRPC JSON) | `getPruningInfo` |
| gRPC oneof slots | request `1136`, response `1137` |
| Read-only | yes (D6) — no mutation methods |

### 4.2 Wire format

```text
RpcPruningInfo {
    pruning_depth:             u64,    // Params::pruning_depth() at this node's BPS
    finality_depth:            u64,    // Params::finality_depth() at this node's BPS
    current_pruning_point:     RpcHash, // 32-byte block hash
    pruning_point_blue_score:  u64,    // GHOSTDAG blue score of current_pruning_point
    is_archival:               bool,   // true iff node was started with --archival
}
```

### 4.3 Pruning lifecycle (frozen)

Per `docs/PRUNING_POLICY.md` §4: blocks below `pruning_depth` are
deleted in atomic batches. In `--archival` mode the pruning point
still advances but deletion is skipped.

### 4.4 Retention SLA (frozen)

Per `docs/PRUNING_POLICY.md` §2.1 and §2.2: 8 categories of data
always retained (headers, GHOSTDAG metadata, L1 ALT entries, J4
events archival indexes, K2 filter headers, etc.) vs 8 categories
window-only (block transactions, UTXO diffs, acceptance data, K2
filter bytes, etc.).

## 5. Rationale

Deferred to the full SIP body. The AUDIT doc §3 already enumerates the
seven ratified decisions (D1–D7) and their rationales; what changes in
the full SIP is the addition of empirical numbers from operator
deployments (per-network pruning depth in practice, archival storage
growth rate, RPC query patterns hitting pruned blocks).

The most likely points of operator-driven revision are:

- D1 — per-network `pruning_depth` overrides (currently fixed by
  formula). May be revisited if testnet operators want shallower
  retention for fast resyncs.
- D5 — adding a `getPruningHistory` RPC if operators need historical
  pruning-point progression for deeper monitoring.
- D6 — adding mutation RPCs if a legitimate operational need
  surfaces. Currently none has.

## 6. Backwards Compatibility

**Activated at genesis.** Sophis has not launched mainnet, so there is
no soft-fork window. Existing nodes that don't implement
`getPruningInfo` are not shipped — the reference implementation
includes the method on every full node. Wallets and explorers written
against SIP-8 work against any full node from the J8 commit forward.

There is no consensus impact. All J8 work happens at the read-RPC +
documentation layer; pruning + archival mode + the underlying
machinery were already shipping pre-J8.

## 7. Reference Implementation

Reference implementation: `sophis-network/Sophis` commit `<TBD>`
(single commit shipping all J8 sub-fases):

| Sub-fase | Scope |
|---------|-------|
| J8.0 | `docs/J8_PRUNING_AUDIT.md` (~205 lines) + `docs/PRUNING_POLICY.md` (~225 lines) operator-facing guide. |
| J8.1 | `rpc-core::model::pruning_info` types + `RpcApiOps::GetPruningInfo = 162` + `RpcApi::get_pruning_info` trait + service impl + 2 mock stubs + gRPC binding (proto + ops + conversions + route + factory) + wRPC binding + integration test. 3 unit tests. |
| J8.2 | This SIP stub + `SIPS/README.md` index update. |
| J8.3 | Workspace check + clippy strict + single commit. |

## 8. Security Considerations

- **No consensus impact** — purely operational + read-only RPC.
- **Read-only RPC** (D6) — no attack surface from runtime mutation.
- **Pruning is irreversible per node** (D4) — operators must consciously
  switch to archival before pruning deletes data they want to keep;
  the daemon's transition prompt (sophisd/src/daemon.rs:543) prevents
  accidental data loss.
- **PQC posture preserved** — no new primitives.
- **Eclipse / wrong-data risk** — `getPruningInfo` returns local node
  state; a malicious node could return false `is_archival = true` to
  deceive callers about historical query availability. Mitigation:
  callers verify by attempting historical queries themselves;
  inconsistency between `is_archival` claim and `getBlock` for a
  pre-pruning block reveals the lie.

## 9. Test Vectors

Canonical vectors live with the reference implementation in:

- `rpc/core/src/model/pruning_info.rs` (`tests` module) — 3 round-trip
  tests covering pruned-node response, archival-node response, and
  request shape.
- `testing/integration/src/rpc_tests.rs` — integration round-trip
  case verifying the RPC plumbing succeeds.

The wire format is frozen as of the J8 implementation commit.

## 10. References

- `docs/J8_PRUNING_AUDIT.md` — authoritative audit + ABI freeze
- `docs/PRUNING_POLICY.md` — operator-facing SLA + lifecycle + monitoring
- `docs/archival.md` — existing archival operator guide (416 lines)
- `consensus/src/pipeline/pruning_processor/processor.rs` — implementation
- `consensus/core/src/config/bps.rs` — `pruning_depth` and
  `finality_depth` formulas
- `consensus/core/src/config/constants.rs` — `FINALITY_DURATION`,
  `MERGE_DEPTH_DURATION`, `PRUNING_DURATION`
- `sophisd/src/args.rs` — `--archival` CLI flag
- `sophisd/src/daemon.rs` — archival lifecycle + transition prompt

## 11. Copyright

This SIP is released into the public domain (CC0).
