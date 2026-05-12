# Sophis Pruning Policy — Operator Guide

> Companion to `docs/archival.md` (archival-side operator guide) and
> `docs/J8_PRUNING_AUDIT.md` (audit + ABI freeze). This document is for
> **node operators** running pruned (default) Sophis nodes. Archival
> operators read `docs/archival.md` first; this doc covers the
> pruning-side perspective they should also know.

## Audience

* **Node operators** running pruned `sophisd` (default mode) — §1, §2, §4, §5
* **Block explorers and indexers** querying historical data — §3, §6
* **Wallet implementers** caching pruning info — §6
* **Auditors and researchers** verifying retention guarantees — §2, §7

## 1. What pruning does

A pruned Sophis node deletes block data older than `pruning_depth`
blocks below the virtual selected tip. The deleted data is gone from
local storage; only an explicit resync (from another node) or a
switch to archival mode (with backup restore) brings it back.

Pruning frees disk space — the difference between pruned and archival
storage at saturated 10 BPS is significant (hundreds of GB to TB+
over years). The trade-off: pruned nodes cannot answer historical
queries beyond their retention window.

## 2. What pruning retains (the SLA)

A pruned Sophis node MUST retain everything in this list, indefinitely
or until pruned per `pruning_depth`. Anything else MAY be discarded.

### 2.1 Always retained, regardless of depth

| Data | Source store | Why |
|------|--------------|-----|
| Block headers | `headers_store` | Light clients (J5) sync the header chain; explorers cite headers; consensus needs deep ancestry for reorg analysis. |
| Selected chain index | `selected_chain_store` | L3 commitment levels need it; J5 SPV needs it. |
| GHOSTDAG metadata | `ghostdag_store` | Required for chain validation across the entire history. |
| Past pruning points | `past_pruning_points_store` | Bootstrap of new nodes via pruning proof. |
| L1 ALT entries (prefix 200) | `alt_store` | **Permanent** per L1 design §4 — never pruned. |
| L1 ALT resolutions (prefix 202) | `alt_store` | **Permanent** per L1 design. |
| J4 events archival indexes (prefixes 205, 206) | `event_store` | **Permanent** per J4 design §4.4 — historical filter queries against pre-pruning blocks remain answerable. |
| K2 filter headers (prefix 208) | `block_filters_store` | **Permanent** per K2 design §6 — SPV resync from any block continues to work. |

### 2.2 Retained for the pruning window only (`pruning_depth` blocks deep)

| Data | Source store | Pruned when |
|------|--------------|-------------|
| Block transactions | `block_transactions_store` | Block falls below pruning point. |
| UTXO diffs | `utxo_diffs_store` | Same. |
| UTXO multisets | `utxo_multisets_store` | Same. |
| Acceptance data | `acceptance_data_store` | Same. |
| Phase 6 DA carrier payloads (prefixes 196, 198) | `da_store` | Same. The DA *bundle index* (prefix 197) is permanent. |
| L1 ALT block-creation index (prefix 201) | `alt_store` | Pruned with the block; the entries themselves (prefix 200) survive. |
| J4 events per-block / per-tx (prefixes 203, 204) | `event_store` | Pruned with the block; archival indexes (205, 206) survive. |
| K2 filter bytes (prefix 207) | `block_filters_store` | Pruned with the block; the header chain (208) survives. |

### 2.3 Pruned-mode RPC behaviour beyond the window

Calls that target a pruned block return one of:
* `Option<None>` (e.g. `getBlock(hash)` for a pruned block)
* `RpcError::PrunedBlock(hash)` (older API style)
* Empty result (e.g. `getTxMerkleProof(tx_id, pruned_block_hash)` →
  `None` since the block transactions are gone)

Wallets and indexers MUST handle these cases gracefully — typically by
treating them as "data unavailable, retry against an archival node"
or "data unavailable, this is expected for old blocks".

## 3. The retention window in numbers

At Sophis mainnet (BPS = 10):

| Quantity | Value | Wall-clock |
|----------|-------|------------|
| `Params::finality_depth()` | 432 000 blocks | ~12 h |
| `Params::pruning_depth()` | depends on safety margin formula; typically ~600 000-1 000 000 blocks | ~17-28 h on mainnet defaults |
| `MERGE_DEPTH_DURATION` (parameter) | 3 600 s | 1 h |
| `FINALITY_DURATION` (parameter) | 43 200 s | 12 h |

The exact pruning depth is computed by `Params::pruning_depth()` from
constants in `consensus-core/src/config/constants.rs`. The
`getPruningInfo` RPC (J8.1) exposes the runtime value; query it once
at wallet bootstrap and cache.

## 4. Pruning lifecycle

1. **Block accepted** at virtual tip. No pruning yet — block is "fresh".
2. **Block ages.** As the chain advances, this block sinks below the
   virtual tip.
3. **Block crosses `pruning_depth`.** The pruning processor schedules
   it for deletion in the next pruning step.
4. **Pruning step runs.** The processor batches all deletions for one
   chain block at a time, atomically:
   * Deletes block transactions from `block_transactions_store`
   * Deletes UTXO diff from `utxo_diffs_store`
   * Deletes UTXO multiset from `utxo_multisets_store`
   * Deletes acceptance data from `acceptance_data_store`
   * Deletes DA carrier payloads from `da_store` (bundle index survives)
   * Calls `forget_block_index` on `event_store` (block + tx survive
     archival via prefixes 205/206)
   * Calls `forget_filter_for_pruned_block` on `block_filters_store`
     (header chain survives)
   * Updates the pruning point in management metadata
5. **Restart safety.** If the daemon restarts mid-pruning, the
   pruning processor's idempotent design picks up where it left off.

In `--archival` mode, steps 4's deletion calls are skipped — the
block data stays on disk indefinitely.

## 5. Disk usage estimates

### Pruned mode (default)

* Header chain (always): ~150 bytes/header × 10 BPS × 86400 ≈ **130 MB/day**, ~50 GB/year.
* Block transactions (window): saturated chain-block can carry hundreds of KB; budget ~**10-20 GB** for the active pruning window.
* RocksDB overhead, indexes, GHOSTDAG metadata: another **~20-30 GB**.
* **Practical pruned-mode disk budget: ~80-100 GB** for a node operating for one year.

### Archival mode

See `docs/archival.md` for HDD-optimised tuning. Practical estimates:
* **500 GB minimum**, 2 TB+ recommended for multi-year archival horizons.

## 6. Monitoring + queryability

### 6.1 The `getPruningInfo` RPC

Returns 5 fields per design J8.0:
- `pruning_depth: u64` — frozen-per-BPS retention window
- `finality_depth: u64` — frozen-per-BPS finality threshold
- `current_pruning_point: RpcHash` — deepest block we still retain
- `pruning_point_blue_score: u64` — blue score of the pruning point
- `is_archival: bool` — whether this node skips deletion

Wallets and indexers SHOULD query this once at startup and cache.
Operators can use it for monitoring (alert on archival mode flips,
track pruning point advancement rate).

Example (gRPC):

```python
# Requires `pip install -e .` from sophis-network/sophis-py and
# running `./proto/fetch_and_compile.sh` once to generate stubs.
from sophis_grpc import SophisClient

with SophisClient("127.0.0.1:46110") as client:
    info = client.get_pruning_info()
    print(f"pruning_depth={info.pruning_depth}")
    print(f"current_pruning_point={info.current_pruning_point}")
    print(f"is_archival={info.is_archival}")
```

Example (wRPC JSON):

```bash
curl -X POST http://localhost:18110 \
  -H "Content-Type: application/json" \
  -d '{"method": "getPruningInfo", "params": {}}'
```

### 6.2 Dashboard widgets

Operators running `tools/sophis-dashboard` (item I1) see archival
status in the metrics snapshot. Recommended additions for J8 era:

- `pruning_point_advancement_rate` — should track BPS minus a small
  margin; sudden stalls indicate disk pressure.
- `archival_status_change_alert` — fires once if `is_archival` flips
  between sessions (operators can choose to dismiss or investigate).

(Both are dashboard polish for follow-up work; not part of J8 v1.)

## 7. Disaster recovery

### Pruned node lost some block data (e.g. disk corruption)

Two options:

1. **Resync from another node.** Standard recovery path; resync time
   depends on chain depth and bandwidth. The pruning processor
   re-establishes the pruning point as the chain syncs forward.
2. **Switch to archival mode** by restarting with `--archival` and
   restoring from an archival backup (if you have one). The daemon
   warns on the pruned → archival transition (it doesn't actually
   delete anything during the transition; just keeps more data going
   forward).

### Archival node accidentally pruned via `--archival false`

Sophisd refuses this transition silently — it prompts at startup with
"Proceeding may delete archived data. Do you confirm? (y/n)" (per
`sophisd/src/daemon.rs:543`). Operators who answer 'n' keep their
archival data. Answering 'y' is irreversible.

## 8. References

- `docs/J8_PRUNING_AUDIT.md` — audit findings + ABI freeze + ratified decisions
- `docs/archival.md` — archival-side operator guide (existing, 416 lines)
- `SIPS/SIP-8-PRUNING-POLICY.md` — Standards-track stub
- `consensus/src/pipeline/pruning_processor/processor.rs` — implementation (694 lines)
- `consensus/core/src/config/bps.rs` — `pruning_depth` and `finality_depth` formulas
- `consensus/core/src/config/constants.rs` — `FINALITY_DURATION`, `MERGE_DEPTH_DURATION`, `PRUNING_DURATION`
- `sophisd/src/args.rs` — `--archival` CLI flag
- `sophisd/src/daemon.rs` — archival lifecycle + transition prompt

## 9. Document history

| Date       | Change |
|------------|--------|
| 2026-05-11 | Initial policy document (sub-fase J8.0). |
