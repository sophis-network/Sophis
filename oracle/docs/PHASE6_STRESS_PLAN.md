# Sophis Phase 6 — pre-mainnet stress plan (sub-fase 6.8)

This document specifies the **72-hour devnet stress run** that must pass
before Phase 6 can ship on mainnet. It covers the test scenario, the
metrics to capture, the acceptance gates, and a step-by-step operator
recipe.

**Status:** v2, updated at sub-fase 6.8.b (2026-05-14). The plan
ships with `devnet/da_stress_check.py` (observability) and
`tools/sophis-da-stress` (traffic generator, sub-fase 6.8.b). Both
6.4.b (gRPC client binding) and 6.5.b (real `current_blue_score`)
have landed, so this plan is now executable end-to-end.

---

## 1. Goal

Validate that the V5 DA carrier path holds up under 72 hours of
sustained 50%-block-mass saturation by carriers, with the Phase 3
rollup sequencer + Phase 5 oracle relayer concurrently active. Note
that Phase 5 was deprecated on 2026-05-11 in favor of Phase 9
(SIP-11); the Phase 5 relayer is exercised here as a dual-path
fallback rather than the primary oracle code path. Once SIP-11 D11
flips, the Phase 5 component drops out and this plan can re-run with
Phase 9 publishers exclusively.

A pass certifies:

- The DA store does not grow unboundedly outside of accepted
  carrier inputs.
- Indexation latency stays bounded (no GC / cache pathology).
- Pruning works correctly: pruned-body lookups behave per the design
  doc §8.
- No consensus regressions, no stuck mempool, no node crash.

## 2. Scenario

5-node devnet, all nodes co-located on a single host or split across
two machines (no public internet exposure). Networking via the standard
devnet ports (46611 + offsets, see `CLAUDE.md` Devnet section).

### 2.1 Producer profile

Three concurrent producers, all running for the full 72h:

| Producer | Domain bit | Target rate |
|---|---|---|
| Phase 3 rollup sequencer | `CARRIER_FLAG_DOMAIN_ROLLUP` (0x10) | 1 batch / 30 s, ≤ 8 fragments/tx |
| Phase 5 oracle relayer with `da_publish=true` | `CARRIER_FLAG_DOMAIN_ORACLE` (0x20) | 1 carrier / 30 s |
| Synthetic stress generator | `CARRIER_FLAG_DOMAIN_USER` (0x40) | tuned to fill remaining mass |

The synthetic generator is the load knob; rollup + relayer represent
realistic background traffic. The generator targets:

```
target_per_block_bytes = 0.5 × max_block_mass_bytes
                       = 0.5 × (max_block_mass / TRANSIENT_BYTE_TO_MASS_FACTOR)
                       = 0.5 × (500_000 / 4)
                       = 62_500 bytes
```

At 10 BPS, that's **~625 KB/s of carrier bytes**, ~50 GB over 72 hours
(before any pruning).

### 2.2 Carrier composition

The generator publishes a mix:

- **70% single-fragment, 1-32 KiB random** — exercises the common path
- **20% 5-fragment bundles, ~64 KiB each** — exercises reassembly + by_domain bucketing
- **10% 32-fragment, 64 KiB each (= 2 MiB max bundle)** — exercises MAX_FRAGMENTS edge

**Multi-tx publishing:** because consensus caps carrier outputs per tx
at `MAX_CARRIER_OUTPUTS_PER_TX` (= 8, ABI freeze), bundles with
more than 8 fragments are split across **N sequential sub-txs** sharing
the same `bundle_id`. The store's `BundleIndex` (prefix 197) reassembles
by bundle_id regardless of how many txs the fragments arrived in. The
32-fragment class therefore fires `ceil(32 / 8) = 4` sub-txs per bundle.
The generator waits ~250 ms between sub-txs so the previous tx's change
UTXO can land in the mempool.

Generator must drop to zero submissions on observed mempool back-pressure
(use `get_mempool_entries`); the stress is sustained, not bursty. The
reference generator skips an iteration entirely when `get_mempool_entries`
exceeds the configured threshold (CLI `--mempool-threshold`, default 100)
and logs a `backpressure_skip` row to the CSV.

## 3. Metrics

Every 60 s the observability helper (`devnet/da_stress_check.py`)
captures one row of metrics from each node and appends to a CSV file:

| Metric | How |
|---|---|
| `accepting_blue_score` | gRPC `get_block_dag_info` → `virtual_daa_score` (proxy until 6.5.b lands) |
| `da_store_bytes` | du(`<data_dir>/<network>/consensus`) — coarse but consistent |
| `payloads_count` | RocksDB property `rocksdb.estimate-num-keys` for prefix 196 |
| `bundles_count` | same, prefix 197 |
| `by_block_count` | same, prefix 198 |
| `by_domain_count` | same, prefix 199 |
| `indexation_lag_blocks` | `current_blue_score` minus highest `blue_score` in `payloads` |
| `process_rss_mb` | `psutil.Process(pid).memory_info().rss` for sophisd |
| `process_cpu_pct` | `psutil.Process(pid).cpu_percent(interval=1.0)` |
| `mempool_entries` | gRPC `get_mempool_entries` len |

Plus, at the **end** of the 72h run, a one-shot prune-correctness
report:

- For 1000 random pre-prune-horizon `payload_id`s, query
  `da_get_payload`. Expected: 0 hits (all pruned).
- For 1000 random post-prune-horizon `payload_id`s, query
  `da_get_payload`. Expected: ≥ 99.9% hits (transient writes may have
  been re-orged out).

## 4. Acceptance gates

A run **passes** iff all gates below clear simultaneously:

| Gate | Threshold |
|---|---|
| **G1 — no panics** | sophisd, sequencer, relayer log files have zero `panic!`/`thread 'main' panicked` lines |
| **G2 — no stuck consensus** | `accepting_blue_score` advances by ≥ 60 every 60 s (= ≥ 1 block/sec on average; loose to absorb hiccups) |
| **G3 — no DA index error** | log files have zero lines matching `WARN.*DA carrier indexing failed` |
| **G4 — bounded RAM** | `process_rss_mb` (sophisd) stays under 8 GB; no monotonic growth past hour 4 |
| **G5 — bounded indexation lag** | `indexation_lag_blocks` stays under 100 (= 10 s of DAG-time at 10 BPS) for ≥ 99% of samples |
| **G6 — DA store growth tracks input** | `da_store_bytes` growth in any 1-hour window is within ±20% of `bytes_submitted` |
| **G7 — no DB corruption** | sophisd restarts cleanly at hour 24, 48, 72 (operator-triggered) and replays the chain without `KeyNotFound` errors |
| **G8 — pruning correctness** | the post-run report meets the §3 expectation |
| **G9 — mempool drains** | after submissions stop at hour 72:00, mempool reaches 0 entries within 5 minutes |

A failure on any gate blocks the mainnet ship. Operators triage:

- G1, G3, G7 → file a bug; rerun after fix.
- G2, G5 → likely cache / RocksDB tuning; consult perf params.
- G4, G6 → memory leak or store bloat; bisect against 6.2.b commits.
- G8 → pruning bug; do not ship.
- G9 → mempool back-pressure not honored; tune generator.

## 5. Operator recipe

> **Pre-requisite:** sub-fase 6.4.b (gRPC carrier submission for the
> stress generator) and sub-fase 6.5.b (real `current_blue_score` so
> indexation lag is meaningful). Without these, the 72h run is not
> meaningful — partial-run smoke tests are still useful.

### 5.1 Setup (T-30 min)

```bash
# 1. Ensure no stale data
cd <devnet-scripts-dir>
python orchestrator.py purge

# 2. Start 5 nodes
python orchestrator.py start

# 3. Wait for coinbase maturity on node-0
python orchestrator.py wait-mature
```

### 5.2 Baseline capture (T-15 min)

```bash
# Capture the pre-stress baseline metrics for comparison
python da_stress_check.py --once --out baseline.csv
```

### 5.3 Producers

In separate terminals:

```bash
# Phase 3 rollup sequencer (already wired by 6.3 — runs auto with mining)
# (no extra command — the rollup-node binary kicks in when devnet is up)

# Phase 5 oracle relayer with da_publish=true
cd <repo-root>
copy oracle\relayer\stress.toml relayer.toml  # da_publish=true variant
cargo run --release --features grpc-submit -p sophis-oracle-relayer -- daemon

# Synthetic stress generator (sub-fase 6.8.b)
# --profile mixed = canonical 70/20/10 mix from §2.2 (default)
# --target-mb-per-s 0.625 maps to ~2.18 iter/s using the mix's average payload
# --mempool-threshold 100 honors §2.1 back-pressure rule
# --domain user keeps stress traffic distinct from rollup/oracle bits
cargo run --release -p sophis-da-stress -- \
  --wallet devnet/devnet_mining_wallet.json \
  --rpcserver localhost:46610 \
  --profile mixed \
  --target-mb-per-s 0.625 \
  --domain user \
  --mempool-threshold 100 \
  --duration 72h \
  --csv stress-traffic.csv
```

### 5.4 Observability loop

```bash
# Sample every 60 s, append to stress.csv, run for 72h
python da_stress_check.py --interval 60 --duration 72h --out stress.csv
```

### 5.5 Restarts (G7 gate)

At T+24h, T+48h:

```bash
python orchestrator.py restart-node 0   # rolling, one node at a time
# Wait for resync, confirm no KeyNotFound errors in node-0.log
```

### 5.6 Post-run analysis

```bash
python da_stress_check.py --report stress.csv
# emits a stress-report.txt with one row per gate, PASS/FAIL
```

### 5.7 Cleanup

```bash
python orchestrator.py stop
# Archive: stress.csv, stress-report.txt, node-{0..4}.log, relayer.log
```

## 6. Reporting template

The `--report` flag produces a markdown summary like:

```text
# Phase 6 stress report — <ISO timestamp>

Duration:        <hours>h <mins>m
Nodes:           5
Producers:       rollup, oracle (da_publish=on), synthetic (0.625 MB/s)

Gate results:
  G1 no panics                  PASS
  G2 consensus advance          PASS  (avg 9.7 blocks/sec, min 7.1)
  G3 no DA index error          PASS
  G4 bounded RAM                PASS  (peak 4.2 GB at T+18h)
  G5 indexation lag             PASS  (99.4% under 100 blocks)
  G6 DA store growth            PASS  (within ±12% per hour)
  G7 restart cleanliness        PASS  (3/3 restarts clean)
  G8 prune correctness          PASS  (1000/1000 prune-horizon hits, 0/1000 pre-horizon)
  G9 mempool drains             PASS  (0 entries within 3m20s)

Overall:                        PASS — Phase 6 cleared for mainnet ship.
```

## 7. What this plan does NOT validate

- **Multi-region latency** — the run is local. WAN consensus is a
  separate test (deferred to bootstrap-node setup).
- **Adversarial / Byzantine** — covered by sub-fase 6.7 unit tests, not
  here. Multi-node Byzantine simulation is post-mainnet hardening.
- **Hard fork upgrades mid-run** — Phase 6 ships at genesis; no upgrade
  path test needed.
- **Light-client behavior** — there is no light-client implementation
  in v1 (see PHASE6_DA_DESIGN §14.1).

## 8. Dependencies (all delivered)

| Dep | Sub-fase | Status |
|---|---|---|
| `sophis-da-stress` binary | 6.8.b | ✅ delivered 2026-05-14 (`tools/sophis-da-stress`, 17 unit tests) |
| Real `current_blue_score` plumbing | 6.5.b | ✅ delivered |
| `GrpcClient::get_da_payload` real impl | 6.4.b | ✅ delivered |
| Synthetic carrier generator | 6.8.b | ✅ delivered (mixed profile 70/20/10, multi-tx publishing, back-pressure) |

The 72h soak is executable end-to-end. `da_stress_check.py` runs in
da-aware mode against the carrier metrics now that 6.4.b is wired.

## 9. Reference

- Design freeze: `oracle/docs/PHASE6_DA_DESIGN.md`
- Operator manual: `oracle/docs/PHASE6_RUNBOOK.md`
- Adversarial matrix: `devnet/test_phase6_da_attacks.py`
- Observability helper: `devnet/da_stress_check.py` (this sub-fase)
- Mainnet acceptance gates: this document, §4.
