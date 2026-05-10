# I1 — Dashboard Extension (Hyperliquid-style)

> **Status:** design frozen for sub-fase I1.0 — ready for I1.1 implementation.
> **Originating roadmap:** Roadmap I (Hyperliquid lessons), item I1.
> **Companion docs:** future `docs/I1_RUNBOOK.md` (operator guide,
> sub-fase I1.5).
> **Pre-existing baseline:** `tools/sophis-dashboard/` (~360 LOC, axum
> server + embedded HTML, entregue 2026-05-07 com 9 métricas core). I1
> *extends* this baseline, não substitui.

## 1. Motivation

The existing dashboard answers "is the chain alive and is the founder
within their cap?" — exactly what the 24h post-genesis defensive window
needs (LAUNCH_CHECKLIST.md ação #2). It does **not** answer the next-
order questions a market participant asks once mainnet is past T+24h:

- *How fast is the chain producing blocks right now?* (BPS observed,
  not theoretical 10 BPS)
- *Is the mempool congested?* (depth in tx count + cumulative mass)
- *How decentralised is hashrate?* (unique miners observed in the last
  rolling 60min window)
- *Where does ownership concentrate?* (top 100 wallets by balance)
- *When can I trust this transaction?* (finality probability at depth N)

Hyperliquid, Solana, Ethereum block-explorers all surface these as
first-class metrics. Sophis's existing dashboard is **defensive** (cap
monitor); I1 makes it **probative** (chain-health monitor) so it can
double as the on-chain transparency layer that the project's "Bitcoin
Core / Monero Project" model implicitly promises.

This deliverable also serves an operational role: the data feeds become
input to the third-party block explorers / market data integrators that
will eventually build on Sophis. Publishing them in a stable JSON format
at `/metrics` saves every downstream integrator from re-implementing the
derivation formulas.

## 2. Ratified design decisions

These decisions were committed by the founder on 2026-05-10 and are
frozen for the I1 implementation. Re-opening any of them requires an
explicit user reset.

| ID | Question | Choice | Rationale |
|----|----------|--------|-----------|
| **D1** | Source for "Top 100 wallets" data | Recent-activity heuristic + balance lookup | No `get_top_balances` RPC exists; full UTXO scan via `UtxoIndex` is also too slow for a 5-minute refresh. Compromise: scan the last K blocks (~17 minutes at 10 BPS) for distinct addresses in tx outputs, then `get_balances_by_addresses` to rank. Documented as "approximate, refreshes every 5 min, biased toward recently-active addresses". |
| **D2** | Finality probability formula | GHOSTDAG-aware (`blue_score` based) | Sophis is a DAG, not a linear chain. `1 − (1/2)^N` (Bitcoin-style) ignores GHOSTDAG's `blue_score` accumulation. C3 of the original D2 menu: report `99.9% finalized after N blue blocks` where N is configurable via CLI flag (default = 100, matching the existing `coinbase_maturity` for mainnet). |
| **D3** | Unique-miners aggregation window | Rolling 60-min sliding window | Top-of-hour buckets cause UI to "jump" at every :00 minute. Rolling 60min is the dashboard convention used by Hyperliquid, Dune, Glassnode. Sliding window is computed by maintaining a per-poll list of (timestamp, address) tuples and filtering ≥ now-3600s on every emission. |
| **D4** | Frontend visual stack | Tailwind via CDN + Alpine.js via CDN, no build step | A) keeps the existing HTML/CSS too plain; C) React+Vite breaks the single-binary deploy model. B) Tailwind+Alpine via CDN gets a Hyperliquid-grade visual polish while preserving `cargo run -p sophis-dashboard` as the canonical deployment story. |

### D1 — note on the trade-off

D1 has a known soundness gap: a wallet that has held a large balance for
years but has not transacted recently (cold storage) may not appear in
the recent-blocks heuristic. The dashboard surfaces this caveat in the
UI label: *"Top 100 wallets by balance, sampled from recent on-chain
activity. Cold wallets that haven't transacted in the last ~17 minutes
may be missing."*

A future SIP (deferred) would propose a `get_top_balances(n)` RPC method
backed by a sorted index maintained inside `UtxoIndex`. That work is
out-of-scope for I1 — it is a consensus-level addition that needs its
own design discussion.

## 3. Existing dashboard inventory

`tools/sophis-dashboard/` ships today with the following metrics, served
at `/metrics` as JSON:

| Metric | Source | Refresh |
|--------|--------|---------|
| `snapshot_unix_ms` | local clock | 10s |
| `genesis_unix_ms` | CLI flag | constant |
| `seconds_since_genesis` | derived | 10s |
| `seconds_until_founder_window_ends` | derived (24h cap) | 10s |
| `founder_in_wait_window` | derived | 10s |
| `hashrate_hps` | `get_block_dag_info().difficulty * 10` | 10s |
| `total_supply_sompi` | `get_coin_supply().circulating_sompi` | 10s |
| `founder_balance_sompi` | `get_balance_by_address(founder)` | 10s |
| `founder_share_ratio` | derived | 10s |
| `block_count` | `get_block_dag_info().block_count` | 10s |
| `virtual_daa_score` | `get_block_dag_info().virtual_daa_score` | 10s |
| `rpc_healthy` | poll outcome | 10s |
| `last_rpc_error` | poll outcome | 10s |
| `founder_address` | CLI flag | constant |
| `founder_wait_window_secs` | constant 86 400 | constant |

I1 **adds** the metrics in §4. It does **not** rename or remove any
existing field — downstream consumers that pin on the current schema
remain compatible.

## 4. New metrics catalog

The `MetricsSnapshot` JSON gains five top-level fields, all
nullable / zero-defaulted so downstream parsers that observe the
dashboard before the first successful poll see consistent shapes.

### 4.1 `bps_actual` — observed blocks-per-second

```json
"bps_actual": 9.83
```

- **Computation:** `(block_count_now − block_count_60s_ago) / 60`. The
  poller maintains a small ring buffer of the last 60 seconds of
  `block_count` snapshots (one per 10s poll = 6 entries). Reports `0.0`
  before the buffer is warm.
- **Refresh:** every 10s (same poll loop).
- **Why 60s window:** smooths the natural BPS jitter at the 10 BPS
  target without lagging the UI noticeably. A shorter window over-reads
  jitter; a longer window obscures real congestion.

### 4.2 `mempool_depth` — current mempool size

```json
"mempool_depth": {
  "tx_count": 142,
  "total_mass": 5_237_400,
  "include_orphans": false
}
```

- **Computation:** `get_mempool_entries(include_orphan_pool=false,
  filter_transaction_pool=false)`. Sum `tx_count` and aggregate `mass`
  field of every entry.
- **Refresh:** every 30s (less frequent than 10s to avoid hammering
  RPC; mempool changes slowly relative to consensus).
- **Operator note:** if `tx_count > 10_000` the dashboard adds a UI
  warning *"mempool is congested"* — informational only, no consensus
  effect.

### 4.3 `finality_probability` — GHOSTDAG-aware confidence

```json
"finality_probability": {
  "blue_score_now": 12_450,
  "blue_blocks_for_99_9": 100,
  "label": "99.9% finalized after 100 blue blocks (~10s at 10 BPS)"
}
```

- **Source:** `get_block_dag_info().virtual_daa_score` plus a constant
  `BLUE_BLOCKS_FOR_99_9_FINALITY` (default = 100, configurable via
  `--finality-blue-blocks` CLI flag).
- **Why constant N:** Sophis's GHOSTDAG with `coinbase_maturity = 100`
  already encodes the project's "safe-to-spend" depth. Reusing that
  number keeps the dashboard label honest: at depth N, the same
  guarantee that allows spending coinbase outputs applies.
- **Refresh:** every 10s.
- **Label semantics:** the number is informational. A wallet that needs
  cryptographic-grade finality should ask `is_chain_block(hash)` against
  a recent virtual-state snapshot.

### 4.4 `unique_miners_60min` — rolling decentralisation gauge

```json
"unique_miners_60min": {
  "distinct_addresses": 47,
  "blocks_observed": 36_000,
  "window_seconds": 3600
}
```

- **Computation:** the poller maintains a `VecDeque<(unix_ms, Address)>`
  of (timestamp, coinbase-address) tuples observed in the last 3600s.
  Each new block pulled via `get_blocks(low_hash, true /* include_txs */)`
  appends `(now, coinbase_address)`; entries older than 3600s are
  evicted on every emission. `distinct_addresses` = cardinality of
  the address set after eviction.
- **Refresh:** every 30s. New blocks since the last poll are pulled
  via `get_blocks` with the previous tip as `low_hash`.
- **Memory bound:** at 10 BPS × 3600s = 36 000 tuples × ~80 bytes =
  ~3 MB. Cheap, fits in process memory comfortably.
- **Edge case:** at startup the buffer is empty → reports
  `distinct_addresses = 0` until the first block is pulled.

### 4.5 `top_100_wallets` — recent-activity-biased ranking

```json
"top_100_wallets": {
  "entries": [
    {"rank": 1, "address": "sophis:qxx...", "balance_sompi": 1_234_567_890_000},
    ...
  ],
  "sampling_window_blocks": 10000,
  "refreshed_unix_ms": 1731224700000,
  "approximate": true,
  "caveat": "Sampled from on-chain activity in the last ~10k blocks; cold wallets may be missing."
}
```

- **Computation (D1=A):**
  1. Maintain a `HashSet<Address>` of "recently active addresses" by
     scanning the outputs of every block pulled by §4.4 (reuse the
     same `get_blocks` calls — no extra RPC).
  2. Cap the set at K = 100_000 addresses (LRU eviction by last-seen
     timestamp).
  3. Every 5 minutes, `get_balances_by_addresses(addresses_in_set)`.
  4. Sort by balance descending, take top 100.
- **Refresh:** every 300s (5 min). The 5-minute interval avoids
  hammering `get_balances_by_addresses` with 100k addresses too often.
- **Approximate flag:** the JSON exposes `approximate: true` and a
  human-readable `caveat` so consumers can disclaim accordingly.
- **Performance target:** the 5-minute refresh cycle should complete
  in under 10 seconds end-to-end on a node with the UTXO index
  populated. Benchmark established in I1.3.

## 5. RPC dependencies

All RPC methods needed by I1 already exist in `sophis_rpc_core::api::rpc::RpcApi`:

| Method | Used by | Frequency |
|--------|---------|-----------|
| `get_block_dag_info` | existing + bps_actual + finality_probability | 10s |
| `get_coin_supply` | existing | 10s |
| `get_balance_by_address` | existing (founder) | 10s |
| `get_mempool_entries` | mempool_depth | 30s |
| `get_blocks` | unique_miners_60min + top_100_wallets (input collection) | 30s |
| `get_balances_by_addresses` | top_100_wallets (ranking step) | 300s |

**No new RPC methods are required for I1.** This is by design — the
dashboard is operational tooling, not a consensus surface. Any RPC
addition (e.g. a future `get_top_balances`) would be a separate SIP.

## 6. Frontend layout (Tailwind + Alpine, no build)

The HTML page (`dashboard.html`) keeps its current structure (single
file, embedded into the binary via `include_str!`) but switches to:

- **Tailwind v3.x via CDN** (`<script src="https://cdn.tailwindcss.com"></script>`)
- **Alpine.js v3.x via CDN** for reactive bindings
  (`<script defer src="https://cdn.jsdelivr.net/npm/alpinejs"></script>`)

Both are loaded directly from public CDNs; no `package.json`, no Vite,
no node modules. The tradeoff is that the dashboard requires internet
access to fetch the CDN payloads on first page load — acceptable given
that the dashboard is itself a public-internet HTTP service.

### 6.1 Section layout (top-to-bottom)

| Section | Content | Refresh visual |
|---------|---------|----------------|
| Hero | Genesis countdown / 24h founder window status (existing) | live |
| Network health | Hashrate · BPS actual · Block count · Virtual DAA | 10s |
| Mempool | tx_count · total_mass · congestion warning | 30s |
| Decentralisation | Unique miners 60min · Founder share % | 30s / 10s |
| Top wallets | Top 100 list with rank, address, balance, % of supply | 300s |
| Finality | Blue score now · safe-spend depth label | 10s |
| Footer | RPC health · last error · snapshot timestamp | 10s |

All times in the UI are in operator-local timezone (browser-derived).
The JSON `/metrics` endpoint always reports unix milliseconds (UTC).

### 6.2 Aesthetic constraints

- **Dark theme by default** (Hyperliquid convention). Light theme via
  Alpine `:class` toggle, persisted to `localStorage`.
- **Monospace font** for numbers (avoids width jitter as values change).
- **No animations** except a subtle fade on metric updates (Alpine
  `x-transition`). Sophis dashboard is informational, not gamified.
- **Color palette:** consistent with existing brand (no specific brand
  colours yet — Tailwind's `slate`/`emerald`/`amber` defaults).

## 7. Performance targets

| Metric | Target |
|--------|--------|
| `/metrics` endpoint p99 latency | < 50 ms (in-memory snapshot read) |
| Backend poll cycle (10s loop) | completes in < 2s under healthy RPC |
| Backend poll cycle worst case | < 10s (RPC timeouts are 15s; one timeout shouldn't stall the loop) |
| `top_100_wallets` refresh full cycle | < 10s end-to-end on a populated node |
| Dashboard binary memory footprint | < 50 MB resident (excluding CDN-loaded JS in the browser) |
| Dashboard binary startup time | < 1s to bind port and start polling |

These are observability targets, not consensus invariants. Failure to
meet them is a quality issue, not a chain issue.

## 8. Threat model

### 8.1 In scope

| # | Threat | Mitigation |
|---|--------|------------|
| T1 | DoS via dashboard scraping | Rate limit `/metrics` at axum layer (default 60 req/min/IP via `tower-governor`, configurable). |
| T2 | RPC abuse via dashboard | All RPC calls go through the dashboard's own poller, never proxied; users cannot trigger arbitrary RPC. |
| T3 | Founder-address spoofing in URL (`?founder=...`) | The founder address is set via CLI flag at startup, NEVER from query string or HTTP header. |
| T4 | Stale data presented as fresh | UI shows `snapshot_age_secs`; > 60s triggers a *"data may be stale"* warning. |
| T5 | Top-100 wallet leak (privacy) | All UTXO data is already public — dashboard shows what `get_balance_by_address` already serves. No additional privacy leak. |

### 8.2 Out of scope

| # | Non-threat | Why excluded |
|---|------------|--------------|
| N1 | Cross-site scripting via Tailwind/Alpine CDN compromise | Standard web hygiene; users running the dashboard locally can self-host the CDN payloads if concerned (documented in RUNBOOK §6). |
| N2 | Discrepancy between dashboard's view of chain and consensus reality | Dashboard is informational; consensus is authoritative. Use `sophisd` directly for cryptographic decisions. |
| N3 | Censorship of certain addresses from top-100 display | Dashboard does NOT filter; if your address has a high enough balance and recent activity, it appears. |

## 9. Out-of-scope (for I1)

The following are explicitly NOT delivered by I1:

- A new RPC method `get_top_balances(n)` for exact ranking (deferred SIP)
- WebSocket push (`/metrics/stream`) for real-time UI updates without polling
  (current polling is fine for the v1 dashboard)
- Historical charting (graphs over time) — would require persistent
  storage; out-of-scope for a stateless dashboard
- Multi-network awareness (current dashboard is single-network)
- Alerting / paging integration (Prometheus / OpsGenie) — separate
  observability stack, not the founder's launch dashboard
- Mobile-optimised layout (responsive layout via Tailwind is enough;
  separate mobile app is ecosystem)

## 10. Activation summary

I1 is a tooling extension. There is no consensus rule, no fork, no
on-chain change. Activation = "merge the I1.x commits and rebuild the
`sophis-dashboard` binary".

Operators upgrading from the pre-I1 dashboard simply replace the binary
and pass the same CLI flags. New optional flags introduced by I1:

| Flag | Default | Purpose |
|------|---------|---------|
| `--finality-blue-blocks` | `100` | N for the "99.9% finalized after N blue blocks" label (D2). |
| `--top-wallets-window-blocks` | `10000` | Number of recent blocks scanned for active-address heuristic (D1). |
| `--rate-limit-rpm` | `60` | `/metrics` rate limit per IP per minute (T1). |

## 11. Glossary

| Term | Meaning |
|------|---------|
| BPS | Blocks per second observed (vs. theoretical 10 BPS target). |
| Mempool depth | Number of transactions + total mass currently in the local mempool. |
| Unique miners | Distinct coinbase recipient addresses observed in a rolling time window. |
| Finality probability | Heuristic confidence that a block at depth N will not be reorganised; expressed as label, not consensus rule. |
| Top wallets | Approximate ranking of addresses by balance, sampled from recent on-chain activity. |
| Hyperliquid-style | Visual idiom established by the Hyperliquid front-end: dark theme, monospace numbers, sectioned cards, minimal animation. |
| Approximate | A metric whose computation includes a sampling step that may miss data (specifically: cold wallets in §4.5). |

## 12. Document history

| Date       | Change |
|------------|--------|
| 2026-05-10 | Initial design (sub-fase I1.0). Decisions D1–D4 ratified. |
