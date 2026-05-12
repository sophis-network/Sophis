# I1 Dashboard — Operator Runbook

> Companion to `docs/I1_DASHBOARD_DESIGN.md`. This document is for
> **node operators** who deploy `tools/sophis-dashboard` as the public
> mainnet status page (LAUNCH_CHECKLIST.md ação #2 + Roadmap I item I1).

## Audience

* **Node operators** running the dashboard binary on a public VPS: §1, §2, §6, §7
* **Wallet / dApp / explorer integrators** consuming `/metrics` JSON: §3, §4
* **Founder / launch coordinator** ensuring the 24h defensive window is visible: §5

## 1. What this binary does

`sophis-dashboard` is a single Rust binary that:

1. Connects to a local `sophisd` via gRPC.
2. Polls a small set of RPC methods on staggered cadences (10s / 30s / 5min).
3. Aggregates results into a `MetricsSnapshot` cached in process memory.
4. Serves three HTTP endpoints:
   * `GET /` — embedded HTML page (Tailwind + Alpine via CDN, dark theme)
   * `GET /metrics` — same snapshot as JSON
   * `GET /healthz` — `200 OK` for uptime probes

It is **stateless** beyond the in-memory caches. Restarting the binary
takes ~10s for the first poll cycle to re-warm the state. The 60-min
miner ring buffer and the 5-min top-wallets snapshot start empty after
restart and re-populate as new blocks arrive.

## 2. Running the binary

### 2.1 Local sanity test

```powershell
cd <repo-root>
cargo run --release -p sophis-dashboard -- `
    --rpcserver localhost:46110 `
    --listen-addr 0.0.0.0:8080 `
    --founder-address sophis:q2sdls98vf40p3v53eyu2ylu3rnfyvjr3cw3gwmuhj8pwnkkgdn5677h7448r `
    --genesis-unix-ms 1731224700000
```

Open `http://localhost:8080/`. The page should render with placeholder
"—" values until the first poll completes (~10s later).

### 2.2 CLI flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--rpcserver` / `-s` | `localhost:46110` | sophisd gRPC endpoint. |
| `--listen-addr` / `-l` | `0.0.0.0:8080` | Bind address for the HTTP server. |
| `--founder-address` / `-f` | (required) | The publicly-declared founder mining address. Used both for the founder share calculation and as the network-prefix source for top-wallets address derivation. |
| `--genesis-unix-ms` / `-g` | `0` (countdown disabled) | Genesis timestamp in unix milliseconds. When `0`, the 24h founder-window countdown displays "—". |
| `--finality-blue-blocks` | `100` | N for the "99.9% finalized after N blue blocks" label (D2; matches mainnet `coinbase_maturity`). |
| `--top-wallets-window-blocks` | `10000` | Number of recent blocks scanned for the active-address heuristic (D1; ~17 minutes at 10 BPS). |

### 2.3 Production deployment (VPS)

The dashboard is one binary + one TCP port. Recommended setup:

* **Reverse proxy:** nginx or Caddy in front of port 8080, terminating TLS
  (`status.sophis.org` → dashboard).
* **Process supervisor:** `systemd` unit (`Restart=always`) or
  `pm2`/`supervisord`. The binary exits non-zero on bind failure or
  `axum::serve` errors; restart-on-failure is the right policy.
* **Co-location:** run on the same machine as `sophisd` so the gRPC
  poll has near-zero latency. The dashboard adds negligible CPU /
  memory load over a stock `sophisd`.

Sample systemd unit (`/etc/systemd/system/sophis-dashboard.service`):

```ini
[Unit]
Description=Sophis Public Dashboard
After=sophisd.service
Requires=sophisd.service

[Service]
Type=simple
User=sophis
ExecStart=/opt/sophis/sophis-dashboard \
    --rpcserver localhost:46110 \
    --listen-addr 127.0.0.1:8080 \
    --founder-address sophis:q2sdls98vf40p3v53eyu2ylu3rnfyvjr3cw3gwmuhj8pwnkkgdn5677h7448r \
    --genesis-unix-ms 1731224700000
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

## 3. The `/metrics` JSON contract

Stable, additive-only schema. Downstream consumers can pin on field
presence; future I1.x sub-fases will only add fields, never rename or
remove them.

Top-level keys:

| Field | Type | Refresh | Source |
|-------|------|---------|--------|
| `snapshot_unix_ms` | u64 | 10s | local clock |
| `genesis_unix_ms` | u64 | constant | `--genesis-unix-ms` |
| `seconds_since_genesis` | i64 | 10s | derived |
| `seconds_until_founder_window_ends` | i64 | 10s | derived (24h) |
| `founder_in_wait_window` | bool | 10s | derived |
| `hashrate_hps` | u64 | 10s | `get_block_dag_info().difficulty * 10` |
| `total_supply_sompi` | u64 | 10s | `get_coin_supply` |
| `founder_balance_sompi` | u64 | 10s | `get_balance_by_address` |
| `founder_share_ratio` | f64 | 10s | derived |
| `block_count` | u64 | 10s | `get_block_dag_info` |
| `virtual_daa_score` | u64 | 10s | `get_block_dag_info` |
| `rpc_healthy` | bool | 10s | poll outcome |
| `last_rpc_error` | string\|null | 10s | poll outcome |
| `founder_address` | string | constant | `--founder-address` |
| `founder_wait_window_secs` | i64 | constant | `86400` |
| `bps_actual` | f64 | 10s | I1.1 — 60s ring buffer derivation |
| `mempool_depth` | object | 30s | I1.1 — `{ tx_count, total_mass, include_orphans }` |
| `finality_probability` | object | 10s | I1.1 — `{ blue_score_now, blue_blocks_for_99_9, label }` |
| `unique_miners_60min` | object | 30s | I1.2 — `{ distinct_addresses, blocks_observed, window_seconds }` |
| `top_100_wallets` | object | 5min | I1.3 — `{ entries[], sampling_window_blocks, refreshed_unix_ms, approximate, caveat }` |

### 3.1 Stability guarantees

* Field name + JSON path: stable forever (additive-only).
* Field semantic: stable forever; any change requires a major version bump
  (the binary itself versions via `--version`).
* Field type: stable forever (e.g. `bps_actual` will not flip from f64
  to integer).

The contract above is what every wallet, explorer, indexer, and on-chain
analyst integrating with the dashboard depends on. Treat changes here as
breaking — propose them via SIP if needed.

### 3.2 Refresh cadences and staleness

The dashboard does NOT serve "live" data. Every field is the latest
*polled* value. Cadences:

* `/metrics` itself is served from in-memory state, < 50 ms.
* Backend poll loop runs every `POLL_INTERVAL = 10s`.
* Mempool, miner-buffer top-up, recent-blocks poll: every 30s sub-cycle.
* Top-wallets refresh: every 5 min sub-cycle.

A consumer that polls `/metrics` faster than 10s will see repeating
snapshots. For real-time-ish UX, a future SIP could add WebSocket push
(`/metrics/stream`); not in scope for I1.

## 4. Approximate-by-design fields

### 4.1 `bps_actual`

Derived from a 60-second ring buffer of `block_count` snapshots. Reports
`0.0` for the first ~60s after dashboard start (cold buffer).

### 4.2 `unique_miners_60min`

Counted by deduplicating coinbase recipient script-public-key bytes
within a rolling 1-hour window. **Limitations:**

* Multi-output coinbases (founder + dev fund + others) count every
  output — this over-counts slightly but errs on the side of more
  decentralisation visible.
* Restart loses the buffer; first hour after restart will under-report.

### 4.3 `top_100_wallets`

**This metric is approximate by design** (D1 of DESIGN, §4.5):

* Sampled from on-chain activity in the last `--top-wallets-window-blocks`
  blocks (~17 min at 10 BPS).
* Cold wallets that haven't transacted recently may be missing.
* Refresh cadence: 5 min (heavy RPC pressure if shorter).
* The `approximate: true` flag and `caveat` string in the JSON make this
  contract explicit. Display the caveat in any UI that surfaces this
  field.

A future SIP could propose a `get_top_balances(n)` RPC backed by a
sorted index in `UtxoIndex`. That's a consensus-layer addition; deferred
out of I1 scope.

## 5. Founder-launch defensive window

The Hero card on the dashboard surfaces the founder's 24h post-genesis
mining moratorium (`FOUNDER_WAIT_SECS = 86_400`). During the window:

* `founder_in_wait_window: true`
* `seconds_until_founder_window_ends` counts down
* The Hero card switches to a warning-tinted style
* `founder_share_ratio` should be `0.0` if the founder has honoured the
  window

After the window:

* `founder_in_wait_window: false`
* `founder_share_ratio` displays the live share
* The Hero card switches to:
  * **green** (accent) if `founder_share_ratio < 0.05` (under cap)
  * **amber** (warn) if `founder_share_ratio >= 0.05` (cap reached;
    auto-pause script should have triggered already)

The 5% lifetime cap is enforced *off-chain* by `scripts/cap_5pct_monitor.py`
(see `docs/FOUNDER_SELF_RESTRICTION.md`). The dashboard surfaces the
state but does not enforce; cap enforcement lives in the miner script.

## 6. Frontend: CDN dependencies

The `dashboard.html` page loads two scripts from public CDNs on first
visit:

* `https://cdn.tailwindcss.com` — Tailwind v3.x runtime
* `https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js` — Alpine.js v3

Operators wanting an air-gapped deployment must self-host these:

```bash
# Download once
curl -o tailwind.js https://cdn.tailwindcss.com
curl -o alpine.js https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js
# Serve from the same nginx/Caddy that fronts /metrics
# Then patch the <script> src= attributes in dashboard.html before
# building the binary.
```

The CDN payloads are served over HTTPS with subresource integrity
*not* set (Tailwind ships a CSS-in-JS runtime that mutates on every
page load). Operators with strict CSP requirements should self-host.

## 7. Monitoring the dashboard itself

* `GET /healthz` → `200 OK` (no body parsing) for uptime probes.
* `journalctl -u sophis-dashboard -f` (or equivalent) to follow logs.
  Watch for `WARN ` lines — `mempool poll failed`, `recent-blocks poll
  failed`, `top-wallets refresh failed` indicate transient RPC issues.
  Stale-data warnings on `/` (snapshot age > 60s) typically correlate
  with sustained RPC failure.
* A continuously red `rpc_healthy: false` for > 5 min means the
  dashboard cannot reach `sophisd`. Check:
  1. `systemctl status sophisd` (is sophisd running?)
  2. `ss -lntp | grep 46110` (is the gRPC port open?)
  3. `--rpcserver` flag points at the right host:port?

## 8. Performance characteristics

Measured on a typical 2-core VPS:

| Metric | Target | Observed |
|--------|--------|----------|
| `/metrics` p99 latency | < 50 ms | ~5 ms |
| Backend poll cycle (healthy) | < 2 s | ~200 ms |
| Backend poll cycle (one RPC timeout) | < 10 s | ~15 s with default `RPC_TIMEOUT` |
| Resident memory | < 50 MB | ~25 MB steady-state |
| Startup time | < 1 s | < 200 ms |

If `/metrics` p99 grows beyond 50 ms, you likely have lock contention
between the `/metrics` reader and the poller writer; investigate by
checking the poll loop's last-success timestamp.

## 9. Pre-mainnet checklist

For operators planning to launch the dashboard alongside mainnet day
zero:

- [ ] Binary built from `sophis-network/Sophis@568616b` or later.
- [ ] `--founder-address` matches the publicly-declared founder mining
      address (verify against `LAUNCH_CHECKLIST.md` ação #1's hash).
- [ ] `--genesis-unix-ms` set to the planned genesis time before T-72h
      (acceptable to set after genesis if you redeploy; the countdown
      will then be retroactive).
- [ ] Reverse proxy + TLS configured (`status.sophis.org` or chosen
      subdomain).
- [ ] Systemd unit (or equivalent) installed; `systemctl enable
      sophis-dashboard`.
- [ ] First boot test: `/metrics` returns non-empty JSON, `/` renders
      the page.
- [ ] Alerting integration optional (see §7).

## 10. Disengagement

The dashboard can be disabled/redeployed at any time without affecting
the chain. It is observability infrastructure, not consensus
infrastructure. Operators who want to fork the dashboard for their own
node fleet can do so under the AGPL.

If `sophisd` exposes future RPC methods relevant to a new metric, the
dashboard can absorb them additively (per §3.1 stability guarantee).
Removed RPC methods break the dashboard but never the chain.

## 11. References

* `docs/I1_DASHBOARD_DESIGN.md` — design spec, decisions D1–D4
* `tools/sophis-dashboard/src/main.rs` — backend
* `tools/sophis-dashboard/src/dashboard.html` — frontend
* `LAUNCH_CHECKLIST.md` — defensive actions ação #2 (this dashboard)
* `FOUNDER_SELF_RESTRICTION.md` — 5% cap policy the dashboard surfaces
* `OPERATIONAL_BOUNDARIES.md` — non-custodial commitments

## 12. Document history

| Date       | Change |
|------------|--------|
| 2026-05-10 | Initial runbook (sub-fase I1.5). Closes the I1 deliverable. |
