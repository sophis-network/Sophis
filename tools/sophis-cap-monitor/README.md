# sophis-cap-monitor

A watchdog that enforces the **founder self-restriction cap** declared in the
Sophis monetary policy: the founder's single declared address must not hold
more than a fixed share of the circulating supply.

Default trip threshold is **4.9%** (490 basis points), strictly below the
public commitment of 5.0%. When the threshold is crossed, the watchdog kills
the local `sophis-miner` process and refuses to issue another kill until its
state file is cleared manually.

The binary is **public** and identical for everyone. Anyone can run it against
their own `sophisd` node to independently audit the cap — see the
"Independent verification" section below.

## What it does, exactly

On every tick (default every 5 minutes):

1. Calls `get_coin_supply` → `circulating_sompi` (network supply, issued minus
   burned).
2. Calls `get_balance_by_address` → current balance of the address declared
   on the command line.
3. Updates a **monotone high-water-mark** of the balance in the state file.
   Spending from the address does not lower the effective cap.
4. Computes `ratio_bps = hwm * 10000 / circulating`.
5. If `ratio_bps >= --threshold-bps` and the state file does not already
   record a pause event:
   - On Windows, runs `taskkill /F /IM <miner-process>`.
   - On Unix, runs `pkill -f <miner-process>`.
   - Persists `paused = true` to the state file and exits with status 2.

Using **circulating** (rather than total issued) as the denominator is
strictly more conservative for a cap on the founder's share: if anyone burns,
the denominator shrinks and the watchdog trips earlier rather than later.

## Requirements

- A running `sophisd` started with `--utxoindex` (required for
  `get_balance_by_address`).
- The watchdog should run on the same host as the miner so the local
  `taskkill`/`pkill` actually reaches the miner process. It cannot kill a
  remote miner.

## Founder usage (mainnet, real run)

```pwsh
sophis-cap-monitor.exe `
  --address "sophis:q2sdls98vf40p3v53eyu2ylu3rnfyvjr3cw3gwmuhj8pwnkkgdn5677h7448r" `
  --rpc-server "127.0.0.1:46110" `
  --threshold-bps 490 `
  --interval-secs 300 `
  --state-file "C:\Projetos\sophis-data\mainnet\cap-monitor-state.json"
```

The watchdog runs in a third terminal, alongside the node and miner. It does
not interact with either except through (a) the node's RPC and (b) `taskkill`.

## Independent verification

Anyone can run the watchdog in **read-only / dry-run mode** against their own
node to verify the founder's compliance:

```bash
sophis-cap-monitor \
  --address "sophis:q2sdls98vf40p3v53eyu2ylu3rnfyvjr3cw3gwmuhj8pwnkkgdn5677h7448r" \
  --rpc-server "127.0.0.1:46110" \
  --state-file ./verify-cap-state.json \
  --interval-secs 3600 \
  --dry-run
```

`--dry-run` suppresses the kill action — the watchdog only logs and updates
its own state file. The state file is plain JSON and shows the observed
high-water-mark plus the most recent ratio in basis points.

There is **no privileged execution** in the watchdog. Two independent runs
against two independent nodes should produce the same numbers (modulo
short-term divergence near the tip), and either can be diffed against the
founder's published state file.

## State file format

```json
{
  "address": "sophis:q2sdls98vf40p3v53eyu2ylu3rnfyvjr3cw3gwmuhj8pwnkkgdn5677h7448r",
  "hwm_sompi": 0,
  "hwm_observed_at_unix": 0,
  "last_check_unix": 0,
  "last_circulating_sompi": 0,
  "last_balance_sompi": 0,
  "last_ratio_bps": 0,
  "paused": false,
  "pause_event_unix": null
}
```

The watchdog refuses to reuse a state file whose `address` field does not
match the `--address` CLI argument — to prevent accidental cross-address
mixing.

Writes are atomic (write tmp → rename) so a crash mid-tick cannot corrupt
the file.

## Operational semantics

- `paused = true` is a **terminal** state. The watchdog logs the condition,
  exits, and will refuse to issue another kill on next launch (you would see
  the original pause event re-logged on startup). To resume mining you must
  delete or rename the state file deliberately — i.e., the operator must
  consciously override the cap.
- If `--threshold-bps` is set above 500 (the public commitment), the
  watchdog logs a loud warning but proceeds, since the binary is meant to
  be useful to anyone monitoring any address, not just the founder.
- The watchdog only kills the local miner. It does not try to coordinate
  across machines; the founder is committed to operating from a single
  declared address, so monitoring one node is sufficient.
