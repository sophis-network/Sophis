# J4 sVM Events — Operator Runbook

> Companion to `docs/J4_EVENTS_DESIGN.md` and `SIPS/SIP-4-EVENTS.md`. This
> document is for **node operators**, **contract developers**, and
> **indexer / wallet implementors** who need to know how to interact with
> the J4 sVM event-log feature in day-to-day operation.

## Audience

* **Node operators** running `sophisd`: §1, §3, §6, §7
* **sVM contract developers** emitting events from WASM: §4
* **Indexer / wallet developers** consuming events: §2, §5
* **dApp developers** integrating event streams: §5

## 1. Activation status

J4 sVM Events is **active at genesis on every Sophis network** (mainnet,
testnet, devnet, simnet). There is no soft-fork window, no flag day, and
no operator action required to "turn on" the feature.

* `Capability::EmitEvent` is recognised in any contract manifest
* `MAX_TOPICS_PER_EVENT = 4` — frozen ABI
* `TOPIC_LEN = 32` — frozen ABI
* `MAX_EVENT_DATA_BYTES = 4096` — frozen ABI
* `MAX_EVENTS_PER_TX = 32` — frozen ABI
* `MAX_EVENTS_PER_BLOCK = 1024` — frozen ABI
* `MAX_LOGS_PER_RESPONSE = 1000` — server-enforced RPC cap
* `EVENTS_BY_CONTRACT_BUCKET_SIZE = 65_536` — DAA bucket size
* `GAS_EVENT_EMIT_BASE = 1000`, `GAS_EVENT_EMIT_PER_BYTE = 8` — frozen ABI

A node compiled from `sophis-network/Sophis@f700c85` or later automatically
indexes events emitted by sVM contracts into the four `EventsBy*` RocksDB
stores as part of every chain-block commit, and exposes them via the
`getLogs` RPC method on all three transports (in-process, gRPC, wRPC JSON).

## 2. Recognising events

Events are pure **execution side effects** of sVM contract calls. They
are **not** part of the transaction wire format — there is no script
discriminator or magic prefix, and no `EventsBy*` data ever appears
on the P2P bus. Indexers that want events MUST query them via the
`getLogs` RPC against a node that has indexed the chain block.

A single event carries:

| Field | Type | Source |
|-------|------|--------|
| `contract_id` | `[u8; 32]` | sVM execution context (contract being called) |
| `topics` | `Vec<[u8; 32]>` (0..=4) | contract-supplied at emit time |
| `data` | `Vec<u8>` (0..=4096) | contract-supplied at emit time |
| `block_hash` | `[u8; 32]` | chain block accepting the tx |
| `tx_id` | `[u8; 32]` | accepting tx |
| `tx_index` | `u32` | `index_within_block` of the tx |
| `log_index` | `u32` | sequential within the chain block, starts at 0 |
| `daa_score` | `u64` | DAA score of the chain block |

Convention: `topic[0]` is the event signature hash
(`SHA3-384(event_signature)[..32]`), topics 1..3 are indexed parameters.

## 3. RocksDB stores

Four new prefixes were allocated for J4, immediately after the L1 ALT range:

| Prefix | Constant | Key | Value | Lifecycle |
|--------|----------|-----|-------|-----------|
| 203 | `EventsByBlock` | `block_hash` | `EventLogs` (full per-block log list) | Pruned with the block |
| 204 | `EventsByTx` | `tx_id` | `EventLogs` (full per-tx log list) | Pruned with the block |
| 205 | `EventsByContract` | `contract_id || daa_bucket(8 bytes LE)` | `EventLogPointers` | **Permanent** — never pruned |
| 206 | `EventsByTopic` | `topic || daa_bucket(8 bytes LE)` | `EventLogPointers` | **Permanent** — never pruned |

**Important:** prefixes 205 and 206 grow monotonically (archival
indexes; DESIGN §4.4). Their growth rate is bounded by the per-block cap
times the per-tx cap times BPS:

* Worst case (sustained adversarial spam at the cap): `1024 events/block × 10 BPS × 36 bytes per pointer × 5 (contract + 4 topics avg) ≈ 16 MB/day`
* Realistic case (moderate dApp ecosystem, a few hundred events/block): `~1-2 MB/day`

The per-block (203) and per-tx (204) stores are pruned alongside the
block transaction body, so their disk footprint is bounded by the
pruning window (~30 days).

Disk impact estimate over a year of operation: **archival indexes ≤ ~5
GB worst case, ~500 MB realistic**. Well within typical node disk
budgets.

## 4. sVM contract integration

Contracts that emit events MUST declare `Capability::EmitEvent` in their
manifest at deploy time:

```text
ContractManifest::new(
    contract_id,
    UpgradePolicy::Immutable,
    vec![Capability::EmitEvent, /* other caps */],
)
```

At runtime, contracts call the host function via the SDK helper:

```text
use sophis_sdk::env::{Env, EmitEventError};

let env = Env::new();
let topic_signature: [u8; 32] = sha3_384("Transfer(address,address,uint256)")[..32].try_into().unwrap();
let topic_from: [u8; 32] = ...;
let topic_to: [u8; 32]   = ...;
let amount_bytes: [u8; 32] = u256_to_bytes(1_000_000);

env.emit_event(
    &[topic_signature, topic_from, topic_to],
    &amount_bytes,
)?;
```

The host function status codes mapped to `EmitEventError` are:

| Status | Variant | Meaning |
|--------|---------|---------|
| 0 | (Ok) | Event accepted; appended to `ExecutionContext.events` |
| -1 | `CapabilityMissing` | manifest missing `EmitEvent` |
| -2 | `GasExhausted` | per-tx gas budget exhausted |
| -3 | `TopicCountTooLarge` | more than 4 topics |
| -4 | `DataTooLarge` | data > 4096 bytes |
| -5 | `StructuralError` | OOB memory / truncated payload / length mismatch |
| -6 | `PerTxCapReached` | tx already emitted 32 events |

Gas cost per emission is `GAS_EVENT_EMIT_BASE + GAS_EVENT_EMIT_PER_BYTE × payload_len = 1000 + 8 × payload_len`. Topics are not metered separately
(bounded to `4 × 32 = 128` bytes max).

**Emitted events do not affect transaction validity beyond the per-tx
gas they burn.** A failed emit (return value < 0) is handled by the
contract — most contracts will treat any negative status as a hard
revert, but the choice is the contract author's.

## 5. RPC consumption

The unified `getLogs(filter)` method is the only RPC for J4 events.
Filter shape mirrors Ethereum `eth_getLogs`:

```text
GetLogsRequest {
    contract_id:  Option<[u8; 32]>,         // wildcard if None
    topics:       Vec<Option<[u8; 32]>>,    // up to 4, positional, per-slot wildcard
    from_block:   Option<RpcHash>,          // inclusive
    to_block:     Option<RpcHash>,          // inclusive
    limit:        Option<u32>,              // server cap = 1000
}
```

**At least one of {`contract_id`, any non-None `topics[i]`, both
`from_block` + `to_block`}** must be specified — whole-chain scans are
rejected with an error.

### 5.1 gRPC example

The gRPC binding lives at `protowire.GetLogsRequestMessage`. Empty
`Vec<u8>` / empty `string` encodes the `None` variant on the wire (proto3
has no native Option):

```python
# Requires `pip install -e .` from sophis-network/sophis-py and
# running `./proto/fetch_and_compile.sh` once to generate stubs.
import grpc
from sophis_grpc import SophisClient
from sophis_grpc._generated import messages_pb2 as pb

with SophisClient("127.0.0.1:46110") as client:
    req = pb.GetLogsRequestMessage(
        contract_id = b"",                                   # wildcard
        topics = [pb.RpcEventLogTopicSlot(present=True, topic=topic_signature_bytes)],
        from_block = "ab12cd...",                            # 32-byte hex-encoded hash
        to_block   = "ef34gh...",
        limit = 100,
    )
    resp = client._stub.GetLogs(req)
    for log in resp.logs:
        print(log.contract_id.hex(), log.tx_id, log.block_hash, log.daa_score)
```

> The `SophisClient` wrapper exposes most J4 patterns via the higher-level
> `client.get_contract_events(...)` and `client.subscribe_contract_events(...)`
> helpers. The raw-proto example above is shown when finer control over the
> request — e.g., the explicit `RpcEventLogTopicSlot(present=...)` slots — is
> needed.

### 5.2 wRPC JSON example (curl)

```bash
curl -X POST http://localhost:18110 \
  -H "Content-Type: application/json" \
  -d '{
    "method": "getLogs",
    "params": {
      "contractId": null,
      "topics": [{"present": true, "topic": "<32-byte hex>"}],
      "fromBlock": "<32-byte hex>",
      "toBlock":   "<32-byte hex>",
      "limit":     100
    }
  }'
```

(Port 18110 is wRPC JSON-RPC default for mainnet; substitute per your
network: testnet 28110, devnet 38110, simnet 48110.)

### 5.3 Server-side query strategy

The resolver picks the **most-selective index** per design §7.3:

1. Any non-None topic → walk `EventsByTopic` for the first non-None slot.
2. Else if `contract_id` is `Some` → walk `EventsByContract`.
3. Else if `from_block == to_block` → single-block lookup via `EventsByBlock`.
4. Else (no selective axis) → reject.

For each pointer hit the server hydrates the full `EventLog` via
`get_logs_by_block` (with last-block cache), post-filters by remaining
axes, and stops when it hits `min(client.limit, MAX_LOGS_PER_RESPONSE)`.

Cost is tied to filter selectivity, not chain cardinality.

## 6. Indexer / wallet patterns

### 6.1 Polling pattern

Pull-only is the supported v1 model. WebSocket subscription is
deferred (DESIGN §9). Recommended cadence:

```text
last_seen_block = checkpoint;
loop:
    new_block = rpc.get_sink().await;
    logs = rpc.get_logs({
        contract_id: Some(my_contract),
        from_block:  Some(last_seen_block),
        to_block:    Some(new_block),
        limit:       1000,
    });
    process(logs);
    if logs.len() == 1000:
        # paginate by sliding from_block forward through the returned logs
        last_seen_block = logs.last().block_hash;
        continue;
    last_seen_block = new_block;
    sleep(POLL_INTERVAL);
```

Choose `POLL_INTERVAL` between 1s (responsive UI) and 30s (low-cost
indexer). With `MAX_LOGS_PER_RESPONSE = 1000` and 10 BPS, a ~5s poll
interval is sufficient for any single contract under normal load.

### 6.2 ABI decoding

Sophis does **not** bless any specific ABI format. Contract authors
publish their ABIs out-of-band; consumers decode `data` according to
the contract's own convention. A common starting pattern:

```text
let event_sig = sha3_384("Transfer(address,address,uint256)")[..32];
if log.topics[0] == event_sig:
    let from   = log.topics[1];
    let to     = log.topics[2];
    let amount = u256_from_be_bytes(&log.data);
```

## 7. Node operator monitoring

### 7.1 Logs to watch

`sophisd` emits `WARN` lines on the rare paths where event indexing
fails:

```
J4: event indexing failed for block <hash>: <error>
```

This log line should never appear in normal operation. If it does,
investigate the underlying RocksDB error before continuing — the chain
will keep advancing (the indexing failure is non-fatal by design,
mirroring Phase 6 DA and L1 ALT), but downstream RPC consumers will
see "missing" events for the affected block.

A second warning line fires if a chain block exceeds the per-block cap:

```
J4: per-block event cap (1024) reached for chain block <hash>; trailing events truncated
```

This indicates either heavy on-chain activity or an adversary attempting
event-log spam. Trailing events are dropped; the accepted txs themselves
remain valid.

### 7.2 RPC endpoints

The following methods are reachable on every node running
`sophis-network/Sophis@f700c85` or later:

* In-process: `RpcApi::get_logs(request)` and `get_logs_call(...)`
* gRPC: `protowire.GetLogsRequestMessage` / `GetLogsResponseMessage`
* wRPC JSON: `getLogs`

### 7.3 Dashboards and alerts

Recommended metrics for operators running the dashboard at
`tools/sophis-dashboard/`:

- `events_per_block` — should rarely exceed 100-200 in normal traffic;
  sustained values near 1024 indicate either heavy DEX/DAO activity or
  an adversary attempting event-log spam.
- `events_total` — monotonic counter; growth-rate alerts fire if rate
  exceeds 1000 per minute sustained.
- `events_by_topic_lookup_p99_latency` — RocksDB lookup latency; should
  stay sub-millisecond. Tail spikes suggest cache cold-misses (raise
  `block_data_cache_size`).

(These metrics are operational follow-ups; the dashboard at I1 already
exposes the underlying RocksDB cache hit rates and can be extended.)

## 8. Pre-mainnet checklist

For operators planning to run a node that serves event RPC queries
from mainnet day zero:

- [ ] Node binary is `sophis-network/Sophis@f700c85` or later (verify
      with `sophisd --version`).
- [ ] Disk has at least 10 GB headroom for the archival event indexes
      over a 1-year horizon.
- [ ] If serving `getLogs` to public clients, configure a rate limiter at
      the reverse proxy layer — `MAX_LOGS_PER_RESPONSE = 1000` caps
      bytes per call but does not cap calls per second.
- [ ] Indexer software has been tested against devnet event traffic
      (use `dilithium-wallet` once event-emit example contracts ship).

## 9. Disengagement

J4 sVM Events cannot be cleanly removed once mainnet launches because:

1. Contracts in production deploy with `Capability::EmitEvent` declared.
   Removing the capability would brick those contracts at the next call.
2. Archival indexes (205, 206) are part of the on-disk state. Removing
   them would orphan historical filter queries and break indexer pagination.

A future SIP that wished to deprecate event emission would have to either:

- Hard-fork the chain to reject `Capability::EmitEvent` at deploy time
  (existing deployed contracts continue to work; new deploys cannot
  request the capability), OR
- Soft-disable via a per-tx gas reservation that makes events
  prohibitively expensive (similar to how some Bitcoin opcodes were
  soft-disabled after BIP-66 by raising their effective cost).

Operators considering forks of the codebase that strip events should
follow option (a) only and only at a fresh genesis.

## 10. References

- `docs/J4_EVENTS_DESIGN.md` — wire-format and consensus specification
- `SIPS/SIP-4-EVENTS.md` — SIP stub (full body deferred to post-testnet)
- `consensus/core/src/events/` — types, codec, parser
- `consensus/src/model/stores/events.rs` — RocksDB store
- `consensus/src/pipeline/virtual_processor/processor.rs` — commit hook
  (`drain_events_collector_for_block`, `index_events_in_block`)
- `consensus/src/processes/transaction_validator/mod.rs` — `EventsCollector`
- `svm/core/src/events.rs` — runtime-facing parser + ABI constants
- `svm/runtime/src/host.rs` — `sophis_emit_event` host fn
- `svm/sdk/src/env.rs` — `Env::emit_event` SDK helper
- `rpc/core/src/model/events.rs` — RPC types
- `rpc/service/src/service.rs` — `get_logs_call` query strategy
- `docs/L1_RUNBOOK.md` — sibling runbook for L1 ALT; shares operational
  philosophy
- `oracle/docs/PHASE6_RUNBOOK.md` — sibling runbook for Phase 6 DA

## 11. Document history

| Date       | Change |
|------------|--------|
| 2026-05-10 | Initial runbook (sub-fase J4.6). |
