# Sophis Phase 6 — Data Availability operator runbook (sub-fase 6.6)

This document is the **operator manual** for the Phase 6 DA layer. It
covers what carriers are, how full nodes index them, how producers
(rollup sequencer, oracle relayer, user wallets) publish them, how the
sVM contract path consumes them, monitoring, and troubleshooting.

**Status:** v1, locked at sub-fase 6.6 (2026-05-06). Pairs with the
design freeze in `oracle/docs/PHASE6_DA_DESIGN.md` and the V5 carrier
ABI in `consensus/core/src/da/`.

---

## 1. Preflight — who needs to read this

| Role | What you need from this doc |
|---|---|
| Full-node operator | §3 (DA store on-disk layout), §6 (monitoring), §8 (pruning + retention), §9 (troubleshooting) |
| Phase 3 rollup sequencer operator | §4 (automatic — nothing to configure), §6 (logs), §9 |
| Phase 5 oracle relayer operator | §5 (`da_publish` opt-in), §9 |
| Third-party indexer / archival service | §3 (store layout), §7 (RPC), §10 (replay verification) |
| Wallet / dapp developer | §7 (RPC), §11 (CLI helpers) |

If you're running a stock sophisd today, you're already running the DA
layer — there is nothing to enable. The only opt-in switch is the
oracle relayer's `submit.da_publish` flag (§5).

## 2. Quick start — what is a carrier?

A **carrier** is a transaction output with `script_public_key.version == 5`.
Its script body is a 64-byte header followed by opaque data bytes:

```
magic    = b"SPHS-DA1"           (8 bytes)
flags    = u8                    (FRAGMENTED | LAST | DOMAIN_*)
reserved = 0                     (1 byte, must be zero)
count    = u8                    (1..=32)
index    = u8                    (0..count)
data_len = u32 LE                (0..=65_536)
bundle   = SHA3-384 of full data (48 bytes)
data     = up to 64 KiB
```

Carriers are **unspendable** — every output must have `value = 0` and
no transaction may use a V5 output as an input. Once the consensus
layer accepts the containing transaction, every full node indexes the
carrier into the local DA store and removes it from the active UTXO
set. From that point on, anyone can fetch the bytes by `payload_id`
(SHA3-384 of the framed script) or reassemble a full bundle by
`bundle_id` (SHA3-384 of the concatenated `data` sections).

The complete consensus rules are in §5 of the design doc; the codec is
in `consensus/core/src/da/codec.rs`.

## 3. DA store on-disk layout

The store lives next to the rest of the consensus database under four
RocksDB column-family-equivalent prefixes (see
`database/src/registry.rs`):

| Prefix | Key | Value | Purpose |
|---|---|---|---|
| `196` `DaCarrierPayloads` | `payload_id (48 B)` | `PayloadEntry` | Per-fragment full record |
| `197` `DaCarrierBundles` | `bundle_id (48 B)` | `BundleIndex` | All `payload_id`s sharing the bundle, sorted by `fragment_index` |
| `198` `DaCarrierByBlock` | `block_hash (32 B)` | `BlockCarriers` | All `payload_id`s the block accepted |
| `199` `DaCarrierByDomain` | `(domain_byte, blue_score / 1000)` | `DomainBucket` | Routing index for ROLLUP / ORACLE / USER carriers |

Cache budget reuses the per-block `block_data` cache policy; payload
bodies are paged in on demand. There is no separate process — the
store is populated synchronously inside
`virtual_processor::commit_utxo_state`, in the same `WriteBatch` that
records `acceptance_data`. Atomicity is RocksDB-native.

## 4. Rollup sequencer — automatic DA publishing

Phase 3 sequencers (the rollup-node binary) emit a third tx, `T_carrier`,
on every batch flush. The order is:

1. `Prep` tx — commits `BatchJournal { ..., da_bundle_id: SHA3-384(borsh(batch)) }`
2. `T_carrier` tx — V5 carriers with the borsh-serialized batch
   (`flags = CARRIER_FLAG_DOMAIN_ROLLUP`)
3. `StateUpdate` tx — absorbs the Submission UTXO, advances state

There is **nothing to configure** on the sequencer side; the wiring
ships in 6.3 (`rollup/sequencer/src/sequencer.rs::flush_batch`). The
guest computes the same `da_bundle_id` inside the zkVM, so the proof
and the journal agree on what calldata is on-chain.

**Capacity envelope:**

- Max single-tx calldata: 8 fragments × 64 KiB = **512 KiB**
- Larger batches: rejected with
  `SequencerError::L1Client("calldata too large for a single T_carrier tx")`.
  Multi-tx splitting is a future enhancement.
- Phase 3 batch of 100 L2 txs ≈ 370 KiB → comfortably one tx.

**T_carrier fee:** `CARRIER_TX_FEE = 50_000` sompi (5× a Prep fee). Set
conservatively to cover storage mass of large carriers.

## 5. Oracle relayer — `da_publish` opt-in

Phase 5 relayers (`oracle/relayer`) inline the signed bundle into the
invocation tx. Phase 6 adds an **opt-in** archival publish: the relayer
also emits a V5 carrier (`flags = CARRIER_FLAG_DOMAIN_ORACLE`) with the
wire bytes after each successful `submit_bundle`.

### 5.1 Enabling

In `relayer.toml`:

```toml
[submit]
grpc_endpoint    = "127.0.0.1:46110"
contract_address = "sophis:qx..."
state_path       = "./relayer-state.json"
network_prefix   = "devnet"
da_publish       = true   # NEW (default: false)
```

### 5.2 Behavior

- Each iteration: relayer publishes the invocation tx as before, then
  (if `da_publish=true`) publishes the V5 carrier.
- **Carrier publish failure does NOT abort the iteration.** The journal
  is already on L1; the DA copy is purely archival. Failure is logged
  as `WARN`.
- Wire format: see `bundle_to_carrier_wire` in
  `oracle/relayer/src/daemon.rs`. Frame is `version=1` + length-prefixed
  `journal | oracle_proof | verify_air_proof`.

### 5.3 Cost

One additional L1 tx per iteration, paying the standard mass fee. At
the default `daemon.interval_secs = 30` and a typical bundle of ~3 KiB,
the extra cost is dominated by the per-tx mass overhead, not by carrier
size.

## 6. Monitoring

### 6.1 Full node — DA indexation

The virtual processor logs DA failures via `warn!`:

```
WARN  DA carrier indexing failed for block <block_hash>: <error>
```

This should be **rare**. A spike indicates either a corrupted DA store
or a code regression. The chain continues regardless — DA indexing
failures never abort consensus (`commit_utxo_state` swallows the error).

### 6.2 Sequencer

Successful `T_carrier` publication logs:

```
[l1_client] T_carrier published: bundle_id=<48-byte hex> txid=<32-byte hex>
```

If the calldata exceeds 512 KiB:

```
fee UTXO too small for carrier tx: have <X> sompi, need <CARRIER_TX_FEE>
```

or:

```
calldata too large for a single T_carrier tx: <N> fragments > MAX 8
```

The first means the sequencer fee wallet needs more SPHS; the second
means the batch should be split (current implementation rejects; future
multi-tx splitter would batch-split automatically).

### 6.3 Oracle relayer (`da_publish=true`)

```
INFO  daemon starting: state.last_sequence=N, interval=30s, da_publish=true
INFO  submitted seq N as txid <hex>
INFO  published oracle DA carrier for seq N
```

Or:

```
WARN  DA carrier publish failed for seq N: <error> — journal already on L1
```

The journal is still on L1 in that case; only the archival copy is
missing for that sequence.

## 7. RPC

Five methods on `RpcApi` expose the DA store (sub-fase 6.4.a). gRPC
and wRPC bindings are stubbed (`NotImplemented`) until 6.4.b/c land.
For local integration tests inside a sophisd binary, call the trait
methods directly via `RpcCoreService`.

| Method | Purpose |
|---|---|
| `get_da_payload(payload_id: Vec<u8>)` | Single fragment + script bytes |
| `get_da_bundle(bundle_id: Vec<u8>)` | Reassembled bundle (server-side) |
| `get_da_carriers_by_block(block_hash: RpcHash)` | All carriers in a block |
| `get_da_carriers_by_domain(domain_byte: u8, blue_score: u64)` | Bucket query (~100s window) |
| `get_da_payload_status(payload_id: Vec<u8>)` | Acceptance + confirmation count |

Wire types are documented in `rpc/core/src/model/da.rs`.

> **Pending (6.4.b, 6.4.c):** the gRPC client (`GrpcClient`) and the
> wRPC client (`SophisRpcClient`) currently return `NotImplemented` for
> these methods. External callers should poll directly through the
> service-impl layer or wait for the binding sub-fases.

## 8. Pruning + retention

Carriers follow the same pruning regime as ordinary transactions. A
pruned node:

- Drops the carrier body bytes (`script` field of `PayloadEntry`).
- May still keep the `PayloadEntry` metadata record up to the prune
  horizon — `Capability::VerifyDataAvailability` (see §9 of the design)
  continues to return `1` for pruned-but-confirmed payloads.
- Past the prune horizon, the metadata is also dropped; `da_get_*`
  returns `None` and the capability returns `0` ("not present").

Operators that run `--archival` keep all bodies indefinitely.
Third-party indexers SHOULD shard archival across more than one
operator so that the prune horizon of any single node is not the
network's effective retention window.

## 9. Troubleshooting

### 9.1 Carrier rejected at the consensus level

Look at the consensus log line near the rejecting block. Possible
causes:

| Symptom | Reason | Fix |
|---|---|---|
| `CarrierMalformed(i, "magic mismatch")` | First 8 bytes of script are not `b"SPHS-DA1"` | Producer bug; check `encode_carrier_script` use |
| `CarrierMalformed(i, "data_len exceeds 65536")` | Single fragment too large | Use `encode_bundle` to chunk, or limit raw producer to 64 KiB |
| `CarrierNonZeroValue(i, V)` | Output value != 0 | V5 outputs MUST be `value: 0` |
| `CarrierInCoinbase(i)` | Coinbase tx has a V5 output | Coinbases cannot carry data; emit a separate tx |
| `TooManyCarrierOutputs(N, 8)` | More than 8 V5 outputs in one tx | Split across multiple txs |

### 9.2 Bundle `data: None` from `get_da_bundle`

The reassembly returns `None` when at least one fragment is missing.
Check `BundleIndex.payload_ids.len()` against `fragment_count`:

```text
get_da_bundle(bundle_id) -> { fragment_count: 5, payload_ids: [3 entries], data: None }
```

Means 2 fragments are still pending. Possible causes:

- The producer published only some fragments and the rest are still in
  the mempool.
- The remaining fragments live in a block that the local node has not
  yet processed (IBD / lag).
- The producer never sent the rest (bug or interrupted submission).
  Confirm by querying `get_da_carriers_by_block` for the producer's
  recent blocks.

### 9.3 `da_get_payload` returns `None` for a payload you just published

- Did the containing block reach the virtual chain? Carriers index
  only on `commit_utxo_state` (§4 of this doc, sub-fase 6.2.b).
  Side-chain blocks do not populate the store.
- Was the block disqualified? Check
  `StatusDisqualifiedFromChain` in the statuses store.
- Was the body pruned? See §8.

### 9.4 `Capability::VerifyDataAvailability` always returns 0

Most likely cause as of sub-fase 6.5: `current_blue_score = 0` is
hard-wired (a deliberate, conservative no-op). Once 6.5.b lands and
the validator threads the chain block's blue score into `SophisDaBackend`,
the host fn returns 1 for properly confirmed payloads.

If 6.5.b has shipped and you're still seeing 0:

- The contract did not declare `Capability::VerifyDataAvailability` in
  its manifest → host fn returns -2.
- The 48 byte arg is not 48 bytes / `padding != 0` → -4.
- `query_kind` is not 0 or 1 → -1.
- `min_confirmations` is negative → -1.
- Gas exhausted → -3.

## 10. Replay verification (third-party indexers)

A standalone indexer can rebuild any application's history from the DA
store alone:

1. Stream `da_carriers_by_block` for every block on the canonical
   chain (or filter by `da_carriers_by_domain` for a specific
   producer category).
2. For each `payload_id`, fetch `da_get_payload` to get the script
   bytes, recover the framed header via `parse_carrier_header`.
3. Group by `bundle_id`; once `payload_ids.len() == fragment_count`,
   call `da_get_bundle` to receive the reassembled body.
4. Verify `SHA3-384(body) == bundle_id` (the server already does this,
   but double-check).
5. Decode the body according to the producer's domain: borsh `Batch`
   for ROLLUP, the relayer's `bundle_to_carrier_wire` framing for
   ORACLE.

No producer signature is required to trust the bytes — the consensus
layer hashed them at acceptance time, and the SHA3-384 commitment is
collision-resistant under all known attack models.

## 11. CLI helpers

Phase 6.6 ships RPC + relayer plumbing only; first-party CLI helpers
(e.g. `dilithium-wallet da publish`, `da inspect`) are deferred to
post-mainnet. Until then, third parties can use the trait methods on
`RpcApi` from any Rust binary that links `sophis-rpc-core`.

A minimal in-process inspect script:

```rust
let session = consensus.unguarded_session();
for pid in session.async_da_list_by_block(block_hash).await {
    if let Some(entry) = session.async_da_get_payload(pid).await {
        println!(
            "payload_id={} bundle_id={} blue_score={}",
            hex::encode(pid),
            hex::encode(entry.bundle_id.0),
            entry.blue_score,
        );
    }
}
```

## 12. Pending work

| Sub | Pending |
|---|---|
| 6.4.b | gRPC binding (real `route!()` invocations + proto messages) |
| 6.4.c | wRPC JSON binding (`build_wrpc_client_interface!` ops) |
| 6.5.b | Plumb `current_blue_score` from POV block into `SophisDaBackend` |
| 6.6 | First-party `dilithium-wallet` carrier helpers (deferred post-mainnet) |
| 6.7 | Adversarial devnet scripts |
| 6.8 | Pre-mainnet stress tests (72h devnet at 50% mass saturation) |
| 6.9 | DIY audit + RFC + bug bounty |

## 13. Reference

- Design freeze: `oracle/docs/PHASE6_DA_DESIGN.md`
- Consensus rules: `consensus/core/src/da/mod.rs`, `consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs`
- Codec: `consensus/core/src/da/codec.rs`
- Store: `consensus/src/model/stores/da.rs`
- Pipeline hook: `consensus/src/pipeline/virtual_processor/processor.rs::index_carriers_in_block`
- Sequencer: `rollup/sequencer/src/sequencer.rs`, `rollup/sequencer/src/l1_client.rs::submit_carrier_calldata`
- Relayer: `oracle/relayer/src/config.rs::SubmitSection.da_publish`, `oracle/relayer/src/daemon.rs::one_iteration`
- sVM capability: `svm/core/src/capability.rs`, `svm/runtime/src/host.rs::sophis_verify_da`
- Real backend: `consensus/src/svm_da.rs`
- RPC: `rpc/core/src/api/rpc.rs`, `rpc/core/src/model/da.rs`, `rpc/service/src/service.rs`
