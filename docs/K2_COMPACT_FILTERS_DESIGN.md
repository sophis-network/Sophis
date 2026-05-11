# K2 — Compact Block Filters (BIP-157/158-equivalent)

> **Status:** design frozen for sub-fase K2.0 — ready for K2.1 implementation.
> **Originating roadmap:** Roadmap K (Bitcoin lessons), item K2.
> **Companion docs:** future `docs/K2_RUNBOOK.md` (deferred follow-up)
> and `SIPS/SIP-6-COMPACT-FILTERS.md` (also deferred follow-up; not
> part of K2 v1 ship).
> **Pre-existing baseline:** **none**. Sophis ships today with no
> filter infrastructure for light clients. Verified 2026-05-10 via
> grep across `consensus/` and `rpc/`.

## 1. Motivation

Every modern blockchain that supports light clients ships a per-block
*compact filter* — a small probabilistic data structure that lets a
client check "does this block contain anything relevant to my
addresses?" without downloading the block body OR revealing which
addresses it cares about.

- **Bitcoin** ships BIP-158 basic filters (Golomb-Rice coded over
  scriptPubKeys) and BIP-157 P2P fetch protocol. Production deployed
  since Bitcoin Core 0.19 (2019). Replaced the privacy-broken BIP-37
  bloom filters.
- **Ethereum** ships per-block bloom filters (Yellow Paper §4.4.4) for
  log filtering — different use case but same role.
- **Sophis** has nothing. A light client (J5, deferred) cannot work
  efficiently without K2 first.

Without compact filters:

- **Light clients must either trust a full node** ("show me txs for
  this address") — privacy-broken; or **download every block** —
  bandwidth-broken.
- **Wallet sync from a deep checkpoint** has to walk every chain
  block linearly, parsing every tx, looking for known SPKs. ~ten
  minutes of CPU per million blocks even on a fast machine.
- **dApps that want "show me when any address in this set sees
  activity"** have to poll `getBlock` per chain block; no
  query-side index exists.

K2 solves the *structural* problem: per-block deterministic Golomb-Rice
filter computed by the consensus layer, served via RPC, with a header
chain so a client can verify a filter against the chain it already
trusts (via L3 commitment levels). The light client itself (J5) and
the P2P fetch protocol (analogous to BIP-157) are deferred — K2 ships
the in-process pieces a future light client will need.

This is item #8 in the sequential roadmap (`project_roadmap_sequence_2026_05_09.md`)
and the second-largest deliverable on the list (~2-4 weeks original
estimate, condensed to a single bundle here following recent rhythm).

## 2. Ratified design decisions

These decisions were committed by the founder on 2026-05-10 and are
frozen for the K2 implementation. Re-opening any of them requires a
new SIP.

| ID | Question | Choice | Rationale |
|----|----------|--------|-----------|
| **D1** | Filter format | Golomb-Rice coded set, parameter `P = 19` (i.e. `M = 2^19 = 524 288` per item) | Matches BIP-158 verbatim. ~20 bits per element gives a false positive rate of 1/M ≈ 1.9 × 10⁻⁶ per query. Filter sizes fall around 20-40 KB per saturated chain block at Sophis BPS — well within reach of mobile bandwidth. |
| **D2** | Hash function | `SHA3-384(b"sophis-cf-v1\0" \|\| block_hash \|\| item)[..8]` (8-byte truncation interpreted as u64 big-endian) | PQC-aligned with the rest of Sophis (J2/J3/J4 all use SHA3-384 truncated). Domain separator `b"sophis-cf-v1\0"` (13 bytes including the trailing null) prevents cross-subsystem collision and locks the version. Per-block keying via `block_hash` is the BIP-158 idea minus the SipHash dependency. |
| **D3** | Filter content | Every output's `script_public_key.script()` for every accepted tx in the block, plus every input's `previous_outpoint`-resolved `script_public_key.script()`. Coinbase output SPKs included. Coinbase inputs (none) excluded by definition. | Identical scope to BIP-158 "basic" filter: lets a wallet detect both incoming receives (output match) and outgoing spends (input match). v=1 ALT-reference outputs (script[0]=0xFD) hash their *raw 8-byte reference bytes*, not the resolved SPK — light clients that care about ALT-resolved spends do an extra `getAltEntry` lookup. v=5 DA carrier outputs ARE included (they have observable scripts even if non-spendable). |
| **D4** | Per-block filter header chain | `filter_header(block) = SHA3-384(filter_header(prev_block) \|\| filter_hash(block))[..32]`, with `filter_header(genesis_parent) = [0u8; 32]` | Mirrors BIP-157 §"Filter Headers". A light client trusting a recent `(block_hash, filter_header)` pair can verify any subsequent filter by walking forward through the header chain — no re-download of older filters. Header is 32 bytes; chain costs ~32 bytes per block (`32 × 10 BPS × 86400 ≈ 28 MB/day`, archival-friendly). |
| **D5** | Storage | Two RocksDB prefixes: `BlockFilters = 207` (block_hash → bytes), `BlockFilterHeaders = 208` (block_hash → 32 bytes) | Mirrors the L1 ALT (200-202), Phase 6 DA (196-199), J4 events (203-206) prefix-allocation pattern. Filters are append-only at index time; pruning removes them alongside the block body (filters are not archival, the header chain alone is enough for SPV resync). |
| **D6** | RPC shape | Two methods: `getBlockFilter(block_hash)` returns `Option<RpcBlockFilter>`; `getBlockFilterHeader(block_hash)` returns `Option<RpcBlockFilterHeader>` | Two separate methods (vs one combined response) lets a syncing light client fetch headers cheaply (~32 bytes/block) before deciding which full filters to fetch. Standard BIP-157 pattern. Batch fetch is a separate future RPC. |
| **D7** | P2P propagation | **Out of scope for K2.** Filters are computed locally by every full node from the chain it already has; cross-node propagation is unnecessary for the v1 use case (RPC fetch from a trusted full node). Light-client-vs-light-client propagation (BIP-157 messages) defers to J5 / a separate SIP. | Bitcoin's BIP-157 P2P messages (`cfheaders`, `cfilter`, `cfcheckpt`) are needed only when light clients ask other light clients for filter data. The Sophis v1 model is "light client connects to a full node via RPC", same as Electrum/Esplora today. P2P propagation can be added later without breaking the wire format or storage. |

## 3. Wire format

### 3.1 Filter content extraction

For a chain block `B` accepted by the GHOSTDAG selected chain:

```text
items = []
for tx in B.transactions:
    for output in tx.outputs:
        items.append(output.script_public_key.script())   // raw script bytes
    for input in tx.inputs:
        if input.previous_outpoint != null:               // skip coinbase
            spent_utxo = utxo_view[input.previous_outpoint]
            items.append(spent_utxo.script_public_key.script())
```

Items are NOT deduplicated before encoding (BIP-158 sorts + dedupes
before encoding; we follow that to keep filters smaller). Empty items
(zero-length scripts) are dropped to avoid trivial false-positive
inflation.

### 3.2 Hash mapping (BIP-158 §"Set-membership filter")

Each item is mapped to a `u64` modulo `N · M` where `N = items.len()`
and `M = 2^P = 524 288`:

```text
fn h(item: &[u8], block_hash: &Hash) -> u64 {
    let mut hasher = Sha3_384::new();
    hasher.update(b"sophis-cf-v1\0");      // 13 bytes
    hasher.update(block_hash.as_bytes());  // 32 bytes
    hasher.update(item);
    let digest = hasher.finalize();
    u64::from_be_bytes(digest[..8].try_into().unwrap())
}

let mapped: Vec<u64> = items.iter()
    .map(|it| {
        let raw = h(it, block_hash);
        // Map u64 → [0, N · M)
        ((raw as u128) * (N as u128 * M as u128) >> 64) as u64
    })
    .collect();
mapped.sort();
mapped.dedup();
```

The `>> 64` map is BIP-158's approach to uniform reduction without
modulo bias.

### 3.3 Golomb-Rice encoding

For each successive value `v_i`, encode `delta_i = v_i - v_{i-1} - 1`
(with `v_{-1} = -1`) as Golomb-Rice with parameter `P`:

```text
quotient  = delta >> P    // unary: `quotient` 1-bits then a 0-bit
remainder = delta & ((1 << P) - 1)   // P-bit binary
output    = quotient_unary || remainder_binary
```

The full filter on the wire is `serialise(N) || gr_bitstream`, where
`serialise(N)` is the BIP-158 compact-size encoding (1 byte if N < 253,
3 bytes if N < 2^16, …).

### 3.4 Filter hash

```text
filter_hash(B) = SHA3-384(filter_bytes(B))[..32]
```

Plain SHA3-384 of the on-the-wire filter bytes, truncated to 32. Used
as the input to the filter header chain.

### 3.5 Filter header chain

```text
filter_header(B) = SHA3-384(
    filter_header(prev(B)) ||
    filter_hash(B)
)[..32]

filter_header(GENESIS_PARENT) = [0u8; 32]
```

`prev(B)` is the GHOSTDAG selected-parent of `B`. The chain mirrors
BIP-157 §"Filter Headers" exactly, with SHA3-384 in place of double
SHA-256.

### 3.6 Wire encoding (RPC)

```text
RpcBlockFilter {
    block_hash:   RpcHash,
    filter_bytes: Vec<u8>,   // raw on-the-wire filter (compact-size + GR)
    filter_hash:  Vec<u8>,   // 32 bytes
}

RpcBlockFilterHeader {
    block_hash:    RpcHash,
    prev_header:   Vec<u8>,  // 32 bytes (filter_header of selected parent)
    filter_hash:   Vec<u8>,  // 32 bytes
    filter_header: Vec<u8>,  // 32 bytes (this block's filter_header)
}
```

Both responses are wrapped in `Option` (proto3-style: 0 or 1 element
in a `repeated` field).

## 4. Threat model

| ID | Threat | Mitigation |
|----|--------|------------|
| T1 | Eclipse: adversary serves a forged filter to the victim | Out of scope at the protocol layer. Light clients verify filters against the filter header chain, which they verify against the GHOSTDAG block header chain (which they verify against PoW work). Eclipse defenses are at the P2P / sync layer. |
| T2 | False-positive inflation: adversary stuffs a block with txs whose SPKs collide-by-design with the victim's known SPKs | Bounded by Golomb-Rice false-positive rate `1/M ≈ 1.9 × 10⁻⁶`. Per-item attacker work is ~2²⁰ SHA3-384 evaluations to find one collision; per-block content is bounded by mempool acceptance rules. Net effect: maybe 1-2 spurious "matches" per block under sustained adversarial spam. Acceptable. |
| T3 | Privacy leak via filter request pattern | Out of scope for K2. Light clients hide their address sets behind the false-positive cushion; nodes serving filters see "block_hash query" patterns, which are inherent to *any* SPV protocol. Mitigated by per-client rotation across multiple full nodes. |
| T4 | Determinism failure: two nodes compute different filters for the same block | Cannot happen by construction. Inputs are (a) raw script bytes from chain state (deterministic), (b) `block_hash` (deterministic), (c) the SHA3-384 derivation chain (deterministic). |
| T5 | Filter computation cost stalls block validation | Filter is computed in `commit_utxo_state` AFTER UTXO validation completes, in the same `WriteBatch` as the carrier / ALT / event indexing. Cost is O(items_in_block × SHA3-384), ~milliseconds even at saturated blocks. Failures are non-fatal (warn + continue), mirroring carrier / ALT / event indexing. |
| T6 | PQC posture loss | K2 uses SHA3-384 throughout (existing primitive). No new cryptographic dependency. PQC posture preserved. |
| T7 | Header chain forks during reorg | Filter header is recomputed for every accepted chain block. On reorg, the new chain block's `prev_header` resolves to the new selected parent's filter header, so the chain re-derives correctly. Light clients that cached headers from a now-reorg'd chain see a mismatch on the next sync and re-fetch from the divergence point. |

## 5. Comparison vs alternatives

| System | Format | Hash | Privacy | Per-block bytes | Light-client-friendly |
|--------|--------|------|---------|-----------------|------------------------|
| Bitcoin BIP-37 (deprecated) | Bloom filter | Murmur3 | broken (server learns set) | varies | yes-but-broken |
| Bitcoin BIP-158/157 | Golomb-Rice | SipHash-2-4 keyed by block | strong (server sees only block_hash) | 20-40 KB | yes |
| Ethereum block bloom | Bloom (per-tx logs) | keccak256 | strong | 256 bytes (fixed) | yes (logs only) |
| **Sophis K2** | Golomb-Rice (P=19) | SHA3-384 keyed by block | strong | 20-40 KB | yes |

K2 is the BIP-158 model with the SipHash → SHA3-384 swap. Wire format
stays compatible at the Golomb-Rice layer — Bitcoin tooling that knows
how to decode Golomb-Rice can decode Sophis filters once it knows the
hash function.

## 6. Out-of-scope (for K2)

- **Light client implementation (J5)** — separate roadmap item;
  K2 ships the storage + RPC pieces a future J5 will consume.
- **P2P propagation (BIP-157 cfheaders/cfilter/cfcheckpt messages)** —
  defer until a real light-client population exists. Full nodes
  compute filters from local chain state.
- **Filter type registry** — only "basic" filter (D3) in v1.
  Extended filter types (e.g. "all witness data", "all OP_RETURN
  payloads") can be added later without breaking v1.
- **Range / batch RPC** (`getBlockFilters(start_hash, count)`) —
  single-block fetch in v1; batch can be added without changing the
  per-block format.
- **Pruning policy** — filter bytes are pruned alongside the block
  body. Filter headers (32 bytes each) are kept indefinitely.

## 7. Frozen ABI surface

| Item | Value |
|------|-------|
| Domain separator | `b"sophis-cf-v1\0"` (13 bytes including trailing null) |
| Hash function | SHA3-384 truncated to 8 bytes (filter content) and 32 bytes (filter hash + header chain) |
| Golomb-Rice parameter | `P = 19` (`M = 524 288`) |
| `RpcApiOps::GetBlockFilter` | `159` |
| `RpcApiOps::GetBlockFilterHeader` | `160` |
| RocksDB prefix `BlockFilters` | `207` |
| RocksDB prefix `BlockFilterHeaders` | `208` |
| gRPC oneof slots | request 1130/1132, response 1131/1133 |
| Crate name | `sophis-compact-filters` (path: `wallet/filters`) |

## 8. Reference implementation map

| Sub-fase | Scope |
|---------|-------|
| K2.0 | This design document |
| K2.1 | `wallet/filters` new crate — Golomb-Rice encode/decode + filter builder + tests |
| K2.2 | `consensus/src/model/stores/block_filters.rs` — RocksDB store with prefixes 207/208 |
| K2.3 | `index_filters_in_block` commit hook in virtual_processor (parallel to carriers/ALT/events) |
| K2.4 | `ConsensusApi::get_block_filter` + `get_block_filter_header` defaults + Consensus impl + session wrappers |
| K2.5 | `rpc-core::model::filters` types + `RpcApiOps::GetBlockFilter/Header` + service impl + 2 mock stubs |
| K2.6 | gRPC binding (proto + ops + conversions + route + factory) + wRPC binding (server router + client macro) + integration test |
| K2.7 | Workspace check + clippy strict + single commit |

## 9. Glossary

| Term | Meaning |
|------|---------|
| Compact filter | A small probabilistic data structure committing to a set of items (here: SPKs in a block); supports membership queries with bounded false-positive rate. |
| Golomb-Rice coding | Variable-length integer encoding optimised for geometric distributions; encodes `delta = quotient × 2^P + remainder` as `unary(quotient) || binary(remainder, P bits)`. |
| Filter hash | `SHA3-384(filter_bytes)[..32]` — 32-byte commitment to one block's filter. |
| Filter header | `SHA3-384(prev_header || filter_hash)[..32]` — running 32-byte commitment to all filters up to and including this block. The header chain is what light clients verify, not individual filters. |
| Basic filter | BIP-158 nomenclature for the "every output SPK + every input SPK" filter shape (D3). Sophis v1 ships only the basic filter. |
| False-positive rate | `1/M = 1/524288 ≈ 1.9 × 10⁻⁶` per individual membership query. |
