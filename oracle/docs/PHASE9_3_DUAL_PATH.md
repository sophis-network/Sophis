# Phase 9.3 — Dual-Path Source Dispatch (Phase 5 ↔ Phase 9)

> **Status:** spec + SDK helpers frozen; ships in `oracle/pqc-core/src/source.rs`.
> No on-chain coordinator contract in v1 — the dispatch is operator-side
> consensus over public data, deterministically reproducible by any
> independent indexer.
>
> **Originates from:** SIP-11 D11 (migration path).
> **Companion module:** `oracle/pqc-core/src/source.rs`.
> **Future work:** an on-chain announcement contract (Phase 9.3.x
> post-mainnet SIP) if real demand for chain-anchored flip authority
> surfaces.

## 1. Why a dual path

Phase 5 (Pyth singleton + Plonky3 STARK + Dilithium relayer) is the
bootstrap oracle Sophis ships with — it has Pyth's institutional
publisher breadth on day one and verifies attestations cryptographically
inside a STARK. Its residual cost is that the underlying signatures are
ed25519 (a classical-crypto primitive). Phase 9 (per-publisher Dilithium
attestations) closes that residual.

We cannot flag-day-cut over: at mainnet T+0 there are zero Sophis-native
publishers for any feed. Some feeds may never reach Phase 9 quorum
(specialty markets, low-volume pairs). The dual path lets every feed
migrate **independently**, on its own schedule, while both paths remain
operational.

SIP-11 D11 ratifies the migration shape: a feed flips from Phase 5 to
Phase 9 when (a) ≥ 3 Sophis-native publishers are active, (b) they have
been submitting consistently for ≥ 7 days, and (c) their median agrees
with Phase 5 within tolerance (≤ 0.5%).

## 2. Architecture

### 2.1 Inputs

For each feed, an indexer maintains two rolling histories:

- **`phase5_history`** — the latest accepted Phase 5 verifications,
  decoded from the Phase 5 `OracleJournal` events. Each entry is
  `(publish_ts, price_e8)`.
- **`phase9_aggregated_history`** — the **median** of each Phase 9
  publishing round, decoded from the J4 `PriceAttestation` event log
  emitted by `oracle/pqc-contract`. Each entry is `(publish_ts,
  median_price_e8)`. Individual publisher submissions are aggregated
  off-chain into rounds (default round window: 60 s, SIP-11 D4).

The indexer also tracks `phase9_publisher_count` per asset over the
consistency window.

### 2.2 The decision function

`oracle_pqc_core::evaluate_flip(inputs, policy) -> FlipDecision`

Pure, deterministic, idempotent. Same inputs → same output everywhere.
Two independent indexers consuming the same public chain state arrive at
the same `FlipDecision`. This is the entire correctness property the
v1 dispatch relies on; no on-chain coordinator is needed.

`FlipDecision` is one of:

- **`Stay { reason: StayReason }`** — current source remains canonical.
  `StayReason` enumerates why: `BelowQuorum`, `ConsistencyWindowNotReached`,
  `SpreadOutOfBounds`, `OperatorHold`.
- **`Flip`** — all SIP-11 D11 criteria are met; switch this feed's
  active source to Phase 9.
- **`StaleSource { phase5_last_seen_secs_ago }`** — Phase 5 has gone
  silent and Phase 9 has not yet reached quorum; consumers should treat
  the feed as unavailable.

### 2.3 The registry

`InMemoryFeedSourceRegistry` is the operator-side `Map<asset_id,
FeedSource>` that surfaces the current source for consumer SDKs. It is
maintained by the indexer:

1. On every aggregation round (default once per minute), the indexer
   re-runs `evaluate_flip` for every tracked asset.
2. If the decision changes (e.g. `Stay → Flip`), the indexer updates
   the registry entry and emits a "flip notice" in its public API.
3. Consumer SDKs poll the indexer's registry view on a heartbeat and
   cache locally.

A consumer can also run its own indexer + registry — the public chain
state is sufficient input. Multiple indexers SHOULD converge on the
same decisions because `evaluate_flip` is deterministic.

### 2.4 Why no on-chain coordinator in v1

Three reasons:

1. **No authority to vest.** Per Decisão 6 / SIP-11 D3 there is no
   foundation, no curator, no "official" indexer. Putting flip authority
   on-chain would require choosing whose signature is canonical, which
   contradicts the open-permissioned posture.
2. **No contention benefit.** A flip is a once-per-feed event. The
   on-chain registry would serialise all flip events through a single
   UTXO (per-asset or global) for very little gain over indexer-side
   consensus on a deterministic policy.
3. **Soft-fork friendly.** If a future SIP demands chain-anchored flip
   authority, it adds a new announcement contract without invalidating
   v1 indexer behaviour. v1 indexers can ignore the on-chain notices
   they don't yet know about; v2 indexers can prefer them.

A Phase 9.3.x SIP can land an announcement contract later — current
deferred decisions are listed in the source-module doc-comment.

## 3. Operator workflow

For an indexer operator running Phase 9 dispatch:

```text
loop {
    for each tracked asset_id:
        phase5_history    ← latest Phase 5 OracleJournal events
        phase9_history    ← median of latest Phase 9 PriceAttestation rounds
        publisher_count   ← distinct publisher_fingerprint topics in
                            phase9 events over the last 7 days
        decision          ← evaluate_flip(
                                FlipInputs { phase5_history, phase9_history,
                                             phase9_publisher_count: publisher_count,
                                             now: wall_clock() },
                                &FlipPolicy::default()
                            )
        match decision:
            Flip          ⇒ registry.set(asset_id, FeedSource::Phase9 {
                                active_since_ts: wall_clock() })
            Stay { .. }   ⇒ registry stays
            StaleSource   ⇒ registry.set(asset_id, FeedSource::Unavailable)
    publish_registry_snapshot()
    sleep(60s)
}
```

Operators that want a more conservative migration may override
`FlipPolicy` defaults — e.g. `min_publishers: 5`, `min_consistency_
window_secs: 14 * 24 * 3600`. Different policies → different `Flip`
moments across operators; this is acceptable in v1 because consumers
can verify any operator's decision themselves.

## 4. Consumer workflow

For a dApp / wallet / settlement engine reading prices:

```rust
let asset_id = asset_id_from_symbol(b"BTC/USD");
match registry.get(&asset_id) {
    Some(FeedSource::Phase5) => {
        // Read Phase 5 OracleJournal latest event for asset_id
        consume_phase5_price(asset_id)
    }
    Some(FeedSource::Phase9 { active_since_ts }) => {
        // Read Phase 9 PriceAttestation J4 event log; compute median
        consume_phase9_median(asset_id, active_since_ts)
    }
    Some(FeedSource::Unavailable) => {
        // Feed temporarily unavailable; consumer-side fallback policy
        // (refuse to act on stale data, surface error to user, etc.)
        bail!("oracle feed unavailable")
    }
    None => {
        // Asset not tracked by this registry
        bail!("asset not registered")
    }
}
```

The consumer SHOULD verify the registry's claim independently when
making a high-value decision: re-fetch `phase5_history`,
`phase9_history`, and `phase9_publisher_count` from the chain, run
`evaluate_flip` locally, and refuse to proceed if the result disagrees
with the registry's claim. This makes the indexer un-trusted from the
consumer's perspective.

## 5. Spread tolerance computation

The 50 bp default (SIP-11 D11) is computed as a per-sample check, not a
window aggregate:

For every Phase 9 sample in the consistency window, the policy finds
the **nearest Phase 5 sample** (within `stale_after_secs` proximity) and
verifies the two are within `max_spread_bp` of each other. A single
out-of-bounds pair fails the spread check. This is conservative — even
brief disagreements postpone the flip.

If no Phase 5 sample is close enough to a Phase 9 sample (gap > 5
minutes, the default `stale_after_secs`), the spread check fails closed.
This catches the case where Phase 5 has been silent for stretches inside
the otherwise-acceptable window.

## 6. Stale-source semantics

If Phase 5 has not produced a sample in the last `stale_after_secs`
seconds **and** Phase 9 has not yet reached quorum (fewer than
`min_publishers` registered OR the consistency window not yet
satisfied), `evaluate_flip` returns
`FlipDecision::StaleSource { phase5_last_seen_secs_ago }`. The registry
sets the feed to `FeedSource::Unavailable` and consumers refuse to act.

This is the only "fail-closed" pathway in v1 dispatch. Operators MUST
NOT silently fall back to a stale Phase 5 sample.

## 7. Edge cases pinned by the tests

The Phase 9.3 module ships with eight unit tests (see
`oracle/pqc-core/src/source.rs::tests`). They pin:

1. Default `FlipPolicy` values match SIP-11 (3 publishers, 7 days, 50 bp, 5 min).
2. 50 bp spread tolerance is enforced symmetrically (price ± 0.5%).
3. Zero / negative reference prices fall back to exact equality (no div-by-zero).
4. `BelowQuorum` returned when fewer than 3 active publishers.
5. `ConsistencyWindowNotReached` when Phase 9 has < 7 days of history.
6. `SpreadOutOfBounds` when Phase 9 median diverges from Phase 5 by > 50 bp.
7. `Flip` only when all three D11 criteria are simultaneously satisfied.
8. `StaleSource` when Phase 5 silent + Phase 9 below quorum.
9. Empty histories on both paths → `StaleSource`.
10. `InMemoryFeedSourceRegistry` set / get / overwrite / iter behaviour.
11. `FeedSource` borsh roundtrip preserves all three variants.

## 8. Out of scope for Phase 9.3 v1

- **On-chain flip announcement contract.** Reserved for a Phase 9.3.x
  post-mainnet SIP if real demand surfaces.
- **Cross-source weighted aggregation.** v1 picks ONE source per feed
  at a time. A future SIP may add `FeedSource::Hybrid` that combines
  both paths with publisher-specific weighting.
- **Reputation-weighted Phase 9 medians.** SIP-11 D12 v2 work; v1
  uses equal-weight median per round.
- **Cross-indexer disagreement resolution.** v1 expects indexers to
  converge on the deterministic policy; if they don't, consumers
  verify independently.

## 9. Relationship to the Phase 9 series

| Slice | Provides | Consumed by |
|---|---|---|
| 9.0 Foundation | `PriceAttestation` wire format, sign/verify helpers | publisher + contract + indexer |
| 9.1 Submission contract | on-chain validation + J4 event emission | indexer (event ingestion) |
| 9.2 Publisher CLI | per-operator signed attestations | submitted to 9.1 contract |
| **9.3 Dual-path** | `FeedSource` + `evaluate_flip` + registry | indexer dispatch + consumer SDK |
| 9.5 Reference indexer | `oracle/pqc-indexer` — deterministic core (round median D4 + quorum D6 + `evaluate_flip` dispatch + price/source registry) + `sophis-oracle-indexer` bin | operators (use/extend instead of writing a watcher from scratch) |
| 9.4 End-to-end tests | full pipeline coverage | CI / pre-testnet acceptance |

Phase 9.3 is the **consumer-side glue** that makes Phase 5 and Phase 9
coexist gracefully during migration. It does not add any new
cryptographic primitives or contract code — the dispatch is a policy
function over public chain state.
