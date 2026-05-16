# Phase 9 PQC-Native Oracle — Operator RUNBOOK

> **Scope:** the operational playbook a publisher, indexer operator,
> or consumer integrator needs to run Phase 9 in production. Companion
> to the SIP-11 specification (`SIPS/SIP-11-PQC-ORACLE.md`), the design
> doc (`docs/PQC_NATIVE_ORACLE_DESIGN.md`), and the dual-path dispatch
> doc (`oracle/docs/PHASE9_3_DUAL_PATH.md`).
>
> **Status:** pre-testnet. All four implementation slices (9.0–9.4)
> shipped. Operators reading this RUNBOOK are bootstrapping for testnet
> launch.

## 1. Roles

| Role | What they run | What they need |
|---|---|---|
| Publisher | `sophis-oracle-publisher` CLI | BIP-39 mnemonic, price feed source (CEX API, on-prem market data), wallet-side tool that wraps signed bytes into Sophis transactions |
| Indexer operator | **Reference indexer `oracle/pqc-indexer`** (`sophis-oracle-indexer` bin) — deterministic round-median (D4) + quorum (D6) + `evaluate_flip` dispatch + price/source registry. Use/extend it instead of writing a watcher from scratch; the live-node J4 subscription is the operator's thin adapter seam (out of v1 core, exactly as `pqc-publisher` punts submission to `dilithium-wallet`) | Sophis full node, persistent storage for event log, public HTTP/RPC surface |
| Consumer integrator | Their dApp / wallet / settlement engine | Indexer URL OR Sophis full node (for self-verification) |

A single party may wear multiple hats. The architecture is permissionless;
no role grants authority over another's behaviour.

## 2. Publisher operations

### 2.1 Key generation

```bash
# 1. Generate a BIP-39 mnemonic (offline machine, no network)
dilithium-wallet new --output mnemonic.txt
# 24 words are written to mnemonic.txt; back it up physically (paper, 2 locations)
# and DESTROY any digital copies once the paper backup is verified.

# 2. Derive the Dilithium pubkey for registry use
sophis-oracle-publisher keygen \
  --mnemonic-file mnemonic.txt \
  --output-pubkey publisher.pubkey
# publisher.pubkey is 1312 bytes; share this freely (it goes into the indexer's
# registered-publisher set). NEVER share the mnemonic.
```

The mnemonic stays offline. The publisher daemon either:

- reads the mnemonic each invocation (operationally simplest, but the
  mnemonic touches the daemon's filesystem), OR
- pre-derives the 2560-byte signing key once via
  `sophis-oracle-publisher keygen --output-signing-key publisher.sk`
  (chmod 0600 on Unix) and the daemon reads only the signing key.

Either is acceptable; the trade-off is mnemonic exposure vs raw-key
exposure on the daemon host.

### 2.2 Signing schedule

Recommended baseline cadence per asset:

- 1 attestation per minute for high-priority feeds (BTC/USD, ETH/USD)
- 1 attestation per 10 minutes for medium-priority feeds
- 1 attestation per hour for low-volume feeds

Higher cadences are permitted up to the SIP-11 D8 rate limit (1
submission per publisher per asset per 10 s).

Sequence-number policy: monotonic per (publisher, asset). Operators
SHOULD persist the last-used sequence to a local file and increment
on every signed attestation. If the daemon crashes mid-cycle, restart
with the next-after-last-persisted value — duplicates with the same
sequence are dropped by the indexer (see § 5.3).

### 2.3 Submission

`sophis-oracle-publisher sign` emits hex on stdout. Wrap it into a
transaction:

```bash
ATTESTATION_HEX=$(sophis-oracle-publisher sign \
  --mnemonic-file mnemonic.txt \
  --asset BTC/USD \
  --price 65432.10 \
  --conf 50.00 \
  --sequence "$(cat seq.btc.txt)")
echo $((1 + $(cat seq.btc.txt))) > seq.btc.txt

# Pipe into the wallet-side submitter (operator's choice of tool):
dilithium-wallet send-raw \
  --to-contract <phase9-contract-address> \
  --payload-hex "$ATTESTATION_HEX"
```

The wallet pays the tx fee from the publisher's SPHS balance.
Publishers SHOULD keep a small SPHS float on the publisher wallet for
this; replenish from cold storage as needed.

### 2.4 Cost expectation

At a Dilithium signature of 2,420 bytes + a 1,312-byte pubkey + ~200
bytes of tx framing, each submission costs ~4 KB of block space. At
typical mainnet fee rates, the per-attestation fee is dominated by the
storage mass; cap your budget accordingly.

## 3. Indexer operations

### 3.1 Event ingestion

Subscribe to J4 events with `topic[0] = event_id_phase9_attestation()`
(the canonical Phase 9 event tag — see § 3.2). For each event:

1. Decode the event-data payload (32 bytes) into `EventDataV1`.
2. Decode the spending input UTXO's `script_public_key.script` into a
   full `PriceAttestation`.
3. Verify the Dilithium signature against the canonical Phase 9 domain
   separator using `oracle_pqc_core::verify_attestation`.
4. Look up the publisher fingerprint (`topic[2]`) in the operator's
   registered-publisher allowlist. Drop events from non-registered
   publishers.
5. Check the (publisher, asset, sequence) dedup key against the
   indexer's local store. Drop duplicates.
6. Insert into the per-asset rolling history.

### 3.2 Canonical event id

```rust
use sha3::{Digest, Sha3_384};
let mut hasher = Sha3_384::new();
hasher.update(b"sophis-oracle-pqc-v1/PriceAttestation");
let event_id: [u8; 32] = hasher.finalize()[..32].try_into().unwrap();
```

Indexers that prefer not to depend on `sophis-oracle-pqc-contract`
can derive the constant locally. The Phase 9 integration tests
include a "decoupled derivation" assertion that pins the result.

### 3.3 Aggregation rounds (per-asset)

Default round window: 60 seconds (SIP-11 D4). For each asset, every
round:

1. Collect all accepted attestations whose `publish_ts ∈ [round_start,
   round_end]`.
2. If count < `min_quorum` (3 by default), the round produces no
   aggregate; emit a "below quorum" notice.
3. Otherwise compute the median of `price_e8` values; that is the
   round's canonical Phase 9 price.
4. Append to `phase9_aggregated_history` for the asset.

### 3.4 Dispatch evaluation

Once per round (or on a heartbeat — your choice), for each tracked asset:

```rust
let inputs = FlipInputs {
    phase5_history: &phase5_recent,
    phase9_aggregated_history: &phase9_recent,
    phase9_publisher_count: indexer.distinct_publishers_for(asset_id),
    now: wall_clock_secs(),
};
let decision = evaluate_flip(inputs, &FlipPolicy::default());
match decision {
    FlipDecision::Stay { reason } => log::debug!("{asset_id}: stay ({reason:?})"),
    FlipDecision::Flip => {
        log::info!("{asset_id}: flipping Phase 5 → Phase 9");
        registry.set(asset_id, FeedSource::Phase9 { active_since_ts: wall_clock_secs() });
    }
    FlipDecision::StaleSource { phase5_last_seen_secs_ago } => {
        log::warn!("{asset_id}: stale source ({phase5_last_seen_secs_ago}s ago)");
        registry.set(asset_id, FeedSource::Unavailable);
    }
}
```

Publish the resulting registry as a stable HTTP/RPC artifact —
consumers poll it on a heartbeat. Operators MAY publish their flip
history (Phase 5 → Phase 9 transitions with timestamps + reason)
as a separate artifact for transparency.

### 3.5 Storage budget

Per asset per year at 1 attestation per minute per publisher with
5 publishers:

- 525,600 attestations / minute × 5 = 2,628,000 attestations / year
- 4 KB each → 10.5 GB / year per asset on raw bytes
- Indexers should compress + index by `(asset, publisher_fingerprint,
  sequence)`; rolling retention of 30–90 days is sufficient for the
  dispatch policy (the 7-day consistency window is the only on-line
  dependency).

## 4. Consumer integration

### 4.1 Reading prices

```rust
let registry: Box<dyn FeedSourceRegistry> = fetch_registry_from_indexer();
let asset_id = asset_id_from_symbol(b"BTC/USD");

match registry.get(&asset_id) {
    Some(FeedSource::Phase5) => {
        let (price_e8, conf_e8, ts) = indexer.read_phase5(asset_id);
        // use price; honour conf as 1-sigma uncertainty
    }
    Some(FeedSource::Phase9 { .. }) => {
        let (price_e8, conf_e8, ts) = indexer.read_phase9_median(asset_id);
        // identical wire shape; consumers can be source-agnostic
    }
    Some(FeedSource::Unavailable) | None => {
        // refuse to act on unavailable feed
    }
}
```

### 4.2 Verification recommendation

For any decision worth more than the cost of running an extra check
(liquidations, settlements, treasury operations), consumers SHOULD
verify the indexer's claim:

1. Re-fetch the Phase 5 history and Phase 9 aggregated history from a
   Sophis full node directly.
2. Re-fetch `phase9_publisher_count` from the J4 event log directly.
3. Run `evaluate_flip` locally with the SIP-11 default `FlipPolicy`.
4. Compare the local decision against the indexer's registry. If they
   disagree, refuse to proceed and surface the divergence.

This is the security property the v1 architecture relies on: no
indexer is trusted; consumers re-derive the canonical truth from
public chain state on demand.

### 4.3 Staleness handling

Always treat `last_aggregated_at` as load-bearing. A round older than
your tolerance (5 minutes by default, but tune per asset) MUST be
rejected — DO NOT silently fall back to the most recent successful
round.

## 5. Migration playbook

### 5.1 Pre-flip

For each feed:

1. Ensure ≥ 3 publishers are registered and submitting on the asset.
2. Watch `phase9_aggregated_history` stay within 50 bp of Phase 5 for
   7 consecutive days.
3. Run `evaluate_flip` continuously; once it returns `Flip`, you are
   ready.

The 7-day window is **soft** in v1 — operators MAY publish their
flip decision earlier with a custom `FlipPolicy` (e.g. for testnet
where 7 days is impractical), but SHOULD use the SIP-11 default on
mainnet unless there is a documented operational reason.

### 5.2 The flip

The flip is purely an indexer config change:

```rust
registry.set(asset_id, FeedSource::Phase9 { active_since_ts: wall_clock_secs() });
```

Publish the updated registry. Optionally emit a public notice (blog,
status page, public IRC channel). Consumers that poll the registry on
a heartbeat pick up the change within their poll interval.

### 5.3 Post-flip: deprecation period

After flip, Phase 5 continues to ingest in parallel. The indexer
SHOULD:

- Continue computing the Phase 5 / Phase 9 spread; surface
  divergences > 50 bp as warnings.
- Track `phase9_publisher_count`; if it falls below quorum, revert
  the feed to `FeedSource::Phase5` and announce.
- Periodically run a sanity check that the Phase 5 path is still
  cryptographically intact (the underlying STARK still verifies).

Hard removal of Phase 5 is a separate future SIP (not Phase 9.4).

## 6. Monitoring

Operators SHOULD instrument and alert on:

| Signal | Threshold | Action |
|---|---|---|
| Phase 5 last-seen age | > 5 minutes | Investigate Pyth → relayer path |
| Phase 9 publisher count for active asset | < 3 | Fall back to Phase 5 (deprecated 2026-05-11; recruit publishers to restore Phase 9 quorum and remove the fallback) |
| Phase 9 / Phase 5 spread | > 50 bp sustained | Investigate publisher misbehaviour |
| Indexer registry divergence (peers disagree) | any | Re-run `evaluate_flip` from raw chain state |
| Publisher submission rate | drops to 0 for > 1 hour | Publisher down — alert publisher operator |
| Same-sequence duplicate rate | > 10% of submissions | Publisher misconfigured or attempting replay |

## 7. Incident response

### 7.1 Suspected publisher key compromise

1. Publisher revokes the compromised key from their registry record
   (operationally — there is no on-chain revocation in v1; the indexer's
   registered-publisher list is the source of truth).
2. Operator opens an incident on the public status page documenting
   the suspected window of compromise.
3. Indexer flags all submissions from the compromised pubkey within
   the window as untrusted; consumers SHOULD re-evaluate their reliance
   on the affected asset's median for that window.
4. Publisher generates a new mnemonic + key, re-registers, resumes.

### 7.2 Phase 5 path goes silent during migration

If Phase 5 goes stale BEFORE Phase 9 reaches quorum, the feed enters
`FeedSource::Unavailable`. Operators should:

1. Investigate the Pyth → relayer → STARK path; restore Phase 5 if
   possible.
2. If Phase 5 is permanently broken, accelerate Phase 9 quorum:
   recruit more publishers, lower `min_publishers` only via an
   operator override in `FlipPolicy` (rare; document the override).
3. Once Phase 9 quorum is reached, flip even though the 7-day window
   was not fully observed — document the policy override on the
   public status page.

### 7.3 Indexer divergence

Two indexers disagreeing on `FeedSource` for the same asset is a v1
race condition, not a security failure. Consumers detect the divergence
during their verification step (§ 4.2) and refuse to act on the
affected feed until indexers converge. Operators should reconcile by:

1. Running the same `FlipPolicy` defaults.
2. Confirming both indexers see the same registered-publisher set.
3. Confirming both indexers compute the same aggregated history.
4. Publishing the resolved decision; consumers re-poll.

## 8. References

- `SIPS/SIP-11-PQC-ORACLE.md` — formal SIP
- `docs/PQC_NATIVE_ORACLE_DESIGN.md` — technical design
- `oracle/docs/PHASE9_3_DUAL_PATH.md` — dispatch policy details
- `oracle/pqc-core/src/source.rs` — `FlipPolicy` + `evaluate_flip` reference
- `oracle/pqc-publisher/src/main.rs` — CLI source
- `oracle/pqc-contract/src/lib.rs` — submission validator contract
- `oracle/pqc-tests/src/scenarios.rs` — end-to-end pipeline tests
