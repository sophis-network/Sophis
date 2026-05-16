# PQC-Native Oracle — Design

> **Status:** spec frozen this session; foundation crate (`oracle/pqc-core`)
> ships in this PR alongside this doc and SIP-11. Aggregator contract,
> publisher CLI, dual-path Phase 5 deprecation, and pipeline integration
> tests ship in follow-up sessions — **all pre-testnet**.
>
> **Replaces / deprecates:** Phase 5 ZK-Oracle Aggregator (Pyth singleton +
> Plonky3 STARK + Dilithium relayer). Phase 5 remains for read-only feeds
> during the migration window; Phase 9 supersedes it for any feed where a
> Sophis-native publisher set is registered.
>
> **Originating analysis:** the deep PQC audit completed in cleanup round 8
> identified the residual exposure: Phase 5 verifies ed25519 signatures
> (from Pyth publishers) inside a Plonky3 STARK. The STARK itself is
> PQC-safe (BabyBear + Poseidon2 + FRI) but it transitively trusts the
> ed25519 chain — a quantum adversary that breaks ed25519 can forge Pyth
> signatures, which the relayer accepts, which then aggregate into a
> STARK that "correctly" proves verification of forged data. Sophis L1
> chain integrity is unaffected (Dilithium-only); only oracle feed
> truthfulness is at risk. Phase 9 closes this exposure by replacing the
> Pyth path with a Sophis-native publisher network signing each update
> with Dilithium ML-DSA-44.

## 1. Motivation

Phase 5 was built on the only oracle pattern available in 2026: pull
Pyth feeds, prove ed25519 verification inside a STARK, aggregate. It
ships and works. It is also the last classical-crypto trust dependency
in the Sophis stack — and the only one that would cost the chain any
real economic value (oracle feed corruption → DeFi liquidation /
settlement errors → user funds at risk) if classical signatures fall.

A Sophis-native oracle removes that dependency by having publishers
sign updates directly with Dilithium ML-DSA-44 and submit them as
ordinary on-chain transactions. The aggregator contract (sVM) collects
submissions within a time window and reports the median to consumers.

Trade-offs are honest:

- **Loses Pyth breadth.** Pyth has ~80 institutional publishers (Jane
  Street, Jump, Wintermute, exchanges). Sophis Phase 9 starts with
  whoever runs a Sophis-native publisher binary. Day-zero quality of
  the median price is bounded by who shows up.
- **Block bandwidth grows linear in N publishers × M feeds.** A
  Dilithium ML-DSA-44 sig is 2,420 bytes; a `PriceAttestation`
  transaction is ≈4 KB. Pyth's STARK aggregates 80×200 sigs into one
  ≈10 KB proof. Sophis Phase 9 cannot match that density without a
  separate aggregation layer (deferred to Phase 9.x as Dilithium STARK
  chips mature).
- **Cost per update falls on the publisher.** Each publisher pays its
  own tx fee. There is no relayer amortising verify cost across feeds.

These are the costs of removing the ed25519 trust line. They are
aligned with the rest of the Sophis posture: small, sovereign,
PQC-pure, no foundation, no curated publisher curation.

## 2. Ratified design decisions

These decisions are committed for Phase 9 v1 and frozen for the wire
format published in `oracle/pqc-core` (this PR). Re-opening any of
them requires a new SIP.

| ID  | Question | Choice | Rationale |
|-----|----------|--------|-----------|
| **D1** | Per-publisher signing vs STARK aggregation | **Per-publisher direct signing** for v1; STARK aggregation deferred to Phase 9.x once Dilithium STARK chips are practical | Dilithium STARK chips today would be 10-100× the prover cost of ed25519 chips (rejection sampling + NTT). Direct submission is implementable in weeks, not months, and uses primitives Sophis already has (`Capability::VerifyDilithium`). |
| **D2** | Signature scheme | **Dilithium ML-DSA-44** (FIPS 204), same parameter set as L1 consensus signatures | Single PQC primitive across the stack. ML-DSA-44 gives 128-bit post-quantum security; sig size 2,420 bytes; pubkey 1,312 bytes. Reusing the consensus primitive means one auditable crypto surface, one validated implementation (`libcrux-ml-dsa`). |
| **D3** | Publisher registry | **Open-permissioned.** Anyone can register a publisher by submitting an on-chain registration tx (small fee). No core-team curation. Reputation accrues via observed participation and accuracy over time, weighted into the aggregator | Aligned with Decisão 6 (operational boundaries: core team does not curate). Open-permissioned means anyone willing to stake reputation can publish. Pyth's approach of "we know who Jane Street is" is incompatible with a no-foundation chain. |
| **D4** | Aggregation function | **Median of submissions within a per-feed time window** (default 60 s) | Outlier-resistant: a single misbehaving publisher cannot move the median by more than the inter-publisher spread. Same family as Pyth's aggregated price. Mean is rejected (1 malicious publisher can move it arbitrarily). Trimmed mean is reserved for a future revision; v1 sticks with plain median. |
| **D5** | Staleness policy | A feed is **stale** if the last accepted submission's `publish_ts` is older than `staleness_window` (default 5 min). Consumers MUST check staleness and MAY refuse to act on stale data | Defence-in-depth against publisher silence. Consumers (lending protocols, AMMs) define their own staleness tolerance; the contract surfaces the timestamp so consumers can compute it. |
| **D6** | Minimum quorum | **3 publishers per feed** to produce a valid median. Below quorum the feed reports `Unavailable` | Threshold-3 means a single malicious publisher cannot fabricate a one-publisher consensus. Below 3 the median is statistically meaningless. Higher quorums (5, 7) are configurable per feed via the registry; 3 is the floor. |
| **D7** | Asset ID space | **`SHA3-384(symbol \|\| "/" \|\| quote_currency)[..32]`**, e.g. `SHA3-384("BTC/USD")[..32]` | Deterministic, decentralized, no allocation authority. Anyone constructs the ID by hashing the symbol string. Collisions theoretical at 2^128; the registry surface deduplicates by ID. The `/` separator is mandatory (prevents `BTCUSD` ≠ `BTC/USD` confusion). |
| **D8** | Update rate limit | **1 submission per publisher per asset per 10 s.** Submissions inside the rate-limit window are rejected at mempool admission | Anti-spam without making legitimate publishing painful. 10 s is the smallest reasonable interval given a 60 s aggregation window: a publisher who updates every 10 s contributes ≤ 6 samples to one window. |
| **D9** | Price encoding | **`price_e8: i64`** (price × 10^8, signed) and **`conf_e8: u64`** (1-sigma confidence interval, same scale). Exponent fixed at -8 | Matches Pyth wire format byte-for-byte for the price + conf fields. Wallets / dApps that already parse Pyth payloads adapt with zero work. `i64` allows negative prices (futures basis, rates). |
| **D10** | Signature payload (what is signed) | **`sha3-384(domain_sep \|\| borsh(PriceAttestationCore))`**, where `domain_sep = b"sophis-oracle-pqc-v1\0"` (length-prefixed) and `PriceAttestationCore` excludes the sig + pubkey fields | Domain separator prevents cross-protocol replay. SHA3-384 (truncated to 32 bytes for the Dilithium message) matches the chain hash family. Excluding sig from the signed scope is the standard "sign-then-encode" pattern. |
| **D11** | Migration path from Phase 5 | **Dual-path during migration.** Aggregator contract supports both: a Phase 5 (Plonky3 STARK) input and a Phase 9 (per-publisher Dilithium) input. Consumers pick which feed type to read. Once ≥ 3 Sophis-native publishers are registered for a feed, Phase 5 path for that feed is marked **deprecated** in the registry; Phase 5 reads emit a runtime warning. Hard-deprecation timeline: per-feed, requires SIP | No flag-day migration. Phase 5 work is not wasted — it remains the bootstrap path for feeds without enough native publishers. Hard removal of Phase 5 is its own future SIP, not a Phase 9 decision. |
| **D12** | Reputation weighting | **v1: equal weight median** (no reputation). v2 (Phase 9.x): weight each publisher's contribution by their `blue_score`-anchored uptime + observed accuracy vs the post-aggregation median. v2 ships as a follow-up SIP once v1 has 3 months of empirical data | Reputation algorithms are surprisingly easy to game pre-launch and surprisingly load-bearing post-launch. v1 keeps the aggregation logic simple and auditable; reputation is an additive evolution, not a launch invariant. |

## 3. Wire format

### 3.1 `PriceAttestationCore` (signed payload)

The bytes that go into the Dilithium signature. Borsh-encoded.

```rust
pub struct PriceAttestationCore {
    /// 32-byte canonical asset id (D7): `SHA3-384(symbol)[..32]`.
    pub asset_id: [u8; 32],

    /// Price × 10^8, signed (D9).
    pub price_e8: i64,

    /// 1-sigma confidence interval × 10^8, unsigned (D9).
    pub conf_e8: u64,

    /// Publisher-clock wall-clock timestamp in seconds since Unix epoch.
    /// Aggregator checks staleness against current block timestamp.
    pub publish_ts: u64,

    /// Monotonic per-publisher per-asset sequence number. Aggregator
    /// rejects out-of-order submissions and replays.
    pub sequence: u64,
}
```

**Frozen size:** `32 + 8 + 8 + 8 + 8 = 64 bytes` borsh-encoded.

### 3.2 `PriceAttestation` (signed wire format)

What goes inside the transaction payload.

```rust
pub struct PriceAttestation {
    pub core: PriceAttestationCore,

    /// Dilithium ML-DSA-44 public key (1,312 bytes).
    pub publisher_pubkey: [u8; 1312],

    /// Dilithium ML-DSA-44 signature over
    /// `sha3-384(b"sophis-oracle-pqc-v1\0" || borsh(core))[..32]` (D10).
    pub signature: Box<[u8; 2420]>,
}
```

**Frozen total size:** `64 + 1312 + 2420 = 3796 bytes` borsh-encoded.
Plus tx framing (≈200 bytes) yields ≈4 KB per submission.

### 3.3 Domain separator

```
b"sophis-oracle-pqc-v1\0"
```

Length-prefixed null-terminated bytes. The `\0` byte is mandatory and
included in the hash input. The `v1` suffix versions the entire wire
format; bumping to `v2` is a hard fork of the oracle protocol (but
not of the L1 chain).

### 3.4 Signature computation

```
msg_hash = sha3_384(
    LE_u32(len(domain_sep)) || domain_sep
    || LE_u32(len(borsh_core)) || borsh_core
)[..32]

signature = dilithium_mldsa_44_sign(secret_key, msg_hash)
```

The truncation to 32 bytes matches Sophis's chain-wide SHA3-384-to-32
convention.

## 4. Aggregator contract semantics

**Out of scope for this PR; landed in a follow-up session.** Spec
ratified here so the contract implementer has a frozen target.

### 4.1 Contract storage

Per registered feed:

- `feed_config: FeedConfig { asset_id, time_window_secs, staleness_window_secs, min_quorum }`
- `submissions: VecDeque<AcceptedSubmission>` — ring buffer of last
  `MAX_SUBMISSIONS_PER_FEED` accepted submissions (e.g. 256)
- `last_aggregated_at: u64` — block timestamp of last median computation
- `last_aggregated_price: Option<(i64, u64)>` — `(price_e8, conf_e8)` or
  `None` if below quorum

### 4.2 Submission entry point

```
fn submit_attestation(env, attestation: PriceAttestation) -> i32
```

Validates, in order:

1. **Domain check:** sig was computed over the correct domain separator (rejects cross-protocol replay).
2. **Sig check:** `dilithium_verify(publisher_pubkey, msg_hash, signature) == true`. Uses sVM capability `VerifyDilithium`.
3. **Registry check:** `publisher_pubkey` is registered (any registered publisher; no per-feed curation).
4. **Asset check:** `attestation.core.asset_id` matches a registered feed.
5. **Sequence check:** `attestation.core.sequence > last_seen_sequence(publisher, asset)`. Rejects replay + reorder.
6. **Rate limit:** `current_block_time - last_submission_time(publisher, asset) >= 10s` (D8).
7. **Sanity bounds:** `price_e8 != i64::MIN`; `conf_e8 < i64::MAX as u64`. Reject obvious garbage.
8. **Timestamp sanity:** `|publish_ts - current_block_time| < 600s` (10 min). Reject far-future or far-past submissions.

On accept:

- Push to `submissions` ring buffer (evict oldest if full).
- Update `last_submission_time(publisher, asset)`, `last_seen_sequence`.
- Recompute median over all submissions whose `publish_ts > now - time_window_secs`. If ≥ `min_quorum`, update `last_aggregated_price` and `last_aggregated_at`. Otherwise `last_aggregated_price = None`.

### 4.3 Read entry point

```
fn read_price(env, asset_id: [u8; 32]) -> Option<(i64, u64, u64)>
```

Returns `(price_e8, conf_e8, last_aggregated_at)` if the feed is
above quorum and not stale. `None` otherwise.

Consumers check staleness by comparing `last_aggregated_at` against
their own tolerance.

### 4.4 Registry entry points

- `register_publisher(env, pubkey: [u8; 1312], attestation: PublisherRegistrationAttestation)` — self-registration with proof-of-Dilithium-key-control.
- `register_feed(env, config: FeedConfig)` — open-permissioned: anyone can register a new feed for an asset_id; first-registrant wins for the canonical config; future SIP may allow contested re-registration.
- `deregister_publisher(env, pubkey)` — publisher voluntarily removes themselves; their existing submissions remain valid until they age out of the time window.

## 5. Cost / scaling analysis

Numbers for a Sophis chain at 10 BPS with current block mass limits.

| Scenario | Bytes/sec | Bytes/min | Verdict |
|---|---|---|---|
| 3 feeds × 5 publishers × 1 update/min | ≈ 1.0 KB/s | ≈ 60 KB/min | ✅ Comfortable |
| 10 feeds × 5 publishers × 1 update/min | ≈ 3.3 KB/s | ≈ 200 KB/min | ✅ Within typical block budget |
| 20 feeds × 10 publishers × 1 update/min | ≈ 13 KB/s | ≈ 800 KB/min | ⚠️ Pressures block mass for ordinary tx flow |
| 200 feeds × 20 publishers × 1 update/s | ≈ 16 MB/s | ≈ 1 GB/min | ❌ Inviable; needs STARK aggregation |

The "boutique oracle" sweet spot is 3-20 feeds with 5-10 publishers
each, updating once per minute. That is the design target. For
Pyth-scale breadth (200+ feeds, sub-second updates), Phase 9.x will
add Dilithium STARK aggregation when feasible.

## 6. Migration from Phase 5

> **v1 dispatch is off-chain (ratified re-scope of D11).** This section
> describes the *eventual* on-chain dispatch (the §4 frozen target). The
> **shipped v1** does NOT put dispatch on-chain: per-feed source
> selection is operator-side, deterministic over public chain state, as
> ratified in `oracle/docs/PHASE9_3_DUAL_PATH.md` (derived from SIP-11
> D11; rationale: no curator authority to vest per Decisão 6 / D3, and
> a once-per-feed flip gains nothing from on-chain serialization). An
> on-chain announcement/`update_feed_source` contract is deferred to a
> Phase 9.3.x post-mainnet SIP if chain-anchored flip authority is ever
> demanded. Read §6 below as the deferred target; read
> `PHASE9_3_DUAL_PATH.md` for the v1 mechanism that actually ships.

Phase 5 (Plonky3 + Pyth ed25519) and Phase 9 (per-publisher Dilithium)
coexist during the transition. The aggregator contract dispatches by
feed: each feed has a `source` tag (`Phase5` or `Phase9`).

### 6.1 Bootstrap (testnet → mainnet T+0)

All feeds start on `Phase5` path. Sophis-native publishers register
their Dilithium keys ahead of time but no feed is switched yet.

### 6.2 Per-feed flip (post-mainnet T+N)

A feed flips from `Phase5` to `Phase9` when:

1. ≥ 3 Sophis-native publishers (D6 quorum) have been registered for it.
2. They have been submitting attestations consistently for ≥ 7 days.
3. Their median agrees with the corresponding Phase 5 feed within
   tolerance (e.g. ≤ 0.5% spread over the 7-day window).

The flip is a `update_feed_source` registry call. Once flipped:

- Phase 5 path for that feed continues to ingest but its output is
  marked `deprecated`. Consumers reading Phase 5 see a warning.
- Phase 9 is the canonical read path.

### 6.3 Hard removal of Phase 5

A future SIP (Phase 9.x) defines criteria for removing Phase 5
ingestion entirely (e.g. all feeds have been on Phase 9 for ≥ 6
months with no rollback). Until then, Phase 5 code remains in-tree
as the fallback.

## 7. Comparison with Pyth pull pattern

| Property | Pyth pull (Phase 5) | Sophis Phase 9 |
|---|---|---|
| Publisher count | ~80 institutional | 5-20 boutique to start |
| Signature scheme | ed25519 (classical) | Dilithium ML-DSA-44 (PQC) |
| On-chain bytes per update batch | ≈ 10 KB (STARK proof) | ≈ 4 KB × N publishers |
| Feeds per batch | 200+ | 1 per submission |
| Latency to on-chain price | ≈ 1 Solana slot + STARK aggregation + relayer | ≈ 1 Sophis block per publisher tx |
| Trust model | Pyth publishers + Wormhole relayer + ed25519 chain | Sophis publisher set + Dilithium chain |
| Quantum vulnerability | Yes (ed25519 forgeable if Shor) | No (Dilithium FIPS 204) |
| Aggregation | Pyth's `aggregator.cairo` median | sVM aggregator contract median |
| Curation | Pyth Foundation curates publishers | Open-permissioned, no core team curation |

## 8. Security model

**Adversary 1 — single malicious publisher (classical).** Bounded by
median resistance: a single publisher cannot move the median by more
than `(max_attestation - median) / quorum`. With quorum 3, one bad
publisher contributes one of three samples; the median is the middle
sample, so the attacker can at most shift the reported median by the
gap between the median and the next-nearest honest sample.

**Adversary 2 — N publishers colluding.** With M total publishers and
N colluding, the attacker controls the median when `N > M / 2`. v1
mitigation is open-permissioned publisher registration: economic and
reputational cost of running N publishers is the chain's defence. v2
(reputation weighting) hardens this.

**Adversary 3 — quantum forge of publisher Dilithium key.** Requires
breaking ML-DSA-44 (no known attack, even for quantum adversary, with
≥ 128-bit security margin). Out of scope for this design.

**Adversary 4 — stale data exploitation.** Mitigated by the
`staleness_window` (D5) and consumer-side staleness checks. The
contract surfaces `last_aggregated_at` so consumers compute their
own tolerance.

**Adversary 5 — replay / out-of-order submissions.** Sequence number
(D10, §3.1) + per-publisher monotonic check (§4.2 step 5) rule this
out at the contract layer. Domain separator (D10) rules out
cross-protocol replay.

## 9. Out of scope for v1

- **Dilithium STARK aggregation chips.** Needed to scale to Pyth-level
  breadth. Deferred to Phase 9.x (post-mainnet, multi-month research).
- **Reputation-weighted aggregation.** Deferred to Phase 9.x v2 SIP
  with empirical data from v1.
- **Cross-asset correlation checks.** A future SIP could reject
  submissions whose implied cross-asset rate is wildly off market;
  v1 trusts the median alone.
- **Privacy-preserving publishers.** All submissions are public
  on-chain. A future SIP could add per-publisher commitment schemes
  if confidentiality of submission timing becomes valuable; v1 is
  transparent.
- **Slashing.** Pyth has no slashing either. v1 publishers can be
  removed only by voluntary deregistration or by community-built
  consumer-side blacklists. v2 reputation weighting is the
  closest-equivalent economic disincentive.

## 10. Deliverables

This PR (foundation):

- `docs/PQC_NATIVE_ORACLE_DESIGN.md` (this file)
- `SIPS/SIP-11-PQC-ORACLE.md` (formal SIP stub)
- `oracle/pqc-core/` crate — types + sign/verify + tests
- Update `SIPS/README.md` index

Future sessions, all **pre-testnet**:

- `oracle/pqc-contract/` — aggregator contract WASM
- `oracle/pqc-publisher/` — publisher CLI binary
- Phase 5 dual-path support in oracle aggregator
- Integration tests `oracle/pqc-tests/` covering end-to-end pipeline
- `oracle/docs/PHASE9_RUNBOOK.md` — operator guide

## 11. References

- [FIPS 204 ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) — Dilithium standardization
- [Pyth Pull architecture](https://docs.pyth.network/price-feeds/pull-updates) — for the model Phase 5 mirrored
- `docs/PRE_MAINNET_AUDIT.md` — original audit identifying the ed25519 residual
- `docs/PHASE6_DA_DESIGN.md` — pattern reference for Sophis design docs
- `docs/J7_MULTICALL_DESIGN.md` — pattern reference for ratified-decisions table
