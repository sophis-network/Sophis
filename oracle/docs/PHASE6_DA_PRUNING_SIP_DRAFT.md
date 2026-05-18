# SIP-DRAFT — Phase-6 self-DA carrier-store pruning (F-26)

> **Status:** ✅ **IMPLEMENTED & VALIDATED 2026-05-18.** §1–§6 design
> RATIFIED; §7 executed on branch `f26-da-pruning`: M1 `098333c` (Fix A:
> `prune_block_batch` + pruning_processor wiring + unit 10/10), M2
> `143bf7e` (deterministic integration test = **G8** prune-correctness),
> M3.1 `adcd024` (Fix B metadata/body split — adopted the *storage-only*
> refinement, ~1/5 blast radius of the literal §7.2, founder-approved),
> M3.2 `c769b43` (short body-horizon GC). Unit 12/12; **G8** real pruning
> processor invokes the prune (no regression A+split+GC); **G7** real
> private kill-9 + restart on persisted DA-pruned datadir → clean
> recovery, chain advanced, pruning resumed (PASS). F-26 **code-resolved**;
> MAINNET re-gating pending **founder/SIP verdict re-review** only.
> Branch unpushed pending founder push authorization.
> **Refs:** `audit/AUDIT_REPORT.md` §6 F-26 (root), F-25 (superseded);
> `oracle/docs/PHASE6_DA_DESIGN.md` §6.1, §10.7 (the unimplemented spec);
> memory `pretestnet-ops-roadmap` #2.

## 1. Problem (F-26)

The self-DA carrier store (RocksDB prefixes 196-199) has **no
pruning/deletion implementation anywhere**:

- `pipeline/pruning_processor/processor.rs` — 0 references to the DA store;
  prunes a fixed enumerated set (utxo_multisets, utxo_diffs,
  acceptance_data, block_transactions, ghostdag, daa_excluded, tips,
  selected_chain, relations, reachability, statuses, headers). DA absent.
- `consensus/src/model/stores/da.rs` `DbDaStore` — insert-only
  (`index_carrier_batch`); **no delete/prune fn**. (The J4 events store
  has `by_block.delete`; the DA store does not.)
- `consensus/src/consensus/storage.rs:76` builds `da_store` and the
  pruning processor already holds `storage: Arc<ConsensusStorage>`
  (processor.rs:70) — the handle exists, it is simply never used to prune.

`PHASE6_DA_DESIGN.md` §6.1 / §10.7 ("carrier bodies follow the same
pruning regime as transactions / pruned nodes drop bodies") is **specified
but unimplemented**. Effect: every node's DA store grows **unbounded
forever** (insert-only), on testnet AND mainnet. Severity **P1
pre-mainnet** (proposed). The design's own T11 storage-griefing
mitigation does not exist.

## 2. Safety basis — H1 (Layer-A code validation, confirmed)

Consensus validation of finalized state is **body-free**:

- `SophisDaBackend::verify_payload` / `verify_bundle` (`consensus/src/svm_da.rs`)
  read only `PayloadEntry.blue_score`, `fragment_count`, bundle membership
  — never `PayloadEntry.script` (the body).
- Rollup `verify_batch` (`rollup/verifier/src/lib.rs`) validates via journal
  + state-root chaining + sequencer Dilithium sig — no carrier body read.
- `DEFAULT_DA_CONFIRMATIONS = 1000` (`consensus/core/src/da/mod.rs:68`); the
  confirmation check is metadata-only arithmetic.

⇒ Dropping the carrier **body** never affects consensus determinism. Only
the lightweight **metadata** is consensus-relevant.

`PayloadEntry` (`consensus/core/src/da/store_types.rs:132`):

| field | role | size |
|---|---|---|
| `script: Vec<u8>` | **BODY** (heavy, ≤ 2 MiB/bundle) | variable |
| `accepting_block_hash: Hash` | metadata | 32 B |
| `blue_score: u64` | metadata (consensus: confirmations) | 8 B |
| `fragment_index: u8` | metadata | 1 B |
| `fragment_count: u8` | metadata | 1 B |
| `bundle_id: PayloadIdHash` | metadata | 48 B |
| `domain_byte: u8` | metadata | 1 B |

Metadata is a fixed ~91 B; the body is the entire weight.

## 3. Fix A — wire the DA store into the pruning processor (MANDATORY)

Closes F-26 by implementing the design's stated §6.1 behaviour: DA store
pruned at the **same consensus pruning point** as everything else.

### 3.1 New `DbDaStore` method

```
fn prune_block_batch(&self, batch: &mut WriteBatch, accepting_block_hash: Hash)
    -> Result<(), StoreError>
```

Algorithm (uses the existing `by_block` index — no new index needed):

1. `pids = by_block.read(accepting_block_hash)`; if absent → nothing to do.
2. for each `pid` in `pids`:
   a. `entry = payloads.read(pid)` → take `bundle_id`, `domain_byte`,
      `blue_score`.
   b. `payloads.delete(pid)`.
   c. `bundles[bundle_id]`: remove `pid` from `payload_ids`; if the vec
      becomes empty → `bundles.delete(bundle_id)`, else rewrite.
   d. if `domain_byte != 0`: `by_domain[(domain_byte, bucket(blue_score))]`:
      remove `pid`; delete bucket if empty, else rewrite.
3. `by_block.delete(accepting_block_hash)`.

Idiom mirrors the J4 events store
(`events.rs:220 self.by_block.delete(BatchDbWriter::new(batch), …)`).

### 3.2 Call site

In `pruning_processor/processor.rs`, the per-pruned-block loop, **same
`WriteBatch`** as the existing deletes, immediately after
`self.block_transactions_store.delete_batch(&mut batch, current)`
(processor.rs:488):

```
self.storage.da_store.prune_block_batch(&mut batch, current)?;
```

**No constructor / signature change** — the processor already holds
`storage: Arc<ConsensusStorage>` and `storage.da_store` exists.

### 3.3 Semantics / determinism

- A bundle whose fragments straddle the pruning boundary: fragments in
  pruned blocks are removed; the `BundleIndex` survives with fewer
  `payload_ids`. `verify_bundle` then returns `false`
  (`payload_ids.len() != fragment_count`) = **exactly** the §10.7
  semantics ("post-prune ⇒ not present ⇒ consensus-equivalent to 0").
  No panic; consistent index.
- Pruning runs over the **same block set at the same consensus pruning
  point** → every node flips `VerifyDataAvailability`→0 for the same
  payloads at the same height. **Deterministic.**
- ⇒ **Fix A is consensus-relevant → SIP / hard-fork class** (it changes
  *when* `VerifyDataAvailability` returns 0). Low controversy: it merely
  implements already-documented §6.1 behaviour.

### 3.4 Effect

DA store bounded to `pruning_depth` worth of carriers (design intent).
Normal tx-rate → small. Adversarial flood → the ~30 h ceiling, finite,
continuously pruned thereafter. **Mandatory pre-mainnet.**

## 4. Fix B — short body horizon (RECOMMENDED, pre-genesis; NOT a hard fork)

Reduces the bounded ceiling from `flood × pruning_depth` (~hundreds of GB)
to `flood × H_body` (~tens of GB).

### 4.1 Schema split (genesis-time format choice → no migration)

- `DaCarrierPayloads` (196) → **metadata only** (the 6 light fields).
- New `DaCarrierBodies = 209` (free prefix; 209+ unused per
  `database/src/registry.rs`): key = `payload_id`, value = body bytes
  (`script`). Written by `index_carrier_batch`, read by `da_get_payload`
  / consumers only.

### 4.2 Body GC (the main remaining design detail — see §6 open Q)

Body is deleted on a horizon `H_body` ≪ `pruning_depth`, **independent of
the consensus pruning point**. Candidate mechanisms:

- **(B-i, recommended)** body-retention watermark: a lightweight sweep
  (hook in virtual-state commit, or periodic) deletes `DaCarrierBodies`
  for blocks whose `blue_score < current_blue_score − H_body`, walking
  blocks via `by_block` between the last body-GC watermark and the new
  one. Reuses the existing block→payload_ids index; bounded work.
- (B-ii) secondary blue_score-ordered body index for GC (more storage,
  simpler sweep). Rejected unless B-i proves awkward.

### 4.3 Classification — **B is NOT a hard fork** (refinement vs. earlier)

Because consensus is body-free (§2), body presence/absence **never**
affects validation determinism. Therefore:

- `H_body` is **not** a consensus parameter; it can even be a node
  operator policy (like `--archival`) without breaking consensus.
- The real constraint on `H_body` is a **network-health / data-availability
  SLA**, not consensus: enough well-distributed nodes must retain bodies
  long enough that any honest consumer (rollup full node re-syncing L2
  state, indexer, `da_get_payload` user) can fetch within its window.
- ⇒ B = node storage policy + a network availability-SLA decision +
  genesis-time schema choice. **Not** SIP/hard-fork class (unlike A).

### 4.4 `H_body` lower bound

Must exceed the maximum honest-consumer fetch latency after publication.
Anchor: `DEFAULT_DA_CONFIRMATIONS = 1000` blue score ≈ 100 s @ 10 BPS is
the *acceptance* freshness scale; a re-syncing rollup full node needs
longer. **Proposed default: a few hours** (e.g. 6 h) — large safety
margin over any plausible honest fetch, still ~120× smaller than the
~30 h `pruning_depth` ceiling. **This default is the key value to
ratify.**

## 5. Test plan (Fix A finally unblocks G7/G8)

- Unit: `prune_block_batch` — single payload; multi-fragment bundle fully
  pruned; bundle straddling boundary (partial removal, `verify_bundle`→
  false, no panic); by_domain bucket emptied; idempotent re-prune.
- Integration: small **devnet-only `pruning_depth`** (test instrumentation
  — *not* the F-25 retracted "fix"; with A implemented this just makes A's
  pruning observable inside a short soak) → run the DA-carrier soak →
  assert store **plateaus** (bounded), consensus keeps advancing,
  `da_get_*`→None + `VerifyDataAvailability`→0 post-horizon per §10.7.
- This makes the soak ladder Stage 2/3/4 feasible on the **current 15.6 GB
  box** and makes **G7** (restart cleanliness — meaningful once bounded)
  and **G8** (prune-correctness sample) finally testable; they were
  deferred precisely because nothing pruned the DA store.
- Fix B: same, plus assert body absent after `H_body` while metadata +
  `verify_payload`/`verify_bundle` still correct to `pruning_depth`.

## 6. Open decisions for founder / SIP

1. Ratify **A** as a SIP/hard-fork item (implements §6.1; mandatory
   pre-mainnet, gates MAINNET).
2. Ratify **B** for **pre-genesis** inclusion (no migration ever) +
   accept it is **not** a hard fork (node policy + availability SLA).
3. Choose **B-i vs B-ii** body-GC mechanism (recommend B-i).
4. Ratify **`H_body` default** (proposed ~6 h) and the network
   body-retention SLA (how many / how distributed nodes must keep bodies
   that long — interacts with `--archival` incentives + T11).
5. Sequencing: A is the pre-mainnet blocker; B strongly recommended
   before genesis but can trail A if needed.

---

# 7. Implementation plan (RATIFIED 2026-05-18 — execute in milestones)

## 7.0 Ratified decisions

A (mandatory, closes F-26) **and** B (pre-genesis) — both in scope. B-i
GC mechanism. `H_body = 6 h` default. A gates MAINNET. Professional, safe,
**zero future rework** is the explicit bar.

## 7.1 Fork / timing framing (precondition — verify, do not assume)

Testnet/mainnet have **not launched** (memory: "next = real Testnet").
**Precondition M1.0:** confirm no live testnet/mainnet chain exists. If
true (expected) → A and B are simply the **genesis ruleset**, NOT a hard
fork of a live chain, and B's prefix-209 schema is a genesis-time format
choice with **zero migration ever**. This is the ideal moment and the
core anti-rework lever. If a testnet chain *is* live, A needs a testnet
fork-activation height (escalate before coding).

## 7.2 Exact code changes

### Fix A — `consensus/src/model/stores/da.rs`

Add to `DbDaStore` (mirrors `index_carrier_batch`, reverse):

```
pub fn prune_block_batch(&self, batch: &mut WriteBatch, accepting_block_hash: Hash)
    -> Result<(), StoreError>
```

- `by_block.read(accepting_block_hash)` → KeyNotFound ⇒ `Ok(())` (idempotent).
- For each `pid`: `payloads.read(pid)` (KeyNotFound ⇒ skip, idempotent) →
  capture `bundle_id`, `domain_byte`, `blue_score`;
  `payloads.delete(BatchDbWriter::new(batch), pid)`.
- `bundles`: read `bundle_id`; retain != pid; if empty → `delete`, else
  `write` the shrunk vec (preserve fragment_index order — already sorted).
- if `domain_byte != 0`: `by_domain` key `DomainBucketKey::new(domain_byte,
  blue_score)`; read, retain != pid; empty → delete, else write.
- `by_block.delete(BatchDbWriter::new(batch), accepting_block_hash)`.
- All ops via `BatchDbWriter::new(batch)` → atomic with the rest of the
  prune WriteBatch. Uses only existing `CachedDbAccess::{read,write,delete}`.

### Fix A — `consensus/src/pipeline/pruning_processor/processor.rs`

Call site: in the per-pruned-block branch, **immediately after**
`self.block_transactions_store.delete_batch(&mut batch, current).unwrap();`
(currently line 488), same `batch`:

```
self.storage.da_store.prune_block_batch(&mut batch, current)
    .expect("DA carrier prune");
```

`self.storage: Arc<ConsensusStorage>` is already a field (processor.rs:70);
`storage.da_store` already exists (storage.rs:76). **Zero constructor /
struct-field change** (chosen over mirroring a `da_store` field — minimal
surface = least rework risk; note the field-mirror alternative exists only
for stylistic symmetry and is explicitly NOT taken).

### Fix B — schema split (genesis-time, no migration)

- `database/src/registry.rs`: add `DaCarrierBodies = 209` (209+ free).
- `da/store_types.rs`: `PayloadEntry` loses `script`; new
  `PayloadBody(pub Vec<u8>)` (or `type` alias) stored under 209 keyed by
  `payload_id`. `PayloadEntry` becomes the 6 fixed metadata fields (~91 B).
  Update `MemSizeEstimator` (drop the `+ script.len()` term from
  `PayloadEntry`; add one for the body record).
- `da/codec.rs` + any (de)serializer of `PayloadEntry`: split accordingly.
- `DbDaStore`: 5th sub-store `bodies: CachedDbAccess<PayloadIdHash,
  Vec<u8>>`. `index_carrier_batch` writes metadata→`payloads`(196) **and**
  body→`bodies`(209), same batch. `get_payload` reassembles for
  body-needing callers (`da_get_payload` RPC); **consensus path
  (`SophisDaBackend::verify_*`) reads metadata-only — never touches 209**
  (H1 — keep it that way; add a debug-assert / doc invariant).
- `prune_block_batch` (Fix A) also deletes the `bodies` entry (so the
  pruning_depth sweep stays complete for nodes that still hold bodies).

### Fix B — body GC (B-i), **NOT in the consensus path** (refinement)

Body presence is non-consensus (H1) ⇒ GC must **not** be in
`commit_utxo_state`'s consensus WriteBatch (no consensus-path latency/risk).
Implement as a **separate lightweight maintenance task**:

- A `body_gc` routine: walks `by_block` for blocks with
  `blue_score < tip_blue_score − H_body_blocks` (where `H_body_blocks =
  6 h × BPS = 6×3600×10 = 216_000`), deleting their `bodies`(209) entries
  only; **metadata/indexes untouched** (kept to pruning_depth by Fix A).
- Watermark `last_body_gc_blue_score` persisted (tiny meta key) so each
  sweep is incremental and crash-safe (resume from watermark).
- Triggered off the same cadence as other periodic maintenance (not the
  block-commit critical path). Idempotent; safe to interrupt.
- `H_body` exposed as a config constant (not consensus); `--archival`
  nodes skip body GC entirely (keep forever).

## 7.3 Invariants to preserve (regression guards)

1. **Idempotency:** re-pruning a block / missing keys ⇒ `Ok(())`, no
   panic (matches `index_carrier_batch` idempotency contract).
2. **Atomicity:** Fix A writes only via the caller's `WriteBatch`.
3. **Determinism (A):** prunes exactly the consensus pruning block set →
   `VerifyDataAvailability` flip is uniform across nodes (§10.7).
4. **H1 invariant:** no consensus path may read prefix 209. Enforce by
   construction + a code comment + a test that `verify_payload`/
   `verify_bundle` succeed with the body absent.
5. **F-22 awareness:** carriers are value==0 outputs — this work does not
   touch mass calc, but do not regress `is_zero_value_protocol_output`
   coupling (see memory `feedback-f22-zero-value-output-landmine`).
6. **No Schnorr/secp256k1, no devfund, no entity** — unaffected, but the
   invariant sweep still applies to any new public surface.

## 7.4 Test matrix (Fix A unblocks G7/G8)

- Unit (`da.rs` tests, extend the existing `mod tests`):
  single-payload prune; full multi-fragment bundle prune; **bundle
  straddling the prune boundary** (partial removal → `verify_bundle`
  false, BundleIndex consistent, no panic); by_domain bucket emptied vs
  shrunk; idempotent re-prune; missing-key prune = Ok.
- Unit (`svm_da.rs`): `verify_payload`/`verify_bundle` still correct with
  body (209) absent but metadata present (H1 regression guard).
- Unit (B): split round-trip (metadata+body); `get_payload` reassembles;
  body GC deletes ≤ watermark only, watermark resume after interrupt.
- Integration: small **devnet-only `pruning_depth`** as *test
  instrumentation* (NOT the retracted F-25 "fix" — with A implemented it
  merely makes A's pruning observable in a short soak) → DA-carrier soak
  → assert store **plateaus**, consensus advances, `da_get_*`→None &
  `VerifyDataAvailability`→0 post-horizon (§10.7), **G7** restart-clean,
  **G8** prune-correctness sample passes. Runs on the current 15.6 GB box.
- Tier-2 Linux Docker `--features svm-zk` + full native suite green
  (per the audit CI invariants) before each milestone commit.

## 7.5 Milestones (each: code → unit tests → `cargo build --release` +
targeted tests green → **local commit** w/ DCO sign-off → honest status →
STOP for review. No `git push` without explicit OK. Branch off, never on a
default branch.)

| M | Scope | Definition of done |
|---|---|---|
| **M1.0** | Verify §7.1 precondition (no live chain) + create work branch | confirmed; branch created |
| **M1** | Fix A: `prune_block_batch` + call site | unit tests (7.4) green; release build green; local commit |
| **M2** | Fix A integration: devnet pruning_depth instrumentation + soak plateau + **G7/G8** | soak bounded+clean; G7/G8 pass; commit |
| **M3** | Fix B: schema split (209) + codec + DbDaStore 5th store + index/get/prune updates | split round-trip + H1 guard tests green; build green; commit |
| **M4** | Fix B: body GC (B-i) + watermark + `H_body`/`--archival` wiring | GC/watermark tests green; soak shows body-horizon bound; commit |
| **M5** | Full validation: Tier-2 Docker + native suite + soak ladder Stage 2 bounded; finalize SIP, update AUDIT_REPORT F-26 → resolved-pending-verdict | all green; docs updated; commit; await founder push/verdict OK |

## 7.6 Risks / rollback

- A touches the live consensus prune loop → M1 isolated + heavily
  unit-tested before M2 integration. Rollback = revert the single call +
  method (no schema change in A).
- B is a genesis-format change → only safe pre-launch (M1.0 gate). If a
  chain is live, B is deferred and escalated.
- Each milestone is independently revertible (separate local commits);
  no mega-commit. Founder reviews between milestones.
</content>
