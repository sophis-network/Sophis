# Sophis Fee Priority Reference

**Status:** v1, drafted 2026-05-09. Reference document for wallet
authors, integrators, and tooling. Describes the fee/mass model, the
3-tier feerate API, and the recommended pattern for surfacing
priority fees in wallet UX.

This document is **descriptive** — it standardizes language and
recommends UX patterns around the existing implementation. It is not
a SIP and does not change consensus or relay rules.

---

## 1. Units and definitions

| Term | Definition |
|---|---|
| `sompi` | Smallest SPHS unit. `1 SPHS = 100,000,000 sompi` (8 decimals) |
| `mass` | Consensus-defined transaction weight, accounting for signature size, output count, and computational cost |
| `feerate` | Fee per unit mass. Units: **sompi per gram** (`sompi/gram`) |
| `fee` | `feerate × mass(tx)` — total absolute fee for a given transaction at a given feerate |

Mass is the unit of bandwidth/CPU pricing on Sophis. A Dilithium
ML-DSA-44 signature (~2.5 KB) consumes substantially more mass than a
classical secp256k1 signature would, which is reflected in the mass
field and therefore in the absolute fee at any given feerate.

Code: `mining/src/feerate/mod.rs`. Wallet-side helpers:
`wallet/core/src/tx/fees.rs`.

## 2. Three-tier feerate API

The feerate estimator (`mining/src/feerate/mod.rs`) returns
`FeerateEstimations`:

```rust
pub struct FeerateEstimations {
    pub priority_bucket: FeerateBucket,
    pub normal_buckets: Vec<FeerateBucket>,
    pub low_buckets:    Vec<FeerateBucket>,
}

pub struct FeerateBucket {
    pub feerate:           f64,
    pub estimated_seconds: f64,
}
```

| Tier | Inclusion target | UX label suggestion |
|---|---|---|
| **Priority** | sub-second | "Priority — for time-sensitive transactions" |
| **Normal** | sub-minute | "Normal — typical confirmation latency" |
| **Low** | sub-hour | "Low — patient, lowest fee" |

The `normal_buckets` and `low_buckets` are vectors so wallets can
sample multiple points along the feerate-to-time curve and
interpolate. Composing `[priority] | normal | low` yields a complete
client-side feerate function.

## 3. Wallet UX recommendation

Wallets SHOULD expose the three tiers with these properties:

1. **Default to `Normal`** for routine payments (sub-minute is fast
   for human-perceived UX without over-paying).
2. **Show absolute fees** in addition to feerate. Users do not
   reason in `sompi/gram`; they reason in "this will cost me X
   SPHS".
3. **Show estimated time** alongside each tier. The estimator
   returns this directly.
4. **Surface RBF as "Speed up"** when a user wants to escalate a
   pending tx. See `docs/MEMPOOL_POLICY.md` §2.
5. **Refresh estimates** at submission time, not at compose time —
   Sophis runs at 10 BPS and feerates can shift quickly.

### 3.1 Pattern reference (TS / Rust)

```typescript
// Pseudo-API; concrete client API in rpc/wrpc/client and grpc/client
const estimates = await rpc.feerateEstimate();
const tiers = {
  priority: estimates.priorityBucket,
  normal:   estimates.normalBuckets[0],
  low:      estimates.lowBuckets[0],
};

const tx = compose(...);
const massEstimate = tx.mass();
const feeAt = (tier) => tier.feerate * massEstimate;

// Show user:
//   Priority: 0.0042 SPHS (~0.8s)
//   Normal:   0.0010 SPHS (~12s)
//   Low:      0.0003 SPHS (~5min)
```

## 4. Fee escalation patterns

Three patterns fit the 10-BPS / RBF model:

### 4.1 Speed up (RBF)

Submitter has a pending tx and wants to bump the fee. Client
re-builds the tx with a higher feerate (typically ≥2× the original)
and submits with `RbfPolicy::Mandatory`. The replacement is accepted
if exactly one mempool conflict matches and the new feerate exceeds
the threshold (`docs/MEMPOOL_POLICY.md` §2.3).

### 4.2 Cancel

Submitter wants to abort a pending tx. Client builds a self-spend at
the same input(s) with a higher feerate and submits with
`RbfPolicy::Mandatory`. The original tx is replaced; the new tx
sends value back to the submitter's own wallet.

### 4.3 Auto-bid

A wallet that wants automatic latency targeting can poll the
feerate API on a short interval (e.g. every 5 seconds for
high-value, time-critical UX) and re-submit with RBF if the
in-flight tx falls below the target tier.

Caveat: at 10 BPS, the cost of an extra round-trip can exceed the
fee delta. Profile the target interval against the user's
sensitivity-to-latency before shipping aggressive auto-bid UX.

## 5. Comparison to other chains

The Sophis fee model **mixes** ideas from three lineages:

| Concept | Source | Sophis mapping |
|---|---|---|
| Per-tx mass-based pricing | Bitcoin (vsize-based fee) | Mass = vsize generalization |
| 3-tier latency-targeted estimate | Bitcoin Core fee estimator | Direct adaptation |
| Replace-by-fee | Bitcoin BIP-125 | `RbfPolicy::{Forbidden,Allowed,Mandatory}` |
| Base + priority bidding | Ethereum EIP-1559 | Conceptually present but expressed as feerate buckets, not split base/priority fields |
| Multi-level commitment | Solana (`processed`/`confirmed`/`finalized`) | Roadmap L3 plans the analogous Sophis API for transaction confirmation depth |

The Sophis API does **not** have an EIP-1559 split between
"base fee" and "priority tip". The single `feerate` field is the
total fee per mass; bidding higher than `priority_bucket` works
exactly as expected (faster inclusion, paid in full to the miner —
no burn). See `project_burn_fees_rejected.md` (memory) for the
rationale on no fee burning.

## 6. Coinbase and miner reward (cross-reference)

Block reward + transaction fees both go **100% to the miner**. There
is no fee split, no protocol-level burn, no devfund (decision
2026-05-04 #2; see `MONETARY_POLICY.md` §2). When wallets surface
fees to users, they can truthfully state: "this fee goes entirely to
the block producer".

## 7. Reference

- Code: `mining/src/feerate/mod.rs`,
  `mining/src/mempool/model/frontier/feerate_key.rs`,
  `mining/src/mempool/model/frontier/selectors.rs`,
  `wallet/core/src/tx/fees.rs`
- RPC: `rpc/core/src/model/feerate_estimate.rs`,
  `rpc/grpc/core/proto/rpc.proto`
- Companion: `docs/MEMPOOL_POLICY.md`,
  `docs/SVM_EXECUTION_MODEL.md`,
  `docs/ECOSYSTEM_OVERVIEW.md`
- Cultural reference: Bitcoin Core fee estimator, Ethereum EIP-1559
  (concepts adopted), Solana commitment levels (Roadmap L3)
- Decision rationale: `MONETARY_POLICY.md`,
  `project_burn_fees_rejected.md` (memory)
