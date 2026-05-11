```
SIP: 10
Title: Multicall Pattern (SDK Contract Template)
Author: Hiroshi Tatakawa <sophis-network@proton.me>
Status: Draft
Type: Standards
Created: 2026-05-11
Requires: 0
```

# SIP-10: Multicall Pattern

> **Status note:** this SIP and its companion `docs/J7_MULTICALL_DESIGN.md`
> + `wallet/multicall-template/` directory are **specification + sample
> template only.** No reference Rust SDK crate, no sVM
> `Capability::ExecuteBatch`, no consensus-relevant ABI ships in J7 v1.
> Future SIPs introduce the Rust SDK helper and (subject to design
> §6 D6 criteria) native batching. Same pattern as SIP-3, SIP-7, SIP-9
> spec-only / template-only deliverables.

## 1. Abstract

Sophis sVM today supports one contract-call per input. Wallets that
want to batch "approve + swap + claim" submit three separate
transactions — three signatures, three mempool entries, three reorg
windows. SIP-10 ratifies the canonical Sophis Multicall pattern: a
deployed sVM contract that accepts a list of sub-calls and dispatches
them atomically (with per-call `allow_failure` opt-in for partial
flows).

Wire format mirrors Ethereum Multicall3.sol exactly — same
`(target, call_data, value, allow_failure)` per sub-call — so wallets
that already render Ethereum Multicall payloads can adapt to Sophis
J7 with minimal work.

J7 introduces no new cryptographic primitive and no on-chain ABI
surface in v1. Native promotion to `Capability::ExecuteBatch` is gated
on D6 criteria (2+ production dApps with measured ≥30% gas reduction
AND ≥1 wallet team request).

## 2. Motivation

See `docs/J7_MULTICALL_DESIGN.md` §1 for the canonical motivation:
DEX flows + governance + claim flows + AA prerequisites all benefit
from batched-action UX; multi-tx flows leak gas to repeated overhead
and rack up confirmation latency; off-chain orchestration without
atomicity creates partial-state phishing surfaces.

J7 is item #12 (last) in the sequential roadmap. Originally estimated
"2-4 weeks, post-mainnet on-demand"; J7 v1 ships only the spec doc +
template + SIP per founder guidance (`project_ethereum_lessons.md`
item J7: "Ship como contract no SDK; nativo só se demand aparecer").

## 3. Specification

The technically complete specification is published at
`docs/J7_MULTICALL_DESIGN.md`. It enumerates:

- 6 ratified design decisions (D1–D6, §2)
- Wire format with byte-level borsh layout (§3)
- Re-entrancy guard rule (§3.4)
- Threat model with 7 in-scope items (§4)
- Comparison vs Ethereum Multicall.sol / Multicall3.sol / Solana
  versioned-tx / Cosmos `MsgExec` (§5)
- Frozen ABI surface (§7)

Sample contract template lives at `wallet/multicall-template/` (not
built in workspace; documents the canonical contract shape).

This SIP body will be re-issued in **Review** once a reference Rust
SDK crate lands and the first 2 production dApps document gas
reduction. Until then the DESIGN doc + template are authoritative.

## 4. Frozen ABI surface

The following are **frozen** as of the J7 specification. Any
implementation that disagrees on these values is incorrect.

### 4.1 Sub-call wire format

```rust
struct SubCall {
    target_contract_id: [u8; 32],
    call_data:          Vec<u8>,
    value_sompi:        u64,
    allow_failure:      bool,    // default false (strict atomic batching)
}
```

Borsh-serialised. The `allow_failure` field is **last** so future
backwards-compatible field additions (D6 native promotion era) can
append without breaking v1 decoders.

### 4.2 Batch payload (Multicall contract input)

```rust
struct MulticallInput {
    calls: Vec<SubCall>,
}
```

Empty `calls` is a structural error (`MulticallError::EmptyBatch`).

### 4.3 Per-call result wire format

```rust
struct SubCallResult {
    success:     bool,    // false for allow_failure sub-calls that failed
    return_data: Vec<u8>, // opaque, target-defined
    gas_used:    u64,     // sums to ≤ batch gas budget
}
```

### 4.4 Aggregated output wire format

```rust
struct MulticallOutput {
    results: Vec<SubCallResult>,   // ordered to match MulticallInput.calls
}
```

### 4.5 Re-entrancy guard

The Multicall contract MUST refuse to dispatch a sub-call whose
`target_contract_id` equals its own deployed contract id. Detection
via `env.contract_id()` comparison; rejection via hard revert.

### 4.6 Atomicity contract

| Failure mode | Behaviour |
|--------------|-----------|
| Sub-call returns failure AND `allow_failure = false` | Hard revert; full transaction reverts. |
| Sub-call returns failure AND `allow_failure = true` | Continue batch; record `success = false` in results. |
| Gas exhausted mid-batch | Hard revert (no per-call recovery). |
| Re-entrancy detected | Hard revert (per §4.5). |
| Decode failure on `MulticallInput` | Hard revert. |
| Empty `calls` vector | Hard revert. |

### 4.7 Native promotion criteria (D6, frozen)

`Capability::ExecuteBatch` ships only after:
- ≥ 2 production dApps deploying the SDK contract document a measured
  ≥ 30% gas reduction (vs the SDK approach)
- ≥ 1 wallet team requests it for UX consistency

Single-integrator pressure is insufficient. Documents in advance to
prevent speculative scope creep.

## 5. Rationale

Deferred to the full SIP body. The DESIGN doc §2 already enumerates
the six ratified decisions (D1–D6) and their rationales. The most
likely points of post-deployment revision are:

- D6 promotion criteria — may tighten or loosen as real ZK / dApp
  ecosystem patterns surface.
- D5 re-entrancy guard — may extend to forbid nested batching across
  ALL Sophis Multicall deployments (not just self) if a multi-deploy
  ecosystem appears with measured re-entrancy issues.
- Adding native `Capability::ExecuteBatch` once D6 fires.

## 6. Backwards Compatibility

**Activated at genesis** (since no on-chain ABI ships in J7, "activated"
is a no-op for full nodes). The Multicall contract is just another
deployable sVM contract; ecosystem teams compile + deploy it (or a
per-app fork) when they need it.

There is no consensus impact in J7 v1.

When a follow-up SIP introduces `Capability::ExecuteBatch`, the wire
format frozen here MUST be honoured by the host-fn implementation;
otherwise dApps that batched against the SDK contract pre-promotion
won't compose with native batching cleanly.

## 7. Reference Implementation

Reference implementation: `sophis-network/Sophis` commit `<TBD>`
(spec + template, single commit):

| Sub-fase | Scope |
|---------|-------|
| J7.0 | Design document (`docs/J7_MULTICALL_DESIGN.md`, ~265 lines) |
| J7.1 | `wallet/multicall-template/{README.md, Multicall.template.rs}` — template-only sVM contract source documenting canonical shape |
| J7.2 | This SIP stub + `SIPS/README.md` index update + single commit (closes 12/12 sequential roadmap) |

Future follow-up sub-fases (separate SIP numbers when demand
surfaces):

- **J7.x.a** — Reference Rust SDK crate `sophis-multicall-sdk` for
  client-side batched-payload construction. Ships when 2+ dApps need
  the same wrapper.
- **J7.x.b** — Native `Capability::ExecuteBatch` per D6 criteria.
  Requires a separate ABI-freeze SIP (capability slot + host fn +
  gas cost).

## 8. Security Considerations

Comprehensive threat model in DESIGN §4. Highlights:

- **Adversarial batch size** — capped by per-tx gas limit; oversized
  batches hit gas exhaustion and revert. No new DoS surface.
- **Nested re-entrancy** — explicit guard (§4.5) makes it a hard
  fail rather than silent corruption.
- **Phishing via multi-step batches** — composes with J2 typed
  signing; wallet displays the full sub-call list before signing.
- **Gas accounting** — `SubCallResult.gas_used` aggregates exactly;
  no double-charging or leakage.
- **Atomicity** — sVM execution already atomic per-tx; Multicall
  never commits partial state in atomic mode.
- **PQC posture** — preserved (no new primitives; tx still signed
  by Dilithium ML-DSA-44).
- **Native promotion under pressure** — D6 frozen criteria prevent
  single-integrator scope creep.

## 9. Test Vectors

Test vectors will be published in `docs/J7_MULTICALL_DESIGN.md` when
the first reference SDK crate (J7.x.a) lands. Until then,
implementations should agree by deriving from §3 of the DESIGN doc.

## 10. References

- [Multicall.sol] (Maker / MakerDAO) — original Ethereum pattern
- [Multicall3.sol] (mds1) — production reference; `allowFailure` field
  ratified here as Sophis `allow_failure`
- `docs/J7_MULTICALL_DESIGN.md` — authoritative spec
- `wallet/multicall-template/` — sample contract source
- `wallet/aa-spec/` — sibling template-only deliverable (J1 AA spec)
- `project_ethereum_lessons.md` item J7 — strategic context
- `SIPS/SIP-9-POSEIDON.md` — same spec-only pattern
- `SIPS/SIP-1-PSBS.md` — composes with J7 for multi-signer batches

[Multicall.sol]: https://github.com/makerdao/multicall
[Multicall3.sol]: https://github.com/mds1/multicall

## 11. Copyright

This SIP is released into the public domain (CC0).
