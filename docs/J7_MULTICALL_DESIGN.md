# J7 — Multicall Pattern (SDK Contract Template)

> **Status:** spec frozen for sub-fase J7.0; template + spec ship in
> J7.1 / J7.2; **no native sVM capability ships in J7.**
> **Originating roadmap:** Roadmap J (Ethereum lessons), item J7.
> **Companion docs:** `wallet/multicall-template/` (sample contract
> source) and `SIPS/SIP-10-MULTICALL.md` (Standards-track stub).
> **Pre-existing baseline:** Sophis sVM today supports one
> contract-call per input. Wallets that want to batch
> "approve + swap + claim" submit three separate transactions, each
> with its own signature, fee, and worst-case-reorg risk. Ethereum
> solved this via [Multicall.sol] (Maker, MakerDAO, OpenZeppelin
> patterns) — a single deployed contract that accepts a list of
> sub-calls and dispatches them atomically. J7 v1 ratifies the
> equivalent pattern for Sophis sVM.
> **Why SDK-contract-first:** founder guidance
> (`project_ethereum_lessons.md` item J7: "Ship como contract no SDK;
> nativo só se demand aparecer. Pode ser SDK contract first;
> promoção a nativo via SIP futuro"). J7 v1 is a deployable contract
> pattern + SIP, not a sVM capability.

[Multicall.sol]: https://github.com/mds1/multicall

## 1. Motivation

Wallet UX wins from "batch N actions in one signed transaction":

- **DEX flows.** A user wanting to swap token A → B → C using two
  pools today signs (a) approve B-pool to spend A, (b) swap A→B,
  (c) approve C-pool to spend B, (d) swap B→C — four signatures,
  four mempool entries, four reorg-windows where partial state
  matters.
- **Governance + claim flows.** "Claim staking rewards + restake +
  vote" is three separate operations; users sign each individually
  today.
- **Account abstraction (J1) prerequisites.** Even a minimal AA
  pattern needs batching as a primitive — a single user-op routes to
  N contract calls.

Without a multicall pattern:

- **Wallet UX is per-action signing.** Hardware wallets prompt N
  times instead of once-with-summary; mobile wallets show N status
  spinners instead of one.
- **dApp UX is multi-tx confirmation.** "Your approve completed.
  Now confirm the swap." Multi-step flows leak gas to repeated tx
  overhead and racking up confirmation latency.
- **Atomicity is opt-in via off-chain orchestration only.** A user's
  approve can land in block N while their swap fails in block N+1
  due to slippage; their stranded approval becomes a phishing
  surface.

J7 ratifies the canonical Sophis Multicall pattern — a deployable
sVM contract + a wire format for sub-call lists + an atomicity
contract — so all dApps batch the same way and wallets can render
the same UX.

This is item #12 (last) in the sequential roadmap. Originally
estimated "2-4 weeks, post-mainnet on-demand"; J7 v1 ships only the
spec + template + SIP per founder guidance. A native sVM capability
follows when a concrete dApp demands it.

## 2. Ratified design decisions

These decisions were committed by the founder on 2026-05-11 and are
frozen for the J7 specification. Re-opening any of them requires a
new SIP.

| ID | Question | Choice | Rationale |
|----|----------|--------|-----------|
| **D1** | Native sVM capability vs SDK contract | **SDK contract** for v1; promotion to `Capability::ExecuteBatch` is a future SIP gated on real dApp demand | Per founder guidance. Native batching adds consensus-relevant ABI surface (atomicity + fee accounting + nested-trap handling) that should land under proven demand, not speculation. SDK contract pattern lets every dApp deploy the canonical Multicall to a known address (or a per-app fork) without any Sophis fork. |
| **D2** | Wire format | **Borsh-encoded `Vec<SubCall>`** where each `SubCall = (target_contract_id: [u8; 32], call_data: Vec<u8>, value_sompi: u64)` | Borsh because every other Sophis SDK type is borsh; consistent with `Datum` / `ContractManifest` shapes. Triple `(target, call_data, value)` matches Ethereum Multicall3.sol semantics one-to-one and makes parser code shape-equivalent across chains. |
| **D3** | Atomicity model | **Atomic by default** (revert on first failure); opt-in per-call `allow_failure: bool` flag for partial-execution flows | Atomic-by-default matches the user mental model: "all my actions or none". Per-call `allow_failure` covers the rare case where a sub-call is cosmetic (e.g. emit a tracking event) and shouldn't tank a critical step. Mirrors Multicall3.sol's `allowFailure` field exactly. |
| **D4** | Result aggregation | **`Vec<SubCallResult>` returned in order**, where each `SubCallResult = (success: bool, return_data: Vec<u8>, gas_used: u64)` | Order-preserving so callers can match results to inputs by index. `gas_used` per call lets wallets show per-action cost in the post-tx receipt. `return_data` opaque so contracts pass through whatever sub-call returns. |
| **D5** | Failure modes | **Hard-revert on**: (a) any non-`allow_failure` sub-call returns failure; (b) gas exhaustion mid-batch; (c) nested re-entrancy detected. **Soft-skip on**: `allow_failure = true` sub-calls that fail. | Standard atomicity contract. Re-entrancy detection: the Multicall contract refuses to dispatch a sub-call whose target IS the Multicall contract itself; nested batching is out-of-scope for v1. |
| **D6** | Promotion-to-native criteria | Native `Capability::ExecuteBatch` ships **only after** at least 2 production dApps document a measured ≥ 30% gas reduction (vs SDK contract approach) AND ≥ 1 wallet team requests it for UX consistency | Concrete bar prevents speculative scope creep. Documents the criteria in advance so future founder isn't pressured into shipping native batching from a single integrator request. |

## 3. Wire format

### 3.1 Sub-call

```rust
#[derive(BorshSerialize, BorshDeserialize)]
pub struct SubCall {
    /// 32-byte sVM contract id (target of this sub-call).
    pub target_contract_id: [u8; 32],
    /// Opaque call data the target contract decodes itself.
    pub call_data: Vec<u8>,
    /// Sompi to forward to the sub-call (0 for read-only / state-only calls).
    pub value_sompi: u64,
    /// If true, this call's failure does NOT revert the batch.
    /// Default false (strict atomic batching).
    pub allow_failure: bool,
}
```

### 3.2 Batch payload (Multicall contract input)

```rust
#[derive(BorshSerialize, BorshDeserialize)]
pub struct MulticallInput {
    pub calls: Vec<SubCall>,
}
```

The Multicall contract's `validate()` function reads its input UTXO's
`Datum`, borsh-decodes a `MulticallInput`, dispatches each sub-call
in order, accumulates results, and writes the `Vec<SubCallResult>`
into its output UTXO's `Datum`.

### 3.3 Sub-call result

```rust
#[derive(BorshSerialize, BorshDeserialize)]
pub struct SubCallResult {
    /// `true` iff the sub-call returned success (and was actually dispatched).
    /// `false` for sub-calls that failed AND had `allow_failure = true`.
    pub success: bool,
    /// Whatever the target contract returned. Opaque.
    pub return_data: Vec<u8>,
    /// Gas used by this sub-call. Sums to ≤ batch gas budget.
    pub gas_used: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct MulticallOutput {
    pub results: Vec<SubCallResult>,
}
```

### 3.4 Re-entrancy guard (consensus rule for the Multicall contract)

The Multicall contract MUST refuse to dispatch a sub-call whose
`target_contract_id` equals its own deployed contract id. This
prevents nested batching, which v1 does not support and which would
introduce non-trivial gas-accounting complexity.

Detection at the contract level: compare `sub_call.target_contract_id`
against the Multicall's own `manifest.contract_id` (available via
the sVM execution context); revert if equal.

## 4. Threat model

| ID | Threat | Mitigation |
|----|--------|------------|
| T1 | Adversarial batch size | The Multicall contract's gas budget caps total work; an oversized batch hits gas exhaustion and reverts. No new DoS surface beyond existing per-tx gas limits. |
| T2 | Nested re-entrancy via Multicall-calling-Multicall | D5 + the explicit re-entrancy guard in §3.4. Nested batching is undefined behaviour in v1; the guard makes it a hard fail rather than silent corruption. |
| T3 | Phishing: dApp puts a malicious sub-call after a benign one | Wallets MUST display the full sub-call list to the user before signing — this is the typed-signing problem (J2). Multicall does not bypass typed signing; it composes with it. The user signs the batched payload, sees N sub-calls in their wallet, approves all-or-nothing. |
| T4 | Gas accounting mismatch (caller paid for X, sub-calls used Y) | `SubCallResult.gas_used` aggregates exactly. The batch tx's total gas equals the Multicall's overhead + sum of sub-call gas. No double-charging, no leakage. |
| T5 | Atomicity violation: partial state on revert | sVM execution is already atomic per-tx; the Multicall contract never commits partial state in atomic mode. `allow_failure = true` sub-calls explicitly opt out per D3, with the wallet UX responsibility to surface the choice. |
| T6 | PQC posture | J7 introduces no new cryptographic primitive. Tx signing is Dilithium ML-DSA-44 (existing); the Multicall payload is borsh-encoded data inside an existing tx. PQC posture preserved. |
| T7 | Native promotion under pressure | D6 frozen criteria — 2+ dApps with measured gas reduction AND wallet team request. Single-integrator pressure is insufficient. |

## 5. Comparison vs alternatives

| System | Pattern | Atomicity | Native? | Per-call result? |
|--------|---------|-----------|---------|-------------------|
| Ethereum Multicall.sol (Maker) | deployed contract | atomic | no (contract) | yes |
| Ethereum Multicall3.sol (mds1) | deployed contract | atomic + per-call `allowFailure` | no (contract) | yes (return data + success bool) |
| Solana versioned tx + LUTs | tx-format primitive | atomic | yes (tx-format) | implicit (per-instruction logs) |
| Cosmos `MsgExec` | governance message | atomic | yes (genesis-time) | yes |
| **Sophis J7 v1** | deployed sVM contract template | atomic + per-call `allow_failure` (D3) | **no** (D1, by design) | yes (D4) |

Sophis J7 v1 mirrors Multicall3.sol's design exactly: same triple of
fields per sub-call (`target / data / value`), same `allowFailure`
flag for partial flows, same return-data + success-bool aggregation.
A wallet that supports Multicall3.sol on Ethereum will recognise the
shape of Sophis J7 batched payloads.

The native promotion path (D6) keeps a future hard fork to
`Capability::ExecuteBatch` open without committing to it.

## 6. Out-of-scope (for J7 v1)

- **Native `Capability::ExecuteBatch`** (D1, D6). Future SIP if
  demand surfaces.
- **Nested batching** (D5). v1 explicitly rejects via the re-entrancy
  guard.
- **Cross-contract atomic transactions** (e.g. "if A succeeds, then
  B; otherwise call C as compensating action"). v1 is linear; the
  atomic-or-revert contract is sufficient for the common cases.
- **Multi-signer batching** (M-of-N approving the batch as a whole).
  Composes with PSBS (SIP-1) and AA (J1 spec) — not J7 v1's job.
- **Per-call delegated authorization** (e.g. "this sub-call uses
  signer A, that one uses signer B"). v1 batches under one
  signature; AA spec (J1) covers multi-signer flows.
- **Reference Rust SDK helper** for constructing batched payloads
  client-side. Future sub-fase J7.x.a; trivial when needed.

## 7. Frozen ABI surface

| Item | Value |
|------|-------|
| Sub-call wire format | `(target_contract_id: [u8; 32], call_data: Vec<u8>, value_sompi: u64, allow_failure: bool)` borsh |
| Result wire format | `(success: bool, return_data: Vec<u8>, gas_used: u64)` borsh |
| Re-entrancy guard | Multicall MUST reject `sub_call.target_contract_id == self.manifest.contract_id` |
| Atomicity default | `allow_failure = false` (strict atomic batching) |
| Sample template path | `wallet/multicall-template/` (template only; not built in workspace) |
| Native capability slot | RESERVED for future SIP. No `Capability::ExecuteBatch` in J7. |

## 8. Reference implementation map

| Sub-fase | Scope |
|---------|-------|
| J7.0 | This design document |
| J7.1 | `wallet/multicall-template/` — README + sample sVM contract source (not built in workspace; template form like `wallet/aa-spec/`) |
| J7.2 | `SIPS/SIP-10-MULTICALL.md` stub + `SIPS/README.md` index update + single commit (closes 12/12 Roadmap) |

Future follow-up sub-fases (separate SIP numbers when demand
surfaces):

- **J7.x.a** — Reference Rust crate `sophis-multicall-sdk` for
  client-side batched-payload construction. Ships when 2+ dApps need
  the same wrapper.
- **J7.x.b** — `Capability::ExecuteBatch` native sVM capability + host
  fn + gas constant. Ships only after D6 criteria are met (2+ dApps
  + wallet team).

## 9. Glossary

| Term | Meaning |
|------|---------|
| Multicall | A pattern (or contract) that bundles N contract calls into one execution unit, atomic by default. Originated as Maker's Multicall.sol on Ethereum. |
| Sub-call | One element of a Multicall batch: (target contract, call data, value, allow_failure flag). |
| Atomic batch | All sub-calls succeed or the entire transaction reverts. Default behaviour. |
| Best-effort batch | Sub-calls with `allow_failure = true` may fail without reverting the batch. Per-call opt-in. |
| Re-entrancy guard | The Multicall contract's refusal to dispatch a sub-call back into itself. Prevents nested batching. |
| Result aggregation | The post-execution `Vec<SubCallResult>` returned to the caller, ordered to match the input `Vec<SubCall>`. |
