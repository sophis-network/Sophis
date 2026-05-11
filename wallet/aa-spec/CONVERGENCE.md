# Account Abstraction Convergence — what 5 chains agreed on (and didn't)

**Status:** Pre-RFC draft. Maintainers MUST verify these claims against current chain specs before publishing the RFC. The founder's knowledge cutoff is 2026-01; some details may have evolved.

**Author:** Marcelo Delgado <sophis-network@proton.me>

**Date:** 2026-05-09

---

## 0. Why this document exists

The Sophis approach to Account Abstraction is **convergence-driven**: design choices that ≥3 of the 5 surveyed chains independently agreed on are treated as load-bearing and copied; choices that only one chain made are treated as design-space exploration and **rejected** unless they survive the full Sophis review process.

This is the opposite of "innovation". Account Abstraction has been deployed in production on multiple chains for 3+ years; the parts that converged are the parts that survived adversarial conditions. Sophis benefits from absorbing the survivors and skipping the casualties.

This document tabulates that convergence. It is **not** an authoritative reference for any of the surveyed chains — for that, read each chain's own specifications. This document is the founder's map of what is load-bearing **for the purpose of the Sophis spec**.

## 1. The 5 chains surveyed

| Chain | Mechanism | First production | Current status |
|---|---|---|---|
| Ethereum | **ERC-4337** (off-consensus) | March 2023 | Production; ~2M+ accounts deployed; multiple paymaster ecosystems |
| Ethereum | **ERC-7702** (Pectra hard fork) | May 2025 | EOA→AA upgrade path; allows EOAs to delegate to contract code |
| Aptos | **Native AA** | 2024 | Built into the Move VM; no off-consensus contract layer |
| Starknet | **Native AA from genesis** | November 2021 | Every account is a contract; no externally-owned accounts at all |
| zkSync Era | **IAccount system contracts** | March 2023 | Native, similar shape to Starknet |

Sophis does not match any single chain exactly; the convergence below extracts the shared structure.

**Caveat for maintainers:** the founder has higher confidence in the ERC-4337 + Starknet + Aptos analyses than in the ERC-7702 + zkSync Era ones. Cells marked `[VERIFY DURING RFC]` indicate areas where independent verification is essential before publishing the SIP.

## 2. Convergence table — load-bearing decisions

| Decision | ERC-4337 | ERC-7702 | Aptos | Starknet | zkSync Era | Convergence | Sophis adopts? |
|---|---|---|---|---|---|---|---|
| Account is a contract (or contract-like delegation), not a key | ✅ | ✅ | ✅ | ✅ | ✅ | **5/5** | ✅ D2 |
| Authorization via contract-defined `validate` callback | ✅ | ⚠️ via delegation | ✅ | ✅ | ✅ | **4/5** | ✅ D2 |
| Modular: account vs paymaster vs aggregator are distinct | ✅ | ✅ | ⚠️ less explicit | ⚠️ less explicit | ✅ | **3/5** | ✅ D2 |
| Replay protection via per-account nonce | ✅ | ✅ | ✅ | ✅ | ✅ | **5/5** | ✅ §6.6 |
| Wire-format versioning | ✅ (entryPoint version) | ✅ (delegation type) | ✅ (Move type) | ⚠️ implicit | ✅ | **4/5** | ✅ D3 |
| Batched operations as first-class concept | ✅ | ✅ | ✅ | ✅ | ✅ | **5/5** | ✅ D2 (Batching contract) |
| Deploy-by-user, no official factory | ✅ | ✅ | ⚠️ Aptos has reference impl | ⚠️ Starknet has multiple official impls | ⚠️ | **2/5** | ✅ D5 (Sophis stronger than survey) |
| Recovery / key rotation as separate concern from authorization | ⚠️ varies by wallet | ✅ | ✅ | ⚠️ varies | ⚠️ varies | **2/5 explicit** | ✅ D2 (Recovery contract) |
| Session keys / scoped delegation | ⚠️ via 4337 plugins | ⚠️ via 7702 delegation | ✅ native | ✅ native | ✅ native | **3/5** | ✅ D2 (SessionKey contract) |
| Conservative defaults enforced in contract | ❌ left to UI | ❌ left to UI | ❌ | ⚠️ partial | ❌ | **0/5** | ✅ D4 (Sophis improvement on the survey) |
| Owner-key rotation, NOT key fragmentation | ✅ where implemented | ✅ via 7702 | ✅ | ✅ | ✅ | **5/5** | ✅ D6 |

**Key observation:** the rows where convergence is 3+ form the load-bearing core of any sane AA system. Sophis adopts all of them via D1–D8.

The two most surprising rows for someone new to AA design:

- **Conservative defaults** — Sophis is **more conservative** than any of the 5 surveyed chains. Every existing system left guardian thresholds and session expiries to the wallet UI to enforce, with the predictable result that many wallets shipped 1-of-1 recovery via a single email, defeating the security model. Sophis encodes the floors in the contract itself (D4). Maintainers should expect pushback ("UX-hostile") and should reject that pushback — UX is downstream, security floors are not.

- **Recovery as separate concern** — only Aptos and ERC-7702 explicitly separate recovery from authorization. ERC-4337 left it to wallet implementers, with the result that wallet UIs vary wildly in recovery semantics. Sophis follows the cleaner design (separate `Recovery` contract), accepting the modest extra cost.

## 3. Divergence table — what NOT to copy

These are choices made by ≤2 chains, indicating they are individual design experiments rather than load-bearing patterns. Sophis explicitly rejects each unless a strong, Sophis-specific reason emerges during RFC.

| Choice | Chain(s) | Why Sophis rejects |
|---|---|---|
| Singleton EntryPoint contract operated as ecosystem service | ERC-4337 | Concentrates legal-risk profile; "operating service provider" framing. Sophis D5. |
| Bundlers as off-chain ecosystem actors | ERC-4337 | Adds an extra trusted party between user and chain; Sophis miners already do this job. |
| Aggregator contracts for signature aggregation | ERC-4337 | No production-ready Dilithium aggregation; revisit when one exists. |
| EOA-to-contract upgrade in-place | ERC-7702 | Sophis has no EOAs to upgrade — every Sophis address is already a P2SH or P2PKH-Dilithium output. |
| Native account contracts at genesis | Starknet, Aptos, zkSync | Sophis ships AA as sVM contracts post-genesis (D1) — same end state, less risk. |
| `__execute__` / `__validate__` magic function names | Starknet | Cosmetic; Sophis uses regular trait method names. |
| Move resources as account state | Aptos | Move-specific; Sophis sVM is WASM-based. |
| zkLogin / WebAuthn / OAuth integration | zkSync (zkLogin), Sui (zkLogin) | **Permanently rejected** — see `ANTI_PATTERNS.md` §3. |
| Account contract registry / verified accounts list | Various wallet UIs | Curation = D5 violation. |

## 4. Anti-convergence — what every chain got wrong, and what Sophis does instead

These are areas where multiple chains independently made choices that, in retrospect, the community has criticized:

| Mistake | Chains affected | Consequence | Sophis avoids by |
|---|---|---|---|
| Default to insecure config (1-of-1 recovery via email) | Most ERC-4337 wallets [VERIFY DURING RFC] | Mass user phishing via "recovery email" attacks | D4 — contract rejects M < 3 |
| Calling guardian-recovery "social recovery" in marketing | Argent, Loopring, others | Conflation with custodial fragmentation models; legal ambiguity | D6 + `ANTI_PATTERNS.md` §4 |
| Operating an "official paymaster" that sponsors gas | Various | Service-provider framing; jurisdictional risk | Paymaster deferred to v2; v2 explicitly user-deployed |
| Mixing AA contract code with wallet UI code | Most early ERC-4337 wallets | Contract upgrades break UI; UI bugs ship as contract changes | Modular (D2) — separate contracts, separate cadence |
| No version field, optimistic forward-compatibility | Some Starknet implementations [VERIFY DURING RFC] | Old wallets accept new payloads as garbage | D3 — magic bytes hard-fail wrong-version parsing |
| Allowing arbitrarily long session expiry | All surveyed | Session keys outlive their compromise window | D4 — contract rejects expiry > 7 days |

## 5. Dilithium-specific divergence

The 5 surveyed chains all use ECDSA (secp256k1) or Ed25519. None has a production AA system designed around a 1.3 KB pubkey + 2.4 KB signature.

This means Sophis cannot blindly adopt any wire format. Specifically:

- **Variable-length signature buffers** (Sophis D7) are not a feature of any surveyed chain because their signatures fit in a fixed 64–96 bytes. Sophis adopts variable-length out of necessity.
- **State-cost-as-design-concern** (Sophis D8) is implicit in every chain (storage is paid for) but is rarely surfaced as a first-class design concern, because for ECDSA the per-account state is small enough to be ignored. Sophis surfaces it because at 5 × 1312 = 6.5 KB per account, it cannot be ignored.
- **No HD derivation** (Sophis §8.2) is unique to Sophis among the surveyed chains; all 5 surveyed have an HD scheme for their respective signature algorithm. Maintainers must design Recovery / SessionKey contracts to accept independent keys, not derivation paths.

## 6. Where the convergence is weakest — research areas

These are areas where the 5 chains diverge significantly and where the Sophis design must make an opinionated choice without strong precedent. Maintainers should treat each as an open research question:

1. **Optimal guardian count default.** ERC-4337 wallet implementations vary from 3 to 7. Sophis chose 5 (D4) as the upper end of "manageable for a typical user". Open: would 3 default with hard floor of 3 be better than 5 default with hard floor of 3? Solicit comments.

2. **Session key allowance accounting.** Should allowance be (a) per-call cap, (b) per-period cap (e.g. 1 SPHS / hour), or (c) cumulative cap depleted across calls? Sophis spec §4.3 picks (c) for simplicity. ERC-4337 plugin ecosystem has all three. Validate during testnet.

3. **Atomic batch failure semantics.** If operation 3 of 5 fails, should the batch (a) revert all 5, (b) commit 1-2 and report failure on 3, (c) be configurable? Sophis spec §4.4 picks (a) — atomicity. Solicit comments.

4. **Guardian-set evolution.** Adding a guardian: who authorizes? Owner alone? Owner + M existing guardians? Sophis spec leaves this to the implementer's choice but recommends "owner alone for additions, M existing guardians for removals". Validate in testnet.

5. **Session key cross-account scope.** Should a session key be scoped to one account (current Sophis spec §4.3) or be reusable across multiple accounts owned by the same human? Sophis spec picks single-account. Cross-account scope reopens identity-correlation concerns and is rejected for v1.

## 7. Maintainer due-diligence checklist

Before publishing the SIP, a maintainer SHOULD:

- [ ] Re-read the official ERC-4337 specification (eips.ethereum.org/EIPS/eip-4337) and verify §2 claims about it
- [ ] Re-read EIP-7702 and verify §1 mechanism claims
- [ ] Re-read Aptos `account_abstraction` framework documentation and verify the modularity claims
- [ ] Read at least one Starknet account contract reference implementation and verify the validate-callback shape
- [ ] Read the zkSync Era IAccount interface and verify the modularity claims
- [ ] Confirm or refute the "ERC-4337 left defaults to UI" claim by surveying 3+ deployed ERC-4337 wallets
- [ ] Identify any AA design choice published since 2026-01 (the founder's knowledge cutoff) that affects the convergence analysis

If the due diligence reveals that any claim in this document is wrong, **update this document and re-circulate before publishing the SIP**. Do not let the analysis ossify based on outdated information.

## 8. Last touched

2026-05-09 — initial pre-RFC draft. Cells marked `[VERIFY DURING RFC]` are explicit gaps in the founder's confidence; maintainers MUST resolve them.
