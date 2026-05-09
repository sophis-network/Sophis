# Account Abstraction (AA) Spec for Sophis

**This directory is a specification, not compilable code.** Nothing here is built into `sophisd`, `dilithium-wallet`, or any other Sophis binary. Files in `templates/` use `unimplemented!()` markers and are deliberately not part of the workspace `Cargo.toml`.

## What this is

A complete design specification for adding **Account Abstraction** to Sophis as a sVM-layer feature — wallets that are smart contracts, supporting:

- Guardian-based key recovery
- Session keys with bounded scope
- Batched operations
- (Eventually, post-v2) third-party paymasters

The spec was prepared so that **future maintainers** — not the founder — can implement these primitives cleanly, after a public RFC process, with minimal redesign needed.

## Why spec-only

Three reasons, in order of importance:

1. **Process discipline.** Account Abstraction has a long history of being shipped too fast, frozen incorrectly, and then carrying that weight forever (ERC-4337 went through 11+ revisions before its first stable release; ERC-7702 took two more years on top of that). The Sophis approach is the opposite: long public review, no deadline, freeze only after multi-month testnet validation. Implementing during a single founder session would violate that principle.

2. **Founder operational boundaries.** Per the project's `OPERATIONAL_BOUNDARIES.md` and `project_no_entity_decision.md` memory, the founder operates as Bitcoin Core / Monero Project model — reference code only, no operations, no curation. Account Abstraction infrastructure that the founder *implements* invites pressure to *operate* (default factory? recommended guardians? official paymaster?). Spec-only inverts that: the founder publishes intent, maintainers implement, and operational responsibility is distributed.

3. **Design-space size.** Account Abstraction is the largest single design space in any chain's wallet stack. Multiple chains have shipped their own designs (ERC-4337, ERC-7702, Aptos AA, Starknet IAccount, zkSync Era IAccount), each with non-trivial trade-offs. The right move is to absorb the convergence — what 3+ chains independently agreed on — and reject the divergence. That research belongs in the spec, not in a hurried implementation.

## What you will find here

| File | Purpose |
|---|---|
| `SPEC.md` | The canonical specification: grammar, ratified design decisions D1–D8, threat model, Dilithium-specific constraints, conservative defaults, test vectors plan |
| `CONVERGENCE.md` | Comparative analysis of ERC-4337, ERC-7702, Aptos AA, Starknet IAccount, zkSync Era IAccount — what to copy, what to reject |
| `ANTI_PATTERNS.md` | What **not** to do, with empirical cases (Sui zkLogin OAuth lock-in, etc.) |
| `templates/IAccount.template.rs` | Trait skeleton with structural comments — the shape future implementers should match |
| `templates/Recovery.template.rs` | Guardian-based recovery template (3-of-5 default, no fragmentation, contract separate from IAccount) |
| `OPERATIONAL_BOUNDARIES_PARAGRAPH.md` | Drop-in text for `OPERATIONAL_BOUNDARIES.md` and whitepaper §11 once AA implementation begins |

Future additions (next session, maintainer work):

- `templates/SessionKey.template.rs` — session keys pattern, 24h default expiry
- `templates/Batching.template.rs` — batched operations pattern
- `templates/Paymaster.template.rs.deferred` — paymaster pattern, marked v2 (NOT v1)
- `INTEGRATION.md` — how AA composes with PSBS (K1), wallet descriptors (K3), Phase 6 DA
- `TEST_PLAN.md` — what to test during the 6+ month pre-freeze testnet
- `RFC_TEMPLATE.md` — pre-filled SIP template ready for the RFC publication

## What this is not

This is **not** an implementation plan for the founder. The founder will not implement Account Abstraction. Pre-mainnet, the founder is finishing PSBS (K1) and may complete wallet descriptors (K3); everything beyond that — AA (J1), Vault patterns (K5), CCS funding (O1) — is intended to be implemented by external maintainers post-mainnet, governed by SIPs.

If you are a maintainer considering implementation:

1. Read `SPEC.md` end-to-end first. Do not skip the threat model.
2. Read `CONVERGENCE.md` to understand which design choices are load-bearing (3+ chain convergence) versus which are individual chain quirks (reject).
3. Read `ANTI_PATTERNS.md` before writing any code. Several of the listed anti-patterns have killed real wallets in production (zkLogin OAuth dependency, social-recovery custody framing, official paymaster operations creating jurisdictional exposure).
4. Open a SIP. Do not skip the public review window. The spec exists to give you a strong starting point; it does not authorize implementation.

## What if no one implements

A blunt question that deserves a blunt answer.

If no maintainer ever implements Account Abstraction, Sophis still has a functioning wallet (`dilithium-wallet` CLI, single-sig hot key model, `send` / `info` / `restore` commands). What it loses:

- No multisig — corporate / DAO treasury management is structurally impossible
- No guardian-based recovery — losing the seed phrase is permanent loss
- No session keys — every transaction needs full-key authorization
- No batched operations — multi-step flows always cost N transactions

Those are real losses. But they do not break the chain, and they do not prevent it from being used. The hope behind publishing this spec is that a maintainer eventually picks it up; the contingency if no one does is that Sophis remains a Bitcoin-style minimalist chain, which is the worst case but not a catastrophic one.

## Status

| Phase | Status |
|---|---|
| Spec frozen for RFC publication | ⏳ in progress (this session: K1.0–K1.5 of the spec deliverables) |
| Public RFC opened | ❌ not yet |
| 30-day public comment period | ❌ blocked by RFC publication |
| 60-day no-changes period | ❌ blocked by comment period |
| 6-month testnet implementation | ❌ blocked by no-changes period |
| 90-day mainnet beta | ❌ blocked by testnet validation |
| Mainnet freeze | ❌ blocked by mainnet beta |

The current state is **pre-RFC**. Maintainers interested in driving the RFC process should open a discussion on the project's public repository.

## Last touched

This README was created on 2026-05-09 as part of the J1 spec-only initiative. See `next_session.md` and `pending_blockers.md` in the founder's memory for current state.
