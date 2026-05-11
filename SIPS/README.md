# Sophis Improvement Proposals (SIPs)

This directory contains the **Sophis Improvement Proposals** — the
canonical record of design decisions and protocol changes for the
Sophis project.

A SIP is a Markdown document that describes a single, well-scoped
proposal. The format and review process are defined in
[`SIP-0-process.md`](./SIP-0-process.md).

The SIP process is modeled on Bitcoin BIPs, Ethereum EIPs, and
Hyperliquid HIPs. SIPs are released into the public domain (CC0)
so other projects can port Sophis specifications without licensing
friction; reference implementations remain under the project
licence (AGPL-3.0; see [`LICENSE`](../LICENSE)).

---

## Index

| SIP | Title | Type | Status | Created |
|---|---|---|---|---|
| [0](./SIP-0-process.md) | SIP Process and Template | Process | Active | 2026-05-08 |
| [1](./SIP-1-PSBS.md) | Partially-Signed Sophis Transactions (PSBS) | Standards | Draft | 2026-05-09 |
| [2](./SIP-2-TYPED-SIGNING.md) | Typed Data Signing for Dilithium | Standards | Draft | 2026-05-10 |
| [3](./SIP-3-ALT.md) | Address Lookup Tables (ALT) | Standards | Draft | 2026-05-10 |
| [4](./SIP-4-EVENTS.md) | sVM Event Logs | Standards | Draft | 2026-05-10 |
| [5](./SIP-5-DESCRIPTORS.md) | Wallet Descriptors (BIP-380-style, Dilithium-aware) | Standards | Draft | 2026-05-11 |
| [7](./SIP-7-LIGHT-CLIENT.md) | Light Client SPV Protocol | Standards | Draft | 2026-05-10 |
| [8](./SIP-8-PRUNING-POLICY.md) | Pruning Policy + getPruningInfo RPC | Standards | Draft | 2026-05-11 |
| [9](./SIP-9-POSEIDON.md) | Canonical Poseidon Specification (spec-only) | Standards | Draft | 2026-05-11 |
| [10](./SIP-10-MULTICALL.md) | Multicall Pattern (SDK contract template) | Standards | Draft | 2026-05-11 |
| [11](./SIP-11-PQC-ORACLE.md) | PQC-Native Oracle (Phase 9) | Standards | Draft | 2026-05-11 |

(Index will grow as SIPs are submitted and accepted. Maintainers
update this table when a SIP changes status.)

---

## How to submit a SIP

1. Read [`SIP-0-process.md`](./SIP-0-process.md). All sections are
   short. Skim §2 ("When a SIP is required") to confirm your
   change needs one.
2. Copy [`SIP-template.md`](./SIP-template.md) to a new file
   `SIP-DRAFT-short-name.md` in this directory.
3. Fill in every section. Sections marked mandatory cannot be
   omitted.
4. Open a Pull Request titled `SIP-DRAFT: <Title>`. Use
   `git commit -s` per the DCO (see
   [`CONTRIBUTING.md`](../CONTRIBUTING.md) § DCO).
5. Discussion happens in the PR. A maintainer assigns the SIP
   number when it is ready to move from Draft to Review.

If you are unsure whether your idea fits, open a GitHub Issue
describing the problem before writing the SIP.

---

## Why SIPs

A SIP exists to:

- Make design decisions discoverable months and years later
- Give wallets, exchanges, miners, and ecosystem participants a
  single document to read when planning their work
- Provide a public review surface so that "the founder decided"
  is never the only available account of why a change was made
- Signal to external observers (auditors, reviewers, regulators)
  that protocol changes follow a documented process rather than
  ad-hoc commits

This is the same rationale Bitcoin Core has applied since BIP-1
in 2011, and that has held up across ~600 BIPs over 13 years.

---

## What a SIP is not

A SIP is not:

- A vote. Sophis has no on-chain governance, no DAO, no token-
  weighted decision making. SIPs are reviewed by named
  maintainers (see [`MAINTAINERS.md`](../MAINTAINERS.md)).
- A funding mechanism. There is no on-chain treasury, no devfund
  split, no SIP "bounty". See
  [`MONETARY_POLICY.md`](../MONETARY_POLICY.md) § 2–3.
- A binding promise of timeline. Maintainers do not promise
  specific roadmap items by specific dates (see
  [`MAINTAINERS.md`](../MAINTAINERS.md) § 4).
- A bypass for the contribution flow in
  [`CONTRIBUTING.md`](../CONTRIBUTING.md). DCO and AGPL-3.0
  apply to SIP PRs as to all other PRs.

---

## Reference

- [`SIP-0-process.md`](./SIP-0-process.md) — process and format
- [`SIP-template.md`](./SIP-template.md) — blank template
- [`../CONTRIBUTING.md`](../CONTRIBUTING.md) — DCO, PR flow
- [`../MAINTAINERS.md`](../MAINTAINERS.md) — current maintainer set
- [`../MONETARY_POLICY.md`](../MONETARY_POLICY.md) — emission, no devfund
- [`../OPERATIONAL_BOUNDARIES.md`](../OPERATIONAL_BOUNDARIES.md) — non-custodial posture
- [`../LICENSE`](../LICENSE) — AGPL-3.0 (reference implementation)
