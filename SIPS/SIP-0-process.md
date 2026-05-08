```
SIP: 0
Title: SIP Process and Template
Author: Hiroshi Tatakawa
Status: Active
Type: Process
Created: 2026-05-08
```

# SIP-0: SIP Process and Template

This SIP defines the **Sophis Improvement Proposal (SIP)** process —
the standardized format and review workflow for proposing changes to
the Sophis protocol, reference implementation, and surrounding
specifications.

It is itself a SIP (the meta-SIP), so future amendments to the process
follow the process it defines.

---

## 1. What a SIP is

A SIP is a Markdown document that describes a single, well-scoped
proposal for change. It serves four purposes:

1. **Specification** — the canonical technical description of the
   change, sufficient for an independent implementer to write a
   compatible client.
2. **Rationale** — why this approach was chosen over alternatives.
3. **Audit trail** — a permanent record discoverable by anyone
   inspecting the protocol months or years later.
4. **Coordination** — a single document that wallets, exchanges,
   miners, and ecosystem participants can read to plan their work.

The SIP process is modeled on BIP (Bitcoin), EIP (Ethereum), and
HIP (Hyperliquid). Differences from those are documented in §10.

> **Naming.** The canonical short name is `SIP`. The longer form
> `SBIP` (Sophis Bitcoin-style Improvement Proposal) appears in some
> early documents; both refer to the same artifact. Files in this
> directory use `SIP-` only.

---

## 2. When a SIP is required

A SIP **is required** for changes that affect:

- Consensus rules (block validation, signature schemes, opcodes,
  emission curve, coinbase rules, finality logic)
- Network protocol (P2P messages, gossip rules, DNS seed format)
- The sVM ABI, host functions, capability set, gas accounting
- ZK-Rollup (Phase 3) journal format, sequencer rules, bridge
  contracts
- ZK-Oracle (Phase 5) air_id assignments, public-value layouts,
  verifier dispatch
- Data Availability (Phase 6) carrier format, version bump,
  consensus rules
- Wallet wire formats intended for ecosystem use (PSBS, descriptors,
  typed-signing schemas, address formats)
- Any change that requires a soft fork or hard fork

A SIP **is not required** for:

- Bug fixes that restore behaviour to match an existing SIP
- Refactors with no behavioural change
- Internal performance optimisations
- Documentation corrections
- Test additions
- CI / build / packaging changes

When in doubt, open a GitHub Issue first and ask. A maintainer will
tell you whether a SIP is needed.

---

## 3. SIP types

| Type | Definition |
|---|---|
| **Standards** | Changes affecting interoperability between independent implementations: consensus, P2P, sVM, rollup, oracle, DA, wallet wire formats. Requires reference implementation. |
| **Process** | Meta-proposals that change the SIP process itself, contributor flow, release cadence, or maintainer practice. SIP-0 is a Process SIP. |
| **Informational** | Design notes, recommendations, ecosystem guidelines that do not bind any implementation. Examples: "recommended CSPRNG sources", "wallet UX conventions". |

---

## 4. SIP statuses

```
                    ┌──────────┐
                    │  Draft   │  author iterating
                    └────┬─────┘
                         │
                         ▼
                    ┌──────────┐
                    │  Review  │  maintainer review (≥14 days)
                    └────┬─────┘
                         │
                         ▼
                    ┌──────────┐
                    │ Last Call│  final window (≥14 days, bugfix only)
                    └────┬─────┘
                         │
                         ▼
                    ┌──────────┐
                    │ Accepted │  approved, awaiting implementation
                    └────┬─────┘
                         │
                         ▼
                    ┌──────────┐
                    │  Final   │  deployed (or Active for Process)
                    └──────────┘

  Side states (any stage):
    Withdrawn  — author withdrew
    Rejected   — maintainers declined
    Replaced   — superseded by another SIP (link forward)
    Deferred   — paused, may resume
    Active     — non-implementing Process/Informational that lives indefinitely
```

| Status | Meaning |
|---|---|
| Draft | Author is iterating. Not yet under formal review. |
| Review | Submitted for maintainer review. Comments period. |
| Last Call | Approaching acceptance. No major changes; only bug fixes / clarifications for ≥14 days. |
| Accepted | Approved by required ACK threshold. Awaiting implementation. |
| Final | Implemented and (for Standards Track requiring activation) deployed at the announced height. |
| Active | Living document with no implementation activation (e.g., SIP-0). |
| Withdrawn | Author withdrew. PR closed. |
| Rejected | Maintainers declined. Reason recorded in PR + status note. |
| Replaced | Superseded by a newer SIP. New SIP must link back; old SIP must link forward. |
| Deferred | Paused. May resume later by author or maintainers. |

---

## 5. Workflow

### 5.1 Pre-discussion (optional)

If you are unsure whether your idea fits, open a GitHub Issue
describing the problem and your proposed direction. Maintainers and
community will weigh in before you spend time writing the SIP.

### 5.2 Submitting a Draft

1. Fork the Sophis repository.
2. Create a new file `SIPS/SIP-XXXX-short-name.md` where `XXXX` is
   the next free integer. Use `SIP-DRAFT-short-name.md` if you
   would prefer the maintainer to assign the number on review.
3. Copy `SIPS/SIP-template.md` and fill it in. All sections are
   mandatory unless explicitly marked optional.
4. Submit a Pull Request titled `SIP-XXXX: <Title>` (or
   `SIP-DRAFT: <Title>`). Use `git commit -s` per the DCO (see
   `CONTRIBUTING.md` § DCO).
5. Status in the SIP header is `Draft`.

### 5.3 Review

After community discussion in the PR, the author requests review
status by editing the SIP header (`Status: Review`) in a new commit
on the same PR. From that moment:

- A minimum **14 calendar days** of review is required.
- Maintainers leave explicit `ACK <reason>` or `NACK <reason>`
  comments (Bitcoin Core convention).
- The author may iterate based on feedback. Substantive changes
  reset the 14-day clock.

### 5.4 Last Call

When at least one maintainer has ACK'd and no maintainer has open
NACKs, the author moves the status to `Last Call`. From that moment:

- A minimum **14 additional calendar days** elapse.
- Only **bug fixes and clarifications** are accepted; no new
  features, no changed semantics.
- Substantive changes during Last Call return the SIP to Review.

### 5.5 Acceptance threshold

| Maintainer count (per `MAINTAINERS.md` § 1) | Required ACKs |
|---|---|
| 1 | 1 (founder; see §10.2) |
| 2–4 | 2 |
| 5+ | 3 (or majority, whichever is lower) |

ACKs must be from named active maintainers (not emeritus). One NACK
from an active maintainer can block acceptance; the author should
address the concern or, if they disagree, escalate per §6.

### 5.6 Acceptance

Maintainers merge the PR with status `Accepted`. The merged file is
the canonical SIP. From this point:

- Implementation tracking moves to separate PR(s) referencing the
  SIP number in the title and commit body.
- For Standards Track SIPs requiring activation (soft fork / hard
  fork), the activation height or signaling rule must be in §8.

### 5.7 Implementation and Final

The reference implementation is merged via separate PR(s). Tests,
documentation, and integration follow normal contribution flow
(`CONTRIBUTING.md`).

When the SIP is implemented in the reference client and (for
activation-gated SIPs) the activation block height is reached, a
maintainer updates the status to `Final` in a small documentation PR.

For `Process` and `Informational` SIPs that do not require
implementation, status moves directly to `Active` upon merge.

---

## 6. Conflict resolution

Disagreements between author and reviewers, or between maintainers,
are resolved in this order:

1. **Discussion in the PR.** Most disagreements close here.
2. **Public design discussion** in a GitHub Issue or RFC document
   linked from the PR.
3. **Maintainer vote** — if disagreement persists after at least
   30 days of public discussion, active maintainers may vote.
   Simple majority decides; ties default to Rejected.
4. **Withdrawal and resubmission** — a Rejected author may resubmit
   later if circumstances change (new evidence, broader support).

There is no "founder veto" beyond §10.2 below. The process must
remain credibly open for the project to remain credibly
decentralised.

---

## 7. Anti-feature-creep guidelines

This is the cultural section. It is non-binding but applied during
review.

- **Default = no.** New features must justify their value relative
  to the complexity, surface area, and review cost they add. The
  null-hypothesis answer is "do not change Sophis."
- **Slow change.** Post-mainnet, the project follows a slow-change
  culture (modeled on Bitcoin Core and Monero). Most changes will
  take months from Draft to Final, not weeks.
- **One change per SIP.** Bundle is the enemy of review. If you
  find yourself writing "and also...", split into two SIPs.
- **Reference implementation required for Standards Track.**
  No spec-without-code. The implementation does not need to be
  production-ready in the SIP PR, but it must exist and run.
- **Backward compatibility is the default.** A SIP that breaks
  compatibility must explain in §Backwards Compatibility why the
  break is justified, what the migration cost is, and whether it
  requires a hard fork or soft fork.
- **Privacy and consensus invariants.** SIPs must not introduce
  privacy primitives banned by `MONETARY_POLICY.md` /
  `OPERATIONAL_BOUNDARIES.md` (FHE, mixers, ring signatures,
  shielded transactions). SIPs must not reintroduce constructs
  removed by the regulatory pivot of 2026-05-04 (devfund on-chain,
  cross-chain bridge in core).
- **PQC purity.** Standards Track SIPs that introduce cryptographic
  primitives must be quantum-resistant under standard assumptions.
  Pairing-based primitives (BLS, BLS12-381, Pasta curves) are not
  acceptable as primary mechanisms.

---

## 8. SIP file format

Every SIP starts with a fenced code block (the **header**) followed
by a Markdown body. The header fields are:

| Field | Required | Notes |
|---|---|---|
| `SIP` | yes | integer assigned by maintainers, or `DRAFT` until assigned |
| `Title` | yes | concise; under 60 chars |
| `Author` | yes | `Name <email>` or GitHub handle; multiple authors comma-separated |
| `Status` | yes | one of §4 |
| `Type` | yes | `Standards` / `Process` / `Informational` |
| `Created` | yes | ISO date `YYYY-MM-DD` |
| `Replaces` | optional | comma-separated SIP numbers this supersedes |
| `Replaced-By` | optional | filled in when this SIP becomes Replaced |
| `Requires` | optional | other SIPs whose Final status is a prerequisite |
| `Activation-Height` | optional | block height for activation (Standards Track only) |

The body must contain these sections in this order:

1. **Abstract** — 2–3 sentences. What does this SIP propose?
2. **Motivation** — what problem does it solve?
3. **Specification** — technically complete description.
4. **Rationale** — why this approach and not the alternatives.
5. **Backwards Compatibility** — does it break things? hard or soft fork?
6. **Reference Implementation** — link to the code (PR or commit).
7. **Security Considerations** — what can go wrong?
8. **Test Vectors** — example inputs and expected outputs (mandatory for Standards Track involving cryptography or wire formats).
9. **References** — papers, prior art, related SIPs, BIPs, EIPs, HIPs.
10. **Copyright** — `This document is released into the public domain (CC0).`

The template at `SIPS/SIP-template.md` provides empty versions of
each section.

---

## 9. Numbering

- SIP-0 is reserved for this document.
- Numbers are assigned in chronological order of acceptance into
  Review status, not Draft submission. Two contemporaneous Drafts
  do not compete for a fixed number.
- Numbers are never reused. A Withdrawn SIP-12 leaves a permanent
  gap; the next assigned SIP is SIP-13.

---

## 10. Sophis-specific differences from BIP / EIP / HIP

### 10.1 No foundation, no editor role

BIPs and EIPs have a designated "editor" (Luke-Jr, Hudson Jameson,
etc.) who shepherds the process. Sophis does not. Maintainers
collectively perform the editor function: assigning numbers,
moving statuses, merging.

This is consistent with `MAINTAINERS.md` § 4 and the no-entity
posture of the project.

### 10.2 Founder phase

While `MAINTAINERS.md` § 1 lists exactly one active maintainer
(the founder), SIPs can technically be ACK'd by that single
maintainer. This is a transitional concession. To compensate:

- **Public review window is doubled** during the founder-only
  phase: 28 days for Review and 28 days for Last Call (instead of
  14 each).
- **Major Standards Track SIPs** that change consensus rules
  require a second voice — explicit endorsement by at least one
  recognised external reviewer (e.g., a contributor who has
  landed ≥3 non-trivial PRs, or an external cryptographer).
- The founder-phase concession ends automatically when ≥2
  maintainers are listed in `MAINTAINERS.md`.

### 10.3 No DAO, no on-chain voting

SIPs are not voted on by token holders. There is no on-chain
governance mechanism. The decision-making body is the maintainer
set (per `MAINTAINERS.md` § 4), accountable to the community
through public review and the right of any party to fork.

This is a deliberate choice consistent with the regulatory pivot
of 2026-05-04 (no on-chain governance vector that could be
construed as a security or as DAO custody).

### 10.4 Hard fork SIPs follow Roadmap K cultural posture

Standards Track SIPs that require a hard fork must, additionally:

- Provide ≥6 months of advance notice between Final status and
  activation height
- Include explicit miner-signaling rules
- Document the rollback plan if signaling fails
- Be discussed publicly for at least 90 days before Last Call

This is independent of the SIP review timeline and reflects the
slow-change cultural posture (`pending_blockers.md` Roadmap K
"Lições Bitcoin").

---

## 11. Copyright

This document is released into the public domain (CC0). Reference
implementations remain under the project licence (AGPL-3.0; see
`LICENSE`). The license split — public domain for the SIP text,
AGPL for the reference code — mirrors BIP / EIP convention and lets
other projects port Sophis specifications without licensing
friction.

---

## 12. References

- `CONTRIBUTING.md` — DCO, PR flow, AGPL-3.0
- `MAINTAINERS.md` — current maintainer set and onboarding
- `MONETARY_POLICY.md` — emission, no devfund, no on-chain treasury
- `OPERATIONAL_BOUNDARIES.md` — non-custodial, no entity
- `FOUNDER_SELF_RESTRICTION.md` — 5% lifetime cap, transition
- BIP-1, BIP-2 (Bitcoin Improvement Proposal process)
- EIP-1 (Ethereum Improvement Proposal process)
- `SIPS/SIP-template.md` — blank SIP template
- `SIPS/README.md` — index of all SIPs

---

**Document version:** v1
**Last updated:** 2026-05-08
