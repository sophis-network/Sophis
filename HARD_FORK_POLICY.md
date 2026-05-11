# Sophis Hard Fork Policy

**Status:** v1, drafted 2026-05-09. Pre-mainnet canonical document.
SHA-256 of this file is to be published with the T-72h mainnet
announcement so the commitments below are locked to a verifiable
timestamp prior to the chain itself.

This document is the Sophis Project's public posture on
consensus-rule changes (hard forks) post-mainnet. It is a binding
posture, not a protocol rule. The protocol does not enforce the
constraints below; the project commits to following them.

---

## 1. Default: slow change

Sophis adopts the Bitcoin Core posture on post-launch protocol
evolution: **slow change is a feature, not a bug.** Once mainnet is
live, the protocol is treated as a stable substrate that other
software builds on. Changes that would require every node operator,
exchange, miner, and wallet developer to act are made rarely,
deliberately, and only when the case is overwhelmingly clear.

This is the opposite of "move fast and iterate", and it is
deliberate. A protocol that changes constantly is one that builders
cannot commit to.

## 2. No scheduled cadence

Sophis does **not** schedule hard forks. There is no fixed cadence —
no "yearly HF", no "spring/autumn release of consensus changes".
Every hard fork is initiated only by a specific need that justifies
the disruption.

This is a direct lesson from Monero (`project_monero_lessons.md`):
from 2017 to 2022, Monero ran a 6-month scheduled cadence which
created predictable attack windows around activation dates and
slowly entrenched "we have to ship something every 6 months" as a
forcing function for unnecessary changes. Monero abandoned scheduled
cadence in 2022. Sophis starts with the lesson already absorbed.

## 3. Yearly maximum

The Sophis Project commits not to merge more than **one
hard-fork-activating SIP per 12-month rolling window**, except in §5
emergencies. The cap binds maintainer-led merges; community forks
are out of scope of this commitment (any group is free to fork).

The cap is **not a goal**. The realistic expectation is **zero hard
forks per year** in a healthy state. The cap exists to prevent
normalization of consensus changes through accumulation.

## 4. SIP-required

Every hard fork begins with a SIP (Sophis Improvement Proposal)
following `SIPS/SIP-0-process.md`. The SIP must:

- Document the technical problem and the proposed change
- Provide a reference implementation or pseudocode sufficient for
  review
- Specify activation logic (canary block height, signaling
  mechanism)
- Document the migration path for miners, exchanges, wallets, and
  third-party tooling
- Include rollback considerations if the fork fails to activate
  cleanly

Discussion proceeds publicly on `sophis-network/Sophis` GitHub and on
whatever public mailing list / IRC channel the maintainer collective
is using at that time. ACK/NACK culture (Bitcoin-style code review)
governs merge.

The minimum public discussion period is **60 days** from first SIP
draft to first call for ACK. The minimum notice window between SIP
merge and canary activation is **90 days**.

## 5. Emergency-only window

A hard fork may be activated in less than the §4 timeline only when:

- A consensus-level vulnerability is being actively exploited or is
  imminently exploitable, **AND**
- The fix cannot be delivered as a soft fork or as a non-consensus
  mitigation, **AND**
- The maintainer collective publishes a public emergency advisory
  simultaneously with the fix release

Even under emergency, the activation height must be far enough out
(typically ≥7 days, ≥6M blocks at 10 BPS) for non-malicious miners
and exchanges to upgrade. The "emergency" qualifies the **discussion
timeline**, not the **activation cliff**.

The bar for invoking §5 is high. It does NOT cover:

- "We discovered a better algorithm" — §4 procedure applies
- "An ASIC was announced" — §4 procedure plus `POW_POLICY.md`
- "Throughput / latency / fee market is suboptimal" — soft fork or
  no fork
- "A popular dApp wants this" — §4 procedure if the case is general;
  otherwise no
- Any change that adds new functionality — §4 procedure regardless
  of how clear the win seems

## 6. What is in scope

A "hard fork" under this policy is any consensus-rule change that
would cause an upgraded node to reject a block that an unupgraded
node would accept, or vice versa. Examples that are in scope:

- Block validity rule changes (PoW algorithm, signature scheme,
  opcode semantics)
- Block-mass / fee-mechanism changes that affect what is includable
- Coinbase rules (changes are governed additionally by
  `MONETARY_POLICY.md` §2.1, which forbids reintroducing
  devfund-style splits via hard fork)
- New opcodes or capabilities that pre-existing nodes would not
  validate
- Changes to address prefix or signature format

Out of scope of this policy (allowed under normal SIP process
without §3 yearly cap):

- Soft forks (changes only making previously-valid blocks invalid in
  a strict subset)
- Non-consensus changes (RPC additions, gossip optimizations, log
  format)
- Off-chain components (relayers, third-party bridges, wallet UX)
- Documentation, build, CI, dependency updates

## 7. Anti-rug invariants — never via hard fork

Independent of any SIP, certain invariants are **never** to be
relaxed via hard fork without effectively changing the chain's
identity:

1. **Fixed supply 210M SPHS** (`MONETARY_POLICY.md` §8.1)
2. **Coinbase 100% to miner** — no splits, no schedules, no
   compulsory recipient (`MONETARY_POLICY.md` §8.2;
   `DECISOES_2026-05-04.md` decision #2)
3. **No retroactive premine** (`MONETARY_POLICY.md` §8.4)
4. **Dilithium-only signature scheme** — no reintroduction of
   pre-quantum primitives (Schnorr, secp256k1, ECDSA, ed25519
   outside designated oracle contexts) into the user-facing
   transaction signature path
5. **No native privacy primitives** — no FHE, no mixers, no ring
   signatures, no confidential transactions, no native shielded
   pool (`DECISOES_2026-05-04.md` decision #5)
6. **No core-team-operated bridge or treasury**
   (`DECISOES_2026-05-04.md` decision #4,
   `OPERATIONAL_BOUNDARIES.md`)

A SIP that proposes any of (1)–(6) will be NACKed by the present
maintainer collective. Such a fork would create a different chain by
economics or by cryptographic foundation, regardless of what name
ships in the binary.

## 8. Cultural reference

This policy follows from observation of three reference points:

- **Bitcoin Core (positive):** 16+ years of slow consensus
  evolution, ACK/NACK culture, anti-feature-creep ethos. The protocol
  that programmers can build on for a decade.
- **Monero (positive correction):** 5 years of scheduled cadence
  (2017–2022), then explicit abandonment after recognizing the
  attack-window cost. The lesson is internalized at Sophis genesis.
- **Ethereum (negative reference):** frequent consensus changes and
  multiple coordinated transitions in early history. Builders
  responded by routing around mainnet (L2 proliferation). Sophis
  would rather not force that route.

## 9. Reference

- SIP process: `SIPS/SIP-0-process.md`, `SIPS/SIP-template.md`
- Companion documents: `POW_POLICY.md`, `MONETARY_POLICY.md`,
  `OPERATIONAL_BOUNDARIES.md`, `FOUNDER_SELF_RESTRICTION.md`
- Cultural references: `project_bitcoin_lessons.md`,
  `project_monero_lessons.md` (memory)
- Pivot decision: `DECISOES_2026-05-04.md`
