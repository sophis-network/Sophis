# Sophis Proof-of-Work Policy

**Status:** v1, drafted 2026-05-09. Pre-mainnet canonical document.
SHA-256 of this file is to be published with the T-72h mainnet
announcement so the commitments below are locked to a verifiable
timestamp prior to the chain itself.

This document is the Sophis Project's public statement on the choice
of proof-of-work algorithm and its commitment to maintaining open,
CPU-first, anti-ASIC mining. It is a binding posture, not a protocol
rule. The protocol enforces RandomX as currently selected; this
document explains the conditions under which the project would
propose changing it.

---

## 1. Algorithm

Sophis uses **RandomX** as its proof-of-work algorithm. RandomX is:

- Memory-hard (~2 GB working set), CPU-first by construction
- Originally specified by tevador and the Monero community (2019)
- Battle-tested in Monero production since November 2019
- Inherited by Sophis literally — the same reference algorithm, the
  same tunings, the same dataset structure

RandomX targets fairness through two mechanisms: (a) the working-set
size makes ASIC implementations structurally unprofitable relative to
CPUs; (b) the JIT-compiled virtual machine design means an ASIC must
replicate a small general-purpose CPU, defeating the design margin
that gives custom silicon its edge against narrow-purpose hashes.

Reference implementation: `consensus/pow/` (Sophis), upstream
`tevador/RandomX` (algorithm).

## 2. Commitment

The Sophis Project commits, **publicly and prior to mainnet**, to the
following posture on mining hardware:

> If an ASIC implementation of RandomX (or a sufficiently
> RandomX-tuned FPGA implementation) emerges that delivers a
> sustained price-performance advantage over commodity CPU hardware
> significant enough to threaten open-membership mining, the project
> will propose a hard-fork change of the proof-of-work algorithm via
> the SIP process (§4).

This is a stated posture, not a protocol rule. The protocol does not
detect ASICs; humans do. The project commits to acting on that
detection within the constraints of §4.

## 3. Detection criteria

"ASIC presence" is determined empirically, not by speculation. The
criteria, in rough order of weight:

1. **Public hardware emergence** — an ASIC manufacturer announces,
   ships, or sells a RandomX-targeted product, or such a product is
   documented by independent reporting
2. **Hashrate distribution shift** — the public dashboard (Roadmap
   item I1, Hyperliquid-style status page) shows a sudden, sustained
   step-change in network hashrate (>3× over weeks) inconsistent
   with CPU adoption rates
3. **Per-watt efficiency floor breach** — third-party benchmarks
   document hardware delivering hashrate-per-watt several-fold beyond
   the best commodity CPU at the time
4. **Block-template signal analysis** — solo / pool distribution
   patterns indicate concentrated minting from non-CPU sources, e.g.
   a small set of addresses producing blocks at a hashrate that
   commodity hardware cannot explain

No single criterion is sufficient. The judgment is necessarily
community-driven and lives in public discussion (GitHub, mailing
list, IRC) before any SIP is filed. FUD is not evidence.

## 4. Response procedure

If §3 criteria are met to the satisfaction of the maintainer
collective, the response follows:

1. **Public discussion period** — minimum 60 days from first SIP
   draft to first call for ACK
2. **SIP filing** — formal Sophis Improvement Proposal documenting
   evidence, proposed algorithm, and migration plan
   (`SIPS/SIP-0-process.md`)
3. **Notice window** — minimum 90 days between SIP merge and the
   canary block height. The notice window allows miners to migrate
   hardware, exchanges to update node software, and third-party
   tooling to validate the new algorithm
4. **Canary block height** — fixed in advance, hard-coded in the
   release that activates the new algorithm
5. **Cutover** — at canary height, the validation rule changes;
   pre-fork blocks remain valid as the historical chain

No emergency activation for the anti-ASIC scenario. ASIC emergence
is not a security incident; it is a market-structure shift that
admits planning. (The emergency procedure in `HARD_FORK_POLICY.md`
§5 applies only to actively exploited consensus-level vulnerabilities
and does not extend to PoW changes.)

The procedure does **not** specify which algorithm replaces RandomX.
That choice belongs to the SIP discussion at the time, informed by
the state of memory-hard CPU-friendly PoW research at that point.

## 5. Historical reference — Monero

Monero, the originator of RandomX, has executed three anti-ASIC
algorithm changes:

| Year | Change | Trigger |
|---|---|---|
| 2017 | CryptoNight → CryptoNight-v7 | Bitmain X3 ASIC announced |
| 2018 | CryptoNight-v7 → CryptoNight-v2 (CNv2) | Subsequent ASIC iterations |
| 2019 | CryptoNight-v2 → RandomX | Long-term anti-ASIC architecture |

Monero's experience demonstrates two facts that inform Sophis policy:

- **Scheduled hard-fork cadences create attack windows.** Monero ran
  a 6-month scheduled cadence from 2017 to 2022, which was exploited
  by parties timing actions around predictable activation dates and
  slowly entrenched "we ship something every 6 months" as a forcing
  function for unnecessary changes. Monero abandoned scheduled
  cadence in 2022. Sophis adopts the lesson directly — see
  `HARD_FORK_POLICY.md`.
- **Three successive anti-ASIC HFs are achievable.** A community can
  credibly defend CPU-mining against repeated ASIC pressure if it
  commits to do so in advance and communicates clearly.

## 6. What this is NOT

This policy is **not**:

- **Not a guarantee that ASICs will never exist.** ASICs may emerge
  regardless of the project's intent. The commitment is to act, not
  to prevent.
- **Not a contract with miners.** No party has standing to compel
  the project to fork. The community decides.
- **Not a commitment to fork on first mention of ASIC.** The §3
  criteria are deliberately conservative.
- **Not a commitment to RandomX specifically and forever.** If a
  future SIP demonstrates a strictly superior memory-hard CPU PoW,
  the project may propose migrating to it for non-ASIC reasons. The
  §4 procedure applies regardless of motivation.

## 7. Why this matters

Open-membership PoW is the foundation of Sophis's regulatory and
economic posture. If mining concentrates into a small set of
specialist hardware operators, the chain inherits the centralization
vectors PoS chains were designed around — exchange-staking
concentration, validator-set capture, and the legal-attribution risk
that follows from identifiable, professional operators.

The project's broader commitment to non-curated, non-custodial
operation (`OPERATIONAL_BOUNDARIES.md`) holds only while the
network's hashrate is distributed across general-purpose hardware.
This document protects that condition.

## 8. Reference

- Algorithm: `consensus/pow/`, upstream `tevador/RandomX`
- SIP process: `SIPS/SIP-0-process.md`
- Companion documents: `HARD_FORK_POLICY.md`, `OPERATIONAL_BOUNDARIES.md`,
  `MONETARY_POLICY.md`, `FOUNDER_SELF_RESTRICTION.md`
- Cultural reference: `project_monero_lessons.md` (memory) — Monero
  anti-ASIC history
