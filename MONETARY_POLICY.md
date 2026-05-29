# Sophis Monetary Policy

**Status:** v1, drafted 2026-05-06. Pre-mainnet canonical document. To be
hashed (SHA-256) and the hash published with the T-72h mainnet
announcement so the policy is locked to a verifiable timestamp prior to
the chain itself.

This document is the **complete and binding** statement of how SPHS is
created, distributed, and never (re-)allocated by any party, including
the founder. It is the monetary side of the broader pre-launch posture
documented in `OPERATIONAL_BOUNDARIES.md` and `FOUNDER_SELF_RESTRICTION.md`.

---

## 1. Issuance

| Parameter | Value |
|---|---|
| Asset symbol | **SPHS** |
| Total supply (lifetime cap) | **210,000,000 SPHS** |
| Sompi per SPHS | 100,000,000 (8 decimals) |
| Block production target | 10 blocks per second |
| Coinbase maturity | 1000 blocks (mainnet) |
| Proof-of-work | RandomX (memory-hard, CPU-first, anti-ASIC) |
| Signature scheme | ML-DSA-44 (Dilithium, FIPS 204) — post-quantum |

The emission curve is hard-coded in `consensus/core/src/config/params.rs`
and `consensus/src/processes/coinbase.rs`. The reference implementation
is the only authoritative source; this section paraphrases it for human
readers.

## 2. Coinbase distribution: 100% to the miner

**Every SPHS minted by every block goes to the miner of that block.**
There is no pre-mine, no founder allocation, no developer fund, no
treasury, no foundation reserve, no validator reward, no slashed-stake
recycling, and no community grant pool baked into the protocol. The
genesis block has zero outputs; the first SPHS that ever exists comes
out of the first non-genesis block's coinbase.

This is not a temporary configuration — it is the consensus rule. The
2026-05-04 regulatory pivot (commit `cffe1d1`) **eliminated** the
previously-planned `devfund_address` field and emission schedule from
`params.rs`. There is no path within the v1 consensus to direct any
fraction of the coinbase to anyone other than the block's miner.

### 2.1 What about future hard forks?

The Sophis core team has made a **public, irrevocable pre-mainnet
commitment** never to propose a hard fork that reintroduces a coinbase
split, a developer fund, or any compulsory recipient other than the
block's miner. This commitment is in §5 of `OPERATIONAL_BOUNDARIES.md`.

A hard fork that violates this commitment would, by construction, be
rejected by the present authors. Any community-led fork that does so
becomes a different chain by name and by economics; SPHS holders may
follow it or not, but the Sophis Project does not.

## 3. No issuer

Sophis has no issuer in the regulatory sense (FATF, MiCA, FinCEN, BCB,
SEC). There is:

- No ICO, no IDO, no IEO, no presale, no airdrop financed by issuance.
- No legal entity (no foundation, no LLC, no Cayman vehicle, no MEI/CNPJ
  attached to "Sophis"). See § 4.2 of `FOUNDER_SELF_RESTRICTION.md` and
  § 5 of `OPERATIONAL_BOUNDARIES.md` for the binding statements.
- No marketing budget funded by SPHS.
- No paid development funded by on-chain SPHS.

Anyone who wants to buy SPHS must do so peer-to-peer (mining, OTC, a
secondary market, or a third-party exchange that lists it). The Sophis
Project does not custody, broker, or facilitate the sale of SPHS.

## 4. Founder mining

The founder is allowed to mine like any other participant, with the
following self-imposed restrictions in addition to the protocol rules:

- **24h restraint window** — founder mining begins 24 hours after the
  genesis block, not at genesis.
- **Single declared address** — all founder mining lifetime accrues to
  the address `sophis:q2sdls98vf40p3v53eyu2ylu3rnfyvjr3cw3gwmuhj8pwnkkgdn5677h7448r`.
- **5% lifetime cap** — when the founder address holds 5% of the
  emitted supply, mining ceases (auto-paused at 4.9% by a public
  monitoring script).
- **Cessation is permanent** — the cap may not be reset by changing
  addresses; cumulative across the founder's lifetime.

The full text of these restrictions is in `FOUNDER_SELF_RESTRICTION.md`.

## 5. Donations and tipping

Operators of the reference miner (`sophis-miner`) MAY split their own
coinbase reward to additional addresses they choose, via the opt-in
`--donate-to <address> --donate-percent <N>` flags (commit `e54fcd9`).

This is **client-side** — it is not a consensus rule. It rewrites the
miner's own coinbase transaction before submitting the block. The
default is **off**; with the flag unset, 100% of the coinbase reward
goes to the miner.

The Sophis core team does **not curate, host, or recommend** any
donation address list. The flag exists so operators can route part of
their own rewards to causes of their choice (development, charity, an
independent maintainer). Whatever they choose is their personal
decision. See `OPERATIONAL_BOUNDARIES.md` §3 for the canonical wording.

## 6. Halvings

The emission schedule (block reward over time) is hard-coded in
`consensus/src/processes/coinbase.rs`. The full table is in the
reference implementation. There is no governance mechanism to alter
the schedule short of a hard fork; see §2.1.

## 7. SPHS as a utility token

SPHS exists to pay block-mass / transaction fees, post bonded stake in
contracts that require it, and provide the unit of account for native
tokens issued on Sophis. SPHS does **not** represent:

- A claim on the Sophis Project's labor, future updates, or roadmap
- A share of revenue from any operator
- Voting rights in any governance body
- A redemption right against any party

SPHS is a permissionless commodity-style native asset, in the lineage
of BTC and XMR. The Sophis Project's posture as an open-source
protocol developer (not an issuer, custodian, or operator) is set out
across this document and its companions `OPERATIONAL_BOUNDARIES.md`
and `HARD_FORK_POLICY.md`.

## 8. Anti-rug invariants

These invariants are **never** to be relaxed by future maintainers
without changing the chain's name:

1. **Total supply is 210,000,000 SPHS.** Not "soft" capped, not
   "subject to community vote", not "rebased". Hard ceiling.
2. **Coinbase is 100% to the miner.** No exceptions, no schedules,
   no temporary funds.
3. **Genesis has zero pre-allocated outputs.** SPHS only enters
   circulation through proof-of-work.
4. **No retroactive premine.** No edition of `params.rs` will ever
   move SPHS from "to be mined" to "already allocated to X".
5. **No on-chain treasury.** The protocol layer holds zero SPHS.

Violating any of (1)-(5) would, by the project's stated posture,
constitute a transition from open-source protocol developer to
issuer-of-a-security. The Sophis Project does not make that
transition.

## 9. Reference

- Implementation: `consensus/core/src/config/params.rs`,
  `consensus/src/processes/coinbase.rs`
- Companion documents: `FOUNDER_SELF_RESTRICTION.md`,
  `OPERATIONAL_BOUNDARIES.md`, `HARD_FORK_POLICY.md`,
  `SUCCESSION.md`, `LAUNCH_CHECKLIST.md`
