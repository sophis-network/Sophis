```
SIP: 11
Title: PQC-Native Oracle (Phase 9)
Author: Hiroshi Tatakawa <sophis-network@proton.me>
Status: Draft
Type: Standards
Created: 2026-05-11
Requires: 0
```

# SIP-11: PQC-Native Oracle

> **Status note:** this SIP ratifies the design committed in
> `docs/PQC_NATIVE_ORACLE_DESIGN.md`. The foundation crate
> `oracle/pqc-core` (wire-format types + sign/verify helpers + tests)
> ships in the same PR as this SIP. The aggregator contract, publisher
> CLI, dual-path Phase 5 integration, and pipeline tests follow in
> companion PRs — **all pre-testnet**, as Phase 9 must reach feature
> parity with Phase 5 before any chain goes live carrying an oracle
> consumer in production.

## 1. Abstract

Phase 5 ZK-Oracle Aggregator (the original Sophis oracle path)
verifies ed25519 signatures from Pyth publishers inside a Plonky3
STARK and accepts the aggregated price. The STARK itself is
post-quantum secure (BabyBear field + Poseidon2 + FRI), but the
verification is *of* a classical signature. A quantum adversary that
breaks ed25519 can forge a Pyth publisher signature, the relayer
accepts it, the STARK proves verification correctly succeeded, and
Sophis L1 ingests the resulting (forged) price.

SIP-11 replaces that trust chain with a Sophis-native publisher set
that signs each price attestation directly with Dilithium ML-DSA-44
(the same primitive used at the L1 signing layer). Publishers submit
ordinary on-chain transactions; an sVM aggregator contract collects
submissions within a per-feed time window and reports the median.

Phase 5 and Phase 9 coexist during migration: per-feed source flips
from Phase 5 to Phase 9 when ≥ 3 Sophis-native publishers have been
contributing accurate attestations for ≥ 7 days. Hard removal of
Phase 5 is gated on a future SIP.

## 2. Motivation

See `docs/PQC_NATIVE_ORACLE_DESIGN.md` § 1 for the canonical
motivation. Summary:

- Phase 5 is the last classical-crypto trust dependency in the
  Sophis stack.
- It is also the only such dependency whose failure has a clear
  economic blast radius: oracle feed corruption → DeFi
  liquidation / settlement errors → user funds at risk.
- Quantum risk to ed25519 is not imminent but is a known direction
  of travel; Sophis's PQC-first posture demands the path be closed
  before the chain accrues meaningful oracle-consumer TVL.
- Sophis's no-foundation / no-curation posture (Decisão 6, regulatory
  pivot of 2026-05-04) precludes a Pyth-style curated publisher set
  even if the cryptography were post-quantum. SIP-11 design is
  open-permissioned by construction.

## 3. Specification

The technically complete specification is at
`docs/PQC_NATIVE_ORACLE_DESIGN.md`. It enumerates:

- 12 ratified design decisions (D1–D12, § 2)
- Wire format with byte-level borsh layout (§ 3)
- Aggregator contract semantics — submission validation steps,
  median computation, staleness handling (§ 4)
- Cost / scaling analysis at 10 BPS with current block mass (§ 5)
- Migration path from Phase 5 (§ 6)
- Comparison with Pyth pull pattern (§ 7)
- Security model — 5 enumerated adversaries (§ 8)
- Out-of-scope items deferred to Phase 9.x SIPs (§ 9)

This SIP is the public-process ratification of those decisions; the
design doc is the technical reference.

## 4. Rationale

Three decisions deserve specific public airing here, beyond the
design doc:

**Direct submission vs STARK aggregation (D1).** A natural alternative
is to keep Phase 5's architecture but swap the ed25519 verify chips
for Dilithium verify chips. This is rejected for v1 because Dilithium
verification has ~1-2 orders of magnitude more STARK constraints than
ed25519 (rejection sampling, NTT polynomial operations, ≥ 1312-byte
public-key handling). The prover cost would dominate the relayer
budget and require months of Etapa-3-style chip research. Direct
submission ships in weeks using primitives already in
`Capability::VerifyDilithium`. STARK aggregation is a Phase 9.x
optimisation path, not a v1 requirement.

**Open-permissioned publisher registry (D3).** A natural alternative
is the Pyth model — a curated set of known institutional publishers
under the chain's foundation's stewardship. This is rejected because
Sophis has no foundation and the core team is contractually
non-curator. Open-permissioned with reputation accrual (D12 v2)
matches the rest of the Sophis posture. The cost is that the day-zero
publisher set is whoever shows up; the benefit is that no entity is
needed to vet publishers and no entity bears liability for their
behaviour.

**Equal-weight median in v1, reputation weighting in v2 (D12).**
Reputation algorithms are easy to get wrong at design time and hard
to fix after launch. v1 ships the simplest aggregation that resists
single-publisher adversaries (median with quorum 3) and lets empirical
data shape the v2 weighting. The v2 design will use blue-score-anchored
uptime and post-aggregation accuracy as inputs; v1 commits to the
data collection but not the algorithm.

## 5. Backwards compatibility

Phase 9 introduces a **new aggregator contract** and a **new wire
format**. Phase 5 remains operational; existing Phase 5 consumers see
no change. Feeds flip from Phase 5 to Phase 9 individually, on a
per-feed timetable, governed by the aggregator's `update_feed_source`
call.

No L1 hard fork is required. The new wire format lives at the sVM
contract layer (Dilithium sigs verified via existing capability),
under a new `Capability::VerifyDilithium` consumer.

## 6. Reference implementation

This PR ships:

- `oracle/pqc-core/` — frozen wire-format types (`PriceAttestationCore`,
  `PriceAttestation`) + signing / verification helpers built on
  `libcrux-ml-dsa` + tests covering encode/decode roundtrip, sign /
  verify happy path, rejection of malformed sigs, rejection of
  cross-domain replay attempts, and rejection of expired timestamps.

Companion PRs (pre-testnet) ship:

- `oracle/pqc-contract/` — aggregator contract template + WASM build
- `oracle/pqc-publisher/` — publisher CLI binary that signs and
  submits attestations on a configurable schedule
- Phase 5 / Phase 9 dual-path dispatch in the aggregator
- `oracle/pqc-tests/` — end-to-end integration tests
- `oracle/docs/PHASE9_RUNBOOK.md` — operator guide

## 7. Test plan

In-scope for this PR:

- Encode / decode roundtrip for `PriceAttestation` (borsh).
- Sign / verify happy path with a generated Dilithium keypair.
- Verify rejects: tampered core, tampered signature, wrong pubkey,
  wrong domain separator, expired timestamp.
- Cross-domain replay: signature over `b"sophis-oracle-pqc-v1\0"` must
  not validate when the verifier checks `b"sophis-other-domain\0"`.

In-scope for companion PRs:

- Aggregator: submission acceptance / rejection paths (8 validation
  steps per § 4.2 of the design doc).
- Aggregator: median computation with quorum / below-quorum / staleness
  transitions.
- Publisher CLI: end-to-end submit + read with multiple publishers.
- Phase 5 / Phase 9 dual-path: a feed served by both sources, source
  flip flow.
- Devnet smoke test: 3 publishers + 1 aggregator + 1 consumer over 1
  hour, observing median stability vs Pyth reference.

## 8. Open questions

These are deliberately not pinned by SIP-11 and remain available for
community input:

- **Quorum floor of 3 vs higher.** v1 mandates 3 as floor; per-feed
  override permitted. Empirical data may motivate raising the floor
  in a follow-up SIP.
- **Reputation weighting algorithm shape.** v2 SIP will pin specific
  weights and tunables; v1 only commits to the data collection.
- **Hard-removal criteria for Phase 5.** A future SIP defines them.
  This SIP commits only that Phase 5 will eventually be removed.
- **Privacy-preserving publishers.** v1 is transparent; a future SIP
  may add commit-reveal patterns if submission-timing confidentiality
  becomes operationally valuable.
- **Cross-asset sanity checks at the contract layer.** v1 trusts the
  median; a future SIP may add cross-asset arbitrage-bound rejection
  rules.

## 9. References

- `docs/PQC_NATIVE_ORACLE_DESIGN.md` — full technical specification
- `docs/PRE_MAINNET_AUDIT.md` § 1.3 — original ed25519 residual identification
- FIPS 204 (ML-DSA) — the Dilithium standard SIP-11 builds on
- Pyth Network pull architecture — the predecessor design Phase 5 mirrored
- `SIPS/SIP-0-process.md` — SIP process
