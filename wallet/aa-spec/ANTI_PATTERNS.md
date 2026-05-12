# Account Abstraction Anti-Patterns

**Status:** Pre-RFC draft. Empirical-cases section may be updated as new failures emerge in production on other chains.

**Author:** Marcelo Delgado <sophis-network@proton.me>

**Date:** 2026-05-09

---

## 0. Purpose

This document lists design choices that any Sophis Account Abstraction implementation MUST reject, even when they are convenient, even when other chains do them, and even when users request them.

Each anti-pattern is documented with:

- **What:** the pattern in plain terms
- **Why it is rejected:** the structural reason, not just opinion
- **Empirical case:** a production system where this pattern caused harm or risk
- **Acceptable alternative:** what to do instead, when there is one

If a future maintainer believes one of these anti-patterns should be allowed despite this document, the SIP must explicitly cite this document and argue why the rejection no longer applies. "Times have changed" is not an argument; the structural reason is what matters.

---

## 1. Custodial fragmentation framed as "social recovery"

**What:** Splitting the user's signing key into N pieces (Shamir or similar), distributing the pieces among guardians, and reassembling the key when M guardians cooperate.

**Why it is rejected:** Guardians who collectively hold reassemblable key material are, technically and likely legally, custodians of the user's funds. The user's "self-custody" claim becomes false at the moment fragmentation occurs, because at any time M guardians could collude to reconstitute the key without the user's involvement and without leaving an on-chain trace.

This collapses the legal distinction between "the user holds their key" (clear non-custodial) and "the user has shared the key with N people" (custodial under FATF / FinCEN / MiCA definitions, regardless of contract framing). The pattern survives in many wallet products primarily because it is shipped under the marketing term "social recovery", which obscures the structural change.

**Empirical case:** Multiple production wallets (Argent, Loopring, others [VERIFY DURING RFC]) ship Shamir-based recovery and market it as social recovery. Legal status of these systems under MiCA's 2024 KYC / custody requirements is unsettled as of 2026-01; some operators have begun adding KYC steps to recovery flows, which would not be necessary in a true non-custodial design. The spec author is not aware of a successful prosecution but considers this a matter of "not yet" rather than "no risk".

**Acceptable alternative:** Owner-key rotation (Sophis D6). Guardians do not hold any portion of the user's signing key. Recovery = M-of-N guardian signatures authorize the contract to set a new owner public key. The user's old key dies; new key controls the account. Each guardian independently has their own Dilithium key, generated and held entirely by them, and their signing of a `RotateOwnerKey` message is a single-purpose authorization, not a key reconstruction.

---

## 2. "Social recovery" linguistic framing

**What:** Calling the guardian-recovery mechanism described above "social recovery", "social wallet", or "recovery by friends and family" in user-facing communications, even if the underlying implementation is owner-key rotation.

**Why it is rejected:** Linguistic framing matters legally. "Social recovery" terminology is associated in regulator-facing communications with Shamir-style fragmentation (anti-pattern #1), which is custodial. Using the same name for owner-key rotation invites the same legal classification regardless of the technical difference.

The Sophis project specifically chose a different name to make the technical and legal distinction visible: **guardian-based recovery**. This term emphasizes that guardians authorize a transition, not that they hold key material.

**Empirical case:** No specific case of confusion causing harm is documented as of 2026-01, but the linguistic conflation is observable in regulator-facing white papers from multiple wallet projects, where guardian-rotation systems are described in social-recovery language and invite questions about custodian status.

**Acceptable alternative:** Use "guardian-based recovery" in all user-facing materials, marketing, support documentation, contract names, function names, and error messages. Reserve "social recovery" only for explicit references to the rejected fragmentation pattern (e.g., "Sophis does not implement social recovery; see ANTI_PATTERNS.md §1").

---

## 3. OAuth / WebAuthn / zkLogin / "log in with [Big Tech]" key derivation

**What:** Deriving the user's wallet signing key from an OAuth identity (Google, Apple, Twitter login), a WebAuthn credential, or a zero-knowledge proof of an OAuth claim (zkLogin pattern from Sui).

**Why it is rejected:** Three independent reasons, any one of which is sufficient:

1. **Identity-provider lock-in.** The user's account becomes recoverable only by re-authenticating with the identity provider. If the provider terminates the user's account (account suspension, ToS violation, regulatory pressure on the provider), the wallet becomes permanently inaccessible. This converts the wallet from a non-custodial asset (user controls their key) to a provider-mediated asset (provider controls user's access).

2. **PQC violation.** zkLogin specifically uses Groth16 proofs over pairing-based curves (BN254 family). These curves are broken by Shor's algorithm. Adopting them in Sophis directly contradicts the project's PQC-first invariant and would require deprecation when quantum threats materialize, exactly the situation Sophis was designed to avoid.

3. **KYC vector.** Big Tech identity providers operate under KYC/AML regimes in their respective jurisdictions. Using their identities as wallet keys structurally imports those KYC obligations into Sophis wallet UX, even if Sophis itself collects no information.

**Empirical case:** Sui's zkLogin (2023) was promoted as an onboarding solution but adoption data [VERIFY DURING RFC] suggests low usage and concerns from privacy-focused communities. The pattern has been rejected by Bitcoin, Monero, and most security-conscious chains specifically because of the identity-provider dependency.

**Acceptable alternative:** Standard Dilithium key generation from BIP-39 mnemonic (the existing Sophis pattern via `dilithium-wallet`), combined with guardian-based recovery (J1) for loss-of-key scenarios. The user's key never leaves their control; the user's identity never depends on a third party.

If there is ever pressure to add OAuth-style onboarding to Sophis, the response is the rejection text in `docs/deferred-decisions.md` §3 (already published in commit `1c2c890`).

---

## 4. Official factory contract

**What:** A core-team-deployed sVM contract that creates and registers `IAccount` instances for users, optionally maintaining a directory of "verified" accounts.

**Why it is rejected:** This pattern concentrates legal-risk profile from "publishing reference code" (clear non-operation) to "operating account-creation infrastructure" (potentially classifiable as service provision). The Sophis core team operates under the deliberate posture documented in `OPERATIONAL_BOUNDARIES.md` and `project_no_entity_decision.md`: ship reference contracts under AGPL-3.0, deploy by users.

A factory contract operated by the core team would also create a directory of accounts (whatever accounts the factory created), which becomes a curation surface (next anti-pattern, §5).

**Empirical case:** ERC-4337's `EntryPoint` contract is deployed and operated as a singleton on Ethereum mainnet by various ecosystem actors; the legal posture has been the subject of multiple analyses [VERIFY DURING RFC] without consensus on whether operation constitutes service provision. The Sophis approach is to not test that boundary.

**Acceptable alternative:** Reference contracts published in `wallet/aa/` (post-RFC), deployed by users via standard sVM contract deployment. SDK provides convenience helpers for "deploy a standard 3-of-5 guardian account", but the helper is library code on the user's machine, not an operated service.

---

## 5. Verified guardian registry / curated guardian directory

**What:** An on-chain or off-chain list maintained by the core team of "trusted guardians" (e.g., reputable institutions, identity-verified individuals, KYC'd entities) recommended for use as guardians.

**Why it is rejected:** Same structural reason as the rejected H2 (`category_tag_registry`) — see `project_h2_rejected.md`. Curating a guardian list is functionally identical to curating an NGO list, and reopens the regulatory-facilitation surface that the 2026-05-04 pivot specifically closed (Decision 6 — Operational Boundaries).

The pressure to curate is inevitable once the registry exists — users will ask "who are the recommended guardians?" — and the only way to refuse the pressure is to not build the registry in the first place.

**Empirical case:** The pattern has not yet emerged in production for Account Abstraction specifically, but is widespread in custody services (Coinbase Custody, BitGo, etc.) and analogous to the operational stance the Sophis 2026-05-04 pivot was designed to avoid.

**Acceptable alternative:** Wallet UI suggests guardian categories ("a family member with a hardware wallet", "your other phone", "a trusted colleague") without naming any specific individual or institution. Users select their own guardians; the project does not curate, verify, or recommend.

---

## 6. Official paymaster operated by the core team

**What:** A paymaster contract (third party that pays gas for user operations) operated as a Sophis-team-funded service to subsidize user transactions.

**Why it is rejected:** Same reason as §4 (factory). Operating gas sponsorship is a service. The Sophis core team does not provide services. If paymasters ship in v2 (currently deferred), they will be user-deployed, third-party operated, and the SDK will provide reference code only.

**Empirical case:** Paymaster-as-a-service offerings on Ethereum (Stackup, Pimlico, etc.) operate under various legal frameworks. The arrangement is workable for entity-backed projects but is not appropriate for a no-entity project like Sophis.

**Acceptable alternative:** Paymaster pattern documented in `templates/Paymaster.template.rs.deferred` (forthcoming), implementable by any third party. SDK exposes paymaster-aware transaction construction. Sophis core ships no paymaster contract instance.

---

## 7. KYC integration in the recovery flow

**What:** Requiring users to complete KYC (identity verification, document submission, video call, etc.) as part of the guardian-recovery process, either via the contract or via a UI gate.

**Why it is rejected:** KYC integration converts the recovery process from a peer-to-peer cryptographic protocol (M guardians sign a message) into a service-mediated process (a KYC provider verifies identities before honoring guardian signatures). This is structurally custodial regardless of how the contract is written.

**Empirical case:** Some custodial recovery services have begun adding KYC steps post-MiCA (May 2024) [VERIFY DURING RFC]. Sophis explicitly designs around this trend rather than following it.

**Acceptable alternative:** Recovery is purely cryptographic. The contract verifies signatures; it does not verify identities. Users who want identity-verified guardians can choose institutions that verify identities, but the cryptographic verification on-chain is unchanged.

---

## 8. Insurance / dispute resolution / chargebacks

**What:** Building protocol-level mechanisms to "undo" a transaction, "freeze" stolen funds, or "compensate" users for loss.

**Why it is rejected:** Each of these mechanisms requires a trusted authority — an insurance pool operator, a dispute arbiter, a fund freezer. Sophis has no such authority and is not creating one.

The economic argument that "AA enables insurance, so we should add insurance" reverses the order of design priorities: protocol primitives should be neutral and minimal; economic services should be built on top by entities that take that operational burden, not by the protocol.

**Empirical case:** Multiple "DeFi insurance" projects (Nexus Mutual, etc.) have demonstrated that the insurance layer is a viable business but is also a centralization vector with real legal complexity. The Sophis layer is not the right place for it.

**Acceptable alternative:** Third parties may build insurance products on top of Sophis using sVM contracts and external coordination. The protocol does not interfere; the protocol does not subsidize; the protocol does not route claims.

---

## 9. "Aggregate signature" optimization without production-ready scheme

**What:** Adding `AggregatedSignature` as a `SignaturePayload` variant in v1 without a battle-tested aggregation scheme for Dilithium ML-DSA-44.

**Why it is rejected:** As of 2026-01, no production-ready aggregate signature scheme exists for ML-DSA. Research-grade proposals exist but none has been deployed at scale. Adopting an unverified scheme into the wire format would be the exact "Phase 4 v2" risk the spec is designed to prevent — locking in a specification that turns out to be wrong.

**Empirical case:** Schnorr aggregation (MuSig2, FROST) took 5+ years from research to production-ready libraries. ECDSA aggregation does not have a clean equivalent. Dilithium aggregation is in the same early-research stage Schnorr was in 2017.

**Acceptable alternative:** v1 ships with `MultiKey` variant (M independent signatures, lexicographically ordered). When a Dilithium aggregation scheme matures, a SIP can add a new `Aggregated` variant to the `SignaturePayload` enum without breaking existing v1 deployments — this is exactly what wire-format versioning (D3) enables.

---

## 10. Hybrid signatures (classical + post-quantum)

**What:** Schemes that require both an ECDSA signature and a Dilithium signature on the same message, intended as "defense in depth" against quantum attacks on Dilithium.

**Why it is rejected:** Sophis is PQC-only at consensus (`OpCheckSig` is disabled, only `OpCheckSigDilithium` is active). A hybrid scheme would require either re-enabling secp256k1 verification at consensus (rejected by the 2026-05-04 pivot's PQC-first invariant) or adding a parallel signature track outside consensus (defeats the "defense in depth" framing because the consensus itself is single-track).

The right response to "what if Dilithium ML-DSA-44 is broken?" is to migrate to ML-DSA-65 / ML-DSA-87 (still PQC, stronger parameters). The wire-format versioning (D3) supports this migration without hard fork.

**Empirical case:** Some PQC research papers propose hybrid schemes for transition periods. None of the surveyed AA-supporting chains (the 5 in `CONVERGENCE.md`) implement hybrid signatures.

**Acceptable alternative:** Migration to stronger Dilithium parameters via SIP, as documented in `SPEC.md` §8.3.

---

## 11. Account-bound human identity (ENS / address books / on-chain naming)

**What:** Mechanisms by which a Sophis address is publicly mapped to a human-readable name (ENS-style), a verified identity, a social media handle, or any other off-chain identifier.

**Why it is rejected:** Identity layer is intentionally NOT a Sophis core concern (whitepaper §10 / §5.6.4). The design rationale parallels Bitcoin's: the protocol provides addresses; humans coordinate naming through whatever channels they choose; the protocol does not validate identity claims.

Building identity into AA accounts also creates a privacy regression — a single address that previously was just a public key now becomes "Alice's account", correlatable across all of Alice's transactions.

**Empirical case:** ENS (Ethereum Name Service) is widely used and broadly considered a positive contribution to Ethereum UX, but is also the subject of trademark disputes, fee revenue debates, and centralization concerns around the .eth registrar. Sophis explicitly avoids these by not building the layer at all.

**Acceptable alternative:** Third parties may build naming systems in sVM (or off-chain) without core-team involvement, identical to how the project handles bridges (out-of-scope, third-party risk).

---

## 12. Hard-coded "panic button" / global pause

**What:** A mechanism by which the core team (or any specific entity) can globally disable all AA accounts, freeze the AA system, or otherwise intervene in user accounts without per-user authorization.

**Why it is rejected:** This is a kill switch. Kill switches:

1. Concentrate authority — whoever holds the key to the panic button has discretionary control over user accounts
2. Become legal targets — once the kill switch exists, regulators and courts have a button to demand it be pressed
3. Create operator status — the entity holding the kill switch is operating the system, regardless of what the contract says

Sophis has no central authority. There is no panic button.

**Empirical case:** Multiple bridge contracts and DeFi protocols have shipped with admin keys / pause functions, and have been targeted by either regulator demands or social-engineering attacks aimed at the admin holders. The pattern has been a consistent source of failures.

**Acceptable alternative:** If a critical bug is discovered in deployed AA contracts, the response is (a) public disclosure, (b) reference v2 contracts published with the fix, (c) users migrate at their own pace. The protocol does not pause; users vote with their feet by upgrading or not.

---

## 13. Tracking — what to add as new patterns emerge

This document is meant to be updated as the AA ecosystem evolves and new failure modes become visible. When adding an entry, follow the format:

- **What:** plain-language description
- **Why rejected:** structural reason (not "we don't like it" — explain the mechanism)
- **Empirical case:** at least one production system where it caused harm or visible risk
- **Acceptable alternative:** what to do instead

If a maintainer believes a listed anti-pattern should be revisited, **do not silently update this document**; open a SIP, present the case, and let the community decide. The list exists to be load-bearing — easy mutability defeats the purpose.

## 14. Last touched

2026-05-09 — initial pre-RFC draft. Cells marked `[VERIFY DURING RFC]` are explicit gaps in the founder's confidence; maintainers MUST resolve them before SIP publication.
