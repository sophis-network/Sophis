# Deferred Decisions — comparative-roadmap items intentionally not implemented

This document records design items evaluated against the Sophis roadmap and **intentionally deferred or rejected**, together with ready-made responses for when the topic comes up. The list exists so the same conversation does not need to be re-litigated repeatedly.

The items below were considered as candidates from the comparative analyses of other chains (see `pending_blockers.md` Roadmaps J/K/L/M/O and the per-chain `project_*_lessons.md` memory files) and were classified as not worth doing in the current scope.

---

## 1. ZK-VM design space document

**Origin:** Polygon lessons (reference #1) — proposed `oracle/docs/ZK_VM_DESIGN_SPACE.md` documenting the trade-offs between Risc0 (general-purpose RISC-V), Plonky3 + custom AIRs (manual specialization), and Polygon Miden (intermediate point), with justification of Sophis's Risc0 + Plonky3 choice.

**Decision:** Not writing this document.

**Why:** Audience is too narrow (only ZK-VM implementers). The justification for Sophis's choice is already embedded in the existing oracle code, the `oracle/docs/PHASE5_*` design documents, and the whitepaper §9. A standalone "design space" document would be educational rather than load-bearing, and would age quickly as Risc0 and Miden evolve.

**If asked, respond:**
> *"The trade-off between general-purpose RISC-V proving (Risc0), specialized AIR construction (Plonky3 with custom chips), and intermediate-point VMs like Polygon Miden is real, and Sophis uses both Risc0 (Phase 3 ZK-Rollup) and Plonky3 (Phase 5 ZK-Oracle) for that reason — Risc0 where general-purpose execution semantics matter, Plonky3 where dedicated chips give a constant-factor proving speedup. The current `oracle/docs/PHASE5_*` documents and whitepaper §9 cover the rationale per use case. We have not produced a separate design-space document because the choice is concrete and already documented per use, and we prefer not to maintain general comparative material that ages quickly."*

---

## 2. Security incident history document

**Origin:** Polygon lessons (reference #3) — proposed comprehensive document on disclosure procedures, emergency release process, and historical chain incidents (Polygon MATIC double-spend Dec 2021, Heimdall halts, etc.) as motivation.

**Decision:** Not writing this document at this time. Will revisit if a specific request from an exchange, auditor, or contributor justifies it.

**Why:** documenting an "emergency release process" that depends on infrastructure the project does not have would be aspirational rather than operational. Vulnerability handling is already covered by `SECURITY.md` (responsible disclosure, voluntary, no reward).

**If asked, respond:**
> *"Vulnerability disclosure follows `SECURITY.md`: report privately via GitHub private vulnerability reporting or the security email; reports are triaged on a best-effort basis and fixes coordinated with the reporter. There is no bug bounty and no monetary reward — security review is voluntary. The history of incidents on other chains (Polygon, Solana, Multichain) informs Sophis's defensive design choices — slow change post-launch, no bridge in core, PoW open-membership — but is not catalogued in a Sophis-specific document, because the choices already reflect the lessons."*

---

## 3. OAuth-as-keys anti-pattern document

**Origin:** Sui lessons — proposed `docs/anti-patterns/oauth-as-keys.md` explaining why Sophis will not adopt OAuth-based key generation (Google/Apple/Twitter login → derived key), using Sui's zkLogin as the negative example.

**Decision:** Not writing this document unless and until someone formally proposes integrating OAuth into Sophis.

**Why:** Defensive documents written without a corresponding offensive proposal are wasted effort and read as gratuitous criticism of another project. The grounds for rejection are already clear from the Sophis design — Dilithium private keys are user-generated, no third-party identity provider participates in key derivation, and the choice of pairing-based proof systems (Groth16, used by zkLogin) is incompatible with Sophis's PQC-first invariant. If a proposal arrives, the response below is the rejection letter.

**If asked, respond:**
> *"OAuth-derived keys are not on the Sophis roadmap. Three independent reasons: (1) the recovery story routes through a Big Tech identity provider (Google, Apple, etc.), which couples user wallets to centralized account recovery and the KYC framework those providers operate under — incompatible with the project's non-custodial, no-KYC posture; (2) implementations like Sui's zkLogin rely on Groth16 proofs over pairing-based curves, which are broken by Shor's algorithm and incompatible with Sophis's PQC-first invariant; (3) social-recovery and account-abstraction primitives — which do solve the legitimate UX problem OAuth-keys address — are within roadmap scope as native Dilithium-aware primitives (see Roadmap J item J1). Recovery via peer-to-peer social contacts using Dilithium signatures gives the same UX win without the Big Tech identity dependency or the PQC violation."*

---

## Re-opening criteria

Each of the items above can be re-opened. The trigger conditions:

| Item | Re-open trigger |
|---|---|
| ZK-VM design space doc | A specific external builder requests it as blocker for adoption decision |
| Security incident history doc | Reaching ≥2 active maintainers AND an external party (exchange, auditor) requests it as part of due diligence |
| OAuth-as-keys anti-pattern doc | Someone files a SIP or PR proposing OAuth integration — at which point the response above becomes the rejection rationale |

The default is to remain closed until one of these triggers actually occurs.
