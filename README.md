# Sophis ($SPHS)

## A Fair-Launch, Post-Quantum Layer-1 BlockDAG

**Version — 2026-05-05**
**Author:** Marcelo Delgado
**Status:** devnet

---

> *"First fair-launch L1 native in post-quantum cryptography, modeled after Bitcoin's monetary discipline."*

---

# Documentation

Single navigable table of contents for the markdown files in this
repo, grouped by **audience** rather than by directory. If you don't
know where to start, scan the section that matches your role.

> Last refreshed: 2026-05-11

---

## 📄 Whitepaper — start here

- [Whitepaper.md](Whitepaper.md) — Sophis whitepaper (English). Canonical project document: vision, monetary policy, PoW + PQC stack, sVM, ZK-Rollup, oracle, governance boundaries. Read this before any section below.

---

## 🌍 Users — running a node, mining, using a wallet

You want to participate in the network: run `sophisd`, mine, hold
SPHS, send transactions.

- [sophisd/README.md](sophisd/README.md) — node binary, CLI flags, ports
- [wallet/README.md](wallet/README.md) — wallet workspace overview
- [wallet/bip39/README.md](wallet/bip39/README.md) — mnemonic generation / restore
- [SIPS/SIP-6-WALLET-VERIFICATION.md](SIPS/SIP-6-WALLET-VERIFICATION.md) — `.well-known/sophis-wallet.json` integrity spec (SIP-6)
- [docs/archival.md](docs/archival.md) — running an archive node (HDD-optimized RocksDB)
- [docs/override-params.md](docs/override-params.md) — `--override-params-file` for local testing (mainnet-blocked)
- [docs/PRUNING_POLICY.md](docs/PRUNING_POLICY.md) — pruning depth + finality window
- [bridge/docs/README.md](bridge/docs/README.md) — local-only stratum bridge for ASIC operators
- [oracle/docs/PHASE6_BUG_BOUNTY.md](oracle/docs/PHASE6_BUG_BOUNTY.md) — DA bug bounty program

---

## 🏗️ Developers — building on Sophis

You want to write a contract, deploy via the WASM sVM, or integrate
the SDK from outside.

- [docs/DEVELOPER_LANDING.md](docs/DEVELOPER_LANDING.md) — main entry point for builders
- [docs/ECOSYSTEM_OVERVIEW.md](docs/ECOSYSTEM_OVERVIEW.md) — layer architecture diagram + sub-project map
- [docs/SVM_EXECUTION_MODEL.md](docs/SVM_EXECUTION_MODEL.md) — sVM determinism, capability set, gas model
- [docs/FEE_PRIORITY.md](docs/FEE_PRIORITY.md) — 3-tier feerate API + mempool ordering
- [docs/MEMPOOL_POLICY.md](docs/MEMPOOL_POLICY.md) — RBF, packages, eviction
- [wallet/pskt/DESIGN.md](wallet/pskt/DESIGN.md) — partially-signed bundle spec (SIP-1)
- [wallet/descriptors/DESIGN.md](wallet/descriptors/DESIGN.md) — output script descriptors (SIP-5)
- [SIPS/SIP-12-AA.md](SIPS/SIP-12-AA.md) — Account Abstraction Standards-track spec (SIP-12)
- [wallet/aa-spec/README.md](wallet/aa-spec/README.md) — AA implementation guide entry
- [wallet/aa-spec/SPEC.md](wallet/aa-spec/SPEC.md) — AA full design specification (companion to SIP-12)
- [wallet/aa-spec/CONVERGENCE.md](wallet/aa-spec/CONVERGENCE.md) — AA convergence test
- [wallet/aa-spec/ANTI_PATTERNS.md](wallet/aa-spec/ANTI_PATTERNS.md) — AA anti-patterns (zkLogin, etc.)
- [wallet/aa-spec/OPERATIONAL_BOUNDARIES_PARAGRAPH.md](wallet/aa-spec/OPERATIONAL_BOUNDARIES_PARAGRAPH.md) — AA section of operator statement
- [wallet/multicall-template/README.md](wallet/multicall-template/README.md) — Multicall sample (SIP-10)
- [wasm/README.md](wasm/README.md) — WASM SDK overview
- [wasm/CHANGELOG.md](wasm/CHANGELOG.md) — WASM SDK release notes
- [wasm/npm/README.md](wasm/npm/README.md) — NPM package
- [wasm/examples/browser-extension/README.md](wasm/examples/browser-extension/README.md) — browser extension example
- [wasm/examples/nodejs/typescript/README.md](wasm/examples/nodejs/typescript/README.md) — Node.js TS example

---

## 🔧 Operators — running services & infrastructure

You want to operate a publisher, indexer, DA carrier, or runbook your
own production deployment.

- [docs/L1_RUNBOOK.md](docs/L1_RUNBOOK.md) — Address Lookup Tables operator guide
- [docs/I1_RUNBOOK.md](docs/I1_RUNBOOK.md) — public dashboard hosting
- [docs/J4_RUNBOOK.md](docs/J4_RUNBOOK.md) — sVM event indexer ops
- [oracle/docs/PHASE9_RUNBOOK.md](oracle/docs/PHASE9_RUNBOOK.md) — Phase 9 PQC publisher / indexer / consumer operations
- [oracle/docs/PHASE9_3_DUAL_PATH.md](oracle/docs/PHASE9_3_DUAL_PATH.md) — Phase 5 ↔ Phase 9 dispatch pattern
- [oracle/docs/PHASE6_RUNBOOK.md](oracle/docs/PHASE6_RUNBOOK.md) — DA carrier publisher / consumer ops
- [oracle/docs/PHASE6_STRESS_PLAN.md](oracle/docs/PHASE6_STRESS_PLAN.md) — pre-mainnet DA stress acceptance gates
- [oracle/docs/PHASE6_AUDIT.md](oracle/docs/PHASE6_AUDIT.md) — DA threat matrix + adversarial scenarios
- [oracle/docs/PHASE6_RFC.md](oracle/docs/PHASE6_RFC.md) — DA RFC for community review

---

## ⚖️ Governance & policy — legal / political surface

These documents are the project's public commitments. Each one is
individually addressable (citable by URL + commit hash) — they are
intentionally separate so that links don't drift.

- [MONETARY_POLICY.md](MONETARY_POLICY.md) — emission curve, no pre-mine, no devfund, supply cap
- [FOUNDER_SELF_RESTRICTION.md](FOUNDER_SELF_RESTRICTION.md) — 5% lifetime mining cap + pause mechanism
- [OPERATIONAL_BOUNDARIES.md](OPERATIONAL_BOUNDARIES.md) — non-custodial team scope
- [SUCCESSION.md](SUCCESSION.md) — keys / marks / domain handover plan
- [MAINTAINERS.md](MAINTAINERS.md) — maintainer roster + onboarding
- [HARD_FORK_POLICY.md](HARD_FORK_POLICY.md) — when and how a hard fork is acceptable
- [POW_POLICY.md](POW_POLICY.md) — RandomX commitment + algorithm selector reserved field
- [LAUNCH_CHECKLIST.md](LAUNCH_CHECKLIST.md) — pre-mainnet operational checklist
- [docs/PRE_MAINNET_AUDIT.md](docs/PRE_MAINNET_AUDIT.md) — pre-PQC residual + dead-code audit

---

## 📜 SIPs — numbered improvement proposals

Sophis follows a BIP/EIP-style proposal process. Each SIP is
immutable once accepted; numbered gaps are reserved.

- [SIPS/README.md](SIPS/README.md) — SIPs index
- [SIPS/SIP-0-process.md](SIPS/SIP-0-process.md) — SIP process spec
- [SIPS/SIP-template.md](SIPS/SIP-template.md) — template for new proposals
- [SIPS/SIP-1-PSBS.md](SIPS/SIP-1-PSBS.md) — Partially-signed bundle spec
- [SIPS/SIP-2-TYPED-SIGNING.md](SIPS/SIP-2-TYPED-SIGNING.md) — EIP-712-equivalent for Dilithium
- [SIPS/SIP-3-ALT.md](SIPS/SIP-3-ALT.md) — Address Lookup Tables
- [SIPS/SIP-4-EVENTS.md](SIPS/SIP-4-EVENTS.md) — sVM event logs
- [SIPS/SIP-5-DESCRIPTORS.md](SIPS/SIP-5-DESCRIPTORS.md) — Wallet descriptors (BIP-380-style, Dilithium-aware)
- [SIPS/SIP-7-LIGHT-CLIENT.md](SIPS/SIP-7-LIGHT-CLIENT.md) — Light client SPV
- [SIPS/SIP-8-PRUNING-POLICY.md](SIPS/SIP-8-PRUNING-POLICY.md) — State pruning policy
- [SIPS/SIP-9-POSEIDON.md](SIPS/SIP-9-POSEIDON.md) — Poseidon canonical hash (spec-only)
- [SIPS/SIP-10-MULTICALL.md](SIPS/SIP-10-MULTICALL.md) — Multicall pattern
- [SIPS/SIP-11-PQC-ORACLE.md](SIPS/SIP-11-PQC-ORACLE.md) — PQC-native oracle

---

## 🔬 Architecture & design — roadmap feature docs

Design rationale, ABI freeze tables, and constants for each roadmap
item. Each design doc pairs with a SIP (where applicable) and may
have a separate runbook under §Operators above.

- [docs/PQC_NATIVE_ORACLE_DESIGN.md](docs/PQC_NATIVE_ORACLE_DESIGN.md) — Phase 9 oracle (SIP-11)
- [docs/L1_ALT_DESIGN.md](docs/L1_ALT_DESIGN.md) — Address Lookup Tables (SIP-3)
- [docs/I1_DASHBOARD_DESIGN.md](docs/I1_DASHBOARD_DESIGN.md) — public dashboard backend / frontend
- [docs/J4_EVENTS_DESIGN.md](docs/J4_EVENTS_DESIGN.md) — sVM event logs (SIP-4)
- [docs/J3_VRF_DESIGN.md](docs/J3_VRF_DESIGN.md) — native VRF via RandomX block hash
- [docs/J2_TYPED_SIGNING_DESIGN.md](docs/J2_TYPED_SIGNING_DESIGN.md) — typed signing (SIP-2)
- [docs/L3_COMMITMENT_DESIGN.md](docs/L3_COMMITMENT_DESIGN.md) — Pending/Accepted/Confirmed/Finalized levels
- [docs/H1_CALCULATOR_DESIGN.md](docs/H1_CALCULATOR_DESIGN.md) — Energy Offset calculator
- [docs/K2_COMPACT_FILTERS_DESIGN.md](docs/K2_COMPACT_FILTERS_DESIGN.md) — BIP-157/158-equivalent SPV filters
- [docs/J5_LIGHT_CLIENT_DESIGN.md](docs/J5_LIGHT_CLIENT_DESIGN.md) — Light client SPV library (SIP-7)
- [docs/J8_PRUNING_AUDIT.md](docs/J8_PRUNING_AUDIT.md) — pruning audit + RPC (SIP-8)
- [docs/J6_POSEIDON_DESIGN.md](docs/J6_POSEIDON_DESIGN.md) — Poseidon spec (SIP-9)
- [docs/J7_MULTICALL_DESIGN.md](docs/J7_MULTICALL_DESIGN.md) — Multicall pattern (SIP-10)
- [oracle/docs/PHASE6_DA_DESIGN.md](oracle/docs/PHASE6_DA_DESIGN.md) — Phase 6 self-DA design

---

## 🤝 Contributors — devs working ON Sophis itself

If you are sending a PR, reviewing code, or onboarding to the
codebase as a maintainer, these are your starting points.

- [CONTRIBUTING.md](CONTRIBUTING.md) — DCO + PR workflow
- [CLAUDE.md](CLAUDE.md) — Claude Code dev guide for this repo (build env, gotchas, invariants)
- [docs/deferred-decisions.md](docs/deferred-decisions.md) — "why we said no to X" — read before proposing comparable-chain features
- [consensus/src/processes/Parallel Processing.md](consensus/src/processes/Parallel%20Processing.md) — DAG block processing design
- [notify/src/subscription/processing.md](notify/src/subscription/processing.md) — subscription system design
- [rpc/core/src/api/Extending RpcApi.md](rpc/core/src/api/Extending%20RpcApi.md) — HOWTO add an RPC method
- [.github/ISSUE_TEMPLATE/bug_report.md](.github/ISSUE_TEMPLATE/bug_report.md)
- [.github/ISSUE_TEMPLATE/feature_request.md](.github/ISSUE_TEMPLATE/feature_request.md)

---

## ⛔ Deprecated — Phase 5 ZK-Oracle (do not start new integrations)

Phase 5 (Pyth + Plonky3 STARK + ed25519 trust chain) was deprecated on
2026-05-11 and is scheduled for deletion after Phase 9 publisher
quorum bootstrap per SIP-11 D11. The five Phase 5 documents under
`oracle/docs/` (ABI.md, CONTRACT_DISPATCH.md, RUNBOOK.md, and the two
PHASE5_ETAPA3_10_* design notes) were deleted in the same audit.
Consult git history if you need them.

The Phase 5 crates (`oracle/{core,feeds,host,relayer}`) still build
and run as a fallback while indexers transition. They will be deleted
in the commit that follows `evaluate_flip == Flip` on production
indexers.

> **New work** must use Phase 9 (see §Architecture above).

---

## Index maintenance

If you add a new `.md`, add a one-line entry under the matching
audience header above. Keep entries to a single line with a short
purpose clause after the em-dash. The goal is `Ctrl+F` navigability —
not comprehensive prose. Anything longer than one line belongs in the
file itself.
