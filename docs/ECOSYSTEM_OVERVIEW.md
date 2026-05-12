# Sophis Ecosystem Overview

**Status:** v1, drafted 2026-05-09. Living document — keep aligned
with the workspace structure and phase status as the project evolves.

This document is the **navigation entry point** for builders and
operators trying to figure out which part of Sophis to read or use
for a given purpose. It is not a tutorial; it is a map.

---

## 1. Layer summary

```
┌──────────────────────────────────────────────────────────────┐
│  Phase 9 — PQC-native Oracle (Dilithium publishers, current) │
│  Phase 5 — ZK-Oracle (Pythnet→Plonky3, deprecated 2026-05-11)│
├──────────────────────────────────────────────────────────────┤
│  Phase 6 — Self-DA (V5 carrier UTXOs, SHA3-384 Merkle)       │
├──────────────────────────────────────────────────────────────┤
│  Phase 3 — ZK-Rollup L2 (Risc0 + STARKs, miner-rotation seq) │
├──────────────────────────────────────────────────────────────┤
│                          sVM                                 │
│      (Wasmtime + 7-layer security + Capability set)          │
├──────────────────────────────────────────────────────────────┤
│   Native Tokens L1 + Dilithium signature scheme + UTXO       │
├──────────────────────────────────────────────────────────────┤
│        GHOSTDAG consensus + RandomX PoW + 10 BPS DAG         │
└──────────────────────────────────────────────────────────────┘
```

Every layer is independent in the sense that you can build on one
without understanding the layer below it in detail. This document
points you to the right one.

## 2. "I want to do X" — index

### 2.1 Run a node

| Goal | Read |
|---|---|
| Run a full node | `sophisd/README.md` (or `bridge/docs/README.md` for in-process miner setup) |
| Run a CPU miner | `miner/README.md` (if present), `mainnet-mining/DAY-ZERO-GUIDE.md` for first-launch users |
| Mine via stratum | `bridge/docs/README.md` — local-only stratum bridge for ASIC/external miner support |
| Run a DNS seeder | `sophis-dnsseeder/` crate (operator-curated; the project does not host these) |
| Run a faucet | `testnet-faucet/` crate (testnet only) |
| Run a block explorer | `sophis-explorer/` crate |

### 2.2 Build a wallet

| Goal | Read |
|---|---|
| Generate Dilithium keys | `wallet/keys/`, `dilithium-wallet/` (CLI reference) |
| HD wallet (BIP-32) | `wallet/bip32/`, `wallet/core/src/derivation.rs` |
| Sign and submit transactions | `wallet/core/src/tx/`, `wallet/wasm/` (browser-compatible) |
| Partially-signed transactions (PSBS-equivalent) | `wallet/pskt/` — pre-existing PSKT format; PSBS standardization work is tracked as Roadmap K1 (deferred) |
| Multisig | `wallet/pskt/examples/multisig.rs` |
| Account abstraction (Dilithium-aware AA) | `wallet/aa-spec/` — design docs (`SPEC.md`, `CONVERGENCE.md`, `ANTI_PATTERNS.md`); production AA is post-mainnet (Roadmap J1) |

### 2.3 Build a smart contract

| Goal | Read |
|---|---|
| Write a Sophis contract | `svm/sdk/`, `svm/sdk-macros/`, `examples/contracts/` (token-minting-policy, transfer-policy, time-lock) |
| Understand the WASM execution model | `svm/runtime/`, `svm/host/`, `docs/SVM_EXECUTION_MODEL.md` |
| Use the host capability set | `svm/host/src/lib.rs` — capabilities: `ReadUtxo`, `ProduceOutput`, `VerifyDilithium`, `ReadBlockHeight`, `HashSha3`, `VerifyRisc0Proof`, `VerifyPlonky3Proof`, `VerifyDataAvailability` |
| Lint a contract before deploy | `svm/lint/` (cargo dylint integration) |
| Verify formal properties | `svm/kani-proofs/` |
| Sample contracts | `examples/contracts/{token-minting-policy,transfer-policy,time-lock}/` |

### 2.4 Use the ZK-Rollup (Phase 3)

| Goal | Read |
|---|---|
| Submit txs to the rollup | `rollup/sequencer/` API, `rollup/node/` for the rollup-node binary |
| Verify rollup state on L1 | `rollup/verifier/` — Risc0 proof verification consumed by the sVM `Capability::VerifyRisc0Proof` |
| Deposit / withdraw between L1 and L2 | `rollup/bridge/deposit/`, `rollup/bridge/withdrawal/` (internal bridge contracts; not cross-chain) |
| Understand the prover | `rollup/host/` (host) and `rollup/host/guest/` (guest, separate workspace compiled by `risc0-build`) |

### 2.5 Use the Oracle (Phase 9 — PQC-native, current)

| Goal | Read |
|---|---|
| Subscribe to a price feed | `oracle/pqc-core/src/source.rs` — `evaluate_flip` + `FeedSource` dual-path dispatch |
| Run a publisher | `oracle/pqc-publisher/` CLI; sign attestations with Dilithium directly |
| Verify an attestation on-chain | `oracle/pqc-contract/` reads `utxo.script_public_key.script`, calls `Capability::VerifyDilithium` |
| Design doc | `docs/PQC_NATIVE_ORACLE_DESIGN.md`, `SIPS/SIP-11-PQC-ORACLE.md` |
| Operator runbook | `oracle/docs/PHASE9_RUNBOOK.md` |
| Dual-path Phase 5 ↔ Phase 9 dispatch | `oracle/docs/PHASE9_3_DUAL_PATH.md` |

> Phase 5 (Pyth + Plonky3 STARK + ed25519 trust chain) was deprecated on
> 2026-05-11 and is scheduled for deletion after Phase 9 publisher quorum
> bootstrap. The `oracle/{core,feeds,host,relayer}` crates still build and
> run as a fallback until indexers flip per SIP-11 D11; the corresponding
> design / ABI / runbook documents under `oracle/docs/` were removed in
> the same audit, since no production deployment depends on them.

### 2.6 Use Data Availability (Phase 6)

| Goal | Read |
|---|---|
| Publish a DA bundle | `oracle/docs/PHASE6_DA_DESIGN.md` for the V5 carrier format; relayer with `da_publish` opt-in |
| Read a published DA carrier | `consensus/core/src/da/codec.rs` for the codec; RPC methods `get_da_*` |
| Verify DA inclusion in a contract | sVM `Capability::VerifyDataAvailability` + `sophis_verify_da` host fn |
| Stress-test a DA path | `oracle/docs/PHASE6_STRESS_PLAN.md`, `tools/sophis-da-stress/` |
| Operate / runbook | `oracle/docs/PHASE6_RUNBOOK.md` |
| Audit / threat model | `oracle/docs/PHASE6_AUDIT.md`, `oracle/docs/PHASE6_RFC.md` |

### 2.7 Operate, monitor, integrate

| Goal | Read |
|---|---|
| RPC reference | `rpc/core/`, `rpc/grpc/`, `rpc/wrpc/` — gRPC and wRPC (JSON over WebSocket) clients available |
| Indexer / UTXO index | `indexes/utxoindex/` |
| Metrics + perf monitoring | `metrics/core/`, `metrics/perf_monitor/` |
| Mempool + RBF | `mining/src/mempool/`, `docs/MEMPOOL_POLICY.md` |
| Fee estimation + priority | `mining/src/feerate/`, `docs/FEE_PRIORITY.md` |
| Block explorer | `sophis-explorer/` |
| Dashboard (Hyperliquid-style network status) | `tools/sophis-dashboard/` (in development per Roadmap I1) |

## 3. Layer guarantees and boundaries

Each layer is structured so that **it remains useful when subsequent
layers do not exist**. Reading bottom-up:

### 3.1 Consensus layer (mandatory)

`consensus/`, `consensus/core/`, `consensus/pow/`. GHOSTDAG ordering,
RandomX proof-of-work, block templating, header chain. Required for
any node. No transactions, no smart contracts — just block ordering.

### 3.2 Native asset layer (mandatory)

`crypto/txscript/`, `crypto/addresses/`, `consensus/core/src/tx/`. UTXO
model, Dilithium signature verification, native tokens issued and
held at L1. SPHS itself lives here. Sufficient for a Bitcoin-style
chain without smart contracts.

### 3.3 sVM layer (optional, but consensus-relevant)

`svm/`. WASM-based smart contracts with Wasmtime runtime and a closed
capability set. Contracts can be deployed and called via dedicated
opcodes, but the chain is fully usable without ever invoking them
(Native Tokens L1 covers a lot of ground on its own).

The sVM layer hosts host functions that **other** Sophis layers
piggyback on:

- `Capability::VerifyRisc0Proof` is consumed by Phase 3 ZK-Rollup
- `Capability::VerifyPlonky3Proof` is consumed by Phase 5 oracle
- `Capability::VerifyDataAvailability` is consumed by Phase 6 DA

A node that does **not** opt into sVM features (`--features svm-zk`)
ships with stub verifiers that panic explicitly — they cannot fork
silently. Production nodes MUST run with `--features svm-zk` to
validate Phase 3+ blocks.

### 3.4 Phase 3 — ZK-Rollup L2 (optional layer)

`rollup/`. State-machine running off-chain with periodic L1 commit via
Risc0 proofs. Sequencer rotates per-epoch (every 100 blocks); current
miner of block N×100 becomes the sequencer. No external sequencer, no
admin, no upgrade key.

Use it when you need higher TPS than L1 can offer for an
application-specific subdomain. Bridges in/out are internal-only
contracts (`rollup/bridge/`); cross-chain is out of scope.

### 3.5 Phase 9 — PQC-native Oracle (optional layer, current)

`oracle/pqc-{core,contract,publisher,tests}`. Each publisher fetches its
own data source and signs attestations directly with Dilithium ML-DSA-44.
The on-chain contract reads the attestation from a UTXO's
`script_public_key.script` and verifies via `Capability::VerifyDilithium`.
Indexers aggregate published medians and emit J4 events; consumers read
those events and apply `evaluate_flip` policy.

Use it when you need external price data verifiable on-chain with a
PQC-only trust chain.

### 3.5.1 Phase 5 — ZK-Oracle Aggregator (deprecated 2026-05-11)

`oracle/{core,feeds,host,relayer}`. The original ZK-Oracle path: a
relayer pulls signed price updates from Pythnet, generates Plonky3
STARK proofs over the ed25519 verification + aggregation logic, and
submits them to a Sophis contract. Still builds and runs as a fallback
during the Phase 9 publisher quorum bootstrap window. Scheduled for
deletion per SIP-11 D11 once `evaluate_flip` returns `Flip` on
production indexers. Do not start new integrations against Phase 5.

### 3.6 Phase 6 — Self-DA (optional layer)

V5 carrier UTXO format (consensus-validated payload format) +
SHA3-384 Merkle commitments + RPC/sVM access paths. Lets contracts
or rollups commit large data to L1 without bridging to an external DA
layer.

Use it when your protocol needs verifiable data availability and you
want to stay inside Sophis trust boundaries.

## 4. What the project explicitly does NOT ship

- **Cross-chain bridges (out of scope, decision 2026-05-04 #4).** The
  project does not operate, host, or recommend any bridge to
  Bitcoin, Ethereum, or any other chain. Third parties may build
  bridges; the project will not curate them.
- **Native privacy primitives (out of scope, decision 2026-05-04 #5).**
  No FHE, no ring signatures, no shielded pool, no confidential
  transactions, no mixers. L1 is transparent by deliberate design.
- **DeFi primitives (Phase 7 excluded).** No DEX contracts, no
  lending protocol, no stablecoin in core. SDK + docs are provided;
  the ecosystem builds the protocols.
- **Hosted services.** No core-team-operated mining pool, exchange,
  custody, faucet beyond a rate-limited testnet helper, or named
  bridge.

See `OPERATIONAL_BOUNDARIES.md` for the full statement.

## 5. Phase status snapshot

| Phase | Status | Where |
|---|---|---|
| Phase 1 — DAG consensus + Dilithium E2E | ✅ Complete | `consensus/`, `crypto/`, `mining/` |
| Phase 2 — sVM + native tokens | ✅ Complete | `svm/`, `examples/contracts/` |
| Phase 3 — ZK-Rollup internal | ✅ Complete | `rollup/` |
| Phase 4 — Cross-chain ZK-Bridge | ❌ **Excluded** — ecosystem builds | (n/a) |
| Phase 5 — ZK-Oracle Aggregator | ⚠️ **Deprecated 2026-05-11** (fallback only; superseded by Phase 9) | `oracle/{core,feeds,host,relayer}` |
| Phase 9 — PQC-native Oracle | ✅ Complete (production path) | `oracle/pqc-{core,contract,publisher,tests}` |
| Phase 6 — Self-DA | ✅ Complete | `consensus/core/src/da/`, `oracle/docs/PHASE6_*.md` |
| Phase 7 — DeFi infrastructure | ❌ **Excluded** — ecosystem builds | (n/a) |
| Phase 8 — FHE / privacy | ❌ **Removed** 2026-05-04 (out of scope) | (n/a) |

For phase-by-phase commit history and design notes, see `CLAUDE.md`.

## 6. Reference documents

- **Policy / commitments:** `MONETARY_POLICY.md`,
  `OPERATIONAL_BOUNDARIES.md`, `FOUNDER_SELF_RESTRICTION.md`,
  `POW_POLICY.md`, `HARD_FORK_POLICY.md`, `SUCCESSION.md`
- **Process:** `CONTRIBUTING.md`, `MAINTAINERS.md`,
  `LAUNCH_CHECKLIST.md`, `SIPS/SIP-0-process.md`
- **Oracle (current):** `oracle/docs/PHASE9_RUNBOOK.md`,
  `oracle/docs/PHASE9_3_DUAL_PATH.md`, `docs/PQC_NATIVE_ORACLE_DESIGN.md`
- **Data availability:** `oracle/docs/PHASE6_DA_DESIGN.md`,
  `oracle/docs/PHASE6_RUNBOOK.md`, `oracle/docs/PHASE6_AUDIT.md`,
  `oracle/docs/PHASE6_RFC.md`, `oracle/docs/PHASE6_BUG_BOUNTY.md`,
  `oracle/docs/PHASE6_STRESS_PLAN.md`
- **Operational:** `docs/MEMPOOL_POLICY.md`, `docs/FEE_PRIORITY.md`,
  `docs/SVM_EXECUTION_MODEL.md`, `docs/WALLET_VERIFICATION.md`,
  `docs/archival.md`, `docs/override-params.md`
- **Audit:** `docs/PRE_MAINNET_AUDIT.md`,
  `docs/deferred-decisions.md`
