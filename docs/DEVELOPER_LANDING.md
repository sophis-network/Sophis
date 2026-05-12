# Sophis Developer Landing — Content Source

**Status:** v1, drafted 2026-05-09. This document is the **source
content** that feeds the public developer landing site (target
location: `docs.sophis.org` or equivalent, modeled after
`hyperliquid.gitbook.io`). The actual hosted site is external
infrastructure; this file is what gets rendered.

Hosting / build / theming decisions for the public site are out of
scope of this content document. As long as a static-site generator
can consume the Markdown in `docs/` and link the canonical root-level
docs (`MONETARY_POLICY.md`, etc.), the site is content-complete.

---

# Welcome to Sophis

Sophis is a fair-launched, post-quantum L1 blockchain. Every
SPHS that exists comes from proof-of-work mining; there is no
pre-mine, no founder allocation, no developer fund, no foundation.
All transaction signatures are Dilithium (ML-DSA-44) from genesis;
no classical primitives like secp256k1 or Schnorr exist on the
user-facing path.

The chain extends GHOSTDAG with RandomX proof-of-work and a WASM
smart-contract VM. ZK-Rollup and ZK-Oracle layers are built into the
codebase but optional to use.

## Quick links by role

| If you are... | Start here |
|---|---|
| A user wanting to mine SPHS | `mainnet-mining/DAY-ZERO-GUIDE.md` and `bridge/docs/README.md` (stratum bridge) |
| A wallet developer | [Wallet developer track](#wallet-developer-track) below |
| A smart-contract developer | [Contract developer track](#contract-developer-track) below |
| An exchange / custodian integrator | [Exchange integrator track](#exchange-integrator-track) below |
| A relayer / oracle operator | [Oracle operator track](#oracle-operator-track) below |
| A node operator | [Node operator track](#node-operator-track) below |
| A regulator / journalist / auditor | [Verification track](#verification-track) below |

If you are not sure, read [The five-minute orientation](#the-five-minute-orientation).

---

# The five-minute orientation

**What it is.** A blockchain. UTXO model. 10 blocks per second. DAG
ordering. Proof-of-work mining (RandomX, the same algorithm Monero
uses). Fixed supply 210,000,000 SPHS. Smart contracts in WebAssembly.

**What is unusual.** All transaction signatures are post-quantum —
specifically Dilithium ML-DSA-44 (FIPS 204, "ML-DSA"). This is not
a future migration; the chain has no classical signature scheme.
Mainnet day one is post-quantum.

**What is missing on purpose.** There is no foundation. No issuer.
No legal entity attached to "Sophis". No native privacy primitives
(no FHE, no mixers, no shielded pool — L1 is transparent). No
official cross-chain bridge. No DeFi primitives in the core protocol.

**Why those choices.** See `MONETARY_POLICY.md` (the issuance
discipline) and `OPERATIONAL_BOUNDARIES.md` (what the project does
and doesn't do).

**What the project provides:** the protocol, the reference node,
miner, and SDK. **What the project does not provide:** any hosted
service users could route value through.

---

# The architecture in one diagram

```
┌──────────────────────────────────────────────────────────────┐
│  Phase 9 — PQC-native Oracle (Dilithium publishers, current) │
│  Phase 5 — ZK-Oracle (Pythnet→Plonky3, deprecated 2026-05-11)│
├──────────────────────────────────────────────────────────────┤
│  Phase 6 — Self-DA (V5 carrier UTXOs, SHA3-384 Merkle)       │
├──────────────────────────────────────────────────────────────┤
│  Phase 3 — ZK-Rollup L2 (Risc0, miner-rotation sequencer)    │
├──────────────────────────────────────────────────────────────┤
│                          sVM                                 │
│      (Wasmtime + 7-layer security + Capability set)          │
├──────────────────────────────────────────────────────────────┤
│   Native Tokens L1 + Dilithium signature scheme + UTXO       │
├──────────────────────────────────────────────────────────────┤
│        GHOSTDAG consensus + RandomX PoW + 10 BPS DAG         │
└──────────────────────────────────────────────────────────────┘
```

Detailed walkthrough: `docs/ECOSYSTEM_OVERVIEW.md`.

---

# Wallet developer track

You are building a wallet, key manager, or signing tool.

## What you need to know

- **Address format:** `sophis:` (mainnet), `sophistest:`, `sophisdev:`,
  `sophissim:` (test networks). Bech32-style. See `crypto/addresses/`.
- **Signature scheme:** Dilithium ML-DSA-44 (FIPS 204). Public keys
  ~1.3 KB; signatures ~2.5 KB. This affects mass / fees compared to
  classical chains.
- **HD derivation:** BIP-32 / BIP-39 / BIP-44 with Sophis-specific
  coin type. See `wallet/bip32/` and `wallet/keys/`.
- **L2 derivation:** same mnemonic, distinct path
  `m/44'/111111'/0'/1/0` (chain index 1) for the Phase 3 rollup. L1
  uses `…/0/0`.
- **PSKT (partially signed):** offline / multisig flows via
  `wallet/pskt/`. See examples in `wallet/pskt/examples/multisig.rs`.

## Where to start

1. Read `wallet/keys/README.md` for the key model
2. Read `wallet/bip32/README.md` for HD derivation
3. Read `wallet/README.md` for the high-level wallet API
4. Read `dilithium-wallet/` for a reference CLI implementation
5. Read `docs/MEMPOOL_POLICY.md` for RBF / fee bumping
6. Read `docs/FEE_PRIORITY.md` for the 3-tier fee API

## Common patterns

| Pattern | Reference |
|---|---|
| Generate new wallet from mnemonic | `dilithium-wallet/src/main.rs` (`generate` subcommand) |
| Restore from mnemonic | `dilithium-wallet/src/main.rs` (`restore` subcommand) |
| Build and sign a payment | `wallet/core/src/tx/generator/` |
| Build and sign with PSKT for multisig | `wallet/pskt/examples/multisig.rs` |
| Speed up a stuck transaction | RBF with `RbfPolicy::Mandatory` (see `docs/MEMPOOL_POLICY.md` §2) |

## Future work to track

- Account abstraction (Roadmap J1) — Dilithium-aware AA design lives
  in `wallet/aa-spec/`
- PSBS standardization (Roadmap K1) — formal partially-signed format
- Wallet descriptors (Roadmap K3) — Dilithium-aware descriptor syntax

---

# Contract developer track

You are writing smart contracts that run on the sVM.

## What you need to know

- Contracts are **WebAssembly modules**. Any WASM-targeting language
  works in principle, but the SDK and tooling target Rust first.
- Determinism is enforced. See `docs/SVM_EXECUTION_MODEL.md` §5.
- Capabilities are a **closed set**. See
  `docs/SVM_EXECUTION_MODEL.md` §2.
- Memory is bounded: declare `maximum` in the WASM memory section,
  ≤256 pages (16 MiB).
- Gas is metered in **mass** units. See `docs/FEE_PRIORITY.md` §1.

## Where to start

1. Read `docs/SVM_EXECUTION_MODEL.md` end-to-end
2. Skim `examples/contracts/token-minting-policy/`,
   `examples/contracts/transfer-policy/`,
   `examples/contracts/time-lock/`
3. Read `svm/sdk/` documentation for the contract author API
4. Run `cargo dylint` against your contract before deploy
   (`svm/lint/` is the dylint library)
5. For contracts that consume verifiable data: see
   `oracle/pqc-core/` (Phase 9 price feeds, current),
   `rollup/verifier/` (rollup state),
   `oracle/docs/PHASE6_DA_DESIGN.md` (data availability)

## Common pitfalls

- **Unbounded memory** — validation rejects WASM modules without a
  declared max
- **Non-deterministic floating-point** — avoid; use fixed-point
- **Reading wall-clock time** — there is no wall-clock capability;
  the closest is `Capability::ReadBlockHeight`
- **Random numbers** — none; use a contract-supplied seed and
  `Capability::HashSha3`, or wait for the planned VRF (Roadmap J3)

## Future work to track

- VRF nativo via RandomX (Roadmap J3, P1 pré-mainnet)
- Standardized event/log emission + filterable RPC (Roadmap J4)
- Poseidon pre-compile (Roadmap J6)
- Multicall pattern (Roadmap J7)
- IDL standardization (Roadmap L2)

---

# Exchange integrator track

You are integrating Sophis as a deposit/withdrawal asset.

## What you need to know

- **Confirmation depth:** Sophis finality is probabilistic. Use the
  multi-level commitment exposure (Roadmap L3 in progress, target
  `accepted` / `confirmed` / `finalized`). For now, depth-of-1000+
  blocks is conservative for high-value deposits.
- **Address format:** see Wallet track. Validate the prefix matches
  the network you are operating on.
- **RBF risk:** an `accepted` deposit can be replaced if it was
  submitted with `RbfPolicy::Allowed`. Wait for `confirmed` or
  `finalized` before crediting.
- **Reorg behavior:** the DAG can re-order blocks; reorgs of small
  depth are expected. Re-validate confirmation count every block.
- **Mass-based fees:** withdrawal cost depends on output count and
  signature scheme. Dilithium signatures dominate the mass budget.

## Where to start

1. Read `rpc/grpc/` and `rpc/wrpc/` for RPC reference
2. Read `docs/MEMPOOL_POLICY.md` §8 (exchange-specific guidance)
3. Read `docs/FEE_PRIORITY.md` for fee estimation
4. Stand up a node with `sophisd --utxoindex` and connect via gRPC
5. Test with the testnet faucet (`testnet-faucet/`) before any
   mainnet integration

## Operational notes

- The Sophis Project does **not** operate any custody, exchange,
  on-ramp, or off-ramp service (`OPERATIONAL_BOUNDARIES.md`).
  Exchange listings are independent of the project; due diligence
  is the listing venue's responsibility.
- For listing-related questions, the project will provide
  open-source documentation but cannot provide commercial agreements
  or escrow services.

---

# Oracle operator track

You are running an oracle price-feed publisher or building an oracle
consumer.

## Publisher operator (Phase 9 — PQC-native, current)

1. Read `oracle/docs/PHASE9_RUNBOOK.md` for the operational runbook
2. Read `SIPS/SIP-11-PQC-ORACLE.md` for the protocol spec
3. Build the publisher: `cargo build -p sophis-oracle-publisher --release`
4. Generate a Dilithium keypair: `sophis-oracle-publisher keygen`
5. Sign attestations and pipe into your wallet-side tx-construction
   tool (the publisher CLI is a signer, not a submitter)

## Oracle consumer (contract author)

1. Read `docs/PQC_NATIVE_ORACLE_DESIGN.md` for the consumer pattern
2. Use `oracle/pqc-core::evaluate_flip` to pick between Phase 5 fallback
   and Phase 9 medians during the bootstrap window
3. In your contract, decode the attestation from
   `utxo.script_public_key.script` and call `Capability::VerifyDilithium`
4. Read `oracle/docs/PHASE9_3_DUAL_PATH.md` for the dual-path dispatch
   pattern that indexers and consumers should mirror

> Phase 5 (Pyth + Plonky3 STARK + Dilithium relayer) was deprecated on
> 2026-05-11. The `oracle/{core,feeds,host,relayer}` crates still build
> while indexers fall back to Phase 5 medians, but new operators should
> run the Phase 9 publisher instead. The Phase 5 design / ABI / runbook
> documents were deleted in the same audit; consult git history if you
> need them.

## Phase 6 DA consumer

1. Read `oracle/docs/PHASE6_DA_DESIGN.md`
2. Use `Capability::VerifyDataAvailability` in your contract
3. For publishing: use the relayer with `da_publish` opt-in flag

---

# Node operator track

You are running a Sophis full node.

## Production setup

1. Read `sophisd/README.md`
2. Build with `--features svm-zk` for production (validates Phase 3
   ZK-Rollup batches; without it, the node ships stub verifiers
   that panic explicitly to prevent silent fork)
3. Sync from the genesis block; expect days for full sync depending
   on chain age
4. Configure RPC: gRPC default `46110`, wRPC JSON `48110`, Borsh
   `47110`, P2P `46111`
5. Run a DNS seeder if you want to help with peer discovery (the
   project does not host central seeders; the binary is
   `sophis-dnsseeder`)

## Hardware

| Resource | Minimum | Recommended |
|---|---|---|
| RAM | 4 GB (lite mode) | 16 GB (full + svm-zk) |
| CPU | 4 cores | 16 cores |
| Disk | 100 GB SSD | 1 TB NVMe |
| Network | 50 Mbps symmetric | 200 Mbps symmetric |

(Subject to revision based on mainnet observed load. See `I1`
dashboard for live network state once available.)

## Mining

If you also mine: see `mainnet-mining/DAY-ZERO-GUIDE.md`. Mining is
RandomX (CPU-first); ASICs do not exist as of mainnet launch (and
the project commits to act if they emerge — see `POW_POLICY.md`).

---

# Verification track

You are auditing, journaling on, or independently verifying claims
about the Sophis network.

## Founder mining cap (5%)

```
python scripts/cap_5pct_monitor.py --check-once
```

Outputs the founder address balance ratio against total emitted
supply. Reads from any Sophis full node via gRPC. The script is
open-source. The project commits in `FOUNDER_SELF_RESTRICTION.md`
that founder mining auto-pauses at 4.9%.

## Coinbase distribution

The protocol delivers 100% of every coinbase to the block's miner.
Verify by reading `consensus/src/processes/coinbase.rs` — there is
no split, no schedule, no compulsory recipient. The 2026-05-04 pivot
removed the previously-planned devfund (commit `cffe1d1`).

## No issuer

There is no entity selling or distributing SPHS. Mining is the only
issuance path. See `MONETARY_POLICY.md` §3.

## Operational scope

`OPERATIONAL_BOUNDARIES.md` lists what the project does and does not
operate. The list is short and excludes mining pools, exchanges,
custody, bridges, and any infrastructure that handles user funds.

## Pre-mainnet integrity

Three documents are SHA-256-hashed and the hashes published 72 hours
before mainnet launch:

- `MONETARY_POLICY.md`
- `FOUNDER_SELF_RESTRICTION.md`
- `OPERATIONAL_BOUNDARIES.md`

After launch, verify the on-chain content against the pre-published
hashes. Any divergence is a public breach of stated commitment.

---

# Reference index

## Canonical commitments (root of repo)

- [`MONETARY_POLICY.md`](../MONETARY_POLICY.md) — issuance discipline
- [`FOUNDER_SELF_RESTRICTION.md`](../FOUNDER_SELF_RESTRICTION.md) — founder mining cap and rules
- [`OPERATIONAL_BOUNDARIES.md`](../OPERATIONAL_BOUNDARIES.md) — what the project does and does not operate
- [`POW_POLICY.md`](../POW_POLICY.md) — proof-of-work and anti-ASIC commitment
- [`HARD_FORK_POLICY.md`](../HARD_FORK_POLICY.md) — hard fork cadence and emergency procedure
- [`SUCCESSION.md`](../SUCCESSION.md) — keys, domains, trademark continuity plan
- [`MAINTAINERS.md`](../MAINTAINERS.md) — current maintainers and GPG fingerprints
- [`LAUNCH_CHECKLIST.md`](../LAUNCH_CHECKLIST.md) — pre-mainnet checklist
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) — DCO, code review, PR process

## Process

- [`SIPS/SIP-0-process.md`](../SIPS/SIP-0-process.md) — improvement proposal process
- [`SIPS/SIP-template.md`](../SIPS/SIP-template.md) — template for new SIPs

## Operational reference

- [`docs/ECOSYSTEM_OVERVIEW.md`](ECOSYSTEM_OVERVIEW.md) — modular layer map
- [`docs/MEMPOOL_POLICY.md`](MEMPOOL_POLICY.md) — RBF, admission rules, exchange guidance
- [`docs/FEE_PRIORITY.md`](FEE_PRIORITY.md) — 3-tier feerate API
- [`docs/SVM_EXECUTION_MODEL.md`](SVM_EXECUTION_MODEL.md) — sVM determinism, capability set, gas
- [`docs/WALLET_VERIFICATION.md`](WALLET_VERIFICATION.md) — `.well-known/sophis-wallet.json` spec
- [`docs/PRE_MAINNET_AUDIT.md`](PRE_MAINNET_AUDIT.md) — pre-quantum residuals, dead Kaspa code

## Phase-specific reference

- `oracle/docs/PHASE9_RUNBOOK.md` — Phase 9 publisher / indexer / consumer ops
- `oracle/docs/PHASE9_3_DUAL_PATH.md` — Phase 5 ↔ Phase 9 dispatch pattern
- `SIPS/SIP-11-PQC-ORACLE.md` — Phase 9 protocol spec
- `docs/PQC_NATIVE_ORACLE_DESIGN.md` — Phase 9 design doc
- `oracle/docs/PHASE6_DA_DESIGN.md` — Phase 6 self-DA design
- `oracle/docs/PHASE6_RUNBOOK.md` — Phase 6 operational runbook
- `oracle/docs/PHASE6_AUDIT.md` — Phase 6 threat matrix
- `oracle/docs/PHASE6_RFC.md` — Phase 6 RFC for community review

## Crate-level READMEs

- `sophisd/README.md`, `wallet/README.md`, `wallet/bip32/README.md`,
  `wasm/README.md`, `bridge/docs/README.md`

## Historical / transition

- [`docs/crescendo-guide.md`](crescendo-guide.md)
- [`docs/testnet10-transition.md`](testnet10-transition.md)
- [`docs/archival.md`](archival.md)
- [`docs/deferred-decisions.md`](deferred-decisions.md)
- [`docs/override-params.md`](override-params.md)

## External

- Public repo: `sophis-network/Sophis` on GitHub
- Algorithm reference: `tevador/RandomX` upstream
- Standards: FIPS 204 (ML-DSA), RFC 8615 (`.well-known`),
  RFC 8785 (JCS)
