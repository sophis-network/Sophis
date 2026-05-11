# Sophis sVM Execution Model

**Status:** v1, drafted 2026-05-09. Reference document for contract
authors, integrators, and performance-sensitive operators. Describes
how the sVM executes transactions today, what guarantees apply, and
what is parallelizable in principle vs. in the current
implementation.

This is a **descriptive** document of Sophis 1.1. The execution model
may evolve via SIP post-mainnet (`HARD_FORK_POLICY.md`).

---

## 1. Architecture

The sVM runs WebAssembly contracts inside Wasmtime, with a closed
**capability set** mediating access to chain state. The crates are
organized as:

| Crate | Role |
|---|---|
| `svm/core` | Capability and WASM-related core types, B3 dispatch by UTXO type |
| `svm/runtime` | Execution loop; gas accounting; host function dispatch |
| `svm/host` | Native host functions backing each capability |
| `svm/sdk` | Contract-author-facing Rust SDK |
| `svm/sdk-macros` | Procedural macros for contract entry points |
| `svm/lint` | `cargo dylint` library — pre-deploy contract lints |
| `svm/kani-proofs` | Formal harnesses for safety-critical invariants |

Contracts are deployed as compiled WASM modules with deterministic
instantiation. Determinism is enforced at validate time
(`svm/runtime/src/host.rs`) — non-deterministic WASM features (NaN
canonicalization, threading, SIMD where non-deterministic) are
forbidden.

## 2. Capability set

The sVM permits contracts to interact with chain state only through
the capabilities below. A contract that imports a host function not
backed by a granted capability fails validation at deploy time.

| Capability | Purpose |
|---|---|
| `ReadUtxo` | Read a UTXO by outpoint |
| `ProduceOutput` | Construct a new output as part of the current transaction |
| `VerifyDilithium` | Verify a Dilithium ML-DSA-44 signature |
| `ReadBlockHeight` | Read the current block height |
| `HashSha3` | Compute a SHA3-384 hash |
| `VerifyRisc0Proof` | Verify a Risc0 STARK proof (consumed by Phase 3 ZK-Rollup) |
| `VerifyPlonky3Proof` | Verify a Plonky3 STARK proof (consumed by Phase 5 oracle) |
| `VerifyDataAvailability` | Verify a Phase 6 DA carrier inclusion + commitment |

**No** capability for: privacy primitives (FHE, mixers, ring
signatures); cross-chain bridge proofs (extracted to standalone
repo); pre-quantum signatures (Schnorr, secp256k1, ed25519 outside
the oracle context). Adding a capability is a SIP; removal is a hard
fork.

## 3. Execution model — sequential per-transaction

**As of Sophis 1.1, sVM contract execution is sequential within a
block.** Specifically:

- Each transaction in a block that invokes a contract is executed in
  block order
- Contracts within a single transaction execute sequentially through
  the script tree
- The runtime does not currently parallelize execution of independent
  transactions inside a block

A grep of the workspace as of 2026-05-09 confirms zero use of
`rayon::par_iter` / `par_chunks` or other parallelism primitives in
`svm/`. The execution loop is single-threaded.

### 3.1 Why this is acceptable today

- Block target throughput is 10 BPS with relatively small block
  mass; sequential execution does not currently bottleneck block
  validation in healthy state
- The UTXO model gives a clean correctness story — sequential
  execution matches the natural state-transition order
- Determinism is straightforward: every node executes in the same
  order with no scheduling variance

### 3.2 Why parallelization is theoretically available

UTXO is naturally parallelizable: two transactions that share no
inputs and no outputs can execute concurrently without conflict. This
is a structural property of the UTXO model that account-model chains
(like Solana) have to recover via mechanisms like Sealevel's
read/write set declarations.

Sophis can, in principle, partition a block's transactions into
independent groups by UTXO read/write sets and execute the groups
in parallel. The cost is implementation complexity (conflict
detection, scheduling, error propagation) for a benefit that is only
apparent under sustained heavy block load.

### 3.3 When parallelization may become useful

Triggers that would justify a parallel-execution SIP post-mainnet:

- Sustained block fullness >70% for weeks
- Single-thread execution latency consuming >50% of block time at p95
- Adversarial spam patterns specifically targeting serial-execution
  bottlenecks
- A clear measurement showing parallelization would yield ≥3×
  throughput on real workload (not synthetic)

Until then, the simpler sequential model is preferred. Slow change
is a feature (`HARD_FORK_POLICY.md` §1).

## 4. Gas / mass accounting

The sVM uses **gas counted in mass units** to bound resource
consumption per contract call, paired with the EIP-1559-style
fee/mass market documented in `docs/FEE_PRIORITY.md`.

| Concept | Sophis mapping |
|---|---|
| Gas limit | Per-tx mass cap; consensus-validated |
| Base fee | Network-set floor; fee/mass in sompi/gram |
| Priority fee | Submitter's bid on top of base; selector orders by total fee/mass |
| Refund on revert | None — gas spent up to the revert point is paid; no post-execution refunds |

Host functions have **fixed gas costs** assigned at the capability
level. Cryptographic verifications (`VerifyDilithium`,
`VerifyRisc0Proof`, `VerifyPlonky3Proof`) carry the largest costs;
`ReadBlockHeight` and `HashSha3` are cheap.

## 5. Determinism guarantees

A contract's execution result is purely a function of:

1. The transaction's inputs (referenced UTXOs)
2. The contract's WASM code
3. Block-level state visible via `ReadBlockHeight`
4. Capability-mediated reads

There is **no** access to:
- Wall-clock time
- Random number generation (use `Capability::HashSha3` with
  contract-supplied entropy if you need a hash, or use the VRF
  feature gated by Roadmap J3)
- File system, network, or any external IO
- Other transactions' execution state within the same block

Two nodes executing the same block produce bit-identical sVM state
transitions. A divergence indicates a node bug.

## 6. Multi-block dependencies

A contract executing in block N can read state committed up to and
including block N-1. State produced in block N is not readable by
other contracts in the same block — this preserves the parallelization
property of §3.2 even though §3.1 doesn't currently exploit it.

## 7. Stability vs. extension paths

What is **stable** in 1.1 (will not change without a major SIP):

- Capability set (each capability + its gas cost)
- Sequential execution semantics (a future parallel scheduler must
  produce identical results to the sequential one)
- Gas-as-mass accounting unit
- Determinism rules in §5

What is **extensible** (SIP-friendly future work):

- Adding a new capability (additive; contracts that don't use it are
  unaffected)
- Optimizing the execution loop (parallelization, caching) without
  changing semantics
- Adding pre-compiles for hot primitives (Roadmap J6: Poseidon)

## 8. Common patterns

| Pattern | Approach |
|---|---|
| Single-author signed action | Contract verifies a Dilithium signature against a known public key embedded in UTXO data |
| Multisig (k-of-n) | Contract verifies k Dilithium signatures from a list of n public keys; PSKT (`wallet/pskt/`) supports the offline signing flow |
| Time-locked output | Contract reads `Capability::ReadBlockHeight` and refuses spending before threshold |
| Token issuance | See `examples/contracts/token-minting-policy/` |
| Access-controlled transfer | See `examples/contracts/transfer-policy/` |
| Verifiable rollup state | Contract calls `Capability::VerifyRisc0Proof` against the Phase 3 sequencer's batch journal |
| Verifiable oracle price (Phase 9, current) | Contract reads a Dilithium-signed attestation from `utxo.script_public_key.script` and calls `Capability::VerifyDilithium`; consumer SDK in `oracle/pqc-core/` |
| Verifiable oracle price (Phase 5, deprecated 2026-05-11) | Contract calls `Capability::VerifyPlonky3Proof` with the appropriate `air_id`; fallback path while Phase 9 publishers bootstrap |

## 9. Common pitfalls

- **Memory growth**: WASM modules MUST declare `maximum` in the
  memory section. The validator rejects unbounded memory or memory
  >256 pages (16 MiB).
- **Upgrade policy**: `MultisigTimelock` upgrade policy requires
  `threshold > 0`, `threshold ≤ keys.len()`, `keys.len() ≤ 16`.
- **Gas overflows**: per-call gas is capped; don't write loops
  expecting infinite headroom. Use `cargo dylint` (svm/lint) for
  static analysis pre-deploy.

## 10. Reference

- Code: `svm/core/`, `svm/runtime/`, `svm/host/`, `svm/sdk/`,
  `svm/sdk-macros/`
- Examples: `examples/contracts/{token-minting-policy,transfer-policy,time-lock}/`
- Lints: `svm/lint/`
- Formal proofs: `svm/kani-proofs/`
- Companion: `docs/MEMPOOL_POLICY.md`, `docs/FEE_PRIORITY.md`,
  `docs/ECOSYSTEM_OVERVIEW.md`
- Security review (2026-04-29): see `project_svm_wasm.md` (memory)
- Decision rationale: `DECISOES_2026-05-04.md`
