# Sophis ($SPHS)

## A Fair-Launch, Post-Quantum Layer-1 BlockDAG

**Version 2.0 — 2026-05-05**
**Author:** Hiroshi Tatakawa
**Status:** Pre-mainnet (whitepaper supersedes Whitepaper.pdf v1.0)

---

> *"First fair-launch L1 native in post-quantum cryptography, modeled after Bitcoin's monetary discipline."*

---

## Abstract

Sophis is a Proof-of-Work BlockDAG built on the GHOSTDAG protocol, designed from genesis around three principles that have rarely coexisted in a single Layer-1: (1) **post-quantum cryptography** via CRYSTALS-Dilithium ML-DSA-44 (NIST FIPS 204) as the **only** signature scheme — there is no secp256k1, Schnorr or ECDSA fallback; (2) a **pure fair launch** with no pre-mine, no ICO, no venture allocation, no foundation grant, and **no on-chain developer fund** of any kind; (3) **CPU-friendly memory-hard PoW** via RandomX, the same algorithm Monero uses, deliberately chosen to resist ASIC and large-FPGA centralization.

The protocol extends the GHOSTDAG ordering algorithm to a 10-blocks-per-second BlockDAG, with a hard supply cap of 210,000,000 SPHS and a Bitcoin-style halving emission curve. On top of consensus, Sophis ships a sandboxed WASM virtual machine (sVM) for smart contracts, native L1 token primitives with linear-typed `Resource<T>` accounting, and a Risc0-based ZK-Rollup providing optional L2 throughput while preserving the L1's transparent, single-asset character.

The protocol does **not** include native privacy (no FHE, no ring signatures, no shielded pools, no `OP_PRIVACY`) and does **not** ship an official cross-chain bridge. These boundaries are deliberate, regulatory-aware, and binding on the core team — they are documented in `DECISOES_2026-05-04.md` and reflected in the codebase invariants. Sophis is therefore a transparent, isolated L1 in the Bitcoin / Monero Project mold, rather than a privacy chain or a multi-chain hub.

This whitepaper supersedes v1.0 (2026-04-XX). Sections describing FHE, OP_PRIVACY, cross-chain ZK-Bridge, Wrapped SPHS (WSPHS) and on-chain devfund have been removed; they are no longer part of the Sophis core scope.

---

## 1. Introduction

### 1.1 What Sophis is — and is not

Sophis is **not**:

- Not a fork of Kaspa. Sophis builds on the GHOSTDAG protocol foundation but ships a different cryptographic stack (PQC from genesis), different supply (210M cap), different ports (46xxx), and different invariants (no devfund, no Schnorr, no kHeavyHash).
- Not a privacy coin. Validators see all amounts and addresses. There is no FHE, no ring signatures, no zk-shielded pool. This is a deliberate scope boundary, not a roadmap gap.
- Not a multi-chain or "ecosystem hub". There is no official cross-chain bridge, no Wrapped SPHS on Ethereum, no IBC, no relayer model. Interoperability with other chains is **out-of-scope** for the core team.
- Not a foundation-led project. There is no Sophis Foundation, no LLC, no CNPJ vinculado, no DAO treasury. The project follows the Bitcoin Core / Monero Project model: code + protocol + community.
- Not a yield-bearing asset by design. There is no staking, no on-chain inflation reward beyond PoW, no validator fee-share, no liquid restaking primitive baked into consensus.

Sophis **is**:

- A Layer-1 BlockDAG with 10 blocks per second under GHOSTDAG ordering.
- Post-quantum from genesis. Every transaction is signed with Dilithium ML-DSA-44; every script verifies with `OpCheckSigDilithium` (opcode `0xc4`). There is no key type to migrate from.
- ASIC-resistant via RandomX, the CPU-first memory-hard algorithm originally designed by the Monero community.
- Fair launch in the strictest sense: no pre-mine, no genesis allocation, no founder allocation, no insider tokens. The genesis block produces zero coins. All 210M SPHS are mined in real time by the public, starting at block 1.
- Smart-contract-capable via the sVM, a sandboxed WASM runtime executing within consensus, with explicit capability gating and a linear-typed token resource model.
- L2-capable via a Risc0 ZK-Rollup that anchors STARK proofs on L1 without altering L1 economics or trust assumptions.

### 1.2 Why this combination is rare

Among existing chains:

- **Bitcoin** is fair-launched and conservative, but its cryptography (ECDSA / Schnorr) is breakable by a sufficiently large quantum computer running Shor's algorithm.
- **QRL** and **IOTA** ship post-quantum signatures, but neither is a pure fair launch in the Bitcoin sense — both involved early allocations.
- **Monero** combines fair launch with strong privacy and ASIC resistance (RandomX), but its cryptography is also pre-quantum and its privacy model now classifies it as an Anonymity-Enhancing Cryptocurrency (AEC) under MiCA Article 76, leading to widespread CEX delistings.

Sophis occupies the empty intersection: **fair launch + post-quantum signatures + transparent L1**. None of the three properties is novel in isolation; their combination in a single chain, at genesis, with no migration debt, is.

### 1.3 What problem this solves

The motivating threat is not abstract. NIST published FIPS 204 (ML-DSA / Dilithium) as a federal standard in August 2024. The "harvest-now-decrypt-later" attack model already applies to long-lived signatures: an adversary can store today's transactions and forge them retroactively the day a cryptanalytically relevant quantum computer (CRQC) becomes available. For a chain whose UTXOs may sit for decades, retrofitting PQC after the fact requires a hard fork plus key migration; users who never migrate are permanently exposed.

Sophis side-steps that migration debt by being PQC from block 0. There is no legacy curve to deprecate, no soft-fork window, no dual-signature transition period.

---

## 2. System overview

| Property | Value |
|---|---|
| Consensus | GHOSTDAG (k = 124) over BlockDAG |
| Block rate | 10 blocks / second (BPS) |
| PoW algorithm | RandomX (memory-hard, CPU-first, anti-ASIC) |
| Signature scheme | CRYSTALS-Dilithium ML-DSA-44 (NIST FIPS 204) |
| Signature opcode | `OpCheckSigDilithium` = `0xc4` |
| Ticker | SPHS |
| Hard supply cap | 210,000,000 SPHS |
| Smallest unit | 1 sompi = 10⁻⁸ SPHS (i.e. 1 SPHS = 100,000,000 sompi) |
| Address prefixes | `sophis:` (mainnet) · `sophistest:` (testnet) · `sophisdev:` (devnet) · `sophissim:` (simnet) |
| Coinbase distribution | 100 % to miner — **no devfund**, no split, no protocol-level recipient |
| Coinbase maturity | 100 blocks (mainnet) / 20 blocks (devnet) |
| L1 ports (mainnet) | P2P 46111 · gRPC 46110 · Borsh RPC 47110 · JSON RPC 48110 |
| L2 throughput | ZK-Rollup (Risc0 STARK) anchored on L1 |
| Native VM | sVM (Wasmtime, fuel-metered, capability-gated) |
| Native tokens | First-class L1 primitive, linear-typed `Resource<T>` model |
| Cross-chain bridge | Out-of-scope (no official bridge, no WSPHS) |
| Native privacy | Out-of-scope (no FHE, no ring sigs, no shielded pools) |

---

## 3. Cryptography

### 3.1 Why Dilithium, and only Dilithium

Sophis ships exactly one signature scheme: **CRYSTALS-Dilithium ML-DSA-44**, as standardized in NIST FIPS 204 (August 2024). The implementation is `libcrux-ml-dsa`, a constant-time Rust library audited as part of the broader libcrux suite.

| Parameter | Value |
|---|---|
| Public key | 1,312 bytes |
| Signing key | 2,560 bytes |
| Signature | 2,420 bytes |
| Security category | NIST Level 2 (≈ AES-128 classical, MLWE-hard quantum) |

There is **no secp256k1, Schnorr, or ECDSA fallback** anywhere in the codebase. This includes the script engine, the SDK, the sVM host functions, the wallet, and the rollup. The capability enum exposed by sVM contracts contains `VerifyDilithium` and explicitly does not — and will not — contain `VerifySchnorr`.

This monolithic stance is a deliberate trade-off. Sophis accepts:
- Larger transactions (~2.5 kB per signature) and consequently a larger `max_block_mass` than a curve-based chain would need;
- Reduced library maturity vs. secp256k1, which has had a decade of public scrutiny;

in exchange for:
- No quantum-vulnerable transactions ever entering the chain history;
- No migration cliff, no key-rotation soft-fork, no dual-mode wallet UX;
- No "bridge" between curve-based and lattice-based UTXOs that would itself become an attack surface.

### 3.2 Address format

Sophis uses Bech32 addresses, with two active versions on the script side:

- `Version::PubKeyDilithium = 2` — the input-side encoding of a 32-byte Blake2b hash of the Dilithium public key.
- `Version::ScriptHash = 8` — the on-script representation. Dilithium addresses are stored on-chain as P2SH scripts, so a UTXO queried back through `extract_script_pub_key_address()` returns `ScriptHash`, not `PubKeyDilithium`. Wallet code is aware of this asymmetry.

The redeem script for a Dilithium output is built by `dilithium_redeem_script()` in `crypto/txscript/src/standard.rs`. The signature hash function is `calc_signature_hash()` in `consensus/core/src/hashing/sighash.rs`; it is algorithm-agnostic and does not carry a Schnorr-specific name in the codebase.

### 3.3 Why no hybrid mode

Many "PQC-ready" chains ship a hybrid signature (curve + lattice). Sophis does not. Hybrid mode doubles the verification cost, doubles the failure surface, and — critically — encourages the long-term retention of the curve component, defeating the purpose. Sophis treats Dilithium as the only acceptable signature for a chain that aspires to outlive a CRQC.

---

## 4. Proof-of-Work

### 4.1 RandomX

Sophis uses **RandomX** as its PoW algorithm. RandomX was designed by the Monero community to be memory-hard, branch-heavy, and amenable to commodity CPUs while penalizing dedicated ASIC designs. The implementation is the `randomx-rs` Rust binding.

Key implementation details:

- Each consensus VM is thread-local and re-keyed per **epoch**, where `EPOCH_LENGTH = 2048` blocks.
- The epoch key is derived from a deterministic function of the chain state, which prevents pre-computation of the dataset across epoch boundaries (an ASIC vendor cannot bake the dataset into hardware).
- A `--fast-mode` variant allocates ~2 GB of dataset RAM and runs roughly 10× faster; this is used by the Sophis test suite and by miners with sufficient memory.

### 4.2 Why RandomX (and not kHeavyHash, kHeavyHash++, ProgPow, etc.)

Sophis explicitly rejects the kHeavyHash family used by Kaspa. kHeavyHash is GPU-friendly by design, and Sophis judged that GPU PoW concentrates rapidly in industrial farms (as Ethereum's Ethash trajectory demonstrated until merge). RandomX instead aligns hashing economics with CPU rental markets — anyone with a desktop, laptop or server CPU can mine usefully on day one without specialized hardware.

This choice has a cost: RandomX hashrates are lower in absolute hashes per second per Watt than ASIC-friendly algorithms. Sophis accepts that cost as the price of the wider distribution it produces.

### 4.3 Difficulty adjustment

Sophis inherits the GHOSTDAG-era sampled difficulty window from the protocol foundation. The window is sampled, not contiguous, to bound storage and computation. The block rate target is `target_time_per_block = 100 ms` (i.e. 10 BPS). Difficulty is recomputed every block based on a sampled window of recent blocks; the sampling rate and window size are consensus parameters.

### 4.4 Note on a future PoW algorithm selector

A reserved 1-byte field is documented in the design notes for a future PoW algorithm selector (insurance policy in case RandomX needs to be swapped via hard fork without breaking the header layout). This is a nice-to-have, not a commitment, and is **not** active at genesis — RandomX is the sole PoW algorithm at mainnet launch.

---

## 5. Monetary policy

### 5.1 Hard cap and emission curve

Sophis has a hard supply cap of **210,000,000 SPHS**, denominated in sompi (10⁻⁸ SPHS).

The emission curve follows a Bitcoin-style **halving** schedule expressed in DAA (Difficulty-Adjustment Algorithm) score, the BlockDAG analogue of block height. Two phases govern the subsidy:

1. **Pre-deflationary phase** — flat subsidy of `pre_deflationary_phase_base_subsidy` sompi per block. This phase ends at `deflationary_phase_daa_score`, which is set to roughly half a year after genesis.
2. **Deflationary phase** — subsidy halves on a fixed schedule expressed in the `bps_history()` table, which the `CoinbaseManager` consults each block. The schedule is monotone non-increasing and asymptotes to zero before reaching the 210M cap.

The exact subsidy formula is implemented in `consensus/src/processes/coinbase.rs`. There is no governance lever to change it; modifying any subsidy parameter requires a hard fork.

### 5.2 Coinbase distribution — 100 % to the miner

**Every block's subsidy + transaction fees go entirely to the miner who produced the block.**

- There is no on-chain developer fund.
- There is no foundation allocation.
- There is no protocol-level recipient address.
- There is no coinbase split.
- There is no schedule that gradually retires a devfund, because there is no devfund to retire.

This is enforced in code: `consensus/core/src/config/params.rs` carries no `dev_fund_address` field, and `expected_coinbase_transaction()` in `consensus/src/processes/coinbase.rs` produces a single output per blue mergeset block, paying the full subsidy plus fees to the miner. The structures that previously held a devfund script-public-key were removed in the 2026-05-04 cleanup commit. (See `DECISOES_2026-05-04.md`, Decision 2.)

This is an irrevocable design choice. The core team commits publicly that no future hard fork will reintroduce a devfund — not as a multisig, not as a "voluntary" recipient compulsorily encoded in consensus, not under any other label. Voluntary donations to a published address are acceptable; consensus-encoded recipients are not.

### 5.3 Founder self-restriction

The founder will mine SPHS personally, on commodity CPU hardware, under three publicly-binding restrictions:

1. **Wait period.** The founder's mining hardware will not produce a single hash on mainnet until **24 hours after the genesis block** has been mined. The mainnet announcement will precede genesis by at least 72 hours, for a total minimum window of four days between public announcement and the founder's first block.

2. **Independent operation.** The founder will mine solo, or via a third-party pool. **Never** via a pool operated by the Sophis team. The team does not, and will not, run a Sophis mining pool — that would constitute a custodial money-transmission service under FATF/MiCA/FinCEN/BCB definitions and is permanently outside the team's Operational Boundaries (see §11).

3. **5 % lifetime cap.** The founder's mining address is single, declared publicly before the announcement, and never changed. A public monitoring script computes `(balance_address / total_emitted_supply)` continuously; when the ratio reaches 4.9 %, the script auto-pauses the miner. Mining may resume only when the ratio drops below the threshold (because supply continues to grow). The cap is **lifetime** — it does not expire.

The 5 % figure is calibrated below the historical Satoshi accumulation pattern (~5–10 % over the first two years per Patoshi analysis) and well below explicit founder allocations in chains like Solana (~10 % via genesis allocation). The full statement is published as the **Founder Self-Restriction Statement** at mainnet launch, alongside the script source.

### 5.4 Why no on-chain treasury

Treasury funding via consensus introduces an "issuer-identifiable common enterprise" element that aligns uncomfortably with the *Howey* test (US securities), MiCA's "issuer" concept, and Brazil's Lei 14.478/2022 definition of public offer. Removing it does not eliminate regulatory risk in absolute terms, but it removes the single largest vector and makes Sophis structurally indistinguishable from Bitcoin and Monero on the question "who receives newly minted coins?"

The cost is real: the project has no consensus-funded development budget. Maintenance is funded by the founder personally, by external grants (HRF, OpenSats, Brink-style), by voluntary donations to a publicly-disclosed multisig address, and eventually by independent maintainers. This is the same funding model that has sustained Bitcoin Core and the Monero Project; Sophis assumes it can sustain Sophis too.

---

## 6. Consensus: GHOSTDAG over BlockDAG

### 6.1 BlockDAG fundamentals

A BlockDAG generalizes a blockchain by allowing multiple blocks to share a parent and by treating "the chain" as a directed acyclic graph rather than a linear sequence. GHOSTDAG, the ordering algorithm Sophis uses, defines a **k-cluster** of blocks (with k = 124) and produces a deterministic linear ordering over the DAG by greedily picking the heaviest cluster anchor at each step.

The benefits over a single-chain PoW:
- Higher throughput at fixed security: multiple blocks can be valid simultaneously.
- Resistance to selfish-mining at low orphan rates.
- Natural compatibility with high block rates (10 BPS would produce unmanageable orphan rates in a linear chain).

The trade-off is engineering complexity: the consensus must track parent relations, mergeset blues/reds, and reachability efficiently. Sophis inherits the mature implementation of these primitives from the GHOSTDAG protocol foundation and extends it with a different cryptographic stack and economic policy.

### 6.2 Block production rate and finality

Sophis targets `target_time_per_block = 100 ms` for an effective 10 BPS. With k = 124, the protocol tolerates substantial network delay before orphans dominate.

**Finality** in Sophis is probabilistic, not BFT-instant. The recommended confirmation depth for high-value transactions is in the range of 1,000 to 2,000 blocks (≈ 100 to 200 seconds), consistent with the orphan-rate alert threshold (`orphan_rate_alert_threshold = 0.10`). A PoS finality gadget was considered and explicitly rejected: it would have introduced a non-PoW economic actor into consensus, undermining the fair-launch character.

### 6.3 Pruning and storage

Sophis implements pruning of historical block bodies past a finality-derived depth (`pruning_depth()`), using the GHOSTDAG-era pruning proof manager. Headers and the UTXO set remain authoritative; old block bodies can be discarded by full nodes that do not serve historical sync. Archival nodes opt into full retention.

### 6.4 Mass system

Sophis applies a three-mass cost model (compute, transient, storage) summed against `max_block_mass`:

- **Compute mass** = `size × mass_per_tx_byte + spk_size × mass_per_script_pub_key_byte + sig_ops × mass_per_sig_op`.
- **Transient mass** = `size × TRANSIENT_BYTE_TO_MASS_FACTOR` (bounds in-flight memory).
- **Storage mass** follows the generalized KIP-0009 formula and penalizes UTXO bloat economically.

Because Dilithium signatures are ~2.4 kB each, `max_block_mass` is set to `500_000` for mainnet and elevated to `10_000_000` for devnet/simnet to accommodate oversized test transactions. The mass parameters are consensus-critical.

---

## 7. Native tokens

Sophis exposes **native tokens as a first-class L1 primitive**, not an ERC-20-style smart-contract pattern. A native token output uses `ScriptPublicKey.version() == SCRIPT_VERSION_TOKEN = 2`, which causes the transaction validator to dispatch into the native-token codepath rather than the standard P2SH/Dilithium codepath.

Each native token is identified by a `TokenId` (a Blake3 hash of its mint manifest). The supply is enforced by the validator: minting requires a contract authorization, transfers require source-output authorization, and burns reduce supply atomically.

### 7.1 The `Resource<T>` linear type

In the SDK, native-token amounts are represented by a `Resource<T>` value that **panics if dropped without `.consume()`**. This linear-typed design is the SDK's enforcement mechanism for "every token amount must end up somewhere" — it is impossible to silently lose tokens by forgetting a code path.

Example shape:

```rust
fn split(input: Resource<MyToken>, parts: u32) -> Vec<Resource<MyToken>> {
    let chunks = input.divide_into(parts);  // .consume() called internally
    chunks
}
```

If the contract author writes `let _ = input;` and never consumes the resource, the WASM execution panics and the transaction is invalid. This is checked at runtime by the `Resource<T>` `Drop` implementation in the SDK.

### 7.2 Transfer policy

Native tokens carry an optional **Transfer Policy** — a small predicate evaluated by the validator on every transfer. Common patterns include "transferable to anyone", "transferable only to whitelisted scripts", "frozen until block N", "burnable but not transferable". The policy is part of the mint manifest and is immutable unless the manifest sets `UpgradePolicy::MultisigTimelock { keys, threshold }`.

---

## 8. sVM — the Sophis Virtual Machine

### 8.1 Architecture

sVM is a sandboxed WASM execution engine, implemented over Wasmtime, that runs as a sub-component of the transaction validator. A contract output uses `ScriptPublicKey.version() == SCRIPT_VERSION_CONTRACT = 1`, which routes the validator into the sVM dispatch path.

Four crates compose the sVM:

| Crate | Responsibility |
|---|---|
| `svm/core` | Shared types: `ContractManifest`, `NativeTokenUtxoData`, `TokenId`, `Capability`, `GasConfig`, `UpgradePolicy` |
| `svm/runtime` | Wasmtime engine, RocksDB-backed `DbContractStore`, bytecode validator, fuel metering |
| `svm/host` | `SophisHostCrypto`, the host-function surface exposed to WASM contracts |
| `svm/sdk` | The `#[sophis_contract]` macro, `Env`, `Resource<T>`, borsh codec helpers |

### 8.2 Seven security layers

1. **Bytecode validation.** The validator rejects floats, SIMD instructions, threads, exception handling, and any feature that would make execution non-deterministic across nodes. Memory must declare a `maximum`; the cap is 256 pages = 16 MiB. An undeclared or oversized memory section fails deployment.
2. **Fuel metering.** Every WASM instruction consumes fuel from a budget set by the transaction's mass; a contract that exceeds its budget is aborted and its transaction invalidated. Fuel is not refundable.
3. **Capability gating.** A contract declares the host capabilities it requires in its manifest. The runtime registers only those host functions for that contract; unrequested capabilities are not imported, and an attempt to call an unimported function is a link-time error. The current `Capability` enum is exactly: `ReadUtxo`, `ProduceOutput`, `VerifyDilithium`, `ReadBlockHeight`, `HashSha3`, `VerifyRisc0Proof`. No `VerifySchnorr`. No `OP_PRIVACY` capability. These six are the entire surface.
4. **Linear-typed resources.** As described in §7.1, `Resource<T>` enforces that every token amount is explicitly consumed.
5. **Deterministic crypto host functions.** Every crypto function exposed to a contract is deterministic and side-effect-free: same inputs produce the same output across all nodes.
6. **Upgrade policy enforcement.** A contract's `UpgradePolicy` is validated at deployment by `validate_contract_deploy()`. For `MultisigTimelock` the rules are: `threshold > 0`, `threshold ≤ keys.len()`, `keys.len() ≤ 16`. Once deployed, the policy is immutable.
7. **Formal verification harnesses.** Critical host functions and resource-accounting code carry Kani harnesses that exhaustively model-check the relevant property over bounded inputs.

### 8.3 Adding a new host function

The procedure is intentionally rigid:

1. Add the function to the `HostCrypto` trait in `svm/host`.
2. Register it in the linker in `svm/host/host.rs`.
3. Create a corresponding `Capability` variant.
4. Expose it in `Env` in the SDK.
5. Write a Kani harness that proves any safety property the function relies on.

Steps 1–4 without step 5 are rejected at code review.

### 8.4 What sVM is not

sVM is not Ethereum-compatible. There is no EVM bytecode interpreter, no Solidity ABI, no `eth_call`. WASM was chosen specifically because it allows formal-verification-friendly languages (Rust), avoids 256-bit arithmetic as the default word size, and produces smaller, faster contracts than EVM bytecode for the same logical operation.

sVM also does not expose any privacy primitive. There is no FHE library, no `OP_PRIVACY_ENABLE` opcode, no shielded pool. Adding such a primitive to the protocol is permanently out-of-scope for the core team (see §11).

---

## 9. ZK-Rollup Layer 2

Sophis ships a native-style ZK-Rollup at L2, designed to scale throughput without changing L1 economics or trust assumptions. The rollup is **internal** — there is no cross-chain component. It is not a bridge to Ethereum or any other foreign chain.

### 9.1 Architecture

| Crate | Responsibility |
|---|---|
| `rollup/core` | Shared types: `L2Tx`, `L2Utxo`, `Batch`, `BatchJournal`, `StateRoot`, `hash_withdrawals` |
| `rollup/guest` | Risc0 RISC-V guest implementing the L2 state-transition function |
| `rollup/host` | Risc0 host that orchestrates proof generation and produces the STARK proof |
| `rollup/verifier` | sVM WASM contract that verifies a `BatchJournal` on L1 (8 unit tests) |
| `rollup/sequencer` | mempool, `Sequencer<C>`, `BatchTrigger`, `L1Client` trait, HTTP RPC (19 tests) |
| `rollup/node` | CLI binary `start` + `gen-key`, HTTP :9944 |
| `rollup/bridge/deposit` | `DepositRecord`, `BRIDGE_VAULT_VERSION = 3`, L1 vault helpers |
| `rollup/bridge/withdrawal` | sVM WASM contract validating `WithdrawalClaim` (`BRIDGE_CLAIM_VERSION = 4`) |

The rollup `guest/` is a **separate Cargo workspace** isolated to a `riscv32im` target; it is built with its own `cargo build` and is not part of the main host workspace.

### 9.2 STARK proofs and verification

The guest executes the L2 state-transition function over a batch of L2 transactions. The host produces a Risc0 STARK proof of correct execution, plus a **journal** containing the batch's input commitment, output state root, and withdrawal commitments. The journal is serialized with **borsh** (never serde), because the Dilithium key types do not implement `serde::Serialize`.

The `rollup/verifier` sVM contract receives the journal on L1 and uses the `VerifyRisc0Proof` capability to check the STARK. On success, it commits the new state root and updates withdrawal balances atomically.

The `VerifyRisc0Proof` capability exists exclusively for this internal rollup. It is not — and will not be — repurposed as a generic "verify anything from chain X" primitive that would, in effect, become a bridge.

### 9.3 Sequencer selection

Sophis avoids a separate sequencer set with its own economics. The miner of L1 block `N × 100` becomes the sequencer for the next batch window. A batch is finalized when **either**:

- 100 L2 transactions have been collected, **or**
- 30 seconds have elapsed since the previous batch.

No staking, no slashing, no separate sequencer token. The sequencer's reward is the L2 fees of the batch they prove; their bond is the L1 block they had to mine to qualify.

### 9.4 Deposits and withdrawals

Deposits to L2 lock SPHS in an L1 vault UTXO whose script version is `BRIDGE_VAULT_VERSION = 3`. The deposit emits a `DepositRecord` that the next batch picks up.

Withdrawals back to L1 are claimed via the `rollup/bridge/withdrawal` sVM contract, which verifies a Merkle inclusion proof against the batch's withdrawal commitment and releases the corresponding amount from the vault. Claim outputs use `BRIDGE_CLAIM_VERSION = 4`.

`BRIDGE_VAULT_VERSION` and `BRIDGE_CLAIM_VERSION` are protocol constants; changing them requires a hard fork.

### 9.5 L2 key derivation

L2 wallets reuse the same BIP-39 mnemonic as L1, but on a distinct derivation path: `m/44'/111111'/0'/1/0` (vs L1 `m/44'/111111'/0'/0/0`). This keeps L2 funds isolated cryptographically while sharing the same recovery seed.

### 9.6 Feature gate

The L1 `sophisd` Windows native build does not require ZK verification by default; the WASM contract that depends on `VerifyRisc0Proof` panics explicitly under a stub if the `svm-zk` Cargo feature is not enabled. **Production nodes MUST build with `--features svm-zk`** to validate Phase 3 ZK-Rollup batches; lite/dev/wallet nodes that only use RPC can omit it.

---

## 10. Out-of-scope by design

This section lists features that are not, and will not become, part of the Sophis core protocol. Each exclusion is binding on the core team, documented in `DECISOES_2026-05-04.md`, and reflected as a code-level invariant.

### 10.1 No cross-chain bridge

Sophis does not include, and will not include, an officially-developed cross-chain bridge. There is no Wrapped SPHS (WSPHS) ERC-20 issued by the Sophis team on any foreign chain.

The reasoning is regulatory, not technical: an officially-operated bridge processes third-party funds, which under FATF Recommendation 16, MiCA Title V, FinCEN 31 CFR §1010.100(ff)(5), and Brazil's Lei 14.478/2022 unambiguously qualifies as money transmission requiring a license the Sophis team does not have and will not pursue. The Pertsev (Tornado Cash, sentenced May 2024 to 5y4m in the Netherlands) and Storm (Tornado Cash, US trial 2024–2025) cases have clarified that protocol authors who deploy and promote such infrastructure are personally exposed regardless of the contract's permissionless character.

If independent third parties build bridges between Sophis and other chains at their own risk, the core team **does not endorse, does not promote, and does not operate** any such bridge. The reference codebase that previously prototyped a ZK-Bridge has been extracted to an external, non-deploy repository (`C:\Projetos\ZKBridge\`, BSL 1.1, private).

### 10.2 No native privacy

Sophis does not include, and will not include, native privacy primitives. There is no FHE, no ring signatures, no zk-SNARK shielded pool, no confidential-transaction homomorphism, no `OP_PRIVACY_ENABLE` opcode, no mixer encoded in consensus.

The reasoning is regulatory: under MiCA Article 76 and ESMA's 2024 guidelines, a chain that exposes a native privacy mechanism is classified as an Anonymity-Enhancing Cryptocurrency (AEC). AEC status triggers compulsory CEX delisting in the EU (precedent: Monero delisted from Binance EU, Kraken UK, Bitstamp 2023–2024) and impossible-to-satisfy AML/Travel-Rule compliance. The "opt-in privacy" defense does not work under MiCA — the categorization is of the tool, not of individual use. Zcash, with ~95 % transparent transactions, is treated as AEC anyway.

This exclusion is permanent. Privacy-preserving applications can be built **on top of** Sophis by independent third parties — as L2 protocols, off-chain mixers, etc. — at their own regulatory risk; they will not be features of the core protocol.

### 10.3 No on-chain devfund

As detailed in §5.2: 100 % of every block's coinbase goes to the miner. There is no devfund, no foundation allocation, no protocol-encoded recipient. This is binding and will not be reintroduced via hard fork under any label.

### 10.4 No legal entity bound to the protocol

There is no Sophis Foundation, no LLC, no Stiftung, no Fundación, no DAO LLC, no CNPJ vinculado ao protocolo. The project follows the Bitcoin Core / Monero Project model: code + protocol + community. The founder operates personally as a developer, mitigated by individual measures (open-source license, DCO requirement, trademark registration in personal name, personal succession document, recruited external maintainers).

A formal entity may be revisited only if specific external triggers fire: market cap > US$ 50M sustained, tier-1 CEX listing requiring institutional counterpart, significant external grant flow, imminent litigation, personal-safety threat, or a commercial contract that legally requires a juridical counterparty. Aesthetic or community pressure to "professionalize" is explicitly **not** a trigger.

---

## 11. Operational Boundaries

The Sophis core team commits to operating only **non-custodial infrastructure**:

| Service | Status | Notes |
|---|---|---|
| Faucet | Operate, with limits | ≤ US$ 1 equivalent / user, captcha + 24h IP rate-limit, no KYC, monthly budget cap, funded from founder personal wallet, framed as "personal donation in faucet form" |
| Block explorer | Operate, view-only | No tx broadcasting through UI, no PII collection, no per-address labeling |
| DNS seeders | Operate `sophisnet.org`, `sophisd.net`, `sophis.ws` | Recruiting 2–3 independent operators for additional seeders post-mainnet |
| `sophis-stratum-bridge` (software) | Maintain code | README explicitly warns "local-only use — do not run as a service to third parties without licensure"; no team-operated instance |
| Mining pool | **Do not operate** | A pool fulfils 3 of the 5 VASP categories (custody, third-party accounting, transfer). Independent operators may run pools at their own risk |
| Bridge / Wrapped SPHS | **Do not operate** | See §10.1 |
| Centralized exchange / DEX with custody / wallet custody | **Do not operate** | These are full VASP services; the core team is non-custodial |

The full text of the Operational Boundaries Statement is published at mainnet launch alongside the binaries.

---

## 12. Network parameters

### 12.1 Mainnet ports

| Protocol | Port |
|---|---|
| P2P | 46111 |
| gRPC | 46110 |
| Borsh RPC | 47110 |
| JSON RPC (wRPC) | 48110 |

Devnet uses 46611 / 46610 / 47610 / 48610 with +10 offsets per node in a multi-node setup. Testnet-10 uses 46211 / 46210 / 47210 / 48210.

### 12.2 Address prefixes

`sophis:` — mainnet.
`sophistest:` — testnet.
`sophisdev:` — devnet.
`sophissim:` — simnet.

Bech32 prefixes are part of consensus: a transaction signed for `sophistest:` cannot be replayed on mainnet.

### 12.3 Genesis

The Sophis genesis block is hard-coded in `consensus/core/src/config/genesis.rs`. It contains **zero coins** — there is no genesis allocation, founder allocation, or pre-mine. Block 1 is the first block to produce a coinbase reward, mined by whoever wins the first PoW solution after genesis.

### 12.4 Coinbase maturity

Coinbase outputs require **100 confirmations on mainnet** (20 on devnet) before they are spendable. This depth is calibrated to the GHOSTDAG reorg-tolerance window.

---

## 13. Reference implementation

Sophis ships as a Rust workspace at `C:\Projetos\sophis\`, organized into the following top-level crates:

| Component | Location |
|---|---|
| Node binary | `sophisd/` |
| Miner binary | `miner/` (RandomX, light + fast modes, epoch-key-aware) |
| Wallet (CLI) | `wallet/`, `crypto/wallet-bip32/` |
| Consensus | `consensus/`, `consensus/core/` |
| GHOSTDAG | `consensus/src/processes/ghostdag/` |
| RandomX PoW | `consensus/pow/` |
| Cryptography | `crypto/addresses/`, `crypto/txscript/`, `consensus/core/src/sign.rs` |
| sVM | `svm/core`, `svm/runtime`, `svm/host`, `svm/sdk` |
| ZK-Rollup | `rollup/core`, `rollup/guest`, `rollup/host`, `rollup/verifier`, `rollup/sequencer`, `rollup/node`, `rollup/bridge/deposit`, `rollup/bridge/withdrawal` |
| RPC | `rpc/core`, `rpc/grpc`, `rpc/wrpc`, `rpc/service` |
| Block explorer | external repo (separate from `sophisd`) |
| Faucet | external repo (separate from `sophisd`) |

Build dependencies on Windows: Rust 1.94+, MSVC 2022 C++ toolchain, LLVM 22+ (`LIBCLANG_PATH`), `protoc`, and CMake 4.3+ (required by `randomx-rs`). The codebase **must** live outside Google Drive paths — Drive's lack of hard-link support breaks Cargo's incremental cache. The canonical path is `C:\Projetos\sophis\`.

---

## 14. Roadmap

### 14.1 Completed

- **Phase 1.** GHOSTDAG consensus, RandomX PoW, Dilithium end-to-end, orphan-rate monitor.
- **Phase 2.** sVM (WASM), native L1 tokens, Rust SDK, `sophis-lint` (Dylint), Kani formal proofs, CLI Dilithium wallet, faucet, block explorer, emission curve, complete removal of secp256k1/Schnorr from the codebase, sVM security review, whitepaper v1.0.
- **Phase 3.** ZK-Rollup L2 (STARKs + Risc0 + native sequencer): all seven crates complete with passing test suites, sVM `VerifyRisc0Proof` capability live.

### 14.2 In progress (pre-mainnet)

- **Founder Self-Restriction monitoring script** — public GitHub repo, watches `(balance / total_emitted_supply)`, auto-pauses miner at 4.9 %.
- **Three canonical documents** for mainnet announcement: Sophis Monetary Policy, Founder Self-Restriction Statement, Operational Boundaries Statement.
- **Bootstrap nodes** in two or more geographies; recruited independent DNS seeder operators.
- **LICENSE** (MIT or Apache 2.0) and **CONTRIBUTING.md** with DCO requirement at the repo root.
- **Testnet hardening** — final stress test under realistic geographic and adversarial conditions.

### 14.3 Permanently out-of-scope

The following items, present in earlier roadmap drafts, are **removed and will not return**:

- Phase 3 (FHE / OP_PRIVACY / native privacy) — see §10.2.
- Phase 4 (ZK-Bridge cross-chain / WSPHS) — see §10.1.
- Phase 8 (any future privacy-related extension) — see §10.2.
- On-chain devfund in any form — see §5.2.
- Sophis Foundation or other legal entity bound to the protocol — see §10.4.

### 14.4 Possible future work (not commitments)

- **PoW algorithm selector** — 1-byte field reserved in the header for a future swap of RandomX (insurance policy, not a planned migration).
- **P2Pool or Stratum V2** support — to reduce demand for centralized mining pools.
- **NUMA-aware mining optimizations** — re-evaluated post-testnet only if they would not create unequal hardware advantages.
- **Application-layer privacy** built by independent third parties as L2 protocols, off-chain mixers, etc. — at their own regulatory risk, never as core-protocol features.

The community and independent contributors may propose additional features. The core team reserves the right to decline proposals that conflict with the binding invariants in §10.

---

## 15. Threat model and limitations

### 15.1 What Sophis defends against

- **Quantum forgery of historical signatures.** Dilithium ML-DSA-44 is the only signature scheme; harvested transactions cannot be retroactively forged after a CRQC arrives.
- **ASIC monopolization of PoW.** RandomX's memory-hardness penalizes ASIC designs; CPU rental markets keep hashrate broadly available.
- **Insider economic capture.** No pre-mine, no allocation, no devfund, no founder cap above 5 % lifetime — there is no built-in lever for an insider class to extract rent from holders.
- **Regulatory tail-risk attached to optional features.** Native privacy and official cross-chain bridges, the two highest-risk feature categories under current EU/US/Brazil regulation, are excluded by design.

### 15.2 What Sophis does not defend against

- **CRQC-broken hash functions.** SHA-3 / Blake3 / Blake2b are conjectured quantum-resistant under Grover (factor-2 security loss), but no chain is immune to a hypothetical *cryptanalytic* break of its hash functions.
- **51 % attacks under low hashrate.** A young chain with limited hashrate is structurally vulnerable to rented-hashrate attacks; participants should treat early confirmations as low-finality.
- **Implementation bugs in libcrux-ml-dsa.** The library is high-quality and audited, but Dilithium is younger in deployment than secp256k1; a discovered library bug could affect Sophis disproportionately because Dilithium is the **only** scheme.
- **Application-layer privacy leakage.** Because Sophis is transparent, on-chain analysis links addresses by default. Users seeking privacy must rely on application-layer techniques (third-party mixers, fresh-address hygiene) at their own risk.
- **Regulatory shifts.** A future regulation that, e.g., classified all L1 PoW chains as VASPs (currently not the case) would affect Sophis as it would affect Bitcoin. The Operational Boundaries posture mitigates this but does not eliminate it.

### 15.3 What the core team does not promise

- **No specific performance figure.** Throughput and finality are dependent on network conditions, miner geography, and adversarial behavior. Numbers cited here are design targets, not service-level agreements.
- **No exchange listing.** The core team does not promote Sophis to exchanges and does not commit to securing any listing. CEX listings, if they happen, are by exchange initiative, not by team lobbying.
- **No price target.** SPHS has no intrinsic value claim, no yield, no buyback program, no peg, no stablecoin reserve. It is a fair-launch PoW commodity-like asset and may be worth zero.

---

## 16. Acknowledgements and references

Sophis builds on a decade of public research. In particular:

- **Sompolinsky, Lewenberg, Zohar.** "PHANTOM, GHOSTDAG: A Scalable Generalization of Nakamoto Consensus." 2018.
- **NIST.** FIPS 204 — Module-Lattice-Based Digital Signature Algorithm (ML-DSA / Dilithium). August 2024.
- **Monero Research Lab.** RandomX specification and reference implementation. 2019–present.
- **Risc0.** zkVM and Risc0 STARK protocol. 2023–present.
- **libcrux team.** `libcrux-ml-dsa` constant-time Rust implementation of ML-DSA. 2024–present.
- **Wasmtime (Bytecode Alliance).** Production-grade WebAssembly runtime.
- **Dylint, Kani.** Static and model-checking tooling for Rust used by Sophis to enforce invariants.

The decision to ship without a devfund, native privacy, and a cross-chain bridge follows the lessons of LBRY, Telegram (TON), Tornado Cash (Pertsev / Storm), and the Monero / Zcash MiCA delistings, documented in `DECISOES_2026-05-04.md`.

---

## 17. Disclaimer

SPHS is an experimental cryptocurrency. There is no issuer, no foundation, no guaranteed exchange, no stable peg, and no claim of any future utility or value. Mining and using Sophis is at your own risk, subject to your own jurisdiction's laws. The core team operates non-custodial infrastructure only and does not provide financial, legal, or tax advice.

Holding SPHS does not give the holder a contractual relationship with the core team, the founder, or any other party. The founder operates personally under the constraints described in §5.3 (24 h wait, 5 % lifetime cap, single declared address) but is not, in any legal sense, the issuer of SPHS. SPHS is created by miners performing PoW, block by block, with no central party in between.

This whitepaper is informational. The authoritative specification is the source code at `C:\Projetos\sophis\` and its public Git history.

---

*End of whitepaper v2.0 — 2026-05-05.*
