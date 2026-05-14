# Sophis — Pre-Testnet Audit Report

**Started:** 2026-05-14
**Auditor:** Claude Code (Opus 4.7, 1M context)
**Scope:** Complete workspace audit before official testnet launch
**Format:** Monolithic report (per founder decision 2026-05-14)
**Cadence:** Multi-session (1-2 weeks)

> **Status:** 🟡 IN PROGRESS — Session 1 (baseline + inventory)

---

## 0. Methodology

This audit categorizes the workspace into four Tiers by blast radius. A bug in Tier 0 corrupts consensus and is permanently fatal; a bug in Tier 3 is cosmetic. The audit treats them with proportional rigor:

- **Tier 0 — Consensus-critical.** Function-by-function, parameter-by-parameter, every public API and every invariant. Goal: 100% test coverage on consensus paths, every error variant exercised, every constant proven derivation-correct, every panic path justified.
- **Tier 1 — Operational security.** sVM host capabilities, wallet/signing, RPC auth, mining manager, anti-long-range-attack. Each capability covered with positive + adversarial test. Each panic path traced. Each unsafe block justified.
- **Tier 2 — ZK plumbing.** Phase 3 rollup + Phase 5 oracle (deprecated) + Phase 6 DA + Phase 9 PQC oracle. Witness/AIR correctness already covered by RFC/FIPS vectors; audit focuses on wire format invariants, prover/verifier mismatches, dispatch fan-out.
- **Tier 3 — UX/infra.** Faucet, explorer, dashboard, calculator, da-stress, dnsseeder. Smoke tests + obvious safety; not blocking.

Each session below either appends new findings or updates the Veredito section. Findings are classed:
- **P0** — must fix before testnet launch
- **P1** — must fix before mainnet launch
- **P2** — post-mainnet technical debt
- **OK** — confirmed correct under audit, no action needed

---

## 1. Baseline (Session 1, 2026-05-14)

### 1.1 Repo state

| Field | Value |
|---|---|
| Repository | `C:\Projetos\sophis\` |
| Branch | `main` |
| HEAD | `a83bf79` (docs: CLAUDE.md — expand prod infra section) |
| Untracked | `Whitepaper.pdf` (1 file) |
| Working tree | otherwise clean |
| Rust | 1.94.1 (rustc 1.94.1, cargo 1.94.1) |
| Toolchain reqs | LLVM 22+, MSVC Build Tools 2022, protoc, CMake 4.3+ |
| Workspace edition | 2024 |
| Workspace version | `1.1.0` |
| License | Apache-2.0 |

> ⚠️ **Drift vs. project CLAUDE.md:** project CLAUDE.md references `1eead7b` as HEAD ("ROADMAP COMPLETE"). Actual HEAD = `a83bf79`, a docs-only commit *after* the roadmap closer. The roadmap commit `1eead7b` is preserved in history. This is not a regression — it is documentation drift to be re-synced before audit closure.

### 1.2 Workspace inventory

| Metric | Count |
|---|---|
| Workspace members (Cargo.toml) | **75 crates** + 1 guest workspace (`rollup/host/guest`) |
| Rust source files (excluding `target/`) | **986** |
| Lines of Rust code (excluding `target/`) | **178,745** |
| Test attributes (`#[test]`, `#[tokio::test]`, `#[wasm_bindgen_test]`) | **1,897 in 282 files** |
| `unsafe` blocks/fns/impls | **54 occurrences in 27 files** ⚠️ (must justify each) |
| `pub fn`/`pub async fn`/`pub const fn` (line-start regex; impl-block pubs not counted) | **638 in 233 files** (lower bound) |

> ℹ️ Project CLAUDE.md mentions "414/414 verdes + 4 ignored slow" for Phase 5 oracle scope only. Workspace-wide totals collected here are larger and include integration, sVM, consensus, RPC, wallet, mining, etc.

### 1.3 Workspace members — by Tier

#### Tier 0 — Consensus-critical (12 crates)

```
consensus              — GHOSTDAG pipeline, virtual processor, body/header processors
consensus/core         — block, tx, hashing, sighash, network, merkle, mass, ALT, DA, events
consensus/pow          — RandomX integration, matrix, xoshiro
consensus/client       — tx/input/output/outpoint shared types
consensus/notify       — consensus event distribution
consensus/wasm         — wasm bindings for consensus types
crypto/hashes          — pow_hashers, sha3 wrapper, blake2b wrapper
crypto/merkle          — Merkle tree (SHA3-384)
crypto/muhash          — Multiplicative hash for UTXO commitment
crypto/addresses       — Bech32m + sophis: / sophistest: / sophisdev: / sophissim:
crypto/txscript        — Script engine, opcodes (incl. 0xc4 Dilithium), upgrade policy
crypto/txscript/errors — Script error variants
```

#### Tier 1 — Operational security (15 crates)

```
svm/core         — Capability enum, types, deploy, token, events
svm/runtime      — WASM validator (7 safety layers), host interface
svm/host         — host fns: dilithium, sha3, risc0, plonky3
svm/sdk          — contract author SDK (Env, UTXO, Resource)
svm/sdk-macros   — proc macros (panic_handler, contract entry)
svm/kani-proofs  — formal proofs (model checking)
svm/lint         — dylint library (no_unsafe, no_unchecked_arith, no_float)
dilithium-wallet — CLI wallet (Dilithium ML-DSA-44)
wallet/bip39     — mnemonic + derivation
wallet/pskt      — partially-signed Sophis transaction
wallet/descriptors — script descriptors (BIP-380-equivalent)
wallet/typed-data — EIP-712-equivalent typed signing (J2)
wallet/filters   — BIP-157/158-equivalent compact filters (K2)
wallet/spv       — Light client SPV (J5)
rpc/{core,service,macros,grpc/*,wrpc/*} — RPC fan-out (10 crates)
mining + miner   — mining manager + CPU miner binary (donate flag)
sophisd          — node binary
protocol/{p2p,flows,mining} — networking + flow handlers
components/{addressmanager,connectionmanager,consensusmanager} — runtime services
```

#### Tier 2 — ZK plumbing (15 crates)

```
rollup/core              — Phase 3 batch journal types
rollup/host              — Risc0 host prover
rollup/verifier          — Risc0 verifier
rollup/sequencer         — native L1 sequencer
rollup/node              — rollup-node binary
rollup/bridge/{deposit,withdrawal} — Phase 3 internal bridge (NOT Phase 4 ZKBridge)
rollup/host/guest        — separate workspace (Risc0 guest, RISC-V target)
oracle/pqc-core          — Phase 9 PQC oracle types + Dilithium sign/verify
oracle/pqc-contract      — Phase 9 aggregator contract WASM template
oracle/pqc-publisher     — Phase 9 publisher CLI
oracle/pqc-tests         — Phase 9 integration scenarios
oracle/core              — Phase 5 DEPRECATED types + journal
oracle/feeds             — Phase 5 DEPRECATED Pythnet pull adapter
oracle/host              — Phase 5 DEPRECATED Plonky3 prover + AIRs (~55 chips)
oracle/relayer           — Phase 5 DEPRECATED relayer daemon
consensus/core/src/{alt,da,events,commitment} — sVM-bearing L1 surfaces
```

#### Tier 3 — UX/infra (12 crates)

```
testnet-faucet         — HTTP faucet (deployed to faucet.sophis.org)
sophis-explorer        — block explorer (view-only)
sophis-dnsseeder       — DNS seeder (deployed to testnet-seed.sophis.org)
tools/sophis-dashboard — Hyperliquid-style metrics dashboard
tools/sophis-calculator — Energy offset calculator (H1)
tools/sophis-da-stress — DA throughput stress tool
indexes/{core,processor,utxoindex} — UTXO + processor indexing
notify                  — pub/sub notify (events)
metrics/{core,perf_monitor}
core                   — small helpers (log, panic, time, console, env)
utils + utils/tower + utils/alloc + simpa + rothschild + bridge + math + database + wasm + wasm/core
examples/contracts/{token-minting-policy,transfer-policy,time-lock} — sample contracts
```

> 75 crate breakdown above sums to >75 because some crates are counted in groupings; the explicit list in `Cargo.toml` is authoritative.

### 1.4 Build/test environment confirmed

```
rustc 1.94.1 (e408947bf 2026-03-25)
cargo 1.94.1 (29ea6fb6a 2026-03-24)
LIBCLANG_PATH = C:\Program Files\LLVM\bin                                ✓
PROTOC        = C:\Users\mfhor\AppData\Local\Microsoft\WinGet\...\protoc.exe  ✓
cmake         = C:\Program Files\CMake\bin\cmake.exe                     ✓
target/       present                                                    ✓
```

### 1.5 Baseline test/compile results

| Step | Command | Result |
|---|---|---|
| Compile workspace (Windows, all defaults) | `cargo check --workspace --all-targets` | ❌ **FAILS — known risc0/MSVC issue, expected (§1.5.1)** |
| Compile workspace (Windows, excluding risc0 host crates) | `cargo check --workspace --all-targets --exclude sophis-rollup-host --exclude rollup-node` | ✅ **exit 0 in 1m00s, 99 crates, zero warnings** |
| Workspace test suite | `cargo test --workspace --exclude sophis-rollup-host --exclude rollup-node --no-fail-fast` | ✅ **exit 0** — **174 suites, 1,914 passed, 0 failed, 65 ignored** (Session 1) — after F-5 fix: 1,917/0/65 with 3 new sign tests |
| Clippy CI invariant | `cargo clippy --workspace --all-targets --exclude sophis-rollup-host --exclude rollup-node -- -D warnings` | ✅ **exit 0** — **0 errors, 0 warnings, finished in 49.53s** (Session 3, after fixing one regression introduced by F-5 commit; see `3261134` "drop useless `ZERO_HASH.into()`") |
| Test suite (svm-zk / risc0) | `cargo nextest run -p sophis-svm-host --features risc0` | ⏳ Linux Docker only — Session 8/9 |
| Test suite (plonky3 dispatch) | `cargo nextest run -p sophis-svm-host --features plonky3` | ⏳ Session 2 (after coverage) |
| Devnet end-to-end (5 nodes) | `python devnet/test_runner.py --fast-mode` | ✅ **10/10 tests passed, 0 failures** (Session 3, end-to-end Phase 1 Rodada 2) — B1.1 devnet bring-up, B1.2 RandomX mining (~0.30 MH/s), B1.3 Dilithium TX throughput, B2.1 keygen, B2.2 coinbase to Dilithium addr, **B2.3 valid TX accepted, B2.4 tampered TX rejected** (verifier-side integrity check), B3.1 stress with 2 simultaneous wallets, B4.1 genesis hash unit, B4.2 Dilithium sign+verify unit |

**Baseline summary:** 100% test pass rate (1,914/1,914 non-ignored). 65 ignored are documented slow paths (RFC 8032 STARK round-trip and similar, per CLAUDE.md §"Status testes"). Note: this count is *higher* than the 1,897 `#[test]` attribute count from §1.2 because doc-tests and macro-generated test cases also contribute.

#### 1.5.1 Known build limitation on Windows (NOT a regression)

`cargo check --workspace` fails on Windows because of two `risc0-sys`-derived C++ build issues:

```
error: failed to run custom build command for `risc0-circuit-keccak-sys v4.0.2`
  cc-rs: cl.exe exit code 2 (C++ compilation failure under MSVC 14.44)
error: failed to run custom build command for `risc0-circuit-recursion-sys v4.0.2`
error: linking with `link.exe` failed: exit code: 1120
  librisc0_zkvm_platform-...: error LNK2019: unresolved external symbol sys_alloc_aligned
```

This is documented in project CLAUDE.md (`§"Caminho 2 — feature-gate svm-zk"`) and ZKBridge memory file:
> "Construção | Linux Docker (canonical); MSVC trava em risc0 C++20 (bug pré-existente, idêntico Sophis)"

**Impact on audit:** Tier 2 audit of `rollup/host` + `rollup/host/guest` + `--features svm-zk` paths must be done in Linux Docker, not on this Windows machine. This is recorded as a baseline limitation, **not** a finding.

**Next-session task:** stand up Linux Docker build (`docker compose -f docker-compose.dev.yml run …` or equivalent) and re-run `cargo nextest run --workspace --features svm-zk` to populate the Tier 2 baseline.

### 1.6 Invariants confirmed clean on visual inspection

Performed automated grep over the entire workspace; results triaged manually.

| Invariant (per CLAUDE.md) | Grep / Probe | Verdict |
|---|---|---|
| Devfund on-chain eliminado | `devfund\|dev_fund\|DEV_FUND\|DevFund` | ✅ **CLEAN.** Single match: a comment in `consensus/src/processes/coinbase.rs:110` documenting removal. No code paths reachable. Also verified: zero hits in `consensus/core/src/config/params.rs` (`MAINNET_PARAMS`, `TESTNET_PARAMS`, `SIMNET_PARAMS`, `DEVNET_PARAMS` all clean). |
| Coinbase 100% to miner | Read `consensus/src/processes/coinbase.rs:97-144` | ✅ **CLEAN.** `expected_coinbase_transaction` pays `reward_data.subsidy + reward_data.total_fees` to each mergeset_blue block's reported script; red rewards pay to current `miner_data.script_public_key`. No split, no devfund recipient. |
| Sem privacidade nativa (FHE / OP_PRIVACY / ring sigs / mixers / confidential) | `fhe\|tfhe\|ring_sig\|mixer\|OP_PRIVACY\|confidential` (case-insensitive) | ✅ **CLEAN.** 4 false positives, all matching substring "fhe" inside `ProofHeader` / `JtfHeader` identifiers (case-insensitive). No FHE code remains. |
| Sem Schnorr / secp256k1 (signatures) | `schnorr\|secp256k1` (case-insensitive) | ✅ **CLEAN.** Zero hits in `.rs` files. Note: project CLAUDE.md observes that `rothschild/Cargo.toml` historically listed `secp256k1` as a dep for keypair derivation residual — not verified this session, will check Tier 1. |
| Sem kHeavyHash (PoW = RandomX only) | `kHeavyHash\|KHeavyHash` (case-insensitive) | ⚠️ **PARTIAL.** See finding F-1 below — `KHeavyHash` still compiled as default-OFF feature fallback. |
| sVM `Capability` enum — Dilithium only signature, no Schnorr | Read `svm/core/src/capability.rs` | ✅ **CLEAN.** 11 variants: `ReadUtxo`, `ProduceOutput`, `VerifyDilithium`, `ReadBlockHeight`, `HashSha3`, `VerifyRisc0Proof`, `VerifyPlonky3Proof`, `VerifyDataAvailability`, `ResolveAlt`, `EmitEvent`, `VrfRandomness`. **No `VerifySchnorr`**. CLAUDE.md lists 8 — drift: 3 variants (`ResolveAlt`, `EmitEvent`, `VrfRandomness`) were added via roadmap items #1/#3/#4 in 2026-05-10 but the doc wasn't updated to enumerate them. Code matches the SIPs (SIP-1 ALT, SIP-3 VRF, SIP-4 Events). |
| ABI-frozen constants — L1 ALT | Read `consensus/core/src/alt/mod.rs:70-102, 752-757` | ✅ **CLEAN.** All 8 constants match CLAUDE.md exactly: `ALT_HEADER_LEN=22`, `ALT_HANDLE_LEN=6`, `MAX_ALT_ENTRIES=256`, `MAX_ALT_ENTRY_SCRIPT_BYTES=4096`, `MAX_ALT_CREATIONS_PER_TX=4`, `MAX_ALT_CREATIONS_PER_BLOCK=16`, `BASE_ALT_CREATION_MASS=100_000`, `ALT_STORAGE_MASS_FACTOR=1`. **Tested with `#[test] fn frozen_constants()` at line 752.** |
| ABI-frozen constants — J4 Events | Read `consensus/core/src/events/mod.rs:45-217` | ✅ **CLEAN.** All match CLAUDE.md: `MAX_TOPICS_PER_EVENT=4`, `TOPIC_LEN=32`, `MAX_EVENT_DATA_BYTES=4096`, `MAX_EVENTS_PER_TX=32`, `MAX_EVENTS_PER_BLOCK=1024`, `MAX_LOGS_PER_RESPONSE=1000`, `EVENTS_BY_CONTRACT_BUCKET_SIZE=65_536`. **Tested with `#[test] fn frozen_constants()` at line 207.** |
| Anti-long-range-attack — two-layer architecture | Files touching `min_chain_work` + `max_chain_work_seen` | ✅ **CLEAN.** Both layers wired: (1) `Params.min_chain_work` constant per network — set to `BlueWorkType::ZERO` for all 4 networks at this initial release (per CLAUDE.md "bumpa release-by-release"); (2) `MaxChainWorkSeen` store in `consensus/src/model/stores/max_chain_work_seen.rs` (prefix 62 in `database/src/registry.rs`). Hot paths: `consensus/src/pipeline/header_processor/processor.rs` (gating), `consensus/src/pipeline/virtual_processor/processor.rs` (floor raise). Tests in `consensus/src/pipeline/virtual_processor/tests.rs`. |
| MAX_SCRIPT_PUBLIC_KEY_VERSION expected = 5 (post Phase 6 carrier bump) | grep `MAX_SCRIPT_PUBLIC_KEY_VERSION` | ⏳ to be confirmed Tier 0 / Phase 6 audit. Project CLAUDE.md older line still says =2; memory `project_phase6_subfase_6_1_v5_carrier.md` says bumped to 5 (with v=3,4 reserved). Drift in doc. |

### 1.7 Findings — Session 1 (preliminary)

#### F-1 — PoW algorithm is a compile-time feature flag, not a consensus rule (P1) ✅ FIXED

**Severity:** P1 — must fix before mainnet launch.
**Found:** Session 1, 2026-05-14.
**Status:** ✅ **fixed in commit `a50706f` (same session, 2026-05-14)**. Adopted Option 1 with a WASM exemption: `compile_error!()` at the top of `consensus/pow/src/lib.rs` gated on `#[cfg(all(not(feature = "randomx"), not(feature = "wasm32-sdk")))]`. Verified:
- `cargo check -p sophis-pow` (default features) → exit 0, compiles in ~57s.
- `cargo check -p sophis-pow --no-default-features` → **fails as expected** with the documented message ("sophis-pow requires either the 'randomx' feature … or the 'wasm32-sdk' feature").
- The WASM browser-display path (`wasm.rs`) is preserved.
- Pre-existing latent warning `unused import: std::sync::Arc` in `lib.rs` only surfaces under the now-blocked path; not user-facing.

**Description.**
`sophis-pow` declares `default = ["randomx"]` and gates the entire RandomX integration behind `#[cfg(feature = "randomx")]`. When the feature is OFF, `State::new`, `State::calculate_pow`, and `State::check_pow` fall back to the legacy `Matrix::heavy_hash` + `PowHash` pipeline (`consensus/pow/src/lib.rs:90-95, 132-139, 210-215`; `consensus/pow/src/matrix.rs:124`).

The downstream crates that depend on `sophis-pow` all explicitly request `features = ["randomx"]` in their `Cargo.toml`:
- `consensus/Cargo.toml:32`
- `miner/Cargo.toml:22`
- `bridge/Cargo.toml:16`
- `testing/integration/Cargo.toml:31`

So **the default `cargo build` of a node binary unambiguously uses RandomX**, and any node operator following the documented build instructions is safe.

**Risk.**
A consumer who builds with `--no-default-features` (e.g., to strip an unrelated default feature without realizing this one is load-bearing) or who depends on `sophis-pow` from an out-of-tree wallet/SDK without explicitly setting `features = ["randomx"]` will get a node that validates PoW using `kHeavyHash`. Such a node would reject every real network block (RandomX hash never satisfies a `kHeavyHash`-derived target) — this is a *fail-stop* outcome, not a silent fork. But it would manifest as confusing "all blocks invalid" errors during testnet launch and could erode trust.

**Recommended fixes (any one of):**
1. **Compile-time guard** in `sophis-pow/src/lib.rs`: add a `#[cfg(not(feature = "randomx"))] compile_error!("Sophis requires the 'randomx' feature; non-default builds are not supported on mainnet/testnet")`. Drops the feature from "optional" to "required without an explicit override token."
2. **Runtime assertion** in `sophisd` startup: log + panic if the binary was built without the `randomx` feature. Acceptable but weaker than (1).
3. **Drop the WASM kHeavyHash fallback** in `consensus/pow/src/wasm.rs` — it is explicitly documented as for browser-only dev/educational use and is not exercised by the production node. Move the WASM PoW story to "browsers must use Stratum to a real miner" without shipping any code that pretends otherwise.

**Audit note:** the existence of this code path *probably* dates back to the Kaspa fork and was never deleted when RandomX was wired in. This is dead-code-by-config rather than a vulnerability, but mainnet should not ship with two compilable PoW algorithms in one binary's source tree.

#### F-2 — Unsafe WASM ABI cast lacks safecast check (P2) ✅ FIXED (partial)

**Severity:** P2 — dívida pós-mainnet (WASM-only path; not exercised by mainnet node).
**Found:** Session 1, 2026-05-14.
**Status:** ✅ **null-pointer reject added in commit `cd53691` (Session 3, 2026-05-14).** Full type-id check intentionally deferred — wasm-bindgen does not expose `try_from_abi` for arbitrary user types; emulating the type-id check would require reimplementing wasm-bindgen's internal reference-table bookkeeping. The null-pointer guard closes the most likely accidental-use-after-free trigger (caller passes a moved-from or un-initialized JS handle). A SAFETY comment documents the residual contract.

**Verification:** `cargo check -p sophis-addresses` exit 0 after fix. Wasm32 builds will exercise the new path; native node/miner/RPC unaffected.

#### F-3 — `sVM Capability` enum has 3 variants not enumerated in project CLAUDE.md (documentation drift only — no code finding) ✅ FIXED

**Severity:** doc-drift (not a code finding).
**Found:** Session 1, 2026-05-14.
**Status:** ✅ **fixed in Session 3, 2026-05-14** — `G:\Meu Drive\Claude\Sophis\CLAUDE.md` updated to list all 11 variants (including `ResolveAlt`, `EmitEvent`, `VrfRandomness`) with their roadmap-item references and the canonical source path `svm/core/src/capability.rs`. The repo `C:\Projetos\sophis\CLAUDE.md` was already correct (line 264).

#### F-4 — `MAX_SCRIPT_PUBLIC_KEY_VERSION` documentation drift (Phase 6 carrier bump) ✅ VERIFIED

**Severity:** doc-drift.
**Found:** Session 1, 2026-05-14.
**Status:** ✅ **verified in code (Session 3).** Action item: update CLAUDE.md at audit closure.

**Code reality (verified by direct grep):**
- `consensus/core/src/constants.rs:30` defines `pub const MAX_SCRIPT_PUBLIC_KEY_VERSION: u16 = 5` (this is the L1 consensus value — what `ScriptPublicKey.version` is allowed to be on-chain).
- `crypto/txscript/src/lib.rs:59` defines a *separate* `pub const MAX_SCRIPT_PUBLIC_KEY_VERSION: u16 = 0` (this is the version the txscript *engine* knows how to execute; higher versions get the "anyone-can-spend" treatment until activated, à la Bitcoin segwit reserved versions).
- The two constants are documented as intentionally distinct in `crypto/txscript/src/lib.rs:45-59`: *"**Not** the same as `sophis_consensus_core::constants::MAX_SCRIPT_PUBLIC_KEY_VERSION`"*.

**Conclusion:** Code is correct. CLAUDE.md text — *"MAX_SCRIPT_PUBLIC_KEY_VERSION | 2 (puro — sem versions de bridge externa)"* — is **stale on two counts**:
1. The numeric value is **5**, not 2 (bumped in Phase 6 sub-fase 6.1, with v=3,4 reserved for legacy rollup-bridge versions per project memory `project_phase6_subfase_6_1_v5_carrier.md`).
2. The "puro — sem versions de bridge externa" comment dates back to before Phase 6's V5 DA carrier landed and is no longer accurate.

**Recommended fix** (at audit closure): update the `§"Parâmetros da rede"` table in CLAUDE.md.

**Status:** ✅ **fixed in Session 3, 2026-05-14** — `G:\Meu Drive\Claude\Sophis\CLAUDE.md` line 125 updated with the corrected value (`5`), v=1..5 semantics, and a footnote clarifying that the txscript engine pins its own `MAX_SCRIPT_PUBLIC_KEY_VERSION = 0` intentionally. The repo `C:\Projetos\sophis\CLAUDE.md` does not contain the stale line.

---

## 1.8 Session 1 — closing summary

**Status:** Session 1 of 7 — **structural baseline complete**, test-suite verification pending.

### What's done

- Workspace inventoried (75 crates, 986 files, 178,745 LOC, 1,897 test attributes, 54 unsafe).
- `audit/AUDIT_REPORT.md` created with full Tier 0/1/2/3 structure for Sessions 2-final.
- 7 audit tasks created in the task list.
- `cargo check --workspace --exclude sophis-rollup-host --exclude rollup-node` → ✅ **exit 0 in 1m00s, 99 crates clean, zero warnings**. Windows MSVC risc0 limitation documented (canonical build = Linux Docker, per project memory).
- **9 invariants visually confirmed clean** (devfund eliminated, coinbase 100% miner, no FHE/privacy, no Schnorr/secp256k1 in code, sVM Capability has no `VerifySchnorr`, L1 ALT constants frozen + tested, J4 Events constants frozen + tested, anti-long-range-attack two layers wired, `min_chain_work = ZERO` per network as documented).
- **4 findings filed**: F-1 (P1 PoW compile-time switch), F-2 (P2 WASM ABI), F-3/F-4 (doc drift).

### What's still running

- `cargo test --workspace --exclude sophis-rollup-host --exclude rollup-node --no-fail-fast` (background; was still compiling test binaries at end of Session 1).
  - When complete, this will populate the actual pass/fail count vs the 1,897 attribute target.
  - Tier 2 svm-zk / risc0 tests must be re-run on Linux Docker — separate session.

### Plan for Session 2

Per the per-task dependencies set up:

1. **First**: confirm test-suite result from Session 1's background run (capture in §1.5).
2. Install `cargo-llvm-cov` if missing.
3. Generate workspace coverage → `audit/COVERAGE_MAP.md`.
4. List `pub fn` functions with 0% line coverage, grouped by Tier.
5. Identify which crates have *no* test attributes at all (per §1.2 file-count gap).
6. Save crate-by-crate coverage table back into AUDIT_REPORT.md as §2.0 "Coverage baseline".

### Estimate vs. user's 1-2 week multi-session window

- Session 1: **done in this turn** (baseline + first 4 findings).
- Sessions 2: ~1 turn (coverage map).
- Sessions 3-5: ~3 turns (Tier 0 — biggest crate-by-crate effort).
- Sessions 6-7: ~2 turns (Tier 1).
- Sessions 8-9: ~2 turns (Tier 2 — needs Linux Docker setup).
- Session 10 + final: ~2 turns (Tier 3 + verdict).

Total: ~11 working sessions. Fits comfortably in 1-2 weeks.

---

### 1.6 Cross-cutting risk markers (raw, to be analyzed in later sessions)

| Risk marker | Count | Audit action |
|---|---|---|
| `unsafe` blocks/fns/impls | 54 in 27 files | List each in Tier 1+2; require comment justifying soundness |
| `.unwrap()` / `.expect(` / `panic!` / `todo!` / `unimplemented!` / `unreachable!` | very large (21KB+ output) | Restrict to Tier 0 paths; every consensus-side panic must be unreachable-in-practice OR justified by a layer above |
| Test-attribute-bearing files | 282 of 986 | Crates without any test attributes are P1 (no internal unit tests) |

---

## 2.0 Coverage baseline (Session 2, 2026-05-14)

Generated with `cargo llvm-cov --workspace --exclude sophis-rollup-host --exclude rollup-node --no-fail-fast --summary-only` (source-based instrumentation, LLVM 22 / `cargo-llvm-cov 0.8.7`). Full per-file table in `audit/coverage_full.txt` (700 lines).

### Workspace totals

- **Regions:** 66.08% (107,808/163,158)
- **Functions:** 59.94% (7,245/12,087) — **~40% of functions have zero coverage**
- **Lines:** 65.88% (60,025/91,116)
- **Branches:** unsupported by `cargo-llvm-cov 0.8.7` on this LLVM build (column reports `-`).

### By Tier

| Tier | Files | Lines covered | Functions covered | Regions covered | Zero-pct files | Sub-50% files |
|---|---|---|---|---|---|---|
| **T0** — Consensus-critical | 153 | **77.33%** (19,277/24,927) | **68.20%** (2,052/3,009) | 77.10% (33,509/43,461) | 19 | 10 |
| **T1** — Operational security | 256 | **55.70%** (14,483/26,003) | **51.33%** (2,119/4,128) | 54.28% (25,309/46,631) | 76 | 40 |
| **T2** — ZK plumbing | 125 | **84.87%** (17,929/21,125) | **74.04%** (1,842/2,488) | 86.93% (34,980/40,238) | 6 | 7 |
| **T3** — UX/infra | 162 | 43.73% (8,336/19,061) | 50.04% (1,232/2,462) | 42.68% (14,010/32,828) | 52 | 28 |

**Reading.** T2 (ZK plumbing — Phase 3/5/6/9) is the best-tested category, reflecting the FIPS/RFC-grade witness validation and oracle-host AIR test density (~50 chips × multiple tests each). T0 (consensus) is the next-strongest at 77% lines, but has critical zero-pct files (F-5, F-6, F-7 below). T1 (operational) has the largest gap by absolute lines missed (11,520 lines uncovered) — protocol flow handlers and IBD code dominate. T3 low coverage is expected for binaries (faucet, explorer, dashboard, calculator, da-stress all have `main.rs` at 0% — these are exercised by smoke/manual testing, not unit tests).

### Tier 0 zero-coverage files (19 total)

| File | Lines | Fns | Verdict |
|---|---|---|---|
| `consensus/core/src/sign.rs` | 22 | 1 | 🚨 **F-5 below — P0/P1** — canonical Dilithium signing fn, 9 call sites across 5 binaries, **zero direct test** |
| `consensus/src/processes/pruning_proof/validate.rs` | 251 | 17 | 🚨 **F-6 below — P0/P1** — IBD pruning-proof validator, consensus-anti-fork-critical |
| `consensus/src/processes/pruning_proof/apply.rs` | 137 | 10 | 🚨 **F-7 below — P1** — applies pruning proof during IBD |
| `consensus/core/src/api/mod.rs` | 227 | 90 | 🟡 trait definitions; methods tested through implementations — likely OK in audit, confirm Tier 0 |
| `consensus/client/src/transaction.rs` | 323 | 62 | 🟡 RPC/wallet wrapper; tested at call-site (RPC integration) — confirm Tier 1 |
| `consensus/client/src/utxo.rs` | 236 | 61 | 🟡 same |
| `consensus/client/src/serializable/{numeric,string}.rs` | 210+209 | 24+24 | 🟡 same |
| `consensus/client/src/{input,output,outpoint,error}.rs` | 115+52+74+29 | 27+15+17+9 | 🟡 same |
| `consensus/core/src/errors/block.rs` | 13 | 5 | 🟢 error variants; covered indirectly via fail-path tests |
| `consensus/core/src/{pruning,trusted}.rs` | 3+9 | 1+3 | 🟢 tiny, low risk |
| `consensus/src/processes/utils.rs` | 9 | 3 | 🟢 small helpers |
| `consensus/wasm/src/error.rs` | 23 | 7 | 🟢 wasm error variants |
| `crypto/addresses/src/wasm.rs` | 45 | 13 | 🟡 WASM bindings (F-2 lives here) |
| `crypto/txscript/src/error.rs` | 29 | 9 | 🟢 error variants |

### Tier 1 zero-coverage hot list (top 10 by line count)

These cluster heavily on protocol flows and binary mains:

```
protocol/flows/src/ibd/flow.rs                       611 lines, 61 fns — F-8
dilithium-wallet/src/main.rs                        1142 lines, 72 fns — F-9 (binary; integration test)
protocol/flows/src/v7/blockrelay/flow.rs             199 lines, 23 fns — F-8
miner/src/main.rs                                    250 lines,  8 fns — binary; integration test
protocol/flows/src/v8/mod.rs                         130 lines,  2 fns
protocol/flows/src/v7/mod.rs                         124 lines,  2 fns
protocol/flows/src/ibd/streams.rs                     91 lines, 12 fns — F-8
protocol/flows/src/ibd/negotiate.rs                  115 lines,  6 fns — F-8
protocol/flows/src/v7/{request_*}.rs (10 files)     ~280 lines total
protocol/flows/src/v7/{ping,address}.rs              ~84 lines total
```

Detailed audit per-file deferred to Tier 1 sessions (6-7). Filed two collected findings here:
- **F-8 (P1)**: zero direct test coverage on Initial Block Download flow + v7 message handlers. IBD security is critical — a bug here lets an adversary stall or corrupt new-node sync.
- **F-9 (P2)**: CLI binaries (`dilithium-wallet`, `miner`) have 1,142 + 250 lines of `main.rs` code with zero direct unit tests. Acceptable if devnet integration tests exercise the user-visible code paths — to confirm in Tier 1.

### Session 2 findings — Tier 0 / Tier 1

#### F-5 — `sign_input_dilithium` has 0% direct test coverage (P0) ✅ FIXED

**Severity:** P0 — must fix before testnet (founder ratified Session 2, 2026-05-14).
**Found:** Session 2, 2026-05-14.
**Status:** ✅ **fixed in commit `1dcbbad` (Session 3, 2026-05-14)**. Added a `#[cfg(test)] mod tests` block in `consensus/core/src/sign.rs:60-188` with three unit tests:

1. **`test_sign_input_dilithium_round_trip`** — sign a single-input populated tx, verify the 2420-byte signature against the same sighash via `libcrux_ml_dsa::ml_dsa_44::verify`. Closes the sighash-binding / script-encoding bug class.
2. **`test_sign_input_dilithium_sighash_type_binding`** — sign with `SIG_HASH_ALL`, `SIG_HASH_NONE`, `SIG_HASH_SINGLE`; assert the three signatures differ pairwise and that the trailing hash-type byte echoes the requested variant. Closes the "signer ignores SigHashType" bug class.
3. **`test_sign_input_dilithium_randomness_nondeterminism`** — sign the same input twice with the same key; assert signatures differ (ML-DSA is hedged). Pins `libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE == 32` so a future libcrux upgrade changing the constant fails this test rather than the production signer. Closes the "randomness slice mis-sized" bug class.

Verification: `cargo test -p sophis-consensus-core sign::` → **3 passed, 0 failed, 0 ignored**.

The tests reuse the same `PopulatedTransaction` / `Transaction` patterns as `consensus/core/src/hashing/sighash.rs::test_signature_hash`, so future sighash refactors will surface here as well.

**Description.** `consensus/core/src/sign.rs:30-58` defines `sign_input_dilithium`, the canonical function that:
1. Computes the sighash via `calc_signature_hash(tx, input_index, hash_type, &reused_values)`.
2. Loads the 2560-byte Dilithium-2 (ML-DSA-44) signing key into `MLDSA44SigningKey`.
3. Draws 32 bytes of `getrandom::getrandom` for ML-DSA randomness.
4. Calls `ml_dsa_44::sign(&sk, message, b"", randomness)`.
5. Builds the P2SH input script: `[0x4d, sig_len_lo, sig_len_hi, sig_bytes ‖ hash_type_byte]`.

`cargo-llvm-cov` shows **0/22 line coverage, 0/1 function coverage**. The function is called from **9 sites** in 5 binaries (`dilithium-wallet`, `tools/sophis-da-stress`, `testnet-faucet`, `oracle/relayer`, `rollup/sequencer`), and there is no `#[test]` in `consensus/core/src/sign.rs` itself or in any sibling test module that invokes it.

**Why this matters.**
- A bug in sighash binding silently invalidates every signed transaction (caller side) or accepts forged ones (verifier side). The verifier path *is* tested (via opcode `0xc4` Dilithium opcode tests in `txscript`), but the signer is not.
- The randomness sourcing (line 42-45) reads from `getrandom`. A bug that mis-sizes the slice or leaks the secret-key bytes through randomness would be invisible to a happy-path integration test that simply sends and confirms a tx.
- The script encoding (lines 50-56) hand-writes the OP_PUSHDATA2 prefix. A wrong endianness or a 1-byte slip silently produces an unspendable output that the signer cannot tell apart from a normal one.

**P0-vs-P1 rationale.**
- P0 view: this is consensus-critical code with zero test. Testnet should not launch without a round-trip vector.
- P1 view: the verifier side has exhaustive tests (libcrux ML-DSA-44 ships its own NIST-KAT verification) and integration via the rothschild-style traffic generator on devnet implicitly exercises the path. So a *catastrophic* bug would surface in the first 24 hours of testnet via "all txs rejected" symptoms.

**Recommended fix (minimum):** add three unit tests in `consensus/core/src/sign.rs#[cfg(test)]`:
1. **Round-trip** — generate a Dilithium keypair, sign a single-input tx, run the signature through the `txscript` Dilithium opcode verifier (or `libcrux_ml_dsa::ml_dsa_44::verify`), assert it accepts.
2. **SigHashType variation** — sign the same tx with each of the documented SigHashType variants, assert signatures differ.
3. **Determinism / randomness probe** — sign the same tx twice with the same key, assert signatures differ (because randomness is sampled). Bind explicitly to `libcrux::ml_dsa::SIGNING_RANDOMNESS_SIZE` so a future libcrux upgrade that changes the constant fails the test rather than the code.

#### F-6 — `pruning_proof/validate.rs` has 0% test coverage (P1)

**Severity:** P1 — must fix before mainnet (testnet-tolerable).
**Found:** Session 2, 2026-05-14.
**Status:** open, deeper analysis Session 3.

**Description.** `consensus/src/processes/pruning_proof/validate.rs` (251 lines, 17 fns) validates incoming pruning-point proofs during Initial Block Download. **Zero direct test coverage.** Workspace-wide grep confirms zero matches for the symbol in `testing/integration/**/*.rs` — no integration test exercises this path either.

The pruning-proof verifier is the gating mechanism for new nodes joining the network. An adversary peer that sneaks a malformed proof past it can fork a fresh node away from the canonical chain.

**Session 3 deeper finding.** This is *not* a simple unit-test gap. The function `validate_pruning_point_proof` takes a `&PruningPointProof` and `&PruningProofMetadata` and reads from 12+ RocksDB stores (`DbHeadersStore`, `DbGhostdagStore`, `DbReachabilityStore`, `DbRelationsStore`, …). The only way to produce a *valid* `PruningPointProof` is to:

1. Stand up a `TestConsensus` instance.
2. Mine a synthetic DAG of depth ≥ `pruning_depth` (which is a function of `finality_depth`; on the production 10-BPS network this is ≥ hundreds of thousands of blocks).
3. Trigger pruning so `build_pruning_point_proof` produces a proof.
4. Call `validate_pruning_point_proof` on that proof and assert OK.
5. Mutate the proof to hit each of 31 `PruningImportError` variants + 2 `ProofWeakness` variants.

Steps 2-3 are an integration-test scale of work. Existing helpers exist (`TestConsensus::add_header_only_block_with_parents`, `TestBlockBuilder::build_block_template_with_parents`) but no test currently builds a DAG anywhere near pruning depth.

**Recommended action (out of scope for Session 3):**

1. **Session 4 (dedicated)** — research the minimum DAG depth that produces a coherent pruning proof. **Session 3 follow-up:** `pruning_depth` is computed as `finality_depth + 2·merge_depth + 4·mergeset_size_limit·k + 2k + 2` (`consensus/core/src/config/bps.rs:96-107`). With the structural floors enforced by `Bps<BPS>` (`mergeset_size_limit ≥ 180`, `ghostdag_k ≥ 18` for BPS=1), the minimum coherent `pruning_depth` is approximately **13,094 blocks** even on BPS=1 — *not* the "≈ 32" originally floated. A useful integration test therefore needs either:
   - A multi-thousand-block synthetic DAG (slow but viable), or
   - Constants overrides at the workspace level (touching `bps.rs` floors, which has cross-cutting impact and would itself need a regression suite).

2. Once a tractable harness exists, add `consensus/src/processes/pruning_proof/tests.rs` with:
   - `test_validate_pruning_proof_round_trip` — happy path: build a proof on the synthetic DAG, validate it, assert OK.
   - `test_validate_pruning_proof_rejects_*` for each `PruningImportError` variant (31 variants → at least cover the 2 `ProofWeakness` variants first).
3. Coverage should reach ≥80% on `validate.rs` after.

**Pre-mainnet:** P1 gate. **Pre-testnet:** documented gap; testnet will exercise the path under real IBD with hundreds of joining nodes, which is itself a useful (if non-deterministic) test.

A scaffold `#[ignore]`d test has not been added to the codebase to avoid lying-about-coverage; this finding is the authoritative record. Estimate revised to **4-8 hours / dedicated session**, not the originally stated 2-3h.

#### F-7 — `pruning_proof/apply.rs` has 0% test coverage (P1)

**Severity:** P1 — must fix before mainnet (testnet-tolerable).
**Found:** Session 2, 2026-05-14.
**Status:** open, deeper analysis Session 3.

**Description.** `consensus/src/processes/pruning_proof/apply.rs` (137 lines, 10 fns) commits a validated pruning proof to local state during IBD. Sister to F-6.

**Session 3 deeper finding.** Same integration-harness constraint as F-6. Once F-6's tiny-pruning-params machinery exists, `apply.rs` becomes testable by the same harness: call `validate_pruning_point_proof` then `apply_proof` on the same proof and assert the resulting state matches expectations.

**Recommended action:** bundled with F-6's Session 4 work.

#### F-8 — IBD + v7 message handlers have 0% coverage (P1)

**Severity:** P1 — must fix before mainnet (testnet-tolerable with manual smoke).
**Found:** Session 2, 2026-05-14.
**Status:** open.

**Description.** `protocol/flows/src/ibd/{flow,negotiate,progress,streams}.rs` totals 858 lines / 82 fns, all 0%. The v7 family (`v7/{blockrelay,ping,address,request_*,*}`) adds another ~1,200 lines / 130 fns. These are the message handlers that govern how a fresh node syncs from peers. Bugs here typically manifest as IBD stalls or partial syncs — caught by devnet integration testing but not by unit tests.

**Action.** Tier 1 audit (Sessions 6-7) must inventory the v7 / v8 protocol surface, identify which messages have *no* integration test exercising them on devnet, and either add coverage or document the risk.

#### F-9 — CLI binary `main.rs` has 0% coverage (P2)

**Severity:** P2 — post-mainnet technical debt.
**Found:** Session 2, 2026-05-14.

**Description.** Several `*/src/main.rs` are 0% covered (most by-design):
- `dilithium-wallet/src/main.rs` — 1142 lines, 72 fns
- `miner/src/main.rs` — 250 lines, 8 fns
- `testnet-faucet/src/main.rs` — 0%
- `sophis-explorer/src/main.rs` — 0%
- `tools/sophis-*/src/main.rs` — 0%

These are end-user CLI binaries. Integration / smoke tests on devnet implicitly exercise them but no automated assertion holds. Acceptable for testnet; tightening requires either extracting logic into a `lib.rs` testable surface or building a CLI smoke-test harness.

---

## 2. Tier 0 — Consensus-critical (Sessions 3-5)

> ⏳ Pending. To be populated function-by-function with: signature, callers, invariants, panic paths, test coverage, audit verdict (OK / finding).

### 2.1 `consensus/core`

#### `consensus/core/src/config/params.rs`
- Founder-mode invariants: no `devfund_address`, no devfund schedule (Decisão 2 — devfund eliminado 2026-05-04, commit `cffe1d1`). **Pre-audit confirmation required.**

#### `consensus/core/src/coinbase.rs`
- Founder-mode invariants: coinbase split = 100% to miner. **Pre-audit confirmation required.**

#### `consensus/core/src/{alt,da,events,commitment}/`
- ABI-frozen constants per project CLAUDE.md §"Constants ABI-frozen". **Each constant traced and tested.**

(Section will expand per-file in Sessions 3-5.)

### 2.2 `consensus` (pipeline)
### 2.3 `consensus/pow`
### 2.4 `crypto/*`

---

## 3. Tier 1 — Operational security (Sessions 6-7)

### 3.1 `svm/*` — sVM stack audit (Session 3 continuation, 2026-05-14)

Audited files: `svm/host/src/lib.rs`, `svm/runtime/src/{validator,host,context}.rs`, `svm/lint/src/*`, `consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs::validate_contract_deploy`.

**Verdict per file:**

| File | Verdict | Notes |
|---|---|---|
| `svm/host/src/lib.rs` | ✅ STRONG | All 4 host crypto methods (`verify_dilithium`, `sha3_384`, `verify_risc0_proof`, `verify_plonky3_proof`) correctly wired. `cfg(not(feature = "risc0"))` and `cfg(not(feature = "plonky3"))` branches explicitly *log + panic* rather than return `false` — prevents silent consensus fork between feature-on and feature-off nodes. Documented rationale in lines 38-58 and 65-82. |
| `svm/runtime/src/validator.rs` | ✅ STRONG | 7 security layers confirmed: float scalar (f32/f64), float SIMD (F32x4/F64x2 NaN payload divergence), atomics/threads, shared-memory imports, unbounded memory, memory > 256 pages (16 MiB), bytecode size limit. Single entry point `validate_bytecode`; 16 unit tests per coverage data. |
| `svm/runtime/src/host.rs` | ✅ STRONG | All 11 host fns gated with `check_capability(&Capability::X)` at function entry, returning a specific error code on missing capability: 0 for read paths, -1 for VRF/Alt/Event, -2 for DA. Coverage: see F-10 below for the residual "return-vs-trap" doc drift. |
| `svm/runtime/src/context.rs` | ✅ STRONG | `check_capability` is a direct delegate to `manifest.has_capability(cap)`; correct.`ExecutionContext::new` defaults backends to safe stubs (`StubDa`, `StubAlt`, `StubVrf`) that are replaced by real backends only when consensus transaction validator wires them. |
| `svm/lint/src/*` | ⚠️ GAP (see F-10) | Only 3 lints: `no_float`, `no_unchecked_arith`, `no_unsafe`. No lint enforces that the contract's `required_capabilities` matches the host fns it imports from `env::*`. |
| `consensus/.../validate_contract_deploy` | ⚠️ GAP (see F-10) | Validates WASM bytecode (calls `validate_bytecode`), `contract_id == hash(wasm)`, and `upgrade_policy.is_valid()`. **Does not** post-validate that the contract's WASM `ImportSection` (from the `"env"` module) is consistent with the manifest's `required_capabilities`. |

#### F-10 — Manifest / WASM-imports consistency not enforced at deploy time (P2)

**Severity:** P2 — defense-in-depth gap, not a unilateral vulnerability.
**Found:** Session 3 continuation, 2026-05-14.
**Status:** open.

**Description.** A contract declares `required_capabilities` in its `ContractManifest`. The runtime calls `check_capability` at every host-fn entry and returns a specific error code (0 / -1 / -2) if the capability is missing. The runtime does **not** trap, despite CLAUDE.md saying *"Wasmtime traps immediately if the contract calls a host function not listed in its ContractManifest.required_capabilities."* (`C:\Projetos\sophis\CLAUDE.md` original line.) Behavior is correct (graceful error) but diverges from doc.

The deeper concern is that **no layer enforces consistency between the WASM's `(import "env" "verify_dilithium")` (et al.) and the manifest's `required_capabilities` array**:
- `svm/lint/src/*` has rules for floats / unchecked arith / unsafe but not for imports-vs-capabilities.
- `validate_contract_deploy` checks WASM bytecode + contract_id + upgrade_policy but not imports-vs-manifest.
- Runtime `check_capability` is the only line of defense, returning an error code.

**Attack model.** Self-harm only — a contract author who declares `required_capabilities = []` and then writes `let ok = env::verify_dilithium(...); /* ignore */ release_funds(...)` has shot their own foot, but only their own. **No cross-contract / cross-tx attack** is enabled because the runtime check still fires and the host fn still returns 0. There is no privilege escalation.

The real-world risk is third-party contract libraries that internally call `env::*` host fns: if a library is imported into a parent contract that doesn't declare the necessary capability, the parent silently gets a failure return without any deploy-time signal.

**Recommended mitigation (any of, P2 priority):**
1. **Deploy-time check:** in `validate_contract_deploy`, walk the WASM `ImportSection` for `"env"` namespace, map each imported fn to its `Capability` (the registration in `host.rs` is the canonical map), and reject the deploy if any imported host fn maps to a `Capability` not in `manifest.required_capabilities`. Strongest mitigation.
2. **Static lint:** add an `svm-lint` rule that inspects the contract's `#[sophis_contract]` macro expansion and confirms the manifest enumerates every capability used at the source level. Catches it at `cargo dylint` time.
3. **Doc fix only:** update CLAUDE.md to say "returns an error code (graceful) rather than traps". Acceptable as a near-term placeholder, but does not eliminate the silent-failure third-party-library risk.

**Why P2 not P1:** there is no cross-contract attack and no consensus-fork risk. The capability check is enforced; the gap is operator-side / library-side. Acceptable for testnet (which has no production-grade third-party WASM ecosystem yet); should be fixed before mainnet enables a contract-developer flywheel.

### 3.2 `svm/sdk` + `svm/sdk-macros` (Session 3 continuation, 2026-05-14)

**Verdict per file:**

| File | Verdict | Notes |
|---|---|---|
| `svm/sdk-macros/src/lib.rs` | ✅ STRONG | `#[sophis_contract]` attribute macro walks the AST and rejects (a) `unsafe fn` on the outer signature, (b) `unsafe` blocks, (c) `unsafe fn` declarations inside, (d) float literals, (e) unchecked arithmetic operators (`+ - * / %`). Generates the `extern "C" fn validate() -> i32` entry point with the user's fn renamed to `__sophis_inner_<name>`. **The macro does *not* generate `ContractManifest::required_capabilities`** — that's separately declared by the deployer in the deploy tx payload. This is the structural origin of F-10. |
| `svm/sdk/src/env.rs` | ⚠️ GAP (see F-11) | Declares 9 of the 11 host functions actually registered by `svm/runtime/src/host.rs`. **Missing from the SDK surface:** `sophis_alt_lookup` (Capability::ResolveAlt) and `sophis_verify_da` (Capability::VerifyDataAvailability). |

#### F-11 — SDK surface incomplete: ALT and DA host fns not exposed (P2)

**Severity:** P2 — ergonomics gap, not a security vulnerability.
**Found:** Session 3 continuation, 2026-05-14.
**Status:** open.

**Description.** `svm/sdk/src/env.rs` declares the extern "C" shims that contract authors call via `env.verify_dilithium(...)`, `env.sha3_384(...)`, etc. The grep for `sophis_alt_lookup` and `sophis_verify_da` (or `alt_lookup` / `verify_da`) in the file returns **zero matches**, yet both are real host functions registered in `svm/runtime/src/host.rs` and have corresponding `Capability::ResolveAlt` and `Capability::VerifyDataAvailability` variants.

Contracts that need to resolve L1 ALT references (e.g., a multisig contract spending v=1 transactions) or check Phase 6 DA presence (e.g., the rollup withdrawal contract, oracle aggregator) must therefore:
1. Declare their own `extern "C" { fn sophis_alt_lookup(...) -> i32; }` block.
2. Write their own unsafe FFI shim.
3. Wire the call manually.

**Why P2 not P1:** the runtime side is fully functional (host fns work). The capability check still fires (Capability::ResolveAlt / VerifyDataAvailability would still be in the manifest). The only impact is contract-author ergonomics + a higher barrier for third-party contract development.

**Recommended fix.** Add to `svm/sdk/src/env.rs`:
- `pub fn alt_lookup(&self, handle: &[u8; 6], index: u8) -> Option<Vec<u8>>` calling `sophis_alt_lookup`.
- `pub fn verify_da(&self, hash: &[u8; 48], min_confirmations: u32, query_kind: u8) -> Result<DaPresence, DaError>` calling `sophis_verify_da`.

Mirror the existing `verify_dilithium` / `emit_event` shim style. Update `svm/sdk` semantic version to signal new SDK surface to downstream consumers.

### 3.3 `mining` + `miner` (donate flag) — Session 3 continuation, 2026-05-14

| File | Verdict | Notes |
|---|---|---|
| `miner/src/donate.rs` | ✅ STRONG | `MAX_DONATION_OUTPUTS = 8` cap; `parse_donations` enforces length match + cap + percent sum ≤ 100 (u32 to safely catch overflow) + prefix match across all entries; `compute_split` uses u128 arithmetic to prevent overflow during `total_value * pct / 100`, `saturating_sub` prevents underflow, rounding remainder always accrues to miner; `rewrite_coinbase_outputs` preserves miner output at index 0 (tooling compatibility); 18 unit tests per coverage map. **Aligned with Operational Boundaries Statement** — no core-team curated NGO list, opt-in client-side. |

### 3.4 `wallet/typed-data` (J2 typed signing) — Session 3 continuation, 2026-05-14

| File | Verdict | Notes |
|---|---|---|
| `wallet/typed-data/src/digest.rs` | ✅ STRONG | `TYPED_SIGNING_PREFIX = [0x73, 0x01]` ABI-frozen with explicit test (`prefix_bytes_are_frozen_abi`); `compute_typed_digest = SHA3-384(prefix \|\| domain_separator \|\| struct_hash)` truncated to 32 bytes; deterministic schema lookup. Mirrors EIP-712 structure with Sophis-native primitives. 35 tests per CLAUDE.md. |

### 3.5 RPC stack (auth + bind defaults) — Session 3 continuation, 2026-05-14

| File | Verdict | Notes |
|---|---|---|
| `rpc/wrpc/server/src/service.rs` | ✅ STRONG | Default `listen_address: "127.0.0.1:47110"` — localhost-only by default, matches Bitcoin/Ethereum RPC security posture. `MAX_WRPC_MESSAGE_SIZE = 128 MB` caps incoming WS frames. **Minor:** lines 73-80 contain a commented-out `handshake::greeting(...)` block marked `TODO - discuss and implement handshake` — dead-code TODO since the operational posture is "no auth at RPC layer; operator runs reverse proxy with TLS/auth if exposing remotely". Recommend deleting the dead block (not a security issue, just clutter). |
| `sophisd/src/args.rs:171` | ✅ OK | `config.p2p_listen_address = ContextualNetAddress::unspecified()` defaults p2p to all interfaces (0.0.0.0), which is correct — a p2p node must accept incoming peer connections. |

### 3.6 Protocol flows + peer banning (F-8 area) — Session 3 continuation, 2026-05-14

| File | Verdict | Notes |
|---|---|---|
| `protocol/flows/src/ibd/flow.rs` | ⚠️ TODO-noisy | The IBD flow correctly disconnects peers on misbehavior at 8+ call sites (`streams.rs:166`, `flow.rs:293/308/418/582/640/725/896`). But line 79 carries the bare TODO *"define a peer banning strategy"* and lines 293, 308, 418 say *"consider performing additional actions on finality conflicts in addition to disconnecting from the peer (e.g., banning, rpc notification)"*. **The mechanism exists** (`components/addressmanager/src/stores/banned_address_store.rs` implements `BannedAddressesStore` with `set/get/remove` keyed by IPv6-mapped address and a `ConnectionBanTimestamp`). What's missing is the *policy* — how a misbehaving peer transitions from "disconnect once" to "added to the ban store". See F-12 below. |
| `components/addressmanager/src/stores/banned_address_store.rs` | ✅ STRONG | Store implementation is clean: IPv4→IPv6-mapped key (16 bytes), per-IP ConnectionBanTimestamp, `set/get/remove` semantics. Ready for callers. |

#### F-12 — Peer banning strategy not defined (P2)

**Severity:** P2 — testnet-tolerable; pre-mainnet hardening recommended.
**Found:** Session 3 continuation, 2026-05-14.
**Status:** open.

**Description.** The peer-banning *mechanism* is fully implemented. The IBD + p2p flows correctly *disconnect* misbehaving peers at every adversarial decision point. **What's missing** is the *strategy* that promotes "disconnected" to "banned" — i.e., the per-IP score that tracks repeated misbehavior across reconnections and writes to the ban store after a threshold.

Without this strategy, a malicious peer:
1. Connects to a node.
2. Submits invalid IBD message → gets disconnected.
3. Immediately reconnects.
4. Repeats.

Each individual disconnect is correct, but the aggregate behavior is "infinite retries with no cost". CPU/memory cost per disconnect is small, but it's a DoS-amplification surface.

**Recommended mitigation.** Define a peer-score policy at the `protocol/flows` or `protocol/p2p` layer:
- Per-IP score, decay with time, increment on disconnect cause.
- Threshold → write to `BannedAddressesStore` with a ban duration (e.g., 24h initial, exponential backoff on repeat).
- Connection accept hook reads the store before handshake; reject banned IPs.

This is a Bitcoin Core-style policy; the Kaspa upstream may have had a partial implementation that the Sophis fork preserved but did not finish wiring.

### 3.7 `dilithium-wallet` + `wallet/{bip39,pskt,descriptors,filters,spv}` — to audit

⏳ pending: wallet CLI binary (1,142 lines main.rs, F-9), BIP-39 mnemonic, PSKT (partially-signed transaction), descriptors (BIP-380-equivalent), compact filters, SPV light client.

### 3.8 Anti-long-range-attack confirmed Session 1 §1.6 — no further action.

---

## 4. Tier 2 — ZK plumbing (Sessions 8-9)

> ⏳ Pending.

### 4.1 Phase 3 rollup
### 4.2 Phase 5 oracle (DEPRECATED — confirm gate of removal)
### 4.3 Phase 6 DA (consensus/core/src/da + tools/sophis-da-stress)
### 4.4 Phase 9 PQC oracle

---

## 5. Tier 3 — UX/infra (Session 10)

> ⏳ Pending.

### 5.1 Cross-cutting sweep
- `cargo clippy` under each feature combination
- Fuzz target inventory (`math/fuzz`, `crypto/muhash/fuzz`)
- Kani harness coverage (`svm/kani-proofs`)
- `unsafe` block-by-block audit

---

## 6. Verdict (Session final)

> ⏳ Pending. Will deliver: APPROVED / REJECTED for testnet, with numbered gate list.

---

## Appendix A — Audit ledger

| Session | Date | Tier/area | Findings P0/P1/P2 | Status |
|---|---|---|---|---|
| 1 | 2026-05-14 | Baseline + inventory | TBD | 🚧 in progress |
| 2 | TBD | Coverage map | — | ⏳ |
| 3-5 | TBD | Tier 0 | — | ⏳ |
| 6-7 | TBD | Tier 1 | — | ⏳ |
| 8-9 | TBD | Tier 2 | — | ⏳ |
| 10 | TBD | Tier 3 + sweep | — | ⏳ |
| final | TBD | Verdict | — | ⏳ |
