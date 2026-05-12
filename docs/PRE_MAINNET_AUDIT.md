# Pre-Mainnet Audit — Pre-Quantum Crypto Residuals + Dead Kaspa Code

**Status:** v1, drafted 2026-05-09. Audit deliverable for pending blockers
item #6. **This document lists findings only.** Removal/migration
decisions are tracked as individual follow-up tasks; this audit
determined what exists, not what to do about each item.

Methodology: ripgrep over the workspace for known marker strings
(`secp256k1`, `schnorr`, `ed25519`, `bls12`, `kHeavyHash`, `Kaspa`,
`OP_PRIVACY`, FHE vendor names). Results categorized by domain and by
recommended disposition.

---

## 1. Pre-quantum crypto references

Sophis' invariant is **Dilithium-only** for user-facing transaction
signatures. Pre-quantum primitives are permitted only in narrow,
well-defined contexts (e.g. verifying external attestations from
classical-crypto chains in the Phase 5 oracle). All other occurrences
are residuals to be reviewed.

### 1.1 `secp256k1` — 78 file matches

| Domain | Count est. | Disposition |
|---|---|---|
| `wallet/keys/`, `wallet/bip32/`, `wallet/core/` | majority | **Review** — wallet stack still embeds secp256k1 keypair derivation as a residual layer alongside Dilithium. CLAUDE.md notes the Cargo.toml dep is intentional but called residual. Decide per crate whether to remove the path or fence it behind a `#[cfg(feature = "secp256k1-residual")]` |
| `crypto/txscript/` | several | **Review** — opcode dispatch and signature verification paths likely have unused secp256k1 branches |
| `rothschild/` | several | **Justified residual** — CLAUDE.md confirms internal migration to Dilithium with secp256k1 retained for keypair derivation only. Either complete the migration or document the residual scope |
| `Cargo.toml` workspace dep | 1 | **Pin and justify** — add a comment explaining the residual scope, or remove entirely |
| `Cargo.toml` `[profile.dev.package.secp256k1]` opt-level entry | 1 | **Likely deletable** if dep is removed |
| Doc files (`HARD_FORK_POLICY.md`, `wallet/aa-spec/*.md`, `wallet/pskt/DESIGN.md`, `README.md`) | several | **Keep** — these are policy/design docs that name `secp256k1` as a rejected primitive. Documentation of what was excluded is itself valuable |
| `oracle/core/src/lib.rs` | 1 | **Verify context** — oracle core mentions secp256k1; if it is only a comment about not supporting it, fine |

### 1.2 `Schnorr` / `BIP-340` / `MuSig`

Documentation references only. No code path implements Schnorr signing
or verification. **No action required**; the doc references serve as
"this was rejected" markers (`HARD_FORK_POLICY.md` §7,
`wallet/aa-spec/CONVERGENCE.md`, `wallet/aa-spec/ANTI_PATTERNS.md`).

### 1.3 `ed25519` / `Curve25519` / `BLS12` / `Pasta` / `Groth16` — 60 file matches

| Domain | Disposition |
|---|---|
| `oracle/host/src/chips/ed25519/*`, `oracle/host/src/chips/field25519/*`, `oracle/host/src/chips/scalar25519/*` | **Justified** — Phase 5 oracle verifies ed25519 attestations from Pyth (a classical-crypto external feed). The verification AIR is the entire reason for these chips. Cannot be removed without losing oracle functionality |
| `oracle/host/src/{decompress,scalar_mul,verify_air}_stark*.rs` | **Justified** — STARK plumbing for the ed25519 verification AIR |
| `oracle/host/src/chips/sha512/mod.rs` | **Justified** — SHA-512 is part of ed25519 signature verification (ed25519 hash-to-scalar) |
| `oracle/feeds/src/pythnet.rs`, `oracle/feeds/src/rpc.rs`, `oracle/feeds/src/lib.rs` | **Justified** — Pythnet integration |
| `oracle/relayer/src/{config,pipeline}.rs` | **Justified** — Phase 5 relayer pipeline |
| `oracle/docs/*.md`, `SIPS/SIP-0-process.md`, `HARD_FORK_POLICY.md`, `docs/deferred-decisions.md` | **Keep** — documentation references |
| `oracle/host/src/chips/lookup/range_n.rs` | **Verify** — lookup module is generic; check for incidental ed25519 string |
| `wallet/aa-spec/ANTI_PATTERNS.md` | **Keep** — documents rejected zkLogin/OAuth pattern that uses ed25519 |
| `svm/host/src/plonky3.rs`, `svm/host/src/risc0.rs`, `svm/runtime/src/host.rs` | **Verify** — likely module-level mentions, not signature paths |

`BLS12` matches in `Cargo.lock` are transitive deps pulled by Plonky3
deps and similar; not reachable from Sophis consensus or transaction
paths. **Verify no direct workspace use.**

`Groth16` matches: similar transitive (risc0 stack); **verify**.

`Pasta` curves: search the matches; if any are direct-use (vs. doc),
those would be a finding. Doc-only is fine (reject markers).

### 1.4 BLS / `bls12_381` aside

CLAUDE.md and `project_chains_batch_2026_05_08.md` (memory) document
BLS12-381 as a hard-rejected anti-PQC primitive (used by ICP threshold
sigs, Ethereum sync committee). Sophis must not introduce BLS code
paths. The transitive presence in `Cargo.lock` is acceptable as long
as no Sophis crate imports a BLS API directly.

---

## 2. Dead / dormant Kaspa-inherited code

Sophis is built on the GHOSTDAG protocol foundation, originally
implemented in Kaspa's `rusty-kaspa`. Some Kaspa-specific elements
are dead in Sophis (different PoW, different supply, different
prefixes) but still present as code.

### 2.1 `kHeavyHash` — 9 file matches

| File | Action |
|---|---|
| `consensus/pow/src/matrix.rs` | **Likely deletable** — kHeavyHash matrix definition. Sophis uses RandomX. Verify no consensus path still references this matrix |
| `consensus/pow/src/lib.rs` | **Verify** — check if kHeavyHash is exported / referenced; if dead, prune |
| `consensus/pow/src/wasm.rs` | **Verify** — wasm binding for PoW |
| `consensus/pow/benches/bench.rs` | **Likely deletable** — benchmarks for an unused algorithm waste CI cycles |
| `crypto/hashes/src/pow_hashers.rs` | **Verify** — separate `kHeavyHash` impl; if not referenced, prune |
| `crypto/hashes/src/hashers.rs` | **Verify** — `Hasher` trait dispatch may still list a kHeavyHash variant |
| `crypto/hashes/benches/bench.rs` | **Likely deletable** — companion benchmarks |
| `consensus/core/src/config/genesis.rs` | **Verify** — genesis configuration may reference kHeavyHash for historical Kaspa testnet params; should be Sophis genesis only |
| `README.md` | **Update** — remove any kHeavyHash mention from the user-facing README |

**Recommendation:** schedule a focused PR that removes the kHeavyHash
algorithm implementation, the matrix, and the bench files. Trace each
remaining reference and either delete or replace with RandomX
equivalent. Risk: `consensus/pow` is the security-critical module —
test thoroughly, including devnet test suite.

### 2.2 Kaspa naming / branding residuals

| Item | Files | Disposition |
|---|---|---|
| `Kaspa` / `kaspad` / `kaspawallet` strings | docs and historical files | Most are in changelog-style or transition docs (`docs/testnet10-transition.md`, `docs/crescendo-guide.md` — these are historical). Keep as-is unless misleading |
| `rusty-sophis` repo URL in `Cargo.toml` `repository` field | 1 | **Update to `sophis-network/Sophis`** or whatever the canonical repo URL becomes |
| `sophisnet/rusty-sophis` issue links in `bridge/docs/README.md` | several | **Update** to `sophis-network/Sophis` |
| Test file names referencing "kaspa" | a few | **Verify and rename** if internal test names leak Kaspa identity |
| `rothschild` crate | whole crate | **Documented retention** — CLAUDE.md confirms migrated to Dilithium internally. Either complete the rename to a Sophis-themed name or document it in a code comment in `rothschild/src/main.rs` |

### 2.3 Phase 4 ZK-Bridge residuals

CLAUDE.md confirms Phase 4 was extracted to a separate, non-deploy
reference repository on 2026-05-04. The current Sophis workspace
should have **zero** references to:

- `bridge-eth-node` binary
- `WSPHS` token
- `BRIDGE_ETH_VERSION = 5` constant
- `BLS12-381 sync committee`
- `RiscZeroGroth16Verifier` outside the Phase 3 internal rollup context

**Action:** grep workspace for these terms. If any survive in `.rs`
files (vs. doc-only mentions), they are dead code.

`Cargo.toml` workspace comment block already documents the Phase 4
extraction — that comment is **not** a residual; it is correct
historical documentation.

### 2.4 FHE / privacy-stack residuals

CLAUDE.md confirms the 2026-05-05 FHE audit found "zero resíduos no
código (Cargo.toml/Cargo.lock/.rs limpos; só doc opt-out em README)".

**Action:** re-grep on the eve of mainnet for: `Zama`, `tfhe`,
`Concrete`, `Inco`, `OP_PRIVACY_ENABLE`, `op_privacy`, `confidential_tx`,
`ring_signature`, `stealth_address`. Expectation: zero matches in
`.rs` files, doc-only acceptable.

This audit confirms that finding for the current commit (zero
non-doc matches for `kHeavyHash` are the same pattern as zero
non-doc matches for FHE — a clean state).

### 2.5 `devfund_keygen` rename

CLAUDE.md confirms `devfund_keygen` was renamed to `wallet_keygen` on
2026-05-06. **Verify:** `miner/src/bin/devfund_keygen.rs` no longer
exists; no `[[bin]]` or `[[example]]` entry in `miner/Cargo.toml`
references the old name; binaries at `target/{debug,release}/` are
pruned in CI.

---

## 3. Other residual sweeps

### 3.1 Workspace `repository` URL

`Cargo.toml` line 109: `repository = "https://github.com/sophisnet/rusty-sophis"`.
The canonical public repo is moving to `sophis-network/Sophis` per
the pseudonym decision (`project_pseudonym_decision.md` in memory).
**Update before mainnet T-72h.**

### 3.2 Comment / doc string sweep

Manual review pre-mainnet of:
- All `// TODO` comments mentioning Kaspa-era assumptions
- All module-level docstrings using "Kaspa" as the system name
- `README.md` — already updated, but verify no leaked references

### 3.3 Disabled / commented-out code blocks

`Cargo.toml` has multi-line comment blocks with old `workflow-rs` git
deps. These are intentional alternative dep configurations for
contributor workflows. **Keep.**

---

## 4. Disposition summary

| Category | Action | Effort | Owner |
|---|---|---|---|
| `kHeavyHash` removal sweep | PR to delete dead PoW implementation | 1-2 days | Core team |
| `secp256k1` wallet stack review | Per-crate decision (residual vs. remove) | 1-2 weeks | Core team |
| `rothschild` migration completion or rename | Decide and execute | 1-3 days | Core team |
| `Cargo.toml` repo URL update | 1-line edit | 5 min | Pre-mainnet T-72h |
| `bridge/docs/README.md` issue links | Update to `sophis-network/Sophis` | 5 min | Same as above |
| Phase 4 residuals re-grep | Verify zero leakage | 30 min | Pre-mainnet |
| FHE residuals re-grep | Verify zero leakage | 30 min | Pre-mainnet |
| ed25519/oracle context audit | Confirm all matches are Phase 5-justified | 2 hours | Pre-mainnet |
| Comment / docstring sweep | Manual read of TODO + module docs | half day | Pre-mainnet |

**Total effort for full execution:** ~3-4 weeks if done seriously, with
the secp256k1 wallet review as the dominant chunk. Most items are
hours, not days.

**Critical-path items** (must be clean before mainnet T-72h):
1. `Cargo.toml` repo URL
2. `bridge/docs/README.md` issue links
3. Phase 4 residual re-grep (verify zero leakage)
4. FHE residual re-grep (verify zero leakage)

**Non-critical** (acceptable to ship with documented residuals):
- `kHeavyHash` dead code (compiles cleanly, just wasted SLOC)
- `secp256k1` wallet residuals (already documented, contained)

---

## 5. References

- Companion: `pending_blockers.md` (memory) item #6
- Methodology source: this audit's grep matches were captured
  2026-05-09 against the workspace at HEAD of `main` for the public
  repo (`sophis-network/Sophis`)
- Related: `project_phases_completed.md`, `project_zkbridge_extraido.md`
  (memory) for historical context on what was extracted/removed
