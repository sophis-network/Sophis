# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
cargo build --workspace
cargo build --release -p sophisd        # node binary
cargo build --release -p sophis-miner   # miner binary

# Check (lint + fmt) — run before every commit
./check          # Linux/Mac
./check.ps1      # Windows PowerShell

# Test
cargo test --workspace --lib            # all lib tests (fast, use this most)
cargo test -p sophis-consensus --lib    # single crate
cargo test -p sophis-consensus test_name  # single test by name

# Clippy — local convenience (./check uses this)
cargo clippy --workspace --tests --benches

# Clippy — CI-strict (matches Lints job; will fail on any warning)
cargo clippy --workspace --tests --benches --examples \
    --exclude sophis-rollup-host --exclude rollup-node \
    -- -D warnings

# Custom lint (dylint — requires cargo-dylint + dylint-link)
cargo sophis-lint
```

**Build environment (Windows):** Build from a local filesystem path. Do NOT build from paths under Google Drive (or any other cloud-sync mount) — Rust hard links are unsupported there and break builds. Use Unix shell syntax (bash) for commands even on Windows.

**Build dependencies:** Rust 1.88+ (workspace MSRV; Lints CI job pins 1.93.0), MSVC toolchain, LLVM/Clang, `protoc`, `cmake` (required by RandomX).

## Architecture

### Consensus layer (`consensus/`, `consensus/core/`)

BlockDAG with GhostDAG ordering. Key parameters in `consensus/core/src/config/params.rs`:
- 10 BPS, k=124 (blue set size)
- `ForkActivation` struct gates all protocol upgrades by DAA score
- Three networks share a unified `Params` struct with `ParamsOverrides` for per-network tuning

Transaction dispatch in `consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs` branches on **script version** (`ScriptPublicKey.version()`):
- `0` → standard txscript (Dilithium P2SH)
- `SCRIPT_VERSION_CONTRACT = 1` → sVM contract execution
- `SCRIPT_VERSION_TOKEN = 2` → native token spend + Transfer Policy

### Cryptography — Dilithium only

**secp256k1/Schnorr/ECDSA have been completely removed.** The sole signing scheme is ML-DSA-44 (CRYSTALS-Dilithium, NIST FIPS 204) via `libcrux-ml-dsa`.

- **Signing key:** 2560 bytes; **Signature:** 2420 bytes
- **Opcode:** `OpCheckSigDilithium (0xc4)` in `crypto/txscript/src/opcodes/mod.rs`
- **Transaction hash function:** `calc_signature_hash()` in `consensus/core/src/hashing/sighash.rs` (algorithm-agnostic; formerly `calc_schnorr_signature_hash`)
- **Signing function:** `sign_input_dilithium()` in `consensus/core/src/sign.rs`

### Address system (`crypto/addresses/`)

Bech32 format. Active versions:
- `Version::PubKeyDilithium = 2` — 32-byte Blake2b hash of the Dilithium public key; input-side only
- `Version::ScriptHash = 8` — P2SH; what the script engine returns when extracting an address from a script

**Critical:** Dilithium addresses (`PubKeyDilithium`) are stored as P2SH scripts. When a UTXO is queried back through `extract_script_pub_key_address()`, it always returns `Version::ScriptHash`, not `Version::PubKeyDilithium`. In tests that roundtrip through the script layer, use `Version::ScriptHash` for expected values.

Network prefixes: `sophis:` (mainnet) · `sophistest:` (testnet) · `sophisdev:` (devnet) · `sophissim:` (simnet)

### Script engine (`crypto/txscript/`)

`ScriptClass` has two active variants: `NonStandard` and `ScriptHash`. `TxScriptEngine` handles Dilithium via `OpCheckSigDilithium`. The Dilithium redeem script and P2SH script builders are in `crypto/txscript/src/standard.rs` (`dilithium_redeem_script()`, `dilithium_address()`).

### PoW (`consensus/pow/`)

RandomX (`randomx-rs` crate). Thread-local VM with epoch key (`EPOCH_LENGTH = 2048` blocks). Fast mode (10× faster, used in tests) enabled via `--fast-mode`. The epoch key derivation prevents pre-computation across epoch boundaries.

### Mass / fee system (`consensus/core/src/mass/`)

Three mass types (all must fit within `max_block_mass`):
- **Compute mass** — size × `mass_per_tx_byte` + SPK size × `mass_per_script_pub_key_byte` + sig ops × `mass_per_sig_op`
- **Transient mass** — size × `TRANSIENT_BYTE_TO_MASS_FACTOR`
- **Storage mass** — KIP-0009 generalized formula; `MassCalculator` in `consensus/core/src/mass/mod.rs`

Dilithium transactions have large signatures (~2420 bytes), so `max_block_mass` for devnet/simnet is set to `10_000_000` (vs `500_000` for mainnet) to accommodate them in tests.

> ⚠️ **F-22 LANDMINE (audit P0, fix `d7c877e`).** Storage mass divides `C·p²/amount` per output. Any new output type with a consensus-mandated `value == 0` (Phase 6 V5 carriers, ALT-creation, and anything added later) **MUST** be added to `is_zero_value_protocol_output()` in `mass/mod.rs` or it re-introduces a divide-by-zero that panics `sophisd` on the first such tx (crashes every validator). The filter is a manual allow-list; the panic is invisible to unit/integration tests + static analysis (F-22 only surfaced under live stress soak). On any output-type change: grep `is_zero_value_protocol_output`, add the case, add a `mass::tests` unit test mirroring `test_storage_mass_skips_v5_carrier`.

### sVM (`svm/`)

Four crates:
- `svm/core` — types: `ContractManifest`, `NativeTokenUtxoData`, `TokenId`, `Capability`, `GasConfig`, `UpgradePolicy`
- `svm/runtime` — Wasmtime engine; `DbContractStore` (RocksDB); bytecode validator (rejects floats, SIMD); fuel metering
- `svm/host` — `SophisHostCrypto`; host functions exposed to WASM contracts
- `svm/sdk` — `#[sophis_contract]` macro, `Env`, `Resource<T>`, borsh types for contract authors

`Resource<T>` is a linear type: panics if dropped without calling `.consume()`. This enforces explicit accounting of token amounts in contract logic.

### L1 Address Lookup Tables (`consensus/core/src/alt/`, `consensus/src/model/stores/alt.rs`)

v=1 transactions can substitute inline `ScriptPublicKey` outputs with 8-byte ALT references (1B discriminator `0xFD` + 6B handle + 1B index). ALT-creation outputs use discriminator `0xFE` + magic `b"SPHS-AL1"`. Handle is content-derived: `SHA3-384(entries_canonical)[..6]`. RocksDB prefixes 200-202 (`AltEntries`, `AltCreatedInBlock`, `AltHandleResolutions`); permanent (no rent). sVM `Capability::ResolveAlt` + `sophis_alt_lookup` host fn for contract-side resolution. Spec: `docs/L1_ALT_DESIGN.md`. SIP-3 stub: `SIPS/SIP-3-ALT.md`. Operator: `docs/L1_RUNBOOK.md`.

### sVM Event Logs (`consensus/core/src/events/`, `consensus/src/model/stores/events.rs`)

sVM contracts emit structured events via `sophis_emit_event` host fn (`Capability::EmitEvent`, J4.3 in progress). Wire format: `topic_count u8 (0..=4) + topics [u8;32]*N + data_len u32 LE + data (≤4096B)`. Persisted in 4 RocksDB indexes (prefixes 203-206): `EventsByBlock`, `EventsByTx` (pruned with block); `EventsByContract`, `EventsByTopic` (archival, bucketed by DAA score / 65_536). Filterable via `getLogs(filter)` RPC (J4.5 in progress, mirrors `eth_getLogs`). Spec: `docs/J4_EVENTS_DESIGN.md`.

### Coinbase (`consensus/src/processes/coinbase.rs`)

100% of block subsidy + fees goes to the miner. **No on-chain devfund** — eliminated 2026-05-04 by regulatory pivot. `params.rs` no longer carries `dev_fund_address`. Do not reintroduce coinbase split, devfund schedule, or compulsory multisig recipient — committed compromise: no hard fork will reintroduce devfund.

### Network ports

| Protocol | Port  |
|----------|-------|
| P2P      | 46111 |
| gRPC     | 46110 |
| Borsh RPC | 47110 |
| JSON RPC | 48110 |

Testnet ports add 100 (P2P 46211, gRPC 46210, etc.).

### Production testnet infrastructure (deployed 2026-05-14)

Two Hetzner Cloud VMs running `sophisd-mainnet` + `sophisd-testnet`,
cloud-init defined in `bootstrap-nodes/cloud-init/`:

| Role | Location | IP | Plan | Services |
|------|----------|------|------|----------|
| `sophis-bootstrap1` | Hillsboro, OR | `5.78.211.57` | CPX11 (2 GB) | sophisd-mainnet/testnet, faucet, nginx, fail2ban, dnsseeder-testnet |
| `sophis-bootstrap2` | Nuremberg, DE | `178.105.175.220` | CX23 (~4 GB) | sophisd-mainnet/testnet, fail2ban, dnsseeder-testnet |

Both pinned in two continents (US ↔ EU) for jurisdictional + backbone
diversity. Node 2 is pinned to node 1 with `--addpeer=5.78.211.57:46111`
(and `:46211` for testnet). **Do NOT use `--connect=`** — that flag
puts sophisd into client-only mode (no inbound listener, no discovery),
silently breaking external peering even though `systemctl is-active`
reports `active`.

#### DNS seeders

Each host also runs `sophis-dnsseeder` on UDP/53 to publish a rolling
list of reachable peer IPs as DNS A records. Cloudflare delegates
`testnet-seed.sophis.org` to `ns1.sophis.org` + `ns2.sophis.org`
(A-records to the two bootstraps), so `nslookup -type=A
testnet-seed.sophis.org` returns reachable testnet peers.
`TESTNET_PARAMS.dns_seeders` in `consensus/core/src/config/params.rs`
points at this hostname so fresh testnet nodes bootstrap automatically.

Gotcha for fresh installs: Ubuntu 24.04 ships `systemd-resolved` with
a stub listener that squats UDP/53. Drop in
`bootstrap-nodes/systemd/resolved-no-stub.conf` (also commits the
`/etc/resolv.conf` symlink fix) before starting the dnsseeder unit.

Mainnet seeder unit is committed at
`bootstrap-nodes/systemd/sophis-dnsseeder-mainnet.service` but **not
enabled** — both seeders cannot coexist on the same host (single
UDP/53). Activates when mainnet ships.

#### Faucet HTTPS

`https://faucet.sophis.org/` runs on bootstrap1 via the
`testnet-faucet` Rust crate behind nginx with Let's Encrypt cert
(auto-renew every 60 days). Cloudflare A-record is currently
`DNS only` (gray cloud) — proxy can be flipped on later if traffic
or DDoS pressure justifies, but ACME renewals need a Page Rule
bypass for `/.well-known/acme-challenge/*` in that case.

The faucet wallet is at `/var/lib/sophis-faucet/wallet.json` on
bootstrap1. Address visible via
`sudo jq -r .address /var/lib/sophis-faucet/wallet.json`. Needs to
be funded before `/drip` will dispense.

Pitfall hit during first deploy: running `certbot --nginx --redirect`
on the cloud-init's pre-baked vhost (with `listen 443 ssl` lines
commented out so nginx could come up before any cert existed) causes
certbot to inject a parallel `:443` server block whose only directive
is the HTTPS-to-HTTPS redirect — endless loop. Documented fix is in
`bootstrap-nodes/BOOTSTRAP_RUNBOOK.md` under "Faucet HTTPS — certbot
+ nginx pitfall"; the cleaner path for the next operator is
`certbot certonly --webroot` + manual sed-uncomment of the SSL lines.

#### Monitoring

UptimeRobot watches 4 P2P ports + the faucet HTTPS endpoint
(5 monitors total, 5-minute interval, email alerts). The DNS
seeders are reachable via UDP/53 — UptimeRobot's free tier does
TCP probes only, so they're not on the monitor list directly;
operationally they're covered by the sophisd-testnet monitors
(if the host's down, the seeder's down too).

Full deploy notes + 8-bug post-mortem in
`bootstrap-nodes/HETZNER_SETUP_GUIDE.md` and
`bootstrap-nodes/BOOTSTRAP_RUNBOOK.md`.

### Public-facing endpoints (live as of 2026-05-14)

| URL | Served by | Purpose |
|-----|-----------|---------|
| `https://sophis.org/` | Cloudflare Pages (repo `sophis-network/Sophis.eth`) | Institutional site, 18 pages EN/PT/ES |
| `https://sophis.org/Whitepaper.pdf` | Cloudflare Pages | Whitepaper v1.0, 27 pp (canonical source: `Whitepaper.md` in this repo) |
| `https://faucet.sophis.org/` | nginx on bootstrap1 | Testnet faucet UI |
| `https://faucet.sophis.org/status` | nginx → testnet-faucet | Wallet balance JSON |
| `https://faucet.sophis.org/drip` | nginx → testnet-faucet | POST endpoint, rate-limited |
| `testnet-seed.sophis.org` (UDP/53) | sophis-dnsseeder on both bootstraps | Testnet peer discovery |
| `5.78.211.57:46111` / `178.105.175.220:46111` | sophisd-mainnet | P2P (mainnet) |
| `5.78.211.57:46211` / `178.105.175.220:46211` | sophisd-testnet | P2P (testnet) |

### ZK-Rollup L2 (`rollup/`)

Phase 3 complete. Seven crates:
- `rollup/core` — shared types: `L2Tx`, `L2Utxo`, `Batch`, `BatchJournal`, `StateRoot`, `hash_withdrawals`
- `rollup/guest` — Risc0 guest (RISC-V workspace, isolated from main target): state transition function
- `rollup/host` — Risc0 host: orchestrates proof generation, produces STARK proof
- `rollup/verifier` — sVM WASM contract: verifies `BatchJournal` on-chain (8 tests)
- `rollup/sequencer` — mempool, `Sequencer<C>`, `BatchTrigger`, `L1Client` trait, HTTP RPC (19 tests)
- `rollup/node` — CLI binary: `start` + `gen-key`; HTTP :9944; key file = 3872 bytes (2560 SK ‖ 1312 VK)
- `rollup/bridge/deposit` — `DepositRecord`, `BRIDGE_VAULT_VERSION=3`; L1 vault UTXO helpers
- `rollup/bridge/withdrawal` — sVM WASM contract: validates `WithdrawalClaim` before releasing SPHS (11 tests)

`rollup/guest/` is a **separate Cargo workspace** (RISC-V target isolated from the main workspace). Build it with its own `cargo build` inside `rollup/guest/`.

Sequencer selection: miner of block N×100 becomes sequencer. Batch trigger: 100 txs OR 30 s. `WrpcL1Client` in rollup-node is a stub — full L1 wRPC integration is Phase 3b.

Journal serialization uses **borsh** (never serde). `BRIDGE_VAULT_VERSION=3` (deposit) and `BRIDGE_CLAIM_VERSION=4` (withdrawal) are protocol constants — do not change without a hard fork.

L2 key derivation: same BIP-39 mnemonic, path `m/44'/111111'/0'/1/0` (distinct from L1 `…/0/0`).

### Branch convention

Active development uses `phase3-stable-v0.X.Y`. Create feature branches from the latest stable branch before committing, not after.

## SIP track (as of 2026-05-12)

17 SIPs published, range 0–16, no gaps. Standards-track formalization of every consensus-impacting subsystem plus off-chain/wallet/SDK conventions. **Zero SIPs force a future hard fork** — every consensus-impacting SIP was baked in pre-mainnet (DAA 0); 3 spec-only or sVM-only SIPs (9 Poseidon, 10 Multicall, 12 AA) have *optional* future-promotion paths gated on separate follow-up SIPs + demand + production data, never on present-day commitment.

| # | SIP file | Subject | Consensus-impacting? |
|---|---|---|---|
| 0 | `SIPS/SIP-0-process.md` | Process and template | ❌ |
| 1 | `SIPS/SIP-1-PSBS.md` | Partially-signed transactions (Dilithium-aware) | ❌ wallet |
| 2 | `SIPS/SIP-2-TYPED-SIGNING.md` | Typed data signing (J2) | ❌ wallet |
| 3 | `SIPS/SIP-3-ALT.md` | L1 Address Lookup Tables | ✅ baked pre-genesis |
| 4 | `SIPS/SIP-4-EVENTS.md` | sVM event logs (J4) | ✅ baked pre-genesis |
| 5 | `SIPS/SIP-5-DESCRIPTORS.md` | Wallet descriptors (BIP-380-like) | ❌ wallet |
| 6 | `SIPS/SIP-6-WALLET-VERIFICATION.md` | `.well-known/sophis-wallet.json` | ❌ off-chain |
| 7 | `SIPS/SIP-7-LIGHT-CLIENT.md` | Light Client SPV (J5) | ✅ baked pre-genesis |
| 8 | `SIPS/SIP-8-PRUNING-POLICY.md` | Pruning policy + `getPruningInfo` RPC (J8) | ❌ RPC + policy |
| 9 | `SIPS/SIP-9-POSEIDON.md` | Canonical Poseidon (spec-only, J6) | ❌ today; promotion-gated |
| 10 | `SIPS/SIP-10-MULTICALL.md` | Multicall SDK contract pattern (J7) | ❌ today; promotion-gated |
| 11 | `SIPS/SIP-11-PQC-ORACLE.md` | PQC-native oracle (Phase 9) | ✅ baked pre-genesis |
| 12 | `SIPS/SIP-12-AA.md` | Account abstraction (J1) | ❌ today (sVM); promotion-gated ≥12 months |
| 13 | `SIPS/SIP-13-IDL.md` | sVM contract IDL | ❌ off-chain JSON |
| 14 | `SIPS/SIP-14-DNS-SEEDER.md` | DNS seeder protocol | ❌ off-chain DNS |
| 15 | `SIPS/SIP-15-STRATUM-V2.md` | Stratum V2 for Sophis (RandomX + Dilithium coinbase) | ❌ off-chain pool |
| 16 | `SIPS/SIP-16-DA.md` | Self-DA via V5 carrier UTXOs (Phase 6) | ✅ baked pre-genesis |

Discipline: ship via implementation pre-mainnet, then formalize via SIP; no SIP gates future activation. Anti-rug invariants in `HARD_FORK_POLICY.md` (210M cap, Dilithium-only, no devfund, no privacy primitives, no team-operated bridge, no foundation) are not modifiable by any SIP — NACK automatic per SIP-0 process.

## Key invariants

- **No secp256k1/Schnorr/ECDSA.** If you see these imported anywhere, it is a bug.
- `calc_signature_hash()` is the transaction hash function for all signature types — do not rename or create a Schnorr-specific variant.
- `SCRIPT_VERSION_CONTRACT = 1` and `SCRIPT_VERSION_TOKEN = 2` are consensus constants — changing them requires a hard fork.
- `max_block_mass` for simnet/devnet is intentionally 20× mainnet to support oversized Dilithium test transactions.
- `cargo test --workspace --lib` should always pass with zero failures before any commit. The `daemon_integration_tests` binary test has a known pre-existing race condition and is excluded from the required pass.
- **sVM `Capability` enum:** 11 variants — `ReadUtxo`, `ProduceOutput`, `VerifyDilithium`, `ReadBlockHeight`, `HashSha3`, `VerifyRisc0Proof` (Phase 3 ZK-Rollup), `VerifyPlonky3Proof` (legacy Phase 5 oracle, deprecated 2026-05-11), `VerifyDataAvailability` (Phase 6 self-DA), `ResolveAlt` (L1 ALT), `EmitEvent` (J4), `VrfRandomness` (J3). Canonical source: `svm/core/src/capability.rs`. Never re-add `VerifySchnorr`. The `VerifyRisc0Proof` path is feature-gated by `svm-zk` — production nodes MUST build with `--features svm-zk` or they will panic on rollup state-update contracts.
- **WASM memory:** contracts must declare `maximum`; validator rejects unbounded or > 256 pages (16 MiB).
- **`UpgradePolicy::is_valid()`** is called in `validate_contract_deploy()`. For `MultisigTimelock`: `threshold > 0`, `threshold <= keys.len()`, `keys.len() <= 16`.
- When adding a new host function: (1) add to `HostCrypto` trait, (2) register in linker in `host.rs`, (3) create matching `Capability`, (4) expose in `Env` in the SDK, (5) add Kani harness.
- `BRIDGE_VAULT_VERSION=3` and `BRIDGE_CLAIM_VERSION=4` are protocol constants — changing them requires a hard fork.
- **No SIP currently in the repo forces a future hard fork.** See the SIP track table above. Any change to that statement would be a structural-discipline regression — proposals to promote SIP-9 / 10 / 12 to consensus primitives require a separate follow-up SIP and explicit demand + production-data gates; they do not happen as a side-effect of the existing SIP set.

## CI invariants (2026-05-08)

The `Tests` workflow has 10 jobs. Local validation must match CI strictness, not just `./check`.

- **Lints job uses `-D warnings`.** `./check` does not. To match CI locally: see "CI-strict" clippy command above. Without `-D warnings`, deprecation warnings (e.g. `rand 0.9` rename) silently pass locally and break CI.
- **Workspace clippy allowlist** in `[workspace.lints.clippy]` permits 7 categories tailored for STARK/AIR code (`needless_range_loop`, `manual_memcpy`, `inconsistent_digit_grouping`, `assertions_on_constants`, `doc_overindented_list_items`, `empty_docs`, `uninlined_format_args`). Each is justified inline. Do not remove without checking what breaks in `oracle/host`.
- **New crates in `oracle/*` MUST add `[lints] workspace = true`** to their `Cargo.toml`. Without this, the workspace allowlist does not apply to them and CI strict clippy will reject the new crate's STARK/AIR patterns.
- **wasm32 builds require `getrandom_backend="wasm_js"` cfg.** Already set in `.cargo/config.toml`. `consensus/core/Cargo.toml` carries a target-specific `getrandom v0.3 features=["wasm_js"]` dep that propagates feature unification to every wasm32 build graph that depends on consensus-core (= all of them).
- **`wasm/build-release` script** sets `RUSTFLAGS=` directly, which overrides `.cargo/config.toml` rustflags. The cfg is duplicated there; remember if adding more wasm-pack invocations.
- **`Test Suite (svm-zk)` is a separate job** that runs `cargo nextest run -p sophis-svm-host --features risc0` in isolation. Stacking it onto the workspace test run exceeds the GitHub runner's ~14GB free disk (`librocksdb.a` static archive step fails with "No space left on device").
- **kip-10 example** in `crypto/txscript/examples/kip-10.rs` is gated behind `legacy-schnorr-example` feature (never enabled by default). The example uses `OpCheckSig`/`secp256k1::Keypair` and is incompatible with Dilithium-only Sophis. Do not enable the feature unless rewriting the example for Dilithium.
- **`Build Linux Release` job** depends on the `musl-toolchain-v1` GitHub release (asset `x-tools.tar.zst`). Re-run `gh workflow run musl-toolchain.yaml` only if `musl-toolchain/preset.sh` changes.
