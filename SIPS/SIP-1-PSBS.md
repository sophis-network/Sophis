```
SIP: 1
Title: Partially Signed Sophis Transactions (PSBS)
Author: Marcelo Delgado <sophis-network@proton.me>
Status: Draft
Type: Standards
Created: 2026-05-09
```

# SIP-1: Partially Signed Sophis Transactions (PSBS)

## 1. Abstract

This SIP defines **PSBS** — *Partially Signed Sophis Transactions* — a wire format for Sophis transactions in intermediate stages of construction and signing. PSBS lets multiple participants collaborate on a transaction across air-gapped or otherwise-disconnected machines: one participant constructs the unsigned transaction skeleton, another (offline) signs with their Dilithium ML-DSA-44 key, and a third (online) finalizes and broadcasts. PSBS is a client-side format with no consensus impact; it is the foundation primitive for hardware-wallet support, cold-storage workflows, and (eventually) multisig coordination on Sophis.

## 2. Motivation

A wallet that requires its signing key to be available online at transaction time is structurally hostile to two large categories of users:

1. **Cold-storage holders** (long-term savers, treasury managers) who keep signing keys on air-gapped hardware as a defense against malware and remote compromise.
2. **Multi-party signers** (DAOs, corporate treasuries, family multisig) who need M-of-N signatures from independently-operated keys.

Bitcoin solved this with BIP-174 (PSBT, 2017) and Kaspa adopted the same shape as PSKT. Both formats are tightly coupled to secp256k1 — public keys are 33 bytes, signatures 64 bytes — and cannot represent Dilithium ML-DSA-44 inputs/outputs (verification keys 1312 bytes, signatures 2420 bytes) without breaking change.

Sophis ships PQC-only at consensus (`OpCheckSigDilithium` opcode `0xc4` is the only active signature-verification opcode); a wire format suitable for collaborative transaction construction must be Dilithium-native from the start. PSBS provides that format.

Without this SIP:

- Hardware wallet vendors (Ledger, Trezor, Coldcard) cannot meaningfully support Sophis — there is no standard binary container they can implement against.
- Cold-storage workflow remains artisanal — every user invents their own transaction-passing format.
- Multisig coordination across geographically separated signers is impractical.
- Exchange and custody services have a structural reason to delist or refuse to support Sophis.

PSBS exists to remove all four obstacles.

## 3. Specification

### 3.1 Container

PSBS is a borsh-encoded container. The canonical extension for serialized PSBS files is `.psbs`. The text-form representation prefixes the hex-encoded body with the literal ASCII string `PSKT` (preserved from the inherited Kaspa PSKT machinery; the prefix string is a stable identifier of the **Sophis** dialect when accompanied by Dilithium types).

The container is the `Bundle` type:

```
Bundle = Vec<Inner>

Inner = {
    global:  Global,
    inputs:  Vec<Input>,
    outputs: Vec<Output>,
}
```

Wire-version magic bytes are reserved for future incompatible revisions. v1 (this SIP) does not advance the magic; future SIPs that change the wire format MUST advance to a new SIP and a new magic prefix.

### 3.2 Types

The complete type definitions live in `wallet/pskt/src/crypto.rs` and `wallet/pskt/src/{global,input,output,pskt}.rs` of the reference implementation. The following are normative excerpts.

#### 3.2.1 Public key

```rust
pub struct DilithiumPubKey([u8; 1312]);
```

The 1312-byte verification key per FIPS 204 (ML-DSA-44). Serializes as hex string in human-readable contexts (JSON), as raw bytes in binary. Total ordering is lexicographic on the byte sequence; this is used for deterministic ordering of multi-key signature collections.

#### 3.2.2 Signature (versioned variant)

```rust
pub enum Signature {
    DilithiumML44(Box<[u8; 2420]>),  // FIPS 204 ML-DSA-44 signature
    Future { variant: u8, payload: Vec<u8> },
}
```

The signature is wrapped in a versioned enum so that future SIPs may add new schemes (e.g., ML-DSA-65, ML-DSA-87, or Dilithium aggregate signatures if a production-ready scheme emerges) without breaking the wire format. **v1 implementations MUST emit only `DilithiumML44`** and **MUST reject `Future` variants** as `UnsupportedVariant` errors.

The variant discriminator byte (`0x01` for `DilithiumML44`) is reserved-by-convention; future variants MUST be assigned by SIP.

#### 3.2.3 PartialSig collection

```rust
pub type PartialSig = (DilithiumPubKey, Signature);
pub type PartialSigs = Vec<PartialSig>;
```

A `Vec` rather than a `BTreeMap`. Rationale in §4.D3.

#### 3.2.4 Input

```rust
pub struct Input {
    pub utxo_entry:        Option<UtxoEntry>,
    pub previous_outpoint: TransactionOutpoint,
    pub sequence:          Option<u64>,
    pub min_time:          Option<u64>,
    pub partial_sigs:      PartialSigs,            // Vec<(DilithiumPubKey, Signature)>
    pub sighash_type:      SigHashType,
    pub redeem_script:     Option<Vec<u8>>,
    pub sig_op_count:      Option<u8>,
    pub final_script_sig:  Option<Vec<u8>>,        // populated by Finalizer
    pub proprietaries:     BTreeMap<String, serde_value::Value>,
    pub unknowns:          BTreeMap<String, serde_value::Value>,
}
```

`bip32_derivations` and `xpubs` fields present in the inherited Kaspa PSKT have been **removed** in PSBS — see §4.D1/D2.

#### 3.2.5 Output

```rust
pub struct Output {
    pub amount:            u64,
    pub script_public_key: ScriptPublicKey,
    pub redeem_script:     Option<Vec<u8>>,
    pub proprietaries:     BTreeMap<String, serde_value::Value>,
    pub unknowns:          BTreeMap<String, serde_value::Value>,
}
```

#### 3.2.6 Global

```rust
pub struct Global {
    pub version:             Version,    // PSBS version field (currently 0 or 1)
    pub tx_version:          u16,
    pub fallback_lock_time:  Option<u64>,
    pub inputs_modifiable:   bool,
    pub outputs_modifiable:  bool,
    pub input_count:         usize,
    pub output_count:        usize,
    pub id:                  Option<TransactionId>,
    pub proprietaries:       BTreeMap<String, serde_value::Value>,
    pub unknowns:            BTreeMap<String, serde_value::Value>,
    pub payload:             Option<Vec<u8>>,
}
```

### 3.3 Workflow (PSBS roles)

The PSBS workflow is a sequence of role transitions. Each role is a typestate of the `PSKT<R>` Rust type; serialization to bytes erases the role (the on-disk container is role-agnostic), but the in-memory typestate ensures workflow correctness.

```
Creator → Constructor → Updater → Signer (×N) → Combiner → Finalizer → Extractor
```

#### 3.3.1 Creator

Initializes an empty PSBS. Sets `tx_version`, `fallback_lock_time`, and modifiability flags.

#### 3.3.2 Constructor

Adds inputs (`previous_outpoint`, `utxo_entry`, `redeem_script`) and outputs (`amount`, `script_public_key`).

#### 3.3.3 Updater

Adds metadata (`sequence`, `min_time`, `sighash_type`, additional proprietary fields). May be skipped if Constructor already populated everything.

#### 3.3.4 Signer

Holds a Dilithium signing key. For each input the Signer is authorized to sign:

1. Compute the canonical sighash via `calc_signature_hash(tx, input_index, sighash_type, &reused)` from `consensus/core/src/hashing/sighash.rs`.
2. Generate fresh randomness (32 bytes) per `libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE`.
3. Sign with `ml_dsa_44::sign(&signing_key, sighash_bytes, b"", randomness)`.
4. Append `(DilithiumPubKey, Signature::DilithiumML44(sig))` to `input.partial_sigs`.
5. Zeroize randomness.

Signers MUST NOT mutate any field other than `partial_sigs` and (optionally) `bip32_derivations` (which is empty in v1 — see §4.D1).

#### 3.3.5 Combiner

Accepts two PSBS instances representing the same underlying transaction and merges them. Signature collections are deduplicated by pubkey: if two contributions claim signatures from the same pubkey, the first is kept and the second is silently discarded. (Rationale: Combiner is dataflow, not arbiter; a malicious resigning attempt by an honest participant should not crash the workflow.)

The Combiner verifies that all contributing PSBS instances agree on `previous_outpoint`, `utxo_entry`, `sighash_type`, and `redeem_script` for every input, and on every output's `amount` and `script_public_key`. Mismatch is a hard error returned to the caller.

#### 3.3.6 Finalizer

Assembles the final `signature_script` for each input. For single-sig P2SH-Dilithium:

```
sig_with_sighash = sig_bytes || sighash_type_byte
final_script_sig = pay_to_script_hash_signature_script(redeem_script, sig_with_sighash)
```

The Finalizer MUST verify each signature cryptographically before incorporating it. A syntactically-valid but cryptographically-invalid signature MUST cause the Finalizer to fail, not produce a malformed transaction.

#### 3.3.7 Extractor

Reads the finalized PSBS and produces a `Transaction` ready for broadcast. The Extractor calls `extract_tx(&params)` which runs the txscript engine over each input to verify the assembled `signature_script` against the chain's consensus rules; this is a defense-in-depth check, since Finalizer signature verification should already have caught any error.

### 3.4 Reference miner workflow

```
# online machine (RPC access to UTXO set)
dilithium-wallet pskt create --wallet hot.json \
    --to sophis:qx... --amount 100 \
    --rpcserver 127.0.0.1:46110 --output tx.psbs

# offline machine (signing key, no network)
dilithium-wallet pskt sign --wallet cold.json \
    --input tx.psbs --output tx-signed.psbs

# online machine (broadcast)
dilithium-wallet pskt extract --input tx-signed.psbs --output tx.json
# broadcast manually via RPC submit_transaction
```

A `pskt combine` subcommand is provided as a pass-through in v1 (single-sig case) and reserved for multisig coordination once Account Abstraction (J1) lands. See §4.D5.

## 4. Rationale

Five design decisions distinguish PSBS from a literal Dilithium port of BIP-174 PSBT or Kaspa PSKT. Each decision was made deliberately and is load-bearing.

### D1 — `bip32_derivations` field removed

PSBT/PSKT include a `bip32_derivations` map carrying `(pubkey → (master_fingerprint, derivation_path))` for each input/output, so wallets can reconstruct the signing key path from the master seed without holding the full key.

Sophis has **no hierarchical deterministic derivation** for Dilithium. The current key-derivation pattern is `BIP-39 mnemonic → PBKDF2 seed → first 32 bytes → ml_dsa_44::generate_key_pair`, which produces exactly one keypair per mnemonic. There is no NIST-blessed BIP-32 equivalent for ML-DSA as of 2026.

Including `bip32_derivations` with empty or meaningless contents would be a wire-format placeholder for a feature that does not exist. Worse, it would invite wallets to invent ad-hoc HD schemes that diverge across implementations and cannot be reconciled later. PSBS removes the field cleanly. If a NIST-standardized Dilithium HD scheme emerges, a future SIP can reintroduce the field with proper semantics.

### D2 — `xpubs` field removed

For the same reason as D1: extended public keys are a hierarchical-derivation concept; without HD there is no extended public key to represent. Removed entirely from the `Global` map.

### D3 — `PartialSigs = Vec<(DilithiumPubKey, Signature)>` (not `BTreeMap`)

Inherited PSKT used `BTreeMap<secp256k1::PublicKey, Signature>`, where the map key is a 33-byte secp256k1 public key. With Dilithium, the analogous map key is 1312 bytes, making `BTreeMap` operations (key comparison, hashing for state-keyed lookups, serialization) unnecessarily expensive.

PSBS uses an ordered `Vec`. Multisig signature counts in practice are bounded (M-of-N typically ≤ 7 for Sophis-scale workflows), making linear lookup trivial. Combiner deduplication is implemented in the merge step (§3.3.5), preserving the BTreeMap semantics without the BTreeMap costs.

### D4 — `Signature` enum versioned with `Future` placeholder

Dilithium ML-DSA-44 is the v1 signature scheme. ML-DSA-65 and ML-DSA-87 exist as standardized higher-security parameter sets, and aggregate-signature schemes for Dilithium are in active research. The `Signature` enum reserves a `Future { variant: u8, payload: Vec<u8> }` slot so that adopting a new scheme is a non-breaking SIP rather than a wire-format hard fork.

v1 implementations **MUST** reject `Future` variants until a SIP authorizes a specific variant byte. This prevents two well-meaning wallets from independently deploying incompatible "v1.5" schemes that fragment the ecosystem.

### D5 — Multisig deferred (combine is pass-through in v1)

True multisig — M-of-N signatures aggregated into a single redeem-script-driven authorization — requires either (a) Dilithium aggregate signatures (research-grade; no production-ready scheme as of 2026) or (b) a smart-contract layer that executes per-signature verification (= Account Abstraction, J1).

PSBS v1 supports **single-sig flows fully** and **multisig structurally** (the `partial_sigs` Vec accepts arbitrary entries; the Combiner merges them correctly), but the Finalizer in v1 only knows how to assemble single-sig P2SH-Dilithium scripts. Multisig finalization is a SIP yet to be written, dependent on the J1 spec landing first (`wallet/aa-spec/`).

Users and wallet implementers SHOULD treat `pskt combine` in v1 as a single-sig pass-through. Real multi-party use requires the J1 layer.

## 5. Backwards Compatibility

**Standards Track, no consensus impact, no fork required.** PSBS is a client-side wire format. A node that has never heard of PSBS continues to function normally.

Specifically:

- The on-chain transaction format is **unchanged**. PSBS encodes intermediate states; only the final extracted `Transaction` is broadcast, and it is a standard Sophis transaction.
- Existing wallets (single-key signing in `dilithium-wallet send`) are unaffected and continue to work.
- New tooling (hardware wallets, cold-storage CLIs, multisig coordinators) gain a standard format to target.
- The text-form prefix `PSKT` is preserved from the inherited Kaspa machinery so that tooling distinguishing PSBS-text from raw bytes continues to work; the **content** of the hex body is incompatible with Kaspa PSKT (Dilithium types do not parse as secp256k1 types and vice versa). Tools should validate by attempting to deserialize, not by inspecting the prefix.

PSBS is incompatible with Kaspa PSKT by construction. A tool that accepts `.psbs` files MUST NOT silently accept Kaspa `.pskt` files (and vice versa); deserialization will fail loudly because the type sizes disagree.

## 6. Reference Implementation

**Crate:** `wallet/pskt/` (workspace member `sophis-wallet-pskt`, version 1.1.0)

**Design document:** `wallet/pskt/DESIGN.md` (commit `71541df`, 2026-05-09)

**CLI:** `dilithium-wallet pskt {create, sign, combine, extract}` (commit `cc1d3f5`, 2026-05-09)

**Implementation phases (all committed locally as of 2026-05-09):**

| Phase | Commit | Content |
|---|---|---|
| K1.0 | `71541df` | Design doc + decisions D1–D5 |
| K1.1 | `71541df` | `crypto.rs` with DilithiumPubKey / Signature versioned enum |
| K1.2 | `71541df` | bip32_derivations / xpubs removal |
| K1.3 | `893a8ae` | Dilithium-aware tests (12/12 green) |
| K1.4 | `cc1d3f5` | CLI subcommands |
| K1.5 | this SIP | Public RFC opening |
| K1.6 | (forthcoming) | Drop residual `secp256k1` workspace dep from PSKT crate |

**Test status:** `cargo test -p sophis-wallet-pskt --lib` passes 12/12 (5 crypto round-trip + 5 bundle serialization + 2 Dilithium-aware end-to-end). `cargo clippy -p sophis-wallet-pskt --tests -- -D warnings` is green.

## 7. Security Considerations

### 7.1 Confidentiality

PSBS is **not encrypted**. Anyone who intercepts a PSBS file in transit learns the transaction outline (UTXOs being spent, recipient addresses, amounts). This matches PSBT semantics. Confidentiality during transport is the user's responsibility (encrypted channel, sneakernet).

### 7.2 Authenticity at the signing stage

The Signer trusts that the Updater's `utxo_entry` data is accurate. A malicious Updater could lie about UTXO `amount` to trick the Signer into signing a higher-value spend than expected. **Wallets that accept PSBS from external sources MUST display the UTXO `amount` and the recipient address(es) to the user before signing**, allowing manual cross-check against an independent source.

### 7.3 Replay

A finalized PSBS is, by extraction, a complete Sophis transaction. Once broadcast, it can be replayed — but the protocol's UTXO-spent rule prevents the same UTXOs from being consumed twice. Cross-network replay (mainnet ↔ testnet ↔ devnet) is prevented by the address-prefix system (`sophis:` / `sophistest:` / `sophisdev:` / `sophissim:`) and by the network-distinguishing data included in the canonical sighash.

### 7.4 Signing key handling

**The Signer is the only role that touches signing keys.** Signing keys MUST NOT appear anywhere in the PSBS itself; only verification keys (`DilithiumPubKey`) appear in `partial_sigs`. A Signer running on an air-gapped machine reads a `.psbs` file, signs, writes a new `.psbs` file. The signing key never leaves the air-gapped machine.

Wallet implementers MUST take care to zeroize randomness buffers after signing (the reference CLI does this in `cmd_pskt_sign`). Signing-key bytes themselves should be loaded just-in-time and dropped immediately after the signing call returns.

### 7.5 `Future` variant rejection

v1 implementations MUST reject `Signature::Future { variant, .. }` for any `variant` not yet authorized by a subsequent SIP. The reference implementation does this in `Finalizer::finalize_internal` and at the `Signer::pass_signature_sync` boundary.

A wallet that silently accepts an unknown `Future` variant could be tricked into producing a transaction whose authorization it cannot reason about. Strict rejection is the only safe default.

### 7.6 Combiner deduplication semantics

When two PSBS contributions both contain a signature for the same `DilithiumPubKey`, the Combiner keeps the **first** (existing) entry and discards the second. This is documented in `wallet/pskt/src/input.rs` (`Input::Add` impl) and in `wallet/pskt/DESIGN.md` §5.4. Wallets MUST NOT assume that contributing a "fresher" signature replaces an earlier one; if a Signer needs to retract a signature, the workflow is to start over from a clean Updater-stage PSBS.

### 7.7 No side-channel guarantees from this SIP

Side-channel attacks on Dilithium signing (timing, power, EM) are out of scope for this SIP. The Signer's environment (offline hardware, OS-level isolation, etc.) is the user's responsibility. PSBS does not weaken or strengthen the underlying Dilithium implementation's side-channel posture.

### 7.8 Quantum security

PSBS relies entirely on Dilithium ML-DSA-44 for signature integrity. If ML-DSA-44 is broken, all of Sophis breaks, not just PSBS. The migration path for stronger Dilithium parameter sets (ML-DSA-65, ML-DSA-87) is the `Signature::Future` slot (D4) plus a follow-up SIP. There is no hybrid-signature contingency in v1; see SPEC §8.4 for rationale (rejected).

### 7.9 Long-range attack resistance, reorg behaviour, mempool policy

This SIP **does not affect** consensus rules, mempool policy, reorg behaviour, light-client / SPV verifiability, or compatibility with Phase 3 (ZK-Rollup), Phase 5 (ZK-Oracle), or Phase 6 (Data Availability). PSBS is a client-side format with no consensus impact.

## 8. Test Vectors

The canonical test vectors live in `wallet/pskt/src/bundle.rs`, `tests` module, and are part of the standard test suite (`cargo test -p sophis-wallet-pskt --lib`). Reference implementers MUST validate their implementation against these tests before claiming PSBS-v1 conformance.

### 8.1 Single-input single-sig round-trip

**Reference test:** `test_pskt_with_dilithium_partial_sig_roundtrip` (`wallet/pskt/src/bundle.rs`).

**Procedure:**

1. Derive Dilithium keypair `(vk, sk)` from the deterministic seed `b"PSBS_test_seed_alpha____________"` (32 bytes) via `ml_dsa_44::generate_key_pair(seed)`.
2. Construct an `Input` with:
   - `previous_outpoint = 0000…0001:0`
   - `utxo_entry.amount = 1_000_000_000`
   - `utxo_entry.script_public_key = pay_to_script_hash_script(<32-byte placeholder>)`
   - `sig_op_count = 1`
   - `redeem_script = <32-byte placeholder>`
3. Sign `b"PSBS K1.3 test message"` with the signing key + fixed randomness `[0xa5; 32]` to obtain `sig_bytes`.
4. Push `(DilithiumPubKey::from(vk), Signature::DilithiumML44(sig_bytes))` into `input.partial_sigs`.
5. Wrap in a `Bundle::from(PSKT::Creator)`, serialize, deserialize.
6. **Expected invariants:**
   - Bundle round-trip preserves `partial_sigs.len() == 1`
   - Recovered `(pubkey, signature)` is byte-identical to the input
   - `ml_dsa_44::verify(vk, message, b"", recovered_sig)` succeeds

The test is deterministic: with the same input seeds, randomness, and message bytes, every conforming implementation MUST produce the same `vk`, `sig`, and serialized PSBS bytes. Implementers diverging from the reference test outputs are non-conforming.

### 8.2 Two-key combine deduplication

**Reference test:** `test_pskt_with_two_dilithium_partial_sigs_combine_dedup`.

**Procedure:**

1. Derive two keypairs `(vk_a, sk_a)` and `(vk_b, sk_b)` from seeds `b"PSBS_test_seed_alpha____________"` and `b"PSBS_test_seed_beta_____________"`.
2. Construct an `Input` with `partial_sigs = [(vk_a, dummy_sig), (vk_b, dummy_sig)]`.
3. Construct an `rhs Input` clone with an additional `(vk_a, dummy_sig)` appended (pubkey duplicate).
4. Combine `input + rhs`.
5. **Expected invariant:** `combined.partial_sigs.len() == 2` (the duplicate `vk_a` entry is dropped, not appended).

### 8.3 Crypto-only round-trip tests

The `crypto` module (`wallet/pskt/src/crypto.rs`) includes 5 standalone round-trip tests for `DilithiumPubKey` and `Signature` enum serialization (JSON path; binary path is exercised by Bundle tests). Each MUST pass for an implementation to be conforming.

### 8.4 Failure cases

Implementations MUST also reject:

- **Bundle deserialization with a mismatched signature length** (e.g., a `DilithiumML44` claim with 2419 or 2421 bytes payload) — error: `"expected 2420 bytes, got N"`.
- **`Future` variant in a v1 finalize call** — error: `"Future signature variant not supported in PSBS v1"`.
- **Combine with conflicting `previous_outpoint` between two inputs** — error: `CombineError::PreviousTxidMismatch`.

## 9. References

### 9.1 Sophis-internal

- `wallet/pskt/DESIGN.md` — design rationale and decisions D1–D5 in long form.
- `wallet/pskt/src/{crypto,input,output,global,pskt,bundle}.rs` — reference implementation.
- `dilithium-wallet/src/main.rs` (`cmd_pskt_*` functions) — CLI workflow.
- `consensus/core/src/sign.rs` — canonical Dilithium signing primitive used by Signer.
- `consensus/core/src/hashing/sighash.rs` — `calc_signature_hash` consumed by Signer.
- `crypto/txscript/src/standard/dilithium_redeem_script` — P2SH-Dilithium redeem script construction used in Constructor.
- `wallet/aa-spec/SPEC.md` — Account Abstraction spec; multisig finalize path depends on this.

### 9.2 External

- BIP-174 (Andrew Chow, 2017) — *Partially Signed Bitcoin Transaction Format*. The conceptual ancestor of PSBS.
- BIP-370 (Andrew Chow, 2020) — *PSBT Version 2*. Discusses field semantics that PSBS adopts (input/output modifiability flags).
- Kaspa PSKT (rusty-kaspa codebase, `wallet/pskt/`) — secp256k1 implementation that PSBS replaces.
- FIPS 204 (NIST, August 2024) — *Module-Lattice-Based Digital Signature Algorithm*. The ML-DSA-44 specification PSBS depends on.
- libcrux-ml-dsa (https://github.com/cryspen/libcrux) — reference Rust ML-DSA implementation used by Sophis.

### 9.3 Anti-patterns considered and rejected

- Hybrid (classical + PQ) signature support — rejected per `wallet/aa-spec/ANTI_PATTERNS.md` §10.
- Aggregate Dilithium signatures in v1 — rejected per `wallet/aa-spec/ANTI_PATTERNS.md` §9 (no production-ready scheme as of 2026).
- Reusing Kaspa PSKT magic bytes — rejected per `wallet/pskt/DESIGN.md` D5 (would invite silent mis-parsing).

## 10. Copyright

This SIP is released into the public domain (CC0).
