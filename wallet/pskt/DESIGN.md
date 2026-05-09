# PSBS — Partially Signed Sophis Transactions (Dilithium-aware)

**Status:** Design freeze for K1 implementation. Will graduate to formal SIP-1 in K1.5.

**Author:** Hiroshi Tatakawa <sophis-network@proton.me>

**Date:** 2026-05-09

**Replaces:** PSKT (Kaspa-derived, secp256k1-only) — incompatible with Sophis (PQC-only chain).

---

## 1. Context and motivation

Sophis is PQC-only at the consensus layer (Dilithium ML-DSA-44, opcode `0xc4`). The PSKT crate inherited from rusty-kaspa carries the structural workflow (Creator → Updater → Signer → Combiner → Finalizer → Extractor) that any non-trivial wallet flow needs — hardware wallet signing, cold storage, multisig coordination, offline signing — but its internal types are bound to `secp256k1::PublicKey` and `Signature::{ECDSA, Schnorr}`, both of which are inert in Sophis (Schnorr opcodes return `OpcodeDisabled`).

PSBS is the Dilithium-aware redesign of the same workflow. **It is not a migration of PSKT** — the wire format is incompatible by construction (Dilithium VK is 1312 B vs secp256k1 PK 33 B; signatures are 2420 B vs 64 B). PSBS uses its own magic bytes so any tool attempting to parse a PSBS container as PSKT (or vice versa) fails loudly rather than mis-parsing.

This document freezes the design decisions for K1 implementation. It is not yet SIP-1 — the formal SIP follows in sub-phase K1.5 once test vectors and reference implementation are validated.

## 2. Design decisions (ratified)

| ID | Decision | Choice | Rationale |
|---|---|---|---|
| **D1** | `bip32_derivations` field | **Removed** | Sophis has no hierarchical deterministic derivation for Dilithium. The mnemonic-to-keypair derivation is direct (BIP-39 PBKDF2 → 64-byte seed → first 32 bytes → `ml_dsa_44::generate_key_pair`). Without hierarchy, the field has no math semantics. Repurposing as opaque labels would invite metadata abuse without delivering disambiguation that wallets cannot already track internally. |
| **D2** | `Xpub` field in `Global` | **Removed** | Same reason as D1. Extended public keys are a hierarchical derivation concept; Sophis has none. Reserving the slot "for future" pollutes the wire format with a field that is structurally meaningless today. If Dilithium hierarchical derivation ever standardizes, PSBS-v2 can reintroduce it cleanly. |
| **D3** | `PartialSigs` storage | **`Vec<(DilithiumPubKey, Signature)>`** | Map keyed by 1312-byte pubkey is wasteful (every lookup hashes/compares 1.3 KB). A vector preserves deterministic signing order, has trivial linear lookup (multisig N-of-M typically ≤ 7), and serializes naturally. |
| **D4** | `Signature` enum extensibility | **Versioned: `DilithiumML44(...)` + `Future(...)`** | Dilithium is a parameter family (ML-DSA-44 / -65 / -87). Sophis ships with -44 (smallest), but may promote to -65 in the future for higher security. A 1-byte variant discriminator is cheap insurance against PSBS-v2 hard fork purely to add an algorithm. |
| **D5** | Wire format magic | **Own magic bytes (`0x70 0x73 0x62 0x73` = ASCII `"psbs"`)** | Reusing PSKT magic would let Kaspa tooling mis-parse PSBS payloads silently. Different magic = explicit fail-loud incompatibility. |

## 3. Canonical types (Rust)

These are the source-of-truth type signatures. The implementation in `wallet/pskt/src/` must match these exactly.

```rust
// ============================================================================
// Cryptographic primitives — fixed sizes per FIPS 204
// ============================================================================

/// ML-DSA-44 verification key. Fixed 1312 bytes.
#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DilithiumPubKey(pub [u8; 1312]);

/// Versioned signature container.
/// Variant byte allows future Dilithium parameter sets without wire format break.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub enum Signature {
    /// CRYSTALS-Dilithium ML-DSA-44 (FIPS 204). Fixed 2420 bytes.
    /// Default and only variant produced by Sophis at v1.
    DilithiumML44([u8; 2420]),

    /// Reserved for future Dilithium variants (ML-DSA-65 / -87) or other
    /// PQC schemes adopted via SIP. Payload is variant-defined.
    /// MUST NOT be produced by v1 Sophis tooling. v1 verifiers MUST reject.
    Future {
        variant: u8,
        payload: Vec<u8>,
    },
}

/// Pair of (public key, signature). Used in `partial_sigs` and finalized scripts.
pub type PartialSig = (DilithiumPubKey, Signature);

// ============================================================================
// PSBS container
// ============================================================================

/// PSBS magic bytes: ASCII "psbs". Used as discriminator at parse time.
pub const PSBS_MAGIC: [u8; 4] = *b"psbs";

/// PSBS format version. v1 = this design.
pub const PSBS_VERSION: u16 = 1;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Psbs {
    pub magic: [u8; 4],          // == PSBS_MAGIC
    pub version: u16,            // == PSBS_VERSION (== 1 for v1)
    pub global: Global,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Global {
    /// Sophis transaction version (matches consensus tx version).
    pub tx_version: u16,

    /// Optional fallback locktime if no Input declares one.
    pub fallback_locktime: Option<u64>,

    /// Reserved for future use. v1 = empty.
    /// Format: arbitrary key-value pairs; each pair is a Vec<u8>.
    /// Wallets MUST preserve unknown proprietary fields when round-tripping.
    pub proprietary: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Input {
    /// Outpoint being spent.
    pub previous_outpoint: TransactionOutpoint,

    /// UTXO being spent (witness data — `value`, `script_public_key`, etc.).
    /// Required for signing (sighash computation needs UTXO info).
    /// Optional in early Creator-stage PSBS; required by Signer onward.
    pub utxo: Option<TransactionOutput>,

    /// Sequence number for this input.
    pub sequence: Option<u64>,

    /// Sighash type to use. Default: SIGHASH_ALL.
    pub sighash_type: Option<SigHashType>,

    /// Redeem script for P2SH inputs. Required when `utxo.script_public_key`
    /// is a P2SH script (script-hash output type).
    pub redeem_script: Option<Vec<u8>>,

    /// Partial signatures collected so far, in deterministic order
    /// (lexicographic by public key bytes).
    pub partial_sigs: Vec<PartialSig>,

    /// Final signature script after Finalizer runs. None until then.
    /// Format: serialized Sophis script bytes ready for `tx.inputs[i].signature_script`.
    pub final_script_sig: Option<Vec<u8>>,

    /// Reserved for future use.
    pub proprietary: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Output {
    pub amount: u64,
    pub script_public_key: ScriptPublicKey,

    /// Redeem script for P2SH outputs (informational only — not used in
    /// signing, but useful for auditability and watch-only wallets that
    /// want to recognize their own change outputs).
    pub redeem_script: Option<Vec<u8>>,

    /// Reserved for future use.
    pub proprietary: Vec<(Vec<u8>, Vec<u8>)>,
}
```

## 4. Wire format

PSBS is borsh-encoded. The full container serializes in field order as defined in `Psbs`:

```
[ magic: 4 B ]
[ version: 2 B little-endian (borsh u16) ]
[ global: Global ]
[ inputs: Vec<Input> ]
[ outputs: Vec<Output> ]
```

Each `Vec<T>` is borsh-encoded as `[ length: 4 B u32 ][ T0 ][ T1 ]...`.

Each `Option<T>` is borsh-encoded as `[ tag: 1 B (0=None, 1=Some) ][ T if Some ]`.

Enums (`Signature`) are borsh-encoded as `[ discriminant: 1 B ][ variant payload ]`.

A typical 1-input 1-output PSBS containing one Dilithium signature serializes to roughly:

| Component | Size |
|---|---|
| magic + version | 6 B |
| global (minimal) | ~10 B |
| input header (outpoint + UTXO + sighash + flags) | ~80 B |
| 1 partial_sig (1 DilithiumPubKey + 1 DilithiumML44 sig + tag bytes) | 1312 + 2420 + ~5 = **~3737 B** |
| output | ~50 B |
| **Total** | **~3.9 KB** |

A 2-of-3 multisig PSBS adds 2 more partial_sigs: **~3.9 KB + 2 × 3.7 KB ≈ 11.4 KB**. Within Sophis tx limits (32 KB block-typical).

A 5-of-9 multisig PSBS: **~3.9 KB + 4 more sigs ≈ 18.6 KB**. Still within limits but pressing. A 7-of-15 multisig is unsupported in v1 due to wire size; if needed, future PSBS-v2 may compress via aggregate signature schemes if Dilithium-aggregation matures.

## 5. PSBS workflow (roles)

PSBS follows the BIP-174 / Kaspa PSKT role model. Each role consumes a PSBS, performs a transformation, and produces a PSBS that can be passed to the next role. Roles are *capabilities*, not *machines* — one machine may play multiple roles in a single session.

### 5.1 Creator
**Input:** transaction outline (intended outputs, UTXOs being spent).
**Output:** PSBS with `inputs` populated with `previous_outpoint` only (no UTXO data, no sigs yet) and `outputs` populated.

The Creator is the role that decides "I want to spend X to Y". Typically the wallet UI initiates this.

### 5.2 Updater
**Input:** Creator-stage PSBS.
**Output:** PSBS with `utxo` and `redeem_script` fields populated for every input.

The Updater is the role that knows the current UTXO set — a node, an indexer, or a watch-only wallet. The Signer cannot work without UTXO data because sighash computation requires it.

### 5.3 Signer
**Input:** Updater-stage PSBS (UTXOs populated).
**Output:** PSBS with one or more new entries appended to `input.partial_sigs`.

The Signer holds a Dilithium signing key. For each input it can sign (i.e., its public key participates in the input's `redeem_script`), it computes the sighash and produces an MLDSA44 signature. Multiple Signers in series accumulate signatures.

**Signer MUST NOT modify any field other than `partial_sigs`.**

### 5.4 Combiner
**Input:** two or more PSBS instances representing the same underlying transaction.
**Output:** one PSBS with the union of `partial_sigs` across inputs, deduplicated.

Combiners do not require any keys. They are pure-data operations. Used when signing happens in parallel across multiple offline machines.

**Combiner MUST verify** that all input PSBS instances agree on `global`, `inputs[*].previous_outpoint`, `inputs[*].utxo`, `inputs[*].sighash_type`, `inputs[*].redeem_script`, and all `outputs`. Any mismatch is a hard error (caller's responsibility to resolve).

### 5.5 Finalizer
**Input:** PSBS with sufficient `partial_sigs` per input to satisfy the redeem script.
**Output:** PSBS with `input.final_script_sig` populated; `partial_sigs` cleared.

The Finalizer assembles the final signature script — for a P2SH multisig, that means concatenating the required signatures in the script's expected order, prefixing the redeem script. The result is a self-contained `signature_script` that any Sophis node will accept as input witness.

**Finalizer MUST verify each signature** before incorporating it (catches a malicious Signer corrupting the workflow).

### 5.6 Extractor
**Input:** Finalized PSBS (all inputs have `final_script_sig`).
**Output:** Sophis `Transaction` ready for broadcast.

The Extractor is the trivial conversion step. It reads `previous_outpoint`, `final_script_sig`, `sequence` from each input and `amount`, `script_public_key` from each output, and assembles a `Transaction` struct.

## 6. Test vectors plan

K1.5 will publish canonical test vectors. The plan:

1. **Single-sig P2PK**: derive a keypair from the canonical Sophis test mnemonic (`abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`), construct a Creator PSBS sending 1 SPHS to a known address, run through Updater → Signer → Finalizer → Extractor, and assert that the extracted Transaction matches a hex-pinned reference.

2. **2-of-3 multisig P2SH**: derive 3 keypairs from canonical test mnemonics, construct a multisig redeem script, fund a P2SH address, then construct a Creator PSBS spending from it, sign with 2 Signers in parallel, Combine, Finalize, Extract, assert transaction hex matches reference.

3. **PSBS round-trip**: every PSBS at every workflow stage must serialize and deserialize identically (borsh round-trip property).

4. **Cross-tooling negative test**: parsing a Kaspa PSKT (different magic) MUST fail with `InvalidMagic`. Parsing a v1 PSBS as a hypothetical v2 (different version) MUST fail with `UnsupportedVersion`.

5. **Adversarial Signer test**: a Signer producing a syntactically valid but cryptographically invalid signature (e.g., random 2420 bytes) MUST be rejected by the Finalizer's signature verification step.

## 7. Security considerations

### 7.1 Confidentiality
PSBS is **not encrypted**. Anyone who intercepts a PSBS in transit learns the transaction outline (UTXOs, amounts, recipient addresses). This matches PSBT semantics. Confidentiality during transport is the user's responsibility (encrypted channel, sneakernet).

### 7.2 Authenticity at the signing stage
The Signer trusts that the Updater's UTXO data is accurate. A malicious Updater could lie about UTXO `value` to trick the Signer into signing a higher-value spend than expected. **Wallets that accept PSBS from external sources MUST display the UTXO values to the user before signing**, allowing the user to compare against an independent source.

### 7.3 Replay
A finalized PSBS is, by extraction, a complete Sophis transaction. Once broadcast, it can be replayed — but the protocol's UTXO-spent rule prevents the same UTXOs from being consumed twice. Replay across networks (mainnet vs testnet) is prevented by Sophis address prefix (`sophis:` vs `sophistest:`) and by the sighash including network-distinguishing data.

### 7.4 Signature verification timing
Finalizer signature verification uses constant-time `ml_dsa_44::verify` from `libcrux-ml-dsa`. No side channel from verification timing on the Finalizer side.

### 7.5 Signing key handling
**The Signer is the only role that touches signing keys.** Signing keys MUST NOT appear anywhere in the PSBS itself. Only verification keys (`DilithiumPubKey`) appear, and those are public.

A Signer running on an air-gapped machine reads a PSBS file, signs, writes a new PSBS file. The signing key never leaves the air-gapped machine.

### 7.6 Future signature variants
The `Signature::Future { variant, payload }` enum variant is reserved for SIP-defined future Dilithium parameter sets. **v1 Sophis tooling MUST reject any `Signature::Future`** at the Finalizer stage. Activation of a Future variant requires a SIP and concomitant consensus rule update (e.g., new opcode `OpCheckSigDilithium65` at a reserved opcode slot).

## 8. Implementation roadmap

This design corresponds to the K1 sub-phase plan tracked in TaskList:

- **K1.0** (this document) — Design freeze. ← *current*
- **K1.1** — Replace `secp256k1::PublicKey` and `Signature` enum in `wallet/pskt/src/`.
- **K1.2** — Remove `bip32_derivations` and `Xpub` fields per D1+D2.
- **K1.3** — Re-do tests with Dilithium keypairs.
- **K1.4** — Integrate `dilithium-wallet` CLI subcommands (`pskt create/sign/combine/finalize/extract`).
- **K1.5** — Publish formal SIP-1 with this design + test vectors + reference impl pointer.
- **K1.6** — Cleanup: remove `secp256k1` dependency from `wallet/pskt/Cargo.toml`.

After K1.6, the `wallet/pskt` crate is Dilithium-pure and PSBS is the foundation layer of the Sophis Coordination Stack (SCS), unlocking K3 (descriptors) and J1 (AA) work.

## 9. Open items deferred to future SIPs (NOT in K1)

- **Aggregate Dilithium signatures** (research-grade in 2026, no production-ready scheme). Would shrink multisig wire size.
- **Hierarchical deterministic derivation** for Dilithium. No standard exists; if one emerges (e.g., a NIST follow-up SP), PSBS-v2 may reintroduce `bip32_derivations` with proper semantics.
- **Encrypted PSBS transport format**. Out of scope; user-side responsibility.
- **PSBS-aware hardware wallet protocol**. Hardware wallet vendor adoption (Ledger, Trezor, Coldcard) requires PQC support that does not yet exist in shipping firmware. Until then, the air-gapped CLI `dilithium-wallet pskt sign` is the canonical Signer.
- **Multi-party computation (MPC) signers** producing collaborative Dilithium signatures. Research stage.

## Appendix A: Dilithium-2 (ML-DSA-44, FIPS 204) sizes

Per FIPS 204 published August 2024:

| Component | Size (bytes) |
|---|---|
| Verification key (public) | 1312 |
| Signing key (private) | 2560 |
| Signature | 2420 |
| Signing randomness input | 32 |

These sizes are constants. The `libcrux-ml-dsa` crate exposes them as type-level array sizes, validated at compile time.

## Appendix B: Reference implementation pointers

Existing Dilithium API in the codebase (DO NOT duplicate, REUSE):

- `consensus/core/src/sign.rs::sign_input_dilithium` — canonical sighash-then-sign for tx inputs.
- `crypto/txscript/src/lib.rs::OpCheckSigDilithium` (opcode `0xc4`) — canonical verification path used by consensus.
- `dilithium-wallet/src/main.rs::derive_dilithium_from_mnemonic` — BIP-39 → Dilithium keypair derivation.
- `libcrux_ml_dsa::ml_dsa_44::{generate_key_pair, sign, verify}` — primitive API.

The K1 PSBS implementation MUST call these APIs rather than reimplementing them. Any divergence in sighash computation or signature format would create a chain-incompatibility bug.
