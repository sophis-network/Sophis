# Sophis Wallet Descriptors — Design Document

**Status:** Design freeze for K3 implementation. Will graduate to formal SIP-2 in K3.7.

**Author:** Hiroshi Tatakawa <sophis-network@proton.me>

**Date:** 2026-05-09

**Replaces:** none (greenfield).

**Companion:** SIP-1 (PSBS — `SIPS/SIP-1-PSBS.md`); descriptor language is the textual identifier of wallets that PSBS coordinates over.

---

## 1. Context and motivation

A **wallet descriptor** is a short text string that fully describes a wallet's spend conditions. Bitcoin's BIP-380 (Andrew Chow, 2021) defines the canonical example — `pkh(xpub.../0/*)#abcd1234` describes a hierarchical deterministic single-sig wallet, and `multi(2,xpub.../0/*,xpub.../0/*,xpub.../0/*)#xyz` describes a 2-of-3 multisig wallet. Bitcoin Core, Electrum, BlueWallet, Sparrow, and others all consume the same format.

Sophis needs the same primitive for three reasons:

1. **Backup is text, not a 24-word card.** A descriptor `pkh-mldsa44(<vk-hex>)#checksum` can be written down, scanned as QR, transmitted as plain text, and unambiguously imported into a different wallet implementation. The seed phrase remains the secret; the descriptor is the public identity of the wallet.
2. **Watch-only wallets are first-class.** A descriptor lets a wallet observe an address's balance and history without holding the signing key. Critical for accountants, treasury auditors, and exchange listings.
3. **Multisig coordination needs a common schema.** Once Account Abstraction (J1, `wallet/aa-spec/`) lands, multisig accounts need a textual format that participants can exchange to confirm "we are configuring the same wallet". Without a descriptor language, every wallet implementation invents an ad-hoc JSON schema.

Without descriptors:

- Hardware wallet vendors must invent per-vendor wire formats for "import this wallet"
- Backup recovery requires re-running key derivation in the original wallet (cross-wallet portability is broken)
- Multisig coordination across wallets is structurally impossible

Sophis adopts the BIP-380 *concept* (textual descriptor language with checksum) while adapting the *contents* (Dilithium ML-DSA-44 keys, no HD derivation, no Schnorr/Taproot script types) to match the actual Sophis chain.

## 2. Vocabulary

| Term | Meaning |
|---|---|
| **Descriptor** | A text string that describes a wallet's spend conditions. Begins with a script type (`pkh-mldsa44`, `multi-mldsa44`), parenthesizes one or more keys, optionally suffixes a key origin block, and ends with `#` plus an 8-character checksum |
| **Script type** | The first identifier of a descriptor: `pkh-mldsa44` (pay-to-pubkey-hash, single-sig) or `multi-mldsa44` (k-of-n multisig) in Sophis v1 |
| **Key expression** | The representation of a single Dilithium public key inside a descriptor. In v1, this is a 1312-byte verification key encoded as 2624 hex characters, optionally prefixed by a key origin block in square brackets |
| **Key origin** | A square-bracketed annotation `[fingerprint/derivation/path]` recording the master fingerprint and BIP-32-style derivation path that produced the key. In Sophis v1, derivation paths are reserved syntax (D1) — the parser accepts them but rejects them at resolve time |
| **Fingerprint** | A 4-byte identifier of a Dilithium public key, computed as the first 4 bytes of `SHA3-384(verification_key_bytes)`. Encoded as 8 hex characters |
| **Checksum** | The 8-character suffix after `#`, computed via the same Bech32-style polymod and alphabet defined in BIP-380. Sophis reuses this verbatim |
| **Resolve** | The operation that converts a descriptor into one or more `ScriptPublicKey` values consumable by the Sophis consensus rules |

## 3. Decisions (D1–D5) — ratified pre-implementation

These five decisions are the load-bearing structural choices for the Sophis descriptor language. Each was selected from a small set of alternatives, and the rejected alternatives are recorded so future maintainers can revisit if circumstances change.

### D1 — HD derivation: static keys only in v1

**Decision:** Descriptor key expressions accept only **literal Dilithium verification keys** in v1, encoded as 2624 hex characters. The BIP-380 syntax `xpub.../0/*` is reserved (the parser recognizes it) but **rejected at resolve time** with `ResolveError::HdDerivationNotYetSupported`.

**Rationale:** Sophis derives a single Dilithium keypair from a 24-word BIP-39 mnemonic via PBKDF2 — `1 mnemonic = 1 keypair`. There is no NIST-blessed BIP-32 equivalent for ML-DSA in 2026. Implementing pseudo-HD derivation locally would be inventing cryptography, which Sophis explicitly avoids. The reserved syntax means that when (and if) a NIST scheme emerges, descriptors that reference it can be parsed by old tooling and resolved by new tooling — no syntactic break.

**Rejected alternative (B): pseudo-HD scheme invented for Sophis.** Rejected because inventing key-derivation cryptography is the highest-risk activity any chain can undertake. Any error becomes irreversible (it ships in users' backup descriptors).

**Rejected alternative (C): omit the `xpub.../0/*` syntax entirely.** Rejected because it would force a syntactic break later if HD is added. Reserving the syntax now is cheap.

### D2 — Multi descriptors: parse-only, resolve fails

**Decision:** `multi-mldsa44(k, k1, k2, ..., kn)` is **fully parsed and serialized** by the v1 implementation. The `Display` impl preserves the exact textual form. However, `resolve()` returns `Err(ResolveError::MultiSigNotYetSupported)` pointing maintainers at `wallet/aa-spec/` (J1 — Account Abstraction).

**Rationale:** Multisig requires a redeem-script primitive that does not exist in Sophis (`OpCheckMultiSig` is disabled; aggregate Dilithium signatures are research-grade). Real multisig comes via J1's Account Abstraction contracts. The descriptor syntax exists now so that:

- J1 implementers can plug into a stable textual format when their work lands
- Wallet vendors can begin parsing/displaying multisig descriptors before the resolve path is wired
- Test vectors can exercise the syntax even without runtime semantics

**Rejected alternative (B): omit `multi-mldsa44` from v1 entirely.** Rejected because it would force a parser break when J1 lands. Better to define syntax once and unblock resolve later.

### D3 — Crate location: separate `wallet/descriptors/`

**Decision:** New workspace member `wallet/descriptors/` (crate name `sophis-wallet-descriptors`).

**Rationale:** Descriptors and PSBS (`wallet/pskt/`) are conceptually separate — descriptors describe wallet identity, PSBS describes transaction state. Coupling them in one crate would create a subtle import-cycle risk if either grows. Pattern matches the rest of the wallet stack (`wallet/bip32`, `wallet/keys`, `wallet/macros`, `wallet/native`, `wallet/wasm`, etc.).

**Rejected alternative (B): module inside `wallet/pskt/`.** Rejected for the coupling reason above.

### D4 — Fingerprint algorithm: SHA3-384 truncated to 4 bytes

**Decision:** `fingerprint(vk)` = first 4 bytes of `SHA3-384(vk)`, where `vk` is the canonical 1312-byte ML-DSA-44 verification key.

**Rationale:** BIP-32 fingerprints use `RIPEMD-160(SHA-256(pubkey))[..4]`. Sophis cannot reuse this — `RIPEMD-160` is not a primitive available across the Sophis crypto stack, and adopting it would add a dependency for the sake of mimicry. SHA3-384 is already used elsewhere in Sophis (notably in Phase 6 DA `bundle_id_of`), so reusing it for fingerprint:

1. Keeps the cryptographic primitive set small (less audit surface)
2. Provides 384 bits of pre-truncation security, comfortably more than the 4-byte target
3. Has the same 4-byte output that BIP-32 wallets are already used to displaying

**Rejected alternative (B): SHA-256 truncated.** Rejected because SHA-256 is not in Sophis's PQC-aligned primitive set; the project favors SHA-3 family for new uses.

**Rejected alternative (C): BLAKE3 truncated.** Rejected because BLAKE3 is not currently a Sophis dependency; adding it for a single 4-byte derivation is not worth the surface increase.

### D5 — Checksum: BIP-380 polymod verbatim

**Decision:** Sophis reuses the BIP-380 checksum scheme verbatim — same alphabet (96 characters), same generator polynomials, same 8-character output, same `#` separator.

**Rationale:** The BIP-380 checksum is well-tested (deployed in Bitcoin Core since 2021), has good error-detection properties (catches all single-character substitutions, catches most 2-character swaps), and the alphabet is already designed to cover the characters wallet descriptors use (`0-9`, `a-z`, `A-Z`, `()[],'/*`, etc.). Inventing a Sophis-specific checksum would have no cryptographic benefit and would prevent users from copy-pasting checksums between Bitcoin and Sophis tooling (which most descriptor-aware wallets already process).

The BIP-380 alphabet is a superset of what Sophis descriptors need — Sophis uses `pkh-mldsa44`, `multi-mldsa44`, `0-9`, `a-z`, `A-Z`, `()[],/`. All within the BIP-380 alphabet. The hyphen `-` in `pkh-mldsa44` is in the alphabet.

**Rejected alternative (B): Sophis-specific polymod with different generators.** Rejected for portability reasons above.

**Rejected alternative (C): No checksum.** Rejected because descriptors are typed/copy-pasted by humans; a single-character error in a 2624-character vk hex string would silently produce a wrong wallet address. Checksum is a hard safety requirement.

## 4. Grammar (BNF-style)

```
descriptor      ::= script_expr "#" checksum
script_expr     ::= pkh_expr | multi_expr
pkh_expr        ::= "pkh-mldsa44(" key_expr ")"
multi_expr      ::= "multi-mldsa44(" threshold "," key_expr ("," key_expr)+ ")"
threshold       ::= integer  ; 1 ≤ threshold ≤ key_count
key_expr        ::= [ key_origin ] key_data
key_origin      ::= "[" fingerprint_hex ( "/" derivation_step )* "]"
fingerprint_hex ::= 8 * hex_digit
derivation_step ::= integer [ "'" | "h" ]   ; ' or h denote hardened (parsed but reserved per D1)
key_data        ::= vk_hex | xpub_expr   ; only vk_hex resolves in v1
vk_hex          ::= 2624 * hex_digit       ; 1312 bytes ML-DSA-44 verification key
xpub_expr       ::= "xpub" arbitrary_chars ; reserved syntax, NotImplemented at resolve (D1)
checksum        ::= 8 * checksum_char
checksum_char   ::= one of BIP-380 alphabet (96 chars)
hex_digit       ::= "0" .. "9" | "a" .. "f" | "A" .. "F"
integer         ::= digit+
digit           ::= "0" .. "9"
```

**Notes on the grammar:**

- Whitespace inside `pkh-mldsa44(...)` or `multi-mldsa44(...)` is **not allowed**. The descriptor is a single contiguous token (followed by `#` and 8 checksum chars).
- `vk_hex` is case-insensitive at parse time; the canonical Display form is **lowercase**. Round-trip through parse + display normalizes case.
- `multi-mldsa44` requires `threshold ≥ 1` and `threshold ≤ key_count`. Implementations MUST reject `multi-mldsa44(0, ...)` and `multi-mldsa44(N, k1, ..., kM)` where `N > M`.
- Maximum keys in a `multi-mldsa44`: **15** (matches Sophis-conservative defaults; J1 spec at most allows 16 guardians, and one slot is reserved for the threshold-not-included signer if any). Implementations MUST reject `multi-mldsa44` with more than 15 keys.

## 5. Examples (canonical)

### 5.1 Single-sig

```
pkh-mldsa44(c2bd0a31fae37a... [2624 hex chars total] ...4f02bc78)#qe09xy0z
```

The vk hex string is 2624 characters (1312 bytes × 2). Eliding for readability.

### 5.2 Single-sig with key origin

```
pkh-mldsa44([f3a4c108/44h/2025h/0h]c2bd0a31fae37a...4f02bc78)#m5d3rga2
```

The key origin block `[f3a4c108/44h/2025h/0h]`:
- `f3a4c108` — fingerprint of the master key (8 hex chars = 4 bytes)
- `/44h/2025h/0h` — derivation path (Sophis network coin type `2025` is reserved-by-convention; `h` denotes hardened). **In v1, this path is parsed but rejected at resolve time.**

### 5.3 Multisig 2-of-3

```
multi-mldsa44(2,a1b2c3...d4e5f6,1234ab...cd56ef,9988aa...77ccbb)#x7yz4mn5
```

Three vk hex strings, each 2624 chars. Eliding for readability.

### 5.4 Multisig with key origins

```
multi-mldsa44(2,[f3a4c108/44h/2025h/0h]a1b2c3...d4e5f6,[7e9c1d22/44h/2025h/0h]1234ab...cd56ef,[58e3a012/44h/2025h/0h]9988aa...77ccbb)#abcdefgh
```

Each key has its own origin annotation.

## 6. Fingerprint specification

```
fn fingerprint(vk_bytes: &[u8; 1312]) -> [u8; 4] {
    use sha3::{Digest, Sha3_384};
    let hash = Sha3_384::digest(vk_bytes);
    let mut fp = [0u8; 4];
    fp.copy_from_slice(&hash[..4]);
    fp
}
```

Encoded textually as 8 lowercase hex characters when emitted in a descriptor `key_origin` block.

**Properties:**

- **Deterministic:** the same vk always produces the same fingerprint
- **Collision-resistant:** with 32 bits of output, a random collision requires ≈ 2^16 distinct keys (birthday bound). For wallet-identification purposes — distinguishing a few keys held by the same user — this is more than sufficient. Fingerprints are not security-load-bearing; they are a usability aid for displaying which key is which
- **Versionable:** a future SIP can adopt a different hash by introducing a `pkh-mldsa44-v2` script type without breaking v1 parsers

## 7. Checksum specification

The checksum is computed exactly as BIP-380 specifies, with the Sophis descriptor as the input string (the part before `#`). The reference algorithm is well-documented in BIP-380; the Sophis implementation reuses it verbatim, including:

- The alphabet (96 characters)
- The generator polynomials `[0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd]`
- The polymod function
- The `0x3fffffff` final XOR
- The 8-character output (5 bits per character)

**Implementation reference:** see `wallet/descriptors/src/checksum.rs` (forthcoming K3.5).

**Test vector to validate the polymod implementation:** the Bitcoin Core test vector for `pkh(c34dffe6ec38c0a44e0e1d76e2398fa9bd...)#qm0hatk0` MUST produce identical bytes when fed into the Sophis polymod. (The Sophis script type `pkh-mldsa44` is different, but the underlying polymod is the same — same alphabet, same generators, so the same input string must produce the same checksum bytes regardless of which chain is consuming it.)

## 8. Resolve semantics (single-sig only in v1)

```
fn resolve(d: &Descriptor) -> Result<Vec<ScriptPublicKey>, ResolveError> {
    match d {
        Descriptor::Pkh { key } => match key {
            KeyData::VkHex(vk_bytes) => {
                let redeem_script = sophis_txscript::standard::dilithium_redeem_script(vk_bytes)?;
                let spk = sophis_txscript::standard::pay_to_script_hash_script(&redeem_script);
                Ok(vec![spk])
            }
            KeyData::XpubReserved(_) => Err(ResolveError::HdDerivationNotYetSupported),
        },
        Descriptor::Multi { .. } => Err(ResolveError::MultiSigNotYetSupported),
    }
}
```

**Notes:**

- v1 always returns a singleton `Vec` for `Pkh`. The `Vec` return type anticipates future HD descriptors that resolve to multiple addresses (one per derivation index).
- Multi-resolve fails **even with all valid keys** because Sophis has no consensus-supported multisig scheme yet. The error message MUST point at `wallet/aa-spec/` so that users understand the gap is intentional and tracked.

## 9. Errors

```
pub enum ParseError {
    InvalidScriptType(String),                  // unknown script_expr keyword
    UnclosedParenthesis,                        // missing ')'
    UnclosedBracket,                            // missing ']'
    EmptyKeyList,                               // multi-mldsa44(2)
    ThresholdOutOfRange { threshold: u32, max: u32 },
    TooManyKeys { provided: usize, max: usize }, // > 15 keys in multi
    InvalidVkLength { provided: usize, expected: usize },  // not 2624 hex chars
    InvalidVkHex(String),                       // non-hex characters in vk
    InvalidFingerprintLength,                   // not 8 hex chars
    InvalidFingerprintHex,                      // non-hex characters in fingerprint
    InvalidDerivationStep(String),              // bad integer or unknown suffix
    MissingChecksum,                            // no '#' or short checksum
    InvalidChecksumChar(char),                  // char outside BIP-380 alphabet
    ChecksumMismatch { expected: String, actual: String },
}

pub enum ResolveError {
    HdDerivationNotYetSupported,                // xpub/derivation in v1
    MultiSigNotYetSupported,                    // multi-mldsa44 in v1
    RedeemScriptError(String),                  // upstream txscript failure
}
```

Each error MUST carry enough context for the caller to construct a useful user-facing message. The reference CLI (`dilithium-wallet descriptor` subcommand, forthcoming) MUST translate these to localized messages.

## 10. Test vectors plan

Canonical test vectors live in `wallet/descriptors/tests/canonical_vectors.rs` (K3.7). Minimum required:

1. **Fingerprint determinism.** Derive `(vk, _)` from PSBS test seed `b"PSBS_test_seed_alpha____________"` (matches K1.3); compute fingerprint; assert byte-exact match against a hard-coded expected `[u8; 4]`.
2. **Pkh round-trip.** Build `Descriptor::Pkh { key: KeyData::VkHex(vk) }`, compute its `Display` form, parse the result, assert structural equality.
3. **Pkh with key origin round-trip.** Same as above with a `key_origin` block; verify the origin survives the round-trip byte-for-byte.
4. **Multi structural round-trip.** Build `Descriptor::Multi { threshold: 2, keys: vec![...3 keys...] }`, Display, parse, equal. **Resolve MUST fail** with `MultiSigNotYetSupported`.
5. **HD `xpub.../0/*` parsed but resolve-rejected.** Hardcode a valid descriptor with `xpub` syntax; parse succeeds; resolve fails with `HdDerivationNotYetSupported`.
6. **Pkh resolve produces correct ScriptPublicKey.** Resolve a single-sig descriptor; compare the resulting `ScriptPublicKey` byte-for-byte against the SPK that `dilithium-wallet keygen` produces for the same vk.
7. **Checksum verification rejects 1-character corruption.** Take a valid descriptor, flip one character in the checksum, assert `ChecksumMismatch` error.
8. **BIP-380 cross-vector compatibility.** Feed a known BIP-380 input string (without the Sophis script type, just the polymod content) into the Sophis polymod; assert the same checksum bytes as Bitcoin Core's reference test vector.
9. **Boundary tests:** `multi-mldsa44(0, ...)` rejected; `multi-mldsa44(3, k1, k2)` rejected; `multi-mldsa44(2, k1, k2, ..., k16)` rejected (too many keys); `pkh-mldsa44()` rejected (no key).

## 11. Security considerations

### 11.1 Confidentiality

Descriptors are **not secret**. They contain only public verification keys. Users may publish them, share them, store them in cloud backups. The signing key (mnemonic seed) remains the secret.

### 11.2 Authenticity

A descriptor is not signed. Anyone can construct a descriptor that *claims* to belong to anyone — the descriptor `pkh-mldsa44(<attacker's vk>)#valid_checksum` is syntactically valid for the attacker's key. **Wallet implementers MUST display the resolved address(es) to the user before importing**, allowing the user to compare with whatever channel the descriptor came from.

### 11.3 Checksum is for typo detection, not adversarial integrity

The 8-character checksum catches all single-character substitutions and most 2-character swaps. It does **not** prevent a malicious actor from crafting a descriptor with any specific content + valid checksum. This is the same property as BIP-380; the checksum exists for typos in human transcription, not for adversarial integrity.

### 11.4 vk hex case-insensitivity at parse time

Parsers MUST accept both uppercase and lowercase hex in the vk field. Display always emits lowercase. This means `pkh-mldsa44(ABCD...)#xxxx` and `pkh-mldsa44(abcd...)#yyyy` may have **different checksums** even though they represent the same key. Wallet implementers MUST canonicalize (lowercase) before computing the checksum on input from a user.

### 11.5 Reserved future syntax

- The `xpub.../0/*` syntax is reserved (D1). v1 implementations MUST parse it without error and MUST fail at resolve. Future SIPs may activate it.
- The `taproot-mldsa44(...)`, `wpkh-mldsa44(...)`, and `tr-mldsa44(...)` script types do NOT exist and MUST be rejected at parse time. (These are Bitcoin-specific witness types that have no Sophis equivalent.)
- Future script types (e.g., once J1 AA contracts have stable identifiers) will use new keywords distinguishable from existing ones.

### 11.6 No on-chain footprint

This SIP defines a textual format. It does not change consensus, transaction format, sighash, or any on-chain data structure. The only on-chain implication is that resolved descriptors produce ScriptPublicKey values, which are themselves unchanged by this SIP.

## 12. Out-of-scope

| Topic | Status |
|---|---|
| HD derivation for Dilithium | Reserved syntax; no resolve in v1 (D1) |
| `multi-mldsa44` resolve | Parse-only; resolve depends on J1 (D2) |
| BIP-32 / SLIP-0010 derivation paths for ML-DSA | Out of scope; would require NIST-standardized scheme |
| Multipath descriptors `<0;1>/*` | Out of scope; HD-dependent |
| Miniscript / Output Descriptors compositional algebra | Out of scope; future SIP if demand emerges |
| Taproot / Witness / SegWit descriptors | Permanently out of scope; Sophis has no equivalent |
| Threshold signature schemes (FROST-style) | Out of scope; no production-ready Dilithium scheme |

## 13. Reference implementation roadmap

This design corresponds to the K3 sub-phase plan tracked in TaskList:

- **K3.0** (this document) — Design freeze. ← *current*
- **K3.1** — Crate scaffold `sophis-wallet-descriptors` + types
- **K3.2** — Fingerprint via SHA3-384[..4] + tests
- **K3.3** — Parser (`pkh-mldsa44`, `multi-mldsa44`, key origin)
- **K3.4** — `Display` impl + round-trip tests
- **K3.5** — Checksum bech32-style polymod
- **K3.6** — Resolve `pkh-mldsa44` → ScriptPublicKey
- **K3.7** — Test vectors + integration

After K3.7, the descriptor language is implementation-complete for v1 single-sig. Multi-sig resolve unlocks when J1 lands (`wallet/aa-spec/`). HD resolve unlocks when (and if) NIST publishes a BIP-32-equivalent for ML-DSA.

## 14. SIP publication checklist

Before the descriptor language is published as SIP-2:

- [ ] All 9 test vectors in §10 pass
- [ ] BIP-380 cross-vector compatibility test passes
- [ ] At least one independent wallet implementer has reviewed the spec
- [ ] At least one fuzz test (random valid input → parse → display → re-parse → equal) has run for ≥ 1 hour without panic
- [ ] Public RFC opened with 30-day comment window
- [ ] 60-day no-changes period after comment window closes
- [ ] Reference implementation cited in §13 is merged and tagged

After this checklist completes, this DESIGN.md is reformatted and republished as `SIPS/SIP-2-DESCRIPTORS.md` following the SIP-template.md format (same as SIP-1 was structured from `wallet/pskt/DESIGN.md`).

## 15. Appendix A: ML-DSA-44 sizes (reminder)

| Component | Bytes | Hex chars |
|---|---|---|
| Verification key | 1312 | 2624 |
| Signing key | 2560 | 5120 (irrelevant — never appears in descriptors) |
| Signature | 2420 | 4840 (irrelevant — descriptors describe wallets, not transactions) |
| Fingerprint (SHA3-384[..4]) | 4 | 8 |

## 16. Appendix B: Reference dependencies

Existing Sophis components that K3 implementation MUST reuse (do NOT duplicate):

- `sha3` crate (workspace) — for Sha3_384 in fingerprint computation
- `hex` crate (workspace) — for vk hex encoding/decoding
- `sophis_consensus_core::tx::ScriptPublicKey` — output type of resolve
- `sophis_txscript::standard::{dilithium_redeem_script, pay_to_script_hash_script}` — used in resolve for `pkh-mldsa44`
- `sophis_wallet_pskt::crypto::{DilithiumPubKey, DILITHIUM44_VK_SIZE}` — vk type and size constant

The descriptor crate adds NO new external dependencies beyond what Sophis already vendors.

## 17. Last touched

2026-05-09 — initial pre-implementation draft. K3.1 may be started against this document. Maintainers MAY propose changes via SIP discussion when this graduates to SIP-2.
