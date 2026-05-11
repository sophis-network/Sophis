```
SIP: 5
Title: Wallet Descriptors (BIP-380-style, Dilithium-aware)
Author: Marcelo Delgado <sophis-network@proton.me>
Status: Draft
Type: Standards
Created: 2026-05-11
Requires: 1
```

# SIP-5: Wallet Descriptors (BIP-380-style, Dilithium-aware)

## 1. Abstract

This SIP defines a **wallet descriptor language** for Sophis — a short
text format that fully describes a wallet's spend conditions and that
multiple wallet implementations can consume interoperably. The
language adopts BIP-380's *concept* (textual descriptor with checksum)
while adapting the *contents* to Sophis (Dilithium ML-DSA-44 keys
instead of secp256k1, no HD derivation in v1, no Schnorr/Taproot
script types). Descriptors are client-side — they have no consensus
impact — and are the foundation primitive for backup/recovery,
watch-only wallets, hardware-wallet onboarding, and (once SIP-J1
Account Abstraction lands) multisig coordination across wallets.

## 2. Motivation

A wallet's identity is currently expressed only through one or more
addresses. Two problems follow:

1. **Backup recovery is implementation-coupled.** Recovering a wallet
   from a 24-word seed phrase requires running the same key-derivation
   steps that produced the original keypair — every wallet
   implementation invents its own. A descriptor decouples *what* the
   wallet contains from *how* the original wallet derived it.
2. **Watch-only wallets cannot exist portably.** A `pkh-mldsa44(vk)`
   descriptor lets accountants, treasury auditors, and exchange
   listing tools observe an address's balance and history *without
   holding the signing key*. Bitcoin solved this with BIP-380 in 2021;
   Sophis needs the equivalent.
3. **Multisig coordination needs a common schema.** Once Account
   Abstraction (see `wallet/aa-spec/`, future SIP) lands, multisig
   accounts will require a textual format that participants exchange
   to confirm "we are configuring the same wallet". Without a
   descriptor language, every wallet implementation invents an ad-hoc
   JSON schema, and cross-wallet multisig coordination is structurally
   impossible.

Sophis cannot reuse BIP-380 unmodified. Bitcoin descriptors carry
33-byte secp256k1 public keys and reference Bitcoin-specific script
types (`wpkh`, `tr`, `multi` over `OP_CHECKMULTISIG`). Sophis uses
1312-byte Dilithium ML-DSA-44 verification keys (Bitcoin's compressed
public-key encoding does not apply) and disables `OP_CHECKMULTISIG`
(opcode rejected with `OpcodeDisabled` since the PQC pivot of
2026-05-04). The Sophis descriptor language is therefore a fresh
specification that *reuses the BIP-380 surface grammar and checksum*
while replacing the type system underneath.

## 3. Specification

### 3.1 Vocabulary

| Term | Meaning |
|---|---|
| **Descriptor** | A text string that describes a wallet's spend conditions. Begins with a script type identifier, parenthesizes one or more keys, optionally suffixes a key origin block, and ends with `#` plus an 8-character checksum |
| **Script type** | The first identifier of a descriptor: `pkh-mldsa44` (pay-to-pubkey-hash, single-sig) or `multi-mldsa44` (k-of-n multisig) in v1 |
| **Key expression** | The representation of a single Dilithium public key inside a descriptor. In v1, this is a 1312-byte verification key encoded as 2624 hex characters, optionally prefixed by a key origin block in square brackets |
| **Key origin** | A square-bracketed annotation `[fingerprint/derivation/path]` recording the master fingerprint and BIP-32-style derivation path that produced the key. In v1, derivation paths are reserved syntax (see D1 in §4) — the parser accepts them but resolve rejects them |
| **Fingerprint** | A 4-byte identifier of a Dilithium public key, computed as the first 4 bytes of `SHA3-384(verification_key_bytes)`. Encoded as 8 hex characters |
| **Checksum** | The 8-character suffix after `#`, computed via the same Bech32-style polymod and alphabet defined in BIP-380. Sophis reuses this verbatim |
| **Resolve** | The operation that converts a descriptor into one or more `ScriptPublicKey` values consumable by Sophis consensus rules |

### 3.2 Grammar (BNF-style)

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
key_data        ::= vk_hex | xpub_expr      ; only vk_hex resolves in v1
vk_hex          ::= 2624 * hex_digit         ; 1312 bytes ML-DSA-44 verification key
xpub_expr       ::= "xpub" arbitrary_chars   ; reserved syntax, NotImplemented at resolve (D1)
checksum        ::= 8 * checksum_char
checksum_char   ::= one of BIP-380 alphabet (96 chars)
hex_digit       ::= "0" .. "9" | "a" .. "f" | "A" .. "F"
integer         ::= digit+
digit           ::= "0" .. "9"
```

**Notes on the grammar:**

- Whitespace inside `pkh-mldsa44(...)` or `multi-mldsa44(...)` is
  **not allowed**. The descriptor is a single contiguous token
  (followed by `#` and 8 checksum chars).
- `vk_hex` is case-insensitive at parse time; the canonical Display
  form is **lowercase**. Round-trip through parse + display
  normalizes case.
- `multi-mldsa44` requires `threshold ≥ 1` and `threshold ≤ key_count`.
  Implementations MUST reject `multi-mldsa44(0, ...)` and
  `multi-mldsa44(N, k1, ..., kM)` where `N > M`.
- Maximum keys in a `multi-mldsa44`: **15**. This matches the
  Sophis-conservative defaults of the AA spec (at most 16 guardians,
  one slot reserved for the threshold-not-included signer if any).
  Implementations MUST reject `multi-mldsa44` with more than 15 keys.

### 3.3 Fingerprint

```rust
fn fingerprint(vk_bytes: &[u8; 1312]) -> [u8; 4] {
    use sha3::{Digest, Sha3_384};
    let hash = Sha3_384::digest(vk_bytes);
    let mut fp = [0u8; 4];
    fp.copy_from_slice(&hash[..4]);
    fp
}
```

Encoded textually as 8 lowercase hex characters when emitted in a
descriptor `key_origin` block.

Properties:

- **Deterministic:** the same vk always produces the same fingerprint.
- **Collision-resistant for usability:** with 32 bits of output, a
  random collision requires ≈ 2¹⁶ distinct keys (birthday bound). For
  wallet-identification purposes — distinguishing a few keys held by
  the same user — this is more than sufficient. Fingerprints are not
  security-load-bearing; they are a usability aid for displaying which
  key is which.
- **Versionable:** a future SIP can adopt a different hash by
  introducing a `pkh-mldsa44-v2` script type without breaking v1
  parsers.

### 3.4 Checksum

The checksum is computed exactly as BIP-380 specifies, with the Sophis
descriptor as the input string (the part before `#`). The Sophis
implementation reuses the BIP-380 reference verbatim:

- The alphabet (96 characters)
- The generator polynomials
  `[0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd]`
- The polymod function
- The `0x3fffffff` final XOR
- The 8-character output (5 bits per character)

**Cross-chain compatibility:** the Bitcoin Core test vector for
`pkh(c34dffe6ec38c0a44e0e1d76e2398fa9bd...)#qm0hatk0` MUST produce
identical checksum bytes when fed into the Sophis polymod (the
underlying polymod is the same — same alphabet, same generators — so
the same input string must produce the same checksum bytes regardless
of which chain is consuming it). This property is exercised by an
integration test in the reference implementation (currently marked
`#[ignore]` pending hand-verification against an independent BIP-380
oracle; see §8).

### 3.5 Resolve semantics (single-sig only in v1)

```rust
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

Notes:

- v1 always returns a singleton `Vec` for `Pkh`. The `Vec` return
  type anticipates future HD descriptors that resolve to multiple
  addresses (one per derivation index).
- Multi-resolve fails **even with all valid keys** because Sophis has
  no consensus-supported multisig scheme yet. The error MUST point at
  `wallet/aa-spec/` so users understand the gap is intentional and
  tracked.

### 3.6 Errors

```rust
pub enum ParseError {
    InvalidScriptType(String),                  // unknown script_expr keyword
    UnclosedParenthesis,                        // missing ')'
    UnclosedBracket,                            // missing ']'
    EmptyKeyList,                               // multi-mldsa44(2)
    ThresholdOutOfRange { threshold: u32, max: u32 },
    TooManyKeys { provided: usize, max: usize }, // > 15 keys in multi
    InvalidVkLength { provided: usize, expected: usize },
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

Each error MUST carry enough context for the caller to construct a
useful user-facing message.

### 3.7 Canonical examples

Single-sig:

```
pkh-mldsa44(c2bd0a31fae37a... [2624 hex chars total] ...4f02bc78)#qe09xy0z
```

Single-sig with key origin:

```
pkh-mldsa44([f3a4c108/44h/2025h/0h]c2bd0a31fae37a...4f02bc78)#m5d3rga2
```

The key origin block `[f3a4c108/44h/2025h/0h]`:
- `f3a4c108` — fingerprint of the master key (8 hex chars = 4 bytes)
- `/44h/2025h/0h` — derivation path (Sophis coin type `2025` is
  reserved-by-convention; `h` denotes hardened). In v1 this path is
  parsed but rejected at resolve time.

Multisig 2-of-3 (parses, does not resolve in v1):

```
multi-mldsa44(2,a1b2c3...d4e5f6,1234ab...cd56ef,9988aa...77ccbb)#x7yz4mn5
```

## 4. Rationale (decisions D1–D5)

Five load-bearing structural decisions, each chosen from a small
explicit set of alternatives. The rejected alternatives are recorded
so future maintainers can revisit if circumstances change.

### D1 — HD derivation: static keys only in v1

**Decision:** Descriptor key expressions accept only **literal
Dilithium verification keys** in v1, encoded as 2624 hex characters.
The BIP-380 syntax `xpub.../0/*` is reserved (parser recognizes it)
but **rejected at resolve time** with
`ResolveError::HdDerivationNotYetSupported`.

**Rationale:** Sophis derives a single Dilithium keypair from a
24-word BIP-39 mnemonic via PBKDF2 — `1 mnemonic = 1 keypair`. There
is no NIST-blessed BIP-32 equivalent for ML-DSA in 2026. Implementing
pseudo-HD derivation locally would be inventing cryptography, which
Sophis explicitly avoids. The reserved syntax means that when (and
if) a NIST scheme emerges, descriptors that reference it can be
parsed by old tooling and resolved by new tooling — no syntactic
break.

**Rejected alternative (B): pseudo-HD scheme invented for Sophis.**
Rejected because inventing key-derivation cryptography is the
highest-risk activity any chain can undertake. Any error becomes
irreversible (it ships in users' backup descriptors).

**Rejected alternative (C): omit the `xpub.../0/*` syntax entirely.**
Rejected because it would force a syntactic break later if HD is
added. Reserving the syntax now is cheap.

### D2 — Multi descriptors: parse-only, resolve fails

**Decision:** `multi-mldsa44(k, k1, k2, ..., kn)` is **fully parsed
and serialized** by v1. The `Display` impl preserves the exact
textual form. However, `resolve()` returns
`Err(ResolveError::MultiSigNotYetSupported)` pointing at
`wallet/aa-spec/` (Account Abstraction).

**Rationale:** Multisig requires a redeem-script primitive that does
not exist in Sophis (`OpCheckMultiSig` is disabled; aggregate
Dilithium signatures are research-grade). Real multisig comes via
Account Abstraction contracts. The descriptor syntax exists now so
that:

- AA implementers can plug into a stable textual format when their
  work lands
- Wallet vendors can begin parsing/displaying multisig descriptors
  before the resolve path is wired
- Test vectors can exercise the syntax even without runtime semantics

**Rejected alternative (B): omit `multi-mldsa44` from v1 entirely.**
Rejected because it would force a parser break when AA lands.

### D3 — Crate location: separate `wallet/descriptors/`

**Decision:** New workspace member `wallet/descriptors/` (crate name
`sophis-wallet-descriptors`).

**Rationale:** Descriptors and PSBS (`wallet/pskt/`, SIP-1) are
conceptually separate — descriptors describe wallet identity, PSBS
describes transaction state. Coupling them in one crate would create
a subtle import-cycle risk if either grows. Pattern matches the rest
of the wallet stack.

**Rejected alternative (B): module inside `wallet/pskt/`.** Rejected
for the coupling reason above.

### D4 — Fingerprint algorithm: SHA3-384 truncated to 4 bytes

**Decision:** `fingerprint(vk)` = first 4 bytes of `SHA3-384(vk)`,
where `vk` is the canonical 1312-byte ML-DSA-44 verification key.

**Rationale:** BIP-32 fingerprints use
`RIPEMD-160(SHA-256(pubkey))[..4]`. Sophis cannot reuse this —
`RIPEMD-160` is not a primitive available across the Sophis crypto
stack, and adopting it would add a dependency for the sake of
mimicry. SHA3-384 is already used elsewhere in Sophis (notably in
Phase 6 DA `bundle_id_of`), so reusing it for fingerprint:

1. Keeps the cryptographic primitive set small (less audit surface)
2. Provides 384 bits of pre-truncation security
3. Has the same 4-byte output that BIP-32 wallets are already used to
   displaying

**Rejected alternative (B): SHA-256 truncated.** Rejected because
SHA-256 is not in Sophis's PQC-aligned primitive set.

**Rejected alternative (C): BLAKE3 truncated.** Rejected because
BLAKE3 is not currently a Sophis dependency.

### D5 — Checksum: BIP-380 polymod verbatim

**Decision:** Sophis reuses the BIP-380 checksum scheme verbatim —
same alphabet (96 characters), same generator polynomials, same
8-character output, same `#` separator.

**Rationale:** The BIP-380 checksum is well-tested (deployed in
Bitcoin Core since 2021), has good error-detection properties
(catches all single-character substitutions, catches most
2-character swaps), and the alphabet is already designed to cover
the characters wallet descriptors use. Inventing a Sophis-specific
checksum would have no cryptographic benefit and would prevent users
from copy-pasting checksums between Bitcoin and Sophis tooling.

**Rejected alternative (B): Sophis-specific polymod.** Rejected for
portability reasons above.

**Rejected alternative (C): No checksum.** Rejected because
descriptors are typed/copy-pasted by humans; a single-character
error in a 2624-character vk hex string would silently produce a
wrong wallet address. Checksum is a hard safety requirement.

## 5. Backwards Compatibility

**Fully backwards compatible.** This SIP defines a client-side
textual format. It does not change consensus, transaction format,
sighash, or any on-chain data structure. The only on-chain
implication is that resolved descriptors produce
`ScriptPublicKey` values, which are themselves unchanged by this
SIP.

No fork required. Wallets that do not implement descriptors continue
to work; they simply cannot read or emit descriptor strings.

## 6. Reference Implementation

Crate: `wallet/descriptors/` (`sophis-wallet-descriptors`).

- LOC: ~1137 source + 169 integration test + 362 design doc (this
  document originated as `wallet/descriptors/DESIGN.md`)
- Tests: 35 unit + 8 integration = **43 passing**, 1 ignored
  (BIP-380 cross-vector pending independent Bitcoin Core
  verification)
- Clippy: `-D warnings` clean
- Workspace dependencies: `sophis-consensus-core`, `sophis-txscript`,
  `sophis-wallet-pskt` (SIP-1), `sha3`, `hex`, `thiserror`. Zero new
  external dependencies.

Module layout:

| File | Purpose |
|---|---|
| `src/types.rs` | `Descriptor`, `KeyData`, `KeyOrigin` enums + struct |
| `src/parse.rs` | BNF parser; returns `Result<Descriptor, ParseError>` |
| `src/display.rs` | `Display` impl emitting canonical text form |
| `src/checksum.rs` | BIP-380 polymod (verbatim) |
| `src/fingerprint.rs` | SHA3-384[..4] over vk bytes |
| `src/resolve.rs` | `Descriptor → Vec<ScriptPublicKey>`; HD + multi return errors per D1/D2 |
| `src/error.rs` | `ParseError`, `ResolveError` |
| `tests/canonical_vectors.rs` | 8 integration scenarios covering §8 test vectors |

DESIGN.md (`wallet/descriptors/DESIGN.md`) is preserved alongside
this SIP as the historical artifact that drove the implementation,
following the same pattern as `wallet/pskt/DESIGN.md` (SIP-1). The
SIP is the canonical specification; the DESIGN.md is reference.

## 7. Security Considerations

### 7.1 Confidentiality

Descriptors are **not secret**. They contain only public
verification keys. Users may publish them, share them, store them in
cloud backups. The signing key (mnemonic seed) remains the secret.

### 7.2 Authenticity

A descriptor is not signed. Anyone can construct a descriptor that
*claims* to belong to anyone — the descriptor
`pkh-mldsa44(<attacker's vk>)#valid_checksum` is syntactically valid
for the attacker's key. **Wallet implementers MUST display the
resolved address(es) to the user before importing**, allowing the
user to compare with whatever channel the descriptor came from.

### 7.3 Checksum is for typo detection, not adversarial integrity

The 8-character checksum catches all single-character substitutions
and most 2-character swaps. It does **not** prevent a malicious
actor from crafting a descriptor with any specific content + valid
checksum. This is the same property as BIP-380; the checksum exists
for typos in human transcription, not for adversarial integrity.

### 7.4 vk hex case-insensitivity at parse time

Parsers MUST accept both uppercase and lowercase hex in the vk
field. Display always emits lowercase. This means
`pkh-mldsa44(ABCD...)#xxxx` and `pkh-mldsa44(abcd...)#yyyy` may have
**different checksums** even though they represent the same key.
Wallet implementers MUST canonicalize (lowercase) before computing
the checksum on input from a user.

### 7.5 Reserved future syntax

- The `xpub.../0/*` syntax is reserved (D1). v1 implementations MUST
  parse it without error and MUST fail at resolve. Future SIPs may
  activate it.
- The `taproot-mldsa44(...)`, `wpkh-mldsa44(...)`, and
  `tr-mldsa44(...)` script types do NOT exist and MUST be rejected
  at parse time. These are Bitcoin-specific witness types that have
  no Sophis equivalent.
- Future script types (e.g., once AA contracts have stable
  identifiers) will use new keywords distinguishable from existing
  ones.

### 7.6 Consensus impact

None. This SIP defines a client-side textual format. It does not
change consensus, transaction format, sighash, mempool policy,
long-range attack resistance, reorg behavior, light-client SPV,
ZK-Rollup (Phase 3), Phase 6 DA, or Phase 9 PQC oracle behavior.

## 8. Test Vectors

Canonical test vectors live in
`wallet/descriptors/tests/canonical_vectors.rs`. The eight
implemented vectors are:

1. **Fingerprint determinism.** Derive `(vk, _)` from PSBS test seed
   `b"PSBS_test_seed_alpha____________"` (shared with SIP-1 test
   vectors); compute fingerprint; assert byte-exact match against
   the hard-coded expected `[u8; 4]`.
2. **Pkh round-trip.** Build
   `Descriptor::Pkh { key: KeyData::VkHex(vk) }`, compute its
   `Display` form, parse the result, assert structural equality.
3. **Pkh with key origin round-trip.** Same as above with a
   `key_origin` block; verify the origin survives the round-trip
   byte-for-byte.
4. **Multi structural round-trip.** Build
   `Descriptor::Multi { threshold: 2, keys: vec![...3 keys...] }`,
   Display, parse, equal. **Resolve MUST fail** with
   `MultiSigNotYetSupported`.
5. **HD `xpub.../0/*` parsed but resolve-rejected.** Hardcode a
   valid descriptor with `xpub` syntax; parse succeeds; resolve
   fails with `HdDerivationNotYetSupported`.
6. **Pkh resolve produces correct ScriptPublicKey.** Resolve a
   single-sig descriptor; compare the resulting `ScriptPublicKey`
   byte-for-byte against the SPK that `dilithium-wallet keygen`
   produces for the same vk.
7. **Checksum verification rejects 1-character corruption.** Take a
   valid descriptor, flip one character in the checksum, assert
   `ChecksumMismatch` error.
8. **Boundary tests:** `multi-mldsa44(0, ...)` rejected;
   `multi-mldsa44(3, k1, k2)` rejected (threshold > keys);
   `multi-mldsa44(2, k1, k2, ..., k16)` rejected (too many keys);
   `pkh-mldsa44()` rejected (no key).

One additional vector is **ignored** pending external verification:

9. **BIP-380 cross-vector compatibility (`#[ignore]`).** Feed a
   known BIP-380 input string (without the Sophis script type, just
   the polymod content) into the Sophis polymod; assert the same
   checksum bytes as Bitcoin Core's reference test vector. This
   requires hand-verification against an independent BIP-380 oracle
   (e.g., Bitcoin Core test fixtures) before un-ignoring; the test
   exists and runs, but the assertion remains marked `#[ignore]`
   until a maintainer confirms the expected bytes against a
   non-Sophis source.

## 9. References

- [BIP-380](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki)
  — Output Descriptors (Andrew Chow, 2021). Source of the surface
  grammar and checksum algorithm.
- [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
  — Hierarchical Deterministic Wallets. Source of the key origin
  syntax (parsed but reserved per D1).
- [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
  — Multi-Account Hierarchy. Source of the canonical derivation
  path shape used in §3.7 examples.
- [SIP-1](./SIP-1-PSBS.md) — PSBS. Companion primitive; descriptor
  language is the textual identifier of wallets that PSBS
  coordinates over.
- [`wallet/aa-spec/`](../wallet/aa-spec/) — Account Abstraction
  specification; multisig descriptor resolve will unlock when a
  future AA SIP graduates.
- [`MONETARY_POLICY.md`](../MONETARY_POLICY.md) §2 — fair launch
  context (no premine, no devfund). Descriptors must work for any
  user-controlled vk, with no special-case "team" or "treasury"
  descriptors.

## 10. Copyright

This SIP is released into the public domain (CC0).
