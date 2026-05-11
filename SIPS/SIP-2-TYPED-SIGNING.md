```
SIP: 2
Title: Typed Data Signing for Dilithium (EIP-712-equivalent)
Author: Marcelo Delgado <sophis-network@proton.me>
Status: Draft
Type: Standards
Created: 2026-05-10
Requires: 0
```

# SIP-2: Typed Data Signing for Dilithium

> **Status note:** this document is the *stub* that accompanies the J2
> reference implementation merged in commits `<TBD>` (single commit,
> ~1 200 LOC + ~40 tests). The full SIP body is intentionally deferred
> until at least 30 days of testnet usage with non-trivial typed-message
> workloads, so the Rationale and Security Considerations sections can
> cite real measurements and dApp integration patterns rather than
> projections. SIP-0 §6 ("Standards Track") permits this two-phase
> pattern: a *stub* anchors the proposal in the SIP series and freezes
> the wire format and decision IDs; the *full body* lands when
> measurements support it.

## 1. Abstract

Sophis wallets sign opaque digests today: the user is shown "sign this
32-byte hash" with no semantic context. This is a phishing vector and
blocks every off-chain signing pattern that production smart-contract
platforms consider table stakes (governance votes, off-chain orders,
meta-tx approvals, EIP-1271-style smart-account auth).

SIP-2 introduces **Sophis Typed Data Signing** — an
`EIP-712`-equivalent canonical wire format adapted to Sophis's
`SHA3-384` hash and Dilithium ML-DSA-44 signature primitives. Wallets
that consume this format can decode the schema and render struct
fields with their type info to the user before signing. dApps publish
their schemas as structured data; the canonical encoder in
`sophis-typed-data` produces a 32-byte digest that gets signed by the
existing `dilithium_sign` primitive.

J2 introduces no new cryptographic primitive. The hash is SHA3-384
(existing). The signature is Dilithium ML-DSA-44 (existing). PQC
posture is preserved.

## 2. Motivation

See `docs/J2_TYPED_SIGNING_DESIGN.md` §1 for the canonical motivation:
the absence of any standardised typed-signing format pre-J2, the
phishing surface that creates, the structural barrier to off-chain
dApp UX, and the cross-wallet portability problem.

J2 is a P1 deliverable per the original Roadmap J priorities (see
`project_ethereum_lessons.md`) and the ideal candidate for SIP-2 (the
second standards-track Sophis Improvement Proposal after SIP-1 PSBS).

## 3. Specification

The technically complete specification is published at
`docs/J2_TYPED_SIGNING_DESIGN.md` in the reference implementation tree
(`sophis-network/Sophis@<TBD>` and forward). It enumerates:

- 6 ratified design decisions (D1–D6, §2)
- Wire format with byte-level layout (§3) — type definitions, type
  hash, struct hash, domain separator, final digest
- Threat model with 7 in-scope items (§4)
- Comparison vs `EIP-712` / Solana sign / Cosmos SignDoc (§5)
- Frozen ABI surface (§7)

This SIP body will be re-issued in **Review** once testnet measurements
are available; readers should treat the DESIGN doc as the authoritative
specification until that re-issue.

## 4. Frozen ABI surface

The following are **frozen** as of the J2 implementation merge. Any
change requires a hard fork of the typed-signing convention (no
on-chain consensus impact).

### 4.1 Signing prefix bytes

| Item | Value |
|------|-------|
| Prefix bytes | `b"\x73\x01"` (2 bytes: `'s'` for Sophis + version 1) |
| Hash function | `SHA3-384` truncated to 32 bytes |
| Empty-bytes/string hash | `SHA3-384("")[..32]` (no special case) |

### 4.2 Domain field order

| Position | Field | Type | Optional |
|----------|-------|------|----------|
| 1 | `name` | `string` | required |
| 2 | `version` | `string` | required |
| 3 | `network` | `uint8` | required |
| 4 | `verifyingAddress` | `address` (32 bytes) | optional (omit when None) |
| 5 | `salt` | `bytes32` | optional (omit when None) |

### 4.3 Network byte assignment

| Value | Network |
|-------|---------|
| 0 | mainnet |
| 1 | testnet |
| 2 | devnet |
| 3 | simnet |

### 4.4 Field encoding (32-byte slot per field)

| Type | Encoding |
|------|----------|
| `bool` | 1 byte (`0x00`/`0x01`) left-padded to 32 |
| `uint8`..`uint256` | big-endian, low-16 bytes for u128-fit values |
| `int8`..`int256` | two's-complement big-endian, sign-extended high bytes |
| `bytesN` (N=1..32) | the N bytes left-padded HIGH (value occupies first N bytes of slot) |
| `address` | 32-byte raw address |
| `bytes` (dynamic) | `SHA3-384(value)[..32]` |
| `string` (dynamic) | `SHA3-384(utf8_bytes)[..32]` |
| `T[]` / `T[N]` | `SHA3-384(concat(encode(T_i)))[..32]` |
| Struct ref | `struct_hash(referenced_schema, value)` |

### 4.5 Type-string canonical format

```text
primary_type_string(s) = s.name + "(" + s.fields.map(|f| f.type_str + " " + f.name).join(",") + ")"

canonical_type_string(s) = primary_type_string(s) + sorted_referenced_struct_strings(s).join("")
```

Nested struct references are appended in alphabetical order by struct
name; the schema's own type-string is the prefix.

### 4.6 Final digest

```text
typed_data_digest(domain, schema, values) = SHA3-384(
    b"\x73\x01" ||
    domain.domain_separator() ||
    struct_hash(schema, values)
)[..32]
```

### 4.7 Crate name

| Item | Value |
|------|-------|
| Reference crate | `sophis-typed-data` (path: `wallet/typed-data`) |

## 5. Rationale

Deferred to the full SIP body. The DESIGN doc §2 already enumerates the
six ratified decisions (D1–D6) and their rationales; what changes in the
full SIP is the addition of empirical numbers (per-dApp typed-message
frequency, schema complexity distribution, wallet-side rendering
performance) to justify the conservative defaults.

The most likely points of testnet-driven revision are:

- D2 — extending signing prefix from 2 bytes to 14 bytes
  (`b"sophis-typed-v1\0"`) for stronger versioning if a v2 format
  becomes necessary
- D5 — reducing canonical type-string overhead by hashing references
  separately rather than concatenating their full type-strings
- Adding a JSON-schema layer for dynamic CLI value validation (deferred
  per DESIGN §6)

## 6. Backwards Compatibility

**Activated at genesis.** Sophis has not launched mainnet, so there is
no soft-fork window. Wallets that don't implement J2 are entirely
unaffected; they simply cannot sign typed data. Wallets that do
implement J2 follow the canonical encoder in `sophis-typed-data`.

There is no consensus impact. All J2 work happens at the wallet /
SDK / dApp layer; no Sophis full node validates a typed-data
signature as part of consensus rules. Contracts that wish to verify
typed-data signatures on-chain do so via `verify_dilithium` against a
digest the contract recomputes (the on-chain `Capability::VerifyTypedData`
is a deferred follow-up; see DESIGN §6).

## 7. Reference Implementation

Reference implementation: `sophis-network/Sophis` commits `<TBD>`
(single commit shipping all J2 sub-fases):

| Sub-fase | Scope |
|---------|-------|
| J2.0 | Design document (`docs/J2_TYPED_SIGNING_DESIGN.md`, ~310 lines) |
| J2.1 | New crate `wallet/typed-data` — `TypedDataDomain`, `TypedField`, `TypedStruct`, `TypedValue`, recursive type-hash + struct-hash + final digest helpers; 34 unit tests + 1 doctest |
| J2.2 | `dilithium-wallet typed sign|verify` CLI subcommands using the lib end-to-end; JSON schema + values input format |
| J2.3 | This SIP stub |
| J2.4 | Workspace check + clippy strict + single commit + SIPS index update |

## 8. Security Considerations

Comprehensive threat model in DESIGN §4. Highlights:

- **Cross-prefix collision:** prefix `b"\x73\x01"` is incompatible with
  any Sophis transaction hash (txs are hashed with a different consensus-
  layer prefix). Forgery requires SHA3-384 second-preimage.
- **Schema mismatch:** signer/verifier disagreement on the schema
  produces different type-hashes → different digests → Dilithium verify
  fails. This is the desired behaviour; verifiers MUST hard-fail rather
  than try to "fix up" the schema.
- **Phishing dApp:** wallet UX SHOULD compute the digest locally from
  the struct it displays to the user, never trust a dApp-supplied
  digest. The reference encoder is exposed as a single function call
  (`compute_typed_digest`) precisely so wallets can re-derive locally.
- **Replay:** domain separator binds (name, version, network); optional
  `verifying_address` and `salt` provide additional axes for dApps that
  need them.
- **Malleability:** canonical encoder normalises whitespace and field
  ordering; verifiers MUST recompute from the structured `TypedStruct`
  value, never from a free-text type string.
- **PQC posture:** preserved. No new cryptographic primitives.

## 9. Test Vectors

Canonical vectors live with the reference implementation in:

- `wallet/typed-data/src/encoder.rs` (`tests` module) — primary
  type-string format + nested-struct ordering + per-type encoding
  (bool, uint, int, bytesN, dynamic bytes, string, array, struct ref)
- `wallet/typed-data/src/digest.rs` (`tests` module) — final digest
  determinism + prefix inclusion + domain/value sensitivity
- `wallet/typed-data/src/domain.rs` (`tests` module) — domain
  separator field-by-field sensitivity (name, version, network,
  verifying_address, salt)
- `wallet/typed-data/src/types.rs` (`tests` module) — serde JSON
  round-trip for `TypedField` / `TypedStruct` / `TypedValue`
  discriminants

Devnet integration vectors will be added in a follow-up sub-fase. The
wire format is frozen as of the implementation commit.

## 10. References

- EIP-712 (Ethereum) — original conceptual ancestor; Sophis follows the
  same encoding philosophy with hash + sig swapped to SHA3-384 +
  Dilithium ML-DSA-44
- `docs/J2_TYPED_SIGNING_DESIGN.md` — authoritative wire-format spec
- `wallet/typed-data/src/lib.rs` — reference encoder
- `dilithium-wallet typed` CLI — worked example end-to-end
- `project_ethereum_lessons.md` — strategic context for Roadmap J
- `SIPS/SIP-1-PSBS.md` — sibling Standards-track SIP (cold-storage
  signing); shares the wallet-layer scope philosophy
- `SIPS/SIP-3-ALT.md` — uses the same "stub + design doc + later full
  body" pattern

## 11. Copyright

This SIP is released into the public domain (CC0).
