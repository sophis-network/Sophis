# J2 — Typed Data Signing for Dilithium (EIP-712-equivalent)

> **Status:** design frozen for sub-fase J2.0 — ready for J2.1 implementation.
> **Originating roadmap:** Roadmap J (Ethereum lessons), item J2.
> **Companion docs:** `SIPS/SIP-2-TYPED-SIGNING.md` (also J2.3) and the
> reference implementation in the new `wallet/typed-data` crate.
> **Pre-existing baseline:** **none**. Sophis wallets sign opaque digests
> today; users see "sign this 32-byte hash" with no semantic context.
> Verified 2026-05-10 via grep across `wallet/` and `svm/sdk/`.

## 1. Motivation

Every production smart-contract platform that lets users sign more than
plain transactions has a **typed-data signing** standard:

- **Ethereum** has EIP-712 (`signTypedData`) — the wallet decodes the
  schema, displays "You are signing: Mail { from: 0xabc…, to: 0xdef…,
  contents: 'gm' }" and the user reads what they sign.
- **Solana** has Memo + signTransaction-with-tags — partial; mostly
  Phantom inventing per-app conventions.
- **Cosmos** has SignDoc (proto) — strongly-typed but not user-facing.

Without a standard:

- **Phishing surface explodes.** Users sign opaque hashes; malicious
  dApps craft hashes that match transactions or capability grants the
  user did not intend.
- **dApps cannot ask users to sign anything off-chain** because no two
  wallets show the same UX. Signed orders, governance votes, meta-tx
  approvals, EIP-1271-style smart-account auth all assume a typed
  signing convention.
- **Cross-wallet UX is impossible** because each wallet invents its own
  per-app message formatting.

J2 solves the *structural* problem: a canonical wire format for
typed messages that wallets can decode and render. The wallet UX layer
(how to render the type tree to humans) is deliberately out of scope —
that lives downstream in each wallet implementation. The *protocol*
piece is the canonical bytes the signer commits to.

This is a P1 deliverable per the original Roadmap J priorities and the
ideal candidate for SIP-2 (the second standards-track Sophis Improvement
Proposal after SIP-1 PSBS).

## 2. Ratified design decisions

These decisions were committed by the founder on 2026-05-10 and are
frozen for the J2 implementation. Re-opening any of them requires a
new SIP.

| ID | Question | Choice | Rationale |
|----|----------|--------|-----------|
| **D1** | Hash function | `SHA3-384(...)[..32]` (truncated to 32 bytes) | Sophis's canonical hash everywhere is SHA3-384. Truncation to 32 bytes matches the J3 VRF and J4 topic conventions, so SDK helpers compose. The full 384-bit digest is computed but only the first 32 bytes are returned. Discarded upper 16 bytes preserve domain-separator independence vs callers that do their own SHA3-384. |
| **D2** | Signing prefix bytes | `b"\x73\x01"` (`'s'` for Sophis + version 1) | Two bytes, EIP-712-shaped (`0x19 0x01` was Ethereum's choice). `0x73` makes a Sophis typed-signing digest cryptographically distinct from any Ethereum prefixed signature. Version byte at `0x01` enables future-proofing without breaking the prefix shape. |
| **D3** | Type registry / schema source | Caller-supplied (no global registry) | The signer provides the canonical schema (`TypedStruct { name, fields }`) at signing time; the verifier provides the same schema at verifying time. No on-chain or wallet-side registry. PRO: zero coordination overhead; dApps can iterate freely. CON: schema drift between signer and verifier produces invalid signatures (a feature — schema mismatch should be a hard fail, not silent acceptance). |
| **D4** | Domain field set | `{ name, version, network, verifying_address?, salt? }` | `name` + `version` + `network` are mandatory (binds signature to a specific dApp + version + chain). `verifying_address` (32-byte sVM contract id or P2PKH-Dilithium address) is optional — bound at the signer's discretion. `salt` is optional — for dApps that want app-specific replay isolation across versions. |
| **D5** | Type-string canonical format | `Type Name(field_type field_name,...)` recursive, struct refs sorted alphabetically by name | Mirrors EIP-712 §`encodeType` exactly — "Mail(address from,address to,string contents)". Nested struct references are concatenated in alphabetical order: `Outer(Inner i)Inner(uint256 x)`. Removing or reordering whitespace MUST produce the same hash; the canonical encoder normalises. |
| **D6** | Signing flow | Caller computes the digest, signs the digest with Dilithium | The typed-data library produces a `[u8; 32]` digest. Signing is a separate Dilithium operation against that digest — same `dilithium_sign` and `verify_dilithium` callers use for any other 32-byte hash. PRO: zero new sig primitive; uses existing audited paths. CON: signers must remember to apply the typed-data digest before signing (cannot accidentally sign raw bytes that match a typed structure — the prefix `\x73\x01` makes that infeasible). |

## 3. Wire format

### 3.1 Type definitions

A `TypedField` describes one field by name + type:

```text
TypedField {
    name:       String,           // arbitrary; UTF-8
    type_str:   String,           // e.g. "uint256", "address", "string", "Mail"
}
```

A `TypedStruct` is a named ordered list of fields:

```text
TypedStruct {
    name:    String,
    fields:  Vec<TypedField>,
}
```

Type strings are EIP-712-style:

| Type string | Encoded as | Length |
|-------------|------------|--------|
| `bool` | 1 byte (`0x00` / `0x01`) padded to 32 | 32 |
| `uint8`..`uint256` | big-endian 32-byte word, zero-padded | 32 |
| `int8`..`int256` | two's-complement big-endian 32-byte word | 32 |
| `bytesN` (N=1..32) | the N bytes left-padded to 32 | 32 |
| `address` | 32-byte raw address (Sophis P2PKH-Dilithium / contract id) | 32 |
| `bytes` (dynamic) | `SHA3-384(value)[..32]` | 32 |
| `string` (dynamic) | `SHA3-384(utf8_bytes)[..32]` | 32 |
| `T[]` (dynamic array) | `SHA3-384(concat(encode(T_i)))[..32]` | 32 |
| `T[N]` (fixed array) | `SHA3-384(concat(encode(T_i)))[..32]` | 32 |
| Struct ref (`Mail`) | `struct_hash(Mail, value)` | 32 |

Every encoded value is exactly 32 bytes. Recursion bottoms out at the
primitive encodings above.

### 3.2 type_hash

```text
type_hash(struct) = SHA3-384(canonical_type_string(struct))[..32]

canonical_type_string(s) =
    s.name + "(" + s.fields.iter().map(|f| f.type_str + " " + f.name).join(",") + ")"
    + sorted_referenced_struct_strings(s).join("")

sorted_referenced_struct_strings(s) =
    // Walk all struct types reachable via s.fields; emit each one's
    // primary type-string (without recursive references), sorted
    // alphabetically by name.
```

The recursive type collection MUST exclude `s` itself (a struct's own
type string is the prefix; references are appended after it sorted).

### 3.3 struct_hash

```text
struct_hash(struct, value) = SHA3-384(
    type_hash(struct) || encode_field(struct.fields[0], value.fields[0]) || ...
)[..32]
```

Each encoded field is exactly 32 bytes (per §3.1). Concatenation is
plain byte concatenation — no length prefixes between fields, no padding
beyond the per-field 32-byte rule.

### 3.4 Domain separator

```text
TypedDataDomain {
    name:                String,             // dApp name, e.g. "MyDApp"
    version:             String,             // dApp version, e.g. "1.0.0"
    network:             u8,                 // network discriminator (mainnet=0, testnet=1, devnet=2, simnet=3)
    verifying_address:   Option<[u8; 32]>,   // optional contract / wallet address
    salt:                Option<[u8; 32]>,   // optional app-specific salt
}

domain_separator(d) = struct_hash(EIP712Domain_struct(d), d.values())
```

The synthetic `EIP712Domain` struct is:

```text
fields = [
    ("name",              "string"),
    ("version",           "string"),
    ("network",           "uint8"),
    Some(("verifyingAddress", "address")) if d.verifying_address.is_some(),
    Some(("salt",         "bytes32")) if d.salt.is_some(),
]
```

Fields are kept in this fixed order; optional fields are simply omitted
when not present. The type-string and the values list MUST agree on the
omission.

### 3.5 Final digest

```text
typed_data_digest(domain, struct, value) = SHA3-384(
    b"\x73\x01" ||
    domain_separator(domain) ||
    struct_hash(struct, value)
)[..32]
```

The 34-byte preimage (2 prefix + 32 domain + 32 struct = 66 total before
truncation) is hashed with SHA3-384 and the first 32 bytes are returned.

This is the digest signed by Dilithium. The signing call is the
existing `dilithium_sign(secret_key, digest, &mut sig)` — no new
signing primitive.

## 4. Threat model

| ID | Threat | Mitigation |
|----|--------|------------|
| T1 | Signed digest collides with a raw transaction hash | Prefix `b"\x73\x01"` is incompatible with any Sophis transaction hash (txs are hashed with a different domain prefix at the consensus layer). Cross-prefix collision requires SHA3-384 second-preimage, computationally infeasible. |
| T2 | Schema mismatch between signer and verifier | Type-hash differs → struct-hash differs → digest differs → Dilithium verify fails. The verifier MUST hard-fail rather than try to "fix up" the schema. |
| T3 | Phishing dApp displays one struct but signs another | Wallet UX SHOULD compute the digest itself from the struct it displays, not trust dApp-supplied digests. The lib provides `compute_typed_digest(domain, struct, value)` so wallets can re-derive locally. |
| T4 | Cross-domain replay: signature on (dApp A, version 1) reused on (dApp A, version 2) | Domain separator binds both. Signers using `verifying_address` get a third axis. Signers needing per-action replay isolation use `salt`. |
| T5 | Malleability via whitespace / case in type strings | Canonical encoder normalises. Verifiers MUST recompute from the raw `TypedStruct` value, never from a free-text type string. |
| T6 | PQC posture loss | J2 introduces no new cryptographic primitive. Hash is SHA3-384 (existing). Sig is Dilithium ML-DSA-44 (existing). PQC posture preserved. |
| T7 | Replay across networks | `network` field in domain. Mainnet → testnet replay impossible. |

## 5. Comparison vs alternatives

| System | Hash | Sig | User UX | Per-app schema | Cross-wallet portable |
|--------|------|-----|---------|----------------|----------------------|
| EIP-712 (Ethereum) | keccak256 | secp256k1 | excellent (MetaMask, Rabby) | dApp-supplied | yes |
| Solana memo+sign | sha256 of message | ed25519 | poor (opaque hash) | per-wallet ad-hoc | no |
| Cosmos SignDoc | sha256 of proto | secp256k1 / Tendermint | medium | proto-defined | yes within Cosmos |
| **Sophis J2** | SHA3-384[..32] | Dilithium ML-DSA-44 | depends on wallet | dApp-supplied | yes (canonical schema) |

Sophis J2 is the EIP-712 pattern adapted to Sophis's hash + signature.
The wire format is intentionally close enough to EIP-712 that an
Ethereum dev can port a typed-message library in an afternoon.

## 6. Out-of-scope (for J2)

The following are deliberately deferred:

- **On-chain sVM verifier capability** (`Capability::VerifyTypedData`)
  — contracts that want to validate user-signed typed messages can do
  it today by calling `verify_dilithium` against a digest the contract
  computes itself. A dedicated host fn would only save a few SHA3 ops;
  defer until a real meta-tx pattern emerges.
- **Wallet-side rendering UX** — how the wallet displays the struct
  tree (collapsing nested structs, address book lookups, Unicode
  homoglyph detection). Wallets implement per their own UX.
- **Type-string parser** that re-derives the schema from a Solidity-
  style string. The canonical direction is `TypedStruct → type_string`,
  not `type_string → TypedStruct`. dApps publish their schemas as
  structured data, not as freeform strings.
- **WebAssembly bindings** for browser wallets. Trivial follow-up;
  defer until a JS wallet asks.
- **Dynamic value JSON schema** for CLI sign-typed. The `dilithium-wallet`
  CLI in J2.2 ships with a worked example; full JSON-schema validation
  of caller-supplied values is a UX polish for v2.

## 7. Frozen ABI surface

The following are **frozen** as of the J2 implementation merge. Any
change requires a hard fork of the typed-signing convention (no
on-chain consensus impact).

| Item | Value |
|------|-------|
| Signing prefix bytes | `b"\x73\x01"` (2 bytes) |
| Hash function | SHA3-384 truncated to 32 bytes |
| Domain field order | `name, version, network, verifyingAddress?, salt?` |
| Domain `network` byte | `mainnet=0, testnet=1, devnet=2, simnet=3` (matches `NetworkType`) |
| Empty-bytes / empty-string hash | `SHA3-384("")[..32]` (canonical, no special case) |
| `address` field width | 32 bytes (Sophis P2PKH-Dilithium hash or sVM contract id) |
| `bool` encoding | 1 byte `0x00`/`0x01` left-padded to 32 |
| Crate name | `sophis-typed-data` |

## 8. Reference implementation map

| Sub-fase | Scope |
|---------|-------|
| J2.0 | This design document |
| J2.1 | `wallet/typed-data` crate — `TypedDataDomain`, `TypedField`, `TypedStruct`, encoder + digest helpers + tests |
| J2.2 | `dilithium-wallet typed sign|verify` CLI subcommands using the lib end-to-end |
| J2.3 | `SIPS/SIP-2-TYPED-SIGNING.md` stub (this design as authoritative spec) |
| J2.4 | Workspace check + clippy strict + single commit + SIPS index update |

## 9. Glossary

| Term | Meaning |
|------|---------|
| Typed data | A structured message described by a schema (struct name + fields with type strings) rather than raw bytes. |
| Type hash | `SHA3-384(canonical_type_string)[..32]` — uniquely identifies a struct schema. |
| Struct hash | `SHA3-384(type_hash || encoded_field_values)[..32]` — commits to both the schema and the values. |
| Domain separator | `struct_hash(EIP712Domain, domain_values)` — pins the signature to a specific dApp + version + chain. |
| Final digest | `SHA3-384(b"\x73\x01" || domain_separator || struct_hash)[..32]` — the 32-byte input to Dilithium signing. |
| Schema drift | Signer and verifier disagree on the struct definition; type hashes differ; verification fails by design. |
