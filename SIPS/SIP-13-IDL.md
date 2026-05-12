```
SIP: 13
Title: sVM Contract Interface Definition Language (IDL)
Author: Marcelo Delgado <sophis-network@proton.me>
Status: Draft
Type: Standards
Created: 2026-05-12
```

# SIP-13: sVM Contract Interface Definition Language (IDL)

## 1. Abstract

This SIP defines a JSON-based **Interface Definition Language (IDL)** for Sophis sVM contracts. An IDL document is a human- and machine-readable description of a deployed contract's public surface: callable functions, emitted events, error variants, type definitions, and metadata. Wallets, block explorers, dApp backends, SDK code-generators, and L2 tooling consume the IDL to produce typed bindings, render transaction previews, decode event logs, and validate user input against expected types. The IDL is **off-chain** — it lives in source-control repositories, on `.well-known/` paths, or in package registries — and is produced by the contract author at compile time, not embedded in the chain itself.

## 2. Motivation

A sVM contract deployed to Sophis is a WASM blob with a small set of exported entry points. Without an IDL, every tool that wants to interact with the contract must hand-write decoding logic for that contract's specific input/output layouts. This is the same problem Ethereum had before ABI JSON (2015) and Solana had before Anchor IDL (2021).

Concretely, three pain points emerge without a standardized IDL:

1. **Wallet UX** — when a user signs a transaction calling `contract.transfer(recipient, amount)`, the wallet has no way to render a meaningful confirmation screen. Without an IDL, the user signs raw bytes and trusts the dApp's claim about what those bytes mean.
2. **Event indexing** — explorers and dashboards that want to decode `sVM event logs` (SIP-4) need to know each contract's event signatures. Hand-curated per-contract decoders do not scale.
3. **SDK code generation** — Rust, TypeScript, Python, and Go SDKs all need typed bindings for each contract a developer wants to call. Without a portable IDL, every SDK reimplements parsing for each contract.

Three constraints shape the design:

- **Sophis is Dilithium-only.** Cryptographic primitives in function inputs/outputs (signatures, public keys, hashes) have specific sizes (1312 / 2420 / 48 bytes). The IDL must support these as first-class types, not generic `bytes`.
- **Sophis has native tokens (L1) with linear-typed `Resource<T>` accounting.** The IDL must describe `Resource<T>` types in a way that wallets can render token balances and code-generators can produce type-safe move semantics.
- **Sophis has ZK-Rollup L2 (Phase 3).** L2 contracts have the same shape as L1 contracts; the IDL must work for both contexts without separate dialects.

Ethereum ABI JSON solves (1) and partially (3); it does not natively support Dilithium sizes, post-quantum schemes, or linear types. Solana Anchor IDL solves (1) and (3) more elegantly but is Solana-specific. The Sophis IDL borrows the JSON structure familiar from both, then adds Dilithium-aware types and `Resource<T>` semantics.

## 3. Specification

### 3.1 File location and naming

A contract's IDL document is a JSON file named `<contract-name>.idl.json`. The canonical locations, in order of preference:

1. **In the contract's source repository**, alongside the WASM build artifact: `target/sophis/<contract-name>.idl.json`.
2. **On the deployer's domain** under `.well-known/`: `https://<domain>/.well-known/sophis-contract/<contract-name>.idl.json`. This is the discovery path for wallets that find a contract via address-to-domain bindings (see SIP-6).
3. **In a package registry** (e.g., `crates.io`, `npm`, or a Sophis-specific registry if one emerges in the future).

The IDL is **not** stored on-chain. Contracts MAY embed a SHA3-384 hash of their canonical IDL in their constructor metadata to enable verifier trust, but the IDL bytes themselves remain off-chain.

### 3.2 Top-level schema

The IDL is a JSON object with the following fields:

```json
{
  "idl_version": "1.0",
  "contract": {
    "name": "TokenVault",
    "version": "0.3.1",
    "address": "sophis:q...",
    "compiler": {
      "name": "rustc",
      "version": "1.93.0",
      "target": "wasm32-unknown-unknown"
    },
    "wasm_hash": "<48-byte SHA3-384 hex of compiled WASM>",
    "source_url": "https://github.com/example/token-vault"
  },
  "types": [ /* see §3.4 */ ],
  "functions": [ /* see §3.5 */ ],
  "events": [ /* see §3.6 */ ],
  "errors": [ /* see §3.7 */ ],
  "metadata": { /* optional, see §3.8 */ }
}
```

### 3.3 Field semantics

| Field | Required | Description |
|---|---|---|
| `idl_version` | yes | The IDL format version. v1.0 in this SIP. Future versions advance to `1.1`, `2.0`, etc. |
| `contract.name` | yes | Human-readable contract name. UTF-8, max 64 chars |
| `contract.version` | yes | Semantic version of the contract source |
| `contract.address` | no | The deployed `sophis:` address of the contract instance. May be omitted in published IDL templates that target multiple deployments |
| `contract.compiler` | yes | Object identifying the compiler used to produce the WASM artifact this IDL describes |
| `contract.wasm_hash` | yes | SHA3-384 hex digest of the canonical WASM bytes. Verifiers MUST refuse to use an IDL whose hash does not match the on-chain WASM bytes for the claimed address |
| `contract.source_url` | no | URL pointing to the source code that produced the WASM. Strongly encouraged for transparency |
| `types` | yes | Array of named type definitions (see §3.4) |
| `functions` | yes | Array of callable entry points (see §3.5) |
| `events` | yes | Array of emitted events (see §3.6). MAY be empty |
| `errors` | yes | Array of error variants (see §3.7). MAY be empty |
| `metadata` | no | Free-form object for contract-specific extension data (see §3.8) |

### 3.4 Type system

The IDL supports a fixed set of primitive types plus user-defined struct, enum, and array types.

**Primitive types:**

| Type name | Size (bytes) | Encoding |
|---|---|---|
| `bool` | 1 | `0x00` = false, `0x01` = true |
| `u8`, `u16`, `u32`, `u64`, `u128` | 1, 2, 4, 8, 16 | little-endian unsigned integer |
| `i8`, `i16`, `i32`, `i64`, `i128` | 1, 2, 4, 8, 16 | little-endian two's-complement signed integer |
| `string` | variable | UTF-8 prefixed with `u32` length |
| `bytes` | variable | raw bytes prefixed with `u32` length |

**Sophis-specific primitive types (the Dilithium / Resource layer):**

| Type name | Size (bytes) | Description |
|---|---|---|
| `dilithium_pubkey` | 1312 | Dilithium ML-DSA-44 verification key (FIPS 204) |
| `dilithium_signature` | 2420 | Dilithium ML-DSA-44 signature (FIPS 204) |
| `sophis_address` | variable | Bech32-encoded `sophis:` / `sophistest:` / `sophisdev:` / `sophissim:` string. Prefix is part of the encoded value |
| `script_hash` | 32 | Blake2b-256 hash used in Sophis script-pubkey-version-8 (ScriptHash) addresses |
| `sha3_384` | 48 | SHA3-384 hash (Sophis's canonical hash for DA carriers, descriptor identity, and asset IDs) |
| `blue_score` | 8 | `u64` blue score, equivalent semantically to a block height in GHOSTDAG |
| `daa_score` | 8 | `u64` DAA (Difficulty-Adjustment-Algorithm) score |
| `resource<T>` | variable | Linear-typed native token resource. `T` is a user-defined token type. Encoding includes a 32-byte resource ID + balance encoding |

**User-defined types** are declared in the `types` array of the IDL:

```json
{
  "types": [
    {
      "name": "Allocation",
      "kind": "struct",
      "fields": [
        { "name": "recipient", "type": "sophis_address" },
        { "name": "amount", "type": "u64" },
        { "name": "lockup_until", "type": "blue_score" }
      ]
    },
    {
      "name": "VoteOption",
      "kind": "enum",
      "variants": [
        { "name": "Yea" },
        { "name": "Nay" },
        { "name": "Abstain", "fields": [{ "name": "reason", "type": "string" }] }
      ]
    },
    {
      "name": "Signatories",
      "kind": "array",
      "element_type": "dilithium_pubkey",
      "max_length": 16
    }
  ]
}
```

The `kind` field is one of `struct`, `enum`, `array`, or `optional`. Each is encoded per the rules in §3.9.

### 3.5 Function declarations

```json
{
  "functions": [
    {
      "name": "transfer",
      "selector": "<8-byte hex prefix of Blake2b-256(canonical_signature)>",
      "inputs": [
        { "name": "recipient", "type": "sophis_address" },
        { "name": "amount", "type": "u64" }
      ],
      "outputs": [
        { "name": "tx_id", "type": "sha3_384" }
      ],
      "state_mutability": "writable",
      "gas_estimate": { "min": 5000, "typical": 12000 },
      "docs": "Transfer `amount` sompi to `recipient`. Fails if balance is insufficient."
    }
  ]
}
```

| Function field | Required | Description |
|---|---|---|
| `name` | yes | Function name as exported by the WASM module |
| `selector` | yes | First 8 bytes (hex) of Blake2b-256 over the canonical signature `name(input_type1,input_type2,...)`. Used as the dispatch ID in call payloads |
| `inputs` | yes | Ordered array of typed parameters |
| `outputs` | yes | Ordered array of typed return values. MAY be empty |
| `state_mutability` | yes | One of `pure` (no state read or write), `view` (read-only), `writable` (state-changing) |
| `gas_estimate` | no | Author-provided gas hints; verifiers MUST NOT enforce these — they are advisory for wallet UX |
| `docs` | no | Free-text documentation, max 4 KB |

### 3.6 Event declarations

Events declared here must match the runtime `emit_event` calls in the contract WASM. Wallets and indexers use this to decode SIP-4 event logs.

```json
{
  "events": [
    {
      "name": "Transfer",
      "selector": "<8-byte hex prefix of Blake2b-256(canonical_event_signature)>",
      "topics": [
        { "name": "from", "type": "sophis_address", "indexed": true },
        { "name": "to",   "type": "sophis_address", "indexed": true }
      ],
      "data": [
        { "name": "amount", "type": "u64" }
      ],
      "docs": "Emitted on every successful transfer."
    }
  ]
}
```

Per SIP-4, up to 4 indexed topics per event; the remaining payload goes in `data`. Each event's selector is the first 8 bytes of Blake2b-256 over the canonical event signature.

### 3.7 Error declarations

```json
{
  "errors": [
    {
      "name": "InsufficientBalance",
      "code": 100,
      "fields": [
        { "name": "requested", "type": "u64" },
        { "name": "available", "type": "u64" }
      ],
      "docs": "Caller requested a transfer exceeding the account balance."
    }
  ]
}
```

`code` is a contract-local `u16`. Error codes are not globally unique; the contract + code pair is the disambiguator. Reserved range: codes `0..=99` are reserved for SDK-emitted system errors.

### 3.8 Metadata

The `metadata` object holds free-form extension data. Recommended keys (none mandatory):

- `metadata.license`: SPDX identifier of the contract source license
- `metadata.audit`: object describing audit history (auditor, date, URL)
- `metadata.upgradability`: how upgrades work (e.g., `"frozen"`, `"multisig"`, `"timelock"`)
- `metadata.deployment_chain`: `"mainnet"` / `"testnet"` / `"devnet"` for the bound `contract.address`

Tools MUST ignore unknown metadata fields rather than fail.

### 3.9 Encoding rules

All values follow **borsh** encoding (the same convention used elsewhere in the Sophis stack). Composite types compose recursively:

- `struct`: fields encoded in declaration order, concatenated.
- `enum`: a `u8` variant tag followed by the variant's fields.
- `array`: a `u32` length prefix followed by `length` element encodings.
- `optional<T>`: a `u8` (0 or 1) followed by, if 1, the encoded `T`.

For functions, the on-the-wire call payload is:

```
+-----------------+-------------------------+
| selector (8 B)  | borsh(input_args)       |
+-----------------+-------------------------+
```

For events, the runtime emits `(selector, topics[], data_blob)` where each topic is a 32-byte word (per SIP-4) and `data_blob` is borsh-encoded non-indexed fields.

### 3.10 Canonical signature for selector computation

The canonical signature used to derive a function or event selector is the UTF-8 string `name(type1,type2,...)` with **no whitespace** and **no parameter names**. For example:

- `transfer(sophis_address,u64)` → Blake2b-256 → first 8 bytes = selector
- `Transfer(sophis_address,sophis_address,u64)` → Blake2b-256 → first 8 bytes = selector

User-defined types are referenced by their declared `name` from the `types` array. Recursive type references are not allowed (a `struct A` cannot contain a `struct A` field, directly or indirectly).

## 4. Rationale

### 4.1 Why JSON, not a custom binary format

JSON loses ~30% wire efficiency compared to a binary format like CBOR or borsh-the-IDL-itself. The trade-off is intentional: every developer toolchain has JSON parsers, schema validators, diffing tools, and editor support. The IDL is consumed primarily by humans (browsing) and tools (codegen) — runtime performance is not a constraint. Ethereum's ABI JSON, Solana's Anchor IDL, OpenAPI, and JSON Schema all made the same trade.

### 4.2 Why selectors are 8 bytes, not 4 (Ethereum) or 32 (Solana)

Ethereum's 4-byte function selectors have caused real collisions over the ABI history (e.g., the `transferFrom` family). Solana's 32-byte selectors are collision-free but inflate calldata.

8 bytes gives 2⁶⁴ keyspace — collision-resistant for any practical contract count, while only adding 4 bytes per call versus Ethereum. Blake2b-256 (Sophis's standard hash) is used because it is already linked into every Sophis contract; SHA3-384 would force a hash family that the contract does not otherwise need.

### 4.3 Why Dilithium and Resource types are first-class

A generic `bytes` type forces every wallet, explorer, and SDK to treat Dilithium keys as opaque blobs, with no rendering rules ("show first 6 + last 6 of the hex string" being typical and unhelpful). Promoting `dilithium_pubkey`, `dilithium_signature`, and `resource<T>` to first-class types lets the IDL drive specialized rendering (e.g., "this is a key bound to address `sophis:q...`") and type-safe codegen.

The cost is one IDL revision per cryptographic primitive added at protocol level. This is acceptable: such additions are rare and require a hard fork anyway (Schnorr return = NACK per HARD_FORK_POLICY anti-rug invariant #4; new PQC primitive would itself be a SIP).

### 4.4 Why WASM hash is mandatory

A wallet rendering a transaction confirmation needs assurance that the IDL it is using actually describes the contract being called. Without a hash check, a hostile dApp could ship an IDL claiming `function transfer(recipient, amount)` for a contract whose actual exported function is `function drain(victim, attacker)`.

The `wasm_hash` field, combined with the verifier's on-chain query of the contract's actual WASM bytes, defeats this attack: the verifier hashes the on-chain bytes, compares to `contract.wasm_hash`, and refuses to render if they disagree.

### 4.5 Why off-chain storage

Storing IDLs on-chain (via DA carriers per SIP-6, or as a special transaction type) would impose state costs proportional to ecosystem growth — every contract upgrade republishes its IDL. The DA layer (Phase 6) is reserved for L2 batches and oracle data, not metadata. Off-chain storage with hash anchoring is the standard solution (Etherscan caches IDLs; npm caches package manifests; PyPI caches wheel metadata) and works without consensus involvement.

## 5. Backwards Compatibility

**Fully backwards compatible at every level.**

- **Consensus:** zero impact. The IDL is off-chain.
- **Existing contracts:** can ship an IDL retroactively. Contracts without an IDL continue to work; their tooling experience just remains opaque.
- **Existing tools:** Etherscan-style block explorers that today decode calldata via hand-curated tables can gradually migrate to IDL-driven decoding without breaking the old path.

## 6. Reference Implementation

A reference implementation is part of the Sophis SDK Rust workspace (post-mainnet roadmap):

- A `sophis-idl` crate exposing the IDL as a typed Rust struct, with serde-driven JSON parsing and validation.
- A `cargo sophis-build` subcommand that emits an `<contract-name>.idl.json` alongside the compiled WASM.
- An optional `sophis-idl-gen` tool that takes an IDL and emits typed Rust / TypeScript / Python bindings.

This SIP is **spec-only** at the time of submission. Per SIP-0 §5, the SIP remains in Draft status until a reference implementation exists and runs. Implementation tracks the existing Roadmap I item (cross-language SDK; not blocking pre-mainnet).

## 7. Security Considerations

### 7.1 Threat model

- **Malicious IDL.** A hostile party publishes an IDL claiming function signatures different from the deployed contract's actual exports. **Defense:** mandatory `wasm_hash` check (§4.4). Verifiers refuse to use an IDL whose hash does not match the on-chain WASM.
- **Outdated IDL.** A contract is upgraded but the publicly served IDL still describes the old version. **Defense:** the `wasm_hash` check fails for the new contract version, surfacing the mismatch to the user. Tools SHOULD refresh IDLs when they see hash mismatches.
- **Selector collisions.** Two different functions hash to the same 8-byte selector. **Defense:** the selector keyspace is 2⁶⁴ (~1.8×10¹⁹). A collision requires either deliberate construction (Blake2b-256 preimage resistance defends here) or vast contract corpus (each contract has ~10-50 functions; 2¹⁰ contracts × 50 functions ≈ 5×10⁴ entries, collision probability ≈ 10⁻¹⁵).
- **IDL availability denial.** The author's hosting goes down; tools cannot retrieve the IDL. **Defense:** tools SHOULD cache IDLs locally; package registries provide redundancy; multiple hosting locations are permitted (§3.1).

### 7.2 Cryptographic assumptions

- Blake2b-256 is collision-resistant (used for selector derivation and `script_hash` type).
- SHA3-384 is collision-resistant (used for `wasm_hash`, asset IDs, descriptor identity).
- These are the same assumptions backing the consensus layer; this SIP introduces no new cryptographic assumptions.

### 7.3 Privacy implications

IDLs are public by design. Publishing an IDL discloses the contract's interface, which discloses the application semantics. This is intentional: a contract whose interface is secret is also a contract whose users cannot review it. Contracts wishing to obscure behavior should not deploy publicly; the chain itself remains transparency-by-default.

### 7.4 Impact on Sophis subsystems

- **Long-range attack resistance:** none — IDL is off-chain.
- **Reorg behaviour:** none — off-chain.
- **Mempool policy:** none — off-chain.
- **Light-client / SPV verifiability:** unaffected; IDL is consumed by wallet UI, not by SPV validation.
- **ZK-Rollup (Phase 3):** L2 contracts MAY use the same IDL format. No L2-specific dialect is defined; SIP-13 v1 is universal across L1 and L2 sVM contracts.
- **ZK-Oracle (Phase 5 / Phase 9):** unaffected; oracle wire formats are separately specified (SIP-11).
- **Data Availability (Phase 6):** IDLs do not live in DA carriers.

## 8. Test Vectors

Test vectors for IDL parsing, selector computation, and type encoding will be published with the reference implementation. The initial set MUST include:

- A minimal contract with one function and no events (selector reproducibility test).
- A contract using every primitive type (round-trip encoding test).
- A contract using `resource<T>`, `dilithium_pubkey`, and `dilithium_signature` (Sophis-specific type test).
- A contract with an event declaring 4 indexed topics + a data blob (SIP-4 cross-reference test).

Implementers wishing to ship pre-vector compliance MAY generate their own from the reference compiler output and cross-check selector hashes manually.

## 9. References

- Ethereum ABI JSON (Solidity documentation, "Application Binary Interface") — prior art for JSON-based contract IDL
- Solana Anchor IDL (Anchor framework `idl.json`) — prior art for typed-binding generation
- NEAR ABI (`near-abi` crate) — Rust-native IDL generation
- IETF RFC 8259 — JSON specification
- NIST FIPS 204 — Dilithium ML-DSA (provides type definitions for `dilithium_pubkey`, `dilithium_signature`)
- SIP-4: sVM Event Logs — defines the event-log topic/data format that this IDL describes
- SIP-1: PSBS — borsh encoding conventions that this IDL inherits for parameter and return-value layouts
- SIP-5: Wallet Descriptors — uses Blake2b-256 in checksum computation, the same hash family this IDL uses for selectors

## 10. Copyright

This SIP is released into the public domain (CC0).
