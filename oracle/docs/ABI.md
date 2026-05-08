# Sophis ZK-Oracle — ABI specification (sub-fase 5.5.b)

This document is the **stable ABI** of the Phase 5 ZK-Oracle. Every byte
order, every constant, every length prefix is binding: the relayer, the
on-chain contract, the SDK, and any third-party integration MUST agree
on this surface or they will be mutually unintelligible.

**Status:** v1, locked at sub-fase 5.5 (2026-05-05). Bumping any value
in this document is a hard fork of the relayer↔contract↔SDK protocol —
do not change without a coordinated rollout (see `MIGRATION.md`, TBD).

---

## 1. Constants

| Name | Value | Purpose |
|---|---|---|
| `ORACLE_INVOKE_VERSION` | `7` (u16) | SPK version of the relayer's invocation tx output |
| `FEED_STATE_VERSION` | `8` (u16) | SPK version of the contract's per-feed state UTXO |
| `BUNDLE_DOMAIN_V1` | `b"sophis-oracle-relayer-bundle-v1:"` (32 bytes) | Domain separator for the bundle commitment hash |
| `ORACLE_AIR_ID_V1` | `SHA3-384("sophis-oracle-air-v1")[..32]` (32 bytes) | Plonky3 AIR id for OracleAir |
| `VERIFY_AIR_ID_V1` | `SHA3-384("sophis-verify-air-v1")[..32]` (32 bytes) | Plonky3 AIR id for VerifyAirChip |
| `ML_DSA_44_SK_SIZE` | `2560` | FIPS 204 ML-DSA-44 secret key length |
| `ML_DSA_44_VK_SIZE` | `1312` | FIPS 204 ML-DSA-44 verification key length |
| `ML_DSA_44_SIG_SIZE` | `2420` | FIPS 204 ML-DSA-44 signature length |
| `INVOCATION_UTXO_VALUE` | `1_000` sompi | Locked in each invocation UTXO (reclaimed by contract) |
| `SUBMIT_TX_FEE` | `50_000` sompi | Relayer's fee per invocation tx |

## 2. Type encodings

All structured types use **borsh** (NOT serde) for canonical, deterministic
serialization. Borsh field order matches struct declaration order.

### 2.1 `FeedId`

8 raw bytes. Symbol left-padded to 8 bytes with NUL. Examples:

```text
"BTC/USD" -> 0x42 0x54 0x43 0x2F 0x55 0x53 0x44 0x00
"ETH"     -> 0x45 0x54 0x48 0x00 0x00 0x00 0x00 0x00
```

### 2.2 `PublisherKey`

32 raw bytes. The publisher's ed25519 public key on Pythnet (no encoding,
just the 32-byte serialized point).

### 2.3 `PriceUpdate` (borsh)

```text
feed:        FeedId       (8 bytes)
publisher:   PublisherKey (32 bytes)
price:       i64          (LE)
conf:        u64          (LE)
exponent:    i32          (LE)
publish_time: u64         (LE; UNIX seconds)
```

Total: 8 + 32 + 8 + 8 + 4 + 8 = **68 bytes** fixed.

### 2.4 `OracleJournal` (borsh)

```text
sequence:      u64  (LE; relayer-assigned monotonic counter)
feed:          FeedId
publisher:     PublisherKey
price:         i64  (LE)
exponent:      i32  (LE)
publish_time:  u64  (LE)
min_price:     i64  (LE; bound the AIR enforced)
max_price:     i64  (LE; bound the AIR enforced)
max_age_secs:  u64  (LE; bound the AIR enforced)
payload_hash:  [u8; 32]  (SHA3-256 of borsh(PriceUpdate) under the
                          domain "sophis-oracle-payload-v1:")
```

Total: 8 + 8 + 32 + 8 + 4 + 8 + 8 + 8 + 8 + 32 = **124 bytes** fixed.

### 2.5 `FeedSnapshot` (borsh) — what the contract persists

```text
price:         i64 (LE)
exponent:      i32 (LE)
publish_time:  u64 (LE)
sequence:      u64 (LE)
publisher:     [u8; 32]
```

Total: 8 + 4 + 8 + 8 + 32 = **60 bytes** fixed.

The contract stores ONE such snapshot per active feed in a UTXO of
SPK version 8. The script field of that UTXO is:

```text
borsh((FeedId, FeedSnapshot)) → 8 + 60 = 68 bytes
```

The SDK (`sophis-oracle-sdk`) reads exactly this layout.

## 3. Bundle commitment

The relayer signs the SHA3-256 hash of the bundle. Hash inputs are
fed in this exact order:

```text
SHA3-256(
    BUNDLE_DOMAIN_V1                               // 32 bytes
 || borsh(OracleJournal)                           // 124 bytes
 || u64_le(now_secs)                               // 8 bytes
 || u32_le(oracle_proof.len())                     // 4 bytes
 || oracle_proof                                   // variable
 || u32_le(verify_air_proof.len())                 // 4 bytes (0 if absent)
 || verify_air_proof                               // variable (empty if absent)
 || u32_le(verify_air_public_values.len())         // 4 bytes
 || verify_air_public_values                       // variable; if present, 96 bytes (pk||sig)
)
```

Result: 32 bytes. This is the message the relayer signs with ML-DSA-44.

## 4. Wire payload (invocation UTXO script)

The relayer's invocation tx puts these bytes into `output[0].script_public_key.script`:

```text
[u32 LE] L1 = oracle_journal.len()                 (always 124)
[bytes ] borsh(OracleJournal)
[u32 LE] L2 = oracle_proof.len()
[bytes ] oracle_proof_bytes
[u32 LE] L3 = verify_air_proof.len()               (0 if absent)
[bytes ] verify_air_proof_bytes
[u32 LE] L4 = verify_air_public_values.len()       (0 if absent; 96 if present)
[bytes ] verify_air_public_values
[u64 LE] now_secs                                  (8 bytes)
[1312 b] relayer_verification_key
[2420 b] relayer_signature                         (over the SHA3-256 commitment in §3)
```

Total length: `4 + 124 + 4 + L2 + 4 + L3 + 4 + L4 + 8 + 1312 + 2420`.

For a typical bundle (no companion): `1880 + L2`.
For a bundle with companion (96 PV + verify_air proof): `1980 + L2 + L3`.

The contract decodes this in one streaming pass and rejects on:
- Truncation (any LP overflow).
- Trailing bytes after the signature.
- VK length mismatch (must be exactly 1312).
- Sig length mismatch (must be exactly 2420).

## 5. STARK public values

### 5.1 OracleAir (`ORACLE_AIR_ID_V1`)

```text
[bytes] borsh(OracleJournal)         (124 bytes)
[u64 LE] now_secs                    (8 bytes; appended)
```

Total: 132 bytes. The SDK / contract reconstructs this from the wire
payload by serializing the journal and appending `now_secs`.

### 5.2 VerifyAirChip (`VERIFY_AIR_ID_V1`) — post sub-fase 5.6.0

```text
[32 bytes]  public_key  (publisher's ed25519 pk)
[64 bytes]  signature   (R || s)
[36 × 4 b]  R_point    limbs (X || Y || Z || T, each limb u32 LE)
[36 × 4 b]  A_point    limbs
[36 × 4 b]  sB         limbs
[36 × 4 b]  hA         limbs
```

Total: **672 bytes** = 96 raw + 576 limb bytes.

Bytes region: one BabyBear field element per byte (canonical 0..255).
Limbs region: one BabyBear element per 30-bit limb (serialized as u32 LE
because BabyBear's prime is just over 2^31, so each limb fits in 32 bits).

**5.6.0 expansion rationale:** Previously (5.4.b) only `(pk, sig)` were
exposed as public values, so the AIR's witnessed boundary points
`(R, A, sB, hA)` were invisible to the contract. This blocked companion
proof aggregation: future `decompress_air` / `scalar_mul_air` /
`sha512_compression` proofs each expose their own outputs as public
values, and the contract checks they equal the corresponding slot here.
Without 5.6.0, those companion proofs could not be bound to the
verify_air result.

## 6. AIR ID derivation

The SHA3-384 of the versioned domain string, truncated to 32 bytes:

```text
ORACLE_AIR_ID_V1 = SHA3-384(b"sophis-oracle-air-v1")[..32]
                 = ec 26 e0 81 1d 7a fb 27 36 db 8c 2c 33 5a 0e 6e
                   8f 23 b3 1f f5 4b a6 a9 80 4e 65 ce 7b 28 d3 6e
                   (recompute locally — do not trust this comment)

VERIFY_AIR_ID_V1 = SHA3-384(b"sophis-verify-air-v1")[..32]
                 = (recompute locally)
```

**Always recompute** in your code; do not hardcode the byte string. The
domain string (`sophis-oracle-air-v1`, `sophis-verify-air-v1`) is the
canonical source.

## 7. SVM capability requirement

Contracts that consume oracle bundles MUST declare these capabilities
in their `ContractManifest`:

- `Capability::VerifyDilithium` (for the relayer's bundle signature)
- `Capability::VerifyPlonky3Proof` (for both OracleAir and VerifyAirChip)
- `Capability::HashSha3` (for re-deriving the bundle commitment)
- `Capability::ReadUtxo` + `Capability::ProduceOutput` (for state UTXO update)

A node MUST be built with `--features svm-zk` to validate these
contracts. Lite builds panic loudly (anti-fork policy; see
`svm/host/src/lib.rs`).

## 8. Endianness

All multi-byte integers are **little-endian** (matches Sophis L1
convention and borsh default). No big-endian fields anywhere.

## 9. Relayer ↔ contract version compatibility

| Relayer wire version | Contract decodes | Notes |
|---|---|---|
| v1 (this doc) | v1 | Lockstep — relayer and contract pinned together |

A future v2 wire format (e.g. adding companion fields for SHA-512
binding) MUST bump `BUNDLE_DOMAIN_V1` to `v2`, increment
`ORACLE_INVOKE_VERSION` to `9`, and ship a coordinated rollout.

## 10. Third-party TypeScript / WASM bindings

The Sophis core team does NOT maintain official TS bindings. The wire
format above is sufficient for any language with:

1. SHA3-256 and SHA3-384 implementations (e.g. `@noble/hashes`)
2. borsh deserializer (e.g. `borsh-js`)
3. ML-DSA-44 verifier (FIPS 204; see `@noble/post-quantum`)
4. Plonky3 STARK verifier (port from `oracle/host` if going on-chain in
   another L1; off-chain JS verifier is non-trivial and not yet
   provided)

A reference TS reader for `FeedSnapshot` (no proof verification, just
trust the L1 RPC) requires only items (1)–(2) and ~50 lines of code.
This is left to the ecosystem.
