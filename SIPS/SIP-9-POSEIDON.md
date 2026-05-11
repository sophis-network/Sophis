```
SIP: 9
Title: Canonical Poseidon Specification (Spec-Only)
Author: Marcelo Delgado <sophis-network@proton.me>
Status: Draft
Type: Standards
Created: 2026-05-11
Requires: 0
```

# SIP-9: Canonical Poseidon Specification

> **Status note:** this SIP and its companion `docs/J6_POSEIDON_DESIGN.md`
> are **specification only.** No reference implementation, no sVM
> capability, no on-chain ABI ships in J6. Follow-up SIPs introduce the
> reference Rust crate (`crypto/poseidon`) and sVM
> `Capability::HashPoseidon` when a concrete ZK application demands them.
> This is the same pattern used by SIP-3 (ALT stub before full body)
> and J1 / K5 / O1 spec-only deliverables — founder ratifies the
> canonical format ahead of demand so future implementers compose freely.

## 1. Abstract

Sophis SDK currently exposes SHA3-384 (via `Capability::HashSha3`) and
Blake2b-384 (in `sophis-merkle`). Neither is zk-friendly: a SHA3 / Blake2b
hash inside a SNARK circuit costs ~10 000–30 000 constraints, while a
Poseidon hash costs ~50 — a 200–600× difference that makes complex ZK
applications prohibitively expensive on Sophis today.

SIP-9 ratifies the canonical Sophis Poseidon parameters (BabyBear field,
`t = 16`, `α = 7`, `R_F = 8`, `R_P = 13`, Poseidon2 variant per Plonky3
v0.5.x) and the canonical hash function shape (length-prefixed, domain-
separated, sponge with 15 absorbable lanes per round, 8-element squeeze
producing 32 bytes). With these frozen, the first ZK application built
on Sophis can reuse the spec without negotiating parameters.

J6 introduces no new cryptographic primitive **at the implementation
layer** — Plonky3 `p3-poseidon2` v0.5.x is the reference. SIP-9
formalises the Sophis-specific wrapping (domain separator, length
preamble, squeeze format) that future implementers MUST follow for
cross-implementation interoperability.

## 2. Motivation

See `docs/J6_POSEIDON_DESIGN.md` §1 for the canonical motivation:
SHA3-384 + Blake2b-384 are NOT zk-friendly; a future Sophis ZK dapp
without canonical Poseidon parameters would invent its own arbitrarily;
locking the spec **before** any rollup integration exists prevents
the parameter-fragmentation problem that plagued early Ethereum L2s.

J6 is item #11 in the sequential roadmap. Originally estimated
"1-2 weeks, post-mainnet on-demand"; J6 v1 ships only the spec doc +
SIP per founder guidance (`project_ethereum_lessons.md` item J6:
"esperar demanda real, não especulativo").

## 3. Specification

The technically complete specification is published at
`docs/J6_POSEIDON_DESIGN.md` in the reference implementation tree. It
enumerates:

- 7 ratified design decisions (D1–D7, §2)
- Hash function pseudocode (§3.2)
- Test vector slots (§3.3, populated by first impl)
- Threat model with 7 in-scope items (§4)
- Comparison vs SHA-256 / SHA3-384 / Blake2b-384 / Poseidon BN254 (§5)
- Frozen ABI surface (§7)

This SIP body will be re-issued in **Review** once the first reference
Rust implementation lands and populates the test vectors. Until then
the DESIGN doc is authoritative.

## 4. Frozen ABI surface

The following are **frozen** as of the J6 specification ratification.
Any implementation that disagrees on these values is incorrect.

### 4.1 Parameters

| Item | Value |
|------|-------|
| Field | BabyBear (`p = 0x78000001 = 2^31 - 2^27 + 1`) |
| State size `t` | 16 |
| S-box exponent `α` | 7 |
| Full rounds `R_F` | 8 |
| Partial rounds `R_P` | 13 |
| Linear layer | Poseidon2 standard MDS for `t = 16` BabyBear (Plonky3 `MAT_16_BB`) |
| Output length | 32 bytes (8 BabyBear field elements, big-endian per element) |
| Reference implementation | Plonky3 `p3-poseidon2` v0.5.x, `Poseidon2BabyBear::<16>` |

### 4.2 Hash function shape

```text
fn poseidon_hash(input: &[u8]) -> [u8; 32]:
    preamble = (input.len() as u32).to_le_bytes()
            || b"sophis-poseidon-v1\0"      // 19 bytes incl. trailing null
    stream   = preamble || input
    elements = stream.iter().map(|b| F::from(b as u32)).collect()
    while elements.len() % 15 != 0: elements.push(F::ZERO)

    let mut state: [F; 16] = [F::ZERO; 16];
    for chunk in elements.chunks(15):
        for i in 0..15: state[i] += chunk[i]
        poseidon2_permutation(&mut state)

    let mut out = [0u8; 32];
    for i in 0..8:
        out[i*4..(i+1)*4].copy_from_slice(&state[i].as_canonical_u32().to_be_bytes())
    out
```

### 4.3 Domain separator

| Item | Value |
|------|-------|
| Bytes | `b"sophis-poseidon-v1\0"` |
| Length | 19 bytes (including trailing null) |
| Position | Prepended to the input AFTER the 4-byte LE length preamble |
| Future versions | `b"sophis-poseidon-v2\0"` (etc.) introduced by future SIPs |

The trailing null byte makes the separator unambiguous against any
future `sophis-poseidon-vN` extension. Mirrors the J3 VRF
(`sophis-vrf-v1\0`), K2 filters (`sophis-cf-v1\0`), and J2 typed
signing (`sophis-typed-v1`) conventions.

### 4.4 Test vectors

Test vectors are **TBD** in v1. The first reference implementation
will populate `docs/J6_POSEIDON_DESIGN.md` §3.3 and re-issue this
SIP with the values pinned forever. Implementations published before
the test vectors are pinned MUST agree by deriving from the §3.1 +
§3.2 specification using Plonky3 `p3-poseidon2` v0.5.x.

## 5. Rationale

Deferred to the full SIP body. The DESIGN doc §2 already enumerates the
seven ratified decisions (D1–D7) and their rationales. The most likely
points of post-implementation revision are:

- D6 — denser input encoding (multiple bytes per field element) if
  bandwidth matters for an early adopter. Cost: a v2 separator + a
  new SIP.
- D2 — `t = 8` variant for circuits with smaller state budgets, if
  one shows up. v2 territory.
- D7 — promoting Poseidon to a sVM `Capability::HashPoseidon` once a
  concrete on-chain consumer surfaces. Separate SIP at that point.

## 6. Backwards Compatibility

**Activated at genesis** (since no on-chain ABI ships in J6, "activated"
is a no-op for full nodes). Existing Sophis hashes (SHA3-384, Blake2b-384)
remain canonical for their respective subsystems. Poseidon enters as a
new hash family used only by future ZK applications that opt in.

There is no consensus impact in J6 v1.

When a follow-up SIP introduces `Capability::HashPoseidon`, the
domain separator + parameters frozen in this SIP MUST be honoured by
the host-fn implementation; otherwise hashes computed off-chain
(during proving) won't match hashes computed on-chain (during
verification), breaking every proof.

## 7. Reference Implementation

Reference implementation: `sophis-network/Sophis` commit `<TBD>`
(spec-only single commit):

| Sub-fase | Scope |
|---------|-------|
| J6.0 | Design document (`docs/J6_POSEIDON_DESIGN.md`, ~270 lines) |
| J6.1 | This SIP stub + `SIPS/README.md` index update |
| J6.2 | Single commit; no code |

Future follow-up sub-fases (separate SIP numbers when they land):

- **Reference Rust crate** (`crypto/poseidon`) — wraps Plonky3
  `p3-poseidon2` v0.5.x with the J6 domain separator + length
  preamble + 8-element squeeze. Ships when 2+ Sophis projects need
  the same wrapper.
- **sVM `Capability::HashPoseidon`** — host fn + gas constant.
  Ships when a concrete rollup verifier contract needs on-chain
  access. Will require a separate ABI-freeze SIP (operations slot,
  gas cost, gRPC oneof slot if exposed via RPC).
- **Test vector population** — ships with the first reference
  implementation.

## 8. Security Considerations

Comprehensive threat model in DESIGN §4. Highlights:

- **Parameter mismatch produces a different hash** — implementations
  that diverge from §4.1 / §4.2 silently fail interoperability;
  domain separator + frozen parameter set make this loud rather than
  subtle.
- **Length-extension** — input length committed in 4-byte preamble;
  padding deterministic; no suffix can match a different
  `(input_len, input_bytes)` pair.
- **Collision resistance** — 8-element squeeze gives ~248 effective
  bits, comfortably above 128-bit collision security. Use cases
  needing more should layer their own construction.
- **Domain confusion across Sophis subsystems** — per-subsystem
  separator pattern prevents cross-system collision via SHA3 /
  Poseidon second-preimage (computationally infeasible).
- **PQC posture preserved** — Poseidon is not PQC at the hash layer
  (neither is SHA3 / Blake2b), but Sophis PQC posture is at the
  *signature* layer (Dilithium ML-DSA-44). Adding Poseidon does not
  change the security model.
- **Specifier ambiguity** — D4 explicitly chose Poseidon2 (the
  optimised variant). Plonky3 `p3-poseidon2` v0.5.x is the canonical
  reference; implementations byte-compare against it.

## 9. Test Vectors

Test vectors will be published in `docs/J6_POSEIDON_DESIGN.md` §3.3
when the first reference implementation lands. Until then:

- Empty input: TBD
- `"abc"`: TBD
- `b"\x00" × 32`: TBD
- 1 KB of `0xAA`: TBD

Implementations MUST agree by deriving from §3.1 + §3.2 using the
Plonky3 reference.

## 10. References

- Poseidon paper — Grassi, Khovratovich, Rechberger, Roy, Schofnegger
  (2019), *"Poseidon: A New Hash Function for Zero-Knowledge Proof
  Systems"*
- Poseidon2 paper — Grassi, Khovratovich, Schofnegger (2023),
  *"Poseidon2: A Faster Version of the Poseidon Hash Function"*
- Plonky3 `p3-poseidon2` v0.5.x — canonical reference implementation
  for parameters, MDS matrices, round constants
- `docs/J6_POSEIDON_DESIGN.md` — authoritative spec
- `project_ethereum_lessons.md` item J6 — strategic context
- `SIPS/SIP-3-ALT.md` — same "stub + design doc" pattern; J6 v1
  adopts the same shape
- `oracle/` — existing Phase 5 ZK-Oracle stack uses Poseidon2 BabyBear
  for AIR Merkle trees; J6 aligns Sophis canonical Poseidon with it

## 11. Copyright

This SIP is released into the public domain (CC0).
