# J6 — Canonical Poseidon Specification (Spec-Only)

> **Status:** spec frozen for sub-fase J6.0; no code ships in J6.
> **Originating roadmap:** Roadmap J (Ethereum lessons), item J6.
> **Companion docs:** `SIPS/SIP-9-POSEIDON.md`.
> **Pre-existing baseline:** Sophis sVM exposes `Capability::HashSha3`
>   (SHA3-384 truncated where needed); `sophis-merkle` uses Blake2b
>   variants. Neither is zk-friendly: a Poseidon hash inside a SNARK
>   circuit costs ~50 constraints, while a SHA3-384 invocation costs
>   ~30 000 — a 600× difference that makes complex ZK applications
>   prohibitively expensive on Sophis today.
> **Why spec-only:** founder guidance (`project_ethereum_lessons.md`
>   item J6: "esperar demanda real, não especulativo. pós-mainnet
>   on-demand"). J6 ratifies the canonical Sophis Poseidon parameters
>   so that when a real ZK application surfaces, every implementer
>   uses the same constants and no second SIP is needed to retrofit
>   compatibility.

## 1. Motivation

Poseidon is a hash function family designed to be efficient inside
zk-SNARK / zk-STARK circuits. Its core operation is a permutation
over a prime field, with parameters tunable per security target. Used
by:

- **Ethereum L2s** (zkSync, Polygon Hermez, Aztec, StarkNet) — every
  major zk-rollup commits Poseidon hashes inside transaction proofs.
- **Mina Protocol** — uses Poseidon as the core hash everywhere,
  including state commitments.
- **Filecoin** — Poseidon for SDR / PoSt circuits.
- **Iden3 / Polygon ID** — zk-identity circuits.

Without a canonical Poseidon specification:

- **A future Sophis ZK dapp builder picks parameters arbitrarily.**
  Their circuit + their hash code work locally, but the hash isn't
  interoperable with anyone else's — no shared commitment registry,
  no cross-app proof composition.
- **The Sophis Phase 5 ZK-Oracle (Plonky3 STARK)** uses BabyBear
  field by convention; a future on-chain Poseidon should align with
  that field choice unless there's a compelling reason to diverge.
- **Sophis SDK has SHA3-384 + Blake2b**; adding Poseidon as a
  "first-class" sVM capability requires a hard-fork-relevant decision
  about parameters that should be made deliberately, not under
  pressure from a rollup integration.

J6 makes the parameter decision **once, before any rollup integration
exists**, freezing the canonical Sophis Poseidon spec so future ZK
work can compose freely.

This is item #11 in the sequential roadmap. Originally estimated
"1-2 weeks, post-mainnet on-demand"; J6 v1 ships only the spec doc +
SIP — no code, no sVM capability, no library implementation. Those
follow when a concrete ZK application demands them.

## 2. Ratified design decisions

These decisions were committed by the founder on 2026-05-11 and are
frozen for the J6 specification. Re-opening any of them requires a
new SIP.

| ID | Question | Choice | Rationale |
|----|----------|--------|-----------|
| **D1** | Prime field | **BabyBear** (`p = 2^31 - 2^27 + 1 = 0x78000001`) | Aligned with Sophis Phase 5 ZK-Oracle (Plonky3) which already standardises on BabyBear. Lets future Poseidon-using ZK applications compose with the existing oracle pipeline. Smaller than BN254 / BLS12-381, but lower-bit security (~64 bits over a single field element vs ~127 bits) is acceptable because Sophis Poseidon is for SNARK-internal commitments, not standalone authentication — security comes from accumulating multiple hashes (Merkle trees, transcripts) where collision resistance compounds. |
| **D2** | State size `t` | **`t = 16`** (16 field elements per permutation state, 15 absorbable lanes per round) | Parametric sweet-spot for BabyBear circuits per Plonky3 conventions. Larger `t` improves throughput per permutation but increases circuit width; `t = 16` matches the existing Sophis oracle stack (BabyBear + Poseidon2 + Plonky3 STARK in `oracle/` — 50+ chip implementation). |
| **D3** | S-box exponent `alpha` | **`alpha = 7`** | Smallest exponent satisfying `gcd(alpha, p-1) = 1` over BabyBear. Standard Plonky3 / Poseidon2 choice. |
| **D4** | Round counts `(R_F, R_P)` | **`(R_F = 8, R_P = 13)`** | Plonky3 Poseidon2 BabyBear-`t16` defaults; security level ~128 bits. The Plonky3 `poseidon2` crate v0.5.x ships with these as the canonical BabyBear-`t16` config; Sophis adopts byte-for-byte to maximize tooling compatibility. |
| **D5** | Domain separator | **`b"sophis-poseidon-v1\0"`** (19 bytes incl. trailing null), prepended to the hash input as one or more BabyBear field elements (each byte is a value in `[0, 256)`, comfortably below `p`). | Mirrors the J3 VRF + K2 filter convention (`b"sophis-{subsystem}-v1\0"`). Per-subsystem separator + version byte allow future `sophis-poseidon-v2` without breaking v1 callers. |
| **D6** | Input encoding | **Bytes packed into BabyBear field elements**: each input byte occupies one field element (4 bytes wasted per element since BabyBear is 31-bit, but uniform encoding eliminates ambiguity). Hash input length `L` is committed via prepended `L_LE_4` (4-byte little-endian length) so length-extension attacks are infeasible. | Simplicity > byte-packing efficiency for v1. Production ZK apps that need denser packing can layer their own field-element packing on top of the v1 spec — the canonical hash output is what other apps rely on. |
| **D7** | sVM capability | **DEFERRED.** No `Capability::HashPoseidon` ships in J6. | Per founder guidance (`project_ethereum_lessons.md` item J6: "esperar demanda real, não especulativo"). When a concrete ZK rollup or dapp integration needs on-chain Poseidon access, a follow-up SIP introduces the host fn + capability + gas cost, referencing the J6 spec for parameters. Until then, off-chain provers and verifier contracts can use any Rust Poseidon library configured per §3 below. |

## 3. Specification

### 3.1 Canonical parameters summary

```text
field            : BabyBear (p = 0x78000001 = 2^31 - 2^27 + 1)
state size t     : 16
sbox exponent α  : 7
full rounds R_F  : 8
partial rounds   : R_P = 13
total rounds     : R_F + R_P = 21
linear layer     : Poseidon2 standard MDS for t=16 BabyBear (matrix MAT_16_BB per Plonky3)
domain separator : b"sophis-poseidon-v1\0" (19 bytes, including trailing null)
```

### 3.2 Hash function `H(input_bytes) -> [u8; 32]`

```text
fn poseidon_hash(input: &[u8]) -> [u8; 32]:
    // 1. Prepend length + domain separator.
    let preamble = (input.len() as u32).to_le_bytes()
                || b"sophis-poseidon-v1\0";
    let stream = preamble || input;

    // 2. Encode each byte as one BabyBear field element (value = byte as u32).
    let mut elements: Vec<F> = stream.iter().map(|&b| F::from(b as u32)).collect();

    // 3. Pad with zeros to a multiple of (t - 1) = 15 elements.
    while elements.len() % 15 != 0:
        elements.push(F::ZERO);

    // 4. Sponge absorption: state initially [0; t]. For each chunk of 15 elements,
    //    XOR (additive in field) into the first 15 lanes, then permute.
    let mut state: [F; 16] = [F::ZERO; 16];
    for chunk in elements.chunks(15):
        for i in 0..15:
            state[i] += chunk[i];
        poseidon2_permutation(&mut state);

    // 5. Squeeze: take 8 BabyBear field elements (256 bits → 32 bytes via
    //    big-endian per-element 4-byte serialisation, ignoring the upper bit
    //    since BabyBear values fit in 31 bits).
    let mut out = [0u8; 32];
    for i in 0..8:
        let bytes = state[i].as_canonical_u32().to_be_bytes();
        out[i*4..(i+1)*4].copy_from_slice(&bytes);
    out
```

`poseidon2_permutation` is Poseidon2's standard `(R_F = 8, R_P = 13)`
permutation over BabyBear with `t = 16` and `alpha = 7`. Reference
implementation: Plonky3 `p3-poseidon2` crate v0.5.x, instantiated with
`Poseidon2BabyBear::<16>`.

### 3.3 Test vectors

The following vectors are FROZEN ABI. Any implementation that
disagrees on these values is incorrect.

| Input | Output (hex) |
|-------|--------------|
| `""` (empty) | TBD — first reference implementation will populate; pinned forever once published |
| `"abc"` | TBD |
| `b"\x00" × 32` | TBD |
| 1 KB of 0xAA | TBD |

The TBD values get filled in by the first reference implementation
and pinned in this doc + SIP-9 in a follow-up commit. Until then,
implementations should agree by deriving from the §3.1 + §3.2
specification.

### 3.4 What this spec does NOT cover

- **Merkle tree construction** using Poseidon. The hash function is
  the building block; tree shape (binary, n-ary, sparse, padding)
  is the application's choice. The Sophis ZK-Oracle's existing
  Plonky3 stack uses Poseidon2-keyed Merkle trees with
  `t = 16`; future on-chain Poseidon-based Merkle trees should
  document their tree shape in their own SIPs.
- **SNARK proof systems** (Groth16, PLONK, STARK) — Poseidon is
  proof-system-agnostic. The choice of proving system is a separate
  decision for each ZK application.
- **Cipher / encryption modes** — Poseidon-based ciphers exist
  (e.g. Rescue-Prime) but Sophis privacy posture is no native
  privacy (Decisão 5 of the 2026-05-04 pivot). v1 covers hash only.
- **Proof-of-work** — Sophis uses RandomX (per
  `project_pow_randomx_decisao_definitiva.md`). Poseidon does not
  replace it.

## 4. Threat model

| ID | Threat | Mitigation |
|----|--------|------------|
| T1 | Parameter mismatch between two implementations of "Sophis Poseidon" | Domain separator `b"sophis-poseidon-v1\0"` plus the frozen `(t, alpha, R_F, R_P, MAT)` set make any deviation produce a different hash. Mismatch is thus loud (test-vector failure), not silent. |
| T2 | Length-extension attack | Input length committed in the preamble (`L_LE_4`); padding is deterministic. No suffix can match a different `(input_len, input_bytes)` pair. |
| T3 | Collision via low-bit-security BabyBear | BabyBear single-field-element security is ~64 bits, BUT the hash output is **8 field elements squeezed = 248 effective bits**, comfortably above 128-bit collision resistance. Use cases that need >128-bit security should layer their own collision-resistant construction (e.g. double-hash). |
| T4 | Domain confusion across Sophis subsystems | Per-subsystem separator pattern (`sophis-vrf-v1`, `sophis-cf-v1`, `sophis-typed-v1`, `sophis-poseidon-v1`) ensures cross-system collision requires SHA3 / Poseidon second-preimage, computationally infeasible. |
| T5 | Future Poseidon parameter migration (Poseidon3?) | Version byte at end of separator (`v1` → `v2`) lets a future SIP introduce Poseidon3 parameters as a new Sophis Poseidon variant. Old v1 hashes remain valid against v1 spec; new v2 work uses v2 separator. No on-chain consensus impact since J6 ships no on-chain capability. |
| T6 | PQC posture | Poseidon is not a PQC hash (no quantum hardness claims for the underlying field arithmetic), but neither is SHA3 or Blake2b. PQC posture is at the **signature** layer (Dilithium ML-DSA-44), not the hash layer. Adding Poseidon does not change PQC posture. |
| T7 | Specifier ambiguity (Poseidon vs Poseidon2 vs Rescue) | D4 explicitly chose Poseidon2 (the optimised variant, current Plonky3 default). Spec doc + SIP-9 reference Plonky3 `p3-poseidon2` v0.5.x as the canonical reference implementation; future implementers can byte-compare against it. |

## 5. Comparison vs alternatives

| Hash | Family | Field | SNARK constraints/hash | Use case |
|------|--------|-------|-------------------------|----------|
| SHA-256 | Merkle-Damgård | bytes | ~30 000 (BN254) | Bitcoin, general |
| SHA3-384 (existing Sophis) | Keccak | bytes | ~30 000 (BN254) | Sophis canonical hash |
| Blake2b-384 (existing Sophis Merkle) | Blake | bytes | ~10 000 (BN254) | Sophis Merkle trees |
| **Poseidon2 BabyBear-`t16`** (J6) | **arithmetic** | **BabyBear** | **~50 (BabyBear-native STARKs)** | **Sophis ZK-friendly hash** |
| Poseidon BN254-`t3` | arithmetic | BN254 | ~250 (BN254 SNARK) | Ethereum L2s / Mina |
| Rescue-Prime BabyBear | arithmetic | BabyBear | ~70 | Alternative |

J6 chooses the BabyBear-`t16` variant to align with the existing Phase 5
ZK-Oracle stack (which already ships Poseidon2-based Merkle trees as
part of the AIR construction in `oracle/`). This makes the Sophis
ZK toolchain coherent: same field, same hash, same proof system.

## 6. Out-of-scope (for J6 v1)

J6 v1 is **specification only**. The following are deliberately
deferred to follow-up SIPs that will land when concrete demand
surfaces:

- **Reference Rust implementation** (`crypto/poseidon` crate) —
  ecosystem implementers can use Plonky3 `p3-poseidon2` v0.5.x
  directly today; a Sophis-canonical wrapper crate adds value only
  when 2+ Sophis projects need the same wrapper.
- **sVM `Capability::HashPoseidon`** — D7. Requires a hard-fork-
  relevant ABI commitment; defers until a concrete ZK application
  needs on-chain access (e.g. a rollup verifier contract).
- **Test vectors filled in** — §3.3 placeholders. The first
  implementation populates; this doc gets a follow-up commit pinning
  the values forever.
- **Merkle tree spec** — Poseidon is the building block; tree shape
  is application-specific.
- **SNARK / STARK proof system bindings** — proof-system agnostic.

## 7. Frozen ABI surface (such as it is for spec-only)

| Item | Value |
|------|-------|
| Field | BabyBear (`p = 0x78000001`) |
| State size `t` | 16 |
| S-box exponent `α` | 7 |
| `(R_F, R_P)` | `(8, 13)` |
| Domain separator | `b"sophis-poseidon-v1\0"` (19 bytes) |
| Output length | 32 bytes (8 BabyBear field elements, big-endian per element) |
| Reference implementation | Plonky3 `p3-poseidon2` v0.5.x, `Poseidon2BabyBear::<16>` |

## 8. Reference implementation map

| Sub-fase | Scope |
|---------|-------|
| J6.0 | This design document |
| J6.1 | `SIPS/SIP-9-POSEIDON.md` stub + `SIPS/README.md` index update |
| J6.2 | git commit (no code, no tests) |

Future follow-up sub-fases (separate SIP numbers when they land):

- **J6.x.a** — Reference Rust crate (`crypto/poseidon`) wrapping
  Plonky3 `p3-poseidon2` with the J6 domain separator + length
  preamble + 8-element squeeze. Ships when 2+ Sophis projects need
  the same wrapper.
- **J6.x.b** — sVM `Capability::HashPoseidon` + `sophis_hash_poseidon`
  host fn + gas constant. Ships when a concrete rollup verifier
  contract needs on-chain access.
- **J6.x.c** — Test vector population. Ships with J6.x.a or earlier.

## 9. Glossary

| Term | Meaning |
|------|---------|
| Poseidon | Hash function family designed for SNARK-friendliness; uses arithmetic operations over a prime field instead of bit operations. |
| Poseidon2 | Optimised variant of Poseidon (2023); reduces round count + simplifies the linear layer. Current Plonky3 default; Sophis canonical choice. |
| BabyBear | Prime field with `p = 2^31 - 2^27 + 1`. Smaller than BN254 / BLS12-381 but ~10× faster for STARK provers. Used by Plonky3 + RISC0 + the Sophis Phase 5 ZK-Oracle stack. |
| State size `t` | Number of field elements in the permutation's internal state. Larger `t` = higher throughput per permutation but larger circuits. |
| `R_F` / `R_P` | Number of full / partial rounds. Full rounds apply S-box to every state element; partial rounds apply only to the first. Together they determine the security level. |
| α (alpha) | The S-box exponent. Standard choices: 3, 5, 7. Sophis uses 7 (smallest valid for BabyBear). |
| Sponge construction | Hash-from-permutation paradigm: absorb input chunks into state, then squeeze output chunks. Used by SHA3 and adapted here for Poseidon. |
| Domain separator | Byte-string prefix prepended to the hash input to ensure the hash is unambiguously "this hash from this Sophis subsystem v1", preventing cross-subsystem collisions. |
