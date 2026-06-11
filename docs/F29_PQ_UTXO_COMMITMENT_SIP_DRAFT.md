# SIP-draft: Post-Quantum UTXO-Set Commitment via LtHash (closes F-29)

> **Status:** DRAFT — design only, no code. Remediation for audit finding **F-29** (deep re-audit 2026-06-05). Pre-genesis consensus change; parameter selection gated on crypto-owner sign-off.
> **Scope:** replaces the UTXO-set commitment primitive (`crypto/muhash`) and its consumers; the block header `utxo_commitment` field and its 32-byte size are **unchanged**.

## 1. Abstract

The UTXO-set commitment is currently an additive accumulator `Σ blake2b(utxo_i) mod 2²⁵⁶` (`crypto/muhash/src/lib.rs`). This is the AdHash construction and is **not binding** at the intended security level: finding two distinct UTXO sets with the same commitment reduces to modular subset-sum, solvable far below 2¹²⁸ by lattice reduction / Wagner's generalized-birthday (Bellare–Micciancio show AdHash needs a modulus of ~1600+ bits). This SIP replaces it with **LtHash**, a lattice/SIS-based homomorphic set hash that preserves the O(1) incremental `add`/`remove`/`combine` interface while providing post-quantum binding, and applies the (currently dormant) `MuHashFinalizeHash` to produce the unchanged 32-byte header commitment.

## 2. Motivation (F-29)

- The commitment is consumed at the **pruning-point UTXO-set import** path (`consensus/src/consensus/mod.rs:1073 append_imported_pruning_point_utxos`, `:1088 import_pruning_point_utxo_set`). A syncing node verifies the imported pruning-point UTXO set against the committed multiset. A forgeable commitment lets a malicious peer inject a fabricated UTXO set (e.g. crediting itself) that matches the honest commitment → false-state / fund-theft against new/syncing nodes.
- The original audit (§6) never reviewed the additive rewrite — it still describes `crypto/muhash` as "Multiplicative hash".
- Sophis is PQC-from-block-0 (Dilithium-only). The commitment must be **post-quantum binding** — ruling out both the original multiplicative MuHash (Z* / EC, Shor-breakable) and the current additive-mod-2²⁵⁶ (classically subset-sum-broken).

## 3. Requirements for the primitive

The consumers (`consensus/core/src/muhash.rs::MuHashExtensions`, the `UtxoMultisetsStore`, the header validation, the pruning import) need:

1. **Incremental, O(1):** `add_element` / `remove_element` / `combine`, applied per block without rehashing the whole UTXO set.
2. **Order-independent:** the commitment is a function of the *set*, not insertion order (abelian group).
3. **Binding at ≥128-bit PQ:** infeasible to find two distinct (multi)sets with equal commitment.
4. **32-byte finalized output** for the header `utxo_commitment` field.
5. **No discrete-log / factoring group** (anti-Shor); deterministic, no float / hash-map-iteration / platform dependence.

Incrementality + homomorphism force an abelian-group state; binding = hardness of finding a non-trivial signed combination of element-images equal to the identity. The design choice is *which group*.

## 4. Specification — LtHash

LtHash (Lewi, Kim, Maykov, Weis — "Securing Update Propagation with Homomorphic Hashing", 2019): an incremental set hash whose state is a vector over `Z_{2^b}^n`, with security reducible to a short-vector / SIS lattice problem.

### 4.1 Parameters
- **Baseline: `LtHash16` — `n = 1024` lanes × `b = 16` bits → 2048-byte state.** This is the deployed Facebook parameter set; targets ≥128-bit collision resistance against currently-known lattice attacks.
- The exact `(n, b)` and target security level are the **crypto-owner's decision** (§9). Larger `n` (e.g. 2048 lanes / 4 KiB) buys margin at proportional storage/compute cost. The spec below is parameterized over `(n, b)`; only the genesis re-baseline depends on the concrete choice.

### 4.2 Element encoding → lattice vector
- The element bytes are **unchanged** from today (`write_utxo`: `outpoint.transaction_id ‖ outpoint.index_le ‖ block_daa_score_le ‖ amount_le ‖ is_coinbase ‖ spk_version_le ‖ var_bytes(spk_script)`). No consensus-visible change to *what* is committed.
- Expand the element to the `n·b`-bit lattice vector with a XOF: `expand = SHAKE128("SophisLtHashElement" ‖ element_bytes)` read as `n` little-endian `u16` lanes (for `b=16`). (SHAKE/Keccak keeps the SHA-3 family already used by `crypto/hashes`; blake2x is an acceptable alternative — pin one.)

### 4.3 Operations (drop-in for the current `MuHash` API)
| API (unchanged signature) | LtHash semantics |
|---|---|
| `MuHash::new()` | state = all-zero `[u16; n]` |
| `add_element(bytes)` | `state[i] = state[i].wrapping_add(expand(bytes)[i])` ∀ i |
| `remove_element(bytes)` | `state[i] = state[i].wrapping_sub(expand(bytes)[i])` ∀ i |
| `add_element_builder` / `remove_element_builder` | same, streaming the element into the XOF |
| `combine(other)` | `state[i] = state[i].wrapping_add(other.state[i])` ∀ i |
| `finalize() -> Hash` | **`MuHashFinalizeHash(serialize(state)) -> 32 bytes`** (the dormant hasher at `crypto/hashes/src/hashers.rs:23`, finally used) |
| `serialize() -> [u8; 2·n]` | little-endian lane bytes |
| `deserialize([u8; 2·n])` | inverse |

Abelian (commutative + associative) ⇒ order-independence; `add`∘`remove` = identity; `combine` = multiset union — all preserved. Remove is exact (group inverse), so reorg/spend semantics are unchanged.

### 4.4 Constants that change
- `EMPTY_MUHASH = finalize(all-zero state)` — a fixed 32-byte hash, **no longer `[0u8; 32]`**. (`crypto/muhash/src/lib.rs:9`, `consensus/core/src/config/genesis.rs:135`.)
- `SERIALIZED_MUHASH_SIZE = 2·n` (e.g. 2048), no longer 32. `HASH_SIZE` (the finalized commitment) stays 32.
- `genesis.utxo_commitment` — recomputed by `set_genesis_utxo_commitment_from_config` (`utxo_set_override.rs:14`), no code change there, just a new value.

## 5. Security

- **Binding** reduces to: finding a non-zero short integer combination `Σ cᵢ·expand(eᵢ) ≡ 0 (mod 2^b)` per lane — a short-vector/SIS instance. For `LtHash16` this is the analyzed, deployed parameterization; the 32-byte output adds a second collision-resistance layer via `MuHashFinalizeHash` (blake2b/SHA-3, ~128-bit PQ under Grover).
- **vs current additive-mod-2²⁵⁶:** that is the `n=1, b=256` degenerate case — a 1-dimensional subset-sum, the easy regime. LtHash is hard precisely because `n` is large.
- **vs multiplicative MuHash:** no discrete-log group ⇒ not Shor-breakable.
- **Empty/forgery:** `EMPTY` is a hash output, so "find a non-empty set summing to the empty commitment" is the same SIS hardness (not the trivial "sum to 0" of the current `[0;32]` empty).
- **Honest caveat:** the concrete bit-security of any lattice parameterization tracks the best-known attacks, which evolve. The chosen `(n,b)` must be signed off against a current estimate (§9), not asserted here.

## 6. Consensus & ABI impact

- **Block header `utxo_commitment`: UNCHANGED** (still 32 bytes = `finalize()`). No header-format / wire change.
- **`UtxoMultisetsStore` serialization GROWS** (`get/insert(hash, MuHash)`): 32 B → `2·n` B per stored multiset. This is the one storage-ABI change.
- **Hard-fork class, but PRE-GENESIS** → **no migration**: mainnet has not launched. Re-baseline `EMPTY_MUHASH`, `genesis.utxo_commitment`, and any fixed test vectors; that is the entire "migration".
- Closes F-29: pruning-point sync can no longer be fed a forged UTXO set.

## 7. Storage strategy (important — bounds the overhead)

The full `2·n`-byte state is only needed to **revert** a block's diff on reorg; reorgs are bounded by `finality_depth`, not `pruning_depth`.

- **Retain the full LtHash state only for chain blocks within the reorg/finality horizon**; for older (final) blocks keep only the 32-byte finalized commitment (sufficient for historical verification, never reverted).
- Steady-state overhead then ≈ `finality_depth × 2·n` bytes (bounded, small), **not** `pruning_depth × 2·n`.
- Without this optimization, `LtHash16` over a ~1.08 M-block `pruning_depth` would add ≈ 2.1 GB (vs ≈ 34 MB today); with it, the resident cost is the finality window only. **This split is a required part of the implementation, not optional.**
- Per-element compute: each UTXO add/remove now XOF-expands to `2·n` bytes (~64× the single blake2b today). Not dominant vs full block validation, but benchmark `add_transaction` over a worst-case block before genesis.

## 8. Reference-implementation plan

1. `crypto/muhash` — replace the accumulator internals; keep the public type/method names so `MuHashExtensions` and the stores are source-compatible. Bump `SERIALIZED_MUHASH_SIZE`. Wire `MuHashFinalizeHash` into `finalize()`.
2. `crypto/hashes` — `MuHashElementHash` → the XOF expansion (or add an `LtHashExpand` hasher); `MuHashFinalizeHash` now actually called.
3. `consensus/src/model/stores/utxo_multisets.rs` — widen the serialized form; implement the §7 full-state-within-finality / commitment-beyond split.
4. `consensus/core/src/config/genesis.rs` + `utxo_set_override.rs` — recompute `EMPTY_MUHASH` / genesis commitment (no logic change).
5. Re-baseline any committed test vectors / golden values.

## 9. Open decisions (crypto-owner sign-off)

1. **Parameters:** `LtHash16` (1024×16, 2 KiB) vs a larger `n` for margin — and the **target security level** against a current lattice-attack estimate.
2. **XOF:** SHAKE128 (SHA-3 family, already in tree) vs blake2x — pin one + the domain-separation strings.
3. **Storage horizon:** confirm `finality_depth` as the full-state retention window (§7).
4. (Rejected alternative recorded for the SIP: *wide-modulus AdHash* — additive mod a ≥2048-bit prime + finalize, ~256 B state, Bellare–Micciancio pedigree, simpler code, but parameter-sensitive and shares the "additive set-hash done wrong" failure mode. Available as a fallback if LtHash's storage/compute is deemed unacceptable.)

## 10. Test & validation plan

- Reuse the existing `crypto/muhash` property tests (order-independence, add/remove inverse, combine = union, serialize round-trip) — they must pass unchanged against the new internals.
- New: `EMPTY ≠ finalize(any non-empty set)`; fixed input→output test vectors (lock the XOF + finalize); a determinism vector reproduced byte-for-byte.
- Cross-check: a known UTXO set's commitment computed two ways (incremental vs from-scratch) must match.
- Soak/consensus: full `cargo test -p sophis-consensus` (the virtual-processor / pruning-import tests exercise the commitment end-to-end) + a devnet bring-up confirming genesis `utxo_commitment` validates.
