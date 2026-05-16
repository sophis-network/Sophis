```
SIP: 16
Title: Self-Hosted Data Availability via V5 Carrier UTXOs (Phase 6)
Author: Marcelo Delgado <sophis-network@proton.me>
Status: Draft
Type: Standards
Created: 2026-05-12
```

# SIP-16: Self-Hosted Data Availability via V5 Carrier UTXOs (Phase 6)

## 1. Abstract

This SIP defines the **Self-Hosted Data Availability (DA)** layer in Sophis — a consensus-level primitive that allows arbitrary payloads to be published to the Sophis DAG by encoding them in `ScriptPublicKey` outputs with version 5 (the "carrier" version). Carrier outputs are validated by every node, indexed in an off-utxo DA store, and exposed to sVM contracts via the `Capability::VerifyDataAvailability` host function. The DA layer is the foundation for Phase 3 ZK-Rollup batch publication, Phase 5 oracle bundle publication (until SIP-11 D11 flip), and any third-party Sophis-aware application that needs L1-anchored data availability without relying on an external DA committee. This SIP formalizes the wire format, consensus rules, sVM capability, RPC methods, and operational constants of what was previously documented only as `oracle/docs/PHASE6_DA_DESIGN.md`.

## 2. Motivation

Layer-2 systems on Sophis — the Phase 3 ZK-Rollup, the Phase 5 oracle (and its Phase 9 successor in SIP-11), and any future application that wants L2-style throughput — need to publish data to L1 with three guarantees:

1. **Inclusion** — once a transaction containing a payload is accepted into the DAG, every full node has the bytes.
2. **Addressability** — payloads are content-addressed by a deterministic 48-byte hash, so anyone with the id can request the bytes from any full node.
3. **sVM verifiability** — a contract running in the sVM can deterministically check, at consensus time, whether a given payload id is present in the DAG with at least N confirmations.

External DA layers (Avail, Celestia, EigenDA) provide a (1)–(3) equivalent but introduce two structural problems for Sophis:

- **Pre-quantum signature stacks.** Avail uses BLS12-381 + Ed25519; Celestia uses Ed25519 + BLS. A CRQC adversary that breaks pre-quantum signatures can forge DA committee attestations and feed Sophis a fake "data is available" signal. Sophis ships PQC-only at L1 (FIPS 204 Dilithium ML-DSA-44); accepting a pre-quantum DA trust layer would undermine the overall posture.
- **Cross-chain custody and operational surface.** A Sophis ↔ Avail bridge would require either operating a relayer (regulatory surface per `OPERATIONAL_BOUNDARIES.md`) or accepting an external committee as a critical trust assumption (centralization).

This SIP defines DA at the Sophis L1 layer itself — every full node stores the bytes, every full node validates inclusion, every full node indexes the off-utxo DA store. The trust assumption for DA is identical to the trust assumption for the chain itself (honest majority of full nodes plus RandomX-secured PoW). No external chain, no external committee, no pre-quantum primitives.

The cost is upfront storage. Sophis pays for DA in block mass; carrier bytes are counted at the same `TRANSIENT_BYTE_TO_MASS_FACTOR` as any other transaction byte. This is consistent with Sophis's overall posture of transparent, fully-replicated L1 state.

## 3. Specification

The full specification is maintained at [`oracle/docs/PHASE6_DA_DESIGN.md`](../oracle/docs/PHASE6_DA_DESIGN.md). This SIP §3 distills the load-bearing wire format, constants, consensus rules, and sVM capability. In case of ambiguity between this SIP and the design document, the design document is canonical for implementation detail; this SIP is canonical for the **standard** that other Sophis-aware implementations must follow.

### 3.1 Wire format — V5 carrier output

A carrier output is a `TransactionOutput` whose `script_public_key.version` equals `5`. The script is structured as:

```
+-----------------------+------+----------------------------------------+
| offset                | bytes | content                                |
+-----------------------+------+----------------------------------------+
| 0..8                  | 8    | CARRIER_MAGIC = b"SPHS-DA1"            |
| 8                     | 1    | flags (see §3.2)                       |
| 9                     | 1    | reserved-1 (MUST be 0)                 |
| 10                    | 1    | fragment_count (1..=32)                |
| 11                    | 1    | fragment_index (0..fragment_count)     |
| 12..16                | 4    | data_len (little-endian u32, ≤ 65_536) |
| 16..64                | 48   | bundle_id (SHA3-384, all-zero if       |
|                       |      | fragment_count == 1)                   |
| 64..(64 + data_len)   | var  | data payload                           |
+-----------------------+------+----------------------------------------+
```

`script_public_key.script.len()` MUST equal exactly `64 + data_len`. `output.value` MUST equal `0` sompi (any non-zero value rejects the transaction).

### 3.2 Flags byte

Bits in `flags` (most significant on the left):

| Bit | Name | Semantic |
|---|---|---|
| 0 (lsb) | `CARRIER_FLAG_FRAGMENTED` (0x01) | Set iff `fragment_count > 1` |
| 1 | `CARRIER_FLAG_LAST` (0x02) | Set iff `fragment_index == fragment_count - 1` |
| 2 | reserved (MUST be 0) | — |
| 3 | reserved (MUST be 0) | — |
| 4 | `CARRIER_FLAG_DOMAIN_ROLLUP` (0x10) | Informational: Phase 3 batch payload |
| 5 | `CARRIER_FLAG_DOMAIN_ORACLE` (0x20) | Informational: oracle bundle (Phase 5 / Phase 9) |
| 6 | `CARRIER_FLAG_DOMAIN_USER` (0x40) | Informational: third-party application |
| 7 | reserved (MUST be 0) | — |

At most one of bits 4, 5, 6 MAY be set. Domain flags are informational only — they do not change consensus validation but allow indexers and dashboards to filter carriers by producer category.

### 3.3 Constants (ABI freeze)

The following constants form the ABI freeze. Any change requires a hard fork:

| Name | Value | Purpose |
|---|---|---|
| `SCRIPT_VERSION_CARRIER` | `5` (u16) | SPK version of a carrier output |
| `MAX_SCRIPT_PUBLIC_KEY_VERSION` | `5` | Highest accepted SPK version (3, 4 = Phase 3 bridge legacy; 5 = carrier) |
| `CARRIER_MAGIC` | `b"SPHS-DA1"` (8 bytes) | First 8 bytes of every carrier script |
| `CARRIER_HEADER_LEN` | `64` | Fixed header bytes before `data` |
| `CARRIER_PAYLOAD_HASH_ALG` | `SHA3-384` | Used for `payload_id` and `bundle_id` |
| `CARRIER_PAYLOAD_HASH_LEN` | `48` | Hash length in bytes |
| `MAX_FRAGMENTS` | `32` | Max carrier outputs per bundle |
| `MAX_DATA_PER_CARRIER` | `65_536` (64 KiB) | Max `data_len` per carrier output |
| `MAX_BUNDLE_BYTES` | `2_097_152` (2 MiB = 32 × 64 KiB) | Max reassembled bundle size |
| `CARRIER_OUTPUT_VALUE` | `0` sompi | Mandatory; any non-zero value rejects the transaction |
| `MAX_CARRIER_OUTPUTS_PER_TX` | `8` | Anti-spam cap per transaction |
| `DEFAULT_DA_CONFIRMATIONS` | `1000` (blue-score gap) | Default `min_confirmations` for `VerifyDataAvailability` |

### 3.4 Identifier derivation

Two identifiers anchor every carrier:

```
payload_id = SHA3-384(CARRIER_MAGIC || header_bytes || data)        // 48 bytes, per-output
bundle_id  = SHA3-384(CARRIER_MAGIC || fragment_count || data_concat)  // 48 bytes, per-bundle
```

Where `header_bytes` is bytes `8..64` of the carrier script (excluding the magic prefix), and `data_concat` for a fragmented bundle is the concatenation of every fragment's `data` in `fragment_index` order. For a single-fragment bundle (`fragment_count == 1`), `bundle_id == payload_id`.

A bundle is **reassemblable** iff a full node has received and accepted every fragment indexed `0..fragment_count`. The DA store maintains this state and exposes it via the RPC `getDaBundle` method.

### 3.5 Consensus rules

A transaction containing one or more carrier outputs is valid iff **all** of the following hold for **every** such output:

1. `script_public_key.script.len() >= CARRIER_HEADER_LEN` (64 bytes).
2. `script[0..8] == CARRIER_MAGIC`.
3. `script[9] == 0` (reserved-1).
4. `flags = script[8]` has reserved bits 2, 3, 7 unset.
5. At most one of bits 4, 5, 6 of `flags` is set.
6. `fragment_count = script[10]` is in `1..=MAX_FRAGMENTS`.
7. `fragment_index = script[11]` is in `0..fragment_count`.
8. `(flags & CARRIER_FLAG_FRAGMENTED) != 0` iff `fragment_count > 1`.
9. `(flags & CARRIER_FLAG_LAST) != 0` iff `fragment_index == fragment_count - 1`.
10. `data_len = u32::from_le_bytes(script[12..16])` is in `0..=MAX_DATA_PER_CARRIER`.
11. `script.len() == CARRIER_HEADER_LEN + data_len` exactly.
12. `output.value == 0` sompi.

Plus, at the transaction level:

13. The transaction has at most `MAX_CARRIER_OUTPUTS_PER_TX` (= 8) outputs with `version == 5`.
14. Carrier outputs MUST NOT appear in a coinbase transaction.

If any of rules 1–14 fail, the transaction is rejected. Carrier outputs are **immediately removed from the active UTXO set** after the containing block is accepted into the selected parent chain. They do not appear in subsequent `getUtxosByAddresses` lookups, do not appear in the Merkle UTXO commitment, and cannot be spent.

A separate **DA store** (see §3.7) holds the body of every accepted carrier output, keyed by `payload_id` and `bundle_id`. The store is part of full-node state but is NOT part of the consensus state commitment for v1.

### 3.6 sVM capability — `VerifyDataAvailability`

The sVM exposes a host function for contracts to query DA inclusion deterministically:

```rust
fn sophis_verify_da(
    payload_id: &[u8; 48],
    min_confirmations: u64,
) -> bool;
```

Returns `true` iff:

1. The payload with the given `payload_id` is present in the DA store.
2. The block that accepted that payload has at least `min_confirmations` blue-score depth below the current virtual selected tip at the time of the contract call.

If `min_confirmations == 0`, the function uses `DEFAULT_DA_CONFIRMATIONS` (1000). Determinism is guaranteed because both the DA store contents and the current virtual selected tip are inputs to deterministic block validation — every full node computes the same boolean for the same `payload_id` at the same DAA score.

The capability is registered as `Capability::VerifyDataAvailability` in the sVM capability enum (see SIP-4 capability registration pattern; SIP-16 follows the same shape).

### 3.7 DA store

Every full node maintains a key-value store under its data directory:

```
<data_dir>/<network>/da-store/
    payloads/      // key = payload_id (48 B);  value = (script bytes, accepting_block_hash,
                   //                                     blue_score, fragment_index, bundle_id)
    bundles/       // key = bundle_id (48 B);   value = sorted list of payload_ids by fragment_index
    by_block/      // key = block_hash;         value = list of payload_ids accepted in that block
    by_domain/     // key = (domain_byte, blue_score_bucket); value = list of payload_ids
```

The reference implementation uses RocksDB column families inside the existing consensus storage. Alternative implementations MAY use any storage backend that satisfies the read API defined in §3.8.

Pruning of the DA store follows the same rules as block storage: pruned blocks remove their associated carrier entries. Archival nodes (per SIP-8) retain all carriers indefinitely.

### 3.8 RPC methods

Three new RPC methods are added to the canonical gRPC, wRPC, and JSON-RPC transports:

| Method | Returns |
|---|---|
| `getDaSection(carrier_id)` | A single carrier fragment: `(carrier_id, bundle_id, fragment_index, total_fragments, domain, block_hash, payload)` |
| `getDaBundle(bundle_id)` | The reassembled full bundle: `(bundle_id, domain, fragment_count, anchor_block_hash, payload)`. Fails if any fragment is missing |
| `getDaStats()` | Aggregate counts: total carriers indexed, total bundles complete, total bytes stored, per-domain breakdown |

Wire formats are defined in `rpc/grpc/core/proto/messages.proto`. Clients SHOULD use the canonical Python (`sophis-network/sophis-py`), Rust SDK, or any other community implementation for these methods.

## 4. Rationale

### 4.1 Why version 5 specifically

The `ScriptPublicKey.version` field is a `u16` reserved for future expansion. Versions 0–2 are pre-existing Sophis script versions (P2PKH-equivalent, P2SH, native token). Versions 3 and 4 are reserved for the Phase 3 ZK-Rollup bridge legacy formats (`BRIDGE_VAULT_VERSION = 3`, `BRIDGE_CLAIM_VERSION = 4`). Version 5 is the next available slot and is dedicated to carrier outputs.

Choosing a dedicated version (rather than overloading version 0/1/2) keeps the consensus dispatch clean: a single match on `script_public_key.version()` routes to the carrier-validation codepath without ambiguity.

### 4.2 Why SHA3-384 rather than SHA-256 or Blake2b

SHA3-384 is chosen for three reasons:

1. **Post-quantum margin.** SHA3-384 provides 192-bit classical preimage resistance and 96-bit Grover-bound quantum preimage resistance. SHA3-256 (128-bit / 64-bit) was rejected as insufficient margin for a long-lived L1 primitive. Sophis is designed for multi-decade operation; the hash choice should outlast the Dilithium signature scheme it complements.
2. **NIST-standardized.** SHA-3 family (FIPS 202) is the only NIST-standardized hash with both 256-bit and 384-bit variants; using the same family across the entire Sophis stack (asset IDs, descriptor identity, DA payloads) simplifies cryptographic agility analysis.
3. **Independent from Blake2b.** Blake2b is used for Sophis address derivation. Using a different hash family for DA payload addressing means a hypothetical Blake2b collision-attack does not propagate to the DA layer.

The 48-byte hash length pays a small wire-format premium (16 bytes more than SHA-256, 16 bytes more than Blake2b-256) per payload. For the 64-byte carrier header the premium is in the noise; for the per-payload `payload_id` field it is a deliberate design choice for post-quantum margin.

### 4.3 Why payloads are not in the UTXO set

Carrier outputs have zero value and are unspendable by construction (rule 12 in §3.5; the validation rules prevent any spending transaction from referencing them). Keeping them in the UTXO set would inflate the working state of full nodes proportionally to total carrier publication.

The DA store is separate from the UTXO set: carriers leave the UTXO set the moment their containing block is accepted, but their bytes are indexed in the DA store. This separation lets nodes apply different pruning policies to the two stores (e.g., archival of UTXO history with weekly pruning of DA payloads, if a future SIP defines that policy).

### 4.4 Why the DA store is not in the consensus state commitment

Including the DA store in the Merkle UTXO commitment would force every node to compute and verify a commitment over every carrier payload. For a 2 MiB bundle this is non-trivial work that benefits no consensus-critical decision: the carrier inclusion check is satisfied by witnessing the transaction containing the carrier output, which is already part of the block (and thus part of the block hash commitment chain).

`Capability::VerifyDataAvailability` therefore operates on the DA store state at the **time of contract execution**, not at the time of block production. This is the same trust model as `Capability::ReadUtxo` (which reads the local UTXO snapshot at execution time) — every full node computes the same answer because every full node computes the DA store state from the same input blocks.

### 4.5 Why 2 MiB maximum bundle size

A 2 MiB bundle covers Phase 3 batch calldata for up to ~5,000 L2 transactions (typical 400 bytes each), which is well above both the 100-tx-batch trigger and the 30-second time trigger that govern Phase 3 sequencer batches. Allowing larger bundles would require either accepting larger transactions (raising block mass concerns) or accepting multi-block bundles (creating reassembly complexity and adversarial-truncation surface).

`MAX_FRAGMENTS × MAX_DATA_PER_CARRIER = 32 × 64 KiB = 2 MiB` is the upper bound; smaller bundles are encouraged. A 100-tx batch (~40 KiB) fits in a single fragment.

### 4.6 Why this is a SIP

Phase 6 was implemented and shipped pre-mainnet (consensus baked in from DAA 0). The implementation predates the SIP-0 process formalization. This SIP retroactively formalizes the standard so that:

- Other Sophis-aware implementations (future alternative full nodes, light clients, or wallet integrations) can implement carrier validation against an authoritative reference.
- The wire format and constants are documented in a Standards-track file rather than only in implementation-side design notes.
- Cross-references from SIP-1 (PSBS), SIP-4 (events), SIP-11 (PQC Oracle), SIP-12 (AA), and SIP-13 (IDL) can point to a SIP rather than to ad-hoc design documents.

## 5. Backwards Compatibility

**This is the activation specification, not a change.** Phase 6 ships at genesis with no activation gate. Nodes upgraded after the publication of this SIP MUST already be Phase-6-aware (i.e., MUST validate carrier outputs per §3.5). Nodes that ignore carrier validation would reject otherwise-valid blocks containing carrier transactions and fork off the canonical chain.

For the reference implementation, Phase 6 was completed in sub-fases 6.0 through 6.9 (see `oracle/docs/PHASE6_DA_DESIGN.md` §1, `oracle/docs/PHASE6_AUDIT.md`, `oracle/docs/PHASE6_RUNBOOK.md`). Total reference-implementation code count: ~83 tests, 11 commits, fuzz coverage on the codec.

A future hard fork that modifies the §3.3 constants, the §3.5 consensus rules, or the §3.6 capability signature would require a new SIP and the migration process documented in SIP-0 §10.4. Such changes are explicitly **strongly discouraged** unless a security flaw is discovered, given the production-data dependency of L2 systems (Phase 3 ZK-Rollup, Phase 5 oracle) on the current ABI.

## 6. Reference Implementation

The reference implementation is the Sophis main codebase. Key locations:

- [`consensus/core/src/da/`](../consensus/core/src/da/) — DA codec (`payload_id`, `bundle_id_of`, `encode_*`, `reassemble`) with SHA3-384 NIST test-vector validation
- [`consensus/src/model/stores/da.rs`](../consensus/src/model/stores/da.rs) — RocksDB DA store with 4 prefixes (196-199)
- [`consensus/src/pipeline/virtual_processor/`](../consensus/src/pipeline/virtual_processor/) — carrier indexing hook in `commit_utxo_state` (`index_carriers_in_block`)
- [`svm/`](../svm/) — `Capability::VerifyDataAvailability` registration, `HostDa` trait, `SophisDaBackend`
- [`rpc/grpc/core/proto/messages.proto`](../rpc/grpc/core/proto/messages.proto) — `getDaSection` / `getDaBundle` / `getDaStats` request/response messages
- [`oracle/docs/PHASE6_DA_DESIGN.md`](../oracle/docs/PHASE6_DA_DESIGN.md) — canonical design specification
- [`oracle/docs/PHASE6_RUNBOOK.md`](../oracle/docs/PHASE6_RUNBOOK.md) — operational runbook
- [`oracle/docs/PHASE6_AUDIT.md`](../oracle/docs/PHASE6_AUDIT.md) — adversarial test runner + threat matrix (13 threats)
- [`oracle/docs/PHASE6_STRESS_PLAN.md`](../oracle/docs/PHASE6_STRESS_PLAN.md) — 72-hour pre-mainnet stress test (9 acceptance gates)
- [`oracle/docs/PHASE6_BUG_BOUNTY.md`](../oracle/docs/PHASE6_BUG_BOUNTY.md) — voluntary security review (unpaid, no reward)
- [`oracle/docs/PHASE6_RFC.md`](../oracle/docs/PHASE6_RFC.md) — RFC for community review

This SIP enters Draft simultaneously with the existing reference implementation. Per SIP-0 §5, Draft → Review transition requires the reference implementation to "exist and run" — that condition is already met. Draft → Final transition requires the pre-mainnet stress test (`oracle/docs/PHASE6_STRESS_PLAN.md`, 9 acceptance gates, 72-hour run) to complete successfully; this stress run is operational follow-up.

## 7. Security Considerations

The full threat matrix is in [`oracle/docs/PHASE6_AUDIT.md`](../oracle/docs/PHASE6_AUDIT.md). Summary of the load-bearing concerns:

### 7.1 Threat model

| Adversary | Capability | Design response |
|---|---|---|
| Malicious carrier producer | Publish a carrier with invalid header bytes | Consensus rule (§3.5) rejects; block containing the tx is invalid |
| Carrier-flood DoS | Submit many large carriers to inflate full-node storage | `MAX_CARRIER_OUTPUTS_PER_TX = 8` + standard block-mass cap enforce upper bound; carrier bytes pay regular fee |
| Bundle reassembly inconsistency | Publish fragment 0 in block N, fragment 1 in block N+1000, never publish fragment 2 | Reassembly is incomplete; `getDaBundle` returns "missing fragment 2" error; consumers can decide their own timeout policy |
| Fragment forgery | Publish a fragment with a fabricated `bundle_id` | `bundle_id` is content-addressed (`SHA3-384(data_concat)`); a fragment claiming a `bundle_id` that does not match the actual data hash fails reassembly |
| sVM `VerifyDataAvailability` race | Contract A queries carrier X; X is then pruned; contract B (later) gets `false` | Pruning is deterministic per block-height policy. Both contracts see consistent state for the same DAA score |
| Long-range attack against historical carrier inclusion | Adversary builds an alternate history containing a fake carrier | `min_chain_work` + `max_chain_work_seen` (anti long-range attack) defends; an alternate history below the floor is rejected before its carriers can override the canonical DA store |
| External-DA quantum forge | (Not applicable — Sophis DA uses no external committee) | Self-DA inherits the same PQC guarantees as L1 itself |

### 7.2 Cryptographic assumptions

- **SHA3-384 (FIPS 202)** is collision-resistant. The 48-byte digest provides 192-bit classical and 96-bit Grover-bound quantum preimage resistance.
- **Dilithium ML-DSA-44 (FIPS 204)** is unforgeable. Used to sign the transactions that contain carrier outputs (the carriers themselves do not require a separate signature beyond the transaction signature).
- **RandomX PoW** is computationally infeasible to fake. Carrier inclusion requires the containing block to be PoW-valid.

These are the same assumptions backing L1 consensus; this SIP introduces no new cryptographic assumptions.

### 7.3 Privacy implications

Carriers are public bytes. Applications wishing to publish encrypted blobs MUST encrypt off-chain before publishing; the consensus layer treats every carrier as opaque public bytes. There is no privacy primitive at the DA layer, consistent with the broader Sophis posture of transparency-by-default.

### 7.4 Impact on Sophis subsystems

- **Long-range attack resistance:** carriers participate in long-range protection like any other transaction-byte; `min_chain_work` defense applies.
- **Reorg behaviour:** carriers in reorged-out blocks are removed from the DA store atomically with the rollback of UTXO state.
- **Mempool policy:** carrier transactions are subject to the same mempool admission and replacement rules as any other transaction.
- **Coinbase maturity:** carriers cannot appear in coinbase outputs (§3.5 rule 14), so coinbase maturity is not affected.
- **Light-client / SPV verifiability:** SPV clients (SIP-7) can verify carrier transactions are in a block via the standard Merkle-proof path. They cannot, however, verify the carrier *bytes* without a full node (or a server that exposes the DA store).
- **ZK-Rollup (Phase 3) compatibility:** Phase 3 sequencer publishes batch calldata via Phase 6 carriers. `BatchJournal.da_bundle_id` references the carrier bundle.
- **ZK-Oracle (Phase 5) / Phase 9:** Phase 5 relayer optionally publishes via `da_publish=true`; Phase 9 publisher CLI MAY use the same mechanism.
- **Account Abstraction (SIP-12):** AA contracts MAY use `Capability::VerifyDataAvailability` to gate operations on DA-published data (e.g., "execute this operation only if the off-chain instruction X is anchored").
- **IDL (SIP-13):** contracts using `VerifyDataAvailability` declare it in their IDL `capabilities` array.

## 8. Test Vectors

Reference test vectors for the codec, identifier derivation, and consensus rules are validated in [`consensus/core/src/da/codec.rs`](../consensus/core/src/da/codec.rs) tests. The vectors cover:

- NIST SHA3-384 test vectors (FIPS 202 §C.2 "abc" and §C.2 empty-string) for the underlying hash.
- A single-fragment carrier round-trip: encode → decode → re-encode reproduces byte-identical output.
- A 32-fragment maximum bundle: encode → fragment → reassemble produces byte-identical bundle.
- Boundary cases: `data_len = 0`, `data_len = 65_536`, `fragment_count = 1`, `fragment_count = 32`.
- Adversarial cases: wrong magic, wrong reserved-1 byte, mismatched `script.len()` vs `data_len`, fragment_index ≥ fragment_count, non-zero output value.
- Fuzzing: `fuzz_payload_id_is_collision_resistant_for_distinct_inputs`, `fuzz_encode_bundle_roundtrips_for_random_blobs`, `reassemble_rejects_duplicate_fragment_index`, `reassemble_rejects_missing_fragment`, `reassemble_handles_unordered_inputs`, `reassemble_happy_path_multi_fragment`, plus 6 codec-level fuzz tests (~10k iterations each).

A complete table of test-vector inputs and expected `payload_id` / `bundle_id` outputs will accompany the SIP at the time of its Final-status transition. Implementations claiming SIP-16 conformance MUST pass all tests in `consensus/core/src/da/codec.rs::tests::*`.

## 9. References

- [`oracle/docs/PHASE6_DA_DESIGN.md`](../oracle/docs/PHASE6_DA_DESIGN.md) — canonical design specification (this SIP §3 is its distillation)
- [`oracle/docs/PHASE6_AUDIT.md`](../oracle/docs/PHASE6_AUDIT.md) — adversarial threat matrix (13 threats)
- [`oracle/docs/PHASE6_RUNBOOK.md`](../oracle/docs/PHASE6_RUNBOOK.md) — operational runbook
- [`oracle/docs/PHASE6_STRESS_PLAN.md`](../oracle/docs/PHASE6_STRESS_PLAN.md) — 72-hour pre-mainnet stress test (9 acceptance gates)
- [`oracle/docs/PHASE6_BUG_BOUNTY.md`](../oracle/docs/PHASE6_BUG_BOUNTY.md) — voluntary security review (unpaid, no reward)
- [`oracle/docs/PHASE6_RFC.md`](../oracle/docs/PHASE6_RFC.md) — RFC for community review
- NIST FIPS 202 — SHA-3 family (the hash function used for `payload_id` / `bundle_id`)
- NIST FIPS 204 — Dilithium ML-DSA-44 (the signature scheme securing transactions that contain carriers)
- [`SIP-1: PSBS`](./SIP-1-PSBS.md) — borsh encoding conventions inherited by the DA codec
- [`SIP-4: sVM Event Logs`](./SIP-4-EVENTS.md) — capability registration pattern that `VerifyDataAvailability` follows
- [`SIP-7: Light Client SPV`](./SIP-7-LIGHT-CLIENT.md) — SPV interaction with carrier transactions
- [`SIP-11: PQC-Native Oracle`](./SIP-11-PQC-ORACLE.md) — Phase 9 oracle producers may publish via carriers
- [`SIP-12: Account Abstraction`](./SIP-12-AA.md) — AA contracts may consume `VerifyDataAvailability`
- [`SIP-13: IDL`](./SIP-13-IDL.md) — IDL `capabilities` field declares contract dependency on this primitive
- Avail DA (https://www.availproject.org/) — pre-quantum external DA layer rejected during 2026-05 design review
- Celestia DA (https://celestia.org/) — same rejection rationale
- [`project_phase6_avail_da.md`](../) (project memory, historical) — superseded Avail integration proposal

## 10. Copyright

This SIP is released into the public domain (CC0).
