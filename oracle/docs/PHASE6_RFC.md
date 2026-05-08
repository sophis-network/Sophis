# RFC — Sophis Phase 6: native L1 Data Availability layer

**Status:** v1, public RFC published at sub-fase 6.9 (2026-05-06).
**Branch:** `phase6-DALayer` (10 commits, `54a1d99..cf16b27`).
**Comment window:** 30 days from publication date.

This RFC consolidates the Phase 6 Data Availability layer for public
review. It is the entry point for external reviewers, integrators, and
bug-bounty participants. The technical content is split across nine
companion documents — this RFC indexes them and summarizes the design
decisions worth flagging upfront.

---

## 1. What Phase 6 is

Phase 6 adds a **native L1 data-availability primitive** to Sophis: a
new transaction output type (V5 carrier, `script_public_key.version = 5`)
that lets producers publish arbitrary bytes to the Sophis DAG with
three guarantees:

1. **Inclusion** — once the consensus accepts the containing tx, every
   full node has the bytes.
2. **Addressability** — every blob has a deterministic 48-byte
   SHA3-384 `payload_id`. Anyone with the id queries any full node
   and gets the bytes.
3. **Verifiability inside the sVM** — a smart contract can call
   `Capability::VerifyDataAvailability` and learn, deterministically
   and at consensus time, whether a `payload_id` is present in the DAG
   with at least N confirmations.

Phase 6 ships at **mainnet genesis** alongside Phase 1 (DAG + RandomX
+ Dilithium), Phase 2 (sVM + native tokens), Phase 3 (ZK-Rollup), and
Phase 5 (ZK-Oracle). There is no activation gate; the zero-gates
strategy was decided in `project_phase6_schedule_activation.md`.

## 2. Why Self-DA, not Avail / Celestia

The original Phase 6 proposal called for an Avail integration. The
current proposal is **self-DA on the Sophis L1**. Reasons (full
discussion in `PHASE6_DA_DESIGN.md` §2):

| Vector | External DA | Self-DA |
|---|---|---|
| **PQC posture** | Avail BLS12-381, Celestia Ed25519 — both pre-quantum. CRQC adversary forges DA committee attestations. | Inherits Sophis L1's PQC posture (Dilithium ML-DSA-44 + RandomX + SHA3-384). |
| **Operational dependency** | Sophis L2 dies if Avail dies. | Sophis L2 inherits Sophis L1 liveness. |
| **Regulatory surface** | Bridge to non-PQC DA reintroduces the cross-chain dependency the 2026-05-04 pivot eliminated. | No third-party legal entity in the trust path. |
| **Zero-gates fit** | Activation gate required (Avail testnet, bridge deployment). | Ships at genesis. |
| **Cost** | $100-300k integration + ongoing AVAIL fees. | Marginal; storage cost amortized into the existing block mass model. |

The Avail proposal solved a problem (multi-rollup DA throughput at
hundreds of MB/s) Sophis does not have at launch and will not have for
years. Self-DA solves the actual Phase 3 + Phase 5 problem with zero
external dependency.

## 3. Wire format (frozen)

V5 carrier output:

```text
ScriptPublicKey {
    version: u16 = 5,                   // SCRIPT_VERSION_CARRIER
    script:  Vec<u8>,                   // see below
}
```

Script body (64-byte fixed header + variable data):

```text
0..8    magic = b"SPHS-DA1"
8..9    flags: u8        (FRAGMENTED | LAST | DOMAIN_*)
9..10   reserved = 0
10..11  fragment_count    1..=32
11..12  fragment_index    0..fragment_count
12..16  data_len          0..=65_536  (LE u32)
16..64  bundle_id         SHA3-384(reassembled body)
64..N   data
```

Constants:

| Name | Value |
|---|---|
| `SCRIPT_VERSION_CARRIER` | 5 |
| `MAX_SCRIPT_PUBLIC_KEY_VERSION` | 5 |
| `CARRIER_MAGIC` | `b"SPHS-DA1"` |
| `MAX_FRAGMENTS` | 32 |
| `MAX_DATA_PER_CARRIER` | 65_536 (64 KiB) |
| `MAX_BUNDLE_BYTES` | 2 MiB |
| `MAX_CARRIER_OUTPUTS_PER_TX` | 8 |
| `CARRIER_OUTPUT_VALUE` | 0 sompi (mandatory) |
| `DEFAULT_DA_CONFIRMATIONS` | 1000 (blue-score gap) |
| `GAS_DA_VERIFY` | 2_000 |

V5 outputs are **unspendable** (`value = 0` mandatory; no transaction
may use a V5 output as input). They never appear in the active UTXO
set; they live in a separate DA store keyed by `payload_id` and
`bundle_id`.

A complete `BatchJournal` (Phase 3) carries a new
`da_bundle_id: [u8; 48]` field equal to `SHA3-384(borsh(batch))`, so
any verifier can bind the journal to its source bytes via
`sophis_verify_da`.

## 4. SPK version registry

`consensus/core/src/constants.rs` documents the allocated versions:

| Version | Name | Owner |
|---|---|---|
| 0 | standard P2PKH-Dilithium / P2SH-Dilithium | core |
| 1 | `SCRIPT_VERSION_CONTRACT` (sVM dispatch) | Phase 2 |
| 2 | `SCRIPT_VERSION_TOKEN` (native token UTXO) | Phase 2 |
| 3 | `BRIDGE_VAULT_VERSION` (rollup deposit) | Phase 3 |
| 4 | `BRIDGE_CLAIM_VERSION` (rollup withdrawal claim) | Phase 3 |
| 5 | `SCRIPT_VERSION_CARRIER` (DA carrier) | Phase 6 |

`MAX_SCRIPT_PUBLIC_KEY_VERSION = 5` is the current ceiling. Any
expansion is a hard fork.

## 5. Integration surface

### 5.1 Phase 3 rollup sequencer

The sequencer auto-publishes a third tx per batch:

1. `Prep` tx — commits `BatchJournal { ..., da_bundle_id }`
2. `T_carrier` tx — V5 carriers (`flags = DOMAIN_ROLLUP`) with
   `borsh(batch)` chunked at 64 KiB
3. `StateUpdate` tx — absorbs the Submission UTXO

The Risc0 guest computes `da_bundle_id` inside the zkVM, so the proof
+ the journal agree on what calldata is on-chain.

### 5.2 Phase 5 oracle relayer

Opt-in via `[submit] da_publish = true` in `relayer.toml`. After each
successful invocation submission, the relayer publishes a V5 carrier
(`flags = DOMAIN_ORACLE`) with the signed wire bytes. Carrier publish
failure is a `WARN` (the journal is already on L1; the carrier is
purely archival).

### 5.3 sVM contracts

Contracts that declare `Capability::VerifyDataAvailability` in their
`ContractManifest` can call:

```text
sophis_verify_da(
    ptr_payload_id    : *const u8 (48 bytes),
    _padding          : i32 (= 0),
    min_confirmations : i64,
    query_kind        : i32 (0 = payload_id, 1 = bundle_id),
) -> i32

return:  1 = present + confirmed
         0 = absent / under-confirmed
        -1 = query_kind invalid OR min_conf < 0
        -2 = capability not granted
        -3 = gas exhausted
        -4 = memory OOB OR padding != 0
```

Gas cost: `GAS_DA_VERIFY = 2_000` (RocksDB lookup is O(1)).

### 5.4 RPC

Five new methods on `RpcApi`:

- `get_da_payload(payload_id)`
- `get_da_bundle(bundle_id)` — server-side reassembly
- `get_da_carriers_by_block(block_hash)`
- `get_da_carriers_by_domain(domain_byte, blue_score)`
- `get_da_payload_status(payload_id)`

> **v1 caveat:** gRPC + wRPC client bindings stub these as
> `NotImplemented`. In-process Rust callers via `RpcCoreService` work
> today. Sub-fases 6.4.b/c add the binary-protocol bindings.

## 6. Security review

The full DIY audit playbook is in `PHASE6_AUDIT.md`. Summary:

- 14 consensus rules (§5 of `PHASE6_DA_DESIGN.md`) — each mapped to
  unit tests
- 13 threats (§9) — mapped to defenses + cargo test filters in
  `devnet/test_phase6_da_attacks.py`
- 6 property/fuzz tests in `consensus/core/src/da/{mod,codec}.rs`
  (5000-iteration random inputs; never-panic + roundtrip + collision-
  resistance invariants)
- 9 acceptance gates for the 72h stress run (`PHASE6_STRESS_PLAN.md`)
- 30-day public bug bounty (`PHASE6_BUG_BOUNTY.md`)

83 tests verde at sub-fase 6.9 close (77 from 6.1-6.8 + 6 fuzz tests).

## 7. Known limitations (v1)

These are **explicit ship trade-offs**, not bugs. Reviewers should
not flag them as omissions:

- gRPC + wRPC binary-protocol bindings stubbed (sub-fase 6.4.b/c)
- `current_blue_score = 0` in `build_da_backend` (sub-fase 6.5.b)
- No CLI wallet helper for carrier publish (post-mainnet polish)
- No fuzz harness binary (cargo-fuzz / libFuzzer is Linux-only;
  property tests in `cargo test` cover the surface)
- Multi-tx splitting for >512 KiB calldata (Phase 3 batches don't
  reach this; reject-with-error today)
- `GrpcSubmit::publish_carrier` defaults to no-op (real impl deferred)
- 72h stress run not yet executed (plan + helper shipped; depends
  on 6.4.b/6.5.b/6.8.b)

Each is tracked in `PHASE6_AUDIT.md §4` with reasoning.

## 8. Out of scope (not v1)

- DAS / erasure coding for light clients (`PHASE6_DA_DESIGN.md §14.1`)
- Encrypted carriers (`§14.2` — apps encrypt off-chain if needed)
- `Capability::ReadDataAvailability` (`§14.3`)
- Multi-bundle aggregation merkle indexing (`§14.4`)
- External DA layers (Avail, Celestia, EigenDA — superseded by §2 of
  this RFC)
- Cross-chain bridges of carrier data (`PHASE6_DA_DESIGN.md §1.2`)

## 9. Companion documents

| Doc | Purpose | Lines |
|---|---|---|
| `oracle/docs/PHASE6_DA_DESIGN.md` | Design freeze: 14 rules, 13 threats, ABI freeze, roadmap | ~750 |
| `oracle/docs/PHASE6_RUNBOOK.md` | Operator manual (full nodes, sequencer, relayer, indexers) | ~360 |
| `oracle/docs/PHASE6_STRESS_PLAN.md` | 72h pre-mainnet stress + 9 acceptance gates | ~250 |
| `oracle/docs/PHASE6_AUDIT.md` | DIY audit playbook + findings ledger | ~200 |
| `oracle/docs/PHASE6_BUG_BOUNTY.md` | 30-day pre-mainnet bug bounty announcement | ~180 |
| `oracle/docs/PHASE6_RFC.md` | This document | (you are here) |
| `devnet/test_phase6_da_attacks.py` | Adversarial threat × defense matrix runner | ~350 |
| `devnet/da_stress_check.py` | Stress observability helper | ~370 |

## 10. Comment window

Public comments accepted until 30 days post-publication. Channels:

- GitHub PR comments on `phase6-DALayer` branch
- Email to the founder (Dilithium-signed preferred for security
  findings)
- Bug-bounty channel for security-relevant items
  (`PHASE6_BUG_BOUNTY.md §6`)

After the window closes, the team (1) addresses all comments in a
public response addendum appended to `PHASE6_AUDIT.md §5.2`,
(2) commits any agreed-upon changes to `phase6-DALayer`, and (3)
merges to `main` for mainnet ship.

## 11. Authors / contact

This RFC is published under the no-entity / fair-launch posture
documented in `project_no_entity_decision.md`. There is no foundation
to "represent" Sophis. Contact channels are personal:

- GitHub: `sophis-network/Sophis`
- Email: see `PHASE6_BUG_BOUNTY.md §6`

Reviewers do not need to identify themselves to participate; the
acknowledgment field in `PHASE6_AUDIT.md §5.2` accepts pseudonyms.
