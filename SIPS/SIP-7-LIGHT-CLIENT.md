```
SIP: 7
Title: Light Client SPV Protocol
Author: Marcelo Delgado <sophis-network@proton.me>
Status: Draft
Type: Standards
Created: 2026-05-10
Requires: 0
```

# SIP-7: Light Client SPV Protocol

> **Status note:** this document is the *stub* that accompanies the J5
> reference implementation merged in commit `<TBD>` (single commit,
> ~2 800 LOC + ~33 tests). The full SIP body is intentionally deferred
> until at least 30 days of testnet usage with non-trivial light-client
> workloads, so the Rationale and Security Considerations sections can
> cite real measurements rather than projections. Same two-phase pattern
> as SIP-3, SIP-4.

## 1. Abstract

Sophis full nodes already serve cheap header-chain syncs (`getHeaders`)
and per-block compact filters (`getBlockFilter` / `getBlockFilterHeader`,
SIP-6). What was missing for a complete SPV protocol was (a) a
per-transaction Merkle proof primitive and (b) a library that wires
header sync + filter sync + Merkle verification into one coherent flow.

SIP-7 adds both:

* **Merkle proof RPC** (`getTxMerkleProof`): returns a sibling path
  proving "tx X is at position P within block B's transaction list",
  verifiable against the block header's `hash_merkle_root` (Blake2b-384).
* **Reference library** (`sophis-spv`): header chain validator,
  K2 filter chain verifier with divergence detection, wallet-scan
  helper, and Merkle-proof verification re-exported from `sophis-merkle`.

J5 introduces no new cryptographic primitive. Hash family is Blake2b
(existing `sophis-merkle`) for the Merkle tree and SHA3-384 for the K2
filters (re-used from SIP-6). PQC posture preserved.

## 2. Motivation

See `docs/J5_LIGHT_CLIENT_DESIGN.md` §1 for the canonical motivation:
mobile wallets cannot run on Sophis without an SPV protocol; hardware
wallets and watch-only setups depend on per-tx Merkle proofs;
embedded / IoT integrations need cryptographically-verifiable
proofs without full validation cost.

J5 is item #9 in the sequential roadmap and pairs with K2 (SIP-6).

## 3. Specification

The technically complete specification is published at
`docs/J5_LIGHT_CLIENT_DESIGN.md` in the reference implementation tree.
It enumerates:

- 7 ratified design decisions (D1–D7, §2)
- The full SPV protocol flow (§3): cold sync, incremental sync, reorg
  recovery, single-tx verification
- Wire format for `TxMerkleProof` and `SyncCheckpoint` (§4)
- Threat model with 8 in-scope items (§5)
- Comparison vs Bitcoin BIP-37/158, Electrum, Ethereum LES (§6)
- Frozen ABI surface (§8)

This SIP body will be re-issued in **Review** once testnet measurements
are available; readers should treat the DESIGN doc as authoritative
until that re-issue.

## 4. Frozen ABI surface

The following are **frozen** as of the J5 implementation merge.

### 4.1 RPC

| Item | Value |
|------|-------|
| `RpcApiOps::GetTxMerkleProof` | `161` |
| Method name (gRPC) | `GetTxMerkleProof` |
| Method name (wRPC JSON) | `getTxMerkleProof` |
| gRPC oneof slots | request `1134`, response `1135` |

### 4.2 Wire format

```text
TxMerkleProof {
    tx_id:         Hash,            // 32 bytes
    block_hash:    Hash,            // 32 bytes
    leaf_sibling:  Hash,            // 32 bytes (ZERO_HASH if odd-out leaf)
    node_siblings: Vec<MerkleHash>, // each 48 bytes, leaf-direction first
    position:      u32,             // tx index within block.transactions
}

SyncCheckpoint {
    block_hash:    Hash,        // 32 bytes
    blue_score:    u64,
    daa_score:     u64,
    filter_header: [u8; 32],    // K2 filter_header at this block
}
```

### 4.3 Verification algorithm (frozen)

```text
fn verify_merkle_proof(proof: &TxMerkleProof, expected_root: &MerkleHash) -> bool {
    let pos = proof.position as usize;
    let mut acc: MerkleHash = if pos & 1 == 0 {
        merkle_hash_from_tx(proof.tx_id, proof.leaf_sibling)
    } else {
        merkle_hash_from_tx(proof.leaf_sibling, proof.tx_id)
    };
    let mut idx = pos >> 1;
    for sibling in &proof.node_siblings {
        acc = if idx & 1 == 0 {
            merkle_hash_from_node(acc, *sibling)
        } else {
            merkle_hash_from_node(*sibling, acc)
        };
        idx >>= 1;
    }
    acc == *expected_root
}
```

Where `merkle_hash_from_tx` and `merkle_hash_from_node` are the
existing `sophis_merkle` helpers (Blake2b-384 keyed via the
`MerkleBranchHash` type).

### 4.4 Crate names

| Item | Value |
|------|-------|
| Reference library crate | `sophis-spv` (path: `wallet/spv`) |
| RPC types module | `sophis-rpc-core::model::merkle_proof` |
| Re-exports | `sophis_spv::{verify_merkle_proof, build_merkle_proof, TxMerkleProof}` (re-exported from `sophis-merkle`) |

## 5. Rationale

Deferred to the full SIP body. The DESIGN doc §2 already enumerates the
seven ratified decisions (D1–D7) and their rationales; what changes in
the full SIP is the addition of empirical numbers from testnet light-
client deployments (sync time per fresh wallet, false-positive rate
observed under real transaction traffic, average filter size by
domain).

The most likely points of testnet-driven revision are:

- D2 — adding an alternative proof against `accepted_id_merkle_root`
  for clients that need "did this tx land on the canonical chain?"
  semantics in one call rather than combining D2 + L3 commitment
  level.
- D7 — promoting `getTxMerkleProofs(tx_ids)` batch fetch if mobile
  wallet sync patterns suggest it would meaningfully reduce round-
  trips.
- Adding a `getMerkleProofForRange` for descriptor-style wallets
  scanning over many addresses.

## 6. Backwards Compatibility

**Activated at genesis.** Sophis has not launched mainnet, so there is
no soft-fork window. Full nodes that don't implement the
`getTxMerkleProof` RPC are not shipped — the reference implementation
includes the method on every full node. Light clients written against
SIP-7 work against any full node from the J5 commit forward.

There is no consensus impact. All J5 work happens at the read-RPC
layer + a wallet library; no Sophis full node validates a Merkle proof
as part of consensus rules.

## 7. Reference Implementation

Reference implementation: `sophis-network/Sophis` commit `<TBD>`
(single commit shipping all J5 sub-fases):

| Sub-fase | Scope |
|---------|-------|
| J5.0 | Design document (`docs/J5_LIGHT_CLIENT_DESIGN.md`, ~310 lines) |
| J5.1 | `sophis-merkle` extended with `TxMerkleProof` + `build_merkle_proof` + `verify_merkle_proof`; `ConsensusApi::get_tx_merkle_proof` default + Consensus impl + session wrapper. 10 unit tests in `sophis-merkle`. |
| J5.2 | `rpc-core::model::merkle_proof` types + `RpcApiOps::GetTxMerkleProof = 161` + `RpcApi::get_tx_merkle_proof` trait + service impl + 2 mock stubs + gRPC binding (proto + ops + conversions + route + factory) + wRPC binding + integration test. 4 unit tests. |
| J5.3 | `wallet/spv` new crate (`sophis-spv`) — `SyncCheckpoint`, `MinHeader` + `validate_header_link`, `FilterChain` with divergence detection, `WalletScan` SPK matcher. 18 unit + 1 doctest. |
| J5.4 | This SIP stub + `SIPS/README.md` index update + workspace check + clippy strict + single commit. |

## 8. Security Considerations

Comprehensive threat model in DESIGN §5. Highlights:

- **Forged chain:** light client trusts only PoW work + Merkle proofs.
  Forging requires re-doing RandomX work back to the divergence point;
  cost ≥ block reward × divergence depth.
- **Hidden-tx filter:** filter is committed by `filter_header`, which
  is committed by the filter-header chain. To hide a tx the adversary
  would have to forge a different filter under a header chain that the
  light client also accepts — impossible without re-doing PoW work.
- **Wrong-block proof:** verifier checks against the
  `hash_merkle_root` of the header it trusts (cached from header
  sync). If `block_hash` does not match a known header, the proof is
  rejected before verification.
- **Wrong-tx proof:** Merkle path doesn't reproduce the expected root.
  Hard fail.
- **Wrong-position proof:** position bits drive the sibling-orientation
  during recomputation; tampering with `position` produces a different
  root. Hard fail.
- **Eclipse:** standard one-honest-peer assumption; light client
  rotates across multiple full nodes for defence in depth.
- **PQC posture:** preserved — Blake2b-384 (Merkle), SHA3-384 (K2),
  RandomX (PoW), no new primitives.
- **Reorg races:** filter chain divergence detection (per FilterChain
  module) forces rollback to deepest `Confirmed` checkpoint.

## 9. Test Vectors

Canonical vectors live with the reference implementation in:

- `crypto/merkle/src/lib.rs` (`tests` module) — Merkle proof
  round-trip across 1, 2, 4, 5, 7-tx blocks (covers leaf-level and
  internal-level padding); rejection of wrong root / wrong tx_id /
  wrong position.
- `rpc/core/src/model/merkle_proof.rs` (`tests` module) —
  workflow_serializer round-trip for `RpcTxMerkleProof` /
  `GetTxMerkleProofRequest` / `GetTxMerkleProofResponse`, including
  empty-node-siblings case (single-tx block).
- `wallet/spv/src/header_chain.rs` (`tests` module) — header-link
  validation: parent linkage / blue_score / DAA score; equal DAA
  score accepted.
- `wallet/spv/src/filter_chain.rs` (`tests` module) — happy-path
  multi-block walk; divergence rejection; tampered-header
  recomputation rejection; frontier non-advancement on error.
- `wallet/spv/src/scan.rs` (`tests` module) — SPK match,
  empty-set, empty-filter, malformed-filter resilience,
  first-match ordering.

The wire format is frozen as of the J5 implementation commit.

## 10. References

- BIP-37 (Bitcoin) — original SPV bloom filters; deprecated due to
  privacy issues
- BIP-157/158 (Bitcoin) — modern compact filter SPV; conceptual
  ancestor for Sophis K2 + J5
- Ethereum LES (Light Ethereum Subprotocol) — alternative SPV design
  via P2P sub-protocol; Sophis chose RPC-based SPV instead
- `docs/J5_LIGHT_CLIENT_DESIGN.md` — authoritative wire-format spec
- `docs/K2_COMPACT_FILTERS_DESIGN.md` — sibling design doc (K2
  compact filters); J5 consumes K2 directly. A future SIP-6 will
  formalise the K2 wire format; until then the DESIGN doc is
  authoritative.
- `SIPS/SIP-3-ALT.md` — same "stub + design doc + later full body"
  pattern

## 11. Copyright

This SIP is released into the public domain (CC0).
