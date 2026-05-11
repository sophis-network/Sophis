# J5 — Light Client SPV Protocol

> **Status:** design frozen for sub-fase J5.0 — ready for J5.1 implementation.
> **Originating roadmap:** Roadmap J (Ethereum lessons), item J5.
> **Companion docs:** future `docs/J5_RUNBOOK.md` (deferred follow-up).
> **Pre-existing baseline:** Sophis already ships `getHeaders` (header
>   sync) and now K2 compact filters (committed `535667a`). The missing
>   pieces for a complete SPV protocol are: (a) a Merkle-proof primitive
>   so a client can verify a single transaction belongs to a block
>   without downloading the block body, and (b) a library that wires
>   header sync + filter sync + Merkle verification into a coherent
>   protocol. J5 fills both.

## 1. Motivation

A "light client" — also called a Simplified Payment Verification (SPV)
client — is a wallet that does NOT download or validate full block
bodies. Instead it:

1. Syncs only the header chain (cheap: a few KB per block).
2. Verifies headers via the PoW work they commit to.
3. For wallet sync, asks a full node "did any address I care about
   appear in block N?" — but via filters (K2) instead of disclosing
   the addresses.
4. When a filter matches, fetches the relevant transaction + a Merkle
   proof linking it to the header it already trusts.

Without a complete SPV protocol:

- **Mobile wallets cannot run on Sophis.** Phone bandwidth + storage
  budget rules out full-node syncs (~hundreds of GB at saturated
  10 BPS over years).
- **Hardware wallets and watch-only setups** have to either trust the
  full node ("show me transactions for this address") or download
  every block looking for matches — privacy-broken on one side,
  bandwidth-broken on the other.
- **Embedded / IoT integrations** (point-of-sale, smart contracts
  reacting to off-chain state) need cryptographically-verifiable
  per-transaction proofs without the full validation cost.

J5 ships the **library** components a wallet implementer needs:

- Header chain validator: verifies PoW + parent linkage starting from
  a trusted checkpoint.
- Filter chain validator: walks the K2 filter header chain forward
  from a trusted starting point, verifying each entry against the
  previous.
- Scan helper: given an SPK set, walks fetched filters, identifies
  blocks with potential matches, returns the (block_hash, candidate
  reasons) pairs the wallet should investigate further.
- Merkle-proof verifier: given a transaction, the block it claims to
  belong to, and a `getTxMerkleProof` response, returns true/false.

The protocol-side piece — `getTxMerkleProof` RPC — is added in J5.1.

The wallet UX layer (key management, UI, derivation paths) is
**out of scope**: J5 ships building blocks, not a wallet. A concrete
wallet binary using the J5 library is a separate follow-up
(`tools/sophis-spv-client` or third-party).

This is item #9 in the sequential roadmap. Originally estimated 2-4
weeks; condensed to a single bundle here following recent rhythm,
scoped to library + Merkle RPC (no binary).

## 2. Ratified design decisions

| ID | Question | Choice | Rationale |
|----|----------|--------|-----------|
| **D1** | Protocol shape | header sync → filter header chain verify → filter fetch on demand → tx fetch on filter match | Standard BIP-157/158 SPV flow. Caller fetches the cheap header chain first, walks the K2 filter header chain to verify what they're about to fetch, fetches only filters they need (typically the recent ones since their last sync), runs the SPK match on each, fetches full transactions ONLY for blocks where a filter signaled a possible match. False-positive rate `1/M = 1.9 × 10⁻⁶` per query means ~1 spurious fetch per 530 000 SPK-queries. |
| **D2** | Merkle proof tree | Proof against `hash_merkle_root` (block-level Merkle of transaction hashes), NOT `accepted_id_merkle_root` | `hash_merkle_root` proves "this transaction is in this block". `accepted_id_merkle_root` is the GHOSTDAG mergeset acceptance set, which is a deeper consensus concern — clients verifying "did my tx land on the canonical chain?" combine the block-Merkle proof with L3 commitment-level data (block must be at `Confirmed`/`Finalized`). Two-level model is clearer than one combined proof. |
| **D3** | Wallet address tracking | Caller supplies a `Vec<ScriptPublicKey>` (the SPKs they care about); J5 returns blocks with potential matches | Address derivation (HD wallets, multi-account, etc.) lives at the wallet layer above J5. The library only sees opaque SPK bytes. This keeps J5 testable in isolation. |
| **D4** | Reorg handling | Filter header chain divergence detection: if a node serves a filter header that doesn't link to the previously-cached `filter_header`, the client treats everything from that block forward as "potentially reorganised" and re-walks. | Robust because the filter header chain is committed by every full node from local chain state — divergence implies the client either talked to a forked-but-honest node or got a malicious response. Light clients SHOULD cache the (block_hash, filter_header) pair at each `Confirmed` checkpoint and only roll back to that depth on divergence. |
| **D5** | Trust model | One honest full node assumption | Standard BIP-157 model. The full node provides headers + filters + transactions + Merkle proofs; the light client verifies everything cryptographically against the chain of PoW work it already trusts. An adversarial node can withhold information (DoS) or feed information from a parallel chain (eclipse), but cannot forge data the light client accepts — every accepted answer is verifiable. |
| **D6** | Checkpoint format | `SyncCheckpoint { block_hash, blue_score, daa_score, filter_header }` — the wallet caches this after every successful sync | The four fields are the minimum to bootstrap from cold. Wallets initialising from a fresh install get a "ship-with" checkpoint baked into the binary (released signed by founder); ongoing wallets cache their own as they sync forward. |
| **D7** | P2P propagation | **Out of scope.** Light clients fetch from a full node via RPC; light-client-to-light-client propagation (BIP-157 messages) is deferred to a future SIP. | Same rationale as K2.7: the v1 deployment model is "wallet connects to a trusted full node via gRPC/wRPC". P2P light-client mesh can be added later without breaking either the wire format or the library API. |

## 3. The protocol

### 3.1 Cold sync from genesis (or trusted checkpoint)

```text
1. Wallet has: checkpoint = SyncCheckpoint { block_hash, blue_score, daa_score, filter_header }
   (Either ship-with-binary or cached from a prior session.)

2. Header sync:
   start = checkpoint.block_hash
   loop:
     headers = rpc.get_headers(start, LIMIT, is_ascending=true)
     for h in headers:
       validate_header_chain(h)?     // PoW + parent linkage
       cache(h)
     if headers.len() < LIMIT: break
     start = last_header_hash(headers)

3. Filter header chain verify (parallel/post-pass):
   prev_filter_header = checkpoint.filter_header
   for h in cached_headers in chain order:
     fh_entry = rpc.get_block_filter_header(h.hash)?
     assert fh_entry.prev_header == prev_filter_header  // divergence check (D4)
     prev_filter_header = fh_entry.filter_header
     cache(h.hash → fh_entry.filter_hash)               // for later filter validation

4. Wallet scan:
   relevant_blocks = []
   for h in cached_headers in chain order:
     filter = rpc.get_block_filter(h.hash)?
     assert filter_hash(filter.filter_bytes) == cached_filter_hash(h.hash)
     for spk in wallet.spk_set():
       if filter_matches(filter.filter_bytes, h.hash, spk):
         relevant_blocks.push((h.hash, spk))
         break  // one match is enough; full tx fetch covers everything

5. Per-relevant-block resolution:
   for (block_hash, _spk_hint) in relevant_blocks:
     block = rpc.get_block(block_hash, include_transactions=true)?
     for tx in block.transactions:
       if tx.touches_any_of(wallet.spk_set()):
         wallet.add_pending_tx(tx, block_hash)
         // Optional Merkle proof verify for paranoid clients:
         proof = rpc.get_tx_merkle_proof(tx.id(), block_hash)?
         assert verify_merkle_proof(&tx.id(), &proof, &block.header.hash_merkle_root)

6. Save checkpoint:
   checkpoint = SyncCheckpoint {
     block_hash:      latest_synced_hash,
     blue_score:      latest_blue_score,
     daa_score:       latest_daa_score,
     filter_header:   prev_filter_header,
   }
```

### 3.2 Incremental sync

Identical to §3.1 but starting from the wallet's last cached checkpoint
rather than genesis. Steps 2-5 walk forward from `checkpoint.block_hash`
to the current sink.

### 3.3 Reorg recovery

If step 3 detects `fh_entry.prev_header != prev_filter_header`, the
node we are talking to either (a) saw a real reorg or (b) is feeding
us a divergent chain. The wallet:

1. Rolls back local state to the deepest `Confirmed` checkpoint
   (`commitment_level == Confirmed` per L3).
2. Re-runs steps 2-5 from that checkpoint.
3. If divergence repeats, the wallet SHOULD switch to a different full
   node (eclipse-defence).

### 3.4 Single-tx verification (no wallet, no sync)

A dApp that just wants "did this specific transaction land on the
chain?" can skip steps 2-5 and call:

```text
proof = rpc.get_tx_merkle_proof(tx_id, block_hash)?
commitment = rpc.get_block_commitment(block_hash)?     // L3
header = rpc.get_headers(block_hash, 1, true)?[0]      // existing
assert verify_merkle_proof(&tx_id, &proof, &header.hash_merkle_root)
assert commitment.commitment >= CommitmentLevel::Confirmed
```

This is the "lightest possible" SPV — three RPC calls, no caching, no
header chain walk. Trust model: the full node could lie about
`commitment`, but the Merkle proof + header signature is verifiable
against the PoW work in `header`.

## 4. Wire format

### 4.1 Merkle proof

```text
TxMerkleProof {
    tx_id:       Hash,         // echoed
    block_hash:  Hash,          // echoed
    siblings:    Vec<Hash>,     // siblings along the path, root-to-leaf
    position:    u32,           // index of tx_id within block.transactions
}
```

Verification (caller-side):

```text
fn verify_merkle_proof(tx_id: &Hash, proof: &TxMerkleProof, expected_root: &Hash) -> bool {
    let mut acc = *tx_id;
    let mut idx = proof.position;
    for sibling in &proof.siblings {
        acc = if idx & 1 == 0 {
            merkle_hash_pair(&acc, sibling)
        } else {
            merkle_hash_pair(sibling, &acc)
        };
        idx >>= 1;
    }
    acc == *expected_root
}
```

`merkle_hash_pair` is the same hash function used to build
`hash_merkle_root` — Sophis uses MerkleHash (Blake2b-256 in the
existing `sophis-merkle` crate). The protocol exposes the same
function via `sophis-spv::verify_merkle_proof`.

### 4.2 Sync checkpoint

```text
SyncCheckpoint {
    block_hash:    Hash,
    blue_score:    u64,
    daa_score:     u64,
    filter_header: [u8; 32],
}
```

Wallets serialise this however suits their storage; the library
provides borsh + serde impls for convenience.

## 5. Threat model

| ID | Threat | Mitigation |
|----|--------|------------|
| T1 | Adversary full node serves a forged chain | Light client trusts only PoW work (verified per header) and Merkle proofs (verified against `hash_merkle_root`). A forged chain requires re-doing RandomX work back to the divergence point; cost ≥ block reward × divergence depth, prohibitive after `Confirmed` (~10 s) and astronomical after `Finalized` (~12 h). |
| T2 | Adversary feeds filter that hides a tx the wallet should see | Filter is committed by `filter_header`, which is committed by the filter-header chain. To hide a tx the adversary would have to forge a different filter under a header chain that the light client also accepts — impossible without re-doing the PoW work for the entire chain from divergence point. |
| T3 | Privacy leak via per-query analysis: full node sees which `block_hash` the wallet queries | Inherent to any SPV protocol that fetches per-block data. Mitigated by querying every block in the wallet's sync range (not just suspected matches) and by rotating across multiple full nodes. The false-positive cushion of K2 filters means the node cannot tell which match was a true positive. |
| T4 | Adversary feeds Merkle proof for a tx that's NOT in the block | Verifier recomputes `merkle_hash_pair` chain; mismatched proof yields a root that doesn't equal `expected_root`. Hard fail. |
| T5 | Adversary feeds Merkle proof for the WRONG block | Light client verifies against the `hash_merkle_root` of the header it trusts (cached from step 2). If `block_hash` does not match a known header, the proof is rejected before verification. |
| T6 | Eclipse: light client only talks to a malicious node | Standard eclipse defence — wallet rotates across multiple known-good full nodes. Light client provides hooks (multiple RPC endpoints, periodic re-verification) but cannot eliminate eclipse at the protocol layer. |
| T7 | PQC posture loss | J5 uses Blake2b (existing `sophis-merkle`), SHA3-384 (K2 filters), RandomX (PoW). No new primitives. PQC posture preserved. |
| T8 | Reorg races | Per D4: filter header chain divergence detection forces a rollback to the deepest `Confirmed` checkpoint. Light clients SHOULD NOT show "received" status for transactions in blocks at `Accepted` only — use `Confirmed` as the wallet UX threshold. |

## 6. Comparison vs alternatives

| System | Header sync | Filter privacy | Per-tx proof | Trust model |
|--------|-------------|----------------|---------------|--------------|
| Bitcoin BIP-37 | full headers | broken (server learns set) | yes (Merkle) | one honest peer |
| Bitcoin BIP-157/158 | full headers | strong (K2-shaped) | yes (Merkle, BIP-37-shape) | one honest peer |
| Electrum protocol | full headers | leaks to server (address-based queries) | yes | one honest server |
| Ethereum LES (light Ethereum subprotocol) | header chain via P2P | n/a (no compact filters) | trie proofs | one honest peer |
| **Sophis J5** | full headers (`getHeaders`) | strong (K2 SHA3-384) | yes (`getTxMerkleProof`) | one honest full node |

Sophis J5 is the BIP-158 model adapted to Sophis primitives:
SHA3-384 in the filter hash, Blake2b in the Merkle tree, RandomX in
the header chain. Trust model matches Bitcoin's: one honest full node
is enough; eclipse defences are at the P2P layer above.

## 7. Out-of-scope (for J5)

- **Reference wallet binary** (`tools/sophis-spv-client`) — library
  ships in `wallet/spv`; binary is a separate follow-up.
- **P2P propagation** (`cfheaders`/`cfilter`/`cfcheckpt` messages or
  Sophis equivalents) — RPC fetch from a trusted full node in v1.
- **Multi-node verification** (querying N nodes, checking consensus
  before accepting) — library exposes hooks for the wallet to
  implement this policy; J5 does not bake the policy in.
- **Watch-only descriptor sync** — `getTxMerkleProof` is per-tx-per-
  block, not range-of-blocks. Descriptor wallets can layer their own
  scan on top of K2 + `getBlock` calls; J5 ships the primitive
  building blocks.
- **HD-wallet key derivation** — wallet layer above J5; the library
  receives an opaque `Vec<ScriptPublicKey>`.

## 8. Frozen ABI surface

| Item | Value |
|------|-------|
| `RpcApiOps::GetTxMerkleProof` | `161` |
| gRPC oneof slots | request `1134`, response `1135` |
| Merkle hash function | Blake2b-256 (existing `sophis-merkle`) |
| Filter hash function | SHA3-384[..8] keyed via `b"sophis-cf-v1\0"` (K2) |
| Crate name | `sophis-spv` (path: `wallet/spv`) |
| Module name (RPC types) | `rpc-core::model::merkle_proof` |

## 9. Reference implementation map

| Sub-fase | Scope |
|---------|-------|
| J5.0 | This design document |
| J5.1 | `consensus-core::merkle_proof` types + `ConsensusApi::get_tx_merkle_proof` default + Consensus impl + session wrapper |
| J5.2 | `rpc-core::model::merkle_proof` types + `RpcApiOps::GetTxMerkleProof = 161` + RpcApi trait + service impl + 2 mock stubs + gRPC binding (proto + ops + conversions + route + factory) + wRPC binding (server router + client macro) + integration test |
| J5.3 | `wallet/spv` new crate — `HeaderChain` validator, `FilterChain` verifier, `WalletScan` helper, `SyncCheckpoint`, `verify_merkle_proof`. Tests against synthetic chains + cross-crate integration with `sophis-compact-filters`. |
| J5.4 | `SIPS/SIP-7-LIGHT-CLIENT.md` stub + `SIPS/README.md` index update + workspace check + clippy strict + single commit |

## 10. Glossary

| Term | Meaning |
|------|---------|
| SPV | Simplified Payment Verification — Bitcoin Whitepaper §8 nomenclature for a wallet that does NOT validate full block bodies, only headers + per-tx Merkle proofs. |
| Light client | Synonym for "SPV client". Some chains (Ethereum LES) use slightly different protocols but the role is the same. |
| Header chain | Sequence of block headers from a trusted starting point (genesis or a cached checkpoint) to the current tip. Verifiable via PoW work + parent linkage. Cheap to download (~150 bytes/header × 10 BPS × 86400 ≈ 130 MB/day, archival-friendly). |
| Filter chain | Sequence of K2 `filter_header` values, one per block, chained by `filter_header(B) = SHA3-384(filter_header(prev(B)) \|\| filter_hash(B))[..32]`. Light client verifies this chain forward from a trusted starting point; divergence triggers reorg recovery. |
| Merkle proof | Sibling path from a transaction's hash up to the block's `hash_merkle_root`. Allows a light client to prove "tx X is in block B" without downloading all of B's transactions. Size: `O(log2(n_txs))` hashes. |
| Sync checkpoint | `(block_hash, blue_score, daa_score, filter_header)` tuple cached by the wallet between sync sessions. Ship-with-binary checkpoints are signed by the founder and baked into wallet releases. |
| False-positive | A filter that matches an SPK the wallet does NOT actually have a transaction for. Rate per query: `1/M = 1/524288 ≈ 1.9 × 10⁻⁶` (K2). Cost per false positive: one extra `getBlock` RPC call. |
