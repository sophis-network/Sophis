# Sophis ZK-Oracle — sVM contract dispatch specification (sub-fase 5.5.d)

This document specifies the **on-chain sVM contract** that closes the
Phase 5 ZK-Oracle loop. It consumes the relayer's invocation tx and
writes the resulting `FeedSnapshot` to the per-feed state UTXO that
the SDK reads.

**Status:** specification only (sub-fase 5.5.d). The actual WASM
contract bytecode is out of scope for sub-fase 5.5 — this document
hands the implementer everything they need to write it.

---

## 1. Inputs and outputs

```text
Inputs:
  [0..N-1]  Previous per-feed state UTXOs (one per feed being updated)
            SPK version: FEED_STATE_VERSION (8)
            Script: borsh((FeedId, FeedSnapshot))
  [N]       The relayer's invocation UTXO from output[0] of the most
            recently submitted relayer tx
            SPK version: ORACLE_INVOKE_VERSION (7)
            Script: encode_wire(SignedBundle)  (see ABI.md §4)

Outputs:
  [0..M-1]  New per-feed state UTXOs (one per feed updated this tx)
            SPK version: FEED_STATE_VERSION (8)
            Script: borsh((FeedId, FeedSnapshot)) with updated snapshot
  [M]       Optional change UTXO back to the contract's address
            (residual sompi from the invocation UTXO + state UTXO inputs)
```

A typical update tx for one feed: 2 inputs (state + invocation), 1
output (new state). Multiple-feed updates batch by including more
state inputs and outputs in the same tx — the contract's WASM code
loops through them.

## 2. Required capabilities

The contract's `ContractManifest` MUST declare:

```rust
required_capabilities: vec![
    Capability::ReadUtxo,           // read state inputs
    Capability::ProduceOutput,      // write state outputs
    Capability::VerifyDilithium,    // bundle signature
    Capability::VerifyPlonky3Proof, // both AIRs
    Capability::HashSha3,           // re-derive bundle commitment
    Capability::ReadBlockHeight,    // freshness sanity check
],
```

Missing any of these → the host rejects the contract at deploy time
(see `svm/core/src/manifest.rs::has_capability`).

## 3. Validation pipeline

The contract MUST execute these checks **in order** on every invocation
tx. Any failure aborts the tx (no state change, fee paid by relayer).

### Step 1 — Parse the wire payload

```text
Decode invocation_input.script_public_key.script as the wire layout
defined in ABI.md §4. Reject on any LP overflow, trailing bytes,
or fixed-length mismatch (VK must be exactly 1312, sig 2420).
```

Reject reason: `MalformedWirePayload`.

### Step 2 — Re-derive the bundle commitment

```text
commit := SHA3-256(
    BUNDLE_DOMAIN_V1
 || borsh(journal)
 || u64_le(now_secs)
 || u32_le(oracle_proof.len()) || oracle_proof
 || u32_le(va_proof.len())     || va_proof          (empty if absent)
 || u32_le(va_pv.len())        || va_pv             (empty if absent)
)
```

Reject reason: implicit (must match Step 3's verify input).

### Step 3 — Verify the relayer's Dilithium signature

```rust
env.verify_dilithium(
    &decoded.verification_key,    // 1312 bytes
    &commit,                      // 32 bytes (from Step 2)
    &decoded.signature,           // 2420 bytes
)
```

Reject reason: `BadRelayerSignature`.

### Step 4 — Check relayer is allow-listed

The contract maintains an internal allow-list of acceptable relayer
VK hashes (e.g. SHA3-256 of the 1312-byte VK). The list is updated by
a separate governance flow (out of scope for v1; see §6).

```rust
let vk_hash = env.sha3_384(&decoded.verification_key)[..32];
if !state.relayer_allowlist.contains(&vk_hash) {
    abort();  // NotAllowedRelayer
}
```

Reject reason: `NotAllowedRelayer`.

### Step 5 — Verify the OracleAir STARK proof

```text
oracle_air_pv := borsh(journal) || u64_le(now_secs)

env.verify_plonky3_proof(
    &decoded.oracle_proof,
    &oracle_air_pv,
    &ORACLE_AIR_ID_V1,        // pinned constant; recompute via SHA3-384
)
```

Reject reason: `BadOracleProof`.

### Step 6 — Verify the VerifyAirChip companion (if present)

If `decoded.verify_air_proof` and `decoded.verify_air_pv` are both
non-empty:

```rust
// Post sub-fase 5.6.0: PV is 672 bytes (pk||sig||R||A||sB||hA limbs).
if !env.verify_plonky3_proof(
    &decoded.verify_air_proof,
    &decoded.verify_air_pv,
    &VERIFY_AIR_ID_V1,
) { abort(); }

// Decode PV slots for binding.
let (pk, sig, r_point, a_point, sb, ha) = decode_verify_air_pv(&decoded.verify_air_pv)?;

// Bind the publisher.
if pk != journal.publisher.0 { abort(); }   // PublisherBindingFailed
if sig != decoded.signature_in_journal_bytes { abort(); }  // SigBindingFailed
```

Reject reasons: `BadVerifyAirProof`, `PublisherBindingFailed`, `SigBindingFailed`.

### Step 6.a–d — Companion proof aggregation (sub-fases 5.6.a-d)

Ed25519 message-binding closes via four companion proofs the relayer
ships alongside `verify_air_proof`. Each binds an upstream computation
to the corresponding boundary slot of `verify_air_pv`. The contract
verifies all four and checks the chain consistency.

#### Step 6.a — decompress(R_bytes) → R_point

```rust
let pv_decompress_r = decompress_pv(sig[0..32], r_point, /*valid*/ true);
if !env.verify_plonky3_proof(&proof_decompress_r, &pv_decompress_r, &DECOMPRESS_AIR_ID_V1) {
    abort();  // BadDecompressRProof
}
// Binding implicit: PV[0..32] == sig[0..32], PV[32..68] == r_point.
// AIR (post 5.6.a.1) enforces equality with its boundary cells.
```

Same for `decompress(pk) → A_point` against `a_point` (Step 6.b).

#### Step 6.c — sha512(R || A || M) → digest

```rust
let mut hash_input = Vec::new();
hash_input.extend_from_slice(&sig[0..32]);    // R bytes
hash_input.extend_from_slice(&pk);            // A bytes
hash_input.extend_from_slice(&decoded.message);
let pv_sha = sha_pv(&hash_input, expected_digest);
if !env.verify_plonky3_proof(&proof_sha, &pv_sha, &SHA512_AIR_ID_V1) {
    abort();  // BadShaProof
}
```

> **Trust-shim caveat (5.6.c is stub):** the current SHA-512 plumbing
> ships as a sentinel-bytes wrapper that re-derives the digest via the
> witness function. A real AIR-backed proof lands in 5.6.c.1. The
> contract treats the proof as trustworthy because the relayer is
> already trusted via Dilithium signature on the bundle (same blast
> radius). When 5.6.c.1 ships, no consensus fork — the wire format
> stays the same.

#### Step 6.d — reduce_mod_l(digest) → h

```rust
let pv_reduce = reduce_mod_l_pv(expected_digest, expected_h);
if !env.verify_plonky3_proof(&proof_reduce, &pv_reduce, &REDUCE_MOD_L_AIR_ID_V1) {
    abort();  // BadReduceModLProof
}
```

> Same trust-shim caveat as 5.6.c (5.6.d.1 ships real AIR).

#### Step 6.e — scalar_mul(s, basepoint) → sB

```rust
let pv_sm_sb = scalar_mul_pv(/*scalar*/ &sig[32..64], &basepoint, sb);
if !env.verify_plonky3_proof(&proof_sm_sb, &pv_sm_sb, &SCALAR_MUL_AIR_ID_V1) {
    abort();  // BadScalarMulSbProof
}
```

#### Step 6.f — scalar_mul(h, A_point) → hA

```rust
let pv_sm_ha = scalar_mul_pv(&expected_h, &a_point, ha);
if !env.verify_plonky3_proof(&proof_sm_ha, &pv_sm_ha, &SCALAR_MUL_AIR_ID_V1) {
    abort();  // BadScalarMulHaProof
}
```

#### Aggregation result

After Steps 6.a–6.f, the message binding is closed transitively:

```text
sig[0..32]                    decompress         R_point  =  verify_air.R_point
                            ─────────────────►          
pk                            decompress         A_point  =  verify_air.A_point
                            ─────────────────►
R || A || M                   sha512             digest
                            ─────────────────►
digest                        reduce_mod_l       h
                            ─────────────────►
(s, basepoint)                scalar_mul         sB       =  verify_air.sB
                            ─────────────────►
(h, A_point)                  scalar_mul         hA       =  verify_air.hA
                            ─────────────────►
verify_air                    [s]B == R + [h]A   ← group equation
```

Soundness: the relayer cannot pick `R_point`/`A_point`/`sB`/`hA`
arbitrarily because each companion proof binds them to upstream values
the contract sees on-wire. The signed message `M` is bound via the
SHA-512 input chain.

If any of Steps 6.a-6.f fails, the contract rejects the bundle with
the corresponding error reason. The relayer's Dilithium signature
(Step 3) covers the entire bundle — including all six proofs and
their public values — so no part can be tampered post-signing.

> **Soundness note (legacy):** message binding (i.e. that the signed bytes encode
> the price the journal claims) was previously NOT verified. This is
> CLOSED as of sub-fases 5.6.0 + 5.6.a-d (this section). Real AIR
> backing for sha512 + reduce_mod_l (5.6.c.1, 5.6.d.1) is the only
> remaining pre-mainnet item; the wire format stays the same.

### Step 7 — Read previous state

For each per-feed state input (one or more), borsh-decode its script:

```rust
for state_input in tx.state_inputs() {
    let (feed_id, prev_snapshot) = borsh::from_slice(state_input.script())?;
    state_map.insert(feed_id, prev_snapshot);
}
```

A first-time feed (no prior state UTXO) is allowed: the contract
detects it by absence in `state_map` and treats `prev_snapshot.sequence`
as 0.

### Step 8 — Validate journal vs prev state

```rust
if let Some(prev) = state_map.get(&journal.feed) {
    if journal.sequence <= prev.sequence {
        abort();  // ReplayedSequence
    }
    if journal.publisher != prev.publisher {
        abort();  // PublisherChangedWithoutGovernance
    }
}
```

Reject reasons: `ReplayedSequence`, `PublisherChangedWithoutGovernance`.

### Step 9 — Validate journal vs contract policy

The contract holds a per-feed `FeedPolicy` (publisher, min/max price,
max age). Reject if the journal's bounds are wider than what the
contract accepts:

```rust
let policy = state.policies.get(&journal.feed).ok_or(UnknownFeed)?;
if journal.min_price < policy.min_price { abort(); }
if journal.max_price > policy.max_price { abort(); }
if journal.max_age_secs > policy.max_age_secs { abort(); }
if journal.publisher != policy.publisher { abort(); }
```

Reject reasons: `BoundsTooWide`, `WrongPublisher`, `UnknownFeed`.

### Step 10 — Freshness sanity (optional but recommended)

```rust
let now = env.read_block_height_unix_secs();    // approximate
if journal.publish_time + journal.max_age_secs < now {
    abort();  // StaleAtContractTime
}
```

Reject reason: `StaleAtContractTime`. This is a defense-in-depth check
(the prover already enforced it via `now_minus_max_age` in the
OracleAir public inputs); rejecting here catches the case where the
relayer submits a long-delayed bundle.

### Step 11 — Write new state

```rust
let new_snapshot = FeedSnapshot {
    price: journal.price,
    exponent: journal.exponent,
    publish_time: journal.publish_time,
    sequence: journal.sequence,
    publisher: journal.publisher.0,
};
let new_script = borsh::to_vec(&(journal.feed, new_snapshot))?;
let spk = ScriptPublicKey::from_vec(FEED_STATE_VERSION, new_script);
env.produce_output(spk, prev_state_input.amount);   // preserve sompi
```

The new state UTXO inherits the sompi value from the consumed state
input (or `INVOCATION_UTXO_VALUE` for a first-time feed, taken from
the invocation UTXO).

### Step 12 — Sweep change

If the invocation UTXO + state input(s) carry more sompi than the new
state UTXO needs, produce a change output back to the contract's own
address:

```rust
let change = total_input_value - sum_state_output_values;
if change > 0 {
    let contract_addr_spk = env.contract_address_p2sh_script();
    env.produce_output(contract_addr_spk, change);
}
```

## 4. State management

The contract persists in **two structures**:

### 4.1 Per-feed state (one UTXO per feed)

```rust
struct PerFeedStateUtxo {
    spk_version: u16 = FEED_STATE_VERSION,  // 8
    script: borsh((FeedId, FeedSnapshot)),  // 8 + 60 = 68 bytes
    amount: u64,                            // sompi (≥ INVOCATION_UTXO_VALUE)
}
```

Read by the SDK (`sophis-oracle-sdk::GrpcBackend`) via
`get_utxos_by_addresses(contract_address)` filtered to version 8.

### 4.2 Contract config (one UTXO total)

```rust
struct ContractConfigUtxo {
    spk_version: u16 = CONTRACT_CONFIG_VERSION,  // TBD, probably 9
    script: borsh(ContractConfig),
    amount: u64,
}

struct ContractConfig {
    relayer_allowlist: Vec<[u8; 32]>,    // SHA3-384 hashes of allowed relayer VKs (truncated to 32)
    policies: Vec<(FeedId, FeedPolicy)>, // per-feed bounds
    governance: GovernancePolicy,        // who can update the above
}
```

Updated by a separate governance contract entrypoint (see §6).

## 5. Error vocabulary

The contract MUST emit structured error reasons (sVM `abort_with_reason`
or equivalent) for every reject. This lets operators triage from logs
without a debugger:

```text
MalformedWirePayload
BadRelayerSignature
NotAllowedRelayer
BadOracleProof
BadVerifyAirProof
PublisherBindingFailed
ReplayedSequence
PublisherChangedWithoutGovernance
BoundsTooWide
WrongPublisher
UnknownFeed
StaleAtContractTime
```

A sVM tx with one of these reasons in its log is the definitive source
of truth — the relayer's logs alone may show "submitted" but be
silently rejected on-chain.

## 6. Governance (deferred to v2 spec)

v1 ships with a **single hard-coded relayer VK** and **single
hard-coded feed policy** baked into the contract at deploy time.
Bumping either requires deploying a new contract.

v2 (separate spec) will add governance entrypoints:

- `add_relayer(vk_hash, sig_quorum)`
- `remove_relayer(vk_hash, sig_quorum)`
- `set_policy(feed, policy, sig_quorum)`

with multisig (`UpgradePolicy::MultisigTimelock`) gating each.

## 7. Implementation hints (for the contract author)

- Use `sophis-sdk` macros (`#[entrypoint]`) to declare the contract
  entrypoint signature.
- The wire-payload decoder is straightforward — port directly from
  `oracle/relayer/src/sign.rs::decode_wire` (no async, no I/O).
- `ContractConfig` should be cached on the WASM heap once at
  invocation start; don't re-fetch per check.
- All borsh decoding must use `try_from_slice` (returns `Result`,
  doesn't panic).
- Test the contract end-to-end with the relayer in a devnet:
  - Spin up sophisd devnet
  - Deploy the contract
  - Run `sophis-oracle-relayer relay-once` against it
  - Read the resulting state UTXO via `sophis-oracle-sdk::FeedReader`

## 8. Reference symbols

The contract author needs these Rust symbols (all in
`sophis-oracle-core`, `sophis-oracle-relayer`, or the sVM SDK):

| Symbol | Crate | Use |
|---|---|---|
| `FeedId`, `PublisherKey`, `OracleJournal` | `sophis-oracle-core` | borsh decode |
| `ORACLE_INVOKE_VERSION = 7` | `sophis-oracle-core` | recognise invocation UTXO |
| `BUNDLE_DOMAIN_V1` | `sophis-oracle-relayer::sign` | re-derive commitment |
| `decode_wire(...)` | `sophis-oracle-relayer::sign` | parse wire payload |
| `oracle_air_id_v1()`, `verify_air_id_v1()` | `svm-host::plonky3` (under `--features plonky3`) | AIR ids |
| `FeedSnapshot` | `sophis-oracle-sdk` | borsh encode for state UTXO |
| `FEED_STATE_VERSION = 8` | `sophis-oracle-sdk::grpc` (under `--features grpc-read`) | state UTXO SPK version |

The SDK's `FEED_STATE_VERSION` constant SHOULD be re-exported from a
non-feature-gated crate (`sophis-oracle-core`?) for v2 — for v1 the
contract author can hardcode `8`.

## 9. Test plan

For the contract author to verify their implementation:

1. **Replay rejection** — submit two bundles with the same sequence,
   confirm the second is rejected with `ReplayedSequence`.
2. **Tampered signature** — flip a bit in the relayer signature, confirm
   `BadRelayerSignature`.
3. **Wrong publisher** — bundle's `journal.publisher` differs from
   the contract policy's expected publisher → `WrongPublisher`.
4. **OracleAir proof corruption** — flip a bit in the oracle proof
   bytes, confirm `BadOracleProof`.
5. **VerifyAir companion binding** — if companion present, mutate
   `verify_air_pv[..32]` away from `journal.publisher.0`, confirm
   `PublisherBindingFailed`.
6. **First-feed bootstrap** — no prior state UTXO; invoke fresh →
   new state UTXO produced with sequence = 1.
7. **Multi-feed batch** — two state inputs + one invocation → two
   state outputs, both with new snapshots.
8. **End-to-end** — devnet run with real relayer + real SDK reader.
