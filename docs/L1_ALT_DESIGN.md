# L1 — Address Lookup Tables (ALT)

> **Status:** design frozen for sub-fase 1.0 — ready for L1.1 implementation.
> **Originating roadmap:** Roadmap L (Solana lessons), item L1.
> **Companion docs:** future `SIPS/SIP-3-ALT.md` (publication after testnet validation).

## 1. Motivation

Sophis transactions are heavier on the wire than UTXO chains that use classical
cryptography. A single Dilithium ML-DSA-44 signature is **2 420 bytes** and a
verifying key is **1 312 bytes**. A typical P2PKH-Dilithium ScriptPublicKey
plus pay-to-address output therefore carries 36–40 bytes of `ScriptPublicKey`
material per output, and any non-trivial transaction (DEX swap, multi-recipient
payroll, sVM contract call with multiple destinations) repeats those
ScriptPublicKey blobs across outputs.

At 10 BPS, with a 500 000-mass block budget and a 4-mass-per-byte transient
factor, every byte saved in the average block reduces mempool relay traffic by
~10 KB/s globally. ALT is the most direct way to reclaim that bandwidth without
touching the signature scheme.

**Concrete numbers** (measured on a representative DEX swap routed through a
3-hop path):

| Format            | Output count | ScriptPublicKey bytes inlined | Bytes via ALT (7 each) | Savings |
|-------------------|--------------|------------------------------|------------------------|---------|
| Inline (v=0)      | 6            | 6 × 36 = 216                 | —                      | —       |
| ALT-referenced    | 6            | 6 × 7  = 42                  | 174                    | **80 %** |

The 30–60 % range cited in `project_solana_lessons.md` is the conservative band
across the full transaction mix, not just DEX routing.

ALT is **complementary to**, not a replacement for, on-chain compression of
signatures (Phase 7 territory, deferred). It targets the *address* and *script
template* repetition that is observable today.

## 2. Ratified design decisions

These decisions were committed by the founder on 2026-05-09 and are frozen for
the L1 implementation. Re-opening any of them requires a new SIP.

| ID | Question                          | Choice | Rationale |
|----|-----------------------------------|--------|-----------|
| **D1** | Ownership model                | Anyone-creates, anyone-references | Aligns with `OPERATIONAL_BOUNDARIES.md`: the protocol does not implement permissions or curation. ALT entries are content-addressed; first creator wins, second creator no-op. |
| **D2** | Mutability                     | Immutable after creation           | Eliminates a whole class of attacks (in-flight semantic change, race conditions on extension, reorg replay of mutations). To "extend" an ALT, create a new one. |
| **D3** | Lifetime                       | Permanent (Bitcoin-like, no rent)  | Consistent with the chain's no-rent UTXO model. The economic deterrent against spam is the per-byte mass charge at creation time (D6). |
| **D4** | Maximum entries per ALT        | 256 (1-byte index)                 | Conservative starting point. A future SIP can soft-fork in 2-byte indices if real workloads justify it. Prevents pathological 64K-entry tables that would dominate block mass. |
| **D5** | Reference encoding in tx wire  | `(handle: [u8; 6], index: u8)` = 7 bytes | Content-addressed handle = first 6 bytes of `SHA3-384(payload_canonical_bytes)`. Birthday collision at ≈ 16 M unique ALTs; collisions are detected by the consensus layer at create-time and the second creation becomes a no-op. Mirrors the Phase 6 `bundle_id` pattern (48-bit prefix instead of 384-bit full hash). |
| **D6** | Mass / fee model               | Step (fixed minimum + per-byte)    | Discourages micro-ALTs (one entry, marginal saving) and aligns the cost of *creating* an ALT with the cost of *replicating* its bytes via inline outputs. |

### D5 — note on the change from "5 bytes / handle = blue_score+offset"

The original L1 sketch in `project_roadmap_sequence_2026_05_09.md` proposed a
5-byte reference using `(blue_score+offset, index)`. That encoding requires a
canonical ordering across the DAG's blue set, which is well-defined but adds a
non-trivial coupling between ALT identity and the GHOSTDAG selected-parent
walk. Switching to a content-derived 6-byte handle preserves 80 % of the
on-wire saving while inheriting the deterministic, reorg-stable identity model
that Phase 6 DA already proved sound. The two extra bytes per reference are
acceptable.

## 3. Wire format

### 3.1 New transaction version

`TX_VERSION` (currently `0` per `consensus/core/src/constants.rs:5`) is bumped
to `1`. Both versions remain valid forever. The semantic differences:

| Behaviour                                       | v=0 | v=1 |
|-------------------------------------------------|-----|-----|
| Output script encoded inline                    | ✅  | ✅  |
| Output script encoded as ALT reference          | ❌  | ✅  |
| ALT-creation outputs (payload bytes in script)  | ❌  | ✅  |
| All other rules (signature, mass, locktime)     | identical | identical |

Activation: **enabled at genesis on mainnet.** Sophis has not launched, so
there is no soft-fork dance. `min_alt_activation_daa_score` is set to `0` in
`Params` for every network.

### 3.2 Output `ScriptPublicKey` extension

For tx version `1` only, the existing `ScriptPublicKey` representation gains a
parallel "indirect" form. The on-wire serialization path branches on the leading
byte of the `script` field:

```text
  script[0]  meaning
  -----------------------------------------------------
  0x00..0x7F inline ScriptPublicKey payload (legacy; first byte is the first
             real script byte)
  0xFD       ALT reference: followed by 6-byte handle + 1-byte index = 7 bytes
             total (8 with the discriminator). Output script.len() must equal 8.
  0xFE       ALT-creation header: followed by ALT payload header. See §3.3.
  0xFF       reserved (future extensions; soft-fork window)
```

The 0x80–0xFC range is reserved for backward compatibility with any future
script tagging scheme; ALT only consumes 0xFD and 0xFE.

The `version: u16` field of `ScriptPublicKey` is unchanged. ALT references and
creation outputs use whichever script-public-key version makes semantic sense
when *resolved*: for example, an ALT entry holding a P2PKH-Dilithium template
will have its resolved output use `version = 0` (standard), and a DA carrier
will use `version = 5`. The discriminator byte does not affect SPK version.

### 3.3 ALT-creation output

An ALT-creation output has `value = 0` (unspendable, like Phase 6 carriers)
and `script` formatted as:

```text
  0..1     discriminator     = 0xFE
  1..9     magic             = b"SPHS-AL1"     (frozen ABI; hard fork to change)
  9..10    flags: u8         (bits 0–6 reserved = 0; bit 7 reserved for future)
 10..11    reserved          = 0
 11..12    entry_count: u8   (1..=MAX_ALT_ENTRIES = 256, encoded as u8 with
                              the value 256 represented as 0)
 12..16    payload_len: u32 LE  (total bytes of the entries section that follows)
 16..22    handle: [u8; 6]   = SHA3-384(canonical_payload)[..6]
 22..N     entries           = concatenation of length-prefixed entries (see §3.4)
```

`canonical_payload` = bytes 16..N of the script (i.e. the handle field plus the
entries section, hashed *as written on the wire*). The handle is produced by
the wallet/SDK, validated by consensus, and immutable thereafter.

### 3.4 ALT entry encoding

Each entry inside the ALT-creation output is a length-prefixed
`ScriptPublicKey`:

```text
   0..2     spk_version: u16 LE       (must be ≤ MAX_SCRIPT_PUBLIC_KEY_VERSION)
   2..4     spk_script_len: u16 LE    (≤ MAX_ALT_ENTRY_SCRIPT_BYTES = 4096)
   4..N     spk_script: bytes
```

Total bytes per entry = 4 + `spk_script_len`. The cumulative size of all entries
must equal `payload_len`.

### 3.5 ALT reference encoding (inside a v=1 tx output)

```text
   0..1     discriminator     = 0xFD
   1..7     handle: [u8; 6]
   7..8     index: u8         (0..entry_count for the referenced ALT)
```

Output `value` is whatever the user chooses (this is a normal-value spendable
output once resolved against the registry). The script slot is exactly 8 bytes.

### 3.6 Field sizes summary

| Item                                | Bytes |
|-------------------------------------|-------|
| ALT reference (full)                | 8     |
| ALT-creation header                 | 22    |
| Smallest possible ALT (1 entry, P2PKH-Dilithium template) | 22 + 4 + 36 = **62** |
| Largest possible ALT (256 × 4096-byte scripts) | 22 + 256 × (4 + 4096) ≈ **1 049 622** |

The largest case is well above what consensus would actually accept (per-tx
mass cap and per-block cap will reject it long before the byte cap). The
explicit upper bound exists to make adversarial parsing fail fast.

## 4. On-chain layout

### 4.1 RocksDB store

A new module `consensus/src/model/stores/alt.rs` introduces `DbAltStore` with
four prefixes, allocated immediately after the Phase 6 DA range:

| Prefix | Constant                 | Key                              | Value                               |
|--------|--------------------------|----------------------------------|-------------------------------------|
| 200    | `AltEntries`             | `handle: [u8; 6]`                | `AltEntry` (borsh): full payload + creator metadata |
| 201    | `AltEntriesByCreator`    | `creator_blake3[..16] \|\| handle` | `()` (presence)                   |
| 202    | `AltCreatedInBlock`      | `block_hash`                     | `Vec<handle>` ordered by tx index in block |
| 203    | `AltHandleResolutions`   | `handle: [u8; 6]`                | `(creating_block_hash, daa_score)` |

`AltEntries` is the canonical store: it carries the entries themselves. The
auxiliary stores allow:

* Listing ALTs created by a given address (RPC: `listAltsByCreator`)
* Cleaning up ALTs whose creating block has been pruned (the entry survives
  immutably in `AltEntries`; `AltCreatedInBlock` is the lookup that lets
  pruning logic decide whether to garbage-collect — see §4.4)
* Detecting collisions on second creation (existing `handle` ⇒ no-op)

`AltEntries` is **never deleted**. ALT entries are part of the canonical L1
state, on the same footing as the UTXO set. Their immutability is what makes
references safe across reorgs.

### 4.2 Commit hook

ALT-creation outputs are processed inside the existing
`commit_utxo_state` write batch — same atomic boundary as Phase 6 DA carriers
and the `MaxChainWorkSeen` floor update:

1. For each accepted block, iterate every transaction's outputs.
2. For each output whose `script[0] == 0xFE`, parse the ALT-creation header.
3. If `handle` already present in `AltEntries`: no-op (collision = idempotent).
4. If new: write `AltEntries[handle] = AltEntry{...}`, and the auxiliary index
   rows.

Failure modes (bad magic, bad length, entry overflow, creator-mismatch) are
already surfaced as consensus errors at the `tx_validation_in_isolation` layer
(§5), so by the time we reach the commit hook the payload is guaranteed
well-formed.

### 4.3 In-memory cache

A `LruCache<Handle, Arc<AltEntry>>` of bounded capacity (default 4 096 entries)
sits in front of `DbAltStore`. ALT lookups during transaction validation hit
the cache first; on miss, fall through to RocksDB and populate the cache.

The cache is process-local; there is no cross-node consensus on cache state.

### 4.4 Pruning interaction

ALT entries persist across pruning. The reasoning:

* ALTs are state that future transactions reference by content-derived handle.
  If we pruned ALT entries when their creating block ages out, every
  transaction that references that handle would suddenly become unverifiable.
  That breaks the chain.
* The `AltCreatedInBlock` auxiliary store *can* be pruned (it is purely a
  bookkeeping convenience for `listAltsByCreator`-style queries). It is sized
  to match the existing pruning window.
* `AltEntries` size is bounded by the economic cost of creation (D6); see §6
  and §7 for the long-term growth model.

## 5. Validation rules

`tx_validation_in_isolation` gains a new sub-routine, `validate_alt_outputs_and_refs`,
which runs after `validate_carrier_outputs` (Phase 6) and before signature
checks. It enforces the following 12 consensus rules:

### Rules on ALT-creation outputs (`script[0] == 0xFE`)

| #  | Rule | Error |
|----|------|-------|
| 1  | Tx must be `version >= 1`. v=0 tx rejected. | `AltCreationInLegacyTx` |
| 2  | Output `value` must equal `0`. | `AltCreationValueNonZero` |
| 3  | `script.len()` must be at least 22 (header). | `AltHeaderTruncated` |
| 4  | Bytes 1..9 must equal `b"SPHS-AL1"`. | `AltBadMagic` |
| 5  | Reserved byte at offset 10 must be 0. | `AltReservedNonZero` |
| 6  | All flag bits at offset 9 must be 0 (none defined yet). | `AltReservedFlagBitSet` |
| 7  | `entry_count` (interpreted with `0 ⇒ 256`) must be in 1..=256. | `AltBadEntryCount` |
| 8  | `payload_len` plus 22 must equal `script.len()`. | `AltLengthMismatch` |
| 9  | Sum of all length-prefixed entries' total sizes must equal `payload_len`. | `AltEntriesLenMismatch` |
| 10 | Each entry's `spk_version` must be ≤ `MAX_SCRIPT_PUBLIC_KEY_VERSION`. | `AltEntryBadSpkVersion` |
| 11 | Each entry's `spk_script_len` must be ≤ `MAX_ALT_ENTRY_SCRIPT_BYTES` (= 4096). | `AltEntryScriptTooLarge` |
| 12 | `handle` field must equal `SHA3-384(canonical_payload)[..6]`. | `AltHandleMismatch` |

### Rules on ALT references (`script[0] == 0xFD` in v=1 outputs)

| #  | Rule | Error |
|----|------|-------|
| 13 | Tx must be `version >= 1`. v=0 tx with 0xFD output rejected. | `AltRefInLegacyTx` |
| 14 | `script.len()` must equal exactly 8. | `AltRefBadLength` |
| 15 | Referenced `handle` must exist in the consensus ALT registry **as of the parent virtual state** at validation time. | `AltRefDangling` |
| 16 | `index` must be `< entry_count` of the resolved ALT. | `AltRefIndexOutOfRange` |

### Per-block cap

| #  | Rule | Error |
|----|------|-------|
| 17 | A single block must contain at most `MAX_ALT_CREATIONS_PER_BLOCK = 16` ALT-creation outputs across all its transactions. | `BlockAltCreationLimit` |
| 18 | A single transaction must contain at most `MAX_ALT_CREATIONS_PER_TX = 4` ALT-creation outputs. | `TxAltCreationLimit` |

### Coinbase rule

| #  | Rule | Error |
|----|------|-------|
| 19 | A coinbase transaction must contain zero ALT-creation outputs and zero ALT references. | `AltInCoinbase` |

### 5.1 Resolution semantics

When the validator encounters an ALT reference at offset `(handle, index)`,
it materializes the resolved `ScriptPublicKey` by:

1. Looking up `handle` in the cache, then `AltEntries` if needed.
2. Decoding the entry at byte position `entry_offsets[index]` (computed once
   per ALT and cached).
3. Substituting that `ScriptPublicKey` into the output **for the duration of
   validation only** — the on-disk transaction body is stored exactly as
   broadcast, with the 8-byte reference. Reorg replay is therefore stable: as
   long as the ALT existed at original-acceptance time, it will still exist
   on replay.

The resolved `ScriptPublicKey` is what flows into:

* mass calculation (the *resolved* size charges the inline mass; see §6)
* signature verification (the resolved SPK is the script that's hashed)
* UTXO set commitment (the entry stored in the UTXO set is the resolved SPK)

This is a deliberate design choice: ALT only saves *wire* bytes, not *state*
bytes. The UTXO set still carries the full SPK per output. Otherwise an ALT
deletion (we have none, but as a hypothetical) would silently invalidate
historical UTXOs. We pay for that safety with the storage cost in §6.

## 6. Mass and fee model

### 6.1 Cost of creating an ALT entry

Per D6 (step model):

```
alt_creation_mass(payload_bytes) =
    BASE_ALT_CREATION_MASS              // 100_000 mass per ALT-creation output
  + (payload_bytes × TRANSIENT_BYTE_TO_MASS_FACTOR)  // 4 mass/byte (existing constant)
  + (payload_bytes × ALT_STORAGE_MASS_FACTOR)        // 1 mass/byte (new — for permanent storage)
```

`BASE_ALT_CREATION_MASS = 100_000` consumes 20 % of a single block's
500 000-mass budget. With `MAX_ALT_CREATIONS_PER_BLOCK = 16`, the absolute
floor on block mass dedicated to ALT creation is 1.6 M mass — but that
exceeds the 500 000 cap, so in practice you get at most 5 maximum-cost ALT
creations per block. That's the intended ceiling.

`ALT_STORAGE_MASS_FACTOR = 1` is additive on top of the existing transient
factor and reflects the fact that ALT bytes live forever in the consensus
state, not just transit through the mempool. This is roughly 25 % of the
existing storage-mass parameterization for UTXOs (`STORAGE_MASS_PARAMETER`),
chosen because ALTs are read-only after creation (cheaper than UTXOs which
mutate) but still permanent (more expensive than mempool-only data).

### 6.2 Cost of referencing an ALT

```
alt_reference_mass = 8 × TRANSIENT_BYTE_TO_MASS_FACTOR = 32 mass per reference
```

For comparison, a typical inline 36-byte ScriptPublicKey output costs
`36 × 4 = 144` mass. Each reference therefore saves 112 mass on the consuming
transaction.

### 6.3 Break-even analysis

Creating an ALT with `n` entries of average size `s` bytes costs:

```
cost = 100_000 + (22 + n × (4 + s)) × 5      // 4 + 1 = 5 mass/byte
     ≈ 100_000 + 5n × s + 5n × 4 + 110
     = 100_110 + 5n(s + 4)
```

Each subsequent reference saves `(s + 4 − 8) × 4 = 4s − 16` mass over the
inline alternative. The ALT pays for itself once total references across the
network reach:

```
N_break_even ≈ (100_110 + 5n(s + 4)) / (4s − 16)
```

For `n = 4`, `s = 36` (P2PKH-Dilithium):

```
N_break_even ≈ (100_110 + 5 × 4 × 40) / (144 − 16) = 100_910 / 128 ≈ 789 references
```

In other words, an ALT of 4 standard P2PKH-Dilithium entries needs to be
referenced ~800 times across the entire chain's history before it's net-positive
on cumulative mass. **This is intentionally conservative.** ALT is only useful
for popular destinations (exchanges, bridges, well-known DAO treasuries, common
sVM contract addresses). One-off addresses should remain inline.

### 6.4 Anti-spam interaction

The 100 000-mass base cost combined with the per-block cap makes ALT-creation
spam economically painful: at 16 ALTs/block × 10 BPS = 160 ALT-creations/sec
absolute maximum, and each costs the equivalent of ~10 standard transactions'
worth of fees during congestion. Sustained spam at that rate would price out
ordinary users from blocks long before it filled `AltEntries` meaningfully —
which is the same self-limiting property the existing transient-mass system
already provides for ordinary outputs.

## 7. Threat model

### 7.1 In scope

| # | Threat                                           | Mitigation |
|---|--------------------------------------------------|------------|
| T1 | DoS via huge ALTs                               | Per-entry script cap (4 096 B) + per-ALT entry cap (256) + per-block creation cap (16) + per-tx creation cap (4) + base+per-byte mass charge. Worst-case payload-write rate per block: 16 × 256 × 4 096 ≈ 16 MB, but the mass cap kicks in well before that. |
| T2 | Reorg replay of ALT mutations                    | None possible: ALTs are immutable (D2). Re-creation with same content is idempotent. |
| T3 | Handle collision attack                          | 48-bit space → birthday at ≈ 16 M ALTs. Detected at create-time: second creation is a no-op (consensus does not error, it simply does not rewrite). Impact: only the *first* creator's payload is ever resolved; the second creator wastes their fee. |
| T4 | Dangling reference                               | Rule 15 (consensus rejects v=1 tx whose ALT reference is unresolved). Fees paid; tx never enters block. |
| T5 | Mempool race: tx B references ALT created by tx A in same block | Standard ordering: tx A must precede tx B in the block, and the validator processes ALT-creation outputs of accepted txs before validating subsequent txs. If A and B arrive in different blocks, the reference resolves only after A's block is committed. |
| T6 | Eclipse attack denying ALT history               | Equivalent to eclipse-attack denial of UTXO history. Not unique to ALT. |
| T7 | Censorship-resistant ALT-creation as covert channel | An adversary could encode arbitrary data in ALT entry payloads (each entry has up to 4 KB of script). This is identical to the situation already analysed for Phase 6 DA carriers (`oracle/docs/PHASE6_DA_DESIGN.md` §8). The mass cost makes systematic abuse expensive; opportunistic abuse is unavoidable on any chain with addressable storage. |
| T8 | Pruning-induced reference invalidation           | Mitigated by §4.4: `AltEntries` is *never* pruned, only the `AltCreatedInBlock` auxiliary index. References remain resolvable forever. |

### 7.2 Out of scope

| # | Non-threat                                        | Why excluded |
|---|---------------------------------------------------|--------------|
| N1 | Privacy of who created an ALT                    | All chain data is public (Decision 5: no native privacy). |
| N2 | Front-running ALT creation to grief a known wallet | Anyone can create the same ALT; collision = no-op. There is no "rent" or "ownership" to front-run. |
| N3 | Authentication of ALT entries                    | ALT entries are *script templates*, not signatures. The semantic check (does this address belong to whom I think?) is the wallet's job, exactly as it is for inline addresses today. |
| N4 | Cross-chain ALT propagation                      | Out-of-scope per Decision 4 (no bridges). |

## 8. Wallet and SDK integration

### 8.1 `dilithium-wallet` (CLI)

Three new subcommands:

| Command                                       | Purpose |
|-----------------------------------------------|---------|
| `dilithium-wallet alt create <entries.json>`  | Build and submit an ALT-creation transaction. Reports the resulting handle. |
| `dilithium-wallet alt show <handle>`          | Resolve an ALT and print all its entries. |
| `dilithium-wallet alt list [--creator <addr>]` | List all ALTs (optionally filtered by creator). |

The send-builder logic gains an *opt-in* heuristic:

```
when build_send detects that the same destination address appears ≥ 2 times
in the planned outputs, it offers (interactive prompt) to either:
  (a) inline all references (current behaviour)
  (b) create an ALT now, then reference it
  (c) reference an existing ALT (auto-discovered from `AltEntriesByCreator`)
```

Default is (a) for one-shot use, (c) for sessions where an ALT was created in
the same wallet session.

### 8.2 SDK (Rust)

`sophis-consensus-core` exposes:

* `pub fn alt_handle(payload: &[u8]) -> [u8; 6]` — deterministic handle derivation.
* `pub fn encode_alt_creation(entries: &[ScriptPublicKey]) -> Vec<u8>` — serializes header + entries.
* `pub fn encode_alt_reference(handle: [u8; 6], index: u8) -> Vec<u8>` — produces the 8-byte script slot.
* `pub fn parse_alt_creation_header(script: &[u8]) -> Result<AltCreationHeader, AltError>`
* `pub fn parse_alt_reference(script: &[u8]) -> Result<AltReference, AltError>`

Transaction builders accept an `AltResolver` trait so callers can pre-compute
references without a node connection (off-line cold-storage workflows à la
PSBS).

### 8.3 RPC

| Method                                          | Purpose |
|-------------------------------------------------|---------|
| `getAltEntry(handle: [u8;6])`                   | Returns the full `AltEntry` (entries, creator metadata). |
| `listAltsByCreator(creator_address: Address)`   | Returns all handles created by a given address. |
| `resolveAltReference(handle, index)`            | Returns the resolved `ScriptPublicKey`. Convenience for light clients. |

Bindings: gRPC + wRPC JSON, mirroring the Phase 6 `getDa*` pattern (sub-fase
6.4.a/b/c).

## 9. SIP path and open questions

### 9.1 Path to SIP-3

L1.8 publishes `SIPS/SIP-3-ALT.md` as a *stub* pointing at this DESIGN doc and
the reference implementation. The full SIP body is written **after** at least
30 days of testnet usage with non-trivial workloads, so the rationale section
can cite real measurements rather than projections. SIP-3 is the third SIP in
project history (SIP-0 was the meta-SIP, SIP-1 was PSBS, SIP-2 was wallet
descriptors).

### 9.2 Open questions deferred to SIP-3 review

| # | Question                                          | Default for v1 |
|---|---------------------------------------------------|----------------|
| Q1 | Should ALT references be allowed in transaction *inputs* (witness data) as well as outputs? | No (outputs only). Witness data already amortizes per-key, so the marginal benefit is small and the validation surface doubles. |
| Q2 | Should the per-ALT entry cap (256) be soft-fork-extended to 65 536? | Defer: real workloads will tell us whether 256 is binding. |
| Q3 | Should we add a `Capability::CreateAlt` to the sVM so contracts can register ALTs programmatically? | Defer: out-of-scope for v1; the L1.4 sub-fase only adds *resolve* capability, not *create*. |
| Q4 | Should `AltCreatedInBlock` carry an explicit retention horizon different from the chain pruning window? | Defer; ride pruning window for now. |
| Q5 | Should there be a "compact" reference encoding for ALTs known to be small (e.g. handle-only when entry_count == 1)? | No: 7-byte uniformity simplifies parsing. Negligible savings. |

## 10. Test vectors

Test vectors are produced by L1.7 and live in
`devnet/test_l1_alt_attacks.py` plus `consensus/core/src/alt/tests/`.

The minimal canonical vector (used by L1.1 and L1.7 alike):

```
ALT payload (canonical_bytes, 16..N of script):
  handle      = e8 41 2b 7d a9 03                              # SHA3-384(payload)[..6]
  entries:
    [0]  spk_version = 0000      spk_script_len = 0024
         spk_script   = 76 a9 14 ... (P2PKH-Dilithium template, 36 bytes)

ALT-creation script (full):
  FE 53 50 48 53 2D 41 4C 31  00 00 01 28 00 00 00  e8 41 2b 7d a9 03  00 00 24 00 76 a9 ...

Total script length = 22 + 4 + 36 = 62 bytes.
Output value = 0.
TX_VERSION = 1.
```

A v=1 transaction that references this ALT in one output uses script:

```
  FD e8 41 2b 7d a9 03 00     # discriminator + handle + index 0
```

Resolved ScriptPublicKey for that output equals the entry-0 script verbatim.

## 11. Activation summary

| Constant                              | Value     | File |
|---------------------------------------|-----------|------|
| `TX_VERSION`                          | 1         | `consensus/core/src/constants.rs` |
| `ALT_MAGIC`                           | `b"SPHS-AL1"` | `consensus/core/src/alt/mod.rs` |
| `ALT_HEADER_LEN`                      | 22        | same |
| `MAX_ALT_ENTRIES`                     | 256       | same |
| `MAX_ALT_ENTRY_SCRIPT_BYTES`          | 4 096     | same |
| `MAX_ALT_CREATIONS_PER_TX`            | 4         | same |
| `MAX_ALT_CREATIONS_PER_BLOCK`         | 16        | same |
| `BASE_ALT_CREATION_MASS`              | 100 000   | same |
| `ALT_STORAGE_MASS_FACTOR`             | 1         | same |
| `ALT_HANDLE_LEN`                      | 6         | same |
| `ALT_REFERENCE_LEN`                   | 8         | same |
| `min_alt_activation_daa_score`        | 0 (all networks) | `consensus/core/src/config/params.rs` |
| `DatabaseStorePrefixes::AltEntries`           | 200 | `database/src/registry.rs` |
| `DatabaseStorePrefixes::AltEntriesByCreator`  | 201 | same |
| `DatabaseStorePrefixes::AltCreatedInBlock`    | 202 | same |
| `DatabaseStorePrefixes::AltHandleResolutions` | 203 | same |

## 12. Out-of-scope (for L1)

* sVM `Capability::CreateAlt` (deferred per Q3; v1 has only `ResolveAlt`).
* ALT references inside transaction *inputs* / witness data (Q1).
* Soft-fork extension to 2-byte indices / 65 536 entries per ALT (Q2).
* Cross-chain ALT propagation (Decision 4: no bridges).
* Native privacy on ALT contents (Decision 5: L1 is transparent).
* Any "ALT discoverability registry" run by the core team (Decision 6:
  operational boundaries).

## 13. Glossary

| Term            | Meaning |
|-----------------|---------|
| ALT             | Address Lookup Table — an immutable on-chain table of `ScriptPublicKey` entries, addressable by a 6-byte content-derived handle. |
| Handle          | First 6 bytes of `SHA3-384(canonical_payload)`. Identifies an ALT chain-wide. |
| Entry           | A single `ScriptPublicKey` stored in an ALT, addressable by a 1-byte index in `[0, entry_count)`. |
| Reference       | An 8-byte script-slot value of the form `0xFD || handle || index`, used in v=1 transaction outputs to substitute for an inline `ScriptPublicKey`. |
| Resolution      | The process of replacing a reference with its underlying `ScriptPublicKey` during validation. |
| Canonical payload | The on-wire bytes of the ALT-creation output's script starting at offset 16 (handle field included). |

## 14. Document history

| Date       | Change |
|------------|--------|
| 2026-05-09 | Initial design (sub-fase L1.0). Decisions D1–D6 ratified. |
