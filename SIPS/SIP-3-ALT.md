```
SIP: 3
Title: Address Lookup Tables (ALT)
Author: Marcelo Delgado <sophis-network@proton.me>
Status: Draft
Type: Standards
Created: 2026-05-10
Requires: 0
```

# SIP-3: Address Lookup Tables (ALT)

> **Status note:** this document is the *stub* that accompanies the L1 ALT
> reference implementation merged in commits `d1add7d`..`c009b99` (5
> commits, ~3000 LOC + ~50 tests). The full SIP body is intentionally
> deferred until after at least 30 days of testnet usage with non-trivial
> ALT workloads, so the Rationale and Security Considerations sections can
> cite real measurements rather than projections. SIP-0 §6 ("Standards
> Track") permits this two-phase pattern: a *stub* anchors the proposal
> in the SIP series and freezes the wire format and decision IDs; the
> *full body* lands when measurements support it.

## 1. Abstract

Sophis transactions are heavier on the wire than UTXO chains using
classical cryptography because Dilithium ML-DSA-44 verifying keys and
signatures are 1 312 B and 2 420 B respectively. SIP-3 introduces
**Address Lookup Tables (ALT)**: an immutable on-chain registry of
`ScriptPublicKey` entries, addressable by a 6-byte content-derived
handle. v=1 transactions can substitute an inline `ScriptPublicKey`
with a 7-byte ALT reference, reducing on-wire size by 30–60 % for
typical multi-output transactions and by 80 % for routed DEX swaps.

ALT is gated behind a new transaction version (`MAX_TX_VERSION = 1`)
and activated at genesis on every network. v=0 transactions retain
their full wire format forever.

## 2. Motivation

See `docs/L1_ALT_DESIGN.md` §1 for the canonical motivation, the
measurement table comparing inline vs ALT-referenced encodings, and
the bandwidth-savings argument at 10 BPS.

## 3. Specification

The technically complete specification is published at
`docs/L1_ALT_DESIGN.md` in the reference implementation tree
(`sophis-network/Sophis@c009b99` and forward). It enumerates:

- 19 numbered consensus rules (§5)
- Wire format with hex-level byte layouts (§3.3, §3.4, §3.5)
- On-chain RocksDB layout and prefix allocation 200..202 (§4)
- Mass / fee model with break-even analysis (§6)
- Threat model with 8 in-scope and 4 out-of-scope items (§7)
- 6 ratified design decisions (D1–D6, §2)

This SIP body will be re-issued in Review once testnet measurements are
available; readers should treat the DESIGN doc as the authoritative
specification until that re-issue.

## 4. Rationale

Deferred to the full SIP body. The DESIGN doc §2 already enumerates the
six ratified decisions (D1–D6) and their rationales; what changes in the
full SIP is the addition of empirical numbers (transaction-mix breakdown,
average savings observed, ALT cache hit-rate from devnet/testnet runs)
to justify the conservative defaults.

The most likely points of testnet-driven revision are:

- Q1 — extending references to transaction *inputs* (defaulted to "no" in
  L1.0, may be revisited if witness data dominates measurements)
- Q2 — soft-forking the per-ALT entry cap from 256 (1-byte index) to
  65 536 (2-byte index)
- D6 — concrete `BASE_ALT_CREATION_MASS` calibration (currently 100 000)

## 5. Backwards Compatibility

**Activated at genesis.** Sophis has not launched mainnet, so there is no
soft-fork window. v=0 and v=1 transactions are simultaneously valid from
block 0. The validator accepts any version in `[TX_VERSION,
MAX_TX_VERSION]`.

Wallets that do not use ALT are entirely unaffected and need no upgrade.
Wallets that wish to *consume* ALT references in v=1 outputs must
implement the resolution algorithm from DESIGN §5.1 (or call the
forthcoming `getAltEntry` RPC introduced by L1.6 — separate sub-fase).

## 6. Reference Implementation

Reference implementation: `sophis-network/Sophis` commits
`d1add7d`..`c009b99` (5 commits over the L1.0–L1.4 sub-fases):

| Commit | Sub-fase | Scope |
|--------|---------|-------|
| `d1add7d` | L1.0 | Design document (`docs/L1_ALT_DESIGN.md`, ~550 lines) |
| `b5e49a8` | L1.1 | Consensus types: `consensus/core/src/alt/` (parser, codec, 32 tests) |
| `c4adb2a` | L1.2 | RocksDB store: `consensus/src/model/stores/alt.rs` (16 tests) |
| `d9f8fab` | L1.3.a | Per-tx isolation validation (rules 1-14, 18, 19; 14 tests) |
| `cc8d050` | L1.3.b/c/d | utxo-context resolution (rules 15-16) + per-block cap (rule 17) + mass model + commit hook |
| `c009b99` | L1.4 | sVM `Capability::ResolveAlt` + `sophis_alt_lookup` host fn |

Operational sub-fases L1.5 (wallet CLI), L1.6 (gRPC + wRPC), L1.7
(adversarial devnet runner) and L1.8 (this stub + RUNBOOK) close the
core team's L1 deliverables.

## 7. Security Considerations

Comprehensive threat model in DESIGN §7. Highlights:

- **Determinism:** ALT lookup is a pure RocksDB read against a registry
  populated at chain-block commit time (sub-fase L1.3.d). All full nodes
  observing the same chain block see the same registry state.
- **Reorg safety:** ALT entries are *never* deleted. References from
  re-organised transactions remain resolvable forever; the auxiliary
  `AltCreatedInBlock` index is the only thing pruning may touch.
- **DoS:** capped via `MAX_ALT_CREATIONS_PER_TX = 4`,
  `MAX_ALT_CREATIONS_PER_BLOCK = 16`, `MAX_ALT_ENTRIES = 256`,
  `MAX_ALT_ENTRY_SCRIPT_BYTES = 4096`, plus a `BASE_ALT_CREATION_MASS`
  of 100 000 on top of the existing per-byte transient charge.
- **Collision:** 6-byte content-derived handle space (~16 M unique ALTs
  before birthday). Detected at create time; second creator becomes a
  no-op (first writer wins). No attack surface — content addresses.
- **PQC:** ALT does not introduce any new cryptographic primitive. The
  handle uses SHA3-384 (Sophis's existing hash). PQC posture preserved.
- **DA/ZK compatibility:** ALT lives in transaction outputs, parallel
  to the Phase 6 V5 carrier output. The two systems are independent;
  a single transaction may contain both.

## 8. Test Vectors

Canonical vectors live with the reference implementation in:

- `consensus/core/src/alt/codec.rs` (`tests` module) — codec round-trip
- `consensus/core/src/alt/mod.rs` (`tests` module) — parser per-rule
  rejection (14 vectors covering rules 3-14)
- `docs/L1_ALT_DESIGN.md` §10 — minimal canonical wire-format vector
  (one entry, P2PKH-Dilithium template)

Devnet integration vectors will be added by L1.7. The wire format is
frozen as of `b5e49a8`.

## 9. References

- BIP-380 — descriptor checksum / generators (cited for the polymod
  algorithm reused in K3 wallet descriptors; out of scope for SIP-3
  itself but cross-referenced for the descriptor / ALT integration
  story)
- Solana ALT (Address Lookup Tables) — original conceptual ancestor;
  divergences described in `project_solana_lessons.md` and DESIGN §1
- `oracle/docs/PHASE6_DA_DESIGN.md` — V5 carrier output, the prior
  art for "discriminator-byte plus magic-prefixed payload inside an
  unspendable output"
- `docs/L1_ALT_DESIGN.md` — authoritative wire-format spec
- `consensus/src/svm_alt.rs` — `HostAlt` impl

## 10. Copyright

This SIP is released into the public domain (CC0).
