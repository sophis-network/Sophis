# Sophis Phase 6 — DIY audit playbook (sub-fase 6.9)

This is the **self-audit methodology** for the Phase 6 Data Availability
layer. The Sophis core team has no paid third-party security audit
budget for v1; the "audit" is therefore the union of:

1. The 14 consensus rules + threat model in `PHASE6_DA_DESIGN.md`
2. The unit + integration tests across the consensus, sVM, RPC, and
   relayer crates (77 tests verde at 6.8 close)
3. The property-style fuzz tests in `consensus/core/src/da/{mod,codec}.rs`
4. The adversarial threat × defense matrix in `devnet/test_phase6_da_attacks.py`
5. The 72h pre-mainnet stress run defined in `PHASE6_STRESS_PLAN.md`
6. The 30-day public voluntary security review (unpaid) in `PHASE6_BUG_BOUNTY.md`
7. Findings tracked in §5 of this document, with disclosure dates

The combination is **not** equivalent to a paid Trail-of-Bits-style
audit. It is the maximum operator-reasonable due-diligence the core
team can deliver under the no-entity / fair-launch / no-foundation
posture. The trade-off is explicit and documented.

**Status:** v1, drafted at sub-fase 6.9 (2026-05-06). This document
will accumulate findings as the voluntary security review runs and after the 72h
stress executes. Each finding is appended in §5 with a disclosure
date and a fix commit hash.

---

## 1. Scope

In scope for the self-audit (and for the voluntary security review in §3):

- `consensus/core/src/da/{mod,codec,store_types}.rs` — all 14 rules,
  the codec, the persisted types
- `consensus/src/model/stores/da.rs` — DbDaStore + DomainBucketKey
- `consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs`
  — `validate_carrier_outputs` + coinbase rule + value-range / SPK-len
  exemptions
- `consensus/src/pipeline/virtual_processor/processor.rs::index_carriers_in_block`
  — block-acceptance hook
- `consensus/src/svm_da.rs` — `SophisDaBackend`
- `svm/runtime/src/host.rs::sophis_verify_da` — capability + host fn
- `mining/src/mempool/check_transaction_standard.rs` — defense-in-depth
- `rollup/sequencer/src/{sequencer,batch,l1_client}.rs` — Phase 3 carrier
  publish path
- `rollup/host/guest/src/main.rs::da_bundle_id` computation
- `oracle/relayer/src/{config,daemon,submit}.rs` — `da_publish` flow

Out of scope (the design doc lists these as deferred):

- DAS / erasure coding (deferred per design §14.1)
- Encrypted carriers (deferred per §14.2)
- `Capability::ReadDataAvailability` (deferred per §14.3)
- Multi-region / WAN consensus dynamics (separate test track)
- gRPC / wRPC bindings (sub-fases 6.4.b/c pending — clients return
  `NotImplemented` and that is the expected behavior in v1)

## 2. Methodology

### 2.1 Static review (✅ done)

Every consensus rule (§5 of the design doc) maps to at least one unit
test. The mapping lives in `devnet/test_phase6_da_attacks.py` (sub-fase
6.7). For each of the 14 rules:

- Rule 1 (header truncated) → `da::tests::rule_1_header_truncated`
- Rule 2 (bad magic) → `rule_2_bad_magic`
- ... (see the test runner for the full mapping)

77 unit tests + 6 fuzz tests = **83 tests verde** at 6.9 ship.

### 2.2 Property / fuzz testing (✅ done)

`consensus/core/src/da/{mod,codec}.rs` contains 6 fuzz tests using
`rand` + 1000-5000 iterations each:

| Test | Invariant |
|---|---|
| `fuzz_parse_never_panics_on_random_input` | `parse_carrier_header` returns a `Result` for any input length 0..200 bytes |
| `fuzz_parse_never_panics_around_header_boundary` | Same, biased toward the magic prefix to drive past rule 2 |
| `fuzz_well_formed_inputs_always_parse` | Encoding 1000 random valid inputs and parsing them recovers all fields |
| `fuzz_parse_and_reassemble_never_panics` | `parse_and_reassemble` over random script sets does not panic |
| `fuzz_encode_bundle_roundtrips_for_random_blobs` | `encode_bundle → parse_and_reassemble` is the identity over 0..2 KiB blobs |
| `fuzz_payload_id_is_collision_resistant_for_distinct_inputs` | 1000 distinct random scripts produce 1000 distinct `payload_id`s (SHA3-384 sanity) |

These run as part of `cargo test -p sophis-consensus-core --lib da::`
in ~100 ms. Operators that want a deeper sweep can multiply the
iteration counts and re-run — there is no separate harness binary in
v1, by design (cargo-fuzz / libFuzzer require Linux + LLVM tooling
that is not part of the Sophis Windows-native build path).

### 2.3 Adversarial review (✅ done)

`devnet/test_phase6_da_attacks.py` (sub-fase 6.7) maps the 13 threats
in §9 of the design doc to their static defenses + cargo test filters.
Distribution:

- 8 covered (T1, T2, T5, T7, T9, T10, T11, T13)
- 2 skipped, multi-node Byzantine simulation required (T6, T8)
- 3 doc-only, cryptographic assumptions (T3 SHA3-384 collision, T4
  Grover preimage, T12 CRQC vs Dilithium)

### 2.4 Stress run (⏳ pending, plan ✅)

`oracle/docs/PHASE6_STRESS_PLAN.md` (sub-fase 6.8) defines the 72h
devnet run with 9 acceptance gates. Execution depends on:

- 6.4.b — gRPC carrier submission binding for the synthetic generator
- 6.5.b — real `current_blue_score` plumbing for G5 indexation lag
- 6.8.b — `sophis-da-stress` synthetic generator binary

Once executed, the full report appends to §5.4 of this document with
gate-by-gate PASS/FAIL.

### 2.5 Public review (⏳ in progress)

The 30-day voluntary security review in `PHASE6_BUG_BOUNTY.md` is the
public-review phase. RFC posted alongside it; design + RUNBOOK + STRESS_PLAN
+ test runner all visible in the `phase6-DALayer` GitHub branch.

## 3. Review checklist

Reviewers (internal + external) work through this checklist. Each box
links back to where the answer lives.

- [ ] **All 14 §5 rules have a unit test** — see §2.1; map in
      `devnet/test_phase6_da_attacks.py`
- [ ] **All 13 §9 threats have a documented defense** — see §2.3;
      map in `devnet/test_phase6_da_attacks.py`
- [ ] **Carrier bytes participate in block mass** — checked in
      `tx_validation_in_isolation::tests::carrier_*` and the standard
      mass formulas in `consensus/core/src/mass/`
- [ ] **Carrier outputs are unspendable** — V5 outputs never appear
      in `utxos_by_outpoints` lookups (verified by the indexation
      path; sub-fase 6.2.b)
- [ ] **`da_bundle_id` in BatchJournal matches `borsh(batch)` SHA3-384** —
      `rollup/sequencer/src/batch.rs::compute_da_bundle_id` +
      `rollup/host/guest/src/main.rs` (cross-checked against
      `consensus_core::da::bundle_id_of` in
      `da_bundle_id_matches_codec_bundle_id_of`)
- [ ] **`sophis_verify_da` is deterministic** — host fn captures
      `current_blue_score` at backend construction; same answer on
      every node
- [ ] **B3 boundary preserved** — `svm/host` does not depend on
      `consensus`; `SophisDaBackend` lives in `consensus/src/svm_da.rs`
- [ ] **No reintroduction of Schnorr / FHE / privacy primitives** —
      grep across the patch
- [ ] **No expansion of the SPK version registry beyond `5`** —
      `consensus/core/src/constants.rs::MAX_SCRIPT_PUBLIC_KEY_VERSION`
- [ ] **All 9 stress gates pass on devnet** — pending §2.4 execution

## 4. Known limitations (acknowledged at ship)

These are limitations the team accepts at v1, documented so reviewers
do not flag them as "missing":

| Item | Reason |
|---|---|
| `current_blue_score = 0` in `build_da_backend` (6.5.b deferred) | Conservative no-op; any `min_confirmations >= 1` returns 0. Determinístico. |
| gRPC + wRPC bindings stubbed (6.4.b/c deferred) | Trait + service impl is wired; binary client paths return `NotImplemented`. In-process Rust callers work today. |
| No CLI wallet helper (`dilithium-wallet da publish`) | Deferred to post-mainnet polish; integrators use the trait directly. |
| No fuzz harness binary (cargo-fuzz / libFuzzer) | Property tests in `cargo test` cover the same surface; libFuzzer needs Linux + LLVM tooling outside the Windows-native build path |
| Multi-tx splitting for >512 KiB calldata | Phase 3 batches don't reach this. Reject-with-error today; multi-tx splitter is a future enhancement |
| `GrpcSubmit::publish_carrier` real impl deferred | Default no-op covers the common case while operators are not yet running `da_publish=true` in prod |
| 72h stress run not yet executed | Plan + helper shipped; execution depends on 6.4.b/6.5.b/6.8.b |

## 5. Findings ledger

Findings are appended here as they come in. Each entry has the form:

```text
### F-N — <short title>
- Reporter: <name or pseudonym>
- Disclosed: YYYY-MM-DD
- Severity: critical | high | medium | low | info
- Scope: <module / file>
- Status: open | mitigated | fixed (commit <hash>)
- Description:
  <details>
- Mitigation / fix:
  <details>
```

### 5.1 Internal review pass (sub-fase 6.9, 2026-05-06)

No findings. The codebase ships with the limitations in §4 acknowledged
in the open.

### 5.2 Voluntary security-review findings (T-30d to T-0)

(empty until the review window opens)

### 5.3 Stress run report

(empty until §2.4 is executed)

### 5.4 Post-mainnet findings (T-0 onward)

(empty)

## 6. Reference

- Design freeze: `oracle/docs/PHASE6_DA_DESIGN.md`
- Operator manual: `oracle/docs/PHASE6_RUNBOOK.md`
- Stress plan: `oracle/docs/PHASE6_STRESS_PLAN.md`
- Public RFC wrapper: `oracle/docs/PHASE6_RFC.md`
- Voluntary security review: `oracle/docs/PHASE6_BUG_BOUNTY.md`
- Adversarial matrix: `devnet/test_phase6_da_attacks.py`
- Stress observability: `devnet/da_stress_check.py`
