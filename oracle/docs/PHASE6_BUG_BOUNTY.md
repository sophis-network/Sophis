# Sophis Phase 6 — voluntary pre-mainnet security review

Sophis runs a **30-day voluntary security-review window** on the Phase 6
Data Availability layer. The window opens with the public RFC
announcement (see `PHASE6_RFC.md`) and closes 30 calendar days later.

**This is a voluntary review. There is no bug bounty and no monetary
reward.** Participation is unpaid. Reporters of verified findings may be
publicly credited if they wish — recognition is the only acknowledgment
offered. Findings outside the window are still welcome and are recorded
in `PHASE6_AUDIT.md` §5.2.

**Status:** v1, drafted at sub-fase 6.9 (2026-05-06). Not active until
the start-of-window announcement is published.

---

## 1. Scope (in)

The same surface as `PHASE6_AUDIT.md` §1:

- Consensus rules: 14 rules of §5 of the design doc
- Carrier codec: `consensus/core/src/da/{mod,codec,store_types}.rs`
- DA store: `consensus/src/model/stores/da.rs` + the virtual_processor
  hook
- sVM capability: `svm/runtime/src/host.rs::sophis_verify_da` +
  `consensus/src/svm_da.rs`
- Sequencer + relayer integration: `rollup/sequencer/`,
  `oracle/relayer/`
- RPC trait + service impl: `rpc/core/src/{api/rpc.rs, model/da.rs}`,
  `rpc/service/src/service.rs`

## 2. Scope (out)

Findings in these areas are still welcomed (recorded per
`PHASE6_AUDIT.md §5.2`) but are not the focus of this window:

- **Cryptographic assumptions of SHA3-384 / Dilithium ML-DSA-44 /
  RandomX** — inherited from the L1 and from NIST-standard primitives.
- **Stubbed gRPC / wRPC clients returning `NotImplemented`** — that is
  the documented v1 behavior (sub-fase 6.4.b/c deferred).
- **`current_blue_score = 0`** — documented limitation, not a bug. See
  `PHASE6_AUDIT.md §4`.
- **Performance regressions** — covered by the 72h stress run.
- **Issues outside `oracle/docs/PHASE6_*` and the Phase 6 code paths
  listed in §1** — file separately if relevant.

## 3. What counts as a finding

| Class | Example |
|---|---|
| **Consensus break** | A V5 carrier the consensus accepts but the §5 rules should reject; or vice-versa |
| **Determinism break** | Two correctly synced nodes return different `sophis_verify_da` answers for the same query against the same chain state |
| **Memory safety / panic** | A reachable `panic!` / `unreachable!` / `unwrap` on attacker-controlled input |
| **Capability bypass** | A contract calls `sophis_verify_da` and gets `1`/`0`/`-1` without declaring `Capability::VerifyDataAvailability` |
| **DOS at lower cost than the published gas / mass formula** | Submitting a carrier that consumes >> the mass it pays |
| **Indexation corruption** | A sequence of carriers that leaves `DbDaStore` with `payload_id` pointing to a body that does not hash to it |
| **Cross-domain confusion** | A carrier with `DOMAIN_ROLLUP` decoded as oracle / user without consensus rejection |
| **Pruning regression** | A pruned node returns inconsistent answers post-restart |

## 4. Out of scope ("not a bug")

- "I tampered with my own RocksDB and the answers are wrong" — the
  trust boundary is "honest local storage."
- "I forked the chain on my devnet" — fork attacks against an isolated
  devnet do not transfer to mainnet without separate WAN-scale
  reproduction.
- "I built a contract that always returns false from
  `sophis_verify_da` and that broke my dapp" — that is the documented
  StubDa fallback for tests / lite builds.
- Unit-test corner cases without a meaningful exploit narrative.

## 5. How to report

- Use the private channel in `SECURITY.md` (GitHub private vulnerability
  reporting, or the security email).
- DO NOT open a public GitHub issue with consensus-impact details;
  use the private channel until a fix is committed and released.

A report should include:

1. The finding class from §3
2. A reproducer (Rust test, Python script, or step-by-step description)
3. The branch + commit you tested against
4. Suggested mitigation, if any

## 6. Disclosure

- Report received: acknowledged on a best-effort basis.
- Severity triage shared privately with the reporter.
- Fix or mitigation committed; public disclosure on the repo plus an
  entry in `PHASE6_AUDIT.md §5.2`. Consensus-affecting fixes may require
  a coordinated network upgrade and have no fixed timeline.

## 7. What this review is NOT

- **Not insurance against a v1 mainnet bug.** It is a best-effort
  voluntary review, not a guarantee.
- **Not a paid program.** No reward schedule exists, before or after
  mainnet.
- **Not a substitute for a paid third-party audit.** This voluntary
  review plus the DIY methodology in `PHASE6_AUDIT.md` is the
  due-diligence the project delivers under its no-foundation posture.
  The trade-off is explicit.

## 8. Reference

- DIY audit playbook: `oracle/docs/PHASE6_AUDIT.md`
- Public RFC: `oracle/docs/PHASE6_RFC.md`
- Design freeze: `oracle/docs/PHASE6_DA_DESIGN.md`
- Operator manual: `oracle/docs/PHASE6_RUNBOOK.md`
- Stress plan: `oracle/docs/PHASE6_STRESS_PLAN.md`
- Adversarial test runner: `devnet/test_phase6_da_attacks.py`
- Disclosure process: `SECURITY.md`
