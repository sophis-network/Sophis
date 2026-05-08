# Sophis Phase 6 — pre-mainnet bug bounty

The Sophis core team is offering a **30-day pre-mainnet bug bounty** on
the Phase 6 Data Availability layer. The window opens with the public
RFC announcement (see `PHASE6_RFC.md`) and closes 30 calendar days
later. Findings inside the window pay; findings outside the window are
acknowledged in `PHASE6_AUDIT.md` §5.4 but do not pay.

**Status:** v1, drafted at sub-fase 6.9 (2026-05-06). Not active until
the founder publishes the start-of-window announcement. The reward
amounts are placeholders pending the founder's discretionary budget
decision (no on-chain treasury, see `project_no_entity_decision.md`).

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

Findings in these areas DO NOT qualify for a bounty payment but ARE
welcomed as `PHASE6_AUDIT.md §5.2` notes:

- **Cryptographic assumptions of SHA3-384 / Dilithium ML-DSA-44 /
  RandomX** — these are inherited from the L1 and from NIST-standard
  primitives. A new attack on them would qualify for a separate L1
  bounty, not this Phase 6 one.
- **Stubbed gRPC / wRPC clients returning `NotImplemented`** — that is
  the documented v1 behavior (sub-fase 6.4.b/c deferred). Bug bounty
  expects functional Rust trait calls to work.
- **`current_blue_score = 0`** — documented limitation, not a bug. See
  `PHASE6_AUDIT.md §4`. A 6.5.b commit will plumb the real value;
  reports that the conservative-zero behavior produces "false negatives"
  for confirmation counts are expected.
- **Performance regressions** — covered by the 72h stress run, not the
  bounty.
- **Issues outside `oracle/docs/PHASE6_*` and the Phase 6 code paths
  listed in §1** — out of bounty scope (file separately if relevant).

## 3. What counts as a finding

A bug-bounty-eligible finding must demonstrate one of:

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
  trust boundary is "honest local storage." Findings that require
  manual DB corruption do not pay.
- "I forked the chain on my devnet" — fork attacks against an isolated
  devnet do not transfer to mainnet without separate WAN-scale
  reproduction.
- "I built a contract that always returns false from
  `sophis_verify_da` and that broke my dapp" — that is the documented
  StubDa fallback for tests / lite builds.
- Unit-test corner cases without a meaningful exploit narrative.

## 5. Reward schedule

(Placeholder — final amounts confirmed at the start-of-window
announcement.)

| Severity | Criteria | Reward (placeholder) |
|---|---|---|
| Critical | Consensus break OR determinism break OR capability bypass that lets a malicious contract steal funds | $5,000 USD-equivalent (paid in SPHS at mainnet day-zero rate) |
| High | Reachable panic from attacker-controlled input; DOS materially below the mass formula | $1,500 |
| Medium | Indexation corruption that requires DB rebuild; cross-domain confusion | $500 |
| Low | Spec / doc inconsistencies that could lead to misuse but have no direct exploit | $100 |
| Info | Style / nit / unsafe-but-untriggerable code patterns | acknowledgment in `PHASE6_AUDIT.md §5.2` |

Funding is from the founder's pre-genesis discretionary budget. The
core team has **no on-chain treasury** by policy
(`project_no_entity_decision.md`); payouts are therefore capped by
that budget and made manually after each acknowledged finding.

## 6. How to report

- Email: `<founder-public-key>` (Dilithium-signed report preferred)
- GitHub Security Advisory on the Sophis repo (when the repo goes
  public)
- DO NOT open a public GitHub issue with consensus-impact details;
  use the private channel until a fix is committed and released.

A report should include:

1. The finding class from §3
2. A reproducer (Rust test, Python script, or step-by-step description)
3. The branch + commit you tested against (latest `phase6-DALayer`
   commit at submission time)
4. Suggested mitigation, if any

## 7. Disclosure timeline

- T+0 (report received): acknowledgment within 72h
- T+72h: severity triage published privately to the reporter
- T+30d (max): fix or mitigation committed, public disclosure on
  the Sophis repo + entry in `PHASE6_AUDIT.md §5.2`
- T+90d (max): payout (if applicable) settled

If the founder is unable to triage within 72h, the timeline pauses
until acknowledgment. Critical findings open the next-day-touchable
escalation channel (founder personal email, off-system).

## 8. What this bounty is NOT

- **Not insurance against a v1 mainnet bug.** Bug bounty is a
  best-effort review program, not a guarantee.
- **Not a standing program.** It runs for 30 days pre-mainnet only.
  Post-mainnet, finding reports are still appreciated and may pay at
  the founder's discretion, but there is no committed window or
  reward schedule.
- **Not a substitute for a paid third-party audit.** The Sophis team
  has no audit budget for v1; this bounty + the DIY methodology in
  `PHASE6_AUDIT.md` is the maximum operator-reasonable due-diligence
  the team can deliver under the no-foundation posture. The trade-off
  is explicit.

## 9. Reference

- DIY audit playbook: `oracle/docs/PHASE6_AUDIT.md`
- Public RFC: `oracle/docs/PHASE6_RFC.md`
- Design freeze: `oracle/docs/PHASE6_DA_DESIGN.md`
- Operator manual: `oracle/docs/PHASE6_RUNBOOK.md`
- Stress plan: `oracle/docs/PHASE6_STRESS_PLAN.md`
- Adversarial test runner: `devnet/test_phase6_da_attacks.py`
