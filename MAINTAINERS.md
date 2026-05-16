# Sophis Maintainers

This file lists the **current active maintainers** of the Sophis
reference implementation. It is updated as people join or leave the
maintainer set. Each entry is a personal commitment by the named
individual, not a corporate role.

The maintainer list interacts with two other documents:

- `FOUNDER_SELF_RESTRICTION.md` § 4: trademark + domain transition to
  a maintainer collective is gated by ≥ 2 active maintainers
- `SUCCESSION.md` § 5.2: in succession activation, stewardship
  transfers to whoever appears on this list at that moment

---

## 1. Active maintainers

| Name / handle | Role | Since | Commit access | Public key (GPG fingerprint) |
|---|---|---|---|---|
| Marcelo Delgado (`sophis-network`) | Founder, lead maintainer | 2024 | yes | `5D8F DABF 2394 1210 3CFB  69DD 9EBC FF7D A279 7E07` |

(The list intentionally has only one entry at v1. The founder is
actively recruiting per the `Year 1–2` step of
`OPERATIONAL_BOUNDARIES.md` § 4.1.)

## 2. Emeritus maintainers

(empty)

Maintainers who have stepped down move here. Emeritus status is a
recognition of past contribution; it does not confer commit access or
governance.

## 3. How to become a maintainer

Maintainership is by **invitation from the existing maintainer set**,
based on demonstrated technical contribution and community trust.
There is no application form, no pay, no token grant.

A typical path:

1. Submit non-trivial, well-reasoned PRs over a sustained period
   (months, not weeks). Quality > quantity.
2. Participate in code reviews; respond thoughtfully to other PRs.
3. Engage in design discussions on issues / RFCs in a way that shows
   understanding of the project's invariants
   (`MONETARY_POLICY.md`, `OPERATIONAL_BOUNDARIES.md`,
   `project_legal_positioning.md` non-negotiables).
4. After a track record of (1)–(3), an existing maintainer may invite
   you to become one. The invitation is private (e-mail or DM).
5. If you accept: your handle is added to §1, you generate a GPG key
   if you don't already have one, the existing maintainers add you
   to the GitHub repo's maintainers team, and you commit-sign all
   future contributions.

## 4. What maintainers do

- Review and merge PRs against `sophis-network/Sophis`
- Triage issues
- Make release decisions (which commits cut a release, when)
- Respond to security advisories within agreed-upon time
- Steward the trademark and domain after the founder transition
  (per `FOUNDER_SELF_RESTRICTION.md` § 5)

Maintainers do **not**:

- Promise specific roadmap items by specific dates
- Speak for the Sophis Project on legal matters
- Custody user funds in any form
- Operate exchanges, pools, or bridges as part of the role

## 5. What maintainers do not get

- Salary or token grant from the protocol — there is no on-chain
  treasury (`MONETARY_POLICY.md` § 3)
- A coinbase split — the consensus rule is 100% to miner
  (`MONETARY_POLICY.md` § 2)
- Equity in any "Sophis entity" — there is no such entity by policy
  (`project_no_entity_decision.md`)

Independent employment and personal mining within the personal cap are
permitted as long as they do not create a conflict of interest with the
project non-negotiables.

## 6. Reference

- Founder restrictions: `FOUNDER_SELF_RESTRICTION.md`
- Operational boundaries: `OPERATIONAL_BOUNDARIES.md`
- Succession: `SUCCESSION.md`
- Disengagement plan: `project_disengagement_strategy.md` (memory)
- DCO / contribution policy: `CONTRIBUTING.md`
- License: `LICENSE` (Apache 2.0) and `NOTICE`

---

**Document version:** v1, 2026-05-06
**Last updated:** 2026-05-06
