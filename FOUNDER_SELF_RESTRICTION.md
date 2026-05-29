# Sophis Founder Self-Restriction Statement

**Status:** v1, drafted 2026-05-06. Pre-mainnet canonical document.
SHA-256 of this file is to be published with the T-72h mainnet
announcement so the commitments below are locked to a verifiable
timestamp prior to the chain itself.

This is the founder's **public, lifetime, irrevocable** statement on
how they will participate in the Sophis network as a miner and as a
project lead. It is binding to the founder personally; it is not a
protocol rule and not a property of any legal entity. The Sophis
Project has no legal entity bound to its name — see § 5 of
`OPERATIONAL_BOUNDARIES.md`.

---

## 1. Identification

| Field | Value |
|---|---|
| Founder mining address (single, lifetime) | `sophis:q2sdls98vf40p3v53eyu2ylu3rnfyvjr3cw3gwmuhj8pwnkkgdn5677h7448r` |
| GitHub identity | `sophis-network` |
| Public name | Marcelo Delgado |
| Mainnet T-0 timestamp | (filled in at announcement) |
| Statement publication time | (filled in at announcement, ≥72h before T-0) |

The founder commits not to mine SPHS to any other address. If the
private key for the address above is lost or compromised, the founder
will publicly announce the cessation of personal mining and **will
not** declare a replacement address. The cap is cumulative across the
founder's lifetime, not address-bounded.

## 2. Mining restrictions

### 2.1 24-hour restraint window

Founder mining begins **24 hours after** the genesis block. During the
first 24 hours of the network, the founder mines zero blocks. This is
not a protocol rule — any other participant may mine immediately. It
is a personal commitment that:

- Other miners have a 24-hour head start, in which the founder is
  demonstrably absent
- The founder's first block is on-chain auditable as ≥24h post-genesis
- Five defensive actions during this window (see `LAUNCH_CHECKLIST.md`)
  produce contemporaneous evidence rather than retroactive narrative

### 2.2 5% lifetime cap

Founder mining ceases when **either** of the following holds:

- (a) the balance held at the founder mining address (§1) reaches **5%
  of the total emitted SPHS supply at that moment**, OR
- (b) the founder publicly announces voluntary cessation of mining,
  whichever comes first.

After cessation, the founder:

- Operates no mining nodes, full or pool
- Owns no mining operation, jointly or otherwise
- Accepts no payment-in-kind for non-mining work that would re-route
  block rewards to the founder under another name

### 2.3 Auto-pause at 4.9%

The Sophis Project ships a public watchdog binary,
`tools/sophis-cap-monitor`, that tracks the ratio

```
ratio_bps = high_water_mark(balance(founder_address)) * 10000 /
            circulating_sompi
```

and **auto-pauses** the founder's `sophis-miner` process when the
ratio crosses 4.9% (490 basis points). The 0.1% margin below the 5%
cap absorbs block-acceptance race conditions and brief settling
periods around the tip.

The denominator is `circulating_sompi` (issued minus burned), which
is strictly more conservative than total issued: if anyone burns,
the denominator shrinks and the watchdog trips earlier rather than
later. The numerator is a **monotone high-water-mark** of the
address balance, persisted to a JSON state file with atomic writes,
so that spending from the address does not lower the effective cap.

Once paused, the paused state is **terminal**. The founder must
consciously delete the watchdog's state file to resume mining — there
is no automatic resume even if the denominator (circulating supply)
later grows past the threshold. A conscious override is on-record by
definition.

The watchdog binary is part of the public release and identical for
everyone. Operators (regulators, journalists, anyone) may run it in
`--dry-run` mode against any Sophis full node started with
`--utxoindex` and verify the ratio in real time without any privileged
access. Two independent runs against two independent nodes should
produce identical `hwm_sompi` and `last_ratio_bps` (modulo short-term
tip divergence), and either can be diffed against the founder's
published state file.

### 2.4 Address change is forbidden

The founder commits **never** to declare a second mining address. Any
attempt to "reset" the cap by mining to a fresh address would be a
violation of this statement and a public breach of trust. The cap is
cumulative against the founder personally, not against any specific
key.

## 3. Sale of SPHS

### 3.1 First-year freeze

The founder commits to selling **zero SPHS during the first 12 months**
post-genesis. This includes:

- No sales on any centralized exchange
- No OTC sales
- No collateralization that creates a synthetic short position
- No transfer to a third party who would sell on the founder's behalf

### 3.2 Post-month-12 sale rules

After month 12, any sale follows these rules:

- A sale schedule is **publicly announced before any sale begins**.
  The schedule is linear (constant amount per period) over a duration
  the founder discloses at announcement. The founder may not deviate
  from the schedule in a way that increases per-period sales.
- Each sale is documented with the on-chain transaction hash and
  reported within 7 days on a public ledger maintained by the founder.
- No single sale exceeds 1% of the past-30-day trading volume of the
  venue used.
- No sales occur during the 30 days following any major Sophis
  announcement (release, RFC publication, security advisory, etc.).

These rules implement a linear, publicly-disclosed disengagement
schedule. They do not preclude the founder from a stricter posture
(for example: selling nothing, indefinitely) — only from deviating
from a publicly-disclosed schedule without re-announcing it first.

## 4. Governance restrictions

### 4.1 Public-only decisions

The founder commits to **no private channels with miners, validators,
maintainers, exchanges, or investors** that influence Sophis-relevant
decisions. All technical decisions go through public GitHub PRs and
issues. The founder does not provide private advisory.

### 4.2 No Sophis-branded entity

The founder will not establish a foundation, LLC, MEI/CNPJ, Cayman
vehicle, or any other legal entity whose name, branding, or legal
personality is bound to "Sophis". Personal MEI / CNPJ for unrelated
freelance work remain permissible; the binding constraint is "no
entity tied to the project's name".

This constraint is permanent. A future maintainer collective (§5) may
choose differently for itself, at which point the project's identity
will follow that collective, not the founder.

### 4.3 No silent control

The founder commits not to retain hidden authority after public
disengagement. Specifically: after the steward-to-collective
trademark transfer (§5), the founder relinquishes:

- Domain registrar control (`sophis.org` and any other Sophis domains)
- DNS seeders' DNSSEC keys (transferred to maintainer collective)
- Any GitHub organization-admin role
- Any ability to merge to `main` on the canonical repo

## 5. Trademark and domain stewardship

The "Sophis" trademark (INPI BR + USPTO US) and the `sophis.org`
domain are held by the founder **as steward, not owner**. They will be
transferred to a maintainer collective within **36 months of mainnet
genesis**, or earlier upon the founder's choice or upon §6 cessation.

No revenue (royalty, licensing fee, etc.) is extracted from these
assets while in the founder's stewardship. Trademark registration
costs (R$ 350 INPI + ~US$ 250-750 USPTO) are paid out-of-pocket and
documented in `SUCCESSION.md`.

## 6. Cessation and emergency policies

### 6.1 Voluntary cessation

The founder may, at any time, publicly announce cessation of personal
mining and project stewardship. This triggers:

- Immediate stop of `sophis-miner` at the founder's address
- Public announcement on `sophis-network/Sophis` GitHub
- Acceleration of the §5 trademark/domain transfer to whatever
  maintainer collective exists at that moment, or to the most-recent
  named maintainer in `MAINTAINERS.md` if no collective is established

### 6.2 Incapacity

If the founder becomes incapable of executing this statement (illness,
death, legal restriction), the procedures in `SUCCESSION.md` activate.
A pre-designated contact (named in `SUCCESSION.md` and updated
annually) takes possession of the keys, domains, and trademark
custody, and follows the same lifetime cap on the founder address.
The pre-designated contact does not become a "new founder"; they
become a custodian of the disengagement.

## 7. Disclosures

The founder commits to publishing, annually:

- A holdings report listing the balance at the founder address
- A sales report (post month 12) listing every transaction hash
- A list of any current involvements with Sophis-adjacent businesses
  (none expected; documented if any arise)

## 8. Verification

Anyone may verify § 2 (mining + cap) at any time by running the
public watchdog binary in `--dry-run` mode against any Sophis full
node started with `--utxoindex`:

```bash
sophis-cap-monitor \
  --address "sophis:q2sdls98vf40p3v53eyu2ylu3rnfyvjr3cw3gwmuhj8pwnkkgdn5677h7448r" \
  --rpc-server "127.0.0.1:46110" \
  --state-file ./verify-cap-state.json \
  --interval-secs 3600 \
  --dry-run
```

`--dry-run` suppresses the kill action — the binary only logs and
updates its own state file. The state file is plain JSON and shows
the observed high-water-mark, the current `ratio_bps`, and whether
the watchdog has tripped. Auditors do not need the founder's
permission to run it; the binary is identical for everyone, and the
source is in `tools/sophis-cap-monitor/` on `sophis-network/Sophis`.

## 9. Footing

This statement is the founder's voluntary, public, and lifetime
commitment. It is not a contract with anyone; the legal structure
requires neither offer nor acceptance. It is a published constraint
which any party (regulator, miner, journalist, holder) may rely on.

The founder accepts that **any deviation from this statement** is a
public breach of stated commitment, will be visible on-chain (for
mining), and is a basis for the community to cease cooperation with
the founder personally and proceed with maintainer collective
formation under whatever process the community chooses.

## 10. Reference

- Public address: declared in § 1 above and re-stated in
  `MONETARY_POLICY.md` § 4
- Cap-monitoring watchdog: `tools/sophis-cap-monitor/` (Rust binary,
  ships with every release; usage in `tools/sophis-cap-monitor/README.md`)
- Sister documents: `MONETARY_POLICY.md`, `OPERATIONAL_BOUNDARIES.md`,
  `HARD_FORK_POLICY.md`, `SUCCESSION.md`, `LAUNCH_CHECKLIST.md`
