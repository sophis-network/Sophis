# Sophis Operational Boundaries Statement

**Status:** v1, drafted 2026-05-06. Pre-mainnet canonical document.
SHA-256 of this file is to be published with the T-72h mainnet
announcement.

This statement defines, in binding language, what the **Sophis Project**
(the unincorporated group of contributors maintaining the reference
implementation) does and does not do. It is the operational counterpart
to `MONETARY_POLICY.md` (what SPHS is) and `FOUNDER_SELF_RESTRICTION.md`
(what the founder does and does not do).

---

## 1. Canonical positioning

> Sophis is a permissionless utility blockchain protocol distributed
> under Apache 2.0. There is no ICO, no foundation, no founder premine,
> and no custodial component. The reference implementation is
> open-source software. Use of the protocol is the responsibility of
> operators.

This single sentence is the core of the project's external posture. It
is to be reproduced verbatim in any communication that requires a
one-line description of Sophis's legal character.

## 2. Non-custodial declaration

The Sophis Project:

- **Does not operate, does not act as an intermediary, does not act as
  a custodian, and does not administer third-party funds** in any
  form.
- Does not operate a mining pool, an exchange, a custody service, a
  bridge, or any tool that processes SPHS transfers on behalf of other
  users.
- Holds no SPHS in any address it controls beyond the founder's
  personal mining proceeds (capped per `FOUNDER_SELF_RESTRICTION.md`).

Services built **by third parties** on Sophis are the exclusive
responsibility of those operators and must comply with the regulatory
requirements applicable in their respective jurisdictions. The Sophis
Project does not endorse, audit, or take responsibility for
third-party services.

## 3. Service-by-service boundaries

| Service | Status | Constraints |
|---|---|---|
| **Faucet** | Maintained | ≤ 0.1 SPHS per drip, captcha, 1/24h per IP, no KYC, funded as personal donation by the founder, monthly budget published |
| **Block explorer** | Maintained | View-only — no broadcasting via the interface, no personal-data collection, no per-address labeling |
| **DNS seeders** | Maintained and expanded | Domains TBD; aiming to recruit 2–3 independent operators before mainnet |
| **`sophis-stratum-bridge`** | Code maintained, no instance operated | README explicit: "local-only use" |
| **Mining pool** | NOT OPERATED | Sophis Project commits never to run a centralized pool. Community is free to use P2Pool / Stratum V2 / independent third parties |
| **Bridge / wrapped SPHS / cross-chain** | NOT OPERATED | Cross-chain interoperability is intentionally out-of-scope for the core team. ZKBridge prototype was extracted to a separate non-deploy reference repository in 2026-05-04. Third parties may build bridges at their own risk; the project endorses none |
| **Exchange / custody / OTC desk** | NOT OPERATED | Anyone wanting to buy SPHS uses third-party venues |
| **Stablecoin issuance** | NOT OPERATED | Out of scope for Sophis Project |

The faucet, explorer, and seeders are **infrastructure of last resort**:
each of them follows the Bitcoin Core / Monero Project precedent of
hosting public goods that any individual operator could host instead.
The team commits that these are operated as **public service**, not as
a customer-facing business.

## 4. The 5 founder pre-commitments

These are personal commitments of the founder. Each is binding on the
founder personally and irrevocable as a public statement. They are
included here (rather than only in `FOUNDER_SELF_RESTRICTION.md`) so a
single document captures the entire pre-launch posture.

### 4.1 Transition timeline

```
Year 0–1:  Founder is sole maintainer with commit access.
Year 1–2:  2–3 additional maintainers recruited; commit access shared.
Year 2–3:  Founder transitions to "regular contributor" status.
Year 3+:   Maintainer collective owns trademark, domain, governance.
```

### 4.2 Sale policy

The founder commits to:

- Selling no SPHS during the first **12 months** post-genesis
- After month 12, sales follow a publicly-announced **linear schedule**
- Each sale is documented with the on-chain transaction hash
- No sale exceeds **1% of the past-30-day trading volume** of any
  single venue
- No sales during 30 days following any major Sophis announcement

### 4.3 Mining policy

```
Founder mining begins 24h post-genesis. Founder mining ceases when
(a) lifetime mined SPHS reaches 5% of supply, OR (b) the founder
publicly announces voluntary cessation, whichever first. After
cessation, the founder operates no mining nodes, owns no mining
operation, and accepts no payment-in-kind for non-mining work that
would route block rewards to the founder under another name.
```

### 4.4 Trademark and domain stewardship

```
The "Sophis" trademark and the sophis.org domain are held by the
founder as steward, not owner. They will be transferred to a
maintainer collective within 36 months of mainnet genesis, or
earlier upon founder's choice. No revenue is extracted from these
assets.
```

### 4.5 Anti-silent-control

```
The founder maintains no private channels with miners, validators,
or maintainers. All technical decisions go through public GitHub
PRs and issues. The founder does not provide private advisory to
specific actors, exchanges, or investors.
```

## 5. Hard-fork commitments

The Sophis Project commits not to propose, support, or implement a
hard fork that:

- Reintroduces a developer fund / coinbase split / treasury
- Backdates a premine to any party (including the founder)
- Reduces the total supply cap of 210,000,000 SPHS
- Removes the Apache 2.0 license or relicenses to source-available
  or proprietary terms
- Introduces native privacy primitives (FHE, on-chain mixers, ring
  signatures, blinded zk-SNARKs)
- Establishes an official cross-chain bridge in the protocol layer
- Creates a foundation / legal entity bound to the project's name

## 6. Donation flag — opt-in only

The reference miner (`sophis-miner`) ships with an **opt-in
`--donate-percent` flag** for client-side coinbase splits to addresses
chosen by the operator (commit `e54fcd9`, sub-fase 6.6 ABI).

> The reference miner ships with an opt-in `--donate-percent` flag for
> client-side coinbase splits to addresses chosen by the operator. The
> core team does not curate, host, or recommend any donation address
> list, and the default behavior is **OFF** (100% of the coinbase
> reward goes to the miner).

This is the canonical wording. Any third party hosting a list of
donation addresses does so independently; the Sophis Project does not
endorse such lists.

## 7. Defense against third-party-operator liability

If a third party operates a pool, bridge, exchange, or custodial
service using Sophis software and is the subject of a regulatory
action, the Sophis Project's defense rests on:

- This statement, hashed and pre-published before mainnet
- The absence of promotion or endorsement of the third party
- The Apache 2.0 license, which makes the software a tool with no
  reserved rights to the publisher and includes an explicit
  patent-retaliation clause
- The precedent set by the Bitcoin Core / Monero Project lines of
  cases — 15 years, zero criminal prosecutions of upstream protocol
  developers (see `project_legal_positioning.md`)

The Sophis Project does not represent third-party operators in legal
proceedings, does not provide legal advice to them, and does not
indemnify them.

## 8. Reference

- Disengagement plan: `project_disengagement_strategy.md` (memory)
- Donation flag spec: `project_miner_donate_flag.md` (memory)
- Legal posture: `project_legal_positioning.md` (memory)
- Sister documents: `MONETARY_POLICY.md`, `FOUNDER_SELF_RESTRICTION.md`,
  `SUCCESSION.md`, `LAUNCH_CHECKLIST.md`
