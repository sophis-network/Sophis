# Sophis — Founder succession plan

**Status:** v1, drafted 2026-05-06. Pre-mainnet canonical document.
This file is intentionally **public and templated**: it documents the
**procedure** for succession without leaking any of the secret
material. Sensitive data (private key locations, contact phone
numbers, exchange recovery codes) lives in a separate **private**
medium described in §3.

This is one of the six pre-mainnet mitigations the founder commits to
under the no-foundation posture (`project_no_entity_decision.md`,
`project_disengagement_strategy.md`). It exists to cover the case
where the founder is suddenly unable to continue (illness, death,
legal restriction, prolonged unavailability) so the project is not
silently abandoned with assets stranded.

The plan is designed with a single founder + zero pre-recruited
maintainers as the worst-case starting condition (current state at
v1). It tightens automatically as `MAINTAINERS.md` populates.

---

## 1. Scope of "founder assets"

The founder, as of v1, holds operational control of:

| Asset class | Examples (template only) |
|---|---|
| **Cryptographic keys** | Founder mining wallet (Dilithium, address `sophis:q2sdls98v...`), GitHub commit signing key, GPG identity, optional SSH keys for any infrastructure |
| **Domain registrations** | `sophis.org` (when registered), any other Sophis-aligned domains |
| **Hosting / infrastructure** | Bootstrap node VPS credentials, faucet host, block explorer host, DNS seeder operator credentials (when stood up) |
| **Trademark** | INPI Brazil application (when filed), USPTO US application (when filed) |
| **Repository control** | GitHub: `sophis-network/Sophis` admin role; canonical branches; release signing |
| **Communication channels** | Project email forwarder, any social handles representing Sophis officially |

The actual values — passwords, recovery codes, key file locations —
are **not** in this document. They are in the private succession
package described in §3.

## 2. Succession trigger conditions

The succession plan activates when **any** of the following holds:

- (T1) The founder publicly announces stepping down
- (T2) The founder is unreachable for 30 consecutive days through all
  declared channels (email, GitHub, primary phone)
- (T3) A competent court declares the founder legally incapacitated
- (T4) Death certificate is presented to the pre-designated contact
- (T5) The founder voluntarily activates the plan via the procedure
  in §4

Conditions T2 and T1 are reversible at the founder's discretion if
the founder reappears within the relevant timeline. Conditions T3
and T4 are not.

## 3. Private succession package

The founder maintains a sealed package containing:

1. A printed key inventory: which key controls which asset, which
   wallet contains which funds, which password unlocks which
   secret-management vault
2. The master passphrase to a password manager (or a separate set of
   per-asset recovery codes if no password manager is used)
3. Step-by-step instructions for the pre-designated contact to
   execute §4
4. Contact information for any third parties who may need to be
   notified (registrar customer service, hosting provider, GitHub
   support, etc.)

The package is stored **physically**, in two copies, in two separate
secure locations (one at the founder's residence, one with a
pre-designated contact). The founder reviews and updates the package
**annually** and after any material change in holdings or
infrastructure.

The package does **NOT** live on a cloud service, in plaintext on
disk, or in any digital form accessible without physical possession.

## 4. Pre-designated contact

The pre-designated contact is a person (not a legal entity, not a
company) who has agreed in advance to act as **custodian of the
disengagement** if §2 conditions activate.

| Field | Value (template; private detail in the §3 package) |
|---|---|
| Name | (filled in §3 package; not public) |
| Relationship to founder | (e.g., immediate family, long-term collaborator) |
| Has agreed to role | yes (signed and dated, archived in §3) |
| Last review date | (annual; recorded in §3) |

The pre-designated contact is **NOT** a successor founder. They are a
custodian whose only duties are:

- (a) Take possession of the §3 package
- (b) Execute the procedure in §5 to hand off control to the
  maintainer collective (or, if none yet exists, to the most-recently
  named contributor in `MAINTAINERS.md`)
- (c) Cease founder mining (auto-triggered by the founder address
  going inactive; the contact does not need to mine)
- (d) Publicly announce activation via the channels listed in the §3
  package

The contact does NOT acquire founder mining proceeds, take over
trademark stewardship, or assume governance role. They are a one-shot
relay.

## 5. Hand-off procedure

Once §2 conditions activate and the pre-designated contact opens the
§3 package:

### 5.1 Within 7 days

- Public announcement on `sophis-network/Sophis` repository (issue + pinned
  README banner) noting succession activation. Statement template is
  in the §3 package.
- All `sophis-miner` instances at the founder address are stopped.
  The cap monitoring script (`scripts/cap_5pct_monitor.py`) is
  configured to log this state explicitly.

### 5.2 Within 30 days

- Trademark and domain stewardship is transferred:
  - If `MAINTAINERS.md` lists ≥2 active maintainers: stewardship
    transfers to that collective, governed by majority decision among
    them.
  - If `MAINTAINERS.md` lists 1 maintainer: stewardship transfers to
    them as steward (same role the founder had), not owner.
  - If `MAINTAINERS.md` is empty: a public call for stewardship is
    posted; the contact holds passive custody for up to 6 months
    waiting for volunteers; if none appear, domains are allowed to
    expire and trademark applications are abandoned.
- GitHub admin role on `sophis-network/Sophis` is transferred to the same
  collective / individual.

### 5.3 Within 90 days

- Founder personal SPHS holdings (founder mining proceeds, capped per
  `FOUNDER_SELF_RESTRICTION.md`) are managed per the founder's
  pre-existing instructions in the §3 package. Default behavior:
  holdings remain in the founder's address; the pre-designated
  contact's only role with respect to private funds is per the
  founder's separate civil estate plan, NOT this succession document.
- Annual disclosures from `FOUNDER_SELF_RESTRICTION.md §7` cease;
  succession activation date is recorded.

### 5.4 Indefinite

- This `SUCCESSION.md` document is updated by whoever now stewards
  the project, replacing "founder" with the current steward set, and
  the pre-designated contact relationship is re-established with a
  new person.

## 6. What this plan does NOT do

- It does not transfer founder personal funds outside the
  `FOUNDER_SELF_RESTRICTION.md` mining cap to anyone. Civil estate /
  inheritance is a separate matter handled outside this document.
- It does not create a successor "founder" role. The project becomes
  community-led; no one inherits the founder identity.
- It does not provide legal authority for anyone to bind the Sophis
  Project to commitments. The Sophis Project has no legal entity to
  bind (`project_no_entity_decision.md`).
- It does not commit any specific person to operating infrastructure.
  The faucet, explorer, and seeders may go offline if no one
  volunteers to host them.

## 7. Maintenance

This document is reviewed:

- **Annually**, on the founder's birthday or another fixed date
- After any change in the §3 package contents
- After any change in `MAINTAINERS.md` (new maintainer added or
  removed)
- After any material change in operational infrastructure (new VPS,
  new domain, new repository, new social account)

Each review increments a version footer at the bottom and is committed
to the canonical repository.

## 8. Reference

- Disengagement plan: `project_disengagement_strategy.md` (memory)
- No-entity decision: `project_no_entity_decision.md` (memory)
- Founder restrictions: `FOUNDER_SELF_RESTRICTION.md`
- Maintainer list: `MAINTAINERS.md`
- Cap monitoring: `scripts/cap_5pct_monitor.py`

---

**Document version:** v1, 2026-05-06
**Next scheduled review:** 2027-05-06
**Reviewed by:** founder (`sophis-network`)
