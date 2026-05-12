# Sophis Wallet Verification (`.well-known/sophis-wallet.json`)

**Status:** v1, drafted 2026-05-09. Specification document for a
self-attestation file format that lets any operator publish a signed
binding between a public DNS domain and one or more Sophis addresses.

The file is **published by the operator** at
`https://<domain>/.well-known/sophis-wallet.json` over TLS. The
Sophis Project does not host, register, or curate any such file.
This document defines the format so wallets, explorers, and the
Green Miner Pledge community repo can verify domain↔address bindings
consistently.

---

## 1. Use cases

- An operator running a public-facing project (NGO, software
  collective, individual maintainer) wants users to verify that an
  address shown on their site corresponds to a key they actually
  control
- The Green Miner Pledge community repo wants to mark signatories
  whose wallets are independently verifiable
- A donation widget wants to confirm that a recipient address is
  bound to the domain it claims to come from

The file is **opt-in publication** by the operator and **opt-in
verification** by the consumer. There is no on-chain registry; the
binding lives at the operator's domain under their own control.

## 2. File location

```
https://<domain>/.well-known/sophis-wallet.json
```

The path follows IETF RFC 8615 (`.well-known` URI prefix). HTTPS is
required; verifiers MUST refuse to fetch the file over plain HTTP or
follow redirects from HTTPS to HTTP.

## 3. Format

The file is a JSON document with the following schema:

```json
{
  "version": 1,
  "domain": "example.org",
  "issued_at": "2026-05-09T12:00:00Z",
  "expires_at": "2027-05-09T12:00:00Z",
  "addresses": [
    {
      "address": "sophis:q...",
      "purpose": "donations",
      "label": "Project donation address",
      "categories": ["education"]
    }
  ],
  "signature": {
    "scheme": "ml-dsa-44",
    "public_key": "<base64-encoded Dilithium pubkey>",
    "value":      "<base64-encoded Dilithium signature>",
    "covers":     ["version", "domain", "issued_at", "expires_at", "addresses"]
  }
}
```

### 3.1 Field semantics

| Field | Required | Description |
|---|---|---|
| `version` | yes | Format version. Currently `1` |
| `domain` | yes | The hostname that hosts this file. MUST exactly match the host portion of the URL the verifier fetched |
| `issued_at` | yes | RFC 3339 timestamp at which the file was signed |
| `expires_at` | yes | RFC 3339 timestamp after which verifiers MUST treat the file as stale |
| `addresses[]` | yes (≥1) | List of Sophis addresses bound by this file |
| `addresses[].address` | yes | A `sophis:` / `sophistest:` / `sophisdev:` address |
| `addresses[].purpose` | yes | Free-form short string. Suggested values: `donations`, `mining-rewards`, `treasury`, `relayer-bond`, `signing-only` |
| `addresses[].label` | no | Human-readable label for UX |
| `addresses[].categories` | no | Array of free-form tags. **No project-curated enum** — operators self-categorize |
| `signature.scheme` | yes | MUST be `"ml-dsa-44"` for Sophis 1.x |
| `signature.public_key` | yes | Base64-encoded Dilithium ML-DSA-44 public key |
| `signature.value` | yes | Base64-encoded signature |
| `signature.covers` | yes | Ordered list of fields that were canonically serialized and signed |

### 3.2 No category enum (core team) — community vocabulary instead

The `categories` field on each address is **deliberately free-form at
the protocol and spec level**. The Sophis core team does not curate
a list of valid categories, and there is no on-chain enum (decision
documented in `project_h2_rejected.md`, memory). Operators choose
their own labels; downstream consumers (community repos, dashboards)
decide independently which labels they recognize.

This is a feature, not an oversight. A protocol-level category
registry would create curation pressure on the core team and would
require a hard-fork decision to add or remove categories. A
core-team-maintained off-chain list would create the same curation
pressure with the same political surface, just without the hard
fork. Both are avoided on purpose.

**Recommended vocabulary — community-maintained, not authoritative.**
To reduce label fragmentation ("environmental" vs "Environmental"
vs "env" vs "ecology") without reopening core-team curation, an
independent community repository — **`sophis-network/community-labels`**
— maintains a recommended vocabulary of category labels with an
explicit `others` fallback. The repo is:

- **Community-governed**, not core-team-curated. PRs to add or remove
  labels are reviewed by community maintainers with documented
  criteria. The core team does not adjudicate label disputes and
  does not have merge authority over that repo.
- **Off-chain and opt-in**. Operators may follow the recommended
  vocabulary or use any other label they prefer. Verifiers may
  recognize the recommended vocabulary, recognize their own subset,
  or ignore categories entirely.
- **Non-authoritative**. A label being on or off the recommended
  list carries no protocol-level meaning. Dashboards and wallets
  that present the recommended vocabulary should make clear that
  it is community guidance, not project endorsement of any
  particular address.

The split — protocol stays free-form, vocabulary lives in a separate
community-governed repo — preserves the regulatory posture of the
2026-05-04 pivot (core team does not curate semantic categories at
any level) while giving the ecosystem a Schelling point to converge
on without inventing dozens of synonyms.

## 4. Signature procedure

### 4.1 Canonical serialization for signing

The signature covers a canonical UTF-8 JSON serialization of the
fields named in `signature.covers`, with:

- Object keys sorted lexicographically
- No whitespace between tokens (no spaces, no newlines)
- Numbers serialized in their shortest unambiguous decimal form
- Strings serialized with minimal JSON escaping (no escaping of
  characters that need not be escaped)

Reference implementation: `serde_json` with the
`canonical-json`-style sorted-keys option, or any RFC 8785 (JCS)
implementation.

### 4.2 Signing key

The signing key MUST be a Dilithium ML-DSA-44 key. The corresponding
public key is published in `signature.public_key`. Verifiers MUST:

1. Decode the canonical bytes per §4.1
2. Verify the Dilithium signature in `signature.value` against the
   bytes using the public key in `signature.public_key`
3. Verify that at least one of the addresses in `addresses[]` is
   derivable from the public key (proves the signing key controls
   the published address — defends against an attacker publishing
   *someone else's* address with their own signing key)

Step 3 is the binding that prevents an attacker from claiming
arbitrary addresses on a domain they control. The convention is:
**the public key in `signature.public_key` MUST correspond to the
first address in `addresses[]`**.

### 4.3 TLS proof — the implicit second factor

The file is fetched over HTTPS. The verifier therefore implicitly
trusts:

- The domain's TLS certificate (proves the operator controls the
  domain's web infrastructure)
- The Dilithium signature (proves the operator controls the Sophis
  key)

The combination is the binding: "the entity that controls
`example.org` also controls this Sophis key, signed at this
timestamp". TLS alone is insufficient (anyone with web-server
control could publish anything); Dilithium alone is insufficient
(anyone could publish a signature without proving they control the
domain). Together, they bind.

## 5. Refresh and expiry

Verifiers MUST refuse files where `expires_at` is in the past
(beyond a small clock-skew tolerance, e.g. ±5 minutes).

Operators SHOULD republish at least 30 days before `expires_at`. A
recommended cadence is yearly (`issued_at` to `expires_at` ≈ 365
days), republished at ~9 months.

A revoked binding can be communicated by:
- Publishing a fresh file with `addresses[]` empty (signed,
  current timestamp)
- Or simply removing the file and waiting for cached copies to
  expire

There is no on-chain revocation list. This is consistent with the
"no protocol-level registry" posture.

## 6. Verifier responsibilities

A correctly implemented verifier MUST:

1. Fetch over HTTPS only; reject on HTTP or redirect to HTTP
2. Validate TLS certificate against the standard CA bundle
3. Parse JSON and validate schema (§3)
4. Validate `domain` matches the URL host (with `xn--` IDNA handling
   if applicable)
5. Validate `expires_at` is in the future (±5min skew)
6. Canonicalize the covered fields per §4.1
7. Verify the Dilithium signature
8. Verify the public key derives at least the first address in
   `addresses[]`
9. Surface the verified binding to the user along with the timestamp

A correctly implemented verifier SHOULD:

- Cache the validated file with a TTL no longer than `expires_at`
- Pin the public key on first observation and warn the user on key
  rotation (TOFU pattern)
- Display the `purpose` and `categories` fields verbatim — never
  filter or re-categorize

## 7. Integration with the Green Miner Pledge

The Green Miner Pledge community repo (`H5` template) recommends
signatories publish a `.well-known/sophis-wallet.json` at their
project domain. The repo's `signatories.md` then lists each entry
as:

```
- Example Project — example.org — verified ✓
```

Verification is performed by any independent party (a maintainer of
the community repo, a curious user, an automated CI job). The repo
itself does NOT operate a verification authority — it just provides
a place to list signatories who have followed the convention.

## 8. Anti-pattern: do not centralize

The wrong direction for this primitive is to build a central registry
where Sophis maps domains to addresses. The right direction is what
this document describes: **the file lives at the operator's own
domain**, the binding is verifiable peer-to-peer, and no third party
(including the Sophis Project) is required to mediate.

If you find yourself building a server that "indexes
`.well-known/sophis-wallet.json` files and serves them as an API",
stop and consider whether you are recreating the curation problem
the format was specifically designed to avoid.

## 9. Reference

- Template file: `docs/well-known-sophis-wallet.template.json`
- Recommended label vocabulary (community-maintained):
  `sophis-network/community-labels` — independent repo, not curated
  by the core team; consumed opt-in by dashboards and wallets that
  want a Schelling point for category names. See §3.2.
- Companion: `sophis-network/green-miner-pledge` — independent
  community-maintained repository listing miners who declare they use
  the reference miner's `--donate-to` flag; not maintained by the
  Sophis core team
- Related decision: `project_h2_rejected.md` (memory) — why no
  on-chain category registry
- Related decision: `project_ngo_curation_no_core_team.md` (memory)
  — why no curated NGO list
- Format references: RFC 8615 (`.well-known`), RFC 8785 (JCS)
