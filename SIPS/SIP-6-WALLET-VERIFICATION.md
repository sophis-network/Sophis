```
SIP: 6
Title: Domain-to-Wallet Self-Attestation (`.well-known/sophis-wallet.json`)
Author: Marcelo Delgado <sophis-network@proton.me>
Status: Draft
Type: Standards
Created: 2026-05-09
```

# SIP-6: Domain-to-Wallet Self-Attestation (`.well-known/sophis-wallet.json`)

## 1. Abstract

This SIP defines a JSON file format and verification procedure that allows any operator of a public DNS domain to **self-attest** a binding between their domain and one or more Sophis wallet addresses, by placing a Dilithium-signed file at a well-known URL on their domain. Verifiers fetch the file over HTTPS, validate the TLS certificate (proving control of the domain), and verify the Dilithium signature (proving control of the signing key for the declared address). The combination produces a cryptographically auditable binding without requiring any on-chain registry or central party.

## 2. Motivation

Sophis is transparent-by-design at the protocol layer: every address is a bech32 string with no inherent link to a real-world organization. A donor or counterparty who sees an address claim ("send to `sophis:q…` to support our NGO") has no way to verify that the address actually belongs to the organization presenting it.

Three classes of users need this verification:

1. **Donors** wanting to confirm that a donation address shown on an organization's website belongs to a key the organization actually controls (and not an attacker who replaced the address via XSS or domain compromise).
2. **Community catalogues** like `sophis-network/green-miner-pledge` and `sophis-network/donation-dashboard` that surface lists of recipient addresses and want to mark which entries are domain-verifiable.
3. **Wallets and explorers** that want to render addresses with a "verified ✓ via example.org" indicator next to the bech32 string.

Three structural constraints rule out alternative designs:

- **No on-chain registry.** Sophis explicitly rejects on-chain category/identity registries (see `project_h2_rejected.md`); the cost of curation pressure on the core team is greater than the UX benefit.
- **No core-team-operated central directory.** The `OPERATIONAL_BOUNDARIES.md` posture prohibits the Sophis project from operating "approved address" lists.
- **No trust in third-party identity providers.** Sophis ships PQC-only at consensus; tying identity to OAuth, Google Sign-In, WebAuthn, or any pre-quantum primitive would undermine the chain's PQC posture.

The solution is to use what already exists in every operator's hands: a domain they control + HTTPS + Dilithium signing. Each operator publishes their own file; nobody else mediates.

This is the IETF RFC 8615 `.well-known/` URI pattern, already used by ACME, OpenID Connect, security.txt, host-meta, and dozens of other standards. It is the canonical way to attach metadata to a domain.

## 3. Specification

### 3.1 File location

The file MUST be served at exactly:

```
https://<domain>/.well-known/sophis-wallet.json
```

The path follows IETF RFC 8615 (`.well-known` URI prefix). The transport MUST be HTTPS. Verifiers MUST refuse to fetch over plain HTTP and MUST NOT follow HTTPS→HTTP redirects.

### 3.2 File format

The file is a JSON document. The canonical v1 schema is:

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

### 3.3 Field semantics

| Field | Required | Description |
|---|---|---|
| `version` | yes | Format version. Currently `1`. Future versions advance to `2`, `3`, etc.; verifiers MUST refuse unknown major versions |
| `domain` | yes | The hostname that hosts this file. MUST exactly match the host portion of the URL the verifier fetched. IDNA `xn--` form is supported when handled per RFC 5890 |
| `issued_at` | yes | RFC 3339 timestamp at which the file was signed |
| `expires_at` | yes | RFC 3339 timestamp after which verifiers MUST treat the file as stale |
| `addresses[]` | yes (≥1) | List of Sophis addresses bound by this file |
| `addresses[].address` | yes | A `sophis:` / `sophistest:` / `sophisdev:` / `sophissim:` address |
| `addresses[].purpose` | yes | Free-form short string. Suggested values: `donations`, `mining-rewards`, `treasury`, `relayer-bond`, `signing-only` |
| `addresses[].label` | no | Human-readable label for UX |
| `addresses[].categories` | no | Array of free-form tags. **No project-curated enum** — operators self-categorize (see §4.2) |
| `signature.scheme` | yes | MUST be `"ml-dsa-44"` for Sophis 1.x |
| `signature.public_key` | yes | Base64-encoded Dilithium ML-DSA-44 public key (1312 bytes raw, ≈ 1752 bytes base64) |
| `signature.value` | yes | Base64-encoded signature (2420 bytes raw, ≈ 3228 bytes base64) |
| `signature.covers` | yes | Ordered list of fields that were canonically serialized and signed |

### 3.4 Canonical serialization for signing

The signature covers a canonical UTF-8 JSON serialization of the fields named in `signature.covers`, computed as follows:

1. Construct a JSON object containing only the fields listed in `signature.covers`, in the order they appear in that list.
2. Serialize the object using **JSON Canonicalization Scheme (JCS) per RFC 8785**:
   - Object keys sorted lexicographically (by Unicode code-point order)
   - No whitespace between tokens
   - Numbers in shortest unambiguous decimal form
   - Strings with minimal JSON escaping (only the characters that MUST be escaped per RFC 8259)
3. The resulting bytes are the input to the Dilithium signing operation.

Reference implementation: any RFC 8785 implementation. The Rust ecosystem currently has `serde_jcs`; verifiers MUST cross-check against the test vectors in §8.

### 3.5 Signing key derivation

The signing key MUST be a Dilithium ML-DSA-44 key. The corresponding public key is published verbatim in `signature.public_key`. Verifiers MUST perform three checks:

1. **Signature validity.** Decode the canonical bytes per §3.4, decode `signature.value` from base64, decode `signature.public_key` from base64, and verify the Dilithium signature.
2. **Key-to-address binding.** Verify that the **first address** in `addresses[]` is derivable from `signature.public_key` using the standard Sophis address derivation (`bech32(network, ScriptHash(Blake2b(pubkey)))`).
3. **Domain match.** Verify that `domain` exactly matches the host portion of the URL the file was fetched from.

Step 2 is the binding that prevents an attacker from claiming arbitrary addresses on a domain they happen to control. If the first address does not derive from the published public key, the file is invalid regardless of signature validity.

### 3.6 Verifier procedure

A correctly implemented verifier MUST perform the following steps in order:

1. Fetch the URL over HTTPS only; reject on plain HTTP or any HTTP redirect.
2. Validate the TLS certificate against the standard system CA bundle (or a configured trust anchor for testing).
3. Parse the response as JSON; reject on parse error or schema mismatch with §3.2.
4. Validate `domain` matches the URL host (with IDNA handling per RFC 5890 if applicable).
5. Validate `issued_at` ≤ now ≤ `expires_at`, with a clock-skew tolerance of ±5 minutes.
6. Canonicalize the covered fields per §3.4.
7. Verify the Dilithium signature per §3.5 step 1.
8. Verify the public key binds to the first address per §3.5 step 2.
9. Surface the verified binding to the user along with the timestamp.

A correctly implemented verifier SHOULD additionally:

- Cache validated files locally with a TTL no longer than `expires_at`.
- Pin the public key on first observation and warn the user on key rotation (trust-on-first-use / TOFU pattern).
- Display the `purpose` and `categories` fields verbatim — never silently filter, re-categorize, or hide entries.

### 3.7 Refresh and expiry

Verifiers MUST refuse files where `expires_at` is in the past beyond the ±5-minute clock-skew tolerance. There is no online revocation list and no on-chain revocation mechanism.

Operators SHOULD re-publish at least 30 days before `expires_at`. The recommended cadence is yearly (`issued_at` to `expires_at` ≈ 365 days), re-published at the ~9-month mark.

To **revoke** a binding, operators have two options:

1. Publish a fresh file with `addresses[]` empty (signed, current timestamp). Verifiers will see "no bindings claimed".
2. Remove the file from the server and wait for cached copies to expire.

There is intentionally no on-chain revocation list. This is consistent with the broader "no protocol-level identity registry" posture documented elsewhere in the Sophis project.

## 4. Rationale

### 4.1 Why `.well-known/` rather than DNS TXT or on-chain

Three competing designs were considered and rejected:

| Alternative | Rejection reason |
|---|---|
| **DNS TXT record** | TXT-record-based binding (e.g., `_sophis-wallet.example.org IN TXT "...sig=..."`) is bandwidth-cheap but produces fragile UX. DNS resolvers truncate at 255 chars per string; Dilithium pubkey + signature do not fit in a single TXT string without chunking. RFC 8615 `.well-known/` over HTTPS sidesteps the size cap entirely |
| **On-chain registry contract** | Would require an sVM contract that wallets/explorers query at validation time. Adds latency, gas cost, and (worst) **curation pressure on the contract author**: who is allowed to register a domain? If anyone, it's spam-vulnerable; if curated, it reopens the operator-as-curator regulatory surface that `project_h2_rejected.md` permanently closed |
| **PGP/keybase-style external identity service** | Re-introduces a third-party trust anchor that can disappear (Keybase was effectively shuttered after the 2020 Zoom acquisition), undermining the binding's longevity. A file at the operator's own domain has the same survival profile as the operator itself |

### 4.2 Why `categories` is free-form

The `categories` field on each address is deliberately free-form at the protocol level. The Sophis core team does NOT curate a list of valid categories and there is NO on-chain enum.

A protocol-level category registry would require a hard fork to add or remove categories — a permanent commitment to a vocabulary that may evolve over decades. A core-team-maintained off-chain list would create the same curation pressure with the same political surface, just without the hard fork. Both are avoided on purpose.

To reduce label fragmentation ("environmental" vs "Environmental" vs "env" vs "ecology") without reopening core-team curation, an independent community repository — **`sophis-network/community-labels`** — maintains a recommended vocabulary with an explicit `others` fallback. The repo is:

- **Community-governed**, not core-team-curated.
- **Off-chain and opt-in**: operators may follow the recommended vocabulary or use any other label.
- **Non-authoritative**: a label being on or off the recommended list carries no protocol-level meaning.

See `sophis-network/community-labels/README.md` for the current vocabulary.

### 4.3 Why TLS + Dilithium together (the "two-factor" design)

TLS alone proves only that the verifier reached the actual domain. An attacker who controls the operator's web server (without controlling the Sophis signing key) could publish arbitrary `addresses[]` claims. The Dilithium signature defeats this: the attacker can serve a file but cannot produce a valid signature without the Sophis private key.

Dilithium alone proves only key ownership. An attacker who steals the Sophis key (without controlling the domain) could sign a file, but a verifier fetching `https://example.org/.well-known/sophis-wallet.json` would not retrieve the attacker's file — the verifier reaches the actual `example.org`, and the attacker has no way to inject content there without also controlling the web server.

The **combination** is the binding: the same entity must control (a) the web server at `example.org` and (b) the Sophis signing key whose public key is published in the file. Compromise of either factor in isolation fails the verification.

### 4.4 Why the first address binds to the public key

Without the §3.5 step 2 check, the file format would allow this attack:

> Attacker controls `attacker.example`. Attacker generates their own Dilithium key. Attacker publishes `.well-known/sophis-wallet.json` listing the **victim NGO's address** in `addresses[0]`, signed with the attacker's key (which derives a *different* address). The signature is valid. The verifier confirms "this file is from attacker.example and signed by Dilithium key X". A naïve verifier might surface "addresses[0] verified at attacker.example" — but the actual binding is between attacker's key and attacker's domain, not the NGO's address.

Requiring the first address to derive from the published public key prevents this: the attacker would have to publish *their own* address (which is fine — operators may publish whatever addresses they control), and they cannot fake the binding to a wallet they do not control.

The first address is privileged for this binding check. Additional addresses in `addresses[1..]` are claims by the operator that "we also use these addresses" — the verifier treats them with caution, and downstream tooling SHOULD mark them as "claimed by example.org but not directly bound to the signing key".

### 4.5 Why no online revocation list

Bitcoin Core, Monero, and most modern PGP deployments have moved away from online revocation lists. The reasons are:

- **Survivability.** A revocation list maintained by anyone other than the operator can disappear; the binding then becomes ambiguous (was it revoked or was the list lost?).
- **Censorship resistance.** Centralized revocation gives an arbitrary party the power to invalidate any binding.
- **UX simplicity.** Verifiers do not need to make a second request per binding.

Setting `addresses[]: []` on a fresh signed file accomplishes the same goal with strictly less infrastructure. The cost is that verifiers must re-fetch periodically (which they should do anyway, given `expires_at`).

## 5. Backwards Compatibility

**Fully backwards compatible.** This SIP does not modify the Sophis protocol, consensus rules, RPC schema, or wallet wire formats. It defines a format for off-chain attestations served from operators' own domains.

No existing wallets, miners, exchanges, or indexers need to change to remain functional. Adoption is per-organization, per-tool, opt-in on both the publishing and verifying side.

## 6. Reference Implementation

A reference template JSON document, with all fields pre-populated as a starting point for operators, ships at:

- [`docs/well-known-sophis-wallet.template.json`](../docs/well-known-sophis-wallet.template.json)

Reference verifier implementations:

- The Sophis-native `dilithium-wallet` CLI (Rust) is expected to gain a `verify-domain` subcommand in a future release.
- The Python client at [`sophis-network/sophis-py`](https://github.com/sophis-network/sophis-py) is the recommended location for a community-maintained reference verifier.
- The Sophis explorer (when built by the community) is expected to expose verification badges next to addresses.

The signing operation can be performed today by any Dilithium ML-DSA-44 library that supports the FIPS 204 final standard. The Sophis reference miner and wallet both link `pqcrypto-mldsa` and can produce signatures over arbitrary byte strings.

## 7. Security Considerations

### 7.1 Threat model

Adversaries considered:

- **Web-server compromise without key compromise:** attacker controls `example.org` but does not have the Dilithium private key. The Dilithium signature check prevents arbitrary `addresses[]` claims.
- **Key compromise without web-server compromise:** attacker has the Dilithium private key but does not control `example.org`. The HTTPS+TLS binding prevents the attacker's signed file from being served from the legitimate domain.
- **Both compromised simultaneously:** the binding fails open. This is the irreducible worst case; mitigations include short `expires_at` windows, key rotation cadence, and out-of-band key transparency (e.g., publishing the public-key fingerprint on independent channels).
- **Quantum adversary against TLS but not Dilithium:** a future quantum-computing-capable adversary may break the RSA/ECDSA-based TLS certificate chain while Dilithium remains secure. The Dilithium signature continues to bind key-to-address, but the TLS proof of domain control degrades. Verifiers SHOULD warn when relying on pre-quantum TLS certificates for high-value verifications; the broader Sophis ecosystem's transition to PQ-safe TLS (when widely deployed) restores the full binding.
- **DNS hijacking:** an attacker who hijacks DNS for `example.org` redirects HTTPS to their own server. TLS catches this if their server cannot present a valid certificate for `example.org`; the attacker would need to compromise a CA or the operator's TLS keys. Mitigations: CAA records, HSTS preloading, certificate transparency monitoring (all standard hygiene, not specific to this SIP).
- **Replay across networks:** a `.well-known/` file lists a `sophis:` address (mainnet). An attacker on testnet could mirror the file pretending the binding applies to a `sophistest:` address derived from the same public key. The address derivation per §3.5 step 2 catches this: the bech32 prefix is part of the derived address, so the verifier's network must match the file's stated address.

### 7.2 Cryptographic assumptions

- Dilithium ML-DSA-44 (FIPS 204) is unforgeable under chosen-message attacks. This is the same assumption that backs every Sophis transaction signature.
- The TLS certificate chain used by the verifier is sound. Standard web-PKI assumptions apply; this SIP does not strengthen or weaken them.
- The Blake2b hash inside the Sophis address derivation is collision-resistant. Same assumption as the consensus layer.

### 7.3 Privacy implications

The file is **inherently public**. Operators choosing to publish `.well-known/sophis-wallet.json` are voluntarily linking their domain to their on-chain addresses, with all that implies for transaction tracing. The protocol does not provide privacy guarantees for participants in addresses listed in such a file.

This is fine for organizations (NGOs, public-facing projects) where the linkage is desired. It is inappropriate for individuals who want pseudonymous on-chain activity; such individuals SHOULD NOT publish this file.

### 7.4 Operational considerations

- **Caching pressure on operator infrastructure:** verifiers cache files for up to `expires_at`. An operator should size their static-file hosting for the expected verification rate; for a community-scale project, this is negligible.
- **Key rotation:** when a key rotates, the operator publishes a fresh file with the new public key. Verifiers using TOFU will see the rotation and SHOULD warn. The previous key cannot be used to sign new attestations after rotation (the operator simply no longer signs with it).
- **Loss of signing key:** if the operator loses access to the signing key while retaining domain control, they cannot publish a new signed attestation. Recovery is: generate a new Dilithium key, publish a new file with the new public key and new `addresses[]`, and rely on the verifier's TOFU warning to alert downstream consumers of the change.

### 7.5 Impact on Sophis subsystems

- **Long-range attack resistance:** none — this SIP is off-chain.
- **Reorg behaviour:** none — off-chain.
- **Mempool policy:** none — off-chain.
- **Light-client / SPV verifiability:** none — off-chain.
- **ZK-Rollup (Phase 3) compatibility:** unaffected.
- **ZK-Oracle (Phase 5) / Phase 9:** unaffected.
- **Data Availability (Phase 6) compatibility:** unaffected. The file lives in HTTP, not in V5 carriers.

## 8. Test Vectors

Test vectors for the canonical serialization and signature verification are pending consolidation in a future revision of this SIP. Implementers MAY temporarily generate their own vectors by:

1. Producing a known-good `.well-known/sophis-wallet.json` with a deterministic Dilithium key (e.g., seeded RNG).
2. Computing the canonical bytes per §3.4.
3. Verifying that the signature in the file validates against the canonical bytes.

The reference implementation in [`sophis-network/sophis-py`](https://github.com/sophis-network/sophis-py) will publish canonical test vectors in `examples/well_known_test_vectors/` once a stable maintainer roster forms.

## 9. References

- IETF RFC 8615 — Well-Known URIs (the `.well-known/` prefix)
- IETF RFC 8785 — JSON Canonicalization Scheme (JCS)
- IETF RFC 3339 — Date and Time on the Internet: Timestamps
- IETF RFC 5890 — Internationalized Domain Names for Applications (IDNA): Definitions and Document Framework
- NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (Dilithium ML-DSA)
- [`docs/well-known-sophis-wallet.template.json`](../docs/well-known-sophis-wallet.template.json) — reference template
- [`sophis-network/community-labels`](https://github.com/sophis-network/community-labels) — recommended category vocabulary (community-maintained)
- [`sophis-network/green-miner-pledge`](https://github.com/sophis-network/green-miner-pledge) — companion community repository listing donating miners
- [`sophis-network/donation-dashboard`](https://github.com/sophis-network/donation-dashboard) — reference architecture for community dashboards that consume `.well-known/` files
- [`project_h2_rejected.md`](../) (project memory) — why there is no on-chain category registry
- [`project_ngo_curation_no_core_team.md`](../) (project memory) — why the core team does not curate NGO lists

## 10. Copyright

This SIP is released into the public domain (CC0).
