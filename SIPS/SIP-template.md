```
SIP: DRAFT
Title: <Concise title under 60 chars>
Author: <Name <email>> or <@github_handle>
Status: Draft
Type: Standards | Process | Informational
Created: YYYY-MM-DD
```

<!--
Optional header fields, delete if unused:

Replaces: <comma-separated SIP numbers>
Replaced-By: <SIP number>
Requires: <comma-separated SIP numbers>
Activation-Height: <integer block height>

Replace `SIP: DRAFT` with the assigned number once a maintainer
moves your SIP from Draft to Review.

Process for filling this template is in SIP-0-process.md.
-->

# SIP-XXXX: <Title>

## 1. Abstract

<Two or three sentences. State precisely what this SIP proposes,
in plain language. A wallet developer should be able to read this
section alone and decide whether the SIP is relevant to them.>

## 2. Motivation

<What problem does this SIP solve? Who benefits? What goes wrong
today without this change? Cite specific issues, prior
discussions, or external precedents (BIP / EIP / HIP / academic
work) where relevant.>

## 3. Specification

<The technically complete description. An independent implementer,
reading this section in isolation, must be able to write a
compatible implementation. Include:

- Exact data structures (with byte layouts where applicable)
- Algorithm pseudocode or precise prose
- Field-by-field semantics
- Wire-format definitions for any new messages or transaction
  formats
- Boundary conditions, edge cases, error handling
- Activation rules (for Standards Track requiring a fork)

Avoid prose ambiguity. If a field is "the SHA3-384 hash of the
canonical encoding", say so; do not write "the hash of the data".>

## 4. Rationale

<Why this approach over the alternatives? Briefly enumerate the
alternatives considered and why they were rejected. Include
references to comparable mechanisms in other systems (BIP-N,
EIP-N, etc.) and explain divergences.

This is the most important section for future maintainers reading
the SIP years later. Be generous.>

## 5. Backwards Compatibility

<Does this SIP break anything? Possible answers, in order of
preference:

- "Fully backwards compatible." (most-preferred)
- "Backwards compatible for users; nodes must upgrade by block
  height H. Soft fork."
- "Hard fork required at block height H. Old nodes will reject
  blocks after H." (least-preferred; see SIP-0 § 10.4 for
  additional process requirements)

Describe migration cost for wallets, exchanges, miners, indexers.
If new opcodes / capabilities are added, list every component
that must be updated.>

## 6. Reference Implementation

<Link to the implementation PR or commit. For Standards Track
SIPs, the implementation does not need to be production-ready at
the time the SIP enters Review, but it must exist and run.

For Process and Informational SIPs that have no implementation,
write "Not applicable" and explain why.>

## 7. Security Considerations

<What can go wrong? Threat model. Adversaries considered.
Failure modes. Cryptographic assumptions and their justification
(especially relevant given Sophis's PQC-only posture). Denial-of-
service vectors. Privacy implications (Sophis is transparency-by-
default; if this SIP changes that, justify in §4).

For consensus-affecting SIPs, include the impact on:

- Long-range attack resistance
- Reorg behaviour
- Mempool policy
- Light-client / SPV verifiability
- ZK-Rollup (Phase 3) compatibility, if applicable
- ZK-Oracle (Phase 5) compatibility, if applicable
- Data Availability (Phase 6) compatibility, if applicable

Mandatory section. SIPs without a Security Considerations section
are returned to Draft.>

## 8. Test Vectors

<Mandatory for Standards Track SIPs involving cryptography, wire
formats, or hash chains. For other types, write "Not applicable".

Provide concrete inputs and expected outputs in machine-readable
form (hex strings, JSON). Test vectors must be reproducible by
the reference implementation.>

## 9. References

<Bibliography. BIPs, EIPs, HIPs, academic papers, prior Sophis
SIPs, GitHub issues, prior discussions. Hyperlinked.>

## 10. Copyright

This SIP is released into the public domain (CC0).
