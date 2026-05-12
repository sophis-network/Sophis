# Sophis Wallet Verification (`.well-known/sophis-wallet.json`)

> **The canonical specification for this format is [SIP-6: Domain-to-Wallet
> Self-Attestation](../SIPS/SIP-6-WALLET-VERIFICATION.md).**
>
> This file previously held the full specification. It was promoted to a
> formal Standards-track SIP on 2026-05-12 to make its cross-implementation
> nature explicit and to align with the SIP process for tracking changes,
> deprecations, and test vectors.

## Where to read what

| You want… | Read… |
|---|---|
| The full specification and verification procedure | [`SIPS/SIP-6-WALLET-VERIFICATION.md`](../SIPS/SIP-6-WALLET-VERIFICATION.md) |
| A pre-filled JSON template to copy | [`well-known-sophis-wallet.template.json`](./well-known-sophis-wallet.template.json) |
| The recommended community vocabulary for the `categories` field | [`sophis-network/community-labels`](https://github.com/sophis-network/community-labels) |
| A reference verifier implementation | [`sophis-network/sophis-py`](https://github.com/sophis-network/sophis-py) (community-maintained) |
| The architectural rationale (why this design, why not alternatives) | SIP-6 §4 "Rationale" |
| The threat model and security considerations | SIP-6 §7 "Security Considerations" |

## Why a stub

Standards-track documents that other independent implementations need to follow live under `SIPS/` and follow the SIP-0 process for versioning, deprecation, and ratification. Implementation guides, runbooks, and policies that describe how *this specific implementation* behaves live under `docs/`. Wallet verification crossed that line: it is a cross-implementation format consumed by wallets, explorers, indexers, dashboards, and community catalogues, so it belongs in the SIP series.

This stub remains because external links to `docs/WALLET_VERIFICATION.md` exist in the wild and should not 404.
