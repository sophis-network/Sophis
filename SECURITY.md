# Security Policy

This is a good-faith responsible-disclosure process for Sophis. It is a
process, **not a contract, warranty, or guarantee**.

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion for a
suspected vulnerability** — that exposes users before a fix exists.

Report privately through either:

1. **GitHub private vulnerability reporting** (preferred) — the
   "Report a vulnerability" button under this repository's *Security*
   tab.
2. **Email** — `team@sophis.org`. Encryption is preferred; the
   public key is published in this file when available.
   - PGP fingerprint: `<TO BE PUBLISHED HERE>`

Please include the affected component, a clear description, and a
proof-of-concept or reproduction steps.

## Scope

In scope: consensus, proof-of-work, cryptography, the sVM, networking,
wallet key handling, RPC surfaces, and this repository's build pipeline.

Out of scope: social engineering; volumetric denial-of-service;
vulnerabilities only in third-party dependencies (report upstream);
issues only in throwaway test material; and theoretical reports with no
proof-of-concept.

## Handling and disclosure

Reports are triaged on a best-effort basis. Fixes are developed
privately and disclosed in coordination with the reporter. Issues that
affect consensus may require a coordinated network upgrade and therefore
have no fixed fix timeline.

## No bug bounty

Sophis does **not** operate a paid bug bounty and offers **no monetary
reward** for reports. Security review and disclosure are entirely
voluntary. Reporters of verified issues may be publicly credited if they
wish; recognition is the only acknowledgment offered.
