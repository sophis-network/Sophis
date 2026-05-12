```
SIP: 12
Title: Account Abstraction (AA) for Sophis Wallets
Author: Marcelo Delgado <sophis-network@proton.me>
Status: Draft
Type: Standards
Created: 2026-05-12
```

# SIP-12: Account Abstraction (AA) for Sophis Wallets

## 1. Abstract

This SIP specifies an **Account Abstraction** (AA) system for Sophis: a set of sVM contracts that lets a user deploy a wallet whose authentication and authorization rules are programmable, replacing the implicit "one Dilithium key, one address, one transaction" model with a contract-mediated flow that supports guardian-based key recovery, bounded-scope session keys, batched operations, and per-account upgradeability. The system is implemented entirely at the sVM layer with no consensus-level changes; the base transaction format is unchanged, and AA accounts are addresses whose redeem script invokes an sVM contract that implements the `IAccount` trait. This SIP defines the wire format, the four contract interfaces, the eight ratified design decisions (D1–D8), and the verifier procedure. The full design rationale, anti-patterns, and implementation guide live in [`wallet/aa-spec/`](../wallet/aa-spec/).

## 2. Motivation

A Sophis address that maps to a single Dilithium ML-DSA-44 verification key has four structural weaknesses for ordinary users:

1. **Key loss is permanent.** A lost or destroyed owner key destroys the account; recovery is impossible without an alternative authorization path.
2. **Key compromise is total.** An attacker with the owner key has the same authority as the user, with no scope limits.
3. **Every transaction needs the owner key online.** Cold-storage UX and delegated-signing UX both suffer.
4. **No batching primitive.** Multi-step interactions require multiple separately-signed transactions, each paying its own per-transaction overhead.

Ethereum's ERC-4337 (deployed 2023, still evolving through ERC-7702/Pectra in 2024–2025) demonstrates that this is solvable at the contract layer, without consensus-level changes. The 4-year-plus iteration cycle ERC-4337 went through — surfacing at least 11 design revisions and roughly 6 distinct attack classes — would have been catastrophic if each iteration required a hard fork. Account Abstraction belongs in contract-land.

Sophis has the advantage of arriving at this design space after Ethereum has paid the iteration cost. SIP-12 absorbs the lessons (modularity, conservative defaults, no central operator/factory, post-quantum signature sizing) without re-litigating the rejected paths.

## 3. Specification

The full specification is maintained at [`wallet/aa-spec/SPEC.md`](../wallet/aa-spec/SPEC.md). This SIP §3 distills the load-bearing decisions and interfaces. In case of ambiguity between this SIP and the spec file, the spec file is canonical for implementation detail; this SIP is canonical for the **standard** that other implementations must follow.

### 3.1 Ratified design decisions (D1–D8)

These eight decisions are binding for any v1 implementation:

| ID | Decision | Implication |
|---|---|---|
| **D1** | Implement at the sVM layer, not the consensus layer | No new opcodes, no transaction-format changes; AA accounts are P2SH outputs whose redeem script invokes an sVM contract |
| **D2** | Four independent contracts (modular), not one monolith | `IAccount`, `Recovery`, `SessionKey`, `Batching` — each independently deployable and upgradeable |
| **D3** | Versioning via magic-bytes wire prefix (`aav1` = `0x61 0x61 0x76 0x31`) + SDK type-system enum | Wrong-version payloads fail to parse loudly; SDK enforces version at the type level |
| **D4** | Conservative defaults | Min 3 guardians, min 3-of-N threshold, max 24h session expiry, max 16 ops per batch — enforced at contract level, not just UI |
| **D5** | No factory, no deployer, no curation by the core team | Reference contracts ship under Apache 2.0; deployment is per-user; no "official" factory or guardian registry exists |
| **D6** | Owner-key rotation, never key fragmentation | Recovery replaces the owner key entirely; the old key is invalidated. Sharded keys (Shamir, threshold) are out of scope for v1 |
| **D7** | Signature buffer is variable-length | Dilithium ML-DSA-44 verification key 1312 B, signature 2420 B; wire size for single-sig single-op ≈ 3.8 KB; multisig ≈ 12 KB |
| **D8** | State cost is a first-class design concern | Every state addition is justified against block-mass budget; no UX feature is allowed to push per-tx state below the line documented in `wallet/aa-spec/SPEC.md` §3.D8 |

### 3.2 The four contracts

Every v1 implementation MUST provide reference contracts for the following four roles:

| Contract | Role | Required interface |
|---|---|---|
| `IAccount` | The user's wallet contract. Holds funds, holds owner-key state, validates incoming operations | `validate(operation, signature) -> bool`, `rotate_owner_key(new_key, authorization)`, `nonce() -> u64` |
| `Recovery` | Stores guardian set + threshold. Produces signed instructions to rotate the bound `IAccount`'s owner key when M-of-N guardians sign | `init(account, guardians, threshold)`, `propose_rotation(new_key)`, `approve_rotation(proposal_id, signature)`, `execute_rotation(proposal_id)` |
| `SessionKey` | Stores active session keys with expiry and scope (allowance, optional contract whitelist) | `add_session(key, expiry, allowance, whitelist)`, `revoke(key)`, `is_authorized(key, op) -> bool` |
| `Batching` | Takes an array of operations + one signature and dispatches them in order against a known `IAccount` | `execute_batch(account, operations, signature_payload) -> Result<(), BatchError>` |

Full method signatures, parameter types, and error variants are in [`wallet/aa-spec/SPEC.md`](../wallet/aa-spec/SPEC.md) §4.

### 3.3 Wire format

The AA payload is borsh-encoded with a fixed magic-bytes prefix. The canonical layout is:

```
+------------------------+--------+
| magic                  | 4 B    |  "aav1" = 0x61 0x61 0x76 0x31
+------------------------+--------+
| operation_count        | 1 B    |  1..=16 (D4 conservative default)
+------------------------+--------+
| operations             | varies |  borsh-encoded Vec<Operation>
+------------------------+--------+
| signature_payload      | varies |  enum: SingleKey | MultiKey | Future
+------------------------+--------+
```

The `signature_payload` enum:

```rust
enum SignaturePayload {
    SingleKey {
        scheme: u8,                          // 0x01 = owner, 0x03 = session
        signer: DilithiumPubKey,             // 1312 B
        signature: DilithiumSignature,       // 2420 B
    },
    MultiKey {
        scheme: u8,                          // 0x02
        signers: Vec<(DilithiumPubKey, DilithiumSignature)>,  // M entries, lexicographic order
    },
    Future {
        scheme: u8,
        payload: Vec<u8>,                    // reserved; v1 MUST reject
    },
}
```

v1 implementations MUST reject the `Future` variant; it exists as a forward-compatibility hook for v2 (aggregate signatures, threshold schemes, etc.).

### 3.4 Replay protection

Every `Operation` includes an account-level monotonic nonce. The `IAccount` contract MUST track the next-expected nonce and MUST reject any operation whose nonce is not exactly that value. Cross-network replay is prevented by the standard Sophis sighash, which already includes network-distinguishing data; no AA-specific cross-network protection is required.

### 3.5 Verifier procedure (block validator path)

When the sVM dispatches an operation against an `IAccount` contract:

1. The contract decodes the AA payload (`aav1` magic + operations + signature_payload).
2. The contract validates each operation's nonce against its tracked next-expected value; rejects on mismatch.
3. The contract calls `validate(operation, signature_payload)`. The default `validate` implementation:
   - For `SingleKey` with `scheme = 0x01`: verifies the signature against the configured owner key.
   - For `SingleKey` with `scheme = 0x03`: invokes the bound `SessionKey` contract's `is_authorized` and, if authorized, verifies the signature against the session-key public key.
   - For `MultiKey` with `scheme = 0x02`: verifies all M signatures against the configured multi-owner set; requires the threshold to be met.
4. If `validate` returns true, the operation executes in the order specified; the contract's `nonce()` is incremented after each successful operation.

The contract MUST NOT execute any operation whose validation fails. Partial-failure semantics within a batch are specified in `wallet/aa-spec/SPEC.md` §4.4.

## 4. Rationale

The eight decisions in §3.1 each correspond to a structural choice that was selected for one of three reasons:

- **3+ chain convergence** — multiple independent chains agreed on the same approach (modularity per ERC-4337; conservative defaults per Argent/Safe; magic-bytes versioning per BIP-174/PSBS).
- **Sophis-specific constraint** — Dilithium key/signature sizes, no HD derivation, Apache 2.0 license posture, no consensus-level identity layer.
- **Risk control** — minimizes regulatory or operational exposure (D5 "no factory, no deployer, no curation" is binding on the Sophis core team per `OPERATIONAL_BOUNDARIES.md` §6).

The full decision-by-decision justification, including the alternatives considered and rejected for each, is in [`wallet/aa-spec/SPEC.md`](../wallet/aa-spec/SPEC.md) §3. A separate document [`wallet/aa-spec/ANTI_PATTERNS.md`](../wallet/aa-spec/ANTI_PATTERNS.md) catalogs designs that **must never** be accepted into this SIP, no matter how compelling the argument: official factory contracts, verified guardian registries, OAuth/zkLogin integrations, and several others. The anti-pattern list is normative — a future SIP that proposes reintroducing any of those patterns must explicitly address the anti-pattern's rationale.

### 4.1 Why sVM contracts rather than consensus primitives

ERC-4337 stayed off-consensus from 2021 to 2025, then partially merged via ERC-7702/Pectra. The 4-year off-consensus period absorbed 11+ revisions and discovered roughly 6 distinct attack classes. Hard-forking each iteration would have been catastrophic for Ethereum. Sophis adopts the same posture from the start: AA is an sVM contract system in v1, with promotion to consensus primitives gated on ≥ 12 months of production data and a successful follow-up SIP.

### 4.2 Why modular (four contracts) rather than monolithic

ERC-4337's modularity is what allowed paymasters, validators, and aggregators to evolve independently of the Account contract itself. A monolithic design creates one upgrade decision for the entire system; modular allows fail-soft per piece. Sophis adopts this structurally: separating `IAccount`, `Recovery`, `SessionKey`, and `Batching` into independently versioned contracts means a bug in `Recovery` does not require redeploying `IAccount`, and vice versa.

### 4.3 Why "guardian-based recovery" and never "social recovery"

The term "social recovery" implies that guardians are trusted individuals chosen for social reasons (friends, family). In practice, the recovery threshold is a security mechanism, not a social one — choosing guardians whose collusion is implausible (different jurisdictions, different devices, different relationships) is the load-bearing decision. The terminology shift to "guardian-based recovery" is deliberate: it forces wallet UIs to surface the trust threshold rather than disguising it as a friendship-based mechanism. See `wallet/aa-spec/ANTI_PATTERNS.md` §4 for the full anti-pattern.

### 4.4 Why no factory and no deployer

The Sophis core team's `OPERATIONAL_BOUNDARIES.md` posture forbids the team from operating curated infrastructure. An "official factory" deployed and operated by the team would arguably constitute "service provision" rather than "tool publishing", undermining the legal posture documented in `project_legal_positioning.md` (memory) — specifically the category 🟢 (open-source protocol developer) that has zero historical criminal prosecutions over 15 years of Bitcoin Core / Monero precedent. ERC-4337's EntryPoint operates as a singleton on Ethereum mainnet; multiple legal-risk analyses have argued that operation crosses into service-provision territory. Sophis explicitly refuses to test that boundary.

## 5. Backwards Compatibility

**Fully backwards compatible at the consensus level.** AA contracts are sVM contracts; they neither add opcodes, change transaction validation, nor modify the address format. Wallets, miners, and exchanges that do not implement AA continue to work unchanged.

**Forward-compatibility hooks:**

- Wire-format magic bytes (`aav1` / `aav2` / …) allow hard-fail parsing of unknown versions.
- `SignaturePayload::Future` variant reserves space for aggregate-signature schemes and other v2 mechanisms; v1 verifiers reject it loudly.
- The four-contract modular structure allows individual contracts to be replaced without redeploying the entire system.

## 6. Reference Implementation

The reference implementation is staged in [`wallet/aa-spec/`](../wallet/aa-spec/), comprising:

- [`SPEC.md`](../wallet/aa-spec/SPEC.md) — full specification (this SIP §3 is its distillation)
- [`ANTI_PATTERNS.md`](../wallet/aa-spec/ANTI_PATTERNS.md) — normative list of designs that must not be accepted
- [`OPERATIONAL_BOUNDARIES_PARAGRAPH.md`](../wallet/aa-spec/OPERATIONAL_BOUNDARIES_PARAGRAPH.md) — canonical text to be inserted into `OPERATIONAL_BOUNDARIES.md` once any reference contract from this SIP is published as code
- `templates/` — contract scaffolds (when shipped; templates are pre-RFC at the time of this SIP's submission)

The reference contracts themselves are not yet implemented in code as of this SIP's submission. Reference contract code is **intentionally deferred to the post-mainnet roadmap (item J1)** for two reasons:

1. **AA is UX-premium functionality, not required for the chain to function.** Users can transact day-zero with direct Dilithium-signed wallets via the `dilithium-wallet` CLI. AA adds guardian recovery, session keys, and batching as quality-of-life improvements, but the chain operates without it.
2. **AA reference implementations have high iteration risk.** ERC-4337 took roughly four years and eleven-plus revisions to stabilize on Ethereum, surfacing approximately six distinct attack classes along the way. Sophis chooses to wait for the standard to be implemented once, correctly, after community review of this SIP — rather than rushed under launch pressure.

Per SIP-0 §5, this SIP remains in **Draft** status until reference contract code exists and runs. The SIP cannot enter **Review** without the reference implementation; it cannot enter **Final** without the implementation being production-ready and audited. The status progression is the intended forcing function: implementers planning to support AA know the standard is frozen at the level of D1–D8 + wire format + interfaces, while the SIP's lifecycle stage signals where reference code stands.

## 7. Security Considerations

### 7.1 Threat model

The full threat model is in [`wallet/aa-spec/SPEC.md`](../wallet/aa-spec/SPEC.md) §6. Summary of adversaries considered and the design response:

| Adversary | Capability | Design response |
|---|---|---|
| Owner-key compromise | Sign arbitrary operations, drain funds | Guardian-based recovery within hours; loss = pre-rotation window |
| Single guardian compromise | Sign as that guardian | M ≥ 3 means no single guardian can rotate; replace_guardian removes the compromised one |
| **M-of-N guardian collusion** | **Rotate owner key to attacker's choice** | **Irreducible** — fundamental property of M-of-N. Mitigation is user choice of guardians whose collusion is implausible |
| Session-key compromise | Sign within session scope | Bounded blast radius (allowance, contract whitelist, expiry); owner can revoke at any time |
| Cross-network replay | Capture testnet payload, replay on mainnet | Sophis sighash includes network-distinguishing data; signature invalid across networks |
| Same-network replay | Capture and resubmit payload | Account-level monotonic nonce; reject any non-next-expected value |
| Cross-account contract impersonation | Pretend to be IAccount, interact with Recovery/Batching | Recovery binds to one IAccount at init; Batching verifies account parameter |

### 7.2 Explicitly out of scope

- **Network-level attacks** (sybil, eclipse) — Sophis consensus layer, not AA.
- **Quantum attacks on Dilithium ML-DSA-44** — if Dilithium breaks, all of Sophis breaks, not just AA.
- **Side-channel attacks on Dilithium signing** — wallet implementer responsibility.
- **Phishing the user into deploying a malicious account contract** — UX responsibility, not protocol.

### 7.3 Impact on Sophis subsystems

- **Long-range attack resistance:** none — AA is sVM-layer, not consensus.
- **Reorg behaviour:** unchanged.
- **Mempool policy:** unchanged.
- **Light-client / SPV verifiability:** AA accounts are normal P2SH UTXOs; SPV clients see them as ordinary outputs. They can verify the existence of a transaction without understanding AA semantics.
- **ZK-Rollup (Phase 3) compatibility:** AA accounts can participate in L2 like any other address. L2-internal AA is a separate question not addressed here.
- **ZK-Oracle (Phase 5 / Phase 9) compatibility:** unaffected; oracle attestations are independent of AA.
- **Data Availability (Phase 6) compatibility:** unaffected; DA carriers and AA contracts are orthogonal.

## 8. Test Vectors

The test-vector plan is specified in [`wallet/aa-spec/SPEC.md`](../wallet/aa-spec/SPEC.md) §7. Each of the four contracts requires:

- Round-trip wire encoding tests
- Signature verification tests with known-good Dilithium key pairs
- Nonce-rejection tests (replay defense)
- Guardian threshold edge cases (M-of-N for M ∈ {3, 4, 5})
- Session-key expiry and scope rejection tests
- Batching partial-failure semantics tests

Concrete vectors will be published as part of the reference implementation. Implementers wishing to ship pre-vector compliance MAY generate their own using seeded RNG and cross-check against other implementations as they emerge.

## 9. References

- [`wallet/aa-spec/SPEC.md`](../wallet/aa-spec/SPEC.md) — canonical specification
- [`wallet/aa-spec/ANTI_PATTERNS.md`](../wallet/aa-spec/ANTI_PATTERNS.md) — normative anti-pattern list
- [`wallet/aa-spec/OPERATIONAL_BOUNDARIES_PARAGRAPH.md`](../wallet/aa-spec/OPERATIONAL_BOUNDARIES_PARAGRAPH.md) — canonical text for OPERATIONAL_BOUNDARIES.md and Whitepaper §11
- [`SIP-1: PSBS`](./SIP-1-PSBS.md) — wire format conventions (magic bytes, borsh encoding) shared with AA
- [`SIP-2: Typed Data Signing`](./SIP-2-TYPED-SIGNING.md) — Dilithium-aware signing primitive used by IAccount.validate
- [`SIP-5: Wallet Descriptors`](./SIP-5-DESCRIPTORS.md) — descriptor language that may, in the future, encode AA account templates
- ERC-4337 — Ethereum's Account Abstraction Using Alt Mempool, the prior art absorbed and adapted here
- ERC-7702 (Pectra, 2024–2025) — partial-consensus AA in Ethereum; informs Sophis's "stay off consensus in v1" choice (D1)
- Argent Wallet, Safe (Gnosis Safe) — production deployments demonstrating guardian-based recovery
- NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (Dilithium ML-DSA-44)
- IETF RFC 8174 — Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words (RFC 2119 requirement-level keywords are used throughout)
- [`project_legal_positioning.md`](../) (project memory) — legal posture rationale for D5
- [`OPERATIONAL_BOUNDARIES.md`](../OPERATIONAL_BOUNDARIES.md) §6 — binding constraint on D5

## 10. Copyright

This SIP is released into the public domain (CC0).
