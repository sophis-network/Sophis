# Sophis Account Abstraction — Specification

**Status:** Pre-RFC draft. Frozen for publication. Implementation gated on the RFC process described in `README.md`.

**Author:** Marcelo Delgado <sophis-network@proton.me>

**Date prepared:** 2026-05-09

**Implementation target:** sVM contracts (NOT consensus primitives). See D1.

---

## 0. Reading order

1. This SPEC for the design itself.
2. `CONVERGENCE.md` for why each design decision was made.
3. `ANTI_PATTERNS.md` for what to never accept into the design, no matter how compelling.
4. Templates in `templates/` for the shape of each contract.

If you read only one section: §3 (Decisions D1–D8) is load-bearing.

---

## 1. Scope

This document specifies a system of sVM contracts that, when deployed by a user, give that user a wallet whose authentication and authorization rules are programmable rather than tied to a single Dilithium signing key. The system targets:

- **Guardian-based key recovery** — owner key compromise or loss does not destroy the account
- **Session keys** — bounded delegation of signing authority to short-lived subordinate keys
- **Batched operations** — multiple intents authorized in a single signature
- **Versioning** — the system itself can evolve via SIPs without hard forks

The system does **not** target, in v1:

- Paymasters (third-party gas sponsorship). Deferred to v2.
- Multi-party computation (MPC) signers. Out of scope; research-grade as of 2026.
- Aggregate Dilithium signatures. No production-ready scheme exists; reserved for a future spec when one emerges.
- OAuth or any third-party identity provider integration. **Permanently rejected** — see `ANTI_PATTERNS.md` §3.

## 2. Vocabulary

| Term | Meaning |
|---|---|
| **Account** | An sVM contract instance, deployed by a user, that holds funds and signs transactions on the user's behalf |
| **Owner key** | The Dilithium ML-DSA-44 verification key (1312 B) currently authorized to sign on behalf of the account |
| **Guardian** | A Dilithium key independently chosen by the account holder, able to participate in owner-key replacement when a guardian-recovery threshold is met |
| **Guardian-based recovery** | The mechanism by which `M` of `N` guardian signatures replace the owner key. **Never** to be called "social recovery" — see `ANTI_PATTERNS.md` §4 |
| **Session key** | A subordinate key with bounded scope (expiry timestamp, allowance, optional contract whitelist) authorized by the owner to sign without further owner involvement |
| **IAccount** | The trait every account contract must implement; the minimum interface used by the sVM to validate a transaction's authorization |
| **Operation** | A single state-changing intent (transfer, contract call). Batched operations are an array of operations validated by one signature |
| **Wire version** | Magic-bytes prefix (`aav1` = `0x61 0x61 0x76 0x31`) identifying the AA wire format. See D3 |

## 3. Decisions (D1–D8) — ratified pre-RFC

These eight decisions are the load-bearing structural choices. Each was selected for one of three reasons:

- **3+ chain convergence** — multiple independent chains agreed on this, so it is likely correct
- **Sophis-specific constraint** — Dilithium sizes, no HD derivation, AGPL position
- **Risk control** — minimizes regulatory or operational exposure

Maintainers implementing this spec **may revisit** any decision by opening a SIP, but they should treat each one as the default and justify any deviation explicitly.

### D1 — Implement at the sVM layer, not the consensus layer

**Decision:** Account Abstraction is a sVM contract system. There is **no** consensus-level concept of "account contract" in v1. The base transaction format is unchanged; AA accounts are addresses that happen to be P2SH outputs whose redeem script is an sVM contract call.

**Rationale:** ERC-4337 stayed off-consensus from 2021–2025 (then partially merged via ERC-7702/Pectra). The 4-year off-consensus period absorbed 11+ revisions and discovered ~6 distinct attack classes. Hard-forking each iteration would have been catastrophic.

**Implication for maintainers:** if the design proves wrong post-launch, ship v2 contracts; do not hard-fork. Promotion to consensus primitives is a separate decision, conditional on ≥12 months of production data and a successful SIP.

### D2 — Modular: four independent contracts, not one monolith

**Decision:** Four contracts, each independently deployable, independently versioned, independently upgradeable:

| Contract | Role |
|---|---|
| `IAccount` | The user's wallet contract. Implements `validate(operation, signature) -> bool`. Holds funds, owns owner-key state |
| `Recovery` | Stores guardian set + threshold; produces signed instructions to rotate `IAccount`'s owner key when M-of-N guardians sign |
| `SessionKey` | Stores active session keys with expiry + scope; called by `IAccount.validate` when the signing key is a session key, not the owner |
| `Batching` | Helper contract: takes an array of operations + one signature and dispatches them in order |

**Rationale:** ERC-4337's modularity is what allowed paymasters, validators, and aggregators to evolve independently of the Account contract. A monolithic design creates one upgrade decision for the entire system; modular allows fail-soft per piece.

**Implication for maintainers:** **never** put recovery logic inside `IAccount`. **Never** put session-key state inside `IAccount`. The seam is the entire point.

### D3 — Versioning: magic bytes wire prefix + SDK enum

**Decision:** Two versioning layers:

1. **Wire format magic bytes:** every AA-wire-format payload begins with `aav1` (`0x61 0x61 0x76 0x31`). Future versions advance to `aav2`, `aav3`, etc.
2. **SDK type-system enum:** Rust SDK exposes `AccountVersion::V1`, propagated through every API call. Type checker prevents mixing v1 and v2 payloads in code.

**Rationale:** PSBS (K1) uses magic-bytes versioning; descriptors (K3) will use checksum + version. Consistency across the wallet stack reduces tooling complexity. Signature size and account-contract layout will likely change between major versions; the magic byte must hard-fail wrong-version parsing.

**Implication for maintainers:** **never** "extend v1 silently". Either v1 stays frozen and v2 is a new wire format, or you risk every wallet implementer mis-parsing.

### D4 — Conservative defaults

**Decision:** Defaults selected to favor security over convenience:

| Setting | v1 default | Configurable lower? |
|---|---|---|
| Guardian count `N` | 5 | Minimum 3 (hard-coded; reject lower) |
| Recovery threshold `M` | 3 | Minimum 3 (hard-coded; reject 1-of-N or 2-of-N) |
| Session key expiry | 24 hours | Maximum 7 days (hard-coded; reject longer) |
| Session key allowance | None (must be set explicitly) | — |
| Session key contract whitelist | None (must be set explicitly) | — |
| Batched operation max count | 16 | Maximum 64 (block-mass concern) |

**Rationale:** Insecure configurations (1-of-1 recovery, year-long sessions) should be **structurally harder** than secure ones. ERC-4337 left defaults entirely to the wallet UI, with predictable bad results: many wallets shipped 1-of-1 recovery via a single email, defeating the point.

**Implication for maintainers:** the contract MUST reject parameters outside the bounds above. Wallet UI is downstream and can warn additionally, but the contract-level guard is what matters.

### D5 — No factory, no deployer, no curation

**Decision:** The Sophis core team does **not** publish an "official factory contract", does **not** maintain a "verified guardian registry", does **not** operate a paymaster (when v2 ships paymasters), does **not** recommend any specific wallet UI. Reference contracts ship under AGPL-3.0; deployment is per-user.

**Rationale:** ERC-4337 EntryPoint operates as a singleton on Ethereum mainnet. Several legal-risk analyses have argued that operating an AA-coordinator contract is closer to "service provider" than "tool publisher". By contrast, AGPL-licensed reference contracts deployed user-by-user mirror the legal posture of Bitcoin Core and have survived 15+ years. See `ANTI_PATTERNS.md` §5.

**Implication for maintainers:** if any design decision implies "the core team operates X", reject that decision and redesign. Decision 6 of the 2026-05-04 regulatory pivot is the binding constraint.

### D6 — Owner-key rotation, never key fragmentation

**Decision:** Guardian-based recovery rotates the **owner key**, atomically. Guardians do not hold any portion of the user's signing key. Recovery flow:

1. User loses owner key
2. User contacts ≥M guardians
3. Each guardian independently signs a `RotateOwnerKey { new_owner_pubkey, account_address, nonce }` message
4. M signatures are submitted to `Recovery` contract
5. `Recovery` contract verifies signatures, calls `IAccount.set_owner(new_owner_pubkey)`
6. The user's old key is dead forever; new key controls the account

**Rationale:** The "social recovery" framing common in Web3 marketing (Argent, Loopring) routinely conflates two distinct mechanisms: (a) Shamir-style key fragmentation across guardians (each guardian holds a piece, M pieces reconstruct the key), and (b) authorization to rotate (guardians can authorize a new owner). (a) is **structurally custodial** because guardians collectively hold key material; (b) is not. Sophis implements only (b).

This distinction matters legally (custodian status under MiCA / FATF / FinCEN typically attaches to "control of funds", which (a) creates and (b) does not), and matters technically (Dilithium signing key is 2560 bytes; Shamir-splitting a 2560-byte secret is awkward and has no production-ready library targeting Dilithium key sizes).

**Implication for maintainers:** never accept a design where guardians collectively hold any portion of the owner's signing key. Reject Shamir-style designs explicitly.

### D7 — Signature buffer is variable-length

**Decision:** The wire format for an AA operation includes a length-prefixed signature buffer, not a fixed-size field:

```
[ aav1 magic: 4 B ]
[ operation_count: 1 B (1..=16) ]
[ operation_array: borsh-encoded ]
[ sig_count: 1 B (1..=N) ]
[ sig_array: borsh-encoded Vec<DilithiumSignature> ]
[ scheme_discriminator: 1 B (0x01 = single-key, 0x02 = multi-key, 0x03 = session-key, ...) ]
```

**Rationale:** Multisig (M-of-N) requires N × 2.5 KB signatures. A fixed buffer would either waste space for single-sig or truncate multi-sig. Variable-length is the only honest representation given Dilithium sizes.

**Implication for maintainers:** the sVM `validate` callback must enforce both `sig_count <= N` (wire-level) and the count expected by the chosen `scheme_discriminator`. Mismatch is an authorization failure.

### D8 — State cost is a first-class design concern

**Decision:** Every contract design choice that adds per-account state (guardian list, session-key list, batching nonces, etc.) must include an explicit per-account size estimate, denominated in bytes.

**Rationale:** Each Dilithium pubkey is 1312 bytes. A 5-guardian set is 5 × 1312 = 6.5 KB of permanent on-chain state per account. Multiplied across 1000 accounts, that is 6.5 MB. Across 1M accounts, 6.5 GB. The state-bloat trajectory of an AA system is materially worse than the secp256k1 equivalent (33 B/key), and design must respect that.

**Implication for maintainers:** when adding any new field to `IAccount`, `Recovery`, `SessionKey`, or `Batching`, document the worst-case per-account byte cost in the contract source. Consider Merkle-tree-of-pubkeys patterns (store one root, N pubkeys off-chain) for guardian lists with N > 5.

---

## 4. The four contracts — minimum interface

The signatures below are the **minimum required** by this spec. Implementations may add functions, but may not remove or rename these.

### 4.1 `IAccount`

```rust
trait IAccount {
    /// Called by the sVM when authorizing an inbound operation.
    /// Returns Ok(()) iff the signature(s) authorize the operation(s) per
    /// the account's current owner key OR an active session key.
    fn validate(
        &self,
        operations: &[Operation],
        signature_payload: &SignaturePayload,
    ) -> Result<(), ValidationError>;

    /// Called by the Recovery contract on successful guardian-recovery.
    /// MUST verify that the caller is the contract address registered as
    /// this account's recovery contract.
    fn set_owner(&mut self, new_owner: DilithiumPubKey) -> Result<(), AuthError>;

    /// The currently authorized owner key.
    fn owner(&self) -> &DilithiumPubKey;

    /// Wire-format version this account understands. v1 returns AccountVersion::V1.
    fn version(&self) -> AccountVersion;
}
```

### 4.2 `Recovery`

```rust
trait Recovery {
    /// Initialize: bind this Recovery contract to a single IAccount and
    /// declare the guardian set + threshold. Both M and N are checked
    /// against D4 conservative defaults.
    fn init(
        &mut self,
        account: ContractAddress,
        guardians: Vec<DilithiumPubKey>,  // N keys, MIN 3, MAX 16
        threshold: u8,                     // M, MIN 3
    ) -> Result<(), InitError>;

    /// Rotate the bound IAccount's owner key. Requires `threshold` valid
    /// signatures from members of the guardian set over the message
    /// `RotateOwnerKey { new_owner, account, nonce }`. The contract
    /// MUST verify each signature individually (no aggregate scheme in v1).
    fn rotate_owner(
        &mut self,
        new_owner: DilithiumPubKey,
        signatures: Vec<(DilithiumPubKey, DilithiumSignature)>,
    ) -> Result<(), RecoveryError>;

    /// Replace a single guardian (e.g., guardian lost their key).
    /// Requires `threshold` signatures from OTHER guardians over the
    /// message `ReplaceGuardian { old, new, nonce }`.
    fn replace_guardian(
        &mut self,
        old: DilithiumPubKey,
        new: DilithiumPubKey,
        signatures: Vec<(DilithiumPubKey, DilithiumSignature)>,
    ) -> Result<(), RecoveryError>;

    /// Read-only: current guardian set + threshold.
    fn guardians(&self) -> (&[DilithiumPubKey], u8);
}
```

### 4.3 `SessionKey`

```rust
trait SessionKey {
    /// Owner authorizes a new session key with bounded scope.
    fn add_session_key(
        &mut self,
        session_pubkey: DilithiumPubKey,
        expiry_unix_seconds: u64,        // MUST be <= now + 7 days (D4)
        max_total_value: u64,             // sompi cap; 0 = no value transfers
        contract_whitelist: Vec<ContractAddress>,  // empty = no calls allowed
        owner_signature: DilithiumSignature,
    ) -> Result<(), AuthError>;

    /// Revoke a session key immediately. Owner OR the session key itself
    /// may revoke (a session key revoking itself is useful for "logout").
    fn revoke_session_key(
        &mut self,
        session_pubkey: DilithiumPubKey,
        signature: DilithiumSignature,
    ) -> Result<(), AuthError>;

    /// Used by IAccount.validate when authorizing with a session key.
    /// Returns Ok iff the session key is active, not expired, has remaining
    /// allowance, and the operations target only whitelisted contracts.
    fn validate_session(
        &self,
        session_pubkey: &DilithiumPubKey,
        operations: &[Operation],
    ) -> Result<(), ValidationError>;
}
```

### 4.4 `Batching`

```rust
trait Batching {
    /// Dispatch a batch of operations atomically. Either all succeed or
    /// none take effect. Authorization is a single call to IAccount.validate
    /// over the entire batch; child operations do NOT each authorize
    /// separately.
    ///
    /// MUST enforce operations.len() <= 64 (D4 hard upper bound).
    fn dispatch_batch(
        &mut self,
        account: ContractAddress,
        operations: Vec<Operation>,
        signature_payload: SignaturePayload,
    ) -> Result<(), BatchError>;
}
```

---

## 5. Wire format

The AA wire format is borsh-encoded with a fixed magic-bytes prefix.

### 5.1 Container

```
+------------------------+--------+
| magic                  | 4 B    |  "aav1" = 0x61 0x61 0x76 0x31
+------------------------+--------+
| operation_count        | 1 B    |  1..=16 (D4)
+------------------------+--------+
| operations             | varies |  borsh-encoded Vec<Operation>
+------------------------+--------+
| signature_payload      | varies |  see §5.2
+------------------------+--------+
```

### 5.2 SignaturePayload

```rust
enum SignaturePayload {
    /// Single key: owner signature OR session-key signature.
    SingleKey {
        scheme: u8,                           // 0x01 = owner, 0x03 = session
        signer: DilithiumPubKey,              // 1312 B
        signature: DilithiumSignature,        // 2420 B
    },

    /// Multi-key: M-of-N owner signatures (if account is configured as multisig).
    /// Signatures must be in lexicographic order of the signer pubkey.
    MultiKey {
        scheme: u8,                           // 0x02
        signers: Vec<(DilithiumPubKey, DilithiumSignature)>,  // M entries
    },

    /// Reserved for future schemes (aggregate signatures, etc.).
    /// v1 implementations MUST reject this variant.
    Future {
        scheme: u8,
        payload: Vec<u8>,
    },
}
```

Total wire size for a single-sig single-operation transaction: ~3.8 KB. For 3-of-5 multisig: ~12 KB. Block-mass implications must be re-validated against current Sophis BPS during testnet.

---

## 6. Threat model

The threat model lists, for each adversary, what they can do and what the design assumes they cannot.

### 6.1 Owner-key compromise

**Adversary can:** sign arbitrary operations on behalf of the account, including draining funds.

**Design provides:** guardian-based recovery — within hours, the user gathers M guardian signatures and rotates the owner key, killing the attacker's access. The window between compromise and rotation is the user's loss. Vault patterns (K5, future) extend this with timelock.

**Design does not provide:** instant revocation. There is no "panic button" in v1; the user must coordinate guardians.

### 6.2 Single guardian compromise

**Adversary can:** sign as that one guardian.

**Design provides:** with M ≥ 3, no single guardian can rotate the owner key. Honest user uses `replace_guardian` to remove the compromised guardian.

**Design does not provide:** automatic detection of guardian compromise. User responsibility.

### 6.3 M-of-N guardian collusion

**Adversary controls:** ≥ M guardians.

**Design provides:** **nothing**. Collusive guardians can rotate the owner key to any address they choose. This is a fundamental property of M-of-N recovery and is irreducible.

**Mitigation guidance for users (NOT for the contract):** choose guardians whose collusion is implausible — different jurisdictions, different relationships, different devices. The wallet UI may warn, but the contract cannot enforce this.

### 6.4 Session-key compromise

**Adversary can:** sign within the session-key scope (allowance, contract whitelist, expiry).

**Design provides:** bounded blast radius — even total compromise cannot exceed the configured allowance. Owner can revoke at any time.

**Design does not provide:** zero-knowledge session validation. The session-key public key is on-chain; an attacker who learns the corresponding private key has the same scope as the legitimate session.

### 6.5 Replay across networks

**Adversary can:** capture a signed AA payload from testnet, attempt to replay on mainnet (or vice-versa).

**Design provides:** cross-network replay protection via the same mechanism Sophis already uses — sighash includes network-distinguishing data, so a signature for `sophis:` is invalid for `sophistest:`.

### 6.6 Replay within network (same account)

**Adversary can:** capture a signed AA payload, replay it in the same account.

**Design provides:** every `Operation` includes an account-level monotonic nonce; the contract MUST track the next-expected nonce and reject any operation whose nonce is not exactly that value.

### 6.7 Cross-account contract impersonation

**Adversary deploys:** a contract pretending to be `IAccount`, tries to interact with `Recovery` or `Batching`.

**Design provides:** `Recovery` contracts are bound to exactly one `IAccount` address at `init()` and refuse to operate on any other. `Batching` contracts verify the `account` parameter is a known IAccount via address-format check or whitelist.

### 6.8 What is NOT in the threat model

- **Network-level attacks** (sybil, eclipse, etc.) — these belong to the Sophis consensus layer, not AA.
- **Quantum attacks on Dilithium** — explicitly out of scope. Dilithium ML-DSA-44 was selected by NIST as quantum-resistant; if it is broken, all of Sophis breaks, not just AA.
- **Side-channel attacks on Dilithium signing** — wallet implementer responsibility.
- **Phishing the user into deploying a malicious account contract** — UX responsibility, not protocol.

---

## 7. Test vectors plan

Reference test vectors live in `TEST_PLAN.md` (next session). Minimum required vectors before RFC freeze:

1. **Single-sig owner authorization** — derive a Dilithium keypair from a canonical mnemonic, deploy `IAccount`, sign a transfer, verify acceptance.
2. **Owner-key rotation via 3-of-5 guardians** — five guardian keypairs from canonical mnemonics, three sign a `RotateOwnerKey`, verify owner change.
3. **Session-key bounded scope** — owner adds session key with allowance 100 SPHS; session signs three transfers totaling 80 SPHS (accept), then signs a 50 SPHS transfer (reject — exceeds remaining allowance).
4. **Batched operation atomicity** — batch of 5 transfers; verify all succeed; in a separate test, batch with a deliberately-invalid 3rd op; verify all 5 are rolled back (none of them apply).
5. **Replay rejection** — submit a valid operation; submit it again; verify second submission fails on nonce mismatch.
6. **Cross-network replay rejection** — sign a `sophistest:` operation, attempt to submit to a `sophis:` node; verify rejection.
7. **Invalid-version rejection** — submit a wire payload with magic bytes `aav2`; verify v1 implementations reject with `UnsupportedVersion`.
8. **Configuration boundary tests** — attempt to init Recovery with M=2 (should reject), N=2 (should reject), session expiry 30 days (should reject).

Maintainers MUST add additional adversarial vectors discovered during testnet — see `TEST_PLAN.md` (forthcoming).

---

## 8. Dilithium-specific implementation notes

### 8.1 Sizes

| Component | Bytes | Source |
|---|---|---|
| Verification key | 1312 | FIPS 204, ML-DSA-44 |
| Signing key | 2560 | FIPS 204, ML-DSA-44 |
| Signature | 2420 | FIPS 204, ML-DSA-44 |
| Single-sig auth payload (1 sig + magic + nonce) | ~3800 | Engineered |
| 3-of-5 multisig auth payload | ~11800 | Engineered |
| 5-guardian Recovery state | ~6560 | 5 × 1312 |

### 8.2 No HD derivation

Sophis derives a single Dilithium keypair from a 24-word BIP-39 mnemonic via PBKDF2 → first 32 bytes as the ML-DSA-44 randomness input. There is **no** hierarchical deterministic derivation for Dilithium in 2026, and this spec does not assume one will exist.

Implication: each guardian, each session key, and each owner key is generated from a separate seed (or, equivalently, from separate randomness). There is no `m/44'/.../i'` path for Dilithium child keys; do not encode one into the spec.

If a NIST-blessed HD scheme for ML-DSA emerges post-spec-freeze, `Recovery` and `SessionKey` contracts can be amended via SIP to accept derivation paths in their key-add functions. This change would be additive (existing contracts remain valid) and does not require hard fork.

### 8.3 Migration path to ML-DSA-65 / ML-DSA-87

ML-DSA-44 may eventually be deprecated in favor of ML-DSA-65 or ML-DSA-87 (higher security parameters, larger keys/signatures). The migration path:

1. SIP defines wire-format magic `aav2` with `DilithiumML65` and `DilithiumML87` variants in the signature scheme enum.
2. New `IAccount` v2 contracts accept both v1 and v2 keys, allowing accounts to add stronger keys without rotating to a new contract.
3. Recovery contracts gain a `set_owner_key_scheme(scheme)` function that lets the account migrate from ML44 to ML65 atomically.
4. Block-mass model is re-validated for the larger signatures (ML-DSA-87 is ~4.6 KB per signature).

Implementers SHOULD design v1 with the v2 migration in mind — for example, wire-format `scheme` byte should be a u8 even though only `0x01` is valid in v1, so that `0x02` and `0x03` are reserved.

### 8.4 No hybrid (classical + PQ) signatures

Some chains have proposed hybrid schemes (ECDSA + Dilithium) for "defense in depth". Sophis explicitly rejects this: the chain is PQC-only at consensus, and hybrid signatures invite incompatibility with that invariant. If ML-DSA-44 is later considered insufficient, the migration is to ML-DSA-65 / -87 (still PQC), not to hybrid.

---

## 9. Operational boundaries — text from `OPERATIONAL_BOUNDARIES_PARAGRAPH.md`

The following text is quoted from `OPERATIONAL_BOUNDARIES_PARAGRAPH.md` and is to be inserted verbatim into the project's `OPERATIONAL_BOUNDARIES.md` and whitepaper §11 once any reference contract from this spec is published as code (not before).

> Account abstraction reference contracts and SDK are released open-source under AGPL-3.0. The core team does not operate, host, custody, or recover any user account. Guardians for any account are chosen exclusively by the account holder; the project does not curate, verify, or recommend guardian sets. There is no official factory contract, no official paymaster, no official wallet UI. Reference contracts are templates for third-party deployment, identical in legal posture to Bitcoin Core wallet code.

The text exists as a separate file rather than being embedded here so that the canonical version travels with the operational documentation, not the spec.

---

## 10. Out-of-scope (deferred or rejected)

| Topic | Status | Reasoning |
|---|---|---|
| Paymasters | **v2** | Paymaster operations create jurisdictional risk profile distinct from contract publishing. Defer until v1 has 12+ months of production data and a separate SIP justifies the addition. |
| Aggregate Dilithium signatures | **research** | No production-ready scheme exists in 2026. When one matures, a separate spec adds it as a new `SignaturePayload` variant. |
| MPC signers | **research** | Same reasoning as aggregate signatures. |
| OAuth / zkLogin / WebAuthn integration | **rejected permanently** | See `ANTI_PATTERNS.md` §3. Couples user wallets to centralized identity providers and (zkLogin specifically) to non-PQC proof systems. |
| ENS-style human-readable names | **out of scope** | Identity layer is intentionally NOT a Sophis core concern. Third parties may build naming systems in sVM if they wish. |
| Account-bound social media identity | **rejected** | Same reasoning as OAuth — couples to off-chain centralized services. |
| Zero-knowledge proof of guardian-recovery | **deferred to research** | Could hide guardian identities; current design treats guardian pubkeys as public, which is acceptable for v1. |
| Insurance / dispute resolution / chargeback | **out of scope** | Custodial framing; structurally incompatible with non-custodial design. |

---

## 11. RFC publication checklist

Before this spec is published as a SIP for community review, maintainers MUST:

- [ ] Verify `CONVERGENCE.md` claims against current ERC-4337, ERC-7702, Aptos AA, Starknet, zkSync IAccount specs (the founder's knowledge cutoff is 2026-01; some details may have evolved)
- [ ] Validate Dilithium block-mass numbers in §5 against current Sophis BPS / mass parameters
- [ ] Add at least 3 additional adversarial test vectors per category
- [ ] Open a GitHub Discussion announcing the RFC and inviting comment
- [ ] Set the public-comment window to 30 days minimum
- [ ] Track each comment in a SIP discussion thread; respond or close each before the no-changes period
- [ ] Run a 60-day no-changes period after the comment window closes
- [ ] Publish a reference implementation in `wallet/aa/` (NOT this `aa-spec/` directory) gated by `[cfg(feature = "experimental-aa")]` for testnet validation
- [ ] Run the testnet validation for ≥6 months with bug bounty open
- [ ] If no critical issues, publish mainnet beta with reference wallet for ≥90 days
- [ ] Only then: freeze the spec, declare v1, and publish the SIP as accepted

This checklist is the single most important contribution this document makes. Bypassing it is the failure mode the spec exists to prevent.

---

## 12. Document conventions

- **MUST / MUST NOT / SHOULD / SHOULD NOT / MAY** are used per RFC 2119.
- Code blocks use Rust syntax even where the actual implementation may be in WASM-compiled languages other than Rust. The Rust syntax is illustrative.
- Byte sizes are decimal (1 KB = 1000 B, 1 MB = 1,000,000 B). Where binary matters (memory page sizes), this is called out explicitly.
- "v1" refers to this spec's first frozen revision. There is no v0 — pre-RFC drafts are this document's revision history, not a numbered version.

---

## 13. Last touched

2026-05-09 — initial pre-RFC draft, prepared by founder. See `README.md` for status and process.
