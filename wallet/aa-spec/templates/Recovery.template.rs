// =============================================================================
// Recovery.template.rs — REFERENCE TEMPLATE, NOT PRODUCTION CODE
// =============================================================================
//
// Guardian-based recovery contract template — the M-of-N owner-key rotation
// mechanism described in SPEC.md §4.2 / D6. Bound to exactly one IAccount
// instance at init() time.
//
// CRITICAL READING — DO NOT skip:
//   1. wallet/aa-spec/SPEC.md §3 D6 — owner-key rotation, NEVER fragmentation
//   2. wallet/aa-spec/ANTI_PATTERNS.md §1 — custodial fragmentation rejected
//   3. wallet/aa-spec/ANTI_PATTERNS.md §2 — "social recovery" linguistic anti-pattern
//   4. wallet/aa-spec/ANTI_PATTERNS.md §5 — guardian registry / curated guardians anti-pattern
//
// The vocabulary in this file deliberately avoids "social recovery". Use
// "guardian-based recovery" everywhere — including comments, error messages,
// and documentation generated from this file.
//
// Author: Marcelo Delgado <sophis-network@proton.me>
// Date:   2026-05-09
// =============================================================================

#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::result_large_err)]

// Reuses constants and type aliases from IAccount.template.rs in the same
// directory. In a real implementation crate, these will live in a shared
// `aa::types` module.
use super::IAccount; // template-only; production crate will refactor
use super::{ContractAddress, DilithiumPubKey, DilithiumSignature};

// -----------------------------------------------------------------------------
// CONSERVATIVE DEFAULTS — SPEC.md D4.
//
// These are HARD FLOORS. The contract MUST reject configurations below them.
// Wallet UI may suggest higher values; it MUST NOT pass through values lower.
//
// Rationale: the most common AA-related failure mode is wallets that ship 1-of-1
// "recovery" via a single email or SMS, which is functionally not recovery at
// all and trivially defeats the security model. Encoding the floor in the
// contract removes the tempting wallet-UX shortcut.
// -----------------------------------------------------------------------------

/// Minimum number of guardians (N). MUST NOT be lowered.
pub const MIN_GUARDIAN_COUNT: u8 = 3;

/// Maximum number of guardians (N). Above this, state cost (1.3 KB per pubkey)
/// becomes uncomfortable. SPEC.md D8 — state cost as design concern.
pub const MAX_GUARDIAN_COUNT: u8 = 16;

/// Minimum recovery threshold (M). MUST NOT be lowered.
/// Note: M=2 is rejected because two guardians is "two friends colluding"
/// territory. M=3 forces a meaningful coordination cost on attackers.
pub const MIN_RECOVERY_THRESHOLD: u8 = 3;

/// State-cost constant (informational, used in budget checks).
/// Each guardian's pubkey is 1312 bytes; full N=5 set is 6.5 KB per account.
pub const PUBKEY_BYTES_PER_GUARDIAN: usize = 1312;

// -----------------------------------------------------------------------------
// State — bound to one IAccount instance.
// -----------------------------------------------------------------------------

#[derive(Debug)]
pub struct RecoveryState {
    /// The IAccount this Recovery contract is bound to. Set at init() and
    /// never changes. Recovery operates only on this account.
    bound_account: ContractAddress,

    /// Guardian public keys, ordered lexicographically. Lexicographic
    /// ordering makes signature-set replay across orderings detectable.
    /// IMPLEMENTATION NOTE: storing N pubkeys at 1.3 KB each is significant
    /// state — consider Merkle-tree-of-pubkeys for N > 5 (see SPEC.md D8).
    guardians: Vec<DilithiumPubKey>,

    /// M (recovery threshold). Always satisfies M >= MIN_RECOVERY_THRESHOLD.
    threshold: u8,

    /// Monotonic nonce for recovery operations.
    /// SPEC.md §6.6 — replay protection. Increments on every successful
    /// rotate_owner / replace_guardian; never decrements.
    nonce: u64,
}

// -----------------------------------------------------------------------------
// Errors — keep granular, action-specific.
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitError {
    /// Caller already initialized this contract; double-init forbidden.
    AlreadyInitialized,

    /// Guardian count below MIN_GUARDIAN_COUNT or above MAX_GUARDIAN_COUNT.
    GuardianCountOutOfRange { count: u8, min: u8, max: u8 },

    /// Threshold (M) below MIN_RECOVERY_THRESHOLD or above guardian count.
    ThresholdOutOfRange { threshold: u8, min: u8, max_for_count: u8 },

    /// Duplicate pubkey in guardian list — each guardian must be distinct.
    DuplicateGuardian(DilithiumPubKey),

    /// Bound account address is structurally invalid.
    InvalidAccountAddress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    /// Insufficient signatures to meet threshold.
    NotEnoughSignatures { provided: usize, required: u8 },

    /// One of the provided signatures is from a key that is not a guardian.
    NonGuardianSigner(DilithiumPubKey),

    /// Same guardian provided multiple signatures (only one counts; this
    /// is rejected to make signature counts unambiguous).
    DuplicateSigner(DilithiumPubKey),

    /// One of the signatures failed cryptographic verification.
    InvalidSignature { signer: DilithiumPubKey },

    /// Nonce in the signed message does not match expected next nonce.
    /// SPEC.md §6.6.
    NonceMismatch { expected: u64, found: u64 },

    /// `replace_guardian` was called with `old` not in the guardian set.
    GuardianNotFound(DilithiumPubKey),

    /// `replace_guardian` was called with `new` already in the guardian set.
    GuardianAlreadyExists(DilithiumPubKey),

    /// Calling `replace_guardian`, the signing set included the guardian
    /// being replaced (logically inconsistent — they cannot vote on their
    /// own removal).
    SignerIsBeingReplaced(DilithiumPubKey),

    /// Recovery contract was not initialized before this call.
    NotInitialized,
}

// -----------------------------------------------------------------------------
// Recovery trait — the contract surface.
//
// IMPLEMENTATION REQUIRED for every method below.
// -----------------------------------------------------------------------------

pub trait Recovery {
    /// Bind this Recovery contract to one IAccount and declare the guardian
    /// set + threshold. Can be called exactly ONCE per contract instance.
    ///
    /// IMPLEMENTATION REQUIRED:
    ///   1. Check the contract is not already initialized.
    ///   2. Validate `guardians.len()` is in [MIN, MAX].
    ///   3. Validate `threshold` is in [MIN, guardians.len()].
    ///   4. Validate no duplicate pubkeys (compare canonical encoding).
    ///   5. Validate `account` is a structurally-valid contract address.
    ///   6. Sort guardians lexicographically (canonical state representation).
    ///   7. Initialize nonce to 0.
    fn init(
        &mut self,
        account: ContractAddress,
        guardians: Vec<DilithiumPubKey>,
        threshold: u8,
    ) -> Result<(), InitError> {
        unimplemented!(
            "Recovery::init — see wallet/aa-spec/SPEC.md §4.2 + this file's MIN/MAX constants. \
             This template is not production code; implement after the SIP/RFC process closes."
        )
    }

    /// Rotate the bound IAccount's owner key. Triggered when the account
    /// holder loses or compromises the owner key.
    ///
    /// `signatures` is a Vec of (guardian_pubkey, signature) pairs over the
    /// canonical message:
    ///
    ///     RotateOwnerKey {
    ///         new_owner: DilithiumPubKey,
    ///         account: ContractAddress,
    ///         nonce: u64,
    ///     }
    ///
    /// IMPLEMENTATION REQUIRED:
    ///   1. Verify contract is initialized (`bound_account` is set).
    ///   2. Verify `signatures.len() >= threshold`.
    ///   3. For each signature pair:
    ///      a. Verify signer is a current guardian.
    ///      b. Verify signature cryptographically against the canonical message.
    ///      c. Track signers seen — reject DuplicateSigner.
    ///   4. After all signatures verified, count distinct guardians signed.
    ///      MUST be >= threshold.
    ///   5. Verify the canonical message's `nonce` field equals `self.nonce`.
    ///   6. Atomically:
    ///      a. Increment `self.nonce`.
    ///      b. Call `IAccount::set_owner(new_owner)` on `bound_account`.
    ///   7. Emit a `OwnerRotated` event with old_owner, new_owner, nonce.
    ///
    /// MUST NOT:
    ///   - Allow the old owner to participate as a "guardian" — owner key is
    ///     the asset being rotated; using it would defeat the recovery logic.
    ///     The contract enforces this by maintaining a strict guardian-list
    ///     check that does not include the owner.
    ///   - Attempt to "merge" or "split" guardian signatures into any kind of
    ///     aggregate. v1 verifies each signature individually. SPEC.md §3 D6.
    fn rotate_owner(
        &mut self,
        new_owner: DilithiumPubKey,
        signatures: Vec<(DilithiumPubKey, DilithiumSignature)>,
    ) -> Result<(), RecoveryError> {
        unimplemented!(
            "Recovery::rotate_owner — see wallet/aa-spec/SPEC.md §4.2 for required behavior. \
             Linguistic note: this is GUARDIAN-BASED RECOVERY, never 'social recovery'."
        )
    }

    /// Replace one guardian with another. Used when a guardian loses their
    /// key, no longer wishes to participate, or is suspected of compromise.
    ///
    /// `signatures` is a Vec of (guardian_pubkey, signature) pairs over the
    /// canonical message:
    ///
    ///     ReplaceGuardian {
    ///         old: DilithiumPubKey,
    ///         new: DilithiumPubKey,
    ///         account: ContractAddress,
    ///         nonce: u64,
    ///     }
    ///
    /// IMPLEMENTATION REQUIRED:
    ///   1. Verify contract is initialized.
    ///   2. Verify `old` is currently in the guardian list.
    ///   3. Verify `new` is NOT currently in the guardian list.
    ///   4. Verify `signatures.len() >= threshold`.
    ///   5. For each signature pair:
    ///      a. Verify signer is a current guardian.
    ///      b. **Reject if signer == old** — guardian being replaced cannot
    ///         vote on their own removal.
    ///      c. Verify signature cryptographically against canonical message.
    ///      d. Track signers seen — reject DuplicateSigner.
    ///   6. Verify nonce matches.
    ///   7. Atomically:
    ///      a. Increment `self.nonce`.
    ///      b. Replace `old` with `new` in `self.guardians`.
    ///      c. Re-sort `self.guardians` lexicographically.
    ///   8. Emit a `GuardianReplaced` event with old, new, nonce.
    ///
    /// MUST NOT:
    ///   - Allow the guardian being replaced to count as a signer.
    ///   - Allow `replace_guardian` to be used to circumvent the M minimum
    ///     (e.g., by chaining replacements that effectively reduce the
    ///     guardian count). The N count stays constant; only individual
    ///     identities change.
    fn replace_guardian(
        &mut self,
        old: DilithiumPubKey,
        new: DilithiumPubKey,
        signatures: Vec<(DilithiumPubKey, DilithiumSignature)>,
    ) -> Result<(), RecoveryError> {
        unimplemented!(
            "Recovery::replace_guardian — see wallet/aa-spec/SPEC.md §4.2 for required behavior."
        )
    }

    /// Read-only: current guardian list and threshold.
    fn guardians(&self) -> (&[DilithiumPubKey], u8) {
        unimplemented!("Recovery::guardians — read accessor for state.")
    }

    /// Read-only: bound IAccount address.
    fn bound_account(&self) -> &ContractAddress {
        unimplemented!("Recovery::bound_account — read accessor for state.")
    }

    /// Read-only: next expected recovery nonce. Increments on every successful
    /// rotate_owner / replace_guardian.
    fn nonce(&self) -> u64 {
        unimplemented!("Recovery::nonce — read accessor for state.")
    }
}

// =============================================================================
// Notes — what is intentionally NOT in this trait
// =============================================================================
//
// 1. No `add_guardian()` standalone function.
//    Adding a guardian without removing one would let the user expand the
//    guardian set over time. The current spec prefers fixed N; users who
//    want to change N must redeploy the Recovery contract. This is a
//    deliberate UX trade-off favoring simplicity and auditability.
//    Maintainers MAY revisit this via SIP if usage data shows it is too
//    rigid, but the conservative starting point is "fixed N at init".
//
// 2. No `remove_guardian()` standalone function.
//    Same rationale as #1. Use `replace_guardian` (with `new` being a
//    placeholder address controlled by the user) if a guardian truly
//    needs to be retired.
//    [VERIFY DURING RFC: this leaves the user with N-1 effective guardians
//    if the placeholder is meaningless. Maybe a real `remove` with
//    explicit minimum-count check is better. Solicit comments.]
//
// 3. No `change_threshold()` function.
//    Changing M post-init would let users initially commit to "5 of 7" but
//    later silently weaken to "2 of 7", trivializing the recovery model.
//    Threshold is fixed at init.
//
// 4. No `freeze_account()` / `panic()` / kill switches.
//    ANTI_PATTERNS.md §12. There is no panic button.
//
// 5. No `verify_guardian_identity()` / KYC integration.
//    ANTI_PATTERNS.md §7. The contract verifies signatures, not identities.
//
// 6. No `recover_to_existing_guardian()` shortcut.
//    The new owner key MUST be supplied externally. Auto-promoting a guardian
//    to owner would conflate guardian and owner roles in a way that is hard
//    to reason about and easy to abuse.
//
// 7. No `register_with_directory()` / public guardian registry hooks.
//    ANTI_PATTERNS.md §5. There is no curated directory of guardians.
//    Guardian identities are an off-chain matter between the user and their
//    chosen guardians.
//
// =============================================================================
// User-facing wallet UI guidance (NOT implemented in the contract — for the
// reference wallet's reference; deviating wallets at their own discretion)
// =============================================================================
//
// Suggested guardian categories for wallets to surface in UI:
//
//   - "A second device of yours" (your other phone, hardware wallet, laptop)
//   - "A trusted family member or close friend with crypto experience"
//   - "A trusted colleague or business partner"
//   - "A trustless backup service" (if such a thing exists; treat with skepticism)
//
// Wallets MUST NOT:
//   - Suggest a SPECIFIC named individual or institution as a guardian
//   - Maintain or query a "verified guardian" list
//   - Default to fewer than N=5 guardians (M=3 threshold)
//   - Default to ONE-DEVICE-ONLY guardians ("your phone is enough")
//
// Wallets SHOULD:
//   - Walk the user through generating an independent Dilithium keypair for
//     each guardian, owned by that guardian, never visible to the wallet
//     UI itself
//   - Encourage the user to physically separate guardian devices
//   - Make it visible in UI when fewer than the recommended N are configured
//
// =============================================================================
// Maintainer checklist — Recovery-specific items
// =============================================================================
//
// In addition to the IAccount checklist:
//
// [ ] Verify the canonical message format for signatures matches what the
//     reference wallet implementation produces (cross-validate test vectors)
// [ ] Add adversarial test: collusion of M guardians can rotate the key
//     (this is by design — verify the collusion path works as expected)
// [ ] Add adversarial test: M-1 guardians cannot rotate the key
// [ ] Add adversarial test: guardian-being-replaced cannot count as signer
// [ ] Add adversarial test: replay of a successful rotate_owner call fails
//     on second submission (nonce protection)
// [ ] Stress-test state cost at N=16 guardians; document the per-account
//     storage cost in the SIP
//
// =============================================================================

// Compile-time guard: this template must NEVER ship in a release build.
#[cfg(not(any(test, doc, debug_assertions)))]
compile_error!(
    "wallet/aa-spec/templates/Recovery.template.rs is a SPEC template, not production code. \
     Implement the production Recovery contract in wallet/aa/ after completing the SIP/RFC \
     process described in wallet/aa-spec/README.md."
);
