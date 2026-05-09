// =============================================================================
// IAccount.template.rs — REFERENCE TEMPLATE, NOT PRODUCTION CODE
// =============================================================================
//
// This file is a structural template for the IAccount sVM contract trait that
// future maintainers will implement once the SIP/RFC process closes (see
// `wallet/aa-spec/SPEC.md` §11). It is deliberately NOT part of the workspace
// Cargo.toml and contains `unimplemented!()` markers throughout.
//
// Reading order:
//   1. wallet/aa-spec/SPEC.md  — read end to end first
//   2. wallet/aa-spec/CONVERGENCE.md — understand load-bearing decisions
//   3. wallet/aa-spec/ANTI_PATTERNS.md — what NOT to do
//   4. THIS FILE — the trait shape your implementation must match
//
// Status: pre-RFC draft, NOT a frozen API. Maintainers may propose changes via
// SIP. The shape below is the recommended starting point, not the mandate.
//
// Author: Hiroshi Tatakawa <sophis-network@proton.me>
// Date:   2026-05-09
// =============================================================================

#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::result_large_err)]

// -----------------------------------------------------------------------------
// Dilithium ML-DSA-44 (FIPS 204) sizes — these are constants, do not change.
// Pulled here from `consensus/core/src/sign.rs` and
// `wallet/pskt/src/crypto.rs` so future implementers do not have to chase
// them across the codebase.
// -----------------------------------------------------------------------------

/// ML-DSA-44 verification key, fixed 1312 bytes per FIPS 204.
pub const DILITHIUM44_VK_SIZE: usize = 1312;

/// ML-DSA-44 signature, fixed 2420 bytes per FIPS 204.
pub const DILITHIUM44_SIG_SIZE: usize = 2420;

/// ML-DSA-44 signing key, fixed 2560 bytes per FIPS 204.
/// IAccount itself does not hold signing keys (those stay with the user);
/// listed here for completeness and to discourage anyone from inadvertently
/// embedding a signing key in contract state.
pub const DILITHIUM44_SK_SIZE: usize = 2560;

// -----------------------------------------------------------------------------
// Wire-format magic bytes per SPEC.md §5.1 / D3.
// CRITICAL: every AA wire payload must begin with these four bytes. Any
// payload that does not is not v1 and must be rejected.
// -----------------------------------------------------------------------------

pub const AA_WIRE_MAGIC_V1: [u8; 4] = *b"aav1";

// -----------------------------------------------------------------------------
// Type aliases — concrete types live in the eventual implementation crate
// (probably `wallet/aa/`). Stub types here are placeholder so the trait
// signatures parse.
// -----------------------------------------------------------------------------

pub type DilithiumPubKey = [u8; DILITHIUM44_VK_SIZE];
pub type DilithiumSignature = [u8; DILITHIUM44_SIG_SIZE];

/// sVM contract address. Real type lives in `consensus/core` or
/// `oracle/host`; this is a placeholder.
pub type ContractAddress = [u8; 32];

// -----------------------------------------------------------------------------
// Account version enum — D3 type-system component.
// MUST be exhaustively matched in any code that consumes it.
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AccountVersion {
    /// IAccount v1 — this template's frozen-on-RFC-closure version.
    V1,
    // Future versions added here via SIP. Wire-format magic advances in
    // lockstep (`aav2`, `aav3`, …).
    //
    // V2 is reserved for: ML-DSA-65 / -87 support, possible aggregate
    // signature variant, possible HD-derivation if a NIST scheme emerges.
    // See SPEC.md §8.3 for the migration model.
}

// -----------------------------------------------------------------------------
// Operation — single state-changing intent.
//
// IMPLEMENTATION REQUIRED: this enum MUST cover at minimum the operations
// listed below. Maintainers MAY add variants but MUST NOT remove or rename
// existing ones (wire-format stability).
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Operation {
    /// Transfer SPHS from this account to a recipient address.
    Transfer {
        recipient: ContractAddress,
        amount_sompi: u64,
    },

    /// Call another sVM contract with calldata.
    ContractCall {
        target: ContractAddress,
        calldata: Vec<u8>,
        value_sompi: u64,
    },

    /// Reserved for future operation types (e.g. token operations once
    /// Native Tokens L1 spec is finalized). v1 implementations MUST
    /// reject this variant when encountered in a wire payload.
    Future {
        op_type: u8,
        payload: Vec<u8>,
    },
}

// -----------------------------------------------------------------------------
// SignaturePayload — per SPEC.md §5.2.
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum SignaturePayload {
    /// Single key authorization (owner OR session key).
    /// `scheme` byte: 0x01 = owner, 0x03 = session key.
    SingleKey {
        scheme: u8,
        signer: DilithiumPubKey,
        signature: DilithiumSignature,
    },

    /// Multi-key authorization — M-of-N owner signatures.
    /// `scheme` byte: 0x02.
    /// IMPLEMENTATION REQUIRED: enforce lexicographic ordering of signers
    /// to make signature replay across orderings impossible.
    MultiKey {
        scheme: u8,
        signers: Vec<(DilithiumPubKey, DilithiumSignature)>,
    },

    /// Reserved for future signature schemes (aggregate signatures, etc.).
    /// v1 implementations MUST reject this variant.
    Future {
        scheme: u8,
        payload: Vec<u8>,
    },
}

// -----------------------------------------------------------------------------
// Errors — keep granular so callers can act on specific failure modes.
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Payload's magic bytes were not `aav1`. SPEC.md D3.
    UnsupportedVersion { found: [u8; 4] },

    /// Operation count outside [1, 16]. SPEC.md D4.
    OperationCountOutOfRange { count: usize, max: usize },

    /// Signature verification failed (Dilithium verify returned error).
    InvalidSignature,

    /// Signer is not currently authorized (not owner key, not active session).
    UnauthorizedSigner,

    /// `Future` variant of `SignaturePayload` or `Operation` encountered.
    /// v1 always rejects these. SPEC.md D3 + §5.2.
    FutureVariantRejectedByV1,

    /// Nonce mismatch — replay attempt or out-of-order. SPEC.md §6.6.
    NonceMismatch { expected: u64, found: u64 },

    /// Other validation failure (specific reason in message).
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// Caller is not authorized to invoke this function.
    /// For `set_owner`, this means caller is not the bound Recovery contract.
    NotAuthorized,

    /// Owner-key bytes failed structural validation (length, etc.).
    InvalidOwnerKey,
}

// =============================================================================
// IAccount — the trait every account contract must implement.
//
// The validate-then-execute split mirrors ERC-4337's `validateUserOp` /
// `execute` pattern (CONVERGENCE.md row "Authorization via contract-defined
// validate callback"; 4-of-5 chains converge).
// =============================================================================

pub trait IAccount {
    // -------------------------------------------------------------------------
    // CORE — every implementation MUST provide these four methods exactly.
    // -------------------------------------------------------------------------

    /// Called by the sVM when authorizing an inbound batch of operations.
    ///
    /// Implementation MUST:
    ///   1. Verify the wire-format magic is `AA_WIRE_MAGIC_V1`.
    ///   2. Verify operation count is in [1, 16] (SPEC.md D4).
    ///   3. For SingleKey scheme=0x01: verify signature against current owner key.
    ///   4. For SingleKey scheme=0x03: delegate to SessionKey contract's
    ///      `validate_session` method.
    ///   5. For MultiKey scheme=0x02 (if account configured as multisig):
    ///      verify each (pubkey, signature) pair, count distinct authorized
    ///      pubkeys, and check threshold.
    ///   6. For Future variants: return `FutureVariantRejectedByV1`.
    ///   7. Verify nonce equals expected_next_nonce; on success, increment.
    ///
    /// MUST NOT:
    ///   - Mutate any state OTHER than the nonce counter.
    ///   - Call any external contract.
    ///   - Allocate dynamically beyond bounded size.
    ///
    /// IMPLEMENTATION REQUIRED.
    fn validate(
        &mut self,
        operations: &[Operation],
        signature_payload: &SignaturePayload,
    ) -> Result<(), ValidationError> {
        unimplemented!(
            "IAccount::validate — see wallet/aa-spec/SPEC.md §4.1 for required behavior. \
             This template is not production code; implement after the SIP/RFC process closes."
        )
    }

    /// Called by the bound Recovery contract when guardian-recovery has
    /// successfully verified M-of-N guardian signatures and produced a new
    /// owner key.
    ///
    /// Implementation MUST:
    ///   1. Verify the caller's address matches the Recovery contract address
    ///      registered in this account's state.
    ///   2. Validate `new_owner` length and structural sanity.
    ///   3. Replace the stored owner key atomically.
    ///   4. Emit a clearly-named event so wallets / explorers can detect the
    ///      rotation (this is the user's only signal that recovery happened).
    ///
    /// MUST NOT:
    ///   - Allow owner-only authorization to invoke this method.
    ///     (The whole point of recovery is that the owner key is lost or
    ///     compromised; if owner authorization were accepted, attacker
    ///     could lock out the legitimate user.)
    ///
    /// IMPLEMENTATION REQUIRED.
    fn set_owner(&mut self, new_owner: DilithiumPubKey) -> Result<(), AuthError> {
        unimplemented!(
            "IAccount::set_owner — see wallet/aa-spec/SPEC.md §4.1 for required behavior."
        )
    }

    /// Read-only: the currently authorized owner public key.
    ///
    /// IMPLEMENTATION REQUIRED.
    fn owner(&self) -> &DilithiumPubKey {
        unimplemented!("IAccount::owner — read accessor for stored owner key.")
    }

    /// Read-only: this implementation's wire-format version.
    /// v1 implementations return `AccountVersion::V1`.
    ///
    /// IMPLEMENTATION REQUIRED.
    fn version(&self) -> AccountVersion {
        AccountVersion::V1
    }

    // -------------------------------------------------------------------------
    // OPTIONAL — implementations MAY override these for richer behavior.
    // Default impls below provide minimum sane behavior.
    // -------------------------------------------------------------------------

    /// Optional: dispatch a single operation after `validate` has succeeded.
    /// The default implementation handles `Transfer` and `ContractCall`;
    /// `Future` variants are rejected.
    ///
    /// Implementations that need transaction-tracing (logging, analytics,
    /// circuit-breakers) override this to inject behavior.
    fn execute_operation(&mut self, op: &Operation) -> Result<(), ValidationError> {
        match op {
            Operation::Transfer { .. } => {
                unimplemented!("execute_operation:Transfer — invoke sVM transfer primitive")
            }
            Operation::ContractCall { .. } => {
                unimplemented!("execute_operation:ContractCall — invoke sVM contract-call primitive")
            }
            Operation::Future { .. } => Err(ValidationError::FutureVariantRejectedByV1),
        }
    }
}

// =============================================================================
// Notes on what is intentionally NOT in this trait
// =============================================================================
//
// 1. No `recover()` method on IAccount.
//    Recovery is a SEPARATE CONTRACT (D2). IAccount only exposes `set_owner`,
//    which the Recovery contract calls. This separation is load-bearing:
//    putting recovery logic inside IAccount would (a) bloat per-account state,
//    (b) couple recovery upgrades to account upgrades, and (c) make the
//    "guardians do not custody fragments" framing harder to maintain.
//
// 2. No `add_session_key()` / `revoke_session_key()` on IAccount.
//    Same reason: SessionKey is a separate contract (D2). IAccount only knows
//    "is this signer a valid session key?" by delegating to SessionKey contract.
//
// 3. No `dispatch_batch()` on IAccount.
//    The Batching contract is the dispatcher; IAccount just validates. This
//    lets multiple Batching strategies coexist (atomic-revert, partial-commit,
//    custom error handling) without forking IAccount itself.
//
// 4. No `freeze()` / `pause()` / `kill()` methods.
//    Anti-pattern §12 — kill switches are rejected. There is no global pause.
//
// 5. No `ENS / name registration` methods.
//    Anti-pattern §11 — identity layer is intentionally NOT a Sophis core
//    concern. Third parties may build naming systems, but not via IAccount.
//
// 6. No `oauth_login()` / `webauthn_attest()` / `zk_login()` methods.
//    Anti-pattern §3 — permanently rejected. Wallet keys are Dilithium,
//    period.
//
// 7. No `insurance_claim()` / `chargeback()` methods.
//    Anti-pattern §8 — protocol does not provide custodial recovery
//    semantics. Third-party insurance can be built on top.
//
// =============================================================================
// Maintainer checklist before implementing this trait
// =============================================================================
//
// Before writing the first line of production IAccount code:
//
// [ ] Read SPEC.md end to end
// [ ] Read CONVERGENCE.md, particularly §3 (divergence — what NOT to copy)
// [ ] Read ANTI_PATTERNS.md, all 13 sections
// [ ] Open a SIP titled "SIP-N: Account Abstraction v1 reference contracts"
// [ ] Run a 30-day public comment period; respond to or close every comment
// [ ] Run a 60-day no-changes period after comments close
// [ ] Implement contracts under `wallet/aa/` (NOT this `aa-spec/` directory)
//     gated by `[cfg(feature = "experimental-aa")]` so the build does not
//     ship them by default
// [ ] Run a 6-month testnet validation with a public bug bounty
// [ ] Run a 90-day mainnet beta with a reference wallet
// [ ] Only then declare v1, freeze the spec, and publish the SIP as accepted
//
// Bypassing any step above defeats the purpose of this template existing.
// The whole point of pre-RFC spec discipline is that AA gets exactly one
// chance to ship correctly; rushing it produces a Phase-4-class problem.
//
// =============================================================================

// Compile-time assertion: this file must NEVER be added to a production build.
// If you see this assertion firing in CI, someone added `aa-spec` to the
// workspace Cargo.toml — back that change out.
#[cfg(not(any(test, doc, debug_assertions)))]
compile_error!(
    "wallet/aa-spec/templates/IAccount.template.rs is a SPEC template, not production code. \
     It must not be compiled in release builds. Implement the production trait in wallet/aa/ \
     after completing the SIP/RFC process described in wallet/aa-spec/README.md."
);
