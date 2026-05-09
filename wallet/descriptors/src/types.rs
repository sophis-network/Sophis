//! Core types — `Descriptor` enum and supporting structures.
//!
//! See `wallet/descriptors/DESIGN.md` §4 (grammar) and §3 (decisions D1–D5).

use sophis_wallet_pskt::crypto::DilithiumPubKey;

use crate::fingerprint::Fingerprint;

/// A wallet descriptor — the textual identity of a Sophis wallet.
///
/// v1 supports two script types: `pkh-mldsa44` (single-sig) and
/// `multi-mldsa44` (k-of-n; parsed-only, see DESIGN.md D2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Descriptor {
    /// Pay-to-pubkey-hash, single Dilithium key. Script: `pkh-mldsa44(<key>)`.
    Pkh { key: DescriptorKey },

    /// k-of-n multisig over Dilithium keys. Script:
    /// `multi-mldsa44(<threshold>, <key>, <key>, ..., <key>)`.
    ///
    /// **v1 parses and serializes this form but `resolve()` returns
    /// `MultiSigNotYetSupported` (D2).** Real multisig depends on
    /// Account Abstraction (J1, see `wallet/aa-spec/`).
    Multi {
        /// `threshold` ∈ [1, keys.len()], with maximum keys.len() = 15.
        threshold: u32,
        keys: Vec<DescriptorKey>,
    },
}

/// A key entry inside a descriptor — public key data plus optional origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorKey {
    pub origin: Option<KeyOrigin>,
    pub data: KeyData,
}

impl DescriptorKey {
    /// Construct a literal-key entry without origin annotation.
    pub fn new_literal(key: DilithiumPubKey) -> Self {
        Self { origin: None, data: KeyData::VkHex(Box::new(key)) }
    }
}

/// The actual key material in a descriptor. v1 only resolves `VkHex`;
/// `XpubReserved` is parsed for forward-compatibility but rejected at
/// resolve-time (DESIGN.md D1).
///
/// `VkHex` is boxed to avoid `large_enum_variant` clippy warning — the
/// 1312-byte Dilithium key would dwarf the small `XpubReserved` string by
/// 50×. Boxing is purely an in-memory layout optimization; the wire/text
/// format is unaffected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyData {
    /// Literal Dilithium ML-DSA-44 verification key (1312 bytes), encoded as
    /// 2624 hex characters in textual form.
    VkHex(Box<DilithiumPubKey>),

    /// Reserved syntax for a future hierarchical-deterministic Dilithium
    /// scheme. Parsed for forward-compatibility; v1 `resolve()` returns
    /// `HdDerivationNotYetSupported`.
    ///
    /// The string is the raw `xpub...` token preserved verbatim from
    /// the parsed input, so that round-tripping (parse → display) is
    /// byte-identical even before the future scheme is defined.
    XpubReserved(String),
}

/// `[fingerprint/derivation/path]` annotation on a key expression.
///
/// In v1 the derivation path is parsed and round-tripped but is not
/// consulted by `resolve()` (D1). The fingerprint MUST match the SHA3-384
/// derivation of the key it annotates; mismatch is a parse-time error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyOrigin {
    pub fingerprint: Fingerprint,

    /// Derivation steps as parsed. Each step is the integer index;
    /// the boolean indicates whether the step was hardened (suffix `'` or `h`).
    /// Empty `Vec` = no derivation path (just `[fingerprint]`).
    pub derivation_path: Vec<DerivationStep>,
}

/// A single step in a derivation path. Hardened steps are preserved through
/// round-trips even though v1 does not act on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivationStep {
    pub index: u32,
    pub hardened: bool,
}

/// Maximum number of keys in a `multi-mldsa44` expression. See DESIGN.md §4.
pub const MAX_MULTI_KEYS: usize = 15;
