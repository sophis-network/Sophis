//! L1 — Address Lookup Tables.
//!
//! Canonical reference: `docs/L1_ALT_DESIGN.md`. The constants and the
//! parsers in this module form the **ABI freeze** of sub-fase L1.0. Any
//! change requires a hard fork of the L1.
//!
//! An ALT-creation output is an unspendable transaction output (value = 0,
//! version-1 transaction) whose `script` starts with the discriminator byte
//! `0xFE` and the magic prefix `b"SPHS-AL1"`. It registers an immutable
//! lookup table of `ScriptPublicKey` entries that subsequent transactions
//! may reference by 7-byte handle/index pairs.
//!
//! An ALT reference is a v=1 transaction output whose `script` starts with
//! the discriminator byte `0xFD` followed by a 6-byte handle and a 1-byte
//! index — exactly 8 bytes in total. Resolution at validation time
//! substitutes the referenced `ScriptPublicKey` from the consensus ALT
//! registry.
//!
//! Layout of an ALT-creation `script` (see §3.3 of the design doc):
//! ```text
//!   0..1     discriminator   = 0xFE
//!   1..9     magic           = b"SPHS-AL1"
//!   9..10    flags: u8       (all bits reserved, must be 0)
//!  10..11    reserved        = 0
//!  11..12    entry_count: u8 (1..=256, value 0 means 256)
//!  12..16    payload_len: u32 LE  (entries section bytes; 0..=remaining script len)
//!  16..22    handle: [u8; 6] = SHA3-384(canonical_payload)[..6]
//!  22..N     entries         = repeated (spk_version u16 LE, spk_len u16 LE, spk_bytes)
//! ```
//!
//! Layout of an ALT reference `script`:
//! ```text
//!   0..1     discriminator   = 0xFD
//!   1..7     handle: [u8; 6]
//!   7..8     index: u8
//! ```
//!
//! The 19 consensus rules of §5 are enforced by:
//! * rules 1, 13: `validate_alt_outputs_and_refs` (L1.3) — version gate
//! * rules 2, 17, 18, 19: `tx_validation_in_isolation` / `check_coinbase_in_isolation`
//! * rules 3-12, 14-16: `parse_alt_creation_header` and `parse_alt_reference`
//!   return Err on any structural violation; rule 15 (dangling reference) is
//!   enforced by the validator using the consensus ALT registry.

use std::fmt;

use sha3::{Digest, Sha3_384};

pub mod codec;

pub use codec::{alt_handle_of, encode_alt_creation_script, encode_alt_reference_script};

// --- discriminators ----------------------------------------------------

/// Leading byte that marks a v=1 output's script as an ALT reference.
pub const ALT_DISCRIMINATOR_REFERENCE: u8 = 0xFD;

/// Leading byte that marks a v=1 output's script as an ALT-creation output.
pub const ALT_DISCRIMINATOR_CREATION: u8 = 0xFE;

// --- magic and header --------------------------------------------------

/// Bytes 1..9 of every ALT-creation script. Frozen ABI.
pub const ALT_MAGIC: [u8; 8] = *b"SPHS-AL1";

/// Total length in bytes of the fixed creation header (discriminator + magic
/// + flags + reserved + entry_count + payload_len + handle).
pub const ALT_HEADER_LEN: usize = 22;

/// Length of an ALT handle (`SHA3-384(canonical_payload)[..ALT_HANDLE_LEN]`).
pub const ALT_HANDLE_LEN: usize = 6;

/// Total length of an ALT reference output script (discriminator + handle + index).
pub const ALT_REFERENCE_LEN: usize = 8;

// --- caps and limits ---------------------------------------------------

/// Maximum entries in a single ALT, per design D4. Encoded as `u8` with
/// the value `256` represented on-wire as the byte `0` (i.e. the byte
/// `entry_count == 0` is interpreted as `256`).
pub const MAX_ALT_ENTRIES: u16 = 256;

/// Cap on a single entry's `spk_script` size. Anything larger should not be
/// shoved into an ALT — store it inline or use sVM contract storage.
pub const MAX_ALT_ENTRY_SCRIPT_BYTES: u16 = 4_096;

/// Maximum ALT-creation outputs per transaction (anti-spam).
pub const MAX_ALT_CREATIONS_PER_TX: usize = 4;

/// Maximum ALT-creation outputs per block across all its transactions.
pub const MAX_ALT_CREATIONS_PER_BLOCK: usize = 16;

// --- mass model --------------------------------------------------------

/// Base mass charged for any ALT-creation output, regardless of payload.
pub const BASE_ALT_CREATION_MASS: u64 = 100_000;

/// Additional storage-mass factor for ALT entry bytes (in addition to the
/// existing `TRANSIENT_BYTE_TO_MASS_FACTOR` on the wire bytes themselves).
pub const ALT_STORAGE_MASS_FACTOR: u64 = 1;

// --- view types --------------------------------------------------------

/// Decoded view of the fixed 22-byte ALT-creation header. Returned by
/// `parse_alt_creation_header`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltCreationHeader {
    pub flags: u8,
    /// Logical entry count in `1..=MAX_ALT_ENTRIES`. The on-wire byte is
    /// translated through `decode_entry_count` so that `0` becomes `256`.
    pub entry_count: u16,
    pub payload_len: u32,
    pub handle: [u8; ALT_HANDLE_LEN],
}

/// Decoded view of an ALT reference (8-byte output script).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AltReference {
    pub handle: [u8; ALT_HANDLE_LEN],
    pub index: u8,
}

impl AltReference {
    pub const fn new(handle: [u8; ALT_HANDLE_LEN], index: u8) -> Self {
        Self { handle, index }
    }
}

/// Length-prefixed entry inside an ALT-creation payload. Returned by
/// `iter_alt_entries`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltEntryView<'a> {
    pub spk_version: u16,
    pub spk_script: &'a [u8],
}

// --- errors ------------------------------------------------------------

/// Reasons the consensus may reject an ALT-creation script. Each numbered
/// variant maps to a rule from §5 of the design document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AltCreationError {
    /// Rule 3 — script too short to carry the 22-byte header.
    HeaderTruncated { actual: usize },
    /// Rule 4 — bytes 1..9 do not equal `ALT_MAGIC`.
    BadMagic,
    /// Rule 5 — reserved byte at offset 10 is non-zero.
    ReservedNonZero(u8),
    /// Rule 6 — flag byte at offset 9 has at least one reserved bit set.
    ReservedFlagBitSet(u8),
    /// Rule 7 — interpreting `entry_count == 0` as `256` still yields zero
    /// when caller's intent was zero; this branch is unreachable in v1 but
    /// reserved for future flag-driven semantics. Returned only when the
    /// computed logical count exits `1..=MAX_ALT_ENTRIES`.
    BadEntryCount(u16),
    /// Rule 8 — `payload_len + ALT_HEADER_LEN` does not equal `script.len()`.
    LengthMismatch { actual: usize, expected: usize },
    /// Rule 9 — the entries section does not parse cleanly as
    /// `entry_count` length-prefixed `(spk_version u16, spk_len u16, spk_bytes)`
    /// blocks summing to exactly `payload_len`.
    EntriesLenMismatch { decoded: usize, expected: u32 },
    /// Rule 10 — an entry's `spk_version` exceeds the consensus cap.
    EntryBadSpkVersion { entry: u16, version: u16 },
    /// Rule 11 — an entry's declared `spk_len` exceeds `MAX_ALT_ENTRY_SCRIPT_BYTES`.
    EntryScriptTooLarge { entry: u16, len: u16 },
    /// Rule 12 — `handle` field disagrees with `SHA3-384(canonical_payload)[..6]`.
    HandleMismatch { declared: [u8; ALT_HANDLE_LEN], computed: [u8; ALT_HANDLE_LEN] },
}

impl fmt::Display for AltCreationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTruncated { actual } => {
                write!(f, "ALT-creation script is {actual} bytes, below header minimum of {ALT_HEADER_LEN}")
            }
            Self::BadMagic => write!(f, "ALT-creation magic prefix mismatch (expected SPHS-AL1)"),
            Self::ReservedNonZero(b) => {
                write!(f, "ALT-creation reserved byte at offset 10 must be 0, got 0x{b:02x}")
            }
            Self::ReservedFlagBitSet(flags) => {
                write!(f, "ALT-creation flag byte 0x{flags:02x} has reserved bit(s) set; all flag bits are reserved in v1")
            }
            Self::BadEntryCount(c) => {
                write!(f, "ALT-creation entry_count={c} is outside [1, {MAX_ALT_ENTRIES}]")
            }
            Self::LengthMismatch { actual, expected } => {
                write!(f, "ALT-creation script length is {actual}, expected {expected} (header + payload_len)")
            }
            Self::EntriesLenMismatch { decoded, expected } => {
                write!(f, "ALT-creation entries section decoded {decoded} bytes, expected payload_len={expected}")
            }
            Self::EntryBadSpkVersion { entry, version } => {
                write!(f, "ALT entry {entry} declares spk_version={version} which is above MAX_SCRIPT_PUBLIC_KEY_VERSION")
            }
            Self::EntryScriptTooLarge { entry, len } => {
                write!(f, "ALT entry {entry} declares spk_len={len} above MAX_ALT_ENTRY_SCRIPT_BYTES={MAX_ALT_ENTRY_SCRIPT_BYTES}")
            }
            Self::HandleMismatch { declared, computed } => {
                write!(
                    f,
                    "ALT-creation handle mismatch: declared={} computed={}",
                    hex::fmt6(declared),
                    hex::fmt6(computed),
                )
            }
        }
    }
}

impl std::error::Error for AltCreationError {}

/// Reasons the consensus may reject an ALT reference output's script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AltReferenceError {
    /// Rule 14 — script length is not exactly 8.
    BadLength { actual: usize },
}

impl fmt::Display for AltReferenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength { actual } => {
                write!(f, "ALT reference script length is {actual}, expected exactly {ALT_REFERENCE_LEN}")
            }
        }
    }
}

impl std::error::Error for AltReferenceError {}

// --- helpers -----------------------------------------------------------

/// Translates the on-wire `entry_count` byte to its logical value, per the
/// `0 ⇒ 256` convention. Returns `Err(0)` if the byte is `0` *and* the
/// caller has already filtered out the 256 case (caller never does this in
/// practice; included for symmetry with `encode`).
const fn decode_entry_count(byte: u8) -> u16 {
    if byte == 0 { MAX_ALT_ENTRIES } else { byte as u16 }
}

/// Computes the canonical-payload hash exactly the way consensus expects:
/// `SHA3-384(script[ALT_HEADER_LEN..])[..ALT_HANDLE_LEN]`.
///
/// The canonical payload is the **entries section only**, NOT including the
/// handle bytes at offset 16..22. This makes the handle a pure function of
/// the entries (no fixed-point iteration during encoding) and matches the
/// "content-addressed" semantics from §3.3 of the design doc.
///
/// Caller is responsible for ensuring `script.len() >= ALT_HEADER_LEN`.
/// Used by the codec's `alt_handle_of` and by the `parse_alt_creation_header`
/// rule 12 check.
fn hash_canonical_payload(script: &[u8]) -> [u8; ALT_HANDLE_LEN] {
    debug_assert!(script.len() >= ALT_HEADER_LEN);
    let mut hasher = Sha3_384::new();
    hasher.update(&script[ALT_HEADER_LEN..]);
    let digest = hasher.finalize();
    let mut out = [0u8; ALT_HANDLE_LEN];
    out.copy_from_slice(&digest[..ALT_HANDLE_LEN]);
    out
}

mod hex {
    use super::ALT_HANDLE_LEN;
    use std::fmt::Write;

    /// Formats a 6-byte handle as `"e8412b7da903"` for diagnostic output.
    pub(super) fn fmt6(bytes: &[u8; ALT_HANDLE_LEN]) -> String {
        let mut out = String::with_capacity(ALT_HANDLE_LEN * 2);
        for b in bytes {
            let _ = write!(&mut out, "{b:02x}");
        }
        out
    }
}

// --- parsers -----------------------------------------------------------

/// Parses and validates the 22-byte header of an ALT-creation script, plus
/// the length-consistency check between `payload_len` and `script.len()`,
/// the entries section structure (rule 9), the entries' SPK constraints
/// (rules 10-11), and the handle integrity (rule 12).
///
/// Rules enforced in this single pass: 3-12 (excluding 7's "BadEntryCount"
/// branch which is unreachable for current encoding). Rules 1, 2, 13, 17-19
/// are enforced at the transaction-validator layer because they require
/// additional context the parser does not see; rules 14-16 belong to
/// `parse_alt_reference`.
///
/// On `Ok`, the script is structurally well-formed and its handle matches
/// the canonical hash. The `AltCreationHeader` returned does NOT contain
/// the entries themselves; iterate via [`iter_alt_entries`].
pub fn parse_alt_creation_header(script: &[u8]) -> Result<AltCreationHeader, AltCreationError> {
    // Rule 3
    if script.len() < ALT_HEADER_LEN {
        return Err(AltCreationError::HeaderTruncated { actual: script.len() });
    }

    // Discriminator: not strictly part of the magic but enforced here so the
    // parser is callable directly on the raw script bytes. Distinct error
    // would be redundant — the magic check catches every misuse worth
    // distinguishing (the byte at offset 0 is not part of the canonical
    // payload).
    if script[0] != ALT_DISCRIMINATOR_CREATION {
        return Err(AltCreationError::BadMagic);
    }

    // Rule 4
    if script[1..9] != ALT_MAGIC {
        return Err(AltCreationError::BadMagic);
    }

    let flags = script[9];

    // Rule 6
    if flags != 0 {
        return Err(AltCreationError::ReservedFlagBitSet(flags));
    }

    // Rule 5
    if script[10] != 0 {
        return Err(AltCreationError::ReservedNonZero(script[10]));
    }

    let entry_count = decode_entry_count(script[11]);

    // Rule 7 (post-decode guard for symmetry with future flag-driven counts)
    if entry_count == 0 || entry_count > MAX_ALT_ENTRIES {
        return Err(AltCreationError::BadEntryCount(entry_count));
    }

    let payload_len = u32::from_le_bytes([script[12], script[13], script[14], script[15]]);

    // Rule 8
    let expected_len = ALT_HEADER_LEN + payload_len as usize;
    if script.len() != expected_len {
        return Err(AltCreationError::LengthMismatch { actual: script.len(), expected: expected_len });
    }

    let mut handle = [0u8; ALT_HANDLE_LEN];
    handle.copy_from_slice(&script[16..16 + ALT_HANDLE_LEN]);

    // Rule 9-11 — walk the entries section and re-check structure.
    let entries_section = &script[ALT_HEADER_LEN..];
    let mut cursor = 0usize;
    let mut decoded_entries: u16 = 0;
    while cursor < entries_section.len() {
        // Need at least 4 bytes for spk_version + spk_len.
        if entries_section.len() - cursor < 4 {
            return Err(AltCreationError::EntriesLenMismatch {
                decoded: cursor,
                expected: payload_len,
            });
        }
        let spk_version = u16::from_le_bytes([entries_section[cursor], entries_section[cursor + 1]]);
        let spk_len = u16::from_le_bytes([entries_section[cursor + 2], entries_section[cursor + 3]]);
        // Rule 10
        if spk_version > crate::constants::MAX_SCRIPT_PUBLIC_KEY_VERSION {
            return Err(AltCreationError::EntryBadSpkVersion { entry: decoded_entries, version: spk_version });
        }
        // Rule 11
        if spk_len > MAX_ALT_ENTRY_SCRIPT_BYTES {
            return Err(AltCreationError::EntryScriptTooLarge { entry: decoded_entries, len: spk_len });
        }
        let entry_total = 4usize + spk_len as usize;
        if entries_section.len() - cursor < entry_total {
            return Err(AltCreationError::EntriesLenMismatch {
                decoded: cursor,
                expected: payload_len,
            });
        }
        cursor += entry_total;
        decoded_entries = decoded_entries.saturating_add(1);
    }

    // Rule 9 — exact match required, AND the count of decoded entries must
    // equal the declared `entry_count`.
    if cursor != payload_len as usize || decoded_entries != entry_count {
        return Err(AltCreationError::EntriesLenMismatch {
            decoded: cursor,
            expected: payload_len,
        });
    }

    // Rule 12 — handle integrity.
    let computed = hash_canonical_payload(script);
    if handle != computed {
        return Err(AltCreationError::HandleMismatch { declared: handle, computed });
    }

    Ok(AltCreationHeader { flags, entry_count, payload_len, handle })
}

/// Iterator over the entries section of a well-formed ALT-creation script.
/// Caller MUST have validated `script` via `parse_alt_creation_header`
/// first. This iterator does not re-check structural rules and will
/// `debug_assert!` on malformed input but otherwise yields whatever it can.
pub fn iter_alt_entries(script: &[u8]) -> impl Iterator<Item = AltEntryView<'_>> {
    debug_assert!(script.len() >= ALT_HEADER_LEN);
    let entries_section = &script[ALT_HEADER_LEN..];
    AltEntriesIter { rest: entries_section }
}

struct AltEntriesIter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for AltEntriesIter<'a> {
    type Item = AltEntryView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.len() < 4 {
            debug_assert!(self.rest.is_empty(), "iter_alt_entries on malformed script");
            return None;
        }
        let spk_version = u16::from_le_bytes([self.rest[0], self.rest[1]]);
        let spk_len = u16::from_le_bytes([self.rest[2], self.rest[3]]) as usize;
        debug_assert!(self.rest.len() >= 4 + spk_len, "iter_alt_entries on malformed script");
        let spk_script = &self.rest[4..4 + spk_len];
        self.rest = &self.rest[4 + spk_len..];
        Some(AltEntryView { spk_version, spk_script })
    }
}

/// Parses and validates an ALT reference output script. Enforces rule 14
/// (script length); rule 15 (existence of the referenced handle in the
/// consensus ALT registry) and rule 16 (index in range) belong to the
/// validator layer, where the registry is in scope.
pub fn parse_alt_reference(script: &[u8]) -> Result<AltReference, AltReferenceError> {
    if script.len() != ALT_REFERENCE_LEN {
        return Err(AltReferenceError::BadLength { actual: script.len() });
    }
    debug_assert_eq!(script[0], ALT_DISCRIMINATOR_REFERENCE, "caller must dispatch on discriminator first");
    let mut handle = [0u8; ALT_HANDLE_LEN];
    handle.copy_from_slice(&script[1..1 + ALT_HANDLE_LEN]);
    let index = script[1 + ALT_HANDLE_LEN];
    Ok(AltReference { handle, index })
}

/// Cheap classifier used by the validator to dispatch on the leading byte
/// of an output's script. Returns `None` for anything that is not an ALT
/// discriminator (i.e. a normal inline script).
pub fn classify_alt_script(script: &[u8]) -> Option<AltScriptKind> {
    match *script.first()? {
        ALT_DISCRIMINATOR_REFERENCE => Some(AltScriptKind::Reference),
        ALT_DISCRIMINATOR_CREATION => Some(AltScriptKind::Creation),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AltScriptKind {
    Reference,
    Creation,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_creation_script(entries: &[(u16, Vec<u8>)]) -> Vec<u8> {
        // Build the entries section first.
        let mut entries_bytes = Vec::new();
        for (ver, body) in entries {
            entries_bytes.extend_from_slice(&ver.to_le_bytes());
            entries_bytes.extend_from_slice(&(body.len() as u16).to_le_bytes());
            entries_bytes.extend_from_slice(body);
        }

        // payload_len counts the entries section bytes only — the 6-byte handle
        // is part of the fixed header (`ALT_HEADER_LEN = 22` already includes it).
        let payload_len = entries_bytes.len() as u32;

        // Compute handle from entries bytes alone (matches hash_canonical_payload
        // which hashes `script[ALT_HEADER_LEN..]` — i.e. the entries section).
        let mut hasher = Sha3_384::new();
        hasher.update(&entries_bytes);
        let digest = hasher.finalize();
        let mut handle = [0u8; ALT_HANDLE_LEN];
        handle.copy_from_slice(&digest[..ALT_HANDLE_LEN]);

        let mut script = Vec::with_capacity(ALT_HEADER_LEN + payload_len as usize);
        script.push(ALT_DISCRIMINATOR_CREATION);
        script.extend_from_slice(&ALT_MAGIC);
        script.push(0); // flags
        script.push(0); // reserved
        let raw_count = if entries.len() == MAX_ALT_ENTRIES as usize { 0 } else { entries.len() as u8 };
        script.push(raw_count);
        script.extend_from_slice(&payload_len.to_le_bytes());
        script.extend_from_slice(&handle);
        script.extend_from_slice(&entries_bytes);
        script
    }

    fn happy_minimal_creation() -> Vec<u8> {
        // Single 4-byte entry, version 0.
        build_creation_script(&[(0u16, vec![0xAAu8; 4])])
    }

    #[test]
    fn parse_happy_minimal_creation() {
        let s = happy_minimal_creation();
        let h = parse_alt_creation_header(&s).expect("happy path must parse");
        assert_eq!(h.flags, 0);
        assert_eq!(h.entry_count, 1);
        // payload_len = entries section only = spk_version(2) + spk_len(2) + body(4) = 8
        assert_eq!(h.payload_len, 8);
        assert_eq!(h.handle.len(), ALT_HANDLE_LEN);
    }

    #[test]
    fn parse_happy_iterates_one_entry() {
        let s = happy_minimal_creation();
        parse_alt_creation_header(&s).unwrap();
        let entries: Vec<_> = iter_alt_entries(&s).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].spk_version, 0);
        assert_eq!(entries[0].spk_script, &[0xAAu8; 4]);
    }

    #[test]
    fn parse_happy_three_entries_mixed_versions() {
        let s = build_creation_script(&[(0u16, vec![1u8, 2, 3, 4]), (1u16, vec![0xCCu8; 8]), (5u16, vec![])]);
        let h = parse_alt_creation_header(&s).unwrap();
        assert_eq!(h.entry_count, 3);
        let collected: Vec<_> = iter_alt_entries(&s).collect();
        assert_eq!(collected.len(), 3);
        assert_eq!(collected[0].spk_version, 0);
        assert_eq!(collected[1].spk_version, 1);
        assert_eq!(collected[2].spk_version, 5);
        assert_eq!(collected[2].spk_script, &[] as &[u8]);
    }

    // --- Rule 3 -------------------------------------------------------

    #[test]
    fn rule_3_header_truncated() {
        let s = vec![0u8; 21];
        match parse_alt_creation_header(&s) {
            Err(AltCreationError::HeaderTruncated { actual }) => assert_eq!(actual, 21),
            other => panic!("expected HeaderTruncated, got {other:?}"),
        }
    }

    // --- Rule 4 (and discriminator) -----------------------------------

    #[test]
    fn rule_4_bad_discriminator() {
        let mut s = happy_minimal_creation();
        s[0] = 0xAB;
        assert_eq!(parse_alt_creation_header(&s), Err(AltCreationError::BadMagic));
    }

    #[test]
    fn rule_4_bad_magic() {
        let mut s = happy_minimal_creation();
        s[1] = b'X';
        assert_eq!(parse_alt_creation_header(&s), Err(AltCreationError::BadMagic));
    }

    // --- Rule 5 -------------------------------------------------------

    #[test]
    fn rule_5_reserved_byte_nonzero() {
        let mut s = happy_minimal_creation();
        s[10] = 0x42;
        assert_eq!(parse_alt_creation_header(&s), Err(AltCreationError::ReservedNonZero(0x42)));
    }

    // --- Rule 6 -------------------------------------------------------

    #[test]
    fn rule_6_reserved_flag_bit_set() {
        let mut s = happy_minimal_creation();
        s[9] = 0x01;
        match parse_alt_creation_header(&s) {
            Err(AltCreationError::ReservedFlagBitSet(0x01)) => {}
            other => panic!("expected ReservedFlagBitSet, got {other:?}"),
        }
    }

    // --- Rule 8 -------------------------------------------------------

    #[test]
    fn rule_8_length_mismatch_extra_trailing() {
        let mut s = happy_minimal_creation();
        s.push(0xFF);
        match parse_alt_creation_header(&s) {
            Err(AltCreationError::LengthMismatch { actual, expected }) => {
                assert_eq!(actual, expected + 1);
            }
            other => panic!("expected LengthMismatch (extra), got {other:?}"),
        }
    }

    #[test]
    fn rule_8_length_mismatch_missing_payload_bytes() {
        let mut s = happy_minimal_creation();
        s.pop(); // remove last byte of entry body
        match parse_alt_creation_header(&s) {
            Err(AltCreationError::LengthMismatch { .. }) => {}
            other => panic!("expected LengthMismatch (missing), got {other:?}"),
        }
    }

    // --- Rule 9 (entries section structure) ---------------------------

    #[test]
    fn rule_9_entries_decoded_does_not_match_count() {
        // Declare entry_count = 2 but only encode 1 entry's worth of bytes.
        let entries_bytes = {
            let mut b = Vec::new();
            // entry 0: ver 0, len 4
            b.extend_from_slice(&0u16.to_le_bytes());
            b.extend_from_slice(&4u16.to_le_bytes());
            b.extend_from_slice(&[1u8, 2, 3, 4]);
            b
        };
        let payload_len = entries_bytes.len() as u32;
        let mut script = Vec::new();
        script.push(ALT_DISCRIMINATOR_CREATION);
        script.extend_from_slice(&ALT_MAGIC);
        script.push(0);
        script.push(0);
        script.push(2); // declared count = 2
        script.extend_from_slice(&payload_len.to_le_bytes());
        script.extend_from_slice(&[0u8; ALT_HANDLE_LEN]); // placeholder handle
        script.extend_from_slice(&entries_bytes);
        let handle = hash_canonical_payload(&script);
        script[16..16 + ALT_HANDLE_LEN].copy_from_slice(&handle);
        match parse_alt_creation_header(&script) {
            Err(AltCreationError::EntriesLenMismatch { decoded, expected }) => {
                assert_eq!(decoded, entries_bytes.len());
                assert_eq!(expected, payload_len);
            }
            other => panic!("expected EntriesLenMismatch, got {other:?}"),
        }
    }

    // --- Rule 10 ------------------------------------------------------

    #[test]
    fn rule_10_entry_bad_spk_version() {
        // spk_version = MAX + 1 = 6.
        let bad_version = crate::constants::MAX_SCRIPT_PUBLIC_KEY_VERSION + 1;
        let entries_bytes = {
            let mut b = Vec::new();
            b.extend_from_slice(&bad_version.to_le_bytes());
            b.extend_from_slice(&0u16.to_le_bytes());
            b
        };
        let payload_len = entries_bytes.len() as u32;
        let mut script = Vec::new();
        script.push(ALT_DISCRIMINATOR_CREATION);
        script.extend_from_slice(&ALT_MAGIC);
        script.push(0);
        script.push(0);
        script.push(1);
        script.extend_from_slice(&payload_len.to_le_bytes());
        script.extend_from_slice(&[0u8; ALT_HANDLE_LEN]);
        script.extend_from_slice(&entries_bytes);
        let handle = hash_canonical_payload(&script);
        script[16..16 + ALT_HANDLE_LEN].copy_from_slice(&handle);
        match parse_alt_creation_header(&script) {
            Err(AltCreationError::EntryBadSpkVersion { entry: 0, version }) => {
                assert_eq!(version, bad_version);
            }
            other => panic!("expected EntryBadSpkVersion, got {other:?}"),
        }
    }

    // --- Rule 11 ------------------------------------------------------

    #[test]
    fn rule_11_entry_script_too_large() {
        let oversized = MAX_ALT_ENTRY_SCRIPT_BYTES + 1;
        let entries_bytes = {
            let mut b = Vec::new();
            b.extend_from_slice(&0u16.to_le_bytes());
            b.extend_from_slice(&oversized.to_le_bytes());
            // We don't actually allocate `oversized` bytes — the parser will fail
            // on the length declaration before checking the body. But to keep
            // total length consistent with payload_len, we still need to claim
            // it. Instead: declare oversized, let length-mismatch fire? No, the
            // parser checks rule 11 BEFORE rule 9's entry-by-entry body length.
            b
        };
        let payload_len = entries_bytes.len() as u32;
        let mut script = Vec::new();
        script.push(ALT_DISCRIMINATOR_CREATION);
        script.extend_from_slice(&ALT_MAGIC);
        script.push(0);
        script.push(0);
        script.push(1);
        script.extend_from_slice(&payload_len.to_le_bytes());
        script.extend_from_slice(&[0u8; ALT_HANDLE_LEN]);
        script.extend_from_slice(&entries_bytes);
        let handle = hash_canonical_payload(&script);
        script[16..16 + ALT_HANDLE_LEN].copy_from_slice(&handle);
        match parse_alt_creation_header(&script) {
            Err(AltCreationError::EntryScriptTooLarge { entry: 0, len }) => {
                assert_eq!(len, oversized);
            }
            other => panic!("expected EntryScriptTooLarge, got {other:?}"),
        }
    }

    // --- Rule 12 ------------------------------------------------------

    #[test]
    fn rule_12_handle_mismatch() {
        let mut s = happy_minimal_creation();
        // Flip a bit of the handle.
        s[16] ^= 0x01;
        match parse_alt_creation_header(&s) {
            Err(AltCreationError::HandleMismatch { .. }) => {}
            other => panic!("expected HandleMismatch, got {other:?}"),
        }
    }

    // --- ALT reference parsing ----------------------------------------

    #[test]
    fn parse_reference_happy() {
        let mut s = vec![ALT_DISCRIMINATOR_REFERENCE];
        s.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
        s.push(7);
        let r = parse_alt_reference(&s).unwrap();
        assert_eq!(r.handle, [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
        assert_eq!(r.index, 7);
    }

    #[test]
    fn rule_14_reference_bad_length_too_short() {
        let s = vec![ALT_DISCRIMINATOR_REFERENCE; 7];
        match parse_alt_reference(&s) {
            Err(AltReferenceError::BadLength { actual: 7 }) => {}
            other => panic!("expected BadLength, got {other:?}"),
        }
    }

    #[test]
    fn rule_14_reference_bad_length_too_long() {
        let s = vec![ALT_DISCRIMINATOR_REFERENCE; 9];
        match parse_alt_reference(&s) {
            Err(AltReferenceError::BadLength { actual: 9 }) => {}
            other => panic!("expected BadLength, got {other:?}"),
        }
    }

    // --- classify -----------------------------------------------------

    #[test]
    fn classify_dispatches_correctly() {
        assert_eq!(classify_alt_script(&[]), None);
        assert_eq!(classify_alt_script(&[0x76, 0xa9]), None); // legacy P2PKH start
        assert_eq!(classify_alt_script(&[ALT_DISCRIMINATOR_REFERENCE]), Some(AltScriptKind::Reference));
        assert_eq!(classify_alt_script(&[ALT_DISCRIMINATOR_CREATION]), Some(AltScriptKind::Creation));
    }

    // --- size constants sanity ---------------------------------------

    #[test]
    fn constants_are_consistent() {
        assert_eq!(ALT_HEADER_LEN, 22);
        assert_eq!(ALT_HANDLE_LEN, 6);
        assert_eq!(ALT_REFERENCE_LEN, 8);
        assert_eq!(ALT_MAGIC.len(), 8);
        assert_eq!(MAX_ALT_ENTRIES, 256);
        assert!(MAX_ALT_CREATIONS_PER_TX <= MAX_ALT_CREATIONS_PER_BLOCK);
    }

    // --- 256 entries edge case ---------------------------------------

    #[test]
    fn entry_count_256_round_trips_through_zero_byte() {
        // Build 256 trivially small entries.
        let entries: Vec<(u16, Vec<u8>)> = (0..256u16).map(|_| (0u16, vec![])).collect();
        let s = build_creation_script(&entries);
        let h = parse_alt_creation_header(&s).unwrap();
        assert_eq!(h.entry_count, 256);
        // Confirm the on-wire byte at offset 11 is 0.
        assert_eq!(s[11], 0);
    }
}
