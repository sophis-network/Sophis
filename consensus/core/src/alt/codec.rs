//! L1 — codec for ALT-creation and ALT-reference output scripts.
//!
//! Pure helpers, no I/O, no consensus state. Owns three primitives:
//!
//! * `alt_handle_of`              — derive a 6-byte handle from an entries blob
//! * `encode_alt_creation_script` — assemble a v=1 ALT-creation output script
//! * `encode_alt_reference_script`— assemble an 8-byte ALT-reference script
//!
//! Cross-references:
//! * §3 of `docs/L1_ALT_DESIGN.md` — wire format
//! * `alt::parse_alt_creation_header` — inverse of `encode_alt_creation_script`
//! * `alt::parse_alt_reference`        — inverse of `encode_alt_reference_script`

use sha3::{Digest, Sha3_384};

use super::{
    ALT_DISCRIMINATOR_CREATION, ALT_DISCRIMINATOR_REFERENCE, ALT_HANDLE_LEN, ALT_HEADER_LEN, ALT_MAGIC, ALT_REFERENCE_LEN,
    AltCreationError, MAX_ALT_ENTRIES, MAX_ALT_ENTRY_SCRIPT_BYTES,
};

/// Derives an ALT handle from the canonical entries blob.
///
/// The input is the `entries` section that will appear at offset
/// `ALT_HEADER_LEN..` of the on-wire script — i.e. the concatenation of
/// length-prefixed `(spk_version u16 LE, spk_len u16 LE, spk_bytes)` blocks.
/// The handle does NOT depend on the handle field itself, eliminating the
/// fixed-point problem that would arise if the handle hashed its own bytes.
pub fn alt_handle_of(entries_canonical_bytes: &[u8]) -> [u8; ALT_HANDLE_LEN] {
    let mut hasher = Sha3_384::new();
    hasher.update(entries_canonical_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; ALT_HANDLE_LEN];
    out.copy_from_slice(&digest[..ALT_HANDLE_LEN]);
    out
}

/// Builds a v=1 ALT-creation output script from a list of `(spk_version, spk_bytes)`
/// pairs. Returns `Err` on misuse so producer tooling cannot silently emit
/// bytes that consensus would reject:
///
/// * empty entries list                       → `BadEntryCount(0)`
/// * more than `MAX_ALT_ENTRIES` entries      → `BadEntryCount(n)`
/// * any entry with `spk_version > MAX_SPK_VERSION` → `EntryBadSpkVersion`
/// * any entry with `spk_bytes.len() > MAX_ALT_ENTRY_SCRIPT_BYTES` → `EntryScriptTooLarge`
///
/// On success the returned `Vec<u8>` is bit-exact what consensus expects:
/// `parse_alt_creation_header(&out).is_ok()` always holds.
pub fn encode_alt_creation_script(entries: &[(u16, &[u8])]) -> Result<Vec<u8>, AltCreationError> {
    if entries.is_empty() || entries.len() > MAX_ALT_ENTRIES as usize {
        return Err(AltCreationError::BadEntryCount(entries.len() as u16));
    }

    // Validate per-entry constraints up-front so errors fire before any
    // allocation work. Mirrors rules 10-11 of the parser.
    for (idx, (ver, body)) in entries.iter().enumerate() {
        if *ver > super::super::constants::MAX_SCRIPT_PUBLIC_KEY_VERSION {
            return Err(AltCreationError::EntryBadSpkVersion { entry: idx as u16, version: *ver });
        }
        if body.len() > MAX_ALT_ENTRY_SCRIPT_BYTES as usize {
            return Err(AltCreationError::EntryScriptTooLarge { entry: idx as u16, len: body.len() as u16 });
        }
    }

    // Build the entries section.
    let mut entries_bytes = Vec::with_capacity(entries.iter().map(|(_, b)| 4 + b.len()).sum());
    for (ver, body) in entries {
        entries_bytes.extend_from_slice(&ver.to_le_bytes());
        entries_bytes.extend_from_slice(&(body.len() as u16).to_le_bytes());
        entries_bytes.extend_from_slice(body);
    }

    let payload_len = entries_bytes.len() as u32;
    let handle = alt_handle_of(&entries_bytes);

    let mut script = Vec::with_capacity(ALT_HEADER_LEN + payload_len as usize);
    script.push(ALT_DISCRIMINATOR_CREATION);
    script.extend_from_slice(&ALT_MAGIC);
    script.push(0); // flags — all reserved in v1
    script.push(0); // reserved
    // entry_count: `0` byte means 256 (per design D4 / decode_entry_count).
    let raw_count = if entries.len() == MAX_ALT_ENTRIES as usize { 0 } else { entries.len() as u8 };
    script.push(raw_count);
    script.extend_from_slice(&payload_len.to_le_bytes());
    script.extend_from_slice(&handle);
    script.extend_from_slice(&entries_bytes);

    Ok(script)
}

/// Builds an 8-byte ALT-reference output script for the given handle and index.
/// Always succeeds — index validity is a runtime concern of the resolving
/// validator (§5 rule 16), not of the wire-format encoder.
pub fn encode_alt_reference_script(handle: [u8; ALT_HANDLE_LEN], index: u8) -> [u8; ALT_REFERENCE_LEN] {
    let mut out = [0u8; ALT_REFERENCE_LEN];
    out[0] = ALT_DISCRIMINATOR_REFERENCE;
    out[1..1 + ALT_HANDLE_LEN].copy_from_slice(&handle);
    out[1 + ALT_HANDLE_LEN] = index;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alt::{parse_alt_creation_header, parse_alt_reference};

    #[test]
    fn round_trip_minimal_creation() {
        let entries: &[(u16, &[u8])] = &[(0u16, &[0xAA, 0xBB, 0xCC, 0xDD])];
        let script = encode_alt_creation_script(entries).unwrap();
        let parsed = parse_alt_creation_header(&script).unwrap();
        assert_eq!(parsed.entry_count, 1);
        assert_eq!(parsed.flags, 0);
        // Re-derive handle from entries section and verify equality.
        let entries_section = &script[ALT_HEADER_LEN..];
        assert_eq!(parsed.handle, alt_handle_of(entries_section));
    }

    #[test]
    fn round_trip_three_entries() {
        let body_a: Vec<u8> = vec![1, 2, 3, 4];
        let body_b: Vec<u8> = vec![0xCCu8; 36];
        let body_c: Vec<u8> = vec![];
        let entries: Vec<(u16, &[u8])> = vec![(0, body_a.as_slice()), (1, body_b.as_slice()), (5, body_c.as_slice())];
        let script = encode_alt_creation_script(&entries).unwrap();
        let parsed = parse_alt_creation_header(&script).unwrap();
        assert_eq!(parsed.entry_count, 3);
        let collected: Vec<_> = crate::alt::iter_alt_entries(&script).collect();
        assert_eq!(collected.len(), 3);
        assert_eq!(collected[0].spk_script, body_a.as_slice());
        assert_eq!(collected[1].spk_script, body_b.as_slice());
        assert_eq!(collected[2].spk_script, body_c.as_slice());
    }

    #[test]
    fn handle_is_deterministic_for_same_entries() {
        let entries: &[(u16, &[u8])] = &[(0u16, b"hello world")];
        let s1 = encode_alt_creation_script(entries).unwrap();
        let s2 = encode_alt_creation_script(entries).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn handle_changes_with_entry_content() {
        let s1 = encode_alt_creation_script(&[(0u16, b"hello".as_slice())]).unwrap();
        let s2 = encode_alt_creation_script(&[(0u16, b"world".as_slice())]).unwrap();
        assert_ne!(s1[16..16 + ALT_HANDLE_LEN], s2[16..16 + ALT_HANDLE_LEN]);
    }

    #[test]
    fn encode_rejects_empty_entries() {
        match encode_alt_creation_script(&[]) {
            Err(AltCreationError::BadEntryCount(0)) => {}
            other => panic!("expected BadEntryCount(0), got {other:?}"),
        }
    }

    #[test]
    fn encode_rejects_too_many_entries() {
        // 257 trivial entries; first 256 are fine, 257th overflows.
        let entries: Vec<(u16, &[u8])> = (0..257).map(|_| (0u16, &[][..])).collect();
        match encode_alt_creation_script(&entries) {
            Err(AltCreationError::BadEntryCount(257)) => {}
            other => panic!("expected BadEntryCount(257), got {other:?}"),
        }
    }

    #[test]
    fn encode_accepts_exactly_256_entries() {
        let entries: Vec<(u16, &[u8])> = (0..256).map(|_| (0u16, &[][..])).collect();
        let script = encode_alt_creation_script(&entries).unwrap();
        // Byte at offset 11 (entry_count) must be 0 — convention "0 means 256".
        assert_eq!(script[11], 0);
        let parsed = parse_alt_creation_header(&script).unwrap();
        assert_eq!(parsed.entry_count, 256);
    }

    #[test]
    fn encode_rejects_oversized_entry_script() {
        let big = vec![0u8; (MAX_ALT_ENTRY_SCRIPT_BYTES + 1) as usize];
        let entries: &[(u16, &[u8])] = &[(0u16, &big)];
        match encode_alt_creation_script(entries) {
            Err(AltCreationError::EntryScriptTooLarge { entry: 0, len }) => {
                assert_eq!(len as u32, MAX_ALT_ENTRY_SCRIPT_BYTES as u32 + 1);
            }
            other => panic!("expected EntryScriptTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn encode_rejects_unsupported_spk_version() {
        let bad = crate::constants::MAX_SCRIPT_PUBLIC_KEY_VERSION + 1;
        let entries: &[(u16, &[u8])] = &[(bad, b"x")];
        match encode_alt_creation_script(entries) {
            Err(AltCreationError::EntryBadSpkVersion { entry: 0, version }) => {
                assert_eq!(version, bad);
            }
            other => panic!("expected EntryBadSpkVersion, got {other:?}"),
        }
    }

    #[test]
    fn reference_round_trip() {
        let h = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let s = encode_alt_reference_script(h, 42);
        assert_eq!(s.len(), ALT_REFERENCE_LEN);
        let parsed = parse_alt_reference(&s).unwrap();
        assert_eq!(parsed.handle, h);
        assert_eq!(parsed.index, 42);
    }

    #[test]
    fn reference_first_byte_is_discriminator() {
        let s = encode_alt_reference_script([0u8; ALT_HANDLE_LEN], 0);
        assert_eq!(s[0], ALT_DISCRIMINATOR_REFERENCE);
    }

    #[test]
    fn alt_handle_of_matches_design_test_vector_format() {
        // Sanity: handle is 6 bytes derived from SHA3-384 of the entries blob.
        // We don't pin a specific value here (would over-constrain encoding);
        // the round-trip tests verify consensus equivalence end-to-end.
        let h = alt_handle_of(b"non-empty");
        assert_eq!(h.len(), ALT_HANDLE_LEN);
        let h2 = alt_handle_of(b"non-empty");
        assert_eq!(h, h2);
    }
}
