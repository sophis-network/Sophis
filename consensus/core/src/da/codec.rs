//! Phase 6 — codec for V5 carrier outputs.
//!
//! Pure helpers, no I/O, no consensus state. Owns four primitives:
//!
//! * `encode_carrier_script` — build a `script` payload from a header and data
//! * `payload_id`            — SHA3-384 of the framed `script` (identifies one fragment)
//! * `bundle_id_of`          — SHA3-384 of the reassembled bytes (identifies the whole bundle)
//! * `reassemble`            — concatenate fragments by index and verify the bundle hash
//!
//! Cross-references:
//! * §3 of `oracle/docs/PHASE6_DA_DESIGN.md` — wire format
//! * `da::parse_carrier_header`               — inverse of `encode_carrier_script`
//! * `da::CarrierError`                       — structural rejection codes

use sha3::{Digest, Sha3_384};

use super::{
    CARRIER_FLAG_FRAGMENTED, CARRIER_FLAG_LAST, CARRIER_HEADER_LEN, CARRIER_MAGIC, CARRIER_PAYLOAD_HASH_LEN,
    CarrierDomain, CarrierError, CarrierHeader, MAX_DATA_PER_CARRIER, MAX_FRAGMENTS, parse_carrier_header,
};

/// Computes `payload_id = SHA3-384(script[0..(64 + data_len)])`.
///
/// `script` is expected to be the entire `script_public_key.script()` of a
/// V5 carrier output, including the 64-byte header and the trailing data.
/// The caller is responsible for having validated structural correctness
/// via `parse_carrier_header` first if they want a defensive guarantee
/// that the input is well-formed; `payload_id` itself is purely a hash.
pub fn payload_id(script: &[u8]) -> [u8; CARRIER_PAYLOAD_HASH_LEN] {
    let mut hasher = Sha3_384::new();
    hasher.update(script);
    hasher.finalize().into()
}

/// Computes `bundle_id = SHA3-384(data_full)` of a fully reassembled blob.
///
/// `data_full` is the concatenation of every fragment's `data` section in
/// `fragment_index` order. Single-fragment bundles call this with that
/// single fragment's body.
pub fn bundle_id_of(data_full: &[u8]) -> [u8; CARRIER_PAYLOAD_HASH_LEN] {
    let mut hasher = Sha3_384::new();
    hasher.update(data_full);
    hasher.finalize().into()
}

/// Encodes a carrier `script` from primitive parts.
///
/// The caller supplies the `flags` byte directly so that producer tooling
/// (sequencer, relayer, user wallet) can set domain bits + reserved bits
/// independently. `encode_carrier_script` enforces the same length and
/// fragment-count bounds the consensus does, returning `Err` on misuse so
/// producers cannot silently emit invalid bytes.
///
/// On success the returned `Vec<u8>` is bit-exact what consensus expects:
/// `parse_carrier_header(&out).is_ok()` whenever the inputs themselves
/// also satisfy rules 1-11 of §5 (the function does NOT reach into flags
/// to fix mismatches).
pub fn encode_carrier_script(
    flags: u8,
    fragment_count: u8,
    fragment_index: u8,
    data: &[u8],
    bundle_id: [u8; CARRIER_PAYLOAD_HASH_LEN],
) -> Result<Vec<u8>, CarrierError> {
    if fragment_count == 0 || fragment_count > MAX_FRAGMENTS {
        return Err(CarrierError::BadFragmentCount(fragment_count));
    }
    if fragment_index >= fragment_count {
        return Err(CarrierError::FragmentIndexOutOfRange { index: fragment_index, count: fragment_count });
    }
    if data.len() > MAX_DATA_PER_CARRIER as usize {
        return Err(CarrierError::DataTooLarge { data_len: data.len() as u32 });
    }

    let mut out = Vec::with_capacity(CARRIER_HEADER_LEN + data.len());
    out.extend_from_slice(&CARRIER_MAGIC);
    out.push(flags);
    out.push(0); // reserved
    out.push(fragment_count);
    out.push(fragment_index);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&bundle_id);
    out.extend_from_slice(data);
    Ok(out)
}

/// Helper: encode a single-fragment carrier given the data and an optional
/// domain. Sets `CARRIER_FLAG_LAST` and computes `bundle_id` from the data.
/// Use this when you have one blob that fits in `MAX_DATA_PER_CARRIER`.
pub fn encode_single_fragment(data: &[u8], domain: Option<CarrierDomain>) -> Result<Vec<u8>, CarrierError> {
    let mut flags = CARRIER_FLAG_LAST;
    if let Some(d) = domain {
        flags |= match d {
            CarrierDomain::Rollup => super::CARRIER_FLAG_DOMAIN_ROLLUP,
            CarrierDomain::Oracle => super::CARRIER_FLAG_DOMAIN_ORACLE,
            CarrierDomain::User => super::CARRIER_FLAG_DOMAIN_USER,
        };
    }
    let bundle_id = bundle_id_of(data);
    encode_carrier_script(flags, 1, 0, data, bundle_id)
}

/// Splits a blob into a vector of carrier scripts (one per fragment), all
/// sharing the same `bundle_id`. Returns `Err` if the blob exceeds
/// `MAX_FRAGMENTS * MAX_DATA_PER_CARRIER` bytes (which would not fit even
/// if every fragment is at max capacity).
///
/// The caller decides chunk boundaries; this helper uses
/// `MAX_DATA_PER_CARRIER`-sized chunks (the largest legal). Producers that
/// want different sizing (e.g. align to 4 KiB for storage friendliness)
/// can call `encode_carrier_script` directly per fragment.
pub fn encode_bundle(blob: &[u8], domain: Option<CarrierDomain>) -> Result<Vec<Vec<u8>>, CarrierError> {
    let chunk = MAX_DATA_PER_CARRIER as usize;
    let total = blob.len();
    let count = if total == 0 { 1 } else { total.div_ceil(chunk) };
    if count > MAX_FRAGMENTS as usize {
        return Err(CarrierError::DataTooLarge { data_len: total as u32 });
    }

    let bundle_id = bundle_id_of(blob);
    let domain_flag = match domain {
        None => 0,
        Some(CarrierDomain::Rollup) => super::CARRIER_FLAG_DOMAIN_ROLLUP,
        Some(CarrierDomain::Oracle) => super::CARRIER_FLAG_DOMAIN_ORACLE,
        Some(CarrierDomain::User) => super::CARRIER_FLAG_DOMAIN_USER,
    };

    let mut scripts = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * chunk;
        let end = (start + chunk).min(total);
        let part = &blob[start..end];

        let mut flags = domain_flag;
        if count > 1 {
            flags |= CARRIER_FLAG_FRAGMENTED;
        }
        if i == count - 1 {
            flags |= CARRIER_FLAG_LAST;
        }
        let script = encode_carrier_script(flags, count as u8, i as u8, part, bundle_id)?;
        scripts.push(script);
    }
    Ok(scripts)
}

/// One fragment's view, supplied to `reassemble`. Producers and consumers
/// usually read this directly from the parsed header + script bytes, so
/// the type is intentionally a plain pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassembleInput<'a> {
    pub header: CarrierHeader,
    pub script: &'a [u8],
}

/// Reassembly errors are distinct from `CarrierError`: a single fragment
/// may parse cleanly yet still produce a defective bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassembleError {
    /// The fragment list was empty.
    NoFragments,
    /// Fragments disagree on `fragment_count`.
    FragmentCountMismatch { first: u8, found: u8 },
    /// Fragments disagree on `bundle_id`.
    BundleIdMismatch,
    /// Some `fragment_index` value was missing.
    MissingFragmentIndex(u8),
    /// Two fragments had the same `fragment_index`.
    DuplicateFragmentIndex(u8),
    /// SHA3-384 of the reassembled body did not equal the claimed bundle_id.
    BundleHashMismatch,
}

impl std::fmt::Display for ReassembleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoFragments => write!(f, "no fragments supplied to reassemble"),
            Self::FragmentCountMismatch { first, found } => {
                write!(f, "fragments disagree on fragment_count: {first} vs {found}")
            }
            Self::BundleIdMismatch => write!(f, "fragments carry different bundle_ids"),
            Self::MissingFragmentIndex(i) => write!(f, "fragment index {i} is missing from the input set"),
            Self::DuplicateFragmentIndex(i) => write!(f, "fragment index {i} appears more than once"),
            Self::BundleHashMismatch => write!(f, "SHA3-384 of reassembled bytes does not match claimed bundle_id"),
        }
    }
}

impl std::error::Error for ReassembleError {}

/// Concatenates fragment bodies in `fragment_index` order, verifying that
/// the resulting bytes hash to the claimed `bundle_id`. Returns the
/// reassembled blob on success.
///
/// Inputs are unordered: callers can pass fragments in any order. The
/// function indexes them internally and rejects gaps, duplicates, and
/// disagreements about either `fragment_count` or `bundle_id`.
pub fn reassemble(inputs: &[ReassembleInput<'_>]) -> Result<Vec<u8>, ReassembleError> {
    if inputs.is_empty() {
        return Err(ReassembleError::NoFragments);
    }

    let count = inputs[0].header.fragment_count;
    let bundle_id = inputs[0].header.bundle_id;

    for input in &inputs[1..] {
        if input.header.fragment_count != count {
            return Err(ReassembleError::FragmentCountMismatch { first: count, found: input.header.fragment_count });
        }
        if input.header.bundle_id != bundle_id {
            return Err(ReassembleError::BundleIdMismatch);
        }
    }

    // Slot fragments into a fixed array indexed by fragment_index. We use
    // Option<&[u8]> instead of Vec<u8> to avoid copying twice.
    let mut slots: Vec<Option<&[u8]>> = vec![None; count as usize];
    for input in inputs {
        let idx = input.header.fragment_index as usize;
        if slots[idx].is_some() {
            return Err(ReassembleError::DuplicateFragmentIndex(input.header.fragment_index));
        }
        let data_start = CARRIER_HEADER_LEN;
        let data_end = data_start + input.header.data_len as usize;
        slots[idx] = Some(&input.script[data_start..data_end]);
    }

    let mut total = 0usize;
    for (i, slot) in slots.iter().enumerate() {
        match slot {
            Some(d) => total += d.len(),
            None => return Err(ReassembleError::MissingFragmentIndex(i as u8)),
        }
    }

    let mut out = Vec::with_capacity(total);
    for slot in slots.iter() {
        out.extend_from_slice(slot.unwrap());
    }

    if bundle_id_of(&out) != bundle_id {
        return Err(ReassembleError::BundleHashMismatch);
    }

    Ok(out)
}

/// Convenience: parse each `script` and feed the result into `reassemble`.
/// Produces both the structural error (if any script is malformed) and
/// the reassembly error in one call. Returns the reassembled blob.
pub fn parse_and_reassemble(scripts: &[&[u8]]) -> Result<Vec<u8>, ReassembleError> {
    let mut owned: Vec<(CarrierHeader, &[u8])> = Vec::with_capacity(scripts.len());
    for s in scripts {
        let h = parse_carrier_header(s).map_err(|_| ReassembleError::BundleHashMismatch)?;
        owned.push((h, *s));
    }
    let inputs: Vec<ReassembleInput<'_>> =
        owned.into_iter().map(|(header, script)| ReassembleInput { header, script }).collect();
    reassemble(&inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_384_known_vector_empty() {
        // FIPS 202 test vector for SHA3-384("")
        let expected: [u8; 48] = hex_decode_48(
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
        );
        assert_eq!(bundle_id_of(b""), expected);
    }

    #[test]
    fn sha3_384_known_vector_abc() {
        // FIPS 202 test vector for SHA3-384("abc")
        let expected: [u8; 48] = hex_decode_48(
            "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
        );
        assert_eq!(bundle_id_of(b"abc"), expected);
    }

    #[test]
    fn encode_then_parse_roundtrip_single() {
        let data = b"Sophis Phase 6 carrier";
        let script = encode_single_fragment(data, Some(CarrierDomain::Oracle)).unwrap();
        let h = parse_carrier_header(&script).unwrap();
        assert_eq!(h.fragment_count, 1);
        assert_eq!(h.fragment_index, 0);
        assert_eq!(h.data_len as usize, data.len());
        assert!(h.is_last());
        assert!(!h.is_fragmented());
        assert_eq!(h.domain(), Some(CarrierDomain::Oracle));
        assert_eq!(h.bundle_id, bundle_id_of(data));
    }

    #[test]
    fn payload_id_is_sha3_384_of_full_script() {
        let data = b"some bytes";
        let script = encode_single_fragment(data, None).unwrap();
        let pid = payload_id(&script);
        // Recompute by hand
        let mut hasher = Sha3_384::new();
        hasher.update(&script);
        let manual: [u8; 48] = hasher.finalize().into();
        assert_eq!(pid, manual);
    }

    #[test]
    fn payload_id_differs_from_bundle_id_for_single_fragment() {
        let data = b"x";
        let script = encode_single_fragment(data, None).unwrap();
        let pid = payload_id(&script);
        let bid = bundle_id_of(data);
        // payload_id hashes the framed script (header + data); bundle_id hashes raw data
        assert_ne!(pid, bid, "payload_id and bundle_id MUST differ even for a single fragment");
    }

    #[test]
    fn encode_bundle_single_fragment_when_blob_fits() {
        let blob = vec![0xAB; 100];
        let scripts = encode_bundle(&blob, Some(CarrierDomain::Rollup)).unwrap();
        assert_eq!(scripts.len(), 1);
        let h = parse_carrier_header(&scripts[0]).unwrap();
        assert_eq!(h.fragment_count, 1);
        assert!(!h.is_fragmented());
        assert!(h.is_last());
    }

    #[test]
    fn encode_bundle_splits_when_blob_exceeds_chunk() {
        // One chunk + 1 byte forces 2 fragments
        let blob = vec![0xCD; MAX_DATA_PER_CARRIER as usize + 1];
        let scripts = encode_bundle(&blob, None).unwrap();
        assert_eq!(scripts.len(), 2);
        let h0 = parse_carrier_header(&scripts[0]).unwrap();
        let h1 = parse_carrier_header(&scripts[1]).unwrap();
        assert!(h0.is_fragmented());
        assert!(!h0.is_last());
        assert!(h1.is_fragmented());
        assert!(h1.is_last());
        assert_eq!(h0.bundle_id, h1.bundle_id);
        assert_eq!(h0.bundle_id, bundle_id_of(&blob));
    }

    #[test]
    fn encode_bundle_rejects_oversize() {
        let oversize = vec![0u8; (MAX_FRAGMENTS as usize * MAX_DATA_PER_CARRIER as usize) + 1];
        match encode_bundle(&oversize, None) {
            Err(CarrierError::DataTooLarge { .. }) => {}
            other => panic!("expected DataTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn reassemble_happy_path_multi_fragment() {
        let blob: Vec<u8> = (0u8..=200).cycle().take(MAX_DATA_PER_CARRIER as usize * 3 + 17).collect();
        let scripts = encode_bundle(&blob, None).unwrap();
        assert_eq!(scripts.len(), 4);
        let refs: Vec<&[u8]> = scripts.iter().map(|s| s.as_slice()).collect();
        let out = parse_and_reassemble(&refs).unwrap();
        assert_eq!(out, blob);
    }

    #[test]
    fn reassemble_handles_unordered_inputs() {
        let blob = vec![0x77; MAX_DATA_PER_CARRIER as usize * 2 + 5];
        let scripts = encode_bundle(&blob, None).unwrap();
        // Reverse the order
        let refs: Vec<&[u8]> = scripts.iter().rev().map(|s| s.as_slice()).collect();
        let out = parse_and_reassemble(&refs).unwrap();
        assert_eq!(out, blob);
    }

    #[test]
    fn reassemble_rejects_no_fragments() {
        match reassemble(&[]) {
            Err(ReassembleError::NoFragments) => {}
            other => panic!("expected NoFragments, got {other:?}"),
        }
    }

    #[test]
    fn reassemble_rejects_missing_fragment() {
        let blob = vec![0xEE; MAX_DATA_PER_CARRIER as usize + 10];
        let scripts = encode_bundle(&blob, None).unwrap();
        // Drop fragment 0
        let only_last = vec![scripts[1].as_slice()];
        match parse_and_reassemble(&only_last) {
            Err(ReassembleError::MissingFragmentIndex(0)) => {}
            other => panic!("expected MissingFragmentIndex(0), got {other:?}"),
        }
    }

    #[test]
    fn reassemble_rejects_duplicate_fragment_index() {
        let blob = vec![0xAA; MAX_DATA_PER_CARRIER as usize + 4];
        let scripts = encode_bundle(&blob, None).unwrap();
        // Two copies of fragment 0
        let dup = vec![scripts[0].as_slice(), scripts[0].as_slice()];
        match parse_and_reassemble(&dup) {
            Err(ReassembleError::DuplicateFragmentIndex(0)) => {}
            other => panic!("expected DuplicateFragmentIndex(0), got {other:?}"),
        }
    }

    #[test]
    fn reassemble_rejects_bundle_id_mismatch() {
        // Build two single-fragment scripts that agree on count but disagree on bundle_id
        let script_a = encode_single_fragment(b"A", None).unwrap();
        let script_b = encode_single_fragment(b"B", None).unwrap();
        let h_a = parse_carrier_header(&script_a).unwrap();
        let mut h_b = parse_carrier_header(&script_b).unwrap();
        // Fake count=2 to expose the bundle_id mismatch path. Use raw struct construction.
        h_b.fragment_count = 2;
        let inputs = [
            ReassembleInput {
                header: CarrierHeader { fragment_count: 2, ..h_a.clone() },
                script: &script_a,
            },
            ReassembleInput { header: h_b, script: &script_b },
        ];
        match reassemble(&inputs) {
            Err(ReassembleError::BundleIdMismatch) => {}
            other => panic!("expected BundleIdMismatch, got {other:?}"),
        }
    }

    #[test]
    fn reassemble_rejects_fragment_count_mismatch() {
        let blob = vec![0xCC; 10];
        let script_real = encode_single_fragment(&blob, None).unwrap();
        let h_real = parse_carrier_header(&script_real).unwrap();
        // Same script but with header claiming count=3
        let mut h_fake = h_real.clone();
        h_fake.fragment_count = 3;
        let inputs = [
            ReassembleInput { header: h_real, script: &script_real },
            ReassembleInput { header: h_fake, script: &script_real },
        ];
        match reassemble(&inputs) {
            Err(ReassembleError::FragmentCountMismatch { first: 1, found: 3 }) => {}
            other => panic!("expected FragmentCountMismatch, got {other:?}"),
        }
    }

    #[test]
    fn reassemble_rejects_bundle_hash_mismatch() {
        // Forge a single-fragment script whose bundle_id field lies about the data
        let data = b"hello";
        let mut script = encode_single_fragment(data, None).unwrap();
        // Tamper the bundle_id bytes (offset 16..64) so the claimed hash != SHA3-384(data)
        script[16] ^= 0xFF;
        let refs = [script.as_slice()];
        match parse_and_reassemble(&refs) {
            Err(ReassembleError::BundleHashMismatch) => {}
            other => panic!("expected BundleHashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn encode_carrier_script_rejects_oversize_data() {
        let huge = vec![0u8; MAX_DATA_PER_CARRIER as usize + 1];
        match encode_carrier_script(CARRIER_FLAG_LAST, 1, 0, &huge, [0u8; 48]) {
            Err(CarrierError::DataTooLarge { data_len }) => {
                assert_eq!(data_len, MAX_DATA_PER_CARRIER + 1);
            }
            other => panic!("expected DataTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn encode_carrier_script_rejects_zero_count() {
        match encode_carrier_script(0, 0, 0, b"x", [0u8; 48]) {
            Err(CarrierError::BadFragmentCount(0)) => {}
            other => panic!("expected BadFragmentCount, got {other:?}"),
        }
    }

    #[test]
    fn encode_carrier_script_rejects_index_oob() {
        match encode_carrier_script(0, 3, 5, b"x", [0u8; 48]) {
            Err(CarrierError::FragmentIndexOutOfRange { index: 5, count: 3 }) => {}
            other => panic!("expected FragmentIndexOutOfRange, got {other:?}"),
        }
    }

    // --- helpers ---

    fn hex_decode_48(s: &str) -> [u8; 48] {
        let mut out = [0u8; 48];
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), 96, "expected 96 hex chars for 48 bytes");
        for i in 0..48 {
            let hi = hex_nibble(bytes[2 * i]);
            let lo = hex_nibble(bytes[2 * i + 1]);
            out[i] = (hi << 4) | lo;
        }
        out
    }

    fn hex_nibble(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => 10 + b - b'a',
            b'A'..=b'F' => 10 + b - b'A',
            _ => panic!("invalid hex nibble: {b:?}"),
        }
    }

    // --- property / fuzz-style tests (sub-fase 6.9) ------------------

    #[test]
    fn fuzz_parse_and_reassemble_never_panics() {
        // Throw random scripts at parse_and_reassemble. The function MUST
        // return a Result (never panic), regardless of how malformed the
        // input is.
        use rand::Rng as _;
        let mut rng = rand::thread_rng();
        for _ in 0..1_000 {
            let n_fragments = rng.gen_range(1..=4);
            let mut scripts: Vec<Vec<u8>> = Vec::new();
            for _ in 0..n_fragments {
                let len = rng.gen_range(0..200);
                let mut bytes = vec![0u8; len];
                rng.fill(&mut bytes[..]);
                scripts.push(bytes);
            }
            let refs: Vec<&[u8]> = scripts.iter().map(|s| s.as_slice()).collect();
            // Don't care about success — just that we don't crash.
            let _ = parse_and_reassemble(&refs);
        }
    }

    #[test]
    fn fuzz_encode_bundle_roundtrips_for_random_blobs() {
        // For every random blob within MAX_BUNDLE_BYTES, encoding + parsing
        // + reassembling must recover the original bytes.
        use rand::Rng as _;
        let mut rng = rand::thread_rng();
        for _ in 0..200 {
            // Keep blob sizes modest so the test stays fast (2000 bytes).
            let len = rng.gen_range(0..=2_000usize);
            let mut blob = vec![0u8; len];
            rng.fill(&mut blob[..]);

            // Random domain choice.
            let domain = match rng.gen_range(0..4) {
                0 => None,
                1 => Some(CarrierDomain::Rollup),
                2 => Some(CarrierDomain::Oracle),
                _ => Some(CarrierDomain::User),
            };
            let scripts = encode_bundle(&blob, domain).expect("blob fits");
            let refs: Vec<&[u8]> = scripts.iter().map(|s| s.as_slice()).collect();
            let recovered = parse_and_reassemble(&refs).expect("encode→parse roundtrip");
            assert_eq!(recovered, blob);
        }
    }

    #[test]
    fn fuzz_payload_id_is_collision_resistant_for_distinct_inputs() {
        // 1000 random small scripts → expect 1000 distinct payload_ids.
        // SHA3-384 should not produce *any* collisions over 1000 inputs;
        // a hit would indicate a hashing bug.
        use rand::Rng as _;
        use std::collections::HashSet;
        let mut rng = rand::thread_rng();
        let mut seen: HashSet<[u8; 48]> = HashSet::new();
        for _ in 0..1_000 {
            let len = rng.gen_range(64..200);
            let mut bytes = vec![0u8; len];
            rng.fill(&mut bytes[..]);
            let pid = payload_id(&bytes);
            assert!(seen.insert(pid), "collision detected over 1000 inputs (cannot happen with SHA3-384)");
        }
    }
}
