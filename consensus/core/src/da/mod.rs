//! Phase 6 — Data Availability primitives.
//!
//! Canonical reference: `oracle/docs/PHASE6_DA_DESIGN.md`. The constants
//! and the parser in this module form the **ABI freeze** of sub-fase 6.0.
//! Any change requires a hard fork of the L1.
//!
//! A Phase 6 carrier is an unspendable transaction output whose
//! `ScriptPublicKey` has `version == SCRIPT_VERSION_CARRIER` (= 3) and
//! whose `script` starts with the magic prefix `b"SPHS-DA1"`.
//!
//! Layout of `script` (see §3.2 of the design doc):
//! ```text
//!   0..8    magic = b"SPHS-DA1"
//!   8..9    flags: u8
//!   9..10   reserved = 0
//!  10..11   fragment_count: u8     (1..=MAX_FRAGMENTS)
//!  11..12   fragment_index: u8     (0..fragment_count)
//!  12..16   data_len:       u32 LE (0..=MAX_DATA_PER_CARRIER)
//!  16..64   bundle_id:      [u8; 48]   SHA3-384 of the reassembled blob
//!  64..N    data
//! ```
//!
//! The 14 consensus rules of §5 are enforced by:
//! * rules 1-11: `parse_carrier_header` returns Err on any structural violation
//! * rule 12 (value=0): checked in `tx_validation_in_isolation` next to `validate_carrier_outputs`
//! * rule 13 (max-per-tx): same place
//! * rule 14 (no coinbase carriers): checked in `check_coinbase_in_isolation`

use std::fmt;

pub mod codec;
pub mod store_types;

pub use codec::{
    ReassembleError, ReassembleInput, bundle_id_of, encode_bundle, encode_carrier_script, encode_single_fragment,
    parse_and_reassemble, payload_id, reassemble,
};
pub use store_types::{
    BlockCarriers, BundleIndex, DOMAIN_BUCKET_SIZE, DomainBucket, PayloadEntry, PayloadId, PayloadIdHash, domain_bucket_key_bytes,
};

/// First 8 bytes of every carrier `script`. Frozen ABI.
pub const CARRIER_MAGIC: [u8; 8] = *b"SPHS-DA1";

/// Fixed-size header before the variable `data` section.
pub const CARRIER_HEADER_LEN: usize = 64;

/// Length in bytes of `payload_id` and `bundle_id`. SHA3-384 output.
pub const CARRIER_PAYLOAD_HASH_LEN: usize = 48;

/// Maximum number of fragments that can share a single `bundle_id`.
pub const MAX_FRAGMENTS: u8 = 32;

/// Maximum bytes in the `data` section of a single carrier output.
pub const MAX_DATA_PER_CARRIER: u32 = 65_536;

/// Maximum reassembled bundle size = MAX_FRAGMENTS * MAX_DATA_PER_CARRIER.
pub const MAX_BUNDLE_BYTES: u64 = (MAX_FRAGMENTS as u64) * (MAX_DATA_PER_CARRIER as u64);

/// Cap on V3 carrier outputs per transaction (anti-spam).
pub const MAX_CARRIER_OUTPUTS_PER_TX: usize = 8;

/// Default `min_confirmations` parameter for `Capability::VerifyDataAvailability`.
pub const DEFAULT_DA_CONFIRMATIONS: u64 = 1000;

/// Mandatory value of a carrier output (sompi). Non-zero is rejected.
pub const CARRIER_OUTPUT_VALUE: u64 = 0;

// --- flag bits ---------------------------------------------------------

pub const CARRIER_FLAG_FRAGMENTED: u8 = 0x01;
pub const CARRIER_FLAG_LAST: u8 = 0x02;
// bits 2 and 3 reserved (must be 0)
pub const CARRIER_FLAG_DOMAIN_ROLLUP: u8 = 0x10;
pub const CARRIER_FLAG_DOMAIN_ORACLE: u8 = 0x20;
pub const CARRIER_FLAG_DOMAIN_USER: u8 = 0x40;
// bit 7 reserved (must be 0)

const RESERVED_FLAG_MASK: u8 = 0b1000_1100; // bits 2, 3, 7
const DOMAIN_FLAG_MASK: u8 = CARRIER_FLAG_DOMAIN_ROLLUP | CARRIER_FLAG_DOMAIN_ORACLE | CARRIER_FLAG_DOMAIN_USER;

/// Decoded view of a V3 carrier `script`. Returned by `parse_carrier_header`.
///
/// The header itself is exactly `CARRIER_HEADER_LEN` (= 64) bytes; the
/// `data_len` field describes how many additional `data` bytes follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarrierHeader {
    pub flags: u8,
    pub fragment_count: u8,
    pub fragment_index: u8,
    pub data_len: u32,
    pub bundle_id: [u8; CARRIER_PAYLOAD_HASH_LEN],
}

impl CarrierHeader {
    pub fn is_fragmented(&self) -> bool {
        self.flags & CARRIER_FLAG_FRAGMENTED != 0
    }

    pub fn is_last(&self) -> bool {
        self.flags & CARRIER_FLAG_LAST != 0
    }

    /// Returns the single domain bit set (rollup / oracle / user) or `None`
    /// if the carrier is unclassified. Multiple-bit cases are rejected
    /// during parsing, so `Some` is always unambiguous here.
    pub fn domain(&self) -> Option<CarrierDomain> {
        match self.flags & DOMAIN_FLAG_MASK {
            0 => None,
            CARRIER_FLAG_DOMAIN_ROLLUP => Some(CarrierDomain::Rollup),
            CARRIER_FLAG_DOMAIN_ORACLE => Some(CarrierDomain::Oracle),
            CARRIER_FLAG_DOMAIN_USER => Some(CarrierDomain::User),
            _ => unreachable!("multi-domain bits are rejected by parse_carrier_header"),
        }
    }
}

/// Informational routing tag set by the producer. Has no consensus effect
/// beyond being well-formed (exactly one of the three or none).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierDomain {
    Rollup,
    Oracle,
    User,
}

/// Reasons the consensus may reject a V3 carrier output. Each maps to a
/// numbered rule from §5 of the design document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CarrierError {
    /// Rule 1 — script too short to carry the 64-byte header.
    HeaderTruncated { actual: usize },
    /// Rule 2 — first 8 bytes do not equal `CARRIER_MAGIC`.
    BadMagic,
    /// Rule 3 — reserved byte at offset 9 is non-zero.
    Reserved1NonZero(u8),
    /// Rule 4 — one of the reserved flag bits (2, 3, 7) is set.
    ReservedFlagBitSet(u8),
    /// Rule 5 — more than one mutually-exclusive domain bit is set.
    MultipleDomainFlags(u8),
    /// Rule 6 — `fragment_count` is zero or above `MAX_FRAGMENTS`.
    BadFragmentCount(u8),
    /// Rule 7 — `fragment_index >= fragment_count`.
    FragmentIndexOutOfRange { index: u8, count: u8 },
    /// Rule 8 — fragmented flag does not match `fragment_count > 1`.
    FragmentedFlagMismatch { flag_set: bool, count: u8 },
    /// Rule 9 — last flag does not match `fragment_index == fragment_count - 1`.
    LastFlagMismatch { flag_set: bool, index: u8, count: u8 },
    /// Rule 10 — `data_len` exceeds `MAX_DATA_PER_CARRIER`.
    DataTooLarge { data_len: u32 },
    /// Rule 11 — `script.len()` does not equal `CARRIER_HEADER_LEN + data_len`.
    LengthMismatch { actual: usize, expected: usize },
}

impl fmt::Display for CarrierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTruncated { actual } => {
                write!(f, "carrier script is {actual} bytes, below header minimum of {CARRIER_HEADER_LEN}")
            }
            Self::BadMagic => write!(f, "carrier magic prefix mismatch (expected SPHS-DA1)"),
            Self::Reserved1NonZero(b) => write!(f, "carrier reserved byte at offset 9 must be 0, got 0x{b:02x}"),
            Self::ReservedFlagBitSet(flags) => {
                write!(f, "carrier flags 0x{flags:02x} have a reserved bit set (mask 0x{RESERVED_FLAG_MASK:02x})")
            }
            Self::MultipleDomainFlags(flags) => {
                write!(f, "carrier flags 0x{flags:02x} have more than one domain bit set")
            }
            Self::BadFragmentCount(c) => {
                write!(f, "carrier fragment_count={c} is outside [1, {MAX_FRAGMENTS}]")
            }
            Self::FragmentIndexOutOfRange { index, count } => {
                write!(f, "carrier fragment_index={index} is not in [0, {count})")
            }
            Self::FragmentedFlagMismatch { flag_set, count } => {
                write!(f, "carrier FRAGMENTED flag is {flag_set} but fragment_count={count} (must be set iff count > 1)")
            }
            Self::LastFlagMismatch { flag_set, index, count } => {
                write!(f, "carrier LAST flag is {flag_set} for fragment_index={index} of {count} (must be set iff index == count - 1)")
            }
            Self::DataTooLarge { data_len } => {
                write!(f, "carrier data_len={data_len} exceeds MAX_DATA_PER_CARRIER={MAX_DATA_PER_CARRIER}")
            }
            Self::LengthMismatch { actual, expected } => {
                write!(f, "carrier script length is {actual}, expected {expected} (header + data_len)")
            }
        }
    }
}

impl std::error::Error for CarrierError {}

/// Parses and validates the 64-byte header of a carrier `script`, plus the
/// length-consistency check between `data_len` and `script.len()`.
///
/// On `Ok` the script is structurally well-formed for rules 1-11 of §5.
/// Rule 12 (value=0), rule 13 (max-per-tx), and rule 14 (no carrier in
/// coinbase) are enforced at the transaction-validator layer because they
/// require additional context the parser does not see.
pub fn parse_carrier_header(script: &[u8]) -> Result<CarrierHeader, CarrierError> {
    // Rule 1
    if script.len() < CARRIER_HEADER_LEN {
        return Err(CarrierError::HeaderTruncated { actual: script.len() });
    }

    // Rule 2
    if script[0..8] != CARRIER_MAGIC {
        return Err(CarrierError::BadMagic);
    }

    let flags = script[8];

    // Rule 3
    if script[9] != 0 {
        return Err(CarrierError::Reserved1NonZero(script[9]));
    }

    // Rule 4
    if flags & RESERVED_FLAG_MASK != 0 {
        return Err(CarrierError::ReservedFlagBitSet(flags));
    }

    // Rule 5
    let domain_bits = flags & DOMAIN_FLAG_MASK;
    if domain_bits != 0 && !domain_bits.is_power_of_two() {
        return Err(CarrierError::MultipleDomainFlags(flags));
    }

    let fragment_count = script[10];
    let fragment_index = script[11];

    // Rule 6
    if fragment_count == 0 || fragment_count > MAX_FRAGMENTS {
        return Err(CarrierError::BadFragmentCount(fragment_count));
    }

    // Rule 7
    if fragment_index >= fragment_count {
        return Err(CarrierError::FragmentIndexOutOfRange { index: fragment_index, count: fragment_count });
    }

    // Rule 8
    let frag_flag_set = flags & CARRIER_FLAG_FRAGMENTED != 0;
    if frag_flag_set != (fragment_count > 1) {
        return Err(CarrierError::FragmentedFlagMismatch { flag_set: frag_flag_set, count: fragment_count });
    }

    // Rule 9
    let last_flag_set = flags & CARRIER_FLAG_LAST != 0;
    if last_flag_set != (fragment_index == fragment_count - 1) {
        return Err(CarrierError::LastFlagMismatch { flag_set: last_flag_set, index: fragment_index, count: fragment_count });
    }

    let data_len = u32::from_le_bytes([script[12], script[13], script[14], script[15]]);

    // Rule 10
    if data_len > MAX_DATA_PER_CARRIER {
        return Err(CarrierError::DataTooLarge { data_len });
    }

    // Rule 11
    let expected_len = CARRIER_HEADER_LEN + data_len as usize;
    if script.len() != expected_len {
        return Err(CarrierError::LengthMismatch { actual: script.len(), expected: expected_len });
    }

    let mut bundle_id = [0u8; CARRIER_PAYLOAD_HASH_LEN];
    bundle_id.copy_from_slice(&script[16..16 + CARRIER_PAYLOAD_HASH_LEN]);

    Ok(CarrierHeader { flags, fragment_count, fragment_index, data_len, bundle_id })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_script(flags: u8, count: u8, index: u8, data: &[u8], bundle_id: [u8; 48]) -> Vec<u8> {
        let mut s = Vec::with_capacity(CARRIER_HEADER_LEN + data.len());
        s.extend_from_slice(&CARRIER_MAGIC);
        s.push(flags);
        s.push(0); // reserved
        s.push(count);
        s.push(index);
        s.extend_from_slice(&(data.len() as u32).to_le_bytes());
        s.extend_from_slice(&bundle_id);
        s.extend_from_slice(data);
        s
    }

    fn happy_single_fragment() -> Vec<u8> {
        build_script(CARRIER_FLAG_LAST, 1, 0, b"hello", [0x42u8; 48])
    }

    #[test]
    fn parse_happy_single_fragment() {
        let s = happy_single_fragment();
        let h = parse_carrier_header(&s).expect("happy path must parse");
        assert_eq!(h.fragment_count, 1);
        assert_eq!(h.fragment_index, 0);
        assert_eq!(h.data_len, 5);
        assert_eq!(h.bundle_id, [0x42u8; 48]);
        assert!(!h.is_fragmented());
        assert!(h.is_last());
        assert_eq!(h.domain(), None);
    }

    #[test]
    fn parse_happy_multi_fragment_first() {
        // count=3, index=0 -> fragmented set, last clear
        let s = build_script(CARRIER_FLAG_FRAGMENTED, 3, 0, &[0xAA; 100], [0u8; 48]);
        let h = parse_carrier_header(&s).unwrap();
        assert!(h.is_fragmented());
        assert!(!h.is_last());
    }

    #[test]
    fn parse_happy_multi_fragment_last() {
        // count=3, index=2 -> both flags set
        let s = build_script(CARRIER_FLAG_FRAGMENTED | CARRIER_FLAG_LAST, 3, 2, &[0xAA; 100], [0u8; 48]);
        let h = parse_carrier_header(&s).unwrap();
        assert!(h.is_fragmented());
        assert!(h.is_last());
    }

    #[test]
    fn parse_happy_with_domain_oracle() {
        let flags = CARRIER_FLAG_LAST | CARRIER_FLAG_DOMAIN_ORACLE;
        let s = build_script(flags, 1, 0, b"x", [0u8; 48]);
        let h = parse_carrier_header(&s).unwrap();
        assert_eq!(h.domain(), Some(CarrierDomain::Oracle));
    }

    // --- Rule 1 -------------------------------------------------------

    #[test]
    fn rule_1_header_truncated() {
        let s = vec![0u8; 63]; // 1 byte short
        match parse_carrier_header(&s) {
            Err(CarrierError::HeaderTruncated { actual }) => assert_eq!(actual, 63),
            other => panic!("expected HeaderTruncated, got {other:?}"),
        }
    }

    // --- Rule 2 -------------------------------------------------------

    #[test]
    fn rule_2_bad_magic() {
        let mut s = happy_single_fragment();
        s[0] = b'X';
        assert_eq!(parse_carrier_header(&s), Err(CarrierError::BadMagic));
    }

    // --- Rule 3 -------------------------------------------------------

    #[test]
    fn rule_3_reserved_byte_nonzero() {
        let mut s = happy_single_fragment();
        s[9] = 0xFF;
        assert_eq!(parse_carrier_header(&s), Err(CarrierError::Reserved1NonZero(0xFF)));
    }

    // --- Rule 4 -------------------------------------------------------

    #[test]
    fn rule_4_reserved_flag_bit_set() {
        // bit 2 set
        let mut s = happy_single_fragment();
        s[8] = CARRIER_FLAG_LAST | 0x04;
        match parse_carrier_header(&s) {
            Err(CarrierError::ReservedFlagBitSet(_)) => {}
            other => panic!("expected ReservedFlagBitSet, got {other:?}"),
        }
        // bit 7 set
        let mut s = happy_single_fragment();
        s[8] = CARRIER_FLAG_LAST | 0x80;
        match parse_carrier_header(&s) {
            Err(CarrierError::ReservedFlagBitSet(_)) => {}
            other => panic!("expected ReservedFlagBitSet for bit 7, got {other:?}"),
        }
    }

    // --- Rule 5 -------------------------------------------------------

    #[test]
    fn rule_5_multiple_domain_flags() {
        let mut s = happy_single_fragment();
        s[8] = CARRIER_FLAG_LAST | CARRIER_FLAG_DOMAIN_ROLLUP | CARRIER_FLAG_DOMAIN_ORACLE;
        match parse_carrier_header(&s) {
            Err(CarrierError::MultipleDomainFlags(_)) => {}
            other => panic!("expected MultipleDomainFlags, got {other:?}"),
        }
    }

    // --- Rule 6 -------------------------------------------------------

    #[test]
    fn rule_6_zero_fragment_count() {
        // can't go via build_script with count=0 because it would also fail rules 8/9;
        // construct manually
        let mut s = happy_single_fragment();
        s[10] = 0;
        s[8] = 0; // clear LAST so we don't double-fail
        match parse_carrier_header(&s) {
            Err(CarrierError::BadFragmentCount(0)) => {}
            other => panic!("expected BadFragmentCount(0), got {other:?}"),
        }
    }

    #[test]
    fn rule_6_fragment_count_too_high() {
        let mut s = happy_single_fragment();
        s[10] = MAX_FRAGMENTS + 1;
        match parse_carrier_header(&s) {
            Err(CarrierError::BadFragmentCount(c)) => assert_eq!(c, MAX_FRAGMENTS + 1),
            other => panic!("expected BadFragmentCount, got {other:?}"),
        }
    }

    // --- Rule 7 -------------------------------------------------------

    #[test]
    fn rule_7_fragment_index_out_of_range() {
        // count = 3, index = 5
        let mut s = build_script(CARRIER_FLAG_FRAGMENTED, 3, 0, b"", [0u8; 48]);
        s[11] = 5;
        match parse_carrier_header(&s) {
            Err(CarrierError::FragmentIndexOutOfRange { index, count }) => {
                assert_eq!(index, 5);
                assert_eq!(count, 3);
            }
            other => panic!("expected FragmentIndexOutOfRange, got {other:?}"),
        }
    }

    // --- Rule 8 -------------------------------------------------------

    #[test]
    fn rule_8_fragmented_flag_mismatch_set_but_count_one() {
        // count = 1 but FRAGMENTED set
        let s = build_script(CARRIER_FLAG_FRAGMENTED | CARRIER_FLAG_LAST, 1, 0, b"x", [0u8; 48]);
        match parse_carrier_header(&s) {
            Err(CarrierError::FragmentedFlagMismatch { flag_set: true, count: 1 }) => {}
            other => panic!("expected FragmentedFlagMismatch (set but count=1), got {other:?}"),
        }
    }

    #[test]
    fn rule_8_fragmented_flag_mismatch_clear_but_count_three() {
        // count = 3 but FRAGMENTED not set; index 2 so LAST is set
        let s = build_script(CARRIER_FLAG_LAST, 3, 2, b"x", [0u8; 48]);
        match parse_carrier_header(&s) {
            Err(CarrierError::FragmentedFlagMismatch { flag_set: false, count: 3 }) => {}
            other => panic!("expected FragmentedFlagMismatch (clear but count=3), got {other:?}"),
        }
    }

    // --- Rule 9 -------------------------------------------------------

    #[test]
    fn rule_9_last_flag_mismatch_set_at_non_last_index() {
        // count = 3, index = 0, LAST wrongly set, FRAGMENTED correct
        let s = build_script(CARRIER_FLAG_FRAGMENTED | CARRIER_FLAG_LAST, 3, 0, b"x", [0u8; 48]);
        match parse_carrier_header(&s) {
            Err(CarrierError::LastFlagMismatch { flag_set: true, index: 0, count: 3 }) => {}
            other => panic!("expected LastFlagMismatch (set at non-last), got {other:?}"),
        }
    }

    #[test]
    fn rule_9_last_flag_mismatch_clear_at_last_index() {
        // count = 3, index = 2, LAST wrongly cleared
        let s = build_script(CARRIER_FLAG_FRAGMENTED, 3, 2, b"x", [0u8; 48]);
        match parse_carrier_header(&s) {
            Err(CarrierError::LastFlagMismatch { flag_set: false, index: 2, count: 3 }) => {}
            other => panic!("expected LastFlagMismatch (clear at last), got {other:?}"),
        }
    }

    // --- Rule 10 ------------------------------------------------------

    #[test]
    fn rule_10_data_too_large() {
        // construct a header with declared data_len = MAX_DATA_PER_CARRIER + 1, but no body
        // (we only need to fail on the data_len check, not actually allocate)
        let mut s = vec![0u8; CARRIER_HEADER_LEN];
        s[0..8].copy_from_slice(&CARRIER_MAGIC);
        s[8] = CARRIER_FLAG_LAST;
        s[10] = 1;
        s[11] = 0;
        let bad_len = MAX_DATA_PER_CARRIER + 1;
        s[12..16].copy_from_slice(&bad_len.to_le_bytes());
        match parse_carrier_header(&s) {
            Err(CarrierError::DataTooLarge { data_len }) => assert_eq!(data_len, bad_len),
            other => panic!("expected DataTooLarge, got {other:?}"),
        }
    }

    // --- Rule 11 ------------------------------------------------------

    #[test]
    fn rule_11_length_mismatch_extra_trailing_bytes() {
        let mut s = happy_single_fragment();
        s.push(0xFF);
        match parse_carrier_header(&s) {
            Err(CarrierError::LengthMismatch { actual, expected }) => {
                assert_eq!(actual, expected + 1);
            }
            other => panic!("expected LengthMismatch (extra), got {other:?}"),
        }
    }

    #[test]
    fn rule_11_length_mismatch_missing_data_bytes() {
        // data_len = 10 declared but only 5 actual bytes
        let mut s = happy_single_fragment(); // data_len=5
        s[12..16].copy_from_slice(&10u32.to_le_bytes());
        match parse_carrier_header(&s) {
            Err(CarrierError::LengthMismatch { actual: 69, expected: 74 }) => {}
            other => panic!("expected LengthMismatch (missing), got {other:?}"),
        }
    }

    // --- size constants sanity ---------------------------------------

    #[test]
    fn constants_are_consistent() {
        assert_eq!(CARRIER_HEADER_LEN, 64);
        assert_eq!(CARRIER_PAYLOAD_HASH_LEN, 48);
        assert_eq!(MAX_BUNDLE_BYTES, 32 * 65_536);
        assert_eq!(CARRIER_MAGIC.len(), 8);
        // reserved mask must NOT include any of the legal bits
        let legal = CARRIER_FLAG_FRAGMENTED
            | CARRIER_FLAG_LAST
            | CARRIER_FLAG_DOMAIN_ROLLUP
            | CARRIER_FLAG_DOMAIN_ORACLE
            | CARRIER_FLAG_DOMAIN_USER;
        assert_eq!(RESERVED_FLAG_MASK & legal, 0);
        assert_eq!(RESERVED_FLAG_MASK | legal, 0xFF);
    }

    // --- property / fuzz-style tests (sub-fase 6.9) ------------------
    //
    // These run ~5000 random inputs per test; cheap (each parse is
    // microseconds). The invariant being guarded is `no panics`: every
    // call must return a Result, never abort the host.

    #[test]
    fn fuzz_parse_never_panics_on_random_input() {
        use rand::Rng as _;
        let mut rng = rand::rng();
        for _ in 0..5_000 {
            let len = rng.random_range(0..200);
            let mut bytes = vec![0u8; len];
            rng.fill(&mut bytes[..]);
            // Whatever happens, parse_carrier_header MUST return Result.
            // We don't care which variant — just that the call survives.
            let _ = parse_carrier_header(&bytes);
        }
    }

    #[test]
    fn fuzz_parse_never_panics_around_header_boundary() {
        // Aim random bytes specifically at the 64..200 byte band where
        // structural decisions happen, biased toward the magic prefix
        // so we exercise the deeper code paths.
        use rand::Rng as _;
        let mut rng = rand::rng();
        for _ in 0..2_000 {
            let len = rng.random_range(64..256);
            let mut bytes = vec![0u8; len];
            rng.fill(&mut bytes[..]);
            // 50% of the time, plant the magic prefix to drive past rule 2.
            if rng.random::<bool>() {
                bytes[0..8].copy_from_slice(&CARRIER_MAGIC);
            }
            let _ = parse_carrier_header(&bytes);
        }
    }

    #[test]
    fn fuzz_well_formed_inputs_always_parse() {
        // Generate random *valid* carriers and assert they roundtrip
        // through parse_carrier_header. Catches regressions where a new
        // rule rejects a well-formed input.
        use rand::Rng as _;
        let mut rng = rand::rng();
        for _ in 0..1_000 {
            let count = rng.random_range(1..=MAX_FRAGMENTS);
            let index = rng.random_range(0..count);
            let data_len = rng.random_range(0..=512usize); // keep small for speed
            let mut data = vec![0u8; data_len];
            rng.fill(&mut data[..]);
            let mut bundle_id = [0u8; 48];
            rng.fill(&mut bundle_id[..]);

            let mut flags = 0u8;
            if count > 1 {
                flags |= CARRIER_FLAG_FRAGMENTED;
            }
            if index == count - 1 {
                flags |= CARRIER_FLAG_LAST;
            }
            // Random domain bit (or none).
            match rng.random_range(0..4) {
                0 => {}
                1 => flags |= CARRIER_FLAG_DOMAIN_ROLLUP,
                2 => flags |= CARRIER_FLAG_DOMAIN_ORACLE,
                _ => flags |= CARRIER_FLAG_DOMAIN_USER,
            }

            let s = build_script(flags, count, index, &data, bundle_id);
            let h = parse_carrier_header(&s).unwrap_or_else(|e| {
                panic!("well-formed carrier rejected: count={count} index={index} data_len={data_len} flags={flags:#04x} err={e:?}")
            });
            assert_eq!(h.fragment_count, count);
            assert_eq!(h.fragment_index, index);
            assert_eq!(h.data_len as usize, data_len);
            assert_eq!(h.bundle_id, bundle_id);
        }
    }
}
