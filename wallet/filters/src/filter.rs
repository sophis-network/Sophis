//! Golomb-Rice filter construction + membership query.
//!
//! Implementation of the BIP-158 "basic filter" shape with the
//! BIP-158 SipHash-2-4 swapped for Sophis-canonical SHA3-384 keyed by
//! the block hash + a fixed domain separator. See
//! `docs/K2_COMPACT_FILTERS_DESIGN.md` §3 for the canonical algorithm.

use sha3::{Digest, Sha3_384};
use sophis_hashes::Hash;

use crate::codec::{decode_compact_size, encode_compact_size};
use crate::error::{FilterError, FilterResult};

/// Domain separator prepended to every per-item SHA3-384 input.
/// Frozen ABI per design §7. `b"sophis-cf-v1\0"` (14 bytes including
/// the trailing null) is identical in shape to the J3 VRF domain
/// separator — pattern: `b"sophis-{subsystem}-v1\0"`.
pub const DOMAIN_SEPARATOR: &[u8] = b"sophis-cf-v1\0";

/// Golomb-Rice parameter. `M = 2^P = 524 288`. Frozen ABI.
pub const GOLOMB_RICE_P: u32 = 19;

/// `M = 2^P`. Provided as a constant so callers can avoid the shift.
pub const GOLOMB_RICE_M: u64 = 1u64 << GOLOMB_RICE_P;

// ---------------------------------------------------------------------------
// Hash
// ---------------------------------------------------------------------------

/// Computes the 64-bit per-item hash. Output is the first 8 bytes of
/// `SHA3-384(domain || block_hash || item)` interpreted as big-endian.
pub fn hash_item(block_hash: &Hash, item: &[u8]) -> u64 {
    let mut hasher = Sha3_384::new();
    hasher.update(DOMAIN_SEPARATOR);
    hasher.update(block_hash.as_bytes());
    hasher.update(item);
    let digest = hasher.finalize();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(buf)
}

/// BIP-158-style uniform map from u64 → `[0, n * m)`. Avoids modulo
/// bias via the `(raw * range) >> 64` widening-multiply trick.
pub fn map_to_range(raw: u64, n: u64, m: u64) -> u64 {
    let range = (n as u128).saturating_mul(m as u128);
    (((raw as u128) * range) >> 64) as u64
}

// ---------------------------------------------------------------------------
// Bit writer / reader
// ---------------------------------------------------------------------------

/// MSB-first bit writer. Used to serialise the Golomb-Rice bitstream
/// as a stream of bytes.
struct BitWriter {
    out: Vec<u8>,
    /// Number of bits already filled in the current trailing byte.
    /// `0..=7`. When `==8` the byte is full and we push a fresh one.
    bits_in_last: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self { out: Vec::new(), bits_in_last: 8 }
    }

    fn write_bit(&mut self, bit: u8) {
        if self.bits_in_last == 8 {
            self.out.push(0);
            self.bits_in_last = 0;
        }
        let last = self.out.last_mut().expect("just pushed");
        // MSB-first: shift bit into position (7 - bits_in_last).
        *last |= (bit & 1) << (7 - self.bits_in_last);
        self.bits_in_last += 1;
    }

    /// Writes the low `nbits` bits of `value`, MSB-first.
    fn write_bits(&mut self, value: u64, nbits: u32) {
        for i in (0..nbits).rev() {
            self.write_bit(((value >> i) & 1) as u8);
        }
    }

    fn finish(self) -> Vec<u8> {
        self.out
    }
}

/// MSB-first bit reader.
struct BitReader<'a> {
    bytes: &'a [u8],
    /// Bit offset from the start of the byte stream.
    pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn read_bit(&mut self) -> Option<u8> {
        let byte_idx = self.pos / 8;
        let bit_idx = self.pos % 8;
        if byte_idx >= self.bytes.len() {
            return None;
        }
        let bit = (self.bytes[byte_idx] >> (7 - bit_idx)) & 1;
        self.pos += 1;
        Some(bit)
    }

    fn read_bits(&mut self, nbits: u32) -> Option<u64> {
        let mut v = 0u64;
        for _ in 0..nbits {
            v = (v << 1) | self.read_bit()? as u64;
        }
        Some(v)
    }
}

// ---------------------------------------------------------------------------
// Golomb-Rice encode / decode of a sorted-deduped u64 sequence
// ---------------------------------------------------------------------------

/// Encodes the deltas of a sorted-deduped u64 sequence with Golomb-Rice
/// parameter P. `delta_i = v_i - v_{i-1} - 1` with `v_{-1} = -1`
/// (i.e. the first element's "delta" is `v_0`).
fn encode_gr(values: &[u64], p: u32) -> Vec<u8> {
    let mut bw = BitWriter::new();
    let mut prev: i128 = -1;
    for &v in values {
        let delta = (v as i128 - prev - 1) as u64;
        prev = v as i128;
        // Quotient: unary `q` 1-bits then a 0 terminator.
        let q = delta >> p;
        for _ in 0..q {
            bw.write_bit(1);
        }
        bw.write_bit(0);
        // Remainder: low p bits.
        let r = delta & ((1u64 << p) - 1);
        bw.write_bits(r, p);
    }
    bw.finish()
}

/// Decodes the Golomb-Rice bitstream to recover the sorted-deduped
/// original u64 sequence. Returns the values as `Vec<u64>` for
/// callers that want to enumerate the filter contents (rare); the
/// hot path is `filter_matches` which short-circuits.
#[allow(dead_code)]
fn decode_gr(bytes: &[u8], n: u64, p: u32) -> FilterResult<Vec<u64>> {
    let mut br = BitReader::new(bytes);
    let mut out = Vec::with_capacity(n as usize);
    let mut prev: i128 = -1;
    for i in 0..n {
        // Read unary quotient.
        let mut q: u64 = 0;
        loop {
            match br.read_bit() {
                Some(1) => q += 1,
                Some(_) => break, // 0
                None => return Err(FilterError::TruncatedBitstream(i)),
            }
        }
        let r = br.read_bits(p).ok_or(FilterError::TruncatedBitstream(i))?;
        let delta = (q << p) | r;
        let v = (prev + 1 + delta as i128) as u64;
        prev = v as i128;
        out.push(v);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Filter construction
// ---------------------------------------------------------------------------

/// Builds the BIP-158 basic-filter wire bytes for the given items.
/// Empty items are dropped; remaining items are hashed-mapped-sorted-
/// deduped before encoding. Returns the on-the-wire bytes (compact-size
/// element count + Golomb-Rice bitstream).
///
/// Frozen ABI: `P = GOLOMB_RICE_P = 19`.
pub fn build_basic_filter(block_hash: &Hash, items: &[&[u8]]) -> Vec<u8> {
    // 1. Drop empties.
    let nonempty: Vec<&[u8]> = items.iter().copied().filter(|i| !i.is_empty()).collect();
    let n = nonempty.len() as u64;
    if n == 0 {
        // Empty filter: just the compact-size 0 byte.
        let mut out = Vec::with_capacity(1);
        encode_compact_size(0, &mut out);
        return out;
    }

    // 2. Hash + map-to-range.
    let mut mapped: Vec<u64> = nonempty.iter().map(|it| map_to_range(hash_item(block_hash, it), n, GOLOMB_RICE_M)).collect();

    // 3. Sort + dedupe (BIP-158 spec).
    mapped.sort_unstable();
    mapped.dedup();

    // 4. Encode: compact-size N (original count, NOT post-dedupe) + GR bitstream.
    let mut out = Vec::with_capacity(1 + mapped.len() * 4);
    encode_compact_size(n, &mut out);
    out.extend_from_slice(&encode_gr(&mapped, GOLOMB_RICE_P));
    out
}

/// Computes the 32-byte `filter_hash` of an on-the-wire filter.
/// `SHA3-384(filter_bytes)[..32]`.
pub fn filter_hash(filter_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_384::new();
    hasher.update(filter_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// Computes the 32-byte `filter_header` for a block.
/// `SHA3-384(prev_header || filter_hash)[..32]`. `prev_header` is the
/// `filter_header` of the GHOSTDAG selected parent; `[0u8; 32]` for
/// the genesis-parent case.
pub fn build_filter_header(prev_header: &[u8; 32], current_filter_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_384::new();
    hasher.update(prev_header);
    hasher.update(current_filter_hash);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

// ---------------------------------------------------------------------------
// Membership query
// ---------------------------------------------------------------------------

/// Checks whether `item` is (probably) present in `filter_bytes`.
/// `Ok(true)` indicates the filter contains a hash matching `item`;
/// `Ok(false)` is an authoritative absence (zero false negatives).
/// `Err(_)` is a wire-format error.
///
/// False-positive rate per query: `1 / GOLOMB_RICE_M ≈ 1.9 × 10⁻⁶`.
pub fn filter_matches(filter_bytes: &[u8], block_hash: &Hash, item: &[u8]) -> FilterResult<bool> {
    if item.is_empty() {
        // Empty items are dropped at construction time.
        return Ok(false);
    }
    let (n, prefix_len) = decode_compact_size(filter_bytes)?;
    if n == 0 {
        return Ok(false);
    }
    let bitstream = &filter_bytes[prefix_len..];
    let target = map_to_range(hash_item(block_hash, item), n, GOLOMB_RICE_M);

    // Stream through the GR bitstream, comparing on the fly.
    let mut br = BitReader::new(bitstream);
    let mut prev: i128 = -1;
    for i in 0..n {
        let mut q: u64 = 0;
        loop {
            match br.read_bit() {
                Some(1) => q += 1,
                Some(_) => break, // 0
                None => return Err(FilterError::TruncatedBitstream(i)),
            }
        }
        let r = br.read_bits(GOLOMB_RICE_P).ok_or(FilterError::TruncatedBitstream(i))?;
        let delta = (q << GOLOMB_RICE_P) | r;
        let v = (prev + 1 + delta as i128) as u64;
        prev = v as i128;
        if v == target {
            return Ok(true);
        }
        if v > target {
            // Sorted stream — no future value can match.
            return Ok(false);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(byte: u8) -> Hash {
        Hash::from_slice(&[byte; 32])
    }

    #[test]
    fn domain_separator_is_frozen() {
        assert_eq!(DOMAIN_SEPARATOR, b"sophis-cf-v1\0");
        // 12 chars ("sophis-cf-v1") + 1 null = 13 bytes. Differs from
        // sophis-vrf-v1 (14 bytes) because "cf" is one char shorter
        // than "vrf".
        assert_eq!(DOMAIN_SEPARATOR.len(), 13);
    }

    #[test]
    fn p_constant_is_19() {
        assert_eq!(GOLOMB_RICE_P, 19);
        assert_eq!(GOLOMB_RICE_M, 524_288);
    }

    #[test]
    fn empty_filter_has_just_compact_size_zero() {
        let f = build_basic_filter(&block(1), &[]);
        assert_eq!(f, vec![0]);
    }

    #[test]
    fn empty_filter_matches_nothing() {
        let f = build_basic_filter(&block(1), &[]);
        assert!(!filter_matches(&f, &block(1), b"anything").unwrap());
    }

    #[test]
    fn singleton_filter_matches_known_item() {
        let f = build_basic_filter(&block(2), &[b"hello"]);
        assert!(filter_matches(&f, &block(2), b"hello").unwrap());
    }

    #[test]
    fn singleton_filter_misses_unknown_item() {
        // Hand-pick a value pair where the false-positive doesn't fire.
        let f = build_basic_filter(&block(3), &[b"hello"]);
        // Probability of accidental match for any specific other input
        // is 1/M ≈ 1.9e-6. Try several to be statistically safe.
        for s in [b"world".as_slice(), b"foo", b"bar", b"baz"] {
            let m = filter_matches(&f, &block(3), s).unwrap();
            // If this asserts false, we got the 1-in-half-million case
            // for ALL of these inputs simultaneously — astronomically
            // unlikely with a deterministic hash. Re-roll if it ever
            // happens.
            assert!(!m, "unexpected match on {:?}", s);
        }
    }

    #[test]
    fn multi_item_filter_matches_each() {
        let items: Vec<&[u8]> = vec![b"alpha", b"beta", b"gamma", b"delta"];
        let f = build_basic_filter(&block(4), &items);
        for it in &items {
            assert!(filter_matches(&f, &block(4), it).unwrap(), "missed {:?}", it);
        }
    }

    #[test]
    fn filter_changes_with_block_hash() {
        let f1 = build_basic_filter(&block(5), &[b"x"]);
        let f2 = build_basic_filter(&block(6), &[b"x"]);
        assert_ne!(f1, f2);
    }

    #[test]
    fn empty_items_dropped() {
        let items: Vec<&[u8]> = vec![&[], b"x", &[]];
        let f = build_basic_filter(&block(7), &items);
        // Element count should be 1, not 3
        let (n, _) = decode_compact_size(&f).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn duplicate_items_match_once() {
        let items: Vec<&[u8]> = vec![b"x", b"x", b"x"];
        let f = build_basic_filter(&block(8), &items);
        // Wire format compact-size is the post-empty count (3 here, not 1).
        // Internal sort+dedup brings the GR stream down to a single element.
        let (n, _) = decode_compact_size(&f).unwrap();
        assert_eq!(n, 3, "compact-size encodes pre-dedupe count");
        assert!(filter_matches(&f, &block(8), b"x").unwrap());
    }

    #[test]
    fn filter_hash_is_32_bytes_deterministic() {
        let f = build_basic_filter(&block(9), &[b"a", b"b", b"c"]);
        let h1 = filter_hash(&f);
        let h2 = filter_hash(&f);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn filter_header_chains() {
        let prev = [0u8; 32];
        let fh = filter_hash(&build_basic_filter(&block(10), &[b"x"]));
        let h1 = build_filter_header(&prev, &fh);
        // Same inputs → same output.
        let h2 = build_filter_header(&prev, &fh);
        assert_eq!(h1, h2);
        // Changing prev or fh changes the result.
        let h3 = build_filter_header(&[0xAA; 32], &fh);
        assert_ne!(h1, h3);
    }

    #[test]
    fn map_to_range_no_modulo_bias_on_max() {
        // Sanity: u64::MAX maps to slightly less than n*m
        let v = map_to_range(u64::MAX, 1000, GOLOMB_RICE_M);
        assert!(v < 1000 * GOLOMB_RICE_M);
    }

    #[test]
    fn decode_gr_round_trips() {
        let values = vec![5u64, 10, 1000, 1_000_000, 10_000_000];
        let bytes = encode_gr(&values, GOLOMB_RICE_P);
        let decoded = decode_gr(&bytes, values.len() as u64, GOLOMB_RICE_P).unwrap();
        assert_eq!(decoded, values);
    }

    #[test]
    fn decode_gr_single_value() {
        let v = vec![42u64];
        let bytes = encode_gr(&v, GOLOMB_RICE_P);
        let d = decode_gr(&bytes, 1, GOLOMB_RICE_P).unwrap();
        assert_eq!(d, v);
    }

    #[test]
    fn truncated_bitstream_errors_on_decode() {
        let v = vec![5u64, 10, 1000];
        let mut bytes = encode_gr(&v, GOLOMB_RICE_P);
        bytes.pop(); // drop trailing byte
        let result = decode_gr(&bytes, 3, GOLOMB_RICE_P);
        assert!(matches!(result, Err(FilterError::TruncatedBitstream(_))));
    }

    #[test]
    fn membership_short_circuits_on_value_above_target() {
        // Construct a filter where target sorts to position 0; the
        // membership check should short-circuit after element 0 if
        // every other item maps higher.
        let items: Vec<&[u8]> = (0..100).map(|_| b"x".as_slice()).collect();
        let f = build_basic_filter(&block(11), &items);
        assert!(filter_matches(&f, &block(11), b"x").unwrap());
    }

    #[test]
    fn large_filter_round_trip() {
        // Construct ~1000 items, verify each is reported present.
        let items_owned: Vec<Vec<u8>> = (0..1000u32).map(|i| i.to_le_bytes().to_vec()).collect();
        let items: Vec<&[u8]> = items_owned.iter().map(|v| v.as_slice()).collect();
        let f = build_basic_filter(&block(12), &items);
        for it in &items {
            assert!(filter_matches(&f, &block(12), it).unwrap());
        }
        // And a known-not-in item is missed (could false-positive 1/M of the time).
        let fp_count: usize = (1000..1100u32).filter(|&i| filter_matches(&f, &block(12), &i.to_le_bytes()).unwrap()).count();
        // Expected 100 * 1/524288 ≈ 0; allow generous slack.
        assert!(fp_count < 5, "too many false positives: {}", fp_count);
    }
}
