//! Post-quantum UTXO-set commitment via **LtHash** (lattice / SIS-based
//! homomorphic set hash; Lewi, Kim, Maykov, Weis 2019).
//!
//! Replaces the prior additive accumulator (`Σ blake2b(utxo) mod 2^256`,
//! the AdHash construction), whose binding is governed by modular
//! subset-sum and is broken well below 2^128 by lattice reduction /
//! generalized birthday — see audit finding F-29 + the SIP draft at
//! `docs/F29_PQ_UTXO_COMMITMENT_SIP_DRAFT.md`.
//!
//! The state is a vector of `LTHASH_LANES` 16-bit lanes (LtHash16). Each
//! element is expanded into one lane-vector (counter-mode keyed blake2b via
//! `MuHashElementHash`; SHAKE would also serve — see the SIP) and added (or
//! subtracted, for removal) component-wise mod 2^16 — an abelian group, so
//! `add`/`remove`/`combine` are O(1) and order-independent. Binding reduces
//! to a short-vector / SIS lattice problem (post-quantum). The published
//! 32-byte commitment is `MuHashFinalizeHash(state)`.

use core::fmt;

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sophis_hashes::{Hash, HasherBase, MuHashElementHash, MuHashFinalizeHash};
use sophis_utils::mem_size::MemSizeEstimator;

/// Number of 16-bit lanes in the LtHash state (LtHash16 baseline).
/// State size = `LTHASH_LANES * 2` bytes. Parameter choice is gated on
/// crypto-owner sign-off (SIP §9) — keep all sizing derived from this const.
pub const LTHASH_LANES: usize = 1024;

/// Serialized size of the LtHash **state** (the incremental multiset value
/// persisted in `UtxoMultisetsStore`). NOTE: this is the internal state, not
/// the 32-byte finalized header commitment.
pub const SERIALIZED_MUHASH_SIZE: usize = LTHASH_LANES * 2;

/// Size of the finalized commitment (the header `utxo_commitment`).
pub const HASH_SIZE: usize = 32;

/// Number of 32-byte keyed-blake2b blocks needed to fill the lane vector.
const EXPANSION_BLOCKS: usize = SERIALIZED_MUHASH_SIZE / 32;

/// Post-quantum UTXO-set commitment of the empty set: `finalize(zero state)`.
/// (No longer the all-zero hash of the additive design — the empty set now
/// maps to a hash output, so "find a non-empty set colliding with empty" is
/// the same SIS hardness as any other collision.)
pub const EMPTY_MUHASH: Hash = Hash::from_bytes([
    // = MuHashFinalizeHash(all-zero LtHash16 state); pinned from the
    // `bootstrap_empty` test. Re-baseline if LTHASH_LANES or the expansion
    // construction changes.
    37, 11, 157, 25, 120, 63, 36, 205, 245, 74, 59, 199, 171, 47, 170, 82, 95, 235, 9, 13, 228, 16, 125, 187, 160, 171, 100, 181, 216,
    119, 224, 234,
]);

/// Post-quantum UTXO-set commitment (LtHash16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MuHash {
    lanes: [u16; LTHASH_LANES],
}

impl MuHash {
    #[inline]
    pub fn new() -> Self {
        Self { lanes: [0u16; LTHASH_LANES] }
    }

    #[inline]
    pub fn add_element(&mut self, data: &[u8]) {
        accumulate(data, true, &mut self.lanes);
    }

    #[inline]
    pub fn remove_element(&mut self, data: &[u8]) {
        accumulate(data, false, &mut self.lanes);
    }

    #[inline]
    pub fn add_element_builder(&mut self) -> MuHashElementBuilder<'_> {
        MuHashElementBuilder::new(&mut self.lanes, true)
    }

    #[inline]
    pub fn remove_element_builder(&mut self) -> MuHashElementBuilder<'_> {
        MuHashElementBuilder::new(&mut self.lanes, false)
    }

    /// Combine two multisets (set union) — component-wise lane addition.
    #[inline]
    pub fn combine(&mut self, other: &Self) {
        for (a, b) in self.lanes.iter_mut().zip(other.lanes.iter()) {
            *a = a.wrapping_add(*b);
        }
    }

    /// The 32-byte commitment for the header: `MuHashFinalizeHash(state)`.
    ///
    /// Takes `&self` — calling `finalize` does not mutate the accumulator.
    /// After finalization the accumulator should not be used further.
    #[inline]
    pub fn finalize(&self) -> Hash {
        let mut h = MuHashFinalizeHash::new();
        h.write(self.to_bytes());
        h.finalize()
    }

    /// Serialize the full LtHash **state** (little-endian lanes).
    #[inline]
    pub fn to_bytes(&self) -> [u8; SERIALIZED_MUHASH_SIZE] {
        let mut out = [0u8; SERIALIZED_MUHASH_SIZE];
        for (i, lane) in self.lanes.iter().enumerate() {
            out[2 * i..2 * i + 2].copy_from_slice(&lane.to_le_bytes());
        }
        out
    }

    /// Reconstruct from the serialized state form.
    #[inline]
    pub fn from_bytes(data: [u8; SERIALIZED_MUHASH_SIZE]) -> Self {
        let mut lanes = [0u16; LTHASH_LANES];
        for (i, lane) in lanes.iter_mut().enumerate() {
            *lane = u16::from_le_bytes([data[2 * i], data[2 * i + 1]]);
        }
        Self { lanes }
    }
}

/// Expand `data` into the lane-vector and add (or subtract) it into `lanes`.
///
/// Counter-mode keyed blake2b: lane block `i = MuHashElementHash(i_le ‖ data)`.
/// The counter is hashed FIRST so a variable-length `data` cannot be confused
/// with a different `(data, block)` pairing (no length-extension ambiguity);
/// `MuHashElementHash`'s blake2b key provides domain separation.
#[inline]
fn accumulate(data: &[u8], adding: bool, lanes: &mut [u16; LTHASH_LANES]) {
    for blk in 0..EXPANSION_BLOCKS {
        let mut h = MuHashElementHash::new();
        h.write((blk as u32).to_le_bytes());
        h.write(data);
        let block = h.finalize();
        let bytes = block.as_bytes();
        for j in 0..16 {
            let idx = blk * 16 + j;
            let v = u16::from_le_bytes([bytes[2 * j], bytes[2 * j + 1]]);
            lanes[idx] = if adding { lanes[idx].wrapping_add(v) } else { lanes[idx].wrapping_sub(v) };
        }
    }
}

/// Streaming element builder — buffers the streamed element bytes, then
/// adds/subtracts the expanded lane-vector on `finalize`. Elements are small
/// (a serialized UTXO), so buffering is cheap and keeps the counter-mode
/// expansion identical to the one-shot `add_element` path.
///
/// **Must call `finalize()`** — dropping without it is a silent no-op that
/// loses the element, which is a consensus bug (double-spend vector).
/// `#[must_use]` catches unused temporaries at compile time; the `Drop`
/// guard catches the remaining cases at runtime.
#[must_use = "MuHashElementBuilder has no effect unless finalize() is called"]
pub struct MuHashElementBuilder<'a> {
    lanes: &'a mut [u16; LTHASH_LANES],
    buf: Vec<u8>,
    adding: bool,
    /// Set to `true` by `finalize()` so the `Drop` guard can distinguish a
    /// clean teardown from a forgotten call.
    finalized: bool,
}

impl HasherBase for MuHashElementBuilder<'_> {
    fn update<A: AsRef<[u8]>>(&mut self, data: A) -> &mut Self {
        self.buf.extend_from_slice(data.as_ref());
        self
    }
}

impl<'a> MuHashElementBuilder<'a> {
    fn new(lanes: &'a mut [u16; LTHASH_LANES], adding: bool) -> Self {
        Self { lanes, buf: Vec::new(), adding, finalized: false }
    }

    pub fn finalize(mut self) {
        self.finalized = true;
        accumulate(&self.buf, self.adding, self.lanes);
    }
}

impl Drop for MuHashElementBuilder<'_> {
    fn drop(&mut self) {
        // LTHASH-13: dropping without finalize() silently discards the element.
        // In production this is a consensus bug (the UTXO multiset diverges from
        // the committed state, enabling double-spend). Panic loudly instead.
        if !self.finalized {
            panic!("MuHashElementBuilder dropped without calling finalize() — element lost");
        }
    }
}

impl Default for MuHash {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// LtHash state is a fixed-size inline array — no heap. The cache for
// utxo_multisets uses CachePolicy::Count (untracked), so estimate_size is
// never called.
impl MemSizeEstimator for MuHash {}

// ---------------------------------------------------------------------------
// serde — the state is a `[u16; LTHASH_LANES]`, larger than serde's derived
// array support, so serialize it as the little-endian byte form.
// ---------------------------------------------------------------------------

impl Serialize for MuHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

struct MuHashVisitor;

impl<'de> Visitor<'de> for MuHashVisitor {
    type Value = MuHash;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a {SERIALIZED_MUHASH_SIZE}-byte LtHash state")
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<MuHash, E> {
        if v.len() != SERIALIZED_MUHASH_SIZE {
            return Err(E::invalid_length(v.len(), &self));
        }
        let mut arr = [0u8; SERIALIZED_MUHASH_SIZE];
        arr.copy_from_slice(v);
        Ok(MuHash::from_bytes(arr))
    }

    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<MuHash, E> {
        self.visit_bytes(&v)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<MuHash, A::Error> {
        let mut arr = [0u8; SERIALIZED_MUHASH_SIZE];
        for (i, b) in arr.iter_mut().enumerate() {
            *b = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(i, &self))?;
        }
        Ok(MuHash::from_bytes(arr))
    }
}

impl<'de> Deserialize<'de> for MuHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(MuHashVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::{EMPTY_MUHASH, MuHash, SERIALIZED_MUHASH_SIZE};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn element_from_byte(b: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = b;
        out
    }

    /// Prints the canonical empty commitment so `EMPTY_MUHASH` can be pinned.
    /// Run with `--nocapture` to read the value when re-baselining parameters.
    #[test]
    fn bootstrap_empty() {
        let bytes = MuHash::new().finalize();
        println!("EMPTY_MUHASH = {:?}", bytes.as_bytes());
    }

    #[test]
    fn test_empty_hash() {
        let empty = MuHash::new();
        assert_eq!(empty.finalize(), EMPTY_MUHASH);
    }

    #[test]
    fn test_order_independence() {
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..10 {
            let mut res = None;
            let mut table = [0u8; 4];
            rng.fill(&mut table[..]);

            for order in 0..4 {
                let mut acc = MuHash::new();
                for i in 0..4 {
                    let t = table[i ^ order];
                    if (t & 4) != 0 {
                        acc.remove_element(&element_from_byte(t & 3));
                    } else {
                        acc.add_element(&element_from_byte(t & 3));
                    }
                }
                let out = acc.finalize();
                match res {
                    None => res = Some(out),
                    Some(expected) => assert_eq!(expected, out),
                }
            }
        }
    }

    #[test]
    fn test_add_remove_inverse() {
        let x = element_from_byte(1);
        let y = element_from_byte(2);
        let mut acc = MuHash::new();
        acc.add_element(&x);
        acc.add_element(&y);
        acc.remove_element(&x);
        acc.remove_element(&y);
        assert_eq!(acc.finalize(), EMPTY_MUHASH);
    }

    /// The streaming builder path (used by consensus via `write_utxo`) must
    /// produce the exact same result as the one-shot `add_element`, regardless
    /// of how the bytes are chunked across `update` calls. This is the path the
    /// node actually exercises, so lock it.
    #[test]
    fn test_builder_matches_one_shot() {
        use sophis_hashes::HasherBase;
        let data: Vec<u8> = (0u8..137).collect();

        let mut one_shot = MuHash::new();
        one_shot.add_element(&data);

        let mut streamed = MuHash::new();
        {
            let mut b = streamed.add_element_builder();
            b.update(&data[..10]);
            b.update(&data[10..50]);
            b.update(&data[50..]);
            b.finalize();
        }
        assert_eq!(one_shot.finalize(), streamed.finalize());

        // And the remove builder must invert the add builder.
        {
            let mut b = streamed.remove_element_builder();
            b.update(&data);
            b.finalize();
        }
        assert_eq!(streamed.finalize(), EMPTY_MUHASH);
    }

    #[test]
    fn test_combine() {
        let x = element_from_byte(1);
        let y = element_from_byte(2);
        let mut a = MuHash::new();
        a.add_element(&x);
        let mut b = MuHash::new();
        b.add_element(&y);
        a.combine(&b);

        let mut expected = MuHash::new();
        expected.add_element(&x);
        expected.add_element(&y);
        assert_eq!(a.finalize(), expected.finalize());
    }

    #[test]
    fn test_combine_cancel() {
        let x = element_from_byte(1);
        let mut add = MuHash::new();
        add.add_element(&x);
        let mut remove = MuHash::new();
        remove.remove_element(&x);
        add.combine(&remove);
        assert_eq!(add.finalize(), EMPTY_MUHASH);
    }

    #[test]
    fn test_serialize_roundtrip() {
        let mut mh = MuHash::new();
        mh.add_element(&element_from_byte(1));
        mh.add_element(&element_from_byte(2));
        let ser = mh.to_bytes();
        assert_eq!(ser.len(), SERIALIZED_MUHASH_SIZE);
        let deserialized = MuHash::from_bytes(ser);
        assert_eq!(mh.finalize(), deserialized.finalize());
    }

    #[test]
    fn test_serde_bincode_roundtrip() {
        let mut mh = MuHash::new();
        mh.add_element(&element_from_byte(7));
        let bytes = bincode::serialize(&mh).unwrap();
        let back: MuHash = bincode::deserialize(&bytes).unwrap();
        let mh2 = mh.clone();
        assert_eq!(mh2.finalize(), back.finalize());
    }

    #[test]
    fn test_nonempty_not_equal_empty() {
        let mut mh = MuHash::new();
        mh.add_element(&element_from_byte(1));
        assert_ne!(mh.finalize(), EMPTY_MUHASH);
    }

    #[test]
    fn test_muhash_add_remove() {
        const LOOPS: usize = 1024;
        let mut rng = StdRng::seed_from_u64(42);
        let mut set = MuHash::new();
        let list: Vec<_> = (0..LOOPS)
            .map(|_| {
                let mut data = [0u8; 100];
                rng.fill(&mut data[..]);
                set.add_element(&data);
                data
            })
            .collect();

        assert_ne!(set.finalize(), EMPTY_MUHASH);

        for elem in list.iter() {
            set.remove_element(elem);
        }

        assert_eq!(set.finalize(), EMPTY_MUHASH);
    }

    #[test]
    fn test_commutativity() {
        let data = [element_from_byte(1), element_from_byte(2), element_from_byte(3)];
        for remove_index in 0..data.len() {
            let mut m1 = MuHash::new();
            let mut m2 = MuHash::new();
            m1.remove_element(&data[remove_index]);
            for (i, d) in data.iter().enumerate() {
                if i != remove_index {
                    m1.add_element(d);
                    m2.add_element(d);
                }
            }
            m2.remove_element(&data[remove_index]);
            assert_eq!(m1.finalize(), m2.finalize());
        }
    }
}
