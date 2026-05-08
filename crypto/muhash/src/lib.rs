use serde::{Deserialize, Serialize};
use sophis_hashes::{Hash, Hasher, HasherBase, MuHashElementHash};
use sophis_utils::mem_size::MemSizeEstimator;

pub const HASH_SIZE: usize = 32;
pub const SERIALIZED_MUHASH_SIZE: usize = 32;
// Post-quantum UTXO commitment — accumulator of element hashes mod 2^256.
// Empty set: all-zero accumulator returned directly as the commitment hash.
pub const EMPTY_MUHASH: Hash = Hash::from_bytes([0u8; 32]);

/// Post-quantum UTXO set commitment.
///
/// Replaces multiplicative MuHash (Z_p*, quantum-vulnerable via Shor) with a
/// hash-and-sum accumulator: commitment = Σ blake2b("MuHashElement", utxo_i) mod 2^256.
///
/// Properties preserved from the original design:
/// - O(1) add/remove
/// - Order-independent (commutative, associative)
/// - O(1) combine (set union)
///
/// Security: preimage resistance of blake2b gives ~128-bit post-quantum security (Grover).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MuHash {
    accumulator: [u8; 32],
}

impl MuHash {
    #[inline]
    pub fn new() -> Self {
        Self { accumulator: [0u8; 32] }
    }

    #[inline]
    pub fn add_element(&mut self, data: &[u8]) {
        let h = MuHashElementHash::hash(data);
        wrapping_add_u256(&mut self.accumulator, &h.as_bytes());
    }

    #[inline]
    pub fn remove_element(&mut self, data: &[u8]) {
        let h = MuHashElementHash::hash(data);
        wrapping_sub_u256(&mut self.accumulator, &h.as_bytes());
    }

    #[inline]
    pub fn add_element_builder(&mut self) -> MuHashElementBuilder<'_> {
        MuHashElementBuilder::new(&mut self.accumulator, true)
    }

    #[inline]
    pub fn remove_element_builder(&mut self) -> MuHashElementBuilder<'_> {
        MuHashElementBuilder::new(&mut self.accumulator, false)
    }

    #[inline]
    pub fn combine(&mut self, other: &Self) {
        wrapping_add_u256(&mut self.accumulator, &other.accumulator);
    }

    #[inline]
    pub fn finalize(&mut self) -> Hash {
        Hash::from_bytes(self.accumulator)
    }

    #[inline]
    pub fn serialize(&mut self) -> [u8; SERIALIZED_MUHASH_SIZE] {
        self.accumulator
    }

    #[inline]
    pub fn deserialize(data: [u8; SERIALIZED_MUHASH_SIZE]) -> Self {
        Self { accumulator: data }
    }
}

pub struct MuHashElementBuilder<'a> {
    accumulator: &'a mut [u8; 32],
    hasher: MuHashElementHash,
    adding: bool,
}

impl HasherBase for MuHashElementBuilder<'_> {
    fn update<A: AsRef<[u8]>>(&mut self, data: A) -> &mut Self {
        self.hasher.write(data);
        self
    }
}

impl<'a> MuHashElementBuilder<'a> {
    fn new(accumulator: &'a mut [u8; 32], adding: bool) -> Self {
        Self { accumulator, hasher: MuHashElementHash::new(), adding }
    }

    pub fn finalize(self) {
        let hash = self.hasher.finalize();
        if self.adding {
            wrapping_add_u256(self.accumulator, &hash.as_bytes());
        } else {
            wrapping_sub_u256(self.accumulator, &hash.as_bytes());
        }
    }
}

// Little-endian wrapping addition mod 2^256
fn wrapping_add_u256(acc: &mut [u8; 32], rhs: &[u8]) {
    let mut carry = 0u16;
    for (a, b) in acc.iter_mut().zip(rhs.iter()) {
        let sum = *a as u16 + *b as u16 + carry;
        *a = sum as u8;
        carry = sum >> 8;
    }
}

// Little-endian wrapping subtraction mod 2^256
fn wrapping_sub_u256(acc: &mut [u8; 32], rhs: &[u8]) {
    let mut borrow = 0u16;
    for (a, b) in acc.iter_mut().zip(rhs.iter()) {
        let diff = (*a as u16) + 256 - (*b as u16) - borrow;
        *a = diff as u8;
        borrow = 1 - (diff >> 8);
    }
}

impl Default for MuHash {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// MuHash is a fixed-size 32-byte struct with no heap allocations.
// The cache for utxo_multisets uses CachePolicy::Count (untracked), so estimate_size is never called.
impl MemSizeEstimator for MuHash {}

#[cfg(test)]
mod tests {
    use super::{EMPTY_MUHASH, MuHash};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn element_from_byte(b: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = b;
        out
    }

    #[test]
    fn test_empty_hash() {
        let mut empty = MuHash::new();
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
        let ser = mh.serialize();
        assert_eq!(ser.len(), 32);
        let mut deserialized = MuHash::deserialize(ser);
        assert_eq!(mh.finalize(), deserialized.finalize());
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
