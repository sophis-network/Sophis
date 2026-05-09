//! PSBS cryptographic primitives — Dilithium ML-DSA-44 (FIPS 204) types.
//!
//! See `wallet/pskt/DESIGN.md` for the canonical specification of the wire
//! format and decisions D1–D5. The types in this module are the source of
//! truth for what is serialized inside a PSBS container.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;

/// ML-DSA-44 verification key size (bytes), per FIPS 204.
pub const DILITHIUM44_VK_SIZE: usize = 1312;

/// ML-DSA-44 signature size (bytes), per FIPS 204.
pub const DILITHIUM44_SIG_SIZE: usize = 2420;

/// Discriminant byte for the `DilithiumML44` `Signature` variant.
pub const SIGNATURE_VARIANT_DILITHIUM_ML44: u8 = 0x01;

// ---------------------------------------------------------------------------
// Internal helpers — manual serde for fixed arrays larger than serde's
// auto-derived limit (32). Human-readable serializers (JSON) emit hex;
// non-human-readable (borsh/bincode) emit raw bytes.
// ---------------------------------------------------------------------------

fn serialize_fixed_bytes<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        serializer.serialize_str(&hex::encode(bytes))
    } else {
        serializer.serialize_bytes(bytes)
    }
}

fn deserialize_fixed_bytes<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    if deserializer.is_human_readable() {
        let s = String::deserialize(deserializer)?;
        let v = hex::decode(&s).map_err(D::Error::custom)?;
        v.try_into().map_err(|v: Vec<u8>| D::Error::custom(format!("expected {N} bytes, got {}", v.len())))
    } else {
        let v = <Vec<u8>>::deserialize(deserializer)?;
        v.try_into().map_err(|v: Vec<u8>| D::Error::custom(format!("expected {N} bytes, got {}", v.len())))
    }
}

// ---------------------------------------------------------------------------
// DilithiumPubKey
// ---------------------------------------------------------------------------

/// Newtype wrapper around an ML-DSA-44 verification key.
///
/// Fixed 1312 bytes, stored inline. `BTreeMap` nodes already heap-allocate
/// keys; the inline cost only matters in rare value-move scenarios.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DilithiumPubKey(pub [u8; DILITHIUM44_VK_SIZE]);

impl DilithiumPubKey {
    /// Construct from raw bytes. Caller is responsible for validity.
    pub fn from_bytes(bytes: [u8; DILITHIUM44_VK_SIZE]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying byte slice.
    pub fn as_bytes(&self) -> &[u8; DILITHIUM44_VK_SIZE] {
        &self.0
    }
}

impl std::fmt::Debug for DilithiumPubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = hex::encode(&self.0[..8]);
        write!(f, "DilithiumPubKey({prefix}…)")
    }
}

impl std::fmt::Display for DilithiumPubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = hex::encode(&self.0[..8]);
        write!(f, "DilithiumPubKey({prefix}…)")
    }
}

impl PartialOrd for DilithiumPubKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DilithiumPubKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl Serialize for DilithiumPubKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_fixed_bytes(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for DilithiumPubKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_fixed_bytes::<D, DILITHIUM44_VK_SIZE>(deserializer).map(Self)
    }
}

// ---------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------

/// Versioned signature container.
///
/// A discriminator byte allows future Dilithium parameter sets (ML-DSA-65 / -87)
/// or other PQC schemes to be added via SIP without breaking the PSBS wire format.
///
/// **v1 producers MUST emit only `DilithiumML44`.** v1 verifiers MUST reject
/// `Future` variants until a SIP authorizes a specific value.
/// Boxed to avoid `large_enum_variant` (2420-byte inline payload would dwarf
/// the small `Future` variant by 100×). Heap allocation per signature is
/// acceptable: signatures are constructed at signing time, not on hot loops.
#[derive(Clone, PartialEq, Eq)]
pub enum Signature {
    /// CRYSTALS-Dilithium ML-DSA-44 (FIPS 204). Fixed 2420-byte signature.
    DilithiumML44(Box<[u8; DILITHIUM44_SIG_SIZE]>),

    /// Reserved for future variants. Variant byte is the discriminator;
    /// payload is variant-defined. v1 MUST reject when encountered.
    Future { variant: u8, payload: Vec<u8> },
}

impl Signature {
    /// Construct from a raw 2420-byte ML-DSA-44 signature.
    pub fn dilithium_ml44_from_bytes(bytes: [u8; DILITHIUM44_SIG_SIZE]) -> Self {
        Self::DilithiumML44(Box::new(bytes))
    }

    /// Borrow the signature bytes if this is a `DilithiumML44` variant.
    /// Returns `None` for `Future` variants (v1 callers should reject those upstream).
    pub fn as_dilithium_ml44(&self) -> Option<&[u8; DILITHIUM44_SIG_SIZE]> {
        match self {
            Self::DilithiumML44(b) => Some(b.as_ref()),
            Self::Future { .. } => None,
        }
    }

    /// Borrow the raw signature bytes (length depends on variant).
    pub fn raw_bytes(&self) -> &[u8] {
        match self {
            Self::DilithiumML44(b) => b.as_slice(),
            Self::Future { payload, .. } => payload.as_slice(),
        }
    }

    /// The discriminator byte that identifies this variant on the wire.
    pub fn variant(&self) -> u8 {
        match self {
            Self::DilithiumML44(_) => SIGNATURE_VARIANT_DILITHIUM_ML44,
            Self::Future { variant, .. } => *variant,
        }
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DilithiumML44(bytes) => {
                let prefix = hex::encode(&bytes[..8]);
                write!(f, "Signature::DilithiumML44({prefix}…)")
            }
            Self::Future { variant, payload } => {
                write!(f, "Signature::Future {{ variant: 0x{variant:02x}, payload_len: {} }}", payload.len())
            }
        }
    }
}

// Manual Serialize/Deserialize over a surrogate enum mirroring the public
// `Signature` shape. We dereference the box at the (de)serialization
// boundary so the wire format is identical to a non-boxed variant — boxing
// is purely an in-memory representation choice (avoids `large_enum_variant`).
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::large_enum_variant)] // wire-only intermediate; never stored long-lived
enum SignatureRepr {
    DilithiumML44 {
        #[serde(serialize_with = "serialize_dilithium_sig", deserialize_with = "deserialize_dilithium_sig")]
        bytes: [u8; DILITHIUM44_SIG_SIZE],
    },
    Future {
        variant: u8,
        payload: Vec<u8>,
    },
}

fn serialize_dilithium_sig<S: Serializer>(bytes: &[u8; DILITHIUM44_SIG_SIZE], s: S) -> Result<S::Ok, S::Error> {
    serialize_fixed_bytes(bytes, s)
}

fn deserialize_dilithium_sig<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; DILITHIUM44_SIG_SIZE], D::Error> {
    deserialize_fixed_bytes::<D, DILITHIUM44_SIG_SIZE>(d)
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::DilithiumML44(b) => SignatureRepr::DilithiumML44 { bytes: **b }.serialize(serializer),
            Self::Future { variant, payload } => {
                SignatureRepr::Future { variant: *variant, payload: payload.clone() }.serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match SignatureRepr::deserialize(deserializer)? {
            SignatureRepr::DilithiumML44 { bytes } => Ok(Signature::DilithiumML44(Box::new(bytes))),
            SignatureRepr::Future { variant, payload } => Ok(Signature::Future { variant, payload }),
        }
    }
}

// ---------------------------------------------------------------------------
// Aliases
// ---------------------------------------------------------------------------

/// A `(pubkey, signature)` pair as accumulated in `Input.partial_sigs`.
pub type PartialSig = (DilithiumPubKey, Signature);

/// Vector of partial signatures collected so far on an Input.
///
/// Per design D3, this is a `Vec` rather than a `BTreeMap` — at PSBS scale
/// (multisig N-of-M typically ≤ 7), linear lookup is trivial and the 1.3 KB
/// pubkey makes a map key wasteful.
///
/// Combiners deduplicate by pubkey when merging two PSBS instances.
pub type PartialSigs = Vec<PartialSig>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_roundtrip_serde_json() {
        let bytes = [42u8; DILITHIUM44_VK_SIZE];
        let pk = DilithiumPubKey::from_bytes(bytes);
        let json = serde_json::to_string(&pk).expect("serialize pubkey");
        let de: DilithiumPubKey = serde_json::from_str(&json).expect("deserialize pubkey");
        assert_eq!(pk, de);
    }

    #[test]
    fn signature_dilithium_roundtrip_serde_json() {
        let bytes = [7u8; DILITHIUM44_SIG_SIZE];
        let sig = Signature::dilithium_ml44_from_bytes(bytes);
        let json = serde_json::to_string(&sig).expect("serialize sig");
        let de: Signature = serde_json::from_str(&json).expect("deserialize sig");
        assert_eq!(sig, de);
        assert_eq!(de.variant(), SIGNATURE_VARIANT_DILITHIUM_ML44);
    }

    #[test]
    fn signature_future_roundtrip_serde_json() {
        let sig = Signature::Future { variant: 0xfe, payload: vec![1, 2, 3] };
        let json = serde_json::to_string(&sig).expect("serialize future sig");
        let de: Signature = serde_json::from_str(&json).expect("deserialize future sig");
        assert_eq!(sig, de);
        assert_eq!(de.variant(), 0xfe);
    }

    #[test]
    fn pubkey_ord_is_lexicographic() {
        let a = DilithiumPubKey::from_bytes([0u8; DILITHIUM44_VK_SIZE]);
        let mut b_bytes = [0u8; DILITHIUM44_VK_SIZE];
        b_bytes[0] = 1;
        let b = DilithiumPubKey::from_bytes(b_bytes);
        assert!(a < b);
    }

    #[test]
    fn pubkey_debug_truncates() {
        let pk = DilithiumPubKey::from_bytes([0xab; DILITHIUM44_VK_SIZE]);
        let s = format!("{pk:?}");
        assert!(s.contains("ababab"));
        assert!(s.len() < 100);
    }
}
