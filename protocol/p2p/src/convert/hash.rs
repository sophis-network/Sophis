use super::error::ConversionError;
use crate::pb as protowire;
use sophis_hashes::{Hash, MerkleHash};

// ----------------------------------------------------------------------------
// consensus_core to protowire
// ----------------------------------------------------------------------------

impl From<Hash> for protowire::Hash {
    fn from(hash: Hash) -> Self {
        Self { bytes: Vec::from(hash.as_bytes()) }
    }
}

impl From<&Hash> for protowire::Hash {
    fn from(hash: &Hash) -> Self {
        Self { bytes: Vec::from(hash.as_bytes()) }
    }
}

// ----------------------------------------------------------------------------
// protowire to consensus_core
// ----------------------------------------------------------------------------

impl TryFrom<protowire::Hash> for Hash {
    type Error = ConversionError;

    fn try_from(hash: protowire::Hash) -> Result<Self, Self::Error> {
        Ok(Self::from_bytes(hash.bytes.as_slice().try_into()?))
    }
}

// MerkleHash ↔ protowire::Hash (48-byte payload)

impl From<MerkleHash> for protowire::Hash {
    fn from(hash: MerkleHash) -> Self {
        Self { bytes: hash.as_bytes().to_vec() }
    }
}

impl From<&MerkleHash> for protowire::Hash {
    fn from(hash: &MerkleHash) -> Self {
        Self { bytes: hash.as_bytes().to_vec() }
    }
}

impl TryFrom<protowire::Hash> for MerkleHash {
    type Error = ConversionError;

    fn try_from(hash: protowire::Hash) -> Result<Self, Self::Error> {
        Self::try_from_slice(hash.bytes.as_slice()).map_err(|_| ConversionError::General)
    }
}
