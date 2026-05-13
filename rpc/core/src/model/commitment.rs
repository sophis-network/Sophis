//! L3 — Block commitment level RPC types.
//!
//! See `docs/L3_COMMITMENT_DESIGN.md` for the canonical specification.
//! Frozen ABI per design §7 — any change requires a hard fork.

use crate::RpcHash;
use serde::{Deserialize, Serialize};
use workflow_serializer::prelude::*;

/// Commitment level a block is at relative to the GHOSTDAG selected
/// chain and the current sink. Wire-encoded as a single `u8` per design
/// §3.3 + §7.
///
/// | Variant | u8 | Meaning |
/// |---------|----|---------|
/// | `Pending`  | 0 | Block exists but is OFF the selected chain. |
/// | `Accepted` | 1 | On chain, `confirmations < CONFIRMED_DEPTH_BLOCKS`. |
/// | `Confirmed`| 2 | On chain, `confirmations ≥ 100`. |
/// | `Finalized`| 3 | On chain, `confirmations ≥ finality_depth`. |
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[repr(u8)]
pub enum RpcCommitmentLevel {
    Pending = 0,
    Accepted = 1,
    Confirmed = 2,
    Finalized = 3,
}

impl RpcCommitmentLevel {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Pending),
            1 => Some(Self::Accepted),
            2 => Some(Self::Confirmed),
            3 => Some(Self::Finalized),
            _ => None,
        }
    }
}

/// Per-block commitment status. Mirrors the consensus-side
/// `BlockCommitment` type but uses RPC-friendly `RpcHash` instead of
/// `sophis_hashes::Hash`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockCommitment {
    pub block_hash: RpcHash,
    pub block_blue_score: u64,
    pub current_blue_score: u64,
    pub confirmations: u64,
    pub is_chain_block: bool,
    pub commitment: RpcCommitmentLevel,
}

impl Serializer for RpcBlockCommitment {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?;
        store!(RpcHash, &self.block_hash, writer)?;
        store!(u64, &self.block_blue_score, writer)?;
        store!(u64, &self.current_blue_score, writer)?;
        store!(u64, &self.confirmations, writer)?;
        store!(bool, &self.is_chain_block, writer)?;
        store!(u8, &self.commitment.as_u8(), writer)
    }
}

impl Deserializer for RpcBlockCommitment {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version: u8 = load!(u8, reader)?;
        let block_hash = load!(RpcHash, reader)?;
        let block_blue_score = load!(u64, reader)?;
        let current_blue_score = load!(u64, reader)?;
        let confirmations = load!(u64, reader)?;
        let is_chain_block = load!(bool, reader)?;
        let commitment_byte: u8 = load!(u8, reader)?;
        let commitment = RpcCommitmentLevel::from_u8(commitment_byte).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("invalid commitment level byte {commitment_byte}"))
        })?;
        Ok(Self { block_hash, block_blue_score, current_blue_score, confirmations, is_chain_block, commitment })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockCommitmentRequest {
    pub block_hash: RpcHash,
}

impl GetBlockCommitmentRequest {
    pub fn new(block_hash: RpcHash) -> Self {
        Self { block_hash }
    }
}

impl Serializer for GetBlockCommitmentRequest {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;
        store!(RpcHash, &self.block_hash, writer)
    }
}

impl Deserializer for GetBlockCommitmentRequest {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        let block_hash = load!(RpcHash, reader)?;
        Ok(Self { block_hash })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockCommitmentResponse {
    pub commitment: Option<RpcBlockCommitment>,
}

impl GetBlockCommitmentResponse {
    pub fn new(commitment: Option<RpcBlockCommitment>) -> Self {
        Self { commitment }
    }
}

impl Serializer for GetBlockCommitmentResponse {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;
        match &self.commitment {
            Some(c) => {
                store!(u8, &1, writer)?;
                serialize!(RpcBlockCommitment, c, writer)
            }
            None => store!(u8, &0, writer),
        }
    }
}

impl Deserializer for GetBlockCommitmentResponse {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        let tag: u8 = load!(u8, reader)?;
        let commitment = if tag == 1 { Some(deserialize!(RpcBlockCommitment, reader)?) } else { None };
        Ok(Self { commitment })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt<T>(value: &T) -> T
    where
        T: Serializer + Deserializer,
    {
        let mut buf: Vec<u8> = Vec::new();
        value.serialize(&mut buf).unwrap();
        T::deserialize(&mut buf.as_slice()).unwrap()
    }

    #[test]
    fn level_byte_roundtrip_all_variants() {
        for v in
            [RpcCommitmentLevel::Pending, RpcCommitmentLevel::Accepted, RpcCommitmentLevel::Confirmed, RpcCommitmentLevel::Finalized]
        {
            assert_eq!(RpcCommitmentLevel::from_u8(v.as_u8()), Some(v));
        }
    }

    #[test]
    fn level_byte_invalid_returns_none() {
        for invalid in [4u8, 5, 99, 255] {
            assert!(RpcCommitmentLevel::from_u8(invalid).is_none());
        }
    }

    #[test]
    fn level_byte_assignment_is_frozen() {
        // Pin the byte values per design §7. Changing these requires a
        // hard fork because old clients would mis-decode.
        assert_eq!(RpcCommitmentLevel::Pending.as_u8(), 0);
        assert_eq!(RpcCommitmentLevel::Accepted.as_u8(), 1);
        assert_eq!(RpcCommitmentLevel::Confirmed.as_u8(), 2);
        assert_eq!(RpcCommitmentLevel::Finalized.as_u8(), 3);
    }

    #[test]
    fn rt_request_round_trips() {
        let r = GetBlockCommitmentRequest::new(RpcHash::from_slice(&[0xAA; 32]));
        let d = rt(&r);
        assert_eq!(d.block_hash, r.block_hash);
    }

    #[test]
    fn rt_response_some_round_trips() {
        let c = RpcBlockCommitment {
            block_hash: RpcHash::from_slice(&[0x10; 32]),
            block_blue_score: 1000,
            current_blue_score: 1500,
            confirmations: 500,
            is_chain_block: true,
            commitment: RpcCommitmentLevel::Confirmed,
        };
        let r = GetBlockCommitmentResponse::new(Some(c));
        let d = rt(&r);
        let back = d.commitment.unwrap();
        assert_eq!(back.block_blue_score, 1000);
        assert_eq!(back.current_blue_score, 1500);
        assert_eq!(back.confirmations, 500);
        assert!(back.is_chain_block);
        assert_eq!(back.commitment, RpcCommitmentLevel::Confirmed);
    }

    #[test]
    fn rt_response_none_round_trips() {
        let r = GetBlockCommitmentResponse::new(None);
        let d = rt(&r);
        assert!(d.commitment.is_none());
    }

    #[test]
    fn rt_pending_level_round_trips() {
        let c = RpcBlockCommitment {
            block_hash: RpcHash::from_slice(&[0x20; 32]),
            block_blue_score: 100,
            current_blue_score: 200,
            confirmations: 100,
            is_chain_block: false,
            commitment: RpcCommitmentLevel::Pending,
        };
        let r = GetBlockCommitmentResponse::new(Some(c));
        let d = rt(&r);
        let back = d.commitment.unwrap();
        assert!(!back.is_chain_block);
        assert_eq!(back.commitment, RpcCommitmentLevel::Pending);
    }
}
