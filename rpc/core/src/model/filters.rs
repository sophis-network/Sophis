//! K2 — Compact Block Filter RPC types.
//!
//! Wire models for the two `getBlockFilter*` RPC methods. Mirrors the
//! `BlockFilter` and `BlockFilterHeader` types from
//! `consensus/src/model/stores/block_filters.rs` but uses RPC-friendly
//! `Vec<u8>` for the 32-byte hashes (workflow-serializer compatible).
//!
//! See `docs/K2_COMPACT_FILTERS_DESIGN.md` for the canonical
//! specification.

use crate::RpcHash;
use serde::{Deserialize, Serialize};
use workflow_serializer::prelude::*;

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/// Compact filter as exposed via RPC. The 32-byte `filter_hash` is
/// `SHA3-384(filter_bytes)[..32]`; consumers verifying against the
/// header chain MAY recompute it themselves to skip trusting the RPC.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockFilter {
    pub block_hash: RpcHash,
    pub filter_bytes: Vec<u8>,
    pub filter_hash: Vec<u8>, // always 32 bytes
}

impl Serializer for RpcBlockFilter {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?; // version
        store!(RpcHash, &self.block_hash, writer)?;
        store!(Vec<u8>, &self.filter_bytes, writer)?;
        store!(Vec<u8>, &self.filter_hash, writer)
    }
}

impl Deserializer for RpcBlockFilter {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version: u8 = load!(u8, reader)?;
        let block_hash = load!(RpcHash, reader)?;
        let filter_bytes = load!(Vec<u8>, reader)?;
        let filter_hash = load!(Vec<u8>, reader)?;
        Ok(Self { block_hash, filter_bytes, filter_hash })
    }
}

/// Per-block filter header chain entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockFilterHeader {
    pub block_hash: RpcHash,
    pub prev_header: Vec<u8>,    // 32 bytes
    pub filter_hash: Vec<u8>,    // 32 bytes
    pub filter_header: Vec<u8>,  // 32 bytes
}

impl Serializer for RpcBlockFilterHeader {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?;
        store!(RpcHash, &self.block_hash, writer)?;
        store!(Vec<u8>, &self.prev_header, writer)?;
        store!(Vec<u8>, &self.filter_hash, writer)?;
        store!(Vec<u8>, &self.filter_header, writer)
    }
}

impl Deserializer for RpcBlockFilterHeader {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version: u8 = load!(u8, reader)?;
        let block_hash = load!(RpcHash, reader)?;
        let prev_header = load!(Vec<u8>, reader)?;
        let filter_hash = load!(Vec<u8>, reader)?;
        let filter_header = load!(Vec<u8>, reader)?;
        Ok(Self { block_hash, prev_header, filter_hash, filter_header })
    }
}

// ---------------------------------------------------------------------------
// 1. GetBlockFilter
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockFilterRequest {
    pub block_hash: RpcHash,
}

impl GetBlockFilterRequest {
    pub fn new(block_hash: RpcHash) -> Self {
        Self { block_hash }
    }
}

impl Serializer for GetBlockFilterRequest {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;
        store!(RpcHash, &self.block_hash, writer)
    }
}

impl Deserializer for GetBlockFilterRequest {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        let block_hash = load!(RpcHash, reader)?;
        Ok(Self { block_hash })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockFilterResponse {
    pub filter: Option<RpcBlockFilter>,
}

impl GetBlockFilterResponse {
    pub fn new(filter: Option<RpcBlockFilter>) -> Self {
        Self { filter }
    }
}

impl Serializer for GetBlockFilterResponse {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;
        match &self.filter {
            Some(f) => {
                store!(u8, &1, writer)?;
                serialize!(RpcBlockFilter, f, writer)
            }
            None => store!(u8, &0, writer),
        }
    }
}

impl Deserializer for GetBlockFilterResponse {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        let tag: u8 = load!(u8, reader)?;
        let filter = if tag == 1 { Some(deserialize!(RpcBlockFilter, reader)?) } else { None };
        Ok(Self { filter })
    }
}

// ---------------------------------------------------------------------------
// 2. GetBlockFilterHeader
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockFilterHeaderRequest {
    pub block_hash: RpcHash,
}

impl GetBlockFilterHeaderRequest {
    pub fn new(block_hash: RpcHash) -> Self {
        Self { block_hash }
    }
}

impl Serializer for GetBlockFilterHeaderRequest {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;
        store!(RpcHash, &self.block_hash, writer)
    }
}

impl Deserializer for GetBlockFilterHeaderRequest {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        let block_hash = load!(RpcHash, reader)?;
        Ok(Self { block_hash })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockFilterHeaderResponse {
    pub header: Option<RpcBlockFilterHeader>,
}

impl GetBlockFilterHeaderResponse {
    pub fn new(header: Option<RpcBlockFilterHeader>) -> Self {
        Self { header }
    }
}

impl Serializer for GetBlockFilterHeaderResponse {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;
        match &self.header {
            Some(h) => {
                store!(u8, &1, writer)?;
                serialize!(RpcBlockFilterHeader, h, writer)
            }
            None => store!(u8, &0, writer),
        }
    }
}

impl Deserializer for GetBlockFilterHeaderResponse {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        let tag: u8 = load!(u8, reader)?;
        let header = if tag == 1 { Some(deserialize!(RpcBlockFilterHeader, reader)?) } else { None };
        Ok(Self { header })
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
    fn rt_filter_request() {
        let r = GetBlockFilterRequest::new(RpcHash::from_slice(&[0x10; 32]));
        let d = rt(&r);
        assert_eq!(d.block_hash, r.block_hash);
    }

    #[test]
    fn rt_filter_response_some() {
        let f = RpcBlockFilter {
            block_hash: RpcHash::from_slice(&[0x10; 32]),
            filter_bytes: vec![0x01, 0x02, 0x03, 0x04],
            filter_hash: vec![0xAA; 32],
        };
        let r = GetBlockFilterResponse::new(Some(f));
        let d = rt(&r);
        let back = d.filter.unwrap();
        assert_eq!(back.filter_bytes, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(back.filter_hash.len(), 32);
    }

    #[test]
    fn rt_filter_response_none() {
        let r = GetBlockFilterResponse::new(None);
        let d = rt(&r);
        assert!(d.filter.is_none());
    }

    #[test]
    fn rt_header_request() {
        let r = GetBlockFilterHeaderRequest::new(RpcHash::from_slice(&[0x20; 32]));
        let d = rt(&r);
        assert_eq!(d.block_hash, r.block_hash);
    }

    #[test]
    fn rt_header_response_some() {
        let h = RpcBlockFilterHeader {
            block_hash: RpcHash::from_slice(&[0x20; 32]),
            prev_header: vec![0xBB; 32],
            filter_hash: vec![0xCC; 32],
            filter_header: vec![0xDD; 32],
        };
        let r = GetBlockFilterHeaderResponse::new(Some(h));
        let d = rt(&r);
        let back = d.header.unwrap();
        assert_eq!(back.prev_header.len(), 32);
        assert_eq!(back.filter_hash.len(), 32);
        assert_eq!(back.filter_header.len(), 32);
    }

    #[test]
    fn rt_header_response_none() {
        let r = GetBlockFilterHeaderResponse::new(None);
        let d = rt(&r);
        assert!(d.header.is_none());
    }
}
