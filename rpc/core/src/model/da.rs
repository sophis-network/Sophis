//! Phase 6 — Data Availability RPC types.
//!
//! Wire models for the five `get_da_*` methods of the RPC trait. Mirrors
//! `consensus_core::da::{PayloadEntry, BundleIndex, BlockCarriers, DomainBucket}`
//! but uses RPC-friendly types: `Vec<u8>` for the 48-byte SHA3-384 hashes
//! (serde + workflow-serializer compatible without ad-hoc trait impls).
//!
//! See `oracle/docs/PHASE6_DA_DESIGN.md` §6.2 for the underlying store schema.

use crate::RpcHash;
use serde::{Deserialize, Serialize};
use workflow_serializer::prelude::*;

// ---------------------------------------------------------------------------
// Shared types (response shapes)
// ---------------------------------------------------------------------------

/// One V5 carrier output as exposed via RPC. The 48-byte SHA3-384 hashes
/// (`payload_id`, `bundle_id`) are encoded as `Vec<u8>` so the type works
/// out-of-the-box with both serde (JSON) and workflow-serializer (binary).
/// Length is always 48; consumers MAY assert on it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcDaPayload {
    pub payload_id: Vec<u8>,
    pub script: Vec<u8>,
    pub accepting_block_hash: RpcHash,
    pub blue_score: u64,
    pub fragment_index: u8,
    pub fragment_count: u8,
    pub bundle_id: Vec<u8>,
    pub domain_byte: u8,
}

impl Serializer for RpcDaPayload {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?; // version
        store!(Vec<u8>, &self.payload_id, writer)?;
        store!(Vec<u8>, &self.script, writer)?;
        store!(RpcHash, &self.accepting_block_hash, writer)?;
        store!(u64, &self.blue_score, writer)?;
        store!(u8, &self.fragment_index, writer)?;
        store!(u8, &self.fragment_count, writer)?;
        store!(Vec<u8>, &self.bundle_id, writer)?;
        store!(u8, &self.domain_byte, writer)
    }
}

impl Deserializer for RpcDaPayload {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version: u8 = load!(u8, reader)?;
        let payload_id = load!(Vec<u8>, reader)?;
        let script = load!(Vec<u8>, reader)?;
        let accepting_block_hash = load!(RpcHash, reader)?;
        let blue_score = load!(u64, reader)?;
        let fragment_index = load!(u8, reader)?;
        let fragment_count = load!(u8, reader)?;
        let bundle_id = load!(Vec<u8>, reader)?;
        let domain_byte = load!(u8, reader)?;
        Ok(Self { payload_id, script, accepting_block_hash, blue_score, fragment_index, fragment_count, bundle_id, domain_byte })
    }
}

/// Inline view of a reassembled DA bundle, plus its fragment list.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcDaBundle {
    pub bundle_id: Vec<u8>,
    pub fragment_count: u8,
    /// `payload_id`s of the fragments (sorted by fragment_index ascending).
    pub payload_ids: Vec<Vec<u8>>,
    /// Concatenated body bytes if reassembly succeeded; `None` if any
    /// fragment is missing.
    pub data: Option<Vec<u8>>,
}

impl Serializer for RpcDaBundle {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?;
        store!(Vec<u8>, &self.bundle_id, writer)?;
        store!(u8, &self.fragment_count, writer)?;
        store!(Vec<Vec<u8>>, &self.payload_ids, writer)?;
        store!(Option<Vec<u8>>, &self.data, writer)
    }
}

impl Deserializer for RpcDaBundle {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version: u8 = load!(u8, reader)?;
        let bundle_id = load!(Vec<u8>, reader)?;
        let fragment_count = load!(u8, reader)?;
        let payload_ids = load!(Vec<Vec<u8>>, reader)?;
        let data = load!(Option<Vec<u8>>, reader)?;
        Ok(Self { bundle_id, fragment_count, payload_ids, data })
    }
}

/// Confirmation status of a single payload_id.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcDaPayloadStatus {
    pub accepted: bool,
    pub accepting_block_hash: RpcHash,
    pub blue_score: u64,
    pub confirmations: u64,
}

impl Serializer for RpcDaPayloadStatus {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?;
        store!(bool, &self.accepted, writer)?;
        store!(RpcHash, &self.accepting_block_hash, writer)?;
        store!(u64, &self.blue_score, writer)?;
        store!(u64, &self.confirmations, writer)
    }
}

impl Deserializer for RpcDaPayloadStatus {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version: u8 = load!(u8, reader)?;
        let accepted = load!(bool, reader)?;
        let accepting_block_hash = load!(RpcHash, reader)?;
        let blue_score = load!(u64, reader)?;
        let confirmations = load!(u64, reader)?;
        Ok(Self { accepted, accepting_block_hash, blue_score, confirmations })
    }
}

// ---------------------------------------------------------------------------
// 1. GetDaPayload — fetch one fragment
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDaPayloadRequest {
    /// 48-byte SHA3-384 payload_id.
    pub payload_id: Vec<u8>,
}

impl GetDaPayloadRequest {
    pub fn new(payload_id: Vec<u8>) -> Self {
        Self { payload_id }
    }
}

impl Serializer for GetDaPayloadRequest {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;
        store!(Vec<u8>, &self.payload_id, writer)
    }
}

impl Deserializer for GetDaPayloadRequest {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        let payload_id = load!(Vec<u8>, reader)?;
        Ok(Self { payload_id })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDaPayloadResponse {
    /// `None` if the payload_id is unknown (or pruned).
    pub entry: Option<RpcDaPayload>,
}

impl GetDaPayloadResponse {
    pub fn new(entry: Option<RpcDaPayload>) -> Self {
        Self { entry }
    }
}

impl Serializer for GetDaPayloadResponse {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;
        match &self.entry {
            Some(p) => {
                store!(u8, &1, writer)?;
                serialize!(RpcDaPayload, p, writer)
            }
            None => store!(u8, &0, writer),
        }
    }
}

impl Deserializer for GetDaPayloadResponse {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        let tag: u8 = load!(u8, reader)?;
        let entry = if tag == 1 { Some(deserialize!(RpcDaPayload, reader)?) } else { None };
        Ok(Self { entry })
    }
}

// ---------------------------------------------------------------------------
// 2. GetDaBundle — reassemble + return bytes
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDaBundleRequest {
    pub bundle_id: Vec<u8>,
}

impl GetDaBundleRequest {
    pub fn new(bundle_id: Vec<u8>) -> Self {
        Self { bundle_id }
    }
}

impl Serializer for GetDaBundleRequest {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;
        store!(Vec<u8>, &self.bundle_id, writer)
    }
}

impl Deserializer for GetDaBundleRequest {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        let bundle_id = load!(Vec<u8>, reader)?;
        Ok(Self { bundle_id })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDaBundleResponse {
    pub bundle: Option<RpcDaBundle>,
}

impl GetDaBundleResponse {
    pub fn new(bundle: Option<RpcDaBundle>) -> Self {
        Self { bundle }
    }
}

impl Serializer for GetDaBundleResponse {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;
        match &self.bundle {
            Some(b) => {
                store!(u8, &1, writer)?;
                serialize!(RpcDaBundle, b, writer)
            }
            None => store!(u8, &0, writer),
        }
    }
}

impl Deserializer for GetDaBundleResponse {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        let tag: u8 = load!(u8, reader)?;
        let bundle = if tag == 1 { Some(deserialize!(RpcDaBundle, reader)?) } else { None };
        Ok(Self { bundle })
    }
}

// ---------------------------------------------------------------------------
// 3. GetDaCarriersByBlock
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDaCarriersByBlockRequest {
    pub block_hash: RpcHash,
}

impl GetDaCarriersByBlockRequest {
    pub fn new(block_hash: RpcHash) -> Self {
        Self { block_hash }
    }
}

impl Serializer for GetDaCarriersByBlockRequest {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;
        store!(RpcHash, &self.block_hash, writer)
    }
}

impl Deserializer for GetDaCarriersByBlockRequest {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        let block_hash = load!(RpcHash, reader)?;
        Ok(Self { block_hash })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDaCarriersByBlockResponse {
    pub payload_ids: Vec<Vec<u8>>,
}

impl GetDaCarriersByBlockResponse {
    pub fn new(payload_ids: Vec<Vec<u8>>) -> Self {
        Self { payload_ids }
    }
}

impl Serializer for GetDaCarriersByBlockResponse {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;
        store!(Vec<Vec<u8>>, &self.payload_ids, writer)
    }
}

impl Deserializer for GetDaCarriersByBlockResponse {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        let payload_ids = load!(Vec<Vec<u8>>, reader)?;
        Ok(Self { payload_ids })
    }
}

// ---------------------------------------------------------------------------
// 4. GetDaCarriersByDomain — query (domain, blue_score) bucket
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDaCarriersByDomainRequest {
    /// Single `CARRIER_FLAG_DOMAIN_*` byte (0x10 rollup, 0x20 oracle, 0x40 user).
    pub domain_byte: u8,
    /// Any blue_score within the desired bucket. Bucket = blue_score / 1000.
    pub blue_score: u64,
}

impl GetDaCarriersByDomainRequest {
    pub fn new(domain_byte: u8, blue_score: u64) -> Self {
        Self { domain_byte, blue_score }
    }
}

impl Serializer for GetDaCarriersByDomainRequest {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;
        store!(u8, &self.domain_byte, writer)?;
        store!(u64, &self.blue_score, writer)
    }
}

impl Deserializer for GetDaCarriersByDomainRequest {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        let domain_byte = load!(u8, reader)?;
        let blue_score = load!(u64, reader)?;
        Ok(Self { domain_byte, blue_score })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDaCarriersByDomainResponse {
    pub payload_ids: Vec<Vec<u8>>,
}

impl GetDaCarriersByDomainResponse {
    pub fn new(payload_ids: Vec<Vec<u8>>) -> Self {
        Self { payload_ids }
    }
}

impl Serializer for GetDaCarriersByDomainResponse {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;
        store!(Vec<Vec<u8>>, &self.payload_ids, writer)
    }
}

impl Deserializer for GetDaCarriersByDomainResponse {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        let payload_ids = load!(Vec<Vec<u8>>, reader)?;
        Ok(Self { payload_ids })
    }
}

// ---------------------------------------------------------------------------
// 5. GetDaPayloadStatus — accepted? confirmation count?
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDaPayloadStatusRequest {
    pub payload_id: Vec<u8>,
}

impl GetDaPayloadStatusRequest {
    pub fn new(payload_id: Vec<u8>) -> Self {
        Self { payload_id }
    }
}

impl Serializer for GetDaPayloadStatusRequest {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;
        store!(Vec<u8>, &self.payload_id, writer)
    }
}

impl Deserializer for GetDaPayloadStatusRequest {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        let payload_id = load!(Vec<u8>, reader)?;
        Ok(Self { payload_id })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDaPayloadStatusResponse {
    pub status: Option<RpcDaPayloadStatus>,
}

impl GetDaPayloadStatusResponse {
    pub fn new(status: Option<RpcDaPayloadStatus>) -> Self {
        Self { status }
    }
}

impl Serializer for GetDaPayloadStatusResponse {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;
        match &self.status {
            Some(s) => {
                store!(u8, &1, writer)?;
                serialize!(RpcDaPayloadStatus, s, writer)
            }
            None => store!(u8, &0, writer),
        }
    }
}

impl Deserializer for GetDaPayloadStatusResponse {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        let tag: u8 = load!(u8, reader)?;
        let status = if tag == 1 { Some(deserialize!(RpcDaPayloadStatus, reader)?) } else { None };
        Ok(Self { status })
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

    fn sample_payload() -> RpcDaPayload {
        RpcDaPayload {
            payload_id: vec![0xAA; 48],
            script: vec![0x01, 0x02, 0x03],
            accepting_block_hash: RpcHash::from_slice(&[0x10; 32]),
            blue_score: 1234,
            fragment_index: 2,
            fragment_count: 5,
            bundle_id: vec![0xBB; 48],
            domain_byte: 0x10,
        }
    }

    #[test]
    fn rt_get_da_payload_request() {
        let r = GetDaPayloadRequest::new(vec![0x42; 48]);
        let d = rt(&r);
        assert_eq!(d.payload_id, vec![0x42; 48]);
    }

    #[test]
    fn rt_get_da_payload_response_some() {
        let r = GetDaPayloadResponse::new(Some(sample_payload()));
        let d = rt(&r);
        let entry = d.entry.expect("Some round-trip");
        assert_eq!(entry.fragment_index, 2);
        assert_eq!(entry.fragment_count, 5);
        assert_eq!(entry.domain_byte, 0x10);
        assert_eq!(entry.blue_score, 1234);
    }

    #[test]
    fn rt_get_da_payload_response_none() {
        let r = GetDaPayloadResponse::new(None);
        let d = rt(&r);
        assert!(d.entry.is_none());
    }

    #[test]
    fn rt_get_da_bundle_response() {
        let bundle = RpcDaBundle {
            bundle_id: vec![0xCC; 48],
            fragment_count: 3,
            payload_ids: vec![vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]],
            data: Some(b"hello-world".to_vec()),
        };
        let r = GetDaBundleResponse::new(Some(bundle));
        let d = rt(&r);
        let b = d.bundle.unwrap();
        assert_eq!(b.fragment_count, 3);
        assert_eq!(b.payload_ids.len(), 3);
        assert_eq!(b.data.as_deref(), Some(b"hello-world".as_slice()));
    }

    #[test]
    fn rt_get_da_carriers_by_block() {
        let req = GetDaCarriersByBlockRequest::new(RpcHash::from_slice(&[7u8; 32]));
        let dr = rt(&req);
        assert_eq!(dr.block_hash.as_bytes(), [7u8; 32]);

        let resp = GetDaCarriersByBlockResponse::new(vec![vec![9u8; 48], vec![10u8; 48]]);
        let dresp = rt(&resp);
        assert_eq!(dresp.payload_ids.len(), 2);
    }

    #[test]
    fn rt_get_da_carriers_by_domain() {
        let req = GetDaCarriersByDomainRequest::new(0x20, 5_000);
        let dr = rt(&req);
        assert_eq!(dr.domain_byte, 0x20);
        assert_eq!(dr.blue_score, 5_000);
    }

    #[test]
    fn rt_get_da_payload_status() {
        let status = RpcDaPayloadStatus {
            accepted: true,
            accepting_block_hash: RpcHash::from_slice(&[0xCC; 32]),
            blue_score: 100,
            confirmations: 250,
        };
        let resp = GetDaPayloadStatusResponse::new(Some(status));
        let d = rt(&resp);
        let s = d.status.unwrap();
        assert!(s.accepted);
        assert_eq!(s.confirmations, 250);
    }
}
