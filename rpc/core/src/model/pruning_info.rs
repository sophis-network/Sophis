//! J8 — Pruning info RPC types.
//!
//! Wire models for `getPruningInfo` per `docs/J8_PRUNING_AUDIT.md` §4.

use crate::RpcHash;
use serde::{Deserialize, Serialize};
use workflow_serializer::prelude::*;

/// Per-node pruning info as exposed via RPC. Read-only by design D6.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcPruningInfo {
    pub pruning_depth: u64,
    pub finality_depth: u64,
    pub current_pruning_point: RpcHash,
    pub pruning_point_blue_score: u64,
    pub is_archival: bool,
}

impl Serializer for RpcPruningInfo {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?;
        store!(u64, &self.pruning_depth, writer)?;
        store!(u64, &self.finality_depth, writer)?;
        store!(RpcHash, &self.current_pruning_point, writer)?;
        store!(u64, &self.pruning_point_blue_score, writer)?;
        store!(bool, &self.is_archival, writer)
    }
}

impl Deserializer for RpcPruningInfo {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version: u8 = load!(u8, reader)?;
        let pruning_depth = load!(u64, reader)?;
        let finality_depth = load!(u64, reader)?;
        let current_pruning_point = load!(RpcHash, reader)?;
        let pruning_point_blue_score = load!(u64, reader)?;
        let is_archival = load!(bool, reader)?;
        Ok(Self { pruning_depth, finality_depth, current_pruning_point, pruning_point_blue_score, is_archival })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPruningInfoRequest {}

impl GetPruningInfoRequest {
    pub fn new() -> Self {
        Self {}
    }
}

impl Serializer for GetPruningInfoRequest {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)
    }
}

impl Deserializer for GetPruningInfoRequest {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        Ok(Self {})
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPruningInfoResponse {
    pub info: RpcPruningInfo,
}

impl GetPruningInfoResponse {
    pub fn new(info: RpcPruningInfo) -> Self {
        Self { info }
    }
}

impl Serializer for GetPruningInfoResponse {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;
        serialize!(RpcPruningInfo, &self.info, writer)
    }
}

impl Deserializer for GetPruningInfoResponse {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        let info = deserialize!(RpcPruningInfo, reader)?;
        Ok(Self { info })
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
    fn rt_request() {
        let r = GetPruningInfoRequest::new();
        let _d = rt(&r);
    }

    #[test]
    fn rt_response_pruned_node() {
        let info = RpcPruningInfo {
            pruning_depth: 432_000,
            finality_depth: 432_000,
            current_pruning_point: RpcHash::from_slice(&[0xAB; 32]),
            pruning_point_blue_score: 999_999,
            is_archival: false,
        };
        let r = GetPruningInfoResponse::new(info);
        let d = rt(&r);
        assert_eq!(d.info.pruning_depth, 432_000);
        assert_eq!(d.info.finality_depth, 432_000);
        assert_eq!(d.info.pruning_point_blue_score, 999_999);
        assert!(!d.info.is_archival);
    }

    #[test]
    fn rt_response_archival_node() {
        let info = RpcPruningInfo {
            pruning_depth: 600_000,
            finality_depth: 432_000,
            current_pruning_point: RpcHash::from_slice(&[0xCD; 32]),
            pruning_point_blue_score: 1_500_000,
            is_archival: true,
        };
        let r = GetPruningInfoResponse::new(info);
        let d = rt(&r);
        assert!(d.info.is_archival);
        assert_eq!(d.info.current_pruning_point, RpcHash::from_slice(&[0xCD; 32]));
    }
}
