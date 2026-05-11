//! J4 — sVM event-log RPC types.
//!
//! Wire models for the `getLogs` RPC method described in
//! `docs/J4_EVENTS_DESIGN.md` §7. Mirrors `consensus_core::events::EventLog`
//! but uses RPC-friendly types: `Vec<u8>` for the 32-byte topics and
//! contract id (serde + workflow-serializer compatible without ad-hoc trait
//! impls) and the `RpcHash` newtype for chain hashes.
//!
//! All-axes filter shape is intentionally Ethereum-`eth_getLogs`-shaped so
//! existing indexer tooling speaks the same idiom. See `RpcEventLogFilter`
//! semantics below.

use crate::RpcHash;
use serde::{Deserialize, Serialize};
use workflow_serializer::prelude::*;

/// Server-side hard cap on the number of logs in a single response,
/// regardless of the client `limit` field. Matches
/// `consensus_core::events::MAX_LOGS_PER_RESPONSE`. Frozen ABI.
pub const MAX_LOGS_PER_RESPONSE: u32 = 1_000;

// ---------------------------------------------------------------------------
// RpcEventLog — wire form of one stored event
// ---------------------------------------------------------------------------

/// One indexed sVM event as exposed via RPC. The 32-byte `contract_id`
/// and topics are encoded as `Vec<u8>` so the type works out of the box
/// with both serde (JSON) and workflow-serializer (binary). Lengths are
/// always 32; consumers MAY assert on them.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcEventLog {
    pub contract_id: Vec<u8>,
    /// 0..=4 topics, each exactly 32 bytes (`MAX_TOPICS_PER_EVENT`).
    pub topics: Vec<Vec<u8>>,
    /// Free-form data, capped at `MAX_EVENT_DATA_BYTES` (= 4096) by the
    /// emit-time consensus check.
    pub data: Vec<u8>,
    pub block_hash: RpcHash,
    pub tx_id: RpcHash,
    pub tx_index: u32,
    pub log_index: u32,
    pub daa_score: u64,
}

impl Serializer for RpcEventLog {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?; // version
        store!(Vec<u8>, &self.contract_id, writer)?;
        store!(Vec<Vec<u8>>, &self.topics, writer)?;
        store!(Vec<u8>, &self.data, writer)?;
        store!(RpcHash, &self.block_hash, writer)?;
        store!(RpcHash, &self.tx_id, writer)?;
        store!(u32, &self.tx_index, writer)?;
        store!(u32, &self.log_index, writer)?;
        store!(u64, &self.daa_score, writer)
    }
}

impl Deserializer for RpcEventLog {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version: u8 = load!(u8, reader)?;
        let contract_id = load!(Vec<u8>, reader)?;
        let topics = load!(Vec<Vec<u8>>, reader)?;
        let data = load!(Vec<u8>, reader)?;
        let block_hash = load!(RpcHash, reader)?;
        let tx_id = load!(RpcHash, reader)?;
        let tx_index = load!(u32, reader)?;
        let log_index = load!(u32, reader)?;
        let daa_score = load!(u64, reader)?;
        Ok(Self { contract_id, topics, data, block_hash, tx_id, tx_index, log_index, daa_score })
    }
}

// ---------------------------------------------------------------------------
// GetLogsRequest — eth_getLogs-shaped filter
// ---------------------------------------------------------------------------

/// Filter passed to `getLogs`. All axes AND-combined.
///
/// * `contract_id` — `Some(id)` matches only events emitted by `id`.
///   `None` is wildcard.
/// * `topics` — positional, 0..=4 entries. `topics[i] = Some(t)` requires
///   slot `i` of the event to equal `t`. `None` is wildcard at that slot.
///   Empty `topics` vector is wildcard at every slot.
/// * `from_block` / `to_block` — inclusive block-hash bounds. The server
///   resolves them to DAA scores via the headers store and walks the
///   bucketed indexes. `None` means open-ended on that side.
/// * `limit` — client-side cap on returned rows. Server still enforces
///   `MAX_LOGS_PER_RESPONSE` (`1000`) regardless. `None` defers to the
///   server cap.
///
/// **At least one of {`contract_id`, any `topics[i] = Some`, both
/// `from_block` and `to_block` set}** must be specified — otherwise the
/// server rejects with an error. This mirrors the Ethereum
/// reference-implementation rule preventing whole-chain scans.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetLogsRequest {
    pub contract_id: Option<Vec<u8>>,
    pub topics: Vec<Option<Vec<u8>>>,
    pub from_block: Option<RpcHash>,
    pub to_block: Option<RpcHash>,
    pub limit: Option<u32>,
}

impl GetLogsRequest {
    pub fn new(
        contract_id: Option<Vec<u8>>,
        topics: Vec<Option<Vec<u8>>>,
        from_block: Option<RpcHash>,
        to_block: Option<RpcHash>,
        limit: Option<u32>,
    ) -> Self {
        Self { contract_id, topics, from_block, to_block, limit }
    }
}

impl Serializer for GetLogsRequest {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?; // version
        // Option<Vec<u8>> via tag byte
        match &self.contract_id {
            Some(c) => {
                store!(u8, &1, writer)?;
                store!(Vec<u8>, c, writer)?;
            }
            None => store!(u8, &0, writer)?,
        }
        // Vec<Option<Vec<u8>>> — manual tag-per-slot
        store!(u32, &(self.topics.len() as u32), writer)?;
        for slot in &self.topics {
            match slot {
                Some(t) => {
                    store!(u8, &1, writer)?;
                    store!(Vec<u8>, t, writer)?;
                }
                None => store!(u8, &0, writer)?,
            }
        }
        // Option<RpcHash>
        match &self.from_block {
            Some(h) => {
                store!(u8, &1, writer)?;
                store!(RpcHash, h, writer)?;
            }
            None => store!(u8, &0, writer)?,
        }
        match &self.to_block {
            Some(h) => {
                store!(u8, &1, writer)?;
                store!(RpcHash, h, writer)?;
            }
            None => store!(u8, &0, writer)?,
        }
        // Option<u32>
        match &self.limit {
            Some(l) => {
                store!(u8, &1, writer)?;
                store!(u32, l, writer)?;
            }
            None => store!(u8, &0, writer)?,
        }
        Ok(())
    }
}

impl Deserializer for GetLogsRequest {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version: u16 = load!(u16, reader)?;
        let contract_id = if load!(u8, reader)? == 1 { Some(load!(Vec<u8>, reader)?) } else { None };
        let n_topics: u32 = load!(u32, reader)?;
        let mut topics: Vec<Option<Vec<u8>>> = Vec::with_capacity(n_topics as usize);
        for _ in 0..n_topics {
            let slot = if load!(u8, reader)? == 1 { Some(load!(Vec<u8>, reader)?) } else { None };
            topics.push(slot);
        }
        let from_block = if load!(u8, reader)? == 1 { Some(load!(RpcHash, reader)?) } else { None };
        let to_block = if load!(u8, reader)? == 1 { Some(load!(RpcHash, reader)?) } else { None };
        let limit = if load!(u8, reader)? == 1 { Some(load!(u32, reader)?) } else { None };
        Ok(Self { contract_id, topics, from_block, to_block, limit })
    }
}

// ---------------------------------------------------------------------------
// GetLogsResponse
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetLogsResponse {
    pub logs: Vec<RpcEventLog>,
}

impl GetLogsResponse {
    pub fn new(logs: Vec<RpcEventLog>) -> Self {
        Self { logs }
    }
}

impl Serializer for GetLogsResponse {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?; // version
        store!(u32, &(self.logs.len() as u32), writer)?;
        for log in &self.logs {
            serialize!(RpcEventLog, log, writer)?;
        }
        Ok(())
    }
}

impl Deserializer for GetLogsResponse {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version: u16 = load!(u16, reader)?;
        let n: u32 = load!(u32, reader)?;
        let mut logs: Vec<RpcEventLog> = Vec::with_capacity(n as usize);
        for _ in 0..n {
            logs.push(deserialize!(RpcEventLog, reader)?);
        }
        Ok(Self { logs })
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

    fn sample_log() -> RpcEventLog {
        RpcEventLog {
            contract_id: vec![0xAAu8; 32],
            topics: vec![vec![0xBBu8; 32], vec![0xCCu8; 32]],
            data: vec![1, 2, 3, 4, 5],
            block_hash: RpcHash::from_slice(&[0x10u8; 32]),
            tx_id: RpcHash::from_slice(&[0x20u8; 32]),
            tx_index: 7,
            log_index: 3,
            daa_score: 9999,
        }
    }

    #[test]
    fn rt_event_log() {
        let l = sample_log();
        let d = rt(&l);
        assert_eq!(d.contract_id, l.contract_id);
        assert_eq!(d.topics, l.topics);
        assert_eq!(d.data, l.data);
        assert_eq!(d.block_hash, l.block_hash);
        assert_eq!(d.tx_id, l.tx_id);
        assert_eq!(d.tx_index, l.tx_index);
        assert_eq!(d.log_index, l.log_index);
        assert_eq!(d.daa_score, l.daa_score);
    }

    #[test]
    fn rt_request_full() {
        let r = GetLogsRequest::new(
            Some(vec![0xAAu8; 32]),
            vec![Some(vec![0xBBu8; 32]), None, Some(vec![0xCCu8; 32])],
            Some(RpcHash::from_slice(&[0x01u8; 32])),
            Some(RpcHash::from_slice(&[0x02u8; 32])),
            Some(500),
        );
        let d = rt(&r);
        assert_eq!(d.contract_id, r.contract_id);
        assert_eq!(d.topics.len(), 3);
        assert!(d.topics[0].is_some());
        assert!(d.topics[1].is_none());
        assert!(d.topics[2].is_some());
        assert_eq!(d.from_block, r.from_block);
        assert_eq!(d.to_block, r.to_block);
        assert_eq!(d.limit, r.limit);
    }

    #[test]
    fn rt_request_minimal() {
        let r = GetLogsRequest::default();
        let d = rt(&r);
        assert!(d.contract_id.is_none());
        assert!(d.topics.is_empty());
        assert!(d.from_block.is_none());
        assert!(d.to_block.is_none());
        assert!(d.limit.is_none());
    }

    #[test]
    fn rt_response_empty() {
        let r = GetLogsResponse::default();
        let d = rt(&r);
        assert!(d.logs.is_empty());
    }

    #[test]
    fn rt_response_multi_logs() {
        let r = GetLogsResponse::new(vec![sample_log(), sample_log(), sample_log()]);
        let d = rt(&r);
        assert_eq!(d.logs.len(), 3);
        for l in &d.logs {
            assert_eq!(l.tx_index, 7);
            assert_eq!(l.daa_score, 9999);
        }
    }

    #[test]
    fn max_logs_per_response_constant_matches_consensus() {
        assert_eq!(MAX_LOGS_PER_RESPONSE, 1_000);
    }
}
