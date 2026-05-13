//! J5 — Light client SPV Merkle proof RPC types.
//!
//! Wire models for `getTxMerkleProof`. Mirrors the `TxMerkleProof`
//! type from `sophis_merkle` but uses RPC-friendly `Vec<u8>` for the
//! Hash + MerkleHash byte arrays (workflow-serializer compatible).
//!
//! See `docs/J5_LIGHT_CLIENT_DESIGN.md` for the canonical specification.

use crate::RpcHash;
use serde::{Deserialize, Serialize};
use workflow_serializer::prelude::*;

/// Per-transaction Merkle proof. The `tx_id` and `block_hash` are
/// echoed for caller convenience; `leaf_sibling` is a 32-byte `Hash`;
/// `node_siblings` is a sequence of 48-byte `MerkleHash` values
/// (root-direction last); `position` is the tx's index within the
/// block's transaction list.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTxMerkleProof {
    pub tx_id: RpcHash,
    pub block_hash: RpcHash,
    pub leaf_sibling: Vec<u8>,       // 32 bytes
    pub node_siblings: Vec<Vec<u8>>, // each 48 bytes
    pub position: u32,
}

impl Serializer for RpcTxMerkleProof {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u8, &1, writer)?;
        store!(RpcHash, &self.tx_id, writer)?;
        store!(RpcHash, &self.block_hash, writer)?;
        store!(Vec<u8>, &self.leaf_sibling, writer)?;
        store!(Vec<Vec<u8>>, &self.node_siblings, writer)?;
        store!(u32, &self.position, writer)
    }
}

impl Deserializer for RpcTxMerkleProof {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version: u8 = load!(u8, reader)?;
        let tx_id = load!(RpcHash, reader)?;
        let block_hash = load!(RpcHash, reader)?;
        let leaf_sibling = load!(Vec<u8>, reader)?;
        let node_siblings = load!(Vec<Vec<u8>>, reader)?;
        let position = load!(u32, reader)?;
        Ok(Self { tx_id, block_hash, leaf_sibling, node_siblings, position })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTxMerkleProofRequest {
    pub tx_id: RpcHash,
    pub block_hash: RpcHash,
}

impl GetTxMerkleProofRequest {
    pub fn new(tx_id: RpcHash, block_hash: RpcHash) -> Self {
        Self { tx_id, block_hash }
    }
}

impl Serializer for GetTxMerkleProofRequest {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;
        store!(RpcHash, &self.tx_id, writer)?;
        store!(RpcHash, &self.block_hash, writer)
    }
}

impl Deserializer for GetTxMerkleProofRequest {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        let tx_id = load!(RpcHash, reader)?;
        let block_hash = load!(RpcHash, reader)?;
        Ok(Self { tx_id, block_hash })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTxMerkleProofResponse {
    pub proof: Option<RpcTxMerkleProof>,
}

impl GetTxMerkleProofResponse {
    pub fn new(proof: Option<RpcTxMerkleProof>) -> Self {
        Self { proof }
    }
}

impl Serializer for GetTxMerkleProofResponse {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        store!(u16, &1, writer)?;
        match &self.proof {
            Some(p) => {
                store!(u8, &1, writer)?;
                serialize!(RpcTxMerkleProof, p, writer)
            }
            None => store!(u8, &0, writer),
        }
    }
}

impl Deserializer for GetTxMerkleProofResponse {
    fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _version = load!(u16, reader)?;
        let tag: u8 = load!(u8, reader)?;
        let proof = if tag == 1 { Some(deserialize!(RpcTxMerkleProof, reader)?) } else { None };
        Ok(Self { proof })
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
        let r = GetTxMerkleProofRequest::new(RpcHash::from_slice(&[0x10; 32]), RpcHash::from_slice(&[0x20; 32]));
        let d = rt(&r);
        assert_eq!(d.tx_id, r.tx_id);
        assert_eq!(d.block_hash, r.block_hash);
    }

    #[test]
    fn rt_response_some() {
        let p = RpcTxMerkleProof {
            tx_id: RpcHash::from_slice(&[0x10; 32]),
            block_hash: RpcHash::from_slice(&[0x20; 32]),
            leaf_sibling: vec![0xAA; 32],
            node_siblings: vec![vec![0xBB; 48], vec![0xCC; 48], vec![0xDD; 48]],
            position: 5,
        };
        let r = GetTxMerkleProofResponse::new(Some(p));
        let d = rt(&r);
        let back = d.proof.unwrap();
        assert_eq!(back.leaf_sibling, vec![0xAA; 32]);
        assert_eq!(back.node_siblings.len(), 3);
        assert_eq!(back.position, 5);
    }

    #[test]
    fn rt_response_none() {
        let r = GetTxMerkleProofResponse::new(None);
        let d = rt(&r);
        assert!(d.proof.is_none());
    }

    #[test]
    fn rt_response_empty_node_siblings() {
        // Single-tx block: node_siblings is empty.
        let p = RpcTxMerkleProof {
            tx_id: RpcHash::from_slice(&[0x10; 32]),
            block_hash: RpcHash::from_slice(&[0x20; 32]),
            leaf_sibling: vec![0; 32],
            node_siblings: vec![],
            position: 0,
        };
        let r = GetTxMerkleProofResponse::new(Some(p));
        let d = rt(&r);
        assert!(d.proof.unwrap().node_siblings.is_empty());
    }
}
