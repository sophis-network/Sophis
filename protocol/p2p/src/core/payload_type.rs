use crate::pb::sophisd_message::Payload as SophisdMessagePayload;

#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
pub enum SophisdMessagePayloadType {
    Addresses = 0,
    Block,
    Transaction,
    BlockLocator,
    RequestAddresses,
    RequestRelayBlocks,
    RequestTransactions,
    IbdBlock,
    InvRelayBlock,
    InvTransactions,
    Ping,
    Pong,
    Verack,
    Version,
    TransactionNotFound,
    Reject,
    PruningPointUtxoSetChunk,
    RequestIbdBlocks,
    UnexpectedPruningPoint,
    IbdBlockLocator,
    IbdBlockLocatorHighestHash,
    RequestNextPruningPointUtxoSetChunk,
    DonePruningPointUtxoSetChunks,
    IbdBlockLocatorHighestHashNotFound,
    BlockWithTrustedData,
    DoneBlocksWithTrustedData,
    RequestPruningPointAndItsAnticone,
    BlockHeaders,
    RequestNextHeaders,
    DoneHeaders,
    RequestPruningPointUtxoSet,
    RequestHeaders,
    RequestBlockLocator,
    PruningPoints,
    RequestPruningPointProof,
    PruningPointProof,
    Ready,
    BlockWithTrustedDataV4,
    TrustedData,
    RequestIbdChainBlockLocator,
    IbdChainBlockLocator,
    RequestAntipast,
    RequestNextPruningPointAndItsAnticoneBlocks,
    BlockBody,
    RequestBlockBodies,
}

impl From<&SophisdMessagePayload> for SophisdMessagePayloadType {
    fn from(payload: &SophisdMessagePayload) -> Self {
        match payload {
            SophisdMessagePayload::Addresses(_) => SophisdMessagePayloadType::Addresses,
            SophisdMessagePayload::Block(_) => SophisdMessagePayloadType::Block,
            SophisdMessagePayload::Transaction(_) => SophisdMessagePayloadType::Transaction,
            SophisdMessagePayload::BlockLocator(_) => SophisdMessagePayloadType::BlockLocator,
            SophisdMessagePayload::RequestAddresses(_) => SophisdMessagePayloadType::RequestAddresses,
            SophisdMessagePayload::RequestRelayBlocks(_) => SophisdMessagePayloadType::RequestRelayBlocks,
            SophisdMessagePayload::RequestTransactions(_) => SophisdMessagePayloadType::RequestTransactions,
            SophisdMessagePayload::IbdBlock(_) => SophisdMessagePayloadType::IbdBlock,
            SophisdMessagePayload::InvRelayBlock(_) => SophisdMessagePayloadType::InvRelayBlock,
            SophisdMessagePayload::InvTransactions(_) => SophisdMessagePayloadType::InvTransactions,
            SophisdMessagePayload::Ping(_) => SophisdMessagePayloadType::Ping,
            SophisdMessagePayload::Pong(_) => SophisdMessagePayloadType::Pong,
            SophisdMessagePayload::Verack(_) => SophisdMessagePayloadType::Verack,
            SophisdMessagePayload::Version(_) => SophisdMessagePayloadType::Version,
            SophisdMessagePayload::TransactionNotFound(_) => SophisdMessagePayloadType::TransactionNotFound,
            SophisdMessagePayload::Reject(_) => SophisdMessagePayloadType::Reject,
            SophisdMessagePayload::PruningPointUtxoSetChunk(_) => SophisdMessagePayloadType::PruningPointUtxoSetChunk,
            SophisdMessagePayload::RequestIbdBlocks(_) => SophisdMessagePayloadType::RequestIbdBlocks,
            SophisdMessagePayload::UnexpectedPruningPoint(_) => SophisdMessagePayloadType::UnexpectedPruningPoint,
            SophisdMessagePayload::IbdBlockLocator(_) => SophisdMessagePayloadType::IbdBlockLocator,
            SophisdMessagePayload::IbdBlockLocatorHighestHash(_) => SophisdMessagePayloadType::IbdBlockLocatorHighestHash,
            SophisdMessagePayload::RequestNextPruningPointUtxoSetChunk(_) => {
                SophisdMessagePayloadType::RequestNextPruningPointUtxoSetChunk
            }
            SophisdMessagePayload::DonePruningPointUtxoSetChunks(_) => SophisdMessagePayloadType::DonePruningPointUtxoSetChunks,
            SophisdMessagePayload::IbdBlockLocatorHighestHashNotFound(_) => {
                SophisdMessagePayloadType::IbdBlockLocatorHighestHashNotFound
            }
            SophisdMessagePayload::BlockWithTrustedData(_) => SophisdMessagePayloadType::BlockWithTrustedData,
            SophisdMessagePayload::DoneBlocksWithTrustedData(_) => SophisdMessagePayloadType::DoneBlocksWithTrustedData,
            SophisdMessagePayload::RequestPruningPointAndItsAnticone(_) => {
                SophisdMessagePayloadType::RequestPruningPointAndItsAnticone
            }
            SophisdMessagePayload::BlockHeaders(_) => SophisdMessagePayloadType::BlockHeaders,
            SophisdMessagePayload::RequestNextHeaders(_) => SophisdMessagePayloadType::RequestNextHeaders,
            SophisdMessagePayload::DoneHeaders(_) => SophisdMessagePayloadType::DoneHeaders,
            SophisdMessagePayload::RequestPruningPointUtxoSet(_) => SophisdMessagePayloadType::RequestPruningPointUtxoSet,
            SophisdMessagePayload::RequestHeaders(_) => SophisdMessagePayloadType::RequestHeaders,
            SophisdMessagePayload::RequestBlockLocator(_) => SophisdMessagePayloadType::RequestBlockLocator,
            SophisdMessagePayload::PruningPoints(_) => SophisdMessagePayloadType::PruningPoints,
            SophisdMessagePayload::RequestPruningPointProof(_) => SophisdMessagePayloadType::RequestPruningPointProof,
            SophisdMessagePayload::PruningPointProof(_) => SophisdMessagePayloadType::PruningPointProof,
            SophisdMessagePayload::Ready(_) => SophisdMessagePayloadType::Ready,
            SophisdMessagePayload::BlockWithTrustedDataV4(_) => SophisdMessagePayloadType::BlockWithTrustedDataV4,
            SophisdMessagePayload::TrustedData(_) => SophisdMessagePayloadType::TrustedData,
            SophisdMessagePayload::RequestIbdChainBlockLocator(_) => SophisdMessagePayloadType::RequestIbdChainBlockLocator,
            SophisdMessagePayload::IbdChainBlockLocator(_) => SophisdMessagePayloadType::IbdChainBlockLocator,
            SophisdMessagePayload::RequestAntipast(_) => SophisdMessagePayloadType::RequestAntipast,
            SophisdMessagePayload::RequestNextPruningPointAndItsAnticoneBlocks(_) => {
                SophisdMessagePayloadType::RequestNextPruningPointAndItsAnticoneBlocks
            }
            SophisdMessagePayload::BlockBody(_) => SophisdMessagePayloadType::BlockBody,
            SophisdMessagePayload::RequestBlockBodies(_) => SophisdMessagePayloadType::RequestBlockBodies,
        }
    }
}
