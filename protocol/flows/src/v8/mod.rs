use crate::v7::{
    address::{ReceiveAddressesFlow, SendAddressesFlow},
    blockrelay::{flow::HandleRelayInvsFlow, handle_requests::HandleRelayBlockRequests},
    ping::{ReceivePingsFlow, SendPingsFlow},
    request_antipast::HandleAntipastRequests,
    request_block_locator::RequestBlockLocatorFlow,
    request_headers::RequestHeadersFlow,
    request_ibd_blocks::HandleIbdBlockRequests,
    request_ibd_chain_block_locator::RequestIbdChainBlockLocatorFlow,
    request_pp_proof::RequestPruningPointProofFlow,
    request_pruning_point_and_anticone::PruningPointAndItsAnticoneRequestsFlow,
    request_pruning_point_utxo_set::RequestPruningPointUtxoSetFlow,
    txrelay::flow::{RelayTransactionsFlow, RequestTransactionsFlow},
};
pub(crate) mod request_block_bodies;
use crate::{flow_context::FlowContext, flow_trait::Flow};

use crate::ibd::IbdFlow;
use request_block_bodies::HandleBlockBodyRequests;
use sophis_p2p_lib::{Router, SharedIncomingRoute, SophisdMessagePayloadType, convert::header::HeaderFormat};
use sophis_utils::channel;
use std::sync::Arc;

pub fn register(ctx: FlowContext, router: Arc<Router>, protocol_version: u32) -> Vec<Box<dyn Flow>> {
    // IBD flow <-> invs flow communication uses a job channel in order to always
    // maintain at most a single pending job which can be updated
    let (ibd_sender, relay_receiver) = channel::job();
    let body_only_ibd_permitted = true;
    let header_format = HeaderFormat::from(protocol_version);
    let mut flows: Vec<Box<dyn Flow>> = vec![
        Box::new(IbdFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![
                SophisdMessagePayloadType::BlockHeaders,
                SophisdMessagePayloadType::DoneHeaders,
                SophisdMessagePayloadType::IbdBlockLocatorHighestHash,
                SophisdMessagePayloadType::IbdBlockLocatorHighestHashNotFound,
                SophisdMessagePayloadType::BlockWithTrustedDataV4,
                SophisdMessagePayloadType::DoneBlocksWithTrustedData,
                SophisdMessagePayloadType::IbdChainBlockLocator,
                SophisdMessagePayloadType::IbdBlock,
                SophisdMessagePayloadType::BlockBody,
                SophisdMessagePayloadType::TrustedData,
                SophisdMessagePayloadType::PruningPoints,
                SophisdMessagePayloadType::PruningPointProof,
                SophisdMessagePayloadType::UnexpectedPruningPoint,
                SophisdMessagePayloadType::PruningPointUtxoSetChunk,
                SophisdMessagePayloadType::DonePruningPointUtxoSetChunks,
            ]),
            relay_receiver,
            body_only_ibd_permitted,
            header_format,
        )),
        Box::new(HandleRelayBlockRequests::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SophisdMessagePayloadType::RequestRelayBlocks]),
            header_format,
        )),
        Box::new(ReceivePingsFlow::new(ctx.clone(), router.clone(), router.subscribe(vec![SophisdMessagePayloadType::Ping]))),
        Box::new(SendPingsFlow::new(ctx.clone(), router.clone(), router.subscribe(vec![SophisdMessagePayloadType::Pong]))),
        Box::new(RequestHeadersFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SophisdMessagePayloadType::RequestHeaders, SophisdMessagePayloadType::RequestNextHeaders]),
            header_format,
        )),
        Box::new(RequestPruningPointProofFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SophisdMessagePayloadType::RequestPruningPointProof]),
            header_format,
        )),
        Box::new(RequestIbdChainBlockLocatorFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SophisdMessagePayloadType::RequestIbdChainBlockLocator]),
        )),
        Box::new(PruningPointAndItsAnticoneRequestsFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![
                SophisdMessagePayloadType::RequestPruningPointAndItsAnticone,
                SophisdMessagePayloadType::RequestNextPruningPointAndItsAnticoneBlocks,
            ]),
            header_format,
        )),
        Box::new(RequestPruningPointUtxoSetFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![
                SophisdMessagePayloadType::RequestPruningPointUtxoSet,
                SophisdMessagePayloadType::RequestNextPruningPointUtxoSetChunk,
            ]),
        )),
        Box::new(HandleIbdBlockRequests::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SophisdMessagePayloadType::RequestIbdBlocks]),
            header_format,
        )),
        Box::new(HandleBlockBodyRequests::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SophisdMessagePayloadType::RequestBlockBodies]),
        )),
        Box::new(HandleAntipastRequests::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SophisdMessagePayloadType::RequestAntipast]),
            header_format,
        )),
        Box::new(RelayTransactionsFlow::new(
            ctx.clone(),
            router.clone(),
            router
                .subscribe_with_capacity(vec![SophisdMessagePayloadType::InvTransactions], RelayTransactionsFlow::invs_channel_size()),
            router.subscribe_with_capacity(
                vec![SophisdMessagePayloadType::Transaction, SophisdMessagePayloadType::TransactionNotFound],
                RelayTransactionsFlow::txs_channel_size(),
            ),
        )),
        Box::new(RequestTransactionsFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SophisdMessagePayloadType::RequestTransactions]),
        )),
        Box::new(ReceiveAddressesFlow::new(ctx.clone(), router.clone(), router.subscribe(vec![SophisdMessagePayloadType::Addresses]))),
        Box::new(SendAddressesFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SophisdMessagePayloadType::RequestAddresses]),
        )),
        Box::new(RequestBlockLocatorFlow::new(
            ctx.clone(),
            router.clone(),
            router.subscribe(vec![SophisdMessagePayloadType::RequestBlockLocator]),
        )),
    ];

    let invs_route = router.subscribe_with_capacity(vec![SophisdMessagePayloadType::InvRelayBlock], ctx.block_invs_channel_size());
    let shared_invs_route = SharedIncomingRoute::new(invs_route);

    let num_relay_flows = (ctx.config.bps() as usize / 2).max(1);
    flows.extend((0..num_relay_flows).map(|_| {
        Box::new(HandleRelayInvsFlow::new(
            ctx.clone(),
            router.clone(),
            shared_invs_route.clone(),
            router.subscribe(vec![]),
            ibd_sender.clone(),
            header_format,
        )) as Box<dyn Flow>
    }));

    // The reject message is handled as a special case by the router
    // SophisdMessagePayloadType::Reject,

    // We do not register the below two messages since they are deprecated also in go-sophis
    // SophisdMessagePayloadType::BlockWithTrustedData,
    // SophisdMessagePayloadType::IbdBlockLocator,

    flows
}
