use super::error::Result;
use core::fmt::Debug;
use sophis_grpc_core::{
    ops::SophisdPayloadOps,
    protowire::{SophisdRequest, SophisdResponse},
};
use std::{sync::Arc, time::Duration};
use tokio::sync::oneshot;

pub(crate) mod id;
pub(crate) mod matcher;
pub(crate) mod queue;

pub(crate) trait Resolver: Send + Sync + Debug {
    fn register_request(&self, op: SophisdPayloadOps, request: &SophisdRequest) -> SophisdResponseReceiver;
    fn handle_response(&self, response: SophisdResponse);
    fn remove_expired_requests(&self, timeout: Duration);
}

pub(crate) type DynResolver = Arc<dyn Resolver>;

pub(crate) type SophisdResponseSender = oneshot::Sender<Result<SophisdResponse>>;
pub(crate) type SophisdResponseReceiver = oneshot::Receiver<Result<SophisdResponse>>;
