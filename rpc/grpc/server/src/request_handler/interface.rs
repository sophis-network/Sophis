use super::method::{DropFn, Method, MethodTrait, RoutingPolicy};
use crate::{
    connection::Connection,
    connection_handler::ServerContext,
    error::{GrpcServerError, GrpcServerResult},
};
use sophis_grpc_core::{
    ops::SophisdPayloadOps,
    protowire::{SophisdRequest, SophisdResponse},
};
use std::fmt::Debug;
use std::{collections::HashMap, sync::Arc};

pub type SophisdMethod = Method<ServerContext, Connection, SophisdRequest, SophisdResponse>;
pub type DynSophisdMethod = Arc<dyn MethodTrait<ServerContext, Connection, SophisdRequest, SophisdResponse>>;
pub type SophisdDropFn = DropFn<SophisdRequest, SophisdResponse>;
pub type SophisdRoutingPolicy = RoutingPolicy<SophisdRequest, SophisdResponse>;

/// An interface providing methods implementations and a fallback "not implemented" method
/// actually returning a message with a "not implemented" error.
///
/// The interface can provide a method clone for every [`SophisdPayloadOps`] variant for later
/// processing of related requests.
///
/// It is also possible to directly let the interface itself process a request by invoking
/// the `call()` method.
pub struct Interface {
    server_ctx: ServerContext,
    methods: HashMap<SophisdPayloadOps, DynSophisdMethod>,
    method_not_implemented: DynSophisdMethod,
}

impl Interface {
    pub fn new(server_ctx: ServerContext) -> Self {
        let method_not_implemented = Arc::new(Method::new(|_, _, sophisd_request: SophisdRequest| {
            Box::pin(async move {
                match sophisd_request.payload {
                    Some(ref request) => Ok(SophisdResponse {
                        id: sophisd_request.id,
                        payload: Some(
                            SophisdPayloadOps::from(request).to_error_response(GrpcServerError::MethodNotImplemented.into()),
                        ),
                    }),
                    None => Err(GrpcServerError::InvalidRequestPayload),
                }
            })
        }));
        Self { server_ctx, methods: Default::default(), method_not_implemented }
    }

    pub fn method(&mut self, op: SophisdPayloadOps, method: SophisdMethod) {
        let method: DynSophisdMethod = Arc::new(method);
        if self.methods.insert(op, method).is_some() {
            panic!("RPC method {op:?} is declared multiple times")
        }
    }

    pub fn replace_method(&mut self, op: SophisdPayloadOps, method: SophisdMethod) {
        let method: DynSophisdMethod = Arc::new(method);
        let _ = self.methods.insert(op, method);
    }

    pub fn set_method_properties(
        &mut self,
        op: SophisdPayloadOps,
        tasks: usize,
        queue_size: usize,
        routing_policy: SophisdRoutingPolicy,
    ) {
        self.methods.entry(op).and_modify(|x| {
            let method: Method<ServerContext, Connection, SophisdRequest, SophisdResponse> =
                Method::with_properties(x.method_fn(), tasks, queue_size, routing_policy);
            let method: Arc<dyn MethodTrait<ServerContext, Connection, SophisdRequest, SophisdResponse>> = Arc::new(method);
            *x = method;
        });
    }

    pub async fn call(
        &self,
        op: &SophisdPayloadOps,
        connection: Connection,
        request: SophisdRequest,
    ) -> GrpcServerResult<SophisdResponse> {
        self.methods.get(op).unwrap_or(&self.method_not_implemented).call(self.server_ctx.clone(), connection, request).await
    }

    pub fn get_method(&self, op: &SophisdPayloadOps) -> DynSophisdMethod {
        self.methods.get(op).unwrap_or(&self.method_not_implemented).clone()
    }
}

impl Debug for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interface").finish()
    }
}
