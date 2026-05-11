use crate::protowire::{SophisdRequest, SophisdResponse, sophisd_request};

impl From<sophisd_request::Payload> for SophisdRequest {
    fn from(item: sophisd_request::Payload) -> Self {
        SophisdRequest { id: 0, payload: Some(item) }
    }
}

impl AsRef<SophisdRequest> for SophisdRequest {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsRef<SophisdResponse> for SophisdResponse {
    fn as_ref(&self) -> &Self {
        self
    }
}

pub mod sophisd_request_convert {
    use crate::protowire::*;
    use sophis_rpc_core::{RpcError, RpcResult};

    impl_into_sophisd_request!(Shutdown);
    impl_into_sophisd_request!(SubmitBlock);
    impl_into_sophisd_request!(GetBlockTemplate);
    impl_into_sophisd_request!(GetBlock);
    impl_into_sophisd_request!(GetInfo);

    impl_into_sophisd_request!(GetCurrentNetwork);
    impl_into_sophisd_request!(GetPeerAddresses);
    impl_into_sophisd_request!(GetSink);
    impl_into_sophisd_request!(GetMempoolEntry);
    impl_into_sophisd_request!(GetMempoolEntries);
    impl_into_sophisd_request!(GetConnectedPeerInfo);
    impl_into_sophisd_request!(AddPeer);
    impl_into_sophisd_request!(SubmitTransaction);
    impl_into_sophisd_request!(SubmitTransactionReplacement);
    impl_into_sophisd_request!(GetSubnetwork);
    impl_into_sophisd_request!(GetVirtualChainFromBlock);
    impl_into_sophisd_request!(GetBlocks);
    impl_into_sophisd_request!(GetBlockCount);
    impl_into_sophisd_request!(GetBlockDagInfo);
    impl_into_sophisd_request!(ResolveFinalityConflict);
    impl_into_sophisd_request!(GetHeaders);
    impl_into_sophisd_request!(GetUtxosByAddresses);
    impl_into_sophisd_request!(GetBalanceByAddress);
    impl_into_sophisd_request!(GetBalancesByAddresses);
    impl_into_sophisd_request!(GetSinkBlueScore);
    impl_into_sophisd_request!(Ban);
    impl_into_sophisd_request!(Unban);
    impl_into_sophisd_request!(EstimateNetworkHashesPerSecond);
    impl_into_sophisd_request!(GetMempoolEntriesByAddresses);
    impl_into_sophisd_request!(GetCoinSupply);
    impl_into_sophisd_request!(Ping);
    impl_into_sophisd_request!(GetMetrics);
    impl_into_sophisd_request!(GetConnections);
    impl_into_sophisd_request!(GetSystemInfo);
    impl_into_sophisd_request!(GetServerInfo);
    impl_into_sophisd_request!(GetSyncStatus);
    impl_into_sophisd_request!(GetDaaScoreTimestampEstimate);
    impl_into_sophisd_request!(GetFeeEstimate);
    impl_into_sophisd_request!(GetFeeEstimateExperimental);
    impl_into_sophisd_request!(GetCurrentBlockColor);
    impl_into_sophisd_request!(GetUtxoReturnAddress);
    impl_into_sophisd_request!(GetVirtualChainFromBlockV2);

    // Phase 6 — Data Availability (sub-fase 6.4.b)
    impl_into_sophisd_request!(GetDaPayload);
    impl_into_sophisd_request!(GetDaBundle);
    impl_into_sophisd_request!(GetDaCarriersByBlock);
    impl_into_sophisd_request!(GetDaCarriersByDomain);
    impl_into_sophisd_request!(GetDaPayloadStatus);

    // J4 — sVM Event Logs (sub-fase J4.5.b)
    impl_into_sophisd_request!(GetLogs);

    // L3 — Block commitment levels (sub-fase L3)
    impl_into_sophisd_request!(GetBlockCommitment);

    // K2 — Compact Block Filters (sub-fase K2)
    impl_into_sophisd_request!(GetBlockFilter);
    impl_into_sophisd_request!(GetBlockFilterHeader);

    // J5 — Light client SPV Merkle proof (sub-fase J5)
    impl_into_sophisd_request!(GetTxMerkleProof);

    // J8 — Pruning info (sub-fase J8)
    impl_into_sophisd_request!(GetPruningInfo);

    impl_into_sophisd_request!(NotifyBlockAdded);
    impl_into_sophisd_request!(NotifyNewBlockTemplate);
    impl_into_sophisd_request!(NotifyUtxosChanged);
    impl_into_sophisd_request!(NotifyPruningPointUtxoSetOverride);
    impl_into_sophisd_request!(NotifyFinalityConflict);
    impl_into_sophisd_request!(NotifyVirtualDaaScoreChanged);
    impl_into_sophisd_request!(NotifyVirtualChainChanged);
    impl_into_sophisd_request!(NotifySinkBlueScoreChanged);

    macro_rules! impl_into_sophisd_request {
        ($name:tt) => {
            paste::paste! {
                impl_into_sophisd_request_ex!(sophis_rpc_core::[<$name Request>],[<$name RequestMessage>],[<$name Request>]);
            }
        };
    }

    use impl_into_sophisd_request;

    macro_rules! impl_into_sophisd_request_ex {
        // ($($core_struct:ident)::+, $($protowire_struct:ident)::+, $($variant:ident)::+) => {
        ($core_struct:path, $protowire_struct:ident, $variant:ident) => {
            // ----------------------------------------------------------------------------
            // rpc_core to protowire
            // ----------------------------------------------------------------------------

            impl From<&$core_struct> for sophisd_request::Payload {
                fn from(item: &$core_struct) -> Self {
                    Self::$variant(item.into())
                }
            }

            impl From<&$core_struct> for SophisdRequest {
                fn from(item: &$core_struct) -> Self {
                    Self { id: 0, payload: Some(item.into()) }
                }
            }

            impl From<$core_struct> for sophisd_request::Payload {
                fn from(item: $core_struct) -> Self {
                    Self::$variant((&item).into())
                }
            }

            impl From<$core_struct> for SophisdRequest {
                fn from(item: $core_struct) -> Self {
                    Self { id: 0, payload: Some((&item).into()) }
                }
            }

            // ----------------------------------------------------------------------------
            // protowire to rpc_core
            // ----------------------------------------------------------------------------

            impl TryFrom<&sophisd_request::Payload> for $core_struct {
                type Error = RpcError;
                fn try_from(item: &sophisd_request::Payload) -> RpcResult<Self> {
                    if let sophisd_request::Payload::$variant(request) = item {
                        request.try_into()
                    } else {
                        Err(RpcError::MissingRpcFieldError("Payload".to_string(), stringify!($variant).to_string()))
                    }
                }
            }

            impl TryFrom<&SophisdRequest> for $core_struct {
                type Error = RpcError;
                fn try_from(item: &SophisdRequest) -> RpcResult<Self> {
                    item.payload
                        .as_ref()
                        .ok_or(RpcError::MissingRpcFieldError("SophisRequest".to_string(), "Payload".to_string()))?
                        .try_into()
                }
            }

            impl From<$protowire_struct> for SophisdRequest {
                fn from(item: $protowire_struct) -> Self {
                    Self { id: 0, payload: Some(sophisd_request::Payload::$variant(item)) }
                }
            }

            impl From<$protowire_struct> for sophisd_request::Payload {
                fn from(item: $protowire_struct) -> Self {
                    sophisd_request::Payload::$variant(item)
                }
            }
        };
    }
    use impl_into_sophisd_request_ex;
}

pub mod sophisd_response_convert {
    use crate::protowire::*;
    use sophis_rpc_core::{RpcError, RpcResult};

    impl_into_sophisd_response!(Shutdown);
    impl_into_sophisd_response!(SubmitBlock);
    impl_into_sophisd_response!(GetBlockTemplate);
    impl_into_sophisd_response!(GetBlock);
    impl_into_sophisd_response!(GetInfo);
    impl_into_sophisd_response!(GetCurrentNetwork);

    impl_into_sophisd_response!(GetPeerAddresses);
    impl_into_sophisd_response!(GetSink);
    impl_into_sophisd_response!(GetMempoolEntry);
    impl_into_sophisd_response!(GetMempoolEntries);
    impl_into_sophisd_response!(GetConnectedPeerInfo);
    impl_into_sophisd_response!(AddPeer);
    impl_into_sophisd_response!(SubmitTransaction);
    impl_into_sophisd_response!(SubmitTransactionReplacement);
    impl_into_sophisd_response!(GetSubnetwork);
    impl_into_sophisd_response!(GetVirtualChainFromBlock);
    impl_into_sophisd_response!(GetBlocks);
    impl_into_sophisd_response!(GetBlockCount);
    impl_into_sophisd_response!(GetBlockDagInfo);
    impl_into_sophisd_response!(ResolveFinalityConflict);
    impl_into_sophisd_response!(GetHeaders);
    impl_into_sophisd_response!(GetUtxosByAddresses);
    impl_into_sophisd_response!(GetBalanceByAddress);
    impl_into_sophisd_response!(GetBalancesByAddresses);
    impl_into_sophisd_response!(GetSinkBlueScore);
    impl_into_sophisd_response!(Ban);
    impl_into_sophisd_response!(Unban);
    impl_into_sophisd_response!(EstimateNetworkHashesPerSecond);
    impl_into_sophisd_response!(GetMempoolEntriesByAddresses);
    impl_into_sophisd_response!(GetCoinSupply);
    impl_into_sophisd_response!(Ping);
    impl_into_sophisd_response!(GetMetrics);
    impl_into_sophisd_response!(GetConnections);
    impl_into_sophisd_response!(GetSystemInfo);
    impl_into_sophisd_response!(GetServerInfo);
    impl_into_sophisd_response!(GetSyncStatus);
    impl_into_sophisd_response!(GetDaaScoreTimestampEstimate);
    impl_into_sophisd_response!(GetFeeEstimate);
    impl_into_sophisd_response!(GetFeeEstimateExperimental);
    impl_into_sophisd_response!(GetCurrentBlockColor);
    impl_into_sophisd_response!(GetUtxoReturnAddress);
    impl_into_sophisd_response!(GetVirtualChainFromBlockV2);

    // Phase 6 — Data Availability (sub-fase 6.4.b)
    impl_into_sophisd_response!(GetDaPayload);
    impl_into_sophisd_response!(GetDaBundle);
    impl_into_sophisd_response!(GetDaCarriersByBlock);
    impl_into_sophisd_response!(GetDaCarriersByDomain);
    impl_into_sophisd_response!(GetDaPayloadStatus);

    // J4 — sVM Event Logs (sub-fase J4.5.b)
    impl_into_sophisd_response!(GetLogs);

    // L3 — Block commitment levels (sub-fase L3)
    impl_into_sophisd_response!(GetBlockCommitment);

    // K2 — Compact Block Filters (sub-fase K2)
    impl_into_sophisd_response!(GetBlockFilter);
    impl_into_sophisd_response!(GetBlockFilterHeader);

    // J5 — Light client SPV Merkle proof (sub-fase J5)
    impl_into_sophisd_response!(GetTxMerkleProof);

    // J8 — Pruning info (sub-fase J8)
    impl_into_sophisd_response!(GetPruningInfo);

    impl_into_sophisd_notify_response!(NotifyBlockAdded);
    impl_into_sophisd_notify_response!(NotifyNewBlockTemplate);
    impl_into_sophisd_notify_response!(NotifyUtxosChanged);
    impl_into_sophisd_notify_response!(NotifyPruningPointUtxoSetOverride);
    impl_into_sophisd_notify_response!(NotifyFinalityConflict);
    impl_into_sophisd_notify_response!(NotifyVirtualDaaScoreChanged);
    impl_into_sophisd_notify_response!(NotifyVirtualChainChanged);
    impl_into_sophisd_notify_response!(NotifySinkBlueScoreChanged);

    impl_into_sophisd_notify_response!(NotifyUtxosChanged, StopNotifyingUtxosChanged);
    impl_into_sophisd_notify_response!(NotifyPruningPointUtxoSetOverride, StopNotifyingPruningPointUtxoSetOverride);

    macro_rules! impl_into_sophisd_response {
        ($name:tt) => {
            paste::paste! {
                impl_into_sophisd_response_ex!(sophis_rpc_core::[<$name Response>],[<$name ResponseMessage>],[<$name Response>]);
            }
        };
        ($core_name:tt, $protowire_name:tt) => {
            paste::paste! {
                impl_into_sophisd_response_base!(sophis_rpc_core::[<$core_name Response>],[<$protowire_name ResponseMessage>],[<$protowire_name Response>]);
            }
        };
    }
    use impl_into_sophisd_response;

    macro_rules! impl_into_sophisd_response_base {
        ($core_struct:path, $protowire_struct:ident, $variant:ident) => {
            // ----------------------------------------------------------------------------
            // rpc_core to protowire
            // ----------------------------------------------------------------------------

            impl From<RpcResult<$core_struct>> for $protowire_struct {
                fn from(item: RpcResult<$core_struct>) -> Self {
                    item.as_ref().map_err(|x| (*x).clone()).into()
                }
            }

            impl From<RpcError> for $protowire_struct {
                fn from(item: RpcError) -> Self {
                    let x: RpcResult<&$core_struct> = Err(item);
                    x.into()
                }
            }

            impl From<$protowire_struct> for sophisd_response::Payload {
                fn from(item: $protowire_struct) -> Self {
                    sophisd_response::Payload::$variant(item)
                }
            }

            impl From<$protowire_struct> for SophisdResponse {
                fn from(item: $protowire_struct) -> Self {
                    Self { id: 0, payload: Some(sophisd_response::Payload::$variant(item)) }
                }
            }
        };
    }
    use impl_into_sophisd_response_base;

    macro_rules! impl_into_sophisd_response_ex {
        ($core_struct:path, $protowire_struct:ident, $variant:ident) => {
            // ----------------------------------------------------------------------------
            // rpc_core to protowire
            // ----------------------------------------------------------------------------

            impl From<RpcResult<&$core_struct>> for sophisd_response::Payload {
                fn from(item: RpcResult<&$core_struct>) -> Self {
                    sophisd_response::Payload::$variant(item.into())
                }
            }

            impl From<RpcResult<&$core_struct>> for SophisdResponse {
                fn from(item: RpcResult<&$core_struct>) -> Self {
                    Self { id: 0, payload: Some(item.into()) }
                }
            }

            impl From<RpcResult<$core_struct>> for sophisd_response::Payload {
                fn from(item: RpcResult<$core_struct>) -> Self {
                    sophisd_response::Payload::$variant(item.into())
                }
            }

            impl From<RpcResult<$core_struct>> for SophisdResponse {
                fn from(item: RpcResult<$core_struct>) -> Self {
                    Self { id: 0, payload: Some(item.into()) }
                }
            }

            impl_into_sophisd_response_base!($core_struct, $protowire_struct, $variant);

            // ----------------------------------------------------------------------------
            // protowire to rpc_core
            // ----------------------------------------------------------------------------

            impl TryFrom<&sophisd_response::Payload> for $core_struct {
                type Error = RpcError;
                fn try_from(item: &sophisd_response::Payload) -> RpcResult<Self> {
                    if let sophisd_response::Payload::$variant(response) = item {
                        response.try_into()
                    } else {
                        Err(RpcError::MissingRpcFieldError("Payload".to_string(), stringify!($variant).to_string()))
                    }
                }
            }

            impl TryFrom<&SophisdResponse> for $core_struct {
                type Error = RpcError;
                fn try_from(item: &SophisdResponse) -> RpcResult<Self> {
                    item.payload
                        .as_ref()
                        .ok_or(RpcError::MissingRpcFieldError("SophisResponse".to_string(), "Payload".to_string()))?
                        .try_into()
                }
            }
        };
    }
    use impl_into_sophisd_response_ex;

    macro_rules! impl_into_sophisd_notify_response {
        ($name:tt) => {
            impl_into_sophisd_response!($name);

            paste::paste! {
                impl_into_sophisd_notify_response_ex!(sophis_rpc_core::[<$name Response>],[<$name ResponseMessage>]);
            }
        };
        ($core_name:tt, $protowire_name:tt) => {
            impl_into_sophisd_response!($core_name, $protowire_name);

            paste::paste! {
                impl_into_sophisd_notify_response_ex!(sophis_rpc_core::[<$core_name Response>],[<$protowire_name ResponseMessage>]);
            }
        };
    }
    use impl_into_sophisd_notify_response;

    macro_rules! impl_into_sophisd_notify_response_ex {
        ($($core_struct:ident)::+, $protowire_struct:ident) => {
            // ----------------------------------------------------------------------------
            // rpc_core to protowire
            // ----------------------------------------------------------------------------

            impl<T> From<Result<(), T>> for $protowire_struct
            where
                T: Into<RpcError>,
            {
                fn from(item: Result<(), T>) -> Self {
                    item
                        .map(|_| $($core_struct)::+{})
                        .map_err(|err| err.into()).into()
                }
            }

        };
    }
    use impl_into_sophisd_notify_response_ex;
}
