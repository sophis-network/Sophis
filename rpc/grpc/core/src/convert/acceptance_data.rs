use crate::protowire::{self};
use crate::{from, try_from};
use sophis_rpc_core::RpcError;

// ----------------------------------------------------------------------------
// rpc_core to protowire
// ----------------------------------------------------------------------------

from!(item: &sophis_rpc_core::RpcDataVerbosityLevel, protowire::RpcDataVerbosityLevel, {
    match item {
        sophis_rpc_core::RpcDataVerbosityLevel::None => protowire::RpcDataVerbosityLevel::None,
        sophis_rpc_core::RpcDataVerbosityLevel::Low => protowire::RpcDataVerbosityLevel::Low,
        sophis_rpc_core::RpcDataVerbosityLevel::High => protowire::RpcDataVerbosityLevel::High,
        sophis_rpc_core::RpcDataVerbosityLevel::Full => protowire::RpcDataVerbosityLevel::Full,
    }
});

// ----------------------------------------------------------------------------
// protowire to rpc_core
// ----------------------------------------------------------------------------

try_from!(item: &protowire::RpcDataVerbosityLevel, sophis_rpc_core::RpcDataVerbosityLevel,  {
    match item {
        protowire::RpcDataVerbosityLevel::None => sophis_rpc_core::RpcDataVerbosityLevel::None,
        protowire::RpcDataVerbosityLevel::Low => sophis_rpc_core::RpcDataVerbosityLevel::Low,
        protowire::RpcDataVerbosityLevel::High => sophis_rpc_core::RpcDataVerbosityLevel::High,
        protowire::RpcDataVerbosityLevel::Full => sophis_rpc_core::RpcDataVerbosityLevel::Full
    }
});
