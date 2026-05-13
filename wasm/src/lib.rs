/*!
# Rusty Sophis WASM32 bindings

[<img alt="github" src="https://img.shields.io/badge/github-sophisnet/rusty--sophis-8da0cb?style=for-the-badge&labelColor=555555&color=8da0cb&logo=github" height="20">](https://github.com/sophis-network/Sophis/tree/main/wasm)
[<img alt="crates.io" src="https://img.shields.io/crates/v/sophis-wasm.svg?maxAge=2592000&style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/sophis-wasm)
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-sophis--wasm-56c2a5?maxAge=2592000&style=for-the-badge&logo=docs.rs" height="20">](https://docs.rs/sophis-wasm)
<img alt="license" src="https://img.shields.io/crates/l/sophis-wasm.svg?maxAge=2592000&color=6ac&style=for-the-badge&logoColor=fff" height="20">

<br>

Rusty-Sophis WASM32 bindings offer direct integration of Rust code and Rusty-Sophis
codebase within JavaScript environments such as Node.js and Web Browsers.

## Documentation

- [**Integrating with Sophis** guide](https://sophis.aspectron.org/)
- [Rust SDK documentation (**Rustdoc**)](https://docs.rs/sophis-wasm/)
- [TypeScript documentation (**JSDoc**)](https://sophis.aspectron.org/docs/)

Please note that while WASM directly binds JavaScript and Rust resources, their names on JavaScript side
are different from their name in Rust as they conform to the 'camelCase' convention in JavaScript and
to the 'snake_case' convention in Rust.

## Interfaces

The APIs are currently separated into the following groups (this will be expanded in the future):

- **Consensus Client API** — Bindings for primitives related to transactions.
- **RPC API** — [RPC interface bindings](sophis_wrpc_wasm::client) for the Sophis node using WebSocket (wRPC) connections.
- **Wallet SDK** — API for async core wallet processing tasks.
- **Wallet API** — A rust implementation of the fully-featured wallet usable in the native Rust, Browser or NodeJs and Bun environments.

## NPM Modules

For JavaScript / TypeScript environments, there are two
available NPM modules:

- <https://www.npmjs.com/package/sophis>
- <https://www.npmjs.com/package/sophis-wasm>

The `sophis-wasm` module is a pure WASM32 module that includes
the entire wallet framework, but does not support RPC due to an absence
of a native WebSocket in NodeJs environment, while
the `sophis` module includes `websocket` package dependency simulating
the W3C WebSocket and due to this supports RPC.

NOTE: for security reasons it is always recommended to build WASM SDK from source or
download pre-built redistributables from releases or development builds.

## Examples

JavaScript examples for using this framework can be found at:
<https://github.com/sophis-network/Sophis/tree/main/wasm/nodejs>

## WASM32 Binaries

For pre-built browser-compatible WASM32 redistributables of this
framework please see the releases section of the Rusty Sophis
repository at <https://github.com/sophis-network/Sophis/releases>.

## Development Builds

The latest development builds from <https://sophis.aspectron.org/nightly/downloads/>.
Development builds typically contain fixes and improvements that are not yet available in
stable releases. Additional information can be found at
<https://aspectron.org/en/projects/sophis-wasm.html>.

## Using RPC

No special handling is required to use the RPC client
in **Browser** or **Bun** environments due to the fact that
these environments provide native WebSocket support.

**NODEJS:** If you are building from source, to use WASM RPC client
in the NodeJS environment, you need to introduce a global W3C WebSocket
object before loading the WASM32 library (to simulate the browser behavior).
You can the [WebSocket](https://www.npmjs.com/package/websocket)
module that offers W3C WebSocket compatibility and is compatible
with Sophis RPC implementation.

You can use the following shims:

```js
// WebSocket
globalThis.WebSocket = require('websocket').w3cwebsocket;
```

## Loading in a Web App

```html
<html>
    <head>
        <script type="module">
            import * as sophis_wasm from './sophis/sophis-wasm.js';
            (async () => {
                const sophis = await sophis_wasm.default('./sophis/sophis-wasm_bg.wasm');
                // ...
            })();
        </script>
    </head>
    <body></body>
</html>
```

## Loading in a Node.js App

```javascript
// W3C WebSocket module shim
// this is provided by NPM `sophis` module and is only needed
// if you are building WASM libraries for NodeJS from source
// globalThis.WebSocket = require('websocket').w3cwebsocket;

let {RpcClient,Encoding,initConsolePanicHook} = require('./sophis-rpc');

// enabling console panic hooks allows WASM to print panic details to console
// initConsolePanicHook();
// enabling browser panic hooks will create a full-page DIV with panic details
// this is useful for mobile devices where console is not available
// initBrowserPanicHook();

// if port is not specified, it will use the default port for the specified network
const rpc = new RpcClient("127.0.0.1", Encoding.Borsh, "testnet-10");
const rpc = new RpcClient({
    url : "127.0.0.1",
    encoding : Encoding.Borsh,
    networkId : "testnet-10"
});


(async () => {
    try {
        await rpc.connect();
        let info = await rpc.getInfo();
        console.log(info);
    } finally {
        await rpc.disconnect();
    }
})();
```

For more details, please follow the [**Integrating with Sophis**](https://sophis.aspectron.org/) guide.

*/

#![allow(unused_imports)]

#[cfg(all(
    any(feature = "wasm32-sdk", feature = "wasm32-rpc", feature = "wasm32-core"),
    not(target_arch = "wasm32")
))]
compile_error!(
    "`sophis-wasm` crate for WASM32 target must be built with `--features wasm32-sdk|wasm32-rpc|wasm32-core`"
);

mod version;
pub use version::*;

cfg_if::cfg_if! {

    if #[cfg(feature = "wasm32-sdk")] {

        pub use sophis_addresses::{Address, Version as AddressVersion};
        pub use sophis_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput};
        pub use sophis_pow::wasm::*;
        pub use sophis_txscript::wasm::*;

        pub mod rpc {
            //! Sophis RPC interface
            //!

            pub mod messages {
                //! Sophis RPC messages
                pub use sophis_rpc_core::model::message::*;
            }
            pub use sophis_rpc_core::api::rpc::RpcApi;
            pub use sophis_rpc_core::wasm::message::*;

            pub use sophis_wrpc_wasm::client::*;
            pub use sophis_wrpc_wasm::resolver::*;
            pub use sophis_wrpc_wasm::notify::*;
        }

        pub use sophis_consensus_wasm::*;

    } else if #[cfg(feature = "wasm32-core")] {

        pub use sophis_addresses::{Address, Version as AddressVersion};
        pub use sophis_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput};
        pub use sophis_pow::wasm::*;
        pub use sophis_txscript::wasm::*;

        pub mod rpc {
            //! Sophis RPC interface
            //!

            pub mod messages {
                //! Sophis RPC messages
                pub use sophis_rpc_core::model::message::*;
            }
            pub use sophis_rpc_core::api::rpc::RpcApi;
            pub use sophis_rpc_core::wasm::message::*;

            pub use sophis_wrpc_wasm::client::*;
            pub use sophis_wrpc_wasm::resolver::*;
            pub use sophis_wrpc_wasm::notify::*;
        }

        pub use sophis_consensus_wasm::*;

    } else if #[cfg(feature = "wasm32-rpc")] {

        pub use sophis_rpc_core::api::rpc::RpcApi;
        pub use sophis_rpc_core::wasm::message::*;
        pub use sophis_rpc_core::wasm::message::IPingRequest;
        pub use sophis_wrpc_wasm::client::*;
        pub use sophis_wrpc_wasm::resolver::*;
        pub use sophis_wrpc_wasm::notify::*;
        pub use sophis_wasm_core::types::*;

    }
}
