# Sophis WASM SDK

An integration wrapper around [`sophis-wasm`](https://www.npmjs.com/package/sophis-wasm) module that uses [`websocket`](https://www.npmjs.com/package/websocket) W3C adaptor for WebSocket communication.

This is a Node.js module that provides bindings to the Sophis WASM SDK strictly for use in the Node.js environment. The web browser version of the SDK is available as part of official SDK releases at [https://github.com/sophisnet/rusty-sophis/releases](https://github.com/sophisnet/rusty-sophis/releases)

## Usage

Sophis NPM module exports include all WASM32 bindings.
```javascript
const sophis = require('sophis');
console.log(sophis.version());
```

## Documentation

Documentation is available at [https://sophis.aspectron.org/docs/](https://sophis.aspectron.org/docs/)


## Building from source & Examples

SDK examples as well as information on building the project from source can be found at [https://github.com/sophisnet/rusty-sophis/tree/master/wasm](https://github.com/sophisnet/rusty-sophis/tree/master/wasm)

## Releases

Official releases as well as releases for Web Browsers are available at [https://github.com/sophisnet/rusty-sophis/releases](https://github.com/sophisnet/rusty-sophis/releases).

Nightly / developer builds are available at: [https://aspectron.org/en/projects/sophis-wasm.html](https://aspectron.org/en/projects/sophis-wasm.html)

