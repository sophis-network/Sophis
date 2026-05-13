//! Phase 9 PQC-native oracle — end-to-end pipeline integration tests.
//!
//! Each scenario in [`scenarios`] composes pieces from `oracle/pqc-core`,
//! `oracle/pqc-contract`, and `oracle/pqc-publisher` to exercise the full
//! publisher → contract → indexer → consumer flow without relying on the
//! WASM runtime. The WASM glue itself (the `#[sophis_contract]`-generated
//! `validate()` export, the host `verify_dilithium` capability) is
//! covered by future sVM-side devnet smoke tests; this crate proves the
//! pure pipeline composes correctly under all the conditions SIP-11
//! pins.

#[cfg(test)]
mod scenarios;
