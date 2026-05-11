// Sophis is Dilithium-only at the transaction layer. The original Kaspa-era
// BIP-32 secp256k1 extended-key derivation paths were removed in the
// pre-mainnet PQC cleanup sweep; this crate retains only the pure BIP-39
// mnemonic stack plus the BIP-32 metadata types (DerivationPath,
// KeyFingerprint, ChildNumber, ExtendedKeyAttrs, Prefix) that downstream
// crates use for key-path bookkeeping without invoking any EC math.

mod address_type;
mod attrs;
mod child_number;
mod derivation_path;
mod error;
mod mnemonic;
pub mod types;

pub mod wasm {
    //! WASM bindings for the `bip32` module.
    pub use crate::mnemonic::{Language, Mnemonic, WordCount};
}

pub use address_type::AddressType;
pub use attrs::ExtendedKeyAttrs;
pub use child_number::ChildNumber;
pub use derivation_path::DerivationPath;
pub use mnemonic::{Language, Mnemonic, WordCount};
pub use types::*;
