//! J2 — TypedDataDomain + domain-separator construction.

use serde::{Deserialize, Serialize};

use crate::digest::sha3_384_truncated;
use crate::encoder::{encode_field_value, type_hash};
use crate::error::TypedDataResult;
use crate::types::{TypedField, TypedStruct, TypedValue};

/// Network discriminator byte. Mirrors `NetworkType` in `consensus-core`
/// — keep in lockstep. Frozen ABI per design §7.
pub const NETWORK_MAINNET: u8 = 0;
pub const NETWORK_TESTNET: u8 = 1;
pub const NETWORK_DEVNET: u8 = 2;
pub const NETWORK_SIMNET: u8 = 3;

/// Typed-data domain — pins a signature to a specific dApp + version
/// + chain. Optional `verifying_address` and `salt` provide additional
///   replay-isolation axes; both default to `None`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedDataDomain {
    pub name: String,
    pub version: String,
    pub network: u8,
    pub verifying_address: Option<[u8; 32]>,
    pub salt: Option<[u8; 32]>,
}

impl TypedDataDomain {
    /// Minimal constructor — name + version + network only.
    pub fn new(name: impl Into<String>, version: impl Into<String>, network: u8) -> Self {
        Self { name: name.into(), version: version.into(), network, verifying_address: None, salt: None }
    }

    pub fn with_verifying_address(mut self, addr: [u8; 32]) -> Self {
        self.verifying_address = Some(addr);
        self
    }

    pub fn with_salt(mut self, salt: [u8; 32]) -> Self {
        self.salt = Some(salt);
        self
    }

    /// Builds the synthetic `EIP712Domain`-equivalent struct schema for
    /// this domain instance. Optional fields are omitted when `None`.
    pub fn synthetic_schema(&self) -> TypedStruct {
        let mut fields = vec![
            TypedField { name: "name".into(), type_str: "string".into() },
            TypedField { name: "version".into(), type_str: "string".into() },
            TypedField { name: "network".into(), type_str: "uint8".into() },
        ];
        if self.verifying_address.is_some() {
            fields.push(TypedField { name: "verifyingAddress".into(), type_str: "address".into() });
        }
        if self.salt.is_some() {
            fields.push(TypedField { name: "salt".into(), type_str: "bytes32".into() });
        }
        TypedStruct { name: "EIP712Domain".into(), fields }
    }

    /// Builds the value vector matching `synthetic_schema`. Order MUST
    /// match exactly; the encoder iterates them positionally.
    pub fn synthetic_values(&self) -> Vec<TypedValue> {
        let mut values = vec![
            TypedValue::String(self.name.clone()),
            TypedValue::String(self.version.clone()),
            TypedValue::Uint(self.network as u128, 8),
        ];
        if let Some(addr) = self.verifying_address {
            values.push(TypedValue::Address(addr));
        }
        if let Some(salt) = self.salt {
            values.push(TypedValue::BytesFixed(salt.to_vec(), 32));
        }
        values
    }

    /// Computes the 32-byte domain separator for this domain instance.
    /// Equals `struct_hash(synthetic_schema, synthetic_values)`.
    pub fn domain_separator(&self) -> TypedDataResult<[u8; 32]> {
        let schema = self.synthetic_schema();
        let values = self.synthetic_values();
        let th = type_hash(&schema, &|_: &str| None)?;

        // Inline the struct_hash logic to keep this module's API surface
        // small. Same byte layout as `encoder::struct_hash` for non-nested
        // structs (the synthetic schema has no nested struct refs).
        let mut concat: Vec<u8> = Vec::with_capacity(32 * (1 + schema.fields.len()));
        concat.extend_from_slice(&th);
        for (i, field) in schema.fields.iter().enumerate() {
            let encoded = encode_field_value(field, &values[i], &|_: &str| None)?;
            concat.extend_from_slice(&encoded);
        }
        Ok(sha3_384_truncated(&concat))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separator_is_deterministic() {
        let d = TypedDataDomain::new("X", "1", NETWORK_DEVNET);
        let a = d.domain_separator().unwrap();
        let b = d.domain_separator().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn domain_separator_differs_with_name() {
        let d1 = TypedDataDomain::new("A", "1", NETWORK_DEVNET);
        let d2 = TypedDataDomain::new("B", "1", NETWORK_DEVNET);
        assert_ne!(d1.domain_separator().unwrap(), d2.domain_separator().unwrap());
    }

    #[test]
    fn domain_separator_differs_with_version() {
        let d1 = TypedDataDomain::new("X", "1.0", NETWORK_DEVNET);
        let d2 = TypedDataDomain::new("X", "2.0", NETWORK_DEVNET);
        assert_ne!(d1.domain_separator().unwrap(), d2.domain_separator().unwrap());
    }

    #[test]
    fn domain_separator_differs_with_network() {
        let d1 = TypedDataDomain::new("X", "1", NETWORK_MAINNET);
        let d2 = TypedDataDomain::new("X", "1", NETWORK_TESTNET);
        assert_ne!(d1.domain_separator().unwrap(), d2.domain_separator().unwrap());
    }

    #[test]
    fn verifying_address_changes_separator() {
        let d1 = TypedDataDomain::new("X", "1", NETWORK_DEVNET);
        let d2 = TypedDataDomain::new("X", "1", NETWORK_DEVNET).with_verifying_address([0xAA; 32]);
        assert_ne!(d1.domain_separator().unwrap(), d2.domain_separator().unwrap());
    }

    #[test]
    fn salt_changes_separator() {
        let d1 = TypedDataDomain::new("X", "1", NETWORK_DEVNET);
        let d2 = TypedDataDomain::new("X", "1", NETWORK_DEVNET).with_salt([0xCC; 32]);
        assert_ne!(d1.domain_separator().unwrap(), d2.domain_separator().unwrap());
    }

    #[test]
    fn synthetic_schema_has_3_fields_minimal_5_full() {
        let d_min = TypedDataDomain::new("X", "1", NETWORK_DEVNET);
        assert_eq!(d_min.synthetic_schema().fields.len(), 3);

        let d_full =
            TypedDataDomain::new("X", "1", NETWORK_DEVNET).with_verifying_address([0; 32]).with_salt([0; 32]);
        assert_eq!(d_full.synthetic_schema().fields.len(), 5);
    }

    #[test]
    fn network_constants_match_canonical_assignment() {
        assert_eq!(NETWORK_MAINNET, 0);
        assert_eq!(NETWORK_TESTNET, 1);
        assert_eq!(NETWORK_DEVNET, 2);
        assert_eq!(NETWORK_SIMNET, 3);
    }
}
