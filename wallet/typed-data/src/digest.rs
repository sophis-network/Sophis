//! J2 — final-digest construction.
//!
//! `compute_typed_digest(domain, struct, values, supplemental_schemas)`
//! returns the 32-byte hash that gets signed by Dilithium.

use sha3::{Digest, Sha3_384};

use crate::domain::TypedDataDomain;
use crate::encoder::{lookup_schema, struct_hash};
use crate::error::TypedDataResult;
use crate::types::{TypedStruct, TypedValue};

/// Sophis typed-signing prefix bytes. Frozen ABI per design §7. `0x73`
/// is `'s'` (Sophis); `0x01` is the version byte. Two bytes total.
pub const TYPED_SIGNING_PREFIX: [u8; 2] = [0x73, 0x01];

/// Convenience helper: compute SHA3-384(`bytes`) and return the first
/// 32 bytes. Used everywhere in the typed-data spec.
pub fn sha3_384_truncated(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_384::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// Computes the 32-byte typed-data digest that gets signed by Dilithium.
///
/// `supplemental_schemas` MUST include any nested struct schemas
/// referenced (transitively) from `schema.fields`. The order doesn't
/// matter; the encoder sorts them alphabetically.
pub fn compute_typed_digest(
    domain: &TypedDataDomain,
    schema: &TypedStruct,
    values: &[TypedValue],
    supplemental_schemas: &[TypedStruct],
) -> TypedDataResult<[u8; 32]> {
    // Build a lookup that includes the top-level schema so nested-struct
    // resolution can find it if a recursive type names it.
    let mut all_schemas: Vec<&TypedStruct> = Vec::with_capacity(supplemental_schemas.len() + 1);
    all_schemas.push(schema);
    for s in supplemental_schemas {
        all_schemas.push(s);
    }
    let lookup = |name: &str| lookup_schema(&all_schemas, name);

    let domain_sep = domain.domain_separator()?;
    let msg_hash = struct_hash(schema, values, &lookup)?;

    let mut hasher = Sha3_384::new();
    hasher.update(TYPED_SIGNING_PREFIX);
    hasher.update(domain_sep);
    hasher.update(msg_hash);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::NETWORK_DEVNET;
    use crate::types::TypedField;

    #[test]
    fn prefix_bytes_are_frozen_abi() {
        assert_eq!(TYPED_SIGNING_PREFIX, [0x73, 0x01]);
    }

    #[test]
    fn empty_string_hash_matches_canonical_sha3_384() {
        // SHA3-384("") test vector: 0c63a75b...c25 (full 48 bytes per FIPS 202)
        // We assert the truncated 32 bytes via a fresh sha3 call rather than
        // hard-coding the bytes — this catches the "we forgot to truncate"
        // class of bugs.
        let actual = sha3_384_truncated(b"");
        let mut hasher = Sha3_384::new();
        hasher.update(b"");
        let full = hasher.finalize();
        assert_eq!(&actual[..], &full[..32]);
    }

    #[test]
    fn compute_typed_digest_simple_message() {
        let domain = TypedDataDomain::new("MyDApp", "1.0", NETWORK_DEVNET);
        let schema = TypedStruct {
            name: "Mail".into(),
            fields: vec![
                TypedField { name: "from".into(), type_str: "address".into() },
                TypedField { name: "to".into(), type_str: "address".into() },
                TypedField { name: "contents".into(), type_str: "string".into() },
            ],
        };
        let values = vec![
            TypedValue::Address([0xAA; 32]),
            TypedValue::Address([0xBB; 32]),
            TypedValue::String("gm".into()),
        ];
        let digest = compute_typed_digest(&domain, &schema, &values, &[]).unwrap();
        assert_eq!(digest.len(), 32);
        // Determinism: two calls produce the same bytes.
        let again = compute_typed_digest(&domain, &schema, &values, &[]).unwrap();
        assert_eq!(digest, again);
    }

    #[test]
    fn digest_changes_with_domain() {
        let schema = TypedStruct {
            name: "M".into(),
            fields: vec![TypedField { name: "x".into(), type_str: "uint256".into() }],
        };
        let values = vec![TypedValue::Uint(42, 256)];
        let d1 = TypedDataDomain::new("DApp", "1.0", NETWORK_DEVNET);
        let d2 = TypedDataDomain::new("DApp", "2.0", NETWORK_DEVNET); // version bumped
        let digest1 = compute_typed_digest(&d1, &schema, &values, &[]).unwrap();
        let digest2 = compute_typed_digest(&d2, &schema, &values, &[]).unwrap();
        assert_ne!(digest1, digest2, "version bump must change digest");
    }

    #[test]
    fn digest_changes_with_message_value() {
        let domain = TypedDataDomain::new("DApp", "1.0", NETWORK_DEVNET);
        let schema = TypedStruct {
            name: "M".into(),
            fields: vec![TypedField { name: "x".into(), type_str: "uint256".into() }],
        };
        let v1 = vec![TypedValue::Uint(1, 256)];
        let v2 = vec![TypedValue::Uint(2, 256)];
        let d1 = compute_typed_digest(&domain, &schema, &v1, &[]).unwrap();
        let d2 = compute_typed_digest(&domain, &schema, &v2, &[]).unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn digest_includes_prefix_in_preimage() {
        // Compute a digest, then recompute by hand and compare. Catches
        // "we forgot the prefix" bugs.
        let domain = TypedDataDomain::new("X", "1", NETWORK_DEVNET);
        let schema = TypedStruct {
            name: "M".into(),
            fields: vec![TypedField { name: "x".into(), type_str: "uint256".into() }],
        };
        let values = vec![TypedValue::Uint(7, 256)];
        let actual = compute_typed_digest(&domain, &schema, &values, &[]).unwrap();

        let domain_sep = domain.domain_separator().unwrap();
        let lookup = |_: &str| None;
        let msg_hash = struct_hash(&schema, &values, &lookup).unwrap();
        let mut hasher = Sha3_384::new();
        hasher.update(TYPED_SIGNING_PREFIX);
        hasher.update(domain_sep);
        hasher.update(msg_hash);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&hasher.finalize()[..32]);
        assert_eq!(actual, expected);
    }
}
