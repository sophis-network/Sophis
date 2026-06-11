//! J2 — canonical type-string + struct-hash + field encoding.
//!
//! Pure helpers; no I/O, no signing. The two entry points the rest of
//! the crate (and downstream callers) use are:
//!   * `type_hash(schema, lookup)` — 32-byte hash of the canonical
//!     type-string for `schema` plus its sorted referenced struct strings
//!   * `struct_hash(schema, values, lookup)` — 32-byte hash of
//!     `type_hash || encode_field(...) || ...`
//!
//! `lookup` is a closure `&str -> Option<&TypedStruct>` so callers can
//! supply nested struct schemas without allocating a HashMap.

use std::collections::BTreeMap;

use crate::digest::sha3_384_truncated;
use crate::error::{TypedDataError, TypedDataResult};
use crate::types::{TypedField, TypedStruct, TypedValue};

/// Helper used by `compute_typed_digest` to build a `lookup` closure
/// from a flat slice of schemas.
pub fn lookup_schema<'a>(all: &'a [&'a TypedStruct], name: &str) -> Option<&'a TypedStruct> {
    all.iter().copied().find(|s| s.name == name)
}

/// Validates the field/type strings used in a schema. Run on every
/// schema involved in encoding. Catches commas / spaces that would
/// break the canonical type-string parser.
fn validate_schema(schema: &TypedStruct) -> TypedDataResult<()> {
    for f in &schema.fields {
        if f.name.contains(',') {
            return Err(TypedDataError::FieldNameContainsComma(f.name.clone()));
        }
        if f.name.contains(' ') {
            return Err(TypedDataError::FieldNameContainsSpace(f.name.clone()));
        }
        if f.type_str.contains(',') {
            return Err(TypedDataError::TypeStringContainsComma(f.type_str.clone()));
        }
    }
    Ok(())
}

/// Walks the schema's reachable struct references and returns their
/// names in alphabetical order, excluding the schema itself.
fn referenced_struct_names<'a>(
    schema: &'a TypedStruct,
    lookup: &dyn Fn(&str) -> Option<&'a TypedStruct>,
) -> TypedDataResult<Vec<String>> {
    let mut acc = BTreeMap::<String, ()>::new();
    walk_struct_refs(schema, lookup, &mut acc, schema.name.as_str())?;
    Ok(acc.into_keys().collect())
}

/// Recursive DFS that adds every struct name reachable from `schema`
/// (other than `skip`) into `acc`.
fn walk_struct_refs<'a>(
    schema: &'a TypedStruct,
    lookup: &dyn Fn(&str) -> Option<&'a TypedStruct>,
    acc: &mut BTreeMap<String, ()>,
    skip: &str,
) -> TypedDataResult<()> {
    for field in &schema.fields {
        let inner_struct_name = inner_struct_type(&field.type_str);
        if let Some(name) = inner_struct_name {
            if name == skip {
                continue;
            }
            if acc.contains_key(name) {
                continue;
            }
            let nested = lookup(name).ok_or_else(|| TypedDataError::NestedStructUndefined(name.to_string()))?;
            acc.insert(name.to_string(), ());
            // Recurse into the nested schema with the same `skip`.
            walk_struct_refs(nested, lookup, acc, skip)?;
        }
    }
    Ok(())
}

/// If `type_str` references a struct (including arrays of structs),
/// returns the bare struct name. Otherwise returns None.
fn inner_struct_type(type_str: &str) -> Option<&str> {
    // Strip [..] suffixes recursively.
    let mut t = type_str;
    while let Some(open) = t.rfind('[') {
        let close = t[open..].find(']')?;
        if open + close + 1 != t.len() {
            return None;
        }
        t = &t[..open];
    }
    if is_primitive_type(t) { None } else { Some(t) }
}

/// Returns true if `type_str` (without array suffix) is a primitive
/// type recognised by the encoder.
fn is_primitive_type(t: &str) -> bool {
    matches!(t, "bool" | "address" | "bytes" | "string")
        || (t.starts_with("uint") && t.len() > 4 && t[4..].parse::<usize>().is_ok())
        || (t.starts_with("int") && t.len() > 3 && t[3..].parse::<usize>().is_ok())
        || (t.starts_with("bytes") && t.len() > 5 && t[5..].parse::<usize>().is_ok())
}

/// Builds the canonical type-string for `schema` (no nested references).
pub fn primary_type_string(schema: &TypedStruct) -> String {
    let mut s = String::with_capacity(64);
    s.push_str(&schema.name);
    s.push('(');
    for (i, f) in schema.fields.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&f.type_str);
        s.push(' ');
        s.push_str(&f.name);
    }
    s.push(')');
    s
}

/// Builds the canonical type-string with appended sorted nested-struct
/// strings. This is the input to `type_hash`.
pub fn canonical_type_string<'a>(
    schema: &'a TypedStruct,
    lookup: &dyn Fn(&str) -> Option<&'a TypedStruct>,
) -> TypedDataResult<String> {
    validate_schema(schema)?;
    let mut s = primary_type_string(schema);
    let refs = referenced_struct_names(schema, lookup)?;
    for name in &refs {
        let nested = lookup(name).ok_or_else(|| TypedDataError::NestedStructUndefined(name.clone()))?;
        validate_schema(nested)?;
        s.push_str(&primary_type_string(nested));
    }
    Ok(s)
}

/// 32-byte hash of the canonical type string.
pub fn type_hash<'a>(schema: &'a TypedStruct, lookup: &dyn Fn(&str) -> Option<&'a TypedStruct>) -> TypedDataResult<[u8; 32]> {
    let s = canonical_type_string(schema, lookup)?;
    Ok(sha3_384_truncated(s.as_bytes()))
}

/// 32-byte hash of `type_hash || encode_field(...) || ...`. Caller MUST
/// pass `values.len() == schema.fields.len()`.
pub fn struct_hash<'a>(
    schema: &'a TypedStruct,
    values: &[TypedValue],
    lookup: &dyn Fn(&str) -> Option<&'a TypedStruct>,
) -> TypedDataResult<[u8; 32]> {
    if values.len() != schema.fields.len() {
        return Err(TypedDataError::ArityMismatch { schema_len: schema.fields.len(), value_len: values.len() });
    }
    let th = type_hash(schema, lookup)?;
    let mut buf: Vec<u8> = Vec::with_capacity(32 * (1 + schema.fields.len()));
    buf.extend_from_slice(&th);
    for (i, field) in schema.fields.iter().enumerate() {
        let encoded = encode_field_value(field, &values[i], lookup)?;
        buf.extend_from_slice(&encoded);
    }
    Ok(sha3_384_truncated(&buf))
}

/// 32-byte encoding of a single field value, per design §3.1.
pub fn encode_field_value<'a>(
    field: &TypedField,
    value: &TypedValue,
    lookup: &dyn Fn(&str) -> Option<&'a TypedStruct>,
) -> TypedDataResult<[u8; 32]> {
    let t = field.type_str.as_str();

    // Array types end with `]`.
    if t.ends_with(']') {
        let TypedValue::Array(elements) = value else {
            return Err(TypedDataError::TypeMismatch {
                index: 0,
                declared: t.to_string(),
                actual: value.discriminant_str().to_string(),
            });
        };
        // Compute element type (strip the [..] suffix).
        let open = t.rfind('[').expect("checked ends_with(']')");
        let element_type = &t[..open];
        let mut concat: Vec<u8> = Vec::with_capacity(32 * elements.len());
        for elem in elements {
            // Synthesise a per-element field with the element type. The
            // field name is irrelevant for value encoding (only the type
            // matters at this layer).
            let elem_field = TypedField { name: String::new(), type_str: element_type.to_string() };
            let enc = encode_field_value(&elem_field, elem, lookup)?;
            concat.extend_from_slice(&enc);
        }
        return Ok(sha3_384_truncated(&concat));
    }

    // Primitive / struct dispatch.
    match (t, value) {
        ("bool", TypedValue::Bool(b)) => {
            let mut out = [0u8; 32];
            out[31] = if *b { 1 } else { 0 };
            Ok(out)
        }
        ("address", TypedValue::Address(a)) => Ok(*a),
        ("bytes", TypedValue::Bytes(b)) => Ok(sha3_384_truncated(b)),
        ("string", TypedValue::String(s)) => Ok(sha3_384_truncated(s.as_bytes())),
        _ if t.starts_with("uint") && t.len() > 4 => {
            let bits: usize = t[4..].parse().map_err(|_| TypedDataError::UnrecognisedType(t.to_string()))?;
            if bits == 0 || bits > 256 || !bits.is_multiple_of(8) {
                return Err(TypedDataError::InvalidIntBitWidth(bits));
            }
            let TypedValue::Uint(v, w) = value else {
                return Err(TypedDataError::TypeMismatch {
                    index: 0,
                    declared: t.to_string(),
                    actual: value.discriminant_str().to_string(),
                });
            };
            if (*w as usize) != bits {
                return Err(TypedDataError::InvalidIntBitWidth(*w as usize));
            }
            // F-37 — range-check the value against the declared bit width so an
            // out-of-range value is rejected, not silently encoded. (bits >= 128:
            // any u128 already fits in the low 128 bits of the 256-bit word.)
            if bits < 128 && *v >= (1u128 << bits) {
                return Err(TypedDataError::ValueOutOfRange(bits));
            }
            let mut out = [0u8; 32];
            out[16..32].copy_from_slice(&v.to_be_bytes());
            Ok(out)
        }
        _ if t.starts_with("int") && t.len() > 3 => {
            let bits: usize = t[3..].parse().map_err(|_| TypedDataError::UnrecognisedType(t.to_string()))?;
            if bits == 0 || bits > 256 || !bits.is_multiple_of(8) {
                return Err(TypedDataError::InvalidIntBitWidth(bits));
            }
            let TypedValue::Int(v, w) = value else {
                return Err(TypedDataError::TypeMismatch {
                    index: 0,
                    declared: t.to_string(),
                    actual: value.discriminant_str().to_string(),
                });
            };
            if (*w as usize) != bits {
                return Err(TypedDataError::InvalidIntBitWidth(*w as usize));
            }
            // F-37 — signed range-check: -2^(bits-1) <= v <= 2^(bits-1)-1.
            // (bits >= 128: any i128 fits in a 128-bit two's-complement word.)
            if bits < 128 {
                let max = (1i128 << (bits - 1)) - 1;
                let min = -(1i128 << (bits - 1));
                if *v < min || *v > max {
                    return Err(TypedDataError::ValueOutOfRange(bits));
                }
            }
            // Sign-extend the i128 into a 32-byte big-endian word.
            let mut out = if *v < 0 { [0xFFu8; 32] } else { [0u8; 32] };
            out[16..32].copy_from_slice(&v.to_be_bytes());
            Ok(out)
        }
        _ if t.starts_with("bytes") && t.len() > 5 => {
            let n: usize = t[5..].parse().map_err(|_| TypedDataError::UnrecognisedType(t.to_string()))?;
            if !(1..=32).contains(&n) {
                return Err(TypedDataError::InvalidBytesNWidth(n));
            }
            let TypedValue::BytesFixed(b, w) = value else {
                return Err(TypedDataError::TypeMismatch {
                    index: 0,
                    declared: t.to_string(),
                    actual: value.discriminant_str().to_string(),
                });
            };
            if (*w as usize) != n {
                return Err(TypedDataError::InvalidBytesNWidth(*w as usize));
            }
            if b.len() != n {
                return Err(TypedDataError::BytesNWidthMismatch { declared: n, actual: b.len() });
            }
            let mut out = [0u8; 32];
            // Left-pad: bytes go into the LOW-order positions, padding HIGH.
            // (EIP-712 left-pads bytesN, meaning the value occupies the
            // first N bytes of the 32-byte slot.)
            out[..n].copy_from_slice(b);
            Ok(out)
        }
        // Struct reference
        _ => {
            // Caller's `value` must be a Struct with matching schema_name.
            let TypedValue::Struct { schema_name, values } = value else {
                return Err(TypedDataError::TypeMismatch {
                    index: 0,
                    declared: t.to_string(),
                    actual: value.discriminant_str().to_string(),
                });
            };
            if schema_name != t {
                return Err(TypedDataError::TypeMismatch {
                    index: 0,
                    declared: t.to_string(),
                    actual: format!("Struct({schema_name})"),
                });
            }
            let nested = lookup(t).ok_or_else(|| TypedDataError::NestedStructUndefined(t.to_string()))?;
            struct_hash(nested, values, lookup)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_lookup<'a>() -> impl Fn(&str) -> Option<&'a TypedStruct> {
        |_| None
    }

    #[test]
    fn primary_type_string_canonical_format() {
        let s = TypedStruct {
            name: "Mail".into(),
            fields: vec![
                TypedField { name: "from".into(), type_str: "address".into() },
                TypedField { name: "to".into(), type_str: "address".into() },
                TypedField { name: "contents".into(), type_str: "string".into() },
            ],
        };
        assert_eq!(primary_type_string(&s), "Mail(address from,address to,string contents)");
    }

    #[test]
    fn type_hash_no_nested_refs() {
        let s = TypedStruct { name: "Mail".into(), fields: vec![TypedField { name: "x".into(), type_str: "uint256".into() }] };
        let h = type_hash(&s, &no_lookup()).unwrap();
        // Sanity: deterministic and 32 bytes.
        assert_eq!(h.len(), 32);
        let h2 = type_hash(&s, &no_lookup()).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn canonical_type_string_includes_nested_refs_sorted() {
        let outer = TypedStruct {
            name: "Outer".into(),
            fields: vec![
                TypedField { name: "z".into(), type_str: "Inner".into() },
                TypedField { name: "a".into(), type_str: "Apple".into() },
            ],
        };
        let inner = TypedStruct { name: "Inner".into(), fields: vec![TypedField { name: "x".into(), type_str: "uint256".into() }] };
        let apple = TypedStruct { name: "Apple".into(), fields: vec![TypedField { name: "y".into(), type_str: "uint8".into() }] };
        let lookup = |name: &str| -> Option<&TypedStruct> {
            match name {
                "Inner" => Some(&inner),
                "Apple" => Some(&apple),
                _ => None,
            }
        };
        let s = canonical_type_string(&outer, &lookup).unwrap();
        // Nested refs sorted alphabetically: Apple before Inner.
        assert_eq!(s, "Outer(Inner z,Apple a)Apple(uint8 y)Inner(uint256 x)");
    }

    #[test]
    fn struct_hash_arity_mismatch_errors() {
        let s = TypedStruct { name: "M".into(), fields: vec![TypedField { name: "x".into(), type_str: "uint256".into() }] };
        let err = struct_hash(&s, &[], &no_lookup()).unwrap_err();
        assert_eq!(err, TypedDataError::ArityMismatch { schema_len: 1, value_len: 0 });
    }

    #[test]
    fn struct_hash_type_mismatch_errors() {
        let s = TypedStruct { name: "M".into(), fields: vec![TypedField { name: "x".into(), type_str: "uint256".into() }] };
        let err = struct_hash(&s, &[TypedValue::Bool(true)], &no_lookup()).unwrap_err();
        assert!(matches!(err, TypedDataError::TypeMismatch { .. }));
    }

    #[test]
    fn encode_bool_pads_correctly() {
        let f = TypedField { name: "b".into(), type_str: "bool".into() };
        let t = encode_field_value(&f, &TypedValue::Bool(true), &no_lookup()).unwrap();
        assert_eq!(t[31], 1);
        assert!(t[..31].iter().all(|&x| x == 0));
        let f0 = encode_field_value(&f, &TypedValue::Bool(false), &no_lookup()).unwrap();
        assert_eq!(f0, [0u8; 32]);
    }

    #[test]
    fn encode_address_passes_through_32_bytes() {
        let f = TypedField { name: "a".into(), type_str: "address".into() };
        let t = encode_field_value(&f, &TypedValue::Address([0xCD; 32]), &no_lookup()).unwrap();
        assert_eq!(t, [0xCD; 32]);
    }

    #[test]
    fn encode_uint256_big_endian_low_16_bytes() {
        let f = TypedField { name: "x".into(), type_str: "uint256".into() };
        let t = encode_field_value(&f, &TypedValue::Uint(0x12345u128, 256), &no_lookup()).unwrap();
        // Upper 16 bytes zero; lower 16 bytes = 0x12345 in big-endian
        assert!(t[..16].iter().all(|&x| x == 0));
        let mut expected_lower = [0u8; 16];
        expected_lower[12..].copy_from_slice(&0x12345u32.to_be_bytes());
        assert_eq!(&t[16..], &expected_lower[..]);
    }

    #[test]
    fn f37_value_out_of_declared_width_is_rejected() {
        // uint8 = 256 overflows 8 bits → rejected, not silently encoded.
        let f = TypedField { name: "x".into(), type_str: "uint8".into() };
        let r = encode_field_value(&f, &TypedValue::Uint(256, 8), &no_lookup());
        assert!(matches!(r, Err(TypedDataError::ValueOutOfRange(8))), "got {r:?}");
        // 255 fits.
        assert!(encode_field_value(&f, &TypedValue::Uint(255, 8), &no_lookup()).is_ok());
        // int8 = 128 overflows the signed range [-128, 127] → rejected; 127 fits.
        let g = TypedField { name: "y".into(), type_str: "int8".into() };
        assert!(matches!(encode_field_value(&g, &TypedValue::Int(128, 8), &no_lookup()), Err(TypedDataError::ValueOutOfRange(8))));
        assert!(encode_field_value(&g, &TypedValue::Int(127, 8), &no_lookup()).is_ok());
        assert!(encode_field_value(&g, &TypedValue::Int(-128, 8), &no_lookup()).is_ok());
    }

    #[test]
    fn encode_int_negative_sign_extends() {
        let f = TypedField { name: "s".into(), type_str: "int256".into() };
        let t = encode_field_value(&f, &TypedValue::Int(-1, 256), &no_lookup()).unwrap();
        // -1 as int256 = all 0xFF
        assert_eq!(t, [0xFFu8; 32]);
    }

    #[test]
    fn encode_dynamic_bytes_hashes_value() {
        let f = TypedField { name: "b".into(), type_str: "bytes".into() };
        let t = encode_field_value(&f, &TypedValue::Bytes(b"hello".to_vec()), &no_lookup()).unwrap();
        assert_eq!(t, sha3_384_truncated(b"hello"));
    }

    #[test]
    fn encode_string_hashes_utf8_bytes() {
        let f = TypedField { name: "s".into(), type_str: "string".into() };
        let t = encode_field_value(&f, &TypedValue::String("café".into()), &no_lookup()).unwrap();
        assert_eq!(t, sha3_384_truncated("café".as_bytes()));
    }

    #[test]
    fn encode_bytes32_left_padded_value_in_low_positions() {
        let f = TypedField { name: "b".into(), type_str: "bytes32".into() };
        let t = encode_field_value(&f, &TypedValue::BytesFixed(vec![0xAA; 32], 32), &no_lookup()).unwrap();
        assert_eq!(t, [0xAA; 32]);
    }

    #[test]
    fn encode_bytes4_padded_high_bytes_zero() {
        let f = TypedField { name: "b".into(), type_str: "bytes4".into() };
        let t = encode_field_value(&f, &TypedValue::BytesFixed(vec![1, 2, 3, 4], 4), &no_lookup()).unwrap();
        let mut expected = [0u8; 32];
        expected[..4].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(t, expected);
    }

    #[test]
    fn encode_dynamic_array_hashes_concatenation() {
        let f = TypedField { name: "xs".into(), type_str: "uint256[]".into() };
        let xs = TypedValue::Array(vec![TypedValue::Uint(1, 256), TypedValue::Uint(2, 256)]);
        let t = encode_field_value(&f, &xs, &no_lookup()).unwrap();
        // Hand-compute: concat of two 32-byte big-endian uints, then SHA3-384[..32]
        let mut concat = Vec::with_capacity(64);
        let mut e1 = [0u8; 32];
        e1[31] = 1;
        let mut e2 = [0u8; 32];
        e2[31] = 2;
        concat.extend_from_slice(&e1);
        concat.extend_from_slice(&e2);
        assert_eq!(t, sha3_384_truncated(&concat));
    }

    #[test]
    fn encode_nested_struct_uses_struct_hash() {
        let outer = TypedStruct { name: "Outer".into(), fields: vec![TypedField { name: "i".into(), type_str: "Inner".into() }] };
        let inner = TypedStruct { name: "Inner".into(), fields: vec![TypedField { name: "x".into(), type_str: "uint256".into() }] };
        let lookup = |name: &str| -> Option<&TypedStruct> { (name == "Inner").then_some(&inner) };
        let outer_values = vec![TypedValue::Struct { schema_name: "Inner".into(), values: vec![TypedValue::Uint(42, 256)] }];
        let h = struct_hash(&outer, &outer_values, &lookup).unwrap();
        assert_eq!(h.len(), 32);
        // Re-derive Inner's struct_hash and confirm its 32 bytes appear in
        // Outer's preimage.
        let inner_h = struct_hash(&inner, &[TypedValue::Uint(42, 256)], &lookup).unwrap();
        let outer_th = type_hash(&outer, &lookup).unwrap();
        let mut preimage = Vec::with_capacity(64);
        preimage.extend_from_slice(&outer_th);
        preimage.extend_from_slice(&inner_h);
        let expected = sha3_384_truncated(&preimage);
        assert_eq!(h, expected);
    }

    #[test]
    fn schema_field_name_with_comma_rejected() {
        let s = TypedStruct { name: "Bad".into(), fields: vec![TypedField { name: "a,b".into(), type_str: "uint256".into() }] };
        let err = type_hash(&s, &no_lookup()).unwrap_err();
        assert!(matches!(err, TypedDataError::FieldNameContainsComma(_)));
    }

    #[test]
    fn nested_struct_undefined_rejected() {
        let s = TypedStruct { name: "X".into(), fields: vec![TypedField { name: "i".into(), type_str: "MissingType".into() }] };
        let err = type_hash(&s, &no_lookup()).unwrap_err();
        assert!(matches!(err, TypedDataError::NestedStructUndefined(name) if name == "MissingType"));
    }
}
