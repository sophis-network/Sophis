use serde::{Deserialize, Serialize};

/// One field of a typed struct schema. `name` is the human label that
/// wallets render to users; `type_str` is the EIP-712-style type
/// identifier (`"address"`, `"uint256"`, `"string"`, `"Mail"`, `"uint256[]"`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedField {
    pub name: String,
    pub type_str: String,
}

/// A named, ordered struct schema.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedStruct {
    pub name: String,
    pub fields: Vec<TypedField>,
}

/// A concrete value matching one slot of a `TypedStruct.fields` entry.
///
/// The discriminant must agree with the field's `type_str`:
/// - `Bool` ↔ `"bool"`
/// - `Uint(_, w)` ↔ `"uint{w}"`
/// - `Int(_, w)` ↔ `"int{w}"`
/// - `BytesFixed(_, w)` ↔ `"bytes{w}"`
/// - `Address(_)` ↔ `"address"`
/// - `Bytes(_)` ↔ `"bytes"`
/// - `String(_)` ↔ `"string"`
/// - `Array(_)` ↔ `"T[]"` or `"T[N]"`
/// - `Struct { ... }` ↔ struct reference (e.g. `"Mail"`)
///
/// Mismatches surface as `TypedDataError::TypeMismatch` at encode time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypedValue {
    Bool(bool),
    /// Unsigned integer + bit width (8, 16, …, 256). Value MUST fit in
    /// the declared width (caller responsibility).
    Uint(u128, u16),
    /// Signed integer + bit width (8, 16, …, 256). Stored as i128; values
    /// > 128 bits are NOT representable in this v1.
    Int(i128, u16),
    /// Fixed-width bytes. Length MUST match `width`.
    BytesFixed(Vec<u8>, u8),
    /// 32-byte Sophis address (P2PKH-Dilithium hash or sVM contract id).
    Address([u8; 32]),
    /// Dynamic-length raw bytes.
    Bytes(Vec<u8>),
    /// UTF-8 string.
    String(String),
    /// Homogeneous array. The element type-string is on the schema side
    /// (`"T[]"` or `"T[N]"`); element values live here.
    Array(Vec<TypedValue>),
    /// Nested struct. `schema_name` MUST match a `TypedStruct.name` provided
    /// to the encoder via the supplemental-schemas list.
    Struct {
        schema_name: String,
        values: Vec<TypedValue>,
    },
}

impl TypedValue {
    /// String representation of the discriminant, used in error messages.
    pub fn discriminant_str(&self) -> &'static str {
        match self {
            TypedValue::Bool(_) => "Bool",
            TypedValue::Uint(_, _) => "Uint",
            TypedValue::Int(_, _) => "Int",
            TypedValue::BytesFixed(_, _) => "BytesFixed",
            TypedValue::Address(_) => "Address",
            TypedValue::Bytes(_) => "Bytes",
            TypedValue::String(_) => "String",
            TypedValue::Array(_) => "Array",
            TypedValue::Struct { .. } => "Struct",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_field_round_trips_serde_json() {
        let f = TypedField { name: "from".into(), type_str: "address".into() };
        let s = serde_json::to_string(&f).unwrap();
        let d: TypedField = serde_json::from_str(&s).unwrap();
        assert_eq!(f, d);
    }

    #[test]
    fn typed_struct_round_trips_serde_json() {
        let s = TypedStruct {
            name: "Mail".into(),
            fields: vec![
                TypedField { name: "from".into(), type_str: "address".into() },
                TypedField { name: "contents".into(), type_str: "string".into() },
            ],
        };
        let j = serde_json::to_string(&s).unwrap();
        let d: TypedStruct = serde_json::from_str(&j).unwrap();
        assert_eq!(s, d);
    }

    #[test]
    fn typed_value_discriminants_are_distinct() {
        let vs = vec![
            TypedValue::Bool(true),
            TypedValue::Uint(0, 256),
            TypedValue::Int(0, 256),
            TypedValue::BytesFixed(vec![0; 4], 4),
            TypedValue::Address([0; 32]),
            TypedValue::Bytes(vec![]),
            TypedValue::String("".into()),
            TypedValue::Array(vec![]),
            TypedValue::Struct { schema_name: "X".into(), values: vec![] },
        ];
        let mut names: Vec<&str> = vs.iter().map(|v| v.discriminant_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 9);
    }
}
