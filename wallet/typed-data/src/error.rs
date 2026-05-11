use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TypedDataError {
    /// Caller supplied a values vector whose length does not match the
    /// number of fields in the schema.
    #[error("schema/value arity mismatch: schema has {schema_len} fields, got {value_len} values")]
    ArityMismatch { schema_len: usize, value_len: usize },

    /// Caller supplied a value whose discriminant does not match the
    /// type string declared in the schema for that position.
    #[error("type mismatch at field index {index}: schema declares `{declared}`, got `{actual}`")]
    TypeMismatch { index: usize, declared: String, actual: String },

    /// Field name contains a comma — would break canonical type-string parsing.
    #[error("field name `{0}` contains a comma; commas are forbidden")]
    FieldNameContainsComma(String),

    /// Field name contains a space — would break canonical type-string parsing.
    #[error("field name `{0}` contains a space; spaces are forbidden")]
    FieldNameContainsSpace(String),

    /// Type string contains a comma — would break canonical type-string parsing.
    #[error("type string `{0}` contains a comma; commas are forbidden")]
    TypeStringContainsComma(String),

    /// Caller referenced a struct type by name but did not provide its
    /// schema in the supplemental schemas list.
    #[error("nested struct schema `{0}` not provided")]
    NestedStructUndefined(String),

    /// Inline `bytesN` width is outside the legal range 1..=32.
    #[error("invalid bytesN width: {0} (must be 1..=32)")]
    InvalidBytesNWidth(usize),

    /// `bytesN` value did not match its declared width.
    #[error("bytesN width mismatch: declared bytes{declared}, got {actual} bytes")]
    BytesNWidthMismatch { declared: usize, actual: usize },

    /// `uintN` / `intN` width is not a multiple of 8 in 8..=256.
    #[error("invalid integer bit width: {0} (must be multiple of 8 in 8..=256)")]
    InvalidIntBitWidth(usize),

    /// Unrecognised type string (could not parse as primitive, array, or
    /// known struct reference).
    #[error("unrecognised type string `{0}`")]
    UnrecognisedType(String),
}

pub type TypedDataResult<T> = Result<T, TypedDataError>;
