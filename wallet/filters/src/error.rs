use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FilterError {
    /// Filter wire bytes shorter than the minimum (1 compact-size byte).
    #[error("filter bytes too short: {0} bytes")]
    TooShort(usize),

    /// Compact-size length prefix indicates more elements than the
    /// remaining bytes can contain.
    #[error("declared element count {declared} exceeds plausible bytes ({remaining} after prefix)")]
    DeclaredTooLarge { declared: u64, remaining: usize },

    /// Compact-size encoding is malformed or uses a non-canonical form.
    #[error("malformed compact-size prefix")]
    MalformedCompactSize,

    /// Bitstream ended mid-codeword while decoding Golomb-Rice.
    #[error("truncated Golomb-Rice bitstream at element {0}")]
    TruncatedBitstream(u64),
}

pub type FilterResult<T> = Result<T, FilterError>;
