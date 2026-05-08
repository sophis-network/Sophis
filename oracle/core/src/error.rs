use thiserror::Error;

#[derive(Debug, Error)]
pub enum OracleError {
    #[error("ed25519 signature verification failed for publisher {publisher}")]
    InvalidSignature { publisher: String },

    #[error("price update is stale: publish_time={publish_time}, now={now}, max_age={max_age}")]
    Stale { publish_time: u64, now: u64, max_age: u64 },

    #[error("price {price} is outside accepted range [{min}, {max}]")]
    OutOfRange { price: i64, min: i64, max: i64 },

    #[error("publisher {got} is not the registered singleton {expected}")]
    PublisherMismatch { got: String, expected: String },

    #[error("borsh serialization error: {0}")]
    Borsh(#[from] std::io::Error),
}
