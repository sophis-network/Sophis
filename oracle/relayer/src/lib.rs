//! sophis-oracle-relayer (Phase 5 sub-phase 5.4).
//!
//! Library surface so integration tests in `tests/` can drive the same
//! pipeline modules the binary uses. The CLI lives in `main.rs`.

pub mod config;
pub mod daemon;
pub mod error;
pub mod pipeline;
pub mod sign;
pub mod state;
pub mod submit;
