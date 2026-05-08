//! `sophis_lint` — custom Clippy-style lints for Sophis smart contracts.
//!
//! Three lints are registered:
//!
//! | Lint | Level | What it catches |
//! |---|---|---|
//! | `SOPHIS_NO_FLOAT` | deny | `f32`/`f64` types and float literals |
//! | `SOPHIS_NO_UNSAFE` | deny | `unsafe` blocks, `unsafe fn`, `unsafe impl` |
//! | `SOPHIS_NO_UNCHECKED_ARITH` | deny | Integer `+`, `-`, `*`, `/`, `%` without checked methods |
//!
//! # Usage
//!
//! ```text
//! cargo install cargo-dylint dylint-link
//! cargo dylint sophis_lint --manifest-path svm/lint/Cargo.toml -- \
//!     --manifest-path path/to/my-contract/Cargo.toml
//! ```
//!
//! Or via the workspace alias:
//! ```text
//! cargo sophis-lint
//! ```
#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_ast;
extern crate rustc_hir;
extern crate rustc_lint;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

mod no_float;
mod no_unchecked_arith;
mod no_unsafe;

dylint_linting::dylint_library!();

/// Entry point called by the dylint driver to register all lints.
#[allow(clippy::no_mangle_with_rust_abi)]
#[no_mangle]
pub fn register_lints(sess: &rustc_session::Session, lint_store: &mut rustc_lint::LintStore) {
    no_float::register(sess, lint_store);
    no_unsafe::register(sess, lint_store);
    no_unchecked_arith::register(sess, lint_store);
}
