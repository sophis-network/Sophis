//! Ed25519 verification AIR (sub-phases 5.2.1.4 through 5.2.1.7).
//!
//! Stack of chips:
//!
//! - `point`         (5.2.1.4): Edwards twisted curve point addition in
//!                              extended `(X, Y, Z, T)` coordinates with
//!                              `xy = T/Z`. Witness shipped; AIR chip
//!                              deferred to 5.2.1.4.air.
//! - `scalar_mul`    (5.2.1.5): 256-bit scalar multiplication via the
//!                              double-and-add algorithm (windowed for
//!                              concrete savings). Composes `point` 256
//!                              times for doubles plus ~128 for adds.
//! - `decompress`    (5.2.1.6): Recover `x` from a compressed point's `y`
//!                              coordinate plus the sign bit. Requires one
//!                              modular square root via the standard
//!                              `(p+3)/8` exponentiation.
//! - `verify`        (5.2.1.7): The top-level routine implementing
//!                              `[s]B == R + [H(R || A || M)]A`. Composes
//!                              `decompress` (for R and A), `scalar_mul`
//!                              (for `[s]B` and `[h]A`), and `point` (for
//!                              the final addition + equality check).

pub mod decompress;
pub mod decompress_air;
pub mod decompress_air_chunked;
pub mod point;
pub mod point_add_air;
pub mod point_add_air_chunked;
pub mod scalar_mul;
pub mod scalar_mul_air;
pub mod scalar_mul_air_chunked;
pub mod verify;
pub mod verify_air;
pub mod verify_air_chunked;
