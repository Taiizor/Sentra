//! Common utilities including mockable clock abstractions.

/// Mockable clock abstractions and system time providers.
pub mod clock;
/// Cryptographic hashing primitives.
pub mod crypto;

pub use clock::{Clock, MockClock, SystemClock};
pub use crypto::{Sha256Stream, sha256_bytes, sha256_digest, sha256_prefixed};
