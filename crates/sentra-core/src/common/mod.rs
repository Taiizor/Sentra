//! Common utilities including mockable clock abstractions.

/// Mockable clock abstractions and system time providers.
pub mod clock;

pub use clock::{Clock, MockClock, SystemClock};
