use std::sync::atomic::{AtomicU64, Ordering};

use crate::domain::time::TimestampUtc;

/// Abstraction for time sources, enabling deterministic and non-flaky tests.
pub trait Clock: Send + Sync {
    /// Returns the current UTC timestamp.
    fn now(&self) -> TimestampUtc;
}

/// Standard system clock reading UTC time from the operating system.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl SystemClock {
    /// Creates a new system clock instance.
    pub const fn new() -> Self {
        Self
    }
}

impl Clock for SystemClock {
    fn now(&self) -> TimestampUtc {
        TimestampUtc::now()
    }
}

/// A deterministic mock clock whose time can be explicitly controlled in unit tests.
#[derive(Debug)]
pub struct MockClock {
    millis: AtomicU64,
}

impl MockClock {
    /// Creates a mock clock initialized at the given timestamp.
    pub fn new(initial: TimestampUtc) -> Self {
        Self {
            millis: AtomicU64::new(initial.as_epoch_millis()),
        }
    }

    /// Sets the current timestamp to an explicit value.
    pub fn set_time(&self, time: TimestampUtc) {
        self.millis.store(time.as_epoch_millis(), Ordering::SeqCst);
    }

    /// Advances the clock forward by the given number of seconds.
    pub fn advance_seconds(&self, seconds: u64) {
        self.millis
            .fetch_add(seconds.saturating_mul(1000), Ordering::SeqCst);
    }

    /// Advances the clock forward by the given number of milliseconds.
    pub fn advance_millis(&self, millis: u64) {
        self.millis.fetch_add(millis, Ordering::SeqCst);
    }
}

impl Clock for MockClock {
    fn now(&self) -> TimestampUtc {
        TimestampUtc::from_epoch_millis(self.millis.load(Ordering::SeqCst))
    }
}

impl<T: ?Sized + Clock> Clock for std::sync::Arc<T> {
    fn now(&self) -> TimestampUtc {
        (**self).now()
    }
}

impl<T: ?Sized + Clock> Clock for &T {
    fn now(&self) -> TimestampUtc {
        (**self).now()
    }
}
