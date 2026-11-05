use std::{
    fmt,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::domain::error::DomainError;

/// An immutable, type-safe UTC timestamp represented as milliseconds since the Unix epoch.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimestampUtc {
    epoch_millis: u64,
}

impl TimestampUtc {
    /// Creates a timestamp representing the current system UTC time.
    pub fn now() -> Self {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        Self {
            epoch_millis: duration.as_millis() as u64,
        }
    }

    /// Creates a timestamp from milliseconds since the Unix epoch.
    pub const fn from_epoch_millis(millis: u64) -> Self {
        Self {
            epoch_millis: millis,
        }
    }

    /// Creates a timestamp from seconds since the Unix epoch.
    pub const fn from_epoch_secs(secs: u64) -> Self {
        Self {
            epoch_millis: secs.saturating_mul(1000),
        }
    }

    /// Returns the milliseconds since the Unix epoch.
    pub const fn as_epoch_millis(&self) -> u64 {
        self.epoch_millis
    }

    /// Returns the seconds since the Unix epoch.
    pub const fn as_epoch_secs(&self) -> u64 {
        self.epoch_millis / 1000
    }

    /// Returns whether this timestamp is before or equal to the given `other` timestamp.
    pub fn is_expired_at(&self, other: TimestampUtc) -> bool {
        self.epoch_millis <= other.epoch_millis
    }

    /// Returns a new timestamp with the specified seconds added.
    pub fn add_seconds(&self, secs: u64) -> Self {
        Self {
            epoch_millis: self.epoch_millis.saturating_add(secs.saturating_mul(1000)),
        }
    }

    /// Parses an ISO 8601 / RFC 3339 UTC string into a TimestampUtc.
    pub fn from_rfc3339(s: &str) -> Result<Self, DomainError> {
        Self::from_str(s)
    }

    /// Formats the timestamp as an ISO 8601 / RFC 3339 UTC string (e.g. `2026-11-05T20:15:00.000Z`).
    pub fn to_rfc3339(&self) -> String {
        let total_secs = self.epoch_millis / 1000;
        let millis_part = self.epoch_millis % 1000;

        let days_since_epoch = total_secs / 86400;
        let day_secs = total_secs % 86400;

        let hours = day_secs / 3600;
        let minutes = (day_secs % 3600) / 60;
        let seconds = day_secs % 60;

        let (year, month, day) = days_to_date(days_since_epoch);

        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            year, month, day, hours, minutes, seconds, millis_part
        )
    }
}

impl fmt::Display for TimestampUtc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_rfc3339())
    }
}

impl fmt::Debug for TimestampUtc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TimestampUtc({})", self.to_rfc3339())
    }
}

impl FromStr for TimestampUtc {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(DomainError::InvalidTimestamp(
                "empty timestamp string".to_string(),
            ));
        }

        // Parse YYYY-MM-DDTHH:MM:SS[.mmm]Z
        let parts: Vec<&str> = trimmed.split('T').collect();
        if parts.len() != 2 {
            return Err(DomainError::InvalidTimestamp(format!(
                "invalid RFC 3339 format, missing 'T': {trimmed}"
            )));
        }

        let date_parts: Vec<&str> = parts[0].split('-').collect();
        if date_parts.len() != 3 {
            return Err(DomainError::InvalidTimestamp(format!(
                "invalid date part: {}",
                parts[0]
            )));
        }

        let year: i32 = date_parts[0]
            .parse()
            .map_err(|_| DomainError::InvalidTimestamp("invalid year".to_string()))?;
        let month: u32 = date_parts[1]
            .parse()
            .map_err(|_| DomainError::InvalidTimestamp("invalid month".to_string()))?;
        let day: u32 = date_parts[2]
            .parse()
            .map_err(|_| DomainError::InvalidTimestamp("invalid day".to_string()))?;

        let time_str = parts[1].trim_end_matches('Z');
        let time_parts: Vec<&str> = time_str.split(':').collect();
        if time_parts.len() != 3 {
            return Err(DomainError::InvalidTimestamp(format!(
                "invalid time part: {}",
                parts[1]
            )));
        }

        let hour: u32 = time_parts[0]
            .parse()
            .map_err(|_| DomainError::InvalidTimestamp("invalid hour".to_string()))?;
        let minute: u32 = time_parts[1]
            .parse()
            .map_err(|_| DomainError::InvalidTimestamp("invalid minute".to_string()))?;

        let sec_parts: Vec<&str> = time_parts[2].split('.').collect();
        let second: u32 = sec_parts[0]
            .parse()
            .map_err(|_| DomainError::InvalidTimestamp("invalid second".to_string()))?;
        let millis: u32 = if sec_parts.len() > 1 {
            let m_str = sec_parts[1];
            let normalized = if m_str.len() >= 3 { &m_str[..3] } else { m_str };
            normalized
                .parse::<u32>()
                .map_err(|_| DomainError::InvalidTimestamp("invalid subsecond".to_string()))?
                * match normalized.len() {
                    1 => 100,
                    2 => 10,
                    _ => 1,
                }
        } else {
            0
        };

        if !(1..=12).contains(&month)
            || !(1..=31).contains(&day)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return Err(DomainError::InvalidTimestamp(format!(
                "date/time values out of range: {trimmed}"
            )));
        }

        let days = date_to_days(year, month, day);
        let total_secs =
            days * 86400 + (hour as u64) * 3600 + (minute as u64) * 60 + (second as u64);
        let total_millis = total_secs * 1000 + (millis as u64);

        Ok(Self::from_epoch_millis(total_millis))
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 => 31,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        3 => 31,
        4 => 30,
        5 => 31,
        6 => 30,
        7 => 31,
        8 => 31,
        9 => 30,
        10 => 31,
        11 => 30,
        12 => 31,
        _ => 30,
    }
}

fn days_to_date(days_since_epoch: u64) -> (i32, u32, u32) {
    let mut days_left = days_since_epoch;
    let mut year = 1970;

    loop {
        let leap = is_leap_year(year);
        let days_in_year = if leap { 366 } else { 365 };
        if days_left < days_in_year {
            break;
        }
        days_left -= days_in_year;
        year += 1;
    }

    let mut month = 1;
    loop {
        let dim = days_in_month(year, month) as u64;
        if days_left < dim {
            break;
        }
        days_left -= dim;
        month += 1;
    }

    let day = (days_left + 1) as u32;
    (year, month, day)
}

fn date_to_days(year: i32, month: u32, day: u32) -> u64 {
    let mut days: u64 = 0;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    for m in 1..month {
        days += days_in_month(year, m) as u64;
    }
    days += (day - 1) as u64;
    days
}
