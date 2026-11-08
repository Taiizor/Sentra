//! Safe pure-Rust semantic versioning and constraint evaluator (Requirement F-07).
//!
//! Provides zero-third-party semver parsing and range constraint matching
//! under `#![forbid(unsafe_code)]`.

use std::{fmt, str::FromStr};

use crate::advisory::error::{AdvisoryError, AdvisoryErrorKind};

/// A semantic version representation `MAJOR.MINOR.PATCH[-PRERELEASE]`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SemverVersion {
    /// Major version number (breaking changes).
    pub major: u64,
    /// Minor version number (backward-compatible new functionality).
    pub minor: u64,
    /// Patch version number (backward-compatible bug fixes).
    pub patch: u64,
    /// Optional pre-release identifier string (e.g. `alpha.1`).
    pub pre: Option<String>,
}

impl SemverVersion {
    /// Creates a new semantic version.
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
            pre: None,
        }
    }

    /// Creates a new semantic version with a pre-release tag.
    pub fn with_pre(major: u64, minor: u64, patch: u64, pre: impl Into<String>) -> Self {
        Self {
            major,
            minor,
            patch,
            pre: Some(pre.into()),
        }
    }
}

impl PartialOrd for SemverVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SemverVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.major.cmp(&other.major) {
            std::cmp::Ordering::Equal => match self.minor.cmp(&other.minor) {
                std::cmp::Ordering::Equal => match self.patch.cmp(&other.patch) {
                    std::cmp::Ordering::Equal => match (&self.pre, &other.pre) {
                        (None, None) => std::cmp::Ordering::Equal,
                        (Some(_), None) => std::cmp::Ordering::Less, // Pre-release has lower precedence than normal version
                        (None, Some(_)) => std::cmp::Ordering::Greater,
                        (Some(a), Some(b)) => a.cmp(b),
                    },
                    ord => ord,
                },
                ord => ord,
            },
            ord => ord,
        }
    }
}

impl fmt::Display for SemverVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref pre) = self.pre {
            write!(f, "{}.{}.{}-{}", self.major, self.minor, self.patch, pre)
        } else {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        }
    }
}

impl FromStr for SemverVersion {
    type Err = AdvisoryError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(AdvisoryError::new(
                AdvisoryErrorKind::InvalidVersion,
                "version string cannot be empty",
            ));
        }

        let (core, pre) = match trimmed.split_once('-') {
            Some((c, p)) => {
                if p.is_empty() {
                    return Err(AdvisoryError::new(
                        AdvisoryErrorKind::InvalidVersion,
                        format!("empty pre-release tag in '{s}'"),
                    ));
                }
                (c, Some(p.to_string()))
            }
            None => (trimmed, None),
        };

        let parts: Vec<&str> = core.split('.').collect();
        if parts.is_empty() || parts.len() > 3 {
            return Err(AdvisoryError::new(
                AdvisoryErrorKind::InvalidVersion,
                format!("expected 1-3 numeric components in '{s}'"),
            ));
        }

        let major = parts[0].parse::<u64>().map_err(|e| {
            AdvisoryError::new(
                AdvisoryErrorKind::InvalidVersion,
                format!("invalid major version in '{s}': {e}"),
            )
        })?;

        let minor = if parts.len() > 1 {
            parts[1].parse::<u64>().map_err(|e| {
                AdvisoryError::new(
                    AdvisoryErrorKind::InvalidVersion,
                    format!("invalid minor version in '{s}': {e}"),
                )
            })?
        } else {
            0
        };

        let patch = if parts.len() > 2 {
            parts[2].parse::<u64>().map_err(|e| {
                AdvisoryError::new(
                    AdvisoryErrorKind::InvalidVersion,
                    format!("invalid patch version in '{s}': {e}"),
                )
            })?
        } else {
            0
        };

        Ok(Self {
            major,
            minor,
            patch,
            pre,
        })
    }
}

/// A comparison operator for version requirements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Exact version match (`=`).
    Exact,
    /// Strictly greater than (`>`).
    Greater,
    /// Greater than or equal to (`>=`).
    GreaterEq,
    /// Strictly less than (`<`).
    Less,
    /// Less than or equal to (`<=`).
    LessEq,
    /// Compatible version update (`^`).
    Caret,
    /// Minor version update (`~`).
    Tilde,
}

/// A single comparator predicate (e.g. `>= 1.2.0`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Comparator {
    /// Comparison operator.
    pub op: Op,
    /// Target version against which to compare.
    pub version: SemverVersion,
}

impl Comparator {
    /// Evaluates whether a given version satisfies this comparator.
    pub fn matches(&self, ver: &SemverVersion) -> bool {
        match self.op {
            Op::Exact => ver == &self.version,
            Op::Greater => ver > &self.version,
            Op::GreaterEq => ver >= &self.version,
            Op::Less => ver < &self.version,
            Op::LessEq => ver <= &self.version,
            Op::Caret => {
                if ver < &self.version {
                    return false;
                }
                if self.version.major > 0 {
                    ver.major == self.version.major
                } else if self.version.minor > 0 {
                    ver.major == 0 && ver.minor == self.version.minor
                } else {
                    ver == &self.version
                }
            }
            Op::Tilde => {
                if ver < &self.version {
                    return false;
                }
                ver.major == self.version.major && ver.minor == self.version.minor
            }
        }
    }
}

/// A composite version requirement consisting of one or more comparators.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionReq {
    comparators: Vec<Comparator>,
}

impl VersionReq {
    /// Evaluates whether a given version satisfies all comparators in this requirement.
    pub fn matches(&self, ver: &SemverVersion) -> bool {
        if self.comparators.is_empty() {
            return true;
        }
        self.comparators.iter().all(|c| c.matches(ver))
    }
}

impl FromStr for VersionReq {
    type Err = AdvisoryError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed == "*" || trimmed.is_empty() {
            return Ok(Self {
                comparators: Vec::new(),
            });
        }

        let mut comparators = Vec::new();
        // Split on comma (e.g. ">= 1.0.0, < 2.0.0")
        for chunk in trimmed.split(',') {
            let part = chunk.trim();
            if part.is_empty() {
                continue;
            }

            let (op, ver_str) = if let Some(rest) = part.strip_prefix(">=") {
                (Op::GreaterEq, rest)
            } else if let Some(rest) = part.strip_prefix("<=") {
                (Op::LessEq, rest)
            } else if let Some(rest) = part.strip_prefix('>') {
                (Op::Greater, rest)
            } else if let Some(rest) = part.strip_prefix('<') {
                (Op::Less, rest)
            } else if let Some(rest) = part.strip_prefix('=') {
                (Op::Exact, rest)
            } else if let Some(rest) = part.strip_prefix('^') {
                (Op::Caret, rest)
            } else if let Some(rest) = part.strip_prefix('~') {
                (Op::Tilde, rest)
            } else {
                (Op::Caret, part)
            };

            let ver = SemverVersion::from_str(ver_str)?;
            comparators.push(Comparator { op, version: ver });
        }

        Ok(Self { comparators })
    }
}
