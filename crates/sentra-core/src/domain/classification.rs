use std::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    str::FromStr,
};

use crate::domain::error::DomainError;

/// Security classification levels for project data, finding reports, and operations.
/// Strictly defined per Sentra requirements (S-01, S-05, and DATA_MODEL.md).
#[derive(Clone, Copy, Debug, Eq)]
pub enum SecurityClassification {
    /// Publicly disclosable data (e.g. open-source code, public advisories).
    Public,
    /// Internal operator or organization data not intended for external egress.
    Internal,
    /// Sensitive private repository code, unpublished findings, or customer data.
    Confidential,
    /// High-risk credentials, zero-day exploit primitives, or secret material.
    Restricted,
}

impl SecurityClassification {
    /// Explicit numeric rank assigned to each classification level.
    /// This prevents comparisons from depending on enum variant declaration order.
    pub const fn rank(&self) -> u8 {
        match self {
            Self::Public => 10,
            Self::Internal => 20,
            Self::Confidential => 30,
            Self::Restricted => 40,
        }
    }

    /// Determines whether data at this classification level can flow to a destination
    /// without violating security policy (no write-down to lower classification).
    pub fn can_flow_to(&self, destination: &SecurityClassification) -> bool {
        self.rank() <= destination.rank()
    }

    /// Returns whether this classification requires human approval for external transfer.
    pub fn requires_approval_for_external_egress(&self) -> bool {
        match self {
            Self::Public => false,
            Self::Internal | Self::Confidential | Self::Restricted => true,
        }
    }

    /// Returns the canonical uppercase string representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "PUBLIC",
            Self::Internal => "INTERNAL",
            Self::Confidential => "CONFIDENTIAL",
            Self::Restricted => "RESTRICTED",
        }
    }
}

impl PartialEq for SecurityClassification {
    fn eq(&self, other: &Self) -> bool {
        self.rank() == other.rank()
    }
}

impl Hash for SecurityClassification {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.rank().hash(state);
    }
}

impl Ord for SecurityClassification {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for SecurityClassification {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for SecurityClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for SecurityClassification {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_uppercase().as_str() {
            "PUBLIC" => Ok(Self::Public),
            "INTERNAL" => Ok(Self::Internal),
            "CONFIDENTIAL" => Ok(Self::Confidential),
            "RESTRICTED" => Ok(Self::Restricted),
            other => Err(DomainError::PolicyViolation(format!(
                "unsupported security classification: '{other}'"
            ))),
        }
    }
}
