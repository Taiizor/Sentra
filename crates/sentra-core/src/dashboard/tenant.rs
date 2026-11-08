//! Multi-tenant isolation boundaries, tenant identifiers, and context models (REQ-F19, ADR-0001, ADR-0003).

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

use crate::dashboard::error::{DashboardError, DashboardErrorKind};

/// Strongly-typed tenant identifier representing an isolated organizational boundary.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TenantId(String);

impl TenantId {
    /// Maximum allowed character length for a tenant identifier.
    pub const MAX_LENGTH: usize = 64;

    /// Creates and validates a new `TenantId`.
    ///
    /// Identifiers must be 1 to 64 characters in length and may only contain
    /// ASCII alphanumeric characters, hyphens (`-`), and underscores (`_`).
    pub fn new(id: impl Into<String>) -> Result<Self, DashboardError> {
        let raw = id.into();
        let trimmed = raw.trim();

        if trimmed.is_empty() {
            return Err(DashboardError::new(
                DashboardErrorKind::InvalidQuery,
                "tenant identifier cannot be empty",
            ));
        }

        if trimmed.len() > Self::MAX_LENGTH {
            return Err(DashboardError::new(
                DashboardErrorKind::InvalidQuery,
                format!(
                    "tenant identifier exceeds maximum length of {} characters (got {})",
                    Self::MAX_LENGTH,
                    trimmed.len()
                ),
            ));
        }

        for ch in trimmed.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
                return Err(DashboardError::new(
                    DashboardErrorKind::InvalidQuery,
                    format!(
                        "invalid character '{}' in tenant identifier; only ASCII alphanumeric, '-', and '_' are allowed",
                        ch
                    ),
                ));
            }
        }

        Ok(Self(trimmed.to_string()))
    }

    /// Creates a deterministic tenant identifier for test fixtures and reproducible environments.
    pub fn deterministic(index: u64) -> Self {
        Self(format!("tenant-{index:016x}"))
    }

    /// Returns a string slice representing the tenant identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for TenantId {
    type Err = DashboardError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// Isolation level governing cross-tenant boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IsolationLevel {
    /// Single operator workspace; cross-tenant operations are permitted or single-tenant default.
    SingleOperator,
    /// Strict multi-tenant fencing; cross-tenant operations fail closed with `CrossTenantAccessDenied`.
    MultiTenantIsolated,
}

impl IsolationLevel {
    /// Returns a static descriptive label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SingleOperator => "single_operator",
            Self::MultiTenantIsolated => "multi_tenant_isolated",
        }
    }
}

impl fmt::Display for IsolationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Tenant context carrying caller identity, tenant boundary, and isolation requirements.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantContext {
    tenant_id: TenantId,
    user_id: String,
    isolation_level: IsolationLevel,
}

impl TenantContext {
    /// Creates a new tenant execution context.
    pub fn new(
        tenant_id: TenantId,
        user_id: impl Into<String>,
        isolation_level: IsolationLevel,
    ) -> Self {
        Self {
            tenant_id,
            user_id: user_id.into(),
            isolation_level,
        }
    }

    /// Convenience constructor for single operator mode.
    pub fn single_operator(tenant_id: TenantId, user_id: impl Into<String>) -> Self {
        Self::new(tenant_id, user_id, IsolationLevel::SingleOperator)
    }

    /// Convenience constructor for strict multi-tenant isolation mode.
    pub fn multi_tenant(tenant_id: TenantId, user_id: impl Into<String>) -> Self {
        Self::new(tenant_id, user_id, IsolationLevel::MultiTenantIsolated)
    }

    /// Returns the associated tenant identifier.
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the caller user identifier.
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Returns the active isolation level.
    pub fn isolation_level(&self) -> IsolationLevel {
        self.isolation_level
    }

    /// Asserts tenant isolation against a target resource's tenant identifier.
    ///
    /// If `isolation_level` is `MultiTenantIsolated` and `self.tenant_id != *target_tenant`,
    /// this function fails closed with `CrossTenantAccessDenied`.
    pub fn assert_tenant_isolation(&self, target_tenant: &TenantId) -> Result<(), DashboardError> {
        if self.isolation_level == IsolationLevel::MultiTenantIsolated
            && self.tenant_id != *target_tenant
        {
            return Err(DashboardError::cross_tenant_denied(format!(
                "cross-tenant access denied: context tenant '{}' cannot access resource belonging to tenant '{}'",
                self.tenant_id, target_tenant
            )));
        }
        Ok(())
    }
}
