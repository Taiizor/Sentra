//! Dashboard and enterprise administration error models (REQ-F19, ADR-0001, ADR-0003).

use std::fmt;

/// Categories of dashboard service, access control, and tenant isolation errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DashboardErrorKind {
    /// Caller lacks the required role for the requested dashboard action.
    UnauthorizedRole,
    /// Cross-tenant access attempted; tenant context does not match target resource.
    CrossTenantAccessDenied,
    /// Tenant identifier was not found.
    TenantNotFound,
    /// Session identifier was not found.
    SessionNotFound,
    /// Dashboard action was denied by policy engine.
    PolicyDenied,
    /// Malformed query or parameter.
    InvalidQuery,
}

impl DashboardErrorKind {
    /// Returns a static descriptive label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::UnauthorizedRole => "unauthorized_role",
            Self::CrossTenantAccessDenied => "cross_tenant_access_denied",
            Self::TenantNotFound => "tenant_not_found",
            Self::SessionNotFound => "session_not_found",
            Self::PolicyDenied => "policy_denied",
            Self::InvalidQuery => "invalid_query",
        }
    }
}

impl fmt::Display for DashboardErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Strongly-typed error produced by the dashboard service layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DashboardError {
    kind: DashboardErrorKind,
    message: String,
}

impl DashboardError {
    /// Creates a new dashboard error.
    pub fn new(kind: DashboardErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Returns the category of this error.
    pub fn kind(&self) -> DashboardErrorKind {
        self.kind
    }

    /// Returns the descriptive error message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Helper for unauthorized role errors.
    pub fn unauthorized_role(msg: impl Into<String>) -> Self {
        Self::new(DashboardErrorKind::UnauthorizedRole, msg)
    }

    /// Helper for cross-tenant access denied errors.
    pub fn cross_tenant_denied(msg: impl Into<String>) -> Self {
        Self::new(DashboardErrorKind::CrossTenantAccessDenied, msg)
    }

    /// Helper for session not found errors.
    pub fn session_not_found(msg: impl Into<String>) -> Self {
        Self::new(DashboardErrorKind::SessionNotFound, msg)
    }

    /// Helper for policy denied errors.
    pub fn policy_denied(msg: impl Into<String>) -> Self {
        Self::new(DashboardErrorKind::PolicyDenied, msg)
    }
}

impl fmt::Display for DashboardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.kind, self.message)
    }
}

impl std::error::Error for DashboardError {}
