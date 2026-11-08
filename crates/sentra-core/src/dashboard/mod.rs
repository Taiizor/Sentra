//! Dashboard core services, multi-tenant session isolation, and RBAC authorization (REQ-F19, ADR-0001, ADR-0003).

/// Dashboard and access control error definitions.
pub mod error;
/// Role-based access control (RBAC) roles, actions, and enforcement.
pub mod rbac;
/// Enterprise dashboard application service and multi-tenant coordinator.
pub mod service;
/// Multi-tenant identifiers, contexts, and isolation boundary rules.
pub mod tenant;
/// View models and data transfer objects representing core dashboard views.
pub mod view;

pub use error::{DashboardError, DashboardErrorKind};
pub use rbac::{DashboardAction, UserRole, enforce_rbac};
pub use service::DashboardService;
pub use tenant::{IsolationLevel, TenantContext, TenantId};
pub use view::{
    AuditLogView, CampaignLedgerView, DashboardOverview, FindingView, PatchBundleView,
    SessionSummaryView,
};
