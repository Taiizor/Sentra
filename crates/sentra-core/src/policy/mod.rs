//! Policy enforcement, operation authorization, and human approval broker.

/// Operation action requests and deterministic action digests.
pub mod action;
/// In-memory human approval broker and single-use grants.
pub mod approval;
/// Validated monetary costs and budget policy configuration.
pub mod budget;
/// Policy evaluation outcomes and auditable denial reasons.
pub mod decision;
/// Policy engine enforcing default-deny authorization and auto-budget ceilings.
pub mod engine;

pub use action::OperationAction;
pub use approval::{ApprovalAuthority, ApprovalBroker, ApprovalGrant, ApprovalRequest};
pub use budget::{BudgetPolicyConfig, CostUsd};
pub use decision::{DenialReason, PolicyDecision};
pub use engine::PolicyEngine;
