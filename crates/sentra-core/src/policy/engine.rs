use crate::{
    common::clock::Clock,
    domain::classification::SecurityClassification,
    policy::{
        action::OperationAction,
        approval::{ApprovalBroker, ApprovalGrant, ApprovalRequest},
        decision::{DenialReason, PolicyDecision},
    },
    session::metadata::SessionMetadata,
};

/// Deterministic policy engine enforcing default-deny authorization,
/// security classification constraints, and human approval broker lifecycles.
#[derive(Debug, Default)]
pub struct PolicyEngine {
    approval_broker: ApprovalBroker,
    max_auto_budget_usd: f64,
}

impl PolicyEngine {
    /// Creates a new policy engine with default configurations.
    pub fn new() -> Self {
        Self {
            approval_broker: ApprovalBroker::new(),
            max_auto_budget_usd: 1.00, // Operations exceeding $1.00 require human approval
        }
    }

    /// Returns the maximum cost in USD that can be automatically approved without human grant.
    pub fn max_auto_budget_usd(&self) -> f64 {
        self.max_auto_budget_usd
    }

    /// Sets the maximum cost in USD that can be automatically approved.
    pub fn set_max_auto_budget_usd(&mut self, budget: f64) {
        self.max_auto_budget_usd = budget;
    }

    /// Returns a mutable reference to the internal approval broker.
    pub fn broker_mut(&mut self) -> &mut ApprovalBroker {
        &mut self.approval_broker
    }

    /// Returns an immutable reference to the internal approval broker.
    pub fn broker(&self) -> &ApprovalBroker {
        &self.approval_broker
    }

    /// Evaluates an operation request against session context, classification, and approval grants.
    ///
    /// Adheres strictly to the Default-Deny invariant:
    /// - Unknown operations are denied immediately.
    /// - Restricted data operations require explicit human approval.
    /// - Inherently sensitive actions (tool execution, checkout modification, external export) require approval.
    /// - If a valid, non-expired, unconsumed grant is provided, the action is Granted.
    /// - If approval is required and no grant is provided, returns NeedsApproval.
    /// - If an invalid, expired, or reused grant is provided, returns Denied.
    pub fn evaluate(
        &mut self,
        session: &SessionMetadata,
        classification: SecurityClassification,
        action: &OperationAction,
        grant: Option<&ApprovalGrant>,
        clock: &impl Clock,
    ) -> PolicyDecision {
        // 1. Unknown operations are unconditionally denied (Default-Deny)
        if let OperationAction::UnknownOperation { operation_name } = action {
            return PolicyDecision::Denied {
                reason: DenialReason::UnknownOperation(operation_name.clone()),
            };
        }

        // 2. Cost ceiling check: exceed max auto-budget triggers approval requirement
        let mut requires_approval = action.is_sensitive();
        if let OperationAction::InvokeProvider {
            estimated_cost_usd, ..
        } = action
            && *estimated_cost_usd > self.max_auto_budget_usd
        {
            requires_approval = true;
        }

        // 3. Security Classification check:
        // Restricted data always requires human approval for any active processing or export
        if classification == SecurityClassification::Restricted {
            requires_approval = true;
        }

        // 4. If approval is not required, grant immediately
        if !requires_approval {
            return PolicyDecision::Granted;
        }

        // 5. If approval IS required, evaluate the grant (if provided) or emit NeedsApproval
        match grant {
            Some(g) => {
                // Verify grant through broker
                match self.approval_broker.verify_and_consume(g, clock) {
                    Ok(()) => PolicyDecision::Granted,
                    Err(denial) => PolicyDecision::Denied { reason: denial },
                }
            }
            None => {
                // Generate and register an ApprovalRequest
                let request = ApprovalRequest::new(
                    session.session_id,
                    &session.operator_id,
                    action.action_digest(),
                    &session.policy_digest, // Using policy/scope digest as target revision baseline
                    format!(
                        "Human approval required for action: {}",
                        action.action_name()
                    ),
                    None,
                    clock.now(),
                    3600, // 1 hour expiration window
                );
                self.approval_broker.submit_request(request.clone());
                PolicyDecision::NeedsApproval { request }
            }
        }
    }
}
