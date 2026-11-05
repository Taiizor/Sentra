use crate::{
    common::clock::Clock,
    domain::classification::SecurityClassification,
    policy::{
        action::OperationAction,
        approval::{ApprovalBroker, ApprovalGrant, ApprovalRequest},
        budget::{BudgetPolicyConfig, CostUsd},
        decision::{DenialReason, PolicyDecision},
    },
    session::metadata::SessionMetadata,
};

/// Deterministic policy engine enforcing default-deny authorization,
/// security classification constraints, and human approval broker lifecycles.
#[derive(Debug, Default)]
pub struct PolicyEngine {
    approval_broker: ApprovalBroker,
    config: BudgetPolicyConfig,
}

impl PolicyEngine {
    /// Creates a new policy engine with default configurations.
    pub fn new() -> Self {
        Self {
            approval_broker: ApprovalBroker::new(),
            config: BudgetPolicyConfig::default(),
        }
    }

    /// Creates a policy engine with custom budget configuration.
    pub fn with_config(config: BudgetPolicyConfig) -> Self {
        Self {
            approval_broker: ApprovalBroker::new(),
            config,
        }
    }

    /// Returns the maximum cost that can be automatically approved without human grant.
    pub fn max_auto_budget(&self) -> CostUsd {
        self.config.max_auto_budget
    }

    /// Sets the maximum cost that can be automatically approved.
    pub fn set_max_auto_budget(&mut self, budget: CostUsd) {
        self.config.max_auto_budget = budget;
    }

    /// Returns a reference to the active budget policy configuration.
    pub fn config(&self) -> &BudgetPolicyConfig {
        &self.config
    }

    /// Returns a reference to the internal approval broker.
    pub fn broker(&self) -> &ApprovalBroker {
        &self.approval_broker
    }

    /// Evaluates an operation request against session context, classification, and approval grants.
    ///
    /// Adheres strictly to the Default-Deny invariant:
    /// 1. Unknown operations are unconditionally denied.
    /// 2. Information flow violations (write-down to lower classification) are denied.
    /// 3. Restricted data operations require explicit human approval.
    /// 4. Inherently sensitive actions (tool execution, checkout modification, external export) require approval.
    /// 5. Operations exceeding auto-budget threshold require approval.
    /// 6. If approval is required and a valid grant is provided, the grant is atomically consumed and returns Granted.
    /// 7. If approval is required and no grant is provided, returns NeedsApproval.
    /// 8. If an invalid, expired, or reused grant is provided, returns Denied.
    pub fn evaluate(
        &self,
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

        // 2. Bell-LaPadula Information Flow Check:
        // No write-down to lower classification levels
        if let OperationAction::ExportReport {
            destination_classification: Some(dst_class),
            ..
        } = action
            && !classification.can_flow_to(dst_class)
        {
            return PolicyDecision::Denied {
                reason: DenialReason::ClassificationExceeded {
                    classification,
                    detail: format!(
                        "data at classification [{classification}] cannot flow down to [{dst_class}] under Bell-LaPadula rules"
                    ),
                },
            };
        }

        // 3. Egress and Sensitivity checks
        let mut requires_approval = action.is_sensitive();

        // Check external egress rules
        if let OperationAction::ExportReport { is_external, .. } = action
            && *is_external
            && classification.requires_approval_for_external_egress()
        {
            requires_approval = true;
        }

        // 4. Cost ceiling check: exceed max auto-budget triggers approval requirement
        if let OperationAction::InvokeProvider { estimated_cost, .. } = action
            && *estimated_cost > self.config.max_auto_budget
        {
            requires_approval = true;
        }

        // 5. Security Classification check:
        // Restricted data always requires human approval for ANY active processing or export
        if classification == SecurityClassification::Restricted {
            requires_approval = true;
        }

        // 6. If approval is not required, grant immediately
        if !requires_approval {
            return PolicyDecision::Granted;
        }

        // 7. If approval IS required, evaluate the grant (if provided) or emit NeedsApproval
        match grant {
            Some(g) => {
                // Atomically verify and consume grant through broker
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
