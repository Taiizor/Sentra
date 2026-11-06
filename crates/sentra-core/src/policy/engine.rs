use crate::{
    common::clock::Clock,
    domain::classification::SecurityClassification,
    policy::{
        action::OperationAction,
        approval::{ApprovalAuthority, ApprovalBroker, ApprovalGrant},
        budget::{BudgetPolicyConfig, CostUsd},
        decision::{DenialReason, PolicyDecision},
    },
    session::metadata::SessionMetadata,
};

/// Deterministic policy engine enforcing default-deny authorization,
/// security classification constraints, and human approval broker lifecycles.
/// Effective configuration is immutable after construction. A different policy
/// value cannot replace a registered persistent policy without owner re-registration.
/// ```compile_fail
/// use sentra_core::{PolicyEngine, CostUsd};
/// let mut engine = PolicyEngine::new();
/// engine.set_max_auto_budget(CostUsd::ZERO);
/// ```
#[derive(Debug, Default)]
pub struct PolicyEngine {
    approval_broker: ApprovalBroker,
    config: BudgetPolicyConfig,
}

impl PolicyEngine {
    /// Creates an unconfigured engine; missing trusted session context denies requests.
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

    /// Bootstrap a configured evaluator and its separate privileged approval handle.
    /// Keep the authority in the trusted controller, never in an untrusted request path.
    pub fn with_authority(config: BudgetPolicyConfig) -> (Self, ApprovalAuthority) {
        let (approval_broker, authority) = ApprovalBroker::with_authority();
        (
            Self {
                approval_broker,
                config,
            },
            authority,
        )
    }

    /// Returns the maximum cost that can be automatically approved without human grant.
    pub fn max_auto_budget(&self) -> CostUsd {
        self.config.max_auto_budget
    }

    /// Bootstrap-only ownership transfer into the service's immutable configuration.
    /// The service never exposes this engine or a configuration mutator.
    pub(crate) fn for_service(self, budget: CostUsd) -> Self {
        Self {
            config: BudgetPolicyConfig {
                max_auto_budget: budget,
                ..self.config
            },
            ..self
        }
    }

    /// Canonical effective rule identity, not a cryptographic digest. Reserved
    /// configuration fields do not relax mandatory sensitivity/egress rules.
    /// Only the auto-budget threshold currently changes evaluation semantics.
    pub(crate) fn policy_identity(&self) -> String {
        format!(
            "sentra-policy:v1:auto-microusd={}",
            self.config.max_auto_budget.as_micro_usd()
        )
    }

    pub(crate) fn valid_policy_identity(value: &str) -> bool {
        value
            .strip_prefix("sentra-policy:v1:auto-microusd=")
            .is_some_and(|number| {
                number
                    .parse::<u64>()
                    .is_ok_and(|parsed| parsed.to_string() == number)
            })
    }

    /// Returns a reference to the active budget policy configuration.
    pub fn config(&self) -> &BudgetPolicyConfig {
        &self.config
    }

    /// Returns the request/consume interface; it cannot register context or issue grants.
    pub fn broker(&self) -> &ApprovalBroker {
        &self.approval_broker
    }

    /// Check an already owner-installed context; this cannot install or replace it.
    pub fn register_session_context(
        &self,
        session: &SessionMetadata,
        target_revision: &str,
        minimum_classification: SecurityClassification,
    ) -> Result<(), DenialReason> {
        self.approval_broker
            .set_session_context(session, target_revision, minimum_classification)
    }

    /// Evaluate rules against a snapshot supplied ONLY by the persistent authority.
    /// The persistent service does not synchronize a second in-memory authority.
    pub(crate) fn evaluate_authoritative(
        &self,
        floor: SecurityClassification,
        classification: SecurityClassification,
        action: &OperationAction,
        amount: CostUsd,
    ) -> Result<bool, DenialReason> {
        validate_operation_constraints(classification, action)?;
        if classification < floor {
            return Err(DenialReason::MissingAuthorization(
                "classification floor".into(),
            ));
        }
        if let OperationAction::InvokeProvider { estimated_cost, .. } = action
            && *estimated_cost != amount
        {
            return Err(DenialReason::MissingAuthorization(
                "inconsistent cost bound".into(),
            ));
        }
        Ok(action.is_sensitive()
            || classification == SecurityClassification::Restricted
            || amount > self.config.max_auto_budget)
    }

    /// Evaluates an operation request against session context, classification, and approval grants.
    ///
    /// Adheres strictly to the Default-Deny invariant:
    /// 1. Unknown operations are unconditionally denied.
    /// 2. Information flow violations (write-down to lower classification) are denied.
    /// 3. Restricted data operations require explicit human approval.
    /// 4. Inherently sensitive actions (tool execution, checkout modification, external export) require approval.
    /// 5. Operations exceeding auto-budget threshold require approval.
    /// 6. Every supplied grant is checked and atomically consumed, including otherwise automatic operations.
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

        if let Err(reason) = self
            .approval_broker
            .validate_context(session, classification, action)
        {
            return PolicyDecision::Denied { reason };
        }

        if let Err(reason) = validate_operation_constraints(classification, action) {
            return PolicyDecision::Denied { reason };
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

        // 6. Preserve automatic rules only for trusted context with no presented receipt.
        if !requires_approval && grant.is_none() {
            return PolicyDecision::Granted;
        }

        // 7. If approval IS required, evaluate the grant (if provided) or emit NeedsApproval
        match grant {
            Some(g) => {
                // Atomically verify and consume grant through broker
                match self.approval_broker.verify_and_consume(
                    Some(g),
                    session,
                    classification,
                    action,
                    clock,
                ) {
                    Ok(()) => PolicyDecision::Granted,
                    Err(denial) => PolicyDecision::Denied { reason: denial },
                }
            }
            None => {
                match self
                    .approval_broker
                    .request_approval(session, classification, action, clock)
                {
                    Ok(request) => PolicyDecision::NeedsApproval { request },
                    Err(reason) => PolicyDecision::Denied { reason },
                }
            }
        }
    }
}

pub(crate) fn validate_operation_constraints(
    classification: SecurityClassification,
    action: &OperationAction,
) -> Result<(), DenialReason> {
    if let OperationAction::UnknownOperation { operation_name } = action {
        return Err(DenialReason::UnknownOperation(operation_name.clone()));
    }
    action
        .validate()
        .map_err(|_| DenialReason::MissingAuthorization("malformed operation".into()))?;
    if let OperationAction::ExportReport {
        destination_classification: Some(destination),
        ..
    } = action
        && !classification.can_flow_to(destination)
    {
        return Err(DenialReason::ClassificationExceeded {
            classification,
            detail: format!(
                "data at classification [{classification}] cannot flow down to [{destination}] under Bell-LaPadula rules"
            ),
        });
    }
    Ok(())
}
