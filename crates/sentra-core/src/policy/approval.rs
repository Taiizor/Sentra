use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{Arc, Mutex},
};

use crate::{
    common::Clock,
    domain::{ApprovalId, SecurityClassification, SessionId, TimestampUtc},
    session::SessionMetadata,
};

use super::{OperationAction, budget::CostUsd, decision::DenialReason};

/// Display copy of a broker-created approval request, never an issuance capability.
#[derive(Clone, Debug, PartialEq)]
pub struct ApprovalRequest {
    /// Correlation identifier; possession is not proof of approval.
    pub request_id: ApprovalId,
    /// Trusted registered session identity.
    pub session_id: SessionId,
    /// Registered operator requesting approval.
    pub actor_id: String,
    /// Canonical structured operation identity, not a cryptographic digest.
    pub action_digest: String,
    /// Explicit registered target revision, independent of policy_digest.
    pub target_revision: String,
    /// Registered target workspace identity.
    pub workspace_root: String,
    /// Classification bound to this particular operation.
    pub classification: SecurityClassification,
    /// Human-readable description.
    pub explanation: String,
    /// Requested cost ceiling when applicable.
    pub budget_limit: Option<CostUsd>,
    /// Creation time from the supplied trusted clock.
    pub created_at_utc: TimestampUtc,
    /// Exclusive expiry boundary.
    pub expires_at_utc: TimestampUtc,
}

/// Grant receipt with private in-process issuance provenance.
///
/// Public fields are untrusted views: modifying any one invalidates the receipt.
/// A receipt is not a serializable bearer token or a cryptographic signature.
#[derive(Clone)]
pub struct ApprovalGrant {
    /// Associated broker request.
    pub request_id: ApprovalId,
    /// Associated session.
    pub session_id: SessionId,
    /// Recorded trusted issuer actor.
    pub granted_by_actor: String,
    /// Issuance time.
    pub granted_at_utc: TimestampUtc,
    /// Approved canonical operation identity.
    pub action_digest: String,
    /// Approved revision.
    pub target_revision: String,
    /// Approved workspace identity.
    pub workspace_root: String,
    /// Approved operation classification.
    pub classification: SecurityClassification,
    /// Correlation label only; this predictable string is not proof of issuance.
    pub token: String,
    provenance: Arc<()>,
}

impl ApprovalGrant {
    /// Construct an UNISSUED proposal for compatibility/transport validation.
    ///
    /// This cannot authorize anything. Only ApprovalAuthority::issue_grant produces
    /// a receipt registered in the broker. Copying all visible fields is insufficient.
    pub fn new(
        request_id: ApprovalId,
        session_id: SessionId,
        granted_by_actor: impl Into<String>,
        granted_at_utc: TimestampUtc,
        action_digest: impl Into<String>,
        target_revision: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        Self {
            request_id,
            session_id,
            granted_by_actor: granted_by_actor.into(),
            granted_at_utc,
            action_digest: action_digest.into(),
            target_revision: target_revision.into(),
            workspace_root: String::new(),
            classification: SecurityClassification::Public,
            token: token.into(),
            provenance: Arc::new(()),
        }
    }

    fn matches_receipt(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.provenance, &other.provenance)
            && self.request_id == other.request_id
            && self.session_id == other.session_id
            && self.granted_by_actor == other.granted_by_actor
            && self.granted_at_utc == other.granted_at_utc
            && self.action_digest == other.action_digest
            && self.target_revision == other.target_revision
            && self.workspace_root == other.workspace_root
            && self.classification == other.classification
            && self.token == other.token
    }
}

impl fmt::Debug for ApprovalGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApprovalGrant([redacted receipt])")
    }
}

impl PartialEq for ApprovalGrant {
    fn eq(&self, other: &Self) -> bool {
        self.matches_receipt(other)
    }
}
impl Eq for ApprovalGrant {}

#[derive(Clone)]
struct SessionContext {
    metadata: SessionMetadata,
    revision: String,
    minimum_classification: SecurityClassification,
    // Re-registering a session invalidates old requests, even after an ABA revision change.
    generation: Arc<()>,
}

impl SessionContext {
    fn matches_metadata(&self, metadata: &SessionMetadata) -> bool {
        let trusted = &self.metadata;
        trusted.session_id == metadata.session_id
            && trusted.workspace_root == metadata.workspace_root
            && trusted.operator_id == metadata.operator_id
            && trusted.policy_digest == metadata.policy_digest
            && trusted.operating_mode == metadata.operating_mode
            && trusted.created_at_utc == metadata.created_at_utc
        // Assessment completeness is not an authorization input.
    }
}

#[derive(Clone)]
struct Binding {
    session: SessionContext,
    classification: SecurityClassification,
    action: String,
}

impl Binding {
    fn matches(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.session.generation, &other.session.generation)
            && self.session.matches_metadata(&other.session.metadata)
            && self.session.revision == other.session.revision
            && self.classification == other.classification
            && self.action == other.action
    }
}

struct StoredRequest {
    view: ApprovalRequest,
    binding: Binding,
}

#[derive(Default)]
struct BrokerInner {
    sessions: BTreeMap<SessionId, SessionContext>,
    requests: BTreeMap<ApprovalId, StoredRequest>,
    issued: BTreeMap<ApprovalId, ApprovalGrant>,
    consumed: BTreeSet<ApprovalId>,
    revoked: BTreeSet<ApprovalId>,
}

/// Read/plan/consume side of the single trusted, Mutex-protected approval mechanism.
///
/// It exposes no context-registration, grant-issuance or request-injection method.
///
/// ```compile_fail
/// use sentra_core::{ApprovalBroker, ApprovalRequest};
/// fn inject(broker: &ApprovalBroker, request: ApprovalRequest) {
///     broker.submit_request(request);
/// }
/// ```
///
/// ```compile_fail
/// use sentra_core::{ApprovalBroker, ApprovalId, MockClock};
/// fn issue(broker: &ApprovalBroker, id: &ApprovalId, clock: &MockClock) {
///     broker.issue_grant(id, "human", clock);
/// }
/// ```
#[derive(Clone, Default)]
pub struct ApprovalBroker {
    inner: Arc<Mutex<BrokerInner>>,
}

/// Privileged control-plane handle to the SAME broker, retained by the trusted owner.
///
/// Never expose this handle to request submitters, target files, models or adapters.
/// Frontend authentication/human identity is outside this in-process mechanism.
pub struct ApprovalAuthority {
    inner: Arc<Mutex<BrokerInner>>,
}

impl fmt::Debug for ApprovalBroker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApprovalBroker([redacted])")
    }
}
impl fmt::Debug for ApprovalAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApprovalAuthority([privileged])")
    }
}

fn unavailable() -> DenialReason {
    DenialReason::MissingAuthorization("approval context unavailable".into())
}
fn mismatch() -> DenialReason {
    DenialReason::ApprovalMismatched("current operation context differs from approval".into())
}
fn invalid() -> DenialReason {
    DenialReason::InvalidApprovalGrant("unknown, revoked or modified receipt".into())
}

fn valid_text(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

fn binding(
    inner: &BrokerInner,
    session: &SessionMetadata,
    classification: SecurityClassification,
    action: &OperationAction,
) -> Result<Binding, DenialReason> {
    action
        .validate()
        .map_err(|_| DenialReason::MissingAuthorization("malformed operation".into()))?;
    let trusted = inner
        .sessions
        .get(&session.session_id)
        .ok_or_else(unavailable)?;
    if !trusted.matches_metadata(session) || classification < trusted.minimum_classification {
        return Err(unavailable());
    }
    Ok(Binding {
        session: trusted.clone(),
        classification,
        action: action.action_digest(),
    })
}

impl ApprovalBroker {
    /// Create an unconfigured broker; operations fail closed until a trusted context exists.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bootstrap both sides once; only trusted setup retains the authority handle.
    pub fn with_authority() -> (Self, ApprovalAuthority) {
        let broker = Self::new();
        let authority = ApprovalAuthority {
            inner: Arc::clone(&broker.inner),
        };
        (broker, authority)
    }

    /// Check an existing owner-installed context without changing it.
    /// Only ApprovalAuthority can install or replace authoritative context.
    pub fn set_session_context(
        &self,
        session: &SessionMetadata,
        target_revision: &str,
        minimum_classification: SecurityClassification,
    ) -> Result<(), DenialReason> {
        if session.session_id.as_bytes().iter().all(|byte| *byte == 0)
            || !valid_text(&session.workspace_root)
            || !valid_text(&session.operator_id)
            || !valid_text(&session.policy_digest)
            || !valid_text(target_revision)
        {
            return Err(unavailable());
        }
        let inner = self.inner.lock().map_err(|_| unavailable())?;
        let context = inner
            .sessions
            .get(&session.session_id)
            .ok_or_else(unavailable)?;
        if context.metadata != *session
            || context.revision != target_revision
            || context.minimum_classification != minimum_classification
        {
            return Err(unavailable());
        }
        Ok(())
    }

    /// Validate registered context for an existing automatic, non-sensitive policy rule.
    pub(crate) fn validate_context(
        &self,
        session: &SessionMetadata,
        classification: SecurityClassification,
        action: &OperationAction,
    ) -> Result<(), DenialReason> {
        let inner = self.inner.lock().map_err(|_| unavailable())?;
        binding(&inner, session, classification, action).map(|_| ())
    }

    /// Create a pending request from canonical current inputs, never an injected DTO.
    pub fn request_approval(
        &self,
        session: &SessionMetadata,
        classification: SecurityClassification,
        action: &OperationAction,
        clock: &impl Clock,
    ) -> Result<ApprovalRequest, DenialReason> {
        let mut inner = self.inner.lock().map_err(|_| unavailable())?;
        let expected = binding(&inner, session, classification, action)?;
        let now = clock.now();
        let expires = now.add_seconds(3600);
        if expires <= now {
            return Err(unavailable());
        }
        let id = ApprovalId::new();
        if inner.requests.contains_key(&id) {
            return Err(unavailable());
        }
        let view = ApprovalRequest {
            request_id: id,
            session_id: expected.session.metadata.session_id,
            actor_id: expected.session.metadata.operator_id.clone(),
            action_digest: expected.action.clone(),
            target_revision: expected.session.revision.clone(),
            workspace_root: expected.session.metadata.workspace_root.clone(),
            classification,
            explanation: format!("Human approval required: {}", action.action_name()),
            budget_limit: match action {
                OperationAction::InvokeProvider { estimated_cost, .. } => Some(*estimated_cost),
                _ => None,
            },
            created_at_utc: now,
            expires_at_utc: expires,
        };
        inner.requests.insert(
            id,
            StoredRequest {
                view: view.clone(),
                binding: expected,
            },
        );
        Ok(view)
    }

    /// Return an untrusted display copy; mutating it cannot affect broker state.
    pub fn get_request(&self, request_id: &ApprovalId) -> Option<ApprovalRequest> {
        let inner = self.inner.lock().ok()?;
        if inner.consumed.contains(request_id) || inner.revoked.contains(request_id) {
            return None;
        }
        inner
            .requests
            .get(request_id)
            .map(|stored| stored.view.clone())
    }

    /// Atomically validate provenance, current binding, expiry and single-use state,
    /// then consume. There is deliberately no separate successful validate-only API.
    pub fn verify_and_consume(
        &self,
        grant: Option<&ApprovalGrant>,
        session: &SessionMetadata,
        classification: SecurityClassification,
        action: &OperationAction,
        clock: &impl Clock,
    ) -> Result<(), DenialReason> {
        let mut inner = self.inner.lock().map_err(|_| unavailable())?;
        let current = binding(&inner, session, classification, action)?;
        let grant =
            grant.ok_or_else(|| DenialReason::MissingApprovalGrant("approved operation".into()))?;
        let stored = inner.requests.get(&grant.request_id).ok_or_else(invalid)?;
        // Check current context before replay state, so a racing mismatch never consumes.
        if !stored.binding.matches(&current) {
            return Err(mismatch());
        }
        let issued = inner.issued.get(&grant.request_id).ok_or_else(invalid)?;
        if !issued.matches_receipt(grant) || inner.revoked.contains(&grant.request_id) {
            return Err(invalid());
        }
        if inner.consumed.contains(&grant.request_id) {
            return Err(DenialReason::ApprovalReused(
                "receipt already consumed".into(),
            ));
        }
        let now = clock.now();
        if stored.view.expires_at_utc.is_expired_at(now) {
            return Err(DenialReason::ExpiredApprovalGrant(
                "request lifetime elapsed".into(),
            ));
        }
        if now < stored.view.created_at_utc || now < issued.granted_at_utc {
            return Err(invalid());
        }
        inner.consumed.insert(grant.request_id);
        Ok(())
    }
}

impl ApprovalAuthority {
    /// Install a trusted workspace/session/revision snapshot and classification floor.
    /// Every call replaces its generation, invalidating all old requests for that session.
    /// The owner must supply an already established workspace identity and real revision.
    pub fn set_session_context(
        &self,
        session: &SessionMetadata,
        target_revision: &str,
        minimum_classification: SecurityClassification,
    ) -> Result<(), DenialReason> {
        if session.session_id.as_bytes().iter().all(|byte| *byte == 0)
            || !valid_text(&session.workspace_root)
            || !valid_text(&session.operator_id)
            || !valid_text(&session.policy_digest)
            || !valid_text(target_revision)
        {
            return Err(unavailable());
        }
        let mut inner = self.inner.lock().map_err(|_| unavailable())?;
        inner.sessions.insert(
            session.session_id,
            SessionContext {
                metadata: session.clone(),
                revision: target_revision.into(),
                minimum_classification,
                generation: Arc::new(()),
            },
        );
        Ok(())
    }

    /// Issue a registered receipt after the trusted controller obtains human approval.
    /// Actor text records that controller's decision; it does not authenticate a human.
    pub fn issue_grant(
        &self,
        request_id: &ApprovalId,
        granted_by_actor: &str,
        clock: &impl Clock,
    ) -> Result<ApprovalGrant, DenialReason> {
        if !valid_text(granted_by_actor) {
            return Err(invalid());
        }
        let mut inner = self.inner.lock().map_err(|_| unavailable())?;
        let stored = inner.requests.get(request_id).ok_or_else(invalid)?;
        let current = inner
            .sessions
            .get(&stored.view.session_id)
            .ok_or_else(unavailable)?;
        if !Arc::ptr_eq(&current.generation, &stored.binding.session.generation) {
            return Err(mismatch());
        }
        if inner.issued.contains_key(request_id)
            || inner.revoked.contains(request_id)
            || inner.consumed.contains(request_id)
        {
            return Err(invalid());
        }
        let now = clock.now();
        if stored.view.expires_at_utc.is_expired_at(now) {
            return Err(DenialReason::ExpiredApprovalGrant(
                "request lifetime elapsed".into(),
            ));
        }
        if now < stored.view.created_at_utc {
            return Err(invalid());
        }
        let grant = ApprovalGrant {
            request_id: *request_id,
            session_id: stored.view.session_id,
            granted_by_actor: granted_by_actor.into(),
            granted_at_utc: now,
            action_digest: stored.view.action_digest.clone(),
            target_revision: stored.view.target_revision.clone(),
            workspace_root: stored.view.workspace_root.clone(),
            classification: stored.view.classification,
            token: format!("approval:{request_id}"),
            provenance: Arc::new(()),
        };
        inner.issued.insert(*request_id, grant.clone());
        Ok(grant)
    }

    /// Revoke a pending request through the trusted control plane.
    pub fn revoke_request(&self, request_id: &ApprovalId) -> Result<bool, DenialReason> {
        let mut inner = self.inner.lock().map_err(|_| unavailable())?;
        if !inner.requests.contains_key(request_id) || inner.consumed.contains(request_id) {
            return Ok(false);
        }
        Ok(inner.revoked.insert(*request_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MockClock, OperatingMode};

    #[test]
    fn poisoned_broker_denies_context_issuance_and_consumption() {
        let (broker, authority) = ApprovalBroker::with_authority();
        let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));
        let session = SessionMetadata::new(
            SessionId::for_test_sequence(531),
            clock.now(),
            "/trusted/root",
            OperatingMode::ContinuousReview,
            "operator",
            "policy",
        )
        .unwrap();
        authority
            .set_session_context(&session, "revision", SecurityClassification::Public)
            .unwrap();
        let action = OperationAction::DiscoverMetadata {
            relative_path: "metadata".into(),
        };
        let request = broker
            .request_approval(
                &session,
                SecurityClassification::Restricted,
                &action,
                &clock,
            )
            .unwrap();
        let grant = authority
            .issue_grant(&request.request_id, "human", &clock)
            .unwrap();
        let inner = Arc::clone(&broker.inner);
        assert!(
            std::thread::spawn(move || {
                let _held = inner.lock().unwrap();
                panic!("synthetic poison");
            })
            .join()
            .is_err()
        );
        assert!(matches!(
            broker.verify_and_consume(
                Some(&grant),
                &session,
                SecurityClassification::Restricted,
                &action,
                &clock
            ),
            Err(DenialReason::MissingAuthorization(_))
        ));
        assert!(
            authority
                .issue_grant(&request.request_id, "human", &clock)
                .is_err()
        );
        assert!(
            authority
                .set_session_context(&session, "revision", SecurityClassification::Public)
                .is_err()
        );
        assert!(broker.get_request(&request.request_id).is_none());
    }
}
