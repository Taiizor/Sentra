use std::collections::{BTreeMap, BTreeSet};

use crate::{
    common::clock::Clock,
    domain::{ApprovalId, SessionId, TimestampUtc},
    policy::decision::DenialReason,
};

/// Represents an explicit human approval request for a sensitive action (S-02, S-10).
#[derive(Clone, Debug, PartialEq)]
pub struct ApprovalRequest {
    /// Unique identifier for this approval request.
    pub request_id: ApprovalId,
    /// Identifier of the session requiring approval.
    pub session_id: SessionId,
    /// Actor requesting approval.
    pub actor_id: String,
    /// Cryptographic or canonical digest identifying the exact action and arguments.
    pub action_digest: String,
    /// Target repository commit revision or scope hash.
    pub target_revision: String,
    /// Human-readable explanation of why approval is needed.
    pub explanation: String,
    /// Optional upper cost limit in USD for this operation.
    pub budget_limit_usd: Option<f64>,
    /// UTC timestamp when the request was generated.
    pub created_at_utc: TimestampUtc,
    /// Expiration UTC timestamp after which the request is automatically invalid.
    pub expires_at_utc: TimestampUtc,
}

impl ApprovalRequest {
    /// Creates a new approval request with an explicit lifetime in seconds.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: SessionId,
        actor_id: impl Into<String>,
        action_digest: impl Into<String>,
        target_revision: impl Into<String>,
        explanation: impl Into<String>,
        budget_limit_usd: Option<f64>,
        created_at_utc: TimestampUtc,
        lifetime_seconds: u64,
    ) -> Self {
        Self {
            request_id: ApprovalId::new(),
            session_id,
            actor_id: actor_id.into(),
            action_digest: action_digest.into(),
            target_revision: target_revision.into(),
            explanation: explanation.into(),
            budget_limit_usd,
            created_at_utc,
            expires_at_utc: created_at_utc.add_seconds(lifetime_seconds),
        }
    }
}

/// An authorization grant submitted by a human operator or authorized credential.
#[derive(Clone, Debug, PartialEq)]
pub struct ApprovalGrant {
    /// Unique identifier of the approval request being granted.
    pub request_id: ApprovalId,
    /// Identifier of the session.
    pub session_id: SessionId,
    /// Operator identity granting approval.
    pub granted_by_actor: String,
    /// UTC timestamp when approval was granted.
    pub granted_at_utc: TimestampUtc,
    /// Canonical action digest confirmed by the operator.
    pub action_digest: String,
    /// Target revision confirmed by the operator.
    pub target_revision: String,
    /// Single-use authorization token.
    pub token: String,
}

impl ApprovalGrant {
    /// Constructs a new ApprovalGrant record.
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
            token: token.into(),
        }
    }
}

/// In-memory Human Approval Broker managing pending requests, validation,
/// expiration, and single-use replay protection (S-02).
#[derive(Debug, Default)]
pub struct ApprovalBroker {
    pending_requests: BTreeMap<ApprovalId, ApprovalRequest>,
    consumed_tokens: BTreeSet<String>,
    revoked_requests: BTreeSet<ApprovalId>,
}

impl ApprovalBroker {
    /// Creates a new empty ApprovalBroker.
    pub fn new() -> Self {
        Self {
            pending_requests: BTreeMap::new(),
            consumed_tokens: BTreeSet::new(),
            revoked_requests: BTreeSet::new(),
        }
    }

    /// Registers a pending approval request in the broker.
    pub fn submit_request(&mut self, request: ApprovalRequest) -> ApprovalId {
        let id = request.request_id;
        self.pending_requests.insert(id, request);
        id
    }

    /// Returns a reference to a pending request by ID.
    pub fn get_request(&self, request_id: &ApprovalId) -> Option<&ApprovalRequest> {
        self.pending_requests.get(request_id)
    }

    /// Explicitly revokes or denies a pending approval request.
    pub fn revoke_request(&mut self, request_id: &ApprovalId) -> bool {
        if self.pending_requests.remove(request_id).is_some() {
            self.revoked_requests.insert(*request_id);
            true
        } else {
            false
        }
    }

    /// Verifies and consumes an approval grant.
    ///
    /// Invariants enforced:
    /// 1. Token must not have been previously consumed (Replay prevention).
    /// 2. Request ID must exist in pending requests.
    /// 3. Request must not have been revoked.
    /// 4. Action digest in the grant must match the request's action digest.
    /// 5. Target revision in the grant must match the request's target revision.
    /// 6. Grant must not be expired according to the provided clock.
    /// 7. On success, the token is permanently consumed and the pending request is removed.
    pub fn verify_and_consume<C: Clock>(
        &mut self,
        grant: &ApprovalGrant,
        clock: &C,
    ) -> Result<(), DenialReason> {
        // 1. Replay check
        if self.consumed_tokens.contains(&grant.token) {
            return Err(DenialReason::ApprovalReused(format!(
                "token '{}' was already consumed",
                grant.token
            )));
        }

        // 2. Revocation check
        if self.revoked_requests.contains(&grant.request_id) {
            return Err(DenialReason::InvalidApprovalGrant(format!(
                "request '{}' was revoked",
                grant.request_id
            )));
        }

        // 3. Pending request check
        let request = match self.pending_requests.get(&grant.request_id) {
            Some(req) => req,
            None => {
                return Err(DenialReason::InvalidApprovalGrant(format!(
                    "no pending request found for ID '{}'",
                    grant.request_id
                )));
            }
        };

        // 4. Session match check
        if request.session_id != grant.session_id {
            return Err(DenialReason::ApprovalMismatched(format!(
                "session ID mismatch: request belongs to '{}', grant specifies '{}'",
                request.session_id, grant.session_id
            )));
        }

        // 5. Action digest match check
        if request.action_digest != grant.action_digest {
            return Err(DenialReason::ApprovalMismatched(format!(
                "action digest mismatch: request '{}', grant '{}'",
                request.action_digest, grant.action_digest
            )));
        }

        // 6. Target revision match check
        if request.target_revision != grant.target_revision {
            return Err(DenialReason::ApprovalMismatched(format!(
                "target revision mismatch: request '{}', grant '{}'",
                request.target_revision, grant.target_revision
            )));
        }

        // 7. Expiry check
        let now = clock.now();
        if request.expires_at_utc.is_expired_at(now) {
            return Err(DenialReason::ExpiredApprovalGrant(format!(
                "approval expired at {} (current time: {})",
                request.expires_at_utc, now
            )));
        }

        // Invariants satisfied: consume token and remove pending request
        self.consumed_tokens.insert(grant.token.clone());
        self.pending_requests.remove(&grant.request_id);

        Ok(())
    }
}
