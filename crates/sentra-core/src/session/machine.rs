use crate::{
    audit::event::{AuditEvent, AuditEventKind},
    common::clock::Clock,
    domain::{
        SessionId,
        error::{DomainError, SessionTransitionError},
    },
    session::{
        metadata::SessionMetadata,
        state::{AssessmentCompleteness, SessionState},
    },
};

/// Encapsulates the deterministic session lifecycle state machine.
/// Ensures all state changes are valid, audited, and strictly transition-checked.
#[derive(Debug)]
pub struct SessionStateMachine {
    metadata: SessionMetadata,
    state: SessionState,
    sequence_counter: u64,
}

impl SessionStateMachine {
    /// Creates a new state machine initialized in the `Created` state.
    pub fn new(metadata: SessionMetadata) -> Self {
        Self {
            metadata,
            state: SessionState::Created,
            sequence_counter: 0,
        }
    }

    /// Returns the current session state.
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Returns a reference to the session metadata.
    pub const fn metadata(&self) -> &SessionMetadata {
        &self.metadata
    }

    /// Returns the unique session identifier.
    pub const fn session_id(&self) -> SessionId {
        self.metadata.session_id
    }

    /// Returns the current sequence counter for audit events.
    pub const fn sequence_counter(&self) -> u64 {
        self.sequence_counter
    }

    /// Attempts to transition the session to a new state.
    ///
    /// If the transition is prohibited by the state machine rules:
    /// - Returns an `Err(SessionTransitionError)`.
    /// - Leaves the internal state unchanged.
    /// - Does NOT increment the sequence counter.
    /// - Does NOT emit an audit event.
    ///
    /// If the transition is permitted:
    /// - Updates the internal state.
    /// - Increments the sequence counter.
    /// - Constructs and returns an immutable `AuditEvent` representing the transition.
    pub fn transition_to(
        &mut self,
        target: SessionState,
        actor: &str,
        reason: &str,
        clock: &dyn Clock,
    ) -> Result<AuditEvent, SessionTransitionError> {
        if !self.state.can_transition_to(target) {
            return Err(SessionTransitionError {
                from: self.state,
                attempted_to: target,
            });
        }

        let from = self.state;
        self.state = target;
        self.sequence_counter = self.sequence_counter.saturating_add(1);

        let event = AuditEvent::new(
            self.metadata.session_id,
            self.sequence_counter,
            clock.now(),
            actor,
            AuditEventKind::StateTransition {
                from,
                to: target,
                reason: reason.to_string(),
            },
            format!("Transitioned from {from:?} to {target:?}: {reason}"),
        );

        Ok(event)
    }

    /// Sets the final assessment completeness. Allowed only when the session is `Completed`.
    pub fn set_completeness(
        &mut self,
        completeness: AssessmentCompleteness,
    ) -> Result<(), DomainError> {
        if self.state != SessionState::Completed {
            return Err(DomainError::PolicyViolation(format!(
                "cannot set completeness on non-completed session (current state: {:?})",
                self.state
            )));
        }
        self.metadata.completeness = completeness;
        Ok(())
    }
}
