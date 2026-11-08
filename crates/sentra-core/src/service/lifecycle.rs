//! Formal backend lifecycle and cancellation contracts (Section 5, F-551-02).
//!
//! # Architecture and Future Isolated VM Lifecycle
//!
//! In Phase 1, `SyntheticFixtureBackend` executes synchronously and simulates
//! task outcomes in-memory. However, future Phase 2 execution against disposable
//! Hyper-V VMs requires an explicit, multi-stage lifecycle contract:
//!
//! 1. **Cancellation Request**: Controller registers cancellation intent and issues a termination signal.
//! 2. **Cancellation Acknowledgement**: Host-to-guest transport receives and acknowledges the signal.
//! 3. **Termination Confirmation**: Worker VM terminates and guest OS process teardown is confirmed.
//! 4. **Timeout Handling**: If worker does not terminate within a grace period, host forcibly terminates the VM.
//! 5. **Late Backend Responses**: Late responses arriving after forced termination are discarded.
//! 6. **Uncertain Termination**: If termination cannot be confirmed, budget settlement remains conservative.
//! 7. **Resource Teardown**: Disposable VM disk diffs and temporary directories are wiped.
//! 8. **Auditability**: Every stage is immutably logged to the audit ledger.

use crate::{
    AttemptId, ExecutionId, SessionId, SessionState, TaskId, TimestampUtc,
    persistence::{AttemptState, SettlementStatus},
};

/// Trigger reason for task cancellation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CancellationReason {
    /// Explicit cancellation requested by operator or interactive user.
    OperatorRequested,
    /// Session wall-clock timeout exceeded.
    SessionTimeout,
    /// Task execution timeout exceeded.
    TaskTimeout,
    /// Policy revoked or authorization context invalidated.
    PolicyRevoked,
    /// System or resource limits exceeded.
    ResourceExhaustion,
}

impl CancellationReason {
    /// Canonical string identifier for audit logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OperatorRequested => "OPERATOR_REQUESTED",
            Self::SessionTimeout => "SESSION_TIMEOUT",
            Self::TaskTimeout => "TASK_TIMEOUT",
            Self::PolicyRevoked => "POLICY_REVOKED",
            Self::ResourceExhaustion => "RESOURCE_EXHAUSTION",
        }
    }
}

/// Discrete phase of the backend cancellation lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancellationPhase {
    /// Cancellation intent registered; signal dispatched to worker.
    Requested,
    /// Worker or backend supervisor acknowledged receipt of cancellation signal.
    Acknowledged,
    /// Worker confirmed complete process termination and resource release.
    ConfirmedTerminated,
    /// Worker failed to terminate within grace period; status is uncertain.
    UncertainTermination,
}

impl CancellationPhase {
    /// Whether this phase represents a definitive, confirmed termination.
    pub fn is_confirmed(&self) -> bool {
        matches!(self, Self::ConfirmedTerminated)
    }

    /// Whether this phase represents an uncertain or ambiguous outcome.
    pub fn is_uncertain(&self) -> bool {
        matches!(
            self,
            Self::Requested | Self::Acknowledged | Self::UncertainTermination
        )
    }

    /// Canonical string identifier for audit logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Requested => "REQUESTED",
            Self::Acknowledged => "ACKNOWLEDGED",
            Self::ConfirmedTerminated => "CONFIRMED_TERMINATED",
            Self::UncertainTermination => "UNCERTAIN_TERMINATION",
        }
    }
}

/// Formal cancellation report tracking the lifecycle outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancellationReport {
    /// Associated execution attempt identifier.
    pub execution_id: ExecutionId,
    /// Timestamp when cancellation was requested.
    pub requested_at: TimestampUtc,
    /// Cancellation trigger reason.
    pub reason: CancellationReason,
    /// Achieved lifecycle phase.
    pub phase: CancellationPhase,
    /// Resulting budget settlement status.
    ///
    /// Preserves the conservative reservation invariant: if `phase` is not `ConfirmedTerminated`,
    /// this must be `SettlementStatus::CancelledUncertain` to ensure unconfirmed budget is not released.
    pub settlement_status: SettlementStatus,
    /// Human-readable diagnostic notes.
    pub notes: &'static str,
}

impl CancellationReport {
    /// Creates a simulated cancellation report for Phase 1 in-memory synthetic testing.
    pub fn simulated_synthetic(
        execution_id: ExecutionId,
        reason: CancellationReason,
        requested_at: TimestampUtc,
    ) -> Self {
        Self {
            execution_id,
            requested_at,
            reason,
            phase: CancellationPhase::ConfirmedTerminated,
            settlement_status: SettlementStatus::CancelledUncertain,
            notes: "Phase 1 simulated synthetic fixture cancellation; guest VM lifecycle deferred to Phase 2",
        }
    }

    /// Creates an uncertain cancellation report when termination cannot be verified.
    pub fn uncertain(
        execution_id: ExecutionId,
        reason: CancellationReason,
        requested_at: TimestampUtc,
    ) -> Self {
        Self {
            execution_id,
            requested_at,
            reason,
            phase: CancellationPhase::UncertainTermination,
            settlement_status: SettlementStatus::CancelledUncertain,
            notes: "Worker termination could not be confirmed; conservative budget reservation preserved",
        }
    }
}

/// Reconciled attempt status during session continuation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciledAttempt {
    /// Unique attempt identifier.
    pub attempt_id: AttemptId,
    /// Parent task identifier.
    pub task_id: TaskId,
    /// Prior lifecycle state before reconciliation.
    pub previous_state: AttemptState,
    /// Reconciled lifecycle state after continuation.
    pub reconciled_state: AttemptState,
    /// Whether budget reservation remains conservatively held.
    pub budget_held: bool,
}

/// Comprehensive report produced when resuming an interrupted session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionResumeReport {
    /// Target session identifier.
    pub session_id: SessionId,
    /// State of session before resumption.
    pub previous_state: SessionState,
    /// State of session after resumption.
    pub resumed_state: SessionState,
    /// Advanced context generation invalidating stale authorizations.
    pub new_context_generation: u64,
    /// Reconciled incomplete attempts.
    pub reconciled_attempts: Vec<ReconciledAttempt>,
    /// Completed tasks that are preserved and skipped.
    pub completed_tasks: Vec<TaskId>,
    /// Remaining tasks awaiting execution.
    pub pending_tasks: Vec<TaskId>,
}
