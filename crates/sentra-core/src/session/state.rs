use std::fmt;

/// The canonical lifecycle states of a Sentra research session (DATA_MODEL.md, CORE_ENGINE_DESIGN.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionState {
    /// Initial session state after creation; workspace not yet scoped.
    Created,
    /// Workspace root boundary inspected and canonicalized.
    Scoped,
    /// Task dependency graph constructed and resource bounds planned.
    Planned,
    /// Tasks are actively executing under leased worker workers.
    Running,
    /// Execution is suspended waiting for human approval for a sensitive action.
    WaitingForApproval,
    /// Execution is temporarily paused by operator request.
    Paused,
    /// Planned tasks completed; assessment completeness recorded. (Terminal)
    Completed,
    /// Unrecoverable error encountered. (Terminal)
    Failed,
    /// Explicitly cancelled by operator request. (Terminal)
    Cancelled,
}

impl SessionState {
    /// States eligible for a new synchronous task admission. Approval waiting,
    /// pause, unscoped creation and all terminal states deny execution.
    pub const fn allows_execution(&self) -> bool {
        matches!(self, Self::Scoped | Self::Planned | Self::Running)
    }

    /// Returns whether this state is terminal (no further transitions permitted).
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    /// Returns whether this state represents an active, non-terminal session.
    pub const fn is_active(&self) -> bool {
        !self.is_terminal()
    }

    /// Evaluates whether a transition from `self` to `target` is permitted by the state machine.
    pub const fn can_transition_to(&self, target: SessionState) -> bool {
        match (self, target) {
            // Self-transitions are not permitted; transition must represent a real state change.
            (a, b) if *a as u8 == b as u8 => false,

            // Terminal states cannot transition to ANY state.
            (Self::Completed, _) | (Self::Failed, _) | (Self::Cancelled, _) => false,

            // From Created:
            (Self::Created, Self::Scoped) => true,
            (Self::Created, Self::Cancelled) | (Self::Created, Self::Failed) => true,

            // From Scoped:
            (Self::Scoped, Self::Planned) => true,
            (Self::Scoped, Self::Cancelled) | (Self::Scoped, Self::Failed) => true,

            // From Planned:
            (Self::Planned, Self::Running) => true,
            (Self::Planned, Self::WaitingForApproval) => true,
            (Self::Planned, Self::Cancelled) | (Self::Planned, Self::Failed) => true,

            // From WaitingForApproval:
            (Self::WaitingForApproval, Self::Running) => true,
            (Self::WaitingForApproval, Self::Cancelled)
            | (Self::WaitingForApproval, Self::Failed) => true,

            // From Running:
            (Self::Running, Self::WaitingForApproval) => true,
            (Self::Running, Self::Paused) => true,
            (Self::Running, Self::Completed) => true,
            (Self::Running, Self::Failed) => true,
            (Self::Running, Self::Cancelled) => true,

            // From Paused:
            (Self::Paused, Self::Running) => true,
            (Self::Paused, Self::Cancelled) | (Self::Paused, Self::Failed) => true,

            // All other transitions are forbidden.
            _ => false,
        }
    }

    /// Returns the canonical uppercase string representation of the state.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "CREATED",
            Self::Scoped => "SCOPED",
            Self::Planned => "PLANNED",
            Self::Running => "RUNNING",
            Self::WaitingForApproval => "WAITING_FOR_APPROVAL",
            Self::Paused => "PAUSED",
            Self::Completed => "COMPLETED",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
        }
    }
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Assessment completeness metric ensuring operational completion is not confused
/// with a complete security audit (DATA_MODEL.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AssessmentCompleteness {
    /// All planned components and code paths were analyzed within budget.
    Complete,
    /// Execution finished, but certain targets or checks were skipped or incomplete.
    Partial,
    /// The target architecture or language is currently unsupported.
    Unsupported,
}

impl AssessmentCompleteness {
    /// Returns the uppercase string representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Complete => "COMPLETE",
            Self::Partial => "PARTIAL",
            Self::Unsupported => "UNSUPPORTED",
        }
    }
}

impl fmt::Display for AssessmentCompleteness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// The authorized operating mode for the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OperatingMode {
    /// Continuous review mode focusing on incremental commits and pull request diffs.
    ContinuousReview,
    /// Deep security research mode with wider Scout/Analyst coverage and fuzzing.
    DeepSecurityResearch,
}

impl OperatingMode {
    /// Returns the uppercase string representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ContinuousReview => "CONTINUOUS_REVIEW",
            Self::DeepSecurityResearch => "DEEP_SECURITY_RESEARCH",
        }
    }
}

impl fmt::Display for OperatingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
