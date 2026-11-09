//! Research campaign lifecycle, task fanout control, and anti-collusion orchestration (REQ-F04, REQ-S06, REQ-S08, Autonomous Research Specification).

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

use crate::{
    domain::{
        id::{CampaignId, SessionId, TaskId},
        time::TimestampUtc,
    },
    research::{
        coverage::CoverageLedger,
        error::{ResearchError, ResearchErrorKind},
        hypothesis::{Hypothesis, HypothesisDeduplicator},
        role::{ResearchRole, assert_peer_approval_forbidden},
    },
};

/// Resource and fanout boundaries governing a research campaign (REQ-S06).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignLimits {
    /// Maximum number of concurrently executing research tasks.
    pub max_concurrent_tasks: u32,
    /// Maximum hierarchical depth of child tasks spawned from root scouts.
    pub max_depth: u32,
    /// Total monetary budget ceiling in micro-USD ($1.00 = 1,000,000 micro-USD).
    pub max_budget_micro_usd: u64,
    /// Maximum wall-clock execution duration in seconds.
    pub max_duration_seconds: u64,
    /// Maximum number of hypotheses permitted for exploration.
    pub max_hypotheses: u32,
}

impl Default for CampaignLimits {
    fn default() -> Self {
        Self {
            max_concurrent_tasks: 4,
            max_depth: 2,
            max_budget_micro_usd: 50_000_000, // $50.00 USD
            max_duration_seconds: 3600,       // 1 hour
            max_hypotheses: 20,
        }
    }
}

/// Operational state of a security research campaign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStatus {
    /// Campaign initialized; ready to receive initial tasks.
    Planning,
    /// Campaign actively executing tasks within limits.
    Active,
    /// Temporarily paused by operator or policy.
    Paused,
    /// Completed naturally after achieving targets.
    Completed,
    /// Stopped prematurely due to limits or operator request.
    Stopped,
}

/// Specific reason why a research campaign concluded or stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStopReason {
    /// All scoped targets and hypotheses evaluated.
    TargetCoverageAchieved,
    /// Total campaign monetary budget exhausted.
    BudgetExhausted,
    /// Wall-clock execution time ceiling reached.
    TimeoutReached,
    /// Operator explicitly requested campaign cancellation.
    OperatorCancelled,
    /// Exploration made no progress across repeated iterations.
    NoProgressThresholdReached,
    /// Maximum tree exploration depth reached.
    MaxDepthExceeded,
}

/// Execution status of an individual campaign task.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchTaskStatus {
    /// Task currently running.
    Running,
    /// Task concluded successfully.
    Completed,
    /// Task encountered a fatal error.
    Failed,
    /// Task cancelled before completion.
    Cancelled,
}

/// Managed research task within a campaign tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignTask {
    /// Unique task identifier.
    pub task_id: TaskId,
    /// Parent task identifier if spawned as a child task.
    pub parent_task_id: Option<TaskId>,
    /// Assigned research role.
    pub role: ResearchRole,
    /// Tree depth (0 for root scouts, 1 for analysts, 2 for validators).
    pub depth: u32,
    /// Reserved budget in micro-USD.
    pub budget_reserved_micro_usd: u64,
    /// Settled actual budget in micro-USD.
    pub budget_spent_micro_usd: u64,
    /// Current execution status.
    pub status: ResearchTaskStatus,
    /// Isolated canary token for verifying secret isolation.
    pub secret_canary: String,
}

#[derive(Serialize, Deserialize)]
struct CampaignTaskPayload {
    task_id: String,
    parent_task_id: Option<String>,
    role: ResearchRole,
    depth: u32,
    budget_reserved_micro_usd: u64,
    budget_spent_micro_usd: u64,
    status: ResearchTaskStatus,
    secret_canary: String,
}

impl Serialize for CampaignTask {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let payload = CampaignTaskPayload {
            task_id: self.task_id.to_string(),
            parent_task_id: self.parent_task_id.map(|id| id.to_string()),
            role: self.role,
            depth: self.depth,
            budget_reserved_micro_usd: self.budget_reserved_micro_usd,
            budget_spent_micro_usd: self.budget_spent_micro_usd,
            status: self.status,
            secret_canary: self.secret_canary.clone(),
        };
        payload.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CampaignTask {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let payload = CampaignTaskPayload::deserialize(deserializer)?;
        let task_id = TaskId::from_str(&payload.task_id).map_err(serde::de::Error::custom)?;
        let parent_task_id = match payload.parent_task_id {
            Some(s) => Some(TaskId::from_str(&s).map_err(serde::de::Error::custom)?),
            None => None,
        };

        Ok(Self {
            task_id,
            parent_task_id,
            role: payload.role,
            depth: payload.depth,
            budget_reserved_micro_usd: payload.budget_reserved_micro_usd,
            budget_spent_micro_usd: payload.budget_spent_micro_usd,
            status: payload.status,
            secret_canary: payload.secret_canary,
        })
    }
}

/// Coordinated research campaign orchestrator enforcing fanout bounds and role boundaries (REQ-F04).
#[derive(Clone, Debug)]
pub struct Campaign {
    /// Unique campaign identifier.
    pub id: CampaignId,
    /// Associated parent session identifier.
    pub session_id: SessionId,
    /// Configured resource and fanout boundaries.
    pub limits: CampaignLimits,
    /// Current lifecycle status.
    pub status: CampaignStatus,
    /// Final stop reason if finished.
    pub stop_reason: Option<CampaignStopReason>,
    /// Managed tasks in this campaign.
    pub tasks: Vec<CampaignTask>,
    /// Surface exploration coverage ledger.
    pub coverage_ledger: CoverageLedger,
    /// Deduplication registry for hypotheses.
    pub deduplicator: HypothesisDeduplicator,
    /// Total actual spent budget in micro-USD.
    pub budget_spent_micro_usd: u64,
    /// Total currently reserved budget in micro-USD.
    pub budget_reserved_micro_usd: u64,
    /// Campaign start timestamp.
    pub created_at: TimestampUtc,
}

impl Campaign {
    /// Initializes a new research campaign.
    pub fn new(session_id: SessionId, limits: CampaignLimits, now: TimestampUtc) -> Self {
        Self {
            id: CampaignId::new(),
            session_id,
            limits,
            status: CampaignStatus::Planning,
            stop_reason: None,
            tasks: Vec::new(),
            coverage_ledger: CoverageLedger::new(),
            deduplicator: HypothesisDeduplicator::new(),
            budget_spent_micro_usd: 0,
            budget_reserved_micro_usd: 0,
            created_at: now,
        }
    }

    /// Transitions campaign into the active execution state.
    pub fn activate(&mut self) {
        self.status = CampaignStatus::Active;
    }

    /// Returns the number of currently executing tasks.
    pub fn active_task_count(&self) -> u32 {
        self.tasks
            .iter()
            .filter(|t| t.status == ResearchTaskStatus::Running)
            .count() as u32
    }

    /// Spawns a new research task enforcing concurrency, tree depth, and budget limits (REQ-S06).
    pub fn spawn_task(
        &mut self,
        role: ResearchRole,
        parent_task_id: Option<TaskId>,
        budget_reservation: u64,
        _now: TimestampUtc,
    ) -> Result<TaskId, ResearchError> {
        if self.status != CampaignStatus::Active {
            return Err(ResearchError::new(
                ResearchErrorKind::CampaignAlreadyFinished {
                    status: format!("{:?}", self.status),
                },
                format!(
                    "Cannot spawn task in campaign with status {:?}",
                    self.status
                ),
            ));
        }

        // 1. Tree depth limit check (structural validation)
        let depth = match parent_task_id {
            Some(parent_id) => {
                let parent = self
                    .tasks
                    .iter()
                    .find(|t| t.task_id == parent_id)
                    .ok_or_else(|| {
                        ResearchError::new(
                            ResearchErrorKind::TaskNotFound {
                                task_id: parent_id.to_string(),
                            },
                            format!("Parent task '{parent_id}' not found"),
                        )
                    })?;
                parent.depth + 1
            }
            None => 0,
        };

        if depth > self.limits.max_depth {
            return Err(ResearchError::max_depth_exceeded(
                depth,
                self.limits.max_depth,
            ));
        }

        // 2. Concurrency limit check
        let active = self.active_task_count();
        if active >= self.limits.max_concurrent_tasks {
            return Err(ResearchError::concurrency_limit_exceeded(
                active,
                self.limits.max_concurrent_tasks,
            ));
        }

        // 3. Budget ceiling check
        let total_committed = self
            .budget_spent_micro_usd
            .saturating_add(self.budget_reserved_micro_usd)
            .saturating_add(budget_reservation);

        if total_committed > self.limits.max_budget_micro_usd {
            let available = self.limits.max_budget_micro_usd.saturating_sub(
                self.budget_spent_micro_usd
                    .saturating_add(self.budget_reserved_micro_usd),
            );
            return Err(ResearchError::budget_exhausted(
                budget_reservation,
                available,
            ));
        }

        let task_id = TaskId::new();
        let secret_canary = format!("canary-secret-{}", task_id);

        self.budget_reserved_micro_usd = self
            .budget_reserved_micro_usd
            .saturating_add(budget_reservation);

        self.tasks.push(CampaignTask {
            task_id,
            parent_task_id,
            role,
            depth,
            budget_reserved_micro_usd: budget_reservation,
            budget_spent_micro_usd: 0,
            status: ResearchTaskStatus::Running,
            secret_canary,
        });

        Ok(task_id)
    }

    /// Completes a task and settles its reserved budget.
    pub fn complete_task(
        &mut self,
        task_id: TaskId,
        actual_spent_micro_usd: u64,
    ) -> Result<(), ResearchError> {
        let task = self
            .tasks
            .iter_mut()
            .find(|t| t.task_id == task_id)
            .ok_or_else(|| {
                ResearchError::new(
                    ResearchErrorKind::TaskNotFound {
                        task_id: task_id.to_string(),
                    },
                    format!("Task '{task_id}' not found"),
                )
            })?;

        task.status = ResearchTaskStatus::Completed;
        task.budget_spent_micro_usd = actual_spent_micro_usd;

        let reserved = task.budget_reserved_micro_usd;
        self.budget_reserved_micro_usd = self.budget_reserved_micro_usd.saturating_sub(reserved);
        self.budget_spent_micro_usd = self
            .budget_spent_micro_usd
            .saturating_add(actual_spent_micro_usd);

        Ok(())
    }

    /// Marks a task as failed and releases its unused budget reservation.
    pub fn fail_task(&mut self, task_id: TaskId) -> Result<(), ResearchError> {
        let task = self
            .tasks
            .iter_mut()
            .find(|t| t.task_id == task_id)
            .ok_or_else(|| {
                ResearchError::new(
                    ResearchErrorKind::TaskNotFound {
                        task_id: task_id.to_string(),
                    },
                    format!("Task '{task_id}' not found"),
                )
            })?;

        task.status = ResearchTaskStatus::Failed;
        let reserved = task.budget_reserved_micro_usd;
        self.budget_reserved_micro_usd = self.budget_reserved_micro_usd.saturating_sub(reserved);

        Ok(())
    }

    /// Stops the campaign with an explicit stop reason.
    pub fn stop(&mut self, reason: CampaignStopReason) {
        self.status = CampaignStatus::Stopped;
        self.stop_reason = Some(reason);
    }

    /// Submits a hypothesis, ensuring it is tracked and deduplicated (REQ-F05).
    pub fn propose_hypothesis(&mut self, hypothesis: Hypothesis) -> Result<(), ResearchError> {
        if self.deduplicator.count() >= self.limits.max_hypotheses as usize {
            return Err(ResearchError::new(
                ResearchErrorKind::MaxDepthExceeded {
                    current_depth: self.deduplicator.count() as u32,
                    max_depth: self.limits.max_hypotheses,
                },
                format!("Hypothesis limit {} reached", self.limits.max_hypotheses),
            ));
        }

        self.deduplicator.register(&hypothesis)
    }

    /// Verifies that secrets belonging to other tasks are not leaked in the observed text (Security Isolation).
    ///
    /// Fails closed with `SecretIsolationBreach` if any peer task's canary token is present.
    pub fn verify_secret_isolation(
        &self,
        current_task_id: TaskId,
        observed_text: &str,
    ) -> Result<(), ResearchError> {
        for task in &self.tasks {
            if task.task_id != current_task_id && observed_text.contains(&task.secret_canary) {
                return Err(ResearchError::new(
                    ResearchErrorKind::SecretIsolationBreach {
                        canary: task.secret_canary.clone(),
                    },
                    format!(
                        "Secret isolation breach: canary of task '{}' detected in output",
                        task.task_id
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Validates anti-collusion rule: peer tasks cannot approve each other's work (Anti-Collusion Specification).
    pub fn verify_no_peer_approval(
        &self,
        proposer_task_id: TaskId,
        approver_task_id: TaskId,
    ) -> Result<(), ResearchError> {
        let proposer = self
            .tasks
            .iter()
            .find(|t| t.task_id == proposer_task_id)
            .ok_or_else(|| {
                ResearchError::new(
                    ResearchErrorKind::TaskNotFound {
                        task_id: proposer_task_id.to_string(),
                    },
                    format!("Proposer task '{proposer_task_id}' not found"),
                )
            })?;

        let approver = self
            .tasks
            .iter()
            .find(|t| t.task_id == approver_task_id)
            .ok_or_else(|| {
                ResearchError::new(
                    ResearchErrorKind::TaskNotFound {
                        task_id: approver_task_id.to_string(),
                    },
                    format!("Approver task '{approver_task_id}' not found"),
                )
            })?;

        assert_peer_approval_forbidden(proposer.role, approver.role)
    }
}
