//! Remote worker node definitions, state machines, and isolation profiles (REQ-F19, ADR-0004).

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

use crate::{
    dashboard::TenantId,
    domain::time::TimestampUtc,
    fleet::error::{FleetError, FleetErrorKind},
    verification::{ContainmentLevel, EgressPolicy, WorkerArchitecture, WorkerResourceCaps},
};

/// Strongly-typed identifier representing a remote worker node in the fleet.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RemoteWorkerId(String);

impl RemoteWorkerId {
    /// Maximum allowed character length for a remote worker identifier.
    pub const MAX_LENGTH: usize = 64;

    /// Creates and validates a new `RemoteWorkerId`.
    pub fn new(id: impl Into<String>) -> Result<Self, FleetError> {
        let raw = id.into();
        let trimmed = raw.trim();

        if trimmed.is_empty() {
            return Err(FleetError::new(
                FleetErrorKind::InvalidInput,
                "remote worker identifier cannot be empty",
            ));
        }

        if trimmed.len() > Self::MAX_LENGTH {
            return Err(FleetError::new(
                FleetErrorKind::InvalidInput,
                format!(
                    "remote worker identifier exceeds maximum length of {} characters",
                    Self::MAX_LENGTH
                ),
            ));
        }

        for ch in trimmed.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
                return Err(FleetError::new(
                    FleetErrorKind::InvalidInput,
                    format!("invalid character '{}' in remote worker identifier", ch),
                ));
            }
        }

        Ok(Self(trimmed.to_string()))
    }

    /// Creates a deterministic worker identifier for tests and fixtures.
    pub fn deterministic(index: u64) -> Self {
        Self(format!("worker-{index:012x}"))
    }

    /// Returns a string slice representing the worker identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RemoteWorkerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for RemoteWorkerId {
    type Err = FleetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// Lifecycle states of a remote execution worker node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum WorkerState {
    /// Worker is being provisioned in a clean, disposable VM boundary.
    Provisioning,
    /// Worker is clean, idle, and available to accept a tenant lease.
    Ready,
    /// Worker is actively leased and bound to an exclusive tenant context.
    Leased {
        /// The exclusive tenant owning this lease.
        tenant_id: TenantId,
        /// Unique lease token identifier.
        lease_id: String,
        /// Timestamp when the lease was granted.
        leased_at: TimestampUtc,
    },
    /// Worker is quarantined due to missed heartbeats, fault, or pending reset.
    Quarantined {
        /// Reason explaining the quarantine.
        reason: String,
    },
    /// Worker has been terminated and its resources reclaimed.
    Terminated,
}

impl WorkerState {
    /// Returns a static descriptive label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Ready => "ready",
            Self::Leased { .. } => "leased",
            Self::Quarantined { .. } => "quarantined",
            Self::Terminated => "terminated",
        }
    }
}

impl fmt::Display for WorkerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Remote disposable execution worker node managed by the fleet coordinator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteWorkerNode {
    /// Unique worker identifier.
    pub worker_id: RemoteWorkerId,
    /// Internal network endpoint URL.
    pub endpoint_url: String,
    /// Runtime CPU architecture and OS profile.
    pub architecture: WorkerArchitecture,
    /// Containment boundary enclosing untrusted code execution.
    pub containment: ContainmentLevel,
    /// Enforced memory, CPU, disk, and execution limits.
    pub resource_caps: WorkerResourceCaps,
    /// Outbound network egress restriction policy.
    pub egress_policy: EgressPolicy,
    /// Current lifecycle state.
    pub state: WorkerState,
    /// Timestamp of most recently received keepalive heartbeat.
    pub last_heartbeat: TimestampUtc,
}

impl RemoteWorkerNode {
    /// Creates a new disposable remote worker node in `Ready` state.
    pub fn new(
        worker_id: RemoteWorkerId,
        endpoint_url: impl Into<String>,
        architecture: WorkerArchitecture,
        containment: ContainmentLevel,
        resource_caps: WorkerResourceCaps,
        egress_policy: EgressPolicy,
    ) -> Self {
        Self {
            worker_id,
            endpoint_url: endpoint_url.into(),
            architecture,
            containment,
            resource_caps,
            egress_policy,
            state: WorkerState::Ready,
            last_heartbeat: TimestampUtc::now(),
        }
    }

    /// Returns whether this worker is ready to be leased.
    pub fn is_available(&self) -> bool {
        matches!(self.state, WorkerState::Ready)
    }

    /// Checks if this worker is currently leased to the specified tenant.
    pub fn is_leased_to(&self, target_tenant: &TenantId) -> bool {
        match &self.state {
            WorkerState::Leased { tenant_id, .. } => tenant_id == target_tenant,
            _ => false,
        }
    }

    /// Updates the worker's keepalive heartbeat timestamp.
    pub fn record_heartbeat(&mut self, timestamp: TimestampUtc) {
        self.last_heartbeat = timestamp;
    }

    /// Evaluates if the worker's heartbeat is stale relative to a timeout window.
    pub fn is_heartbeat_stale(&self, now: TimestampUtc, timeout_secs: u64) -> bool {
        let diff_millis = now
            .as_epoch_millis()
            .saturating_sub(self.last_heartbeat.as_epoch_millis());
        let diff_secs = diff_millis / 1000;
        diff_secs > timeout_secs
    }
}
