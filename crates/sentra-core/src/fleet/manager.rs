//! Remote worker fleet coordinator, tenant leasing, and lifecycle isolation (REQ-F19, ADR-0004).

use crate::{
    dashboard::TenantContext,
    domain::time::TimestampUtc,
    fleet::{
        error::{FleetError, FleetErrorKind},
        worker::{RemoteWorkerId, RemoteWorkerNode, WorkerState},
    },
    verification::WorkerArchitecture,
};

/// Containment readiness of a worker fleet, as far as Sentra can establish it.
///
/// There is deliberately no "ready" variant: Sentra cannot yet verify a worker's isolation
/// boundary, so it never reports containment as ready.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainmentReadiness {
    /// No workers are registered, so nothing can run under worker containment.
    NoWorkers,
    /// Workers are registered, but none has attested containment evidence.
    Unattested,
}

impl ContainmentReadiness {
    /// Stable machine-readable label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoWorkers => "no_workers",
            Self::Unattested => "unattested",
        }
    }

    /// Whether untrusted execution may rely on worker containment. Never true without
    /// attestation evidence, which Sentra does not collect.
    pub const fn is_ready(&self) -> bool {
        match self {
            Self::NoWorkers | Self::Unattested => false,
        }
    }
}

/// High-level fleet manager coordinating remote disposable execution workers.
///
/// Enforces exclusive single-tenant worker leases, prevents cross-tenant contamination
/// via mandatory quarantine-and-reset lifecycles, and monitors worker keepalive heartbeats.
#[derive(Clone, Debug, Default)]
pub struct WorkerFleetManager {
    workers: Vec<RemoteWorkerNode>,
    lease_counter: u64,
}

impl WorkerFleetManager {
    /// Creates a new, empty worker fleet manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluates whether untrusted execution may rely on worker containment.
    ///
    /// A worker's declared [`crate::verification::ContainmentLevel`] is an operator claim.
    /// Sentra has no worker attestation protocol, so no fleet is ever reported as ready.
    pub fn containment_readiness(&self) -> ContainmentReadiness {
        if self.workers.is_empty() {
            ContainmentReadiness::NoWorkers
        } else {
            ContainmentReadiness::Unattested
        }
    }

    /// Registers a newly provisioned remote worker node into the fleet.
    pub fn register_worker(&mut self, worker: RemoteWorkerNode) -> Result<(), FleetError> {
        if self.workers.iter().any(|w| w.worker_id == worker.worker_id) {
            return Err(FleetError::new(
                FleetErrorKind::InvalidInput,
                format!(
                    "worker '{}' is already registered in the fleet",
                    worker.worker_id
                ),
            ));
        }
        self.workers.push(worker);
        Ok(())
    }

    /// Retrieves an immutable reference to a registered worker node.
    pub fn get_worker(&self, worker_id: &RemoteWorkerId) -> Result<&RemoteWorkerNode, FleetError> {
        self.workers
            .iter()
            .find(|w| w.worker_id == *worker_id)
            .ok_or_else(|| {
                FleetError::worker_not_found(format!("worker '{worker_id}' not found in fleet"))
            })
    }

    /// Leases an available worker matching the required architecture exclusively to the calling tenant.
    pub fn lease_worker(
        &mut self,
        context: &TenantContext,
        required_arch: WorkerArchitecture,
    ) -> Result<(RemoteWorkerId, String), FleetError> {
        let available_idx = self
            .workers
            .iter()
            .position(|w| w.is_available() && w.architecture == required_arch)
            .ok_or_else(|| {
                FleetError::worker_busy(format!(
                    "no available workers in fleet matching architecture '{:?}'",
                    required_arch
                ))
            })?;

        self.lease_counter = self.lease_counter.saturating_add(1);
        let lease_id = format!("lease-{:012x}", self.lease_counter);
        let worker_id = self.workers[available_idx].worker_id.clone();

        self.workers[available_idx].state = WorkerState::Leased {
            tenant_id: context.tenant_id().clone(),
            lease_id: lease_id.clone(),
            leased_at: TimestampUtc::now(),
        };

        Ok((worker_id, lease_id))
    }

    /// Verifies that the caller tenant has valid, exclusive access to a leased worker.
    ///
    /// Fails closed with `CrossTenantWorkerAccessDenied` if the worker is leased to a different tenant.
    pub fn verify_worker_access(
        &self,
        context: &TenantContext,
        worker_id: &RemoteWorkerId,
        lease_id: &str,
    ) -> Result<(), FleetError> {
        let worker = self.get_worker(worker_id)?;

        match &worker.state {
            WorkerState::Leased {
                tenant_id,
                lease_id: active_lease,
                ..
            } => {
                if tenant_id != context.tenant_id() {
                    return Err(FleetError::cross_tenant_denied(format!(
                        "cross-tenant worker access denied: worker '{worker_id}' is leased to tenant '{tenant_id}', not caller tenant '{}'",
                        context.tenant_id()
                    )));
                }

                if active_lease != lease_id {
                    return Err(FleetError::new(
                        FleetErrorKind::InvalidInput,
                        format!("mismatched lease ID for worker '{worker_id}'"),
                    ));
                }

                Ok(())
            }
            WorkerState::Ready => Err(FleetError::worker_busy(format!(
                "worker '{worker_id}' is idle and not currently leased"
            ))),
            WorkerState::Quarantined { reason } => Err(FleetError::quarantined(format!(
                "worker '{worker_id}' is quarantined: {reason}"
            ))),
            WorkerState::Provisioning => Err(FleetError::worker_busy(format!(
                "worker '{worker_id}' is currently provisioning"
            ))),
            WorkerState::Terminated => Err(FleetError::worker_not_found(format!(
                "worker '{worker_id}' has been terminated"
            ))),
        }
    }

    /// Releases a tenant's lease and immediately transitions the worker into `Quarantined`.
    ///
    /// To guarantee zero cross-tenant contamination, released workers cannot be re-leased
    /// until they undergo an explicit `sanitize_and_reset_worker` boundary purge.
    pub fn release_and_quarantine_worker(
        &mut self,
        context: &TenantContext,
        worker_id: &RemoteWorkerId,
        lease_id: &str,
    ) -> Result<(), FleetError> {
        self.verify_worker_access(context, worker_id, lease_id)?;

        let worker = self
            .workers
            .iter_mut()
            .find(|w| w.worker_id == *worker_id)
            .ok_or_else(|| FleetError::worker_not_found("worker not found"))?;

        worker.state = WorkerState::Quarantined {
            reason: format!(
                "Lease '{lease_id}' released by tenant '{}'; pending reset",
                context.tenant_id()
            ),
        };

        Ok(())
    }

    /// Sanitizes a quarantined worker and restores it to `Ready` status.
    ///
    /// Simulates or executes the disposable VM boundary reset (memory wipe and ephemeral disk reset).
    pub fn sanitize_and_reset_worker(
        &mut self,
        worker_id: &RemoteWorkerId,
    ) -> Result<(), FleetError> {
        let worker = self
            .workers
            .iter_mut()
            .find(|w| w.worker_id == *worker_id)
            .ok_or_else(|| FleetError::worker_not_found("worker not found"))?;

        match &worker.state {
            WorkerState::Quarantined { .. } | WorkerState::Provisioning => {
                worker.state = WorkerState::Ready;
                worker.last_heartbeat = TimestampUtc::now();
                Ok(())
            }
            WorkerState::Leased { .. } => Err(FleetError::worker_busy(format!(
                "cannot sanitize worker '{worker_id}': worker is actively leased"
            ))),
            WorkerState::Ready => Ok(()),
            WorkerState::Terminated => Err(FleetError::worker_not_found(format!(
                "cannot sanitize terminated worker '{worker_id}'"
            ))),
        }
    }

    /// Updates the heartbeat timestamp for a registered worker node.
    pub fn record_heartbeat(
        &mut self,
        worker_id: &RemoteWorkerId,
        timestamp: TimestampUtc,
    ) -> Result<(), FleetError> {
        let worker = self
            .workers
            .iter_mut()
            .find(|w| w.worker_id == *worker_id)
            .ok_or_else(|| FleetError::worker_not_found("worker not found"))?;

        worker.record_heartbeat(timestamp);
        Ok(())
    }

    /// Quarantines any workers whose keepalive heartbeat has exceeded the timeout threshold.
    pub fn reap_stale_heartbeats(&mut self, now: TimestampUtc, timeout_secs: u64) -> usize {
        let mut count = 0;
        for w in &mut self.workers {
            if matches!(w.state, WorkerState::Ready | WorkerState::Leased { .. })
                && w.is_heartbeat_stale(now, timeout_secs)
            {
                w.state = WorkerState::Quarantined {
                    reason: format!("Heartbeat timeout exceeded (> {}s)", timeout_secs),
                };
                count += 1;
            }
        }
        count
    }

    /// Total count of registered workers in the fleet.
    pub fn total_workers(&self) -> usize {
        self.workers.len()
    }

    /// Count of workers currently in `Ready` state.
    pub fn available_workers(&self) -> usize {
        self.workers.iter().filter(|w| w.is_available()).count()
    }

    /// Count of workers actively leased to tenants.
    pub fn active_leases(&self) -> usize {
        self.workers
            .iter()
            .filter(|w| matches!(w.state, WorkerState::Leased { .. }))
            .count()
    }

    /// Count of workers currently quarantined.
    pub fn quarantined_workers(&self) -> usize {
        self.workers
            .iter()
            .filter(|w| matches!(w.state, WorkerState::Quarantined { .. }))
            .count()
    }

    /// Iterates over all workers in the fleet.
    pub fn iter_workers(&self) -> impl Iterator<Item = &RemoteWorkerNode> {
        self.workers.iter()
    }
}
