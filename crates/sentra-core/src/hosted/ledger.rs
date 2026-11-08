//! Delivery ledger for webhook deduplication and replay attack prevention (REQ-F18, THREAT_MODEL T-11).

use std::collections::HashMap;

use crate::{
    domain::TimestampUtc,
    hosted::{error::WebhookError, provider::HostedProvider},
};

/// Default maximum allowable clock drift for incoming webhook payloads (300 seconds / 5 minutes).
pub const DEFAULT_MAX_DRIFT_SECS: u64 = 300;

/// Default maximum capacity of the in-memory delivery ledger before pruning expired entries.
pub const DEFAULT_MAX_LEDGER_CAPACITY: usize = 10_000;

/// Immutable record of a processed webhook delivery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryRecord {
    /// Delivery / event identifier.
    pub event_id: String,
    /// Originating hosted provider.
    pub provider: HostedProvider,
    /// Ingestion timestamp.
    pub received_at: TimestampUtc,
}

/// Delivery ledger tracking recent webhook delivery IDs to guarantee idempotency and prevent replays.
#[derive(Clone, Debug)]
pub struct DeliveryLedger {
    records: HashMap<String, DeliveryRecord>,
    max_drift_secs: u64,
    max_capacity: usize,
}

impl Default for DeliveryLedger {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_DRIFT_SECS, DEFAULT_MAX_LEDGER_CAPACITY)
    }
}

impl DeliveryLedger {
    /// Constructs a new delivery ledger with specified drift window and capacity limits.
    pub fn new(max_drift_secs: u64, max_capacity: usize) -> Self {
        Self {
            records: HashMap::new(),
            max_drift_secs,
            max_capacity,
        }
    }

    /// Returns the number of tracked delivery records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Checks if the ledger is currently empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Records a new delivery into the ledger, enforcing freshness and replay protection.
    pub fn record_delivery(
        &mut self,
        event_id: &str,
        provider: HostedProvider,
        event_timestamp: Option<TimestampUtc>,
        now: TimestampUtc,
    ) -> Result<(), WebhookError> {
        let trimmed_id = event_id.trim();
        if trimmed_id.is_empty() {
            return Err(WebhookError::malformed_payload(
                "Missing or empty webhook delivery identifier",
            ));
        }

        // 1. Replay check
        if self.records.contains_key(trimmed_id) {
            return Err(WebhookError::replay_detected(trimmed_id));
        }

        // 2. Timestamp freshness check (if event timestamp was provided)
        if let Some(ts) = event_timestamp {
            let diff_millis = if now.as_epoch_millis() >= ts.as_epoch_millis() {
                now.as_epoch_millis() - ts.as_epoch_millis()
            } else {
                ts.as_epoch_millis() - now.as_epoch_millis()
            };
            let diff_secs = diff_millis / 1000;
            if diff_secs > self.max_drift_secs {
                return Err(WebhookError::timestamp_drift(
                    diff_secs,
                    self.max_drift_secs,
                ));
            }
        }

        // 3. Prune expired entries if capacity ceiling is reached
        if self.records.len() >= self.max_capacity {
            let threshold_millis = now
                .as_epoch_millis()
                .saturating_sub(self.max_drift_secs.saturating_mul(2000));
            self.records
                .retain(|_, r| r.received_at.as_epoch_millis() >= threshold_millis);
        }

        // 4. Record entry
        self.records.insert(
            trimmed_id.to_string(),
            DeliveryRecord {
                event_id: trimmed_id.to_string(),
                provider,
                received_at: now,
            },
        );

        Ok(())
    }
}
