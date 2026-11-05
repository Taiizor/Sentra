//! Configuration models for the Core Service layer.

use crate::{CostUsd, MAX_EVIDENCE_SIZE_BYTES};

/// Configuration parameters governing Core Service operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreServiceConfig {
    /// Maximum cost that can be automatically approved without human intervention.
    pub max_auto_budget: CostUsd,
    /// Maximum allowable evidence payload size in bytes.
    pub max_evidence_size_bytes: u64,
    /// Default task execution timeout in milliseconds.
    pub default_timeout_millis: u64,
    /// Optional whitelist of allowable MIME media types.
    pub allowed_media_types: Option<Vec<String>>,
}

impl Default for CoreServiceConfig {
    fn default() -> Self {
        Self {
            max_auto_budget: CostUsd::from_micro_usd(1_000_000), // $1.00
            max_evidence_size_bytes: MAX_EVIDENCE_SIZE_BYTES,    // 50 MiB
            default_timeout_millis: 60_000,                      // 60 seconds
            allowed_media_types: None,
        }
    }
}

impl CoreServiceConfig {
    /// Creates a new configuration builder with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Overrides maximum auto-budget threshold.
    pub fn with_max_auto_budget(mut self, budget: CostUsd) -> Self {
        self.max_auto_budget = budget;
        self
    }

    /// Overrides maximum allowable evidence size ceiling.
    pub fn with_max_evidence_size(mut self, size_bytes: u64) -> Self {
        self.max_evidence_size_bytes = size_bytes;
        self
    }

    /// Overrides default task timeout limit.
    pub fn with_default_timeout_millis(mut self, timeout_millis: u64) -> Self {
        self.default_timeout_millis = timeout_millis;
        self
    }

    /// Sets explicit media type allowlist.
    pub fn with_allowed_media_types(mut self, types: Vec<String>) -> Self {
        self.allowed_media_types = Some(types);
        self
    }
}
