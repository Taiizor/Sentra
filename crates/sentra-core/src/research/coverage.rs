//! Coverage ledger recording visited surfaces, audit coverage, and explicitly skipped regions (REQ-F04, Autonomous Research Specification).

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::HashMap, str::FromStr};

use crate::{
    domain::{id::TaskId, time::TimestampUtc},
    research::role::ResearchRole,
};

/// Specific rationale for skipping an audit target, file, or code region.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// Outside the explicitly configured campaign or session scope.
    OutOfScope,
    /// Build or compilation failed; cannot instrument or test.
    UnbuildableTarget,
    /// Language or runtime is not supported by available workers.
    LanguageUnsupported,
    /// Budget exhausted before region could be investigated.
    BudgetExhaustion,
    /// Execution time ceiling reached during exploration.
    TimeoutCeiling,
    /// Blocked by security policy or lack of human approval.
    PolicyExcluded,
    /// Target exhibits nondeterministic crashes or flaky execution.
    NonDeterministicCrash,
}

impl SkipReason {
    /// Returns static string representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::OutOfScope => "out_of_scope",
            Self::UnbuildableTarget => "unbuildable_target",
            Self::LanguageUnsupported => "language_unsupported",
            Self::BudgetExhaustion => "budget_exhaustion",
            Self::TimeoutCeiling => "timeout_ceiling",
            Self::PolicyExcluded => "policy_excluded",
            Self::NonDeterministicCrash => "nondeterministic_crash",
        }
    }
}

/// An explicitly recorded skipped region with justification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedRegion {
    /// Target file path relative to workspace root.
    pub target_path: String,
    /// Optional symbol or function name.
    pub symbol_name: Option<String>,
    /// Categorized skip reason.
    pub reason: SkipReason,
    /// Explicit explanatory rationale.
    pub rationale: String,
    /// Timestamp when skip was recorded.
    pub recorded_at: TimestampUtc,
}

#[derive(Serialize, Deserialize)]
struct SkippedRegionPayload {
    target_path: String,
    symbol_name: Option<String>,
    reason: SkipReason,
    rationale: String,
    recorded_at: String,
}

impl Serialize for SkippedRegion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let payload = SkippedRegionPayload {
            target_path: self.target_path.clone(),
            symbol_name: self.symbol_name.clone(),
            reason: self.reason,
            rationale: self.rationale.clone(),
            recorded_at: self.recorded_at.to_string(),
        };
        payload.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SkippedRegion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let payload = SkippedRegionPayload::deserialize(deserializer)?;
        let recorded_at =
            TimestampUtc::from_str(&payload.recorded_at).map_err(serde::de::Error::custom)?;

        Ok(Self {
            target_path: payload.target_path,
            symbol_name: payload.symbol_name,
            reason: payload.reason,
            rationale: payload.rationale,
            recorded_at,
        })
    }
}

/// A verified covered region explored by a research task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoveredRegion {
    /// Target file path relative to workspace root.
    pub target_path: String,
    /// Optional symbol or function name.
    pub symbol_name: Option<String>,
    /// Number of lines analyzed or instrumented.
    pub lines_covered: u32,
    /// Role that explored this region.
    pub role: ResearchRole,
    /// Task that performed the exploration.
    pub task_id: TaskId,
    /// Timestamp when coverage was confirmed.
    pub recorded_at: TimestampUtc,
}

#[derive(Serialize, Deserialize)]
struct CoveredRegionPayload {
    target_path: String,
    symbol_name: Option<String>,
    lines_covered: u32,
    role: ResearchRole,
    task_id: String,
    recorded_at: String,
}

impl Serialize for CoveredRegion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let payload = CoveredRegionPayload {
            target_path: self.target_path.clone(),
            symbol_name: self.symbol_name.clone(),
            lines_covered: self.lines_covered,
            role: self.role,
            task_id: self.task_id.to_string(),
            recorded_at: self.recorded_at.to_string(),
        };
        payload.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CoveredRegion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let payload = CoveredRegionPayload::deserialize(deserializer)?;
        let task_id = TaskId::from_str(&payload.task_id).map_err(serde::de::Error::custom)?;
        let recorded_at =
            TimestampUtc::from_str(&payload.recorded_at).map_err(serde::de::Error::custom)?;

        Ok(Self {
            target_path: payload.target_path,
            symbol_name: payload.symbol_name,
            lines_covered: payload.lines_covered,
            role: payload.role,
            task_id,
            recorded_at,
        })
    }
}

/// High-level coverage statistics and uncertainty summary.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CoverageSummary {
    /// Total distinct targets considered (covered + skipped).
    pub total_targets: usize,
    /// Count of successfully covered targets.
    pub covered_count: usize,
    /// Count of skipped targets.
    pub skipped_count: usize,
    /// Ratio of covered targets to total considered (0.0 to 1.0).
    pub coverage_ratio: f64,
    /// Detailed count breakdown by skip reason.
    pub skip_breakdown: HashMap<SkipReason, usize>,
}

/// Bounded coverage ledger tracking surface exploration progress (REQ-F04).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CoverageLedger {
    /// Covered target records.
    pub covered_regions: Vec<CoveredRegion>,
    /// Skipped target records with documented reasons.
    pub skipped_regions: Vec<SkippedRegion>,
}

impl CoverageLedger {
    /// Creates a new empty coverage ledger.
    pub fn new() -> Self {
        Self {
            covered_regions: Vec::new(),
            skipped_regions: Vec::new(),
        }
    }

    /// Records a covered region.
    pub fn record_covered(
        &mut self,
        target_path: impl Into<String>,
        symbol_name: Option<String>,
        lines_covered: u32,
        role: ResearchRole,
        task_id: TaskId,
        now: TimestampUtc,
    ) {
        self.covered_regions.push(CoveredRegion {
            target_path: target_path.into(),
            symbol_name,
            lines_covered,
            role,
            task_id,
            recorded_at: now,
        });
    }

    /// Records an explicitly skipped region with rationale.
    pub fn record_skipped(
        &mut self,
        target_path: impl Into<String>,
        symbol_name: Option<String>,
        reason: SkipReason,
        rationale: impl Into<String>,
        now: TimestampUtc,
    ) {
        self.skipped_regions.push(SkippedRegion {
            target_path: target_path.into(),
            symbol_name,
            reason,
            rationale: rationale.into(),
            recorded_at: now,
        });
    }

    /// Calculates aggregate coverage metrics.
    pub fn summary(&self) -> CoverageSummary {
        let covered_count = self.covered_regions.len();
        let skipped_count = self.skipped_regions.len();
        let total_targets = covered_count + skipped_count;

        let coverage_ratio = if total_targets == 0 {
            0.0
        } else {
            covered_count as f64 / total_targets as f64
        };

        let mut skip_breakdown = HashMap::new();
        for s in &self.skipped_regions {
            *skip_breakdown.entry(s.reason).or_insert(0) += 1;
        }

        CoverageSummary {
            total_targets,
            covered_count,
            skipped_count,
            coverage_ratio,
            skip_breakdown,
        }
    }
}
