use std::fmt;

use crate::domain::error::DomainError;

/// Represents a non-negative monetary cost in USD with micro-dollar resolution (1 USD = 1,000,000 micro-USD).
///
/// Designed specifically to eliminate floating-point representation errors, negative amount bypasses,
/// and IEEE-754 NaN/Infinity comparison vulnerabilities in security policy decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CostUsd {
    micro_usd: u64,
}

impl CostUsd {
    /// Zero USD.
    pub const ZERO: Self = Self { micro_usd: 0 };
    /// One USD ($1.00).
    pub const ONE: Self = Self {
        micro_usd: 1_000_000,
    };

    /// Creates a CostUsd from raw integer micro-dollars.
    pub const fn from_micro_usd(micro_usd: u64) -> Self {
        Self { micro_usd }
    }

    /// Creates a CostUsd from whole cents ($0.01 = 10,000 micro-USD).
    pub const fn from_cents(cents: u64) -> Self {
        Self {
            micro_usd: cents.saturating_mul(10_000),
        }
    }

    /// Safely parses and validates a floating-point USD amount.
    ///
    /// Fails closed if the amount is NaN, infinite, negative, or overflows `u64`.
    pub fn from_usd_f64(usd: f64) -> Result<Self, DomainError> {
        if usd.is_nan() {
            return Err(DomainError::InvalidCost(
                "NaN cost is rejected; monetary amounts must be valid numbers".to_string(),
            ));
        }
        if usd.is_infinite() {
            return Err(DomainError::InvalidCost(
                "infinite cost is rejected; monetary amounts must be finite".to_string(),
            ));
        }
        if usd < 0.0 {
            return Err(DomainError::InvalidCost(format!(
                "negative cost ${usd:.4} is rejected; costs must be non-negative"
            )));
        }
        let micro = (usd * 1_000_000.0).round();
        if micro > (u64::MAX as f64) {
            return Err(DomainError::InvalidCost(
                "cost overflows maximum representable micro-dollar bounds".to_string(),
            ));
        }
        Ok(Self {
            micro_usd: micro as u64,
        })
    }

    /// Returns the integer micro-dollar value.
    pub const fn as_micro_usd(&self) -> u64 {
        self.micro_usd
    }

    /// Converts to floating-point USD representation for human display.
    pub fn as_usd_f64(&self) -> f64 {
        (self.micro_usd as f64) / 1_000_000.0
    }

    /// Checked addition preventing overflow.
    pub fn checked_add(&self, other: Self) -> Option<Self> {
        self.micro_usd
            .checked_add(other.micro_usd)
            .map(Self::from_micro_usd)
    }

    /// Saturating addition.
    pub const fn saturating_add(&self, other: Self) -> Self {
        Self::from_micro_usd(self.micro_usd.saturating_add(other.micro_usd))
    }

    /// Checked subtraction preventing underflow.
    pub fn checked_sub(&self, other: Self) -> Option<Self> {
        self.micro_usd
            .checked_sub(other.micro_usd)
            .map(Self::from_micro_usd)
    }

    /// Saturating subtraction.
    pub const fn saturating_sub(&self, other: Self) -> Self {
        Self::from_micro_usd(self.micro_usd.saturating_sub(other.micro_usd))
    }
}

impl fmt::Display for CostUsd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "${:.4}", self.as_usd_f64())
    }
}

/// Validated policy configuration for monetary budgets and automated execution thresholds.
#[derive(Clone, Debug, PartialEq)]
pub struct BudgetPolicyConfig {
    /// Maximum cost that can be automatically approved without human grant.
    pub max_auto_budget: CostUsd,
    /// Absolute ceiling for any single operation; operations exceeding this cannot be approved automatically.
    pub max_request_ceiling: Option<CostUsd>,
    /// Whether untrusted tool executions always require human approval regardless of budget.
    pub require_approval_for_untrusted_tools: bool,
    /// Whether external report egress always requires human approval.
    pub require_approval_for_external_egress: bool,
}

impl Default for BudgetPolicyConfig {
    fn default() -> Self {
        Self {
            max_auto_budget: CostUsd::from_cents(100), // $1.00
            max_request_ceiling: Some(CostUsd::from_cents(5000)), // $50.00
            require_approval_for_untrusted_tools: true,
            require_approval_for_external_egress: true,
        }
    }
}

impl BudgetPolicyConfig {
    /// Constructs a budget policy configuration with explicit auto-budget ceiling.
    pub fn new(max_auto_budget: CostUsd) -> Self {
        Self {
            max_auto_budget,
            ..Default::default()
        }
    }

    /// Validates internal consistency of the configuration invariants.
    pub fn validate(&self) -> Result<(), DomainError> {
        if let Some(ceiling) = self.max_request_ceiling
            && self.max_auto_budget > ceiling
        {
            return Err(DomainError::InvalidCost(format!(
                "max_auto_budget ({}) cannot exceed max_request_ceiling ({})",
                self.max_auto_budget, ceiling
            )));
        }
        Ok(())
    }
}
