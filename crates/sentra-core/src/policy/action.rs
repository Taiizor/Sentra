use std::fmt;

use crate::{
    domain::{DomainError, classification::SecurityClassification},
    policy::budget::CostUsd,
};

/// Operation actions that can be requested within a Sentra session.
#[derive(Clone, Debug, PartialEq)]
pub enum OperationAction {
    /// Read-only metadata discovery (no target code execution).
    DiscoverMetadata {
        /// Relative path within the authorized workspace.
        relative_path: String,
    },
    /// Executing an analysis tool or scanner against code.
    ExecuteTool {
        /// Tool or scanner identifier.
        tool_id: String,
        /// Whether the tool executes untrusted target code.
        untrusted: bool,
        /// Command-line arguments passed to the tool.
        arguments: Vec<String>,
    },
    /// Invoking an AI model provider.
    InvokeProvider {
        /// Unique model identifier (e.g. mock-analysis-v1).
        model_id: String,
        /// Estimated cost in USD for this invocation.
        estimated_cost: CostUsd,
    },
    /// Exporting findings, reports, or evidence.
    ExportReport {
        /// Target destination or file path.
        destination: String,
        /// Whether the export egresses to an external system.
        is_external: bool,
        /// Optional classification of the destination system for flow checks.
        destination_classification: Option<SecurityClassification>,
    },
    /// Modifying files in the operator's checkout (sensitive action, S-10).
    ModifyCheckout {
        /// Number of files proposed to be modified.
        file_count: usize,
        /// Explicit list of target file paths proposed for modification.
        target_paths: Vec<String>,
    },
    /// An unknown or unrecognized operation (strictly denied by default).
    UnknownOperation {
        /// Name of the unrecognized operation.
        operation_name: String,
    },
}

impl OperationAction {
    /// Returns the canonical action name for audit and policy rules.
    pub fn action_name(&self) -> &'static str {
        match self {
            Self::DiscoverMetadata { .. } => "DISCOVER_METADATA",
            Self::ExecuteTool { .. } => "EXECUTE_TOOL",
            Self::InvokeProvider { .. } => "INVOKE_PROVIDER",
            Self::ExportReport { .. } => "EXPORT_REPORT",
            Self::ModifyCheckout { .. } => "MODIFY_CHECKOUT",
            Self::UnknownOperation { .. } => "UNKNOWN_OPERATION",
        }
    }

    /// Determines whether the operation is inherently sensitive, requiring explicit approval.
    pub fn is_sensitive(&self) -> bool {
        match self {
            Self::DiscoverMetadata { .. } => false,
            Self::ExecuteTool { .. } => true,
            Self::ModifyCheckout { .. } => true,
            Self::ExportReport { is_external, .. } => *is_external,
            Self::InvokeProvider { estimated_cost, .. } => *estimated_cost > CostUsd::ONE,
            Self::UnknownOperation { .. } => true,
        }
    }

    /// Reject missing or inconsistent operation parameters before authorization.
    /// This does not resolve filesystem paths or authorize target execution.
    pub fn validate(&self) -> Result<(), DomainError> {
        let name = |value: &str| !value.trim().is_empty() && !value.chars().any(char::is_control);
        let valid = match self {
            Self::DiscoverMetadata { relative_path } => name(relative_path),
            Self::ExecuteTool {
                tool_id, arguments, ..
            } => name(tool_id) && arguments.iter().all(|value| !value.contains('\0')),
            Self::InvokeProvider { model_id, .. } => name(model_id),
            Self::ExportReport { destination, .. } => name(destination),
            Self::ModifyCheckout {
                file_count,
                target_paths,
            } => {
                *file_count != 0
                    && *file_count == target_paths.len()
                    && target_paths.iter().all(|path| name(path))
            }
            Self::UnknownOperation { .. } => false,
        };
        if valid {
            Ok(())
        } else {
            Err(DomainError::ActionMalformed(
                "missing or inconsistent operation parameters".into(),
            ))
        }
    }

    /// Computes a deterministic canonical action descriptor string representing this action's identity and parameters.
    ///
    /// NOTE: This is a canonical structured descriptor representing the action parameters.
    /// Authorization integrity is enforced by the deterministic `ApprovalBroker`.
    ///
    /// Version 2 frames every variable string and list, including resource identifiers.
    /// Checkout path order is intentionally insignificant; argument order is significant.
    pub fn action_digest(&self) -> String {
        let field = |value: &str| format!("{}#{value}", value.len());
        let list = |values: &[String]| {
            format!(
                "{}[{}]",
                values.len(),
                values.iter().map(|value| field(value)).collect::<String>()
            )
        };
        match self {
            Self::DiscoverMetadata { relative_path } => {
                format!("action:v2:discover:{}", field(relative_path))
            }
            Self::ExecuteTool {
                tool_id,
                untrusted,
                arguments,
            } => {
                format!(
                    "action:v2:exec:{}:untrusted={}:args={}",
                    field(tool_id),
                    untrusted,
                    list(arguments)
                )
            }
            Self::InvokeProvider {
                model_id,
                estimated_cost,
            } => {
                format!(
                    "action:v2:provider:{}:microusd={}",
                    field(model_id),
                    estimated_cost.as_micro_usd()
                )
            }
            Self::ExportReport {
                destination,
                is_external,
                destination_classification,
            } => {
                let dst_class_str = match destination_classification {
                    Some(c) => c.as_str(),
                    None => "NONE",
                };
                format!(
                    "action:v2:export:{}:external={}:dst_class={}",
                    field(destination),
                    is_external,
                    dst_class_str
                )
            }
            Self::ModifyCheckout {
                file_count,
                target_paths,
            } => {
                let mut sorted_paths = target_paths.clone();
                sorted_paths.sort();
                format!(
                    "action:v2:modify_checkout:files={}:paths={}",
                    file_count,
                    list(&sorted_paths)
                )
            }
            Self::UnknownOperation { operation_name } => {
                format!("action:v2:unknown:{}", field(operation_name))
            }
        }
    }
}

impl fmt::Display for OperationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.action_digest())
    }
}
