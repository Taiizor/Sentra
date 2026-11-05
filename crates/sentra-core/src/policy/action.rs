use std::fmt;

use crate::{domain::classification::SecurityClassification, policy::budget::CostUsd};

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

    /// Computes a deterministic canonical action descriptor string representing this action's identity and parameters.
    ///
    /// NOTE: This is a canonical structured descriptor, NOT a cryptographic hash or signature.
    /// In Phase 1 Increment 5.2, authorization integrity is maintained by trusted in-memory state in
    /// `ApprovalBroker`. Cryptographic hashing (SHA-256) is scheduled for Increment 5.4.
    ///
    /// Argument and path lists use length-prefixed encoding (`len#value`) to prevent delimiter-injection
    /// collisions (e.g. distinguishing `["a,b", "c"]` from `["a", "b,c"]`).
    pub fn action_digest(&self) -> String {
        match self {
            Self::DiscoverMetadata { relative_path } => {
                format!("action:discover:{}#{}", relative_path.len(), relative_path)
            }
            Self::ExecuteTool {
                tool_id,
                untrusted,
                arguments,
            } => {
                let args_encoded: Vec<String> = arguments
                    .iter()
                    .map(|a| format!("{}#{}", a.len(), a))
                    .collect();
                format!(
                    "action:exec:{}:untrusted={}:args=[{}]",
                    tool_id,
                    untrusted,
                    args_encoded.join(",")
                )
            }
            Self::InvokeProvider {
                model_id,
                estimated_cost,
            } => {
                format!(
                    "action:provider:{}:microusd={}",
                    model_id,
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
                    None => "UNSPECIFIED",
                };
                format!(
                    "action:export:{}#{}:external={}:dst_class={}",
                    destination.len(),
                    destination,
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
                let paths_encoded: Vec<String> = sorted_paths
                    .iter()
                    .map(|p| format!("{}#{}", p.len(), p))
                    .collect();
                format!(
                    "action:modify_checkout:files={}:paths=[{}]",
                    file_count,
                    paths_encoded.join(",")
                )
            }
            Self::UnknownOperation { operation_name } => {
                format!("action:unknown:{}", operation_name)
            }
        }
    }
}

impl fmt::Display for OperationAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.action_digest())
    }
}
