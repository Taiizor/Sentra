use std::fmt;

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
        estimated_cost_usd: f64,
    },
    /// Exporting findings, reports, or evidence.
    ExportReport {
        /// Target destination or file path.
        destination: String,
        /// Whether the export egresses to an external system.
        is_external: bool,
    },
    /// Modifying files in the operator's checkout (sensitive action, S-10).
    ModifyCheckout {
        /// Number of files proposed to be modified.
        file_count: usize,
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
            Self::InvokeProvider {
                estimated_cost_usd, ..
            } => *estimated_cost_usd > 1.0,
            Self::UnknownOperation { .. } => true,
        }
    }

    /// Computes a deterministic digest string representing this action's identity and parameters.
    /// This digest is cryptographically bound to approval grants (S-02).
    pub fn action_digest(&self) -> String {
        match self {
            Self::DiscoverMetadata { relative_path } => {
                format!("action:discover:{}", relative_path)
            }
            Self::ExecuteTool {
                tool_id,
                untrusted,
                arguments,
            } => {
                format!(
                    "action:exec:{}:untrusted={}:args={}",
                    tool_id,
                    untrusted,
                    arguments.join(",")
                )
            }
            Self::InvokeProvider {
                model_id,
                estimated_cost_usd,
            } => {
                format!(
                    "action:provider:{}:cost={:.4}",
                    model_id, estimated_cost_usd
                )
            }
            Self::ExportReport {
                destination,
                is_external,
            } => {
                format!("action:export:{}:external={}", destination, is_external)
            }
            Self::ModifyCheckout { file_count } => {
                format!("action:modify_checkout:files={}", file_count)
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
