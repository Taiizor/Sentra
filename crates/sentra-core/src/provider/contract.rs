//! Capability-scoped model provider contract types and interfaces (REQ-F03, REQ-F08, ADR-0005).

use std::{collections::BTreeMap, fmt};

/// Sensitivity classification of data being evaluated by a provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataClass {
    /// Publicly accessible open-source code or documentation.
    Public,
    /// Proprietary or private source code subject to egress restrictions.
    PrivateSource,
    /// Discovered candidate vulnerability or security finding.
    SecurityFinding,
    /// Credentials, API keys, or private keys (strictly forbidden from remote egress).
    Secret,
}

/// Execution location and hosting topology of a model backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Location {
    /// Local machine or private dedicated worker (zero external egress).
    Local,
    /// Remote hosted cloud service or API endpoint.
    Remote,
}

/// Declared capabilities supported by a model adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    /// Whether the model supports structured JSON/schema constrained outputs.
    pub structured: bool,
    /// Whether the model supports token streaming.
    pub streaming: bool,
    /// Whether the model supports streaming constrained to structured schemas.
    pub structured_streaming: bool,
    /// Whether active inference operations can be cleanly cancelled.
    pub cancellation: bool,
    /// Whether offline or pre-request token counting is supported.
    pub token_counting: bool,
    /// Whether detailed input/output token usage is reported with completions.
    pub usage: bool,
}

/// Synthetic or configured pricing rates in micro-USD per token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rates {
    /// Cost per input token in micro-USD.
    pub input: u64,
    /// Cost per output token in micro-USD.
    pub output: u64,
}

/// Static capability and limit descriptor for an individual model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    /// Unique model identifier (e.g. `mock-eval-1` or `local-llama-3`).
    pub id: String,
    /// Hosting location (Local or Remote).
    pub location: Location,
    /// Supported capability flags.
    pub capabilities: Capabilities,
    /// Maximum context window size in tokens.
    pub context_tokens: u64,
    /// Maximum byte size permitted for prompt inputs.
    pub max_input_bytes: usize,
    /// Maximum number of tokens the model can generate per completion.
    pub max_output_tokens: u64,
    /// Maximum response payload byte limit.
    pub max_response_bytes: usize,
    /// Pricing rates for budget estimation, if applicable.
    pub rates: Option<Rates>,
}

/// Expected output structure format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// Free-form unstructured text.
    Text,
    /// Canonical Decision V1 schema (`{ "accepted": bool, "summary": string }`).
    DecisionV1,
}

/// Typed completion request dispatched to a model provider.
#[derive(Clone)]
pub struct Request {
    /// Monotonic request identifier.
    pub id: u64,
    /// Target model identifier.
    pub model: String,
    /// Raw prompt input string.
    pub input: String,
    /// Data sensitivity classification.
    pub classification: DataClass,
    /// Expected response format.
    pub format: Format,
    /// Whether to stream intermediate chunks.
    pub stream: bool,
    /// Maximum output tokens allowed.
    pub max_output_tokens: u64,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("id", &self.id)
            .field("model", &self.model)
            .field("input", &"[redacted]")
            .field("classification", &self.classification)
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}

/// Typed structured value representation for schema validation.
#[derive(Clone, PartialEq, Eq)]
pub enum Value {
    /// Text string.
    Text(String),
    /// Boolean flag.
    Bool(bool),
    /// Integer number.
    Number(i64),
    /// Map of key-value pairs.
    Object(BTreeMap<String, Value>),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Value([redacted])")
    }
}

/// Response payload from an inference operation.
#[derive(Clone, PartialEq, Eq)]
pub enum Body {
    /// Plaintext response string.
    Text(String),
    /// Structured data value.
    Structured(Value),
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Body([redacted])")
    }
}

impl Body {
    /// Calculates the aggregate byte size of the payload.
    pub fn byte_size(&self) -> Result<usize, ErrorKind> {
        fn size(value: &Value, depth: usize) -> Result<usize, ErrorKind> {
            if depth > 4 {
                return Err(ErrorKind::InvalidOutput);
            }
            match value {
                Value::Text(text) => Ok(text.len()),
                Value::Bool(_) => Ok(1),
                Value::Number(_) => Ok(8),
                Value::Object(fields) => fields.iter().try_fold(0usize, |sum, (key, value)| {
                    sum.checked_add(key.len())
                        .and_then(|n| n.checked_add(size(value, depth + 1).ok()?))
                        .ok_or(ErrorKind::InvalidOutput)
                }),
            }
        }
        match self {
            Self::Text(text) => Ok(text.len()),
            Self::Structured(value) => size(value, 0),
        }
    }

    /// Validates payload conformance against expected format specification.
    pub fn validate(&self, format: Format) -> Result<(), ErrorKind> {
        match (self, format) {
            (Self::Text(_), Format::Text) => Ok(()),
            (Self::Structured(Value::Object(fields)), Format::DecisionV1) if fields.len() == 2 => {
                match (fields.get("summary"), fields.get("accepted")) {
                    (Some(Value::Text(summary)), Some(Value::Bool(_)))
                        if !summary.trim().is_empty() && summary.len() <= 256 =>
                    {
                        Ok(())
                    }
                    _ => Err(ErrorKind::InvalidOutput),
                }
            }
            _ => Err(ErrorKind::InvalidOutput),
        }
    }
}

/// Measured token usage counts for an attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Usage {
    /// Tokens consumed by prompt input.
    pub input_tokens: u64,
    /// Tokens generated in completion output.
    pub output_tokens: u64,
}

/// Failure categories returned by provider adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// Provider is not configured or registered.
    NotConfigured,
    /// Provider has not been initialized.
    NotInitialized,
    /// Provider has been closed.
    Closed,
    /// Operation denied by policy engine.
    PolicyDenied,
    /// Requested capability is unsupported by the model.
    Unsupported,
    /// Requested model ID is unknown.
    UnknownModel,
    /// Input byte size or token count exceeds model ceiling.
    InputLimit,
    /// Total context window limit exceeded.
    ContextLimit,
    /// Output generation limit exceeded.
    OutputLimit,
    /// Response payload does not conform to requested schema format.
    InvalidOutput,
    /// Underlying protocol error or invalid response envelope.
    Protocol,
    /// Request timed out before completion.
    Timeout,
    /// Operation was cancelled.
    Cancelled,
    /// Provider rate limit or concurrency throttle exceeded.
    RateLimited,
    /// Authentication or credential failure.
    Authentication,
    /// Provider service is temporarily unavailable.
    Unavailable,
    /// Unspecified internal provider error.
    Internal,
    /// Cost could not be estimated or determined.
    CostUnknown,
    /// Budget reservation exceeded available funds.
    BudgetExceeded,
    /// Reported usage metrics violated invariants.
    InvalidUsage,
    /// Numeric arithmetic overflow during accounting.
    Arithmetic,
}

/// Strongly typed failure envelope with optional capability or cancellation details.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    /// Primary error category.
    pub kind: ErrorKind,
    /// Specific unsupported feature, if applicable.
    pub unsupported_feature: Option<Feature>,
    /// Whether cancellation was confirmed by backend.
    pub cancellation_confirmed: Option<bool>,
}

/// Feature flags for capability validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feature {
    /// Structured output formatting.
    StructuredOutput,
    /// Text streaming.
    TextStreaming,
    /// Structured schema streaming.
    StructuredStreaming,
    /// Cancellation support.
    Cancellation,
    /// Token counting.
    TokenCounting,
    /// Usage reporting.
    UsageReporting,
}

impl Failure {
    /// Constructs an unsupported feature failure.
    pub fn unsupported(feature: Feature) -> Self {
        Self {
            kind: ErrorKind::Unsupported,
            unsupported_feature: Some(feature),
            cancellation_confirmed: None,
        }
    }
}

impl From<ErrorKind> for Failure {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            unsupported_feature: None,
            cancellation_confirmed: None,
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "provider operation failed: {:?}", self.kind)
    }
}

impl std::error::Error for Failure {}

/// Gateway execution policy governing model interaction parameters.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Requires operator or service explicit initiation.
    pub explicitly_initiated: bool,
    /// Permits metadata inspection.
    pub metadata: bool,
    /// Permits model inference dispatch.
    pub inference: bool,
    /// Permits remote network egress.
    pub remote_egress: bool,
    /// Permits classified data input.
    pub classified_input: bool,
    /// Requires verified usage reporting.
    pub require_usage: bool,
    /// Requires cancellation support.
    pub require_cancellation: bool,
    /// Maximum allowed input byte length.
    pub max_input_bytes: usize,
    /// Maximum allowed output byte length.
    pub max_output_bytes: usize,
    /// Milliseconds before request is aborted due to timeout.
    pub timeout_ms: u64,
    /// Maximum retry attempts for transient errors.
    pub max_attempts: u32,
    /// Maximum exponential backoff delay in milliseconds.
    pub max_retry_delay_ms: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            explicitly_initiated: false,
            metadata: false,
            inference: false,
            remote_egress: false,
            classified_input: false,
            require_usage: true,
            require_cancellation: true,
            max_input_bytes: 1024,
            max_output_bytes: 1024,
            timeout_ms: 20,
            max_attempts: 1,
            max_retry_delay_ms: 10,
        }
    }
}

/// Structured diagnostic event codes recorded during gateway operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticCode {
    /// Gateway initialized.
    Initialized,
    /// Models discovered.
    Discovered,
    /// Request dispatched.
    Dispatched,
    /// Request retrying after transient failure.
    Retrying,
    /// Request completed.
    Completed,
    /// Request rejected by policy or limits.
    Rejected,
    /// Request stopped or cancelled.
    Stopped,
}

/// Single diagnostic entry recorded in the gateway ring buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    /// Event category code.
    pub code: DiagnosticCode,
    /// Attempt index (1-based).
    pub attempt: u32,
    /// Error category, if applicable.
    pub error: Option<ErrorKind>,
}

/// Terminal completion response returned by the gateway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// Response body payload.
    pub body: Body,
    /// Input data sensitivity classification.
    pub classification: DataClass,
    /// Verified usage metrics, if reported by backend.
    pub usage: Option<Usage>,
    /// Settled actual cost in micro-USD, if usage reporting was complete.
    pub cost_actual_micro_usd: Option<u64>,
    /// Observed actual cost settled during execution.
    pub observed_cost_micro_usd: u64,
    /// Budget amount held conservatively for unconfirmed or unsettled attempts.
    pub held_unknown_micro_usd: u64,
    /// Whether all attempts had complete and valid usage reporting.
    pub usage_complete: bool,
    /// Number of attempts made to complete the request.
    pub attempts: u32,
    /// Milliseconds elapsed during execution.
    pub elapsed_ms: u64,
    /// Number of streaming chunks received.
    pub stream_chunks: u32,
}

/// Intermediate progress state reported by an active operation.
pub enum Progress {
    /// Operation is active and waiting.
    Pending,
    /// Streaming text fragment available.
    Chunk {
        /// Sequence index of the streaming chunk.
        sequence: u32,
        /// Streaming text delta.
        text: String,
    },
    /// Operation reached successful completion.
    Done {
        /// Generating model ID.
        model: String,
        /// Response payload.
        body: Body,
        /// Usage counts, if reported.
        usage: Option<Usage>,
    },
    /// Operation terminated in failure.
    Failed {
        /// Failure classification.
        kind: ErrorKind,
        /// Retry delay suggested by backend.
        retry_after_ms: Option<u64>,
        /// Incurred token usage prior to failure.
        usage: Option<Usage>,
        /// Whether the failure is safe to retry.
        safe_to_retry: bool,
    },
}

/// Receipt confirming cancellation status.
pub struct CancelReceipt {
    /// Whether backend confirmed cancellation.
    pub confirmed: bool,
    /// Partial usage incurred up to cancellation point.
    pub usage: Option<Usage>,
}

/// Stateful handle representing an active model inference operation.
pub trait Operation {
    /// Polls current execution progress.
    fn poll(&mut self, now_ms: u64) -> Progress;
    /// Signals cooperative cancellation.
    fn cancel(&mut self) -> CancelReceipt;
}

/// Adapter-neutral boundary for model backends (ADR-0005).
pub trait Provider {
    /// Performs one-time provider initialization.
    fn initialize(&mut self) -> Result<(), ErrorKind>;
    /// Discovers available model descriptors.
    fn discover(&self) -> Result<Vec<Model>, ErrorKind>;
    /// Counts tokens for prompt input prior to dispatch.
    fn count_input_tokens(&self, input: &str) -> Option<u64>;
    /// Dispatches an inference request.
    fn start(&mut self, request: &Request, now_ms: u64) -> Box<dyn Operation>;
    /// Releases provider resources.
    fn close(&mut self);
}
