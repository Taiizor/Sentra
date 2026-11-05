use std::{collections::BTreeMap, fmt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataClass {
    Public,
    PrivateSource,
    SecurityFinding,
    Secret,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Location {
    Local,
    Remote,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub structured: bool,
    pub streaming: bool,
    pub structured_streaming: bool,
    pub cancellation: bool,
    pub token_counting: bool,
    pub usage: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rates {
    /// Synthetic micro-USD per token, not a real provider price.
    pub input: u64,
    pub output: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    pub id: String,
    pub location: Location,
    pub capabilities: Capabilities,
    pub context_tokens: u64,
    pub max_input_bytes: usize,
    pub max_output_tokens: u64,
    pub max_response_bytes: usize,
    pub rates: Option<Rates>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Text,
    DecisionV1,
}

#[derive(Clone)]
pub struct Request {
    pub id: u64,
    pub model: String,
    pub input: String,
    pub classification: DataClass,
    pub format: Format,
    pub stream: bool,
    pub max_output_tokens: u64,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("id", &self.id)
            .field("input", &"[redacted]")
            .field("classification", &self.classification)
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum Value {
    Text(String),
    Bool(bool),
    Number(i64),
    Object(BTreeMap<String, Value>),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Value([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum Body {
    Text(String),
    Structured(Value),
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Body([redacted])")
    }
}

impl Body {
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

    /// One narrow typed schema; this is not a JSON parser or JSON Schema engine.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    NotConfigured,
    NotInitialized,
    Closed,
    PolicyDenied,
    Unsupported,
    UnknownModel,
    InputLimit,
    ContextLimit,
    OutputLimit,
    InvalidOutput,
    Protocol,
    Timeout,
    Cancelled,
    RateLimited,
    Authentication,
    Unavailable,
    Internal,
    CostUnknown,
    BudgetExceeded,
    InvalidUsage,
    Arithmetic,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub kind: ErrorKind,
    pub unsupported_feature: Option<Feature>,
    pub cancellation_confirmed: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feature {
    StructuredOutput,
    TextStreaming,
    StructuredStreaming,
    Cancellation,
    TokenCounting,
    UsageReporting,
}

impl Failure {
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

#[derive(Clone, Debug)]
pub struct Policy {
    pub explicitly_initiated: bool,
    pub metadata: bool,
    pub inference: bool,
    pub remote_egress: bool,
    pub classified_input: bool,
    pub require_usage: bool,
    pub require_cancellation: bool,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub timeout_ms: u64,
    pub max_attempts: u32,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticCode {
    Initialized,
    Discovered,
    Dispatched,
    Retrying,
    Completed,
    Rejected,
    Stopped,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: DiagnosticCode,
    pub attempt: u32,
    pub error: Option<ErrorKind>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub body: Body,
    pub classification: DataClass,
    pub usage: Option<Usage>,
    pub cost_actual_micro_usd: Option<u64>,
    pub observed_cost_micro_usd: u64,
    pub held_unknown_micro_usd: u64,
    pub usage_complete: bool,
    pub attempts: u32,
    pub elapsed_ms: u64,
    pub stream_chunks: u32,
}

pub enum Progress {
    Pending,
    Chunk {
        sequence: u32,
        text: String,
    },
    Done {
        model: String,
        body: Body,
        usage: Option<Usage>,
    },
    Failed {
        kind: ErrorKind,
        retry_after_ms: Option<u64>,
        usage: Option<Usage>,
        safe_to_retry: bool,
    },
}

pub struct CancelReceipt {
    pub confirmed: bool,
    pub usage: Option<Usage>,
}

pub trait Operation {
    fn poll(&mut self, now_ms: u64) -> Progress;
    fn cancel(&mut self) -> CancelReceipt;
}

/// Adapter-neutral boundary. No provider SDK, credential or HTTP type is exposed.
pub trait Provider {
    fn initialize(&mut self) -> Result<(), ErrorKind>;
    fn discover(&self) -> Result<Vec<Model>, ErrorKind>;
    fn count_input_tokens(&self, input: &str) -> Option<u64>;
    fn start(&mut self, request: &Request, now_ms: u64) -> Box<dyn Operation>;
    fn close(&mut self);
}
