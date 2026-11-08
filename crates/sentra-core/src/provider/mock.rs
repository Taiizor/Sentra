//! Synthetic deterministic mock provider for reproducible test harnesses and verification.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use crate::provider::contract::*;

/// Execution trace recording lifecycle events emitted by the mock provider.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Trace {
    /// Number of times `initialize()` was invoked.
    pub initialized: u32,
    /// Number of times `discover()` was invoked.
    pub discovered: u32,
    /// Ordered sequence of request IDs passed to `start()`.
    pub starts: Vec<u64>,
    /// Number of cancellations signaled.
    pub cancelled: u32,
    /// Number of times `close()` was invoked.
    pub closed: u32,
}

/// Thread-safe shared trace handle.
pub type SharedTrace = Arc<Mutex<Trace>>;

/// Simulated failure payload for mock fault injection.
pub enum MockFailure {
    /// Rate limit exceeded with suggested backoff delay in milliseconds.
    RateLimit(u64),
    /// Authentication failure.
    Authentication(String),
    /// Service temporarily unavailable.
    Unavailable(String),
    /// Internal unexpected error.
    Internal(String),
    /// Invalid or malformed response envelope.
    InvalidOutput(String),
}

/// Simulated terminal outcome for a scripted attempt.
pub enum Terminal {
    /// Successful completion response.
    Response {
        /// Optional model ID override.
        model: Option<String>,
        /// Completed body payload.
        body: Body,
        /// Incurred token usage metrics.
        usage: Option<Usage>,
    },
    /// Injected terminal failure.
    Failure {
        /// Raw failure classification.
        raw: MockFailure,
        /// Incurred token usage prior to failure.
        usage: Option<Usage>,
        /// Whether the failure should be marked safe to retry.
        safe_to_retry: bool,
    },
}

/// Scripted execution recipe for an individual request.
pub struct Script {
    /// Simulated execution delay in milliseconds before reaching terminal outcome.
    pub delay_ms: u64,
    /// Intermediate streaming chunks `(at_ms, sequence, text)`.
    pub chunks: VecDeque<(u64, u32, String)>,
    /// Terminal outcome (response or failure).
    pub terminal: Terminal,
    /// Whether cancellation is confirmed if signaled.
    pub cancel_confirmed: bool,
    /// Token usage incurred up to cancellation point.
    pub cancel_usage: Option<Usage>,
}

impl Script {
    /// Constructs a successful response script.
    pub fn response(body: Body, usage: Option<Usage>) -> Self {
        Self {
            delay_ms: 0,
            chunks: VecDeque::new(),
            terminal: Terminal::Response {
                model: None,
                body,
                usage,
            },
            cancel_confirmed: true,
            cancel_usage: None,
        }
    }

    /// Constructs a failure injection script.
    pub fn failure(raw: MockFailure, safe_to_retry: bool) -> Self {
        Self {
            delay_ms: 0,
            chunks: VecDeque::new(),
            terminal: Terminal::Failure {
                raw,
                usage: Some(Usage {
                    input_tokens: 0,
                    output_tokens: 0,
                }),
                safe_to_retry,
            },
            cancel_confirmed: true,
            cancel_usage: None,
        }
    }
}

/// Creates a standard synthetic reference model descriptor supporting all capabilities.
pub fn full_model() -> Model {
    Model {
        id: "mock-full".into(),
        location: Location::Local,
        capabilities: Capabilities {
            structured: true,
            streaming: true,
            structured_streaming: false,
            cancellation: true,
            token_counting: true,
            usage: true,
        },
        context_tokens: 64,
        max_input_bytes: 64,
        max_output_tokens: 16,
        max_response_bytes: 1024,
        rates: Some(Rates {
            input: 1,
            output: 2,
        }),
    }
}

/// Deterministic mock provider adapter for test harnesses.
pub struct SyntheticMockProvider {
    /// Models supported by this mock instance.
    pub models: Vec<Model>,
    /// Queue of scripted responses.
    pub scripts: VecDeque<Script>,
    /// Execution trace tracker.
    pub trace: SharedTrace,
    /// Injected failure returned by `initialize()`, if configured.
    pub initialize_error: Option<ErrorKind>,
    ready: bool,
}

impl SyntheticMockProvider {
    /// Constructs a new synthetic mock provider.
    pub fn new(models: Vec<Model>, scripts: Vec<Script>) -> Self {
        Self {
            models,
            scripts: scripts.into(),
            trace: Arc::default(),
            initialize_error: None,
            ready: false,
        }
    }
}

impl Provider for SyntheticMockProvider {
    fn initialize(&mut self) -> Result<(), ErrorKind> {
        self.trace.lock().expect("trace lock").initialized += 1;
        if let Some(error) = self.initialize_error {
            return Err(error);
        }
        self.ready = true;
        Ok(())
    }

    fn discover(&self) -> Result<Vec<Model>, ErrorKind> {
        if !self.ready {
            return Err(ErrorKind::NotInitialized);
        }
        self.trace.lock().expect("trace lock").discovered += 1;
        Ok(self.models.clone())
    }

    fn count_input_tokens(&self, input: &str) -> Option<u64> {
        u64::try_from(input.len()).ok()
    }

    fn start(&mut self, request: &Request, now_ms: u64) -> Box<dyn Operation> {
        self.trace
            .lock()
            .expect("trace lock")
            .starts
            .push(request.id);
        let script = self.scripts.pop_front().unwrap_or_else(|| {
            Script::failure(MockFailure::Unavailable("script exhausted".into()), false)
        });
        Box::new(MockOperation {
            script: Some(script),
            start: now_ms,
            requested_model: request.model.clone(),
            trace: self.trace.clone(),
        })
    }

    fn close(&mut self) {
        self.trace.lock().expect("trace lock").closed += 1;
        self.ready = false;
    }
}

struct MockOperation {
    script: Option<Script>,
    start: u64,
    requested_model: String,
    trace: SharedTrace,
}

impl Operation for MockOperation {
    fn poll(&mut self, now_ms: u64) -> Progress {
        let script = self
            .script
            .as_mut()
            .expect("operation polled after completion");
        let elapsed = now_ms - self.start;
        if script
            .chunks
            .front()
            .is_some_and(|(at, _, _)| elapsed >= *at)
        {
            let (_, sequence, text) = script.chunks.pop_front().expect("queued chunk");
            return Progress::Chunk { sequence, text };
        }
        if elapsed < script.delay_ms {
            return Progress::Pending;
        }
        match self.script.take().expect("pending script").terminal {
            Terminal::Response { model, body, usage } => Progress::Done {
                model: model.unwrap_or_else(|| self.requested_model.clone()),
                body,
                usage,
            },
            Terminal::Failure {
                raw,
                usage,
                safe_to_retry,
            } => {
                let (kind, retry_after_ms) = match raw {
                    MockFailure::RateLimit(delay) => (ErrorKind::RateLimited, Some(delay)),
                    MockFailure::Authentication(_) => (ErrorKind::Authentication, None),
                    MockFailure::Unavailable(_) => (ErrorKind::Unavailable, None),
                    MockFailure::Internal(_) => (ErrorKind::Internal, None),
                    MockFailure::InvalidOutput(_) => (ErrorKind::InvalidOutput, None),
                };
                Progress::Failed {
                    kind,
                    retry_after_ms,
                    usage,
                    safe_to_retry,
                }
            }
        }
    }

    fn cancel(&mut self) -> CancelReceipt {
        self.trace.lock().expect("trace lock").cancelled += 1;
        let script = self.script.as_ref().expect("cancel pending operation");
        CancelReceipt {
            confirmed: script.cancel_confirmed,
            usage: script.cancel_usage,
        }
    }
}
