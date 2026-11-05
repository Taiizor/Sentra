use crate::contract::*;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Trace {
    pub initialized: u32,
    pub discovered: u32,
    pub starts: Vec<u64>,
    pub cancelled: u32,
    pub closed: u32,
}

pub type SharedTrace = Arc<Mutex<Trace>>;

/// Vendor-specific data is confined to this adapter and never copied to diagnostics.
pub enum MockFailure {
    RateLimit(u64),
    Authentication(String),
    Unavailable(String),
    Internal(String),
    InvalidOutput(String),
}

pub enum Terminal {
    Response {
        model: Option<String>,
        body: Body,
        usage: Option<Usage>,
    },
    Failure {
        raw: MockFailure,
        usage: Option<Usage>,
        safe_to_retry: bool,
    },
}

pub struct Script {
    pub delay_ms: u64,
    pub chunks: VecDeque<(u64, u32, String)>,
    pub terminal: Terminal,
    pub cancel_confirmed: bool,
    pub cancel_usage: Option<Usage>,
}

impl Script {
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

pub struct MockProvider {
    pub models: Vec<Model>,
    pub scripts: VecDeque<Script>,
    pub trace: SharedTrace,
    pub initialize_error: Option<ErrorKind>,
    ready: bool,
}

impl MockProvider {
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

impl Provider for MockProvider {
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
        // This mock counts UTF-8 bytes. It does not represent any real tokenizer.
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
