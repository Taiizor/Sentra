//! Local dedicated inference adapter enforcing strict zero-egress containment (REQ-F03, REQ-F08, ADR-0005).

use crate::provider::contract::*;

/// Private local inference adapter strictly enforcing `Location::Local` and zero remote network egress.
pub struct LocalInferenceEndpointProvider {
    endpoint_label: String,
    models: Vec<Model>,
    initialized: bool,
}

impl LocalInferenceEndpointProvider {
    /// Constructs a new local inference endpoint adapter.
    pub fn new(endpoint_label: impl Into<String>, models: Vec<Model>) -> Self {
        Self {
            endpoint_label: endpoint_label.into(),
            models,
            initialized: false,
        }
    }

    /// Label or host identifier of the local worker.
    pub fn endpoint_label(&self) -> &str {
        &self.endpoint_label
    }
}

impl Provider for LocalInferenceEndpointProvider {
    fn initialize(&mut self) -> Result<(), ErrorKind> {
        // Enforce that all registered models have Local location
        for model in &self.models {
            if model.location != Location::Local {
                return Err(ErrorKind::PolicyDenied);
            }
        }
        self.initialized = true;
        Ok(())
    }

    fn discover(&self) -> Result<Vec<Model>, ErrorKind> {
        if !self.initialized {
            return Err(ErrorKind::NotInitialized);
        }
        Ok(self.models.clone())
    }

    fn count_input_tokens(&self, input: &str) -> Option<u64> {
        u64::try_from(input.len()).ok()
    }

    fn start(&mut self, request: &Request, now_ms: u64) -> Box<dyn Operation> {
        // Find requested model
        let model = self.models.iter().find(|m| m.id == request.model).cloned();

        Box::new(LocalOperation {
            request_id: request.id,
            model,
            _start_time: now_ms,
            input_length: request.input.len() as u64,
            completed: false,
        })
    }

    fn close(&mut self) {
        self.initialized = false;
    }
}

struct LocalOperation {
    request_id: u64,
    model: Option<Model>,
    _start_time: u64,
    input_length: u64,
    completed: bool,
}

impl Operation for LocalOperation {
    fn poll(&mut self, _now_ms: u64) -> Progress {
        if self.completed {
            return Progress::Failed {
                kind: ErrorKind::Closed,
                retry_after_ms: None,
                usage: None,
                safe_to_retry: false,
            };
        }

        let Some(model) = &self.model else {
            self.completed = true;
            return Progress::Failed {
                kind: ErrorKind::UnknownModel,
                retry_after_ms: None,
                usage: None,
                safe_to_retry: false,
            };
        };

        if model.location != Location::Local {
            self.completed = true;
            return Progress::Failed {
                kind: ErrorKind::PolicyDenied,
                retry_after_ms: None,
                usage: None,
                safe_to_retry: false,
            };
        }

        self.completed = true;
        Progress::Done {
            model: model.id.clone(),
            body: Body::Text(format!(
                "Local inference completed for request {}",
                self.request_id
            )),
            usage: Some(Usage {
                input_tokens: self.input_length,
                output_tokens: 8,
            }),
        }
    }

    fn cancel(&mut self) -> CancelReceipt {
        self.completed = true;
        CancelReceipt {
            confirmed: true,
            usage: Some(Usage {
                input_tokens: self.input_length,
                output_tokens: 0,
            }),
        }
    }
}
