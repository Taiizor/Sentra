use crate::contract::*;

#[derive(Clone, Copy)]
struct AttemptLimits {
    reservation: u64,
    input: u64,
    output: u64,
    rates: Rates,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ledger {
    pub limit: u64,
    pub actual: u64,
    /// Held upper bounds remain uncertain, never reported as measured zero cost.
    pub held_unknown: u64,
    pub unknown_attempts: u64,
}

impl Ledger {
    fn reserve(&mut self, amount: u64) -> Result<(), ErrorKind> {
        let total = self
            .actual
            .checked_add(self.held_unknown)
            .and_then(|n| n.checked_add(amount))
            .ok_or(ErrorKind::Arithmetic)?;
        if total > self.limit {
            return Err(ErrorKind::BudgetExceeded);
        }
        self.held_unknown += amount;
        Ok(())
    }

    fn settle(
        &mut self,
        reservation: u64,
        usage: Option<Usage>,
        input_limit: u64,
        output_limit: u64,
        rates: Rates,
    ) -> Result<Option<u64>, ErrorKind> {
        let Some(usage) = usage else {
            self.unknown_attempts = self
                .unknown_attempts
                .checked_add(1)
                .ok_or(ErrorKind::Arithmetic)?;
            return Ok(None);
        };
        if usage.input_tokens > input_limit || usage.output_tokens > output_limit {
            self.unknown_attempts = self
                .unknown_attempts
                .checked_add(1)
                .ok_or(ErrorKind::Arithmetic)?;
            return Err(ErrorKind::InvalidUsage);
        }
        let cost = price(usage.input_tokens, usage.output_tokens, rates)?;
        if cost > reservation {
            return Err(ErrorKind::InvalidUsage);
        }
        self.held_unknown -= reservation;
        self.actual = self.actual.checked_add(cost).ok_or(ErrorKind::Arithmetic)?;
        Ok(Some(cost))
    }
}

fn price(input: u64, output: u64, rates: Rates) -> Result<u64, ErrorKind> {
    input
        .checked_mul(rates.input)
        .and_then(|n| n.checked_add(output.checked_mul(rates.output)?))
        .ok_or(ErrorKind::Arithmetic)
}

#[derive(Clone, Debug, Default)]
pub struct VirtualControl {
    pub now_ms: u64,
    pub cancel_at_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalStatus {
    pub provider_configured: bool,
    pub initialized: bool,
    pub discovered_models: usize,
}

/// Isolated provider boundary probe, not production Core Engine implementation.
pub struct Gateway {
    provider: Option<Box<dyn Provider>>,
    initialized: bool,
    closed: bool,
    models: Vec<Model>,
    pub ledger: Ledger,
    pub diagnostics: Vec<Diagnostic>,
}

impl Gateway {
    pub fn new(provider: Option<Box<dyn Provider>>, budget_micro_usd: u64) -> Self {
        Self {
            provider,
            initialized: false,
            closed: false,
            models: Vec::new(),
            ledger: Ledger {
                limit: budget_micro_usd,
                actual: 0,
                held_unknown: 0,
                unknown_attempts: 0,
            },
            diagnostics: Vec::new(),
        }
    }

    pub fn local_status(&self) -> LocalStatus {
        LocalStatus {
            provider_configured: self.provider.is_some(),
            initialized: self.initialized,
            discovered_models: self.models.len(),
        }
    }

    fn log(&mut self, code: DiagnosticCode, attempt: u32, error: Option<ErrorKind>) {
        if self.diagnostics.len() == 64 {
            self.diagnostics.remove(0);
        }
        self.diagnostics.push(Diagnostic {
            code,
            attempt,
            error,
        });
    }

    pub fn initialize(&mut self, policy: &Policy) -> Result<(), Failure> {
        if !policy.explicitly_initiated || !policy.metadata {
            return Err(ErrorKind::PolicyDenied.into());
        }
        if self.closed {
            return Err(ErrorKind::Closed.into());
        }
        if self.initialized {
            return Ok(());
        }
        self.provider
            .as_mut()
            .ok_or(ErrorKind::NotConfigured)?
            .initialize()?;
        self.initialized = true;
        self.log(DiagnosticCode::Initialized, 0, None);
        Ok(())
    }

    pub fn discover(&mut self, policy: &Policy) -> Result<Vec<Model>, Failure> {
        if !policy.explicitly_initiated || !policy.metadata {
            return Err(ErrorKind::PolicyDenied.into());
        }
        if self.closed {
            return Err(ErrorKind::Closed.into());
        }
        if !self.initialized {
            return Err(ErrorKind::NotInitialized.into());
        }
        let models = self
            .provider
            .as_ref()
            .ok_or(ErrorKind::NotConfigured)?
            .discover()?;
        if models.len() > 16 {
            return Err(ErrorKind::Protocol.into());
        }
        let mut ids = std::collections::BTreeSet::new();
        for model in &models {
            if model.id.is_empty()
                || model.id.len() > 64
                || !model
                    .id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
                || !ids.insert(model.id.clone())
                || model.context_tokens == 0
                || model.max_output_tokens > model.context_tokens
                || model.max_input_bytes == 0
                || model.max_response_bytes == 0
            {
                return Err(ErrorKind::Protocol.into());
            }
        }
        self.models = models.clone();
        self.log(DiagnosticCode::Discovered, 0, None);
        Ok(models)
    }

    pub fn close(&mut self) {
        if !self.closed
            && let Some(provider) = &mut self.provider
        {
            provider.close();
        }
        self.closed = true;
        self.initialized = false;
        self.models.clear();
    }

    pub fn run(
        &mut self,
        request: &Request,
        policy: &Policy,
        control: &mut VirtualControl,
    ) -> Result<Response, Failure> {
        let result = self.run_checked(request, policy, control);
        if let Err(error) = &result {
            self.log(DiagnosticCode::Rejected, 0, Some(error.kind));
        }
        result
    }

    fn stop(
        &mut self,
        operation: &mut dyn Operation,
        model: &Model,
        limits: AttemptLimits,
        kind: ErrorKind,
    ) -> Failure {
        let receipt = if model.capabilities.cancellation {
            operation.cancel()
        } else {
            CancelReceipt {
                confirmed: false,
                usage: None,
            }
        };
        // A partial usage receipt cannot release budget while execution may continue.
        // Invalid, missing or unconfirmed final usage leaves the reservation held.
        let final_usage = receipt.confirmed.then_some(receipt.usage).flatten();
        let _ = self.ledger.settle(
            limits.reservation,
            final_usage,
            limits.input,
            limits.output,
            limits.rates,
        );
        self.log(DiagnosticCode::Stopped, 0, Some(kind));
        Failure {
            kind,
            unsupported_feature: None,
            cancellation_confirmed: Some(receipt.confirmed),
        }
    }

    fn run_checked(
        &mut self,
        request: &Request,
        policy: &Policy,
        control: &mut VirtualControl,
    ) -> Result<Response, Failure> {
        if !policy.explicitly_initiated
            || !policy.inference
            || request.classification == DataClass::Secret
            || (request.classification != DataClass::Public && !policy.classified_input)
        {
            return Err(ErrorKind::PolicyDenied.into());
        }
        if self.closed {
            return Err(ErrorKind::Closed.into());
        }
        if self.provider.is_none() {
            return Err(ErrorKind::NotConfigured.into());
        }
        if !self.initialized {
            return Err(ErrorKind::NotInitialized.into());
        }
        if policy.max_attempts == 0
            || policy.max_attempts > 16
            || policy.timeout_ms == 0
            || policy.timeout_ms > 1000
        {
            return Err(ErrorKind::Protocol.into());
        }
        let model = self
            .models
            .iter()
            .find(|m| m.id == request.model)
            .cloned()
            .ok_or(ErrorKind::UnknownModel)?;
        if model.location == Location::Remote && !policy.remote_egress {
            return Err(ErrorKind::PolicyDenied.into());
        }
        let unsupported = [
            (
                request.format == Format::DecisionV1 && !model.capabilities.structured,
                Feature::StructuredOutput,
            ),
            (
                request.stream && !model.capabilities.streaming,
                Feature::TextStreaming,
            ),
            // Advertisements cannot enable an unimplemented gateway feature.
            (
                request.stream && request.format == Format::DecisionV1,
                Feature::StructuredStreaming,
            ),
            (
                policy.require_cancellation && !model.capabilities.cancellation,
                Feature::Cancellation,
            ),
            (
                policy.require_usage && !model.capabilities.usage,
                Feature::UsageReporting,
            ),
            (!model.capabilities.token_counting, Feature::TokenCounting),
        ]
        .into_iter()
        .find(|(missing, _)| *missing);
        if let Some((_, feature)) = unsupported {
            return Err(Failure::unsupported(feature));
        }
        if request.input.len() > model.max_input_bytes.min(policy.max_input_bytes) {
            return Err(ErrorKind::InputLimit.into());
        }
        let input = self
            .provider
            .as_ref()
            .ok_or(ErrorKind::NotConfigured)?
            .count_input_tokens(&request.input)
            .ok_or_else(|| Failure::unsupported(Feature::TokenCounting))?;
        if request.max_output_tokens == 0
            || request.max_output_tokens > model.max_output_tokens
            || input
                .checked_add(request.max_output_tokens)
                .ok_or(ErrorKind::Arithmetic)?
                > model.context_tokens
        {
            return Err(ErrorKind::ContextLimit.into());
        }
        let rates = model.rates.ok_or(ErrorKind::CostUnknown)?;
        let reservation = price(input, request.max_output_tokens, rates)?;
        let attempt_limits = AttemptLimits {
            reservation,
            input,
            output: request.max_output_tokens,
            rates,
        };
        let start = control.now_ms;
        let deadline = start
            .checked_add(policy.timeout_ms)
            .ok_or(ErrorKind::Arithmetic)?;
        let output_limit = model.max_response_bytes.min(policy.max_output_bytes);
        let initial_actual = self.ledger.actual;
        let initial_held = self.ledger.held_unknown;
        let initial_unknown_attempts = self.ledger.unknown_attempts;
        for attempt in 1..=policy.max_attempts {
            if control.cancel_at_ms.is_some_and(|at| control.now_ms >= at) {
                return Err(ErrorKind::Cancelled.into());
            }
            if control.now_ms >= deadline {
                return Err(ErrorKind::Timeout.into());
            }
            self.ledger.reserve(reservation)?;
            self.log(DiagnosticCode::Dispatched, attempt, None);
            let mut operation = self
                .provider
                .as_mut()
                .ok_or(ErrorKind::NotConfigured)?
                .start(request, control.now_ms);
            let mut stream = String::new();
            let mut sequence = 0;
            loop {
                let cancel = control.cancel_at_ms.is_some_and(|at| control.now_ms >= at);
                if cancel || control.now_ms >= deadline {
                    let kind = if cancel {
                        ErrorKind::Cancelled
                    } else {
                        ErrorKind::Timeout
                    };
                    return Err(self.stop(operation.as_mut(), &model, attempt_limits, kind));
                }
                match operation.poll(control.now_ms) {
                    Progress::Pending => {
                        control.now_ms =
                            control.now_ms.checked_add(1).ok_or(ErrorKind::Arithmetic)?;
                    }
                    Progress::Chunk {
                        sequence: index,
                        text,
                    } => {
                        let error = if !request.stream || index != sequence {
                            Some(ErrorKind::Protocol)
                        } else if sequence >= 64
                            || stream
                                .len()
                                .checked_add(text.len())
                                .is_none_or(|n| n > output_limit)
                        {
                            Some(ErrorKind::OutputLimit)
                        } else {
                            None
                        };
                        if let Some(kind) = error {
                            return Err(self.stop(
                                operation.as_mut(),
                                &model,
                                attempt_limits,
                                kind,
                            ));
                        }
                        stream.push_str(&text);
                        sequence += 1;
                    }
                    Progress::Done {
                        model: response_model,
                        body,
                        usage,
                    } => {
                        if response_model != request.model {
                            self.ledger.settle(
                                reservation,
                                None,
                                input,
                                request.max_output_tokens,
                                rates,
                            )?;
                            return Err(ErrorKind::Protocol.into());
                        }
                        self.ledger.settle(
                            reservation,
                            usage,
                            input,
                            request.max_output_tokens,
                            rates,
                        )?;
                        if policy.require_usage && usage.is_none() {
                            return Err(ErrorKind::InvalidUsage.into());
                        }
                        if body.byte_size()? > output_limit {
                            return Err(ErrorKind::OutputLimit.into());
                        }
                        body.validate(request.format)?;
                        if request.stream && (body != Body::Text(stream)) {
                            return Err(ErrorKind::Protocol.into());
                        }
                        self.log(DiagnosticCode::Completed, attempt, None);
                        let observed_cost = self.ledger.actual - initial_actual;
                        let held_unknown = self.ledger.held_unknown - initial_held;
                        let usage_complete =
                            self.ledger.unknown_attempts == initial_unknown_attempts;
                        return Ok(Response {
                            body,
                            classification: request.classification,
                            usage,
                            cost_actual_micro_usd: usage_complete.then_some(observed_cost),
                            observed_cost_micro_usd: observed_cost,
                            held_unknown_micro_usd: held_unknown,
                            usage_complete,
                            attempts: attempt,
                            elapsed_ms: control.now_ms - start,
                            stream_chunks: sequence,
                        });
                    }
                    Progress::Failed {
                        kind,
                        retry_after_ms,
                        usage,
                        safe_to_retry,
                    } => {
                        self.ledger.settle(
                            reservation,
                            usage,
                            input,
                            request.max_output_tokens,
                            rates,
                        )?;
                        let retry = safe_to_retry
                            && sequence == 0
                            && matches!(kind, ErrorKind::RateLimited | ErrorKind::Unavailable)
                            && attempt < policy.max_attempts;
                        let delay = retry_after_ms.unwrap_or(1u64 << (attempt - 1));
                        let next = control
                            .now_ms
                            .checked_add(delay)
                            .ok_or(ErrorKind::Arithmetic)?;
                        if !retry || delay > policy.max_retry_delay_ms || next >= deadline {
                            return Err(kind.into());
                        }
                        self.log(DiagnosticCode::Retrying, attempt, Some(kind));
                        control.now_ms = next;
                        break;
                    }
                }
            }
        }
        Err(ErrorKind::Internal.into())
    }
}
