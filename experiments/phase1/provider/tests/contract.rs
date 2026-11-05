use sentra_provider_contract_probe::{contract::*, gateway::*, mock::*};
use std::collections::{BTreeMap, VecDeque};

fn policy() -> Policy {
    Policy {
        explicitly_initiated: true,
        metadata: true,
        inference: true,
        ..Policy::default()
    }
}

fn request() -> Request {
    Request {
        id: 42,
        model: "mock-full".into(),
        input: "hi".into(),
        classification: DataClass::Public,
        format: Format::Text,
        stream: false,
        max_output_tokens: 4,
    }
}

fn measured() -> Option<Usage> {
    Some(Usage {
        input_tokens: 2,
        output_tokens: 2,
    })
}
fn success() -> Script {
    Script::response(Body::Text("ok".into()), measured())
}

fn configured(models: Vec<Model>, scripts: Vec<Script>, budget: u64) -> (Gateway, SharedTrace) {
    let mock = MockProvider::new(models, scripts);
    let trace = mock.trace.clone();
    let mut gateway = Gateway::new(Some(Box::new(mock)), budget);
    gateway.initialize(&policy()).unwrap();
    gateway.discover(&policy()).unwrap();
    (gateway, trace)
}

fn setup(scripts: Vec<Script>) -> (Gateway, SharedTrace) {
    configured(vec![full_model()], scripts, 1000)
}
fn invoke(gateway: &mut Gateway) -> Result<Response, Failure> {
    gateway.run(&request(), &policy(), &mut VirtualControl::default())
}
fn decision() -> Value {
    Value::Object(BTreeMap::from([
        ("accepted".into(), Value::Bool(true)),
        ("summary".into(), Value::Text("ok".into())),
    ]))
}

#[test]
fn t01_provider_free_boundary_remains_available() {
    let mut gateway = Gateway::new(None, 100);
    assert_eq!(
        gateway.local_status(),
        LocalStatus {
            provider_configured: false,
            initialized: false,
            discovered_models: 0
        }
    );
    assert_eq!(
        invoke(&mut gateway).unwrap_err().kind,
        ErrorKind::NotConfigured
    );
    assert_eq!(gateway.ledger.actual, 0);
    assert_eq!(gateway.ledger.held_unknown, 0);
}

#[test]
fn t02_construction_does_not_initiate_provider_operations() {
    let mock = MockProvider::new(vec![full_model()], vec![success()]);
    let trace = mock.trace.clone();
    let gateway = Gateway::new(Some(Box::new(mock)), 100);
    assert!(!gateway.local_status().initialized);
    assert_eq!(*trace.lock().unwrap(), Trace::default());
}

#[test]
fn t03_initialization_discovery_and_close_have_explicit_lifecycles() {
    let (mut gateway, trace) = setup(vec![success()]);
    gateway.initialize(&policy()).unwrap();
    assert_eq!(gateway.local_status().discovered_models, 1);
    gateway.close();
    gateway.close();
    assert_eq!(
        gateway.initialize(&policy()).unwrap_err().kind,
        ErrorKind::Closed
    );
    assert_eq!(invoke(&mut gateway).unwrap_err().kind, ErrorKind::Closed);
    let trace = trace.lock().unwrap();
    assert_eq!(
        (trace.initialized, trace.discovered, trace.closed),
        (1, 1, 1)
    );
    assert!(trace.starts.is_empty());
}

#[test]
fn t04_metadata_requires_an_explicit_policy_grant() {
    let mock = MockProvider::new(vec![full_model()], vec![]);
    let trace = mock.trace.clone();
    let mut gateway = Gateway::new(Some(Box::new(mock)), 100);
    assert_eq!(
        gateway.initialize(&Policy::default()).unwrap_err().kind,
        ErrorKind::PolicyDenied
    );
    assert_eq!(
        gateway.discover(&Policy::default()).unwrap_err().kind,
        ErrorKind::PolicyDenied
    );
    assert_eq!(*trace.lock().unwrap(), Trace::default());
}

#[test]
fn t05_requests_cannot_implicitly_initialize_a_provider() {
    let mock = MockProvider::new(vec![full_model()], vec![success()]);
    let trace = mock.trace.clone();
    let mut gateway = Gateway::new(Some(Box::new(mock)), 100);
    assert_eq!(
        invoke(&mut gateway).unwrap_err().kind,
        ErrorKind::NotInitialized
    );
    assert_eq!(*trace.lock().unwrap(), Trace::default());
}

#[test]
fn t06_initialization_failure_leaves_the_provider_unready() {
    let mut mock = MockProvider::new(vec![full_model()], vec![]);
    mock.initialize_error = Some(ErrorKind::Authentication);
    let mut gateway = Gateway::new(Some(Box::new(mock)), 100);
    assert_eq!(
        gateway.initialize(&policy()).unwrap_err().kind,
        ErrorKind::Authentication
    );
    assert!(!gateway.local_status().initialized);
    assert_eq!(
        gateway.discover(&policy()).unwrap_err().kind,
        ErrorKind::NotInitialized
    );
}

#[test]
fn t07_discovery_preserves_provider_specific_capability_differences() {
    let full = full_model();
    let mut basic = full.clone();
    basic.id = "mock-basic".into();
    basic.capabilities.structured = false;
    basic.capabilities.streaming = false;
    basic.capabilities.usage = false;
    let (mut gateway, _) = configured(vec![full.clone(), basic.clone()], vec![], 100);
    assert_eq!(gateway.discover(&policy()).unwrap(), vec![full, basic]);
}

#[test]
fn t08_malformed_and_duplicate_model_descriptors_are_rejected() {
    for models in [
        vec![full_model(), full_model()],
        vec![Model {
            id: "unsafe\nmodel".into(),
            ..full_model()
        }],
        vec![Model {
            context_tokens: 0,
            ..full_model()
        }],
        vec![Model {
            max_input_bytes: 0,
            ..full_model()
        }],
    ] {
        let mock = MockProvider::new(models, vec![]);
        let mut gateway = Gateway::new(Some(Box::new(mock)), 100);
        gateway.initialize(&policy()).unwrap();
        assert_eq!(
            gateway.discover(&policy()).unwrap_err().kind,
            ErrorKind::Protocol
        );
        assert_eq!(gateway.local_status().discovered_models, 0);
    }
}

#[test]
fn t09_success_is_normalized_and_actual_usage_settles_reservation() {
    let (mut gateway, trace) = setup(vec![success()]);
    let response = invoke(&mut gateway).unwrap();
    assert_eq!(response.body, Body::Text("ok".into()));
    assert_eq!(response.usage, measured());
    assert_eq!(response.cost_actual_micro_usd, Some(6));
    assert!(response.usage_complete);
    assert_eq!(response.attempts, 1);
    assert_eq!((gateway.ledger.actual, gateway.ledger.held_unknown), (6, 0));
    assert_eq!(trace.lock().unwrap().starts, vec![42]);
}

#[test]
fn t10_identical_mock_runs_produce_identical_responses_and_diagnostics() {
    let (mut first, _) = setup(vec![success()]);
    let (mut second, _) = setup(vec![success()]);
    assert_eq!(invoke(&mut first), invoke(&mut second));
    assert_eq!(first.diagnostics, second.diagnostics);
    assert_eq!(first.ledger, second.ledger);
}

#[test]
fn t11_a_valid_decision_v1_structure_is_accepted() {
    let (mut gateway, _) = setup(vec![Script::response(
        Body::Structured(decision()),
        measured(),
    )]);
    let req = Request {
        format: Format::DecisionV1,
        ..request()
    };
    let response = gateway
        .run(&req, &policy(), &mut VirtualControl::default())
        .unwrap();
    assert_eq!(response.body, Body::Structured(decision()));
}

#[test]
fn t12_missing_extra_and_wrongly_typed_structured_fields_fail_validation() {
    for body in [
        Body::Text("not a structured object".into()),
        Body::Structured(Value::Object(BTreeMap::new())),
        Body::Structured(Value::Object(BTreeMap::from([
            ("summary".into(), Value::Text("ok".into())),
            ("accepted".into(), Value::Number(1)),
        ]))),
        Body::Structured(Value::Object(BTreeMap::from([
            ("summary".into(), Value::Text(String::new())),
            ("accepted".into(), Value::Bool(true)),
        ]))),
        Body::Structured(Value::Object(BTreeMap::from([
            ("summary".into(), Value::Text("ok".into())),
            ("accepted".into(), Value::Bool(true)),
            ("extra".into(), Value::Bool(true)),
        ]))),
    ] {
        let (mut gateway, _) = setup(vec![Script::response(body, measured())]);
        let req = Request {
            format: Format::DecisionV1,
            ..request()
        };
        assert_eq!(
            gateway
                .run(&req, &policy(), &mut VirtualControl::default())
                .unwrap_err()
                .kind,
            ErrorKind::InvalidOutput
        );
        assert_eq!(
            gateway.ledger.actual, 6,
            "billed invalid output is not free"
        );
    }
}

#[test]
fn t13_malformed_adapter_output_is_normalized_without_retry() {
    let (mut gateway, trace) = setup(vec![
        Script::failure(
            MockFailure::InvalidOutput("raw private payload".into()),
            true,
        ),
        success(),
    ]);
    let p = Policy {
        max_attempts: 2,
        ..policy()
    };
    assert_eq!(
        gateway
            .run(&request(), &p, &mut VirtualControl::default())
            .unwrap_err()
            .kind,
        ErrorKind::InvalidOutput
    );
    assert_eq!(trace.lock().unwrap().starts.len(), 1);
}

#[test]
fn t14_unsupported_structured_output_is_not_silently_downgraded() {
    let mut model = full_model();
    model.capabilities.structured = false;
    let (mut gateway, trace) = configured(vec![model], vec![success()], 100);
    let req = Request {
        format: Format::DecisionV1,
        ..request()
    };
    assert_eq!(
        gateway
            .run(&req, &policy(), &mut VirtualControl::default())
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
    assert!(trace.lock().unwrap().starts.is_empty());
}

#[test]
fn t15_unsupported_streaming_is_rejected_before_dispatch() {
    let mut model = full_model();
    model.capabilities.streaming = false;
    let (mut gateway, trace) = configured(vec![model], vec![success()], 100);
    let req = Request {
        stream: true,
        ..request()
    };
    assert_eq!(
        gateway
            .run(&req, &policy(), &mut VirtualControl::default())
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
    assert!(trace.lock().unwrap().starts.is_empty());
}

#[test]
fn t16_individual_features_do_not_imply_support_for_their_combination() {
    let (mut gateway, trace) = setup(vec![success()]);
    let req = Request {
        format: Format::DecisionV1,
        stream: true,
        ..request()
    };
    assert_eq!(
        gateway
            .run(&req, &policy(), &mut VirtualControl::default())
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
    assert!(trace.lock().unwrap().starts.is_empty());
}

fn streaming() -> Script {
    let mut script = success();
    script.delay_ms = 3;
    script.chunks = VecDeque::from([(1, 0, "o".into()), (2, 1, "k".into())]);
    script
}

#[test]
fn t17_stream_chunks_are_ordered_bounded_and_finalized() {
    let (mut gateway, _) = setup(vec![streaming()]);
    let response = gateway
        .run(
            &Request {
                stream: true,
                ..request()
            },
            &policy(),
            &mut VirtualControl::default(),
        )
        .unwrap();
    assert_eq!((response.stream_chunks, response.elapsed_ms), (2, 3));
    assert_eq!(response.body, Body::Text("ok".into()));
}

#[test]
fn t18_out_of_order_stream_is_cancelled_and_never_promoted() {
    let mut script = streaming();
    script.chunks[0].1 = 1;
    let (mut gateway, trace) = setup(vec![script]);
    assert_eq!(
        gateway
            .run(
                &Request {
                    stream: true,
                    ..request()
                },
                &policy(),
                &mut VirtualControl::default()
            )
            .unwrap_err()
            .kind,
        ErrorKind::Protocol
    );
    assert_eq!(trace.lock().unwrap().cancelled, 1);
    assert_eq!(gateway.ledger.held_unknown, 10);
}

#[test]
fn t19_stream_final_content_must_match_assembled_chunks() {
    let mut script = streaming();
    script.terminal = Terminal::Response {
        model: None,
        body: Body::Text("different".into()),
        usage: measured(),
    };
    let (mut gateway, _) = setup(vec![script]);
    assert_eq!(
        gateway
            .run(
                &Request {
                    stream: true,
                    ..request()
                },
                &policy(),
                &mut VirtualControl::default()
            )
            .unwrap_err()
            .kind,
        ErrorKind::Protocol
    );
    assert_eq!(gateway.ledger.actual, 6);
}

#[test]
fn t20_a_failure_after_partial_stream_output_is_not_retried() {
    let mut script = Script::failure(
        MockFailure::Unavailable("private transport details".into()),
        true,
    );
    script.delay_ms = 2;
    script.chunks = VecDeque::from([(1, 0, "partial".into())]);
    let (mut gateway, trace) = setup(vec![script, success()]);
    let p = Policy {
        max_attempts: 2,
        ..policy()
    };
    assert_eq!(
        gateway
            .run(
                &Request {
                    stream: true,
                    ..request()
                },
                &p,
                &mut VirtualControl::default()
            )
            .unwrap_err()
            .kind,
        ErrorKind::Unavailable
    );
    assert_eq!(trace.lock().unwrap().starts.len(), 1);
}

#[test]
fn t21_timeout_cancels_the_operation_and_retains_unknown_cost() {
    let mut script = success();
    script.delay_ms = 10;
    let (mut gateway, trace) = setup(vec![script]);
    let mut control = VirtualControl::default();
    let error = gateway
        .run(
            &request(),
            &Policy {
                timeout_ms: 5,
                ..policy()
            },
            &mut control,
        )
        .unwrap_err();
    assert_eq!(
        error,
        Failure {
            kind: ErrorKind::Timeout,
            unsupported_feature: None,
            cancellation_confirmed: Some(true)
        }
    );
    assert_eq!(control.now_ms, 5);
    assert_eq!(trace.lock().unwrap().cancelled, 1);
    assert_eq!(
        (
            gateway.ledger.actual,
            gateway.ledger.held_unknown,
            gateway.ledger.unknown_attempts
        ),
        (0, 10, 1)
    );
}

#[test]
fn t22_mid_request_cancellation_uses_the_virtual_clock() {
    let mut script = success();
    script.delay_ms = 10;
    let (mut gateway, trace) = setup(vec![script]);
    let mut control = VirtualControl {
        now_ms: 0,
        cancel_at_ms: Some(3),
    };
    let error = gateway
        .run(&request(), &policy(), &mut control)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Cancelled);
    assert_eq!(control.now_ms, 3);
    assert_eq!(trace.lock().unwrap().cancelled, 1);
    assert_eq!(gateway.ledger.held_unknown, 10);
}

#[test]
fn t23_pre_dispatch_cancellation_never_calls_the_provider() {
    let (mut gateway, trace) = setup(vec![success()]);
    let mut control = VirtualControl {
        now_ms: 0,
        cancel_at_ms: Some(0),
    };
    assert_eq!(
        gateway
            .run(&request(), &policy(), &mut control)
            .unwrap_err()
            .kind,
        ErrorKind::Cancelled
    );
    assert!(trace.lock().unwrap().starts.is_empty());
    assert_eq!(gateway.ledger.held_unknown, 0);
}

#[test]
fn t24_unsupported_remote_cancellation_stays_unconfirmed() {
    let mut model = full_model();
    model.capabilities.cancellation = false;
    let mut script = success();
    script.delay_ms = 10;
    let (mut gateway, trace) = configured(vec![model], vec![script], 100);
    let p = Policy {
        require_cancellation: false,
        ..policy()
    };
    let mut control = VirtualControl {
        now_ms: 0,
        cancel_at_ms: Some(2),
    };
    assert_eq!(
        gateway
            .run(&request(), &p, &mut control)
            .unwrap_err()
            .cancellation_confirmed,
        Some(false)
    );
    assert_eq!(trace.lock().unwrap().cancelled, 0);
    assert_eq!(gateway.ledger.held_unknown, 10);
}

#[test]
fn t25_required_cancellation_support_is_negotiated_before_dispatch() {
    let mut model = full_model();
    model.capabilities.cancellation = false;
    let (mut gateway, trace) = configured(vec![model], vec![success()], 100);
    assert_eq!(
        invoke(&mut gateway).unwrap_err().kind,
        ErrorKind::Unsupported
    );
    assert!(trace.lock().unwrap().starts.is_empty());
}

#[test]
fn t26_rate_limit_retry_preserves_request_identity_and_retry_after() {
    let (mut gateway, trace) = setup(vec![
        Script::failure(MockFailure::RateLimit(3), true),
        success(),
    ]);
    let p = Policy {
        max_attempts: 2,
        ..policy()
    };
    let response = gateway
        .run(&request(), &p, &mut VirtualControl::default())
        .unwrap();
    assert_eq!((response.attempts, response.elapsed_ms), (2, 3));
    assert_eq!(trace.lock().unwrap().starts, vec![42, 42]);
    assert_eq!((gateway.ledger.actual, gateway.ledger.held_unknown), (6, 0));
}

#[test]
fn t27_retry_attempt_count_is_finite() {
    let scripts = (0..3)
        .map(|_| Script::failure(MockFailure::RateLimit(1), true))
        .collect();
    let (mut gateway, trace) = setup(scripts);
    let p = Policy {
        max_attempts: 3,
        ..policy()
    };
    assert_eq!(
        gateway
            .run(&request(), &p, &mut VirtualControl::default())
            .unwrap_err()
            .kind,
        ErrorKind::RateLimited
    );
    assert_eq!(trace.lock().unwrap().starts.len(), 3);
}

#[test]
fn t28_excessive_retry_after_is_not_silently_shortened() {
    let (mut gateway, trace) = setup(vec![
        Script::failure(MockFailure::RateLimit(100), true),
        success(),
    ]);
    let mut control = VirtualControl::default();
    assert_eq!(
        gateway
            .run(
                &request(),
                &Policy {
                    max_attempts: 2,
                    ..policy()
                },
                &mut control
            )
            .unwrap_err()
            .kind,
        ErrorKind::RateLimited
    );
    assert_eq!(control.now_ms, 0);
    assert_eq!(trace.lock().unwrap().starts.len(), 1);
}

#[test]
fn t29_unavailable_provider_uses_bounded_exponential_backoff() {
    let (mut gateway, trace) = setup(vec![
        Script::failure(MockFailure::Unavailable("one".into()), true),
        Script::failure(MockFailure::Unavailable("two".into()), true),
        success(),
    ]);
    let response = gateway
        .run(
            &request(),
            &Policy {
                max_attempts: 3,
                ..policy()
            },
            &mut VirtualControl::default(),
        )
        .unwrap();
    assert_eq!((response.attempts, response.elapsed_ms), (3, 3));
    assert_eq!(trace.lock().unwrap().starts.len(), 3);
}

#[test]
fn t30_authentication_errors_are_normalized_redacted_and_not_retried() {
    let secret = "AUTH_SECRET_CANARY";
    let (mut gateway, trace) = setup(vec![
        Script::failure(MockFailure::Authentication(secret.into()), true),
        success(),
    ]);
    let error = gateway
        .run(
            &request(),
            &Policy {
                max_attempts: 2,
                ..policy()
            },
            &mut VirtualControl::default(),
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Authentication);
    assert!(!format!("{error:?} {error} {:?}", gateway.diagnostics).contains(secret));
    assert_eq!(trace.lock().unwrap().starts.len(), 1);
}

#[test]
fn t31_internal_failure_does_not_receive_a_transient_retry() {
    let (mut gateway, trace) = setup(vec![
        Script::failure(
            MockFailure::Internal("private provider detail".into()),
            true,
        ),
        success(),
    ]);
    assert_eq!(
        gateway
            .run(
                &request(),
                &Policy {
                    max_attempts: 2,
                    ..policy()
                },
                &mut VirtualControl::default()
            )
            .unwrap_err()
            .kind,
        ErrorKind::Internal
    );
    assert_eq!(trace.lock().unwrap().starts.len(), 1);
}

#[test]
fn t32_missing_usage_is_unknown_and_its_reservation_cannot_be_reused() {
    let (mut gateway, trace) = configured(
        vec![full_model()],
        vec![Script::response(Body::Text("ok".into()), None), success()],
        10,
    );
    let p = Policy {
        require_usage: false,
        ..policy()
    };
    let response = gateway
        .run(&request(), &p, &mut VirtualControl::default())
        .unwrap();
    assert_eq!(response.cost_actual_micro_usd, None);
    assert_eq!(response.held_unknown_micro_usd, 10);
    assert!(!response.usage_complete);
    assert_eq!(
        gateway
            .run(&request(), &p, &mut VirtualControl::default())
            .unwrap_err()
            .kind,
        ErrorKind::BudgetExceeded
    );
    assert_eq!(trace.lock().unwrap().starts.len(), 1);
}

#[test]
fn t33_required_but_missing_usage_rejects_success_and_retains_reservation() {
    let (mut gateway, _) = setup(vec![Script::response(Body::Text("ok".into()), None)]);
    assert_eq!(
        invoke(&mut gateway).unwrap_err().kind,
        ErrorKind::InvalidUsage
    );
    assert_eq!(gateway.ledger.held_unknown, 10);
}

#[test]
fn t34_models_without_usage_reporting_expose_that_difference() {
    let mut model = full_model();
    model.capabilities.usage = false;
    let (mut gateway, trace) = configured(
        vec![model],
        vec![Script::response(Body::Text("ok".into()), None)],
        100,
    );
    assert_eq!(
        invoke(&mut gateway).unwrap_err().kind,
        ErrorKind::Unsupported
    );
    assert!(trace.lock().unwrap().starts.is_empty());
    let response = gateway
        .run(
            &request(),
            &Policy {
                require_usage: false,
                ..policy()
            },
            &mut VirtualControl::default(),
        )
        .unwrap();
    assert_eq!(response.usage, None);
    assert!(!response.usage_complete);
}

#[test]
fn t35_usage_exceeding_input_or_output_bounds_is_rejected() {
    for usage in [
        Usage {
            input_tokens: 99,
            output_tokens: 1,
        },
        Usage {
            input_tokens: 1,
            output_tokens: 99,
        },
    ] {
        let (mut gateway, _) = setup(vec![Script::response(Body::Text("ok".into()), Some(usage))]);
        assert_eq!(
            invoke(&mut gateway).unwrap_err().kind,
            ErrorKind::InvalidUsage
        );
        assert_eq!(
            (gateway.ledger.actual, gateway.ledger.held_unknown),
            (0, 10)
        );
    }
}

#[test]
fn t36_price_overflow_cannot_bypass_the_budget() {
    let mut model = full_model();
    model.rates = Some(Rates {
        input: u64::MAX,
        output: 2,
    });
    let (mut gateway, trace) = configured(vec![model], vec![success()], u64::MAX);
    assert_eq!(
        invoke(&mut gateway).unwrap_err().kind,
        ErrorKind::Arithmetic
    );
    assert!(trace.lock().unwrap().starts.is_empty());
}

#[test]
fn t37_unknown_prices_block_paid_dispatch_instead_of_implying_zero() {
    let (mut gateway, trace) = configured(
        vec![Model {
            rates: None,
            ..full_model()
        }],
        vec![success()],
        100,
    );
    assert_eq!(
        invoke(&mut gateway).unwrap_err().kind,
        ErrorKind::CostUnknown
    );
    assert!(trace.lock().unwrap().starts.is_empty());
}

#[test]
fn t38_cost_is_reserved_before_the_first_attempt() {
    let (mut gateway, trace) = configured(vec![full_model()], vec![success()], 9);
    assert_eq!(
        invoke(&mut gateway).unwrap_err().kind,
        ErrorKind::BudgetExceeded
    );
    assert!(trace.lock().unwrap().starts.is_empty());
}

#[test]
fn t39_input_byte_limits_include_unicode_and_policy_intersection() {
    for (model_limit, policy_limit) in [(64, 5), (5, 1024)] {
        let (mut gateway, trace) = configured(
            vec![Model {
                max_input_bytes: model_limit,
                ..full_model()
            }],
            vec![success()],
            100,
        );
        let req = Request {
            input: "\u{fc}\u{fc}\u{fc}".into(),
            ..request()
        };
        let p = Policy {
            max_input_bytes: policy_limit,
            ..policy()
        };
        assert_eq!(
            gateway
                .run(&req, &p, &mut VirtualControl::default())
                .unwrap_err()
                .kind,
            ErrorKind::InputLimit
        );
        assert!(trace.lock().unwrap().starts.is_empty());
    }
}

#[test]
fn t40_context_window_and_output_token_limits_are_jointly_enforced() {
    for req in [
        Request {
            input: "x".repeat(61),
            ..request()
        },
        Request {
            max_output_tokens: 17,
            ..request()
        },
        Request {
            max_output_tokens: 0,
            ..request()
        },
    ] {
        let (mut gateway, trace) = setup(vec![success()]);
        assert_eq!(
            gateway
                .run(&req, &policy(), &mut VirtualControl::default())
                .unwrap_err()
                .kind,
            ErrorKind::ContextLimit
        );
        assert!(trace.lock().unwrap().starts.is_empty());
    }
}

#[test]
fn t41_unsupported_token_counting_is_not_assumed_compatible() {
    let mut model = full_model();
    model.capabilities.token_counting = false;
    let (mut gateway, trace) = configured(vec![model], vec![success()], 100);
    assert_eq!(
        invoke(&mut gateway).unwrap_err().kind,
        ErrorKind::Unsupported
    );
    assert!(trace.lock().unwrap().starts.is_empty());
}

#[test]
fn t42_output_byte_limits_apply_even_to_billed_responses() {
    let (mut gateway, _) = setup(vec![Script::response(
        Body::Text("oversized".into()),
        measured(),
    )]);
    assert_eq!(
        gateway
            .run(
                &request(),
                &Policy {
                    max_output_bytes: 2,
                    ..policy()
                },
                &mut VirtualControl::default()
            )
            .unwrap_err()
            .kind,
        ErrorKind::OutputLimit
    );
    assert_eq!(gateway.ledger.actual, 6);
}

#[test]
fn t43_stream_event_count_is_bounded() {
    let mut script = Script::response(Body::Text("x".repeat(65)), measured());
    script.chunks = (0..65).map(|sequence| (0, sequence, "x".into())).collect();
    let (mut gateway, trace) = setup(vec![script]);
    assert_eq!(
        gateway
            .run(
                &Request {
                    stream: true,
                    ..request()
                },
                &policy(),
                &mut VirtualControl::default()
            )
            .unwrap_err()
            .kind,
        ErrorKind::OutputLimit
    );
    assert_eq!(trace.lock().unwrap().cancelled, 1);
}

#[test]
fn t44_inference_requires_both_explicit_initiation_and_policy_permission() {
    for p in [
        Policy {
            explicitly_initiated: false,
            ..policy()
        },
        Policy {
            inference: false,
            ..policy()
        },
    ] {
        let (mut gateway, trace) = setup(vec![success()]);
        assert_eq!(
            gateway
                .run(&request(), &p, &mut VirtualControl::default())
                .unwrap_err()
                .kind,
            ErrorKind::PolicyDenied
        );
        assert!(trace.lock().unwrap().starts.is_empty());
    }
}

#[test]
fn t45_private_inputs_and_findings_require_grants_and_keep_classification() {
    for classification in [DataClass::PrivateSource, DataClass::SecurityFinding] {
        let (mut gateway, trace) = setup(vec![success()]);
        let req = Request {
            classification,
            ..request()
        };
        assert_eq!(
            gateway
                .run(&req, &policy(), &mut VirtualControl::default())
                .unwrap_err()
                .kind,
            ErrorKind::PolicyDenied
        );
        assert!(trace.lock().unwrap().starts.is_empty());
        let response = gateway
            .run(
                &req,
                &Policy {
                    classified_input: true,
                    ..policy()
                },
                &mut VirtualControl::default(),
            )
            .unwrap();
        assert_eq!(response.classification, classification);
    }
}

#[test]
fn t46_remote_egress_needs_separate_permission_even_for_public_input() {
    let (mut gateway, trace) = configured(
        vec![Model {
            location: Location::Remote,
            ..full_model()
        }],
        vec![success()],
        100,
    );
    assert_eq!(
        invoke(&mut gateway).unwrap_err().kind,
        ErrorKind::PolicyDenied
    );
    assert!(trace.lock().unwrap().starts.is_empty());
    // This is still the local mock, not an actual remote transport.
    gateway
        .run(
            &request(),
            &Policy {
                remote_egress: true,
                ..policy()
            },
            &mut VirtualControl::default(),
        )
        .unwrap();
    assert_eq!(trace.lock().unwrap().starts.len(), 1);
}

#[test]
fn t47_ordinary_debug_and_diagnostics_exclude_sensitive_payloads() {
    let canary = "SENSITIVE_CANARY";
    let scripts = (0..70)
        .map(|_| Script::response(Body::Text(canary.into()), measured()))
        .collect();
    let (mut gateway, _) = configured(vec![full_model()], scripts, 10000);
    let req = Request {
        input: canary.into(),
        ..request()
    };
    for _ in 0..70 {
        let response = gateway
            .run(&req, &policy(), &mut VirtualControl::default())
            .unwrap();
        assert!(!format!("{req:?} {response:?}").contains(canary));
    }
    assert!(gateway.diagnostics.len() <= 64);
    assert!(!format!("{:?}", gateway.diagnostics).contains(canary));
}

#[test]
fn t48_deadline_overflow_is_rejected_before_dispatch() {
    let (mut gateway, trace) = setup(vec![success()]);
    let mut control = VirtualControl {
        now_ms: u64::MAX - 1,
        cancel_at_ms: None,
    };
    assert_eq!(
        gateway
            .run(&request(), &policy(), &mut control)
            .unwrap_err()
            .kind,
        ErrorKind::Arithmetic
    );
    assert!(trace.lock().unwrap().starts.is_empty());
}

#[test]
fn t49_completion_at_the_exclusive_deadline_times_out() {
    let mut script = success();
    script.delay_ms = 5;
    let (mut gateway, _) = setup(vec![script]);
    assert_eq!(
        gateway
            .run(
                &request(),
                &Policy {
                    timeout_ms: 5,
                    ..policy()
                },
                &mut VirtualControl::default()
            )
            .unwrap_err()
            .kind,
        ErrorKind::Timeout
    );
}

#[test]
fn t50_retry_delay_cannot_exceed_the_overall_deadline() {
    let (mut gateway, trace) = setup(vec![
        Script::failure(MockFailure::RateLimit(10), true),
        success(),
    ]);
    let p = Policy {
        timeout_ms: 10,
        max_attempts: 2,
        ..policy()
    };
    assert_eq!(
        gateway
            .run(&request(), &p, &mut VirtualControl::default())
            .unwrap_err()
            .kind,
        ErrorKind::RateLimited
    );
    assert_eq!(trace.lock().unwrap().starts.len(), 1);
}

#[test]
fn t51_response_model_mismatch_is_a_protocol_error() {
    let mut script = success();
    if let Terminal::Response { model, .. } = &mut script.terminal {
        *model = Some("other-model".into());
    }
    let (mut gateway, _) = setup(vec![script]);
    assert_eq!(invoke(&mut gateway).unwrap_err().kind, ErrorKind::Protocol);
    assert_eq!(
        (gateway.ledger.actual, gateway.ledger.held_unknown),
        (0, 10)
    );
}

#[test]
fn t52_unconfirmed_cancellation_is_not_reported_as_remote_termination() {
    let mut script = success();
    script.delay_ms = 10;
    script.cancel_confirmed = false;
    let (mut gateway, trace) = setup(vec![script]);
    let error = gateway
        .run(
            &request(),
            &Policy {
                timeout_ms: 5,
                ..policy()
            },
            &mut VirtualControl::default(),
        )
        .unwrap_err();
    assert_eq!(error.cancellation_confirmed, Some(false));
    assert_eq!(trace.lock().unwrap().cancelled, 1);
    assert_eq!(gateway.ledger.held_unknown, 10);
}

#[test]
fn t53_unknown_usage_on_an_earlier_attempt_stays_visible_after_retry_success() {
    let mut first = Script::failure(MockFailure::RateLimit(1), true);
    if let Terminal::Failure { usage, .. } = &mut first.terminal {
        *usage = None;
    }
    let (mut gateway, _) = configured(vec![full_model()], vec![first, success()], 20);
    let response = gateway
        .run(
            &request(),
            &Policy {
                max_attempts: 2,
                ..policy()
            },
            &mut VirtualControl::default(),
        )
        .unwrap();
    assert_eq!(
        (
            response.observed_cost_micro_usd,
            response.held_unknown_micro_usd
        ),
        (6, 10)
    );
    assert_eq!(response.cost_actual_micro_usd, None);
    assert!(!response.usage_complete);
    assert_eq!(
        (gateway.ledger.actual, gateway.ledger.held_unknown),
        (6, 10)
    );
}

#[test]
fn t54_known_partial_usage_is_charged_after_timeout() {
    let mut script = success();
    script.delay_ms = 10;
    script.cancel_usage = Some(Usage {
        input_tokens: 1,
        output_tokens: 0,
    });
    let (mut gateway, _) = setup(vec![script]);
    assert_eq!(
        gateway
            .run(
                &request(),
                &Policy {
                    timeout_ms: 5,
                    ..policy()
                },
                &mut VirtualControl::default()
            )
            .unwrap_err()
            .kind,
        ErrorKind::Timeout
    );
    assert_eq!((gateway.ledger.actual, gateway.ledger.held_unknown), (1, 0));
}

#[test]
fn t55_secret_classification_cannot_be_overridden_by_egress_permission() {
    let (mut gateway, trace) = setup(vec![success()]);
    let req = Request {
        classification: DataClass::Secret,
        ..request()
    };
    let p = Policy {
        classified_input: true,
        remote_egress: true,
        ..policy()
    };
    assert_eq!(
        gateway
            .run(&req, &p, &mut VirtualControl::default())
            .unwrap_err()
            .kind,
        ErrorKind::PolicyDenied
    );
    assert!(trace.lock().unwrap().starts.is_empty());
}

#[test]
fn t56_unsolicited_stream_events_are_rejected() {
    let (mut gateway, trace) = setup(vec![streaming()]);
    assert_eq!(invoke(&mut gateway).unwrap_err().kind, ErrorKind::Protocol);
    assert_eq!(trace.lock().unwrap().cancelled, 1);
}

#[test]
fn t57_unknown_model_never_dispatches_to_a_default_provider_model() {
    let (mut gateway, trace) = setup(vec![success()]);
    let req = Request {
        model: "unknown".into(),
        ..request()
    };
    assert_eq!(
        gateway
            .run(&req, &policy(), &mut VirtualControl::default())
            .unwrap_err()
            .kind,
        ErrorKind::UnknownModel
    );
    assert!(trace.lock().unwrap().starts.is_empty());
}

#[test]
fn t58_advertised_features_cannot_enable_unimplemented_structured_streaming() {
    let mut model = full_model();
    model.capabilities.structured_streaming = true;
    let (mut gateway, trace) = configured(vec![model], vec![success()], 100);
    let req = Request {
        format: Format::DecisionV1,
        stream: true,
        ..request()
    };
    assert_eq!(
        gateway
            .run(&req, &policy(), &mut VirtualControl::default())
            .unwrap_err()
            .kind,
        ErrorKind::Unsupported
    );
    assert!(trace.lock().unwrap().starts.is_empty());
}

#[test]
fn t59_missing_usage_is_visible_even_with_a_zero_price_quote() {
    let model = Model {
        rates: Some(Rates {
            input: 0,
            output: 0,
        }),
        ..full_model()
    };
    let (mut gateway, _) = configured(
        vec![model],
        vec![Script::response(Body::Text("ok".into()), None)],
        100,
    );
    let response = gateway
        .run(
            &request(),
            &Policy {
                require_usage: false,
                ..policy()
            },
            &mut VirtualControl::default(),
        )
        .unwrap();
    assert_eq!(response.cost_actual_micro_usd, None);
    assert!(!response.usage_complete);
    assert_eq!(gateway.ledger.unknown_attempts, 1);
}

#[test]
fn t60_invalid_retry_configuration_is_rejected_before_dispatch() {
    for p in [
        Policy {
            max_attempts: 0,
            ..policy()
        },
        Policy {
            max_attempts: 17,
            ..policy()
        },
        Policy {
            timeout_ms: 0,
            ..policy()
        },
    ] {
        let (mut gateway, trace) = setup(vec![success()]);
        assert_eq!(
            gateway
                .run(&request(), &p, &mut VirtualControl::default())
                .unwrap_err()
                .kind,
            ErrorKind::Protocol
        );
        assert!(trace.lock().unwrap().starts.is_empty());
    }
}

#[test]
fn t61_unsupported_capability_identifies_the_missing_feature() {
    let mut model = full_model();
    model.capabilities.structured = false;
    let (mut gateway, trace) = configured(vec![model], vec![success()], 100);
    let req = Request {
        format: Format::DecisionV1,
        ..request()
    };
    let failure = gateway
        .run(&req, &policy(), &mut VirtualControl::default())
        .unwrap_err();
    assert_eq!(failure.kind, ErrorKind::Unsupported);
    assert_eq!(failure.unsupported_feature, Some(Feature::StructuredOutput));
    assert!(trace.lock().unwrap().starts.is_empty());
}

#[test]
fn t62_partial_usage_cannot_release_budget_before_confirmed_cancellation() {
    let mut script = success();
    script.delay_ms = 10;
    script.cancel_confirmed = false;
    script.cancel_usage = Some(Usage {
        input_tokens: 1,
        output_tokens: 0,
    });
    let (mut gateway, _) = configured(vec![full_model()], vec![script, success()], 10);
    let failure = gateway
        .run(
            &request(),
            &Policy {
                timeout_ms: 5,
                ..policy()
            },
            &mut VirtualControl::default(),
        )
        .unwrap_err();
    assert_eq!(failure.cancellation_confirmed, Some(false));
    assert_eq!(
        (gateway.ledger.actual, gateway.ledger.held_unknown),
        (0, 10)
    );
    assert_eq!(gateway.ledger.unknown_attempts, 1);
    assert_eq!(
        invoke(&mut gateway).unwrap_err().kind,
        ErrorKind::BudgetExceeded
    );
}
