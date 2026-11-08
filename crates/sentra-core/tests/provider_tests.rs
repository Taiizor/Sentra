//! Integration tests for Model Provider Abstraction, Privacy Redaction, and Local Adapters (REQ-F03, REQ-F08, REQ-F09, ADR-0005).

use std::collections::BTreeMap;

use sentra_core::{
    LocalInferenceEndpointProvider, ProviderBody, ProviderCapabilities, ProviderDataClass,
    ProviderErrorKind, ProviderFormat, ProviderGateway, ProviderLocation, ProviderModel,
    ProviderPolicy, ProviderRates, ProviderRequest, ProviderScript, ProviderUsage, ProviderValue,
    ProviderVirtualControl, RedactionFilter, SyntheticMockProvider, full_model,
};

fn standard_policy() -> ProviderPolicy {
    ProviderPolicy {
        explicitly_initiated: true,
        metadata: true,
        inference: true,
        remote_egress: false,
        classified_input: true,
        require_usage: true,
        require_cancellation: true,
        max_input_bytes: 1024,
        max_output_bytes: 1024,
        timeout_ms: 100,
        max_attempts: 1,
        max_retry_delay_ms: 10,
    }
}

#[test]
fn test_provider_initialization_and_discovery() {
    let mock = SyntheticMockProvider::new(vec![full_model()], vec![]);
    let mut gateway = ProviderGateway::new(Some(Box::new(mock)), 10_000);

    // Uninitiated policy fails closed
    let denied_policy = ProviderPolicy {
        explicitly_initiated: false,
        ..standard_policy()
    };
    let err = gateway.initialize(&denied_policy).unwrap_err();
    assert_eq!(err.kind, ProviderErrorKind::PolicyDenied);

    // Explicitly initiated policy succeeds
    let policy = standard_policy();
    gateway.initialize(&policy).expect("initialize");

    let models = gateway.discover(&policy).expect("discover");
    assert_eq!(models.len(), 1);
    assert_eq!(models[0].id, "mock-full");
    assert_eq!(models[0].location, ProviderLocation::Local);
}

#[test]
fn test_provider_execution_and_budget_settlement() {
    let script = ProviderScript::response(
        ProviderBody::Text("Security review verdict: No vulnerabilities found.".to_string()),
        Some(ProviderUsage {
            input_tokens: 10,
            output_tokens: 5,
        }),
    );
    let mock = SyntheticMockProvider::new(vec![full_model()], vec![script]);
    let mut gateway = ProviderGateway::new(Some(Box::new(mock)), 100_000);
    let policy = standard_policy();
    gateway.initialize(&policy).expect("init");
    gateway.discover(&policy).expect("discover");

    let request = ProviderRequest {
        id: 1,
        model: "mock-full".to_string(),
        input: "Analyze auth.rs".to_string(),
        classification: ProviderDataClass::PrivateSource,
        format: ProviderFormat::Text,
        stream: false,
        max_output_tokens: 16,
    };

    let mut control = ProviderVirtualControl::default();
    let response = gateway.run(&request, &policy, &mut control).expect("run");

    assert_eq!(
        response.body,
        ProviderBody::Text("Security review verdict: No vulnerabilities found.".to_string())
    );
    assert_eq!(response.classification, ProviderDataClass::PrivateSource);
    assert!(response.usage_complete);
    assert!(response.cost_actual_micro_usd.is_some());
    // Rates in full_model: input = 1, output = 2.
    // 10 * 1 + 5 * 2 = 20 micro-USD
    assert_eq!(response.cost_actual_micro_usd.unwrap(), 20);
    assert_eq!(gateway.ledger.actual, 20);
    assert_eq!(gateway.ledger.held_unknown, 0);
}

#[test]
fn test_provider_budget_exceeded_fails_closed() {
    let mock = SyntheticMockProvider::new(vec![full_model()], vec![]);
    // Budget ceiling set to tiny amount (5 micro-USD)
    let mut gateway = ProviderGateway::new(Some(Box::new(mock)), 5);
    let policy = standard_policy();
    gateway.initialize(&policy).expect("init");
    gateway.discover(&policy).expect("discover");

    let request = ProviderRequest {
        id: 2,
        model: "mock-full".to_string(),
        input: "Long prompt needing more budget than 5 micro-USD".to_string(),
        classification: ProviderDataClass::PrivateSource,
        format: ProviderFormat::Text,
        stream: false,
        max_output_tokens: 16,
    };

    let mut control = ProviderVirtualControl::default();
    let err = gateway.run(&request, &policy, &mut control).unwrap_err();
    assert_eq!(err.kind, ProviderErrorKind::BudgetExceeded);
}

#[test]
fn test_provider_cancellation() {
    let mut script = ProviderScript::response(
        ProviderBody::Text("Should not be delivered".to_string()),
        Some(ProviderUsage {
            input_tokens: 5,
            output_tokens: 5,
        }),
    );
    script.delay_ms = 50;

    let mock = SyntheticMockProvider::new(vec![full_model()], vec![script]);
    let mut gateway = ProviderGateway::new(Some(Box::new(mock)), 100_000);
    let policy = standard_policy();
    gateway.initialize(&policy).expect("init");
    gateway.discover(&policy).expect("discover");

    let request = ProviderRequest {
        id: 3,
        model: "mock-full".to_string(),
        input: "Test cancellation".to_string(),
        classification: ProviderDataClass::PrivateSource,
        format: ProviderFormat::Text,
        stream: false,
        max_output_tokens: 16,
    };

    // Cancellation scheduled at 5ms (before completion at 50ms)
    let mut control = ProviderVirtualControl {
        now_ms: 0,
        cancel_at_ms: Some(5),
    };
    let err = gateway.run(&request, &policy, &mut control).unwrap_err();
    assert_eq!(err.kind, ProviderErrorKind::Cancelled);
    assert_eq!(err.cancellation_confirmed, Some(true));
}

#[test]
fn test_provider_secret_redaction() {
    let raw_prompt = r#"
Here is our config:
aws_key = "AKIA1234567890ABCDEF"
github_token = "ghp_111122223333444455556666777788889999"
auth_header = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz"
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y7...
-----END RSA PRIVATE KEY-----
"#;

    assert!(RedactionFilter::contains_secrets(raw_prompt));

    let sanitized = RedactionFilter::redact_text(raw_prompt);

    assert!(!sanitized.contains("AKIA1234567890ABCDEF"));
    assert!(!sanitized.contains("ghp_111122223333444455556666777788889999"));
    assert!(!sanitized.contains("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz"));
    assert!(!sanitized.contains("MIIEowIBAAKCAQEA0Y7"));

    assert!(sanitized.contains("[REDACTED_AWS_KEY]"));
    assert!(sanitized.contains("[REDACTED_TOKEN]"));
    assert!(sanitized.contains("[REDACTED_BEARER_TOKEN]"));
    assert!(sanitized.contains("[REDACTED_PRIVATE_KEY]"));

    assert!(!RedactionFilter::contains_secrets(&sanitized));
}

#[test]
fn test_local_inference_endpoint_zero_egress() {
    let local_model = ProviderModel {
        id: "local-llama-3".to_string(),
        location: ProviderLocation::Local,
        capabilities: ProviderCapabilities {
            structured: true,
            streaming: false,
            structured_streaming: false,
            cancellation: true,
            token_counting: true,
            usage: true,
        },
        context_tokens: 4096,
        max_input_bytes: 4096,
        max_output_tokens: 512,
        max_response_bytes: 4096,
        rates: Some(ProviderRates {
            input: 0,
            output: 0,
        }),
    };

    let local_provider = LocalInferenceEndpointProvider::new("localhost:11434", vec![local_model]);
    let mut gateway = ProviderGateway::new(Some(Box::new(local_provider)), 0);

    let policy = ProviderPolicy {
        remote_egress: false, // Strictly zero remote egress
        ..standard_policy()
    };

    gateway.initialize(&policy).expect("init local");
    let models = gateway.discover(&policy).expect("discover local");
    assert_eq!(models.len(), 1);
    assert_eq!(models[0].id, "local-llama-3");

    let request = ProviderRequest {
        id: 4,
        model: "local-llama-3".to_string(),
        input: "Review function for bounds check".to_string(),
        classification: ProviderDataClass::PrivateSource,
        format: ProviderFormat::Text,
        stream: false,
        max_output_tokens: 64,
    };

    let mut control = ProviderVirtualControl::default();
    let response = gateway
        .run(&request, &policy, &mut control)
        .expect("run local");

    assert!(
        matches!(response.body, ProviderBody::Text(t) if t.contains("Local inference completed"))
    );
}

#[test]
fn test_structured_decision_v1_format_validation() {
    let mut obj = BTreeMap::new();
    obj.insert(
        "summary".to_string(),
        ProviderValue::Text("Vulnerability verified".to_string()),
    );
    obj.insert("accepted".to_string(), ProviderValue::Bool(true));

    let valid_body = ProviderBody::Structured(ProviderValue::Object(obj));
    assert!(valid_body.validate(ProviderFormat::DecisionV1).is_ok());

    // Invalid body (missing accepted field)
    let mut invalid_obj = BTreeMap::new();
    invalid_obj.insert(
        "summary".to_string(),
        ProviderValue::Text("Incomplete".to_string()),
    );
    let invalid_body = ProviderBody::Structured(ProviderValue::Object(invalid_obj));
    assert!(invalid_body.validate(ProviderFormat::DecisionV1).is_err());
}

#[test]
fn test_two_approved_model_backends_run_same_contract() {
    // Backend 1: SyntheticMockProvider
    let script = ProviderScript::response(
        ProviderBody::Text("Mock response".to_string()),
        Some(ProviderUsage {
            input_tokens: 4,
            output_tokens: 2,
        }),
    );
    let mock = SyntheticMockProvider::new(vec![full_model()], vec![script]);
    let mut gateway_mock = ProviderGateway::new(Some(Box::new(mock)), 10_000);

    // Backend 2: LocalInferenceEndpointProvider
    let local_model = ProviderModel {
        id: "local-phi".to_string(),
        location: ProviderLocation::Local,
        capabilities: ProviderCapabilities {
            structured: true,
            streaming: false,
            structured_streaming: false,
            cancellation: true,
            token_counting: true,
            usage: true,
        },
        context_tokens: 2048,
        max_input_bytes: 1024,
        max_output_tokens: 128,
        max_response_bytes: 1024,
        rates: Some(ProviderRates {
            input: 1,
            output: 1,
        }),
    };
    let local = LocalInferenceEndpointProvider::new("localhost:8080", vec![local_model]);
    let mut gateway_local = ProviderGateway::new(Some(Box::new(local)), 10_000);

    let policy = standard_policy();
    gateway_mock.initialize(&policy).expect("init mock");
    gateway_local.initialize(&policy).expect("init local");
    gateway_mock.discover(&policy).expect("discover mock");
    gateway_local.discover(&policy).expect("discover local");

    let req_mock = ProviderRequest {
        id: 10,
        model: "mock-full".to_string(),
        input: "Test".to_string(),
        classification: ProviderDataClass::Public,
        format: ProviderFormat::Text,
        stream: false,
        max_output_tokens: 10,
    };

    let req_local = ProviderRequest {
        id: 11,
        model: "local-phi".to_string(),
        input: "Test".to_string(),
        classification: ProviderDataClass::Public,
        format: ProviderFormat::Text,
        stream: false,
        max_output_tokens: 10,
    };

    let mut control = ProviderVirtualControl::default();
    let resp_mock = gateway_mock
        .run(&req_mock, &policy, &mut control)
        .expect("run mock");
    let resp_local = gateway_local
        .run(&req_local, &policy, &mut control)
        .expect("run local");

    // Both satisfy the exact same contract
    assert_eq!(resp_mock.classification, ProviderDataClass::Public);
    assert_eq!(resp_local.classification, ProviderDataClass::Public);
    assert!(resp_mock.usage.is_some());
    assert!(resp_local.usage.is_some());
}
