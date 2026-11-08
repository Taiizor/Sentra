//! Integration tests for Linux user-space C/C++ fuzzing, crash reproduction,
//! input minimization, and tri-method comparison benchmarks (REQ-F09, REQ-F10, REQ-F11, Roadmap Phase 3).

use sentra_core::{
    CrashArtifact, FuzzEngine, FuzzRunConfig, FuzzTarget, ResearchApproach, SanitizerType,
    TimestampUtc, VulnerabilityCategory, generate_reference_tri_method_matrix, minimize_input,
    reference_root_cause_targets,
};

#[test]
fn test_reference_targets_loaded() {
    let targets = reference_root_cause_targets();
    assert_eq!(targets.len(), 3);

    let t1 = &targets[0];
    assert_eq!(t1.target_id, "cwe-120-packet-buffer-overflow");
    assert_eq!(t1.root_cause, VulnerabilityCategory::BufferOverflow);
    assert_eq!(t1.expected_sanitizer, SanitizerType::AddressSanitizer);
    assert_eq!(t1.fatal_signal, 11);

    let t2 = &targets[1];
    assert_eq!(t2.target_id, "cwe-416-callback-use-after-free");
    assert_eq!(t2.root_cause, VulnerabilityCategory::UseAfterFree);
    assert_eq!(t2.expected_sanitizer, SanitizerType::AddressSanitizer);
    assert_eq!(t2.fatal_signal, 11);

    let t3 = &targets[2];
    assert_eq!(t3.target_id, "cwe-190-alloc-integer-overflow");
    assert_eq!(t3.root_cause, VulnerabilityCategory::IntegerOverflow);
    assert_eq!(
        t3.expected_sanitizer,
        SanitizerType::UndefinedBehaviorSanitizer
    );
    assert_eq!(t3.fatal_signal, 6);
}

#[test]
fn test_reproduction_cwe_120_buffer_overflow() {
    let now = TimestampUtc::now();
    let targets = reference_root_cause_targets();
    let target = &targets[0];

    // 1. Crashing seed triggers vulnerability
    let crash = target
        .execute_vulnerable(target.crashing_seed, now)
        .expect("reproduction must succeed on vulnerable target");

    assert_eq!(crash.target_id, target.target_id);
    assert_eq!(crash.root_cause, VulnerabilityCategory::BufferOverflow);
    assert_eq!(crash.fatal_signal, Some(11));
    assert_eq!(crash.sanitizer, Some(SanitizerType::AddressSanitizer));
    assert!(crash.reproducible_in_fresh_worker);
    assert!(crash.minimized_input_bytes.is_some());

    // 2. Patched code safely rejects/handles the crashing seed
    assert!(target.execute_patched(target.crashing_seed));
}

#[test]
fn test_reproduction_cwe_416_use_after_free() {
    let now = TimestampUtc::now();
    let targets = reference_root_cause_targets();
    let target = &targets[1];

    // 1. Crashing seed triggers UAF
    let crash = target
        .execute_vulnerable(target.crashing_seed, now)
        .expect("reproduction must succeed on UAF target");

    assert_eq!(crash.target_id, target.target_id);
    assert_eq!(crash.root_cause, VulnerabilityCategory::UseAfterFree);
    assert_eq!(crash.fatal_signal, Some(11));
    assert_eq!(crash.sanitizer, Some(SanitizerType::AddressSanitizer));
    assert!(crash.reproducible_in_fresh_worker);

    // 2. Patched code prevents UAF
    assert!(target.execute_patched(target.crashing_seed));
}

#[test]
fn test_reproduction_cwe_190_integer_overflow() {
    let now = TimestampUtc::now();
    let targets = reference_root_cause_targets();
    let target = &targets[2];

    // 1. Crashing seed triggers integer overflow
    let crash = target
        .execute_vulnerable(target.crashing_seed, now)
        .expect("reproduction must succeed on integer overflow target");

    assert_eq!(crash.target_id, target.target_id);
    assert_eq!(crash.root_cause, VulnerabilityCategory::IntegerOverflow);
    assert_eq!(crash.fatal_signal, Some(6));
    assert_eq!(
        crash.sanitizer,
        Some(SanitizerType::UndefinedBehaviorSanitizer)
    );
    assert!(crash.reproducible_in_fresh_worker);

    // 2. Patched code rejects overflow
    assert!(target.execute_patched(target.crashing_seed));
}

#[test]
fn test_input_minimization_reduces_size() {
    // Large 128-byte input where only bytes [42..46] equal to b"DEAD" trigger the crash
    let mut large_input = vec![b'X'; 128];
    large_input[42..46].copy_from_slice(b"DEAD");

    let is_crashing = |bytes: &[u8]| -> bool { bytes.windows(4).any(|w| w == b"DEAD") };

    assert!(is_crashing(&large_input));

    let minimized = minimize_input(&large_input, is_crashing);
    assert!(is_crashing(&minimized));
    // Minimized input should be dramatically smaller than 128 bytes
    assert!(minimized.len() <= 16);
    assert!(minimized.len() >= 4);
}

#[test]
fn test_tri_method_comparison_matrix_generation_and_metrics() {
    // Generate canonical 10-target, 3-repetition benchmark matrix
    let matrix = generate_reference_tri_method_matrix();
    assert_eq!(matrix.runs.len(), 90); // 10 targets * 3 reps * 3 approaches = 90 runs

    // 1. Classical Fuzzer summary
    let fuzzer_summary = matrix.summary_by_approach(ResearchApproach::ClassicalFuzzer);
    assert_eq!(fuzzer_summary.total_runs, 30);
    assert_eq!(fuzzer_summary.average_cost_micro_usd, 0); // Open source fuzzer has zero LLM token cost
    assert!(fuzzer_summary.reproduction_rate > 0.60);
    assert_eq!(fuzzer_summary.patch_verified_count, 0); // Raw fuzzer cannot create patches

    // 2. OSS-CRS Candidate summary
    let oss_crs_summary = matrix.summary_by_approach(ResearchApproach::OssCrsCandidate);
    assert_eq!(oss_crs_summary.total_runs, 30);
    assert_eq!(oss_crs_summary.reproduction_rate, 1.0);
    assert!(oss_crs_summary.patch_verified_count > 0);
    assert!(oss_crs_summary.average_cost_micro_usd > 0);

    // 3. Sentra Agent-Assisted summary
    let sentra_summary = matrix.summary_by_approach(ResearchApproach::SentraAgentAssisted);
    assert_eq!(sentra_summary.total_runs, 30);
    assert_eq!(sentra_summary.reproduction_rate, 1.0);
    assert_eq!(sentra_summary.patch_verification_rate, 1.0); // Dual-state verification achieves 100%
    assert!(sentra_summary.average_branches_covered > fuzzer_summary.average_branches_covered);

    // 4. Markdown report generation
    let report = matrix.generate_markdown_report();
    assert!(report.contains("classical_fuzzer"));
    assert!(report.contains("oss_crs_candidate"));
    assert!(report.contains("sentra_agent_assisted"));
}

#[test]
fn test_crash_artifact_serde_roundtrip() {
    let now = TimestampUtc::now();
    let targets = reference_root_cause_targets();
    let crash = targets[0]
        .execute_vulnerable(targets[0].crashing_seed, now)
        .expect("crash artifact");

    let json = serde_json::to_string(&crash).expect("serialize crash artifact");
    let recovered: CrashArtifact = serde_json::from_str(&json).expect("deserialize crash artifact");

    assert_eq!(recovered.artifact_id, crash.artifact_id);
    assert_eq!(recovered.target_id, crash.target_id);
    assert_eq!(recovered.root_cause, crash.root_cause);
    assert_eq!(recovered.fatal_signal, crash.fatal_signal);
    assert_eq!(recovered.sanitizer, crash.sanitizer);
    assert_eq!(recovered.raw_input_bytes, crash.raw_input_bytes);
    assert_eq!(recovered.minimized_input_bytes, crash.minimized_input_bytes);
    assert_eq!(
        recovered.reproducible_in_fresh_worker,
        crash.reproducible_in_fresh_worker
    );
}

#[test]
fn test_fuzz_target_and_config_serde_roundtrip() {
    let target = FuzzTarget {
        target_id: "cwe-120-packet-parser".to_string(),
        name: "Packet Parser Target".to_string(),
        harness_path: "fuzz/fuzz_packet.c".to_string(),
        sanitizers: vec![
            SanitizerType::AddressSanitizer,
            SanitizerType::UndefinedBehaviorSanitizer,
        ],
        timeout_per_run_secs: 25,
        memory_limit_mib: 1024,
    };

    let config = FuzzRunConfig {
        engine: FuzzEngine::LibFuzzer,
        max_duration_secs: 300,
        max_iterations: 50_000,
        seed_corpus_path: Some("fuzz/corpus/packet".to_string()),
        dictionary_path: Some("fuzz/dict/packet.dict".to_string()),
    };

    let target_json = serde_json::to_string(&target).expect("serialize target");
    let target_recovered: FuzzTarget =
        serde_json::from_str(&target_json).expect("deserialize target");
    assert_eq!(target_recovered, target);

    let config_json = serde_json::to_string(&config).expect("serialize config");
    let config_recovered: FuzzRunConfig =
        serde_json::from_str(&config_json).expect("deserialize config");
    assert_eq!(config_recovered, config);
}
