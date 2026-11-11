//! `prompt --skills` composition: workflow rules and schema are preserved,
//! skill ids are de-duplicated, and unknown ids are rejected.

use sentra_core::research::{
    ResearchRole, SkillPromptComposer, ThreatModelingPromptBuilder, VerificationPromptBuilder,
    prompt::SkillPromptError,
};

#[test]
fn augmenting_a_workflow_prompt_keeps_grounding_rules_and_schema() {
    let base = ThreatModelingPromptBuilder::build_stride_assessment_prompt(
        "workspace",
        "workspace",
        "Target scope: workspace",
    );
    let (prompt, ids) =
        SkillPromptComposer::augment_prompt_with_ids(base.clone(), &["stride-analysis-patterns"])
            .unwrap();

    assert_eq!(ids, vec!["stride-analysis-patterns"]);
    assert!(prompt.system_prompt.starts_with(&base.system_prompt));
    assert!(prompt.system_prompt.contains("Evidence & Grounding Rules"));
    assert!(
        prompt
            .system_prompt
            .contains("Activated Domain Security Guidelines")
    );
    assert!(prompt.system_prompt.contains("(stride-analysis-patterns)"));
    assert_eq!(prompt.user_prompt, base.user_prompt);
    assert_eq!(prompt.expected_schema, base.expected_schema);
    assert!(prompt.expected_schema.is_some());
    assert!(
        prompt
            .to_composite_prompt()
            .contains("OUTPUT FORMAT SPECIFICATION")
    );
}

#[test]
fn duplicate_ids_are_injected_once_and_frontmatter_is_stripped() {
    let base = VerificationPromptBuilder::build_dual_state_verification_prompt("v", "t", "d", "e");
    let (prompt, ids) = SkillPromptComposer::augment_prompt_with_ids(
        base,
        &[
            "stride-analysis-patterns",
            " STRIDE-ANALYSIS-PATTERNS ",
            "stride-analysis-patterns",
        ],
    )
    .unwrap();
    assert_eq!(ids, vec!["stride-analysis-patterns"]);
    assert_eq!(
        prompt
            .system_prompt
            .matches("### Cognitive Playbook:")
            .count(),
        1
    );
    assert!(
        !prompt
            .system_prompt
            .contains("\nname: stride-analysis-patterns\n")
    );
    assert!(!prompt.system_prompt.contains('\r'));
}

#[test]
fn unknown_ids_are_rejected() {
    let base = VerificationPromptBuilder::build_dual_state_verification_prompt("v", "t", "d", "e");
    let err = SkillPromptComposer::augment_prompt_with_ids(
        base,
        &["stride-analysis-patterns", "bogus-id", "bogus-id"],
    )
    .unwrap_err();
    assert_eq!(
        err,
        SkillPromptError::UnknownSkills {
            ids: vec!["bogus-id".to_string()]
        }
    );
    assert_eq!(err.code(), "skill_not_found");
    assert_eq!(err.exit_code(), 7);

    let err = SkillPromptComposer::try_compose_role_prompt(
        ResearchRole::Analyst,
        "task",
        &["bogus-id"],
        "",
    )
    .unwrap_err();
    assert_eq!(err.code(), "skill_not_found");
}

#[test]
fn empty_skill_list_leaves_the_prompt_unchanged() {
    let base = VerificationPromptBuilder::build_dual_state_verification_prompt("v", "t", "d", "e");
    let (prompt, ids) = SkillPromptComposer::augment_prompt_with_ids(base.clone(), &[]).unwrap();
    assert!(ids.is_empty());
    assert_eq!(prompt, base);
}

#[test]
fn general_composition_resolves_skills_strictly() {
    let prompt = SkillPromptComposer::try_compose_role_prompt(
        ResearchRole::Analyst,
        "Analyze authentication routes",
        &["golang-security", "golang-security"],
        "Target: pkg/auth/handler.go",
    )
    .unwrap();
    assert!(prompt.system_prompt.contains("Vulnerability Analyst"));
    assert_eq!(
        prompt
            .system_prompt
            .matches("### Cognitive Playbook:")
            .count(),
        1
    );
    assert!(prompt.user_prompt.contains("Target: pkg/auth/handler.go"));
}
