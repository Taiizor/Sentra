//! Skill installer behavior: per-target locations, complete skill trees,
//! idempotent refresh, legacy cleanup, Aider config merging, and errors.
//!
//! Every test uses private temporary directories and explicit [`HostDirs`],
//! so nothing touches the real home directory or the repository.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use sentra_core::skills::{
    AgentTarget, SkillDefinition, find_skill_by_id,
    installer::{
        FileStatus, HostDirs, InstallError, LegacyAction, SkillDelivery, install_selected_skills,
        install_skills_in, resolve_skill_ids,
    },
    list_builtin_skills,
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "sentra-skill-installer-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        if path.exists() {
            fs::remove_dir_all(&path).unwrap();
        }
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Sandbox {
    _root: TempDir,
    workspace: PathBuf,
    host: HostDirs,
}

impl Sandbox {
    fn new(label: &str, windows: bool) -> Self {
        let root = TempDir::new(label);
        let workspace = root.path().join("ws");
        let home = root.path().join("home");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&home).unwrap();
        let host = HostDirs {
            home: Some(home.clone()),
            appdata: Some(home.join("AppData").join("Roaming")),
            xdg_config_home: None,
            windows,
        };
        Self {
            _root: root,
            workspace,
            host,
        }
    }

    fn home(&self) -> PathBuf {
        self.host.home.clone().unwrap()
    }

    fn install(
        &self,
        ids: &[&str],
        target: AgentTarget,
        global: bool,
    ) -> Result<sentra_core::skills::InstallReport, InstallError> {
        let skills = resolve_skill_ids(ids)?;
        install_skills_in(&self.host, &skills, target, global, &self.workspace)
    }
}

/// A bundled skill that ships supporting files next to `SKILL.md`.
fn skill_with_supporting_files() -> &'static SkillDefinition {
    list_builtin_skills()
        .iter()
        .max_by_key(|skill| skill.files().len())
        .expect("bundled skills")
}

fn join(base: &Path, rel: &str) -> PathBuf {
    rel.split('/')
        .fold(base.to_path_buf(), |path, part| path.join(part))
}

fn assert_full_tree(skills_dir: &Path, skill: &SkillDefinition) {
    let skill_dir = skills_dir.join(skill.id);
    assert_eq!(
        fs::read(skill_dir.join("SKILL.md")).unwrap(),
        skill.content.as_bytes(),
        "SKILL.md for {}",
        skill.id
    );
    for (relative, bytes) in skill.files() {
        if *relative == "SKILL.md" {
            continue;
        }
        let path = join(&skill_dir, relative);
        assert_eq!(&fs::read(&path).unwrap()[..], *bytes, "{}", path.display());
    }
}

#[test]
fn every_native_target_gets_the_complete_skill_tree_in_its_documented_location() {
    let skill = skill_with_supporting_files();
    assert!(
        skill.files().len() > 1,
        "expected supporting files in {}",
        skill.id
    );

    let workspace_expectations: &[(AgentTarget, &[&str])] = &[
        (AgentTarget::Claude, &[".claude", "skills"]),
        (AgentTarget::Antigravity, &[".agents", "skills"]),
        (AgentTarget::Cursor, &[".cursor", "skills"]),
        (AgentTarget::Windsurf, &[".agents", "skills"]),
        (AgentTarget::Cline, &[".cline", "skills"]),
        (AgentTarget::Roo, &[".roo", "skills"]),
        (AgentTarget::Devin, &[".devin", "skills"]),
        (AgentTarget::Codex, &[".agents", "skills"]),
        (AgentTarget::Copilot, &[".github", "skills"]),
        (AgentTarget::Zed, &[".agents", "skills"]),
        (AgentTarget::OpenCode, &[".opencode", "skills"]),
        (AgentTarget::Trae, &[".trae", "skills"]),
        (AgentTarget::Kimi, &[".agents", "skills"]),
        (AgentTarget::Augment, &[".augment", "skills"]),
        (AgentTarget::OpenHands, &[".agents", "skills"]),
        (AgentTarget::Goose, &[".agents", "skills"]),
        (AgentTarget::Tabnine, &[".tabnine", "agent", "skills"]),
        (AgentTarget::Junie, &[".junie", "skills"]),
        (AgentTarget::Warp, &[".agents", "skills"]),
        (AgentTarget::Droid, &[".factory", "skills"]),
        (AgentTarget::Kiro, &[".kiro", "skills"]),
        (AgentTarget::Qwen, &[".qwen", "skills"]),
        (AgentTarget::Hermes, &[".hermes", "skills"]),
        (AgentTarget::Replit, &[".agents", "skills"]),
    ];

    for (target, parts) in workspace_expectations {
        let sandbox = Sandbox::new("native-ws", false);
        let report = sandbox.install(&[skill.id], *target, false).unwrap();
        let expected = parts
            .iter()
            .fold(sandbox.workspace.clone(), |path, part| path.join(part));
        assert_eq!(report.destination_dir, expected, "{target}");
        assert_full_tree(&expected, skill);
        assert_eq!(report.skills, vec![skill.id]);
        assert_eq!(
            report.installed_files.len(),
            skill.files().len(),
            "{target}"
        );
        assert!(report.files.iter().all(|f| f.status == FileStatus::Created));
        for always_on in [
            ".cursorrules",
            ".windsurfrules",
            ".clinerules",
            ".roorules",
            "CONVENTIONS.md",
        ] {
            assert!(
                !sandbox.workspace.join(always_on).exists(),
                "{target}: {always_on}"
            );
        }
        assert!(
            !sandbox
                .workspace
                .join(".github")
                .join("copilot-instructions.md")
                .exists()
        );
    }
}

#[test]
fn global_locations_follow_vendor_documentation() {
    let skill = find_skill_by_id("stride-analysis-patterns").unwrap();
    let cases: &[(AgentTarget, bool, &[&str])] = &[
        (AgentTarget::Claude, false, &[".claude", "skills"]),
        (
            AgentTarget::Antigravity,
            false,
            &[".gemini", "config", "skills"],
        ),
        (AgentTarget::Cursor, false, &[".cursor", "skills"]),
        (AgentTarget::Windsurf, false, &[".agents", "skills"]),
        (AgentTarget::Roo, false, &[".roo", "skills"]),
        (AgentTarget::Augment, false, &[".augment", "skills"]),
        (AgentTarget::Copilot, false, &[".copilot", "skills"]),
        (AgentTarget::Zed, false, &[".agents", "skills"]),
        (AgentTarget::Warp, false, &[".agents", "skills"]),
        (AgentTarget::Kimi, false, &[".agents", "skills"]),
        (AgentTarget::Goose, true, &[".agents", "skills"]),
        (AgentTarget::Codex, false, &[".agents", "skills"]),
        (
            AgentTarget::OpenCode,
            false,
            &[".config", "opencode", "skills"],
        ),
        (AgentTarget::Devin, false, &[".config", "devin", "skills"]),
        (
            AgentTarget::Devin,
            true,
            &["AppData", "Roaming", "devin", "skills"],
        ),
    ];
    for (target, windows, parts) in cases {
        let sandbox = Sandbox::new("global", *windows);
        let report = sandbox.install(&[skill.id], *target, true).unwrap();
        let expected = parts
            .iter()
            .fold(sandbox.home(), |path, part| path.join(part));
        assert_eq!(
            report.destination_dir, expected,
            "{target} windows={windows}"
        );
        assert!(report.is_global);
        assert_full_tree(&expected, skill);
        assert!(
            !sandbox.workspace.join(".agents").exists(),
            "{target} wrote into workspace"
        );
    }
}

#[test]
fn unsupported_targets_and_scopes_fail_without_writing() {
    let sandbox = Sandbox::new("unsupported", false);
    let cases = [
        (AgentTarget::Cody, false, "unsupported_target"),
        (AgentTarget::Cody, true, "unsupported_target"),
        (AgentTarget::AmazonQ, true, "unsupported_scope"),
        (AgentTarget::ContinueDev, true, "unsupported_scope"),
        (AgentTarget::Replit, true, "unsupported_scope"),
    ];
    for (target, global, code) in cases {
        let err = sandbox
            .install(&["security-review"], target, global)
            .unwrap_err();
        assert_eq!(err.code(), code, "{target}");
        assert_eq!(err.exit_code(), 2);
        let json = err.to_json();
        assert_eq!(json["error"], code);
        assert_eq!(json["target"], target.as_str());
    }
    assert_eq!(fs::read_dir(&sandbox.workspace).unwrap().count(), 0);
    assert_eq!(fs::read_dir(sandbox.home()).unwrap().count(), 0);
}

#[test]
fn amp_is_its_own_target_not_an_alias_for_replit() {
    assert_eq!(AgentTarget::parse("amp"), Some(AgentTarget::Amp));
    assert_eq!(AgentTarget::parse("replit"), Some(AgentTarget::Replit));
    assert_eq!(AgentTarget::parse("kimi-code"), Some(AgentTarget::Kimi));

    // Amp: project `.agents/skills/`, user `~/.config/agents/skills/`
    // (https://ampcode.com/docs/customize/skills).
    let skill = find_skill_by_id("security-review").unwrap();
    let sandbox = Sandbox::new("amp", false);
    let ws = sandbox
        .install(&[skill.id], AgentTarget::Amp, false)
        .unwrap();
    assert_eq!(
        ws.destination_dir,
        join(&sandbox.workspace, ".agents/skills")
    );
    let global = sandbox
        .install(&[skill.id], AgentTarget::Amp, true)
        .unwrap();
    let expected = join(&sandbox.home(), ".config/agents/skills");
    assert_eq!(global.destination_dir, expected);
    assert_full_tree(&expected, skill);
}

#[test]
fn devin_global_skills_follow_xdg_config_home() {
    let skill = find_skill_by_id("security-review").unwrap();
    let mut sandbox = Sandbox::new("devin-xdg", false);
    let xdg = sandbox.home().join("xdg");
    sandbox.host.xdg_config_home = Some(xdg.clone());
    let report = sandbox
        .install(&[skill.id], AgentTarget::Devin, true)
        .unwrap();
    assert_eq!(report.destination_dir, join(&xdg, "devin/skills"));
}

#[test]
fn aider_requires_an_explicit_skill_selection() {
    let sandbox = Sandbox::new("aider-all", false);
    let err =
        sentra_core::skills::install_all_skills(AgentTarget::Aider, false, &sandbox.workspace)
            .unwrap_err();
    assert_eq!(err.code(), "skill_selection_required");
    assert_eq!(err.exit_code(), 2);
    let json = err.to_json();
    assert_eq!(json["bundled_skills"], list_builtin_skills().len());
    assert!(json["bundled_bytes"].as_u64().unwrap() > 0);
    assert_eq!(fs::read_dir(&sandbox.workspace).unwrap().count(), 0);
}

#[test]
fn unknown_skill_ids_are_rejected_before_anything_is_written() {
    let sandbox = Sandbox::new("unknown", false);
    let err = install_selected_skills(
        &["security-review", "does-not-exist", "does-not-exist"],
        AgentTarget::Claude,
        false,
        &sandbox.workspace,
    )
    .unwrap_err();
    assert_eq!(err.code(), "skill_not_found");
    assert_eq!(err.exit_code(), 7);
    match &err {
        InstallError::SkillNotFound { ids } => assert_eq!(ids, &vec!["does-not-exist".to_string()]),
        other => panic!("unexpected error {other:?}"),
    }
    assert_eq!(fs::read_dir(&sandbox.workspace).unwrap().count(), 0);

    let empty = resolve_skill_ids(&[" ", ","]).unwrap_err();
    assert_eq!(empty.code(), "no_skills_selected");

    let deduped =
        resolve_skill_ids(&["security-review,SECURITY-REVIEW", " security-review "]).unwrap();
    assert_eq!(deduped.len(), 1);
}

#[test]
fn missing_workspace_and_home_are_reported() {
    let sandbox = Sandbox::new("missing", false);
    let skills = resolve_skill_ids(&["security-review"]).unwrap();
    let err = install_skills_in(
        &sandbox.host,
        &skills,
        AgentTarget::Claude,
        false,
        &sandbox.workspace.join("typo"),
    )
    .unwrap_err();
    assert_eq!(err.code(), "workspace_not_found");

    let no_home = HostDirs {
        home: None,
        appdata: None,
        xdg_config_home: None,
        windows: false,
    };
    let err = install_skills_in(
        &no_home,
        &skills,
        AgentTarget::Claude,
        true,
        &sandbox.workspace,
    )
    .unwrap_err();
    assert_eq!(err.code(), "home_dir_unavailable");
}

#[test]
fn reinstall_is_idempotent_and_backs_up_user_edits() {
    let sandbox = Sandbox::new("refresh", false);
    let first = sandbox
        .install(&["security-review"], AgentTarget::Claude, false)
        .unwrap();
    let skill_md = sandbox
        .workspace
        .join(".claude")
        .join("skills")
        .join("security-review")
        .join("SKILL.md");
    assert!(first.files.iter().all(|f| f.status == FileStatus::Created));

    let second = sandbox
        .install(&["security-review"], AgentTarget::Claude, false)
        .unwrap();
    assert!(
        second
            .files
            .iter()
            .all(|f| f.status == FileStatus::Unchanged)
    );
    assert_eq!(second.written_files().count(), 0);
    assert!(second.backups().is_empty());

    fs::write(&skill_md, "my local edits").unwrap();
    let third = sandbox
        .install(&["security-review"], AgentTarget::Claude, false)
        .unwrap();
    let updated = third
        .files
        .iter()
        .find(|f| f.path == skill_md)
        .expect("SKILL.md in report");
    assert_eq!(updated.status, FileStatus::Updated);
    let backup = updated.backup.clone().expect("backup");
    assert_eq!(fs::read_to_string(&backup).unwrap(), "my local edits");
    // The backup lives outside the directory the agent loads as the skill.
    let skills_dir = sandbox.workspace.join(".claude").join("skills");
    assert_eq!(
        backup,
        skills_dir
            .join(".sentra-backups")
            .join("security-review")
            .join("SKILL.md.bak")
    );
    assert!(
        !skills_dir
            .join("security-review")
            .join("SKILL.md.bak")
            .exists()
    );
    assert_eq!(
        fs::read_to_string(&skill_md).unwrap(),
        find_skill_by_id("security-review").unwrap().content
    );
}

#[test]
fn legacy_always_on_blocks_and_flat_rules_are_removed_and_reported() {
    let sandbox = Sandbox::new("legacy", false);
    let skill = find_skill_by_id("security-review").unwrap();
    let other = find_skill_by_id("stride-analysis-patterns").unwrap();
    let crlf_content = skill.content.replace('\n', "\r\n");

    // `.cursorrules` as written by the old installer, plus user text and a
    // block for a skill that is not part of this install.
    let cursorrules = sandbox.workspace.join(".cursorrules");
    let original = format!(
        "Always use tabs.\n\n<!-- sentra-skill: {} -->\n{}\n\n<!-- sentra-skill: {} -->\n{}\n",
        skill.id, crlf_content, other.id, other.content
    );
    fs::write(&cursorrules, &original).unwrap();

    // Old per-skill rule file identical to the playbook, and one the user edited.
    let rules = sandbox.workspace.join(".cursor").join("rules");
    fs::create_dir_all(&rules).unwrap();
    let stale_rule = rules.join(format!("{}.mdc", skill.id));
    fs::write(&stale_rule, skill.content).unwrap();

    let report = sandbox
        .install(&[skill.id], AgentTarget::Cursor, false)
        .unwrap();

    let remaining = fs::read_to_string(&cursorrules).unwrap();
    assert!(remaining.starts_with("Always use tabs.\n"));
    assert!(!remaining.contains(&format!("<!-- sentra-skill: {} -->", skill.id)));
    assert!(remaining.contains(&format!("<!-- sentra-skill: {} -->", other.id)));
    assert!(!stale_rule.exists());

    let block = report
        .legacy
        .iter()
        .find(|item| item.path == cursorrules)
        .unwrap();
    assert_eq!(block.action, LegacyAction::RemovedBlock);
    let backup = block.backup.clone().unwrap();
    assert_eq!(fs::read_to_string(&backup).unwrap(), original);
    assert!(
        report
            .legacy
            .iter()
            .any(|item| item.path == stale_rule && item.action == LegacyAction::RemovedFile)
    );
    assert!(report.backups().contains(&backup.as_path()));
    assert_full_tree(&sandbox.workspace.join(".cursor").join("skills"), skill);
}

#[test]
fn legacy_rule_file_holding_only_sentra_blocks_is_deleted_and_edits_are_kept() {
    let sandbox = Sandbox::new("legacy-only", false);
    let skill = find_skill_by_id("security-review").unwrap();

    let copilot = sandbox
        .workspace
        .join(".github")
        .join("copilot-instructions.md");
    fs::create_dir_all(copilot.parent().unwrap()).unwrap();
    fs::write(
        &copilot,
        format!("\n<!-- sentra-skill: {} -->\n{}\n", skill.id, skill.content),
    )
    .unwrap();

    let roorules = sandbox.workspace.join(".roorules");
    fs::write(
        &roorules,
        format!(
            "\n<!-- sentra-skill: {} -->\nmy edited playbook\n",
            skill.id
        ),
    )
    .unwrap();

    let report = sandbox
        .install(&[skill.id], AgentTarget::Copilot, false)
        .unwrap();
    assert!(
        !copilot.exists(),
        "file left with only Sentra content must be removed"
    );
    assert!(
        report
            .legacy
            .iter()
            .any(|i| i.action == LegacyAction::RemovedBlock)
    );

    let report = sandbox
        .install(&[skill.id], AgentTarget::Roo, false)
        .unwrap();
    assert!(roorules.exists());
    let kept = report.legacy.iter().find(|i| i.path == roorules).unwrap();
    assert_eq!(kept.action, LegacyAction::KeptModifiedBlock);
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("review and remove it manually"))
    );
}

#[test]
fn cline_rules_directory_is_left_alone() {
    let sandbox = Sandbox::new("cline-dir", false);
    let rules_dir = sandbox.workspace.join(".clinerules");
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(rules_dir.join("01-mine.md"), "mine").unwrap();

    sandbox
        .install(&["security-review"], AgentTarget::Cline, false)
        .unwrap();
    assert_eq!(
        fs::read_to_string(rules_dir.join("01-mine.md")).unwrap(),
        "mine"
    );
    assert_eq!(fs::read_dir(&rules_dir).unwrap().count(), 1);
}

#[test]
fn continue_and_amazon_q_get_on_demand_rules_instead_of_full_always_on_playbooks() {
    let sandbox = Sandbox::new("rules", false);
    let skill = find_skill_by_id("security-review").unwrap();

    let report = sandbox
        .install(&[skill.id], AgentTarget::ContinueDev, false)
        .unwrap();
    let rule = sandbox
        .workspace
        .join(".continue")
        .join("rules")
        .join(format!("sentra-{}.md", skill.id));
    let text = fs::read_to_string(&rule).unwrap();
    assert!(text.starts_with("---\nname: "));
    assert!(text.contains("\nalwaysApply: false\n"));
    assert!(text.contains(".agents/skills/security-review/"));
    assert!(
        !text.contains("\nname: security-review\n"),
        "skill frontmatter must be stripped"
    );
    assert!(report.installed_files.contains(&rule));
    assert_full_tree(&sandbox.workspace.join(".agents").join("skills"), skill);

    let report = sandbox
        .install(&[skill.id], AgentTarget::AmazonQ, false)
        .unwrap();
    let pointer = sandbox
        .workspace
        .join(".amazonq")
        .join("rules")
        .join(format!("sentra-{}.md", skill.id));
    let text = fs::read_to_string(&pointer).unwrap();
    assert!(text.len() < 2048, "pointer rule must stay small");
    assert!(text.contains("`.agents/skills/security-review/SKILL.md`"));
    assert!(report.notes.iter().any(|n| n.starts_with("amazonq:")));
    match report.targets[0].skills_dir.as_deref() {
        Some(dir) => assert!(dir.ends_with(Path::new(".agents").join("skills"))),
        None => panic!("Amazon Q must be installed"),
    }
}

#[test]
fn aider_read_entries_are_merged_losslessly() {
    let sandbox = Sandbox::new("aider", false);
    let config = sandbox.workspace.join(".aider.conf.yml");
    let original = "# team settings\nmodel: sonnet # pinned\nread: [CONVENTIONS.md]\n";
    fs::write(&config, original).unwrap();

    let report = sandbox
        .install(
            &["security-review", "golang-security"],
            AgentTarget::Aider,
            false,
        )
        .unwrap();
    assert_eq!(
        fs::read_to_string(&config).unwrap(),
        "# team settings\nmodel: sonnet # pinned\nread: [CONVENTIONS.md, .agents/skills/security-review/SKILL.md, .agents/skills/golang-security/SKILL.md]\n"
    );
    let change = report.files.iter().find(|f| f.path == config).unwrap();
    assert_eq!(change.status, FileStatus::Updated);
    assert_eq!(
        fs::read_to_string(change.backup.as_ref().unwrap()).unwrap(),
        original
    );
    assert!(!sandbox.workspace.join("CONVENTIONS.md").exists());

    let again = sandbox
        .install(&["security-review"], AgentTarget::Aider, false)
        .unwrap();
    assert!(
        again
            .files
            .iter()
            .all(|f| f.status == FileStatus::Unchanged)
    );
}

#[test]
fn aider_config_that_cannot_be_edited_safely_requires_a_manual_step() {
    let sandbox = Sandbox::new("aider-manual", false);
    let config = sandbox.workspace.join(".aider.conf.yml");
    let original = "read: &shared\n  - CONVENTIONS.md\n";
    fs::write(&config, original).unwrap();

    let err = sandbox
        .install(&["security-review"], AgentTarget::Aider, false)
        .unwrap_err();
    assert_eq!(err.code(), "manual_config_edit_required");
    assert_eq!(err.exit_code(), 6);
    assert_eq!(
        fs::read_to_string(&config).unwrap(),
        original,
        "config must not change"
    );
    match &err {
        InstallError::ManualStepRequired {
            report,
            config_path,
            snippet,
            ..
        } => {
            assert_eq!(config_path, &config);
            assert_eq!(
                snippet,
                "read:\n  - .agents/skills/security-review/SKILL.md\n"
            );
            assert_full_tree(
                &sandbox.workspace.join(".agents").join("skills"),
                find_skill_by_id("security-review").unwrap(),
            );
            assert!(!report.installed_files.is_empty());
        }
        other => panic!("unexpected error {other:?}"),
    }
    let json = err.to_json();
    assert_eq!(json["error"], "manual_config_edit_required");
    assert!(
        json["snippet"]
            .as_str()
            .unwrap()
            .contains("security-review")
    );
}

#[test]
fn aider_global_config_uses_absolute_entries() {
    let sandbox = Sandbox::new("aider-global", true);
    let report = sandbox
        .install(&["security-review"], AgentTarget::Aider, true)
        .unwrap();
    let config = sandbox.home().join(".aider.conf.yml");
    let text = fs::read_to_string(&config).unwrap();
    let expected = sandbox
        .home()
        .join(".agents")
        .join("skills")
        .join("security-review")
        .join("SKILL.md")
        .to_string_lossy()
        .replace('\\', "/");
    assert!(text.contains(&expected), "{text}");
    assert!(report.installed_files.contains(&config));
    match AgentTarget::Aider
        .skill_location_in(&sandbox.host, true, &sandbox.workspace)
        .unwrap()
        .delivery
    {
        SkillDelivery::AiderReadList { config: path } => assert_eq!(path, config),
        other => panic!("unexpected delivery {other:?}"),
    }
}

#[test]
fn install_all_reports_every_file_once_and_serializes_to_valid_json() {
    let sandbox = Sandbox::new("all", false);
    let skill = skill_with_supporting_files();
    let report = sandbox
        .install(&[skill.id], AgentTarget::All, false)
        .unwrap();

    assert_eq!(report.targets.len(), AgentTarget::CONCRETE.len());
    let skipped: Vec<_> = report
        .targets
        .iter()
        .filter(|t| t.skipped.is_some())
        .map(|t| t.target)
        .collect();
    assert_eq!(skipped, vec![AgentTarget::Aider, AgentTarget::Cody]);

    let mut unique = report.installed_files.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        report.installed_files.len(),
        "duplicate paths in report"
    );
    for path in &report.installed_files {
        assert!(path.is_file(), "{} reported but missing", path.display());
    }
    assert!(!sandbox.workspace.join(".aider.conf.yml").exists());

    let text = serde_json::to_string(&report.to_json()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["command"], "install");
    assert_eq!(parsed["target"], "all");
    assert_eq!(parsed["count"], 1);
    assert_eq!(parsed["file_count"], report.installed_files.len());
    assert_eq!(
        parsed["destination"].as_str().unwrap(),
        report.destination_dir.display().to_string()
    );
    assert_eq!(parsed["targets"][7]["status"], "skipped");
}
