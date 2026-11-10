//! Cross-Platform Skill Installer for Agent Environments (REQ-F17, EXTENSIONS.md).
//!
//! Installs built-in AppSec skills into Claude Code, Antigravity, Cursor, Windsurf,
//! Cline, Roo Code, Continue.dev, Aider, Amazon Q, Cody, Devin, Codex, Copilot,
//! Zed, OpenCode, Trae, Kimi, Augment, OpenHands, Goose, Tabnine, Junie, Warp,
//! Droid, Kiro, Qwen, Hermes, or Replit environments in local or global scope.

use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::skills::catalog::{SkillDefinition, find_skill_by_id, list_builtin_skills};

/// Target AI agent environment or editor integration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AgentTarget {
    /// Claude Code (`.claude/skills/`).
    Claude,
    /// Google Antigravity & Gemini agents (`.agents/skills/` or `~/.gemini/config/skills/`).
    Antigravity,
    /// Cursor IDE (`.cursor/rules/` and `.cursorrules`).
    Cursor,
    /// Windsurf / Cascade (`.windsurf/rules/` and `.windsurfrules`).
    Windsurf,
    /// Cline (`.cline/skills/` and `.clinerules`).
    Cline,
    /// Roo Code (`.roo/rules/` and `.roorules`).
    Roo,
    /// Continue.dev (`.continue/rules/`).
    ContinueDev,
    /// Aider (`CONVENTIONS.md` and `.aider/conventions/`).
    Aider,
    /// Amazon Q Developer (`.amazonq/rules/`).
    AmazonQ,
    /// Sourcegraph Cody (`.cody/rules/`).
    Cody,
    /// Cognition AI Devin (`.devin/skills/` or `.devin/rules/`).
    Devin,
    /// OpenAI Codex CLI (`.codex/skills/`).
    Codex,
    /// GitHub Copilot (`.github/copilot-instructions.md`, `.github/instructions/`, `~/.copilot/skills/`).
    Copilot,
    /// Zed editor (`.zed/rules/`).
    Zed,
    /// OpenCode (`.opencode/skills/`).
    OpenCode,
    /// Trae IDE (`.trae/skills/`).
    Trae,
    /// Kimi CLI (`.agents/skills/` or `~/.config/agents/skills/`).
    Kimi,
    /// Augment Code (`.augment/rules/`).
    Augment,
    /// OpenHands / OpenDevin (`.openhands/skills/`).
    OpenHands,
    /// Goose by Block (`.goose/skills/` or `~/.config/goose/skills/`).
    Goose,
    /// Tabnine CLI & Agent (`.tabnine/agent/skills/`).
    Tabnine,
    /// JetBrains Junie (`.junie/skills/`).
    Junie,
    /// Warp AI Terminal (`.warp/rules/`).
    Warp,
    /// Factory AI Droid (`.factory/skills/`).
    Droid,
    /// Kiro CLI (`.kiro/skills/`).
    Kiro,
    /// Qwen Code (`.qwen/skills/`).
    Qwen,
    /// Hermes Agent (`.hermes/skills/`).
    Hermes,
    /// Replit Agent / Amp (`.agents/skills/`).
    Replit,
    /// All supported agent ecosystems simultaneously.
    All,
}

impl AgentTarget {
    /// Parses a target string identifier into an `AgentTarget`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "claude" | "claudecode" | "claude-code" | ".claude" => Some(Self::Claude),
            "antigravity" | "agy" | "gemini" => Some(Self::Antigravity),
            "cursor" | ".cursor" => Some(Self::Cursor),
            "windsurf" | "codeium" | ".windsurf" => Some(Self::Windsurf),
            "cline" | ".cline" => Some(Self::Cline),
            "roo" | "roo-code" | "roocode" | ".roo" => Some(Self::Roo),
            "continue" | "continue-dev" | "continuedev" | ".continue" => Some(Self::ContinueDev),
            "aider" | ".aider" => Some(Self::Aider),
            "amazonq" | "amazon-q" | "q" | "aws-q" | ".amazonq" => Some(Self::AmazonQ),
            "cody" | "sourcegraph" | "sourcegraph-cody" | ".cody" => Some(Self::Cody),
            "devin" | "cognition" | ".devin" => Some(Self::Devin),
            "codex" | "openai-codex" | ".codex" => Some(Self::Codex),
            "copilot" | "github-copilot" | ".copilot" => Some(Self::Copilot),
            "zed" | ".zed" => Some(Self::Zed),
            "opencode" | "open-code" | ".opencode" => Some(Self::OpenCode),
            "trae" | ".trae" => Some(Self::Trae),
            "kimi" | "kimi-code" => Some(Self::Kimi),
            "augment" | "augment-code" | ".augment" => Some(Self::Augment),
            "openhands" | "opendevin" | ".openhands" => Some(Self::OpenHands),
            "goose" | ".goose" => Some(Self::Goose),
            "tabnine" | "tabnine-cli" | ".tabnine" => Some(Self::Tabnine),
            "junie" | ".junie" => Some(Self::Junie),
            "warp" | ".warp" => Some(Self::Warp),
            "droid" | "factory" | "factory-droid" | ".factory" => Some(Self::Droid),
            "kiro" | "kiro-cli" | ".kiro" => Some(Self::Kiro),
            "qwen" | "qwen-code" | ".qwen" => Some(Self::Qwen),
            "hermes" | "hermes-agent" | ".hermes" => Some(Self::Hermes),
            "replit" | "amp" | ".replit" => Some(Self::Replit),
            "all" | "*" => Some(Self::All),
            _ => None,
        }
    }

    /// Returns the canonical display name.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Antigravity => "antigravity",
            Self::Cursor => "cursor",
            Self::Windsurf => "windsurf",
            Self::Cline => "cline",
            Self::Roo => "roo",
            Self::ContinueDev => "continue",
            Self::Aider => "aider",
            Self::AmazonQ => "amazonq",
            Self::Cody => "cody",
            Self::Devin => "devin",
            Self::Codex => "codex",
            Self::Copilot => "copilot",
            Self::Zed => "zed",
            Self::OpenCode => "opencode",
            Self::Trae => "trae",
            Self::Kimi => "kimi",
            Self::Augment => "augment",
            Self::OpenHands => "openhands",
            Self::Goose => "goose",
            Self::Tabnine => "tabnine",
            Self::Junie => "junie",
            Self::Warp => "warp",
            Self::Droid => "droid",
            Self::Kiro => "kiro",
            Self::Qwen => "qwen",
            Self::Hermes => "hermes",
            Self::Replit => "replit",
            Self::All => "all",
        }
    }

    /// Resolves the destination directory for the specified target and scope.
    pub fn destination_dir(&self, global: bool, workspace: &Path) -> PathBuf {
        let base = if global {
            get_user_home_dir()
        } else {
            workspace.to_path_buf()
        };

        match self {
            Self::Claude => base.join(".claude").join("skills"),
            Self::Antigravity => {
                if global {
                    base.join(".gemini").join("config").join("skills")
                } else {
                    base.join(".agents").join("skills")
                }
            }
            Self::Cursor => {
                if global {
                    base.join(".cursor").join("skills")
                } else {
                    base.join(".cursor").join("rules")
                }
            }
            Self::Windsurf => {
                if global {
                    base.join(".codeium").join("windsurf").join("skills")
                } else {
                    base.join(".windsurf").join("rules")
                }
            }
            Self::Cline => base.join(".cline").join("skills"),
            Self::Roo => {
                if global {
                    base.join(".roo").join("skills")
                } else {
                    base.join(".roo").join("rules")
                }
            }
            Self::ContinueDev => base.join(".continue").join("rules"),
            Self::Aider => base.join(".aider").join("conventions"),
            Self::AmazonQ => base.join(".amazonq").join("rules"),
            Self::Cody => base.join(".cody").join("rules"),
            Self::Devin => {
                if global {
                    base.join(".config").join("devin").join("skills")
                } else {
                    base.join(".devin").join("skills")
                }
            }
            Self::Codex => base.join(".codex").join("skills"),
            Self::Copilot => {
                if global {
                    base.join(".copilot").join("skills")
                } else {
                    base.join(".github").join("instructions")
                }
            }
            Self::Zed => {
                if global {
                    base.join(".config").join("zed").join("rules")
                } else {
                    base.join(".zed").join("rules")
                }
            }
            Self::OpenCode => {
                if global {
                    base.join(".config").join("opencode").join("skills")
                } else {
                    base.join(".opencode").join("skills")
                }
            }
            Self::Trae => base.join(".trae").join("skills"),
            Self::Kimi => {
                if global {
                    base.join(".config").join("agents").join("skills")
                } else {
                    base.join(".agents").join("skills")
                }
            }
            Self::Augment => {
                if global {
                    base.join(".augment").join("skills")
                } else {
                    base.join(".augment").join("rules")
                }
            }
            Self::OpenHands => base.join(".openhands").join("skills"),
            Self::Goose => {
                if global {
                    base.join(".config").join("goose").join("skills")
                } else {
                    base.join(".goose").join("skills")
                }
            }
            Self::Tabnine => base.join(".tabnine").join("agent").join("skills"),
            Self::Junie => base.join(".junie").join("skills"),
            Self::Warp => base.join(".warp").join("rules"),
            Self::Droid => base.join(".factory").join("skills"),
            Self::Kiro => base.join(".kiro").join("skills"),
            Self::Qwen => base.join(".qwen").join("skills"),
            Self::Hermes => base.join(".hermes").join("skills"),
            Self::Replit => {
                if global {
                    base.join(".config").join("agents").join("skills")
                } else {
                    base.join(".agents").join("skills")
                }
            }
            Self::All => base.join(".agents").join("skills"),
        }
    }
}

/// Result of installing skills into a target ecosystem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallReport {
    /// Target ecosystem installed to.
    pub target: AgentTarget,
    /// Whether installed to global user scope.
    pub is_global: bool,
    /// Base destination directory.
    pub destination_dir: PathBuf,
    /// Files successfully created or updated.
    pub installed_files: Vec<PathBuf>,
}

/// Gets the current user's home directory across Windows and Unix platforms.
fn get_user_home_dir() -> PathBuf {
    if let Ok(profile) = std::env::var("USERPROFILE")
        && !profile.trim().is_empty()
    {
        return PathBuf::from(profile);
    }
    if let Ok(home) = std::env::var("HOME")
        && !home.trim().is_empty()
    {
        return PathBuf::from(home);
    }
    PathBuf::from(".")
}

/// Installs a single skill definition into the specified agent target.
pub fn install_single_skill(
    skill: &SkillDefinition,
    target: AgentTarget,
    global: bool,
    workspace: &Path,
) -> std::io::Result<PathBuf> {
    if target == AgentTarget::All {
        let targets = [
            AgentTarget::Claude,
            AgentTarget::Antigravity,
            AgentTarget::Cursor,
            AgentTarget::Windsurf,
            AgentTarget::Cline,
            AgentTarget::Roo,
            AgentTarget::ContinueDev,
            AgentTarget::Aider,
            AgentTarget::AmazonQ,
            AgentTarget::Cody,
            AgentTarget::Devin,
            AgentTarget::Codex,
            AgentTarget::Copilot,
            AgentTarget::Zed,
            AgentTarget::OpenCode,
            AgentTarget::Trae,
            AgentTarget::Kimi,
            AgentTarget::Augment,
            AgentTarget::OpenHands,
            AgentTarget::Goose,
            AgentTarget::Tabnine,
            AgentTarget::Junie,
            AgentTarget::Warp,
            AgentTarget::Droid,
            AgentTarget::Kiro,
            AgentTarget::Qwen,
            AgentTarget::Hermes,
            AgentTarget::Replit,
        ];
        let mut last_path = PathBuf::new();
        for t in targets {
            last_path = install_single_skill(skill, t, global, workspace)?;
        }
        return Ok(last_path);
    }

    let base_dir = target.destination_dir(global, workspace);

    let (target_file_path, content_to_write) = match target {
        AgentTarget::Cursor => {
            // Cursor prefers `.cursor/rules/<skill_id>.mdc`
            let file_path = base_dir.join(format!("{}.mdc", skill.id));
            if !global {
                let cursorrules = workspace.join(".cursorrules");
                let mut existing = fs::read_to_string(&cursorrules).unwrap_or_default();
                let marker = format!("<!-- sentra-skill: {} -->", skill.id);
                if !existing.contains(&marker) {
                    if !existing.is_empty() && !existing.ends_with('\n') {
                        existing.push('\n');
                    }
                    existing.push_str(&format!("\n{marker}\n{}\n", skill.content));
                    let _ = fs::write(&cursorrules, existing);
                }
            }
            (file_path, skill.content.to_string())
        }
        AgentTarget::Windsurf => {
            let file_path = base_dir.join(format!("{}.md", skill.id));
            if !global {
                let windsurfrules = workspace.join(".windsurfrules");
                let mut existing = fs::read_to_string(&windsurfrules).unwrap_or_default();
                let marker = format!("<!-- sentra-skill: {} -->", skill.id);
                if !existing.contains(&marker) {
                    if !existing.is_empty() && !existing.ends_with('\n') {
                        existing.push('\n');
                    }
                    existing.push_str(&format!("\n{marker}\n{}\n", skill.content));
                    let _ = fs::write(&windsurfrules, existing);
                }
            }
            (file_path, skill.content.to_string())
        }
        AgentTarget::Cline => {
            let skill_dir = base_dir.join(skill.id);
            let file_path = skill_dir.join("SKILL.md");
            if !global {
                let clinerules = workspace.join(".clinerules");
                let mut existing = fs::read_to_string(&clinerules).unwrap_or_default();
                let marker = format!("<!-- sentra-skill: {} -->", skill.id);
                if !existing.contains(&marker) {
                    if !existing.is_empty() && !existing.ends_with('\n') {
                        existing.push('\n');
                    }
                    existing.push_str(&format!("\n{marker}\n{}\n", skill.content));
                    let _ = fs::write(&clinerules, existing);
                }
            }
            (file_path, skill.content.to_string())
        }
        AgentTarget::Roo => {
            let file_path = base_dir.join(format!("{}.md", skill.id));
            if !global {
                let roorules = workspace.join(".roorules");
                let mut existing = fs::read_to_string(&roorules).unwrap_or_default();
                let marker = format!("<!-- sentra-skill: {} -->", skill.id);
                if !existing.contains(&marker) {
                    if !existing.is_empty() && !existing.ends_with('\n') {
                        existing.push('\n');
                    }
                    existing.push_str(&format!("\n{marker}\n{}\n", skill.content));
                    let _ = fs::write(&roorules, existing);
                }
            }
            (file_path, skill.content.to_string())
        }
        AgentTarget::Aider => {
            let file_path = base_dir.join(format!("{}.md", skill.id));
            if !global {
                let conventions = workspace.join("CONVENTIONS.md");
                let mut existing = fs::read_to_string(&conventions).unwrap_or_default();
                let marker = format!("<!-- sentra-skill: {} -->", skill.id);
                if !existing.contains(&marker) {
                    if !existing.is_empty() && !existing.ends_with('\n') {
                        existing.push('\n');
                    }
                    existing.push_str(&format!("\n{marker}\n{}\n", skill.content));
                    let _ = fs::write(&conventions, existing);
                }
            }
            (file_path, skill.content.to_string())
        }
        AgentTarget::Copilot => {
            if global {
                let skill_dir = base_dir.join(skill.id);
                let file_path = skill_dir.join("SKILL.md");
                (file_path, skill.content.to_string())
            } else {
                // 1. Multi-file instruction: .github/instructions/<id>.instructions.md
                let file_path = base_dir.join(format!("{}.instructions.md", skill.id));
                // 2. Repository-wide primary instructions: .github/copilot-instructions.md
                let copilot_root = workspace.join(".github").join("copilot-instructions.md");
                if let Some(parent) = copilot_root.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let mut existing = fs::read_to_string(&copilot_root).unwrap_or_default();
                let marker = format!("<!-- sentra-skill: {} -->", skill.id);
                if !existing.contains(&marker) {
                    if !existing.is_empty() && !existing.ends_with('\n') {
                        existing.push('\n');
                    }
                    existing.push_str(&format!("\n{marker}\n{}\n", skill.content));
                    let _ = fs::write(&copilot_root, existing);
                }
                (file_path, skill.content.to_string())
            }
        }
        AgentTarget::Zed
        | AgentTarget::ContinueDev
        | AgentTarget::AmazonQ
        | AgentTarget::Cody
        | AgentTarget::Warp
        | AgentTarget::Augment => {
            // Rule-based markdown targets: `<base_dir>/<skill_id>.md`
            let file_path = base_dir.join(format!("{}.md", skill.id));
            (file_path, skill.content.to_string())
        }
        _ => {
            // Standard agent skills (Claude, Antigravity, Devin, Codex, OpenCode, Trae, Kimi, OpenHands, Goose, Tabnine, Junie, Droid, Kiro, Qwen, Hermes, Replit)
            let skill_dir = base_dir.join(skill.id);
            let file_path = skill_dir.join("SKILL.md");
            (file_path, skill.content.to_string())
        }
    };

    if let Some(parent) = target_file_path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(&target_file_path, content_to_write)?;
    Ok(target_file_path)
}

/// Installs all built-in skills into the specified agent target.
pub fn install_all_skills(
    target: AgentTarget,
    global: bool,
    workspace: &Path,
) -> std::io::Result<InstallReport> {
    let mut installed_files = Vec::new();
    let base_dir = target.destination_dir(global, workspace);

    for skill in list_builtin_skills() {
        let path = install_single_skill(skill, target, global, workspace)?;
        installed_files.push(path);
    }

    Ok(InstallReport {
        target,
        is_global: global,
        destination_dir: base_dir,
        installed_files,
    })
}

/// Installs selected skills by IDs into the specified agent target.
pub fn install_selected_skills(
    skill_ids: &[&str],
    target: AgentTarget,
    global: bool,
    workspace: &Path,
) -> std::io::Result<InstallReport> {
    let mut installed_files = Vec::new();
    let base_dir = target.destination_dir(global, workspace);

    for &id in skill_ids {
        if let Some(skill) = find_skill_by_id(id) {
            let path = install_single_skill(skill, target, global, workspace)?;
            installed_files.push(path);
        }
    }

    Ok(InstallReport {
        target,
        is_global: global,
        destination_dir: base_dir,
        installed_files,
    })
}
