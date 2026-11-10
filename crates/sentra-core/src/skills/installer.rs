//! Cross-Platform Skill Installer for Agent Environments (REQ-F17, EXTENSIONS.md).
//!
//! Installs built-in AppSec skills into Claude Code, Antigravity, Cursor, Windsurf,
//! Cline, Codex, Copilot, Zed, OpenCode, Trae, or Kimi environments
//! in either local workspace or global user scope.

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
    /// Google Antigravity & Gemini agents (`.agents/skills/` or `~/.gemini/skills/`).
    Antigravity,
    /// Cursor IDE (`.cursor/rules/`).
    Cursor,
    /// Windsurf (`.windsurf/rules/`).
    Windsurf,
    /// Cline (`.cline/skills/`).
    Cline,
    /// OpenAI Codex CLI (`.codex/skills/`).
    Codex,
    /// GitHub Copilot (`.github/instructions/`).
    Copilot,
    /// Zed editor (`.zed/rules/`).
    Zed,
    /// OpenCode (`.opencode/skills/`).
    OpenCode,
    /// Trae IDE (`.trae/skills/`).
    Trae,
    /// Kimi CLI (`.agents/skills/` or `~/.config/agents/skills/`).
    Kimi,
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
            "codex" | "openai-codex" | ".codex" => Some(Self::Codex),
            "copilot" | "github-copilot" | ".copilot" => Some(Self::Copilot),
            "zed" | ".zed" => Some(Self::Zed),
            "opencode" | "open-code" | ".opencode" => Some(Self::OpenCode),
            "trae" | ".trae" => Some(Self::Trae),
            "kimi" | "kimi-code" => Some(Self::Kimi),
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
            Self::Codex => "codex",
            Self::Copilot => "copilot",
            Self::Zed => "zed",
            Self::OpenCode => "opencode",
            Self::Trae => "trae",
            Self::Kimi => "kimi",
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
                    base.join(".gemini").join("skills")
                } else {
                    base.join(".agents").join("skills")
                }
            }
            Self::Cursor => base.join(".cursor").join("rules"),
            Self::Windsurf => base.join(".windsurf").join("rules"),
            Self::Cline => base.join(".cline").join("skills"),
            Self::Codex => base.join(".codex").join("skills"),
            Self::Copilot => {
                if global {
                    base.join(".config")
                        .join("github-copilot")
                        .join("instructions")
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
            AgentTarget::Codex,
            AgentTarget::Copilot,
            AgentTarget::Zed,
            AgentTarget::OpenCode,
            AgentTarget::Trae,
            AgentTarget::Kimi,
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
            (file_path, skill.content.to_string())
        }
        AgentTarget::Zed | AgentTarget::Windsurf => {
            // Zed and Windsurf prefer `.zed/rules/<skill_id>.md` or `.windsurf/rules/<skill_id>.md`
            let file_path = base_dir.join(format!("{}.md", skill.id));
            (file_path, skill.content.to_string())
        }
        AgentTarget::Copilot => {
            // GitHub Copilot instructions: `.github/instructions/<skill_id>.instructions.md`
            let file_path = base_dir.join(format!("{}.instructions.md", skill.id));
            (file_path, skill.content.to_string())
        }
        _ => {
            // Standard agent skills (Claude, Antigravity, Cline, Codex, OpenCode, Trae, Kimi) use `<base_dir>/<skill_id>/SKILL.md`
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
