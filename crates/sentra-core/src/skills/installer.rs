//! Cross-platform skill installer for agent environments (REQ-F17, EXTENSIONS.md).
//!
//! Installs the bundled AppSec skills as on-demand Agent Skills
//! (`<skills dir>/<id>/SKILL.md` plus every supporting file shipped with the
//! skill) into the location each agent documents for workspace or user
//! (global) scope.
//!
//! Design rules:
//!
//! * Skills are never appended to always-on rule files (`.cursorrules`,
//!   `.windsurfrules`, `.clinerules`, `.roorules`, `CONVENTIONS.md`,
//!   `.github/copilot-instructions.md`). Blocks that earlier Sentra versions
//!   appended there are removed on reinstall only when they still match the
//!   bundled playbook exactly; every removal is reported.
//! * Agents without native skill discovery get the smallest documented hook:
//!   Continue gets an agent-requested rule (`alwaysApply: false`), Amazon Q a
//!   one-paragraph pointer rule, and Aider a `read:` entry merged losslessly
//!   into `.aider.conf.yml` (or a manual snippet when that is not possible).
//! * Targets or scopes without a documented file location fail with an
//!   explicit error instead of writing files nothing reads.
//! * Writes are change-detecting, atomic, and back up differing content first;
//!   backups of skill files go to `<skills dir>/.sentra-backups/<id>/`, outside
//!   the directory the agent loads as the skill.
//! * Aider loads every `read:` file into every chat, so it requires an explicit
//!   skill selection ([`install_all_skills`] refuses it).
//!
//! Per-target locations were checked against vendor documentation on
//! 2026-11-11; see the target documentation on [`AgentTarget`].

use std::{
    collections::HashSet,
    fmt, io,
    path::{Path, PathBuf},
};

use crate::skills::{
    catalog::{SkillDefinition, find_skill_by_id, list_builtin_skills, skill_files},
    install_aider::{self, ManualEdit},
    install_fs,
    install_text::{display_path, normalize_newlines, strip_frontmatter},
};

pub use crate::skills::install_fs::{FileStatus, LegacyAction, LegacyCleanup};

/// Directory below a skills directory that receives backups of user-edited
/// skill files (`<skills_dir>/.sentra-backups/<id>/<file>.bak`).
pub const SKILL_BACKUP_DIR: &str = ".sentra-backups";

/// Target AI agent environment or editor integration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AgentTarget {
    /// Claude Code: `.claude/skills/` and `~/.claude/skills/`.
    Claude,
    /// Google Antigravity: `.agents/skills/` and `~/.gemini/config/skills/`.
    Antigravity,
    /// Cursor: `.cursor/skills/` and `~/.cursor/skills/`.
    Cursor,
    /// Windsurf / Devin Desktop: `.agents/skills/` and `~/.agents/skills/`.
    Windsurf,
    /// Cline: `.cline/skills/` and `~/.cline/skills/`.
    Cline,
    /// Roo Code: `.roo/skills/` and `~/.roo/skills/`.
    Roo,
    /// Continue: agent-requested rules in `.continue/rules/` (workspace only).
    ContinueDev,
    /// Aider: `read:` entries in `.aider.conf.yml` pointing at `.agents/skills/`.
    Aider,
    /// Amazon Q Developer: pointer rules in `.amazonq/rules/` (workspace only).
    AmazonQ,
    /// Sourcegraph Cody: no documented file-based skills or rules location (unsupported).
    Cody,
    /// Devin CLI: `.devin/skills/`, `~/.config/devin/skills/` (`%APPDATA%\devin\skills` on Windows).
    Devin,
    /// OpenAI Codex CLI: `.agents/skills/` and `~/.agents/skills/`.
    Codex,
    /// GitHub Copilot: `.github/skills/` and `~/.copilot/skills/`.
    Copilot,
    /// Zed: `.agents/skills/` and `~/.agents/skills/`.
    Zed,
    /// OpenCode: `.opencode/skills/` and `$XDG_CONFIG_HOME/opencode/skills/` (default `~/.config`).
    OpenCode,
    /// Trae: `.trae/skills/` and `~/.trae/skills/`.
    Trae,
    /// Kimi CLI and Kimi Code: `.agents/skills/` and `~/.agents/skills/`.
    Kimi,
    /// Augment Code / Auggie: `.augment/skills/` and `~/.augment/skills/`.
    Augment,
    /// OpenHands: `.agents/skills/` and `~/.agents/skills/`.
    OpenHands,
    /// Goose: `.agents/skills/` and `~/.agents/skills/`.
    Goose,
    /// Tabnine CLI: `.tabnine/agent/skills/` and `~/.tabnine/agent/skills/`.
    Tabnine,
    /// JetBrains Junie: `.junie/skills/` and `~/.junie/skills/`.
    Junie,
    /// Warp: `.agents/skills/` and `~/.agents/skills/`.
    Warp,
    /// Factory Droid: `.factory/skills/` and `~/.factory/skills/`.
    Droid,
    /// Kiro: `.kiro/skills/` and `~/.kiro/skills/`.
    Kiro,
    /// Qwen Code: `.qwen/skills/` and `~/.qwen/skills/`.
    Qwen,
    /// Hermes Agent: `.hermes/skills/` and `~/.hermes/skills/`.
    Hermes,
    /// Replit Agent: `.agents/skills/` (workspace only).
    Replit,
    /// Sourcegraph Amp: `.agents/skills/` and `~/.config/agents/skills/`
    /// (<https://ampcode.com/docs/customize/skills>).
    Amp,
    /// Every concrete target at once.
    All,
}

impl AgentTarget {
    /// Every concrete (non-`All`) target, in installation order.
    pub const CONCRETE: [Self; 29] = [
        Self::Claude,
        Self::Antigravity,
        Self::Cursor,
        Self::Windsurf,
        Self::Cline,
        Self::Roo,
        Self::ContinueDev,
        Self::Aider,
        Self::AmazonQ,
        Self::Cody,
        Self::Devin,
        Self::Codex,
        Self::Copilot,
        Self::Zed,
        Self::OpenCode,
        Self::Trae,
        Self::Kimi,
        Self::Augment,
        Self::OpenHands,
        Self::Goose,
        Self::Tabnine,
        Self::Junie,
        Self::Warp,
        Self::Droid,
        Self::Kiro,
        Self::Qwen,
        Self::Hermes,
        Self::Replit,
        Self::Amp,
    ];

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
            "replit" | ".replit" => Some(Self::Replit),
            "amp" | "ampcode" | "amp-code" | ".amp" => Some(Self::Amp),
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
            Self::Amp => "amp",
            Self::All => "all",
        }
    }

    /// Resolves where this target loads skills from, using the process environment.
    pub fn skill_location(
        &self,
        global: bool,
        workspace: &Path,
    ) -> Result<SkillLocation, InstallError> {
        self.skill_location_in(&HostDirs::from_env(), global, workspace)
    }

    /// Resolves where this target loads skills from, using explicit host directories.
    pub fn skill_location_in(
        &self,
        host: &HostDirs,
        global: bool,
        workspace: &Path,
    ) -> Result<SkillLocation, InstallError> {
        let root = scope_root(host, global, workspace)?;
        self.location_in(host, &root, global)
    }

    fn location_in(
        &self,
        host: &HostDirs,
        root: &Path,
        global: bool,
    ) -> Result<SkillLocation, InstallError> {
        let dir = |parts: &[&str]| join_all(root, parts);
        let agents = || dir(&[".agents", "skills"]);
        let native = |skills_dir: PathBuf| SkillLocation {
            target: *self,
            global,
            root: root.to_path_buf(),
            skills_dir,
            delivery: SkillDelivery::SkillDirectory,
        };

        let location = match self {
            Self::Claude => native(dir(&[".claude", "skills"])),
            Self::Antigravity if global => native(dir(&[".gemini", "config", "skills"])),
            Self::Cursor => native(dir(&[".cursor", "skills"])),
            Self::Cline => native(dir(&[".cline", "skills"])),
            Self::Roo => native(dir(&[".roo", "skills"])),
            Self::ContinueDev if global => {
                return Err(self.unsupported_scope(
                    global,
                    "Continue documents rules only in the workspace `.continue/rules` folder",
                ));
            }
            Self::ContinueDev => SkillLocation {
                target: *self,
                global,
                root: root.to_path_buf(),
                skills_dir: agents(),
                delivery: SkillDelivery::RequestableRule {
                    rules_dir: dir(&[".continue", "rules"]),
                },
            },
            Self::Aider => SkillLocation {
                target: *self,
                global,
                root: root.to_path_buf(),
                skills_dir: agents(),
                delivery: SkillDelivery::AiderReadList {
                    config: root.join(".aider.conf.yml"),
                },
            },
            Self::AmazonQ if global => {
                return Err(self.unsupported_scope(
                    global,
                    "Amazon Q Developer documents project rules only (`.amazonq/rules` in the workspace)",
                ));
            }
            Self::AmazonQ => SkillLocation {
                target: *self,
                global,
                root: root.to_path_buf(),
                skills_dir: agents(),
                delivery: SkillDelivery::PointerRule {
                    rules_dir: dir(&[".amazonq", "rules"]),
                },
            },
            Self::Cody => {
                return Err(InstallError::UnsupportedTarget {
                    target: *self,
                    reason: "Sourcegraph documents no file-based skills or rules location for Cody",
                });
            }
            Self::Devin if global => native(host.devin_config_dir()?.join("skills")),
            Self::Devin => native(dir(&[".devin", "skills"])),
            Self::Copilot if global => native(dir(&[".copilot", "skills"])),
            Self::Copilot => native(dir(&[".github", "skills"])),
            Self::OpenCode if global => {
                native(host.xdg_config_dir()?.join("opencode").join("skills"))
            }
            Self::OpenCode => native(dir(&[".opencode", "skills"])),
            Self::Trae => native(dir(&[".trae", "skills"])),
            Self::Augment => native(dir(&[".augment", "skills"])),
            Self::Tabnine => native(dir(&[".tabnine", "agent", "skills"])),
            Self::Junie => native(dir(&[".junie", "skills"])),
            Self::Droid => native(dir(&[".factory", "skills"])),
            Self::Kiro => native(dir(&[".kiro", "skills"])),
            Self::Qwen => native(dir(&[".qwen", "skills"])),
            Self::Hermes => native(dir(&[".hermes", "skills"])),
            Self::Replit if global => {
                return Err(self.unsupported_scope(
                    global,
                    "Replit manages workspace-wide skills in Workspace Settings; only project `.agents/skills` is file-based",
                ));
            }
            // `amp skill add --global` installs under `~/.config/agents/skills/`; the
            // Amp docs name that literal path (no `$XDG_CONFIG_HOME` lookup).
            Self::Amp if global => native(dir(&[".config", "agents", "skills"])),
            Self::Antigravity
            | Self::Windsurf
            | Self::Codex
            | Self::Zed
            | Self::Kimi
            | Self::OpenHands
            | Self::Goose
            | Self::Warp
            | Self::Replit
            | Self::Amp => native(agents()),
            Self::All => {
                return Err(InstallError::UnsupportedTarget {
                    target: *self,
                    reason: "`all` expands to every concrete target and has no single location",
                });
            }
        };
        Ok(location)
    }

    fn unsupported_scope(&self, global: bool, reason: &'static str) -> InstallError {
        InstallError::UnsupportedScope {
            target: *self,
            global,
            reason,
        }
    }

    /// Always-on rule files to which earlier Sentra versions appended marker blocks.
    fn legacy_block_files(&self, root: &Path, global: bool) -> Vec<PathBuf> {
        if global {
            return Vec::new();
        }
        match self {
            Self::Cursor => vec![root.join(".cursorrules")],
            Self::Windsurf => vec![root.join(".windsurfrules")],
            Self::Cline => vec![root.join(".clinerules")],
            Self::Roo => vec![root.join(".roorules")],
            Self::Aider => vec![root.join("CONVENTIONS.md")],
            Self::Copilot => vec![join_all(root, &[".github", "copilot-instructions.md"])],
            _ => Vec::new(),
        }
    }

    /// Per-skill files earlier Sentra versions wrote to undocumented, always-on,
    /// or duplicate-loading locations. The flag marks `<id>/SKILL.md` layouts whose
    /// directory may be removed once empty.
    fn legacy_skill_files(
        &self,
        host: &HostDirs,
        root: &Path,
        global: bool,
        id: &str,
    ) -> Vec<(PathBuf, bool)> {
        let flat = |parts: &[&str], file: String| (join_all(root, parts).join(file), false);
        let skill_md = |parts: &[&str]| (join_all(root, parts).join(id).join("SKILL.md"), true);
        let md = format!("{id}.md");

        match (self, global) {
            (Self::Cursor, false) => vec![flat(&[".cursor", "rules"], format!("{id}.mdc"))],
            (Self::Cursor, true) => vec![flat(&[".cursor", "skills"], format!("{id}.mdc"))],
            (Self::Windsurf, false) => vec![flat(&[".windsurf", "rules"], md)],
            (Self::Windsurf, true) => vec![flat(&[".codeium", "windsurf", "skills"], md)],
            (Self::Roo, false) => vec![flat(&[".roo", "rules"], md)],
            (Self::Roo, true) => vec![flat(&[".roo", "skills"], md)],
            (Self::ContinueDev, false) => vec![flat(&[".continue", "rules"], md)],
            (Self::Aider, _) => vec![flat(&[".aider", "conventions"], md)],
            (Self::AmazonQ, false) => vec![flat(&[".amazonq", "rules"], md)],
            (Self::Copilot, false) => {
                vec![flat(
                    &[".github", "instructions"],
                    format!("{id}.instructions.md"),
                )]
            }
            (Self::Zed, false) => vec![flat(&[".zed", "rules"], md)],
            (Self::Zed, true) => vec![flat(&[".config", "zed", "rules"], md)],
            (Self::Warp, _) => vec![flat(&[".warp", "rules"], md)],
            (Self::Augment, false) => vec![flat(&[".augment", "rules"], md)],
            (Self::Augment, true) => vec![flat(&[".augment", "skills"], md)],
            (Self::Codex, _) => vec![skill_md(&[".codex", "skills"])],
            (Self::OpenHands, _) => vec![skill_md(&[".openhands", "skills"])],
            (Self::Goose, false) => vec![skill_md(&[".goose", "skills"])],
            (Self::Goose, true) => vec![skill_md(&[".config", "goose", "skills"])],
            (Self::Devin, true) if host.windows => vec![skill_md(&[".config", "devin", "skills"])],
            _ => Vec::new(),
        }
    }
}

impl fmt::Display for AgentTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a target discovers installed skills.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkillDelivery {
    /// The agent discovers `<skills_dir>/<id>/SKILL.md` on demand.
    SkillDirectory,
    /// Skill trees live in `skills_dir`; an agent-requested rule
    /// (`alwaysApply: false`) carrying the playbook is written to `rules_dir`.
    RequestableRule {
        /// Rules directory (`.continue/rules`).
        rules_dir: PathBuf,
    },
    /// Skill trees live in `skills_dir`; the agent applies every rule on every
    /// request, so only a short pointer rule is written to `rules_dir`.
    PointerRule {
        /// Rules directory (`.amazonq/rules`).
        rules_dir: PathBuf,
    },
    /// Skill trees live in `skills_dir`; each `SKILL.md` is listed under `read:`
    /// in the Aider config file.
    AiderReadList {
        /// `.aider.conf.yml` in the workspace root or the home directory.
        config: PathBuf,
    },
}

/// Resolved skill location for one concrete target and scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkillLocation {
    /// Concrete target.
    pub target: AgentTarget,
    /// Whether this is the user (global) scope.
    pub global: bool,
    /// Workspace root (workspace scope) or home directory (global scope).
    pub root: PathBuf,
    /// Directory that receives `<id>/SKILL.md` skill trees.
    pub skills_dir: PathBuf,
    /// How the agent discovers the installed skills.
    pub delivery: SkillDelivery,
}

/// Host directories used to resolve user-scope locations.
///
/// [`HostDirs::from_env`] reads the process environment; tests and embedders
/// can construct the struct directly to stay away from the real home directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostDirs {
    /// User home directory (`USERPROFILE`/`HOME`).
    pub home: Option<PathBuf>,
    /// Windows roaming application data (`APPDATA`).
    pub appdata: Option<PathBuf>,
    /// XDG configuration home (`XDG_CONFIG_HOME`).
    pub xdg_config_home: Option<PathBuf>,
    /// Whether Windows-specific locations apply.
    pub windows: bool,
}

impl HostDirs {
    /// Reads host directories from the process environment.
    ///
    /// Only absolute, non-empty values are accepted. The home directory prefers
    /// `USERPROFILE` on Windows and `HOME` elsewhere.
    pub fn from_env() -> Self {
        let windows = cfg!(windows);
        let order: [&str; 2] = if windows {
            ["USERPROFILE", "HOME"]
        } else {
            ["HOME", "USERPROFILE"]
        };
        Self {
            home: order.iter().find_map(|key| env_dir(key)),
            appdata: env_dir("APPDATA"),
            xdg_config_home: env_dir("XDG_CONFIG_HOME"),
            windows,
        }
    }

    fn home_dir(&self) -> Result<PathBuf, InstallError> {
        self.home.clone().ok_or(InstallError::HomeDirUnavailable)
    }

    /// `%APPDATA%\devin` on Windows; elsewhere `$XDG_CONFIG_HOME/devin` when set,
    /// otherwise `~/.config/devin` (<https://docs.devin.ai/windsurf/plugins/cascade/mcp>).
    fn devin_config_dir(&self) -> Result<PathBuf, InstallError> {
        if self.windows {
            if let Some(appdata) = &self.appdata {
                return Ok(appdata.join("devin"));
            }
            return Ok(join_all(
                &self.home_dir()?,
                &["AppData", "Roaming", "devin"],
            ));
        }
        Ok(self.xdg_config_dir()?.join("devin"))
    }

    /// `$XDG_CONFIG_HOME` when set, otherwise `~/.config` (OpenCode uses this on every OS).
    fn xdg_config_dir(&self) -> Result<PathBuf, InstallError> {
        match &self.xdg_config_home {
            Some(dir) => Ok(dir.clone()),
            None => Ok(self.home_dir()?.join(".config")),
        }
    }
}

/// One file managed by an installation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledFile {
    /// Absolute path of the file.
    pub path: PathBuf,
    /// Whether the file was created, updated, or already current.
    pub status: FileStatus,
    /// Backup of the previous content when the file was updated.
    pub backup: Option<PathBuf>,
}

/// Per-target result inside an installation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetOutcome {
    /// Concrete target.
    pub target: AgentTarget,
    /// Directory that received the skill trees, when the target was installed.
    pub skills_dir: Option<PathBuf>,
    /// Reason the target was skipped (only for `all`).
    pub skipped: Option<String>,
}

/// Result of installing skills into a target ecosystem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallReport {
    /// Target ecosystem installed to.
    pub target: AgentTarget,
    /// Whether installed to global user scope.
    pub is_global: bool,
    /// Primary skills directory (`<root>/.agents/skills` for `all`).
    pub destination_dir: PathBuf,
    /// Every file the installation manages (created, updated, or already current).
    pub installed_files: Vec<PathBuf>,
    /// Installed skill ids, in request order without duplicates.
    pub skills: Vec<&'static str>,
    /// Per-file status, in the same order as `installed_files`.
    pub files: Vec<InstalledFile>,
    /// Per-target outcome (one entry for a single target, every target for `all`).
    pub targets: Vec<TargetOutcome>,
    /// Artifacts from earlier Sentra versions that were removed or need review.
    pub legacy: Vec<LegacyCleanup>,
    /// Human-readable notes about target behavior the user should know.
    pub notes: Vec<String>,
}

impl InstallReport {
    /// Files that were created or updated by this run.
    pub fn written_files(&self) -> impl Iterator<Item = &InstalledFile> {
        self.files
            .iter()
            .filter(|file| file.status != FileStatus::Unchanged)
    }

    /// Every backup written by this run (updated files and rewritten legacy rule files).
    pub fn backups(&self) -> Vec<&Path> {
        let mut backups: Vec<&Path> = Vec::new();
        let candidates = self
            .files
            .iter()
            .filter_map(|file| file.backup.as_deref())
            .chain(self.legacy.iter().filter_map(|item| item.backup.as_deref()));
        for backup in candidates {
            if !backups.contains(&backup) {
                backups.push(backup);
            }
        }
        backups
    }

    /// Stable JSON representation for `sentra install --json` and MCP tools.
    pub fn to_json(&self) -> serde_json::Value {
        let display = |path: &Path| path.display().to_string();
        serde_json::json!({
            "schema_version": 1,
            "command": "install",
            "target": self.target.as_str(),
            "global": self.is_global,
            "scope": if self.is_global { "global" } else { "workspace" },
            "destination": display(&self.destination_dir),
            "count": self.skills.len(),
            "skills": self.skills,
            "file_count": self.installed_files.len(),
            "files": self.installed_files.iter().map(|p| display(p)).collect::<Vec<_>>(),
            "file_changes": self.files.iter().map(|file| serde_json::json!({
                "path": display(&file.path),
                "status": file.status.as_str(),
                "backup": file.backup.as_deref().map(display),
            })).collect::<Vec<_>>(),
            "targets": self.targets.iter().map(|outcome| serde_json::json!({
                "target": outcome.target.as_str(),
                "status": if outcome.skipped.is_some() { "skipped" } else { "installed" },
                "skills_dir": outcome.skills_dir.as_deref().map(display),
                "reason": outcome.skipped,
            })).collect::<Vec<_>>(),
            "legacy_cleanup": self.legacy.iter().map(|item| serde_json::json!({
                "path": display(&item.path),
                "skill": item.skill_id,
                "action": item.action.as_str(),
                "manual_review": item.action.needs_manual_review(),
                "backup": item.backup.as_deref().map(display),
            })).collect::<Vec<_>>(),
            "backups": self.backups().into_iter().map(display).collect::<Vec<_>>(),
            "notes": self.notes,
        })
    }
}

/// Failure modes of skill installation. Each maps to a stable error code.
#[derive(Debug)]
pub enum InstallError {
    /// One or more requested skill ids are not bundled.
    SkillNotFound {
        /// Unknown ids, in request order.
        ids: Vec<String>,
    },
    /// A skill selection was requested but contained no ids.
    NoSkillsSelected,
    /// The target loads every installed skill into every chat, so the skills
    /// must be chosen explicitly (`--skill`) instead of installing all of them.
    SkillSelectionRequired {
        /// Target that was requested.
        target: AgentTarget,
        /// Number of bundled skills an unselected install would have added.
        bundled_skills: usize,
        /// Combined size of their `SKILL.md` files in bytes.
        bundled_bytes: usize,
    },
    /// The target has no documented file-based skill location.
    UnsupportedTarget {
        /// Target that was requested.
        target: AgentTarget,
        /// Why the target is unsupported.
        reason: &'static str,
    },
    /// The target does not support the requested scope.
    UnsupportedScope {
        /// Target that was requested.
        target: AgentTarget,
        /// Requested scope (`true` = global).
        global: bool,
        /// Why the scope is unsupported.
        reason: &'static str,
    },
    /// The workspace directory does not exist.
    WorkspaceNotFound {
        /// Path that was given.
        path: PathBuf,
    },
    /// No absolute home directory could be determined for global scope.
    HomeDirUnavailable,
    /// Skills were installed, but an existing config file could not be edited
    /// losslessly; the user must add `snippet` manually.
    ManualStepRequired {
        /// Everything that was installed before the manual step.
        report: Box<InstallReport>,
        /// Config file that needs the manual edit.
        config_path: PathBuf,
        /// Why the file was not edited automatically.
        reason: String,
        /// Exact text to merge into the config file.
        snippet: String,
    },
    /// A filesystem operation failed.
    Io {
        /// Path being written, read, or removed.
        path: PathBuf,
        /// Underlying error.
        source: io::Error,
    },
}

impl InstallError {
    /// Stable machine-readable error code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::SkillNotFound { .. } => "skill_not_found",
            Self::NoSkillsSelected => "no_skills_selected",
            Self::SkillSelectionRequired { .. } => "skill_selection_required",
            Self::UnsupportedTarget { .. } => "unsupported_target",
            Self::UnsupportedScope { .. } => "unsupported_scope",
            Self::WorkspaceNotFound { .. } => "workspace_not_found",
            Self::HomeDirUnavailable => "home_dir_unavailable",
            Self::ManualStepRequired { .. } => "manual_config_edit_required",
            Self::Io { .. } => "install_failed",
        }
    }

    /// Recommended CLI exit code (2 usage, 5 failure, 6 action required, 7 not found).
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::SkillNotFound { .. } => 7,
            Self::NoSkillsSelected
            | Self::SkillSelectionRequired { .. }
            | Self::UnsupportedTarget { .. }
            | Self::UnsupportedScope { .. }
            | Self::WorkspaceNotFound { .. } => 2,
            Self::ManualStepRequired { .. } => 6,
            Self::HomeDirUnavailable | Self::Io { .. } => 5,
        }
    }

    /// Stable JSON error body (`schema_version`, `command`, `error`, details).
    pub fn to_json(&self) -> serde_json::Value {
        let mut body = serde_json::json!({
            "schema_version": 1,
            "command": "install",
            "error": self.code(),
            "message": self.to_string(),
        });
        let details = match self {
            Self::SkillNotFound { ids } => serde_json::json!({
                "unknown_skills": ids,
                "available_skills": list_builtin_skills().iter().map(|s| s.id).collect::<Vec<_>>(),
            }),
            Self::UnsupportedTarget { target, reason } => {
                serde_json::json!({ "target": target.as_str(), "reason": reason })
            }
            Self::SkillSelectionRequired {
                target,
                bundled_skills,
                bundled_bytes,
            } => serde_json::json!({
                "target": target.as_str(),
                "bundled_skills": bundled_skills,
                "bundled_bytes": bundled_bytes,
                "available_skills": list_builtin_skills().iter().map(|s| s.id).collect::<Vec<_>>(),
            }),
            Self::UnsupportedScope {
                target,
                global,
                reason,
            } => serde_json::json!({
                "target": target.as_str(),
                "scope": if *global { "global" } else { "workspace" },
                "reason": reason,
            }),
            Self::WorkspaceNotFound { path } | Self::Io { path, .. } => {
                serde_json::json!({ "path": path.display().to_string() })
            }
            Self::ManualStepRequired {
                report,
                config_path,
                reason,
                snippet,
            } => serde_json::json!({
                "config_path": config_path.display().to_string(),
                "reason": reason,
                "snippet": snippet,
                "report": report.to_json(),
            }),
            Self::NoSkillsSelected | Self::HomeDirUnavailable => serde_json::json!({}),
        };
        if let (Some(target), serde_json::Value::Object(extra)) = (body.as_object_mut(), details) {
            target.extend(extra);
        }
        body
    }
}

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SkillNotFound { ids } => {
                write!(f, "unknown skill id(s): {}", ids.join(", "))
            }
            Self::NoSkillsSelected => f.write_str("no skill ids were given"),
            Self::SkillSelectionRequired {
                target,
                bundled_skills,
                bundled_bytes,
            } => write!(
                f,
                "{target} loads every installed skill into every chat, and all {bundled_skills} bundled playbooks total {bundled_bytes} bytes; choose the skills you need with --skill <id>[,<id>...] (see `sentra skills list`)"
            ),
            Self::UnsupportedTarget { target, reason } => {
                write!(f, "skills cannot be installed for {target}: {reason}")
            }
            Self::UnsupportedScope {
                target,
                global,
                reason,
            } => write!(
                f,
                "{} scope is not supported for {target}: {reason}",
                if *global { "global" } else { "workspace" }
            ),
            Self::WorkspaceNotFound { path } => {
                write!(
                    f,
                    "workspace directory {} does not exist",
                    display_path(path)
                )
            }
            Self::HomeDirUnavailable => f.write_str(
                "cannot determine an absolute home directory (USERPROFILE/HOME) for global scope",
            ),
            Self::ManualStepRequired {
                config_path,
                reason,
                snippet,
                ..
            } => write!(
                f,
                "skills were installed, but {} was not edited automatically ({reason}); add this manually:\n{snippet}",
                display_path(config_path)
            ),
            Self::Io { path, source } => write!(f, "{}: {source}", display_path(path)),
        }
    }
}

impl std::error::Error for InstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Resolves skill ids (comma-separated values allowed) to bundled skills,
/// removing duplicates and rejecting unknown ids.
pub fn resolve_skill_ids(ids: &[&str]) -> Result<Vec<&'static SkillDefinition>, InstallError> {
    let mut resolved: Vec<&'static SkillDefinition> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    let mut any = false;
    for id in ids.iter().flat_map(|value| value.split(',')).map(str::trim) {
        if id.is_empty() {
            continue;
        }
        any = true;
        match find_skill_by_id(id) {
            Some(skill) if !resolved.iter().any(|known| known.id == skill.id) => {
                resolved.push(skill);
            }
            Some(_) => {}
            None if !unknown.iter().any(|u| u == id) => unknown.push(id.to_string()),
            None => {}
        }
    }
    if !unknown.is_empty() {
        return Err(InstallError::SkillNotFound { ids: unknown });
    }
    if !any {
        return Err(InstallError::NoSkillsSelected);
    }
    Ok(resolved)
}

/// Installs a single skill definition into the specified agent target and
/// returns every file path the installation manages.
pub fn install_single_skill(
    skill: &SkillDefinition,
    target: AgentTarget,
    global: bool,
    workspace: &Path,
) -> Result<Vec<PathBuf>, InstallError> {
    install_skills_in(&HostDirs::from_env(), &[skill], target, global, workspace)
        .map(|report| report.installed_files)
}

/// Installs all built-in skills into the specified agent target.
///
/// Aider loads every `read:` file into every chat, so it requires an explicit
/// selection ([`install_selected_skills`]) and fails here with
/// [`InstallError::SkillSelectionRequired`] before anything is written.
pub fn install_all_skills(
    target: AgentTarget,
    global: bool,
    workspace: &Path,
) -> Result<InstallReport, InstallError> {
    let skills: Vec<&SkillDefinition> = list_builtin_skills().iter().collect();
    if target == AgentTarget::Aider {
        return Err(InstallError::SkillSelectionRequired {
            target,
            bundled_skills: skills.len(),
            bundled_bytes: skills.iter().map(|skill| skill.content.len()).sum(),
        });
    }
    install_skills_in(&HostDirs::from_env(), &skills, target, global, workspace)
}

/// Installs selected skills by id into the specified agent target.
///
/// Every id is resolved before anything is written; unknown ids fail with
/// [`InstallError::SkillNotFound`].
pub fn install_selected_skills(
    skill_ids: &[&str],
    target: AgentTarget,
    global: bool,
    workspace: &Path,
) -> Result<InstallReport, InstallError> {
    let skills = resolve_skill_ids(skill_ids)?;
    install_skills_in(&HostDirs::from_env(), &skills, target, global, workspace)
}

/// Installs `skills` into `target` using explicit host directories.
pub fn install_skills_in(
    host: &HostDirs,
    skills: &[&SkillDefinition],
    target: AgentTarget,
    global: bool,
    workspace: &Path,
) -> Result<InstallReport, InstallError> {
    let mut unique: Vec<SkillRef> = Vec::new();
    for skill in skills {
        if !unique.iter().any(|known| known.id == skill.id) {
            unique.push(SkillRef::from(*skill));
        }
    }

    let root = scope_root(host, global, workspace)?;
    let mut run = Run::default();
    let mut manual = None;

    let destination_dir = if target == AgentTarget::All {
        for concrete in AgentTarget::CONCRETE {
            if concrete == AgentTarget::Aider {
                run.skip(
                    concrete,
                    "edits .aider.conf.yml and loads skills into every chat; run `sentra install aider` explicitly".to_string(),
                );
                continue;
            }
            match concrete.location_in(host, &root, global) {
                Ok(location) => {
                    run.install_location(host, &location, &unique)?;
                }
                Err(
                    err @ (InstallError::UnsupportedTarget { .. }
                    | InstallError::UnsupportedScope { .. }),
                ) => run.skip(concrete, err.to_string()),
                Err(err) => return Err(err),
            }
        }
        join_all(&root, &[".agents", "skills"])
    } else {
        let location = target.location_in(host, &root, global)?;
        manual = run.install_location(host, &location, &unique)?;
        location.skills_dir
    };

    let report = run.into_report(target, global, destination_dir, &unique);
    match manual {
        Some((config_path, edit)) => Err(InstallError::ManualStepRequired {
            report: Box::new(report),
            config_path,
            reason: edit.reason,
            snippet: edit.snippet,
        }),
        None => Ok(report),
    }
}

/// `'static` view of a bundled skill.
#[derive(Clone, Copy)]
struct SkillRef {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    content: &'static str,
}

impl From<&SkillDefinition> for SkillRef {
    fn from(skill: &SkillDefinition) -> Self {
        Self {
            id: skill.id,
            name: skill.name,
            description: skill.description,
            content: skill.content,
        }
    }
}

impl SkillRef {
    /// Every file of the skill as `(relative path, bytes)`, `SKILL.md` first.
    fn files(&self) -> Vec<(&'static str, &'static [u8])> {
        let mut files: Vec<(&'static str, &'static [u8])> = Vec::new();
        files.push(("SKILL.md", self.content.as_bytes()));
        if let Some(tree) = skill_files(self.id) {
            files.extend(tree.iter().copied().filter(|(path, _)| *path != "SKILL.md"));
        }
        files
    }
}

/// Mutable state of one installation run.
#[derive(Default)]
struct Run {
    files: Vec<InstalledFile>,
    seen_files: HashSet<PathBuf>,
    seen_legacy: HashSet<PathBuf>,
    legacy: Vec<LegacyCleanup>,
    targets: Vec<TargetOutcome>,
    notes: Vec<String>,
}

impl Run {
    fn skip(&mut self, target: AgentTarget, reason: String) {
        self.targets.push(TargetOutcome {
            target,
            skills_dir: None,
            skipped: Some(reason),
        });
    }

    fn note(&mut self, note: String) {
        if !self.notes.contains(&note) {
            self.notes.push(note);
        }
    }

    fn write(&mut self, path: PathBuf, contents: &[u8]) -> Result<(), InstallError> {
        let stem = path.clone();
        self.write_backed_up_as(path, contents, &stem)
    }

    /// Writes `path`, backing differing content up to `<backup_stem>.bak`.
    fn write_backed_up_as(
        &mut self,
        path: PathBuf,
        contents: &[u8],
        backup_stem: &Path,
    ) -> Result<(), InstallError> {
        if !self.seen_files.insert(path.clone()) {
            return Ok(());
        }
        let outcome = install_fs::write_file_preserving_backed_up_as(&path, contents, backup_stem)
            .map_err(|source| InstallError::Io {
                path: path.clone(),
                source,
            })?;
        self.files.push(InstalledFile {
            path,
            status: outcome.status,
            backup: outcome.backup,
        });
        Ok(())
    }

    /// Installs every skill for one concrete location. Returns the manual step
    /// required for Aider when its config could not be edited.
    fn install_location(
        &mut self,
        host: &HostDirs,
        location: &SkillLocation,
        skills: &[SkillRef],
    ) -> Result<Option<(PathBuf, ManualEdit)>, InstallError> {
        for skill in skills {
            self.write_skill_tree(&location.skills_dir, skill)?;
            match &location.delivery {
                SkillDelivery::SkillDirectory | SkillDelivery::AiderReadList { .. } => {}
                SkillDelivery::RequestableRule { rules_dir } => {
                    let rule = requestable_rule(location, skill);
                    self.write(
                        rules_dir.join(format!("sentra-{}.md", skill.id)),
                        rule.as_bytes(),
                    )?;
                }
                SkillDelivery::PointerRule { rules_dir } => {
                    let rule = pointer_rule(location, skill);
                    self.write(
                        rules_dir.join(format!("sentra-{}.md", skill.id)),
                        rule.as_bytes(),
                    )?;
                }
            }
        }

        self.cleanup_legacy(host, location, skills)?;
        self.targets.push(TargetOutcome {
            target: location.target,
            skills_dir: Some(location.skills_dir.clone()),
            skipped: None,
        });

        match &location.delivery {
            SkillDelivery::SkillDirectory => Ok(None),
            SkillDelivery::RequestableRule { .. } => {
                self.note(format!(
                    "{}: rules are written with `alwaysApply: false`, so the agent loads a playbook only when its description matches the task.",
                    location.target
                ));
                Ok(None)
            }
            SkillDelivery::PointerRule { .. } => {
                self.note(format!(
                    "{}: every project rule is applied to every chat, so Sentra writes one short pointer rule per skill; the playbooks stay under {}.",
                    location.target,
                    display_path(&location.skills_dir)
                ));
                Ok(None)
            }
            SkillDelivery::AiderReadList { config } => {
                let bytes: usize = skills.iter().map(|skill| skill.content.len()).sum();
                self.note(format!(
                    "aider: every `read:` file is loaded into every chat; the {} SKILL.md file(s) listed for this install add {bytes} bytes to each chat, so install only the skills you need with --skill.",
                    skills.len()
                ));
                if !location.global {
                    self.note("aider: workspace `read:` entries are relative; start aider from the workspace root.".to_string());
                }
                self.update_aider_config(location, config, skills)
            }
        }
    }

    fn write_skill_tree(
        &mut self,
        skills_dir: &Path,
        skill: &SkillRef,
    ) -> Result<(), InstallError> {
        let skill_dir = skills_dir.join(skill.id);
        // Backups of user-edited skill files go to `<skills_dir>/.sentra-backups/<id>/`
        // so they never sit inside the directory the agent loads as the skill.
        let backup_dir = skills_dir.join(SKILL_BACKUP_DIR).join(skill.id);
        for (relative, bytes) in skill.files() {
            let path = safe_join(&skill_dir, relative)?;
            let stem = safe_join(&backup_dir, relative)?;
            self.write_backed_up_as(path, bytes, &stem)?;
        }
        Ok(())
    }

    fn cleanup_legacy(
        &mut self,
        host: &HostDirs,
        location: &SkillLocation,
        skills: &[SkillRef],
    ) -> Result<(), InstallError> {
        let target = location.target;
        let root = &location.root;

        let blocks: Vec<(&'static str, &'static str)> =
            skills.iter().map(|s| (s.id, s.content)).collect();
        for path in target.legacy_block_files(root, location.global) {
            if !self.seen_legacy.insert(path.clone()) {
                continue;
            }
            let actions = install_fs::remove_legacy_blocks(&path, &blocks).map_err(|source| {
                InstallError::Io {
                    path: path.clone(),
                    source,
                }
            })?;
            self.record_legacy(actions);
        }

        for skill in skills {
            for (path, skill_dir) in
                target.legacy_skill_files(host, root, location.global, skill.id)
            {
                if self.seen_files.contains(&path) || !self.seen_legacy.insert(path.clone()) {
                    continue;
                }
                let action =
                    install_fs::remove_legacy_file(&path, skill.id, skill.content, skill_dir)
                        .map_err(|source| InstallError::Io {
                            path: path.clone(),
                            source,
                        })?;
                self.record_legacy(action);
            }
        }
        Ok(())
    }

    fn record_legacy(&mut self, items: impl IntoIterator<Item = LegacyCleanup>) {
        for item in items {
            if item.action.needs_manual_review() {
                self.note(format!(
                    "{} contains Sentra content for `{}` from an earlier version that differs from the bundled playbook; review and remove it manually.",
                    display_path(&item.path),
                    item.skill_id
                ));
            }
            self.legacy.push(item);
        }
    }

    fn update_aider_config(
        &mut self,
        location: &SkillLocation,
        config: &Path,
        skills: &[SkillRef],
    ) -> Result<Option<(PathBuf, ManualEdit)>, InstallError> {
        let entries: Vec<String> = skills
            .iter()
            .map(|skill| aider_entry(location, skill))
            .collect();
        let io_err = |source| InstallError::Io {
            path: config.to_path_buf(),
            source,
        };

        let existing = install_fs::read_regular_file(config).map_err(io_err)?;
        let text = match existing.as_deref().map(std::str::from_utf8) {
            None => None,
            Some(Ok(text)) => Some(text),
            Some(Err(_)) => {
                return Ok(Some((
                    config.to_path_buf(),
                    ManualEdit {
                        reason: "the file is not valid UTF-8".to_string(),
                        snippet: install_aider::manual_snippet(&entries),
                    },
                )));
            }
        };

        match install_aider::plan_read_entries(text, &entries) {
            Ok(Some(updated)) => {
                self.write(config.to_path_buf(), updated.as_bytes())?;
                Ok(None)
            }
            Ok(None) => {
                if self.seen_files.insert(config.to_path_buf()) {
                    self.files.push(InstalledFile {
                        path: config.to_path_buf(),
                        status: FileStatus::Unchanged,
                        backup: None,
                    });
                }
                Ok(None)
            }
            Err(edit) => Ok(Some((config.to_path_buf(), edit))),
        }
    }

    fn into_report(
        self,
        target: AgentTarget,
        global: bool,
        destination_dir: PathBuf,
        skills: &[SkillRef],
    ) -> InstallReport {
        InstallReport {
            target,
            is_global: global,
            destination_dir,
            installed_files: self.files.iter().map(|file| file.path.clone()).collect(),
            skills: skills.iter().map(|skill| skill.id).collect(),
            files: self.files,
            targets: self.targets,
            legacy: self.legacy,
            notes: self.notes,
        }
    }
}

/// Continue rule: `alwaysApply: false` with a description, so the agent pulls it in on demand.
fn requestable_rule(location: &SkillLocation, skill: &SkillRef) -> String {
    let skill_root = display_relative(location, &location.skills_dir.join(skill.id));
    format!(
        "---\nname: {}\ndescription: {}\nalwaysApply: false\n---\n\n<!-- Installed by Sentra from the bundled `{id}` skill. Files referenced below are relative to `{skill_root}/`. -->\n\n{}",
        yaml_string(skill.name),
        yaml_string(skill.description),
        ensure_trailing_newline(&normalize_newlines(strip_frontmatter(skill.content))),
        id = skill.id,
    )
}

/// Amazon Q rule: a short always-on pointer to the on-disk playbook.
fn pointer_rule(location: &SkillLocation, skill: &SkillRef) -> String {
    let skill_root = display_relative(location, &location.skills_dir.join(skill.id));
    format!(
        "# Sentra skill: {name}\n\n{description}\n\nWhen a request matches this description, read `{skill_root}/SKILL.md` and follow it. Files it references are relative to `{skill_root}/`.\n",
        name = skill.name,
        description = skill.description,
    )
}

/// Aider `read:` entry: workspace-relative in a workspace config, absolute in `~/.aider.conf.yml`.
fn aider_entry(location: &SkillLocation, skill: &SkillRef) -> String {
    let path = location.skills_dir.join(skill.id).join("SKILL.md");
    if location.global {
        path.to_string_lossy().replace('\\', "/")
    } else {
        display_relative(location, &path)
    }
}

/// Forward-slash path of `path` relative to the location root (absolute if outside it).
fn display_relative(location: &SkillLocation, path: &Path) -> String {
    let shown = path.strip_prefix(&location.root).unwrap_or(path);
    shown.to_string_lossy().replace('\\', "/")
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| format!("\"{}\"", value.replace('"', "'")))
}

fn ensure_trailing_newline(text: &str) -> String {
    if text.ends_with('\n') {
        text.to_string()
    } else {
        format!("{text}\n")
    }
}

/// Joins a catalog-relative (`/`-separated) path below `base`, rejecting anything
/// that could escape the skill directory.
fn safe_join(base: &Path, relative: &str) -> Result<PathBuf, InstallError> {
    let mut path = base.to_path_buf();
    let mut components = 0;
    for part in relative.split('/') {
        let invalid =
            part.is_empty() || part == "." || part == ".." || part.contains(['\\', ':', '\0']);
        if invalid {
            return Err(InstallError::Io {
                path: base.join(relative),
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("bundled skill file has an unsafe relative path `{relative}`"),
                ),
            });
        }
        path.push(part);
        components += 1;
    }
    if components == 0 {
        return Err(InstallError::Io {
            path: base.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidData, "empty bundled file path"),
        });
    }
    Ok(path)
}

fn scope_root(host: &HostDirs, global: bool, workspace: &Path) -> Result<PathBuf, InstallError> {
    if global {
        return host.home_dir();
    }
    if workspace.is_dir() {
        Ok(workspace.to_path_buf())
    } else {
        Err(InstallError::WorkspaceNotFound {
            path: workspace.to_path_buf(),
        })
    }
}

fn join_all(base: &Path, parts: &[&str]) -> PathBuf {
    let mut path = base.to_path_buf();
    for part in parts {
        path.push(part);
    }
    path
}

fn env_dir(key: &str) -> Option<PathBuf> {
    let value = std::env::var_os(key)?;
    if value.to_string_lossy().trim().is_empty() {
        return None;
    }
    let path = PathBuf::from(value);
    path.is_absolute().then_some(path)
}
