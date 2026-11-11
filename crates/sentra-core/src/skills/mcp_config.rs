//! Automated MCP (Model Context Protocol) server registration for AI coding agents
//! (REQ-F17, EXTENSIONS.md).
//!
//! Registers Sentra's stdio MCP server (`<sentra> mcp`) in the configuration
//! file each agent documents, per scope:
//!
//! | Target | Workspace | Global | Format |
//! |---|---|---|---|
//! | Claude Code | `.mcp.json` | `~/.claude.json` (`$CLAUDE_CONFIG_DIR/.claude.json`) | `mcpServers` |
//! | Antigravity | `.agents/mcp_config.json` | `~/.gemini/config/mcp_config.json` | `mcpServers` |
//! | GitHub Copilot | `.github/mcp.json` (CLI) and `.vscode/mcp.json` (VS Code `servers`) | `$COPILOT_HOME/mcp-config.json` | `mcpServers` |
//! | Cursor | `.cursor/mcp.json` | `~/.cursor/mcp.json` | `mcpServers` |
//! | Windsurf / Devin Desktop | `.devin/mcp_config.json` | Cascade's `mcp_config.json` in `%APPDATA%\devin` / `$XDG_CONFIG_HOME/devin` / `~/.config/devin` (same file as Devin) | `mcpServers` |
//! | Cline | unsupported | `$CLINE_MCP_SETTINGS_PATH` or `~/.cline/data/settings/cline_mcp_settings.json` | `mcpServers` |
//! | Roo Code | `.roo/mcp.json` | unsupported (VS Code extension storage) | `mcpServers` |
//! | Continue | `.continue/mcpServers/sentra.yaml` | unsupported (manual `config.yaml` edit) | YAML block |
//! | Goose | unsupported | `config.yaml` (`%APPDATA%\Block\goose\config` / `~/.config/goose`) | YAML `extensions` |
//! | Tabnine | `.tabnine/mcp_servers.json` | `~/.tabnine/mcp_servers.json` | `mcpServers` |
//! | Junie | `.junie/mcp/mcp.json` | `~/.junie/mcp/mcp.json` | `mcpServers` |
//! | Warp | `.warp/.mcp.json` | `~/.warp/.mcp.json` | `mcpServers` |
//! | Droid | `.factory/mcp.json` | `~/.factory/mcp.json` | `mcpServers` |
//! | Kiro | `.kiro/settings/mcp.json` | `~/.kiro/settings/mcp.json` | `mcpServers` |
//! | Codex | `.codex/config.toml` | `$CODEX_HOME/config.toml` | TOML `[mcp_servers.sentra]` |
//! | Zed | `.zed/settings.json` | `%APPDATA%\Zed` / `$XDG_CONFIG_HOME/zed` / `~/.config/zed` | JSONC `context_servers` |
//! | Amazon Q | `.amazonq/mcp.json` | `~/.aws/amazonq/mcp.json` | `mcpServers` |
//! | Devin | `.devin/mcp_config.json` | `mcp_config.json` in `%APPDATA%\devin` / `$XDG_CONFIG_HOME/devin` / `~/.config/devin` | `mcpServers` |
//! | OpenCode | `opencode.json(c)` | `~/.config/opencode/opencode.json(c)` | JSONC `mcp.servers` |
//! | Trae | `.trae/mcp.json` | unsupported (IDE-managed) | `mcpServers` |
//! | Kimi Code | `.kimi-code/mcp.json` | `$KIMI_CODE_HOME/mcp.json` | `mcpServers` |
//! | Qwen Code | `.qwen/settings.json` | `~/.qwen/settings.json` | JSONC `mcpServers` |
//! | Hermes | unsupported | `~/.hermes/config.yaml` | YAML `mcp_servers` |
//! | Augment | `.augment/settings.json` | `~/.augment/settings.json` | JSONC `mcpServers` |
//! | Amp | `.amp/settings.json` | `~/.config/amp/settings.json` | JSONC `amp.mcpServers` |
//! | Aider, OpenHands, Replit, Cody | no file-based stdio MCP configuration | | |
//!
//! Existing files are never re-serialised: edits are surgical (see
//! `mcp_jsonc`, `mcp_toml`, `mcp_yaml`), every replaced file is backed up to
//! `<file>.bak`, and writes are atomic. A file Sentra cannot edit losslessly
//! is left untouched and the error carries the exact snippet to add by hand.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Value, json};

use crate::skills::install_text::display_path;
use crate::skills::installer::AgentTarget;
use crate::skills::mcp_fs::{self, CommitError, LoadError, Loaded, Written};
use crate::skills::mcp_jsonc::{self, EditError, Managed, Render, Upsert};
use crate::skills::mcp_toml;
use crate::skills::mcp_yaml::{self, Locate, YamlValue};

/// Name of the MCP server entry Sentra registers.
pub const MCP_SERVER_NAME: &str = "sentra";

/// Arguments that start Sentra's stdio MCP server.
const MCP_SERVER_ARGS: [&str; 1] = ["mcp"];

/// Number of attempts when another process changes a file during an update.
const MAX_ATTEMPTS: usize = 3;

/// An agent or editor whose MCP configuration Sentra can manage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum McpTarget {
    /// Claude Code.
    Claude,
    /// Google Antigravity.
    Antigravity,
    /// GitHub Copilot (Copilot CLI and VS Code).
    Copilot,
    /// Cursor.
    Cursor,
    /// Windsurf (now Devin Desktop).
    Windsurf,
    /// Cline.
    Cline,
    /// Roo Code.
    Roo,
    /// Continue.
    Continue,
    /// Aider (no MCP configuration file).
    Aider,
    /// OpenHands (MCP is configured in the UI or SDK).
    OpenHands,
    /// Goose.
    Goose,
    /// Tabnine.
    Tabnine,
    /// JetBrains Junie.
    Junie,
    /// Warp.
    Warp,
    /// Factory Droid.
    Droid,
    /// Kiro.
    Kiro,
    /// OpenAI Codex CLI.
    Codex,
    /// Zed.
    Zed,
    /// Amazon Q Developer.
    AmazonQ,
    /// Sourcegraph Cody (MCP lives in editor settings).
    Cody,
    /// Devin (Devin CLI / Devin Desktop).
    Devin,
    /// OpenCode.
    OpenCode,
    /// Trae.
    Trae,
    /// Kimi Code CLI.
    Kimi,
    /// Qwen Code.
    Qwen,
    /// Nous Research Hermes Agent.
    Hermes,
    /// Replit Agent (remote HTTPS MCP servers only).
    Replit,
    /// Augment Code / Auggie CLI.
    Augment,
    /// Sourcegraph Amp.
    Amp,
}

impl McpTarget {
    /// Every target, in display order.
    pub const ALL: [Self; 29] = [
        Self::Claude,
        Self::Antigravity,
        Self::Copilot,
        Self::Cursor,
        Self::Windsurf,
        Self::Cline,
        Self::Roo,
        Self::Continue,
        Self::Aider,
        Self::OpenHands,
        Self::Goose,
        Self::Tabnine,
        Self::Junie,
        Self::Warp,
        Self::Droid,
        Self::Kiro,
        Self::Codex,
        Self::Zed,
        Self::AmazonQ,
        Self::Cody,
        Self::Devin,
        Self::OpenCode,
        Self::Trae,
        Self::Kimi,
        Self::Qwen,
        Self::Hermes,
        Self::Replit,
        Self::Augment,
        Self::Amp,
    ];

    /// Parses a target name or alias (case-insensitive). `all` is not a target;
    /// use [`install_mcp_server_all`] for it.
    pub fn parse(value: &str) -> Option<Self> {
        let target = match value.trim().to_ascii_lowercase().as_str() {
            "claude" | "claudecode" | "claude-code" | ".claude" => Self::Claude,
            "antigravity" | "agy" | "gemini" => Self::Antigravity,
            "copilot" | "github-copilot" | ".copilot" => Self::Copilot,
            "cursor" | ".cursor" => Self::Cursor,
            "windsurf" | "codeium" | ".windsurf" => Self::Windsurf,
            "cline" | ".cline" => Self::Cline,
            "roo" | "roo-code" | "roocode" | ".roo" => Self::Roo,
            "continue" | "continue-dev" | "continuedev" | ".continue" => Self::Continue,
            "aider" | ".aider" => Self::Aider,
            "openhands" | "opendevin" | ".openhands" => Self::OpenHands,
            "goose" | ".goose" => Self::Goose,
            "tabnine" | "tabnine-cli" | ".tabnine" => Self::Tabnine,
            "junie" | ".junie" => Self::Junie,
            "warp" | ".warp" => Self::Warp,
            "droid" | "factory" | "factory-droid" | ".factory" => Self::Droid,
            "kiro" | "kiro-cli" | ".kiro" => Self::Kiro,
            "codex" | "openai-codex" | ".codex" => Self::Codex,
            "zed" | ".zed" => Self::Zed,
            "amazonq" | "amazon-q" | "q" | "aws-q" | ".amazonq" => Self::AmazonQ,
            "cody" | "sourcegraph" | "sourcegraph-cody" | ".cody" => Self::Cody,
            "devin" | "cognition" | ".devin" => Self::Devin,
            "opencode" | "open-code" | ".opencode" => Self::OpenCode,
            "trae" | ".trae" => Self::Trae,
            "kimi" | "kimi-code" | "kimi-cli" | ".kimi-code" => Self::Kimi,
            "qwen" | "qwen-code" | ".qwen" => Self::Qwen,
            "hermes" | "hermes-agent" | ".hermes" => Self::Hermes,
            "replit" | ".replit" => Self::Replit,
            "augment" | "augment-code" | "auggie" | ".augment" => Self::Augment,
            "amp" | "ampcode" | "amp-code" | ".amp" => Self::Amp,
            _ => return None,
        };
        Some(target)
    }

    /// Canonical identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Antigravity => "antigravity",
            Self::Copilot => "copilot",
            Self::Cursor => "cursor",
            Self::Windsurf => "windsurf",
            Self::Cline => "cline",
            Self::Roo => "roo",
            Self::Continue => "continue",
            Self::Aider => "aider",
            Self::OpenHands => "openhands",
            Self::Goose => "goose",
            Self::Tabnine => "tabnine",
            Self::Junie => "junie",
            Self::Warp => "warp",
            Self::Droid => "droid",
            Self::Kiro => "kiro",
            Self::Codex => "codex",
            Self::Zed => "zed",
            Self::AmazonQ => "amazonq",
            Self::Cody => "cody",
            Self::Devin => "devin",
            Self::OpenCode => "opencode",
            Self::Trae => "trae",
            Self::Kimi => "kimi",
            Self::Qwen => "qwen",
            Self::Hermes => "hermes",
            Self::Replit => "replit",
            Self::Augment => "augment",
            Self::Amp => "amp",
        }
    }

    /// Maps a skill-installer target onto an MCP target (`None` for `all`).
    ///
    /// The mapping goes through the canonical name so that it stays correct
    /// when the installer gains or renames variants.
    pub fn from_agent_target(target: AgentTarget) -> Option<Self> {
        Self::parse(target.as_str())
    }
}

impl fmt::Display for McpTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where the MCP server is registered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpScope {
    /// Project configuration inside the workspace.
    Workspace,
    /// User-wide configuration in the home/config directory.
    Global,
}

impl McpScope {
    /// Scope for the legacy `global: bool` flag.
    pub const fn from_global(global: bool) -> Self {
        if global {
            Self::Global
        } else {
            Self::Workspace
        }
    }

    /// Canonical identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Global => "global",
        }
    }
}

/// Host operating system family (decides per-OS configuration paths).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpHostOs {
    /// Windows.
    Windows,
    /// macOS.
    MacOs,
    /// Linux and other Unix-like systems.
    Linux,
}

impl McpHostOs {
    /// The operating system Sentra was compiled for.
    pub const fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Linux
        }
    }
}

/// Environment used to resolve global configuration paths.
///
/// [`McpEnvironment::from_process`] reads the real environment; tests and
/// embedders can construct one explicitly instead of mutating process state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpEnvironment {
    /// Host operating system family.
    pub os: McpHostOs,
    /// Home directory (`USERPROFILE` / `HOME`).
    pub home: Option<PathBuf>,
    /// Windows roaming application data (`APPDATA`).
    pub appdata: Option<PathBuf>,
    /// `XDG_CONFIG_HOME`.
    pub xdg_config_home: Option<PathBuf>,
    /// `CLAUDE_CONFIG_DIR` (moves `.claude.json`).
    pub claude_config_dir: Option<PathBuf>,
    /// `CODEX_HOME` (default `~/.codex`).
    pub codex_home: Option<PathBuf>,
    /// `COPILOT_HOME` (default `~/.copilot`).
    pub copilot_home: Option<PathBuf>,
    /// `KIMI_CODE_HOME` (default `~/.kimi-code`).
    pub kimi_code_home: Option<PathBuf>,
    /// `CLINE_MCP_SETTINGS_PATH` (explicit settings file).
    pub cline_mcp_settings_path: Option<PathBuf>,
    /// `CLINE_DATA_DIR` (default `<CLINE_DIR>/data`).
    pub cline_data_dir: Option<PathBuf>,
    /// `CLINE_DIR` (default `~/.cline`).
    pub cline_dir: Option<PathBuf>,
}

impl McpEnvironment {
    /// An environment with no variables set for the given OS.
    pub const fn empty(os: McpHostOs) -> Self {
        Self {
            os,
            home: None,
            appdata: None,
            xdg_config_home: None,
            claude_config_dir: None,
            codex_home: None,
            copilot_home: None,
            kimi_code_home: None,
            cline_mcp_settings_path: None,
            cline_data_dir: None,
            cline_dir: None,
        }
    }

    /// Reads the variables from the current process environment. Empty and
    /// relative values are ignored so a misconfigured variable can never
    /// redirect a write into the current directory.
    pub fn from_process() -> Self {
        fn var(name: &str) -> Option<PathBuf> {
            let value = std::env::var_os(name)?;
            let path = PathBuf::from(value);
            (!path.as_os_str().is_empty() && path.is_absolute()).then_some(path)
        }
        let os = McpHostOs::current();
        let home = if os == McpHostOs::Windows {
            var("USERPROFILE").or_else(|| var("HOME"))
        } else {
            var("HOME").or_else(|| var("USERPROFILE"))
        };
        Self {
            os,
            home,
            appdata: var("APPDATA"),
            xdg_config_home: var("XDG_CONFIG_HOME"),
            claude_config_dir: var("CLAUDE_CONFIG_DIR"),
            codex_home: var("CODEX_HOME"),
            copilot_home: var("COPILOT_HOME"),
            kimi_code_home: var("KIMI_CODE_HOME"),
            cline_mcp_settings_path: var("CLINE_MCP_SETTINGS_PATH"),
            cline_data_dir: var("CLINE_DATA_DIR"),
            cline_dir: var("CLINE_DIR"),
        }
    }
}

/// Options for an MCP installation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpInstallOptions {
    /// Workspace or global scope.
    pub scope: McpScope,
    /// Workspace root (used for workspace scope).
    pub workspace: PathBuf,
    /// Executable to register. `None` registers the canonical path of the
    /// running Sentra binary ([`std::env::current_exe`]).
    pub command: Option<PathBuf>,
    /// Environment used to resolve global paths.
    pub environment: McpEnvironment,
}

impl McpInstallOptions {
    /// Options using the process environment and the running executable.
    pub fn new(scope: McpScope, workspace: impl Into<PathBuf>) -> Self {
        Self {
            scope,
            workspace: workspace.into(),
            command: None,
            environment: McpEnvironment::from_process(),
        }
    }
}

/// What happened to a configuration file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpFileAction {
    /// A new file was created.
    Created,
    /// An existing file was updated (a backup was written first).
    Updated,
    /// The file already contained the desired entry.
    Unchanged,
}

/// Configuration file syntax.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpConfigFormat {
    /// Strict JSON (comments are still preserved if present).
    Json,
    /// JSON with comments and trailing commas.
    Jsonc,
    /// TOML.
    Toml,
    /// YAML.
    Yaml,
}

/// One configuration file touched by an installation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpFileChange {
    /// Configuration file path.
    pub path: PathBuf,
    /// File syntax.
    pub format: McpConfigFormat,
    /// Created, updated or unchanged.
    pub action: McpFileAction,
    /// Copy of the previous content (only for updated files).
    pub backup_file: Option<PathBuf>,
}

/// Report of an automated MCP server installation for one target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpInstallReport {
    /// Target identifier.
    pub target: String,
    /// Whether configured in global user scope.
    pub is_global: bool,
    /// Scope that was configured.
    pub scope: McpScope,
    /// Primary configuration file (first entry of `files`).
    pub config_file: PathBuf,
    /// Whether the primary file was newly created.
    pub created_new_file: bool,
    /// Action taken on the primary file.
    pub action: McpFileAction,
    /// Backup of the primary file, when it was updated.
    pub backup_file: Option<PathBuf>,
    /// Name of the configured MCP server entry (`sentra`).
    pub server_name: String,
    /// Registered executable.
    pub command: String,
    /// Registered arguments.
    pub args: Vec<String>,
    /// Every configuration file written for this target.
    pub files: Vec<McpFileChange>,
}

/// A configuration change the user must make by hand.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpManualStep {
    /// File to edit.
    pub path: PathBuf,
    /// Syntax of `snippet`.
    pub format: McpConfigFormat,
    /// Exact snippet to merge into the file.
    pub snippet: String,
    /// Human-readable instructions.
    pub instructions: String,
}

/// Why an MCP installation did not complete. No file is modified when an
/// error is returned for a single-file target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum McpInstallError {
    /// `all` (or another non-target) was given where one target is required.
    InvalidTarget {
        /// The rejected value.
        target: String,
    },
    /// The agent has no file-based stdio MCP configuration.
    UnsupportedTarget {
        /// Target identifier.
        target: McpTarget,
        /// How to register Sentra instead.
        hint: String,
        /// Snippet for an editor-managed setting, when one exists.
        manual: Option<Box<McpManualStep>>,
    },
    /// The agent does not support MCP configuration in this scope.
    UnsupportedScope {
        /// Target identifier.
        target: McpTarget,
        /// Rejected scope.
        scope: McpScope,
        /// How to register Sentra instead.
        hint: String,
        /// Snippet to add by hand, when a manual route exists.
        manual: Option<Box<McpManualStep>>,
    },
    /// No home directory could be determined for a global installation.
    HomeUnresolved,
    /// The executable to register could not be determined.
    CommandUnresolved {
        /// Details.
        detail: String,
    },
    /// The existing file is not valid JSON/JSONC/TOML/YAML.
    ConfigUnparseable {
        /// Offending file.
        path: PathBuf,
        /// Parser message.
        detail: String,
        /// What to add by hand once the file is fixed.
        manual: Box<McpManualStep>,
    },
    /// The existing file is not UTF-8 (for example UTF-16).
    ConfigUnsupportedEncoding {
        /// Offending file.
        path: PathBuf,
        /// Detected encoding problem.
        encoding: String,
        /// What to add by hand.
        manual: Box<McpManualStep>,
    },
    /// The existing file parses, but its structure cannot be edited without
    /// discarding or reinterpreting user data.
    ConfigUnexpectedShape {
        /// Offending file.
        path: PathBuf,
        /// What is unexpected.
        detail: String,
        /// What to add by hand.
        manual: Box<McpManualStep>,
    },
    /// The file uses syntax Sentra does not edit automatically (complex TOML
    /// or YAML layouts).
    ManualStepRequired {
        /// File to edit.
        path: PathBuf,
        /// Why automation stopped.
        reason: String,
        /// What to add by hand.
        manual: Box<McpManualStep>,
    },
    /// Reading, backing up or writing a file failed.
    Io {
        /// Affected path.
        path: PathBuf,
        /// Operation that failed.
        operation: String,
        /// Error kind.
        kind: io::ErrorKind,
        /// Error message.
        detail: String,
        /// What to add by hand.
        manual: Option<Box<McpManualStep>>,
    },
}

impl McpInstallError {
    /// Stable machine-readable error code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidTarget { .. } => "invalid_target",
            Self::UnsupportedTarget { .. } => "mcp_unsupported_target",
            Self::UnsupportedScope { .. } => "unsupported_scope",
            Self::HomeUnresolved => "home_directory_unresolved",
            Self::CommandUnresolved { .. } => "mcp_command_unresolved",
            Self::ConfigUnparseable { .. } => "mcp_config_unparseable",
            Self::ConfigUnsupportedEncoding { .. } => "mcp_config_unsupported_encoding",
            Self::ConfigUnexpectedShape { .. } => "mcp_config_unexpected_shape",
            Self::ManualStepRequired { .. } => "mcp_manual_step_required",
            Self::Io { .. } => "mcp_install_io_failed",
        }
    }

    /// Suggested CLI exit code (2 usage, 4 invalid existing input, 5 I/O).
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::InvalidTarget { .. }
            | Self::UnsupportedTarget { .. }
            | Self::UnsupportedScope { .. } => 2,
            Self::ConfigUnparseable { .. }
            | Self::ConfigUnsupportedEncoding { .. }
            | Self::ConfigUnexpectedShape { .. }
            | Self::ManualStepRequired { .. } => 4,
            Self::HomeUnresolved | Self::CommandUnresolved { .. } | Self::Io { .. } => 5,
        }
    }

    /// The snippet the user must add by hand, if any.
    pub fn manual_step(&self) -> Option<&McpManualStep> {
        match self {
            Self::ConfigUnparseable { manual, .. }
            | Self::ConfigUnsupportedEncoding { manual, .. }
            | Self::ConfigUnexpectedShape { manual, .. }
            | Self::ManualStepRequired { manual, .. } => Some(manual.as_ref()),
            Self::UnsupportedTarget { manual, .. }
            | Self::UnsupportedScope { manual, .. }
            | Self::Io { manual, .. } => manual.as_deref(),
            Self::InvalidTarget { .. } | Self::HomeUnresolved | Self::CommandUnresolved { .. } => {
                None
            }
        }
    }

    /// The configuration file involved, if any.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::ConfigUnparseable { path, .. }
            | Self::ConfigUnsupportedEncoding { path, .. }
            | Self::ConfigUnexpectedShape { path, .. }
            | Self::ManualStepRequired { path, .. }
            | Self::Io { path, .. } => Some(path),
            Self::UnsupportedScope { manual, .. } => {
                manual.as_deref().map(|step| step.path.as_path())
            }
            Self::InvalidTarget { .. }
            | Self::UnsupportedTarget { .. }
            | Self::HomeUnresolved
            | Self::CommandUnresolved { .. } => None,
        }
    }

    /// Whether `all` should treat this as an expected skip, not a failure.
    pub const fn is_skip(&self) -> bool {
        matches!(
            self,
            Self::UnsupportedTarget { .. } | Self::UnsupportedScope { .. }
        )
    }

    /// JSON view: `{code, message, path, manual_step}`.
    pub fn to_json(&self) -> Value {
        json!({
            "code": self.code(),
            "message": self.to_string(),
            "path": self.path(),
            "manual_step": self.manual_step(),
        })
    }
}

impl Serialize for McpInstallError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_json().serialize(serializer)
    }
}

impl fmt::Display for McpInstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTarget { target } => {
                write!(f, "\"{target}\" is not a single MCP target")
            }
            Self::UnsupportedTarget { target, hint, .. } => {
                write!(
                    f,
                    "{target} has no file-based MCP configuration Sentra can write: {hint}"
                )
            }
            Self::UnsupportedScope {
                target,
                scope,
                hint,
                ..
            } => write!(
                f,
                "{target} does not support {} MCP configuration: {hint}",
                scope.as_str()
            ),
            Self::HomeUnresolved => f.write_str(
                "cannot determine the home directory (set USERPROFILE or HOME to an absolute path)",
            ),
            Self::CommandUnresolved { detail } => {
                write!(f, "cannot determine the Sentra executable path: {detail}")
            }
            Self::ConfigUnparseable { path, detail, .. } => write!(
                f,
                "{} could not be parsed ({detail}); it was not modified",
                display_path(path)
            ),
            Self::ConfigUnsupportedEncoding { path, encoding, .. } => write!(
                f,
                "{} is {encoding}; Sentra only edits UTF-8 files and did not modify it",
                display_path(path)
            ),
            Self::ConfigUnexpectedShape { path, detail, .. } => write!(
                f,
                "{} has an unexpected structure ({detail}); it was not modified",
                display_path(path)
            ),
            Self::ManualStepRequired { path, reason, .. } => write!(
                f,
                "{} cannot be edited automatically ({reason}); it was not modified",
                display_path(path)
            ),
            Self::Io {
                path,
                operation,
                detail,
                ..
            } => write!(f, "failed to {operation} {}: {detail}", display_path(path)),
        }
    }
}

impl std::error::Error for McpInstallError {}

/// A target that `all` skipped or failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct McpTargetIssue {
    /// Target identifier.
    pub target: McpTarget,
    /// Reason (serialised as `{code, message, path, manual_step}`).
    pub error: McpInstallError,
}

/// Result of [`install_mcp_server_all`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct McpBatchReport {
    /// Scope that was configured.
    pub scope: McpScope,
    /// Targets configured successfully.
    pub installed: Vec<McpInstallReport>,
    /// Targets without MCP support in this scope (not an error).
    pub skipped: Vec<McpTargetIssue>,
    /// Targets that failed; their files were left untouched.
    pub failed: Vec<McpTargetIssue>,
}

impl McpBatchReport {
    /// `true` when no target failed.
    pub fn is_success(&self) -> bool {
        self.failed.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Target table
// ---------------------------------------------------------------------------

/// Shape of the server entry for JSON-family files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// `{ "command": ..., "args": [...] }`.
    Command,
    /// `{ "type": <type>, "command": ..., "args": [...] }`.
    Typed(&'static str),
    /// Copilot CLI: `{ "type": "local", "command", "args", "tools": ["*"] }`.
    CopilotCli,
    /// Zed: `{ "command", "args", "env": {} }`.
    Zed,
    /// OpenCode: `{ "type": "local", "command": [exe, "mcp"] }`.
    OpenCode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum YamlKind {
    Goose,
    Hermes,
    ContinueBlock,
}

#[derive(Clone, Debug)]
enum FilePlan {
    Json {
        path: PathBuf,
        format: McpConfigFormat,
        container: &'static [&'static str],
        shape: Shape,
    },
    Toml {
        path: PathBuf,
    },
    Yaml {
        path: PathBuf,
        kind: YamlKind,
    },
}

impl FilePlan {
    fn path(&self) -> &Path {
        match self {
            Self::Json { path, .. } | Self::Toml { path } | Self::Yaml { path, .. } => path,
        }
    }

    fn format(&self) -> McpConfigFormat {
        match self {
            Self::Json { format, .. } => *format,
            Self::Toml { .. } => McpConfigFormat::Toml,
            Self::Yaml { .. } => McpConfigFormat::Yaml,
        }
    }
}

const MCP_SERVERS: &[&str] = &["mcpServers"];
const OPENCODE_SERVERS: &[&str] = &["mcp", "servers"];

fn json(path: PathBuf, shape: Shape) -> FilePlan {
    FilePlan::Json {
        path,
        format: McpConfigFormat::Json,
        container: MCP_SERVERS,
        shape,
    }
}

fn jsonc(path: PathBuf, container: &'static [&'static str], shape: Shape) -> FilePlan {
    FilePlan::Json {
        path,
        format: McpConfigFormat::Jsonc,
        container,
        shape,
    }
}

struct Context<'a> {
    workspace: &'a Path,
    env: &'a McpEnvironment,
    command: &'a str,
    args: &'a [String],
}

impl Context<'_> {
    fn home(&self) -> Result<PathBuf, McpInstallError> {
        self.env.home.clone().ok_or(McpInstallError::HomeUnresolved)
    }

    /// `$XDG_CONFIG_HOME` or `~/.config`.
    fn xdg_config(&self) -> Result<PathBuf, McpInstallError> {
        match &self.env.xdg_config_home {
            Some(path) => Ok(path.clone()),
            None => Ok(self.home()?.join(".config")),
        }
    }

    fn ws(&self, relative: &str) -> PathBuf {
        relative
            .split('/')
            .fold(self.workspace.to_path_buf(), |path, part| path.join(part))
    }

    fn under(&self, base: PathBuf, relative: &str) -> PathBuf {
        relative.split('/').fold(base, |path, part| path.join(part))
    }
}

fn manual_for(plan: &FilePlan, ctx: &Context<'_>) -> Box<McpManualStep> {
    let (snippet, instructions) = match plan {
        FilePlan::Json {
            container, shape, ..
        } => {
            let (fresh, _) = json_entry(*shape, ctx.command, ctx.args);
            let snippet = mcp_jsonc::render_new_document(
                container,
                &Render::object(vec![(MCP_SERVER_NAME, fresh)]),
                &mcp_jsonc::Style::default(),
            );
            let location = container
                .iter()
                .map(|key| format!("\"{key}\""))
                .collect::<Vec<_>>()
                .join(" > ");
            (
                snippet,
                format!(
                    "Merge the \"{MCP_SERVER_NAME}\" entry into the {location} object of this file, keeping every other key."
                ),
            )
        }
        FilePlan::Toml { .. } => (
            mcp_toml::render_table(MCP_SERVER_NAME, ctx.command, ctx.args, "\n"),
            format!("Append this [mcp_servers.{MCP_SERVER_NAME}] table to the file."),
        ),
        FilePlan::Yaml { kind, .. } => {
            let entry = yaml_entry(*kind, ctx.command, ctx.args);
            let snippet = if *kind == YamlKind::ContinueBlock {
                continue_document(&entry, "\n")
            } else {
                mcp_yaml::render_block(&entry, "\n")
            };
            (
                snippet,
                format!(
                    "Add the \"{MCP_SERVER_NAME}\" entry under the top-level `{}` key, keeping every other entry.",
                    entry.top_key
                ),
            )
        }
    };
    Box::new(McpManualStep {
        path: plan.path().to_path_buf(),
        format: plan.format(),
        snippet,
        instructions,
    })
}

fn unsupported_target(target: McpTarget, ctx: &Context<'_>) -> McpInstallError {
    let args = ctx.args.join(" ");
    let (hint, manual) = match target {
        McpTarget::Aider => (
            "Aider does not document MCP server support; nothing was written.".to_owned(),
            None,
        ),
        McpTarget::OpenHands => (
            format!(
                "OpenHands has no MCP configuration file; add a stdio server in the UI under Settings > MCP (or pass `mcp_config` to the SDK) with command `{}` and arguments `{args}`.",
                ctx.command
            ),
            None,
        ),
        McpTarget::Replit => (
            "Replit Agent only accepts remote HTTPS MCP servers (Settings > Integrations > Add personal MCP server); a local stdio server cannot be registered.".to_owned(),
            None,
        ),
        McpTarget::Cody => {
            let snippet = format!(
                "{}\n",
                serde_json::to_string_pretty(&json!({
                    "cody.mcpServers": {
                        MCP_SERVER_NAME: { "command": ctx.command, "args": ctx.args }
                    }
                }))
                .unwrap_or_default()
            );
            (
                "Cody reads MCP servers from the `cody.mcpServers` editor setting (VS Code settings.json or JetBrains cody_settings.json, absolute command path) and requires the agentic-context-mcp-enabled feature flag; Sentra does not edit editor settings.".to_owned(),
                Some(Box::new(McpManualStep {
                    path: PathBuf::from("settings.json"),
                    format: McpConfigFormat::Jsonc,
                    snippet,
                    instructions: "Add this to your editor's Cody settings.".to_owned(),
                })),
            )
        }
        _ => (
            "no MCP configuration file is documented".to_owned(),
            None,
        ),
    };
    McpInstallError::UnsupportedTarget {
        target,
        hint,
        manual,
    }
}

fn unsupported_scope(
    target: McpTarget,
    scope: McpScope,
    hint: &str,
    manual: Option<Box<McpManualStep>>,
) -> McpInstallError {
    McpInstallError::UnsupportedScope {
        target,
        scope,
        hint: hint.to_owned(),
        manual,
    }
}

/// Picks an existing OpenCode config (`.jsonc` or `.json`) or the default.
fn opencode_file(
    directory: &Path,
    fallback_dir: Option<&Path>,
    ctx: &Context<'_>,
) -> Result<PathBuf, McpInstallError> {
    let mut search = vec![directory.to_path_buf()];
    if let Some(dir) = fallback_dir {
        search.push(dir.to_path_buf());
    }
    for dir in &search {
        let jsonc = dir.join("opencode.jsonc");
        let json = dir.join("opencode.json");
        match (jsonc.exists(), json.exists()) {
            (true, true) => {
                let plan = FilePlan::Json {
                    path: jsonc.clone(),
                    format: McpConfigFormat::Jsonc,
                    container: OPENCODE_SERVERS,
                    shape: Shape::OpenCode,
                };
                return Err(McpInstallError::ManualStepRequired {
                    path: jsonc.clone(),
                    reason: format!(
                        "both {} and {} exist; add the entry to the one OpenCode uses",
                        display_path(&jsonc),
                        display_path(&json)
                    ),
                    manual: manual_for(&plan, ctx),
                });
            }
            (true, false) => return Ok(jsonc),
            (false, true) => return Ok(json),
            (false, false) => {}
        }
    }
    Ok(directory.join("opencode.jsonc"))
}

/// Devin's user configuration directory (Devin CLI and Devin Desktop / Windsurf
/// Cascade): `%APPDATA%\devin` on Windows, otherwise `$XDG_CONFIG_HOME/devin`
/// when set, else `~/.config/devin`
/// (<https://docs.devin.ai/windsurf/plugins/cascade/mcp>).
fn devin_config_dir(ctx: &Context<'_>) -> Result<PathBuf, McpInstallError> {
    if ctx.env.os == McpHostOs::Windows {
        return Ok(match &ctx.env.appdata {
            Some(dir) => dir.join("devin"),
            None => ctx.under(ctx.home()?, "AppData/Roaming/devin"),
        });
    }
    Ok(ctx.xdg_config()?.join("devin"))
}

fn plan(
    target: McpTarget,
    scope: McpScope,
    ctx: &Context<'_>,
) -> Result<Vec<FilePlan>, McpInstallError> {
    use McpScope::{Global, Workspace};
    use McpTarget as T;

    let plans = match (target, scope) {
        (T::Aider | T::OpenHands | T::Replit | T::Cody, _) => {
            return Err(unsupported_target(target, ctx));
        }

        (T::Claude, Workspace) => vec![json(ctx.ws(".mcp.json"), Shape::Command)],
        (T::Claude, Global) => {
            let base = match &ctx.env.claude_config_dir {
                Some(dir) => dir.clone(),
                None => ctx.home()?,
            };
            vec![json(base.join(".claude.json"), Shape::Command)]
        }

        (T::Antigravity, Workspace) => {
            vec![json(ctx.ws(".agents/mcp_config.json"), Shape::Command)]
        }
        (T::Antigravity, Global) => vec![json(
            ctx.under(ctx.home()?, ".gemini/config/mcp_config.json"),
            Shape::Command,
        )],

        (T::Copilot, Workspace) => vec![
            json(ctx.ws(".github/mcp.json"), Shape::CopilotCli),
            jsonc(
                ctx.ws(".vscode/mcp.json"),
                &["servers"],
                Shape::Typed("stdio"),
            ),
        ],
        (T::Copilot, Global) => {
            let base = match &ctx.env.copilot_home {
                Some(dir) => dir.clone(),
                None => ctx.home()?.join(".copilot"),
            };
            vec![json(base.join("mcp-config.json"), Shape::CopilotCli)]
        }

        (T::Cursor, Workspace) => vec![json(ctx.ws(".cursor/mcp.json"), Shape::Command)],
        (T::Cursor, Global) => vec![json(
            ctx.under(ctx.home()?, ".cursor/mcp.json"),
            Shape::Command,
        )],

        // Windsurf is now Devin Desktop: Cascade reads the Cortex-managed
        // `devin/mcp_config.json`. `~/.codeium/windsurf/mcp_config.json` is only
        // read by the editor's opt-in MCP discovery, so Sentra does not write it.
        (T::Windsurf | T::Devin, Workspace) => {
            vec![json(ctx.ws(".devin/mcp_config.json"), Shape::Command)]
        }
        (T::Windsurf | T::Devin, Global) => vec![json(
            devin_config_dir(ctx)?.join("mcp_config.json"),
            Shape::Command,
        )],

        (T::Cline, Workspace) => {
            return Err(unsupported_scope(
                target,
                scope,
                "Cline has no project-level MCP file; use --global (Cline CLI settings) or the Cline panel's Configure MCP Servers.",
                None,
            ));
        }
        (T::Cline, Global) => {
            let path = if let Some(path) = &ctx.env.cline_mcp_settings_path {
                path.clone()
            } else {
                let data = match (&ctx.env.cline_data_dir, &ctx.env.cline_dir) {
                    (Some(data), _) => data.clone(),
                    (None, Some(dir)) => dir.join("data"),
                    (None, None) => ctx.home()?.join(".cline").join("data"),
                };
                data.join("settings").join("cline_mcp_settings.json")
            };
            vec![json(path, Shape::Command)]
        }

        (T::Roo, Workspace) => vec![json(ctx.ws(".roo/mcp.json"), Shape::Command)],
        (T::Roo, Global) => {
            return Err(unsupported_scope(
                target,
                scope,
                "Roo Code keeps global MCP servers in VS Code extension storage, edited from the Roo MCP panel (Edit Global MCP); use workspace scope (.roo/mcp.json) instead.",
                None,
            ));
        }

        (T::Continue, Workspace) => vec![FilePlan::Yaml {
            path: ctx.ws(".continue/mcpServers/sentra.yaml"),
            kind: YamlKind::ContinueBlock,
        }],
        (T::Continue, Global) => {
            let path = ctx.under(ctx.home()?, ".continue/config.yaml");
            let entry = yaml_entry(YamlKind::ContinueBlock, ctx.command, ctx.args);
            let manual = McpManualStep {
                path: path.clone(),
                format: McpConfigFormat::Yaml,
                snippet: mcp_yaml::render_block(&entry, "\n"),
                instructions: "Add this item to the `mcpServers` list of your Continue config.yaml (Continue only reads .continue/mcpServers block files inside a workspace).".to_owned(),
            };
            return Err(unsupported_scope(
                target,
                scope,
                "Continue reads MCP block files only from a workspace's .continue/mcpServers/ folder, and Sentra does not rewrite the user-level config.yaml; add the snippet by hand or use workspace scope.",
                Some(Box::new(manual)),
            ));
        }

        (T::Goose, Workspace) => {
            return Err(unsupported_scope(
                target,
                scope,
                "Goose reads extensions only from the user config.yaml; use --global.",
                None,
            ));
        }
        (T::Goose, Global) => {
            let path = if ctx.env.os == McpHostOs::Windows {
                let appdata = match &ctx.env.appdata {
                    Some(dir) => dir.clone(),
                    None => ctx.home()?.join("AppData").join("Roaming"),
                };
                ctx.under(appdata, "Block/goose/config/config.yaml")
            } else {
                ctx.under(ctx.xdg_config()?, "goose/config.yaml")
            };
            vec![FilePlan::Yaml {
                path,
                kind: YamlKind::Goose,
            }]
        }

        (T::Tabnine, Workspace) => vec![json(ctx.ws(".tabnine/mcp_servers.json"), Shape::Command)],
        (T::Tabnine, Global) => vec![json(
            ctx.under(ctx.home()?, ".tabnine/mcp_servers.json"),
            Shape::Command,
        )],

        (T::Junie, Workspace) => vec![json(ctx.ws(".junie/mcp/mcp.json"), Shape::Command)],
        (T::Junie, Global) => vec![json(
            ctx.under(ctx.home()?, ".junie/mcp/mcp.json"),
            Shape::Command,
        )],

        (T::Warp, Workspace) => vec![json(ctx.ws(".warp/.mcp.json"), Shape::Command)],
        (T::Warp, Global) => vec![json(
            ctx.under(ctx.home()?, ".warp/.mcp.json"),
            Shape::Command,
        )],

        (T::Droid, Workspace) => vec![json(ctx.ws(".factory/mcp.json"), Shape::Command)],
        (T::Droid, Global) => vec![json(
            ctx.under(ctx.home()?, ".factory/mcp.json"),
            Shape::Command,
        )],

        (T::Kiro, Workspace) => vec![json(ctx.ws(".kiro/settings/mcp.json"), Shape::Command)],
        (T::Kiro, Global) => vec![json(
            ctx.under(ctx.home()?, ".kiro/settings/mcp.json"),
            Shape::Command,
        )],

        (T::Codex, Workspace) => vec![FilePlan::Toml {
            path: ctx.ws(".codex/config.toml"),
        }],
        (T::Codex, Global) => {
            let base = match &ctx.env.codex_home {
                Some(dir) => dir.clone(),
                None => ctx.home()?.join(".codex"),
            };
            vec![FilePlan::Toml {
                path: base.join("config.toml"),
            }]
        }

        (T::Zed, Workspace) => vec![jsonc(
            ctx.ws(".zed/settings.json"),
            &["context_servers"],
            Shape::Zed,
        )],
        (T::Zed, Global) => {
            let base = match ctx.env.os {
                McpHostOs::Windows => match &ctx.env.appdata {
                    Some(dir) => dir.join("Zed"),
                    None => ctx.under(ctx.home()?, "AppData/Roaming/Zed"),
                },
                McpHostOs::MacOs => ctx.under(ctx.home()?, ".config/zed"),
                McpHostOs::Linux => ctx.xdg_config()?.join("zed"),
            };
            vec![jsonc(
                base.join("settings.json"),
                &["context_servers"],
                Shape::Zed,
            )]
        }

        (T::AmazonQ, Workspace) => vec![json(ctx.ws(".amazonq/mcp.json"), Shape::Command)],
        (T::AmazonQ, Global) => vec![json(
            ctx.under(ctx.home()?, ".aws/amazonq/mcp.json"),
            Shape::Command,
        )],

        (T::OpenCode, Workspace) => {
            let path = opencode_file(ctx.workspace, Some(&ctx.workspace.join(".opencode")), ctx)?;
            vec![jsonc(path, OPENCODE_SERVERS, Shape::OpenCode)]
        }
        (T::OpenCode, Global) => {
            let path = opencode_file(&ctx.xdg_config()?.join("opencode"), None, ctx)?;
            vec![jsonc(path, OPENCODE_SERVERS, Shape::OpenCode)]
        }

        (T::Trae, Workspace) => vec![json(ctx.ws(".trae/mcp.json"), Shape::Command)],
        (T::Trae, Global) => {
            return Err(unsupported_scope(
                target,
                scope,
                "Trae manages user-level MCP servers in the IDE (Settings > MCP); use workspace scope (.trae/mcp.json, with 'Enable Project MCP' turned on).",
                None,
            ));
        }

        (T::Kimi, Workspace) => vec![json(ctx.ws(".kimi-code/mcp.json"), Shape::Command)],
        (T::Kimi, Global) => {
            let base = match &ctx.env.kimi_code_home {
                Some(dir) => dir.clone(),
                None => ctx.home()?.join(".kimi-code"),
            };
            vec![json(base.join("mcp.json"), Shape::Command)]
        }

        (T::Qwen, Workspace) => vec![jsonc(
            ctx.ws(".qwen/settings.json"),
            MCP_SERVERS,
            Shape::Command,
        )],
        (T::Qwen, Global) => vec![jsonc(
            ctx.under(ctx.home()?, ".qwen/settings.json"),
            MCP_SERVERS,
            Shape::Command,
        )],

        (T::Hermes, Workspace) => {
            return Err(unsupported_scope(
                target,
                scope,
                "Hermes reads MCP servers only from ~/.hermes/config.yaml; use --global.",
                None,
            ));
        }
        (T::Hermes, Global) => vec![FilePlan::Yaml {
            path: ctx.under(ctx.home()?, ".hermes/config.yaml"),
            kind: YamlKind::Hermes,
        }],

        (T::Augment, Workspace) => vec![jsonc(
            ctx.ws(".augment/settings.json"),
            MCP_SERVERS,
            Shape::Command,
        )],
        (T::Augment, Global) => vec![jsonc(
            ctx.under(ctx.home()?, ".augment/settings.json"),
            MCP_SERVERS,
            Shape::Command,
        )],

        (T::Amp, Workspace) => vec![jsonc(
            ctx.ws(".amp/settings.json"),
            &["amp.mcpServers"],
            Shape::Command,
        )],
        (T::Amp, Global) => vec![jsonc(
            ctx.under(ctx.home()?, ".config/amp/settings.json"),
            &["amp.mcpServers"],
            Shape::Command,
        )],
    };
    Ok(plans)
}

// ---------------------------------------------------------------------------
// Entry rendering
// ---------------------------------------------------------------------------

/// Returns the fresh entry and the members managed on re-runs.
fn json_entry(shape: Shape, command: &str, args: &[String]) -> (Render, Vec<Managed>) {
    let command_value = Render::Json(json!(command));
    let args_value = Render::Json(json!(args));
    let standard = vec![
        Managed {
            key: "command".to_owned(),
            value: command_value.clone(),
            legacy_object_keys: &[],
        },
        Managed {
            key: "args".to_owned(),
            value: args_value.clone(),
            legacy_object_keys: &[],
        },
    ];
    match shape {
        Shape::Command => (
            Render::object(vec![("command", command_value), ("args", args_value)]),
            standard,
        ),
        Shape::Typed(kind) => (
            Render::object(vec![
                ("type", Render::Json(json!(kind))),
                ("command", command_value),
                ("args", args_value),
            ]),
            standard,
        ),
        Shape::CopilotCli => (
            Render::object(vec![
                ("type", Render::Json(json!("local"))),
                ("command", command_value),
                ("args", args_value),
                ("tools", Render::Json(json!(["*"]))),
            ]),
            standard,
        ),
        Shape::Zed => (
            Render::object(vec![
                ("command", command_value.clone()),
                ("args", args_value.clone()),
                ("env", Render::Json(json!({}))),
            ]),
            vec![
                Managed {
                    key: "command".to_owned(),
                    value: command_value,
                    // Pre-2025-06-27 Zed shape: "command": {"path", "args"}.
                    legacy_object_keys: &["path", "args"],
                },
                Managed {
                    key: "args".to_owned(),
                    value: args_value,
                    legacy_object_keys: &[],
                },
            ],
        ),
        Shape::OpenCode => {
            let mut full = vec![command.to_owned()];
            full.extend(args.iter().cloned());
            let command_array = Render::Json(json!(full));
            (
                Render::object(vec![
                    ("type", Render::Json(json!("local"))),
                    ("command", command_array.clone()),
                ]),
                vec![Managed {
                    key: "command".to_owned(),
                    value: command_array,
                    legacy_object_keys: &[],
                }],
            )
        }
    }
}

fn yaml_entry<'a>(kind: YamlKind, command: &str, args: &[String]) -> mcp_yaml::Entry<'a> {
    let args = YamlValue::Seq(args.to_vec());
    let command = YamlValue::Str(command.to_owned());
    match kind {
        YamlKind::Goose => mcp_yaml::Entry {
            top_key: "extensions",
            locate: Locate::MapKey(MCP_SERVER_NAME),
            fresh: vec![
                ("type", YamlValue::Raw("stdio")),
                ("name", YamlValue::Str(MCP_SERVER_NAME.to_owned())),
                ("enabled", YamlValue::Raw("true")),
                ("cmd", command.clone()),
                ("args", args.clone()),
                ("env_keys", YamlValue::Raw("[]")),
                ("envs", YamlValue::Raw("{}")),
                ("timeout", YamlValue::Raw("300")),
            ],
            managed: vec![("cmd", command), ("args", args)],
        },
        YamlKind::Hermes => mcp_yaml::Entry {
            top_key: "mcp_servers",
            locate: Locate::MapKey(MCP_SERVER_NAME),
            fresh: vec![("command", command.clone()), ("args", args.clone())],
            managed: vec![("command", command), ("args", args)],
        },
        YamlKind::ContinueBlock => mcp_yaml::Entry {
            top_key: "mcpServers",
            locate: Locate::SeqItemByName(MCP_SERVER_NAME),
            fresh: vec![
                ("name", YamlValue::Str(MCP_SERVER_NAME.to_owned())),
                ("type", YamlValue::Raw("stdio")),
                ("command", command.clone()),
                ("args", args.clone()),
            ],
            managed: vec![("command", command), ("args", args)],
        },
    }
}

/// A complete Continue block file.
fn continue_document(entry: &mcp_yaml::Entry<'_>, eol: &str) -> String {
    format!(
        "name: Sentra{eol}version: 0.0.1{eol}schema: v1{eol}{}",
        mcp_yaml::render_block(entry, eol)
    )
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/// Resolves the executable to register: the override when given, otherwise
/// the canonical path of the running binary (without a Windows `\\?\` prefix).
pub fn resolve_server_command(override_path: Option<&Path>) -> Result<String, McpInstallError> {
    let path = match override_path {
        Some(path) if path.as_os_str().is_empty() => {
            return Err(McpInstallError::CommandUnresolved {
                detail: "the command override is empty".to_owned(),
            });
        }
        Some(path) => {
            let bare_name = path.components().count() == 1 && !path.is_absolute();
            if bare_name || path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(|error| McpInstallError::CommandUnresolved {
                        detail: error.to_string(),
                    })?
                    .join(path)
            }
        }
        None => {
            let exe =
                std::env::current_exe().map_err(|error| McpInstallError::CommandUnresolved {
                    detail: error.to_string(),
                })?;
            mcp_fs::simplify_path(std::fs::canonicalize(&exe).unwrap_or(exe))
        }
    };
    path.into_os_string()
        .into_string()
        .map_err(|_| McpInstallError::CommandUnresolved {
            detail: "the executable path is not valid Unicode".to_owned(),
        })
}

struct Prepared {
    loaded: Loaded,
    format: McpConfigFormat,
    new_text: Option<String>,
}

fn load_error(error: LoadError, plan: &FilePlan, ctx: &Context<'_>) -> McpInstallError {
    let path = plan.path().to_path_buf();
    let manual = manual_for(plan, ctx);
    match error {
        LoadError::Utf16 => McpInstallError::ConfigUnsupportedEncoding {
            path,
            encoding: "UTF-16".to_owned(),
            manual,
        },
        LoadError::InvalidUtf8 => McpInstallError::ConfigUnsupportedEncoding {
            path,
            encoding: "not valid UTF-8".to_owned(),
            manual,
        },
        LoadError::NulBytes => McpInstallError::ConfigUnsupportedEncoding {
            path,
            encoding: "binary or UTF-16 without a byte-order mark (contains NUL bytes)".to_owned(),
            manual,
        },
        LoadError::NotAFile => McpInstallError::ConfigUnexpectedShape {
            path,
            detail: "the path exists but is not a regular file".to_owned(),
            manual,
        },
        LoadError::Io(source) => McpInstallError::Io {
            path,
            operation: "read".to_owned(),
            kind: source.kind(),
            detail: source.to_string(),
            manual: Some(manual),
        },
    }
}

fn prepare(plan: &FilePlan, ctx: &Context<'_>) -> Result<Prepared, McpInstallError> {
    let loaded = mcp_fs::load(plan.path()).map_err(|error| load_error(error, plan, ctx))?;
    let new_text = match plan {
        FilePlan::Json {
            container, shape, ..
        } => {
            if *shape == Shape::OpenCode {
                check_opencode_layout(&loaded.text, plan, ctx)?;
            }
            let (fresh, managed) = json_entry(*shape, ctx.command, ctx.args);
            let upsert = Upsert {
                container_path: container,
                entry_name: MCP_SERVER_NAME,
                fresh,
                managed,
            };
            mcp_jsonc::upsert(&loaded.text, &upsert).map_err(|error| match error {
                EditError::Syntax(syntax) => McpInstallError::ConfigUnparseable {
                    path: plan.path().to_path_buf(),
                    detail: syntax.to_string(),
                    manual: manual_for(plan, ctx),
                },
                EditError::Shape(detail) => McpInstallError::ConfigUnexpectedShape {
                    path: plan.path().to_path_buf(),
                    detail,
                    manual: manual_for(plan, ctx),
                },
            })?
        }
        FilePlan::Toml { .. } => {
            mcp_toml::upsert_server(&loaded.text, MCP_SERVER_NAME, ctx.command, ctx.args).map_err(
                |refusal| McpInstallError::ManualStepRequired {
                    path: plan.path().to_path_buf(),
                    reason: refusal.0,
                    manual: manual_for(plan, ctx),
                },
            )?
        }
        FilePlan::Yaml { kind, .. } => {
            let entry = yaml_entry(*kind, ctx.command, ctx.args);
            if loaded.original.is_none() && *kind == YamlKind::ContinueBlock {
                Some(continue_document(&entry, "\n"))
            } else {
                mcp_yaml::upsert(&loaded.text, &entry).map_err(|refusal| {
                    McpInstallError::ManualStepRequired {
                        path: plan.path().to_path_buf(),
                        reason: refusal.0,
                        manual: manual_for(plan, ctx),
                    }
                })?
            }
        }
    };
    Ok(Prepared {
        loaded,
        format: plan.format(),
        new_text,
    })
}

/// OpenCode V1 placed servers directly under `mcp`; adding `mcp.servers` to
/// such a file would be read as a server named "servers".
fn check_opencode_layout(
    text: &str,
    plan: &FilePlan,
    ctx: &Context<'_>,
) -> Result<(), McpInstallError> {
    let Ok(Some(root)) = mcp_jsonc::parse(text) else {
        return Ok(()); // syntax errors are reported by the editor
    };
    let Some(mcp_jsonc::Node {
        kind: mcp_jsonc::Kind::Object(members),
        ..
    }) = mcp_jsonc::lookup(&root, &["mcp"])
    else {
        return Ok(());
    };
    let legacy = members.iter().any(|member| {
        member.key != "servers"
            && matches!(&member.value.kind, mcp_jsonc::Kind::Object(inner)
                if inner.iter().any(|field| field.key == "type"))
    });
    if legacy {
        return Err(McpInstallError::ConfigUnexpectedShape {
            path: plan.path().to_path_buf(),
            detail: "servers are declared directly under \"mcp\" (OpenCode V1 layout); migrate them to \"mcp.servers\" or add the entry by hand".to_owned(),
            manual: manual_for(plan, ctx),
        });
    }
    Ok(())
}

fn commit_error(error: CommitError, plan: &FilePlan, ctx: &Context<'_>) -> McpInstallError {
    let manual = Some(manual_for(plan, ctx));
    match error {
        CommitError::Concurrent => McpInstallError::Io {
            path: plan.path().to_path_buf(),
            operation: "update (the file kept changing while Sentra edited it)".to_owned(),
            kind: io::ErrorKind::Other,
            detail: "concurrent modification".to_owned(),
            manual,
        },
        CommitError::ReadOnly => McpInstallError::Io {
            path: plan.path().to_path_buf(),
            operation: "write".to_owned(),
            kind: io::ErrorKind::PermissionDenied,
            detail: "the file is read-only".to_owned(),
            manual,
        },
        CommitError::Io {
            operation,
            path,
            source,
        } => McpInstallError::Io {
            path,
            operation: operation.to_owned(),
            kind: source.kind(),
            detail: source.to_string(),
            manual,
        },
    }
}

fn commit(
    plan: &FilePlan,
    ctx: &Context<'_>,
    mut prepared: Prepared,
) -> Result<McpFileChange, McpInstallError> {
    for attempt in 0..MAX_ATTEMPTS {
        let Some(text) = prepared.new_text.as_deref() else {
            return Ok(McpFileChange {
                path: prepared.loaded.requested.clone(),
                format: prepared.format,
                action: McpFileAction::Unchanged,
                backup_file: None,
            });
        };
        match mcp_fs::commit(&prepared.loaded, text) {
            Ok(written) => {
                let (action, backup_file) = match written {
                    Written::Created => (McpFileAction::Created, None),
                    Written::Updated { backup } => (McpFileAction::Updated, Some(backup)),
                    Written::Unchanged => (McpFileAction::Unchanged, None),
                };
                return Ok(McpFileChange {
                    path: prepared.loaded.requested.clone(),
                    format: prepared.format,
                    action,
                    backup_file,
                });
            }
            Err(CommitError::Concurrent) if attempt + 1 < MAX_ATTEMPTS => {
                prepared = prepare(plan, ctx)?;
            }
            Err(error) => return Err(commit_error(error, plan, ctx)),
        }
    }
    Err(commit_error(CommitError::Concurrent, plan, ctx))
}

/// Registers Sentra's MCP server for one target.
///
/// Every file of the target is parsed and edited in memory first; nothing is
/// written unless all of them can be updated losslessly.
pub fn install_mcp_server(
    target: McpTarget,
    options: &McpInstallOptions,
) -> Result<McpInstallReport, McpInstallError> {
    let command = resolve_server_command(options.command.as_deref())?;
    let args: Vec<String> = MCP_SERVER_ARGS
        .iter()
        .map(|arg| (*arg).to_owned())
        .collect();
    let ctx = Context {
        workspace: &options.workspace,
        env: &options.environment,
        command: &command,
        args: &args,
    };
    let plans = plan(target, options.scope, &ctx)?;
    let prepared = plans
        .iter()
        .map(|plan| prepare(plan, &ctx))
        .collect::<Result<Vec<_>, _>>()?;
    let mut files = Vec::with_capacity(plans.len());
    for (plan, prepared) in plans.iter().zip(prepared) {
        files.push(commit(plan, &ctx, prepared)?);
    }
    let primary = files[0].clone();
    Ok(McpInstallReport {
        target: target.as_str().to_owned(),
        is_global: options.scope == McpScope::Global,
        scope: options.scope,
        config_file: primary.path,
        created_new_file: primary.action == McpFileAction::Created,
        action: primary.action,
        backup_file: primary.backup_file,
        server_name: MCP_SERVER_NAME.to_owned(),
        command,
        args,
        files,
    })
}

/// Registers Sentra for every target that supports the scope.
pub fn install_mcp_server_all(options: &McpInstallOptions) -> McpBatchReport {
    let mut report = McpBatchReport {
        scope: options.scope,
        installed: Vec::new(),
        skipped: Vec::new(),
        failed: Vec::new(),
    };
    for target in McpTarget::ALL {
        match install_mcp_server(target, options) {
            Ok(installed) => report.installed.push(installed),
            Err(error) if error.is_skip() => {
                report.skipped.push(McpTargetIssue { target, error });
            }
            Err(error) => report.failed.push(McpTargetIssue { target, error }),
        }
    }
    report
}

/// Configuration files Sentra writes for `target` in the given scope.
pub fn mcp_config_paths(
    target: McpTarget,
    options: &McpInstallOptions,
) -> Result<Vec<PathBuf>, McpInstallError> {
    let command = options.command.as_deref().map_or_else(
        || MCP_SERVER_NAME.to_owned(),
        |path| path.display().to_string(),
    );
    let args: Vec<String> = MCP_SERVER_ARGS
        .iter()
        .map(|arg| (*arg).to_owned())
        .collect();
    let ctx = Context {
        workspace: &options.workspace,
        env: &options.environment,
        command: &command,
        args: &args,
    };
    Ok(plan(target, options.scope, &ctx)?
        .iter()
        .map(|plan| plan.path().to_path_buf())
        .collect())
}

/// Resolves the primary MCP configuration file for a skill-installer target
/// using the process environment.
///
/// Compatibility wrapper around [`mcp_config_paths`].
pub fn resolve_mcp_config_path(
    target: AgentTarget,
    global: bool,
    workspace: &Path,
) -> Result<PathBuf, McpInstallError> {
    let target = McpTarget::from_agent_target(target).ok_or(McpInstallError::InvalidTarget {
        target: target.as_str().to_owned(),
    })?;
    let options = McpInstallOptions::new(McpScope::from_global(global), workspace);
    mcp_config_paths(target, &options)?
        .into_iter()
        .next()
        .ok_or(McpInstallError::InvalidTarget {
            target: target.as_str().to_owned(),
        })
}

/// Configures Sentra's stdio MCP server for a skill-installer target using
/// the process environment and the running executable.
///
/// Compatibility wrapper: for [`AgentTarget::All`] it runs
/// [`install_mcp_server_all`] and returns the first failure, or the last
/// successful report. New callers should use [`install_mcp_server`] /
/// [`install_mcp_server_all`] directly.
pub fn configure_agent_mcp(
    target: AgentTarget,
    global: bool,
    workspace: &Path,
) -> Result<McpInstallReport, McpInstallError> {
    let options = McpInstallOptions::new(McpScope::from_global(global), workspace);
    match McpTarget::from_agent_target(target) {
        Some(target) => install_mcp_server(target, &options),
        None => {
            let mut batch = install_mcp_server_all(&options);
            if !batch.failed.is_empty() {
                return Err(batch.failed.remove(0).error);
            }
            batch.installed.pop().ok_or(McpInstallError::InvalidTarget {
                target: target.as_str().to_owned(),
            })
        }
    }
}
