//! Zero-dependency embedded AppSec Skill Catalog and Cross-Platform Agent Installer (REQ-F17, EXTENSIONS.md).
//!
//! Exposes the bundled third-party AppSec skills, the skill installer (29 agent
//! targets, of which Cody is rejected as unsupported and some are limited to one
//! scope; see [`installer::AgentTarget`]) and MCP server registration (29 targets,
//! of which four have no file-based stdio MCP configuration; see
//! [`mcp_config::McpTarget`]).

pub mod catalog;
mod install_aider;
mod install_fs;
pub(crate) mod install_text;
pub mod installer;
pub mod mcp_config;
mod mcp_fs;
mod mcp_jsonc;
mod mcp_toml;
mod mcp_yaml;

pub use catalog::{
    BUILTIN_SKILLS, SkillCategory, SkillDefinition, find_skill_by_id, list_builtin_skills,
    search_skills, skill_files, skill_folder_hash,
};
pub use installer::{
    AgentTarget, FileStatus, HostDirs, InstallError, InstallReport, InstalledFile, LegacyAction,
    LegacyCleanup, SKILL_BACKUP_DIR, SkillDelivery, SkillLocation, TargetOutcome,
    install_all_skills, install_selected_skills, install_single_skill, install_skills_in,
    resolve_skill_ids,
};
pub use mcp_config::{
    MCP_SERVER_NAME, McpBatchReport, McpConfigFormat, McpEnvironment, McpFileAction, McpFileChange,
    McpHostOs, McpInstallError, McpInstallOptions, McpManualStep, McpScope, McpTarget,
    McpTargetIssue, install_mcp_server, install_mcp_server_all, mcp_config_paths,
    resolve_server_command,
};
pub use mcp_config::{McpInstallReport, configure_agent_mcp, resolve_mcp_config_path};
