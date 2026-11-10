//! Zero-dependency embedded AppSec Skill Catalog and Cross-Platform Agent Installer (REQ-F17, EXTENSIONS.md).
//!
//! Exposes built-in AppSec skills and automated cross-agent installation across
//! 28 AI coding environments including Claude, Antigravity, GitHub Copilot,
//! Cursor, Windsurf, Cline, Roo, Continue, Aider, OpenHands, Goose, Devin, and more.

pub mod catalog;
pub mod installer;
pub mod mcp_config;

pub use catalog::{
    BUILTIN_SKILLS, SkillCategory, SkillDefinition, find_skill_by_id, list_builtin_skills,
    search_skills,
};
pub use installer::{
    AgentTarget, InstallReport, install_all_skills, install_selected_skills, install_single_skill,
};
pub use mcp_config::{McpInstallReport, configure_agent_mcp, resolve_mcp_config_path};
