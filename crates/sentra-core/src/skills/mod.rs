//! Zero-dependency embedded AppSec Skill Catalog and Cross-Platform Agent Installer (REQ-F17, EXTENSIONS.md).
//!
//! Exposes built-in AppSec skills and automated installation to Claude, Antigravity,
//! Cursor, Windsurf, Cline, Roo, Continue, Aider, Amazon Q, Cody, Devin, Codex,
//! Copilot, Zed, OpenCode, Trae, Kimi, and Augment environments.

pub mod catalog;
pub mod installer;

pub use catalog::{
    BUILTIN_SKILLS, SkillCategory, SkillDefinition, find_skill_by_id, list_builtin_skills,
    search_skills,
};
pub use installer::{
    AgentTarget, InstallReport, install_all_skills, install_selected_skills, install_single_skill,
};
