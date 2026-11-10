//! Automated MCP (Model Context Protocol) Server Configuration for Agents (REQ-F17, EXTENSIONS.md).
//!
//! Automatically installs and configures Sentra's stdio MCP server (`sentra mcp`)
//! into agent configuration files (Claude, Cursor, Antigravity, Windsurf, Cline,
//! Roo, Zed, Continue, Copilot, etc.) in workspace or global scope with non-destructive JSON merging.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::skills::installer::AgentTarget;

/// Report of an automated MCP server installation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpInstallReport {
    /// Agent or editor environment configured.
    pub target: String,
    /// Whether configured in global user scope.
    pub is_global: bool,
    /// Path to the updated or created configuration file.
    pub config_file: PathBuf,
    /// Whether a new file was created (vs merged into existing).
    pub created_new_file: bool,
    /// Name of the configured MCP server entry (`sentra`).
    pub server_name: String,
}

/// Gets the user's home directory.
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

/// Resolves the canonical MCP configuration file path for a target agent.
pub fn resolve_mcp_config_path(target: AgentTarget, global: bool, workspace: &Path) -> PathBuf {
    let base = if global {
        get_user_home_dir()
    } else {
        workspace.to_path_buf()
    };

    match target {
        AgentTarget::Claude => base.join(".claude").join("mcp.json"),
        AgentTarget::Antigravity => {
            if global {
                base.join(".gemini")
                    .join("antigravity-cli")
                    .join("mcp.json")
            } else {
                base.join(".agents").join("mcp.json")
            }
        }
        AgentTarget::Cursor => base.join(".cursor").join("mcp.json"),
        AgentTarget::Windsurf => {
            if global {
                base.join(".codeium")
                    .join("windsurf")
                    .join("mcp_config.json")
            } else {
                base.join(".windsurf").join("mcp.json")
            }
        }
        AgentTarget::Cline => base.join(".cline").join("mcp_settings.json"),
        AgentTarget::Roo => base.join(".roo").join("mcp.json"),
        AgentTarget::Zed => {
            if global {
                base.join(".config").join("zed").join("settings.json")
            } else {
                base.join(".zed").join("settings.json")
            }
        }
        AgentTarget::ContinueDev => base.join(".continue").join("config.json"),
        AgentTarget::Copilot => {
            if global {
                base.join(".copilot").join("mcp.json")
            } else {
                base.join(".github").join("mcp.json")
            }
        }
        _ => {
            // OpenHands, Goose, Devin, Codex, Aider, and generic agents use standard .agents/mcp.json
            base.join(".agents").join("mcp.json")
        }
    }
}

/// Merges Sentra MCP configuration into a JSON configuration object.
fn merge_sentra_mcp_into_json(target: AgentTarget, root: &mut Value) {
    match target {
        AgentTarget::Zed => {
            // Zed uses "context_servers": { "sentra": { "command": { "path": "sentra", "args": ["mcp"] } } }
            if !root.is_object() {
                *root = json!({});
            }
            let obj = root.as_object_mut().unwrap();
            let context_servers = obj.entry("context_servers").or_insert_with(|| json!({}));
            if !context_servers.is_object() {
                *context_servers = json!({});
            }
            context_servers.as_object_mut().unwrap().insert(
                "sentra".to_string(),
                json!({
                    "command": {
                        "path": "sentra",
                        "args": ["mcp"]
                    }
                }),
            );
        }
        AgentTarget::ContinueDev => {
            // Continue uses "experimental": { "modelContextProtocolServers": [ ... ] }
            if !root.is_object() {
                *root = json!({});
            }
            let obj = root.as_object_mut().unwrap();
            let experimental = obj.entry("experimental").or_insert_with(|| json!({}));
            if !experimental.is_object() {
                *experimental = json!({});
            }
            let exp_obj = experimental.as_object_mut().unwrap();
            let mcp_list = exp_obj
                .entry("modelContextProtocolServers")
                .or_insert_with(|| json!([]));
            if !mcp_list.is_array() {
                *mcp_list = json!([]);
            }
            let arr = mcp_list.as_array_mut().unwrap();
            // Remove existing sentra if present
            arr.retain(|item| {
                item.get("transport")
                    .and_then(|t| t.get("command"))
                    .and_then(|c| c.as_str())
                    != Some("sentra")
            });
            arr.push(json!({
                "transport": {
                    "type": "stdio",
                    "command": "sentra",
                    "args": ["mcp"]
                }
            }));
        }
        _ => {
            // Standard format: "mcpServers": { "sentra": { "command": "sentra", "args": ["mcp"] } }
            if !root.is_object() {
                *root = json!({});
            }
            let obj = root.as_object_mut().unwrap();
            let mcp_servers = obj.entry("mcpServers").or_insert_with(|| json!({}));
            if !mcp_servers.is_object() {
                *mcp_servers = json!({});
            }
            mcp_servers.as_object_mut().unwrap().insert(
                "sentra".to_string(),
                json!({
                    "command": "sentra",
                    "args": ["mcp"]
                }),
            );
        }
    }
}

/// Configures Sentra's stdio MCP server for the target agent environment.
pub fn configure_agent_mcp(
    target: AgentTarget,
    global: bool,
    workspace: &Path,
) -> std::io::Result<McpInstallReport> {
    if target == AgentTarget::All {
        let targets = [
            AgentTarget::Claude,
            AgentTarget::Antigravity,
            AgentTarget::Cursor,
            AgentTarget::Windsurf,
            AgentTarget::Cline,
            AgentTarget::Roo,
            AgentTarget::Zed,
            AgentTarget::ContinueDev,
            AgentTarget::Copilot,
        ];
        let mut last_rep = McpInstallReport {
            target: "all".to_string(),
            is_global: global,
            config_file: workspace.join(".agents").join("mcp.json"),
            created_new_file: false,
            server_name: "sentra".to_string(),
        };
        for t in targets {
            last_rep = configure_agent_mcp(t, global, workspace)?;
        }
        return Ok(last_rep);
    }

    let config_path = resolve_mcp_config_path(target, global, workspace);
    let mut created_new = true;
    let mut root_val = if config_path.exists() {
        if let Ok(content) = fs::read_to_string(&config_path) {
            created_new = false;
            serde_json::from_str(&content).unwrap_or_else(|_| json!({}))
        } else {
            json!({})
        }
    } else {
        json!({})
    };

    merge_sentra_mcp_into_json(target, &mut root_val);

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let formatted = serde_json::to_string_pretty(&root_val)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    fs::write(&config_path, formatted)?;

    Ok(McpInstallReport {
        target: target.as_str().to_string(),
        is_global: global,
        config_file: config_path,
        created_new_file: created_new,
        server_name: "sentra".to_string(),
    })
}
