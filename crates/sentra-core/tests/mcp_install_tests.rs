//! MCP server registration: per-agent paths/formats and data-safety guarantees.
//!
//! Every test works in its own temporary directory with an explicit
//! [`McpEnvironment`]; no test reads or writes the real home directory.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sentra_core::skills::{
    AgentTarget, McpConfigFormat, McpEnvironment, McpFileAction, McpHostOs, McpInstallError,
    McpInstallOptions, McpScope, McpTarget, install_mcp_server, install_mcp_server_all,
    mcp_config_paths,
};
use serde_json::{Value, json};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "sentra-mcp-install-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("ws")).unwrap();
        fs::create_dir_all(root.join("home")).unwrap();
        Self { root }
    }

    fn ws(&self) -> PathBuf {
        self.root.join("ws")
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn command(&self) -> PathBuf {
        self.root.join("bin").join("sentra-bin")
    }

    fn env(&self, os: McpHostOs) -> McpEnvironment {
        let mut env = McpEnvironment::empty(os);
        env.home = Some(self.home());
        if os == McpHostOs::Windows {
            env.appdata = Some(self.home().join("AppData").join("Roaming"));
        }
        env
    }

    fn options(&self, scope: McpScope) -> McpInstallOptions {
        self.options_with(scope, self.env(McpHostOs::Linux))
    }

    fn options_with(&self, scope: McpScope, environment: McpEnvironment) -> McpInstallOptions {
        McpInstallOptions {
            scope,
            workspace: self.ws(),
            command: Some(self.command()),
            environment,
        }
    }

    fn command_str(&self) -> String {
        self.command().to_str().unwrap().to_owned()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn rel(base: &Path, relative: &str) -> PathBuf {
    relative
        .split('/')
        .fold(base.to_path_buf(), |path, part| path.join(part))
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(files_under(&path));
            } else {
                out.push(path);
            }
        }
    }
    out
}

#[test]
fn documented_paths_for_every_file_based_target() {
    let sandbox = Sandbox::new();
    let ws = sandbox.ws();
    let home = sandbox.home();
    let cases: &[(McpTarget, McpScope, PathBuf)] = &[
        (
            McpTarget::Claude,
            McpScope::Workspace,
            rel(&ws, ".mcp.json"),
        ),
        (
            McpTarget::Claude,
            McpScope::Global,
            rel(&home, ".claude.json"),
        ),
        (
            McpTarget::Antigravity,
            McpScope::Workspace,
            rel(&ws, ".agents/mcp_config.json"),
        ),
        (
            McpTarget::Antigravity,
            McpScope::Global,
            rel(&home, ".gemini/config/mcp_config.json"),
        ),
        (
            McpTarget::Copilot,
            McpScope::Global,
            rel(&home, ".copilot/mcp-config.json"),
        ),
        (
            McpTarget::Cursor,
            McpScope::Workspace,
            rel(&ws, ".cursor/mcp.json"),
        ),
        (
            McpTarget::Cursor,
            McpScope::Global,
            rel(&home, ".cursor/mcp.json"),
        ),
        (
            McpTarget::Windsurf,
            McpScope::Workspace,
            rel(&ws, ".devin/mcp_config.json"),
        ),
        (
            McpTarget::Windsurf,
            McpScope::Global,
            rel(&home, ".config/devin/mcp_config.json"),
        ),
        (
            McpTarget::Cline,
            McpScope::Global,
            rel(&home, ".cline/data/settings/cline_mcp_settings.json"),
        ),
        (
            McpTarget::Roo,
            McpScope::Workspace,
            rel(&ws, ".roo/mcp.json"),
        ),
        (
            McpTarget::Continue,
            McpScope::Workspace,
            rel(&ws, ".continue/mcpServers/sentra.yaml"),
        ),
        (
            McpTarget::Goose,
            McpScope::Global,
            rel(&home, ".config/goose/config.yaml"),
        ),
        (
            McpTarget::Tabnine,
            McpScope::Workspace,
            rel(&ws, ".tabnine/mcp_servers.json"),
        ),
        (
            McpTarget::Tabnine,
            McpScope::Global,
            rel(&home, ".tabnine/mcp_servers.json"),
        ),
        (
            McpTarget::Junie,
            McpScope::Workspace,
            rel(&ws, ".junie/mcp/mcp.json"),
        ),
        (
            McpTarget::Junie,
            McpScope::Global,
            rel(&home, ".junie/mcp/mcp.json"),
        ),
        (
            McpTarget::Warp,
            McpScope::Workspace,
            rel(&ws, ".warp/.mcp.json"),
        ),
        (
            McpTarget::Warp,
            McpScope::Global,
            rel(&home, ".warp/.mcp.json"),
        ),
        (
            McpTarget::Droid,
            McpScope::Workspace,
            rel(&ws, ".factory/mcp.json"),
        ),
        (
            McpTarget::Droid,
            McpScope::Global,
            rel(&home, ".factory/mcp.json"),
        ),
        (
            McpTarget::Kiro,
            McpScope::Workspace,
            rel(&ws, ".kiro/settings/mcp.json"),
        ),
        (
            McpTarget::Kiro,
            McpScope::Global,
            rel(&home, ".kiro/settings/mcp.json"),
        ),
        (
            McpTarget::Codex,
            McpScope::Workspace,
            rel(&ws, ".codex/config.toml"),
        ),
        (
            McpTarget::Codex,
            McpScope::Global,
            rel(&home, ".codex/config.toml"),
        ),
        (
            McpTarget::Zed,
            McpScope::Workspace,
            rel(&ws, ".zed/settings.json"),
        ),
        (
            McpTarget::Zed,
            McpScope::Global,
            rel(&home, ".config/zed/settings.json"),
        ),
        (
            McpTarget::AmazonQ,
            McpScope::Workspace,
            rel(&ws, ".amazonq/mcp.json"),
        ),
        (
            McpTarget::AmazonQ,
            McpScope::Global,
            rel(&home, ".aws/amazonq/mcp.json"),
        ),
        (
            McpTarget::Devin,
            McpScope::Workspace,
            rel(&ws, ".devin/mcp_config.json"),
        ),
        (
            McpTarget::Devin,
            McpScope::Global,
            rel(&home, ".config/devin/mcp_config.json"),
        ),
        (
            McpTarget::OpenCode,
            McpScope::Workspace,
            rel(&ws, "opencode.jsonc"),
        ),
        (
            McpTarget::OpenCode,
            McpScope::Global,
            rel(&home, ".config/opencode/opencode.jsonc"),
        ),
        (
            McpTarget::Trae,
            McpScope::Workspace,
            rel(&ws, ".trae/mcp.json"),
        ),
        (
            McpTarget::Kimi,
            McpScope::Workspace,
            rel(&ws, ".kimi-code/mcp.json"),
        ),
        (
            McpTarget::Kimi,
            McpScope::Global,
            rel(&home, ".kimi-code/mcp.json"),
        ),
        (
            McpTarget::Qwen,
            McpScope::Workspace,
            rel(&ws, ".qwen/settings.json"),
        ),
        (
            McpTarget::Qwen,
            McpScope::Global,
            rel(&home, ".qwen/settings.json"),
        ),
        (
            McpTarget::Hermes,
            McpScope::Global,
            rel(&home, ".hermes/config.yaml"),
        ),
        (
            McpTarget::Augment,
            McpScope::Workspace,
            rel(&ws, ".augment/settings.json"),
        ),
        (
            McpTarget::Augment,
            McpScope::Global,
            rel(&home, ".augment/settings.json"),
        ),
        (
            McpTarget::Amp,
            McpScope::Workspace,
            rel(&ws, ".amp/settings.json"),
        ),
        (
            McpTarget::Amp,
            McpScope::Global,
            rel(&home, ".config/amp/settings.json"),
        ),
    ];
    for (target, scope, expected) in cases {
        let paths = mcp_config_paths(*target, &sandbox.options(*scope)).unwrap();
        assert_eq!(&paths[0], expected, "{target} {scope:?}");
    }
    let copilot =
        mcp_config_paths(McpTarget::Copilot, &sandbox.options(McpScope::Workspace)).unwrap();
    assert_eq!(
        copilot,
        vec![rel(&ws, ".github/mcp.json"), rel(&ws, ".vscode/mcp.json")]
    );
    // No generic `.agents/mcp.json` fallback remains for any target.
    for target in McpTarget::ALL {
        for scope in [McpScope::Workspace, McpScope::Global] {
            if let Ok(paths) = mcp_config_paths(target, &sandbox.options(scope)) {
                for path in paths {
                    assert!(
                        !path.ends_with(Path::new(".agents").join("mcp.json")),
                        "{target} {scope:?} uses the generic fallback"
                    );
                }
            }
        }
    }
}

#[test]
fn per_os_and_env_overrides_for_global_paths() {
    let sandbox = Sandbox::new();
    let home = sandbox.home();
    let appdata = home.join("AppData").join("Roaming");
    let windows = sandbox.options_with(McpScope::Global, sandbox.env(McpHostOs::Windows));
    let first = |target| mcp_config_paths(target, &windows).unwrap().remove(0);
    assert_eq!(first(McpTarget::Zed), rel(&appdata, "Zed/settings.json"));
    assert_eq!(
        first(McpTarget::Goose),
        rel(&appdata, "Block/goose/config/config.yaml")
    );
    assert_eq!(
        first(McpTarget::Devin),
        rel(&appdata, "devin/mcp_config.json")
    );
    // Windsurf (Devin Desktop) Cascade reads the same Cortex-managed file, not the
    // editor-discovery file under ~/.codeium/windsurf.
    assert_eq!(
        first(McpTarget::Windsurf),
        rel(&appdata, "devin/mcp_config.json")
    );

    let mac = sandbox.options_with(McpScope::Global, sandbox.env(McpHostOs::MacOs));
    assert_eq!(
        mcp_config_paths(McpTarget::Zed, &mac).unwrap()[0],
        rel(&home, ".config/zed/settings.json")
    );
    for target in [McpTarget::Devin, McpTarget::Windsurf] {
        assert_eq!(
            mcp_config_paths(target, &mac).unwrap()[0],
            rel(&home, ".config/devin/mcp_config.json")
        );
    }

    let xdg = sandbox.root.join("xdg");
    let mut env = sandbox.env(McpHostOs::Linux);
    env.xdg_config_home = Some(xdg.clone());
    env.claude_config_dir = Some(sandbox.root.join("claude-cfg"));
    env.codex_home = Some(sandbox.root.join("codex-home"));
    env.copilot_home = Some(sandbox.root.join("copilot-home"));
    env.kimi_code_home = Some(sandbox.root.join("kimi-home"));
    env.cline_dir = Some(sandbox.root.join("cline-dir"));
    let options = sandbox.options_with(McpScope::Global, env.clone());
    let first = |target| mcp_config_paths(target, &options).unwrap().remove(0);
    assert_eq!(first(McpTarget::Zed), rel(&xdg, "zed/settings.json"));
    assert_eq!(first(McpTarget::Goose), rel(&xdg, "goose/config.yaml"));
    assert_eq!(
        first(McpTarget::OpenCode),
        rel(&xdg, "opencode/opencode.jsonc")
    );
    assert_eq!(first(McpTarget::Devin), rel(&xdg, "devin/mcp_config.json"));
    assert_eq!(
        first(McpTarget::Windsurf),
        rel(&xdg, "devin/mcp_config.json")
    );
    assert_eq!(
        first(McpTarget::Claude),
        sandbox.root.join("claude-cfg").join(".claude.json")
    );
    assert_eq!(
        first(McpTarget::Codex),
        sandbox.root.join("codex-home").join("config.toml")
    );
    assert_eq!(
        first(McpTarget::Copilot),
        sandbox.root.join("copilot-home").join("mcp-config.json")
    );
    assert_eq!(
        first(McpTarget::Kimi),
        sandbox.root.join("kimi-home").join("mcp.json")
    );
    assert_eq!(
        first(McpTarget::Cline),
        rel(
            &sandbox.root.join("cline-dir"),
            "data/settings/cline_mcp_settings.json"
        )
    );

    env.cline_mcp_settings_path = Some(sandbox.root.join("explicit.json"));
    let options = sandbox.options_with(McpScope::Global, env);
    assert_eq!(
        mcp_config_paths(McpTarget::Cline, &options).unwrap()[0],
        sandbox.root.join("explicit.json")
    );

    let mut no_home = McpEnvironment::empty(McpHostOs::Linux);
    no_home.xdg_config_home = None;
    let options = sandbox.options_with(McpScope::Global, no_home);
    assert_eq!(
        mcp_config_paths(McpTarget::Cursor, &options).unwrap_err(),
        McpInstallError::HomeUnresolved
    );
}

#[test]
fn unsupported_targets_and_scopes_write_nothing() {
    let sandbox = Sandbox::new();
    for target in [
        McpTarget::Aider,
        McpTarget::OpenHands,
        McpTarget::Replit,
        McpTarget::Cody,
    ] {
        for scope in [McpScope::Workspace, McpScope::Global] {
            let error = install_mcp_server(target, &sandbox.options(scope)).unwrap_err();
            assert_eq!(error.code(), "mcp_unsupported_target", "{target}");
            assert_eq!(error.exit_code(), 2);
        }
    }
    let cody =
        install_mcp_server(McpTarget::Cody, &sandbox.options(McpScope::Workspace)).unwrap_err();
    assert!(
        cody.manual_step()
            .unwrap()
            .snippet
            .contains("cody.mcpServers")
    );

    for (target, scope) in [
        (McpTarget::Cline, McpScope::Workspace),
        (McpTarget::Roo, McpScope::Global),
        (McpTarget::Goose, McpScope::Workspace),
        (McpTarget::Hermes, McpScope::Workspace),
        (McpTarget::Trae, McpScope::Global),
        (McpTarget::Continue, McpScope::Global),
    ] {
        let error = install_mcp_server(target, &sandbox.options(scope)).unwrap_err();
        assert_eq!(error.code(), "unsupported_scope", "{target} {scope:?}");
    }
    let continue_global =
        install_mcp_server(McpTarget::Continue, &sandbox.options(McpScope::Global)).unwrap_err();
    let manual = continue_global.manual_step().unwrap();
    assert!(
        manual
            .snippet
            .starts_with("mcpServers:\n  - name: sentra\n")
    );
    assert!(
        manual
            .path
            .ends_with(Path::new(".continue").join("config.yaml"))
    );

    assert!(files_under(&sandbox.ws()).is_empty());
    assert!(files_under(&sandbox.home()).is_empty());
}

#[test]
fn claude_workspace_create_rerun_and_update_keeps_user_fields() {
    let sandbox = Sandbox::new();
    let options = sandbox.options(McpScope::Workspace);
    let report = install_mcp_server(McpTarget::Claude, &options).unwrap();
    let path = sandbox.ws().join(".mcp.json");
    assert_eq!(report.config_file, path);
    assert_eq!(report.action, McpFileAction::Created);
    assert!(report.created_new_file);
    assert_eq!(report.command, sandbox.command_str());
    assert_eq!(report.args, vec!["mcp".to_owned()]);
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.ends_with('\n'));
    assert_eq!(
        read_json(&path),
        json!({"mcpServers": {"sentra": {"command": sandbox.command_str(), "args": ["mcp"]}}})
    );

    // Re-running is a no-op that writes no backup.
    let again = install_mcp_server(McpTarget::Claude, &options).unwrap();
    assert_eq!(again.action, McpFileAction::Unchanged);
    assert!(!sandbox.ws().join(".mcp.json.bak").exists());

    // A user customises env and another server; a new command only touches command/args.
    let customised = "{\n  \"mcpServers\": {\n    \"sentra\": {\n      \"command\": \"C:/old/sentra.exe\",\n      \"args\": [\"mcp\", \"--old\"],\n      \"env\": {\"SENTRA_X\": \"1\"}\n    },\n    \"other\": {\"command\": \"x\"}\n  },\n  \"zeta\": 1,\n  \"alpha\": 2\n}\n";
    fs::write(&path, customised).unwrap();
    let updated = install_mcp_server(McpTarget::Claude, &options).unwrap();
    assert_eq!(updated.action, McpFileAction::Updated);
    let backup = updated.backup_file.clone().unwrap();
    assert_eq!(backup, sandbox.ws().join(".mcp.json.bak"));
    assert_eq!(fs::read_to_string(&backup).unwrap(), customised);
    let value = read_json(&path);
    assert_eq!(
        value["mcpServers"]["sentra"]["command"],
        sandbox.command_str()
    );
    assert_eq!(value["mcpServers"]["sentra"]["args"], json!(["mcp"]));
    assert_eq!(
        value["mcpServers"]["sentra"]["env"],
        json!({"SENTRA_X": "1"})
    );
    assert_eq!(value["mcpServers"]["other"], json!({"command": "x"}));
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.find("\"zeta\"").unwrap() < text.find("\"alpha\"").unwrap());
    assert!(text.ends_with("}\n"));
}

#[test]
fn claude_global_preserves_large_state_file_byte_for_byte() {
    let sandbox = Sandbox::new();
    let path = sandbox.home().join(".claude.json");
    let original = "{\n  \"numStartups\": 42,\n  \"theme\": \"dark\",\n  \"tipsHistory\": {\"x\": 1.50, \"big\": 12345678901234567890},\n  \"projects\": {\n    \"/repo\": {\"allowedTools\": [], \"mcpServers\": {}}\n  },\n  \"oauthAccount\": {\"emailAddress\": \"a@example.invalid\"}\n}";
    fs::write(&path, original).unwrap();
    let report = install_mcp_server(McpTarget::Claude, &sandbox.options(McpScope::Global)).unwrap();
    assert_eq!(report.action, McpFileAction::Updated);
    let text = fs::read_to_string(&path).unwrap();
    // Everything before the insertion point is untouched, including number spellings.
    let head = "{\n  \"numStartups\": 42,\n  \"theme\": \"dark\",\n  \"tipsHistory\": {\"x\": 1.50, \"big\": 12345678901234567890},\n  \"projects\": {\n    \"/repo\": {\"allowedTools\": [], \"mcpServers\": {}}\n  },\n  \"oauthAccount\": {\"emailAddress\": \"a@example.invalid\"}";
    assert!(text.starts_with(head), "{text}");
    assert!(!text.ends_with('\n'), "trailing newline convention is kept");
    let value = read_json(&path);
    assert_eq!(
        value["mcpServers"]["sentra"]["command"],
        sandbox.command_str()
    );
    assert_eq!(value["projects"]["/repo"]["mcpServers"], json!({}));
    assert_eq!(
        fs::read_to_string(sandbox.home().join(".claude.json.bak")).unwrap(),
        original
    );
}

#[test]
fn unparseable_jsonc_bom_and_utf16_are_never_overwritten() {
    let sandbox = Sandbox::new();
    let options = sandbox.options(McpScope::Workspace);
    let cursor = sandbox.ws().join(".cursor").join("mcp.json");
    fs::create_dir_all(cursor.parent().unwrap()).unwrap();

    let broken = "{ \"mcpServers\": { \"keep\": {\"command\": \"k\"} ";
    fs::write(&cursor, broken).unwrap();
    let error = install_mcp_server(McpTarget::Cursor, &options).unwrap_err();
    assert_eq!(error.code(), "mcp_config_unparseable");
    assert_eq!(error.exit_code(), 4);
    assert_eq!(fs::read_to_string(&cursor).unwrap(), broken);
    let manual = error.manual_step().unwrap();
    assert_eq!(manual.format, McpConfigFormat::Json);
    assert!(manual.snippet.contains("\"sentra\""));
    assert!(manual.snippet.contains("\"mcpServers\""));
    assert!(!sandbox.ws().join(".cursor").join("mcp.json.bak").exists());

    let utf16: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain("{}".encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    fs::write(&cursor, &utf16).unwrap();
    let error = install_mcp_server(McpTarget::Cursor, &options).unwrap_err();
    assert_eq!(error.code(), "mcp_config_unsupported_encoding");
    assert_eq!(fs::read(&cursor).unwrap(), utf16);

    for (text, code) in [
        ("[1, 2]", "mcp_config_unexpected_shape"),
        ("{\"mcpServers\": [\"a\"]}", "mcp_config_unexpected_shape"),
        (
            "{\"mcpServers\": {\"sentra\": \"x\"}}",
            "mcp_config_unexpected_shape",
        ),
    ] {
        fs::write(&cursor, text).unwrap();
        let error = install_mcp_server(McpTarget::Cursor, &options).unwrap_err();
        assert_eq!(error.code(), code, "{text}");
        assert_eq!(fs::read_to_string(&cursor).unwrap(), text);
    }

    // A UTF-8 BOM and JSONC comments/trailing commas are edited in place.
    let jsonc = "\u{feff}// team servers\n{\n  \"mcpServers\": {\n    \"keep\": {\"command\": \"k\"}, // pinned\n  },\n}\n";
    fs::write(&cursor, jsonc).unwrap();
    let report = install_mcp_server(McpTarget::Cursor, &options).unwrap();
    assert_eq!(report.action, McpFileAction::Updated);
    let bytes = fs::read(&cursor).unwrap();
    assert!(bytes.starts_with(&[0xEF, 0xBB, 0xBF]));
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("// team servers"));
    assert!(text.contains("// pinned"));
    assert!(text.contains("\"keep\""));
    assert!(text.contains("\"sentra\""));
}

#[test]
fn zed_settings_keep_comments_and_migrate_legacy_command() {
    let sandbox = Sandbox::new();
    let options = sandbox.options(McpScope::Workspace);
    let path = sandbox.ws().join(".zed").join("settings.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let settings = "// Zed settings\n{\n  \"theme\": \"One Dark\",\n  \"ui_font_size\": 16,\n  \"context_servers\": {\n    \"other\": {\"command\": \"o\", \"args\": []},\n  },\n}\n";
    fs::write(&path, settings).unwrap();
    install_mcp_server(McpTarget::Zed, &options).unwrap();
    let text = fs::read_to_string(&path).unwrap();
    assert!(
        text.starts_with("// Zed settings\n{\n  \"theme\": \"One Dark\",\n  \"ui_font_size\": 16,")
    );
    assert!(text.contains("\"other\": {\"command\": \"o\", \"args\": []},"));
    assert!(text.contains("\"sentra\": {"));
    assert!(text.contains("\"env\": {}"));

    // Old Sentra releases wrote the pre-2025 nested form; it is flattened.
    let legacy = "{\"context_servers\": {\"sentra\": {\"command\": {\"path\": \"sentra\", \"args\": [\"mcp\"]}}}}";
    fs::write(&path, legacy).unwrap();
    install_mcp_server(McpTarget::Zed, &options).unwrap();
    let value = read_json(&path);
    assert_eq!(
        value["context_servers"]["sentra"]["command"],
        sandbox.command_str()
    );
    assert_eq!(value["context_servers"]["sentra"]["args"], json!(["mcp"]));

    // A nested form carrying user env cannot be flattened without loss.
    let nested_env = "{\"context_servers\": {\"sentra\": {\"command\": {\"path\": \"s\", \"env\": {\"K\": \"V\"}}}}}";
    fs::write(&path, nested_env).unwrap();
    let error = install_mcp_server(McpTarget::Zed, &options).unwrap_err();
    assert_eq!(error.code(), "mcp_config_unexpected_shape");
    assert_eq!(fs::read_to_string(&path).unwrap(), nested_env);
}

#[test]
fn copilot_opencode_and_amp_shapes() {
    let sandbox = Sandbox::new();
    let options = sandbox.options(McpScope::Workspace);
    let report = install_mcp_server(McpTarget::Copilot, &options).unwrap();
    assert_eq!(report.files.len(), 2);
    let cli = read_json(&sandbox.ws().join(".github").join("mcp.json"));
    assert_eq!(
        cli["mcpServers"]["sentra"],
        json!({"type": "local", "command": sandbox.command_str(), "args": ["mcp"], "tools": ["*"]})
    );
    let vscode = read_json(&sandbox.ws().join(".vscode").join("mcp.json"));
    assert_eq!(
        vscode["servers"]["sentra"],
        json!({"type": "stdio", "command": sandbox.command_str(), "args": ["mcp"]})
    );

    install_mcp_server(McpTarget::OpenCode, &options).unwrap();
    let opencode = read_json(&sandbox.ws().join("opencode.jsonc"));
    assert_eq!(
        opencode["mcp"]["servers"]["sentra"],
        json!({"type": "local", "command": [sandbox.command_str(), "mcp"]})
    );
    // V1 layout (servers directly under `mcp`) is refused instead of mixed.
    let v1 = "{\"mcp\": {\"legacy\": {\"type\": \"local\", \"command\": [\"x\"]}}}";
    fs::write(sandbox.ws().join("opencode.jsonc"), v1).unwrap();
    let error = install_mcp_server(McpTarget::OpenCode, &options).unwrap_err();
    assert_eq!(error.code(), "mcp_config_unexpected_shape");
    assert_eq!(
        fs::read_to_string(sandbox.ws().join("opencode.jsonc")).unwrap(),
        v1
    );

    install_mcp_server(McpTarget::Amp, &options).unwrap();
    let amp = read_json(&sandbox.ws().join(".amp").join("settings.json"));
    assert_eq!(
        amp["amp.mcpServers"]["sentra"],
        json!({"command": sandbox.command_str(), "args": ["mcp"]})
    );
    assert_eq!(McpTarget::parse("amp"), Some(McpTarget::Amp));
    assert_eq!(McpTarget::parse("replit"), Some(McpTarget::Replit));
    assert_eq!(McpTarget::parse("kimi-code"), Some(McpTarget::Kimi));
    assert_eq!(McpTarget::parse("all"), None);
    // Every skill-installer target name maps onto the same MCP target.
    for target in McpTarget::ALL {
        if let Some(agent) = AgentTarget::parse(target.as_str()) {
            assert_eq!(
                McpTarget::from_agent_target(agent),
                Some(target),
                "{target}"
            );
        }
    }
    assert_eq!(McpTarget::from_agent_target(AgentTarget::All), None);
}

#[test]
fn codex_toml_is_appended_updated_or_refused() {
    let sandbox = Sandbox::new();
    let options = sandbox.options(McpScope::Global);
    let path = sandbox.home().join(".codex").join("config.toml");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let original = "model = \"o4-mini\" # default\n\n[mcp_servers.other]\ncommand = \"npx\"\nargs = [\"-y\", \"x\"]\n";
    fs::write(&path, original).unwrap();
    let report = install_mcp_server(McpTarget::Codex, &options).unwrap();
    assert_eq!(report.action, McpFileAction::Updated);
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.starts_with(original));
    assert!(text.contains("[mcp_servers.sentra]\ncommand = "));
    assert!(text.ends_with("args = [\"mcp\"]\n"));
    assert_eq!(
        install_mcp_server(McpTarget::Codex, &options)
            .unwrap()
            .action,
        McpFileAction::Unchanged
    );

    let inline = "mcp_servers = { other = { command = \"x\" } }\n";
    fs::write(&path, inline).unwrap();
    let error = install_mcp_server(McpTarget::Codex, &options).unwrap_err();
    assert_eq!(error.code(), "mcp_manual_step_required");
    assert_eq!(fs::read_to_string(&path).unwrap(), inline);
    let manual = error.manual_step().unwrap();
    assert_eq!(manual.format, McpConfigFormat::Toml);
    assert!(
        manual
            .snippet
            .starts_with("[mcp_servers.sentra]\ncommand = ")
    );
}

#[test]
fn yaml_targets_goose_hermes_and_continue() {
    let sandbox = Sandbox::new();
    let global = sandbox.options(McpScope::Global);

    let goose = sandbox
        .home()
        .join(".config")
        .join("goose")
        .join("config.yaml");
    fs::create_dir_all(goose.parent().unwrap()).unwrap();
    let existing = "GOOSE_PROVIDER: openai\nextensions:\n  developer:\n    bundled: true\n    enabled: true\n    name: developer\n    type: builtin\n";
    fs::write(&goose, existing).unwrap();
    install_mcp_server(McpTarget::Goose, &global).unwrap();
    let text = fs::read_to_string(&goose).unwrap();
    assert!(text.starts_with(existing));
    assert!(
        text.contains("  sentra:\n    type: stdio\n    name: sentra\n    enabled: true\n    cmd: ")
    );
    assert!(text.contains("    args:\n      - mcp\n"));

    let flow = "extensions: {developer: {enabled: true}}\n";
    fs::write(&goose, flow).unwrap();
    let error = install_mcp_server(McpTarget::Goose, &global).unwrap_err();
    assert_eq!(error.code(), "mcp_manual_step_required");
    assert_eq!(fs::read_to_string(&goose).unwrap(), flow);
    assert!(
        error
            .manual_step()
            .unwrap()
            .snippet
            .starts_with("extensions:\n  sentra:\n")
    );

    let report = install_mcp_server(McpTarget::Hermes, &global).unwrap();
    assert_eq!(report.action, McpFileAction::Created);
    let hermes = fs::read_to_string(sandbox.home().join(".hermes").join("config.yaml")).unwrap();
    assert!(hermes.starts_with("mcp_servers:\n  sentra:\n    command: "));

    let workspace = sandbox.options(McpScope::Workspace);
    install_mcp_server(McpTarget::Continue, &workspace).unwrap();
    let block = sandbox
        .ws()
        .join(".continue")
        .join("mcpServers")
        .join("sentra.yaml");
    let text = fs::read_to_string(&block).unwrap();
    assert!(text.starts_with("name: Sentra\nversion: 0.0.1\nschema: v1\nmcpServers:\n  - name: sentra\n    type: stdio\n    command: "));
    assert_eq!(
        install_mcp_server(McpTarget::Continue, &workspace)
            .unwrap()
            .action,
        McpFileAction::Unchanged
    );
}

#[test]
fn cline_global_and_kimi_and_qwen_jsonc() {
    let sandbox = Sandbox::new();
    let global = sandbox.options(McpScope::Global);
    install_mcp_server(McpTarget::Cline, &global).unwrap();
    let cline = read_json(&rel(
        &sandbox.home(),
        ".cline/data/settings/cline_mcp_settings.json",
    ));
    assert_eq!(cline["mcpServers"]["sentra"]["args"], json!(["mcp"]));

    let qwen = rel(&sandbox.home(), ".qwen/settings.json");
    fs::create_dir_all(qwen.parent().unwrap()).unwrap();
    fs::write(&qwen, "{\n  // personal\n  \"theme\": \"x\",\n}\n").unwrap();
    install_mcp_server(McpTarget::Qwen, &global).unwrap();
    let text = fs::read_to_string(&qwen).unwrap();
    assert!(text.contains("// personal"));
    assert!(text.contains("\"mcpServers\": {"));

    let workspace = sandbox.options(McpScope::Workspace);
    install_mcp_server(McpTarget::Kimi, &workspace).unwrap();
    assert!(sandbox.ws().join(".kimi-code").join("mcp.json").exists());
}

#[test]
fn all_targets_install_or_skip_explicitly() {
    let sandbox = Sandbox::new();
    let workspace = install_mcp_server_all(&sandbox.options(McpScope::Workspace));
    assert!(workspace.is_success(), "{:?}", workspace.failed);
    let skipped: Vec<_> = workspace.skipped.iter().map(|issue| issue.target).collect();
    for target in [
        McpTarget::Aider,
        McpTarget::OpenHands,
        McpTarget::Replit,
        McpTarget::Cody,
        McpTarget::Cline,
        McpTarget::Goose,
        McpTarget::Hermes,
    ] {
        assert!(skipped.contains(&target), "{target} should be skipped");
    }
    assert_eq!(
        workspace.installed.len() + workspace.skipped.len(),
        McpTarget::ALL.len()
    );

    let global = install_mcp_server_all(&sandbox.options(McpScope::Global));
    assert!(global.is_success(), "{:?}", global.failed);
    assert!(sandbox.home().join(".claude.json").exists());
    assert!(!sandbox.home().join(".agents").exists());
    let serialised = serde_json::to_value(&global).unwrap();
    assert_eq!(serialised["scope"], "global");
    assert!(serialised["skipped"][0]["error"]["code"].is_string());

    // A second run changes nothing anywhere.
    let rerun = install_mcp_server_all(&sandbox.options(McpScope::Global));
    assert!(rerun.installed.iter().all(|report| {
        report
            .files
            .iter()
            .all(|file| file.action == McpFileAction::Unchanged)
    }));
}

#[cfg(unix)]
#[test]
fn file_permissions_are_preserved() {
    use std::os::unix::fs::PermissionsExt;
    let sandbox = Sandbox::new();
    let path = sandbox.home().join(".claude.json");
    fs::write(&path, "{}\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    install_mcp_server(McpTarget::Claude, &sandbox.options(McpScope::Global)).unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn read_only_config_is_reported_not_replaced() {
    let sandbox = Sandbox::new();
    let path = sandbox.ws().join(".mcp.json");
    fs::write(&path, "{}\n").unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&path, permissions.clone()).unwrap();
    let error =
        install_mcp_server(McpTarget::Claude, &sandbox.options(McpScope::Workspace)).unwrap_err();
    assert_eq!(error.code(), "mcp_install_io_failed");
    assert!(error.manual_step().is_some());
    assert_eq!(fs::read_to_string(&path).unwrap(), "{}\n");
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    fs::set_permissions(&path, permissions).unwrap();
}
