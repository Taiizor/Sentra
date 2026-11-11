//! Plugin discovery, manifest ingestion, and directory scanning (REQ-F16, EXTENSIONS.md).
//!
//! Discovery only reads the directories the caller passes in. It never searches the
//! current directory, its parents or a repository checkout on its own; choosing the
//! directory is an operator decision (see [`default_plugin_dir`]).

use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::plugin::{
    error::PluginError,
    manifest::{MANIFEST_KEYS, PluginManifest, QUOTA_KEYS},
};

/// File name of a plugin manifest inside an adapter directory.
pub const MANIFEST_FILE_NAME: &str = "manifest.json";

/// Environment variable naming the operator's plugin directory.
pub const PLUGIN_DIR_ENV: &str = "SENTRA_PLUGIN_DIR";

/// Largest manifest file that is read.
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;

/// Representation of a discovered plugin on the local filesystem.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredPlugin {
    /// Deserialized and validated manifest.
    pub manifest: PluginManifest,
    /// Path to the manifest.json file.
    pub manifest_path: PathBuf,
    /// Directory containing the manifest and adapter assets.
    pub adapter_dir: PathBuf,
}

/// Severity of a discovery diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    /// The entry was still loaded.
    Warning,
    /// The entry was skipped.
    Error,
}

/// Explanation of a skipped or suspicious discovery entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryDiagnostic {
    /// Directory or manifest the diagnostic is about.
    pub path: PathBuf,
    /// Whether the entry was skipped.
    pub severity: DiagnosticSeverity,
    /// Stable machine-readable code.
    pub code: String,
    /// Sanitized human-readable explanation.
    pub message: String,
}

/// Result of scanning explicit plugin directories.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginDiscovery {
    /// Loadable plugins with a unique id, sorted by id.
    pub plugins: Vec<DiscoveredPlugin>,
    /// Skipped manifests, ambiguous ids, missing directories and warnings.
    pub diagnostics: Vec<DiscoveryDiagnostic>,
}

impl PluginDiscovery {
    /// Whether any entry was skipped.
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity == DiagnosticSeverity::Error)
    }
}

impl DiscoveredPlugin {
    /// Loads and validates a plugin from a direct manifest.json path.
    pub fn from_manifest_file(path: impl AsRef<Path>) -> Result<Self, PluginError> {
        let (plugin, _) = load_manifest(path.as_ref()).map_err(|(_, error)| error)?;
        Ok(plugin)
    }
}

/// Reads, parses and validates one manifest; also returns unknown-key warnings.
fn load_manifest(
    manifest_path: &Path,
) -> Result<(DiscoveredPlugin, Vec<String>), (&'static str, PluginError)> {
    let shown = crate::skills::install_text::display_path(manifest_path);
    let metadata = std::fs::metadata(manifest_path).map_err(|e| {
        (
            "manifest_unreadable",
            PluginError::invalid_manifest(format!(
                "Failed to read plugin manifest at '{shown}': {e}"
            )),
        )
    })?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err((
            "manifest_too_large",
            PluginError::invalid_manifest(format!(
                "Plugin manifest at '{shown}' is larger than {MAX_MANIFEST_BYTES} bytes"
            )),
        ));
    }
    let bytes = std::fs::read(manifest_path).map_err(|e| {
        (
            "manifest_unreadable",
            PluginError::invalid_manifest(format!(
                "Failed to read plugin manifest at '{shown}': {e}"
            )),
        )
    })?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        (
            "manifest_invalid_json",
            PluginError::invalid_manifest(format!("Plugin manifest at '{shown}' is not UTF-8")),
        )
    })?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let value: serde_json::Value = serde_json::from_str(text).map_err(|e| {
        (
            "manifest_invalid_json",
            PluginError::invalid_manifest(format!(
                "Failed to parse plugin manifest at '{shown}': {e}"
            )),
        )
    })?;
    let unknown = unknown_keys(&value);
    let manifest: PluginManifest = serde_json::from_value(value).map_err(|e| {
        (
            "manifest_invalid",
            PluginError::invalid_manifest(format!(
                "Failed to parse plugin manifest at '{shown}': {e}"
            )),
        )
    })?;
    manifest.validate().map_err(|e| ("manifest_invalid", e))?;

    let adapter_dir = manifest_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    Ok((
        DiscoveredPlugin {
            manifest,
            manifest_path: manifest_path.to_path_buf(),
            adapter_dir,
        },
        unknown,
    ))
}

fn unknown_keys(value: &serde_json::Value) -> Vec<String> {
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    let mut unknown: Vec<String> = object
        .keys()
        .filter(|k| !MANIFEST_KEYS.contains(&k.as_str()))
        .cloned()
        .collect();
    if let Some(quotas) = object.get("quotas").and_then(|q| q.as_object()) {
        unknown.extend(
            quotas
                .keys()
                .filter(|k| !QUOTA_KEYS.contains(&k.as_str()))
                .map(|k| format!("quotas.{k}")),
        );
    }
    unknown
}

fn diagnostic(
    path: &Path,
    severity: DiagnosticSeverity,
    code: &str,
    message: impl Into<String>,
) -> DiscoveryDiagnostic {
    DiscoveryDiagnostic {
        path: path.to_path_buf(),
        severity,
        code: code.to_string(),
        message: crate::plugin::error::sanitize_text(&message.into()),
    }
}

/// Loads one manifest into `out`, recording diagnostics for failures and unknown keys.
fn collect_manifest(manifest_path: &Path, out: &mut PluginDiscovery) {
    match load_manifest(manifest_path) {
        Ok((plugin, unknown)) => {
            if !unknown.is_empty() {
                out.diagnostics.push(diagnostic(
                    manifest_path,
                    DiagnosticSeverity::Warning,
                    "manifest_unknown_field",
                    format!("ignored unknown manifest keys: {}", unknown.join(", ")),
                ));
            }
            out.plugins.push(plugin);
        }
        Err((code, error)) => out.diagnostics.push(diagnostic(
            manifest_path,
            DiagnosticSeverity::Error,
            code,
            error.to_string(),
        )),
    }
}

/// Child directories of `dir` that contain a manifest, sorted by path.
fn child_manifests(dir: &Path, out: &mut PluginDiscovery) -> Vec<PathBuf> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            out.diagnostics.push(diagnostic(
                dir,
                DiagnosticSeverity::Error,
                "plugin_dir_unreadable",
                format!("cannot list plugin directory: {e}"),
            ));
            return Vec::new();
        }
    };
    let mut manifests: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|child| child.is_dir())
        .map(|child| child.join(MANIFEST_FILE_NAME))
        .filter(|candidate| candidate.is_file())
        .collect();
    manifests.sort();
    manifests
}

fn scan_one_dir(dir: &Path, out: &mut PluginDiscovery) {
    if !dir.is_dir() {
        out.diagnostics.push(diagnostic(
            dir,
            DiagnosticSeverity::Error,
            "plugin_dir_not_found",
            "plugin directory does not exist or is not a directory",
        ));
        return;
    }

    // A directory holding its own manifest is a single adapter directory.
    let direct = dir.join(MANIFEST_FILE_NAME);
    if direct.is_file() {
        collect_manifest(&direct, out);
        for nested in child_manifests(dir, out) {
            out.diagnostics.push(diagnostic(
                &nested,
                DiagnosticSeverity::Warning,
                "nested_manifest_ignored",
                format!(
                    "not loaded: '{}' is itself an adapter directory; pass the child directory explicitly to load it",
                    crate::skills::install_text::display_path(dir)
                ),
            ));
        }
        return;
    }

    for manifest in child_manifests(dir, out) {
        collect_manifest(&manifest, out);
    }
}

/// Scans explicit plugin directories.
///
/// Each directory is either an adapter directory (it holds `manifest.json`) or a
/// container whose immediate child directories hold one manifest each. Plugins whose
/// id is declared more than once are all excluded and reported as `duplicate_plugin_id`.
pub fn scan_plugin_dirs(dirs: &[PathBuf]) -> PluginDiscovery {
    scan_with_duplicates(dirs).0
}

/// Scans and also returns, per ambiguous id, every manifest that declares it.
fn scan_with_duplicates(dirs: &[PathBuf]) -> (PluginDiscovery, BTreeMap<String, Vec<PathBuf>>) {
    let mut scanned = PluginDiscovery::default();
    let mut duplicates = BTreeMap::new();
    for dir in dirs {
        scan_one_dir(dir, &mut scanned);
    }

    let mut by_id: BTreeMap<String, Vec<DiscoveredPlugin>> = BTreeMap::new();
    for plugin in scanned.plugins.drain(..) {
        by_id
            .entry(plugin.manifest.id.clone())
            .or_default()
            .push(plugin);
    }
    for (id, mut group) in by_id {
        if group.len() == 1 {
            scanned.plugins.extend(group.pop());
            continue;
        }
        let paths: Vec<String> = group
            .iter()
            .map(|p| crate::skills::install_text::display_path(&p.manifest_path))
            .collect();
        for plugin in &group {
            scanned.diagnostics.push(diagnostic(
                &plugin.manifest_path,
                DiagnosticSeverity::Error,
                "duplicate_plugin_id",
                format!(
                    "plugin id '{id}' is declared by more than one manifest ({}); none of them is loaded",
                    paths.join(", ")
                ),
            ));
        }
        duplicates.insert(
            id,
            group
                .into_iter()
                .map(|p| p.manifest_path)
                .collect::<Vec<_>>(),
        );
    }
    (scanned, duplicates)
}

/// Resolves a plugin id in explicit directories, failing on unknown or ambiguous ids.
pub fn resolve_plugin(dirs: &[PathBuf], plugin_id: &str) -> Result<DiscoveredPlugin, PluginError> {
    let (scanned, mut duplicates) = scan_with_duplicates(dirs);
    if let Some(paths) = duplicates.remove(plugin_id) {
        return Err(PluginError::duplicate_plugin_id(plugin_id, paths));
    }
    scanned
        .plugins
        .into_iter()
        .find(|p| p.manifest.id == plugin_id)
        .ok_or_else(|| PluginError::plugin_not_found(plugin_id))
}

/// Discovers plugins located within a single directory or its immediate child subdirectories.
///
/// Diagnostics are dropped; use [`scan_plugin_dirs`] to report them.
pub fn discover_plugins_in_dir(dir: &Path) -> Vec<DiscoveredPlugin> {
    scan_plugin_dirs(&[dir.to_path_buf()]).plugins
}

/// Discovers plugins across explicit directories, excluding ambiguous ids.
///
/// Diagnostics are dropped; use [`scan_plugin_dirs`] to report them.
pub fn discover_plugins(search_paths: &[PathBuf]) -> Vec<DiscoveredPlugin> {
    scan_plugin_dirs(search_paths).plugins
}

/// Searches for a plugin id in explicit directories; `None` when unknown or ambiguous.
///
/// Use [`resolve_plugin`] to tell the two cases apart.
pub fn find_plugin_by_id(search_paths: &[PathBuf], plugin_id: &str) -> Option<DiscoveredPlugin> {
    resolve_plugin(search_paths, plugin_id).ok()
}

/// The operator's default plugin directory, from the process environment.
///
/// See [`default_plugin_dir_from`].
pub fn default_plugin_dir() -> Option<PathBuf> {
    default_plugin_dir_from(|name| std::env::var_os(name))
}

/// The operator's default plugin directory, reading variables through `var`.
///
/// 1. `SENTRA_PLUGIN_DIR`, when set to an absolute path.
/// 2. Windows: `%APPDATA%\sentra\plugins`.
/// 3. macOS: `$HOME/Library/Application Support/sentra/plugins`.
/// 4. Other Unix: `$XDG_CONFIG_HOME/sentra/plugins` when absolute, otherwise
///    `$HOME/.config/sentra/plugins`.
///
/// Relative values are ignored. The directory is not created and may not exist.
pub fn default_plugin_dir_from<F>(var: F) -> Option<PathBuf>
where
    F: Fn(&str) -> Option<OsString>,
{
    let absolute = |name: &str| {
        var(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    if let Some(dir) = absolute(PLUGIN_DIR_ENV) {
        return Some(dir);
    }
    let base = if cfg!(windows) {
        absolute("APPDATA")?
    } else if cfg!(target_os = "macos") {
        absolute("HOME")?
            .join("Library")
            .join("Application Support")
    } else {
        absolute("XDG_CONFIG_HOME").or_else(|| absolute("HOME").map(|h| h.join(".config")))?
    };
    Some(base.join("sentra").join("plugins"))
}

/// Diagnostic for a `SENTRA_PLUGIN_DIR` value that is set but ignored because it is
/// not an absolute path (discovery then falls back to the platform default).
pub fn plugin_dir_env_diagnostic() -> Option<DiscoveryDiagnostic> {
    plugin_dir_env_diagnostic_from(|name| std::env::var_os(name))
}

/// [`plugin_dir_env_diagnostic`] reading variables through `var`.
pub fn plugin_dir_env_diagnostic_from<F>(var: F) -> Option<DiscoveryDiagnostic>
where
    F: Fn(&str) -> Option<OsString>,
{
    let value = var(PLUGIN_DIR_ENV).filter(|v| !v.is_empty())?;
    let path = PathBuf::from(value);
    if path.is_absolute() {
        return None;
    }
    Some(diagnostic(
        &path,
        DiagnosticSeverity::Warning,
        "plugin_dir_env_ignored",
        format!(
            "{PLUGIN_DIR_ENV} is not an absolute path and was ignored; the platform default plugin directory is used instead"
        ),
    ))
}
