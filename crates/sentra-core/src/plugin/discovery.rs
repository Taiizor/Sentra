//! Plugin discovery, manifest ingestion, and directory scanning (REQ-F16, EXTENSIONS.md).

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::plugin::{error::PluginError, manifest::PluginManifest};

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

impl DiscoveredPlugin {
    /// Loads and validates a plugin from a direct manifest.json path.
    pub fn from_manifest_file(path: impl AsRef<Path>) -> Result<Self, PluginError> {
        let manifest_path = path.as_ref().to_path_buf();
        let content = std::fs::read_to_string(&manifest_path).map_err(|e| {
            PluginError::invalid_manifest(format!(
                "Failed to read plugin manifest at '{}': {e}",
                manifest_path.display()
            ))
        })?;

        let manifest: PluginManifest = serde_json::from_str(&content).map_err(|e| {
            PluginError::invalid_manifest(format!(
                "Failed to parse plugin manifest at '{}': {e}",
                manifest_path.display()
            ))
        })?;

        manifest.validate()?;

        let adapter_dir = manifest_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));

        Ok(Self {
            manifest,
            manifest_path,
            adapter_dir,
        })
    }
}

/// Discovers plugins located within a single directory or its immediate child subdirectories.
pub fn discover_plugins_in_dir(dir: &Path) -> Vec<DiscoveredPlugin> {
    let mut discovered = Vec::new();
    if !dir.is_dir() {
        return discovered;
    }

    // Check direct manifest.json in dir
    let direct_manifest = dir.join("manifest.json");
    if let Ok(plugin) = DiscoveredPlugin::from_manifest_file(&direct_manifest) {
        discovered.push(plugin);
        return discovered;
    }

    // Check immediate child directories
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let child_path = entry.path();
            if child_path.is_dir() {
                let candidate = child_path.join("manifest.json");
                if let Ok(plugin) = DiscoveredPlugin::from_manifest_file(&candidate) {
                    discovered.push(plugin);
                }
            }
        }
    }

    discovered
}

/// Discovers and deduplicates plugins across multiple candidate search directories.
pub fn discover_plugins(search_paths: &[PathBuf]) -> Vec<DiscoveredPlugin> {
    let mut results = Vec::new();
    let mut seen_ids = HashSet::new();

    for path in search_paths {
        for plugin in discover_plugins_in_dir(path) {
            if seen_ids.insert(plugin.manifest.id.clone()) {
                results.push(plugin);
            }
        }
    }

    results.sort_by(|a, b| a.manifest.id.cmp(&b.manifest.id));
    results
}

/// Searches for a specific plugin ID within candidate search directories.
pub fn find_plugin_by_id(search_paths: &[PathBuf], plugin_id: &str) -> Option<DiscoveredPlugin> {
    for path in search_paths {
        for plugin in discover_plugins_in_dir(path) {
            if plugin.manifest.id == plugin_id {
                return Some(plugin);
            }
        }
    }
    None
}
