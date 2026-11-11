//! Query pack status and prefetch for host CodeQL analysis (ADR-0011):
//! `sentra codeql packs`.
//!
//! A CLI-only CodeQL distribution has no query packs, and the first analysis of a
//! language has to download `codeql/<language>-queries` (tens of MB; minutes on a slow
//! connection), during which CodeQL prints nothing. This module reports, per language,
//! whether the pack and the query suite file are already in the distribution's
//! `qlpacks/` or the pack cache, and with `download` fetches the missing ones ahead of
//! an analysis, one `codeql pack download` per pack so that completed packs stay in the
//! cache when a later one fails. Like host analysis, each download writes into a
//! staging directory and only a complete pack is moved into the pack cache, so a
//! download that is cancelled or times out leaves no partial pack behind.
//!
//! Listing runs no program. A download runs the launcher validated by
//! [`validate_codeql_launcher_with`] with the same allowlisted environment, a new
//! private run directory inside the pack cache as working, temporary and home
//! directory, a total time budget, process-tree containment and cancellation as host
//! analysis. The query packs are MIT-licensed (`LICENSE` of github/codeql); the CodeQL
//! CLI that downloads them is licensed under the GitHub CodeQL Terms and Conditions.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use serde::Serialize;

use crate::plugin::{
    codeql_host::{
        CodeQlHostError, CodeQlHostErrorKind, CodeQlHostLanguage, CodeQlProgressEvent, CodeQlSuite,
        DownloadOutcome, LauncherFs, LauncherPlatform, NEEDS_BUILD_REASON, RealLauncherFs,
        StepRunner, check_private_dirs, create_run_dirs, download_query_pack,
        extractor_build_modes, find_query_suite, prepare_outside_dir, step_environment,
        unique_nanos, validate_codeql_launcher_with,
    },
    codeql_sarif::display_path,
};

/// Most directory entries visited to size one pack; beyond it the size is not reported.
const PACK_SIZE_MAX_ENTRIES: usize = 200_000;

/// Request of [`codeql_query_packs`].
#[derive(Clone, Debug)]
pub struct CodeQlPacksRequest {
    /// CodeQL launcher (see [`validate_codeql_launcher_with`]).
    pub codeql: PathBuf,
    /// Pack cache (`--common-caches`); created when missing.
    pub pack_cache: PathBuf,
    /// Languages to report; empty means every language.
    pub languages: Vec<CodeQlHostLanguage>,
    /// Query suite whose file must be present.
    pub suite: CodeQlSuite,
    /// Whether missing packs of analysable languages are downloaded.
    pub download: bool,
    /// Time budget of all downloads together.
    pub timeout: Duration,
    /// Interval of `heartbeat` progress events while a download runs.
    pub heartbeat: Duration,
    /// When set and it becomes true, the running download's process tree is killed and
    /// the command ends with [`CodeQlHostErrorKind::Cancelled`].
    pub cancel: Option<Arc<AtomicBool>>,
}

/// Where a query pack was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQlPackSource {
    /// The distribution's `qlpacks/` (the CodeQL bundle ships them).
    Distribution,
    /// `<pack cache>/packages/`.
    PackCache,
}

/// State of one language's query pack.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQlPackState {
    /// The pack and the suite file are present.
    Present,
    /// They are not present (and were not downloaded).
    Missing,
    /// They were downloaded by this command.
    Downloaded,
    /// The download failed; `reason` gives CodeQL's message.
    Failed,
    /// Sentra does not analyse this language on the host; `reason` says why.
    NotAnalysable,
}

/// One language of a [`CodeQlPacksReport`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CodeQlPackStatus {
    /// CodeQL language id.
    pub language: String,
    /// Query pack name (`codeql/<language>-queries`).
    pub pack: String,
    /// Whether host analysis runs this language with this distribution.
    pub analysable: bool,
    /// State.
    pub status: CodeQlPackState,
    /// Why the language is not analysable, why a download failed, or why a missing
    /// pack was not downloaded.
    pub reason: Option<String>,
    /// Pack version (its directory name).
    pub version: Option<String>,
    /// Where the pack was found.
    pub source: Option<CodeQlPackSource>,
    /// Pack version directory.
    pub location: Option<String>,
    /// Suite file analysis would use.
    pub suite_file: Option<String>,
    /// Bytes of the pack version directory (its bundled library packs included); `None`
    /// when it has more than 200 000 entries.
    pub size_bytes: Option<u64>,
    /// Time the download took, when this command downloaded or tried to.
    pub duration_ms: Option<u64>,
}

/// Output of `sentra codeql packs`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CodeQlPacksReport {
    /// Contract version.
    pub schema_version: u32,
    /// `codeql packs`.
    pub command: &'static str,
    /// CodeQL distribution directory.
    pub distribution: String,
    /// Pack cache.
    pub pack_cache: String,
    /// Suite whose file was checked.
    pub suite: String,
    /// Whether `--download` was given.
    pub download_requested: bool,
    /// One entry per requested language, in CodeQL id order (or the requested order).
    pub languages: Vec<CodeQlPackStatus>,
    /// Analysable languages whose pack is present (downloaded ones included).
    pub present: usize,
    /// Analysable languages whose pack is missing (failed downloads included).
    pub missing: usize,
    /// Packs downloaded by this command.
    pub downloaded: usize,
    /// Downloads that failed.
    pub failed: usize,
    /// Notes for the operator.
    pub warnings: Vec<String>,
}

/// `sentra codeql packs` failure with the report gathered so far.
#[derive(Clone, Debug)]
pub struct CodeQlPacksError {
    /// Failure kind.
    pub kind: CodeQlHostErrorKind,
    /// Explanation for the operator.
    pub message: String,
    /// Per-language state when the failure came after the listing.
    pub report: Option<Box<CodeQlPacksReport>>,
}

impl From<CodeQlHostError> for CodeQlPacksError {
    fn from(error: CodeQlHostError) -> Self {
        Self {
            kind: error.kind,
            message: error.message,
            report: None,
        }
    }
}

impl std::fmt::Display for CodeQlPacksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind.code(), self.message)
    }
}

impl std::error::Error for CodeQlPacksError {}

/// Lists (and with `download` fetches) query packs with the real file system and the
/// process environment.
pub fn codeql_query_packs(
    request: &CodeQlPacksRequest,
    progress: &mut dyn FnMut(&CodeQlProgressEvent),
) -> Result<CodeQlPacksReport, CodeQlPacksError> {
    codeql_query_packs_with(request, &RealLauncherFs, std::env::vars_os(), progress)
}

/// Name of the pack's version directory (`.../codeql-suites/<file>` → version).
fn version_dir(suite_file: &Path) -> Option<&Path> {
    suite_file.parent()?.parent()
}

/// Total bytes of the files below `dir` (links are not followed), or `None` past
/// [`PACK_SIZE_MAX_ENTRIES`] entries or when the directory cannot be read.
fn directory_size(dir: &Path) -> Option<u64> {
    let mut total = 0_u64;
    let mut seen = 0_usize;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in std::fs::read_dir(&current).ok()?.flatten() {
            seen += 1;
            if seen > PACK_SIZE_MAX_ENTRIES {
                return None;
            }
            let Ok(metadata) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            }
        }
    }
    Some(total)
}

/// Fills the location fields of `status` from the suite file found.
fn describe_present(
    status: &mut CodeQlPackStatus,
    suite_file: &Path,
    distribution: &Path,
    state: CodeQlPackState,
) {
    status.status = state;
    status.reason = None;
    status.suite_file = Some(display_path(suite_file));
    if let Some(dir) = version_dir(suite_file) {
        status.version = dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());
        status.location = Some(display_path(dir));
        status.size_bytes = directory_size(dir);
        status.source = Some(if dir.starts_with(distribution) {
            CodeQlPackSource::Distribution
        } else {
            CodeQlPackSource::PackCache
        });
    }
}

/// [`codeql_query_packs`] with injected file-system rules (launcher validation) and
/// caller environment.
pub fn codeql_query_packs_with<I>(
    request: &CodeQlPacksRequest,
    fs: &dyn LauncherFs,
    parent_env: I,
    progress: &mut dyn FnMut(&CodeQlProgressEvent),
) -> Result<CodeQlPacksReport, CodeQlPacksError>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let launcher = validate_codeql_launcher_with(&request.codeql, LauncherPlatform::current(), fs)?;
    let pack_cache = prepare_outside_dir(
        &request.pack_cache,
        None,
        CodeQlHostErrorKind::UnsafeDirectory,
        "pack cache",
    )?;
    check_private_dirs(&[(&pack_cache, "pack cache")])?;
    let distribution = launcher.distribution.clone();

    let mut languages: Vec<CodeQlHostLanguage> = Vec::new();
    let requested: &[CodeQlHostLanguage] = if request.languages.is_empty() {
        &CodeQlHostLanguage::ALL
    } else {
        &request.languages
    };
    for language in requested {
        if !languages.contains(language) {
            languages.push(*language);
        }
    }

    let mut report = CodeQlPacksReport {
        schema_version: 1,
        command: "codeql packs",
        distribution: display_path(&distribution),
        pack_cache: display_path(&pack_cache),
        suite: request.suite.as_str().to_string(),
        download_requested: request.download,
        languages: Vec::new(),
        present: 0,
        missing: 0,
        downloaded: 0,
        failed: 0,
        warnings: Vec::new(),
    };
    let mut to_download: Vec<usize> = Vec::new();
    for language in &languages {
        let language = *language;
        let mut status = CodeQlPackStatus {
            language: language.as_str().to_string(),
            pack: format!("codeql/{language}-queries"),
            analysable: false,
            status: CodeQlPackState::NotAnalysable,
            reason: None,
            version: None,
            source: None,
            location: None,
            suite_file: None,
            size_bytes: None,
            duration_ms: None,
        };
        let blocked = match language.host_block_reason() {
            Some(reason) => Some(reason.to_string()),
            None => match extractor_build_modes(&distribution, language) {
                None => Some(format!(
                    "the CodeQL distribution has no {language} extractor"
                )),
                Some(modes) if !modes.iter().any(|m| m == "none") => {
                    Some(NEEDS_BUILD_REASON.to_string())
                }
                Some(_) => None,
            },
        };
        if let Some(reason) = blocked {
            status.reason = Some(reason);
        } else {
            status.analysable = true;
            match find_query_suite(language, request.suite, &distribution, &pack_cache) {
                Some(suite_file) => describe_present(
                    &mut status,
                    &suite_file,
                    &distribution,
                    CodeQlPackState::Present,
                ),
                None => {
                    status.status = CodeQlPackState::Missing;
                    status.reason = Some(format!(
                        "{} (suite {}) is not in the CodeQL distribution or the pack cache",
                        status.pack,
                        request.suite.file_name(language)
                    ));
                    to_download.push(report.languages.len());
                }
            }
        }
        report.languages.push(status);
    }

    if request.download && !to_download.is_empty() {
        download_missing(
            request,
            &mut report,
            &to_download,
            &launcher.program,
            &distribution,
            &pack_cache,
            parent_env,
            progress,
        )?;
    }
    finish_counts(&mut report);
    Ok(report)
}

fn finish_counts(report: &mut CodeQlPacksReport) {
    let count = |state: CodeQlPackState| {
        report
            .languages
            .iter()
            .filter(|status| status.status == state)
            .count()
    };
    report.downloaded = count(CodeQlPackState::Downloaded);
    report.failed = count(CodeQlPackState::Failed);
    report.present = count(CodeQlPackState::Present) + report.downloaded;
    report.missing = count(CodeQlPackState::Missing) + report.failed;
}

#[allow(clippy::too_many_arguments)]
fn download_missing<I>(
    request: &CodeQlPacksRequest,
    report: &mut CodeQlPacksReport,
    to_download: &[usize],
    program: &Path,
    distribution: &Path,
    pack_cache: &Path,
    parent_env: I,
    progress: &mut dyn FnMut(&CodeQlProgressEvent),
) -> Result<(), CodeQlPacksError>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let dirs = create_run_dirs(pack_cache.join(format!(
        ".sentra-run-{}-{}",
        std::process::id(),
        unique_nanos()
    )))?;
    let env = step_environment(parent_env, &dirs, None, LauncherPlatform::current());
    let never = AtomicBool::new(false);
    let cancel: &AtomicBool = request.cancel.as_deref().unwrap_or(&never);
    let mut runner = StepRunner {
        program,
        cwd: &dirs.run,
        env: &env,
        cancel,
        progress,
        heartbeat: request.heartbeat.max(Duration::from_millis(100)),
    };
    let mut budget = request.timeout;
    let mut stop: Option<(CodeQlHostErrorKind, String)> = None;
    for &index in to_download {
        let status = &mut report.languages[index];
        if let Some((kind, _)) = &stop {
            status.reason = Some(match kind {
                CodeQlHostErrorKind::Cancelled => {
                    "not downloaded: the command was cancelled first".to_string()
                }
                _ => {
                    "not downloaded: the download budget (--timeout-secs) ran out first".to_string()
                }
            });
            continue;
        }
        let Some(language) = CodeQlHostLanguage::parse(&status.language) else {
            continue;
        };
        let (outcome, spent) = download_query_pack(&mut runner, language, pack_cache, &mut budget);
        status.duration_ms = Some(u64::try_from(spent.as_millis()).unwrap_or(u64::MAX));
        match outcome {
            DownloadOutcome::NotStarted => {
                status.duration_ms = None;
                status.reason = Some(
                    "not downloaded: the download budget (--timeout-secs) ran out first"
                        .to_string(),
                );
                stop = Some((
                    CodeQlHostErrorKind::Timeout,
                    format!(
                        "the query pack download budget (--timeout-secs {} s) ran out before codeql pack download {} could start; packs downloaded before stay in the pack cache",
                        request.timeout.as_secs(),
                        status.pack
                    ),
                ));
            }
            DownloadOutcome::Downloaded => {
                match find_query_suite(language, request.suite, distribution, pack_cache) {
                    Some(suite_file) => describe_present(
                        status,
                        &suite_file,
                        distribution,
                        CodeQlPackState::Downloaded,
                    ),
                    None => {
                        status.status = CodeQlPackState::Failed;
                        status.reason = Some(format!(
                            "codeql pack download finished, but {} with suite {} is not in the pack cache",
                            status.pack,
                            request.suite.file_name(language)
                        ));
                    }
                }
            }
            DownloadOutcome::Failed(reason) => {
                status.status = CodeQlPackState::Failed;
                status.reason = Some(reason);
            }
            DownloadOutcome::TimedOut => {
                status.status = CodeQlPackState::Failed;
                status.reason = Some(format!(
                    "the download did not finish within the time budget (--timeout-secs {} s); the CodeQL process tree was killed",
                    request.timeout.as_secs()
                ));
                stop = Some((
                    CodeQlHostErrorKind::Timeout,
                    format!(
                        "the query pack downloads did not finish within the time budget (during codeql pack download {}); the process tree was killed, and packs downloaded before stay in the pack cache",
                        status.pack
                    ),
                ));
            }
            DownloadOutcome::Cancelled => {
                status.status = CodeQlPackState::Failed;
                status.reason = Some("cancelled; the CodeQL process tree was killed".into());
                stop = Some((
                    CodeQlHostErrorKind::Cancelled,
                    format!(
                        "the query pack download was cancelled (during codeql pack download {}); the process tree was killed, and packs downloaded before stay in the pack cache",
                        status.pack
                    ),
                ));
            }
        }
    }
    if let Err(e) = std::fs::remove_dir_all(&dirs.run) {
        report.warnings.push(format!(
            "the run directory '{}' could not be deleted: {e}",
            display_path(&dirs.run)
        ));
    }
    finish_counts(report);
    if let Some((kind, message)) = stop {
        return Err(CodeQlPacksError {
            kind,
            message,
            report: Some(Box::new(report.clone())),
        });
    }
    let failures: Vec<String> = report
        .languages
        .iter()
        .filter(|status| status.status == CodeQlPackState::Failed)
        .map(|status| {
            format!(
                "{}: {}",
                status.pack,
                status.reason.as_deref().unwrap_or("failed")
            )
        })
        .collect();
    if !failures.is_empty() {
        let mut message = format!(
            "{} of {} query pack downloads failed ({}); packs downloaded successfully stay in the pack cache",
            failures.len(),
            to_download.len(),
            failures.join("; ")
        );
        if message.chars().count() > 2_000 {
            message = message.chars().take(2_000).collect::<String>() + "...";
        }
        return Err(CodeQlPacksError {
            kind: CodeQlHostErrorKind::PackDownloadFailed,
            message,
            report: Some(Box::new(report.clone())),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_size_counts_files_below_the_pack() {
        let root = std::env::temp_dir().join(format!(
            "sentra-pack-size-{}-{}",
            std::process::id(),
            unique_nanos()
        ));
        std::fs::create_dir_all(root.join("a").join("b")).unwrap();
        std::fs::write(root.join("qlpack.yml"), "12345").unwrap();
        std::fs::write(root.join("a").join("b").join("x.qlx"), "1234567890").unwrap();
        assert_eq!(directory_size(&root), Some(15));
        assert_eq!(directory_size(&root.join("missing")), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn version_directory_is_two_levels_above_the_suite_file() {
        let suite = Path::new("/c/packages/codeql/python-queries/1.9.0/codeql-suites/x.qls");
        assert_eq!(
            version_dir(suite),
            Some(Path::new("/c/packages/codeql/python-queries/1.9.0"))
        );
    }
}
