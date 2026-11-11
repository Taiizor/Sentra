//! Opt-in CodeQL analysis on the bridge host (ADR-0011, narrowly superseding ADR-0004
//! for this case).
//!
//! Sentra runs an operator-installed CodeQL CLI against a workspace without building
//! or running the project:
//!
//! - Only `codeql database create --build-mode=none` is used. `autobuild`, `manual`,
//!   `--command` and build tracing are never used; there is no code path that emits
//!   them.
//! - Languages whose extractor has no `none` mode (Go, Swift) are skipped. Rust, C#
//!   and Java are skipped too: their `none`-mode extractors run project-controlled
//!   code (Cargo build scripts and procedural macros; `dotnet restore`; the project's
//!   Gradle wrapper or Gradle/Maven). Remaining: actions, cpp, javascript, python,
//!   ruby.
//! - The analysis refuses to start unless the caller accepted the CodeQL terms.
//! - The launcher must be the `codeql` program of a CodeQL distribution: on Windows a
//!   `codeql.exe` with a PE header (never `.cmd`/`.bat`), elsewhere an executable file
//!   named `codeql` (the distribution's shell launcher is allowed).
//! - Every step runs with the run directory (inside the work directory, which must be
//!   outside the workspace) as its working directory, an allowlisted environment with
//!   the temporary and home directories redirected into the run directory, a deadline
//!   derived from the total timeout, and process-tree containment
//!   ([`run_contained_cancellable`]); a caller can cancel the run, which kills the tree
//!   too. Databases and SARIF files are deleted afterwards.
//! - On Windows, CodeQL's extractors run batch scripts that expand the source root and
//!   the scratch directory unquoted (`set LGTM_SRC=%CD%`), so a workspace, work
//!   directory, pack cache or distribution path containing a cmd.exe metacharacter
//!   (`&`, `^`, `!`, `%`) is refused before CodeQL starts: such a path would run part
//!   of itself, or a file from the workspace, as a command.
//! - On Unix the run directory is created with mode 0700 and must not exist yet, and
//!   the work directory and pack cache must belong to the current user and not be
//!   writable by group or others, so another local user cannot swap the run directory
//!   (whose `HOME` the extractors' host Python reads) or the query packs.
//! - Query packs come from the distribution (`qlpacks/`) or the explicit pack cache.
//!   Sentra checks that the pack is present before CodeQL resolves anything and passes
//!   the query suite by path with `--search-path=<distribution>` and
//!   `--common-caches=<pack cache>`, so CodeQL is not asked to look for a missing pack
//!   in the directories next to the distribution. `codeql pack download` runs only
//!   when downloads are allowed.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fmt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use serde::Serialize;

use crate::plugin::{
    codeql::{CodeQlLanguage, probe_codeql_workspace},
    codeql_sarif::{
        CODEQL_ANALYSIS_SARIF_MAX_BYTES, CodeQlLanguageOutcome, CodeQlLanguageStatus,
        CodeQlResultReport, CodeQlSarifOptions, display_path, normalize_codeql_sarif,
        read_sarif_file,
    },
    process::{ContainedRun, run_contained_cancellable, strip_verbatim},
};

/// Default total time budget of one host analysis (30 minutes).
pub const DEFAULT_CODEQL_TIMEOUT_SECS: u64 = 1_800;

/// Largest accepted total time budget (24 hours).
pub const MAX_CODEQL_TIMEOUT_SECS: u64 = 86_400;

/// Time limit of the `codeql version` step (bounded by the total budget).
pub const CODEQL_VERSION_TIMEOUT: Duration = Duration::from_secs(120);

/// Bytes of stdout/stderr kept per CodeQL step.
pub const CODEQL_OUTPUT_TAIL_BYTES: usize = 16 * 1024;

/// Bytes of stdout/stderr kept for `codeql version --format=json`, whose top-level
/// `version` key comes first and must not fall out of the tail.
const CODEQL_VERSION_OUTPUT_BYTES: usize = 256 * 1024;

/// Reason given for languages whose extractor has no `none` build mode.
pub const NEEDS_BUILD_REASON: &str =
    "requires building the project, which Sentra does not do on the host";

const RUST_REASON: &str = "CodeQL's Rust extractor runs the project's Cargo build scripts and procedural macros (target code), which Sentra does not do on the host";
const CSHARP_REASON: &str = "CodeQL's C# extractor in build-mode none restores dependencies with dotnet restore, which evaluates the project's own MSBuild files and uses the NuGet feeds of its nuget.config; Sentra does not do this on the host";
const JAVA_REASON: &str = "CodeQL's Java extractor in build-mode none runs the project's Gradle wrapper (gradlew) or Gradle/Maven to infer dependencies, which Sentra does not do on the host";

/// CodeQL language ids known to Sentra's host analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CodeQlHostLanguage {
    /// GitHub Actions workflows.
    Actions,
    /// C and C++.
    Cpp,
    /// C#.
    Csharp,
    /// Go.
    Go,
    /// Java and Kotlin.
    Java,
    /// JavaScript and TypeScript.
    Javascript,
    /// Python.
    Python,
    /// Ruby.
    Ruby,
    /// Rust.
    Rust,
    /// Swift.
    Swift,
}

impl CodeQlHostLanguage {
    /// Every language, in CodeQL id order.
    pub const ALL: [Self; 10] = [
        Self::Actions,
        Self::Cpp,
        Self::Csharp,
        Self::Go,
        Self::Java,
        Self::Javascript,
        Self::Python,
        Self::Ruby,
        Self::Rust,
        Self::Swift,
    ];

    /// CodeQL language id (`--language=<id>`, `codeql/<id>-queries`).
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Actions => "actions",
            Self::Cpp => "cpp",
            Self::Csharp => "csharp",
            Self::Go => "go",
            Self::Java => "java",
            Self::Javascript => "javascript",
            Self::Python => "python",
            Self::Ruby => "ruby",
            Self::Rust => "rust",
            Self::Swift => "swift",
        }
    }

    /// Parses a CodeQL language id or a common alias (`typescript`, `c-cpp`,
    /// `java-kotlin`, `c#`, ...), case-insensitively.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value.to_ascii_lowercase().as_str() {
            "actions" => Self::Actions,
            "cpp" | "c" | "c++" | "c-cpp" => Self::Cpp,
            "csharp" | "c#" => Self::Csharp,
            "go" => Self::Go,
            "java" | "kotlin" | "java-kotlin" => Self::Java,
            "javascript" | "typescript" | "javascript-typescript" | "js" | "ts" => Self::Javascript,
            "python" | "py" => Self::Python,
            "ruby" | "rb" => Self::Ruby,
            "rust" => Self::Rust,
            "swift" => Self::Swift,
            _ => return None,
        })
    }

    fn from_probe(language: CodeQlLanguage) -> Self {
        match language {
            CodeQlLanguage::Javascript => Self::Javascript,
            CodeQlLanguage::Python => Self::Python,
            CodeQlLanguage::Rust => Self::Rust,
            CodeQlLanguage::Go => Self::Go,
            CodeQlLanguage::Cpp => Self::Cpp,
            CodeQlLanguage::Java => Self::Java,
            CodeQlLanguage::Csharp => Self::Csharp,
            CodeQlLanguage::Ruby => Self::Ruby,
            CodeQlLanguage::Swift => Self::Swift,
        }
    }

    /// Why Sentra never analyses this language on the host, or `None` when it may.
    pub const fn host_block_reason(&self) -> Option<&'static str> {
        match self {
            Self::Go | Self::Swift => Some(NEEDS_BUILD_REASON),
            Self::Rust => Some(RUST_REASON),
            Self::Csharp => Some(CSHARP_REASON),
            Self::Java => Some(JAVA_REASON),
            Self::Actions | Self::Cpp | Self::Javascript | Self::Python | Self::Ruby => None,
        }
    }
}

impl fmt::Display for CodeQlHostLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Query suite run on each database.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub enum CodeQlSuite {
    /// `<language>-code-scanning.qls` (GitHub's default suite).
    #[default]
    CodeScanning,
    /// `<language>-security-extended.qls`.
    SecurityExtended,
}

impl CodeQlSuite {
    /// Contract label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::CodeScanning => "code-scanning",
            Self::SecurityExtended => "security-extended",
        }
    }

    /// Parses `code-scanning` or `security-extended`.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "code-scanning" => Some(Self::CodeScanning),
            "security-extended" => Some(Self::SecurityExtended),
            _ => None,
        }
    }

    /// Suite file name inside `codeql/<language>-queries/<version>/codeql-suites/`.
    pub fn file_name(&self, language: CodeQlHostLanguage) -> String {
        format!("{}-{}.qls", language.as_str(), self.as_str())
    }
}

/// Kind of a host analysis failure; [`Self::code`] is the CLI error code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeQlHostErrorKind {
    /// `--accept-codeql-terms` was not given.
    TermsNotAccepted,
    /// The launcher is missing, cannot start, or is not a CodeQL distribution launcher.
    NotFound,
    /// The workspace is not an accessible directory.
    InvalidWorkspace,
    /// The work directory is the workspace or inside it.
    WorkDirInsideWorkspace,
    /// The pack cache is the workspace or inside it.
    PackCacheInsideWorkspace,
    /// The work directory or pack cache cannot be used safely: on Windows its path
    /// contains a cmd.exe metacharacter, on Unix another user owns it or group or
    /// others can write to it.
    UnsafeDirectory,
    /// No language could be analysed because its query pack is missing and pack
    /// download is not allowed.
    QueryPackMissing,
    /// The total time budget ran out; the process tree was killed.
    Timeout,
    /// Every attempted language failed.
    Failed,
    /// The caller cancelled the analysis; the process tree was killed.
    Cancelled,
    /// A local file-system operation failed.
    Io,
}

impl CodeQlHostErrorKind {
    /// Stable CLI error code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TermsNotAccepted => "codeql_terms_not_accepted",
            Self::NotFound => "codeql_not_found",
            Self::InvalidWorkspace => "invalid_workspace",
            Self::WorkDirInsideWorkspace => "work_dir_inside_workspace",
            Self::PackCacheInsideWorkspace => "pack_cache_inside_workspace",
            Self::UnsafeDirectory => "unsafe_directory",
            Self::QueryPackMissing => "codeql_query_pack_missing",
            Self::Timeout => "codeql_timeout",
            Self::Failed => "codeql_failed",
            Self::Cancelled => "codeql_cancelled",
            Self::Io => "io_error",
        }
    }
}

/// Host analysis failure with the partial report when one exists.
#[derive(Clone, Debug)]
pub struct CodeQlHostError {
    /// Failure kind.
    pub kind: CodeQlHostErrorKind,
    /// Explanation for the operator.
    pub message: String,
    /// Languages and warnings gathered before the failure.
    pub report: Option<Box<CodeQlResultReport>>,
}

impl CodeQlHostError {
    fn new(kind: CodeQlHostErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            report: None,
        }
    }
}

impl fmt::Display for CodeQlHostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.code(), self.message)
    }
}

impl std::error::Error for CodeQlHostError {}

/// Platform rules applied to the launcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LauncherPlatform {
    /// `codeql.exe` with a PE header only.
    Windows,
    /// An executable file named `codeql` (script or binary).
    Unix,
}

impl LauncherPlatform {
    /// Rules of the platform Sentra was built for.
    pub const fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Unix
        }
    }
}

/// Characters that cmd.exe interprets in an unquoted batch line such as CodeQL's
/// `set LGTM_SRC=%CD%`: `&` separates commands, `^` escapes, `!` expands variables
/// under delayed expansion, `%` expands variables. (`|`, `<`, `>` and `"` cannot occur in
/// Windows file names.)
pub const CMD_METACHARACTERS: [char; 4] = ['&', '^', '!', '%'];

/// On Windows, the cmd.exe metacharacters (`'&'`, ...) that `path` contains, quoted and
/// comma-separated; `None` when there are none, and always on Unix.
///
/// CodeQL runs its Python and JavaScript extractors (and, through PowerShell, the
/// Actions extractor) on Windows through batch scripts that expand the source root
/// (`set LGTM_SRC=%CD%`), the scratch directory below the database and the extractor
/// directory without quotes. A path containing `&` would make cmd.exe run the rest of
/// the path as a command: with a workspace such as `C:\src\R&D\app` it runs
/// `D\app.cmd` from the workspace, which is target code.
pub fn cmd_metacharacters_in(path: &Path, platform: LauncherPlatform) -> Option<String> {
    if platform != LauncherPlatform::Windows {
        return None;
    }
    let text = path.to_string_lossy();
    let found: Vec<String> = CMD_METACHARACTERS
        .iter()
        .filter(|c| text.contains(**c))
        .map(|c| format!("'{c}'"))
        .collect();
    (!found.is_empty()).then(|| found.join(", "))
}

/// File-system queries used to validate a launcher (injectable for tests).
pub trait LauncherFs {
    /// Canonical absolute path.
    fn canonicalize(&self, path: &Path) -> std::io::Result<PathBuf>;
    /// Whether `path` is a regular file.
    fn is_file(&self, path: &Path) -> bool;
    /// Whether `path` is a directory.
    fn is_dir(&self, path: &Path) -> bool;
    /// First `len` bytes of a file (fewer when it is shorter).
    fn read_head(&self, path: &Path, len: usize) -> std::io::Result<Vec<u8>>;
    /// Whether any execute permission bit is set (always true where there is none).
    fn is_executable(&self, path: &Path) -> bool;
    /// Whether a direct subdirectory of `distribution` holds `codeql-extractor.yml`.
    fn has_extractor(&self, distribution: &Path) -> bool;
}

/// [`LauncherFs`] backed by the real file system.
#[derive(Clone, Copy, Debug, Default)]
pub struct RealLauncherFs;

impl LauncherFs for RealLauncherFs {
    fn canonicalize(&self, path: &Path) -> std::io::Result<PathBuf> {
        std::fs::canonicalize(path).map(strip_verbatim)
    }

    fn is_file(&self, path: &Path) -> bool {
        path.is_file()
    }

    fn is_dir(&self, path: &Path) -> bool {
        path.is_dir()
    }

    fn read_head(&self, path: &Path, len: usize) -> std::io::Result<Vec<u8>> {
        use std::io::Read;
        let mut head = Vec::with_capacity(len);
        std::fs::File::open(path)?
            .take(len as u64)
            .read_to_end(&mut head)?;
        Ok(head)
    }

    #[cfg(unix)]
    fn is_executable(&self, path: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
    }

    #[cfg(not(unix))]
    fn is_executable(&self, _path: &Path) -> bool {
        true
    }

    fn has_extractor(&self, distribution: &Path) -> bool {
        std::fs::read_dir(distribution).is_ok_and(|entries| {
            entries
                .flatten()
                .any(|entry| entry.path().join("codeql-extractor.yml").is_file())
        })
    }
}

/// A validated CodeQL launcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeQlLauncher {
    /// Canonical path of the program Sentra starts.
    pub program: PathBuf,
    /// The distribution directory that contains it.
    pub distribution: PathBuf,
}

/// Validates `path` with the rules of the current platform and the real file system.
pub fn validate_codeql_launcher(path: &Path) -> Result<CodeQlLauncher, CodeQlHostError> {
    validate_codeql_launcher_with(path, LauncherPlatform::current(), &RealLauncherFs)
}

/// Validates that `path` is the `codeql` launcher of a CodeQL distribution.
///
/// Windows: the file must be named `codeql.exe` (any case) and start with a PE (`MZ`)
/// header; `codeql.cmd`, `.bat` files and the extension-less shell launcher are
/// refused. Unix: the file must be named `codeql` and have an execute bit; the
/// distribution's shell-script launcher is allowed. On both, the directory that holds
/// it must contain `tools/` and either `.codeqlmanifest.json` or a
/// `<language>/codeql-extractor.yml`.
pub fn validate_codeql_launcher_with(
    path: &Path,
    platform: LauncherPlatform,
    fs: &dyn LauncherFs,
) -> Result<CodeQlLauncher, CodeQlHostError> {
    let shown = display_path(path);
    let not_found = |why: &str| {
        CodeQlHostError::new(
            CodeQlHostErrorKind::NotFound,
            format!("'{shown}' cannot be used as the CodeQL launcher: {why}"),
        )
    };
    let program = fs
        .canonicalize(path)
        .map_err(|_| not_found("it does not exist or cannot be accessed"))?;
    if !fs.is_file(&program) {
        return Err(not_found("it is not a file"));
    }
    let name = program
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    match platform {
        LauncherPlatform::Windows => {
            if !name.eq_ignore_ascii_case("codeql.exe") {
                return Err(not_found(
                    "on Windows only the codeql.exe program of a CodeQL distribution is run (codeql.cmd, .bat files and the shell launcher are refused)",
                ));
            }
            let head = fs
                .read_head(&program, 2)
                .map_err(|_| not_found("it cannot be read"))?;
            if head != b"MZ" {
                return Err(not_found("it is not a Windows executable (no PE header)"));
            }
        }
        LauncherPlatform::Unix => {
            if name != "codeql" {
                return Err(not_found(
                    "the launcher must be the file named codeql at the top of a CodeQL distribution",
                ));
            }
            if !fs.is_executable(&program) {
                return Err(not_found("it is not executable"));
            }
        }
    }
    let distribution = program
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| not_found("it has no parent directory"))?;
    let separator = match platform {
        LauncherPlatform::Windows => ';',
        LauncherPlatform::Unix => ':',
    };
    if distribution.to_string_lossy().contains(separator) {
        return Err(not_found(&format!(
            "the distribution directory contains '{separator}', which CodeQL reads as a search-path separator"
        )));
    }
    if let Some(found) = cmd_metacharacters_in(&distribution, platform) {
        return Err(not_found(&format!(
            "the distribution directory contains {found}, which CodeQL's Windows extractor scripts would run as part of a command (they expand the extractor directory unquoted)"
        )));
    }
    let has_manifest = fs.is_file(&distribution.join(".codeqlmanifest.json"));
    if !fs.is_dir(&distribution.join("tools")) || !(has_manifest || fs.has_extractor(&distribution))
    {
        return Err(not_found(
            "it does not live in a CodeQL distribution (expected a tools directory and .codeqlmanifest.json or <language>/codeql-extractor.yml next to it)",
        ));
    }
    Ok(CodeQlLauncher {
        program,
        distribution,
    })
}

/// Environment variables copied from the caller into every CodeQL step (compared
/// case-insensitively on Windows). `PATH` keeps only absolute entries outside the
/// workspace. Tokens, provider keys, `SENTRA_*`, `CODEQL_*`, `JAVA_TOOL_OPTIONS` and
/// every other variable are never forwarded.
pub const CODEQL_ENV_PASSTHROUGH: &[&str] = &[
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "PROCESSOR_ARCHITECTURE",
    "NUMBER_OF_PROCESSORS",
    "LANG",
    "LC_ALL",
];

/// Directories of one analysis run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeQlRunDirs {
    /// Run directory: working directory of every step; deleted afterwards.
    pub run: PathBuf,
    /// `TEMP`, `TMP` and `TMPDIR`.
    pub tmp: PathBuf,
    /// `HOME` (and on Windows `USERPROFILE`, `APPDATA`, `LOCALAPPDATA` below it).
    pub home: PathBuf,
}

impl CodeQlRunDirs {
    /// Layout below `run`.
    pub fn new(run: PathBuf) -> Self {
        Self {
            tmp: run.join("tmp"),
            home: run.join("home"),
            run,
        }
    }
}

fn is_passthrough(name: &str, platform: LauncherPlatform) -> bool {
    CODEQL_ENV_PASSTHROUGH.iter().any(|allowed| match platform {
        LauncherPlatform::Windows => allowed.eq_ignore_ascii_case(name),
        LauncherPlatform::Unix => *allowed == name,
    })
}

/// Whether `child` is `parent` or below it (canonical paths when both exist, else
/// lexical; case-insensitive on Windows).
fn is_within(child: &Path, parent: &Path) -> bool {
    let child = std::fs::canonicalize(child)
        .map(strip_verbatim)
        .unwrap_or_else(|_| child.to_path_buf());
    let parent = std::fs::canonicalize(parent)
        .map(strip_verbatim)
        .unwrap_or_else(|_| parent.to_path_buf());
    if cfg!(windows) {
        let lower = |p: &Path| PathBuf::from(p.to_string_lossy().to_lowercase());
        lower(&child).starts_with(lower(&parent))
    } else {
        child.starts_with(parent)
    }
}

/// Builds the environment of every CodeQL step from the caller's variables.
///
/// Passthrough variables ([`CODEQL_ENV_PASSTHROUGH`]) are copied; `PATH` loses
/// relative and empty entries and entries inside the workspace (the extractors start
/// in the source root, where a relative entry would resolve). `TEMP`, `TMP`, `TMPDIR`
/// and `HOME` point into the run directory, and on Windows so do `USERPROFILE`,
/// `APPDATA` and `LOCALAPPDATA`. Three fixed variables are added:
/// `NoDefaultCurrentDirectoryInExePath=1` on Windows (programs started by name are
/// not looked up in the current directory, which is the source root during
/// extraction) and `CODEQL_EXTRACTOR_PYTHON_ENABLE_SITE=1` (skips the Python
/// extractor's `python -S -c "import gzip"` probe, which would import a `gzip.py`
/// from the source root) and `PYTHONDONTWRITEBYTECODE=1` (the host Python started by
/// the Python extractor writes no `__pycache__` files, which it otherwise does next to
/// the extractor's own scripts inside the CodeQL distribution).
pub fn codeql_host_environment<I>(
    parent: I,
    dirs: &CodeQlRunDirs,
    workspace: &Path,
    platform: LauncherPlatform,
) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let mut env: Vec<(OsString, OsString)> = Vec::new();
    for (name, value) in parent {
        let Some(text) = name.to_str() else {
            continue;
        };
        if !is_passthrough(text, platform) {
            continue;
        }
        if text.eq_ignore_ascii_case("PATH") {
            let kept: Vec<PathBuf> = std::env::split_paths(&value)
                .filter(|entry| entry.is_absolute() && !is_within(entry, workspace))
                .collect();
            if let Ok(joined) = std::env::join_paths(kept) {
                env.push((name, joined));
            }
        } else {
            env.push((name, value));
        }
    }
    let tmp = dirs.tmp.as_os_str().to_os_string();
    let home = dirs.home.as_os_str().to_os_string();
    for name in ["TEMP", "TMP", "TMPDIR"] {
        env.push((name.into(), tmp.clone()));
    }
    env.push(("HOME".into(), home.clone()));
    if platform == LauncherPlatform::Windows {
        env.push(("USERPROFILE".into(), home));
        env.push((
            "APPDATA".into(),
            dirs.home.join("AppData").join("Roaming").into_os_string(),
        ));
        env.push((
            "LOCALAPPDATA".into(),
            dirs.home.join("AppData").join("Local").into_os_string(),
        ));
        env.push(("NoDefaultCurrentDirectoryInExePath".into(), "1".into()));
    }
    env.push(("CODEQL_EXTRACTOR_PYTHON_ENABLE_SITE".into(), "1".into()));
    env.push(("PYTHONDONTWRITEBYTECODE".into(), "1".into()));
    env
}

fn path_flag(name: &str, value: &Path) -> OsString {
    let mut flag = OsString::from(format!("--{name}="));
    flag.push(value.as_os_str());
    flag
}

fn resource_flags(args: &mut Vec<OsString>, threads: Option<u32>, ram_mb: Option<u32>) {
    if let Some(threads) = threads {
        args.push(format!("--threads={threads}").into());
    }
    if let Some(ram) = ram_mb {
        args.push(format!("--ram={ram}").into());
    }
}

/// `codeql version --format=json --common-caches=<pack cache>`.
pub fn codeql_version_args(pack_cache: &Path) -> Vec<OsString> {
    vec![
        "version".into(),
        "--format=json".into(),
        path_flag("common-caches", pack_cache),
    ]
}

/// `codeql pack download <pack> --common-caches=<pack cache>`.
pub fn codeql_pack_download_args(pack: &str, pack_cache: &Path) -> Vec<OsString> {
    vec![
        "pack".into(),
        "download".into(),
        pack.into(),
        path_flag("common-caches", pack_cache),
    ]
}

/// Inputs of `codeql database create`.
#[derive(Clone, Copy, Debug)]
pub struct DatabaseCreateSpec<'a> {
    /// Database directory (created by CodeQL).
    pub database: &'a Path,
    /// Language extracted.
    pub language: CodeQlHostLanguage,
    /// Source root (the workspace).
    pub source_root: &'a Path,
    /// CodeQL distribution directory (`--search-path`).
    pub distribution: &'a Path,
    /// Pack cache (`--common-caches`).
    pub pack_cache: &'a Path,
    /// `--threads`.
    pub threads: Option<u32>,
    /// `--ram` in MB.
    pub ram_mb: Option<u32>,
}

/// `codeql database create <db> --language=<id> --build-mode=none ...`.
///
/// The build mode is always `none`; no build command, `autobuild` or tracing option
/// exists in this builder.
pub fn codeql_database_create_args(spec: &DatabaseCreateSpec<'_>) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "database".into(),
        "create".into(),
        spec.database.as_os_str().to_os_string(),
        format!("--language={}", spec.language.as_str()).into(),
        "--build-mode=none".into(),
        path_flag("source-root", spec.source_root),
        path_flag("search-path", spec.distribution),
        path_flag("common-caches", spec.pack_cache),
    ];
    resource_flags(&mut args, spec.threads, spec.ram_mb);
    args
}

/// Inputs of `codeql database analyze`.
#[derive(Clone, Copy, Debug)]
pub struct DatabaseAnalyzeSpec<'a> {
    /// Database directory.
    pub database: &'a Path,
    /// Absolute path of the `.qls` query suite.
    pub suite_file: &'a Path,
    /// SARIF output file.
    pub sarif: &'a Path,
    /// CodeQL distribution directory (`--search-path`).
    pub distribution: &'a Path,
    /// Pack cache (`--common-caches`).
    pub pack_cache: &'a Path,
    /// `--threads`.
    pub threads: Option<u32>,
    /// `--ram` in MB.
    pub ram_mb: Option<u32>,
}

/// `codeql database analyze <db> <suite.qls> --format=sarif-latest --output=<file> ...`
/// (never `--download`).
pub fn codeql_database_analyze_args(spec: &DatabaseAnalyzeSpec<'_>) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "database".into(),
        "analyze".into(),
        spec.database.as_os_str().to_os_string(),
        spec.suite_file.as_os_str().to_os_string(),
        "--format=sarif-latest".into(),
        path_flag("output", spec.sarif),
        path_flag("search-path", spec.distribution),
        path_flag("common-caches", spec.pack_cache),
    ];
    resource_flags(&mut args, spec.threads, spec.ram_mb);
    args
}

/// Build modes declared by `<distribution>/<language>/codeql-extractor.yml`, or
/// `None` when the distribution has no extractor for the language.
pub fn extractor_build_modes(
    distribution: &Path,
    language: CodeQlHostLanguage,
) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(
        distribution
            .join(language.as_str())
            .join("codeql-extractor.yml"),
    )
    .ok()?;
    Some(parse_build_modes(&text))
}

/// Reads the `build_modes:` list of a `codeql-extractor.yml`.
pub fn parse_build_modes(yml: &str) -> Vec<String> {
    let mut modes = Vec::new();
    let mut in_list = false;
    for line in yml.lines() {
        let trimmed = line.trim();
        if !in_list {
            in_list = line.starts_with("build_modes:");
            continue;
        }
        if let Some(item) = trimmed.strip_prefix("- ") {
            modes.push(item.trim().trim_matches('"').trim_matches('\'').to_string());
        } else if !trimmed.is_empty() && !trimmed.starts_with('#') {
            break;
        }
    }
    modes
}

fn parse_version(name: &str) -> Option<(u64, u64, u64, bool)> {
    let (core, pre) = match name.split_once('-') {
        Some((core, _)) => (core, true),
        None => (name, false),
    };
    let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
    let version = (parts.next()??, parts.next()??, parts.next()??);
    if parts.next().is_some() {
        return None;
    }
    // A release sorts above its pre-releases.
    Some((version.0, version.1, version.2, !pre))
}

/// Absolute path of `codeql/<language>-queries/<version>/codeql-suites/<suite file>` in
/// the distribution's `qlpacks/` (preferred: it matches the CLI) or the pack cache's
/// `packages/`, highest version first; `None` when neither holds it.
pub fn find_query_suite(
    language: CodeQlHostLanguage,
    suite: CodeQlSuite,
    distribution: &Path,
    pack_cache: &Path,
) -> Option<PathBuf> {
    let pack = format!("{}-queries", language.as_str());
    let file = suite.file_name(language);
    [
        distribution.join("qlpacks").join("codeql").join(&pack),
        pack_cache.join("packages").join("codeql").join(&pack),
    ]
    .iter()
    .find_map(|base| {
        let versions: Vec<((u64, u64, u64, bool), PathBuf)> = std::fs::read_dir(base)
            .ok()?
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                let version = parse_version(&name)?;
                let dir = entry.path();
                let suite_file = dir.join("codeql-suites").join(&file);
                (dir.join("qlpack.yml").is_file() && suite_file.is_file())
                    .then_some((version, suite_file))
            })
            .collect();
        versions
            .into_iter()
            .max_by_key(|(version, _)| *version)
            .map(|(_, path)| path)
    })
}

/// Languages to analyse when none were requested: the workspace language probe plus
/// `actions` when `.github/workflows` holds a `.yml`/`.yaml` file.
pub fn detect_host_languages(workspace: &Path) -> Result<Vec<CodeQlHostLanguage>, String> {
    let probe = probe_codeql_workspace(workspace).map_err(|e| e.to_string())?;
    let mut languages: Vec<CodeQlHostLanguage> = probe
        .detected_languages
        .iter()
        .map(|(language, _)| CodeQlHostLanguage::from_probe(*language))
        .collect();
    let has_workflow =
        std::fs::read_dir(workspace.join(".github").join("workflows")).is_ok_and(|entries| {
            entries.flatten().any(|entry| {
                let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
                (name.ends_with(".yml") || name.ends_with(".yaml")) && entry.path().is_file()
            })
        });
    if has_workflow {
        languages.push(CodeQlHostLanguage::Actions);
    }
    Ok(languages)
}

/// Request of [`analyze_workspace_with_codeql`].
#[derive(Clone, Debug)]
pub struct CodeQlAnalyzeRequest {
    /// Workspace (source root); never written.
    pub workspace: PathBuf,
    /// CodeQL launcher (see [`validate_codeql_launcher`]).
    pub codeql: PathBuf,
    /// Work directory outside the workspace; a run directory is created inside it.
    pub work_dir: PathBuf,
    /// Pack cache outside the workspace (`--common-caches`).
    pub pack_cache: PathBuf,
    /// Whether the caller accepted the CodeQL terms (`--accept-codeql-terms`).
    pub terms_accepted: bool,
    /// Languages to analyse; empty means detect.
    pub languages: Vec<CodeQlHostLanguage>,
    /// Query suite.
    pub suite: CodeQlSuite,
    /// `--threads` passed to CodeQL.
    pub threads: Option<u32>,
    /// `--ram` passed to CodeQL, in MB.
    pub ram_mb: Option<u32>,
    /// Total time budget.
    pub timeout: Duration,
    /// Whether `codeql pack download` may run.
    pub allow_pack_download: bool,
    /// Most findings returned.
    pub max_results: usize,
    /// When set and it becomes true, the running CodeQL step's process tree is killed and
    /// the analysis ends with [`CodeQlHostErrorKind::Cancelled`]. `sentra codeql analyze
    /// --cancel-on-stdin-eof` sets it when its standard input closes.
    pub cancel: Option<Arc<AtomicBool>>,
}

/// Runs a host analysis with the real file system and the process environment.
pub fn analyze_workspace_with_codeql(
    request: &CodeQlAnalyzeRequest,
) -> Result<CodeQlResultReport, CodeQlHostError> {
    analyze_workspace_with(request, &RealLauncherFs, std::env::vars_os())
}

/// Resolves `path` (which may not exist yet) and refuses it when it is `workspace` or
/// below it; creates it otherwise and returns its canonical form.
fn prepare_outside_dir(
    path: &Path,
    workspace: &Path,
    inside_kind: CodeQlHostErrorKind,
    label: &str,
) -> Result<PathBuf, CodeQlHostError> {
    let inside = || {
        CodeQlHostError::new(
            inside_kind,
            format!(
                "the {label} '{}' is the workspace or inside it; use a directory outside the workspace",
                display_path(path)
            ),
        )
    };
    // Resolve the nearest existing ancestor so links are followed before creating.
    let mut existing = path.to_path_buf();
    let mut rest: Vec<OsString> = Vec::new();
    while !existing.exists() {
        let Some(name) = existing.file_name().map(OsStr::to_os_string) else {
            break;
        };
        rest.push(name);
        if !existing.pop() {
            break;
        }
    }
    let mut resolved = std::fs::canonicalize(&existing)
        .map(strip_verbatim)
        .unwrap_or(existing);
    for name in rest.iter().rev() {
        resolved.push(name);
    }
    if is_within(&resolved, workspace) {
        return Err(inside());
    }
    if let Some(found) = cmd_metacharacters_in(&resolved, LauncherPlatform::current()) {
        return Err(CodeQlHostError::new(
            CodeQlHostErrorKind::UnsafeDirectory,
            format!(
                "the {label} '{}' contains {found}, which CodeQL's Windows extractor scripts expand unquoted, so part of the path would run as a command; use a directory whose path has none of & ^ ! %",
                display_path(path)
            ),
        ));
    }
    private_dir_builder(true).create(&resolved).map_err(|e| {
        CodeQlHostError::new(
            CodeQlHostErrorKind::Io,
            format!(
                "the {label} '{}' cannot be created: {e}",
                display_path(path)
            ),
        )
    })?;
    let canonical = std::fs::canonicalize(&resolved)
        .map(strip_verbatim)
        .map_err(|e| {
            CodeQlHostError::new(
                CodeQlHostErrorKind::Io,
                format!(
                    "the {label} '{}' is not accessible: {e}",
                    display_path(path)
                ),
            )
        })?;
    if is_within(&canonical, workspace) {
        return Err(inside());
    }
    Ok(canonical)
}

/// A [`std::fs::DirBuilder`] that creates directories private to the current user on
/// Unix (mode 0700); `recursive` false makes an existing directory an error.
#[cfg(unix)]
fn private_dir_builder(recursive: bool) -> std::fs::DirBuilder {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(recursive).mode(0o700);
    builder
}

/// A [`std::fs::DirBuilder`]; `recursive` false makes an existing directory an error.
#[cfg(not(unix))]
fn private_dir_builder(recursive: bool) -> std::fs::DirBuilder {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(recursive);
    builder
}

/// Why a directory with owner `owner` and permission bits `mode` must not hold the run
/// directory or the query packs of user `uid`, or `None` when it may.
#[cfg_attr(not(unix), allow(dead_code))]
fn shared_directory_problem(owner: u32, mode: u32, uid: u32) -> Option<&'static str> {
    if owner != uid {
        Some("it belongs to another user, who could replace what Sentra and CodeQL write there")
    } else if mode & 0o022 != 0 {
        Some(
            "group or other users can write to it, so they could replace what Sentra and CodeQL write there",
        )
    } else {
        None
    }
}

/// Refuses work directories and pack caches that another local user could write to.
///
/// The current user's id is read from a file created in the first directory (through
/// the open handle, so a concurrent rename cannot change the answer).
#[cfg(unix)]
fn check_private_dirs(dirs: &[(&Path, &str)]) -> Result<(), CodeQlHostError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let Some((first, first_label)) = dirs.first() else {
        return Ok(());
    };
    let io_error = |label: &str, path: &Path, e: std::io::Error| {
        CodeQlHostError::new(
            CodeQlHostErrorKind::Io,
            format!(
                "the {label} '{}' cannot be checked: {e}",
                display_path(path)
            ),
        )
    };
    let probe = first.join(format!(
        ".sentra-owner-probe-{}-{}",
        std::process::id(),
        unique_nanos()
    ));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&probe)
        .map_err(|e| io_error(first_label, first, e))?;
    let uid = file.metadata().map(|m| m.uid());
    drop(file);
    let _ = std::fs::remove_file(&probe);
    let uid = uid.map_err(|e| io_error(first_label, first, e))?;
    for (dir, label) in dirs {
        let metadata = std::fs::metadata(dir).map_err(|e| io_error(label, dir, e))?;
        if let Some(problem) = shared_directory_problem(metadata.uid(), metadata.mode(), uid) {
            return Err(CodeQlHostError::new(
                CodeQlHostErrorKind::UnsafeDirectory,
                format!(
                    "the {label} '{}' cannot be used: {problem}; use a directory that only you can write to, such as ~/.cache/sentra-codeql",
                    display_path(dir)
                ),
            ));
        }
    }
    Ok(())
}

/// Windows has no Unix owner or mode bits; the directories are used as given.
#[cfg(not(unix))]
fn check_private_dirs(_dirs: &[(&Path, &str)]) -> Result<(), CodeQlHostError> {
    Ok(())
}

/// Nanoseconds since the Unix epoch (0 when the clock is before it), for unique names.
fn unique_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default()
}

/// CLI version from `codeql version --format=json` output (`{"version": "2.27.4", ...}`).
pub fn parse_codeql_version(stdout: &str) -> Option<String> {
    let from_json = serde_json::from_str::<serde_json::Value>(stdout.trim())
        .ok()
        .and_then(|v| v.get("version")?.as_str().map(str::to_string));
    let version = from_json.or_else(|| {
        // Tolerate surrounding noise: the first `"version" : "<value>"` pair.
        let start = stdout.find("\"version\"")? + "\"version\"".len();
        let rest = stdout[start..].trim_start().strip_prefix(':')?.trim_start();
        let rest = rest.strip_prefix('"')?;
        Some(rest[..rest.find('"')?].to_string())
    })?;
    (!version.is_empty() && version.len() <= 64 && version.chars().all(|c| c.is_ascii_graphic()))
        .then_some(version)
}

/// Whether `line` is a CodeQL progress line such as `[16/89] Loaded ...` or
/// `[86/89 eval 4ms] Evaluation done ...`.
fn is_progress_line(line: &str) -> bool {
    let Some(rest) = line.strip_prefix('[') else {
        return false;
    };
    let digits = rest.chars().take_while(char::is_ascii_digit).count();
    digits > 0 && rest[digits..].starts_with('/')
}

/// CodeQL's warning about a distribution installed directly below a file-system root,
/// printed by every step there; reported once as a Sentra warning instead.
fn is_root_install_warning(line: &str) -> bool {
    line.starts_with("WARNING: This CodeQL Distribution is installed in")
}

/// Markers of CodeQL or its Java VM running out of memory (heap reservation or commit,
/// including Windows error 1455, "the paging file is too small"). The first two were
/// observed with CodeQL 2.27.4 on Windows 11 on 2026-11-11.
const JVM_MEMORY_MARKERS: &[&str] = &[
    "os::commit_memory",
    "CodeQL is out of memory",
    "errno=1455",
    "OutOfMemoryError",
    "insufficient memory for the Java Runtime",
    "Could not reserve enough space",
];

/// Explanation prepended when a step failed because CodeQL's Java VM got no memory.
pub const JVM_MEMORY_HINT: &str = "CodeQL's Java VM could not get the memory it asked for (the host is short of free memory or page file); pass a --ram value that fits the free memory, or free memory on the host";

/// Last non-empty lines of a step's output, without control characters, bounded.
/// CodeQL progress lines and its root-installation warning are left out when other lines
/// exist, so the error itself is kept.
fn output_excerpt(run: &ContainedRun) -> String {
    let source = if run.stderr_tail.trim().is_empty() {
        &run.stdout_tail
    } else {
        &run.stderr_tail
    };
    let all: Vec<&str> = source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let informative: Vec<&str> = all
        .iter()
        .copied()
        .filter(|line| !is_progress_line(line) && !is_root_install_warning(line))
        .collect();
    let lines = if informative.is_empty() {
        all
    } else {
        informative
    };
    let start = lines.len().saturating_sub(3);
    let joined = lines[start..].join(" | ");
    let cleaned: String = joined.chars().filter(|c| !c.is_control()).collect();
    if cleaned.chars().count() > 600 {
        let mut cut: String = cleaned.chars().take(600).collect();
        cut.push_str("...");
        cut
    } else {
        cleaned
    }
}

fn step_failure(step: &str, run: &ContainedRun) -> String {
    let excerpt = output_excerpt(run);
    let code = run
        .exit_code
        .map(|c| c.to_string())
        .unwrap_or_else(|| "none (terminated)".into());
    let out_of_memory = [&run.stderr_tail, &run.stdout_tail].iter().any(|text| {
        JVM_MEMORY_MARKERS
            .iter()
            .any(|marker| text.contains(marker))
    });
    let hint = if out_of_memory {
        format!("{JVM_MEMORY_HINT}. ")
    } else {
        String::new()
    };
    if excerpt.is_empty() {
        format!("{hint}{step} exited with code {code}")
    } else {
        format!("{hint}{step} exited with code {code}: {excerpt}")
    }
}

/// Mutable state of one analysis.
struct Session<'a> {
    launcher: &'a CodeQlLauncher,
    dirs: &'a CodeQlRunDirs,
    env: &'a [(OsString, OsString)],
    deadline: Instant,
    cancel: &'a AtomicBool,
    report: CodeQlResultReport,
}

/// Result of one CodeQL step.
enum StepResult {
    Done(ContainedRun),
    TimedOut,
    Cancelled,
    SpawnFailed(String),
}

impl Session<'_> {
    fn run(&self, args: &[OsString], cap: Option<Duration>, tail_bytes: usize) -> StepResult {
        if self.cancel.load(Ordering::SeqCst) {
            return StepResult::Cancelled;
        }
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        let limit = cap.map_or(remaining, |cap| cap.min(remaining));
        if limit.is_zero() {
            return StepResult::TimedOut;
        }
        match run_contained_cancellable(
            &self.launcher.program,
            args,
            &self.dirs.run,
            self.env,
            limit,
            tail_bytes,
            self.cancel,
        ) {
            Ok(run) if run.cancelled => StepResult::Cancelled,
            Ok(run) if run.timed_out => {
                if cap.is_some_and(|cap| cap < remaining) {
                    StepResult::Done(run)
                } else {
                    StepResult::TimedOut
                }
            }
            Ok(run) => StepResult::Done(run),
            Err(e) => StepResult::SpawnFailed(e.to_string()),
        }
    }

    fn cancel_error(mut self, during: &str) -> CodeQlHostError {
        self.report.warnings.push(format!(
            "the analysis was cancelled during {during}; the CodeQL process tree was killed"
        ));
        CodeQlHostError {
            kind: CodeQlHostErrorKind::Cancelled,
            message: format!(
                "the analysis was cancelled (during {during}); the CodeQL process tree was killed and partial results were discarded"
            ),
            report: Some(Box::new(self.report)),
        }
    }

    fn timeout_error(mut self, during: &str) -> CodeQlHostError {
        self.report.warnings.push(format!(
            "the time budget ran out during {during}; the CodeQL process tree was killed"
        ));
        CodeQlHostError {
            kind: CodeQlHostErrorKind::Timeout,
            message: format!(
                "CodeQL did not finish within the time budget (during {during}); the process tree was killed and partial results were discarded"
            ),
            report: Some(Box::new(self.report)),
        }
    }
}

/// Plan of one requested language.
enum Plan {
    Ready(PathBuf),
    NeedsDownload,
}

/// Runs a host analysis with injected file-system rules and caller environment.
pub fn analyze_workspace_with<I>(
    request: &CodeQlAnalyzeRequest,
    fs: &dyn LauncherFs,
    parent_env: I,
) -> Result<CodeQlResultReport, CodeQlHostError>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let started = Instant::now();
    if !request.terms_accepted {
        return Err(CodeQlHostError::new(
            CodeQlHostErrorKind::TermsNotAccepted,
            "host analysis runs the CodeQL CLI, which is licensed under the GitHub CodeQL Terms and Conditions (LICENSE.md in the CodeQL distribution); pass --accept-codeql-terms to confirm that this use is permitted for this codebase",
        ));
    }
    let workspace = std::fs::canonicalize(&request.workspace)
        .map(strip_verbatim)
        .ok()
        .filter(|w| w.is_dir())
        .ok_or_else(|| {
            CodeQlHostError::new(
                CodeQlHostErrorKind::InvalidWorkspace,
                format!(
                    "the workspace '{}' is not an accessible directory",
                    display_path(&request.workspace)
                ),
            )
        })?;
    if let Some(found) = cmd_metacharacters_in(&workspace, LauncherPlatform::current()) {
        return Err(CodeQlHostError::new(
            CodeQlHostErrorKind::InvalidWorkspace,
            format!(
                "the workspace path '{}' contains {found}: CodeQL's Windows extractor scripts expand the source directory unquoted (set LGTM_SRC=%CD%), so cmd.exe would run part of the path, or a file in the workspace it names, as a command; host analysis refuses such paths. Analyse a copy under a path without & ^ ! %, or import a SARIF produced elsewhere",
                display_path(&workspace)
            ),
        ));
    }
    let launcher = validate_codeql_launcher_with(&request.codeql, LauncherPlatform::current(), fs)?;
    let work_dir = prepare_outside_dir(
        &request.work_dir,
        &workspace,
        CodeQlHostErrorKind::WorkDirInsideWorkspace,
        "work directory",
    )?;
    let pack_cache = prepare_outside_dir(
        &request.pack_cache,
        &workspace,
        CodeQlHostErrorKind::PackCacheInsideWorkspace,
        "pack cache",
    )?;

    let mut languages: Vec<CodeQlHostLanguage> = Vec::new();
    let requested = if request.languages.is_empty() {
        detect_host_languages(&workspace).map_err(|e| {
            CodeQlHostError::new(
                CodeQlHostErrorKind::InvalidWorkspace,
                format!("the workspace languages could not be detected: {e}"),
            )
        })?
    } else {
        request.languages.clone()
    };
    for language in requested {
        if !languages.contains(&language) {
            languages.push(language);
        }
    }

    check_private_dirs(&[(&work_dir, "work directory"), (&pack_cache, "pack cache")])?;

    let dirs = CodeQlRunDirs::new(work_dir.join(format!(
        "sentra-codeql-{}-{}",
        std::process::id(),
        unique_nanos()
    )));
    // The run directory must be new (never reused) and, on Unix, private.
    if let Err(e) = private_dir_builder(false).create(&dirs.run) {
        return Err(CodeQlHostError::new(
            CodeQlHostErrorKind::Io,
            format!("the run directory cannot be created: {e}"),
        ));
    }
    let mut created = vec![dirs.tmp.clone(), dirs.home.clone()];
    if LauncherPlatform::current() == LauncherPlatform::Windows {
        created.push(dirs.home.join("AppData"));
        created.push(dirs.home.join("AppData").join("Roaming"));
        created.push(dirs.home.join("AppData").join("Local"));
    }
    for dir in &created {
        if let Err(e) = private_dir_builder(false).create(dir) {
            let _ = std::fs::remove_dir_all(&dirs.run);
            return Err(CodeQlHostError::new(
                CodeQlHostErrorKind::Io,
                format!("the run directory cannot be created: {e}"),
            ));
        }
    }
    let env = codeql_host_environment(parent_env, &dirs, &workspace, LauncherPlatform::current());
    let never = AtomicBool::new(false);
    let cancel: &AtomicBool = request.cancel.as_deref().unwrap_or(&never);

    let mut warnings = Vec::new();
    if launcher
        .distribution
        .parent()
        .is_some_and(|p| p.parent().is_none())
    {
        warnings.push(format!(
            "CodeQL is installed directly below a drive or file-system root ({}): CodeQL searches the directories next to its distribution for any pack it cannot find otherwise, which there means the whole drive, so Sentra runs only query suites whose pack is already in the distribution or the pack cache",
            display_path(&launcher.distribution)
        ));
    }
    let session = Session {
        launcher: &launcher,
        dirs: &dirs,
        env: &env,
        deadline: started + request.timeout,
        cancel,
        report: CodeQlResultReport {
            schema_version: 1,
            command: "codeql analyze",
            workspace: display_path(&workspace),
            codeql_version: None,
            suite: Some(request.suite.as_str().to_string()),
            pack_download_allowed: request.allow_pack_download,
            target_code_executed: false,
            languages: Vec::new(),
            findings: Vec::new(),
            results_total: 0,
            results_outside_workspace: 0,
            truncated: false,
            warnings,
            source_tool: None,
        },
    };
    let outcome = run_session(session, request, &languages, &workspace, &pack_cache);
    let cleanup = std::fs::remove_dir_all(&dirs.run);
    match (outcome, cleanup) {
        (Ok(mut report), Err(e)) => {
            report.warnings.push(format!(
                "the run directory '{}' could not be deleted: {e}",
                display_path(&dirs.run)
            ));
            Ok(report)
        }
        (Err(mut error), Err(e)) => {
            if let Some(report) = error.report.as_mut() {
                report.warnings.push(format!(
                    "the run directory '{}' could not be deleted: {e}",
                    display_path(&dirs.run)
                ));
            }
            Err(error)
        }
        (outcome, Ok(())) => outcome,
    }
}

fn run_session(
    mut session: Session<'_>,
    request: &CodeQlAnalyzeRequest,
    languages: &[CodeQlHostLanguage],
    workspace: &Path,
    pack_cache: &Path,
) -> Result<CodeQlResultReport, CodeQlHostError> {
    let distribution = session.launcher.distribution.clone();

    // 1. CLI version; also proves the launcher starts.
    match session.run(
        &codeql_version_args(pack_cache),
        Some(CODEQL_VERSION_TIMEOUT),
        CODEQL_VERSION_OUTPUT_BYTES,
    ) {
        StepResult::SpawnFailed(e) => {
            return Err(CodeQlHostError::new(
                CodeQlHostErrorKind::NotFound,
                format!(
                    "the CodeQL launcher '{}' could not be started: {e}",
                    display_path(&session.launcher.program)
                ),
            ));
        }
        StepResult::TimedOut => return Err(session.timeout_error("codeql version")),
        StepResult::Cancelled => return Err(session.cancel_error("codeql version")),
        StepResult::Done(run) if run.exit_code == Some(0) && !run.timed_out => {
            session.report.codeql_version = parse_codeql_version(&run.stdout_tail);
            if session.report.codeql_version.is_none() {
                session
                    .report
                    .warnings
                    .push("codeql version did not report a version".into());
            }
        }
        StepResult::Done(run) => {
            let reason = if run.timed_out {
                "codeql version did not answer within 120 seconds".to_string()
            } else {
                step_failure("codeql version", &run)
            };
            session.report.warnings.push(reason);
        }
    }

    // 2. Plan every language without running CodeQL.
    let mut plans: Vec<(CodeQlHostLanguage, Plan)> = Vec::new();
    let mut pack_missing = 0_usize;
    for &language in languages {
        let skip = |reason: String| CodeQlLanguageOutcome {
            language: language.as_str().to_string(),
            status: CodeQlLanguageStatus::Skipped,
            reason: Some(reason),
            results: 0,
            duration_ms: None,
            rules: Vec::new(),
        };
        if let Some(reason) = language.host_block_reason() {
            session.report.languages.push(skip(reason.to_string()));
            continue;
        }
        match extractor_build_modes(&distribution, language) {
            None => {
                session.report.languages.push(skip(format!(
                    "the CodeQL distribution has no {language} extractor"
                )));
                continue;
            }
            Some(modes) if !modes.iter().any(|m| m == "none") => {
                session
                    .report
                    .languages
                    .push(skip(NEEDS_BUILD_REASON.to_string()));
                continue;
            }
            Some(_) => {}
        }
        match find_query_suite(language, request.suite, &distribution, pack_cache) {
            Some(suite_file) => plans.push((language, Plan::Ready(suite_file))),
            None if request.allow_pack_download => plans.push((language, Plan::NeedsDownload)),
            None => {
                pack_missing += 1;
                session.report.languages.push(skip(format!(
                    "query pack codeql/{language}-queries (suite {}) is not in the CodeQL distribution or the pack cache, and pack download is not allowed",
                    request.suite.file_name(language)
                )));
            }
        }
    }

    // 3. Downloads (only when allowed), then analysis per language.
    let mut analyzed = 0_usize;
    let mut failed = 0_usize;
    for (language, plan) in plans {
        let language_started = Instant::now();
        let fail = |reason: String| CodeQlLanguageOutcome {
            language: language.as_str().to_string(),
            status: CodeQlLanguageStatus::Failed,
            reason: Some(reason),
            results: 0,
            duration_ms: Some(language_started.elapsed().as_millis() as u64),
            rules: Vec::new(),
        };
        let suite_file = match plan {
            Plan::Ready(path) => path,
            Plan::NeedsDownload => {
                let pack = format!("codeql/{language}-queries");
                match session.run(
                    &codeql_pack_download_args(&pack, pack_cache),
                    None,
                    CODEQL_OUTPUT_TAIL_BYTES,
                ) {
                    StepResult::TimedOut => {
                        session.report.languages.push(fail("timed out".into()));
                        return Err(session.timeout_error(&format!("codeql pack download {pack}")));
                    }
                    StepResult::Cancelled => {
                        session.report.languages.push(fail("cancelled".into()));
                        return Err(session.cancel_error(&format!("codeql pack download {pack}")));
                    }
                    StepResult::SpawnFailed(e) => {
                        failed += 1;
                        session
                            .report
                            .languages
                            .push(fail(format!("codeql pack download could not start: {e}")));
                        continue;
                    }
                    StepResult::Done(run) if run.exit_code != Some(0) => {
                        failed += 1;
                        session
                            .report
                            .languages
                            .push(fail(step_failure("codeql pack download", &run)));
                        continue;
                    }
                    StepResult::Done(_) => {}
                }
                match find_query_suite(language, request.suite, &distribution, pack_cache) {
                    Some(path) => path,
                    None => {
                        failed += 1;
                        session.report.languages.push(fail(format!(
                            "codeql pack download finished, but {pack} with suite {} is not in the pack cache",
                            request.suite.file_name(language)
                        )));
                        continue;
                    }
                }
            }
        };

        let database = session.dirs.run.join(format!("db-{language}"));
        let sarif = session.dirs.run.join(format!("results-{language}.sarif"));
        let create = codeql_database_create_args(&DatabaseCreateSpec {
            database: &database,
            language,
            source_root: workspace,
            distribution: &distribution,
            pack_cache,
            threads: request.threads,
            ram_mb: request.ram_mb,
        });
        match session.run(&create, None, CODEQL_OUTPUT_TAIL_BYTES) {
            StepResult::TimedOut => {
                session.report.languages.push(fail("timed out".into()));
                return Err(session.timeout_error(&format!("codeql database create ({language})")));
            }
            StepResult::Cancelled => {
                session.report.languages.push(fail("cancelled".into()));
                return Err(session.cancel_error(&format!("codeql database create ({language})")));
            }
            StepResult::SpawnFailed(e) => {
                failed += 1;
                session
                    .report
                    .languages
                    .push(fail(format!("codeql database create could not start: {e}")));
                continue;
            }
            StepResult::Done(run) if run.exit_code != Some(0) => {
                failed += 1;
                session
                    .report
                    .languages
                    .push(fail(step_failure("codeql database create", &run)));
                let _ = std::fs::remove_dir_all(&database);
                continue;
            }
            StepResult::Done(_) => {}
        }
        let analyze = codeql_database_analyze_args(&DatabaseAnalyzeSpec {
            database: &database,
            suite_file: &suite_file,
            sarif: &sarif,
            distribution: &distribution,
            pack_cache,
            threads: request.threads,
            ram_mb: request.ram_mb,
        });
        let analyzed_run = session.run(&analyze, None, CODEQL_OUTPUT_TAIL_BYTES);
        let _ = std::fs::remove_dir_all(&database);
        match analyzed_run {
            StepResult::TimedOut => {
                session.report.languages.push(fail("timed out".into()));
                return Err(session.timeout_error(&format!("codeql database analyze ({language})")));
            }
            StepResult::Cancelled => {
                session.report.languages.push(fail("cancelled".into()));
                return Err(session.cancel_error(&format!("codeql database analyze ({language})")));
            }
            StepResult::SpawnFailed(e) => {
                failed += 1;
                session.report.languages.push(fail(format!(
                    "codeql database analyze could not start: {e}"
                )));
                continue;
            }
            StepResult::Done(run) if run.exit_code != Some(0) => {
                failed += 1;
                session
                    .report
                    .languages
                    .push(fail(step_failure("codeql database analyze", &run)));
                continue;
            }
            StepResult::Done(_) => {}
        }
        let remaining = request
            .max_results
            .saturating_sub(session.report.findings.len());
        let parsed = read_sarif_file(&sarif, CODEQL_ANALYSIS_SARIF_MAX_BYTES).and_then(|bytes| {
            normalize_codeql_sarif(
                &bytes,
                &CodeQlSarifOptions {
                    max_results: remaining,
                    default_language: Some(language.as_str().to_string()),
                },
            )
        });
        let _ = std::fs::remove_file(&sarif);
        let summary = match parsed {
            Ok(summary) => summary,
            Err(e) => {
                failed += 1;
                session.report.languages.push(fail(format!(
                    "the SARIF written by CodeQL could not be read: {e}"
                )));
                continue;
            }
        };
        analyzed += 1;
        let report = &mut session.report;
        if report.source_tool.is_none() {
            report.source_tool = summary.source_tool.clone();
        }
        report.results_total += summary.results_total;
        report.results_outside_workspace += summary.results_outside_workspace;
        report.truncated |= summary.truncated;
        for warning in summary.warnings {
            report.warnings.push(format!("{language}: {warning}"));
        }
        // Every rule in this language's SARIF ran for this language.
        let rules: BTreeSet<String> = summary.rule_ids.into_values().flatten().collect();
        report.languages.push(CodeQlLanguageOutcome {
            language: language.as_str().to_string(),
            status: CodeQlLanguageStatus::Analyzed,
            reason: None,
            results: summary.findings.len(),
            duration_ms: Some(language_started.elapsed().as_millis() as u64),
            rules: rules.into_iter().collect(),
        });
        report.findings.extend(summary.findings);
    }

    if languages.is_empty() {
        session
            .report
            .warnings
            .push("no CodeQL-supported source files were detected in the workspace".into());
    }
    let mut report = session.report;
    // Stable order: requested/detected language order.
    let order: BTreeMap<String, usize> = languages
        .iter()
        .enumerate()
        .map(|(i, l)| (l.as_str().to_string(), i))
        .collect();
    report
        .languages
        .sort_by_key(|outcome| order.get(&outcome.language).copied().unwrap_or(usize::MAX));
    if analyzed == 0 && failed == 0 && pack_missing > 0 {
        return Err(CodeQlHostError {
            kind: CodeQlHostErrorKind::QueryPackMissing,
            message: "no language could be analysed: the CodeQL query packs are not in the CodeQL distribution or the pack cache, and pack download is not allowed (install the CodeQL bundle, which includes the packs, or allow pack download)".into(),
            report: Some(Box::new(report)),
        });
    }
    if analyzed == 0 && failed > 0 {
        return Err(CodeQlHostError {
            kind: CodeQlHostErrorKind::Failed,
            message: "CodeQL failed for every language it was run for (see languages[].reason)"
                .into(),
            report: Some(Box::new(report)),
        });
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// In-memory file system for launcher validation (paths compared with `/`).
    #[derive(Default)]
    struct FakeFs {
        files: BTreeMap<String, Vec<u8>>,
        dirs: BTreeSet<String>,
        executable: BTreeSet<String>,
        extractors: BTreeSet<String>,
    }

    fn key(path: &Path) -> String {
        path.to_string_lossy().replace('\\', "/")
    }

    impl LauncherFs for FakeFs {
        fn canonicalize(&self, path: &Path) -> std::io::Result<PathBuf> {
            let k = key(path);
            if self.files.contains_key(&k) || self.dirs.contains(&k) {
                Ok(PathBuf::from(k))
            } else {
                Err(std::io::Error::from(std::io::ErrorKind::NotFound))
            }
        }
        fn is_file(&self, path: &Path) -> bool {
            self.files.contains_key(&key(path))
        }
        fn is_dir(&self, path: &Path) -> bool {
            self.dirs.contains(&key(path))
        }
        fn read_head(&self, path: &Path, len: usize) -> std::io::Result<Vec<u8>> {
            self.files
                .get(&key(path))
                .map(|b| b.iter().take(len).copied().collect())
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        }
        fn is_executable(&self, path: &Path) -> bool {
            self.executable.contains(&key(path))
        }
        fn has_extractor(&self, distribution: &Path) -> bool {
            self.extractors.contains(&key(distribution))
        }
    }

    fn windows_dist() -> FakeFs {
        let mut fs = FakeFs::default();
        fs.dirs.insert("D:/CodeQL".into());
        fs.dirs.insert("D:/CodeQL/tools".into());
        fs.files
            .insert("D:/CodeQL/codeql.exe".into(), b"MZ\x90\x00".to_vec());
        fs.files
            .insert("D:/CodeQL/codeql.cmd".into(), b"@echo off".to_vec());
        fs.files
            .insert("D:/CodeQL/codeql".into(), b"#!/bin/sh".to_vec());
        fs.files
            .insert("D:/CodeQL/.codeqlmanifest.json".into(), b"{}".to_vec());
        fs.files.insert("D:/Fake/codeql.exe".into(), b"MZ".to_vec());
        fs.dirs.insert("D:/Fake".into());
        fs.files
            .insert("D:/CodeQL/renamed.exe".into(), b"MZ".to_vec());
        fs
    }

    #[test]
    fn windows_launcher_must_be_a_pe_codeql_exe_in_a_distribution() {
        let fs = windows_dist();
        let launcher = validate_codeql_launcher_with(
            Path::new("D:/CodeQL/codeql.exe"),
            LauncherPlatform::Windows,
            &fs,
        )
        .unwrap();
        assert_eq!(key(&launcher.distribution), "D:/CodeQL");
        for (path, needle) in [
            ("D:/CodeQL/codeql.cmd", "codeql.cmd, .bat files"),
            ("D:/CodeQL/codeql", "codeql.cmd, .bat files"),
            ("D:/CodeQL/renamed.exe", "only the codeql.exe"),
            (
                "D:/Fake/codeql.exe",
                "does not live in a CodeQL distribution",
            ),
            ("D:/CodeQL/missing.exe", "does not exist"),
            ("D:/CodeQL", "not a file"),
        ] {
            let err =
                validate_codeql_launcher_with(Path::new(path), LauncherPlatform::Windows, &fs)
                    .unwrap_err();
            assert_eq!(err.kind, CodeQlHostErrorKind::NotFound, "{path}");
            assert!(err.message.contains(needle), "{path}: {}", err.message);
        }
        let mut fs = windows_dist();
        fs.files
            .insert("D:/CodeQL/codeql.exe".into(), b"#!".to_vec());
        let err = validate_codeql_launcher_with(
            Path::new("D:/CodeQL/codeql.exe"),
            LauncherPlatform::Windows,
            &fs,
        )
        .unwrap_err();
        assert!(err.message.contains("no PE header"), "{}", err.message);
    }

    #[test]
    fn unix_launcher_script_is_allowed_inside_a_distribution() {
        let mut fs = FakeFs::default();
        fs.dirs.insert("/opt/codeql".into());
        fs.dirs.insert("/opt/codeql/tools".into());
        fs.files
            .insert("/opt/codeql/codeql".into(), b"#!/bin/sh\n".to_vec());
        fs.executable.insert("/opt/codeql/codeql".into());
        fs.extractors.insert("/opt/codeql".into());
        fs.files
            .insert("/opt/codeql/codeql.exe".into(), b"MZ".to_vec());
        fs.executable.insert("/opt/codeql/codeql.exe".into());
        fs.files
            .insert("/usr/bin/codeql".into(), b"#!/bin/sh\n".to_vec());
        fs.executable.insert("/usr/bin/codeql".into());
        fs.dirs.insert("/usr/bin".into());
        fs.files
            .insert("/opt/other/codeql".into(), b"#!/bin/sh\n".to_vec());
        fs.dirs.insert("/opt/other".into());
        fs.dirs.insert("/opt/other/tools".into());

        let launcher = validate_codeql_launcher_with(
            Path::new("/opt/codeql/codeql"),
            LauncherPlatform::Unix,
            &fs,
        )
        .unwrap();
        assert_eq!(key(&launcher.program), "/opt/codeql/codeql");
        for (path, needle) in [
            ("/opt/codeql/codeql.exe", "file named codeql"),
            ("/usr/bin/codeql", "does not live in a CodeQL distribution"),
            ("/opt/other/codeql", "not executable"),
        ] {
            let err = validate_codeql_launcher_with(Path::new(path), LauncherPlatform::Unix, &fs)
                .unwrap_err();
            assert!(err.message.contains(needle), "{path}: {}", err.message);
        }
        fs.executable.insert("/opt/other/codeql".into());
        let err = validate_codeql_launcher_with(
            Path::new("/opt/other/codeql"),
            LauncherPlatform::Unix,
            &fs,
        )
        .unwrap_err();
        assert!(
            err.message
                .contains("does not live in a CodeQL distribution")
        );
    }

    #[test]
    fn language_policy_allows_only_extractors_that_do_not_run_project_code() {
        let allowed: Vec<&str> = CodeQlHostLanguage::ALL
            .iter()
            .filter(|l| l.host_block_reason().is_none())
            .map(CodeQlHostLanguage::as_str)
            .collect();
        assert_eq!(allowed, ["actions", "cpp", "javascript", "python", "ruby"]);
        assert_eq!(
            CodeQlHostLanguage::Go.host_block_reason(),
            Some(NEEDS_BUILD_REASON)
        );
        assert_eq!(
            CodeQlHostLanguage::Swift.host_block_reason(),
            Some(NEEDS_BUILD_REASON)
        );
        assert!(
            CodeQlHostLanguage::Rust
                .host_block_reason()
                .unwrap()
                .contains("build scripts")
        );
        assert!(
            CodeQlHostLanguage::Csharp
                .host_block_reason()
                .unwrap()
                .contains("dotnet restore")
        );
        assert!(
            CodeQlHostLanguage::Java
                .host_block_reason()
                .unwrap()
                .contains("gradlew")
        );
        assert_eq!(
            CodeQlHostLanguage::parse("TypeScript"),
            Some(CodeQlHostLanguage::Javascript)
        );
        assert_eq!(
            CodeQlHostLanguage::parse("c-cpp"),
            Some(CodeQlHostLanguage::Cpp)
        );
        assert_eq!(
            CodeQlHostLanguage::parse("c#"),
            Some(CodeQlHostLanguage::Csharp)
        );
        assert_eq!(CodeQlHostLanguage::parse("cobol"), None);
    }

    #[test]
    fn arguments_never_build_trace_or_download() {
        let db = Path::new("/w/run/db-python");
        let create = codeql_database_create_args(&DatabaseCreateSpec {
            database: db,
            language: CodeQlHostLanguage::Python,
            source_root: Path::new("/ws"),
            distribution: Path::new("/opt/codeql"),
            pack_cache: Path::new("/cache"),
            threads: Some(4),
            ram_mb: Some(4096),
        });
        let analyze = codeql_database_analyze_args(&DatabaseAnalyzeSpec {
            database: db,
            suite_file: Path::new(
                "/cache/packages/codeql/python-queries/1.0.0/codeql-suites/python-code-scanning.qls",
            ),
            sarif: Path::new("/w/run/results-python.sarif"),
            distribution: Path::new("/opt/codeql"),
            pack_cache: Path::new("/cache"),
            threads: None,
            ram_mb: None,
        });
        let text = |args: &[OsString]| -> Vec<String> {
            args.iter()
                .map(|a| a.to_string_lossy().replace('\\', "/"))
                .collect()
        };
        let create = text(&create);
        let analyze = text(&analyze);
        assert_eq!(&create[..3], ["database", "create", "/w/run/db-python"]);
        for expected in [
            "--language=python",
            "--build-mode=none",
            "--source-root=/ws",
            "--search-path=/opt/codeql",
            "--common-caches=/cache",
            "--threads=4",
            "--ram=4096",
        ] {
            assert!(
                create.contains(&expected.to_string()),
                "{expected} in {create:?}"
            );
        }
        assert_eq!(&analyze[..2], ["database", "analyze"]);
        assert!(analyze.contains(&"--format=sarif-latest".to_string()));
        assert!(analyze.contains(&"--common-caches=/cache".to_string()));
        for args in [&create, &analyze] {
            for arg in args {
                for banned in [
                    "--command",
                    "autobuild",
                    "manual",
                    "trace",
                    "--download",
                    "--build-mode=a",
                    "--build-mode=m",
                ] {
                    assert!(!arg.contains(banned), "{banned} in {arg}");
                }
            }
        }
        let download = text(&codeql_pack_download_args(
            "codeql/python-queries",
            Path::new("/cache"),
        ));
        assert_eq!(
            download,
            [
                "pack",
                "download",
                "codeql/python-queries",
                "--common-caches=/cache"
            ]
        );
        let version = text(&codeql_version_args(Path::new("/cache")));
        assert_eq!(
            version,
            ["version", "--format=json", "--common-caches=/cache"]
        );
    }

    #[test]
    fn codeql_version_is_read_from_json_or_a_noisy_tail() {
        assert_eq!(
            parse_codeql_version(r#"{"productName":"CodeQL","version":"2.27.4","features":{}}"#)
                .as_deref(),
            Some("2.27.4")
        );
        assert_eq!(
            parse_codeql_version(
                "warning
{ \"version\" : \"2.27.4\", \"x\": ["
            )
            .as_deref(),
            Some("2.27.4")
        );
        assert_eq!(parse_codeql_version(r#"{"version":"two words"}"#), None);
        assert_eq!(parse_codeql_version("no json"), None);
    }

    #[test]
    fn distribution_paths_with_search_path_separators_are_refused() {
        let mut fs = FakeFs::default();
        fs.dirs.insert("/opt/code:ql".into());
        fs.dirs.insert("/opt/code:ql/tools".into());
        fs.files
            .insert("/opt/code:ql/codeql".into(), b"#!/bin/sh".to_vec());
        fs.files
            .insert("/opt/code:ql/.codeqlmanifest.json".into(), b"{}".to_vec());
        fs.executable.insert("/opt/code:ql/codeql".into());
        let err = validate_codeql_launcher_with(
            Path::new("/opt/code:ql/codeql"),
            LauncherPlatform::Unix,
            &fs,
        )
        .unwrap_err();
        assert!(
            err.message.contains("search-path separator"),
            "{}",
            err.message
        );
    }

    fn finished_run(exit_code: i32, stderr: &str) -> ContainedRun {
        ContainedRun {
            exit_code: Some(exit_code),
            timed_out: false,
            cancelled: false,
            stdout_tail: String::new(),
            stdout_bytes: 0,
            stderr_tail: stderr.to_string(),
            stderr_bytes: stderr.len(),
            elapsed: Duration::from_secs(1),
        }
    }

    #[test]
    fn step_failures_skip_progress_lines_and_name_jvm_memory_errors() {
        // Shape of a real `codeql database analyze` failure (CodeQL 2.27.4, Windows 11,
        // 2026-11-11, host short of commit memory).
        let stderr = "Running queries.\n\
            [16/89] Loaded C:/cache/packages/codeql/javascript-queries/2.5.0/Security/CWE-022/ZipSlip.qlx.\n\
            [17/89] Loaded C:/cache/packages/codeql/javascript-queries/2.5.0/Security/CWE-073/TemplateObjectInjection.qlx.\n\
            OpenJDK 64-Bit Server VM warning: INFO: os::commit_memory(0x0000000763800000, 658505728, 0) failed; error='...' (DOS error/errno=1455)\n\
            [18/89 eval 4ms] Evaluation done; writing results.\n";
        let reason = step_failure("codeql database analyze", &finished_run(1, stderr));
        assert!(reason.starts_with(JVM_MEMORY_HINT), "{reason}");
        assert!(reason.contains("errno=1455"), "{reason}");
        assert!(!reason.contains("ZipSlip"), "{reason}");
        assert!(reason.contains("Running queries."), "{reason}");

        // Only progress lines: they are kept rather than reporting nothing.
        let reason = step_failure(
            "codeql database analyze",
            &finished_run(2, "[1/2] Loaded a.qlx.\n"),
        );
        assert_eq!(
            reason,
            "codeql database analyze exited with code 2: [1/2] Loaded a.qlx."
        );
        assert!(!is_progress_line("[WARNING] text"));
        assert!(is_progress_line("[86/89 eval 4ms] Evaluation done"));

        // Exit 99 of a real `codeql database analyze` on the same host: the root-install
        // warning is left out and the out-of-memory message is recognised.
        let stderr = "Running queries.\n\
            WARNING: This CodeQL Distribution is installed in 'D:\\', which is a root filesystem directory. This could cause performance issues.\n\
            CodeQL is out of memory. You may need to adjust the memory used by CodeQL using the --ram option.\n";
        let reason = step_failure("codeql database analyze", &finished_run(99, stderr));
        assert!(reason.starts_with(JVM_MEMORY_HINT), "{reason}");
        assert!(!reason.contains("root filesystem"), "{reason}");
        assert!(reason.ends_with("Running queries. | CodeQL is out of memory. You may need to adjust the memory used by CodeQL using the --ram option."), "{reason}");
    }

    #[test]
    fn build_modes_are_read_from_the_extractor_manifest() {
        let yml = "name: \"go\"\nbuild_modes:\n  - autobuild\n  - manual\ndefault_queries:\n  - codeql/go-queries\n";
        assert_eq!(parse_build_modes(yml), ["autobuild", "manual"]);
        let yml = "build_modes:\n  - none\n\n# comment\noptions:\n";
        assert_eq!(parse_build_modes(yml), ["none"]);
        assert!(parse_build_modes("name: x\n").is_empty());
    }

    #[test]
    fn environment_is_allowlisted_and_redirected() {
        let dirs = CodeQlRunDirs::new(PathBuf::from(if cfg!(windows) {
            "C:/work/run"
        } else {
            "/work/run"
        }));
        let workspace = PathBuf::from(if cfg!(windows) { "C:/ws" } else { "/ws" });
        let inside = workspace.join("bin");
        let outside = PathBuf::from(if cfg!(windows) {
            "C:/Windows/System32"
        } else {
            "/usr/bin"
        });
        let path = std::env::join_paths([
            inside.clone(),
            PathBuf::from("relative/bin"),
            outside.clone(),
        ])
        .unwrap();
        let parent: Vec<(OsString, OsString)> = vec![
            ("PATH".into(), path),
            ("SystemRoot".into(), "C:/Windows".into()),
            ("LANG".into(), "en_US.UTF-8".into()),
            ("GITHUB_TOKEN".into(), "ghp_secret".into()),
            ("GH_TOKEN".into(), "gho_secret".into()),
            ("OPENAI_API_KEY".into(), "sk-secret".into()),
            ("SENTRA_WEB_TOKENS".into(), "secret".into()),
            ("CODEQL_EXTRACTOR_PYTHON_OPTION_X".into(), "y".into()),
            ("JAVA_TOOL_OPTIONS".into(), "-javaagent:x".into()),
            ("TEMP".into(), "C:/Users/op/AppData/Local/Temp".into()),
            ("HOME".into(), "/home/op".into()),
        ];
        let platform = LauncherPlatform::current();
        let env = codeql_host_environment(parent, &dirs, &workspace, platform);
        let get = |name: &str| {
            env.iter()
                .filter(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
                .collect::<Vec<_>>()
        };
        for secret in [
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "OPENAI_API_KEY",
            "SENTRA_WEB_TOKENS",
            "JAVA_TOOL_OPTIONS",
            "CODEQL_EXTRACTOR_PYTHON_OPTION_X",
        ] {
            assert!(get(secret).is_empty(), "{secret} leaked");
        }
        assert_eq!(get("TEMP"), [dirs.tmp.clone().into_os_string()]);
        assert_eq!(get("TMP"), [dirs.tmp.clone().into_os_string()]);
        assert_eq!(get("HOME"), [dirs.home.clone().into_os_string()]);
        assert_eq!(get("LANG"), [OsString::from("en_US.UTF-8")]);
        assert_eq!(
            get("CODEQL_EXTRACTOR_PYTHON_ENABLE_SITE"),
            [OsString::from("1")]
        );
        assert_eq!(get("PYTHONDONTWRITEBYTECODE"), [OsString::from("1")]);
        let kept: Vec<PathBuf> = std::env::split_paths(&get("PATH")[0]).collect();
        assert_eq!(kept, [outside]);
        if platform == LauncherPlatform::Windows {
            assert_eq!(
                get("NoDefaultCurrentDirectoryInExePath"),
                [OsString::from("1")]
            );
            assert_eq!(get("USERPROFILE"), [dirs.home.clone().into_os_string()]);
            assert_eq!(get("SystemRoot"), [OsString::from("C:/Windows")]);
        }
    }

    #[test]
    fn query_suites_prefer_the_distribution_then_the_highest_cached_version() {
        let root = std::env::temp_dir().join(format!(
            "sentra-codeql-suite-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let dist = root.join("dist");
        let cache = root.join("cache");
        let make = |base: &Path, version: &str, suite: &str| {
            let dir = base.join("codeql").join("python-queries").join(version);
            std::fs::create_dir_all(dir.join("codeql-suites")).unwrap();
            std::fs::write(dir.join("qlpack.yml"), "name: codeql/python-queries\n").unwrap();
            std::fs::write(dir.join("codeql-suites").join(suite), "- queries: .\n").unwrap();
        };
        assert_eq!(
            find_query_suite(
                CodeQlHostLanguage::Python,
                CodeQlSuite::CodeScanning,
                &dist,
                &cache
            ),
            None
        );
        make(&cache.join("packages"), "1.2.0", "python-code-scanning.qls");
        make(
            &cache.join("packages"),
            "1.10.0",
            "python-code-scanning.qls",
        );
        make(
            &cache.join("packages"),
            "1.11.0-dev",
            "python-code-scanning.qls",
        );
        make(
            &cache.join("packages"),
            "2.0.0",
            "python-security-extended.qls",
        );
        let found = find_query_suite(
            CodeQlHostLanguage::Python,
            CodeQlSuite::CodeScanning,
            &dist,
            &cache,
        )
        .unwrap();
        assert!(
            found.ends_with(Path::new(
                "1.11.0-dev/codeql-suites/python-code-scanning.qls"
            )) || found.to_string_lossy().contains("1.11.0-dev"),
            "{found:?}"
        );
        make(&dist.join("qlpacks"), "0.9.0", "python-code-scanning.qls");
        let found = find_query_suite(
            CodeQlHostLanguage::Python,
            CodeQlSuite::CodeScanning,
            &dist,
            &cache,
        )
        .unwrap();
        assert!(found.starts_with(&dist), "{found:?}");
        let extended = find_query_suite(
            CodeQlHostLanguage::Python,
            CodeQlSuite::SecurityExtended,
            &dist,
            &cache,
        )
        .unwrap();
        assert!(extended.to_string_lossy().contains("2.0.0"), "{extended:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cmd_metacharacters_are_found_only_on_windows() {
        // Reproduced on Windows 11: a batch line `set LGTM_SRC=%CD%` run with the working
        // directory `ws&echo INJECTED&rem x` printed INJECTED.
        let path = Path::new("C:/src/R&D/app");
        assert_eq!(
            cmd_metacharacters_in(path, LauncherPlatform::Windows).as_deref(),
            Some("'&'")
        );
        assert_eq!(cmd_metacharacters_in(path, LauncherPlatform::Unix), None);
        assert_eq!(
            cmd_metacharacters_in(Path::new("C:/a^b/c!d/100%"), LauncherPlatform::Windows)
                .as_deref(),
            Some("'^', '!', '%'")
        );
        for safe in [
            "C:/Program Files (x86)/repo",
            "D:/work/my-repo_1.2",
            "C:/Users/op/proje;ct",
        ] {
            assert_eq!(
                cmd_metacharacters_in(Path::new(safe), LauncherPlatform::Windows),
                None,
                "{safe}"
            );
        }
    }

    #[test]
    fn launcher_in_a_distribution_path_with_cmd_metacharacters_is_refused() {
        let mut fs = FakeFs::default();
        fs.dirs.insert("D:/R&D/CodeQL".into());
        fs.dirs.insert("D:/R&D/CodeQL/tools".into());
        fs.files
            .insert("D:/R&D/CodeQL/codeql.exe".into(), b"MZ".to_vec());
        fs.files
            .insert("D:/R&D/CodeQL/.codeqlmanifest.json".into(), b"{}".to_vec());
        let err = validate_codeql_launcher_with(
            Path::new("D:/R&D/CodeQL/codeql.exe"),
            LauncherPlatform::Windows,
            &fs,
        )
        .unwrap_err();
        assert_eq!(err.kind, CodeQlHostErrorKind::NotFound);
        assert!(err.message.contains("'&'"), "{}", err.message);
    }

    #[test]
    fn shared_directories_are_refused() {
        assert_eq!(shared_directory_problem(1000, 0o40700, 1000), None);
        assert_eq!(shared_directory_problem(1000, 0o40755, 1000), None);
        assert!(
            shared_directory_problem(1001, 0o40700, 1000)
                .unwrap()
                .contains("another user")
        );
        for mode in [0o40775, 0o40757, 0o41777, 0o40777] {
            assert!(
                shared_directory_problem(1000, mode, 1000)
                    .unwrap()
                    .contains("can write"),
                "{mode:o}"
            );
        }
        assert_eq!(
            CodeQlHostErrorKind::UnsafeDirectory.code(),
            "unsafe_directory"
        );
        assert_eq!(CodeQlHostErrorKind::Cancelled.code(), "codeql_cancelled");
    }
}
