//! Adapter process supervision: executable resolution, environment scrubbing, bounded
//! stdio pumps and process-tree termination (REQ-F16, REQ-S06).
//!
//! Tree termination:
//! - Windows: right after it starts, the adapter is assigned to a Job Object created
//!   with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (no breakaway allowed). Every descendant
//!   joins the job, including detached ones, and closing the job when the session ends
//!   (or when the host process exits) terminates all of them, also after the adapter
//!   itself has exited. If the job cannot be created or assigned, the host falls back
//!   to `taskkill /T /F`, which only reaches descendants while the adapter is alive.
//! - Unix: the adapter leads a new process group, which outlives its leader. On Linux
//!   and macOS the adapter also gets a per-session [`CONTAINMENT_ENV`] variable that
//!   its descendants inherit. When the session ends, the host reads the process table
//!   (`/proc` on Linux, `ps -E` on macOS) and sends `SIGKILL` with the system `kill`
//!   utility to the group and to every live process of the tree: the adapter while it
//!   has not been reaped, every process whose initial environment carries the
//!   variable, and every descendant of either by parent process id. The table is read
//!   before anything is signalled, so children are still linked to their parents, and
//!   again after each round until nothing is left (a bounded number of rounds).
//!   This also reaches descendants that left the group with `setsid` or `setpgid`
//!   (Node documents `detached: true` as starting a new session; Bun's left the group
//!   on Linux in CI), including descendants of an adapter that has already exited.
//!   Other Unix systems only kill the group.
//! - The tree is always killed before the adapter's stdin is closed: a stdin-driven
//!   adapter exits on end of input, and on the fallback path its children would then
//!   be unreachable.
//!
//! Residual risks:
//! - Windows: a descendant created in the moment between process creation and job
//!   assignment, or any descendant when job assignment fails, is not contained.
//! - Linux and macOS: a descendant that left the process group and does not carry
//!   [`CONTAINMENT_ENV`] in its initial environment (it was started with an
//!   environment without it, or its environment cannot be read, for example after it
//!   changed user) is found only through its parent: once its parent chain up to the
//!   adapter or a marked process has exited, it is not killed. On macOS with System
//!   Integrity Protection enabled, the kernel withholds the environment of a process
//!   whose code signature is restricted (`CS_RESTRICT`, as for Apple's own binaries)
//!   from `ps -E` (`sysctl_procargsx` in XNU's `bsd/kern/kern_sysctl.c`), so such a
//!   process never counts as marked; which third-party binaries (Bun, a JDK) are
//!   restricted was not checked, and GitHub-hosted macOS runners, where the CI tests
//!   run, are reported to have SIP disabled, so CI does not cover this case. The
//!   variable is not a secret, so a process outside the tree that carries it is
//!   killed too. A process id can be reused by an unrelated process between reading
//!   the table and `kill` (milliseconds). When `/proc` or `ps` cannot be read, only
//!   the group is killed.
//! - Other Unix systems: a descendant that calls `setsid` or `setpgid` leaves the
//!   process group and is not killed.
//! - Inheritable handles of the host process (including its own stdout) can be
//!   inherited by the adapter tree on Windows; they are released only when every
//!   process holding them has exited, which the Job Object guarantees at session end.
//! - Memory and network egress are not limited.

use std::{
    collections::{BTreeSet, hash_map::RandomState},
    ffi::{OsStr, OsString},
    hash::BuildHasher,
    io::{BufRead, BufReader, Read, Write},
    path::{Component, Path, PathBuf, Prefix},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::plugin::error::PluginError;

/// Environment variables passed to adapters; everything else is cleared.
///
/// Matches the web console bridge allowlist. Names are compared case-insensitively on
/// Windows. Provider keys and tokens are never forwarded.
pub const ADAPTER_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "PROGRAMDATA",
    "LANG",
    "LC_ALL",
];

/// Most stderr bytes kept for diagnostics (the rest is counted and discarded).
pub const STDERR_TAIL_BYTES: usize = 16 * 1024;

/// Environment variable that marks every process of one contained tree on Linux and
/// macOS (see the module documentation).
///
/// The host sets it for each adapter and each [`run_contained`] program in addition to
/// the variables it passes on; descendants inherit it unless they are started with an
/// environment without it. The value only identifies one session or run (host process
/// id, a sequence number and random bits) and is not a secret. It is not set on Windows
/// (the Job Object contains the tree) or on other Unix systems (no process-table scan).
pub const CONTAINMENT_ENV: &str = "CONTAINED_BY_SENTRA";

const STDERR_CHUNK_BYTES: usize = 8 * 1024;
const STDOUT_BUFFER_BYTES: usize = 64 * 1024;
const EXIT_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Longest wait for the stderr pump to reach end of file after the tree was killed. The
/// pipe closes once every process holding it has exited; only a descendant that
/// escaped containment can keep it open this long.
const STDERR_DRAIN_GRACE: Duration = Duration::from_secs(2);

/// Whether the process table is scanned for the tree (Linux `/proc`, macOS `ps`).
const PROCESS_TABLE_SCAN: bool = cfg!(any(target_os = "linux", target_os = "macos"));

/// Scan-and-kill rounds before a tree that keeps changing is given up on.
const KILL_ROUNDS: usize = 10;

/// Pause before the process table is read again, so that killed processes have exited.
const KILL_ROUND_PAUSE: Duration = Duration::from_millis(10);

/// Most targets passed to one `kill` invocation.
const KILL_BATCH: usize = 256;

/// Most bytes read from one `/proc/<pid>/environ`.
const ENVIRON_READ_LIMIT: u64 = 4 * 1024 * 1024;

/// Filters an environment down to [`ADAPTER_ENV_ALLOWLIST`].
pub fn adapter_environment<I>(vars: I) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    vars.into_iter()
        .filter(|(name, _)| name.to_str().is_some_and(is_allowed_env_name))
        .collect()
}

fn is_allowed_env_name(name: &str) -> bool {
    ADAPTER_ENV_ALLOWLIST.iter().any(|allowed| {
        if cfg!(windows) {
            allowed.eq_ignore_ascii_case(name)
        } else {
            *allowed == name
        }
    })
}

fn env_value<'a>(env: &'a [(OsString, OsString)], name: &str) -> Option<&'a OsStr> {
    env.iter()
        .find(|(key, _)| {
            key.to_str().is_some_and(|k| {
                if cfg!(windows) {
                    k.eq_ignore_ascii_case(name)
                } else {
                    k == name
                }
            })
        })
        .map(|(_, value)| value.as_os_str())
}

/// Resolved adapter program and arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterCommand {
    /// Absolute path of the program that is started.
    pub program: PathBuf,
    /// Arguments passed to it, without shell interpretation.
    pub args: Vec<String>,
}

/// Resolves a manifest command line to an absolute program.
///
/// - A program containing a path separator is resolved against `adapter_dir` (never
///   against the host's working directory) and must stay inside it after
///   canonicalization.
/// - An absolute program path is used as given and must exist.
/// - A bare name is looked up in the absolute entries of `PATH` from `env` (with
///   `PATHEXT` on Windows); `python` and `python3` fall back to each other.
pub fn resolve_adapter_command(
    argv: &[String],
    adapter_dir: &Path,
    env: &[(OsString, OsString)],
) -> Result<AdapterCommand, PluginError> {
    let (first, rest) = argv
        .split_first()
        .filter(|(first, _)| !first.is_empty())
        .ok_or_else(|| PluginError::invalid_manifest("Executable path cannot be empty"))?;
    let adapter_root = std::fs::canonicalize(adapter_dir).map_err(|e| {
        PluginError::executable_rejected(format!(
            "adapter directory '{}' is not accessible: {e}",
            adapter_dir.display()
        ))
    })?;

    let candidate = Path::new(first);
    let program = if candidate.is_absolute() {
        existing_file(candidate)?
    } else if first.contains(['/', '\\', ':']) {
        if candidate
            .components()
            .any(|c| matches!(c, Component::Prefix(_) | Component::RootDir))
        {
            return Err(PluginError::executable_rejected(format!(
                "'{first}' is neither absolute nor relative to the adapter directory"
            )));
        }
        let resolved = existing_file(&adapter_root.join(candidate))?;
        if !resolved.starts_with(&adapter_root) {
            return Err(PluginError::executable_rejected(format!(
                "'{first}' resolves outside the adapter directory"
            )));
        }
        resolved
    } else {
        let alternates: &[&str] = match first.as_str() {
            "python" => &["python", "python3"],
            "python3" => &["python3", "python"],
            _ => &[],
        };
        let names: Vec<&str> = if alternates.is_empty() {
            vec![first.as_str()]
        } else {
            alternates.to_vec()
        };
        names
            .iter()
            .find_map(|name| search_path(name, env))
            .ok_or_else(|| {
                PluginError::executable_rejected(format!(
                    "'{first}' was not found on PATH (the adapter directory and the current directory are not searched for bare names; use './{first}')"
                ))
            })?
    };

    Ok(AdapterCommand {
        program: strip_verbatim(program),
        args: rest.to_vec(),
    })
}

fn existing_file(path: &Path) -> Result<PathBuf, PluginError> {
    let resolved = std::fs::canonicalize(path).map_err(|e| {
        PluginError::executable_rejected(format!("'{}' is not accessible: {e}", path.display()))
    })?;
    if !resolved.is_file() {
        return Err(PluginError::executable_rejected(format!(
            "'{}' is not a file",
            path.display()
        )));
    }
    Ok(resolved)
}

fn search_path(name: &str, env: &[(OsString, OsString)]) -> Option<PathBuf> {
    let path_var = env_value(env, "PATH")?;
    let extensions = executable_extensions(name, env);
    std::env::split_paths(path_var)
        .filter(|dir| dir.is_absolute())
        .flat_map(|dir| {
            extensions
                .iter()
                .map(move |ext| dir.join(format!("{name}{ext}")))
        })
        .find(|candidate| is_executable_file(candidate))
}

/// Suffixes tried for a bare program name (`PATHEXT` on Windows, none elsewhere).
fn executable_extensions(name: &str, env: &[(OsString, OsString)]) -> Vec<String> {
    if !cfg!(windows) {
        return vec![String::new()];
    }
    let pathext = env_value(env, "PATHEXT")
        .and_then(OsStr::to_str)
        .unwrap_or(".COM;.EXE;.BAT;.CMD");
    let extensions: Vec<String> = pathext
        .split(';')
        .filter(|e| e.starts_with('.') && e.len() > 1)
        .map(str::to_ascii_lowercase)
        .collect();
    let lower = name.to_ascii_lowercase();
    if extensions.iter().any(|ext| lower.ends_with(ext.as_str())) {
        vec![String::new()]
    } else {
        extensions
    }
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

/// Turns `\\?\C:\x` into `C:\x` and `\\?\UNC\s\x` into `\\s\x`; other paths unchanged.
pub(crate) fn strip_verbatim(path: PathBuf) -> PathBuf {
    let Some(Component::Prefix(prefix)) = path.components().next() else {
        return path;
    };
    let rest: PathBuf = path.components().skip(1).collect();
    match prefix.kind() {
        Prefix::VerbatimDisk(letter) => {
            PathBuf::from(format!("{}:\\", char::from(letter))).join(rest)
        }
        Prefix::VerbatimUNC(server, share) => {
            let mut unc = OsString::from(r"\\");
            unc.push(server);
            unc.push(r"\");
            unc.push(share);
            unc.push(r"\");
            PathBuf::from(unc).join(rest)
        }
        _ => path,
    }
}

/// Events produced by the stdio pump threads.
#[derive(Debug)]
pub(crate) enum PumpEvent {
    /// One stdout line without its terminator.
    Frame(Vec<u8>),
    /// A stdout line grew past the frame limit before a newline arrived.
    FrameTooLarge(usize),
    /// stdout reached end of file.
    StdoutClosed,
    /// Reading stdout failed.
    StdoutFailed(String),
    /// Bytes drained from stderr.
    Stderr(usize),
}

/// Bounded tail of the adapter's stderr.
#[derive(Debug, Default)]
struct StderrTail {
    bytes: Vec<u8>,
    total: usize,
}

impl StderrTail {
    fn push(&mut self, chunk: &[u8]) {
        self.total = self.total.saturating_add(chunk.len());
        self.bytes.extend_from_slice(chunk);
        if self.bytes.len() > STDERR_TAIL_BYTES {
            let excess = self.bytes.len() - STDERR_TAIL_BYTES;
            self.bytes.drain(..excess);
        }
    }
}

/// Final observations about one adapter process.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProcessSummary {
    pub exit_code: Option<i32>,
    pub killed_by_host: bool,
    pub stderr_bytes: usize,
    pub stderr_tail: String,
}

/// A running adapter whose whole tree is killed on every exit path, including drop.
pub(crate) struct AdapterProcess {
    child: Child,
    tree: TreeGuard,
    events: mpsc::Receiver<PumpEvent>,
    stdin: Option<mpsc::Sender<Vec<u8>>>,
    stderr: Arc<Mutex<StderrTail>>,
    /// Signalled (or disconnected) once the stderr pump has reached end of file.
    stderr_drained: mpsc::Receiver<()>,
    finished: Option<ProcessSummary>,
}

/// Windows containment: a kill-on-close Job Object holding the process tree.
#[cfg(windows)]
struct JobTree(Option<win32job::Job>);

#[cfg(windows)]
impl JobTree {
    /// Nothing is configured before the process starts.
    fn prepare(_builder: &mut Command) -> Self {
        Self(None)
    }

    /// Creates the job and assigns the process; no job when either step fails.
    fn attach(&mut self, child: &Child) {
        use std::os::windows::io::AsRawHandle;

        let mut limits = win32job::ExtendedLimitInfo::new();
        limits.limit_kill_on_job_close();
        self.0 = win32job::Job::create_with_limit_info(&limits)
            .ok()
            .filter(|job| job.assign_process(child.as_raw_handle() as isize).is_ok());
    }

    /// Whether the process was assigned to the job.
    fn has_job(&self) -> bool {
        self.0.is_some()
    }

    /// Closes the job (the last handle to it), terminating every process still in it.
    fn close_job(&mut self) {
        self.0 = None;
    }

    /// Fallback without a job: `taskkill /T /F`, which walks the tree from `pid` and so
    /// only reaches descendants while that process is alive.
    fn kill_tree(&self, pid: u32, _leader_reaped: bool) {
        let system_root = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        let taskkill = system_root.join("System32").join("taskkill.exe");
        let _ = Command::new(taskkill)
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .env_clear()
            .env("SystemRoot", &system_root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[cfg(windows)]
type TreeGuard = JobTree;

/// Unix containment: the process group plus, on Linux and macOS, the
/// [`CONTAINMENT_ENV`] marker and process-table scans (see the module documentation).
///
/// Compiled on every platform so that Windows builds type-check it; only Unix uses it.
#[cfg_attr(windows, allow(dead_code))]
struct GroupTree {
    /// `NAME=value` entry of [`CONTAINMENT_ENV`] when the process table is scanned.
    marker: Option<String>,
}

#[cfg_attr(windows, allow(dead_code))]
impl GroupTree {
    /// Makes the process lead a new process group and sets the marker variable. Must be
    /// called after the environment of `builder` has been set up.
    fn prepare(builder: &mut Command) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            builder.process_group(0);
        }
        let marker = PROCESS_TABLE_SCAN.then(|| {
            let id = new_containment_id();
            builder.env(CONTAINMENT_ENV, &id);
            format!("{CONTAINMENT_ENV}={id}")
        });
        Self { marker }
    }

    /// The group and the marker are in place before the process starts.
    fn attach(&mut self, _child: &Child) {}

    fn has_job(&self) -> bool {
        false
    }

    fn close_job(&mut self) {}

    /// Kills the group led by `leader` and every live process of the tree.
    /// `leader_reaped` tells whether the leader's exit status was already collected, in
    /// which case its process id may belong to another process by now.
    fn kill_tree(&self, leader: u32, leader_reaped: bool) {
        if cfg!(unix) {
            kill_group_tree(leader, leader_reaped, self.marker.as_deref());
        }
    }
}

#[cfg(not(windows))]
type TreeGuard = GroupTree;

/// A [`CONTAINMENT_ENV`] value that no other live tree uses: the host's process id
/// (unique among live processes), a per-process sequence number, and random bits that
/// tell it apart from trees left behind by an earlier host with the same process id.
#[cfg_attr(windows, allow(dead_code))]
fn new_containment_id() -> String {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    // `RandomState` keys are seeded from OS randomness per process.
    let entropy = RandomState::new().hash_one((sequence, nanos));
    format!("{}-{sequence}-{entropy:016x}", std::process::id())
}

/// One process in a snapshot of the process table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessEntry {
    pid: u32,
    ppid: u32,
    /// Already exited (zombie): it cannot run, fork or be killed any more.
    exited: bool,
    /// Its initial environment contains the tree's [`CONTAINMENT_ENV`] entry.
    marked: bool,
}

/// Live members of a contained tree in one process-table snapshot: `root` (the
/// unreaped leader), every process carrying the marker, and every descendant of either
/// by parent process id. Never the calling process, process 0 or 1, or a process that
/// has already exited.
fn tree_members(table: &[ProcessEntry], root: Option<u32>, own_pid: u32) -> BTreeSet<u32> {
    let eligible = |pid: u32| pid > 1 && pid != own_pid;
    let mut in_tree: BTreeSet<u32> = table
        .iter()
        .filter(|entry| eligible(entry.pid) && (entry.marked || Some(entry.pid) == root))
        .map(|entry| entry.pid)
        .collect();
    loop {
        let before = in_tree.len();
        for entry in table {
            if eligible(entry.pid) && in_tree.contains(&entry.ppid) {
                in_tree.insert(entry.pid);
            }
        }
        if in_tree.len() == before {
            break;
        }
    }
    table
        .iter()
        .filter(|entry| !entry.exited && in_tree.contains(&entry.pid))
        .map(|entry| entry.pid)
        .collect()
}

/// Reads the process table; `None` where it is not scanned or cannot be read.
#[cfg_attr(windows, allow(dead_code))]
fn process_table(marker: Option<&str>) -> Option<Vec<ProcessEntry>> {
    if cfg!(target_os = "linux") {
        proc_fs_table(Path::new("/proc"), marker)
    } else if cfg!(target_os = "macos") {
        ps_table(marker)
    } else {
        None
    }
}

/// Reads a Linux `/proc`: state and parent of every process from `<pid>/stat` and,
/// when `marker` is set, whether `<pid>/environ` (the initial environment) contains
/// it. `None` when the directory cannot be listed.
fn proc_fs_table(proc_root: &Path, marker: Option<&str>) -> Option<Vec<ProcessEntry>> {
    let entries = std::fs::read_dir(proc_root).ok()?;
    let mut table = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .filter(|name| name.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let dir = entry.path();
        // A process can exit at any moment; one whose files are gone is skipped.
        let Some((state, ppid)) = std::fs::read(dir.join("stat"))
            .ok()
            .and_then(|stat| parse_proc_stat(&stat))
        else {
            continue;
        };
        let exited = matches!(state, b'Z' | b'X' | b'x');
        let marked = !exited
            && marker.is_some_and(|marker| {
                read_environ(&dir).is_some_and(|environ| environ_contains(&environ, marker))
            });
        table.push(ProcessEntry {
            pid,
            ppid,
            exited,
            marked,
        });
    }
    Some(table)
}

/// State character and parent process id from a `/proc/<pid>/stat` line. The command
/// name in parentheses may contain anything, including `)`, spaces and non-UTF-8
/// bytes, so the fields are read after its last `)`.
fn parse_proc_stat(stat: &[u8]) -> Option<(u8, u32)> {
    let close = stat.iter().rposition(|b| *b == b')')?;
    let rest = std::str::from_utf8(&stat[close + 1..]).ok()?;
    let mut fields = rest.split_ascii_whitespace();
    let state = *fields.next()?.as_bytes().first()?;
    let ppid = fields.next()?.parse().ok()?;
    Some((state, ppid))
}

/// Reads `<dir>/environ`; `None` when it cannot be read (the process exited, or it
/// belongs to another user or is not dumpable).
fn read_environ(dir: &Path) -> Option<Vec<u8>> {
    let mut environ = Vec::new();
    std::fs::File::open(dir.join("environ"))
        .ok()?
        .take(ENVIRON_READ_LIMIT)
        .read_to_end(&mut environ)
        .ok()?;
    Some(environ)
}

/// Whether a NUL-separated environment block contains exactly `entry` (`NAME=value`).
fn environ_contains(environ: &[u8], entry: &str) -> bool {
    environ
        .split(|b| *b == 0)
        .any(|candidate| candidate == entry.as_bytes())
}

/// Reads the macOS process table with `ps`. With a marker, `-E` adds each process's
/// initial environment to the command column (shown for the user's own processes only).
fn ps_table(marker: Option<&str>) -> Option<Vec<ProcessEntry>> {
    let mut ps = Command::new("/bin/ps");
    ps.args(["-A", "-ww", "-o", "pid=", "-o", "ppid=", "-o", "stat="]);
    if marker.is_some() {
        ps.args(["-E", "-o", "command="]);
    }
    let output = ps
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    Some(
        text.lines()
            .filter_map(|line| parse_ps_line(line, marker))
            .collect(),
    )
}

/// Parses one `ps -o pid= -o ppid= -o stat= [-E -o command=]` line. The marker counts
/// only as a whole whitespace-separated word of the command column.
fn parse_ps_line(line: &str, marker: Option<&str>) -> Option<ProcessEntry> {
    let mut fields = line.split_whitespace();
    let pid = fields.next()?.parse().ok()?;
    let ppid = fields.next()?.parse().ok()?;
    let exited = fields.next()?.starts_with('Z');
    let marked = !exited && marker.is_some_and(|marker| fields.any(|word| word == marker));
    Some(ProcessEntry {
        pid,
        ppid,
        exited,
        marked,
    })
}

/// Kills the process group led by `leader` and, where the process table is scanned,
/// every live process of its tree (see [`tree_members`]), reading the table again after
/// each round until nothing is left or [`KILL_ROUNDS`] rounds have passed.
#[cfg_attr(windows, allow(dead_code))]
fn kill_group_tree(leader: u32, leader_reaped: bool, marker: Option<&str>) {
    if leader <= 1 {
        return;
    }
    let own_pid = std::process::id();
    // An unreaped leader keeps its process id; a reaped one's id may have been reused.
    let root = (!leader_reaped).then_some(leader);
    let scan = || process_table(marker).map(|table| tree_members(&table, root, own_pid));
    // Read the table before anything is signalled: a child whose parent died is
    // re-parented and then linked to the tree only by the marker.
    let mut members = scan();
    // The group outlives its leader; it is signalled once, in the first round.
    let mut targets = vec![format!("-{leader}")];
    for round in 1..=KILL_ROUNDS {
        targets.extend(members.iter().flatten().map(u32::to_string));
        send_sigkill(&targets);
        targets.clear();
        if round == KILL_ROUNDS || members.as_ref().is_none_or(BTreeSet::is_empty) {
            return;
        }
        // Catch processes forked between the scan and the signal.
        thread::sleep(KILL_ROUND_PAUSE);
        members = scan();
    }
}

/// Sends `SIGKILL` to every target (a process id, or `-<pgid>` for a process group)
/// with the system `kill` utility: `std` cannot signal arbitrary processes and
/// `#![forbid(unsafe_code)]` rules out calling `kill(2)` directly.
#[cfg_attr(windows, allow(dead_code))]
fn send_sigkill(targets: &[String]) {
    for batch in targets.chunks(KILL_BATCH) {
        for kill in ["/bin/kill", "/usr/bin/kill"] {
            let status = Command::new(kill)
                .args(["-s", "KILL", "--"])
                .args(batch)
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            if status.is_ok() {
                break;
            }
        }
    }
}

impl AdapterProcess {
    /// Starts the adapter with a cleared environment and pumps for every stdio stream.
    pub(crate) fn spawn(
        command: &AdapterCommand,
        adapter_dir: &Path,
        env: &[(OsString, OsString)],
        max_frame_bytes: usize,
    ) -> Result<Self, PluginError> {
        let mut builder = Command::new(&command.program);
        builder
            .args(&command.args)
            .current_dir(adapter_dir)
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut tree = TreeGuard::prepare(&mut builder);
        let mut child = builder.spawn().map_err(|e| {
            PluginError::spawn_failed(format!(
                "'{}' in '{}': {e}",
                command.program.display(),
                adapter_dir.display()
            ))
        })?;
        // Contain the tree before the adapter gets a chance to start children.
        tree.attach(&child);

        let (Some(stdin), Some(stdout), Some(stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            let _ = child.kill();
            tree.close_job();
            let _ = child.wait();
            return Err(PluginError::spawn_failed(
                "adapter stdio pipes were not created",
            ));
        };

        let (event_tx, events) = mpsc::channel();
        let stderr_tail = Arc::new(Mutex::new(StderrTail::default()));

        // Writer: requests never block the supervising thread.
        let (stdin_tx, stdin_rx) = mpsc::channel::<Vec<u8>>();
        thread::spawn(move || {
            let mut stdin = stdin;
            for frame in stdin_rx {
                if stdin
                    .write_all(&frame)
                    .and_then(|()| stdin.flush())
                    .is_err()
                {
                    break;
                }
            }
        });

        // stdout: bounded line reads; never buffers more than one frame plus one byte.
        let stdout_tx = event_tx.clone();
        thread::spawn(move || pump_stdout(stdout, max_frame_bytes, &stdout_tx));

        // stderr: always drained so the adapter can never block on it.
        let tail = Arc::clone(&stderr_tail);
        let (drained_tx, stderr_drained) = mpsc::channel();
        thread::spawn(move || {
            pump_stderr(stderr, &tail, &event_tx);
            let _ = drained_tx.send(());
        });

        Ok(Self {
            child,
            tree,
            events,
            stdin: Some(stdin_tx),
            stderr: stderr_tail,
            stderr_drained,
            finished: None,
        })
    }

    /// Queues one encoded frame for the adapter's stdin.
    pub(crate) fn send(&self, frame: String) {
        if let Some(stdin) = &self.stdin {
            // A closed writer means the adapter is gone; the next read reports it.
            let _ = stdin.send(frame.into_bytes());
        }
    }

    /// Waits for the next pump event until `deadline`.
    pub(crate) fn next_event(&self, deadline: Instant) -> Option<PumpEvent> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return self.events.try_recv().ok();
        }
        self.events.recv_timeout(remaining).ok()
    }

    /// Exit code of the adapter if it exits within `grace`, without killing it.
    pub(crate) fn exit_code_within(&mut self, grace: Duration) -> Option<i32> {
        let deadline = Instant::now() + grace;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return status.code(),
                Ok(None) if Instant::now() < deadline => thread::sleep(EXIT_POLL_INTERVAL),
                _ => return None,
            }
        }
    }

    /// Called once the adapter acknowledged `shutdown`.
    ///
    /// When descendants stay reachable after the adapter exits (Job Object; on Unix the
    /// process group and, on Linux and macOS, the [`CONTAINMENT_ENV`] marker), the
    /// adapter gets a short grace period to exit by itself so its real exit status is
    /// reported; [`Self::finish`] then kills whatever is left. Otherwise the tree is
    /// killed right away, while the adapter is still alive and its children can still
    /// be found.
    pub(crate) fn settle_after_shutdown_ack(&mut self, grace: Duration) {
        if self.contains_descendants() {
            let _ = self.exit_code_within(grace);
        } else {
            self.finish();
        }
    }

    /// Whether descendants stay reachable after the adapter itself has exited (Windows
    /// Job Object; Unix process group and marker, see the module documentation for the
    /// descendants that are not).
    pub(crate) fn contains_descendants(&self) -> bool {
        self.tree.has_job() || cfg!(unix)
    }

    /// Kills the process tree, then closes stdin, reaps the adapter and waits (bounded)
    /// until stderr is fully drained. Idempotent.
    ///
    /// The tree is killed before stdin is closed: a stdin-driven adapter exits on end
    /// of input, after which `taskkill /T` could no longer reach its children.
    pub(crate) fn finish(&mut self) -> ProcessSummary {
        if let Some(summary) = &self.finished {
            return summary.clone();
        }

        let pid = self.child.id();
        let status = self.child.try_wait();
        let already_exited = matches!(status, Ok(Some(_)));
        // Unix: `try_wait` collected the exit status of an adapter that has exited, so
        // its process id may already belong to another process (unknown on error).
        let leader_reaped = !matches!(status, Ok(None));
        if self.tree.has_job() {
            // Terminate the adapter itself first so it reports the host's kill, then
            // close the job: every remaining descendant (also orphaned ones) dies.
            if !already_exited {
                let _ = self.child.kill();
            }
            self.tree.close_job();
        } else if cfg!(unix) || !already_exited {
            // Unix: the group outlives its leader and marked descendants outlive both,
            // so the tree is always killed. Windows without a job: `taskkill /T` can
            // only walk the tree while the adapter is alive; the unreaped `Child`
            // handle keeps the PID from being reused.
            self.tree.kill_tree(pid, leader_reaped);
        }
        let _ = self.child.kill();
        self.stdin = None;
        let exit_code = self.child.wait().ok().and_then(|status| status.code());
        // The pump may still be reading what the adapter wrote just before it exited
        // (a pipe buffers 64 KiB by default, more where a process enlarged it, as Linux
        // allows). The pipe reaches end of file once every process holding it is gone;
        // wait for that so that `stderr_bytes` counts everything that was written.
        // Bounded, in case a descendant escaped containment and keeps the pipe open.
        let _ = self.stderr_drained.recv_timeout(STDERR_DRAIN_GRACE);

        let (stderr_bytes, stderr_tail) = self
            .stderr
            .lock()
            .map(|tail| {
                (
                    tail.total,
                    String::from_utf8_lossy(&tail.bytes).into_owned(),
                )
            })
            .unwrap_or_default();
        let summary = ProcessSummary {
            exit_code,
            killed_by_host: !already_exited,
            stderr_bytes,
            stderr_tail,
        };
        self.finished = Some(summary.clone());
        summary
    }
}

impl Drop for AdapterProcess {
    fn drop(&mut self) {
        self.finish();
    }
}

fn pump_stdout<R: Read>(stdout: R, max_frame_bytes: usize, events: &mpsc::Sender<PumpEvent>) {
    let mut reader = BufReader::with_capacity(STDOUT_BUFFER_BYTES, stdout);
    let limit = u64::try_from(max_frame_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(2);
    loop {
        let mut line = Vec::new();
        let read = (&mut reader).take(limit).read_until(b'\n', &mut line);
        let event = match read {
            Ok(0) => {
                let _ = events.send(PumpEvent::StdoutClosed);
                return;
            }
            Ok(_) => {
                let terminated = line.last() == Some(&b'\n');
                if terminated {
                    line.pop();
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                }
                if line.len() > max_frame_bytes {
                    let _ = events.send(PumpEvent::FrameTooLarge(line.len()));
                    return;
                }
                PumpEvent::Frame(line)
            }
            Err(e) => {
                let _ = events.send(PumpEvent::StdoutFailed(e.to_string()));
                return;
            }
        };
        if events.send(event).is_err() {
            return;
        }
    }
}

fn pump_stderr<R: Read>(mut stderr: R, tail: &Mutex<StderrTail>, events: &mpsc::Sender<PumpEvent>) {
    let mut chunk = vec![0_u8; STDERR_CHUNK_BYTES];
    loop {
        match stderr.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if let Ok(mut tail) = tail.lock() {
                    tail.push(&chunk[..n]);
                }
                // Keep draining after the supervisor has gone so the adapter never
                // blocks on a full pipe before it is killed.
                let _ = events.send(PumpEvent::Stderr(n));
            }
        }
    }
}

/// Observations of one command run by [`run_contained`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContainedRun {
    /// Exit code of the started program; `None` when it was killed or exited by signal.
    pub exit_code: Option<i32>,
    /// Whether the deadline passed and the process tree was killed.
    pub timed_out: bool,
    /// Whether the run was cancelled (see [`run_contained_cancellable`]) and the
    /// process tree was killed.
    pub cancelled: bool,
    /// Last bytes written to stdout (lossy UTF-8, at most the requested tail size).
    pub stdout_tail: String,
    /// Total stdout bytes observed.
    pub stdout_bytes: usize,
    /// Last bytes written to stderr (lossy UTF-8, at most the requested tail size).
    pub stderr_tail: String,
    /// Total stderr bytes observed.
    pub stderr_bytes: usize,
    /// Wall-clock time from start until the process tree was gone.
    pub elapsed: Duration,
}

/// Bounded tail of one output stream with a byte counter.
#[derive(Debug)]
struct BoundedTail {
    bytes: Vec<u8>,
    total: usize,
    limit: usize,
}

impl BoundedTail {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            total: 0,
            limit,
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        self.total = self.total.saturating_add(chunk.len());
        self.bytes.extend_from_slice(chunk);
        if self.bytes.len() > self.limit {
            let excess = self.bytes.len() - self.limit;
            self.bytes.drain(..excess);
        }
    }

    fn snapshot(&self) -> (String, usize) {
        (
            String::from_utf8_lossy(&self.bytes).into_owned(),
            self.total,
        )
    }
}

/// Drains `stream` into `tail` until end of file and reports completion on `done`.
fn drain_into<R: Read + Send + 'static>(
    stream: Option<R>,
    tail: Arc<Mutex<BoundedTail>>,
    done: mpsc::Sender<()>,
) {
    thread::spawn(move || {
        if let Some(mut stream) = stream {
            let mut chunk = vec![0_u8; STDERR_CHUNK_BYTES];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if let Ok(mut tail) = tail.lock() {
                            tail.push(&chunk[..n]);
                        }
                    }
                }
            }
        }
        let _ = done.send(());
    });
}

/// Runs `program` to completion inside the same containment as plugin adapters and
/// returns what was observed.
///
/// - The environment is exactly `env` (the parent environment is cleared), stdin is
///   the null device and `cwd` is the working directory.
/// - stdout and stderr are always drained; only the last `tail_bytes` of each are kept.
/// - Windows: the process is assigned to a kill-on-close Job Object right after it
///   starts, and the job is closed when the run ends (normal exit, timeout or error),
///   so descendants it left behind are terminated too. Without a job, `taskkill /T`
///   is used while the process is still alive.
/// - Unix: the process leads a new process group, which is killed when the run ends.
/// - When `timeout` passes, the whole tree is killed and `timed_out` is set.
///
/// The same residual risks as for adapters apply (see the module documentation); in
/// addition, if the calling process is itself killed, a Unix process group started
/// here is not killed (on Windows the Job Object closes with the caller). Callers that
/// must stop the tree on request use [`run_contained_cancellable`].
pub fn run_contained(
    program: &Path,
    args: &[OsString],
    cwd: &Path,
    env: &[(OsString, OsString)],
    timeout: Duration,
    tail_bytes: usize,
) -> std::io::Result<ContainedRun> {
    let never = AtomicBool::new(false);
    run_contained_cancellable(program, args, cwd, env, timeout, tail_bytes, &never)
}

/// [`run_contained`] that also stops when `cancel` becomes true: the whole tree is
/// killed as on a timeout and `cancelled` is set. The flag is polled with the exit
/// status, so the tree is gone within a few tens of milliseconds of the request.
pub fn run_contained_cancellable(
    program: &Path,
    args: &[OsString],
    cwd: &Path,
    env: &[(OsString, OsString)],
    timeout: Duration,
    tail_bytes: usize,
    cancel: &AtomicBool,
) -> std::io::Result<ContainedRun> {
    run_contained_observed(
        program,
        args,
        cwd,
        env,
        timeout,
        tail_bytes,
        cancel,
        &mut || {},
    )
}

/// [`run_contained_cancellable`] that also calls `on_poll` each time it checks the exit
/// status while the program runs (about every 20 milliseconds), on the calling thread,
/// so a caller can report progress without a thread of its own. A slow `on_poll`
/// delays the deadline and cancellation checks by the time it takes.
#[allow(clippy::too_many_arguments)]
pub fn run_contained_observed(
    program: &Path,
    args: &[OsString],
    cwd: &Path,
    env: &[(OsString, OsString)],
    timeout: Duration,
    tail_bytes: usize,
    cancel: &AtomicBool,
    on_poll: &mut dyn FnMut(),
) -> std::io::Result<ContainedRun> {
    let mut builder = Command::new(program);
    builder
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut tree = TreeGuard::prepare(&mut builder);
    let started = Instant::now();
    let mut child = builder.spawn()?;
    // Contain the tree before the program gets a chance to start children.
    tree.attach(&child);

    let stdout_tail = Arc::new(Mutex::new(BoundedTail::new(tail_bytes)));
    let stderr_tail = Arc::new(Mutex::new(BoundedTail::new(tail_bytes)));
    let (done_tx, done_rx) = mpsc::channel();
    drain_into(
        child.stdout.take(),
        Arc::clone(&stdout_tail),
        done_tx.clone(),
    );
    drain_into(child.stderr.take(), Arc::clone(&stderr_tail), done_tx);

    let deadline = started + timeout;
    let mut timed_out = false;
    let mut cancelled = false;
    let mut exit_code = None;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = status.code();
                break;
            }
            Ok(None) if cancel.load(Ordering::SeqCst) => {
                cancelled = true;
                break;
            }
            Ok(None) if Instant::now() < deadline => {
                on_poll();
                thread::sleep(EXIT_POLL_INTERVAL);
            }
            Ok(None) => {
                timed_out = true;
                break;
            }
            Err(_) => break,
        }
    }

    // Kill whatever is left of the tree: the program itself on timeout, and any
    // descendant it left running after a normal exit.
    let pid = child.id();
    // Unix: once `try_wait` collected the exit status, the process id may already
    // belong to another process (unknown on error).
    let leader_reaped = !matches!(child.try_wait(), Ok(None));
    if tree.has_job() {
        if exit_code.is_none() {
            let _ = child.kill();
        }
        tree.close_job();
    } else if cfg!(unix) || exit_code.is_none() {
        tree.kill_tree(pid, leader_reaped);
    }
    let _ = child.kill();
    let _ = child.wait();

    // The pipes close once every holder is gone; wait briefly for both pumps.
    let pump_deadline = Instant::now() + Duration::from_secs(5);
    for _ in 0..2 {
        let remaining = pump_deadline.saturating_duration_since(Instant::now());
        if done_rx.recv_timeout(remaining).is_err() {
            break;
        }
    }
    let (stdout_tail, stdout_bytes) = stdout_tail
        .lock()
        .map(|tail| tail.snapshot())
        .unwrap_or_default();
    let (stderr_tail, stderr_bytes) = stderr_tail
        .lock()
        .map(|tail| tail.snapshot())
        .unwrap_or_default();
    Ok(ContainedRun {
        exit_code: if timed_out || cancelled {
            None
        } else {
            exit_code
        },
        timed_out,
        cancelled,
        stdout_tail,
        stdout_bytes,
        stderr_tail,
        stderr_bytes,
        elapsed: started.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(pid: u32, ppid: u32) -> ProcessEntry {
        ProcessEntry {
            pid,
            ppid,
            exited: false,
            marked: false,
        }
    }

    fn set(pids: &[u32]) -> BTreeSet<u32> {
        pids.iter().copied().collect()
    }

    #[test]
    fn tree_members_follow_parents_from_the_leader_and_from_marked_processes() {
        let own = 50;
        let table = [
            entry(1, 0),
            entry(own, 1),
            // The adapter (leader), its child and grandchild.
            entry(100, own),
            entry(101, 100),
            entry(102, 101),
            // A marked orphan (re-parented to init) and its unmarked child.
            ProcessEntry {
                marked: true,
                ..entry(200, 1)
            },
            entry(201, 200),
            // An exited (zombie) child is not a target.
            ProcessEntry {
                exited: true,
                ..entry(103, 100)
            },
            // Unrelated processes, including another child of the host.
            entry(300, 1),
            entry(301, 300),
            entry(400, own),
        ];
        assert_eq!(
            tree_members(&table, Some(100), own),
            set(&[100, 101, 102, 200, 201])
        );
        // A reaped leader is not a seed: only the marked part of the tree is found.
        assert_eq!(tree_members(&table, None, own), set(&[200, 201]));
    }

    #[test]
    fn tree_members_never_include_the_host_init_or_their_children() {
        let own = 50;
        let marked = |pid, ppid| ProcessEntry {
            marked: true,
            ..entry(pid, ppid)
        };
        // Even a marked host or init is never a target or a seed.
        let table = [marked(1, 0), marked(own, 1), entry(400, own), entry(2, 1)];
        assert!(tree_members(&table, Some(own), own).is_empty());
        assert!(tree_members(&table, Some(1), own).is_empty());
        assert!(tree_members(&table, Some(0), own).is_empty());
    }

    #[test]
    fn proc_stat_fields_are_read_after_the_last_parenthesis() {
        assert_eq!(
            parse_proc_stat(b"4242 (bun) S 4200 4200 4200 0 -1 4194560 120 0 0 0"),
            Some((b'S', 4200))
        );
        // A command name may contain `)`, spaces, digits and non-UTF-8 bytes.
        assert_eq!(
            parse_proc_stat(b"7 (a) Z 9 (b\xff) ) R 31 7 7 0"),
            Some((b'R', 31))
        );
        assert_eq!(parse_proc_stat(b"7 (x) Z 1"), Some((b'Z', 1)));
        assert_eq!(parse_proc_stat(b"7 (x)"), None);
        assert_eq!(parse_proc_stat(b"7 x S 1"), None);
        assert_eq!(parse_proc_stat(b"7 (x) S -1"), None);
    }

    #[test]
    fn environ_entries_match_exactly() {
        let marker = "CONTAINED_BY_SENTRA=1-2-ab";
        assert!(environ_contains(
            b"PATH=/bin\0CONTAINED_BY_SENTRA=1-2-ab\0HOME=/h\0",
            marker
        ));
        assert!(environ_contains(b"CONTAINED_BY_SENTRA=1-2-ab", marker));
        assert!(!environ_contains(
            b"CONTAINED_BY_SENTRA=1-2-abc\0X=CONTAINED_BY_SENTRA=1-2-ab\0",
            marker
        ));
        assert!(!environ_contains(b"", marker));
    }

    #[test]
    fn ps_lines_report_parent_state_and_marker_words() {
        let marker = Some("CONTAINED_BY_SENTRA=1-2-ab");
        assert_eq!(
            parse_ps_line(
                "  812   1 Ss   /opt/bun -e code CONTAINED_BY_SENTRA=1-2-ab HOME=/Users/x",
                marker
            ),
            Some(ProcessEntry {
                pid: 812,
                ppid: 1,
                exited: false,
                marked: true
            })
        );
        assert_eq!(
            parse_ps_line(" 9 8 S /bin/sh CONTAINED_BY_SENTRA=1-2-abc", marker),
            Some(entry(9, 8))
        );
        assert_eq!(
            parse_ps_line(" 9 8 Z <defunct> CONTAINED_BY_SENTRA=1-2-ab", marker),
            Some(ProcessEntry {
                exited: true,
                ..entry(9, 8)
            })
        );
        assert_eq!(parse_ps_line("  33 1 R", None), Some(entry(33, 1)));
        assert_eq!(parse_ps_line("PID PPID STAT", marker), None);
        assert_eq!(parse_ps_line("", marker), None);
    }

    #[test]
    fn proc_fs_table_reads_stat_and_environ() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let root =
            std::env::temp_dir().join(format!("sentra-proc-table-{}-{nanos}", std::process::id()));
        let process = |pid: &str, stat: &[u8], environ: Option<&[u8]>| {
            let dir = root.join(pid);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("stat"), stat).unwrap();
            if let Some(environ) = environ {
                std::fs::write(dir.join("environ"), environ).unwrap();
            }
        };
        let marker = "CONTAINED_BY_SENTRA=1-2-ab";
        process(
            "10",
            b"10 (bun) S 1 10 10 0",
            Some(b"A=1\0CONTAINED_BY_SENTRA=1-2-ab\0".as_slice()),
        );
        process("11", b"11 (sh) S 10 10 10 0", None);
        process(
            "12",
            b"12 (gone) Z 10 10 10 0",
            Some(b"CONTAINED_BY_SENTRA=1-2-ab\0".as_slice()),
        );
        process("13", b"13 (other) R 1 13 13 0", Some(b"A=1\0".as_slice()));
        process("14", b"garbage", None);
        // Not process directories.
        process("self", b"10 (bun) S 1 10 10 0", None);
        process("+15", b"15 (bun) S 1 10 10 0", None);

        let mut table = proc_fs_table(&root, Some(marker)).unwrap();
        table.sort_by_key(|entry| entry.pid);
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(
            table,
            vec![
                ProcessEntry {
                    marked: true,
                    ..entry(10, 1)
                },
                entry(11, 10),
                ProcessEntry {
                    exited: true,
                    ..entry(12, 10)
                },
                entry(13, 1),
            ]
        );
        assert!(proc_fs_table(&root, Some(marker)).is_none());
    }

    #[test]
    fn containment_ids_are_unique_and_name_the_host() {
        let first = new_containment_id();
        let second = new_containment_id();
        assert_ne!(first, second);
        assert!(first.starts_with(&format!("{}-", std::process::id())));
        assert!(first.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'));
    }

    #[test]
    fn group_tree_marks_the_command_only_where_the_table_is_scanned() {
        let mut command = Command::new("program");
        let tree = GroupTree::prepare(&mut command);
        let value = command
            .get_envs()
            .find(|(name, _)| *name == OsStr::new(CONTAINMENT_ENV))
            .and_then(|(_, value)| value)
            .map(|value| value.to_string_lossy().into_owned());
        assert_eq!(value.is_some(), PROCESS_TABLE_SCAN);
        assert_eq!(
            tree.marker,
            value.map(|value| format!("{CONTAINMENT_ENV}={value}"))
        );
    }
}
