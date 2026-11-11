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
//! - Unix: the adapter leads a new process group that is killed with `kill -KILL`; the
//!   group outlives its leader.
//! - The tree is always killed before the adapter's stdin is closed: a stdin-driven
//!   adapter exits on end of input, and on the fallback path its children would then
//!   be unreachable.
//!
//! Residual risks:
//! - Windows: a descendant created in the moment between process creation and job
//!   assignment, or any descendant when job assignment fails, is not contained.
//! - Unix: a descendant that calls `setsid` leaves the process group.
//! - Inheritable handles of the host process (including its own stdout) can be
//!   inherited by the adapter tree on Windows; they are released only when every
//!   process holding them has exited, which the Job Object guarantees at session end.
//! - Memory and network egress are not limited.

use std::{
    ffi::{OsStr, OsString},
    io::{BufRead, BufReader, Read, Write},
    path::{Component, Path, PathBuf, Prefix},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
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

const STDERR_CHUNK_BYTES: usize = 8 * 1024;
const STDOUT_BUFFER_BYTES: usize = 64 * 1024;
const EXIT_POLL_INTERVAL: Duration = Duration::from_millis(20);

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
    finished: Option<ProcessSummary>,
}

/// Windows containment: a kill-on-close Job Object holding the adapter tree.
#[cfg(windows)]
struct TreeGuard(Option<win32job::Job>);

#[cfg(windows)]
impl TreeGuard {
    /// Creates the job and assigns the adapter; `None` inside when either step fails.
    fn attach(child: &Child) -> Self {
        use std::os::windows::io::AsRawHandle;

        let mut limits = win32job::ExtendedLimitInfo::new();
        limits.limit_kill_on_job_close();
        let job = win32job::Job::create_with_limit_info(&limits)
            .ok()
            .filter(|job| job.assign_process(child.as_raw_handle() as isize).is_ok());
        Self(job)
    }

    /// Whether the adapter was assigned to the job.
    fn has_job(&self) -> bool {
        self.0.is_some()
    }

    /// Closes the job (the last handle to it), terminating every process still in it.
    fn close_job(&mut self) {
        self.0 = None;
    }
}

/// Without a Job Object, Unix containment is the adapter's own process group (see
/// [`kill_tree`]).
#[cfg(not(windows))]
struct TreeGuard;

#[cfg(not(windows))]
impl TreeGuard {
    fn attach(_child: &Child) -> Self {
        Self
    }

    fn has_job(&self) -> bool {
        false
    }

    fn close_job(&mut self) {}
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
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            builder.process_group(0);
        }
        let mut child = builder.spawn().map_err(|e| {
            PluginError::spawn_failed(format!(
                "'{}' in '{}': {e}",
                command.program.display(),
                adapter_dir.display()
            ))
        })?;
        // Contain the tree before the adapter gets a chance to start children.
        let mut tree = TreeGuard::attach(&child);

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
        thread::spawn(move || pump_stderr(stderr, &tail, &event_tx));

        Ok(Self {
            child,
            tree,
            events,
            stdin: Some(stdin_tx),
            stderr: stderr_tail,
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
    /// When every descendant stays reachable after the adapter exits (Job Object or
    /// process group), the adapter gets a short grace period to exit by itself so its
    /// real exit status is reported; [`Self::finish`] then kills whatever is left.
    /// Otherwise the tree is killed right away, while the adapter is still alive and
    /// its children can still be found.
    pub(crate) fn settle_after_shutdown_ack(&mut self, grace: Duration) {
        if self.contains_descendants() {
            let _ = self.exit_code_within(grace);
        } else {
            self.finish();
        }
    }

    /// Whether every descendant stays reachable after the adapter itself has exited
    /// (Windows Job Object, Unix process group).
    pub(crate) fn contains_descendants(&self) -> bool {
        self.tree.has_job() || cfg!(unix)
    }

    /// Kills the process tree, then closes stdin and reaps the adapter. Idempotent.
    ///
    /// The tree is killed before stdin is closed: a stdin-driven adapter exits on end
    /// of input, after which `taskkill /T` could no longer reach its children.
    pub(crate) fn finish(&mut self) -> ProcessSummary {
        if let Some(summary) = &self.finished {
            return summary.clone();
        }

        let pid = self.child.id();
        let already_exited = matches!(self.child.try_wait(), Ok(Some(_)));
        if self.tree.has_job() {
            // Terminate the adapter itself first so it reports the host's kill, then
            // close the job: every remaining descendant (also orphaned ones) dies.
            if !already_exited {
                let _ = self.child.kill();
            }
            self.tree.close_job();
        } else if cfg!(unix) || !already_exited {
            // Unix: the group outlives its leader, so it is always signalled. Windows
            // without a job: `taskkill /T` can only walk the tree while the adapter is
            // alive; the unreaped `Child` handle keeps the PID from being reused.
            kill_tree(pid);
        }
        let _ = self.child.kill();
        self.stdin = None;
        let exit_code = self.child.wait().ok().and_then(|status| status.code());

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

/// Kills the adapter's process tree (best effort).
#[cfg(windows)]
fn kill_tree(pid: u32) {
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

/// Kills the adapter's process group (best effort).
#[cfg(unix)]
fn kill_tree(pid: u32) {
    let group = format!("-{pid}");
    for kill in ["/bin/kill", "/usr/bin/kill"] {
        let status = Command::new(kill)
            .args(["-s", "KILL", "--", &group])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if status.is_ok() {
            return;
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn kill_tree(_pid: u32) {}
