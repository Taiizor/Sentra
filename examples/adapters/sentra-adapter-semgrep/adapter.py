#!/usr/bin/env python3
"""
Sentra subprocess adapter for the Semgrep CLI (example, REQ-F16).

Speaks the newline-delimited JSON protocol of `crates/sentra-core/src/plugin/protocol.rs`:

  initialize -> initialize_ack
  probe      -> probe_result   (is a usable `semgrep` on PATH?)
  plan       -> plan_result
  execute    -> execute_result (scan of the workspace_root sent by the host)
  cancel     -> cancel_ack
  shutdown   -> shutdown_ack

What it does on `execute`:
  - scans the `workspace_root` from the execute frame, passed to Semgrep as an absolute
    target (it never scans its own working directory);
  - runs only local rules: `arguments.config` (paths inside the workspace) or the
    operator's `rules/` directory next to this file. Registry rulesets (`p/...`, `r/...`,
    `s/...`), `auto` and URLs are refused, because the manifest declares
    `egress_policy: strictly_denied`;
  - passes `--metrics=off` and `--disable-version-check`, and `--no-git-ignore` unless
    `arguments.git_ignore` is true;
  - bounds the Semgrep process (timeout below the manifest's session deadline, captured
    stdout/stderr, stdin closed) and reports real results only: counts by severity and
    the top findings in `summary`, truncated to stay inside `max_frame_bytes`, plus a
    `sha256:` digest of the Semgrep JSON report in `evidence_refs`.

It never fabricates findings. When Semgrep is missing, `probe` reports not applicable
and `execute` answers with an `error` frame.

Python standard library only.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
from typing import Any, Dict, List, Optional, Sequence, Tuple

PLUGIN_ID = "org.sentra.adapter.semgrep"
INTERFACE_VERSION = 1
CAPABILITIES = ["static_analysis"]

ADAPTER_DIR = os.path.dirname(os.path.abspath(__file__))
MANIFEST_PATH = os.path.join(ADAPTER_DIR, "manifest.json")
# Operator-supplied local rules used when `arguments.config` is absent. Nothing is
# shipped here: Semgrep-maintained registry rules are not bundled (ADR-0007).
OPERATOR_RULES_DIR = os.path.join(ADAPTER_DIR, "rules")

# Host defaults (crates/sentra-core/src/plugin/manifest.rs) used if manifest.json
# cannot be read.
DEFAULT_MAX_FRAME_BYTES = 1_048_576
DEFAULT_MAX_EXECUTION_TIME_SECS = 60

# Error frame codes (adapter-defined).
ERR_BAD_REQUEST = 400
ERR_INTERNAL = 500
ERR_SEMGREP_FAILED = 502
ERR_SEMGREP_UNAVAILABLE = 503
ERR_SEMGREP_TIMEOUT = 504

ALLOWED_ARGUMENTS = ("config", "ruleset", "timeout_secs", "max_results", "git_ignore")
MAX_CONFIG_ENTRIES = 16
MAX_CONFIG_VALUE_CHARS = 4096
DEFAULT_MAX_RESULTS = 20
MAX_RESULTS_LIMIT = 200

VERSION_TIMEOUT_SECS = 30
MAX_REPORT_BYTES = 64 * 1024 * 1024  # Semgrep JSON kept in memory at most
STDERR_TAIL_BYTES = 8 * 1024
SUMMARY_MAX_BYTES = 32 * 1024
FRAME_OVERHEAD_BYTES = 2 * 1024  # task id, evidence label and JSON framing
MESSAGE_MAX_CHARS = 240
MAX_ERROR_LINES = 3

# Most severe first. Semgrep reports ERROR/WARNING/INFO (and INVENTORY/EXPERIMENT);
# newer rules may use CRITICAL/HIGH/MEDIUM/LOW. Unknown labels sort last.
SEVERITY_RANK = {
    "CRITICAL": 0,
    "HIGH": 1,
    "ERROR": 1,
    "MEDIUM": 2,
    "WARNING": 2,
    "LOW": 3,
    "INFO": 3,
    "INVENTORY": 4,
    "EXPERIMENT": 4,
}

# Values Semgrep resolves over the network instead of reading a local file.
REGISTRY_PREFIXES = ("p/", "r/", "s/", "http://", "https://")


class AdapterError(Exception):
    """A request that is answered with an `error` frame."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def log(msg: str) -> None:
    """Diagnostics go to stderr; stdout carries protocol frames only."""
    sys.stderr.write(f"[{PLUGIN_ID}] {msg}\n")
    sys.stderr.flush()


def encode(response: dict) -> bytes:
    """One single-line JSON frame (ASCII, so its byte length is exact)."""
    return json.dumps(response, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"


def emit(response: dict) -> None:
    sys.stdout.buffer.write(encode(response))
    sys.stdout.buffer.flush()


def error_frame(code: int, message: str) -> dict:
    return {"status": "error", "code": code, "message": message}


# ---------------------------------------------------------------------------
# Manifest quotas
# ---------------------------------------------------------------------------


def read_quotas() -> Tuple[int, int]:
    """(max_frame_bytes, max_execution_time_secs) from the adapter's own manifest."""
    frame, deadline = DEFAULT_MAX_FRAME_BYTES, DEFAULT_MAX_EXECUTION_TIME_SECS
    try:
        with open(MANIFEST_PATH, "r", encoding="utf-8-sig") as handle:
            quotas = json.load(handle).get("quotas") or {}
        if isinstance(quotas.get("max_frame_bytes"), int) and quotas["max_frame_bytes"] > 0:
            frame = quotas["max_frame_bytes"]
        if isinstance(quotas.get("max_execution_time_secs"), int) and quotas["max_execution_time_secs"] > 0:
            deadline = min(quotas["max_execution_time_secs"], 3600)
    except (OSError, ValueError, AttributeError) as exc:
        log(f"manifest quotas unavailable, using host defaults: {type(exc).__name__}")
    return frame, deadline


def scan_timeout_cap(deadline_secs: int) -> int:
    """Longest Semgrep run that still leaves time to answer before the host deadline."""
    margin = min(20, max(1, deadline_secs // 4))
    return max(1, deadline_secs - margin)


# ---------------------------------------------------------------------------
# Locating Semgrep
# ---------------------------------------------------------------------------


def find_semgrep() -> Tuple[Optional[List[str]], str]:
    """Returns (command prefix, note) for `semgrep` on PATH, or (None, reason).

    Only absolute PATH entries are searched; the current directory never is (unlike
    `shutil.which` on Windows). On Windows only `.exe`/`.com` files are started: a
    `.bat`/`.cmd` shim would run through cmd.exe, which re-parses the arguments.
    """
    path_value = os.environ.get("PATH", "")
    is_windows = os.name == "nt"
    if is_windows:
        exts = [e.lower() for e in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";") if e.startswith(".")]
        names = ["semgrep" + e for e in exts]
    else:
        names = ["semgrep"]
    skipped: List[str] = []
    for entry in path_value.split(os.pathsep):
        entry = entry.strip().strip('"')
        if not entry or not os.path.isabs(entry):
            continue
        for name in names:
            candidate = os.path.join(entry, name)
            if not os.path.isfile(candidate):
                continue
            if is_windows:
                if os.path.splitext(name)[1] not in (".exe", ".com"):
                    skipped.append(candidate)
                    continue
                return [candidate], candidate
            if os.access(candidate, os.X_OK):
                return [candidate], candidate
    reason = "semgrep was not found on the PATH passed to the adapter (absolute PATH entries only)"
    if skipped:
        reason += "; batch-file shims are not started: " + ", ".join(skipped[:3])
    return None, reason


def child_environment() -> Dict[str, str]:
    """The adapter's (host-filtered) environment without SEMGREP_* settings, plus
    the documented switches that turn metrics and the version check off."""
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("SEMGREP_")}
    env["SEMGREP_SEND_METRICS"] = "off"
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "false"
    return env


# ---------------------------------------------------------------------------
# Bounded subprocess
# ---------------------------------------------------------------------------


class RunResult:
    def __init__(self) -> None:
        self.returncode: Optional[int] = None
        self.stdout = b""
        self.stdout_total = 0
        self.stdout_overflow = False
        self.stdout_complete = True
        self.stderr_tail = ""
        self.timed_out = False


def run_bounded(argv: Sequence[str], timeout_secs: float, max_stdout: int) -> RunResult:
    """Runs `argv` with stdin closed, stdout capped at `max_stdout` bytes, the last
    STDERR_TAIL_BYTES of stderr kept, and the process killed after `timeout_secs`.

    Raises OSError when the program cannot be started. The direct child is killed on
    timeout; any descendants it left behind are ended by the host's process-tree
    termination when the session ends.
    """
    proc = subprocess.Popen(
        list(argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=ADAPTER_DIR,
        env=child_environment(),
    )
    result = RunResult()
    out = bytearray()
    err = bytearray()

    # Each pipe is closed by the thread that reads it, once it reaches end of file.
    def pump_stdout() -> None:
        with proc.stdout:
            while True:
                chunk = proc.stdout.read(65536)
                if not chunk:
                    return
                result.stdout_total += len(chunk)
                room = max_stdout - len(out)
                if room > 0:
                    out.extend(chunk[:room])
                if len(chunk) > room:
                    result.stdout_overflow = True

    def pump_stderr() -> None:
        with proc.stderr:
            while True:
                chunk = proc.stderr.read(8192)
                if not chunk:
                    return
                err.extend(chunk)
                if len(err) > STDERR_TAIL_BYTES:
                    del err[: len(err) - STDERR_TAIL_BYTES]

    threads = [threading.Thread(target=pump_stdout, daemon=True), threading.Thread(target=pump_stderr, daemon=True)]
    for thread in threads:
        thread.start()
    try:
        result.returncode = proc.wait(timeout=timeout_secs)
    except subprocess.TimeoutExpired:
        result.timed_out = True
        proc.kill()
        try:
            result.returncode = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            result.returncode = None
    # A descendant that still holds a pipe would block EOF; never wait for it long.
    for thread in threads:
        thread.join(timeout=2 if result.timed_out else 10)
    result.stdout_complete = not threads[0].is_alive()
    result.stdout = bytes(out)
    result.stderr_tail = clean_text(err.decode("utf-8", "replace"), 1200)
    return result


# ---------------------------------------------------------------------------
# Request validation
# ---------------------------------------------------------------------------


def clean_text(value: Any, limit: int = MESSAGE_MAX_CHARS) -> str:
    """Single-line, control-character-free text of at most `limit` characters."""
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    text = "".join(ch if ch >= " " and ch != "\x7f" else " " for ch in text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: max(0, limit - 3)].rstrip() + "..."
    return text


def validate_workspace(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise AdapterError(
            ERR_BAD_REQUEST,
            "the execute request has no workspace_root; run it with a workspace (sentra plugin run --workspace <directory>)",
        )
    if not os.path.isabs(value):
        raise AdapterError(ERR_BAD_REQUEST, "workspace_root must be an absolute path")
    if not os.path.isdir(value):
        raise AdapterError(ERR_BAD_REQUEST, "workspace_root is not an existing directory")
    return os.path.realpath(value)


def is_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([os.path.normcase(path), os.path.normcase(root)]) == os.path.normcase(root)
    except ValueError:  # different drives on Windows
        return False


def resolve_configs(arguments: dict, workspace: str) -> List[Tuple[str, str]]:
    """Returns [(absolute rules path, display label)].

    `config` (or its alias `ruleset`) is a string or a list of strings. Relative values
    are resolved against the workspace root; every value must, after resolving links,
    be an existing file or directory inside the workspace or inside the operator's
    `rules/` directory next to the adapter. Without `config`, that `rules/` directory
    is used if it exists.
    """
    if "config" in arguments and "ruleset" in arguments:
        raise AdapterError(ERR_BAD_REQUEST, "pass either 'config' or its alias 'ruleset', not both")
    raw = arguments.get("config", arguments.get("ruleset"))
    operator_rules = os.path.realpath(OPERATOR_RULES_DIR)

    if raw is None:
        if os.path.isdir(operator_rules):
            return [(operator_rules, "adapter rules/")]
        raise AdapterError(
            ERR_BAD_REQUEST,
            "no Semgrep rules configured: pass arguments {\"config\": \"<rules file or directory inside the workspace>\"} "
            "or put local rules in the adapter's rules/ directory. Registry rulesets are not downloaded "
            "(the manifest declares egress_policy strictly_denied).",
        )

    values = raw if isinstance(raw, list) else [raw]
    if not values or len(values) > MAX_CONFIG_ENTRIES:
        raise AdapterError(ERR_BAD_REQUEST, f"'config' must name 1-{MAX_CONFIG_ENTRIES} local rules paths")

    resolved: List[Tuple[str, str]] = []
    for value in values:
        if not isinstance(value, str) or not value.strip() or len(value) > MAX_CONFIG_VALUE_CHARS or "\x00" in value:
            raise AdapterError(ERR_BAD_REQUEST, "each 'config' entry must be a non-empty path string")
        value = value.strip()
        shown = clean_text(value, 120)
        lowered = value.lower()
        if lowered == "auto" or lowered.startswith(REGISTRY_PREFIXES):
            raise AdapterError(
                ERR_BAD_REQUEST,
                f"'{shown}' is a Semgrep registry ruleset or URL; this adapter only runs local rules because its manifest "
                "declares egress_policy strictly_denied. Download the rules you are licensed to use and pass their local path.",
            )
        candidate = value if os.path.isabs(value) else os.path.join(workspace, value)
        real = os.path.realpath(candidate)
        if is_within(real, workspace):
            label = os.path.relpath(real, workspace).replace(os.sep, "/")
        elif os.path.isdir(operator_rules) and is_within(real, operator_rules):
            rel = os.path.relpath(real, operator_rules).replace(os.sep, "/")
            label = "adapter rules/" + ("" if rel == "." else rel)
        else:
            raise AdapterError(
                ERR_BAD_REQUEST,
                f"rules path '{shown}' is outside the workspace and the adapter's rules/ directory (links are resolved first)",
            )
        if not os.path.exists(real):
            raise AdapterError(ERR_BAD_REQUEST, f"rules path '{shown}' does not exist")
        if not (os.path.isfile(real) or os.path.isdir(real)):
            raise AdapterError(ERR_BAD_REQUEST, f"rules path '{shown}' is not a file or directory")
        resolved.append((real, label))
    return resolved


def bounded_int(arguments: dict, key: str, default: int, low: int, high: int) -> int:
    value = arguments.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise AdapterError(ERR_BAD_REQUEST, f"'{key}' must be an integer from {low} to {high}")
    return value


# ---------------------------------------------------------------------------
# Report summary
# ---------------------------------------------------------------------------


def display_path(raw: Any, workspace: str) -> str:
    if not isinstance(raw, str) or not raw:
        return "?"
    absolute = raw if os.path.isabs(raw) else os.path.join(ADAPTER_DIR, raw)
    absolute = os.path.normpath(absolute)
    if is_within(absolute, workspace):
        return os.path.relpath(absolute, workspace).replace(os.sep, "/")
    return clean_text(raw, 160)


def severity_of(result: dict) -> str:
    extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
    label = clean_text(extra.get("severity"), 24).upper()
    return label or "UNKNOWN"


def line_of(result: dict) -> Any:
    start = result.get("start") if isinstance(result.get("start"), dict) else {}
    line = start.get("line")
    return line if isinstance(line, int) else "?"


def summarize_report(
    report: Any,
    workspace: str,
    config_labels: List[str],
    max_results: int,
    budget_bytes: int,
) -> str:
    if not isinstance(report, dict):
        raise AdapterError(ERR_SEMGREP_FAILED, "Semgrep JSON output is not an object")
    results = report.get("results")
    errors = report.get("errors") or []
    if not isinstance(results, list) or not isinstance(errors, list):
        raise AdapterError(ERR_SEMGREP_FAILED, "Semgrep JSON output has no results/errors arrays")
    results = [r for r in results if isinstance(r, dict)]

    counts: Dict[str, int] = {}
    files = set()
    for result in results:
        sev = severity_of(result)
        counts[sev] = counts.get(sev, 0) + 1
        files.add(display_path(result.get("path"), workspace))
    order = sorted(counts, key=lambda s: (SEVERITY_RANK.get(s, 9), s))
    by_severity = ", ".join(f"{s} {counts[s]}" for s in order)

    version = clean_text(report.get("version"), 32) or "unknown version"
    paths = report.get("paths") if isinstance(report.get("paths"), dict) else {}
    scanned = paths.get("scanned")
    scanned_text = f"{len(scanned)} file(s) scanned" if isinstance(scanned, list) else "scanned file count not reported"

    header = (
        f"Semgrep {version}: {len(results)} finding(s)"
        + (f" in {len(files)} file(s) ({by_severity})" if results else "")
        + f"; {scanned_text}; {len(errors)} Semgrep error(s); rules: {clean_text(', '.join(config_labels), 300)}."
    )
    lines = [header]
    for err in errors[:MAX_ERROR_LINES]:
        if isinstance(err, dict):
            where = f" ({display_path(err.get('path'), workspace)})" if err.get("path") else ""
            lines.append(f"Semgrep {clean_text(err.get('level'), 16) or 'error'}{where}: {clean_text(err.get('message'), 200)}")
    if len(errors) > MAX_ERROR_LINES:
        lines.append(f"... {len(errors) - MAX_ERROR_LINES} more Semgrep error(s) not shown.")

    ranked = sorted(
        results,
        key=lambda r: (
            SEVERITY_RANK.get(severity_of(r), 9),
            display_path(r.get("path"), workspace),
            line_of(r) if isinstance(line_of(r), int) else 0,
        ),
    )
    # Reserve room for the "Top N" header and the "... more" trailer.
    used = len("\n".join(lines).encode("utf-8")) + 240
    entries: List[str] = []
    for index, result in enumerate(ranked[:max_results], start=1):
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        entry = (
            f"{index}. [{severity_of(result)}] {clean_text(result.get('check_id'), 120) or '?'} at "
            f"{display_path(result.get('path'), workspace)}:{line_of(result)}: {clean_text(extra.get('message'))}"
        )
        cost = len(entry.encode("utf-8")) + 1
        if used + cost > budget_bytes:
            break
        entries.append(entry)
        used += cost
    if entries:
        lines.append(f"Top {len(entries)} of {len(results)} finding(s), most severe first:")
        lines.extend(entries)
    if len(entries) < len(results):
        lines.append(
            f"... {len(results) - len(entries)} more finding(s) not listed "
            f"(max_results {max_results}, summary limit {budget_bytes} bytes)."
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------


def handle_initialize(req: dict) -> dict:
    log(f"initialize (host interface version {req.get('host_version')})")
    return {
        "status": "initialize_ack",
        "plugin_id": PLUGIN_ID,
        "interface_version": INTERFACE_VERSION,
        "capabilities": CAPABILITIES,
    }


def semgrep_version(command: List[str]) -> Tuple[Optional[str], str]:
    _, deadline = read_quotas()
    try:
        run = run_bounded(command + ["--version"], min(VERSION_TIMEOUT_SECS, scan_timeout_cap(deadline)), 4096)
    except OSError as exc:
        return None, f"semgrep could not be started: {clean_text(exc, 200)}"
    if run.timed_out:
        return None, "semgrep --version did not answer in time"
    if run.returncode != 0:
        return None, f"semgrep --version exited with {run.returncode}: {run.stderr_tail or 'no stderr'}"
    version = clean_text(run.stdout.decode("utf-8", "replace"), 64)
    return (version or "unknown version"), ""


def handle_probe(req: dict) -> dict:
    workspace = req.get("workspace_root")
    if not isinstance(workspace, str) or not os.path.isabs(workspace) or not os.path.isdir(workspace):
        return {
            "status": "probe_result",
            "applicable": False,
            "details": "workspace_root is missing or not an existing directory",
            "unsupported_reason": "invalid workspace_root",
        }
    command, note = find_semgrep()
    if command is None:
        return {
            "status": "probe_result",
            "applicable": False,
            "details": "Semgrep CLI not available; install it and make sure it is on the PATH of the process that runs sentra",
            "unsupported_reason": note,
        }
    version, problem = semgrep_version(command)
    if version is None:
        return {
            "status": "probe_result",
            "applicable": False,
            "details": f"semgrep found at {note} but not usable",
            "unsupported_reason": problem,
        }
    rules = "operator rules/ directory present" if os.path.isdir(OPERATOR_RULES_DIR) else "no operator rules/ directory; execute needs arguments.config"
    return {
        "status": "probe_result",
        "applicable": True,
        "details": f"Semgrep {version} at {note}; {rules}. Only local rules are run.",
        "unsupported_reason": None,
    }


def handle_plan(req: dict) -> dict:
    input_ref = req.get("input_ref", "")
    return {
        "status": "plan_result",
        "input_refs": [input_ref] if isinstance(input_ref, str) and input_ref else [],
        "predicted_cost_micro_usd": 0,  # local process, no paid API
        "required_capabilities": ["static_analysis"],
    }


def handle_execute(req: dict) -> dict:
    task_id = req.get("task_id")
    if not isinstance(task_id, str) or not task_id:
        raise AdapterError(ERR_BAD_REQUEST, "execute request has no task_id")
    if req.get("capability") != "static_analysis":
        raise AdapterError(ERR_BAD_REQUEST, f"capability '{clean_text(req.get('capability'), 64)}' is not provided by this adapter")
    arguments = req.get("arguments")
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        raise AdapterError(ERR_BAD_REQUEST, "arguments must be a JSON object")
    unknown = sorted(k for k in arguments if k not in ALLOWED_ARGUMENTS)
    if unknown:
        raise AdapterError(
            ERR_BAD_REQUEST,
            f"unknown argument(s) {', '.join(clean_text(k, 40) for k in unknown[:5])}; accepted: {', '.join(ALLOWED_ARGUMENTS)}",
        )

    workspace = validate_workspace(req.get("workspace_root"))
    configs = resolve_configs(arguments, workspace)
    max_frame_bytes, deadline = read_quotas()
    cap = scan_timeout_cap(deadline)
    timeout_secs = bounded_int(arguments, "timeout_secs", cap, 1, cap)
    max_results = bounded_int(arguments, "max_results", DEFAULT_MAX_RESULTS, 0, MAX_RESULTS_LIMIT)
    git_ignore = arguments.get("git_ignore", False)
    if not isinstance(git_ignore, bool):
        raise AdapterError(ERR_BAD_REQUEST, "'git_ignore' must be true or false")

    command, note = find_semgrep()
    if command is None:
        raise AdapterError(ERR_SEMGREP_UNAVAILABLE, note)

    argv = command + ["scan", "--json", "--metrics=off", "--disable-version-check"]
    if not git_ignore:
        argv.append("--no-git-ignore")
    for path, _ in configs:
        argv += ["--config", path]
    argv.append(workspace)

    log(f"task {task_id}: running {note} on the workspace with {len(configs)} rules path(s), timeout {timeout_secs}s")
    try:
        run = run_bounded(argv, timeout_secs, MAX_REPORT_BYTES)
    except OSError as exc:
        raise AdapterError(ERR_SEMGREP_UNAVAILABLE, f"semgrep could not be started: {clean_text(exc, 200)}")

    if run.timed_out:
        raise AdapterError(
            ERR_SEMGREP_TIMEOUT,
            f"Semgrep did not finish within {timeout_secs}s and was stopped; no results are reported. "
            "Narrow the rules or the workspace, or raise the manifest's max_execution_time_secs.",
        )
    if run.stdout_overflow:
        raise AdapterError(
            ERR_SEMGREP_FAILED,
            f"Semgrep JSON output exceeded {MAX_REPORT_BYTES // (1024 * 1024)} MiB and was not parsed; narrow the rules or the workspace.",
        )

    report: Any = None
    try:
        report = json.loads(run.stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        report = None

    # Exit codes: https://docs.semgrep.dev/cli-reference (0 = success without --error,
    # 1 = findings with --error, >= 2 = failure).
    if run.returncode not in (0, 1) or report is None:
        detail = ""
        if isinstance(report, dict) and isinstance(report.get("errors"), list) and report["errors"]:
            first = report["errors"][0]
            if isinstance(first, dict):
                detail = f" First Semgrep error: {clean_text(first.get('message'), 300)}"
        state = "returned no parseable JSON" if report is None else "reported a failure"
        incomplete = "" if run.stdout_complete else " (stdout was still open after Semgrep exited)"
        raise AdapterError(
            ERR_SEMGREP_FAILED,
            f"Semgrep exited with {run.returncode} and {state}{incomplete}.{detail} stderr: {run.stderr_tail or 'none'}",
        )

    budget = max(512, min(SUMMARY_MAX_BYTES, max_frame_bytes - FRAME_OVERHEAD_BYTES))
    summary = summarize_report(report, workspace, [label for _, label in configs], max_results, budget)
    response = {
        "status": "execute_result",
        "task_id": task_id,
        "exit_code": 0,
        "evidence_refs": ["sha256:" + hashlib.sha256(run.stdout).hexdigest()],
        "summary": summary,
    }
    # Escaping can grow the frame; shrink the summary until the frame fits.
    while len(encode(response)) > max_frame_bytes and budget > 512:
        budget //= 2
        response["summary"] = summarize_report(report, workspace, [label for _, label in configs], max_results, budget)
    if len(encode(response)) > max_frame_bytes:
        response["summary"] = clean_text(response["summary"].split("\n", 1)[0], 200)
    return response


def handle_cancel(req: dict) -> dict:
    # Requests are handled one at a time, so no task is running when a cancel is read.
    task_id = req.get("task_id", "")
    log(f"cancel for task {clean_text(task_id, 128)}: no task is running")
    return {"status": "cancel_ack", "task_id": task_id if isinstance(task_id, str) else "", "terminated": False}


HANDLERS = {
    "initialize": handle_initialize,
    "probe": handle_probe,
    "plan": handle_plan,
    "execute": handle_execute,
    "cancel": handle_cancel,
}


def handle_line(raw: bytes) -> Tuple[Optional[dict], bool]:
    """Returns (response frame or None for a blank line, whether to stop)."""
    try:
        text = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return error_frame(ERR_BAD_REQUEST, "request frame is not valid UTF-8"), False
    if not text:
        return None, False
    try:
        req = json.loads(text)
    except ValueError as exc:
        return error_frame(ERR_BAD_REQUEST, f"malformed JSON: {clean_text(exc, 200)}"), False
    if not isinstance(req, dict):
        return error_frame(ERR_BAD_REQUEST, "request frame must be a JSON object"), False
    op = req.get("operation")
    if op == "shutdown":
        return {"status": "shutdown_ack"}, True
    handler = HANDLERS.get(op) if isinstance(op, str) else None
    if handler is None:
        return error_frame(ERR_BAD_REQUEST, f"unknown operation '{clean_text(op, 64)}'"), False
    try:
        return handler(req), False
    except AdapterError as exc:
        log(f"{op} failed ({exc.code}): {exc.message}")
        return error_frame(exc.code, exc.message), False
    except Exception as exc:  # never die silently; the host reports the error frame
        log(f"{op} raised {type(exc).__name__}: {clean_text(exc, 300)}")
        return error_frame(ERR_INTERNAL, f"internal adapter error ({type(exc).__name__})"), False


def main() -> None:
    log("waiting for frames on stdin")
    for raw in sys.stdin.buffer:
        response, stop = handle_line(raw)
        if response is not None:
            emit(response)
        if stop:
            log("shutdown acknowledged")
            break


if __name__ == "__main__":
    main()
