# Sentra Adapter: Semgrep (example)

An example subprocess adapter that runs a locally installed [Semgrep](https://semgrep.dev/) CLI on the workspace Sentra sends, with local rules only, and reports what Semgrep found.

Status (2026-11-11): the adapter is an **example**, not a supported integration. It was exercised through the real host (`sentra plugin probe` / `sentra plugin run`) and its unit tests on Windows 11 with Python 3.14.8, using a **stand-in `semgrep` executable** that prints Semgrep-shaped JSON. It has **not** been run against a real Semgrep installation; the Semgrep options it uses are taken from the Semgrep CLI reference (see [Sources](#sources)).

The adapter never fabricates findings. When Semgrep is missing, `probe` reports the adapter as not applicable and `run` fails with an error.

---

## Requirements

- Python 3 (standard library only). The manifest starts it as `python adapter.py`; the host looks `python` (or `python3`) up on `PATH`.
- The Semgrep CLI on the `PATH` of the process that runs `sentra` (for the web console, the bridge process). The host clears the adapter's environment except an allowlist that includes `PATH`; the adapter then searches only the **absolute** `PATH` entries, never its working directory. On Windows only `semgrep.exe` / `semgrep.com` are started: a `semgrep.bat` / `semgrep.cmd` shim is refused, because `cmd.exe` re-parses the arguments (which contain workspace paths). There is no setting for the Semgrep path: values from the request are never turned into a program to run.
- Local Semgrep rules (see below). The adapter ships none: Semgrep-maintained registry rules are not bundled ([ADR-0007](../../../docs/adr/0007-open-source-and-integration-licensing.md)) and have their own license terms.

## Rules: local only

The manifest declares `"egress_policy": "strictly_denied"`. The host records that declaration but does **not** enforce it, so the adapter keeps it honest itself:

- `config` must name local rules. Registry rulesets (`p/...`, `r/...`, `s/...`), `auto` and `http(s)://` URLs are refused with an error, because Semgrep would download them.
- Each `config` entry is a rules file or directory. A relative entry is resolved against the workspace root. After resolving links, every entry must lie **inside the workspace** or **inside this adapter's `rules/` directory**; anything else is refused, so a caller (for example a web-console user) cannot make Semgrep read arbitrary files on the host.
- Without `config`, the adapter uses `<adapter directory>/rules/` when the operator created it (put rules you are licensed to use there). Otherwise `run` fails and says how to configure rules. Rules inside the scanned workspace are only used when the caller names them, so the scanned repository cannot choose its own rules unasked.
- The adapter passes `--metrics=off` and `--disable-version-check`, removes every inherited `SEMGREP_*` variable (such as `SEMGREP_APP_TOKEN` or `SEMGREP_RULES`) and sets `SEMGREP_SEND_METRICS=off` and `SEMGREP_ENABLE_VERSION_CHECK=false`. Per the Semgrep CLI reference, `auto` metrics are sent when the config pulls from the Semgrep server or the user is logged in, and the version check contacts the Semgrep servers. Whether a real Semgrep makes no network requests with these settings was **not** tested here.

## Arguments (`sentra plugin run --args '<json>'`)

| Key | Type | Default | Meaning |
| :--- | :--- | :--- | :--- |
| `config` | string or array of 1–16 strings | `rules/` next to the adapter, if present | Local rules files or directories (see above). `ruleset` is accepted as an alias; passing both is an error. |
| `timeout_secs` | integer | the maximum | Semgrep time limit, 1 to `max_execution_time_secs` minus a margin of `min(20, max(1, max_execution_time_secs / 4))` seconds (rounded down) (100 s with the shipped 120 s quota), so the adapter can still answer before the host's session deadline. |
| `max_results` | integer 0–200 | 20 | Most findings listed in the summary (most severe first). |
| `git_ignore` | boolean | `false` | `false` passes `--no-git-ignore`, which per the Semgrep CLI reference makes Semgrep not call `git` and not consult `.gitignore`. `true` lets Semgrep use `git` in the workspace, where `git` reads the repository's own configuration (`.git/config`), which the scanned repository controls; use it only for trusted workspaces. |

Unknown keys are rejected, so a typo does not silently change the scan.

## What `run` does

```text
semgrep scan --json --metrics=off --disable-version-check [--no-git-ignore] --config <abs rules path>... <abs workspace root>
```

- The target is the absolute `workspace_root` from the `execute` frame (validated again: it must be an existing directory). The process is started with the adapter directory as its working directory, so the scan never depends on it. A request without `workspace_root` is refused.
- Semgrep's stdin is closed (it can never read protocol frames), stdout is captured up to 64 MiB, the last 8 KiB of stderr are kept (error messages quote up to 1,200 characters of it), and the process is killed when `timeout_secs` expires. On a timeout only the direct child is killed; anything it started is ended by the host's process-tree termination when the session ends.
- Exit codes 0 and 1 with parseable JSON count as a completed scan; anything else is a failure ([exit codes](https://docs.semgrep.dev/cli-reference)).

The `execute_result` (all fields adapter-reported):

- `exit_code`: `0` when the scan completed, whether or not it found anything.
- `summary`: Semgrep version, number of findings and of files with findings, counts by severity, files scanned, number of Semgrep errors (with the first three messages) and the rules used, followed by the top `max_results` findings as `[SEVERITY] rule-id at path:line: message`, with paths relative to the workspace. Text is reduced to single lines without control characters. The summary is at most 32 KiB and is shortened until the whole frame fits the manifest's `max_frame_bytes` (read from `manifest.json` next to the adapter); a trailing line says how many findings were not listed. The protocol has no structured findings field, so findings are not returned individually and are not stored by Sentra.
- `evidence_refs`: one label, `sha256:<hex>`, the SHA-256 of the Semgrep JSON report bytes. The report itself is not kept anywhere; Sentra never resolves or admits the label as evidence.

Failures are `error` frames, which the CLI reports as `plugin_adapter_error` (exit code 5):

| Code | Meaning |
| :--- | :--- |
| 400 | Invalid request: no `workspace_root`, a capability other than `static_analysis`, unknown or malformed arguments, no rules configured, a registry ruleset or URL, a rules path outside the allowed directories or missing. |
| 500 | Unexpected adapter error. |
| 502 | Semgrep failed: exit code other than 0/1, output that is not Semgrep JSON, or a report larger than 64 MiB. The message includes Semgrep's first error and its stderr tail. |
| 503 | Semgrep was not found on `PATH` or could not be started. |
| 504 | Semgrep did not finish within `timeout_secs`; no partial results are reported. |

## What `probe` does

It checks that `workspace_root` is an existing directory, looks for `semgrep` as described above and runs `semgrep --version` (at most 30 s). It reports `applicable: false` with an `unsupported_reason` when the workspace is invalid, Semgrep is missing or `--version` fails, and otherwise `applicable: true` with the version, the executable path and whether an operator `rules/` directory exists. It does not inspect the workspace's languages.

`plan` returns `static_analysis` with zero predicted cost. `cancel` answers `terminated: false`: requests are handled one at a time, so no task is running when a cancel is read (the host does not send `plan` or `cancel` today).

## Residual risks

- **Not sandboxed.** Semgrep runs with the operator's privileges and parses the scanned (untrusted) code; the host enforces the session deadline, output quotas and process-tree termination, not memory or network limits. See [`docs/PLUGINS_GUIDE.md` §7](../../../docs/PLUGINS_GUIDE.md#7-security-model-and-residual-risks).
- `egress_policy` remains a declaration. The adapter refuses registry and URL configs and turns metrics and the version check off, but nothing stops a Semgrep version from contacting the network.
- Semgrep's own side effects, such as settings or log files it may write under the user's home directory, were not observed here.
- How a `.semgrepignore` in the workspace is applied when the workspace is passed as an absolute target from another working directory depends on the Semgrep version and was not tested.

## Files

- `manifest.json`: id, the single `static_analysis` capability, quotas (120 s session deadline, 1 MiB frames) and the declared `strictly_denied` egress policy.
- `adapter.py`: the adapter (newline-delimited JSON over stdio, UTF-8).
- `tests/test_adapter.py`: standard-library unit tests with a Python stand-in for Semgrep. Run from the repository root (writes only to temporary directories, no bytecode):

  ```bash
  python examples/adapters/sentra-adapter-semgrep/tests/test_adapter.py
  ```

The `tests/` directory is not needed at run time; you can leave it out when copying the adapter into a plugin directory.

## Trying it

```bash
# Install: copy the adapter (see docs/PLUGINS_GUIDE.md §2), optionally with a rules/ directory.
sentra plugin probe --id org.sentra.adapter.semgrep --workspace ./my-project
sentra plugin run --id org.sentra.adapter.semgrep --capability static_analysis \
  --workspace ./my-project --args '{"config": ".semgrep.yml"}' --json
```

Standalone, without Sentra (one request per line on stdin; `workspace_root` must be absolute):

```bash
printf '%s\n' \
  '{"operation":"initialize","host_version":1}' \
  '{"operation":"probe","workspace_root":"/abs/path/to/project"}' \
  '{"operation":"execute","task_id":"task-1","lease_id":"lease-task-1","capability":"static_analysis","workspace_root":"/abs/path/to/project","arguments":{"config":".semgrep.yml"}}' \
  '{"operation":"shutdown"}' | python adapter.py
```

## Sources

- Semgrep CLI reference, <https://docs.semgrep.dev/cli-reference> (read 2026-11-11): `--config`, `--json`, `--metrics` / `SEMGREP_SEND_METRICS`, `--disable-version-check` / `SEMGREP_ENABLE_VERSION_CHECK`, `--no-git-ignore`, exit codes. Source-reported behaviour, not verified with a real Semgrep here.
