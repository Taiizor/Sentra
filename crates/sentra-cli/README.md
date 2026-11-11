<div align="center">
  <img src="https://raw.githubusercontent.com/Taiizor/Sentra/develop/assets/sentra-logo.svg" width="100" height="100" alt="Sentra Logo" />
  <h1>sentra-cli</h1>
  <p><strong>Command-Line Interface for Sentra</strong></p>

  [![Crates.io](https://img.shields.io/crates/v/sentra-cli.svg)](https://crates.io/crates/sentra-cli)
  [![Documentation](https://docs.rs/sentra-cli/badge.svg)](https://docs.rs/sentra-cli)
  [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
  [![Safety](https://img.shields.io/badge/Unsafe-Forbidden-success.svg)](https://github.com/Taiizor/Sentra)
</div>

Command-line interface and terminal tools for [Sentra](https://github.com/Taiizor/Sentra), an AI-assisted security research and remediation platform. Remediation output is a local preview; no patch is built, tested or verified (see [docs/LIMITATIONS.md](https://github.com/Taiizor/Sentra/blob/develop/docs/LIMITATIONS.md)).

Provides the `sentra` binary.

## Installation

Install via `cargo`:

```bash
cargo install sentra-cli
```

Once installed, the `sentra` executable will be available in your `PATH`.

## Quick Start

```bash
# Display help and available commands
sentra --help

# Initialize a new local security workspace and foundation session
sentra init --workspace ./my-project --database ./sentra.db

# Inspect workspace health, active session, and discovery metadata
sentra status --workspace ./my-project --database ./sentra.db

# Run heuristic line-based secret and antipattern rules (results are unverified candidates)
sentra scan --workspace ./my-project

# Scan an inline snippet; --file-name labels it and selects the language rules
sentra scan --snippet "let q = 'SELECT * FROM users WHERE id = ' + req.query.id; db.execute(q);" --file-name handler.ts --json
cat handler.go | sentra scan - --file-name handler.go --json

# List lockfiles (recursive, read-only, links not followed) and their parsed packages
sentra inventory --workspace ./my-project [--max-depth 6] --json

# Validate a single-file unified diff without writing anything
sentra patch apply --patch fix.patch --workspace ./my-project --target src/db.ts --dry-run --json

# Apply it (all hunks or nothing), keep a backup, and record a PatchApplied audit event
sentra patch apply --patch fix.patch --workspace ./my-project --target src/db.ts \
  --backup-dir ./backups --database ./sentra.db --json

# Restore from the backup and record a PatchRolledBack audit event
sentra patch rollback --backup ./backups/db.ts_<millis>.bak --workspace ./my-project \
  --target src/db.ts --database ./sentra.db --json

# Compare two directory snapshots with pure-Rust diff engine
sentra diff --base ./repo-v1 --head ./repo-v2

# Launch the local MCP stdio server (legacy revisions 2025-11-25 ... 2024-11-05), confined to a workspace
sentra mcp --workspace ./my-project [--database ./sentra.db]

# Install bundled skills or register the MCP server for an agent (targets: docs/EXTENSIONS.md)
sentra install claude --skill golang-security --workspace ./my-project --json
sentra install mcp cursor --workspace ./my-project

# Plugins load only from --dir or the default plugin directory (SENTRA_PLUGIN_DIR, else the platform plugin directory)
sentra plugin list --dir ./examples/adapters
```

## Command Contracts

All `--json` output is a single line on stdout; failures print
`{"schema_version":1,"error":"<code>"}` on stderr with a non-zero exit code.

`init`, `status`, `session`, `recover`, `audit`, `scan` and `diff` refuse a
workspace or `--database` path that passes through a symbolic link or junction,
also in a directory above it (`invalid_workspace` or
`invalid_storage_location`, exit 4); the path is not resolved first. On macOS
this includes `/tmp/...` and `/var/...` (links to `/private/...`); see
[docs/LIMITATIONS.md](https://github.com/Taiizor/Sentra/blob/develop/docs/LIMITATIONS.md).

### `sentra inventory [--workspace <dir>] [--max-depth <n>] --json`

Discovers supported lockfiles recursively (default depth 6, maximum 32) and
skips `.git`, `node_modules`, `target`, `vendor`, `dist`, `build`, `out`,
`.venv`, `venv`, `__pycache__`, `.next`, `.nuxt`, `.gradle`, `.idea`,
`.vscode`, `bin` and `obj`. Symbolic links and junctions are never followed.
Nothing is executed or written.

```json
{"schema_version":1,"command":"inventory","workspace":"E:/repo","lockfiles":[{"path":"web/bun.lock","kind":"Bun","ecosystem":"npm","packages":123,"parse_error":null}],"packages":[{"name":"react","version":"19.3.1","ecosystem":"npm","lockfile":"web/bun.lock"}],"total_packages":123,"truncated":false,"untrusted_execution":false}
```

`ecosystem` uses OSV names (`crates.io`, `npm`, `PyPI`, `Go`, `Packagist`,
`NuGet`, `RubyGems`; Deno JSR packages are labelled `JSR`). Local code is not
listed: Cargo workspace/path members (no `source`) and npm-family
`workspace:`/`file:`/`link:`/`portal:` packages. Rows are distinct per lockfile
by name and version. A lockfile that
cannot be read or parsed is listed with `packages: 0` and a `parse_error`.
`truncated` is true when an entry, lockfile or package limit cut the result
short. An invalid workspace exits 4 with `invalid_workspace`; an out-of-range
depth exits 2 with `invalid_arguments`.

### `sentra scan (--snippet <code> | -) --file-name <name> --json`

`<name>` must match `^[A-Za-z0-9._-]{1,100}$`. It selects the language rule
families by extension and becomes `file_path` in every match. It is rejected
together with `--workspace`. Without it, a snippet is labelled `snippet.ts`.

Secret rules (`SECRET_LEAK`) are line heuristics. They cover AWS access key IDs
(`SENTRA-SEC-001`), AWS secret access keys next to an AWS secret identifier
(`SENTRA-SEC-006`), GitHub and Slack tokens, and private key headers.
`SENTRA-SEC-005` reports long quoted literals on secret keyword lines and
literals of 6 or more characters, containing a digit or symbol, assigned to an
identifier ending in `password`, `passwd` or `passphrase`. Unquoted values
count only in dotenv, YAML, properties, INI, shell and Dockerfile sources. A
line already reported by a specific secret rule is not reported again by
`SENTRA-SEC-005`. A secret that matches none of these heuristics is not
reported.

### `sentra patch apply ... [--dry-run] --json`

The diff must describe exactly one existing file. Every hunk is located by its
`@@ -a,b +c,d @@` header with exact context and removed lines, allowing at most
200 lines of offset. All hunks apply or nothing is written. There is no
whitespace fuzzing and no re-indentation. Line endings and a UTF-8 BOM are
preserved. `already_patched` is true only when the patch does not apply and
every hunk's post-image is already at its own position.

- Dry run, which writes nothing and does not open the store:
  `{"schema_version":1,"command":"patch apply","status":"success","dry_run":true,"target_path":"src/db.ts","already_patched":false,"hunks":1,"patch_sha256":"…","pre_image_sha256":"…","post_image_sha256":"…","untrusted_execution":false}`
- Apply:
  `{"schema_version":1,"command":"patch apply","status":"success","dry_run":false,"target_path":"src/db.ts","backup_path":"C:/backups/db.ts_1794333074535.bak","already_patched":false,"hunks":1,"audit_recorded":true,"patch_sha256":"…","pre_image_sha256":"…","post_image_sha256":"…","untrusted_execution":false}`

With `--database`, the existing local store must belong to `--workspace`. It is
validated before the file is touched. A `PatchApplied` event, carrying the
target, backup, hunk count and the three SHA-256 digests, is committed to the
session audit trail after the write. If the commit fails, the file is restored
and the command exits 5 with `storage_or_service_failure`. Without
`--database`, `audit_recorded` is `false`.

`patch rollback` prints `target_path`, `restored_from`, `audit_recorded` and the
pre-/post-image digests. With `--database` it records `PatchRolledBack`.

| Error code | Exit | Meaning |
| --- | --- | --- |
| `patch_does_not_apply` | 4 | Well-formed diff whose hunks do not match the target (or ambiguous) |
| `invalid_patch` | 4 | Unreadable, empty, malformed, multi-file, binary, creation or deletion diff |
| `invalid_patch_target` | 4 | Target missing, outside the workspace, behind a link, not a regular UTF-8 file |
| `invalid_backup` | 4 | Rollback backup missing, unreadable or not a regular file |
| `workspace_mismatch` / `incomplete_storage` | 4 / 6 | `--database` store belongs elsewhere or does not exist |
| `io_error` | 5 | Backup or target write failed |

### `sentra audit --database <file> [--workspace <dir>] --json`

Matches lockfile packages against the bundled pinned advisory sample. This is a
small hand-written set, not a synchronized OSV or RustSec feed, so a clean result
does not mean the dependencies have no known vulnerabilities. The output names
the set and its curation date. `is_stale` is true once that date is more than
30 days old.

```json
{"schema_version":1,"command":"audit","session_id":"…","task_id":"…","packages_audited":1,"vulnerable_packages":1,"is_stale":false,"advisory_db_source":"bundled_pinned_sample","advisory_db_records":6,"advisory_db_updated_at":"2026-11-08T23:43:22.000Z","unknown_version_packages":[],"findings":[…],"untrusted_execution":false}
```

### `sentra fleet status --json` / `sentra fleet list --json`

No worker registry source exists yet, so the registry is empty and no workers
are invented. `containment_ready` is never `true`: Sentra does not attest
worker isolation, so a declared containment level is not evidence.
`containment_status` is `no_workers`, or `unattested` when workers are
registered in-process.

```json
{"schema_version":1,"command":"fleet status","total_workers":0,"available_workers":0,"active_leases":0,"quarantined_workers":0,"containment_ready":false,"containment_status":"no_workers","untrusted_execution":false}
```

### `sentra tenant list --database <file> --json`

Read-only. It lists the rows that exist. A missing file or a missing table
yields `"total":0`. No demo rows are seeded and nothing is created.

### `sentra tenant add --id <id> --name <name> --database <file> --json`

Writes to a dedicated tenant registry file, which it creates when missing. A
Sentra core store (core `application_id` or a `schema_migrations` table) is
refused with `invalid_storage_location` (exit 4) and is not modified, because an
extra table would break the core store's exact-schema check.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](https://github.com/Taiizor/Sentra/blob/develop/LICENSE) for details.
