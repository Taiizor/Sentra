<div align="center">
  <img src="https://raw.githubusercontent.com/Taiizor/Sentra/develop/assets/sentra-logo.svg" width="100" height="100" alt="Sentra Logo" />
  <h1>sentra-core</h1>
  <p><strong>Core Security Analysis & Verification Engine</strong></p>

  [![Crates.io](https://img.shields.io/crates/v/sentra-core.svg)](https://crates.io/crates/sentra-core)
  [![Documentation](https://docs.rs/sentra-core/badge.svg)](https://docs.rs/sentra-core)
  [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
  [![Safety](https://img.shields.io/badge/Unsafe-Forbidden-success.svg)](https://github.com/Taiizor/Sentra)
</div>

Core security analysis, intra-procedural taint tracking, lockfile vulnerability auditing, and evidence verification engine for the [Sentra](https://github.com/Taiizor/Sentra) platform.

Strictly implemented under `#![forbid(unsafe_code)]` in Safe Rust.

## Features

- **In-Engine Pure-Rust Taint Analysis:** Fast, zero-dependency lexical data-flow tracking for SQL Injection (CWE-89), OS Command Injection (CWE-78), Dynamic Code Eval (CWE-95), and Path Traversal (CWE-22) with automatic sanitizer and constant-argument false-positive suppression.
- **Lockfile Parsing and Inventory:** Pure-Rust parsers for Cargo, Bun (text `bun.lock`), npm (v1/v3), Yarn (classic/berry), pnpm (v6/v9), Poetry, Pipenv, pip `requirements.txt`, Go `go.sum`, Composer, Gemfile, NuGet and Deno lockfiles. `collect_lockfile_inventory` discovers them recursively and read-only, with a skip list, depth and size limits, and no link or junction traversal. It reports each package with its OSV ecosystem name, and each lockfile's parse error. The built-in `AdvisoryDatabase::default_pinned` is a small, fixed sample, not a synchronized OSV or RustSec feed. It is stamped with its curation date (`PINNED_ADVISORY_SET_CURATED_AT_MILLIS`, 2026-11-08), not the current time, so `is_stale` reports its real age.
- **Positional Patch Engine:** `UnifiedPatch` / `PatchPlan` apply a single-file unified diff by hunk position with exact context and a bounded offset search. All hunks apply or nothing is written. Line endings are preserved. A patch is reported as already applied only when every hunk's post-image is at its own position.
- **Pure-Rust Differential Review:** Directory snapshot comparisons with SHA-256 tree hashing, 1:1 rename detection, and bounded hunk generation.
- **Three-Tier Verification Engine:** Strict verification invariant ensuring remediation patches reproduce original failures, pass on patched code, and break zero regression suites.
- **Model Context Protocol (MCP):** JSON-RPC 2.0 stdio server for seamless AI coding assistant integrations.
- **Durable Persistence:** ACID transactions with SQLite WAL mode and content-addressed CAS blob storage.

## Usage

Add `sentra-core` to your `Cargo.toml`:

```toml
[dependencies]
sentra-core = "0.1.0"
```

### Static Analysis & Taint Flow Tracking

```rust
use sentra_core::sast::scanner::SastScanner;

let scanner = SastScanner::new();
let code = r#"
    let user_input = req.query.id;
    let query = "SELECT * FROM users WHERE id = " + user_input;
    db.execute(query);
"#;

// The file name selects language rules; matches are unverified candidates.
let matches = scanner.scan_content("handler.ts", code);
println!("Candidate signals: {}", matches.len());
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](https://github.com/Taiizor/Sentra/blob/develop/LICENSE) for details.
