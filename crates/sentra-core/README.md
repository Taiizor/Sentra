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
- **12-Ecosystem Lockfile Auditor:** Native parsing and OSV/RustSec vulnerability auditing across Cargo, Bun, npm (v1/v3), Yarn (classic/berry), pnpm (v6/v9), Poetry, Pip, Go sum, Composer, Gemfile, NuGet, and Deno lockfiles.
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

let report = scanner.scan_content(code, "handler.ts");
println!("Findings detected: {}", report.findings.len());
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](https://github.com/Taiizor/Sentra/blob/develop/LICENSE) for details.
