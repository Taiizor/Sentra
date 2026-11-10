<div align="center">
  <img src="https://raw.githubusercontent.com/Taiizor/Sentra/develop/assets/sentra-logo.svg" width="100" height="100" alt="Sentra Logo" />
  <h1>Sentra</h1>
  <p><strong>Autonomous Security Research & Independently Verified Remediation Platform</strong></p>
</div>

`sentra` is the primary library package for the Sentra security platform. It provides the full deterministic AST & taint analysis core alongside autonomous AI agent orchestration and verification in safe Rust (`#![forbid(unsafe_code)]`).

---

## Installation

### As a Rust Dependency

Add Sentra to your `Cargo.toml`:

```bash
cargo add sentra
```

Or manually in `Cargo.toml`:

```toml
[dependencies]
sentra = "0.1.0"
```

### As a CLI Tool

To install the Sentra command-line interface binary (`sentra`):

```bash
cargo install sentra-cli
```

Verify installation:

```bash
sentra --help
```

---

## Features

- **🛡️ In-Engine Pure-Rust Taint Analysis & SAST:** Zero-dependency lexical data-flow tracking detecting SQL Injection (CWE-89), Command Injection (CWE-78), Dynamic Code Eval (CWE-95), Path Traversal (CWE-22), and hardcoded credential leaks.
- **📦 Lockfile Inventory:** Recursive, read-only lockfile discovery (`sentra inventory`) with pure-Rust parsers for Cargo, Bun (text `bun.lock`), npm (v1/v3), Yarn (classic/berry), pnpm (v6/v9), Poetry, Pipenv, pip `requirements.txt`, Go `go.sum`, Composer, Gemfile, NuGet and Deno; packages are reported with OSV ecosystem names. The built-in advisory set is a small, fixed sample, not a synchronized OSV or RustSec feed.
- **🧪 Three-Tier Verification Invariant:** Remediation patches are marked verified if and only if: (1) baseline fails on unpatched code, (2) target passes on remediated code, and (3) zero regressions across existing test suites.
- **🤖 Native Model Context Protocol (MCP) Server:** Built-in JSON-RPC 2.0 stdio transport (`sentra mcp`) for integration with Claude Desktop, Cursor, and IDE coding agents.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](https://github.com/Taiizor/Sentra/blob/develop/LICENSE) for details.
