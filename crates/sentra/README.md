<div align="center">
  <img src="https://raw.githubusercontent.com/Taiizor/Sentra/develop/assets/sentra-logo.svg" width="100" height="100" alt="Sentra Logo" />
  <h1>Sentra</h1>
  <p><strong>AI-Assisted Security Research & Remediation Platform</strong></p>
</div>

`sentra` is the primary library package for the Sentra security platform. It re-exports the core and the CLI in safe Rust (`#![forbid(unsafe_code)]`): heuristic line-based SAST with intra-procedural lexical taint tracking (no syntax tree is built), lockfile parsers matched against a small bundled advisory sample, a local stdio MCP server, and verification bundles that are modelled but not executed, because no isolated runner exists yet. See [docs/LIMITATIONS.md](https://github.com/Taiizor/Sentra/blob/develop/docs/LIMITATIONS.md).

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
sentra = "0.3.0"
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
- **🧪 Three-Tier Verification Invariant (modelled, not yet executed):** A remediation patch may be marked verified only if (1) the baseline fails on unpatched code, (2) the target passes on remediated code, and (3) existing test suites show zero regressions. No isolated runner executes verification bundles yet, so no patch is marked verified.
- **🤖 Native Model Context Protocol (MCP) Server:** Built-in JSON-RPC 2.0 stdio transport (`sentra mcp`) for integration with Claude Desktop, Cursor, and IDE coding agents.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](https://github.com/Taiizor/Sentra/blob/develop/LICENSE) for details.
