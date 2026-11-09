<div align="center">
  <img src="https://raw.githubusercontent.com/Taiizor/Sentra/develop/assets/sentra-logo.svg" width="100" height="100" alt="Sentra Logo" />
  <h1>sentra-cli</h1>
  <p><strong>Command-Line Interface for Autonomous Security Research</strong></p>

  [![Crates.io](https://img.shields.io/crates/v/sentra-cli.svg)](https://crates.io/crates/sentra-cli)
  [![Documentation](https://docs.rs/sentra-cli/badge.svg)](https://docs.rs/sentra-cli)
  [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
  [![Safety](https://img.shields.io/badge/Unsafe-Forbidden-success.svg)](https://github.com/Taiizor/Sentra)
</div>

Command-line interface and terminal tools for [Sentra](https://github.com/Taiizor/Sentra) — an autonomous AI security research and independently verified remediation platform.

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

# Run pure-Rust taint analysis and secret scanning
sentra scan --workspace ./my-project

# Scan an inline code snippet with SARIF output
sentra scan --snippet "let q = 'SELECT * FROM users WHERE id = ' + req.query.id; db.execute(q);"

# Audit package dependencies across 12 lockfile formats
sentra audit --workspace ./my-project --database ./sentra.db

# Compare two directory snapshots with pure-Rust diff engine
sentra diff --base ./repo-v1 --head ./repo-v2

# Launch the Model Context Protocol (MCP) JSON-RPC 2.0 stdio server
sentra mcp
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](https://github.com/Taiizor/Sentra/blob/develop/LICENSE) for details.
