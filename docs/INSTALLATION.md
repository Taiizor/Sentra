# Sentra Installation & Getting Started Guide

**Target Audience:** Operators, Security Researchers, Enterprise Administrators  
**Platform Version:** 0.3.0  
**Supported Host Platforms:** Windows 11 x64 (PowerShell 7), Linux x86_64 (Docker container test runner)  

---

## 1. Prerequisites

Before installing and compiling Sentra from source, verify that your development environment satisfies the following requirements:

### 1.1 Operating System & Shell
- **Windows 11 x64** with **PowerShell 7+** (recommended development host).
- Paths must use forward slashes (`/`) consistently across all tooling.

### 1.2 Toolchain & Compilers
- **Rust & Cargo:** Version 1.88+ (edition 2024 with let-chains; tested on stable 1.99.0 x64 MSVC).
  ```powershell
  rustc --version
  cargo --version
  ```
- **MSVC Build Tools:** Microsoft Visual C++ Build Tools (14.40+) including Windows 11 SDK (required for bundling native SQLite).
- **Bun Runtime:** Bun is the sole JavaScript/TypeScript runtime and package manager used by Sentra tooling.
  ```powershell
  bun --version
  ```
  *(Note: Node.js, npm, npx, pnpm, and yarn are not installed and not used).*

### 1.3 Container Runtime (Optional for Linux Verification)
- **Docker Desktop** (Engine 24.0+ with Linux container backend) for running isolated multi-platform integration tests via `scripts/docker-test.ps1`.

---

## 2. Building from Source

Clone the repository and build all workspace crates using offline-capable Cargo flags:

```powershell
# Clone the repository
git clone https://github.com/Taiizor/Sentra.git
cd Sentra

# Build all workspace crates (sentra-core and sentra-cli)
cargo build --workspace

# Build optimized release binaries
cargo build --workspace --release
```

The compiled binaries will be placed in `target/debug/sentra.exe` (or `target/release/sentra.exe`).

---

## 3. Running the Verification Test Suite

Sentra includes extensive integration test suites ensuring 100% fail-closed containment, memory safety, and cross-platform determinism.

### 3.1 Host Test Execution (Windows 11 MSVC)
Run the complete workspace test suite (on Windows 11 x64 on 2026-11-11: 857 tests and 7 compile-fail doctests passed, 5 tests ignored):

```powershell
# Run all workspace unit and integration tests
cargo test --workspace

# Run code formatting check
cargo fmt --all -- --check

# Run static analysis and linting (fails on warnings)
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

### 3.2 Isolated Linux Docker Container Execution
Sentra provides an isolated, multi-suite Linux Docker test runner that mounts the host workspace read-only:

```powershell
# Run all 23 independent test suites in Linux Docker
pwsh -NoProfile -File scripts/docker-test.ps1 -Mode all

# Run specific suite (e.g. dashboard tests)
pwsh -NoProfile -File scripts/docker-test.ps1 -Mode test -Package sentra-core -TestName dashboard_tests
```

---

## 4. Local CLI Usage

The `sentra` CLI provides local repository inspection, audit, session recovery, and dependency vulnerability detection:

### 4.1 Help and Command Overview
```powershell
cargo run --package sentra-cli -- --help
```

### 4.2 Initialize Project Context
Initialize a new local security workspace and foundation session:
```powershell
sentra init --workspace ./my-project --database ./sentra.db --json
```

### 4.3 Inspect Workspace Status
Query workspace health, active session, and discovery metadata:
```powershell
sentra status --workspace ./my-project --database ./sentra.db --json
```

### 4.4 Audit Dependency Advisories (Bundled Sample Only)
Match the packages of the lockfiles at the workspace root (12 formats) against the small advisory sample bundled with Sentra (6 hand-written records, curated 2026-11-08). It is not a synchronized OSV or RustSec feed, so a clean result says nothing about advisories outside the sample; advisories are matched by package name and version only, without comparing ecosystems. `sentra sync-advisories` only checks that local OSV JSON parses and persists nothing. See [LIMITATIONS.md](LIMITATIONS.md#6-web-console-and-pinned-core-commands).
```powershell
sentra audit --workspace ./my-project --database ./sentra.db --json
```

### 4.5 Operator Recovery for Interrupted Stores
Recover an incomplete or interrupted initialization store:
```powershell
sentra recover --workspace ./my-project --database ./sentra.db --json
```
