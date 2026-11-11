# Contributing to Sentra

Thank you for your interest in contributing to **Sentra**! Sentra is an open-source, local-first security review toolkit (heuristic SAST rules, lockfile auditing, differential review, patch application and a web console). Scanner and model output are unverified candidates; see [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for what is not implemented.

To maintain our rigorous safety, determinism, and security standards, all contributions must adhere to the guidelines outlined below.

---

## 1. Core Architectural & Security Invariants

Every contribution must preserve Sentra's foundational security invariants:

1. **Strictly Safe Rust:** `#![forbid(unsafe_code)]` is unconditionally enforced across all Rust crates. Pull requests introducing `unsafe` code or disabling this attribute will be rejected.
2. **Fail-Closed Design:** Any ambiguous path, permission error, corrupted record, or unexpected state transition must fail closed with explicit typed errors.
3. **Zero Unexpected Host Network Egress:** Core analysis, local workspace discovery, and offline lockfile auditing must never trigger unauthorized outbound network connections.
4. **Secret Redaction:** Any new token, credential, or sensitive string output must pass through `RedactionFilter` before persistence or logging.
5. **Disposable Worker Containment:** Execution of untrusted code, build scripts, tests, or fuzzing targets must strictly occur within isolated disposable worker boundaries (`ContainmentLevel::DisposableVm` or disposable ephemeral container profiles).
6. **Three-Tier Patch Verification:** Automated remediation patches must be supported by cryptographic verification bundles proving:
   - Original baseline tests fail on unpatched code.
   - Target tests pass on patched code.
   - All existing regression test suites pass without degradation.

---

## 2. Development Prerequisites

- **Rust:** Stable toolchain (`rustc 1.85+`, `cargo`, `rustfmt`, `clippy`).
- **Bun:** Sole JavaScript/TypeScript runtime and package manager (`bun --version >= 1.2`).  
  *Note: Node.js, npm, npx, yarn, and pnpm are not used in this repository.*
- **Operating Systems:**
  - **Windows:** Windows 11 / Windows 10 x64 with MSVC toolchain and PowerShell 7.
  - **Linux:** Linux x86_64 (Debian, Ubuntu, Arch, Fedora) with GCC / Clang.
  - **macOS:** Apple Silicon (ARM64) or Intel (x86_64) with Xcode Command Line Tools.
- **Docker (Optional):** For executing the isolated Linux container test runner (`scripts/docker-test.ps1`).

---

## 3. Getting Started & Local Workflow

### 3.1 Clone the Repository

```bash
git clone https://github.com/Taiizor/Sentra.git
cd Sentra
git checkout develop
```

### 3.2 Building and Testing Rust Crates

```bash
# Check compilation across all crates
cargo check --workspace

# Run all workspace unit and integration tests
cargo test --workspace

# Verify code formatting
cargo fmt --all -- --check

# Run strict clippy analysis (fails on any warning)
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

### 3.3 Building the Web Dashboard

```bash
# Install frontend dependencies using Bun
cd web
bun install --frozen-lockfile

# Run Oxlint
bun run lint

# Build production bundle with TypeScript type-checking
bun run build
```

---

## 4. Submitting a Pull Request

1. **Branching Strategy:**
   - Always branch off `develop` (e.g., `feat/my-feature` or `fix/reparse-point-handling`).
   - Keep pull requests focused, atomic, and tied to a single roadmap milestone or bug fix.
2. **Commit Messages:**
   - Follow [Conventional Commits](https://www.conventionalcommits.org/):
     - `feat: add OSV advisory parser for Ruby gems`
     - `fix: prevent TOCTOU race during ancestor directory pinning`
     - `docs: update Phase 2 cross-platform verification records`
3. **Pull Request Checklist:**
   - Complete the [Pull Request Template](.github/pull_request_template.md).
   - Ensure all CI suites pass (`cargo fmt`, `cargo clippy`, `cargo test` across OS matrix, and `bun run build`).
   - Document any new CLI arguments, configuration options, or domain entities.
4. **Code Review & Governance:**
   - All PRs undergo human-in-the-loop technical review.
   - Merging requires passing all status checks (`CI Success Gate`, `CodeQL Analysis`).

---

## 5. Reporting Security Vulnerabilities

Please **do not** open public GitHub issues for sensitive security vulnerabilities. Follow our coordinated vulnerability disclosure process in [SECURITY.md](SECURITY.md) or use [GitHub Private Vulnerability Reporting](https://github.com/Taiizor/Sentra/security/advisories/new).
