# Security Policy

## Current project status

Sentra provides a complete, independently verified security analysis platform implemented entirely in safe Rust (`#![forbid(unsafe_code)]`):
- **Core Governance & Audit:** Strict session lifecycles, default-deny policy engine, SQLite WAL persistence, and content-addressed evidence storage with immutable source snapshots.
- **Differential Review & Advisory Auditing:** Base/head differential analysis, offline zero-dependency advisory auditing, capability-scoped AI reasoning, and disposable worker patch verification.
- **Autonomous Research Engine:** Deep security research campaigns, multi-agent Scout/Analyst task fanout, structured coverage ledgers, and Linux C/C++ user-space fuzzing integration with root-cause crash minimization.
- **Extensibility & Agent Interoperability:** Subprocess plugin SDK with capability fencing and local Model Context Protocol (MCP) server for Claude Desktop, Cursor, and custom IDEs.
- **Continuous Hosted Integrations:** Authenticated webhook intake with RFC 2104 / RFC 4231 HMAC-SHA256 signatures, replay defense, and approval-gated remediation proposals with zero-secret fork boundaries.
- **Fleet Orchestration & Web Management:** Enterprise management dashboard, multi-tenant session isolation, role-based access control (RBAC), supported-target capability matrices, and remote worker fleet isolation audits.

Untrusted target repository execution remains **strictly disabled and fail-closed** by default on the host development machine (`FailClosedBackend`). Target code execution requires an approved, isolated disposable Linux VM worker (`ADR-0004`).

Only analyze software and environments for which you have explicit, documented authorization. A repository's public visibility, or possession of its source code, is not authorization to test deployed infrastructure or services.

---

## Reporting a Vulnerability in Sentra

The Sentra project takes the security of its platform and users seriously. We maintain a coordinated vulnerability disclosure process for reporting security defects in Sentra itself.

### Private Reporting Channel
- **Primary Reporting Channel:** Submit security advisories privately via **GitHub Security Advisories** on the official Sentra repository (`Security` tab -> `Report a vulnerability`).
- **Alternative Email Channel:** If GitHub private reporting is unavailable, submit reports to `taiizor@vegalya.com` encrypted with the published project PGP key.

### Response & Triage SLA
- **Initial Acknowledgment:** Within **48 hours** of report receipt.
- **Triage & Impact Assessment:** Within **7 calendar days**, with classification according to CVSS v3.1.
- **Remediation & Patch Verification:** Targeted within **30 days** for critical/high vulnerabilities, and within **90 days** for coordinated public disclosure.

### Responsible Disclosure Guidelines
- **Do not disclose publicly:** Do not publish vulnerability details, reproduction scripts, or exploit artifacts in public issues, discussions, or pull requests prior to coordinated release.
- **Third-Party Targets:** Vulnerabilities discovered in an analyzed third-party repository or package must be reported directly to that project's authorized security contacts, not to the Sentra team.

---

## Required Security Posture & Invariants

1. **Explicit Scope & Authorization:** Every security analysis session must specify an explicit repository boundary. Reparse points, symlinks escaping the workspace, and parent components are rejected.
2. **Fail-Closed Execution:** Real untrusted builds, procedural macros, tests, scanners, and PoCs must never execute on the host developer workstation. A dedicated disposable Linux VM boundary with `StrictlyDenied` network egress is mandatory (`ADR-0004`).
3. **Zero Secret Inheritance:** Worker execution environments must never receive host tokens, API keys, or write credentials. Untrusted fork PR runs unconditionally enforce `secrets_permitted: false`.
4. **Three-Tier Patch Verification:** An automated remediation proposal is verified only when original baseline tests fail, target tests pass on patched code, and all regression suites pass without regression.
5. **Anti-Collusion & Confused Deputy Prevention:** AI models and automated agents cannot self-approve remediation proposals. All sensitive operations require explicit human operator admission (`HumanApprovalRequired`).
6. **Immutable Audit Trail:** All mutations, policy evaluations, and approvals emit monotonically sequenced, immutable audit records (`AuditEventKind`).
7. **Multi-Tenant Fencing:** Cross-tenant resource queries or worker allocations fail closed at the core domain boundary (`CrossTenantAccessDenied`, `CrossTenantWorkerAccessDenied`).

---

## Privacy, Retention, and Evidence

1. **Local-First Default:** All session records, finding databases, and content-addressed evidence blobs are stored locally by default.
2. **Zero Unexpected Egress:** Local inference endpoints enforce `Location::Local` with zero external network traffic. Sensitive tokens (PEM private keys, GitHub PATs, GitLab tokens, AWS keys, Bearer tokens) are automatically redacted before logging.
3. **Evidence Retention:** Evidence storage is bounded by strict configurable quotas (`StorageLimits`). Sensitive artifacts adhere to the security classification of the analyzed input.

---

## Limits of Assurance

1. **Host Administrator Compromise:** A malicious local operating system administrator or process executing under the same user token with elevated privileges can compromise local storage. Unprivileged NTFS cannot prevent same-user hostile file deletion without service credential boundaries.
2. **Container Boundaries:** Container engines sharing a host kernel (such as Docker Desktop or WSL2) do not satisfy Sentra's hostile-target containment requirements.
3. **Absence of Proof:** A clean scan is not proof of vulnerability absence; a patch that passes selected regression tests may still contain subtle edge-case flaws.
4. **Target Matrices:** Target support is restricted to verified 7-tuples. Universal language, tool, or kernel support is not claimed.

For full technical specifications, refer to [THREAT_MODEL.md](docs/THREAT_MODEL.md), [LIMITATIONS.md](docs/LIMITATIONS.md), and [ARCHITECTURE.md](ARCHITECTURE.md).
