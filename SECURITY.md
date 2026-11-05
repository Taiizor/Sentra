# Security Policy

## Current project status

Sentra is in the documentation stage. There are no application releases, supported binaries, hosted services, or implemented security guarantees. All isolation, approval, and privacy controls described in this repository are requirements for future implementations.

Only analyze software and environments for which you have explicit authorization. A repository's visibility, or possession of its source, is not permission to test a deployed service.

## Reporting a vulnerability in Sentra

A private reporting channel has not yet been established or tested. Before the first public release, maintainers must configure a private security-reporting channel, publish its verified contact details here, and define acknowledgment and remediation targets. No monitored email address or response SLA is claimed today.

Do not place secrets, proprietary source, working exploit artifacts, or undisclosed vulnerability details in public issues. Until a private channel is available, a public issue may request a private contact without including sensitive details. Vulnerabilities discovered in an analyzed third-party target must be handled with that target's authorized owner and disclosure process, rather than assumed to be Sentra vulnerabilities.

## Required security posture

- Require a recorded project scope and authorization reference before analysis.
- Default to local state and deny network egress unless an explicit policy permits it.
- Require a disposable VM boundary for real untrusted builds, tests, scanners, and PoCs; do not run them directly on the developer host.
- Separate model credentials, acquisition credentials, operator files, and target execution.
- Treat repository instructions, logs, model text, and plugin results as untrusted data.
- Require independent evidence review and fresh execution for verified findings and patches.
- Require action-specific approval for sensitive execution, scope changes, source transfer, checkout changes, publication, and remote repository writes.
- Bound time, spend, fanout, processes, memory, disk, and artifact sizes; record incomplete work.

These requirements apply equally to open-source and proprietary targets. The permission model is specified in [THREAT_MODEL.md](docs/THREAT_MODEL.md), and the task/approval records in [DATA_MODEL.md](docs/DATA_MODEL.md).

## Privacy and evidence

Local-first means that project state and artifacts are kept locally by default. It does not mean a hosted provider never receives source. Hosted inference requires a separate egress decision describing endpoint, data categories, retention assumptions, and permitted repository scope. Do not promise training exclusion or zero retention without validating the chosen provider's applicable terms and configuration.

Generated PoCs, crash dumps, source snippets, patches, and dependency names may expose confidential information. Access and export rules follow the input classification. Default telemetry must contain no source or raw prompts and remain opt-in. Exact retention defaults are a Phase 2 decision; sessions must declare retention before collecting sensitive evidence.

## Limits of assurance

A local administrator can compromise local state and credentials. Containers share a guest/host kernel, and Docker Desktop/WSL2 convenience does not establish a disposable research boundary. A model can fabricate explanations or miss vulnerabilities. A clean scan is not proof of security; a patch can pass selected tests and still be incomplete. Reports must retain these practical limits and identify unverified claims.

Security controls and external integration permissions require re-evaluation as the platform grows. See the [threat model](docs/THREAT_MODEL.md), [isolation research](docs/research/ISOLATION.md), and [validation plan](docs/VALIDATION.md).
