# Sentra Adapter: Snyk Dependency Auditor

A protocol example of a dependency-audit subprocess adapter for the **Sentra Security Platform**. It does not perform software composition analysis: it never starts the Snyk CLI, never contacts Snyk and never reads a lockfile's contents. Its results are fixed sample data.

Authored in **TypeScript** and executed natively with [Bun](https://bun.sh).

---

## Capabilities

- **`dependency_audit`**: `probe` reports whether one of `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `requirements.txt`, `go.sum` or `composer.lock` exists at the workspace root (it only checks that the file exists). `execute` always returns the same summary, `Snyk audit detected 2 vulnerable package(s).`, built from two hard-coded sample vulnerabilities (axios 0.21.1 and lodash 4.17.15), and the placeholder evidence label `sha256:snyk-audit-<task id>`, whatever the workspace contains. Treat the output as test data.

---

## Standalone Verification

You can test this adapter directly using Bun:

```bash
# 1. Initialize Handshake
echo '{"operation":"initialize","host_version":1}' | bun run adapter.ts

# 2. Probe Current Workspace
echo '{"operation":"probe","workspace_root":"."}' | bun run adapter.ts

# 3. Execute Dependency Audit
echo '{"operation":"execute","task_id":"snyk-task-01","lease_id":"lease-01","capability":"dependency_audit","arguments":{"severity_threshold":"high"}}' | bun run adapter.ts

# 4. Graceful Shutdown
echo '{"operation":"shutdown"}' | bun run adapter.ts
```
