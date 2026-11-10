# Sentra Adapter: Snyk Dependency Auditor

A reference subprocess adapter connecting Snyk Software Composition Analysis (SCA) with the **Sentra Security Platform**.

Authored in **TypeScript** and executed natively with [Bun](https://bun.sh).

---

## Capabilities

- **`dependency_audit`**: Inspects dependency lockfiles (npm, Yarn, pnpm, Cargo, pip, Composer) and evaluates known vulnerability databases.

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
