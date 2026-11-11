# Sentra Adapter: Semgrep SAST

A reference subprocess adapter connecting [Semgrep](https://semgrep.dev/) with the **Sentra Security Platform**.

---

## Capabilities

- **`source_discovery`**: Probes the target repository for supported languages (TypeScript, JavaScript, Python, Go, Rust, Java, C).
- **`static_analysis`**: Executes semantic rulesets and formats outputs into normalized Sentra finding structures.

---

## File Structure

- `manifest.json`: Official plugin manifest declaring quotas, ID, and the `strictly_denied` egress policy. The policy is declared, not enforced: `semgrep --config p/security-audit` downloads its rules from the Semgrep registry.
- `adapter.py`: Standalone Python script implementing the newline-delimited JSON IPC state machine.

---

## Standalone Verification

You can test this adapter manually via stdin/stdout:

```bash
# 1. Initialize Handshake
echo '{"operation":"initialize","host_version":1}' | python adapter.py

# Expected Output:
# {"status":"initialize_ack","plugin_id":"org.sentra.adapter.semgrep","interface_version":1,"capabilities":["source_discovery","static_analysis"]}

# 2. Probe Workspace
echo '{"operation":"probe","workspace_root":"."}' | python adapter.py

# 3. Execute Analysis
echo '{"operation":"execute","task_id":"task-123","lease_id":"lease-abc","capability":"static_analysis","arguments":{"ruleset":"p/security-audit"}}' | python adapter.py

# 4. Graceful Shutdown
echo '{"operation":"shutdown"}' | python adapter.py
```
