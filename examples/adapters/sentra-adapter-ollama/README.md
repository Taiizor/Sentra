# Sentra Adapter: Ollama Local AI Provider

A reference subprocess adapter connecting local [Ollama](https://ollama.com/) instances to the **Sentra Security Platform** for local patch generation against a loopback Ollama daemon.

---

## Capabilities

- **`patch_generation`**: Generates unified diff remediation proposals using local coding models (`deepseek-coder`, `qwen2.5-coder`, `llama3`).
- **Network Egress Policy**: Declares `whitelisted_local_only` and only connects to `http://127.0.0.1:11434`. The host does not enforce the policy; nothing prevents other network access.

---

## Standalone Verification

```bash
# 1. Initialize Handshake
echo '{"operation":"initialize","host_version":1}' | python adapter.py

# 2. Probe Local Ollama Daemon & Installed Models
echo '{"operation":"probe","workspace_root":"."}' | python adapter.py

# 3. Plan Zero-Cost Inference
echo '{"operation":"plan","input_ref":"prompt-manifest-1"}' | python adapter.py

# 4. Generate Remediation Patch
echo '{"operation":"execute","task_id":"task-cve-fix","lease_id":"lease-01","capability":"patch_generation","arguments":{"model":"deepseek-coder:6.7b","prompt":"Fix SQL Injection in src/db.rs"}}' | python adapter.py

# 5. Graceful Shutdown
echo '{"operation":"shutdown"}' | python adapter.py
```
