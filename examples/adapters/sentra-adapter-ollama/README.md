# Sentra Adapter: Ollama Local AI Provider

A reference subprocess adapter connecting local [Ollama](https://ollama.com/) instances to the **Sentra Security Platform** for air-gapped, zero-cloud patch generation.

---

## Capabilities

- **`patch_generation`**: Generates unified diff remediation proposals using local coding models (`deepseek-coder`, `qwen2.5-coder`, `llama3`).
- **Network Egress Policy**: Bound strictly to `whitelisted_local_only` (connects only to `http://127.0.0.1:11434`; all public internet access is prohibited).

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
