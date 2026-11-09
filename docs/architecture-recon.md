# Sentra Phase 1 Security Reconnaissance Summary
Generated under Cloudflare Security Audit Doctrine (RECONNAISSANCE.md Phase 1)
Target: Sentra (Pure-Rust Security Platform)

## 1. Product, Stack & Comparable Software
- **Product Type:** High-assurance SAST & Taint security analyzer with autonomous AI remediation and human-in-the-loop verification.
- **Tech Stack:** Rust 1.80+ (Core CLI/AST), Bun 1.2+ / TypeScript 5.8 / React 19 (Web Operator Dashboard), SQLite 3.45 (Immutable WAL Audit Trail).
- **Offline Limits:** Fully operational offline. No external cloud dependency required for AST scans, diff analysis, or coverage ledger verification.

## 2. Principals & Trust Boundaries
- **Lower-Trust Principals:** Untrusted workspace source code under review, external webhook payloads (GitHub/GitLab), untrusted LLM prompt outputs.
- **Authority Levels:** Viewer (Read-only AST metrics), Operator (Run scans & propose patches), SecurityAdmin (Apply verified patches to disk).
- **Core Invariant:** FailClosedBackend strictly rejects executing target-controlled build scripts or procedural macros.

## 3. Entry Surfaces & Monitored Sinks
- **Surfaces:** CLI arguments (`sentra scan`), Webhooks (`/api/webhook/github`), MCP Server IPC (`mcp://tools`), Vector RAG cache.
- **Monitored Sinks:** `Command::new`, `subprocess.run(shell=True)`, `db.execute`, `fs.readFile`, `tracing::info!`.

## 4. Companion Selection & Hunting Allocation
- **Selected Domains:** AI & LLM, Data Isolation, Supply Chain & CI/CD, Protocols & RPC, Resource Exhaustion.
- **Derived Units:** 14 Canonical Ledger Units seeded across 3 run waves.