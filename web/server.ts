import { spawn } from "node:child_process";
import path from "node:path";
import fs from "node:fs/promises";
import os from "node:os";

const PORT = 3001;
const REPO_ROOT = path.resolve(import.meta.dirname, "..");
const SENTRA_BIN = path.resolve(REPO_ROOT, "target/debug/sentra.exe");
const DEFAULT_STORAGE = path.resolve(REPO_ROOT, "../sentra_web_storage/sentra.db");

// Helper to run sentra.exe and collect JSON output
function runSentra(args: string[]): Promise<{ code: number; stdout: string; stderr: string; data?: any }> {
  return new Promise((resolve) => {
    const child = spawn(SENTRA_BIN, args, {
      cwd: REPO_ROOT,
      windowsHide: true,
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("close", (code) => {
      let data = undefined;
      try {
        const trimmed = stdout.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
          data = JSON.parse(trimmed);
        }
      } catch (err) {
        // Not JSON
      }
      resolve({ code: code ?? 0, stdout, stderr, data });
    });

    child.on("error", (err) => {
      resolve({ code: -1, stdout, stderr: err.message });
    });
  });
}

const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);
    const origin = req.headers.get("origin") || "*";

    // Standard CORS headers
    const corsHeaders = {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Content-Type": "application/json",
    };

    if (req.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // Health check
    if (url.pathname === "/api/health") {
      const exists = await fs
        .access(SENTRA_BIN)
        .then(() => true)
        .catch(() => false);
      return new Response(
        JSON.stringify({
          status: "ok",
          binaryPath: SENTRA_BIN,
          binaryExists: exists,
          defaultStorage: DEFAULT_STORAGE,
          repoRoot: REPO_ROOT,
        }),
        { headers: corsHeaders }
      );
    }

    // POST /api/scan
    if (url.pathname === "/api/scan" && req.method === "POST") {
      try {
        const body = (await req.json()) as { workspace?: string };
        const workspace = body.workspace || path.resolve(REPO_ROOT, "crates/sentra-core/tests");
        const res = await runSentra(["scan", "--workspace", workspace, "--json"]);
        return new Response(JSON.stringify(res.data || { raw: res.stdout, error: res.stderr, code: res.code }), {
          headers: corsHeaders,
        });
      } catch (err: any) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: corsHeaders });
      }
    }

    // POST /api/audit
    if (url.pathname === "/api/audit" && req.method === "POST") {
      try {
        const body = (await req.json()) as { workspace?: string; database?: string };
        const workspace = body.workspace || REPO_ROOT;
        const database = body.database || DEFAULT_STORAGE;
        const res = await runSentra(["audit", "--workspace", workspace, "--database", database, "--json"]);
        return new Response(JSON.stringify(res.data || { raw: res.stdout, error: res.stderr, code: res.code }), {
          headers: corsHeaders,
        });
      } catch (err: any) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: corsHeaders });
      }
    }

    // POST /api/codeql
    if (url.pathname === "/api/codeql" && req.method === "POST") {
      try {
        const body = (await req.json()) as { workspace?: string };
        const workspace = body.workspace || REPO_ROOT;
        const res = await runSentra(["codeql", "--workspace", workspace, "--json"]);
        return new Response(JSON.stringify(res.data || { raw: res.stdout, error: res.stderr, code: res.code }), {
          headers: corsHeaders,
        });
      } catch (err: any) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: corsHeaders });
      }
    }

    // POST /api/diff
    if (url.pathname === "/api/diff" && req.method === "POST") {
      try {
        const body = (await req.json()) as { base?: string; head?: string };
        const base = body.base || path.resolve(REPO_ROOT, "crates/sentra-core");
        const head = body.head || path.resolve(REPO_ROOT, "crates/sentra-cli");
        const res = await runSentra(["diff", "--base", base, "--head", head, "--json"]);
        return new Response(JSON.stringify(res.data || { raw: res.stdout, error: res.stderr, code: res.code }), {
          headers: corsHeaders,
        });
      } catch (err: any) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: corsHeaders });
      }
    }

    // POST /api/status
    if (url.pathname === "/api/status" && req.method === "POST") {
      try {
        const body = (await req.json()) as { workspace?: string; database?: string };
        const workspace = body.workspace || REPO_ROOT;
        const database = body.database || DEFAULT_STORAGE;
        const res = await runSentra(["status", "--workspace", workspace, "--database", database, "--json"]);
        return new Response(JSON.stringify(res.data || { raw: res.stdout, error: res.stderr, code: res.code }), {
          headers: corsHeaders,
        });
      } catch (err: any) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: corsHeaders });
      }
    }

    // POST /api/scan-snippet (Live Studio Code Sandbox)
    if (url.pathname === "/api/scan-snippet" && req.method === "POST") {
      try {
        const body = (await req.json()) as { code: string; language?: string };
        const extMap: Record<string, string> = {
          rust: "rs",
          python: "py",
          javascript: "js",
          typescript: "ts",
          json: "json",
          yaml: "yaml",
          yml: "yml",
          text: "txt",
        };
        const ext = extMap[body.language || ""] || "ts";
        const tempDir = path.resolve(REPO_ROOT, "target/tmp_studio_" + Date.now());
        await fs.mkdir(tempDir, { recursive: true });
        const filePath = path.resolve(tempDir, `sample.${ext}`);
        await fs.writeFile(filePath, body.code, "utf8");

        const res = await runSentra(["scan", "--workspace", tempDir, "--json"]);
        await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});

        return new Response(JSON.stringify(res.data || { raw: res.stdout, error: res.stderr, code: res.code }), {
          headers: corsHeaders,
        });
      } catch (err: any) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: corsHeaders });
      }
    }

    return new Response(JSON.stringify({ error: "Not Found" }), { status: 404, headers: corsHeaders });
  },
});

console.log(`[Sentra Web Bridge] Bun server listening on http://localhost:${server.port}`);
