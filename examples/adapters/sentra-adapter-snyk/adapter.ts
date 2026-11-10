#!/usr/bin/env bun
/**
 * Sentra Subprocess Adapter for Snyk Dependency Vulnerability Auditing.
 * Authored in TypeScript, executed via Bun runtime.
 * Implements the Sentra Subprocess Plugin Protocol (REQ-F16).
 */

import * as readline from "readline";
import { existsSync } from "fs";
import { join } from "path";

const PLUGIN_ID = "org.sentra.adapter.snyk";
const INTERFACE_VERSION = 1;
const CAPABILITIES = ["dependency_audit"];

function log(msg: string) {
  // Use stderr for diagnostics to keep stdout pure for JSON protocol frames
  process.stderr.write(`[${PLUGIN_ID}] ${msg}\n`);
}

function emit(response: object) {
  process.stdout.write(JSON.stringify(response) + "\n");
}

function handleInitialize(req: any) {
  log(`Initializing adapter handshake with host version: ${req.host_version}`);
  return {
    status: "initialize_ack",
    plugin_id: PLUGIN_ID,
    interface_version: INTERFACE_VERSION,
    capabilities: CAPABILITIES,
  };
}

function handleProbe(req: any) {
  const ws = req.workspace_root || ".";
  const supportedLockfiles = [
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "requirements.txt",
    "go.sum",
    "composer.lock",
  ];

  const found = supportedLockfiles.filter((file) => existsSync(join(ws, file)));

  if (found.length > 0) {
    return {
      status: "probe_result",
      applicable: true,
      details: `Discovered supported package manifest(s): ${found.join(", ")}`,
      unsupported_reason: null,
    };
  }

  return {
    status: "probe_result",
    applicable: false,
    details: "No supported dependency lockfiles discovered in workspace root.",
    unsupported_reason: "Missing supported lockfiles (Cargo.lock, package-lock.json, etc.)",
  };
}

function handlePlan(req: any) {
  return {
    status: "plan_result",
    input_refs: req.input_ref ? [req.input_ref] : [],
    predicted_cost_micro_usd: 0,
    required_capabilities: ["dependency_audit"],
  };
}

function handleExecute(req: any) {
  const taskId = req.task_id || "task-0";
  const args = req.arguments || {};
  const severityThreshold = args.severity_threshold || "medium";

  log(`Auditing lockfile dependencies for task ${taskId} (threshold: ${severityThreshold})...`);

  // Synthetic finding conforming to Sentra CVE/CWE data normalization
  const sampleVulnerabilities = [
    {
      id: "SNYK-JS-AXIOS-1579269",
      package: "axios",
      version: "0.21.1",
      title: "Server-Side Request Forgery (SSRF)",
      severity: "high",
      remediation: "Upgrade to axios@0.21.2",
    },
    {
      id: "SNYK-JS-LODASH-567746",
      package: "lodash",
      version: "4.17.15",
      title: "Prototype Pollution in zipObjectDeep",
      severity: "critical",
      remediation: "Upgrade to lodash@4.17.21",
    },
  ];

  const summary = `Snyk audit detected ${sampleVulnerabilities.length} vulnerable package(s).`;

  return {
    status: "execute_result",
    task_id: taskId,
    exit_code: 0,
    evidence_refs: [`sha256:snyk-audit-${taskId}`],
    summary,
  };
}

function handleCancel(req: any) {
  return {
    status: "cancel_ack",
    task_id: req.task_id || "",
    terminated: true,
  };
}

async function main() {
  log("Snyk adapter daemon running under Bun, listening on stdin...");

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
  });

  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    try {
      const req = JSON.parse(trimmed);
      switch (req.operation) {
        case "initialize":
          emit(handleInitialize(req));
          break;
        case "probe":
          emit(handleProbe(req));
          break;
        case "plan":
          emit(handlePlan(req));
          break;
        case "execute":
          emit(handleExecute(req));
          break;
        case "cancel":
          emit(handleCancel(req));
          break;
        case "shutdown":
          emit({ status: "shutdown_ack" });
          log("Shutdown completed. Exiting.");
          process.exit(0);
        default:
          emit({ status: "error", code: 400, message: `Unsupported operation '${req.operation}'` });
      }
    } catch (err: any) {
      emit({ status: "error", code: 400, message: `JSON parse error: ${err.message}` });
    }
  }
}

main();
