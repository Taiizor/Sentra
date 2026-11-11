import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import {
  CANNOT_RUN_HERE_LABEL,
  describeCannotRun,
  describeToolPath,
  otherCopiesLabel,
  toolActions,
  toolDetectionSummary,
  toolPathUsageText,
  toolStatus,
} from "../../src/components/dashboard/tool-row-format.ts";
import type { BinaryInfo, ToolAvailability, ToolSearchStatus } from "../../src/types/api.ts";

// Wording of the console's tools table and tool badges (Host & workers, Settings → System).

const NATIVE: BinaryInfo = { format: "elf", architectures: ["arm64"], compatibility: "native", note: null };
const FOREIGN: BinaryInfo = { format: "elf", architectures: ["x64"], compatibility: "incompatible", note: "x64 binary cannot run on arm64 Linux unless binfmt_misc/qemu-user is configured" };

function row(overrides: Partial<ToolAvailability>): ToolAvailability {
  return {
    name: "semgrep",
    available: true,
    path: "/usr/bin/semgrep",
    resolvedPath: null,
    resolvedVia: null,
    source: "process_path",
    onProcessPath: true,
    binary: NATIVE,
    usage: "not_used",
    usageNote: "",
    shadowed: [],
    selection: "automatic",
    configuredPath: null,
    configuredPathProblem: null,
    pathConfigurable: true,
    pathHint: null,
    ...overrides,
  };
}

const SEARCH: ToolSearchStatus = {
  searchedDirectories: 12,
  skippedNetworkEntries: 0,
  persistedPathRead: true,
  persistedPathError: null,
  refreshedAt: "2026-11-11T00:00:00.000Z",
};

describe("tool status", () => {
  test("a broken configured path still says when the file shown instead cannot run here", () => {
    const tool = row({ configuredPath: "/opt/semgrep", configuredPathProblem: "Nothing exists at /opt/semgrep.", binary: FOREIGN });
    const status = toolStatus(tool);
    expect(status.kind).toBe("configured_broken");
    expect(status.detail).toBe("showing automatic detection: built for another platform — cannot run here");
    expect(status.title).toContain("Automatic detection found /usr/bin/semgrep, which is shown instead. Its header says it cannot run on this host:");
    expect(status.title).toContain("Built for: x64");
    expect(describeToolPath(tool)).toContain("Its header says it cannot run on this host");
    // A usable fallback is not flagged.
    expect(toolStatus({ ...tool, binary: NATIVE }).detail).toBe("showing automatic detection");
    expect(toolStatus({ ...tool, available: false, path: null, binary: null }).detail).toBe("automatic detection: not found");
  });

  test("the cannot-run detail names the format, what the file is built for and why, nothing else", () => {
    expect(describeCannotRun(FOREIGN)).toBe(`ELF executable\nBuilt for: x64\n${FOREIGN.note}`);
    expect(describeCannotRun({ format: "macho_universal", architectures: ["ia32", "unknown"], compatibility: "incompatible", note: null })).toBe(
      "Mach-O universal binary\nBuilt for: ia32",
    );
    const status = toolStatus(row({ binary: FOREIGN }));
    expect(status).toMatchObject({ kind: "cannot_run", label: CANNOT_RUN_HERE_LABEL, detail: null });
    expect(status.title).not.toContain("On this host");
  });
});

describe("other copies of a tool", () => {
  test("for a chosen path they are what automatic detection found, not later matches", () => {
    const configured = row({ path: "/opt/semgrep/semgrep", source: "configured", selection: "configured", configuredPath: "/opt/semgrep/semgrep", shadowed: ["/usr/bin/semgrep"] });
    expect(otherCopiesLabel(configured)).toBe("1 other copy found automatically");
    const tooltip = describeToolPath(configured);
    expect(tooltip).toContain("Other copies found by automatic detection (not reported while a path is set in the console):\n  /usr/bin/semgrep");
    expect(tooltip).not.toContain("Later matches");

    const pinnedGh = row({ name: "gh", path: "/opt/gh/gh", source: "environment", selection: "environment", shadowed: ["/usr/bin/gh", "/usr/local/bin/gh"], pathConfigurable: false });
    expect(otherCopiesLabel(pinnedGh)).toBe("2 other copies found automatically");
    expect(describeToolPath(pinnedGh)).toContain("Other copies found by automatic detection (not run while SENTRA_GH_BIN is set):");

    const automatic = row({ shadowed: ["/usr/local/bin/semgrep"] });
    expect(otherCopiesLabel(automatic)).toBe("1 later match");
    expect(describeToolPath(automatic)).toContain("Later matches in search order:\n  /usr/local/bin/semgrep");
    expect(otherCopiesLabel(row({}))).toBeNull();
  });
});

describe("path actions", () => {
  const states: [string, ToolAvailability][] = [
    ["not found", row({ available: false, path: null, source: null, binary: null })],
    ["found automatically", row({})],
    ["set in the console", row({ source: "configured", selection: "configured", configuredPath: "/opt/semgrep" })],
    ["broken console path", row({ configuredPath: "/opt/semgrep", configuredPathProblem: "Nothing exists at /opt/semgrep." })],
  ];

  test("every state of a settable tool keeps the path button, so focus survives a save or reset", () => {
    expect(states.map(([state, tool]) => [state, toolActions(tool).edit?.label, toolActions(tool).reset?.label ?? null])).toEqual([
      ["not found", "Set path", null],
      ["found automatically", "Change", null],
      ["set in the console", "Change", "Reset to automatic"],
      ["broken console path", "Change", "Reset to automatic"],
    ]);
    expect(toolActions(states[0][1]).edit?.primary).toBe(true);
    expect(toolActions(states[1][1]).edit?.primary).toBe(false);
  });

  test("accessible names start with the visible label (WCAG 2.5.3) and name the tool", () => {
    for (const [, tool] of states) {
      const { edit, reset } = toolActions(tool);
      for (const button of [edit, reset]) {
        if (!button) continue;
        expect(button.ariaLabel.startsWith(button.label)).toBe(true);
        expect(button.ariaLabel).toContain(tool.name);
      }
    }
    expect(toolActions(states[0][1]).edit?.ariaLabel).toBe("Set path for semgrep");
    expect(toolActions(states[2][1]).reset?.ariaLabel).toBe("Reset to automatic detection for semgrep");
  });

  test("gh and bun get no actions; gh says how its path is set instead", () => {
    const hint = "Set SENTRA_GH_BIN on the bridge host, or store a GitHub token in Settings.";
    expect(toolActions(row({ name: "gh", pathConfigurable: false, pathHint: hint }))).toEqual({ edit: null, reset: null, hint });
    expect(toolActions(row({ name: "bun", usage: "runtime", pathConfigurable: false }))).toEqual({ edit: null, reset: null, hint: null });
  });
});

describe("tool path wording", () => {
  test("Settings → System says the search, not running a tool, is what a console path replaces", () => {
    const summary = toolDetectionSummary(SEARCH, "linux");
    expect(summary).toBe(
      "Found automatically by searching the bridge process PATH, the persisted PATH (/etc/environment) and standard install locations, unless a path was set in the console (or SENTRA_GH_BIN for gh). Finding a tool never runs it.",
    );
    expect(summary).not.toMatch(/without running any tool, unless/);
  });

  test("the dialog names a scan message only for codeql", () => {
    expect(toolPathUsageText("codeql")).toContain("in the CodeQL stage message of scans");
    for (const tool of ["git", "cargo", "semgrep", "osv-scanner", "docker"]) {
      const text = toolPathUsageText(tool);
      expect(text).not.toMatch(/\bscans?\b|scan message/i);
      expect(text).toContain("topology reports");
      expect(text).toContain(`still look ${tool} up on the bridge process PATH`);
    }
  });

  test("the tool path dialog keeps the dialog's phone gutter (no unprefixed max-w-* override)", () => {
    const source = fs.readFileSync(path.join(import.meta.dir, "..", "..", "src", "components", "dashboard", "tool-path-dialog.tsx"), "utf8");
    const classes = /<DialogContent className="([^"]*)"/.exec(source)?.[1].split(/\s+/) ?? [];
    expect(classes).toContain("sm:max-w-lg");
    expect(classes.filter((name) => name.startsWith("max-w-"))).toEqual([]);
  });
});
