"""Standard-library tests for the Semgrep example adapter.

Semgrep itself is not needed: a small Python stand-in that prints Semgrep-shaped JSON
replaces it. Everything is written to temporary directories.

Run from the repository root (no bytecode is written):

    python examples/adapters/sentra-adapter-semgrep/tests/test_adapter.py
"""

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

sys.dont_write_bytecode = True

ADAPTER_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "adapter.py")
_spec = importlib.util.spec_from_file_location("semgrep_adapter", ADAPTER_PATH)
adapter = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(adapter)

FAKE_SEMGREP = textwrap.dedent(
    """
    import json, os, sys, time
    mode, argv = sys.argv[1], sys.argv[2:]
    if argv == ["--version"]:
        print("1.97.0")
        sys.exit(0)
    target = argv[-1]
    if mode == "hang":
        time.sleep(120)
    if mode == "fail":
        sys.stderr.write("[ERROR] invalid configuration\\n")
        print(json.dumps({"version": "1.97.0", "results": [], "errors": [{"level": "error", "message": "Invalid rule schema"}]}))
        sys.exit(7)
    if mode == "garbage":
        print("not json")
        sys.exit(0)
    count = 300 if mode == "many" else 1
    results = [{
        "check_id": "rules.eval-%d" % i,
        "path": os.path.join(target, "app.py"),
        "start": {"line": i + 1, "col": 1, "offset": 0},
        "end": {"line": i + 1, "col": 6, "offset": 5},
        "extra": {"message": "eval\\nused \\u00e7" * (20 if mode == "many" else 1), "severity": ["ERROR", "WARNING"][i % 2]},
    } for i in range(count)]
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "argv.json"), "w") as fh:
        json.dump(argv, fh)
    print(json.dumps({"version": "1.97.0", "results": results, "errors": [], "paths": {"scanned": [os.path.join(target, "app.py")]}}))
    """
)


def frame(response):
    return json.loads(adapter.encode(response).decode("ascii"))


class AdapterTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sentra-semgrep-adapter-")
        self.workspace = os.path.realpath(os.path.join(self.tmp, "workspace"))
        os.makedirs(self.workspace)
        with open(os.path.join(self.workspace, "app.py"), "w") as fh:
            fh.write("eval(x)\n")
        with open(os.path.join(self.workspace, ".semgrep.yml"), "w") as fh:
            fh.write("rules: []\n")
        self.fake = os.path.join(self.tmp, "fake_semgrep.py")
        with open(self.fake, "w") as fh:
            fh.write(FAKE_SEMGREP)
        # No operator rules directory unless a test creates one.
        patcher = mock.patch.object(adapter, "OPERATOR_RULES_DIR", os.path.join(self.tmp, "no-rules"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def use_fake(self, mode):
        patcher = mock.patch.object(adapter, "find_semgrep", return_value=([sys.executable, self.fake, mode], "fake semgrep"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def execute(self, arguments, **overrides):
        req = {
            "operation": "execute",
            "task_id": "task-1",
            "lease_id": "lease-task-1",
            "capability": "static_analysis",
            "workspace_root": self.workspace,
            "arguments": arguments,
        }
        req.update(overrides)
        response, stop = adapter.handle_line(json.dumps(req).encode("utf-8"))
        self.assertFalse(stop)
        return frame(response)


class ProtocolTests(AdapterTestCase):
    def test_initialize_acknowledges_only_static_analysis(self):
        response, _ = adapter.handle_line(b'{"operation":"initialize","host_version":1}\n')
        self.assertEqual(response["status"], "initialize_ack")
        self.assertEqual(response["plugin_id"], "org.sentra.adapter.semgrep")
        self.assertEqual(response["capabilities"], ["static_analysis"])

    def test_capabilities_match_manifest(self):
        with open(os.path.join(os.path.dirname(ADAPTER_PATH), "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        self.assertEqual(manifest["declared_capabilities"], adapter.CAPABILITIES)
        self.assertEqual(manifest["id"], adapter.PLUGIN_ID)

    def test_malformed_frames_get_error_frames(self):
        for raw in (b"{not json\n", b"[1,2]\n", b"\xff\xfe\n", b'{"operation":"bogus"}\n'):
            response, stop = adapter.handle_line(raw)
            self.assertEqual(response["status"], "error", raw)
            self.assertEqual(response["code"], 400)
            self.assertFalse(stop)
        self.assertEqual(adapter.handle_line(b"   \n"), (None, False))

    def test_shutdown_stops(self):
        self.assertEqual(adapter.handle_line(b'{"operation":"shutdown"}'), ({"status": "shutdown_ack"}, True))

    def test_cancel_does_not_claim_termination(self):
        response, _ = adapter.handle_line(b'{"operation":"cancel","task_id":"task-9"}')
        self.assertEqual(response, {"status": "cancel_ack", "task_id": "task-9", "terminated": False})

    def test_frames_are_single_ascii_lines(self):
        data = adapter.encode({"status": "error", "code": 1, "message": "line\nbreak ç"})
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data.count(b"\n"), 1)
        data.decode("ascii")


class ProbeTests(AdapterTestCase):
    def test_missing_semgrep_is_not_applicable(self):
        with mock.patch.object(adapter, "find_semgrep", return_value=(None, "semgrep was not found")):
            response = frame(adapter.handle_probe({"workspace_root": self.workspace}))
        self.assertFalse(response["applicable"])
        self.assertEqual(response["unsupported_reason"], "semgrep was not found")

    def test_invalid_workspace_is_not_applicable(self):
        response = adapter.handle_probe({"workspace_root": os.path.join(self.tmp, "missing")})
        self.assertFalse(response["applicable"])

    def test_available_semgrep_reports_version(self):
        self.use_fake("ok")
        response = adapter.handle_probe({"workspace_root": self.workspace})
        self.assertTrue(response["applicable"])
        self.assertIn("1.97.0", response["details"])


class ExecuteValidationTests(AdapterTestCase):
    def test_requires_workspace_root(self):
        response = self.execute({"config": ".semgrep.yml"}, workspace_root=None)
        self.assertEqual((response["status"], response["code"]), ("error", 400))
        self.assertIn("workspace_root", response["message"])

    def test_rejects_other_capabilities(self):
        response = self.execute({"config": ".semgrep.yml"}, capability="source_discovery")
        self.assertEqual(response["code"], 400)

    def test_requires_rules(self):
        response = self.execute({})
        self.assertEqual(response["code"], 400)
        self.assertIn("no Semgrep rules configured", response["message"])

    def test_refuses_registry_and_urls(self):
        for value in ("p/security-audit", "r/python.lang", "s/abc", "auto", "https://example.com/r.yml"):
            response = self.execute({"config": value})
            self.assertEqual(response["code"], 400, value)
            self.assertIn("strictly_denied", response["message"])
        response = self.execute({"ruleset": "p/security-audit"})
        self.assertIn("strictly_denied", response["message"])

    def test_refuses_paths_outside_workspace(self):
        outside = os.path.join(self.tmp, "outside.yml")
        with open(outside, "w") as fh:
            fh.write("rules: []\n")
        for value in (outside, os.path.join("..", "outside.yml")):
            response = self.execute({"config": value})
            self.assertEqual(response["code"], 400, value)
            self.assertIn("outside the workspace", response["message"])

    def test_rejects_unknown_and_malformed_arguments(self):
        cases = [
            {"rule_suite": "owasp-top-10"},
            {"config": ".semgrep.yml", "ruleset": ".semgrep.yml"},
            {"config": 5},
            {"config": []},
            {"config": "missing.yml"},
            {"config": ".semgrep.yml", "timeout_secs": 0},
            {"config": ".semgrep.yml", "max_results": True},
            {"config": ".semgrep.yml", "git_ignore": "yes"},
        ]
        for arguments in cases:
            response = self.execute(arguments)
            self.assertEqual(response["code"], 400, arguments)

    def test_missing_semgrep_is_an_error_not_a_finding(self):
        with mock.patch.object(adapter, "find_semgrep", return_value=(None, "semgrep was not found")):
            response = self.execute({"config": ".semgrep.yml"})
        self.assertEqual((response["status"], response["code"]), ("error", 503))


class ExecuteRunTests(AdapterTestCase):
    def test_scans_the_workspace_with_local_rules(self):
        self.use_fake("ok")
        response = self.execute({"config": ".semgrep.yml"})
        self.assertEqual(response["status"], "execute_result")
        self.assertEqual(response["task_id"], "task-1")
        self.assertEqual(response["exit_code"], 0)
        self.assertIn("1 finding(s)", response["summary"])
        self.assertIn("rules.eval-0 at app.py:1", response["summary"])
        self.assertRegex(response["evidence_refs"][0], r"^sha256:[0-9a-f]{64}$")
        with open(os.path.join(self.tmp, "argv.json")) as fh:
            argv = json.load(fh)
        self.assertEqual(argv[-1], self.workspace)
        self.assertEqual(argv[:5], ["scan", "--json", "--metrics=off", "--disable-version-check", "--no-git-ignore"])
        self.assertIn(os.path.join(self.workspace, ".semgrep.yml"), argv)

    def test_git_ignore_opt_in_and_operator_rules_default(self):
        self.use_fake("ok")
        rules = os.path.join(self.tmp, "operator-rules")
        os.makedirs(rules)
        with mock.patch.object(adapter, "OPERATOR_RULES_DIR", rules):
            response = self.execute({"git_ignore": True})
        self.assertEqual(response["status"], "execute_result")
        self.assertIn("rules: adapter rules/.", response["summary"])
        with open(os.path.join(self.tmp, "argv.json")) as fh:
            argv = json.load(fh)
        self.assertNotIn("--no-git-ignore", argv)
        self.assertIn(os.path.realpath(rules), argv)

    def test_no_findings_reports_zero(self):
        report = {"version": "1.97.0", "results": [], "errors": [], "paths": {"scanned": []}}
        summary = adapter.summarize_report(report, self.workspace, [".semgrep.yml"], 20, 4096)
        self.assertEqual(summary, "Semgrep 1.97.0: 0 finding(s); 0 file(s) scanned; 0 Semgrep error(s); rules: .semgrep.yml.")

    def test_semgrep_failure_is_an_error(self):
        self.use_fake("fail")
        response = self.execute({"config": ".semgrep.yml"})
        self.assertEqual((response["status"], response["code"]), ("error", 502))
        self.assertIn("exited with 7", response["message"])
        self.assertIn("Invalid rule schema", response["message"])

    def test_unparseable_output_is_an_error(self):
        self.use_fake("garbage")
        response = self.execute({"config": ".semgrep.yml"})
        self.assertEqual(response["code"], 502)

    def test_timeout_stops_semgrep(self):
        self.use_fake("hang")
        started = time.monotonic()
        response = self.execute({"config": ".semgrep.yml", "timeout_secs": 2})
        self.assertEqual(response["code"], 504)
        self.assertLess(time.monotonic() - started, 30)

    def test_summary_fits_a_small_frame(self):
        self.use_fake("many")
        with mock.patch.object(adapter, "read_quotas", return_value=(4096, 120)):
            response = self.execute({"config": ".semgrep.yml", "max_results": 200})
        self.assertEqual(response["status"], "execute_result")
        self.assertLessEqual(len(adapter.encode(response)), 4096)
        self.assertIn("300 finding(s)", response["summary"])
        self.assertIn("more finding(s) not listed", response["summary"])


class LocateSemgrepTests(AdapterTestCase):
    def test_ignores_relative_entries_and_batch_shims(self):
        bindir = os.path.join(self.tmp, "bin")
        os.makedirs(bindir)
        if os.name == "nt":
            shim = os.path.join(bindir, "semgrep.cmd")
            with open(shim, "w") as fh:
                fh.write("@echo 1.0\r\n")
            env = {"PATH": "relative-dir" + os.pathsep + bindir, "PATHEXT": ".COM;.EXE;.BAT;.CMD"}
            with mock.patch.dict(os.environ, env, clear=False):
                command, reason = adapter.find_semgrep()
            self.assertIsNone(command)
            self.assertIn("batch-file shims are not started", reason)
        else:
            exe = os.path.join(bindir, "semgrep")
            with open(exe, "w") as fh:
                fh.write("#!/bin/sh\necho 1.0\n")
            os.chmod(exe, 0o755)
            with mock.patch.dict(os.environ, {"PATH": "relative-dir" + os.pathsep + bindir}, clear=False):
                command, _ = adapter.find_semgrep()
            self.assertEqual(command, [exe])

    def test_not_found(self):
        with mock.patch.dict(os.environ, {"PATH": os.path.join(self.tmp, "empty")}, clear=False):
            command, reason = adapter.find_semgrep()
        self.assertIsNone(command)
        self.assertIn("not found", reason)

    def test_child_environment_drops_semgrep_settings(self):
        with mock.patch.dict(os.environ, {"SEMGREP_APP_TOKEN": "secret", "SEMGREP_RULES": "p/x"}, clear=False):
            env = adapter.child_environment()
        self.assertNotIn("SEMGREP_APP_TOKEN", env)
        self.assertNotIn("SEMGREP_RULES", env)
        self.assertEqual(env["SEMGREP_SEND_METRICS"], "off")
        self.assertEqual(env["SEMGREP_ENABLE_VERSION_CHECK"], "false")


if __name__ == "__main__":
    unittest.main()
