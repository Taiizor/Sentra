//! End-to-end tests of `sentra codeql analyze` against a fake CodeQL launcher.
//!
//! This test binary has its own `main` (`harness = false`). Copied into a fake CodeQL
//! distribution as `codeql.exe` (Windows) or `codeql` (elsewhere), it behaves like a
//! tiny CodeQL CLI: it appends its arguments, working directory and environment to
//! `calls.jsonl` next to itself and acts according to `fake-config.json`. No real
//! CodeQL is run.

#![forbid(unsafe_code)]

use std::{
    ffi::OsString,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

use serde_json::{Value, json};

const LAUNCHER: &str = if cfg!(windows) {
    "codeql.exe"
} else {
    "codeql"
};

/// A SARIF document as CodeQL writes it: rules in `tool.extensions`, results pointing at
/// them through `rule.toolComponent.index`.
const FAKE_SARIF: &str = r#"{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": { "name": "CodeQL", "semanticVersion": "9.9.9", "rules": [] },
      "extensions": [{
        "name": "codeql/python-queries",
        "semanticVersion": "1.0.0",
        "rules": [{
          "id": "py/sql-injection",
          "name": "py/sql-injection",
          "shortDescription": { "text": "SQL query built from user-controlled sources" },
          "defaultConfiguration": { "level": "error" },
          "properties": {
            "name": "SQL query built from user-controlled sources",
            "problem.severity": "error",
            "precision": "high",
            "security-severity": "8.8",
            "tags": ["security", "external/cwe/cwe-089"]
          }
        }]
      }]
    },
    "results": [
      {
        "ruleId": "py/sql-injection",
        "rule": { "id": "py/sql-injection", "index": 0, "toolComponent": { "index": 0 } },
        "message": { "text": "This SQL query depends on a user-provided value." },
        "locations": [{ "physicalLocation": {
          "artifactLocation": { "uri": "app.py", "uriBaseId": "%SRCROOT%" },
          "region": { "startLine": 3, "startColumn": 5, "endColumn": 30 }
        }}],
        "partialFingerprints": { "primaryLocationLineHash": "abcdef0123456789:1", "primaryLocationStartColumnFingerprint": "4" }
      },
      {
        "ruleId": "py/sql-injection",
        "rule": { "id": "py/sql-injection", "index": 0, "toolComponent": { "index": 0 } },
        "message": { "text": "Escaping path" },
        "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "../outside.py" }, "region": { "startLine": 1 } } }]
      },
      {
        "ruleId": "py/sql-injection",
        "message": { "text": "Absolute path" },
        "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "file:///etc/passwd" }, "region": { "startLine": 1 } } }]
      }
    ]
  }]
}"#;

// ---------------------------------------------------------------------------
// Fake CodeQL
// ---------------------------------------------------------------------------

fn fake_codeql(exe: &Path) -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dist = exe
        .parent()
        .expect("fake launcher has a parent")
        .to_path_buf();
    if args.first().map(String::as_str) == Some("__heartbeat") {
        let file = PathBuf::from(&args[1]);
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(120) {
            let _ = fs::write(&file, format!("{}", started.elapsed().as_nanos()));
            std::thread::sleep(Duration::from_millis(50));
        }
        return 0;
    }
    let config: Value = fs::read_to_string(dist.join("fake-config.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(Value::Null);
    let mode = config["mode"].as_str().unwrap_or("ok").to_string();
    let env: Vec<(String, String)> = std::env::vars().collect();
    #[cfg(unix)]
    let cwd_mode: Option<u32> = {
        use std::os::unix::fs::PermissionsExt;
        std::env::current_dir()
            .and_then(fs::metadata)
            .ok()
            .map(|m| m.permissions().mode() & 0o777)
    };
    #[cfg(not(unix))]
    let cwd_mode: Option<u32> = None;
    let record = json!({
        "args": args,
        "cwd": std::env::current_dir().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default(),
        "cwd_mode": cwd_mode,
        "env": env.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
    });
    if let Ok(mut log) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dist.join("calls.jsonl"))
    {
        let _ = writeln!(log, "{record}");
    }
    let flag = |name: &str| {
        args.iter()
            .find_map(|a| a.strip_prefix(&format!("--{name}=")).map(PathBuf::from))
    };
    match (
        args.first().map(String::as_str),
        args.get(1).map(String::as_str),
    ) {
        (Some("version"), _) => {
            println!("{{\"productName\":\"CodeQL\",\"vendor\":\"GitHub\",\"version\":\"9.9.9\"}}");
            0
        }
        (Some("pack"), Some("download")) => {
            let cache = flag("common-caches").expect("pack cache");
            let pack = args[2].trim_start_matches("codeql/").to_string();
            let language = pack.trim_end_matches("-queries");
            let listed = |key: &str| {
                config[key]
                    .as_array()
                    .is_some_and(|list| list.iter().any(|l| l == language))
            };
            if config["download_hang"].as_bool() == Some(true) {
                // Like CodeQL 2.27.4 killed while it unpacks: the pack's directory in
                // --common-caches already has qlpack.yml and the suite file, the rest is
                // missing.
                let partial = cache
                    .join("packages")
                    .join("codeql")
                    .join(&pack)
                    .join("1.2.3");
                fs::create_dir_all(partial.join("codeql-suites")).unwrap();
                fs::write(partial.join("qlpack.yml"), "name: partial\n").unwrap();
                fs::write(
                    partial
                        .join("codeql-suites")
                        .join(format!("{language}-code-scanning.qls")),
                    "- queries: .\n",
                )
                .unwrap();
                let heartbeat = config["heartbeat"].as_str().unwrap().to_string();
                let _ = Command::new(exe).args(["__heartbeat", &heartbeat]).spawn();
                std::thread::sleep(Duration::from_secs(120));
                return 0;
            }
            if let Some(delay) = config["download_delay_ms"].as_u64() {
                std::thread::sleep(Duration::from_millis(delay));
            }
            let marker = dist.join(format!("failed-once-{language}"));
            if listed("download_fail") || (listed("download_fail_once") && !marker.exists()) {
                let _ = fs::write(&marker, "1");
                // A bell character: control characters must not reach Sentra's messages.
                eprintln!(
                    "fake registry error\u{7}: connection timed out while fetching codeql/{pack}"
                );
                return 1;
            }
            let dir = cache
                .join("packages")
                .join("codeql")
                .join(&pack)
                .join("1.2.3");
            fs::create_dir_all(dir.join("codeql-suites")).unwrap();
            fs::write(dir.join("qlpack.yml"), "name: fake\n").unwrap();
            fs::write(
                dir.join("codeql-suites")
                    .join(format!("{language}-code-scanning.qls")),
                "- queries: .\n",
            )
            .unwrap();
            0
        }
        (Some("database"), Some("create")) => {
            let _ = fs::create_dir_all(&args[2]);
            match mode.as_str() {
                "hang_create" => {
                    let heartbeat = config["heartbeat"].as_str().unwrap().to_string();
                    let _ = Command::new(exe).args(["__heartbeat", &heartbeat]).spawn();
                    std::thread::sleep(Duration::from_secs(120));
                    0
                }
                "fail_create" => {
                    eprintln!("fake extractor failure: cannot parse anything");
                    3
                }
                _ => 0,
            }
        }
        (Some("database"), Some("analyze")) => {
            let output = flag("output").expect("--output");
            fs::write(output, FAKE_SARIF).unwrap();
            0
        }
        _ => {
            eprintln!("fake codeql: unexpected arguments {args:?}");
            2
        }
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    root: PathBuf,
    dist: PathBuf,
    workspace: PathBuf,
    work: PathBuf,
    cache: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let root = std::env::temp_dir().join(format!(
            "sentra-codeql-host-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let root = strip_verbatim(fs::canonicalize(&root).unwrap());
        let dist = root.join("dist");
        let workspace = root.join("ws");
        fs::create_dir_all(dist.join("tools")).unwrap();
        fs::create_dir_all(&workspace).unwrap();
        fs::write(dist.join(".codeqlmanifest.json"), "{\"provide\":[]}").unwrap();
        for (language, modes) in [
            ("python", "  - none\n"),
            ("javascript", "  - none\n"),
            ("actions", "  - none\n"),
            ("rust", "  - none\n"),
            ("go", "  - autobuild\n  - manual\n"),
        ] {
            fs::create_dir_all(dist.join(language)).unwrap();
            fs::write(
                dist.join(language).join("codeql-extractor.yml"),
                format!("name: \"{language}\"\nbuild_modes:\n{modes}default_queries:\n  - codeql/{language}-queries\n"),
            )
            .unwrap();
        }
        fs::copy(std::env::current_exe().unwrap(), dist.join(LAUNCHER)).unwrap();
        fs::write(
            workspace.join("app.py"),
            "import os\nq = 'x'\ncursor.execute(q)\n",
        )
        .unwrap();
        Self {
            work: root.join("work"),
            cache: root.join("cache"),
            root,
            dist,
            workspace,
        }
    }

    fn with_python_pack(self) -> Self {
        let dir = self
            .dist
            .join("qlpacks")
            .join("codeql")
            .join("python-queries")
            .join("1.0.0");
        fs::create_dir_all(dir.join("codeql-suites")).unwrap();
        fs::write(dir.join("qlpack.yml"), "name: codeql/python-queries\n").unwrap();
        fs::write(
            dir.join("codeql-suites").join("python-code-scanning.qls"),
            "- queries: .\n",
        )
        .unwrap();
        self
    }

    fn config(&self, value: Value) {
        fs::write(self.dist.join("fake-config.json"), value.to_string()).unwrap();
    }

    fn analyze(&self, extra: &[&str]) -> Output {
        let mut args: Vec<OsString> = vec![
            "codeql".into(),
            "analyze".into(),
            "--workspace".into(),
            self.workspace.clone().into(),
            "--codeql".into(),
            self.dist.join(LAUNCHER).into(),
            "--work-dir".into(),
            self.work.clone().into(),
            "--pack-cache".into(),
            self.cache.clone().into(),
            "--json".into(),
        ];
        args.extend(extra.iter().map(OsString::from));
        Command::new(env!("CARGO_BIN_EXE_sentra"))
            .args(args)
            .env("GITHUB_TOKEN", "ghp_must_not_leak")
            .env("GH_TOKEN", "gho_must_not_leak")
            .env("OPENAI_API_KEY", "sk-must-not-leak")
            .env("SENTRA_WEB_TOKENS", "must-not-leak")
            .env(
                "CODEQL_EXTRACTOR_PYTHON_OPTION_LOGGING_VERBOSITY",
                "must-not-leak",
            )
            .output()
            .unwrap()
    }

    /// [`Self::analyze`] with extra environment variables and, when given, this `PATH`.
    fn analyze_env(&self, extra: &[&str], vars: &[(&str, &str)], path: Option<&Path>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sentra"));
        command
            .args(["codeql", "analyze", "--workspace"])
            .arg(&self.workspace)
            .arg("--codeql")
            .arg(self.dist.join(LAUNCHER))
            .arg("--work-dir")
            .arg(&self.work)
            .arg("--pack-cache")
            .arg(&self.cache)
            .arg("--json")
            .args(extra)
            .envs(vars.iter().copied());
        if let Some(path) = path {
            command.env("PATH", path);
        }
        command.output().unwrap()
    }

    /// A native executable (a copy of this test binary) at `dir/name`, standing in for
    /// a JavaScript runtime; it is validated but never run.
    fn native_exe(&self, dir: &Path, name: &str) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        let target = dir.join(name);
        fs::copy(std::env::current_exe().unwrap(), &target).unwrap();
        strip_verbatim(fs::canonicalize(&target).unwrap())
    }

    /// `codeql packs --codeql <fake> --pack-cache <cache> --json` plus `extra`, with the
    /// same secret-bearing environment as [`Self::analyze`].
    fn packs(&self, extra: &[&str]) -> Output {
        let mut args: Vec<OsString> = vec![
            "codeql".into(),
            "packs".into(),
            "--codeql".into(),
            self.dist.join(LAUNCHER).into(),
            "--pack-cache".into(),
            self.cache.clone().into(),
            "--json".into(),
        ];
        args.extend(extra.iter().map(OsString::from));
        Command::new(env!("CARGO_BIN_EXE_sentra"))
            .args(args)
            .env("GITHUB_TOKEN", "ghp_must_not_leak")
            .env("OPENAI_API_KEY", "sk-must-not-leak")
            .env("SENTRA_WEB_TOKENS", "must-not-leak")
            .output()
            .unwrap()
    }

    /// A pack `codeql/<language>-queries/<version>` in the pack cache with the given
    /// suite files and one 1000-byte query file.
    fn with_cached_pack(self, language: &str, version: &str, suites: &[&str]) -> Self {
        let dir = self
            .cache
            .join("packages")
            .join("codeql")
            .join(format!("{language}-queries"))
            .join(version);
        fs::create_dir_all(dir.join("codeql-suites")).unwrap();
        fs::write(dir.join("qlpack.yml"), "name: x\n").unwrap();
        fs::write(dir.join("Query.qlx"), vec![b'q'; 1000]).unwrap();
        for suite in suites {
            fs::write(
                dir.join("codeql-suites")
                    .join(format!("{language}-{suite}.qls")),
                "- queries: .\n",
            )
            .unwrap();
        }
        self
    }

    fn calls(&self) -> Vec<Value> {
        fs::read_to_string(self.dist.join("calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// Entries of the pack cache whose name starts with `prefix`.
    fn cache_entries(&self, prefix: &str) -> usize {
        fs::read_dir(&self.cache)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
                    .count()
            })
            .unwrap_or(0)
    }

    /// Asserts that an interrupted download left neither a (partial) pack of `language`
    /// in the pack cache nor a staging directory, and that a listing reports it missing.
    fn assert_no_partial_pack(&self, id: &str) {
        let dir = self
            .cache
            .join("packages")
            .join("codeql")
            .join(format!("{id}-queries"));
        assert!(
            !dir.exists(),
            "an interrupted download left {}",
            dir.display()
        );
        assert_eq!(
            self.cache_entries(".sentra-staging-"),
            0,
            "staging directory left"
        );
        let before = self.calls().len();
        let report = stdout_json(&self.packs(&["--language", id]));
        assert_eq!(language(&report, id)["status"], "missing");
        assert_eq!(self.calls().len(), before);
    }

    fn run_dirs_left(&self) -> usize {
        fs::read_dir(&self.work)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|e| {
                        e.file_name()
                            .to_string_lossy()
                            .starts_with("sentra-codeql-")
                    })
                    .count()
            })
            .unwrap_or(0)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn strip_verbatim(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC") => PathBuf::from(rest),
        _ => path,
    }
}

fn norm(text: &str) -> String {
    let lower = text.replace('\\', "/");
    if cfg!(windows) {
        lower.to_lowercase()
    } else {
        lower
    }
}

fn stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}): {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn stderr_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stderr).unwrap_or_else(|e| {
        panic!(
            "stderr is not JSON ({e}): {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// Keys of every progress line, in contract order.
const PROGRESS_KEYS: [&str; 8] = [
    "progress",
    "event",
    "step",
    "language",
    "pack",
    "elapsed_ms",
    "duration_ms",
    "message",
];

/// Splits stderr into progress events (checked for the contract shape) and the lines
/// after them that are not progress events.
fn split_stderr(output: &Output) -> (Vec<Value>, Vec<String>) {
    let text = String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8");
    let mut events = Vec::new();
    let mut rest = Vec::new();
    for line in text.lines() {
        let value: Option<Value> = serde_json::from_str(line).ok();
        match value {
            Some(value) if value.get("progress").is_some() => {
                assert!(rest.is_empty(), "progress line after the result: {text}");
                let object = value.as_object().expect("progress line is an object");
                let keys: Vec<&str> = object.keys().map(String::as_str).collect();
                let mut expected = PROGRESS_KEYS.to_vec();
                expected.sort_unstable();
                let mut sorted = keys.clone();
                sorted.sort_unstable();
                assert_eq!(sorted, expected, "{line}");
                assert_eq!(value["progress"], true, "{line}");
                let message = value["message"].as_str().unwrap_or_default();
                assert!(
                    !message.chars().any(char::is_control),
                    "control character in {line}"
                );
                events.push(value);
            }
            _ => rest.push(line.to_string()),
        }
    }
    (events, rest)
}

/// `event step language` of every progress event that is not a heartbeat.
fn milestones(events: &[Value]) -> Vec<String> {
    events
        .iter()
        .filter(|e| e["event"] != "heartbeat")
        .map(|e| {
            format!(
                "{} {} {}",
                e["event"].as_str().unwrap(),
                e["step"].as_str().unwrap_or("-"),
                e["language"].as_str().unwrap_or("-")
            )
        })
        .collect()
}

fn env_of(call: &Value) -> Vec<(String, String)> {
    call["env"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            (
                pair[0].as_str().unwrap().to_string(),
                pair[1].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn language<'a>(report: &'a Value, id: &str) -> &'a Value {
    report["languages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["language"] == id)
        .unwrap_or_else(|| panic!("language {id} missing in {report}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn analysis_uses_build_mode_none_and_a_contained_environment() {
    let f = Fixture::new("ok").with_python_pack();
    fs::write(f.workspace.join("main.go"), "package main\n").unwrap();
    fs::write(f.workspace.join("lib.rs"), "fn main() {}\n").unwrap();
    fs::create_dir_all(f.workspace.join(".github").join("workflows")).unwrap();
    fs::write(
        f.workspace.join(".github").join("workflows").join("ci.yml"),
        "on: push\n",
    )
    .unwrap();
    f.config(json!({ "mode": "ok" }));

    let out = f.analyze(&["--accept-codeql-terms", "--threads", "2", "--ram", "2048"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = stdout_json(&out);
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["command"], "codeql analyze");
    assert_eq!(report["codeql_version"], "9.9.9");
    assert_eq!(report["suite"], "code-scanning");
    assert_eq!(report["pack_download_allowed"], false);
    assert_eq!(report["target_code_executed"], false);
    assert_eq!(
        norm(report["workspace"].as_str().unwrap()),
        norm(&f.workspace.to_string_lossy())
    );

    let python = language(&report, "python");
    assert_eq!(python["status"], "analyzed");
    assert_eq!(python["results"], 1);
    assert!(python["duration_ms"].is_u64());
    assert_eq!(language(&report, "go")["status"], "skipped");
    assert_eq!(
        language(&report, "go")["reason"],
        "requires building the project, which Sentra does not do on the host"
    );
    let rust = language(&report, "rust");
    assert_eq!(rust["status"], "skipped");
    assert!(rust["reason"].as_str().unwrap().contains("build scripts"));
    let actions = language(&report, "actions");
    assert_eq!(actions["status"], "skipped");
    assert!(
        actions["reason"]
            .as_str()
            .unwrap()
            .contains("pack download is not allowed")
    );

    assert_eq!(report["results_total"], 3);
    assert_eq!(report["results_outside_workspace"], 2);
    assert_eq!(report["truncated"], false);
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding["rule_id"], "py/sql-injection");
    assert_eq!(
        finding["rule_name"],
        "SQL query built from user-controlled sources"
    );
    assert_eq!(finding["severity"], "high");
    assert_eq!(finding["security_severity"], 8.8);
    assert_eq!(finding["problem_severity"], "error");
    assert_eq!(finding["precision"], "high");
    assert_eq!(finding["cwe"], json!(["CWE-89"]));
    assert_eq!(finding["path"], "app.py");
    assert_eq!(finding["start_line"], 3);
    assert_eq!(finding["end_line"], 3);
    assert_eq!(finding["start_column"], 5);
    // Line hash and start-column fingerprint together (two results of one rule on one
    // line would otherwise share an identity).
    assert_eq!(finding["fingerprint"], "abcdef0123456789:1|4");
    // Every rule the SARIF lists ran for the language, also rules without results.
    assert_eq!(python["rules"], json!(["py/sql-injection"]));
    assert_eq!(language(&report, "go")["rules"], json!([]));
    assert_eq!(finding["language"], "python");
    assert_eq!(
        report["source_tool"],
        json!({ "name": "CodeQL", "version": "9.9.9" })
    );

    // CodeQL was asked for exactly: version, database create, database analyze.
    let calls = f.calls();
    let verbs: Vec<String> = calls
        .iter()
        .map(|c| {
            format!(
                "{} {}",
                c["args"][0].as_str().unwrap(),
                c["args"][1].as_str().unwrap_or("")
            )
        })
        .collect();
    assert_eq!(
        verbs,
        [
            "version --format=json",
            "database create",
            "database analyze"
        ],
        "{calls:?}"
    );
    let create: Vec<String> = calls[1]["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| norm(a.as_str().unwrap()))
        .collect();
    let ws = norm(&f.workspace.to_string_lossy());
    let dist = norm(&f.dist.to_string_lossy());
    let cache = norm(&strip_verbatim(fs::canonicalize(&f.cache).unwrap()).to_string_lossy());
    for expected in [
        "--language=python".to_string(),
        "--build-mode=none".to_string(),
        format!("--source-root={ws}"),
        format!("--search-path={dist}"),
        format!("--common-caches={cache}"),
        "--threads=2".to_string(),
        "--ram=2048".to_string(),
    ] {
        assert!(create.contains(&expected), "{expected} not in {create:?}");
    }
    for call in &calls {
        for arg in call["args"].as_array().unwrap() {
            let arg = arg.as_str().unwrap();
            for banned in [
                "--command",
                "autobuild",
                "--build-mode=manual",
                "trace",
                "--download",
            ] {
                assert!(!arg.contains(banned), "{banned} passed to CodeQL: {arg}");
            }
        }
    }
    let analyze: Vec<String> = calls[2]["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| norm(a.as_str().unwrap()))
        .collect();
    assert!(
        analyze[3].ends_with(
            "qlpacks/codeql/python-queries/1.0.0/codeql-suites/python-code-scanning.qls"
        )
    );
    assert!(analyze.contains(&"--format=sarif-latest".to_string()));

    // Working directory and environment of every step.
    let work = norm(&strip_verbatim(fs::canonicalize(&f.work).unwrap()).to_string_lossy());
    for call in &calls {
        let cwd = norm(call["cwd"].as_str().unwrap());
        assert!(
            cwd.starts_with(&format!("{work}/sentra-codeql-")),
            "cwd {cwd}"
        );
        assert!(!cwd.starts_with(&ws), "cwd inside the workspace: {cwd}");
        let env = env_of(call);
        for (name, value) in &env {
            assert!(
                !value.contains("must-not-leak") && !value.contains("must_not_leak"),
                "{name} leaked"
            );
            let upper = name.to_ascii_uppercase();
            assert!(
                !upper.contains("TOKEN")
                    && !upper.contains("API_KEY")
                    && !upper.starts_with("SENTRA_"),
                "{name} forwarded"
            );
        }
        let get = |key: &str| {
            env.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .map(|(_, v)| norm(v))
        };
        assert!(
            get("TEMP")
                .unwrap()
                .starts_with(&format!("{work}/sentra-codeql-"))
        );
        assert!(
            get("HOME")
                .unwrap()
                .starts_with(&format!("{work}/sentra-codeql-"))
        );
        assert_eq!(
            get("CODEQL_EXTRACTOR_PYTHON_ENABLE_SITE").as_deref(),
            Some("1")
        );
        assert_eq!(get("PYTHONDONTWRITEBYTECODE").as_deref(), Some("1"));
        if cfg!(windows) {
            assert_eq!(
                get("NoDefaultCurrentDirectoryInExePath").as_deref(),
                Some("1")
            );
            assert!(
                get("USERPROFILE")
                    .unwrap()
                    .starts_with(&format!("{work}/sentra-codeql-"))
            );
        }
    }
    assert_eq!(f.run_dirs_left(), 0, "run directory not deleted");
    let ws_entries: Vec<String> = fs::read_dir(&f.workspace)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !ws_entries
            .iter()
            .any(|e| e.starts_with("db-") || e.ends_with(".sarif")),
        "{ws_entries:?}"
    );

    // Human-readable output.
    let text = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["codeql", "analyze", "--workspace"])
        .arg(&f.workspace)
        .arg("--codeql")
        .arg(f.dist.join(LAUNCHER))
        .arg("--work-dir")
        .arg(&f.work)
        .arg("--pack-cache")
        .arg(&f.cache)
        .args(["--accept-codeql-terms", "--language", "python"])
        .output()
        .unwrap();
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(
        text.contains("Sentra CodeQL host analysis: completed"),
        "{text}"
    );
    assert!(text.contains("Target code executed: no"), "{text}");
    assert!(text.contains("py/sql-injection"), "{text}");
}

fn missing_packs_fail_before_codeql_resolves_anything() {
    let f = Fixture::new("nopack");
    f.config(json!({ "mode": "ok" }));
    let out = f.analyze(&["--accept-codeql-terms", "--language", "python"]);
    assert_eq!(
        out.status.code(),
        Some(6),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = stderr_json(&out);
    assert_eq!(err["error"], "codeql_query_pack_missing");
    assert_eq!(err["target_code_executed"], false);
    assert_eq!(err["languages"][0]["status"], "skipped");
    let verbs: Vec<Value> = f.calls().iter().map(|c| c["args"][0].clone()).collect();
    assert_eq!(verbs, [json!("version")], "only the version step may run");
    assert_eq!(f.run_dirs_left(), 0);
}

fn packs_are_downloaded_into_the_pack_cache_only_when_allowed() {
    let f = Fixture::new("download");
    f.config(json!({ "mode": "ok" }));
    let out = f.analyze(&[
        "--accept-codeql-terms",
        "--language",
        "python",
        "--allow-pack-download",
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = stdout_json(&out);
    assert_eq!(report["pack_download_allowed"], true);
    assert_eq!(language(&report, "python")["status"], "analyzed");
    let calls = f.calls();
    let download = calls
        .iter()
        .find(|c| c["args"][0] == "pack")
        .expect("pack download ran");
    let cache = norm(&strip_verbatim(fs::canonicalize(&f.cache).unwrap()).to_string_lossy());
    assert_eq!(download["args"][1], "download");
    assert_eq!(download["args"][2], "codeql/python-queries");
    // CodeQL downloads into a staging directory inside the pack cache; Sentra moves the
    // complete pack into the pack cache afterwards and deletes the staging directory.
    let common_caches = norm(download["args"][3].as_str().unwrap());
    assert!(
        common_caches.starts_with(&format!("--common-caches={cache}/.sentra-staging-")),
        "{common_caches}"
    );
    assert!(
        f.cache
            .join("packages/codeql/python-queries/1.2.3/qlpack.yml")
            .is_file()
    );
    assert_eq!(f.cache_entries(".sentra-staging-"), 0, "staging left");
    // The analysis reads the pack from the pack cache itself.
    let analyze = calls
        .iter()
        .find(|c| c["args"][0] == "database" && c["args"][1] == "analyze")
        .expect("analysis ran");
    let suite = norm(analyze["args"][3].as_str().unwrap());
    assert_eq!(
        suite,
        format!(
            "{cache}/packages/codeql/python-queries/1.2.3/codeql-suites/python-code-scanning.qls"
        )
    );
}

fn failing_language_is_reported_with_the_codeql_error() {
    let f = Fixture::new("fail").with_python_pack();
    f.config(json!({ "mode": "fail_create" }));
    let out = f.analyze(&[
        "--accept-codeql-terms",
        "--language",
        "python",
        "--language",
        "go",
    ]);
    assert_eq!(
        out.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = stderr_json(&out);
    assert_eq!(err["error"], "codeql_failed");
    let python = &err["languages"][0];
    assert_eq!(python["language"], "python");
    assert_eq!(python["status"], "failed");
    let reason = python["reason"].as_str().unwrap();
    assert!(
        reason.contains("codeql database create exited with code 3"),
        "{reason}"
    );
    assert!(reason.contains("fake extractor failure"), "{reason}");
    assert_eq!(err["languages"][1]["status"], "skipped");
    assert_eq!(f.run_dirs_left(), 0);
}

fn timeout_kills_the_whole_codeql_process_tree() {
    let f = Fixture::new("hang").with_python_pack();
    let heartbeat = f.root.join("heartbeat.txt");
    f.config(json!({ "mode": "hang_create", "heartbeat": heartbeat.to_string_lossy() }));
    let started = Instant::now();
    let out = f.analyze(&[
        "--accept-codeql-terms",
        "--language",
        "python",
        "--timeout-secs",
        "4",
    ]);
    let elapsed = started.elapsed();
    assert_eq!(
        out.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = stderr_json(&out);
    assert_eq!(err["error"], "codeql_timeout");
    assert_eq!(err["languages"][0]["status"], "failed");
    assert!(elapsed < Duration::from_secs(40), "took {elapsed:?}");
    assert!(heartbeat.exists(), "the CodeQL child never started");
    std::thread::sleep(Duration::from_millis(500));
    let before = fs::read_to_string(&heartbeat).unwrap_or_default();
    std::thread::sleep(Duration::from_millis(800));
    let after = fs::read_to_string(&heartbeat).unwrap_or_default();
    assert_eq!(before, after, "a CodeQL descendant survived the timeout");
    assert_eq!(f.run_dirs_left(), 0);
}

fn terms_gate_and_launcher_rules_refuse_before_running_anything() {
    let f = Fixture::new("gate").with_python_pack();
    f.config(json!({ "mode": "ok" }));
    let out = f.analyze(&[]);
    assert_eq!(out.status.code(), Some(4));
    let err = stderr_json(&out);
    assert_eq!(err["error"], "codeql_terms_not_accepted");
    assert!(
        err["message"]
            .as_str()
            .unwrap()
            .contains("--accept-codeql-terms")
    );
    assert!(f.calls().is_empty());
    assert!(
        !f.work.exists(),
        "work directory created before the terms gate"
    );

    // Work directory and pack cache inside the workspace.
    let inside = f.workspace.join("tmp-work");
    for (flag, code) in [
        ("--work-dir", "work_dir_inside_workspace"),
        ("--pack-cache", "pack_cache_inside_workspace"),
    ] {
        let mut args: Vec<OsString> = vec![
            "codeql".into(),
            "analyze".into(),
            "--workspace".into(),
            f.workspace.clone().into(),
            "--codeql".into(),
            f.dist.join(LAUNCHER).into(),
            "--accept-codeql-terms".into(),
            "--json".into(),
        ];
        let (work, cache) = if flag == "--work-dir" {
            (inside.clone(), f.cache.clone())
        } else {
            (f.work.clone(), inside.clone())
        };
        args.extend([
            "--work-dir".into(),
            work.into_os_string(),
            "--pack-cache".into(),
            cache.into_os_string(),
        ]);
        let out = Command::new(env!("CARGO_BIN_EXE_sentra"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(4));
        assert_eq!(stderr_json(&out)["error"], code);
        assert!(!inside.exists(), "{flag} created inside the workspace");
    }

    // Launchers that are not the distribution's codeql program.
    let script = if cfg!(windows) {
        "codeql.cmd"
    } else {
        "codeql.sh"
    };
    fs::write(f.dist.join(script), "echo pwned\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "codeql",
            "analyze",
            "--accept-codeql-terms",
            "--json",
            "--workspace",
        ])
        .arg(&f.workspace)
        .arg("--codeql")
        .arg(f.dist.join(script))
        .arg("--work-dir")
        .arg(&f.work)
        .arg("--pack-cache")
        .arg(&f.cache)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(stderr_json(&out)["error"], "codeql_not_found");
    let outside = f.root.join("elsewhere");
    fs::create_dir_all(&outside).unwrap();
    fs::copy(f.dist.join(LAUNCHER), outside.join(LAUNCHER)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "codeql",
            "analyze",
            "--accept-codeql-terms",
            "--json",
            "--workspace",
        ])
        .arg(&f.workspace)
        .arg("--codeql")
        .arg(outside.join(LAUNCHER))
        .arg("--work-dir")
        .arg(&f.work)
        .arg("--pack-cache")
        .arg(&f.cache)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(7));
    let err = stderr_json(&out);
    assert!(
        err["message"]
            .as_str()
            .unwrap()
            .contains("CodeQL distribution"),
        "{err}"
    );
    assert!(f.calls().is_empty(), "a refused launcher was started");
}

fn workspace_and_directory_paths_with_cmd_metacharacters_are_refused_on_windows() {
    // Regression: CodeQL's Windows extractor scripts expand the source root unquoted
    // (`set LGTM_SRC=%CD%`); a workspace under `R&D` made cmd.exe run `D\app.cmd`.
    let mut f = Fixture::new("amp").with_python_pack();
    f.config(json!({ "mode": "ok" }));
    let workspace = f.root.join("R&D").join("app");
    fs::create_dir_all(&workspace).unwrap();
    fs::write(workspace.join("app.py"), "print(1)\n").unwrap();
    // A file the injected command would have run.
    fs::write(f.root.join("R&D").join("D"), "not a program\n").unwrap();
    f.workspace = workspace;
    let out = f.analyze(&["--accept-codeql-terms", "--language", "python"]);
    if cfg!(windows) {
        assert_eq!(
            out.status.code(),
            Some(4),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let err = stderr_json(&out);
        assert_eq!(err["error"], "invalid_workspace");
        let message = err["message"].as_str().unwrap();
        assert!(message.contains("'&'"), "{message}");
        assert!(message.contains("LGTM_SRC"), "{message}");
        assert!(f.calls().is_empty(), "CodeQL ran for a workspace with '&'");
        assert!(!f.work.exists(), "work directory created before the check");
    } else {
        // Unix launchers quote these paths; nothing is refused there.
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // The work directory and the pack cache are expanded by the same scripts.
    let f = Fixture::new("amp-dirs").with_python_pack();
    f.config(json!({ "mode": "ok" }));
    for (flag, code) in [
        ("--work-dir", "unsafe_directory"),
        ("--pack-cache", "unsafe_directory"),
    ] {
        let unsafe_dir = f.root.join(format!("Q&A{}", flag.trim_start_matches('-')));
        let (work, cache) = if flag == "--work-dir" {
            (unsafe_dir.clone(), f.cache.clone())
        } else {
            (f.work.clone(), unsafe_dir.clone())
        };
        let out = Command::new(env!("CARGO_BIN_EXE_sentra"))
            .args(["codeql", "analyze", "--accept-codeql-terms", "--json"])
            .arg("--workspace")
            .arg(&f.workspace)
            .arg("--codeql")
            .arg(f.dist.join(LAUNCHER))
            .arg("--work-dir")
            .arg(&work)
            .arg("--pack-cache")
            .arg(&cache)
            .args(["--language", "python"])
            .output()
            .unwrap();
        if cfg!(windows) {
            assert_eq!(out.status.code(), Some(4), "{flag}");
            assert_eq!(stderr_json(&out)["error"], code, "{flag}");
            assert!(!unsafe_dir.exists(), "{flag} created before the check");
        } else {
            assert_eq!(out.status.code(), Some(0), "{flag}");
        }
    }
    if cfg!(windows) {
        assert!(f.calls().is_empty());
    }
}

fn shared_work_directories_are_refused_on_unix() {
    let f = Fixture::new("shared").with_python_pack();
    f.config(json!({ "mode": "ok" }));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // A world-writable work directory (like a /tmp/sentra-codeql another user
        // created) lets that user swap the run directory.
        let shared = f.root.join("shared-work");
        fs::create_dir_all(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_sentra"))
            .args(["codeql", "analyze", "--accept-codeql-terms", "--json"])
            .arg("--workspace")
            .arg(&f.workspace)
            .arg("--codeql")
            .arg(f.dist.join(LAUNCHER))
            .arg("--work-dir")
            .arg(&shared)
            .arg("--pack-cache")
            .arg(&f.cache)
            .args(["--language", "python"])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(4),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let err = stderr_json(&out);
        assert_eq!(err["error"], "unsafe_directory");
        assert!(
            err["message"].as_str().unwrap().contains("can write"),
            "{err}"
        );
        assert!(f.calls().is_empty());
        let leftovers = fs::read_dir(&shared).unwrap().count();
        assert_eq!(leftovers, 0, "probe or run directory left behind");
    }
    // Directories Sentra creates itself are private, and every step runs in a 0700 run
    // directory (the fake records the mode of its working directory on Unix).
    let out = f.analyze(&["--accept-codeql-terms", "--language", "python"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for call in f.calls() {
        if cfg!(unix) {
            assert_eq!(call["cwd_mode"], json!(0o700), "{call}");
        } else {
            assert!(call["cwd_mode"].is_null());
        }
    }
}

fn closing_stdin_cancels_the_analysis_and_kills_the_codeql_tree() {
    let f = Fixture::new("cancel").with_python_pack();
    let heartbeat = f.root.join("heartbeat.txt");
    f.config(json!({ "mode": "hang_create", "heartbeat": heartbeat.to_string_lossy() }));
    let mut child = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["codeql", "analyze", "--workspace"])
        .arg(&f.workspace)
        .arg("--codeql")
        .arg(f.dist.join(LAUNCHER))
        .arg("--work-dir")
        .arg(&f.work)
        .arg("--pack-cache")
        .arg(&f.cache)
        .args([
            "--accept-codeql-terms",
            "--language",
            "python",
            "--timeout-secs",
            "600",
            "--cancel-on-stdin-eof",
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let waiting = Instant::now();
    while !heartbeat.exists() && waiting.elapsed() < Duration::from_secs(60) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(heartbeat.exists(), "the CodeQL child never started");
    // Closing stdin is how the bridge cancels; it also happens when the bridge dies.
    drop(child.stdin.take());
    let closed = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if closed.elapsed() > Duration::from_secs(40) {
            let _ = child.kill();
            panic!("sentra did not stop after stdin closed");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = stderr_json(&out);
    assert_eq!(err["error"], "codeql_cancelled");
    assert_eq!(err["languages"][0]["status"], "failed");
    assert_eq!(err["languages"][0]["reason"], "cancelled");
    std::thread::sleep(Duration::from_millis(500));
    let before = fs::read_to_string(&heartbeat).unwrap_or_default();
    std::thread::sleep(Duration::from_millis(800));
    let after = fs::read_to_string(&heartbeat).unwrap_or_default();
    assert_eq!(
        before, after,
        "a CodeQL descendant survived the cancellation"
    );
    assert_eq!(f.run_dirs_left(), 0);
}

fn progress_events_report_each_step_with_heartbeats() {
    // Regression: during a first-run pack download CodeQL prints nothing for minutes and
    // the console looked frozen. --progress reports every step and a heartbeat.
    let f = Fixture::new("progress");
    fs::write(f.workspace.join("main.go"), "package main\n").unwrap();
    f.config(json!({ "mode": "ok", "download_delay_ms": 2600 }));
    let out = f.analyze(&[
        "--accept-codeql-terms",
        "--allow-pack-download",
        "--language",
        "python",
        "--language",
        "go",
        "--progress",
        "--heartbeat-secs",
        "1",
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The result on stdout is the same document as without --progress.
    let report = stdout_json(&out);
    assert_eq!(report["command"], "codeql analyze");
    assert_eq!(language(&report, "python")["status"], "analyzed");
    let (events, rest) = split_stderr(&out);
    assert!(rest.is_empty(), "non-progress stderr: {rest:?}");
    assert_eq!(
        milestones(&events),
        [
            "step_started version -",
            "step_finished version -",
            "language_skipped - go",
            "step_started pack_download python",
            "step_finished pack_download python",
            "step_started database_create python",
            "step_finished database_create python",
            "step_started database_analyze python",
            "step_finished database_analyze python",
        ]
    );
    let find = |event: &str, step: &str| {
        events
            .iter()
            .find(|e| e["event"] == event && e["step"] == step)
            .unwrap_or_else(|| panic!("{event} {step} missing"))
    };
    assert_eq!(
        find("step_finished", "version")["message"],
        "CodeQL CLI 9.9.9"
    );
    let skipped = events
        .iter()
        .find(|e| e["event"] == "language_skipped")
        .unwrap();
    assert!(skipped["step"].is_null());
    assert_eq!(
        skipped["message"],
        "requires building the project, which Sentra does not do on the host"
    );
    let started = find("step_started", "pack_download");
    assert_eq!(started["pack"], "codeql/python-queries");
    assert!(started["elapsed_ms"].is_null() && started["duration_ms"].is_null());
    assert!(
        started["message"]
            .as_str()
            .unwrap()
            .contains("Downloading query pack codeql/python-queries"),
        "{started}"
    );
    // Heartbeats while the 2.6 s download runs, about once per second.
    let beats: Vec<&Value> = events
        .iter()
        .filter(|e| e["event"] == "heartbeat" && e["step"] == "pack_download")
        .collect();
    assert!(beats.len() >= 2, "{events:?}");
    let mut last = 0;
    for beat in &beats {
        let elapsed = beat["elapsed_ms"].as_u64().unwrap();
        assert!(elapsed >= 1000 && elapsed > last, "{beat}");
        last = elapsed;
        assert!(beat["duration_ms"].is_null());
        assert_eq!(beat["language"], "python");
        assert_eq!(beat["message"], "Still downloading codeql/python-queries");
    }
    let downloaded = find("step_finished", "pack_download");
    assert!(downloaded["duration_ms"].as_u64().unwrap() >= 2600);
    assert_eq!(downloaded["elapsed_ms"], downloaded["duration_ms"]);
    assert_eq!(
        find("step_started", "database_create")["message"],
        "Creating the python database (build mode none)"
    );
    assert_eq!(
        find("step_started", "database_analyze")["message"],
        "Analyzing python (code-scanning suite)"
    );
    assert_eq!(
        find("step_finished", "database_analyze")["message"],
        "python analyzed: 1 result (code-scanning suite)"
    );
}

fn output_without_progress_is_unchanged_and_errors_stay_last() {
    let f = Fixture::new("noprogress").with_python_pack();
    f.config(json!({ "mode": "ok" }));
    let out = f.analyze(&["--accept-codeql-terms", "--language", "python"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(language(&stdout_json(&out), "python")["status"], "analyzed");

    // A failure without --progress: stderr is exactly the error document.
    f.config(json!({ "mode": "fail_create" }));
    let out = f.analyze(&["--accept-codeql-terms", "--language", "python"]);
    assert_eq!(out.status.code(), Some(5));
    assert_eq!(stderr_json(&out)["error"], "codeql_failed");

    // With --progress the error is still the last stderr line, without a progress key.
    let out = f.analyze(&[
        "--accept-codeql-terms",
        "--language",
        "python",
        "--progress",
    ]);
    assert_eq!(out.status.code(), Some(5));
    assert!(out.stdout.is_empty());
    let (events, rest) = split_stderr(&out);
    assert_eq!(rest.len(), 1, "{rest:?}");
    let error: Value = serde_json::from_str(&rest[0]).unwrap();
    assert_eq!(error["error"], "codeql_failed");
    assert!(error.get("progress").is_none());
    let failed = events
        .iter()
        .find(|e| e["event"] == "step_failed")
        .expect("step_failed event");
    assert_eq!(failed["step"], "database_create");
    assert!(failed["duration_ms"].is_u64());
    assert!(
        failed["message"]
            .as_str()
            .unwrap()
            .contains("fake extractor failure"),
        "{failed}"
    );
}

fn pack_downloads_have_their_own_budget() {
    // A download longer than --timeout-secs does not use up the analysis budget.
    let f = Fixture::new("budget");
    f.config(json!({ "mode": "ok", "download_delay_ms": 5000 }));
    let started = Instant::now();
    let out = f.analyze(&[
        "--accept-codeql-terms",
        "--allow-pack-download",
        "--language",
        "python",
        "--timeout-secs",
        "4",
        "--download-timeout-secs",
        "120",
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(started.elapsed() >= Duration::from_secs(5));
    assert_eq!(language(&stdout_json(&out), "python")["status"], "analyzed");

    // A download longer than --download-timeout-secs is stopped; the language fails
    // with that reason and the download is not retried. The next language's download is
    // not started, and its reason says so (regression: it claimed a killed download).
    let f = Fixture::new("dlbudget");
    let heartbeat = f.root.join("heartbeat.txt");
    f.config(
        json!({ "mode": "ok", "download_hang": true, "heartbeat": heartbeat.to_string_lossy() }),
    );
    let started = Instant::now();
    let out = f.analyze(&[
        "--accept-codeql-terms",
        "--allow-pack-download",
        "--language",
        "python",
        "--language",
        "actions",
        "--download-timeout-secs",
        "2",
        "--progress",
    ]);
    assert!(started.elapsed() < Duration::from_secs(40));
    assert_eq!(
        out.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (events, rest) = split_stderr(&out);
    let error: Value = serde_json::from_str(rest.last().unwrap()).unwrap();
    assert_eq!(error["error"], "codeql_failed");
    let reason = language(&error, "python")["reason"].as_str().unwrap();
    assert!(reason.contains("--download-timeout-secs 2 s"), "{reason}");
    assert!(reason.contains("did not finish"), "{reason}");
    let actions = language(&error, "actions");
    assert_eq!(actions["status"], "failed");
    let reason = actions["reason"].as_str().unwrap();
    assert!(
        reason.contains("ran out before this pack's download could start"),
        "{reason}"
    );
    assert!(!reason.contains("killed"), "{reason}");
    let failed: Vec<&Value> = events
        .iter()
        .filter(|e| e["event"] == "step_failed" && e["step"] == "pack_download")
        .collect();
    assert_eq!(failed.len(), 2, "{events:?}");
    assert!(
        failed[0]["message"].as_str().unwrap().contains("timed out"),
        "{}",
        failed[0]
    );
    assert_eq!(failed[1]["language"], "actions");
    assert!(
        failed[1]["message"]
            .as_str()
            .unwrap()
            .starts_with("not started"),
        "{}",
        failed[1]
    );
    assert!(
        !events
            .iter()
            .any(|e| e["event"] == "step_started" && e["language"] == "actions"),
        "{events:?}"
    );
    let downloads = f.calls().iter().filter(|c| c["args"][0] == "pack").count();
    assert_eq!(downloads, 1, "a timed-out download was retried");
    assert!(heartbeat.exists(), "the download child never started");
    std::thread::sleep(Duration::from_millis(500));
    let before = fs::read_to_string(&heartbeat).unwrap_or_default();
    std::thread::sleep(Duration::from_millis(800));
    assert_eq!(
        before,
        fs::read_to_string(&heartbeat).unwrap_or_default(),
        "a download descendant survived the download budget"
    );
    assert_eq!(f.run_dirs_left(), 0);
    // The fake had written qlpack.yml and the suite file before it was killed, as CodeQL
    // does while it unpacks; none of it may reach the pack cache.
    f.assert_no_partial_pack("python");
}

fn closing_stdin_cancels_a_pack_download() {
    for packs in [false, true] {
        let f = Fixture::new(if packs { "cancel-packs" } else { "cancel-dl" });
        let heartbeat = f.root.join("heartbeat.txt");
        f.config(json!({ "mode": "ok", "download_hang": true, "heartbeat": heartbeat.to_string_lossy() }));
        let mut command = Command::new(env!("CARGO_BIN_EXE_sentra"));
        if packs {
            command
                .args(["codeql", "packs", "--codeql"])
                .arg(f.dist.join(LAUNCHER))
                .arg("--pack-cache")
                .arg(&f.cache)
                .args([
                    "--download",
                    "--language",
                    "python",
                    "--language",
                    "actions",
                ]);
        } else {
            command
                .args(["codeql", "analyze", "--workspace"])
                .arg(&f.workspace)
                .arg("--codeql")
                .arg(f.dist.join(LAUNCHER))
                .arg("--work-dir")
                .arg(&f.work)
                .arg("--pack-cache")
                .arg(&f.cache)
                .args([
                    "--accept-codeql-terms",
                    "--allow-pack-download",
                    "--language",
                    "python",
                ]);
        }
        let mut child = command
            .args(["--cancel-on-stdin-eof", "--progress", "--json"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let waiting = Instant::now();
        while !heartbeat.exists() && waiting.elapsed() < Duration::from_secs(60) {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(heartbeat.exists(), "the download child never started");
        drop(child.stdin.take());
        let closed = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if closed.elapsed() > Duration::from_secs(40) {
                let _ = child.kill();
                panic!("sentra did not stop after stdin closed");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let out = child.wait_with_output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(5),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let (events, rest) = split_stderr(&out);
        let error: Value = serde_json::from_str(rest.last().unwrap()).unwrap();
        assert_eq!(error["error"], "codeql_cancelled");
        assert!(
            events
                .iter()
                .any(|e| e["event"] == "step_failed" && e["step"] == "pack_download"),
            "{events:?}"
        );
        if packs {
            assert_eq!(error["command"], "codeql packs");
            let python = &error["languages"][0];
            assert_eq!(python["status"], "failed");
            assert!(python["reason"].as_str().unwrap().contains("cancelled"));
            let actions = &error["languages"][1];
            assert_eq!(actions["status"], "missing");
            assert!(
                actions["reason"]
                    .as_str()
                    .unwrap()
                    .contains("cancelled first")
            );
            let leftovers = fs::read_dir(&f.cache)
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(".sentra-run-"))
                .count();
            assert_eq!(leftovers, 0, "packs run directory not deleted");
        } else {
            assert_eq!(error["languages"][0]["reason"], "cancelled");
            assert_eq!(f.run_dirs_left(), 0);
        }
        std::thread::sleep(Duration::from_millis(500));
        let before = fs::read_to_string(&heartbeat).unwrap_or_default();
        std::thread::sleep(Duration::from_millis(800));
        assert_eq!(
            before,
            fs::read_to_string(&heartbeat).unwrap_or_default(),
            "a download descendant survived the cancellation"
        );
        let downloads = f.calls().iter().filter(|c| c["args"][0] == "pack").count();
        assert_eq!(downloads, 1, "a cancelled download was retried");
        // Regression: the partial pack the killed download had written (qlpack.yml and
        // the suite file included) must not be taken as installed.
        f.assert_no_partial_pack("python");
    }
}

fn packs_lists_distribution_and_cache_packs_without_running_codeql() {
    let f = Fixture::new("packs-list")
        .with_python_pack()
        .with_cached_pack("javascript", "2.5.0", &["code-scanning"]);
    let f = f.with_cached_pack("javascript", "2.4.0", &["code-scanning"]);
    f.config(json!({ "mode": "ok" }));
    let out = f.packs(&[]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stderr.is_empty());
    let report = stdout_json(&out);
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["command"], "codeql packs");
    assert_eq!(report["suite"], "code-scanning");
    assert_eq!(report["download_requested"], false);
    assert_eq!(
        norm(report["distribution"].as_str().unwrap()),
        norm(&f.dist.to_string_lossy())
    );
    let ids: Vec<&str> = report["languages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["language"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            "actions",
            "cpp",
            "csharp",
            "go",
            "java",
            "javascript",
            "python",
            "ruby",
            "rust",
            "swift"
        ]
    );
    let python = language(&report, "python");
    assert_eq!(python["status"], "present");
    assert_eq!(python["analysable"], true);
    assert_eq!(python["pack"], "codeql/python-queries");
    assert_eq!(python["source"], "distribution");
    assert_eq!(python["version"], "1.0.0");
    assert!(
        norm(python["location"].as_str().unwrap())
            .ends_with("dist/qlpacks/codeql/python-queries/1.0.0")
    );
    assert!(python["size_bytes"].as_u64().unwrap() > 0);
    assert!(python["reason"].is_null() && python["duration_ms"].is_null());
    let javascript = language(&report, "javascript");
    assert_eq!(javascript["status"], "present");
    assert_eq!(javascript["source"], "pack_cache");
    assert_eq!(
        javascript["version"], "2.5.0",
        "the highest version is used"
    );
    // qlpack.yml (8 bytes) + Query.qlx (1000) + the suite file (13).
    assert_eq!(javascript["size_bytes"], 1021);
    assert!(
        norm(javascript["suite_file"].as_str().unwrap())
            .ends_with("2.5.0/codeql-suites/javascript-code-scanning.qls")
    );
    let actions = language(&report, "actions");
    assert_eq!(actions["status"], "missing");
    assert_eq!(actions["analysable"], true);
    assert!(actions["version"].is_null() && actions["location"].is_null());
    assert!(
        actions["reason"]
            .as_str()
            .unwrap()
            .contains("not in the CodeQL distribution or the pack cache")
    );
    let cpp = language(&report, "cpp");
    assert_eq!(cpp["status"], "not_analysable");
    assert_eq!(cpp["analysable"], false);
    assert_eq!(
        cpp["reason"],
        "the CodeQL distribution has no cpp extractor"
    );
    assert_eq!(
        language(&report, "go")["reason"],
        "requires building the project, which Sentra does not do on the host"
    );
    for blocked in ["rust", "csharp", "java", "swift"] {
        assert_eq!(language(&report, blocked)["status"], "not_analysable");
    }
    assert_eq!(
        (
            report["present"].as_u64(),
            report["missing"].as_u64(),
            report["downloaded"].as_u64(),
            report["failed"].as_u64()
        ),
        (Some(2), Some(1), Some(0), Some(0))
    );
    assert!(f.calls().is_empty(), "listing ran CodeQL");

    // --language and --suite narrow the check.
    let out = f.packs(&[
        "--language",
        "TypeScript",
        "--language",
        "python",
        "--suite",
        "security-extended",
    ]);
    let report = stdout_json(&out);
    let ids: Vec<&str> = report["languages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["language"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["javascript", "python"]);
    assert_eq!(report["suite"], "security-extended");
    assert_eq!(language(&report, "python")["status"], "missing");
    assert_eq!(language(&report, "javascript")["status"], "missing");

    // Human-readable output.
    let text = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["codeql", "packs", "--codeql"])
        .arg(f.dist.join(LAUNCHER))
        .arg("--pack-cache")
        .arg(&f.cache)
        .output()
        .unwrap();
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("Sentra CodeQL query packs"), "{text}");
    assert!(text.contains("Run with --download"), "{text}");
    assert!(
        text.contains("javascript  present codeql/javascript-queries 2.5.0 (pack cache"),
        "{text}"
    );
    assert!(f.calls().is_empty());
}

fn packs_download_fetches_missing_packs_one_at_a_time_and_retries_once() {
    let f = Fixture::new("packs-dl");
    f.config(json!({ "mode": "ok", "download_fail_once": ["python"] }));
    // A partial directory without qlpack.yml (left by an interrupted download of an older
    // version, or by hand), which made CodeQL refuse every later download ("not empty
    // and is not a package"); a download replaces it.
    let stale = f.cache.join("packages/codeql/actions-queries/1.2.3");
    fs::create_dir_all(&stale).unwrap();
    fs::write(stale.join("Half.qlx"), "x").unwrap();
    let out = f.packs(&[
        "--download",
        "--language",
        "python",
        "--language",
        "actions",
        "--language",
        "go",
        "--progress",
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = stdout_json(&out);
    assert_eq!(report["download_requested"], true);
    for id in ["python", "actions"] {
        let status = language(&report, id);
        assert_eq!(status["status"], "downloaded", "{status}");
        assert_eq!(status["source"], "pack_cache");
        assert_eq!(status["version"], "1.2.3");
        assert!(status["duration_ms"].is_u64());
        assert!(status["reason"].is_null());
    }
    assert_eq!(language(&report, "go")["status"], "not_analysable");
    assert_eq!(
        (report["present"].as_u64(), report["downloaded"].as_u64()),
        (Some(2), Some(2))
    );
    // One `codeql pack download` per pack, python twice (one retry), nothing else.
    let calls = f.calls();
    let packs: Vec<String> = calls
        .iter()
        .map(|c| {
            assert_eq!(c["args"][0], "pack");
            assert_eq!(c["args"][1], "download");
            assert_eq!(c["args"].as_array().unwrap().len(), 4, "{c}");
            c["args"][2].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(
        packs,
        [
            "codeql/python-queries",
            "codeql/python-queries",
            "codeql/actions-queries"
        ]
    );
    let cache = norm(&strip_verbatim(fs::canonicalize(&f.cache).unwrap()).to_string_lossy());
    let mut staging_dirs = Vec::new();
    for call in &calls {
        let common_caches = norm(call["args"][3].as_str().unwrap());
        assert!(
            common_caches.starts_with(&format!("--common-caches={cache}/.sentra-staging-")),
            "{common_caches}"
        );
        staging_dirs.push(common_caches);
        let cwd = norm(call["cwd"].as_str().unwrap());
        assert!(cwd.starts_with(&format!("{cache}/.sentra-run-")), "{cwd}");
        if cfg!(unix) {
            assert_eq!(call["cwd_mode"], json!(0o700), "{call}");
        }
        let env = env_of(call);
        for (name, value) in &env {
            assert!(
                !value.contains("must-not-leak") && !value.contains("must_not_leak"),
                "{name} leaked"
            );
        }
        let get = |key: &str| {
            env.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .map(|(_, v)| norm(v))
        };
        assert!(
            get("HOME")
                .unwrap()
                .starts_with(&format!("{cache}/.sentra-run-"))
        );
        assert!(
            get("TEMP")
                .unwrap()
                .starts_with(&format!("{cache}/.sentra-run-"))
        );
    }
    // Every attempt gets a new staging directory, and none is left.
    staging_dirs.sort();
    staging_dirs.dedup();
    assert_eq!(staging_dirs.len(), 3, "{staging_dirs:?}");
    assert_eq!(f.cache_entries(".sentra-staging-"), 0, "staging left");
    assert!(stale.join("qlpack.yml").is_file());
    assert!(
        !stale.join("Half.qlx").exists(),
        "the partial directory was kept"
    );
    let leftovers = fs::read_dir(&f.cache)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(".sentra-run-"))
        .count();
    assert_eq!(leftovers, 0, "run directory not deleted");
    let (events, rest) = split_stderr(&out);
    assert!(rest.is_empty(), "{rest:?}");
    assert_eq!(
        milestones(&events),
        [
            "step_started pack_download python",
            "step_failed pack_download python",
            "step_started pack_download python",
            "step_finished pack_download python",
            "step_started pack_download actions",
            "step_finished pack_download actions",
        ]
    );
    let first_failure = &events[1];
    let message = first_failure["message"].as_str().unwrap();
    assert!(message.contains("fake registry error"), "{message}");
    assert!(message.ends_with("; retrying once"), "{message}");
    assert!(
        events[2]["message"]
            .as_str()
            .unwrap()
            .contains("attempt 2 of 2")
    );

    // Listing afterwards finds them without running CodeQL.
    let before = f.calls().len();
    let report = stdout_json(&f.packs(&["--language", "python"]));
    assert_eq!(language(&report, "python")["status"], "present");
    assert_eq!(f.calls().len(), before);
}

fn packs_download_failures_keep_completed_packs_and_report_codeql_s_message() {
    let f = Fixture::new("packs-fail");
    f.config(json!({ "mode": "ok", "download_fail": ["python"] }));
    let out = f.packs(&[
        "--download",
        "--language",
        "actions",
        "--language",
        "python",
    ]);
    assert_eq!(
        out.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty());
    let err = stderr_json(&out);
    assert_eq!(err["error"], "codeql_pack_download_failed");
    assert_eq!(err["command"], "codeql packs");
    let message = err["message"].as_str().unwrap();
    assert!(
        message.contains("1 of 2 query pack downloads failed"),
        "{message}"
    );
    assert!(message.contains("fake registry error"), "{message}");
    assert!(!message.chars().any(char::is_control), "{message}");
    assert!(message.contains("stay in the pack cache"), "{message}");
    assert_eq!(err["languages"][0]["status"], "downloaded");
    let python = &err["languages"][1];
    assert_eq!(python["status"], "failed");
    let reason = python["reason"].as_str().unwrap();
    assert!(
        reason.contains("codeql pack download exited with code 1: fake registry error"),
        "{reason}"
    );
    assert!(reason.ends_with("(failed twice)"), "{reason}");
    assert_eq!(
        (err["downloaded"].as_u64(), err["failed"].as_u64()),
        (Some(1), Some(1))
    );
    assert!(
        f.cache
            .join("packages/codeql/actions-queries/1.2.3/qlpack.yml")
            .is_file(),
        "the completed pack was not kept"
    );
    let python_calls = f
        .calls()
        .iter()
        .filter(|c| c["args"][2] == "codeql/python-queries")
        .count();
    assert_eq!(python_calls, 2, "one retry expected");

    // The budget covers all downloads together: when it runs out, the rest are not
    // attempted.
    let f = Fixture::new("packs-budget");
    f.config(json!({ "mode": "ok", "download_delay_ms": 5000 }));
    let started = Instant::now();
    let out = f.packs(&[
        "--download",
        "--language",
        "python",
        "--language",
        "actions",
        "--timeout-secs",
        "2",
    ]);
    assert!(started.elapsed() < Duration::from_secs(30));
    assert_eq!(out.status.code(), Some(5));
    let err = stderr_json(&out);
    assert_eq!(err["error"], "codeql_timeout");
    assert_eq!(err["languages"][0]["status"], "failed");
    assert!(
        err["languages"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("--timeout-secs 2 s")
    );
    assert_eq!(err["languages"][1]["status"], "missing");
    assert!(
        err["languages"][1]["reason"]
            .as_str()
            .unwrap()
            .contains("budget (--timeout-secs) ran out first")
    );
    assert_eq!(f.calls().len(), 1);
}

fn packs_refuses_unsafe_pack_caches_and_foreign_launchers() {
    let f = Fixture::new("packs-gate");
    f.config(json!({ "mode": "ok" }));
    let unsafe_cache = f.root.join("Q&A-cache");
    let out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["codeql", "packs", "--json", "--download", "--codeql"])
        .arg(f.dist.join(LAUNCHER))
        .arg("--pack-cache")
        .arg(&unsafe_cache)
        .args(["--language", "python"])
        .output()
        .unwrap();
    if cfg!(windows) {
        assert_eq!(out.status.code(), Some(4));
        let err = stderr_json(&out);
        assert_eq!(err["error"], "unsafe_directory");
        assert!(err["message"].as_str().unwrap().contains("'&'"));
        assert!(
            !unsafe_cache.exists(),
            "pack cache created before the check"
        );
        assert!(f.calls().is_empty());
    } else {
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let script = if cfg!(windows) {
        "codeql.cmd"
    } else {
        "codeql.sh"
    };
    fs::write(f.dist.join(script), "echo pwned\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["codeql", "packs", "--json", "--download", "--codeql"])
        .arg(f.dist.join(script))
        .arg("--pack-cache")
        .arg(&f.cache)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(stderr_json(&out)["error"], "codeql_not_found");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let shared = f.root.join("shared-cache");
        fs::create_dir_all(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_sentra"))
            .args(["codeql", "packs", "--json", "--codeql"])
            .arg(f.dist.join(LAUNCHER))
            .arg("--pack-cache")
            .arg(&shared)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(4));
        assert_eq!(stderr_json(&out)["error"], "unsafe_directory");
    }
    if cfg!(windows) {
        assert!(f.calls().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Minimal harness
// ---------------------------------------------------------------------------

fn typescript_runtime_and_excludes_reach_codeql_only_through_their_variables() {
    let f = Fixture::new("tsrt").with_cached_pack("javascript", "2.5.0", &["code-scanning"]);
    fs::write(f.workspace.join("app.ts"), "export const x: number = 1;\n").unwrap();
    f.config(json!({ "mode": "ok" }));
    let bun_name = if cfg!(windows) { "bun.exe" } else { "bun" };
    let runtime = f.native_exe(&f.root.join("runtime"), bun_name);
    let leaks = [
        ("SEMMLE_TYPESCRIPT_NODE_RUNTIME", "must-not-leak"),
        ("SEMMLE_TYPESCRIPT_NODE_RUNTIME_EXTRA_ARGS", "must-not-leak"),
        ("LGTM_INDEX_FILTERS", "include:must-not-leak"),
        ("LGTM_INDEX_INCLUDE", "must-not-leak"),
    ];
    let runtime_arg = runtime.to_string_lossy().into_owned();
    let out = f.analyze_env(
        &[
            "--accept-codeql-terms",
            "--language",
            "javascript",
            "--typescript-runtime",
            &runtime_arg,
            "--exclude",
            "**/node_modules",
            "--exclude",
            "**/target",
            "--progress",
        ],
        &leaks,
        None,
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = stdout_json(&out);
    assert_eq!(language(&report, "javascript")["status"], "analyzed");
    assert!(
        !report["warnings"].to_string().contains("TypeScript"),
        "{report}"
    );
    let calls = f.calls();
    assert_eq!(calls.len(), 3, "{calls:?}");
    for call in &calls {
        let env = env_of(call);
        let get = |key: &str| {
            env.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .map(|(_, v)| v.clone())
        };
        assert_eq!(
            get("SEMMLE_TYPESCRIPT_NODE_RUNTIME").map(|v| norm(&v)),
            Some(norm(&runtime_arg))
        );
        assert_eq!(
            get("LGTM_INDEX_FILTERS").as_deref(),
            Some("exclude:**/node_modules\nexclude:**/target")
        );
        // No other SEMMLE_* or LGTM_* variable is passed on.
        for (name, value) in &env {
            let upper = name.to_ascii_uppercase();
            if upper.starts_with("SEMMLE_") || upper.starts_with("LGTM_") {
                assert!(
                    upper == "SEMMLE_TYPESCRIPT_NODE_RUNTIME" || upper == "LGTM_INDEX_FILTERS",
                    "{name} passed to CodeQL"
                );
            }
            assert!(!value.contains("must-not-leak"), "{name} leaked");
        }
    }
    let (events, _) = split_stderr(&out);
    let create = events
        .iter()
        .find(|e| e["event"] == "step_started" && e["step"] == "database_create")
        .expect("database_create started");
    let message = create["message"].as_str().unwrap();
    assert!(
        message.starts_with(
            "Creating the javascript database (build mode none; TypeScript is parsed with "
        ) && norm(message).contains(&norm(&runtime_arg)),
        "{message}"
    );

    // Without --typescript-runtime the first bun on PATH is used.
    let path_bin = f.root.join("pathbin");
    let found = f.native_exe(&path_bin, bun_name);
    fs::remove_file(f.dist.join("calls.jsonl")).unwrap();
    let out = f.analyze_env(
        &["--accept-codeql-terms", "--language", "javascript"],
        &leaks,
        Some(&path_bin),
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for call in f.calls() {
        let env = env_of(&call);
        let value = env
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("SEMMLE_TYPESCRIPT_NODE_RUNTIME"))
            .map(|(_, v)| norm(v));
        assert_eq!(value, Some(norm(&found.to_string_lossy())));
        assert!(
            !env.iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("LGTM_INDEX_FILTERS")),
            "no --exclude, no filters"
        );
    }

    // Neither: CodeQL's default (node on PATH) and a warning.
    let empty_bin = f.root.join("emptybin");
    fs::create_dir_all(&empty_bin).unwrap();
    fs::remove_file(f.dist.join("calls.jsonl")).unwrap();
    let out = f.analyze_env(
        &["--accept-codeql-terms", "--language", "javascript"],
        &leaks,
        Some(&empty_bin),
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = stdout_json(&out);
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("--typescript-runtime")),
        "{report}"
    );
    for call in f.calls() {
        assert!(
            !env_of(&call)
                .iter()
                .any(|(k, _)| k.to_ascii_uppercase().starts_with("SEMMLE_")),
            "{call}"
        );
    }
    // Python alone needs no TypeScript runtime: no warning.
    let out = f.analyze_env(
        &[
            "--accept-codeql-terms",
            "--language",
            "python",
            "--allow-pack-download",
        ],
        &[],
        Some(&empty_bin),
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !stdout_json(&out)["warnings"]
            .to_string()
            .contains("--typescript-runtime")
    );
}

fn invalid_typescript_runtimes_and_excludes_are_refused_before_codeql_runs() {
    let f = Fixture::new("tsbad").with_cached_pack("javascript", "2.5.0", &["code-scanning"]);
    f.config(json!({ "mode": "ok" }));
    let bun_name = if cfg!(windows) { "bun.exe" } else { "bun" };
    let inside = f.native_exe(&f.workspace.join("tools"), bun_name);
    let script = f
        .root
        .join("runtime")
        .join(if cfg!(windows) { "bun.cmd" } else { "bun.sh" });
    fs::create_dir_all(script.parent().unwrap()).unwrap();
    fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut cases: Vec<(String, &str)> = vec![
        ("relative/bun.exe".to_string(), "absolute path"),
        (
            f.root
                .join("missing")
                .join(bun_name)
                .to_string_lossy()
                .into_owned(),
            "does not exist",
        ),
        (
            inside.to_string_lossy().into_owned(),
            "inside the workspace",
        ),
        (
            script.to_string_lossy().into_owned(),
            if cfg!(windows) {
                ".exe program"
            } else {
                "not a native executable"
            },
        ),
    ];
    if cfg!(windows) {
        let odd = f.native_exe(&f.root.join("R&D"), "bun.exe");
        cases.push((odd.to_string_lossy().into_owned(), "'&'"));
        cases.push((r"\\server\share\bun.exe".to_string(), "network"));
    }
    for (runtime, why) in &cases {
        let out = f.analyze_env(
            &["--accept-codeql-terms", "--typescript-runtime", runtime],
            &[],
            None,
        );
        assert_eq!(
            out.status.code(),
            Some(4),
            "{runtime}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let error = stderr_json(&out);
        assert_eq!(error["error"], "invalid_typescript_runtime", "{runtime}");
        assert!(
            error["message"].as_str().unwrap().contains(why),
            "{runtime}: {error}"
        );
    }
    let long = "a".repeat(201);
    for (glob, why) in [
        ("../outside", "'..'"),
        ("src/../../x", "'..'"),
        ("/abs/path", "relative"),
        ("C:/x", "relative"),
        (r"a\b", "separator"),
        ("**/x\u{7}", "control"),
        ("   ", "empty"),
        (long.as_str(), "200"),
    ] {
        let out = f.analyze_env(&["--accept-codeql-terms", "--exclude", glob], &[], None);
        assert_eq!(
            out.status.code(),
            Some(4),
            "{glob}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let error = stderr_json(&out);
        assert_eq!(error["error"], "invalid_exclude", "{glob}");
        assert!(
            error["message"].as_str().unwrap().contains(why),
            "{glob}: {error}"
        );
    }
    // Regression: the 51st --exclude was an argument error (invalid_arguments, exit 2),
    // not the documented invalid_exclude (exit 4); 50 are accepted.
    let globs: Vec<String> = (0..51).map(|i| format!("dir{i}/**")).collect();
    let mut many: Vec<&str> = vec!["--accept-codeql-terms"];
    for glob in &globs {
        many.extend(["--exclude", glob.as_str()]);
    }
    let out = f.analyze_env(&many, &[], None);
    assert_eq!(
        out.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let error = stderr_json(&out);
    assert_eq!(error["error"], "invalid_exclude");
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("at most 50 exclude globs"),
        "{error}"
    );
    assert!(f.calls().is_empty(), "CodeQL ran: {:?}", f.calls());
    let mut fifty: Vec<&str> = many[..many.len() - 2].to_vec();
    fifty.extend(["--language", "javascript"]);
    let out = f.analyze_env(&fifty, &[], None);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn main() {
    let exe = std::env::current_exe().expect("current exe");
    let stem = exe
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    if stem == "codeql" {
        std::process::exit(fake_codeql(&exe));
    }
    let filters: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let tests: [(&str, fn()); 19] = [
        (
            "typescript_runtime_and_excludes_reach_codeql_only_through_their_variables",
            typescript_runtime_and_excludes_reach_codeql_only_through_their_variables,
        ),
        (
            "invalid_typescript_runtimes_and_excludes_are_refused_before_codeql_runs",
            invalid_typescript_runtimes_and_excludes_are_refused_before_codeql_runs,
        ),
        (
            "progress_events_report_each_step_with_heartbeats",
            progress_events_report_each_step_with_heartbeats,
        ),
        (
            "output_without_progress_is_unchanged_and_errors_stay_last",
            output_without_progress_is_unchanged_and_errors_stay_last,
        ),
        (
            "pack_downloads_have_their_own_budget",
            pack_downloads_have_their_own_budget,
        ),
        (
            "closing_stdin_cancels_a_pack_download",
            closing_stdin_cancels_a_pack_download,
        ),
        (
            "packs_lists_distribution_and_cache_packs_without_running_codeql",
            packs_lists_distribution_and_cache_packs_without_running_codeql,
        ),
        (
            "packs_download_fetches_missing_packs_one_at_a_time_and_retries_once",
            packs_download_fetches_missing_packs_one_at_a_time_and_retries_once,
        ),
        (
            "packs_download_failures_keep_completed_packs_and_report_codeql_s_message",
            packs_download_failures_keep_completed_packs_and_report_codeql_s_message,
        ),
        (
            "packs_refuses_unsafe_pack_caches_and_foreign_launchers",
            packs_refuses_unsafe_pack_caches_and_foreign_launchers,
        ),
        (
            "analysis_uses_build_mode_none_and_a_contained_environment",
            analysis_uses_build_mode_none_and_a_contained_environment,
        ),
        (
            "workspace_and_directory_paths_with_cmd_metacharacters_are_refused_on_windows",
            workspace_and_directory_paths_with_cmd_metacharacters_are_refused_on_windows,
        ),
        (
            "shared_work_directories_are_refused_on_unix",
            shared_work_directories_are_refused_on_unix,
        ),
        (
            "closing_stdin_cancels_the_analysis_and_kills_the_codeql_tree",
            closing_stdin_cancels_the_analysis_and_kills_the_codeql_tree,
        ),
        (
            "missing_packs_fail_before_codeql_resolves_anything",
            missing_packs_fail_before_codeql_resolves_anything,
        ),
        (
            "packs_are_downloaded_into_the_pack_cache_only_when_allowed",
            packs_are_downloaded_into_the_pack_cache_only_when_allowed,
        ),
        (
            "failing_language_is_reported_with_the_codeql_error",
            failing_language_is_reported_with_the_codeql_error,
        ),
        (
            "timeout_kills_the_whole_codeql_process_tree",
            timeout_kills_the_whole_codeql_process_tree,
        ),
        (
            "terms_gate_and_launcher_rules_refuse_before_running_anything",
            terms_gate_and_launcher_rules_refuse_before_running_anything,
        ),
    ];
    let mut failed = Vec::new();
    let mut ran = 0;
    for (name, test) in tests {
        if !filters.is_empty() && !filters.iter().any(|f| name.contains(f.as_str())) {
            continue;
        }
        ran += 1;
        let started = Instant::now();
        match std::panic::catch_unwind(test) {
            Ok(()) => println!(
                "test {name} ... ok ({:.1}s)",
                started.elapsed().as_secs_f64()
            ),
            Err(_) => {
                println!("test {name} ... FAILED");
                failed.push(name);
            }
        }
    }
    println!(
        "\ntest result: {}. {} passed; {} failed",
        if failed.is_empty() { "ok" } else { "FAILED" },
        ran - failed.len(),
        failed.len()
    );
    if !failed.is_empty() {
        std::process::exit(101);
    }
}
