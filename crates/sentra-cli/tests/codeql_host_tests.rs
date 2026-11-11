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

    fn calls(&self) -> Vec<Value> {
        fs::read_to_string(self.dist.join("calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
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
    assert_eq!(
        norm(download["args"][3].as_str().unwrap()),
        format!("--common-caches={cache}")
    );
    assert!(
        f.cache
            .join("packages/codeql/python-queries/1.2.3/qlpack.yml")
            .is_file()
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

// ---------------------------------------------------------------------------
// Minimal harness
// ---------------------------------------------------------------------------

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
    let tests: [(&str, fn()); 9] = [
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
