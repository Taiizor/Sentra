//! Regression tests for documentation that claimed behaviour the code does not have.
//!
//! The documents are read from the repository checkout. Outside it (for example when the
//! crate is built from a published package) the documents are absent and the test returns
//! early.

use std::{
    fs,
    path::{Path, PathBuf},
};

fn repository_root() -> Option<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    root.join("ROADMAP.md").is_file().then_some(root)
}

fn read(root: &Path, file: &str) -> String {
    fs::read_to_string(root.join(file)).unwrap_or_else(|error| panic!("{file}: {error}"))
}

#[test]
fn documents_do_not_repeat_retracted_claims() {
    let Some(root) = repository_root() else {
        return;
    };
    let retracted: &[(&str, &[&str])] = &[
        (
            "README.md",
            &[
                "interprocedural taint tracking",
                "independently verified patch generation",
                "generates candidate fixes verified against test oracles",
                "reproduces crashes inside isolated workers",
                "Remediation patches are marked verified if and only if",
            ],
        ),
        (
            "crates/sentra/README.md",
            &[
                "AST & taint analysis core",
                "Remediation patches are marked verified if and only if",
            ],
        ),
        (
            "crates/sentra-core/README.md",
            &["Strict verification invariant ensuring remediation patches"],
        ),
        ("crates/sentra/src/lib.rs", &["whose tools write no files."]),
        (
            "SECURITY.md",
            &[
                "Sentra provides a complete, independently verified security analysis platform",
                "capability-scoped AI reasoning, and disposable worker patch verification.",
                "capability matrices, and remote worker fleet isolation audits.",
            ],
        ),
        (
            "examples/adapters/README.md",
            &["Software composition analysis (SCA) via Snyk CLI"],
        ),
        (
            "examples/adapters/sentra-adapter-snyk/README.md",
            &[
                "connecting Snyk Software Composition Analysis",
                "evaluates known vulnerability databases",
            ],
        ),
        (
            "examples/adapters/sentra-adapter-ollama/README.md",
            &["Generates unified diff remediation proposals"],
        ),
        ("web/README.md", &["it is not a plain absolute local path"]),
        (
            "docs/README.md",
            &[
                "autonomous repository vulnerability discovery",
                "verified across Windows 11, Linux, and macOS platforms",
            ],
        ),
        ("CONTRIBUTING.md", &["independently verified remediation"]),
        (
            "ARCHITECTURE.md",
            &["is an autonomous AI security research and remediation platform"],
        ),
        (
            "AGENTS.md",
            &["multi-tenant fleet management are implemented and verified"],
        ),
        (".github/labels.yml", &["OSV/RustSec advisory ingestion"]),
        ("web/README.md", &["`<APPDATA>sentraplugins`"]),
        (
            "docs/PLUGINS_GUIDE.md",
            &["not a plain absolute local path"],
        ),
        (
            "CHANGELOG.md",
            &[
                "an executable resolved inside the adapter directory",
                "not a plain absolute local path",
            ],
        ),
    ];
    for (file, claims) in retracted {
        let text = read(&root, file);
        for claim in *claims {
            assert!(!text.contains(claim), "{file} still claims {claim:?}");
        }
    }

    // The 2026-11-08 gate audit is kept for history, with a dated correction.
    let audit = read(&root, "docs/RELEASE_GATES_AUDIT.md");
    assert!(audit.contains("Correction (2026-11-11)"));
    assert!(audit.contains("2 RustSec and 4 GHSA records"));
    let security = read(&root, "SECURITY.md");
    assert!(security.contains("Correction (2026-11-11)"));
    assert!(security.contains("`sentra verify-audit` is not implemented"));
}
