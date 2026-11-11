//! Draft pull request previews for remediation (REQ-F11, REQ-F18, Remediation Specification).
//!
//! Builds local, unsigned preview packages (title, body, commit message, an illustrative
//! diff and a suggested `gh` command) for human review. Nothing here writes to Git, pushes,
//! or contacts a forge, and nothing is verified: the body states which checks were not done.

use serde::{Deserialize, Serialize};

use crate::{
    advisory::database::AdvisoryMatch,
    common::crypto::sha256_digest,
    domain::{
        finding::{Finding, FindingSource, Severity},
        time::TimestampUtc,
    },
};

/// Replaces every character that has a meaning inside double quotes in POSIX shells,
/// PowerShell or `cmd.exe` (for example `$`, backticks, `"`, `\`, `!`, `%`, `^`, `&` and
/// parentheses), and every non-ASCII or control character, with `_`.
fn paste_safe(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    ' ' | '.' | '_' | '-' | ':' | '+' | '/' | ',' | '=' | '@' | '[' | ']'
                )
            {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Suggested `gh pr create` command that can be pasted into a POSIX shell, PowerShell or
/// `cmd.exe` as shown: double-quoted arguments without shell metacharacters, and the body
/// read from `<proposal_id>.md` instead of being inlined.
fn suggested_gh_command(title: &str, branch_name: &str, proposal_id: &str) -> String {
    format!(
        "gh pr create --draft --title \"{}\" --head \"{}\" --body-file \"{}.md\"",
        paste_safe(title),
        paste_safe(branch_name),
        paste_safe(proposal_id)
    )
}

/// A local draft pull request preview for human review. Creating the branch, commit and
/// pull request is left to the operator; Sentra does none of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationPrPackage {
    /// Deterministic proposal identifier (e.g. `prop-c39f18a2...`).
    pub proposal_id: String,
    /// Suggested Git branch name (e.g. `sentra/remediate-ghsa-p6mc-m468-83gw`); not created.
    pub branch_name: String,
    /// Pull request title.
    pub title: String,
    /// Conventional commit message.
    pub commit_message: String,
    /// Markdown pull request body, including the checks that were and were not done.
    pub body_markdown: String,
    /// Illustrative diff. It is not computed from the file contents and does not apply as-is.
    pub patch_diff: String,
    /// Suggested GitHub CLI (`gh`) command; Sentra never runs it. It needs the branch to exist
    /// on the remote and `body_markdown` saved as `<proposal_id>.md`: the body is not inlined,
    /// because its Markdown backticks and `$` would be expanded by a shell. In the title and
    /// branch, every character a shell could interpret is replaced with `_`, since lockfile
    /// versions come from the scanned repository.
    pub gh_command: String,
    /// Affected component or package name.
    pub target_component: String,
    /// Advisory or rule identifier (e.g. `GHSA-p6mc-m468-83gw`, `SENTRA-SEC-001`).
    pub advisory_or_rule_id: String,
    /// Severity classification.
    pub severity: Severity,
    /// Strict invariant: Sentra proposals are always draft-only and require explicit human admission.
    pub is_draft_only: bool,
    /// Package creation timestamp.
    pub created_at: String,
}

impl RemediationPrPackage {
    /// Generates an illustrative version-bump diff for `manifest_path`. The hunk is a fixed
    /// JSON-style line pair, not read from the file, so it does not apply to real lockfiles.
    pub fn create_version_bump_diff(
        manifest_path: &str,
        package: &str,
        from_version: &str,
        to_version: &str,
    ) -> String {
        format!(
            "--- a/{manifest_path}\n+++ b/{manifest_path}\n@@ -1,3 +1,3 @@\n-    \"{package}\": \"{from_version}\"\n+    \"{package}\": \"^{to_version}\"\n"
        )
    }

    /// Generates a draft pull request preview from an advisory match.
    ///
    /// `manifest_filename` is the lockfile the package was read from. `advisory_source`
    /// describes the advisory data the match came from (for example the bundled pinned
    /// sample) and is quoted in the body, which never claims a check that was not done.
    pub fn from_advisory_match(
        m: &AdvisoryMatch,
        manifest_filename: &str,
        base_commit_sha: &str,
        advisory_source: &str,
    ) -> Self {
        let advisory_id = &m.advisory.id;
        let package = &m.package;
        let installed = &m.installed_version;
        let patch_target = m.recommended_patch.as_deref().unwrap_or(installed);

        let slug_id = advisory_id
            .to_ascii_lowercase()
            .replace(['_', ':', '/'], "-");
        let branch_name = format!("sentra/remediate-{slug_id}");
        let title = format!(
            "[Security] Remediate {}: Bump {} from {} to {}",
            advisory_id, package, installed, patch_target
        );

        let commit_message = format!(
            "fix(deps): bump {package} from {installed} to {patch_target}\n\nRemediates {advisory_id}: {}\nReported by Sentra Security Engine",
            m.advisory.title
        );

        let patch_diff =
            Self::create_version_bump_diff(manifest_filename, package, installed, patch_target);

        let aliases_text = if m.advisory.aliases.is_empty() {
            "None listed".to_string()
        } else {
            m.advisory.aliases.join(", ")
        };

        let body_markdown = format!(
            "### Sentra Remediation Preview\n\n\
            | Property | Value |\n\
            | :--- | :--- |\n\
            | **Advisory ID** | `{advisory_id}` |\n\
            | **Aliases** | {aliases_text} |\n\
            | **Affected Component** | `{package}` |\n\
            | **Lockfile** | `{manifest_filename}` |\n\
            | **Installed Version** | `{installed}` |\n\
            | **Remediation Target** | `^{patch_target}` |\n\
            | **Severity** | `{severity}` |\n\n\
            #### Vulnerability Summary\n\
            {summary}\n\n\
            #### Description\n\
            {description}\n\n\
            #### What Sentra Checked\n\
            - [x] `{manifest_filename}` was parsed by Sentra's built-in lockfile parser (no subprocess).\n\
            - [x] The package name and version were matched against: {advisory_source}.\n\
            - [ ] Reachability was not analysed; the match records `{reachability}`.\n\
            - [ ] The version bump was not applied, built or tested; the diff in this preview is illustrative and does not apply as-is.\n\
            - [x] No target code was executed to produce this preview.\n\n\
            ---\n\
            *Draft preview generated locally by [Sentra](https://github.com/Taiizor/Sentra) for human review. Sentra did not create a branch, commit or pull request. Base: `{base_commit_sha}`.*",
            severity = m.advisory.severity,
            summary = m.advisory.title,
            description = m.advisory.description,
            reachability = m.reachability.as_str(),
        );

        let mut id_payload = Vec::new();
        id_payload.extend_from_slice(package.as_bytes());
        id_payload.push(b':');
        id_payload.extend_from_slice(advisory_id.as_bytes());
        id_payload.push(b':');
        id_payload.extend_from_slice(base_commit_sha.as_bytes());
        id_payload.push(b':');
        id_payload.extend_from_slice(patch_diff.as_bytes());

        let proposal_id = format!("prop-{}", &sha256_digest(&id_payload)[..16]);
        let gh_command = suggested_gh_command(&title, &branch_name, &proposal_id);

        Self {
            proposal_id,
            branch_name,
            title,
            commit_message,
            body_markdown,
            patch_diff,
            gh_command,
            target_component: package.clone(),
            advisory_or_rule_id: advisory_id.clone(),
            severity: m.advisory.severity,
            is_draft_only: true,
            created_at: TimestampUtc::now().to_string(),
        }
    }

    /// Generates a draft pull request preview from a (candidate) finding.
    ///
    /// The diff is a placeholder that names the finding location; the finding carries no
    /// fix, so the body marks the fix and its verification as not done.
    pub fn from_finding(finding: &Finding, base_commit_sha: &str) -> Self {
        let (id, target) = match finding.source() {
            FindingSource::CargoLockAdvisory {
                advisory_id,
                package,
                ..
            } => (advisory_id.clone(), package.clone()),
            FindingSource::DependencyLockAdvisory {
                advisory_id,
                package,
                ..
            } => (advisory_id.clone(), package.clone()),
            FindingSource::StaticAnalysis { engine, rule_id } => {
                (rule_id.clone(), format!("{engine}:{rule_id}"))
            }
            FindingSource::DynamicAnalysis {
                agent_role,
                oracle_id,
            } => (oracle_id.clone(), agent_role.clone()),
            FindingSource::Manual { author } => (
                format!("MANUAL-{}", finding.id()),
                format!("manual-review-by-{author}"),
            ),
        };

        let slug = id.to_ascii_lowercase().replace(['_', ':', '/'], "-");
        let branch_name = format!("sentra/fix-{slug}");
        let title = format!("[Security] Remediate {}: {}", id, finding.title());

        let commit_message = format!(
            "fix(security): address {id}\n\n{}\nReported by Sentra Security Engine",
            finding.title()
        );

        let body_markdown = format!(
            "### Sentra Remediation Preview\n\n\
            **Finding ID:** `{}`\n\
            **Rule / Advisory:** `{id}`\n\
            **Severity:** `{}`\n\
            **Confidence:** `{}`\n\
            **Reachability:** `{}`\n\n\
            #### Description\n\
            {}\n\n\
            #### What Sentra Checked\n\
            - [ ] No fix was written, applied, built or tested; the diff in this preview is a placeholder.\n\
            - [ ] The finding is a candidate; it has not been independently verified.\n\n\
            ---\n\
            *Draft preview generated locally by [Sentra](https://github.com/Taiizor/Sentra) for human review. Sentra did not create a branch, commit or pull request. Base: `{base_commit_sha}`.*",
            finding.id(),
            finding.severity(),
            finding.confidence(),
            finding.reachability(),
            finding.description()
        );

        // Placeholder only: the finding carries no fix, so no real diff can be produced.
        let patch_diff = if let Some(loc) = finding.location() {
            format!(
                "--- a/{path}\n+++ b/{path}\n@@ -{line},1 +{line},1 @@\n- // Vulnerable code at line {line}\n+ // Remediated code\n",
                path = loc.path,
                line = loc.start_line.unwrap_or(1)
            )
        } else {
            "--- a/remediation.patch\n+++ b/remediation.patch\n@@ -0,0 +1,1 @@\n+// Remediation patch pending human review\n".to_string()
        };

        let mut id_payload = Vec::new();
        id_payload.extend_from_slice(target.as_bytes());
        id_payload.push(b':');
        id_payload.extend_from_slice(id.as_bytes());
        id_payload.push(b':');
        id_payload.extend_from_slice(base_commit_sha.as_bytes());

        let proposal_id = format!("prop-{}", &sha256_digest(&id_payload)[..16]);
        let gh_command = suggested_gh_command(&title, &branch_name, &proposal_id);

        Self {
            proposal_id,
            branch_name,
            title,
            commit_message,
            body_markdown,
            patch_diff,
            gh_command,
            target_component: target,
            advisory_or_rule_id: id,
            severity: finding.severity(),
            is_draft_only: true,
            created_at: TimestampUtc::now().to_string(),
        }
    }
}
