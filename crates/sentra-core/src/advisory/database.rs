//! Pinned advisory database and package vulnerability evaluator (Requirement F-07).
//!
//! Evaluates lockfile packages against security advisories. Distinguishes:
//! - Affected packages
//! - Unaffected packages
//! - Stale advisory database states
//! - Unknown/malformed version packages
//! - Enforces Reachability::PresentOnly for lockfile matches (Requirement F-07).

use serde::{Deserialize, Serialize};

use crate::{
    advisory::{
        cargo_lock::PackageRecord,
        error::{AdvisoryError, AdvisoryErrorKind},
        semver::{SemverVersion, VersionReq},
    },
    domain::{
        finding::{Confidence, Finding, FindingSource, Reachability, Severity, TargetLocation},
        id::{FindingId, SessionId, TaskId},
        time::TimestampUtc,
    },
};

/// A security advisory definition (compatible with RustSec / GHSA schemas).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advisory {
    /// Advisory identifier (e.g. `RUSTSEC-2023-0001`).
    pub id: String,
    /// Affected crate name.
    pub package: String,
    /// Concise summary title.
    pub title: String,
    /// Detailed description of the vulnerability.
    pub description: String,
    /// Assessed severity rating.
    pub severity: Severity,
    /// Raw affected version requirement strings (e.g. `"< 1.2.0"`).
    pub affected_version_reqs: Vec<String>,
    /// Patched versions (e.g. `1.2.0`).
    pub patched_versions: Vec<String>,
    /// Advisory publication or disclosure date.
    pub published_at: String,
    /// Aliases (e.g. `CVE-2023-XXXX`).
    pub aliases: Vec<String>,
}

/// A matched vulnerability finding for a specific package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisoryMatch {
    /// Matched security advisory.
    pub advisory: Advisory,
    /// Package name found in the lockfile.
    pub package: String,
    /// Exact version installed in the lockfile.
    pub installed_version: String,
    /// Demonstrated reachability (Requirement F-07: strictly `PresentOnly` for lockfile findings).
    pub reachability: Reachability,
    /// Recommended patched version, if available.
    pub recommended_patch: Option<String>,
}

/// Consolidated results from auditing a set of packages against the advisory database.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisoryAuditResult {
    /// Matched vulnerabilities.
    pub matches: Vec<AdvisoryMatch>,
    /// Total number of distinct packages examined.
    pub packages_audited: usize,
    /// Total count of packages with identified vulnerabilities.
    pub vulnerable_packages: usize,
    /// Whether the advisory database is considered stale relative to current time.
    pub is_stale: bool,
    /// Packages with unparseable or malformed version strings (Requirement F-07).
    pub unknown_version_packages: Vec<String>,
}

impl AdvisoryAuditResult {
    /// Converts matched advisories into authoritative candidate findings for a specific lockfile path.
    pub fn to_candidate_findings_for_lockfile(
        &self,
        session_id: SessionId,
        task_id: TaskId,
        now: TimestampUtc,
        lockfile_path: &str,
    ) -> Vec<Finding> {
        self.matches
            .iter()
            .map(|m| match_to_finding(m, session_id, task_id, now, lockfile_path))
            .collect()
    }

    /// Converts matched advisories into candidate findings, each located at the lockfile its
    /// package was read from. `lockfiles` holds one workspace-relative lockfile path per entry
    /// of `matches`, in the same order; a match without an entry is attributed to `Cargo.lock`,
    /// like [`Self::to_candidate_findings`].
    pub fn to_candidate_findings_per_lockfile(
        &self,
        session_id: SessionId,
        task_id: TaskId,
        now: TimestampUtc,
        lockfiles: &[String],
    ) -> Vec<Finding> {
        self.matches
            .iter()
            .enumerate()
            .map(|(index, m)| {
                let lockfile = lockfiles.get(index).map_or("Cargo.lock", String::as_str);
                match_to_finding(m, session_id, task_id, now, lockfile)
            })
            .collect()
    }

    /// Converts matched advisories into authoritative candidate findings (defaults to Cargo.lock).
    pub fn to_candidate_findings(
        &self,
        session_id: SessionId,
        task_id: TaskId,
        now: TimestampUtc,
    ) -> Vec<Finding> {
        self.to_candidate_findings_for_lockfile(session_id, task_id, now, "Cargo.lock")
    }
}

/// One candidate finding for one advisory match, located at `lockfile_path`.
fn match_to_finding(
    m: &AdvisoryMatch,
    session_id: SessionId,
    task_id: TaskId,
    now: TimestampUtc,
    lockfile_path: &str,
) -> Finding {
    let title = format!(
        "Vulnerability in {}: {} ({})",
        m.package, m.advisory.title, m.advisory.id
    );
    let description = format!(
        "Package '{}' version '{}' is affected by advisory {}.\n\nDescription: {}\n\nRecommended patch: {}",
        m.package,
        m.installed_version,
        m.advisory.id,
        m.advisory.description,
        m.recommended_patch.as_deref().unwrap_or("None available")
    );

    let source = if lockfile_path == "Cargo.lock" {
        FindingSource::CargoLockAdvisory {
            advisory_id: m.advisory.id.clone(),
            package: m.package.clone(),
            version: m.installed_version.clone(),
        }
    } else {
        FindingSource::DependencyLockAdvisory {
            advisory_id: m.advisory.id.clone(),
            package: m.package.clone(),
            version: m.installed_version.clone(),
            lockfile_path: lockfile_path.to_string(),
        }
    };

    Finding::new_candidate(
        FindingId::new(),
        session_id,
        task_id,
        title,
        description,
        m.advisory.severity,
        Confidence::Confirmed,
        m.reachability, // Preserves Reachability::PresentOnly per F-07
        source,
        Some(TargetLocation {
            path: lockfile_path.to_string(),
            start_line: None,
            end_line: None,
        }),
        None,
        now,
    )
}

/// When the entries of [`AdvisoryDatabase::pinned_advisories`] were last edited, in
/// milliseconds since the Unix epoch: 2026-11-08T23:43:22Z, the commit time of repository
/// commit `f753e09`.
///
/// The bundled set is a small hand-written sample. It is not synchronized with OSV,
/// RustSec or GHSA, so its age is this curation date and never the time a command runs.
/// Freshness checks against it therefore report real staleness.
pub const PINNED_ADVISORY_SET_CURATED_AT_MILLIS: u64 = 1_794_181_402_000;

/// Pinned advisory database maintaining security advisories.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvisoryDatabase {
    advisories: Vec<Advisory>,
    updated_at: TimestampUtc,
}

impl AdvisoryDatabase {
    /// Creates a new advisory database with an explicit snapshot update timestamp.
    pub fn new(advisories: Vec<Advisory>, updated_at: TimestampUtc) -> Self {
        Self {
            advisories,
            updated_at,
        }
    }

    /// Creates an empty advisory database.
    pub fn empty(updated_at: TimestampUtc) -> Self {
        Self {
            advisories: Vec::new(),
            updated_at,
        }
    }

    /// Creates the bundled pinned advisory database for offline auditing (Requirement F-07).
    ///
    /// The snapshot is stamped with [`Self::pinned_curated_at`], the date its entries were
    /// last edited, so `is_stale` reflects the real age of this small fixed sample.
    pub fn default_pinned() -> Self {
        Self::new(Self::pinned_advisories(), Self::pinned_curated_at())
    }

    /// Curation timestamp of the bundled pinned advisory set.
    pub const fn pinned_curated_at() -> TimestampUtc {
        TimestampUtc::from_epoch_millis(PINNED_ADVISORY_SET_CURATED_AT_MILLIS)
    }

    /// Returns the hand-written advisory entries bundled with Sentra.
    ///
    /// Callers that need these entries under a different snapshot timestamp (for example a
    /// test that pins its clock) must say so explicitly through [`Self::new`].
    pub fn pinned_advisories() -> Vec<Advisory> {
        vec![
            Advisory {
                id: "RUSTSEC-2021-0145".to_string(),
                package: "atty".to_string(),
                title: "Potential unaligned read in atty on Windows".to_string(),
                description: "On Windows, atty dereferences a raw pointer without checking alignment.".to_string(),
                severity: Severity::Medium,
                affected_version_reqs: vec!["< 0.2.14".to_string()],
                patched_versions: vec!["0.2.14".to_string()],
                published_at: "2021-12-05T00:00:00Z".to_string(),
                aliases: vec!["CVE-2021-45720".to_string()],
            },
            Advisory {
                id: "RUSTSEC-2020-0071".to_string(),
                package: "time".to_string(),
                title: "Potential segfault in localtime_r invocations".to_string(),
                description: "Invocations of libc::localtime_r in time may result in segmentation faults in multithreaded programs.".to_string(),
                severity: Severity::High,
                affected_version_reqs: vec![">= 0.2.0, < 0.2.23".to_string()],
                patched_versions: vec!["0.2.23".to_string()],
                published_at: "2020-11-18T00:00:00Z".to_string(),
                aliases: vec!["CVE-2020-26235".to_string()],
            },
            Advisory {
                id: "GHSA-p6mc-m468-83gw".to_string(),
                package: "lodash".to_string(),
                title: "Prototype Pollution in lodash".to_string(),
                description: "lodash versions prior to 4.17.12 are vulnerable to Prototype Pollution via zipObjectDeep.".to_string(),
                severity: Severity::Critical,
                affected_version_reqs: vec!["< 4.17.12".to_string()],
                patched_versions: vec!["4.17.12".to_string()],
                published_at: "2019-07-02T00:00:00Z".to_string(),
                aliases: vec!["CVE-2019-10744".to_string()],
            },
            Advisory {
                id: "GHSA-vh95-rmgr-6w4m".to_string(),
                package: "minimist".to_string(),
                title: "Prototype Pollution in minimist".to_string(),
                description: "minimist before 0.2.1 or 1.2.3 is vulnerable to prototype pollution.".to_string(),
                severity: Severity::Medium,
                affected_version_reqs: vec!["< 0.2.1".to_string(), ">= 1.0.0, < 1.2.3".to_string()],
                patched_versions: vec!["0.2.1".to_string(), "1.2.3".to_string()],
                published_at: "2020-03-11T00:00:00Z".to_string(),
                aliases: vec!["CVE-2020-7598".to_string()],
            },
            Advisory {
                id: "GHSA-qw6h-v559-w396".to_string(),
                package: "express".to_string(),
                title: "Path traversal in express via malformed response redirects".to_string(),
                description: "express versions prior to 4.20.0 are vulnerable to open redirect and path traversal.".to_string(),
                severity: Severity::High,
                affected_version_reqs: vec!["< 4.20.0".to_string()],
                patched_versions: vec!["4.20.0".to_string()],
                published_at: "2024-09-10T00:00:00Z".to_string(),
                aliases: vec!["CVE-2024-43796".to_string()],
            },
            Advisory {
                id: "GHSA-wf5p-g6vw-rhxx".to_string(),
                package: "axios".to_string(),
                title: "Cross-site scripting and credential leakage in axios".to_string(),
                description: "axios versions prior to 1.6.0 leak confidential auth headers across cross-origin redirects.".to_string(),
                severity: Severity::High,
                affected_version_reqs: vec!["< 1.6.0".to_string()],
                patched_versions: vec!["1.6.0".to_string()],
                published_at: "2023-11-01T00:00:00Z".to_string(),
                aliases: vec!["CVE-2023-45857".to_string()],
            },
        ]
    }

    /// Returns the database last update timestamp.
    pub fn updated_at(&self) -> TimestampUtc {
        self.updated_at
    }

    /// Returns the number of advisories held by the database.
    pub fn advisory_count(&self) -> usize {
        self.advisories.len()
    }

    /// Checks if the advisory database exceeds the freshness threshold (Requirement F-07).
    pub fn is_stale(&self, now: TimestampUtc, max_age_days: u32) -> bool {
        let max_age_millis = (max_age_days as u64) * 24 * 60 * 60 * 1000;
        now.as_epoch_millis()
            .saturating_sub(self.updated_at.as_epoch_millis())
            > max_age_millis
    }

    /// Adds an advisory to the database.
    pub fn add_advisory(&mut self, advisory: Advisory) {
        self.advisories.push(advisory);
    }

    /// Ingests advisories from an OSV JSON payload (either single record or array bundle).
    pub fn ingest_osv_payload(&mut self, json_str: &str) -> Result<usize, AdvisoryError> {
        let advisories = crate::advisory::osv::parse_osv_payload(json_str)?;
        let count = advisories.len();
        for adv in advisories {
            self.add_advisory(adv);
        }
        Ok(count)
    }

    /// Ingests all `.json` OSV files from a local mirror directory.
    pub fn ingest_osv_directory(
        &mut self,
        dir_path: &std::path::Path,
    ) -> Result<usize, AdvisoryError> {
        crate::advisory::osv::ingest_osv_directory(self, dir_path)
    }

    /// Audits a slice of package records against all registered advisories (Requirement F-07).
    ///
    /// Advisories are matched by package name (ASCII case-insensitive) and version range
    /// only: [`Advisory`] carries no ecosystem, so a same-named package from another
    /// ecosystem matches too.
    pub fn audit_packages(
        &self,
        packages: &[PackageRecord],
        now: TimestampUtc,
        stale_threshold_days: u32,
    ) -> Result<AdvisoryAuditResult, AdvisoryError> {
        let is_stale = self.is_stale(now, stale_threshold_days);
        let mut matches = Vec::new();
        let mut unknown_version_packages = Vec::new();
        let mut vulnerable_package_names = std::collections::HashSet::new();

        for pkg in packages {
            let semver = match &pkg.semver {
                Ok(v) => v,
                Err(_) => {
                    unknown_version_packages.push(format!("{}@{}", pkg.name, pkg.raw_version));
                    continue;
                }
            };

            for adv in &self.advisories {
                if !adv.package.eq_ignore_ascii_case(&pkg.name) {
                    continue;
                }

                // Check affected version requirements
                let mut is_affected = false;
                for req_str in &adv.affected_version_reqs {
                    let req: VersionReq = req_str.parse().map_err(|e: AdvisoryError| {
                        AdvisoryError::new(
                            AdvisoryErrorKind::InvalidDatabase,
                            format!("corrupt advisory {} constraint: {}", adv.id, e.message()),
                        )
                    })?;
                    if req.matches(semver) {
                        is_affected = true;
                        break;
                    }
                }

                if is_affected {
                    // Check if installed version is already in patched_versions
                    let is_patched = adv.patched_versions.iter().any(|p| {
                        p.parse::<SemverVersion>()
                            .map(|pv| &pv == semver)
                            .unwrap_or(false)
                    });

                    if !is_patched {
                        vulnerable_package_names.insert(pkg.name.clone());
                        let recommended_patch = adv.patched_versions.first().cloned();
                        matches.push(AdvisoryMatch {
                            advisory: adv.clone(),
                            package: pkg.name.clone(),
                            installed_version: pkg.raw_version.clone(),
                            // Requirement F-07: dependency presence MUST be separate from demonstrated runtime reachability
                            reachability: Reachability::PresentOnly,
                            recommended_patch,
                        });
                    }
                }
            }
        }

        Ok(AdvisoryAuditResult {
            vulnerable_packages: vulnerable_package_names.len(),
            matches,
            packages_audited: packages.len(),
            is_stale,
            unknown_version_packages,
        })
    }
}
