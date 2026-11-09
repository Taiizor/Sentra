//! Pure-Rust parser for Ruby Bundler lockfiles (`Gemfile.lock`).
//!
//! Extracts resolved Ruby gems and exact versions under `#![forbid(unsafe_code)]`.

use std::collections::BTreeSet;

use crate::advisory::{cargo_lock::PackageRecord, error::AdvisoryError};

/// Parses a `Gemfile.lock` content into structured package records.
///
/// Handles the `specs:` block format:
/// ```text
/// GEM
///   remote: https://rubygems.org/
///   specs:
///     actionpack (7.1.3.4)
///       actionview (= 7.1.3.4)
///     rails (7.1.3.4)
/// ```
pub fn parse_gemfile_lock(content: &str) -> Result<Vec<PackageRecord>, AdvisoryError> {
    let mut packages = Vec::new();
    let mut seen = BTreeSet::new();
    let mut in_specs_block = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Detect section headers
        if !line.starts_with(' ') && !line.starts_with('\t') {
            in_specs_block = false;
        }

        if trimmed == "specs:" {
            in_specs_block = true;
            continue;
        }

        if in_specs_block {
            // Gem definitions have exactly 4 spaces (or 1 indent unit under specs)
            // e.g. `    actionpack (7.1.3.4)`
            // Sub-dependencies have 6 spaces: `      actionview (= 7.1.3.4)`
            let leading_spaces = line.chars().take_while(|c| *c == ' ').count();
            if leading_spaces == 4
                && let Some((name_part, rest)) = trimmed.split_once('(')
            {
                let gem_name = name_part.trim();
                let gem_ver = rest.trim().trim_end_matches(')').trim();

                if !gem_name.is_empty()
                    && !gem_ver.is_empty()
                    && seen.insert((gem_name.to_string(), gem_ver.to_string()))
                {
                    packages.push(PackageRecord::new(gem_name, gem_ver));
                }
            }
        }
    }

    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gemfile_lock() {
        let data = "
GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.1.3.4)
      actionview (= 7.1.3.4)
      activesupport (= 7.1.3.4)
      rack (>= 2.2.4)
    rails (7.1.3.4)
      actioncable (= 7.1.3.4)
      actionmailbox (= 7.1.3.4)
    nokogiri (1.16.2)
      racc (~> 1.4)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 7.1.3)
";
        let pkgs = parse_gemfile_lock(data).unwrap();
        assert_eq!(pkgs.len(), 3);
        assert_eq!(pkgs[0].name, "actionpack");
        assert_eq!(pkgs[0].raw_version, "7.1.3.4");
        assert_eq!(pkgs[1].name, "rails");
        assert_eq!(pkgs[1].raw_version, "7.1.3.4");
        assert_eq!(pkgs[2].name, "nokogiri");
        assert_eq!(pkgs[2].raw_version, "1.16.2");
    }
}
